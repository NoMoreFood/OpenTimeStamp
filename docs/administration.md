# Administration and Operations

## Authentication and Administration

Only Anonymous and Windows authentication are supported. Basic, Digest, and both
IIS client-certificate mapping mechanisms are explicitly disabled at the public
application and admin path; installation fails closed if IIS will not apply and
report those settings while the corresponding role service is installed. An
absent role service is also accepted because that scheme cannot run. Anonymous
mode records the principal as anonymous. Windows mode relies on IIS Windows
authentication and writes the authenticated username, SID, and authentication
type into every application audit record. The installer writes
the same immutable authentication mode to IIS and `web.config`; after
installation, confirm the effective selection on the local administrative page.

The installer protects `/admin` independently of the public endpoints:

1. IIS permits only IPv4 peer addresses assigned to the server, including
   `127.0.0.1`.
2. IIS requires Windows authentication.
3. The application requires a local peer and an exact host in the immutable
   `AdminHostNames` deployment allowlist; it rejects forwarded client-address
   headers.
4. A required Windows-group allowlist defaults to `BUILTIN\Administrators` and
   can be replaced with one or more dedicated administrative group names or SIDs.

The installer populates `AdminHostNames` from non-wildcard IIS site binding host
headers, localhost/loopback, the short machine name, the computer FQDN, and
values passed through `-AdminHostNames`. Blank or wildcard bindings never become
allowed hosts. On an existing deployment, omitted custom host values are
preserved. Rerun the installer after adding, removing, or renumbering a network
interface so the IIS peer-address allowlist stays current.

Use a browser directly on the server. Do not publish or reverse-proxy the admin
path. In particular, a same-host reverse proxy makes a remote request appear to
originate from the local computer; it can defeat peer-address controls if it
strips the forwarded headers that the application rejects.

## FIPS and Legacy Behavior

OpenTimeStamp reads the effective Windows FIPS policy at runtime. When FIPS mode
is enabled:

- MD5 and SHA-1 request hashes are rejected even if present in saved settings;
- SHA-1 cannot be used to sign timestamps; and
- the legacy Authenticode endpoint is unavailable.

The service's FIPS gate continues to permit RFC 3161 with SHA-256, SHA-384, or
SHA-512, but successful issuance still depends on the configured key provider.
For ML-DSA, the installed Windows CNG provider and effective cryptographic policy
must also permit the selected key and algorithm. This is a fail-closed runtime
gate, not just an administrative-page option. A policy change should be followed
by an application-pool recycle and an RFC 3161 validation request. Check the
server policy without changing it:

```powershell
Get-ItemProperty `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' `
    -Name Enabled
```

Enabling legacy algorithms when policy permits them is for compatibility only.
Prefer RFC 3161 and SHA-256 or stronger for every new integration.

## State, Logs, and Operations

Mutable data is under the configured data directory (`App_Data` by default).
Settings are written atomically with a backup; timestamp state reliably
allocates serial numbers, authenticates its state/high-water metadata, repairs
only consistent redundant copies, and detects clock rollback. UTF-8 JSON Lines
audit logs are stored in its `Logs` subdirectory. Daily rollover produces
`timestamp-YYYYMMDD.jsonl`; hourly rollover produces
`timestamp-YYYYMMDD-HH.jsonl`; weekly rollover produces
`timestamp-week-YYYYMMDD.jsonl`, dated for Monday at the start of the UTC week.
Administration can enable or disable automatic pruning and select a retention
period from 1 through 3650 days. New configurations default to daily rollover
and 365 days of retention.
Cross-process coordination uses persistent zero-content `tsa.config.lock`,
`issuance.state.lock`, and `Logs\.audit.lock` files. These are neither state nor
backup payloads and should not be deleted during normal operation or recovery.
Local validation cannot detect a coherent rollback of every issuance-state and
high-water copy. Backup and restore procedures must compare an external
monotonic generation checkpoint or append-only/off-host audit anchor before the
service resumes issuance.

Audit records include result, protocol, correlation ID, remote address, policy,
hash OID, serial, certificate thumbprint, elapsed time, and identity fields.
Request-hash logging is configurable. Audit failure is fail-closed by default:
a token is not returned when its audit record cannot be committed to disk.
The local administrative dashboard shows service health, certificate-selection
mode, and recent in-memory history of up to 100 successfully logged timestamp results
from the last 24 hours, including recent users. It shows the newest 50 results
and excludes HTTP or admission failures that never produce an audit event. This
bounded in-memory view clears on application-pool recycle and is not a replacement
for the audit logs on disk.

- Synchronize the host through Windows Time and alert on loss of synchronization
  or clock steps.
- Restrict server administration and back up the configured data directory
  securely as one application-consistent set. Treat issuance state as
  consistency-critical; do not select an older individual `.bak` file or roll the
  state/high-water generation backward during a restore.
- Forward audit logs to append-only or off-host protected storage before local
  retention expires.
- Monitor certificate expiry, private-key availability, disk space, HTTP errors,
  audit-write failures, and health.
- Keep each active instance's serial-number state coherent. Do not clone a live
  data directory into two independently issuing servers.

See [Security Guidance](../.github/SECURITY.md) before exposing the service.
