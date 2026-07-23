# Security Guidance

OpenTimeStamp is security-sensitive infrastructure. A signed timestamp can
remain relevant long after the server and certificate have been retired. Review
this document together with your CA/TSA policy, certificate practice statement,
retention requirements, and incident-response process.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the repository maintainers. Do
not include a production private key, authentication token, raw confidential
message imprint, or unredacted production log in a report. Include the affected
version, deployment mode, minimal reproduction, and security impact. If no
private reporting channel is available, ask the maintainers to establish one
before sharing exploit details.

This checkout does not publish a private vulnerability-reporting address. Do
not infer that a public issue tracker is safe for embargoed details; establish a
verified private channel with the maintainers first.

## Security boundaries

- Public timestamp requests are untrusted binary input. IIS and the application
  enforce bounded request sizes and strict DER parsing.
- The timestamp signing private key is the principal high-value secret. The IIS
  worker receives read/sign access to one selected key, not administrative
  rights.
- The configured data directory contains mutable configuration,
  serial-number/time state, and audit logs. The pool can modify this directory
  but can only read application code.
- The administrative UI is a local management surface, not a remotely supported
  control plane.
- A timestamp token proves that the TSA asserted a message imprint at a stated
  time under a policy. It does not prove document authorship, correctness, or
  confidentiality.

## Administrative interface

The supported IIS installation applies four controls to `/admin`: an IIS
allowlist for IPv4 addresses assigned to the server, Windows authentication, an
application local-peer plus exact-host allowlist check, and a required
Windows-group authorization allowlist. IIS 10 IP Security rules accept IPv4 addresses, so
the administrative connection must use IPv4 even though the application also
recognizes IPv6 loopback. Do not weaken any one of these controls merely because
the others exist.

Never expose `/admin` through URL Rewrite, ARR, a load balancer, port forwarding,
or a reverse proxy. A proxy running on the timestamp server will originate its
backend connection from a local address; remote traffic could therefore satisfy
both local-peer checks if the proxy strips the forwarded headers that the
application normally rejects. Do not rely on `X-Forwarded-For` or similar headers
for administrative authorization.

The Windows-group allowlist is required and defaults to `BUILTIN\Administrators`.
Consider replacing that default with a dedicated administrative group, keep its
membership small, and review it periodically. A
local process running as an authorized user is within the administrative trust
boundary. Apply Windows application control and normal server hardening
accordingly.

## Authentication and transport

Anonymous and Windows authentication apply to the public timestamp and health
endpoints. The admin endpoint always uses Windows authentication. The installer
overrides inherited Basic, Digest, Microsoft client-certificate mapping, and IIS
client-certificate mapping authentication to disabled and verifies the effective
values at both paths; a missing configuration section is accepted only when its
Windows role service is confirmed absent. Do not enable other authentication
schemes or accept credentials in application parameters.

Use HTTPS for network access, especially with Windows authentication. Configure
only supported TLS versions and cipher suites through current Windows/IIS policy.
Prefer Kerberos for domain deployments. If NTLM compatibility is required,
constrain and monitor it according to domain policy; the application does not
implement its own password or token authentication.

In Windows mode, verify that audit records contain the expected username, SID,
and authentication type. In anonymous mode they deliberately identify the
caller as anonymous. IIS access logs are supplemental and do not replace the
application audit trail.

## Private keys and certificates

Use a CA-issued, policy-governed TSA certificate with critical timestamping-only
EKU. Prefer a hardware-protected, noninteractive RSA CNG key when operationally
possible and test provider compatibility, including the non-signing health key
access and association check and an explicit RFC 3161 issuance, before production.
The included self-signed certificate script is development-only.

- Store a software key in `LocalMachine\My` and grant read access only to the
  dedicated application-pool identity.
- Never grant `Users`, `Authenticated Users`, `IIS_IUSRS`, or a shared pool broad
  access to the private key.
- Keep the app pool dedicated to OpenTimeStamp; another application in the same
  pool would execute with the same key access.
- Use a non-exportable key when supported. Protect any CA handoff, escrow, and
  backup under documented dual-control procedures.
- Monitor certificate validity and chain status well before expiry. Plan rollover
  and client trust distribution; do not overwrite historical audit identity.
- Treat an unexplained signature, ACL change, key export, or pool-identity change
  as a potential compromise.

The `CurrentUser\My` store is the worker process identity's store, not the
interactive administrator's. Misunderstanding this distinction commonly causes
either outages or overly broad key ACLs. Use `LocalMachine\My` unless a deliberate
service-account profile design requires otherwise.

## Release authenticity

The deployment manifest's hashes detect corruption but do not identify who
published the release. Production installation requires a detached CMS
signature over the manifest's exact bytes and an explicitly pinned release
signer thumbprint. Keep that release-signing identity separate from the TSA
signing certificate and the IIS TLS certificate, and protect its private key
under the organization's release process.

`-AllowUnsignedManifest` disables this authenticity boundary. Use it only for a
development build or an explicitly reviewed legacy deployment, copy the payload
over a trusted channel, and remove the exception for the next controlled
production release. Never place the detached signature inside the manifested
payload or load cryptographic assemblies from an unauthenticated payload.

## Algorithms and FIPS policy

SHA-256, SHA-384, and SHA-512 are the production baseline. MD5, SHA-1, and the
legacy Authenticode protocol exist only for compatibility. Windows FIPS mode
overrides saved configuration at request time: legacy imprints, SHA-1 signing,
and Authenticode are rejected. Do not add a fallback that silently downgrades a
request when policy blocks an algorithm.

Changing FIPS or cryptographic policy is an operating-system security decision,
not an application troubleshooting step. Coordinate it with security owners,
recycle the pool after the change, and validate both an allowed RFC 3161 request
and an expected legacy rejection.

## Audit and state integrity

Keep fail-closed audit writing enabled unless a documented risk decision says
otherwise. If logging fails closed, investigate disk capacity, ACLs, filesystem
health, and log forwarding; do not simply grant broad write permissions.

The issuance state prevents serial reuse and unsafe clock rollback. Back it up
with application-consistent procedures. Restoring an old state while continuing
to issue can duplicate serials or move generation time backward. Stop issuance,
reconcile state and logs, and obtain security approval before a restore or
multi-node topology change.

Local JSONL logs are protected from the pool's application-code directory but
remain writable because retention and append operations require it. Forward
them promptly to storage where the IIS identity cannot alter or delete records.
Protect logged message imprints according to the sensitivity of the underlying
workflow; even a digest can enable confirmation attacks against guessable data.

## Host and IIS hardening

- Patch Windows, .NET Framework, IIS, certificate providers, and build tools.
- Use the dedicated 64-bit integrated application pool and
  `ApplicationPoolIdentity`; enforce one worker process and non-overlapping
  recycling so application-wide admission limits remain exact; do not run it as
  LocalSystem or an administrator.
- Keep write permission limited to the configured data directory and the selected
  private-key ACL.
- Keep the 1 MiB IIS request limit and the equal-or-lower application limit.
- Remove unused IIS modules, bindings, applications, and authentication schemes.
- Restrict network access to intended clients and rate-limit upstream when the
  service is internet-facing. The request limit does not prevent request-flood
  or expensive-signature denial of service.
- Use Windows Time with a trustworthy hierarchy and alert on drift, rollback,
  loss of synchronization, or unexpected source changes.
- Do not place writable user content, scripts, or logs beneath executable web
  paths. Prefer the installer's separate `%ProgramData%` data-directory option.

## Incident response

If key compromise or unauthorized issuance is suspected, stop the application
pool, preserve volatile and durable evidence, restrict access to the host,
contact the issuing CA and TSA policy owner, and follow the certificate
revocation/termination plan. Preserve issuance state, application audit logs,
IIS logs, Windows event logs, certificate-store changes, and relevant time-service
events. Do not delete the suspect certificate or rotate logs before evidence is
captured.

A replacement certificate and clean host do not by themselves resolve the
status of previously issued tokens. Communicate the incident and validation
policy to relying parties under the governing timestamp policy.
