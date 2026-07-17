# IIS Deployment

The build produces a WiX MSI that uses this same hardened deployment routine.
It prompts for an existing IIS website and the application name used as the URL
root. IIS and its required role services must be installed before the MSI runs;
the package does not add Windows features. See the
[MSI installer guide](../setup/msi/README.md). Continue with the manual workflow
below when the pool, authentication mode, deployment root, or other advanced
settings must be customized.

## Install on IIS

Copy the entire repository `deploy` directory, including
`Deployment.Common.ps1`, and the published payload to the server. In an elevated
Windows PowerShell 5.1 prompt:

```powershell
.\deploy\Install-IisApplication.ps1 `
    -SourcePath .\artifacts\OpenTimeStamp `
    -SiteName 'Default Web Site' `
    -ApplicationPath '/OpenTimeStamp' `
    -AuthenticationMode Anonymous `
    -AllowUnsignedManifest
```

For Windows authentication, use `-AuthenticationMode Windows`. `PhysicalPath`
is a deployment root, not the directory that IIS serves directly. A default
installation has this shape:

```text
C:\inetpub\OpenTimeStamp\
  .opentimestamp-deployment.json
  App_Data\                         mutable, never in a release
    .opentimestamp-data.json
    tsa.config
    issuance.state...
    Logs\
  Releases\
    <release-id>\                   IIS application physical path
      OpenTimeStamp.DeploymentManifest.json
      Web.config
      bin\...
```

On 64-bit Windows, run the installer from a 64-bit PowerShell process; it
rejects a 32-bit WOW64 process before reading or changing IIS configuration.
IIS Shared Configuration must be disabled on the target server. The installer
checks this before installing role services or mutating IIS because its exact
rollback snapshots require the local IIS configuration store.

The IIS installer does not change Office or Acrobat settings. Those settings are
per signing user and normally belong on separate workstations; applying them from
an elevated server installation would write the server administrator's user hive.
Use the client instructions below on each signing workstation.

The installer:

- validates the source manifest and every file before changing IIS, copies only
  manifested files to a new sibling staging directory, writes deployment
  settings, then generates and validates the exact active-release manifest;
- moves that complete staging directory to a new immutable
  `Releases\<release-id>` path and switches the IIS application pointer instead
  of overlaying the live application, so stale files cannot remain active;
- retains the newest five validated immutable releases by default and removes
  older validated releases only after the new release commits; use
  `-RetainReleases` to select another bounded retention count, while malformed or
  unrecognized release-shaped directories are preserved with a warning;
- enables only the IIS leaf services needed by ASP.NET 4.x, Windows
  authentication, request filtering, IP restrictions, HTTP errors/logging, and
  the PowerShell administration provider;
- creates a dedicated `OpenTimeStamp` application pool using
  `ApplicationPoolIdentity`, 64-bit integrated mode, .NET CLR v4.0, one worker
  process, non-overlapping recycling, `AlwaysRunning` startup, no idle timeout,
  and no scheduled periodic recycle, and
  refuses both a target pool and an existing application's actual current pool
  if either is assigned to another IIS application;
- enables site, pool, and ASP.NET service auto-start, registers the
  `OpenTimeStampPreloadClient` provider, and initializes configuration, routes,
  admission controls, and a background health probe before the first request;
- grants the pool read/execute access to the application and modify access only
  to the configured data directory (`App_Data` by default);
- writes the selected mode to the application's immutable
  `AuthenticationMode` setting and to the matching IIS modules;
- explicitly disables and verifies Basic, Digest, Microsoft client-certificate
  mapping, and IIS client-certificate mapping authentication at both paths, or
  verifies that the corresponding role service is absent;
- clears every inherited static MIME mapping because the application serves no
  static files, rejects double-escaped and non-ASCII URLs, permits only GET,
  HEAD, and POST, and caps IIS request bodies at 1 MiB;
- applies the selected public authentication mode; and
- independently requires Windows authentication, a locally assigned IPv4 peer,
  and an exact configured host name for `/admin`.

During a release switch, the installer stops the application's real current pool
and the target pool. A successful installation leaves the selected site and
target pool started so service auto-start can warm the worker immediately and
after future IIS restarts. If a failure occurs before the issuance-state format
commit, the IIS application pointer, always-warm attributes, provider
registration, pool settings, and original site and pool states are rolled back.
A shared current pool is rejected before any stop, because quiescing it would
interrupt unrelated applications. The enforced single-worker and
non-overlapping-recycle settings keep the application-wide admission limits
exact and avoid leaking named-semaphore capacity when a worker terminates while
another worker still holds the same kernel object.

The separately marked data directory survives every release. On an existing
deployment, omitting `-DataPath` or `-AdminHostNames` preserves the current
values. Omitting `-AuthenticationMode` is accepted only when the existing
`web.config` value and effective IIS Anonymous/Windows settings are both valid
and agree exactly; ambiguity fails closed. Pass the mode explicitly to repair an
inconsistent deployment. `-DataPath` selects a location; it does not migrate
state from a previously configured location. Stop issuance and perform an
application-consistent move before changing it.

Upgrades also preserve and validate the five request-concurrency settings:
`TimestampBodyReadTimeoutSeconds`, `TimestampBodyIntakeLimit`,
`TimestampBodyIntakePerClientLimit`, `TimestampProcessingLimit`, and
`TimestampProcessingPerClientLimit`. Per-client limits may not exceed their
global limits. Repair an invalid existing value before upgrading rather than
silently replacing it with a new release default.

The first upgrade from the former flat-directory layout may need explicit data
adoption. An absent, empty, or `.gitkeep`-only data directory is safe bootstrap
scaffolding. An unmarked legacy directory is accepted only when its root
contains the narrowly recognized OpenTimeStamp configuration/OTS1 state names
and its log names match the product format; after reviewing and backing it up,
rerun with `-AdoptExistingDataPath`. A generic `Logs` directory, unexpected
sibling, invalid marker, or other ambiguous non-empty directory is rejected and
cannot be adopted.

As its final durable commit, the installer calls the selected release's
`IssuanceStateStore.Initialize()`. This creates authenticated OTS2 state for a
new installation, validates/repairs an existing authenticated store, or migrates
a valid legacy OTS1 state. A marked data directory with no remaining issuance
artifacts is rejected rather than silently starting a new serial sequence. Once
an OTS1-to-OTS2 transition has committed, the old binary cannot read the new
state, so binary rollback is deliberately suppressed and the new release remains
selected. Never restore `issuance.state.bak` over active state: it can lag a
serial allocation. Recover the complete state set according to your controlled
backup procedure without moving its high-water mark backward.

For stronger separation in production, place mutable data outside the web root:

```powershell
.\deploy\Install-IisApplication.ps1 `
    -SourcePath .\artifacts\OpenTimeStamp `
    -DataPath "$env:ProgramData\OpenTimeStamp" `
    -AdminHostNames 'tsa.example.com' `
    -AuthenticationMode Windows `
    -RequireHttps `
    -ManifestSignaturePath .\OpenTimeStamp.DeploymentManifest.p7s `
    -TrustedManifestSignerThumbprint '<release-signing-certificate-thumbprint>'
```

The installer creates the dedicated data directory and restricts its DACL to
SYSTEM, local Administrators, and the application-pool identity. It refuses a
non-empty unrecognized destination so an accidental path cannot be relabeled or
have its ACL replaced. ACL repair is recursive: protected descendant DACLs are
unprotected, explicit descendant ACEs are removed, and inheritance from the
restricted root is verified. Reapply any intentionally narrower read-only access
needed by an off-host log-forwarding agent after every upgrade, and confirm it
does not expose configuration or issuance state. Reparse points are rejected in
all deployment-controlled paths.

For production, create a dedicated IIS site and exact host-name HTTPS binding,
install its TLS certificate, then install OpenTimeStamp as the child application
shown above and pass `-RequireHttps`. A dedicated site avoids inheriting unrelated
application settings. The installer deliberately does not create bindings or
select a site's TLS certificate: a safe binding needs an operator-selected IP,
host name, port, certificate, and SNI policy, and the existing
`-CertificateThumbprint` parameter identifies the TSA signing certificate, not a
TLS certificate. HTTPS is strongly recommended for all deployments and is
essential when authentication credentials traverse a network. `-RequireHttps`
accepts only a usable HTTPS binding that directly identifies one currently valid
`LocalMachine` certificate with a private key; the installer rechecks bindings
at the durable commit boundary and reports a base URL derived from that binding.

By default, the installer asks ServerManager for only `Web-Asp-Net45`,
`Web-Windows-Auth`, `Web-IP-Security`, `Web-Filtering`, `Web-Http-Errors`,
`Web-Http-Logging`, and `Web-Scripting-Tools`; Windows adds only their required
dependencies. It does not request Static Content, Default Document, Directory
Browsing, WebDAV, CGI, classic ASP, FTP, the remote Management Service, the IIS
Manager GUI, or the broad default `Web-Server` feature set. HTTP logging is kept
as the one non-runtime service needed for security investigation. The installer
never removes a pre-existing IIS feature because another site may need it.

If IIS is already provisioned, pass `-InstallIisFeatures:$false`. The installer
still verifies every required leaf service and reports the missing names without
changing IIS. If Windows reports that role installation needs a restart, restart
the server and rerun the installer before serving requests.

## Development Certificate

`New-DevelopmentTsaCertificate.ps1` creates a self-signed, non-exportable RSA
certificate with a critical, timestamping-only EKU and a seven-day lifetime. It
does not create an ML-DSA certificate. It is explicitly for development and
validation, is limited to at most 30 days, and is not added to a trusted root
store. Certificate creation, optional public export, and optional key-ACL grant
are one transaction: a failure removes the newly created certificate/private key,
restores an applied key ACL when it still matches, and removes staged export
files.

Create the IIS pool first, then run this in an elevated prompt:

```powershell
$tsa = .\deploy\New-DevelopmentTsaCertificate.ps1 `
    -StoreLocation LocalMachine `
    -GrantToIdentity 'IIS AppPool\OpenTimeStamp' `
    -ExportPublicCertificatePath .\artifacts\OpenTimeStamp-development.cer

$tsa | Format-List
```

Open `http://127.0.0.1/OpenTimeStamp/admin` locally. For HTTPS administration,
use an exact site binding host name or one supplied with `-AdminHostNames`, and
issue the IIS TLS certificate for that name. The installer also allows
`localhost`, IPv4/IPv6 loopback, the short machine name, and the computer FQDN at
the application layer; the IIS IP restriction requires the connection itself to
arrive over IPv4 from an address assigned to this server. Select `LocalMachine`
and the returned thumbprint. Because this certificate is deliberately
self-signed and untrusted, check **DEVELOPMENT ONLY — allow a certificate whose
chain is not trusted or whose revocation status cannot be verified** before
saving. Clear that bypass before production and select a certificate whose chain
and revocation status validate normally. Configure a timestamp policy OID owned
by your organization for production. A made-up OID must not be published as an
organizational policy.

Do not use the development key in production, lengthen its lifetime, export its
private key, or silently trust it on client fleets. Delete it from
`LocalMachine\My` after testing.

## Production TSA certificate

Obtain a certificate under your organization's timestamp policy and CA
governance. An eligible certificate must:

- be currently valid and include a private RSA signing key, or include a pure
  ML-DSA-44, ML-DSA-65, or ML-DSA-87 private signing key for an RFC 3161-only
  configuration on an operating system whose provider supports it;
- have digital-signature key usage;
- have the critical extended key usage `1.3.6.1.5.5.7.3.8` (`timeStamping`) as
  its only EKU, as required for an RFC 3161 TSA certificate; and
- have a chain that clients can validate for the intended lifetime and policy.

The legacy Authenticode endpoint must be disabled when an ML-DSA certificate is
selected. Any configuration that enables Authenticode requires an RSA key.

Install the certificate and chain into `LocalMachine\My` (recommended), then
grant only the application-pool identity access to its private key:

```powershell
.\deploy\Grant-TsaPrivateKeyAccess.ps1 `
    -Thumbprint '0123456789ABCDEF0123456789ABCDEF01234567' `
    -Identity 'IIS AppPool\OpenTimeStamp'
```

Alternatively, pass `-CertificateThumbprint` to
`Install-IisApplication.ps1` to grant the ACL during installation; certificate
selection still occurs on the local admin page. The helper supports inbox
Windows RSA CNG and RSA CSP machine-key providers and changes only the selected
private-key file ACL. ML-DSA requires a persisted CNG machine key in the
Microsoft Software Key Storage Provider; the helper locates it through stable
Windows Crypt32 and NCrypt APIs. The target must resolve to a
dedicated IIS application-pool virtual SID; shared service accounts and broad
targets such as `IIS_IUSRS` or `NETWORK SERVICE` are rejected. The helper also
fails by default when an owner or allow ACE gives key-usable rights to any
principal other than SYSTEM, BUILTIN\Administrators, or the requested pool
identity. Remove those exceptions after review whenever possible.
`-AllowBroadExistingKeyAcl` (or the same installer switch) explicitly accepts
and preserves those risks; it does not make a key with unrelated access safe.

The administrative page enumerates eligible certificates from both
`LocalMachine\My` and the `CurrentUser\My` store of the account actually running
the worker process. Manual selection pins one listed certificate. Automatic
selection periodically re-evaluates both stores, considers profile, endpoint
and digest compatibility, private-key access, validity, and configured trust
policy, then uses the eligible certificate with the latest expiration. Ties
prefer `LocalMachine\My` and then the normalized thumbprint. Import a replacement
and grant its key to the application-pool identity before expecting automatic
selection to adopt it. `CurrentUser` does **not** mean the interactive
administrator's store. The installer enables profile loading, but a user-store
certificate must still be created or imported while running as that exact pool
identity. For IIS virtual accounts, `LocalMachine\My` plus a narrow private-key
ACL is substantially easier to operate and audit.

## Validate a Deployment

Check health locally. Add `-UseDefaultCredentials` in Windows mode:

```powershell
Invoke-WebRequest `
    -Uri 'http://localhost/OpenTimeStamp/health' `
    -UseBasicParsing
```

Health is cached for 30 seconds and checks configuration, the effective FIPS
gate, issuance-state and audit writability, plus a small private-key signature
probe using the configured CMS digest. Use a noninteractive Windows key provider
so health and issuance cannot block on a UI or PIN prompt.

Post an existing DER RFC 3161 request and save the binary response:

```powershell
Invoke-WebRequest `
    -Uri 'http://localhost/OpenTimeStamp/timestamp/rfc3161' `
    -Method Post `
    -ContentType 'application/timestamp-query' `
    -InFile .\request.tsq `
    -OutFile .\response.tsr `
    -UseBasicParsing
```

Windows SDK SignTool can validate both client flows. `/tr` and `/td` select RFC
3161; `/t` selects the legacy Authenticode service:

```text
signtool timestamp /tr http://server/OpenTimeStamp/timestamp/rfc3161 /td SHA256 signed-file.exe
signtool timestamp /t  http://server/OpenTimeStamp/timestamp/authenticode signed-file.exe
```

Also verify the returned token's signature, certificate chain, policy OID,
message imprint, nonce (when supplied), and generation time with an independent
client before production use.
