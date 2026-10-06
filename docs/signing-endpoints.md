# Signing Endpoints and Hash Policies

OpenTimeStamp exposes explicit RFC 3161 and legacy Authenticode routes under each IIS application. Each application has its own certificate selection, signing digest, allowed request hashes, RFC policy OIDs, authentication mode, issuance state, audit logs, and request limits. Deploy separate applications when signing needs require different settings. The routes within one application share that application's configuration.

## Select the Protocol and Hash

| Request hash | Imprint length | RFC 3161 support | CMS signing digest |
| --- | --- | --- | --- |
| MD5 | 16 bytes | Explicit compatibility opt-in; blocked by FIPS policy | Unavailable |
| SHA-1 | 20 bytes | Explicit compatibility opt-in; blocked by FIPS policy | Available outside FIPS mode |
| SHA-224 | 28 bytes | Explicit opt-in | Unavailable |
| SHA-256 | 32 bytes | Enabled by default | Available |
| SHA-384 | 48 bytes | Enabled by default | Available |
| SHA-512 | 64 bytes | Enabled by default | Available |

The RFC request's `messageImprint` OID chooses its hash. OpenTimeStamp validates its length and allowlist, preserves the AlgorithmIdentifier and digest in the reply, and echoes a supplied nonce. The application setting **Timestamp signing hash** independently controls the CMS token signature. For example, a SHA-512 request can receive a token signed using SHA-256; the response still contains the original SHA-512 imprint. Choose a separate application if a client also requires a different token-signing digest. SHA-224 can be timestamped because its imprint is supplied by the client; it does not require a Windows SHA-224 CMS signer.

Use `/timestamp/rfc3161` for SignTool `/tr`, Office document signing, and Acrobat. SignTool `/fd` selects the file-signature digest; `/td`, following `/tr`, selects the timestamp request digest. These are distinct from the server's CMS signing digest. Microsoft's [SignTool reference](https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe) describes those options.

```powershell
signtool.exe sign /s My /sha1 <code-signing-thumbprint> /fd SHA256 `
    /tr http://tsa.example.com/TsaModern/timestamp/rfc3161 /td SHA512 application.exe
signtool.exe verify /pa /all /tw application.exe
```

Use `/timestamp/authenticode` for SignTool `/t`, Windows PowerShell's `Set-AuthenticodeSignature`, and the built-in VBA project signer. A legacy request contains the client's signature bytes rather than an RFC hash selector; `/td` does not apply to `/t`. This endpoint requires RSA and is blocked by FIPS policy. Some SignTool builds reject HTTPS timestamp URLs before sending a request, and `Set-AuthenticodeSignature` requires HTTP for its legacy URL. Keep an explicitly configured HTTP binding for clients with that requirement and an HTTPS binding for clients that support it. Verify the installed client's transport rather than assuming its `/tr` or `/t` option implies HTTPS support. See [Client Configuration](client-configuration.md).

Unsupported hashes, disabled hashes, incorrect digest lengths, and unacceptable RFC policy OIDs return DER protocol rejections with HTTP 200. Check the PKI status and verify the token; HTTP success alone is insufficient. There is no automatic protocol-detecting `/timestamp` route. Disabled protocol routes return HTTP 404.

## Deploy Independent Signing Profiles

The following example uses two existing IIS websites: **Timestamp Service** for Anonymous clients, with TLS and an optional HTTP compatibility binding at `tsa.example.com`, and **Restricted Timestamp Service** with only an HTTPS binding at `tsa-internal.example.com`. Publish and sign the release manifest according to [Build and Publishing](build-and-publish.md). Transfer the manifest and its listed release files to the server; keep the publish-only `.opentimestamp-publish.json` ownership marker in the original build staging directory. Install each profile from the same release payload with a distinct application path, pool, deployment root, and data directory:

```powershell
$release = '.\artifacts\OpenTimeStamp'
$releaseSignature = '.\OpenTimeStamp.DeploymentManifest.p7s'
$releaseSigner = '<trusted-release-signing-thumbprint>'

.\deploy\Install-IisApplication.ps1 -SourcePath $release `
    -SiteName 'Timestamp Service' -ApplicationPath '/TsaModern' `
    -AppPoolName 'TsaModern' -PhysicalPath 'C:\inetpub\TsaModern' `
    -DataPath 'C:\ProgramData\TsaModern' -AuthenticationMode Anonymous `
    -AdminHostNames 'tsa.example.com' `
    -ManifestSignaturePath $releaseSignature -TrustedManifestSignerThumbprint $releaseSigner

.\deploy\Install-IisApplication.ps1 -SourcePath $release `
    -SiteName 'Timestamp Service' -ApplicationPath '/TsaLegacy' `
    -AppPoolName 'TsaLegacy' -PhysicalPath 'C:\inetpub\TsaLegacy' `
    -DataPath 'C:\ProgramData\TsaLegacy' -AuthenticationMode Anonymous `
    -AdminHostNames 'tsa.example.com' `
    -ManifestSignaturePath $releaseSignature -TrustedManifestSignerThumbprint $releaseSigner

.\deploy\Install-IisApplication.ps1 -SourcePath $release `
    -SiteName 'Restricted Timestamp Service' -ApplicationPath '/TsaRestricted' `
    -AppPoolName 'TsaRestricted' -PhysicalPath 'C:\inetpub\TsaRestricted' `
    -DataPath 'C:\ProgramData\TsaRestricted' -AuthenticationMode Windows `
    -AdminHostNames 'tsa-internal.example.com' `
    -ManifestSignaturePath $releaseSignature -TrustedManifestSignerThumbprint $releaseSigner
```

Create certificates using the [timestamp signing template](timestamp-certificate-template.md). Grant each dedicated pool access to its own certificate with `Grant-TsaPrivateKeyAccess.ps1`. Configure each application's local `/admin` page independently:

| Setting | TsaModern | TsaLegacy | TsaRestricted |
| --- | --- | --- | --- |
| Protocols | RFC 3161 | Authenticode; RFC 3161 only if required | RFC 3161 |
| Signing key | Dedicated RSA TSA key | Dedicated RSA TSA key | Dedicated RSA TSA key |
| Certificate selection | Manual | Manual | Manual |
| Allowed RFC request hashes | SHA-256, SHA-384, SHA-512 | Add SHA-1 only if an RFC client requires it; MD5 only for an explicitly accepted compatibility requirement | SHA-384, SHA-512 |
| CMS signing digest | SHA-256 | SHA-256, or SHA-1 only for a verified legacy client requirement | SHA-512 |
| RFC policy | Your modern-service policy OID | Your compatibility-service policy OID if RFC is enabled | Your restricted-service policy OID |
| Public authentication | Anonymous | Anonymous | Windows |

The resulting client URLs include `https://tsa.example.com/TsaModern/timestamp/rfc3161`, `http://tsa.example.com/TsaLegacy/timestamp/authenticode` when the compatibility HTTP binding is configured, and `https://tsa-internal.example.com/TsaRestricted/timestamp/rfc3161`. Prefer HTTPS for capable clients. Keep HTTP bindings on the Anonymous site; the Windows-authenticated site must remain HTTPS-only. Windows authentication requires a client that can participate in the configured IIS authentication flow; do not assume SignTool or Acrobat will authenticate just because a browser can.

Never reuse a pool, physical deployment root, or data directory across profiles. The installer rejects a shared pool; distinct deployment roots and data directories preserve independent settings, upgrades, serial allocation, and audit history. Separate profiles using one shared private key are one signing authority and need coordinated serial uniqueness; use distinct keys for independent instances. A URL path is not itself an RFC policy: clients requesting a policy must use an OID accepted by that application's settings. Windows FIPS policy applies to all profiles on that computer, so a separate legacy application cannot bypass it.

## Verify the Endpoints

Check each `/health` independently and exercise the actual client protocol. Health requires every enabled protocol to be usable: an application with legacy Authenticode enabled reports HTTP 503 under Windows FIPS policy even if its modern RFC 3161 requests can still succeed. Disable legacy Authenticode on a profile intended to remain healthy under that policy. For RFC 3161, generate and verify a request using OpenSSL:

```powershell
openssl.exe ts -query -data .\example.bin -sha512 -cert -out .\request.tsq
Invoke-WebRequest -Uri 'https://tsa.example.com/TsaModern/timestamp/rfc3161' `
    -Method Post -ContentType 'application/timestamp-query' `
    -InFile .\request.tsq -OutFile .\response.tsr -UseBasicParsing
openssl.exe ts -verify -queryfile .\request.tsq -in .\response.tsr `
    -CAfile .\approved-root.pem -untrusted .\issuing-chain.pem
```

Repeat with every allowed request hash, and verify rejection of a disabled hash. Check the signer certificate, CMS digest, policy, imprint, nonce, and time against the intended profile. Verify an actual signed file with `/pa /all /tw` for both SignTool timestamp routes. Use [the live IIS qualification harness](testing.md#live-iis-hash-and-endpoint-qualification) in an isolated VM to test endpoint isolation, concurrent requests, protocol errors, and FIPS behavior without changing a production server.
