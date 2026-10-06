# Testing

## Automated Regression Suite

The standard build runs the discoverable MSTest suite and the deployment and
packaging regression suite after compilation:

```powershell
.\build\Build.ps1 -Configuration Debug
```

Use `-SkipTests` only when a compile-only diagnostic is intentional.

## Product Signing Interoperability

On a Windows client with PowerShell 7.6, run this from the repository root:

```cmd
tests\ProductSigning\Run-Tests.cmd
```

The harness creates, signs, timestamps, and verifies representative Word, Excel
VBA, PDF, PowerShell, and EXE artifacts. Missing products are skipped. The Word
test uses its native signing dialog; pass `-NonInteractive` to skip that one
test. A run fails when no selected test passes. Pass
`-RequireAllSelectedTests` (alias `-Strict`) when any skipped selected test must
also fail, as in release qualification.

See the [detailed product-signing test guide](../tests/ProductSigning/README.md)
for prerequisites, URL overrides, certificate handling, and the exact
verification performed for each format.

## Live IIS Hash and Endpoint Qualification

Use a disposable Windows Server VM with IIS and a checkpoint. Attach its network adapter only to a private virtual switch, without external connectivity; native timestamp clients can need a usable Windows network stack even for loopback requests. Install the current published payload as separate IIS applications using the deployment script; assign each its own pool, deployment root, data directory, TSA key, and policy OID. Configure RSA token signing with SHA-1, SHA-256, SHA-384, and SHA-512 in different applications, vary their request hash allowlists, enable Windows authentication on one profile, and disable Authenticode on one. SHA-1 and MD5 are compatibility fixtures, not production defaults. See [Signing Endpoints and Hash Policies](signing-endpoints.md).

`tests/LiveIis/TimestampEndpointChecks.cs` exercises the real HTTP endpoints. Its PowerShell launcher only compiles and starts the C# verifier. The checks cover all six request hashes, NULL and absent algorithm parameters, nonce and imprint preservation, certificate inclusion, policy and signer isolation, DER rejections, HTTP limits, authentication, concurrent requests, native EXE signing, and PowerShell legacy signing. OpenSSL independently verifies granted RFC replies; Windows SDK SignTool verifies actual timestamped signatures. No server settings or certificate stores are modified by the verifier itself. Native signing creates disposable files and requires a test code-signing certificate with a private key.

Build the server and compile the verifier on the build computer:

```powershell
.\build\Publish.ps1 -Configuration Release
.\tests\LiveIis\Invoke-TimestampEndpointChecks.ps1 `
    -BinaryDirectory .\artifacts\OpenTimeStamp\bin `
    -OutputDirectory .\artifacts\EndpointChecks -CompileOnly
```

Copy the complete `EndpointChecks` directory into the VM along with OpenSSL, its runtime dependencies, Windows SDK SignTool, and an explicit UTF-8 JSON manifest. Configure HTTPS and trust only the VM's fixture TLS, TSA, and code-signing certificates inside that VM. The verifier requires loopback URLs and does not override TLS validation. A profile manifest has this shape; replace every example path, thumbprint, and policy with the disposable deployment's actual values:

```json
{
  "FipsEnabled": false,
  "OpenSslPath": "C:\\EndpointLab\\openssl\\openssl.exe",
  "SignToolPath": "C:\\EndpointLab\\signtool.exe",
  "SigningCertificateThumbprint": "<fixture-code-signing-thumbprint>",
  "CertificateRequestFile": "C:\\EndpointLab\\timestamp-signing.req",
  "Profiles": [
    {
      "Name": "modern",
      "BaseUrl": "https://localhost:8443/TsaModern",
      "NativeClientBaseUrl": "http://127.0.0.1:8080/TsaModern",
      "SigningHash": "SHA256",
      "PolicyOid": "1.3.6.1.4.1.55555.201",
      "CertificateFile": "C:\\EndpointLab\\modern.cer",
      "CertificatePemFile": "C:\\EndpointLab\\modern.pem",
      "AllowedHashes": ["SHA256", "SHA384", "SHA512"],
      "AuthenticodeEnabled": true,
      "WindowsAuthentication": false
    }
  ]
}
```

Supply additional profiles in the `Profiles` array to exercise different configurations simultaneously. `CertificateFile` is the public DER TSA certificate and `CertificatePemFile` is its PEM representation. `CertificateRequestFile` is optional; generate it using the [documented enrollment INF](examples/timestamp-signing.inf) and `certreq -new` to check the actual machine request's key size, critical EKU, end-entity constraints, and request signature. `NativeClientBaseUrl` is optional and selects the transport used by SignTool; an HTTP value also enables PowerShell's legacy transport test. Direct protocol probes still use `BaseUrl` and validate HTTPS normally. The example policy OID is test data; production uses your authority's assigned policies.

In the VM, use a new output directory for each pass:

```powershell
C:\EndpointChecks\TimestampEndpointChecks.exe `
    C:\EndpointLab\manifest.json C:\EndpointLab\results-normal
```

The verifier reports progress after every check, applies native-tool and HTTP deadlines, writes `results.json`, and returns a failing exit code for any failed check. Keep the server's `MaxRequestBytes` at 65,536 for this qualification. Each profile must accept SHA-256 for the concurrent progress check; include SHA-384 and SHA-512 profiles as appropriate. Its cryptographic receipts must use zero published accuracy and `Ordering = false`, matching the normal defaults.

After the normal pass, enable Windows FIPS policy **only in the disposable VM**, stop and restart all test pools, set `FipsEnabled` to `true` in a second manifest, and rerun. Require MD5/SHA-1 imprint rejection, SHA-1 signing rejection, unavailable Authenticode, and continued modern RFC issuance. Disable the test policy, restart the pools, and run a recovery pass with the original manifest. This verifies the application's effective policy gate, not formal provider certification. Restore the VM checkpoint after collecting results so test certificates, trust changes, policy, and deployments do not remain active. Publishing a production AD CS template and verifying its CA-issued certificate and revocation endpoints remain separate PKI acceptance steps.
