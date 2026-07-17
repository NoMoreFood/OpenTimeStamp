# Product signing interoperability tests

`tests\ProductSigning\Run-Tests.cmd` creates representative files, signs each with a temporary
Current User certificate, asks OpenTimeStamp to timestamp the signatures, and
then verifies both the native signature and the embedded timestamp. PowerShell
7.6 or later is required.

Run the defaults from the repository root:

```cmd
tests\ProductSigning\Run-Tests.cmd
```

A run fails if no selected product test passes. Release qualification should
also reject missing prerequisites and already-running products:

```cmd
tests\ProductSigning\Run-Tests.cmd -RequireAllSelectedTests
```

`-Strict` is an alias. The summary reports passed, skipped, and failed counts.

Override the service URLs when IIS is not using the default application path:

```cmd
tests\ProductSigning\Run-Tests.cmd ^
  -Rfc3161Url http://tsa.example.test/OpenTimeStamp/timestamp/rfc3161 ^
  -AuthenticodeUrl http://tsa.example.test/OpenTimeStamp/timestamp/authenticode ^
  -TsaCertificatePath C:\Certificates\OpenTimeStamp-TSA.cer
```

Use `-NonInteractive` to skip the Word test. Word exposes its native document
signature certificate choice through a dialog, so the default run pauses there
and asks you to select the certificate whose name starts with
`OpenTimeStamp Product Signing Test`. The other tests are unattended.
Close Word, Excel, Acrobat, and Reader before starting; a running application is
skipped so the harness cannot disturb an existing session or stale settings.

## What each test covers

| Test | Created artifact | Signing interface | Timestamp protocol | Verification |
| --- | --- | --- | --- | --- |
| Word | `.docx` | Office XML signature | RFC 3161 in XAdES-T | Word and embedded-token checks |
| Excel VBA | `.xlsm` with VBA | Office VBA SIP and SignTool | RFC 3161 | x86 SignTool and Excel `VBASigned` |
| PDF | `.pdf` | Acrobat PPKLite/PAdES | RFC 3161 CMS attribute | Acrobat and embedded-token checks |
| PowerShell | `.ps1` | `Set-AuthenticodeSignature` | Legacy Authenticode | PowerShell, SignTool, and timestamp checks |
| EXE | compiled `.exe` | Windows SDK SignTool | RFC 3161 | SignTool, Authenticode, and execution |

The PowerShell and EXE tests require the native-architecture Windows SDK
SignTool. The Excel test requires the x86 SignTool and Microsoft's Office
Subject Interface Package for VBA projects. The EXE test also requires the .NET
Framework C# compiler. A missing application or tool is reported as `SKIPPED`;
a present product that cannot sign, timestamp, or verify is reported as
`FAILED`. Native compilers, executables, and SignTool operations have a two-minute
default timeout; a timeout terminates the process tree and fails that test.

The PDF test requires full Adobe Acrobat, not Reader. It installs a uniquely
named, user-level folder JavaScript long enough to call Acrobat's supported
PPKLite signing interface, and removes it when the test ends. Close Acrobat and
Reader before running so Acrobat loads that temporary setup without disturbing
an existing session. Protected Mode may remain enabled and the test does not add
a URL or privileged-host exception. If policy opens every PDF in the read-only
Protected View, unattended PDF mutation cannot complete; trust only the generated
PDF for a manual run rather than weakening Protected View or recursively trusting
the output folder.

## Certificate and configuration safety

By default, the harness creates a two-day, exportable 3072-bit RSA development signing
certificate and temporarily places it only in the Current User Personal store.
It deliberately does not add that self-signed identity to a trusted root store,
which would trigger a high-impact Windows trust prompt. Verification therefore
accepts only SignTool's specific untrusted-test-root diagnostic, rejects every
other SignTool error or warning (including a missing timestamp), and independently
checks the signer identity, content/signature integrity, and timestamp token. Pass
`-CertificateThumbprint` for a fully trusted certificate already in Current
User Personal when native trust-chain success is itself under test.

The private-key PFX exists only in the user's temporary directory while Acrobat
runs. The harness removes the PFX, certificate, and named CNG key that it
created. `-KeepTestCertificate` preserves the signing certificate and key for
manual investigation, but never preserves the PFX. Cleanup retries transient
file locks, verifies that credential-bearing files are gone, and fails the run
if any PFX, generated certificate/key, or Acrobat JavaScript cannot be removed.

If the host is forcibly terminated, remove any matching temporary
`OpenTimeStamp-ProductSigning-*.pfx` file and uniquely named `OTS*.js` file under
`%APPDATA%\Adobe\Acrobat\<version>\JavaScripts` before running again.

Word's `XAdESLevel`, `MinXAdESLevel`, and `TSALocation` values and Excel's
`AccessVBOM` value are snapshotted and restored. A conflicting Group Policy
causes the affected test to skip instead of overriding policy. Before restoring,
the harness verifies that each value still equals the value it applied; it
refuses to overwrite a concurrent user or policy change, verifies the restored
state, and reports cleanup or Office shutdown failures as test failures.

For a development OpenTimeStamp deployment, pass the public TSA certificate
created by `deploy\New-DevelopmentTsaCertificate.ps1` with
`-TsaCertificatePath`. If `artifacts\OpenTimeStamp-development.cer` exists, the
harness finds it automatically. The harness does not trust or install that
certificate; it requires each inspectable timestamp token to be signed by that
exact certificate. Production TSA chains should already be trusted according to
your normal client policy.

For fully unattended signing, expose the timestamp endpoints with Anonymous
authentication on an isolated test deployment. The product timestamp clients do
not share one consistent mechanism for supplying Windows credentials. Never use
the temporary signing certificate or these relaxed test assumptions for
production signing.

Each run writes artifacts and `results.json` beneath
`artifacts\ProductSigningTests\<UTC-run-id>`.
