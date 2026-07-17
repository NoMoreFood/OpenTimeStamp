# Configure Signing Clients

Use the RFC 3161 endpoint for current document and PDF signing tools, and the
legacy endpoint only for clients that explicitly require Microsoft
Authenticode:

```powershell
$rfc3161Url = 'https://tsa.example.com/OpenTimeStamp/timestamp/rfc3161'
$authenticodeUrl = 'https://tsa.example.com/OpenTimeStamp/timestamp/authenticode'
```

The document or code-signing certificate and its private key belong on the
signing workstation; the TSA certificate and private key remain on the server.
Distribute the production TSA chain through the organization's normal trust
policy so clients can validate returned tokens. Do not distribute the
development TSA private key or broadly trust its self-signed certificate.

The desktop products below do not share a reliable way to provide Windows
credentials to a timestamp server. Anonymous authentication is therefore the
interoperable public-endpoint setting; use Windows authentication only after
validating every intended client and deployment mechanism. Prefer HTTPS and
restrict network access rather than enabling Basic authentication, which this
installer deliberately disables.

### Microsoft Office document signatures

Word, Excel, and PowerPoint use the RFC 3161 endpoint for XAdES-T document
signatures. Current Microsoft 365 and supported perpetual Office releases use
registry version `16.0`; the per-user path is the same for 32-bit and 64-bit
Office. Run this as each signing user while the Office applications are closed:

```powershell
$officeVersion = '16.0'
$officeSignatures = "HKCU:\Software\Microsoft\Office\$officeVersion\Common\Signatures"
New-Item -Path $officeSignatures -Force | Out-Null
New-ItemProperty -Path $officeSignatures -Name XAdESLevel `
    -PropertyType DWord -Value 2 -Force | Out-Null
New-ItemProperty -Path $officeSignatures -Name MinXAdESLevel `
    -PropertyType DWord -Value 2 -Force | Out-Null
New-ItemProperty -Path $officeSignatures -Name TSALocation `
    -PropertyType String -Value $rfc3161Url -Force | Out-Null
```

Level 2 selects XAdES-T. Setting both the requested and minimum levels prevents
Office from silently falling back to an untimestamped XAdES-BES signature when
the TSA is unavailable. Values under
`HKCU\Software\Policies\Microsoft\Office\16.0\Common\Signatures` can override
these user settings; deploy the same three values through the Office policy
templates when configuration is centrally managed.

Restart Office, then use `File > Info > Protect Document/Workbook/Presentation >
Add a Digital Signature`, choose the document-signing certificate, and sign.
Open the Signatures pane and its signature details to confirm that the signature
and timestamp validate. Microsoft's current signing UI is described in
[Add or remove a digital signature for Microsoft 365 files](https://support.microsoft.com/en-US/Office/security-privacy/add-or-remove-a-digital-signature-for-microsoft-365-files).

### VBA project signatures

The Visual Basic Editor's built-in signer uses the legacy Authenticode endpoint,
not the RFC 3161 URL. The service must use an RSA TSA certificate, Authenticode
must be enabled, and Windows FIPS policy must permit the legacy protocol. The
per-user registry path is shared by 32-bit and 64-bit Office:

```powershell
$vbaSecurity = 'HKCU:\Software\Microsoft\VBA\Security'
New-Item -Path $vbaSecurity -Force | Out-Null
New-ItemProperty -Path $vbaSecurity -Name TimeStampURL `
    -PropertyType String -Value $authenticodeUrl -Force | Out-Null
New-ItemProperty -Path $vbaSecurity -Name TimeStampRetryCount `
    -PropertyType DWord -Value 3 -Force | Out-Null
New-ItemProperty -Path $vbaSecurity -Name TimeStampRetryDelay `
    -PropertyType DWord -Value 1000 -Force | Out-Null

# SHA-256 VBA signatures; supported by the latest Microsoft 365 Current Channel builds.
New-ItemProperty -Path $vbaSecurity -Name V1HashEnhanced `
    -PropertyType DWord -Value 2 -Force | Out-Null
```

`TimeStampRetryDelay` is in milliseconds. Omit `V1HashEnhanced` on Office builds
that do not support it. In the Office application, open **Developer > Visual
Basic > Tools > Digital Signature**, choose a code-signing certificate, save,
close, and reopen the file to verify the signature. Sign only after the project
is final because editing its code removes the signature. See Microsoft's
[Digitally sign your VBA macro project](https://support.microsoft.com/en-US/Office/vba/digitally-sign-your-vba-macro-project)
for the current UI and registry definitions.

For unattended signing, install the Windows SDK SignTool and Microsoft's current
[Office Subject Interface Packages](https://www.microsoft.com/en-us/download/details.aspx?id=56617).
The download supplies separate x86 and x64 packages; register the package from
its included `readme.txt` and use a SignTool process of the same architecture.
Then use the RFC 3161 endpoint:

```powershell
signtool sign /s My /sha1 <SIGNING-CERTIFICATE-THUMBPRINT> /fd SHA256 `
    /tr https://tsa.example.com/OpenTimeStamp/timestamp/rfc3161 /td SHA256 file.xlsm
```

The repository's automated Excel VBA test currently covers the x86 SIP and x86
SignTool combination. Validate the x64 combination in your environment before
making it a production dependency.

### Adobe Acrobat Continuous, 32-bit and 64-bit

The current Acrobat Continuous interface uses the same timestamp configuration
and per-user registry paths for 32-bit and 64-bit Acrobat. Close Acrobat and
Reader, then configure the current signing user with the supplied helper:

```powershell
.\deploy\Configure-AcrobatTimestamping.ps1 -TimestampUrl $rfc3161Url
```

The helper preserves other timestamp servers, adds or reuses the exact
OpenTimeStamp URL, selects it as the default with SHA-256, and requires timestamp
retrieval to succeed so Acrobat cannot silently fall back to the workstation
clock. It removes Acrobat's alternative hash-OID selector when selecting
SHA-256 so the two settings cannot conflict. It writes only beneath
`HKCU\Software\Adobe\Adobe Acrobat\DC\Security`; the shared HKCU path works for
both Acrobat architectures. For an HTTP-only development endpoint, add
`-AllowInsecureHttp`; the helper limits that exception to loopback URLs. Do not
use it for production.

The equivalent manual setup is:

1. Select **Menu > Preferences > Signatures**.
2. Under **Document Timestamping**, select **More**.
3. Select **Time Stamp Servers > New**, enter `OpenTimeStamp` and the exact RFC
   3161 URL, and leave login credentials disabled when the endpoint uses
   Anonymous authentication.
4. Select the new server, choose **Set Default**, confirm, and close the dialogs.
5. Use **All tools > Use a certificate > Digitally sign**, select the signing
   digital ID, and complete the signature. Acrobat automatically uses the
   default timestamp server.
6. Open the Signature Panel and signature properties and confirm that the signer
   signature and timestamp both validate.

Protected Mode may remain enabled. Adobe treats the PPKLite timestamp exchange as
an Acrobat-originated request, so it does not need a Protected Mode broker rule,
`cTrustedSites` entry, or cross-domain policy. Protected View is separate: a PDF
that remains in its read-only Protected View cannot be signed. Select **Enable All
Features** for a trusted document or have an administrator trust the exact PDF or
source location; trusting the TSA URL does not make an untrusted PDF editable.

No Protected Mode exception is needed for the timestamp server. Do not add the
TSA host to `Privileged\tHostWhiteList`; Adobe documents that preference only for
suppressing URL-navigation dialogs in specific webview and authentication
workflows, not timestamp requests. Do not enable `bUseWhitelistConfigFile` or
create a Protected Mode broker-policy file for this purpose: that mechanism
allows otherwise blocked operating-system actions and is not a URL allowlist.
Likewise, do not add the TSA to `cTrustedSites` or Trust Manager `tHostPerms`;
those settings trust PDF content origins or permit PDF-authored Internet access,
respectively, and would broaden the document trust boundary without enabling the
built-in timestamp provider. For centrally managed clients, deploy the same
per-user `Security` timestamp values with Adobe Customization Wizard or another
user-targeted configuration mechanism rather than running the IIS installer
under a server administrator account. See Adobe's
[timestamp preference reference](https://www.adobe.com/devnet-docs/acrobatetk/tools/PrefRef/Windows/Security.html),
[Protected Mode preference reference](https://www.adobe.com/devnet-docs/acrobatetk/tools/PrefRef/Windows/Privileged.html),
[Trust Manager reference](https://www.adobe.com/devnet-docs/acrobatetk/tools/PrefRef/Windows/TrustManager.html),
and [cross-domain timestamp exemption](https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/xdomain.html).

The **Timestamp** action in **Use a certificate** creates a standalone document
timestamp; it is different from timestamping a certificate-based signer
signature. Adobe's current procedure is
[Add timestamps to PDFs in Acrobat](https://helpx.adobe.com/acrobat/desktop/e-sign-documents/fill-sign-documents/add-time-stamps.html).
The automated repository test requires full Acrobat rather than Reader and tests
the `Adobe.PPKLite` signing interface while detecting either a 32-bit or 64-bit
Acrobat installation. It leaves Protected Mode enabled. An all-files Protected
View policy prevents unattended PDF mutation; in that environment, trust only
the generated test PDF and run that case manually.

For a private production CA, distribute only the intended root and intermediate
certificates or an administrator-approved Acrobat security-settings file. Avoid
enabling Acrobat's broad **Trust ALL root certificates in the Windows Certificate
Store** options merely to make one TSA validate; Adobe notes that these choices
change the document trust boundary. See
[Acrobat signature validation preferences](https://helpx.adobe.com/acrobat/desktop/e-sign-documents/manage-digital-signatures/set-preferences.html).
