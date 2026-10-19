# Windows Signing Client Settings

OpenTimeStamp has two timestamp protocols. Most document and package tools use `/timestamp/rfc3161`; the VBA editor and PowerShell's native Authenticode signer use `/timestamp/authenticode`. There is no shared Windows preference that selects a TSA for every signing application. Windows clock synchronization is a separate service.

The setup scripts run in Windows PowerShell 5.1 and PowerShell on Windows. They configure application preferences, not the IIS server. Supply the deployed IIS application URL, for example `https://tsa.example.com/OpenTimeStamp`. Use an RSA TSA signing profile for broad interoperability. The legacy endpoint also requires Authenticode to be enabled and permitted by the server's Windows FIPS policy. Desktop signing clients need network access to the TSA and the certificate chain's revocation endpoints; a browser GET against a POST timestamp URL is not a signing test.

## Application Coverage

| Application or workflow | Required setting | Setup support |
| --- | --- | --- |
| Word, Excel, PowerPoint document signatures | `TSALocation`, `XAdESLevel=2`, `MinXAdESLevel=2` in Office `Common\Signatures`; RFC 3161 | `Office`: sets and verifies per-user preferences; refuses conflicting Office policy |
| Office VBA editor | `TimeStampURL`, optional retry count and delay under `Microsoft\VBA\Security`; legacy Authenticode | `Vba`: sets and verifies the shared VBA preferences |
| Adobe Acrobat and Reader, Continuous or Acrobat Classic | Timestamp server list, default provider URL, SHA-256, required property retrieval; RFC 3161 | `Acrobat` or `AcrobatReader`: sets the selected preference branch |
| LibreOffice Writer, Calc, Impress, Draw PDF export | `TSAURLs` in the user profile; choose the URL on the PDF export Digital Signatures tab | `LibreOffice`: registers the TSA; reports that selection is still required |
| PDF-XChange Editor | Timestamp server preset, then select that preset in Sign Document | `PdfXChange`: merges a preset; reports that selection is still required |
| Foxit PDF Editor and Reader | Add the RFC 3161 server under Time Stamp Servers, select Set Default, permit the timestamp connection | Reports manual configuration instructions; no documented stable registry schema established |
| Nitro PDF Pro | Add the RFC 3161 server, enable Acquire timestamp from attestable server, select Set Default | Reports manual instructions; no documented stable registry schema established |
| Bluebeam Revu | Confirm custom TSA support for the installed release with Bluebeam | Reports a limitation; reviewed vendor signing/preferences documentation does not establish a custom RFC 3161 setup interface |
| Windows SDK SignTool: EXE, DLL, MSI, CAB, MSIX/AppX, PowerShell scripts | `/tr <RFC3161 URL> /td SHA256 /fd SHA256` | HTTP argument helper; signing wrapper supplies validated HTTPS transport |
| PowerShell `Set-AuthenticodeSignature` | `TimestampServer=<legacy URL>`, `HashAlgorithm=SHA256` | HTTP parameter helper; signing wrapper supplies validated HTTPS transport |
| NuGet CLI and `dotnet nuget sign` | Timestamper URL and timestamp hash algorithm; RFC 3161 | Signing argument helper |
| Visual Studio 2026/MSBuild ClickOnce manifests | Project or publish-profile `ManifestTimestampUrl`; RFC 3161 | `VisualStudio`: updates the explicitly selected project or publish profile |
| Visual Studio Code | Manual workspace signing task invoking the signing wrapper | `VisualStudioCode`: preserves existing tasks, inputs, comments, and Workspace Trust |
| Mage manifest signing | `-TimestampUri <RFC3161 URL> -Algorithm sha256RSA` | Signing argument helper; validate the installed SDK's manifest signer |
| Java `jarsigner` | `-tsa <RFC3161 URL> -tsadigestalg SHA-256` | Signing argument helper; TSA trust must also be available to Java |
| Inno Setup | Define a SignTool command using `/tr` and `/td`; select it in the `.iss` project | Project/compiler configuration described below |
| NSIS | Sign the output installer and generated uninstaller with SignTool | Build pipeline configuration described below |
| WiX | Sign the appropriate MSI, CAB, and bundle outputs with SignTool | Build pipeline configuration; no universal TSA registry preference |
| Advanced Installer | Digital Signature settings: timestamp service URL or a custom SignTool command | Project configuration; use the explicit RFC 3161 SignTool command |
| InstallShield IDE and Standalone Build | Existing `DigitalSignature` timestamp attributes in that installation's `Settings.xml`; enable release signing separately | `InstallShield`: changes the explicitly selected settings file, with a backup |
| AutoCAD drawing signatures | Autodesk's `timesrvr.txt` time-service list | The reviewed Autodesk mechanism does not establish an RFC 3161 HTTP TSA interface; do not substitute an OpenTimeStamp endpoint into this list |
| Adobe Acrobat Sign cloud workflows | Account-level custom provider enabled by Adobe Support | Configure the cloud account; Windows workstation preferences do not control this workflow |

The table covers common document, PDF, code, package, and installer signing workflows. Applications without an established configuration interface are not reported as automatically configured. A saved PDF preset or TSA list entry is registration, and does not prove that an actual signature contains a trusted timestamp.

## Application and Signing Architecture

The setup scripts can run in x86 or x64 PowerShell on Windows. Office, VBA, and Adobe preferences beneath the selected user's `Software` hive are shared between application architectures. They must not be copied into an invented `WOW6432Node` user branch. Machine application discovery examines both registry views, and developer-tool discovery also uses Visual Studio's installer inventory and VS Code's system and user installation locations. [Microsoft's registry redirection reference](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys) identifies the shared user and application-discovery paths.

| Target | Architecture behavior |
| --- | --- |
| Office documents and VBA | x86 and x64 Office use the same preferences. For SDK signing through the Office SIP, match PowerShell, SignTool, and the installed SIP architecture. |
| Acrobat and Reader | x86 and x64 use the same selected product preference branch. Unified Reader using `Acrobat.exe` uses `Acrobat`; separate Reader using `AcroRd32.exe` uses `AcrobatReader`. |
| LibreOffice | Both architectures use the same roaming profile format. Supply `SettingsPath` for a separate or portable profile. |
| PDF-XChange | Both architectures use the same preset format. Supply `PresetPath` for portable or separate profiles. Both executable names are recognized. |
| InstallShield | Supply the existing `Settings.xml` for each intended IDE or Standalone Build installation, edition, and language. Its installation directory need not match the setup PowerShell architecture. |
| Visual Studio 2026 | The IDE runs on 64-bit Windows and can build x86 or x64 outputs. ClickOnce timestamp properties apply to both build platforms. |
| VS Code | Current Windows releases support 64-bit systems. Signing tasks can explicitly launch x86 or x64 PowerShell on 64-bit Windows. |
| SignTool and PowerShell | x86 and x64 signers can sign x86 or x64 PE files; architecture-specific SIPs and key providers must be available to the signing process. |

Visual Studio's [system requirements](https://learn.microsoft.com/en-us/visualstudio/releases/2026/vs-system-requirements) exclude a 32-bit IDE installation. VS Code's [architecture support](https://code.visualstudio.com/docs/supporting/faq#_windows-32bit-versions) excludes current 32-bit Windows releases of the editor. These limits concern the editor itself, rather than the architecture of the application being built or signed.

## Configure a Workstation

Close the applications being configured. Run as the signing user; an elevated session started with a different administrator account has that administrator's HKCU. Preview and then apply the settings:

```powershell
$setup = '.\tools\deploy\Configure-SigningClients.ps1'
$server = 'https://tsa.example.com/OpenTimeStamp'
& $setup -ServerUrl $server -WhatIf
& $setup -ServerUrl $server
```

HTTPS is accepted by default. To use an HTTP endpoint on this computer or another computer, add `-AllowInsecureHttp`:

```powershell
& $setup -ServerUrl 'http://tsa.example.com/OpenTimeStamp' -Applications Office,Vba,Acrobat -AllowInsecureHttp
```

The default `Detected` selection discovers applications from PATH and Windows App Paths in the user and machine registry, including both registry layouts. It does not scan arbitrary portable installation folders. Explicitly select applications when discovery is incomplete or when preconfiguring a user:

```powershell
& $setup -ServerUrl $server -Applications Office,Vba,Acrobat
& $setup -ServerUrl $server -Applications AcrobatReader
& $setup -ServerUrl $server -Applications Acrobat -AcrobatVersion 2024
```

For LibreOffice profiles or PDF-XChange portable installations, specify the settings file on that computer:

```powershell
& $setup -ServerUrl $server -Applications LibreOffice `
    -LibreOfficeSettingsPath 'C:\Users\Signer\AppData\Roaming\LibreOffice\4\user\registrymodifications.xcu'
& $setup -ServerUrl $server -Applications PdfXChange `
    -PdfXChangePresetPath 'C:\Users\Signer\AppData\Roaming\PDF-XChange\PDF Editor\Presets\TimeStampServer.presets'
```

PDF-XChange profile names differ between installation families. The helper considers `%APPDATA%\PDF-XChange\PDF Editor` and `%APPDATA%\Tracker Software\PDFXEditor\3.0`. When both or neither exists, supply the intended path or create an exported preset and import it in the Editor. The current path is established by [PDF-XChange support's profile guidance](https://forum.pdf-xchange.com/viewtopic.php?t=49730); the timestamp JSON schema and import/deployment mechanism are documented by [PDF-XChange support](https://forum.pdf-xchange.com/viewtopic.php?t=31122).

InstallShield uses an installation-level settings file, shared by builds using that installation. Select it explicitly from an elevated prompt while the IDE and build processes are closed:

```powershell
& $setup -ServerUrl $server -Applications InstallShield `
    -InstallShieldSettingsPath 'C:\Program Files (x86)\InstallShield\2025\Support\0409\Settings.xml'
```

Use the actual edition and language path on the target computer. The helper changes existing `/DevStudio/Build/DigitalSignature` attributes: `Timestamp` receives the Authenticode URL; `TimestampRFC3161`, when already present, receives the RFC 3161 URL. It refuses files with no recognized timestamp selector and does not invent missing attributes. [Revenera documents the installation-wide Timestamp setting](https://docs.revenera.com/installshield31helplib/helplibrary/SettingsXML-Timestamp.htm) and [separate IDE and Standalone Build settings locations](https://docs.revenera.com/installshield31helplib/helplibrary/SettingsXML.htm). Choose the required release-signing method and digest in InstallShield, and verify the built signature. InstallShield is configured only through explicit application selection.

Configure another signed-in user's loaded profile with `-UserSid`. No offline hives are loaded, and no all-user registry setting is invented:

```powershell
& $setup -ServerUrl $server -Applications Office,Vba,Acrobat `
    -UserSid 'S-1-5-21-111-222-333-1001'
```

For a remote computer with PowerShell remoting already enabled, use:

```powershell
& $setup -ServerUrl $server -ComputerName 'SIGNING-PC01' `
    -Applications Office,Vba,Acrobat -UserSid 'S-1-5-21-111-222-333-1001' -WhatIf
& $setup -ServerUrl $server -ComputerName 'SIGNING-PC01' `
    -Applications Office,Vba,Acrobat -UserSid 'S-1-5-21-111-222-333-1001'
```

Optional `-Credential` uses an explicit remoting account. Without `-UserSid`, the authenticated remoting account is the signing user being configured. A remote `-WhatIf` previews the computer-level action without connecting. Helper sources are sent in memory, so the repository does not need to be copied to the remote computer. Alternate file paths are interpreted on the target. Cross-user setup needs permission to modify that user's hive and profile files; redirected AppData must also be accessible from the execution account. Remoting does not configure WinRM or change firewall rules.

The entry script returns `Configured`, `SelectionRequired`, `ProjectRequired`, `ManualReview`, `NotDetected`, or local `WhatIf` results, along with the computer, user SID, endpoints, and helper details. A failed helper produces a `Failed` record and the entry script terminates with an error after processing the selected applications. Successful applications remain configured. Registry helpers roll back their own partial writes; file helpers preserve the original file beside it as the returned `BackupPath` and replace it atomically. Restore a file backup while the application is closed. Repeat setup reuses existing matching entries. `-AllowSigningWithoutTimestamp` permits fallback for Office document and Adobe signatures; it does not add a fail-closed feature to VBA, LibreOffice, or PDF-XChange.

The individual `Configure-OfficeTimestamping.ps1`, `Configure-AcrobatTimestamping.ps1`, `Configure-LibreOfficeTimestamping.ps1`, `Configure-PdfXChangeTimestamping.ps1`, and `Configure-InstallShieldTimestamping.ps1` helpers also run independently from the `deploy` directory. Keep `ClientConfiguration.Common.ps1` beside the helpers that use it.

## Exact Office and Adobe Preferences

Office document preferences are under `HKCU\Software\Microsoft\Office\16.0\Common\Signatures`: `TSALocation` is `REG_SZ`; `XAdESLevel` and `MinXAdESLevel` are `REG_DWORD`. The requested and minimum level are both 2, requiring XAdES-T. The helper checks the same values under `HKCU\Software\Policies\Microsoft\Office\16.0\Common\Signatures` before writing. Update conflicting organizational policy through its normal management mechanism. [GlobalSign's Office integration instructions](https://support.globalsign.com/digital-certificates/digital-signing/add-timestamping-microsoft-office-2010-2013-2016-2019) describe the TSA URL and XAdES level. This repository's Word signing test exercises these settings against OpenTimeStamp.

The VBA editor reads `HKCU\Software\Microsoft\VBA\Security\TimeStampURL` (`REG_SZ`), `TimeStampRetryCount` (`REG_DWORD`, helper default 3), and `TimeStampRetryDelay` (`REG_DWORD`, helper default 1000 milliseconds). These settings apply to the built-in VBA signer, not Office package/document signing. Microsoft documents the [VBA timestamp settings](https://support.microsoft.com/en-US/Office/vba/digitally-sign-your-vba-macro-project). Optional signature-format and hash policies are separate choices; these helpers preserve them. For unattended VBA signing, [Microsoft's Office SIP guidance](https://devblogs.microsoft.com/microsoft365dev/upgrade-signed-office-vba-macro-projects-to-v3-signature/) supports a different workflow through SignTool; use its RFC 3161 parameters and the correct SIP architecture.

Adobe preferences are under `HKCU\Software\Adobe\Adobe Acrobat\<branch>\Security` or `HKCU\Software\Adobe\Acrobat Reader\<branch>\Security`. The script writes server-list `tName`, `tServer`, and `bAuthRequired` beneath `cPPKHandler\cTimeStampServers\cN`; it selects the provider with null-terminated ASCII `sURL` (`REG_BINARY`) and authentication flags beneath `cASPKI\cAdobe_TSPProvider`, chooses SHA-256 with `iHashAlgo=2`, removes the alternative `sHashAlgo` selector, and sets `cASPKI\cASPKI\cSign\bReqSigPropRetrieval=1`. The [Adobe preference reference](https://www.adobe.com/devnet-docs/acrobatetk/tools/PrefRef/Windows/Security.html) explains the server list, default provider, hash selection, and retrieval requirement. Protected Mode, Protected View, and broad trust settings are independent of TSA selection.

LibreOffice's `TSAURLs` is the string-list property under `/org.openoffice.Office.Common/Security/Scripting` in `registrymodifications.xcu`. The [configuration schema](https://github.com/LibreOffice/core/blob/master/officecfg/registry/schema/org/openoffice/Office/Common.xcs) defines the property. Registering the URL exposes it in the TSA list; [PDF export still requires selecting a certificate and TSA](https://help.libreoffice.org/latest/en-US/text/shared/01/ref_pdf_export_digital_signature.html). System-managed LibreOffice configuration may override user preferences, so check the effective list in the application.

Adobe may separately prompt to permit the timestamp network connection. After closing Adobe, `Configure-AdobeTimestampNetworkAccess.ps1 -TimestampUrl <RFC3161 URL>` explicitly adds its hostname to the custom Internet-access list. Adobe matches this permission across schemes and ports on that hostname; use a dedicated TSA hostname when that scope matters. The entry script exposes the same operation through `-AllowAdobeTimestampNetworkAccess`. Other host rules and unknown-site restrictions remain in place; a block-all preference becomes a custom list that blocks unknown sites. The helper refuses a conflicting policy that prevents retaining that restriction. This does not create a privileged document location or disable sandboxing. See [Adobe's Internet-access preferences](https://www.adobe.com/devnet-docs/acrobatetk/tools/PrefRef/Windows/TrustManager.html). Unified Acrobat Reader installations that use `Acrobat.exe` use the `Acrobat` preference branch.

Protected View is read-only in Adobe and Office. A document must become trusted and editable before it can accept a signature. Timestamp setup does not unblock downloaded files or alter Protected View and macro policies. LibreOffice macro restrictions are independent of signed PDF export; keep the intended macro security level. PDF-XChange signing must also respect the document's modification permissions and any centrally managed application policy.

## Developer Workspaces

Visual Studio timestamping belongs to the selected ClickOnce project or publish profile. Assembly strong-name signing has no timestamp-server setting. Configure the profile used to publish the application:

```powershell
.\tools\deploy\Configure-SigningClients.ps1 -ServerUrl https://tsa.example.com/OpenTimeStamp `
    -Applications VisualStudio -VisualStudioProjectPath C:\src\App\Properties\PublishProfiles\Production.pubxml
```

The helper preserves signing enablement, certificate selection, platform conditions, and unrelated project properties. Enable ClickOnce manifest signing and choose its certificate separately. [Visual Studio's manifest signing workflow](https://learn.microsoft.com/en-us/visualstudio/ide/how-to-sign-application-and-deployment-manifests) describes the timestamp URL field. Native executable signing uses the SignTool wrapper; NuGet and VSIX signing use their package tools. A ClickOnce property does not configure those other workflows.

For VS Code, add a manual workspace task:

```powershell
.\tools\deploy\Configure-SigningClients.ps1 -ServerUrl https://tsa.example.com/OpenTimeStamp `
    -Applications VisualStudioCode -VSCodeWorkspacePath C:\src\App -VSCodePowerShellArchitecture x64
```

Open that workspace and use **Terminal > Run Task** to select the generated OpenTimeStamp task. Supply the full input-file path and signing certificate thumbprint. The default task signs PowerShell files. For executables, add `-VSCodeSigningTool SignTool -VSCodeSignToolPath <SDK-SIGNTOOL-PATH>`. Choose `-VSCodePowerShellArchitecture x86` when the installed SIP or key provider requires a 32-bit signing process. The task uses process arguments and does not bypass execution policy or run automatically on folder opening.

The task references the existing signing wrapper. Keep it beside `ClientConfiguration.Common.ps1` at that location. For a remote computer, supply `-VSCodeSigningScriptPath` identifying the installed wrapper on the target. Setup preserves existing tasks, inputs, comments, and trailing commas; conflicting task labels are rejected without writing. The standalone helper accepts `-TaskLabel` to add another named signing configuration. IDE entries return `ProjectRequired` until their project or workspace paths are supplied.

VS Code [Restricted Mode](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) gates task execution. Setup leaves that protection enabled: the user must trust the intended workspace through the normal workflow before running its signing task. [VS Code's task documentation](https://code.visualstudio.com/docs/debugtest/tasks) defines the process task and input-variable format.

## Tools Configured for Each Signing Operation

Use the signing wrapper for SignTool or native PowerShell with either transport:

```powershell
.\tools\deploy\Invoke-TimestampSigning.ps1 -ServerUrl $server -LiteralPath '.\Application.exe' `
    -CertificateThumbprint '<SIGNING-CERTIFICATE-THUMBPRINT>' -Tool SignTool `
    -SignToolPath 'C:\Path\To\signtool.exe'
.\tools\deploy\Invoke-TimestampSigning.ps1 -ServerUrl $server -LiteralPath '.\Script.ps1' `
    -CertificateThumbprint '<SIGNING-CERTIFICATE-THUMBPRINT>' -Tool PowerShell
```

Windows SDK SignTool rejects HTTPS timestamp URLs in the tested SDKs. Native Windows PowerShell also rejects them. The wrapper starts a temporary server bound exclusively to `127.0.0.1`, with a random port and request path, and forwards timestamp requests to the configured HTTPS endpoint with TLS certificate validation. It uses TLS 1.2, rejects redirects, bounds request and response sizes, and removes the local server after signing. It does not create a firewall exception, install certificates, or change application protection settings. Windows PowerShell needs .NET Framework 4.8. Supply `-CertificateStoreLocation LocalMachine` for a machine signing key and optionally `-ExpectedTsaThumbprint` to require a specific timestamp signer.

The wrapper signs a temporary sibling file and verifies the signer signature and timestamp before atomically replacing the input. An unavailable TSA, untrusted TLS certificate, failed signature, or changed input leaves the original file intact. `-WhatIf` previews signing without creating a listener or modifying the file. HTTP still requires `-AllowInsecureHttp`.

For a native SignTool command using HTTP, the argument helper returns `/tr`, `/td SHA256`, and `/fd SHA256`. It refuses an HTTPS `SignTool` request with directions to the wrapper. [SignTool's options](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool) distinguish legacy `/t` from RFC 3161 `/tr`. A signing process can create the signer signature and then fail to obtain the timestamp, so reject warning exits and verify the artifact.

The same helper supplies `NuGet`, `DotNetNuGet`, `JarSigner`, and `Mage` arguments. `PowerShell` returns a splattable hashtable and `MSBuild` returns a project-property hashtable:

```powershell
$timestampArgs = @(.\tools\deploy\Get-TimestampSigningParameters.ps1 -ServerUrl $server -Tool DotNetNuGet)
& dotnet nuget sign '.\Package.nupkg' @timestampArgs --certificate-fingerprint '<THUMBPRINT>'
if ($LASTEXITCODE -ne 0) { throw 'NuGet package signing failed.' }

$timestampArgs = @(.\tools\deploy\Get-TimestampSigningParameters.ps1 -ServerUrl $server -Tool JarSigner)
& jarsigner @timestampArgs -keystore '.\signing.p12' '.\Application.jar' 'signing-key'

# Native PowerShell parameters use an explicitly permitted HTTP endpoint:
$signingParameters = .\tools\deploy\Get-TimestampSigningParameters.ps1 `
    -ServerUrl http://tsa.example.com/OpenTimeStamp -Tool PowerShell -AllowInsecureHttp
$signature = Set-AuthenticodeSignature -LiteralPath '.\Script.ps1' -Certificate $certificate @signingParameters
if ($signature.Status -ne 'Valid' -or -not $signature.TimeStamperCertificate) {
    throw 'A valid timestamped signature was not obtained.'
}
```

HTTPS support differs between PowerShell's URL validation and the underlying Windows signing API. The argument helper exposes HTTP native parameters and directs HTTPS requests to the signing wrapper for consistent transport. HTTP requires explicit `-AllowInsecureHttp`, including when accessing a server on another computer. PowerShell's [native signer documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) describes the per-call timestamp parameter; its [signing implementation](https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/security/Authenticode.cs) delegates signing to Windows CryptUI.

The [NuGet CLI](https://learn.microsoft.com/en-us/nuget/reference/cli-reference/cli-ref-sign), [dotnet NuGet signer](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-nuget-sign), and [Java jarsigner](https://docs.oracle.com/en/java/javase/25/docs/specs/man/jarsigner.html) document their RFC 3161 options. Java's truststore is separate from the Windows certificate store. [Mage](https://learn.microsoft.com/en-us/dotnet/framework/tools/mage-exe-manifest-generation-and-editing-tool) exposes `TimestampUri`; [MSBuild's manifest signer](https://github.com/dotnet/msbuild/blob/main/src/Tasks/ManifestUtil/mansign2.cs) requests RFC 3161 before its optional legacy fallback. `ManifestTimestampUrl` belongs in the intended ClickOnce project, not a global Windows registry key. Older SDK signing implementations require their own interoperability check.

For Inno Setup, define a uniquely named signing command in Tools > Configure Sign Tools or with the compiler's `-s` option, then select it with the project's `[Setup] SignTool` directive. Use `signtool.exe sign /fd SHA256 /tr <HTTP RFC3161 URL> /td SHA256 ... $f`, or invoke the signing wrapper with the HTTPS application URL; `$f` is Inno Setup's quoted input-file placeholder. [Inno Setup's signing reference](https://jrsoftware.org/ishelp/topic_setup_signtool.htm) defines these settings. NSIS and WiX signing belongs in the build pipeline: sign the finished installer and any separately generated uninstaller, external cabinet, or bundle payload required by that project using the same native HTTP parameters or HTTPS wrapper.

Advanced Installer supports [a custom SignTool command](https://www.advancedinstaller.com/user-guide/qa-custom-sign.html) on its Digital Signature settings page. Select the RFC 3161 parameters explicitly; the tool appends the file to be signed. InstallShield's helper configures existing timestamp selectors; selecting the release's signing method, certificate, and digest remains a project choice.

## Applications Requiring Manual Setup or Further Validation

Foxit requires adding the server and selecting it as the default under File > Preferences > Time Stamp Servers. Its signer may prompt to allow the timestamp network connection. Review the returned timestamp certificate through the application's trusted-certificate workflow. See [Foxit's timestamp instructions](https://help.foxit.com/csh/q/product/phantom/id/TimeStampDocument/language/en-us/version/11.0.1) and its [Reader manual](https://cdn01.foxitsoftware.com/pub/foxit/manual/reader/en_us/foxit-pdf-reader-user-manual-2026.1.1.pdf). The helper reports these steps without guessing the stored timestamp-server encoding.

Nitro's File > Preferences > Digital Signature > Time Stamp Servers preferences require a server entry, the acquisition checkbox, and a default server. Nitro can fall back to another available server if the default is unavailable; review the list when the timestamp must come from OpenTimeStamp. See [Nitro's timestamp reference](https://www.gonitro.com/user-guide/pro/article/digital-signature-timestamp).

Bluebeam documents [digital signing](https://support.bluebeam.com/user-manual/menus/tools/digitally-sign-document.html) and [signature preferences](https://support.bluebeam.com/user-manual/menus/revu/tools-preferences.html), but these reviewed pages do not establish an external TSA URL or stable automation interface. This is a research limitation, not a claim that every Revu edition lacks timestamp support. The script returns `ManualReview` until that interface is established for the installed release.

AutoCAD's documented mechanism selects named time services through [timesrvr.txt and ADSKSIGTIMESRVR](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-Core/files/GUID-F9623564-396F-428C-BEC9-1CC782BFFA77.htm). It does not document an RFC 3161 HTTP request in that workflow. Adobe Acrobat Sign's [custom TSA settings](https://helpx.adobe.com/sign/web/config/time-stamp-settings.html) are cloud-account settings and require Adobe Support enablement. Neither is configured by these workstation scripts.

## Trust and Verification

An endpoint preference cannot make the TSA trusted. Deploy the intended CA chain through the organization's certificate-management mechanism and, where applicable, the application's own trust manager. Use separate signer and TSA certificates, keep the TSA private key on the server, and retain revocation checking. These scripts do not import trust anchors, enable macros, alter execution policy, or relax PDF security settings. Anonymous timestamp endpoints are the common interoperable choice; validate each client's authentication support before enabling Windows authentication on the TSA.

After setup, create one representative signature in each application and check both the signer signature and the timestamp. Also test an unreachable TSA when timestamping must be mandatory. LibreOffice and PDF-XChange still require selecting the registered server during signing; VBA does not expose a documented strict retrieval setting. The repository's product signing tests exercise Word, Excel VBA through the Office SIP, PowerShell, executables, and Acrobat separately from configuration tests.

Run the isolated configuration tests in both hosts:

```powershell
powershell.exe -NoProfile -File .\src\tests\ClientConfiguration.Tests.ps1
pwsh.exe -NoProfile -File .\src\tests\ClientConfiguration.Tests.ps1
```

These tests use temporary profile files and dedicated test registry branches. They cover preserving preferences, policy conflicts, rollback after partial registry writes, file backups, concurrent-change rejection, repeated setup, and `-WhatIf`. They do not prove end-to-end signing in every application or remote transport in a particular environment.

Use `src\tests\Invoke-TimestampSigningChecks.ps1` for real PowerShell and executable signing against explicitly selected HTTP and HTTPS application URLs. Supply an existing signing key, SignTool, an output directory, and the expected TSA thumbprint. `-UntrustedHttpsServerUrl` optionally verifies that TLS rejection preserves the unsigned input. The test creates disposable fixtures and independently verifies each result with SignTool.
