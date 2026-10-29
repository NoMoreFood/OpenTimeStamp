# MSI Installer

The OpenTimeStamp MSI is a 64-bit, per-machine WiX 7 package. It caches a
manifested release and the deployment scripts under
`Program Files\OpenTimeStamp\Installer`, then invokes the same hardened IIS
deployment routine used by manual installations.

The MSI prompts for an existing IIS website and an application name. It defaults
to `Default Web Site/OpenTimeStamp`, creates the dedicated `OpenTimeStamp`
application pool, and defaults the public endpoints to Anonymous authentication.
The application name becomes the URL root, such as `/OpenTimeStamp`.

IIS and every required role service must already be installed. The MSI exits
without installing Windows features when IIS is absent or incomplete, and it
rejects a website name that does not already exist. For an unattended install,
set the public MSI properties explicitly:

```powershell
msiexec /i OpenTimeStamp-1.0.0-x64.msi `
    IISSITENAME="Default Web Site" `
    APPLICATIONNAME="OpenTimeStamp"
```

The chosen website and application name are retained for upgrades and safe
uninstall. Upgrades preserve the existing authoritative authentication mode.
Use the PowerShell deployment workflow when a different initial authentication
mode or other advanced topology is required.

MSI repair restores the installer cache while keeping the existing deployed
release selected. Use the PowerShell deployment workflow with a newly published
release to repair the running application.

Windows Installer rollback restores the selected IIS application, dedicated pool configuration and running state, local authentication and access settings, and preexisting data-directory permissions. A failed first installation removes its unchanged new deployment files so that setup can be retried. Existing issuance state, releases, and configuration are preserved. Rollback must be enabled in Windows Installer.

MSI upgrades require current issuance-state storage. Use the PowerShell deployment workflow to migrate legacy state before upgrading through MSI. The new pool stays stopped until Windows Installer commits, and release cleanup runs only after commit.

Recovery snapshots are restricted to administrators and SYSTEM under `%WINDIR%\Installer\OpenTimeStamp-{ProductCode}` and are removed after successful commit or rollback. If recovery detects a conflicting change to the target IIS configuration or data, or an interrupted operation has no complete recovery snapshot, it preserves the journal and stops rather than overwriting that change. Keep the journal and reconcile the target application before retrying setup; do not restore its IIS configuration snapshot over the whole server.

Uninstall removes the matching IIS application and dedicated application pool only after validating their ownership.
It deliberately preserves releases, configuration, issuance state, and audit
logs under the deployment root for recovery. A later reinstall must use the
PowerShell workflow with an explicit `-AuthenticationMode`; MSI setup fails
closed rather than guessing how to expose a preserved deployment whose IIS
application was removed.

Build the application and MSI from the repository root:

```powershell
.\tools\build\Build.ps1 -Configuration Release
```

The build uses [WiX Toolset 7.0.0](https://github.com/wixtoolset/wix/releases/tag/v7.0.0)
through the pinned SDK project and writes
`tools\artifacts\OpenTimeStamp-1.0.0-x64.msi`. WiX 7 use is subject to its Open Source
Maintenance Fee terms and requires acceptance of the applicable WiX EULA.

Signing follows the WinDirStat build pattern: SignTool selects a suitable code-
signing certificate, signs with SHA-256, and obtains an RFC 3161 timestamp from
`http://time.certum.pl/`. Signing failure leaves a usable unsigned development
MSI unless `-RequireSignedInstaller` is supplied. Use
`-InstallerCertificateThumbprint` to select a certificate explicitly,
`-InstallerTimestampUrl` to choose another RFC 3161 service,
`-SkipInstallerSigning` for an intentional unsigned build, or `-SkipInstaller`
to omit MSI packaging.
