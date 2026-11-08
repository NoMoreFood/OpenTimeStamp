# MSI Installer

The OpenTimeStamp MSI is a 64-bit, per-machine WiX 7 package. It installs a manifested release and the deployment scripts in `Program Files\OpenTimeStamp`, or another folder chosen during setup, then invokes the same hardened IIS deployment routine used by manual installations.

Setup lists the server's IIS websites, then the selected website's existing applications. Choose an application or enter a new name; the name becomes the URL root, such as `/OpenTimeStamp`. Setup defaults to `Default Web Site/OpenTimeStamp`, creates the dedicated `OpenTimeStamp` application pool, and defaults the public endpoints to Anonymous authentication. Listing websites requires administrator rights, so start setup from an elevated prompt.

The application page also sets the public endpoint paths: automatic detection (`/timestamp`), RFC 3161 (`/timestamp/rfc3161`), Authenticode (`/timestamp/authenticode`), and service health (`/health`). Administration always uses `/admin`. See [Public Endpoint Paths](../../docs/deployment.md#public-endpoint-paths) for the allowed names; setup rolls back when a path is invalid or duplicated.

Choosing an existing application that is not an OpenTimeStamp deployment points it at the new release and the dedicated pool. Its previous content, application pool, and other virtual directories remain unchanged, and rollback restores its original selection.

IIS and every required role service must already be installed. The MSI exits
without installing Windows features when IIS is absent or incomplete, and it
rejects a website name that does not already exist. For an unattended install,
set the public MSI properties explicitly:

```powershell
msiexec /i OpenTimeStamp-<version>-x64.msi `
    IISSITENAME="Default Web Site" `
    APPLICATIONNAME="OpenTimeStamp"
```

Add `TIMESTAMPPATH`, `RFC3161PATH`, `AUTHENTICODEPATH`, or `HEALTHPATH` to choose other public paths.

After an interactive installation, setup lists the service home, endpoint, health, and administration URLs for every website binding. The **OpenTimeStamp Administration** Start menu shortcut opens the administration page on the server.

The chosen website, application name, and public paths are retained for upgrades and safe uninstall. Upgrades preserve the existing authoritative authentication mode. Use the PowerShell deployment workflow when a different initial authentication mode or other advanced topology is required.

MSI repair restores the installed program files while keeping the existing deployed release selected. Use the PowerShell deployment workflow with a newly published release to repair the running application.

Windows Installer rollback restores the selected IIS application, dedicated pool configuration and running state, local authentication and access settings, and preexisting data-directory permissions. A failed first installation removes its unchanged new deployment files so that setup can be retried. Existing issuance state, releases, and configuration are preserved. Rollback must be enabled in Windows Installer.

MSI upgrades require current issuance-state storage. Use the PowerShell deployment workflow to migrate legacy state before upgrading through MSI. The new pool stays stopped until Windows Installer commits, and release cleanup runs only after commit.

Recovery snapshots are restricted to administrators and SYSTEM under `%WINDIR%\Installer\OpenTimeStamp-{ProductCode}` and are removed after successful commit or rollback. If recovery detects a conflicting change to the target IIS configuration or data, or an interrupted operation has no complete recovery snapshot, it preserves the journal and stops rather than overwriting that change. Keep the journal and reconcile the target application before retrying setup; do not restore its IIS configuration snapshot over the whole server.

Uninstall removes the matching IIS application and dedicated application pool only after validating their ownership. It deliberately preserves releases, configuration, issuance state, and audit logs under the deployment root for recovery, and it removes the saved setup choices.

Reinstalling over a preserved deployment in `C:\inetpub\OpenTimeStamp` recovers its authentication mode, data directory, administrative host names, and request limits when every retained release matches its manifest and all of them agree; setup stops when they conflict. Setup applies the website, application, and public paths chosen during the reinstall, so enter any custom paths again. It installs a new release beside the retained ones and leaves their files unchanged.

Build the application and MSI from the repository root:

```powershell
.\tools\build\Build.ps1 -Configuration Release
```

The build uses the [WiX Toolset 7](https://github.com/wixtoolset/wix/releases) SDK pinned by the setup project and writes `tools\artifacts\OpenTimeStamp-<version>-x64.msi`. WiX 7 use is subject to its Open Source Maintenance Fee terms and requires acceptance of the applicable WiX EULA.

Signing follows the WinDirStat build pattern: SignTool selects a suitable code-
signing certificate, signs with SHA-256, and obtains an RFC 3161 timestamp from
`http://time.certum.pl/`. Signing failure leaves a usable unsigned development
MSI unless `-RequireSignedInstaller` is supplied. Use
`-InstallerCertificateThumbprint` to select a certificate explicitly,
`-InstallerTimestampUrl` to choose another RFC 3161 service,
`-SkipInstallerSigning` for an intentional unsigned build, or `-SkipInstaller`
to omit MSI packaging.
