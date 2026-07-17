# Build Requirements and Publishing

## Platform and Prerequisites

- Windows Server 2019 for RSA deployments, or Windows Server 2025 for RSA and
  supported ML-DSA deployments, with current security updates
- .NET Framework 4.8 or a compatible in-place update on the IIS server
- IIS 10; the installation script enables the required role services
- Visual Studio 18 or later Build Tools with a C# 14-capable MSBuild, the .NET
  Framework 4.8 targeting pack, and Web development build tools on the build
  computer
- .NET SDK 8 or later, which restores the pinned WiX Toolset 7 SDK and runs the
  test projects
- Windows PowerShell 5.1 for the supplied scripts

The solution deliberately targets .NET Framework 4.8 (`net48`). It runs on
Windows Server 2025's in-box .NET Framework 4.8.1 without installing another
.NET runtime; .NET Framework 4.8.1 is an in-place, runtime-compatible update,
not a separate application target required by this project. Windows Server 2019
remains a supported RSA deployment target with its in-box .NET Framework 4.8.
The projects use the C# 14 compiler, but only language features that emit code
compatible with the .NET Framework 4.8 runtime.

The service uses the first-party `Microsoft.Bcl.Cryptography`, `System.Formats.Asn1`, and
`System.Security.Cryptography.Pkcs` NuGet packages plus their transitive
dependencies. The build computer restores these assemblies and publishing
places the required DLLs beside the application. The IIS installer deploys that
complete payload and never downloads packages or installs another .NET runtime.
On .NET Framework, `System.Security.Cryptography.Pkcs` is a partial facade over
the inbox PKCS implementation: CMS signing still uses the Windows-backed
`SignedCms` implementation and therefore depends on the operating system's
cryptographic provider support.

The managed ML-DSA key-access members in the current BCL package are marked
`SYSLIB5006` (evaluation only). This service does not suppress that diagnostic
or call those members. It uses the stable `MLDsa.IsSupported` capability check
and CMS surface for provider detection, signing, and private-key probes, and
uses Crypt32/NCrypt only for deployment-time machine-key ACL discovery.

## Build and Publish

From a PowerShell 5.1 prompt on the build computer:

```powershell
.\build\Build.ps1 -Configuration Release
.\build\Publish.ps1 -Configuration Release
```

The deployable output is `artifacts\OpenTimeStamp`, and the WiX 7 installer is
`artifacts\OpenTimeStamp-1.0.0-x64.msi`. Use `-MSBuildPath` if MSBuild cannot be
discovered through `vswhere.exe` or `PATH`, and use `-OutputPath` to stage the
manual payload elsewhere. `Build.ps1` runs both the discoverable MSTest
regression suite and the deployment/packaging regression suite under Windows
PowerShell 5.1 after a successful compile; `-SkipTests` is available for a
compile-only diagnostic. Central Microsoft .NET analyzer rules use
the .NET 10 recommended analysis baseline. Analyzer findings are warnings for
incremental adoption, while compiler warnings remain errors.
Restore runs in NuGet locked mode on the build computer and fails before
compilation if a project and its committed `packages.lock.json` disagree. The
published `bin` directory contains the application-local cryptography assemblies
required at runtime. Build and publish share one toolchain probe and reject an
MSBuild installation that lacks the Visual Studio 18 WebApplication targets or a
C# 14-capable Roslyn compiler. When publishing from a Git worktree, required
build, deployment, lock, fixture, and product-test files must be tracked; this
prevents an accidentally incomplete commit from becoming a release. Exported
source without Git metadata remains publishable.

The build restores the installer through the pinned `WixToolset.Sdk/7.0.0`
project; a global WiX installation is not required. WiX 7 is subject to its Open
Source Maintenance Fee terms and requires acceptance of the applicable EULA.
The default build follows the WinDirStat signing pattern: it asks SignTool to
select a code-signing certificate, uses SHA-256 with an RFC 3161 timestamp, and
continues with an unsigned development MSI if signing is unavailable. Use
`-InstallerCertificateThumbprint` to select the certificate,
`-InstallerTimestampUrl` to change the timestamp service,
`-RequireSignedInstaller` for a release build that must fail closed,
`-SkipInstallerSigning` for an intentional unsigned package, or `-SkipInstaller`
to omit MSI packaging. See the [MSI installer guide](../setup/msi/README.md).

If this checkout already has `artifacts\OpenTimeStamp` from a publisher version
that predates staging ownership markers, migrate it once with:

```powershell
.\build\Publish.ps1 -Configuration Release -AdoptLegacyDefaultOutput
```

Adoption is limited to the historical default path and only a recognized legacy
payload containing no runtime `App_Data` state or unexpected files. Arbitrary
existing outputs remain unowned and are never replaced. Omit the switch after
the first successful adoption.

Publishing creates `OpenTimeStamp.DeploymentManifest.json`, with the exact file
list, lengths, and SHA-256 hashes for one release. A publish payload never
contains `App_Data`: mutable configuration, issuance state, and logs are owned by
the installed data directory. Publishing replaces files only in the selected
staging output. It refuses a marked deployment root, a release tree, or an output
that has acquired runtime `App_Data` content. Do not publish directly into a live
IIS directory, and do not add, remove, or edit payload files after publishing.
Publishing and installation refuse repository source paths. The IIS installer
does not download dependencies.

Hashes detect corruption and payload drift, but an unsigned hash manifest does
not authenticate its publisher. Publishing leaves the manifest unsigned so an
organization can apply its own controlled release-signing identity. Production
installation requires a detached CMS signature over the manifest's exact bytes
and pins its one embedded signer certificate by thumbprint. Keep the detached
signature outside the payload directory, because every payload file must be in
the manifest. Use `-AllowUnsignedManifest` only for a development build or an
explicitly approved legacy package.
