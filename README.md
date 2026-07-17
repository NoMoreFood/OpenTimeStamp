# OpenTimeStamp

OpenTimeStamp is an IIS-hosted timestamp authority for Windows Server. It
implements RFC 3161 timestamp replies and the legacy Microsoft Authenticode
countersignature protocol using .NET Framework and Windows cryptography. Public
timestamp endpoints can use Anonymous or Windows authentication, while the
administrative interface remains restricted to the server.

> This software creates cryptographic evidence, not an organizational trust
> framework. A production TSA also needs a controlled certificate lifecycle,
> trustworthy time, protected audit records, documented policies, monitoring,
> backup, and incident response.

## Endpoints

For the default IIS application path `/OpenTimeStamp`:

| Path | Method | Purpose |
| --- | --- | --- |
| `/OpenTimeStamp/timestamp/rfc3161` | `POST` | RFC 3161 timestamping; use this for SignTool `/tr` |
| `/OpenTimeStamp/timestamp/authenticode` | `POST` | Legacy Authenticode timestamping; use this for SignTool `/t` |
| `/OpenTimeStamp/health` | `GET` | Operational health and readiness |
| `/OpenTimeStamp/admin` | `GET`, `POST` | Local, Windows-authenticated administration |

See [Protocols and Endpoints](docs/protocols.md) for supported algorithms,
content types, and compatibility details.

## Requirements

- Windows Server 2019 for RSA deployments, or Windows Server 2025 for RSA and
  supported ML-DSA deployments
- .NET Framework 4.8 or a compatible in-place update on the IIS server
- IIS 10
- Visual Studio 18 or later Build Tools with the .NET Framework 4.8 targeting
  pack and Web development build tools
- Windows PowerShell 5.1

The solution targets .NET Framework 4.8 (`net48`). The build uses a C# 14-capable
compiler while emitting code compatible with that runtime. See
[Build Requirements and Publishing](docs/build-and-publish.md) for complete
prerequisites and release-payload guidance.

## Quick Start

From a Windows PowerShell 5.1 prompt on the build computer:

```powershell
.\build\Build.ps1 -Configuration Release
.\build\Publish.ps1 -Configuration Release
```

The deployable output is written to `artifacts\OpenTimeStamp`, and the MSI is
written to `artifacts\OpenTimeStamp-1.0.0-x64.msi`. Install the
payload manually from an elevated Windows PowerShell 5.1 prompt:

```powershell
.\deploy\Install-IisApplication.ps1 `
    -SourcePath .\artifacts\OpenTimeStamp `
    -SiteName 'Default Web Site' `
    -ApplicationPath '/OpenTimeStamp' `
    -AuthenticationMode Anonymous `
    -AllowUnsignedManifest
```

`-AllowUnsignedManifest` is for development or explicitly approved legacy
packages. Production deployment should use a detached, organization-signed
manifest and HTTPS. Continue with the [IIS Deployment](docs/deployment.md) guide
before exposing the service.

## Documentation

| Topic | Guide |
| --- | --- |
| Protocol behavior and endpoint compatibility | [Protocols and Endpoints](docs/protocols.md) |
| Build prerequisites and release publishing | [Build Requirements and Publishing](docs/build-and-publish.md) |
| MSI installation and signing | [MSI Installer](setup/msi/README.md) |
| IIS installation, certificates, upgrades, and validation | [IIS Deployment](docs/deployment.md) |
| Admin access, FIPS behavior, state, logs, and operations | [Administration and Operations](docs/administration.md) |
| Microsoft Office, VBA, and Adobe Acrobat clients | [Client Configuration](docs/client-configuration.md) |
| Product-signing interoperability tests | [Testing](docs/testing.md) |
| Production hardening and incident guidance | [Security Guidance](.github/SECURITY.md) |

## Repository Layout

| Path | Contents |
| --- | --- |
| `src` | Web application and core timestamping implementation |
| `deploy` | IIS installation, certificate, and client-configuration scripts |
| `build` | Build and publishing scripts |
| `setup` | WiX MSI project and installer integration scripts |
| `tests` | Automated, deployment, and product-interoperability tests |
| `docs` | Focused operator and integration documentation |

Before a production rollout, review both the
[deployment guide](docs/deployment.md) and [security guidance](.github/SECURITY.md).
