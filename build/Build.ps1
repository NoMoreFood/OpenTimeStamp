#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$MSBuildPath,

    [switch]$NoClean,

    [switch]$SkipTests,

    [switch]$SkipInstaller,

    [switch]$SkipInstallerSigning,

    [string]$InstallerCertificateThumbprint,

    [string]$InstallerTimestampUrl = 'http://time.certum.pl/',

    [switch]$RequireSignedInstaller
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$solutionPath = Join-Path $repositoryRoot 'OpenTimeStamp.sln'
$buildCommon = Join-Path $PSScriptRoot 'Build.Common.ps1'
if (-not (Test-Path -LiteralPath $buildCommon -PathType Leaf)) {
    throw "Build support functions were not found at '$buildCommon'."
}
. $buildCommon

if (-not (Test-Path -LiteralPath $solutionPath -PathType Leaf)) {
    throw "The solution was not found at '$solutionPath'."
}
if ($SkipInstaller -and $RequireSignedInstaller) {
    throw 'RequireSignedInstaller cannot be used with SkipInstaller.'
}
if ($SkipInstallerSigning -and $RequireSignedInstaller) {
    throw 'RequireSignedInstaller cannot be used with SkipInstallerSigning.'
}

$referenceAssembliesRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
$referenceAssembly = Join-Path $referenceAssembliesRoot 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8\mscorlib.dll'
if (-not (Test-Path -LiteralPath $referenceAssembly -PathType Leaf)) {
    throw 'The .NET Framework 4.8 targeting pack is not installed.'
}

$msbuild = Resolve-OpenTimeStampMSBuild -RequestedPath $MSBuildPath
$target = if ($NoClean) { 'Build' } else { 'Rebuild' }
$arguments = @(
    $solutionPath,
    '/restore',
    '/p:RestoreLockedMode=true',
    "/t:$target",
    "/p:Configuration=$Configuration",
    '/p:Platform=Any CPU',
    '/m',
    '/nologo',
    '/v:minimal'
)

Write-Host "Building OpenTimeStamp ($Configuration) with $msbuild"
& $msbuild @arguments
if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE."
}

if (-not $SkipTests) {
    $testProject = Join-Path $repositoryRoot 'tests\OpenTimeStamp.Tests\OpenTimeStamp.Tests.csproj'
    $dotnet = Get-Command dotnet.exe -ErrorAction SilentlyContinue
    if ($null -eq $dotnet) {
        throw 'The .NET SDK is required to run the managed regression tests.'
    }

    Write-Host 'Running OpenTimeStamp managed regression suite with MSTest'
    & $dotnet.Source test $testProject --no-build --no-restore --configuration $Configuration --nologo `
        -- RunConfiguration.TreatNoTestsAsError=true
    if ($LASTEXITCODE -ne 0) {
        throw "The managed regression suite failed with exit code $LASTEXITCODE."
    }

    $deploymentTests = Join-Path $repositoryRoot 'tests\Deployment.Tests.ps1'
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
        throw 'Windows PowerShell 5.1 is required to run deployment regression tests.'
    }
    if (-not (Test-Path -LiteralPath $deploymentTests -PathType Leaf)) {
        throw "Deployment regression tests were not found at '$deploymentTests'."
    }

    Write-Host 'Running deployment and packaging regression suite under Windows PowerShell 5.1'
    & $windowsPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $deploymentTests
    if ($LASTEXITCODE -ne 0) {
        throw "The deployment regression suite failed with exit code $LASTEXITCODE."
    }
}

if (-not $SkipInstaller) {
    $installerBuild = Join-Path $repositoryRoot 'setup\msi\Build-Msi.ps1'
    if (-not (Test-Path -LiteralPath $installerBuild -PathType Leaf)) {
        throw "The MSI build script was not found at '$installerBuild'."
    }
    $installerArguments = @{
        Configuration = $Configuration
        MSBuildPath = $msbuild
        TimestampUrl = $InstallerTimestampUrl
        SkipSigning = [bool]$SkipInstallerSigning
        RequireSignedInstaller = [bool]$RequireSignedInstaller
    }
    if (-not [string]::IsNullOrWhiteSpace($InstallerCertificateThumbprint)) {
        $installerArguments.CertificateThumbprint = $InstallerCertificateThumbprint
    }
    & $installerBuild @installerArguments
}

Write-Host 'Build completed successfully.'
