#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$MSBuildPath,

    [string]$OutputPath,

    [string]$CertificateThumbprint,

    [ValidateNotNullOrEmpty()]
    [string]$TimestampUrl = 'http://time.certum.pl/',

    [string]$ProductUrl,

    [switch]$SkipSigning,

    [switch]$RequireSignedInstaller
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-SignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) { return $command.Source }

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (-not (Test-Path -LiteralPath $kitsRoot -PathType Container)) { return $null }
    $versions = @(Get-ChildItem -LiteralPath $kitsRoot -Directory | Where-Object {
            $parsed = [version]'0.0'
            [version]::TryParse($_.Name, [ref]$parsed)
        } | Sort-Object { [version]$_.Name } -Descending)
    foreach ($version in $versions) {
        $candidate = Join-Path $version.FullName 'x64\signtool.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}

function Invoke-InstallerSigning {
    param(
        [string]$MsiPath,
        [string]$Thumbprint,
        [string]$Rfc3161Url,
        [string]$InformationUrl,
        [switch]$Required
    )

    $signTool = Resolve-SignTool
    if ($null -eq $signTool) {
        if ($Required) { throw 'SignTool was not found, but a signed installer is required.' }
        Write-Warning 'SignTool was not found. Continuing with an unsigned MSI.'
        return $false
    }

    $timestampUri = $null
    if (-not [Uri]::TryCreate($Rfc3161Url, [UriKind]::Absolute, [ref]$timestampUri) -or
        $timestampUri.Scheme -notin @('http', 'https')) {
        throw 'TimestampUrl must be an absolute HTTP or HTTPS URL.'
    }
    $arguments = @('sign', '/fd', 'SHA256', '/tr', $Rfc3161Url, '/td', 'SHA256', '/d', 'OpenTimeStamp')
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        $arguments += '/a'
    }
    else {
        $normalizedThumbprint = ($Thumbprint -replace '\s', '').ToUpperInvariant()
        if ($normalizedThumbprint -notmatch '^[0-9A-F]{40}$') {
            throw 'CertificateThumbprint must be a 40-character SHA-1 certificate thumbprint.'
        }
        $arguments += @('/sha1', $normalizedThumbprint)
    }
    if (-not [string]::IsNullOrWhiteSpace($InformationUrl)) {
        $informationUri = $null
        if (-not [Uri]::TryCreate($InformationUrl, [UriKind]::Absolute, [ref]$informationUri) -or
            $informationUri.Scheme -notin @('http', 'https')) {
            throw 'ProductUrl must be an absolute HTTP or HTTPS URL.'
        }
        $arguments += @('/du', $InformationUrl)
    }
    $arguments += $MsiPath

    Write-Host "Signing MSI with $signTool"
    & $signTool @arguments
    $signExitCode = $LASTEXITCODE
    if ($signExitCode -ne 0) {
        if ($Required) { throw "MSI signing failed with exit code $signExitCode." }
        Write-Warning "MSI signing failed with exit code $signExitCode. Continuing without a verified signature."
        return $false
    }

    & $signTool verify /pa /all $MsiPath
    if ($LASTEXITCODE -ne 0) {
        if ($Required) { throw 'The MSI signature could not be verified.' }
        Write-Warning 'The MSI signature could not be verified.'
        return $false
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $MsiPath
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.TimeStamperCertificate) {
        if ($Required) { throw 'The MSI does not have a valid timestamped Authenticode signature.' }
        Write-Warning 'The MSI signature is missing, invalid, or not timestamped.'
        return $false
    }
    Write-Host "Signed and verified MSI with '$($signature.SignerCertificate.Subject)'."
    return $true
}

if ($SkipSigning -and $RequireSignedInstaller) {
    throw 'RequireSignedInstaller cannot be used with SkipSigning.'
}

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$buildCommon = Join-Path $repositoryRoot 'build\Build.Common.ps1'
$deploymentCommon = Join-Path $repositoryRoot 'deploy\Deployment.Common.ps1'
$webProject = Join-Path $repositoryRoot 'src\OpenTimeStamp.Web\OpenTimeStamp.Web.csproj'
$assemblyInfo = Join-Path $repositoryRoot 'src\OpenTimeStamp.Web\Properties\AssemblyInfo.cs'
$wixProject = Join-Path $PSScriptRoot 'OpenTimeStamp.Setup.wixproj'
foreach ($requiredFile in @($buildCommon, $deploymentCommon, $webProject, $assemblyInfo, $wixProject)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required MSI build input '$requiredFile' is missing."
    }
}
. $buildCommon
. $deploymentCommon

$assemblyText = Get-Content -LiteralPath $assemblyInfo -Raw
$versionMatch = [regex]::Match($assemblyText, 'AssemblyFileVersion\("(?<version>[0-9]+(?:\.[0-9]+){2,3})"\)')
if (-not $versionMatch.Success) { throw 'OpenTimeStamp assembly file version was not found.' }
$assemblyVersion = [version]$versionMatch.Groups['version'].Value
$productVersion = '{0}.{1}.{2}' -f $assemblyVersion.Major, $assemblyVersion.Minor, $assemblyVersion.Build

$usingDefaultOutput = [string]::IsNullOrWhiteSpace($OutputPath)
if ($usingDefaultOutput) {
    $OutputPath = Join-Path $repositoryRoot "artifacts\OpenTimeStamp-$productVersion-x64.msi"
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
if ([System.IO.Path]::GetExtension($OutputPath) -ne '.msi') { throw 'OutputPath must end in .msi.' }
$outputParent = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    $defaultArtifacts = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot 'artifacts'))
    if (-not $usingDefaultOutput -or
        -not $outputParent.Equals($defaultArtifacts, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The custom MSI output parent '$outputParent' must already exist."
    }
    New-Item -ItemType Directory -Path $outputParent | Out-Null
}

$dotnet = Get-Command dotnet.exe -ErrorAction SilentlyContinue
if ($null -eq $dotnet) { throw 'The .NET SDK is required to restore and build WiX 7.' }
$resolvedMSBuild = Resolve-OpenTimeStampMSBuild -RequestedPath $MSBuildPath
$temporaryBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')
$temporaryRoot = Join-Path $temporaryBase ('OpenTimeStamp.Msi.' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
try {
    $payloadPath = Join-Path $temporaryRoot 'payload'
    New-Item -ItemType Directory -Path $payloadPath | Out-Null
    $publishArguments = @(
        $webProject,
        '/t:WebPublish',
        "/p:Configuration=$Configuration",
        '/p:Platform=AnyCPU',
        '/p:WebPublishMethod=FileSystem',
        '/p:DeleteExistingFiles=true',
        "/p:publishUrl=$payloadPath",
        '/nologo',
        '/v:minimal')
    Write-Host 'Preparing the manifested IIS payload for the MSI.'
    & $resolvedMSBuild @publishArguments
    if ($LASTEXITCODE -ne 0) { throw "MSI payload publish failed with exit code $LASTEXITCODE." }
    New-OpenTimeStampDeploymentManifest -PayloadPath $payloadPath | Out-Null
    Assert-OpenTimeStampPublishedPayload -PayloadPath $payloadPath | Out-Null

    $wixOutput = Join-Path $temporaryRoot 'wix-bin'
    $wixIntermediate = Join-Path $temporaryRoot 'wix-obj'
    $wixArguments = @(
        'build', $wixProject,
        '--configuration', $Configuration,
        '--nologo',
        '--property:RestoreLockedMode=true',
        "--property:PayloadPath=$payloadPath",
        "--property:DeployPath=$(Join-Path $repositoryRoot 'deploy')",
        "--property:SetupPath=$PSScriptRoot",
        "--property:ProductVersion=$productVersion",
        "--property:OutputPath=$wixOutput\",
        "--property:BaseIntermediateOutputPath=$wixIntermediate\")
    Write-Host 'Building the WiX 7 MSI.'
    & $dotnet.Source @wixArguments
    if ($LASTEXITCODE -ne 0) { throw "WiX MSI build failed with exit code $LASTEXITCODE." }

    $builtPackages = @(Get-ChildItem -LiteralPath $wixOutput -Filter '*.msi' -File -Recurse)
    if ($builtPackages.Count -ne 1) {
        throw "The WiX build produced $($builtPackages.Count) MSI packages instead of one."
    }
    Copy-Item -LiteralPath $builtPackages[0].FullName -Destination $OutputPath -Force
}
finally {
    $resolvedTemporaryRoot = [System.IO.Path]::GetFullPath($temporaryRoot).TrimEnd('\')
    if ($resolvedTemporaryRoot.StartsWith($temporaryBase + '\', [System.StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedTemporaryRoot).StartsWith('OpenTimeStamp.Msi.',
            [System.StringComparison]::Ordinal) -and
        (Test-Path -LiteralPath $resolvedTemporaryRoot -PathType Container)) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}

$signed = $false
if (-not $SkipSigning) {
    $signed = Invoke-InstallerSigning -MsiPath $OutputPath `
        -Thumbprint $CertificateThumbprint `
        -Rfc3161Url $TimestampUrl `
        -InformationUrl $ProductUrl `
        -Required:$RequireSignedInstaller
}
Write-Host "MSI completed: $OutputPath"
Write-Host "Authenticode signature: $(if ($signed) { 'signed and timestamped' } else { 'not verified' })"
Write-Output $OutputPath
