#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$OutputPath,

    [string]$MSBuildPath,

    [switch]$SkipTests,

    [switch]$AdoptLegacyDefaultOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$webProject = Join-Path $repositoryRoot 'src\OpenTimeStamp.Web\OpenTimeStamp.Web.csproj'
$buildScript = Join-Path $PSScriptRoot 'Build.ps1'
$buildCommon = Join-Path $PSScriptRoot 'Build.Common.ps1'
$deploymentCommon = Join-Path $repositoryRoot 'deploy\Deployment.Common.ps1'

if (-not (Test-Path -LiteralPath $deploymentCommon -PathType Leaf)) {
    throw "Deployment support functions were not found at '$deploymentCommon'."
}
if (-not (Test-Path -LiteralPath $buildCommon -PathType Leaf)) {
    throw "Build support functions were not found at '$buildCommon'."
}

. $buildCommon
. $deploymentCommon

function Assert-OpenTimeStampReleaseInputsTracked {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

    $gitMetadata = Join-Path $RepositoryRoot '.git'
    $git = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($null -eq $git) { $git = Get-Command git -ErrorAction SilentlyContinue }
    if ($null -eq $git) {
        if (Test-Path -LiteralPath $gitMetadata) {
            throw 'This is a Git worktree, but git is unavailable to verify that release inputs are tracked.'
        }
        return
    }

    $insideWorktree = & $git.Source -C $RepositoryRoot rev-parse --is-inside-work-tree 2>$null
    if ($LASTEXITCODE -ne 0 -or $insideWorktree -ne 'true') { return }
    $releaseInputFiles = @(
        '.editorconfig',
        '.globalconfig',
        'Directory.Build.props',
        'Directory.Packages.props',
        'OpenTimeStamp.sln',
        'tests/Deployment.Tests.ps1')
    $releaseInputDirectories = @(
        'build',
        'deploy',
        'setup/msi',
        'src',
        'tests/OpenTimeStamp.Tests',
        'tests/ProductSigning')
    $releaseInputs = @($releaseInputFiles) + @($releaseInputDirectories)
    foreach ($relativePath in $releaseInputFiles) {
        $absolutePath = Join-Path $RepositoryRoot $relativePath
        if (-not (Test-Path -LiteralPath $absolutePath -PathType Leaf)) {
            throw "Required release input '$relativePath' is missing."
        }
        & $git.Source -C $RepositoryRoot ls-files --error-unmatch -- $relativePath 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Required release input '$relativePath' is not tracked by Git." }
    }
    foreach ($relativeDirectory in $releaseInputDirectories) {
        $absoluteDirectory = Join-Path $RepositoryRoot $relativeDirectory
        if (-not (Test-Path -LiteralPath $absoluteDirectory -PathType Container)) {
            throw "Required release input directory '$relativeDirectory' is missing."
        }
    }

    $untracked = @(& $git.Source -C $RepositoryRoot ls-files --others --exclude-standard -- @releaseInputs)
    if ($LASTEXITCODE -ne 0) { throw 'Git could not verify untracked release inputs.' }
    if ($untracked.Count -ne 0) {
        throw "Publishing from this worktree is blocked because release inputs are untracked: $($untracked -join ', ')."
    }
}

if ($null -eq ('OpenTimeStamp.PublishNativeMethods' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace OpenTimeStamp {
    [StructLayout(LayoutKind.Sequential)]
    public struct ByHandleFileInformation {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    public static class PublishNativeMethods {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(
            string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
            uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetFileInformationByHandle(
            SafeFileHandle handle, out ByHandleFileInformation information);
    }
}
'@
}

function Open-PublishDirectoryHandle {
    param([string]$Path, [switch]$AllowDeleteShare)

    $fileListDirectory = 0x00000001
    $fileFlagBackupSemantics = 0x02000000
    $fileFlagOpenReparsePoint = 0x00200000
    $handle = [OpenTimeStamp.PublishNativeMethods]::CreateFileW(
        $Path, $fileListDirectory, $(if ($AllowDeleteShare) { 7 } else { 3 }),
        [IntPtr]::Zero, 3, ($fileFlagBackupSemantics -bor $fileFlagOpenReparsePoint), [IntPtr]::Zero)
    if ($null -eq $handle -or $handle.IsInvalid) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($null -ne $handle) { $handle.Dispose() }
        throw New-Object ComponentModel.Win32Exception($errorCode, "Could not pin publish directory '$Path'.")
    }
    return $handle
}

function Get-PublishDirectoryIdentity {
    param($Handle)
    $information = New-Object OpenTimeStamp.ByHandleFileInformation
    if (-not [OpenTimeStamp.PublishNativeMethods]::GetFileInformationByHandle($Handle, [ref]$information)) {
        throw New-Object ComponentModel.Win32Exception(
            [Runtime.InteropServices.Marshal]::GetLastWin32Error(), 'Could not read the publish directory identity.')
    }
    if (($information.FileAttributes -band 0x00000400) -ne 0) {
        throw 'The publish directory handle refers to a reparse point.'
    }
    return '{0:X8}:{1:X8}{2:X8}' -f $information.VolumeSerialNumber, $information.FileIndexHigh, $information.FileIndexLow
}

function Write-PinnedPublishMarker {
    param(
        [string]$Path,
        [string]$CanonicalOutputPath,
        [string]$StagingId,
        [string]$CreatedUtc
    )

    $marker = [ordered]@{
        Product = 'OpenTimeStamp'
        SchemaVersion = 1
        Purpose = 'PublishStaging'
        OutputPath = $CanonicalOutputPath
        StagingId = $StagingId
        CreatedUtc = $CreatedUtc
    }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $stream = New-Object System.IO.FileStream(
        $Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $writer = New-Object System.IO.StreamWriter($stream, $encoding)
        try { $writer.Write(($marker | ConvertTo-Json -Depth 3) + [Environment]::NewLine) }
        finally { $writer.Dispose() }
    }
    finally { $stream.Dispose() }
}

$usingDefaultOutput = [string]::IsNullOrWhiteSpace($OutputPath)
if ($usingDefaultOutput) {
    $OutputPath = Join-Path $repositoryRoot 'artifacts\OpenTimeStamp'
}

if (-not (Test-Path -LiteralPath $webProject -PathType Leaf)) {
    throw "The web project was not found at '$webProject'."
}
if (-not (Test-Path -LiteralPath $buildScript -PathType Leaf)) {
    throw "The build script was not found at '$buildScript'."
}
Assert-OpenTimeStampReleaseInputsTracked -RepositoryRoot $repositoryRoot

$OutputPath = Assert-OpenTimeStampPublishOutputSafe -OutputPath $OutputPath -RepositoryRoot $repositoryRoot `
    -AllowLegacyDefaultOutput:$AdoptLegacyDefaultOutput
if ($OutputPath.IndexOfAny([char[]]@('%', '$', '@', '(', ')', ';', ',', '?', '*')) -ge 0) {
    throw "The publish output path contains characters that can alter MSBuild property parsing."
}
$publishLock = Enter-OpenTimeStampDeploymentLock -Scope ('OpenTimeStamp-Publish:' + $OutputPath)
$publishDirectoryHandle = $null
$claimHandle = $null
$claimPath = $null
$ownershipVerifiedAfterPin = $false
$expectedMarker = $null
$expectedStagingId = $null
$expectedCreatedUtc = $null
try {
    if (Test-Path -LiteralPath $OutputPath -PathType Container) {
        $publishDirectoryHandle = Open-PublishDirectoryHandle -Path $OutputPath
        [void](Get-PublishDirectoryIdentity -Handle $publishDirectoryHandle)
        $markerPath = Join-Path $OutputPath $script:OpenTimeStampPublishMarkerName
        if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
            if (-not $AdoptLegacyDefaultOutput) {
                throw "The existing publish output is missing its staging ownership marker."
            }

            # Revalidate the narrowly recognized predecessor output after pinning
            # the directory, then establish durable ownership before any delete.
            Assert-OpenTimeStampLegacyDefaultPublishOutput -OutputPath $OutputPath `
                -RepositoryRoot $repositoryRoot | Out-Null
            $legacyStagingId = [Guid]::NewGuid().ToString('D')
            $legacyCreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
            Write-PinnedPublishMarker -Path $markerPath -CanonicalOutputPath $OutputPath `
                -StagingId $legacyStagingId -CreatedUtc $legacyCreatedUtc

            # Historical web-publish output could contain only this empty
            # App_Data placeholder. Remove it without recursion; any concurrent
            # runtime content makes the directory removal fail closed.
            $legacyAppData = Join-Path $OutputPath 'App_Data'
            $legacyPlaceholder = Join-Path $legacyAppData '.gitkeep'
            if (Test-Path -LiteralPath $legacyPlaceholder -PathType Leaf) {
                Remove-Item -LiteralPath $legacyPlaceholder -Force
            }
            if (Test-Path -LiteralPath $legacyAppData -PathType Container) {
                Remove-Item -LiteralPath $legacyAppData -Force
            }
            Write-Host "Adopted the validated legacy publish output '$OutputPath'."
        }
        $expectedMarker = Assert-OpenTimeStampPublishMarker -OutputPath $OutputPath
    }
    else {
        $outputParent = Split-Path -Parent $OutputPath
        if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
            $defaultArtifactsParent = Get-OpenTimeStampCanonicalDirectoryPath `
                -Path (Join-Path $repositoryRoot 'artifacts')
            if (-not $usingDefaultOutput -or
                -not $outputParent.Equals($defaultArtifactsParent, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "The publish output parent '$outputParent' must already exist."
            }
            New-Item -ItemType Directory -Path $outputParent -ErrorAction Stop | Out-Null
        }
        # The parent is not deployment-owned and may contain unrelated reparse
        # points. Validate only its ancestry; the unpredictable claimed leaf is
        # pinned without delete sharing/OpenReparsePoint and the owned output is
        # recursively validated before destructive work.
        Assert-OpenTimeStampNoReparsePoints -Root $outputParent -AncestryOnly
        $claimPath = Join-Path $outputParent ('.opentimestamp-publish-claim-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $claimPath -ErrorAction Stop | Out-Null
        $claimStagingId = [Guid]::NewGuid().ToString('D')
        $claimCreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Write-PinnedPublishMarker -Path (Join-Path $claimPath $script:OpenTimeStampPublishMarkerName) `
            -CanonicalOutputPath $OutputPath -StagingId $claimStagingId -CreatedUtc $claimCreatedUtc
        $claimHandle = Open-PublishDirectoryHandle -Path $claimPath -AllowDeleteShare
        $claimIdentity = Get-PublishDirectoryIdentity -Handle $claimHandle
        [System.IO.Directory]::Move($claimPath, $OutputPath)
        $publishDirectoryHandle = Open-PublishDirectoryHandle -Path $OutputPath
        if ((Get-PublishDirectoryIdentity -Handle $publishDirectoryHandle) -ne $claimIdentity) {
            throw 'The atomically claimed publish output does not retain the created directory identity.'
        }
        $claimHandle.Dispose()
        $claimHandle = $null
        $claimPath = $null
        $expectedMarker = Assert-OpenTimeStampPublishMarker -OutputPath $OutputPath
    }

    $expectedStagingGuid = [Guid]::Empty
    if (-not [Guid]::TryParse([string]$expectedMarker.StagingId, [ref]$expectedStagingGuid) -or
        $expectedStagingGuid -eq [Guid]::Empty) {
        throw 'The approved publish marker has an invalid staging identifier.'
    }
    $expectedStagingId = $expectedStagingGuid.ToString('D')
    $expectedCreated = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse([string]$expectedMarker.CreatedUtc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind, [ref]$expectedCreated)) {
        throw 'The approved publish marker has an invalid creation timestamp.'
    }
    $expectedCreatedUtc = [string]$expectedMarker.CreatedUtc

    $buildArguments = @{
        Configuration = $Configuration
        SkipInstaller = $true
    }
    if (-not [string]::IsNullOrWhiteSpace($MSBuildPath)) {
        $buildArguments.MSBuildPath = $MSBuildPath
    }
    if ($SkipTests) {
        $buildArguments.SkipTests = $true
    }

    & $buildScript @buildArguments

    $MSBuildPath = Resolve-OpenTimeStampMSBuild -RequestedPath $MSBuildPath

    $publishArguments = @(
        $webProject,
        '/t:WebPublish',
        "/p:Configuration=$Configuration",
        '/p:Platform=AnyCPU',
        '/p:WebPublishMethod=FileSystem',
        '/p:DeleteExistingFiles=true',
        "/p:publishUrl=$OutputPath",
        '/nologo',
        '/v:minimal'
    )

    Write-Host "Publishing IIS payload to $OutputPath"
    # Build and toolchain discovery can take time. Re-check ownership and path
    # ancestry immediately before the first DeleteExistingFiles-capable action.
    $OutputPath = Assert-OpenTimeStampPublishOutputSafe -OutputPath $OutputPath `
        -RepositoryRoot $repositoryRoot
    $publishExitCode = $null
    $manifestPath = $null
    $pinnedMarker = Assert-OpenTimeStampPublishMarker -OutputPath $OutputPath
    if (-not ([string]$pinnedMarker.StagingId).Equals(
            $expectedStagingId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The publish marker changed before the destructive publish could begin.'
    }
    if (-not ([string]$pinnedMarker.CreatedUtc).Equals(
            $expectedCreatedUtc, [System.StringComparison]::Ordinal)) {
        throw 'The publish marker creation timestamp changed before the destructive publish could begin.'
    }
    $publishedAppData = Join-Path $OutputPath 'App_Data'
    if (Test-Path -LiteralPath $publishedAppData) {
        throw "The owned publish output contains App_Data; refusing a destructive publish that could erase runtime state."
    }
    $ownershipVerifiedAfterPin = $true

    & $MSBuildPath @publishArguments
    $publishExitCode = $LASTEXITCODE
    if ($publishExitCode -ne 0) {
        throw "Web publish failed with exit code $publishExitCode."
    }

    $requiredFiles = @(
        (Join-Path $OutputPath 'web.config'),
        (Join-Path $OutputPath 'bin\OpenTimeStamp.Web.dll'),
        (Join-Path $OutputPath 'bin\OpenTimeStamp.Core.dll');
        Get-OpenTimeStampRequiredRuntimeAssemblies | ForEach-Object {
            Join-Path $OutputPath "bin\$_"
        })

    foreach ($requiredFile in $requiredFiles) {
        if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
            throw "The publish completed without required file '$requiredFile'."
        }
    }

    # Mutable state must never be part of a release. The IIS installer owns a
    # separately marked data directory and refuses unmanifested files.
    if (Test-Path -LiteralPath $publishedAppData) {
        throw "The published payload unexpectedly contains App_Data. Configure the project to exclude mutable state."
    }

    $manifestPath = New-OpenTimeStampDeploymentManifest -PayloadPath $OutputPath
    Assert-OpenTimeStampPublishedPayload -PayloadPath $OutputPath -AllowPublishMarker | Out-Null
}
finally {
    try {
        try {
            if ($ownershipVerifiedAfterPin) {
                $markerPath = Join-Path $OutputPath $script:OpenTimeStampPublishMarkerName
                if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
                    $finalMarker = Assert-OpenTimeStampPublishMarker -OutputPath $OutputPath
                    if (-not ([string]$finalMarker.StagingId).Equals(
                            $expectedStagingId, [System.StringComparison]::OrdinalIgnoreCase)) {
                        throw 'The publish marker was replaced during publish and will not be overwritten.'
                    }
                }
                else {
                    Write-PinnedPublishMarker -Path $markerPath -CanonicalOutputPath $OutputPath `
                        -StagingId $expectedStagingId -CreatedUtc $expectedCreatedUtc
                    $finalMarker = Assert-OpenTimeStampPublishMarker -OutputPath $OutputPath
                    if (-not ([string]$finalMarker.StagingId).Equals(
                            $expectedStagingId, [System.StringComparison]::OrdinalIgnoreCase)) {
                        throw 'The pinned publish marker could not be restored with its original identifier.'
                    }
                }
            }
        }
        finally {
            if ($null -ne $claimPath) {
                Write-Warning "Publish claim '$claimPath' was preserved because exact ownership-safe cleanup could not be proven."
            }
            if ($null -ne $claimHandle) { $claimHandle.Dispose() }
            if ($null -ne $publishDirectoryHandle) { $publishDirectoryHandle.Dispose() }
        }
    }
    finally {
        Exit-OpenTimeStampDeploymentLock -Lock $publishLock
    }
}

Write-Host 'Publish completed successfully.'
Write-Host "Deployment manifest: $manifestPath"
Write-Output $OutputPath
