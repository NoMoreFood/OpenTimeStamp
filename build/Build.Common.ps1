#Requires -Version 5.1

Set-StrictMode -Version Latest

function Assert-OpenTimeStampMSBuildToolchain {
    param([Parameter(Mandatory = $true)][string]$MSBuildPath)

    $resolved = [System.IO.Path]::GetFullPath($MSBuildPath)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "MSBuild was not found at '$resolved'."
    }

    $directory = Get-Item -LiteralPath (Split-Path -Parent $resolved)
    while ($null -ne $directory -and
        -not $directory.Name.Equals('MSBuild', [System.StringComparison]::OrdinalIgnoreCase)) {
        $directory = $directory.Parent
    }
    if ($null -eq $directory) {
        throw "MSBuild '$resolved' is not installed beneath a Visual Studio MSBuild directory."
    }

    $webTargets = Join-Path $directory.FullName `
        'Microsoft\VisualStudio\v18.0\WebApplications\Microsoft.WebApplication.targets'
    if (-not (Test-Path -LiteralPath $webTargets -PathType Leaf)) {
        throw "MSBuild '$resolved' does not have the Visual Studio 18 Web development build targets."
    }
    $compiler = Join-Path $directory.FullName 'Current\Bin\Roslyn\csc.exe'
    if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
        throw "MSBuild '$resolved' does not have the Visual Studio Roslyn compiler."
    }
    $compilerVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($compiler).ProductVersion
    $compilerMajor = 0
    if ($compilerVersion -notmatch '^(?<Major>[0-9]+)' -or
        -not [int]::TryParse($Matches.Major, [ref]$compilerMajor) -or $compilerMajor -lt 5) {
        throw "Compiler '$compiler' version '$compilerVersion' is not C# 14-capable."
    }
    return $resolved
}

function Resolve-OpenTimeStampMSBuild {
    param([string]$RequestedPath)

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        return (Assert-OpenTimeStampMSBuildToolchain -MSBuildPath $RequestedPath)
    }

    $discoveryError = $null
    $programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    $vswhere = Join-Path $programFilesX86 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
        # Workload IDs differ between full Visual Studio and Build Tools installations.
        # Discover MSBuild broadly, then validate the actual compiler and web-target files below.
        $matches = @(& $vswhere -all -products * -requires Microsoft.Component.MSBuild `
            -find 'MSBuild\**\Bin\MSBuild.exe')
        if ($LASTEXITCODE -eq 0) {
            foreach ($match in $matches) {
                try { return (Assert-OpenTimeStampMSBuildToolchain -MSBuildPath $match) }
                catch { $discoveryError = $_ }
            }
        }
    }

    $command = Get-Command MSBuild.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return (Assert-OpenTimeStampMSBuildToolchain -MSBuildPath $command.Source)
    }

    $suffix = if ($null -ne $discoveryError) { " Last discovered candidate: $($discoveryError.Exception.Message)" } else { '' }
    throw ('A C# 14-capable Visual Studio 18 MSBuild with the .NET Framework 4.8 targeting pack and Web ' +
        "development build tools was not found. Install the required workload, or pass -MSBuildPath.$suffix")
}
