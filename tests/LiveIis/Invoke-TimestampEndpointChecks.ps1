#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BinaryDirectory,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$ManifestPath,
    [switch]$CompileOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Compile the live verifier with the repository's compiler and the exact published dependency set.
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repositoryRoot 'build\Build.Common.ps1')
$msbuild = Resolve-OpenTimeStampMSBuild
$compiler = Join-Path (Split-Path -Parent $msbuild) 'Roslyn\csc.exe'
$binaryPath = [IO.Path]::GetFullPath($BinaryDirectory)
$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
if (-not (Test-Path -LiteralPath (Join-Path $binaryPath 'OpenTimeStamp.Core.dll') -PathType Leaf)) {
    throw 'BinaryDirectory must contain the current published Core assembly and its dependencies.'
}
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
Get-ChildItem -LiteralPath $binaryPath -File -Filter '*.dll' |
    Copy-Item -Destination $outputPath -Force

# Reference the deployed libraries so native verification uses the same dependencies as the tested server.
$executable = Join-Path $outputPath 'TimestampEndpointChecks.exe'
$references = @('System.dll', 'System.Core.dll', 'System.Runtime.Serialization.dll') + @(
    Get-ChildItem -LiteralPath $outputPath -File -Filter '*.dll' | Select-Object -ExpandProperty FullName)
$arguments = @('/nologo', '/langversion:14', '/platform:x64', '/target:exe', '/optimize+', "/out:$executable") + @(
    $references | ForEach-Object { "/reference:$_" }) + @(Join-Path $PSScriptRoot 'TimestampEndpointChecks.cs')
& $compiler @arguments
if ($LASTEXITCODE -ne 0) { throw "Live verifier compilation failed with exit code $LASTEXITCODE." }

# Supply the application runtime target so framework networking selects the operating system's TLS defaults.
$runtimeConfiguration = @'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8" />
  </startup>
</configuration>
'@
[IO.File]::WriteAllText($executable + '.config', $runtimeConfiguration, [Text.UTF8Encoding]::new($false))

# Compilation can happen on the build computer before copying the complete verifier directory into a VM.
if ($CompileOnly) { return $executable }
if ([string]::IsNullOrWhiteSpace($ManifestPath) -or -not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw 'Supply an explicit live IIS manifest, or select CompileOnly.'
}
$evidencePath = Join-Path $outputPath ('results-' + [guid]::NewGuid().ToString('N'))
& $executable ([IO.Path]::GetFullPath($ManifestPath)) $evidencePath
if ($LASTEXITCODE -ne 0) { throw "Live IIS checks failed. Inspect '$evidencePath\results.json'." }
