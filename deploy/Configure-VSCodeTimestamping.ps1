#Requires -Version 5.1

<#
.SYNOPSIS
Adds a manual timestamped-signing task to a selected VS Code workspace.
.DESCRIPTION
Preserves existing tasks, inputs, comments, and trailing commas. A conflicting
task label is rejected. The task references an existing signing wrapper and
does not change Workspace Trust or PowerShell execution policy. Use a trusted
workspace when running it. PowerShellArchitecture selects the signing host,
independently of the executable being signed.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$WorkspacePath,
    [Parameter(Mandatory = $true)][uri]$ServerUrl,
    [ValidateSet('PowerShell', 'SignTool')][string]$SigningTool = 'PowerShell',
    [ValidateSet('Auto', 'x86', 'x64')][string]$PowerShellArchitecture = 'Auto',
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$CertificateStoreLocation = 'CurrentUser',
    [string]$SigningScriptPath,
    [string]$SignToolPath,
    [string]$TaskLabel,
    [switch]$AllowInsecureHttp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-ClientTimestampUrl -CommandType Function -ErrorAction SilentlyContinue))
{
    . (Join-Path $PSScriptRoot 'ClientConfiguration.Common.ps1')
}
Get-ClientServerEndpoints -ServerUrl $ServerUrl -AllowInsecureHttp:$AllowInsecureHttp | Out-Null
$workspace = Get-Item -LiteralPath $WorkspacePath -ErrorAction Stop
if (-not $workspace.PSIsContainer) { throw 'WorkspacePath must identify an existing project directory.' }
if (-not $SigningScriptPath) { $SigningScriptPath = Join-Path $PSScriptRoot 'Invoke-TimestampSigning.ps1' }
$SigningScriptPath = (Get-Item -LiteralPath $SigningScriptPath -ErrorAction Stop).FullName
$commonPath = Join-Path (Split-Path -Parent $SigningScriptPath) 'ClientConfiguration.Common.ps1'
if (-not (Test-Path -LiteralPath $commonPath -PathType Leaf))
{
    throw 'Keep the signing wrapper beside ClientConfiguration.Common.ps1 on the signing computer.'
}
if ($SigningTool -eq 'SignTool')
{
    if (-not $SignToolPath)
    {
        $command = Get-Command signtool.exe -CommandType Application -ErrorAction SilentlyContinue
        if (-not $command) { throw 'Supply SignToolPath for the intended Windows SDK signing executable.' }
        $SignToolPath = $command.Source
    }
    $SignToolPath = (Get-Item -LiteralPath $SignToolPath -ErrorAction Stop).FullName
}
$architecture = $PowerShellArchitecture
if ($architecture -eq 'Auto') { $architecture = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' } }
if ($architecture -eq 'x64' -and -not [Environment]::Is64BitOperatingSystem)
{ throw 'The selected signing host requires 64-bit Windows.' }
$systemDirectory = if ($architecture -eq 'x86' -and [Environment]::Is64BitOperatingSystem) { 'SysWOW64' }
else { 'System32' }
$hostPath = Join-Path $env:SystemRoot "$systemDirectory\WindowsPowerShell\v1.0\powershell.exe"
$probePath = $hostPath
if ($architecture -eq 'x64' -and -not [Environment]::Is64BitProcess)
{ $probePath = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe' }
if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) { throw 'The selected signing host is not installed.' }
if (-not $TaskLabel) { $TaskLabel = "OpenTimeStamp: $SigningTool signing ($($ServerUrl.Scheme), $architecture)" }
if ([string]::IsNullOrWhiteSpace($TaskLabel)) { throw 'TaskLabel must contain visible text.' }
$sha256 = [Security.Cryptography.SHA256]::Create()
try { $id = ([BitConverter]::ToString($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($TaskLabel)))).Replace('-', '') }
finally { $sha256.Dispose() }
$fileInput = 'OpenTimeStampFile' + $id.Substring(0, 12)
$certificateInput = 'OpenTimeStampCertificate' + $id.Substring(0, 12)
$arguments = @('-NoLogo', '-NoProfile', '-File', $SigningScriptPath,
    '-LiteralPath', ('${input:' + $fileInput + '}'), '-ServerUrl', $ServerUrl.AbsoluteUri,
    '-CertificateThumbprint', ('${input:' + $certificateInput + '}'), '-Tool', $SigningTool,
    '-CertificateStoreLocation', $CertificateStoreLocation)
if ($SigningTool -eq 'SignTool') { $arguments += @('-SignToolPath', $SignToolPath) }
if ($AllowInsecureHttp) { $arguments += '-AllowInsecureHttp' }
$task = [pscustomobject][ordered]@{
    label = $TaskLabel
    type = 'process'
    command = $hostPath
    args = $arguments
    problemMatcher = @()
}
$inputs = @(
    [pscustomobject][ordered]@{ id = $fileInput; type = 'promptString'; description = 'Full path of the file to sign' },
    [pscustomobject][ordered]@{ id = $certificateInput; type = 'promptString'; description = 'Signing certificate thumbprint' })
$path = Join-Path $workspace.FullName '.vscode\tasks.json'
$original = if ([IO.File]::Exists($path)) { [IO.File]::ReadAllBytes($path) } else { $null }
$text = if ($original) { [IO.File]::ReadAllText($path) } else { '{"version":"2.0.0","tasks":[],"inputs":[]}' }
$updated = Add-ClientJsonArrayEntries -Text $text -Entries @{ tasks = @($task); inputs = $inputs } `
    -IdentityProperties @{ tasks = 'label'; inputs = 'id' }
if (-not $PSCmdlet.ShouldProcess($path, "Add signing task '$TaskLabel'")) { return }
$backup = $null
if ($updated -cne $text)
{
    $encoding = [Text.UTF8Encoding]::new($false)
    if ($original)
    {
        $stream = [IO.MemoryStream]::new($original, $false)
        $reader = [IO.StreamReader]::new($stream, $encoding, $true)
        try { $reader.ReadToEnd() | Out-Null; $encoding = $reader.CurrentEncoding }
        finally { $reader.Dispose() }
    }
    $bytes = $encoding.GetPreamble() + $encoding.GetBytes($updated)
    $backup = Set-ClientSettingsFile -Path $path -Bytes $bytes -OriginalBytes $original
}
[pscustomobject]@{
    Product = 'Visual Studio Code'
    WorkspacePath = $workspace.FullName
    TasksPath = $path
    TaskLabel = $TaskLabel
    PowerShellArchitecture = $architecture
    BackupPath = $backup
    NextStep = 'In a trusted workspace, run the signing task and supply the file path and signing certificate thumbprint.'
}
