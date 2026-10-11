#Requires -Version 5.1

<#
.SYNOPSIS
Configures the timestamp URLs in an explicitly selected InstallShield Settings.xml.
.DESCRIPTION
Updates existing DigitalSignature Timestamp and TimestampRFC3161 attributes,
preserving other settings and saving the original file as a backup. Close the
IDE and build processes first. The IDE and Standalone Build use separate files.
Changing an installed Settings.xml normally requires an elevated prompt.
.PARAMETER SettingsPath
The existing Settings.xml for the intended InstallShield edition and language.
The script does not discover or modify other installed editions automatically.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$SettingsPath,
    [Parameter(Mandatory = $true)][uri]$ServerUrl,
    [switch]$AllowInsecureHttp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-ClientTimestampUrl -CommandType Function -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'ClientConfiguration.Common.ps1')
}
$endpoints = Get-ClientServerEndpoints -ServerUrl $ServerUrl -AllowInsecureHttp:$AllowInsecureHttp
$SettingsPath = [IO.Path]::GetFullPath($SettingsPath)
if (-not [IO.File]::Exists($SettingsPath)) {
    throw 'SettingsPath must identify an existing InstallShield Settings.xml.'
}
$original = [IO.File]::ReadAllBytes($SettingsPath)
$document = New-Object Xml.XmlDocument
$document.PreserveWhitespace = $true
$document.XmlResolver = $null
$readerSettings = New-Object Xml.XmlReaderSettings
$readerSettings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
$stream = [IO.MemoryStream]::new($original, $false)
$reader = [Xml.XmlReader]::Create($stream, $readerSettings)
try { $document.Load($reader) }
finally { $reader.Dispose(); $stream.Dispose() }
$nodes = @($document.SelectNodes('/DevStudio/Build/DigitalSignature[@Timestamp or @TimestampRFC3161]'))
if (-not $nodes.Count) {
    throw 'Settings.xml has no recognized DevStudio/Build/DigitalSignature timestamp selector. Check the installed schema.'
}
$changed = $false
foreach ($node in $nodes) {
    foreach ($attribute in ([ordered]@{
            Timestamp = $endpoints.AuthenticodeUrl; TimestampRFC3161 = $endpoints.Rfc3161Url
        }).GetEnumerator()) {
        if ($node.HasAttribute($attribute.Key) -and $node.GetAttribute($attribute.Key) -cne $attribute.Value) {
            $node.SetAttribute($attribute.Key, $attribute.Value)
            $changed = $true
        }
    }
}
if (-not $PSCmdlet.ShouldProcess($SettingsPath, 'Configure InstallShield timestamp servers')) { return }
if (Get-Process -Name isdev, ISCmdBld, ISBuild -ErrorAction SilentlyContinue) {
    throw 'Close InstallShield and its build processes before changing Settings.xml.'
}
$backup = $null
if ($changed) {
    if ($document.FirstChild -is [Xml.XmlDeclaration]) { $document.FirstChild.Encoding = 'UTF-8' }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($document.OuterXml)
    $backup = Set-ClientSettingsFile -Path $SettingsPath -Bytes $bytes -OriginalBytes $original
}
[PSCustomObject]@{
    Product = 'InstallShield'
    SettingsPath = $SettingsPath
    BackupPath = $backup
    Rfc3161Url = $endpoints.Rfc3161Url
    AuthenticodeUrl = $endpoints.AuthenticodeUrl
    NextStep = 'Enable release signing, verify an output timestamp, and configure the Standalone Build if used.'
}
