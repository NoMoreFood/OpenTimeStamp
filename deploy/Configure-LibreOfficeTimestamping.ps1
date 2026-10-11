#Requires -Version 5.1

<#
.SYNOPSIS
Registers an RFC 3161 server in a LibreOffice user profile.
.DESCRIPTION
Preserves existing TSA URLs and other preferences. Close LibreOffice and its
Quickstarter first. Select the registered TSA when exporting a signed PDF;
adding it to this list does not automatically timestamp every document.
.PARAMETER SettingsPath
Optional registrymodifications.xcu path for a custom LibreOffice user profile.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][uri]$TimestampUrl,
    [string]$UserSid,
    [string]$SettingsPath,
    [switch]$AllowInsecureHttp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-ClientTimestampUrl -CommandType Function -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'ClientConfiguration.Common.ps1')
}
$canonicalUrl = Get-ClientTimestampUrl -Url $TimestampUrl -Protocol rfc3161 -AllowInsecureHttp:$AllowInsecureHttp
$userContext = Get-ClientUserContext -UserSid $UserSid
if (-not $SettingsPath) {
    $SettingsPath = Join-Path (Get-ClientRoamingAppData -UserContext $userContext) `
        'LibreOffice\4\user\registrymodifications.xcu'
}
$SettingsPath = [IO.Path]::GetFullPath($SettingsPath)
$original = if ([IO.File]::Exists($SettingsPath)) { [IO.File]::ReadAllBytes($SettingsPath) } else { $null }
$document = New-Object Xml.XmlDocument
$document.PreserveWhitespace = $true
$document.XmlResolver = $null
if ($null -ne $original) {
    $readerSettings = New-Object Xml.XmlReaderSettings
    $readerSettings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $stream = [IO.MemoryStream]::new($original, $false)
    $reader = [Xml.XmlReader]::Create($stream, $readerSettings)
    try { $document.Load($reader) }
    finally { $reader.Dispose(); $stream.Dispose() }
}
else {
    $document.LoadXml('<oor:items xmlns:oor="http://openoffice.org/2001/registry"></oor:items>')
}
$namespace = 'http://openoffice.org/2001/registry'
if ($document.DocumentElement.LocalName -ne 'items' -or $document.DocumentElement.NamespaceURI -ne $namespace) {
    throw 'SettingsPath must contain a LibreOffice registrymodifications.xcu document.'
}
$namespaces = New-Object Xml.XmlNamespaceManager $document.NameTable
$namespaces.AddNamespace('oor', $namespace)
$configPath = '/org.openoffice.Office.Common/Security/Scripting'
$selector = "/oor:items/item[@oor:path='$configPath']/prop[@oor:name='TSAURLs']"
$properties = @($document.SelectNodes($selector, $namespaces))
if ($properties.Count -gt 1) {
    throw 'The LibreOffice profile contains duplicate TSAURLs settings. Resolve them first.'
}
if ($properties.Count) { $property = $properties[0] }
else {
    $item = $document.CreateElement('item')
    $item.SetAttribute('path', $namespace, $configPath) | Out-Null
    $property = $document.CreateElement('prop')
    $property.SetAttribute('name', $namespace, 'TSAURLs') | Out-Null
    $property.SetAttribute('op', $namespace, 'fuse') | Out-Null
    $property.SetAttribute('type', $namespace, 'oor:string-list') | Out-Null
    $item.AppendChild($property) | Out-Null
    $document.DocumentElement.AppendChild($item) | Out-Null
}
$value = $property.SelectSingleNode('value')
$urls = @()
if ($value) {
    if ($value.HasAttribute('separator', $namespace)) {
        throw 'The LibreOffice TSA list uses a custom separator. Configure this profile through the application.'
    }
    $items = @($value.SelectNodes('it'))
    if ($items.Count) { $urls = @($items | ForEach-Object { $_.InnerText }) }
    elseif ($value.InnerText.Trim()) { $urls = @($value.InnerText.Trim() -split '\s+') }
}
$registered = @($urls | Where-Object { $_ -ceq $canonicalUrl }).Count -ne 0
if (-not $registered) {
    if ($value) { $property.RemoveChild($value) | Out-Null }
    $value = $document.CreateElement('value')
    foreach ($url in @($urls) + @($canonicalUrl)) {
        $item = $document.CreateElement('it')
        $item.InnerText = $url
        $value.AppendChild($item) | Out-Null
    }
    $property.AppendChild($value) | Out-Null
}
if (-not $PSCmdlet.ShouldProcess($SettingsPath, "Register LibreOffice timestamp server '$canonicalUrl'")) { return }
if (Get-Process -Name soffice, 'soffice.bin' -ErrorAction SilentlyContinue) {
    throw 'Close LibreOffice and its Quickstarter before changing the user profile.'
}
$backup = $null
if (-not $registered) {
    if ($document.FirstChild -is [Xml.XmlDeclaration]) { $document.FirstChild.Encoding = 'UTF-8' }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($document.OuterXml)
    $backup = Set-ClientSettingsFile -Path $SettingsPath -Bytes $bytes -OriginalBytes $original
}
[PSCustomObject]@{
    Product = 'LibreOffice'
    UserSid = $userContext.Sid
    TimestampUrl = $canonicalUrl
    SettingsPath = $SettingsPath
    BackupPath = $backup
    NextStep = 'Select this TSA in Export as PDF > Digital Signatures after selecting a signing certificate.'
}
