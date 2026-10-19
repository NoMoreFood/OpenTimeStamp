#Requires -Version 5.1

<#
.SYNOPSIS
Registers an anonymous RFC 3161 preset for PDF-XChange Editor.
.DESCRIPTION
Merges the server into TimeStampServer.presets, preserving other presets and IDs.
Close the Editor before setup. Select this preset when signing; this script does
not change the application's default signing template.
.PARAMETER PresetPath
Optional destination for a portable installation or an exported preset file.
Without it, the existing user profile is detected. Ambiguous profiles require
an explicit path so setup cannot target an obsolete profile.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][uri]$TimestampUrl,
    [ValidateNotNullOrEmpty()][string]$ServerName = 'OpenTimeStamp',
    [string]$UserSid,
    [string]$PresetPath,
    [switch]$AllowInsecureHttp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-ClientTimestampUrl -CommandType Function -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'ClientConfiguration.Common.ps1')
}
$canonicalUrl = Get-ClientTimestampUrl -Url $TimestampUrl -Protocol rfc3161 -AllowInsecureHttp:$AllowInsecureHttp
if ([string]::IsNullOrWhiteSpace($ServerName) -or $ServerName.IndexOfAny([char[]]"`r`n") -ge 0) {
    throw 'ServerName must contain visible text on one line.'
}
$userContext = Get-ClientUserContext -UserSid $UserSid
if (-not $PresetPath) {
    $appData = Get-ClientRoamingAppData -UserContext $userContext
    $profiles = @(
        (Join-Path $appData 'PDF-XChange\PDF Editor'),
        (Join-Path $appData 'Tracker Software\PDFXEditor\3.0'))
    $existing = @($profiles | Where-Object { Test-Path -LiteralPath $_ -PathType Container })
    if ($existing.Count -ne 1) {
        throw 'Supply PresetPath: the PDF-XChange user profile is missing or more than one profile exists.'
    }
    $PresetPath = Join-Path $existing[0] 'Presets\TimeStampServer.presets'
}
$PresetPath = [IO.Path]::GetFullPath($PresetPath)
$original = if ([IO.File]::Exists($PresetPath)) { [IO.File]::ReadAllBytes($PresetPath) } else { $null }
$settings = if ($null -ne $original) {
    Get-Content -LiteralPath $PresetPath -Raw -Encoding UTF8 | ConvertFrom-Json
}
else { [PSCustomObject]@{ TimestampServers = [PSCustomObject]@{ Items = @() } } }
if (-not $settings -or $settings -is [array] -or -not $settings.PSObject.Properties['TimestampServers'] -or
    -not $settings.TimestampServers -or -not $settings.TimestampServers.PSObject.Properties['Items']) {
    throw 'PresetPath must contain a JSON object with TimestampServers.Items.'
}
$items = @($settings.TimestampServers.Items)
$matches = @()
foreach ($item in $items) {
    if (-not $item -or -not $item.PSObject.Properties['Data'] -or -not $item.Data -or
        -not $item.Data.PSObject.Properties['URL'] -or -not $item.PSObject.Properties['Name']) {
        throw 'An existing PDF-XChange timestamp preset is malformed. Resolve it in the Editor first.'
    }
    $existingUrl = [string]$item.Data.URL
    try {
        $existingUrl = Get-ClientTimestampUrl -Url ([uri]$existingUrl) -Protocol rfc3161 `
            -AllowInsecureHttp:$AllowInsecureHttp
    }
    catch { }
    $sameUrl = $existingUrl -ceq $canonicalUrl
    if ($item.Name -eq $ServerName -and -not $sameUrl) {
        throw "PDF-XChange server name '$ServerName' already refers to another URL. Supply a different ServerName."
    }
    if ($sameUrl) { $matches += $item }
}
if ($matches.Count -gt 1) { throw 'PDF-XChange contains duplicate presets for this timestamp URL.' }
$preset = if ($matches.Count) { $matches[0] } else {
    [PSCustomObject]@{ ID = '{' + [Guid]::NewGuid().ToString().ToUpperInvariant() + '}'; Flags = 0 }
}
$description = "URL: $canonicalUrl"
if ($preset.PSObject.Properties['Name']) { $preset.Name = $ServerName }
else { $preset | Add-Member -NotePropertyName Name -NotePropertyValue $ServerName }
if ($preset.PSObject.Properties['Desc']) { $preset.Desc = $description }
else { $preset | Add-Member -NotePropertyName Desc -NotePropertyValue $description }
if (-not $preset.PSObject.Properties['Data']) {
    $preset | Add-Member -NotePropertyName Data -NotePropertyValue ([PSCustomObject]@{})
}
$serverSettings = [ordered]@{ URL = $canonicalUrl; User = ''; Password = ''; RequireAuth = $false }
foreach ($setting in $serverSettings.GetEnumerator()) {
    if ($preset.Data.PSObject.Properties[$setting.Key]) { $preset.Data.($setting.Key) = $setting.Value }
    else { $preset.Data | Add-Member -NotePropertyName $setting.Key -NotePropertyValue $setting.Value }
}
if (-not $matches.Count) { $items += $preset }
$settings.TimestampServers.Items = @($items)
$bytes = [Text.UTF8Encoding]::new($false).GetBytes(($settings | ConvertTo-Json -Depth 30 -WarningAction Stop) + "`r`n")
if (-not $PSCmdlet.ShouldProcess($PresetPath, "Register PDF-XChange timestamp preset '$ServerName'")) { return }
if (Get-Process -Name PDFXEdit, PXCEditor -ErrorAction SilentlyContinue) {
    throw 'Close PDF-XChange Editor before changing timestamp presets.'
}
$backup = Set-ClientSettingsFile -Path $PresetPath -Bytes $bytes -OriginalBytes $original
[PSCustomObject]@{
    Product = 'PDF-XChange Editor'
    UserSid = $userContext.Sid
    TimestampUrl = $canonicalUrl
    PresetPath = $PresetPath
    BackupPath = $backup
    NextStep = 'Select this timestamp preset in Sign Document; import the preset file if it is not listed.'
}
