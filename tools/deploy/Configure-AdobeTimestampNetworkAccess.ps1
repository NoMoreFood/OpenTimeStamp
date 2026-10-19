#Requires -Version 5.1

<#
.SYNOPSIS
Permits the selected TSA hostname in Adobe's Internet-access preferences.
.DESCRIPTION
Use when Adobe prompts for the timestamp network connection. This separate,
explicit operation merges one hostname into the custom Internet-access list.
Adobe matches hostnames independently of scheme and port.
Other entries, unknown-site restrictions, sandboxing, and document trust remain
in place. A block-all preference becomes a custom list with unknown sites blocked.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][uri]$TimestampUrl,
    [ValidateSet('Acrobat', 'Reader')][string]$Product = 'Acrobat',
    [ValidateSet('DC', '2024')][string]$Version = 'DC',
    [string]$UserSid,
    [switch]$AllowInsecureHttp,
    [Parameter(DontShow = $true)]
    [ValidatePattern('^Registry::HKEY_CURRENT_USER\\Software\\OpenTimeStamp-AcrobatSetupTests-[A-Fa-f0-9]+$')]
    [string]$RegistryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-ClientTimestampUrl -CommandType Function -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'ClientConfiguration.Common.ps1')
}
$url = [uri](Get-ClientTimestampUrl -Url $TimestampUrl -Protocol rfc3161 -AllowInsecureHttp:$AllowInsecureHttp)
$user = Get-ClientUserContext -UserSid $UserSid
$productName = if ($Product -eq 'Reader') { 'Acrobat Reader' } else { 'Adobe Acrobat' }
$root = if ($RegistryRoot) { $RegistryRoot } else { "$($user.RegistryRoot)\Software\Adobe\$productName\$Version" }
$path = Join-Path $root 'TrustManager\cDefaultLaunchURLPerms'
$key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
$mode = if ($key) { $key.GetValue('iURLPerms', 1) } else { 1 }
$unknown = if ($key) { $key.GetValue('iUnknownURLPerms', 1) } else { 1 }
if ($mode -notin 0,1,2 -or $unknown -notin 1,2,3) { throw 'Adobe Internet-access preferences are unrecognized.' }
if ($mode -eq 1 -and -not $RegistryRoot) {
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            foreach ($prefix in @('SOFTWARE\Policies\Adobe', 'SOFTWARE\Adobe')) {
                $policy = $machine.OpenSubKey("$prefix\$productName\$Version\FeatureLockDown\cDefaultLaunchURLPerms")
                if ($policy) {
                    try {
                        if ($policy.GetValueNames() -contains 'iUnknownURLPerms' -and
                            $policy.GetValue('iUnknownURLPerms') -ne 3) {
                            throw 'Adobe policy prevents retaining block-all behavior for other sites. Update the policy.'
                        }
                    }
                    finally { $policy.Dispose() }
                }
            }
        }
        finally { $machine.Dispose() }
    }
}
$hostName = $url.DnsSafeHost.ToLowerInvariant()
if ($mode -eq 2) {
    return [pscustomobject]@{ Product = $productName; Host = $hostName; Status = 'AlreadyAllowed' }
}
$entries = @()
$list = if ($key) { [string]$key.GetValue('tHostPerms', '') } else { '' }
if ($list) {
    $parts = $list -split '\|'
    if ($parts[0] -cne 'version:1') { throw 'Adobe Internet-access list has an unrecognized format.' }
    foreach ($entry in $parts | Select-Object -Skip 1) {
        if (-not $entry) { continue }
        if ($entry -notmatch '^(.+):([123])$') { throw 'An Adobe Internet-access list entry is malformed.' }
        if ($Matches[1] -ine $hostName) { $entries += $entry }
    }
}
$entries += $hostName + ':2'
$values = @(
    [pscustomobject]@{ Path = $path; Name = 'tHostPerms'; Kind = 'String'; Value = 'version:1|' + ($entries -join '|') },
    [pscustomobject]@{ Path = $path; Name = 'iURLPerms'; Kind = 'DWord'; Value = 0 })
if ($mode -eq 1) {
    $values += [pscustomobject]@{ Path = $path; Name = 'iUnknownURLPerms'; Kind = 'DWord'; Value = 3 }
}
if (-not $PSCmdlet.ShouldProcess($path, "Permit the timestamp hostname '$hostName'")) { return }
if (-not $RegistryRoot -and (Get-Process Acrobat,AcroRd32 -ErrorAction SilentlyContinue)) {
    throw 'Close Adobe Acrobat and Reader before changing Internet-access preferences.'
}
Set-ClientRegistryValues -Values $values
[pscustomobject]@{ Product = $productName; Host = $hostName; Status = 'Configured'; RegistryPath = $path }
