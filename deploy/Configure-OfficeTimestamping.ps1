#Requires -Version 5.1

<#
.SYNOPSIS
Configures Microsoft Office document and VBA timestamping for a signing user.
.DESCRIPTION
Document signatures request and require XAdES-T using the RFC 3161 endpoint.
The VBA editor uses the legacy Authenticode endpoint. Close Office before setup.
Policy conflicts stop setup without changing centrally managed settings.
.PARAMETER UserSid
Optional SID of a user whose registry hive is already loaded on this computer.
The default is the user running the script, including in a remoting session.
.PARAMETER AllowSigningWithoutTimestamp
Allows Office document signatures to fall back to XAdES-EPES. VBA's documented
settings do not provide a switch that guarantees timestamp retrieval succeeds.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [uri]$Rfc3161Url,
    [uri]$AuthenticodeUrl,
    [ValidateSet('Documents', 'Vba', 'Both')][string]$SigningType = 'Both',
    [ValidatePattern('^\d+\.0$')][string[]]$OfficeVersion = @('16.0'),
    [string]$UserSid,
    [ValidateRange(1, 100)][int]$VbaRetryCount = 3,
    [ValidateRange(0, 60000)][int]$VbaRetryDelayMilliseconds = 1000,
    [switch]$AllowSigningWithoutTimestamp,
    [switch]$AllowInsecureHttp,
    [Parameter(DontShow = $true)]
    [ValidatePattern('^Registry::HKEY_CURRENT_USER\\Software\\OpenTimeStamp-ClientSetupTests-[A-Fa-f0-9]+$')]
    [string]$RegistryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-ClientTimestampUrl -CommandType Function -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'ClientConfiguration.Common.ps1')
}
$userContext = Get-ClientUserContext -UserSid $UserSid
$effectiveRegistryRoot = if ($RegistryRoot) { $RegistryRoot } else { $userContext.RegistryRoot }
$values = @()

if ($SigningType -in @('Documents', 'Both')) {
    if (-not $Rfc3161Url) { throw 'Rfc3161Url is required for Office document signatures.' }
    $documentUrl = Get-ClientTimestampUrl -Url $Rfc3161Url -Protocol rfc3161 -AllowInsecureHttp:$AllowInsecureHttp
    foreach ($version in $OfficeVersion | Select-Object -Unique) {
        $path = Join-Path $effectiveRegistryRoot "Software\Microsoft\Office\$version\Common\Signatures"
        $minimumLevel = if ($AllowSigningWithoutTimestamp) { 1 } else { 2 }
        $settings = @(
            @{ Name = 'TSALocation'; Kind = 'String'; Value = $documentUrl },
            @{ Name = 'XAdESLevel'; Kind = 'DWord'; Value = 2 },
            @{ Name = 'MinXAdESLevel'; Kind = 'DWord'; Value = $minimumLevel })
        $policyPath = Join-Path $effectiveRegistryRoot "Software\Policies\Microsoft\Office\$version\Common\Signatures"
        $policy = Get-Item -LiteralPath $policyPath -ErrorAction SilentlyContinue
        foreach ($setting in $settings) {
            if ($policy -and $policy.GetValueNames() -contains $setting.Name -and
                ($policy.GetValue($setting.Name) -ne $setting.Value -or
                    [string]$policy.GetValueKind($setting.Name) -ne $setting.Kind)) {
                throw "Office policy '$policyPath\$($setting.Name)' conflicts with setup. Update the Office policy."
            }
            $values += [PSCustomObject]@{
                Path = $path; Name = $setting.Name; Kind = $setting.Kind; Value = $setting.Value
            }
        }
    }
}
if ($SigningType -in @('Vba', 'Both')) {
    if (-not $AuthenticodeUrl) { throw 'AuthenticodeUrl is required for the VBA editor.' }
    $vbaUrl = Get-ClientTimestampUrl -Url $AuthenticodeUrl -Protocol authenticode -AllowInsecureHttp:$AllowInsecureHttp
    $path = Join-Path $effectiveRegistryRoot 'Software\Microsoft\VBA\Security'
    $values += @(
        [PSCustomObject]@{ Path = $path; Name = 'TimeStampURL'; Kind = 'String'; Value = $vbaUrl },
        [PSCustomObject]@{ Path = $path; Name = 'TimeStampRetryCount'; Kind = 'DWord'; Value = $VbaRetryCount },
        [PSCustomObject]@{
            Path = $path; Name = 'TimeStampRetryDelay'; Kind = 'DWord'; Value = $VbaRetryDelayMilliseconds
        })
}

if (-not $PSCmdlet.ShouldProcess("$env:COMPUTERNAME / $($userContext.Sid)",
        "Configure Office $SigningType timestamping")) {
    return
}
if ($effectiveRegistryRoot -eq $userContext.RegistryRoot -and
    (Get-Process -Name WINWORD, EXCEL, POWERPNT, OUTLOOK, MSACCESS, VISIO, MSPUB, WINPROJ `
        -ErrorAction SilentlyContinue)) {
    throw 'Close Microsoft Office applications before changing timestamp settings.'
}
Set-ClientRegistryValues -Values $values
[PSCustomObject]@{
    Product = "Microsoft Office $SigningType"
    UserSid = $userContext.Sid
    RegistryRoot = $effectiveRegistryRoot
    TimestampRequired = if ($SigningType -eq 'Vba') { $null } else { -not [bool]$AllowSigningWithoutTimestamp }
}
