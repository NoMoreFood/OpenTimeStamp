#Requires -Version 5.1

<#
.SYNOPSIS
Configures OpenTimeStamp for the current Adobe Acrobat Continuous user.

.DESCRIPTION
Adds or reuses an anonymous RFC 3161 timestamp server, selects it as Acrobat's
default with SHA-256, and by default requires timestamp retrieval to succeed.
Run this script as each signing user while Acrobat and Reader are closed.

Protected Mode does not require a timestamp URL exception. This script does not
change Protected Mode, Protected View, Enhanced Security, trusted sites, or
Acrobat Trust Manager Internet permissions. It does not make a document in the
read-only Protected View signable.

.PARAMETER TimestampUrl
The exact HTTP(S) RFC 3161 endpoint. HTTPS is required unless
AllowInsecureHttp is supplied for a loopback development endpoint.

.PARAMETER AllowSigningWithoutTimestamp
Allows Acrobat to create a signature using the local clock if timestamp
retrieval fails. Omit this switch to fail closed when no timestamp is available.

.PARAMETER AllowInsecureHttp
Permits HTTP only when TimestampUrl is a loopback URL. Use this solely for local
development; production timestamping should use HTTPS.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [uri]$TimestampUrl,

    [ValidateNotNullOrEmpty()]
    [string]$ServerName = 'OpenTimeStamp',

    [switch]$AllowSigningWithoutTimestamp,

    [switch]$AllowInsecureHttp,

    [Parameter(DontShow = $true)]
    [ValidateScript({
        $_ -eq 'Registry::HKEY_CURRENT_USER\Software\Adobe\Adobe Acrobat\DC' -or
        $_ -match '^Registry::HKEY_CURRENT_USER\\Software\\OpenTimeStamp-AcrobatSetupTests-[A-Fa-f0-9]+$'
    })]
    [string]$RegistryRoot = 'Registry::HKEY_CURRENT_USER\Software\Adobe\Adobe Acrobat\DC'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:acrobatRegistryRoot = $RegistryRoot
$script:registryJournal = [System.Collections.Generic.List[object]]::new()
$script:createdRegistryPaths = @{}

function Get-CanonicalTimestampUrl {
    param([Parameter(Mandatory = $true)][uri]$Url)

    if (-not $Url.IsAbsoluteUri -or $Url.Scheme -notin @('http', 'https') -or
        [string]::IsNullOrWhiteSpace($Url.Host)) {
        throw 'TimestampUrl must be an absolute HTTP or HTTPS URL.'
    }
    if ($Url.Scheme -eq 'http' -and (-not $AllowInsecureHttp -or -not $Url.IsLoopback)) {
        throw 'TimestampUrl must use HTTPS. -AllowInsecureHttp permits only a loopback development endpoint.'
    }
    if (-not [string]::IsNullOrEmpty($Url.UserInfo) -or
        -not [string]::IsNullOrEmpty($Url.Query) -or
        -not [string]::IsNullOrEmpty($Url.Fragment)) {
        throw 'TimestampUrl cannot contain user information, a query, or a fragment.'
    }
    if ($Url.OriginalString.IndexOfAny([char[]]'*|') -ge 0) {
        throw 'TimestampUrl cannot contain a wildcard or the Trust Manager list delimiter.'
    }
    if (-not $Url.AbsolutePath.TrimEnd('/').EndsWith('/timestamp/rfc3161', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'TimestampUrl must identify the OpenTimeStamp /timestamp/rfc3161 endpoint.'
    }

    $builder = New-Object UriBuilder $Url
    $builder.Scheme = $Url.Scheme.ToLowerInvariant()
    $builder.Host = $Url.DnsSafeHost.ToLowerInvariant()
    if (($builder.Scheme -eq 'https' -and $builder.Port -eq 443) -or
        ($builder.Scheme -eq 'http' -and $builder.Port -eq 80)) {
        $builder.Port = -1
    }
    $canonical = $builder.Uri.AbsoluteUri
    foreach ($character in $canonical.ToCharArray()) {
        if ([int]$character -gt 127) {
            throw 'TimestampUrl must have an ASCII registry representation; use the URL ASCII/punycode form.'
        }
    }
    return $canonical
}

function Test-RegistryValueEqual {
    param($Left, $Right)

    if ($Left -is [byte[]] -or $Right -is [byte[]]) {
        if (-not ($Left -is [byte[]]) -or -not ($Right -is [byte[]]) -or $Left.Length -ne $Right.Length) {
            return $false
        }
        for ($index = 0; $index -lt $Left.Length; $index++) {
            if ($Left[$index] -ne $Right[$index]) { return $false }
        }
        return $true
    }
    return $Left -eq $Right
}

function Add-MissingRegistryPaths {
    param([Parameter(Mandatory = $true)][string]$Path)

    $missing = @()
    $candidate = $Path
    while ($candidate.StartsWith($script:acrobatRegistryRoot, [StringComparison]::OrdinalIgnoreCase) -and
        -not (Test-Path -LiteralPath $candidate)) {
        $missing += $candidate
        if ($candidate.Equals($script:acrobatRegistryRoot, [StringComparison]::OrdinalIgnoreCase)) { break }
        $candidate = Split-Path -Parent $candidate
    }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    foreach ($created in $missing) { $script:createdRegistryPaths[$created] = $true }
}

function Set-TrackedRegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][Microsoft.Win32.RegistryValueKind]$Kind
    )

    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    $existed = $null -ne $key -and $key.GetValueNames() -contains $Name
    $beforeValue = $null
    $beforeKind = $null
    if ($existed) {
        $beforeValue = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $beforeKind = $key.GetValueKind($Name)
        if ($beforeKind -eq $Kind -and (Test-RegistryValueEqual -Left $beforeValue -Right $Value)) { return }
    }

    $entry = [PSCustomObject]@{
        Path = $Path
        Name = $Name
        Existed = $existed
        BeforeValue = $beforeValue
        BeforeKind = $beforeKind
        AppliedValue = $Value
        AppliedKind = $Kind
        AppliedExists = $true
    }
    $script:registryJournal.Add($entry)
    Add-MissingRegistryPaths -Path $Path
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType ([string]$Kind) `
        -Force | Out-Null
    $verified = Get-Item -LiteralPath $Path
    if ($verified.GetValueKind($Name) -ne $Kind -or
        -not (Test-RegistryValueEqual -Left $verified.GetValue($Name) -Right $Value)) {
        throw "Acrobat registry value '$Path\$Name' could not be written and verified."
    }
}

function Remove-TrackedRegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $key -or $key.GetValueNames() -notcontains $Name) { return }

    $entry = [PSCustomObject]@{
        Path = $Path
        Name = $Name
        Existed = $true
        BeforeValue = $key.GetValue(
            $Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        BeforeKind = $key.GetValueKind($Name)
        AppliedValue = $null
        AppliedKind = $null
        AppliedExists = $false
    }
    $script:registryJournal.Add($entry)
    Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
    $verified = Get-Item -LiteralPath $Path
    if ($verified.GetValueNames() -contains $Name) {
        throw "Acrobat registry value '$Path\$Name' could not be removed and verified."
    }
}

function Restore-TrackedRegistryValues {
    $errors = @()
    for ($index = $script:registryJournal.Count - 1; $index -ge 0; $index--) {
        $entry = $script:registryJournal[$index]
        try {
            $key = Get-Item -LiteralPath $entry.Path -ErrorAction SilentlyContinue
            $currentExists = $null -ne $key -and $key.GetValueNames() -contains $entry.Name
            if ($currentExists) {
                $currentKind = $key.GetValueKind($entry.Name)
                $currentValue = $key.GetValue(
                    $entry.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $stillApplied = $entry.AppliedExists -and $currentKind -eq $entry.AppliedKind -and
                    (Test-RegistryValueEqual -Left $currentValue -Right $entry.AppliedValue)
                $alreadyRestored = $entry.Existed -and $currentKind -eq $entry.BeforeKind -and
                    (Test-RegistryValueEqual -Left $currentValue -Right $entry.BeforeValue)
            }
            else {
                $stillApplied = -not $entry.AppliedExists
                $alreadyRestored = -not $entry.Existed
            }
            if ($alreadyRestored) { continue }
            if (-not $stillApplied) {
                $errors += "'$($entry.Path)\$($entry.Name)' changed after setup wrote it"
                continue
            }

            if ($entry.Existed) {
                New-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -Value $entry.BeforeValue `
                    -PropertyType ([string]$entry.BeforeKind) -Force | Out-Null
            }
            else {
                Remove-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -ErrorAction Stop
            }
        }
        catch {
            $errors += "'$($entry.Path)\$($entry.Name)': $($_.Exception.Message)"
        }
    }

    foreach ($path in @($script:createdRegistryPaths.Keys | Sort-Object Length -Descending)) {
        try {
            $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
            if ($key -and $key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) {
                Remove-Item -LiteralPath $path -Force
            }
        }
        catch { $errors += "'$path': $($_.Exception.Message)" }
    }
    if ($errors.Count -ne 0) { throw ('Acrobat registry rollback was incomplete: ' + ($errors -join '; ')) }
}

function Get-AcrobatTimestampServerKey {
    param([Parameter(Mandatory = $true)][string]$Url)

    $listPath = Join-Path $script:acrobatRegistryRoot 'Security\cPPKHandler\cTimeStampServers'
    $urlMatches = @()
    $usedIndexes = @{}
    foreach ($key in @(Get-ChildItem -LiteralPath $listPath -ErrorAction SilentlyContinue)) {
        if ($key.PSChildName -notmatch '^c(?<Index>[0-9]+)$') { continue }
        $usedIndexes[[int]$Matches.Index] = $true
        $existingUrl = [string]$key.GetValue('tServer', '')
        $existingName = [string]$key.GetValue('tName', '')
        $comparableUrl = $existingUrl
        try { $comparableUrl = Get-CanonicalTimestampUrl -Url ([uri]$existingUrl) }
        catch { }
        $sameUrl = $comparableUrl.Equals($Url, [StringComparison]::OrdinalIgnoreCase)
        if ($existingName.Equals($ServerName, [StringComparison]::OrdinalIgnoreCase) -and
            -not $sameUrl) {
            throw "Acrobat timestamp server name '$ServerName' already refers to '$existingUrl'."
        }
        if ($sameUrl) { $urlMatches += $key.PSPath }
    }
    if ($urlMatches.Count -gt 1) { throw "Acrobat contains multiple timestamp server entries for '$Url'." }
    if ($urlMatches.Count -eq 1) { return $urlMatches[0] }

    for ($index = 0; $index -lt 1000; $index++) {
        if (-not $usedIndexes.ContainsKey($index)) { return Join-Path $listPath "c$index" }
    }
    throw 'Acrobat has no available timestamp server list index below c1000.'
}

$canonicalUrl = Get-CanonicalTimestampUrl -Url $TimestampUrl
if ([string]::IsNullOrWhiteSpace($ServerName) -or $ServerName.IndexOfAny([char[]]"`r`n") -ge 0) {
    throw 'ServerName must contain visible text on one line.'
}

$operation = "Configure Adobe Acrobat Continuous timestamping for '$canonicalUrl'"
if (-not $PSCmdlet.ShouldProcess($script:acrobatRegistryRoot, $operation)) { return }
if ($RegistryRoot -eq 'Registry::HKEY_CURRENT_USER\Software\Adobe\Adobe Acrobat\DC' -and
    (Get-Process -Name 'Acrobat', 'AcroRd32' -ErrorAction SilentlyContinue)) {
    throw 'Close Adobe Acrobat and Reader before changing their current-user timestamp settings.'
}

try {
    $serverPath = Get-AcrobatTimestampServerKey -Url $canonicalUrl
    Set-TrackedRegistryValue -Path $serverPath -Name 'tName' -Value $ServerName `
        -Kind ([Microsoft.Win32.RegistryValueKind]::String)
    Set-TrackedRegistryValue -Path $serverPath -Name 'tServer' -Value $canonicalUrl `
        -Kind ([Microsoft.Win32.RegistryValueKind]::String)
    Set-TrackedRegistryValue -Path $serverPath -Name 'bAuthRequired' -Value 0 `
        -Kind ([Microsoft.Win32.RegistryValueKind]::DWord)

    $providerPath = Join-Path $script:acrobatRegistryRoot 'Security\cASPKI\cAdobe_TSPProvider'
    $binaryUrl = [Text.Encoding]::ASCII.GetBytes($canonicalUrl + [char]0)
    Set-TrackedRegistryValue -Path $providerPath -Name 'sURL' -Value $binaryUrl `
        -Kind ([Microsoft.Win32.RegistryValueKind]::Binary)
    Set-TrackedRegistryValue -Path $providerPath -Name 'bAuthReqd' -Value 0 `
        -Kind ([Microsoft.Win32.RegistryValueKind]::DWord)
    Set-TrackedRegistryValue -Path $providerPath -Name 'bAuthRequired' -Value 0 `
        -Kind ([Microsoft.Win32.RegistryValueKind]::DWord)
    Remove-TrackedRegistryValue -Path $providerPath -Name 'sHashAlgo'
    Set-TrackedRegistryValue -Path $providerPath -Name 'iHashAlgo' -Value 2 `
        -Kind ([Microsoft.Win32.RegistryValueKind]::DWord)

    $signPath = Join-Path $script:acrobatRegistryRoot 'Security\cASPKI\cASPKI\cSign'
    $requireTimestamp = if ($AllowSigningWithoutTimestamp) { 0 } else { 1 }
    Set-TrackedRegistryValue -Path $signPath -Name 'bReqSigPropRetrieval' -Value $requireTimestamp `
        -Kind ([Microsoft.Win32.RegistryValueKind]::DWord)

}
catch {
    $configurationError = $_
    try { Restore-TrackedRegistryValues }
    catch {
        throw "Acrobat timestamp setup failed: $($configurationError.Exception.Message) $($_.Exception.Message)"
    }
    throw $configurationError
}

[PSCustomObject]@{
    Product = 'Adobe Acrobat Continuous'
    TimestampUrl = $canonicalUrl
    ServerRegistryPath = $serverPath
    TimestampRequired = -not [bool]$AllowSigningWithoutTimestamp
}
