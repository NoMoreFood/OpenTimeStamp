#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$payloadPath = Join-Path $PSScriptRoot 'payload'
$installer = Join-Path $PSScriptRoot 'deploy\Install-IisApplication.ps1'
if (-not (Test-Path -LiteralPath $payloadPath -PathType Container) -or
    -not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw 'The MSI cache is missing its payload or IIS deployment script.'
}

$configurationKey = 'HKLM:\Software\OpenTimeStamp\Installer'
if (-not (Test-Path -LiteralPath $configurationKey)) {
    throw 'The MSI did not persist its IIS configuration.'
}
$configuration = Get-ItemProperty -LiteralPath $configurationKey
$siteName = ([string]$configuration.SiteName).Trim()
$applicationName = ([string]$configuration.ApplicationName).Trim()
if ([string]::IsNullOrWhiteSpace($siteName) -or $siteName.Length -gt 128 -or
    $siteName.IndexOfAny([char[]]"`0`r`n") -ge 0) {
    throw 'Enter the exact name of an existing IIS website.'
}
if ($applicationName -notmatch '^[A-Za-z0-9._-]+$' -or $applicationName.Length -gt 64) {
    throw 'Application name must be 1–64 characters using only letters, numbers, periods, underscores, or hyphens.'
}

$iisRegistryKey = 'HKLM:\SOFTWARE\Microsoft\InetStp'
$administrationAssembly = Join-Path $env:WINDIR 'System32\inetsrv\Microsoft.Web.Administration.dll'
if (-not (Test-Path -LiteralPath $iisRegistryKey) -or
    -not (Test-Path -LiteralPath $administrationAssembly -PathType Leaf)) {
    throw 'Microsoft IIS is not installed. Install and configure IIS before installing OpenTimeStamp.'
}
Add-Type -Path $administrationAssembly
$manager = New-Object Microsoft.Web.Administration.ServerManager
try {
    if ($null -eq $manager.Sites[$siteName]) {
        throw "The IIS website '$siteName' does not exist. Create or select the website before installing OpenTimeStamp."
    }
}
finally {
    $manager.Dispose()
}

$applicationPath = '/' + $applicationName
Write-Host "Installing OpenTimeStamp as '$siteName$applicationPath'."
& $installer -SourcePath $payloadPath `
    -SiteName $siteName `
    -ApplicationPath $applicationPath `
    -AppPoolName 'OpenTimeStamp' `
    -AuthenticationMode Anonymous `
    -InstallIisFeatures:$false `
    -AllowUnsignedManifest `
    -Confirm:$false
