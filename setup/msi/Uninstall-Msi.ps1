#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$configurationKey = 'HKLM:\Software\OpenTimeStamp\Installer'
if (-not (Test-Path -LiteralPath $configurationKey)) {
    throw 'The MSI IIS configuration is unavailable; refusing to guess which IIS application to remove.'
}
$configuration = Get-ItemProperty -LiteralPath $configurationKey
$siteName = ([string]$configuration.SiteName).Trim()
$applicationName = ([string]$configuration.ApplicationName).Trim()
if ([string]::IsNullOrWhiteSpace($siteName) -or $siteName.Length -gt 128 -or
    $siteName.IndexOfAny([char[]]"`0`r`n") -ge 0 -or
    $applicationName -notmatch '^[A-Za-z0-9._-]+$' -or $applicationName.Length -gt 64) {
    throw 'The saved MSI IIS configuration is invalid; refusing to guess which IIS application to remove.'
}
$applicationPath = '/' + $applicationName
$appPoolName = 'OpenTimeStamp'
$providerName = 'OpenTimeStamp'
$commonScript = Join-Path $PSScriptRoot 'deploy\Deployment.Common.ps1'
if (-not (Test-Path -LiteralPath $commonScript -PathType Leaf)) {
    throw 'The MSI cache is missing its deployment support script.'
}
. $commonScript

$administrationAssembly = Join-Path $env:WINDIR 'System32\inetsrv\Microsoft.Web.Administration.dll'
if (-not (Test-Path -LiteralPath $administrationAssembly -PathType Leaf)) {
    throw 'Microsoft.Web.Administration is unavailable; IIS cannot be updated safely.'
}
Add-Type -Path $administrationAssembly

$manager = New-Object Microsoft.Web.Administration.ServerManager
try {
    $site = $manager.Sites[$siteName]
    $application = if ($null -eq $site) { $null } else { $site.Applications[$applicationPath] }
    if ($null -eq $application) {
        Write-Host "IIS application '$siteName$applicationPath' is already absent."
        return
    }

    $actualPoolName = [string]$application.ApplicationPoolName
    if (-not $actualPoolName.Equals($appPoolName, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "IIS application '$siteName$applicationPath' no longer uses the expected dedicated pool."
    }
    $virtualDirectory = $application.VirtualDirectories['/']
    if ($null -eq $virtualDirectory) { throw 'The IIS application has no root virtual directory.' }
    $activeRelease = Get-OpenTimeStampCanonicalDirectoryPath -Path ([string]$virtualDirectory.PhysicalPath)
    $releasesRoot = Split-Path -Parent $activeRelease
    if (-not (Split-Path -Leaf $releasesRoot).Equals(
            'Releases', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The active IIS path '$activeRelease' is not an immutable OpenTimeStamp release."
    }
    $deploymentRoot = Get-OpenTimeStampCanonicalDirectoryPath -Path (Split-Path -Parent $releasesRoot)
    if (-not (Test-Path -LiteralPath $deploymentRoot -PathType Container) -or
        -not (Test-OpenTimeStampDeploymentRootMarker -Path $deploymentRoot)) {
        throw "The deployment root inferred from '$activeRelease' is not owned by OpenTimeStamp."
    }
    $releasesRoot = Get-OpenTimeStampCanonicalDirectoryPath -Path (Join-Path $deploymentRoot 'Releases')
    if (-not (Split-Path -Parent $activeRelease).Equals(
            $releasesRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The active IIS path '$activeRelease' is not an immutable release owned by this deployment."
    }
    Assert-OpenTimeStampPublishedPayload -PayloadPath $activeRelease | Out-Null

    $poolAssignments = @(foreach ($candidateSite in @($manager.Sites)) {
        foreach ($candidateApplication in @($candidateSite.Applications)) {
            if (([string]$candidateApplication.ApplicationPoolName).Equals(
                    $appPoolName, [System.StringComparison]::OrdinalIgnoreCase)) {
                "$($candidateSite.Name)$($candidateApplication.Path)"
            }
        }
    })
    $unexpectedAssignments = @($poolAssignments | Where-Object {
            -not $_.Equals("$siteName$applicationPath", [System.StringComparison]::OrdinalIgnoreCase)
        })
    if ($unexpectedAssignments.Count -ne 0) {
        throw "Application pool '$appPoolName' is now shared by: $($unexpectedAssignments -join ', ')."
    }

    $pool = $manager.ApplicationPools[$appPoolName]
    if ($null -ne $pool -and [string]$pool.State -notin @('Stopped', 'Stopping')) {
        [void]$pool.Stop()
    }
    [void]$site.Applications.Remove($application)
    if ($null -ne $pool) { [void]$manager.ApplicationPools.Remove($pool) }

    $remainingProviderReferences = @(foreach ($candidateSite in @($manager.Sites)) {
        foreach ($candidateApplication in @($candidateSite.Applications)) {
            if (([string]$candidateApplication.GetAttributeValue('serviceAutoStartProvider')).Equals(
                    $providerName, [System.StringComparison]::OrdinalIgnoreCase)) {
                "$($candidateSite.Name)$($candidateApplication.Path)"
            }
        }
    })
    if ($remainingProviderReferences.Count -eq 0) {
        $configuration = $manager.GetApplicationHostConfiguration()
        $providers = $configuration.GetSection(
            'system.applicationHost/serviceAutoStartProviders').GetCollection()
        $matchingProviders = @($providers | Where-Object {
                ([string]$_.GetAttributeValue('name')).Equals(
                    $providerName, [System.StringComparison]::OrdinalIgnoreCase)
            })
        if ($matchingProviders.Count -gt 1) {
            throw "IIS contains duplicate service auto-start provider '$providerName' entries."
        }
        if ($matchingProviders.Count -eq 1) { [void]$providers.Remove($matchingProviders[0]) }
    }

    $manager.CommitChanges()
}
finally {
    $manager.Dispose()
}

Write-Host "Removed IIS application '$siteName$applicationPath' and its dedicated application pool."
Write-Host "Preserved deployment releases and application data under '$deploymentRoot'."
