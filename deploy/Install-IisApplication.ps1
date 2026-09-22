#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Installs a manifested OpenTimeStamp release as a hardened IIS application.

.DESCRIPTION
Validates and stages an immutable release, keeps mutable state in a separately
marked data directory, switches the IIS application only while its real current
pool is quiesced, and rolls the IIS pointer and pool states back on failure.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$SourcePath,

    [string]$PhysicalPath = "$env:SystemDrive\inetpub\OpenTimeStamp",

    [string]$DataPath,

    [string[]]$AdminHostNames,

    [ValidateNotNullOrEmpty()]
    [string]$SiteName = 'Default Web Site',

    [ValidatePattern('^/[A-Za-z0-9._-]+$')]
    [string]$ApplicationPath = '/OpenTimeStamp',

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$AppPoolName = 'OpenTimeStamp',

    [ValidateSet('Anonymous', 'Windows')]
    [string]$AuthenticationMode = 'Anonymous',

    [bool]$InstallIisFeatures = $true,

    [switch]$RequireHttps,

    [ValidatePattern('^[0-9A-Fa-f ]*$')]
    [string]$CertificateThumbprint,

    [string]$ManifestSignaturePath,

    [string]$TrustedManifestSignerThumbprint,

    [switch]$AllowUnsignedManifest,

    [switch]$AdoptExistingDataPath,

    [switch]$AllowBroadExistingKeyAcl,

    [ValidateRange(1, 100)]
    [int]$RetainReleases = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonScript = Join-Path $PSScriptRoot 'Deployment.Common.ps1'
if (-not (Test-Path -LiteralPath $commonScript -PathType Leaf)) {
    throw "Deployment support functions were not found at '$commonScript'."
}

. $commonScript

function Get-IisAuthenticationPair {
    param(
        [string]$ConfigurationPath,
        [string]$Location
    )

    $anonymous = Get-WebConfigurationProperty -PSPath $ConfigurationPath -Location $Location `
        -Filter 'system.webServer/security/authentication/anonymousAuthentication' -Name enabled
    $windows = Get-WebConfigurationProperty -PSPath $ConfigurationPath -Location $Location `
        -Filter 'system.webServer/security/authentication/windowsAuthentication' -Name enabled
    return [PSCustomObject]@{ Anonymous = [bool]$anonymous.Value; Windows = [bool]$windows.Value }
}

function Get-IisAuthenticationMode {
    param(
        [string]$ConfigurationPath,
        [string]$Location
    )

    $pair = Get-IisAuthenticationPair -ConfigurationPath $ConfigurationPath -Location $Location
    if ($pair.Anonymous -and -not $pair.Windows) { return 'Anonymous' }
    if (-not $pair.Anonymous -and $pair.Windows) { return 'Windows' }
    return $null
}

function Get-IisLocalAttributeSnapshot {
    param(
        [string]$Location,
        [string]$Section,
        [string]$Attribute,
        [string]$ChildElement
    )

    $manager = New-Object Microsoft.Web.Administration.ServerManager
    try {
        $configuration = $manager.GetApplicationHostConfiguration()
        $target = $configuration.GetSection($Section, $Location)
        if (-not [string]::IsNullOrWhiteSpace($ChildElement)) {
            $target = $target.GetChildElement($ChildElement)
        }
        $hasLocalValue = $target.RawAttributes.ContainsKey($Attribute)
        return [PSCustomObject]@{
            Location = $Location
            Section = $Section
            ChildElement = $ChildElement
            Attribute = $Attribute
            Available = $true
            HasLocalValue = $hasLocalValue
            RawValue = if ($hasLocalValue) { $target.RawAttributes[$Attribute] } else { $null }
        }
    }
    finally {
        $manager.Dispose()
    }
}

function Get-IisLocalIpSecuritySnapshot {
    param([string]$Location)

    $configPath = Join-Path $env:WINDIR 'System32\inetsrv\config\applicationHost.config'
    $document = Read-OpenTimeStampXmlDocument -Path $configPath
    $localSection = $null
    foreach ($locationNode in @($document.SelectNodes('/configuration/location'))) {
        if (([string]$locationNode.GetAttribute('path')).Equals(
                $Location, [System.StringComparison]::OrdinalIgnoreCase)) {
            $systemWebServer = $locationNode.SelectSingleNode('./system.webServer')
            if ($null -ne $systemWebServer) {
                $localSection = $systemWebServer.SelectSingleNode('./security/ipSecurity')
            }
            break
        }
    }
    $attributes = @()
    $directives = @()
    if ($null -ne $localSection) {
        $attributes = @($localSection.Attributes | ForEach-Object {
            [PSCustomObject]@{ Name = [string]$_.Name; Value = [string]$_.Value }
        })
        $directives = @($localSection.ChildNodes |
            Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element } |
            ForEach-Object { [string]$_.OuterXml })
    }
    return [PSCustomObject]@{
        Location = $Location
        SectionWasLocal = $null -ne $localSection
        Attributes = $attributes
        Directives = $directives
    }
}

function Get-IisExactLocalState {
    param(
        [string]$AppLocation,
        [string]$AdminLocation,
        $AuthenticationDefinitions
    )

    $attributes = @(foreach ($location in @($AppLocation, $AdminLocation)) {
        foreach ($definition in @($AuthenticationDefinitions)) {
            try {
                Get-IisLocalAttributeSnapshot -Location $location `
                    -Section $definition.Section -Attribute 'enabled'
            }
            catch {
                $feature = if ([string]::IsNullOrWhiteSpace([string]$definition.Feature)) { $null } else {
                    Get-WindowsFeature -Name $definition.Feature -ErrorAction SilentlyContinue
                }
                if ($null -eq $feature -or $feature.Installed) { throw }
                [PSCustomObject]@{
                    Location = $location; Section = $definition.Section; ChildElement = $null
                    Attribute = 'enabled'; Available = $false; HasLocalValue = $false; RawValue = $null
                }
            }
        }
    }
    Get-IisLocalAttributeSnapshot -Location $AppLocation `
        -Section 'system.webServer/security/requestFiltering' -ChildElement 'requestLimits' `
        -Attribute 'maxAllowedContentLength'
    Get-IisLocalAttributeSnapshot -Location $AppLocation `
        -Section 'system.webServer/security/access' -Attribute 'sslFlags'
    Get-IisLocalAttributeSnapshot -Location $AppLocation `
        -Section 'system.web/httpCookies' -Attribute 'requireSSL'
    )
    return [PSCustomObject]@{
        Attributes = $attributes
        IpSecurity = Get-IisLocalIpSecuritySnapshot -Location $AdminLocation
    }
}

function Restore-IisExactLocalState {
    param(
        $Snapshot,
        $ExpectedCurrentSnapshot
    )

    if ($null -ne $ExpectedCurrentSnapshot) {
        $current = Get-IisExactLocalState -AppLocation $appLocation -AdminLocation $adminLocation `
            -AuthenticationDefinitions $allAuthenticationSections
        if (($current | ConvertTo-Json -Depth 8 -Compress) -ne
            ($ExpectedCurrentSnapshot | ConvertTo-Json -Depth 8 -Compress)) {
            throw 'IIS local configuration changed after the installer applied it; refusing to overwrite the external change.'
        }
    }
    $manager = New-Object Microsoft.Web.Administration.ServerManager
    try {
        $configuration = $manager.GetApplicationHostConfiguration()
        foreach ($attribute in @($Snapshot.Attributes | Where-Object { $_.Available })) {
            $target = $configuration.GetSection($attribute.Section, $attribute.Location)
            if (-not [string]::IsNullOrWhiteSpace([string]$attribute.ChildElement)) {
                $target = $target.GetChildElement($attribute.ChildElement)
            }
            if ($attribute.HasLocalValue) { $target.SetAttributeValue($attribute.Attribute, $attribute.RawValue) }
            else { $target.GetAttribute($attribute.Attribute).Delete() }
        }
        $ipSnapshot = $Snapshot.IpSecurity
        $ipSection = $configuration.GetSection('system.webServer/security/ipSecurity', $ipSnapshot.Location)
        $ipSection.RevertToParent()
        if ($ipSnapshot.SectionWasLocal) {
            foreach ($attribute in @($ipSnapshot.Attributes)) {
                $ipSection.SetAttributeValue($attribute.Name, $attribute.Value)
            }
            $collection = $ipSection.GetCollection()
            foreach ($directiveXml in @($ipSnapshot.Directives)) {
                $fragment = New-Object System.Xml.XmlDocument
                $fragment.XmlResolver = $null
                $fragment.LoadXml([string]$directiveXml)
                $directive = $fragment.DocumentElement
                if ($directive.LocalName -eq 'clear') { $collection.Clear(); continue }
                $values = @{}
                foreach ($attribute in @($directive.Attributes)) { $values[$attribute.Name] = $attribute.Value }
                if ($directive.LocalName -eq 'remove') {
                    $matching = @($collection | Where-Object {
                        $candidate = $_
                        @($values.Keys | Where-Object {
                            [string]$candidate.GetAttributeValue($_) -ne [string]$values[$_]
                        }).Count -eq 0
                    }) | Select-Object -First 1
                    if ($null -eq $matching) { throw 'An inherited ipSecurity element required by rollback disappeared.' }
                    [void]$collection.Remove($matching)
                    continue
                }
                if ($directive.LocalName -ne 'add') { throw "Unsupported local ipSecurity directive '$($directive.LocalName)'." }
                $element = $collection.CreateElement('add')
                foreach ($name in @($values.Keys)) { $element.SetAttributeValue($name, $values[$name]) }
                [void]$collection.Add($element)
            }
        }
        $manager.CommitChanges()
    }
    finally { $manager.Dispose() }
    $restored = Get-IisExactLocalState -AppLocation $appLocation -AdminLocation $adminLocation `
        -AuthenticationDefinitions $allAuthenticationSections
    if (($restored | ConvertTo-Json -Depth 8 -Compress) -ne
        ($Snapshot | ConvertTo-Json -Depth 8 -Compress)) {
        throw 'IIS local configuration rollback did not restore the exact prior local state.'
    }
}

function Set-IisDesiredLocalStateAtomic {
    param(
        [string]$AppLocation,
        [string]$AdminLocation,
        $ExpectedState,
        [string]$AuthenticationMode,
        $UnsupportedAuthenticationSections,
        [bool]$SetTlsSettings,
        [bool]$RequireTls,
        [string[]]$AdminIpv4Addresses
    )

    $availableUnsupported = @($UnsupportedAuthenticationSections | Where-Object {
        $feature = Get-WindowsFeature -Name $_.Feature -ErrorAction SilentlyContinue
        $null -eq $feature -or $feature.Installed
    })
    $manager = New-Object Microsoft.Web.Administration.ServerManager
    try {
        $configuration = $manager.GetApplicationHostConfiguration()
        foreach ($location in @($AppLocation, $AdminLocation)) {
            foreach ($definition in $availableUnsupported) {
                $configuration.GetSection($definition.Section, $location).SetAttributeValue('enabled', $false)
            }
        }
        $configuration.GetSection(
            'system.webServer/security/authentication/anonymousAuthentication', $AppLocation).SetAttributeValue(
                'enabled', $AuthenticationMode -eq 'Anonymous')
        $configuration.GetSection(
            'system.webServer/security/authentication/windowsAuthentication', $AppLocation).SetAttributeValue(
                'enabled', $AuthenticationMode -eq 'Windows')
        $configuration.GetSection(
            'system.webServer/security/authentication/anonymousAuthentication', $AdminLocation).SetAttributeValue(
                'enabled', $false)
        $configuration.GetSection(
            'system.webServer/security/authentication/windowsAuthentication', $AdminLocation).SetAttributeValue(
                'enabled', $true)
        $configuration.GetSection('system.webServer/security/requestFiltering', $AppLocation).GetChildElement(
            'requestLimits').SetAttributeValue('maxAllowedContentLength', 1048576)
        if ($SetTlsSettings) {
            $configuration.GetSection('system.webServer/security/access', $AppLocation).SetAttributeValue(
                'sslFlags', $(if ($RequireTls) { 'Ssl' } else { 'None' }))
            $configuration.GetSection('system.web/httpCookies', $AppLocation).SetAttributeValue(
                'requireSSL', $RequireTls)
        }
        $ipSection = $configuration.GetSection('system.webServer/security/ipSecurity', $AdminLocation)
        $ipSection.SetAttributeValue('allowUnlisted', $false)
        $ipSection.SetAttributeValue('denyAction', 'NotFound')
        $ipSection.SetAttributeValue('enableProxyMode', $false)
        $ipSection.SetAttributeValue('enableReverseDns', $false)
        $ipCollection = $ipSection.GetCollection()
        $ipCollection.Clear()
        foreach ($address in $AdminIpv4Addresses) {
            $element = $ipCollection.CreateElement('add')
            $element.SetAttributeValue('ipAddress', $address)
            $element.SetAttributeValue('allowed', $true)
            [void]$ipCollection.Add($element)
        }
        $currentBeforeCommit = Get-IisExactLocalState -AppLocation $AppLocation `
            -AdminLocation $AdminLocation -AuthenticationDefinitions $allAuthenticationSections
        if (($currentBeforeCommit | ConvertTo-Json -Depth 8 -Compress) -ne
            ($ExpectedState | ConvertTo-Json -Depth 8 -Compress)) {
            throw 'IIS local configuration changed before the atomic commit; refusing to overwrite the external change.'
        }
        # Every owned IIS local setting is committed in one apphost transaction.
        $manager.CommitChanges()
    }
    finally { $manager.Dispose() }
}

function Test-IisDesiredLocalState {
    param(
        [string]$AppLocation,
        [string]$AdminLocation,
        [string]$AuthenticationMode,
        $UnsupportedAuthenticationSections,
        $ExpectedState,
        [bool]$SetTlsSettings,
        [bool]$RequireTls,
        [string[]]$AdminIpv4Addresses
    )
    $manager = New-Object Microsoft.Web.Administration.ServerManager
    try {
        $configuration = $manager.GetApplicationHostConfiguration()
        foreach ($location in @($AppLocation, $AdminLocation)) {
            foreach ($definition in @($UnsupportedAuthenticationSections)) {
                $feature = Get-WindowsFeature -Name $definition.Feature -ErrorAction SilentlyContinue
                if ($null -ne $feature -and -not $feature.Installed) { continue }
                if ([bool]$configuration.GetSection($definition.Section, $location).GetAttributeValue('enabled')) {
                    return $false
                }
            }
        }
        if ([bool]$configuration.GetSection(
                'system.webServer/security/authentication/anonymousAuthentication', $AppLocation).GetAttributeValue('enabled') -ne
            ($AuthenticationMode -eq 'Anonymous')) { return $false }
        if ([bool]$configuration.GetSection(
                'system.webServer/security/authentication/windowsAuthentication', $AppLocation).GetAttributeValue('enabled') -ne
            ($AuthenticationMode -eq 'Windows')) { return $false }
        if ([bool]$configuration.GetSection(
                'system.webServer/security/authentication/anonymousAuthentication', $AdminLocation).GetAttributeValue('enabled')) {
            return $false
        }
        if (-not [bool]$configuration.GetSection(
                'system.webServer/security/authentication/windowsAuthentication', $AdminLocation).GetAttributeValue('enabled')) {
            return $false
        }
        if ([uint64]$configuration.GetSection('system.webServer/security/requestFiltering', $AppLocation).GetChildElement(
                'requestLimits').GetAttributeValue('maxAllowedContentLength') -ne 1048576) { return $false }
        if ($SetTlsSettings) {
            $expectedSslFlags = if ($RequireTls) { 'Ssl' } else { 'None' }
            if ([string]$configuration.GetSection('system.webServer/security/access', $AppLocation).GetAttributeValue(
                    'sslFlags') -ne $expectedSslFlags -or
                [bool]$configuration.GetSection('system.web/httpCookies', $AppLocation).GetAttributeValue(
                    'requireSSL') -ne $RequireTls) { return $false }
        }
        else {
            $currentState = Get-IisExactLocalState -AppLocation $AppLocation -AdminLocation $AdminLocation `
                -AuthenticationDefinitions $allAuthenticationSections
            $trackedTlsSections = @('system.webServer/security/access', 'system.web/httpCookies')
            $currentTls = @($currentState.Attributes | Where-Object { $trackedTlsSections -contains $_.Section })
            $expectedTls = @($ExpectedState.Attributes | Where-Object { $trackedTlsSections -contains $_.Section })
            if (($currentTls | ConvertTo-Json -Depth 5 -Compress) -ne
                ($expectedTls | ConvertTo-Json -Depth 5 -Compress)) { return $false }
        }
        $ipSection = $configuration.GetSection('system.webServer/security/ipSecurity', $AdminLocation)
        if ([bool]$ipSection.GetAttributeValue('allowUnlisted') -or
            [string]$ipSection.GetAttributeValue('denyAction') -ne 'NotFound' -or
            [bool]$ipSection.GetAttributeValue('enableProxyMode') -or
            [bool]$ipSection.GetAttributeValue('enableReverseDns')) { return $false }
        $expectedAddresses = @($AdminIpv4Addresses | Sort-Object -Unique)
        $ipRules = @($ipSection.GetCollection())
        if ($ipRules.Count -ne $expectedAddresses.Count) { return $false }
        $actualAddresses = [System.Collections.Generic.List[string]]::new()
        foreach ($ipRule in $ipRules) {
            if (-not [bool]$ipRule.GetAttributeValue('allowed') -or
                $ipRule.RawAttributes.ContainsKey('subnetMask') -or
                $ipRule.RawAttributes.ContainsKey('domainName')) { return $false }
            $address = [string]$ipRule.GetAttributeValue('ipAddress')
            if ($expectedAddresses -notcontains $address -or $actualAddresses -contains $address) { return $false }
            $actualAddresses.Add($address)
        }
        return (@($actualAddresses | Sort-Object) -join '|') -eq ($expectedAddresses -join '|')
    }
    catch { return $false }
    finally { $manager.Dispose() }
}

function Set-IisApplicationPoolSettingsAtomic {
    param([string]$Name, $ExpectedSettings, $Settings)

    $manager = New-Object Microsoft.Web.Administration.ServerManager
    try {
        $pool = $manager.ApplicationPools[$Name]
        if ($null -eq $pool) { throw "Application pool '$Name' disappeared." }
        $currentSettings = [PSCustomObject]@{
            ManagedRuntimeVersion = [string]$pool.ManagedRuntimeVersion
            ManagedPipelineMode = [string]$pool.ManagedPipelineMode
            Enable32Bit = [bool]$pool.Enable32BitAppOnWin64
            IdentityType = [string]$pool.ProcessModel.IdentityType
            LoadUserProfile = [bool]$pool.ProcessModel.LoadUserProfile
            MaxProcesses = [int]$pool.ProcessModel.MaxProcesses
            DisallowOverlappingRotation = [bool]$pool.Recycling.DisallowOverlappingRotation
        }
        if (-not (Test-IisApplicationPoolSettingsEqual -First $currentSettings -Second $ExpectedSettings)) {
            throw "Application pool '$Name' settings changed before the atomic commit; refusing to overwrite the external change."
        }
        $pool.SetAttributeValue('managedRuntimeVersion', [string]$Settings.ManagedRuntimeVersion)
        $pool.SetAttributeValue('managedPipelineMode', [string]$Settings.ManagedPipelineMode)
        $pool.SetAttributeValue('enable32BitAppOnWin64', [bool]$Settings.Enable32Bit)
        $pool.ProcessModel.SetAttributeValue('identityType', [string]$Settings.IdentityType)
        $pool.ProcessModel.SetAttributeValue('loadUserProfile', [bool]$Settings.LoadUserProfile)
        $pool.ProcessModel.SetAttributeValue('maxProcesses', [int]$Settings.MaxProcesses)
        $pool.Recycling.SetAttributeValue(
            'disallowOverlappingRotation', [bool]$Settings.DisallowOverlappingRotation)
        $manager.CommitChanges()
    }
    finally { $manager.Dispose() }
}

function ConvertTo-IisAttributeEffectiveValue {
    param($Value)

    if ($Value -is [TimeSpan]) { return [long]$Value.Ticks }
    if ($Value -is [bool]) { return [bool]$Value }
    return [string]$Value
}

function Get-IisRawAttributeSnapshot {
    param(
        $Element,
        [string]$Name
    )

    $hasLocalValue = $Element.RawAttributes.ContainsKey($Name)
    return [PSCustomObject]@{
        Name = $Name
        HasLocalValue = $hasLocalValue
        RawValue = if ($hasLocalValue) { [string]$Element.RawAttributes[$Name] } else { $null }
        EffectiveValue = ConvertTo-IisAttributeEffectiveValue -Value ($Element.GetAttributeValue($Name))
    }
}

function Restore-IisRawAttributeSnapshot {
    param(
        $Element,
        $Snapshot
    )

    if ($Snapshot.HasLocalValue) {
        $Element.SetAttributeValue([string]$Snapshot.Name, $Snapshot.RawValue)
    }
    else {
        $Element.GetAttribute([string]$Snapshot.Name).Delete()
    }
}

function Get-IisServiceAutoStartProviderReferencesFromManager {
    param(
        $Manager,
        [string]$ProviderName
    )

    $references = @(foreach ($site in @($Manager.Sites)) {
        foreach ($application in @($site.Applications)) {
            $configuredProvider = [string]$application.GetAttributeValue('serviceAutoStartProvider')
            if ($configuredProvider.Equals($ProviderName, [System.StringComparison]::OrdinalIgnoreCase)) {
                "$($site.Name)$($application.Path)"
            }
        }
    })
    return @($references | Sort-Object -Unique)
}

function Get-IisAlwaysWarmStateFromManager {
    param(
        $Manager,
        [string]$SiteName,
        [string]$ApplicationPath,
        [string]$AppPoolName,
        [string]$ProviderName
    )

    $site = $Manager.Sites[$SiteName]
    if ($null -eq $site) { throw "IIS site '$SiteName' disappeared." }
    $pool = $Manager.ApplicationPools[$AppPoolName]
    if ($null -eq $pool) { throw "Application pool '$AppPoolName' disappeared." }
    $application = $site.Applications[$ApplicationPath]
    $applicationState = if ($null -eq $application) {
        [PSCustomObject]@{ Present = $false; ServiceAutoStartEnabled = $null; ServiceAutoStartProvider = $null }
    }
    else {
        [PSCustomObject]@{
            Present = $true
            ServiceAutoStartEnabled = Get-IisRawAttributeSnapshot `
                -Element $application -Name 'serviceAutoStartEnabled'
            ServiceAutoStartProvider = Get-IisRawAttributeSnapshot `
                -Element $application -Name 'serviceAutoStartProvider'
        }
    }

    $configuration = $Manager.GetApplicationHostConfiguration()
    $providerCollection = $configuration.GetSection(
        'system.applicationHost/serviceAutoStartProviders').GetCollection()
    $providers = @($providerCollection | Where-Object {
            ([string]$_.GetAttributeValue('name')).Equals(
                $ProviderName, [System.StringComparison]::OrdinalIgnoreCase)
        })
    if ($providers.Count -gt 1) { throw "IIS contains duplicate service auto-start provider '$ProviderName'." }
    $providerState = if ($providers.Count -eq 0) {
        [PSCustomObject]@{ Present = $false; Type = $null }
    }
    else {
        [PSCustomObject]@{ Present = $true; Type = [string]$providers[0].GetAttributeValue('type') }
    }

    return [PSCustomObject]@{
        Site = [PSCustomObject]@{
            ServerAutoStart = Get-IisRawAttributeSnapshot -Element $site -Name 'serverAutoStart'
        }
        Pool = [PSCustomObject]@{
            AutoStart = Get-IisRawAttributeSnapshot -Element $pool -Name 'autoStart'
            StartMode = Get-IisRawAttributeSnapshot -Element $pool -Name 'startMode'
            IdleTimeout = Get-IisRawAttributeSnapshot -Element $pool.ProcessModel -Name 'idleTimeout'
            PeriodicRestartTime = Get-IisRawAttributeSnapshot `
                -Element $pool.Recycling.PeriodicRestart -Name 'time'
        }
        Application = $applicationState
        Provider = $providerState
        ProviderReferences = @(Get-IisServiceAutoStartProviderReferencesFromManager `
            -Manager $Manager -ProviderName $ProviderName)
    }
}

function Get-IisAlwaysWarmState {
    param(
        [string]$SiteName,
        [string]$ApplicationPath,
        [string]$AppPoolName,
        [string]$ProviderName
    )

    $manager = New-Object Microsoft.Web.Administration.ServerManager
    try {
        return Get-IisAlwaysWarmStateFromManager -Manager $manager -SiteName $SiteName `
            -ApplicationPath $ApplicationPath -AppPoolName $AppPoolName -ProviderName $ProviderName
    }
    finally { $manager.Dispose() }
}

function Test-IisAlwaysWarmStateEqual {
    param($First, $Second)

    if ($null -eq $First -or $null -eq $Second) { return $null -eq $First -and $null -eq $Second }
    return ($First | ConvertTo-Json -Depth 8 -Compress) -eq ($Second | ConvertTo-Json -Depth 8 -Compress)
}

function Test-IisAlwaysWarmPreMutationState {
    param(
        $Before,
        $Current,
        [bool]$ApplicationExisted,
        [string]$ApplicationIdentity
    )

    if ($ApplicationExisted) {
        return (Test-IisAlwaysWarmStateEqual -First $Before -Second $Current)
    }
    $projected = [PSCustomObject]@{
        Site = $Current.Site
        Pool = $Current.Pool
        Application = $Before.Application
        Provider = $Current.Provider
        ProviderReferences = @($Current.ProviderReferences | Where-Object { $_ -ne $ApplicationIdentity })
    }
    return (Test-IisAlwaysWarmStateEqual -First $Before -Second $projected)
}

function Assert-IisServiceAutoStartProviderCompatible {
    param(
        $State,
        [string]$ProviderName,
        [string]$ProviderType
    )

    if ($State.Provider.Present -and
        -not ([string]$State.Provider.Type).Equals($ProviderType, [System.StringComparison]::Ordinal)) {
        throw "IIS service auto-start provider '$ProviderName' is already registered with another type."
    }
    if (-not $State.Provider.Present -and @($State.ProviderReferences).Count -ne 0) {
        throw "IIS application(s) reference missing service auto-start provider '$ProviderName'."
    }
}

function Test-IisAlwaysWarmStateDesired {
    param(
        $State,
        [string]$ApplicationIdentity,
        [string]$ProviderName,
        [string]$ProviderType
    )

    return $State.Site.ServerAutoStart.EffectiveValue -eq $true -and
        $State.Pool.AutoStart.EffectiveValue -eq $true -and
        [string]$State.Pool.StartMode.EffectiveValue -eq 'AlwaysRunning' -and
        [long]$State.Pool.IdleTimeout.EffectiveValue -eq 0 -and
        [long]$State.Pool.PeriodicRestartTime.EffectiveValue -eq 0 -and
        $State.Application.Present -and
        $State.Application.ServiceAutoStartEnabled.EffectiveValue -eq $true -and
        ([string]$State.Application.ServiceAutoStartProvider.EffectiveValue).Equals(
            $ProviderName, [System.StringComparison]::Ordinal) -and
        $State.Provider.Present -and
        ([string]$State.Provider.Type).Equals($ProviderType, [System.StringComparison]::Ordinal) -and
        @($State.ProviderReferences) -contains $ApplicationIdentity
}

function Set-IisAlwaysWarmStateAtomic {
    param(
        [string]$SiteName,
        [string]$ApplicationPath,
        [string]$AppPoolName,
        [string]$ApplicationIdentity,
        [string]$ProviderName,
        [string]$ProviderType,
        $ExpectedState
    )

    $manager = New-Object Microsoft.Web.Administration.ServerManager
    try {
        $current = Get-IisAlwaysWarmStateFromManager -Manager $manager -SiteName $SiteName `
            -ApplicationPath $ApplicationPath -AppPoolName $AppPoolName -ProviderName $ProviderName
        if (-not (Test-IisAlwaysWarmStateEqual -First $current -Second $ExpectedState)) {
            throw ('IIS always-warm settings changed before the atomic commit; ' +
                'refusing to overwrite the external change.')
        }
        Assert-IisServiceAutoStartProviderCompatible -State $current `
            -ProviderName $ProviderName -ProviderType $ProviderType
        if (-not $current.Application.Present) { throw "IIS application '$ApplicationIdentity' disappeared." }

        $site = $manager.Sites[$SiteName]
        $pool = $manager.ApplicationPools[$AppPoolName]
        if ([string]$pool.State -ne 'Stopped') {
            throw 'The IIS application pool must remain stopped before always-warm activation.'
        }

        $configuration = $manager.GetApplicationHostConfiguration()
        $providerCollection = $configuration.GetSection(
            'system.applicationHost/serviceAutoStartProviders').GetCollection()
        if (-not $current.Provider.Present) {
            $provider = $providerCollection.CreateElement('add')
            $provider.SetAttributeValue('name', $ProviderName)
            $provider.SetAttributeValue('type', $ProviderType)
            [void]$providerCollection.Add($provider)
        }

        $application = $site.Applications[$ApplicationPath]
        $site.SetAttributeValue('serverAutoStart', $true)
        $pool.SetAttributeValue('autoStart', $true)
        $pool.SetAttributeValue('startMode', 'AlwaysRunning')
        $pool.ProcessModel.SetAttributeValue('idleTimeout', [TimeSpan]::Zero)
        $pool.Recycling.PeriodicRestart.SetAttributeValue('time', [TimeSpan]::Zero)
        $application.SetAttributeValue('serviceAutoStartEnabled', $true)
        $application.SetAttributeValue('serviceAutoStartProvider', $ProviderName)
        $manager.CommitChanges()
    }
    finally { $manager.Dispose() }
}

function Restore-IisAlwaysWarmStateAtomic {
    param(
        [string]$SiteName,
        [string]$ApplicationPath,
        [string]$AppPoolName,
        [string]$ProviderName,
        $Snapshot,
        $ExpectedCurrentSnapshot
    )

    $manager = New-Object Microsoft.Web.Administration.ServerManager
    try {
        $current = Get-IisAlwaysWarmStateFromManager -Manager $manager -SiteName $SiteName `
            -ApplicationPath $ApplicationPath -AppPoolName $AppPoolName -ProviderName $ProviderName
        if (-not (Test-IisAlwaysWarmStateEqual -First $current -Second $ExpectedCurrentSnapshot)) {
            throw ('IIS always-warm settings changed after installer mutation; ' +
                'refusing to overwrite the external change.')
        }
        if (-not $Snapshot.Application.Present) {
            throw 'Exact always-warm rollback requires the pre-mutation IIS application.'
        }

        $site = $manager.Sites[$SiteName]
        $pool = $manager.ApplicationPools[$AppPoolName]
        $application = $site.Applications[$ApplicationPath]
        Restore-IisRawAttributeSnapshot -Element $site -Snapshot $Snapshot.Site.ServerAutoStart
        Restore-IisRawAttributeSnapshot -Element $pool -Snapshot $Snapshot.Pool.AutoStart
        Restore-IisRawAttributeSnapshot -Element $pool -Snapshot $Snapshot.Pool.StartMode
        Restore-IisRawAttributeSnapshot -Element $pool.ProcessModel -Snapshot $Snapshot.Pool.IdleTimeout
        Restore-IisRawAttributeSnapshot `
            -Element $pool.Recycling.PeriodicRestart -Snapshot $Snapshot.Pool.PeriodicRestartTime
        Restore-IisRawAttributeSnapshot `
            -Element $application -Snapshot $Snapshot.Application.ServiceAutoStartEnabled
        Restore-IisRawAttributeSnapshot `
            -Element $application -Snapshot $Snapshot.Application.ServiceAutoStartProvider

        if (-not $Snapshot.Provider.Present) {
            $configuration = $manager.GetApplicationHostConfiguration()
            $providerCollection = $configuration.GetSection(
                'system.applicationHost/serviceAutoStartProviders').GetCollection()
            $provider = @($providerCollection | Where-Object {
                    ([string]$_.GetAttributeValue('name')).Equals(
                        $ProviderName, [System.StringComparison]::OrdinalIgnoreCase)
                }) | Select-Object -First 1
            $references = @(Get-IisServiceAutoStartProviderReferencesFromManager `
                -Manager $manager -ProviderName $ProviderName)
            if ($references.Count -ne 0) {
                throw "IIS service auto-start provider '$ProviderName' acquired another application reference."
            }
            if ($null -ne $provider) { [void]$providerCollection.Remove($provider) }
        }
        $manager.CommitChanges()
    }
    finally { $manager.Dispose() }

    $restored = Get-IisAlwaysWarmState -SiteName $SiteName -ApplicationPath $ApplicationPath `
        -AppPoolName $AppPoolName -ProviderName $ProviderName
    if (-not (Test-IisAlwaysWarmStateEqual -First $restored -Second $Snapshot)) {
        throw 'IIS always-warm rollback did not restore the exact prior local state.'
    }
}

function Test-IisConfigurationLocationIsEmpty {
    param([string]$Location)

    $configPath = Join-Path $env:WINDIR 'System32\inetsrv\config\applicationHost.config'
    $document = Read-OpenTimeStampXmlDocument -Path $configPath
    $matches = @($document.SelectNodes('/configuration/location') | Where-Object {
            ([string]$_.GetAttribute('path')).Equals($Location, [System.StringComparison]::OrdinalIgnoreCase)
        })
    if ($matches.Count -eq 0) { return $true }
    if ($matches.Count -ne 1) { return $false }
    $locationNode = $matches[0]
    if (@($locationNode.Attributes | Where-Object { $_.Name -ne 'path' }).Count -ne 0) { return $false }
    return @($locationNode.ChildNodes | Where-Object {
            $_.NodeType -eq [System.Xml.XmlNodeType]::Element
        }).Count -eq 0
}

function Restore-PrivateKeyAclChange {
    param($Change)

    if ($null -eq $Change -or -not [bool]$Change.AclChanged) { return }
    if (-not (Test-Path -LiteralPath $Change.PrivateKeyPath -PathType Leaf)) {
        throw "The private-key file '$($Change.PrivateKeyPath)' disappeared before its ACL could be restored."
    }

    $currentAcl = Get-Acl -LiteralPath $Change.PrivateKeyPath
    $currentSddl = $currentAcl.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::All)
    if (-not $currentSddl.Equals([string]$Change.AppliedSddl, [System.StringComparison]::Ordinal)) {
        throw 'The private-key ACL changed after this installer applied it; refusing to overwrite the external change.'
    }

    $security = New-Object System.Security.AccessControl.FileSecurity
    $security.SetSecurityDescriptorSddlForm(
        [string]$Change.PreviousSddl,
        [System.Security.AccessControl.AccessControlSections]::All)
    Set-Acl -LiteralPath $Change.PrivateKeyPath -AclObject $security
    $restoredAcl = Get-Acl -LiteralPath $Change.PrivateKeyPath
    $restoredSddl = $restoredAcl.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::All)
    if (-not $restoredSddl.Equals([string]$Change.PreviousSddl, [System.StringComparison]::Ordinal)) {
        throw 'The prior private-key ACL could not be restored and verified exactly.'
    }
}

function ConvertTo-NormalizedHostName {
    param([string]$HostName)

    $value = if ($null -eq $HostName) { '' } else { $HostName.Trim().TrimEnd('.') }
    if ($value.StartsWith('[') -and $value.EndsWith(']')) {
        $value = $value.Substring(1, $value.Length - 2)
    }

    $parsedAddress = $null
    if ([System.Net.IPAddress]::TryParse($value, [ref]$parsedAddress)) {
        return $parsedAddress.ToString().ToLowerInvariant()
    }

    if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 253 -or
        $value.IndexOfAny([char[]]@('/', '\', ':', ',', ';', "`r", "`n", "`t")) -ge 0 -or
        [System.Uri]::CheckHostName($value) -ne [System.UriHostNameType]::Dns) {
        throw "'$HostName' is not a valid exact administrative host name."
    }

    return $value.ToLowerInvariant()
}

function Get-ExistingWebSettings {
    param([string]$ApplicationPhysicalPath)

    $webConfigPath = Join-Path $ApplicationPhysicalPath 'web.config'
    if (-not (Test-Path -LiteralPath $webConfigPath -PathType Leaf)) {
        throw "The existing IIS application does not contain web.config at '$webConfigPath'. Pass explicit deployment settings only after repairing the application path."
    }

    $document = Read-OpenTimeStampXmlDocument -Path $webConfigPath
    $result = @{}
    foreach ($key in @(
            'AuthenticationMode',
            'DataPath',
            'AdminHostNames',
            'TimestampBodyReadTimeoutSeconds',
            'TimestampBodyIntakeLimit',
            'TimestampBodyIntakePerClientLimit',
            'TimestampProcessingLimit',
            'TimestampProcessingPerClientLimit')) {
        $node = $document.SelectSingleNode("/configuration/appSettings/add[@key='$key']")
        if ($null -eq $node) {
            $result[$key] = $null
        }
        else {
            $result[$key] = [string]$node.GetAttribute('value')
        }
    }

    return $result
}

function Test-IssuanceStateUsesAuthenticatedFormat {
    param([string]$EffectiveDataPath)

    $statePath = Join-Path $EffectiveDataPath 'issuance.state'
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { return $false }
    try {
        $stream = New-Object System.IO.FileStream(
            $statePath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite)
        try {
            $magic = New-Object byte[] 4
            if ($stream.Read($magic, 0, 4) -ne 4) { return $false }
            return $magic[0] -eq 0x4f -and $magic[1] -eq 0x54 -and $magic[2] -eq 0x53 -and $magic[3] -eq 0x32
        }
        finally {
            $stream.Dispose()
        }
    }
    catch {
        return $false
    }
}

function Test-IssuanceStateHasAuthenticatedRuntimeEvidence {
    param([string]$EffectiveDataPath)

    if (Test-IssuanceStateUsesAuthenticatedFormat -EffectiveDataPath $EffectiveDataPath) {
        return $true
    }
    foreach ($name in @('issuance.state.meta', 'issuance.state.meta.bak', 'issuance.state.meta.new')) {
        if (Test-Path -LiteralPath (Join-Path $EffectiveDataPath $name) -PathType Leaf) {
            return $true
        }
    }
    return $false
}

function Test-IssuanceStateArtifactsPresent {
    param([string]$EffectiveDataPath)

    # Keep this list aligned with IssuanceStateStore.PersistentArtifactPaths().
    # A marked data directory with none of these files is not a fresh install:
    # silently reseeding it would destroy serial-number continuity after data loss.
    foreach ($name in @(
        'issuance.state',
        'issuance.state.bak',
        'issuance.state.new',
        'issuance.state.bak.new',
        'issuance.state.migrate',
        'issuance.state.migrate.new',
        'issuance.state.meta',
        'issuance.state.meta.bak',
        'issuance.state.meta.new')) {
        if (Test-Path -LiteralPath (Join-Path $EffectiveDataPath $name) -PathType Leaf) {
            return $true
        }
    }

    return $false
}

function Get-IssuanceStateArtifactNames {
    param([string]$EffectiveDataPath)

    $names = @()
    foreach ($name in @(
        'issuance.state', 'issuance.state.bak', 'issuance.state.new', 'issuance.state.bak.new',
        'issuance.state.migrate', 'issuance.state.migrate.new', 'issuance.state.meta',
        'issuance.state.meta.bak', 'issuance.state.meta.new', 'issuance.state.lock')) {
        if (Test-Path -LiteralPath (Join-Path $EffectiveDataPath $name) -PathType Leaf) { $names += $name }
    }
    return $names
}

function Initialize-IssuanceStateFromRelease {
    param(
        [string]$ReleasePath,
        [string]$EffectiveDataPath
    )

    $assemblyPath = Join-Path $ReleasePath 'bin\OpenTimeStamp.Core.dll'
    try {
        # Load the selected release bytes without LoadFrom identity unification.
        # That guarantees a second deployment in the same PowerShell process
        # cannot accidentally reuse an older, same-version Core assembly.
        $assemblyBytes = [System.IO.File]::ReadAllBytes($assemblyPath)
        $assembly = [System.Reflection.Assembly]::Load($assemblyBytes)
        $type = $assembly.GetType('OpenTimeStamp.Issuance.IssuanceStateStore', $true)
        $store = [System.Activator]::CreateInstance($type, @((Join-Path $EffectiveDataPath 'issuance.state')))
        $method = $type.GetMethod('Initialize', [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::Public)
        if ($null -eq $method) { throw 'The published Core assembly does not expose IssuanceStateStore.Initialize().' }
        [void]$method.Invoke($store, @())
    }
    catch [System.Reflection.TargetInvocationException] {
        $detail = if ($null -eq $_.Exception.InnerException) { $_.Exception.Message } else { $_.Exception.InnerException.Message }
        throw "Issuance-state initialization failed: $detail"
    }
}

function Get-PoolStateValue {
    param([string]$Name)

    if (-not (Test-Path -LiteralPath "IIS:\AppPools\$Name")) { return 'Absent' }
    return [string](Get-WebAppPoolState -Name $Name).Value
}

function Get-IisApplicationPoolSettingsSnapshot {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $item = Get-Item -LiteralPath $Path
    return [PSCustomObject]@{
        ManagedRuntimeVersion = [string]$item.managedRuntimeVersion
        ManagedPipelineMode = [string]$item.managedPipelineMode
        Enable32Bit = [bool]$item.enable32BitAppOnWin64
        IdentityType = [string]$item.processModel.identityType
        LoadUserProfile = [bool]$item.processModel.loadUserProfile
        MaxProcesses = [int]$item.processModel.maxProcesses
        DisallowOverlappingRotation = [bool]$item.recycling.disallowOverlappingRotation
    }
}

function Test-IisApplicationPoolSettingsEqual {
    param($First, $Second)

    if ($null -eq $First -or $null -eq $Second) { return $null -eq $First -and $null -eq $Second }
    return ($First | ConvertTo-Json -Compress) -eq ($Second | ConvertTo-Json -Compress)
}

function Test-IisApplicationMatchesSelection {
    param(
        [string]$Path,
        [string]$PhysicalPath,
        [string]$ApplicationPool
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $item = Get-Item -LiteralPath $Path
    return (Get-OpenTimeStampCanonicalDirectoryPath -Path ([string]$item.physicalPath)).Equals(
            (Get-OpenTimeStampCanonicalDirectoryPath -Path $PhysicalPath),
            [System.StringComparison]::OrdinalIgnoreCase) -and
        ([string]$item.applicationPool).Equals($ApplicationPool, [System.StringComparison]::OrdinalIgnoreCase)
}

function Wait-PoolState {
    param(
        [string]$Name,
        [ValidateSet('Started', 'Stopped')]
        [string]$Desired,
        [int]$Seconds = 30
    )

    for ($attempt = 0; $attempt -lt ($Seconds * 4); $attempt++) {
        if ((Get-PoolStateValue -Name $Name) -eq $Desired) { return }
        Start-Sleep -Milliseconds 250
    }

    throw "Application pool '$Name' did not reach state '$Desired' within $Seconds seconds."
}

function Stop-PoolForDeployment {
    param([string]$Name)

    $state = Get-PoolStateValue -Name $Name
    if ($state -eq 'Absent' -or $state -eq 'Stopped') { return }
    Stop-WebAppPool -Name $Name
    Wait-PoolState -Name $Name -Desired Stopped
}

function Start-PoolForDeployment {
    param([string]$Name)

    if ((Get-PoolStateValue -Name $Name) -eq 'Started') { return }
    Start-WebAppPool -Name $Name
    Wait-PoolState -Name $Name -Desired Started
}

function Restore-PoolState {
    param(
        [string]$Name,
        [string]$InitialState
    )

    if ($InitialState -eq 'Absent') { return }
    if ($InitialState -eq 'Started' -or $InitialState -eq 'Starting') {
        Start-PoolForDeployment -Name $Name
    }
    else {
        Stop-PoolForDeployment -Name $Name
    }
}

function Restore-PoolStateOptimistic {
    param(
        [string]$Name,
        [string]$InitialState,
        [string]$ExpectedCurrentState
    )

    $currentState = Get-PoolStateValue -Name $Name
    if ($currentState -ne $ExpectedCurrentState) {
        throw "Application pool '$Name' state changed from installer-expected '$ExpectedCurrentState' to '$currentState'; refusing to overwrite the external change."
    }
    Restore-PoolState -Name $Name -InitialState $InitialState
    return Get-PoolStateValue -Name $Name
}

function Get-SiteStateValue {
    param([string]$Name)

    if (-not (Test-Path -LiteralPath "IIS:\Sites\$Name")) { return 'Absent' }
    return [string](Get-WebsiteState -Name $Name).Value
}

function Wait-SiteState {
    param(
        [string]$Name,
        [ValidateSet('Started', 'Stopped')]
        [string]$Desired,
        [int]$Seconds = 30
    )

    for ($attempt = 0; $attempt -lt ($Seconds * 4); $attempt++) {
        if ((Get-SiteStateValue -Name $Name) -eq $Desired) { return }
        Start-Sleep -Milliseconds 250
    }

    throw "IIS site '$Name' did not reach state '$Desired' within $Seconds seconds."
}

function Restore-SiteStateOptimistic {
    param(
        [string]$Name,
        [string]$DesiredState,
        [string]$ExpectedCurrentState
    )

    $currentState = Get-SiteStateValue -Name $Name
    $expectedStates = if ($ExpectedCurrentState -eq 'Starting') {
        @('Starting', 'Started')
    }
    elseif ($ExpectedCurrentState -eq 'Stopping') {
        @('Stopping', 'Stopped')
    }
    else {
        @($ExpectedCurrentState)
    }
    if ($currentState -notin $expectedStates) {
        throw ("IIS site '$Name' changed from installer-expected '$ExpectedCurrentState' to '$currentState'; " +
            'refusing to overwrite the external change.')
    }
    if ($currentState -eq 'Starting') {
        Wait-SiteState -Name $Name -Desired Started
        $currentState = 'Started'
    }
    elseif ($currentState -eq 'Stopping') {
        Wait-SiteState -Name $Name -Desired Stopped
        $currentState = 'Stopped'
    }
    if ($DesiredState -eq 'Started' -or $DesiredState -eq 'Starting') {
        if ($currentState -ne 'Started') {
            Start-Website -Name $Name
            Wait-SiteState -Name $Name -Desired Started
        }
    }
    elseif ($currentState -ne 'Stopped') {
        Stop-Website -Name $Name
        Wait-SiteState -Name $Name -Desired Stopped
    }
    return Get-SiteStateValue -Name $Name
}

function Get-IisApplicationPoolAssignments {
    param([string]$Name)

    $assignments = @(foreach ($existingSite in @(Get-Website)) {
        $existingSiteName = [string]$existingSite.Name
        $siteItem = Get-Item -LiteralPath "IIS:\Sites\$existingSiteName"
        $rootPoolProperty = $siteItem.PSObject.Properties['applicationPool']
        if ($null -ne $rootPoolProperty -and [string]$rootPoolProperty.Value -eq $Name) {
            "$existingSiteName/"
        }
        foreach ($existingApplication in @(Get-WebApplication -Site $existingSiteName)) {
            if ([string]$existingApplication.applicationPool -ne $Name) { continue }
            $path = [string]$existingApplication.path
            if ([string]::IsNullOrWhiteSpace($path)) {
                $path = '/' + ([string]$existingApplication.Name).TrimStart('/')
            }
            "$existingSiteName$path"
        }
    })

    return @($assignments | Sort-Object -Unique)
}

function Get-IisApplicationStorageAssignments {
    $assignments = [System.Collections.Generic.List[object]]::new()
    foreach ($existingSite in @(Get-Website)) {
        $siteName = [string]$existingSite.Name
        $siteItem = Get-Item -LiteralPath "IIS:\Sites\$siteName"
        $candidates = @([PSCustomObject]@{
            Identity = "$siteName/"
            PhysicalPath = [string]$siteItem.physicalPath
        }; foreach ($application in @(Get-WebApplication -Site $siteName)) {
            $path = [string]$application.path
            if ([string]::IsNullOrWhiteSpace($path)) { $path = '/' + ([string]$application.Name).TrimStart('/') }
            [PSCustomObject]@{
                Identity = "$siteName$path"
                PhysicalPath = [string]$application.physicalPath
            }
        })
        foreach ($candidate in $candidates) {
            if ([string]::IsNullOrWhiteSpace($candidate.PhysicalPath)) { continue }
            $physicalPath = Get-OpenTimeStampCanonicalDirectoryPath -Path $candidate.PhysicalPath
            $physicalParent = Split-Path -Parent $physicalPath
            $deploymentRoot = if ((Split-Path -Leaf $physicalParent) -eq 'Releases') {
                Split-Path -Parent $physicalParent
            }
            else {
                $physicalPath
            }
            $dataPath = Join-Path $physicalPath 'App_Data'
            $webConfigPath = Join-Path $physicalPath 'web.config'
            $appearsToBeOpenTimeStamp =
                (Test-Path -LiteralPath (Join-Path $physicalPath 'bin\OpenTimeStamp.Web.dll') -PathType Leaf) -or
                (Test-Path -LiteralPath (Join-Path $deploymentRoot $script:OpenTimeStampDeploymentMarkerName) -PathType Leaf)
            if (Test-Path -LiteralPath $webConfigPath -PathType Leaf) {
                try {
                    $document = Read-OpenTimeStampXmlDocument -Path $webConfigPath
                    $node = $document.SelectSingleNode("/configuration/appSettings/add[@key='DataPath']")
                    if ($null -ne $node -and -not [string]::IsNullOrWhiteSpace([string]$node.GetAttribute('value'))) {
                        $configured = [Environment]::ExpandEnvironmentVariables(([string]$node.GetAttribute('value')).Trim())
                        $dataPath = if ([System.IO.Path]::IsPathRooted($configured)) {
                            Get-OpenTimeStampCanonicalDirectoryPath -Path $configured
                        }
                        else {
                            Get-OpenTimeStampCanonicalDirectoryPath -Path (Join-Path $physicalPath $configured)
                        }
                    }
                }
                catch {
                    if ($appearsToBeOpenTimeStamp) {
                        throw "Could not inspect DataPath for apparent OpenTimeStamp IIS application '$($candidate.Identity)': $($_.Exception.Message)"
                    }
                }
            }
            elseif ($appearsToBeOpenTimeStamp) {
                throw "Apparent OpenTimeStamp IIS application '$($candidate.Identity)' has no readable web.config for DataPath inspection."
            }
            $assignments.Add([PSCustomObject]@{
                Application = $candidate.Identity
                PhysicalPath = $physicalPath
                DeploymentRoot = Get-OpenTimeStampCanonicalDirectoryPath -Path $deploymentRoot
                DataPath = Get-OpenTimeStampCanonicalDirectoryPath -Path $dataPath
            })
        }
        $virtualDirectories = @(@(Get-WebVirtualDirectory -Site $siteName) | ForEach-Object {
            [PSCustomObject]@{ ParentApplication = '/'; Item = $_ }
        }; foreach ($application in @(Get-WebApplication -Site $siteName)) {
            $parentApplication = ([string]$application.path).Trim('/')
            if ([string]::IsNullOrWhiteSpace($parentApplication)) {
                $parentApplication = ([string]$application.Name).Trim('/')
            }
            foreach ($virtualDirectory in @(Get-WebVirtualDirectory -Site $siteName -Application $parentApplication)) {
                [PSCustomObject]@{
                    ParentApplication = '/' + $parentApplication
                    Item = $virtualDirectory
                }
            }
        })
        $seenVirtualDirectories = @{}
        foreach ($virtualDirectoryEntry in $virtualDirectories) {
            $virtualDirectory = $virtualDirectoryEntry.Item
            $virtualPath = [string]$virtualDirectory.path
            if ([string]::IsNullOrWhiteSpace($virtualPath) -or $virtualPath -eq '/') { continue }
            $virtualPhysicalPath = [string]$virtualDirectory.physicalPath
            if ([string]::IsNullOrWhiteSpace($virtualPhysicalPath)) { continue }
            $resolvedVirtualPath = Get-OpenTimeStampCanonicalDirectoryPath -Path $virtualPhysicalPath
            $virtualIdentity = "$siteName::virtual-directory::$($virtualDirectoryEntry.ParentApplication)::$virtualPath::$resolvedVirtualPath"
            if ($seenVirtualDirectories.ContainsKey($virtualIdentity)) { continue }
            $seenVirtualDirectories[$virtualIdentity] = $true
            $assignments.Add([PSCustomObject]@{
                Application = $virtualIdentity
                PhysicalPath = $resolvedVirtualPath
                DeploymentRoot = $resolvedVirtualPath
                DataPath = $resolvedVirtualPath
                Kind = 'VirtualDirectory'
            })
        }
    }
    return [object[]]$assignments
}

function Test-OpenTimeStampPathsOverlap {
    param([string]$First, [string]$Second)
    return (Test-OpenTimeStampPathContained -Parent $First -Child $Second -AllowEqual) -or
        (Test-OpenTimeStampPathContained -Parent $Second -Child $First -AllowEqual)
}

function Assert-OpenTimeStampExclusiveIisStorage {
    param(
        [string]$TargetApplication,
        [string]$DeploymentRoot,
        [string]$DataPath
    )
    $targetPaths = @($DeploymentRoot, $DataPath)
    foreach ($assignment in @(Get-IisApplicationStorageAssignments)) {
        if ($assignment.Application.Equals($TargetApplication, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        foreach ($targetPath in $targetPaths) {
            foreach ($otherPath in @($assignment.PhysicalPath, $assignment.DeploymentRoot, $assignment.DataPath)) {
                if (Test-OpenTimeStampPathsOverlap -First $targetPath -Second $otherPath) {
                    throw "IIS application '$($assignment.Application)' already uses overlapping deployment or data storage. OpenTimeStamp storage cannot be shared between IIS applications."
                }
            }
        }
    }
}

function Test-DeploymentRootMarker {
    param([string]$Path)

    return Test-OpenTimeStampDeploymentRootMarker -Path $Path
}

function Initialize-DeploymentRootMarker {
    param([string]$Path)

    $root = Get-OpenTimeStampCanonicalDirectoryPath -Path $Path
    $markerPath = Join-Path $root $script:OpenTimeStampDeploymentMarkerName
    if (Test-DeploymentRootMarker -Path $root) {
        return [PSCustomObject]@{ Created = $false; MarkerPath = $markerPath; MarkerId = $null }
    }
    $marker = [ordered]@{
        Product = 'OpenTimeStamp'
        SchemaVersion = 1
        DeploymentId = [Guid]::NewGuid().ToString('D')
        DeploymentRoot = $root
        CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $markerId = [string]$marker.DeploymentId
    $temporary = $markerPath + '.new-' + [Guid]::NewGuid().ToString('N')
    try {
        [System.IO.File]::WriteAllText($temporary, (($marker | ConvertTo-Json -Depth 3) + [Environment]::NewLine), $encoding)
        Move-Item -LiteralPath $temporary -Destination $markerPath
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
    return [PSCustomObject]@{ Created = $true; MarkerPath = $markerPath; MarkerId = $markerId }
}

function Get-ValidatedSiteBindingEndpoints {
    param(
        [Parameter(Mandatory = $true)]$Bindings,
        [Parameter(Mandatory = $true)][string]$SiteName,
        [switch]$RequireHttps
    )

    $httpBindings = @($Bindings | Where-Object { $_.protocol -in @('http', 'https') })
    if ($httpBindings.Count -eq 0) {
        throw "IIS site '$SiteName' has no HTTP or HTTPS bindings."
    }
    $errors = [System.Collections.Generic.List[string]]::new()
    $endpoints = @(foreach ($binding in $httpBindings) {
        try { Get-OpenTimeStampValidatedBindingEndpoint -Binding $binding }
        catch { $errors.Add($_.Exception.Message) }
    })
    if ($endpoints.Count -eq 0) {
        throw "IIS site '$SiteName' has no usable HTTP or HTTPS binding: $($errors -join '; ')"
    }
    if ($RequireHttps -and @($endpoints | Where-Object Scheme -EQ 'https').Count -eq 0) {
        throw "IIS site '$SiteName' has no usable HTTPS binding: $($errors -join '; ')"
    }
    return $endpoints
}

function Assert-LocalDedicatedPath {
    param(
        [string]$Path,
        [string]$Label,
        [string[]]$ProtectedRoots
    )

    $fullPath = Get-OpenTimeStampCanonicalDirectoryPath -Path $Path
    $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
    $root = $pathRoot.TrimEnd('\')
    if ($fullPath.TrimEnd('\') -eq $root -or $fullPath.StartsWith('\\')) {
        throw "$Label must be a dedicated directory on a local drive, not a drive root or UNC path."
    }
    $driveInfo = New-Object System.IO.DriveInfo($pathRoot)
    if ($driveInfo.DriveType -ne [System.IO.DriveType]::Fixed) {
        throw "$Label must be on a fixed local drive; drive '$pathRoot' is '$($driveInfo.DriveType)'."
    }
    $driveName = $pathRoot.TrimEnd('\')
    foreach ($substMapping in @(& "$env:SystemRoot\System32\subst.exe" 2>$null)) {
        if ([string]$substMapping -match ('^(?i:' + [regex]::Escape($driveName) + '\\:)')) {
            throw "$Label cannot use SUBST drive alias '$driveName'. Use the final fixed-volume path."
        }
    }

    foreach ($protected in $ProtectedRoots) {
        $normalizedProtected = (Get-OpenTimeStampCanonicalDirectoryPath -Path $protected).TrimEnd('\')
        if ($fullPath.TrimEnd('\') -eq $normalizedProtected -or
            $fullPath.StartsWith($normalizedProtected + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "$Label cannot be inside protected operating-system directory '$normalizedProtected'."
        }
    }

    # Also inspect existing ancestors when the dedicated leaf does not exist yet;
    # lexical containment alone cannot make a path below a junction safe.
    Assert-OpenTimeStampNoReparsePoints -Root $fullPath
    return $fullPath
}

$deploymentLock = Enter-OpenTimeStampDeploymentLock -Scope 'OpenTimeStamp-MachineDeployment'
try {
try {
    $frameworkRelease = (Get-ItemProperty -LiteralPath `
        'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release).Release
}
catch {
    throw '.NET Framework 4.8 or later is not installed. Install and service .NET Framework 4.8 before deploying OpenTimeStamp.'
}
if ([int]$frameworkRelease -lt 528040) {
    throw ".NET Framework 4.8 or later is required; the installed release value is $frameworkRelease."
}

# Validate the complete payload before installing features, stopping a pool, or
# touching deployment/data ACLs.
$SourcePath = (Resolve-Path -LiteralPath $SourcePath).ProviderPath
$SourcePath = Get-OpenTimeStampCanonicalDirectoryPath -Path $SourcePath
if ([string]::IsNullOrWhiteSpace($ManifestSignaturePath) -ne
    [string]::IsNullOrWhiteSpace($TrustedManifestSignerThumbprint)) {
    throw 'ManifestSignaturePath and TrustedManifestSignerThumbprint must be supplied together.'
}
$manifestSignature = $null
if (-not [string]::IsNullOrWhiteSpace($ManifestSignaturePath)) {
    if ($AllowUnsignedManifest) {
        throw 'AllowUnsignedManifest cannot be combined with manifest-signature verification parameters.'
    }
    $manifestSignature = Assert-OpenTimeStampManifestSignature `
        -ManifestPath (Join-Path $SourcePath $script:OpenTimeStampDeploymentManifestName) `
        -SignaturePath $ManifestSignaturePath -TrustedSignerThumbprint $TrustedManifestSignerThumbprint
    $manifest = Assert-OpenTimeStampPublishedPayload -PayloadPath $SourcePath `
        -Manifest $manifestSignature.Manifest -AllowPublishMarker
}
elseif (-not $AllowUnsignedManifest) {
    throw 'A detached signed manifest is required. Supply ManifestSignaturePath and TrustedManifestSignerThumbprint, or use -AllowUnsignedManifest only for development or explicitly approved legacy deployment.'
}
else {
    Write-Warning 'Manifest authenticity verification was explicitly disabled with -AllowUnsignedManifest.'
    $manifest = Assert-OpenTimeStampPublishedPayload -PayloadPath $SourcePath -AllowPublishMarker
}

foreach ($requiredRuntimeAssembly in @(Get-OpenTimeStampRequiredRuntimeAssemblies)) {
    $requiredAssemblyPath = Join-Path $SourcePath "bin\$requiredRuntimeAssembly"
    if (-not (Test-Path -LiteralPath $requiredAssemblyPath -PathType Leaf)) {
        throw "The published payload does not contain required assembly '$requiredAssemblyPath'."
    }
}

Assert-OpenTimeStampIisProcessBitness
Assert-OpenTimeStampIisSharedConfigurationDisabled
Import-Module ServerManager
$features = @('Web-Asp-Net45', 'Web-Windows-Auth', 'Web-IP-Security', 'Web-Filtering',
    'Web-Http-Errors', 'Web-Http-Logging', 'Web-Scripting-Tools')
if ($InstallIisFeatures) {
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Install IIS role services: $($features -join ', ')")) {
        $featureResult = Install-WindowsFeature -Name $features
        if (-not $featureResult.Success) { throw 'One or more required IIS role services could not be installed.' }
        if ($featureResult.RestartNeeded -eq 'Yes') {
            throw 'Windows reports that a restart is required. Restart, then rerun this script to finish deployment.'
        }
    }
}
$missingFeatures = @($features | Where-Object {
        $feature = Get-WindowsFeature -Name $_ -ErrorAction SilentlyContinue
        $null -eq $feature -or -not $feature.Installed
    })
if ($missingFeatures.Count -ne 0) {
    throw "Required IIS role services are not installed: $($missingFeatures -join ', ')."
}

Import-Module WebAdministration
if (-not (Test-Path -LiteralPath "IIS:\Sites\$SiteName")) {
    throw "The IIS site '$SiteName' does not exist. Create its bindings and TLS certificate before installing this application."
}

$siteBindings = @(Get-WebBinding -Name $SiteName)
$siteBindingEndpoints = @(Get-ValidatedSiteBindingEndpoints -Bindings $siteBindings `
    -SiteName $SiteName -RequireHttps:$RequireHttps)

$applicationName = $ApplicationPath.TrimStart('/')
$iisApplicationPath = "IIS:\Sites\$SiteName\$applicationName"
$appLocation = "$SiteName/$applicationName"
$adminLocation = "$appLocation/admin"
$configurationPath = 'MACHINE/WEBROOT/APPHOST'
$applicationExists = Test-Path -LiteralPath $iisApplicationPath
$existingApplicationPhysicalPath = $null
$existingApplicationPool = $null
$existingWebSettings = $null
$existingIisAuthentication = $null
$existingSslFlags = $null
$appLocationExistedBefore = @(Get-WebConfigurationLocation -Name $appLocation -PSPath 'IIS:\').Count -ne 0
$adminLocationExistedBefore = @(Get-WebConfigurationLocation -Name $adminLocation -PSPath 'IIS:\').Count -ne 0
$unsupportedAuthenticationSections = @(
    @{ Section = 'system.webServer/security/authentication/basicAuthentication'; Feature = 'Web-Basic-Auth' },
    @{ Section = 'system.webServer/security/authentication/digestAuthentication'; Feature = 'Web-Digest-Auth' },
    @{ Section = 'system.webServer/security/authentication/clientCertificateMappingAuthentication'; Feature = 'Web-Client-Auth' },
    @{ Section = 'system.webServer/security/authentication/iisClientCertificateMappingAuthentication'; Feature = 'Web-Cert-Auth' })
$allAuthenticationSections = @(
    @{ Section = 'system.webServer/security/authentication/anonymousAuthentication'; Feature = $null },
    @{ Section = 'system.webServer/security/authentication/windowsAuthentication'; Feature = 'Web-Windows-Auth' }) +
    $unsupportedAuthenticationSections
$iisLocalStateBefore = Get-IisExactLocalState -AppLocation $appLocation -AdminLocation $adminLocation `
    -AuthenticationDefinitions $allAuthenticationSections
if ($applicationExists) {
    $applicationItem = Get-Item -LiteralPath $iisApplicationPath
    $existingApplicationPhysicalPath = Get-OpenTimeStampCanonicalDirectoryPath -Path ([string]$applicationItem.physicalPath)
    $existingApplicationPool = [string]$applicationItem.applicationPool
    if ([string]::IsNullOrWhiteSpace($existingApplicationPool) -or
        -not (Test-Path -LiteralPath "IIS:\AppPools\$existingApplicationPool")) {
        throw 'The existing IIS application does not reference an existing application pool.'
    }
    $existingWebSettings = Get-ExistingWebSettings -ApplicationPhysicalPath $existingApplicationPhysicalPath
    Assert-OpenTimeStampIntakeSettings -Settings $existingWebSettings
    $existingIisAuthentication = Get-IisAuthenticationMode -ConfigurationPath $configurationPath -Location $appLocation
    $existingSslFlags = (Get-WebConfigurationProperty -PSPath $configurationPath -Location $appLocation `
        -Filter 'system.webServer/security/access' -Name sslFlags).Value

    $currentPoolAssignments = @(Get-IisApplicationPoolAssignments -Name $existingApplicationPool)
    $unexpectedCurrentPoolAssignments = @($currentPoolAssignments |
        Where-Object { $_ -ne "$SiteName$ApplicationPath" })
    if ($unexpectedCurrentPoolAssignments.Count -ne 0) {
        throw "The existing application uses shared pool '$existingApplicationPool', which cannot be safely quiesced for state migration: $($unexpectedCurrentPoolAssignments -join ', '). Move OpenTimeStamp to a dedicated pool first."
    }
}
else {
    if ($appLocationExistedBefore) {
        $existingSslFlags = (Get-WebConfigurationProperty -PSPath $configurationPath -Location $appLocation `
            -Filter 'system.webServer/security/access' -Name sslFlags).Value
    }
}

$effectiveRequireHttps = [bool]$RequireHttps -or
    ($applicationExists -and -not $PSBoundParameters.ContainsKey('RequireHttps') -and
        [string]$existingSslFlags -match 'Ssl')
if ($effectiveRequireHttps -and @($siteBindingEndpoints | Where-Object Scheme -EQ 'https').Count -eq 0) {
    throw "The existing or requested application policy requires HTTPS, but IIS site '$SiteName' has no usable HTTPS binding."
}

if ($applicationExists -and -not $PSBoundParameters.ContainsKey('PhysicalPath')) {
    $parent = Split-Path -Parent $existingApplicationPhysicalPath
    if ((Split-Path -Leaf $parent) -eq 'Releases') {
        $PhysicalPath = Split-Path -Parent $parent
    }
    else {
        $PhysicalPath = $existingApplicationPhysicalPath
    }
}

$protectedRoots = @($env:WINDIR,
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)) |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
$PhysicalPath = Assert-LocalDedicatedPath -Path $PhysicalPath -Label 'PhysicalPath' -ProtectedRoots $protectedRoots
$releasesPath = Join-Path $PhysicalPath 'Releases'
$defaultDataPath = Join-Path $PhysicalPath 'App_Data'

$normalizedSource = $SourcePath.TrimEnd('\')
$normalizedPhysical = $PhysicalPath.TrimEnd('\')
if ($normalizedPhysical -eq $normalizedSource -or
    (Test-OpenTimeStampPathContained -Parent $normalizedSource -Child $normalizedPhysical) -or
    (Test-OpenTimeStampPathContained -Parent $normalizedPhysical -Child $normalizedSource)) {
    throw 'SourcePath and the deployment root must be separate, non-nested directories.'
}

$legacyRootTrusted = $applicationExists -and
    $existingApplicationPhysicalPath.TrimEnd('\').Equals($normalizedPhysical, [System.StringComparison]::OrdinalIgnoreCase) -and
    (Test-Path -LiteralPath (Join-Path $PhysicalPath 'bin\OpenTimeStamp.Web.dll') -PathType Leaf) -and
    (Test-Path -LiteralPath (Join-Path $PhysicalPath 'bin\OpenTimeStamp.Core.dll') -PathType Leaf)
if (Test-Path -LiteralPath $PhysicalPath -PathType Container) {
    $rootItems = @(Get-ChildItem -LiteralPath $PhysicalPath -Force)
    if ($rootItems.Count -ne 0 -and -not (Test-DeploymentRootMarker -Path $PhysicalPath) -and -not $legacyRootTrusted) {
        throw "The non-empty deployment root '$PhysicalPath' is neither marked nor the active legacy OpenTimeStamp application."
    }

    Assert-OpenTimeStampNoReparsePoints -Root $PhysicalPath
}

if ($applicationExists -and -not $PSBoundParameters.ContainsKey('AuthenticationMode')) {
    $configuredMode = if ($null -eq $existingWebSettings['AuthenticationMode']) { '' } else { $existingWebSettings['AuthenticationMode'].Trim() }
    if ($configuredMode -notin @('Anonymous', 'Windows') -or
        $null -eq $existingIisAuthentication -or
        -not $configuredMode.Equals($existingIisAuthentication, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The existing web.config and effective IIS authentication mode are missing, invalid, or ambiguous. Pass -AuthenticationMode explicitly to repair the deployment.'
    }

    $AuthenticationMode = $existingIisAuthentication
}

if (-not $applicationExists -and -not $PSBoundParameters.ContainsKey('AuthenticationMode') -and
    (Test-Path -LiteralPath $PhysicalPath -PathType Container) -and
    @(Get-ChildItem -LiteralPath $PhysicalPath -Force).Count -ne 0) {
    throw 'AuthenticationMode must be explicit when adopting a deployment root that has no authoritative IIS application.'
}

$existingRuntimeDataPath = $null
if ($applicationExists) {
    $savedDataPath = if ($null -eq $existingWebSettings['DataPath']) { '' } else { $existingWebSettings['DataPath'].Trim() }
    if ([string]::IsNullOrWhiteSpace($savedDataPath)) {
        $existingRuntimeDataPath = Join-Path $existingApplicationPhysicalPath 'App_Data'
    }
    else {
        $expandedExistingDataPath = [Environment]::ExpandEnvironmentVariables($savedDataPath)
        $existingRuntimeDataPath = if ([System.IO.Path]::IsPathRooted($expandedExistingDataPath)) {
            Get-OpenTimeStampCanonicalDirectoryPath -Path $expandedExistingDataPath
        }
        else {
            Get-OpenTimeStampCanonicalDirectoryPath -Path (Join-Path $existingApplicationPhysicalPath $expandedExistingDataPath)
        }
    }
}

if ($PSBoundParameters.ContainsKey('DataPath')) {
    $runtimeDataPath = if ([string]::IsNullOrWhiteSpace($DataPath)) {
        $defaultDataPath
    }
    else {
        $expanded = [Environment]::ExpandEnvironmentVariables($DataPath.Trim())
        if (-not [System.IO.Path]::IsPathRooted($expanded)) { throw 'DataPath must be absolute.' }
        Get-OpenTimeStampCanonicalDirectoryPath -Path $expanded
    }
}
elseif ($applicationExists) {
    $runtimeDataPath = $existingRuntimeDataPath
}
else {
    $runtimeDataPath = $defaultDataPath
}

$runtimeDataPath = Assert-LocalDedicatedPath -Path $runtimeDataPath -Label 'DataPath' -ProtectedRoots $protectedRoots
$dataIsDefault = $runtimeDataPath.TrimEnd('\').Equals($defaultDataPath.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)
if ((Test-OpenTimeStampPathContained -Parent $releasesPath -Child $runtimeDataPath -AllowEqual) -or
    (Test-OpenTimeStampPathContained -Parent $SourcePath -Child $runtimeDataPath -AllowEqual) -or
    (Test-OpenTimeStampPathContained -Parent $runtimeDataPath -Child $SourcePath -AllowEqual) -or
    ((Test-OpenTimeStampPathContained -Parent $PhysicalPath -Child $runtimeDataPath) -and -not $dataIsDefault) -or
    (Test-OpenTimeStampPathContained -Parent $runtimeDataPath -Child $PhysicalPath -AllowEqual)) {
    throw 'DataPath must be the deployment App_Data directory or a separate, non-nested local directory.'
}

$targetApplicationIdentity = "$SiteName$ApplicationPath"
$serviceAutoStartProviderName = 'OpenTimeStamp'
$serviceAutoStartProviderType = 'OpenTimeStamp.Web.OpenTimeStampPreloadClient, OpenTimeStamp.Web'
Assert-OpenTimeStampExclusiveIisStorage -TargetApplication $targetApplicationIdentity `
    -DeploymentRoot $PhysicalPath -DataPath $runtimeDataPath

$dataClassification = Get-OpenTimeStampDataDirectoryClassification -Path $runtimeDataPath
if ($dataClassification.Kind -eq 'Legacy' -and -not $AdoptExistingDataPath) {
    throw "The legacy data directory '$runtimeDataPath' requires explicit -AdoptExistingDataPath after its contents are reviewed."
}
if ($dataClassification.Kind -eq 'Unrecognized') {
    throw "The non-empty DataPath '$runtimeDataPath' is not a marked or exactly recognizable OpenTimeStamp data directory."
}
if ($dataClassification.Kind -eq 'Marked' -and
    -not (Test-IssuanceStateArtifactsPresent -EffectiveDataPath $runtimeDataPath) -and
    -not (Test-OpenTimeStampDataDirectoryUninitializedScaffolding `
        -Classification $dataClassification)) {
    throw "The marked DataPath '$runtimeDataPath' contains no issuance-state artifacts. Refusing to reseed serial state; restore the complete state set from a known-good backup or use a genuinely new data directory for a new installation."
}

$hostCandidates = [System.Collections.Generic.List[string]]::new()
foreach ($hostName in @('localhost', '127.0.0.1', '::1', [Environment]::MachineName)) {
    $hostCandidates.Add($hostName)
}
$networkIdentity = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
if (-not [string]::IsNullOrWhiteSpace($networkIdentity.DomainName)) {
    $hostCandidates.Add($networkIdentity.HostName + '.' + $networkIdentity.DomainName.Trim('.'))
}
foreach ($binding in $siteBindings) {
    $bindingParts = @(([string]$binding.bindingInformation).Split(':'))
    $bindingHost = if ($bindingParts.Count -ge 3) { $bindingParts[$bindingParts.Count - 1].Trim() } else { '' }
    if (-not [string]::IsNullOrWhiteSpace($bindingHost) -and $bindingHost.IndexOf('*') -lt 0 -and $bindingHost -ne '+') {
        $hostCandidates.Add($bindingHost)
    }
}
if (-not $PSBoundParameters.ContainsKey('AdminHostNames') -and $applicationExists -and
    -not [string]::IsNullOrWhiteSpace($existingWebSettings['AdminHostNames'])) {
    $AdminHostNames = @($existingWebSettings['AdminHostNames'] -split '[,;]')
}
foreach ($configuredHost in @($AdminHostNames)) {
    if ([string]::IsNullOrWhiteSpace($configuredHost)) { continue }
    foreach ($hostName in @($configuredHost -split '[,;]')) { $hostCandidates.Add($hostName) }
}
$effectiveAdminHostNames = [System.Collections.Generic.List[string]]::new()
$seenAdminHostNames = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($candidate in $hostCandidates) {
    $normalized = ConvertTo-NormalizedHostName -HostName $candidate
    if ($seenAdminHostNames.Add($normalized)) { $effectiveAdminHostNames.Add($normalized) }
}

# A signing-key identity and the application's current pool must both be
# dedicated. Quiescing a shared current pool would create collateral downtime.
$expectedPoolAssignment = "$SiteName$ApplicationPath"
$poolAssignments = @(Get-IisApplicationPoolAssignments -Name $AppPoolName)
$unexpectedPoolAssignments = @($poolAssignments | Where-Object { $_ -ne $expectedPoolAssignment } | Sort-Object -Unique)
if ($unexpectedPoolAssignments.Count -ne 0) {
    throw "Application pool '$AppPoolName' is assigned to another IIS application: $($unexpectedPoolAssignments -join ', ')."
}

$poolPath = "IIS:\AppPools\$AppPoolName"
$targetPoolExisted = Test-Path -LiteralPath $poolPath
$targetPoolOriginalSettings = $null
if ($targetPoolExisted) {
    $targetPoolOriginalSettings = Get-IisApplicationPoolSettingsSnapshot -Path $poolPath
}
$targetPoolPreMutationSettings = $targetPoolOriginalSettings
$targetPoolAppliedSettings = $null
$targetPoolCreatedInitialState = $null

$deploymentParent = Split-Path -Parent $PhysicalPath
$stagePath = Join-Path $deploymentParent ('.' + (Split-Path -Leaf $PhysicalPath) + '.stage-' +
    [string]$manifest.ReleaseId + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$releasePath = Join-Path $releasesPath ([string]$manifest.ReleaseId)
if (Test-Path -LiteralPath $releasePath) {
    throw "Release '$($manifest.ReleaseId)' is already present under '$releasesPath'."
}

if ($WhatIfPreference) {
    Write-Output ([PSCustomObject]@{
        Application = "$SiteName$ApplicationPath"
        DeploymentRoot = $PhysicalPath
        PlannedReleasePath = $releasePath
        DataPath = $runtimeDataPath
        AuthenticationMode = $AuthenticationMode
        AlwaysWarm = $true
        WhatIf = $true
    })
    return
}

if (-not $PSCmdlet.ShouldProcess(
        "$SiteName$ApplicationPath",
        "Deploy manifested release '$($manifest.ReleaseId)' to '$releasePath'")) {
    return
}

$createdTargetPool = $false
$preflightSucceeded = $false
$stageOwnedByInstaller = $false
$privateKeyAccessChange = $null
$deploymentParentCreatedByInstaller = $false
try {
    if (-not (Test-Path -LiteralPath $poolPath)) {
        New-WebAppPool -Name $AppPoolName | Out-Null
        $createdTargetPool = $true
    }
    if (-not (Test-Path -LiteralPath $poolPath)) {
        throw "Application pool '$AppPoolName' does not exist."
    }
    $targetPoolPreMutationSettings = Get-IisApplicationPoolSettingsSnapshot -Path $poolPath
    if ($createdTargetPool) { $targetPoolCreatedInitialState = Get-PoolStateValue -Name $AppPoolName }

    $poolAccount = New-Object System.Security.Principal.NTAccount("IIS AppPool\$AppPoolName")
    $poolSid = $poolAccount.Translate([System.Security.Principal.SecurityIdentifier])
    if (-not (Test-Path -LiteralPath $deploymentParent -PathType Container)) {
        New-Item -ItemType Directory -Path $deploymentParent -ErrorAction Stop | Out-Null
        $deploymentParentCreatedByInstaller = $true
    }

    Copy-OpenTimeStampPublishedPayload -PayloadPath $SourcePath -DestinationPath $stagePath `
        -Manifest $manifest -ApplicationPoolSid $poolSid
    $stageOwnedByInstaller = $true
    Set-OpenTimeStampStagedWebSettings -ReleasePath $stagePath -Mode $AuthenticationMode `
        -EffectiveDataPath $runtimeDataPath -EffectiveAdminHosts $effectiveAdminHostNames `
        -ExistingSettings $existingWebSettings
    New-OpenTimeStampDeploymentManifest -PayloadPath $stagePath -ReleaseId ([string]$manifest.ReleaseId) | Out-Null
    Assert-OpenTimeStampPublishedPayload -PayloadPath $stagePath | Out-Null
    Set-OpenTimeStampRestrictedDirectoryAcl -Path $stagePath -ApplicationPoolSid $poolSid `
        -PoolRights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute) -Recursive

    # Complete all remaining failure-prone observations before a key ACL can be
    # changed. From the grant onward, execution enters the rollback-covered try.
    $initialPoolStates = @{}
    foreach ($pool in @($existingApplicationPool, $AppPoolName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) {
        $initialPoolStates[$pool] = Get-PoolStateValue -Name $pool
    }
    $installerExpectedPoolStates = @{}
    foreach ($pool in @($initialPoolStates.Keys)) { $installerExpectedPoolStates[$pool] = $initialPoolStates[$pool] }
    $initialSiteState = Get-SiteStateValue -Name $SiteName
    if ($initialSiteState -eq 'Absent') { throw "IIS site '$SiteName' disappeared after preflight." }
    if ($initialSiteState -eq 'Starting') {
        Wait-SiteState -Name $SiteName -Desired Started
        $initialSiteState = 'Started'
    }
    elseif ($initialSiteState -eq 'Stopping') {
        Wait-SiteState -Name $SiteName -Desired Stopped
        $initialSiteState = 'Stopped'
    }
    $installerExpectedSiteState = $initialSiteState
    $iisWarmStateBefore = Get-IisAlwaysWarmState -SiteName $SiteName -ApplicationPath $ApplicationPath `
        -AppPoolName $AppPoolName -ProviderName $serviceAutoStartProviderName
    Assert-IisServiceAutoStartProviderCompatible -State $iisWarmStateBefore `
        -ProviderName $serviceAutoStartProviderName -ProviderType $serviceAutoStartProviderType
    $deploymentSucceeded = $false
    $applicationPointerChanged = $false
    $newApplicationCreated = $false
    $dataInitialization = $null
    $dataDirectoryInitialization = $null
    $caughtError = $null
    $issuanceStateWasAuthenticatedFormat = Test-IssuanceStateUsesAuthenticatedFormat -EffectiveDataPath $runtimeDataPath
    $issuanceMigrationCommitted = $false
    $targetPoolConfigurationChanged = $false
    $dataAclChanged = $false
    $deploymentRootAclChanged = $false
    $logDirectoryCreated = $false
    $releaseMoved = $false
    $oldApplicationSelectionRestored = $false
    $iisConfigurationChanged = $false
    $iisLocalStateRestored = $false
    $iisLocalStateApplied = $null
    $iisWarmConfigurationChanged = $false
    $iisWarmStateRestored = $true
    $iisWarmStatePreMutation = $null
    $iisWarmStateApplied = $null
    $dataPathExistedBefore = Test-Path -LiteralPath $runtimeDataPath -PathType Container
    $physicalPathExistedBefore = Test-Path -LiteralPath $PhysicalPath -PathType Container
    $dataAclSnapshotBefore = if ($dataPathExistedBefore) {
        Get-OpenTimeStampRecursiveAclSnapshot -Path $runtimeDataPath
    } else { $null }
    $deploymentRootAclSnapshotBefore = if ($physicalPathExistedBefore) {
        Get-OpenTimeStampRecursiveAclSnapshot -Path $PhysicalPath -RootOnly
    } else { $null }
    $issuanceArtifactsBefore = @(Get-IssuanceStateArtifactNames -EffectiveDataPath $runtimeDataPath)
    $dataAclSnapshotApplied = $null
    $deploymentRootAclSnapshotApplied = $null
    $physicalPathCreatedByInstaller = $false
    $dataDirectoryCreatedByInstaller = $false
    $releasesDirectoryCreatedByInstaller = $false
    $deploymentRootMarkerInitialization = $null
    $preserveInstallerCreatedScaffolding = $false

    if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        $grantScript = Join-Path $PSScriptRoot 'Grant-TsaPrivateKeyAccess.ps1'
        $grantArguments = @{
            Thumbprint = $CertificateThumbprint
            Identity = "IIS AppPool\$AppPoolName"
            Confirm = $false
        }
        if ($AllowBroadExistingKeyAcl) { $grantArguments.AllowBroadExistingKeyAcl = $true }
        $privateKeyAccessChange = & $grantScript @grantArguments
    }

    $preflightSucceeded = $true
}
finally {
    if (-not $preflightSucceeded) {
        if ($null -ne $privateKeyAccessChange -and [bool]$privateKeyAccessChange.AclChanged) {
            try { Restore-PrivateKeyAclChange -Change $privateKeyAccessChange }
            catch { Write-Warning "The private-key ACL could not be restored after preflight failure: $($_.Exception.Message)" }
        }
        if ($stageOwnedByInstaller -and (Test-Path -LiteralPath $stagePath)) {
            try { Remove-OpenTimeStampControlledDirectory -ExpectedParent $deploymentParent -Path $stagePath }
            catch { Write-Warning "Preflight staging directory '$stagePath' could not be removed: $($_.Exception.Message)" }
        }
        if ($createdTargetPool -and (Test-Path -LiteralPath $poolPath)) {
            try {
                $currentSettings = Get-IisApplicationPoolSettingsSnapshot -Path $poolPath
                $currentAssignments = @(Get-IisApplicationPoolAssignments -Name $AppPoolName)
                $currentState = Get-PoolStateValue -Name $AppPoolName
                if (-not (Test-IisApplicationPoolSettingsEqual -First $currentSettings -Second $targetPoolPreMutationSettings) -or
                    $currentAssignments.Count -ne 0 -or $currentState -ne $targetPoolCreatedInitialState) {
                    throw 'The installer-created application pool changed or acquired an assignment; preserving it.'
                }
                Remove-WebAppPool -Name $AppPoolName
            }
            catch { Write-Warning "Preflight application pool '$AppPoolName' could not be removed: $($_.Exception.Message)" }
        }
        if ($deploymentParentCreatedByInstaller -and
            (Test-Path -LiteralPath $deploymentParent -PathType Container) -and
            @(Get-ChildItem -LiteralPath $deploymentParent -Force).Count -eq 0) {
            try { Remove-Item -LiteralPath $deploymentParent -Force }
            catch { Write-Warning "Installer-created deployment parent '$deploymentParent' could not be removed: $($_.Exception.Message)" }
        }
    }
}

try {
    # Recheck mutable IIS assignments immediately before quiescing pools and
    # changing ACLs; the deployment mutex cannot serialize external IIS admins.
    Assert-OpenTimeStampExclusiveIisStorage -TargetApplication $targetApplicationIdentity `
        -DeploymentRoot $PhysicalPath -DataPath $runtimeDataPath
    foreach ($poolName in @($existingApplicationPool, $AppPoolName) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) {
        $lastMinutePoolAssignments = @(Get-IisApplicationPoolAssignments -Name $poolName)
        $lastMinuteUnexpectedPoolAssignments = @($lastMinutePoolAssignments |
            Where-Object { $_ -ne $targetApplicationIdentity })
        if ($lastMinuteUnexpectedPoolAssignments.Count -ne 0) {
            throw "Application pool '$poolName' acquired another assignment before mutation: $($lastMinuteUnexpectedPoolAssignments -join ', ')."
        }
    }
    if ($applicationExists) {
        if (-not (Test-IisApplicationMatchesSelection -Path $iisApplicationPath `
                -PhysicalPath $existingApplicationPhysicalPath -ApplicationPool $existingApplicationPool)) {
            throw 'The target IIS application changed after preflight; refusing to overwrite the external application selection.'
        }
    }
    elseif (Test-Path -LiteralPath $iisApplicationPath) {
        throw 'The target IIS application was created externally after preflight; refusing to adopt or overwrite it.'
    }
    $currentSiteState = Get-SiteStateValue -Name $SiteName
    if ($currentSiteState -ne $initialSiteState) {
        throw "IIS site '$SiteName' changed after preflight from '$initialSiteState' to '$currentSiteState'."
    }
    $currentWarmState = Get-IisAlwaysWarmState -SiteName $SiteName -ApplicationPath $ApplicationPath `
        -AppPoolName $AppPoolName -ProviderName $serviceAutoStartProviderName
    if (-not (Test-IisAlwaysWarmStateEqual -First $currentWarmState -Second $iisWarmStateBefore)) {
        throw 'IIS always-warm settings changed after preflight; refusing to absorb the external change.'
    }
    foreach ($pool in @($initialPoolStates.Keys)) {
        $currentPoolState = Get-PoolStateValue -Name $pool
        if ($currentPoolState -ne $initialPoolStates[$pool]) {
            throw "Application pool '$pool' state changed after preflight from '$($initialPoolStates[$pool])' to '$currentPoolState'."
        }
    }

    foreach ($pool in @($initialPoolStates.Keys)) {
        if ($initialPoolStates[$pool] -ne 'Absent') {
            Stop-PoolForDeployment -Name $pool
            $installerExpectedPoolStates[$pool] = 'Stopped'
        }
    }

    $currentTargetPoolSettings = Get-IisApplicationPoolSettingsSnapshot -Path $poolPath
    if (-not (Test-IisApplicationPoolSettingsEqual -First $currentTargetPoolSettings -Second $targetPoolPreMutationSettings)) {
        throw "Application pool '$AppPoolName' settings changed after preflight; refusing to overwrite the external change."
    }
    $targetPoolConfigurationChanged = $true
    $targetPoolDesiredSettings = [PSCustomObject]@{
        ManagedRuntimeVersion = 'v4.0'
        ManagedPipelineMode = 'Integrated'
        Enable32Bit = $false
        IdentityType = 'ApplicationPoolIdentity'
        LoadUserProfile = $true
        MaxProcesses = 1
        DisallowOverlappingRotation = $true
    }
    $targetPoolAppliedSettings = $targetPoolDesiredSettings
    try {
        Set-IisApplicationPoolSettingsAtomic -Name $AppPoolName `
            -ExpectedSettings $targetPoolPreMutationSettings -Settings $targetPoolDesiredSettings
    }
    catch {
        $poolSettingsMutationError = $_
        try {
            $observedPoolSettings = Get-IisApplicationPoolSettingsSnapshot -Path $poolPath
            if (Test-IisApplicationPoolSettingsEqual -First $observedPoolSettings -Second $targetPoolPreMutationSettings) {
                $targetPoolConfigurationChanged = $false
                $targetPoolAppliedSettings = $targetPoolPreMutationSettings
            }
            elseif (-not (Test-IisApplicationPoolSettingsEqual -First $observedPoolSettings -Second $targetPoolDesiredSettings)) {
                $targetPoolAppliedSettings = $null
            }
        }
        catch { $targetPoolAppliedSettings = $null }
        Write-Warning 'Pool settings mutation failed; rollback will proceed only from a verified original or desired state.'
        throw $poolSettingsMutationError
    }
    $observedPoolSettings = Get-IisApplicationPoolSettingsSnapshot -Path $poolPath
    if (-not (Test-IisApplicationPoolSettingsEqual -First $observedPoolSettings -Second $targetPoolDesiredSettings)) {
        throw "Application pool '$AppPoolName' atomic commit did not apply the exact desired settings."
    }
    $targetPoolAppliedSettings = $targetPoolDesiredSettings

    # Create the deployment root explicitly so default App_Data initialization
    # cannot create it implicitly and obscure ownership. Harden the empty or
    # pre-existing root before placing any data, release, or marker beneath it.
    $physicalDirectoryInitialization = Initialize-OpenTimeStampOwnedDirectory -Path $PhysicalPath
    $physicalPathCreatedByInstaller = [bool]$physicalDirectoryInitialization.Created
    $deploymentRootAclChanged = $true
    try {
        Set-OpenTimeStampRestrictedDirectoryAcl -Path $PhysicalPath -ApplicationPoolSid $poolSid `
            -PoolRights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
    }
    catch {
        $rootAclMutationError = $_
        $deploymentRootAclSnapshotApplied = $null
        Write-Warning 'Deployment-root ACL mutation failed before a complete applied state was verified; rollback will fail closed.'
        throw $rootAclMutationError
    }
    if ($physicalPathExistedBefore) {
        $deploymentRootAclSnapshotApplied = Get-OpenTimeStampRecursiveAclSnapshot -Path $PhysicalPath -RootOnly
    }

    # Establish and restrict DataPath before its ownership marker or Logs are
    # created. This preserves caller ownership separately so rollback can remove
    # an empty directory even if marker initialization itself fails.
    $dataDirectoryInitialization = Initialize-OpenTimeStampOwnedDirectory -Path $runtimeDataPath
    $dataDirectoryCreatedByInstaller = [bool]$dataDirectoryInitialization.Created
    $dataAclChanged = $true
    try {
        Set-OpenTimeStampRestrictedDirectoryAcl -Path $runtimeDataPath -ApplicationPoolSid $poolSid `
            -PoolRights ([System.Security.AccessControl.FileSystemRights]::Modify) -Recursive
    }
    catch {
        $dataAclMutationError = $_
        $dataAclSnapshotApplied = $null
        Write-Warning 'Data ACL mutation failed before a complete applied state was verified; rollback will fail closed.'
        throw $dataAclMutationError
    }
    if ($null -ne $dataAclSnapshotBefore) {
        $dataAclSnapshotApplied = Get-OpenTimeStampRecursiveAclSnapshot -Path $runtimeDataPath
    }

    $dataInitialization = Initialize-OpenTimeStampDataDirectory -Path $runtimeDataPath `
        -AdoptExisting:$AdoptExistingDataPath `
        -DirectoryCreatedByCaller:$dataDirectoryCreatedByInstaller
    $logPath = Join-Path $runtimeDataPath 'Logs'
    if (-not (Test-Path -LiteralPath $logPath -PathType Container)) {
        New-Item -ItemType Directory -Path $logPath -ErrorAction Stop | Out-Null
        $logDirectoryCreated = $true
    }

    if (-not (Test-Path -LiteralPath $releasesPath -PathType Container)) {
        New-Item -ItemType Directory -Path $releasesPath -ErrorAction Stop | Out-Null
        $releasesDirectoryCreatedByInstaller = $true
    }
    $deploymentRootMarkerInitialization = Initialize-DeploymentRootMarker -Path $PhysicalPath
    Move-Item -LiteralPath $stagePath -Destination $releasePath
    $releaseMoved = $true
    $stageOwnedByInstaller = $false
    Set-OpenTimeStampRestrictedDirectoryAcl -Path $releasePath -ApplicationPoolSid $poolSid `
        -PoolRights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute) -Recursive

    if ($applicationExists) {
        # Set the rollback flag before the first property write: changing the
        # physical path can succeed even if the following pool assignment fails.
        $applicationPointerChanged = $true
        Set-ItemProperty -LiteralPath $iisApplicationPath -Name physicalPath -Value $releasePath
        Set-ItemProperty -LiteralPath $iisApplicationPath -Name applicationPool -Value $AppPoolName
    }
    else {
        New-WebApplication -Site $SiteName -Name $applicationName -PhysicalPath $releasePath -ApplicationPool $AppPoolName | Out-Null
        $newApplicationCreated = $true
        $applicationPointerChanged = $true
    }

    $iisConfigurationChanged = $true
    $adminIpv4Addresses = [System.Collections.Generic.List[string]]::new()
    $adminIpv4Addresses.Add('127.0.0.1')
    foreach ($networkInterface in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($networkInterface.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
        foreach ($unicastAddress in $networkInterface.GetIPProperties().UnicastAddresses) {
            if ($unicastAddress.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                $addressText = $unicastAddress.Address.ToString()
                if ($addressText -ne '0.0.0.0' -and $adminIpv4Addresses -notcontains $addressText) {
                    $adminIpv4Addresses.Add($addressText)
                }
            }
        }
    }
    $setTlsSettings = $PSBoundParameters.ContainsKey('RequireHttps') -or -not $applicationExists
    try {
        Set-IisDesiredLocalStateAtomic -AppLocation $appLocation -AdminLocation $adminLocation `
            -ExpectedState $iisLocalStateBefore -AuthenticationMode $AuthenticationMode `
            -UnsupportedAuthenticationSections $unsupportedAuthenticationSections `
            -SetTlsSettings:$setTlsSettings -RequireTls ([bool]$RequireHttps) `
            -AdminIpv4Addresses $adminIpv4Addresses
        $observedIisLocalState = Get-IisExactLocalState -AppLocation $appLocation -AdminLocation $adminLocation `
            -AuthenticationDefinitions $allAuthenticationSections
        if (-not (Test-IisDesiredLocalState -AppLocation $appLocation -AdminLocation $adminLocation `
                -AuthenticationMode $AuthenticationMode `
                -UnsupportedAuthenticationSections $unsupportedAuthenticationSections `
                -ExpectedState $iisLocalStateBefore `
                -SetTlsSettings:$setTlsSettings -RequireTls ([bool]$RequireHttps) `
                -AdminIpv4Addresses $adminIpv4Addresses)) {
            throw 'The atomic IIS commit did not apply the complete desired local state.'
        }
        $iisLocalStateApplied = $observedIisLocalState
    }
    catch {
        $iisMutationError = $_
        try {
            $observedIisLocalState = Get-IisExactLocalState -AppLocation $appLocation -AdminLocation $adminLocation `
                -AuthenticationDefinitions $allAuthenticationSections
            if (($observedIisLocalState | ConvertTo-Json -Depth 8 -Compress) -eq
                ($iisLocalStateBefore | ConvertTo-Json -Depth 8 -Compress)) {
                $iisConfigurationChanged = $false
                $iisLocalStateApplied = $iisLocalStateBefore
            }
            elseif (Test-IisDesiredLocalState -AppLocation $appLocation -AdminLocation $adminLocation `
                    -AuthenticationMode $AuthenticationMode `
                    -UnsupportedAuthenticationSections $unsupportedAuthenticationSections `
                    -ExpectedState $iisLocalStateBefore `
                    -SetTlsSettings:$setTlsSettings -RequireTls ([bool]$RequireHttps) `
                    -AdminIpv4Addresses $adminIpv4Addresses) {
                $iisLocalStateApplied = $observedIisLocalState
            }
            else { $iisLocalStateApplied = $null }
        }
        catch { $iisLocalStateApplied = $null }
        throw $iisMutationError
    }

    $iisWarmStatePreMutation = Get-IisAlwaysWarmState -SiteName $SiteName `
        -ApplicationPath $ApplicationPath -AppPoolName $AppPoolName `
        -ProviderName $serviceAutoStartProviderName
    if (-not (Test-IisAlwaysWarmPreMutationState -Before $iisWarmStateBefore `
            -Current $iisWarmStatePreMutation -ApplicationExisted $applicationExists `
            -ApplicationIdentity $targetApplicationIdentity)) {
        throw 'IIS always-warm settings changed between application selection and the atomic commit.'
    }
    Assert-IisServiceAutoStartProviderCompatible -State $iisWarmStatePreMutation `
        -ProviderName $serviceAutoStartProviderName -ProviderType $serviceAutoStartProviderType

    # This durable commit intentionally precedes always-warm activation because
    # setting AlwaysRunning can cause WAS to load the service auto-start provider.
    # OTS1 -> OTS2 is never rolled back to a lagging backup.
    $currentDataClassification = Get-OpenTimeStampDataDirectoryClassification -Path $runtimeDataPath
    $newMarkerWithoutPriorIssuanceState = [bool]$dataInitialization.MarkerCreated -and
        $issuanceArtifactsBefore.Count -eq 0
    if ($currentDataClassification.Kind -eq 'Marked' -and
        -not (Test-IssuanceStateArtifactsPresent -EffectiveDataPath $runtimeDataPath) -and
        -not $newMarkerWithoutPriorIssuanceState -and
        -not (Test-OpenTimeStampDataDirectoryUninitializedScaffolding `
            -Classification $currentDataClassification)) {
        throw 'All issuance-state artifacts disappeared from the existing marked DataPath during deployment. Refusing to create a replacement serial sequence.'
    }
    # External IIS administrators are not serialized by the deployment mutex.
    # Recheck storage and dedicated-pool ownership at the final commit boundary.
    Assert-OpenTimeStampExclusiveIisStorage -TargetApplication $targetApplicationIdentity `
        -DeploymentRoot $PhysicalPath -DataPath $runtimeDataPath
    $commitSiteBindings = @(Get-WebBinding -Name $SiteName)
    $committedSiteBindingEndpoints = @(Get-ValidatedSiteBindingEndpoints -Bindings $commitSiteBindings `
        -SiteName $SiteName -RequireHttps:$effectiveRequireHttps)
    $commitIisLocalState = Get-IisExactLocalState -AppLocation $appLocation -AdminLocation $adminLocation `
        -AuthenticationDefinitions $allAuthenticationSections
    if ($null -eq $iisLocalStateApplied -or
        ($commitIisLocalState | ConvertTo-Json -Depth 8 -Compress) -ne
        ($iisLocalStateApplied | ConvertTo-Json -Depth 8 -Compress)) {
        throw 'IIS local configuration changed before issuance commit.'
    }
    $commitWarmState = Get-IisAlwaysWarmState -SiteName $SiteName `
        -ApplicationPath $ApplicationPath -AppPoolName $AppPoolName `
        -ProviderName $serviceAutoStartProviderName
    if (-not (Test-IisAlwaysWarmStateEqual -First $commitWarmState -Second $iisWarmStatePreMutation)) {
        throw 'IIS always-warm configuration changed before issuance initialization.'
    }
    $commitSiteState = Get-SiteStateValue -Name $SiteName
    if ($commitSiteState -ne $installerExpectedSiteState) {
        throw "IIS site '$SiteName' changed to '$commitSiteState' before issuance commit."
    }
    foreach ($poolName in @($existingApplicationPool, $AppPoolName) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) {
        $commitPoolAssignments = @(Get-IisApplicationPoolAssignments -Name $poolName)
        $unexpectedCommitPoolAssignments = @($commitPoolAssignments |
            Where-Object { $_ -ne $targetApplicationIdentity })
        if ($unexpectedCommitPoolAssignments.Count -ne 0) {
            throw "Application pool '$poolName' acquired another assignment before issuance commit: $($unexpectedCommitPoolAssignments -join ', ')."
        }
    }
    $commitPoolSettings = Get-IisApplicationPoolSettingsSnapshot -Path $poolPath
    if ($null -eq $targetPoolAppliedSettings -or
        -not (Test-IisApplicationPoolSettingsEqual -First $commitPoolSettings -Second $targetPoolAppliedSettings)) {
        throw "Application pool '$AppPoolName' settings changed before issuance commit."
    }
    foreach ($poolName in @($installerExpectedPoolStates.Keys)) {
        $commitPoolState = Get-PoolStateValue -Name $poolName
        if ($commitPoolState -ne $installerExpectedPoolStates[$poolName] -or $commitPoolState -ne 'Stopped') {
            throw "Application pool '$poolName' is '$commitPoolState' rather than installer-owned Stopped state before issuance commit."
        }
    }
    if (-not (Test-IisApplicationMatchesSelection -Path $iisApplicationPath `
            -PhysicalPath $releasePath -ApplicationPool $AppPoolName)) {
        throw 'The target IIS application changed before issuance commit; refusing to initialize durable state.'
    }
    try {
        Initialize-IssuanceStateFromRelease -ReleasePath $releasePath -EffectiveDataPath $runtimeDataPath
        Set-OpenTimeStampDataDirectoryIssuanceInitialized -Path $runtimeDataPath `
            -ExpectedDataDirectoryId ([string]$dataInitialization.MarkerId) | Out-Null
    }
    finally {
        $issuanceMigrationCommitted = -not $issuanceStateWasAuthenticatedFormat -and
            (Test-IssuanceStateHasAuthenticatedRuntimeEvidence -EffectiveDataPath $runtimeDataPath)
    }

    # AlwaysRunning can invoke the service auto-start provider as soon as IIS
    # commits it, so enable the complete warm state only after issuance is durable.
    $activationWarmState = Get-IisAlwaysWarmState -SiteName $SiteName `
        -ApplicationPath $ApplicationPath -AppPoolName $AppPoolName `
        -ProviderName $serviceAutoStartProviderName
    if (-not (Test-IisAlwaysWarmStateEqual -First $activationWarmState -Second $iisWarmStatePreMutation)) {
        throw 'IIS always-warm configuration changed after issuance initialization.'
    }
    $activationSiteState = Get-SiteStateValue -Name $SiteName
    if ($activationSiteState -ne $installerExpectedSiteState) {
        throw "IIS site '$SiteName' changed to '$activationSiteState' before always-warm activation."
    }
    Assert-IisServiceAutoStartProviderCompatible -State $activationWarmState `
        -ProviderName $serviceAutoStartProviderName -ProviderType $serviceAutoStartProviderType
    if (-not (Test-IisApplicationMatchesSelection -Path $iisApplicationPath `
            -PhysicalPath $releasePath -ApplicationPool $AppPoolName)) {
        throw 'The target IIS application changed before always-warm activation.'
    }
    $activationPoolSettings = Get-IisApplicationPoolSettingsSnapshot -Path $poolPath
    if (-not (Test-IisApplicationPoolSettingsEqual `
            -First $activationPoolSettings -Second $targetPoolAppliedSettings)) {
        throw "Application pool '$AppPoolName' settings changed before always-warm activation."
    }
    foreach ($poolName in @($existingApplicationPool, $AppPoolName) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) {
        $activationPoolAssignments = @(Get-IisApplicationPoolAssignments -Name $poolName)
        $unexpectedActivationPoolAssignments = @($activationPoolAssignments |
            Where-Object { $_ -ne $targetApplicationIdentity })
        if ($unexpectedActivationPoolAssignments.Count -ne 0) {
            throw ("Application pool '$poolName' acquired another assignment before always-warm activation: " +
                "$($unexpectedActivationPoolAssignments -join ', ').")
        }
    }

    $iisWarmConfigurationChanged = $true
    try {
        Set-IisAlwaysWarmStateAtomic -SiteName $SiteName -ApplicationPath $ApplicationPath `
            -AppPoolName $AppPoolName -ApplicationIdentity $targetApplicationIdentity `
            -ProviderName $serviceAutoStartProviderName -ProviderType $serviceAutoStartProviderType `
            -ExpectedState $iisWarmStatePreMutation
    }
    catch {
        $warmMutationError = $_
        try {
            $observedWarmState = Get-IisAlwaysWarmState -SiteName $SiteName `
                -ApplicationPath $ApplicationPath -AppPoolName $AppPoolName `
                -ProviderName $serviceAutoStartProviderName
            if (Test-IisAlwaysWarmStateEqual -First $observedWarmState -Second $iisWarmStatePreMutation) {
                $iisWarmConfigurationChanged = $false
                $iisWarmStateApplied = $iisWarmStatePreMutation
            }
            elseif (Test-IisAlwaysWarmStateDesired -State $observedWarmState `
                    -ApplicationIdentity $targetApplicationIdentity `
                    -ProviderName $serviceAutoStartProviderName -ProviderType $serviceAutoStartProviderType) {
                $iisWarmStateApplied = $observedWarmState
            }
            else { $iisWarmStateApplied = $null }
        }
        catch { $iisWarmStateApplied = $null }
        throw $warmMutationError
    }
    $observedWarmState = Get-IisAlwaysWarmState -SiteName $SiteName `
        -ApplicationPath $ApplicationPath -AppPoolName $AppPoolName `
        -ProviderName $serviceAutoStartProviderName
    if (-not (Test-IisAlwaysWarmStateDesired -State $observedWarmState `
            -ApplicationIdentity $targetApplicationIdentity `
            -ProviderName $serviceAutoStartProviderName -ProviderType $serviceAutoStartProviderType)) {
        throw 'The atomic IIS commit did not apply the complete always-warm state.'
    }
    $iisWarmStateApplied = $observedWarmState

    # A dynamic AlwaysRunning commit may start the site or pool. Issuance is
    # safe now; retain any site activation and quiesce the dedicated pool once
    # more before deliberate startup.
    $warmSiteState = Get-SiteStateValue -Name $SiteName
    if ($warmSiteState -ne $installerExpectedSiteState -and
        $installerExpectedSiteState -eq 'Stopped' -and $warmSiteState -in @('Started', 'Starting')) {
        $installerExpectedSiteState = $warmSiteState
    }
    elseif ($warmSiteState -ne $installerExpectedSiteState) {
        throw "Always-warm configuration left IIS site '$SiteName' in unexpected state '$warmSiteState'."
    }
    $warmPoolState = Get-PoolStateValue -Name $AppPoolName
    if ($warmPoolState -ne 'Stopped') {
        if ($warmPoolState -notin @('Started', 'Starting')) {
            throw "Always-warm configuration left application pool '$AppPoolName' in unexpected state '$warmPoolState'."
        }
        $installerExpectedPoolStates[$AppPoolName] = $warmPoolState
        try {
            Stop-PoolForDeployment -Name $AppPoolName
            $installerExpectedPoolStates[$AppPoolName] = 'Stopped'
        }
        catch {
            $installerExpectedPoolStates[$AppPoolName] = Get-PoolStateValue -Name $AppPoolName
            throw
        }
    }

    if ((Get-PoolStateValue -Name $AppPoolName) -ne $installerExpectedPoolStates[$AppPoolName]) {
        throw "Application pool '$AppPoolName' changed before the committed application could be started."
    }
    try {
        Start-PoolForDeployment -Name $AppPoolName
        $installerExpectedPoolStates[$AppPoolName] = 'Started'
    }
    catch {
        $observedPoolState = Get-PoolStateValue -Name $AppPoolName
        if ($installerExpectedPoolStates[$AppPoolName] -eq 'Stopped' -and
            $observedPoolState -in @('Started', 'Starting')) {
            $installerExpectedPoolStates[$AppPoolName] = $observedPoolState
        }
        throw
    }
    if ((Get-SiteStateValue -Name $SiteName) -ne $installerExpectedSiteState) {
        throw "IIS site '$SiteName' changed before the committed application could be started."
    }
    try {
        $installerExpectedSiteState = Restore-SiteStateOptimistic -Name $SiteName `
            -DesiredState Started -ExpectedCurrentState $installerExpectedSiteState
    }
    catch {
        $observedSiteState = Get-SiteStateValue -Name $SiteName
        if ($installerExpectedSiteState -eq 'Stopped' -and $observedSiteState -in @('Started', 'Starting')) {
            $installerExpectedSiteState = $observedSiteState
        }
        throw
    }
    if ($applicationExists -and $existingApplicationPool -ne $AppPoolName) {
        $installerExpectedPoolStates[$existingApplicationPool] = Restore-PoolStateOptimistic `
            -Name $existingApplicationPool -InitialState $initialPoolStates[$existingApplicationPool] `
            -ExpectedCurrentState $installerExpectedPoolStates[$existingApplicationPool]
    }

    $deploymentSucceeded = $true
}
catch {
    $caughtError = $_
    $activationBoundaryQuiesced = $true
    if ($iisWarmConfigurationChanged) {
        $failedSiteState = Get-SiteStateValue -Name $SiteName
        if ($initialSiteState -eq 'Stopped' -and $failedSiteState -in @('Started', 'Starting', 'Stopping')) {
            try {
                $installerExpectedSiteState = $failedSiteState
                $installerExpectedSiteState = Restore-SiteStateOptimistic -Name $SiteName `
                    -DesiredState $initialSiteState -ExpectedCurrentState $installerExpectedSiteState
            }
            catch {
                $installerExpectedSiteState = Get-SiteStateValue -Name $SiteName
                Write-Warning ("Installer-initiated IIS site transition for '$SiteName' could not be restored: " +
                    $_.Exception.Message)
            }
        }
        try {
            $failedPoolState = Get-PoolStateValue -Name $AppPoolName
            if ($failedPoolState -eq 'Absent') { throw "Application pool '$AppPoolName' disappeared." }
            if ($failedPoolState -ne 'Stopped') {
                $installerExpectedPoolStates[$AppPoolName] = $failedPoolState
                Stop-PoolForDeployment -Name $AppPoolName
                $installerExpectedPoolStates[$AppPoolName] = 'Stopped'
            }
        }
        catch {
            $activationBoundaryQuiesced = $false
            $installerExpectedPoolStates[$AppPoolName] = Get-PoolStateValue -Name $AppPoolName
            Write-Warning ("Application pool '$AppPoolName' could not be quiesced after always-warm failure: " +
                $_.Exception.Message)
        }
    }
    $oldApplicationSelectionRestored = $applicationExists -and -not $applicationPointerChanged
    if ($iisWarmConfigurationChanged -and -not $issuanceMigrationCommitted) {
        $iisWarmStateRestored = $false
        if (-not $activationBoundaryQuiesced) {
            Write-Warning 'Exact IIS always-warm rollback was suppressed because activation could not be quiesced.'
        }
        elseif ($null -eq $iisWarmStateApplied -or $null -eq $iisWarmStatePreMutation) {
            Write-Warning ('IIS always-warm mutation failed before exact before/applied snapshots were captured; ' +
                'refusing a blind rollback.')
        }
        else {
            try {
                Restore-IisAlwaysWarmStateAtomic -SiteName $SiteName -ApplicationPath $ApplicationPath `
                    -AppPoolName $AppPoolName -ProviderName $serviceAutoStartProviderName `
                    -Snapshot $iisWarmStatePreMutation -ExpectedCurrentSnapshot $iisWarmStateApplied
                $iisWarmStateRestored = $true
            }
            catch { Write-Warning "Exact IIS always-warm rollback failed closed: $($_.Exception.Message)" }
        }
    }
    if ($applicationPointerChanged -and -not $issuanceMigrationCommitted -and $iisWarmStateRestored) {
        if ($newApplicationCreated) {
            try {
                $applicationPresent = Test-Path -LiteralPath $iisApplicationPath
                $selectionMatches = $applicationPresent -and
                    (Test-IisApplicationMatchesSelection -Path $iisApplicationPath `
                        -PhysicalPath $releasePath -ApplicationPool $AppPoolName)
                $virtualDirectories = if ($applicationPresent) {
                    @(Get-WebVirtualDirectory -Site $SiteName -Application $applicationName)
                }
                else { @() }
                if (Test-OpenTimeStampNewIisApplicationRollbackCandidate `
                    -ApplicationPresent $applicationPresent -SelectionMatches $selectionMatches `
                    -VirtualDirectories $virtualDirectories -ExpectedPhysicalPath $releasePath) {
                    Remove-WebApplication -Site $SiteName -Name $applicationName
                }
                else {
                    Write-Warning 'The newly created IIS application no longer matches the installer-applied selection and was preserved.'
                }
            }
            catch { Write-Warning "The new IIS application could not be removed during rollback: $($_.Exception.Message)" }
        }
        elseif ($applicationExists) {
            try {
                if (-not (Test-Path -LiteralPath $iisApplicationPath)) {
                    throw 'The target IIS application disappeared during deployment rollback.'
                }
                $currentApplication = Get-Item -LiteralPath $iisApplicationPath
                $currentPhysicalPath = Get-OpenTimeStampCanonicalDirectoryPath -Path ([string]$currentApplication.physicalPath)
                $originalPhysicalPath = Get-OpenTimeStampCanonicalDirectoryPath -Path $existingApplicationPhysicalPath
                $appliedPhysicalPath = Get-OpenTimeStampCanonicalDirectoryPath -Path $releasePath
                $physicalIsOriginal = $currentPhysicalPath.Equals($originalPhysicalPath, [System.StringComparison]::OrdinalIgnoreCase)
                $physicalIsApplied = $currentPhysicalPath.Equals($appliedPhysicalPath, [System.StringComparison]::OrdinalIgnoreCase)
                $currentPool = [string]$currentApplication.applicationPool
                $poolIsOriginal = $currentPool.Equals($existingApplicationPool, [System.StringComparison]::OrdinalIgnoreCase)
                $poolIsApplied = $currentPool.Equals($AppPoolName, [System.StringComparison]::OrdinalIgnoreCase)
                if ((-not $physicalIsOriginal -and -not $physicalIsApplied) -or
                    (-not $poolIsOriginal -and -not $poolIsApplied)) {
                    throw 'The IIS application selection changed externally after installer mutation; preserving the external values.'
                }
                if ($physicalIsApplied -and -not $physicalIsOriginal) {
                    Set-ItemProperty -LiteralPath $iisApplicationPath -Name physicalPath -Value $existingApplicationPhysicalPath
                }
                if ($poolIsApplied -and -not $poolIsOriginal) {
                    Set-ItemProperty -LiteralPath $iisApplicationPath -Name applicationPool -Value $existingApplicationPool
                }
                $oldApplicationSelectionRestored = Test-IisApplicationMatchesSelection -Path $iisApplicationPath `
                    -PhysicalPath $existingApplicationPhysicalPath -ApplicationPool $existingApplicationPool
                if (-not $oldApplicationSelectionRestored) {
                    throw 'The prior IIS application selection could not be restored and verified exactly.'
                }
            }
            catch { Write-Warning "The prior IIS application selection could not be verified: $($_.Exception.Message)" }
        }
        if ($iisConfigurationChanged) {
            $iisLocalStateRestored = $false
            if ($null -eq $iisLocalStateApplied) {
                Write-Warning 'IIS local configuration mutation failed before an exact applied snapshot was captured; refusing a blind full-snapshot rollback.'
            }
            else {
                try {
                    Restore-IisExactLocalState -Snapshot $iisLocalStateBefore `
                        -ExpectedCurrentSnapshot $iisLocalStateApplied
                    $iisLocalStateRestored = $true
                }
                catch { Write-Warning "Exact IIS local configuration rollback failed closed: $($_.Exception.Message)" }
            }
            if ($iisLocalStateRestored) {
                foreach ($locationState in @(
                    @{ Location = $adminLocation; Existed = $adminLocationExistedBefore },
                    @{ Location = $appLocation; Existed = $appLocationExistedBefore })) {
                    if (-not $locationState.Existed -and
                        @(Get-WebConfigurationLocation -Name $locationState.Location -PSPath 'IIS:\').Count -ne 0) {
                        try {
                            if (Test-IisConfigurationLocationIsEmpty -Location $locationState.Location) {
                                Remove-WebConfigurationLocation -Name $locationState.Location -PSPath 'IIS:\' -Confirm:$false
                            }
                            else {
                                Write-Warning "Installer-created IIS configuration location '$($locationState.Location)' now contains other local configuration and was preserved."
                            }
                        }
                        catch { Write-Warning "Installer-created IIS configuration location '$($locationState.Location)' could not be removed: $($_.Exception.Message)" }
                    }
                }
            }
            else {
                Write-Warning 'Installer-created IIS configuration locations were preserved because targeted local configuration was not restored exactly.'
            }
        }
    }
    elseif ($applicationPointerChanged -and -not $issuanceMigrationCommitted) {
        Write-Warning ('The IIS application selection was preserved because always-warm configuration could not ' +
            'be restored exactly.')
    }
    elseif ($applicationPointerChanged) {
        Write-Warning 'The issuance store is now OTS2. Binary rollback was suppressed because the prior release cannot safely read authenticated state; the new release remains selected.'
    }

    if (-not $applicationExists -and -not $issuanceMigrationCommitted -and $iisWarmStateRestored -and
        (Test-Path -LiteralPath $iisApplicationPath)) {
        # New-WebApplication can fail after apphost.config has been changed but
        # before the cmdlet returns, so detect and remove that partial creation.
        try {
            $selectionMatches = Test-IisApplicationMatchesSelection -Path $iisApplicationPath `
                -PhysicalPath $releasePath -ApplicationPool $AppPoolName
            $virtualDirectories =
                @(Get-WebVirtualDirectory -Site $SiteName -Application $applicationName)
            if (Test-OpenTimeStampNewIisApplicationRollbackCandidate -ApplicationPresent $true `
                -SelectionMatches $selectionMatches -VirtualDirectories $virtualDirectories `
                -ExpectedPhysicalPath $releasePath) {
                Remove-WebApplication -Site $SiteName -Name $applicationName
            }
            else {
                Write-Warning 'A partial or externally created IIS application does not match installer-applied values and was preserved.'
            }
        }
        catch { Write-Warning "A partially created IIS application could not be removed: $($_.Exception.Message)" }
    }

}
finally {
    if (-not $deploymentSucceeded) {
        $privateKeyAclRollbackVerified = $true
        if (-not $issuanceMigrationCommitted -and $null -ne $privateKeyAccessChange -and
            [bool]$privateKeyAccessChange.AclChanged) {
            try { Restore-PrivateKeyAclChange -Change $privateKeyAccessChange }
            catch {
                $privateKeyAclRollbackVerified = $false
                Write-Warning "The private-key ACL could not be restored after deployment failure: $($_.Exception.Message)"
            }
        }
        $poolSettingsRollbackVerified = $true
        if (-not $issuanceMigrationCommitted -and $targetPoolExisted -and
            $targetPoolConfigurationChanged -and $null -ne $targetPoolOriginalSettings) {
            try {
                if ($null -eq $targetPoolAppliedSettings) {
                    throw 'The installer could not capture its applied pool settings; refusing an unconditional rollback.'
                }
                $currentPoolSettings = Get-IisApplicationPoolSettingsSnapshot -Path $poolPath
                if (-not (Test-IisApplicationPoolSettingsEqual -First $currentPoolSettings -Second $targetPoolAppliedSettings)) {
                    throw "Application pool '$AppPoolName' settings changed after installer mutation; refusing to overwrite the external change."
                }
                Set-IisApplicationPoolSettingsAtomic -Name $AppPoolName `
                    -ExpectedSettings $targetPoolAppliedSettings -Settings $targetPoolOriginalSettings
                $restoredPoolSettings = Get-IisApplicationPoolSettingsSnapshot -Path $poolPath
                if (-not (Test-IisApplicationPoolSettingsEqual -First $restoredPoolSettings -Second $targetPoolOriginalSettings)) {
                    throw "Application pool '$AppPoolName' settings were not restored exactly."
                }
            }
            catch {
                $poolSettingsRollbackVerified = $false
                Write-Warning "Application pool '$AppPoolName' settings could not be restored: $($_.Exception.Message)"
            }
        }
        $newReleaseIsUnselected = ($applicationExists -and $oldApplicationSelectionRestored) -or
            (-not $applicationExists -and -not (Test-Path -LiteralPath $iisApplicationPath))
        if (-not $issuanceMigrationCommitted -and $newReleaseIsUnselected -and $releaseMoved -and
            (Test-Path -LiteralPath $releasePath)) {
            try {
                Remove-OpenTimeStampControlledDirectory -ExpectedParent $releasesPath -Path $releasePath
                $releaseMoved = $false
            }
            catch { Write-Warning "New release '$releasePath' could not be removed after rollback: $($_.Exception.Message)" }
        }

        if (-not $issuanceMigrationCommitted -and $newReleaseIsUnselected -and
            $null -ne $dataInitialization -and
            [bool]$dataInitialization.MarkerCreated) {
            try {
                $issuanceArtifactsAfter = @(Get-IssuanceStateArtifactNames -EffectiveDataPath $runtimeDataPath)
                $newIssuanceArtifacts = @($issuanceArtifactsAfter | Where-Object { $issuanceArtifactsBefore -notcontains $_ })
                $markerOwned = $false
                if (Test-Path -LiteralPath $dataInitialization.MarkerPath -PathType Leaf) {
                    $createdMarker = Get-Content -LiteralPath $dataInitialization.MarkerPath -Raw | ConvertFrom-Json
                    $markerOwned = [string]$createdMarker.Product -eq 'OpenTimeStamp' -and
                        [int]$createdMarker.SchemaVersion -eq 1 -and
                        ([string]$createdMarker.DataDirectoryId).Equals(
                            [string]$dataInitialization.MarkerId, [System.StringComparison]::OrdinalIgnoreCase) -and
                        ([string]$createdMarker.DataPath).Equals(
                            (Get-OpenTimeStampCanonicalDirectoryPath -Path $runtimeDataPath),
                            [System.StringComparison]::OrdinalIgnoreCase)
                }
                if ($markerOwned -and $newIssuanceArtifacts.Count -eq 0) {
                    Remove-Item -LiteralPath $dataInitialization.MarkerPath -Force
                }
                elseif ($markerOwned) {
                    $preserveInstallerCreatedScaffolding = $true
                    Write-Warning "The installer-created data marker was preserved because initialization left new issuance artifact(s): $($newIssuanceArtifacts -join ', ')."
                }
                else {
                    if ($dataIsDefault) { $preserveInstallerCreatedScaffolding = $true }
                    Write-Warning 'The data marker no longer matches this installer invocation and was preserved.'
                }

                if ($logDirectoryCreated -and (Test-Path -LiteralPath $logPath -PathType Container) -and
                    @(Get-ChildItem -LiteralPath $logPath -Force).Count -eq 0) {
                    Remove-Item -LiteralPath $logPath -Force
                }
                if ([bool]$dataInitialization.DirectoryCreated -and
                    (Test-Path -LiteralPath $runtimeDataPath -PathType Container) -and
                    @(Get-ChildItem -LiteralPath $runtimeDataPath -Force).Count -eq 0) {
                    Remove-Item -LiteralPath $runtimeDataPath -Force
                }
            }
            catch {
                if ($dataIsDefault) { $preserveInstallerCreatedScaffolding = $true }
                Write-Warning "Installer-created data scaffolding could not be removed: $($_.Exception.Message)"
            }
        }
        if (-not $issuanceMigrationCommitted -and $newReleaseIsUnselected -and
            $dataDirectoryCreatedByInstaller -and
            (Test-Path -LiteralPath $runtimeDataPath -PathType Container) -and
            @(Get-ChildItem -LiteralPath $runtimeDataPath -Force).Count -eq 0) {
            try { Remove-Item -LiteralPath $runtimeDataPath -Force }
            catch { Write-Warning "Installer-created DataPath '$runtimeDataPath' could not be removed: $($_.Exception.Message)" }
        }

        if (-not $issuanceMigrationCommitted -and -not $preserveInstallerCreatedScaffolding -and
            $newReleaseIsUnselected -and
            $null -ne $deploymentRootMarkerInitialization -and
            [bool]$deploymentRootMarkerInitialization.Created) {
            try {
                $markerOwned = $false
                if (Test-Path -LiteralPath $deploymentRootMarkerInitialization.MarkerPath -PathType Leaf) {
                    $marker = Get-Content -LiteralPath $deploymentRootMarkerInitialization.MarkerPath -Raw | ConvertFrom-Json
                    $markerOwned = [string]$marker.Product -eq 'OpenTimeStamp' -and
                        [int]$marker.SchemaVersion -eq 1 -and
                        ([string]$marker.DeploymentId).Equals(
                            [string]$deploymentRootMarkerInitialization.MarkerId,
                            [System.StringComparison]::OrdinalIgnoreCase) -and
                        ([string]$marker.DeploymentRoot).Equals(
                            (Get-OpenTimeStampCanonicalDirectoryPath -Path $PhysicalPath),
                            [System.StringComparison]::OrdinalIgnoreCase)
                }
                if ($markerOwned) {
                    Remove-Item -LiteralPath $deploymentRootMarkerInitialization.MarkerPath -Force
                }
                else {
                    Write-Warning 'The deployment-root marker no longer matches this installer invocation and was preserved.'
                }
            }
            catch { Write-Warning "Installer-created deployment marker could not be removed: $($_.Exception.Message)" }
        }
        if (-not $issuanceMigrationCommitted -and $newReleaseIsUnselected -and
            $releasesDirectoryCreatedByInstaller -and
            (Test-Path -LiteralPath $releasesPath -PathType Container) -and
            @(Get-ChildItem -LiteralPath $releasesPath -Force).Count -eq 0) {
            try { Remove-Item -LiteralPath $releasesPath -Force }
            catch { Write-Warning "Installer-created Releases directory could not be removed: $($_.Exception.Message)" }
        }

        $dataAclRollbackVerified = $true
        if (-not $issuanceMigrationCommitted -and $null -ne $dataAclSnapshotBefore -and $dataAclChanged) {
            try {
                if ($null -eq $dataAclSnapshotApplied) {
                    throw 'The installer could not capture its applied DataPath ACL state; refusing an unconditional rollback.'
                }
                Restore-OpenTimeStampRecursiveAclSnapshot -Snapshot $dataAclSnapshotBefore `
                    -ExpectedCurrentSnapshot $dataAclSnapshotApplied
            }
            catch {
                $dataAclRollbackVerified = $false
                Write-Warning "Exact DataPath ACL rollback failed closed: $($_.Exception.Message)"
            }
        }
        $deploymentRootAclRollbackVerified = $true
        if (-not $issuanceMigrationCommitted -and $physicalPathExistedBefore -and $deploymentRootAclChanged) {
            try {
                if ($null -eq $deploymentRootAclSnapshotApplied) {
                    throw 'The installer could not capture its applied deployment-root ACL state; refusing an unconditional rollback.'
                }
                Restore-OpenTimeStampRecursiveAclSnapshot -Snapshot $deploymentRootAclSnapshotBefore `
                    -ExpectedCurrentSnapshot $deploymentRootAclSnapshotApplied
            }
            catch {
                $deploymentRootAclRollbackVerified = $false
                Write-Warning "Exact deployment-root ACL rollback failed closed: $($_.Exception.Message)"
            }
        }
        if (-not $issuanceMigrationCommitted -and $newReleaseIsUnselected -and
            $physicalPathCreatedByInstaller -and
            (Test-Path -LiteralPath $PhysicalPath -PathType Container) -and
            @(Get-ChildItem -LiteralPath $PhysicalPath -Force).Count -eq 0) {
            try { Remove-Item -LiteralPath $PhysicalPath -Force }
            catch { Write-Warning "Installer-created deployment root could not be removed: $($_.Exception.Message)" }
        }

        # Pools remain stopped until application selection, IIS configuration,
        # release/data cleanup, and ACL restoration have all completed. If any
        # critical rollback cannot be verified, fail closed with workers stopped.
        $criticalRollbackVerified = $newReleaseIsUnselected -and
            (-not $iisConfigurationChanged -or $iisLocalStateRestored) -and
            $iisWarmStateRestored -and
            $dataAclRollbackVerified -and $deploymentRootAclRollbackVerified -and
            $privateKeyAclRollbackVerified -and $poolSettingsRollbackVerified
        if (-not $issuanceMigrationCommitted -and $criticalRollbackVerified -and $createdTargetPool -and
            (Get-PoolStateValue -Name $AppPoolName) -ne 'Absent' -and
            -not (Test-Path -LiteralPath $iisApplicationPath)) {
            try {
                $expectedOwnedSettings = if ($targetPoolConfigurationChanged) { $targetPoolAppliedSettings }
                    else { $targetPoolPreMutationSettings }
                if ($null -eq $expectedOwnedSettings -or
                    -not (Test-IisApplicationPoolSettingsEqual `
                        -First (Get-IisApplicationPoolSettingsSnapshot -Path $poolPath) `
                        -Second $expectedOwnedSettings) -or
                    (Get-PoolStateValue -Name $AppPoolName) -ne $installerExpectedPoolStates[$AppPoolName] -or
                    @(Get-IisApplicationPoolAssignments -Name $AppPoolName).Count -ne 0) {
                    throw 'The installer-created application pool changed or acquired an assignment; preserving it.'
                }
                Remove-WebAppPool -Name $AppPoolName
                $installerExpectedPoolStates[$AppPoolName] = 'Absent'
            }
            catch { Write-Warning "New application pool '$AppPoolName' could not be removed after rollback: $($_.Exception.Message)" }
        }
        if ($issuanceMigrationCommitted -or $criticalRollbackVerified) {
            try {
                $desiredSiteState = $initialSiteState
                $installerExpectedSiteState = Restore-SiteStateOptimistic -Name $SiteName `
                    -DesiredState $desiredSiteState -ExpectedCurrentState $installerExpectedSiteState
            }
            catch { Write-Warning "IIS site '$SiteName' could not be restored: $($_.Exception.Message)" }
            foreach ($pool in @($initialPoolStates.Keys)) {
                try {
                    if ($issuanceMigrationCommitted -and $pool -eq $AppPoolName) {
                        $installerExpectedPoolStates[$pool] = Restore-PoolStateOptimistic -Name $pool `
                            -InitialState Stopped `
                            -ExpectedCurrentState $installerExpectedPoolStates[$pool]
                    }
                    else {
                        $installerExpectedPoolStates[$pool] = Restore-PoolStateOptimistic -Name $pool `
                            -InitialState $initialPoolStates[$pool] `
                            -ExpectedCurrentState $installerExpectedPoolStates[$pool]
                    }
                }
                catch { Write-Warning "Application pool '$pool' could not be restored: $($_.Exception.Message)" }
            }
        }
        else {
            Write-Warning 'Critical deployment rollback was not verified; all involved application pools remain stopped.'
        }
    }

    if ($stageOwnedByInstaller -and (Test-Path -LiteralPath $stagePath)) {
        try { Remove-OpenTimeStampControlledDirectory -ExpectedParent $deploymentParent -Path $stagePath }
        catch { Write-Warning "Release staging directory '$stagePath' could not be removed: $($_.Exception.Message)" }
    }
    if (-not $deploymentSucceeded -and -not $issuanceMigrationCommitted -and
        $deploymentParentCreatedByInstaller -and
        (Test-Path -LiteralPath $deploymentParent -PathType Container) -and
        @(Get-ChildItem -LiteralPath $deploymentParent -Force).Count -eq 0) {
        try { Remove-Item -LiteralPath $deploymentParent -Force }
        catch { Write-Warning "Installer-created deployment parent '$deploymentParent' could not be removed: $($_.Exception.Message)" }
    }
}

if ($null -ne $caughtError) {
    throw $caughtError
}

$removedReleases = @()
try {
    $removedReleases = @(Remove-OpenTimeStampObsoleteReleases -ReleasesPath $releasesPath `
        -ActiveReleasePath $releasePath -RetainCount $RetainReleases)
}
catch { Write-Warning "Release retention could not be completed: $($_.Exception.Message)" }

$resultEndpoint = if ($effectiveRequireHttps) {
    $committedSiteBindingEndpoints | Where-Object Scheme -EQ 'https' | Select-Object -First 1
}
else {
    $selected = $committedSiteBindingEndpoints | Where-Object Scheme -EQ 'http' | Select-Object -First 1
    if ($null -eq $selected) {
        $selected = $committedSiteBindingEndpoints | Where-Object Scheme -EQ 'https' | Select-Object -First 1
    }
    $selected
}
$scheme = $resultEndpoint.Scheme
[PSCustomObject]@{
    Application = "$SiteName$ApplicationPath"
    ApplicationPool = $AppPoolName
    DeploymentRoot = $PhysicalPath
    ActiveReleasePath = $releasePath
    ReleaseId = [string]$manifest.ReleaseId
    ManifestSignerThumbprint = if ($null -eq $manifestSignature) { $null } else { $manifestSignature.SignerThumbprint }
    RemovedReleaseCount = $removedReleases.Count
    DataPath = $runtimeDataPath
    AuthenticationMode = $AuthenticationMode
    AlwaysWarm = $true
    AdminHostNames = $effectiveAdminHostNames -join ','
    Rfc3161Path = "$ApplicationPath/timestamp/rfc3161"
    AuthenticodePath = "$ApplicationPath/timestamp/authenticode"
    AdminPath = "$ApplicationPath/admin"
    HealthPath = "$ApplicationPath/health"
    Scheme = $scheme
    BaseUrl = $resultEndpoint.BaseUrl.TrimEnd('/') + $ApplicationPath
}
}
finally {
    Exit-OpenTimeStampDeploymentLock -Lock $deploymentLock
}
