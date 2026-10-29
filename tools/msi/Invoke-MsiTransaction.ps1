#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Install', 'Uninstall', 'Rollback', 'Commit')][string]$Action,
    [Parameter(Mandatory = $true)][guid]$TransactionId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'deploy\Install-IisApplication.ps1') -LoadFunctionsOnly
if (Test-OpenTimeStampIisSharedConfigurationEnabled) {
    throw 'MSI recovery requires local IIS configuration. Disable IIS Shared Configuration before setup.'
}
Add-Type -Path (Join-Path $env:WINDIR 'System32\inetsrv\Microsoft.Web.Administration.dll')
Import-Module WebAdministration

$journalParent = Join-Path $env:WINDIR 'Installer'
$journalPath = Join-Path $journalParent ('OpenTimeStamp-' + $TransactionId.ToString('B').ToUpperInvariant())
$journalFile = Join-Path $journalPath 'transaction.xml'
$appHostPath = Join-Path $env:WINDIR 'System32\inetsrv\config\applicationHost.config'
$allAuthenticationSections = @(
    @{ Section = 'system.webServer/security/authentication/anonymousAuthentication'; Feature = $null },
    @{ Section = 'system.webServer/security/authentication/windowsAuthentication'; Feature = 'Web-Windows-Auth' },
    @{ Section = 'system.webServer/security/authentication/basicAuthentication'; Feature = 'Web-Basic-Auth' },
    @{ Section = 'system.webServer/security/authentication/digestAuthentication'; Feature = 'Web-Digest-Auth' },
    @{ Section = 'system.webServer/security/authentication/clientCertificateMappingAuthentication'; Feature = 'Web-Client-Auth' },
    @{ Section = 'system.webServer/security/authentication/iisClientCertificateMappingAuthentication'; Feature = 'Web-Cert-Auth' })

function Write-MsiJournal {
    $bytes = [Text.Encoding]::UTF8.GetBytes([Management.Automation.PSSerializer]::Serialize($transaction, 20))
    $temporary = $journalFile + '.new'
    $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::Create, [IO.FileAccess]::Write,
        [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    if ([IO.File]::Exists($journalFile)) { [IO.File]::Replace($temporary, $journalFile, [NullString]::Value) }
    else { [IO.File]::Move($temporary, $journalFile) }
}

function Read-MsiJournal {
    if (Test-Path -LiteralPath ($journalFile + '.new')) {
        try { return Import-Clixml -LiteralPath ($journalFile + '.new') }
        catch { Write-Warning 'The staged MSI journal is incomplete; using its published record.' }
    }
    return Import-Clixml -LiteralPath $journalFile
}

function Get-MsiIisScope {
    param([string]$ConfigurationPath = $appHostPath)

    $document = Read-OpenTimeStampXmlDocument -Path $ConfigurationPath
    $site = @($document.SelectNodes('/configuration/system.applicationHost/sites/site') | Where-Object {
        $_.GetAttribute('name') -eq $transaction.SiteName
    }) | Select-Object -First 1
    $application = if ($site) { @($site.SelectNodes('./application') | Where-Object {
        $_.GetAttribute('path') -eq $transaction.ApplicationPath
    }) | Select-Object -First 1 }
    $pools = @(foreach ($name in $transaction.PoolNames) {
        $node = @($document.SelectNodes('/configuration/system.applicationHost/applicationPools/add') | Where-Object {
            $_.GetAttribute('name') -eq $name
        }) | Select-Object -First 1
        [pscustomobject]@{ Name = $name; Xml = if ($node) { $node.OuterXml } else { $null } }
    })
    $locations = @(foreach ($location in @($appLocation, $adminLocation)) {
        $node = @($document.SelectNodes('/configuration/location') | Where-Object {
            $_.GetAttribute('path') -eq $location
        }) | Select-Object -First 1
        [pscustomobject]@{ Location = $location; Xml = if ($node) { $node.OuterXml } else { $null } }
    })
    return [pscustomobject]@{
        SitePresent = $null -ne $site
        Application = if ($application) { $application.OuterXml } else { $null }
        Pools = $pools; Locations = $locations
    }
}

function Test-MsiSnapshotEqual {
    param($First, $Second)
    return ($First | ConvertTo-Json -Depth 12 -Compress) -ceq ($Second | ConvertTo-Json -Depth 12 -Compress)
}

function Get-MsiComparableXml {
    param([string]$Xml)

    if (-not $Xml) { return '' }
    $document = [Xml.XmlDocument]::new()
    $document.XmlResolver = $null
    $document.LoadXml($Xml)
    # IIS may retain empty section containers when local attributes are removed.
    $nodes = @($document.SelectNodes('//*'))
    [array]::Reverse($nodes)
    foreach ($node in $nodes) {
        if ($node -ne $document.DocumentElement -and -not $node.HasAttributes -and
            -not $node.HasChildNodes -and $node.LocalName -ne 'clear') {
            [void]$node.ParentNode.RemoveChild($node)
        }
    }
    return $document.OuterXml
}

function Test-MsiScopeRecoverable {
    param($Current, [switch]$AppliedOnly)

    if ($Current.SitePresent -ne $transaction.Before.SitePresent) { return $false }
    $application = Get-MsiComparableXml $Current.Application
    if ($application -cne (Get-MsiComparableXml $transaction.Applied.Application) -and
        ($AppliedOnly -or $application -cne (Get-MsiComparableXml $transaction.Before.Application))) {
        return $false
    }
    foreach ($kind in @('Pools', 'Locations')) {
        for ($index = 0; $index -lt $Current.$kind.Count; $index++) {
            $xml = Get-MsiComparableXml $Current.$kind[$index].Xml
            if ($xml -cne (Get-MsiComparableXml $transaction.Applied.$kind[$index].Xml) -and
                ($AppliedOnly -or $xml -cne (Get-MsiComparableXml $transaction.Before.$kind[$index].Xml))) {
                return $false
            }
        }
    }
    return $true
}

function Copy-MsiIisElement {
    param($Source, $Target, [Xml.XmlElement]$Local)

    foreach ($attribute in $Local.Attributes) {
        if ($attribute.Name -like 'lock*') {
            $Target.SetMetadata($attribute.Name, $Source.GetMetadata($attribute.Name))
        }
        else {
            $value = $Source.GetAttributeValue($attribute.Name)
            $Target.SetAttributeValue($attribute.Name, $value.PSObject.BaseObject)
        }
    }
    foreach ($child in @($Local.ChildNodes | Where-Object { $_.NodeType -eq [Xml.XmlNodeType]::Element })) {
        $schema = @($Source.Schema.ChildElementSchemas | Where-Object {
            $null -ne $_ -and $_.Name -eq $child.LocalName
        })
        if ($schema.Count) {
            Copy-MsiIisElement -Source $Source.GetChildElement($child.LocalName) `
                -Target $Target.GetChildElement($child.LocalName) -Local $child
            continue
        }
        $collection = $Target.GetCollection()
        if ($child.LocalName -eq 'clear') { $collection.Clear(); continue }
        $candidates = if ($child.LocalName -eq 'remove') { $collection } else { $Source.GetCollection() }
        $matching = @($candidates | Where-Object {
            $candidate = $_
            @($candidate.Attributes | Where-Object {
                $_.Schema.IsUniqueKey -and
                    [string]$candidate.GetAttributeValue($_.Name) -ne $child.GetAttribute($_.Name)
            }).Count -eq 0
        })
        if ($matching.Count -ne 1) { throw 'An IIS collection entry cannot be restored unambiguously.' }
        if ($child.LocalName -eq 'remove') { $collection.Remove($matching[0]); continue }
        $element = $collection.CreateElement($child.LocalName)
        Copy-MsiIisElement -Source $matching[0] -Target $element -Local $child
        [void]$collection.Add($element)
    }
}

function Remove-MsiJournal {
    try { Remove-OpenTimeStampControlledDirectory -ExpectedParent $journalParent -Path $journalPath }
    catch { Write-Warning "MSI recovery files remain at '$journalPath': $($_.Exception.Message)" }
}

function Get-MsiDirectoryContents {
    param([string]$Path)

    Assert-OpenTimeStampNoReparsePoints -Root $Path
    return @(Get-ChildItem -LiteralPath $Path -Force -Recurse | Sort-Object FullName | ForEach-Object {
        [pscustomobject]@{
            Path = $_.FullName; Directory = [bool]$_.PSIsContainer
            Hash = if (-not $_.PSIsContainer) { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
        }
    })
}

$deploymentLock = Enter-OpenTimeStampDeploymentLock -Scope 'OpenTimeStamp-MachineDeployment'
try {
    if ($Action -in @('Install', 'Uninstall')) {
        if (Test-Path -LiteralPath $journalPath) {
            Assert-OpenTimeStampNoReparsePoints -Root $journalPath
            $previous = if (Test-Path -LiteralPath $journalFile) { Read-MsiJournal }
            if ($null -eq $previous -or $previous.Phase -notin @('Committed', 'RolledBack')) {
                throw "An unfinished MSI transaction requires recovery at '$journalPath'."
            }
            Remove-MsiJournal
            if (Test-Path -LiteralPath $journalPath) { throw 'The completed MSI journal could not be removed.' }
        }
        $configuration = Get-ItemProperty -LiteralPath 'HKLM:\Software\OpenTimeStamp\Installer'
        $msiSite = ([string]$configuration.SiteName).Trim()
        $msiApplication = '/' + ([string]$configuration.ApplicationName).Trim()
        if ([string]::IsNullOrWhiteSpace($msiSite) -or $msiSite.Length -gt 128 -or
            $msiSite.IndexOfAny([char[]]"`0`r`n") -ge 0 -or $msiApplication -notmatch '^/[A-Za-z0-9._-]{1,64}$') {
            throw 'The saved MSI IIS configuration is invalid.'
        }
        $appLocation = $msiSite + $msiApplication
        $adminLocation = $appLocation + '/admin'
        $defaultRoot = Join-Path $env:SystemDrive 'inetpub\OpenTimeStamp'
        $defaultRootExisted = Test-Path -LiteralPath $defaultRoot
        $defaultRootWasEmpty = $defaultRootExisted -and
            (Test-Path -LiteralPath $defaultRoot -PathType Container) -and
            @(Get-ChildItem -LiteralPath $defaultRoot -Force).Count -eq 0
        $manager = [Microsoft.Web.Administration.ServerManager]::new()
        try {
            $site = $manager.Sites[$msiSite]
            if ($null -eq $site -and $Action -eq 'Install') { throw "The IIS site '$msiSite' does not exist." }
            $sitePresent = $null -ne $site
            $application = if ($site) { $site.Applications[$msiApplication] }
            $poolNames = @('OpenTimeStamp')
            if ($application) { $poolNames += [string]$application.ApplicationPoolName }
            $poolNames = @($poolNames | Sort-Object -Unique)
            foreach ($poolName in $poolNames) {
                $others = @(Get-IisApplicationPoolAssignments -Name $poolName | Where-Object {
                    $_ -ne ($msiSite + $msiApplication)
                })
                if ($others.Count) { throw "Application pool '$poolName' is shared; MSI cannot transact it safely." }
            }
            $aclRoots = @()
            if ($Action -eq 'Install' -and $application) {
                $active = Get-OpenTimeStampCanonicalDirectoryPath `
                    -Path $application.VirtualDirectories['/'].PhysicalPath
                $parent = Split-Path -Parent $active
                $root = if ((Split-Path -Leaf $parent) -eq 'Releases') { Split-Path -Parent $parent } else { $active }
                $settings = Get-ExistingWebSettings -ApplicationPhysicalPath $active
                $data = [Environment]::ExpandEnvironmentVariables([string]$settings['DataPath'])
                if (-not $data) { $data = Join-Path $active 'App_Data' }
                elseif (-not [IO.Path]::IsPathRooted($data)) { $data = Join-Path $active $data }
                $aclRoots = @(@{ Path = $root; RootOnly = $true }, @{ Path = $data; RootOnly = $false })
            }
            elseif ($Action -eq 'Install' -and $defaultRootWasEmpty) {
                $aclRoots = @(@{ Path = $defaultRoot; RootOnly = $true })
            }
            $poolStates = @(foreach ($name in $poolNames) {
                [pscustomobject]@{ Name = $name; State = Get-PoolStateValue -Name $name }
            })
        }
        finally { $manager.Dispose() }

        # Recovery code and snapshots must survive MSI file removal and be writable only by administrators.
        Assert-OpenTimeStampNoReparsePoints -Root $journalParent -AncestryOnly
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
                'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        [IO.Directory]::CreateDirectory($journalPath, $security) | Out-Null
        [IO.Directory]::CreateDirectory((Join-Path $journalPath 'deploy')) | Out-Null
        Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $journalPath 'Invoke-MsiTransaction.ps1')
        foreach ($name in @('Deployment.Common.ps1', 'Install-IisApplication.ps1')) {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot "deploy\$name") `
                -Destination (Join-Path $journalPath "deploy\$name")
        }
        Copy-Item -LiteralPath $appHostPath -Destination (Join-Path $journalPath 'before.config')
        $transaction = [pscustomobject]@{
            Phase = 'Prepared'; Operation = $Action; SiteName = $msiSite; ApplicationPath = $msiApplication
            PoolNames = $poolNames; PoolStates = $poolStates; Before = $null; Applied = $null
            LocalBefore = if ($sitePresent) {
                Get-IisExactLocalState -AppLocation $appLocation -AdminLocation $adminLocation `
                    -AuthenticationDefinitions $allAuthenticationSections
            } else { $null }
            LocalApplied = $null; AclsBefore = @(); AclsApplied = @(); Result = $null
            CreatedRoot = $null; CreatedRootContents = @(); RootExisted = $defaultRootExisted
            CreatedRelease = $null; CreatedReleaseContents = @()
        }
        $transaction.Before = Get-MsiIisScope -ConfigurationPath (Join-Path $journalPath 'before.config')
        Write-MsiJournal
        try {
            if ($Action -eq 'Install') {
                foreach ($name in $poolNames) {
                    if ((Get-PoolStateValue -Name $name) -ne 'Absent') { Stop-PoolForDeployment -Name $name }
                }
                $transaction.AclsBefore = @(foreach ($entry in $aclRoots) {
                    if (Test-Path -LiteralPath $entry.Path -PathType Container) {
                        Get-OpenTimeStampRecursiveAclSnapshot -Path $entry.Path -RootOnly:$entry.RootOnly
                    }
                })
                Write-MsiJournal
                $transaction.Result = & (Join-Path $PSScriptRoot 'Install-Msi.ps1')
            }
            else { & (Join-Path $PSScriptRoot 'Uninstall-Msi.ps1') }
        }
        finally {
            if ((-not $defaultRootExisted -or $defaultRootWasEmpty) -and $transaction.Result -and
                $transaction.Result.DeploymentRoot -eq $defaultRoot) {
                $transaction.CreatedRoot = $defaultRoot
                $transaction.CreatedRootContents = Get-MsiDirectoryContents -Path $defaultRoot
            }
            elseif ($transaction.Result) {
                $transaction.CreatedRelease = $transaction.Result.ActiveReleasePath
                $transaction.CreatedReleaseContents = Get-MsiDirectoryContents -Path $transaction.CreatedRelease
            }
            $transaction.Applied = Get-MsiIisScope
            if ($sitePresent) {
                $transaction.LocalApplied = Get-IisExactLocalState -AppLocation $appLocation `
                    -AdminLocation $adminLocation -AuthenticationDefinitions $allAuthenticationSections
            }
            $transaction.AclsApplied = @(foreach ($snapshot in $transaction.AclsBefore) {
                if (Test-Path -LiteralPath $snapshot.Root -PathType Container) {
                    Get-OpenTimeStampRecursiveAclSnapshot -Path $snapshot.Root `
                        -RootOnly:($snapshot.Entries.Count -eq 1)
                }
            })
            $transaction.Phase = 'Applied'
            Write-MsiJournal
        }
        return
    }

    if (-not (Test-Path -LiteralPath $journalFile)) { return }
    Assert-OpenTimeStampNoReparsePoints -Root $journalPath
    $transaction = Read-MsiJournal
    $appLocation = $transaction.SiteName + $transaction.ApplicationPath
    $adminLocation = $appLocation + '/admin'
    if ($transaction.Phase -in @('Committed', 'RolledBack')) { Remove-MsiJournal; return }
    if ($null -eq $transaction.Applied) {
        throw "MSI recovery has no completed change snapshot. Preserve '$journalPath' for manual recovery."
    }
    $current = Get-MsiIisScope
    if (-not (Test-MsiScopeRecoverable $current -AppliedOnly:($Action -eq 'Commit'))) {
        throw "The target IIS configuration changed outside MSI; preserve '$journalPath' for manual recovery."
    }
    if ($Action -eq 'Commit') {
        if ($transaction.Operation -eq 'Install') {
            Start-PoolForDeployment -Name 'OpenTimeStamp'
            foreach ($state in $transaction.PoolStates | Where-Object { $_.Name -ne 'OpenTimeStamp' }) {
                if ($state.State -eq 'Started') { Start-PoolForDeployment -Name $state.Name }
            }
        }
        $transaction.Phase = 'Committed'
        Write-MsiJournal
        if ($transaction.Operation -eq 'Install') {
            try { Initialize-OpenTimeStampEventLog }
            catch { Write-Warning "Optional Event Viewer logging could not be registered: $($_.Exception.Message)" }
            try {
                Remove-OpenTimeStampObsoleteReleases `
                    -ReleasesPath (Join-Path $transaction.Result.DeploymentRoot 'Releases') `
                    -ActiveReleasePath $transaction.Result.ActiveReleasePath -RetainCount 5 | Out-Null
            }
            catch { Write-Warning "Release retention could not be completed: $($_.Exception.Message)" }
        }
        Remove-MsiJournal
        return
    }

    # Restore the target application, its dedicated pools, and owned settings; other sites stay untouched.
    foreach ($name in $transaction.PoolNames) {
        $others = @(Get-IisApplicationPoolAssignments -Name $name | Where-Object { $_ -ne $appLocation })
        if ($others.Count) { throw "Pool '$name' acquired another assignment; preserving the MSI recovery journal." }
        if ((Get-PoolStateValue -Name $name) -ne 'Absent') { Stop-PoolForDeployment -Name $name }
    }
    if ($transaction.LocalBefore) {
        $currentLocal = Get-IisExactLocalState -AppLocation $appLocation -AdminLocation $adminLocation `
            -AuthenticationDefinitions $allAuthenticationSections
        if (-not (Test-MsiSnapshotEqual $transaction.LocalBefore $currentLocal)) {
            Restore-IisExactLocalState -Snapshot $transaction.LocalBefore -ExpectedCurrentSnapshot $currentLocal
        }
    }
    foreach ($location in $transaction.Before.Locations) {
        if ($null -eq $location.Xml -and
            @(Get-WebConfigurationLocation -Name $location.Location -PSPath 'IIS:\').Count -ne 0 -and
            (Test-IisConfigurationLocationIsEmpty -Location $location.Location)) {
            Remove-WebConfigurationLocation -Name $location.Location -PSPath 'IIS:\' -Confirm:$false
        }
    }
    if ($transaction.CreatedRoot) {
        $contents = Get-MsiDirectoryContents -Path $transaction.CreatedRoot
        if (-not (Test-MsiSnapshotEqual $contents $transaction.CreatedRootContents) -or
            -not (Test-OpenTimeStampDeploymentRootMarker -Path $transaction.CreatedRoot)) {
            throw "New data changed outside MSI; preserving '$($transaction.CreatedRoot)' and its recovery journal."
        }
        if ($transaction.RootExisted) {
            foreach ($item in Get-ChildItem -LiteralPath $transaction.CreatedRoot -Force) {
                Assert-OpenTimeStampPathContained -Parent $transaction.CreatedRoot -Child $item.FullName
                Remove-Item -LiteralPath $item.FullName -Recurse -Force
            }
        }
        else {
            Remove-OpenTimeStampControlledDirectory -ExpectedParent (Split-Path -Parent $transaction.CreatedRoot) `
                -Path $transaction.CreatedRoot
        }
    }
    elseif ($transaction.CreatedRelease) {
        $contents = Get-MsiDirectoryContents -Path $transaction.CreatedRelease
        if (-not (Test-MsiSnapshotEqual $contents $transaction.CreatedReleaseContents)) {
            throw 'The new release changed outside MSI; preserving it and the recovery journal.'
        }
        Remove-OpenTimeStampControlledDirectory `
            -ExpectedParent (Join-Path $transaction.Result.DeploymentRoot 'Releases') -Path $transaction.CreatedRelease
    }
    foreach ($snapshot in $transaction.AclsBefore) {
        $applied = @($transaction.AclsApplied | Where-Object { $_.Root -eq $snapshot.Root }) | Select-Object -First 1
        $observed = Get-OpenTimeStampRecursiveAclSnapshot -Path $snapshot.Root -RootOnly:($snapshot.Entries.Count -eq 1)
        $currentEntries = @{}
        $appliedEntries = @{}
        foreach ($entry in $observed.Entries) { $currentEntries[$entry.Path] = $entry }
        if ($applied) { foreach ($entry in $applied.Entries) { $appliedEntries[$entry.Path] = $entry } }
        foreach ($entry in $snapshot.Entries) {
            $currentEntry = $currentEntries[$entry.Path]
            $appliedEntry = $appliedEntries[$entry.Path]
            if ($null -eq $currentEntry -or ($currentEntry.Sddl -cne $entry.Sddl -and
                ($null -eq $appliedEntry -or $currentEntry.Sddl -cne $appliedEntry.Sddl))) {
                throw 'A preexisting ACL changed outside MSI; preserving the recovery journal.'
            }
        }
        Restore-OpenTimeStampRecursiveAclSnapshot -Snapshot $snapshot -ExpectedCurrentSnapshot $observed
    }
    $saved = [Microsoft.Web.Administration.ServerManager]::new((Join-Path $journalPath 'before.config'))
    $manager = [Microsoft.Web.Administration.ServerManager]::new()
    try {
        $site = $manager.Sites[$transaction.SiteName]
        if ($null -eq $site -and $transaction.Before.SitePresent) {
            throw 'The target IIS site disappeared during rollback.'
        }
        $application = if ($site) { $site.Applications[$transaction.ApplicationPath] }
        if ($application) { $site.Applications.Remove($application) }
        foreach ($name in $transaction.PoolNames) {
            $pool = $manager.ApplicationPools[$name]
            if ($pool) { $manager.ApplicationPools.Remove($pool) }
            if ($saved.ApplicationPools[$name]) {
                $restoredPool = $manager.ApplicationPools.CreateElement('add')
                [xml]$local = @($transaction.Before.Pools | Where-Object Name -eq $name)[0].Xml
                Copy-MsiIisElement -Source $saved.ApplicationPools[$name] `
                    -Target $restoredPool -Local $local.DocumentElement
                [void]$manager.ApplicationPools.Add($restoredPool)
            }
        }
        $originalSite = $saved.Sites[$transaction.SiteName]
        $original = if ($originalSite) { $originalSite.Applications[$transaction.ApplicationPath] }
        if ($original) {
            $restoredApp = $site.Applications.CreateElement('application')
            [xml]$local = $transaction.Before.Application
            Copy-MsiIisElement -Source $original -Target $restoredApp -Local $local.DocumentElement
            [void]$site.Applications.Add($restoredApp)
        }
        $manager.CommitChanges()
    }
    finally { $manager.Dispose(); $saved.Dispose() }
    $restored = Get-MsiIisScope
    if ((Get-MsiComparableXml $restored.Application) -cne (Get-MsiComparableXml $transaction.Before.Application) -or
        @(for ($index = 0; $index -lt $restored.Pools.Count; $index++) {
            if ((Get-MsiComparableXml $restored.Pools[$index].Xml) -cne
                (Get-MsiComparableXml $transaction.Before.Pools[$index].Xml)) { $false }
        }).Count) {
        throw "MSI could not verify the restored IIS application and pools. Recovery files remain at '$journalPath'."
    }
    foreach ($state in $transaction.PoolStates) {
        if ($state.State -eq 'Started') { Start-PoolForDeployment -Name $state.Name }
        elseif ($state.State -eq 'Stopped') { Stop-PoolForDeployment -Name $state.Name }
    }
    $transaction.Phase = 'RolledBack'
    Write-MsiJournal
    Remove-MsiJournal
}
finally { Exit-OpenTimeStampDeploymentLock -Lock $deploymentLock }
