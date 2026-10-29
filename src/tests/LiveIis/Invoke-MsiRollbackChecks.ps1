#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$MsiPath,
    [Parameter(Mandatory = $true)][string]$UpgradeMsiPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_-]+$')][string]$SiteName,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -Path "$env:WINDIR\System32\inetsrv\Microsoft.Web.Administration.dll"
$MsiPath = (Resolve-Path -LiteralPath $MsiPath).Path
$UpgradeMsiPath = (Resolve-Path -LiteralPath $UpgradeMsiPath).Path
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$deploymentRoot = Join-Path $env:SystemDrive 'inetpub\OpenTimeStamp'
$cache = Join-Path $env:ProgramFiles 'OpenTimeStamp\Installer'
$installer = New-Object -ComObject WindowsInstaller.Installer

function Invoke-DatabaseCommand {
    param($Database, [string]$Sql)
    $view = $Database.OpenView($Sql)
    try { [void]$view.Execute() }
    finally { [void]$view.Close() }
}

function Get-DatabaseValue {
    param($Database, [string]$Sql)
    $view = $Database.OpenView($Sql)
    try { [void]$view.Execute(); return $view.Fetch().StringData(1) }
    finally { [void]$view.Close() }
}

function New-FailingPackage {
    param([string]$Name, [string]$Operation, [string]$Version)

    $path = Join-Path $OutputDirectory ($Name + '.msi')
    $source = if ($Version) { $UpgradeMsiPath } else { $MsiPath }
    Copy-Item -LiteralPath $source -Destination $path
    $database = $installer.OpenDatabase($path, 1)
    $product = '{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}'
    Invoke-DatabaseCommand $database "UPDATE Property SET Value = '$product' WHERE Property = 'ProductCode'"
    if ($Version) {
        Invoke-DatabaseCommand $database "UPDATE Property SET Value = '$Version' WHERE Property = 'ProductVersion'"
        foreach ($bound in @(@{ Property = 'WIX_UPGRADE_DETECTED'; Column = 3 },
                @{ Property = 'WIX_DOWNGRADE_DETECTED'; Column = 2 })) {
            $view = $database.OpenView("SELECT * FROM Upgrade WHERE ActionProperty = '$($bound.Property)'")
            try {
                [void]$view.Execute()
                $record = $view.Fetch()
                [void]$view.Modify(6, $record)
                $record.StringData($bound.Column) = $Version
                [void]$view.Modify(1, $record)
            }
            finally { [void]$view.Close() }
        }
    }
    $action = if ($Operation -eq 'Uninstall') { 'UninstallOpenTimeStamp' } else { 'InstallOpenTimeStamp' }
    $sequence = 1 + [int](Get-DatabaseValue $database (
        "SELECT Sequence FROM InstallExecuteSequence WHERE Action = '$action'"))
    $condition = if ($Operation -eq 'Uninstall') { 'REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE' }
    else { 'NOT Installed AND NOT REMOVE~="ALL"' }
    $condition += ' AND NOT SKIPROLLBACKFAILURE'
    $evidence = Join-Path $OutputDirectory ($Name + '-deferred.json')
    $failureScript = @'
$ErrorActionPreference = 'Stop'
Add-Type -Path "$env:WINDIR\System32\inetsrv\Microsoft.Web.Administration.dll"
$manager = [Microsoft.Web.Administration.ServerManager]::new()
try {
    $site = $manager.Sites['SITE_NAME']
    $app = $site.Applications['/OpenTimeStamp']
    $pool = $manager.ApplicationPools['OpenTimeStamp']
    [pscustomobject]@{
        ApplicationPresent = $null -ne $app; PoolPresent = $null -ne $pool
        Path = if ($app) { $app.VirtualDirectories['/'].PhysicalPath } else { $null }
        PoolState = if ($pool) { [string]$pool.State } else { 'Absent' }
    } | ConvertTo-Json | Set-Content -LiteralPath 'EVIDENCE_PATH'
    $site.Limits.MaxConnections = 123
    $manager.CommitChanges()
}
finally { $manager.Dispose() }
exit 37
'@
    $failureScript = $failureScript.Replace('SITE_NAME', $SiteName).Replace(
        'EVIDENCE_PATH', $evidence.Replace("'", "''"))
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($failureScript))
    $command = '"[System64Folder]WindowsPowerShell\v1.0\powershell.exe" ' +
        '-NoProfile -NonInteractive -EncodedCommand ' + $encoded
    # Type 3106 executes a deferred, elevated EXE after the actual deployment/removal has completed.
    Invoke-DatabaseCommand $database ("INSERT INTO CustomAction (Action, Type, Source, Target) " +
        "VALUES ('ForceRollbackCheck', 3106, 'TARGETDIR', '$command')")
    Invoke-DatabaseCommand $database ("INSERT INTO InstallExecuteSequence (Action, Condition, Sequence) " +
        "VALUES ('ForceRollbackCheck', '$condition', $sequence)")
    $secure = Get-DatabaseValue $database "SELECT Value FROM Property WHERE Property = 'SecureCustomProperties'"
    Invoke-DatabaseCommand $database ("UPDATE Property SET Value = '$secure;SKIPROLLBACKFAILURE' " +
        "WHERE Property = 'SecureCustomProperties'")
    $summary = $database.SummaryInformation(1)
    $summary.Property(9) = '{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}'
    [void]$summary.Persist()
    [void]$database.Commit()
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
    return [pscustomobject]@{ Path = $path; Product = $product; Evidence = $evidence }
}

function Invoke-MsiCheck {
    param([string]$Name, [string]$Arguments, [int]$ExpectedExitCode)

    $log = Join-Path $OutputDirectory ($Name + '.log')
    $process = Start-Process -FilePath "$env:WINDIR\System32\msiexec.exe" -WindowStyle Hidden -Wait -PassThru `
        -ArgumentList "$Arguments /qn /norestart /L*v `"$log`""
    if ($process.ExitCode -ne $ExpectedExitCode) {
        throw "$Name returned $($process.ExitCode), expected $ExpectedExitCode. See '$log'."
    }
}

function Get-DeploymentSnapshot {
    $manager = [Microsoft.Web.Administration.ServerManager]::new()
    try {
        [xml]$xml = Get-Content -LiteralPath "$env:WINDIR\System32\inetsrv\config\applicationHost.config" -Raw
        $site = @($xml.configuration.'system.applicationHost'.sites.site | Where-Object name -eq $SiteName)[0]
        $application = @($site.application | Where-Object path -eq '/OpenTimeStamp')
        $pool = @($xml.configuration.'system.applicationHost'.applicationPools.add |
            Where-Object name -eq 'OpenTimeStamp')
        $app = $manager.Sites[$SiteName].Applications['/OpenTimeStamp']
        $configuration = $manager.GetApplicationHostConfiguration()
        return [pscustomobject]@{
            Application = if ($application.Count) { $application[0].OuterXml } else { $null }
            Pool = if ($pool.Count) { $pool[0].OuterXml } else { $null }
            PoolState = if ($manager.ApplicationPools['OpenTimeStamp']) {
                [string]$manager.ApplicationPools['OpenTimeStamp'].State
            } else { 'Absent' }
            Path = if ($app) { $app.VirtualDirectories['/'].PhysicalPath } else { $null }
            RequestLimit = $configuration.GetSection('system.webServer/security/requestFiltering',
                "$SiteName/OpenTimeStamp").GetChildElement('requestLimits').GetAttributeValue('maxAllowedContentLength')
            ReadAhead = $configuration.GetSection('system.webServer/serverRuntime',
                "$SiteName/OpenTimeStamp").GetAttributeValue('uploadReadAheadSize')
        }
    }
    finally { $manager.Dispose() }
}

function Assert-Restored {
    param($Before, [string]$Name)

    $after = Get-DeploymentSnapshot
    if (($Before | ConvertTo-Json -Compress) -cne ($after | ConvertTo-Json -Compress)) {
        throw "$Name did not restore the complete application, pool settings, and running state."
    }
    $manager = [Microsoft.Web.Administration.ServerManager]::new()
    try {
        if ($manager.Sites[$SiteName].Limits.MaxConnections -ne 123) {
            throw "$Name overwrote an unrelated IIS change."
        }
    }
    finally { $manager.Dispose() }
    $journals = @(Get-ChildItem -LiteralPath "$env:WINDIR\Installer" -Directory -Filter 'OpenTimeStamp-*')
    if ($journals.Count) { throw "$Name left an incomplete recovery journal." }
    Write-Host "PASS $Name"
}

# This suite owns a fresh product installation; it must never adopt an existing deployment.
foreach ($path in @($deploymentRoot, $cache, 'HKLM:\Software\OpenTimeStamp\Installer', $OutputDirectory)) {
    if (Test-Path -LiteralPath $path) { throw "The disposable test environment must not already contain '$path'." }
}
$manager = [Microsoft.Web.Administration.ServerManager]::new()
try {
    if (-not $manager.Sites[$SiteName] -or $manager.Sites[$SiteName].Applications['/OpenTimeStamp'] -or
        $manager.ApplicationPools['OpenTimeStamp']) {
        throw 'Use an existing isolated site with no product application or pool.'
    }
}
finally { $manager.Dispose() }
$security = [Security.AccessControl.DirectorySecurity]::new()
$security.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
[IO.Directory]::CreateDirectory($OutputDirectory, $security) | Out-Null
$fresh = New-FailingPackage -Name 'fresh' -Operation Install
$installed = New-FailingPackage -Name 'installed' -Operation Uninstall
$sourceDatabase = $installer.OpenDatabase($MsiPath, 0)
$version = [version](Get-DatabaseValue $sourceDatabase "SELECT Value FROM Property WHERE Property = 'ProductVersion'")
$upgradeVersion = '{0}.{1}.{2}' -f $version.Major, $version.Minor, ($version.Build + 1)
$upgrade = New-FailingPackage -Name 'upgrade' -Operation Install -Version $upgradeVersion
[GC]::Collect()
[GC]::WaitForPendingFinalizers()
$before = Get-DeploymentSnapshot
Invoke-MsiCheck -Name 'rollback-disabled' -ExpectedExitCode 1603 `
    -Arguments "/i `"$($fresh.Path)`" DISABLEROLLBACK=1 IISSITENAME=$SiteName"
if (Test-Path -LiteralPath $deploymentRoot) { throw 'Disabled rollback allowed deployment.' }
Write-Host 'PASS rollback-disabled install rejected before deployment'
Invoke-MsiCheck -Name 'fresh-failure' -Arguments "/i `"$($fresh.Path)`" IISSITENAME=$SiteName" -ExpectedExitCode 1603
$evidence = Get-Content -LiteralPath $fresh.Evidence -Raw | ConvertFrom-Json
if (-not $evidence.ApplicationPresent -or $evidence.PoolState -ne 'Stopped') {
    throw 'Fresh-install failure did not execute after deployment and before startup.'
}
Assert-Restored -Before $before -Name 'fresh install rollback'
if (Test-Path -LiteralPath $deploymentRoot) { throw 'Fresh rollback left a deployment root that blocks retry.' }
New-Item -ItemType Directory -Path $deploymentRoot | Out-Null
$emptyAcl = (Get-Acl -LiteralPath $deploymentRoot).Sddl
Invoke-MsiCheck -Name 'empty-root-failure' -ExpectedExitCode 1603 `
    -Arguments "/i `"$($fresh.Path)`" IISSITENAME=$SiteName"
Assert-Restored -Before $before -Name 'empty deployment directory rollback'
if (@(Get-ChildItem -LiteralPath $deploymentRoot -Force).Count -ne 0 -or
    (Get-Acl -LiteralPath $deploymentRoot).Sddl -ne $emptyAcl) {
    throw 'Rollback did not preserve the empty directory and its ACL.'
}
Remove-Item -LiteralPath $deploymentRoot
Invoke-MsiCheck -Name 'install-success' -Arguments "/i `"$($installed.Path)`" IISSITENAME=$SiteName" -ExpectedExitCode 0

# Preserve custom configuration and real data across failed upgrades and removals.
$manager = [Microsoft.Web.Administration.ServerManager]::new()
try {
    $pool = $manager.ApplicationPools['OpenTimeStamp']
    $pool.ProcessModel.IdleTimeout = [timespan]::FromMinutes(17)
    $environment = $pool.GetChildElement('environmentVariables').GetCollection()
    $entry = $environment.CreateElement('add')
    $entry.SetAttributeValue('name', 'MSI_ROLLBACK_PROBE')
    $entry.SetAttributeValue('value', 'preserve')
    [void]$environment.Add($entry)
    $app = $manager.Sites[$SiteName].Applications['/OpenTimeStamp']
    [void]$app.VirtualDirectories.Add('/fixture', $OutputDirectory)
    $configuration = $manager.GetApplicationHostConfiguration()
    $configuration.GetSection('system.webServer/security/requestFiltering',
        "$SiteName/OpenTimeStamp").GetChildElement('requestLimits').SetAttributeValue(
            'maxAllowedContentLength', [uint32]1000000)
    $configuration.GetSection('system.webServer/serverRuntime',
        "$SiteName/OpenTimeStamp").SetAttributeValue('uploadReadAheadSize', [uint32]257)
    $manager.CommitChanges()
}
finally { $manager.Dispose() }
$before = Get-DeploymentSnapshot
if ($before.PoolState -ne 'Started') { throw 'Successful install did not start its pool.' }
$data = Join-Path $deploymentRoot 'App_Data'
$fixture = Join-Path $data 'rollback-fixture.txt'
[IO.File]::WriteAllText($fixture, 'Preserve data and explicit ACLs during MSI rollback.')
$fixtureAcl = Get-Acl -LiteralPath $fixture
$fixtureAcl.SetAccessRuleProtection($true, $true)
Set-Acl -LiteralPath $fixture -AclObject $fixtureAcl
$fixtureSddl = (Get-Acl -LiteralPath $fixture).Sddl
$statePath = Join-Path $data 'issuance.state'
$stateHash = (Get-FileHash -LiteralPath $statePath).Hash
$dataAcl = (Get-Acl -LiteralPath $data).Sddl
$webHash = (Get-FileHash -LiteralPath (Join-Path $before.Path 'Web.config')).Hash
Invoke-MsiCheck -Name 'repair' -Arguments "/fa $($installed.Product)" -ExpectedExitCode 0
Assert-Restored -Before $before -Name 'repair preserves selected release'
Invoke-MsiCheck -Name 'upgrade-failure' -ExpectedExitCode 1603 `
    -Arguments "/i `"$($upgrade.Path)`" IISSITENAME=$SiteName"
$evidence = Get-Content -LiteralPath $upgrade.Evidence -Raw | ConvertFrom-Json
if (-not $evidence.ApplicationPresent -or $evidence.Path -eq $before.Path -or $evidence.PoolState -ne 'Stopped') {
    throw 'Upgrade failure did not execute after activating the new release.'
}
Assert-Restored -Before $before -Name 'upgrade rollback'
if (Test-Path -LiteralPath $evidence.Path) { throw 'Upgrade rollback left its new release and blocks retry.' }
Remove-Item -LiteralPath $upgrade.Evidence
Invoke-MsiCheck -Name 'upgrade-retry-failure' -ExpectedExitCode 1603 `
    -Arguments "/i `"$($upgrade.Path)`" IISSITENAME=$SiteName"
if (-not (Test-Path -LiteralPath $upgrade.Evidence)) { throw 'The same upgrade package could not be retried.' }
Assert-Restored -Before $before -Name 'same-package upgrade retry rollback'
if ((Get-FileHash -LiteralPath $statePath).Hash -ne $stateHash -or (Get-Acl -LiteralPath $data).Sddl -ne $dataAcl -or
    (Get-FileHash -LiteralPath (Join-Path $before.Path 'Web.config')).Hash -ne $webHash -or
    (Get-Acl -LiteralPath $fixture).Sddl -ne $fixtureSddl) {
    throw 'Upgrade rollback changed preexisting issuance data, configuration, or data ACLs.'
}
Invoke-MsiCheck -Name 'uninstall-failure' -Arguments "/x $($installed.Product)" -ExpectedExitCode 1603
$evidence = Get-Content -LiteralPath $installed.Evidence -Raw | ConvertFrom-Json
if ($evidence.ApplicationPresent -or $evidence.PoolPresent) {
    throw 'Removal failure did not execute after IIS removal.'
}
Assert-Restored -Before $before -Name 'uninstall rollback'
$manager = [Microsoft.Web.Administration.ServerManager]::new()
try { [void]$manager.ApplicationPools['OpenTimeStamp'].Stop() }
finally { $manager.Dispose() }
for ($attempt = 0; $attempt -lt 50; $attempt++) {
    $stopped = Get-DeploymentSnapshot
    if ($stopped.PoolState -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 100
}
if ($stopped.PoolState -ne 'Stopped') { throw 'Could not stop the fixture pool.' }
Invoke-MsiCheck -Name 'stopped-uninstall-failure' -Arguments "/x $($installed.Product)" -ExpectedExitCode 1603
Assert-Restored -Before $stopped -Name 'uninstall rollback preserves a stopped pool'
Invoke-MsiCheck -Name 'uninstall-success' -ExpectedExitCode 0 `
    -Arguments "/x $($installed.Product) SKIPROLLBACKFAILURE=1"
$after = Get-DeploymentSnapshot
if ($after.Application -or $after.Pool -or (Get-FileHash -LiteralPath $statePath).Hash -ne $stateHash) {
    throw 'Successful uninstall did not remove IIS while preserving issuance data.'
}
Write-Host 'PASS successful install, upgrade rollback, repair, and uninstall preserve issuance data'
Write-Host "Evidence: $OutputDirectory. The test-created deployment data remains at '$deploymentRoot' for inspection."
