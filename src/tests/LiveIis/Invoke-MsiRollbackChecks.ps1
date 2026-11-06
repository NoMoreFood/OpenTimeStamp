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
$cache = Join-Path $env:ProgramFiles 'OpenTimeStamp'
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
            Bindings = $site.SelectSingleNode('./bindings').OuterXml
            Endpoints = @(Get-ItemPropertyValue -LiteralPath 'HKLM:\Software\OpenTimeStamp\Installer' `
                -Name Endpoints -ErrorAction SilentlyContinue)
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
Invoke-MsiCheck -Name 'missing-website' -ExpectedExitCode 1603 `
    -Arguments "/i `"$MsiPath`" IISSITENAME=OpenTimeStampMissingSite"
if ((Get-Content -LiteralPath (Join-Path $OutputDirectory 'missing-website.log') -Raw) -notmatch 'does not exist' -or
    (Test-Path -LiteralPath $deploymentRoot)) {
    throw 'A nonexistent website was not rejected before deployment.'
}
foreach ($path in @('/admin', '/health')) {
    Invoke-MsiCheck -Name ('invalid-route-' + $path.TrimStart('/')) -ExpectedExitCode 1603 `
        -Arguments "/i `"$MsiPath`" IISSITENAME=$SiteName RFC3161PATH=$path"
    if (Test-Path -LiteralPath $deploymentRoot) { throw 'An invalid route created a deployment root.' }
}
Write-Host 'PASS nonexistent websites and invalid route paths are rejected'
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

# Reuse a precreated application without taking ownership of its old content or shared pool.
$precreatedRoot = Join-Path $OutputDirectory 'PrecreatedApplication'
New-Item -ItemType Directory -Path $precreatedRoot | Out-Null
$originalContent = Join-Path $precreatedRoot 'original.txt'
[IO.File]::WriteAllText($originalContent, 'Preserve the existing application files.')
[IO.File]::WriteAllText((Join-Path $precreatedRoot 'web.config'),
    '<configuration><appSettings><add key="AuthenticationMode" value="UnrelatedApplication" /></appSettings></configuration>')
$originalHash = (Get-FileHash -LiteralPath $originalContent).Hash
$originalAcl = (Get-Acl -LiteralPath $precreatedRoot).Sddl
$manager = [Microsoft.Web.Administration.ServerManager]::new()
try {
    $precreated = $manager.Sites[$SiteName].Applications.Add('/OpenTimeStamp', $precreatedRoot)
    $precreated.ApplicationPoolName = 'DefaultAppPool'
    [void]$precreated.VirtualDirectories.Add('/existing', $precreatedRoot)
    $sharedPoolState = [string]$manager.ApplicationPools['DefaultAppPool'].State
    $manager.CommitChanges()
}
finally { $manager.Dispose() }
$before = Get-DeploymentSnapshot
Invoke-MsiCheck -Name 'existing-application-failure' -ExpectedExitCode 1603 `
    -Arguments "/i `"$($fresh.Path)`" IISSITENAME=$SiteName"
$evidence = Get-Content -LiteralPath $fresh.Evidence -Raw | ConvertFrom-Json
if (-not $evidence.ApplicationPresent -or $evidence.Path -eq $precreatedRoot) {
    throw 'Existing-application failure did not execute after deploying into the reused application.'
}
Assert-Restored -Before $before -Name 'existing application rollback'
if (Test-Path -LiteralPath $deploymentRoot) { throw 'Existing-application rollback left a deployment root.' }
Write-Host 'PASS existing application rollback restores its original selection and virtual directories'

Invoke-MsiCheck -Name 'install-success' -ExpectedExitCode 0 -Arguments (
    "/i `"$($installed.Path)`" IISSITENAME=$SiteName TIMESTAMPPATH=/sign/auto " +
    'RFC3161PATH=/sign/rfc AUTHENTICODEPATH=/sign/legacy HEALTHPATH=/status')

# Exercise the installed routes and links against each configured binding before adding rollback fixtures.
$configuration = Get-ItemProperty -LiteralPath 'HKLM:\Software\OpenTimeStamp\Installer'
$links = @($configuration.Endpoints)
$manager = [Microsoft.Web.Administration.ServerManager]::new()
try {
    $site = $manager.Sites[$SiteName]
    if ($links.Count -ne $site.Bindings.Count * 6) { throw 'Completion URLs omit a route or binding.' }
    $activePath = $site.Applications['/OpenTimeStamp'].VirtualDirectories['/'].PhysicalPath
    if ($site.Applications['/OpenTimeStamp'].VirtualDirectories['/existing'].PhysicalPath -ne $precreatedRoot -or
        [string]$manager.ApplicationPools['DefaultAppPool'].State -ne $sharedPoolState -or
        (Get-FileHash -LiteralPath $originalContent).Hash -ne $originalHash -or
        (Get-Acl -LiteralPath $precreatedRoot).Sddl -ne $originalAcl) {
        throw 'Reusing the application changed its old content, virtual directories, or shared pool state.'
    }
    [xml]$webConfig = Get-Content -LiteralPath (Join-Path $activePath 'Web.config') -Raw
    $settings = @{}
    foreach ($setting in $webConfig.configuration.appSettings.add) { $settings[$setting.key] = $setting.value }
    if ($settings.Rfc3161Path -ne '/sign/rfc' -or $settings.AuthenticodePath -ne '/sign/legacy' -or
        $settings.TimestampPath -ne '/sign/auto' -or $settings.HealthPath -ne '/status') {
        throw 'Setup did not persist the chosen public routes.'
    }
}
finally { $manager.Dispose() }
$localAddresses = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | ForEach-Object {
    $_.GetIPProperties().UnicastAddresses | ForEach-Object { $_.Address.ToString() }
})
foreach ($link in $links) {
    $parts = ([string]$link).Split('|', 2)
    $url = [uri]$parts[1]
    $addresses = @([Net.Dns]::GetHostAddresses($url.DnsSafeHost))
    if (-not $addresses.Count -or @($addresses | Where-Object {
        -not [Net.IPAddress]::IsLoopback($_) -and $_.ToString() -notin $localAddresses
    }).Count) { throw "Live MSI checks require URLs resolving only to this server: $url" }
    $request = [Net.HttpWebRequest]::Create($url)
    $request.Proxy = $null
    $request.UseDefaultCredentials = $parts[0] -eq 'Administration'
    $request.Timeout = 30000
    $response = $null
    try {
        try { $response = $request.GetResponse() }
        catch [Net.WebException] { $response = $_.Exception.Response; if (-not $response) { throw } }
        $expected = switch ($parts[0]) {
            'Service Home' { 200 }
            'Administration' { 200 }
            'Service Health' { 503 }
            default { 405 }
        }
        if ([int]$response.StatusCode -ne $expected) {
            throw "$link returned $([int]$response.StatusCode), expected $expected."
        }
    }
    finally { if ($response) { $response.Dispose() } }
}
$shortcutPath = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'OpenTimeStamp Administration.lnk'
if (-not (Test-Path -LiteralPath $shortcutPath) -or (Test-Path -LiteralPath (Join-Path $cache 'Installer'))) {
    throw 'The admin shortcut is missing or the program files retain an Installer subfolder.'
}
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
if ($shortcut.Arguments -notlike '*Open-OpenTimeStamp.ps1* -Admin' -or
    $shortcut.TargetPath -notlike '*\powershell.exe') {
    throw 'The Start menu shortcut does not launch the admin interface.'
}
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut)
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
Write-Host 'PASS application reuse, custom routes, all binding URLs, local admin links, and Start menu shortcut'

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
if ((Test-Path -LiteralPath $shortcutPath) -or $after.Endpoints.Count -ne 0) {
    throw 'Uninstall left the admin shortcut or endpoint URLs behind.'
}
Write-Host 'PASS successful install, upgrade rollback, repair, and uninstall preserve issuance data'

# Reinstall the same package over retained data, including failure after activation and a subsequent retry.
$uninstalled = $after
$rootAcl = (Get-Acl -LiteralPath $deploymentRoot).Sddl
$reinstallArguments = "IISSITENAME=$SiteName TIMESTAMPPATH=/sign/auto RFC3161PATH=/sign/rfc " +
    'AUTHENTICODEPATH=/sign/legacy HEALTHPATH=/status'
Invoke-MsiCheck -Name 'reinstall-failure' -ExpectedExitCode 1603 `
    -Arguments "/i `"$($fresh.Path)`" $reinstallArguments"
$evidence = Get-Content -LiteralPath $fresh.Evidence -Raw | ConvertFrom-Json
if (-not $evidence.ApplicationPresent -or $evidence.Path -eq $before.Path -or
    (Test-Path -LiteralPath $evidence.Path)) {
    throw 'Failed reinstall did not activate and roll back a fresh release.'
}
Assert-Restored -Before $uninstalled -Name 'reinstall rollback'
if ((Get-FileHash -LiteralPath $statePath).Hash -ne $stateHash -or
    (Get-FileHash -LiteralPath (Join-Path $before.Path 'Web.config')).Hash -ne $webHash -or
    (Get-Acl -LiteralPath $data).Sddl -ne $dataAcl -or
    (Get-Acl -LiteralPath $fixture).Sddl -ne $fixtureSddl -or
    (Get-Acl -LiteralPath $deploymentRoot).Sddl -ne $rootAcl) {
    throw 'Failed reinstall changed retained state, configuration, or ACLs.'
}
Invoke-MsiCheck -Name 'reinstall-success' -ExpectedExitCode 0 `
    -Arguments "/i `"$($installed.Path)`" $reinstallArguments"
$reinstalled = Get-DeploymentSnapshot
if (-not $reinstalled.Application -or $reinstalled.PoolState -ne 'Started' -or
    $reinstalled.Path -eq $before.Path -or (Get-FileHash -LiteralPath $statePath).Hash -ne $stateHash -or
    (Get-FileHash -LiteralPath (Join-Path $before.Path 'Web.config')).Hash -ne $webHash) {
    throw 'Reinstall did not preserve retained state while activating a fresh release.'
}
[xml]$reinstalledConfig = Get-Content -LiteralPath (Join-Path $reinstalled.Path 'Web.config') -Raw
$restoredMode = $reinstalledConfig.SelectSingleNode('/configuration/appSettings/add[@key="AuthenticationMode"]')
$restoredData = $reinstalledConfig.SelectSingleNode('/configuration/appSettings/add[@key="DataPath"]')
if ($restoredMode.GetAttribute('value') -ne $settings.AuthenticationMode -or
    $restoredData.GetAttribute('value') -ne $data) {
    throw 'Reinstall changed the saved authentication mode or data path.'
}
Invoke-MsiCheck -Name 'reinstall-uninstall' -ExpectedExitCode 0 `
    -Arguments "/x $($installed.Product) SKIPROLLBACKFAILURE=1"
Write-Host 'PASS same-package reinstall, failed reinstall rollback, and retry preserve retained state and settings'
Write-Host "Evidence: $OutputDirectory. The test-created deployment data remains at '$deploymentRoot' for inspection."
