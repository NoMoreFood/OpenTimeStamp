#Requires -Version 5.1

[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$MsiPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$installer = New-Object -ComObject WindowsInstaller.Installer
$installer.UILevel = 2
$package = $installer.OpenPackage((Resolve-Path -LiteralPath $MsiPath).Path, 0)
$database = $package.GetType().InvokeMember('Database', 'GetProperty', $null, $package, $null)
$fixtureName = "OpenTimeStamp Picker O'Brien " + [guid]::NewGuid().ToString('N')
$createdSites = @()
$otherSiteName = $fixtureName + ' Other'

function Get-PickerValues {
    param([ValidateSet('IISSITENAME', 'APPLICATIONNAME')][string]$Property = 'IISSITENAME')
    $view = $database.OpenView(('SELECT `Value` FROM `ComboBox` WHERE `Property` = ''{0}''' -f $Property))
    try {
        [void]$view.Execute()
        while ($row = $view.Fetch()) { $row.StringData(1) }
    }
    finally { [void]$view.Close() }
}

function Invoke-Picker {
    param([ValidateSet('LoadIisWebsites', 'LoadIisApplications')][string]$Action = 'LoadIisWebsites')
    if ($package.DoAction($Action) -ne 1) { throw "The picker action '$Action' failed." }
}

try {
    $administrationAssembly = Join-Path $env:WINDIR 'System32\inetsrv\Microsoft.Web.Administration.dll'
    if (-not (Test-Path -LiteralPath $administrationAssembly)) {
        Invoke-Picker
        if ($package.Property('IISSITESAVAILABLE') -or $package.Property('IISSITENAME') -or
            @(Get-PickerValues).Count -or $package.Property('IISSITESTATUS') -notlike 'Could not list*') {
            throw 'Unavailable IIS did not clear the selection and report an error.'
        }
        Write-Host 'PASS unavailable IIS clears the list and disables selection'
        $package.Property('APPLICATIONNAME') = 'NewApplication'
        Invoke-Picker LoadIisApplications
        if ($package.Property('IISAPPLICATIONSAVAILABLE') -or @(Get-PickerValues APPLICATIONNAME).Count -or
            $package.Property('APPLICATIONNAME') -ne 'NewApplication' -or
            $package.Property('IISAPPLICATIONSTATUS') -notlike 'Could not list*') {
            throw 'Unavailable IIS did not clear application choices and preserve the entered name.'
        }
        Write-Host 'PASS unavailable IIS clears application choices and preserves typed names'
        return
    }

    Add-Type -Path $administrationAssembly
    $manager = [Microsoft.Web.Administration.ServerManager]::new()
    try {
        $site = $manager.Sites.Add($fixtureName, 'http', '127.0.0.1:61037:picker.invalid', $env:TEMP)
        $site.ServerAutoStart = $false
        foreach ($path in @('/Existing-One', '/Another.App', '/nested/child', '/Unsupported Name',
                '/bin', '/APP_DATA', '/web.config', '/Name.')) {
            [void]$site.Applications.Add($path, $env:TEMP)
        }
        $manager.CommitChanges()
        $createdSites += $fixtureName
        $otherSite = $manager.Sites.Add($otherSiteName, 'http', '127.0.0.1:61038:picker.invalid', $env:TEMP)
        $otherSite.ServerAutoStart = $false
        [void]$otherSite.Applications.Add('/OtherApplication', $env:TEMP)
        $manager.CommitChanges()
        $createdSites += $otherSiteName
        $expected = @($manager.Sites | ForEach-Object Name | Sort-Object)
    }
    finally { $manager.Dispose() }

    $package.Property('IISSITENAME') = $fixtureName.ToUpperInvariant()
    Invoke-Picker
    $actual = @(Get-PickerValues | Sort-Object)
    if ($package.Property('IISSITESAVAILABLE') -ne '1' -or
        $package.Property('IISSITENAME') -cne $fixtureName -or
        ($actual -join "`n") -cne ($expected -join "`n")) {
        throw 'The picker did not enumerate all sites or preserve the canonical selection.'
    }
    Write-Host 'PASS real IIS sites, stopped sites, punctuation, and saved selection'

    Invoke-Picker
    if ((@(Get-PickerValues | Sort-Object) -join "`n") -cne ($expected -join "`n")) {
        throw 'Refreshing the picker changed or duplicated its rows.'
    }
    Write-Host 'PASS refresh replaces the list without duplicate rows'

    $package.Property('APPLICATIONNAME') = 'existing-one'
    Invoke-Picker LoadIisApplications
    if ($package.Property('IISAPPLICATIONSAVAILABLE') -ne '1' -or
        $package.Property('APPLICATIONNAME') -cne 'Existing-One' -or
        (@(Get-PickerValues APPLICATIONNAME | Sort-Object) -join ',') -cne 'Another.App,Existing-One') {
        throw 'Application choices did not match the selected website and supported application names.'
    }
    Write-Host 'PASS application choices are scoped to the website and retain an existing selection'

    $package.Property('APPLICATIONNAME') = 'NewApplication'
    $package.Property('IISSITENAME') = $otherSiteName
    Invoke-Picker LoadIisApplications
    if ($package.Property('APPLICATIONNAME') -cne 'NewApplication' -or
        (@(Get-PickerValues APPLICATIONNAME) -join ',') -cne 'OtherApplication') {
        throw 'Changing websites kept stale application choices or lost the typed name.'
    }
    Write-Host 'PASS changing websites refreshes application choices and preserves new names'

    $manager = [Microsoft.Web.Administration.ServerManager]::new()
    try {
        $site = $manager.Sites[$otherSiteName]
        $site.Applications.Remove($site.Applications['/OtherApplication'])
        $manager.CommitChanges()
    }
    finally { $manager.Dispose() }
    Invoke-Picker LoadIisApplications
    if ($package.Property('IISAPPLICATIONSAVAILABLE') -ne '1' -or
        @(Get-PickerValues APPLICATIONNAME).Count -or $package.Property('APPLICATIONNAME') -cne 'NewApplication') {
        throw 'A website with no named applications did not allow a new name or retained a deleted application.'
    }
    Write-Host 'PASS a website with no named applications allows a new name'

    $package.Property('IISSITENAME') = $fixtureName
    Invoke-Picker LoadIisApplications
    $manager = [Microsoft.Web.Administration.ServerManager]::new()
    try {
        $manager.Sites.Remove($manager.Sites[$fixtureName])
        $manager.CommitChanges()
        $createdSites = @($createdSites | Where-Object { $_ -ne $fixtureName })
    }
    finally { $manager.Dispose() }
    Invoke-Picker LoadIisApplications
    if ($package.Property('IISAPPLICATIONSAVAILABLE') -or @(Get-PickerValues APPLICATIONNAME).Count -or
        $package.Property('IISAPPLICATIONSTATUS') -notlike '*no longer exists*') {
        throw 'A deleted website retained selectable application choices.'
    }
    Write-Host 'PASS a deleted website clears application choices and blocks continuation'
    Invoke-Picker
    if ($package.Property('IISSITENAME') -or @(Get-PickerValues) -contains $fixtureName) {
        throw 'A deleted site remained selectable.'
    }
    Write-Host 'PASS deleted site clears the selection on return'
}
finally {
    foreach ($name in $createdSites) {
        $manager = [Microsoft.Web.Administration.ServerManager]::new()
        try { $manager.Sites.Remove($manager.Sites[$name]); $manager.CommitChanges() }
        finally { $manager.Dispose() }
    }
    foreach ($item in @($database, $package, $installer)) {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($item)
    }
}
