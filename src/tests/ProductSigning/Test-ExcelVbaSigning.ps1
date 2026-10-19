#Requires -PSEdition Core
#Requires -Version 7.6

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][string]$CertificateThumbprint,
    [Parameter(Mandatory)][uri]$Rfc3161Url,
    [switch]$AllowUntrustedRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProductSigning.Common.ps1')

$testName = 'Excel VBA project signature'
if (-not (Get-ApplicationPath -ExecutableName 'EXCEL.EXE')) {
    return New-ProductTestResult -Name $testName -Status Skipped -Detail 'Microsoft Excel is not installed.'
}
if (Get-Process -Name 'EXCEL' -ErrorAction SilentlyContinue) {
    return New-ProductTestResult -Name $testName -Status Skipped `
        -Detail 'Excel is already running. Close it before testing temporary VBA security settings.'
}
$signToolPath = Get-SignToolPath -Architecture x86
if (-not $signToolPath) {
    return New-ProductTestResult -Name $testName -Status Skipped `
        -Detail 'The x86 Windows SDK SignTool required by the Office VBA SIP is not installed.'
}
if (-not (Test-OfficeVbaSipInstalled)) {
    return New-ProductTestResult -Name $testName -Status Skipped `
        -Detail 'The Microsoft Office Subject Interface Package for VBA projects is not registered.'
}

$probe = $null
try {
    $probe = New-Object -ComObject Excel.Application
    $officeVersion = [string]$probe.Version
}
finally {
    if ($probe) { $probe.Quit() }
    Release-ComObject $probe
}

$policyPath = "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\$officeVersion\Excel\Security"
$policyKey = Get-Item -LiteralPath $policyPath -ErrorAction SilentlyContinue
$accessVbomBlocked = $policyKey -and $policyKey.GetValueNames() -contains 'AccessVBOM' -and
    [int]$policyKey.GetValue('AccessVBOM') -eq 0
if ($accessVbomBlocked) {
    return New-ProductTestResult -Name $testName -Status Skipped `
        -Detail 'Group Policy blocks programmatic access to the Excel VBA project object model.'
}

$securityPath = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Office\$officeVersion\Excel\Security"
$registrySnapshot = Save-RegistryValues -Path $securityPath -Names @('AccessVBOM')
$excel = $null
$workbooks = $null
$workbook = $null
$worksheets = $null
$sheet = $null
$cells = $null
$cell = $null
$project = $null
$components = $null
$component = $null
$module = $null
$verificationWorkbook = $null
$artifactPath = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) 'Excel-VBA-Signed.xlsm'
$result = $null
$testFailure = $null
$cleanupFailures = [System.Collections.Generic.List[Exception]]::new()

try {
    Set-RegistryDword -Path $securityPath -Name 'AccessVBOM' -Value 1 -Snapshot $registrySnapshot
    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $excel.DisplayAlerts = $false
    $excel.AutomationSecurity = 3
    $workbooks = $excel.Workbooks
    $workbook = $workbooks.Add()
    $worksheets = $workbook.Worksheets
    $sheet = $worksheets.Item(1)
    $cells = $sheet.Cells
    $cell = $cells.Item(1, 1)
    $cell.Value2 = 'OpenTimeStamp Excel VBA signing test'
    Release-ComObject $cell
    $cell = $cells.Item(2, 1)
    $cell.Value2 = [DateTime]::UtcNow.ToString('O')
    Release-ComObject $cell
    Release-ComObject $cells
    Release-ComObject $worksheets
    Release-ComObject $workbooks
    $cell = $null
    $cells = $null
    $worksheets = $null
    $workbooks = $null
    $project = $workbook.VBProject
    $project.Name = 'OpenTimeStampSigningTest'
    $components = $project.VBComponents
    $component = $components.Add(1)
    Release-ComObject $components
    $components = $null
    $component.Name = 'TimestampTest'
    $module = $component.CodeModule
    $module.AddFromString(@'
Option Explicit

Public Function OpenTimeStampSignatureTest() As String
    OpenTimeStampSignatureTest = "VBA project loaded"
End Function
'@)
    $workbook.SaveAs($artifactPath, 52)
    $workbook.Close($false)
    $excel.Quit()
    Release-ComObject $module
    Release-ComObject $component
    Release-ComObject $project
    Release-ComObject $sheet
    Release-ComObject $workbook
    Release-ComObject $excel
    $module = $null
    $component = $null
    $project = $null
    $sheet = $null
    $workbook = $null
    $excel = $null

    $signOutput = Invoke-SignToolSign -SignToolPath $signToolPath -Path $artifactPath `
        -CertificateThumbprint $CertificateThumbprint -TimestampUrl $Rfc3161Url
    $verifyOutput = Invoke-SignToolVerify -SignToolPath $signToolPath -Path $artifactPath `
        -AllowUntrustedRoot:$AllowUntrustedRoot

    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $excel.DisplayAlerts = $false
    $excel.AutomationSecurity = 3
    $workbooks = $excel.Workbooks
    $verificationWorkbook = $workbooks.Open($artifactPath, 0, $true)
    Release-ComObject $workbooks
    $workbooks = $null
    Assert-Condition ([bool]$verificationWorkbook.VBASigned) 'Excel did not recognize the VBA project signature.'
    $verificationWorkbook.Close($false)
    $excel.Quit()

    $result = New-ProductTestResult -Name $testName -Status Passed -Artifact $artifactPath `
        -Detail 'Excel recognized the signed VBA project, and x86 SignTool validated its RFC 3161 signature.'
}
catch { $testFailure = $_ }
finally {
    if ($verificationWorkbook) {
        try { $verificationWorkbook.Close($false) }
        catch {
            $cleanupFailures.Add([InvalidOperationException]::new(
                'The verification Excel workbook could not be closed during cleanup.', $_.Exception))
        }
    }
    if ($workbook) {
        try { $workbook.Close($false) }
        catch {
            $cleanupFailures.Add([InvalidOperationException]::new(
                'The Excel workbook could not be closed during cleanup.', $_.Exception))
        }
    }
    if ($excel) {
        try { $excel.Quit() }
        catch {
            $cleanupFailures.Add([InvalidOperationException]::new(
                'Excel could not be stopped during cleanup.', $_.Exception))
        }
    }
    foreach ($entry in @(
            [pscustomobject]@{ Name = 'verification workbook'; Value = $verificationWorkbook },
            [pscustomobject]@{ Name = 'VBA module'; Value = $module },
            [pscustomobject]@{ Name = 'VBA component'; Value = $component },
            [pscustomobject]@{ Name = 'VBA components'; Value = $components },
            [pscustomobject]@{ Name = 'VBA project'; Value = $project },
            [pscustomobject]@{ Name = 'cell'; Value = $cell },
            [pscustomobject]@{ Name = 'cells'; Value = $cells },
            [pscustomobject]@{ Name = 'worksheet'; Value = $sheet },
            [pscustomobject]@{ Name = 'worksheets'; Value = $worksheets },
            [pscustomobject]@{ Name = 'workbook'; Value = $workbook },
            [pscustomobject]@{ Name = 'workbooks'; Value = $workbooks },
            [pscustomobject]@{ Name = 'application'; Value = $excel })) {
        try { Release-ComObject $entry.Value }
        catch {
            $cleanupFailures.Add([InvalidOperationException]::new(
                "The Excel $($entry.Name) COM reference could not be released.", $_.Exception))
        }
    }
    try { Restore-RegistryValues -Snapshot $registrySnapshot }
    catch {
        $cleanupFailures.Add([InvalidOperationException]::new(
            'The temporary Excel registry settings could not be restored.', $_.Exception))
    }
    try {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
    catch {
        $cleanupFailures.Add([InvalidOperationException]::new(
            'Pending Excel COM finalizers could not be drained.', $_.Exception))
    }
}

if ($testFailure) {
    if ($cleanupFailures.Count -ne 0) {
        $failures = [System.Collections.Generic.List[Exception]]::new()
        $failures.Add($testFailure.Exception)
        foreach ($failure in $cleanupFailures) { $failures.Add($failure) }
        throw [AggregateException]::new(
            'Excel signing failed and one or more cleanup operations also failed.', $failures)
    }
    throw $testFailure
}
if ($cleanupFailures.Count -ne 0) {
    throw [AggregateException]::new('Excel signing cleanup failed.', $cleanupFailures)
}

$result
