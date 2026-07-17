#Requires -PSEdition Core
#Requires -Version 7.6

[CmdletBinding()]
param(
    [uri]$Rfc3161Url = 'http://localhost/OpenTimeStamp/timestamp/rfc3161',

    [uri]$AuthenticodeUrl = 'http://localhost/OpenTimeStamp/timestamp/authenticode',

    [string]$OutputDirectory = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) `
        'artifacts\ProductSigningTests'),

    [string]$CertificateThumbprint,

    [string]$TsaCertificatePath,

    [ValidateSet('PowerShell', 'Exe', 'ExcelVba', 'Pdf', 'Word')]
    [string[]]$Tests = @('PowerShell', 'Exe', 'ExcelVba', 'Pdf', 'Word'),

    [switch]$NonInteractive,

    [Alias('Strict')]
    [switch]$RequireAllSelectedTests,

    [switch]$KeepTestCertificate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProductSigning.Common.ps1')

if (-not $IsWindows) { throw 'The product signing tests require Windows.' }
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) {
    throw 'The product signing tests require an STA host. Use its Run-Tests.cmd or invoke pwsh with -STA.'
}
Assert-Condition $Rfc3161Url.IsAbsoluteUri 'Rfc3161Url must be an absolute URI.'
Assert-Condition $AuthenticodeUrl.IsAbsoluteUri 'AuthenticodeUrl must be an absolute URI.'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ([string]::IsNullOrWhiteSpace($TsaCertificatePath)) {
    $developmentTsaCertificate = Join-Path $repositoryRoot 'artifacts\OpenTimeStamp-development.cer'
    if (Test-Path -LiteralPath $developmentTsaCertificate -PathType Leaf) {
        $TsaCertificatePath = $developmentTsaCertificate
    }
}

$runName = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$runOutputDirectory = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) $runName
New-Item -ItemType Directory -Path $runOutputDirectory -Force | Out-Null
$results = [System.Collections.Generic.List[object]]::new()
$certificateContext = $null
$fipsPolicy = $false

$healthBuilder = [UriBuilder]::new($Rfc3161Url)
if ($healthBuilder.Path -match '/timestamp/rfc3161/?$') {
    $healthBuilder.Path = $healthBuilder.Path -replace '/timestamp/rfc3161/?$', '/health'
    try {
        $health = Invoke-RestMethod -Uri $healthBuilder.Uri -TimeoutSec 10
        $fipsProperty = $health.PSObject.Properties['fipsPolicy']
        if ($fipsProperty) { $fipsPolicy = [bool]$fipsProperty.Value }
        Write-Host "OpenTimeStamp health: $($health.status); FIPS policy: $fipsPolicy"
    }
    catch {
        Write-Warning "The health endpoint could not be read: $($_.Exception.Message)"
    }
}

Write-Host "Product signing artifacts: $runOutputDirectory"
try {
    $certificateContext = & (Join-Path $PSScriptRoot 'New-TestSigningCertificate.ps1') `
        -OutputDirectory $runOutputDirectory -CertificateThumbprint $CertificateThumbprint `
        -TsaCertificatePath $TsaCertificatePath
    Write-Host "Signing certificate: $($certificateContext.Subject) [$($certificateContext.Thumbprint)]"

    $testDefinitions = @(
        [pscustomobject]@{
            Key = 'PowerShell'
            Path = 'Test-PowerShellSigning.ps1'
            Parameters = @{
                OutputDirectory = $runOutputDirectory
                CertificateThumbprint = $certificateContext.Thumbprint
                AuthenticodeUrl = $AuthenticodeUrl
                ExpectedTsaThumbprint = $certificateContext.ExpectedTsaThumbprint
                AllowUntrustedRoot = $certificateContext.OwnedSigningCertificate
            }
        },
        [pscustomobject]@{
            Key = 'Exe'
            Path = 'Test-ExeSigning.ps1'
            Parameters = @{
                OutputDirectory = $runOutputDirectory
                CertificateThumbprint = $certificateContext.Thumbprint
                Rfc3161Url = $Rfc3161Url
                ExpectedTsaThumbprint = $certificateContext.ExpectedTsaThumbprint
                AllowUntrustedRoot = $certificateContext.OwnedSigningCertificate
            }
        },
        [pscustomobject]@{
            Key = 'ExcelVba'
            Path = 'Test-ExcelVbaSigning.ps1'
            Parameters = @{
                OutputDirectory = $runOutputDirectory
                CertificateThumbprint = $certificateContext.Thumbprint
                Rfc3161Url = $Rfc3161Url
                AllowUntrustedRoot = $certificateContext.OwnedSigningCertificate
            }
        },
        [pscustomobject]@{
            Key = 'Pdf'
            Path = 'Test-PdfSigning.ps1'
            Parameters = @{
                OutputDirectory = $runOutputDirectory
                CertificateThumbprint = $certificateContext.Thumbprint
                Rfc3161Url = $Rfc3161Url
                PfxPath = $certificateContext.PfxPath
                PfxPassword = $certificateContext.PfxPassword
                ExpectedTsaThumbprint = $certificateContext.ExpectedTsaThumbprint
            }
        },
        [pscustomobject]@{
            Key = 'Word'
            Path = 'Test-WordDocumentSigning.ps1'
            Parameters = @{
                OutputDirectory = $runOutputDirectory
                CertificateThumbprint = $certificateContext.Thumbprint
                Rfc3161Url = $Rfc3161Url
                ExpectedTsaThumbprint = $certificateContext.ExpectedTsaThumbprint
                NonInteractive = $NonInteractive
            }
        }
    )

    foreach ($definition in $testDefinitions) {
        if ($definition.Key -notin $Tests) { continue }
        Write-Host "RUN  $($definition.Key)"
        if ($definition.Key -eq 'PowerShell' -and $fipsPolicy) {
            $result = New-ProductTestResult -Name 'PowerShell script signature' -Status Skipped `
                -Detail 'Windows FIPS policy disables the legacy Authenticode timestamp endpoint.'
        }
        else {
            try {
                $parameters = $definition.Parameters
                $testOutput = @(& (Join-Path $PSScriptRoot $definition.Path) @parameters)
                $resultCandidates = @($testOutput | Where-Object {
                    $_ -and $_.PSObject.Properties['Status'] -and $_.PSObject.Properties['Name']
                })
                Assert-Condition ($resultCandidates.Count -eq 1) `
                    "Test '$($definition.Key)' returned $($resultCandidates.Count) results instead of one."
                $result = $resultCandidates[0]
            }
            catch {
                $result = [pscustomobject]@{
                    Name = $definition.Key
                    Status = 'Failed'
                    Artifact = $null
                    Detail = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
                }
            }
        }

        $results.Add($result)
        $color = switch ($result.Status) { 'Passed' { 'Green' } 'Skipped' { 'Yellow' } default { 'Red' } }
        $resultMessage = "{0,-5} {1}: {2}" -f $result.Status.ToUpperInvariant(), $result.Name, $result.Detail
        Write-Host $resultMessage -ForegroundColor $color
    }
}
catch {
    $results.Add([pscustomobject]@{
        Name = 'Test environment'
        Status = 'Failed'
        Artifact = $null
        Detail = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
    })
}
finally {
    if ($certificateContext) {
        try {
            & (Join-Path $PSScriptRoot 'Remove-TestSigningCertificate.ps1') -Context $certificateContext `
                -KeepSigningCertificate:$KeepTestCertificate
        }
        catch {
            $results.Add([pscustomobject]@{
                Name = 'Test environment cleanup'
                Status = 'Failed'
                Artifact = $null
                Detail = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
            })
        }
    }
}

$resultsPath = Join-Path $runOutputDirectory 'results.json'
[IO.File]::WriteAllText(
    $resultsPath,
    (ConvertTo-Json -InputObject @($results) -Depth 4),
    [Text.UTF8Encoding]::new($false))
Write-Host ''
Write-Host 'Summary'
$results | Format-Table Status, Name, Artifact -AutoSize
$passedCount = @($results | Where-Object Status -EQ 'Passed').Count
$skippedCount = @($results | Where-Object Status -EQ 'Skipped').Count
$failedCount = @($results | Where-Object Status -EQ 'Failed').Count
Write-Host "Passed: $passedCount; skipped: $skippedCount; failed: $failedCount"
Write-Host "Machine-readable results: $resultsPath"

if ($results.Count -eq 0) {
    Write-Host 'ERROR No tests were selected.' -ForegroundColor Red
    exit 1
}
if ($failedCount -ne 0) { exit 1 }
if ($passedCount -eq 0) {
    Write-Host 'ERROR No selected product test passed.' -ForegroundColor Red
    exit 1
}
if ($RequireAllSelectedTests -and $skippedCount -ne 0) {
    Write-Host 'ERROR Strict mode does not permit skipped selected tests.' -ForegroundColor Red
    exit 1
}
exit 0
