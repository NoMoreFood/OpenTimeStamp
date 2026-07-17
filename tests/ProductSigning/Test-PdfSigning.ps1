#Requires -PSEdition Core
#Requires -Version 7.6

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][string]$CertificateThumbprint,
    [Parameter(Mandatory)][uri]$Rfc3161Url,
    [string]$PfxPath,
    [string]$PfxPassword,
    [string]$ExpectedTsaThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProductSigning.Common.ps1')

$testName = 'PDF document signature'
$acrobatPath = Get-ApplicationPath -ExecutableName 'Acrobat.exe'
if (-not $acrobatPath) {
    return New-ProductTestResult -Name $testName -Status Skipped -Detail 'Adobe Acrobat is not installed.'
}
if (-not $PfxPath -or -not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) {
    return New-ProductTestResult -Name $testName -Status Skipped `
        -Detail 'The signing key is not exportable as the PFX that Acrobat PPKLite requires.'
}
if (Get-Process -Name 'Acrobat', 'AcroRd32' -ErrorAction SilentlyContinue) {
    return New-ProductTestResult -Name $testName -Status Skipped `
        -Detail 'Acrobat or Reader is already running. Close it so the temporary test JavaScript can load, then rerun.'
}
$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
$inputPath = Join-Path $outputPath 'PDF-Unsigned.pdf'
$artifactPath = Join-Path $outputPath 'PDF-PAdES-T-Signed.pdf'
New-MinimalPdf -Path $inputPath

$testId = 'OTS' + [Guid]::NewGuid().ToString('N')
$fieldName = "OpenTimeStampSignature$testId"
$runName = "${testId}Run"
$pollName = "${testId}Poll"
$resultName = "${testId}Result"
$javascriptDirectory = Get-AcrobatJavaScriptDirectory -AcrobatPath $acrobatPath
$javascriptPath = Join-Path $javascriptDirectory "$testId.js"
New-Item -ItemType Directory -Path $javascriptDirectory -Force | Out-Null
Assert-Condition (-not (Test-Path -LiteralPath $javascriptPath)) `
    "The temporary Acrobat JavaScript path '$javascriptPath' already exists."

$inputJson = ConvertTo-AcrobatPath -Path $inputPath | ConvertTo-Json -Compress
$outputJson = ConvertTo-AcrobatPath -Path $artifactPath | ConvertTo-Json -Compress
$pfxJson = ConvertTo-AcrobatPath -Path $PfxPath | ConvertTo-Json -Compress
$passwordJson = $PfxPassword | ConvertTo-Json -Compress
$timestampJson = $Rfc3161Url.AbsoluteUri | ConvertTo-Json -Compress
$fieldJson = $fieldName | ConvertTo-Json -Compress
$javascript = @"
var ${testId}Attempts = 0;
global.$resultName = "WAITING";
global.setPersistent("$resultName", false);

var $runName = app.trustedFunction(function () {
    app.beginPriv();
    var handler = null;
    try {
        if (app.activeDocs.length === 0) return false;
        var doc = app.activeDocs[0];
        if (doc.path.toLowerCase() !== $inputJson.toLowerCase()) return false;

        var field = doc.addField($fieldJson, "signature", 0, [72, 144, 360, 72]);
        field.signatureSetSeedValue({
            filter: "Adobe.PPKLite",
            subFilter: ["adbe.pkcs7.detached"],
            digestMethod: ["SHA256"],
            timeStampspec: { url: $timestampJson, flags: 1 },
            flags: 67
        });
        handler = security.getHandler("Adobe.PPKLite");
        var loggedIn = handler.login({
            oParams: { cPassword: $passwordJson, cDIPath: $pfxJson },
            bUI: false
        });
        if (!loggedIn) throw new Error("PPKLite could not log in to the test digital ID.");
        var signed = field.signatureSign(handler, {
            reason: "OpenTimeStamp interoperability test",
            location: "Local test host",
            digestMethod: "SHA256",
            timeStamp: $timestampJson
        }, $outputJson, false);
        if (!signed) throw new Error("Acrobat did not create the PDF signature.");
        global.$resultName = "PASS";
        return true;
    }
    catch (error) {
        global.$resultName = "ERROR: " + error;
        return true;
    }
    finally {
        if (handler !== null) handler.logout();
        app.endPriv();
    }
});

function $pollName() {
    ${testId}Attempts++;
    if ($runName()) return;
    if (${testId}Attempts < 120) app.setTimeOut("$pollName()", 500);
}

app.setTimeOut("$pollName()", 750);
"@

$acrobat = $null
$avDocument = $null
$signedAvDocument = $null
$signedPdfDocument = $null
$signedJsObject = $null
$signatureField = $null
$result = $null
$testFailure = $null
$cleanupFailures = [System.Collections.Generic.List[Exception]]::new()
try {
    [IO.File]::WriteAllText($javascriptPath, $javascript, [Text.UTF8Encoding]::new($false))
    $acrobat = New-Object -ComObject AcroExch.App
    $avDocument = New-Object -ComObject AcroExch.AVDoc
    Assert-Condition $avDocument.Open($inputPath, '') "Acrobat could not open '$inputPath'."
    $acrobat.Show()

    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    Assert-Condition (Test-Path -LiteralPath $artifactPath -PathType Leaf) `
        'Acrobat did not produce the signed PDF within 60 seconds. Check that Acrobat JavaScript is enabled.'
    Start-Sleep -Milliseconds 500

    $avDocument.Close($false)
    Release-ComObject $avDocument
    $avDocument = $null
    $signedAvDocument = New-Object -ComObject AcroExch.AVDoc
    Assert-Condition $signedAvDocument.Open($artifactPath, '') "Acrobat could not reopen '$artifactPath'."
    $signedPdfDocument = $signedAvDocument.GetPDDoc()
    $signedJsObject = $signedPdfDocument.GetJSObject()
    $signatureField = $signedJsObject.GetField($fieldName)
    Assert-Condition ($null -ne $signatureField) 'Acrobat could not find the generated PDF signature field.'
    $validationStatus = [int]$signatureField.SignatureValidate()
    Assert-Condition ($validationStatus -in 3, 4) `
        "Acrobat returned PDF signature validation status '$validationStatus' instead of 3 or 4."

    $pdfText = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($artifactPath))
    $contentMatches = [regex]::Matches($pdfText, '(?s)/Contents\s*<([0-9A-Fa-f\s]+)>')
    Assert-Condition ($contentMatches.Count -gt 0) 'The signed PDF has no hexadecimal CMS signature contents.'
    $timestampFound = $false
    $lastError = $null
    foreach ($contentMatch in $contentMatches) {
        try {
            Assert-CmsHasRfc3161Timestamp -Bytes (Convert-HexToBytes -Hex $contentMatch.Groups[1].Value) `
                -ExpectedTsaThumbprint $ExpectedTsaThumbprint
            $timestampFound = $true
            break
        }
        catch {
            $lastError = $_.Exception.Message
        }
    }
    Assert-Condition $timestampFound "The PDF CMS signature did not contain a valid RFC 3161 timestamp: $lastError"

    $result = New-ProductTestResult -Name $testName -Status Passed -Artifact $artifactPath `
        -Detail ('Acrobat validated the PDF signature, and its CMS signature-time-stamp token validated ' +
            'cryptographically.')
}
catch {
    $testFailure = $_
}
finally {
    if ($signedAvDocument) {
        try { [void]$signedAvDocument.Close($false) }
        catch {
            $cleanupFailures.Add([InvalidOperationException]::new(
                'The signed Acrobat document could not be closed during cleanup.', $_.Exception))
        }
    }
    if ($avDocument) {
        try { [void]$avDocument.Close($false) }
        catch {
            $cleanupFailures.Add([InvalidOperationException]::new(
                'The unsigned Acrobat document could not be closed during cleanup.', $_.Exception))
        }
    }
    if ($acrobat) {
        try { [void]$acrobat.Exit() }
        catch {
            $cleanupFailures.Add([InvalidOperationException]::new(
                'Acrobat could not be stopped during cleanup.', $_.Exception))
        }
    }

    foreach ($entry in @(
            [pscustomobject]@{ Name = 'signature field'; Value = $signatureField },
            [pscustomobject]@{ Name = 'signed JavaScript object'; Value = $signedJsObject },
            [pscustomobject]@{ Name = 'signed PDF document'; Value = $signedPdfDocument },
            [pscustomobject]@{ Name = 'signed Acrobat document'; Value = $signedAvDocument },
            [pscustomobject]@{ Name = 'unsigned Acrobat document'; Value = $avDocument },
            [pscustomobject]@{ Name = 'Acrobat application'; Value = $acrobat })) {
        try { Release-ComObject $entry.Value }
        catch {
            $cleanupFailures.Add([InvalidOperationException]::new(
                "The Acrobat $($entry.Name) COM reference could not be released.", $_.Exception))
        }
    }

    try {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
    catch {
        $cleanupFailures.Add([InvalidOperationException]::new(
            'Pending Acrobat COM finalizers could not be drained.', $_.Exception))
    }

    try { Remove-ProductSigningFileVerified -Path $javascriptPath }
    catch { $cleanupFailures.Add($_.Exception) }
}

if ($testFailure) {
    if ($cleanupFailures.Count -ne 0) {
        $failures = [System.Collections.Generic.List[Exception]]::new()
        $failures.Add($testFailure.Exception)
        foreach ($failure in $cleanupFailures) { $failures.Add($failure) }
        throw [AggregateException]::new(
            'PDF signing failed and one or more cleanup operations also failed.',
            $failures)
    }
    throw $testFailure
}
if ($cleanupFailures.Count -ne 0) {
    throw [AggregateException]::new('PDF signing cleanup failed.', $cleanupFailures)
}

$result
