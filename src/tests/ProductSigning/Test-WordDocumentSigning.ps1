#Requires -PSEdition Core
#Requires -Version 7.6

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][string]$CertificateThumbprint,
    [Parameter(Mandatory)][uri]$Rfc3161Url,
    [string]$ExpectedTsaThumbprint,
    [switch]$NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProductSigning.Common.ps1')

$testName = 'Word document signature'
if ($NonInteractive) {
    return New-ProductTestResult -Name $testName -Status Skipped `
        -Detail 'Word requires its certificate-selection dialog; rerun without -NonInteractive.'
}
if (-not (Get-ApplicationPath -ExecutableName 'WINWORD.EXE')) {
    return New-ProductTestResult -Name $testName -Status Skipped -Detail 'Microsoft Word is not installed.'
}
if (Get-Process -Name 'WINWORD' -ErrorAction SilentlyContinue) {
    return New-ProductTestResult -Name $testName -Status Skipped `
        -Detail 'Word is already running. Close it before testing temporary XAdES-T settings.'
}

$probe = $null
try {
    $probe = New-Object -ComObject Word.Application
    $officeVersion = [string]$probe.Version
}
finally {
    if ($probe) { $probe.Quit() }
    Release-ComObject $probe
}

$policyConflict = Get-OfficeTimestampPolicyConflict -OfficeVersion $officeVersion -TimestampUrl $Rfc3161Url
if ($policyConflict) {
    return New-ProductTestResult -Name $testName -Status Skipped -Detail $policyConflict
}

$signaturesPath = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Office\$officeVersion\Common\Signatures"
$registrySnapshot = Save-RegistryValues -Path $signaturesPath -Names @('XAdESLevel', 'MinXAdESLevel', 'TSALocation')
$word = $null
$documents = $null
$document = $null
$documentContent = $null
$signatureSet = $null
$signature = $null
$signatureDetails = $null
$verificationDocuments = $null
$verificationDocument = $null
$verificationSignatures = $null
$verificationSignature = $null
$artifactPath = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) 'Word-XAdES-T.docx'
$result = $null
$testFailure = $null
$cleanupFailures = [System.Collections.Generic.List[Exception]]::new()

try {
    Set-RegistryDword -Path $signaturesPath -Name 'XAdESLevel' -Value 2 -Snapshot $registrySnapshot
    Set-RegistryDword -Path $signaturesPath -Name 'MinXAdESLevel' -Value 2 -Snapshot $registrySnapshot
    Set-RegistryString -Path $signaturesPath -Name 'TSALocation' -Value $Rfc3161Url.AbsoluteUri `
        -Snapshot $registrySnapshot

    $word = New-Object -ComObject Word.Application
    $word.Visible = $true
    $documents = $word.Documents
    $document = $documents.Add()
    $documentContent = $document.Content
    $documentContent.Text = "OpenTimeStamp Word document signing test`r`nCreated $([DateTime]::UtcNow.ToString('O'))."
    Release-ComObject $documentContent
    Release-ComObject $documents
    $documentContent = $null
    $documents = $null
    $document.SaveAs2($artifactPath, 12)

    Write-Host 'ACTION Word opened its signing dialog.' -ForegroundColor Yellow
    $signingCertificate = Get-TestSigningCertificate -Thumbprint $CertificateThumbprint
    $signerName = $signingCertificate.GetNameInfo('SimpleName', $false)
    Write-Host "       Select '$signerName' and choose Sign."
    $signatureSet = $document.Signatures
    $signature = $signatureSet.Add()
    $signatureSet.Commit()
    Assert-Condition $signature.IsSigned 'Word reported that the document was not signed.'
    $signatureDetails = $signature.Details
    Assert-Condition ([int]$signatureDetails.ContentVerificationResults -eq 3) `
        'Word did not validate the signed document content.'
    Assert-Condition ([int]$signatureDetails.CertificateVerificationResults -in 3, 7) `
        "Word returned certificate verification result '$($signatureDetails.CertificateVerificationResults)'."
    $document.Close(0)
    Release-ComObject $signatureDetails
    Release-ComObject $signature
    Release-ComObject $signatureSet
    Release-ComObject $document
    $signature = $null
    $signatureDetails = $null
    $signatureSet = $null
    $document = $null

    $verificationDocuments = $word.Documents
    $verificationDocument = $verificationDocuments.Open($artifactPath, $false, $true)
    Release-ComObject $verificationDocuments
    $verificationDocuments = $null
    $verificationSignatures = $verificationDocument.Signatures
    Assert-Condition ($verificationSignatures.Count -eq 1) `
        "Word reported $($verificationSignatures.Count) document signatures instead of one."
    $verificationSignature = $verificationSignatures.Item(1)
    Assert-Condition $verificationSignature.IsSigned 'Word did not recognize the saved document signature.'
    $signatureDetails = $verificationSignature.Details
    Assert-Condition ([int]$signatureDetails.ContentVerificationResults -eq 3) `
        'Word did not validate the saved document content.'
    Assert-Condition ([int]$signatureDetails.CertificateVerificationResults -in 3, 7) `
        "Word returned certificate verification result '$($signatureDetails.CertificateVerificationResults)'."
    $verificationDocument.Close(0)
    Release-ComObject $signatureDetails
    Release-ComObject $verificationSignature
    Release-ComObject $verificationSignatures
    Release-ComObject $verificationDocument
    $verificationSignature = $null
    $signatureDetails = $null
    $verificationSignatures = $null
    $verificationDocument = $null
    $word.Quit()
    Release-ComObject $word
    $word = $null

    Add-Type -AssemblyName System.IO.Compression
    $archive = [IO.Compression.ZipFile]::OpenRead($artifactPath)
    try {
        $signatureEntry = $archive.Entries | Where-Object FullName -Like '_xmlsignatures/sig*.xml' |
            Select-Object -First 1
        Assert-Condition ($null -ne $signatureEntry) 'The DOCX package has no Office XML signature part.'
        $reader = [IO.StreamReader]::new($signatureEntry.Open())
        try { [xml]$signatureXml = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    }
    finally {
        $archive.Dispose()
    }

    $signerNode = $signatureXml.SelectSingleNode(
        "//*[local-name()='KeyInfo']//*[local-name()='X509Certificate']")
    Assert-Condition ($null -ne $signerNode) 'The Office signature does not embed its signer certificate.'
    $embeddedSigner = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
        [Convert]::FromBase64String($signerNode.InnerText))
    try {
        Assert-Condition ($embeddedSigner.Thumbprint -eq $CertificateThumbprint) `
            "Word used certificate '$($embeddedSigner.Thumbprint)' instead of '$CertificateThumbprint'."
    }
    finally {
        $embeddedSigner.Dispose()
    }

    $timestampNode = $signatureXml.SelectSingleNode("//*[local-name()='EncapsulatedTimeStamp']")
    Assert-Condition ($null -ne $timestampNode) 'The Office signature is not XAdES-T; no RFC 3161 token was embedded.'
    Assert-Rfc3161Token -Bytes ([Convert]::FromBase64String($timestampNode.InnerText)) `
        -ExpectedTsaThumbprint $ExpectedTsaThumbprint

    $result = New-ProductTestResult -Name $testName -Status Passed -Artifact $artifactPath `
        -Detail 'Word validated one native Office XAdES-T document signature and its RFC 3161 token.'
}
catch { $testFailure = $_ }
finally {
    if ($verificationDocument) {
        try { $verificationDocument.Close(0) }
        catch {
            $cleanupFailures.Add([InvalidOperationException]::new(
                'The verification Word document could not be closed during cleanup.', $_.Exception))
        }
    }
    if ($document) {
        try { $document.Close(0) }
        catch {
            $cleanupFailures.Add([InvalidOperationException]::new(
                'The Word document could not be closed during cleanup.', $_.Exception))
        }
    }
    if ($word) {
        try { $word.Quit() }
        catch {
            $cleanupFailures.Add([InvalidOperationException]::new(
                'Word could not be stopped during cleanup.', $_.Exception))
        }
    }
    foreach ($entry in @(
            [pscustomobject]@{ Name = 'verification signature'; Value = $verificationSignature },
            [pscustomobject]@{ Name = 'signature details'; Value = $signatureDetails },
            [pscustomobject]@{ Name = 'verification signatures'; Value = $verificationSignatures },
            [pscustomobject]@{ Name = 'verification document'; Value = $verificationDocument },
            [pscustomobject]@{ Name = 'signature'; Value = $signature },
            [pscustomobject]@{ Name = 'signature set'; Value = $signatureSet },
            [pscustomobject]@{ Name = 'document content'; Value = $documentContent },
            [pscustomobject]@{ Name = 'document'; Value = $document },
            [pscustomobject]@{ Name = 'documents'; Value = $documents },
            [pscustomobject]@{ Name = 'verification documents'; Value = $verificationDocuments },
            [pscustomobject]@{ Name = 'application'; Value = $word })) {
        try { Release-ComObject $entry.Value }
        catch {
            $cleanupFailures.Add([InvalidOperationException]::new(
                "The Word $($entry.Name) COM reference could not be released.", $_.Exception))
        }
    }
    try { Restore-RegistryValues -Snapshot $registrySnapshot }
    catch {
        $cleanupFailures.Add([InvalidOperationException]::new(
            'The temporary Word registry settings could not be restored.', $_.Exception))
    }
    try {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
    catch {
        $cleanupFailures.Add([InvalidOperationException]::new(
            'Pending Word COM finalizers could not be drained.', $_.Exception))
    }
}

if ($testFailure) {
    if ($cleanupFailures.Count -ne 0) {
        $failures = [System.Collections.Generic.List[Exception]]::new()
        $failures.Add($testFailure.Exception)
        foreach ($failure in $cleanupFailures) { $failures.Add($failure) }
        throw [AggregateException]::new(
            'Word signing failed and one or more cleanup operations also failed.', $failures)
    }
    throw $testFailure
}
if ($cleanupFailures.Count -ne 0) {
    throw [AggregateException]::new('Word signing cleanup failed.', $cleanupFailures)
}

$result
