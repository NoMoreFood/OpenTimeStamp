#Requires -PSEdition Core
#Requires -Version 7.6

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProductSigning.Common.ps1')
Add-Type -AssemblyName System.Security.Cryptography.Pkcs

function Assert-PdfRejected {
    param([byte[]]$Bytes, [string]$Message)

    try { Assert-PdfHasRfc3161Timestamp -Bytes $Bytes }
    catch { return }
    throw $Message
}

$rsa = [Security.Cryptography.RSA]::Create(2048)
$certificate = $null
try {
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=OpenTimeStamp PDF regression', $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),
        [DateTimeOffset]::UtcNow.AddHours(1))
    $signer = [Security.Cryptography.Pkcs.CmsSigner]::new($certificate)
    $signer.DigestAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
    $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly

    $prefix = "%PDF-1.4`n1 0 obj`n<< /Type /Sig /SubFilter /adbe.pkcs7.detached /Contents "
    $hexLength = 16384
    $secondOffset = $prefix.Length + $hexLength + 2
    $suffixFormat = " /ByteRange [0 {0:D10} {1:D10} {2:D10}] >>`nendobj`n%%EOF`n"
    $suffixLength = ($suffixFormat -f 0, 0, 0).Length
    $suffix = $suffixFormat -f $prefix.Length, $secondOffset, $suffixLength
    $signedContent = [Text.Encoding]::ASCII.GetBytes($prefix + $suffix)
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new($signedContent), $true)
    $cms.ComputeSignature($signer)
    $signatureHash = [Security.Cryptography.SHA256]::HashData($cms.SignerInfos[0].GetSignature())
    $tokenInfo = [Security.Cryptography.Pkcs.Rfc3161TimestampTokenInfo]::new(
        [Security.Cryptography.Oid]::new('1.2.3.4'),
        [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1'),
        [ReadOnlyMemory[byte]]::new($signatureHash), [ReadOnlyMemory[byte]]::new([byte[]]@(1)),
        [DateTimeOffset]::UtcNow, $null, $false, $null, $null, $null)
    $token = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new(
            [Security.Cryptography.Oid]::new('1.2.840.113549.1.9.16.1.4'), $tokenInfo.Encode()), $false)
    $token.ComputeSignature($signer)
    $cms.SignerInfos[0].AddUnsignedAttribute([Security.Cryptography.AsnEncodedData]::new(
        [Security.Cryptography.Oid]::new('1.2.840.113549.1.9.16.2.14'), $token.Encode()))
    $encoded = $cms.Encode()
    $hex = [Convert]::ToHexString($encoded)
    Assert-Condition ($hex.Length -le $hexLength) 'The PDF regression signature exceeds its placeholder.'
    $pdf = [Text.Encoding]::ASCII.GetBytes($prefix + '<' + $hex.PadRight($hexLength, '0') + '>' + $suffix)
    Assert-PdfHasRfc3161Timestamp -Bytes $pdf -ExpectedTsaThumbprint $certificate.Thumbprint

    $modified = [byte[]]$pdf.Clone()
    $modified[1] = $modified[1] -bxor 1
    Assert-PdfRejected -Bytes $modified -Message 'Modified first signed range was accepted.'
    $modified = [byte[]]$pdf.Clone()
    $modified[$modified.Length - 2] = $modified[$modified.Length - 2] -bxor 1
    Assert-PdfRejected -Bytes $modified -Message 'Modified second signed range was accepted.'
    Assert-PdfRejected -Bytes ([byte[]]($pdf + 0)) -Message 'Unsigned appended bytes were accepted.'
    Assert-PdfRejected -Bytes ([byte[]]$pdf[0..($pdf.Length - 2)]) `
        -Message 'A ByteRange extending beyond the file was accepted.'

    foreach ($range in @(
            ('[1 {0:D10} {1:D10} {2:D10}]' -f $prefix.Length, $secondOffset, $suffixLength),
            ('[0 {0:D10} {1:D10} {2:D10}]' -f $secondOffset, $secondOffset, $suffixLength),
            ('[0 {0:D10} {1:D10} {2:D10}]' -f ($prefix.Length - 1), $secondOffset, $suffixLength),
            '[0 99999999999999999999999999 1 1]', '[0 -1 1 1]')) {
        $modifiedText = [regex]::Replace([Text.Encoding]::ASCII.GetString($pdf),
            '(?<=/ByteRange )\[[^\]]+\]', $range)
        Assert-PdfRejected -Bytes ([Text.Encoding]::ASCII.GetBytes($modifiedText)) `
            -Message "Invalid PDF ByteRange was accepted: $range"
    }
    $withoutTimestamp = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new($signedContent), $true)
    $withoutTimestamp.ComputeSignature($signer)
    $unsignedHex = [Convert]::ToHexString($withoutTimestamp.Encode()).PadRight($hexLength, '0')
    Assert-PdfRejected -Bytes ([Text.Encoding]::ASCII.GetBytes($prefix + '<' + $unsignedHex + '>' + $suffix)) `
        -Message 'A detached PDF signature without a timestamp was accepted.'

    Write-Host 'PASS detached PDF CMS verification, signed-byte integrity, ByteRange bounds, and required timestamp'
}
finally {
    if ($null -ne $certificate) { $certificate.Dispose() }
    $rsa.Dispose()
}
