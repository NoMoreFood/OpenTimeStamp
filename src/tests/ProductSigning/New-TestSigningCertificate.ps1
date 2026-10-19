#Requires -PSEdition Core
#Requires -Version 7.6

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutputDirectory,

    [string]$CertificateThumbprint,

    [string]$TsaCertificatePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProductSigning.Common.ps1')

$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
$ownedSigningCertificate = [string]::IsNullOrWhiteSpace($CertificateThumbprint)
$addedStores = [System.Collections.Generic.List[string]]::new()
$temporaryFiles = [System.Collections.Generic.List[string]]::new()
$keyName = $null
$pfxPath = $null
$certificate = $null
$completed = $false
$context = $null
$setupFailure = $null
$cleanupFailure = $null

try {
    if ($ownedSigningCertificate) {
        $runId = [Guid]::NewGuid().ToString('N').Substring(0, 12)
        $keyName = "OpenTimeStamp-ProductSigning-$([Guid]::NewGuid().ToString('N'))"
        $keyParameters = [Security.Cryptography.CngKeyCreationParameters]::new()
        $keyParameters.Provider = [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
        $keyParameters.ExportPolicy = [Security.Cryptography.CngExportPolicies]::AllowExport -bor
            [Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
        $keyParameters.KeyUsage = [Security.Cryptography.CngKeyUsages]::Signing
        $keyParameters.Parameters.Add([Security.Cryptography.CngProperty]::new(
            'Length',
            [BitConverter]::GetBytes(3072),
            [Security.Cryptography.CngPropertyOptions]::None))
        $key = [Security.Cryptography.CngKey]::Create(
            [Security.Cryptography.CngAlgorithm]::Rsa,
            $keyName,
            $keyParameters)
        try {
            $rsa = [Security.Cryptography.RSACng]::new($key)
            try {
                $subject = "CN=OpenTimeStamp Product Signing Test $runId"
                $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    $subject,
                    $rsa,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    [Security.Cryptography.RSASignaturePadding]::Pkcs1)
                $request.CertificateExtensions.Add(
                    [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
                        $false,
                        $false,
                        0,
                        $true))
                $request.CertificateExtensions.Add(
                    [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
                        $true))
                $enhancedKeyUsages = [Security.Cryptography.OidCollection]::new()
                [void]$enhancedKeyUsages.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
                [void]$enhancedKeyUsages.Add([Security.Cryptography.Oid]::new('1.3.6.1.4.1.311.10.3.12'))
                $request.CertificateExtensions.Add(
                    [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
                        $enhancedKeyUsages,
                        $false))
                $request.CertificateExtensions.Add(
                    [Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new(
                        $request.PublicKey,
                        $false))
                $certificate = $request.CreateSelfSigned((Get-Date).AddMinutes(-5), (Get-Date).AddDays(2))
                $certificate.FriendlyName = "OpenTimeStamp product signing test $runId"
            }
            finally {
                $rsa.Dispose()
            }
        }
        finally {
            $key.Dispose()
        }

        $store = [Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
        try {
            $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $addedStores.Add('My')
            $store.Add($certificate)
        }
        finally {
            $store.Dispose()
        }
    }
    else {
        $certificate = Get-TestSigningCertificate -Thumbprint $CertificateThumbprint
    }

    $publicCertificatePath = Join-Path $outputPath 'ProductSigningTest.cer'
    [IO.File]::WriteAllBytes(
        $publicCertificatePath,
        $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))

    $pfxPassword = 'OpenTimeStamp-' + [Guid]::NewGuid().ToString('N')
    $pfxPath = Join-Path ([IO.Path]::GetTempPath()) `
        ("OpenTimeStamp-ProductSigning-$([Guid]::NewGuid().ToString('N')).pfx")
    try {
        $pfxBytes = $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPassword)
        [IO.File]::WriteAllBytes($pfxPath, $pfxBytes)
        $temporaryFiles.Add($pfxPath)
    }
    catch {
        $pfxExportFailure = $_
        try { Remove-ProductSigningFileVerified -Path $pfxPath }
        catch {
            throw [AggregateException]::new(
                'The Acrobat PFX export failed and its partial credential file could not be removed.',
                [Exception[]]@($pfxExportFailure.Exception, $_.Exception))
        }
        $pfxPath = $null
        $pfxPassword = $null
        Write-Warning "The signing key could not be exported for Acrobat: $($pfxExportFailure.Exception.Message)"
    }

    $expectedTsaThumbprint = $null
    if (-not [string]::IsNullOrWhiteSpace($TsaCertificatePath)) {
        $resolvedTsaPath = [IO.Path]::GetFullPath($TsaCertificatePath)
        Assert-Condition (Test-Path -LiteralPath $resolvedTsaPath -PathType Leaf) `
            "TSA certificate '$resolvedTsaPath' does not exist."
        $tsaCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($resolvedTsaPath)
        try { $expectedTsaThumbprint = $tsaCertificate.Thumbprint }
        finally { $tsaCertificate.Dispose() }
    }

    $context = [pscustomobject]@{
        Certificate = $certificate
        Thumbprint = $certificate.Thumbprint
        Subject = $certificate.Subject
        OwnedSigningCertificate = $ownedSigningCertificate
        AddedStores = @($addedStores)
        KeyName = $keyName
        ExpectedTsaThumbprint = $expectedTsaThumbprint
        PublicCertificatePath = $publicCertificatePath
        PfxPath = $pfxPath
        PfxPassword = $pfxPassword
        TemporaryFiles = @($temporaryFiles)
    }
    $completed = $true
}
catch {
    $setupFailure = $_
}
finally {
    if (-not $completed) {
        $cleanupContext = [pscustomobject]@{
            Certificate = $certificate
            Thumbprint = if ($certificate) { $certificate.Thumbprint } else { $null }
            AddedStores = @($addedStores)
            KeyName = $keyName
            TemporaryFiles = if ($pfxPath) { @($pfxPath) } else { @() }
        }
        try {
            & (Join-Path $PSScriptRoot 'Remove-TestSigningCertificate.ps1') -Context $cleanupContext
        }
        catch {
            $cleanupFailure = $_
        }
    }
}

if ($setupFailure) {
    if ($cleanupFailure) {
        throw [AggregateException]::new(
            'Product-signing certificate setup failed and cleanup was incomplete.',
            [Exception[]]@($setupFailure.Exception, $cleanupFailure.Exception))
    }
    throw $setupFailure
}

$context
