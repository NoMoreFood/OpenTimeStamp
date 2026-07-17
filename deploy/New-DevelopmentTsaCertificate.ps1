#Requires -Version 5.1

<#
.SYNOPSIS
Creates a short-lived, self-signed certificate for OpenTimeStamp development.

.DESCRIPTION
DEVELOPMENT AND VALIDATION ONLY. The certificate is self-signed, expires after
seven days by default, and is not installed into a trusted root store. Obtain a
properly governed TSA certificate from a CA for every production deployment.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('LocalMachine', 'CurrentUser')]
    [string]$StoreLocation = 'LocalMachine',

    [ValidateRange(1, 30)]
    [int]$LifetimeDays = 7,

    [ValidateSet(2048, 3072, 4096)]
    [int]$KeyLength = 3072,

    [ValidateNotNullOrEmpty()]
    [string]$Subject = 'CN=OpenTimeStamp Development TSA',

    [string]$GrantToIdentity,

    [string]$ExportPublicCertificatePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($StoreLocation -eq 'LocalMachine') {
    $principal = New-Object System.Security.Principal.WindowsPrincipal(
        [System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Creating a LocalMachine certificate requires an elevated PowerShell session.'
    }
}
elseif (-not [string]::IsNullOrWhiteSpace($GrantToIdentity)) {
    throw 'Do not grant another identity access to a CurrentUser key. Create/import that certificate while running as the IIS process identity instead.'
}

$certificateParameters = @{
    Subject = $Subject
    FriendlyName = 'OpenTimeStamp DEVELOPMENT ONLY'
    Type = 'Custom'
    CertStoreLocation = "Cert:\$StoreLocation\My"
    Provider = 'Microsoft Software Key Storage Provider'
    KeyAlgorithm = 'RSA'
    KeyLength = $KeyLength
    HashAlgorithm = 'SHA256'
    KeyUsage = 'DigitalSignature'
    KeyUsageProperty = 'Sign'
    KeyExportPolicy = 'NonExportable'
    NotBefore = (Get-Date).AddMinutes(-5)
    NotAfter = (Get-Date).AddDays($LifetimeDays)
    TextExtension = @(
        # RFC 3161 requires a critical EKU containing only id-kp-timeStamping.
        '2.5.29.37={critical}{text}1.3.6.1.5.5.7.3.8',
        '2.5.29.19={critical}{text}ca=false'
    )
}

if (-not $PSCmdlet.ShouldProcess("$StoreLocation\My", "Create short-lived development TSA certificate '$Subject'")) {
    return
}

$certificate = $null
$certificatePath = $null
$exportPath = $null
$stagedExportPath = $null
$createdExportDirectory = $false
$grantResult = $null
$completed = $false
try {
    $certificate = New-SelfSignedCertificate @certificateParameters
    $certificatePath = "Cert:\$StoreLocation\My\$($certificate.Thumbprint)"
    $eku = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($eku.Count -ne 1 -or -not $eku[0].Critical) {
        throw 'Certificate creation did not produce exactly one critical EKU extension.'
    }

    $enhancedKeyUsage = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$eku[0]
    if ($enhancedKeyUsage.EnhancedKeyUsages.Count -ne 1 -or
        $enhancedKeyUsage.EnhancedKeyUsages[0].Value -ne '1.3.6.1.5.5.7.3.8') {
        throw 'Certificate creation did not produce a timestamping-only EKU.'
    }

    if (-not [string]::IsNullOrWhiteSpace($ExportPublicCertificatePath)) {
        $exportPath = [System.IO.Path]::GetFullPath($ExportPublicCertificatePath)
        $exportDirectory = Split-Path -Parent $exportPath
        if (-not (Test-Path -LiteralPath $exportDirectory -PathType Container)) {
            New-Item -ItemType Directory -Path $exportDirectory -Force | Out-Null
            $createdExportDirectory = $true
        }

        $stagedExportPath = Join-Path $exportDirectory `
            ('.{0}.{1}.tmp' -f [System.IO.Path]::GetFileName($exportPath), [guid]::NewGuid().ToString('N'))
        Export-Certificate -Cert $certificate -FilePath $stagedExportPath -Type CERT | Out-Null
    }

    if (-not [string]::IsNullOrWhiteSpace($GrantToIdentity)) {
        $grantScript = Join-Path $PSScriptRoot 'Grant-TsaPrivateKeyAccess.ps1'
        $grantResult = & $grantScript -Thumbprint $certificate.Thumbprint `
            -Identity $GrantToIdentity -Confirm:$false
    }

    if ($null -ne $stagedExportPath) {
        Move-Item -LiteralPath $stagedExportPath -Destination $exportPath -Force
        $stagedExportPath = $null
    }

    $completed = $true
    Write-Warning 'DEVELOPMENT ONLY: this self-signed certificate is not suitable for a production timestamp authority.'
    [PSCustomObject]@{
        Thumbprint = $certificate.Thumbprint
        Subject = $certificate.Subject
        StoreLocation = $StoreLocation
        StoreName = 'My'
        NotAfter = $certificate.NotAfter
        Trusted = $false
        PublicCertificatePath = $exportPath
    }
}
catch {
    if ($completed) { throw }
    $operationError = $_
    $cleanupErrors = New-Object 'System.Collections.Generic.List[string]'
    if ($null -ne $grantResult -and [bool]$grantResult.AclChanged -and
        (Test-Path -LiteralPath ([string]$grantResult.PrivateKeyPath) -PathType Leaf)) {
        try {
            $currentAcl = Get-Acl -LiteralPath ([string]$grantResult.PrivateKeyPath)
            $currentSddl = $currentAcl.GetSecurityDescriptorSddlForm(
                [System.Security.AccessControl.AccessControlSections]::All)
            if (-not $currentSddl.Equals(
                    [string]$grantResult.AppliedSddl, [System.StringComparison]::Ordinal)) {
                throw 'The private-key ACL changed after the development-certificate grant; refusing to overwrite it.'
            }
            $currentAcl.SetSecurityDescriptorSddlForm(
                [string]$grantResult.PreviousSddl,
                [System.Security.AccessControl.AccessControlSections]::Access)
            Set-Acl -LiteralPath ([string]$grantResult.PrivateKeyPath) -AclObject $currentAcl
            $restoredSddl = (Get-Acl -LiteralPath ([string]$grantResult.PrivateKeyPath)).GetSecurityDescriptorSddlForm(
                [System.Security.AccessControl.AccessControlSections]::All)
            if (-not $restoredSddl.Equals(
                    [string]$grantResult.PreviousSddl, [System.StringComparison]::Ordinal)) {
                throw 'The development-certificate private-key ACL was not restored exactly.'
            }
        }
        catch { $cleanupErrors.Add("private-key ACL rollback failed: $($_.Exception.Message)") }
    }
    if ($null -ne $stagedExportPath -and (Test-Path -LiteralPath $stagedExportPath)) {
        try { Remove-Item -LiteralPath $stagedExportPath -Force }
        catch { $cleanupErrors.Add("staged public-certificate cleanup failed: $($_.Exception.Message)") }
    }
    if ($null -ne $certificatePath -and (Test-Path -LiteralPath $certificatePath)) {
        try { Remove-Item -LiteralPath $certificatePath -DeleteKey -Force }
        catch { $cleanupErrors.Add("certificate/private-key cleanup failed: $($_.Exception.Message)") }
    }
    if ($createdExportDirectory -and (Test-Path -LiteralPath $exportDirectory -PathType Container)) {
        try {
            if (@(Get-ChildItem -LiteralPath $exportDirectory -Force).Count -eq 0) {
                Remove-Item -LiteralPath $exportDirectory -Force
            }
        }
        catch { $cleanupErrors.Add("export-directory cleanup failed: $($_.Exception.Message)") }
    }
    if ($cleanupErrors.Count -ne 0) {
        throw "Development certificate creation failed ('$($operationError.Exception.Message)') and cleanup was incomplete: $($cleanupErrors -join '; ')."
    }
    throw $operationError
}
finally {
    if ($null -ne $certificate) { $certificate.Dispose() }
}
