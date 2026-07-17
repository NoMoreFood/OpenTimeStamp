#Requires -PSEdition Core
#Requires -Version 7.6

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][string]$CertificateThumbprint,
    [Parameter(Mandatory)][uri]$AuthenticodeUrl,
    [string]$ExpectedTsaThumbprint,
    [switch]$AllowUntrustedRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProductSigning.Common.ps1')

$testName = 'PowerShell script signature'
if ($AuthenticodeUrl.Scheme -ne 'http') {
    return New-ProductTestResult -Name $testName -Status Skipped `
        -Detail 'Set-AuthenticodeSignature cannot obtain timestamps through HTTPS; supply an HTTP legacy endpoint.'
}
$signToolPath = Get-SignToolPath
if (-not $signToolPath) {
    return New-ProductTestResult -Name $testName -Status Skipped -Detail 'Windows SDK SignTool is not installed.'
}

$artifactPath = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) 'PowerShell-Authenticode-Signed.ps1'
$scriptText = @'
# OpenTimeStamp generated Authenticode test script.
Set-StrictMode -Version Latest
'OpenTimeStamp signed PowerShell script executed.'
'@
[IO.File]::WriteAllText($artifactPath, $scriptText, [Text.UTF8Encoding]::new($true))
$certificate = Get-TestSigningCertificate -Thumbprint $CertificateThumbprint
$signature = Set-AuthenticodeSignature -LiteralPath $artifactPath -Certificate $certificate -HashAlgorithm SHA256 `
    -IncludeChain All -TimestampServer $AuthenticodeUrl.AbsoluteUri
$verifyResult = Invoke-SignToolVerify -SignToolPath $signToolPath -Path $artifactPath `
    -AllowUntrustedRoot:$AllowUntrustedRoot
$verifiedSignature = Assert-AuthenticodeTimestamp -Path $artifactPath -CertificateThumbprint $CertificateThumbprint `
    -ExpectedTsaThumbprint $ExpectedTsaThumbprint -VerifiedUntrustedRoot:$verifyResult.UntrustedRoot

$pwshPath = (Get-Command pwsh.exe).Source
$executionOutput = Invoke-NativeProcess -FilePath $pwshPath -Description 'the signed PowerShell test script' `
    -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $artifactPath)
Assert-Condition ($executionOutput -match 'OpenTimeStamp signed PowerShell script executed') `
    'The signed PowerShell test script did not produce its expected output.'

New-ProductTestResult -Name $testName -Status Passed -Artifact $artifactPath `
    -Detail 'PowerShell and SignTool validated the SHA-256 signature and legacy Authenticode timestamp, then executed it.'
