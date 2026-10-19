#Requires -PSEdition Core
#Requires -Version 7.6

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][string]$CertificateThumbprint,
    [Parameter(Mandatory)][uri]$Rfc3161Url,
    [string]$ExpectedTsaThumbprint,
    [switch]$AllowUntrustedRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProductSigning.Common.ps1')

$testName = 'Windows executable signature'
$signToolPath = Get-SignToolPath
if (-not $signToolPath) {
    return New-ProductTestResult -Name $testName -Status Skipped -Detail 'Windows SDK SignTool is not installed.'
}
$compilerPath = Get-CSharpCompilerPath
if (-not $compilerPath) {
    return New-ProductTestResult -Name $testName -Status Skipped `
        -Detail 'The .NET Framework C# compiler is not installed.'
}

$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
$sourcePath = Join-Path $outputPath 'OpenTimeStamp-Signed-Test.cs'
$artifactPath = Join-Path $outputPath 'OpenTimeStamp-Signed-Test.exe'
$source = @'
using System;

internal static class Program
{
    private static int Main()
    {
        Console.WriteLine("OpenTimeStamp signed executable ran.");
        return 0;
    }
}
'@
[IO.File]::WriteAllText($sourcePath, $source, [Text.UTF8Encoding]::new($false))
$compileOutput = Invoke-NativeProcess -FilePath $compilerPath -Description 'C# test executable compilation' `
    -ArgumentList @('/nologo', '/optimize+', '/target:exe', "/out:$artifactPath", $sourcePath)

$signOutput = Invoke-SignToolSign -SignToolPath $signToolPath -Path $artifactPath `
    -CertificateThumbprint $CertificateThumbprint -TimestampUrl $Rfc3161Url
$verifyResult = Invoke-SignToolVerify -SignToolPath $signToolPath -Path $artifactPath `
    -AllowUntrustedRoot:$AllowUntrustedRoot
$signature = Assert-AuthenticodeTimestamp -Path $artifactPath -CertificateThumbprint $CertificateThumbprint `
    -ExpectedTsaThumbprint $ExpectedTsaThumbprint -VerifiedUntrustedRoot:$verifyResult.UntrustedRoot
$executionOutput = Invoke-NativeProcess -FilePath $artifactPath -Description 'the signed executable' -ArgumentList @()
Assert-Condition ($executionOutput -match 'OpenTimeStamp signed executable ran') `
    'The signed executable did not produce its expected output.'

New-ProductTestResult -Name $testName -Status Passed -Artifact $artifactPath `
    -Detail 'SignTool and Authenticode validated the RFC 3161 timestamp, and the signed executable ran.'
