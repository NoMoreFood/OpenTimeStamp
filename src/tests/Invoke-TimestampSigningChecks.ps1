#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][uri[]]$ServerUrl,
    [Parameter(Mandatory = $true)][string]$CertificateThumbprint,
    [Parameter(Mandatory = $true)][string]$SignToolPath,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$CertificateStoreLocation = 'CurrentUser',
    [ValidateSet('AnyCPU', 'x86', 'x64')][string]$TargetArchitecture = 'AnyCPU',
    [string]$ExpectedTsaThumbprint,
    [uri]$UntrustedHttpsServerUrl,
    [switch]$AllowInsecureHttp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$signingScript = Join-Path $repositoryRoot 'tools\deploy\Invoke-TimestampSigning.ps1'
$runPath = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runPath -Force | Out-Null
$sourcePath = Join-Path $runPath 'Fixture.cs'
$fixturePath = Join-Path $runPath 'Fixture.exe'
[IO.File]::WriteAllText($sourcePath,
    'public static class Program { public static void Main() { System.Console.WriteLine("Signing fixture"); } }')
$compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) {
    $compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
}
& $compiler /nologo /target:exe "/platform:$TargetArchitecture" "/out:$fixturePath" $sourcePath
if ($LASTEXITCODE -ne 0) { throw 'The unsigned executable fixture could not be compiled.' }
$results = @()
foreach ($server in $ServerUrl) {
    foreach ($tool in @('PowerShell', 'SignTool')) {
        $extension = if ($tool -eq 'PowerShell') { 'ps1' } else { 'exe' }
        $path = Join-Path $runPath ($server.Scheme + '-' + $tool + '-' +
            [guid]::NewGuid().ToString('N') + '.' + $extension)
        if ($tool -eq 'PowerShell') { [IO.File]::WriteAllText($path, "'OpenTimeStamp signing qualification'`r`n") }
        else { Copy-Item -LiteralPath $fixturePath -Destination $path }
        $parameters = @{
            LiteralPath = $path; ServerUrl = $server; CertificateThumbprint = $CertificateThumbprint
            CertificateStoreLocation = $CertificateStoreLocation; Tool = $tool; SignToolPath = $SignToolPath
            AllowInsecureHttp = $AllowInsecureHttp
        }
        if ($ExpectedTsaThumbprint) { $parameters.ExpectedTsaThumbprint = $ExpectedTsaThumbprint }
        try {
            $result = & $signingScript @parameters
            $previousErrorAction = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $verification = & $SignToolPath verify /pa /all /tw $path 2>&1
                $exitCode = $LASTEXITCODE
            }
            finally { $ErrorActionPreference = $previousErrorAction }
            if ($exitCode -ne 0) { throw "Independent verification failed: $($verification -join ' ')" }
            $results += [pscustomobject]@{ Name = "$tool $server"; Passed = $true; Detail = $result }
        }
        catch { $results += [pscustomobject]@{ Name = "$tool $server"; Passed = $false; Detail = $_.Exception.Message } }
    }
}
if ($UntrustedHttpsServerUrl) {
    $path = Join-Path $runPath 'untrusted-tls.ps1'
    [IO.File]::WriteAllText($path, "'Untrusted TLS must preserve this input'`r`n")
    $before = (Get-FileHash -LiteralPath $path).Hash
    $rejected = $false
    try {
        & $signingScript -LiteralPath $path -ServerUrl $UntrustedHttpsServerUrl -Tool PowerShell `
            -CertificateThumbprint $CertificateThumbprint -CertificateStoreLocation $CertificateStoreLocation | Out-Null
    }
    catch { $rejected = $true }
    $results += [pscustomobject]@{
        Name = 'Untrusted HTTPS preserves input'
        Passed = $rejected -and (Get-FileHash -LiteralPath $path).Hash -eq $before
    }
}
$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $runPath 'results.json') -Encoding UTF8
$results
if (@($results | Where-Object { -not $_.Passed }).Count) { throw "Signing checks failed. Inspect '$runPath\results.json'." }
