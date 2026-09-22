#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'deploy\Deployment.Common.ps1')

$failures = 0
$tests = 0

function Invoke-Test {
    param([string]$Name, [scriptblock]$Body)

    $script:tests++
    try {
        & $Body
        Write-Host "PASS $Name"
    }
    catch {
        $script:failures++
        Write-Host "FAIL $Name"
        Write-Host "  $($_.Exception.GetType().Name): $($_.Exception.Message)"
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    if ($Expected -ne $Actual) { throw "$Message Expected '$Expected'; found '$Actual'." }
}

function Assert-Throws {
    param([scriptblock]$Body, [string]$Message)
    try { & $Body }
    catch { return }
    throw $Message
}

function New-TestPayload {
    param([string]$Path)

    New-Item -ItemType Directory -Path (Join-Path $Path 'bin') -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $Path 'Global.asax'), '<%@ Application Language="C#" %>')
    [System.IO.File]::WriteAllText((Join-Path $Path 'bin\OpenTimeStamp.Web.dll'), 'web-binary')
    [System.IO.File]::WriteAllText((Join-Path $Path 'bin\OpenTimeStamp.Core.dll'), 'core-binary')
    [System.IO.File]::WriteAllText((Join-Path $Path 'Web.config'), @'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="AuthenticationMode" value="Anonymous" />
    <add key="DataPath" value="" />
    <add key="AdminHostNames" value="localhost" />
    <add key="TimestampBodyReadTimeoutSeconds" value="10" />
    <add key="TimestampBodyIntakeLimit" value="32" />
    <add key="TimestampBodyIntakePerClientLimit" value="4" />
    <add key="TimestampProcessingLimit" value="4" />
    <add key="TimestampProcessingPerClientLimit" value="2" />
  </appSettings>
</configuration>
'@)
}

$testParent = Join-Path ([System.IO.Path]::GetTempPath()) 'OpenTimeStamp.Deployment.Tests'
$testRoot = Join-Path $testParent ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
try {
    Invoke-Test 'Manifest accepts one exact complete payload' {
        $payload = Join-Path $testRoot 'valid-payload'
        New-TestPayload -Path $payload
        $manifestPath = New-OpenTimeStampDeploymentManifest -PayloadPath $payload `
            -ReleaseId '20260717010101Z-0123456789ab'
        Assert-True (Test-Path -LiteralPath $manifestPath -PathType Leaf) 'Manifest was not created.'
        $manifest = Assert-OpenTimeStampPublishedPayload -PayloadPath $payload
        Assert-Equal 'OpenTimeStamp' ([string]$manifest.Product) 'Manifest product differs.'
        Assert-Equal 4 @($manifest.Files).Count 'Unexpected manifest file count.'
    }

    Invoke-Test 'Detached manifest signature is cryptographically verified and signer pinned' {
        $payload = Join-Path $testRoot 'signed-manifest-payload'
        New-TestPayload -Path $payload
        $manifestPath = New-OpenTimeStampDeploymentManifest -PayloadPath $payload `
            -ReleaseId '20260717010102Z-0123456789ab'
        Add-Type -AssemblyName System.Security
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider 2048
        $certificate = $null
        try {
            $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=OpenTimeStamp deployment test', $rsa,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $certificate = $request.CreateSelfSigned(
                [DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddHours(1))
            $signedManifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
            $content = [System.Security.Cryptography.Pkcs.ContentInfo]::new($signedManifestBytes)
            $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
            $signer = [System.Security.Cryptography.Pkcs.CmsSigner]::new($certificate)
            $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
            $cms.ComputeSignature($signer)
            $signaturePath = Join-Path $testRoot 'deployment-manifest.p7s'
            $signatureBytes = $cms.Encode()
            [System.IO.File]::WriteAllBytes($signaturePath, $signatureBytes)

            $verified = Assert-OpenTimeStampManifestSignature -ManifestPath $manifestPath `
                -SignaturePath $signaturePath -TrustedSignerThumbprint $certificate.Thumbprint
            Assert-Equal $certificate.Thumbprint $verified.SignerThumbprint `
                'Detached manifest signature returned the wrong signer.'
            Assert-Equal '20260717010102Z-0123456789ab' ([string]$verified.Manifest.ReleaseId) `
                'Detached manifest verification did not return the signed manifest snapshot.'

            # Replace both payload and on-disk manifest with a self-consistent but
            # unsigned revision. Validation against the already verified snapshot
            # must reject the replacement even though rereading the disk manifest succeeds.
            [System.IO.File]::AppendAllText((Join-Path $payload 'bin\OpenTimeStamp.Core.dll'), '-changed')
            New-OpenTimeStampDeploymentManifest -PayloadPath $payload `
                -ReleaseId '20260717010102Z-0123456789ab' | Out-Null
            Assert-OpenTimeStampPublishedPayload -PayloadPath $payload | Out-Null
            Assert-Throws {
                Assert-OpenTimeStampPublishedPayload -PayloadPath $payload -Manifest $verified.Manifest
            } 'A substituted self-consistent payload was accepted instead of the signed manifest snapshot.'

            [System.IO.File]::WriteAllBytes($manifestPath, $signedManifestBytes)
            $signatureBytes[$signatureBytes.Length - 1] = $signatureBytes[$signatureBytes.Length - 1] -bxor 1
            [System.IO.File]::WriteAllBytes($signaturePath, $signatureBytes)
            Assert-Throws {
                Assert-OpenTimeStampManifestSignature -ManifestPath $manifestPath `
                    -SignaturePath $signaturePath -TrustedSignerThumbprint $certificate.Thumbprint
            } 'A modified detached manifest signature was accepted.'
        }
        finally {
            if ($null -ne $certificate) { $certificate.Dispose() }
            $rsa.Dispose()
        }
    }

    Invoke-Test 'Development certificate creation rolls back certificate, key, and staged export' {
        $subject = 'CN=OpenTimeStamp Transaction Test ' + [Guid]::NewGuid().ToString('N')
        $exportPath = Join-Path $testRoot 'locked-development-certificate.cer'
        [System.IO.File]::WriteAllText($exportPath, 'preserve')
        $lockStream = New-Object System.IO.FileStream(
            $exportPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
        try {
            Assert-Throws {
                & (Join-Path $repositoryRoot 'deploy\New-DevelopmentTsaCertificate.ps1') `
                    -StoreLocation CurrentUser -Subject $subject `
                    -ExportPublicCertificatePath $exportPath -Confirm:$false
            } 'Development certificate creation unexpectedly succeeded while its export target was locked.'
        }
        finally { $lockStream.Dispose() }

        $leakedCertificates = @(Get-ChildItem -LiteralPath Cert:\CurrentUser\My |
            Where-Object Subject -EQ $subject)
        try {
            Assert-Equal 0 $leakedCertificates.Count 'A failed development-certificate transaction left a certificate.'
            Assert-Equal 'preserve' ([System.IO.File]::ReadAllText($exportPath)) `
                'A failed development-certificate transaction replaced the existing export.'
            Assert-Equal 0 @(Get-ChildItem -LiteralPath $testRoot -Filter '.locked-development-certificate.cer.*.tmp').Count `
                'A failed development-certificate transaction left a staged export.'
        }
        finally {
            foreach ($certificate in $leakedCertificates) {
                Remove-Item -LiteralPath $certificate.PSPath -DeleteKey -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Invoke-Test 'Persisted key names cannot escape their machine-key directory' {
        $keyDirectory = Join-Path $testRoot 'machine-keys'
        New-Item -ItemType Directory -Path $keyDirectory | Out-Null
        $expected = Join-Path $keyDirectory 'safe-key-name'
        Assert-Equal ([System.IO.Path]::GetFullPath($expected)) `
            (Resolve-OpenTimeStampPersistedMachineKeyPath -KeyDirectory $keyDirectory `
                -UniqueName 'safe-key-name' -KeyDescription 'Test key') `
            'A safe persisted key name resolved incorrectly.'
        Assert-Throws {
            Resolve-OpenTimeStampPersistedMachineKeyPath -KeyDirectory $keyDirectory `
                -UniqueName '..\outside-key' -KeyDescription 'Test key'
        } 'A traversal persisted key name was accepted.'
        Assert-Throws {
            Resolve-OpenTimeStampPersistedMachineKeyPath -KeyDirectory $keyDirectory `
                -UniqueName 'nested\key' -KeyDescription 'Test key'
        } 'A nested persisted key name was accepted.'
    }

    Invoke-Test 'Office registry rollback is ownership aware and verified' {
        $productCommonPath = Join-Path $repositoryRoot 'tests\ProductSigning\ProductSigning.Common.ps1'
        $productCommon = (Get-Content -LiteralPath $productCommonPath -Raw) -replace '(?m)^#Requires[^\r\n]*(?:\r?\n)?', ''
        Invoke-Expression $productCommon
        $registryPath = 'Registry::HKEY_CURRENT_USER\Software\OpenTimeStamp-ProductTest-' +
            [Guid]::NewGuid().ToString('N')
        try {
            $snapshot = Save-RegistryValues -Path $registryPath -Names @('AccessVBOM')
            Set-RegistryDword -Path $registryPath -Name AccessVBOM -Value 1 -Snapshot $snapshot
            Assert-Equal 1 (Get-ItemPropertyValue -LiteralPath $registryPath -Name AccessVBOM) `
                'The owned registry value was not written.'
            Set-ItemProperty -LiteralPath $registryPath -Name AccessVBOM -Value 2
            Assert-Throws { Restore-RegistryValues -Snapshot $snapshot } `
                'Registry rollback overwrote a concurrent value change.'
            Assert-Equal 2 (Get-ItemPropertyValue -LiteralPath $registryPath -Name AccessVBOM) `
                'Registry rollback changed an externally modified value.'
            Set-ItemProperty -LiteralPath $registryPath -Name AccessVBOM -Value 1
            Restore-RegistryValues -Snapshot $snapshot
            Assert-True (-not (Test-Path -LiteralPath $registryPath)) `
                'Registry rollback did not remove the test-created empty key.'
        }
        finally {
            if (Test-Path -LiteralPath $registryPath) {
                Remove-Item -LiteralPath $registryPath -Recurse -Force
            }
        }
    }

    Invoke-Test 'Native product command lines round-trip and time out under PowerShell 7.6' {
        $productCommonPath = Join-Path $repositoryRoot 'tests\ProductSigning\ProductSigning.Common.ps1'
        $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
        if ($null -eq $pwsh -or $pwsh.Version -lt [version]'7.6') {
            Write-Warning 'PowerShell 7.6 or later is unavailable; native product-process behavior was not exercised.'
            return
        }
        $argumentEcho = Join-Path $testRoot 'ProductArgumentEcho.exe'
        Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

public static class ProductArgumentEcho
{
    public static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "--spawn-child")
        {
            using (Process child = Process.Start(new ProcessStartInfo
            {
                FileName = Process.GetCurrentProcess().MainModule.FileName,
                Arguments = "--child-sleep " + args[1],
                UseShellExecute = false,
                CreateNoWindow = true
            }))
            {
            }
            Thread.Sleep(30000);
            return 0;
        }
        if (args.Length == 2 && args[0] == "--child-sleep")
        {
            string path = Encoding.UTF8.GetString(Convert.FromBase64String(args[1]));
            File.WriteAllText(path, Process.GetCurrentProcess().Id.ToString());
            Thread.Sleep(30000);
            return 0;
        }
        for (int index = 0; index < args.Length; index++)
        {
            Console.WriteLine(index + ":" + Convert.ToBase64String(Encoding.UTF8.GetBytes(args[index])));
        }
        return 0;
    }
}
'@ -OutputAssembly $argumentEcho -OutputType ConsoleApplication
        $argumentsPath = Join-Path $testRoot 'ProductArguments.json'
        $outputPath = Join-Path $testRoot 'ProductArgumentOutput.txt'
        $runnerPath = Join-Path $testRoot 'Invoke-ProductNativeProcessRegression.ps1'
        [IO.File]::WriteAllText($runnerPath, @'
#Requires -PSEdition Core
#Requires -Version 7.6
param(
    [Parameter(Mandatory)][string]$CommonPath,
    [Parameter(Mandatory)][string]$FilePath,
    [Parameter(Mandatory)][string]$ArgumentsPath,
    [Parameter(Mandatory)][string]$OutputPath,
    [int]$TimeoutSeconds = 120
)
$ErrorActionPreference = 'Stop'
. $CommonPath
try {
    $argumentList = @((Get-Content -LiteralPath $ArgumentsPath -Raw | ConvertFrom-Json))
    $output = Invoke-NativeProcess -FilePath $FilePath -ArgumentList $argumentList `
        -Description 'native-process regression helper' -TimeoutSeconds $TimeoutSeconds
    [IO.File]::WriteAllText($OutputPath, [string]$output, [Text.UTF8Encoding]::new($false))
}
catch {
    [Console]::Out.WriteLine($_.Exception.Message)
    exit 1
}
'@, [Text.UTF8Encoding]::new($false))
        $expectedArguments = @('', 'plain', 'two words', 'quote"inside', 'C:\path with space\', 'snowman-☃')
        [IO.File]::WriteAllText($argumentsPath,
            (ConvertTo-Json -InputObject $expectedArguments -Compress), [Text.UTF8Encoding]::new($false))
        $hostOutput = @(& $pwsh.Source -NoLogo -NoProfile -NonInteractive -File $runnerPath `
            -CommonPath $productCommonPath -FilePath $argumentEcho -ArgumentsPath $argumentsPath `
            -OutputPath $outputPath 2>&1)
        Assert-Equal 0 $LASTEXITCODE `
            "PowerShell 7.6 native argument regression failed: $($hostOutput -join [Environment]::NewLine)"
        $output = Get-Content -LiteralPath $outputPath -Raw
        $actualArguments = @($output -split '\r?\n' | ForEach-Object {
            $separator = $_.IndexOf(':')
            [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_.Substring($separator + 1)))
        })
        Assert-Equal $expectedArguments.Count $actualArguments.Count 'Native argument count changed.'
        for ($index = 0; $index -lt $expectedArguments.Count; $index++) {
            Assert-Equal $expectedArguments[$index] $actualArguments[$index] `
                "Native argument $index did not round-trip."
        }

        $childPidPath = Join-Path $testRoot 'ProductArgumentEchoChild.pid'
        $childPidPathBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($childPidPath))
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        $timedOut = $false
        try {
            [IO.File]::WriteAllText($argumentsPath,
                (ConvertTo-Json -InputObject @('--spawn-child', $childPidPathBase64) -Compress),
                [Text.UTF8Encoding]::new($false))
            $timeoutOutput = @(& $pwsh.Source -NoLogo -NoProfile -NonInteractive -File $runnerPath `
                -CommonPath $productCommonPath -FilePath $argumentEcho -ArgumentsPath $argumentsPath `
                -OutputPath $outputPath -TimeoutSeconds 1 2>&1)
            $timedOut = $LASTEXITCODE -ne 0 -and
                ($timeoutOutput -join [Environment]::NewLine) -match 'timed out after 1 seconds'
        }
        finally { $stopwatch.Stop() }
        Assert-True $timedOut 'A hung native product process did not report its timeout.'
        Assert-True ($stopwatch.Elapsed.TotalSeconds -lt 20) 'Native product-process timeout was not bounded.'
        Assert-True (Test-Path -LiteralPath $childPidPath) 'The timeout helper did not spawn its child process.'

        $childProcess = $null
        $childExited = $false
        try {
            try {
                $childProcess = [Diagnostics.Process]::GetProcessById(
                    [int](Get-Content -LiteralPath $childPidPath -Raw))
            }
            catch [ArgumentException] { $childExited = $true }
            if ($null -ne $childProcess) { $childExited = $childProcess.WaitForExit(5000) }
        }
        finally {
            if ($null -ne $childProcess) {
                if (-not $childProcess.HasExited) {
                    $childProcess.Kill()
                    [void]$childProcess.WaitForExit(5000)
                }
                $childProcess.Dispose()
            }
        }
        Assert-True $childExited 'The timed-out native product process left its child running.'
    }

    Invoke-Test 'PDF timestamp validation proves the signed document imprint' {
        $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
        if ($null -eq $pwsh -or $pwsh.Version -lt [version]'7.6') {
            Write-Warning 'PowerShell 7.6 or later is unavailable; PDF signature validation was not exercised.'
            return
        }
        $regressionPath = Join-Path $repositoryRoot 'tests\ProductSigning\Test-PdfSignatureValidation.ps1'
        $output = @(& $pwsh.Source -NoLogo -NoProfile -NonInteractive -File $regressionPath 2>&1)
        Assert-Equal 0 $LASTEXITCODE "PDF signature validation failed: $($output -join [Environment]::NewLine)"
    }

    Invoke-Test 'Administrative host candidates avoid automatic-variable collisions' {
        $installerPath = Join-Path $repositoryRoot 'deploy\Install-IisApplication.ps1'
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $installerPath, [ref]$tokens, [ref]$parseErrors)
        Assert-Equal 0 @($parseErrors).Count 'Installer could not be parsed for host-candidate regression.'
        $loops = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.ForEachStatementAst] -and
                        ($node.Condition.Extent.Text.Contains("'localhost'") -or
                            $node.Condition.Extent.Text.Contains('$configuredHost -split'))
                }, $true))
        Assert-Equal 2 $loops.Count 'The installer host-candidate loops could not be isolated.'
        $hostCandidates = [System.Collections.Generic.List[string]]::new()
        $configuredHost = 'tsa.example.test;tsa2.example.test'
        foreach ($loop in $loops) { & ([scriptblock]::Create($loop.Extent.Text)) }
        Assert-Equal 6 $hostCandidates.Count 'The installer did not collect all default and configured hosts.'
        foreach ($expected in @('localhost', '127.0.0.1', '::1', [Environment]::MachineName,
                'tsa.example.test', 'tsa2.example.test')) {
            Assert-True ($hostCandidates.Contains($expected)) "Administrative host '$expected' was omitted."
        }
    }

    Invoke-Test 'Upgrade intake settings are range checked, related, and preserved' {
        $stage = Join-Path $testRoot 'intake-settings-stage'
        New-TestPayload -Path $stage
        $settings = @{
            TimestampBodyReadTimeoutSeconds = '12'
            TimestampBodyIntakeLimit = '48'
            TimestampBodyIntakePerClientLimit = '6'
            TimestampProcessingLimit = '8'
            TimestampProcessingPerClientLimit = '3'
        }
        Assert-OpenTimeStampIntakeSettings -Settings $settings
        Set-OpenTimeStampStagedWebSettings -ReleasePath $stage -Mode Windows `
            -EffectiveDataPath 'C:\ProgramData\OpenTimeStamp' -EffectiveAdminHosts @('localhost') `
            -ExistingSettings $settings
        [xml]$configuration = Get-Content -LiteralPath (Join-Path $stage 'Web.config') -Raw
        foreach ($key in $settings.Keys) {
            Assert-Equal $settings[$key] `
                $configuration.SelectSingleNode("/configuration/appSettings/add[@key='$key']").GetAttribute('value') `
                "Upgrade setting '$key' was not preserved."
        }
        Assert-Throws {
            Assert-OpenTimeStampIntakeSettings -Settings @{ TimestampBodyIntakeLimit = '0' }
        } 'An out-of-range global intake limit was accepted.'
        Assert-Throws {
            Assert-OpenTimeStampIntakeSettings -Settings @{
                TimestampProcessingLimit = '2'; TimestampProcessingPerClientLimit = '3'
            }
        } 'A per-client processing limit above the global limit was accepted.'
    }

    Invoke-Test 'Binding validation requires a usable HTTPS certificate and returns an exact URL' {
        $hash = New-Object byte[] 20
        for ($index = 0; $index -lt $hash.Length; $index++) { $hash[$index] = [byte]($index + 1) }
        $certificate = [pscustomobject]@{
            HasPrivateKey = $true
            NotBefore = (Get-Date).AddDays(-1)
            NotAfter = (Get-Date).AddDays(1)
        }
        $lookup = { param($StoreName, $Thumbprint) $certificate }.GetNewClosure()
        $binding = [pscustomobject]@{
            protocol = 'https'
            bindingInformation = '*:443:tsa.example.test'
            certificateHash = $hash
            certificateStoreName = 'My'
        }
        $endpoint = Get-OpenTimeStampValidatedBindingEndpoint -Binding $binding -CertificateLookup $lookup
        Assert-Equal 'https://tsa.example.test' $endpoint.BaseUrl 'HTTPS binding URL differs.'
        Assert-Equal ([System.BitConverter]::ToString($hash).Replace('-', '')) `
            $endpoint.CertificateThumbprint 'HTTPS binding certificate differs.'
        Assert-Throws {
            Get-OpenTimeStampValidatedBindingEndpoint -Binding ([pscustomobject]@{
                protocol = 'https'; bindingInformation = '*:443:tsa.example.test'
                certificateHash = $null; certificateStoreName = 'My'
            }) -CertificateLookup $lookup
        } 'An HTTPS binding without a certificate was accepted.'
    }

    Invoke-Test 'Root-only ACL snapshots avoid historical release traversal' {
        $aclRoot = Join-Path $testRoot 'acl-snapshot-root'
        New-Item -ItemType Directory -Path (Join-Path $aclRoot 'child') -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $aclRoot 'child\value.txt'), 'value')
        $rootOnly = Get-OpenTimeStampRecursiveAclSnapshot -Path $aclRoot -RootOnly
        $recursive = Get-OpenTimeStampRecursiveAclSnapshot -Path $aclRoot
        Assert-Equal 1 @($rootOnly.Entries).Count 'Root-only ACL snapshot traversed descendants.'
        Assert-True (@($recursive.Entries).Count -gt 1) 'Recursive ACL snapshot omitted descendants.'
    }

    Invoke-Test 'Release retention removes only validated obsolete releases' {
        $releases = Join-Path $testRoot 'retained-releases'
        New-Item -ItemType Directory -Path $releases | Out-Null
        $active = $null
        for ($index = 1; $index -le 7; $index++) {
            $releaseId = '202607170101{0:D2}Z-{1}' -f $index, $index.ToString('x12')
            $release = Join-Path $releases $releaseId
            New-TestPayload -Path $release
            New-OpenTimeStampDeploymentManifest -PayloadPath $release -ReleaseId $releaseId | Out-Null
            $active = $release
        }
        $removed = @(Remove-OpenTimeStampObsoleteReleases -ReleasesPath $releases `
            -ActiveReleasePath $active -RetainCount 5)
        Assert-Equal 2 $removed.Count 'Release retention removed the wrong number of releases.'
        Assert-Equal 5 @(Get-ChildItem -LiteralPath $releases -Directory).Count `
            'Release retention kept the wrong number of releases.'
        Assert-True (Test-Path -LiteralPath $active -PathType Container) 'Release retention removed the active release.'
        $invalidRelease = Join-Path $releases '20260716010101Z-000000000001'
        New-Item -ItemType Directory -Path $invalidRelease | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $invalidRelease 'unknown.txt'), 'preserve')
        Remove-OpenTimeStampObsoleteReleases -ReleasesPath $releases `
            -ActiveReleasePath $active -RetainCount 5 3>$null | Out-Null
        Assert-True (Test-Path -LiteralPath (Join-Path $invalidRelease 'unknown.txt') -PathType Leaf) `
            'Release retention deleted an unvalidated release-shaped directory.'
    }

    Invoke-Test 'Invalid recent releases cannot displace healthy retained releases' {
        $releases = Join-Path $testRoot 'retention-with-corrupt-recent-release'
        $releasePaths = @{}
        for ($index = 1; $index -le 6; $index++) {
            $releaseId = '202607170102{0:D2}Z-{1}' -f $index, $index.ToString('x12')
            $releasePaths[$index] = Join-Path $releases $releaseId
            New-TestPayload -Path $releasePaths[$index]
            New-OpenTimeStampDeploymentManifest -PayloadPath $releasePaths[$index] `
                -ReleaseId $releaseId | Out-Null
        }
        [IO.File]::AppendAllText((Join-Path $releasePaths[5] 'bin\OpenTimeStamp.Web.dll'), '-corrupt')
        $removed = @(Remove-OpenTimeStampObsoleteReleases -ReleasesPath $releases `
            -ActiveReleasePath $releasePaths[6] -RetainCount 2 3>$null)
        Assert-Equal 3 $removed.Count 'An invalid recent release consumed a healthy retention slot.'
        foreach ($index in @(4, 5, 6)) {
            Assert-True (Test-Path -LiteralPath $releasePaths[$index] -PathType Container) `
                "Retention removed protected release $index."
        }
        Assert-OpenTimeStampPublishedPayload -PayloadPath $releasePaths[4] | Out-Null
        Remove-OpenTimeStampObsoleteReleases -ReleasesPath $releases `
            -ActiveReleasePath $releasePaths[4] -RetainCount 1 3>$null | Out-Null
        Assert-True (Test-Path -LiteralPath $releasePaths[4] -PathType Container) `
            'Retention removed an active release older than the newest valid release.'
    }

    Invoke-Test 'Operation lock rejects a concurrent owner without waiting' {
        $scope = 'OpenTimeStamp-Deployment-Test-' + [Guid]::NewGuid().ToString('N')
        $lock = Enter-OpenTimeStampDeploymentLock -Scope $scope
        $worker = [PowerShell]::Create()
        $async = $null
        try {
            $workerScript = @'
param($CommonScript, $Scope)
$ErrorActionPreference = 'Stop'
. $CommonScript
try {
    $other = Enter-OpenTimeStampDeploymentLock -Scope $Scope
    try { 'acquired' }
    finally { Exit-OpenTimeStampDeploymentLock -Lock $other }
}
catch {
    'blocked:' + $_.Exception.Message
}
'@
            [void]$worker.AddScript($workerScript).AddArgument(
                (Join-Path $repositoryRoot 'deploy\Deployment.Common.ps1')).AddArgument($scope)
            $async = $worker.BeginInvoke()
            if (-not $async.AsyncWaitHandle.WaitOne(5000)) {
                $worker.Stop()
                throw 'A contending operation remained blocked instead of failing fast.'
            }

            $result = @($worker.EndInvoke($async))
            Assert-Equal 1 $result.Count 'The contending operation returned an unexpected result count.'
            Assert-True ([string]$result[0] -like 'blocked:Another OpenTimeStamp operation is already active*') `
                'The contending operation did not report the expected lock conflict.'
        }
        finally {
            $worker.Dispose()
            Exit-OpenTimeStampDeploymentLock -Lock $lock
        }
    }

    Invoke-Test 'Publisher holds a path-scoped lock through destructive work' {
        $publisher = Get-Content -LiteralPath (Join-Path $repositoryRoot 'build\Publish.ps1') -Raw
        $lockStart = $publisher.IndexOf(
            "`$publishLock = Enter-OpenTimeStampDeploymentLock -Scope ('OpenTimeStamp-Publish:' + `$OutputPath)")
        $destructivePublish = $publisher.IndexOf('/p:DeleteExistingFiles=true')
        $lockRelease = $publisher.LastIndexOf('Exit-OpenTimeStampDeploymentLock -Lock $publishLock')
        Assert-True ($lockStart -ge 0) 'Publisher does not acquire a canonical-output-scoped operation lock.'
        Assert-True ($lockStart -lt $destructivePublish) 'Publisher acquires its operation lock after destructive work begins.'
        Assert-True ($lockRelease -gt $destructivePublish) 'Publisher releases its operation lock before destructive work ends.'
    }

    Invoke-Test 'Publisher rejects repository, artifacts root, and unowned existing outputs' {
        Assert-Throws {
            Assert-OpenTimeStampPublishOutputSafe -OutputPath $repositoryRoot -RepositoryRoot $repositoryRoot
        } 'The repository root was accepted as a publish output.'
        Assert-Throws {
            Assert-OpenTimeStampPublishOutputSafe -OutputPath (Join-Path $repositoryRoot 'artifacts') `
                -RepositoryRoot $repositoryRoot
        } 'The artifacts root was accepted as a publish output.'

        $unowned = Join-Path $testRoot 'unowned-empty-output'
        New-Item -ItemType Directory -Path $unowned | Out-Null
        Assert-Throws {
            Assert-OpenTimeStampPublishOutputSafe -OutputPath $unowned -RepositoryRoot $repositoryRoot
        } 'An existing empty but unowned output was accepted.'
    }

    Invoke-Test 'Legacy publish adoption is limited to the recognized historical default' {
        $legacyRepository = Join-Path $testRoot 'legacy-publish-repository'
        $legacyOutput = Join-Path $legacyRepository 'artifacts\OpenTimeStamp'
        New-TestPayload -Path $legacyOutput
        New-Item -ItemType Directory -Path (Join-Path $legacyOutput 'App_Data') | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $legacyOutput 'App_Data\.gitkeep'), '')

        Assert-Throws {
            Assert-OpenTimeStampPublishOutputSafe -OutputPath $legacyOutput `
                -RepositoryRoot $legacyRepository
        } 'An unmarked legacy output was accepted without explicit adoption.'
        Assert-Equal ([System.IO.Path]::GetFullPath($legacyOutput)) `
            (Assert-OpenTimeStampPublishOutputSafe -OutputPath $legacyOutput `
                -RepositoryRoot $legacyRepository -AllowLegacyDefaultOutput) `
            'The recognized historical default could not be explicitly adopted.'

        Write-OpenTimeStampPublishMarker -OutputPath $legacyOutput | Out-Null
        Assert-Equal ([System.IO.Path]::GetFullPath($legacyOutput)) `
            (Assert-OpenTimeStampPublishOutputSafe -OutputPath $legacyOutput `
                -RepositoryRoot $legacyRepository) `
            'The adopted historical output was not accepted as owned staging.'
    }

    Invoke-Test 'Legacy publish adoption rejects unexpected files and runtime state' {
        $unexpectedRepository = Join-Path $testRoot 'unexpected-legacy-repository'
        $unexpectedOutput = Join-Path $unexpectedRepository 'artifacts\OpenTimeStamp'
        New-TestPayload -Path $unexpectedOutput
        [System.IO.File]::WriteAllText((Join-Path $unexpectedOutput 'unrelated.txt'), 'preserve')
        Assert-Throws {
            Assert-OpenTimeStampPublishOutputSafe -OutputPath $unexpectedOutput `
                -RepositoryRoot $unexpectedRepository -AllowLegacyDefaultOutput
        } 'A legacy output containing an unexpected file was adopted.'

        $stateRepository = Join-Path $testRoot 'stateful-legacy-repository'
        $stateOutput = Join-Path $stateRepository 'artifacts\OpenTimeStamp'
        New-TestPayload -Path $stateOutput
        New-Item -ItemType Directory -Path (Join-Path $stateOutput 'App_Data') | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $stateOutput 'App_Data\issuance.state'), 'state')
        Assert-Throws {
            Assert-OpenTimeStampPublishOutputSafe -OutputPath $stateOutput `
                -RepositoryRoot $stateRepository -AllowLegacyDefaultOutput
        } 'A legacy output containing runtime App_Data state was adopted.'

        $otherOutput = Join-Path $stateRepository 'artifacts\OtherProduct'
        New-TestPayload -Path $otherOutput
        Assert-Throws {
            Assert-OpenTimeStampPublishOutputSafe -OutputPath $otherOutput `
                -RepositoryRoot $stateRepository -AllowLegacyDefaultOutput
        } 'A non-default legacy output was adopted.'
    }

    Invoke-Test 'Legacy publish adoption validates an unmarked manifested output' {
        $manifestRepository = Join-Path $testRoot 'manifested-legacy-repository'
        $manifestOutput = Join-Path $manifestRepository 'artifacts\OpenTimeStamp'
        New-TestPayload -Path $manifestOutput
        New-OpenTimeStampDeploymentManifest -PayloadPath $manifestOutput `
            -ReleaseId '20260717010109Z-0123456789ab' | Out-Null
        $unmanifestedDirectory = Join-Path $manifestOutput 'unexpected-empty-directory'
        New-Item -ItemType Directory -Path $unmanifestedDirectory | Out-Null
        Assert-Throws {
            Assert-OpenTimeStampPublishOutputSafe -OutputPath $manifestOutput `
                -RepositoryRoot $manifestRepository -AllowLegacyDefaultOutput
        } 'An unmanifested empty directory in a destructive-adoption target was accepted.'
        Remove-Item -LiteralPath $unmanifestedDirectory -Force
        Assert-Equal ([System.IO.Path]::GetFullPath($manifestOutput)) `
            (Assert-OpenTimeStampPublishOutputSafe -OutputPath $manifestOutput `
                -RepositoryRoot $manifestRepository -AllowLegacyDefaultOutput) `
            'A valid unmarked manifested predecessor output could not be adopted.'

        [System.IO.File]::AppendAllText((Join-Path $manifestOutput 'bin\OpenTimeStamp.Web.dll'), 'tampered')
        Assert-Throws {
            Assert-OpenTimeStampPublishOutputSafe -OutputPath $manifestOutput `
                -RepositoryRoot $manifestRepository -AllowLegacyDefaultOutput
        } 'A tampered unmarked manifested predecessor output was adopted.'
    }

    Invoke-Test 'IIS shared-configuration detection fails closed before mutation' {
        $disabledPath = Join-Path $testRoot 'redirection-disabled.config'
        $defaultPath = Join-Path $testRoot 'redirection-default.config'
        $enabledPath = Join-Path $testRoot 'redirection-enabled.config'
        $invalidPath = Join-Path $testRoot 'redirection-invalid.config'
        [System.IO.File]::WriteAllText(
            $disabledPath, '<configuration><configurationRedirection enabled="false" /></configuration>')
        [System.IO.File]::WriteAllText(
            $defaultPath, '<configuration><configurationRedirection /></configuration>')
        [System.IO.File]::WriteAllText(
            $enabledPath, '<configuration><configurationRedirection enabled="true" /></configuration>')
        [System.IO.File]::WriteAllText(
            $invalidPath, '<configuration><configurationRedirection enabled="sometimes" /></configuration>')

        Assert-True (-not (Test-OpenTimeStampIisSharedConfigurationEnabled `
                -RedirectionConfigPath $disabledPath)) 'Disabled IIS redirection was reported as enabled.'
        Assert-True (-not (Test-OpenTimeStampIisSharedConfigurationEnabled `
                -RedirectionConfigPath $defaultPath)) 'Default IIS redirection was reported as enabled.'
        Assert-True (Test-OpenTimeStampIisSharedConfigurationEnabled `
                -RedirectionConfigPath $enabledPath) 'Enabled IIS redirection was not detected.'
        Assert-Throws {
            Assert-OpenTimeStampIisSharedConfigurationDisabled -RedirectionConfigPath $enabledPath
        } 'Enabled IIS Shared Configuration was accepted.'
        Assert-Throws {
            Test-OpenTimeStampIisSharedConfigurationEnabled -RedirectionConfigPath $invalidPath
        } 'An invalid IIS redirection state was treated as disabled.'

        Assert-OpenTimeStampIisProcessBitness `
            -Is64BitOperatingSystem $false -Is64BitProcess $false
        Assert-OpenTimeStampIisProcessBitness `
            -Is64BitOperatingSystem $true -Is64BitProcess $true
        Assert-Throws {
            Assert-OpenTimeStampIisProcessBitness `
                -Is64BitOperatingSystem $true -Is64BitProcess $false
        } 'A 32-bit deployment process was accepted on 64-bit Windows.'
    }

    Invoke-Test 'Partial IIS application rollback admits only the exact installer selection' {
        $releasePath = Join-Path $testRoot 'rollback-release'
        $rootVirtualDirectory = [PSCustomObject]@{ path = '/'; physicalPath = $releasePath }
        $extraVirtualDirectory = [PSCustomObject]@{
            path = '/content'
            physicalPath = (Join-Path $testRoot 'external-content')
        }
        Assert-True (Test-OpenTimeStampNewIisApplicationRollbackCandidate `
                -ApplicationPresent $true -SelectionMatches $true `
                -VirtualDirectories @($rootVirtualDirectory) -ExpectedPhysicalPath $releasePath) `
            'A matching application committed before New-WebApplication failed would be preserved.'
        Assert-True (-not (Test-OpenTimeStampNewIisApplicationRollbackCandidate `
                -ApplicationPresent $false -SelectionMatches $true `
                -VirtualDirectories @($rootVirtualDirectory) -ExpectedPhysicalPath $releasePath)) `
            'Rollback would remove a missing application.'
        Assert-True (-not (Test-OpenTimeStampNewIisApplicationRollbackCandidate `
                -ApplicationPresent $true -SelectionMatches $false `
                -VirtualDirectories @($rootVirtualDirectory) -ExpectedPhysicalPath $releasePath)) `
            'Rollback would remove an externally changed application.'
        Assert-True (-not (Test-OpenTimeStampNewIisApplicationRollbackCandidate `
                -ApplicationPresent $true -SelectionMatches $true -VirtualDirectories @() `
                -ExpectedPhysicalPath $releasePath)) `
            'Rollback accepted an application without its mandatory root virtual directory.'
        Assert-True (-not (Test-OpenTimeStampNewIisApplicationRollbackCandidate `
                -ApplicationPresent $true -SelectionMatches $true `
                -VirtualDirectories @($rootVirtualDirectory, $extraVirtualDirectory) `
                -ExpectedPhysicalPath $releasePath)) `
            'Rollback would remove an application containing an additional virtual directory.'
        $wrongRoot = [PSCustomObject]@{ path = '/'; physicalPath = (Join-Path $testRoot 'other-release') }
        Assert-True (-not (Test-OpenTimeStampNewIisApplicationRollbackCandidate `
                -ApplicationPresent $true -SelectionMatches $true -VirtualDirectories @($wrongRoot) `
                -ExpectedPhysicalPath $releasePath)) `
            'Rollback accepted a root virtual directory mapped to another physical path.'
    }

    Invoke-Test 'Critical IIS preconditions and partial rollback are structurally wired' {
        $installerPath = Join-Path $repositoryRoot 'deploy\Install-IisApplication.ps1'
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $installerPath, [ref]$tokens, [ref]$parseErrors)
        Assert-Equal 0 @($parseErrors).Count 'Installer could not be parsed for structural checks.'
        $commands = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.CommandAst]
                }, $true))
        $topLevelCommands = @($commands | Where-Object {
                $ancestor = $_.Parent
                while ($null -ne $ancestor) {
                    if ($ancestor -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
                        return $false
                    }
                    $ancestor = $ancestor.Parent
                }
                return $true
            })

        $bitnessCalls = @($topLevelCommands | Where-Object {
                $_.GetCommandName() -eq 'Assert-OpenTimeStampIisProcessBitness'
            })
        $sharedConfigurationCalls = @($topLevelCommands | Where-Object {
                $_.GetCommandName() -eq 'Assert-OpenTimeStampIisSharedConfigurationDisabled'
            })
        $serverManagerImports = @($topLevelCommands | Where-Object {
                $_.GetCommandName() -eq 'Import-Module' -and $_.Extent.Text -match '\bServerManager\b'
            })
        $featureMutations = @($topLevelCommands | Where-Object {
                $_.GetCommandName() -eq 'Install-WindowsFeature'
            })
        Assert-Equal 1 $bitnessCalls.Count 'Installer must contain one top-level process-bitness precondition.'
        Assert-Equal 1 $sharedConfigurationCalls.Count `
            'Installer must contain one top-level Shared Configuration precondition.'
        Assert-Equal 1 $serverManagerImports.Count 'Installer ServerManager import could not be identified.'
        Assert-Equal 1 $featureMutations.Count 'Installer feature mutation could not be identified.'
        Assert-True ($bitnessCalls[0].Extent.StartOffset -lt
            $sharedConfigurationCalls[0].Extent.StartOffset) `
            'Shared Configuration is read before the process-bitness precondition.'
        Assert-True ($sharedConfigurationCalls[0].Extent.StartOffset -lt
            $serverManagerImports[0].Extent.StartOffset) `
            'ServerManager is imported before the Shared Configuration precondition.'
        Assert-True ($sharedConfigurationCalls[0].Extent.StartOffset -lt
            $featureMutations[0].Extent.StartOffset) `
            'IIS role services can be mutated before the Shared Configuration precondition.'

        $rollbackCalls = @($topLevelCommands | Where-Object {
                $_.GetCommandName() -eq 'Test-OpenTimeStampNewIisApplicationRollbackCandidate'
            })
        Assert-Equal 2 $rollbackCalls.Count `
            'Both returned and partial New-WebApplication rollback paths must use the ownership helper.'
        foreach ($call in $rollbackCalls) {
            foreach ($parameter in @('-ApplicationPresent', '-SelectionMatches',
                    '-VirtualDirectories', '-ExpectedPhysicalPath')) {
                Assert-True ($call.Extent.Text -match [regex]::Escape($parameter)) `
                    "Partial-application rollback call omits '$parameter'."
            }

            $ancestor = $call.Parent
            $catch = $null
            $decision = $null
            while ($null -ne $ancestor) {
                if ($null -eq $decision -and
                    $ancestor -is [System.Management.Automation.Language.IfStatementAst]) {
                    $decision = $ancestor
                }
                if ($ancestor -is [System.Management.Automation.Language.CatchClauseAst]) {
                    $catch = $ancestor
                    break
                }
                $ancestor = $ancestor.Parent
            }
            Assert-True ($null -ne $catch) 'Partial-application removal is not confined to deployment failure handling.'
            Assert-True ($null -ne $decision -and $decision.Extent.Text -match '\bRemove-WebApplication\b') `
                'The guarded partial-application decision is not the condition controlling removal.'
        }
    }

    Invoke-Test 'Publish ownership is bound to one canonical staging path' {
        $owned = Join-Path $testRoot 'owned-output'
        $transplanted = Join-Path $testRoot 'transplanted-output'
        Write-OpenTimeStampPublishMarker -OutputPath $owned | Out-Null
        Assert-Equal ([System.IO.Path]::GetFullPath($owned)) `
            (Assert-OpenTimeStampPublishOutputSafe -OutputPath $owned -RepositoryRoot $repositoryRoot) `
            'The owned staging output was rejected.'
        Assert-OpenTimeStampPublishMarker -OutputPath ($owned + '\') | Out-Null
        Assert-Equal ([System.IO.Path]::GetFullPath($owned)) `
            (Assert-OpenTimeStampPublishOutputSafe -OutputPath ($owned + '\') -RepositoryRoot $repositoryRoot) `
            'The same publish output with a trailing separator was rejected.'

        New-Item -ItemType Directory -Path $transplanted | Out-Null
        Copy-Item -LiteralPath (Join-Path $owned $script:OpenTimeStampPublishMarkerName) `
            -Destination (Join-Path $transplanted $script:OpenTimeStampPublishMarkerName)
        Assert-Throws {
            Assert-OpenTimeStampPublishOutputSafe -OutputPath $transplanted -RepositoryRoot $repositoryRoot
        } 'A publish ownership marker transplanted to another path was accepted.'
    }

    Invoke-Test 'Publish marker is excluded from deployed manifests and staged releases' {
        $payload = Join-Path $testRoot 'publish-marker-source'
        $stage = Join-Path $testRoot 'publish-marker-stage'
        New-TestPayload -Path $payload
        Write-OpenTimeStampPublishMarker -OutputPath $payload | Out-Null
        New-OpenTimeStampDeploymentManifest -PayloadPath $payload `
            -ReleaseId '20260717010107Z-0123456789ab' | Out-Null
        Assert-Throws {
            Assert-OpenTimeStampPublishedPayload -PayloadPath $payload | Out-Null
        } 'A publish marker was accepted as part of a deployed release.'
        $manifest = Assert-OpenTimeStampPublishedPayload -PayloadPath $payload -AllowPublishMarker
        Assert-Equal 4 @($manifest.Files).Count 'The publish marker entered the deployment manifest.'
        Copy-OpenTimeStampPublishedPayload -PayloadPath $payload -DestinationPath $stage -Manifest $manifest
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $stage $script:OpenTimeStampPublishMarkerName))) `
            'The publish marker was copied into a staged release.'
        Assert-OpenTimeStampPublishedPayload -PayloadPath $stage | Out-Null
    }

    Invoke-Test 'A manifested live release without publish ownership is rejected as output' {
        $release = Join-Path $testRoot 'live-release-shape'
        New-TestPayload -Path $release
        New-OpenTimeStampDeploymentManifest -PayloadPath $release `
            -ReleaseId '20260717010108Z-0123456789ab' | Out-Null
        Assert-Throws {
            Assert-OpenTimeStampPublishOutputSafe -OutputPath $release -RepositoryRoot $repositoryRoot
        } 'A manifested live-release shape without staging ownership was accepted.'
    }

    Invoke-Test 'Publisher rejects an absent output below a marked deployment root' {
        $deploymentRoot = Join-Path $testRoot 'marked-deployment'
        $nestedOutput = Join-Path $deploymentRoot 'Releases\new-stage'
        New-Item -ItemType Directory -Path (Join-Path $deploymentRoot 'Releases') -Force | Out-Null
        [System.IO.File]::WriteAllText(
            (Join-Path $deploymentRoot $script:OpenTimeStampDeploymentMarkerName),
            '{"Product":"OpenTimeStamp","SchemaVersion":1}')
        Assert-Throws {
            Assert-OpenTimeStampPublishOutputSafe -OutputPath $nestedOutput -RepositoryRoot $repositoryRoot
        } 'An absent output under a marked deployment Releases tree was accepted.'
    }

    Invoke-Test 'Publish parent ancestry check ignores unrelated sibling reparse points' {
        $parent = Join-Path $testRoot 'publish-parent-with-unrelated-junction'
        $unrelatedTarget = Join-Path $testRoot 'unrelated-junction-target'
        $unrelatedJunction = Join-Path $parent 'unrelated-junction'
        New-Item -ItemType Directory -Path $parent | Out-Null
        New-Item -ItemType Directory -Path $unrelatedTarget | Out-Null
        New-Item -ItemType Junction -Path $unrelatedJunction -Target $unrelatedTarget | Out-Null

        Assert-OpenTimeStampNoReparsePoints -Root $parent -AncestryOnly
        Assert-Throws { Assert-OpenTimeStampNoReparsePoints -Root $parent } `
            'Recursive controlled-tree validation ignored an unrelated reparse point.'

        $publish = Get-Content -LiteralPath (Join-Path $repositoryRoot 'build\Publish.ps1') -Raw
        Assert-True ($publish -match 'Assert-OpenTimeStampNoReparsePoints -Root \$outputParent -AncestryOnly') `
            'Publisher still recursively scans unrelated output-parent siblings.'
    }

    Invoke-Test 'Manifest detects a changed release file' {
        $payload = Join-Path $testRoot 'changed-payload'
        New-TestPayload -Path $payload
        New-OpenTimeStampDeploymentManifest -PayloadPath $payload `
            -ReleaseId '20260717010102Z-0123456789ab' | Out-Null
        [System.IO.File]::AppendAllText((Join-Path $payload 'bin\OpenTimeStamp.Web.dll'), 'tampered')
        Assert-Throws { Assert-OpenTimeStampPublishedPayload -PayloadPath $payload | Out-Null } `
            'A changed file was accepted by the manifest validator.'
    }

    Invoke-Test 'Staging copies and revalidates the complete manifested payload' {
        $payload = Join-Path $testRoot 'copy-source'
        $stage = Join-Path $testRoot 'copy-stage'
        New-TestPayload -Path $payload
        New-OpenTimeStampDeploymentManifest -PayloadPath $payload `
            -ReleaseId '20260717010104Z-0123456789ab' | Out-Null
        $manifest = Assert-OpenTimeStampPublishedPayload -PayloadPath $payload
        Copy-OpenTimeStampPublishedPayload -PayloadPath $payload -DestinationPath $stage -Manifest $manifest
        Assert-True (Test-Path -LiteralPath (Join-Path $stage $script:OpenTimeStampDeploymentManifestName) -PathType Leaf) `
            'The staging copy omitted its deployment manifest.'
        $copied = Assert-OpenTimeStampPublishedPayload -PayloadPath $stage
        Assert-Equal ([string]$manifest.ReleaseId) ([string]$copied.ReleaseId) `
            'The staging manifest release identifier changed.'
    }

    Invoke-Test 'A failed staging validation removes only its newly created stage' {
        $payload = Join-Path $testRoot 'failed-copy-source'
        $stage = Join-Path $testRoot 'failed-copy-stage'
        New-TestPayload -Path $payload
        New-OpenTimeStampDeploymentManifest -PayloadPath $payload `
            -ReleaseId '20260717010105Z-0123456789ab' | Out-Null
        $manifest = Assert-OpenTimeStampPublishedPayload -PayloadPath $payload
        [System.IO.File]::AppendAllText((Join-Path $payload 'bin\OpenTimeStamp.Core.dll'), 'changed')
        Assert-Throws {
            Copy-OpenTimeStampPublishedPayload -PayloadPath $payload -DestinationPath $stage -Manifest $manifest
        } 'A changed source payload was staged.'
        Assert-True (-not (Test-Path -LiteralPath $stage)) `
            'A staging directory created by a failed copy was left behind.'
    }

    Invoke-Test 'Staging never removes a pre-existing destination' {
        $payload = Join-Path $testRoot 'existing-stage-source'
        $stage = Join-Path $testRoot 'pre-existing-stage'
        New-TestPayload -Path $payload
        New-OpenTimeStampDeploymentManifest -PayloadPath $payload `
            -ReleaseId '20260717010106Z-0123456789ab' | Out-Null
        $manifest = Assert-OpenTimeStampPublishedPayload -PayloadPath $payload
        New-Item -ItemType Directory -Path $stage | Out-Null
        $sentinel = Join-Path $stage 'belongs-to-someone-else.txt'
        [System.IO.File]::WriteAllText($sentinel, 'preserve')
        Assert-Throws {
            Copy-OpenTimeStampPublishedPayload -PayloadPath $payload -DestinationPath $stage -Manifest $manifest
        } 'A pre-existing staging destination was accepted.'
        Assert-True (Test-Path -LiteralPath $sentinel -PathType Leaf) `
            'A pre-existing staging destination was removed.'
    }

    Invoke-Test 'Manifest rejects unmanifested files' {
        $payload = Join-Path $testRoot 'extra-payload'
        New-TestPayload -Path $payload
        New-OpenTimeStampDeploymentManifest -PayloadPath $payload `
            -ReleaseId '20260717010103Z-0123456789ab' | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $payload 'obsolete.dll'), 'stale')
        Assert-Throws { Assert-OpenTimeStampPublishedPayload -PayloadPath $payload | Out-Null } `
            'An unmanifested stale file was accepted.'
    }

    Invoke-Test 'Publisher refuses App_Data content' {
        $payload = Join-Path $testRoot 'stateful-payload'
        New-TestPayload -Path $payload
        New-Item -ItemType Directory -Path (Join-Path $payload 'App_Data') | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $payload 'App_Data\issuance.state'), [byte[]](0x4f, 0x54, 0x53, 0x31))
        Assert-Throws { New-OpenTimeStampDeploymentManifest -PayloadPath $payload | Out-Null } `
            'Mutable App_Data was included in a release.'
    }

    Invoke-Test 'Manifest rejects even an empty App_Data directory' {
        $payload = Join-Path $testRoot 'empty-app-data-payload'
        New-TestPayload -Path $payload
        New-Item -ItemType Directory -Path (Join-Path $payload 'App_Data') | Out-Null
        Assert-Throws { New-OpenTimeStampDeploymentManifest -PayloadPath $payload | Out-Null } `
            'An empty mutable App_Data directory was included in a release.'
    }

    Invoke-Test 'Logs alone cannot identify or adopt a data directory' {
        $emptyData = Join-Path $testRoot 'empty-logs-only'
        New-Item -ItemType Directory -Path (Join-Path $emptyData 'Logs') -Force | Out-Null
        Assert-Equal 'Unrecognized' (Get-OpenTimeStampDataDirectoryClassification -Path $emptyData).Kind `
            'A generic empty Logs directory was treated as owned scaffolding.'

        $data = Join-Path $testRoot 'logs-only'
        New-Item -ItemType Directory -Path (Join-Path $data 'Logs') -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $data 'Logs\timestamp-20260717.jsonl'), '{}')
        $classification = Get-OpenTimeStampDataDirectoryClassification -Path $data
        Assert-Equal 'Unrecognized' $classification.Kind 'Logs-only classification differs.'
        Assert-Throws { Initialize-OpenTimeStampDataDirectory -Path $data -AdoptExisting | Out-Null } `
            'A generic Logs directory was adopted.'
    }

    Invoke-Test 'Owned directory initialization reports only directories it creates' {
        $parent = Join-Path $testRoot 'owned-directory-parent'
        $existing = Join-Path $parent 'existing'
        $created = Join-Path $parent 'created'
        New-Item -ItemType Directory -Path $existing -Force | Out-Null

        $existingResult = Initialize-OpenTimeStampOwnedDirectory -Path $existing
        Assert-True (-not [bool]$existingResult.Created) `
            'A pre-existing directory was incorrectly claimed by the installer.'
        $createdResult = Initialize-OpenTimeStampOwnedDirectory -Path $created
        Assert-True ([bool]$createdResult.Created) `
            'A newly created directory was not recorded as installer-owned.'
        Assert-True (Test-Path -LiteralPath $created -PathType Container) `
            'Owned directory initialization did not create the requested directory.'

        $dataInitialization = Initialize-OpenTimeStampDataDirectory -Path $created -DirectoryCreatedByCaller
        Assert-True ([bool]$dataInitialization.DirectoryCreated) `
            'Data marker initialization lost caller-created directory ownership.'
        Assert-True ([bool]$dataInitialization.MarkerCreated) `
            'Caller-created DataPath was not marked after its directory was established.'
    }

    Invoke-Test 'Legacy gitkeep-only App_Data bootstraps as empty' {
        $data = Join-Path $testRoot 'gitkeep-only'
        New-Item -ItemType Directory -Path $data -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $data '.gitkeep'), '')
        Assert-Equal 'Empty' (Get-OpenTimeStampDataDirectoryClassification -Path $data).Kind `
            'A gitkeep-only legacy directory was not treated as empty scaffolding.'
        Initialize-OpenTimeStampDataDirectory -Path $data | Out-Null
        Assert-Equal 'Marked' (Get-OpenTimeStampDataDirectoryClassification -Path $data).Kind `
            'Gitkeep-only App_Data did not receive a marker.'
    }

    Invoke-Test 'Persistent coordination locks are recoverable scaffolding, not state evidence' {
        $data = Join-Path $testRoot 'coordination-locks-only'
        $logs = Join-Path $data 'Logs'
        New-Item -ItemType Directory -Path $logs -Force | Out-Null
        foreach ($path in @((Join-Path $data 'issuance.state.lock'),
                (Join-Path $data 'tsa.config.lock'), (Join-Path $logs '.audit.lock'))) {
            [System.IO.File]::WriteAllText($path, '')
        }

        Assert-Equal 'Empty' (Get-OpenTimeStampDataDirectoryClassification -Path $data).Kind `
            'Lock-only interrupted initialization was mistaken for issuance or configuration payload.'
        $initialization = Initialize-OpenTimeStampDataDirectory -Path $data
        $classification = Get-OpenTimeStampDataDirectoryClassification -Path $data
        Assert-Equal 'Marked' $classification.Kind `
            'Recoverable lock-only scaffolding could not be initialized safely.'
        Assert-Equal $false ([bool]$classification.Marker.IssuanceStateInitialized) `
            'A fresh lock-only data marker was incorrectly recorded as initialized.'
        Assert-True (Test-OpenTimeStampDataDirectoryUninitializedScaffolding `
                -Classification $classification) `
            'An exact false-marker lock-only retry was not recognized.'
        foreach ($path in @((Join-Path $data 'issuance.state.lock'),
                (Join-Path $data 'tsa.config.lock'), (Join-Path $logs '.audit.lock'))) {
            Assert-True (Test-Path -LiteralPath $path -PathType Leaf) `
                "Persistent coordination lock '$path' was deleted during data initialization."
        }

        Set-OpenTimeStampDataDirectoryIssuanceInitialized -Path $data `
            -ExpectedDataDirectoryId ([string]$initialization.MarkerId) | Out-Null
        $classification = Get-OpenTimeStampDataDirectoryClassification -Path $data
        Assert-Equal $true ([bool]$classification.Marker.IssuanceStateInitialized) `
            'The data marker lifecycle was not committed atomically.'
        Assert-True (-not (Test-OpenTimeStampDataDirectoryUninitializedScaffolding `
                -Classification $classification)) `
            'A true marker containing only locks was accepted for state reseeding.'
    }

    Invoke-Test 'Data marker lifecycle retries fail closed outside exact fresh scaffolding' {
        $preInitializeData = Join-Path $testRoot 'marker-before-state-initializer'
        Initialize-OpenTimeStampDataDirectory -Path $preInitializeData | Out-Null
        $preInitializeClassification = Get-OpenTimeStampDataDirectoryClassification `
            -Path $preInitializeData
        Assert-True (Test-OpenTimeStampDataDirectoryUninitializedScaffolding `
                -Classification $preInitializeClassification) `
            'A process stop immediately after writing the fresh marker cannot be retried.'
        New-Item -ItemType Directory -Path (Join-Path $preInitializeData 'Logs') | Out-Null
        $preInitializeClassification = Get-OpenTimeStampDataDirectoryClassification `
            -Path $preInitializeData
        Assert-True (Test-OpenTimeStampDataDirectoryUninitializedScaffolding `
                -Classification $preInitializeClassification) `
            'A process stop after creating the empty Logs scaffold cannot be retried.'

        $missingData = Join-Path $testRoot 'coordination-locks-missing-lifecycle'
        New-Item -ItemType Directory -Path $missingData -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $missingData 'issuance.state.lock'), '')
        Initialize-OpenTimeStampDataDirectory -Path $missingData | Out-Null
        $missingMarkerPath = Join-Path $missingData '.opentimestamp-data.json'
        $marker = Get-Content -LiteralPath $missingMarkerPath -Raw | ConvertFrom-Json
        $marker.PSObject.Properties.Remove('IssuanceStateInitialized')
        $encoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText(
            $missingMarkerPath, (($marker | ConvertTo-Json -Depth 3) + [Environment]::NewLine), $encoding)
        $missingClassification = Get-OpenTimeStampDataDirectoryClassification -Path $missingData
        Assert-True (-not (Test-OpenTimeStampDataDirectoryUninitializedScaffolding `
                -Classification $missingClassification)) `
            'A legacy marker missing lifecycle state was allowed to reseed from locks alone.'

        foreach ($invalidValue in @('false', $null)) {
            $marker | Add-Member -NotePropertyName IssuanceStateInitialized `
                -NotePropertyValue $invalidValue -Force
            [System.IO.File]::WriteAllText(
                $missingMarkerPath, (($marker | ConvertTo-Json -Depth 3) + [Environment]::NewLine), $encoding)
            Assert-Throws { Get-OpenTimeStampDataDirectoryClassification -Path $missingData | Out-Null } `
                'A non-Boolean issuance-state lifecycle value was accepted.'
        }

        $stateData = Join-Path $testRoot 'state-created-before-lifecycle-commit'
        New-Item -ItemType Directory -Path $stateData -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $stateData 'issuance.state.lock'), '')
        $stateInitialization = Initialize-OpenTimeStampDataDirectory -Path $stateData
        $state = New-Object byte[] 28
        $state[0] = 0x4f; $state[1] = 0x54; $state[2] = 0x53; $state[3] = 0x31
        [System.IO.File]::WriteAllBytes((Join-Path $stateData 'issuance.state'), $state)
        $stateClassification = Get-OpenTimeStampDataDirectoryClassification -Path $stateData
        Assert-Equal $false ([bool]$stateClassification.Marker.IssuanceStateInitialized) `
            'A crash-window marker unexpectedly changed before lifecycle commit.'
        Assert-True (-not (Test-OpenTimeStampDataDirectoryUninitializedScaffolding `
                -Classification $stateClassification)) `
            'A false marker with issuance payload was mistaken for lock-only scaffolding.'
        Set-OpenTimeStampDataDirectoryIssuanceInitialized -Path $stateData `
            -ExpectedDataDirectoryId ([string]$stateInitialization.MarkerId) | Out-Null
        Assert-Equal $true ([bool](Get-OpenTimeStampDataDirectoryClassification `
                    -Path $stateData).Marker.IssuanceStateInitialized) `
            'A crash-window marker could not be completed after state became durable.'
    }

    Invoke-Test 'Legacy data accepts only zero-content persistent coordination locks' {
        $data = Join-Path $testRoot 'legacy-state-with-locks'
        $logs = Join-Path $data 'Logs'
        New-Item -ItemType Directory -Path $logs -Force | Out-Null
        $state = New-Object byte[] 28
        $state[0] = 0x4f; $state[1] = 0x54; $state[2] = 0x53; $state[3] = 0x31
        [System.IO.File]::WriteAllBytes((Join-Path $data 'issuance.state'), $state)
        [System.IO.File]::WriteAllText((Join-Path $data 'issuance.state.lock'), '')
        [System.IO.File]::WriteAllText((Join-Path $data 'tsa.config.lock'), '')
        [System.IO.File]::WriteAllText((Join-Path $logs '.audit.lock'), '')
        [System.IO.File]::WriteAllText((Join-Path $logs 'timestamp-20260717.jsonl'), '{}')
        [System.IO.File]::WriteAllText((Join-Path $logs 'timestamp-20260717-23.jsonl'), '{}')
        Assert-Equal 'Legacy' (Get-OpenTimeStampDataDirectoryClassification -Path $data).Kind `
            'Valid legacy state with persistent locks was not recognized.'

        [System.IO.File]::WriteAllText((Join-Path $data 'issuance.state.lock'), 'unexpected-content')
        Assert-Equal 'Unrecognized' (Get-OpenTimeStampDataDirectoryClassification -Path $data).Kind `
            'A nonempty coordination lock was accepted as a persistent lock artifact.'
    }

    Invoke-Test 'Exact legacy state requires explicit adoption and becomes marked' {
        $data = Join-Path $testRoot 'legacy-state'
        New-Item -ItemType Directory -Path $data -Force | Out-Null
        $state = New-Object byte[] 28
        $state[0] = 0x4f; $state[1] = 0x54; $state[2] = 0x53; $state[3] = 0x31
        [System.IO.File]::WriteAllBytes((Join-Path $data 'issuance.state'), $state)
        Assert-Equal 'Legacy' (Get-OpenTimeStampDataDirectoryClassification -Path $data).Kind `
            'Exact legacy state was not recognized.'
        Assert-Throws { Initialize-OpenTimeStampDataDirectory -Path $data | Out-Null } `
            'Legacy state was adopted without the explicit switch.'
        Initialize-OpenTimeStampDataDirectory -Path $data -AdoptExisting | Out-Null
        $classification = Get-OpenTimeStampDataDirectoryClassification -Path $data
        Assert-Equal 'Marked' $classification.Kind `
            'Adopted data directory was not marked.'
        Assert-Equal $true ([bool]$classification.Marker.IssuanceStateInitialized) `
            'Adopted legacy issuance state was recorded as a fresh uninitialized directory.'
    }

    Invoke-Test 'Unexpected legacy siblings prevent adoption' {
        $data = Join-Path $testRoot 'ambiguous-state'
        New-Item -ItemType Directory -Path $data -Force | Out-Null
        $state = New-Object byte[] 28
        $state[0] = 0x4f; $state[1] = 0x54; $state[2] = 0x53; $state[3] = 0x31
        [System.IO.File]::WriteAllBytes((Join-Path $data 'issuance.state'), $state)
        [System.IO.File]::WriteAllText((Join-Path $data 'other-product.db'), 'not ours')
        Assert-Equal 'Unrecognized' (Get-OpenTimeStampDataDirectoryClassification -Path $data).Kind `
            'An ambiguous directory was classified as legacy OpenTimeStamp data.'
    }

    Invoke-Test 'Data ownership marker cannot be transplanted to another path' {
        $original = Join-Path $testRoot 'marked-data-original'
        $transplant = Join-Path $testRoot 'marked-data-transplant'
        Initialize-OpenTimeStampDataDirectory -Path $original | Out-Null
        Assert-Equal 'Marked' (Get-OpenTimeStampDataDirectoryClassification -Path ($original + '\')).Kind `
            'The same data directory with a trailing separator was rejected.'
        New-Item -ItemType Directory -Path $transplant | Out-Null
        Copy-Item -LiteralPath (Join-Path $original '.opentimestamp-data.json') -Destination $transplant
        Assert-Throws { Get-OpenTimeStampDataDirectoryClassification -Path $transplant | Out-Null } `
            'A data ownership marker copied to another path was accepted.'
    }

    Invoke-Test 'Deployment ownership marker cannot be transplanted to another path' {
        $original = Join-Path $testRoot 'marked-deployment-original'
        $transplant = Join-Path $testRoot 'marked-deployment-transplant'
        New-Item -ItemType Directory -Path $original | Out-Null
        New-Item -ItemType Directory -Path $transplant | Out-Null
        $marker = [ordered]@{
            Product = 'OpenTimeStamp'; SchemaVersion = 1
            DeploymentId = [Guid]::NewGuid().ToString('D')
            DeploymentRoot = [System.IO.Path]::GetFullPath($original)
        }
        $marker | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $original '.opentimestamp-deployment.json')
        Assert-True (Test-OpenTimeStampDeploymentRootMarker -Path ($original + '\')) `
            'The same deployment root with a trailing separator was rejected.'
        Copy-Item -LiteralPath (Join-Path $original '.opentimestamp-deployment.json') -Destination $transplant
        Assert-Throws { Test-OpenTimeStampDeploymentRootMarker -Path $transplant | Out-Null } `
            'A deployment ownership marker copied to another path was accepted.'
    }

    Invoke-Test 'Legacy artifact names must also have exact file and directory shapes' {
        $data = Join-Path $testRoot 'wrong-artifact-shape'
        New-Item -ItemType Directory -Path $data -Force | Out-Null
        $state = New-Object byte[] 28
        $state[0] = 0x4f; $state[1] = 0x54; $state[2] = 0x53; $state[3] = 0x31
        [System.IO.File]::WriteAllBytes((Join-Path $data 'issuance.state'), $state)
        [System.IO.File]::WriteAllText((Join-Path $data 'Logs'), 'not a log directory')
        Assert-Equal 'Unrecognized' (Get-OpenTimeStampDataDirectoryClassification -Path $data).Kind `
            'A legacy artifact with the wrong filesystem type was accepted.'
    }

    Invoke-Test 'Deployment scripts parse under the Windows PowerShell grammar' {
        $scripts = @('deploy\Deployment.Common.ps1', 'deploy\Install-IisApplication.ps1',
                'deploy\Grant-TsaPrivateKeyAccess.ps1', 'deploy\Configure-AcrobatTimestamping.ps1',
                'deploy\New-DevelopmentTsaCertificate.ps1', 'build\Build.Common.ps1',
                'build\Build.ps1', 'build\Publish.ps1';
            Get-ChildItem -LiteralPath (Join-Path $repositoryRoot 'tests\ProductSigning') `
                -Filter '*.ps1' -File | ForEach-Object { $_.FullName.Substring($repositoryRoot.Length + 1) })
        foreach ($relative in $scripts) {
            $tokens = $null
            $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile(
                (Join-Path $repositoryRoot $relative), [ref]$tokens, [ref]$parseErrors)
            Assert-Equal 0 @($parseErrors).Count "PowerShell parser errors in $relative."
        }
    }

    Invoke-Test 'Product test harness has bounded processes and strict effective coverage' {
        $common = Get-Content -LiteralPath `
            (Join-Path $repositoryRoot 'tests\ProductSigning\ProductSigning.Common.ps1') -Raw
        $runner = Get-Content -LiteralPath `
            (Join-Path $repositoryRoot 'tests\ProductSigning\Invoke-ProductSigningTests.ps1') -Raw
        foreach ($token in @('TimeoutSeconds = 120', 'WaitForExit($TimeoutSeconds * 1000)',
                '$startInfo.ArgumentList.Add($argument)', '$Process.Kill($true)')) {
            Assert-True ($common -match [regex]::Escape($token)) `
                "Product native-process timeout safeguard '$token' is missing."
        }
        foreach ($token in @('RequireAllSelectedTests', 'passedCount', 'skippedCount',
                'No selected product test passed', 'Strict mode does not permit skipped')) {
            Assert-True ($runner -match [regex]::Escape($token)) `
                "Product strict-coverage safeguard '$token' is missing."
        }
    }

    Invoke-Test 'Acrobat client setup is per-user, exact, and security preserving' {
        $setupPath = Join-Path $repositoryRoot 'deploy\Configure-AcrobatTimestamping.ps1'
        $setup = Get-Content -LiteralPath $setupPath -Raw
        $installer = Get-Content -LiteralPath (Join-Path $repositoryRoot 'deploy\Install-IisApplication.ps1') -Raw
        foreach ($required in @(
                'SupportsShouldProcess = $true',
                'HKEY_CURRENT_USER\Software\Adobe\Adobe Acrobat\DC',
                'Security\cPPKHandler\cTimeStampServers',
                'Security\cASPKI\cAdobe_TSPProvider',
                "-Name 'sURL'",
                '[Microsoft.Win32.RegistryValueKind]::Binary',
                '[Text.Encoding]::ASCII.GetBytes($canonicalUrl + [char]0)',
                'Remove-TrackedRegistryValue',
                "-Name 'sHashAlgo'",
                "-Name 'iHashAlgo' -Value 2",
                "-Name 'bReqSigPropRetrieval'",
                'Restore-TrackedRegistryValues')) {
            Assert-True ($setup -match [regex]::Escape($required)) `
                "Acrobat client setup safeguard '$required' is missing."
        }
        foreach ($forbidden in @('HKEY_LOCAL_MACHINE', 'FeatureLockDown', 'iProtectedView', 'bProtectedMode',
                'bEnhancedSecurityStandalone', 'bUseWhitelistConfigFile', 'cTrustedSites', 'cCrossdomain',
                'AllowPdfInternetAccess', 'cDefaultLaunchURLPerms', 'tHostPerms', 'iURLPerms',
                'iUnknownURLPerms')) {
            Assert-True ($setup -notmatch [regex]::Escape($forbidden)) `
                "Acrobat client setup must not change broad security setting '$forbidden'."
        }
        Assert-True ($installer -notmatch 'Configure-AcrobatTimestamping') `
            'The elevated IIS server installer must not configure a signing user Acrobat hive.'
        Assert-Throws {
            & $setupPath -TimestampUrl 'http://tsa.example.test/OpenTimeStamp/timestamp/rfc3161' -WhatIf
        } 'Acrobat client setup accepted insecure HTTP without the explicit development override.'
        Assert-Throws {
            & $setupPath -TimestampUrl 'https://tsa.example.test/OpenTimeStamp/timestamp/rfc3161?unsafe=1' -WhatIf
        } 'Acrobat client setup accepted a timestamp URL containing a query.'
        Assert-Throws {
            & $setupPath -TimestampUrl 'https://tsa.example.test/OpenTimeStamp/timestamp/authenticode' -WhatIf
        } 'Acrobat client setup accepted a non-RFC3161 OpenTimeStamp endpoint.'
        & $setupPath -TimestampUrl 'https://tsa.example.test/OpenTimeStamp/timestamp/rfc3161' `
            -WhatIf 6>$null | Out-Null
        & $setupPath -TimestampUrl 'http://127.0.0.1/OpenTimeStamp/timestamp/rfc3161' `
            -AllowInsecureHttp -WhatIf 6>$null | Out-Null

        $registryTestRoot = 'Registry::HKEY_CURRENT_USER\Software\OpenTimeStamp-AcrobatSetupTests-' +
            [Guid]::NewGuid().ToString('N')
        $timestampUrl = 'https://tsa.example.test/OpenTimeStamp/timestamp/rfc3161'
        try {
            $trustManagerPath = Join-Path $registryTestRoot 'TrustManager'
            New-Item -Path $trustManagerPath -Force | Out-Null
            New-ItemProperty -LiteralPath $trustManagerPath -Name Unrelated -Value preserve `
                -PropertyType String | Out-Null
            $providerPath = Join-Path $registryTestRoot 'Security\cASPKI\cAdobe_TSPProvider'
            New-Item -Path $providerPath -Force | Out-Null
            New-ItemProperty -LiteralPath $providerPath -Name sHashAlgo `
                -Value ([Text.Encoding]::ASCII.GetBytes('1.3.14.3.2.26' + [char]0)) -PropertyType Binary | Out-Null
            $existingServerPath = Join-Path $registryTestRoot 'Security\cPPKHandler\cTimeStampServers\c7'
            New-Item -Path $existingServerPath -Force | Out-Null
            New-ItemProperty -LiteralPath $existingServerPath -Name tName -Value OpenTimeStamp `
                -PropertyType String | Out-Null
            New-ItemProperty -LiteralPath $existingServerPath -Name tServer `
                -Value 'https://TSA.EXAMPLE.TEST:443/OpenTimeStamp/timestamp/rfc3161' `
                -PropertyType String | Out-Null

            $result = & $setupPath -TimestampUrl $timestampUrl -RegistryRoot $registryTestRoot
            Assert-Equal $timestampUrl $result.TimestampUrl 'Acrobat setup returned a different canonical URL.'
            $serverList = Join-Path $registryTestRoot 'Security\cPPKHandler\cTimeStampServers'
            Assert-Equal 1 @(Get-ChildItem -LiteralPath $serverList).Count `
                'Acrobat setup duplicated a semantically equivalent timestamp URL.'
            $serverKey = Get-ChildItem -LiteralPath $serverList | Select-Object -First 1
            Assert-Equal 'OpenTimeStamp' ($serverKey.GetValue('tName')) 'Acrobat server name was not written.'
            Assert-Equal $timestampUrl ($serverKey.GetValue('tServer')) 'Acrobat server URL was not written.'
            Assert-Equal ([Microsoft.Win32.RegistryValueKind]::String) ($serverKey.GetValueKind('tServer')) `
                'Acrobat server URL has the wrong registry type.'

            $providerKey = Get-Item -LiteralPath $providerPath
            $expectedBinaryUrl = [Text.Encoding]::ASCII.GetBytes($timestampUrl + [char]0)
            Assert-Equal ([Convert]::ToBase64String($expectedBinaryUrl)) `
                ([Convert]::ToBase64String([byte[]]$providerKey.GetValue('sURL'))) `
                'Acrobat default timestamp URL does not use the expected terminated ASCII encoding.'
            Assert-Equal ([Microsoft.Win32.RegistryValueKind]::Binary) ($providerKey.GetValueKind('sURL')) `
                'Acrobat default timestamp URL has the wrong registry type.'
            Assert-True ($providerKey.GetValueNames() -notcontains 'sHashAlgo') `
                'Acrobat setup left the alternate hash OID selector in conflict with iHashAlgo.'
            Assert-Equal 2 ($providerKey.GetValue('iHashAlgo')) 'Acrobat timestamp hashing is not SHA-256.'
            $signKey = Get-Item -LiteralPath (Join-Path $registryTestRoot 'Security\cASPKI\cASPKI\cSign')
            Assert-Equal 1 ($signKey.GetValue('bReqSigPropRetrieval')) `
                'Acrobat setup does not fail closed when timestamp retrieval fails.'

            Assert-Equal 'preserve' ((Get-Item -LiteralPath $trustManagerPath).GetValue('Unrelated')) `
                'Acrobat setup changed an unrelated Trust Manager value.'
            & $setupPath -TimestampUrl $timestampUrl -RegistryRoot $registryTestRoot | Out-Null
            Assert-Equal 1 @(Get-ChildItem -LiteralPath $serverList).Count `
                'Acrobat setup is not idempotent for an existing timestamp URL.'
        }
        finally {
            if (Test-Path -LiteralPath $registryTestRoot) {
                Remove-Item -LiteralPath $registryTestRoot -Recurse -Force
            }
        }

    }

    Invoke-Test 'Publisher pins the exact directory and rejects destructive state paths' {
        $publish = Get-Content -LiteralPath (Join-Path $repositoryRoot 'build\Publish.ps1') -Raw
        $build = Get-Content -LiteralPath (Join-Path $repositoryRoot 'build\Build.ps1') -Raw
        $buildCommon = Get-Content -LiteralPath (Join-Path $repositoryRoot 'build\Build.Common.ps1') -Raw
        $deploymentCommon = Get-Content -LiteralPath `
            (Join-Path $repositoryRoot 'deploy\Deployment.Common.ps1') -Raw
        $installer = Get-Content -LiteralPath (Join-Path $repositoryRoot 'deploy\Install-IisApplication.ps1') -Raw
        $coreProject = Get-Content -LiteralPath `
            (Join-Path $repositoryRoot 'src\OpenTimeStamp.Core\OpenTimeStamp.Core.csproj') -Raw
        $webProject = Get-Content -LiteralPath `
            (Join-Path $repositoryRoot 'src\OpenTimeStamp.Web\OpenTimeStamp.Web.csproj') -Raw
        [xml]$directoryBuildProps = Get-Content -LiteralPath `
            (Join-Path $repositoryRoot 'Directory.Build.props') -Raw
        [xml]$directoryPackagesProps = Get-Content -LiteralPath `
            (Join-Path $repositoryRoot 'Directory.Packages.props') -Raw
        foreach ($token in @('$fileListDirectory = 0x00000001', '$fileFlagOpenReparsePoint = 0x00200000',
                'ownershipVerifiedAfterPin', 'contains App_Data', 'MSBuild property parsing')) {
            Assert-True ($publish -match [regex]::Escape($token)) "Publish safeguard '$token' is missing."
        }
        $requiredRuntimeAssemblies = @(
            'Microsoft.Bcl.Cryptography.dll',
            'System.Buffers.dll',
            'System.Formats.Asn1.dll',
            'System.Memory.dll',
            'System.Numerics.Vectors.dll',
            'System.Runtime.CompilerServices.Unsafe.dll',
            'System.Security.Cryptography.Pkcs.dll'
        )
        foreach ($requiredRuntimeAssembly in $requiredRuntimeAssemblies) {
            Assert-True ($deploymentCommon -match [regex]::Escape($requiredRuntimeAssembly)) `
                "Shared deployment metadata does not require runtime assembly '$requiredRuntimeAssembly'."
        }
        Assert-True ($publish -match 'Get-OpenTimeStampRequiredRuntimeAssemblies' -and
            $installer -match 'Get-OpenTimeStampRequiredRuntimeAssemblies') `
            'Publisher and installer do not share the required runtime assembly list.'
        $expectedPackageVersions = [ordered]@{
            'Microsoft.Bcl.Cryptography' = '10.0.10'
            'Microsoft.CodeAnalysis.NetAnalyzers' = '10.0.302'
            'Microsoft.NET.Test.Sdk' = '18.8.1'
            'MSTest.TestAdapter' = '4.3.2'
            'MSTest.TestFramework' = '4.3.2'
            'System.Buffers' = '4.6.1'
            'System.Formats.Asn1' = '10.0.10'
            'System.Security.Cryptography.Pkcs' = '10.0.10'
            'WixToolset.Util.wixext' = '7.0.0'
        }
        Assert-Equal 'true' ([string]$directoryPackagesProps.Project.PropertyGroup.ManagePackageVersionsCentrally) `
            'Central Package Management is not enabled.'
        foreach ($package in $expectedPackageVersions.GetEnumerator()) {
            $node = $directoryPackagesProps.SelectSingleNode(
                "/Project/ItemGroup/PackageVersion[@Include='$($package.Key)']")
            Assert-True ($null -ne $node) "Central package version '$($package.Key)' is missing."
            Assert-Equal $package.Value ([string]$node.Version) `
                "Central package version '$($package.Key)' is not pinned to '$($package.Value)'."
        }
        foreach ($property in ([ordered]@{
                TargetFrameworkVersion = 'v4.8'
                LangVersion = '14.0'
                Deterministic = 'true'
                TreatWarningsAsErrors = 'true'
                RestorePackagesWithLockFile = 'true'
                WarningLevel = '4'
            }).GetEnumerator()) {
            $node = $directoryBuildProps.SelectSingleNode("/Project/PropertyGroup/$($property.Key)")
            Assert-True ($null -ne $node) "Central build property '$($property.Key)' is missing."
            Assert-Equal $property.Value ([string]$node.InnerText) `
                "Central build property '$($property.Key)' is not '$($property.Value)'."
        }
        foreach ($package in @('Microsoft.Bcl.Cryptography', 'System.Security.Cryptography.Pkcs')) {
            $packageReference = '<PackageReference Include="' + [regex]::Escape($package) + '" />'
            Assert-True ($webProject -match $packageReference) `
                "Web project does not directly reference centrally versioned package '$package'."
        }
        Assert-True ($coreProject -match '<PackageReference Include="System\.Formats\.Asn1" />') `
            'Core project does not directly reference the centrally versioned System.Formats.Asn1 package.'
        Assert-True ($coreProject -match '<Compile Include="Infrastructure\\FileSystemLock\.cs" />') `
            'Core project does not compile the shared filesystem lock implementation.'
        Assert-True ($build -match [regex]::Escape('/restore')) `
            'The normal build does not restore PackageReference dependencies.'
        Assert-True ($build -match [regex]::Escape('/p:RestoreLockedMode=true')) `
            'The normal build permits restore to rewrite a mismatched NuGet dependency lock.'
        Assert-True ($build -match [regex]::Escape('RunConfiguration.TreatNoTestsAsError=true')) `
            'The normal build does not fail when the managed test adapter discovers no tests.'
        Assert-True ($build -match 'Resolve-OpenTimeStampMSBuild' -and
            $publish -match 'Resolve-OpenTimeStampMSBuild') `
            'Build and publish do not share one MSBuild resolver.'
        foreach ($toolchainToken in @('Microsoft.Component.MSBuild',
                'Microsoft.WebApplication.targets', 'csc.exe', 'C# 14-capable', '-all')) {
            Assert-True ($buildCommon -match [regex]::Escape($toolchainToken)) `
                "Build toolchain validation omits '$toolchainToken'."
        }
        Assert-True ($publish -match 'Assert-OpenTimeStampReleaseInputsTracked' -and
            $publish -match 'ls-files --others --exclude-standard' -and
            $publish -match 'ls-files --error-unmatch') `
            'Publisher does not fail closed on untracked release inputs or untracked required root files.'
        foreach ($rootBuildInput in @('.editorconfig', '.globalconfig', 'Directory.Build.props',
                'Directory.Packages.props', 'OpenTimeStamp.sln')) {
            Assert-True ($publish -match [regex]::Escape("'$rootBuildInput'")) `
                "Publisher does not treat '$rootBuildInput' as a required tracked build input."
        }
        foreach ($releaseInputScope in @("'src'", "'tests/OpenTimeStamp.Tests'")) {
            Assert-True ($publish -match [regex]::Escape($releaseInputScope)) `
                "Publisher does not inspect release-input scope $releaseInputScope."
        }
        Assert-True ($webProject -match '<Import Project="\$\(VSToolsPath\)\\WebApplications\\Microsoft.WebApplication.targets" />') `
            'The web project silently skips missing WebApplication targets.'
        Assert-True ($publish -notmatch 'Remove-Item -LiteralPath \$publishedAppData') `
            'Publisher still recursively deletes App_Data after publishing.'
        $nativeBlock = [regex]::Match($publish,
            "Add-Type -TypeDefinition @'\r?\n(?<code>.*?)\r?\n'@", [Text.RegularExpressions.RegexOptions]::Singleline)
        Assert-True $nativeBlock.Success 'Publisher native handle helper could not be extracted for a runtime smoke test.'
        if ($null -eq ('OpenTimeStamp.PublishNativeMethods' -as [type])) {
            Add-Type -TypeDefinition $nativeBlock.Groups['code'].Value
        }
        $pinSource = Join-Path $testRoot 'publish-pin-source'
        $pinTarget = Join-Path $testRoot 'publish-pin-target'
        New-Item -ItemType Directory -Path $pinSource | Out-Null
        $handle = [OpenTimeStamp.PublishNativeMethods]::CreateFileW(
            $pinSource, 1, 3, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
        try {
            Assert-True (-not $handle.IsInvalid) 'Publisher native helper could not pin a normal directory.'
            Assert-Throws { [IO.Directory]::Move($pinSource, $pinTarget) } `
                'A publish directory could be renamed while held without delete sharing.'
        }
        finally { $handle.Dispose() }
    }

    Invoke-Test 'WiX 7 MSI packages the hardened deployment and applies release signing policy' {
        $wixProjectPath = Join-Path $repositoryRoot 'setup\msi\OpenTimeStamp.Setup.wixproj'
        $wixSourcePath = Join-Path $repositoryRoot 'setup\msi\OpenTimeStamp.wxs'
        $msiBuildPath = Join-Path $repositoryRoot 'setup\msi\Build-Msi.ps1'
        $msiInstallPath = Join-Path $repositoryRoot 'setup\msi\Install-Msi.ps1'
        $msiUninstallPath = Join-Path $repositoryRoot 'setup\msi\Uninstall-Msi.ps1'
        [xml]$wixProject = Get-Content -LiteralPath $wixProjectPath -Raw
        $wixSource = Get-Content -LiteralPath $wixSourcePath -Raw
        $msiBuild = Get-Content -LiteralPath $msiBuildPath -Raw
        $msiInstall = Get-Content -LiteralPath $msiInstallPath -Raw
        $msiUninstall = Get-Content -LiteralPath $msiUninstallPath -Raw
        $build = Get-Content -LiteralPath (Join-Path $repositoryRoot 'build\Build.ps1') -Raw
        $publish = Get-Content -LiteralPath (Join-Path $repositoryRoot 'build\Publish.ps1') -Raw

        Assert-Equal 'WixToolset.Sdk/7.0.0' ([string]$wixProject.Project.Sdk) `
            'The MSI project does not pin the current WiX 7 SDK.'
        Assert-True ($wixProject.OuterXml -match 'WixToolset\.Util\.wixext') `
            'The MSI project does not reference the WiX utility extension.'
        Assert-True ($wixProject.OuterXml -match 'WixToolset\.UI\.wixext') `
            'The MSI project does not reference the WiX UI extension.'
        foreach ($wixToken in @('Scope="perMachine"', 'ProgramFiles64Folder', 'MajorUpgrade',
                '$(var.PayloadPath)\**', '$(var.DeployPath)\*.ps1', 'WixQuietExec',
                'Impersonate="no"', 'NOT UPGRADINGPRODUCTCODE', 'IISINSTALLED',
                'IISSITENAME', 'APPLICATIONNAME', 'IisConfigurationDlg',
                'After="WriteRegistryValues"', 'Before="RemoveRegistryValues"')) {
            Assert-True ($wixSource -match [regex]::Escape($wixToken)) `
                "MSI authoring safeguard '$wixToken' is missing."
        }
        foreach ($packagingToken in @('/t:WebPublish', 'New-OpenTimeStampDeploymentManifest',
                'Assert-OpenTimeStampPublishedPayload', 'RestoreLockedMode=true')) {
            Assert-True ($msiBuild -match [regex]::Escape($packagingToken)) `
                "MSI packaging safeguard '$packagingToken' is missing."
        }
        foreach ($signingToken in @("'SHA256'", "'/tr'", "'/td'", 'Get-AuthenticodeSignature',
                'TimeStamperCertificate', 'RequireSignedInstaller')) {
            Assert-True ($msiBuild -match [regex]::Escape($signingToken)) `
                "MSI signing safeguard '$signingToken' is missing."
        }
        foreach ($installToken in @('Install-IisApplication.ps1', 'AllowUnsignedManifest',
                '-SiteName $siteName', '-ApplicationPath $applicationPath',
                '-InstallIisFeatures:$false', 'Microsoft IIS is not installed',
                "`$manager.Sites[`$siteName]")) {
            Assert-True ($msiInstall -match [regex]::Escape($installToken)) `
                "MSI deployment integration '$installToken' is missing."
        }
        Assert-True ($msiInstall -notmatch 'AuthenticationMode') `
            'MSI deployment bypasses the main installer authentication-preservation and orphan-root safeguards.'
        foreach ($uninstallToken in @('Test-OpenTimeStampDeploymentRootMarker',
                'Assert-OpenTimeStampPublishedPayload', 'unexpectedAssignments',
                'Preserved deployment releases and application data',
                "'HKLM:\Software\OpenTimeStamp\Installer'", "'/' + `$applicationName")) {
            Assert-True ($msiUninstall -match [regex]::Escape($uninstallToken)) `
                "MSI uninstall ownership safeguard '$uninstallToken' is missing."
        }
        $installCommandStart = $wixSource.IndexOf('<SetProperty Id="InstallOpenTimeStamp"')
        $installCommandEnd = $wixSource.IndexOf('/>', $installCommandStart)
        Assert-True ($installCommandStart -ge 0 -and $installCommandEnd -gt $installCommandStart) `
            'The MSI install command could not be isolated.'
        $installCommand = $wixSource.Substring($installCommandStart, $installCommandEnd - $installCommandStart)
        Assert-True ($installCommand -notmatch 'IISSITENAME|APPLICATIONNAME') `
            'Untrusted IIS selections are interpolated into the elevated PowerShell command line.'
        Assert-True ($build -match [regex]::Escape('setup\msi\Build-Msi.ps1') -and
            $build -match 'RequireSignedInstaller') 'The normal build does not produce and sign the MSI.'
        Assert-True ($publish -match [regex]::Escape("'setup/msi'") -and
            $publish -match 'SkipInstaller = \$true') `
            'Publishing neither tracks the MSI inputs nor suppresses a redundant nested MSI build.'
    }

    Invoke-Test 'SignTool output cannot turn an MSI signing failure into success' {
        $builderPath = Join-Path $repositoryRoot 'setup\msi\Build-Msi.ps1'
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $builderPath, [ref]$tokens, [ref]$parseErrors)
        Assert-Equal 0 @($parseErrors).Count 'MSI builder could not be parsed for signing regression.'
        $signingFunction = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq 'Invoke-InstallerSigning'
            }, $true)
        Assert-True ($null -ne $signingFunction) 'MSI signing function could not be isolated.'
        . ([scriptblock]::Create($signingFunction.Extent.Text))
        function Resolve-SignTool { return 'Invoke-MsiSigningTestTool' }
        function Invoke-MsiSigningTestTool {
            'SignTool regression output'
            $exitCode = if ($args[0] -eq $failurePhase) { 1 } else { 0 }
            Set-Variable -Name LASTEXITCODE -Value $exitCode -Scope 1
        }
        foreach ($failurePhase in @('sign', 'verify')) {
            $result = @(Invoke-InstallerSigning -MsiPath 'unused.msi' `
                -Rfc3161Url 'https://tsa.example.test/' 3>$null 6>$null)
            Assert-Equal 1 $result.Count "SignTool $failurePhase output escaped into the Boolean result."
            Assert-True ($result[0] -is [bool] -and -not $result[0]) `
                "SignTool $failurePhase failure was reported as successful."
            Assert-Throws {
                Invoke-InstallerSigning -MsiPath 'unused.msi' -Rfc3161Url 'https://tsa.example.test/' `
                    -Required 6>$null
            } "Required MSI signing accepted a $failurePhase failure."
        }
    }

    Invoke-Test 'Installer retains release rollback and pool-state safeguards' {
        $installer = Get-Content -LiteralPath (Join-Path $repositoryRoot 'deploy\Install-IisApplication.ps1') -Raw
        $signatureValidation = $installer.IndexOf('$manifestSignature = Assert-OpenTimeStampManifestSignature')
        $signedSnapshotValidation = if ($signatureValidation -lt 0) { -1 } else {
            $installer.IndexOf('-Manifest $manifestSignature.Manifest', $signatureValidation)
        }
        $stagingCopy = if ($signedSnapshotValidation -lt 0) { -1 } else {
            $installer.IndexOf('Copy-OpenTimeStampPublishedPayload', $signedSnapshotValidation)
        }
        Assert-True ($signatureValidation -ge 0 -and $signedSnapshotValidation -gt $signatureValidation) `
            'Installer payload validation does not consume the exact manifest snapshot verified by CMS.'
        Assert-True ($stagingCopy -gt $signedSnapshotValidation) `
            'Installer staging is not ordered after validation of the signed manifest snapshot.'
        Assert-True ($installer -match 'existingApplicationPool') 'Installer does not inspect the actual current pool.'
        Assert-True ($installer -match 'finally\s*\{') 'Installer lacks a finally-based pool restoration path.'
        Assert-True ($installer -match 'Restore-PoolState') 'Installer lacks pool-state restoration.'
        Assert-True ($installer.LastIndexOf('foreach ($pool in @($initialPoolStates.Keys))') -gt
            $installer.LastIndexOf('Restore-OpenTimeStampRecursiveAclSnapshot')) `
            'Installer restores pool states before critical filesystem and ACL rollback completes.'
        Assert-True ($installer -match 'Critical deployment rollback was not verified') `
            'Installer does not fail closed with pools stopped after unverified rollback.'
        Assert-True ($installer -match 'Move-Item -LiteralPath \$stagePath -Destination \$releasePath') `
            'Installer does not activate an immutable staged release.'
        Assert-True ($installer -match 'unexpectedCurrentPoolAssignments') `
            'Installer does not reject a shared actual current pool.'
        foreach ($poolInvariant in @('MaxProcesses = 1', 'DisallowOverlappingRotation = $true',
                "SetAttributeValue('maxProcesses'", "'disallowOverlappingRotation'")) {
            Assert-True ($installer -match [regex]::Escape($poolInvariant)) `
                "Installer does not transactionally enforce dedicated-pool invariant '$poolInvariant'."
        }
        Assert-True ($installer -match 'Initialize-IssuanceStateFromRelease') `
            'Installer does not explicitly initialize or migrate issuance state from the selected release.'
        Assert-True ($installer -match 'Test-IssuanceStateArtifactsPresent') `
            'Installer does not prevent a marked deployment with missing state from being reseeded.'
        Assert-True ($installer -match 'Test-OpenTimeStampDataDirectoryUninitializedScaffolding') `
            'Installer does not constrain first-initialization retry to exact false-marker scaffolding.'
        Assert-True ($installer -match 'Set-OpenTimeStampDataDirectoryIssuanceInitialized') `
            'Installer does not commit the data marker lifecycle after issuance initialization.'
        Assert-True ($installer.LastIndexOf('Initialize-IssuanceStateFromRelease') -lt
            $installer.LastIndexOf('Set-OpenTimeStampDataDirectoryIssuanceInitialized')) `
            'Installer records issuance initialization before the state initializer returns.'
        Assert-True ($installer -match 'missing, invalid, or ambiguous') `
            'Installer does not fail closed on ambiguous inherited authentication settings.'
        Assert-True ($installer -match 'AuthenticationMode must be explicit when adopting a deployment root') `
            'Installer does not fail closed when a preserved deployment has no authoritative IIS application.'
        Assert-True ($installer -notmatch 'issuance\.state\.bak.*(?:Copy|Move|Replace)') `
            'Installer appears to restore a potentially stale issuance-state backup.'
        Assert-True ($installer.IndexOf('Enter-OpenTimeStampDeploymentLock') -lt `
            $installer.IndexOf('$SourcePath = (Resolve-Path')) `
            'Installer lock is acquired after mutable preflight observations begin.'
        Assert-True ($installer -match "-Scope 'OpenTimeStamp-MachineDeployment'") `
            'Installer lock is not one machine-global deployment mutex.'
        Assert-True ($installer -match 'Test-IssuanceStateHasAuthenticatedRuntimeEvidence') `
            'Installer does not treat authenticated marker publication as the migration commit boundary.'
        Assert-True ($installer -match 'Test-OpenTimeStampNewIisApplicationRollbackCandidate') `
            'Installer does not use the guarded partial-application rollback decision.'
        Assert-True ($installer -notmatch 'newApplicationAppliedSnapshot') `
            'Partial-application rollback still depends on state captured only after New-WebApplication returns.'
        Assert-True ($installer.IndexOf('Assert-OpenTimeStampIisSharedConfigurationDisabled') -lt `
            $installer.IndexOf('Install-WindowsFeature')) `
            'Installer checks IIS Shared Configuration only after it can mutate role services.'
        $authenticatedEvidenceStart = $installer.IndexOf('function Test-IssuanceStateHasAuthenticatedRuntimeEvidence')
        $artifactPresenceStart = $installer.IndexOf('function Test-IssuanceStateArtifactsPresent')
        $artifactNamesStart = $installer.IndexOf('function Get-IssuanceStateArtifactNames')
        $initializeStateStart = $installer.IndexOf('function Initialize-IssuanceStateFromRelease')
        $authenticatedEvidenceBlock = $installer.Substring(
            $authenticatedEvidenceStart, $artifactPresenceStart - $authenticatedEvidenceStart)
        $artifactPresenceBlock = $installer.Substring(
            $artifactPresenceStart, $artifactNamesStart - $artifactPresenceStart)
        $artifactNamesBlock = $installer.Substring(
            $artifactNamesStart, $initializeStateStart - $artifactNamesStart)
        Assert-True ($authenticatedEvidenceBlock -notmatch [regex]::Escape('issuance.state.lock')) `
            'The coordination lock is incorrectly treated as authenticated issuance-state evidence.'
        Assert-True ($artifactPresenceBlock -notmatch [regex]::Escape('issuance.state.lock')) `
            'The coordination lock is incorrectly treated as issuance-state payload.'
        Assert-True ($artifactNamesBlock -match [regex]::Escape('issuance.state.lock')) `
            'Installer rollback does not track the persistent issuance coordination lock.'
        foreach ($markerEvidence in @('issuance.state.meta', 'issuance.state.meta.bak', 'issuance.state.meta.new')) {
            Assert-True ($installer -match [regex]::Escape($markerEvidence)) `
                "Installer migration commit evidence omits '$markerEvidence'."
        }
        Assert-True ($installer -match 'Exit-OpenTimeStampDeploymentLock -Lock \$deploymentLock') `
            'Installer does not release its cross-process application lock in the outer finally.'
        foreach ($rollbackToken in @('Restore-IisExactLocalState', 'RawAttributes',
                'ChildElement', 'RevertToParent', 'SectionWasLocal')) {
            Assert-True ($installer -match [regex]::Escape($rollbackToken)) `
                "Installer rollback does not retain '$rollbackToken'."
        }
        Assert-True ($installer -match "directive.LocalName -eq 'clear'") `
            'Exact ipSecurity rollback does not preserve local clear directives.'
        Assert-True ($installer -match "directive.LocalName -eq 'remove'") `
            'Exact ipSecurity rollback does not preserve local remove directives.'
        Assert-True ($installer -match 'ExpectedCurrentSnapshot') `
            'IIS rollback lacks an optimistic exact post-state comparison.'
        Assert-True ($installer -match 'Test-IisConfigurationLocationIsEmpty') `
            'Installer removes IIS location tags without verifying that their raw nodes are otherwise empty.'
        Assert-True ($installer -match 'iisLocalStateRestored') `
            'Installer may remove IIS location tags after targeted configuration restore fails.'
        Assert-True ($installer -match 'Remove-OpenTimeStampControlledDirectory -ExpectedParent \$releasesPath -Path \$releasePath') `
            'Installer does not remove its moved release after a pre-commit rollback.'
        Assert-True ($installer -match 'MarkerId') `
            'Installer does not verify ownership before removing its created data marker.'
        Assert-True ($installer -match 'Get-OpenTimeStampRecursiveAclSnapshot') `
            'Installer does not snapshot recursive ACL state before mutation.'
        Assert-True ($installer -match 'Restore-OpenTimeStampRecursiveAclSnapshot') `
            'Installer does not restore exact recursive ACL state.'
        Assert-True ($installer -notmatch 'dataAclOwnedByDeploymentRoot' -and
            $installer -match 'Get-OpenTimeStampRecursiveAclSnapshot -Path \$PhysicalPath -RootOnly') `
            'Installer still recursively snapshots every historical release for a root-only ACL change.'
        foreach ($releaseSafetyToken in @('Remove-OpenTimeStampObsoleteReleases', 'RetainReleases',
                'AllowUnsignedManifest', 'TrustedManifestSignerThumbprint',
                'Get-ValidatedSiteBindingEndpoints', 'committedSiteBindingEndpoints')) {
            Assert-True ($installer -match [regex]::Escape($releaseSafetyToken)) `
                "Installer release safeguard '$releaseSafetyToken' is missing."
        }
        Assert-True ($installer -match [regex]::Escape('elseif (-not $AllowUnsignedManifest)')) `
            'Installer does not fail closed on an unsigned deployment manifest by default.'
        $physicalCreateIndex = $installer.IndexOf('$physicalDirectoryInitialization = Initialize-OpenTimeStampOwnedDirectory')
        $rootAclIndex = $installer.IndexOf('Set-OpenTimeStampRestrictedDirectoryAcl -Path $PhysicalPath', $physicalCreateIndex)
        $dataInitializationIndex = $installer.IndexOf('$dataInitialization = Initialize-OpenTimeStampDataDirectory')
        Assert-True ($physicalCreateIndex -ge 0 -and $physicalCreateIndex -lt $dataInitializationIndex) `
            'Default DataPath initialization can still create PhysicalPath before ownership is recorded.'
        Assert-True ($rootAclIndex -gt $physicalCreateIndex -and $rootAclIndex -lt $dataInitializationIndex) `
            'PhysicalPath is not hardened immediately after installer-owned creation.'
        $dataDirectoryIndex = $installer.IndexOf('$dataDirectoryInitialization = Initialize-OpenTimeStampOwnedDirectory')
        $dataAclIndex = $installer.IndexOf('Set-OpenTimeStampRestrictedDirectoryAcl -Path $runtimeDataPath', $dataDirectoryIndex)
        $logCreationIndex = $installer.IndexOf('$logPath = Join-Path $runtimeDataPath ''Logs''', $dataInitializationIndex)
        Assert-True ($dataDirectoryIndex -gt $rootAclIndex -and $dataDirectoryIndex -lt $dataAclIndex) `
            'DataPath ownership is not recorded before its ACL mutation.'
        Assert-True ($dataAclIndex -lt $dataInitializationIndex -and $dataInitializationIndex -lt $logCreationIndex) `
            'DataPath marker or Logs can be created before the DataPath ACL is hardened.'
        Assert-True ($installer -match 'dataDirectoryCreatedByInstaller') `
            'Rollback does not retain DataPath directory ownership if marker initialization fails.'
        foreach ($protectedMutation in @(
                'New-Item -ItemType Directory -Path $releasesPath',
                '$deploymentRootMarkerInitialization = Initialize-DeploymentRootMarker',
                'Move-Item -LiteralPath $stagePath -Destination $releasePath')) {
            Assert-True ($rootAclIndex -lt $installer.IndexOf($protectedMutation, $rootAclIndex)) `
                "PhysicalPath ACL hardening occurs after protected mutation '$protectedMutation'."
        }
        foreach ($midMutationToken in @('rootAclMutationError', 'dataAclMutationError',
                'rollback will fail closed')) {
            Assert-True ($installer -match [regex]::Escape($midMutationToken)) `
                "Mid-operation ACL rollback safeguard '$midMutationToken' is missing."
        }
        foreach ($ownedScaffold in @('physicalPathCreatedByInstaller', 'releasesDirectoryCreatedByInstaller',
                'deploymentParentCreatedByInstaller', 'deploymentRootMarkerInitialization')) {
            Assert-True ($installer -match $ownedScaffold) `
                "Installer does not track owned scaffolding '$ownedScaffold'."
        }
        Assert-True ($installer -match 'newIssuanceArtifacts') `
            'Installer does not preserve its data marker after leaving new migration sidecars.'
        Assert-True ($installer -match 'Restore-PrivateKeyAclChange') `
            'Installer does not restore a changed key ACL after pre-commit failure.'
        Assert-True ($installer -match 'Remove-WebConfigurationLocation') `
            'First-install rollback does not remove installer-created IIS location overrides.'
        Assert-True ($installer -match 'appLocationExistedBefore') `
            'Installer does not preserve pre-existing IIS location ownership during first-install rollback.'
        Assert-True ($installer -match 'Get-IisApplicationStorageAssignments') `
            'Installer does not enumerate other IIS applications for shared storage.'
        Assert-True ($installer -match 'Get-WebVirtualDirectory -Site \$siteName -Application \$parentApplication') `
            'Installer omits application-scoped IIS virtual directories from storage exclusivity checks.'
        foreach ($storageToken in @('Test-OpenTimeStampPathsOverlap', 'Identity = "$siteName/"',
                'lastMinutePoolAssignments', 'no readable Web.config')) {
            Assert-True ($installer -match [regex]::Escape($storageToken)) `
                "Installer storage exclusivity checks do not retain '$storageToken'."
        }
        Assert-True ($installer -match 'storage cannot be shared between IIS applications') `
            'Installer does not reject another IIS application sharing its deployment root or DataPath.'
        foreach ($markerBinding in @('DataPath = $classification.Path', 'DeploymentRoot = $root')) {
            $combinedMarkerCode = (Get-Content -LiteralPath (Join-Path $repositoryRoot 'deploy\Deployment.Common.ps1') -Raw) + $installer
            Assert-True ($combinedMarkerCode -match [regex]::Escape($markerBinding)) `
                "Ownership marker is not canonically path-bound with '$markerBinding'."
        }
    }

    Invoke-Test 'IIS always-warm configuration is atomic and exactly reversible' {
        $installer = Get-Content -LiteralPath (Join-Path $repositoryRoot 'deploy\Install-IisApplication.ps1') -Raw
        $global = Get-Content -LiteralPath (Join-Path $repositoryRoot 'src\OpenTimeStamp.Web\Global.asax.cs') -Raw
        foreach ($warmSetting in @(
                "SetAttributeValue('serverAutoStart', `$true)",
                "SetAttributeValue('autoStart', `$true)",
                "SetAttributeValue('startMode', 'AlwaysRunning')",
                "SetAttributeValue('idleTimeout', [TimeSpan]::Zero)",
                "SetAttributeValue('time', [TimeSpan]::Zero)",
                "SetAttributeValue('serviceAutoStartEnabled', `$true)",
                "SetAttributeValue('serviceAutoStartProvider', `$ProviderName)")) {
            Assert-True ($installer -match [regex]::Escape($warmSetting)) `
                "Installer does not atomically enforce always-warm setting '$warmSetting'."
        }
        foreach ($rollbackToken in @('Get-IisRawAttributeSnapshot', 'HasLocalValue',
                'Restore-IisRawAttributeSnapshot', '.Delete()', 'ExpectedCurrentSnapshot',
                'Test-IisAlwaysWarmPreMutationState', 'Restore-IisAlwaysWarmStateAtomic',
                'iisWarmStateRestored')) {
            Assert-True ($installer -match [regex]::Escape($rollbackToken)) `
                "Always-warm rollback does not retain '$rollbackToken'."
        }
        foreach ($providerToken in @('system.applicationHost/serviceAutoStartProviders',
                'OpenTimeStamp.Web.OpenTimeStampPreloadClient, OpenTimeStamp.Web',
                'Get-IisServiceAutoStartProviderReferencesFromManager',
                'IIS service auto-start provider')) {
            Assert-True ($installer -match [regex]::Escape($providerToken)) `
                "Installer service auto-start provider safeguard '$providerToken' is missing."
        }
        $warmStateIndex = $installer.IndexOf('$iisWarmStatePreMutation = Get-IisAlwaysWarmState')
        $issuanceCommitIndex = $installer.IndexOf(
            'Initialize-IssuanceStateFromRelease -ReleasePath', $warmStateIndex)
        $warmCommitIndex = $installer.IndexOf('Set-IisAlwaysWarmStateAtomic -SiteName', $issuanceCommitIndex)
        $poolStopBoundaryIndex = $installer.IndexOf(
            '# Recheck mutable IIS assignments immediately before quiescing pools')
        $poolStopIndex = $installer.IndexOf('Stop-PoolForDeployment -Name $pool', $poolStopBoundaryIndex)
        $poolStartIndex = $installer.IndexOf(
            'Start-PoolForDeployment -Name $AppPoolName', $issuanceCommitIndex)
        $siteStartIndex = $installer.IndexOf('-DesiredState Started', $issuanceCommitIndex)
        Assert-True ($poolStopBoundaryIndex -ge 0 -and $poolStopIndex -gt $poolStopBoundaryIndex -and
            $warmStateIndex -gt $poolStopIndex -and
            $issuanceCommitIndex -gt $warmStateIndex -and $warmCommitIndex -gt $issuanceCommitIndex -and
            $poolStartIndex -gt $warmCommitIndex -and $siteStartIndex -gt $poolStartIndex) `
            'Always-warm activation is not ordered strictly after durable issuance initialization.'
        Assert-True ($installer -match [regex]::Escape(
                'must remain stopped before always-warm activation')) `
            'The atomic always-warm commit does not recheck the dedicated pool activation boundary.'
        $catchIndex = $installer.IndexOf('$caughtError = $_', $warmCommitIndex)
        $warmRestoreIndex = $installer.IndexOf('Restore-IisAlwaysWarmStateAtomic -SiteName', $catchIndex)
        $applicationRestoreIndex = $installer.IndexOf('Remove-WebApplication -Site', $catchIndex)
        Assert-True ($warmRestoreIndex -gt $catchIndex -and $applicationRestoreIndex -gt $warmRestoreIndex) `
            'Application rollback can remove the target before its always-warm attributes are restored exactly.'
        Assert-True ($installer -match [regex]::Escape("-DesiredState Started")) `
            'Successful deployment does not leave the selected IIS site started.'
        Assert-True ($installer -notmatch 'existingApplicationWasRunning') `
            'Successful deployment still preserves a stopped target application pool.'
        $failureSiteRestoreIndex = $installer.IndexOf('$desiredSiteState = $initialSiteState')
        $failClosedPoolIndex = $installer.IndexOf('-InitialState Stopped', $failureSiteRestoreIndex)
        Assert-True ($failureSiteRestoreIndex -ge 0 -and $failClosedPoolIndex -gt $failureSiteRestoreIndex) `
            'A post-migration activation failure does not preserve the site state and stop the target pool.'

        foreach ($startupToken in @('IProcessHostPreloadClient', 'OpenTimeStampPreloadClient',
                'ApplicationStartup.Initialize()', 'ServiceRuntime.Initialize',
                'TimestampHandler.InitializeAdmission', 'HealthHandler.GetHealth()')) {
            Assert-True ($global -match [regex]::Escape($startupToken)) `
                "ASP.NET service auto-start implementation '$startupToken' is missing."
        }
        $routeIndex = $global.IndexOf('routes.Add("Home"')
        $healthWarmIndex = $global.IndexOf('HealthHandler.GetHealth()', $routeIndex)
        Assert-True ($routeIndex -ge 0 -and $healthWarmIndex -gt $routeIndex) `
            'The non-blocking health warm-up runs before runtime routes are initialized.'
        Assert-True ($installer -notmatch 'preloadEnabled') `
            'Installer uses fake-request preload, which cannot warm an application that requires IIS SSL.'
    }

    Invoke-Test 'IIS provisioning and application static surface are minimal' {
        $installer = Get-Content -LiteralPath (Join-Path $repositoryRoot 'deploy\Install-IisApplication.ps1') -Raw
        $featuresStart = $installer.IndexOf('$features = @(')
        $featuresEnd = $installer.IndexOf('if ($InstallIisFeatures)', $featuresStart)
        Assert-True ($featuresStart -ge 0 -and $featuresEnd -gt $featuresStart) `
            'Installer IIS feature selection could not be isolated.'
        $featureBlock = $installer.Substring($featuresStart, $featuresEnd - $featuresStart)
        foreach ($requiredFeature in @('Web-Asp-Net45', 'Web-Windows-Auth', 'Web-IP-Security',
                'Web-Filtering', 'Web-Http-Errors', 'Web-Http-Logging', 'Web-Scripting-Tools')) {
            Assert-True ($featureBlock -match [regex]::Escape("'$requiredFeature'")) `
                "Required IIS leaf feature '$requiredFeature' is not selected."
        }
        foreach ($excludedFeature in @('Web-Server', 'Web-Static-Content', 'Web-Default-Doc',
                'Web-Dir-Browsing', 'Web-WebDAV', 'Web-CGI', 'Web-ASP', 'Web-Basic-Auth',
                'Web-Digest-Auth', 'Web-AppInit', 'Web-Mgmt-Console', 'Web-Mgmt-Service')) {
            Assert-True ($featureBlock -notmatch [regex]::Escape("'$excludedFeature'")) `
                "Unnecessary IIS feature '$excludedFeature' is selected explicitly."
        }
        Assert-True ($installer -notmatch '-IncludeManagementTools') `
            'Installer still requests the broad IIS management-tools set.'
        Assert-True ($installer -match '\$missingFeatures = @\(') `
            'Installer does not verify the required IIS features after optional provisioning.'

        $webConfigPath = Join-Path $repositoryRoot 'src\OpenTimeStamp.Web\Web.config'
        [xml]$webConfig = Get-Content -LiteralPath $webConfigPath -Raw
        $staticContent = $webConfig.SelectSingleNode('/configuration/system.webServer/staticContent')
        Assert-True ($null -ne $staticContent) 'Application does not define an app-local static-content policy.'
        Assert-Equal 1 @($staticContent.SelectNodes('./clear')).Count `
            'Application must clear inherited static MIME mappings exactly once.'
        Assert-Equal 0 @($staticContent.SelectNodes('./mimeMap|./add')).Count `
            'Application must not expose a static MIME mapping.'
        $requestFiltering = $webConfig.SelectSingleNode(
            '/configuration/system.webServer/security/requestFiltering')
        Assert-Equal 'false' $requestFiltering.GetAttribute('allowDoubleEscaping') `
            'Application does not explicitly reject double-escaped URLs.'
        Assert-Equal 'false' $requestFiltering.GetAttribute('allowHighBitCharacters') `
            'Application does not explicitly limit routes to their ASCII surface.'
    }

    Invoke-Test 'Private-key helper requires pool identity and broad-ACL override' {
        $grant = Get-Content -LiteralPath (Join-Path $repositoryRoot 'deploy\Grant-TsaPrivateKeyAccess.ps1') -Raw
        $installer = Get-Content -LiteralPath (Join-Path $repositoryRoot 'deploy\Install-IisApplication.ps1') -Raw
        Assert-True ($grant -match 'S-1-5-82-') 'Private-key helper does not require an application-pool SID.'
        Assert-True ($grant -match 'AllowBroadExistingKeyAcl') 'Private-key helper lacks an explicit broad-ACL override.'
        foreach ($keyAclToken in @('trustedSids', 'Test-KeyAffectingAllowRule', '0xD00D0157',
                'AcceptedExistingKeyAclExceptions', 'IntendedState', 'SupportedRsaCngProviders',
                'SupportedRsaCspProviders', 'Assert-OpenTimeStampPersistedMachineKeyPathSafe')) {
            Assert-True ($grant -match [regex]::Escape($keyAclToken)) `
                "Private-key helper allowlist safeguard '$keyAclToken' is missing."
        }
        Assert-True ($grant -match 'PreviousSddl') 'Private-key helper does not return the prior ACL security descriptor.'
        Assert-True ($grant -match 'AclChanged') 'Private-key helper does not report whether it changed permissions.'
        Assert-True ($grant -match 'AppliedSddl') 'Private-key helper does not return the exact applied ACL descriptor.'
        Assert-True ($installer -match 'refusing to overwrite the external change') `
            'Private-key rollback does not fail closed on a concurrent ACL change.'
        Assert-True ($installer -match 'restored and verified exactly') `
            'Private-key rollback does not verify the restored ACL descriptor.'
    }

    Invoke-Test 'Private-key helper gates pure ML-DSA key discovery through stable Windows CNG APIs' {
        $grant = Get-Content -LiteralPath (Join-Path $repositoryRoot 'deploy\Grant-TsaPrivateKeyAccess.ps1') -Raw
        $installer = Get-Content -LiteralPath (Join-Path $repositoryRoot 'deploy\Install-IisApplication.ps1') -Raw
        foreach ($oid in @('2.16.840.1.101.3.4.3.17', '2.16.840.1.101.3.4.3.18',
                '2.16.840.1.101.3.4.3.19')) {
            Assert-True ($grant -match [regex]::Escape($oid)) "Pure ML-DSA OID '$oid' is not recognized."
        }
        foreach ($token in @('CryptAcquireCertificatePrivateKey', 'NCryptGetProperty',
                'NCryptFreeObject', '0x00040000', '[uint32]::MaxValue', '$callerFree',
                'Algorithm Name', 'Algorithm Group', 'Key Type', 'Provider Handle',
                'Unique Name', 'Microsoft Software Key Storage Provider', 'Microsoft\Crypto\Keys')) {
            Assert-True ($grant -match [regex]::Escape($token)) `
                "Private-key helper ML-DSA safeguard '$token' is missing."
        }
        Assert-True ($grant -notmatch 'GetMLDsaPrivateKey|GetMLDsaPublicKey|MLDsaCng') `
            'Private-key helper must not depend on evaluation-only Microsoft.Bcl.Cryptography APIs.'
        Assert-True ($grant -notmatch 'CompositeMLDsa') `
            'Private-key helper unexpectedly accepts composite ML-DSA certificates.'
        Assert-True ($grant -notmatch 'CryptographyAssemblyPath' -and
            $installer -cnotmatch '(?m)^\s*CryptographyAssemblyPath\s*=') `
            'Deployment scripts must not expose the removed evaluation-only BCL key-access path.'
    }
}
finally {
    $resolvedParent = [System.IO.Path]::GetFullPath($testParent).TrimEnd('\')
    $resolvedRoot = [System.IO.Path]::GetFullPath($testRoot).TrimEnd('\')
    if ($resolvedRoot.StartsWith($resolvedParent + '\', [System.StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedRoot)) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}

Write-Host "Deployment regression suite: $($tests - $failures) passed, $failures failed."
if ($failures -ne 0) { exit 1 }
