#Requires -PSEdition Core
#Requires -Version 7.6

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-ProductTestResult {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('Passed', 'Skipped')]
        [string]$Status,

        [string]$Artifact,

        [string]$Detail
    )

    [pscustomobject]@{
        Name = $Name
        Status = $Status
        Artifact = $Artifact
        Detail = $Detail
    }
}

function Assert-Condition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Remove-ProductSigningFileVerified {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 100)][int]$Attempts = 20,
        [ValidateRange(0, 5000)][int]$DelayMilliseconds = 250
    )

    $lastError = $null
    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        try {
            if (Test-Path -LiteralPath $Path) {
                Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            }
        }
        catch {
            $lastError = $_.Exception
        }

        if (-not (Test-Path -LiteralPath $Path)) { return }
        if ($attempt + 1 -lt $Attempts -and $DelayMilliseconds -ne 0) {
            Start-Sleep -Milliseconds $DelayMilliseconds
        }
    }

    $detail = if ($lastError) { " Last error: $($lastError.Message)" } else { '' }
    throw "Credential-bearing temporary file '$Path' remains after $Attempts cleanup attempts.$detail"
}

function Release-ComObject {
    param([AllowNull()]$InputObject)

    if ($null -ne $InputObject -and [System.Runtime.InteropServices.Marshal]::IsComObject($InputObject)) {
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($InputObject)
    }
}

function Get-ApplicationPath {
    param([Parameter(Mandatory)][string]$ExecutableName)

    $command = Get-Command $ExecutableName -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    $roots = @(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths'
    )
    foreach ($root in $roots) {
        $item = Get-ItemProperty -LiteralPath (Join-Path $root $ExecutableName) -ErrorAction SilentlyContinue
        if ($item -and $item.'(default)' -and (Test-Path -LiteralPath $item.'(default)' -PathType Leaf)) {
            return $item.'(default)'
        }
    }

    return $null
}

function Get-AcrobatJavaScriptDirectory {
    param([Parameter(Mandatory)][string]$AcrobatPath)

    $acrobatDirectory = [IO.Path]::GetFullPath((Split-Path -Parent $AcrobatPath)).TrimEnd('\')
    $registryRoots = @(
        'Registry::HKEY_CURRENT_USER\SOFTWARE\Adobe\Adobe Acrobat',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Adobe\Adobe Acrobat',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat'
    )
    $versions = foreach ($root in $registryRoots) {
        foreach ($versionKey in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $installKey = Join-Path $versionKey.PSPath 'InstallPath'
            if (-not (Test-Path -LiteralPath $installKey)) { continue }
            $installPath = (Get-Item -LiteralPath $installKey).GetValue('')
            if (-not $installPath) { continue }
            [pscustomobject]@{
                Name = $versionKey.PSChildName
                Matches = [IO.Path]::GetFullPath($installPath).TrimEnd('\') -eq $acrobatDirectory
            }
        }
    }
    $selected = $versions | Sort-Object @{ Expression = 'Matches'; Descending = $true }, @{
        Expression = { if ($_.Name -eq 'DC') { [version]'999.0' } else { [version]$_.Name } }
        Descending = $true
    } | Select-Object -First 1
    $version = if ($selected) { $selected.Name } else { 'DC' }
    return Join-Path $env:APPDATA "Adobe\Acrobat\$version\JavaScripts"
}

function Get-SignToolPath {
    param(
        [ValidateSet('Native', 'x86', 'x64', 'arm64')]
        [string]$Architecture = 'Native'
    )

    if ($Architecture -eq 'Native') {
        $osArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
        $Architecture = if ($osArchitecture -eq 'Arm64') { 'arm64' } else { 'x64' }
    }

    $command = Get-Command 'signtool.exe' -ErrorAction SilentlyContinue
    if ($command -and (Split-Path -Leaf (Split-Path -Parent $command.Source)) -eq $Architecture) {
        return $command.Source
    }

    $kitRoots = @(
        (Get-ItemPropertyValue `
            -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Kits\Installed Roots' `
            -Name KitsRoot10 -ErrorAction SilentlyContinue),
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } | Select-Object -Unique

    foreach ($root in $kitRoots) {
        $tools = Get-ChildItem -LiteralPath (Join-Path $root 'bin') -Filter 'signtool.exe' -File -Recurse `
            -ErrorAction SilentlyContinue | Where-Object { $_.Directory.Name -eq $Architecture }
        $selected = $tools | Sort-Object {
            $version = [version]'0.0'
            [void][version]::TryParse($_.Directory.Parent.Name, [ref]$version)
            $version
        } -Descending | Select-Object -First 1
        if ($selected) { return $selected.FullName }
    }

    return $null
}

function Get-CSharpCompilerPath {
    $frameworkRoots = @(
        (Join-Path $env:windir 'Microsoft.NET\Framework64'),
        (Join-Path $env:windir 'Microsoft.NET\Framework')
    )
    foreach ($root in $frameworkRoots) {
        $compiler = Get-ChildItem -LiteralPath $root -Filter 'csc.exe' -File -Recurse -ErrorAction SilentlyContinue |
            Sort-Object { [version]$_.Directory.Name.TrimStart('v') } -Descending | Select-Object -First 1
        if ($compiler) { return $compiler.FullName }
    }

    return $null
}

function Stop-NativeProcessTree {
    param([Parameter(Mandatory)][System.Diagnostics.Process]$Process)

    if ($Process.HasExited) { return }
    try {
        $Process.Kill($true)
    }
    catch [System.InvalidOperationException] {
        if (-not $Process.HasExited) { throw }
    }
    if (-not $Process.WaitForExit(15000)) { throw "Process tree $($Process.Id) could not be terminated." }
}

function Invoke-NativeProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][AllowEmptyString()][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$Description,
        [ValidateRange(1, 3600)][int]$TimeoutSeconds = 120
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $ArgumentList) { $startInfo.ArgumentList.Add($argument) }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        Assert-Condition $process.Start() "Could not start $Description."
        $standardOutput = $process.StandardOutput.ReadToEndAsync()
        $standardError = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            Stop-NativeProcessTree -Process $process
            $output = if ($standardOutput.Wait(5000) -and $standardError.Wait(5000)) {
                (($standardOutput.GetAwaiter().GetResult(), $standardError.GetAwaiter().GetResult()) -join
                    [Environment]::NewLine).Trim()
            }
            else { 'One or more redirected output streams did not close after termination.' }
            if ($output) { $output = "$([Environment]::NewLine)$output" }
            throw "$Description timed out after $TimeoutSeconds seconds and its process tree was terminated.$output"
        }
        $outputs = $standardOutput.GetAwaiter().GetResult(), $standardError.GetAwaiter().GetResult()
        $output = ($outputs -join [Environment]::NewLine).Trim()
        if ($process.ExitCode -ne 0) {
            throw "$Description failed with exit code $($process.ExitCode).$([Environment]::NewLine)$output"
        }

        return $output
    }
    finally {
        $process.Dispose()
    }
}

function Invoke-SignToolSign {
    param(
        [Parameter(Mandatory)][string]$SignToolPath,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$CertificateThumbprint,
        [Parameter(Mandatory)][uri]$TimestampUrl
    )

    Invoke-NativeProcess -FilePath $SignToolPath -Description "SignTool signing '$Path'" -ArgumentList @(
        'sign', '/s', 'My', '/sha1', $CertificateThumbprint, '/fd', 'SHA256', '/tr', $TimestampUrl.AbsoluteUri,
        '/td', 'SHA256', $Path
    )
}

function Invoke-SignToolVerify {
    param(
        [Parameter(Mandatory)][string]$SignToolPath,
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowUntrustedRoot
    )

    try {
        $output = Invoke-NativeProcess -FilePath $SignToolPath -Description "SignTool verification of '$Path'" `
            -ArgumentList @('verify', '/pa', '/all', '/v', '/tw', $Path)
        if ($output -match '(?im)^\s*SignTool Warning:') {
            throw "SignTool verification of '$Path' completed with a warning.$([Environment]::NewLine)$output"
        }
        return [PSCustomObject]@{
            Output = $output
            UntrustedRoot = $false
        }
    }
    catch {
        if ($AllowUntrustedRoot -and (Test-ExpectedSignToolUntrustedRootFailure -Message $_.Exception.Message)) {
            return [PSCustomObject]@{
                Output = 'SignTool completed with the expected trust failure for the isolated self-signed test identity.'
                UntrustedRoot = $true
            }
        }
        throw
    }
}

function Test-ExpectedSignToolUntrustedRootFailure {
    param([Parameter(Mandatory)][string]$Message)

    $untrustedRootPattern = '(?i)(0x800b0109|CERT_E_UNTRUSTEDROOT|' +
        'root certificate which is not trusted by the trust provider)'
    $hasExpectedTrustFailure = $Message -match $untrustedRootPattern
    if (-not $hasExpectedTrustFailure) { return $false }

    # SignTool may report the file as not valid solely because its otherwise
    # valid chain terminates at the isolated test root. Reject every other
    # error or warning, including the /tw warning for a missing timestamp.
    foreach ($line in $Message -split '\r?\n') {
        if ($line -notmatch '(?i)^\s*SignTool (Error|Warning):') { continue }
        if ($line -match $untrustedRootPattern) { continue }
        if ($line -match '(?i)^\s*SignTool Error:\s*File not valid:') { continue }
        return $false
    }

    return $true
}

function Get-TestSigningCertificate {
    param([Parameter(Mandatory)][string]$Thumbprint)

    $normalized = $Thumbprint.Replace(' ', '').ToUpperInvariant()
    $certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$normalized" -ErrorAction SilentlyContinue
    Assert-Condition ($null -ne $certificate) "Signing certificate '$normalized' was not found in CurrentUser\My."
    Assert-Condition $certificate.HasPrivateKey "Signing certificate '$normalized' has no private key."
    return $certificate
}

function Assert-AuthenticodeTimestamp {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$CertificateThumbprint,
        [string]$ExpectedTsaThumbprint,
        [switch]$VerifiedUntrustedRoot
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    # SignTool has already verified the file digest and timestamp before this
    # exception is permitted; this branch accounts only for the isolated test root.
    $expectedUntrustedRoot = $VerifiedUntrustedRoot -and
        $signature.Status -eq [System.Management.Automation.SignatureStatus]::UnknownError
    Assert-Condition ($signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid -or
        $expectedUntrustedRoot) `
        "Authenticode verification returned '$($signature.Status)': $($signature.StatusMessage)"
    Assert-Condition ($null -ne $signature.SignerCertificate) 'The signer certificate is missing from the signature.'
    Assert-Condition ($signature.SignerCertificate.Thumbprint -eq $CertificateThumbprint) `
        "The signature used certificate '$($signature.SignerCertificate.Thumbprint)' instead of " +
        "'$CertificateThumbprint'."
    Assert-Condition ($null -ne $signature.TimeStamperCertificate) `
        'The signature does not contain a timestamp certificate.'
    if ($ExpectedTsaThumbprint) {
        Assert-Condition ($signature.TimeStamperCertificate.Thumbprint -eq $ExpectedTsaThumbprint) `
            "The timestamp used TSA certificate '$($signature.TimeStamperCertificate.Thumbprint)' instead of " +
            "'$ExpectedTsaThumbprint'."
    }
    if ($expectedUntrustedRoot) {
        $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        try {
            $chain.ChainPolicy.TrustMode = [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
            [void]$chain.ChainPolicy.CustomTrustStore.Add($signature.SignerCertificate)
            $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            Assert-Condition $chain.Build($signature.SignerCertificate) `
                'The generated signer certificate did not validate against the isolated test trust store.'
        }
        finally {
            $chain.Dispose()
        }
    }
    return $signature
}

function Save-RegistryValues {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string[]]$Names)

    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    $values = foreach ($name in $Names) {
        $exists = $false
        $value = $null
        $kind = $null
        if ($key -and $key.GetValueNames() -contains $name) {
            $exists = $true
            $value = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $kind = $key.GetValueKind($name)
        }

        [pscustomobject]@{ Name = $name; Exists = $exists; Value = $value; Kind = $kind }
    }

    [pscustomobject]@{
        Path = $Path
        PathExisted = $null -ne $key
        Values = @($values)
        AppliedValues = @{}
    }
}

function Get-RegistryValueState {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)

    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $key -or $key.GetValueNames() -notcontains $Name) {
        return [pscustomobject]@{ Exists = $false; Value = $null; Kind = $null }
    }
    return [pscustomobject]@{
        Exists = $true
        Value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        Kind = $key.GetValueKind($Name)
    }
}

function Test-RegistryValueStateEqual {
    param([Parameter(Mandatory)]$First, [Parameter(Mandatory)]$Second)

    if ([bool]$First.Exists -ne [bool]$Second.Exists) { return $false }
    if (-not [bool]$First.Exists) { return $true }
    if ($First.Kind -ne $Second.Kind) { return $false }
    if ($First.Value -is [string] -and $Second.Value -is [string]) {
        return $First.Value.Equals($Second.Value, [StringComparison]::Ordinal)
    }
    return [object]::Equals($First.Value, $Second.Value)
}

function Set-RegistryValueOwned {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][Microsoft.Win32.RegistryValueKind]$Kind,
        [Parameter(Mandatory)]$Snapshot
    )

    if (-not $Snapshot.Path.Equals($Path, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Registry snapshot path '$($Snapshot.Path)' does not match mutation path '$Path'."
    }
    $priorEntries = @($Snapshot.Values | Where-Object Name -EQ $Name)
    if ($priorEntries.Count -ne 1) { throw "Registry value '$Name' was not captured exactly once before mutation." }
    $current = Get-RegistryValueState -Path $Path -Name $Name
    if (-not (Test-RegistryValueStateEqual -First $current -Second $priorEntries[0])) {
        throw "Registry value '$Path\$Name' changed after it was captured; refusing to overwrite it."
    }

    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value `
        -PropertyType $Kind.ToString() -Force | Out-Null
    $applied = [pscustomobject]@{ Exists = $true; Value = $Value; Kind = $Kind }
    $Snapshot.AppliedValues[$Name] = $applied
    if (-not (Test-RegistryValueStateEqual `
            -First (Get-RegistryValueState -Path $Path -Name $Name) -Second $applied)) {
        throw "Registry value '$Path\$Name' was not written exactly."
    }
}

function Restore-RegistryValues {
    param([Parameter(Mandatory)]$Snapshot)

    foreach ($entry in $Snapshot.Values) {
        if (-not $Snapshot.AppliedValues.ContainsKey($entry.Name)) { continue }
        $current = Get-RegistryValueState -Path $Snapshot.Path -Name $entry.Name
        if (-not (Test-RegistryValueStateEqual -First $current -Second $Snapshot.AppliedValues[$entry.Name])) {
            throw "Registry value '$($Snapshot.Path)\$($entry.Name)' changed after the test mutation; refusing to overwrite it."
        }
    }

    foreach ($entry in $Snapshot.Values) {
        if (-not $Snapshot.AppliedValues.ContainsKey($entry.Name)) { continue }
        if ($entry.Exists) {
            New-ItemProperty -LiteralPath $Snapshot.Path -Name $entry.Name -Value $entry.Value `
                -PropertyType $entry.Kind.ToString() -Force | Out-Null
        }
        else {
            Remove-ItemProperty -LiteralPath $Snapshot.Path -Name $entry.Name -ErrorAction Stop
        }
        if (-not (Test-RegistryValueStateEqual `
                -First (Get-RegistryValueState -Path $Snapshot.Path -Name $entry.Name) -Second $entry)) {
            throw "Registry value '$($Snapshot.Path)\$($entry.Name)' was not restored exactly."
        }
    }
    if (-not $Snapshot.PathExisted) {
        $key = Get-Item -LiteralPath $Snapshot.Path -ErrorAction SilentlyContinue
        if ($key -and $key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) {
            Remove-Item -LiteralPath $Snapshot.Path -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $Snapshot.Path) {
                throw "Test-created registry key '$($Snapshot.Path)' was not removed."
            }
        }
    }
}

function Set-RegistryDword {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value,
        [Parameter(Mandatory)]$Snapshot
    )

    Set-RegistryValueOwned -Path $Path -Name $Name -Value $Value `
        -Kind ([Microsoft.Win32.RegistryValueKind]::DWord) -Snapshot $Snapshot
}

function Set-RegistryString {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)]$Snapshot
    )

    Set-RegistryValueOwned -Path $Path -Name $Name -Value $Value `
        -Kind ([Microsoft.Win32.RegistryValueKind]::String) -Snapshot $Snapshot
}

function Get-OfficeTimestampPolicyConflict {
    param([Parameter(Mandatory)][string]$OfficeVersion, [Parameter(Mandatory)][uri]$TimestampUrl)

    $path = "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\$OfficeVersion\Common\Signatures"
    $policy = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
    if (-not $policy) { return $null }
    $xadesLevel = $policy.PSObject.Properties['XAdESLevel']
    $minimumLevel = $policy.PSObject.Properties['MinXAdESLevel']
    $tsaLocation = $policy.PSObject.Properties['TSALocation']
    if ($xadesLevel -and [int]$xadesLevel.Value -lt 2) { return 'Group Policy requests an XAdES level below XAdES-T.' }
    if ($minimumLevel -and [int]$minimumLevel.Value -lt 2) { return 'Group Policy permits signatures below XAdES-T.' }
    if ($tsaLocation -and $tsaLocation.Value -and
        $tsaLocation.Value.TrimEnd('/') -ne $TimestampUrl.AbsoluteUri.TrimEnd('/')) {
        return "Group Policy fixes the Office TSA at '$($tsaLocation.Value)'."
    }

    return $null
}

function Test-OfficeVbaSipInstalled {
    $roots = @(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0'
    )
    foreach ($root in $roots) {
        $path = Join-Path $root 'CryptSIPDllGetSignedDataMsg\{9FA65764-C36F-4319-9737-658A34585BB7}'
        $registration = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
        if ($registration -and $registration.FuncName -eq 'MsoVBADigSigGetSignedDataMsg') { return $true }
    }

    return $false
}

function Get-DerObjectBytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    Add-Type -AssemblyName System.Formats.Asn1
    $reader = [System.Formats.Asn1.AsnReader]::new(
        $Bytes, [System.Formats.Asn1.AsnEncodingRules]::DER)
    $tag = $reader.PeekTag()
    Assert-Condition ($tag.TagClass -eq [System.Formats.Asn1.TagClass]::Universal -and $tag.IsConstructed -and
        $tag.TagValue -eq [System.Formats.Asn1.UniversalTagNumber]::Sequence) 'The CMS value is not a DER SEQUENCE.'
    $encodedLength = $reader.ReadEncodedValue().Length
    return [byte[]]$Bytes[0..($encodedLength - 1)]
}

function Assert-Rfc3161Token {
    param([Parameter(Mandatory)][byte[]]$Bytes, [string]$ExpectedTsaThumbprint)

    Add-Type -AssemblyName System.Security.Cryptography.Pkcs
    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new()
    $cms.Decode((Get-DerObjectBytes -Bytes $Bytes))
    Assert-Condition ($cms.ContentInfo.ContentType.Value -eq '1.2.840.113549.1.9.16.1.4') `
        "CMS content type '$($cms.ContentInfo.ContentType.Value)' is not RFC 3161 TSTInfo."
    $cms.CheckSignature($true)
    Assert-Condition ($cms.SignerInfos.Count -eq 1) `
        "The RFC 3161 token contains $($cms.SignerInfos.Count) signers instead of one."
    if ($ExpectedTsaThumbprint) {
        $tokenSigner = $cms.SignerInfos[0].Certificate
        Assert-Condition ($tokenSigner -and $tokenSigner.Thumbprint -eq $ExpectedTsaThumbprint) `
            "The token used TSA certificate '$($tokenSigner.Thumbprint)' instead of '$ExpectedTsaThumbprint'."
    }
}

function Assert-CmsHasRfc3161Timestamp {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][byte[]]$DetachedContent,
        [string]$ExpectedTsaThumbprint
    )

    Add-Type -AssemblyName System.Security.Cryptography.Pkcs
    $content = [System.Security.Cryptography.Pkcs.ContentInfo]::new($DetachedContent)
    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
    $cms.Decode((Get-DerObjectBytes -Bytes $Bytes))
    $cms.CheckSignature($true)
    foreach ($signer in $cms.SignerInfos) {
        foreach ($attribute in $signer.UnsignedAttributes) {
            if ($attribute.Oid.Value -ne '1.2.840.113549.1.9.16.2.14') { continue }
            foreach ($value in $attribute.Values) {
                Assert-Rfc3161Token -Bytes $value.RawData -ExpectedTsaThumbprint $ExpectedTsaThumbprint
            }
            return
        }
    }

    throw 'The CMS signature has no RFC 3161 signature-time-stamp unsigned attribute.'
}

function Assert-PdfHasRfc3161Timestamp {
    param([Parameter(Mandatory)][byte[]]$Bytes, [string]$ExpectedTsaThumbprint)

    $text = [Text.Encoding]::ASCII.GetString($Bytes)
    $rangeMatch = [regex]::Match($text,
        '/ByteRange\s*\[\s*([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s*\]')
    Assert-Condition ($rangeMatch.Success -and -not $rangeMatch.NextMatch().Success) `
        'The generated PDF must contain exactly one four-value signature ByteRange.'
    $ranges = [long[]]@(1..4 | ForEach-Object { [long]$rangeMatch.Groups[$_].Value })
    Assert-Condition ($ranges[0] -eq 0 -and $ranges[1] -gt 0 -and $ranges[1] -lt $ranges[2] -and
        $ranges[2] -lt $Bytes.LongLength -and $ranges[3] -eq $Bytes.LongLength - $ranges[2]) `
        'The PDF signature ByteRange must cover the entire file except its Contents value.'

    $contents = [regex]::Match($text.Substring([int]$ranges[1], [int]($ranges[2] - $ranges[1])),
        '\A<([0-9A-Fa-f\s]+)>\z')
    Assert-Condition ($contents.Success -and
        [regex]::IsMatch($text.Substring(0, [int]$ranges[1]), '/Contents\s*\z')) `
        'The PDF signature ByteRange gap must contain exactly its hexadecimal Contents value.'
    $signedContent = [byte[]]::new([int]($ranges[1] + $ranges[3]))
    [Buffer]::BlockCopy($Bytes, 0, $signedContent, 0, [int]$ranges[1])
    [Buffer]::BlockCopy($Bytes, [int]$ranges[2], $signedContent, [int]$ranges[1], [int]$ranges[3])
    Assert-CmsHasRfc3161Timestamp -Bytes (Convert-HexToBytes -Hex $contents.Groups[1].Value) `
        -DetachedContent $signedContent -ExpectedTsaThumbprint $ExpectedTsaThumbprint
}

function Convert-HexToBytes {
    param([Parameter(Mandatory)][string]$Hex)

    $normalized = $Hex -replace '\s', ''
    Assert-Condition ($normalized.Length -ne 0 -and $normalized.Length % 2 -eq 0) `
        'The value is not valid hexadecimal.'
    try {
        return [Convert]::FromHexString($normalized)
    }
    catch [FormatException] {
        throw 'The value is not valid hexadecimal.'
    }
}

function ConvertTo-AcrobatPath {
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path).Replace('\', '/')
    if ($fullPath -match '^([A-Za-z]):/(.*)$') { return "/$($Matches[1].ToUpperInvariant())/$($Matches[2])" }
    return $fullPath
}

function New-MinimalPdf {
    param([Parameter(Mandatory)][string]$Path)

    $streamText = "BT /F1 18 Tf 72 720 Td (OpenTimeStamp PDF signing test) Tj ET`n"
    $objects = @(
        '<< /Type /Catalog /Pages 2 0 R >>',
        '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        ('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources ' +
            '<< /Font << /F1 4 0 R >> >> /Contents 5 0 R >>'),
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
        "<< /Length $([Text.Encoding]::ASCII.GetByteCount($streamText)) >>`nstream`n$streamText" + 'endstream'
    )
    $builder = [Text.StringBuilder]::new("%PDF-1.4`n%OpenTimeStamp`n")
    $offsets = [System.Collections.Generic.List[int]]::new()
    for ($index = 0; $index -lt $objects.Count; $index++) {
        $offsets.Add([Text.Encoding]::ASCII.GetByteCount($builder.ToString()))
        [void]$builder.Append("$($index + 1) 0 obj`n$($objects[$index])`nendobj`n")
    }
    $xrefOffset = [Text.Encoding]::ASCII.GetByteCount($builder.ToString())
    [void]$builder.Append("xref`n0 $($objects.Count + 1)`n0000000000 65535 f `n")
    foreach ($offset in $offsets) { [void]$builder.Append($offset.ToString('0000000000') + " 00000 n `n") }
    [void]$builder.Append("trailer`n<< /Size $($objects.Count + 1) /Root 1 0 R >>`nstartxref`n$xrefOffset`n%%EOF`n")
    [IO.File]::WriteAllBytes($Path, [Text.Encoding]::ASCII.GetBytes($builder.ToString()))
}
