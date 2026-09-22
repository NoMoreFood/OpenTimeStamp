#Requires -Version 5.1

Set-StrictMode -Version Latest

$script:OpenTimeStampDeploymentManifestName = 'OpenTimeStamp.DeploymentManifest.json'
$script:OpenTimeStampPublishMarkerName = '.opentimestamp-publish.json'
$script:OpenTimeStampDataMarkerName = '.opentimestamp-data.json'
$script:OpenTimeStampDeploymentMarkerName = '.opentimestamp-deployment.json'

function Get-OpenTimeStampRequiredRuntimeAssemblies {
    return [string[]]@(
        'Microsoft.Bcl.Cryptography.dll',
        'System.Buffers.dll',
        'System.Formats.Asn1.dll',
        'System.Memory.dll',
        'System.Numerics.Vectors.dll',
        'System.Runtime.CompilerServices.Unsafe.dll',
        'System.Security.Cryptography.Pkcs.dll')
}

function Get-OpenTimeStampFullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path.Trim()))
}

function Get-OpenTimeStampFinalLongPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fullPath = Get-OpenTimeStampFullPath -Path $Path
    $existingPath = $fullPath
    $missingSegments = New-Object 'System.Collections.Generic.List[string]'
    while (-not (Test-Path -LiteralPath $existingPath)) {
        $leaf = Split-Path -Leaf $existingPath
        $parent = Split-Path -Parent $existingPath
        if ([string]::IsNullOrWhiteSpace($leaf) -or [string]::IsNullOrWhiteSpace($parent) -or
            $parent.Equals($existingPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "No existing ancestor could be resolved for path '$fullPath'."
        }
        $missingSegments.Insert(0, $leaf)
        $existingPath = $parent
    }

    # FileSystemInfo.FullName is obtained from the filesystem and expands an
    # existing 8.3 component to its stored long name. Append only not-yet-
    # existing lexical leaves after resolving the nearest existing ancestor.
    $resolvedPath = [string](Get-Item -LiteralPath $existingPath -Force).FullName
    foreach ($segment in $missingSegments) { $resolvedPath = Join-Path $resolvedPath $segment }
    return [System.IO.Path]::GetFullPath($resolvedPath)
}

function Get-OpenTimeStampCanonicalDirectoryPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fullPath = Get-OpenTimeStampFinalLongPath -Path $Path
    $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
    $trimmed = $fullPath.TrimEnd('\')
    if ($trimmed.Equals($pathRoot.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
        return $pathRoot
    }
    return $trimmed
}

function Initialize-OpenTimeStampOwnedDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $root = Get-OpenTimeStampCanonicalDirectoryPath -Path $Path
    if (Test-Path -LiteralPath $root) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            throw "The owned directory path '$root' exists but is not a directory."
        }
        return [PSCustomObject]@{ Path = $root; Created = $false }
    }

    # Do not use -Force: the parent is required to exist, and a concurrent
    # creator must make this operation fail rather than transferring ownership.
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    return [PSCustomObject]@{ Path = $root; Created = $true }
}

function Test-OpenTimeStampPathContained {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Parent,

        [Parameter(Mandatory = $true)]
        [string]$Child,

        [switch]$AllowEqual
    )

    $normalizedParent = (Get-OpenTimeStampCanonicalDirectoryPath -Path $Parent).TrimEnd('\')
    $normalizedChild = (Get-OpenTimeStampCanonicalDirectoryPath -Path $Child).TrimEnd('\')
    if ($AllowEqual -and $normalizedChild.Equals($normalizedParent, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    return $normalizedChild.StartsWith(
        $normalizedParent + '\',
        [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-OpenTimeStampPathContained {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Parent,

        [Parameter(Mandatory = $true)]
        [string]$Child,

        [switch]$AllowEqual
    )

    if (-not (Test-OpenTimeStampPathContained -Parent $Parent -Child $Child -AllowEqual:$AllowEqual)) {
        throw "Path '$Child' is outside the expected root '$Parent'."
    }
}

function Enter-OpenTimeStampDeploymentLock {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Scope
    )

    $normalizedScope = $Scope.Trim().ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($normalizedScope)) {
        throw 'A non-empty deployment lock scope is required.'
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $scopeHash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($normalizedScope))
    }
    finally {
        $sha256.Dispose()
    }

    $mutexName = 'Global\OpenTimeStamp.Deployment.' +
        ([System.BitConverter]::ToString($scopeHash).Replace('-', ''))
    $mutex = New-Object System.Threading.Mutex($false, $mutexName)
    $acquired = $false
    try {
        try {
            # Fail fast instead of leaving an unattended deployment or publish
            # process blocked indefinitely behind an owner that may be stuck.
            $acquired = $mutex.WaitOne(0)
        }
        catch [System.Threading.AbandonedMutexException] {
            # The abandoned mutex is acquired by the thread receiving this exception.
            $acquired = $true
            Write-Warning "The prior deployment owner exited without releasing '$mutexName'; continuing with the recovered lock."
        }

        if (-not $acquired) {
            throw "Another OpenTimeStamp operation is already active for '$Scope'. Wait for it to finish, then retry."
        }

        return [PSCustomObject]@{
            Name = $mutexName
            Mutex = $mutex
        }
    }
    catch {
        $mutex.Dispose()
        throw
    }
}

function Exit-OpenTimeStampDeploymentLock {
    param(
        [Parameter(Mandatory = $true)]
        $Lock
    )

    try {
        $Lock.Mutex.ReleaseMutex()
    }
    finally {
        $Lock.Mutex.Dispose()
    }
}

function Assert-OpenTimeStampNoReparsePoints {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [switch]$AncestryOnly
    )

    $resolvedRoot = Get-OpenTimeStampCanonicalDirectoryPath -Path $Root
    $ancestor = $resolvedRoot
    while (-not [string]::IsNullOrWhiteSpace($ancestor)) {
        if (Test-Path -LiteralPath $ancestor) {
            $ancestorItem = Get-Item -LiteralPath $ancestor -Force
            if (($ancestorItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse points are not permitted in deployment-controlled path ancestry: '$ancestor'."
            }
        }

        $parent = Split-Path -Parent $ancestor
        if ([string]::IsNullOrWhiteSpace($parent) -or
            $parent.Equals($ancestor, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }

        $ancestor = $parent
    }

    if ($AncestryOnly -or -not (Test-Path -LiteralPath $resolvedRoot)) {
        return
    }

    $items = @((Get-Item -LiteralPath $resolvedRoot -Force)) +
        @(Get-ChildItem -LiteralPath $resolvedRoot -Force -Recurse)
    foreach ($item in $items) {
        Assert-OpenTimeStampPathContained -Parent $resolvedRoot -Child $item.FullName -AllowEqual
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse points are not permitted in deployment-controlled paths: '$($item.FullName)'."
        }
    }
}

function Resolve-OpenTimeStampPersistedMachineKeyPath {
    param(
        [Parameter(Mandatory = $true)][string]$KeyDirectory,
        [Parameter(Mandatory = $true)][string]$UniqueName,
        [Parameter(Mandatory = $true)][string]$KeyDescription
    )

    if ([string]::IsNullOrWhiteSpace($UniqueName) -or $UniqueName -in @('.', '..') -or
        $UniqueName.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0 -or
        -not [System.IO.Path]::GetFileName($UniqueName).Equals(
            $UniqueName, [System.StringComparison]::Ordinal)) {
        throw "$KeyDescription does not expose a safe persisted unique name."
    }

    $canonicalDirectory = [System.IO.Path]::GetFullPath($KeyDirectory).TrimEnd('\')
    $keyPath = [System.IO.Path]::GetFullPath((Join-Path $canonicalDirectory $UniqueName))
    if (-not $keyPath.StartsWith(
            $canonicalDirectory + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$KeyDescription path escapes the expected machine-key directory."
    }
    return $keyPath
}

function Assert-OpenTimeStampPersistedMachineKeyPathSafe {
    param(
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][string]$KeyDirectory
    )

    $programDataPath = [System.IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\')
    $canonicalDirectory = [System.IO.Path]::GetFullPath($KeyDirectory).TrimEnd('\')
    $canonicalPath = [System.IO.Path]::GetFullPath($KeyPath)
    if (-not $canonicalDirectory.StartsWith(
            $programDataPath + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $canonicalPath.StartsWith(
            $canonicalDirectory + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The private-key path is outside the expected ProgramData machine-key directory.'
    }

    $current = Get-Item -LiteralPath $canonicalDirectory -Force
    while ($null -ne $current -and
        -not $current.FullName.Equals($programDataPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        if (($current.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The private-key directory '$($current.FullName)' is a reparse point."
        }
        $current = $current.Parent
    }
    if ($null -eq $current) {
        throw 'The private-key directory is not rooted beneath ProgramData.'
    }
    if (($current.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The ProgramData directory '$programDataPath' is a reparse point."
    }

    $keyItem = Get-Item -LiteralPath $canonicalPath -Force
    if ($keyItem.PSIsContainer -or
        ($keyItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The private-key path '$canonicalPath' is not a regular persisted key file."
    }
}

function Read-OpenTimeStampXmlDocument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $document = New-Object System.Xml.XmlDocument
    $document.XmlResolver = $null
    $document.PreserveWhitespace = $true
    $reader = [System.Xml.XmlReader]::Create($Path, $settings)
    try {
        $document.Load($reader)
    }
    finally {
        $reader.Dispose()
    }

    return $document
}

function Test-OpenTimeStampIisSharedConfigurationEnabled {
    param(
        [string]$RedirectionConfigPath = (Join-Path $env:WINDIR `
            'System32\inetsrv\config\redirection.config')
    )

    if (-not (Test-Path -LiteralPath $RedirectionConfigPath -PathType Leaf)) { return $false }

    $document = Read-OpenTimeStampXmlDocument -Path $RedirectionConfigPath
    $redirection = $document.SelectSingleNode('/configuration/configurationRedirection')
    if ($null -eq $redirection) {
        throw "IIS redirection configuration '$RedirectionConfigPath' does not contain configurationRedirection."
    }

    $enabledText = [string]$redirection.GetAttribute('enabled')
    if ([string]::IsNullOrWhiteSpace($enabledText)) { return $false }

    $enabled = $false
    if (-not [bool]::TryParse($enabledText, [ref]$enabled)) {
        throw "IIS redirection configuration '$RedirectionConfigPath' has an invalid enabled value."
    }

    return $enabled
}

function Assert-OpenTimeStampIisProcessBitness {
    param(
        [bool]$Is64BitOperatingSystem = [Environment]::Is64BitOperatingSystem,
        [bool]$Is64BitProcess = [Environment]::Is64BitProcess
    )

    if ($Is64BitOperatingSystem -and -not $Is64BitProcess) {
        throw ('OpenTimeStamp IIS deployment must run in a 64-bit PowerShell process on 64-bit Windows. ' +
            'A 32-bit process is subject to WOW64 filesystem and IIS administration redirection.')
    }
}

function Assert-OpenTimeStampIisSharedConfigurationDisabled {
    param(
        [string]$RedirectionConfigPath = (Join-Path $env:WINDIR `
            'System32\inetsrv\config\redirection.config')
    )

    if (Test-OpenTimeStampIisSharedConfigurationEnabled -RedirectionConfigPath $RedirectionConfigPath) {
        throw ('IIS Shared Configuration is enabled. OpenTimeStamp deployment requires local IIS configuration ' +
            'so rollback snapshots and writes address the same configuration store.')
    }
}

function Get-OpenTimeStampValidatedBindingEndpoint {
    param(
        [Parameter(Mandatory = $true)]$Binding,
        [scriptblock]$CertificateLookup = {
            param([string]$StoreName, [string]$Thumbprint)
            Get-Item -LiteralPath "Cert:\LocalMachine\$StoreName\$Thumbprint" -ErrorAction SilentlyContinue
        }
    )

    $protocolProperty = $Binding.PSObject.Properties['protocol']
    $informationProperty = $Binding.PSObject.Properties['bindingInformation']
    $protocol = if ($null -eq $protocolProperty) { '' } else { ([string]$protocolProperty.Value).ToLowerInvariant() }
    if ($protocol -notin @('http', 'https') -or $null -eq $informationProperty) {
        throw 'The IIS binding is not an HTTP or HTTPS binding with bindingInformation.'
    }
    $information = [string]$informationProperty.Value
    if ($information -notmatch '^(?<Address>.*):(?<Port>[0-9]+):(?<Host>[^:]*)$') {
        throw "IIS binding '$information' is not in address:port:host format."
    }
    $port = 0
    if (-not [int]::TryParse($Matches.Port, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        throw "IIS binding '$information' has an invalid TCP port."
    }
    $bindingHost = $Matches.Host.Trim()
    if ($bindingHost.IndexOfAny([char[]]@('/', '\', "`r", "`n", "`t")) -ge 0 -or
        $bindingHost.IndexOf('*') -ge 0 -or $bindingHost -eq '+') {
        throw "IIS binding '$information' has an unsafe host name."
    }
    $resultHost = $bindingHost
    if ([string]::IsNullOrWhiteSpace($resultHost)) {
        $bindingAddress = $Matches.Address.Trim([char[]]@('[', ']'))
        $parsedAddress = $null
        if ($bindingAddress -notin @('', '*', '+', '0.0.0.0', '::') -and
            [System.Net.IPAddress]::TryParse($bindingAddress, [ref]$parsedAddress)) {
            $resultHost = $parsedAddress.ToString()
        }
        else { $resultHost = [Environment]::MachineName }
    }

    $certificateThumbprint = $null
    if ($protocol -eq 'https') {
        $hashProperty = $Binding.PSObject.Properties['certificateHash']
        $storeProperty = $Binding.PSObject.Properties['certificateStoreName']
        $rawHash = $null
        if ($null -ne $hashProperty) { $rawHash = $hashProperty.Value }
        $certificateThumbprint = if ($rawHash -is [byte[]]) {
            [System.BitConverter]::ToString($rawHash).Replace('-', '')
        }
        else { ([string]$rawHash -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() }
        $storeName = if ($null -eq $storeProperty) { '' } else { ([string]$storeProperty.Value).Trim() }
        if ($certificateThumbprint -notmatch '^[0-9A-F]{40}$' -or $storeName -notmatch '^[A-Za-z0-9._-]+$') {
            throw "HTTPS binding '$information' does not identify one certificate and store."
        }
        $certificates = @(& $CertificateLookup $storeName $certificateThumbprint)
        if ($certificates.Count -ne 1 -or -not [bool]$certificates[0].HasPrivateKey -or
            $certificates[0].NotBefore -gt (Get-Date) -or $certificates[0].NotAfter -le (Get-Date)) {
            throw "HTTPS binding '$information' does not reference one currently valid LocalMachine certificate with a private key."
        }
    }

    $builder = [System.UriBuilder]::new($protocol, $resultHost, $port)
    return [PSCustomObject]@{
        Scheme = $protocol
        Host = $resultHost
        Port = $port
        BindingHost = $bindingHost
        BaseUrl = $builder.Uri.GetLeftPart([System.UriPartial]::Authority)
        CertificateThumbprint = $certificateThumbprint
    }
}

function Assert-OpenTimeStampWebConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "The published payload does not contain '$Path'."
    }

    $document = Read-OpenTimeStampXmlDocument -Path $Path
    foreach ($key in @(
            'AuthenticationMode',
            'DataPath',
            'AdminHostNames',
            'TimestampBodyReadTimeoutSeconds',
            'TimestampBodyIntakeLimit',
            'TimestampBodyIntakePerClientLimit',
            'TimestampProcessingLimit',
            'TimestampProcessingPerClientLimit')) {
        $node = $document.SelectSingleNode("/configuration/appSettings/add[@key='$key']")
        if ($null -eq $node) {
            throw "The published web.config does not contain the required '$key' appSetting."
        }
    }

    return $document
}

function Assert-OpenTimeStampIntakeSettings {
    param([hashtable]$Settings)

    if ($null -eq $Settings) { return }
    $definitions = @(
        @('TimestampBodyReadTimeoutSeconds', 10, 1, 25),
        @('TimestampBodyIntakeLimit', 32, 1, 256),
        @('TimestampBodyIntakePerClientLimit', 4, 1, 32),
        @('TimestampProcessingLimit', 4, 1, 64),
        @('TimestampProcessingPerClientLimit', 2, 1, 64))
    $values = @{}
    foreach ($definition in $definitions) {
        $key = [string]$definition[0]
        $value = [int]$definition[1]
        if ($null -ne $Settings[$key] -and
            (-not [int]::TryParse(
                    ([string]$Settings[$key]).Trim(),
                    [Globalization.NumberStyles]::Integer,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [ref]$value) -or
                $value -lt [int]$definition[2] -or $value -gt [int]$definition[3])) {
            throw "The existing '$key' appSetting must be an integer from $($definition[2]) through $($definition[3])."
        }
        $values[$key] = $value
    }
    if ($values.TimestampBodyIntakePerClientLimit -gt $values.TimestampBodyIntakeLimit) {
        throw "The existing 'TimestampBodyIntakePerClientLimit' appSetting exceeds 'TimestampBodyIntakeLimit'."
    }
    if ($values.TimestampProcessingPerClientLimit -gt $values.TimestampProcessingLimit) {
        throw "The existing 'TimestampProcessingPerClientLimit' appSetting exceeds 'TimestampProcessingLimit'."
    }
}

function Set-OpenTimeStampStagedWebSettings {
    param(
        [string]$ReleasePath,
        [string]$Mode,
        [string]$EffectiveDataPath,
        [string[]]$EffectiveAdminHosts,
        [hashtable]$ExistingSettings
    )

    $path = Join-Path $ReleasePath 'web.config'
    $document = Assert-OpenTimeStampWebConfig -Path $path
    $document.SelectSingleNode("/configuration/appSettings/add[@key='AuthenticationMode']").SetAttribute('value', $Mode)
    $document.SelectSingleNode("/configuration/appSettings/add[@key='DataPath']").SetAttribute('value', $EffectiveDataPath)
    $document.SelectSingleNode("/configuration/appSettings/add[@key='AdminHostNames']").SetAttribute('value', ($EffectiveAdminHosts -join ','))
    foreach ($key in @(
            'TimestampBodyReadTimeoutSeconds',
            'TimestampBodyIntakeLimit',
            'TimestampBodyIntakePerClientLimit',
            'TimestampProcessingLimit',
            'TimestampProcessingPerClientLimit')) {
        if ($null -eq $ExistingSettings -or $null -eq $ExistingSettings[$key]) { continue }
        $node = $document.SelectSingleNode("/configuration/appSettings/add[@key='$key']")
        if ($null -eq $node) {
            throw "The published web.config does not contain the upgrade-preserved '$key' appSetting."
        }
        $node.SetAttribute('value', [string]$ExistingSettings[$key])
    }
    $document.Save($path)
}

function Get-OpenTimeStampRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $normalizedRoot = (Get-OpenTimeStampCanonicalDirectoryPath -Path $Root).TrimEnd('\')
    $normalizedPath = Get-OpenTimeStampCanonicalDirectoryPath -Path $Path
    Assert-OpenTimeStampPathContained -Parent $normalizedRoot -Child $normalizedPath
    return $normalizedPath.Substring($normalizedRoot.Length + 1).Replace('\', '/')
}

function Write-OpenTimeStampDeploymentManifestObject {
    param(
        [Parameter(Mandatory = $true)]
        $Manifest,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $json = $Manifest | ConvertTo-Json -Depth 5
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, $encoding)
}

function New-OpenTimeStampDeploymentManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PayloadPath,

        [string]$ReleaseId
    )

    $root = Get-OpenTimeStampCanonicalDirectoryPath -Path $PayloadPath
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "The publish output '$root' does not exist."
    }

    Assert-OpenTimeStampNoReparsePoints -Root $root
    $appDataPath = Join-Path $root 'App_Data'
    if (Test-Path -LiteralPath $appDataPath) {
        throw "Published payloads must not contain an App_Data file or directory ('$appDataPath')."
    }

    if ([string]::IsNullOrWhiteSpace($ReleaseId)) {
        $ReleaseId = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss\Z') + '-' +
            [Guid]::NewGuid().ToString('N').Substring(0, 12)
    }

    if ($ReleaseId -notmatch '^[0-9]{14}Z-[0-9a-f]{12}$') {
        throw "ReleaseId '$ReleaseId' is not in the required deployment format."
    }

    $manifestPath = Join-Path $root $script:OpenTimeStampDeploymentManifestName
    $publishMarkerPath = Join-Path $root $script:OpenTimeStampPublishMarkerName
    if (Test-Path -LiteralPath $publishMarkerPath) {
        Assert-OpenTimeStampPublishMarker -OutputPath $root | Out-Null
    }
    $files = @(foreach ($file in @(
            Get-ChildItem -LiteralPath $root -Force -File -Recurse | Sort-Object FullName)) {
        if ($file.FullName.Equals($manifestPath, [System.StringComparison]::OrdinalIgnoreCase) -or
            $file.FullName.Equals($publishMarkerPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $relative = Get-OpenTimeStampRelativePath -Root $root -Path $file.FullName
        if ($relative -match '^(?i:App_Data)(?:/|$)') {
            throw "Published payloads must not contain mutable App_Data content ('$relative')."
        }

        [PSCustomObject]@{
            Path = $relative
            Length = [long]$file.Length
            Sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
        }
    })

    $required = @('Web.config', 'Global.asax', 'bin/OpenTimeStamp.Web.dll', 'bin/OpenTimeStamp.Core.dll')
    $publishedNames = @($files | ForEach-Object { [string]$_.Path })
    foreach ($requiredFile in $required) {
        if ($publishedNames -notcontains $requiredFile) {
            throw "The publish output is missing required file '$requiredFile'."
        }
    }

    Assert-OpenTimeStampWebConfig -Path (Join-Path $root 'Web.config') | Out-Null
    $manifest = [ordered]@{
        Product = 'OpenTimeStamp'
        SchemaVersion = 1
        ReleaseId = $ReleaseId
        CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Files = $files
    }
    Write-OpenTimeStampDeploymentManifestObject -Manifest $manifest -Path $manifestPath
    return $manifestPath
}

function Assert-OpenTimeStampManifestSignature {
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$SignaturePath,
        [Parameter(Mandatory = $true)][string]$TrustedSignerThumbprint
    )

    $manifest = [System.IO.Path]::GetFullPath($ManifestPath)
    $signature = [System.IO.Path]::GetFullPath($SignaturePath)
    foreach ($path in @($manifest, $signature)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Manifest-signature input '$path' is not an existing file."
        }
        Assert-OpenTimeStampNoReparsePoints -Root $path -AncestryOnly
        if (((Get-Item -LiteralPath $path -Force).Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Manifest-signature input '$path' is a reparse point."
        }
    }
    if ((Get-Item -LiteralPath $signature -Force).Length -gt 1048576) {
        throw 'The detached manifest signature exceeds 1 MiB.'
    }

    # Hold the manifest open without write/delete sharing while capturing one
    # bounded byte snapshot. Signature verification and JSON parsing must consume
    # these same bytes so a mutable source cannot substitute a different manifest
    # between payload approval and signer verification.
    $manifestStream = [System.IO.FileStream]::new(
        $manifest,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read,
        4096,
        [System.IO.FileOptions]::SequentialScan)
    try {
        if ($manifestStream.Length -gt 4194304) {
            throw 'The deployment manifest exceeds 4 MiB.'
        }

        $manifestBytes = New-Object byte[] ([int]$manifestStream.Length)
        $offset = 0
        while ($offset -lt $manifestBytes.Length) {
            $read = $manifestStream.Read($manifestBytes, $offset, $manifestBytes.Length - $offset)
            if ($read -eq 0) { throw 'The deployment manifest ended before its declared length.' }
            $offset += $read
        }
    }
    finally {
        $manifestStream.Dispose()
    }

    $expectedThumbprint = ($TrustedSignerThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($expectedThumbprint -notmatch '^[0-9A-F]{40}$') {
        throw 'TrustedManifestSignerThumbprint must be one complete SHA-1 certificate thumbprint.'
    }
    try {
        # On .NET Framework, SignedCms is in the inbox System.Security assembly.
        # Never load a same-named assembly from the unauthenticated payload.
        Add-Type -AssemblyName System.Security
        $content = [System.Security.Cryptography.Pkcs.ContentInfo]::new(
            $manifestBytes)
        $signedCms = [System.Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
        $signedCms.Decode([System.IO.File]::ReadAllBytes($signature))
        $signedCms.CheckSignature($true)
    }
    catch {
        throw "The detached deployment-manifest CMS signature is invalid: $($_.Exception.Message)"
    }
    if ($signedCms.SignerInfos.Count -ne 1 -or $null -eq $signedCms.SignerInfos[0].Certificate) {
        throw 'The detached deployment-manifest signature must contain exactly one signer certificate.'
    }
    $actualThumbprint = $signedCms.SignerInfos[0].Certificate.Thumbprint.ToUpperInvariant()
    if (-not $actualThumbprint.Equals($expectedThumbprint, [System.StringComparison]::Ordinal)) {
        throw "The deployment manifest was signed by '$actualThumbprint' instead of '$expectedThumbprint'."
    }

    try {
        $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $manifestJson = $strictUtf8.GetString($manifestBytes)
        if ($manifestJson.Length -ne 0 -and $manifestJson[0] -eq [char]0xFEFF) {
            $manifestJson = $manifestJson.Substring(1)
        }
        $verifiedManifest = $manifestJson | ConvertFrom-Json
        if ($null -eq $verifiedManifest) { throw 'the JSON document is empty' }
    }
    catch {
        throw "The signed deployment manifest could not be parsed as UTF-8 JSON: $($_.Exception.Message)"
    }

    return [PSCustomObject]@{
        SignerThumbprint = $actualThumbprint
        SignerSubject = $signedCms.SignerInfos[0].Certificate.Subject
        Manifest = $verifiedManifest
    }
}

function Assert-OpenTimeStampPublishedPayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PayloadPath,

        $Manifest,

        [switch]$AllowPublishMarker
    )

    $root = Get-OpenTimeStampCanonicalDirectoryPath -Path $PayloadPath
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "The published payload '$root' does not exist."
    }

    Assert-OpenTimeStampNoReparsePoints -Root $root
    $appDataPath = Join-Path $root 'App_Data'
    if (Test-Path -LiteralPath $appDataPath) {
        throw "The published payload must not contain an App_Data file or directory ('$appDataPath')."
    }

    $manifestPath = Join-Path $root $script:OpenTimeStampDeploymentManifestName
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "The payload is missing required manifest '$script:OpenTimeStampDeploymentManifestName'."
    }
    $publishMarkerPath = Join-Path $root $script:OpenTimeStampPublishMarkerName
    if (Test-Path -LiteralPath $publishMarkerPath) {
        if (-not $AllowPublishMarker) {
            throw "The deployed payload contains publish-only ownership entry '$script:OpenTimeStampPublishMarkerName'."
        }
        Assert-OpenTimeStampPublishMarker -OutputPath $root | Out-Null
    }

    if ($null -eq $Manifest) {
        try {
            $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        }
        catch {
            throw "The deployment manifest could not be parsed: $($_.Exception.Message)"
        }
    }
    else {
        # Validate against the object already approved by the caller rather than
        # replacing it with a reread of a mutable manifest file.
        $manifest = $Manifest
    }

    if ([string]$manifest.Product -ne 'OpenTimeStamp' -or [int]$manifest.SchemaVersion -ne 1 -or
        [string]$manifest.ReleaseId -notmatch '^[0-9]{14}Z-[0-9a-f]{12}$') {
        throw 'The deployment manifest product, schema version, or release identifier is invalid.'
    }

    $entries = @($manifest.Files)
    if ($entries.Count -eq 0 -or $entries.Count -gt 4096) {
        throw 'The deployment manifest has an invalid file count.'
    }

    $expected = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        $relative = ([string]$entry.Path).Replace('/', '\')
        if ([string]::IsNullOrWhiteSpace($relative) -or [System.IO.Path]::IsPathRooted($relative) -or
            $relative -match '(^|\\)\.\.(\\|$)' -or $relative -match '^(?i:App_Data)(?:\\|$)') {
            throw "The manifest contains unsafe path '$relative'."
        }

        $fullPath = Get-OpenTimeStampCanonicalDirectoryPath -Path (Join-Path $root $relative)
        Assert-OpenTimeStampPathContained -Parent $root -Child $fullPath
        if ($expected.ContainsKey($relative)) {
            throw "The manifest contains duplicate path '$relative'."
        }

        if ([string]$entry.Sha256 -notmatch '^[0-9A-Fa-f]{64}$' -or [long]$entry.Length -lt 0) {
            throw "The manifest metadata for '$relative' is invalid."
        }

        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            throw "Manifest file '$relative' is missing from the payload."
        }

        $item = Get-Item -LiteralPath $fullPath -Force
        if ([long]$item.Length -ne [long]$entry.Length -or
            (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash -ne ([string]$entry.Sha256).ToUpperInvariant()) {
            throw "Manifest validation failed for '$relative'."
        }

        $expected.Add($relative, $entry)
    }

    foreach ($file in @(Get-ChildItem -LiteralPath $root -Force -File -Recurse)) {
        if ($file.FullName.Equals($manifestPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        if ($AllowPublishMarker -and
            $file.FullName.Equals((Join-Path $root $script:OpenTimeStampPublishMarkerName),
                [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $relative = (Get-OpenTimeStampRelativePath -Root $root -Path $file.FullName).Replace('/', '\')
        if (-not $expected.ContainsKey($relative)) {
            throw "The payload contains unmanifested file '$relative'."
        }
    }

    foreach ($required in @('Web.config', 'Global.asax', 'bin\OpenTimeStamp.Web.dll', 'bin\OpenTimeStamp.Core.dll')) {
        if (-not $expected.ContainsKey($required)) {
            throw "The deployment manifest is missing required file '$required'."
        }
    }

    Assert-OpenTimeStampWebConfig -Path (Join-Path $root 'Web.config') | Out-Null
    return $manifest
}

function Assert-OpenTimeStampPublishOutputSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot,

        [switch]$AllowLegacyDefaultOutput
    )

    $output = (Get-OpenTimeStampCanonicalDirectoryPath -Path $OutputPath).TrimEnd('\')
    $repository = (Get-OpenTimeStampCanonicalDirectoryPath -Path $RepositoryRoot).TrimEnd('\')
    $driveRoot = [System.IO.Path]::GetPathRoot($output).TrimEnd('\')
    if ($output.Equals($driveRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $output.Equals($repository, [System.StringComparison]::OrdinalIgnoreCase) -or
        (Test-OpenTimeStampPathContained -Parent $output -Child $repository)) {
        throw 'A drive root, the repository root, or an ancestor of the repository cannot be used as the publish output directory.'
    }

    $artifactsRoot = (Join-Path $repository 'artifacts').TrimEnd('\')
    if (Test-OpenTimeStampPathContained -Parent $repository -Child $output) {
        if ($output.Equals($artifactsRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-OpenTimeStampPathContained -Parent $artifactsRoot -Child $output)) {
            throw 'A publish output inside the repository must be a child directory under artifacts, not the artifacts root itself.'
        }
    }

    Assert-OpenTimeStampNoReparsePoints -Root $output
    $ancestor = $output
    while (-not [string]::IsNullOrWhiteSpace($ancestor)) {
        if (Test-Path -LiteralPath (Join-Path $ancestor $script:OpenTimeStampDeploymentMarkerName) -PathType Leaf) {
            throw "The publish output is inside the marked OpenTimeStamp deployment root '$ancestor'."
        }
        $parent = Split-Path -Parent $ancestor
        if ([string]::IsNullOrWhiteSpace($parent) -or
            $parent.Equals($ancestor, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $ancestor = $parent
    }
    if (-not (Test-Path -LiteralPath $output)) {
        return $output
    }
    if (-not (Test-Path -LiteralPath $output -PathType Container)) {
        throw "The publish output '$output' exists but is not a directory."
    }

    if ((Test-Path -LiteralPath (Join-Path $output $script:OpenTimeStampDeploymentMarkerName) -PathType Leaf) -or
        (Test-Path -LiteralPath (Join-Path $output 'Releases') -PathType Container)) {
        throw 'The publish output is an OpenTimeStamp deployment root. Publish to a separate staging directory.'
    }

    $publishMarker = Join-Path $output $script:OpenTimeStampPublishMarkerName
    if (Test-Path -LiteralPath $publishMarker -PathType Leaf) {
        Assert-OpenTimeStampPublishMarker -OutputPath $output | Out-Null
    }
    elseif ($AllowLegacyDefaultOutput) {
        Assert-OpenTimeStampLegacyDefaultPublishOutput -OutputPath $output -RepositoryRoot $repository | Out-Null
    }
    else {
        throw ("The existing publish output '$output' is not an owned OpenTimeStamp publish staging directory " +
            "and will not be replaced because the staging ownership marker " +
            "'$script:OpenTimeStampPublishMarkerName' is missing.")
    }

    return $output
}

function Assert-OpenTimeStampLegacyDefaultPublishOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    $output = (Get-OpenTimeStampCanonicalDirectoryPath -Path $OutputPath).TrimEnd('\')
    $repository = (Get-OpenTimeStampCanonicalDirectoryPath -Path $RepositoryRoot).TrimEnd('\')
    $legacyDefault = (Join-Path $repository 'artifacts\OpenTimeStamp').TrimEnd('\')
    if (-not $output.Equals($legacyDefault, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Only the historical artifacts\OpenTimeStamp default can be adopted as a legacy publish output.'
    }
    if (-not (Test-Path -LiteralPath $output -PathType Container)) {
        throw "The legacy publish output '$output' is not an existing directory."
    }

    Assert-OpenTimeStampNoReparsePoints -Root $output
    foreach ($forbidden in @($script:OpenTimeStampDeploymentMarkerName,
            $script:OpenTimeStampPublishMarkerName, 'Releases')) {
        if (Test-Path -LiteralPath (Join-Path $output $forbidden)) {
            throw "The legacy publish output contains forbidden deployment or ownership entry '$forbidden'."
        }
    }

    $manifestPath = Join-Path $output $script:OpenTimeStampDeploymentManifestName
    if (Test-Path -LiteralPath $manifestPath) {
        # A publisher revision between the legacy and owned-staging formats
        # emitted a full deployment manifest but no ownership marker. Require
        # that exact manifest to authenticate every existing payload file.
        $manifest = Assert-OpenTimeStampPublishedPayload -PayloadPath $output
        $expectedDirectories = New-Object 'System.Collections.Generic.HashSet[string]' `
            ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in @($manifest.Files)) {
            $parent = Split-Path -Parent (([string]$entry.Path).Replace('/', '\'))
            while (-not [string]::IsNullOrWhiteSpace($parent)) {
                [void]$expectedDirectories.Add($parent)
                $parent = Split-Path -Parent $parent
            }
        }
        foreach ($directory in @(Get-ChildItem -LiteralPath $output -Force -Directory -Recurse)) {
            $relative = (Get-OpenTimeStampRelativePath -Root $output -Path $directory.FullName).Replace('/', '\')
            if (-not $expectedDirectories.Contains($relative)) {
                throw "The manifested legacy publish output contains unmanifested directory '$relative'."
            }
        }
        return $output
    }

    $allowedTopLevel = @('App_Data', 'bin', 'Global.asax', 'Web.config')
    foreach ($entry in @(Get-ChildItem -LiteralPath $output -Force)) {
        if ($allowedTopLevel -notcontains $entry.Name) {
            throw "The legacy publish output contains unexpected top-level entry '$($entry.Name)'."
        }
    }

    foreach ($requiredFile in @('Global.asax', 'Web.config', 'bin\OpenTimeStamp.Web.dll',
            'bin\OpenTimeStamp.Core.dll')) {
        if (-not (Test-Path -LiteralPath (Join-Path $output $requiredFile) -PathType Leaf)) {
            throw "The legacy publish output is missing required file '$requiredFile'."
        }
    }
    Assert-OpenTimeStampWebConfig -Path (Join-Path $output 'Web.config') | Out-Null

    $allowedBinFiles = @('OpenTimeStamp.Core.dll', 'OpenTimeStamp.Core.pdb', 'OpenTimeStamp.Web.dll',
        'OpenTimeStamp.Web.dll.config', 'OpenTimeStamp.Web.pdb')
    foreach ($entry in @(Get-ChildItem -LiteralPath (Join-Path $output 'bin') -Force)) {
        if (-not $entry.PSIsContainer -and $allowedBinFiles -contains $entry.Name) { continue }
        throw "The legacy publish output contains unexpected bin entry '$($entry.Name)'."
    }

    $appDataPath = Join-Path $output 'App_Data'
    if (Test-Path -LiteralPath $appDataPath) {
        if (-not (Test-Path -LiteralPath $appDataPath -PathType Container)) {
            throw 'The legacy publish output App_Data entry is not a directory.'
        }
        $appDataEntries = @(Get-ChildItem -LiteralPath $appDataPath -Force)
        if ($appDataEntries.Count -gt 1 -or
            ($appDataEntries.Count -eq 1 -and
                ($appDataEntries[0].PSIsContainer -or $appDataEntries[0].Name -ne '.gitkeep' -or
                    [long]$appDataEntries[0].Length -ne 0))) {
            throw 'The legacy publish output contains runtime App_Data content and cannot be adopted.'
        }
    }

    return $output
}

function Test-OpenTimeStampNewIisApplicationRollbackCandidate {
    param(
        [bool]$ApplicationPresent,
        [bool]$SelectionMatches,
        [object[]]$VirtualDirectories,
        [string]$ExpectedPhysicalPath
    )

    if (-not $ApplicationPresent -or -not $SelectionMatches) { return $false }

    $directories = @($VirtualDirectories)
    if ($directories.Count -ne 1) { return $false }

    $root = $directories[0]
    if ([string]$root.path -ne '/' -or [string]::IsNullOrWhiteSpace([string]$root.physicalPath) -or
        [string]::IsNullOrWhiteSpace($ExpectedPhysicalPath)) {
        return $false
    }

    try {
        return (Get-OpenTimeStampCanonicalDirectoryPath -Path ([string]$root.physicalPath)).Equals(
            (Get-OpenTimeStampCanonicalDirectoryPath -Path $ExpectedPhysicalPath),
            [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

function Write-OpenTimeStampPublishMarker {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $root = Get-OpenTimeStampCanonicalDirectoryPath -Path $OutputPath
    Assert-OpenTimeStampNoReparsePoints -Root $root
    if ((Test-Path -LiteralPath $root) -and
        -not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "The publish staging path '$root' exists but is not a directory."
    }
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }
    Assert-OpenTimeStampNoReparsePoints -Root $root

    $marker = [ordered]@{
        Product = 'OpenTimeStamp'
        SchemaVersion = 1
        Purpose = 'PublishStaging'
        OutputPath = $root
        StagingId = [Guid]::NewGuid().ToString('D')
        CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    $path = Join-Path $root $script:OpenTimeStampPublishMarkerName
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText(
        $path,
        (($marker | ConvertTo-Json -Depth 3) + [Environment]::NewLine),
        $encoding)
    return $path
}

function Assert-OpenTimeStampPublishMarker {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $root = Get-OpenTimeStampCanonicalDirectoryPath -Path $OutputPath
    $path = Join-Path $root $script:OpenTimeStampPublishMarkerName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "The staging ownership marker '$script:OpenTimeStampPublishMarkerName' is missing or is not a file."
    }

    try {
        $marker = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $identifier = [Guid]::Empty
        $created = [DateTimeOffset]::MinValue
        if ([string]$marker.Product -ne 'OpenTimeStamp' -or [int]$marker.SchemaVersion -ne 1 -or
            [string]$marker.Purpose -ne 'PublishStaging' -or
            -not ([string]$marker.OutputPath).Equals($root, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not [Guid]::TryParse([string]$marker.StagingId, [ref]$identifier) -or
            $identifier -eq [Guid]::Empty -or
            -not [DateTimeOffset]::TryParse([string]$marker.CreatedUtc,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind, [ref]$created)) {
            throw 'marker fields are invalid'
        }
    }
    catch {
        throw "The staging ownership marker '$path' is invalid: $($_.Exception.Message)"
    }

    return $marker
}

function Copy-OpenTimeStampPublishedPayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PayloadPath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        $Manifest,

        [System.Security.Principal.SecurityIdentifier]$ApplicationPoolSid
    )

    $sourceRoot = Get-OpenTimeStampCanonicalDirectoryPath -Path $PayloadPath
    $destinationRoot = Get-OpenTimeStampCanonicalDirectoryPath -Path $DestinationPath
    if (Test-Path -LiteralPath $destinationRoot) {
        throw "The release staging directory '$destinationRoot' already exists."
    }

    # Freeze the manifest object that was validated by the caller. The source
    # directory may be updated independently while this copy is in progress;
    # staging must still prove that it contains the exact bytes already approved.
    $frozenEntries = @(foreach ($entry in @($Manifest.Files)) {
        [PSCustomObject][ordered]@{
            Path = [string]$entry.Path
            Length = [long]$entry.Length
            Sha256 = ([string]$entry.Sha256).ToUpperInvariant()
        }
    })
    $frozenManifest = [ordered]@{
        Product = [string]$Manifest.Product
        SchemaVersion = [int]$Manifest.SchemaVersion
        ReleaseId = [string]$Manifest.ReleaseId
        CreatedUtc = [string]$Manifest.CreatedUtc
        Files = $frozenEntries
    }

    $destinationCreated = $false
    try {
        New-Item -ItemType Directory -Path $destinationRoot -ErrorAction Stop | Out-Null
        $destinationCreated = $true
        if ($null -ne $ApplicationPoolSid) {
            # Protect the empty stage before copying any release bytes into it so a
            # broadly writable deployment parent cannot create a validation race.
            Set-OpenTimeStampRestrictedDirectoryAcl -Path $destinationRoot `
                -ApplicationPoolSid $ApplicationPoolSid `
                -PoolRights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
        }

        foreach ($entry in $frozenEntries) {
            $relative = ([string]$entry.Path).Replace('/', '\')
            $source = Get-OpenTimeStampCanonicalDirectoryPath -Path (Join-Path $sourceRoot $relative)
            $destination = Get-OpenTimeStampCanonicalDirectoryPath -Path (Join-Path $destinationRoot $relative)
            Assert-OpenTimeStampPathContained -Parent $sourceRoot -Child $source
            Assert-OpenTimeStampPathContained -Parent $destinationRoot -Child $destination
            $parent = Split-Path -Parent $destination
            if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
                New-Item -ItemType Directory -Path $parent -Force | Out-Null
            }

            Copy-Item -LiteralPath $source -Destination $destination -Force
            $copiedItem = Get-Item -LiteralPath $destination -Force
            if ([long]$copiedItem.Length -ne [long]$entry.Length -or
                (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne [string]$entry.Sha256) {
                throw "Source file '$relative' changed after its manifest was validated."
            }
        }

        $destinationManifest = Join-Path $destinationRoot $script:OpenTimeStampDeploymentManifestName
        Write-OpenTimeStampDeploymentManifestObject -Manifest $frozenManifest -Path $destinationManifest

        Assert-OpenTimeStampNoReparsePoints -Root $destinationRoot
        $copiedManifest = Assert-OpenTimeStampPublishedPayload -PayloadPath $destinationRoot `
            -Manifest $frozenManifest
        if ([string]$copiedManifest.ReleaseId -ne [string]$frozenManifest.ReleaseId) {
            throw 'The frozen payload manifest changed during staging.'
        }
    }
    catch {
        $copyError = $_
        if ($destinationCreated -and (Test-Path -LiteralPath $destinationRoot)) {
            try {
                Remove-OpenTimeStampControlledDirectory `
                    -ExpectedParent (Split-Path -Parent $destinationRoot) -Path $destinationRoot
            }
            catch {
                Write-Warning "Incomplete staging directory '$destinationRoot' could not be removed: $($_.Exception.Message)"
            }
        }

        throw $copyError
    }
}

function Test-OpenTimeStampLegacyConfigurationFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }

    try {
        $document = Read-OpenTimeStampXmlDocument -Path $Path
        return $document.DocumentElement.LocalName -eq 'OpenTimeStampConfiguration' -and
            $document.DocumentElement.NamespaceURI -eq 'urn:opentimestamp:configuration:v1'
    }
    catch {
        return $false
    }
}

function Test-OpenTimeStampLegacyStateFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        return $bytes.Length -eq 28 -and $bytes[0] -eq 0x4f -and $bytes[1] -eq 0x54 -and
            $bytes[2] -eq 0x53 -and $bytes[3] -eq 0x31
    }
    catch {
        return $false
    }
}

function Test-OpenTimeStampDataDirectoryCoordinationScaffolding {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [switch]$AllowDataMarker
    )

    $root = Get-OpenTimeStampCanonicalDirectoryPath -Path $Path
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return $false }

    Assert-OpenTimeStampNoReparsePoints -Root $root
    $coordinationArtifactCount = 0
    $dataMarkerFound = $false
    foreach ($item in @(Get-ChildItem -LiteralPath $root -Force)) {
        if ($item.Name -eq $script:OpenTimeStampDataMarkerName) {
            if ($AllowDataMarker -and -not $item.PSIsContainer) {
                $dataMarkerFound = $true
                continue
            }
            return $false
        }
        if ($item.Name -eq '.gitkeep') {
            if ($item.PSIsContainer -or [long]$item.Length -ne 0) { return $false }
            continue
        }
        if ($item.Name -in @('tsa.config.lock', 'issuance.state.lock')) {
            if ($item.PSIsContainer -or [long]$item.Length -ne 0) { return $false }
            $coordinationArtifactCount++
            continue
        }
        if ($item.Name -eq 'Logs' -and $item.PSIsContainer) {
            foreach ($logItem in @(Get-ChildItem -LiteralPath $item.FullName -Force -Recurse)) {
                if ($logItem.PSIsContainer -or $logItem.Name -ne '.audit.lock' -or
                    [long]$logItem.Length -ne 0) {
                    return $false
                }
                $coordinationArtifactCount++
            }
            continue
        }
        return $false
    }

    return $coordinationArtifactCount -ne 0 -or ($AllowDataMarker -and $dataMarkerFound)
}

function Get-OpenTimeStampDataDirectoryClassification {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $root = Get-OpenTimeStampCanonicalDirectoryPath -Path $Path
    if (-not (Test-Path -LiteralPath $root)) {
        return [PSCustomObject]@{ Kind = 'Absent'; Path = $root; Marker = $null }
    }

    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "The data path '$root' exists but is not a directory."
    }

    Assert-OpenTimeStampNoReparsePoints -Root $root
    $markerPath = Join-Path $root $script:OpenTimeStampDataMarkerName
    if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
        try {
            $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
            $identifier = [Guid]::Empty
            if ([string]$marker.Product -ne 'OpenTimeStamp' -or [int]$marker.SchemaVersion -ne 1 -or
                -not [Guid]::TryParse([string]$marker.DataDirectoryId, [ref]$identifier) -or $identifier -eq [Guid]::Empty -or
                -not ([string]$marker.DataPath).Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw 'marker fields are invalid'
            }
            $issuanceInitializedProperty = $marker.PSObject.Properties['IssuanceStateInitialized']
            if ($null -ne $issuanceInitializedProperty -and
                $issuanceInitializedProperty.Value -isnot [bool]) {
                throw 'marker issuance-state lifecycle is invalid'
            }
        }
        catch {
            throw "The OpenTimeStamp data marker '$markerPath' is invalid: $($_.Exception.Message)"
        }

        return [PSCustomObject]@{ Kind = 'Marked'; Path = $root; Marker = $marker }
    }

    $items = @(Get-ChildItem -LiteralPath $root -Force)
    if ($items.Count -eq 0) {
        return [PSCustomObject]@{ Kind = 'Empty'; Path = $root; Marker = $null }
    }
    if ($items.Count -eq 1 -and $items[0].Name -eq '.gitkeep' -and -not $items[0].PSIsContainer) {
        return [PSCustomObject]@{ Kind = 'Empty'; Path = $root; Marker = $null }
    }

    # Persistent zero-content lock files can remain after an interrupted first
    # initialization. They are recoverable scaffolding, never state evidence.
    if (Test-OpenTimeStampDataDirectoryCoordinationScaffolding -Path $root) {
        return [PSCustomObject]@{ Kind = 'Empty'; Path = $root; Marker = $null }
    }

    $allowedNames = @('.gitkeep', 'tsa.config', 'tsa.config.bak', 'tsa.config.lock',
        'issuance.state', 'issuance.state.bak', 'issuance.state.lock', 'Logs')
    $unexpected = @($items | Where-Object { $allowedNames -notcontains $_.Name })
    $shapeValid = @($items | Where-Object {
            ($_.Name -eq 'Logs' -and -not $_.PSIsContainer) -or
            ($_.Name -ne 'Logs' -and $_.PSIsContainer)
        }).Count -eq 0
    $coordinationFilesValid = @($items | Where-Object {
            $_.Name -in @('tsa.config.lock', 'issuance.state.lock') -and
            ($_.PSIsContainer -or [long]$_.Length -ne 0)
        }).Count -eq 0
    $validConfiguration = Test-OpenTimeStampLegacyConfigurationFile -Path (Join-Path $root 'tsa.config')
    $validState = Test-OpenTimeStampLegacyStateFile -Path (Join-Path $root 'issuance.state')
    $logsValid = $true
    $logsPath = Join-Path $root 'Logs'
    if (Test-Path -LiteralPath $logsPath -PathType Container) {
        foreach ($logItem in @(Get-ChildItem -LiteralPath $logsPath -Force -Recurse)) {
            $validAuditLock = -not $logItem.PSIsContainer -and $logItem.Name -eq '.audit.lock' -and
                [long]$logItem.Length -eq 0
            if (-not $validAuditLock -and
                ($logItem.PSIsContainer -or
                    $logItem.Name -notmatch '^timestamp-[0-9]{8}(?:-(?:[01][0-9]|2[0-3]))?\.jsonl$')) {
                $logsValid = $false
                break
            }
        }
    }

    if ($unexpected.Count -eq 0 -and $shapeValid -and $coordinationFilesValid -and $logsValid -and
        ($validConfiguration -or $validState)) {
        return [PSCustomObject]@{ Kind = 'Legacy'; Path = $root; Marker = $null }
    }

    return [PSCustomObject]@{ Kind = 'Unrecognized'; Path = $root; Marker = $null }
}

function Test-OpenTimeStampDataDirectoryUninitializedScaffolding {
    param(
        [Parameter(Mandatory = $true)]
        $Classification
    )

    if ($null -eq $Classification -or [string]$Classification.Kind -ne 'Marked' -or
        $null -eq $Classification.Marker) {
        return $false
    }

    $property = $Classification.Marker.PSObject.Properties['IssuanceStateInitialized']
    if ($null -eq $property -or $property.Value -isnot [bool] -or [bool]$property.Value) {
        return $false
    }

    return Test-OpenTimeStampDataDirectoryCoordinationScaffolding `
        -Path ([string]$Classification.Path) -AllowDataMarker
}

function Initialize-OpenTimeStampDataDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [switch]$AdoptExisting,

        [switch]$DirectoryCreatedByCaller
    )

    $classification = Get-OpenTimeStampDataDirectoryClassification -Path $Path
    if ($classification.Kind -eq 'Marked') {
        return [PSCustomObject]@{
            Path = $classification.Path
            MarkerCreated = $false
            MarkerPath = Join-Path $classification.Path $script:OpenTimeStampDataMarkerName
            MarkerId = [string]$classification.Marker.DataDirectoryId
            DirectoryCreated = [bool]$DirectoryCreatedByCaller
        }
    }

    if ($classification.Kind -eq 'Legacy' -and -not $AdoptExisting) {
        throw "The legacy data directory '$($classification.Path)' is unmarked. Rerun with -AdoptExistingDataPath after reviewing its exact contents."
    }

    if ($classification.Kind -eq 'Unrecognized') {
        throw "The non-empty data directory '$($classification.Path)' is not a marked or safely recognizable OpenTimeStamp data directory."
    }

    $createdDirectory = $classification.Kind -eq 'Absent'
    if ($createdDirectory) {
        New-Item -ItemType Directory -Path $classification.Path -Force | Out-Null
    }

    $marker = [ordered]@{
        Product = 'OpenTimeStamp'
        SchemaVersion = 1
        DataDirectoryId = [Guid]::NewGuid().ToString('D')
        DataPath = $classification.Path
        IssuanceStateInitialized = $classification.Kind -eq 'Legacy'
        CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    $markerId = [string]$marker.DataDirectoryId
    $markerPath = Join-Path $classification.Path $script:OpenTimeStampDataMarkerName
    $temporary = $markerPath + '.new-' + [Guid]::NewGuid().ToString('N')
    $encoding = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($temporary, (($marker | ConvertTo-Json -Depth 3) + [Environment]::NewLine), $encoding)
        Move-Item -LiteralPath $temporary -Destination $markerPath
    }
    catch {
        $initializationError = $_
        if ($createdDirectory -and (Test-Path -LiteralPath $classification.Path -PathType Container) -and
            @(Get-ChildItem -LiteralPath $classification.Path -Force).Count -eq 0) {
            Remove-Item -LiteralPath $classification.Path -Force
        }
        throw $initializationError
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
    return [PSCustomObject]@{
        Path = $classification.Path
        MarkerCreated = $true
        MarkerPath = $markerPath
        MarkerId = $markerId
        DirectoryCreated = $createdDirectory -or [bool]$DirectoryCreatedByCaller
    }
}

function Set-OpenTimeStampDataDirectoryIssuanceInitialized {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedDataDirectoryId
    )

    $classification = Get-OpenTimeStampDataDirectoryClassification -Path $Path
    if ($classification.Kind -ne 'Marked') {
        throw "The data directory '$($classification.Path)' is not marked."
    }
    if (-not ([string]$classification.Marker.DataDirectoryId).Equals(
            $ExpectedDataDirectoryId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The data marker in '$($classification.Path)' is not owned by this deployment operation."
    }

    $property = $classification.Marker.PSObject.Properties['IssuanceStateInitialized']
    if ($null -ne $property -and [bool]$property.Value) { return $classification }

    $classification.Marker | Add-Member -NotePropertyName IssuanceStateInitialized `
        -NotePropertyValue $true -Force
    $markerPath = Join-Path $classification.Path $script:OpenTimeStampDataMarkerName
    $temporary = $markerPath + '.new-' + [Guid]::NewGuid().ToString('N')
    $backup = $markerPath + '.old-' + [Guid]::NewGuid().ToString('N')
    $encoding = New-Object System.Text.UTF8Encoding($false)
    try {
        $json = $classification.Marker | ConvertTo-Json -Depth 3
        [System.IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, $encoding)
        [System.IO.File]::Replace($temporary, $markerPath, $backup)
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
        if (Test-Path -LiteralPath $backup) {
            Remove-Item -LiteralPath $backup -Force
        }
    }

    $verified = Get-OpenTimeStampDataDirectoryClassification -Path $classification.Path
    $verifiedProperty = $verified.Marker.PSObject.Properties['IssuanceStateInitialized']
    if ($verified.Kind -ne 'Marked' -or $null -eq $verifiedProperty -or
        $verifiedProperty.Value -isnot [bool] -or -not [bool]$verifiedProperty.Value -or
        -not ([string]$verified.Marker.DataDirectoryId).Equals(
            $ExpectedDataDirectoryId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The issuance-state lifecycle marker in '$($classification.Path)' could not be verified."
    }

    return $verified
}

function Test-OpenTimeStampDeploymentRootMarker {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $root = Get-OpenTimeStampCanonicalDirectoryPath -Path $Path
    $markerPath = Join-Path $root $script:OpenTimeStampDeploymentMarkerName
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { return $false }
    try {
        $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
        $identifier = [Guid]::Empty
        if ([string]$marker.Product -ne 'OpenTimeStamp' -or [int]$marker.SchemaVersion -ne 1 -or
            -not [Guid]::TryParse([string]$marker.DeploymentId, [ref]$identifier) -or $identifier -eq [Guid]::Empty -or
            -not ([string]$marker.DeploymentRoot).Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'marker fields are invalid'
        }
        return $true
    }
    catch {
        throw "The deployment-root marker '$markerPath' is invalid: $($_.Exception.Message)"
    }
}

function Get-OpenTimeStampAclLocalFingerprint {
    param($Acl)

    $rules = @($Acl.Access | Where-Object { -not $_.IsInherited } | ForEach-Object {
        $rule = $_
        $identity = try { $rule.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]).Value } catch { [string]$rule.IdentityReference }
        '{0}|{1}|{2:X8}|{3}|{4}' -f $identity, $rule.AccessControlType,
            ([uint64]([int64]$rule.FileSystemRights -band 0xFFFFFFFFL)),
            $rule.InheritanceFlags, $rule.PropagationFlags
    } | Sort-Object)
    return ([PSCustomObject]@{
        Owner = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        Group = $Acl.GetGroup([System.Security.Principal.SecurityIdentifier]).Value
        Protected = [bool]$Acl.AreAccessRulesProtected
        Rules = $rules
    } | ConvertTo-Json -Compress)
}

function Get-OpenTimeStampAclLocalFingerprintFromSddl {
    param(
        [string]$Sddl,
        [bool]$IsDirectory,
        $Sections
    )
    $acl = if ($IsDirectory) {
        New-Object System.Security.AccessControl.DirectorySecurity
    } else {
        New-Object System.Security.AccessControl.FileSecurity
    }
    $acl.SetSecurityDescriptorSddlForm($Sddl, $Sections)
    return Get-OpenTimeStampAclLocalFingerprint -Acl $acl
}

function Set-OpenTimeStampRestrictedDirectoryAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$ApplicationPoolSid,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemRights]$PoolRights,

        [switch]$Recursive
    )

    $root = Get-OpenTimeStampCanonicalDirectoryPath -Path $Path
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "The ACL root '$root' does not exist."
    }

    Assert-OpenTimeStampNoReparsePoints -Root $root
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $sections = [System.Security.AccessControl.AccessControlSections]::Access -bor
        [System.Security.AccessControl.AccessControlSections]::Owner -bor
        [System.Security.AccessControl.AccessControlSections]::Group
    # Capture the entire hierarchy before changing the root. Inherited child
    # SDDL changes as soon as the root changes, so later reads are not a valid
    # pre-operation snapshot.
    $items = if ($Recursive) {
        @((Get-Item -LiteralPath $root -Force)) + @(Get-ChildItem -LiteralPath $root -Force -Recurse |
            Sort-Object @{ Expression = { $_.FullName.Length }; Descending = $false }, FullName)
    }
    else { @((Get-Item -LiteralPath $root -Force)) }
    $journal = @(foreach ($item in $items) {
        Assert-OpenTimeStampPathContained -Parent $root -Child $item.FullName -AllowEqual
        $beforeAcl = Get-Acl -LiteralPath $item.FullName
        [PSCustomObject]@{
            Path = $item.FullName
            IsRoot = $item.FullName.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)
            Before = $beforeAcl.GetSecurityDescriptorSddlForm($sections)
            BeforeLocal = Get-OpenTimeStampAclLocalFingerprint -Acl $beforeAcl
            AclObject = $beforeAcl
            Desired = $null
            DesiredLocal = $null
            Applied = $null
            AppliedLocal = $null
        }
    })

    $rootJournal = @($journal | Where-Object { $_.IsRoot })[0]
    $security = $rootJournal.AclObject
    $security.SetAccessRuleProtection($true, $false)
    foreach ($existingRule in @($security.Access | Where-Object { -not $_.IsInherited })) {
        [void]$security.RemoveAccessRuleSpecific($existingRule)
    }
    $security.SetOwner($administratorsSid)
    foreach ($definition in @(
        @($systemSid, [System.Security.AccessControl.FileSystemRights]::FullControl),
        @($administratorsSid, [System.Security.AccessControl.FileSystemRights]::FullControl),
        @($ApplicationPoolSid, $PoolRights))) {
        $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $definition[0], $definition[1], $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None, $allow)))
    }

    try {
        $rootDesired = $security.GetSecurityDescriptorSddlForm($sections)
        $rootJournal.Desired = $rootDesired
        $rootJournal.DesiredLocal = Get-OpenTimeStampAclLocalFingerprint -Acl $security
        $rootCurrent = (Get-Acl -LiteralPath $root).GetSecurityDescriptorSddlForm($sections)
        if (-not $rootCurrent.Equals([string]$rootJournal.Before, [System.StringComparison]::Ordinal)) {
            throw "The ACL for '$root' changed before the restricted ACL could be applied."
        }
        Set-Acl -LiteralPath $root -AclObject $security
        $rootVerifiedAcl = Get-Acl -LiteralPath $root
        $rootJournal.Applied = $rootVerifiedAcl.GetSecurityDescriptorSddlForm($sections)
        $rootJournal.AppliedLocal = Get-OpenTimeStampAclLocalFingerprint -Acl $rootVerifiedAcl
        if (-not $rootJournal.Applied.Equals($rootDesired, [System.StringComparison]::Ordinal) -or
            -not $rootVerifiedAcl.AreAccessRulesProtected) {
            throw "The restricted root ACL for '$root' was not applied exactly."
        }
        if (-not $Recursive) { return }

        foreach ($itemJournal in @($journal | Where-Object { -not $_.IsRoot })) {
            $acl = $itemJournal.AclObject
            $explicit = @($acl.Access | Where-Object { -not $_.IsInherited })
            if ($acl.AreAccessRulesProtected) { $acl.SetAccessRuleProtection($false, $false) }
            foreach ($rule in $explicit) { [void]$acl.RemoveAccessRuleSpecific($rule) }
            $itemJournal.Desired = $acl.GetSecurityDescriptorSddlForm($sections)
            $itemJournal.DesiredLocal = Get-OpenTimeStampAclLocalFingerprint -Acl $acl
            $currentAcl = Get-Acl -LiteralPath $itemJournal.Path
            if ((Get-OpenTimeStampAclLocalFingerprint -Acl $currentAcl) -ne $itemJournal.BeforeLocal) {
                throw "The local ACL for '$($itemJournal.Path)' changed before its inherited ACL could be applied."
            }
            Set-Acl -LiteralPath $itemJournal.Path -AclObject $acl
            $verified = Get-Acl -LiteralPath $itemJournal.Path
            $itemJournal.Applied = $verified.GetSecurityDescriptorSddlForm($sections)
            $itemJournal.AppliedLocal = Get-OpenTimeStampAclLocalFingerprint -Acl $verified
            if ($itemJournal.AppliedLocal -ne $itemJournal.DesiredLocal -or
                $verified.AreAccessRulesProtected -or
                @($verified.Access | Where-Object { -not $_.IsInherited }).Count -ne 0) {
                throw "Explicit or protected descendant ACLs could not be removed from '$($itemJournal.Path)'."
            }
        }
        foreach ($entry in $journal) {
            $finalApplied = (Get-Acl -LiteralPath $entry.Path).GetSecurityDescriptorSddlForm($sections)
            if ([string]::IsNullOrWhiteSpace([string]$entry.Applied) -or
                -not $finalApplied.Equals([string]$entry.Applied, [System.StringComparison]::Ordinal)) {
                throw "The ACL for '$($entry.Path)' changed before the restricted ACL transaction completed."
            }
        }
    }
    catch {
        $mutationError = $_
        $compensationErrors = [System.Collections.Generic.List[string]]::new()
        $descendantsToRestore = [System.Collections.Generic.List[object]]::new()
        try {
            if (-not (Test-Path -LiteralPath $rootJournal.Path)) { throw 'the root path disappeared' }
            $rootValidationAcl = Get-Acl -LiteralPath $rootJournal.Path
            $rootValidationSddl = $rootValidationAcl.GetSecurityDescriptorSddlForm($sections)
            $ownedRoot = if ([string]::IsNullOrWhiteSpace([string]$rootJournal.Applied)) {
                [string]$rootJournal.Desired
            } else { [string]$rootJournal.Applied }
            if (-not $rootValidationSddl.Equals([string]$rootJournal.Before, [System.StringComparison]::Ordinal) -and
                -not $rootValidationSddl.Equals($ownedRoot, [System.StringComparison]::Ordinal)) {
                throw 'the root changed after mutation'
            }
        }
        catch { $compensationErrors.Add("'$($rootJournal.Path)': $($_.Exception.Message)") }
        # Validate ownership of every descendant before restoring any potentially
        # broad explicit ACE. This prevents a later conflict from leaving a
        # partially opened tree below the still-hardened root.
        foreach ($entry in @($journal | Where-Object { -not $_.IsRoot } | Sort-Object `
                @{ Expression = { $_.Path.Length }; Descending = $true },
                @{ Expression = { $_.Path }; Descending = $true })) {
            try {
                if (-not (Test-Path -LiteralPath $entry.Path)) {
                    throw 'the path disappeared during ACL mutation'
                }
                $currentAcl = Get-Acl -LiteralPath $entry.Path
                $currentSddl = $currentAcl.GetSecurityDescriptorSddlForm($sections)
                $currentLocal = Get-OpenTimeStampAclLocalFingerprint -Acl $currentAcl
                if ($currentLocal -eq $entry.BeforeLocal) { continue }
                $owned = (-not [string]::IsNullOrWhiteSpace([string]$entry.Applied) -and
                        $currentSddl.Equals([string]$entry.Applied, [System.StringComparison]::Ordinal)) -or
                    (-not [string]::IsNullOrWhiteSpace([string]$entry.DesiredLocal) -and
                        $currentLocal -eq [string]$entry.DesiredLocal)
                if (-not $owned) {
                    $compensationErrors.Add("'$($entry.Path)' changed after mutation")
                    continue
                }
                $descendantsToRestore.Add($entry)
            }
            catch { $compensationErrors.Add("'$($entry.Path)': $($_.Exception.Message)") }
        }
        $restoreAttemptedDescendants = [System.Collections.Generic.List[object]]::new()
        if ($compensationErrors.Count -eq 0) {
            foreach ($entry in $descendantsToRestore) {
                try {
                    $currentAcl = Get-Acl -LiteralPath $entry.Path
                    $currentLocal = Get-OpenTimeStampAclLocalFingerprint -Acl $currentAcl
                    if ($currentLocal -ne [string]$entry.DesiredLocal -and
                        $currentLocal -ne [string]$entry.AppliedLocal) {
                        throw 'the ACL changed after compensation validation'
                    }
                    $currentAcl.SetSecurityDescriptorSddlForm([string]$entry.Before, $sections)
                    $restoreAttemptedDescendants.Add($entry)
                    Set-Acl -LiteralPath $entry.Path -AclObject $currentAcl
                    $restoredAcl = Get-Acl -LiteralPath $entry.Path
                    if ((Get-OpenTimeStampAclLocalFingerprint -Acl $restoredAcl) -ne $entry.BeforeLocal) {
                        throw 'the local ACL was not restored exactly'
                    }
                }
                catch { $compensationErrors.Add("'$($entry.Path)': $($_.Exception.Message)"); break }
            }
        }
        # Keep the root hardened if any descendant cannot be restored. Restoring
        # a potentially broad root over a partially restored tree fails open.
        $rootRestoreAttempted = $false
        if ($compensationErrors.Count -eq 0) {
            try {
                $currentRootAcl = Get-Acl -LiteralPath $rootJournal.Path
                $currentRoot = $currentRootAcl.GetSecurityDescriptorSddlForm($sections)
                if (-not $currentRoot.Equals([string]$rootJournal.Before, [System.StringComparison]::Ordinal)) {
                    $ownedRoot = if ([string]::IsNullOrWhiteSpace([string]$rootJournal.Applied)) {
                        [string]$rootJournal.Desired
                    } else { [string]$rootJournal.Applied }
                    if (-not $currentRoot.Equals($ownedRoot, [System.StringComparison]::Ordinal)) {
                        throw 'the root changed after mutation'
                    }
                    $currentRootAcl.SetSecurityDescriptorSddlForm([string]$rootJournal.Before, $sections)
                    $rootRestoreAttempted = $true
                    Set-Acl -LiteralPath $rootJournal.Path -AclObject $currentRootAcl
                }
            }
            catch { $compensationErrors.Add("'$($rootJournal.Path)': $($_.Exception.Message)") }
        }
        if ($compensationErrors.Count -eq 0) {
            foreach ($entry in $journal) {
                try {
                    $restored = (Get-Acl -LiteralPath $entry.Path).GetSecurityDescriptorSddlForm($sections)
                    if (-not $restored.Equals([string]$entry.Before, [System.StringComparison]::Ordinal)) {
                        $compensationErrors.Add("'$($entry.Path)' was not restored exactly")
                    }
                }
                catch { $compensationErrors.Add("'$($entry.Path)' verification: $($_.Exception.Message)") }
            }
        }
        if ($compensationErrors.Count -ne 0 -and
            ($rootRestoreAttempted -or $restoreAttemptedDescendants.Count -ne 0)) {
            # A root write may have succeeded before throwing. Re-harden it
            # first, then remove any broad local descendant ACEs restored above.
            try {
                $currentRootAcl = Get-Acl -LiteralPath $rootJournal.Path
                $currentRoot = $currentRootAcl.GetSecurityDescriptorSddlForm($sections)
                if ($currentRoot.Equals([string]$rootJournal.Before, [System.StringComparison]::Ordinal)) {
                    $currentRootAcl.SetSecurityDescriptorSddlForm($ownedRoot, $sections)
                    Set-Acl -LiteralPath $rootJournal.Path -AclObject $currentRootAcl
                }
                elseif (-not $currentRoot.Equals($ownedRoot, [System.StringComparison]::Ordinal)) {
                    throw 'the root changed before re-hardening'
                }
            }
            catch { $compensationErrors.Add("'$($rootJournal.Path)' re-hardening: $($_.Exception.Message)") }
            foreach ($entry in @($restoreAttemptedDescendants | Sort-Object `
                    @{ Expression = { $_.Path.Length }; Descending = $true },
                    @{ Expression = { $_.Path }; Descending = $true })) {
                try {
                    $currentAcl = Get-Acl -LiteralPath $entry.Path
                    $currentLocal = Get-OpenTimeStampAclLocalFingerprint -Acl $currentAcl
                    if ($currentLocal -eq [string]$entry.DesiredLocal) { continue }
                    if ($currentLocal -ne $entry.BeforeLocal) {
                        throw 'the ACL changed before re-hardening'
                    }
                    $currentAcl.SetSecurityDescriptorSddlForm([string]$entry.Desired, $sections)
                    Set-Acl -LiteralPath $entry.Path -AclObject $currentAcl
                    if ((Get-OpenTimeStampAclLocalFingerprint -Acl (Get-Acl -LiteralPath $entry.Path)) -ne
                        [string]$entry.DesiredLocal) { throw 'the ACL was not re-hardened exactly' }
                }
                catch { $compensationErrors.Add("'$($entry.Path)' re-hardening: $($_.Exception.Message)") }
            }
        }
        if ($compensationErrors.Count -ne 0) {
            throw "ACL mutation failed ('$($mutationError.Exception.Message)') and compensation failed closed: $($compensationErrors -join '; ')."
        }
        throw $mutationError
    }
}

function Get-OpenTimeStampRecursiveAclSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [switch]$RootOnly
    )

    $root = Get-OpenTimeStampCanonicalDirectoryPath -Path $Path
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "The ACL snapshot root '$root' does not exist."
    }
    Assert-OpenTimeStampNoReparsePoints -Root $root
    $sections = [System.Security.AccessControl.AccessControlSections]::Access -bor
        [System.Security.AccessControl.AccessControlSections]::Owner -bor
        [System.Security.AccessControl.AccessControlSections]::Group
    $items = if ($RootOnly) { @((Get-Item -LiteralPath $root -Force)) }
    else {
        @((Get-Item -LiteralPath $root -Force)) +
            @(Get-ChildItem -LiteralPath $root -Force -Recurse | Sort-Object { $_.FullName.Length }, FullName)
    }
    $entries = @(foreach ($item in $items) {
        $acl = Get-Acl -LiteralPath $item.FullName
        [PSCustomObject]@{
            Path = $item.FullName
            IsDirectory = [bool]$item.PSIsContainer
            Sddl = $acl.GetSecurityDescriptorSddlForm($sections)
        }
    })
    return [PSCustomObject]@{ Root = $root; Sections = $sections; Entries = $entries }
}

function Restore-OpenTimeStampRecursiveAclSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        $Snapshot,

        $ExpectedCurrentSnapshot
    )

    if ($null -eq $ExpectedCurrentSnapshot) { throw 'Exact ACL rollback requires an applied-state snapshot.' }
    $expected = @{}
    foreach ($entry in @($ExpectedCurrentSnapshot.Entries)) { $expected[[string]$entry.Path] = $entry }
    $entries = @(foreach ($entry in @($Snapshot.Entries)) {
        if (-not (Test-Path -LiteralPath $entry.Path) -or -not $expected.ContainsKey([string]$entry.Path)) {
            throw "ACL rollback cannot verify preexisting path '$($entry.Path)'."
        }
        $expectedEntry = $expected[[string]$entry.Path]
        $current = (Get-Acl -LiteralPath $entry.Path).GetSecurityDescriptorSddlForm($Snapshot.Sections)
        if (-not $current.Equals([string]$expectedEntry.Sddl, [System.StringComparison]::Ordinal)) {
            throw "ACL state for '$($entry.Path)' changed after the installer applied it; refusing to overwrite the external change."
        }
        [PSCustomObject]@{
            Path = [string]$entry.Path
            IsDirectory = [bool]$entry.IsDirectory
            OriginalSddl = [string]$entry.Sddl
            OriginalLocal = Get-OpenTimeStampAclLocalFingerprintFromSddl `
                -Sddl ([string]$entry.Sddl) -IsDirectory ([bool]$entry.IsDirectory) `
                -Sections $Snapshot.Sections
            AppliedSddl = [string]$expectedEntry.Sddl
            Attempted = $false
        }
    })

    try {
        foreach ($entry in @($entries | Sort-Object `
                @{ Expression = { $_.Path.Length }; Descending = $true },
                @{ Expression = { $_.Path }; Descending = $true })) {
            $security = Get-Acl -LiteralPath $entry.Path
            $current = $security.GetSecurityDescriptorSddlForm($Snapshot.Sections)
            if (-not $current.Equals($entry.AppliedSddl, [System.StringComparison]::Ordinal)) {
                throw "ACL state for '$($entry.Path)' changed during rollback; refusing to overwrite the external change."
            }
            $security.SetSecurityDescriptorSddlForm($entry.OriginalSddl, $Snapshot.Sections)
            $entry.Attempted = $true
            Set-Acl -LiteralPath $entry.Path -AclObject $security
        }
        foreach ($entry in $entries) {
            $restored = (Get-Acl -LiteralPath $entry.Path).GetSecurityDescriptorSddlForm($Snapshot.Sections)
            if (-not $restored.Equals($entry.OriginalSddl, [System.StringComparison]::Ordinal)) {
                throw "ACL state for '$($entry.Path)' was not restored exactly."
            }
        }
    }
    catch {
        $restoreError = $_
        $compensationErrors = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in @($entries | Where-Object { $_.Attempted } | Sort-Object `
                @{ Expression = { $_.Path.Length }; Descending = $false },
                @{ Expression = { $_.Path }; Descending = $false })) {
            try {
                $currentAcl = Get-Acl -LiteralPath $entry.Path
                $current = $currentAcl.GetSecurityDescriptorSddlForm($Snapshot.Sections)
                if ($current.Equals($entry.AppliedSddl, [System.StringComparison]::Ordinal)) { continue }
                $currentLocal = Get-OpenTimeStampAclLocalFingerprint -Acl $currentAcl
                if ($currentLocal -ne $entry.OriginalLocal) {
                    $compensationErrors.Add("'$($entry.Path)' changed during rollback")
                    continue
                }
                $currentAcl.SetSecurityDescriptorSddlForm($entry.AppliedSddl, $Snapshot.Sections)
                Set-Acl -LiteralPath $entry.Path -AclObject $currentAcl
            }
            catch { $compensationErrors.Add("'$($entry.Path)': $($_.Exception.Message)") }
        }
        foreach ($entry in $entries) {
            try {
                $current = (Get-Acl -LiteralPath $entry.Path).GetSecurityDescriptorSddlForm($Snapshot.Sections)
                if (-not $current.Equals($entry.AppliedSddl, [System.StringComparison]::Ordinal)) {
                    $compensationErrors.Add("'$($entry.Path)' was not rehardened exactly")
                }
            }
            catch { $compensationErrors.Add("'$($entry.Path)' verification: $($_.Exception.Message)") }
        }
        if ($compensationErrors.Count -ne 0) {
            throw "ACL rollback failed ('$($restoreError.Exception.Message)') and compensation failed closed: $($compensationErrors -join '; ')."
        }
        throw $restoreError
    }
}

function Remove-OpenTimeStampControlledDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExpectedParent,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parent = Get-OpenTimeStampCanonicalDirectoryPath -Path $ExpectedParent
    $target = Get-OpenTimeStampCanonicalDirectoryPath -Path $Path
    Assert-OpenTimeStampPathContained -Parent $parent -Child $target
    if (Test-Path -LiteralPath $target) {
        Assert-OpenTimeStampNoReparsePoints -Root $target
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}

function Remove-OpenTimeStampObsoleteReleases {
    param(
        [Parameter(Mandatory = $true)][string]$ReleasesPath,
        [Parameter(Mandatory = $true)][string]$ActiveReleasePath,
        [ValidateRange(1, 100)][int]$RetainCount = 5
    )

    $root = Get-OpenTimeStampCanonicalDirectoryPath -Path $ReleasesPath
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
    $rootItem = Get-Item -LiteralPath $root -Force
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The Releases directory '$root' is a reparse point."
    }
    $active = Get-OpenTimeStampCanonicalDirectoryPath -Path $ActiveReleasePath
    if (-not (Split-Path -Parent $active).Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The active release '$active' is not a direct child of '$root'."
    }

    $directories = @(Get-ChildItem -LiteralPath $root -Force -Directory |
        Where-Object { $_.Name -match '^[0-9]{14}Z-[0-9a-f]{12}$' } |
        Sort-Object Name -Descending)
    $retainedCount = 0
    $removed = [System.Collections.Generic.List[string]]::new()
    foreach ($directory in $directories) {
        try {
            $manifest = Assert-OpenTimeStampPublishedPayload -PayloadPath $directory.FullName
            if (-not ([string]$manifest.ReleaseId).Equals(
                    $directory.Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "The release manifest identifies '$($manifest.ReleaseId)' instead of '$($directory.Name)'."
            }
            if ($retainedCount -lt $RetainCount) { $retainedCount++; continue }
            if ($directory.FullName.Equals($active, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
            Remove-OpenTimeStampControlledDirectory -ExpectedParent $root -Path $directory.FullName
            $removed.Add($directory.FullName)
        }
        catch {
            Write-Warning "Release '$($directory.FullName)' was preserved: $($_.Exception.Message)"
        }
    }
    return [string[]]$removed
}
