#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-ClientTimestampUrl {
    param(
        [Parameter(Mandatory = $true)][uri]$Url,
        [ValidateSet('rfc3161', 'authenticode', 'Application')][string]$Protocol = 'Application',
        [switch]$AllowInsecureHttp
    )

    if (-not $Url.IsAbsoluteUri -or $Url.Scheme -notin @('http', 'https') -or
        [string]::IsNullOrWhiteSpace($Url.Host)) {
        throw 'The timestamp URL must be an absolute HTTP or HTTPS URL.'
    }
    if ($Url.Scheme -eq 'http' -and -not $AllowInsecureHttp) {
        throw 'Use HTTPS, or explicitly permit an HTTP endpoint with -AllowInsecureHttp.'
    }
    if ($Url.UserInfo -or $Url.Query -or $Url.Fragment -or $Url.OriginalString.IndexOfAny([char[]]'*|') -ge 0) {
        throw 'The timestamp URL cannot contain credentials, a query, a fragment, a wildcard, or a list delimiter.'
    }
    if ($Protocol -ne 'Application' -and
        -not $Url.AbsolutePath.TrimEnd('/').EndsWith("/timestamp/$Protocol", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Use the OpenTimeStamp /timestamp/$Protocol endpoint."
    }

    $builder = New-Object UriBuilder $Url
    $builder.Host = $Url.DnsSafeHost.ToLowerInvariant()
    if ($Url.IsDefaultPort) { $builder.Port = -1 }
    return $builder.Uri.AbsoluteUri
}

function Get-ClientServerEndpoints {
    param([Parameter(Mandatory = $true)][uri]$ServerUrl, [switch]$AllowInsecureHttp)

    $canonical = Get-ClientTimestampUrl -Url $ServerUrl -AllowInsecureHttp:$AllowInsecureHttp
    if ($ServerUrl.AbsolutePath.TrimEnd('/') -match '/timestamp/(rfc3161|authenticode)$') {
        throw 'ServerUrl must identify the IIS application, for example https://tsa.example.com/OpenTimeStamp.'
    }
    return [PSCustomObject]@{
        Rfc3161Url = $canonical.TrimEnd('/') + '/timestamp/rfc3161'
        AuthenticodeUrl = $canonical.TrimEnd('/') + '/timestamp/authenticode'
    }
}

function Get-ClientUserContext {
    param([string]$UserSid)

    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if (-not $UserSid -or $UserSid -eq $currentSid) {
        return [PSCustomObject]@{
            Sid = $currentSid
            RegistryRoot = 'Registry::HKEY_CURRENT_USER'
        }
    }
    if ($UserSid -notmatch '^S-1-5-(\d+-)*\d+$') { throw 'UserSid must be a Windows user SID.' }
    $root = "Registry::HKEY_USERS\$UserSid"
    if (-not (Test-Path -LiteralPath $root)) {
        throw "The profile for '$UserSid' is not loaded. Run as that user or keep that user signed in."
    }
    return [PSCustomObject]@{ Sid = $UserSid; RegistryRoot = $root }
}

function Get-ClientRoamingAppData {
    param([Parameter(Mandatory = $true)]$UserContext, [switch]$Local)

    if ($UserContext.RegistryRoot -eq 'Registry::HKEY_CURRENT_USER') {
        $folder = if ($Local) { [Environment+SpecialFolder]::LocalApplicationData }
        else { [Environment+SpecialFolder]::ApplicationData }
        $path = [Environment]::GetFolderPath($folder)
    }
    else {
        $profileKey = Get-Item -LiteralPath (
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' +
            $UserContext.Sid) -ErrorAction Stop
        $profilePath = [Environment]::ExpandEnvironmentVariables([string]$profileKey.GetValue('ProfileImagePath'))
        $shellKey = Get-Item -LiteralPath (Join-Path $UserContext.RegistryRoot `
            'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders') -ErrorAction Stop
        $name = if ($Local) { 'Local AppData' } else { 'AppData' }
        $path = [string]$shellKey.GetValue($name, $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $path = [regex]::Replace($path, '(?i)%USERPROFILE%', [Text.RegularExpressions.MatchEvaluator]{
            param($match)
            $profilePath
        })
        $path = [Environment]::ExpandEnvironmentVariables($path)
    }
    if ([string]::IsNullOrWhiteSpace($path) -or $path.Contains('%') -or -not [IO.Path]::IsPathRooted($path)) {
        throw 'The signing user roaming AppData path could not be resolved. Supply an explicit settings file path.'
    }
    return $path
}

function Get-ClientApplicationPath {
    param([Parameter(Mandatory = $true)][string[]]$ExecutableNames, [Parameter(Mandatory = $true)]$UserContext)

    foreach ($executable in $ExecutableNames) {
        $command = Get-Command -Name $executable -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($command) { return $command.Source }
        foreach ($hive in @([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryHive]::LocalMachine)) {
            $views = @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)
            foreach ($view in $views) {
                $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
                $key = $null
                try {
                    $prefix = if ($hive -eq [Microsoft.Win32.RegistryHive]::Users) {
                        $UserContext.Sid + '\'
                    }
                    else { '' }
                    $key = $baseKey.OpenSubKey(
                        $prefix + "Software\Microsoft\Windows\CurrentVersion\App Paths\$executable")
                    if ($key) {
                        $path = ([string]$key.GetValue('')).Trim('"')
                        if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) { return $path }
                    }
                }
                finally {
                    if ($key) { $key.Dispose() }
                    $baseKey.Dispose()
                }
            }
        }
    }
    return $null
}

function Get-ClientDeveloperApplicationPath
{
    param([ValidateSet('VisualStudio', 'VisualStudioCode')][string]$Application, $UserContext)

    $executable = if ($Application -eq 'VisualStudio') { 'devenv.exe' } else { 'Code.exe' }
    $path = Get-ClientApplicationPath -ExecutableNames @($executable) -UserContext $UserContext
    if ($path) { return $path }
    if ($Application -eq 'VisualStudio')
    {
        $programFiles = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
        if (-not $programFiles) { return $null }
        $vswhere = Join-Path $programFiles 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { return $null }
        $paths = @(& $vswhere -products '*' -version '[18.0,19.0)' -property productPath)
        return ($paths | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
            Select-Object -First 1)
    }
    $paths = @()
    foreach ($name in @('ProgramW6432', 'ProgramFiles', 'ProgramFiles(x86)'))
    {
        $programFiles = [Environment]::GetEnvironmentVariable($name)
        if ($programFiles) { $paths += Join-Path $programFiles 'Microsoft VS Code\Code.exe' }
    }
    $localData = Get-ClientRoamingAppData -UserContext $UserContext -Local
    $paths += Join-Path $localData 'Programs\Microsoft VS Code\Code.exe'
    return ($paths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1)
}

function Set-ClientRegistryValues {
    param([Parameter(Mandatory = $true)][object[]]$Values)

    $journal = [Collections.Generic.List[object]]::new()
    $createdPaths = [Collections.Generic.List[string]]::new()
    try {
        foreach ($entry in $Values) {
            $key = Get-Item -LiteralPath $entry.Path -ErrorAction SilentlyContinue
            $existed = $key -and $key.GetValueNames() -contains $entry.Name
            $before = if ($existed) {
                $key.GetValue($entry.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
            else { $null }
            $kind = if ($existed) { $key.GetValueKind($entry.Name) } else { $null }
            if ($existed -and $before -eq $entry.Value -and [string]$kind -eq $entry.Kind) { continue }
            $journal.Add([PSCustomObject]@{
                Entry = $entry; Existed = [bool]$existed; Before = $before; Kind = $kind
            })
            $candidate = $entry.Path
            while (-not (Test-Path -LiteralPath $candidate)) {
                if (-not $createdPaths.Contains($candidate)) { $createdPaths.Add($candidate) }
                $candidate = Split-Path -Parent $candidate
            }
            if (-not (Test-Path -LiteralPath $entry.Path)) { New-Item -Path $entry.Path -Force | Out-Null }
            New-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -Value $entry.Value `
                -PropertyType $entry.Kind -Force | Out-Null
            $verified = Get-Item -LiteralPath $entry.Path
            if ($verified.GetValue($entry.Name) -ne $entry.Value -or
                [string]$verified.GetValueKind($entry.Name) -ne $entry.Kind) {
                throw "Could not verify '$($entry.Path)\$($entry.Name)'."
            }
        }
    }
    catch {
        $failure = $_
        $rollbackErrors = @()
        for ($index = $journal.Count - 1; $index -ge 0; $index--) {
            $record = $journal[$index]
            try {
                if ($record.Existed) {
                    New-ItemProperty -LiteralPath $record.Entry.Path -Name $record.Entry.Name -Value $record.Before `
                        -PropertyType ([string]$record.Kind) -Force | Out-Null
                }
                elseif (Test-Path -LiteralPath $record.Entry.Path) {
                    Remove-ItemProperty -LiteralPath $record.Entry.Path -Name $record.Entry.Name `
                        -ErrorAction SilentlyContinue
                }
            }
            catch { $rollbackErrors += $_.Exception.Message }
        }
        foreach ($path in @($createdPaths | Sort-Object Length -Descending)) {
            try {
                $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
                if ($key -and $key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) {
                    Remove-Item -LiteralPath $path -Force
                }
            }
            catch { $rollbackErrors += $_.Exception.Message }
        }
        if ($rollbackErrors.Count) {
            throw "$($failure.Exception.Message) Registry rollback was incomplete: $($rollbackErrors -join '; ')"
        }
        throw $failure
    }
}

function Set-ClientSettingsFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][AllowNull()][byte[]]$OriginalBytes
    )

    $Path = [IO.Path]::GetFullPath($Path)
    $exists = [IO.File]::Exists($Path)
    $current = if ($exists) { [IO.File]::ReadAllBytes($Path) } else { $null }
    if ($exists -ne ($null -ne $OriginalBytes) -or
        ($exists -and [Convert]::ToBase64String($current) -ne [Convert]::ToBase64String($OriginalBytes))) {
        throw "'$Path' changed during setup. Close the application and retry."
    }
    if ($exists -and [Convert]::ToBase64String($current) -eq [Convert]::ToBase64String($Bytes)) { return $null }

    $directory = [IO.Path]::GetDirectoryName($Path)
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $temporary = Join-Path $directory ([IO.Path]::GetRandomFileName())
    $backup = if ($exists) { $Path + '.OpenTimeStamp-' + [Guid]::NewGuid().ToString('N') + '.bak' } else { $null }
    try {
        [IO.File]::WriteAllBytes($temporary, $Bytes)
        if ($exists) { [IO.File]::Replace($temporary, $Path, $backup) }
        else { [IO.File]::Move($temporary, $Path) }
    }
    finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
    return $backup
}

function Add-ClientJsonArrayEntries
{
    param([string]$Text, [hashtable]$Entries, [hashtable]$IdentityProperties)

    # Replace comments and trailing commas with spaces so token offsets still identify the original text.
    $characters = $Text.ToCharArray()
    $lexicalPattern = '"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*[\s\S]*?\*/'
    foreach ($match in [regex]::Matches($Text, $lexicalPattern))
    {
        if (-not $match.Value.StartsWith('/')) { continue }
        for ($index = $match.Index; $index -lt $match.Index + $match.Length; $index++)
        {
            if ($characters[$index] -notin "`r", "`n") { $characters[$index] = ' ' }
        }
    }
    $tokenPattern = '"(?:\\.|[^"\\])*"|[{}\[\],:]|true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?'
    $tokens = @([regex]::Matches((-join $characters), $tokenPattern))
    for ($index = 0; $index -lt $tokens.Count - 1; $index++)
    {
        if ($tokens[$index].Value -eq ',' -and $tokens[$index + 1].Value -in ']', '}')
        { $characters[$tokens[$index].Index] = ' ' }
    }
    $normalized = -join $characters
    $parsed = $normalized | ConvertFrom-Json -ErrorAction Stop
    if (-not $parsed -or $parsed -is [array] -or $normalized.TrimStart()[0] -ne '{')
    { throw 'The VS Code tasks file must contain a JSON object.' }
    $tokens = @([regex]::Matches($normalized, $tokenPattern))
    $properties = @{}
    for ($index = 1; $index -lt $tokens.Count - 1; $index++)
    {
        if ($tokens[$index].Value -eq ',') { continue }
        $name = $tokens[$index].Value | ConvertFrom-Json
        if ($properties.ContainsKey($name)) { throw 'Duplicate root properties in the VS Code tasks file.' }
        $index += 2
        $start = $tokens[$index].Index
        $first = $tokens[$index].Value
        if ($first -in '{', '[')
        {
            $depth = 0
            do
            {
                if ($tokens[$index].Value -in '{', '[') { $depth++ }
                elseif ($tokens[$index].Value -in '}', ']') { $depth-- }
                if ($depth) { $index++ }
            } while ($depth)
        }
        $properties[$name] = @{ Start = $start; End = $tokens[$index].Index; First = $first }
    }
    $missing = @()
    if ($properties.ContainsKey('version'))
    {
        if ($parsed.version -cne '2.0.0') { throw 'The VS Code tasks schema must be version 2.0.0.' }
    }
    else { $missing += '"version": "2.0.0"' }
    $insertions = @()
    foreach ($name in $Entries.Keys)
    {
        $additions = @()
        $existing = @()
        if ($properties.ContainsKey($name))
        {
            if ($properties[$name].First -ne '[') { throw "VS Code '$name' must be an array." }
            $existing = @($parsed.$name)
        }
        foreach ($entry in $Entries[$name])
        {
            $identity = $IdentityProperties[$name]
            $matches = @($existing | Where-Object {
                $_ -and $_.PSObject.Properties[$identity] -and $_.$identity -ceq $entry.$identity
            })
            $json = $entry | ConvertTo-Json -Depth 30 -Compress
            if ($matches.Count)
            {
                if ($matches.Count -ne 1 -or ($matches[0] | ConvertTo-Json -Depth 30 -Compress) -cne $json)
                { throw "VS Code '$($entry.$identity)' conflicts with existing settings. Choose another task label." }
                continue
            }
            $additions += $json
        }
        if (-not $additions.Count) { continue }
        $joined = $additions -join ",`r`n"
        if (-not $properties.ContainsKey($name))
        {
            $missing += '"' + $name + '": [' + "`r`n" + $joined + "`r`n]"
            continue
        }
        $range = $properties[$name]
        $withoutComments = [regex]::Replace($Text.Substring($range.Start + 1,
            $range.End - $range.Start - 1), $lexicalPattern, [Text.RegularExpressions.MatchEvaluator]{
                param($match)
                if ($match.Value.StartsWith('/')) { return ' ' * $match.Length }
                return $match.Value
            }).TrimEnd()
        $comma = if ($existing.Count -and -not $withoutComments.EndsWith(',')) { ',' } else { '' }
        $insertions += @{ Index = $range.End; Text = $comma + "`r`n" + $joined + "`r`n" }
    }
    if ($missing.Count)
    {
        $last = $tokens[-1].Index
        $rootStart = $tokens[0].Index
        $originalBody = [regex]::Replace($Text.Substring($rootStart + 1, $last - $rootStart - 1), $lexicalPattern,
            [Text.RegularExpressions.MatchEvaluator]{
                param($match)
                if ($match.Value.StartsWith('/')) { return ' ' * $match.Length }
                return $match.Value
            }).TrimEnd()
        $comma = if ($properties.Count -and -not $originalBody.EndsWith(',')) { ',' } else { '' }
        $insertions += @{ Index = $last; Text = $comma + "`r`n" + ($missing -join ",`r`n") + "`r`n" }
    }
    foreach ($insertion in $insertions | Sort-Object { $_.Index } -Descending)
    { $Text = $Text.Insert($insertion.Index, $insertion.Text) }
    return $Text
}
