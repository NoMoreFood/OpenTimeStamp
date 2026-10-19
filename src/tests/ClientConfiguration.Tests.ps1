#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$deployPath = Join-Path $repositoryRoot 'tools\deploy'
. (Join-Path $deployPath 'ClientConfiguration.Common.ps1')
$tests = 0
$failures = 0

function Invoke-Test {
    param([string]$Name, [scriptblock]$Body)
    $script:tests++
    try { & $Body; Write-Host "PASS $Name" }
    catch {
        $script:failures++
        Write-Host "FAIL $Name`: $($_.Exception.Message)"
        Write-Host $_.ScriptStackTrace
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Throws {
    param([scriptblock]$Body)
    try { & $Body | Out-Null }
    catch { return }
    throw 'Expected the configuration operation to fail.'
}

$registryRoot = 'Registry::HKEY_CURRENT_USER\Software\OpenTimeStamp-ClientSetupTests-' +
    [Guid]::NewGuid().ToString('N')
$testParent = Join-Path ([IO.Path]::GetTempPath()) 'OpenTimeStamp.ClientConfiguration.Tests'
$testRoot = Join-Path $testParent ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
$rfcUrl = 'https://tsa.example.test/OpenTimeStamp/timestamp/rfc3161'
$legacyUrl = 'https://tsa.example.test/OpenTimeStamp/timestamp/authenticode'
$officeScript = Join-Path $deployPath 'Configure-OfficeTimestamping.ps1'
$libreOfficeScript = Join-Path $deployPath 'Configure-LibreOfficeTimestamping.ps1'
$pdfScript = Join-Path $deployPath 'Configure-PdfXChangeTimestamping.ps1'
$acrobatRoot = 'Registry::HKEY_CURRENT_USER\Software\OpenTimeStamp-AcrobatSetupTests-' +
    [Guid]::NewGuid().ToString('N')
try {
    Invoke-Test 'Signing transport aborts stalled responses and closes active connections on disposal' {
        $tokens = $null
        $parseErrors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $deployPath 'Invoke-TimestampSigning.ps1'), [ref]$tokens, [ref]$parseErrors)
        $source = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
                $node.Value.Contains('public sealed class TimestampTransport')
        }, $true).Value
        $checks = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'SigningTransportChecks.cs'))
        Add-Type -TypeDefinition ($source + "`r`n" + $checks) `
            -ReferencedAssemblies System.dll,System.Core.dll,System.Net.Http.dll
        [OpenTimeStamp.Clients.SigningTransportChecks]::Run()
    }

    Invoke-Test 'Visual Studio preserves signing choices and both platform conditions' {
        foreach ($namespace in @('', ' xmlns="http://schemas.microsoft.com/developer/msbuild/2003"')) {
            $path = Join-Path $testRoot ('publish-' + [guid]::NewGuid().ToString('N') + '.pubxml')
            $xml = '<Project' + $namespace + '><!-- preserve project note -->' +
                '<PropertyGroup Condition="Platform==x86"><ManifestTimestampUrl>old</ManifestTimestampUrl>' +
                '<SignManifests>true</SignManifests><SignAssembly>true</SignAssembly></PropertyGroup>' +
                '<PropertyGroup Condition="Platform==x64"><ManifestTimestampUrl>old</ManifestTimestampUrl>' +
                '<ManifestCertificateThumbprint>preserve</ManifestCertificateThumbprint></PropertyGroup></Project>'
            [IO.File]::WriteAllText($path, $xml)
            foreach ($scheme in @('http', 'https')) {
                $result = & (Join-Path $deployPath 'Configure-VisualStudioTimestamping.ps1') -ProjectPath $path `
                    -ServerUrl "${scheme}://tsa.example.test/OpenTimeStamp" -AllowInsecureHttp:($scheme -eq 'http')
                [xml]$configured = [IO.File]::ReadAllText($path)
                $urls = @($configured.SelectNodes("//*[local-name()='ManifestTimestampUrl']"))
                Assert-True ($urls.Count -eq 2 -and @($urls | Where-Object {
                    $_.InnerText -cne "${scheme}://tsa.example.test/OpenTimeStamp/timestamp/rfc3161"
                }).Count -eq 0) 'A platform configuration missed the timestamp URL.'
                Assert-True ($configured.SelectSingleNode("//*[local-name()='SignAssembly']").InnerText -ceq 'true' `
                    -and $configured.SelectSingleNode("//*[local-name()='ManifestCertificateThumbprint']").InnerText `
                    -ceq 'preserve' -and [IO.File]::ReadAllText($path).Contains('preserve project note')) `
                    'Setup changed another signing choice or removed a comment.'
                Assert-True ([IO.File]::Exists($result.BackupPath)) 'Project setup did not save a backup.'
                $repeated = & (Join-Path $deployPath 'Configure-VisualStudioTimestamping.ps1') -ProjectPath $path `
                    -ServerUrl "${scheme}://tsa.example.test/OpenTimeStamp" -AllowInsecureHttp:($scheme -eq 'http')
                Assert-True ($null -eq $repeated.BackupPath) 'Repeated setup rewrote an unchanged project.'
            }
        }
    }

    Invoke-Test 'VS Code preserves JSON comments, existing tasks, and workspace protections' {
        $workspace = Join-Path $testRoot 'vscode-workspace'
        New-Item -ItemType Directory -Path (Join-Path $workspace '.vscode') -Force | Out-Null
        $path = Join-Path $workspace '.vscode\tasks.json'
        $original = @'
// preserve header
{
    "version": "2.0.0",
    "tasks": [
        {"label":"Existing build", "type":"shell", "command":"echo", "args":["https://example.test/*text*/"]},
        // preserve task note
    ],
}
'@
        [IO.File]::WriteAllText($path, $original)
        $settings = Join-Path $workspace '.vscode\settings.json'
        [IO.File]::WriteAllText($settings, '{"security.workspace.trust.enabled":true}')
        $before = (Get-FileHash -LiteralPath $settings).Hash
        foreach ($scheme in @('http', 'https')) {
            foreach ($architecture in @('x86', 'x64')) {
                if ($architecture -eq 'x64' -and -not [Environment]::Is64BitOperatingSystem) { continue }
                $parameters = @{
                    WorkspacePath = $workspace; ServerUrl = "${scheme}://tsa.example.test/OpenTimeStamp"
                    PowerShellArchitecture = $architecture; AllowInsecureHttp = $scheme -eq 'http'
                }
                $result = & (Join-Path $deployPath 'Configure-VSCodeTimestamping.ps1') @parameters
                $text = [IO.File]::ReadAllText($path)
                Assert-True ($text.Contains('// preserve header') -and $text.Contains('// preserve task note') -and
                    $text.Contains('"label":"Existing build"') -and $text.Contains('https://example.test/*text*/')) `
                    'Task setup removed existing text.'
                Assert-True ($text.Contains($result.TaskLabel) -and $text.Contains('"process"') -and
                    -not $text.Contains('ExecutionPolicy') -and -not $text.Contains('disable-workspace-trust')) `
                    'Task setup omitted the signing task or bypassed a protection.'
                $hash = (Get-FileHash -LiteralPath $path).Hash
                $repeat = & (Join-Path $deployPath 'Configure-VSCodeTimestamping.ps1') @parameters
                Assert-True ($null -eq $repeat.BackupPath -and (Get-FileHash -LiteralPath $path).Hash -ceq $hash) `
                    'Repeated task setup changed the workspace.'
            }
        }
        Assert-True ((Get-FileHash -LiteralPath $settings).Hash -ceq $before) 'Workspace protections changed.'
    }

    Invoke-Test 'VS Code rejects task conflicts before writing and previews without creating files' {
        $workspace = Join-Path $testRoot 'vscode-preview'
        New-Item -ItemType Directory -Path $workspace | Out-Null
        $helper = Join-Path $deployPath 'Configure-VSCodeTimestamping.ps1'
        & $helper -WorkspacePath $workspace -ServerUrl 'https://tsa.example.test/OpenTimeStamp' -WhatIf | Out-Null
        Assert-True (-not (Test-Path (Join-Path $workspace '.vscode'))) 'Preview created a task directory.'
        & $helper -WorkspacePath $workspace -ServerUrl 'https://tsa.example.test/OpenTimeStamp' `
            -TaskLabel 'Selected signing task' | Out-Null
        $path = Join-Path $workspace '.vscode\tasks.json'
        $before = (Get-FileHash -LiteralPath $path).Hash
        Assert-Throws {
            & $helper -WorkspacePath $workspace -ServerUrl 'https://other.example.test/OpenTimeStamp' `
                -TaskLabel 'Selected signing task'
        }
        Assert-True ((Get-FileHash -LiteralPath $path).Hash -ceq $before) 'A conflict overwrote another task.'
    }

    Invoke-Test 'IDE integration requires the intended project and workspace' {
        $results = @(& (Join-Path $deployPath 'Configure-SigningClients.ps1') `
            -ServerUrl 'https://tsa.example.test/OpenTimeStamp' -Applications VisualStudio,VisualStudioCode)
        Assert-True ($results.Count -eq 2 -and @($results | Where-Object Status -ne ProjectRequired).Count -eq 0) `
            'IDE setup invented a global timestamp preference.'
    }

    Invoke-Test 'HTTP and HTTPS setup preserves sandbox, Protected View, and macro restrictions' {
        $protectedValues = @(
            @{ Path = "$acrobatRoot\Privileged"; Name = 'bProtectedMode'; Value = 1 },
            @{ Path = "$acrobatRoot\Privileged"; Name = 'bEnableProtectedModeAppContainer'; Value = 1 },
            @{ Path = "$acrobatRoot\TrustManager"; Name = 'iProtectedView'; Value = 2 },
            @{ Path = "$acrobatRoot\TrustManager"; Name = 'bEnhancedSecurityStandalone'; Value = 1 },
            @{ Path = "$acrobatRoot\TrustManager"; Name = 'bEnhancedSecurityInBrowser'; Value = 1 },
            @{ Path = "$acrobatRoot\TrustManager\cDefaultLaunchURLPerms"; Name = 'iURLPerms'; Value = 2 },
            @{ Path = "$registryRoot\Software\Policies\Microsoft\Office\16.0\Word\Security\ProtectedView";
                Name = 'DisableInternetFilesInPV'; Value = 0 },
            @{ Path = "$registryRoot\Software\Policies\Microsoft\Office\16.0\Word\Security";
                Name = 'blockcontentexecutionfrominternet'; Value = 1 })
        foreach ($setting in $protectedValues) {
            if (-not (Test-Path -LiteralPath $setting.Path)) { New-Item -Path $setting.Path -Force | Out-Null }
            New-ItemProperty -LiteralPath $setting.Path -Name $setting.Name -Value $setting.Value `
                -PropertyType DWord | Out-Null
        }
        $librePath = Join-Path $testRoot 'protected-profile.xcu'
        [IO.File]::WriteAllText($librePath,
            '<oor:items xmlns:oor="http://openoffice.org/2001/registry">' +
            '<item oor:path="/org.openoffice.Office.Common/Security/Scripting">' +
            '<prop oor:name="MacroSecurityLevel" oor:op="fuse"><value>3</value></prop></item></oor:items>')
        $presetPath = Join-Path $testRoot 'transport-presets.json'
        $installShieldPath = Join-Path $testRoot 'transport-settings.xml'
        [IO.File]::WriteAllText($installShieldPath,
            '<DevStudio><Build><DigitalSignature Timestamp="" TimestampRFC3161="" /></Build></DevStudio>')
        foreach ($scheme in @('http', 'https')) {
            $server = "${scheme}://192.0.2.20:8443/OpenTimeStamp"
            $rfc = "$server/timestamp/rfc3161"
            $legacy = "$server/timestamp/authenticode"
            $http = $scheme -eq 'http'
            & $officeScript -Rfc3161Url $rfc -AuthenticodeUrl $legacy -RegistryRoot $registryRoot `
                -AllowInsecureHttp:$http | Out-Null
            & (Join-Path $deployPath 'Configure-AcrobatTimestamping.ps1') -TimestampUrl $rfc `
                -RegistryRoot $acrobatRoot -ServerName "OpenTimeStamp-$scheme" -AllowInsecureHttp:$http | Out-Null
            & $libreOfficeScript -TimestampUrl $rfc -SettingsPath $librePath -AllowInsecureHttp:$http | Out-Null
            & $pdfScript -TimestampUrl $rfc -PresetPath $presetPath -ServerName "OpenTimeStamp-$scheme" `
                -AllowInsecureHttp:$http | Out-Null
            & (Join-Path $deployPath 'Configure-SigningClients.ps1') -ServerUrl $server `
                -Applications InstallShield -InstallShieldSettingsPath $installShieldPath `
                -AllowInsecureHttp:$http | Out-Null
            $arguments = @(& (Join-Path $deployPath 'Get-TimestampSigningParameters.ps1') `
                -ServerUrl $server -Tool NuGet -AllowInsecureHttp:$http)
            Assert-True ($arguments[0] -ceq '-Timestamper' -and $arguments[1] -ceq $rfc) 'NuGet transport differs.'
            $office = Get-Item -LiteralPath "$registryRoot\Software\Microsoft\Office\16.0\Common\Signatures"
            Assert-True ($office.GetValue('TSALocation') -ceq $rfc) 'Office transport differs.'
            $provider = Get-Item -LiteralPath "$acrobatRoot\Security\cASPKI\cAdobe_TSPProvider"
            Assert-True ([Text.Encoding]::ASCII.GetString($provider.GetValue('sURL')).TrimEnd([char]0) -ceq $rfc) `
                'Acrobat transport differs.'
            [xml]$libre = [IO.File]::ReadAllText($librePath)
            Assert-True ($libre.SelectSingleNode("//prop[@*[local-name()='name']='MacroSecurityLevel']/value").InnerText `
                -ceq '3') 'LibreOffice macro restrictions changed.'
            Assert-True (@($libre.SelectNodes('//prop/value/it') | Where-Object InnerText -CEQ $rfc).Count -eq 1) `
                'LibreOffice did not register the transport URL.'
            $presets = [IO.File]::ReadAllText($presetPath) | ConvertFrom-Json
            Assert-True (@($presets.TimestampServers.Items | Where-Object { $_.Data.URL -ceq $rfc }).Count -eq 1) `
                'PDF-XChange did not register the transport URL.'
            foreach ($setting in $protectedValues) {
                Assert-True ((Get-Item -LiteralPath $setting.Path).GetValue($setting.Name) -eq $setting.Value) `
                    "Setup changed protective setting '$($setting.Name)'."
            }
        }
    }

    Invoke-Test 'HTTP requires an explicit opt-in before changing application settings' {
        $http = 'http://192.0.2.20/OpenTimeStamp/timestamp/rfc3161'
        $before = (Get-Item -LiteralPath "$acrobatRoot\Security\cASPKI\cAdobe_TSPProvider").GetValue('sURL')
        Assert-Throws {
            & (Join-Path $deployPath 'Configure-AcrobatTimestamping.ps1') -TimestampUrl $http `
                -RegistryRoot $acrobatRoot
        }
        Assert-True ([Convert]::ToBase64String($before) -ceq [Convert]::ToBase64String(
            (Get-Item -LiteralPath "$acrobatRoot\Security\cASPKI\cAdobe_TSPProvider").GetValue('sURL'))) `
            'Rejected HTTP setup changed Acrobat.'
        $path = Join-Path $testRoot 'rejected-http.xcu'
        Assert-Throws { & $libreOfficeScript -TimestampUrl $http -SettingsPath $path }
        Assert-True (-not (Test-Path -LiteralPath $path)) 'Rejected HTTP setup created a profile.'
    }

    Invoke-Test 'Adobe timestamp Internet permission preserves unrelated rules and blocks unknown sites' {
        $path = Join-Path $acrobatRoot 'TrustManager\cDefaultLaunchURLPerms'
        New-ItemProperty -LiteralPath $path -Name iURLPerms -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -LiteralPath $path -Name iUnknownURLPerms -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -LiteralPath $path -Name tHostPerms -Value 'version:1|https://blocked.example.test:1' `
            -PropertyType String -Force | Out-Null
        $helper = Join-Path $deployPath 'Configure-AdobeTimestampNetworkAccess.ps1'
        & $helper -TimestampUrl $rfcUrl -RegistryRoot $acrobatRoot | Out-Null
        $key = Get-Item -LiteralPath $path
        Assert-True ($key.GetValue('iURLPerms') -eq 0 -and $key.GetValue('iUnknownURLPerms') -eq 3) `
            'The timestamp exception allowed unknown sites.'
        $list = [string]$key.GetValue('tHostPerms')
        Assert-True ($list -ceq 'version:1|https://blocked.example.test:1|tsa.example.test:2') `
            'The timestamp exception altered another rule or omitted the TSA hostname.'
        & $helper -TimestampUrl 'http://tsa.example.test:8080/OpenTimeStamp/timestamp/rfc3161' `
            -RegistryRoot $acrobatRoot -AllowInsecureHttp | Out-Null
        Assert-True ($key.GetValue('tHostPerms') -ceq $list) 'Changing transport duplicated a hostname.'
        Assert-True ((Get-Item -LiteralPath "$acrobatRoot\Privileged").GetValue('bProtectedMode') -eq 1 -and
            (Get-Item -LiteralPath "$acrobatRoot\TrustManager").GetValue('iProtectedView') -eq 2) `
            'The Internet permission changed document protections.'
    }

    Invoke-Test 'Office and VBA settings preserve unrelated values and repeated setup' {
        $path = Join-Path $registryRoot 'Software\Microsoft\Office\16.0\Common\Signatures'
        New-Item -Path $path -Force | Out-Null
        New-ItemProperty -LiteralPath $path -Name Unrelated -Value preserve -PropertyType String | Out-Null
        & $officeScript -Rfc3161Url $rfcUrl -AuthenticodeUrl $legacyUrl -RegistryRoot $registryRoot | Out-Null
        $office = Get-Item -LiteralPath $path
        Assert-True ($office.GetValue('TSALocation') -ceq $rfcUrl -and $office.GetValue('XAdESLevel') -eq 2 -and
            $office.GetValue('MinXAdESLevel') -eq 2) 'Office does not request and require the RFC 3161 timestamp.'
        Assert-True ($office.GetValueKind('TSALocation') -eq [Microsoft.Win32.RegistryValueKind]::String -and
            $office.GetValueKind('MinXAdESLevel') -eq [Microsoft.Win32.RegistryValueKind]::DWord) `
            'Registry types differ.'
        $vba = Get-Item -LiteralPath (Join-Path $registryRoot 'Software\Microsoft\VBA\Security')
        Assert-True ($vba.GetValue('TimeStampURL') -ceq $legacyUrl -and $vba.GetValue('TimeStampRetryCount') -eq 3 -and
            $vba.GetValue('TimeStampRetryDelay') -eq 1000) 'The VBA endpoint or retries differ.'
        & $officeScript -Rfc3161Url $rfcUrl -AuthenticodeUrl $legacyUrl -RegistryRoot $registryRoot | Out-Null
        Assert-True ($office.GetValue('Unrelated') -eq 'preserve' -and $office.ValueCount -eq 4) `
            'Setup lost a preference.'
        Assert-True ($vba.GetValueNames() -notcontains 'V1HashEnhanced') 'Setup changed optional VBA hashing policy.'
    }

    Invoke-Test 'An Office policy conflict prevents the entire Office/VBA operation' {
        $policy = Join-Path $registryRoot 'Software\Policies\Microsoft\Office\16.0\Common\Signatures'
        New-Item -Path $policy -Force | Out-Null
        New-ItemProperty -LiteralPath $policy -Name TSALocation -Value 'https://other.example.test/tsa' `
            -PropertyType String | Out-Null
        Assert-Throws {
            & $officeScript -Rfc3161Url $rfcUrl -AuthenticodeUrl ($legacyUrl.Replace('tsa.', 'changed.')) `
                -RegistryRoot $registryRoot
        }
        $vba = Get-Item -LiteralPath (Join-Path $registryRoot 'Software\Microsoft\VBA\Security')
        Assert-True ($vba.GetValue('TimeStampURL') -ceq $legacyUrl) 'Policy rejection still changed VBA settings.'
        Remove-ItemProperty -LiteralPath $policy -Name TSALocation
    }

    Invoke-Test 'Partial registry failure restores values and removes only newly created empty keys' {
        $path = Join-Path $registryRoot 'Rollback'
        New-Item -Path $path -Force | Out-Null
        New-ItemProperty -LiteralPath $path -Name Existing -Value before -PropertyType String | Out-Null
        New-ItemProperty -LiteralPath $path -Name Unrelated -Value preserve -PropertyType String | Out-Null
        $newPath = Join-Path $path 'New\Child'
        Assert-Throws {
            Set-ClientRegistryValues -Values @(
                [PSCustomObject]@{ Path = $path; Name = 'Existing'; Kind = 'String'; Value = 'after' },
                [PSCustomObject]@{ Path = $newPath; Name = 'Failure'; Kind = 'NotARegistryType'; Value = 1 })
        }
        $key = Get-Item -LiteralPath $path
        Assert-True ($key.GetValue('Existing') -eq 'before' -and $key.GetValue('Unrelated') -eq 'preserve') `
            'Rollback did not preserve the original preferences.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $path 'New'))) 'Rollback left a newly created empty key.'
    }

    Invoke-Test 'Registry rollback preserves another writer while restoring uncontested settings' {
        $path = Join-Path $registryRoot 'ConcurrentRollback'
        New-Item -Path $path -Force | Out-Null
        foreach ($name in @('Uncontested', 'Concurrent')) {
            New-ItemProperty -LiteralPath $path -Name $name -Value before -PropertyType String | Out-Null
        }
        function New-ItemProperty {
            [CmdletBinding()]
            param($LiteralPath, $Name, $Value, $PropertyType, [switch]$Force)

            if ($Name -eq 'Failure') {
                Microsoft.PowerShell.Management\New-ItemProperty -LiteralPath $LiteralPath -Name Concurrent `
                    -Value 'other writer' -PropertyType String -Force | Out-Null
                throw 'Simulated registry write failure.'
            }
            Microsoft.PowerShell.Management\New-ItemProperty @PSBoundParameters
        }
        try {
            Assert-Throws {
                Set-ClientRegistryValues -Values @(
                    [pscustomobject]@{ Path = $path; Name = 'Uncontested'; Kind = 'String'; Value = 'after' },
                    [pscustomobject]@{ Path = $path; Name = 'Concurrent'; Kind = 'String'; Value = 'after' },
                    [pscustomobject]@{ Path = $path; Name = 'Failure'; Kind = 'String'; Value = 'after' })
            }
        }
        finally { Remove-Item Function:\New-ItemProperty }
        $key = Get-Item -LiteralPath $path
        Assert-True ($key.GetValue('Concurrent') -ceq 'other writer') 'Rollback overwrote a concurrent change.'
        Assert-True ($key.GetValue('Uncontested') -ceq 'before') 'Rollback abandoned an uncontested setting.'
        Assert-True ($key.GetValueNames() -notcontains 'Failure') 'Rollback left the failed setting.'
    }

    Invoke-Test 'WhatIf does not create registry keys or profile files' {
        & $officeScript -Rfc3161Url $rfcUrl -SigningType Documents -OfficeVersion 99.0 `
            -RegistryRoot $registryRoot -WhatIf 6>$null | Out-Null
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $registryRoot 'Software\Microsoft\Office\99.0'))) `
            'WhatIf created Office settings.'
        $librePath = Join-Path $testRoot 'whatif\registrymodifications.xcu'
        $pdfPath = Join-Path $testRoot 'whatif\TimeStampServer.presets'
        & $libreOfficeScript -TimestampUrl $rfcUrl -SettingsPath $librePath -WhatIf 6>$null | Out-Null
        & $pdfScript -TimestampUrl $rfcUrl -PresetPath $pdfPath -WhatIf 6>$null | Out-Null
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $testRoot 'whatif'))) 'WhatIf created a profile directory.'
    }

    Invoke-Test 'Entry-script previews resolve normal VBA and Adobe user branches' {
        $result = @(& (Join-Path $deployPath 'Configure-SigningClients.ps1') `
            -ServerUrl 'https://tsa.example.test/OpenTimeStamp' -Applications Vba,AcrobatReader -WhatIf 6>$null)
        Assert-True ($result.Count -eq 2 -and @($result | Where-Object Status -ne WhatIf).Count -eq 0) `
            'The normal user profile could not be previewed through in-memory helpers.'
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        & (Join-Path $deployPath 'Configure-AcrobatTimestamping.ps1') -TimestampUrl $rfcUrl `
            -Version 2024 -UserSid $sid -WhatIf 6>$null | Out-Null
    }

    Invoke-Test 'LibreOffice preserves the profile, backs it up, and does not duplicate a TSA' {
        $path = Join-Path $testRoot 'registrymodifications.xcu'
        $xml = '<?xml version="1.0" encoding="UTF-16"?><oor:items xmlns:oor="http://openoffice.org/2001/registry">' +
            '<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="TSAURLs" ' +
            'oor:op="fuse"><value><it>https://other.example.test/tsa</it></value></prop></item>' +
            '<item oor:path="/unrelated"><prop oor:name="Name"><value>Keep &amp; preserve</value></prop></item>' +
            '</oor:items>'
        [IO.File]::WriteAllText($path, $xml, [Text.Encoding]::Unicode)
        $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        $result = & $libreOfficeScript -TimestampUrl $rfcUrl -SettingsPath $path
        Assert-True ($before -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($result.BackupPath))) `
            'The original LibreOffice profile was not backed up exactly.'
        $after = New-Object Xml.XmlDocument
        $after.Load($path)
        $urls = @($after.SelectNodes('//*[local-name()="prop"]/*[local-name()="value"]/it') |
            ForEach-Object { $_.InnerText })
        Assert-True ($urls.Count -eq 2 -and $urls -contains $rfcUrl -and
            $urls -contains 'https://other.example.test/tsa') `
            'Setup lost or duplicated TSA entries.'
        Assert-True ($after.DocumentElement.InnerText.Contains('Keep & preserve')) 'Setup lost unrelated XML content.'
        $bytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        $again = & $libreOfficeScript -TimestampUrl $rfcUrl -SettingsPath $path
        Assert-True (-not $again.BackupPath -and
            $bytes -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))) `
            'Repeated setup rewrote the existing LibreOffice profile.'
    }

    Invoke-Test 'Malformed application preferences are left unchanged' {
        $path = Join-Path $testRoot 'malformed.xcu'
        [IO.File]::WriteAllText($path, '<broken>')
        Assert-Throws { & $libreOfficeScript -TimestampUrl $rfcUrl -SettingsPath $path }
        Assert-True ([IO.File]::ReadAllText($path) -ceq '<broken>') 'Setup replaced malformed XML.'
        $path = Join-Path $testRoot 'malformed.presets'
        [IO.File]::WriteAllText($path, '{"OtherSettings":true}')
        Assert-Throws { & $pdfScript -TimestampUrl $rfcUrl -PresetPath $path }
        Assert-True ([IO.File]::ReadAllText($path) -ceq '{"OtherSettings":true}') 'Setup replaced unrelated JSON.'
    }

    Invoke-Test 'PDF-XChange preserves other presets and IDs through repeated setup' {
        $path = Join-Path $testRoot 'TimeStampServer.presets'
        $settings = @{
            Unrelated = 'preserve'
            TimestampServers = @{ Items = @(@{
                ID = '{OTHER-ID}'; Name = 'Other'; Flags = 42
                Data = @{ URL = 'https://other.example.test/tsa'; User = 'keep'; Password = 'keep'; RequireAuth = $true }
            }) }
        }
        [IO.File]::WriteAllText($path, ($settings | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
        $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        $result = & $pdfScript -TimestampUrl $rfcUrl -PresetPath $path
        Assert-True ($before -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($result.BackupPath))) `
            'The original PDF-XChange preset file was not backed up exactly.'
        $after = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        Assert-True ($after.Unrelated -eq 'preserve' -and $after.TimestampServers.Items.Count -eq 2) `
            'Setup lost unrelated PDF-XChange preferences.'
        $other = $after.TimestampServers.Items[0]
        Assert-True ($other.ID -eq '{OTHER-ID}' -and $other.Flags -eq 42 -and $other.Data.Password -eq 'keep') `
            'Setup changed another preset.'
        $id = $after.TimestampServers.Items[1].ID
        $again = & $pdfScript -TimestampUrl $rfcUrl -PresetPath $path
        $after = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        Assert-True (-not $again.BackupPath -and $after.TimestampServers.Items.Count -eq 2 -and
            $after.TimestampServers.Items[1].ID -ceq $id) 'Repeated setup duplicated or regenerated a preset.'
    }

    Invoke-Test 'PDF-XChange name conflicts do not overwrite existing settings' {
        $path = Join-Path $testRoot 'TimeStampServer.presets'
        $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        Assert-Throws { & $pdfScript -TimestampUrl $rfcUrl.Replace('tsa.', 'different.') -PresetPath $path }
        Assert-True ($before -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))) `
            'Name conflict changed presets.'
    }

    Invoke-Test 'Settings changed by another writer are preserved' {
        $path = Join-Path $testRoot 'concurrent-settings.txt'
        [IO.File]::WriteAllText($path, 'before')
        $before = [IO.File]::ReadAllBytes($path)
        [IO.File]::WriteAllText($path, 'other writer')
        Assert-Throws {
            Set-ClientSettingsFile -Path $path -Bytes ([Text.Encoding]::UTF8.GetBytes('setup')) -OriginalBytes $before
        }
        Assert-True ([IO.File]::ReadAllText($path) -ceq 'other writer') 'Setup overwrote concurrent changes.'
    }

    Invoke-Test 'InstallShield changes only recognized timestamp fields and backs up its settings' {
        $path = Join-Path $testRoot 'Settings.xml'
        $xml = '<DevStudio><Build><DigitalSignature Timestamp="https://other.example.test/legacy" />' +
            '<DigitalSignature TimestampRFC3161="https://other.example.test/rfc3161" Keep="preserve" />' +
            '<Unrelated enabled="true" /></Build></DevStudio>'
        [IO.File]::WriteAllText($path, $xml, [Text.UTF8Encoding]::new($false))
        $scriptPath = Join-Path $deployPath 'Configure-SigningClients.ps1'
        $result = & $scriptPath -ServerUrl 'https://tsa.example.test/OpenTimeStamp' `
            -Applications InstallShield -InstallShieldSettingsPath $path
        Assert-True ($result.Status -eq 'Configured') 'The in-memory helper invocation failed.'
        Assert-True ([IO.File]::ReadAllText($result.Detail.BackupPath) -ceq $xml) 'InstallShield backup differs.'
        [xml]$after = Get-Content -LiteralPath $path -Raw
        $legacy = $after.SelectSingleNode('/DevStudio/Build/DigitalSignature[@Timestamp]')
        $rfc = $after.SelectSingleNode('/DevStudio/Build/DigitalSignature[@TimestampRFC3161]')
        Assert-True ($legacy.GetAttribute('Timestamp') -ceq $legacyUrl -and
            $rfc.GetAttribute('TimestampRFC3161') -ceq $rfcUrl) 'The protocols were not configured separately.'
        Assert-True ($rfc.GetAttribute('Keep') -eq 'preserve' -and
            $after.SelectSingleNode('/DevStudio/Build/Unrelated').GetAttribute('enabled') -eq 'true') `
            'Setup changed unrelated InstallShield settings.'
        $bytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        $again = & $scriptPath -ServerUrl 'https://tsa.example.test/OpenTimeStamp' `
            -Applications InstallShield -InstallShieldSettingsPath $path
        Assert-True (-not $again.Detail.BackupPath -and
            $bytes -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))) `
            'Repeated setup rewrote Settings.xml.'
        $path = Join-Path $testRoot 'unrecognized-settings.xml'
        [IO.File]::WriteAllText($path, '<DevStudio><Build><Unrelated /></Build></DevStudio>')
        Assert-Throws {
            & (Join-Path $deployPath 'Configure-InstallShieldTimestamping.ps1') `
                -ServerUrl 'https://tsa.example.test/OpenTimeStamp' -SettingsPath $path
        }
        Assert-True ([IO.File]::ReadAllText($path) -ceq '<DevStudio><Build><Unrelated /></Build></DevStudio>') `
            'An unknown InstallShield schema was changed.'
    }

    Invoke-Test 'The entry script reports manual clients without creating their registry settings' {
        $result = @(& (Join-Path $deployPath 'Configure-SigningClients.ps1') `
            -ServerUrl 'https://tsa.example.test/OpenTimeStamp' -Applications Foxit,Nitro,Bluebeam)
        Assert-True ($result.Count -eq 3 -and @($result | Where-Object Status -ne ManualReview).Count -eq 0) `
            'Manual clients were reported as automatically configured.'
    }
}
finally {
    if ($acrobatRoot -match '^Registry::HKEY_CURRENT_USER\\Software\\OpenTimeStamp-AcrobatSetupTests-[A-Fa-f0-9]+$' -and
        (Test-Path -LiteralPath $acrobatRoot)) {
        Remove-Item -LiteralPath $acrobatRoot -Recurse -Force
    }
    if ($registryRoot -match '^Registry::HKEY_CURRENT_USER\\Software\\OpenTimeStamp-ClientSetupTests-[A-Fa-f0-9]+$' -and
        (Test-Path -LiteralPath $registryRoot)) {
        Remove-Item -LiteralPath $registryRoot -Recurse -Force
    }
    $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
    $allowedParent = [IO.Path]::GetFullPath($testParent).TrimEnd('\') + '\'
    if (-not $resolvedTestRoot.StartsWith($allowedParent, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The temporary test directory is outside the expected parent.'
    }
    Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
}
Write-Host "$tests client configuration tests; $failures failures."
if ($failures) { exit 1 }
