#Requires -Version 5.1

<#
.SYNOPSIS
Configures signing clients on a selected Windows computer for OpenTimeStamp.
.DESCRIPTION
Runs the per-application helpers locally or through existing PowerShell
remoting. Detected selects installed supported desktop applications. Explicit
application selection can preconfigure a user before installing an application.
Foxit, Nitro, and Bluebeam return manual steps or a limitation instead of writing
undocumented settings. Desktop preferences are per-user. InstallShield changes
only an explicitly supplied settings file. No trust stores or security policies
are changed by default. AllowAdobeTimestampNetworkAccess explicitly permits the
TSA hostname in Adobe's Internet-access list. Each helper verifies its writes independently.
Visual Studio and VS Code configuration belongs to the explicitly selected
project or workspace. Detected IDEs without those paths return ProjectRequired.
.PARAMETER ServerUrl
IIS application URL, such as https://tsa.example.com/OpenTimeStamp, without the
/timestamp/rfc3161 or /timestamp/authenticode suffix.
.PARAMETER UserSid
An optional loaded user SID on the target computer. Without it, setup affects
the account running the script or the authenticated remoting account.
.PARAMETER ComputerName
One remote computer with PowerShell remoting already configured. Local helper
sources are sent in memory; their directory need not exist on the target.
.PARAMETER VisualStudioProjectPath
An existing ClickOnce project or publish profile on the selected computer.
.PARAMETER VSCodeWorkspacePath
An existing project directory for the generated manual signing task.
.PARAMETER VSCodeSigningScriptPath
The persistent signing wrapper used by VS Code on the selected computer.
The default for local setup is the wrapper beside this setup script.
.PARAMETER VSCodePowerShellArchitecture
The signing host architecture, independent of the IDE or output file architecture.
.EXAMPLE
.\Configure-SigningClients.ps1 -ServerUrl https://tsa.example.com/OpenTimeStamp -WhatIf
.EXAMPLE
.\Configure-SigningClients.ps1 -ServerUrl https://tsa.example.com/OpenTimeStamp -Applications Office,Vba,Acrobat
.EXAMPLE
.\Configure-SigningClients.ps1 -ServerUrl https://tsa.example.com/OpenTimeStamp -ComputerName PC01 `
    -UserSid S-1-5-21-111-222-333-1001
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][uri]$ServerUrl,
    [ValidateSet('Detected', 'Office', 'Vba', 'Acrobat', 'AcrobatReader', 'LibreOffice', 'PdfXChange',
        'Foxit', 'Nitro', 'Bluebeam', 'InstallShield', 'VisualStudio', 'VisualStudioCode')]
    [string[]]$Applications = @('Detected'),
    [string]$ComputerName,
    [PSCredential]$Credential,
    [string]$UserSid,
    [ValidatePattern('^\d+\.0$')][string[]]$OfficeVersion = @('16.0'),
    [ValidateSet('DC', '2024')][string]$AcrobatVersion = 'DC',
    [string]$LibreOfficeSettingsPath,
    [string]$PdfXChangePresetPath,
    [string]$InstallShieldSettingsPath,
    [string]$VisualStudioProjectPath,
    [string]$VSCodeWorkspacePath,
    [string]$VSCodeSigningScriptPath,
    [ValidateSet('PowerShell', 'SignTool')][string]$VSCodeSigningTool = 'PowerShell',
    [ValidateSet('Auto', 'x86', 'x64')][string]$VSCodePowerShellArchitecture = 'Auto',
    [string]$VSCodeSignToolPath,
    [ValidateNotNullOrEmpty()][string]$ServerName = 'OpenTimeStamp',
    [switch]$AllowSigningWithoutTimestamp,
    [switch]$AllowAdobeTimestampNetworkAccess,
    [switch]$AllowInsecureHttp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Applications -contains 'Detected' -and $Applications.Count -ne 1) {
    throw 'Use Detected alone, or explicitly list the applications to configure.'
}
if ($Credential -and -not $ComputerName) { throw 'Credential requires ComputerName.' }
if ($Applications -contains 'InstallShield' -and -not $InstallShieldSettingsPath) {
    throw 'InstallShield requires InstallShieldSettingsPath for the intended edition and language.'
}
. (Join-Path $PSScriptRoot 'ClientConfiguration.Common.ps1')
Get-ClientServerEndpoints -ServerUrl $ServerUrl -AllowInsecureHttp:$AllowInsecureHttp | Out-Null
if (-not $VSCodeSigningScriptPath -and -not $ComputerName) {
    $VSCodeSigningScriptPath = Join-Path $PSScriptRoot 'Invoke-TimestampSigning.ps1'
}
$options = @{}
foreach ($name in @('ServerUrl', 'Applications', 'UserSid', 'OfficeVersion', 'AcrobatVersion',
        'LibreOfficeSettingsPath', 'PdfXChangePresetPath', 'InstallShieldSettingsPath', 'ServerName',
        'VisualStudioProjectPath', 'VSCodeWorkspacePath', 'VSCodeSigningScriptPath', 'VSCodeSigningTool',
        'VSCodePowerShellArchitecture', 'VSCodeSignToolPath')) {
    $options[$name] = Get-Variable -Name $name -ValueOnly
}
$options.AllowSigningWithoutTimestamp = [bool]$AllowSigningWithoutTimestamp
$options.AllowAdobeTimestampNetworkAccess = [bool]$AllowAdobeTimestampNetworkAccess
$options.ServerUrl = $ServerUrl.AbsoluteUri
$options.AllowInsecureHttp = [bool]$AllowInsecureHttp
$options.WhatIf = [bool]$WhatIfPreference
$sources = @{}
foreach ($name in @('ClientConfiguration.Common.ps1', 'Configure-OfficeTimestamping.ps1',
        'Configure-AcrobatTimestamping.ps1', 'Configure-LibreOfficeTimestamping.ps1',
        'Configure-PdfXChangeTimestamping.ps1', 'Configure-InstallShieldTimestamping.ps1',
        'Configure-AdobeTimestampNetworkAccess.ps1', 'Configure-VisualStudioTimestamping.ps1',
        'Configure-VSCodeTimestamping.ps1')) {
    $sources[$name] = Get-Content -LiteralPath (Join-Path $PSScriptRoot $name) -Raw
}

$configure = {
    param([hashtable]$Options, [hashtable]$Sources)

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    . ([scriptblock]::Create($Sources['ClientConfiguration.Common.ps1']))
    $endpoints = Get-ClientServerEndpoints -ServerUrl ([uri]$Options.ServerUrl) `
        -AllowInsecureHttp:$Options.AllowInsecureHttp
    $user = Get-ClientUserContext -UserSid $Options.UserSid
    $executables = [ordered]@{
        Office = @('WINWORD.EXE', 'EXCEL.EXE', 'POWERPNT.EXE')
        Vba = @('WINWORD.EXE', 'EXCEL.EXE', 'POWERPNT.EXE', 'OUTLOOK.EXE', 'MSACCESS.EXE', 'VISIO.EXE', 'WINPROJ.EXE')
        Acrobat = @('Acrobat.exe')
        AcrobatReader = @('AcroRd32.exe')
        LibreOffice = @('soffice.exe')
        PdfXChange = @('PDFXEdit.exe', 'PXCEditor.exe')
        Foxit = @('FoxitPDFEditor.exe', 'FoxitPDFReader.exe', 'FoxitReader.exe', 'FoxitPhantomPDF.exe')
        Nitro = @('NitroPDF.exe')
        Bluebeam = @('Revu.exe')
    }
    $applications = @($Options.Applications | Select-Object -Unique)
    if ($applications -contains 'Detected') {
        $applications = @($executables.Keys | Where-Object {
            Get-ClientApplicationPath -ExecutableNames $executables[$_] -UserContext $user
        })
        foreach ($application in @('VisualStudio', 'VisualStudioCode')) {
            if (Get-ClientDeveloperApplicationPath -Application $application -UserContext $user) {
                $applications += $application
            }
        }
    }
    if (-not $applications.Count) {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME; UserSid = $user.Sid; Application = 'Detected'; Status = 'NotDetected'
            Detail = 'No supported desktop client was detected. Use Applications to select a client explicitly.'
        }
        return
    }
    $failures = @()
    foreach ($application in $applications) {
        $parameters = @{
            UserSid = $Options.UserSid; AllowInsecureHttp = $Options.AllowInsecureHttp
            WhatIf = $Options.WhatIf; Confirm = $false
        }
        $scriptName = $null
        $detail = $null
        $projectRequired = $false
        switch ($application) {
            { $_ -in @('Office', 'Vba') } {
                $scriptName = 'Configure-OfficeTimestamping.ps1'
                $parameters.Rfc3161Url = $endpoints.Rfc3161Url
                $parameters.AuthenticodeUrl = $endpoints.AuthenticodeUrl
                $parameters.OfficeVersion = $Options.OfficeVersion
                $parameters.SigningType = if ($application -eq 'Office') { 'Documents' } else { 'Vba' }
                $parameters.AllowSigningWithoutTimestamp = $Options.AllowSigningWithoutTimestamp
            }
            { $_ -in @('Acrobat', 'AcrobatReader') } {
                $scriptName = 'Configure-AcrobatTimestamping.ps1'
                $parameters.TimestampUrl = $endpoints.Rfc3161Url
                $parameters.ServerName = $Options.ServerName
                $parameters.Product = if ($application -eq 'Acrobat') { 'Acrobat' } else { 'Reader' }
                $parameters.Version = $Options.AcrobatVersion
                $parameters.AllowSigningWithoutTimestamp = $Options.AllowSigningWithoutTimestamp
                if (-not $parameters.UserSid) { $parameters.Remove('UserSid') }
            }
            LibreOffice {
                $scriptName = 'Configure-LibreOfficeTimestamping.ps1'
                $parameters.TimestampUrl = $endpoints.Rfc3161Url
                $parameters.SettingsPath = $Options.LibreOfficeSettingsPath
            }
            PdfXChange {
                $scriptName = 'Configure-PdfXChangeTimestamping.ps1'
                $parameters.TimestampUrl = $endpoints.Rfc3161Url
                $parameters.ServerName = $Options.ServerName
                $parameters.PresetPath = $Options.PdfXChangePresetPath
            }
            InstallShield {
                $scriptName = 'Configure-InstallShieldTimestamping.ps1'
                $parameters.Remove('UserSid')
                $parameters.ServerUrl = $Options.ServerUrl
                $parameters.SettingsPath = $Options.InstallShieldSettingsPath
            }
            VisualStudio {
                if (-not $Options.VisualStudioProjectPath) {
                    $projectRequired = $true
                    $detail = 'Supply VisualStudioProjectPath for the intended ClickOnce project or publish profile.'
                    break
                }
                $scriptName = 'Configure-VisualStudioTimestamping.ps1'
                $parameters.Remove('UserSid')
                $parameters.ProjectPath = $Options.VisualStudioProjectPath
                $parameters.ServerUrl = $Options.ServerUrl
            }
            VisualStudioCode {
                if (-not $Options.VSCodeWorkspacePath -or -not $Options.VSCodeSigningScriptPath) {
                    $projectRequired = $true
                    $detail = 'Supply VSCodeWorkspacePath and an existing VSCodeSigningScriptPath on the target computer.'
                    break
                }
                $scriptName = 'Configure-VSCodeTimestamping.ps1'
                $parameters.Remove('UserSid')
                $parameters.WorkspacePath = $Options.VSCodeWorkspacePath
                $parameters.ServerUrl = $Options.ServerUrl
                $parameters.SigningScriptPath = $Options.VSCodeSigningScriptPath
                $parameters.SigningTool = $Options.VSCodeSigningTool
                $parameters.PowerShellArchitecture = $Options.VSCodePowerShellArchitecture
                $parameters.SignToolPath = $Options.VSCodeSignToolPath
            }
            Foxit {
                $detail = 'Preferences > Time Stamp Servers > New: add the RFC 3161 URL, then Set Default. ' +
                    'Allow the timestamp connection when prompted and validate the TSA certificate chain.'
            }
            Nitro {
                $detail = 'Preferences > Digital Signature > Time Stamp Servers: add the RFC 3161 URL, ' +
                    'enable Acquire timestamp from attestable server, then Set Default. ' +
                    'Other servers can be used on failure.'
            }
            Bluebeam {
                $detail = 'Bluebeam documentation did not establish a supported custom RFC 3161 setting. ' +
                    'Confirm support with the vendor for the installed release before relying on external timestamping.'
            }
        }
        $status = if ($scriptName) { 'Configured' } else { 'ManualReview' }
        if ($projectRequired) { $status = 'ProjectRequired' }
        if ($scriptName) {
            try {
                $detail = & ([scriptblock]::Create($Sources[$scriptName])) @parameters
                if ($application -in @('Acrobat', 'AcrobatReader') -and $Options.AllowAdobeTimestampNetworkAccess) {
                    $networkParameters = @{
                        TimestampUrl = $endpoints.Rfc3161Url; Product = $parameters.Product
                        Version = $parameters.Version; UserSid = $Options.UserSid
                        AllowInsecureHttp = $Options.AllowInsecureHttp; WhatIf = $Options.WhatIf; Confirm = $false
                    }
                    $network = & ([scriptblock]::Create($Sources['Configure-AdobeTimestampNetworkAccess.ps1'])) `
                        @networkParameters
                    $detail = [pscustomobject]@{ Timestamp = $detail; InternetAccess = $network }
                }
                if ($Options.WhatIf) { $status = 'WhatIf' }
                elseif ($application -in @('LibreOffice', 'PdfXChange')) { $status = 'SelectionRequired' }
            }
            catch {
                $status = 'Failed'
                $detail = $_.Exception.Message
                $failures += $application
            }
        }
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            UserSid = $user.Sid
            Application = $application
            Status = $status
            Rfc3161Url = $endpoints.Rfc3161Url
            AuthenticodeUrl = $endpoints.AuthenticodeUrl
            Detail = $detail
        }
    }
    if ($failures.Count) {
        if ($Options.WhatIf) {
            throw "Client preview failed for: $($failures -join ', '). No settings were changed."
        }
        throw "Client setup failed for: $($failures -join ', '). Earlier successful applications remain configured."
    }
}

$target = if ($ComputerName) { $ComputerName } else { $env:COMPUTERNAME }
if (-not $PSCmdlet.ShouldProcess($target, "Configure signing clients for '$ServerUrl'")) {
    if ($WhatIfPreference -and -not $ComputerName) { & $configure $options $sources }
    return
}
if ($ComputerName) {
    $remoteParameters = @{
        ComputerName = $ComputerName; ScriptBlock = $configure; ArgumentList = @($options, $sources)
    }
    if ($Credential) { $remoteParameters.Credential = $Credential }
    Invoke-Command @remoteParameters
}
else { & $configure $options $sources }
