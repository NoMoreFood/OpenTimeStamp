#Requires -Version 5.1

<#
.SYNOPSIS
Returns timestamp parameters for tools configured on each signing operation.
.DESCRIPTION
Returns a parameter hashtable for PowerShell and an argument array for native
tools. Supply the remaining certificate and input-file parameters yourself.
MSBuild returns project properties for ClickOnce signing. This script does not
create a computer-wide default or sign files.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][uri]$ServerUrl,
    [Parameter(Mandatory = $true)]
    [ValidateSet('SignTool', 'PowerShell', 'NuGet', 'DotNetNuGet', 'JarSigner', 'Mage', 'MSBuild')]
    [string]$Tool,
    [switch]$AllowInsecureHttp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-ClientTimestampUrl -CommandType Function -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'ClientConfiguration.Common.ps1')
}
$endpoints = Get-ClientServerEndpoints -ServerUrl $ServerUrl -AllowInsecureHttp:$AllowInsecureHttp
switch ($Tool) {
    SignTool {
        if (([uri]$endpoints.Rfc3161Url).Scheme -eq 'https') {
            throw 'Windows SDK SignTool rejects HTTPS timestamp URLs. Use Invoke-TimestampSigning.ps1 for HTTPS.'
        }
        '/tr'; $endpoints.Rfc3161Url; '/td'; 'SHA256'; '/fd'; 'SHA256'
    }
    PowerShell {
        if (([uri]$endpoints.AuthenticodeUrl).Scheme -eq 'https') {
            throw 'Use Invoke-TimestampSigning.ps1 for HTTPS; native timestamping is not consistent across Windows hosts.'
        }
        @{ TimestampServer = $endpoints.AuthenticodeUrl; HashAlgorithm = 'SHA256' }
    }
    NuGet { '-Timestamper'; $endpoints.Rfc3161Url; '-TimestampHashAlgorithm'; 'SHA256'; '-HashAlgorithm'; 'SHA256' }
    DotNetNuGet {
        '--timestamper'; $endpoints.Rfc3161Url; '--timestamp-hash-algorithm'; 'SHA256'; '--hash-algorithm'; 'SHA256'
    }
    JarSigner { '-tsa'; $endpoints.Rfc3161Url; '-tsadigestalg'; 'SHA-256'; '-digestalg'; 'SHA-256' }
    Mage { '-TimestampUri'; $endpoints.Rfc3161Url; '-Algorithm'; 'sha256RSA' }
    MSBuild { @{ ManifestTimestampUrl = $endpoints.Rfc3161Url } }
}
