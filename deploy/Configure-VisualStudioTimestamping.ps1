#Requires -Version 5.1

<#
.SYNOPSIS
Sets the ClickOnce timestamp URL in a selected Visual Studio project or publish profile.
.DESCRIPTION
Updates ManifestTimestampUrl without selecting a certificate or enabling signing.
The setting is shared by x86 and x64 build configurations and does not affect
assembly strong-name signing. Close or reload the selected file in the IDE.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$ProjectPath,
    [Parameter(Mandatory = $true)][uri]$ServerUrl,
    [switch]$AllowInsecureHttp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-ClientTimestampUrl -CommandType Function -ErrorAction SilentlyContinue))
{
    . (Join-Path $PSScriptRoot 'ClientConfiguration.Common.ps1')
}
$endpoints = Get-ClientServerEndpoints -ServerUrl $ServerUrl -AllowInsecureHttp:$AllowInsecureHttp
$ProjectPath = (Get-Item -LiteralPath $ProjectPath -ErrorAction Stop).FullName
if ([IO.Path]::GetExtension($ProjectPath) -notin '.csproj','.vbproj','.pubxml','.props')
{
    throw 'Select an existing C# or Visual Basic project, publish profile, or MSBuild properties file.'
}
$original = [IO.File]::ReadAllBytes($ProjectPath)
$document = New-Object Xml.XmlDocument
$document.PreserveWhitespace = $true
$document.XmlResolver = $null
$settings = New-Object Xml.XmlReaderSettings
$settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
$stream = [IO.MemoryStream]::new($original, $false)
$reader = [Xml.XmlReader]::Create($stream, $settings)
try { $document.Load($reader) }
finally { $reader.Dispose(); $stream.Dispose() }
if ($document.DocumentElement.LocalName -ne 'Project' -or
    $document.DocumentElement.NamespaceURI -notin '', 'http://schemas.microsoft.com/developer/msbuild/2003')
{
    throw 'The selected file must be an MSBuild Project document.'
}
$namespace = $document.DocumentElement.NamespaceURI
$nodes = @($document.DocumentElement.SelectNodes(
    "./*[local-name()='PropertyGroup']/*[local-name()='ManifestTimestampUrl']"))
$changed = $false
if (-not $nodes.Count)
{
    $group = $document.CreateElement('PropertyGroup', $namespace)
    $node = $document.CreateElement('ManifestTimestampUrl', $namespace)
    $group.AppendChild($node) | Out-Null
    $document.DocumentElement.AppendChild($group) | Out-Null
    $nodes = @($node)
}
foreach ($node in $nodes)
{
    if ($node.InnerText -cne $endpoints.Rfc3161Url)
    {
        $node.InnerText = $endpoints.Rfc3161Url
        $changed = $true
    }
}
if (-not $PSCmdlet.ShouldProcess($ProjectPath, 'Configure the ClickOnce timestamp server')) { return }
$backup = $null
if ($changed)
{
    $output = New-Object IO.MemoryStream
    try
    {
        $document.Save($output)
        $backup = Set-ClientSettingsFile -Path $ProjectPath -Bytes $output.ToArray() -OriginalBytes $original
    }
    finally { $output.Dispose() }
}
[pscustomobject]@{
    Product = 'Visual Studio ClickOnce'
    ProjectPath = $ProjectPath
    TimestampUrl = $endpoints.Rfc3161Url
    BackupPath = $backup
    NextStep = 'Enable ClickOnce manifest signing, select a signing certificate, and verify a published timestamp.'
}
