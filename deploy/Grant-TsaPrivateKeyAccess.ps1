#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Grants one IIS application-pool identity read access to a machine TSA private key.

.DESCRIPTION
The certificate must be in LocalMachine\My and use an inbox Windows CNG or CSP
RSA provider, or the Microsoft Software Key Storage Provider for a pure ML-DSA
key. No access is granted to the certificate store itself; the store is already
readable by local processes. This script changes only the ACL on the
selected private-key file.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f ]+$')]
    [string]$Thumbprint,

    [string]$Identity = 'IIS AppPool\OpenTimeStamp',

    [switch]$AllowBroadExistingKeyAcl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonScript = Join-Path $PSScriptRoot 'Deployment.Common.ps1'
if (-not (Test-Path -LiteralPath $commonScript -PathType Leaf)) {
    throw "Deployment support functions were not found at '$commonScript'."
}
. $commonScript

$script:PureMldsaCertificateOids = @(
    '2.16.840.1.101.3.4.3.17',
    '2.16.840.1.101.3.4.3.18',
    '2.16.840.1.101.3.4.3.19'
)

$script:SupportedRsaCngProviders = @(
    'Microsoft Software Key Storage Provider'
)
$script:SupportedRsaCspProviders = @(
    'Microsoft Base Cryptographic Provider v1.0',
    'Microsoft Enhanced Cryptographic Provider v1.0',
    'Microsoft Enhanced RSA and AES Cryptographic Provider',
    'Microsoft RSA SChannel Cryptographic Provider',
    'Microsoft Strong Cryptographic Provider'
)

if ($null -eq ('OpenTimeStamp.TsaKeyNativeMethods' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace OpenTimeStamp
{
    public static class TsaKeyNativeMethods
    {
        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptAcquireCertificatePrivateKey(
            IntPtr certificate,
            uint flags,
            IntPtr parameters,
            out IntPtr key,
            out uint keySpec,
            [MarshalAs(UnmanagedType.Bool)] out bool callerFree);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int NCryptGetProperty(
            IntPtr handle,
            string property,
            [Out] byte[] output,
            int outputLength,
            out int resultLength,
            int flags);

        [DllImport("ncrypt.dll", ExactSpelling = true)]
        public static extern int NCryptFreeObject(IntPtr handle);
    }
}
'@
}

function Get-NCryptPropertyBytes {
    param(
        [IntPtr]$Handle,
        [string]$Property
    )

    $silent = 0x00000040
    $requiredLength = 0
    $status = [OpenTimeStamp.TsaKeyNativeMethods]::NCryptGetProperty(
        $Handle, $Property, $null, 0, [ref]$requiredLength, $silent)
    if ($status -ne 0) {
        $statusValue = [uint64]([int64]$status -band 0xFFFFFFFFL)
        throw "NCryptGetProperty('$Property') failed with status 0x$($statusValue.ToString('X8'))."
    }
    if ($requiredLength -le 0 -or $requiredLength -gt 0x00100000) {
        throw "NCrypt property '$Property' reported invalid length $requiredLength."
    }

    $value = New-Object byte[] $requiredLength
    $writtenLength = 0
    $status = [OpenTimeStamp.TsaKeyNativeMethods]::NCryptGetProperty(
        $Handle, $Property, $value, $value.Length, [ref]$writtenLength, $silent)
    if ($status -ne 0) {
        $statusValue = [uint64]([int64]$status -band 0xFFFFFFFFL)
        throw "NCryptGetProperty('$Property') failed with status 0x$($statusValue.ToString('X8'))."
    }
    if ($writtenLength -le 0 -or $writtenLength -gt $value.Length) {
        throw "NCrypt property '$Property' returned invalid length $writtenLength."
    }
    if ($writtenLength -eq $value.Length) {
        return ,$value
    }

    $writtenValue = New-Object byte[] $writtenLength
    [System.Array]::Copy($value, $writtenValue, $writtenLength)
    return ,$writtenValue
}

function Get-NCryptStringProperty {
    param(
        [IntPtr]$Handle,
        [string]$Property
    )

    [byte[]]$value = Get-NCryptPropertyBytes -Handle $Handle -Property $Property
    if ($value.Length -lt 2 -or ($value.Length % 2) -ne 0 -or
        $value[$value.Length - 1] -ne 0 -or $value[$value.Length - 2] -ne 0) {
        throw "NCrypt string property '$Property' is not a null-terminated Unicode string."
    }

    $text = [System.Text.Encoding]::Unicode.GetString($value, 0, $value.Length - 2)
    if ($text.IndexOf([char]0) -ge 0) {
        throw "NCrypt string property '$Property' contains an embedded null."
    }
    return $text
}

function Get-NCryptDwordProperty {
    param(
        [IntPtr]$Handle,
        [string]$Property
    )

    [byte[]]$value = Get-NCryptPropertyBytes -Handle $Handle -Property $Property
    if ($value.Length -ne 4) {
        throw "NCrypt DWORD property '$Property' has invalid length $($value.Length)."
    }
    return [System.BitConverter]::ToUInt32($value, 0)
}

function Get-NCryptHandleProperty {
    param(
        [IntPtr]$Handle,
        [string]$Property
    )

    [byte[]]$value = Get-NCryptPropertyBytes -Handle $Handle -Property $Property
    if ($value.Length -ne [IntPtr]::Size) {
        throw "NCrypt handle property '$Property' has invalid length $($value.Length)."
    }

    $propertyHandle = if ([IntPtr]::Size -eq 8) {
        [IntPtr]([System.BitConverter]::ToInt64($value, 0))
    }
    else {
        [IntPtr]([System.BitConverter]::ToInt32($value, 0))
    }
    if ($propertyHandle -eq [IntPtr]::Zero) {
        throw "NCrypt handle property '$Property' returned a null handle."
    }
    return $propertyHandle
}

function Get-MldsaMachineKeyPath {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $keyHandle = [IntPtr]::Zero
    $providerHandle = [IntPtr]::Zero
    [uint32]$keySpec = 0
    [bool]$callerFree = $false
    $acquireFlags = [uint32](0x00040000 -bor 0x00000004 -bor 0x00000040)
    try {
        $acquired = [OpenTimeStamp.TsaKeyNativeMethods]::CryptAcquireCertificatePrivateKey(
            $Certificate.Handle, $acquireFlags, [IntPtr]::Zero,
            [ref]$keyHandle, [ref]$keySpec, [ref]$callerFree)
        if (-not $acquired) {
            $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw New-Object System.ComponentModel.Win32Exception(
                $errorCode, 'The ML-DSA certificate private key could not be acquired through Windows CNG.')
        }
        if ($keyHandle -eq [IntPtr]::Zero -or $keySpec -ne [uint32]::MaxValue) {
            throw 'The ML-DSA certificate did not return a valid Windows CNG private-key handle.'
        }

        $algorithm = Get-NCryptStringProperty -Handle $keyHandle -Property 'Algorithm Name'
        $algorithmGroup = Get-NCryptStringProperty -Handle $keyHandle -Property 'Algorithm Group'
        if (-not $algorithm.Equals('ML-DSA', [System.StringComparison]::Ordinal) -or
            -not $algorithmGroup.Equals('MLDSA', [System.StringComparison]::Ordinal)) {
            throw "The acquired CNG key uses unexpected algorithm '$algorithm' / group '$algorithmGroup'."
        }

        $keyType = Get-NCryptDwordProperty -Handle $keyHandle -Property 'Key Type'
        if (($keyType -band 0x00000020) -eq 0) {
            throw 'The ML-DSA CNG private key is not a machine key.'
        }

        $providerHandle = Get-NCryptHandleProperty -Handle $keyHandle -Property 'Provider Handle'
        $providerName = Get-NCryptStringProperty -Handle $providerHandle -Property 'Name'
        if (-not $providerName.Equals(
                'Microsoft Software Key Storage Provider', [System.StringComparison]::Ordinal)) {
            throw "The ML-DSA CNG provider '$providerName' is not supported by this deployment helper."
        }

        $keyDirectory = Join-Path $env:ProgramData 'Microsoft\Crypto\Keys'
        return Resolve-OpenTimeStampPersistedMachineKeyPath -KeyDirectory $keyDirectory `
            -UniqueName (Get-NCryptStringProperty -Handle $keyHandle -Property 'Unique Name') `
            -KeyDescription 'The ML-DSA CNG private key'
    }
    finally {
        if ($providerHandle -ne [IntPtr]::Zero) {
            [void][OpenTimeStamp.TsaKeyNativeMethods]::NCryptFreeObject($providerHandle)
        }
        if ($callerFree -and $keyHandle -ne [IntPtr]::Zero) {
            [void][OpenTimeStamp.TsaKeyNativeMethods]::NCryptFreeObject($keyHandle)
        }
    }
}

function Get-MachineKeyPath {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    if ($script:PureMldsaCertificateOids -contains $Certificate.PublicKey.Oid.Value) {
        return Get-MldsaMachineKeyPath -Certificate $Certificate
    }

    $privateKey = $null
    try {
        $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        if ($null -ne $privateKey) {
            if ($privateKey -is [System.Security.Cryptography.RSACng]) {
                if (-not $privateKey.Key.IsMachineKey) {
                    throw 'The RSA CNG private key is not a machine key.'
                }
                $providerName = $privateKey.Key.Provider.Provider
                if ($script:SupportedRsaCngProviders -notcontains $providerName) {
                    throw "The RSA CNG provider '$providerName' is not a supported persisted software provider."
                }
                return Resolve-OpenTimeStampPersistedMachineKeyPath `
                    -KeyDirectory (Join-Path $env:ProgramData 'Microsoft\Crypto\Keys') `
                    -UniqueName $privateKey.Key.UniqueName -KeyDescription 'The RSA CNG private key'
            }

            if ($privateKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
                if (-not $privateKey.CspKeyContainerInfo.MachineKeyStore) {
                    throw 'The RSA CSP private key is not a machine key.'
                }
                $providerName = $privateKey.CspKeyContainerInfo.ProviderName
                if ($script:SupportedRsaCspProviders -notcontains $providerName) {
                    throw "The RSA CSP provider '$providerName' is not a supported persisted software provider."
                }
                return Resolve-OpenTimeStampPersistedMachineKeyPath `
                    -KeyDirectory (Join-Path $env:ProgramData 'Microsoft\Crypto\RSA\MachineKeys') `
                    -UniqueName $privateKey.CspKeyContainerInfo.UniqueKeyContainerName `
                    -KeyDescription 'The RSA CSP private key'
            }

            throw "The RSA private-key provider '$($privateKey.GetType().FullName)' is not supported by this deployment helper."
        }
    }
    finally {
        if ($null -ne $privateKey) {
            $privateKey.Dispose()
        }
    }

    throw 'The certificate does not expose a supported RSA private key.'
}

function Get-ExplicitPrincipalAccessRules {
    param($FileSecurity, [System.Security.Principal.SecurityIdentifier]$Sid)
    return @($FileSecurity.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference -eq $Sid })
}

function Get-PrincipalAccessRuleState {
    param($Rules)
    $groups = @{}
    foreach ($rule in @($Rules)) {
        $key = '{0}|{1}|{2}' -f $rule.AccessControlType, $rule.InheritanceFlags, $rule.PropagationFlags
        $mask = [uint64]([int64]$rule.FileSystemRights -band 0xFFFFFFFFL)
        if ($groups.ContainsKey($key)) { $groups[$key] = $groups[$key] -bor $mask }
        else { $groups[$key] = $mask }
    }
    return (@($groups.Keys | Sort-Object | ForEach-Object { '{0}|{1:X8}' -f $_, $groups[$_] }) -join ';')
}

function Restore-ExplicitPrincipalAccessRules {
    param(
        [string]$Path,
        [System.Security.Principal.SecurityIdentifier]$Sid,
        $PriorRules,
        [string]$PriorState,
        [string]$IntendedState)
    $acl = Get-Acl -LiteralPath $Path
    $currentRules = @(Get-ExplicitPrincipalAccessRules -FileSecurity $acl -Sid $Sid)
    $currentState = Get-PrincipalAccessRuleState -Rules $currentRules
    if ($currentState -eq $PriorState) { return }
    if ($currentState -ne $IntendedState) {
        throw 'The target-principal ACE state changed concurrently; refusing to overwrite the external change.'
    }
    foreach ($rule in $currentRules) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    foreach ($rule in @($PriorRules)) { $acl.AddAccessRule($rule) }
    Set-Acl -LiteralPath $Path -AclObject $acl
    $restored = Get-Acl -LiteralPath $Path
    $restoredState = Get-PrincipalAccessRuleState -Rules @(
        Get-ExplicitPrincipalAccessRules -FileSecurity $restored -Sid $Sid)
    if ($restoredState -ne $PriorState) { throw 'The prior explicit target-principal ACE state was not restored exactly.' }
}

function Get-SidValue {
    param($IdentityReference)
    try { return $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch [System.Security.Principal.IdentityNotMappedException] { return $null }
}

function Test-KeyAffectingAllowRule {
    param($Rule)
    if ($Rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
        ($Rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)) { return $false }
    $rights = [uint64]([int64]$Rule.FileSystemRights -band 0xFFFFFFFFL)
    return ($rights -band 0xD00D0157L) -ne 0
}

$normalizedThumbprint = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::My,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)

$certificate = $null
try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly -bor
        [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $matches = $store.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
        $normalizedThumbprint,
        $false)
    if ($matches.Count -ne 1) {
        throw "Expected one certificate with thumbprint $normalizedThumbprint in LocalMachine\My; found $($matches.Count)."
    }

    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($matches[0])
    if (-not $certificate.HasPrivateKey) {
        throw 'The selected certificate has no private key.'
    }

    $account = New-Object System.Security.Principal.NTAccount($Identity)
    try {
        $sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch [System.Security.Principal.IdentityNotMappedException] {
        throw "The identity '$Identity' could not be resolved. Create the IIS application pool before granting key access."
    }

    # This helper deliberately supports only IIS virtual application-pool
    # identities. Shared service identities make the TSA key available to
    # unrelated processes running under the same account.
    if ($sid.Value -notmatch '^S-1-5-82-(?:[0-9]+-){4}[0-9]+$') {
        throw "The identity '$Identity' is not a dedicated IIS application-pool virtual account."
    }

    $keyPath = Get-MachineKeyPath -Certificate $certificate
    if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
        throw "The private-key file was not found at '$keyPath'."
    }
    $keyDirectory = Split-Path -Parent $keyPath
    Assert-OpenTimeStampPersistedMachineKeyPathSafe -KeyPath $keyPath -KeyDirectory $keyDirectory

    $acl = Get-Acl -LiteralPath $keyPath
    $trustedSids = @('S-1-5-18', 'S-1-5-32-544', $sid.Value)
    $aclExceptions = @()
    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($trustedSids -notcontains $ownerSid) {
        $aclExceptions += "owner SID $ownerSid is not SYSTEM, BUILTIN\Administrators, or the requested pool"
    }
    foreach ($entry in $acl.Access) {
        if (-not (Test-KeyAffectingAllowRule -Rule $entry)) { continue }
        $entrySid = Get-SidValue -IdentityReference $entry.IdentityReference
        if ($null -eq $entrySid -or $trustedSids -notcontains $entrySid) {
            $aclExceptions += "principal '$($entry.IdentityReference)' SID $(if ($null -eq $entrySid) { '<unresolved>' } else { $entrySid }) rights '$($entry.FileSystemRights)' $(if ($entry.IsInherited) { 'inherited' } else { 'explicit' })"
        }
    }

    if ($aclExceptions.Count -ne 0 -and -not $AllowBroadExistingKeyAcl) {
        throw "The private-key ACL has key-usable access or ownership outside the trusted allowlist: $($aclExceptions -join '; '). Remove it, or rerun with -AllowBroadExistingKeyAcl only after explicit risk review."
    }
    if ($aclExceptions.Count -ne 0) {
        Write-Warning "Existing private-key ACL exceptions were explicitly accepted: $($aclExceptions -join '; ')."
    }

    $aclChanged = $false
    $appliedSddl = $null
    $previousSddl = $acl.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::All)
    $priorTargetRules = @(Get-ExplicitPrincipalAccessRules -FileSecurity $acl -Sid $sid)
    $priorTargetState = Get-PrincipalAccessRuleState -Rules $priorTargetRules
    if ($PSCmdlet.ShouldProcess($keyPath, "Grant read access to $Identity ($sid)")) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::Read,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.SetAccessRule($rule)
        $intendedTargetState = Get-PrincipalAccessRuleState -Rules @(
            Get-ExplicitPrincipalAccessRules -FileSecurity $acl -Sid $sid)
        $updatedSddl = $acl.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::All)
        $aclChanged = -not $updatedSddl.Equals($previousSddl, [System.StringComparison]::Ordinal)
        if ($aclChanged) {
            try {
                $currentSddl = (Get-Acl -LiteralPath $keyPath).GetSecurityDescriptorSddlForm(
                    [System.Security.AccessControl.AccessControlSections]::All)
                if (-not $currentSddl.Equals($previousSddl, [System.StringComparison]::Ordinal)) {
                    throw 'The private-key ACL changed before the helper write; refusing to overwrite the external change.'
                }
                Assert-OpenTimeStampPersistedMachineKeyPathSafe -KeyPath $keyPath -KeyDirectory $keyDirectory
                Set-Acl -LiteralPath $keyPath -AclObject $acl
                $appliedAcl = Get-Acl -LiteralPath $keyPath
                $appliedSddl = $appliedAcl.GetSecurityDescriptorSddlForm(
                    [System.Security.AccessControl.AccessControlSections]::All)
                if (-not $appliedSddl.Equals($updatedSddl, [System.StringComparison]::Ordinal)) {
                    throw 'The private-key ACL written by the helper could not be verified exactly.'
                }
            }
            catch {
                $writeError = $_
                try {
                    Restore-ExplicitPrincipalAccessRules -Path $keyPath -Sid $sid `
                        -PriorRules $priorTargetRules -PriorState $priorTargetState `
                        -IntendedState $intendedTargetState
                }
                catch {
                    throw "Private-key ACL write failed ('$($writeError.Exception.Message)') and target-principal compensation failed for '$keyPath' / '$sid': $($_.Exception.Message). Manual ACL review is required."
                }
                throw $writeError
            }
        }
    }

    [PSCustomObject]@{
        Thumbprint = $normalizedThumbprint
        Subject = $certificate.Subject
        Identity = $Identity
        PrivateKeyPath = $keyPath
        AclChanged = $aclChanged
        PreviousSddl = if ($aclChanged) { $previousSddl } else { $null }
        AppliedSddl = if ($aclChanged) { $appliedSddl } else { $null }
        AcceptedExistingKeyAclExceptions = [string[]]$aclExceptions
    }
}
finally {
    if ($null -ne $certificate) {
        $certificate.Dispose()
    }

    $store.Close()
}
