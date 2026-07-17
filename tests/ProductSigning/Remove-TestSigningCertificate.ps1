#Requires -PSEdition Core
#Requires -Version 7.6

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    $Context,

    [switch]$KeepSigningCertificate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cleanupFailures = [System.Collections.Generic.List[string]]::new()

function Remove-TemporaryFileVerified {
    param([Parameter(Mandatory)][string]$Path)

    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        try {
            if (Test-Path -LiteralPath $Path -PathType Leaf) {
                Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            }
        }
        catch {
            if ($attempt -eq 19) {
                $cleanupFailures.Add("Temporary file '$Path' could not be removed: $($_.Exception.Message)")
                return
            }
        }

        if (-not (Test-Path -LiteralPath $Path)) { return }
        Start-Sleep -Milliseconds 250
    }

    $cleanupFailures.Add("Temporary file '$Path' still exists after cleanup.")
}

foreach ($path in @($Context.TemporaryFiles)) {
    if ($path) { Remove-TemporaryFileVerified -Path $path }
}

if (-not $KeepSigningCertificate) {
    foreach ($storeName in @($Context.AddedStores)) {
        $certificatePath = "Cert:\CurrentUser\$storeName\$($Context.Thumbprint)"
        try {
            if (Test-Path -LiteralPath $certificatePath) {
                Remove-Item -LiteralPath $certificatePath -Force -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $certificatePath) {
                $cleanupFailures.Add(
                    "Temporary certificate '$certificatePath' still exists after cleanup.")
            }
        }
        catch {
            $cleanupFailures.Add(
                "Temporary certificate '$certificatePath' could not be removed: $($_.Exception.Message)")
        }
    }
    if ($Context.Certificate) { $Context.Certificate.Dispose() }
    if ($Context.KeyName) {
        try {
            $provider = [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
            if ([Security.Cryptography.CngKey]::Exists($Context.KeyName, $provider)) {
                $key = [Security.Cryptography.CngKey]::Open($Context.KeyName, $provider)
                try { $key.Delete() }
                finally { $key.Dispose() }
            }
            if ([Security.Cryptography.CngKey]::Exists($Context.KeyName, $provider)) {
                $cleanupFailures.Add("Temporary CNG key '$($Context.KeyName)' still exists after cleanup.")
            }
        }
        catch {
            $cleanupFailures.Add(
                "Temporary CNG key '$($Context.KeyName)' could not be removed: $($_.Exception.Message)")
        }
    }
}
else {
    if ($Context.Certificate) { $Context.Certificate.Dispose() }
}
if ($cleanupFailures.Count -ne 0) {
    throw "Product-signing cleanup failed: $($cleanupFailures -join ' ')"
}
