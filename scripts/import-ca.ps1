<#
.SYNOPSIS
    Import the AI Proxy CA certificate into the Windows trust store.
.DESCRIPTION
    Adds the specified CA certificate to the Windows certificate store so
    that TLS connections through the MITM proxy are trusted.

    Two scopes are supported:

      -Scope Machine  (default)
        Installs to Cert:\LocalMachine\Root — system-wide trust.
        Requires Administrator privileges.
        Invoked via `make import-ca-windows`.

      -Scope User
        Installs to Cert:\CurrentUser\Root — current-user trust only.
        No elevation required.
        Invoked via `make import-ca-windows-user`.

    Accepts PEM or DER encoded certificates. PEM files are automatically
    converted to DER before import.
.PARAMETER CaPath
    Path to the CA certificate file (PEM or DER).
.PARAMETER Scope
    Target certificate store scope: Machine (default) or User.
.EXAMPLE
    .\import-ca.ps1 -CaPath ca-cert.pem
    # Imports to LocalMachine\Root (requires elevation)
.EXAMPLE
    .\import-ca.ps1 -CaPath ca-cert.pem -Scope User
    # Imports to CurrentUser\Root (no elevation required)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CaPath,

    [ValidateSet('Machine', 'User')]
    [string]$Scope = 'Machine'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Convert to absolute path (resolves relative to process CWD, not PS provider location)
$resolvedPath = [System.IO.Path]::GetFullPath($CaPath)
if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
    Write-Error "CA certificate not found: $resolvedPath"
    exit 1
}

# Elevation check — only required for Machine scope
if ($Scope -eq 'Machine') {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Machine scope requires an elevated PowerShell prompt (Run as Administrator). Use -Scope User for current-user trust without elevation."
        exit 1
    }
}

# Determine cert store location based on scope
$certStoreLocation = if ($Scope -eq 'User') { 'Cert:\CurrentUser\Root' } else { 'Cert:\LocalMachine\Root' }
$scopeLabel = if ($Scope -eq 'User') { 'current user' } else { 'all users' }

# Read the certificate file — convert PEM to DER if needed
$rawContent = [System.IO.File]::ReadAllText($resolvedPath).TrimStart([char]0xFEFF)
if ($rawContent -match '-----BEGIN CERTIFICATE-----') {
    if (($rawContent | Select-String -Pattern '-----BEGIN CERTIFICATE-----' -AllMatches).Matches.Count -gt 1) {
        Write-Error "PEM file contains multiple certificates. Provide a single CA certificate."
        exit 1
    }
    $base64 = $rawContent -replace '-----BEGIN CERTIFICATE-----' -replace '-----END CERTIFICATE-----' -replace '\s'
    $derBytes = [Convert]::FromBase64String($base64)
    $tempDer = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(),
        "ai-proxy-ca-$PID.cer"
    )
    [System.IO.File]::WriteAllBytes($tempDer, $derBytes)
    $importPath = $tempDer
} else {
    $importPath = $resolvedPath
    $tempDer = $null
}

try {
    # Idempotency check — skip if already trusted
    $incoming = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($importPath)
    $existing = Get-ChildItem $certStoreLocation | Where-Object {
        $_.Thumbprint -eq $incoming.Thumbprint
    }
    if ($existing) {
        Write-Output "CA already trusted on Windows for $scopeLabel (thumbprint: $($existing.Thumbprint))."
        exit 0
    }

    # Import and verify
    $cert = Import-Certificate -FilePath $importPath -CertStoreLocation $certStoreLocation
    if (-not $cert) {
        Write-Error "Import-Certificate completed but returned no certificate object."
        exit 1
    }
    $installed = Get-ChildItem $certStoreLocation | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
    if (-not $installed) {
        Write-Error "Certificate not found in store after import — Group Policy or security software may have blocked it."
        exit 1
    }
    Write-Output "CA trusted on Windows for $scopeLabel (thumbprint: $($cert.Thumbprint))."
} catch {
    Write-Error "Failed to import CA certificate: $_"
    exit 1
} finally {
    if ($tempDer -and (Test-Path -LiteralPath $tempDer)) {
        Remove-Item -LiteralPath $tempDer -Force
    }
}
