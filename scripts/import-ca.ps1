<#
.SYNOPSIS
    Import the AI Proxy CA certificate into the Windows trust store.
.DESCRIPTION
    Adds the specified CA certificate to Cert:\LocalMachine\Root so that
    TLS connections through the MITM proxy are trusted system-wide.
    Must be run from an elevated (Administrator) PowerShell prompt.
.PARAMETER CaPath
    Path to the CA certificate file (PEM or DER).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CaPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Resolve to absolute path and verify the file exists
$resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CaPath)
if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
    Write-Error "CA certificate not found: $resolvedPath"
    exit 1
}

# Elevation check — fail cleanly rather than self-elevating
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This target must be run from an elevated PowerShell prompt (Run as Administrator)."
    exit 1
}

Import-Certificate -FilePath $resolvedPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
Write-Output "CA trusted on Windows."
