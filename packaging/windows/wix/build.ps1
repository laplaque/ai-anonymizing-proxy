# AI Anonymizing Proxy — Windows MSI build script.
#
# Builds the MSI via WiX v4 and (when Azure Key Vault credentials are
# present) signs it with AzureSignTool using the EV cert in the vault.
# Runs locally on Windows, in CI on `windows-latest`, or cross-platform
# on macOS/Linux for unsigned PR builds (WiX v4 is .NET 8 / cross-platform).
#
# Required parameters / env vars:
#   VERSION         semver, no 'v' prefix          (or pass -Version)
#   BINARY_PATH     dir containing ai-proxy.exe    (or pass -BinaryPath)
#   PACKAGING_PATH  packaging/windows/wix dir      (or pass -PackagingPath)
#
# Optional signing env vars (CI sets from Secrets):
#   AZURE_KEYVAULT_URI, AZURE_KEYVAULT_CERT_NAME,
#   AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET

param(
  [string]$Version       = $env:VERSION,
  [string]$BinaryPath    = $env:BINARY_PATH,
  [string]$PackagingPath = $env:PACKAGING_PATH
)

$ErrorActionPreference = 'Stop'

if (-not $Version)       { throw "VERSION is required (semver, no leading 'v')" }
if (-not $BinaryPath)    { throw "BINARY_PATH is required (dir containing ai-proxy.exe)" }
if (-not $PackagingPath) { throw "PACKAGING_PATH is required (packaging/windows/wix dir)" }

# Strip a leading 'v' if the caller passed a git tag like v1.2.3 directly.
$Version = $Version -replace '^v', ''

# MSI ProductVersion must be numeric (n.n.n or n.n.n.n). A semver with a
# pre-release suffix like "1.2.3-rc.1" or "0.0.0-dev" will be rejected by
# WiX with a confusing error. Strip any suffix and warn the caller.
if ($Version -match '^(\d+(?:\.\d+){1,3})(.+)$') {
  $stripped = $matches[1]
  if ($Version -ne $stripped) {
    Write-Host "WARN: stripped non-numeric MSI version suffix '$($matches[2])' from '$Version' → '$stripped'"
    $Version = $stripped
  }
} else {
  throw "VERSION '$Version' is not a valid MSI ProductVersion (must start with n.n.n)."
}

$root = Resolve-Path "$PSScriptRoot/../../.."
$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$msi = Join-Path $dist "ai-proxy-$Version-x64.msi"

# Verify WiX is on PATH; install if missing so local builds Just Work.
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  Write-Host "wix CLI not found — installing via dotnet tool install"
  dotnet tool install --global wix
  if ($LASTEXITCODE -ne 0) { throw "dotnet tool install wix failed" }
}

Write-Host "WiX version: $(wix --version)"
Write-Host "Building MSI: $msi"

& wix build `
  -arch x64 `
  -d "Version=$Version" `
  -d "BinaryPath=$BinaryPath" `
  -d "PackagingPath=$PackagingPath" `
  -ext WixToolset.Util.wixext `
  -out $msi `
  "$PSScriptRoot/Product.wxs" `
  "$PSScriptRoot/Service.wxs" `
  "$PSScriptRoot/CATrust.wxs"

if ($LASTEXITCODE -ne 0) { throw "wix build failed" }

# Signing — only if Azure Key Vault credentials are present. PR builds run
# unsigned (CI gates verify the signature on tag builds only).
if ($env:AZURE_KEYVAULT_URI -and $env:AZURE_KEYVAULT_CERT_NAME) {
  if (-not (Get-Command AzureSignTool -ErrorAction SilentlyContinue)) {
    Write-Host "AzureSignTool not found — installing"
    dotnet tool install --global AzureSignTool
    if ($LASTEXITCODE -ne 0) { throw "dotnet tool install AzureSignTool failed" }
  }
  Write-Host "Signing $msi with AzureSignTool"
  & AzureSignTool sign `
    -kvu $env:AZURE_KEYVAULT_URI `
    -kvc $env:AZURE_KEYVAULT_CERT_NAME `
    -kvt $env:AZURE_TENANT_ID `
    -kvi $env:AZURE_CLIENT_ID `
    -kvs $env:AZURE_CLIENT_SECRET `
    -tr http://timestamp.digicert.com `
    -td sha256 `
    -fd sha256 `
    -v `
    $msi
  if ($LASTEXITCODE -ne 0) { throw "AzureSignTool failed" }
} else {
  Write-Host "AZURE_KEYVAULT_URI not set — MSI built unsigned (acceptable for PR builds only)."
}

Write-Host "Built $msi"
