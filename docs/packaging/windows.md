# Windows Packaging

`ai-proxy` ships as a per-machine MSI for `x64` Windows. MSIs are built reproducibly from CI on every release tag, signed with an EV Authenticode certificate (Azure Key Vault HSM-backed), and attached to the GitHub release together with cosign signatures.

ARM64 is not yet shipped; track the issue tracker for progress.

## ⚠ Security posture — read before fleet deployment

Installing this MSI adds a host-local Certificate Authority to `Cert:\LocalMachine\Root`. This is required for the proxy to MITM HTTPS traffic and anonymize PII before it leaves the host, but the implications must be reviewed by a security team before rollout via Intune, SCCM, Group Policy software deployment, or any other UEM tooling.

**After install, this host trusts an `ai-proxy`-controlled CA capable of MITM-ing any HTTPS connection originating from it.** Anyone who can read `C:\ProgramData\AiProxy\ca-key.pem` can mint TLS certificates that Edge, Chrome, .NET, Node.js, and other clients on this host will accept without warning.

Concretely:

- The CA private key lives at `C:\ProgramData\AiProxy\ca-key.pem` and is generated fresh per host at first install. It never leaves the host. The installer applies NTFS ACLs to `C:\ProgramData\AiProxy\` granting access only to `LocalSystem` and the `Administrators` group (via `util:PermissionEx` on the `CADir` component); inherited `Users:Read` is removed automatically — operators do not need a manual post-install hardening step.
- The CA public certificate is installed into `Cert:\LocalMachine\Root` so browsers and CLIs trust any leaf certificate it signs.
- Uninstall removes the CA from `Cert:\LocalMachine\Root` automatically (see [Uninstall](#uninstall)).
- Upgrades preserve the existing CA so client applications that pinned its fingerprint continue to work.

See [docs/tls-mitm.md](../tls-mitm.md) for the broader MITM architecture and threat model.

## Install

### Interactive

Double-click `ai-proxy-<version>-x64.msi` and accept the elevation prompt.

### Silent (UEM / Intune / SCCM / scripted)

```powershell
msiexec /qn /i ai-proxy-<version>-x64.msi /l*v install.log
```

Override defaults at install time via MSI properties:

```powershell
msiexec /qn /i ai-proxy-<version>-x64.msi `
  PROXY_PORT=18080 `
  BIND_ADDRESS=0.0.0.0 `
  ENABLED_PACKS=SECRETS,GLOBAL,DE `
  /l*v install.log
```

The installer:

- Installs the binary at `C:\Program Files\ai-proxy\ai-proxy.exe`.
- Generates a CA cert+key under `C:\ProgramData\AiProxy\` if not already present.
- Imports the CA into `Cert:\LocalMachine\Root` via `certutil`.
- Registers the `ai-proxy` Windows service (`LocalSystem`, automatic delayed start).
- Configures the service to restart on first, second, and subsequent failure with a 5s delay (1-day reset window).
- Starts the service.

## Verify

```powershell
Get-Service ai-proxy
Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -match 'ai-proxy'
Invoke-WebRequest http://127.0.0.1:8081/status
```

Service management:

```powershell
sc.exe stop ai-proxy
sc.exe start ai-proxy
sc.exe query ai-proxy
```

## Configure

Edit `C:\ProgramData\AiProxy\ai-proxy.env` (loaded by the service via `--env-file`) and restart the service:

```powershell
notepad C:\ProgramData\AiProxy\ai-proxy.env
Restart-Service ai-proxy
```

Supported variables mirror the Linux env-file (`BIND_ADDRESS`, `PROXY_PORT`, `MANAGEMENT_PORT`, `UPSTREAM_PROXY`, `CA_CERT_FILE`, `CA_KEY_FILE`, `ENABLED_PACKS`, `USE_AI_DETECTION`, `LOG_LEVEL`, …). The full schema lives in `docs/configuration.md`. The structured config at `C:\ProgramData\AiProxy\proxy-config.json` is also honored and preserved across upgrades.

## Group Policy (ADMX)

Domain admins can override proxy settings via Group Policy. The MSI does not enforce these registry keys directly — Group Policy writes them under `HKLM\SOFTWARE\Policies\laplaque\AiProxy` and the binary reads them at startup. **Group Policy values take precedence over both `proxy-config.json` and `ai-proxy.env`.**

### Deploy the templates

1. Copy `packaging/windows/admx/ai-proxy.admx` to either
   - `\\<DC>\SYSVOL\<domain>\Policies\PolicyDefinitions\` (central store; recommended), or
   - `C:\Windows\PolicyDefinitions\` on each admin workstation.
2. Copy `packaging/windows/admx/en-US/ai-proxy.adml` to the matching `en-US\` subdirectory.
3. Open **Group Policy Management Editor** → **Computer Configuration** → **Administrative Templates** → **AI Anonymizing Proxy**.

### Available policies

| Policy | Registry value | Purpose |
|---|---|---|
| Enable AI Anonymizing Proxy | `Enabled` (REG_DWORD) | Informational: indicates this host is centrally managed. |
| Proxy server address | `Address` (REG_SZ) | Overrides `BIND_ADDRESS`. |
| Proxy server port | `Port` (REG_DWORD) | Overrides `PROXY_PORT`. |

## Intune deployment

Upload the MSI as a Win32 app or a line-of-business app. Use these commands:

| Field | Value |
|---|---|
| Install command | `msiexec /qn /i ai-proxy-<version>-x64.msi /l*v "%PROGRAMDATA%\ai-proxy\install.log"` |
| Uninstall command | `msiexec /qn /x {ProductCode} /l*v "%PROGRAMDATA%\ai-proxy\uninstall.log"` |
| Install behavior | System |
| Detection | MSI product code (auto-detected by Intune) |

Group Policy values configured via Intune Settings Catalog → Administrative Templates (after importing the ADMX) propagate to the same registry path.

## Upgrade

MSI `MajorUpgrade` is configured — newer versions silently replace older ones. The CA cert/key under `C:\ProgramData\AiProxy\` and the env/config files are preserved (`Permanent="no" NeverOverwrite="yes"`).

## Uninstall

Interactive: **Settings → Apps → Installed apps → AI Anonymizing Proxy → Uninstall**.

Silent:

```powershell
msiexec /qn /x ai-proxy-<version>-x64.msi /l*v uninstall.log
# or, when the original MSI is gone:
$pc = (Get-WmiObject Win32_Product -Filter "Name='AI Anonymizing Proxy'").IdentifyingNumber
msiexec /qn /x $pc /l*v uninstall.log
```

Uninstall stops and removes the `ai-proxy` service and deletes the CA from `Cert:\LocalMachine\Root`. Files under `C:\ProgramData\AiProxy\` (CA cert+key, env file, logs) are left in place. Remove them manually if you want a full purge:

```powershell
Remove-Item -Recurse -Force C:\ProgramData\AiProxy
```

## Verify package signature

The MSI carries an Authenticode signature from an EV certificate stored in Azure Key Vault. Verify with `signtool` (from the Windows SDK):

```powershell
signtool verify /pa /v ai-proxy-<version>-x64.msi
```

In addition, every release artifact is signed via Sigstore cosign (keyless, OIDC-bound):

```bash
cosign verify-blob \
  --certificate ai-proxy-<version>-x64.msi.cert \
  --signature ai-proxy-<version>-x64.msi.sig \
  --certificate-identity-regexp 'https://github.com/laplaque/ai-anonymizing-proxy/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ai-proxy-<version>-x64.msi
```

Checksums are published alongside the MSI as `SHA256SUMS-windows` and `SHA512SUMS-windows`.

## Source

Built from `packaging/windows/wix/Product.wxs` (+ `Service.wxs`, `CATrust.wxs`) via `make package-windows`. CI workflow: `.github/workflows/release-windows-msi.yml`.

## Notes for operators

- **EV cert on a hardware token instead of Azure Key Vault?** The CI workflow ships with `AzureSignTool` which talks to Azure Key Vault. EV certs on USB-token devices (YubiKey HSM-FIPS, etc.) require a self-hosted Windows runner with the token attached and a different signing tool (`signtool` directly). Switch the signing step accordingly if that is your setup.
- **CA removal during uninstall** is implemented via an MSI custom action that shells out to PowerShell to read the cert thumbprint and `certutil -delstore Root`. If you encounter cases where the CA lingers after uninstall, file an issue with the contents of `uninstall.log`; the planned hardening is a small `ai-proxy.exe --remove-ca-from-store` helper invoked from a simpler custom action.
