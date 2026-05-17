# Linux Packaging

`ai-proxy` ships as `.deb` and `.rpm` packages for `amd64` and `arm64`. Packages are built reproducibly from CI on every release tag and attached to the GitHub release.

## ⚠ Security posture — read before fleet deployment

Installing this package adds a host-local Certificate Authority to the operating system's trust store. This is required for the proxy to MITM HTTPS traffic and anonymize PII before it leaves the host, but the implications must be reviewed by a security team before rollout via UEM tooling (Intune, JAMF, SCCM, Ansible, etc.).

**After install, this host trusts an `ai-proxy`-controlled CA capable of MITM-ing any HTTPS connection originating from it.** Anyone who can read `/etc/ai-proxy/ca-key.pem` can mint TLS certificates that browsers, CLIs, language runtimes, and other clients on this host will accept without warning.

Concretely:

- The CA private key lives at `/etc/ai-proxy/ca-key.pem` and is generated fresh per host at first install. It never leaves the host. The package sets file mode `0640`, owner `ai-proxy:ai-proxy` — protect this file with the same rigour you'd apply to a host SSH key.
- The CA public certificate is installed into the OS trust store (`/usr/local/share/ca-certificates/` on Debian/Ubuntu, `/etc/pki/trust/anchors/` on openSUSE, `/etc/pki/ca-trust/source/anchors/` on RHEL/Fedora). Browsers and CLI tools on this host will therefore trust any leaf certificate signed by this CA.
- Uninstall removes the CA from the trust store automatically (see [Uninstall](#uninstall)). On upgrade, the existing CA is preserved so applications that have pinned its fingerprint continue to work.
- If the proxy service fails to start, postinstall **rolls back the CA install** and exits non-zero — a successful package install therefore guarantees the proxy is running, so an installed-but-not-intercepting state cannot occur (per CLAUDE.md Invariant #1).

See [docs/tls-mitm.md](../tls-mitm.md) for the broader MITM architecture and threat model.

## Install

### Debian / Ubuntu

```bash
sudo dpkg -i ai-proxy_<version>_amd64.deb
sudo apt-get install -f      # pulls any missing dependencies
```

### RHEL / Fedora / Alma / Rocky

```bash
sudo dnf install ./ai-proxy-<version>-1.x86_64.rpm
```

### openSUSE

```bash
sudo zypper install --allow-unsigned-rpm ./ai-proxy-<version>-1.x86_64.rpm
```

The package:

- Installs the binary at `/usr/bin/ai-proxy`
- Creates the `ai-proxy` system user (no shell, no home)
- Generates a CA cert+key under `/etc/ai-proxy/` if not already present
- Registers the CA in the OS trust store (see the security callout above)
- Installs and enables `ai-proxy.service` (systemd)
- Starts the service immediately; if it fails to start on a `systemd`-managed host, the CA is removed from the trust store and the install aborts non-zero

## Configure

Edit the platform-specific env file and restart the service.

**Debian/Ubuntu:** `/etc/default/ai-proxy`
**RHEL/Fedora/SUSE:** `/etc/sysconfig/ai-proxy`

| Variable | Default | Purpose |
|---|---|---|
| `BIND_ADDRESS` | `127.0.0.1` | Listen address. Use `0.0.0.0` only inside containers. |
| `PROXY_PORT` | `8080` | MITM proxy port. |
| `MANAGEMENT_PORT` | `8081` | Management API port. |
| `UPSTREAM_PROXY` | _(unset)_ | Optional corporate proxy to chain. |
| `CA_CERT_FILE` | `/etc/ai-proxy/ca-cert.pem` | CA cert path. |
| `CA_KEY_FILE` | `/etc/ai-proxy/ca-key.pem` | CA key path. |
| `ENABLED_PACKS` | `SECRETS,GLOBAL,DE` | PII detection packs (order matters). |
| `USE_AI_DETECTION` | `false` | Enable Ollama-backed PII detection. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |

Full schema is documented in `docs/configuration.md`. The structured config at `/etc/ai-proxy/proxy-config.json` is also honored and preserved across upgrades (conffile semantics).

```bash
sudo systemctl restart ai-proxy
```

## Verify

```bash
sudo systemctl status ai-proxy
journalctl -u ai-proxy -f
curl http://127.0.0.1:8081/status
```

## Upgrade

`apt upgrade` and `dnf upgrade` preserve `/etc/ai-proxy/proxy-config.json` and the env file (both declared as `conffile`/`%config(noreplace)`). The generated CA cert and key under `/etc/ai-proxy/` are also preserved.

## Uninstall

```bash
sudo apt-get remove ai-proxy        # Debian/Ubuntu
sudo dnf remove ai-proxy            # RHEL/Fedora
sudo zypper remove ai-proxy         # openSUSE
```

This stops/disables the service and removes the CA from the OS trust store. Files under `/etc/ai-proxy/` are kept (conffile semantics).

To purge configuration as well:

```bash
sudo apt-get purge ai-proxy         # Debian only
sudo rm -rf /etc/ai-proxy           # RHEL/SUSE — manual cleanup
```

## Verify package signature

Every release artifact is signed via Sigstore cosign (keyless, OIDC-bound):

```bash
cosign verify-blob \
  --certificate ai-proxy_<version>_amd64.deb.cert \
  --signature ai-proxy_<version>_amd64.deb.sig \
  --certificate-identity-regexp 'https://github.com/laplaque/ai-anonymizing-proxy/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ai-proxy_<version>_amd64.deb
```

Checksums are published alongside the packages as `SHA256SUMS` and `SHA512SUMS`.

## Source

Built from `packaging/linux/nfpm.yaml` via `make package-linux`. CI workflow: `.github/workflows/release-linux-packages.yml`.
