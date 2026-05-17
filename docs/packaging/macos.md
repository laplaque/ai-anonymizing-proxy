# macOS Packaging

`ai-proxy` ships for macOS as two artifacts:

| Artifact | Use case |
|---|---|
| `ai-proxy-<version>-universal.pkg` | Self-managed install or JAMF "PKG" policy. Universal binary (arm64 + amd64). |
| `ai-proxy-<version>.mobileconfig` | JAMF / MDM declarative deployment — pushes CA trust + global HTTP proxy settings. |

Both are signed with an Apple Developer ID certificate. The PKG is additionally notarized and stapled, so it installs offline without contacting Apple at install time.

Minimum macOS version: **12.0 (Monterey)**.

## ⚠ Security posture — read before fleet deployment

Installing this package adds a host-local Certificate Authority to the macOS System keychain trust store. **After install, this host trusts an `ai-proxy`-controlled CA capable of MITM-ing any HTTPS connection originating from it.** Anyone with read access to `/etc/ai-proxy/ca-key.pem` can mint TLS certificates that Safari, every CLI, Xcode, etc. will accept without warning.

Concretely:

- The CA private key lives at `/etc/ai-proxy/ca-key.pem`, mode `0640`, owned by the `_aiproxy` service user. Protect it with the same rigour you'd apply to a host SSH key.
- The CA public cert is trusted in `/Library/Keychains/System.keychain` via `security add-trusted-cert -d -r trustRoot`.
- The PKG generates a fresh CA per host on first install (preserved on upgrade) — blast radius of a key compromise is **one host**.
- The **`.mobileconfig` deploys the release CA** baked in at build time. That CA is backed by a single repository secret (`MACOS_RELEASE_CA_KEY`) — compromise of that secret confers the ability to mint TLS certs trusted by **every device in the fleet** that installed via the profile, simultaneously. The `.mobileconfig` route's blast radius is the entire managed fleet, not one host. Treat the secret with that threat model in mind: restrict who can read it, rotate it on a schedule, and prefer the per-host PKG path for populations where a per-host CA is acceptable.
- Rotation of the .mobileconfig CA requires re-issuing the profile and pushing it to every device (see [Release CA rotation](#release-ca-rotation)).
- Uninstall removes the CA from the System keychain (see [Uninstall](#uninstall)).
- If the LaunchDaemon fails to start during postinstall, the CA is removed from the System keychain and the install aborts non-zero — installed-but-not-intercepting cannot occur (per CLAUDE.md Invariant #1).

See [docs/tls-mitm.md](../tls-mitm.md) for the broader MITM architecture and threat model.

## Install — PKG

Double-click the `.pkg` in Finder, or silently:

```bash
sudo installer -pkg ai-proxy-<version>-universal.pkg -target /
```

Gatekeeper accepts the package because it is signed (Developer ID Installer) and notarized + stapled.

The package:

- Installs the universal binary at `/usr/local/bin/ai-proxy`
- Creates the `_aiproxy` system user (hidden, no shell, no home; UID auto-allocated in the 220–400 range)
- Generates a CA cert + key under `/etc/ai-proxy/` if not already present
- Trusts the CA in the System keychain via `security add-trusted-cert`
- Installs the LaunchDaemon plist at `/Library/LaunchDaemons/com.ai-anonymizing-proxy.plist`
- Loads + starts the daemon via `launchctl bootstrap system …`
- Ships the uninstall script at `/usr/local/share/ai-proxy/uninstall.sh`

If postinstall cannot load the LaunchDaemon, it removes the CA from the System keychain and exits non-zero.

### UID allocation fallback

The postinstall script scans UIDs 220–400 for a free slot. If that range is fully occupied on a heavily customized host, allocate `_aiproxy` manually before installing:

```bash
sudo dscl . -create /Groups/_aiproxy PrimaryGroupID <free-uid>
sudo dscl . -create /Users/_aiproxy UniqueID <free-uid>
sudo dscl . -create /Users/_aiproxy PrimaryGroupID <free-uid>
sudo dscl . -create /Users/_aiproxy NFSHomeDirectory /var/empty
sudo dscl . -create /Users/_aiproxy UserShell /usr/bin/false
sudo dscl . -create /Users/_aiproxy IsHidden 1
sudo dscl . -create /Users/_aiproxy Password "*"
```

## Configure

The LaunchDaemon does **not** source an env file — macOS launchd reads env vars only from the plist's `EnvironmentVariables` dict.

To change a value, edit `/Library/LaunchDaemons/com.ai-anonymizing-proxy.plist` (or override at MDM-deploy time) and re-bootstrap:

```bash
sudo launchctl bootout system/com.ai-anonymizing-proxy
sudo launchctl bootstrap system /Library/LaunchDaemons/com.ai-anonymizing-proxy.plist
```

The file at `/etc/ai-proxy/ai-proxy.env` is shipped for parity with Linux but is informational on macOS — admins migrating from Linux can read it to remind themselves of the variable names and defaults.

| Variable | Default in plist | Purpose |
|---|---|---|
| `BIND_ADDRESS` | `127.0.0.1` | Listen address. |
| `PROXY_PORT` | `18080` | MITM proxy port. Differs from Linux (8080) to avoid collisions with common dev servers on macOS. |
| `MANAGEMENT_PORT` | `18081` | Management API port. |
| `CA_CERT_FILE` | `/etc/ai-proxy/ca-cert.pem` | CA cert path. |
| `CA_KEY_FILE` | `/etc/ai-proxy/ca-key.pem` | CA key path. |
| `ENABLED_PACKS` | `SECRETS,GLOBAL,DE` | PII detection packs (order matters — `SECRETS` must precede `GLOBAL`). |
| `USE_AI_DETECTION` | `false` | Enable Ollama-backed PII detection. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |

The structured config at `/etc/ai-proxy/proxy-config.json` is honored as a fallback and preserved across upgrades.

## Verify

```bash
# Service state
sudo launchctl print system/com.ai-anonymizing-proxy | head -40

# Logs
tail -f /var/log/ai-proxy/stdout.log /var/log/ai-proxy/stderr.log

# Management API
curl http://127.0.0.1:18081/status

# Trusted CA in the System keychain
sudo security find-certificate -c "ai-proxy" -p /Library/Keychains/System.keychain
```

## Install — `.mobileconfig` (JAMF / MDM)

The `.mobileconfig` profile carries two payloads:

1. **`com.apple.security.root`** — the release CA, trusted as a root in the System keychain.
2. **`com.apple.proxy.http.global`** — a manual HTTP proxy at `127.0.0.1:18080`.

It does **not** install the binary or the LaunchDaemon. The profile is meant to be deployed in tandem with the PKG (PKG installs the daemon, profile establishes trust + proxy settings).

### Manual install

```bash
sudo profiles install -path ai-proxy-<version>.mobileconfig
sudo profiles list | grep ai-proxy
```

Or double-click the file in Finder and approve in **System Settings → Privacy & Security → Profiles**.

### JAMF deployment

In JAMF Pro:

1. **Computers → Configuration Profiles → Upload** the signed `.mobileconfig`.
2. Scope to the target smart group.
3. (Optional) Wrap the PKG in a Policy that runs alongside the profile, so the LaunchDaemon is present on every device that trusts the CA.

JAMF will treat the profile's `PayloadRemovalDisallowed = false` as removable — admin re-scoping pulls the profile and removes both the CA trust and the proxy settings.

### Verify the profile

```bash
sudo profiles list                                          # is it installed?
plutil -lint ai-proxy-<version>.mobileconfig                # XML valid?
/usr/bin/security cms -D -i ai-proxy-<version>.mobileconfig | head   # signed payload
```

## Upgrade

`installer -pkg` reinstalls the binary, plist, and uninstall script. `/etc/ai-proxy/proxy-config.json` and the existing CA cert + key are preserved.

For .mobileconfig: increment `PayloadVersion` in the source and re-push — MDMs replace the existing profile in place.

## Uninstall

```bash
sudo bash /usr/local/share/ai-proxy/uninstall.sh
sudo pkgutil --forget com.ai-anonymizing-proxy.pkg
```

This stops the daemon, removes the CA from the System keychain, and removes the LaunchDaemon plist. Files under `/etc/ai-proxy/` are preserved — purge manually if desired:

```bash
sudo rm -rf /etc/ai-proxy /var/lib/ai-proxy /var/log/ai-proxy
```

For the `.mobileconfig`:

```bash
sudo profiles remove -identifier com.ai-anonymizing-proxy.profile
```

## Verify package signatures

Every release artifact is signed via Sigstore cosign (keyless, OIDC-bound):

```bash
cosign verify-blob \
  --certificate ai-proxy-<version>-universal.pkg.cert \
  --signature   ai-proxy-<version>-universal.pkg.sig \
  --certificate-identity-regexp 'https://github.com/laplaque/ai-anonymizing-proxy/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ai-proxy-<version>-universal.pkg
```

Apple-level signature checks:

```bash
pkgutil --check-signature ai-proxy-<version>-universal.pkg
spctl --assess --type install --verbose=2 ai-proxy-<version>-universal.pkg
```

Checksums are published as `SHA256SUMS-macos` and `SHA512SUMS-macos` alongside the artifacts.

## Release CA rotation

The `.mobileconfig` embeds the release CA at build time. PKG hosts do **not** use this CA — they generate their own per-host CA in `postinstall` (idempotent on upgrade). The procedures differ by deployment route:

### `.mobileconfig` / MDM route

If the release CA private key is suspected compromised:

1. Generate a fresh CA pair locally.
2. Re-encode both PEMs as base64 and update the `MACOS_RELEASE_CA_CERT` / `MACOS_RELEASE_CA_KEY` repository secrets.
3. Cut a new release tag — the CI workflow rebuilds the `.mobileconfig` with the new CA embedded.
4. Push the new profile to every managed device via JAMF / MDM. The old profile is replaced; old CA trust is removed.

### PKG route

PKG hosts each have their own CA at `/etc/ai-proxy/ca-cert.pem` and `/etc/ai-proxy/ca-key.pem`. The release CA from CI never reaches them. Rotation is per-host:

```bash
sudo bash /usr/local/share/ai-proxy/uninstall.sh   # removes old CA trust + daemon
sudo pkgutil --forget com.ai-anonymizing-proxy.pkg
sudo rm -f /etc/ai-proxy/ca-cert.pem /etc/ai-proxy/ca-key.pem
sudo installer -pkg ai-proxy-<version>-universal.pkg -target /
```

In-place rotation via a forthcoming `ai-proxy install --rotate-ca` command is planned (Phase 6). Until then, the PKG-route rotation is uninstall + remove cert + reinstall.

## Troubleshooting

```bash
# Daemon state — look at LastExitStatus, PID, state fields.
sudo launchctl print system/com.ai-anonymizing-proxy

# Structured log — anything the daemon wrote to unified log in the last hour.
log show --predicate 'process == "ai-proxy"' --info --last 1h

# Stdout/stderr captured by launchd.
tail -n 200 /var/log/ai-proxy/stderr.log
```

| Symptom | Likely cause | Action |
|---|---|---|
| `postinstall exit code 1` | LaunchDaemon failed to load; CA trust **was** rolled back. | Check `launchctl print` for the diagnostic; common causes: port collision on 18080/18081, missing dir under `/var/`. Re-run `installer` once the cause is fixed. |
| `postinstall exit code 2` | LaunchDaemon failed AND rollback could not remove the CA. | **PII may leak.** Manually delete the CA: `sudo security delete-certificate -c "ai-proxy CA" /Library/Keychains/System.keychain`. |
| `installer` reports "package signed by unidentified developer" | PKG was modified after signing, or the host has Gatekeeper disabled in a way that surfaces stricter checks. | Re-download the PKG; verify with `pkgutil --check-signature`. |
| Daemon running but HTTPS sites fail with TLS errors | CA not in System keychain. | `sudo security find-certificate -c "ai-proxy" -p /Library/Keychains/System.keychain` — empty output means trust did not install. Re-run postinstall. |
| Profile install silently does nothing | Profile not signed, or signed by a non-trusted cert. | `plutil -lint ai-proxy-*.mobileconfig` + `security cms -D -i ai-proxy-*.mobileconfig`. |

## Pre-tag verification ritual

CI cannot verify that the `.mobileconfig` actually causes a profile-enrolled macOS host's CFNetwork stack to route HTTPS through `127.0.0.1:18080` — the workflow runs on a GitHub-hosted runner with no profile installed. Before every `v*` tag push, execute this ritual on a Tart VM, Apple Silicon test host, or MDM-enrolled device. Tracked in issue [#125](https://github.com/laplaque/ai-anonymizing-proxy/issues/125); the `Notarize PKG` step in `release-macos-pkg.yml` references it.

```bash
# 1. Install PKG + profile
sudo installer -pkg dist/ai-proxy-<version>-universal.pkg -target /
sudo profiles install -path dist/ai-proxy-<version>.mobileconfig

# 2. Confirm both are active
sudo launchctl print system/com.ai-anonymizing-proxy | grep state
sudo profiles list | grep ai-anonymizing-proxy

# 3. HTTPS interception test — note the absence of --proxy on curl
curl -k https://httpbin.org/get

# 4. Verify the daemon logged the connection
tail -n 20 /var/log/ai-proxy/stdout.log | grep httpbin.org
```

**Pass criterion:** step 4 returns at least one log line referencing `httpbin.org`, proving the profile's global HTTP proxy payload caused CFNetwork to route the unproxied `curl` through the daemon.

Record the result (macOS version + log excerpt) on issue #125 before tagging. If the payload shape needs adjustment for a new macOS major version (e.g., HTTPSEnable / HTTPSProxy keys), open a follow-up PR before the tag.

## Source

- PKG: `packaging/macos/pkg/` (`build.sh`, `distribution.xml`, `scripts/{postinstall,preuninstall}`, `notarize.sh`)
- .mobileconfig: `packaging/macos/mobileconfig/` (`ai-proxy.mobileconfig.tmpl`, `build.sh`)
- Build target: `make package-macos`
- CI workflow: `.github/workflows/release-macos-pkg.yml`
