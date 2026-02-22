# Configuring Clients

Point your applications at the proxy by setting environment variables or application-specific
proxy settings. Replace `localhost` with the proxy's host if it runs on a different machine.

## Shell (Linux / macOS)

Add to `~/.bashrc`, `~/.zshrc`, or `~/.profile`:

```bash
export HTTP_PROXY="http://localhost:8080"
export HTTPS_PROXY="http://localhost:8080"
export NODE_EXTRA_CA_CERTS=/opt/ai-proxy/ca-cert.pem   # Node.js CA trust
```

> If a GUI application (e.g. VSCodium/VSCode) launches the proxy as a launchd agent on the same
> machine, also clear these variables in the plist's `EnvironmentVariables` dict so the proxy
> process itself does not inherit them. See [installation.md](installation.md).

## PowerShell (Windows)

Add to your PowerShell profile (`$PROFILE`):

```powershell
$env:HTTP_PROXY = "http://localhost:8080"
$env:HTTPS_PROXY = "http://localhost:8080"
```

Or set system-wide via System Properties > Environment Variables.

## VSCode / VSCodium

Add to `settings.json`:

```json
{
  "http.proxy": "http://localhost:8080"
}
```

> **Note:** `http.proxyStrictSSL` is intentionally omitted. If you enabled MITM TLS interception,
> trust the proxy CA certificate in your OS keychain instead of disabling SSL validation globally
> (disabling it would suppress TLS errors for all VSCode traffic, not just proxy connections).
> See [tls-mitm.md](tls-mitm.md) for per-platform CA trust instructions.

To make sure extensions running in the integrated terminal also use the proxy, add:

```json
{
  "terminal.integrated.env.osx": {
    "HTTP_PROXY": "http://localhost:8080",
    "HTTPS_PROXY": "http://localhost:8080"
  }
}
```

## Git

```bash
git config --global http.proxy http://localhost:8080
git config --global https.proxy http://localhost:8080
```

## Python (pip / requests)

```bash
pip install --proxy http://localhost:8080 <package>
```

Or in code:

```python
import os
os.environ["HTTP_PROXY"] = "http://localhost:8080"
os.environ["HTTPS_PROXY"] = "http://localhost:8080"
```
