# AI Anonymizing Proxy

An HTTP forward proxy that intercepts requests to AI API providers and strips personally identifiable information (PII) from request bodies before forwarding them. Sits between your applications and AI APIs (OpenAI, Anthropic, Cohere, Mistral, etc.) to prevent sensitive data from leaking into LLM prompts.

## How It Works

```
Client ──► Proxy (:8080) ──► anonymize PII ──► AI API
                                  │
                           regex + Ollama
                           (two-stage detection)

Management API (:8081) ──► status, add/remove domains at runtime
```

**Traffic routing:**

| Request type | Behavior |
|---|---|
| HTTPS (CONNECT) | TCP tunnel, no inspection |
| HTTP to AI API domain | Body anonymized, then forwarded |
| HTTP to auth domain/path | Passed through unchanged |
| Everything else | Passed through unchanged |

**PII detection runs in two stages:**

1. **Regex pass** — fast, deterministic patterns for emails, phone numbers, SSNs, credit cards, IP addresses, API keys, street addresses, ZIP codes
2. **Ollama AI pass** — context-aware detection for names, job titles, medical info, salaries, company names (results cached by content hash)

Detected PII is replaced with deterministic anonymized tokens (e.g., `user<hash>@example.com`), so the same input always produces the same output.

## Prerequisites

- **Go 1.21+** — [go.dev/dl](https://go.dev/dl/)
- **Ollama** (optional, for AI-powered PII detection) — [ollama.com](https://ollama.com)

If Ollama is not running, the proxy falls back to regex-only detection.

## Building

### From source (all platforms)

```bash
git clone <repo-url>
cd ai-proxy
```

**Linux / macOS:**

```bash
make build
# Binary: bin/proxy
```

**Windows (PowerShell):**

```powershell
mkdir -Force bin
go build -ldflags="-s -w" -o bin/proxy.exe ./cmd/proxy
# Binary: bin\proxy.exe
```

**Cross-compile:**

```bash
# Linux from macOS/Windows
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/proxy-linux ./cmd/proxy

# Windows from macOS/Linux
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/proxy.exe ./cmd/proxy
```

## Configuration

Configuration is layered: **defaults → `proxy-config.json` → environment variables** (env vars win).

### proxy-config.json

Place this file in the working directory where the proxy runs:

```json
{
  "proxyPort": 8080,
  "managementPort": 8081,
  "ollamaEndpoint": "http://localhost:11434",
  "ollamaModel": "qwen2.5:3b",
  "useAIDetection": true,
  "aiConfidenceThreshold": 0.7,
  "logLevel": "info",
  "aiApiDomains": [
    "api.anthropic.com",
    "api.openai.com",
    "api.cohere.ai",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.together.xyz",
    "api.perplexity.ai",
    "api.replicate.com",
    "api.huggingface.co"
  ],
  "authDomains": [
    "accounts.google.com",
    "login.microsoftonline.com",
    "auth0.com",
    "okta.com"
  ],
  "authPaths": [
    "/auth", "/login", "/signin", "/signup", "/register",
    "/token", "/oauth", "/authenticate", "/session",
    "/v1/auth", "/api/auth", "/api/login", "/api/token"
  ]
}
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `PROXY_PORT` | `8080` | Proxy listener port |
| `MANAGEMENT_PORT` | `8081` | Management API port |
| `OLLAMA_ENDPOINT` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `qwen2.5:3b` | Ollama model for PII detection |
| `USE_AI_DETECTION` | `true` | Set `false` to disable Ollama (regex only) |
| `AI_CONFIDENCE_THRESHOLD` | `0.7` | Minimum confidence for AI detections (0.0–1.0) |
| `LOG_LEVEL` | `info` | Log verbosity |
| `HTTP_PROXY` / `HTTPS_PROXY` | — | Upstream proxy for chaining (e.g., corporate proxy) |

## Running

### Direct

**Linux / macOS:**

```bash
./bin/proxy
```

**Windows:**

```powershell
.\bin\proxy.exe
```

### Behind a corporate proxy

**Linux / macOS:**

```bash
HTTPS_PROXY=http://corporate-proxy:8888 ./bin/proxy
```

**Windows (PowerShell):**

```powershell
$env:HTTPS_PROXY = "http://corporate-proxy:8888"
.\bin\proxy.exe
```

### Custom ports

**Linux / macOS:**

```bash
PROXY_PORT=3128 MANAGEMENT_PORT=3129 ./bin/proxy
```

**Windows (PowerShell):**

```powershell
$env:PROXY_PORT = "3128"
$env:MANAGEMENT_PORT = "3129"
.\bin\proxy.exe
```

## Installing as a Service

### macOS (launchd)

```bash
# Install
sudo mkdir -p /opt/ai-proxy/logs
sudo cp bin/proxy /opt/ai-proxy/proxy
sudo cp proxy-config.json /opt/ai-proxy/proxy-config.json
sudo chown -R $USER /opt/ai-proxy
```

Create `~/Library/LaunchAgents/com.ai-proxy.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ai-proxy</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/ai-proxy/proxy</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/opt/ai-proxy</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/opt/ai-proxy/logs/proxy.out.log</string>
    <key>StandardErrorPath</key>
    <string>/opt/ai-proxy/logs/proxy.err.log</string>
</dict>
</plist>
```

```bash
launchctl load ~/Library/LaunchAgents/com.ai-proxy.plist

# Management
launchctl stop com.ai-proxy      # stop
launchctl start com.ai-proxy     # start
launchctl unload ~/Library/LaunchAgents/com.ai-proxy.plist  # disable
```

### Linux (systemd)

Create `/etc/systemd/system/ai-proxy.service`:

```ini
[Unit]
Description=AI Anonymizing Proxy
After=network.target

[Service]
Type=simple
ExecStart=/opt/ai-proxy/proxy
WorkingDirectory=/opt/ai-proxy
Restart=always
RestartSec=5
User=ai-proxy
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp bin/proxy /opt/ai-proxy/proxy
sudo cp proxy-config.json /opt/ai-proxy/proxy-config.json
sudo useradd -r -s /usr/sbin/nologin ai-proxy
sudo chown -R ai-proxy:ai-proxy /opt/ai-proxy

sudo systemctl daemon-reload
sudo systemctl enable --now ai-proxy

# Management
sudo systemctl status ai-proxy
sudo journalctl -u ai-proxy -f    # tail logs
```

### Windows (NSSM or Task Scheduler)

**Using NSSM (recommended):**

```powershell
# Install NSSM: https://nssm.cc or `choco install nssm`
nssm install ai-proxy C:\ai-proxy\proxy.exe
nssm set ai-proxy AppDirectory C:\ai-proxy
nssm set ai-proxy AppStdout C:\ai-proxy\logs\proxy.out.log
nssm set ai-proxy AppStderr C:\ai-proxy\logs\proxy.err.log
nssm start ai-proxy

# Management
nssm stop ai-proxy
nssm start ai-proxy
nssm remove ai-proxy confirm      # uninstall
```

**Using Task Scheduler (no extra tools):**

```powershell
$action = New-ScheduledTaskAction `
    -Execute "C:\ai-proxy\proxy.exe" `
    -WorkingDirectory "C:\ai-proxy"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Seconds 10)
Register-ScheduledTask -TaskName "ai-proxy" -Action $action -Trigger $trigger -Settings $settings

# Management
Stop-ScheduledTask -TaskName "ai-proxy"
Start-ScheduledTask -TaskName "ai-proxy"
Unregister-ScheduledTask -TaskName "ai-proxy" -Confirm:$false  # remove
```

## Configuring Clients

Point your applications at the proxy by setting environment variables or application-specific settings.

### Shell (Linux / macOS)

Add to `~/.bashrc`, `~/.zshrc`, or `~/.profile`:

```bash
export HTTP_PROXY="http://localhost:8080"
export HTTPS_PROXY="http://localhost:8080"
```

### PowerShell (Windows)

Add to your PowerShell profile (`$PROFILE`):

```powershell
$env:HTTP_PROXY = "http://localhost:8080"
$env:HTTPS_PROXY = "http://localhost:8080"
```

Or set system-wide via System Properties > Environment Variables.

### VSCode / VSCodium

Add to `settings.json`:

```json
{
  "http.proxy": "http://localhost:8080",
  "http.proxyStrictSSL": false
}
```

### Git

```bash
git config --global http.proxy http://localhost:8080
git config --global https.proxy http://localhost:8080
```

### Python (pip / requests)

```bash
pip install --proxy http://localhost:8080 <package>
```

Or in code:

```python
import os
os.environ["HTTP_PROXY"] = "http://localhost:8080"
os.environ["HTTPS_PROXY"] = "http://localhost:8080"
```

## Management API

The management API runs on port 8081 (configurable).

### Check status

```bash
curl http://localhost:8081/status
```

```json
{
  "status": "running",
  "uptime": "2m10s",
  "proxyPort": 8080,
  "aiApiDomains": ["api.openai.com", "api.anthropic.com", "..."],
  "ollama": {
    "endpoint": "http://localhost:11434",
    "model": "qwen2.5:3b",
    "enabled": true
  }
}
```

### Add an AI API domain at runtime

```bash
curl -X POST http://localhost:8081/domains/add \
  -H "Content-Type: application/json" \
  -d '{"domain":"api.newai.example.com"}'
```

### Remove an AI API domain

```bash
curl -X POST http://localhost:8081/domains/remove \
  -H "Content-Type: application/json" \
  -d '{"domain":"api.newai.example.com"}'
```

## Monitoring

### macOS

```bash
tail -f /opt/ai-proxy/logs/proxy.err.log
launchctl list | grep ai-proxy
```

### Linux

```bash
journalctl -u ai-proxy -f
systemctl status ai-proxy
```

### Windows

```powershell
Get-Content C:\ai-proxy\logs\proxy.err.log -Wait
nssm status ai-proxy
```

## Limitations

- **HTTPS traffic is opaque.** CONNECT tunnels are passed through without inspection. The proxy only anonymizes plain HTTP request bodies. Most AI APIs use HTTPS, so requests over HTTPS are tunneled but not anonymized.
- **No TLS termination (MITM).** The proxy does not decrypt HTTPS traffic. To anonymize HTTPS bodies, you would need to add MITM TLS termination with a custom CA certificate trusted by clients.
- **Ollama cache is unbounded.** The in-memory AI detection cache grows without limit. Restart the proxy to clear it.
- **Management API has no authentication.** Anyone who can reach port 8081 can add or remove domains. Bind it to localhost or use firewall rules in production.

## Project Structure

```
ai-proxy/
├── cmd/proxy/main.go              # Entry point
├── internal/
│   ├── anonymizer/anonymizer.go   # PII detection (regex + Ollama)
│   ├── config/config.go           # Configuration loading
│   ├── management/management.go   # Runtime management API
│   └── proxy/proxy.go             # Core HTTP proxy
├── proxy-config.json              # Default configuration
├── Makefile                       # Build targets (Linux/macOS)
└── go.mod
```

## License

MIT
