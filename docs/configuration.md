# Configuration

Configuration is layered: **defaults → `proxy-config.json` → environment variables** (env vars win).

## proxy-config.json

Place this file in the working directory where the proxy runs (e.g. `/opt/ai-proxy/`):

```json
{
  "proxyPort": 8080,
  "managementPort": 8081,
  "bindAddress": "0.0.0.0",
  "managementToken": "",
  "upstreamProxy": "",
  "ollamaEndpoint": "http://localhost:11434",
  "ollamaModel": "qwen2.5:3b",
  "useAIDetection": true,
  "aiConfidenceThreshold": 0.7,
  "logLevel": "info",
  "caCertFile": "ca-cert.pem",
  "caKeyFile": "ca-key.pem",
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

## Environment variables

| Variable                  | Default                     | Description                                                        |
|---------------------------|-----------------------------|--------------------------------------------------------------------|
| `PROXY_PORT`              | `8080`                      | Proxy listener port                                                |
| `MANAGEMENT_PORT`         | `8081`                      | Management API port                                                |
| `BIND_ADDRESS`            | `0.0.0.0`                   | Proxy bind address (`0.0.0.0` = all interfaces)                    |
| `MANAGEMENT_TOKEN`        | —                           | Bearer token for management API (empty = no auth)                  |
| `UPSTREAM_PROXY`          | —                           | Upstream proxy URL for chaining (e.g. `http://corporate:8888`)     |
| `OLLAMA_ENDPOINT`         | `http://localhost:11434`    | Ollama server URL                                                  |
| `OLLAMA_MODEL`            | `qwen2.5:3b`                | Ollama model for PII detection                                     |
| `USE_AI_DETECTION`        | `true`                      | Set `false` to disable Ollama (regex only)                         |
| `AI_CONFIDENCE_THRESHOLD` | `0.7`                       | Minimum confidence for AI detections (0.0–1.0)                     |
| `LOG_LEVEL`               | `info`                      | Log verbosity                                                      |
| `CA_CERT_FILE`            | `ca-cert.pem`               | Path to CA certificate for MITM TLS interception                   |
| `CA_KEY_FILE`             | `ca-key.pem`                | Path to CA private key for MITM TLS interception                   |

> **Important:** `HTTP_PROXY` / `HTTPS_PROXY` environment variables are **not** read by the proxy
> process for its own outbound connections. Use `UPSTREAM_PROXY` (or `upstreamProxy` in
> `proxy-config.json`) instead. This prevents the proxy from accidentally routing its own traffic
> back through itself when those shell variables are set for clients on the same machine.

## Behind a corporate proxy

Set `UPSTREAM_PROXY` (or `upstreamProxy` in `proxy-config.json`) to chain outbound connections
through a corporate proxy:

**Linux / macOS:**

```bash
UPSTREAM_PROXY=http://corporate-proxy:8888 ./bin/proxy
```

**Windows (PowerShell):**

```powershell
$env:UPSTREAM_PROXY = "http://corporate-proxy:8888"
.\bin\proxy.exe
```

Or permanently in `proxy-config.json`:

```json
{
  "upstreamProxy": "http://corporate-proxy:8888"
}
```
