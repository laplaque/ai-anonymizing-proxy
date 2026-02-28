# Configuration

Configuration is layered: **defaults → `proxy-config.json` → environment variables** (env vars win).

## proxy-config.json

Place this file in the working directory where the proxy runs (e.g. `/opt/ai-proxy/`).
The file is optional — all fields have built-in defaults. Unknown fields are silently ignored.

```json
{
  "proxyPort": 8080,
  "managementPort": 8081,
  "bindAddress": "127.0.0.1",
  "managementToken": "",
  "upstreamProxy": "",
  "ollamaEndpoint": "http://localhost:11434",
  "ollamaModel": "qwen2.5:3b",
  "useAIDetection": true,
  "aiConfidenceThreshold": 0.7,
  "ollamaMaxConcurrent": 1,
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

Environment variables override the corresponding `proxy-config.json` fields.

| Variable                  | Default                     | Description                                                          |
|---------------------------|-----------------------------|----------------------------------------------------------------------|
| `PROXY_PORT`              | `8080`                      | Proxy listener port                                                  |
| `MANAGEMENT_PORT`         | `8081`                      | Management API port                                                  |
| `BIND_ADDRESS`            | `127.0.0.1`                 | Proxy bind address (`0.0.0.0` = all interfaces)                      |
| `MANAGEMENT_TOKEN`        | —                           | Bearer token for management API (empty = no auth)                    |
| `UPSTREAM_PROXY`          | —                           | Upstream proxy URL for chaining (e.g. `http://corporate:8888`)       |
| `OLLAMA_ENDPOINT`         | `http://localhost:11434`    | Ollama server URL                                                    |
| `OLLAMA_MODEL`            | `qwen2.5:3b`                | Ollama model for PII detection                                       |
| `USE_AI_DETECTION`        | `true`                      | Set `false` to disable Ollama (regex only)                           |
| `AI_CONFIDENCE_THRESHOLD` | `0.7`                       | Minimum confidence for AI detections to be applied (0.0–1.0)         |
| `OLLAMA_MAX_CONCURRENT`   | `1`                         | Maximum concurrent Ollama queries (additional requests are dropped)  |
| `LOG_LEVEL`               | `info`                      | Log verbosity: `debug`, `info`, `warn`, `error`                      |
| `CA_CERT_FILE`            | `ca-cert.pem`               | Path to CA certificate for MITM TLS interception                     |
| `CA_KEY_FILE`             | `ca-key.pem`                | Path to CA private key for MITM TLS interception                     |

> **Important:** `HTTP_PROXY` / `HTTPS_PROXY` environment variables are **not** read by the proxy
> process for its own outbound connections. Use `UPSTREAM_PROXY` (or `upstreamProxy` in
> `proxy-config.json`) instead. This prevents the proxy from accidentally routing its own traffic
> back through itself when those shell variables are set for clients on the same machine.

## Confidence threshold and AI detection

The regex pass assigns a per-pattern confidence score. If any match falls below
`aiConfidenceThreshold` (or no regex match occurs at all), the text is also sent to Ollama for
context-aware PII detection. Setting `aiConfidenceThreshold` to `0.0` disables the Ollama
trigger (regex only). Setting it to `1.0` causes Ollama to run on virtually every request.

| Pattern type   | Confidence |
|----------------|------------|
| Email          | 0.95       |
| API key        | 0.90       |
| SSN            | 0.85       |
| Credit card    | 0.85       |
| IPv6 address   | 0.85       |
| Street address | 0.75       |
| IPv4 address   | 0.70       |
| Phone number   | 0.65       |
| ZIP code       | 0.40       |

## Token format

Detected PII is replaced with deterministic tokens of the form `[PII_<TYPE>_<8hex>]` —
e.g. `[PII_EMAIL_c160f8cc]`. The type label gives the LLM semantic context; the 8-hex suffix
is the first 8 characters of `md5(original_value)`. See [anonymizer.md](anonymizer.md) for
full details.

## Auth bypass

Requests to `authDomains` or paths matching `authPaths` are passed through without anonymization.
The proxy also bypasses authentication subdomains automatically: `auth.*`, `login.*`,
`accounts.*`, `sso.*`, `oauth.*`.

## Persisting runtime domain changes

Domain additions/removals made via the management API are written atomically to `ai-domains.json`
in the proxy's working directory. On startup, this file takes precedence over `aiApiDomains` in
`proxy-config.json`. If the file is missing or corrupt, the proxy falls back to the JSON config.

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
