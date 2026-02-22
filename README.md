# AI Anonymizing Proxy

An HTTP/HTTPS forward proxy that intercepts requests to AI API providers and strips personally
identifiable information (PII) from request bodies before forwarding them. Sits between your
applications and AI APIs (OpenAI, Anthropic, Cohere, Mistral, etc.) to prevent sensitive data
from leaking into LLM prompts.

Supports **MITM TLS termination** for HTTPS traffic — the proxy decrypts, anonymizes, and
re-encrypts requests to AI API domains using a local CA certificate. Non-AI traffic is tunneled
transparently.

## How It Works

```text
Client ──TLS (proxy CA)──► Proxy (:8080) ──► anonymize PII ──TLS (real cert)──► AI API
                                                   │
                                            regex + Ollama
                                            (two-stage detection)

Management API (:8081) ──► status, add/remove domains at runtime
```

**Traffic routing:**

| Request type                   | Behavior                                                                   |
|--------------------------------|----------------------------------------------------------------------------|
| HTTPS CONNECT to AI API domain | MITM TLS intercept — body anonymized, then forwarded (requires trusted CA) |
| HTTPS CONNECT to other domains | TCP tunnel, no inspection (private IPs blocked)                            |
| HTTP to AI API domain          | Body anonymized, then forwarded                                            |
| HTTP to auth domain/path       | Passed through unchanged                                                   |
| Everything else                | Passed through unchanged                                                   |

**PII detection runs in two stages:**

1. **Regex pass** — fast, deterministic patterns for emails, phone numbers, SSNs, credit cards,
   IP addresses, API keys, street addresses, ZIP codes
2. **Ollama AI pass** (async best-effort) — context-aware detection for names, job titles,
   medical info, salaries, company names. On cache miss the regex-only result is returned
   immediately while Ollama runs in the background; on the next identical request the cached AI
   detections are applied.

Detected PII is replaced with deterministic anonymized tokens (e.g. `user<hash>@example.com`),
so the same input always produces the same output.

## Prerequisites

- **Go 1.24+** — [go.dev/dl](https://go.dev/dl/)
- **Ollama** (optional, for AI-powered PII detection) — [ollama.com](https://ollama.com)

If Ollama is not running, the proxy falls back to regex-only detection.

## Quick Start

```bash
make build
./bin/proxy
```

The proxy listens on `:8080` (proxy) and `10.0.0.52:8081` (management API). On first run it
auto-generates `ca-cert.pem` and `ca-key.pem` in the working directory.

Point clients at `http://localhost:8080` and trust `ca-cert.pem` for HTTPS interception.
See [docs/client-setup.md](docs/client-setup.md) for per-tool instructions.

## Documentation

| Topic | File |
| ----- | ---- |
| Configuration reference (env vars, proxy-config.json, upstream proxy) | [docs/configuration.md](docs/configuration.md) |
| Installing as a service (launchd, systemd, Windows) + log rotation | [docs/installation.md](docs/installation.md) |
| HTTPS/MITM TLS interception and CA trust setup | [docs/tls-mitm.md](docs/tls-mitm.md) |
| Configuring clients (shell, VSCode, Git, Python, Node.js) | [docs/client-setup.md](docs/client-setup.md) |
| Management API reference | [docs/management-api.md](docs/management-api.md) |
| Building, linting, testing, CI/CD | [docs/development.md](docs/development.md) |

## Monitoring

**macOS:**

```bash
tail -f /opt/ai-proxy/logs/proxy.err.log
launchctl list | grep ai-proxy
```

**Linux:**

```bash
journalctl -u ai-proxy -f
systemctl status ai-proxy
```

**Windows:**

```powershell
Get-Content C:\ai-proxy\logs\proxy.err.log -Wait
nssm status ai-proxy
```

## Security

- **SSRF protection.** CONNECT tunnels and plain-HTTP forwarding block destinations that resolve
  to private/loopback/link-local IP ranges (`10.0.0.50/8`, `10.0.0.52/12`, `10.0.0.52/16`,
  `10.0.0.49/8`, `10.0.0.53/16`, `::1`, `fc00::/7`, `fe80::/10`). IP addresses are checked at
  TCP connection time, not DNS resolution time, to prevent DNS rebinding attacks.
- **Isolated outbound transport.** The proxy transport never reads `HTTP_PROXY` / `HTTPS_PROXY`
  from the environment; upstream proxy chaining is configured explicitly via `UPSTREAM_PROXY`.
- **Request body limits.** Anonymization reads at most 50 MB per request body. Ollama response
  reads are capped at 10 MB.
- **Error sanitization.** Upstream errors are logged server-side but never exposed to clients
  (all proxy error responses return generic messages).

## Known Limitations

- **Clients must trust the proxy CA.** HTTPS interception only works if the client trusts the
  proxy's CA certificate. Without it, clients will see TLS certificate errors.
- **Ollama cache is unbounded.** The in-memory AI detection cache grows without limit. Restart
  the proxy to clear it.
- **Management API authentication is optional.** Set `MANAGEMENT_TOKEN` to require bearer token
  auth. Without it, anyone with network access to port 8081 can add or remove domains.

## License

MIT
