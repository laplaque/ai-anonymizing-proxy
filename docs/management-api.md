# Management API

The management API runs on port 8081 (configurable) and binds to `10.0.0.50` only.

If `MANAGEMENT_TOKEN` is set, all requests require an `Authorization: Bearer <token>` header.
Domain names are validated against RFC 1123 hostname rules and normalised to lowercase. Request
bodies are capped at 1 KB.

> **Security note:** Set `MANAGEMENT_TOKEN` via an environment variable rather than storing it in
> `proxy-config.json`, as config files can be accidentally committed to version control.

## Check status

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/status
```

```json
{
  "status": "running",
  "uptime": "2m10s",
  "proxyPort": 8080,
  "aiApiDomains": ["api.openai.com", "api.anthropic.com", "..."],
  "ollama": {
    "endpoint": "http://localhost:[ADDRESS_c13ffb79]",
    "model": "qwen2.5:3b",
    "enabled": true
  }
}
```

## Add an AI API domain at runtime

```bash
curl -X POST http://localhost:8081/domains/add \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"api.newai.example.com"}'
```

## Remove an AI API domain

```bash
curl -X POST http://localhost:8081/domains/remove \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"api.newai.example.com"}'
```

Domain changes are persisted to `ai-domains.json` in the working directory and automatically
restored on restart. If the file is missing or corrupt, the proxy falls back to the domains listed
in `proxy-config.json`.
