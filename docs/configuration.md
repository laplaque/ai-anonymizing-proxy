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
    "api.huggingface.co",
    "*.openai.azure.com",
    "aiplatform.googleapis.com",
    "*-aiplatform.googleapis.com",
    "bedrock-runtime.*.amazonaws.com",
    "bedrock-agent-runtime.*.amazonaws.com"
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
  ],
  "enabledPacks": ["GLOBAL", "DE", "SECRETS"],
  "packDecayRate": 0.05,
  "maxRequestBodyBytes": 0,
  "requestSpoolDir": ""
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
| `ENABLED_PACKS`           | `GLOBAL,DE,SECRETS`         | Comma-separated list of enabled PII detection packs                  |
| `PACK_DECAY_RATE`         | `0.05`                      | Positional confidence decay rate per pack (0.0 = no decay)           |
| `MAX_REQUEST_BODY_BYTES`  | `0`                         | Optional cap on request body bytes received from the client; larger → HTTP 413 (0 = no limit; a value that is not an integer stops startup) |
| `REQUEST_SPOOL_DIR`       | OS temp dir                 | Directory for encrypted spool files of request bodies above 1 MiB    |

> **Important:** `HTTP_PROXY` / `HTTPS_PROXY` environment variables are **not** read by the proxy
> process for its own outbound connections. Use `UPSTREAM_PROXY` (or `upstreamProxy` in
> `proxy-config.json`) instead. This prevents the proxy from accidentally routing its own traffic
> back through itself when those shell variables are set for clients on the same machine.

## Request body size and resources

The proxy has **no built-in request-size cutoff**. Requests to AI API domains are anonymized as
a stream and forwarded complete, however large; the former hardcoded 50 MiB limit (which had no
workload rationale) is gone.

**Processing model.**

1. A body whose `Content-Type` declares JSON (`application/json` or `+json`, as the AI APIs
   use) is read through a 64 KiB buffer and rewritten JSON token by JSON token (see
   [Request body processing](anonymizer.md#request-body-processing)). Every string value is still
   anonymized; nothing is skipped because of size. If it is not valid JSON it is rejected (400).
   Any other body is read whole into memory and anonymized as before streaming: as JSON when it
   is valid JSON, otherwise as one piece of text. Its memory is therefore proportional to its
   size, as it was for every body before #152.
2. The **anonymized** output goes to a spool: the first 1 MiB stays in memory; larger bodies move
   to a temporary file in `requestSpoolDir`, encrypted with AES-256-CTR under a per-request key
   that exists only in process memory. The file is unlinked as soon as it is created on Linux and
   macOS (removed after forwarding on Windows). If a removal fails, the proxy logs the path,
   counts it in the `errors.spoolCleanup` metric, and retries it before later spool files are
   created and at shutdown; a file it still cannot remove stays named in the log. The raw,
   un-anonymized body is never written to disk.
3. The body is forwarded with an exact `Content-Length` (and a replayable body for transport
   retries), then the spool is released.

**Resources per in-flight request.**

| Resource | Bound |
|---|---|
| Memory | Two terms, both per in-flight request (see [Memory envelope](#memory-envelope) below). **Workspace:** ≈ 1 MiB spool buffer + 128 KiB I/O buffers + a multiple of the **largest single JSON string value**, which detection needs whole: measured ≈ 1.6× that string for base64 data and up to ≈ 8.5× for prose with PII matches and escapes (a 128 MiB prose string peaked at 981–1085 MiB). **Session mappings:** every distinct detected value and its token stay in memory until the response has been de-anonymized, however long the response takes: measured 110–140 bytes per distinct value (1M distinct addresses in one request held 133 MiB). Neither term grows with body size as such; the first grows with the largest string, the second with the number of distinct PII values. Bodies not declared as JSON are held whole (see Processing model). |
| Disk | The anonymized body size, for bodies over 1 MiB, until the request completes. |
| CPU | Regex detection dominates: about 4.3–4.8 MB/s with the GLOBAL pack and about 1.1–1.2 MB/s with the default packs (SECRETS, GLOBAL, DE) per request on one core, 0–10% slower than the previous implementation in the measurements below. Concurrent requests use separate cores. |

**Failures before forwarding are reported, never truncated: nothing reaches the upstream.** The
whole body is read and anonymized before the upstream request starts. A failure while the
anonymized body is being sent upstream (for example, the upstream connection drops) can still
leave the upstream with part of the anonymized body, as with any proxied upload; it is reported
to the client as an upstream error.

| Status | Cause |
|---|---|
| 413 Request Entity Too Large | The body exceeds the operator-set `maxRequestBodyBytes` (checked against `Content-Length` before reading, and while streaming bodies of unknown length). |
| 400 Bad Request | The client's body could not be read (for example, the client disconnected mid-upload, which cancels the request: reading and anonymization stop at the next read), or it is declared as JSON but is not valid JSON. |
| 507 Insufficient Storage | The proxy could not buffer the body: `requestSpoolDir` is missing, not writable, or full. |

<a id="memory-envelope"></a>**Memory envelope.** The proxy does not choose a memory budget for you, and running out of
memory terminates the process (it cannot answer 507 for that). Size `maxRequestBodyBytes` to the
memory you give the proxy and the number of requests you expect at once:

```text
peak memory ≈ concurrent requests × 8.5 × maxRequestBodyBytes        (worst case: one prose string)
```

Dense distinct PII stays below this: about 5× the body at peak (1M distinct addresses in a 33 MiB
body peaked at 159 MiB). The **reference envelope**, verified with
`BenchmarkFullContextEnvelope` (4 vCPU, GLOBAL pack, production build): **4 GiB, 4 concurrent
requests, `maxRequestBodyBytes` = 117440512 (112 MiB)**. Each scenario sends four requests of about
110 MiB at once, and all complete:

| Four concurrent requests of ≈ 110 MiB | Time | Peak RSS |
|---|---|---|
| one prose string with PII each (largest-string term) | 27.5 s | 2688 MiB |
| prose dense with distinct addresses, ≈ 3.3M per request (mapping term) | 41.7 s | 2805 MiB |
| mixed full context: tool history, prose, 8 MiB inline images | 28.4 s | 187 MiB |

Scale the limit with the formula for other budgets (for example 8 GiB and 4 requests: 224 MiB). With
no limit, a single prose string of size *S* needs about 8.5 × *S* of memory per request. Typical
full-context requests, where no single string is huge, use far less (the last row).

**Optional administrative limit.** `maxRequestBodyBytes` (`MAX_REQUEST_BODY_BYTES`) caps the
request body as received from the client: it counts input bytes, before anonymization (the
anonymized output can be slightly larger or smaller). `0`, the default, means no limit; a negative
value is treated as `0` with a warning. A value that is not an integer byte count (for example
`50MiB`, a fraction, or a number beyond 2^63−1) is a configuration error and the proxy refuses to
start, so a mistyped cap never leaves it silently unlimited. Use it to bound memory, disk and CPU
per request on shared hosts; it is never applied implicitly.

**Measured capacity.** Synthetic OpenAI-style requests: long prose, tool history and, above 16 MiB,
inline base64 images of 8 MiB each. One request at a time unless noted; 4 vCPU Linux, go1.27.2,
binaries compiled like `make build` (no race or coverage instrumentation, which slow detection
about 13×). Peak RSS is measured above the pre-request baseline. "Previous" is the
implementation before #152 on the same data.

| Request | Packs | Time | Peak RSS | Peak RSS (previous) |
|---|---|---|---|---|
| 4.4 MiB prose + tools (≈ 1M tokens) | GLOBAL | 1.1 s | 1.1 MiB | 41 MiB |
| 17.5 MiB prose + tools | GLOBAL | 4.1 s | 2.3 MiB | 187 MiB |
| 42.3 MiB with images | GLOBAL | 10.4 s | 44 MiB | 415 MiB |
| 67.1 MiB with images | GLOBAL | 15.3 s | 53 MiB | rejected (413) |
| 134 MiB with images | GLOBAL | 29.6 s | 43 MiB | rejected (413) |
| 268 MiB with images | GLOBAL | 60.0 s | 52 MiB | rejected (413) |
| 17.5 MiB prose + tools | default | 15.7 s | 1.6 MiB | 204 MiB |
| 42.3 MiB with images | default | 37.9 s | 48 MiB | 402 MiB |
| 67.1 MiB with images | default | 60.9 s | 56 MiB | rejected (413) |
| 8 × 17.5 MiB concurrently | GLOBAL | 9.6 s | 22 MiB | 1299 MiB |
| 4 × 67.1 MiB concurrently | GLOBAL | 18.5 s | 168 MiB | rejected (413) |
| one 16 MiB prose string with PII | GLOBAL | 4.3 s | 129 MiB | 108 MiB |
| one 64 MiB prose string with PII | GLOBAL | 14.8 s | 473 MiB | rejected (413) |
| one 128 MiB prose string with PII | GLOBAL | 28.2 s | 981 MiB | rejected (413) |
| one 16 MiB base64 string | GLOBAL | 3.3 s | 33 MiB | 62 MiB |
| one 128 MiB base64 string | GLOBAL | 25.5 s | 201 MiB | rejected (413) |
| 100 000 distinct addresses (3.3 MiB) | GLOBAL | 0.7 s | 18 MiB (10.4 MiB retained by the session map) | — |
| 1 000 000 distinct addresses (33 MiB) | GLOBAL | 7.5 s | 159 MiB (133 MiB retained) | — |
| 4 × 1 000 000 distinct addresses concurrently | GLOBAL | 12.2 s | 785 MiB (533 MiB retained) | — |

A single huge prose string costs slightly more than before (129 vs 108 MiB at 16 MiB) because
its original escaped bytes are kept so that an unchanged string can be forwarded byte for byte.

Reproduce with `go test -run '^$' -bench 'BenchmarkFullContext' -benchtime 1x ./internal/proxy/`
(one scenario per process for meaningful peak RSS); see `internal/proxy/fullcontext_bench_test.go`.
The session-map rows come from `BenchmarkFullContextHighCardinality` ("retained" is the heap the
maps still hold after the bodies were sent), the envelope from `BenchmarkFullContextEnvelope`.
The request paths beyond the former 50 MiB limit are verified byte for byte with the default packs
by `TestFullContextBeyondFormerLimitDefaultPacks`.

**Not covered here.** Compressed request bodies (`Content-Encoding: gzip`, `zstd`, …) are not
decoded by this path (#153): declared as JSON, they are not valid JSON and are rejected with 400;
otherwise they are anonymized as text, which can corrupt them.
Verifying compressed full-context requests end to end depends on that fix. Inline base64
inputs (images, files) are anonymized like any other string; with the default packs they pass
through unchanged, but some optional packs (e.g. FINANCE_EU, US, NL) can match short spans inside
base64 and corrupt the payload (#160). Response bodies are unchanged: SSE responses stream, other
responses are buffered for de-anonymization.

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

## Pack system

PII detection patterns are organized into **packs** in `internal/anonymizer/packs/`. Each pack
file self-registers its patterns via `init()`. The anonymizer loads only patterns from packs
listed in `enabledPacks`.

| Pack | Default | Content |
|---|---|---|
| GLOBAL | Enabled | Email, API key, credit card (Luhn validated) |
| DE | Enabled | Steuer-ID (ISO 7064), SVNR, KFZ plate |
| SECRETS | Enabled | SSH keys, JWT, bearer tokens, DB URIs, AWS/GitHub/GitLab/Slack/Stripe/NPM/PyPI/OpenAI/Docker/Google/Shopify/SendGrid/Groq/Twilio/Facebook/Amazon MWS/Cloudinary/PGP tokens |
| US | Available | Phone, SSN, ZIP, address, IPv4/IPv6 |
| FR | Available | NIR, SIRET, SIREN |
| NL | Available | BSN, KvK |
| FINANCE_EU | Available | IBAN, SWIFT/BIC, VAT IDs |
| HEALTHCARE | Available | MRN, ICD-10, insurance IDs |

The **positional decay multiplier** reduces confidence for patterns in later-listed packs:
```
effectiveConfidence = baseConfidence × (1.0 - (position - 1) × packDecayRate)
```

**Startup guard:** zero enabled packs is a fatal error.

## Token format

Detected PII is replaced with deterministic tokens of the form `[PII_<TYPE>_<16hex>]` —
e.g. `[PII_EMAIL_c160f8cc4b2e1a3d]`. The type label gives the LLM semantic context; the
16-hex suffix is the first 16 characters of `md5(original_value)`. Maximum token length:
33 bytes. See [anonymizer.md](anonymizer.md) for full details.

## AI API domain matching (segment-glob)

Entries in `aiApiDomains` are matched against the destination domain of every
CONNECT request. The registry supports two forms:

- **Exact match** — `api.openai.com` matches that one hostname.
- **Segment-glob** — `*` is a wildcard. Two flavors:
  - **Bare `*` segment** — matches exactly one DNS label of any value.
    `*.openai.azure.com` matches `myresource.openai.azure.com`. Segment count
    must match exactly; `evil.openai.azure.com.bad.com` does **not** match.
  - **Label-substring `*`** — a single `*` inside a segment matches any
    non-empty substring within that one label. `*-aiplatform.googleapis.com`
    matches `us-east4-aiplatform.googleapis.com`. Used for Vertex AI's
    regional URL form `{region}-aiplatform.googleapis.com`.

Exact matches take precedence over glob matches. Matching is case-insensitive
(per RFC 1035 §2.3.3) and a single trailing `.` on the inbound host is
stripped (RFC 1035 §3.1 canonical FQDN).

Patterns must be at least 3 segments, must not end in `*`, and must contain
at least one non-`*` segment in the leading positions. `*`, `*.com`, `*.*`,
`foo.*`, and `*.*.com` are all rejected at the management-API boundary to
prevent catch-all mis-classification.

### Default glob entries

| Pattern | Provider | Streaming format | Notes |
|---------|----------|------------------|-------|
| `*.openai.azure.com` | Azure OpenAI | OpenAI SSE | `{resource}.openai.azure.com` |
| `aiplatform.googleapis.com` | Vertex AI (global) | Gemini SSE | Exact match |
| `*-aiplatform.googleapis.com` | Vertex AI (regional) | Gemini SSE | `{region}-aiplatform.googleapis.com` — label-substring wildcard |
| `bedrock-runtime.*.amazonaws.com` | Amazon Bedrock | Passthrough | `bedrock-runtime.{region}.amazonaws.com` |
| `bedrock-agent-runtime.*.amazonaws.com` | Amazon Bedrock Agents | Passthrough | `bedrock-agent-runtime.{region}.amazonaws.com` |

**Bedrock uses passthrough deanonymization** (raw token replacement) rather
than a format-aware SSE parser because the SSE shape depends on the invoked
model (Anthropic models return Anthropic SSE; Meta/Mistral return
OpenAI-compatible SSE). Routing by domain alone can't pick the right parser,
so passthrough is the safe default.

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
