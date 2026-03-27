# Anonymization Pipeline

This document describes how the proxy detects, replaces, and later reverses PII in requests and
responses: the two-stage detection pipeline, token format, session lifecycle, Ollama async cache,
and the streaming deanonymization strategy.

## Overview

```
Request body
    │
    ├─ 1. Regex pass          fast, structured patterns, per-pattern confidence
    │       │
    │       └─ low confidence ─► 2. Ollama cache lookup  (async, never blocks request)
    │
    ├─ 3. Session map write   token → original, ephemeral, deleted after response
    │
    └─► Anonymized body sent to LLM API

Response body
    │
    ├─ 4. Session map lookup  token → original (streaming or buffered)
    │
    └─► Restored body returned to client
```

The Ollama sidecar is **never on the critical path**. It populates a persistent cache
asynchronously; the request is always returned immediately with whatever tokens are available.

---

## Stage 1 — Regex detection

Eight compiled patterns cover the most common structured PII types. Each carries a confidence
score that reflects its false-positive risk:

| PII type       | Token prefix    | Example match              | Confidence |
|----------------|-----------------|----------------------------|------------|
| Email          | `EMAIL`         | `user@example.com`         | 0.95       |
| API key        | `APIKEY`        | `Bearer sk-abc…` (≥20 ch)  | 0.90       |
| SSN            | `SSN`           | `123-45-6789`              | 0.85       |
| Credit card    | `CREDITCARD`    | `4111 1111 1111 1111`      | 0.85       |
| IPv6 address   | `IPADDRESS`     | `::1`, `2001:db8::1`       | 0.85       |
| Street address | `ADDRESS`       | `123 Main Street`          | 0.75       |
| IPv4 address   | `IPADDRESS`     | `192.168.1.1`              | 0.70       |
| Phone number   | `PHONE`         | `+1-555-123-4567`          | 0.65       |
| ZIP code       | `ADDRESS`       | `90210`                    | 0.40       |

If a match's confidence is **at or above** `aiConfidenceThreshold` (default `0.80`), the token
is applied immediately. If it falls below the threshold, Stage 2 runs.

---

## Stage 2 — Ollama async cache

For low-confidence matches the proxy consults a persistent per-value cache keyed by the original
PII string. The cache is populated by background Ollama goroutines that run outside the request
cycle.

```mermaid
stateDiagram-v2
    [*] --> Uncached : new PII value

    Uncached --> Inflight : cache miss\nfallback token applied immediately\nasync Ollama goroutine dispatched

    Inflight --> Inflight : duplicate request for same value\nin-flight dedup — no second goroutine\nfallback token applied to current request

    Inflight --> Cached : Ollama query succeeded\nresult stored in bbolt

    Inflight --> Uncached : Ollama query failed or semaphore full\nnext request retries dispatch

    Cached --> Cached : cache hit\ncached token applied immediately

    note right of Cached
        S3-FIFO eviction at 50 000 entries.
        Evicted entries deleted from bbolt
        so disk usage stays bounded.
    end note
```

**Key properties:**

- A cache miss **never leaves PII unmasked** — the fallback token is applied immediately and the
  miss is logged.
- The in-flight deduplication map prevents multiple goroutines querying Ollama for the same
  value concurrently.
- The Ollama semaphore (`ollamaMaxConcurrent`, default 1) caps concurrent queries; excess
  goroutines are dropped and retried on the next request.

---

## Token format

All tokens use the format:

```
[PII_<TYPE>_<8hex>]
```

For example: `[PII_EMAIL_c160f8cc]`, `[PII_PHONE_7f4e1b02]`, `[PII_IPADDRESS_5d8c3f1a]`.

- `<TYPE>` is the uppercased PII type name, giving the LLM semantic context without revealing the
  original value.
- `<8hex>` is the first 8 hex characters of `md5(original_value)` — deterministic, so the same
  value always produces the same token within and across sessions.
- The bracket notation is chosen to satisfy the **non-retriggering invariant**: no token matches
  any of the eight compiled regex patterns. A violation here would cause the proxy to tokenize
  its own output in future sessions ("proxy eats itself"). `TestTokenFormatNonRetriggering`
  enforces this property on every CI run.

A system instruction is injected into every anonymized request instructing the LLM to reproduce
tokens exactly as written. The type label in the token gives the model enough context to reason
correctly about the surrounding sentence structure.

---

## Session map lifecycle

Each request receives a unique `sessionID` (random UUID). The token → original mapping is stored
in `anonymizer.sessions[sessionID]` and deleted immediately after the response is delivered.

```mermaid
sequenceDiagram
    participant P as proxy.go
    participant A as anonymizer.go
    participant API as LLM API

    P->>A: AnonymizeJSON(body, sessionID)
    Note over A: regex + cache → token map populated
    A-->>P: anonymized body

    P->>API: POST (anonymized)
    API-->>P: response

    alt streaming (SSE)
        P->>A: StreamingDeanonymize(body, sessionID)
        Note over A: snapshot token map under read lock
        A-->>P: io.ReadCloser (tokens replaced on-the-fly)
    else buffered
        P->>A: DeanonymizeText(body, sessionID)
        A-->>P: restored text
    end

    P->>A: DeleteSession(sessionID)
    Note over A: token map freed
```

The token map snapshot in `StreamingDeanonymize` is taken under a read lock before the goroutine
starts, so a `DeleteSession` call that races with streaming cannot cause missed replacements.

---

## Streaming deanonymization

The Anthropic API delivers one or two characters per `text_delta` SSE event, meaning a single
token like `[PII_EMAIL_c160f8cc]` frequently arrives split across multiple events:

```
{"type":"text_delta","text":"[PII_EMA"}
{"type":"text_delta","text":"IL_c160f8cc]"}
```

Raw byte replacement cannot match tokens split this way. `StreamingDeanonymize` delegates to a
pipeline of small helper functions (in `streaming.go`) that each handle one concern:

1. **Line assembly** (`readLoop` → `assembleLines`) — reads raw bytes from the source, splits
   on newlines, strips `\r`, and dispatches complete lines.
2. **Line classification** (`processLine`) — routes each SSE line: comments and empty lines
   pass through verbatim; non-`data:` lines go through the replacer; `data:` lines are parsed
   as JSON.
3. **Text accumulation** (`processTextDelta`) — accumulates text across consecutive
   `content_block_delta` / `text_delta` **and** `thinking_delta` events, tracks the content
   block index, and flushes safe prefixes.
4. **Safe flush boundary** (`safeCutPoint`) — calculates how many accumulated bytes can be
   flushed without splitting a partial token. A `tokenSuffixLen` of 26 bytes is retained in
   the accumulator — enough to cover the longest possible token
   (`[PII_CREDITCARD_XXXXXXXX]` = 25 chars).
5. **Remainder flush** (`flushRemainder`) — when a non-text-delta event arrives or the stream
   ends, any text still in the accumulator is emitted as a synthetic `content_block_delta`
   targeting the correct content block index.
6. **Stream end** (`handleStreamEnd`) — flushes partial lines and accumulated text at EOF or on
   read error.

A `streamContext` struct holds the shared mutable state for a single invocation: the pipe
writer, replacer, text accumulator, last-seen content block index, and logging configuration.
The replacer is applied on **all** passthrough paths (non-JSON lines, non-delta events, etc.)
so tokens embedded anywhere in the SSE stream are deanonymized.

---

## Persistent cache — bbolt + S3-FIFO

The Ollama value cache uses a two-layer design:

| Layer     | Implementation     | Purpose                                              |
|-----------|--------------------|------------------------------------------------------|
| Hot layer | S3-FIFO (memory)   | Serves cache hits in nanoseconds; bounded capacity   |
| Cold layer| bbolt (disk)       | Survives process restarts; source of truth           |

**S3-FIFO** (Yang et al., 2023) uses two FIFO queues — S (10% of capacity, probationary) and
M (90%, protected) — plus a ghost set that tracks recently evicted S keys. A new key enters S;
if accessed while in S it is promoted to M on eviction; if it was in the ghost set it goes
directly to M. This makes the cache scan-resistant without LRU's lock contention.

On eviction from either queue, the entry is also deleted from bbolt, keeping disk usage bounded
to approximately `cacheCapacity` entries (default 50 000).

On a cold read (memory miss, bbolt hit), the entry is re-warmed into the S3-FIFO layer.

---

## Observability

### Logs

Every low-confidence cache miss emits a structured log line:

```
[ANONYMIZER] low-confidence cache miss piiType=phone
```

This is the primary signal that a value is on the weak path. A steady stream of misses for a
given type means either Ollama has not yet warmed the cache for those values (expected at cold
start) or the values change frequently enough that cache entries expire before reuse.

Ollama dispatch outcomes are also logged:

```
[ANONYMIZER] Ollama busy, skipping background query for value
[ANONYMIZER] async Ollama query failed: <error>
[ANONYMIZER] async Ollama cache populated for N value(s)
```

### Metrics (`GET /metrics` → `piiTokens`)

All anonymizer counters are exposed under the `piiTokens` key in the management API metrics
endpoint. They reset on proxy restart.

| Field | Description |
|-------|-------------|
| `replaced` | Total PII tokens inserted across all requests |
| `deanonymized` | Total tokens reversed in responses |
| `cacheHits` | Per-PIIType count of low-confidence matches served from cache. Only types with at least one hit appear. |
| `cacheMisses` | Per-PIIType count of low-confidence cache misses. Each miss also increments `cacheFallbacks`. |
| `ollamaDispatches` | Background Ollama goroutines dispatched (counted before the goroutine starts) |
| `ollamaErrors` | Ollama queries that failed — includes both semaphore-full drops and HTTP/parse errors |
| `cacheFallbacks` | Times a deterministic fallback token was applied on a low-confidence miss |

**Reading cache effectiveness:** `cacheFallbacks / ollamaDispatches` trending toward 0 after
warm-up means the cache is working — recurring values get hits and Ollama is no longer needed
for them. A ratio near 1 after warm-up indicates either Ollama is unreachable, values are
high-cardinality (each occurrence is unique), or `aiConfidenceThreshold` is set too low and is
routing too many patterns through the cache path.

**Per-type breakdown** lets you identify which PII categories generate the most cache pressure.
High miss rates for `phone` or `ipAddress` (lower-confidence patterns) are expected; high miss
rates for `ssn` or `creditCard` (higher-confidence patterns) suggest those patterns are being
triggered by non-PII data and worth investigating with `LOG_LEVEL=debug`.

---

## EU locale packs — DE and FR

The pack system extends PII detection with locale-specific patterns. Each pack self-registers
via `init()` and is loaded when listed in `enabledPacks`. Patterns with a `Validate` function
use checksum algorithms to reject false positives before tokenization.

### DE pack — Germany

| Pattern | PII type | Regex | Checksum | Confidence | Source |
|---------|----------|-------|----------|------------|--------|
| `steuer_id` | `STEUERID` | `\b[1-9]\d{10}\b` | ISO 7064 MOD 11,10 — iterative product algorithm; last digit is check digit | 0.70 | [Wikipedia: Steuerliche Identifikationsnummer](https://de.wikipedia.org/wiki/Steuerliche_Identifikationsnummer) |
| `svnr` | `SVNR` | `\b\d{2}(?:0[1-9]\|[12]\d\|3[01])(?:0[1-9]\|1[0-2])\d{2}[A-Za-z]\d{3}\b` | None (structural constraints on DOB component) | 0.80 | [Wikipedia: Sozialversicherungsnummer](https://de.wikipedia.org/wiki/Sozialversicherungsnummer); silv3rshi3ld/gdpr-pii-scanner |
| `kfz` | `KFZ` | `\b[A-ZÄÖÜ]{1,3}[\s\-][A-Z]{1,2}[\s\-]?\d{1,4}\b` | None (strict format with separator) | 0.75 | [Wikipedia: Kfz-Kennzeichen](https://de.wikipedia.org/wiki/Kfz-Kennzeichen_(Deutschland)); mnestorov/regex-patterns |

**False-positive mitigation (DE):**

- **Steuer-ID:** The ISO 7064 MOD 11,10 check digit rejects ~90% of random 11-digit sequences.
  The first digit must be non-zero, further constraining the match space.
- **SVNR:** The embedded DDMMYY birthday component constrains day (01–31) and month (01–12)
  ranges. The mandatory letter separator between the date and sequence number is structurally
  uncommon in non-PII text.
- **KFZ:** The district code (1–3 uppercase letters including umlauts) followed by a mandatory
  separator (space or hyphen) and then letters + digits creates a distinctive format unlikely to
  appear in prose.

### FR pack — France

| Pattern | PII type | Regex | Checksum | Confidence | Source |
|---------|----------|-------|----------|------------|--------|
| `nir` | `NIR` | `\b[12][\s-]?\d{2}[\s-]?(?:0[1-9]\|1[0-2])[\s-]?(?:\d{2}\|2[AB])[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{2}\b` | `97 - (base % 97) == key`; Corsica: 2A→19, 2B→18 before modulus | 0.80 | [Wikipedia: Numéro de sécurité sociale en France](https://fr.wikipedia.org/wiki/Num%C3%A9ro_de_s%C3%A9curit%C3%A9_sociale_en_France); silv3rshi3ld/gdpr-pii-scanner |
| `siret` | `SIRET` | `\b\d{3}[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{5}\b` | Luhn algorithm (ISO/IEC 7812-1) | 0.75 | [Wikipedia: SIRET](https://fr.wikipedia.org/wiki/Syst%C3%A8me_d%27identification_du_r%C3%A9pertoire_des_%C3%A9tablissements); mnestorov/regex-patterns |
| `siren` | `SIREN` | `\b\d{3}[\s-]?\d{3}[\s-]?\d{3}\b` | Luhn algorithm (ISO/IEC 7812-1) | 0.60 | [Wikipedia: SIREN](https://fr.wikipedia.org/wiki/Syst%C3%A8me_d%27identification_du_r%C3%A9pertoire_des_entreprises); mnestorov/regex-patterns |

**False-positive mitigation (FR):**

- **NIR:** The modulus 97 checksum (`key = 97 - (first 13 digits % 97)`) rejects ~99% of
  random 15-digit sequences. The first digit is constrained to 1 (male) or 2 (female), and the
  month field is constrained to 01–12. Corsica departments (2A, 2B) are handled by substituting
  19 and 18 respectively before computing the modulus. The regex allows optional spaces/hyphens
  between groups to match conventionally formatted NIRs (e.g. `1 85 01 75 012 345 55`).
- **SIRET:** The Luhn checksum rejects ~90% of random 14-digit sequences. The regex matches
  the conventional 3+3+3+5 spaced grouping (e.g. `362 521 874 00036`). The validator strips
  whitespace before verifying exactly 14 digits pass Luhn.
- **SIREN:** The Luhn checksum rejects ~90% of random 9-digit sequences, filtering out
  coincidental matches (phone fragments, ZIP+4 codes). The regex matches the conventional
  3+3+3 spaced grouping (e.g. `362 521 874`). The moderate confidence (0.60) routes remaining
  ambiguous matches through AI verification.

---

## GDPR notes

- PII values are stored in the bbolt cache **only for low-confidence Ollama detections**. Values
  anonymized by the high-confidence regex path do not touch the cache.
- Token → original session maps are in-process memory only and are deleted after each request.
- Setting `USE_AI_DETECTION=false` disables the Ollama path entirely; the bbolt cache is never
  written to.
- The bbolt file path is configured via `CACHE_PATH` (or `cachePath` in `proxy-config.json`). If
  not set, an in-memory cache is used — no PII values persist to disk at all.
