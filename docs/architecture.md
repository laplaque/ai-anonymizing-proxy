# Architecture

This document describes the internal design of the AI Anonymizing Proxy: how requests flow
through the system, how PII detection works, and the rationale behind key design choices.

## System overview

```mermaid
flowchart TD
    subgraph Client side
        APP[Application]
    end

    subgraph Proxy ["AI Anonymizing Proxy (127.0.0.1:8080)"]
        direction TB
        PRXY[proxy.go\nrequest router]
        ANON[anonymizer.go\ntwo-stage PII detection]
        MITM[mitm/\ncert.go · mitm.go]
        REG[(DomainRegistry)]
        MET[metrics.go]
    end

    subgraph Mgmt ["Management API (127.0.0.1:8081)"]
        API[management.go\n/status /metrics /domains]
    end

    subgraph Backends
        AIAPI[AI API\nOpenAI · Anthropic · …]
        OTHER[Other HTTPS]
        OLL[Ollama\nlocal LLM]
    end

    APP -->|HTTP_PROXY| PRXY
    PRXY -->|AI domain| MITM
    MITM -->|plaintext body| ANON
    ANON -->|async cache miss| OLL
    ANON -->|anonymized body| AIAPI
    AIAPI -->|response| ANON
    ANON -->|de-anonymized| APP

    PRXY -->|other domain| OTHER
    API -->|read/write| REG
    PRXY -->|lookup| REG
    PRXY --> MET
    ANON --> MET
```

## Request lifecycle

### HTTPS CONNECT to an AI API domain (MITM path)

```mermaid
sequenceDiagram
    participant C as Client
    participant P as proxy.go
    participant CA as mitm/cert.go
    participant A as anonymizer.go
    participant API as AI API

    C->>P: CONNECT api.openai.com:443
    P->>P: DomainRegistry.Has(domain) → true
    P->>C: 200 Connection Established
    P->>CA: CertFor("api.openai.com")
    CA-->>P: leaf cert signed by proxy CA
    Note over C,P: TLS handshake — client uses proxy CA cert
    Note over P,API: Proxy opens separate real TLS to ai api

    loop each request over the tunnel
        C->>P: POST /v1/messages (plaintext to proxy)
        P->>P: isAuthRequest? → No
        P->>A: AnonymizeJSON(body, sessionID)
        A-->>P: anonymized body + token map stored
        P->>API: POST /v1/messages (anonymized, real TLS)
        API-->>P: response
        alt SSE / text/event-stream
            P->>A: StreamingDeanonymize(body, sessionID)
            A-->>C: token replacements streamed on-the-fly
        else buffered response
            P->>A: DeanonymizeText(body, sessionID)
            A-->>P: restored text
            P-->>C: response with original values
        end
        P->>A: DeleteSession(sessionID)
    end
```

### HTTPS CONNECT to a non-AI domain (opaque tunnel)

```mermaid
sequenceDiagram
    participant C as Client
    participant P as proxy.go
    participant D as ssrfSafeDialContext
    participant S as Destination server

    C->>P: CONNECT other-site.com:443
    P->>P: DomainRegistry.Has → false
    P->>P: isPrivateHost? → No
    P->>D: Dial tcp other-site.com:443
    D->>D: Resolve hostname → check IPs against private CIDRs
    D-->>P: net.Conn (or blocked if private IP)
    P->>C: 200 Connection Established
    Note over C,S: Raw bytes copied bidirectionally — no inspection
```

### Plain HTTP to an AI API domain

```mermaid
sequenceDiagram
    participant C as Client
    participant P as proxy.go
    participant A as anonymizer.go
    participant API as AI API

    C->>P: POST http://api.openai.com/v1/chat (plain HTTP)
    P->>P: isAuthRequest? → No
    P->>A: AnonymizeJSON(body, sessionID)
    A-->>P: anonymized body
    P->>API: POST (anonymized)
    API-->>P: response
    P->>A: DeanonymizeText(response, sessionID)
    A-->>P: restored response
    P-->>C: response
    P->>A: DeleteSession(sessionID)
```

## Anonymization pipeline

```mermaid
flowchart TD
    IN([Request body]) --> PARSE{Valid JSON?}
    PARSE -->|Yes| WALK[Walk string leaves\nrecursively]
    PARSE -->|No| PLAIN[Treat as plain text]
    WALK --> RX
    PLAIN --> RX

    RX[Regex pass\n8 patterns with confidence scores] --> MATCH{Any match?}

    MATCH -->|No| NOCONF[effectiveConfidence = 0.0\ntext may still contain\nAI-detectable PII]
    MATCH -->|Yes| MINC[track minConfidence\nacross all matches]

    MINC --> THRESH{minConfidence\n≥ aiThreshold?}
    THRESH -->|Yes, regex is sufficient| OUT

    THRESH -->|No| AI{useAI enabled?}
    NOCONF --> AI

    AI -->|No| OUT
    AI -->|Yes| CACHE{Cache hit\nfor md5 of text?}

    CACHE -->|Hit| APPLY[Apply cached\nOllama detections\nimmediately]
    APPLY --> OUT

    CACHE -->|Miss| ASYNC[Dispatch background\nOllama goroutine\nvia inflight dedup map]
    ASYNC --> OUT

    OUT([Return anonymized text\ntoken map stored in session])

    ASYNC -.->|populates cache\nfor next request| CACHE
```

**Pattern confidence scores** determine whether Stage 2 triggers:

| PII type       | Example                         | Confidence |
|----------------|---------------------------------|------------|
| Email          | `user@example.com`              | 0.95       |
| API key        | `Bearer sk-abc…` (≥ 20 chars)   | 0.90       |
| SSN            | `123-45-6789`                   | 0.85       |
| Credit card    | `4111 1111 1111 1111`           | 0.85       |
| Street address | `123 Main Street`               | 0.75       |
| IP address     | `192.168.1.1`                   | 0.70       |
| Phone number   | `+1-555-123-4567`               | 0.65       |
| ZIP code       | `90210`                         | 0.40       |

All tokens are derived from `md5(original)[:8]` — deterministic, so the same value always
produces the same token within and across requests.

### Ollama cache states

Each content hash (md5 of the raw text) progresses through three states. The self-transition on
`Inflight` is the in-flight deduplication: a second request for the same content while Ollama is
still querying reuses the running goroutine rather than spawning a new one.

```mermaid
stateDiagram-v2
    [*] --> Uncached : new content hash

    Uncached --> Inflight : cache miss — goroutine dispatched\ncurrent request returns regex-only result

    Inflight --> Inflight : duplicate request for same hash\ninflight dedup — no second goroutine\ncurrent request returns regex-only result

    Inflight --> Cached : Ollama query succeeded\ndetections stored in cache

    Inflight --> Uncached : Ollama query failed\nor semaphore full (request dropped)\nnext request will retry dispatch

    Cached --> Cached : cache hit — AI detections\napplied to current request immediately

    note right of Cached
        No eviction.
        Persists until
        proxy restart.
    end note
```

## De-anonymization and streaming

Each request gets a random `sessionID`. The token→original map is stored in
`anonymizer.sessions[sessionID]` during anonymization and deleted after the response is delivered.

For SSE (`Content-Type: text/event-stream`), `StreamingDeanonymize` wraps the response body in a
pipe-based reader that replaces tokens as data flows through, carrying a `maxTokenLen` (64 byte)
overlap window between chunks to prevent a token from being split across a read boundary.

## SSRF protection

```mermaid
flowchart TD
    REQ([Dial request\nhostname:port]) --> ISIP{Literal IP\nin request?}
    ISIP -->|Yes, private| BLOCK([Block — log + error])
    ISIP -->|No| RESOLVE[Resolve hostname\nnet.DefaultResolver]
    RESOLVE --> CHECK{Any resolved IP\nin private CIDRs?}
    CHECK -->|Yes| BLOCK
    CHECK -->|No| DIAL[Dial first resolved IP\ndirectly]
    DIAL --> CONN([net.Conn])
```

Blocked CIDRs: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`,
`169.254.0.0/16`, `::1/128`, `fc00::/7`, `fe80::/10`.

The check runs at dial time (not at request-parse time) to close the TOCTOU gap exploited by DNS
rebinding, where a hostname resolves to a public IP during the check but switches to a private IP
when the TCP connection is established.

## TLS / MITM cert lifecycle

```mermaid
flowchart LR
    START([Proxy startup]) --> LOAD{ca-cert.pem\nca-key.pem\nexist?}
    LOAD -->|Yes| PARSE[Parse CA cert + key]
    LOAD -->|No| GEN[GenerateCA\nRSA-4096, 10 yr validity]
    GEN --> PARSE
    PARSE --> CA[(mitm.CA\ncert + key + cache)]

    REQ([CONNECT host]) --> CCHECK{cache has\ncert for host?}
    CCHECK -->|Hit, not expired| TLSCFG
    CCHECK -->|Miss or expired| SIGN[GenerateKey RSA-2048\nSignCert 7 day validity]
    SIGN --> STORE[Store in cache\nmax 10 000 entries\nfull clear on overflow]
    STORE --> TLSCFG[tls.Config.GetCertificate]
    TLSCFG --> ALPN{ALPN negotiated?}
    ALPN -->|h2| H2[http2.Server.ServeConn]
    ALPN -->|http/1.1| H1[http.Server\nsingleConnListener]
```

## Domain registry and persistence

```mermaid
flowchart TD
    START([Proxy startup]) --> FILE{ai-domains.json\nexists?}
    FILE -->|Yes| LOAD[Load persisted domains\ntakes precedence]
    FILE -->|No / corrupt| CFG[Load from\nproxy-config.json]
    LOAD --> REG[(DomainRegistry\nmap + RWMutex)]
    CFG --> REG

    REG -->|DomainRegistry.Has| PROXY[proxy: intercept or tunnel?]

    ADD[POST /domains/add] --> LOCK[Lock → mutate map → snapshot]
    RM[POST /domains/remove] --> LOCK
    LOCK --> ATOMIC[Write temp file\nos.Rename → ai-domains.json]
    ATOMIC --> REG
```

Writes use an atomic rename (write to a temp file, then `os.Rename`) so the persisted file is
never partially written. The `DomainRegistry` mutex is released before the write; `Has` calls
are never blocked by disk I/O.

## Packages

| Package               | Responsibility                                                              |
|-----------------------|-----------------------------------------------------------------------------|
| `cmd/proxy`           | Entry point: wires config, shared registry, metrics, both HTTP servers      |
| `internal/config`     | Layered config loading: defaults → `proxy-config.json` → env vars           |
| `internal/anonymizer` | Two-stage PII detection, token replacement, session maps, streaming de-anon |
| `internal/proxy`      | Request router: MITM tunnel, opaque tunnel, plain-HTTP forwarding, SSRF     |
| `internal/mitm`       | CA management, per-host leaf cert generation/caching, TLS handshake, ALPN   |
| `internal/management` | Management HTTP API + persistent `DomainRegistry`                           |
| `internal/metrics`    | Atomic request/error/token counters; latency stats; JSON snapshot           |
| `internal/logger`     | Structured, level-gated logger (debug/info/warn/error) → stderr             |

## Metrics architecture

All hot-path counters (`RequestsTotal`, `TokensReplaced`, etc.) are `sync/atomic.Int64` — no
mutex in the request path. Latency accumulators use one `sync.Mutex` each, updated once per
request at the call site. The `/metrics` endpoint produces a point-in-time JSON snapshot with
min/mean/max for anonymization and upstream round-trip latency.
