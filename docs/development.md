# Development

## Building

**Linux / macOS:**

```bash
make build
# Binary: bin/proxy
```

**Windows (PowerShell):**

```powershell
mkdir -Force bin
go build -ldflags="-s -w" -o bin/proxy.exe ./cmd/proxy
```

**Cross-compile:**

```bash
# Linux binary from macOS/Windows
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/proxy-linux ./cmd/proxy

# Windows binary from macOS/Linux
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/proxy.exe ./cmd/proxy
```

## Linting

The project uses [golangci-lint](https://golangci-lint.run/) with a strict configuration:

```bash
make lint
```

## Testing

```bash
go test -race -count=1 ./...
```

## Security scanning

```bash
make security      # gosec static analysis
make vulncheck     # Go vulnerability database check
```

## All checks

```bash
make check         # lint + test + security + vulncheck
```

## Smoke test (requires running proxy)

```bash
make smoke
```

Runs `curl` to check `/status`, pass a non-AI domain through, and add a domain via the management
API.

## CI/CD

GitHub Actions runs automatically on push/PR to `main` with four parallel jobs:

1. **Lint** — golangci-lint (govet, staticcheck, errcheck, gosec, revive, noctx, bodyclose, etc.)
2. **Test** — `go test -race` with coverage reporting
3. **Security** — gosec + govulncheck
4. **Build** — compiles binary, uploads artifact (depends on all three passing)

## Project structure

```text
ai-proxy/
├── cmd/
│   └── proxy/
│       ├── main.go                # Entry point; wires config, registry, metrics, servers
│       └── main_test.go
├── internal/
│   ├── anonymizer/
│   │   ├── anonymizer.go          # Two-stage PII detection (regex + Ollama) and de-anonymization
│   │   └── anonymizer_test.go
│   ├── config/
│   │   ├── config.go              # Config loading: defaults → proxy-config.json → env vars
│   │   └── config_test.go
│   ├── logger/
│   │   ├── logger.go              # Structured, level-gated logger (debug/info/warn/error)
│   │   └── logger_test.go
│   ├── management/
│   │   ├── management.go          # HTTP management API + persistent DomainRegistry
│   │   └── management_test.go
│   ├── metrics/
│   │   ├── metrics.go             # Atomic request/error/latency counters; JSON snapshot
│   │   └── metrics_test.go
│   ├── mitm/
│   │   ├── cert.go                # CA loading, auto-generation, per-host cert cache
│   │   ├── mitm.go                # MITM TLS handler: HTTP/1.1 + HTTP/2 (ALPN)
│   │   └── mitm_test.go
│   └── proxy/
│       ├── proxy.go               # Core HTTP proxy: MITM tunnel, opaque tunnel, plain HTTP
│       └── proxy_test.go
├── docs/                          # Documentation
│   ├── architecture.md            # Design overview and request lifecycle
│   ├── client-setup.md            # Per-tool proxy configuration
│   ├── configuration.md           # All config fields and env vars
│   ├── development.md             # This file
│   ├── installation.md            # Service installation (launchd, systemd, NSSM)
│   ├── management-api.md          # Management API endpoint reference
│   └── tls-mitm.md                # MITM TLS setup and CA trust
├── .github/workflows/ci.yml       # CI pipeline
├── .golangci.yml                  # Linter configuration
├── proxy-config.json              # Example/default configuration
├── Makefile                       # Build, lint, security, deploy targets
└── go.mod
```

## Key design decisions

**No stdlib log package in hot paths.** The `internal/logger` package provides a structured,
level-gated logger that writes one line per event to stderr. It uses fixed-width columns for
machine-parseable output in log aggregators.

**Metrics use `sync/atomic`.** All request and token counters are `atomic.Int64`, so hot-path
increments never take a lock. Latency stats use a single mutex per dimension updated once per
request.

**Ollama is always async on cache miss.** A background goroutine handles the Ollama query and
writes to the cache. The in-flight map (`inflight`) prevents duplicate concurrent queries for the
same content hash. An unbuffered semaphore (`ollamaSem`) enforces the `ollamaMaxConcurrent` limit.

**SSRF protection at dial time.** `ssrfSafeDialContext` resolves the hostname and checks all
returned IPs against private/loopback/link-local CIDRs before completing the TCP dial. This
closes the TOCTOU gap that exists when IP checks are done at request-parse time but the
connection is established later.

**Streaming de-anonymization.** SSE responses are never fully buffered. A pipe-based reader
replaces tokens on-the-fly using a `maxTokenLen`-byte overlap window carried between chunks,
ensuring tokens cannot straddle a chunk boundary regardless of upstream framing.
