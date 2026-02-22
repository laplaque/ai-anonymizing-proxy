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

The project uses [golangci-lint](https://golangci-lint.run/) with a strict configuration
(15 linters enabled):

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

## CI/CD

GitHub Actions runs automatically on push/PR to `main` with four parallel jobs:

1. **Lint** — golangci-lint (govet, staticcheck, errcheck, gosec, revive, noctx, bodyclose, etc.)
2. **Test** — `go test -race` with coverage reporting
3. **Security** — gosec + govulncheck
4. **Build** — compiles binary, uploads artifact (depends on all three passing)

## Project structure

```text
ai-proxy/
├── cmd/proxy/main.go              # Entry point
├── internal/
│   ├── anonymizer/anonymizer.go   # PII detection (regex + Ollama)
│   ├── config/config.go           # Configuration loading
│   ├── management/
│   │   ├── management.go          # Runtime management API
│   │   └── management_test.go     # Management API tests
│   ├── mitm/
│   │   ├── cert.go                # CA loading, auto-generation, cert cache
│   │   └── mitm.go                # MITM TLS handler (HTTP/1.1 + H2)
│   └── proxy/
│       ├── proxy.go               # Core HTTP proxy
│       └── proxy_test.go          # Proxy unit tests (SSRF, etc.)
├── docs/                          # Detailed documentation
│   ├── configuration.md
│   ├── installation.md
│   ├── tls-mitm.md
│   ├── client-setup.md
│   ├── management-api.md
│   └── development.md
├── .github/workflows/ci.yml       # CI pipeline
├── .golangci.yml                  # Linter configuration
├── proxy-config.json              # Default configuration
├── Makefile                       # Build, lint, security targets
└── go.mod
```
