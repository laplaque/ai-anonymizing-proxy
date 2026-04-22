BINARY     := bin/proxy
CMD        := ./cmd/proxy
GO         := go
BUILD_FLAGS := -ldflags="-s -w"
CA_CERT    := ca-cert.pem
CA_KEY     := ca-key.pem

.PHONY: all build run clean test lint security vulncheck check benchmark gen-ca import-ca-macos import-ca-linux import-ca-windows import-ca-macos-user import-ca-linux-user import-ca-windows-user deploy

all: build

build:
	@mkdir -p bin
	$(GO) build $(BUILD_FLAGS) -o $(BINARY) $(CMD)
	@echo "Built $(BINARY)"

run: build
	./$(BINARY)

# Run behind a corporate proxy
run-with-upstream: build
	HTTPS_PROXY=$(UPSTREAM) ./$(BINARY)

test:
	$(GO) test ./...

lint:
	golangci-lint run ./...

security:
	@echo "Running gosec security scanner..."
	gosec -exclude=G104,G304,G703,G706 ./...

vulncheck:
	@echo "Running govulncheck..."
	govulncheck ./...

check: lint test security vulncheck
	@echo "All checks passed."

benchmark: ## Run latency benchmarks for all proxy gates
	@mkdir -p .tmp
	$(GO) test -run=^$$ -bench=. -benchmem -benchtime=3s -count=3 \
		./internal/anonymizer/... \
		| tee .tmp/benchmark-latest.txt
	@echo ""
	@echo "Benchmark results written to .tmp/benchmark-latest.txt"

sonar: ## Run full analysis and push to SonarQube
	@echo "--- Generating coverage report ---"
	$(GO) test ./... -coverprofile=coverage.out
	@echo "--- Generating test report ---"
	$(GO) test ./... -v -json | go-junit-report -set-exit-code > test-report.xml
	@echo "--- Generating golangci-lint report ---"
	golangci-lint run --output.checkstyle.path golangci-report.xml ./... || true
	@echo "--- Running sonar-scanner ---"
	sonar-scanner
	@echo "--- Cleaning up ---"
	rm -f coverage.out test-report.xml golangci-report.xml

clean:
	rm -rf bin/

deploy: build
	sudo cp $(BINARY) /opt/ai-proxy/proxy
	launchctl kickstart -k gui/$$(id -u)/com.ai-proxy
	@echo "Deployed $(BINARY) → /opt/ai-proxy/proxy and restarted service"

# --- CA Certificate Management ---

# Generate a self-signed CA certificate for MITM TLS interception.
# The proxy can also auto-generate these on first start.
gen-ca:
	openssl genrsa -out $(CA_KEY) 4096
	openssl req -new -x509 -key $(CA_KEY) -out $(CA_CERT) -days 3650 \
		-subj "/CN=AI-Proxy Local CA/O=AI Anonymizing Proxy"
	@echo "CA certificate generated: $(CA_CERT) / $(CA_KEY)"
	@echo "Trust this CA on your OS to enable HTTPS interception."

# Import CA into macOS trust store (requires admin password)
import-ca-macos:
	sudo security add-trusted-cert -d -r trustRoot \
		-k /Library/Keychains/System.keychain $(CA_CERT)
	@echo "CA trusted on macOS."

# Import CA into Linux trust store (Debian/Ubuntu)
import-ca-linux:
	sudo cp $(CA_CERT) /usr/local/share/ca-certificates/ai-proxy-ca.crt
	sudo update-ca-certificates
	@echo "CA trusted on Linux."

# Import CA into Windows trust store (requires elevated PowerShell)
import-ca-windows:
	@test -n "$(CA_CERT)" || { echo "Error: CA_CERT is not set. Run 'make generate-ca' first or set CA_CERT=path/to/ca.pem."; exit 1; }
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/import-ca.ps1 -CaPath "$(CA_CERT)"

# --- User-scope CA trust (no admin / no sudo required) ---

# Trust the proxy CA for the current user only (no sudo, no admin).
# Use this for a zero-admin setup, e.g. VS Code users without root.
import-ca-macos-user:
	security add-trusted-cert -d -r trustRoot \
		-k "$(HOME)/Library/Keychains/login.keychain-db" $(CA_CERT)
	@echo "CA trusted on macOS (current user)."

# Linux has no user-writable system CA store. Set NODE_EXTRA_CA_CERTS,
# REQUESTS_CA_BUNDLE, and SSL_CERT_FILE via a guided installer instead.
# Writes ~/.config/environment.d/ai-proxy.conf + optional shell rc.
import-ca-linux-user:
	@if [ -z "$(CA_CERT)" ] || [ ! -f "$(CA_CERT)" ]; then \
		echo "CA_CERT not found at '$(CA_CERT)'. Generate it first with 'make gen-ca'."; \
		exit 1; \
	fi
	scripts/setup-user-env-linux.sh --ca-path "$(CA_CERT)"

# Trust the proxy CA for the current Windows user (no admin).
# Uses Cert:\CurrentUser\Root instead of Cert:\LocalMachine\Root.
import-ca-windows-user:
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/import-ca.ps1 -CaPath "$(CA_CERT)" -Scope User
	@echo "CA trusted on Windows (current user)."

# Quick smoke test against a running proxy
smoke:
	@echo "--- Status ---"
	curl -s http://localhost:8081/status | jq .
	@echo "\n--- Passthrough (non-AI domain) ---"
	curl -s --proxy http://localhost:8080 https://httpbin.org/ip
	@echo "\n--- Add domain ---"
	curl -s -X POST http://localhost:8081/domains/add \
		-H "Content-Type: application/json" \
		-d '{"domain":"api.newai.example.com"}' | jq .
