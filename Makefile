BINARY     := bin/proxy
CMD        := ./cmd/proxy
GO         := go
BUILD_FLAGS := -ldflags="-s -w"
CA_CERT    := ca-cert.pem
CA_KEY     := ca-key.pem

.PHONY: all build run clean test lint security vulncheck check gen-ca import-ca-macos import-ca-linux import-ca-windows

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

clean:
	rm -rf bin/

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

# Import CA into Windows trust store (run from elevated prompt)
import-ca-windows:
	@echo "Run from an elevated Command Prompt:"
	@echo "  certutil -addstore -f \"ROOT\" $(CA_CERT)"

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
