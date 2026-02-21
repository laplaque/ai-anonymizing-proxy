BINARY     := bin/proxy
CMD        := ./cmd/proxy
GO         := go
BUILD_FLAGS := -ldflags="-s -w"

.PHONY: all build run clean test lint

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

clean:
	rm -rf bin/

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
