// Command proxy is the AI-anonymizing HTTP proxy server.
//
// It intercepts outbound HTTP requests to known AI APIs, anonymizes PII in the
// request body using a combination of regex patterns and a local Ollama model,
// then forwards the cleaned request to the original destination.
//
// Authentication and OAuth endpoints always pass through unchanged.
//
// Upstream proxy chaining (e.g. a corporate proxy) is automatic: Go's net/http
// reads HTTP_PROXY / HTTPS_PROXY / NO_PROXY from the environment. No extra
// configuration is required — set those env vars before starting this process.
//
// Usage:
//
//	# Direct internet access
//	./proxy
//
//	# Behind a corporate proxy
//	HTTPS_PROXY=http://corporate-proxy:8888 ./proxy
//
//	# Custom ports
//	PROXY_PORT=3128 MANAGEMENT_PORT=3129 ./proxy
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/proxy"
)

func main() {
	cfg := config.Load()

	printBanner(cfg)

	// Build the management domain registry so both servers share the same state.
	// Runtime domain changes are persisted to ai-domains.json and restored on restart.
	registry := management.NewDomainRegistry(cfg, "ai-domains.json")

	// Start management API in background.
	// Fatal is intentional: the proxy should not run without its control plane.
	mgmt := management.New(cfg, registry)
	go func() {
		if err := mgmt.ListenAndServe(); err != nil {
			log.Fatalf("[MANAGEMENT] Fatal: %v", err)
		}
	}()

	// Start proxy server
	proxyServer := proxy.New(cfg, registry)

	addr := fmt.Sprintf("%s:%d", cfg.BindAddress, cfg.ProxyPort)
	log.Printf("[PROXY] Listening on %s", addr)

	srv := &http.Server{
		Addr:              addr,
		Handler:           proxyServer,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[PROXY] Fatal: %v", err)
	}
}

func printBanner(cfg *config.Config) {
	upstreamProxy := os.Getenv("HTTPS_PROXY")
	if upstreamProxy == "" {
		upstreamProxy = os.Getenv("HTTP_PROXY")
	}
	if upstreamProxy == "" {
		upstreamProxy = "(direct — set HTTP_PROXY or HTTPS_PROXY to chain upstream)"
	}

	fmt.Printf(`
╔══════════════════════════════════════════════════════╗
║          AI Anonymizing Proxy  (Go)                  ║
╚══════════════════════════════════════════════════════╝
  Proxy port      : %d
  Management port : %d
  Upstream proxy  : %s
  Ollama endpoint : %s
  Ollama model    : %s
  AI detection    : %v

  Point clients here:
    export HTTP_PROXY=http://localhost:%d
    export HTTPS_PROXY=http://localhost:%d

  Check status:
    curl http://localhost:%d/status
`, cfg.ProxyPort, cfg.ManagementPort,
		upstreamProxy,
		cfg.OllamaEndpoint, cfg.OllamaModel, cfg.UseAIDetection,
		cfg.ProxyPort, cfg.ProxyPort,
		cfg.ManagementPort)
}
