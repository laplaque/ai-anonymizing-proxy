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
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
	"ai-anonymizing-proxy/internal/proxy"
)

func main() {
	cfg := config.Load()

	printBanner(cfg)

	// Build the management domain registry so both servers share the same state.
	// Runtime domain changes are persisted to ai-domains.json and restored on restart.
	registry := management.NewDomainRegistry(cfg, "ai-domains.json")

	// Shared metrics collector — passed to both servers so counters are unified.
	m := metrics.New()

	// Start management API in background.
	// Fatal is intentional: the proxy should not run without its control plane.
	mgmt := management.New(cfg, registry, m)
	go func() {
		if err := mgmt.ListenAndServe(); err != nil {
			log.Fatalf("[MANAGEMENT] Fatal: %v", err)
		}
	}()

	// Start proxy server
	proxyServer := proxy.New(cfg, registry, m)
	defer func() {
		if err := proxyServer.Close(); err != nil {
			log.Printf("[PROXY] Cache close error: %v", err)
		}
	}()

	addr := fmt.Sprintf("%s:%d", cfg.BindAddress, cfg.ProxyPort)
	log.Printf("[PROXY] Listening on %s", addr)

	srv := &http.Server{
		Addr:              addr,
		Handler:           proxyServer,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful shutdown on SIGINT / SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Printf("[PROXY] Shutting down…")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("[PROXY] Shutdown error: %v", err)
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
