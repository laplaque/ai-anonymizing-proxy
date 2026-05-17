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

	if len(cfg.EnabledPacks) == 0 {
		log.Fatalf("[PROXY] Fatal: no PII detection packs enabled. Configure enabledPacks in proxy-config.json or set ENABLED_PACKS env var.")
	}

	printBanner(cfg)

	registry := management.NewDomainRegistry(cfg, "ai-domains.json")
	m := metrics.New()

	_ = startManagementAPI(cfg, registry, m)

	proxyServer := proxy.New(cfg, registry, m)
	defer closeProxyServer(proxyServer)

	srv := proxyHTTPServer(cfg, proxyServer)
	log.Printf("[PROXY] Listening on %s", srv.Addr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go installShutdownHandler(quit, srv, 15*time.Second)

	runHTTPServer(srv)
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
