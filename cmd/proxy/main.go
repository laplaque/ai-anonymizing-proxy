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
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/envfile"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
	"ai-anonymizing-proxy/internal/mitm"
	"ai-anonymizing-proxy/internal/proxy"
)

func main() {
	generateCA := flag.Bool("generate-ca", false, "Generate a self-signed CA cert+key pair and exit.")
	caCertOut := flag.String("ca-cert", "ca-cert.pem", "Output path for the generated CA certificate (with --generate-ca / --remove-ca-from-store).")
	caKeyOut := flag.String("ca-key", "ca-key.pem", "Output path for the generated CA private key (with --generate-ca).")
	envFile := flag.String("env-file", "", "Path to a KEY=VALUE env file applied to the process environment before config load.")
	removeCA := flag.Bool("remove-ca-from-store", false, "Remove the CA at --ca-cert from the Windows LocalMachine\\Root trust store and exit. Windows-only.")
	flag.Parse()

	if *envFile != "" {
		if err := envfile.Apply(*envFile); err != nil {
			log.Fatalf("[ENV] %v", err)
		}
	}

	if *generateCA {
		if err := runGenerateCA(*caCertOut, *caKeyOut); err != nil {
			log.Fatalf("[CA] %v", err)
		}
		return
	}

	if *removeCA {
		if err := removeCAFromStore(*caCertOut); err != nil {
			log.Fatalf("[CA] %v", err)
		}
		return
	}

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
	ln, err := bindListener(srv.Addr)
	if err != nil {
		log.Fatalf("[PROXY] Fatal: %v", err)
	}
	// Logged only after a successful bind, so this line is proof the
	// process owns its port (issue #140) — with ProxyPort 0 it reports
	// the kernel-assigned address.
	log.Printf("[PROXY] Listening on %s", ln.Addr())

	runServerOrService(srv, ln)
}

// serviceDispatcher is the entry point that decides whether the process
// is running under the Windows SCM (returning true) or as an
// interactive CLI (returning false). It's a package var so tests can
// swap in a fake that returns true to exercise the early-return path
// from runServerOrService without launching a real Windows service.
var serviceDispatcher = runAsServiceIfNeeded

// runServerOrService dispatches to the Windows SCM handler when the
// process was launched by services.msc, and falls through to the
// signal-driven HTTP loop otherwise. ln is the already-bound proxy
// listener from bindListener.
func runServerOrService(srv *http.Server, ln net.Listener) {
	if serviceDispatcher(srv, ln) {
		return
	}
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		installShutdownHandler(quit, srv, 15*time.Second)
	}()
	runHTTPServer(srv, ln)
	// srv.Serve returns as soon as Shutdown closes the listener, but
	// Shutdown may still be draining in-flight connections. Wait for the
	// handler so the graceful budget is actually honored — mirroring the
	// SCM path's post-Shutdown drain. Blocking is safe: the only non-fatal
	// way Serve returns on this path is the handler's own Shutdown.
	<-shutdownDone
}

// runGenerateCA writes a freshly generated CA cert+key to the given paths.
// Used by package post-install scripts for unattended CA bootstrap.
func runGenerateCA(certPath, keyPath string) error {
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("--ca-cert and --ca-key paths must be non-empty")
	}
	if err := mitm.GenerateCA(certPath, keyPath); err != nil {
		return fmt.Errorf("generate CA: %w", err)
	}
	fmt.Printf("CA certificate: %s\nCA private key: %s\n", certPath, keyPath)
	return nil
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
