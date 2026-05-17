package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
)

// proxyHTTPServer builds the *http.Server wrapping the MITM proxy handler.
// Caller is responsible for invoking ListenAndServe / Serve.
func proxyHTTPServer(cfg *config.Config, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.BindAddress, cfg.ProxyPort),
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// startManagementAPI constructs the management server and launches its
// listener in a background goroutine. Returns the server so callers can hold
// a reference for shutdown.
func startManagementAPI(cfg *config.Config, registry *management.DomainRegistry, m *metrics.Metrics) *management.Server {
	mgmt := management.New(cfg, registry, m)
	go runManagementAPI(mgmt)
	return mgmt
}

// runManagementAPI blocks on mgmt.ListenAndServe and calls log.Fatalf if it
// returns an error. Intended to run as a goroutine — the proxy must not stay
// alive without its control plane.
func runManagementAPI(mgmt *management.Server) {
	if err := mgmt.ListenAndServe(); err != nil {
		log.Fatalf("[MANAGEMENT] Fatal: %v", err)
	}
}

// runHTTPServer blocks on srv.ListenAndServe and calls log.Fatalf if it returns
// a non-shutdown error.
func runHTTPServer(srv *http.Server) {
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[PROXY] Fatal: %v", err)
	}
}

// closeProxyServer invokes Close on the proxy server and logs any error.
// Intended for use as a deferred call in main(). Takes an io.Closer rather
// than *proxy.Server so the error-log branch can be exercised with a fake.
func closeProxyServer(s io.Closer) {
	if err := s.Close(); err != nil {
		log.Printf("[PROXY] Cache close error: %v", err)
	}
}
