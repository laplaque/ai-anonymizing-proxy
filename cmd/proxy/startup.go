package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
)

// logFatalf is a seam over log.Fatalf so the fatal branches of the run*
// helpers below can be asserted in-process without exiting the test binary.
// Production value is log.Fatalf; only tests swap it.
var logFatalf = log.Fatalf

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
// listener in a background goroutine. Returns the server so callers can
// reach Addr and Close — tests use both; production deliberately runs the
// control plane for the process lifetime and discards the handle.
func startManagementAPI(cfg *config.Config, registry *management.DomainRegistry, m *metrics.Metrics) *management.Server {
	mgmt := management.New(cfg, registry, m)
	go runManagementAPI(mgmt)
	return mgmt
}

// runManagementAPI blocks on mgmt.ListenAndServe and fatals if it returns a
// non-shutdown error. Intended to run as a goroutine — the proxy must not
// stay alive without its control plane. ErrServerClosed (produced by
// mgmt.Close) is a deliberate teardown, not a failure.
func runManagementAPI(mgmt *management.Server) {
	if err := mgmt.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logFatalf("[MANAGEMENT] Fatal: %v", err)
	}
}

// bindListener binds the proxy's TCP listener. Binding is separated from
// serving so main can log a truthful "[PROXY] Listening on" only after the
// port is actually owned, and so ProxyPort 0 works with the kernel-assigned
// address reported by ln.Addr() — the race-free alternative to probing for
// a free port and re-binding it (issue #140).
func bindListener(addr string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(context.Background(), "tcp", addr)
}

// runHTTPServer blocks on srv.Serve and fatals if it returns a non-shutdown
// error.
func runHTTPServer(srv *http.Server, ln net.Listener) {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logFatalf("[PROXY] Fatal: %v", err)
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
