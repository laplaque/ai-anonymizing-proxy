package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
)

type fakeCloser struct{ err error }

func (f fakeCloser) Close() error { return f.err }

func TestCloseProxyServer_NoError(t *testing.T) {
	closeProxyServer(fakeCloser{nil})
}

func TestCloseProxyServer_LogsError(t *testing.T) {
	closeProxyServer(fakeCloser{errors.New("boom")})
}

func TestProxyHTTPServer_WiringFromConfig(t *testing.T) {
	cfg := &config.Config{BindAddress: "127.0.0.1", ProxyPort: 18080}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	srv := proxyHTTPServer(cfg, handler)

	if srv.Addr != "127.0.0.1:18080" {
		t.Errorf("Addr = %q, want 127.0.0.1:18080", srv.Addr)
	}
	if srv.Handler == nil {
		t.Error("Handler is nil")
	}
	if srv.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 10s", srv.ReadHeaderTimeout)
	}
}

func TestStartManagementAPI_ServesRequests(t *testing.T) {
	port := freePort(t)
	cfg := &config.Config{
		BindAddress:    "127.0.0.1",
		ManagementPort: port,
		EnabledPacks:   []string{"SECRETS", "GLOBAL"},
	}
	registry := management.NewDomainRegistry(cfg, "")
	m := metrics.New()

	got := startManagementAPI(cfg, registry, m)
	if got == nil {
		t.Fatal("startManagementAPI returned nil server")
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/status", port)
	resp, err := pollUntilUp(url, 2*time.Second)
	if err != nil {
		t.Fatalf("mgmt API not reachable: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 500 {
		t.Errorf("mgmt API status = %d", resp.StatusCode)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		_ = l.Close()
		t.Fatalf("listener address %T is not *net.TCPAddr", l.Addr())
	}
	_ = l.Close()
	return addr.Port
}

func pollUntilUp(url string, timeout time.Duration) (*http.Response, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req) // #nosec G107,G704 -- localhost test URL from a net.Listener bound by the parent test
		cancel()
		if err == nil {
			return resp, nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return nil, lastErr
}
