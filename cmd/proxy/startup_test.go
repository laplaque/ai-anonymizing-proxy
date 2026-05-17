package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
)

type fakeCloser struct{ err error }

func (f fakeCloser) Close() error { return f.err }

// captureLog redirects the default logger's output to a buffer for the
// duration of fn. Restores the previous destination on return.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	prev := log.Writer()
	buf := &bytes.Buffer{}
	log.SetOutput(buf)
	defer log.SetOutput(prev)
	fn()
	return buf.String()
}

func TestCloseProxyServer_NoError_DoesNotLog(t *testing.T) {
	out := captureLog(t, func() { closeProxyServer(fakeCloser{nil}) })
	if out != "" {
		t.Errorf("expected no log output on success, got: %q", out)
	}
}

func TestCloseProxyServer_LogsError(t *testing.T) {
	out := captureLog(t, func() { closeProxyServer(fakeCloser{errors.New("boom")}) })
	if !strings.Contains(out, "[PROXY] Cache close error") {
		t.Errorf("expected '[PROXY] Cache close error' in log, got: %q", out)
	}
	if !strings.Contains(out, "boom") {
		t.Errorf("expected underlying error 'boom' in log, got: %q", out)
	}
}

func TestProxyHTTPServer_WiringFromConfig(t *testing.T) {
	cfg := &config.Config{BindAddress: "127.0.0.1", ProxyPort: 18080}
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

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

// freePort returns a 127.0.0.1 TCP port that is unused at the moment of the
// call. There is an inherent race: the OS may hand the same port to another
// process between this call and the caller's re-bind. We accept that race —
// no clean alternative exists when the consumer is a subprocess that must
// open its own listener — and rely on the helper-process tests' own
// log-based readiness probe to surface the rare collision.
func freePort(t *testing.T) int {
	t.Helper()
	l := listenLocal(t)
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		_ = l.Close()
		t.Fatalf("listener address %T is not *net.TCPAddr", l.Addr())
	}
	_ = l.Close()
	return addr.Port
}

// listenLocal binds an unused 127.0.0.1 port using a context-aware ListenConfig
// (the form noctx accepts). Caller is responsible for Close.
func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	var lc net.ListenConfig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
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
