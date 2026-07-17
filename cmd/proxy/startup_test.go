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
	"sync"
	"testing"
	"time"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
)

type fakeCloser struct{ err error }

func (f fakeCloser) Close() error { return f.err }

// captureLog redirects the default logger's output to a buffer for the
// duration of fn. Restores the previous destination on return. Companion
// to captureServiceLog (service_lifecycle_test.go), the test-lifetime
// variant for goroutine-driven logging ordered by a channel.
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
	// ManagementPort 0 lets the server bind a kernel-assigned port and
	// publish it via Addr() — no free-port probing, so a bind conflict
	// (issue #140) cannot occur here.
	cfg := &config.Config{
		BindAddress:    "127.0.0.1",
		ManagementPort: 0,
		EnabledPacks:   []string{"SECRETS", "GLOBAL"},
	}
	registry := management.NewDomainRegistry(cfg, "")
	m := metrics.New()

	got := startManagementAPI(cfg, registry, m)
	if got == nil {
		t.Fatal("startManagementAPI returned nil server")
	}
	// Teardown: Close makes runManagementAPI's goroutine exit through its
	// ErrServerClosed guard instead of leaking a listener and goroutine
	// for the rest of the test binary's lifetime.
	t.Cleanup(func() { _ = got.Close() })

	// The listener binds in startManagementAPI's goroutine; Addr() is nil
	// until then.
	var addr net.Addr
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if addr = got.Addr(); addr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == nil {
		t.Fatal("management API did not publish its bound address within 2s")
	}

	url := fmt.Sprintf("http://%s/status", addr)
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

// fatalRecorder captures logFatalf invocations so the run* helpers' fatal
// branches can be asserted in-process. Mutex-guarded because runManagementAPI
// may invoke the seam from a goroutine.
type fatalRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (f *fatalRecorder) record(format string, v ...any) {
	f.mu.Lock()
	f.calls = append(f.calls, fmt.Sprintf(format, v...))
	f.mu.Unlock()
}

func (f *fatalRecorder) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

// swapLogFatalf points the logFatalf seam at a recorder for the duration of
// the test, restoring log.Fatalf afterwards.
func swapLogFatalf(t *testing.T) *fatalRecorder {
	t.Helper()
	orig := logFatalf
	t.Cleanup(func() { logFatalf = orig })
	rec := &fatalRecorder{}
	logFatalf = rec.record
	return rec
}

// TestRunHTTPServer_ServeError_Fatal hands runHTTPServer a pre-closed
// listener so srv.Serve fails with a non-shutdown error, exercising the
// "[PROXY] Fatal" branch via the logFatalf seam.
func TestRunHTTPServer_ServeError_Fatal(t *testing.T) {
	rec := swapLogFatalf(t)
	ln := listenLocal(t)
	_ = ln.Close()

	runHTTPServer(&http.Server{ReadHeaderTimeout: time.Second}, ln)

	got := rec.snapshot()
	if len(got) != 1 || !strings.Contains(got[0], "[PROXY] Fatal") {
		t.Errorf("expected one '[PROXY] Fatal' call, got %v", got)
	}
}

// TestRunHTTPServer_Shutdown_NoFatal verifies the ErrServerClosed guard: a
// deliberate srv.Close is a clean shutdown, not a fatal.
func TestRunHTTPServer_Shutdown_NoFatal(t *testing.T) {
	rec := swapLogFatalf(t)
	ln := listenLocal(t)
	srv := &http.Server{ReadHeaderTimeout: time.Second}

	done := make(chan struct{})
	go func() { runHTTPServer(srv, ln); close(done) }()
	if err := srv.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runHTTPServer did not return within 2s of Close")
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Errorf("expected no fatal on ErrServerClosed, got %v", got)
	}
}

// TestRunManagementAPI_BindError_Fatal occupies a port so ListenAndServe
// fails to bind, exercising the "[MANAGEMENT] Fatal" branch via the seam.
func TestRunManagementAPI_BindError_Fatal(t *testing.T) {
	rec := swapLogFatalf(t)
	ln := listenLocal(t)
	defer func() { _ = ln.Close() }()
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %T is not *net.TCPAddr", ln.Addr())
	}

	cfg := &config.Config{ManagementPort: tcpAddr.Port}
	mgmt := management.New(cfg, management.NewDomainRegistry(cfg, ""), nil)
	runManagementAPI(mgmt)

	got := rec.snapshot()
	if len(got) != 1 || !strings.Contains(got[0], "[MANAGEMENT] Fatal") {
		t.Errorf("expected one '[MANAGEMENT] Fatal' call, got %v", got)
	}
}

// TestRunManagementAPI_Close_NoFatal verifies the ErrServerClosed guard:
// mgmt.Close is a deliberate teardown, not a control-plane failure. Close
// is sticky, so this holds regardless of whether it wins or loses the race
// with the goroutine's bind.
func TestRunManagementAPI_Close_NoFatal(t *testing.T) {
	rec := swapLogFatalf(t)
	cfg := &config.Config{ManagementPort: 0}
	mgmt := management.New(cfg, management.NewDomainRegistry(cfg, ""), nil)

	done := make(chan struct{})
	go func() { runManagementAPI(mgmt); close(done) }()
	if err := mgmt.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runManagementAPI did not return within 2s of Close")
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Errorf("expected no fatal on ErrServerClosed, got %v", got)
	}
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
		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err == nil {
			return resp, nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return nil, lastErr
}
