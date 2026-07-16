package main

import (
	"context"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// fakeReporter records every status transition runServiceLifecycle makes.
type fakeReporter struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeReporter) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *fakeReporter) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeReporter) StartPending() { f.record("StartPending") }
func (f *fakeReporter) Running()      { f.record("Running") }
func (f *fakeReporter) StopPending()  { f.record("StopPending") }
func (f *fakeReporter) Interrogate()  { f.record("Interrogate") }

// freeAddr returns "127.0.0.1:<unused port>" — claim a port from the OS,
// then release it. The shutdown-timeout lifecycle test re-binds it via
// srv.ListenAndServe. Inherently TOCTOU (issue #140): another process can
// steal the port between Close and the re-bind, so the caller must treat a
// lost bind race as retryable (see waitServiceReady). Lifecycle tests that
// never dial the server avoid the race entirely by binding ":0" directly.
func freeAddr(t *testing.T) string {
	t.Helper()
	lc := &net.ListenConfig{}
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// pinnedClient returns an http.Client whose transport dials addr no matter
// what the request URL says. Probes use constant URLs — no request URL is
// ever derived from runtime data (nothing for gosec's SSRF taint rules to
// flag, and nothing to suppress) — while the dial still targets exactly
// the listener under test.
func pinnedClient(addr string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
}

func TestRunServiceLifecycle_StopGracefully(t *testing.T) {
	// ":0" lets ListenAndServe pick its own port at bind time — no
	// close-then-rebind window (issue #140). This test never dials the
	// server, so it doesn't need to know which port was chosen.
	srv := &http.Server{Addr: "127.0.0.1:0", ReadHeaderTimeout: time.Second}
	rep := &fakeReporter{}
	requests := make(chan svcCommand, 4)

	done := make(chan uint32, 1)
	go func() { done <- runServiceLifecycle(srv, requests, rep) }()

	// Wait until the lifecycle has reported Running before sending Stop.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hasCall(rep.snapshot(), "Running") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	requests <- cmdStop

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("lifecycle did not exit within 5s; calls=%v", rep.snapshot())
	}

	got := rep.snapshot()
	for _, want := range []string{"StartPending", "Running", "StopPending"} {
		if !hasCall(got, want) {
			t.Errorf("missing status transition %q in %v", want, got)
		}
	}
}

func TestRunServiceLifecycle_InterrogateReEmits(t *testing.T) {
	// ":0" — see TestRunServiceLifecycle_StopGracefully.
	srv := &http.Server{Addr: "127.0.0.1:0", ReadHeaderTimeout: time.Second}
	rep := &fakeReporter{}
	requests := make(chan svcCommand, 4)

	done := make(chan uint32, 1)
	go func() { done <- runServiceLifecycle(srv, requests, rep) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hasCall(rep.snapshot(), "Running") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	requests <- cmdInterrogate
	requests <- cmdStop

	<-done

	got := rep.snapshot()
	if !hasCall(got, "Interrogate") {
		t.Errorf("expected Interrogate in %v", got)
	}
}

func TestRunServiceLifecycle_ShutdownTimeoutLogged(t *testing.T) {
	// Force srv.Shutdown to time out by holding a request open longer
	// than the shutdownDeadline. Exercises the err != nil branch in
	// the cmdStop arm and the trailing `<-serveErr` drain.
	original := shutdownDeadline
	t.Cleanup(func() { shutdownDeadline = original })
	shutdownDeadline = 50 * time.Millisecond

	hold := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/hold", func(w http.ResponseWriter, _ *http.Request) {
		<-hold
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// Unlike the other lifecycle tests this one must dial the server, so it
	// can't bind ":0" — it re-binds a freeAddr port and can lose that bind
	// race to another process (issue #140). Retry on a fresh address when
	// the probe reports a lost race.
	var (
		client   *http.Client
		requests chan svcCommand
		done     chan uint32
	)
	for attempt := 1; ; attempt++ {
		a := freeAddr(t)
		srv := &http.Server{Addr: a, Handler: mux, ReadHeaderTimeout: time.Second}
		req := make(chan svcCommand, 4)
		d := make(chan uint32, 1)
		c := pinnedClient(a)
		go func() { d <- runServiceLifecycle(srv, req, &fakeReporter{}) }()
		if waitServiceReady(t, c, d, 2*time.Second) {
			client, requests, done = c, req, d
			break
		}
		if attempt == maxBindAttempts {
			t.Fatalf("lost the freeAddr bind race %d times in a row", attempt)
		}
		t.Logf("attempt %d/%d: lost the freeAddr bind race, retrying on a fresh port", attempt, maxBindAttempts)
	}
	defer client.CloseIdleConnections()

	// Fire a request that blocks past the shutdown deadline.
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1/hold", http.NoBody)
		resp, err := client.Do(req) //nolint:bodyclose // body is closed below; lint flow analysis misses the err-guard
		if err == nil && resp != nil {
			_ = resp.Body.Close()
		}
	}()
	// Give the request a moment to land.
	time.Sleep(50 * time.Millisecond)

	requests <- cmdStop

	// Release the holding request so Shutdown's drain can complete.
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(hold)
	}()

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code = %d, want 0 (Shutdown-timeout path still exits clean)", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("lifecycle did not exit within 5s on shutdown timeout")
	}
	<-reqDone
}

func TestRunServiceLifecycle_BindFailureReturnsNonZero(t *testing.T) {
	// Bind 127.0.0.1:0 first to capture an actually-bound port, then
	// hand that same address to a fresh server so ListenAndServe collides.
	lc := &net.ListenConfig{}
	listener, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	srv := &http.Server{Addr: listener.Addr().String(), ReadHeaderTimeout: time.Second}
	rep := &fakeReporter{}
	requests := make(chan svcCommand, 4)

	done := make(chan uint32, 1)
	go func() { done <- runServiceLifecycle(srv, requests, rep) }()

	select {
	case code := <-done:
		if code != 1 {
			t.Errorf("bind-failure exit code = %d, want 1", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("lifecycle did not exit within 5s on bind failure")
	}
}

// waitServiceReady polls the lifecycle's HTTP server (via a pinnedClient)
// until GET /ready answers 204 — proof the port is served by *our* mux,
// not by whichever process may have stolen it — or until the lifecycle
// goroutine exits first, which on a freeAddr-allocated port means
// ListenAndServe lost the re-bind race (issue #140). Returns false on a
// lost race so the caller can retry on a fresh port; fails the test on
// timeout or an exit code that a bind failure cannot produce.
func waitServiceReady(t *testing.T, client *http.Client, done <-chan uint32, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case code := <-done:
			if code != 1 {
				t.Fatalf("lifecycle exited with code %d before serving", code)
			}
			return false
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1/ready", http.NoBody)
		if err != nil {
			cancel()
			t.Fatalf("new request: %v", err)
		}
		resp, err := client.Do(req)
		cancel()
		if err == nil {
			ours := resp.StatusCode == http.StatusNoContent
			_ = resp.Body.Close()
			if ours {
				return true
			}
			// A response that isn't ours means a foreign server owns the
			// port; our ListenAndServe already failed, so the next
			// iteration's done check will observe the exit.
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("lifecycle server not ready within %v", timeout)
	return false // unreachable: Fatalf panics
}

func hasCall(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}
