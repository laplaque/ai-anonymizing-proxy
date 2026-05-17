package main

import (
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
// then release it. The lifecycle test re-binds it via srv.ListenAndServe.
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

func TestRunServiceLifecycle_StopGracefully(t *testing.T) {
	srv := &http.Server{Addr: freeAddr(t), ReadHeaderTimeout: time.Second}
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
	srv := &http.Server{Addr: freeAddr(t), ReadHeaderTimeout: time.Second}
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

	addr := freeAddr(t)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: time.Second}
	rep := &fakeReporter{}
	requests := make(chan svcCommand, 4)

	done := make(chan uint32, 1)
	go func() { done <- runServiceLifecycle(srv, requests, rep) }()

	// Wait for Running, then fire a request that blocks past the deadline.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hasCall(rep.snapshot(), "Running") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		_, _ = http.Get("http://" + addr + "/hold")
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
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

func hasCall(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}
