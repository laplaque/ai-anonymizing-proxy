package main

import (
	"bytes"
	"log"
	"net/http"
	"strings"
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

// captureServiceLog redirects the default logger to a buffer for the
// duration of the test, so runServiceLifecycle's log lines can be asserted.
// Reads must happen only after the lifecycle goroutine has delivered its
// exit code (happens-before via the done channel). Tests in this package
// are not parallel, so swapping the global logger is safe.
func captureServiceLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	prev := log.Writer()
	buf := &bytes.Buffer{}
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

// runServiceLifecycle takes an already-bound listener, so every test binds
// "127.0.0.1:0" itself (via listenLocal) and hands the listener over — the
// kernel assigns the port at bind time and no close-then-rebind window
// exists anywhere (issue #140).

func TestRunServiceLifecycle_StopGracefully(t *testing.T) {
	ln := listenLocal(t)
	srv := &http.Server{ReadHeaderTimeout: time.Second}
	rep := &fakeReporter{}
	requests := make(chan svcCommand, 4)

	done := make(chan uint32, 1)
	go func() { done <- runServiceLifecycle(srv, ln, requests, rep) }()

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
	ln := listenLocal(t)
	srv := &http.Server{ReadHeaderTimeout: time.Second}
	rep := &fakeReporter{}
	requests := make(chan svcCommand, 4)

	done := make(chan uint32, 1)
	go func() { done <- runServiceLifecycle(srv, ln, requests, rep) }()

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

	// arrived guarantees the held request has reached the handler before
	// cmdStop is sent, so the Shutdown-timeout branch cannot be silently
	// skipped by a scheduling delay.
	arrived := make(chan struct{})
	hold := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/hold", func(w http.ResponseWriter, _ *http.Request) {
		close(arrived)
		<-hold
		w.WriteHeader(http.StatusOK)
	})

	ln := listenLocal(t)
	addr := ln.Addr().String()
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	logs := captureServiceLog(t)
	requests := make(chan svcCommand, 4)

	done := make(chan uint32, 1)
	go func() { done <- runServiceLifecycle(srv, ln, requests, &fakeReporter{}) }()

	// Fire the request that blocks past the shutdown deadline. The bound
	// listener queues the connection even before Serve accepts, so no
	// readiness poll is needed.
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/hold", http.NoBody)
		resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // body is closed below; lint flow analysis misses the err-guard
		if err == nil && resp != nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("held request did not reach the handler within 5s")
	}

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

	// Pin the timeout branch by its distinctive log line — exit code alone
	// cannot distinguish a timed-out Shutdown from a fast clean one.
	if !strings.Contains(logs.String(), "[SERVICE] shutdown:") {
		t.Errorf("expected '[SERVICE] shutdown:' timeout log, got: %q", logs.String())
	}
}

// TestRunServiceLifecycle_ServeFailureReturnsNonZero closes the listener
// before handing it over, so srv.Serve fails immediately — exercising the
// serveErr error branch and its non-zero exit code.
func TestRunServiceLifecycle_ServeFailureReturnsNonZero(t *testing.T) {
	ln := listenLocal(t)
	_ = ln.Close()

	srv := &http.Server{ReadHeaderTimeout: time.Second}
	rep := &fakeReporter{}
	logs := captureServiceLog(t)
	requests := make(chan svcCommand, 4)

	done := make(chan uint32, 1)
	go func() { done <- runServiceLifecycle(srv, ln, requests, rep) }()

	select {
	case code := <-done:
		if code != 1 {
			t.Errorf("serve-failure exit code = %d, want 1", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("lifecycle did not exit within 5s on serve failure")
	}
	if !strings.Contains(logs.String(), "[SERVICE] HTTP server exited:") {
		t.Errorf("expected '[SERVICE] HTTP server exited:' log, got: %q", logs.String())
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
