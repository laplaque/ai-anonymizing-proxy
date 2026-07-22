package main

import (
	"net"
	"net/http"
	"testing"
	"time"
)

// TestRunServerOrService_ServiceModeReturnsImmediately swaps the
// service dispatcher with a fake that reports "yes, we're under SCM";
// runServerOrService must return immediately, skipping the CLI arm's
// signal-handler setup and srv.Serve. (The listener itself is pre-bound
// by the test — binding happens in main, not here.)
func TestRunServerOrService_ServiceModeReturnsImmediately(t *testing.T) {
	original := serviceDispatcher
	t.Cleanup(func() { serviceDispatcher = original })

	called := false
	serviceDispatcher = func(_ *http.Server, _ net.Listener) bool {
		called = true
		return true
	}

	ln := listenLocal(t)
	defer func() { _ = ln.Close() }()
	done := make(chan struct{})
	go func() {
		runServerOrService(&http.Server{ReadHeaderTimeout: time.Second}, ln)
		close(done)
	}()

	select {
	case <-done:
		if !called {
			t.Fatal("serviceDispatcher was not called")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runServerOrService did not return within 2s in service mode")
	}
}
