package main

import (
	"net/http"
	"testing"
	"time"
)

// TestRunServerOrService_ServiceModeReturnsImmediately swaps the
// service dispatcher with a fake that reports "yes, we're under SCM";
// runServerOrService must return immediately without installing a
// signal handler or starting the HTTP listener.
func TestRunServerOrService_ServiceModeReturnsImmediately(t *testing.T) {
	original := serviceDispatcher
	t.Cleanup(func() { serviceDispatcher = original })

	called := false
	serviceDispatcher = func(_ *http.Server) bool {
		called = true
		return true
	}

	done := make(chan struct{})
	go func() {
		runServerOrService(&http.Server{Addr: "127.0.0.1:0", ReadHeaderTimeout: time.Second})
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
