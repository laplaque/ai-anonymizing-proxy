//go:build !windows

package main

import (
	"net/http"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestRunServerOrService_CLI_DrainsInflightRequest pins two CLI-arm
// contracts at once (reviews N1/N6): the readiness log is emitted only
// after signal.Notify has run, so acting on the log cannot race a SIGTERM
// into the OS default handler; and runServerOrService does not return
// until an in-flight request has drained — deleting the shutdown join
// makes this test fail at the "returned while a request was still in
// flight" assertion.
func TestRunServerOrService_CLI_DrainsInflightRequest(t *testing.T) {
	logs := captureServiceLog(t)
	arrived := make(chan struct{})
	hold := make(chan struct{})
	// releaseHold is Cleanup-registered so a failure path cannot leave the
	// handler, the drain, and the client goroutine blocked for the rest of
	// the binary's lifetime; the happy path calls it exactly once too.
	releaseHold := sync.OnceFunc(func() { close(hold) })
	t.Cleanup(releaseHold)
	mux := http.NewServeMux()
	mux.HandleFunc("/hold", func(w http.ResponseWriter, _ *http.Request) {
		close(arrived)
		<-hold
		w.WriteHeader(http.StatusOK)
	})
	ln := listenLocal(t)
	addr := ln.Addr().String()
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}

	done := make(chan struct{})
	go func() { runServerOrService(srv, ln); close(done) }()
	// Failure-path teardown (runs before the releaseHold cleanup, LIFO):
	// release the held handler and force the server closed so a t.Fatal
	// between here and the drain join cannot leave the listener open and
	// the handler goroutine blocked for the rest of the binary. Best
	// effort by design: if SIGTERM was never sent, the signal-handler
	// goroutine stays parked on its channel (production owns that channel
	// internally and never calls signal.Stop) — harmless, and unreachable
	// on the happy path where done has already closed.
	t.Cleanup(func() {
		releaseHold()
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	// The readiness log implies signal.Notify has completed (ordering
	// contract in runServerOrService), so self-SIGTERM below is safe.
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "[PROXY] Listening on") {
		if time.Now().After(deadline) {
			t.Fatalf("no readiness log within 5s: %q", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/hold", http.NoBody)
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp != nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("held request did not reach the handler within 5s")
	}

	// Deliver a real SIGTERM to this process; the CLI arm's registered
	// channel receives it (Notify is active, so the OS default action is
	// not taken). Note the registration deliberately persists after the
	// test — production never calls signal.Stop — which is harmless here:
	// no other test signals the parent process, and repeat runs each
	// register their own channel.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("self-SIGTERM: %v", err)
	}

	// Serve returns as soon as Shutdown closes the listener, but the held
	// request keeps Shutdown draining — runServerOrService must still be
	// blocked on the join.
	select {
	case <-done:
		t.Fatal("runServerOrService returned while a request was still in flight — shutdown drain not joined")
	case <-time.After(300 * time.Millisecond):
	}

	releaseHold()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runServerOrService did not return within 5s of the request draining")
	}
	select {
	case <-reqDone:
	case <-time.After(5 * time.Second):
		t.Fatal("held request did not complete within 5s of the drain finishing")
	}
}
