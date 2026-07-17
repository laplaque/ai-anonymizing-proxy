package main

import (
	"context"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestInstallShutdownHandler_GracefulOnSignal(t *testing.T) {
	ln := listenLocal(t)
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}),
		ReadHeaderTimeout: 1 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()

	quit := make(chan os.Signal, 1)
	done := make(chan struct{})
	go func() {
		installShutdownHandler(quit, srv, 2*time.Second)
		close(done)
	}()

	quit <- syscall.SIGTERM
	select {
	case <-done:
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			t.Error("server still accepting requests after Shutdown")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("installShutdownHandler did not return within 3s of SIGTERM")
	}
}

func TestInstallShutdownHandler_TimeoutPath(t *testing.T) {
	hung := make(chan struct{})
	defer close(hung)

	ln := listenLocal(t)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			<-hung
		}),
		ReadHeaderTimeout: 1 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()

	// Kick off a long-running request, then shutdown. Use a short client
	// timeout so this goroutine doesn't outlive the test on the timeout path.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond)

	quit := make(chan os.Signal, 1)
	done := make(chan struct{})
	start := time.Now()
	go func() {
		installShutdownHandler(quit, srv, 200*time.Millisecond)
		close(done)
	}()
	quit <- syscall.SIGTERM

	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed > 1*time.Second {
			t.Errorf("shutdown took %v, expected ~200ms (timeout path)", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("installShutdownHandler did not return after Shutdown timeout")
	}
}
