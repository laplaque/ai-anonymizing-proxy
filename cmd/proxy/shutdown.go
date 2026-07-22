package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"
)

// installShutdownHandler blocks on quit, then calls srv.Shutdown with the given
// timeout. Intended to run in a goroutine spawned by runServerOrService.
func installShutdownHandler(quit <-chan os.Signal, srv *http.Server, timeout time.Duration) {
	<-quit
	log.Printf("[PROXY] Shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[PROXY] Shutdown error: %v", err)
	}
}
