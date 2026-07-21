//go:build !windows

package main

import (
	"net/http"
	"testing"
	"time"
)

func TestRunAsServiceIfNeeded_NoOpOnNonWindows(t *testing.T) {
	if runAsServiceIfNeeded(&http.Server{ReadHeaderTimeout: time.Second}, nil) {
		t.Fatal("runAsServiceIfNeeded() returned true on non-Windows, expected false")
	}
}
