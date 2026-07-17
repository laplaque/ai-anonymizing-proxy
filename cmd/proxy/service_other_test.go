//go:build !windows

package main

import (
	"net/http"
	"testing"
)

func TestRunAsServiceIfNeeded_NoOpOnNonWindows(t *testing.T) {
	if runAsServiceIfNeeded(&http.Server{}, nil) {
		t.Fatal("runAsServiceIfNeeded() returned true on non-Windows, expected false")
	}
}
