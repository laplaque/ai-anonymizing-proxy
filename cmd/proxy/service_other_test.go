//go:build !windows

package main

import (
	"net/http"
	"testing"
)

func TestRunAsServiceIfNeeded_NoOpOnNonWindows(t *testing.T) {
	if runAsServiceIfNeeded(&http.Server{}) {
		t.Fatal("runAsServiceIfNeeded() returned true on non-Windows, expected false")
	}
}
