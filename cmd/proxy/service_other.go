//go:build !windows

package main

import "net/http"

// runAsServiceIfNeeded is a no-op on non-Windows platforms. The Windows
// build registers a Service Control Manager handler so the binary works
// as a native Windows service installed by the MSI.
func runAsServiceIfNeeded(_ *http.Server) bool { return false }
