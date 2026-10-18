//go:build !race

package proxy

import (
	"testing"

	"ai-anonymizing-proxy/internal/config"
)

// The tests in this file push requests past the former 50 MiB cutoff. They
// are excluded from race-instrumented builds because the race detector slows
// regex detection to roughly 0.3 MB/s, which would put a single test past
// go test's default 10-minute package timeout. CI runs them without
// instrumentation in a dedicated step (see .github/workflows/ci.yml), and
// `make test` / `make check` run them as part of `go test ./...`. The same
// code paths run under -race at smaller sizes in fullcontext_test.go.

// defaultPacks is the shipped enabledPacks default (config.defaults).
var defaultPacks = []string{"SECRETS", "GLOBAL", "DE"}

// largeWorkload exceeds the former 50 MiB cutoff: ~33 MiB of prose and tool
// history plus ~32 MiB of inline base64 images.
var largeWorkload = fullContextWorkload{
	turns:       1600,
	proseBytes:  20 << 10,
	images:      4,
	imageBytes:  6 << 20,
	instruction: fullContextInstruction,
}

// TestFullContextBeyondFormerLimitDefaultPacks streams a request larger than
// the former 50 MiB cutoff through the plain-HTTP path with the default
// detection packs and verifies the upstream receives the complete expected
// anonymized body byte for byte (length, SHA-256, Content-Length), with no
// raw synthetic address and no spool file left behind.
func TestFullContextBeyondFormerLimitDefaultPacks(t *testing.T) {
	raw, want, err := largeWorkload.digests()
	if err != nil {
		t.Fatal(err)
	}
	if raw.n <= formerRequestLimit || want.n <= formerRequestLimit {
		t.Fatalf("workload is %d raw / %d anonymized bytes; it must exceed the former %d-byte limit",
			raw.n, want.n, formerRequestLimit)
	}
	srv := fullContextProxy(t, func(c *config.Config) { c.EnabledPacks = defaultPacks })
	up := newRecordingUpstream(t)
	assertFullContextForwarded(t, srv, up, largeWorkload, raw, want)
}

// TestFullContextBeyondFormerLimitMITM sends a request larger than the former
// cutoff, with unknown length, through the MITM HTTP/2 path.
func TestFullContextBeyondFormerLimitMITM(t *testing.T) {
	assertFullContextMITM(t, largeWorkload)
}
