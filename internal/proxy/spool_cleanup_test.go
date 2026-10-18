package proxy

import (
	"errors"
	"strings"
	"testing"

	"ai-anonymizing-proxy/internal/metrics"
)

// failingCloser is a spool whose Close fails.
type failingCloser struct{}

func (failingCloser) Close() error {
	return errors.New("remove spool file /spool/x (queued for retry): denied")
}

// TestCloseSpoolReportsFailures verifies a spool cleanup failure is logged
// with the session and the spool's error, and counted, rather than dropped.
func TestCloseSpoolReportsFailures(t *testing.T) {
	buf := captureLog(t)
	s := &Server{m: metrics.New()}
	s.closeSpool(failingCloser{}, "sess-1")
	if got := s.m.ErrorsSpoolCleanup.Load(); got != 1 {
		t.Errorf("ErrorsSpoolCleanup = %d, want 1", got)
	}
	if out := buf.String(); !strings.Contains(out, "sessionID=sess-1 spool cleanup failed") || !strings.Contains(out, "/spool/x") {
		t.Errorf("log = %q, want the session and the failing file", out)
	}

	// Without metrics the failure is still logged.
	(&Server{}).closeSpool(failingCloser{}, "sess-2")
	if !strings.Contains(buf.String(), "sessionID=sess-2 spool cleanup failed") {
		t.Errorf("failure without metrics not logged: %q", buf.String())
	}
}

// TestServerCloseReportsUnremovedSpoolFiles verifies shutdown retries failed
// spool removals and logs those that still fail.
func TestServerCloseReportsUnremovedSpoolFiles(t *testing.T) {
	buf := captureLog(t)
	orig := retrySpoolRemovals
	t.Cleanup(func() { retrySpoolRemovals = orig })
	retrySpoolRemovals = func() int { return 2 }
	srv := fullContextProxy(t, nil)
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !strings.Contains(buf.String(), "2 request-body spool file(s) could not be removed") {
		t.Errorf("log = %q, want the count of unremoved spool files", buf.String())
	}
}
