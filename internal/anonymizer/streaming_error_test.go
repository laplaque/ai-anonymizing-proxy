package anonymizer

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// fakePipeWriter is a pipeWriter whose Write/CloseWithError behavior is
// configurable and which counts Write calls. It exercises the writePipe
// early-return path and the inner failure-logging path in handleStreamEnd that
// a real *io.PipeWriter (CloseWithError always returns nil) cannot reach.
type fakePipeWriter struct {
	writes        int
	written       []byte
	writeErr      error
	closeErr      error
	closeErrCalls int
	closeErrArg   error
}

func (f *fakePipeWriter) Write(p []byte) (int, error) {
	f.writes++
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.written = append(f.written, p...)
	return len(p), nil
}
func (f *fakePipeWriter) Close() error { return nil }
func (f *fakePipeWriter) CloseWithError(err error) error {
	f.closeErrCalls++
	f.closeErrArg = err
	return f.closeErr
}

// TestWritePipeWriteErrorEarlyReturn covers the early return in writePipe when a
// Write fails: the first write errors, so the remaining parts are never written.
func TestWritePipeWriteErrorEarlyReturn(t *testing.T) {
	w := &fakePipeWriter{writeErr: io.ErrClosedPipe}

	writePipe(w, []byte("data"), []byte("more"))

	if w.writes != 1 {
		t.Fatalf("expected writePipe to stop after the first failing write, got %d writes", w.writes)
	}
}

// fakeProvider is a minimal StreamingDeanonymizer that records whether Flush
// was called.
type fakeProvider struct{ flushed bool }

func (p *fakeProvider) ProcessDataPayload(_ []byte) bool { return true }
func (p *fakeProvider) Flush()                           { p.flushed = true }

// TestHandleStreamEndCloseWithErrorLog covers the inner CloseWithError-error
// log in handleStreamEnd (non-EOF read error whose CloseWithError also fails),
// along with the partial-line flush and the provider Flush call.
func TestHandleStreamEndCloseWithErrorLog(t *testing.T) {
	prov := &fakeProvider{}
	fw := &fakePipeWriter{closeErr: errors.New("close failed")}
	// Replacer rewrites the token so we can confirm the partial line is flushed
	// through the replacer rather than written raw or dropped.
	ctx := &streamContext{
		pw:       fw,
		replacer: strings.NewReplacer("[PII_X]", "alice"),
		provider: prov,
	}

	readErr := errors.New("read boom")
	handleStreamEnd([]byte("hi [PII_X]"), readErr, ctx)

	if !prov.flushed {
		t.Error("expected provider.Flush to be called on stream end")
	}
	// Partial-line flush: the leftover buffer must be written, token-replaced.
	if string(fw.written) != "hi alice" {
		t.Errorf("expected partial line flushed via replacer, got %q", string(fw.written))
	}
	// Non-EOF error must close the pipe with exactly that read error.
	if fw.closeErrCalls != 1 {
		t.Errorf("expected CloseWithError called once, got %d", fw.closeErrCalls)
	}
	if fw.closeErrArg != readErr {
		t.Errorf("expected CloseWithError called with the read error, got %v", fw.closeErrArg)
	}
}

// TestHandleStreamEndEOFSkipsClose covers the false branch of the
// `readErr != io.EOF` condition: at EOF with an empty line buffer the close
// block is skipped, but the provider is still flushed.
func TestHandleStreamEndEOFSkipsClose(t *testing.T) {
	prov := &fakeProvider{}
	fw := &fakePipeWriter{closeErr: errors.New("should not be called")}
	ctx := &streamContext{
		pw:       fw,
		replacer: strings.NewReplacer(),
		provider: prov,
	}

	handleStreamEnd(nil, io.EOF, ctx)

	if !prov.flushed {
		t.Error("expected provider.Flush to be called at EOF")
	}
	// The EOF branch must NOT close the pipe with an error — that's the whole
	// point of the `readErr != io.EOF` guard. Pin it: zero CloseWithError calls.
	if fw.closeErrCalls != 0 {
		t.Errorf("expected EOF path to skip CloseWithError, but it was called %d time(s) with %v",
			fw.closeErrCalls, fw.closeErrArg)
	}
}
