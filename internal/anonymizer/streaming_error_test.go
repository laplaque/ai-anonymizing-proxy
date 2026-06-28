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
	writes   int
	writeErr error
	closeErr error
}

func (f *fakePipeWriter) Write(p []byte) (int, error) {
	f.writes++
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return len(p), nil
}
func (f *fakePipeWriter) Close() error                 { return nil }
func (f *fakePipeWriter) CloseWithError(_ error) error { return f.closeErr }

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
	ctx := &streamContext{
		pw:       &fakePipeWriter{closeErr: errors.New("close failed")},
		replacer: strings.NewReplacer(),
		provider: prov,
	}

	handleStreamEnd([]byte("partial line"), errors.New("read boom"), ctx)

	if !prov.flushed {
		t.Error("expected provider.Flush to be called on stream end")
	}
}

// TestHandleStreamEndEOFSkipsClose covers the false branch of the
// `readErr != io.EOF` condition: at EOF with an empty line buffer the close
// block is skipped, but the provider is still flushed.
func TestHandleStreamEndEOFSkipsClose(t *testing.T) {
	prov := &fakeProvider{}
	ctx := &streamContext{
		pw:       &fakePipeWriter{closeErr: errors.New("should not be called")},
		replacer: strings.NewReplacer(),
		provider: prov,
	}

	handleStreamEnd(nil, io.EOF, ctx)

	if !prov.flushed {
		t.Error("expected provider.Flush to be called at EOF")
	}
}
