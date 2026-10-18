package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// cancelAfterReader serves body and cancels its context once it has
// returned after bytes.
type cancelAfterReader struct {
	r      io.Reader
	after  int
	n      int
	cancel context.CancelFunc
}

func (c *cancelAfterReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	if c.n >= c.after {
		c.cancel()
	}
	return n, err
}

// cancelBody returns a JSON body of about size bytes with synthetic
// addresses throughout.
func cancelBody(size int) string {
	var b strings.Builder
	b.WriteString(`{"messages":[{"role":"user","content":"`)
	for b.Len() < size {
		b.WriteString("write to grace@example.com about the plan. ")
	}
	b.WriteString(`"}]}`)
	return b.String()
}

// TestAnonymizeRequestBodyStopsWhenCanceled verifies that a request whose
// context is already done is not read at all, and that one canceled during
// the upload stops reading within one buffer instead of anonymizing the rest.
// Both report a client body error, so nothing is forwarded.
func TestAnonymizeRequestBodyStopsWhenCanceled(t *testing.T) {
	srv := fullContextProxy(t, nil)
	body := cancelBody(2 << 20)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	counter := &cancelAfterReader{r: strings.NewReader(body), after: len(body) + 1, cancel: func() {}}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1", counter)
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	_, _, err := srv.anonymizeRequestBody(req)
	var clientErr *clientBodyError
	if !errors.As(err, &clientErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled: err = %v, want a client body error wrapping context.Canceled", err)
	}
	if counter.n != 0 {
		t.Errorf("already canceled: read %d bytes, want 0", counter.n)
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	mid := &cancelAfterReader{r: strings.NewReader(body), after: 256 << 10, cancel: cancel}
	req = httptest.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1", mid)
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	if _, _, err := srv.anonymizeRequestBody(req); !errors.As(err, &clientErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled mid-upload: err = %v, want a client body error wrapping context.Canceled", err)
	}
	if limit := 256<<10 + 128<<10; mid.n > limit {
		t.Errorf("canceled mid-upload: read %d bytes, want at most %d", mid.n, limit)
	}
}
