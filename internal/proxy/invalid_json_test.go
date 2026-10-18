package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// capturingUpstream records every request body it receives.
type capturingUpstream struct {
	*httptest.Server
	mu     sync.Mutex
	bodies []string
}

func newCapturingUpstream(t *testing.T) *capturingUpstream {
	t.Helper()
	u := &capturingUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.bodies = append(u.bodies, string(b))
		u.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *capturingUpstream) received() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.bodies...)
}

// postWithType sends body through srv's plain-HTTP path with the given
// Content-Type ("" sends none).
func postWithType(t *testing.T, srv *Server, upstreamURL, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	host := backendHostPort(t, upstreamURL, "http")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+host+"/v1/chat/completions", strings.NewReader(body))
	req.Host = host
	req.URL.Host = host
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// prefixLeakBodies are the review reproductions: the streaming parser emits a
// prefix ("123", "true", a skip-key value, an object key) before the syntax
// error, so anonymizing only the remainder forwarded the synthetic address.
var prefixLeakBodies = map[string]string{
	"number before address":     `123@example.com`,
	"literal before address":    `true@example.com`,
	"address in skip-key value": `{"model":"alice@example.com",}`,
	"address in object key":     `{"alice@example.com":0,}`,
}

// TestInvalidDeclaredJSONIsRejected verifies that a body declared as JSON but
// not valid JSON is rejected with 400 before anything reaches the upstream,
// and the anonymization error is counted.
func TestInvalidDeclaredJSONIsRejected(t *testing.T) {
	srv := fullContextProxy(t, nil)
	up := newCapturingUpstream(t)
	for name, body := range prefixLeakBodies {
		for _, ct := range []string{"application/json", "application/json; charset=utf-8", "application/vnd.example+json"} {
			w := postWithType(t, srv, up.URL, ct, body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s (%s): status %d, want 400", name, ct, w.Code)
			}
			if !strings.Contains(w.Body.String(), "not valid JSON") {
				t.Errorf("%s (%s): body %q does not explain the rejection", name, ct, w.Body.String())
			}
		}
	}
	if got := up.received(); len(got) != 0 {
		t.Errorf("upstream received %d rejected bodies: %q", len(got), got)
	}
	if n := srv.m.ErrorsAnonymize.Load(); n != int64(3*len(prefixLeakBodies)) {
		t.Errorf("ErrorsAnonymize = %d, want %d", n, 3*len(prefixLeakBodies))
	}
}

// TestUndeclaredBodyIsAnonymizedWhole verifies that a body not declared as
// JSON keeps the pre-streaming behavior: it is anonymized in one piece (as
// text when it is not valid JSON), so the address in each review
// reproduction reaches the upstream only as a token.
func TestUndeclaredBodyIsAnonymizedWhole(t *testing.T) {
	srv := fullContextProxy(t, nil)
	up := newCapturingUpstream(t)
	token := srv.anon.AnonymizeText("alice@example.com", "probe")
	for name, body := range prefixLeakBodies {
		for _, ct := range []string{"text/plain", "", "application/x-www-form-urlencoded"} {
			if w := postWithType(t, srv, up.URL, ct, body); w.Code != http.StatusNoContent {
				t.Fatalf("%s (%q): status %d: %s", name, ct, w.Code, w.Body.String())
			}
		}
	}
	got := up.received()
	if len(got) != 3*len(prefixLeakBodies) {
		t.Fatalf("upstream received %d bodies, want %d", len(got), 3*len(prefixLeakBodies))
	}
	for _, b := range got {
		if strings.Contains(b, "@example.com") {
			t.Errorf("raw synthetic address forwarded: %q", b)
		}
		if !strings.Contains(b, "[PII_EMAIL_") {
			t.Errorf("forwarded body has no email token: %q", b)
		}
	}
	// The skip-key reproduction is not valid JSON, so it is anonymized as one
	// piece of text, including the value under "model".
	if want := `{"model":"` + token + `",}`; !slices.Contains(got, want) {
		t.Errorf("skip-key reproduction not anonymized as whole text; want %q among %q", want, got)
	}
}

func TestDeclaresJSON(t *testing.T) {
	for ct, want := range map[string]bool{
		"application/json":                true,
		"Application/JSON; charset=utf-8": true,
		"application/problem+json":        true,
		"application/vnd.api+json; v=1":   true,
		"text/plain":                      false,
		"application/x-ndjson":            false,
		"":                                false,
		"application/json; =broken":       false,
	} {
		if got := declaresJSON(ct); got != want {
			t.Errorf("declaresJSON(%q) = %v, want %v", ct, got, want)
		}
	}
}
