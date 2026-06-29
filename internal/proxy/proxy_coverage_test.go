package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
)

// captureLog redirects the standard logger to a buffer so a branch's
// distinctive log line can be asserted. These tests are not parallel.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// --- A) mustParsePrivateNetworks ---

func TestMustParsePrivateNetworks_Panics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for invalid CIDR")
		}
	}()
	mustParsePrivateNetworks([]string{"not-a-cidr"})
}

func TestMustParsePrivateNetworks_Valid(t *testing.T) {
	nets := mustParsePrivateNetworks([]string{"10.0.0.0/8"})
	if len(nets) != 1 {
		t.Fatalf("expected 1 network, got %d", len(nets))
	}
}

// --- B) ssrfSafeDialContext seam-driven branches ---

func TestSsrfSafeDialContext_Branches(t *testing.T) {
	origLookup := lookupIPAddr
	defer func() { lookupIPAddr = origLookup }()

	dialFn := ssrfSafeDialContext(&net.Dialer{})

	t.Run("split host port error falls to direct dial", func(t *testing.T) {
		// No colon -> net.SplitHostPort fails -> the direct d.DialContext path,
		// which must NOT consult the resolver. Pin that branch: fail loudly if
		// lookup is reached (it would be, if the SplitHostPort-error fallback
		// were removed and control fell through to the lookup path).
		lookupReached := false
		lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
			lookupReached = true
			return nil, errors.New("resolver must not be reached on the direct-dial path")
		}
		// Canceled context so the direct dial returns immediately.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := dialFn(ctx, "tcp", "hostwithoutport")
		if err == nil {
			t.Fatal("expected error from direct dial of invalid address")
		}
		if lookupReached {
			t.Error("SplitHostPort-error path must dial directly without resolving")
		}
	})

	t.Run("lookup error", func(t *testing.T) {
		lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
			return nil, errors.New("dns boom")
		}
		_, err := dialFn(context.Background(), "tcp", "example.com:443")
		if err == nil || !strings.Contains(err.Error(), "dns boom") {
			t.Fatalf("expected lookup error, got %v", err)
		}
	})

	t.Run("private IP blocked", func(t *testing.T) {
		lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
		}
		_, err := dialFn(context.Background(), "tcp", "example.com:443")
		if !errors.Is(err, errPrivateIP) {
			t.Fatalf("expected errPrivateIP, got %v", err)
		}
	})

	t.Run("empty IPs", func(t *testing.T) {
		lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{}, nil
		}
		_, err := dialFn(context.Background(), "tcp", "example.com:443")
		if err == nil || !strings.Contains(err.Error(), "no IP addresses") {
			t.Fatalf("expected 'no IP addresses' error, got %v", err)
		}
	})

	t.Run("final dial executes", func(t *testing.T) {
		lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		}
		// Canceled context makes the real dial return immediately.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := dialFn(ctx, "tcp", "example.com:443")
		if err == nil {
			t.Fatal("expected error from canceled-context dial")
		}
	})
}

// --- C) anonymizeRequestBody ---

// infiniteReader yields filler bytes forever (until LimitReader caps it).
type infiniteReader struct{}

func (infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func (infiniteReader) Close() error { return nil }

func TestAnonymizeRequestBody_BodyTooLarge(t *testing.T) {
	srv := newTestProxyServer(t)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "http://example.com", nil)
	req.Body = infiniteReader{}
	req.ContentLength = maxRequestBody + 10

	sessionID, err := srv.anonymizeRequestBody(req)
	if err == nil {
		t.Fatal("expected error for body exceeding limit")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected 'exceeds' error, got %v", err)
	}
	if sessionID != "" {
		t.Fatalf("expected empty sessionID, got %q", sessionID)
	}
}

func TestAnonymizeRequestBody_RandFallback(t *testing.T) {
	srv := newTestProxyServer(t)

	orig := randRead
	defer func() { randRead = orig }()
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }

	body := `{"message":"hi"}`
	req := httptest.NewRequestWithContext(context.Background(), "POST", "http://example.com",
		strings.NewReader(body))
	req.ContentLength = int64(len(body))

	sessionID, err := srv.anonymizeRequestBody(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionID == "" {
		t.Fatal("expected non-empty timestamp-fallback sessionID")
	}
	// The success path is exactly 16 hex chars from rand.Read; the fallback is
	// fmt.Sprintf("%d", time.Now().UnixNano()). Prove the fallback was taken by
	// requiring a base-10 integer in a recent-nanosecond range — a 16-char hex
	// token cannot satisfy this (max all-digit hex value ~1e16 < the bound).
	n, parseErr := strconv.ParseInt(sessionID, 10, 64)
	if parseErr != nil {
		t.Fatalf("expected UnixNano timestamp fallback sessionID, got %q (parse err: %v)", sessionID, parseErr)
	}
	const year2020Nanos = 1_600_000_000_000_000_000
	if n < year2020Nanos {
		t.Fatalf("expected a recent UnixNano timestamp fallback, got %q (%d)", sessionID, n)
	}
	srv.anon.DeleteSession(sessionID)
}

// --- D) deanonymizeResponseBody decompression error ---

func TestDeanonymizeResponseBody_DecompressError(t *testing.T) {
	srv := newTestProxyServer(t)
	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(strings.NewReader("this is not gzip")),
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Encoding", "gzip")

	// Bad gzip -> decompressResponse returns an error -> error-log branch, then
	// deanonymizeResponseBody continues defensively. Prove two things:
	//  1. the resulting body is still readable (ReadAll succeeds with no error),
	//     not a panic or a propagated read failure; and
	//  2. the failure branch was actually taken — a SUCCESSFUL decode deletes the
	//     Content-Encoding header, so its retention pins the error path (and
	//     rules out a silent no-op or the success path).
	srv.deanonymizeResponseBody(resp, "sess-x", "api.example.com")
	if resp.Body == nil {
		t.Fatal("expected non-nil body after deanonymize")
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("body not readable after failed decompression: %v", err)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("expected Content-Encoding retained on decode failure (error branch), got %q", enc)
	}
}

// --- E) Handler-path branches ---

// fakeConnHijacker is an http.Hijacker whose Hijack() always returns an error.
// fakeConnHijacker is an http.Hijacker whose Hijack always errors. It records
// whether WriteHeader and Hijack were invoked so tests can prove the tunnel
// reached the CONNECT-success write and the hijack attempt before the error
// (a bare ResponseRecorder defaults Code to 200, so Code alone proves nothing).
type fakeConnHijacker struct {
	*httptest.ResponseRecorder
	wroteHeader  bool
	hijackCalled bool
}

func newFakeConnHijacker() *fakeConnHijacker {
	return &fakeConnHijacker{ResponseRecorder: httptest.NewRecorder()}
}

func (h *fakeConnHijacker) WriteHeader(code int) {
	h.wroteHeader = true
	h.ResponseRecorder.WriteHeader(code)
}

func (h *fakeConnHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijackCalled = true
	return nil, nil, errors.New("hijack failed")
}

// newCATestServer builds a Server with a real MITM CA and the given AI domain.
func newCATestServer(t *testing.T, aiDomain string) *Server {
	t.Helper()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca-cert.pem")
	keyFile := filepath.Join(dir, "ca-key.pem")
	cfg := &config.Config{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "test",
		AIAPIDomains:   []string{aiDomain},
		EnabledPacks:   []string{"GLOBAL"},
		CACertFile:     certFile,
		CAKeyFile:      keyFile,
	}
	domains := management.NewDomainRegistry(cfg, "")
	srv := New(cfg, domains, metrics.New())
	t.Cleanup(func() { _ = srv.Close() })
	if srv.ca == nil {
		t.Fatal("expected CA to be loaded")
	}
	return srv
}

// handleTunnel MITM branch: routes to handleMITMTunnel, which (with a non-hijacker
// writer) falls back to handleOpaqueTunnel. Use a dialContext that returns quickly.
func TestHandleTunnel_MITMBranch(t *testing.T) {
	srv := newCATestServer(t, "api.example.com")
	// Make the opaque fallback dial fail fast instead of hanging on the network.
	srv.dialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial blocked")
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodConnect,
		"http://api.example.com:443", nil)
	req.Host = "api.example.com:443"
	req.RemoteAddr = "127.0.0.1:5555"

	// httptest.NewRecorder is NOT an http.Hijacker -> MITM falls back to opaque,
	// which dials (fails fast) and returns 502.
	w := httptest.NewRecorder()
	logs := captureLog(t)
	srv.handleTunnel(w, req)

	// Branch-specific evidence that handleTunnel selected the MITM path: only
	// handleMITMTunnel logs "[MITM] ... Intercepting CONNECT" (at its top, before
	// the hijacker fallback). If the AI-domain branch were removed, the request
	// would route straight to handleOpaqueTunnel — same 502, but no MITM log — so
	// asserting the status alone does not prove MITM routing for this privacy path.
	if !strings.Contains(logs.String(), "Intercepting CONNECT api.example.com:443") {
		t.Errorf("expected handleTunnel to route the AI domain into MITM (Intercepting CONNECT log), got: %q", logs.String())
	}
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 from opaque fallback dial failure, got %d", w.Code)
	}
}

// handleMITMTunnel Hijack error branch.
func TestHandleMITMTunnel_HijackError(t *testing.T) {
	srv := newCATestServer(t, "api.example.com")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodConnect,
		"http://api.example.com:443", nil)
	req.RemoteAddr = "127.0.0.1:5555"

	w := newFakeConnHijacker()
	srv.handleMITMTunnel(w, req, "api.example.com:443", "api.example.com")

	// Prove the hijack-error branch was actually reached: the CONNECT-success
	// WriteHeader(200) ran (assert wroteHeader, not Code — a recorder defaults to
	// 200) and Hijack() was attempted before the error return.
	if !w.wroteHeader || w.Code != http.StatusOK {
		t.Fatalf("expected WriteHeader(200) before hijack (wrote=%v code=%d)", w.wroteHeader, w.Code)
	}
	if !w.hijackCalled {
		t.Fatal("expected handleMITMTunnel to attempt Hijack before the error return")
	}
}

// handleMITMTunnel happy-hijack path that returns: a successful Hijack hands back
// a conn whose peer is closed, so mitm.HandleConn fails the TLS handshake and
// returns promptly, letting handleMITMTunnel return and fire its deferred
// clientConn.Close().
func TestHandleMITMTunnel_HandshakeFailReturns(t *testing.T) {
	srv := newCATestServer(t, "api.example.com")

	client, server := net.Pipe()
	// Close the client side so the server-side TLS handshake gets EOF immediately.
	_ = client.Close()

	hw := &pipeHijacker{ResponseRecorder: httptest.NewRecorder(), conn: server}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodConnect,
		"http://api.example.com:443", nil)
	req.RemoteAddr = "127.0.0.1:5555"

	// Returns once HandleConn's handshake fails; the deferred clientConn.Close runs.
	srv.handleMITMTunnel(hw, req, "api.example.com:443", "api.example.com")

	// Pin the success path. A recorder defaults Code to 200, so assert
	// wroteHeader (not just Code) to prove WriteHeader(200) actually ran, and
	// assert the hijack was taken — the handshake-fail-returns flow only runs
	// after a successful Hijack.
	if !hw.wroteHeader || hw.Code != http.StatusOK {
		t.Fatalf("expected WriteHeader(200) before hijack (wrote=%v code=%d)", hw.wroteHeader, hw.Code)
	}
	if !hw.hijackCalled {
		t.Fatal("expected handleMITMTunnel to hijack the connection on the MITM path")
	}
}

// pipeHijacker is an http.Hijacker that returns a preset net.Conn and records
// whether WriteHeader and Hijack were invoked (a bare ResponseRecorder defaults
// Code to 200, so wroteHeader is needed to actually pin the WriteHeader call).
type pipeHijacker struct {
	*httptest.ResponseRecorder
	conn         net.Conn
	wroteHeader  bool
	hijackCalled bool
}

func (h *pipeHijacker) WriteHeader(code int) {
	h.wroteHeader = true
	h.ResponseRecorder.WriteHeader(code)
}

func (h *pipeHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijackCalled = true
	rw := bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn))
	return h.conn, rw, nil
}

// serveMITMRequest !ok branch: oversized body -> processMITMRequestBody returns
// ("", false) -> 413 and no forwarding.
func TestServeMITMRequest_ProcessBodyError(t *testing.T) {
	srv := newTestProxyServer(t)

	req := httptest.NewRequestWithContext(context.Background(), "POST",
		"https://api.example.com/v1/chat", nil)
	req.Body = infiniteReader{}
	req.ContentLength = maxRequestBody + 10

	rw := newResponseRecorder()
	ctx := mitmContext{host: "api.example.com:443", domain: "api.example.com", remoteHash: "abcd1234"}

	srv.serveMITMRequest(rw, req, ctx)

	if rw.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rw.code)
	}
}

// handleOpaqueTunnel: dial succeeds (fake conn) but writer is not a Hijacker.
func TestHandleOpaqueTunnel_HijackNotSupported(t *testing.T) {
	srv := newTestProxyServerAllowLocal(t, nil, nil)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	srv.dialContext = func(context.Context, string, string) (net.Conn, error) {
		return server, nil
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodConnect,
		"http://example.com:443", nil)
	req.Host = "example.com:443"
	req.RemoteAddr = "127.0.0.1:5555"

	// httptest.NewRecorder is not a Hijacker.
	w := httptest.NewRecorder()
	srv.handleOpaqueTunnel(w, req, "example.com:443")

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 hijacking not supported, got %d", w.Code)
	}
}

// handleOpaqueTunnel: dial succeeds but Hijack() errors.
func TestHandleOpaqueTunnel_HijackError(t *testing.T) {
	srv := newTestProxyServerAllowLocal(t, nil, nil)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	srv.dialContext = func(context.Context, string, string) (net.Conn, error) {
		return server, nil
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodConnect,
		"http://example.com:443", nil)
	req.Host = "example.com:443"
	req.RemoteAddr = "127.0.0.1:5555"

	w := newFakeConnHijacker()
	srv.handleOpaqueTunnel(w, req, "example.com:443")

	// Prove the hijack-error branch was reached: the CONNECT-success
	// WriteHeader(200) ran (assert wroteHeader, not Code — a recorder defaults to
	// 200) and Hijack() was attempted before the error return.
	if !w.wroteHeader || w.Code != http.StatusOK {
		t.Fatalf("expected WriteHeader(200) before hijack (wrote=%v code=%d)", w.wroteHeader, w.Code)
	}
	if !w.hijackCalled {
		t.Fatal("expected handleOpaqueTunnel to attempt Hijack before the error return")
	}
}

// handleHTTP ANON path: AI domain, non-auth, body with synthetic PII produces a
// non-empty sessionID and exercises the [ANON] log + DeleteSession defer.
func TestHandleHTTP_AnonPath(t *testing.T) {
	// Capture the body the upstream actually receives so we can prove the [ANON]
	// path ran (PII replaced before forwarding), not merely that a 200 came back
	// — a plain passthrough would also return 200. The buffered channel gives a
	// happens-before edge for the race detector.
	gotBody := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody <- string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	host := backendHostPort(t, backend.URL, "http")
	// handleHTTP matches on the port-stripped host ("localhost"), so register
	// the bare domain (not the host:port form) for the AI-anonymize path.
	srv := newTestProxyServerAllowLocal(t, []string{"localhost"}, nil)

	const pii = "alice@example.com"
	body := `{"prompt":"contact ` + pii + ` please"}`
	req := httptest.NewRequestWithContext(context.Background(), "POST", "http://"+host+"/v1/x",
		strings.NewReader(body))
	req.Host = host
	req.URL.Host = host
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	w := httptest.NewRecorder()
	srv.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	select {
	case received := <-gotBody:
		// The ANON path must have rewritten the synthetic PII into a token before
		// forwarding upstream.
		if strings.Contains(received, pii) {
			t.Errorf("upstream received un-anonymized PII; body was forwarded as passthrough: %s", received)
		}
		if !strings.Contains(received, "[PII_") {
			t.Errorf("expected an anonymized [PII_...] token in the forwarded body, got: %s", received)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the forwarded request")
	}
}

// forward URL.Host fallback + private-host block.
func TestForward_URLHostFallbackPrivate(t *testing.T) {
	srv := newTestProxyServerAllowLocal(t, nil, nil)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://placeholder/test", nil)
	req.URL.Host = ""     // forces fallback to r.Host
	req.Host = "10.0.0.1" // private -> 403 before any dial

	w := httptest.NewRecorder()
	logs := captureLog(t)
	srv.forward(w, req, "", "domain")

	// Pin the private-block branch by its distinctive log line, which also proves
	// the URL.Host fallback ran (it logs the filled-in r.URL.Host = "10.0.0.1").
	// Asserting the 403 alone is environment-coupled: an outbound proxy can also
	// return 403 for a private dial even if this block branch were removed.
	if !strings.Contains(logs.String(), "Blocked request to private address: 10.0.0.1") {
		t.Errorf("expected private-address block log for the fallback host, got: %q", logs.String())
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for private fallback host, got %d", w.Code)
	}
}
