package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
)

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
		// No colon -> net.SplitHostPort fails -> d.DialContext path.
		// Use a canceled context so the dial returns immediately.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := dialFn(ctx, "tcp", "hostwithoutport")
		if err == nil {
			t.Fatal("expected error from direct dial of invalid address")
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
	// Fallback is a UnixNano integer string: all digits.
	for _, c := range sessionID {
		if c < '0' || c > '9' {
			t.Fatalf("expected all-digit fallback sessionID, got %q", sessionID)
		}
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

	// Bad gzip -> decompressResponse returns an error -> error-log branch.
	// Must not panic; should still proceed and produce a readable body.
	srv.deanonymizeResponseBody(resp, "sess-x", "api.example.com")
	if resp.Body == nil {
		t.Fatal("expected non-nil body after deanonymize")
	}
	_, _ = io.ReadAll(resp.Body)
}

// --- E) Handler-path branches ---

// fakeConnHijacker is an http.Hijacker whose Hijack() always returns an error.
type fakeConnHijacker struct {
	*httptest.ResponseRecorder
}

func newFakeConnHijacker() *fakeConnHijacker {
	return &fakeConnHijacker{ResponseRecorder: httptest.NewRecorder()}
}

func (fakeConnHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
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
	srv.handleTunnel(w, req)

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

	// WriteHeader(200) is called before Hijack(); after Hijack errors it returns.
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 written before hijack, got %d", w.Code)
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

	if hw.Code != http.StatusOK {
		t.Fatalf("expected 200 written before hijack, got %d", hw.Code)
	}
}

// pipeHijacker is an http.Hijacker that returns a preset net.Conn.
type pipeHijacker struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (h *pipeHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
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

	// WriteHeader(200) is sent before Hijack(); Hijack errors then returns.
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 written before hijack, got %d", w.Code)
	}
}

// handleHTTP ANON path: AI domain, non-auth, body with synthetic PII produces a
// non-empty sessionID and exercises the [ANON] log + DeleteSession defer.
func TestHandleHTTP_AnonPath(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	host := backendHostPort(t, backend.URL, "http")
	// handleHTTP matches on the port-stripped host ("localhost"), so register
	// the bare domain (not the host:port form) for the AI-anonymize path.
	srv := newTestProxyServerAllowLocal(t, []string{"localhost"}, nil)

	body := `{"prompt":"contact alice@example.com please"}`
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
}

// forward URL.Host fallback + private-host block.
func TestForward_URLHostFallbackPrivate(t *testing.T) {
	srv := newTestProxyServerAllowLocal(t, nil, nil)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://placeholder/test", nil)
	req.URL.Host = ""     // forces fallback to r.Host
	req.Host = "10.0.0.1" // private -> 403 before any dial

	w := httptest.NewRecorder()
	srv.forward(w, req, "", "domain")

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for private fallback host, got %d", w.Code)
	}
}
