package proxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
	"ai-anonymizing-proxy/internal/mitm"
)

// TestIsAuthRequest_PathBypasses verifies that the auth path matching logic
// cannot be bypassed via common path manipulation techniques.
// This is a security-critical test covering issue #18.
func TestIsAuthRequest_PathBypasses(t *testing.T) {
	// Set up a server with /oauth as an auth path
	cfg := &config.Config{
		AuthDomains: []string{"auth.example.com"},
		AuthPaths:   []string{"/oauth", "/login", "/v1/auth"},
	}
	domains := management.NewDomainRegistry(cfg, "")
	srv := New(cfg, domains, nil)

	tests := []struct {
		name   string
		domain string
		path   string
		want   bool
	}{
		// Exact matches — should be auth
		{"exact /oauth", "api.example.com", "/oauth", true},
		{"exact /login", "api.example.com", "/login", true},
		{"exact /v1/auth", "api.example.com", "/v1/auth", true},

		// Sub-paths — should be auth
		{"subpath /oauth/callback", "api.example.com", "/oauth/callback", true},
		{"subpath /oauth/token", "api.example.com", "/oauth/token", true},
		{"subpath /login/sso", "api.example.com", "/login/sso", true},
		{"subpath /v1/auth/token", "api.example.com", "/v1/auth/token", true},

		// Suffix bypass attempts — must NOT be auth
		{"suffix bypass /oauthx", "api.example.com", "/oauthx", false},
		{"suffix bypass /oauth2", "api.example.com", "/oauth2", false},
		{"suffix bypass /loginx", "api.example.com", "/loginx", false},
		{"suffix bypass /v1/authz", "api.example.com", "/v1/authz", false},

		// Path traversal attempts — must NOT be auth (path.Clean normalizes these)
		{"traversal /oauth/../secret", "api.example.com", "/oauth/../secret", false},
		{"traversal /oauth/./callback", "api.example.com", "/oauth/./callback", true}, // normalizes to /oauth/callback
		{"traversal /oauth/../oauth", "api.example.com", "/oauth/../oauth", true},     // normalizes to /oauth

		// Double-slash normalization
		{"double slash //oauth", "api.example.com", "//oauth", true},                   // normalizes to /oauth
		{"double slash /oauth//callback", "api.example.com", "/oauth//callback", true}, // normalizes to /oauth/callback

		// URL-encoded paths (these come URL-decoded from net/http)
		// The path "/oauth%2Fx" would be delivered as "/oauth/x" by net/http
		{"encoded subpath", "api.example.com", "/oauth/x", true},

		// Trailing slash
		{"trailing slash /oauth/", "api.example.com", "/oauth/", true},
		{"trailing slash /login/", "api.example.com", "/login/", true},

		// Non-auth paths
		{"non-auth /api/v1", "api.example.com", "/api/v1", false},
		{"non-auth /status", "api.example.com", "/status", false},
		{"non-auth /", "api.example.com", "/", false},
		{"non-auth empty", "api.example.com", "", false},

		// Auth domains — always auth regardless of path
		{"auth domain any path", "auth.example.com", "/anything", true},
		{"auth domain non-auth path", "auth.example.com", "/api/v1", true},

		// Auth subdomain prefixes
		{"auth subdomain auth.", "auth.openai.com", "/v1/chat", true},
		{"auth subdomain login.", "login.example.com", "/callback", true},
		{"auth subdomain accounts.", "accounts.google.com", "/oauth2", true},
		{"auth subdomain sso.", "sso.company.com", "/saml", true},
		{"auth subdomain oauth.", "oauth.service.com", "/token", true},

		// Non-auth subdomains (should not match just because they contain "auth")
		{"not auth subdomain api.auth", "api.auth.example.com", "/v1", false},
		{"not auth subdomain myauth.", "myauth.example.com", "/callback", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := srv.isAuthRequest(tt.domain, tt.path)
			if got != tt.want {
				t.Errorf("isAuthRequest(%q, %q) = %v, want %v", tt.domain, tt.path, got, tt.want)
			}
		})
	}
}

// TestMatchesAuthPath tests the matchesAuthPath helper function directly.
func TestMatchesAuthPath(t *testing.T) {
	tests := []struct {
		cleanPath string
		authPath  string
		want      bool
	}{
		// Exact matches
		{"/oauth", "/oauth", true},
		{"/login", "/login", true},

		// Sub-path matches
		{"/oauth/callback", "/oauth", true},
		{"/oauth/token/refresh", "/oauth", true},

		// Non-matches (suffix bypass)
		{"/oauthx", "/oauth", false},
		{"/oauth2", "/oauth", false},

		// Edge cases
		{"/", "/", true},
		{"/oauth", "/", false},    // "/" only matches exactly "/" (safer default)
		{"/oau", "/oauth", false}, // shorter path
		{"", "/oauth", false},     // empty path
	}

	for _, tt := range tests {
		t.Run(tt.cleanPath+"_vs_"+tt.authPath, func(t *testing.T) {
			got := matchesAuthPath(tt.cleanPath, tt.authPath)
			if got != tt.want {
				t.Errorf("matchesAuthPath(%q, %q) = %v, want %v", tt.cleanPath, tt.authPath, got, tt.want)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      net.IP
		private bool
	}{
		// Private: 10.x.x.x range (covered by the /8 CIDR)
		{net.ParseIP("10.0.0.52"), true},
		{net.ParseIP("10.0.0.100"), true},
		{net.ParseIP("10.0.0.99"), true},

		// Private: IPv6
		{net.ParseIP("::1"), true},
		{net.ParseIP("fc00::1"), true},
		{net.ParseIP("fdab::1"), true},
		{net.ParseIP("fe80::1"), true},
		{net.ParseIP("fe80::abcd:1234"), true},

		// Public IPv4 — byte arrays avoid the PII anonymizer's IPv4 regex
		{net.IP{8, 8, 8, 8}, false},       // 8.8.8.8  (Google DNS)
		{net.IP{1, 1, 1, 1}, false},       // 1.1.1.1  (Cloudflare)
		{net.IP{93, 184, 216, 34}, false}, // 93.184.216.34 (example.com)

		// Private: loopback and link-local (byte arrays to survive PII anonymizer)
		{net.IP{127, 0, 0, 1}, true},       // loopback
		{net.IP{169, 254, 169, 254}, true}, // link-local / AWS IMDS

		// Public IPv6 (not matched by IPv4 regex; naturally safe to write)
		{net.ParseIP("2607:f8b0:4004:800::200e"), false},
	}
	for _, tt := range tests {
		if got := isPrivateIP(tt.ip); got != tt.private {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}

func TestIsPrivateHost_Literal(t *testing.T) {
	// Build public IP strings at runtime so the source doesn't contain dotted-quad
	// literals that the PII anonymizer would replace with 10.0.0.x.
	publicDNS := fmt.Sprintf("%d.%d.%d.%d:53", 8, 8, 8, 8) // "8.8.8.8:53"
	publicHost := fmt.Sprintf("%d.%d.%d.%d", 1, 1, 1, 1)   // "1.1.1.1"

	tests := []struct {
		host    string
		private bool
	}{
		// Literal private IPs (isPrivateHost only checks literals — no DNS)
		{"10.0.0.52:8080", true},
		{"10.0.0.99", true},
		{"[::1]:80", true},
		{"[fe80::1]:443", true},
		// Literal public IPs (built at runtime)
		{publicDNS, false},
		{publicHost, false},
		// Non-IP hostnames are not resolved by isPrivateHost (TOCTOU safety)
		{"example.com", false},
		{"localhost", false},
	}
	for _, tt := range tests {
		if got := isPrivateHost(tt.host); got != tt.private {
			t.Errorf("isPrivateHost(%q) = %v, want %v", tt.host, got, tt.private)
		}
	}
}

func TestSsrfSafeDialContext_BlocksPrivateIP(t *testing.T) {
	dialer := &net.Dialer{Timeout: 1}
	dialFn := ssrfSafeDialContext(dialer)

	// localhost resolves to ::1 on macOS (/etc/hosts); ::1/128 is in the blocked range.
	_, err := dialFn(t.Context(), "tcp", "localhost:80")
	if err == nil {
		t.Fatal("expected error dialing localhost, got nil")
	}
}

// flushRecorder implements io.Writer and http.Flusher to verify that
// flushingCopy flushes after each write.
type flushRecorder struct {
	mu      sync.Mutex
	writes  int
	flushes int
	buf     bytes.Buffer
}

func (f *flushRecorder) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	return f.buf.Write(p)
}

func (f *flushRecorder) Flush() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushes++
}

// Header and WriteHeader satisfy http.ResponseWriter (needed for the Flusher cast).
func (f *flushRecorder) Header() http.Header { return http.Header{} }
func (f *flushRecorder) WriteHeader(_ int)   {}

func TestFlushingCopy_FlushesPerWrite(t *testing.T) {
	// Simulate a streaming SSE response: three separate chunks arriving over time.
	chunks := "data: chunk1\n\ndata: chunk2\n\ndata: chunk3\n\n"
	src := &slowReader{data: []byte(chunks), chunkSize: 14} // one SSE event per read
	dst := &flushRecorder{}

	flushingCopy(dst, src)

	dst.mu.Lock()
	defer dst.mu.Unlock()

	if dst.writes == 0 {
		t.Fatal("expected at least one write, got 0")
	}
	if dst.flushes != dst.writes {
		t.Errorf("flushes (%d) should equal writes (%d)", dst.flushes, dst.writes)
	}
	if got := dst.buf.String(); got != chunks {
		t.Errorf("content mismatch:\n got: %q\nwant: %q", got, chunks)
	}
}

func TestFlushingCopy_NoFlusher(t *testing.T) {
	// When dst does not implement http.Flusher, flushingCopy should still copy all data.
	src := strings.NewReader("hello world")
	var dst bytes.Buffer

	flushingCopy(&dst, src)

	if got := dst.String(); got != "hello world" {
		t.Errorf("got %q, want %q", got, "hello world")
	}
}

// slowReader returns at most chunkSize bytes per Read, simulating chunked arrival.
type slowReader struct {
	data      []byte
	chunkSize int
	offset    int
}

func (r *slowReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	end := r.offset + r.chunkSize
	if end > len(r.data) {
		end = len(r.data)
	}
	n := copy(p, r.data[r.offset:end])
	r.offset += n
	return n, nil
}

// errorReader always returns an error on Read.
type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("simulated read error")
}

func (errorReader) Close() error { return nil }

// responseRecorder captures HTTP responses for testing.
type responseRecorder struct {
	code   int
	body   bytes.Buffer
	header http.Header
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{header: http.Header{}}
}

func (r *responseRecorder) Header() http.Header         { return r.header }
func (r *responseRecorder) WriteHeader(code int)        { r.code = code }
func (r *responseRecorder) Write(p []byte) (int, error) { return r.body.Write(p) }

func TestProcessMITMRequestBody_AuthPassthrough(t *testing.T) {
	// Set up a minimal server
	cfg := &config.Config{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "test",
		AuthDomains:    []string{},
		AuthPaths:      []string{},
	}
	domains := management.NewDomainRegistry(cfg, "")
	srv := New(cfg, domains, nil)
	defer func() { _ = srv.Close() }()

	// Create a request (body doesn't matter for auth passthrough)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "https://api.example.com/v1/chat", strings.NewReader(`{"test": "data"}`))
	req.Header.Set("Content-Type", "application/json")

	rw := newResponseRecorder()
	ctx := mitmContext{host: "api.example.com:443", domain: "api.example.com", remoteHash: "test123"}

	// Call with isAuth=true
	sessionID, ok := srv.processMITMRequestBody(rw, req, ctx, true)

	if !ok {
		t.Errorf("expected ok=true for auth passthrough, got false")
	}
	if sessionID != "" {
		t.Errorf("expected empty sessionID for auth passthrough, got %q", sessionID)
	}
}

func TestProcessMITMRequestBody_AnonymizationError(t *testing.T) {
	// Set up a minimal server
	cfg := &config.Config{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "test",
		AuthDomains:    []string{},
		AuthPaths:      []string{},
	}
	domains := management.NewDomainRegistry(cfg, "")
	srv := New(cfg, domains, nil)
	defer func() { _ = srv.Close() }()

	// Create a request with an errorReader body to trigger read error
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "https://api.example.com/v1/chat", errorReader{})
	req.ContentLength = 100 // non-zero to trigger body read

	rw := newResponseRecorder()
	ctx := mitmContext{host: "api.example.com:443", domain: "api.example.com", remoteHash: "test123"}

	// Call with isAuth=false to trigger anonymization
	sessionID, ok := srv.processMITMRequestBody(rw, req, ctx, false)

	if ok {
		t.Errorf("expected ok=false for anonymization error, got true")
	}
	if sessionID != "" {
		t.Errorf("expected empty sessionID on error, got %q", sessionID)
	}
	if rw.code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected status %d, got %d", http.StatusRequestEntityTooLarge, rw.code)
	}
}

func TestProcessMITMRequestBody_SuccessfulAnonymization(t *testing.T) {
	// Set up a minimal server
	cfg := &config.Config{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "test",
		AuthDomains:    []string{},
		AuthPaths:      []string{},
	}
	domains := management.NewDomainRegistry(cfg, "")
	srv := New(cfg, domains, nil)
	defer func() { _ = srv.Close() }()

	// Create a request with valid JSON body
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "https://api.example.com/v1/chat", strings.NewReader(`{"message": "hello"}`))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(`{"message": "hello"}`))

	rw := newResponseRecorder()
	ctx := mitmContext{host: "api.example.com:443", domain: "api.example.com", remoteHash: "test123"}

	// Call with isAuth=false to trigger anonymization
	sessionID, ok := srv.processMITMRequestBody(rw, req, ctx, false)

	if !ok {
		t.Errorf("expected ok=true for successful anonymization, got false")
	}
	if sessionID == "" {
		t.Errorf("expected non-empty sessionID for successful anonymization")
	}
	// Clean up the session
	if sessionID != "" {
		srv.anon.DeleteSession(sessionID)
	}
}

// --- helpers for new tests ---

func newTestProxyServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "test",
		AIAPIDomains:   []string{"api.openai.com"},
		AuthDomains:    []string{"auth.example.com"},
		AuthPaths:      []string{"/oauth"},
		EnabledPacks:   []string{"GLOBAL"},
	}
	domains := management.NewDomainRegistry(cfg, "")
	srv := New(cfg, domains, metrics.New())
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// newTestProxyServerAllowLocal creates a proxy that allows connections to
// localhost (overriding SSRF protection) so httptest backends are reachable.
func newTestProxyServerAllowLocal(t *testing.T, aiDomains, authDomains []string) *Server {
	t.Helper()
	cfg := &config.Config{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "test",
		AIAPIDomains:   aiDomains,
		AuthDomains:    authDomains,
		AuthPaths:      []string{"/oauth"},
		EnabledPacks:   []string{"GLOBAL"},
	}
	domains := management.NewDomainRegistry(cfg, "")
	srv := New(cfg, domains, metrics.New())
	// Override dialContext to allow local connections (bypass SSRF for tests)
	dialer := &net.Dialer{Timeout: 5e9}
	srv.dialContext = dialer.DialContext
	srv.transport.DialContext = dialer.DialContext
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// backendHostPort returns the "localhost:<port>" form of an httptest server URL.
// Using "localhost" instead of the raw IP avoids isPrivateHost literal IP checks.
func backendHostPort(t *testing.T, serverURL, scheme string) string {
	t.Helper()
	raw := strings.TrimPrefix(serverURL, scheme+"://")
	_, port, err := net.SplitHostPort(raw)
	if err != nil {
		t.Fatalf("bad server URL %q: %v", serverURL, err)
	}
	return "localhost:" + port
}

// --- hashRemoteAddr ---

func TestHashRemoteAddr(t *testing.T) {
	h := hashRemoteAddr("127.0.0.1:12345")
	if len(h) != 8 {
		t.Errorf("expected 8-char hash, got %d chars: %q", len(h), h)
	}
	// Deterministic
	if h2 := hashRemoteAddr("127.0.0.1:12345"); h != h2 {
		t.Errorf("expected deterministic hash, got %q then %q", h, h2)
	}
	// Different input, different hash
	if h3 := hashRemoteAddr("192.168.1.1:80"); h == h3 {
		t.Error("different addresses should produce different hashes")
	}
}

// --- toSet ---

func TestToSet(t *testing.T) {
	s := toSet([]string{"a", "b", "c"})
	if len(s) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(s))
	}
	for _, k := range []string{"a", "b", "c"} {
		if !s[k] {
			t.Errorf("expected %q in set", k)
		}
	}
	if s["d"] {
		t.Error("unexpected key in set")
	}
	// Empty input
	s2 := toSet(nil)
	if len(s2) != 0 {
		t.Errorf("expected empty set, got %d", len(s2))
	}
}

// --- removeHopByHop ---

func TestRemoveHopByHop(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "keep-alive")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Authorization", "Basic abc")
	h.Set("Content-Type", "application/json")
	h.Set("X-Custom", "value")

	removeHopByHop(h)

	if h.Get("Connection") != "" {
		t.Error("Connection header should be removed")
	}
	if h.Get("Keep-Alive") != "" {
		t.Error("Keep-Alive header should be removed")
	}
	if h.Get("Proxy-Authorization") != "" {
		t.Error("Proxy-Authorization header should be removed")
	}
	if h.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should be preserved")
	}
	if h.Get("X-Custom") != "value" {
		t.Error("X-Custom should be preserved")
	}
}

// --- copyHeader ---

func TestCopyHeader(t *testing.T) {
	src := http.Header{}
	src.Set("Content-Type", "text/plain")
	src.Add("X-Multi", "a")
	src.Add("X-Multi", "b")

	dst := http.Header{}
	copyHeader(dst, src)

	if dst.Get("Content-Type") != "text/plain" {
		t.Errorf("Content-Type not copied: %q", dst.Get("Content-Type"))
	}
	if vals := dst.Values("X-Multi"); len(vals) != 2 {
		t.Errorf("expected 2 X-Multi values, got %d", len(vals))
	}
}

// --- decompressResponse ---

func TestDecompressResponse_Gzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte("hello gzip")); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(&buf),
	}
	resp.Header.Set("Content-Encoding", "gzip")

	if err := decompressResponse(resp); err != nil {
		t.Fatalf("decompressResponse gzip: %v", err)
	}
	if resp.Header.Get("Content-Encoding") != "" {
		t.Error("Content-Encoding should be removed after decompression")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello gzip" {
		t.Errorf("expected 'hello gzip', got %q", string(body))
	}
}

func TestDecompressResponse_Deflate(t *testing.T) {
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := fw.Write([]byte("hello deflate")); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}

	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(&buf),
	}
	resp.Header.Set("Content-Encoding", "deflate")

	if err := decompressResponse(resp); err != nil {
		t.Fatalf("decompressResponse deflate: %v", err)
	}
	if resp.Header.Get("Content-Encoding") != "" {
		t.Error("Content-Encoding should be removed after decompression")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello deflate" {
		t.Errorf("expected 'hello deflate', got %q", string(body))
	}
}

func TestDecompressResponse_Identity(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(strings.NewReader("plain")),
	}
	resp.Header.Set("Content-Encoding", "identity")

	if err := decompressResponse(resp); err != nil {
		t.Fatalf("decompressResponse identity: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "plain" {
		t.Errorf("expected 'plain', got %q", string(body))
	}
}

func TestDecompressResponse_Empty(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(strings.NewReader("plain")),
	}
	if err := decompressResponse(resp); err != nil {
		t.Fatalf("decompressResponse empty: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "plain" {
		t.Errorf("expected 'plain', got %q", string(body))
	}
}

func TestDecompressResponse_Unsupported(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(strings.NewReader("data")),
	}
	resp.Header.Set("Content-Encoding", "br")
	// Should not error, just log and leave body unchanged
	if err := decompressResponse(resp); err != nil {
		t.Fatalf("decompressResponse unsupported: %v", err)
	}
}

func TestDecompressResponse_InvalidGzip(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(strings.NewReader("not gzip data")),
	}
	resp.Header.Set("Content-Encoding", "gzip")
	err := decompressResponse(resp)
	if err == nil {
		t.Error("expected error for invalid gzip data")
	}
}

// --- isStreamingResponse ---

func TestIsStreamingResponse(t *testing.T) {
	tests := []struct {
		contentType string
		want        bool
	}{
		{"text/event-stream", true},
		{"text/event-stream; charset=utf-8", true},
		{"application/json", false},
		{"text/plain", false},
		{"", false},
	}
	for _, tt := range tests {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("Content-Type", tt.contentType)
		if got := isStreamingResponse(resp); got != tt.want {
			t.Errorf("isStreamingResponse(%q) = %v, want %v", tt.contentType, got, tt.want)
		}
	}
}

// --- ReverseProxy ---

func TestReverseProxy(t *testing.T) {
	srv := newTestProxyServer(t)
	rp := srv.ReverseProxy()
	if rp == nil {
		t.Fatal("ReverseProxy() returned nil")
	}
}

// --- deanonymizeResponseBody ---

func TestDeanonymizeResponseBody_NoSessionID(t *testing.T) {
	srv := newTestProxyServer(t)
	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(strings.NewReader("body")),
	}
	// Should not panic or modify when sessionID is empty
	srv.deanonymizeResponseBody(resp, "")
}

func TestDeanonymizeResponseBody_NilResp(t *testing.T) {
	srv := newTestProxyServer(t)
	// Should not panic
	srv.deanonymizeResponseBody(nil, "session123")
}

func TestDeanonymizeResponseBody_NonStreaming(t *testing.T) {
	srv := newTestProxyServer(t)
	resp := &http.Response{
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader("hello world")),
		ContentLength: 11,
	}
	resp.Header.Set("Content-Type", "application/json")

	srv.deanonymizeResponseBody(resp, "test-session")
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello world" {
		t.Errorf("expected 'hello world', got %q", string(body))
	}
}

func TestDeanonymizeResponseBody_Streaming(t *testing.T) {
	srv := newTestProxyServer(t)
	resp := &http.Response{
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader("data: hello\n\n")),
		ContentLength: -1,
	}
	resp.Header.Set("Content-Type", "text/event-stream")

	srv.deanonymizeResponseBody(resp, "test-session")
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "hello") {
		t.Errorf("expected body to contain 'hello', got %q", string(body))
	}
}

func TestDeanonymizeResponseBody_GzipEncoded(t *testing.T) {
	srv := newTestProxyServer(t)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte("compressed body")); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(&buf),
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Encoding", "gzip")

	srv.deanonymizeResponseBody(resp, "test-session")
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "compressed body" {
		t.Errorf("expected 'compressed body', got %q", string(body))
	}
}

func TestDeanonymizeResponseBody_ReadError(t *testing.T) {
	srv := newTestProxyServer(t)
	resp := &http.Response{
		Header: http.Header{},
		Body:   errorReader{},
	}
	resp.Header.Set("Content-Type", "application/json")
	// Should not panic; body should be replaced with empty
	srv.deanonymizeResponseBody(resp, "test-session")
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("expected empty body on read error, got %q", string(body))
	}
}

// --- recordMITMMetrics ---

func TestRecordMITMMetrics_NilMetrics(t *testing.T) {
	cfg := &config.Config{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "test",
	}
	domains := management.NewDomainRegistry(cfg, "")
	srv := New(cfg, domains, nil)
	defer func() { _ = srv.Close() }()
	// Verify no panic with nil metrics
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("recordMITMMetrics panicked with nil metrics: %v", r)
		}
	}()
	srv.recordMITMMetrics(false)
	srv.recordMITMMetrics(true)
}

func TestRecordMITMMetrics_WithMetrics(t *testing.T) {
	srv := newTestProxyServer(t)
	srv.recordMITMMetrics(false) // anonymized
	srv.recordMITMMetrics(true)  // auth

	snap := srv.m.Snapshot()
	if snap.Requests.Total != 2 {
		t.Errorf("expected 2 total requests, got %d", snap.Requests.Total)
	}
}

// --- ServeHTTP dispatching ---

func TestServeHTTP_HTTP_Passthrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "backend response")
	}))
	defer backend.Close()

	host := backendHostPort(t, backend.URL, "http")
	srv := newTestProxyServerAllowLocal(t, nil, nil)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://"+host+"/test", nil)
	req.Host = host
	req.URL.Host = host

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "backend response") {
		t.Errorf("expected 'backend response', got %q", w.Body.String())
	}
}

func TestServeHTTP_HTTP_AIAnonymization(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer backend.Close()

	host := backendHostPort(t, backend.URL, "http")
	srv := newTestProxyServerAllowLocal(t, []string{host}, nil)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "http://"+host+"/v1/chat",
		strings.NewReader(`{"message":"hello"}`))
	req.Host = host
	req.URL.Host = host
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestServeHTTP_HTTP_AuthPassthrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "auth OK")
	}))
	defer backend.Close()

	host := backendHostPort(t, backend.URL, "http")
	srv := newTestProxyServerAllowLocal(t, []string{host}, []string{host})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://"+host+"/oauth/callback", nil)
	req.Host = host
	req.URL.Host = host

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleHTTP_PrivateHostBlocked(t *testing.T) {
	srv := newTestProxyServer(t)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://10.0.0.52:8080/test", nil)
	req.Host = "10.0.0.52:8080"
	req.URL.Host = "10.0.0.52:8080"

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for private host, got %d", w.Code)
	}
}

func TestHandleHTTP_UpstreamError(t *testing.T) {
	srv := newTestProxyServerAllowLocal(t, nil, nil)

	// Point to a non-existent backend
	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://localhost:1/nonexistent", nil)
	req.Host = "localhost:1"
	req.URL.Host = "localhost:1"

	w := httptest.NewRecorder()
	srv.handleHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", w.Code)
	}
}

func TestHandleHTTP_EmptyBody_AIRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	host := backendHostPort(t, backend.URL, "http")
	srv := newTestProxyServerAllowLocal(t, []string{host}, nil)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://"+host+"/v1/models", nil)
	req.Host = host
	req.URL.Host = host

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --- handleTunnel / CONNECT ---

func TestServeHTTP_CONNECT_PrivateHost(t *testing.T) {
	srv := newTestProxyServer(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "http://10.0.0.52:443", nil)
	req.Host = "10.0.0.52:443"

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// handleOpaqueTunnel should block private addresses
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for CONNECT to private host, got %d", w.Code)
	}
}

// --- anonymizeRequestBody ---

func TestAnonymizeRequestBody_NilBody(t *testing.T) {
	srv := newTestProxyServer(t)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	sessionID, err := srv.anonymizeRequestBody(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionID != "" {
		t.Errorf("expected empty sessionID for nil body, got %q", sessionID)
	}
}

func TestAnonymizeRequestBody_ZeroContentLength(t *testing.T) {
	srv := newTestProxyServer(t)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "http://example.com",
		strings.NewReader(""))
	req.ContentLength = 0
	sessionID, err := srv.anonymizeRequestBody(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionID != "" {
		t.Errorf("expected empty sessionID for zero content length, got %q", sessionID)
	}
}

func TestAnonymizeRequestBody_ValidBody(t *testing.T) {
	srv := newTestProxyServer(t)
	body := `{"prompt":"test message"}`
	req := httptest.NewRequestWithContext(context.Background(), "POST", "http://example.com",
		strings.NewReader(body))
	req.ContentLength = int64(len(body))
	sessionID, err := srv.anonymizeRequestBody(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionID == "" {
		t.Error("expected non-empty sessionID")
	}
	// Verify body was replaced
	newBody, _ := io.ReadAll(req.Body)
	if len(newBody) == 0 {
		t.Error("expected non-empty body after anonymization")
	}
	srv.anon.DeleteSession(sessionID)
}

func TestAnonymizeRequestBody_ReadError(t *testing.T) {
	srv := newTestProxyServer(t)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "http://example.com", errorReader{})
	req.ContentLength = 100
	_, err := srv.anonymizeRequestBody(req)
	if err == nil {
		t.Error("expected error for read error")
	}
}

// --- forward with response decompression ---

func TestForward_WithGzipResponse(t *testing.T) {
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	if _, err := gw.Write([]byte(`{"result":"ok"}`)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	gzData := gzBuf.Bytes()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(gzData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer backend.Close()

	host := backendHostPort(t, backend.URL, "http")
	srv := newTestProxyServerAllowLocal(t, []string{host}, nil)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "http://"+host+"/v1/chat",
		strings.NewReader(`{"message":"hello"}`))
	req.Host = host
	req.URL.Host = host
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(`{"message":"hello"}`))

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --- New with CA files ---

func TestNew_WithInvalidCAFiles(t *testing.T) {
	cfg := &config.Config{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "test",
		CACertFile:     "/nonexistent/cert.pem",
		CAKeyFile:      "/nonexistent/key.pem",
		EnabledPacks:   []string{"GLOBAL"},
	}
	domains := management.NewDomainRegistry(cfg, "")
	srv := New(cfg, domains, nil)
	defer func() { _ = srv.Close() }()
	if srv.ca != nil {
		t.Error("expected nil CA with nonexistent cert files")
	}
}

// --- Close ---

func TestServer_Close(t *testing.T) {
	srv := newTestProxyServer(t)
	if err := srv.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// --- ssrfSafeDialContext edge cases ---

func TestSsrfSafeDialContext_NoPort(t *testing.T) {
	dialer := &net.Dialer{Timeout: 1}
	dialFn := ssrfSafeDialContext(dialer)
	// Address without port — falls back to plain DialContext
	_, err := dialFn(t.Context(), "tcp", "invalid-no-port")
	if err == nil {
		t.Error("expected error for address without port")
	}
}

// --- handleHTTP with host from URL ---

func TestHandleHTTP_HostFromURL(t *testing.T) {
	// When req.Host is empty, handleHTTP should fall back to URL.Host for domain matching.
	// We can't test a real round-trip to localhost (SSRF), but we can verify the code path
	// by using a private host that should be blocked — the key is it takes the URL.Host path.
	srv := newTestProxyServerAllowLocal(t, nil, nil)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://10.0.0.52:8080/test", nil)
	req.Host = "" // empty host, should fall back to URL.Host
	req.URL.Host = "10.0.0.52:8080"

	w := httptest.NewRecorder()
	srv.handleHTTP(w, req)

	// Private host gets blocked — but it exercises the host-from-URL code path
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for private host via URL, got %d", w.Code)
	}
}

// --- forward sets scheme ---

func TestForward_SetsScheme(t *testing.T) {
	// When URL.Scheme is empty, forward() should default to "http"
	srv := newTestProxyServerAllowLocal(t, nil, nil)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://10.0.0.52:8080/test", nil)
	req.URL.Scheme = ""
	req.URL.Host = "10.0.0.52:8080"

	w := httptest.NewRecorder()
	srv.forward(w, req, "")

	// Private host gets blocked, but the code path that sets scheme is exercised
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for private host, got %d", w.Code)
	}
}

// --- serveMITMRequest (integration) ---

func TestServeMITMRequest_Integration(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer backend.Close()

	backendHost := strings.TrimPrefix(backend.URL, "https://")
	srv := newTestProxyServerAllowLocal(t, []string{backendHost}, nil)
	srv.transport, _ = backend.Client().Transport.(*http.Transport)

	req := httptest.NewRequestWithContext(context.Background(), "POST", backend.URL+"/v1/chat",
		strings.NewReader(`{"prompt":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(`{"prompt":"test"}`))

	rw := httptest.NewRecorder()
	ctx := mitmContext{host: backendHost, domain: backendHost, remoteHash: "test"}

	srv.serveMITMRequest(rw, req, ctx)

	if rw.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
}

func TestServeMITMRequest_AuthPassthrough(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "auth pass")
	}))
	defer backend.Close()

	backendHost := strings.TrimPrefix(backend.URL, "https://")
	srv := newTestProxyServerAllowLocal(t, []string{backendHost}, []string{backendHost})
	srv.transport, _ = backend.Client().Transport.(*http.Transport)

	req := httptest.NewRequestWithContext(context.Background(), "GET", backend.URL+"/anything", nil)
	rw := httptest.NewRecorder()
	ctx := mitmContext{host: backendHost, domain: backendHost, remoteHash: "test"}

	srv.serveMITMRequest(rw, req, ctx)

	if rw.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rw.Code)
	}
}

// --- handleHTTP metrics and logging branches ---

func TestHandleHTTP_PassthroughMetrics(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	host := backendHostPort(t, backend.URL, "http")
	// Non-AI, non-auth domain: exercises the passthrough metrics path
	srv := newTestProxyServerAllowLocal(t, nil, nil)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://"+host+"/test", nil)
	req.Host = host
	req.URL.Host = host

	w := httptest.NewRecorder()
	srv.handleHTTP(w, req)

	snap := srv.m.Snapshot()
	if snap.Requests.Passthrough == 0 {
		t.Error("expected passthrough counter to be incremented")
	}
}

func TestHandleHTTP_AIAnonymizationError(t *testing.T) {
	host := "example.com:80"
	srv := newTestProxyServerAllowLocal(t, []string{"example.com"}, nil)

	// AI request with body that causes read error
	req := httptest.NewRequestWithContext(context.Background(), "POST", "http://"+host+"/v1/chat", errorReader{})
	req.Host = host
	req.URL.Host = host
	req.ContentLength = 100

	w := httptest.NewRecorder()
	srv.handleHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", w.Code)
	}
}

// --- handleTunnel dispatch ---

func TestHandleTunnel_NonAIDomain(t *testing.T) {
	srv := newTestProxyServer(t)
	// CONNECT to private IP — goes through handleOpaqueTunnel path
	req := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "http://10.0.0.52:443", nil)
	req.Host = "10.0.0.52:443"

	w := httptest.NewRecorder()
	srv.handleTunnel(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandleTunnel_AIDomainWithoutCA(t *testing.T) {
	// CA is nil, so even an AI domain falls through to the opaque tunnel path.
	// Use a private IP so the tunnel is blocked quickly (no DNS/dial timeout).
	srv := newTestProxyServer(t)
	srv.aiDomains.Add("10.0.0.52")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "http://10.0.0.52:443", nil)
	req.Host = "10.0.0.52:443"

	w := httptest.NewRecorder()
	srv.handleTunnel(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// --- ssrfSafeDialContext additional coverage ---

func TestSsrfSafeDialContext_ResolvesToPrivate(t *testing.T) {
	dialer := &net.Dialer{Timeout: 1e9}
	dialFn := ssrfSafeDialContext(dialer)

	// localhost resolves to 127.0.0.1 or ::1, both private
	_, err := dialFn(t.Context(), "tcp", "localhost:80")
	if err == nil {
		t.Fatal("expected error dialing localhost")
	}
}

func TestForwardMITMRequest_UpstreamError(t *testing.T) {
	srv := newTestProxyServerAllowLocal(t, nil, nil)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "https://localhost:1/fail", nil)
	req.RequestURI = ""
	rw := httptest.NewRecorder()

	srv.forwardMITMRequest(rw, req, "")

	if rw.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rw.Code)
	}
}

// --- handleMITMTunnel ---

// hijackResponseWriter wraps an httptest.ResponseRecorder with hijack support
// using a net.Pipe for the client connection.
type hijackResponseWriter struct {
	*httptest.ResponseRecorder
	clientConn net.Conn
	serverConn net.Conn
}

func newHijackResponseWriter() *hijackResponseWriter {
	client, server := net.Pipe()
	return &hijackResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		clientConn:       client,
		serverConn:       server,
	}
}

func (h *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw := bufio.NewReadWriter(bufio.NewReader(h.serverConn), bufio.NewWriter(h.serverConn))
	return h.serverConn, rw, nil
}

func TestHandleMITMTunnel(t *testing.T) {
	// Set up a TLS backend that echoes requests
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer backend.Close()

	backendHost := strings.TrimPrefix(backend.URL, "https://")

	// Create a proxy server with a real CA
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca-cert.pem")
	keyFile := filepath.Join(dir, "ca-key.pem")

	cfg := &config.Config{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "test",
		AIAPIDomains:   []string{backendHost},
		AuthDomains:    []string{},
		AuthPaths:      []string{},
		CACertFile:     certFile,
		CAKeyFile:      keyFile,
		EnabledPacks:   []string{"GLOBAL"},
	}
	domains := management.NewDomainRegistry(cfg, "")
	srv := New(cfg, domains, metrics.New())
	defer func() { _ = srv.Close() }()

	// Override transport to trust the backend's TLS cert
	srv.transport = backend.Client().Transport.(*http.Transport) //nolint:errcheck // test setup

	if srv.ca == nil {
		t.Fatal("expected CA to be loaded")
	}

	// Create a hijack-capable response writer
	hw := newHijackResponseWriter()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "http://"+backendHost, nil)
	req.Host = backendHost
	req.RemoteAddr = "127.0.0.1:12345"

	// Run handleMITMTunnel in a goroutine (it will hijack and serve).
	// The goroutine may outlive the test due to singleConnListener blocking on
	// second Accept(); this is by design in the production code.
	go srv.handleMITMTunnel(hw, req, backendHost, backendHost)

	// Act as a TLS client on the hijacked connection.
	roots := x509.NewCertPool()
	certPEM, readErr := os.ReadFile(certFile)
	if readErr != nil {
		t.Fatalf("read CA cert: %v", readErr)
	}
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add CA cert to pool")
	}
	tlsClient := tls.Client(hw.clientConn, &tls.Config{
		ServerName: backendHost,
		RootCAs:    roots,
		NextProtos: []string{"http/1.1"},
	})
	defer func() { _ = tlsClient.Close() }()

	if hsErr := tlsClient.HandshakeContext(t.Context()); hsErr != nil {
		t.Fatalf("TLS handshake: %v", hsErr)
	}

	// Send an HTTP request through the MITM tunnel
	httpReq, _ := http.NewRequestWithContext(t.Context(), "POST", "https://"+backendHost+"/v1/chat",
		strings.NewReader(`{"prompt":"test"}`))
	httpReq.Header.Set("Content-Type", "application/json")
	if writeErr := httpReq.Write(tlsClient); writeErr != nil {
		t.Fatalf("write request: %v", writeErr)
	}

	resp, respErr := http.ReadResponse(bufio.NewReader(tlsClient), httpReq)
	if respErr != nil {
		t.Fatalf("ReadResponse: %v", respErr)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 through MITM tunnel, got %d", resp.StatusCode)
	}
}

func TestHandleMITMTunnel_NoHijacker(t *testing.T) {
	// When ResponseWriter doesn't support hijacking, should fall through to opaque tunnel
	srv := newTestProxyServer(t)

	// Manually set up CA so the MITM path is tried
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca-cert.pem")
	keyFile := filepath.Join(dir, "ca-key.pem")
	if err := mitm.GenerateCA(certFile, keyFile); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	ca, err := mitm.LoadCA(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	srv.ca = ca

	// Use private IP so the opaque tunnel fallback blocks quickly
	srv.aiDomains.Add("10.0.0.52")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "http://10.0.0.52:443", nil)
	req.Host = "10.0.0.52:443"
	req.RemoteAddr = "127.0.0.1:12345"

	// httptest.NewRecorder does NOT implement http.Hijacker
	w := httptest.NewRecorder()
	srv.handleMITMTunnel(w, req, "10.0.0.52:443", "10.0.0.52")

	// Falls through to opaque tunnel which blocks the private IP
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 fallback, got %d", w.Code)
	}
}
