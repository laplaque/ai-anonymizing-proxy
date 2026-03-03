package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
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
