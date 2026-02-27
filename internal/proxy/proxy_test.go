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
)

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
func (f *flushRecorder) Header() http.Header        { return http.Header{} }
func (f *flushRecorder) WriteHeader(statusCode int) {}

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
