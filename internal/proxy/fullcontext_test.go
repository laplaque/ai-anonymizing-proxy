package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
)

// formerRequestLimit is the hardcoded 50 MiB request-body cutoff that issue
// #152 removed; tests use it only to prove workloads exceed it.
const formerRequestLimit = 50 << 20

const fullContextInstruction = "FULLCTX: reproduce every [PII_*] placeholder exactly."

// localDialer reaches httptest upstreams on loopback, which the proxy's SSRF
// dial check would otherwise refuse.
var localDialer = net.Dialer{Timeout: 5 * time.Second}

// fullContextProxy returns a proxy for plain-HTTP requests to localhost
// upstreams (SSRF dial checks relaxed for httptest) with a fixed PII
// instruction, plus a function applying cfg tweaks before use.
func fullContextProxy(t *testing.T, tweak func(*config.Config)) *Server {
	t.Helper()
	cfg := &config.Config{
		OllamaEndpoint:  "http://localhost:11434",
		OllamaModel:     "test",
		AIAPIDomains:    []string{"localhost"},
		AuthDomains:     []string{},
		AuthPaths:       []string{},
		EnabledPacks:    []string{"GLOBAL"},
		RequestSpoolDir: t.TempDir(),
		PIIInstructions: map[string]string{"default": fullContextInstruction},
	}
	if tweak != nil {
		tweak(cfg)
	}
	srv := New(cfg, management.NewDomainRegistry(cfg, ""), metrics.New())
	srv.anon.SetVerbose(false)
	srv.dialContext = (&localDialer).DialContext
	srv.transport.DialContext = (&localDialer).DialContext
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// recordingUpstream verifies each forwarded body as it streams in and keeps
// the results for the test.
type recordingUpstream struct {
	*httptest.Server
	mu      sync.Mutex
	results []upstreamCheck
	calls   atomic.Int64
}

func newRecordingUpstream(t *testing.T) *recordingUpstream {
	t.Helper()
	u := &recordingUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.calls.Add(1)
		res, err := checkUpstreamBody(r.Body, r.ContentLength)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		u.mu.Lock()
		u.results = append(u.results, res)
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp","choices":[{"message":{"role":"assistant","content":"done"}}]}`)
	}))
	t.Cleanup(u.Close)
	return u
}

// postThroughProxy sends body to the upstream through srv's plain-HTTP path.
func postThroughProxy(t *testing.T, srv *Server, upstreamURL string, body io.Reader, contentLength int64) *httptest.ResponseRecorder {
	t.Helper()
	host := backendHostPort(t, upstreamURL, "http")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+host+"/v1/chat/completions", body)
	req.Host = host
	req.URL.Host = host
	req.ContentLength = contentLength
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// assertForwardedExactly checks the upstream received exactly the expected
// anonymized body: same length and SHA-256, a matching Content-Length, and no
// raw synthetic address.
func assertForwardedExactly(t *testing.T, got upstreamCheck, want workloadDigest) {
	t.Helper()
	if got.leaked {
		t.Error("a raw synthetic email address reached the upstream")
	}
	if got.digest.n != want.n {
		t.Errorf("upstream received %d bytes, want %d", got.digest.n, want.n)
	}
	if got.digest.sum != want.sum {
		t.Errorf("upstream body SHA-256 %x, want %x", got.digest.sum, want.sum)
	}
	if got.contentLength != want.n {
		t.Errorf("upstream Content-Length %d, want %d", got.contentLength, want.n)
	}
}

// largeWorkload exceeds the former 50 MiB cutoff: ~33 MiB of prose, tool
// history and ~32 MiB of inline base64 images.
var largeWorkload = fullContextWorkload{
	turns:       1600,
	proseBytes:  20 << 10,
	images:      4,
	imageBytes:  6 << 20,
	instruction: fullContextInstruction,
}

// TestFullContextRequestBeyondFormerLimit streams a request larger than the
// former 50 MiB cutoff through the plain-HTTP path and verifies the upstream
// receives the complete expected anonymized body, byte for byte, with the
// body spooled to disk rather than held in memory.
func TestFullContextRequestBeyondFormerLimit(t *testing.T) {
	raw, want, err := largeWorkload.digests()
	if err != nil {
		t.Fatal(err)
	}
	if raw.n <= formerRequestLimit || want.n <= formerRequestLimit {
		t.Fatalf("workload is %d raw / %d anonymized bytes; it must exceed the former %d-byte limit", raw.n, want.n, formerRequestLimit)
	}

	srv := fullContextProxy(t, nil)
	up := newRecordingUpstream(t)
	w := postThroughProxy(t, srv, up.URL, largeWorkload.rawStream(), raw.n)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if len(up.results) != 1 {
		t.Fatalf("upstream calls = %d, want 1", len(up.results))
	}
	assertForwardedExactly(t, up.results[0], want)
	if entries, _ := filepathGlob(srv.cfg.RequestSpoolDir); len(entries) != 0 {
		t.Errorf("spool files left behind: %v", entries)
	}
}

func filepathGlob(dir string) ([]string, error) {
	return filepath.Glob(filepath.Join(dir, "*"))
}

// TestFullContextRequestBeyondFormerLimitMITM sends the same request through
// the MITM HTTP/2 path (the production path for HTTPS clients) with an
// unknown body length, and verifies the complete expected body upstream.
func TestFullContextRequestBeyondFormerLimitMITM(t *testing.T) {
	_, want, err := largeWorkload.digests()
	if err != nil {
		t.Fatal(err)
	}

	var got upstreamCheck
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var checkErr error
		got, checkErr = checkUpstreamBody(r.Body, r.ContentLength)
		if checkErr != nil {
			http.Error(w, checkErr.Error(), http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer backend.Close()
	backendHost := strings.TrimPrefix(backend.URL, "https://")

	srv, certFile := newMITMTestServer(t, backendHost)
	srv.anon.SetVerbose(false)
	srv.anon.SetPIIInstructions(map[string]string{"default": fullContextInstruction})
	srv.cfg.RequestSpoolDir = t.TempDir()
	srv.transport, _ = backend.Client().Transport.(*http.Transport) // trust the backend's test cert

	hw := newHijackResponseWriter()
	connect := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "http://"+backendHost, nil)
	connect.Host = backendHost
	connect.RemoteAddr = "127.0.0.1:12345"
	go srv.handleMITMTunnel(hw, connect, backendHost, backendHost)
	tlsClient := mitmTLSClient(t, hw.clientConn, backendHost, certFile, "h2")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"https://"+backendHost+"/v1/chat/completions", largeWorkload.rawStream())
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp := roundTripH2(t, tlsClient, req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		t.Fatalf("response %s over %s", resp.Status, resp.Proto)
	}
	assertForwardedExactly(t, got, want)
}

// TestFullContextConcurrentRequests sends several large requests at once and
// verifies each upstream body independently; sessions must not mix tokens,
// instructions or bytes between requests.
func TestFullContextConcurrentRequests(t *testing.T) {
	const concurrent = 6
	workloads := make([]fullContextWorkload, concurrent)
	raws := make([]workloadDigest, concurrent)
	wants := make(map[[32]byte]bool, concurrent)
	for i := range workloads {
		workloads[i] = fullContextWorkload{
			turns: 200 + 37*i, proseBytes: 16 << 10, images: 1, imageBytes: (2 + i) << 20,
			instruction: fullContextInstruction,
		}
		raw, want, err := workloads[i].digests()
		if err != nil {
			t.Fatal(err)
		}
		raws[i] = raw
		wants[want.sum] = true
	}

	srv := fullContextProxy(t, nil)
	up := newRecordingUpstream(t)
	var wg sync.WaitGroup
	for i := range workloads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := postThroughProxy(t, srv, up.URL, workloads[i].rawStream(), raws[i].n)
			if w.Code != http.StatusOK {
				t.Errorf("request %d: status %d: %s", i, w.Code, w.Body.String())
			}
		}()
	}
	wg.Wait()

	if len(up.results) != concurrent {
		t.Fatalf("upstream calls = %d, want %d", len(up.results), concurrent)
	}
	for _, res := range up.results {
		if res.leaked {
			t.Error("a raw synthetic email address reached the upstream")
		}
		if !wants[res.digest.sum] {
			t.Errorf("an upstream body (%d bytes) matches no expected anonymized request", res.digest.n)
		}
		delete(wants, res.digest.sum)
		if res.contentLength != res.digest.n {
			t.Errorf("Content-Length %d does not match the %d bytes sent", res.contentLength, res.digest.n)
		}
	}
	if snap := srv.m.Snapshot(); snap.Errors.Anonymize != 0 {
		t.Errorf("ErrorsAnonymize = %d, want 0", snap.Errors.Anonymize)
	}
}

// TestFullContextAdminLimitRejectsExplicitly verifies the optional
// maxRequestBodyBytes setting rejects a larger body with 413 and forwards
// nothing, for both declared and streamed lengths.
func TestFullContextAdminLimitRejectsExplicitly(t *testing.T) {
	const limit = 2 << 20
	srv := fullContextProxy(t, func(c *config.Config) { c.MaxRequestBodyBytes = limit })
	up := newRecordingUpstream(t)
	small := fullContextWorkload{turns: 400, proseBytes: 8 << 10, instruction: fullContextInstruction}
	raw, _, err := small.digests()
	if err != nil {
		t.Fatal(err)
	}
	if raw.n <= limit {
		t.Fatalf("workload of %d bytes does not exceed the %d-byte limit", raw.n, limit)
	}
	for name, length := range map[string]int64{"declared": raw.n, "streamed": -1} {
		w := postThroughProxy(t, srv, up.URL, small.rawStream(), length)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: status %d, want 413", name, w.Code)
		}
		if !strings.Contains(w.Body.String(), "maxRequestBodyBytes") {
			t.Errorf("%s: body %q does not name the limit", name, w.Body.String())
		}
	}
	if n := up.calls.Load(); n != 0 {
		t.Errorf("upstream was called %d times for rejected requests", n)
	}

	// A body within the limit still goes through unchanged in behavior.
	within := fullContextWorkload{turns: 20, proseBytes: 8 << 10, instruction: fullContextInstruction}
	raw, want, err := within.digests()
	if err != nil {
		t.Fatal(err)
	}
	if w := postThroughProxy(t, srv, up.URL, within.rawStream(), raw.n); w.Code != http.StatusOK {
		t.Fatalf("within limit: status %d", w.Code)
	}
	assertForwardedExactly(t, up.results[0], want)
}

// TestFullContextSpoolFailureReported verifies that when the spool directory
// is unusable, a body too large for the in-memory spool is rejected with 507
// and a clear message instead of being truncated or forwarded, while small
// bodies that never touch disk still work.
func TestFullContextSpoolFailureReported(t *testing.T) {
	srv := fullContextProxy(t, func(c *config.Config) {
		c.RequestSpoolDir = filepath.Join(c.RequestSpoolDir, "does-not-exist")
	})
	up := newRecordingUpstream(t)

	big := fullContextWorkload{turns: 200, proseBytes: 16 << 10, instruction: fullContextInstruction}
	raw, _, err := big.digests()
	if err != nil {
		t.Fatal(err)
	}
	if raw.n <= requestSpoolMemory {
		t.Fatalf("workload of %d bytes fits the in-memory spool", raw.n)
	}
	w := postThroughProxy(t, srv, up.URL, big.rawStream(), raw.n)
	if w.Code != http.StatusInsufficientStorage {
		t.Fatalf("status %d, want 507: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "could not buffer") {
		t.Errorf("body %q does not explain the failure", w.Body.String())
	}
	if n := up.calls.Load(); n != 0 {
		t.Fatalf("upstream called %d times after a spool failure", n)
	}
	if got := srv.m.Snapshot().Errors.Anonymize; got != 1 {
		t.Errorf("ErrorsAnonymize = %d, want 1", got)
	}

	body := `{"messages":[{"role":"user","content":"hi alice.synthetic@example.com"}]}`
	if w := postThroughProxy(t, srv, up.URL, strings.NewReader(body), int64(len(body))); w.Code != http.StatusOK {
		t.Fatalf("small body with an unusable spool dir: status %d", w.Code)
	}
}

// TestFullContextGetBodyReplaysCompleteBody verifies the replay body the
// transport may use for a retry is the complete anonymized body, including
// the instruction insertion, for both in-memory and spooled bodies.
func TestFullContextGetBodyReplaysCompleteBody(t *testing.T) {
	srv := fullContextProxy(t, nil)
	for _, wl := range []fullContextWorkload{
		{turns: 3, proseBytes: 1 << 10, instruction: fullContextInstruction},                                    // in memory
		{turns: 120, proseBytes: 16 << 10, images: 1, imageBytes: 1 << 20, instruction: fullContextInstruction}, // spooled
	} {
		raw, want, err := wl.digests()
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://localhost/v1", wl.rawStream())
		req.ContentLength = raw.n
		_, release, err := srv.anonymizeRequestBody(req)
		if err != nil {
			t.Fatal(err)
		}
		if req.ContentLength != want.n {
			t.Errorf("ContentLength %d, want %d", req.ContentLength, want.n)
		}
		for i := range 2 {
			body, err := req.GetBody()
			if err != nil {
				t.Fatal(err)
			}
			got, err := checkUpstreamBody(body, want.n)
			if err != nil {
				t.Fatal(err)
			}
			if got.digest != want {
				t.Errorf("replay %d: %d bytes / %x, want %d / %x", i, got.digest.n, got.digest.sum, want.n, want.sum)
			}
		}
		release()
	}
}

// TestFullContextWorkloadExpectedIsValidJSON validates the generator: the
// expected body is valid JSON, carries the instruction once, contains the
// tokens of every address, and parses to tool arguments that are themselves
// valid JSON.
func TestFullContextWorkloadExpectedIsValidJSON(t *testing.T) {
	wl := fullContextWorkload{turns: 5, proseBytes: 2 << 10, images: 1, imageBytes: 3000, instruction: fullContextInstruction}
	var raw, exp bytes.Buffer
	if err := wl.generate(&raw, &exp); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"raw": raw.Bytes(), "expected": exp.Bytes()} {
		if !json.Valid(b) {
			t.Fatalf("%s workload is not valid JSON", name)
		}
	}
	if bytes.Contains(exp.Bytes(), leakMarker) {
		t.Error("expected body contains a raw address")
	}
	if n := bytes.Count(exp.Bytes(), []byte(fullContextInstruction)); n != 1 {
		t.Errorf("instruction appears %d times in expected body", n)
	}
	var doc struct {
		Messages []struct {
			ToolCalls []struct {
				Function struct{ Arguments string } `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(exp.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	calls := 0
	for _, m := range doc.Messages {
		for _, tc := range m.ToolCalls {
			calls++
			if !json.Valid([]byte(tc.Function.Arguments)) {
				t.Errorf("tool arguments are not valid JSON: %s", tc.Function.Arguments)
			}
			if !strings.Contains(tc.Function.Arguments, "[PII_EMAIL_") {
				t.Errorf("tool arguments lack the email token: %s", tc.Function.Arguments)
			}
		}
	}
	if calls != wl.turns {
		t.Errorf("found %d tool calls, want %d", calls, wl.turns)
	}

	// The anonymizer, given the raw workload, must produce the expected body.
	srv := fullContextProxy(t, nil)
	got := srv.anon.AnonymizeJSON(raw.Bytes(), "workload-check")
	if !bytes.Equal(got, exp.Bytes()) {
		t.Errorf("AnonymizeJSON differs from the workload oracle (%d vs %d bytes, sha %x vs %x)",
			len(got), exp.Len(), sha256.Sum256(got), sha256.Sum256(exp.Bytes()))
	}
}
