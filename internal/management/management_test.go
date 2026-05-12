package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/metrics"
)

func testConfig() *config.Config {
	return &config.Config{
		ProxyPort:      8080,
		ManagementPort: 8081,
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "qwen2.5:3b",
		UseAIDetection: true,
		AIAPIDomains:   []string{"api.openai.com", "api.anthropic.com"},
	}
}

// --- DomainRegistry tests ---

func TestDomainRegistry_AddHasRemove(t *testing.T) {
	cfg := testConfig()
	r := NewDomainRegistry(cfg, "")

	if !r.Has("api.openai.com") {
		t.Error("expected api.openai.com to be present")
	}
	if r.Has("api.newai.example.com") {
		t.Error("expected api.newai.example.com to be absent")
	}

	r.Add("api.newai.example.com")
	if !r.Has("api.newai.example.com") {
		t.Error("expected api.newai.example.com after Add")
	}

	r.Remove("api.newai.example.com")
	if r.Has("api.newai.example.com") {
		t.Error("expected api.newai.example.com removed")
	}
}

func TestDomainRegistry_All_Sorted(t *testing.T) {
	cfg := testConfig()
	r := NewDomainRegistry(cfg, "")

	all := r.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(all))
	}
	if all[0] != "api.anthropic.com" || all[1] != "api.openai.com" {
		t.Errorf("expected sorted domains, got %v", all)
	}
}

// TestDomainRegistry_HasCaseInsensitive verifies that the security-classifier
// gate honors RFC 1035 §2.3.3 case-insensitivity end-to-end. The proxy hot
// path passes through `r.Host` (whose case is client-controlled) verbatim;
// a missed lookup here means anonymization is skipped entirely.
func TestDomainRegistry_HasCaseInsensitive(t *testing.T) {
	cfg := &config.Config{
		AIAPIDomains: []string{
			"api.openai.com",
			"*.openai.azure.com",
		},
	}
	r := NewDomainRegistry(cfg, "")

	cases := []struct {
		domain string
		want   bool
	}{
		{"api.openai.com", true},
		{"API.OpenAI.com", true},
		{"API.OPENAI.COM", true},
		{"api.openai.com.", true},             // trailing root-zone dot
		{"API.OpenAI.com.", true},             // both
		{"MyResource.OPENAI.azure.com", true}, // glob, mixed-case
		{"api.anthropic.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.domain, func(t *testing.T) {
			if got := r.Has(tc.domain); got != tc.want {
				t.Errorf("Has(%q) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}

// TestDomainRegistry_AddRemoveCaseInsensitive verifies that case-mixed
// patterns added directly (not via the HTTP handlers, which already
// lowercase) are canonicalized so subsequent lookups and removals see
// the same key.
func TestDomainRegistry_AddRemoveCaseInsensitive(t *testing.T) {
	cfg := &config.Config{AIAPIDomains: []string{}}
	r := NewDomainRegistry(cfg, "")

	r.Add("API.Example.com")
	if !r.Has("api.example.com") {
		t.Error("case-mixed Add did not canonicalize storage")
	}
	if !r.Remove("API.Example.com") {
		t.Error("case-mixed Remove returned false")
	}
	if r.Has("api.example.com") {
		t.Error("entry still present after Remove")
	}
}

func TestDomainRegistry_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.json")

	cfg := testConfig()
	r := NewDomainRegistry(cfg, path)
	r.Add("api.example.com")

	// Verify file was written
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("persist file not created: %v", err)
	}
	var domains []string
	if err := json.Unmarshal(data, &domains); err != nil {
		t.Fatalf("invalid JSON in persist file: %v", err)
	}

	// Create new registry from same file — should load persisted domains
	r2 := NewDomainRegistry(cfg, path)
	if !r2.Has("api.example.com") {
		t.Error("expected api.example.com loaded from disk")
	}
}

func TestDomainRegistry_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.json")

	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	r := NewDomainRegistry(cfg, path)

	// Should fall back to config defaults
	if !r.Has("api.openai.com") {
		t.Error("expected fallback to config defaults on corrupt file")
	}
}

// --- validDomain tests ---

func TestValidDomain(t *testing.T) {
	tests := []struct {
		domain string
		valid  bool
	}{
		{"api.openai.com", true},
		{"a.b.c.d.e", true},
		{"example", true},
		{"my-host.example.com", true},
		{"123.456.789", true},
		{"", false},
		{"-invalid.com", false},
		{"invalid-.com", false},
		{"in valid.com", false},
		{"foo..bar", false},
		{strings.Repeat("a", 64) + ".com", false}, // label > 63 chars
		{strings.Repeat("a.", 126) + "a", true},   // many labels, under 253
	}
	for _, tt := range tests {
		if got := validDomain(tt.domain); got != tt.valid {
			t.Errorf("validDomain(%q) = %v, want %v", tt.domain, got, tt.valid)
		}
	}
}

// --- HTTP handler tests ---

func newTestServer(token string) (*Server, *DomainRegistry) {
	cfg := testConfig()
	cfg.ManagementToken = token
	reg := NewDomainRegistry(cfg, "")
	srv := New(cfg, reg, nil)
	return srv, reg
}

func TestStatus_OK(t *testing.T) {
	srv, _ := newTestServer("")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp["status"] != "running" {
		t.Errorf("expected status=running, got %v", resp["status"])
	}
}

func TestAuth_NoToken_PassThrough(t *testing.T) {
	srv, _ := newTestServer("")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with no token configured, got %d", w.Code)
	}
}

func TestAuth_ValidToken(t *testing.T) {
	srv, _ := newTestServer("secret123")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/status", nil)
	req.Header.Set("Authorization", "Bearer secret123")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with valid token, got %d", w.Code)
	}
}

func TestAuth_InvalidToken(t *testing.T) {
	srv, _ := newTestServer("secret123")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/status", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong token, got %d", w.Code)
	}
}

func TestAuth_MissingToken(t *testing.T) {
	srv, _ := newTestServer("secret123")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with missing token, got %d", w.Code)
	}
}

func TestAddDomain_OK(t *testing.T) {
	srv, reg := newTestServer("")
	body := `{"domain":"api.newai.example.com"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/domains/add", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !reg.Has("api.newai.example.com") {
		t.Error("domain was not added to registry")
	}
}

func TestAddDomain_CaseNormalized(t *testing.T) {
	srv, reg := newTestServer("")
	body := `{"domain":"API.OpenAI.COM"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/domains/add", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !reg.Has("api.openai.com") {
		t.Error("domain should be normalized to lowercase")
	}
}

func TestAddDomain_InvalidDomain(t *testing.T) {
	srv, _ := newTestServer("")
	body := `{"domain":"not a valid domain!"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/domains/add", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid domain, got %d", w.Code)
	}
}

func TestAddDomain_EmptyDomain(t *testing.T) {
	srv, _ := newTestServer("")
	body := `{"domain":""}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/domains/add", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty domain, got %d", w.Code)
	}
}

func TestAddDomain_WrongMethod(t *testing.T) {
	srv, _ := newTestServer("")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/domains/add", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestRemoveDomain_OK(t *testing.T) {
	srv, reg := newTestServer("")
	body := `{"domain":"api.openai.com"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/domains/remove", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if reg.Has("api.openai.com") {
		t.Error("domain was not removed from registry")
	}
}

func TestRemoveDomain_InvalidDomain(t *testing.T) {
	srv, _ := newTestServer("")
	body := `{"domain":"bad domain!"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/domains/remove", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid domain, got %d", w.Code)
	}
}

func TestRemoveDomain_WrongMethod(t *testing.T) {
	srv, _ := newTestServer("")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/domains/remove", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestRemoveDomain_EmptyBody(t *testing.T) {
	srv, _ := newTestServer("")
	body := `{"domain":""}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/domains/remove", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty domain, got %d", w.Code)
	}
}

func TestMetrics_NotEnabled(t *testing.T) {
	srv, _ := newTestServer("")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for no metrics, got %d", w.Code)
	}
}

func TestMetrics_Enabled(t *testing.T) {
	cfg := testConfig()
	reg := NewDomainRegistry(cfg, "")
	m := &metrics.Metrics{}
	srv := New(cfg, reg, m)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for metrics, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
}

func TestDomainRegistry_PersistNoPersistPath(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("persist with no path panicked: %v", r)
		}
	}()
	cfg := testConfig()
	reg := NewDomainRegistry(cfg, "")
	// Add/Remove with no persist path should not panic
	reg.Add("test.example.com")
	reg.Remove("test.example.com")
}

func TestDomainRegistry_PersistAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.json")

	cfg := testConfig()
	r := NewDomainRegistry(cfg, path)

	// Add and verify file exists
	r.Add("test.example.com")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("persist file not created: %v", err)
	}

	// Remove and verify file updated
	r.Remove("test.example.com")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persist file: %v", err)
	}
	var domains []string
	if err := json.Unmarshal(data, &domains); err != nil {
		t.Fatalf("parse persist file: %v", err)
	}
	for _, d := range domains {
		if d == "test.example.com" {
			t.Error("removed domain should not be in persist file")
		}
	}
}

// --- Glob domain tests ---

func TestDomainRegistry_GlobHas(t *testing.T) {
	cfg := &config.Config{
		AIAPIDomains: []string{
			"api.openai.com",
			"*.openai.azure.com",
			"bedrock-runtime.*.amazonaws.com",
		},
	}
	r := NewDomainRegistry(cfg, "")

	cases := []struct {
		domain string
		want   bool
	}{
		// Exact match
		{"api.openai.com", true},
		// Prefix wildcard
		{"myresource.openai.azure.com", true},
		// Infix wildcard
		{"bedrock-runtime.us-east-1.amazonaws.com", true},
		{"bedrock-runtime.eu-west-1.amazonaws.com", true},
		// Non-matches
		{"openai.azure.com", false},
		{"ec2.us-east-1.amazonaws.com", false},
		{"api.anthropic.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.domain, func(t *testing.T) {
			if got := r.Has(tc.domain); got != tc.want {
				t.Errorf("Has(%q) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}

func TestDomainRegistry_GlobAddRemove(t *testing.T) {
	cfg := &config.Config{AIAPIDomains: []string{"api.openai.com"}}
	r := NewDomainRegistry(cfg, "")

	r.Add("bedrock-runtime.*.amazonaws.com")
	if !r.Has("bedrock-runtime.us-east-1.amazonaws.com") {
		t.Error("glob not active after Add")
	}

	r.Remove("bedrock-runtime.*.amazonaws.com")
	if r.Has("bedrock-runtime.us-east-1.amazonaws.com") {
		t.Error("glob still active after Remove")
	}

	// Exact match unaffected
	if !r.Has("api.openai.com") {
		t.Error("exact match broken after glob remove")
	}
}

func TestDomainRegistry_GlobPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.json")

	cfg := &config.Config{
		AIAPIDomains: []string{
			"api.openai.com",
			"*.openai.azure.com",
			"bedrock-runtime.*.amazonaws.com",
		},
	}
	r1 := NewDomainRegistry(cfg, path)
	r1.Add("bedrock-agent-runtime.*.amazonaws.com")

	// Reload from disk
	r2 := NewDomainRegistry(&config.Config{}, path)
	if !r2.Has("myresource.openai.azure.com") {
		t.Error("prefix glob not persisted")
	}
	if !r2.Has("bedrock-runtime.us-east-1.amazonaws.com") {
		t.Error("infix glob not persisted")
	}
	if !r2.Has("bedrock-agent-runtime.eu-west-1.amazonaws.com") {
		t.Error("added glob not persisted")
	}
	if !r2.Has("api.openai.com") {
		t.Error("exact domain not persisted")
	}
}

func TestDomainRegistry_ExactPrecedence(t *testing.T) {
	cfg := &config.Config{
		AIAPIDomains: []string{
			"specific.openai.azure.com",
			"*.openai.azure.com",
		},
	}
	r := NewDomainRegistry(cfg, "")

	if !r.Has("specific.openai.azure.com") {
		t.Error("exact match failed")
	}
	if !r.Has("other.openai.azure.com") {
		t.Error("glob match failed")
	}
}

func TestDomainRegistry_GlobAll(t *testing.T) {
	cfg := &config.Config{
		AIAPIDomains: []string{
			"api.openai.com",
			"*.openai.azure.com",
			"bedrock-runtime.*.amazonaws.com",
		},
	}
	r := NewDomainRegistry(cfg, "")

	all := r.All()
	expected := map[string]bool{
		"api.openai.com":                  false,
		"*.openai.azure.com":              false,
		"bedrock-runtime.*.amazonaws.com": false,
	}
	for _, d := range all {
		if _, ok := expected[d]; ok {
			expected[d] = true
		}
	}
	for d, found := range expected {
		if !found {
			t.Errorf("All() missing entry %q, got: %v", d, all)
		}
	}
}

func TestDomainRegistry_GlobDuplicateAdd(t *testing.T) {
	cfg := &config.Config{AIAPIDomains: []string{}}
	r := NewDomainRegistry(cfg, "")
	r.Add("bedrock-runtime.*.amazonaws.com")
	r.Add("bedrock-runtime.*.amazonaws.com")

	all := r.All()
	count := 0
	for _, d := range all {
		if d == "bedrock-runtime.*.amazonaws.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 glob entry, got %d in: %v", count, all)
	}
}

func TestValidDomain_Glob(t *testing.T) {
	cases := []struct {
		domain string
		valid  bool
	}{
		// Bare-segment wildcards (3+ segments, non-trailing).
		{"*.openai.azure.com", true},
		{"bedrock-runtime.*.amazonaws.com", true},
		{"bedrock-agent-runtime.*.amazonaws.com", true},
		{"*.aiplatform.googleapis.com", true},
		{"a.*.b.*.c", true},
		// Label-substring wildcards (Vertex hyphen-prefix and friends).
		{"*-aiplatform.googleapis.com", true},
		{"foo-*.example.com", true},
		{"foo*bar.example.com", true},
		// Catch-all rejections (defense-in-depth).
		{"*", false},     // single segment — would match any 1-label host
		{"*.com", false}, // 2 segments — would match every public hostname
		{"*.*", false},   // 2 segments
		{"foo.*", false}, // trailing wildcard is a TLD catch-all
		{"foo.bar.*", false},
		// Multi-wildcard leading-segment catch-alls — match every <a>.<b>.com
		// (or deeper) host on the public internet. (Note: a.*.b.*.c above
		// is allowed because at least one leading segment is literal.)
		{"*.*.com", false},
		{"*.*.*.com", false},
		{"*.*.aiplatform.googleapis.com", false},
		// Label-substring foot-guns.
		{"**foo.bar.com", false}, // double "*" in one segment
		{"foo**bar.example.com", false},
		// Empty / malformed.
		{".*.bar", false},
		{"*..bar", false},
		{"foo. *.bar", false}, // whitespace in segment
	}
	for _, tc := range cases {
		if got := validDomain(tc.domain); got != tc.valid {
			t.Errorf("validDomain(%q) = %v, want %v", tc.domain, got, tc.valid)
		}
	}
}

func TestDomainRegistry_RemoveMissReturnsFalse(t *testing.T) {
	cfg := &config.Config{AIAPIDomains: []string{"api.openai.com"}}
	r := NewDomainRegistry(cfg, "")

	if removed := r.Remove("never-registered.example.com"); removed {
		t.Error("Remove of unknown exact domain should return false")
	}
	if removed := r.Remove("nope.*.amazonaws.com"); removed {
		t.Error("Remove of unknown glob should return false")
	}
	if removed := r.Remove("api.openai.com"); !removed {
		t.Error("Remove of known exact domain should return true")
	}
	// Second remove of the same entry should miss.
	if removed := r.Remove("api.openai.com"); removed {
		t.Error("second Remove should return false")
	}
}

func TestHandleRemoveDomain_NotFound(t *testing.T) {
	srv, _ := newTestServer("")
	body := `{"domain":"never-registered.example.com"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/domains/remove", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown domain remove, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Management API glob tests ---

func TestHandleAddDomain_Glob(t *testing.T) {
	srv, reg := newTestServer("")
	body := `{"domain":"bedrock-runtime.*.amazonaws.com"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/domains/add", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !reg.Has("bedrock-runtime.us-west-2.amazonaws.com") {
		t.Error("glob domain did not match concrete region after Add")
	}
}

func TestHandleRemoveDomain_Glob(t *testing.T) {
	srv, reg := newTestServer("")
	reg.Add("bedrock-runtime.*.amazonaws.com")
	if !reg.Has("bedrock-runtime.us-east-1.amazonaws.com") {
		t.Fatal("setup: glob not active before Remove")
	}

	body := `{"domain":"bedrock-runtime.*.amazonaws.com"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/domains/remove", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if reg.Has("bedrock-runtime.us-east-1.amazonaws.com") {
		t.Error("glob still active after Remove")
	}
}

func TestHandleListDomains_IncludesGlobs(t *testing.T) {
	cfg := testConfig()
	cfg.AIAPIDomains = append(cfg.AIAPIDomains,
		"*.openai.azure.com",
		"bedrock-runtime.*.amazonaws.com",
	)
	reg := NewDomainRegistry(cfg, "")
	srv := New(cfg, reg, nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Domains []string `json:"aiApiDomains"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	wantGlobs := []string{"*.openai.azure.com", "bedrock-runtime.*.amazonaws.com"}
	for _, g := range wantGlobs {
		found := false
		for _, d := range resp.Domains {
			if d == g {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("status response missing glob %q, got: %v", g, resp.Domains)
		}
	}
}

func TestAuth_MalformedBearerToken(t *testing.T) {
	srv, _ := newTestServer("secret123")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/status", nil)
	req.Header.Set("Authorization", "Basic secret123") // Wrong scheme
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong auth scheme, got %d", w.Code)
	}
}
