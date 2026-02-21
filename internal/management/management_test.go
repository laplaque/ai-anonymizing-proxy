package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ai-anonymizing-proxy/internal/config"
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
	srv := New(cfg, reg)
	return srv, reg
}

func TestStatus_OK(t *testing.T) {
	srv, _ := newTestServer("")
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
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
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with no token configured, got %d", w.Code)
	}
}

func TestAuth_ValidToken(t *testing.T) {
	srv, _ := newTestServer("secret123")
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("Authorization", "Bearer secret123")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with valid token, got %d", w.Code)
	}
}

func TestAuth_InvalidToken(t *testing.T) {
	srv, _ := newTestServer("secret123")
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong token, got %d", w.Code)
	}
}

func TestAuth_MissingToken(t *testing.T) {
	srv, _ := newTestServer("secret123")
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with missing token, got %d", w.Code)
	}
}

func TestAddDomain_OK(t *testing.T) {
	srv, reg := newTestServer("")
	body := `{"domain":"api.newai.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/domains/add", strings.NewReader(body))
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
	req := httptest.NewRequest(http.MethodPost, "/domains/add", strings.NewReader(body))
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
	req := httptest.NewRequest(http.MethodPost, "/domains/add", strings.NewReader(body))
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
	req := httptest.NewRequest(http.MethodPost, "/domains/add", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty domain, got %d", w.Code)
	}
}

func TestAddDomain_WrongMethod(t *testing.T) {
	srv, _ := newTestServer("")
	req := httptest.NewRequest(http.MethodGet, "/domains/add", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestRemoveDomain_OK(t *testing.T) {
	srv, reg := newTestServer("")
	body := `{"domain":"api.openai.com"}`
	req := httptest.NewRequest(http.MethodPost, "/domains/remove", strings.NewReader(body))
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
	req := httptest.NewRequest(http.MethodPost, "/domains/remove", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid domain, got %d", w.Code)
	}
}
