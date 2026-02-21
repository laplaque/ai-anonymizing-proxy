// Package management provides a lightweight HTTP API for runtime inspection
// and configuration of the running proxy.
//
// Endpoints:
//
//	GET  /status          - proxy health, current AI domain list
//	POST /domains/add     - add an AI API domain {"domain":"api.example.com"}
//	POST /domains/remove  - remove an AI API domain {"domain":"api.example.com"}
package management

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"ai-anonymizing-proxy/internal/config"
)

// Server is the management API server.
type Server struct {
	cfg       *config.Config
	startTime time.Time
	domains   *DomainRegistry
}

// DomainRegistry holds the mutable set of AI API domains.
// It is shared between the proxy and management server.
// Changes are persisted to disk via atomic file writes so they
// survive proxy restarts.
type DomainRegistry struct {
	mu          sync.RWMutex
	domains     map[string]bool
	persistPath string // empty = no persistence
}

// NewDomainRegistry creates a registry seeded from the config defaults.
// If persistPath is non-empty and the file exists, its contents take
// precedence over config defaults (it represents runtime overrides).
func NewDomainRegistry(cfg *config.Config, persistPath string) *DomainRegistry {
	r := &DomainRegistry{
		domains:     make(map[string]bool, len(cfg.AIAPIDomains)),
		persistPath: persistPath,
	}

	// Try to load persisted domains first
	if persistPath != "" {
		if domains, err := r.loadFromDisk(); err == nil {
			for _, d := range domains {
				r.domains[d] = true
			}
			log.Printf("[DOMAINS] Loaded %d domains from %s", len(domains), persistPath)
			return r
		}
	}

	// Fall back to config defaults
	for _, d := range cfg.AIAPIDomains {
		r.domains[d] = true
	}
	return r
}

// Has returns true if the domain is registered as an AI API domain.
func (r *DomainRegistry) Has(domain string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.domains[domain]
}

// Add adds a domain to the registry and persists to disk.
func (r *DomainRegistry) Add(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.domains[domain] = true
	r.persistLocked()
}

// Remove removes a domain from the registry and persists to disk.
func (r *DomainRegistry) Remove(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.domains, domain)
	r.persistLocked()
}

// All returns a sorted slice of all registered domains.
func (r *DomainRegistry) All() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.domains))
	for d := range r.domains {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// loadFromDisk reads the persisted domain list from disk.
func (r *DomainRegistry) loadFromDisk() ([]string, error) {
	data, err := os.ReadFile(r.persistPath)
	if err != nil {
		return nil, err
	}
	var domains []string
	if err := json.Unmarshal(data, &domains); err != nil {
		return nil, fmt.Errorf("parse %s: %w", r.persistPath, err)
	}
	return domains, nil
}

// persistLocked writes the current domain set to disk atomically.
// Caller must hold r.mu (read or write lock).
func (r *DomainRegistry) persistLocked() {
	if r.persistPath == "" {
		return
	}
	domains := make([]string, 0, len(r.domains))
	for d := range r.domains {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	data, err := json.MarshalIndent(domains, "", "  ")
	if err != nil {
		log.Printf("[DOMAINS] Marshal error: %v", err)
		return
	}

	// Atomic write: temp file → rename
	dir := filepath.Dir(r.persistPath)
	tmp, err := os.CreateTemp(dir, ".ai-domains-*.tmp")
	if err != nil {
		log.Printf("[DOMAINS] Persist error (create temp): %v", err)
		return
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()        //nolint:errcheck // best-effort cleanup
		os.Remove(tmpName) //nolint:errcheck // #nosec G703 -- tmpName from os.CreateTemp, not user input
		log.Printf("[DOMAINS] Persist error (write): %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName) //nolint:errcheck // #nosec G703 -- tmpName from os.CreateTemp, not user input
		log.Printf("[DOMAINS] Persist error (close): %v", err)
		return
	}
	if err := os.Rename(tmpName, r.persistPath); err != nil { // #nosec G703 -- paths from trusted config
		os.Remove(tmpName) //nolint:errcheck // #nosec G703 -- tmpName from os.CreateTemp, not user input
		log.Printf("[DOMAINS] Persist error (rename): %v", err)
		return
	}
}

// New creates a management server.
func New(cfg *config.Config, registry *DomainRegistry) *Server {
	return &Server{
		cfg:       cfg,
		startTime: time.Now(),
		domains:   registry,
	}
}

// Handler returns the HTTP handler for the management API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/domains/add", s.handleAddDomain)
	mux.HandleFunc("/domains/remove", s.handleRemoveDomain)
	return mux
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	type response struct {
		Status    string   `json:"status"`
		Uptime    string   `json:"uptime"`
		ProxyPort int      `json:"proxyPort"`
		Domains   []string `json:"aiApiDomains"`
		Ollama    struct {
			Endpoint string `json:"endpoint"`
			Model    string `json:"model"`
			Enabled  bool   `json:"enabled"`
		} `json:"ollama"`
	}

	resp := response{
		Status:    "running",
		Uptime:    time.Since(s.startTime).Round(time.Second).String(),
		ProxyPort: s.cfg.ProxyPort,
		Domains:   s.domains.All(),
	}
	resp.Ollama.Endpoint = s.cfg.OllamaEndpoint
	resp.Ollama.Model = s.cfg.OllamaModel
	resp.Ollama.Enabled = s.cfg.UseAIDetection

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAddDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "invalid request: need {\"domain\":\"...\"}", http.StatusBadRequest)
		return
	}
	s.domains.Add(req.Domain)
	log.Printf("[MANAGEMENT] Added AI domain: %s", req.Domain)
	writeJSON(w, http.StatusOK, map[string]string{"added": req.Domain})
}

func (s *Server) handleRemoveDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "invalid request: need {\"domain\":\"...\"}", http.StatusBadRequest)
		return
	}
	s.domains.Remove(req.Domain)
	log.Printf("[MANAGEMENT] Removed AI domain: %s", req.Domain)
	writeJSON(w, http.StatusOK, map[string]string{"removed": req.Domain})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[MANAGEMENT] JSON encode error: %v", err)
	}
}

// ListenAndServe starts the management HTTP server.
func (s *Server) ListenAndServe() error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.cfg.ManagementPort)
	log.Printf("[MANAGEMENT] Listening on %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}
