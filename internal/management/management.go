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
type DomainRegistry struct {
	domains map[string]bool
}

// NewDomainRegistry creates a registry from the configured list.
func NewDomainRegistry(cfg *config.Config) *DomainRegistry {
	m := make(map[string]bool, len(cfg.AIAPIDomains))
	for _, d := range cfg.AIAPIDomains {
		m[d] = true
	}
	return &DomainRegistry{domains: m}
}

// Has returns true if the domain is registered as an AI API domain.
func (r *DomainRegistry) Has(domain string) bool {
	return r.domains[domain]
}

// Add adds a domain to the registry.
func (r *DomainRegistry) Add(domain string) {
	r.domains[domain] = true
}

// Remove removes a domain from the registry.
func (r *DomainRegistry) Remove(domain string) {
	delete(r.domains, domain)
}

// All returns a sorted slice of all registered domains.
func (r *DomainRegistry) All() []string {
	out := make([]string, 0, len(r.domains))
	for d := range r.domains {
		out = append(out, d)
	}
	return out
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

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "invalid request: need {\"domain\":\"...\"}",  http.StatusBadRequest)
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
	addr := fmt.Sprintf(":%d", s.cfg.ManagementPort)
	log.Printf("[MANAGEMENT] Listening on %s", addr)
	return http.ListenAndServe(addr, s.Handler())
}
