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
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/domainmatch"
	"ai-anonymizing-proxy/internal/metrics"
)

// Server is the management API server.
type Server struct {
	cfg       *config.Config
	startTime time.Time
	domains   *DomainRegistry
	token     string           // bearer token for auth; empty = no auth
	metrics   *metrics.Metrics // nil = no metrics

	mu        sync.Mutex
	boundAddr net.Addr     // set once ListenAndServe has bound; nil before
	srv       *http.Server // set with boundAddr; target for Close
}

// DomainRegistry holds the mutable set of AI API domains.
// It is shared between the proxy and management server.
// Changes are persisted to disk via atomic file writes so they
// survive proxy restarts.
//
// Entries fall into two buckets:
//   - exact-match domains, stored in the domains map for O(1) lookup
//   - segment-glob patterns (containing one or more "*" labels), stored
//     in the globs slice and scanned linearly on lookup
//
// Has() checks the exact-match map first, so an exact entry always wins
// over an overlapping glob.
type DomainRegistry struct {
	mu          sync.RWMutex
	domains     map[string]bool          // exact matches
	globs       []domainmatch.DomainGlob // segment-glob patterns
	persistPath string                   // empty = no persistence
}

// NewDomainRegistry creates a registry seeded from the config defaults.
// If persistPath is non-empty and the file exists, its contents take
// precedence over config defaults (it represents runtime overrides).
// Patterns containing "*" segments are routed to the glob slice; all
// others are stored as exact matches.
func NewDomainRegistry(cfg *config.Config, persistPath string) *DomainRegistry {
	r := &DomainRegistry{
		domains:     make(map[string]bool, len(cfg.AIAPIDomains)),
		persistPath: persistPath,
	}

	// Try to load persisted domains first
	if persistPath != "" {
		domains, err := r.loadFromDisk()
		switch {
		case err == nil:
			for _, d := range domains {
				r.addEntryLocked(d)
			}
			log.Printf("[DOMAINS] Loaded %d domains from %s", len(domains), persistPath)
			return r
		case !os.IsNotExist(err):
			log.Printf("[DOMAINS] Warning: failed to load %s: %v (using config defaults)", persistPath, err)
		}
	}

	// Fall back to config defaults
	for _, d := range cfg.AIAPIDomains {
		r.addEntryLocked(d)
	}
	return r
}

// addEntryLocked routes a single pattern into the appropriate bucket.
// Caller must hold r.mu (or be in a constructor where no concurrent
// access is possible). The pattern is canonicalized (lowercased,
// trailing "." stripped) so direct callers, the persistence loader,
// and the HTTP handlers all converge on the same map keys. Duplicate
// globs are silently dropped.
func (r *DomainRegistry) addEntryLocked(pattern string) {
	pattern = domainmatch.NormalizeHost(pattern)
	if domainmatch.IsGlob(pattern) {
		for _, g := range r.globs {
			if g.Raw() == pattern {
				return
			}
		}
		r.globs = append(r.globs, domainmatch.Parse(pattern))
		return
	}
	r.domains[pattern] = true
}

// Has returns true if the domain is registered as an AI API domain.
// Exact matches take precedence over glob matches. The inbound domain
// is canonicalized (lowercased, trailing "." stripped) per RFC 1035
// §2.3.3; the proxy hot path calls this with `r.Host` whose case is
// client-controlled, so a non-canonical Host header must still resolve.
func (r *DomainRegistry) Has(domain string) bool {
	domain = domainmatch.NormalizeHost(domain)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.domains[domain] {
		return true
	}
	for _, g := range r.globs {
		if g.Match(domain) {
			return true
		}
	}
	return false
}

// Add adds a domain or glob pattern to the registry and persists to disk.
// Patterns containing "*" segments are stored as globs; others as exact matches.
func (r *DomainRegistry) Add(domain string) {
	r.mu.Lock()
	r.addEntryLocked(domain)
	snapshot := r.snapshotLocked()
	r.mu.Unlock()
	r.persist(snapshot)
}

// Remove removes a domain or glob pattern from the registry and persists
// to disk. For glob patterns, the raw pattern string must match exactly
// (e.g. removing "bedrock-runtime.*.amazonaws.com" — passing a concrete
// domain like "bedrock-runtime.us-east-1.amazonaws.com" will not remove
// the glob). Returns true if an entry was removed; false on miss so the
// management API can surface a typo as 404 rather than silent success.
func (r *DomainRegistry) Remove(domain string) bool {
	domain = domainmatch.NormalizeHost(domain)
	r.mu.Lock()
	removed := false
	if domainmatch.IsGlob(domain) {
		for i, g := range r.globs {
			if g.Raw() == domain {
				r.globs = append(r.globs[:i], r.globs[i+1:]...)
				removed = true
				break
			}
		}
	} else if _, ok := r.domains[domain]; ok {
		delete(r.domains, domain)
		removed = true
	}
	if !removed {
		r.mu.Unlock()
		return false
	}
	snapshot := r.snapshotLocked()
	r.mu.Unlock()
	r.persist(snapshot)
	return true
}

// All returns a sorted slice of all registered domains and glob patterns.
// Glob patterns appear with their original "*" segments intact.
func (r *DomainRegistry) All() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshotLocked()
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

// snapshotLocked returns a sorted copy of the current domain set,
// combining exact matches and glob patterns. Caller must hold r.mu.
func (r *DomainRegistry) snapshotLocked() []string {
	out := make([]string, 0, len(r.domains)+len(r.globs))
	for d := range r.domains {
		out = append(out, d)
	}
	for _, g := range r.globs {
		out = append(out, g.Raw())
	}
	sort.Strings(out)
	return out
}

// jsonMarshalIndent is indirected through a package var so tests can force
// the marshal-error path in persist; production always uses json.MarshalIndent.
var jsonMarshalIndent = json.MarshalIndent

// persistTempFile is the subset of *os.File that persist needs; abstracting
// it lets tests inject write/close failures to exercise the cleanup paths.
type persistTempFile interface {
	Write(p []byte) (int, error)
	Close() error
	Name() string
}

// createPersistTempFile creates the temp file persist writes to before the
// atomic rename. It is a package var so tests can inject a fake that fails on
// Write/Close; *os.File from os.CreateTemp satisfies persistTempFile.
var createPersistTempFile = func(dir, pattern string) (persistTempFile, error) {
	return os.CreateTemp(dir, pattern)
}

// persist writes the given domain snapshot to disk atomically.
// It does NOT hold r.mu, so it won't block Has/All calls.
func (r *DomainRegistry) persist(domains []string) {
	if r.persistPath == "" {
		return
	}

	data, err := jsonMarshalIndent(domains, "", "  ")
	if err != nil {
		log.Printf("[DOMAINS] Marshal error: %v", err)
		return
	}

	// Atomic write: temp file → rename
	dir := filepath.Dir(r.persistPath)
	tmp, err := createPersistTempFile(dir, ".ai-domains-*.tmp")
	if err != nil {
		log.Printf("[DOMAINS] Persist error (create temp): %v", err)
		return
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()        // best-effort cleanup
		_ = os.Remove(tmpName) // best-effort cleanup
		log.Printf("[DOMAINS] Persist error (write): %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName) // best-effort cleanup
		log.Printf("[DOMAINS] Persist error (close): %v", err)
		return
	}
	if err := os.Rename(tmpName, r.persistPath); err != nil { // #nosec G703 -- paths from trusted config
		_ = os.Remove(tmpName) // best-effort cleanup
		log.Printf("[DOMAINS] Persist error (rename): %v", err)
		return
	}
}

// New creates a management server.
func New(cfg *config.Config, registry *DomainRegistry, m *metrics.Metrics) *Server {
	s := &Server{
		cfg:       cfg,
		startTime: time.Now(),
		domains:   registry,
		token:     cfg.ManagementToken,
		metrics:   m,
	}
	if s.token != "" {
		log.Printf("[MANAGEMENT] Bearer token authentication enabled")
	}
	return s
}

// Handler returns the HTTP handler for the management API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/domains/add", s.handleAddDomain)
	mux.HandleFunc("/domains/remove", s.handleRemoveDomain)
	return s.authMiddleware(mux)
}

// authMiddleware checks for a valid Bearer token if one is configured.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.token == "" {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimSpace(auth[len(prefix):])), []byte(s.token)) != 1 {
			log.Printf("[MANAGEMENT] Unauthorized access attempt from %s to %s", r.RemoteAddr, r.URL.Path)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// domainLabelRegexp validates a single DNS label (RFC 952 / RFC 1123).
// Labels must be 1-63 chars, start/end alphanumeric, with hyphens allowed
// in the middle.
var domainLabelRegexp = regexp.MustCompile(
	`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`,
)

// validDomain checks that d is a syntactically valid hostname or glob
// pattern. Wildcards are accepted in two forms:
//   - bare "*" segment (segment-glob)
//   - label-substring with one "*" inside a segment (e.g. "*-aiplatform")
//
// To stop a careless or compromised admin from registering catch-all
// patterns that classify almost every outbound HTTPS connection as AI
// traffic, the following are rejected even though they pass per-segment
// syntax: any wildcard pattern with fewer than 3 segments
// (blocks "*", "*.com", "*.*"); any pattern whose final segment is "*"
// (blocks "foo.*"); and any pattern with an empty segment.
func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	segments := strings.Split(d, ".")
	hasWildcard := false
	for _, seg := range segments {
		if seg == "" {
			return false
		}
		if seg == "*" {
			hasWildcard = true
			continue
		}
		if strings.IndexByte(seg, '*') >= 0 {
			// Label-substring wildcard: at most one "*", and the literal
			// pieces around it must form valid label characters.
			hasWildcard = true
			idx := strings.IndexByte(seg, '*')
			if strings.IndexByte(seg[idx+1:], '*') >= 0 {
				return false
			}
			prefix, suffix := seg[:idx], seg[idx+1:]
			if prefix != "" && !labelPieceRegexp.MatchString(prefix) {
				return false
			}
			if suffix != "" && !labelPieceRegexp.MatchString(suffix) {
				return false
			}
			continue
		}
		if !domainLabelRegexp.MatchString(seg) {
			return false
		}
	}
	if hasWildcard {
		if len(segments) < 3 {
			return false // blocks "*", "*.com", "*.*"
		}
		if segments[len(segments)-1] == "*" {
			return false // blocks "foo.*" — never want a catch-all TLD
		}
		// Reject patterns that begin with two or more consecutive bare "*"
		// segments. "*.*.com" or "*.*.aiplatform.googleapis.com" would
		// otherwise pass and match every <a>.<b>...<eTLD> host on the
		// public internet — the same class of foot-gun the "*.com"
		// rejection guards against. A single leading "*" is fine
		// ("*.openai.azure.com"), and interspersed wildcards anchored by
		// literals ("a.*.b.*.c") are operationally meaningful.
		consecutiveLeading := 0
		for _, seg := range segments {
			if seg == "*" {
				consecutiveLeading++
				continue
			}
			break
		}
		if consecutiveLeading >= 2 {
			return false
		}
	}
	return true
}

// labelPieceRegexp validates a fragment of a DNS label adjacent to a "*"
// in a label-substring wildcard. Looser than domainLabelRegexp because a
// fragment doesn't need start/end-anchored alphanumeric (the wildcard
// fills the other side), but still rejects whitespace and label
// separators.
var labelPieceRegexp = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

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
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "invalid request: need {\"domain\":\"...\"}", http.StatusBadRequest)
		return
	}
	req.Domain = strings.ToLower(req.Domain)
	if !validDomain(req.Domain) {
		http.Error(w, "invalid domain name", http.StatusBadRequest)
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
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "invalid request: need {\"domain\":\"...\"}", http.StatusBadRequest)
		return
	}
	req.Domain = strings.ToLower(req.Domain)
	if !validDomain(req.Domain) {
		http.Error(w, "invalid domain name", http.StatusBadRequest)
		return
	}
	if !s.domains.Remove(req.Domain) {
		log.Printf("[MANAGEMENT] Remove miss for unknown AI domain: %s", req.Domain)
		http.Error(w, "domain not registered", http.StatusNotFound)
		return
	}
	log.Printf("[MANAGEMENT] Removed AI domain: %s", req.Domain)
	writeJSON(w, http.StatusOK, map[string]string{"removed": req.Domain})
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	if s.metrics == nil {
		http.Error(w, "metrics not enabled", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, s.metrics.Snapshot())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[MANAGEMENT] JSON encode error: %v", err)
	}
}

// ListenAndServe starts the management HTTP server. It binds synchronously,
// publishes the bound address (see Addr), then serves until the listener
// fails or is closed. Binding before serving lets a caller configure
// ManagementPort 0 and read the kernel-assigned port back from Addr — the
// race-free alternative to probing for a free port and re-binding it
// (issue #140).
func (s *Server) ListenAndServe() error {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", s.cfg.ManagementPort))
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.mu.Lock()
	s.boundAddr = ln.Addr()
	s.srv = srv
	s.mu.Unlock()
	log.Printf("[MANAGEMENT] Listening on %s", ln.Addr())
	return srv.Serve(ln)
}

// Addr returns the address the management listener is bound to, or nil
// before ListenAndServe has bound it. When the server was configured with
// ManagementPort 0, this is the only way to learn the actual port.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.boundAddr
}

// Close immediately closes the management listener and any active
// connections; a blocked ListenAndServe then returns http.ErrServerClosed.
// Returns nil if the server never bound a listener.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv == nil {
		return nil
	}
	return s.srv.Close()
}
