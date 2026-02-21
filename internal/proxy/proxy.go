// Package proxy implements the core HTTP proxy server.
//
// Traffic flow:
//   - HTTPS CONNECT to AI API domains (with MITM CA): TLS terminated, body anonymized
//   - HTTPS CONNECT to other domains: tunneled transparently (no inspection)
//   - HTTP requests to AI API domains: body is anonymized before forwarding
//   - HTTP requests to auth domains/paths: passed through unchanged
//   - All other HTTP requests: passed through unchanged
//
// Upstream proxy (corporate proxy) chaining is automatic: Go's net/http
// respects HTTP_PROXY / HTTPS_PROXY / NO_PROXY environment variables natively.
// No extra configuration is needed — just set those env vars before starting.
package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"ai-anonymizing-proxy/internal/anonymizer"
	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/mitm"
)

// Server is the HTTP proxy server.
type Server struct {
	cfg         *config.Config
	anon        *anonymizer.Anonymizer
	aiDomains   *management.DomainRegistry
	authDomains map[string]bool
	authPaths   map[string]bool
	transport   *http.Transport
	ca          *mitm.CA // nil if MITM is not available
}

// New creates and configures a new proxy server.
func New(cfg *config.Config, domains *management.DomainRegistry) *Server {
	s := &Server{
		cfg:         cfg,
		anon:        anonymizer.New(cfg.OllamaEndpoint, cfg.OllamaModel, cfg.UseAIDetection, cfg.AIConfidence),
		aiDomains:   domains,
		authDomains: toSet(cfg.AuthDomains),
		authPaths:   toSet(cfg.AuthPaths),
	}

	// transport uses ProxyFromEnvironment — automatically picks up
	// HTTP_PROXY / HTTPS_PROXY / NO_PROXY env vars for upstream chaining.
	s.transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          200,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	// Load or auto-generate CA for MITM TLS termination
	if cfg.CACertFile != "" && cfg.CAKeyFile != "" {
		ca, err := mitm.LoadOrGenerateCA(cfg.CACertFile, cfg.CAKeyFile)
		if err != nil {
			log.Printf("[PROXY] MITM disabled: %v", err)
		} else {
			s.ca = ca
			log.Printf("[PROXY] MITM TLS interception enabled for AI API domains")
		}
	}

	return s
}

// ServeHTTP dispatches incoming proxy requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleTunnel(w, r)
		return
	}
	s.handleHTTP(w, r)
}

// handleTunnel dispatches CONNECT requests: MITM intercept for AI domains,
// opaque tunnel for everything else.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	host := r.Host

	// Extract domain without port for matching
	domain := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		domain = h
	}

	// MITM intercept for AI API domains when CA is available
	if s.ca != nil && s.aiDomains.Has(domain) && !s.isAuthRequest(domain, "") {
		s.handleMITMTunnel(w, r, host, domain)
		return
	}

	s.handleOpaqueTunnel(w, r, host)
}

// handleMITMTunnel intercepts HTTPS connections to AI API domains.
// It performs TLS termination with a dynamically generated certificate,
// reads the plaintext HTTP request, anonymizes it, and forwards upstream.
func (s *Server) handleMITMTunnel(w http.ResponseWriter, r *http.Request, host, domain string) {
	log.Printf("[MITM] Intercepting CONNECT %s", host)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[MITM] Hijacking not supported for %s", host)
		s.handleOpaqueTunnel(w, r, host)
		return
	}

	// Tell the client the tunnel is established
	w.WriteHeader(http.StatusOK)

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[MITM] Hijack error for %s: %v", host, err)
		return
	}
	defer clientConn.Close() //nolint:errcheck // best-effort close

	// Build a handler that anonymizes and forwards requests
	handler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Fix up the request URL to be absolute for the transport
		req.URL.Scheme = "https"
		req.URL.Host = host
		req.RequestURI = ""

		isAuth := s.isAuthRequest(domain, req.URL.Path)
		tag := "[ANON]"
		if isAuth {
			tag = "[AUTH][PASS]"
		}
		log.Printf("[MITM] %s %s%s %s", req.Method, domain, req.URL.Path, tag)

		// Anonymize body for non-auth requests
		if !isAuth {
			if err := s.anonymizeRequestBody(req); err != nil {
				log.Printf("[MITM] Anonymization error for %s: %v", domain, err)
			}
		}

		// Forward to the real destination
		removeHopByHop(req.Header)
		resp, err := s.transport.RoundTrip(req)
		if err != nil {
			http.Error(rw, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close() //nolint:errcheck // best-effort close

		removeHopByHop(resp.Header)
		copyHeader(rw.Header(), resp.Header)
		rw.WriteHeader(resp.StatusCode)
		io.Copy(rw, resp.Body) //nolint:errcheck // client disconnect; headers already sent
	})

	// Perform TLS handshake and serve HTTP/1.1 or HTTP/2
	mitm.HandleConn(clientConn, domain, s.ca, handler)
}

// handleOpaqueTunnel establishes a TCP tunnel without inspecting the traffic.
func (s *Server) handleOpaqueTunnel(w http.ResponseWriter, _ *http.Request, host string) {
	log.Printf("[TUNNEL] CONNECT %s", host)

	destConn, err := net.DialTimeout("tcp", host, 20*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot connect to %s: %v", host, err), http.StatusBadGateway)
		return
	}
	defer destConn.Close() //nolint:errcheck // best-effort close

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK) // send "200 Connection established"

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[TUNNEL] Hijack error for %s: %v", host, err)
		return
	}
	defer clientConn.Close() //nolint:errcheck // best-effort close

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() { io.Copy(destConn, clientConn); done <- struct{}{} }() //nolint:errcheck // tunnel; EOF is normal
	go func() { io.Copy(clientConn, destConn); done <- struct{}{} }() //nolint:errcheck // tunnel; EOF is normal
	<-done
}

// handleHTTP handles plain HTTP proxy requests.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	// strip port for domain matching
	domain := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		domain = h
	}

	isAuth := s.isAuthRequest(domain, r.URL.Path)
	isAI := s.aiDomains.Has(domain)

	tag := "[PASS]"
	if isAuth {
		tag = "[AUTH][PASS]"
	} else if isAI {
		tag = "[ANON]"
	}

	log.Printf("[HTTP] %s %s%s %s", r.Method, domain, r.URL.Path, tag)

	// Anonymize body only for AI API requests that are not auth
	if isAI && !isAuth {
		if err := s.anonymizeRequestBody(r); err != nil {
			log.Printf("[HTTP] Anonymization error for %s: %v", domain, err)
		}
	}

	// Forward the request
	s.forward(w, r)
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request) {
	// Ensure the URL is absolute
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	// Strip hop-by-hop headers
	r.RequestURI = ""
	removeHopByHop(r.Header)

	resp, err := s.transport.RoundTrip(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("proxy error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	removeHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck // client disconnect; headers already sent
}

func (s *Server) anonymizeRequestBody(r *http.Request) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}

	body, err := io.ReadAll(r.Body)
	r.Body.Close() //nolint:errcheck // body already read; close is best-effort
	if err != nil {
		return err
	}

	requestID := fmt.Sprintf("%d", time.Now().UnixNano())
	anonymized := s.anon.AnonymizeJSON(body, requestID)

	r.Body = io.NopCloser(bytes.NewReader(anonymized))
	r.ContentLength = int64(len(anonymized))
	return nil
}

func (s *Server) isAuthRequest(domain, path string) bool {
	if s.authDomains[domain] {
		return true
	}
	// Check auth subdomains: auth.*, login.*, accounts.*, sso.*
	authPrefixes := []string{"auth.", "login.", "accounts.", "sso.", "oauth."}
	for _, prefix := range authPrefixes {
		if strings.HasPrefix(domain, prefix) {
			return true
		}
	}
	// Check path prefixes
	for authPath := range s.authPaths {
		if strings.HasPrefix(path, authPath) {
			return true
		}
	}
	return false
}

// ReverseProxy returns an httputil.ReverseProxy-based handler for testing.
func (s *Server) ReverseProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: s.transport,
	}
}

// --- helpers ---

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, v := range items {
		m[v] = true
	}
	return m
}

var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailers", "Transfer-Encoding", "Upgrade", "Proxy-Connection",
}

func removeHopByHop(h http.Header) {
	for _, v := range hopByHopHeaders {
		h.Del(v)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
