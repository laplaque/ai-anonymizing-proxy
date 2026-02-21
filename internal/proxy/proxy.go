// Package proxy implements the core HTTP proxy server.
//
// Traffic flow:
//   - HTTPS CONNECT requests: tunneled transparently (no TLS termination)
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
)

// Server is the HTTP proxy server.
type Server struct {
	cfg        *config.Config
	anon       *anonymizer.Anonymizer
	aiDomains  map[string]bool
	authDomains map[string]bool
	authPaths  map[string]bool
	transport  *http.Transport
}

// New creates and configures a new proxy server.
func New(cfg *config.Config) *Server {
	s := &Server{
		cfg:         cfg,
		anon:        anonymizer.New(cfg.OllamaEndpoint, cfg.OllamaModel, cfg.UseAIDetection, cfg.AIConfidence),
		aiDomains:   toSet(cfg.AIAPIDomains),
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

// handleTunnel handles HTTPS CONNECT requests by establishing a TCP tunnel.
// Traffic inside the tunnel is not inspected (no TLS termination).
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	log.Printf("[TUNNEL] CONNECT %s", host)

	destConn, err := net.DialTimeout("tcp", host, 20*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot connect to %s: %v", host, err), http.StatusBadGateway)
		return
	}
	defer destConn.Close()

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
	defer clientConn.Close()

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() { io.Copy(destConn, clientConn); done <- struct{}{} }() //nolint:errcheck
	go func() { io.Copy(clientConn, destConn); done <- struct{}{} }() //nolint:errcheck
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
	isAI   := s.aiDomains[domain]

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
	defer resp.Body.Close()

	removeHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

func (s *Server) anonymizeRequestBody(r *http.Request) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}

	body, err := io.ReadAll(r.Body)
	r.Body.Close()
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
