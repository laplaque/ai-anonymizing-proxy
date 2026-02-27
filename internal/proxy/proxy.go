// Package proxy implements the core HTTP proxy server.
//
// Traffic flow:
//   - HTTPS CONNECT to AI API domains (with MITM CA): TLS terminated, body anonymized
//   - HTTPS CONNECT to other domains: tunneled transparently (no inspection)
//   - HTTP requests to AI API domains: body is anonymized before forwarding
//   - HTTP requests to auth domains/paths: passed through unchanged
//   - All other HTTP requests: passed through unchanged
//
// Upstream proxy chaining: configure via UPSTREAM_PROXY env var or upstreamProxy in
// proxy-config.json. The transport intentionally never reads HTTP_PROXY / HTTPS_PROXY
// from the environment to prevent the proxy from routing its own traffic back through
// itself when those vars are set for downstream clients.
package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"ai-anonymizing-proxy/internal/metrics"
	"ai-anonymizing-proxy/internal/mitm"
)

// privateNetworks lists CIDR ranges that must never be reachable via CONNECT
// or plain-HTTP forwarding (SSRF protection).
var privateNetworks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("proxy: invalid private network CIDR %q: %v", cidr, err)
		}
		privateNetworks = append(privateNetworks, network)
	}
}

// isPrivateHost checks literal IP addresses only. It does not perform DNS
// resolution to avoid TOCTOU issues (DNS rebinding). DNS-resolved IPs are
// checked at connection time by ssrfSafeDialContext.
func isPrivateHost(host string) bool {
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	if ip := net.ParseIP(hostname); ip != nil {
		return isPrivateIP(ip)
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	for _, n := range privateNetworks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

var errPrivateIP = fmt.Errorf("connection to private IP blocked")

// ssrfSafeDialContext wraps a net.Dialer and checks the resolved IP address
// at connection time — eliminating the TOCTOU gap between DNS resolution and dial.
func ssrfSafeDialContext(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return d.DialContext(ctx, network, addr)
		}

		// Resolve the hostname ourselves so we can inspect the IPs
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}

		for _, ipAddr := range ips {
			if isPrivateIP(ipAddr.IP) {
				log.Printf("[SSRF] Blocked connection to private IP %s (host: %s)", ipAddr.IP, host)
				return nil, errPrivateIP
			}
		}

		// Dial using the first resolved IP to ensure we connect to what we checked.
		// Return an error if the resolver returned no addresses (empty IPs = unknown host).
		if len(ips) == 0 {
			return nil, fmt.Errorf("proxy: no IP addresses returned for host %q", host)
		}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

// Server is the HTTP proxy server.
type Server struct {
	cfg         *config.Config
	anon        *anonymizer.Anonymizer
	m           *metrics.Metrics
	aiDomains   *management.DomainRegistry
	authDomains map[string]bool
	authPaths   map[string]bool
	transport   *http.Transport
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	ca          *mitm.CA // nil if MITM is not available
}

// New creates and configures a new proxy server.
func New(cfg *config.Config, domains *management.DomainRegistry, m *metrics.Metrics) *Server {
	s := &Server{
		cfg:         cfg,
		anon:        anonymizer.NewWithCache(cfg.OllamaEndpoint, cfg.OllamaModel, cfg.UseAIDetection, cfg.AIConfidence, cfg.OllamaMaxConcurrent, m, cfg.OllamaCacheFile),
		m:           m,
		aiDomains:   domains,
		authDomains: toSet(cfg.AuthDomains),
		authPaths:   toSet(cfg.AuthPaths),
	}

	// The custom DialContext enforces SSRF protection at connection time,
	// preventing DNS rebinding attacks (TOCTOU).
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	safeDial := ssrfSafeDialContext(dialer)
	s.dialContext = safeDial

	// ProxyFromEnvironment picks up HTTP_PROXY / HTTPS_PROXY / NO_PROXY.
	s.transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           safeDial,
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

// Close releases resources held by the proxy server, including the persistent
// Ollama cache. Must be called on shutdown.
func (s *Server) Close() error {
	return s.anon.Close()
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

		if s.m != nil {
			s.m.RequestsTotal.Add(1)
			if isAuth {
				s.m.RequestsAuth.Add(1)
			} else {
				s.m.RequestsAnonymized.Add(1)
			}
		}

		// Anonymize body for non-auth requests
		var sessionID string
		if !isAuth {
			var err error
			sessionID, err = s.anonymizeRequestBody(req)
			if err != nil {
				log.Printf("[MITM] Anonymization error for %s: %v", domain, err)
				http.Error(rw, "payload too large", http.StatusRequestEntityTooLarge)
				return
			}
			if sessionID != "" {
				defer s.anon.DeleteSession(sessionID)
			}
		}

		// Forward to the real destination
		removeHopByHop(req.Header)
		upstreamStart := time.Now()
		resp, err := s.transport.RoundTrip(req)
		if err != nil {
			if s.m != nil {
				s.m.ErrorsUpstream.Add(1)
			}
			http.Error(rw, "bad gateway", http.StatusBadGateway)
			return
		}
		if s.m != nil {
			s.m.RecordUpstreamLatency(time.Since(upstreamStart))
		}
		defer resp.Body.Close() //nolint:errcheck // best-effort close

		// De-anonymize response before returning to client
		s.deanonymizeResponseBody(resp, sessionID)

		removeHopByHop(resp.Header)
		copyHeader(rw.Header(), resp.Header)
		rw.WriteHeader(resp.StatusCode)
		flushingCopy(rw, resp.Body) //nolint:errcheck // client disconnect; headers already sent
	})

	// Perform TLS handshake and serve HTTP/1.1 or HTTP/2
	mitm.HandleConn(clientConn, domain, s.ca, handler)
}

// handleOpaqueTunnel establishes a TCP tunnel without inspecting the traffic.
func (s *Server) handleOpaqueTunnel(w http.ResponseWriter, r *http.Request, host string) {
	log.Printf("[TUNNEL] CONNECT %s", host)

	if isPrivateHost(host) {
		log.Printf("[TUNNEL] Blocked CONNECT to private address: %s", host)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Use ssrfSafeDialContext so DNS-resolved IPs are also checked (prevents rebinding).
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	destConn, err := s.dialContext(ctx, "tcp", host)
	if err != nil {
		log.Printf("[TUNNEL] Connection failed for %s: %v", host, err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
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

	if s.m != nil {
		s.m.RequestsTotal.Add(1)
		switch {
		case isAuth:
			s.m.RequestsAuth.Add(1)
		case isAI:
			s.m.RequestsAnonymized.Add(1)
		default:
			s.m.RequestsPassthrough.Add(1)
		}
	}

	// Anonymize body only for AI API requests that are not auth
	var sessionID string
	if isAI && !isAuth {
		var err error
		sessionID, err = s.anonymizeRequestBody(r)
		if err != nil {
			log.Printf("[HTTP] Anonymization error for %s: %v", domain, err)
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		if sessionID != "" {
			defer s.anon.DeleteSession(sessionID)
		}
	}

	// Forward the request
	s.forward(w, r, sessionID)
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, sessionID string) {
	// Ensure the URL is absolute
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	if isPrivateHost(r.URL.Host) {
		log.Printf("[HTTP] Blocked request to private address: %s", r.URL.Host)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Strip hop-by-hop headers
	r.RequestURI = ""
	removeHopByHop(r.Header)

	upstreamStart := time.Now()
	resp, err := s.transport.RoundTrip(r)
	if err != nil {
		if s.m != nil {
			s.m.ErrorsUpstream.Add(1)
		}
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if s.m != nil {
		s.m.RecordUpstreamLatency(time.Since(upstreamStart))
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	// De-anonymize response before returning to client
	s.deanonymizeResponseBody(resp, sessionID)

	removeHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	flushingCopy(w, resp.Body) //nolint:errcheck // client disconnect; headers already sent
}

const maxRequestBody = 50 << 20 // 50 MB

func (s *Server) anonymizeRequestBody(r *http.Request) (string, error) {
	if r.Body == nil || r.ContentLength == 0 {
		return "", nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
	r.Body.Close() //nolint:errcheck // body already read; close is best-effort
	if err != nil {
		if s.m != nil {
			s.m.ErrorsAnonymize.Add(1)
		}
		return "", err
	}
	if int64(len(body)) > maxRequestBody {
		return "", fmt.Errorf("request body exceeds %d bytes", maxRequestBody)
	}

	var sessionID string
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		sessionID = fmt.Sprintf("%d", time.Now().UnixNano())
	} else {
		sessionID = hex.EncodeToString(b)
	}

	anonStart := time.Now()
	anonymized := s.anon.AnonymizeJSON(body, sessionID)
	if s.m != nil {
		s.m.RecordAnonLatency(time.Since(anonStart))
	}

	r.Body = io.NopCloser(bytes.NewReader(anonymized))
	r.ContentLength = int64(len(anonymized))
	return sessionID, nil
}

func (s *Server) deanonymizeResponseBody(resp *http.Response, sessionID string) {
	if sessionID == "" || resp == nil || resp.Body == nil {
		return
	}

	// Streaming responses (SSE or unknown-length chunked) must never be fully
	// buffered: io.ReadAll blocks until the upstream closes the connection.
	// Wrap the body in a pipe-based reader that replaces tokens on-the-fly.
	if isStreamingResponse(resp) {
		resp.Body = s.anon.StreamingDeanonymize(resp.Body, sessionID)
		resp.ContentLength = -1 // length is unknown; let the client stream
		return
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck // body already read; close is best-effort
	if err != nil {
		resp.Body = http.NoBody
		return
	}
	deanonymized := s.anon.DeanonymizeText(string(body), sessionID)
	resp.Body = io.NopCloser(strings.NewReader(deanonymized))
	resp.ContentLength = int64(len(deanonymized))
}

// isStreamingResponse returns true for responses whose body must not be fully
// buffered before forwarding.  SSE connections stay open indefinitely; chunked
// responses with no Content-Length may also be long-lived.
func isStreamingResponse(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "text/event-stream")
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

// flushingCopy copies src to dst, flushing after each write if dst supports
// http.Flusher. This ensures SSE and other streaming responses are delivered
// to the client immediately rather than being buffered.
func flushingCopy(dst io.Writer, src io.Reader) {
	flusher, canFlush := dst.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			dst.Write(buf[:n]) //nolint:errcheck // caller ignores; headers already sent
			if canFlush {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}
