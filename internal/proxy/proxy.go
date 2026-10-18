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
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"
	"time"

	"ai-anonymizing-proxy/internal/anonymizer"
	"ai-anonymizing-proxy/internal/bodyspool"
	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
	"ai-anonymizing-proxy/internal/mitm"
)

// HTTP header and error message constants.
const (
	headerContentEncoding = "Content-Encoding"
	errBadGateway         = "bad gateway"
)

var defaultPrivateCIDRs = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
	"169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
}

// privateNetworks lists CIDR ranges that must never be reachable via CONNECT
// or plain-HTTP forwarding (SSRF protection).
var privateNetworks = mustParsePrivateNetworks(defaultPrivateCIDRs)

// mustParsePrivateNetworks parses CIDR strings, panicking on an invalid entry
// (a programmer error in the hardcoded defaults). Returning an error here and
// panicking keeps the guard while making it unit-testable.
func mustParsePrivateNetworks(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("proxy: invalid private network CIDR %q: %v", cidr, err))
		}
		nets = append(nets, network)
	}
	return nets
}

// hashRemoteAddr returns the first 8 hex characters of sha256(addr).
// This provides a linkable identifier within a session without exposing
// the actual client IP address in logs.
func hashRemoteAddr(addr string) string {
	h := sha256.Sum256([]byte(addr))
	return hex.EncodeToString(h[:4])
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

// lookupIPAddr resolves a hostname to IP addresses. It is a package var so tests
// can substitute a deterministic resolver.
var lookupIPAddr = net.DefaultResolver.LookupIPAddr

// dialContextFn performs the actual outbound dial. It is a package var (the real
// (*net.Dialer).DialContext) so tests can observe the exact address
// ssrfSafeDialContext dials — proving the direct-dial fallback uses the raw addr
// and the post-resolution dial targets the inspected IP (not the original
// hostname), which the SSRF protection depends on.
var dialContextFn = (*net.Dialer).DialContext

// ssrfSafeDialContext wraps a net.Dialer and checks the resolved IP address
// at connection time — eliminating the TOCTOU gap between DNS resolution and dial.
func ssrfSafeDialContext(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return dialContextFn(d, ctx, network, addr)
		}

		// Resolve the hostname ourselves so we can inspect the IPs
		ips, err := lookupIPAddr(ctx, host)
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
		return dialContextFn(d, ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
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
		cfg: cfg,
		anon: func() *anonymizer.Anonymizer {
			a := anonymizer.NewWithCacheAndCapacity(anonymizer.Options{
				OllamaEndpoint:      cfg.OllamaEndpoint,
				OllamaModel:         cfg.OllamaModel,
				UseAI:               cfg.UseAIDetection,
				AIThreshold:         cfg.AIConfidence,
				OllamaMaxConcurrent: cfg.OllamaMaxConcurrent,
				Metrics:             m,
				CachePath:           cfg.OllamaCacheFile,
				CacheCapacity:       50_000,
				EnabledPacks:        cfg.EnabledPacks,
				PackDecayRate:       cfg.PackDecayRate,
			})
			a.SetPIIInstructions(cfg.PIIInstructions)
			return a
		}(),
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

// mitmContext holds context for processing a MITM-intercepted request.
type mitmContext struct {
	host       string
	domain     string
	remoteHash string
}

// handleMITMTunnel intercepts HTTPS connections to AI API domains.
// It performs TLS termination with a dynamically generated certificate,
// reads the plaintext HTTP request, anonymizes it, and forwards upstream.
func (s *Server) handleMITMTunnel(w http.ResponseWriter, r *http.Request, host, domain string) {
	remoteHash := hashRemoteAddr(r.RemoteAddr)
	log.Printf("[MITM] %s Intercepting CONNECT %s", remoteHash, host)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[MITM] %s Hijacking not supported for %s", remoteHash, host)
		s.handleOpaqueTunnel(w, r, host)
		return
	}

	// Tell the client the tunnel is established
	w.WriteHeader(http.StatusOK)

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[MITM] %s Hijack error for %s: %v", remoteHash, host, err)
		return
	}
	defer func() { _ = clientConn.Close() }()

	// Build a handler that anonymizes and forwards requests
	ctx := mitmContext{host: host, domain: domain, remoteHash: remoteHash}
	handler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		s.serveMITMRequest(rw, req, ctx)
	})

	// Perform TLS handshake and serve HTTP/1.1 or HTTP/2
	mitm.HandleConn(clientConn, domain, s.ca, handler)
}

// serveMITMRequest handles a single HTTP request inside a MITM-intercepted TLS connection.
func (s *Server) serveMITMRequest(rw http.ResponseWriter, req *http.Request, ctx mitmContext) {
	// Fix up the request URL to be absolute for the transport
	req.URL.Scheme = "https"
	req.URL.Host = ctx.host
	req.RequestURI = ""

	isAuth := s.isAuthRequest(ctx.domain, req.URL.Path)
	s.recordMITMMetrics(isAuth)

	sessionID, release, ok := s.processMITMRequestBody(rw, req, ctx, isAuth)
	if !ok {
		return // error already sent to client
	}
	defer release()
	if sessionID != "" {
		defer s.anon.DeleteSession(sessionID)
	}

	s.forwardMITMRequest(rw, req, sessionID, ctx.domain)
}

// recordMITMMetrics records metrics for a MITM request.
func (s *Server) recordMITMMetrics(isAuth bool) {
	if s.m == nil {
		return
	}
	s.m.RequestsTotal.Add(1)
	if isAuth {
		s.m.RequestsAuth.Add(1)
	} else {
		s.m.RequestsAnonymized.Add(1)
	}
}

// processMITMRequestBody anonymizes the request body for non-auth requests.
// Returns (sessionID, release, true) on success, ("", release, true) for auth
// pass-through, or ("", nil, false) on error (error response already sent to
// client). release frees the buffered body and must be called once the
// request has been forwarded.
func (s *Server) processMITMRequestBody(rw http.ResponseWriter, req *http.Request, ctx mitmContext, isAuth bool) (string, func(), bool) {
	if isAuth {
		log.Printf("[MITM] %s %s %s%s [AUTH][PASS]", ctx.remoteHash, req.Method, ctx.domain, req.URL.Path)
		return "", func() {}, true
	}

	sessionID, release, err := s.anonymizeRequestBody(req)
	if err != nil {
		log.Printf("[MITM] %s Anonymization error for %s: %v", ctx.remoteHash, ctx.domain, err)
		writeBodyError(rw, err)
		return "", nil, false
	}

	log.Printf("[MITM] %s %s %s%s [ANON] sessionID=%s tokens=%d",
		ctx.remoteHash, req.Method, ctx.domain, req.URL.Path, sessionID, s.anon.SessionTokenCount(sessionID))
	return sessionID, release, true
}

// forwardMITMRequest forwards the request upstream and writes the response.
func (s *Server) forwardMITMRequest(rw http.ResponseWriter, req *http.Request, sessionID string, domain string) {
	removeHopByHop(req.Header)
	upstreamStart := time.Now()
	resp, err := s.transport.RoundTrip(req)
	if err != nil {
		if s.m != nil {
			s.m.ErrorsUpstream.Add(1)
		}
		http.Error(rw, errBadGateway, http.StatusBadGateway)
		return
	}
	if s.m != nil {
		s.m.RecordUpstreamLatency(time.Since(upstreamStart))
	}
	defer func() { _ = resp.Body.Close() }()

	// De-anonymize response before returning to client
	s.deanonymizeResponseBody(resp, sessionID, domain)

	removeHopByHop(resp.Header)
	copyHeader(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	flushingCopy(rw, resp.Body)
}

// handleOpaqueTunnel establishes a TCP tunnel without inspecting the traffic.
func (s *Server) handleOpaqueTunnel(w http.ResponseWriter, r *http.Request, host string) {
	log.Printf("[TUNNEL] %s CONNECT %s", hashRemoteAddr(r.RemoteAddr), host)

	if isPrivateHost(host) {
		log.Printf("[TUNNEL] %s Blocked CONNECT to private address: %s", hashRemoteAddr(r.RemoteAddr), host)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Use ssrfSafeDialContext so DNS-resolved IPs are also checked (prevents rebinding).
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	destConn, err := s.dialContext(ctx, "tcp", host)
	if err != nil {
		log.Printf("[TUNNEL] %s Connection failed for %s: %v", hashRemoteAddr(r.RemoteAddr), host, err)
		http.Error(w, errBadGateway, http.StatusBadGateway)
		return
	}
	defer func() { _ = destConn.Close() }()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK) // send "200 Connection established"

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[TUNNEL] %s Hijack error for %s: %v", hashRemoteAddr(r.RemoteAddr), host, err)
		return
	}
	defer func() { _ = clientConn.Close() }()

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(destConn, clientConn); done <- struct{}{} }() // tunnel; EOF is normal
	go func() { _, _ = io.Copy(clientConn, destConn); done <- struct{}{} }() // tunnel; EOF is normal
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
		var (
			release func()
			err     error
		)
		sessionID, release, err = s.anonymizeRequestBody(r)
		if err != nil {
			log.Printf("[HTTP] %s Anonymization error for %s: %v", hashRemoteAddr(r.RemoteAddr), domain, err)
			writeBodyError(w, err)
			return
		}
		defer release()
		if sessionID != "" {
			defer s.anon.DeleteSession(sessionID)
		}
		log.Printf("[HTTP] %s %s %s%s [ANON] sessionID=%s tokens=%d",
			hashRemoteAddr(r.RemoteAddr), r.Method, domain, r.URL.Path, sessionID, s.anon.SessionTokenCount(sessionID))
	} else if isAuth {
		log.Printf("[HTTP] %s %s %s%s [AUTH][PASS]", hashRemoteAddr(r.RemoteAddr), r.Method, domain, r.URL.Path)
	} else {
		log.Printf("[HTTP] %s %s %s%s [PASS]", hashRemoteAddr(r.RemoteAddr), r.Method, domain, r.URL.Path)
	}

	// Forward the request
	s.forward(w, r, sessionID, domain)
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, sessionID string, domain string) {
	// Ensure the URL is absolute
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	if isPrivateHost(r.URL.Host) {
		log.Printf("[HTTP] %s Blocked request to private address: %s", hashRemoteAddr(r.RemoteAddr), r.URL.Host)
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
		http.Error(w, errBadGateway, http.StatusBadGateway)
		return
	}
	if s.m != nil {
		s.m.RecordUpstreamLatency(time.Since(upstreamStart))
	}
	defer func() { _ = resp.Body.Close() }()

	// De-anonymize response before returning to client
	s.deanonymizeResponseBody(resp, sessionID, domain)

	removeHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	flushingCopy(w, resp.Body)
}

// requestSpoolMemory is how much of an anonymized request body is kept in
// memory before the rest is spooled to an encrypted temporary file. It is a
// memory budget per in-flight request, not a size limit: typical chat
// requests (well under 1 MiB) never touch disk, while full-context requests
// cost at most this much buffer memory each, however large they are.
const requestSpoolMemory = 1 << 20

// randRead fills b with cryptographically secure random bytes. It is a package
// var so tests can inject a failing reader to exercise the timestamp fallback;
// crypto/rand.Read itself treats a reader error as fatal and cannot be made to
// return one in-process.
var randRead = rand.Read

// errRequestBodyLimit reports a body larger than the operator-configured
// maxRequestBodyBytes.
var errRequestBodyLimit = errors.New("request body exceeds maxRequestBodyBytes")

// errInvalidJSONBody reports a body whose Content-Type declares JSON but which
// is not valid JSON. Such a body is rejected rather than forwarded: it is
// anonymized as a stream, and once a syntax error shows the stream's output
// is not a JSON rewrite, the input before the error is no longer available
// to anonymize as text.
var errInvalidJSONBody = errors.New("request body declared as JSON is not valid JSON")

// clientBodyError wraps a failure reading the request body from the client.
type clientBodyError struct{ err error }

func (e *clientBodyError) Error() string { return "read request body: " + e.err.Error() }
func (e *clientBodyError) Unwrap() error { return e.err }

// limitedBody reads a client request body, counting bytes, enforcing the
// optional administrative limit (0 = none), and tagging read failures so
// they can be told apart from spool failures.
type limitedBody struct {
	r     io.Reader
	limit int64
	n     int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.n += int64(n)
	if b.limit > 0 && b.n > b.limit {
		return n, errRequestBodyLimit
	}
	if err != nil && err != io.EOF {
		err = &clientBodyError{err: err}
	}
	return n, err
}

// writeBodyError sends the client the status matching a request-body failure
// from anonymizeRequestBody: 413 for the configured limit, 400 when the
// client's body could not be read or is declared JSON but invalid, and 507
// when the proxy could not buffer the body (an operational resource failure
// such as a full spool disk).
func writeBodyError(w http.ResponseWriter, err error) {
	var clientErr *clientBodyError
	switch {
	case errors.Is(err, errRequestBodyLimit):
		http.Error(w, "request body exceeds the proxy's configured maxRequestBodyBytes limit", http.StatusRequestEntityTooLarge)
	case errors.As(err, &clientErr):
		http.Error(w, "could not read request body", http.StatusBadRequest)
	case errors.Is(err, errInvalidJSONBody):
		http.Error(w, "request body is declared as JSON (Content-Type) but is not valid JSON; nothing was forwarded", http.StatusBadRequest)
	default:
		http.Error(w, "proxy could not buffer the request body for anonymization", http.StatusInsufficientStorage)
	}
}

func newSessionID() string {
	b := make([]byte, 8)
	if _, err := randRead(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// anonymizeRequestBody anonymizes the request body into a bounded-memory
// spool and replaces r.Body with the anonymized result, with ContentLength
// and GetBody set to match. There is no built-in size limit; the optional
// maxRequestBodyBytes setting rejects bodies with more input bytes than that
// explicitly.
//
// A body whose Content-Type declares JSON (the LLM APIs this proxy serves) is
// anonymized as a stream, so memory does not grow with its size; if it is not
// valid JSON it is rejected with errInvalidJSONBody. Any other body is read
// whole and anonymized like the pre-streaming proxy did: as JSON if it is
// valid JSON, otherwise as one piece of text.
//
// On success it returns the session ID (empty when there is no body) and a
// release func that frees the spool; call it once the request has been
// forwarded. On failure nothing is forwarded: the error is errRequestBodyLimit,
// errInvalidJSONBody, a *clientBodyError, or a *bodyspool.StorageError (see
// writeBodyError).
func (s *Server) anonymizeRequestBody(r *http.Request) (string, func(), error) {
	noop := func() {}
	if r.Body == nil || r.ContentLength == 0 {
		return "", noop, nil
	}
	limit := s.cfg.MaxRequestBodyBytes
	if limit > 0 && r.ContentLength > limit {
		_ = r.Body.Close() // nothing will be read; close is best-effort
		s.recordAnonError()
		return "", nil, fmt.Errorf("declared body length %d: %w", r.ContentLength, errRequestBodyLimit)
	}

	sessionID := newSessionID()
	spool := bodyspool.New(s.cfg.RequestSpoolDir, requestSpoolMemory)
	src := &limitedBody{r: r.Body, limit: limit}
	streamed := declaresJSON(r.Header.Get("Content-Type"))

	anonStart := time.Now()
	var insertion *anonymizer.JSONInsertion
	var err error
	if streamed {
		insertion, err = s.streamJSONBody(spool, src, sessionID)
	} else {
		err = s.anonymizeWholeBody(spool, src, sessionID)
	}
	_ = r.Body.Close() // body fully consumed or abandoned; close is best-effort
	if err != nil {
		_ = spool.Close() // discard the partial body; close is best-effort
		s.anon.DeleteSession(sessionID)
		s.recordAnonError()
		return "", nil, err
	}
	if s.m != nil {
		s.m.RecordAnonLatency(time.Since(anonStart))
	}

	body := anonymizedBody{spool: spool, insertion: insertion}
	log.Printf("[ANON] sessionID=%s body in=%d out=%d bytes spool=%s streamed=%v",
		sessionID, src.n, body.size(), spoolLocation(spool), streamed)
	r.Body = io.NopCloser(body.reader())
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(body.reader()), nil }
	r.ContentLength = body.size()
	return sessionID, func() { _ = spool.Close() }, nil // close errors leave nothing to recover
}

// declaresJSON reports whether a Content-Type header names a JSON media type:
// application/json or any type with a +json structured-syntax suffix.
func declaresJSON(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

// streamJSONBody anonymizes a declared-JSON body from src into spool as a
// stream. An invalid document is reported as errInvalidJSONBody; the partial
// output is then discarded by the caller.
func (s *Server) streamJSONBody(spool *bodyspool.Spool, src io.Reader, sessionID string) (*anonymizer.JSONInsertion, error) {
	res, err := s.anon.AnonymizeJSONStream(spool, src, sessionID)
	if errors.Is(err, anonymizer.ErrInvalidJSON) {
		return nil, errInvalidJSONBody
	}
	return res.Insertion, err
}

// anonymizeWholeBody reads all of src, anonymizes it with AnonymizeJSON (a
// JSON rewrite for valid JSON, whole-text anonymization otherwise) and writes
// the result to spool. Memory holds the input and the output.
func (s *Server) anonymizeWholeBody(spool *bodyspool.Spool, src io.Reader, sessionID string) error {
	in, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	_, err = spool.Write(s.anon.AnonymizeJSON(in, sessionID))
	return err
}

func (s *Server) recordAnonError() {
	if s.m != nil {
		s.m.ErrorsAnonymize.Add(1)
	}
}

func spoolLocation(sp *bodyspool.Spool) string {
	if sp.OnDisk() {
		return "disk"
	}
	return "memory"
}

// anonymizedBody is a spooled anonymized body plus the PII-instruction
// insertion that completes it.
type anonymizedBody struct {
	spool     *bodyspool.Spool
	insertion *anonymizer.JSONInsertion
}

// size returns the length of the complete anonymized body.
func (b anonymizedBody) size() int64 {
	if b.insertion == nil {
		return b.spool.Size()
	}
	return b.spool.Size() + int64(len(b.insertion.Data))
}

// reader returns a new reader over the complete anonymized body.
func (b anonymizedBody) reader() io.Reader {
	r := b.spool.Reader()
	if b.insertion == nil {
		return r
	}
	return io.MultiReader(io.LimitReader(r, b.insertion.Offset), bytes.NewReader(b.insertion.Data), r)
}

func (s *Server) deanonymizeResponseBody(resp *http.Response, sessionID string, domain string) {
	if sessionID == "" || resp == nil || resp.Body == nil {
		log.Printf("[DEANON] skipping: sessionID=%q resp=%v bodyNil=%v", sessionID, resp == nil, resp != nil && resp.Body == nil)
		return
	}

	// Decompress the body before token replacement. The upstream may have
	// compressed the response even if we sent Accept-Encoding: identity,
	// so handle it defensively here.
	if err := decompressResponse(resp); err != nil {
		log.Printf("[DEANON] decompression error sessionID=%s: %v", sessionID, err)
	}

	ct := resp.Header.Get("Content-Type")
	streaming := isStreamingResponse(resp)
	log.Printf("[DEANON] sessionID=%s content-type=%q streaming=%v encoding=%q", sessionID, ct, streaming, resp.Header.Get(headerContentEncoding))

	// Streaming responses (SSE or unknown-length chunked) must never be fully
	// buffered: io.ReadAll blocks until the upstream closes the connection.
	// Wrap the body in a pipe-based reader that replaces tokens on-the-fly.
	if streaming {
		resp.Body = s.anon.StreamingDeanonymize(resp.Body, sessionID, domain)
		resp.ContentLength = -1 // length is unknown; let the client stream
		return
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close() // body already read; close is best-effort
	if err != nil {
		resp.Body = http.NoBody
		return
	}
	deanonymized := s.anon.DeanonymizeText(string(body), sessionID)
	log.Printf("[DEANON] non-streaming: body=%d bytes, deanon=%d bytes", len(body), len(deanonymized))
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

func (s *Server) isAuthRequest(domain, reqPath string) bool {
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
	// Clean the path to prevent traversal bypasses (e.g., /oauth/../admin)
	// and normalize double slashes (e.g., //oauth → /oauth).
	cleanPath := path.Clean(reqPath)
	if cleanPath == "" || cleanPath[0] != '/' {
		cleanPath = "/" + cleanPath
	}

	// Check path prefixes with proper boundary enforcement.
	// A configured authPath like "/oauth" must match:
	//   - exactly "/oauth"
	//   - sub-paths like "/oauth/callback"
	// but NOT:
	//   - "/oauthx" (suffix bypass)
	//   - "/oauth/../secret" (traversal, already handled by path.Clean)
	for authPath := range s.authPaths {
		if matchesAuthPath(cleanPath, authPath) {
			return true
		}
	}
	return false
}

// matchesAuthPath returns true if cleanPath matches authPath exactly or is a
// sub-path of authPath. This prevents suffix bypass attacks where "/oauthx"
// would incorrectly match an authPath of "/oauth".
func matchesAuthPath(cleanPath, authPath string) bool {
	// Exact match
	if cleanPath == authPath {
		return true
	}
	// Sub-path match: authPath must be a prefix followed by "/"
	// e.g., authPath="/oauth" matches cleanPath="/oauth/callback"
	if strings.HasPrefix(cleanPath, authPath) && len(cleanPath) > len(authPath) && cleanPath[len(authPath)] == '/' {
		return true
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

// decompressResponse transparently decompresses a gzip or deflate response body
// and removes the Content-Encoding header so the client receives plain text.
// If the encoding is unsupported or absent, the body is left unchanged.
func decompressResponse(resp *http.Response) error {
	enc := strings.ToLower(resp.Header.Get(headerContentEncoding))
	switch enc {
	case "gzip":
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("gzip reader: %w", err)
		}
		resp.Body = struct {
			io.Reader
			io.Closer
		}{gr, resp.Body}
		resp.Header.Del(headerContentEncoding)
		resp.ContentLength = -1
	case "deflate":
		resp.Body = struct {
			io.Reader
			io.Closer
		}{flate.NewReader(resp.Body), resp.Body}
		resp.Header.Del(headerContentEncoding)
		resp.ContentLength = -1
	case "", "identity":
		// nothing to do
	default:
		log.Printf("[DEANON] unsupported Content-Encoding %q — token replacement may fail", enc)
	}
	return nil
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
			_, _ = dst.Write(buf[:n]) // caller ignores; headers already sent
			if canFlush {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}
