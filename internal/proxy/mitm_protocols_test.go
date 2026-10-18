package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
)

// TestHandleMITMTunnel_ProtocolsAnonymizeAndReturn drives a full intercepted
// exchange over both ALPN protocols the MITM server offers. For each it
// verifies the upstream receives the anonymized body (synthetic email
// replaced by a token), the client receives the de-anonymized echo over the
// negotiated protocol, and handleMITMTunnel returns once the client closes
// the tunnel.
func TestHandleMITMTunnel_ProtocolsAnonymizeAndReturn(t *testing.T) {
	const piiEmail = "alice.synthetic@example.com"
	reqBody := `{"model":"test-model","messages":[{"role":"user","content":"contact ` + piiEmail + `"}]}`

	for _, proto := range []string{"http/1.1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			var (
				mu       sync.Mutex
				upstream []byte
			)
			backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				mu.Lock()
				upstream = body
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				// Flush before writing so the echo is sent without a
				// Content-Length header. A Content-Length upstream currently
				// truncates de-anonymized responses on every protocol (#157);
				// this test pins the MITM protocol handling, not that bug.
				flusher, ok := w.(http.Flusher)
				if !ok {
					http.Error(w, "test backend cannot flush", http.StatusInternalServerError)
					return
				}
				flusher.Flush()
				_, _ = w.Write(body)
			}))
			defer backend.Close()
			backendHost := strings.TrimPrefix(backend.URL, "https://")

			srv, certFile := newMITMTestServer(t, backendHost)
			srv.transport, _ = backend.Client().Transport.(*http.Transport) // trust the backend's test cert

			hw := newHijackResponseWriter()
			connect := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "http://"+backendHost, nil)
			connect.Host = backendHost
			connect.RemoteAddr = "127.0.0.1:12345"
			returned := make(chan struct{})
			go func() {
				defer close(returned)
				srv.handleMITMTunnel(hw, connect, backendHost, backendHost)
			}()

			tlsClient := mitmTLSClient(t, hw.clientConn, backendHost, certFile, proto)

			resp := sendThroughTunnel(t, tlsClient, proto, "https://"+backendHost+"/v1/chat/completions", reqBody)
			echoed, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatalf("read response: %v", err)
			}

			wantMajor := 1
			if proto == "h2" {
				wantMajor = 2
			}
			if resp.ProtoMajor != wantMajor {
				t.Errorf("response protocol %s, want major version %d", resp.Proto, wantMajor)
			}

			mu.Lock()
			got := string(upstream)
			mu.Unlock()
			if strings.Contains(got, piiEmail) {
				t.Errorf("upstream received the original email; body: %s", got)
			}
			if !strings.Contains(got, "[PII_EMAIL_") {
				t.Errorf("upstream body has no email token; body: %s", got)
			}
			if !strings.Contains(string(echoed), piiEmail) {
				t.Errorf("client response was not de-anonymized; body: %s", echoed)
			}

			_ = tlsClient.Close()
			select {
			case <-returned:
			case <-time.After(5 * time.Second):
				t.Fatal("handleMITMTunnel did not return after the client closed the tunnel")
			}
		})
	}
}

// newMITMTestServer returns a proxy Server with a freshly generated MITM CA
// that treats host as an AI API domain, plus the CA certificate path.
func newMITMTestServer(t *testing.T, host string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca-cert.pem")
	cfg := &config.Config{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "test",
		AIAPIDomains:   []string{host},
		AuthDomains:    []string{},
		AuthPaths:      []string{},
		CACertFile:     certFile,
		CAKeyFile:      filepath.Join(dir, "ca-key.pem"),
		EnabledPacks:   []string{"GLOBAL"},
	}
	srv := New(cfg, management.NewDomainRegistry(cfg, ""), metrics.New())
	t.Cleanup(func() { _ = srv.Close() })
	if srv.ca == nil {
		t.Fatal("expected CA to be loaded")
	}
	return srv, certFile
}

// mitmTLSClient completes the client side of the TLS handshake on the
// hijacked tunnel, offering only proto via ALPN.
func mitmTLSClient(t *testing.T, conn net.Conn, host, certFile, proto string) *tls.Conn {
	t.Helper()
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add CA cert to pool")
	}
	// The MITM leaf certificate is issued for the CONNECT domain as given
	// (host:port here), matching TestHandleMITMTunnel.
	tlsClient := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: roots, NextProtos: []string{proto}})
	t.Cleanup(func() { _ = tlsClient.Close() })
	if err := tlsClient.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	if got := tlsClient.ConnectionState().NegotiatedProtocol; got != proto {
		t.Fatalf("negotiated %q, want %q", got, proto)
	}
	return tlsClient
}

// sendThroughTunnel POSTs body as JSON over the established tunnel using the
// negotiated protocol and returns the response.
func sendThroughTunnel(t *testing.T, tlsClient *tls.Conn, proto, url, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	if proto != "h2" {
		if err = req.Write(tlsClient); err != nil {
			t.Fatalf("write request: %v", err)
		}
		resp, readErr := http.ReadResponse(bufio.NewReader(tlsClient), req)
		if readErr != nil {
			t.Fatalf("ReadResponse: %v", readErr)
		}
		return resp
	}

	return roundTripH2(t, tlsClient, req)
}

// roundTripH2 sends req over the established HTTP/2 tunnel connection.
func roundTripH2(t *testing.T, tlsClient *tls.Conn, req *http.Request) *http.Response {
	t.Helper()
	var protos http.Protocols
	protos.SetHTTP2(true)
	var dialed sync.Once
	tr := &http.Transport{
		Protocols: &protos,
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			var conn net.Conn
			dialed.Do(func() { conn = tlsClient })
			if conn == nil {
				return nil, errors.New("test transport: tunnel already dialed")
			}
			return conn, nil
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 RoundTrip: %v", err)
	}
	return resp
}
