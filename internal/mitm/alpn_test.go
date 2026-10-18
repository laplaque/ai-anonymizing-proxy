package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// alpnChildEnv marks a re-executed test binary as the ALPN child process; see
// TestALPNChildProcess.
const alpnChildEnv = "MITM_ALPN_CHILD"

// alpnResult is what one dual-protocol request through HandleConn observed.
type alpnResult struct {
	negotiated string // ALPN protocol the TLS handshake selected
	served     string // r.Proto as seen by the handler ("" if never reached)
	err        error
}

func (r alpnResult) String() string {
	return fmt.Sprintf("negotiated=%q served=%q err=%v", r.negotiated, r.served, r.err)
}

// dualProtocolRequest sends one GET through HandleConn using a client that
// offers both "h2" and "http/1.1" over ALPN, as browsers and most HTTP
// libraries do, and reports which protocol was negotiated and served.
func dualProtocolRequest(t *testing.T) alpnResult {
	t.Helper()
	certFile, keyFile := tempCA(t)
	ca, err := LoadCA(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	const host = "alpn.example.com"
	var (
		mu         sync.Mutex
		negotiated string
		served     string
		wg         sync.WaitGroup
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served = r.Proto
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetHTTP2(true)
	tr := &http.Transport{
		Protocols: &protos,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			clientRaw, serverRaw := net.Pipe()
			wg.Go(func() { HandleConn(serverRaw, host, ca, handler) })
			conn := tls.Client(clientRaw, &tls.Config{
				ServerName: host,
				RootCAs:    roots,
				NextProtos: []string{"h2", "http/1.1"},
			})
			if hsErr := conn.HandshakeContext(ctx); hsErr != nil {
				_ = conn.Close()
				return nil, hsErr
			}
			mu.Lock()
			negotiated = conn.ConnectionState().NegotiatedProtocol
			mu.Unlock()
			return conn, nil
		},
	}
	t.Cleanup(func() {
		tr.CloseIdleConnections()
		wg.Wait()
	})

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", http.NoBody)
	var res alpnResult
	resp, err := tr.RoundTrip(req)
	if err == nil {
		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	res.err = err
	mu.Lock()
	res.negotiated, res.served = negotiated, served
	mu.Unlock()
	return res
}

// TestALPNChildProcess is the body of the subprocess started by
// TestHandleConn_ALPNMatchesServingCapability. GODEBUG is read once at process
// start, so the http2server=0 case needs a fresh process; the parent re-runs
// this test binary with only this test selected and alpnChildEnv set. In a
// normal test run alpnChildEnv is unset and there is nothing to do here.
func TestALPNChildProcess(t *testing.T) {
	if os.Getenv(alpnChildEnv) != "1" {
		return
	}
	fmt.Printf("ALPN-RESULT %s\n", dualProtocolRequest(t))
}

// TestHandleConn_ALPNMatchesServingCapability runs a dual-protocol client
// against HandleConn in a child process, with and without
// GODEBUG=http2server=0. The protocol offered over ALPN must be one net/http
// actually serves: with HTTP/2 disabled, net/http drops connections that
// negotiated "h2", so HandleConn must not offer it.
func TestHandleConn_ALPNMatchesServingCapability(t *testing.T) {
	cases := []struct {
		name    string
		godebug string
		want    alpnResult
	}{
		{name: "default", godebug: "", want: alpnResult{negotiated: "h2", served: "HTTP/2.0"}},
		{name: "http2server=0", godebug: "http2server=0", want: alpnResult{negotiated: "http/1.1", served: "HTTP/1.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			//nolint:gosec // G204: os.Args[0] is this test binary (the stdlib helper-process pattern); the arguments are constants, not external input.
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestALPNChildProcess$", "-test.count=1")
			cmd.Env = append(withoutEnv(os.Environ(), "GODEBUG"), alpnChildEnv+"=1", "GODEBUG="+tc.godebug)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child process: %v\n%s", err, out)
			}
			want := "ALPN-RESULT " + tc.want.String()
			if !strings.Contains(string(out), want+"\n") {
				t.Fatalf("child result mismatch\nwant: %s\ngot:\n%s", want, out)
			}
		})
	}
}

// TestHandleConn_OffersOnlyHTTP1WhenH2Unsupported covers the disabled branch
// in-process (the child process above does not contribute coverage): a
// dual-protocol client must negotiate and be served HTTP/1.1, with the
// unchanged HTTP/1.1 server (no idle timeout).
func TestHandleConn_OffersOnlyHTTP1WhenH2Unsupported(t *testing.T) {
	orig := h2Supported
	t.Cleanup(func() { h2Supported = orig })
	h2Supported = func() bool { return false }

	got := dualProtocolRequest(t)
	want := alpnResult{negotiated: "http/1.1", served: "HTTP/1.1"}
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

// TestProbeH2Server_MatchesHandleConnDefault pins that the probe reports
// HTTP/2 as available under the default GODEBUG settings, matching what
// HandleConn serves in the "default" child-process case above.
func TestProbeH2Server_MatchesHandleConnDefault(t *testing.T) {
	if !probeH2Server() {
		t.Fatalf("probeH2Server() = false with GODEBUG=%q; want true by default", os.Getenv("GODEBUG"))
	}
}

// withoutEnv returns env without any assignment to key.
func withoutEnv(env []string, key string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, key+"=") {
			out = append(out, kv)
		}
	}
	return out
}
