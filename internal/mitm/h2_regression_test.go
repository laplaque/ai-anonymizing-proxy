package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// These tests pin HandleConn's observable HTTP/1.1 and HTTP/2 behavior using
// only the standard library, so they hold independently of which HTTP/2
// implementation HandleConn uses internally.

// startMITM runs HandleConn on one end of an in-memory pipe and returns a
// handshaken TLS client for the other end that negotiated proto, plus a
// channel closed when HandleConn returns.
func startMITM(t *testing.T, host, proto string, handler http.Handler) (*tls.Conn, <-chan struct{}) {
	t.Helper()
	certFile, keyFile := tempCA(t)
	ca, err := LoadCA(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		HandleConn(serverRaw, host, ca, handler)
	}()

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	tlsClient := tls.Client(clientRaw, &tls.Config{
		ServerName: host,
		RootCAs:    roots,
		NextProtos: []string{proto},
	})
	if err := tlsClient.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	if got := tlsClient.ConnectionState().NegotiatedProtocol; got != proto {
		t.Fatalf("negotiated %q, want %q", got, proto)
	}
	t.Cleanup(func() { _ = tlsClient.Close() })
	return tlsClient, done
}

// h2ClientFor returns an HTTP/2-only transport whose single connection is the
// already-handshaken tlsClient. Any further dial fails, so callers that issue
// concurrent requests must establish the connection with one request first.
func h2ClientFor(tlsClient *tls.Conn) *http.Transport {
	var protos http.Protocols
	protos.SetHTTP2(true)
	var dialed sync.Once
	return &http.Transport{
		Protocols: &protos,
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			var conn net.Conn
			dialed.Do(func() { conn = tlsClient })
			if conn == nil {
				return nil, errors.New("test transport: connection already dialed")
			}
			return conn, nil
		},
	}
}

// readServerSettings performs the client side of the HTTP/2 connection
// preface and returns the parameters of the server's initial SETTINGS frame
// (RFC 9113 §3.4, §6.5).
func readServerSettings(t *testing.T, conn net.Conn) map[uint16]uint32 {
	t.Helper()
	// Write the client preface concurrently: net.Pipe is unbuffered and the
	// server writes its own SETTINGS frame independently of reading ours.
	go func() {
		preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		preface = append(preface, 0, 0, 0, 0x4, 0, 0, 0, 0, 0) // empty SETTINGS
		_, _ = conn.Write(preface)
	}()

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	if frameType := hdr[3]; frameType != 0x4 {
		t.Fatalf("first server frame type = %#x, want SETTINGS (0x4)", frameType)
	}
	if length%6 != 0 {
		t.Fatalf("SETTINGS payload length %d is not a multiple of 6", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read SETTINGS payload: %v", err)
	}
	settings := make(map[uint16]uint32, length/6)
	for i := 0; i < length; i += 6 {
		settings[binary.BigEndian.Uint16(payload[i:])] = binary.BigEndian.Uint32(payload[i+2:])
	}
	return settings
}

// HTTP/2 SETTINGS parameter identifiers (RFC 9113 §6.5.2).
const (
	settingHeaderTableSize      = 0x1
	settingMaxConcurrentStreams = 0x3
	settingMaxFrameSize         = 0x5
)

// TestHandleConn_H2AdvertisesConfiguredSettings pins the HTTP/2 limits the
// MITM server advertises to clients: 250 concurrent streams, a 1 MiB maximum
// frame size, and a 4096-byte HPACK decoder table.
func TestHandleConn_H2AdvertisesConfiguredSettings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	tlsClient, _ := startMITM(t, "h2settings.example.com", "h2", handler)

	settings := readServerSettings(t, tlsClient)

	want := map[uint16]uint32{
		settingMaxConcurrentStreams: 250,
		settingMaxFrameSize:         1 << 20,
	}
	for id, v := range want {
		if got, ok := settings[id]; !ok || got != v {
			t.Errorf("SETTINGS[%#x] = %d (present=%v), want %d; all settings: %v", id, got, ok, v, settings)
		}
	}
	// 4096 is the protocol default for SETTINGS_HEADER_TABLE_SIZE, so a server
	// may omit it; if present it must still be 4096.
	if got, ok := settings[settingHeaderTableSize]; ok && got != 4096 {
		t.Errorf("SETTINGS_HEADER_TABLE_SIZE = %d, want 4096", got)
	}
}

// TestHandleConn_H2ConcurrentStreams multiplexes many concurrent requests with
// distinct bodies over one MITM HTTP/2 connection and verifies every response
// is HTTP/2 and carries back exactly the request body the handler saw.
func TestHandleConn_H2ConcurrentStreams(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(body)
		w.Header().Set("X-Body-SHA256", fmt.Sprintf("%x", sum))
		_, _ = w.Write(body)
	})
	tlsClient, _ := startMITM(t, "h2concurrent.example.com", "h2", handler)
	tr := h2ClientFor(tlsClient)
	defer tr.CloseIdleConnections()

	// Establish the single HTTP/2 connection before fanning out, so the
	// concurrent requests below all multiplex onto it.
	warm, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"https://h2concurrent.example.com/echo", bytes.NewReader([]byte("warm-up")))
	if err != nil {
		t.Fatal(err)
	}
	warmResp, err := tr.RoundTrip(warm)
	if err != nil {
		t.Fatalf("warm-up RoundTrip: %v", err)
	}
	_, _ = io.Copy(io.Discard, warmResp.Body)
	_ = warmResp.Body.Close()

	const streams = 32
	var wg sync.WaitGroup
	errs := make(chan error, streams)
	for i := range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := bytes.Repeat([]byte{byte('a' + i%26)}, 64<<10+i)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
				"https://h2concurrent.example.com/echo", bytes.NewReader(body))
			if err != nil {
				errs <- err
				return
			}
			resp, err := tr.RoundTrip(req)
			if err != nil {
				errs <- fmt.Errorf("stream %d: %w", i, err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				errs <- fmt.Errorf("stream %d read: %w", i, err)
				return
			}
			want := sha256.Sum256(body)
			switch {
			case resp.ProtoMajor != 2:
				errs <- fmt.Errorf("stream %d: proto %s, want HTTP/2", i, resp.Proto)
			case !bytes.Equal(got, body):
				errs <- fmt.Errorf("stream %d: echoed %d bytes, want %d", i, len(got), len(body))
			case resp.Header.Get("X-Body-SHA256") != fmt.Sprintf("%x", want):
				errs <- fmt.Errorf("stream %d: handler saw a different body", i)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestHandleConn_ReturnsWhenClientCloses verifies HandleConn returns once the
// client closes the connection after a completed exchange, for both
// protocols. HandleConn runs on the CONNECT handler's goroutine, so a
// HandleConn that never returns leaks that goroutine (and the server's) for
// every intercepted connection.
func TestHandleConn_ReturnsWhenClientCloses(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})

	t.Run("http1", func(t *testing.T) {
		tlsClient, done := startMITM(t, "h1close.example.com", "http/1.1", handler)
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://h1close.example.com/", http.NoBody)
		if err := req.Write(tlsClient); err != nil {
			t.Fatalf("write request: %v", err)
		}
		resp, err := http.ReadResponse(newBufReader(tlsClient), req)
		if err != nil {
			t.Fatalf("ReadResponse: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		_ = tlsClient.Close()
		waitReturned(t, done)
	})

	t.Run("h2", func(t *testing.T) {
		tlsClient, done := startMITM(t, "h2close.example.com", "h2", handler)
		tr := h2ClientFor(tlsClient)
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://h2close.example.com/", http.NoBody)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		tr.CloseIdleConnections()
		_ = tlsClient.Close()
		waitReturned(t, done)
	})
}

func waitReturned(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleConn did not return within 5s after the client closed the connection")
	}
}

func newBufReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }

// TestSingleConnListener_SecondAcceptBlocksUntilRelease pins the listener
// contract Serve relies on: the first Accept yields the connection, the next
// blocks until release, then reports net.ErrClosed. release is idempotent.
func TestSingleConnListener_SecondAcceptBlocksUntilRelease(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	l := newSingleConnListener(server)
	if _, err := l.Accept(); err != nil {
		t.Fatalf("first Accept: %v", err)
	}

	accepted := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		accepted <- err
	}()
	select {
	case err := <-accepted:
		t.Fatalf("second Accept returned before release: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	l.release()
	l.release() // must not panic
	select {
	case err := <-accepted:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("second Accept error = %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second Accept still blocked after release")
	}
	if err := l.Close(); err != nil {
		t.Errorf("Close after release: %v", err)
	}
}

// TestHandleConn_IdleTimeoutAppliesToH2Only pins the per-protocol idle
// policy: an idle HTTP/2 connection is closed after h2IdleTimeout (and
// HandleConn returns), while an idle HTTP/1.1 keep-alive connection stays
// usable, as before.
func TestHandleConn_IdleTimeoutAppliesToH2Only(t *testing.T) {
	orig := h2IdleTimeout
	t.Cleanup(func() { h2IdleTimeout = orig })
	h2IdleTimeout = 200 * time.Millisecond

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})

	t.Run("h2 closes when idle", func(t *testing.T) {
		tlsClient, done := startMITM(t, "h2idle.example.com", "h2", handler)
		tr := h2ClientFor(tlsClient)
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://h2idle.example.com/", http.NoBody)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		// The client keeps the connection open; only the idle timeout can end it.
		waitReturned(t, done)
	})

	t.Run("http1 keep-alive survives idle", func(t *testing.T) {
		tlsClient, done := startMITM(t, "h1idle.example.com", "http/1.1", handler)
		br := newBufReader(tlsClient)
		for i := range 2 {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://h1idle.example.com/", http.NoBody)
			if err := req.Write(tlsClient); err != nil {
				t.Fatalf("request %d write: %v", i, err)
			}
			resp, err := http.ReadResponse(br, req)
			if err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if i == 0 {
				time.Sleep(3 * h2IdleTimeout) // idle well past the h2 timeout
			}
		}
		select {
		case <-done:
			t.Fatal("HTTP/1.1 connection was closed while idle")
		default:
		}
	})
}
