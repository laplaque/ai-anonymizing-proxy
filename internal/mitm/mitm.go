package mitm

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// h2IdleTimeout closes an intercepted HTTP/2 connection after this long
// without active streams. It is a var so tests can shorten it.
var h2IdleTimeout = 90 * time.Second

// h2Config holds the HTTP/2 limits the MITM server applies and advertises to
// clients. They are the values previously configured on x/net's
// http2.Server. Some equal the current net/http defaults, but they are pinned
// explicitly so a toolchain change cannot silently alter them.
var h2Config = http.HTTP2Config{
	MaxConcurrentStreams:         250,
	MaxDecoderHeaderTableSize:    4096,
	MaxEncoderHeaderTableSize:    4096,
	MaxReadFrameSize:             1 << 20, // 1 MiB
	PermitProhibitedCipherSuites: false,
}

// h2Supported reports whether net/http in this process serves HTTP/2.
// GODEBUG=http2server=0 (or the nethttpomithttp2 build tag) disables it, and
// net/http then drops any connection that negotiated "h2", so HandleConn only
// offers "h2" over ALPN when this is true. It is a var so tests can simulate
// the disabled case in-process.
var h2Supported = sync.OnceValue(probeH2Server)

// probeH2Server asks net/http itself rather than parsing GODEBUG: Serve
// installs the HTTP/2 handler in TLSNextProto before its first Accept, as it
// does for intercepted connections, unless HTTP/2 is disabled. The listener's
// only connection is marked taken and released, so Accept reports
// net.ErrClosed at once and Serve returns without serving anything.
func probeH2Server() bool {
	conn, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	ln := newSingleConnListener(conn)
	ln.accepted = true
	ln.release()

	cfg := h2Config
	srv := &http.Server{HTTP2: &cfg, ReadHeaderTimeout: 10 * time.Second}
	_ = srv.Serve(ln) // net.ErrClosed; Serve closes ln and with it conn
	_, ok := srv.TLSNextProto["h2"]
	return ok
}

// HandleConn performs a TLS handshake on the hijacked client connection,
// then serves HTTP/1.1 or HTTP/2 requests through the provided handler.
// The handler receives plaintext HTTP requests that can be inspected and modified.
// "h2" is offered over ALPN only when net/http can serve it (see h2Supported).
// It returns once the client connection has been closed.
func HandleConn(clientConn net.Conn, host string, ca *CA, handler http.Handler) {
	tlsCfg := ca.TLSConfigForHost(host)
	if !h2Supported() {
		tlsCfg.NextProtos = []string{"http/1.1"}
	}

	tlsConn := tls.Server(clientConn, tlsCfg)
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		log.Printf("[MITM] TLS handshake failed for %s: %v", host, err)
		return
	}
	defer func() { _ = tlsConn.Close() }() // best-effort close on TLS connection

	ln := newSingleConnListener(tlsConn)
	srv := newConnServer(tlsConn.ConnectionState().NegotiatedProtocol, handler, ln)
	_ = srv.Serve(ln) // returns once the connection closes; the error is always net.ErrClosed
}

// newConnServer builds the http.Server for one intercepted connection.
// net/http serves the connection as HTTP/2 when ALPN negotiated "h2" and as
// HTTP/1.1 otherwise. ReadHeaderTimeout bounds HTTP/1.1 header reads (the
// HTTP/2 server does not consult it); the idle timeout applies to HTTP/2
// only, so idle HTTP/1.1 keep-alive connections stay open as before.
func newConnServer(proto string, handler http.Handler, ln *singleConnListener) *http.Server {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// Release the listener when the connection closes so Serve returns.
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				ln.release()
			}
		},
	}
	if proto == "h2" {
		cfg := h2Config
		srv.HTTP2 = &cfg
		srv.IdleTimeout = h2IdleTimeout
	}
	return srv
}

// singleConnListener wraps a single net.Conn as a net.Listener.
// Accept returns the connection once; later calls block until the connection
// is released (closed) and then report net.ErrClosed, which ends Serve.
type singleConnListener struct {
	conn     net.Conn
	accepted bool // only touched by Serve's accept loop
	done     chan struct{}
	once     sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

// release unblocks a pending Accept. It is safe to call more than once.
func (l *singleConnListener) release() {
	l.once.Do(func() { close(l.done) })
}

func (l *singleConnListener) Close() error {
	l.release()
	return l.conn.Close()
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
