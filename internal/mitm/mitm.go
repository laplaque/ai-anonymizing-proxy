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

// HandleConn performs a TLS handshake on the hijacked client connection,
// then serves HTTP/1.1 or HTTP/2 requests through the provided handler.
// The handler receives plaintext HTTP requests that can be inspected and modified.
// It returns once the client connection has been closed.
func HandleConn(clientConn net.Conn, host string, ca *CA, handler http.Handler) {
	tlsCfg := ca.TLSConfigForHost(host)

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
