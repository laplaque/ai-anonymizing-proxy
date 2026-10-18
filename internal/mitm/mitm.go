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

// HandleConn performs a TLS handshake on the hijacked client connection,
// then serves HTTP/1.1 or HTTP/2 requests through the provided handler.
// The handler receives plaintext HTTP requests that can be inspected and modified.
// It returns once the connection has been closed.
func HandleConn(clientConn net.Conn, host string, ca *CA, handler http.Handler) {
	tlsCfg := ca.TLSConfigForHost(host)

	tlsConn := tls.Server(clientConn, tlsCfg)
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		log.Printf("[MITM] TLS handshake failed for %s: %v", host, err)
		return
	}
	defer func() { _ = tlsConn.Close() }() // best-effort close on TLS connection

	ln := newSingleConnListener(tlsConn)
	srv := newMITMServer(handler, ln)
	_ = srv.Serve(ln) // returns net.ErrClosed once the connection is finished
}

// newMITMServer returns the server for one intercepted connection. net/http
// serves whichever protocol was negotiated via ALPN (TLSConfigForHost offers
// h2 and http/1.1); HTTP/2 uses net/http's built-in implementation, which
// replaces the deprecated golang.org/x/net/http2.Server with the same limits.
func newMITMServer(handler http.Handler, ln *singleConnListener) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		Protocols:         protocols,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:         250,
			MaxDecoderHeaderTableSize:    4096,
			MaxEncoderHeaderTableSize:    4096,
			MaxReadFrameSize:             1 << 20, // 1 MiB
			PermitProhibitedCipherSuites: false,
		},
		// A hijacked connection is owned by its handler, so only a close ends
		// the listener; HandleConn must not close a connection still in use.
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				ln.connDone()
			}
		},
	}
}

// singleConnListener wraps a single net.Conn as a net.Listener for
// http.Server.Serve. Accept returns the connection once; later calls block
// until the connection is finished or the listener is closed, then return
// net.ErrClosed so Serve returns.
type singleConnListener struct {
	conn     net.Conn
	accepted bool // only touched by Serve's accept loop
	done     chan struct{}
	doneOnce sync.Once
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

// connDone releases a blocked Accept. It is safe to call more than once.
func (l *singleConnListener) connDone() {
	l.doneOnce.Do(func() { close(l.done) })
}

func (l *singleConnListener) Close() error {
	l.connDone()
	return l.conn.Close()
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
