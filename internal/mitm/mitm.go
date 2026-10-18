package mitm

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
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

	// Determine which protocol was negotiated
	proto := tlsConn.ConnectionState().NegotiatedProtocol

	switch proto {
	case "h2":
		// Serve HTTP/2 directly on the TLS connection using a configured h2 server.
		// ServeConn errors are logged — previously they were silently discarded,
		// which caused ECONNRESET on the client with nothing in the proxy error log.
		h2srv := &http2.Server{
			MaxHandlers:                  0, // unlimited
			MaxConcurrentStreams:         250,
			MaxDecoderHeaderTableSize:    4096,
			MaxEncoderHeaderTableSize:    4096,
			MaxReadFrameSize:             1 << 20, // 1 MiB
			PermitProhibitedCipherSuites: false,
			IdleTimeout:                  90 * time.Second,
		}
		h2srv.ServeConn(tlsConn, &http2.ServeConnOpts{
			Handler: handler,
		})
	default:
		// HTTP/1.1: serve using a single-connection listener
		ln := newSingleConnListener(tlsConn)
		srv := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			// A hijacked connection is owned by its handler, so only a close
			// ends the listener; HandleConn must not close a connection still in use.
			ConnState: func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					ln.connDone()
				}
			},
		}
		_ = srv.Serve(ln) // returns net.ErrClosed once the connection is finished
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
