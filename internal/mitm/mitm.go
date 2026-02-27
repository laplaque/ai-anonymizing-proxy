package mitm

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// HandleConn performs a TLS handshake on the hijacked client connection,
// then serves HTTP/1.1 or HTTP/2 requests through the provided handler.
// The handler receives plaintext HTTP requests that can be inspected and modified.
func HandleConn(clientConn net.Conn, host string, ca *CA, handler http.Handler) {
	tlsCfg := ca.TLSConfigForHost(host)

	tlsConn := tls.Server(clientConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[MITM] TLS handshake failed for %s: %v", host, err)
		return
	}
	defer tlsConn.Close() //nolint:errcheck // best-effort close on TLS connection

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
		srv := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		ln := &singleConnListener{conn: tlsConn}
		srv.Serve(ln) //nolint:errcheck // always ErrServerClosed for single-conn listener
	}
}

// singleConnListener wraps a single net.Conn as a net.Listener.
// Accept returns the connection once, then blocks until Close is called.
type singleConnListener struct {
	conn net.Conn
	done bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		// Block forever; Serve() calls Close() when the handler returns,
		// which terminates the listener and unblocks the server.
		select {}
	}
	l.done = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error {
	return l.conn.Close()
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
