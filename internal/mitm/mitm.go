package mitm

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"

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
	defer tlsConn.Close()

	// Use an http.Server to handle both HTTP/1.1 and HTTP/2 on this connection.
	// The server reads requests from the decrypted TLS connection and dispatches
	// them to the handler.
	srv := &http.Server{
		Handler: handler,
	}

	// Configure HTTP/2 support on the server
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		log.Printf("[MITM] H2 config error for %s: %v", host, err)
	}

	// Determine which protocol was negotiated
	proto := tlsConn.ConnectionState().NegotiatedProtocol

	switch proto {
	case "h2":
		// Serve HTTP/2 directly on the TLS connection
		srv.TLSConfig = tlsCfg
		h2srv := &http2.Server{}
		h2srv.ServeConn(tlsConn, &http2.ServeConnOpts{
			Handler: handler,
		})
	default:
		// HTTP/1.1: serve using a single-connection listener
		ln := &singleConnListener{conn: tlsConn}
		srv.Serve(ln) //nolint:errcheck
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
		// Block until the server shuts down
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
