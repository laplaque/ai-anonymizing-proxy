package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"time"
)

// svcCommand is the platform-agnostic command vocabulary the service
// lifecycle understands. The Windows SCM bridge in service_windows.go
// translates svc.ChangeRequest values onto this set; tests do the same
// without pulling in the Windows-only svc package.
type svcCommand int

const (
	cmdInterrogate svcCommand = iota + 1
	cmdStop
)

// svcStatusReporter is the platform-agnostic write-side of the service
// status channel. The Windows bridge maps these calls onto svc.Status
// values; tests record them on a slice.
type svcStatusReporter interface {
	StartPending()
	Running()
	StopPending()
	Interrogate() // re-emit the most recent status
}

// shutdownDeadline is how long a shutdown handler waits for srv.Shutdown
// before forcibly returning. Shared by the SCM Stop arm and the CLI
// signal handler so the graceful budget cannot drift between platforms.
// Declared as a var so tests can shrink it to exercise the timeout branch.
var shutdownDeadline = 15 * time.Second

// runServiceLifecycle implements the SCM contract in a platform-neutral
// way: report StartPending, hand the HTTP server and its already-bound
// listener to a goroutine, report Running, then either propagate a server
// error or honor a Stop command with a bounded graceful shutdown. Returns
// the SCM service-specific exit code (0 on clean stop, 1 on server
// failure). Taking a bound listener (rather than binding internally) means
// startup bind failures surface in main before the SCM handshake, and the
// serve loop cannot lose a port race (issue #140).
func runServiceLifecycle(srv *http.Server, ln net.Listener, requests <-chan svcCommand, status svcStatusReporter) uint32 {
	status.StartPending()

	serveErr := make(chan error, 1)
	go func() {
		err := serveFunc(srv, ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	status.Running()

	for {
		select {
		case err := <-serveErr:
			return svcExitCode(err)
		case cmd := <-requests:
			switch cmd {
			case cmdInterrogate:
				status.Interrogate()
			case cmdStop:
				status.StopPending()
				ctx, cancel := context.WithTimeout(context.Background(), shutdownDeadline)
				if err := srv.Shutdown(ctx); err != nil {
					log.Printf("[SERVICE] shutdown: %v", err)
				}
				cancel()
				return svcExitCode(<-serveErr)
			}
		}
	}
}

// serveFunc is a seam over (*http.Server).Serve so tests can drive the
// post-Stop drain with a non-nil terminal error. That state is unreachable
// deterministically through a real Server — its Serve maps every
// post-Shutdown accept failure to ErrServerClosed — yet occurs in
// production whenever a real Serve failure races a Stop command.
// Production value is the real Serve; only tests swap it.
var serveFunc = func(srv *http.Server, ln net.Listener) error { return srv.Serve(ln) }

// svcExitCode maps the serve goroutine's terminal error to the SCM
// service-specific exit code, logging real failures. Shared by the
// error arm and the post-Stop drain so a Serve failure that races a Stop
// command is reported instead of silently swallowed as a clean stop.
func svcExitCode(err error) uint32 {
	if err != nil {
		log.Printf("[SERVICE] HTTP server exited: %v", err)
		return 1
	}
	return 0
}
