package main

import (
	"context"
	"errors"
	"log"
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

// shutdownDeadline is how long the SCM handler waits for srv.Shutdown
// before forcibly returning. Matches the CLI signal handler's budget so
// behavior is consistent across platforms. Declared as a var so tests
// can shrink it to exercise the timeout branch.
var shutdownDeadline = 15 * time.Second

// runServiceLifecycle implements the SCM contract in a platform-neutral
// way: report StartPending, hand the HTTP server to a goroutine, report
// Running, then either propagate a server error or honor a Stop command
// with a bounded graceful shutdown. Returns the SCM service-specific
// exit code (0 on clean stop, 1 on server failure).
func runServiceLifecycle(srv *http.Server, requests <-chan svcCommand, status svcStatusReporter) uint32 {
	status.StartPending()

	serveErr := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	status.Running()

	for {
		select {
		case err := <-serveErr:
			if err != nil {
				log.Printf("[SERVICE] HTTP server exited: %v", err)
				return 1
			}
			return 0
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
				<-serveErr
				return 0
			}
		}
	}
}
