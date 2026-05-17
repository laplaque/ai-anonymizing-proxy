//go:build windows

package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"golang.org/x/sys/windows/svc"
)

// runAsServiceIfNeeded returns true when the current process was launched by
// the Windows Service Control Manager and the service lifecycle has finished.
// In that case main() must return immediately. When the process is a normal
// CLI invocation it returns false so main() can fall through to its
// signal-driven loop.
func runAsServiceIfNeeded(srv *http.Server) bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("[SERVICE] IsWindowsService check failed: %v", err)
		return false
	}
	if !isService {
		return false
	}
	if err := svc.Run("ai-proxy", &proxyService{srv: srv}); err != nil {
		log.Fatalf("[SERVICE] svc.Run: %v", err)
	}
	return true
}

type proxyService struct {
	srv *http.Server
}

func (p *proxyService) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	serveErr := make(chan error, 1)
	go func() {
		err := p.srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	status <- svc.Status{State: svc.Running, Accepts: accepts}

	for {
		select {
		case err := <-serveErr:
			if err != nil {
				log.Printf("[SERVICE] HTTP server exited: %v", err)
				return false, 1
			}
			return false, 0
		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, Accepts: accepts}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				if err := p.srv.Shutdown(ctx); err != nil {
					log.Printf("[SERVICE] shutdown: %v", err)
				}
				cancel()
				<-serveErr
				return false, 0
			}
		}
	}
}
