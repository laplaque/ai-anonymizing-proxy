//go:build windows

package main

import (
	"log"
	"net"
	"net/http"

	"golang.org/x/sys/windows/svc"
)

// runAsServiceIfNeeded returns true when the current process was launched by
// the Windows Service Control Manager and the service lifecycle has finished.
// In that case main() must return immediately. When the process is a normal
// CLI invocation it returns false so main() can fall through to its
// signal-driven loop. ln is the already-bound proxy listener.
func runAsServiceIfNeeded(srv *http.Server, ln net.Listener) bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("[SERVICE] IsWindowsService check failed: %v", err)
		return false
	}
	if !isService {
		return false
	}
	// Readiness for the SCM path: stop requests arrive via the SCM
	// channel (not OS signals) and are ordered by the StartPending →
	// Running handshake inside Execute, so logging after the bind is
	// race-free here (review N1's signal-gap concern is CLI-only).
	log.Printf("[PROXY] Listening on %s", ln.Addr())
	if err := svc.Run("ai-proxy", &proxyService{srv: srv, ln: ln}); err != nil {
		log.Fatalf("[SERVICE] svc.Run: %v", err)
	}
	return true
}

// proxyService is the SCM-facing adapter. It translates svc.ChangeRequest
// values onto the platform-neutral svcCommand vocabulary, runs the
// lifecycle in a goroutine, and forwards svc.Status updates from the
// platform-neutral reporter back to the SCM channel.
type proxyService struct {
	srv *http.Server
	ln  net.Listener
}

const svcAccepts = svc.AcceptStop | svc.AcceptShutdown

func (p *proxyService) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	requests := make(chan svcCommand, 4)
	reporter := &winStatusReporter{out: status}

	exit := make(chan uint32, 1)
	go func() {
		exit <- runServiceLifecycle(p.srv, p.ln, requests, reporter)
	}()

	for {
		select {
		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				requests <- cmdInterrogate
			case svc.Stop, svc.Shutdown:
				requests <- cmdStop
			}
		case code := <-exit:
			// A non-zero code must be flagged service-specific (ssec=true),
			// otherwise svc maps it into Win32ExitCode and the Event Log
			// shows a misleading generic error ("Incorrect function").
			return code != 0, code
		}
	}
}

type winStatusReporter struct {
	out  chan<- svc.Status
	last svc.State
}

func (w *winStatusReporter) StartPending() {
	w.last = svc.StartPending
	w.out <- svc.Status{State: w.last}
}
func (w *winStatusReporter) Running() {
	w.last = svc.Running
	w.out <- svc.Status{State: w.last, Accepts: svcAccepts}
}
func (w *winStatusReporter) StopPending() {
	w.last = svc.StopPending
	w.out <- svc.Status{State: w.last, Accepts: svcAccepts}
}
func (w *winStatusReporter) Interrogate() {
	w.out <- svc.Status{State: w.last, Accepts: svcAccepts}
}
