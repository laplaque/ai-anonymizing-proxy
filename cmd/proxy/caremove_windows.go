//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// removeCAFromStore removes the certificate at certPath from the Windows
// LocalMachine\Root trust store. Idempotent: a thumbprint that is not in
// the store is treated as success. Used by the MSI's uninstall custom
// action so the CA never lingers after `msiexec /x`.
func removeCAFromStore(certPath string) error {
	thumbprint, err := certThumbprint(certPath)
	if err != nil {
		return err
	}

	// Defense-in-depth before handing the value to certutil: enforce the
	// exact shape certThumbprint promises. A 40-char uppercase-hex string
	// cannot carry flags or argument structure, so the exec's safety is
	// checked here rather than argued in a comment.
	if !isSHA1Thumbprint(thumbprint) {
		return fmt.Errorf("refusing certutil call: thumbprint %q is not 40 uppercase hex chars", thumbprint)
	}
	// Anchor certutil to System32 instead of resolving it via PATH, so a
	// planted certutil.exe earlier in the search order cannot be executed
	// by the (typically elevated) uninstall action.
	systemRoot := os.Getenv("SystemRoot")
	if !filepath.IsAbs(systemRoot) {
		// Empty, relative, or otherwise non-absolute values would let a
		// poisoned environment redirect the (typically elevated) exec —
		// fall back to the stock location instead of trusting them.
		systemRoot = `C:\Windows`
	}
	cmd := exec.Command(filepath.Join(systemRoot, "System32", "certutil.exe"), "-delstore", "Root", thumbprint)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	// `certutil -delstore` exits non-zero when the thumbprint isn't present.
	// Treat that as already-removed so re-running the uninstaller is safe.
	if strings.Contains(string(out), "Cannot find object or property") ||
		strings.Contains(string(out), "0x80092004") {
		return nil
	}
	return fmt.Errorf("certutil -delstore Root %s: %w\n%s", thumbprint, err, out)
}
