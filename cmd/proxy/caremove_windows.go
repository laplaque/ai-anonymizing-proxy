//go:build windows

package main

import (
	"fmt"
	"os/exec"
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

	// #nosec G204 — certutil.exe is a Windows-supplied tool; thumbprint is hex SHA-1 not external input
	cmd := exec.Command("certutil.exe", "-delstore", "Root", thumbprint)
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
