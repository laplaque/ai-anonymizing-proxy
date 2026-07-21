package main

import (
	// SHA-1 is the on-the-wire fingerprint format Windows uses for
	// `certutil -delstore Root <thumbprint>`. It is not used as a
	// security primitive here — only to look up an already-installed
	// certificate by its publicly-known thumbprint.
	"crypto/sha1" // #nosec G505 — see comment above on weak-primitive justification
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// certThumbprint returns the uppercase hex SHA-1 of the DER bytes of the
// PEM-encoded certificate at path. Matches the format `certutil -delstore`
// expects and what `Get-PfxCertificate | Select Thumbprint` reports, so
// the MSI uninstall path can remove the exact cert it installed.
func certThumbprint(path string) (string, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read cert %q: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", fmt.Errorf("decode pem at %q: no PEM block found", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse cert at %q: %w", path, err)
	}
	sum := sha1.Sum(cert.Raw) // #nosec G401 — see import comment
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}
