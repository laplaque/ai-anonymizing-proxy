package main

import (
	"crypto/sha1" //nolint:gosec // G401: SHA-1 is the Windows cert-store thumbprint format; not a security primitive
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// certThumbprint returns the uppercase hex SHA-1 of the DER bytes of the
// PEM-encoded certificate at path. Matches the format `certutil -delstore`
// expects and what `Get-PfxCertificate | Select Thumbprint` reports, so
// the MSI uninstall path can remove the exact cert it installed.
func certThumbprint(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is an operator-supplied flag value
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
	sum := sha1.Sum(cert.Raw) //nolint:gosec // G401: see file-level note
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}
