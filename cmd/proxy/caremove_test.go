package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 — see caremove.go import comment; thumbprint format, not a security primitive
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertThumbprint_MatchesSHA1OfDER(t *testing.T) {
	pemPath, der := writeTestCert(t)

	got, err := certThumbprint(pemPath)
	if err != nil {
		t.Fatalf("certThumbprint: %v", err)
	}

	want := sha1.Sum(der) // #nosec G401 — see test-file header
	wantHex := strings.ToUpper(hex.EncodeToString(want[:]))
	if got != wantHex {
		t.Errorf("certThumbprint = %q, want %q", got, wantHex)
	}
}

func TestCertThumbprint_MissingFile(t *testing.T) {
	_, err := certThumbprint(filepath.Join(t.TempDir(), "missing.pem"))
	if err == nil || !strings.Contains(err.Error(), "read cert") {
		t.Errorf("err = %v, want substring 'read cert'", err)
	}
}

func TestCertThumbprint_NotPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(path, []byte("not a pem block at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := certThumbprint(path)
	if err == nil || !strings.Contains(err.Error(), "decode pem") {
		t.Errorf("err = %v, want substring 'decode pem'", err)
	}
}

func TestCertThumbprint_InvalidCertBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der at all")})
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := certThumbprint(path)
	if err == nil || !strings.Contains(err.Error(), "parse cert") {
		t.Errorf("err = %v, want substring 'parse cert'", err)
	}
}

// writeTestCert generates a minimal self-signed cert, writes it to a temp
// PEM file, and returns the path + the DER bytes for thumbprint comparison.
func writeTestCert(t *testing.T) (string, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ai-proxy-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	return path, der
}
