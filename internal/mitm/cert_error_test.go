package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- LoadOrGenerateCA error paths ---

func TestLoadOrGenerateCA_GenerateFails(t *testing.T) {
	dir := t.TempDir()
	// Non-existent subdirectory makes GenerateCA's os.OpenFile fail.
	certFile := filepath.Join(dir, "missing", "ca.pem")
	keyFile := filepath.Join(dir, "missing", "ca.key")

	_, err := LoadOrGenerateCA(certFile, keyFile)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to generate CA") {
		t.Errorf("error = %q, want contains %q", err.Error(), "failed to generate CA")
	}
}

func TestLoadOrGenerateCA_LoadGeneratedFails(t *testing.T) {
	dir := t.TempDir()
	// Same path for cert and key: GenerateCA writes the cert then truncates and
	// overwrites the same file with the key, so the reload finds a key where a
	// certificate is expected.
	path := filepath.Join(dir, "ca.pem")

	_, err := LoadOrGenerateCA(path, path)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to load generated CA") {
		t.Errorf("error = %q, want contains %q", err.Error(), "failed to load generated CA")
	}
}

// --- LoadCA: key parses as non-RSA via PKCS8 fallback ---

func TestLoadCA_KeyNotRSA(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.pem")
	keyFile := filepath.Join(dir, "ca.key")
	if err := GenerateCA(certFile, keyFile); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// Overwrite the key file with a PKCS8-encoded ECDSA (non-RSA) key.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if writeErr := os.WriteFile(keyFile, pemBytes, 0600); writeErr != nil {
		t.Fatalf("WriteFile: %v", writeErr)
	}

	_, err = LoadCA(certFile, keyFile)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not RSA") {
		t.Errorf("error = %q, want contains %q", err.Error(), "not RSA")
	}
}

// --- GenerateCA crypto error seams ---

func TestGenerateCA_SeamErrors(t *testing.T) {
	origRSA := rsaGenerateKey
	origInt := randInt
	origCreate := x509CreateCertificate
	defer func() {
		rsaGenerateKey = origRSA
		randInt = origInt
		x509CreateCertificate = origCreate
	}()

	tests := []struct {
		name    string
		setup   func()
		certOut string // "" => temp file
		keyOut  string // "" => temp file
		wantErr string
	}{
		{
			name: "rsaGenerateKey error",
			setup: func() {
				rsaGenerateKey = func(io.Reader, int) (*rsa.PrivateKey, error) {
					return nil, errors.New("no key")
				}
			},
			wantErr: "generate key",
		},
		{
			name: "randInt error",
			setup: func() {
				randInt = func(io.Reader, *big.Int) (*big.Int, error) {
					return nil, errors.New("no serial")
				}
			},
			wantErr: "generate serial",
		},
		{
			name: "x509CreateCertificate error",
			setup: func() {
				x509CreateCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
					return nil, errors.New("no cert")
				}
			},
			wantErr: "create CA cert",
		},
		{
			name:    "cert write error",
			setup:   func() {},
			certOut: "/dev/full",
			wantErr: "write cert PEM",
		},
		{
			name:    "key write error",
			setup:   func() {},
			keyOut:  "/dev/full",
			wantErr: "write key PEM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset seams to defaults before each subtest.
			rsaGenerateKey = origRSA
			randInt = origInt
			x509CreateCertificate = origCreate
			tt.setup()

			dir := t.TempDir()
			certFile := tt.certOut
			if certFile == "" {
				certFile = filepath.Join(dir, "ca.pem")
			}
			keyFile := tt.keyOut
			if keyFile == "" {
				keyFile = filepath.Join(dir, "ca.key")
			}

			err := GenerateCA(certFile, keyFile)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want contains %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// --- CertFor crypto error seams ---

func TestCertFor_SeamErrors(t *testing.T) {
	certFile, keyFile := tempCA(t)
	ca, err := LoadCA(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	origRSA := rsaGenerateKey
	origInt := randInt
	origCreate := x509CreateCertificate
	defer func() {
		rsaGenerateKey = origRSA
		randInt = origInt
		x509CreateCertificate = origCreate
	}()

	tests := []struct {
		name    string
		host    string
		setup   func()
		wantErr string
	}{
		{
			name: "leaf rsaGenerateKey error",
			host: "host-a.example",
			setup: func() {
				rsaGenerateKey = func(io.Reader, int) (*rsa.PrivateKey, error) {
					return nil, errors.New("no key")
				}
			},
			wantErr: "generate leaf key",
		},
		{
			name: "leaf randInt error",
			host: "host-b.example",
			setup: func() {
				randInt = func(io.Reader, *big.Int) (*big.Int, error) {
					return nil, errors.New("no serial")
				}
			},
			wantErr: "generate serial",
		},
		{
			name: "sign error",
			host: "host-c.example",
			setup: func() {
				x509CreateCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
					return nil, errors.New("no cert")
				}
			},
			wantErr: "sign leaf cert",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rsaGenerateKey = origRSA
			randInt = origInt
			x509CreateCertificate = origCreate
			tt.setup()

			_, err := ca.CertFor(tt.host)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want contains %q", err.Error(), tt.wantErr)
			}
		})
	}
}
