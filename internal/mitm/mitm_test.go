package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// tempCA generates a CA into a temp dir and returns (certFile, keyFile, dir).
func tempCA(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca-cert.pem")
	key := filepath.Join(dir, "ca-key.pem")
	if err := GenerateCA(cert, key); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	return cert, key
}

// --- GenerateCA ---

func TestGenerateCA_CreatesFiles(t *testing.T) {
	cert, key := tempCA(t)

	if _, err := os.Stat(cert); err != nil {
		t.Errorf("cert file missing: %v", err)
	}
	if _, err := os.Stat(key); err != nil {
		t.Errorf("key file missing: %v", err)
	}
}

func TestGenerateCA_FilePermissions(t *testing.T) {
	cert, key := tempCA(t)

	for _, path := range []string{cert, key} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		perm := info.Mode().Perm()
		if perm != 0600 {
			t.Errorf("%s permissions: got %04o, want 0600", path, perm)
		}
	}
}

// --- LoadCA ---

func TestLoadCA_Success(t *testing.T) {
	cert, key := tempCA(t)
	ca, err := LoadCA(cert, key)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if ca == nil {
		t.Fatal("LoadCA returned nil CA")
	}
	if ca.cert == nil {
		t.Error("CA.cert is nil")
	}
	if ca.key == nil {
		t.Error("CA.key is nil")
	}
	if ca.cache == nil {
		t.Error("CA.cache is nil")
	}
}

func TestLoadCA_MissingCertFile(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadCA(filepath.Join(dir, "missing.pem"), filepath.Join(dir, "key.pem"))
	if err == nil {
		t.Error("expected error for missing cert file")
	}
}

func TestLoadCA_MissingKeyFile(t *testing.T) {
	cert, _ := tempCA(t)
	dir := t.TempDir()
	_, err := LoadCA(cert, filepath.Join(dir, "missing-key.pem"))
	if err == nil {
		t.Error("expected error for missing key file")
	}
}

func TestLoadCA_InvalidCertPEM(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "bad-cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, []byte("not a pem"), 0600)
	os.WriteFile(keyFile, []byte("not a pem"), 0600)
	_, err := LoadCA(certFile, keyFile)
	if err == nil {
		t.Error("expected error for invalid cert PEM")
	}
}

// --- LoadOrGenerateCA ---

func TestLoadOrGenerateCA_GeneratesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca-cert.pem")
	key := filepath.Join(dir, "ca-key.pem")

	ca, err := LoadOrGenerateCA(cert, key)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if ca == nil {
		t.Fatal("expected non-nil CA")
	}

	// Files should now exist
	if _, err := os.Stat(cert); err != nil {
		t.Error("cert file was not generated")
	}
}

func TestLoadOrGenerateCA_LoadsExisting(t *testing.T) {
	cert, key := tempCA(t)
	ca, err := LoadOrGenerateCA(cert, key)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if ca == nil {
		t.Fatal("expected non-nil CA")
	}
}

func TestLoadOrGenerateCA_ErrorOnBadExistingCert(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca-cert.pem")
	key := filepath.Join(dir, "ca-key.pem")

	// Write garbage — the file exists but is invalid
	os.WriteFile(cert, []byte("garbage"), 0600)
	os.WriteFile(key, []byte("garbage"), 0600)

	_, err := LoadOrGenerateCA(cert, key)
	if err == nil {
		t.Error("expected error for invalid existing CA files")
	}
}

// --- CertFor ---

func TestCertFor_ReturnsValidCert(t *testing.T) {
	cert, key := tempCA(t)
	ca, _ := LoadCA(cert, key)

	tlsCert, err := ca.CertFor("example.com")
	if err != nil {
		t.Fatalf("CertFor: %v", err)
	}
	if tlsCert == nil {
		t.Fatal("expected non-nil tls.Certificate")
	}
	if tlsCert.Leaf == nil {
		t.Error("Leaf should be set")
	}
	if tlsCert.Leaf.Subject.CommonName != "example.com" {
		t.Errorf("CommonName: got %s, want example.com", tlsCert.Leaf.Subject.CommonName)
	}
}

func TestCertFor_CachesOnSecondCall(t *testing.T) {
	cert, key := tempCA(t)
	ca, _ := LoadCA(cert, key)

	c1, err := ca.CertFor("cache.example.com")
	if err != nil {
		t.Fatalf("first CertFor: %v", err)
	}
	c2, err := ca.CertFor("cache.example.com")
	if err != nil {
		t.Fatalf("second CertFor: %v", err)
	}

	// Pointer equality — second call must return the same object
	if c1 != c2 {
		t.Error("expected same *tls.Certificate on cache hit")
	}
}

func TestCertFor_DifferentHostsDifferentCerts(t *testing.T) {
	cert, key := tempCA(t)
	ca, _ := LoadCA(cert, key)

	c1, _ := ca.CertFor("alpha.example.com")
	c2, _ := ca.CertFor("beta.example.com")

	if c1 == c2 {
		t.Error("different hosts should produce different certs")
	}
	if c1.Leaf.Subject.CommonName == c2.Leaf.Subject.CommonName {
		t.Error("different hosts should have different CNs")
	}
}

func TestCertFor_CertSignedByCA(t *testing.T) {
	certFile, keyFile := tempCA(t)
	ca, _ := LoadCA(certFile, keyFile)

	tlsCert, _ := ca.CertFor("signed.example.com")

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	_, err := tlsCert.Leaf.Verify(x509.VerifyOptions{
		DNSName: "signed.example.com",
		Roots:   roots,
		CurrentTime: time.Now(),
	})
	if err != nil {
		t.Errorf("leaf cert should verify against CA: %v", err)
	}
}

func TestCertFor_ConcurrentAccess(t *testing.T) {
	cert, key := tempCA(t)
	ca, _ := LoadCA(cert, key)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ca.CertFor("concurrent.example.com"); err != nil {
				t.Errorf("concurrent CertFor: %v", err)
			}
		}()
	}
	wg.Wait()
}

// --- TLSConfigForHost ---

func TestTLSConfigForHost_ReturnsConfig(t *testing.T) {
	cert, key := tempCA(t)
	ca, _ := LoadCA(cert, key)

	cfg := ca.TLSConfigForHost("config.example.com")
	if cfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion: got %d, want TLS1.2 (%d)", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.GetCertificate == nil {
		t.Error("GetCertificate should be set")
	}
}

func TestTLSConfigForHost_GetCertificate_Works(t *testing.T) {
	cert, key := tempCA(t)
	ca, _ := LoadCA(cert, key)

	cfg := ca.TLSConfigForHost("getcert.example.com")
	tlsCert, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if tlsCert.Leaf.Subject.CommonName != "getcert.example.com" {
		t.Errorf("CN: got %s", tlsCert.Leaf.Subject.CommonName)
	}
}

func TestTLSConfigForHost_NextProtos(t *testing.T) {
	cert, key := tempCA(t)
	ca, _ := LoadCA(cert, key)

	cfg := ca.TLSConfigForHost("proto.example.com")
	protos := cfg.NextProtos

	hasH2 := false
	hasHTTP1 := false
	for _, p := range protos {
		if p == "h2" {
			hasH2 = true
		}
		if p == "http/1.1" {
			hasHTTP1 = true
		}
	}
	if !hasH2 {
		t.Error("NextProtos should include h2")
	}
	if !hasHTTP1 {
		t.Error("NextProtos should include http/1.1")
	}
}

// --- singleConnListener ---

func TestSingleConnListener_AcceptReturnsConn(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	l := &singleConnListener{conn: server}
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if conn != server {
		t.Error("Accept should return the wrapped connection")
	}
}

func TestSingleConnListener_CloseClosesConn(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	l := &singleConnListener{conn: server}
	if err := l.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// server conn should now be closed; reading should fail
	buf := make([]byte, 1)
	_, err := server.Read(buf)
	if err == nil {
		t.Error("expected error reading from closed conn")
	}
}

func TestSingleConnListener_Addr(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	l := &singleConnListener{conn: server}
	addr := l.Addr()
	if addr == nil {
		t.Error("Addr() should not be nil")
	}
}
