// Package mitm provides MITM TLS termination for intercepting HTTPS traffic.
// It dynamically generates leaf certificates signed by a local CA, enabling
// the proxy to decrypt, inspect, and modify HTTPS request bodies.
package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"time"
)

const maxCertCache = 10_000

// CA holds certificate authority material for generating leaf certificates.
type CA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey

	mu    sync.RWMutex
	cache map[string]*tls.Certificate // hostname → leaf cert (Leaf field carries NotAfter)
}

// LoadOrGenerateCA loads a CA from PEM files, or generates one if the files
// don't exist. If the files exist but are invalid, an error is returned.
func LoadOrGenerateCA(certFile, keyFile string) (*CA, error) {
	// Try loading first
	ca, err := LoadCA(certFile, keyFile)
	if err == nil {
		log.Printf("[MITM] Loaded CA from %s / %s", certFile, keyFile)
		return ca, nil
	}

	// If files don't exist, generate
	if errors.Is(err, os.ErrNotExist) {
		log.Printf("[MITM] CA files not found, generating new CA...")
		if genErr := GenerateCA(certFile, keyFile); genErr != nil {
			return nil, fmt.Errorf("failed to generate CA: %w", genErr)
		}
		ca, err = LoadCA(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load generated CA: %w", err)
		}
		log.Printf("[MITM] Generated new CA: %s / %s", certFile, keyFile)
		log.Printf("[MITM] Trust the CA certificate to enable HTTPS interception:")
		log.Printf("[MITM]   macOS:   security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain %s", certFile)
		log.Printf("[MITM]   Linux:   sudo cp %s /usr/local/share/ca-certificates/ai-proxy.crt && sudo update-ca-certificates", certFile)
		log.Printf("[MITM]   Windows: certutil -addstore Root %s", certFile)
		return ca, nil
	}

	return nil, fmt.Errorf("failed to load CA: %w", err)
}

// LoadCA reads a CA certificate and private key from PEM files.
func LoadCA(certFile, keyFile string) (*CA, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block found in %s", certFile)
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block found in %s", keyFile)
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS8 as fallback (openssl may produce either format)
		key, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse CA key: %w (also tried PKCS8: %v)", err, err2)
		}
		var ok bool
		caKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("CA key is not RSA")
		}
	}

	return &CA{
		cert:  caCert,
		key:   caKey,
		cache: make(map[string]*tls.Certificate),
	}, nil
}

// GenerateCA creates a new self-signed CA certificate and private key,
// writing them to the specified PEM files.
func GenerateCA(certFile, keyFile string) error {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "AI-Proxy Local CA",
			Organization: []string{"AI Anonymizing Proxy"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	// Write cert PEM (public certificate — 0644 is intentional)
	certOut, err := os.OpenFile(certFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) //nolint:gosec // public cert but using 0600 for consistency
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer certOut.Close() //nolint:errcheck // best-effort close
	if encErr := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); encErr != nil {
		return fmt.Errorf("write cert PEM: %w", encErr)
	}

	// Write key PEM (restrictive permissions)
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer keyOut.Close() //nolint:errcheck // best-effort close
	if encErr := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); encErr != nil {
		return fmt.Errorf("write key PEM: %w", encErr)
	}

	return nil
}

// CertFor returns a TLS certificate for the given hostname, generating
// and caching one on first use. The leaf cert is signed by the CA.
func (ca *CA) CertFor(host string) (*tls.Certificate, error) {
	ca.mu.RLock()
	if c, ok := ca.cache[host]; ok {
		if c.Leaf != nil && time.Until(c.Leaf.NotAfter) > time.Hour {
			ca.mu.RUnlock()
			log.Printf("[MITM] Certificate cache hit for %s (expires %s)", host, c.Leaf.NotAfter.Format(time.RFC3339))
			return c, nil
		}
		log.Printf("[MITM] Certificate expired for %s, regenerating", host)
	}
	ca.mu.RUnlock()

	log.Printf("[MITM] Generating certificate for %s", host)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("[MITM] Failed to generate key for %s: %v", host, err)
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Printf("[MITM] Failed to generate serial for %s: %v", host, err)
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		log.Printf("[MITM] Failed to sign certificate for %s: %v", host, err)
		return nil, fmt.Errorf("sign leaf cert: %w", err)
	}

	leaf := &tls.Certificate{
		Certificate: [][]byte{derBytes, ca.cert.Raw},
		PrivateKey:  leafKey,
	}
	leaf.Leaf, _ = x509.ParseCertificate(derBytes)

	ca.mu.Lock()
	ca.cache[host] = leaf
	if len(ca.cache) > maxCertCache {
		// Certs are cheap to regenerate (~ms); clear the map rather than tracking LRU.
		ca.cache = make(map[string]*tls.Certificate)
		ca.cache[host] = leaf
	}
	ca.mu.Unlock()

	log.Printf("[MITM] Certificate cached for %s (expires %s)", host, leaf.Leaf.NotAfter.Format(time.RFC3339))
	return leaf, nil
}

// TLSConfigForHost returns a *tls.Config that presents a dynamically generated
// certificate for the given host, with H2 and HTTP/1.1 ALPN support.
func (ca *CA) TLSConfigForHost(host string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return ca.CertFor(host)
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
}
