package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ai-anonymizing-proxy/internal/config"
)

// captureLog redirects the standard logger to a buffer for the duration of the
// test so a branch's distinctive log message can be asserted. These tests are
// not parallel, so the global SetOutput is safe.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// fakeTempFile is an injectable persistTempFile that lets tests force the
// write/close failure branches of persist without relying on real OS errors
// (which can't be provoked against a concrete *os.File, especially as root).
type fakeTempFile struct {
	name     string
	writeErr error
	closeErr error
}

func (f *fakeTempFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return len(p), nil
}

func (f *fakeTempFile) Close() error { return f.closeErr }
func (f *fakeTempFile) Name() string { return f.name }

// newRegistryWithPath builds a DomainRegistry wired to persistPath without
// loading from disk, so persist behavior can be tested in isolation.
func newRegistryWithPath(persistPath string) *DomainRegistry {
	return &DomainRegistry{
		domains:     make(map[string]bool),
		persistPath: persistPath,
	}
}

// A) MarshalIndent error path (seam #1).
func TestPersist_MarshalError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.json")
	orig := jsonMarshalIndent
	defer func() { jsonMarshalIndent = orig }()
	jsonMarshalIndent = func(_ any, _, _ string) ([]byte, error) {
		return nil, errors.New("forced marshal error")
	}

	r := newRegistryWithPath(path)
	r.persist([]string{"api.example.com"})

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file should not be written on marshal error, stat err = %v", err)
	}
}

// B) CreateTemp error path: parent directory of persistPath does not exist.
func TestPersist_CreateTempError(t *testing.T) {
	// "nope/sub" do not exist, so filepath.Dir(persistPath) is missing and
	// os.CreateTemp fails.
	path := filepath.Join(t.TempDir(), "nope", "sub", "domains.json")
	r := newRegistryWithPath(path)
	r.persist([]string{"api.example.com"})

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("target file should not exist after CreateTemp error, stat err = %v", err)
	}
}

// C) temp-file Write error path (seam #2).
func TestPersist_WriteError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.json")
	tmpName := filepath.Join(dir, "throwaway.tmp")

	orig := createPersistTempFile
	defer func() { createPersistTempFile = orig }()
	createPersistTempFile = func(_, _ string) (persistTempFile, error) {
		return &fakeTempFile{name: tmpName, writeErr: errors.New("forced write error")}, nil
	}

	r := newRegistryWithPath(path)
	logs := captureLog(t)
	r.persist([]string{"api.example.com"})

	// Pin the write-error branch by its distinctive log line. Without this, the
	// "file not created" check alone is satisfied by the downstream Rename of the
	// fake's (nonexistent) temp name, so the test would pass even if the
	// write-error branch were removed.
	if !strings.Contains(logs.String(), "Persist error (write)") {
		t.Errorf("expected write-error branch to log %q, got: %q", "Persist error (write)", logs.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("target file should not exist after write error, stat err = %v", err)
	}
}

// D) temp-file Close error path (seam #2): Write succeeds, Close fails.
func TestPersist_CloseError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.json")
	tmpName := filepath.Join(dir, "throwaway.tmp")

	orig := createPersistTempFile
	defer func() { createPersistTempFile = orig }()
	createPersistTempFile = func(_, _ string) (persistTempFile, error) {
		return &fakeTempFile{name: tmpName, closeErr: errors.New("forced close error")}, nil
	}

	r := newRegistryWithPath(path)
	logs := captureLog(t)
	r.persist([]string{"api.example.com"})

	// Pin the close-error branch by its distinctive log line (see write-error
	// test for why the file-absence check alone is insufficient).
	if !strings.Contains(logs.String(), "Persist error (close)") {
		t.Errorf("expected close-error branch to log %q, got: %q", "Persist error (close)", logs.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("target file should not exist after close error, stat err = %v", err)
	}
}

// E) Rename error path: persistPath is an existing directory, so the rename of
// the temp file onto it fails. Uses the real createPersistTempFile.
func TestPersist_RenameError(t *testing.T) {
	// persistPath itself is a directory; its parent (the enclosing temp dir)
	// exists, so CreateTemp/Write/Close succeed but Rename onto a directory
	// fails.
	dirAsPath := t.TempDir()
	r := newRegistryWithPath(dirAsPath)

	// Must not panic; persist swallows the rename error after cleanup.
	r.persist([]string{"api.example.com"})

	// The destination is still a directory (rename did not replace it).
	info, err := os.Stat(dirAsPath)
	if err != nil {
		t.Fatalf("stat persistPath: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("persistPath should still be a directory after rename failure")
	}
}

// F) Happy path: persist writes valid JSON to the target file.
func TestPersist_HappyPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.json")
	r := newRegistryWithPath(path)

	want := []string{"api.anthropic.com", "api.example.com"}
	r.persist(want)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("persist file not created: %v", err)
	}
	var got []string
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("invalid JSON in persist file: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// G) validDomain label-substring wildcard prefix/suffix validity branches.
func TestValidDomain_LabelSubstringWildcard(t *testing.T) {
	cases := []struct {
		domain string
		valid  bool
	}{
		// Valid label-substring wildcard (suffix is valid label piece).
		{"*-aiplatform.googleapis.com", true},
		// Suffix invalid: "_" is not a valid label-piece character.
		{"x*_.example.com", false},
		// Prefix invalid: "_" is not a valid label-piece character.
		{"_*x.example.com", false},
	}
	for _, tc := range cases {
		if got := validDomain(tc.domain); got != tc.valid {
			t.Errorf("validDomain(%q) = %v, want %v", tc.domain, got, tc.valid)
		}
	}
}

// H) writeJSON encode-error path: a channel cannot be JSON-encoded.
func TestWriteJSON_EncodeError(t *testing.T) {
	w := httptest.NewRecorder()
	logs := captureLog(t)
	// json.Encoder.Encode returns an error for unsupported types like chan.
	writeJSON(w, http.StatusOK, make(chan int))

	// Pin the encode-error branch by its distinctive log line. The status and
	// Content-Type are written BEFORE Encode runs, so asserting only those would
	// pass even if the error handling were removed.
	if !strings.Contains(logs.String(), "JSON encode error") {
		t.Errorf("expected encode-error branch to log %q, got: %q", "JSON encode error", logs.String())
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d to be written before encode, got %d", http.StatusOK, w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json content type, got %q", ct)
	}
}

// I) ListenAndServe error path: bind to an already-occupied port.
func TestListenAndServe_BindError(t *testing.T) {
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to occupy a port: %v", err)
	}
	defer func() { _ = ln.Close() }()
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", ln.Addr())
	}
	port := tcpAddr.Port

	cfg := &config.Config{ManagementPort: port}
	reg := NewDomainRegistry(cfg, "")
	s := New(cfg, reg, nil)

	if err := s.ListenAndServe(); err == nil {
		t.Error("expected ListenAndServe to fail binding an occupied port, got nil")
	}
}
