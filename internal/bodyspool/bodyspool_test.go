package bodyspool

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// syntheticBody returns n reproducible, incompressible bytes (SHA-256 in
// counter mode).
func syntheticBody(n int) []byte {
	b := make([]byte, 0, n+sha256.Size)
	var ctr [8]byte
	for i := uint64(0); len(b) < n; i++ {
		binary.BigEndian.PutUint64(ctr[:], i)
		sum := sha256.Sum256(ctr[:])
		b = append(b, sum[:]...)
	}
	return b[:n]
}

// writeInChunks writes b to s in uneven chunks, as a streaming producer does.
func writeInChunks(t *testing.T, s *Spool, b []byte) {
	t.Helper()
	for off, step := 0, 1; off < len(b); step = step*3 + 7 {
		end := min(off+step, len(b))
		n, err := s.Write(b[off:end])
		if err != nil || n != end-off {
			t.Fatalf("Write(%d bytes) = %d, %v", end-off, n, err)
		}
		off = end
	}
}

func readAll(t *testing.T, s *Spool) []byte {
	t.Helper()
	got, err := io.ReadAll(s.Reader())
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	return got
}

func TestSpoolInMemory(t *testing.T) {
	s := New(t.TempDir(), 1024)
	body := syntheticBody(1024)
	writeInChunks(t, s, body)
	if s.OnDisk() {
		t.Fatal("body at the memory limit spilled to disk")
	}
	if s.Size() != int64(len(body)) || !bytes.Equal(readAll(t, s), body) {
		t.Fatal("in-memory body did not round-trip")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestSpoolSpillsAndRoundTrips writes past the memory limit and verifies the
// body reads back byte-identical (by length and SHA-256) through several
// concurrent readers, with the file already unlinked from the directory.
func TestSpoolSpillsAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 4096)
	body := syntheticBody(3<<20 + 17)
	writeInChunks(t, s, body)
	if !s.OnDisk() {
		t.Fatal("body past the memory limit stayed in memory")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("spool file still linked in %s: %v", dir, entries)
	}
	want := sha256.Sum256(body)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := io.ReadAll(s.Reader())
			if err != nil {
				t.Errorf("concurrent read: %v", err)
				return
			}
			if len(got) != len(body) || sha256.Sum256(got) != want {
				t.Errorf("read back %d bytes with a different hash", len(got))
			}
		}()
	}
	wg.Wait()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestSpoolFileIsEncrypted keeps the file linked (as on platforms that cannot
// unlink open files) and verifies its contents are not the plaintext body,
// and that Close removes it.
func TestSpoolFileIsEncrypted(t *testing.T) {
	orig := removeFile
	t.Cleanup(func() { removeFile = orig })
	removeFile = func(string) error { return errors.New("unlink not supported") }

	dir := t.TempDir()
	s := New(dir, 16)
	body := bytes.Repeat([]byte("synthetic plaintext alice@example.com\n"), 1000)
	writeInChunks(t, s, body)

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one spool file, got %v (%v)", entries, err)
	}
	path := filepath.Join(dir, entries[0].Name())
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spool file: %v", err)
	}
	if len(onDisk) != len(body) {
		t.Errorf("spool file is %d bytes, body is %d", len(onDisk), len(body))
	}
	if bytes.Contains(onDisk, []byte("alice@example.com")) || bytes.Contains(onDisk, []byte("synthetic plaintext")) {
		t.Error("spool file contains plaintext")
	}
	if !bytes.Equal(readAll(t, s), body) {
		t.Error("encrypted body did not round-trip")
	}

	removeFile = orig
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("Close left the spool file behind: %v", err)
	}
}

// TestSpoolCreateFailure reports an unusable spool directory as a sticky
// StorageError.
func TestSpoolCreateFailure(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "missing"), 4)
	_, err := s.Write([]byte("more than four bytes"))
	var se *StorageError
	if !errors.As(err, &se) || se.Op != "create spool file" {
		t.Fatalf("err = %v, want create StorageError", err)
	}
	if _, err2 := s.Write([]byte("x")); !errors.Is(err2, se) {
		t.Errorf("later Write err = %v, want the sticky first error", err2)
	}
	if se.Unwrap() == nil || se.Error() == "" {
		t.Error("StorageError must expose its cause")
	}
}

// closedTemp returns a createTemp seam whose file is already closed, so every
// write to it fails.
func closedTemp(t *testing.T) func(string, string) (*os.File, error) {
	return func(_, pattern string) (*os.File, error) {
		f, err := os.CreateTemp(t.TempDir(), pattern)
		if err != nil {
			return nil, err
		}
		_ = f.Close()
		return f, nil
	}
}

// TestSpoolWriteFailure covers write failures both while spilling the
// buffered bytes and on a later direct write.
func TestSpoolWriteFailure(t *testing.T) {
	orig := createTemp
	t.Cleanup(func() { createTemp = orig })
	createTemp = closedTemp(t)

	s := New(t.TempDir(), 4)
	if _, err := s.Write([]byte("abc")); err != nil {
		t.Fatalf("in-memory write failed: %v", err)
	}
	_, err := s.Write([]byte("defgh"))
	var se *StorageError
	if !errors.As(err, &se) || se.Op != "write spool file" {
		t.Fatalf("spill err = %v, want write StorageError", err)
	}

	s = New(t.TempDir(), 0) // empty memory part: the spill writes nothing
	if _, err = s.Write([]byte("x")); !errors.As(err, &se) || se.Op != "write spool file" {
		t.Fatalf("direct write err = %v, want write StorageError", err)
	}
}

// TestSpoolReadAndCloseFailures covers reading a file that failed underneath
// the spool and closing a file that can no longer be closed or removed.
func TestSpoolReadAndCloseFailures(t *testing.T) {
	s := New(t.TempDir(), 0)
	if _, err := s.Write([]byte("body")); err != nil {
		t.Fatal(err)
	}
	r := s.Reader()
	_ = s.f.Close() // simulate the descriptor failing underneath the reader
	_, err := io.ReadAll(r)
	var se *StorageError
	if !errors.As(err, &se) || se.Op != "read spool file" {
		t.Fatalf("read err = %v, want read StorageError", err)
	}
	if err := s.Close(); !errors.As(err, &se) || se.Op != "close spool file" {
		t.Fatalf("Close err = %v, want close StorageError", err)
	}

	orig := removeFile
	t.Cleanup(func() { removeFile = orig })
	removeFile = func(string) error { return errors.New("cannot remove") }
	s = New(t.TempDir(), 0)
	if _, err := s.Write([]byte("body")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); !errors.As(err, &se) || se.Op != "close spool file" {
		t.Fatalf("Close with failing remove: err = %v", err)
	}
}
