// Package bodyspool holds a request body of any size with bounded memory.
//
// A Spool keeps the first memLimit bytes in memory. When a body grows past
// that, the whole body moves to a temporary file encrypted with AES-256-CTR
// under a key generated per Spool and held only in process memory, so
// spooled bodies are unreadable on disk and become unrecoverable once the
// process forgets the key. Where the platform allows it, the file is unlinked
// as soon as it is created, so nothing is left behind even if the process is
// killed; otherwise Close removes it. A removal that fails is not forgotten:
// Close keeps the path and reports the error, and the path is queued for
// RetryRemovals, which later spools also run before creating their file.
//
// A Spool is written by one goroutine, then read any number of times, from
// any number of goroutines, through independent readers.
package bodyspool

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"os"
	"slices"
	"sync"
)

// StorageError reports that the spool could not store or read back body
// bytes, for example because the spool directory is missing, not writable,
// or out of space.
type StorageError struct {
	Op  string
	Err error
}

func (e *StorageError) Error() string { return "bodyspool: " + e.Op + ": " + e.Err.Error() }
func (e *StorageError) Unwrap() error { return e.Err }

// encryptChunk is the size of the scratch buffer used to encrypt writes.
const encryptChunk = 32 << 10

// Seams for tests.
var (
	createTemp = os.CreateTemp
	removeFile = os.Remove
)

// maxPendingRemovals bounds how many spool files whose removal failed are
// remembered for retry, so a persistently failing directory cannot grow the
// queue without limit. It is a var so tests can lower it.
var maxPendingRemovals = 1024

// pending holds spool file paths whose removal failed.
var pending struct {
	sync.Mutex
	paths []string
}

// queueRemoval remembers path for RetryRemovals. It reports false when the
// queue is full and path could not be remembered.
func queueRemoval(path string) bool {
	pending.Lock()
	defer pending.Unlock()
	if slices.Contains(pending.paths, path) {
		return true
	}
	if len(pending.paths) >= maxPendingRemovals {
		return false
	}
	pending.paths = append(pending.paths, path)
	return true
}

// RetryRemovals tries again to remove spool files whose earlier removal
// failed, and returns how many still could not be removed. A file that no
// longer exists counts as removed.
func RetryRemovals() int {
	pending.Lock()
	defer pending.Unlock()
	kept := pending.paths[:0]
	for _, path := range pending.paths {
		if err := removeFile(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			kept = append(kept, path)
		}
	}
	pending.paths = kept
	return len(kept)
}

// Spool accumulates a body; see the package documentation.
type Spool struct {
	dir      string
	memLimit int

	mem  []byte
	f    *os.File
	path string // set while the file still has to be removed by Close
	key  []byte
	iv   []byte
	enc  cipher.Stream
	buf  []byte
	size int64
	err  error // first storage error; later writes fail with it
}

// New returns an empty Spool that keeps up to memLimit bytes in memory and
// creates its file, if needed, in dir (os.TempDir() when dir is empty).
func New(dir string, memLimit int) *Spool {
	return &Spool{dir: dir, memLimit: memLimit}
}

// Write appends p to the body. Errors are *StorageError and are sticky.
func (s *Spool) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.f == nil {
		if len(s.mem)+len(p) <= s.memLimit {
			s.mem = append(s.mem, p...)
			s.size += int64(len(p))
			return len(p), nil
		}
		if err := s.spill(); err != nil {
			s.err = err
			return 0, err
		}
	}
	n, err := s.writeFile(p)
	s.size += int64(n)
	if err != nil {
		s.err = err
	}
	return n, err
}

// spill moves the in-memory bytes to a new encrypted temporary file. It
// first retries removals that failed for earlier spools.
func (s *Spool) spill() error {
	RetryRemovals()
	f, err := createTemp(s.dir, "ai-proxy-body-*")
	if err != nil {
		return &StorageError{Op: "create spool file", Err: err}
	}
	s.f = f
	// Unlink now where the platform allows it (all but Windows); the open
	// descriptor keeps the data reachable for this process only.
	if removeFile(f.Name()) != nil {
		s.path = f.Name()
	}
	s.key = make([]byte, 32)
	s.iv = make([]byte, aes.BlockSize)
	// crypto/rand.Read never returns an error; it aborts the program instead.
	_, _ = rand.Read(s.key)
	_, _ = rand.Read(s.iv)
	s.enc = newCTR(s.key, s.iv)
	s.buf = make([]byte, encryptChunk)
	mem := s.mem
	s.mem = nil
	_, err = s.writeFile(mem)
	return err
}

// writeFile encrypts p and appends it to the file.
func (s *Spool) writeFile(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := s.buf[:min(len(p), len(s.buf))]
		s.enc.XORKeyStream(chunk, p[:len(chunk)])
		n, err := s.f.Write(chunk)
		written += n
		if err != nil {
			return written, &StorageError{Op: "write spool file", Err: err}
		}
		p = p[len(chunk):]
	}
	return written, nil
}

func newCTR(key, iv []byte) cipher.Stream {
	block, _ := aes.NewCipher(key) // key is always 32 bytes, so this cannot fail
	return cipher.NewCTR(block, iv)
}

// Size returns the number of bytes written.
func (s *Spool) Size() int64 { return s.size }

// OnDisk reports whether the body moved to a spool file.
func (s *Spool) OnDisk() bool { return s.f != nil }

// Reader returns a new reader over the whole body. Readers are independent
// and may be used concurrently. A read failure of the spool file is a
// *StorageError.
func (s *Spool) Reader() io.Reader {
	if s.f == nil {
		return bytes.NewReader(s.mem)
	}
	return cipher.StreamReader{
		S: newCTR(s.key, s.iv),
		R: storageReader{io.NewSectionReader(s.f, 0, s.size)},
	}
}

// storageReader tags file read failures as StorageError.
type storageReader struct{ r io.Reader }

func (r storageReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err != nil && err != io.EOF {
		err = &StorageError{Op: "read spool file", Err: err}
	}
	return n, err
}

// Close releases the spool's memory and removes its file. Readers must not
// be used afterwards. If removing the file fails, Close returns a
// *StorageError, keeps the path so that calling Close again retries the
// removal, and queues it for RetryRemovals; the error says when the queue is
// full and the file will not be retried automatically. Close is otherwise
// idempotent.
func (s *Spool) Close() error {
	s.mem = nil
	var errs []error
	if s.f != nil {
		if err := s.f.Close(); err != nil {
			errs = append(errs, &StorageError{Op: "close spool file", Err: err})
		}
		s.f = nil
	}
	if s.path != "" {
		if err := removeFile(s.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			op := "remove spool file " + s.path + " (queued for retry)"
			if !queueRemoval(s.path) {
				op = "remove spool file " + s.path + " (retry queue full; remove it manually)"
			}
			errs = append(errs, &StorageError{Op: op, Err: err})
		} else {
			s.path = ""
		}
	}
	return errors.Join(errs...)
}
