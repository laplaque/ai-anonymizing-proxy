// Package anonymizer — cache.go
//
// PersistentCache is the interface for the cross-session Ollama value cache.
// It stores original PII value → anonymized token mappings that survive
// process restarts, so recurring values get a cache hit from the first
// request of a new session.
//
// Two implementations are provided:
//   - memoryCache  — in-memory only, used in tests and when no path is configured.
//   - bboltCache   — embedded key-value store (bbolt), used in production.
//
// The interface is intentionally minimal. The anonymizer writes entries one
// value at a time from async Ollama goroutines; reads are per-value lookups
// from the regex match loop. Batch operations and iteration are not needed.
package anonymizer

import (
	"fmt"
	"log"
	"sync"

	bolt "go.etcd.io/bbolt"
)

// PersistentCache is the cross-session Ollama value cache interface.
// All implementations must be safe for concurrent use.
type PersistentCache interface {
	// Get returns the cached token for the given original PII value, if present.
	Get(original string) (token string, ok bool)

	// Set stores original → token. Overwrites any existing entry silently.
	Set(original, token string)

	// Close releases any resources held by the cache (e.g. file handles).
	// Must be called when the anonymizer is shut down.
	Close() error
}

// --- memoryCache ---------------------------------------------------------

// memoryCache is a thread-safe in-memory PersistentCache.
// Used in tests and as a fallback when no bbolt path is configured.
type memoryCache struct {
	mu    sync.RWMutex
	store map[string]string
}

func newMemoryCache() PersistentCache {
	return &memoryCache{store: make(map[string]string)}
}

func (c *memoryCache) Get(original string) (string, bool) {
	c.mu.RLock()
	v, ok := c.store[original]
	c.mu.RUnlock()
	return v, ok
}

func (c *memoryCache) Set(original, token string) {
	c.mu.Lock()
	c.store[original] = token
	c.mu.Unlock()
}

func (c *memoryCache) Close() error { return nil }

// --- bboltCache ----------------------------------------------------------

const bboltBucket = "ollama_cache"

// bboltCache is a PersistentCache backed by an embedded bbolt database.
// Entries survive process restarts. The database file is created at the
// given path if it does not exist.
type bboltCache struct {
	db *bolt.DB
}

// newBboltCache opens (or creates) the bbolt database at path and ensures
// the bucket exists. Returns an error if the file cannot be opened.
func newBboltCache(path string) (PersistentCache, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("open bbolt cache %q: %w", path, err)
	}

	// Ensure the bucket exists.
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bboltBucket))
		return err
	}); err != nil {
		db.Close() //nolint:errcheck // best-effort close on init failure
		return nil, fmt.Errorf("create bbolt bucket: %w", err)
	}

	log.Printf("[ANONYMIZER] persistent cache opened at %s", path)
	return &bboltCache{db: db}, nil
}

func (c *bboltCache) Get(original string) (string, bool) {
	var token string
	err := c.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bboltBucket))
		if b == nil {
			return nil
		}
		v := b.Get([]byte(original))
		if v != nil {
			token = string(v)
		}
		return nil
	})
	if err != nil {
		log.Printf("[ANONYMIZER] bbolt Get error: %v", err)
		return "", false
	}
	return token, token != ""
}

func (c *bboltCache) Set(original, token string) {
	if err := c.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bboltBucket))
		if b == nil {
			return fmt.Errorf("bucket %q not found", bboltBucket)
		}
		return b.Put([]byte(original), []byte(token))
	}); err != nil {
		log.Printf("[ANONYMIZER] bbolt Set error: %v", err)
	}
}

func (c *bboltCache) Close() error {
	return c.db.Close()
}
