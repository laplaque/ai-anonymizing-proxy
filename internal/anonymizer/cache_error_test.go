package anonymizer

import (
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// TestNewBboltCacheBucketError exercises the bucket-creation error path in
// newBboltCache by temporarily setting bboltBucket to the empty string, which
// makes CreateBucketIfNotExists return ErrBucketNameRequired.
func TestNewBboltCacheBucketError(t *testing.T) {
	orig := bboltBucket
	defer func() { bboltBucket = orig }()
	bboltBucket = ""

	c, err := newBboltCache(filepath.Join(t.TempDir(), "x.db"))
	if err == nil {
		t.Fatal("expected error from empty bucket name, got nil")
	}
	if !strings.Contains(err.Error(), "create bbolt bucket") {
		t.Errorf("expected 'create bbolt bucket' in error, got: %v", err)
	}
	if c != nil {
		t.Errorf("expected nil cache on bucket error, got: %v", c)
	}
}

// TestBboltCacheNilBucketPaths exercises the nil-bucket branches of Get, Set,
// and Delete by constructing a bboltCache over a raw db that has no bucket.
func TestBboltCacheNilBucketPaths(t *testing.T) {
	db, err := bolt.Open(filepath.Join(t.TempDir(), "nobucket.db"), 0600, nil)
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	c := &bboltCache{db: db}
	defer func() { _ = c.Close() }() // test cleanup

	// Get with a nil bucket returns ("", false).
	if v, ok := c.Get("k"); ok || v != "" {
		t.Errorf("expected miss on nil bucket, got v=%q ok=%v", v, ok)
	}

	// Set with a nil bucket logs an error and is a no-op (covers Set's nil-bucket
	// branch and the error-log path).
	c.Set("k", "v")
	if v, ok := c.Get("k"); ok || v != "" {
		t.Errorf("Set on nil bucket should not persist, got v=%q ok=%v", v, ok)
	}

	// Delete with a nil bucket is a no-op.
	c.Delete("k")
}

// TestBboltCacheClosedDBPaths exercises the error branches of Get and Delete
// when the underlying db has been closed (db.View / db.Update return an error).
func TestBboltCacheClosedDBPaths(t *testing.T) {
	c, err := newBboltCache(filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatalf("newBboltCache: %v", err)
	}
	bc, ok := c.(*bboltCache)
	if !ok {
		t.Fatalf("expected *bboltCache, got %T", c)
	}
	if closeErr := bc.Close(); closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}

	// Get on a closed db: db.View returns an error → ("", false).
	if v, found := bc.Get("k"); found || v != "" {
		t.Errorf("expected miss on closed db, got v=%q found=%v", v, found)
	}

	// Delete on a closed db: db.Update returns an error → error log.
	bc.Delete("k")
}
