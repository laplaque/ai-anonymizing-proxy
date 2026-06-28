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

	logs := captureLog(t)

	// Get with a nil bucket returns ("", false).
	if v, ok := c.Get("k"); ok || v != "" {
		t.Errorf("expected miss on nil bucket, got v=%q ok=%v", v, ok)
	}

	// Set with a nil bucket takes the nil-bucket branch, which returns an error
	// that Set logs. Assert the log to pin that branch (the no-persist check
	// below is satisfied by Get's own nil-bucket path regardless of Set).
	c.Set("k", "v")
	if !strings.Contains(logs.String(), "bbolt Set error") {
		t.Errorf("expected Set nil-bucket branch to log an error, got: %q", logs.String())
	}
	if v, ok := c.Get("k"); ok || v != "" {
		t.Errorf("Set on nil bucket should not persist, got v=%q ok=%v", v, ok)
	}

	// Delete with a nil bucket is a silent no-op: the nil-bucket guard returns
	// nil before touching b, so it must neither panic nor log an error. (If the
	// guard were dropped, b.Delete on a nil bucket would panic and fail here.)
	c.Delete("k")
	if strings.Contains(logs.String(), "bbolt Delete error") {
		t.Errorf("Delete on nil bucket should be a silent no-op, but logged: %q", logs.String())
	}
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

	logs := captureLog(t)

	// Get on a closed db: db.View returns an error → ("", false).
	if v, found := bc.Get("k"); found || v != "" {
		t.Errorf("expected miss on closed db, got v=%q found=%v", v, found)
	}

	// Delete on a closed db: db.Update returns an error which Delete logs.
	// Assert the log to pin the error branch (the call alone proves nothing).
	bc.Delete("k")
	if !strings.Contains(logs.String(), "bbolt Delete error") {
		t.Errorf("expected Delete closed-db branch to log an error, got: %q", logs.String())
	}
}
