package anonymizer

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMemoryCacheBasicOperations verifies the in-memory cache satisfies the
// PersistentCache contract.
func TestMemoryCacheBasicOperations(t *testing.T) {
	c := newMemoryCache()
	defer c.Close() //nolint:errcheck // test cleanup

	// Miss on empty cache.
	if _, ok := c.Get("missing"); ok {
		t.Error("expected miss on empty cache")
	}

	// Set and hit.
	c.Set("alice@example.com", "[PII_a3f29c81]")
	token, ok := c.Get("alice@example.com")
	if !ok {
		t.Error("expected hit after Set")
	}
	if token != "[PII_a3f29c81]" {
		t.Errorf("unexpected token: %q", token)
	}

	// Overwrite.
	c.Set("alice@example.com", "[PII_newtoken0]")
	token, ok = c.Get("alice@example.com")
	if !ok || token != "[PII_newtoken0]" {
		t.Errorf("expected overwritten token, got %q ok=%v", token, ok)
	}
}

// TestBboltCacheBasicOperations verifies the bbolt cache satisfies the
// PersistentCache contract.
func TestBboltCacheBasicOperations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	c, err := newBboltCache(path)
	if err != nil {
		t.Fatalf("newBboltCache: %v", err)
	}
	defer c.Close() //nolint:errcheck // test cleanup

	// Miss on empty db.
	if _, ok := c.Get("missing"); ok {
		t.Error("expected miss on empty db")
	}

	// Set and hit.
	c.Set("bob@corp.io", "[PII_bb3f1c2a]")
	token, ok := c.Get("bob@corp.io")
	if !ok {
		t.Error("expected hit after Set")
	}
	if token != "[PII_bb3f1c2a]" {
		t.Errorf("unexpected token: %q", token)
	}
}

// TestBboltCacheSurvivesRestart verifies that entries written to the bbolt
// cache are available after the database is closed and reopened — the core
// property that distinguishes persistent from in-memory cache.
func TestBboltCacheSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "persist.db")

	// Write entries and close.
	c1, err := newBboltCache(path)
	if err != nil {
		t.Fatalf("open first instance: %v", err)
	}
	c1.Set("alice@example.com", "[PII_a3f29c81]")
	c1.Set("555-867-5309", "[PII_7f4e1b02]")
	if err := c1.Close(); err != nil {
		t.Fatalf("close first instance: %v", err)
	}

	// Verify the file was actually written.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cache file missing after close: %v", err)
	}

	// Reopen and verify entries survive.
	c2, err := newBboltCache(path)
	if err != nil {
		t.Fatalf("open second instance: %v", err)
	}
	defer c2.Close() //nolint:errcheck // test cleanup

	token, ok := c2.Get("alice@example.com")
	if !ok || token != "[PII_a3f29c81]" {
		t.Errorf("email token did not survive restart: ok=%v token=%q", ok, token)
	}

	token, ok = c2.Get("555-867-5309")
	if !ok || token != "[PII_7f4e1b02]" {
		t.Errorf("phone token did not survive restart: ok=%v token=%q", ok, token)
	}
}

// TestNewWithCacheFallback verifies that NewWithCache falls back to an
// in-memory cache if the bbolt path is unwritable, rather than panicking.
func TestNewWithCacheFallback(t *testing.T) {
	a := NewWithCache("http://localhost:11434", "test-model", false, 0.80, 1, nil, "/nonexistent/path/cache.db")
	if a == nil {
		t.Fatal("expected non-nil anonymizer even with bad cache path")
	}
	defer a.Close() //nolint:errcheck // test cleanup

	// Should still anonymize correctly using the fallback memory cache.
	result := a.AnonymizeText("Contact alice@example.com", "sess-fallback")
	if result == "Contact alice@example.com" {
		t.Error("anonymization failed with fallback cache")
	}
}
