package anonymizer

import (
	"fmt"
	"sync"
	"testing"
)

// newTestS3FIFO creates a small S3-FIFO wrapping an in-memory backing cache
// for tests that do not need bbolt.
func newTestS3FIFO(capacity int) *s3fifoCache {
	c, ok := newS3FIFOCache(newMemoryCache(), capacity).(*s3fifoCache)
	if !ok {
		panic("newS3FIFOCache did not return *s3fifoCache")
	}
	return c
}

// ── Basic contract ───────────────────────────────────────────────────────────

func TestS3FIFOGetSetDelete(t *testing.T) {
	t.Parallel()
	c := newTestS3FIFO(10)
	defer c.Close() //nolint:errcheck

	// Miss on empty cache.
	if _, ok := c.Get("x"); ok {
		t.Error("expected miss on empty cache")
	}

	// Set then Get.
	c.Set("alice@example.com", "[PII_aabbccdd]")
	tok, ok := c.Get("alice@example.com")
	if !ok {
		t.Fatal("expected hit after Set")
	}
	if tok != "[PII_aabbccdd]" {
		t.Errorf("unexpected token: %q", tok)
	}

	// Overwrite.
	c.Set("alice@example.com", "[PII_11223344]")
	tok, ok = c.Get("alice@example.com")
	if !ok || tok != "[PII_11223344]" {
		t.Errorf("expected overwritten value, got %q ok=%v", tok, ok)
	}

	// Delete.
	c.Delete("alice@example.com")
	if _, ok := c.Get("alice@example.com"); ok {
		t.Error("expected miss after Delete")
	}
}

// ── Eviction: capacity enforcement ──────────────────────────────────────────

func TestS3FIFOCapacityEnforced(t *testing.T) {
	t.Parallel()
	capacity := 10
	c := newTestS3FIFO(capacity)
	defer c.Close() //nolint:errcheck

	// Fill to capacity with unique keys.
	for i := 0; i < capacity+5; i++ {
		c.Set(fmt.Sprintf("key-%d", i), fmt.Sprintf("tok-%d", i))
	}

	c.mu.Lock()
	total := c.sQueue.Len() + c.mQueue.Len()
	c.mu.Unlock()

	if total > capacity {
		t.Errorf("in-memory entries %d exceeds capacity %d", total, capacity)
	}
}

// ── Promotion: freq > 0 on S eviction triggers M promotion ─────────────────

func TestS3FIFOPromotionToM(t *testing.T) {
	t.Parallel()
	// capacity=2 → sTarget=1, mTarget=1.
	// S3-FIFO evicts only when total > capacity, so we need capacity+1 insertions
	// to trigger eviction of the oldest S entry.
	c := newTestS3FIFO(2)
	defer c.Close() //nolint:errcheck

	// Insert "hot" and access it so freq > 0.
	c.Set("hot", "tok-hot")
	c.Get("hot") // freq → 1

	// Fill to capacity.
	c.Set("cold", "tok-cold") // total=2, no eviction yet

	// One more insertion pushes total to 3 > 2, triggering evictFromS on "hot".
	// Because hot.freq > 0, it is promoted to M, not evicted.
	c.Set("extra", "tok-extra")

	c.mu.Lock()
	e, ok := c.entries["hot"]
	c.mu.Unlock()

	if !ok {
		t.Fatal("expected 'hot' to still be resident after S eviction")
	}
	if !e.inM {
		t.Error("expected 'hot' to be promoted to M queue (freq > 0 at eviction time)")
	}
}

// ── Ghost set: recently evicted S key bypasses S on re-insert ───────────────

func TestS3FIFOGhostBypassesS(t *testing.T) {
	t.Parallel()
	// capacity=2: eviction fires when total > 2.
	c := newTestS3FIFO(2)
	defer c.Close() //nolint:errcheck

	// Insert "victim" (freq=0) and fill to capacity.
	c.Set("victim", "tok-victim")
	c.Set("displacer", "tok-displacer") // total=2, no eviction yet

	// Third insert pushes total to 3 > 2. evictFromS pops "victim" (freq=0):
	// victim evicted to ghost, "trigger" inserted into S.
	c.Set("trigger", "tok-trigger")

	c.mu.Lock()
	_, victimResident := c.entries["victim"]
	inGhost := c.ghostContains("victim")
	c.mu.Unlock()

	if victimResident {
		t.Error("expected 'victim' to be evicted from memory")
	}
	if !inGhost {
		t.Error("expected 'victim' to be in ghost after S eviction")
	}

	// Re-insert "victim". Ghost hit → should bypass S and go directly to M.
	c.Set("victim", "tok-victim-new")

	c.mu.Lock()
	e, ok := c.entries["victim"]
	c.mu.Unlock()

	if !ok {
		t.Fatal("expected 'victim' to be resident after re-insert")
	}
	if !e.inM {
		t.Error("expected 'victim' to bypass S and go to M on ghost-hit re-insert")
	}
}

// ── Ghost capacity: oldest ghost entry is evicted when ghost is full ─────────

func TestS3FIFOGhostBounded(t *testing.T) {
	t.Parallel()
	// ghostCap = 2*sTarget = 2*(1) = 2, clamped to 4. Use capacity=20 → sTarget=2, ghostCap=4.
	c := newTestS3FIFO(20)
	defer c.Close() //nolint:errcheck

	ghostCap := c.ghostCap

	// Evict ghostCap+2 keys so the ghost overflows.
	for i := 0; i < ghostCap+2; i++ {
		key := fmt.Sprintf("evict-%d", i)
		c.Set(key, "tok")
		// Force eviction from S by inserting a second key (sTarget=2 here).
		c.Set(fmt.Sprintf("filler-%d", i), "tok-f")
	}

	c.mu.Lock()
	ghostCount := c.ghostCount
	c.mu.Unlock()

	if ghostCount > ghostCap {
		t.Errorf("ghost count %d exceeds ghostCap %d", ghostCount, ghostCap)
	}
}

// ── Cold read: bbolt hit re-warms S3-FIFO memory layer ──────────────────────

func TestS3FIFOColdReadRewarmsMemory(t *testing.T) {
	t.Parallel()
	backing := newMemoryCache()
	// Pre-populate the backing store (simulates data written by a previous process).
	backing.Set("cold-key", "tok-cold")

	c, ok := newS3FIFOCache(backing, 10).(*s3fifoCache)
	if !ok {
		t.Fatal("newS3FIFOCache did not return *s3fifoCache")
	}
	defer c.Close() //nolint:errcheck

	// Key is not in S3-FIFO memory yet.
	c.mu.Lock()
	_, inMem := c.entries["cold-key"]
	c.mu.Unlock()
	if inMem {
		t.Fatal("expected cold-key absent from memory before Get")
	}

	// Get triggers backing store lookup and re-warm.
	tok, ok := c.Get("cold-key")
	if !ok || tok != "tok-cold" {
		t.Fatalf("expected cold-key hit from backing, got ok=%v tok=%q", ok, tok)
	}

	// Verify the entry is now in memory.
	c.mu.Lock()
	_, inMem = c.entries["cold-key"]
	c.mu.Unlock()
	if !inMem {
		t.Error("expected cold-key to be re-warmed into memory after Get")
	}
}

// ── Concurrent safety ────────────────────────────────────────────────────────

func TestS3FIFOConcurrentAccess(t *testing.T) {
	t.Parallel()
	c := newTestS3FIFO(100)
	defer c.Close() //nolint:errcheck

	const goroutines = 20
	const ops = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				key := fmt.Sprintf("key-%d-%d", g, i%50)
				tok := fmt.Sprintf("tok-%d-%d", g, i)
				c.Set(key, tok)
				c.Get(key)
				if i%10 == 0 {
					c.Delete(key)
				}
			}
		}(g)
	}
	wg.Wait()

	// Verify structural invariants after concurrent storm.
	c.mu.Lock()
	defer c.mu.Unlock()

	total := c.sQueue.Len() + c.mQueue.Len()
	if total > c.capacity {
		t.Errorf("post-concurrency: %d entries exceed capacity %d", total, c.capacity)
	}
	if len(c.entries) != total {
		t.Errorf("entries map (%d) out of sync with queue lengths (%d)", len(c.entries), total)
	}
	if c.ghostCount > c.ghostCap {
		t.Errorf("ghostCount %d exceeds ghostCap %d", c.ghostCount, c.ghostCap)
	}
}

// ── Frequency saturation ─────────────────────────────────────────────────────

func TestS3FIFOFrequencySaturation(t *testing.T) {
	t.Parallel()
	c := newTestS3FIFO(10)
	defer c.Close() //nolint:errcheck

	c.Set("k", "v")
	// Access many times; freq must saturate at 3.
	for i := 0; i < 100; i++ {
		c.Get("k")
	}

	c.mu.Lock()
	e := c.entries["k"]
	c.mu.Unlock()

	if e.freq != 3 {
		t.Errorf("expected freq=3 (saturated), got %d", e.freq)
	}
}

// ── Interface compliance via bbolt backing ───────────────────────────────────

func TestS3FIFOWithBboltBacking(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bbolt, err := newBboltCache(dir + "/test.db")
	if err != nil {
		t.Fatalf("newBboltCache: %v", err)
	}

	c := newS3FIFOCache(bbolt, 100)
	defer c.Close() //nolint:errcheck

	c.Set("persist@example.com", "[PII_feedbeef]")

	tok, ok := c.Get("persist@example.com")
	if !ok || tok != "[PII_feedbeef]" {
		t.Fatalf("expected hit, got ok=%v tok=%q", ok, tok)
	}

	c.Delete("persist@example.com")
	if _, ok := c.Get("persist@example.com"); ok {
		t.Error("expected miss after Delete")
	}
}

// TestS3FIFOGhostDedup verifies that ghostAdd deduplicates entries —
// adding the same key twice does not increase the ghost count.
func TestS3FIFOGhostDedup(t *testing.T) {
	t.Parallel()
	c := newTestS3FIFO(2) // capacity 2 → sTarget 1, ghostCap 4
	defer c.Close()        //nolint:errcheck

	// Fill and evict to populate the ghost set.
	c.Set("a", "t1")
	c.Set("b", "t2")
	c.Set("c", "t3") // evicts "a" from S → goes to ghost

	c.mu.Lock()
	countBefore := c.ghostCount
	// Manually call ghostAdd with the same key again.
	c.ghostAdd("a")
	countAfter := c.ghostCount
	c.mu.Unlock()

	if countAfter != countBefore {
		t.Errorf("ghost dedup failed: count before=%d after=%d", countBefore, countAfter)
	}
}

// TestS3FIFOEvictFromSEmptyQueue exercises the nil-front guard in evictFromS.
func TestS3FIFOEvictFromSEmptyQueue(t *testing.T) {
	t.Parallel()
	c := newTestS3FIFO(10)
	defer c.Close() //nolint:errcheck

	// Calling evictFromS on an empty S queue should be a no-op.
	c.mu.Lock()
	c.evictFromS()
	c.mu.Unlock()
}

// TestS3FIFOEvictFromMEmptyQueue exercises the nil-front guard in evictFromM.
func TestS3FIFOEvictFromMEmptyQueue(t *testing.T) {
	t.Parallel()
	c := newTestS3FIFO(10)
	defer c.Close() //nolint:errcheck

	// Calling evictFromM on an empty M queue should be a no-op.
	c.mu.Lock()
	c.evictFromM()
	c.mu.Unlock()
}

// TestS3FIFOEvictFromSCorruptedElement exercises the type-assertion guard
// in evictFromS when the queue front contains a non-string value.
func TestS3FIFOEvictFromSCorruptedElement(t *testing.T) {
	t.Parallel()
	c := newTestS3FIFO(10)
	defer c.Close() //nolint:errcheck

	// Inject a corrupted (non-string) element into sQueue.
	c.mu.Lock()
	c.sQueue.PushFront(12345) // int, not string
	c.evictFromS()            // should discard without panic
	c.mu.Unlock()
}

// TestS3FIFOEvictFromMCorruptedElement exercises the type-assertion guard
// in evictFromM when the queue front contains a non-string value.
func TestS3FIFOEvictFromMCorruptedElement(t *testing.T) {
	t.Parallel()
	c := newTestS3FIFO(10)
	defer c.Close() //nolint:errcheck

	// Inject a corrupted (non-string) element into mQueue.
	c.mu.Lock()
	c.mQueue.PushFront(12345) // int, not string
	c.evictFromM()            // should discard without panic
	c.mu.Unlock()
}

// TestS3FIFOEvictFromSStaleEntry exercises the stale element path in evictFromS
// where the queue has a key that's no longer in the entries map.
func TestS3FIFOEvictFromSStaleEntry(t *testing.T) {
	t.Parallel()
	c := newTestS3FIFO(10)
	defer c.Close() //nolint:errcheck

	c.Set("a", "t1")
	c.Set("b", "t2")

	// Manually remove "a" from entries but leave it in sQueue — creating a stale entry.
	c.mu.Lock()
	delete(c.entries, "a")
	c.mu.Unlock()

	// Now fill the cache to trigger eviction, which will encounter the stale "a".
	for i := range 15 {
		c.Set(fmt.Sprintf("fill-%d", i), fmt.Sprintf("v%d", i))
	}
}

// TestS3FIFONewWithZeroCapacity covers the minimum capacity guard in newS3FIFOCache.
func TestS3FIFONewWithZeroCapacity(t *testing.T) {
	t.Parallel()
	// Capacity 1 is the minimum — triggers sTarget=1, ghostCap=4 (min).
	c := newTestS3FIFO(1)
	defer c.Close() //nolint:errcheck

	c.Set("a", "t1")
	c.Set("b", "t2") // triggers eviction
	_, ok := c.Get("b")
	if !ok {
		t.Error("expected hit for most recent entry")
	}
}

// TestS3FIFOEvictFromMPath triggers eviction from M by promoting entries
// from S to M until M overflows.
func TestS3FIFOEvictFromMPath(t *testing.T) {
	t.Parallel()
	c := newTestS3FIFO(2) // capacity 2, sTarget 1, mTarget 1
	defer c.Close()        //nolint:errcheck

	// Set a key and access it to bump freq, then overflow S to trigger promotion to M.
	c.Set("a", "t1")
	c.Get("a") // bump freq

	c.Set("b", "t2") // fills S, "a" has freq>0 so gets promoted to M
	c.Get("b")        // bump freq for b

	c.Set("c", "t3") // "b" promoted to M (freq>0), M now has 2 but target is 1 → evictFromM

	// Verify at least one key was evicted from M.
	c.mu.Lock()
	mLen := c.mQueue.Len()
	c.mu.Unlock()

	if mLen > 1 {
		t.Errorf("expected mQueue len ≤1 after eviction, got %d", mLen)
	}
}
