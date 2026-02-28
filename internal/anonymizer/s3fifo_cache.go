// Package anonymizer — s3fifo_cache.go
//
// s3fifoCache wraps a PersistentCache (bbolt) with an in-memory S3-FIFO
// eviction layer, bounding both the hot in-memory footprint and the on-disk
// store size.
//
// # Algorithm
//
// S3-FIFO ("Simple, Scalable, FIFO-based cache eviction", Yang et al., 2023)
// uses two FIFO queues and a bounded ghost set:
//
//   - S (small, ~10% of capacity): probationary queue.
//     All new keys are inserted here.
//   - M (main, ~90% of capacity): protected queue.
//     Keys promoted from S after at least one access (freq > 0) land here.
//   - G (ghost): a circular-buffer set of keys recently evicted from S,
//     bounded to 2× sTarget. A key found in G on insert bypasses S and goes
//     directly to M, providing scan resistance comparable to ARC without
//     LRU's per-access lock serialization.
//
// Per-object state: saturating frequency counter (uint8, max 3).
// Incremented on every Get hit; reset to 0 on M promotion.
//
// # Eviction
//
//	S → evict oldest head:
//	  freq > 0 → promote to M tail (reset freq); if M now over target, evict M head.
//	  freq == 0 → remove from memory, add key to G, delete from backing store.
//
//	M → evict oldest head:
//	  Remove from memory, delete from backing store.
//	  M evictions do NOT add to G.
//
// Items evicted from either queue are deleted from the bbolt backing store so
// on-disk size is bounded. On restart the in-memory layer is cold; reads fall
// back to bbolt and re-warm the hot set organically.
//
// # Concurrency
//
// All public methods acquire a single mutex for in-memory state. bbolt I/O
// (which carries its own locking) is performed without holding c.mu, via
// goroutines for deletions and direct calls for reads/writes on the hot path.
//
// # Sizing
//
//	sTarget   = max(1, capacity/10)
//	mTarget   = capacity − sTarget
//	ghostCap  = 2 × sTarget   (min 4)
package anonymizer

import (
	"container/list"
	"log"
	"sync"
)

// s3fifoEntry holds the in-memory state for a single cached item.
type s3fifoEntry struct {
	value string
	freq  uint8         // saturating counter in [0, 3]
	elem  *list.Element // back-pointer into sQueue or mQueue
	inM   bool          // true → lives in mQueue, false → sQueue
}

// s3fifoCache wraps a PersistentCache with an S3-FIFO in-memory eviction layer.
type s3fifoCache struct {
	mu sync.Mutex

	capacity int // S + M max items
	sTarget  int // desired S queue size (~10%)
	ghostCap int // maximum ghost set cardinality

	// Hot in-memory index.
	entries map[string]*s3fifoEntry

	// FIFO queues; each element Value is a string key.
	sQueue *list.List
	mQueue *list.List

	// Ghost: bounded circular buffer.
	ghostBuf   []string            // fixed-size ring, length == ghostCap
	ghostSet   map[string]struct{} // O(1) membership test
	ghostHead  int                 // oldest entry index in ghostBuf
	ghostCount int                 // current number of ghost entries

	backing PersistentCache
}

// newS3FIFOCache returns a PersistentCache that applies S3-FIFO eviction in
// front of the given backing store. capacity is the maximum number of items
// kept in memory (and on disk); values < 2 are clamped to 2.
func newS3FIFOCache(backing PersistentCache, capacity int) PersistentCache {
	if capacity < 2 {
		capacity = 2
	}
	sTarget := capacity / 10
	if sTarget < 1 {
		sTarget = 1
	}
	ghostCap := 2 * sTarget
	if ghostCap < 4 {
		ghostCap = 4
	}
	log.Printf("[ANONYMIZER] S3-FIFO cache capacity=%d sTarget=%d ghostCap=%d", capacity, sTarget, ghostCap)
	return &s3fifoCache{
		capacity: capacity,
		sTarget:  sTarget,
		ghostCap: ghostCap,
		entries:  make(map[string]*s3fifoEntry, capacity),
		sQueue:   list.New(),
		mQueue:   list.New(),
		ghostBuf: make([]string, ghostCap),
		ghostSet: make(map[string]struct{}, ghostCap),
		backing:  backing,
	}
}

// ── PersistentCache ─────────────────────────────────────────────────────────

// Get returns the token for original.
// Memory hit: freq counter incremented.
// Memory miss: backing store consulted; hit there is re-warmed into memory.
func (c *s3fifoCache) Get(original string) (string, bool) {
	c.mu.Lock()
	if e, ok := c.entries[original]; ok {
		if e.freq < 3 {
			e.freq++
		}
		v := e.value
		c.mu.Unlock()
		return v, true
	}
	c.mu.Unlock()

	// Cold path: check bbolt without holding the mutex (bbolt is concurrency-safe).
	token, ok := c.backing.Get(original)
	if !ok {
		return "", false
	}
	// Re-warm entry. insertLocked handles its own locking.
	c.insertLocked(original, token)
	return token, true
}

// Set stores original → token in memory and in the backing store.
// If the key is already in memory, only the value is updated (queue position unchanged).
func (c *s3fifoCache) Set(original, token string) {
	c.insertLocked(original, token)
	c.backing.Set(original, token)
}

// Delete removes original from memory and from the backing store.
func (c *s3fifoCache) Delete(original string) {
	c.mu.Lock()
	c.removeFromMemory(original)
	c.mu.Unlock()
	c.backing.Delete(original)
}

// Close closes the backing store. In-memory state is discarded.
func (c *s3fifoCache) Close() error {
	return c.backing.Close()
}

// ── Internal ────────────────────────────────────────────────────────────────

// insertLocked performs the in-memory S3-FIFO insert/update under c.mu.
func (c *s3fifoCache) insertLocked(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update existing entry in-place; do not change its queue position.
	if e, ok := c.entries[key]; ok {
		e.value = value
		return
	}

	// New key: insert into M if key is in ghost, S otherwise.
	inM := c.ghostContains(key)
	var elem *list.Element
	if inM {
		elem = c.mQueue.PushBack(key)
	} else {
		elem = c.sQueue.PushBack(key)
	}
	c.entries[key] = &s3fifoEntry{value: value, freq: 0, elem: elem, inM: inM}

	// Evict until within capacity.
	for c.sQueue.Len()+c.mQueue.Len() > c.capacity {
		c.evictOne()
	}
}

// evictOne removes one entry, following the S3-FIFO policy.
// Must be called with c.mu held.
func (c *s3fifoCache) evictOne() {
	if c.sQueue.Len() > 0 {
		c.evictFromS()
		return
	}
	c.evictFromM()
}

// evictFromS pops the oldest entry from S and either promotes it to M or
// evicts it fully. Must be called with c.mu held.
func (c *s3fifoCache) evictFromS() {
	front := c.sQueue.Front()
	if front == nil {
		return
	}
	key, ok := front.Value.(string)
	if !ok {
		c.sQueue.Remove(front) // corrupted element; discard
		return
	}
	c.sQueue.Remove(front)

	e, ok := c.entries[key]
	if !ok {
		return // stale element; skip
	}

	if e.freq > 0 {
		// Promote to M: reset freq, update membership.
		e.freq = 0
		e.inM = true
		e.elem = c.mQueue.PushBack(key)
		// If M now exceeds its target, immediately evict its head.
		mTarget := c.capacity - c.sTarget
		if c.mQueue.Len() > mTarget {
			c.evictFromM()
		}
	} else {
		// Full eviction: remove from memory, record in ghost, delete from disk.
		delete(c.entries, key)
		c.ghostAdd(key)
		go c.backing.Delete(key) // async: avoid blocking the hot path
	}
}

// evictFromM pops the oldest entry from M and evicts it fully.
// Must be called with c.mu held.
func (c *s3fifoCache) evictFromM() {
	front := c.mQueue.Front()
	if front == nil {
		return
	}
	key, ok := front.Value.(string)
	if !ok {
		c.mQueue.Remove(front) // corrupted element; discard
		return
	}
	c.mQueue.Remove(front)
	delete(c.entries, key)
	go c.backing.Delete(key) // async: avoid blocking the hot path
}

// removeFromMemory removes key from whichever queue it lives in and from
// the entries map. A no-op if the key is not resident.
// Must be called with c.mu held.
func (c *s3fifoCache) removeFromMemory(key string) {
	e, ok := c.entries[key]
	if !ok {
		return
	}
	if e.inM {
		c.mQueue.Remove(e.elem)
	} else {
		c.sQueue.Remove(e.elem)
	}
	delete(c.entries, key)
}

// ghostContains reports whether key is in the ghost set.
// Must be called with c.mu held.
func (c *s3fifoCache) ghostContains(key string) bool {
	_, ok := c.ghostSet[key]
	return ok
}

// ghostAdd inserts key into the bounded circular ghost buffer.
// If the buffer is full, the oldest entry is evicted to make room.
// Must be called with c.mu held.
func (c *s3fifoCache) ghostAdd(key string) {
	if _, exists := c.ghostSet[key]; exists {
		return // already present; avoid duplicate
	}

	if c.ghostCount == c.ghostCap {
		// Evict the oldest ghost entry.
		oldest := c.ghostBuf[c.ghostHead]
		delete(c.ghostSet, oldest)
		c.ghostHead = (c.ghostHead + 1) % c.ghostCap
		c.ghostCount--
	}

	// Write at (ghostHead + ghostCount) % ghostCap — the next free slot.
	writeIdx := (c.ghostHead + c.ghostCount) % c.ghostCap
	c.ghostBuf[writeIdx] = key
	c.ghostSet[key] = struct{}{}
	c.ghostCount++
}
