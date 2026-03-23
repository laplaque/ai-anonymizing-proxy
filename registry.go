// Package packs provides self-registering PII detection pattern packs.
//
// Each pack file defines an init() function that calls Register() to add
// its patterns to the global registry. The anonymizer imports this package
// with a blank import to trigger all init() calls, then calls All() to
// retrieve the full registry.
package packs

import (
	"regexp"
	"sync"
)

// Entry is a pattern registered by a pack.
type Entry struct {
	Name         string
	Pack         string
	Re           *regexp.Regexp
	PIIType      string
	Confidence   float64
	Literal      bool
	Validate     func(string) bool // nil = no validation required
	ReplaceGroup int               // 0 = replace full match; >0 = replace only that capture group
}

var (
	mu       sync.Mutex
	registry []Entry
)

// Register adds entries to the global pack registry.
// Called from each pack's init() function. Thread-safe.
func Register(entries ...Entry) {
	mu.Lock()
	registry = append(registry, entries...)
	mu.Unlock()
}

// All returns the full registry. Called by the pack loader in anonymizer.go. Thread-safe.
func All() []Entry {
	mu.Lock()
	defer mu.Unlock()
	return registry
}

// Reset clears the registry. Used only in tests. Thread-safe.
func Reset() {
	mu.Lock()
	registry = nil
	mu.Unlock()
}
