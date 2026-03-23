// Package packs provides self-registering PII detection pattern packs.
//
// Each pack file defines an init() function that calls Register() to add
// its patterns to the global registry. The anonymizer imports this package
// with a blank import to trigger all init() calls, then calls All() to
// retrieve the full registry.
package packs

import "regexp"

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

var registry []Entry

// Register adds entries to the global pack registry.
// Called from each pack's init() function.
func Register(entries ...Entry) {
	registry = append(registry, entries...)
}

// All returns the full registry. Called by the pack loader in anonymizer.go.
func All() []Entry {
	return registry
}

// Reset clears the registry. Used only in tests.
func Reset() {
	registry = nil
}
