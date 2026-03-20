// Package packs provides self-registering PII pattern packs.
// Each pack file calls Register() from its init() to add patterns to a shared registry.
// The anonymizer's pack loader calls All() to retrieve the full set.
package packs

import "regexp"

// Entry is a pattern registered by a pack.
type Entry struct {
	Name       string
	Pack       string
	Re         *regexp.Regexp
	PIIType    string
	Confidence float64
	Literal    bool
	Validate   func(string) bool // nil = no validation required
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

// Reset clears the registry. Used only in tests to isolate pack registration.
func Reset() {
	registry = nil
}
