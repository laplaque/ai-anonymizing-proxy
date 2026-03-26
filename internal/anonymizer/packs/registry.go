// Package packs provides self-registering PII detection pattern packs.
// Each pack file calls Register() in its init() function to add patterns
// to the global registry. The anonymizer loads patterns from this registry
// filtered by the set of enabled packs in the configuration.
package packs

import (
	"regexp"
	"sync"
)

// Entry describes a single PII detection pattern within a named pack.
type Entry struct {
	Name       string            // human-readable pattern name (e.g. "email", "steuer_id")
	Pack       string            // pack name (e.g. "GLOBAL", "DE", "SECRETS")
	Re         *regexp.Regexp    // compiled regex; nil if Literal is true
	PIIType    string            // PII type label used in tokens (e.g. "EMAIL", "CREDITCARD")
	Confidence float64           // base confidence score (0.0–1.0)
	Literal    bool              // true = exact string match, not regex
	Validate   func(string) bool // optional checksum validator; nil = no validation
}

var (
	registryMu sync.RWMutex
	registry   []Entry
)

// Register adds one or more entries to the global pack registry.
// Called from init() in each pack file. Thread-safe.
func Register(entries ...Entry) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = append(registry, entries...)
}

// All returns a snapshot of all registered entries across all packs. Thread-safe.
func All() []Entry {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return append([]Entry(nil), registry...)
}

// PIITypes returns a deduplicated list of all PIIType strings across all
// registered entries. Used by metrics to auto-populate counters.
func PIITypes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	seen := make(map[string]bool)
	var types []string
	for _, e := range registry {
		if !seen[e.PIIType] {
			seen[e.PIIType] = true
			types = append(types, e.PIIType)
		}
	}
	return types
}
