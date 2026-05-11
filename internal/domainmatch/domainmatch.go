// Package domainmatch provides segment-based glob matching for DNS domain
// names. A "*" segment in a pattern matches exactly one DNS label.
//
// Example patterns:
//
//	*.openai.azure.com               (prefix wildcard)
//	*.aiplatform.googleapis.com      (prefix wildcard)
//	bedrock-runtime.*.amazonaws.com  (infix wildcard)
//
// The matcher is intentionally simple: segment count must match exactly,
// "*" never matches multiple labels or zero labels.
package domainmatch

import "strings"

// DomainGlob is a pre-split domain pattern for segment-based matching.
// "*" in any position matches exactly one DNS label.
type DomainGlob struct {
	raw      string   // original pattern, e.g. "bedrock-runtime.*.amazonaws.com"
	segments []string // split by ".", e.g. ["bedrock-runtime", "*", "amazonaws", "com"]
}

// Raw returns the original pattern string.
func (g DomainGlob) Raw() string { return g.raw }

// Match returns true if domain matches the glob pattern.
// Each "*" segment matches exactly one DNS label. Segment count must match exactly.
func (g DomainGlob) Match(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) != len(g.segments) {
		return false
	}
	for i, seg := range g.segments {
		if seg == "*" {
			continue
		}
		if seg != parts[i] {
			return false
		}
	}
	return true
}

// IsGlob returns true if the pattern contains at least one "*" segment.
func IsGlob(pattern string) bool {
	for _, seg := range strings.Split(pattern, ".") {
		if seg == "*" {
			return true
		}
	}
	return false
}

// Parse creates a DomainGlob from a pattern string.
func Parse(pattern string) DomainGlob {
	return DomainGlob{
		raw:      pattern,
		segments: strings.Split(pattern, "."),
	}
}
