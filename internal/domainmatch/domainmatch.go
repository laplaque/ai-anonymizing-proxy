// Package domainmatch provides segment-based glob matching for DNS domain
// names with two flavors of "*" wildcards:
//
//  1. Bare "*" segment — matches exactly one DNS label of any value.
//     Example: *.openai.azure.com matches myresource.openai.azure.com.
//
//  2. Label-substring "*" — a "*" inside a segment (e.g. *-aiplatform,
//     foo-*, foo*bar) matches any non-empty substring within that single
//     label. Segment count must still match exactly. Only one "*" per
//     non-bare segment is accepted; segments with two or more "*" are
//     treated as literal strings (no second-class wildcard semantics).
//
// Example patterns:
//
//	*.openai.azure.com               (prefix wildcard)
//	*-aiplatform.googleapis.com      (label-substring prefix — Vertex AI)
//	bedrock-runtime.*.amazonaws.com  (infix wildcard)
//
// Both domain and pattern are normalized to lowercase, and a single
// trailing "." (RFC 1035 root-zone canonical form) is stripped before
// comparison. DNS is case-insensitive (RFC 1035 §2.3.3), and TLS SNI /
// HTTP Host headers can legitimately arrive with mixed case or a trailing
// dot — both must compare equal here.
package domainmatch

import "strings"

// DomainGlob is a pre-split domain pattern for segment-based matching.
type DomainGlob struct {
	raw      string   // original pattern, e.g. "bedrock-runtime.*.amazonaws.com"
	segments []string // lowercase, split by ".", trailing "." stripped
}

// Raw returns the original pattern string.
func (g DomainGlob) Raw() string { return g.raw }

// Match returns true if domain matches the glob pattern.
//
// Bare "*" segments match any one DNS label; segments containing exactly
// one embedded "*" match any non-empty substring of that label
// (HasPrefix + HasSuffix on the literal pieces). Segment count must match
// exactly. Comparison is case-insensitive; a single trailing "." on the
// domain is stripped.
func (g DomainGlob) Match(domain string) bool {
	parts := strings.Split(normalizeHost(domain), ".")
	if len(parts) != len(g.segments) {
		return false
	}
	for i, seg := range g.segments {
		if seg == "*" {
			if parts[i] == "" {
				return false
			}
			continue
		}
		if !matchSegment(seg, parts[i]) {
			return false
		}
	}
	return true
}

// matchSegment compares one pattern segment against one label.
// A segment with exactly one embedded "*" is a label-substring wildcard:
// "*-aiplatform" matches "us-east4-aiplatform"; "foo*" matches "foo123".
// All other segments compare as literals.
func matchSegment(pattern, label string) bool {
	idx := strings.IndexByte(pattern, '*')
	if idx < 0 {
		return pattern == label
	}
	// Reject patterns with more than one "*" — they're under-specified
	// and we'd rather treat them as literal so a typo doesn't silently
	// over-match. (validDomain already prevents these from being added
	// via the management API, but Parse may receive arbitrary input.)
	if strings.IndexByte(pattern[idx+1:], '*') >= 0 {
		return pattern == label
	}
	prefix, suffix := pattern[:idx], pattern[idx+1:]
	if len(prefix)+len(suffix) >= len(label) {
		return false // need at least one char to fill the wildcard
	}
	return strings.HasPrefix(label, prefix) && strings.HasSuffix(label, suffix)
}

// IsGlob reports whether pattern contains a "*" wildcard (either as a
// whole segment or embedded within one). It is a membership test, not a
// validation contract — operationally nonsense patterns like "*" or "*.*"
// return true. Use validDomain at the management-API boundary to reject
// dangerous patterns.
func IsGlob(pattern string) bool {
	return strings.IndexByte(pattern, '*') >= 0
}

// Parse creates a DomainGlob from a pattern string. The pattern is
// lowercased and a trailing "." is stripped so Match comparisons are
// case- and FQDN-form-insensitive.
func Parse(pattern string) DomainGlob {
	return DomainGlob{
		raw:      pattern,
		segments: strings.Split(normalizeHost(pattern), "."),
	}
}

// NormalizeHost lowercases h and strips a single trailing "." if present.
// Used on both pattern and domain so callers can pass any DNS-form input.
// Exported so the domain registry can canonicalize keys and inbound
// lookups consistently with the matcher.
func NormalizeHost(h string) string {
	return normalizeHost(h)
}

// normalizeHost lowercases h and strips a single trailing "." if present.
// Used on both pattern and domain so callers can pass any DNS-form input.
func normalizeHost(h string) string {
	h = strings.ToLower(h)
	if len(h) > 1 && h[len(h)-1] == '.' {
		h = h[:len(h)-1]
	}
	return h
}
