package packs

import "regexp"

// luhnValid implements the Luhn algorithm for credit card number validation.
// Source: ISO/IEC 7812-1, https://en.wikipedia.org/wiki/Luhn_algorithm
func luhnValid(s string) bool {
	var sum int
	var alt bool
	// Strip spaces and hyphens, iterate right to left.
	digits := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			digits = append(digits, s[i]-'0')
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i])
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func init() {
	Register(
		// Email: RFC 5322 simplified — unambiguous structural markers (@, domain, TLD).
		// Source: mnestorov/regex-patterns common patterns, adapted for Go.
		// False-positive mitigation: structural @ symbol + domain TLD requirement.
		Entry{
			Name:       "email",
			Pack:       "GLOBAL",
			Re:         regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
			PIIType:    "EMAIL",
			Confidence: 0.95,
		},
		// API key: keyword prefix + long alphanumeric token.
		// Source: silv3rshi3ld/gdpr-pii-scanner API key detection patterns.
		// False-positive mitigation: requires keyword prefix (api_key, token, secret, bearer).
		Entry{
			Name:       "api_key",
			Pack:       "GLOBAL",
			Re:         regexp.MustCompile(`(?i)(?:api[_\-]?key|token|secret|bearer)[\s"':=]+([a-zA-Z0-9_\-.]{20,})`),
			PIIType:    "APIKEY",
			Confidence: 0.90,
		},
		// Credit card: 13-19 digit block pattern with Luhn checksum validation.
		// Source: ISO/IEC 7812-1, mnestorov/regex-patterns credit card patterns.
		// False-positive mitigation: Luhn checksum validator rejects random digit sequences.
		Entry{
			Name:       "credit_card",
			Pack:       "GLOBAL",
			Re:         regexp.MustCompile(`\b(?:\d{4}[\-\s]?){3}\d{4}\b`),
			PIIType:    "CREDITCARD",
			Confidence: 0.85,
			Validate:   luhnValid,
		},
	)
}
