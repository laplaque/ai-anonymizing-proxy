package packs

import (
	"regexp"
	"strings"
)

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

// validateEmailLocalPart rejects email addresses with invalid local parts
// per RFC 5321: no leading/trailing dots, no consecutive dots.
// Source: RFC 5321 section 4.1.2
func validateEmailLocalPart(s string) bool {
	atIdx := strings.IndexByte(s, '@')
	if atIdx <= 0 {
		return false
	}
	local := s[:atIdx]
	if local[0] == '.' || local[len(local)-1] == '.' {
		return false
	}
	return !strings.Contains(local, "..")
}

func init() {
	Register(
		// Email: RFC 5322 simplified — unambiguous structural markers (@, domain, TLD).
		// Source: mnestorov/regex-patterns common patterns, adapted for Go.
		// False-positive mitigation: structural @ symbol + domain TLD requirement.
		// Validator rejects invalid local parts (leading/trailing/consecutive dots) per RFC 5321.
		Entry{
			Name:       "email",
			Pack:       "GLOBAL",
			Re:         regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
			PIIType:    "EMAIL",
			Confidence: 0.95,
			Validate:   validateEmailLocalPart,
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
		// Credit card: 13-19 digit pattern with optional group separators, Luhn validated.
		// Accepts Visa (16), Mastercard (16), Amex (15), Diners (14), Discover (16-19).
		// Source: ISO/IEC 7812-1, mnestorov/regex-patterns credit card patterns.
		// False-positive mitigation: Luhn checksum validator rejects random digit sequences.
		Entry{
			Name:       "credit_card",
			Pack:       "GLOBAL",
			Re:         regexp.MustCompile(`\b\d(?:\d[\-\s]?){12,18}\b`),
			PIIType:    "CREDITCARD",
			Confidence: 0.85,
			Validate:   luhnValid,
		},
	)
}
