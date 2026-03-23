package packs

// Source: email — RFC 5322 simplified; mnestorov/regex-patterns — https://github.com/mnestorov/regex-patterns#emails
// Source: API key — keyword-prefixed credential detection
// Source: credit card — mnestorov/regex-patterns — https://github.com/mnestorov/regex-patterns#credit-and-debit-card-patterns

import (
	"regexp"
	"unicode"
)

func init() {
	Register(
		Entry{
			Name:       "email",
			Pack:       "GLOBAL",
			Re:         regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
			PIIType:    "EMAIL",
			Confidence: 0.95,
		},
		Entry{
			Name: "api_key",
			Pack: "GLOBAL",
			// Capture group 1 = the credential value only.
			// ReplaceGroup=1 ensures only the value is redacted, preserving the keyword prefix.
			Re:           regexp.MustCompile(`(?i)((?:api[_\-]?key|token|secret|bearer)[\s"':=]+)([a-zA-Z0-9_\-.]{20,})`),
			PIIType:      "APIKEY",
			Confidence:   0.90,
			ReplaceGroup: 2,
		},
		Entry{
			Name:       "credit_card",
			Pack:       "GLOBAL",
			Re:         regexp.MustCompile(`\b(?:\d{4}[\-\s]?){3}\d{4}\b`),
			PIIType:    "CREDITCARD",
			Confidence: 0.85,
			Validate:   validateLuhn,
		},
	)
}

// validateLuhn checks a credit card number against the Luhn algorithm.
// Separators (spaces, hyphens) are stripped before validation.
func validateLuhn(s string) bool {
	var digits []int
	for _, r := range s {
		if unicode.IsDigit(r) {
			digits = append(digits, int(r-'0'))
		} else if r != '-' && r != ' ' {
			return false
		}
	}
	n := len(digits)
	if n < 13 || n > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := n - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}
