package packs

import (
	"regexp"
	"strings"
)

// validateSSN rejects SSNs with invalid area codes per SSA rules.
// Area codes 000, 666, and 900-999 have never been issued.
// Group number 00 and serial 0000 are also invalid.
// Source: https://www.ssa.gov/employer/stateweb.htm
func validateSSN(s string) bool {
	digits := make([]byte, 0, 9)
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, byte(c-'0'))
		}
	}
	if len(digits) != 9 {
		return false
	}
	area := int(digits[0])*100 + int(digits[1])*10 + int(digits[2])
	group := int(digits[3])*10 + int(digits[4])
	serial := int(digits[5])*1000 + int(digits[6])*100 + int(digits[7])*10 + int(digits[8])
	if area == 0 || area == 666 || area >= 900 {
		return false
	}
	if group == 0 || serial == 0 {
		return false
	}
	return true
}

// validateUSPhone rejects matches that look like version strings or timestamps.
// Requires at least one non-digit separator (hyphen, dot, space, or parenthesis).
// Source: NANPA formatting conventions.
func validateUSPhone(s string) bool {
	// Reject if preceded by 'v' or 'V' (version string like v1.234.567.8901)
	// The regex match itself won't include the 'v', but all-digit matches
	// with dot separators are suspicious. Require at least one separator
	// that is not a dot to reduce version-string false positives.
	hasParen := strings.ContainsAny(s, "()")
	hasHyphen := strings.ContainsAny(s, "-")
	hasSpace := strings.ContainsAny(s, " ")
	hasPlus := strings.HasPrefix(s, "+")
	hasDot := strings.Contains(s, ".")

	// Pure digits with no separator — too ambiguous.
	if !hasParen && !hasHyphen && !hasSpace && !hasPlus && !hasDot {
		return false
	}
	// Dot-only separators match version strings — reject.
	if hasDot && !hasParen && !hasHyphen && !hasSpace && !hasPlus {
		return false
	}
	return true
}

func init() {
	Register(
		// US Social Security Number (SSN): XXX-XX-XXXX or 9 consecutive digits.
		// Source: https://www.ssa.gov/employer/stateweb.htm
		// Pattern reference: Presidio SSN detector.
		// False-positive mitigation: validator rejects invalid area codes (000, 666, 900-999).
		Entry{
			Name:       "ssn",
			Pack:       "US",
			Re:         regexp.MustCompile(`\b\d{3}-?\d{2}-?\d{4}\b`),
			PIIType:    "SSN",
			Confidence: 0.85,
			Validate:   validateSSN,
		},
		// US phone number: optional +1 country code, area code, 7 digits.
		// Source: NANPA (North American Numbering Plan).
		// Pattern reference: mnestorov/regex-patterns common patterns.
		// False-positive mitigation: validator requires non-dot separator to reject
		// version strings; low confidence triggers AI fallback.
		Entry{
			Name:       "phone_us",
			Pack:       "US",
			Re:         regexp.MustCompile(`(?:\+?1[\-\s]?)?\(?[0-9]{3}\)?[\-.\s][0-9]{3}[\-.\s][0-9]{4}`),
			PIIType:    "PHONE",
			Confidence: 0.65,
			Validate:   validateUSPhone,
		},
		// US street address: number + street name + street type suffix.
		// Source: USPS Publication 28 address format guidelines.
		// False-positive mitigation: requires street-type keyword suffix.
		Entry{
			Name:       "address_us",
			Pack:       "US",
			Re:         regexp.MustCompile(`(?i)\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct)\b`),
			PIIType:    "ADDRESS",
			Confidence: 0.75,
		},
		// IPv6 address: all RFC 5952 compressed and uncompressed forms.
		// Source: RFC 5952 (IPv6 text representation).
		// False-positive mitigation: colon-hex syntax is structurally unambiguous.
		Entry{
			Name: "ipv6",
			Pack: "US",
			Re: regexp.MustCompile(`(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}` +
				`|(?:[0-9a-fA-F]{1,4}:){1,7}:` +
				`|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}` +
				`|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}` +
				`|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}` +
				`|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}` +
				`|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}` +
				`|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}` +
				`|:(?::[0-9a-fA-F]{1,4}){1,7}` +
				`|::`),
			PIIType:    "IPADDRESS",
			Confidence: 0.85,
		},
		// IPv4 address: dotted quad notation.
		// Source: RFC 791 (Internet Protocol).
		// False-positive mitigation: matches version numbers — moderate confidence.
		Entry{
			Name:       "ipv4",
			Pack:       "US",
			Re:         regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
			PIIType:    "IPADDRESS",
			Confidence: 0.70,
		},
		// US ZIP code: 5 digits, optional +4 extension.
		// Source: USPS ZIP code format.
		// False-positive mitigation: very broad — low confidence.
		Entry{
			Name:       "zip_us",
			Pack:       "US",
			Re:         regexp.MustCompile(`\b\d{5}(?:-\d{4})?\b`),
			PIIType:    "ADDRESS",
			Confidence: 0.40,
		},
	)
}
