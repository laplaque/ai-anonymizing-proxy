package packs

import "regexp"

// validateBSN validates a Dutch Burgerservicenummer (BSN / citizen service number)
// using the "elfproef" (11-test) modulo 11 algorithm.
// The BSN is 9 digits. Weighted sum: 9*d1 + 8*d2 + 7*d3 + 6*d4 + 5*d5 + 4*d6 + 3*d7 + 2*d8 - 1*d9
// must be divisible by 11, and the result must not be 0.
// Source: https://nl.wikipedia.org/wiki/Burgerservicenummer
// Reference: silv3rshi3ld/gdpr-pii-scanner BSN detector (11-proef validated).
func validateBSN(s string) bool {
	digits := make([]int, 0, 9)
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) != 9 {
		return false
	}
	// Weighted sum: positions 1-8 use weights 9..2, position 9 uses weight -1.
	sum := 9*digits[0] + 8*digits[1] + 7*digits[2] + 6*digits[3] +
		5*digits[4] + 4*digits[5] + 3*digits[6] + 2*digits[7] - 1*digits[8]
	return sum != 0 && sum%11 == 0
}

func init() {
	Register(
		// Dutch Burgerservicenummer (BSN / Citizen Service Number):
		// 9 digits, validated with the "elfproef" (modulo 11) algorithm.
		// Source: https://nl.wikipedia.org/wiki/Burgerservicenummer
		// Reference: silv3rshi3ld/gdpr-pii-scanner BSN detector.
		// False-positive mitigation: elfproef rejects ~91% of random 9-digit sequences.
		Entry{
			Name:       "bsn",
			Pack:       "NL",
			Re:         regexp.MustCompile(`\b\d{9}\b`),
			PIIType:    "BSN",
			Confidence: 0.70,
			Validate:   validateBSN,
		},
		// Dutch Kamer van Koophandel (KvK) number:
		// 8 digits identifying a business registration in the Netherlands.
		// Source: https://www.kvk.nl/english/
		// Pattern reference: mnestorov/regex-patterns Netherlands section (no specific KvK pattern;
		// format documented by KvK: exactly 8 digits).
		// False-positive mitigation: low confidence routes ambiguous matches to AI verification.
		Entry{
			Name:       "kvk",
			Pack:       "NL",
			Re:         regexp.MustCompile(`\b\d{8}\b`),
			PIIType:    "KVK",
			Confidence: 0.45,
		},
	)
}
