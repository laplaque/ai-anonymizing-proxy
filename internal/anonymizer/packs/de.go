package packs

import "regexp"

// validateSteuerID validates a German tax identification number (Steuerliche
// Identifikationsnummer) using the ISO 7064 MOD 11,10 iterative check digit algorithm.
// The Steuer-ID is 11 digits; the last digit is the check digit.
// Source: https://de.wikipedia.org/wiki/Steuerliche_Identifikationsnummer
// Reference: ISO 7064, https://www.zentraler-kreditausschuss.de/
func validateSteuerID(s string) bool {
	// Extract digits only.
	digits := make([]int, 0, 11)
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) != 11 {
		return false
	}
	// First digit must not be 0.
	if digits[0] == 0 {
		return false
	}
	// ISO 7064 MOD 11,10 iterative algorithm.
	product := 10
	for i := 0; i < 10; i++ {
		sum := (digits[i] + product) % 10
		if sum == 0 {
			sum = 10
		}
		product = (sum * 2) % 11
	}
	check := 11 - product
	if check == 10 {
		check = 0
	}
	return check == digits[10]
}

func init() {
	Register(
		// German Steuerliche Identifikationsnummer (Steuer-ID / Tax ID):
		// 11 digits, first digit non-zero, validated with ISO 7064 MOD 11,10.
		// Source: https://de.wikipedia.org/wiki/Steuerliche_Identifikationsnummer
		// Pattern reference: mnestorov/regex-patterns Germany section.
		// False-positive mitigation: ISO 7064 MOD 11,10 check digit validation.
		Entry{
			Name:       "steuer_id",
			Pack:       "DE",
			Re:         regexp.MustCompile(`\b[1-9]\d{2}[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{2}\b`),
			PIIType:    "STEUERID",
			Confidence: 0.70,
			Validate:   validateSteuerID,
		},
		// German Sozialversicherungsnummer (SVNR / Social Insurance Number):
		// Format: 2 digits (area) + DDMMYY (birthday) + 1 letter + 3 digits + 1 digit (check).
		// Total: 12 characters (2d + 6d + 1a + 2d + 1d).
		// Source: https://de.wikipedia.org/wiki/Sozialversicherungsnummer
		// Pattern reference: adapted from silv3rshi3ld/gdpr-pii-scanner DE detectors.
		// False-positive mitigation: birthday component (DDMMYY) constrains ranges;
		// letter separator is structurally uncommon in random strings.
		Entry{
			Name:       "svnr",
			Pack:       "DE",
			Re:         regexp.MustCompile(`\b\d{2}[\s-]?(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}[\s-]?[A-Za-z][\s-]?\d{3}\b`),
			PIIType:    "SVNR",
			Confidence: 0.80,
		},
		// German vehicle registration plate (Kfz-Kennzeichen):
		// Format: 1-3 letter district code, separator, 1-2 letters, 1-4 digits.
		// Source: https://de.wikipedia.org/wiki/Kfz-Kennzeichen_(Deutschland)
		// Pattern reference: mnestorov/regex-patterns Vehicle Registration Codes.
		// False-positive mitigation: strict structural format with dash/space separator.
		Entry{
			Name:       "kfz",
			Pack:       "DE",
			Re:         regexp.MustCompile(`\b[A-ZÄÖÜ]{1,3}[\s\-][A-Z]{1,2}[\s\-]?\d{1,4}\b`),
			PIIType:    "KFZ",
			Confidence: 0.75,
		},
	)
}
