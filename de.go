package packs

// Source: DE Steuer-ID — BZSt specification https://www.bzst.de/DE/Privatpersonen/SteuerlicheIdentifikationsnummer/steuerlicheidentifikationsnummer_node.html
// Source: DE SVNR — German social insurance number format
// Source: DE KFZ-Kennzeichen — mnestorov/regex-patterns — https://github.com/mnestorov/regex-patterns#vehicle-registration-codes

import (
	"regexp"
	"unicode"
)

func init() {
	Register(
		Entry{
			Name:       "steuer_id",
			Pack:       "DE",
			Re:         regexp.MustCompile(`\b([1-9]\d{10})\b`),
			PIIType:    "STEUERID",
			Confidence: 0.90,
			Validate:   validateSteuerID,
		},
		Entry{
			Name:       "svnr",
			Pack:       "DE",
			Re:         regexp.MustCompile(`\b(\d{2}[0-3]\d[01]\d\d{2}[A-Z]\d{4})\b`),
			PIIType:    "SVNR",
			Confidence: 0.85,
		},
		Entry{
			Name:       "kfz_kennzeichen",
			Pack:       "DE",
			Re:         regexp.MustCompile(`\b([A-Z\x{00C4}\x{00D6}\x{00DC}]{1,3})\s?[-\s]\s?([A-Z]{1,2})\s?[-\s]\s?(\d{1,4})\b`),
			PIIType:    "KFZ",
			Confidence: 0.70,
		},
	)
}

// validateSteuerID implements ISO 7064 MOD 11,10 iterative checksum
// for the German Steuerliche Identifikationsnummer (11 digits).
//
// Rules:
//   - First digit must be 1-9 (already enforced by regex)
//   - Among digits 2-10 (positions 1-9, 0-indexed), no digit appears more than 3 times
//   - Last digit is the check digit per ISO 7064 MOD 11,10
func validateSteuerID(s string) bool {
	if len(s) != 11 {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	if s[0] == '0' {
		return false
	}

	// Check digit frequency: positions 1-9 (digits 2-10), no digit > 3 times
	freq := [10]int{}
	for i := 1; i <= 9; i++ {
		freq[s[i]-'0']++
	}
	for _, f := range freq {
		if f > 3 {
			return false
		}
	}

	// ISO 7064 MOD 11,10 iterative checksum
	product := 10
	for i := 0; i < 10; i++ {
		digit := int(s[i] - '0')
		sum := (digit + product) % 10
		if sum == 0 {
			sum = 10
		}
		product = (sum * 2) % 11
	}
	check := 11 - product
	if check == 10 {
		check = 0
	}
	return int(s[10]-'0') == check
}
