package packs

import (
	"math/big"
	"regexp"
	"strings"
)

// validateIBAN validates an International Bank Account Number using the
// ISO 7064 MOD 97-10 algorithm (ISO 13616).
// Steps: move first 4 chars to end, convert letters to digits (A=10..Z=35),
// compute mod 97 — result must be 1.
// Source: https://en.wikipedia.org/wiki/International_Bank_Account_Number#Validating_the_IBAN
// Reference: mnestorov/regex-patterns common patterns (IBAN section).
func validateIBAN(s string) bool {
	// Strip spaces and hyphens.
	cleaned := strings.NewReplacer(" ", "", "-", "").Replace(s)
	cleaned = strings.ToUpper(cleaned)
	if len(cleaned) < 15 || len(cleaned) > 34 {
		return false
	}
	// First two characters must be letters (country code).
	if cleaned[0] < 'A' || cleaned[0] > 'Z' || cleaned[1] < 'A' || cleaned[1] > 'Z' {
		return false
	}
	// Characters 3-4 must be digits (check digits).
	if cleaned[2] < '0' || cleaned[2] > '9' || cleaned[3] < '0' || cleaned[3] > '9' {
		return false
	}
	// Rearrange: move first 4 chars to end.
	rearranged := cleaned[4:] + cleaned[:4]
	// Convert letters to digits: A=10, B=11, ..., Z=35.
	var numStr strings.Builder
	for _, c := range rearranged {
		if c >= 'A' && c <= 'Z' {
			numStr.WriteString(big.NewInt(int64(c - 'A' + 10)).String())
		} else if c >= '0' && c <= '9' {
			numStr.WriteByte(byte(c))
		} else {
			return false
		}
	}
	// Compute mod 97 using big.Int for arbitrary precision.
	n := new(big.Int)
	n.SetString(numStr.String(), 10)
	mod := new(big.Int)
	mod.Mod(n, big.NewInt(97))
	return mod.Int64() == 1
}

func init() {
	Register(
		// International Bank Account Number (IBAN):
		// 2-letter country code + 2 check digits + up to 30 alphanumeric BBAN characters.
		// Allows optional spaces between groups of 4.
		// Source: https://en.wikipedia.org/wiki/International_Bank_Account_Number
		// Pattern reference: mnestorov/regex-patterns common patterns.
		// False-positive mitigation: ISO 7064 MOD 97-10 checksum rejects >99% of random strings.
		Entry{
			Name:       "iban",
			Pack:       "FINANCE_EU",
			Re:         regexp.MustCompile(`\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){1,7}[\dA-Z]{1,4}\b`),
			PIIType:    "IBAN",
			Confidence: 0.85,
			Validate:   validateIBAN,
		},
		// SWIFT/BIC code (Business Identifier Code):
		// 8 or 11 alphanumeric characters: 4-letter bank code + 2-letter country + 2-char location + optional 3-char branch.
		// Source: https://en.wikipedia.org/wiki/ISO_9362
		// Pattern reference: adapted from standard BIC format documentation.
		// False-positive mitigation: strict structure (4 alpha + 2 alpha country + 2 alnum + optional 3 alnum);
		// moderate confidence routes ambiguous matches to AI verification.
		Entry{
			Name:       "swift_bic",
			Pack:       "FINANCE_EU",
			Re:         regexp.MustCompile(`\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`),
			PIIType:    "SWIFTBIC",
			Confidence: 0.65,
		},
		// EU VAT Identification Number:
		// 2-letter country code prefix + 2-15 alphanumeric characters.
		// Covers all EU member state formats.
		// Source: https://en.wikipedia.org/wiki/VAT_identification_number
		// Pattern reference: mnestorov/regex-patterns (country-specific VAT patterns consolidated).
		// False-positive mitigation: requires known EU country code prefix; moderate confidence.
		Entry{
			Name: "vat_eu",
			Pack: "FINANCE_EU",
			Re: regexp.MustCompile(
				`\b(?:` +
					`AT[U]\d{8}` + // Austria
					`|BE[01]\d{9}` + // Belgium
					`|BG\d{9,10}` + // Bulgaria
					`|HR\d{11}` + // Croatia
					`|CY\d{8}[A-Z]` + // Cyprus
					`|CZ\d{8,10}` + // Czech Republic
					`|DK\d{8}` + // Denmark
					`|EE\d{9}` + // Estonia
					`|FI\d{8}` + // Finland
					`|FR[A-HJ-NP-Z0-9]{2}\d{9}` + // France
					`|DE\d{9}` + // Germany
					`|EL\d{9}` + // Greece
					`|HU\d{8}` + // Hungary
					`|IE\d[A-Z0-9]\d{5}[A-Z]{1,2}` + // Ireland
					`|IT\d{11}` + // Italy
					`|LV\d{11}` + // Latvia
					`|LT(?:\d{9}|\d{12})` + // Lithuania
					`|LU\d{8}` + // Luxembourg
					`|MT\d{8}` + // Malta
					`|NL\d{9}B\d{2}` + // Netherlands
					`|PL\d{10}` + // Poland
					`|PT\d{9}` + // Portugal
					`|RO\d{2,10}` + // Romania
					`|SK\d{10}` + // Slovakia
					`|SI\d{8}` + // Slovenia
					`|ES[A-Z0-9]\d{7}[A-Z0-9]` + // Spain
					`|SE\d{12}` + // Sweden
					`)\b`),
			PIIType:    "VATID",
			Confidence: 0.80,
		},
	)
}
