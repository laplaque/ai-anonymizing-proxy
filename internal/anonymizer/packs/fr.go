package packs

import (
	"regexp"
	"strings"
)

// validateFRNIR validates a French NIR (Numéro d'Inscription au Répertoire /
// Numéro de Sécurité Sociale) using the modulus 97 check.
// Format: 15 digits total — 13-digit base + 2-digit key.
// Key = 97 - (base % 97).
// Corsica departments use 2A (replaced by 19) and 2B (replaced by 18) for
// the modulus computation.
// Source: https://fr.wikipedia.org/wiki/Numéro_de_sécurité_sociale_en_France
// Reference: silv3rshi3ld/gdpr-pii-scanner FR NIR detector (Luhn mod 97).
func validateFRNIR(s string) bool {
	// Defensive: the regex already strips non-digit contexts for contiguous
	// matches, but direct callers may pass formatted NIRs with spaces/hyphens.
	cleaned := strings.NewReplacer(" ", "", "-", "").Replace(s)

	// Handle Corsica: replace 2A→19, 2B→18 in the department position (chars 5-6).
	upper := strings.ToUpper(cleaned)
	if len(upper) >= 7 {
		dept := upper[5:7]
		switch dept {
		case "2A":
			cleaned = cleaned[:5] + "19" + cleaned[7:]
		case "2B":
			cleaned = cleaned[:5] + "18" + cleaned[7:]
		}
	}

	// After Corsica substitution, must be exactly 15 digits.
	if len(cleaned) != 15 {
		return false
	}
	for _, c := range cleaned {
		if c < '0' || c > '9' {
			return false
		}
	}

	// Parse base (first 13 digits) and key (last 2 digits).
	var base int64
	for _, c := range cleaned[:13] {
		base = base*10 + int64(c-'0')
	}
	key := int64(cleaned[13]-'0')*10 + int64(cleaned[14]-'0')

	return key == 97-base%97
}

// validateLuhn implements the Luhn algorithm for SIREN/SIRET validation.
// Strips spaces and hyphens, then verifies the Luhn check digit.
// Source: ISO/IEC 7812-1, https://en.wikipedia.org/wiki/Luhn_algorithm
func validateLuhn(s string) bool {
	// Strip spaces and hyphens to normalize.
	digits := make([]int, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			digits = append(digits, int(s[i]-'0'))
		}
	}
	if len(digits) < 2 {
		return false
	}
	var sum int
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := digits[i]
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

// validateSIRET validates a 14-digit SIRET number using the Luhn algorithm.
// Source: https://fr.wikipedia.org/wiki/Système_d%27identification_du_répertoire_des_établissements
func validateSIRET(s string) bool {
	// Strip spaces and hyphens, verify exactly 14 digits remain.
	cleaned := strings.NewReplacer(" ", "", "-", "").Replace(s)
	if len(cleaned) != 14 {
		return false
	}
	for _, c := range cleaned {
		if c < '0' || c > '9' {
			return false
		}
	}
	return validateLuhn(cleaned)
}

// validateSIREN validates a 9-digit SIREN number using the Luhn algorithm.
// Source: https://fr.wikipedia.org/wiki/Système_d%27identification_du_répertoire_des_entreprises
func validateSIREN(s string) bool {
	// Strip spaces and hyphens, verify exactly 9 digits remain.
	cleaned := strings.NewReplacer(" ", "", "-", "").Replace(s)
	if len(cleaned) != 9 {
		return false
	}
	for _, c := range cleaned {
		if c < '0' || c > '9' {
			return false
		}
	}
	return validateLuhn(cleaned)
}

func init() {
	Register(
		// French NIR (Numéro d'Inscription au Répertoire / Numéro de Sécurité Sociale):
		// 15 characters: sex(1) + year(2) + month(2) + department(2) + commune(3) + order(3) + key(2).
		// Department may be 2A or 2B for Corsica. Regex allows optional spaces/hyphens between groups.
		// Source: https://fr.wikipedia.org/wiki/Numéro_de_sécurité_sociale_en_France
		// Pattern reference: silv3rshi3ld/gdpr-pii-scanner FR NIR detector.
		// False-positive mitigation: modulus 97 checksum validation; Corsica 2A/2B handling.
		Entry{
			Name: "nir",
			Pack: "FR",
			Re: regexp.MustCompile(
				`\b[12][\s-]?\d{2}[\s-]?(?:0[1-9]|1[0-2])[\s-]?(?:\d{2}|2[AB])[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{2}\b`),
			PIIType:    "NIR",
			Confidence: 0.80,
			Validate:   validateFRNIR,
		},
		// French SIRET (Système d'Identification du Répertoire des Établissements):
		// 14 digits — SIREN (9 digits) + NIC (5 digits). Allows optional spaces/hyphens.
		// Luhn-checkable (the full 14-digit SIRET satisfies the Luhn algorithm).
		// Source: https://fr.wikipedia.org/wiki/Système_d%27identification_du_répertoire_des_établissements
		// Pattern reference: mnestorov/regex-patterns France section (VAT prefix FR + 9 digits implies SIREN base).
		// False-positive mitigation: Luhn checksum rejects ~90% of random 14-digit sequences.
		Entry{
			Name: "siret",
			Pack: "FR",
			Re: regexp.MustCompile(
				`\b\d{3}[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{5}\b`),
			PIIType:    "SIRET",
			Confidence: 0.75,
			Validate:   validateSIRET,
		},
		// French SIREN (Système d'Identification du Répertoire des ENtreprises):
		// 9 digits identifying a legal entity in France. Allows optional spaces/hyphens.
		// Luhn-checkable.
		// Source: https://fr.wikipedia.org/wiki/Système_d%27identification_du_répertoire_des_entreprises
		// Pattern reference: mnestorov/regex-patterns France VAT section (SIREN is the 9-digit base of FR VAT).
		// False-positive mitigation: Luhn checksum rejects ~90% of random 9-digit sequences;
		// moderate confidence routes remaining ambiguous matches to AI verification.
		Entry{
			Name: "siren",
			Pack: "FR",
			Re: regexp.MustCompile(
				`\b\d{3}[\s-]?\d{3}[\s-]?\d{3}\b`),
			PIIType:    "SIREN",
			Confidence: 0.60,
			Validate:   validateSIREN,
		},
	)
}
