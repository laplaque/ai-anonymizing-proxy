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
	// Strip spaces and hyphens to normalize.
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

func init() {
	Register(
		// French NIR (Numéro d'Inscription au Répertoire / Numéro de Sécurité Sociale):
		// 15 characters: sex(1) + year(2) + month(2) + department(2) + commune(3) + order(3) + key(2).
		// Department may be 2A or 2B for Corsica.
		// Source: https://fr.wikipedia.org/wiki/Numéro_de_sécurité_sociale_en_France
		// Pattern reference: silv3rshi3ld/gdpr-pii-scanner FR NIR detector.
		// False-positive mitigation: modulus 97 checksum validation; Corsica 2A/2B handling.
		Entry{
			Name:       "nir",
			Pack:       "FR",
			Re:         regexp.MustCompile(`\b[12]\d{2}(?:0[1-9]|1[0-2])(?:\d{2}|2[AB])\d{3}\d{3}\d{2}\b`),
			PIIType:    "NIR",
			Confidence: 0.80,
			Validate:   validateFRNIR,
		},
		// French SIRET (Système d'Identification du Répertoire des Établissements):
		// 14 digits — SIREN (9 digits) + NIC (5 digits).
		// Source: https://fr.wikipedia.org/wiki/Système_d%27identification_du_répertoire_des_établissements
		// Pattern reference: mnestorov/regex-patterns France section (VAT prefix FR + 9 digits implies SIREN base).
		// False-positive mitigation: strict 14-digit length with word boundary; high digit count
		// reduces random matches.
		Entry{
			Name:       "siret",
			Pack:       "FR",
			Re:         regexp.MustCompile(`\b\d{14}\b`),
			PIIType:    "SIRET",
			Confidence: 0.65,
		},
		// French SIREN (Système d'Identification du Répertoire des ENtreprises):
		// 9 digits identifying a legal entity in France.
		// Source: https://fr.wikipedia.org/wiki/Système_d%27identification_du_répertoire_des_entreprises
		// Pattern reference: mnestorov/regex-patterns France VAT section (SIREN is the 9-digit base of FR VAT).
		// False-positive mitigation: low confidence triggers AI verification for ambiguous 9-digit sequences.
		Entry{
			Name:       "siren",
			Pack:       "FR",
			Re:         regexp.MustCompile(`\b\d{9}\b`),
			PIIType:    "SIREN",
			Confidence: 0.50,
		},
	)
}
