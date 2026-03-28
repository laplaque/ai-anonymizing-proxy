package packs

import "testing"

func TestValidateFRNIR(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		// Synthetic checksum-valid NIR numbers.
		// key = 97 - (base % 97)
		// Source: https://fr.wikipedia.org/wiki/Numéro_de_sécurité_sociale_en_France

		// Male, born Jan 1985, dept 75 (Paris), commune 012, order 345.
		// base = 1850175012345 → 1850175012345 % 97 = 42 → key = 97 - 42 = 55
		{"valid male Paris", "185017501234555", true},
		{"valid male Paris spaced", "1 85 01 75 012 345 55", true},

		// Female, born Dec 1990, dept 13 (Bouches-du-Rhône), commune 055, order 001.
		// base = 2901213055001 → 2901213055001 % 97 = 15 → key = 97 - 15 = 82
		{"valid female Marseille", "290121305500182", true},

		// Corsica 2A (Corse-du-Sud): department replaced by 19 for check.
		// sex=1, year=80, month=06, dept=2A, commune=001, order=002
		// For check: base = 1800619001002 → 1800619001002 % 97 = 54 → key = 97 - 54 = 43
		{"valid Corsica 2A", "180062A00100243", true},

		// Corsica 2B (Haute-Corse): department replaced by 18 for check.
		// sex=2, year=75, month=03, dept=2B, commune=010, order=100
		// For check: base = 2750318010100 → 2750318010100 % 97 = 54 → key = 97 - 54 = 43
		{"valid Corsica 2B", "275032B01010043", true},

		// True negatives
		{"wrong key", "185017501234556", false},
		{"too short", "18501750123455", false},
		{"too long", "1850175012345550", false},
		{"invalid sex digit", "385017501234500", false},
		{"all zeros", "000000000000000", false},
		{"non-numeric", "18501750123A555", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateFRNIR(tc.input)
			if got != tc.want {
				t.Errorf("validateFRNIR(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestValidateLuhn(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		// Source: ISO/IEC 7812-1, https://en.wikipedia.org/wiki/Luhn_algorithm
		{"valid 9-digit SIREN", "362521874", true},
		{"valid 9-digit SIREN 2", "443061841", true},
		{"valid 14-digit SIRET", "36252187400036", true},
		{"valid 14-digit SIRET 2", "44306184100013", true},
		{"invalid 9-digit", "362521879", false},
		{"invalid 9-digit 2", "443061840", false},
		{"invalid 14-digit", "12345678901234", false},
		{"single digit", "5", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateLuhn(tc.input)
			if got != tc.want {
				t.Errorf("validateLuhn(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestValidateSIRET(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid contiguous", "36252187400036", true},
		{"valid spaced", "362 521 874 00036", true},
		{"valid second", "44306184100013", true},
		{"invalid Luhn", "12345678901234", false},
		{"too short", "3625218740003", false},
		{"too long", "362521874000360", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateSIRET(tc.input)
			if got != tc.want {
				t.Errorf("validateSIRET(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestValidateSIREN(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid contiguous", "362521874", true},
		{"valid spaced", "362 521 874", true},
		{"valid second", "443061841", true},
		{"invalid Luhn", "362521879", false},
		{"too short", "36252187", false},
		{"too long", "3625218740", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateSIREN(tc.input)
			if got != tc.want {
				t.Errorf("validateSIREN(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestFRPackRegistered(t *testing.T) {
	entries := All()
	packEntries := filterPack(entries, "FR")
	if len(packEntries) == 0 {
		t.Fatal("FR pack has no registered entries")
	}

	names := make(map[string]bool)
	for _, e := range packEntries {
		names[e.Name] = true
	}
	for _, want := range []string{"nir", "siret", "siren"} {
		if !names[want] {
			t.Errorf("FR pack missing pattern %q", want)
		}
	}
}

func TestFRNIRPattern(t *testing.T) {
	entry := findEntry("nir", "FR")
	if entry == nil {
		t.Fatal("nir entry not found in FR pack")
	}
	if entry.Validate == nil {
		t.Fatal("nir entry should have a Validate function")
	}

	// True positives (regex match — contiguous)
	positives := []string{
		"185017501234555", // standard male
		"290121305500182", // standard female
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("nir pattern should match %q", s)
		}
	}

	// True positives (regex match — spaced, as conventionally written)
	spacedPositives := []string{
		"1 85 01 75 012 345 55",
		"2 90 12 13 055 001 82",
	}
	for _, s := range spacedPositives {
		if !entry.Re.MatchString(s) {
			t.Errorf("nir pattern should match spaced format %q", s)
		}
	}

	// Corsica patterns must match regex (2A/2B in department position)
	corsicaPositives := []string{
		"180062A00100243",
		"275032B01010043",
	}
	for _, s := range corsicaPositives {
		if !entry.Re.MatchString(s) {
			t.Errorf("nir pattern should match Corsica format %q", s)
		}
	}

	// True negatives (regex should not match)
	negatives := []string{
		"385017501234500", // sex digit 3 invalid
		"0850175012345",   // starts with 0
	}
	for _, s := range negatives {
		if entry.Re.MatchString(s) {
			t.Errorf("nir pattern should NOT match %q", s)
		}
	}

	// Regex matches but validator rejects (wrong checksum)
	if entry.Re.MatchString("185017501234556") {
		if entry.Validate("185017501234556") {
			t.Error("nir validator should reject wrong checksum 185017501234556")
		}
	}
}

func TestFRSIRETPattern(t *testing.T) {
	entry := findEntry("siret", "FR")
	if entry == nil {
		t.Fatal("siret entry not found in FR pack")
	}
	if entry.Validate == nil {
		t.Fatal("siret entry should have a Validate function")
	}

	// True positive: 14 contiguous digits (3+3+3+5 grouping)
	if !entry.Re.MatchString("36252187400036") {
		t.Error("siret pattern should match 14-digit contiguous number")
	}

	// True positive: spaced format
	if !entry.Re.MatchString("362 521 874 00036") {
		t.Error("siret pattern should match spaced SIRET format")
	}

	// Regex match + validator pass
	if entry.Re.MatchString("36252187400036") && !entry.Validate("36252187400036") {
		t.Error("siret validator should accept Luhn-valid SIRET")
	}

	// Regex match + validator reject (bad Luhn)
	if entry.Re.MatchString("12345678901234") {
		if entry.Validate("12345678901234") {
			t.Error("siret validator should reject Luhn-invalid SIRET")
		}
	}
}

func TestFRSIRENPattern(t *testing.T) {
	entry := findEntry("siren", "FR")
	if entry == nil {
		t.Fatal("siren entry not found in FR pack")
	}
	if entry.Validate == nil {
		t.Fatal("siren entry should have a Validate function")
	}

	// True positive: 9 contiguous digits
	if !entry.Re.MatchString("362521874") {
		t.Error("siren pattern should match 9-digit number")
	}

	// True positive: spaced format
	if !entry.Re.MatchString("362 521 874") {
		t.Error("siren pattern should match spaced SIREN format")
	}

	// Regex match + validator pass
	if entry.Re.MatchString("362521874") && !entry.Validate("362521874") {
		t.Error("siren validator should accept Luhn-valid SIREN")
	}

	// Regex match + validator reject (bad Luhn)
	if entry.Re.MatchString("362521879") {
		if entry.Validate("362521879") {
			t.Error("siren validator should reject Luhn-invalid SIREN")
		}
	}
}

func TestFRNIRValidatorWithRegex(t *testing.T) {
	entry := findEntry("nir", "FR")
	if entry == nil {
		t.Fatal("nir entry not found in FR pack")
	}

	// Test that valid NIRs pass both regex and validator.
	valid := []string{
		"185017501234555",
		"290121305500182",
	}
	for _, s := range valid {
		if !entry.Re.MatchString(s) {
			t.Errorf("nir regex should match %q", s)
		}
		if !entry.Validate(s) {
			t.Errorf("nir validator should accept %q", s)
		}
	}

	// Test Corsica patterns pass both regex and validator.
	corsica := []string{
		"180062A00100243",
		"275032B01010043",
	}
	for _, s := range corsica {
		if !entry.Re.MatchString(s) {
			t.Errorf("nir regex should match Corsica %q", s)
		}
		if !entry.Validate(s) {
			t.Errorf("nir validator should accept Corsica %q", s)
		}
	}
}
