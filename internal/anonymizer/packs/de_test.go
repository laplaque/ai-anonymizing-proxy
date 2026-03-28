package packs

import "testing"

func TestValidateSteuerID(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		// Synthetic checksum-valid Steuer-IDs generated using ISO 7064 MOD 11,10.
		// Source: https://de.wikipedia.org/wiki/Steuerliche_Identifikationsnummer
		{"valid example 1", "65929970489", true},
		{"valid example 2", "86095742719", true},
		// Spaced/hyphenated formats (validateSteuerID strips non-digits).
		{"valid spaced", "659 299 704 89", true},
		{"valid hyphenated", "659-299-704-89", true},
		{"valid mixed", "659 299-704 89", true},
		{"valid spaced example 2", "860 957 427 19", true},
		// True negatives
		{"wrong check digit", "65929970488", false},
		{"starts with zero", "05929970489", false},
		{"too short", "6592997048", false},
		{"too long", "659299704891", false},
		{"all zeros", "00000000000", false},
		{"non-numeric", "6592997A489", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateSteuerID(tc.input)
			if got != tc.want {
				t.Errorf("validateSteuerID(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestDEPackRegistered(t *testing.T) {
	entries := All()
	packEntries := filterPack(entries, "DE")
	if len(packEntries) == 0 {
		t.Fatal("DE pack has no registered entries")
	}

	names := make(map[string]bool)
	for _, e := range packEntries {
		names[e.Name] = true
	}
	for _, want := range []string{"steuer_id", "svnr", "kfz"} {
		if !names[want] {
			t.Errorf("DE pack missing pattern %q", want)
		}
	}
}

func TestDESteuerIDPattern(t *testing.T) {
	entry := findEntry("steuer_id", "DE")
	if entry == nil {
		t.Fatal("steuer_id entry not found in DE pack")
	}

	// True positive: contiguous 11-digit number starting with non-zero.
	if !entry.Re.MatchString("65929970489") {
		t.Error("steuer_id regex should match contiguous format")
	}

	// True positive: spaced format (XXX XXX XXX XX).
	if !entry.Re.MatchString("659 299 704 89") {
		t.Error("steuer_id regex should match spaced format")
	}

	// True positive: hyphenated format.
	if !entry.Re.MatchString("659-299-704-89") {
		t.Error("steuer_id regex should match hyphenated format")
	}

	// True negative: starts with 0.
	if entry.Re.MatchString("05929970489") {
		t.Error("steuer_id regex should NOT match number starting with 0")
	}

	// True negative: double space (not a valid separator).
	if entry.Re.MatchString("659  299 704 89") {
		t.Error("steuer_id regex should NOT match double-space format")
	}

	// True negative: underscore separator.
	if entry.Re.MatchString("659_299_704_89") {
		t.Error("steuer_id regex should NOT match underscore format")
	}
}

func TestDESVNRPattern(t *testing.T) {
	entry := findEntry("svnr", "DE")
	if entry == nil {
		t.Fatal("svnr entry not found in DE pack")
	}

	// Synthetic SVNR: area(12) + DOB(150385) + letter(A) + seq(123)
	if !entry.Re.MatchString("12150385A123") {
		t.Error("svnr regex should match contiguous format")
	}

	// Spaced format: area DOB letter seq
	if !entry.Re.MatchString("12 150385 A 123") {
		t.Error("svnr regex should match spaced format")
	}

	// Hyphenated format
	if !entry.Re.MatchString("12-150385-A-123") {
		t.Error("svnr regex should match hyphenated format")
	}

	// Invalid: bad month (13)
	if entry.Re.MatchString("12151385A123") {
		t.Error("svnr regex should NOT match invalid month")
	}
}

func TestDEKfzPattern(t *testing.T) {
	entry := findEntry("kfz", "DE")
	if entry == nil {
		t.Fatal("kfz entry not found in DE pack")
	}

	positives := []string{
		"B AB 1234",
		"HH-XY 42",
		"M A 1",
		"BN-AB 123",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("kfz pattern should match %q", s)
		}
	}
}
