package packs

import "testing"

func TestValidateBSN(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		// Synthetic checksum-valid BSNs generated using elfproef algorithm.
		// sum = 9*d1 + 8*d2 + 7*d3 + 6*d4 + 5*d5 + 4*d6 + 3*d7 + 2*d8 - 1*d9, must be divisible by 11.
		// Source: https://nl.wikipedia.org/wiki/Burgerservicenummer
		{"valid BSN 111222333", "111222333", true}, // elfproef: 9+8+7+12+10+8+9+6-3 = 66, 66%11=0
		{"valid BSN 123456782", "123456782", true}, // well-known test value
		{"valid BSN 010464554", "010464554", true}, // 0+8+0+24+30+16+15+10-4 = 99 → 99%11=0 ✓
		{"wrong check digit", "123456789", false},
		{"too short", "12345678", false},
		{"too long", "1234567890", false},
		{"all zeros sum=0", "000000000", false}, // sum=0 is rejected
		{"non-numeric", "12345678A", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateBSN(tc.input)
			if got != tc.want {
				t.Errorf("validateBSN(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestNLPackRegistered(t *testing.T) {
	entries := All()
	packEntries := filterPack(entries, "NL")
	if len(packEntries) == 0 {
		t.Fatal("NL pack has no registered entries")
	}

	names := make(map[string]bool)
	for _, e := range packEntries {
		names[e.Name] = true
	}
	for _, want := range []string{"bsn", "kvk"} {
		if !names[want] {
			t.Errorf("NL pack missing pattern %q", want)
		}
	}
}

func TestNLBSNPattern(t *testing.T) {
	entry := findEntry("bsn", "NL")
	if entry == nil {
		t.Fatal("bsn entry not found in NL pack")
	}
	if entry.Validate == nil {
		t.Fatal("bsn entry should have a Validate function")
	}

	// True positive: 9-digit number
	if !entry.Re.MatchString("123456782") {
		t.Error("bsn regex should match valid 9-digit format")
	}

	// Regex match + validator pass
	if entry.Re.MatchString("123456782") && !entry.Validate("123456782") {
		t.Error("bsn validator should accept elfproef-valid BSN")
	}

	// Regex match + validator reject (wrong check digit)
	if entry.Re.MatchString("123456789") {
		if entry.Validate("123456789") {
			t.Error("bsn validator should reject elfproef-invalid BSN")
		}
	}
}

func TestNLKvKPattern(t *testing.T) {
	entry := findEntry("kvk", "NL")
	if entry == nil {
		t.Fatal("kvk entry not found in NL pack")
	}

	// True positive: 8-digit number
	if !entry.Re.MatchString("12345678") {
		t.Error("kvk regex should match 8-digit number")
	}

	// True negative: 7 digits
	if entry.Re.MatchString("1234567") {
		t.Error("kvk regex should NOT match 7-digit number")
	}

	// True negative: 9 digits (would match BSN instead)
	if entry.Re.MatchString("123456789") {
		t.Error("kvk regex should NOT match 9-digit number")
	}
}
