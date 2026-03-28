package packs

import "testing"

func TestValidateSSN(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid hyphenated", "123-45-6789", true},
		{"valid no hyphens", "123456789", true},
		{"area 000 invalid", "000-12-3456", false},
		{"area 666 invalid", "666-12-3456", false},
		{"area 900 invalid", "900-12-3456", false},
		{"area 999 invalid", "999-12-3456", false},
		{"group 00 invalid", "123-00-6789", false},
		{"serial 0000 invalid", "123-45-0000", false},
		{"too short", "12345678", false},
		{"too long", "1234567890", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateSSN(tc.input)
			if got != tc.want {
				t.Errorf("validateSSN(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestValidateUSPhone(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"hyphenated", "555-867-5309", true},
		{"with parens", "(212) 555-0100", true},
		{"with plus", "+1-800-555-1234", true},
		{"spaces", "555 867 5309", true},
		{"dots only rejected", "555.867.5309", false},
		{"no separator rejected", "5558675309", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateUSPhone(tc.input)
			if got != tc.want {
				t.Errorf("validateUSPhone(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestUSPackRegistered(t *testing.T) {
	entries := All()
	packEntries := filterPack(entries, "US")
	if len(packEntries) == 0 {
		t.Fatal("US pack has no registered entries")
	}

	names := make(map[string]bool)
	for _, e := range packEntries {
		names[e.Name] = true
	}
	for _, want := range []string{"ssn", "phone_us", "address_us", "ipv6", "ipv4", "zip_us"} {
		if !names[want] {
			t.Errorf("US pack missing pattern %q", want)
		}
	}
}

func TestUSSSNPattern(t *testing.T) {
	entry := findEntry("ssn", "US")
	if entry == nil {
		t.Fatal("ssn entry not found in US pack")
	}
	if entry.Validate == nil {
		t.Fatal("ssn entry should have a Validate function")
	}

	// Valid SSN.
	if !entry.Re.MatchString("123-45-6789") {
		t.Error("ssn regex should match valid format")
	}
	if !entry.Validate("123-45-6789") {
		t.Error("ssn validator should accept valid SSN")
	}

	// Invalid area code 000.
	if entry.Validate("000-12-3456") {
		t.Error("ssn validator should reject area code 000")
	}

	// Invalid area code 666.
	if entry.Validate("666-12-3456") {
		t.Error("ssn validator should reject area code 666")
	}
}

func TestUSPhonePattern(t *testing.T) {
	entry := findEntry("phone_us", "US")
	if entry == nil {
		t.Fatal("phone_us entry not found in US pack")
	}

	positives := []string{
		"555-867-5309",
		"+1-800-555-1234",
		"(212) 555-0100",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("phone pattern should match %q", s)
		}
	}
}

func TestUSAddressPattern(t *testing.T) {
	entry := findEntry("address_us", "US")
	if entry == nil {
		t.Fatal("address_us entry not found in US pack")
	}

	positives := []string{
		"123 Main Street",
		"456 Elm Ave",
		"789 Oak Boulevard",
		"321 Oak St",
		"10 A St",
		"5 B Ave",
		"100 North Main Rd",
		"42 West Elm Drive",
		"My address is 123 Main St in Springfield", // embedded in surrounding text
		"123 Main Street, Apt 4",                   // trailing punctuation after \b
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("address pattern should match %q", s)
		}
	}

	negatives := []struct {
		name  string
		input string
	}{
		{"German ist", "65929970489 ist korrekt"},
		{"German ist 2", "12345 ist falsch"},
		{"German Kunst", "12345 Kunst und Kultur"},
		{"German Durst", "99 Durst nach Wissen"},
		{"German erst", "100 erst dann"},
		{"German Bist", "42 Bist du sicher"},
		// Addresses where the suffix IS the street name (e.g. "123 Court")
		// are not matched because the regex requires at least one word + space
		// before the suffix. This is an accepted trade-off to eliminate false
		// positives on words ending in street suffixes.
		{"suffix-only street name", "123 Court"},
		{"suffix-only Lane", "456 Lane"},
	}
	for _, tc := range negatives {
		t.Run(tc.name, func(t *testing.T) {
			if entry.Re.MatchString(tc.input) {
				t.Errorf("address pattern should NOT match %q", tc.input)
			}
		})
	}
}

func TestUSIPv4Pattern(t *testing.T) {
	entry := findEntry("ipv4", "US")
	if entry == nil {
		t.Fatal("ipv4 entry not found in US pack")
	}

	positives := []string{"192.168.1.1", "10.0.0.1", "255.255.255.255"}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("ipv4 pattern should match %q", s)
		}
	}
}

func TestUSIPv6Pattern(t *testing.T) {
	entry := findEntry("ipv6", "US")
	if entry == nil {
		t.Fatal("ipv6 entry not found in US pack")
	}

	positives := []string{
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		"::1",
		"fe80::",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("ipv6 pattern should match %q", s)
		}
	}
}

func TestRegistryPIITypes(t *testing.T) {
	types := PIITypes()
	if len(types) == 0 {
		t.Fatal("PIITypes() returned empty list")
	}
	seen := make(map[string]bool)
	for _, t := range types {
		seen[t] = true
	}
	// Spot-check a few expected types.
	for _, want := range []string{"EMAIL", "APIKEY", "STEUERID", "JWT"} {
		if !seen[want] {
			t.Errorf("PIITypes() missing %q", want)
		}
	}
}
