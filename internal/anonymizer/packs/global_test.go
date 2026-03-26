package packs

import "testing"

func TestLuhnValid(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		// True positives — checksum-valid synthetic card numbers.
		// Source: Luhn algorithm test vectors, https://en.wikipedia.org/wiki/Luhn_algorithm
		{"visa valid", "4111111111111111", true},
		{"visa with spaces", "4111 1111 1111 1111", true},
		{"visa with dashes", "4111-1111-1111-1111", true},
		{"mastercard valid", "5500000000000004", true},
		{"amex valid", "378282246310005", true},
		// True negatives — random digit sequences that fail Luhn.
		{"random digits", "1234567890123456", false},
		{"off by one", "4111111111111112", false},
		{"too short", "411111", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := luhnValid(tc.input)
			if got != tc.want {
				t.Errorf("luhnValid(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestGlobalPackRegistered(t *testing.T) {
	entries := All()
	packEntries := filterPack(entries, "GLOBAL")
	if len(packEntries) == 0 {
		t.Fatal("GLOBAL pack has no registered entries")
	}

	// Verify expected pattern names exist.
	names := make(map[string]bool)
	for _, e := range packEntries {
		names[e.Name] = true
	}
	for _, want := range []string{"email", "api_key", "credit_card"} {
		if !names[want] {
			t.Errorf("GLOBAL pack missing pattern %q", want)
		}
	}
}

func TestGlobalEmailPattern(t *testing.T) {
	entry := findEntry("email", "GLOBAL")
	if entry == nil {
		t.Fatal("email entry not found in GLOBAL pack")
	}

	// True positives
	positives := []string{
		"alice@example.com",
		"user.name+tag@domain.co.uk",
		"test@sub.domain.org",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("email pattern should match %q", s)
		}
	}

	// True negatives
	negatives := []string{
		"not-an-email",
		"@missing-local.com",
		"missing-domain@",
	}
	for _, s := range negatives {
		if entry.Re.MatchString(s) {
			t.Errorf("email pattern should NOT match %q", s)
		}
	}
}

func TestGlobalCreditCardWithLuhn(t *testing.T) {
	entry := findEntry("credit_card", "GLOBAL")
	if entry == nil {
		t.Fatal("credit_card entry not found in GLOBAL pack")
	}
	if entry.Validate == nil {
		t.Fatal("credit_card entry should have a Validate function")
	}

	// Valid card number that matches regex AND passes Luhn.
	if !entry.Re.MatchString("4111111111111111") {
		t.Error("regex should match valid Visa number")
	}
	if !entry.Validate("4111111111111111") {
		t.Error("validator should accept valid Visa number")
	}

	// Number that matches regex but fails Luhn.
	if !entry.Re.MatchString("1234567890123456") {
		t.Error("regex should match digit pattern")
	}
	if entry.Validate("1234567890123456") {
		t.Error("validator should reject invalid Luhn number")
	}
}

// --- helpers ---

func filterPack(entries []Entry, pack string) []Entry {
	var result []Entry
	for _, e := range entries {
		if e.Pack == pack {
			result = append(result, e)
		}
	}
	return result
}

func findEntry(name, pack string) *Entry {
	for _, e := range All() {
		if e.Name == name && e.Pack == pack {
			return &e
		}
	}
	return nil
}
