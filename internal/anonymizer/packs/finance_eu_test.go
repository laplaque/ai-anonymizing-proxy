package packs

import "testing"

func TestValidateIBAN(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		// Synthetic checksum-valid IBANs using ISO 7064 MOD 97-10.
		// Source: https://en.wikipedia.org/wiki/International_Bank_Account_Number
		{"valid DE IBAN", "DE89370400440532013000", true},
		{"valid GB IBAN", "GB29NWBK60161331926819", true},
		{"valid NL IBAN", "NL91ABNA0417164300", true},
		{"valid FR IBAN", "FR7630006000011234567890189", true},
		{"valid DE IBAN spaced", "DE89 3704 0044 0532 0130 00", true},
		// True negatives
		{"wrong check digits", "DE00370400440532013000", false},
		{"too short", "DE8937040044", false},
		{"too long", "DE89370400440532013000123456789012345", false},
		{"non-alpha country", "12370400440532013000", false},
		{"non-digit check", "DEAB370400440532013000", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateIBAN(tc.input)
			if got != tc.want {
				t.Errorf("validateIBAN(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestFINANCEEUPackRegistered(t *testing.T) {
	entries := All()
	packEntries := filterPack(entries, "FINANCE_EU")
	if len(packEntries) == 0 {
		t.Fatal("FINANCE_EU pack has no registered entries")
	}

	names := make(map[string]bool)
	for _, e := range packEntries {
		names[e.Name] = true
	}
	for _, want := range []string{"iban", "swift_bic", "vat_eu"} {
		if !names[want] {
			t.Errorf("FINANCE_EU pack missing pattern %q", want)
		}
	}
}

func TestFINANCEEUIBANPattern(t *testing.T) {
	entry := findEntry("iban", "FINANCE_EU")
	if entry == nil {
		t.Fatal("iban entry not found in FINANCE_EU pack")
	}
	if entry.Validate == nil {
		t.Fatal("iban entry should have a Validate function")
	}

	// True positives (regex match — contiguous)
	positives := []string{
		"DE89370400440532013000",
		"GB29NWBK60161331926819",
		"NL91ABNA0417164300",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("iban pattern should match %q", s)
		}
	}

	// True positives (regex match — spaced)
	spacedPositives := []string{
		"DE89 3704 0044 0532 0130 00",
		"GB29 NWBK 6016 1331 9268 19",
	}
	for _, s := range spacedPositives {
		if !entry.Re.MatchString(s) {
			t.Errorf("iban pattern should match spaced format %q", s)
		}
	}

	// Regex match + validator pass
	if entry.Re.MatchString("DE89370400440532013000") && !entry.Validate("DE89370400440532013000") {
		t.Error("iban validator should accept checksum-valid IBAN")
	}

	// Regex match + validator reject (bad checksum)
	if entry.Re.MatchString("DE00370400440532013000") {
		if entry.Validate("DE00370400440532013000") {
			t.Error("iban validator should reject checksum-invalid IBAN")
		}
	}
}

func TestFINANCEEUSWIFTBICPattern(t *testing.T) {
	entry := findEntry("swift_bic", "FINANCE_EU")
	if entry == nil {
		t.Fatal("swift_bic entry not found in FINANCE_EU pack")
	}

	positives := []string{
		"DEUTDEFF",    // Deutsche Bank, 8-char
		"DEUTDEFF500", // Deutsche Bank Frankfurt branch, 11-char
		"COBADEFFXXX", // Commerzbank, 11-char
		"BNPAFRPPXXX", // BNP Paribas, 11-char
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("swift_bic pattern should match %q", s)
		}
	}

	negatives := []string{
		"DEUT",     // too short
		"deutdeff", // lowercase
		"12UTDEFF", // starts with digits
	}
	for _, s := range negatives {
		if entry.Re.MatchString(s) {
			t.Errorf("swift_bic pattern should NOT match %q", s)
		}
	}
}

func TestFINANCEEUVATPattern(t *testing.T) {
	entry := findEntry("vat_eu", "FINANCE_EU")
	if entry == nil {
		t.Fatal("vat_eu entry not found in FINANCE_EU pack")
	}

	positives := []string{
		"DE123456789",    // Germany
		"FR12345678901",  // France (2 digits + 9 digits)
		"NL123456789B01", // Netherlands
		"ATU12345678",    // Austria
		"BE0123456789",   // Belgium
		"ES12345678A",    // Spain
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("vat_eu pattern should match %q", s)
		}
	}

	negatives := []string{
		"XX123456789", // unknown country code
		"DE12345678",  // too short for DE
		"US123456789", // not EU
	}
	for _, s := range negatives {
		if entry.Re.MatchString(s) {
			t.Errorf("vat_eu pattern should NOT match %q", s)
		}
	}
}
