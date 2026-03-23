package packs

import "testing"

func TestDESteuerIDPositives(t *testing.T) {
	entry := findEntry("DE", "steuer_id")
	if entry == nil {
		t.Fatal("steuer_id entry not found")
	}

	// Synthetic checksum-valid Steuer-IDs (ISO 7064 MOD 11,10)
	positives := []string{
		"65929970489",
		"86095742719",
		"57549285017",
		"25768131411",
		"12345679019",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("regex should match: %q", p)
			continue
		}
		if !validateSteuerID(p) {
			t.Errorf("checksum should pass: %q", p)
		}
	}
}

func TestDESteuerIDNegatives(t *testing.T) {
	negatives := []struct {
		name  string
		value string
	}{
		{"first digit zero", "02345678901"},
		{"wrong checksum", "65929970488"},
		{"too short", "6592997048"},
		{"too long", "659299704890"},
		{"all same digit violation", "11111111118"},
	}
	for _, tc := range negatives {
		t.Run(tc.name, func(t *testing.T) {
			if validateSteuerID(tc.value) {
				t.Errorf("checksum should fail: %q", tc.value)
			}
		})
	}
}

func TestDESteuerIDTokenSelfCheck(t *testing.T) {
	entry := findEntry("DE", "steuer_id")
	if entry == nil {
		t.Fatal("steuer_id entry not found")
	}
	token := "[PII_STEUERID_abcdef0123456789]"
	if entry.Re.MatchString(token) {
		t.Errorf("pattern matched its own token: %q", token)
	}
}

func TestDESVNRPositives(t *testing.T) {
	entry := findEntry("DE", "svnr")
	if entry == nil {
		t.Fatal("svnr entry not found")
	}
	positives := []string{
		"12010190A1234",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestDESVNRNegatives(t *testing.T) {
	entry := findEntry("DE", "svnr")
	if entry == nil {
		t.Fatal("svnr entry not found")
	}
	negatives := []string{
		"plaintext",
		"12345678",
		"ABCDEFGHIJKLM",
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}

func TestDEKFZPositives(t *testing.T) {
	entry := findEntry("DE", "kfz_kennzeichen")
	if entry == nil {
		t.Fatal("kfz_kennzeichen entry not found")
	}
	positives := []string{
		"B-AB-1234",
		"M-X-1",
		"HH-AB-123",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestDEKFZNegatives(t *testing.T) {
	entry := findEntry("DE", "kfz_kennzeichen")
	if entry == nil {
		t.Fatal("kfz_kennzeichen entry not found")
	}
	negatives := []string{
		"1234",
		"plaintext",
		"A-B-",
		"-A-1",
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}

func TestDEKFZTokenSelfCheck(t *testing.T) {
	entry := findEntry("DE", "kfz_kennzeichen")
	if entry == nil {
		t.Fatal("kfz_kennzeichen entry not found")
	}
	token := "[PII_KFZ_abcdef0123456789]"
	if entry.Re.MatchString(token) {
		t.Errorf("pattern matched its own token: %q", token)
	}
}

func TestValidateSteuerIDEdgeCases(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty", "", false},
		{"non-digits", "abcdefghijk", false},
		{"ten digits", "1234567890", false},
		{"twelve digits", "123456789012", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateSteuerID(tc.input); got != tc.want {
				t.Errorf("validateSteuerID(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
