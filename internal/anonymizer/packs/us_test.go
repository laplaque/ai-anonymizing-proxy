package packs

import "testing"

func TestUSPhonePositives(t *testing.T) {
	entry := findEntry("US", "us_phone")
	if entry == nil {
		t.Fatal("us_phone entry not found")
	}
	positives := []string{
		"+1-555-123-4567",
		"+1-800-555-1234",
		"(555) 867-5309",
		"555.123.4567",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestUSPhoneNegatives(t *testing.T) {
	entry := findEntry("US", "us_phone")
	if entry == nil {
		t.Fatal("us_phone entry not found")
	}
	negatives := []string{
		"123",
		"abcdefghij",
		"123456",
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}

func TestUSPhoneTokenSelfCheck(t *testing.T) {
	entry := findEntry("US", "us_phone")
	if entry == nil {
		t.Fatal("us_phone entry not found")
	}
	token := "[PII_PHONE_abcdef0123456789]"
	if entry.Re.MatchString(token) {
		t.Errorf("pattern matched its own token: %q", token)
	}
}

func TestUSSSNPositives(t *testing.T) {
	entry := findEntry("US", "us_ssn")
	if entry == nil {
		t.Fatal("us_ssn entry not found")
	}
	positives := []string{
		"123-45-6789",
		"234-56-7890",
		"321-54-9876",
		"456-78-9012",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestUSSSNNegatives(t *testing.T) {
	entry := findEntry("US", "us_ssn")
	if entry == nil {
		t.Fatal("us_ssn entry not found")
	}
	negatives := []string{
		"123456789",   // unformatted — rejected by design
		"1234567890",  // too many digits
		"12-34-5678",  // wrong grouping
		"abc-de-fghi", // letters
		"123-45-678",  // too few in last group
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}

func TestUSSSNTokenSelfCheck(t *testing.T) {
	entry := findEntry("US", "us_ssn")
	if entry == nil {
		t.Fatal("us_ssn entry not found")
	}
	token := "[PII_SSN_abcdef0123456789]"
	if entry.Re.MatchString(token) {
		t.Errorf("pattern matched its own token: %q", token)
	}
}

func TestUSAddressPositives(t *testing.T) {
	entry := findEntry("US", "us_address")
	if entry == nil {
		t.Fatal("us_address entry not found")
	}
	positives := []string{
		"123 Main Street",
		"456 Oak Ave",
		"789 Pine Blvd",
		"1 Elm Drive",
		"42 Broadway Lane",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestUSAddressNegatives(t *testing.T) {
	entry := findEntry("US", "us_address")
	if entry == nil {
		t.Fatal("us_address entry not found")
	}
	negatives := []string{
		"plain text",
		"no number here Street",
		"123",
		"Main Street",
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}

func TestUSIPv6Positives(t *testing.T) {
	entry := findEntry("US", "ipv6")
	if entry == nil {
		t.Fatal("ipv6 entry not found")
	}
	positives := []string{
		"::1",
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestUSIPv4Positives(t *testing.T) {
	entry := findEntry("US", "ipv4")
	if entry == nil {
		t.Fatal("ipv4 entry not found")
	}
	positives := []string{
		"192.168.1.1",
		"127.0.0.1",
		"10.0.0.0",
		"172.16.0.0",
		"0.0.0.0",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}
