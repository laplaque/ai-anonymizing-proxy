package packs

import "testing"

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

	positives := []string{
		"123-45-6789",
		"123456789",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("ssn pattern should match %q", s)
		}
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
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("address pattern should match %q", s)
		}
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
