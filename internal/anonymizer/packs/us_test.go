package packs

import (
	"fmt"
	"testing"
)

func TestUSPhoneTruePositives(t *testing.T) {
	entry := findEntry("US", "us_phone")
	if entry == nil {
		t.Fatal("us_phone entry not found in US pack")
	}
	cases := []string{
		fmt.Sprintf("(%s) %s-%s", "555", "123", "4567"),
		fmt.Sprintf("%s-%s-%s", "555", "867", "5309"),
		fmt.Sprintf("+1 %s-%s-%s", "212", "555", "0100"),
		fmt.Sprintf("%s.%s.%s", "800", "555", "0199"),
		fmt.Sprintf("%s%s%s", "555", "555", "0123"),
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("phone pattern should match %q", tc)
		}
	}
}

func TestUSPhoneTrueNegatives(t *testing.T) {
	cases := []string{
		"12345",
		"abc-def-ghij",
		"12-345-67",
		"not a phone number",
		"123",
	}
	entry := findEntry("US", "us_phone")
	if entry == nil {
		t.Fatal("us_phone entry not found in US pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("phone pattern should NOT match %q", tc)
		}
	}
}

func TestUSPhoneTokenSelfCheck(t *testing.T) {
	entry := findEntry("US", "us_phone")
	if entry == nil {
		t.Fatal("us_phone entry not found in US pack")
	}
	token := "[PII_PHONE_abcdefabcdefabcd]"
	if entry.Re.MatchString(token) {
		t.Errorf("phone pattern must not match its own token: %s", token)
	}
}

func TestUSSSNTruePositives(t *testing.T) {
	entry := findEntry("US", "us_ssn")
	if entry == nil {
		t.Fatal("us_ssn entry not found in US pack")
	}
	cases := []string{
		fmt.Sprintf("%s-%s-%s", "123", "45", "6789"),
		fmt.Sprintf("%s-%s-%s", "987", "65", "4321"),
		fmt.Sprintf("%s-%s-%s", "111", "22", "3333"),
		fmt.Sprintf("%s%s%s", "123", "45", "6789"),
		fmt.Sprintf("%s-%s-%s", "999", "88", "7777"),
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("SSN pattern should match %q", tc)
		}
	}
}

func TestUSSSNTrueNegatives(t *testing.T) {
	cases := []string{
		"12-34-567",
		"12345",
		"1234567",
		"abc-de-fghi",
		"",
	}
	entry := findEntry("US", "us_ssn")
	if entry == nil {
		t.Fatal("us_ssn entry not found in US pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("SSN pattern should NOT match %q", tc)
		}
	}
}

func TestUSSSNTokenSelfCheck(t *testing.T) {
	entry := findEntry("US", "us_ssn")
	if entry == nil {
		t.Fatal("us_ssn entry not found in US pack")
	}
	token := "[PII_SSN_abcdefabcdefabcd]"
	if entry.Re.MatchString(token) {
		t.Errorf("SSN pattern must not match its own token: %s", token)
	}
}

func TestUSIPv4TruePositives(t *testing.T) {
	entry := findEntry("US", "us_ipv4")
	if entry == nil {
		t.Fatal("us_ipv4 entry not found in US pack")
	}
	cases := []string{
		fmt.Sprintf("%d.%d.%d.%d", 192, 168, 1, 1),
		fmt.Sprintf("%d.%d.%d.%d", 10, 0, 0, 1),
		fmt.Sprintf("%d.%d.%d.%d", 172, 16, 0, 1),
		fmt.Sprintf("%d.%d.%d.%d", 8, 8, 8, 8),
		fmt.Sprintf("%d.%d.%d.%d", 255, 255, 255, 0),
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("IPv4 pattern should match %q", tc)
		}
	}
}

func TestUSIPv4TrueNegatives(t *testing.T) {
	cases := []string{
		"999.999.999",
		"not an IP",
		"1.2.3",
		"abc.def.ghi.jkl",
		"",
	}
	entry := findEntry("US", "us_ipv4")
	if entry == nil {
		t.Fatal("us_ipv4 entry not found in US pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("IPv4 pattern should NOT match %q", tc)
		}
	}
}

func TestUSIPv4TokenSelfCheck(t *testing.T) {
	entry := findEntry("US", "us_ipv4")
	if entry == nil {
		t.Fatal("us_ipv4 entry not found in US pack")
	}
	token := "[PII_IP_abcdefabcdefabcd]"
	if entry.Re.MatchString(token) {
		t.Errorf("IPv4 pattern must not match its own token: %s", token)
	}
}

func TestUSAddressTruePositives(t *testing.T) {
	entry := findEntry("US", "us_address")
	if entry == nil {
		t.Fatal("us_address entry not found in US pack")
	}
	cases := []string{
		fmt.Sprintf("%d %s %s", 123, "Main", "Street"),
		fmt.Sprintf("%d %s %s", 456, "Oak", "Avenue"),
		fmt.Sprintf("%d %s %s", 789, "Elm", "Road"),
		fmt.Sprintf("%d %s %s", 100, "Pine", "Boulevard"),
		fmt.Sprintf("%d %s %s", 42, "Maple", "Drive"),
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("address pattern should match %q", tc)
		}
	}
}

func TestUSAddressTrueNegatives(t *testing.T) {
	cases := []string{
		"not an address",
		"123",
		"no street type here",
		"Main Street",
		"42 without suffix",
	}
	entry := findEntry("US", "us_address")
	if entry == nil {
		t.Fatal("us_address entry not found in US pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("address pattern should NOT match %q", tc)
		}
	}
}

func TestUSZipTruePositives(t *testing.T) {
	entry := findEntry("US", "us_zip")
	if entry == nil {
		t.Fatal("us_zip entry not found in US pack")
	}
	cases := []string{
		"90210",
		"10001",
		fmt.Sprintf("%s-%s", "12345", "6789"),
		"55555",
		"00501",
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("ZIP pattern should match %q", tc)
		}
	}
}

func TestUSZipTrueNegatives(t *testing.T) {
	cases := []string{
		"1234",
		"123456",
		"abcde",
		"",
		"1234-",
	}
	entry := findEntry("US", "us_zip")
	if entry == nil {
		t.Fatal("us_zip entry not found in US pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("ZIP pattern should NOT match %q", tc)
		}
	}
}
