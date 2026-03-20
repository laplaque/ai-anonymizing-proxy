package packs

import (
	"fmt"
	"testing"
)

func TestGlobalEmailTruePositives(t *testing.T) {
	cases := []string{
		"user@example.com",
		"test.name@domain.org",
		"first+tag@sub.domain.co.uk",
		"user123@test-domain.com",
		"a@b.io",
	}
	entry := findEntry("GLOBAL", "email")
	if entry == nil {
		t.Fatal("email entry not found in GLOBAL pack")
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("email pattern should match %q", tc)
		}
	}
}

func TestGlobalEmailTrueNegatives(t *testing.T) {
	cases := []string{
		"not-an-email",
		"@missinglocal.com",
		"missing@.com",
		"spaces in local@part not valid",
		"no-tld@example",
	}
	entry := findEntry("GLOBAL", "email")
	if entry == nil {
		t.Fatal("email entry not found in GLOBAL pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("email pattern should NOT match %q", tc)
		}
	}
}

func TestGlobalEmailTokenSelfCheck(t *testing.T) {
	entry := findEntry("GLOBAL", "email")
	if entry == nil {
		t.Fatal("email entry not found in GLOBAL pack")
	}
	token := "[PII_EMAIL_abcdefabcdefabcd]"
	if entry.Re.MatchString(token) {
		t.Errorf("email pattern must not match its own token: %s", token)
	}
}

func TestGlobalAPIKeyTruePositives(t *testing.T) {
	cases := []string{
		`api_key = "sk-abcdefghijklmnopqrstuv"`,
		`token: "ghp_abcdefghijabcdefghij"`,
		`secret="very-long-secret-key-value-here"`,
		`bearer "aBcDeFgHiJkLmNoPqRsTu123"`,
		`API-KEY:"myTokenValueHereAbcdefgh"`,
	}
	entry := findEntry("GLOBAL", "api_key")
	if entry == nil {
		t.Fatal("api_key entry not found in GLOBAL pack")
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("api_key pattern should match %q", tc)
		}
	}
}

func TestGlobalAPIKeyTrueNegatives(t *testing.T) {
	cases := []string{
		"no keywords here",
		"api_key = short",
		"random text without key markers",
		`function(api) { return 42 }`,
		"the word token alone",
	}
	entry := findEntry("GLOBAL", "api_key")
	if entry == nil {
		t.Fatal("api_key entry not found in GLOBAL pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("api_key pattern should NOT match %q", tc)
		}
	}
}

func TestGlobalAPIKeyTokenSelfCheck(t *testing.T) {
	entry := findEntry("GLOBAL", "api_key")
	if entry == nil {
		t.Fatal("api_key entry not found in GLOBAL pack")
	}
	token := "[PII_APIKEY_abcdefabcdefabcd]"
	if entry.Re.MatchString(token) {
		t.Errorf("api_key pattern must not match its own token: %s", token)
	}
}

func TestGlobalCreditCardTruePositives(t *testing.T) {
	cases := []string{
		fmt.Sprintf("%s-%s-%s-%s", "4111", "1111", "1111", "1111"),
		fmt.Sprintf("%s %s %s %s", "5500", "0000", "0000", "0004"),
		fmt.Sprintf("%s%s%s%s", "4012", "8888", "8888", "1881"),
		fmt.Sprintf("%s-%s-%s-%s", "6011", "1111", "1111", "1117"),
		fmt.Sprintf("%s %s %s %s", "4111", "1111", "1111", "1111"),
	}
	entry := findEntry("GLOBAL", "credit_card")
	if entry == nil {
		t.Fatal("credit_card entry not found in GLOBAL pack")
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("credit_card pattern should match %q", tc)
		}
	}
}

func TestGlobalCreditCardTrueNegatives(t *testing.T) {
	cases := []string{
		"1234",
		"1234-5678",
		"not a number at all",
		"12345678901",
		"abcd-efgh-ijkl-mnop",
	}
	entry := findEntry("GLOBAL", "credit_card")
	if entry == nil {
		t.Fatal("credit_card entry not found in GLOBAL pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("credit_card pattern should NOT match %q", tc)
		}
	}
}

func TestGlobalCreditCardTokenSelfCheck(t *testing.T) {
	entry := findEntry("GLOBAL", "credit_card")
	if entry == nil {
		t.Fatal("credit_card entry not found in GLOBAL pack")
	}
	token := "[PII_CC_abcdefabcdefabcd]"
	if entry.Re.MatchString(token) {
		t.Errorf("credit_card pattern must not match its own token: %s", token)
	}
}

// findEntry locates a registered entry by pack and name.
func findEntry(pack, name string) *Entry {
	for i := range registry {
		if registry[i].Pack == pack && registry[i].Name == name {
			return &registry[i]
		}
	}
	return nil
}
