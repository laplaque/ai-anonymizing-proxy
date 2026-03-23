package packs

import (
	"strings"
	"testing"
)

func TestGlobalEmailPositives(t *testing.T) {
	entry := findEntry("GLOBAL", "email")
	if entry == nil {
		t.Fatal("email entry not found")
	}
	positives := []string{
		"user@example.com",
		"first.last@domain.co.uk",
		"test+tag@gmail.com",
		"a@b.io",
		"user123@my-domain.org",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestGlobalEmailNegatives(t *testing.T) {
	entry := findEntry("GLOBAL", "email")
	if entry == nil {
		t.Fatal("email entry not found")
	}
	negatives := []string{
		"plaintext",
		"@missing-local.com",
		"missing-at.com",
		"user@",
		"user@.com",
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}

func TestGlobalEmailTokenSelfCheck(t *testing.T) {
	entry := findEntry("GLOBAL", "email")
	if entry == nil {
		t.Fatal("email entry not found")
	}
	token := "[PII_EMAIL_abcdef0123456789]"
	if entry.Re.MatchString(token) {
		t.Errorf("pattern matched its own token: %q", token)
	}
}

func TestGlobalAPIKeyPositives(t *testing.T) {
	entry := findEntry("GLOBAL", "api_key")
	if entry == nil {
		t.Fatal("api_key entry not found")
	}
	positives := []string{
		`api_key: sk-proj-abcdefghij1234567890`,
		`Bearer eyJhbGciOiJIUzI1NiIsI`,
		`token="ghp_abcdefghijklmnop12345"`,
		`secret: my_secret_value_that_is_long_enough`,
		`API-KEY=xoxb-123456789012345678901`,
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestGlobalAPIKeyNegatives(t *testing.T) {
	entry := findEntry("GLOBAL", "api_key")
	if entry == nil {
		t.Fatal("api_key entry not found")
	}
	negatives := []string{
		"just a word",
		"api_key: short",
		"bearer abc",
		"token=x",
		"no keyword here abcdefghij1234567890",
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}

func TestGlobalAPIKeyPreservesPrefix(t *testing.T) {
	entry := findEntry("GLOBAL", "api_key")
	if entry == nil {
		t.Fatal("api_key entry not found")
	}
	if entry.ReplaceGroup != 2 {
		t.Errorf("api_key ReplaceGroup should be 2, got %d", entry.ReplaceGroup)
	}
	input := `Bearer sk-proj-abcdefghij1234567890`
	subs := entry.Re.FindStringSubmatch(input)
	if len(subs) < 3 {
		t.Fatalf("expected 3+ submatches, got %d: %v", len(subs), subs)
	}
	prefix := subs[1]
	value := subs[2]
	if !strings.HasPrefix(prefix, "Bearer") {
		t.Errorf("prefix should start with Bearer, got %q", prefix)
	}
	if value != "sk-proj-abcdefghij1234567890" {
		t.Errorf("value should be the credential, got %q", value)
	}
}

func TestGlobalAPIKeyTokenSelfCheck(t *testing.T) {
	entry := findEntry("GLOBAL", "api_key")
	if entry == nil {
		t.Fatal("api_key entry not found")
	}
	token := "[PII_APIKEY_abcdef0123456789]"
	if entry.Re.MatchString(token) {
		t.Errorf("pattern matched its own token: %q", token)
	}
}

func TestGlobalCreditCardPositives(t *testing.T) {
	entry := findEntry("GLOBAL", "credit_card")
	if entry == nil {
		t.Fatal("credit_card entry not found")
	}
	positives := []string{
		"4111111111111111",
		"4111-1111-1111-1111",
		"4111 1111 1111 1111",
		"5500000000000004",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestGlobalCreditCardNegatives(t *testing.T) {
	entry := findEntry("GLOBAL", "credit_card")
	if entry == nil {
		t.Fatal("credit_card entry not found")
	}
	negatives := []string{
		"1234",
		"123456789012",
		"abcdefghijklmnop",
		"1234-5678",
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}

func TestGlobalCreditCardTokenSelfCheck(t *testing.T) {
	entry := findEntry("GLOBAL", "credit_card")
	if entry == nil {
		t.Fatal("credit_card entry not found")
	}
	token := "[PII_CREDITCARD_abcdef0123456789]"
	if entry.Re.MatchString(token) {
		t.Errorf("pattern matched its own token: %q", token)
	}
}

// findEntry is a test helper that finds a registry entry by pack and name.
func findEntry(pack, name string) *Entry {
	for i := range All() {
		e := &All()[i]
		if e.Pack == pack && e.Name == name {
			return e
		}
	}
	return nil
}
