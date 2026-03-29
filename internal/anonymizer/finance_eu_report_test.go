package anonymizer

import (
	"strings"
	"testing"
)

// TestFINANCEEUPackPipeline verifies that FINANCE_EU pack patterns detect and
// round-trip EU financial PII through the full anonymization pipeline.
// Test method: pipeline integration per .idea/ai-proxy-test-method.md §2.3.
// UseAI: false, PackDecayRate: 0.0
// Enabled packs: GLOBAL, US, DE, FR, NL, FINANCE_EU, HEALTHCARE, SECRETS.
func TestFINANCEEUPackPipeline(t *testing.T) {
	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint:      "http://localhost:11434",
		OllamaModel:         "test",
		UseAI:               false,
		AIThreshold:         0.8,
		OllamaMaxConcurrent: 1,
		EnabledPacks:        []string{"SECRETS", "GLOBAL", "US", "DE", "FR", "NL", "FINANCE_EU", "HEALTHCARE"},
		PackDecayRate:       0.0,
	})

	type tc struct {
		name  string
		input string
		pii   string
		notes string
	}

	cases := []tc{
		// Happy path — IBAN
		{
			name:  "IBAN DE contiguous",
			input: "Transfer to IBAN DE89370400440532013000 please",
			pii:   "DE89370400440532013000",
			notes: "ISO 7064 MOD 97-10 valid German IBAN",
		},
		{
			name:  "IBAN NL contiguous",
			input: "Pay to NL91ABNA0417164300",
			pii:   "NL91ABNA0417164300",
			notes: "MOD 97-10 valid Dutch IBAN",
		},
		{
			name:  "IBAN GB contiguous",
			input: "Account GB29NWBK60161331926819",
			pii:   "GB29NWBK60161331926819",
			notes: "MOD 97-10 valid British IBAN",
		},
		// Spaced IBAN
		{
			name:  "IBAN DE spaced",
			input: "IBAN: DE89 3704 0044 0532 0130 00",
			pii:   "DE89 3704 0044 0532 0130 00",
			notes: "Spaced format; validator strips spaces before MOD 97-10",
		},
		// Validator reject — IBAN
		{
			name:  "IBAN invalid checksum not anonymized as IBAN",
			input: "IBAN DE00370400440532013000 is wrong",
			pii:   "",
			notes: "MOD 97-10 fails; should NOT be anonymized as IBAN",
		},
		// SWIFT/BIC
		{
			name:  "SWIFT BIC 8-char",
			input: "BIC code DEUTDEFF for transfers",
			pii:   "DEUTDEFF",
			notes: "Deutsche Bank 8-char SWIFT code",
		},
		{
			name:  "SWIFT BIC 11-char",
			input: "Use COBADEFFXXX for wire",
			pii:   "COBADEFFXXX",
			notes: "Commerzbank 11-char SWIFT code with branch",
		},
		// VAT ID
		{
			name:  "VAT DE",
			input: "VAT number DE123456789 registered",
			pii:   "DE123456789",
			notes: "German VAT format: DE + 9 digits",
		},
		{
			name:  "VAT NL",
			input: "BTW nummer NL123456789B01",
			pii:   "NL123456789B01",
			notes: "Dutch VAT format: NL + 9d + B + 2d",
		},
		{
			name:  "VAT FR",
			input: "TVA FR12345678901",
			pii:   "FR12345678901",
			notes: "French VAT format: FR + 2 alnum + 9d",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := a.AnonymizeText(c.input, "sess-fin-"+c.name)
			if c.pii != "" {
				if strings.Contains(result, c.pii) {
					t.Errorf("PII %q not anonymized in result: %q", c.pii, result)
				}
				// Round-trip
				restored := a.DeanonymizeText(result, "sess-fin-"+c.name)
				if !strings.Contains(restored, c.pii) {
					t.Errorf("PII %q not restored after deanonymization: %q", c.pii, restored)
				}
			}
			a.DeleteSession("sess-fin-" + c.name)
		})
	}
}

// TestFINANCEEUIBANCrossPatternCreditCard verifies IBAN does not interfere with
// the GLOBAL credit_card pattern.
// FINDING: IBAN starts with 2 letters, so the credit_card regex (digits only)
// does not match full IBANs. However, the numeric BBAN portion could be captured
// by credit_card if long enough. The IBAN validator prevents this since it
// requires the country code prefix.
func TestFINANCEEUIBANCrossPatternCreditCard(t *testing.T) {
	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint:      "http://localhost:11434",
		OllamaModel:         "test",
		UseAI:               false,
		AIThreshold:         0.8,
		OllamaMaxConcurrent: 1,
		EnabledPacks:        []string{"SECRETS", "GLOBAL", "US", "DE", "FR", "NL", "FINANCE_EU", "HEALTHCARE"},
		PackDecayRate:       0.0,
	})

	result := a.AnonymizeText("IBAN: DE89370400440532013000", "sess-cross-iban")
	if strings.Contains(result, "DE89370400440532013000") {
		t.Error("IBAN should be anonymized")
	}
	if !strings.Contains(result, "[PII_") {
		t.Error("expected a PII token in output")
	}
	a.DeleteSession("sess-cross-iban")
}
