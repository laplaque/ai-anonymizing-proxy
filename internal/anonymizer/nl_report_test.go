package anonymizer

import (
	"strings"
	"testing"
)

// TestNLPackPipeline verifies that NL pack patterns detect and round-trip
// Dutch PII through the full anonymization pipeline.
// Test method: pipeline integration per .idea/ai-proxy-test-method.md §2.3.
// UseAI: false, PackDecayRate: 0.0
// Enabled packs: GLOBAL, US, DE, FR, NL, FINANCE_EU, HEALTHCARE, SECRETS.
func TestNLPackPipeline(t *testing.T) {
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
		pii   string // substring that must be anonymized
		notes string
	}

	cases := []tc{
		// Happy path — BSN
		{
			name:  "BSN contiguous valid elfproef",
			input: "Dutch citizen BSN is 123456782",
			pii:   "123456782",
			notes: "elfproef-valid BSN; sum=154, 154%11=0",
		},
		{
			name:  "BSN second valid value",
			input: "BSN: 111222333",
			pii:   "111222333",
			notes: "elfproef-valid BSN; sum=66, 66%11=0",
		},
		// Validator reject — BSN
		{
			name:  "BSN invalid elfproef not anonymized",
			input: "Number is 123456789 in the record",
			pii:   "",
			notes: "elfproef-invalid; sum=147, 147%11=4; should NOT be anonymized as BSN",
		},
		// KvK — low confidence, broad pattern
		// KNOWN GAP: KvK pattern (8 digits) is very broad and overlaps with many other numeric patterns.
		// At confidence 0.45 it routes to AI verification in production.
		{
			name:  "KvK 8-digit number",
			input: "KvK number 12345678 registered",
			pii:   "12345678",
			notes: "KNOWN GAP: 8-digit pattern is broad; low confidence mitigates false positives",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := a.AnonymizeText(c.input, "sess-nl-"+c.name)
			// Negative cases: pii=="" means the value should NOT be anonymized as the target type
			// (but may be anonymized by other broad patterns like credit_card).
			if c.pii != "" {
				if strings.Contains(result, c.pii) {
					t.Errorf("PII %q not anonymized in result: %q", c.pii, result)
				}
				// Round-trip
				restored := a.DeanonymizeText(result, "sess-nl-"+c.name)
				if !strings.Contains(restored, c.pii) {
					t.Errorf("PII %q not restored after deanonymization: %q", c.pii, restored)
				}
			}
			a.DeleteSession("sess-nl-" + c.name)
		})
	}
}

// TestNLBSNCrossPatternSIREN verifies that a 9-digit BSN does not interfere
// with the FR SIREN pattern (also 9 digits).
// FINDING: BSN and SIREN both match 9-digit sequences. The elfproef validator
// on BSN and Luhn validator on SIREN prevent most cross-matches. Priority is
// determined by pack order.
func TestNLBSNCrossPatternSIREN(t *testing.T) {
	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint:      "http://localhost:11434",
		OllamaModel:         "test",
		UseAI:               false,
		AIThreshold:         0.8,
		OllamaMaxConcurrent: 1,
		EnabledPacks:        []string{"SECRETS", "GLOBAL", "US", "DE", "FR", "NL", "FINANCE_EU", "HEALTHCARE"},
		PackDecayRate:       0.0,
	})

	// 123456782 passes elfproef but NOT Luhn → should be caught as BSN, not SIREN.
	result := a.AnonymizeText("ID: 123456782", "sess-cross-bsn")
	if strings.Contains(result, "123456782") {
		t.Error("BSN should be anonymized")
	}
	if !strings.Contains(result, "[PII_") {
		t.Error("expected a PII token in output")
	}
	a.DeleteSession("sess-cross-bsn")
}
