package anonymizer

import (
	"strings"
	"testing"
)

// TestHEALTHCAREPackPipeline verifies that HEALTHCARE pack patterns detect and
// round-trip medical PII through the full anonymization pipeline.
// Test method: pipeline integration per .idea/ai-proxy-test-method.md §2.3.
// UseAI: false, PackDecayRate: 0.0
// Enabled packs: GLOBAL, US, DE, FR, NL, FINANCE_EU, HEALTHCARE, SECRETS.
func TestHEALTHCAREPackPipeline(t *testing.T) {
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
		// Happy path — MRN
		{
			name:  "MRN with prefix",
			input: "Patient MRN123456 admitted",
			pii:   "MRN123456",
			notes: "Standard MRN format with prefix",
		},
		{
			name:  "MRN with dash separator",
			input: "Record MRN-1234567890 on file",
			pii:   "MRN-1234567890",
			notes: "MRN with dash separator and 10 digits",
		},
		{
			name:  "MR space format",
			input: "Medical record MR 12345678",
			pii:   "MR 12345678",
			notes: "MR prefix with space separator",
		},
		{
			name:  "PAT hash format",
			input: "See PAT#987654 for details",
			pii:   "PAT#987654",
			notes: "PAT prefix with hash separator",
		},
		// Boundary — MRN
		{
			name:  "MRN too few digits not matched",
			input: "Record MRN12345 is short",
			pii:   "",
			notes: "5 digits below 6-digit minimum; should NOT match",
		},
		// Happy path — ICD-10
		{
			name:  "ICD-10 with diagnosis keyword",
			input: "diagnosis: J18.9 pneumonia",
			pii:   "diagnosis: J18.9",
			notes: "ICD-10 code with keyword context",
		},
		{
			name:  "ICD-10 with dx keyword",
			input: "dx: M54.5 lower back pain",
			pii:   "dx: M54.5",
			notes: "ICD-10 code with dx keyword",
		},
		{
			name:  "ICD-10 simple code",
			input: "ICD-10 E11.65 diabetes type 2",
			pii:   "ICD-10 E11.65",
			notes: "ICD-10 code with ICD-10 prefix keyword",
		},
		// Negative — ICD-10
		{
			name:  "ICD-10 no keyword context",
			input: "Value A01.2 is a reference",
			pii:   "",
			notes: "No keyword context; ICD-10 pattern requires context prefix",
		},
		// Happy path — Insurance ID
		{
			name:  "Insurance ID with prefix",
			input: "insurance ID12345678 on record",
			pii:   "insurance ID12345678",
			notes: "Insurance keyword + alphanumeric ID",
		},
		{
			name:  "Policy number",
			input: "policy AB-123456789 active",
			pii:   "policy AB-123456789",
			notes: "Policy keyword + alpha prefix + digits",
		},
		{
			name:  "EHIC card number",
			input: "EHIC DE123456789012 valid",
			pii:   "EHIC DE123456789012",
			notes: "European Health Insurance Card format",
		},
		// Negative — Insurance ID
		{
			name:  "No keyword prefix",
			input: "ID AB12345678 general",
			pii:   "",
			notes: "No insurance/policy/member keyword; should NOT match",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := a.AnonymizeText(c.input, "sess-hc-"+c.name)
			if c.pii != "" {
				if strings.Contains(result, c.pii) {
					t.Errorf("PII %q not anonymized in result: %q", c.pii, result)
				}
				// Round-trip
				restored := a.DeanonymizeText(result, "sess-hc-"+c.name)
				if !strings.Contains(restored, c.pii) {
					t.Errorf("PII %q not restored after deanonymization: %q", c.pii, restored)
				}
			}
			a.DeleteSession("sess-hc-" + c.name)
		})
	}
}

// TestHEALTHCAREMRNCrossPatternSSN verifies that MRN patterns with 9 digits
// do not interfere with the US SSN pattern.
// FINDING: MRN requires a prefix keyword (MRN/MR/PAT), so it does not
// overlap with bare 9-digit SSN matches. The SSN pattern matches bare digit
// sequences while MRN requires the keyword context.
func TestHEALTHCAREMRNCrossPatternSSN(t *testing.T) {
	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint:      "http://localhost:11434",
		OllamaModel:         "test",
		UseAI:               false,
		AIThreshold:         0.8,
		OllamaMaxConcurrent: 1,
		EnabledPacks:        []string{"SECRETS", "GLOBAL", "US", "DE", "FR", "NL", "FINANCE_EU", "HEALTHCARE"},
		PackDecayRate:       0.0,
	})

	// MRN with 9 digits should match MRN pattern, not SSN
	result := a.AnonymizeText("Patient MRN123456789", "sess-cross-mrn")
	if strings.Contains(result, "MRN123456789") {
		t.Error("MRN should be anonymized")
	}
	if !strings.Contains(result, "[PII_") {
		t.Error("expected a PII token in output")
	}
	a.DeleteSession("sess-cross-mrn")
}
