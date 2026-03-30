package anonymizer

import (
	"strings"
	"testing"
)

// TestSecretsPriorityOverGLOBAL verifies that SECRETS patterns match before
// GLOBAL api_key when input contains overlapping keywords (token, secret, bearer).
// This is the regression test for issue #70 (expanded scope).
//
// Pipeline order: SECRETS → GLOBAL → ... (SECRETS runs first).
// UseAI: false, PackDecayRate: 0.0
// Enabled packs: SECRETS, GLOBAL, US, DE, FR, NL, FINANCE_EU, HEALTHCARE.
func TestSecretsPriorityOverGLOBAL(t *testing.T) {
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
		name      string
		input     string
		pii       string // substring that must be anonymized
		wantToken string // expected PII token prefix (e.g. "[PII_GHTOKEN_")
		notes     string
	}

	cases := []tc{
		// --- GitHub token (keyword "Token" would steal via GLOBAL api_key) ---
		{
			name:      "ghtoken with Token keyword",
			input:     "Token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			pii:       "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			wantToken: "[PII_GHTOKEN_",
			notes:     "issue #70: 'Token' keyword must not steal ghp_ match from SECRETS",
		},
		{
			name:      "ghtoken without keyword",
			input:     "Commit ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij vom Entwickler",
			pii:       "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			wantToken: "[PII_GHTOKEN_",
			notes:     "no keyword — SECRETS github_token should still claim it",
		},

		// --- JWT (keyword "token" would steal via GLOBAL api_key) ---
		{
			name:      "jwt with token keyword",
			input:     "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			pii:       "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			wantToken: "[PII_JWT_",
			notes:     "issue #70 expanded: 'token' keyword must not steal JWT match",
		},
		{
			name:      "jwt without keyword",
			input:     "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			pii:       "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			wantToken: "[PII_JWT_",
			notes:     "no keyword — SECRETS jwt should claim it",
		},

		// --- AWS access key (keyword "secret" would steal via GLOBAL api_key) ---
		{
			name:      "aws key with secret keyword",
			input:     "secret: AKIAIOSFODNN7EXAMPLE",
			pii:       "AKIAIOSFODNN7EXAMPLE",
			wantToken: "[PII_AWSKEY_",
			notes:     "issue #70 expanded: 'secret' keyword must not steal AWS key match",
		},
		{
			name:      "aws key without keyword",
			input:     "AKIAIOSFODNN7EXAMPLE",
			pii:       "AKIAIOSFODNN7EXAMPLE",
			wantToken: "[PII_AWSKEY_",
			notes:     "no keyword — SECRETS aws_access_key should claim it",
		},

		// --- DB connection string (keyword "secret" would steal via GLOBAL api_key) ---
		{
			name:      "db conn with secret keyword",
			input:     "secret: postgres://admin:s3cret@db.host:5432/mydb",
			pii:       "postgres://admin:s3cret@db.host:5432/mydb",
			wantToken: "[PII_DBCONN_",
			notes:     "issue #70 expanded: 'secret' keyword must not steal DB connection string",
		},

		// --- Bearer token (keyword "bearer" would steal via GLOBAL api_key) ---
		{
			name:      "bearer token with bearer keyword",
			input:     "bearer abc123def456ghi789jklmno",
			pii:       "abc123def456ghi789jklmno",
			wantToken: "[PII_BEARER_",
			notes:     "issue #70 expanded: 'bearer' keyword must not steal bearer token match",
		},

		// --- sk- tokens now match SECRETS openai_key (issue #77) ---
		{
			name:      "sk- token claimed by openai_key",
			input:     "token: sk-abc123def456ghi789jklmno",
			pii:       "sk-abc123def456ghi789jklmno",
			wantToken: "[PII_OPENAIKEY_",
			notes:     "sk- prefix with 20+ chars is now claimed by SECRETS openai_key (issue #77)",
		},
		// --- GLOBAL api_key must still work for non-SECRETS tokens ---
		{
			name:      "api_key with api_key keyword",
			input:     "api_key=abc123def456ghi789jklmno",
			pii:       "abc123def456ghi789jklmno",
			wantToken: "[PII_APIKEY_",
			notes:     "api_key keyword — GLOBAL should claim it",
		},
		{
			name:      "api_key with secret keyword non-secrets",
			input:     "secret=my_custom_long_token_value_here",
			pii:       "my_custom_long_token_value_here",
			wantToken: "[PII_APIKEY_",
			notes:     "generic secret with no SECRETS-specific prefix — GLOBAL api_key should claim it",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sessID := "sess-secrets-prio-" + c.name
			result := a.AnonymizeText(c.input, sessID)

			if strings.Contains(result, c.pii) {
				t.Errorf("PII %q not anonymized in result: %q", c.pii, result)
			}

			if !strings.Contains(result, c.wantToken) {
				t.Errorf("expected %s token in result, got: %q", c.wantToken, result)
			}

			// Round-trip: deanonymize and verify original PII is restored.
			restored := a.DeanonymizeText(result, sessID)
			if !strings.Contains(restored, c.pii) {
				t.Errorf("PII %q not restored after deanonymization: %q", c.pii, restored)
			}

			a.DeleteSession(sessID)
		})
	}
}

// TestLoadPacksRespectsEnabledPacksOrder verifies that loadPacks iterates in
// enabledPacks order, not init() registration order.
func TestLoadPacksRespectsEnabledPacksOrder(t *testing.T) {
	// SECRETS first — SECRETS patterns should appear before GLOBAL patterns.
	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint:      "http://localhost:11434",
		OllamaModel:         "test",
		UseAI:               false,
		AIThreshold:         0.8,
		OllamaMaxConcurrent: 1,
		EnabledPacks:        []string{"SECRETS", "GLOBAL"},
		PackDecayRate:       0.0,
	})

	firstPack := ""
	for _, p := range a.patterns {
		firstPack = p.pack
		break
	}
	if firstPack != "SECRETS" {
		t.Errorf("expected first pattern to be from SECRETS pack, got %q", firstPack)
	}

	// Verify SECRETS patterns all come before any GLOBAL pattern.
	seenGlobal := false
	for _, p := range a.patterns {
		if p.pack == "GLOBAL" {
			seenGlobal = true
		}
		if p.pack == "SECRETS" && seenGlobal {
			t.Error("SECRETS pattern found after GLOBAL pattern — loadPacks does not respect enabledPacks order")
			break
		}
	}
}
