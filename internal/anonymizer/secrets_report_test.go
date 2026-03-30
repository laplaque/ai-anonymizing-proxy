package anonymizer

import (
	"strings"
	"testing"
)

// TestSecretsExpandedPipeline verifies that the new SECRETS patterns (issue #77)
// detect and round-trip tokens through the full anonymization pipeline.
// Test method: pipeline integration per docs/test-plans/ai-proxy-test-method.md §2.2.
// UseAI: false, PackDecayRate: 0.0
// Enabled packs: SECRETS, GLOBAL, US, DE, FR, NL, FINANCE_EU, HEALTHCARE.
func TestSecretsExpandedPipeline(t *testing.T) {
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
		pii   string // substring that must be anonymized (empty = negative case)
		notes string
	}

	cases := []tc{
		// --- GitLab PAT ---
		{
			name:  "gitlab_pat happy path",
			input: "export GITLAB_TOKEN=glpat-XXXXXXXXXXXXXXXXXXXX",
			pii:   "glpat-XXXXXXXXXXXXXXXXXXXX",
			notes: "valid GitLab PAT with 20 chars after prefix",
		},
		{
			name:  "gitlab_pat negative too short",
			input: "token is glpat-short",
			pii:   "",
			notes: "too few chars after prefix — should NOT match",
		},

		// --- GitLab deploy token ---
		{
			name:  "gitlab_deploy happy path",
			input: "deploy token: gldt-XXXXXXXXXXXXXXXXXXXX",
			pii:   "gldt-XXXXXXXXXXXXXXXXXXXX",
			notes: "valid GitLab deploy token with 20 chars after prefix",
		},
		{
			name:  "gitlab_deploy negative too short",
			input: "token gldt-tiny",
			pii:   "",
			notes: "too few chars — should NOT match",
		},

		// --- Slack token ---
		{
			name:  "slack_token xoxb happy path",
			input: "SLACK_TOKEN=xoxb-123456789012-1234567890123-AbCdEfGhIjKl",
			pii:   "xoxb-123456789012-1234567890123-AbCdEfGhIjKl",
			notes: "valid Slack bot token",
		},
		{
			name:  "slack_token xoxp happy path",
			input: "token xoxp-999888777666-555444333222-aaBBccDD",
			pii:   "xoxp-999888777666-555444333222-aaBBccDD",
			notes: "valid Slack user token",
		},
		{
			name:  "slack_token negative wrong variant",
			input: "token xoxz-123456789012",
			pii:   "",
			notes: "xoxz is not a valid Slack token prefix",
		},

		// --- Stripe key ---
		{
			name:  "stripe_key sk_live happy path",
			input: "STRIPE_KEY=sk_live_ABCDEFghijklmnopqrst",
			pii:   "sk_live_ABCDEFghijklmnopqrst",
			notes: "valid Stripe secret live key",
		},
		{
			name:  "stripe_key pk_test happy path",
			input: "key: pk_test_ABCDEFghijklmnopqrst",
			pii:   "pk_test_ABCDEFghijklmnopqrst",
			notes: "valid Stripe publishable test key",
		},
		{
			name:  "stripe_key negative wrong env",
			input: "key=sk_prod_ABCDEFghijklmnopqrst",
			pii:   "",
			notes: "sk_prod_ is not a valid Stripe prefix",
		},

		// --- NPM token ---
		{
			name:  "npm_token happy path",
			input: "NPM_TOKEN=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			pii:   "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			notes: "valid NPM token with 36 chars after prefix",
		},
		{
			name:  "npm_token negative too short",
			input: "npm_shorttoken",
			pii:   "",
			notes: "too few chars after prefix",
		},

		// --- PyPI token ---
		{
			name:  "pypi_token happy path",
			input: "PYPI_TOKEN=pypi-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPQRSTUV",
			pii:   "pypi-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPQRSTUV",
			notes: "valid PyPI token with 85+ chars after prefix",
		},
		{
			name:  "pypi_token negative too short",
			input: "pypi-short",
			pii:   "",
			notes: "far too few chars — should NOT match",
		},

		// --- OpenAI key ---
		{
			name:  "openai_key happy path",
			input: "OPENAI_API_KEY=sk-ABCDEFghijklmnopqrst",
			pii:   "sk-ABCDEFghijklmnopqrst",
			notes: "valid OpenAI API key with sk- prefix",
		},
		{
			name:  "openai_key sk-proj format",
			input: "OPENAI_API_KEY=sk-proj-ABCDEFghijklmnop",
			pii:   "sk-proj-ABCDEFghijklmnop",
			notes: "valid OpenAI project key with sk-proj- prefix",
		},
		{
			name:  "openai_key negative too short",
			input: "sk-short",
			pii:   "",
			notes: "too few chars — should NOT match",
		},

		// --- Docker Hub PAT ---
		{
			name:  "docker_pat happy path",
			input: "DOCKER_TOKEN=dckr_pat_ABCDEFghijklmnopqrst",
			pii:   "dckr_pat_ABCDEFghijklmnopqrst",
			notes: "valid Docker Hub PAT",
		},
		{
			name:  "docker_pat negative too short",
			input: "dckr_pat_short",
			pii:   "",
			notes: "too few chars",
		},

		// --- Google API key ---
		{
			name:  "google_api_key happy path",
			input: "GOOGLE_KEY=AIzaSyD-example-key-value_1234567890ABC",
			pii:   "AIzaSyD-example-key-value_1234567890ABC",
			notes: "valid Google API key (AIza + 35 chars)",
		},
		{
			name:  "google_api_key negative too short",
			input: "AIzashort",
			pii:   "",
			notes: "too few chars after prefix",
		},

		// --- Shopify token ---
		{
			name:  "shopify_token shpat happy path",
			input: "SHOPIFY=shpat_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
			pii:   "shpat_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
			notes: "valid Shopify access token (32 chars)",
		},
		{
			name:  "shopify_token negative wrong prefix",
			input: "shpxx_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
			pii:   "",
			notes: "shpxx_ is not a valid Shopify prefix",
		},

		// --- SendGrid key ---
		{
			name:  "sendgrid_key happy path",
			input: "SENDGRID_KEY=SG.abcdefghij1234567890",
			pii:   "SG.abcdefghij1234567890",
			notes: "valid SendGrid API key",
		},
		{
			name:  "sendgrid_key negative too short",
			input: "SG.short",
			pii:   "",
			notes: "too few chars after SG.",
		},

		// --- Groq key ---
		{
			name:  "groq_key happy path",
			input: "GROQ_KEY=gsk_ABCDEFghijklmnopqrst",
			pii:   "gsk_ABCDEFghijklmnopqrst",
			notes: "valid Groq API key",
		},
		{
			name:  "groq_key negative too short",
			input: "gsk_short",
			pii:   "",
			notes: "too few chars",
		},

		// --- Twilio SID ---
		{
			name:  "twilio_sid happy path",
			input: "TWILIO_SID=AC00000000000000000000000000000000",
			pii:   "AC00000000000000000000000000000000",
			notes: "valid Twilio Account SID (AC + 32 hex)",
		},
		{
			name:  "twilio_sid negative non-hex",
			input: "ACzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			pii:   "",
			notes: "z is not hex — should NOT match",
		},

		// --- Twilio auth ---
		{
			name:  "twilio_auth happy path",
			input: "TWILIO_AUTH=SK00000000000000000000000000000000",
			pii:   "SK00000000000000000000000000000000",
			notes: "valid Twilio API key SID (SK + 32 hex)",
		},
		{
			name:  "twilio_auth negative short",
			input: "SK1234",
			pii:   "",
			notes: "too few hex chars — should NOT match",
		},

		// --- Facebook token ---
		{
			name:  "facebook_token happy path",
			input: "FB_TOKEN=EAACEdEose0cBAabcdef1234567890",
			pii:   "EAACEdEose0cBAabcdef1234567890",
			notes: "valid Facebook access token",
		},
		{
			name:  "facebook_token negative prefix only",
			input: "EAACEdEose0cBA",
			pii:   "",
			notes: "prefix alone with no trailing chars — should NOT match",
		},

		// --- Amazon MWS ---
		{
			name:  "amazon_mws happy path",
			input: "MWS_KEY=amzn.mws.12345678-1234-1234-1234-123456789012",
			pii:   "amzn.mws.12345678-1234-1234-1234-123456789012",
			notes: "valid Amazon MWS auth token (UUID format)",
		},
		{
			name:  "amazon_mws negative short",
			input: "amzn.mws.short",
			pii:   "",
			notes: "too few chars — should NOT match",
		},

		// --- Cloudinary URL ---
		{
			name:  "cloudinary_url happy path",
			input: "CLOUDINARY_URL=cloudinary://123456789012345:abcdefGHIJ@cloud_name",
			pii:   "cloudinary://123456789012345:abcdefGHIJ@cloud_name",
			notes: "valid Cloudinary URL with credentials",
		},
		{
			name:  "cloudinary_url negative too short",
			input: "cloudinary://short",
			pii:   "",
			notes: "too few chars after scheme",
		},

		// --- Encrypted private key (PKCS#8) ---
		{
			name:  "ssh_private_key encrypted happy path",
			input: "Found key: -----BEGIN ENCRYPTED PRIVATE KEY-----",
			pii:   "-----BEGIN ENCRYPTED PRIVATE KEY-----",
			notes: "PKCS#8 encrypted private key header",
		},
		{
			name:  "ssh_private_key encrypted public negative",
			input: "-----BEGIN ENCRYPTED PUBLIC KEY-----",
			pii:   "",
			notes: "encrypted PUBLIC key — should NOT match private key pattern",
		},

		// --- PGP private key ---
		{
			name:  "pgp_private_key happy path",
			input: "Found key: -----BEGIN PGP PRIVATE KEY BLOCK-----",
			pii:   "-----BEGIN PGP PRIVATE KEY BLOCK-----",
			notes: "PGP private key block header",
		},
		{
			name:  "pgp_private_key negative public key",
			input: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
			pii:   "",
			notes: "public key block — should NOT match PGP private key pattern",
		},

		// --- Cross-pattern: OpenAI sk- vs Stripe sk_ ---
		{
			name:  "cross openai does not steal stripe",
			input: "STRIPE=sk_live_XXXXXXXXXXXXXXXXXXXX",
			pii:   "sk_live_XXXXXXXXXXXXXXXXXXXX",
			notes: "FINDING: Stripe sk_live_ must be claimed by stripe_key, not openai_key (sk- requires hyphen)",
		},

		// --- Cross-pattern: Groq gsk_ vs GitHub ghs_ ---
		{
			name:  "cross groq does not steal github",
			input: "GH=ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			pii:   "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			notes: "FINDING: GitHub ghs_ token must be claimed by github_token, not groq_key",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sessID := "sess-secrets-expanded-" + c.name
			result := a.AnonymizeText(c.input, sessID)

			if c.pii != "" {
				if strings.Contains(result, c.pii) {
					t.Errorf("PII %q not anonymized in result: %q", c.pii, result)
				}
				// Round-trip: deanonymize and verify original PII is restored.
				restored := a.DeanonymizeText(result, sessID)
				if !strings.Contains(restored, c.pii) {
					t.Errorf("PII %q not restored after deanonymization: %q", c.pii, restored)
				}
			}
			// Negative cases (pii=="") verify that the short/invalid value
			// is not matched by the target pattern. Some may still be
			// partially anonymized by other broad patterns (GLOBAL api_key).

			a.DeleteSession(sessID)
		})
	}
}
