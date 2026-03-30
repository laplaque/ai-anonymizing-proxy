package packs

import "testing"

func TestSecretsPackRegistered(t *testing.T) {
	entries := All()
	packEntries := filterPack(entries, "SECRETS")
	if len(packEntries) == 0 {
		t.Fatal("SECRETS pack has no registered entries")
	}

	names := make(map[string]bool)
	for _, e := range packEntries {
		names[e.Name] = true
	}
	for _, want := range []string{
		"ssh_private_key", "jwt", "bearer_token", "db_connection_string", "aws_access_key", "github_token",
		"gitlab_pat", "gitlab_deploy", "slack_token", "stripe_key", "npm_token", "pypi_token", "openai_key",
		"docker_pat", "google_api_key", "shopify_token", "sendgrid_key", "groq_key", "twilio_sid", "twilio_auth",
		"facebook_token", "amazon_mws", "cloudinary_url", "pgp_private_key",
	} {
		if !names[want] {
			t.Errorf("SECRETS pack missing pattern %q", want)
		}
	}
}

func TestSecretsSSHKeyPattern(t *testing.T) {
	entry := findEntry("ssh_private_key", "SECRETS")
	if entry == nil {
		t.Fatal("ssh_private_key entry not found in SECRETS pack")
	}

	positives := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("ssh_private_key pattern should match %q", s)
		}
	}

	negatives := []string{
		"-----BEGIN PUBLIC KEY-----",
		"-----BEGIN CERTIFICATE-----",
	}
	for _, s := range negatives {
		if entry.Re.MatchString(s) {
			t.Errorf("ssh_private_key pattern should NOT match %q", s)
		}
	}
}

func TestSecretsJWTPattern(t *testing.T) {
	entry := findEntry("jwt", "SECRETS")
	if entry == nil {
		t.Fatal("jwt entry not found in SECRETS pack")
	}

	// Synthetic JWT — three base64url segments starting with eyJ.
	valid := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	if !entry.Re.MatchString(valid) {
		t.Error("jwt pattern should match valid JWT")
	}

	// Not a JWT — wrong prefix.
	if entry.Re.MatchString("abc.def.ghi") {
		t.Error("jwt pattern should NOT match non-JWT")
	}
}

func TestSecretsBearerPattern(t *testing.T) {
	entry := findEntry("bearer_token", "SECRETS")
	if entry == nil {
		t.Fatal("bearer_token entry not found in SECRETS pack")
	}

	if !entry.Re.MatchString("Bearer sk-abc123def456ghi789jkl012mno") {
		t.Error("bearer pattern should match Bearer token")
	}

	if entry.Re.MatchString("Bearer short") {
		t.Error("bearer pattern should NOT match short token")
	}
}

func TestSecretsDBConnPattern(t *testing.T) {
	entry := findEntry("db_connection_string", "SECRETS")
	if entry == nil {
		t.Fatal("db_connection_string entry not found in SECRETS pack")
	}

	positives := []string{
		"postgresql://user:pass@localhost:5432/mydb",
		"mysql://root:secret@db.example.com:3306/app",
		"mongodb+srv://admin:pwd@cluster.mongodb.net/db",
		"redis://default:pass@redis.host:6379",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("db_connection_string pattern should match %q", s)
		}
	}
}

func TestSecretsAWSKeyPattern(t *testing.T) {
	entry := findEntry("aws_access_key", "SECRETS")
	if entry == nil {
		t.Fatal("aws_access_key entry not found in SECRETS pack")
	}

	// Synthetic AWS key: AKIA + 16 uppercase alphanumeric.
	if !entry.Re.MatchString("AKIAIOSFODNN7EXAMPLE") {
		t.Error("aws_access_key pattern should match valid AWS key")
	}

	if entry.Re.MatchString("ASIA12345678901234") {
		t.Error("aws_access_key pattern should NOT match non-AKIA prefix")
	}
}

func TestSecretsGitHubTokenPattern(t *testing.T) {
	entry := findEntry("github_token", "SECRETS")
	if entry == nil {
		t.Fatal("github_token entry not found in SECRETS pack")
	}

	// Synthetic GitHub PAT: ghp_ + 36 alnum.
	if !entry.Re.MatchString("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij") {
		t.Error("github_token pattern should match valid GitHub PAT")
	}
}

// --- New pattern tests ---

func TestSecretsGitLabPATPattern(t *testing.T) {
	entry := findEntry("gitlab_pat", "SECRETS")
	if entry == nil {
		t.Fatal("gitlab_pat entry not found")
	}

	positives := []string{
		"glpat-XXXXXXXXXXXXXXXXXXXX",     // exactly 20 chars after prefix
		"glpat-YYYYYYYYYYYYYYYYYYYYYYYY", // 24 chars
		"glpat-XXX_XXX-XXX_XXX_XXXX_XXX", // with underscores and hyphens
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("gitlab_pat should match %q", s)
		}
	}

	negatives := []string{
		"glpat-short",                 // too short (<20)
		"glXat-ABCDEFghijklmnopqrst",  // wrong prefix
		"xglpat-XXXXXXXXXXXXXXXXXXXX", // prefix not at word boundary
	}
	for _, s := range negatives {
		if entry.Re.MatchString(s) {
			t.Errorf("gitlab_pat should NOT match %q", s)
		}
	}
}

func TestSecretsGitLabDeployPattern(t *testing.T) {
	entry := findEntry("gitlab_deploy", "SECRETS")
	if entry == nil {
		t.Fatal("gitlab_deploy entry not found")
	}

	if !entry.Re.MatchString("gldt-XXXXXXXXXXXXXXXXXXXX") {
		t.Error("gitlab_deploy should match valid deploy token")
	}
	if entry.Re.MatchString("gldt-short") {
		t.Error("gitlab_deploy should NOT match short token")
	}
}

func TestSecretsSlackTokenPattern(t *testing.T) {
	entry := findEntry("slack_token", "SECRETS")
	if entry == nil {
		t.Fatal("slack_token entry not found")
	}

	positives := []string{
		"xoxb-123456789012-1234567890123-abcDefGhiJkl",
		"xoxp-999888777666-555444333222-aaBBccDD",
		"xoxa-2-1234567890-1234567890123",
		"xoxr-555666777888-abcdef",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("slack_token should match %q", s)
		}
	}

	negatives := []string{
		"xoxz-123456789012", // wrong variant letter
		"xox-123456789012",  // missing variant letter
	}
	for _, s := range negatives {
		if entry.Re.MatchString(s) {
			t.Errorf("slack_token should NOT match %q", s)
		}
	}
}

func TestSecretsStripeKeyPattern(t *testing.T) {
	entry := findEntry("stripe_key", "SECRETS")
	if entry == nil {
		t.Fatal("stripe_key entry not found")
	}

	positives := []string{
		"sk_live_ABCDEFghijklmnopqrst",
		"sk_test_ABCDEFghijklmnopqrst",
		"pk_live_ABCDEFghijklmnopqrst",
		"pk_test_ABCDEFghijklmnopqrst",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("stripe_key should match %q", s)
		}
	}

	negatives := []string{
		"sk_prod_ABCDEFghijklmnopqrst",  // wrong environment
		"sk_live_short",                 // too short
		"sk-ABCDEFghijklmnopqrstuvwxyz", // OpenAI format (hyphen not underscore)
	}
	for _, s := range negatives {
		if entry.Re.MatchString(s) {
			t.Errorf("stripe_key should NOT match %q", s)
		}
	}
}

func TestSecretsNPMTokenPattern(t *testing.T) {
	entry := findEntry("npm_token", "SECRETS")
	if entry == nil {
		t.Fatal("npm_token entry not found")
	}

	// 36 chars after npm_
	if !entry.Re.MatchString("npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij") {
		t.Error("npm_token should match valid NPM token")
	}
	if entry.Re.MatchString("npm_shorttoken") {
		t.Error("npm_token should NOT match short token")
	}
}

func TestSecretsPyPITokenPattern(t *testing.T) {
	entry := findEntry("pypi_token", "SECRETS")
	if entry == nil {
		t.Fatal("pypi_token entry not found")
	}

	// 85+ chars after pypi-
	long := "pypi-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPQRSTUV"
	if !entry.Re.MatchString(long) {
		t.Error("pypi_token should match valid PyPI token")
	}
	if entry.Re.MatchString("pypi-short") {
		t.Error("pypi_token should NOT match short token")
	}
}

func TestSecretsOpenAIKeyPattern(t *testing.T) {
	entry := findEntry("openai_key", "SECRETS")
	if entry == nil {
		t.Fatal("openai_key entry not found")
	}

	if !entry.Re.MatchString("sk-ABCDEFghijklmnopqrst") {
		t.Error("openai_key should match valid OpenAI key")
	}
	if entry.Re.MatchString("sk-short") {
		t.Error("openai_key should NOT match short key")
	}

	// Cross-pattern: must not match Stripe keys (underscore after sk).
	stripeKey := "sk_live_ABCDEFghijklmnopqrst"
	if entry.Re.MatchString(stripeKey) {
		t.Errorf("openai_key should NOT match Stripe key %q", stripeKey)
	}
}

func TestSecretsDockerPATPattern(t *testing.T) {
	entry := findEntry("docker_pat", "SECRETS")
	if entry == nil {
		t.Fatal("docker_pat entry not found")
	}

	if !entry.Re.MatchString("dckr_pat_ABCDEFghijklmnopqrst") {
		t.Error("docker_pat should match valid Docker PAT")
	}
	if entry.Re.MatchString("dckr_pat_short") {
		t.Error("docker_pat should NOT match short token")
	}
}

func TestSecretsGoogleAPIKeyPattern(t *testing.T) {
	entry := findEntry("google_api_key", "SECRETS")
	if entry == nil {
		t.Fatal("google_api_key entry not found")
	}

	// AIza + exactly 35 chars
	if !entry.Re.MatchString("AIzaSyD-example-key-value_1234567890ABC") {
		t.Error("google_api_key should match valid Google API key")
	}
	if entry.Re.MatchString("AIzashort") {
		t.Error("google_api_key should NOT match short key")
	}
}

func TestSecretsShopifyTokenPattern(t *testing.T) {
	entry := findEntry("shopify_token", "SECRETS")
	if entry == nil {
		t.Fatal("shopify_token entry not found")
	}

	positives := []string{
		"shpat_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", // 32 chars
		"shpca_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
		"shpss_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("shopify_token should match %q", s)
		}
	}

	if entry.Re.MatchString("shpat_short") {
		t.Error("shopify_token should NOT match short token")
	}
	if entry.Re.MatchString("shpxx_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef") {
		t.Error("shopify_token should NOT match unknown shopify prefix")
	}
}

func TestSecretsSendGridKeyPattern(t *testing.T) {
	entry := findEntry("sendgrid_key", "SECRETS")
	if entry == nil {
		t.Fatal("sendgrid_key entry not found")
	}

	if !entry.Re.MatchString("SG.abcdefghij1234567890") {
		t.Error("sendgrid_key should match valid SendGrid key")
	}
	if entry.Re.MatchString("SG.short") {
		t.Error("sendgrid_key should NOT match short key")
	}
}

func TestSecretsGroqKeyPattern(t *testing.T) {
	entry := findEntry("groq_key", "SECRETS")
	if entry == nil {
		t.Fatal("groq_key entry not found")
	}

	if !entry.Re.MatchString("gsk_ABCDEFghijklmnopqrst") {
		t.Error("groq_key should match valid Groq key")
	}
	if entry.Re.MatchString("gsk_short") {
		t.Error("groq_key should NOT match short key")
	}

	// Cross-pattern: must not match GitHub ghs_ tokens.
	if entry.Re.MatchString("ghs_ABCDEFghijklmnopqrstuvwxyz012345678") {
		t.Error("groq_key should NOT match GitHub token with ghs_ prefix")
	}
}

func TestSecretsTwilioSIDPattern(t *testing.T) {
	entry := findEntry("twilio_sid", "SECRETS")
	if entry == nil {
		t.Fatal("twilio_sid entry not found")
	}

	// AC + exactly 32 hex chars
	if !entry.Re.MatchString("AC00000000000000000000000000000000") {
		t.Error("twilio_sid should match valid Twilio Account SID")
	}
	if entry.Re.MatchString("AC1234") {
		t.Error("twilio_sid should NOT match short SID")
	}
	// Must not match with non-hex characters
	if entry.Re.MatchString("ACzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") {
		t.Error("twilio_sid should NOT match non-hex after AC prefix")
	}
}

func TestSecretsTwilioAuthPattern(t *testing.T) {
	entry := findEntry("twilio_auth", "SECRETS")
	if entry == nil {
		t.Fatal("twilio_auth entry not found")
	}

	if !entry.Re.MatchString("SK00000000000000000000000000000000") {
		t.Error("twilio_auth should match valid Twilio API key SID")
	}
	if entry.Re.MatchString("SK1234") {
		t.Error("twilio_auth should NOT match short key")
	}
}

func TestSecretsFacebookTokenPattern(t *testing.T) {
	entry := findEntry("facebook_token", "SECRETS")
	if entry == nil {
		t.Fatal("facebook_token entry not found")
	}

	if !entry.Re.MatchString("EAACEdEose0cBAabcdef1234567890") {
		t.Error("facebook_token should match valid Facebook token")
	}
	if entry.Re.MatchString("EAACEdEose0cBA") {
		t.Error("facebook_token should NOT match prefix alone (no trailing chars)")
	}
}

func TestSecretsAmazonMWSPattern(t *testing.T) {
	entry := findEntry("amazon_mws", "SECRETS")
	if entry == nil {
		t.Fatal("amazon_mws entry not found")
	}

	if !entry.Re.MatchString("amzn.mws.12345678-1234-1234-1234-123456789012") {
		t.Error("amazon_mws should match valid Amazon MWS token")
	}
	if entry.Re.MatchString("amzn.mws.short") {
		t.Error("amazon_mws should NOT match short token")
	}
}

func TestSecretsCloudinaryURLPattern(t *testing.T) {
	entry := findEntry("cloudinary_url", "SECRETS")
	if entry == nil {
		t.Fatal("cloudinary_url entry not found")
	}

	if !entry.Re.MatchString("cloudinary://123456789012345:abcdefGHIJ@cloud_name") {
		t.Error("cloudinary_url should match valid Cloudinary URL")
	}
	if entry.Re.MatchString("cloudinary://short") {
		t.Error("cloudinary_url should NOT match short URL")
	}
}

func TestSecretsPGPKeyPattern(t *testing.T) {
	entry := findEntry("pgp_private_key", "SECRETS")
	if entry == nil {
		t.Fatal("pgp_private_key entry not found")
	}

	if !entry.Re.MatchString("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
		t.Error("pgp_private_key should match PGP private key header")
	}
	if entry.Re.MatchString("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		t.Error("pgp_private_key should NOT match PGP public key header")
	}
}

// Cross-pattern collision tests

func TestSecretsOpenAIvsStripeNoCollision(t *testing.T) {
	openai := findEntry("openai_key", "SECRETS")
	stripe := findEntry("stripe_key", "SECRETS")
	if openai == nil || stripe == nil {
		t.Fatal("missing openai_key or stripe_key entry")
	}

	// sk- (OpenAI) should not match sk_live_ (Stripe)
	stripeVal := "sk_live_XXXXXXXXXXXXXXXXXXXX"
	if openai.Re.MatchString(stripeVal) {
		t.Error("openai_key regex must not match Stripe key")
	}

	// sk_live_ (Stripe) should not match sk- (OpenAI)
	openaiVal := "sk-ABCDEFghijklmnopqrstuvwxyz"
	if stripe.Re.MatchString(openaiVal) {
		t.Error("stripe_key regex must not match OpenAI key")
	}
}

func TestSecretsGroqvsGitHubNoCollision(t *testing.T) {
	groq := findEntry("groq_key", "SECRETS")
	github := findEntry("github_token", "SECRETS")
	if groq == nil || github == nil {
		t.Fatal("missing groq_key or github_token entry")
	}

	ghToken := "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	if groq.Re.MatchString(ghToken) {
		t.Error("groq_key regex must not match GitHub ghs_ token")
	}

	groqVal := "gsk_ABCDEFghijklmnopqrst"
	if github.Re.MatchString(groqVal) {
		t.Error("github_token regex must not match Groq key")
	}
}

func TestSecretsTwilioTightHexRequirement(t *testing.T) {
	sid := findEntry("twilio_sid", "SECRETS")
	auth := findEntry("twilio_auth", "SECRETS")
	if sid == nil || auth == nil {
		t.Fatal("missing twilio_sid or twilio_auth entry")
	}

	// Random English words starting with AC or SK should not match (no 32 hex chars)
	if sid.Re.MatchString("ACCUMULATE") {
		t.Error("twilio_sid must not match common words starting with AC")
	}
	if auth.Re.MatchString("SKILL") {
		t.Error("twilio_auth must not match common words starting with SK")
	}
}
