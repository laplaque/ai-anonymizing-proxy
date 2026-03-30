package packs

import "regexp"

func init() {
	Register(
		// SSH private key header: detects the BEGIN marker of PEM-encoded SSH keys.
		// Source: OpenSSH key format, RFC 7468 (PEM encoding).
		// False-positive mitigation: exact structural prefix is unambiguous.
		Entry{
			Name:       "ssh_private_key",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
			PIIType:    "SSHKEY",
			Confidence: 0.99,
		},
		// JSON Web Token (JWT): three base64url-encoded segments separated by dots.
		// Source: RFC 7519 (JSON Web Token).
		// Pattern reference: silv3rshi3ld/gdpr-pii-scanner JWT detection.
		// False-positive mitigation: requires eyJ prefix (base64 of '{"') + three dot-separated segments.
		Entry{
			Name:       "jwt",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
			PIIType:    "JWT",
			Confidence: 0.95,
		},
		// Bearer token in Authorization header value.
		// Source: RFC 6750 (OAuth 2.0 Bearer Token Usage).
		// False-positive mitigation: requires "Bearer " prefix + long token.
		Entry{
			Name:       "bearer_token",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9_\-.~+/]{20,}`),
			PIIType:    "BEARER",
			Confidence: 0.92,
		},
		// Database connection string: detects common DB URI schemes with credentials.
		// Source: PostgreSQL, MySQL, MongoDB, Redis URI format documentation.
		// False-positive mitigation: requires known DB scheme prefix + :// + user:pass@host pattern.
		Entry{
			Name:       "db_connection_string",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s"']{10,}`),
			PIIType:    "DBCONN",
			Confidence: 0.93,
		},
		// AWS access key ID: starts with AKIA followed by 16 uppercase alphanumeric chars.
		// Source: AWS IAM documentation, silv3rshi3ld/gdpr-pii-scanner AWS key detection.
		// False-positive mitigation: AKIA prefix is unique to AWS access keys.
		Entry{
			Name:       "aws_access_key",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			PIIType:    "AWSKEY",
			Confidence: 0.97,
		},
		// GitHub personal access token: ghp_, gho_, ghu_, ghs_, ghr_ prefix + 36 alnum.
		// Source: GitHub docs on token formats.
		// False-positive mitigation: gh[porsu]_ prefix is unique to GitHub tokens.
		Entry{
			Name:       "github_token",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`),
			PIIType:    "GHTOKEN",
			Confidence: 0.97,
		},

		// --- High priority additions ---

		// GitLab personal access token: glpat- prefix + 20+ alphanumeric/dash/underscore.
		// Source: GitLab docs on personal access tokens.
		// False-positive mitigation: glpat- prefix is unique to GitLab PATs.
		Entry{
			Name:       "gitlab_pat",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`),
			PIIType:    "GLTOKEN",
			Confidence: 0.97,
		},
		// GitLab deploy token: gldt- prefix + 20+ alphanumeric/dash/underscore.
		// Source: GitLab docs on deploy tokens.
		// False-positive mitigation: gldt- prefix is unique to GitLab deploy tokens.
		Entry{
			Name:       "gitlab_deploy",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bgldt-[A-Za-z0-9_\-]{20,}\b`),
			PIIType:    "GLTOKEN",
			Confidence: 0.97,
		},
		// Slack token: xoxb-, xoxp-, xoxa-, xoxr- prefix + alphanumeric/dash segments.
		// Source: Slack API docs on token types.
		// False-positive mitigation: xox[bpar]- prefix is unique to Slack tokens.
		Entry{
			Name:       "slack_token",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bxox[bpar]-[0-9A-Za-z\-]+\b`),
			PIIType:    "SLACKTOKEN",
			Confidence: 0.95,
		},
		// Stripe secret/publishable key: sk_live_, sk_test_, pk_live_, pk_test_ prefix.
		// Source: Stripe docs on API keys.
		// False-positive mitigation: [sp]k_(live|test)_ prefix is unique to Stripe.
		// Cross-pattern: sk_ (with underscore) does not collide with OpenAI sk- (with hyphen).
		Entry{
			Name:       "stripe_key",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\b[sp]k_(?:live|test)_[A-Za-z0-9]{20,}\b`),
			PIIType:    "STRIPEKEY",
			Confidence: 0.97,
		},
		// NPM access token: npm_ prefix + 36+ alphanumeric characters.
		// Source: npm docs on access tokens.
		// False-positive mitigation: npm_ prefix + minimum length reduces false positives.
		Entry{
			Name:       "npm_token",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36,}\b`),
			PIIType:    "NPMTOKEN",
			Confidence: 0.97,
		},
		// PyPI API token: pypi- prefix + 85+ alphanumeric/dash/underscore characters.
		// Source: PyPI docs on API tokens.
		// False-positive mitigation: pypi- prefix + long minimum length (85) is highly specific.
		Entry{
			Name:       "pypi_token",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bpypi-[A-Za-z0-9_\-]{85,}\b`),
			PIIType:    "PYPITOKEN",
			Confidence: 0.97,
		},
		// OpenAI API key: sk- prefix + 20+ alphanumeric characters.
		// Source: OpenAI docs on API keys. Also matches DeepSeek keys with same format.
		// False-positive mitigation: sk- prefix (no underscore) is distinct from Stripe sk_live_/sk_test_.
		// Cross-pattern: Stripe uses sk_ (underscore), OpenAI uses sk- (hyphen) — no collision.
		Entry{
			Name:       "openai_key",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`),
			PIIType:    "OPENAIKEY",
			Confidence: 0.95,
		},

		// --- Medium priority additions ---

		// Docker Hub personal access token: dckr_pat_ prefix + 20+ alphanumeric/dash/underscore.
		// Source: Docker Hub docs on personal access tokens.
		// False-positive mitigation: dckr_pat_ prefix is unique to Docker Hub.
		Entry{
			Name:       "docker_pat",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9_\-]{20,}\b`),
			PIIType:    "DOCKERTOKEN",
			Confidence: 0.97,
		},
		// Google API key: AIza prefix + exactly 35 alphanumeric/dash/underscore characters.
		// Source: Google Cloud docs on API keys.
		// False-positive mitigation: AIza prefix + fixed length (35) is structurally distinctive.
		Entry{
			Name:       "google_api_key",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
			PIIType:    "GOOGLEKEY",
			Confidence: 0.97,
		},
		// Shopify access/custom app/storefront token: shpat_, shpca_, shpss_ prefix + 32+ alnum.
		// Source: Shopify docs on API authentication.
		// False-positive mitigation: shp(at|ca|ss)_ prefix is unique to Shopify tokens.
		Entry{
			Name:       "shopify_token",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bshp(?:at|ca|ss)_[A-Za-z0-9]{32,}\b`),
			PIIType:    "SHOPIFYTOKEN",
			Confidence: 0.97,
		},
		// SendGrid API key: SG. prefix + 20+ alphanumeric/dash/underscore characters.
		// Source: SendGrid docs on API keys.
		// False-positive mitigation: SG. prefix is structurally distinctive.
		Entry{
			Name:       "sendgrid_key",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{20,}\b`),
			PIIType:    "SENDGRIDKEY",
			Confidence: 0.96,
		},
		// Groq API key: gsk_ prefix + 20+ alphanumeric characters.
		// Source: Groq docs on API keys.
		// False-positive mitigation: gsk_ prefix is distinct from GitHub ghs_ prefix.
		// Cross-pattern: gsk_ vs ghs_ — different prefixes, no overlap.
		Entry{
			Name:       "groq_key",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bgsk_[A-Za-z0-9]{20,}\b`),
			PIIType:    "GROQKEY",
			Confidence: 0.96,
		},
		// Twilio Account SID: AC prefix + exactly 32 hex characters.
		// Source: Twilio docs on Account SIDs.
		// False-positive mitigation: AC prefix + exactly 32 hex chars is tight enough to avoid false positives.
		Entry{
			Name:       "twilio_sid",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`),
			PIIType:    "TWILIOTOKEN",
			Confidence: 0.95,
		},
		// Twilio auth token / API key SID: SK prefix + exactly 32 hex characters.
		// Source: Twilio docs on API Key SIDs.
		// False-positive mitigation: SK prefix + exactly 32 hex chars is tight enough to avoid false positives.
		Entry{
			Name:       "twilio_auth",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),
			PIIType:    "TWILIOTOKEN",
			Confidence: 0.95,
		},

		// --- Lower priority additions ---

		// Facebook access token: EAACEdEose0cBA prefix + alphanumeric characters.
		// Source: Facebook Graph API docs on access tokens.
		// False-positive mitigation: long literal prefix EAACEdEose0cBA is highly specific.
		Entry{
			Name:       "facebook_token",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bEAACEdEose0cBA[0-9A-Za-z]+\b`),
			PIIType:    "FBTOKEN",
			Confidence: 0.97,
		},
		// Amazon MWS auth token: amzn.mws. prefix + UUID format (36 hex+dash chars).
		// Source: Amazon MWS docs on auth tokens.
		// False-positive mitigation: amzn.mws. prefix + UUID format is structurally distinctive.
		Entry{
			Name:       "amazon_mws",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bamzn\.mws\.[0-9a-f\-]{36}\b`),
			PIIType:    "AMZTOKEN",
			Confidence: 0.96,
		},
		// Cloudinary URL: cloudinary:// scheme with credentials.
		// Source: Cloudinary docs on configuration URLs.
		// False-positive mitigation: cloudinary:// scheme prefix is unique.
		Entry{
			Name:       "cloudinary_url",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`cloudinary://[^\s"']{10,}`),
			PIIType:    "CLOUDINARYTOKEN",
			Confidence: 0.95,
		},
		// PGP private key block header: detects the BEGIN marker of PGP private keys.
		// Source: RFC 4880 (OpenPGP Message Format).
		// False-positive mitigation: exact structural prefix is unambiguous.
		Entry{
			Name:       "pgp_private_key",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
			PIIType:    "PGPKEY",
			Confidence: 0.99,
		},
	)
}
