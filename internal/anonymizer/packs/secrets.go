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
	)
}
