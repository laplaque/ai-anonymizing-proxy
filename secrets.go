package packs

// Source: SSH private key — OpenSSH PEM header format
// Source: JWT — RFC 7519 three-part base64url structure
// Source: Bearer token — RFC 6750 Authorization header format
// Source: Database connection strings — common driver URI formats
// Source: AWS access key — AWS IAM key format (AKIA prefix)
// Source: GitHub token — GitHub PAT format (ghp_/gho_/ghs_/ghr_ prefix)

import "regexp"

func init() {
	Register(
		Entry{
			Name:       "ssh_private_key",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
			PIIType:    "SSHKEY",
			Confidence: 0.99,
		},
		Entry{
			Name:       "jwt",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
			PIIType:    "JWT",
			Confidence: 0.95,
		},
		Entry{
			Name:         "bearer_token",
			Pack:         "SECRETS",
			Re:           regexp.MustCompile(`(?i)(\bBearer\s+)([A-Za-z0-9_\-.]{20,})`),
			PIIType:      "BEARER",
			Confidence:   0.90,
			ReplaceGroup: 2,
		},
		Entry{
			Name:       "db_connection_string",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql|sqlserver)://[^\s"'` + "`" + `]{10,}`),
			PIIType:    "DBCONN",
			Confidence: 0.95,
		},
		Entry{
			Name:       "aws_access_key",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			PIIType:    "AWSKEY",
			Confidence: 0.95,
		},
		Entry{
			Name:       "github_token",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bgh[pos]_[A-Za-z0-9_]{36,}\b`),
			PIIType:    "GHTOKEN",
			Confidence: 0.95,
		},
	)
}
