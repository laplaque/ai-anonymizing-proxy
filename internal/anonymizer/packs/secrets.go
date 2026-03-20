package packs

import "regexp"

// Source: common secret patterns — SSH key headers, JWT structure, bearer tokens, DB connection strings
// Design decision: token + session deanonymization (consistent with all packs)

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
			Name:       "jwt_token",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
			PIIType:    "JWT",
			Confidence: 0.95,
		},
		Entry{
			Name:       "bearer_token",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9_\-.]{20,}\b`),
			PIIType:    "BEARER",
			Confidence: 0.90,
		},
		Entry{
			Name:       "db_connection_string",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[^\s"']+`),
			PIIType:    "DBCONN",
			Confidence: 0.95,
		},
		Entry{
			Name:       "aws_access_key",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			PIIType:    "AWSKEY",
			Confidence: 0.98,
		},
		Entry{
			Name:       "github_token",
			Pack:       "SECRETS",
			Re:         regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b`),
			PIIType:    "GHTOKEN",
			Confidence: 0.98,
		},
	)
}
