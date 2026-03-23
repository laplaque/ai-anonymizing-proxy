package packs

import "testing"

func TestSecretsSSHKeyPositives(t *testing.T) {
	entry := findEntry("SECRETS", "ssh_private_key")
	if entry == nil {
		t.Fatal("ssh_private_key entry not found")
	}
	positives := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN DSA PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestSecretsSSHKeyNegatives(t *testing.T) {
	entry := findEntry("SECRETS", "ssh_private_key")
	if entry == nil {
		t.Fatal("ssh_private_key entry not found")
	}
	negatives := []string{
		"-----BEGIN PUBLIC KEY-----",
		"-----BEGIN CERTIFICATE-----",
		"some random text",
		"PRIVATE KEY",
		"-----BEGIN RSA PUBLIC KEY-----",
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}

func TestSecretsSSHKeyTokenSelfCheck(t *testing.T) {
	entry := findEntry("SECRETS", "ssh_private_key")
	if entry == nil {
		t.Fatal("ssh_private_key entry not found")
	}
	token := "[PII_SSHKEY_abcdef0123456789]"
	if entry.Re.MatchString(token) {
		t.Errorf("pattern matched its own token: %q", token)
	}
}

func TestSecretsJWTPositives(t *testing.T) {
	entry := findEntry("SECRETS", "jwt")
	if entry == nil {
		t.Fatal("jwt entry not found")
	}
	positives := []string{
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAi.cC4hiUPoj9Eetdgtv3hF80EGrhuB",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestSecretsJWTNegatives(t *testing.T) {
	entry := findEntry("SECRETS", "jwt")
	if entry == nil {
		t.Fatal("jwt entry not found")
	}
	negatives := []string{
		"not-a-jwt",
		"eyJ.short.x",
		"abc.def.ghi",
		"plaintext",
		"eyXnotbase64.part2.part3",
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}

func TestSecretsJWTTokenSelfCheck(t *testing.T) {
	entry := findEntry("SECRETS", "jwt")
	if entry == nil {
		t.Fatal("jwt entry not found")
	}
	token := "[PII_JWT_abcdef0123456789]"
	if entry.Re.MatchString(token) {
		t.Errorf("pattern matched its own token: %q", token)
	}
}

func TestSecretsBearerPositives(t *testing.T) {
	entry := findEntry("SECRETS", "bearer_token")
	if entry == nil {
		t.Fatal("bearer_token entry not found")
	}
	positives := []string{
		"Bearer sk-proj-abcdefghijklmnopqrst",
		"bearer xoxb-123456789012-abcdefghij",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
	// Verify ReplaceGroup preserves "Bearer " prefix
	if entry.ReplaceGroup != 2 {
		t.Errorf("bearer_token ReplaceGroup should be 2, got %d", entry.ReplaceGroup)
	}
}

func TestSecretsBearerNegatives(t *testing.T) {
	entry := findEntry("SECRETS", "bearer_token")
	if entry == nil {
		t.Fatal("bearer_token entry not found")
	}
	negatives := []string{
		"Bearer short",
		"NotBearer abcdefghijklmnopqrst",
		"plaintext",
		"Bearer ",
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}

func TestSecretsBearerTokenSelfCheck(t *testing.T) {
	entry := findEntry("SECRETS", "bearer_token")
	if entry == nil {
		t.Fatal("bearer_token entry not found")
	}
	token := "[PII_BEARER_abcdef0123456789]"
	if entry.Re.MatchString(token) {
		t.Errorf("pattern matched its own token: %q", token)
	}
}

func TestSecretsDBConnPositives(t *testing.T) {
	entry := findEntry("SECRETS", "db_connection_string")
	if entry == nil {
		t.Fatal("db_connection_string entry not found")
	}
	positives := []string{
		"postgres://user:pass@host:5432/dbname",
		"mysql://root:password@localhost/mydb",
		"mongodb+srv://user:pass@cluster0.example.net",
		"redis://default:pass@redis.example.com:6379",
		"mssql://sa:Password@server:1433/db",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestSecretsDBConnNegatives(t *testing.T) {
	entry := findEntry("SECRETS", "db_connection_string")
	if entry == nil {
		t.Fatal("db_connection_string entry not found")
	}
	negatives := []string{
		"http://example.com",
		"postgres://x",
		"plaintext",
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}

func TestSecretsDBConnTokenSelfCheck(t *testing.T) {
	entry := findEntry("SECRETS", "db_connection_string")
	if entry == nil {
		t.Fatal("db_connection_string entry not found")
	}
	token := "[PII_DBCONN_abcdef0123456789]"
	if entry.Re.MatchString(token) {
		t.Errorf("pattern matched its own token: %q", token)
	}
}

func TestSecretsAWSKeyPositives(t *testing.T) {
	entry := findEntry("SECRETS", "aws_access_key")
	if entry == nil {
		t.Fatal("aws_access_key entry not found")
	}
	positives := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"AKIAI44QH8DHBEXAMPLE",
		"AKIA1234567890ABCDEF",
		"AKIAABCDEFGHIJ012345",
		"AKIA0000000000000000",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestSecretsAWSKeyNegatives(t *testing.T) {
	entry := findEntry("SECRETS", "aws_access_key")
	if entry == nil {
		t.Fatal("aws_access_key entry not found")
	}
	negatives := []string{
		"AKIA1234",
		"ASIA1234567890ABCDEF",
		"plaintext",
		"AKIAIOSFODNN7EXAMPLEtoolong",
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}

func TestSecretsGHTokenPositives(t *testing.T) {
	entry := findEntry("SECRETS", "github_token")
	if entry == nil {
		t.Fatal("github_token entry not found")
	}
	positives := []string{
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		"gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		"ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
	}
	for _, p := range positives {
		if !entry.Re.MatchString(p) {
			t.Errorf("should match: %q", p)
		}
	}
}

func TestSecretsGHTokenNegatives(t *testing.T) {
	entry := findEntry("SECRETS", "github_token")
	if entry == nil {
		t.Fatal("github_token entry not found")
	}
	negatives := []string{
		"ghp_short",
		"gha_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		"plaintext",
	}
	for _, n := range negatives {
		if entry.Re.MatchString(n) {
			t.Errorf("should not match: %q", n)
		}
	}
}
