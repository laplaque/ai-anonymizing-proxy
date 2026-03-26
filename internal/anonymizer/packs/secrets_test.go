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
	for _, want := range []string{"ssh_private_key", "jwt", "bearer_token", "db_connection_string", "aws_access_key", "github_token"} {
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
