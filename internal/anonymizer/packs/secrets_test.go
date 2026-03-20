package packs

import "testing"

func TestSecretsSSHKeyTruePositives(t *testing.T) {
	cases := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN DSA PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
	}
	entry := findEntry("SECRETS", "ssh_private_key")
	if entry == nil {
		t.Fatal("ssh_private_key entry not found in SECRETS pack")
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("SSH key pattern should match %q", tc)
		}
	}
}

func TestSecretsSSHKeyTrueNegatives(t *testing.T) {
	cases := []string{
		"-----BEGIN PUBLIC KEY-----",
		"-----BEGIN CERTIFICATE-----",
		"not a key at all",
		"BEGIN PRIVATE KEY",
		"-----END RSA PRIVATE KEY-----",
	}
	entry := findEntry("SECRETS", "ssh_private_key")
	if entry == nil {
		t.Fatal("ssh_private_key entry not found in SECRETS pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("SSH key pattern should NOT match %q", tc)
		}
	}
}

func TestSecretsSSHKeyTokenSelfCheck(t *testing.T) {
	entry := findEntry("SECRETS", "ssh_private_key")
	if entry == nil {
		t.Fatal("ssh_private_key entry not found in SECRETS pack")
	}
	token := "[PII_SSHKEY_abcdefabcdefabcd]"
	if entry.Re.MatchString(token) {
		t.Errorf("SSH key pattern must not match its own token: %s", token)
	}
}

func TestSecretsJWTTruePositives(t *testing.T) {
	cases := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature_here_long",
		"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.MEUCIQCFL_signature_here",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.xL5aBYyijQo-KYIVJi6cXvfo",
		"eyJraWQiOiIxMjM0NTY3OCJ9.eyJhdWQiOiJ0ZXN0In0.abcdefghijklmn",
	}
	entry := findEntry("SECRETS", "jwt_token")
	if entry == nil {
		t.Fatal("jwt_token entry not found in SECRETS pack")
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("JWT pattern should match %q", tc)
		}
	}
}

func TestSecretsJWTTrueNegatives(t *testing.T) {
	cases := []string{
		"not.a.jwt",
		"eyJ.short.tok",
		"regular text without dots",
		"abc.def.ghi",
		"eyJhbGci.only_two_parts",
	}
	entry := findEntry("SECRETS", "jwt_token")
	if entry == nil {
		t.Fatal("jwt_token entry not found in SECRETS pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("JWT pattern should NOT match %q", tc)
		}
	}
}

func TestSecretsJWTTokenSelfCheck(t *testing.T) {
	entry := findEntry("SECRETS", "jwt_token")
	if entry == nil {
		t.Fatal("jwt_token entry not found in SECRETS pack")
	}
	token := "[PII_JWT_abcdefabcdefabcd]"
	if entry.Re.MatchString(token) {
		t.Errorf("JWT pattern must not match its own token: %s", token)
	}
}

func TestSecretsBearerTruePositives(t *testing.T) {
	cases := []string{
		"Bearer sk-abcdefghijklmnopqrstuvwx",
		"bearer AAAAAABBBBBBCCCCCCDDDDDD",
		"BEARER xyzxyzxyzxyzxyzxyzxyzx",
		"Bearer abcdef.ghijkl-mnopqr_stuv",
		"bearer aaaabbbbccccddddeeeefffff",
	}
	entry := findEntry("SECRETS", "bearer_token")
	if entry == nil {
		t.Fatal("bearer_token entry not found in SECRETS pack")
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("bearer pattern should match %q", tc)
		}
	}
}

func TestSecretsBearerTrueNegatives(t *testing.T) {
	cases := []string{
		"Bearer short",
		"not bearer at all",
		"Bearer ",
		"Bearertoken",
		"Bearer abc",
	}
	entry := findEntry("SECRETS", "bearer_token")
	if entry == nil {
		t.Fatal("bearer_token entry not found in SECRETS pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("bearer pattern should NOT match %q", tc)
		}
	}
}

func TestSecretsDBConnTruePositives(t *testing.T) {
	cases := []string{
		"postgresql://user:pass@localhost:5432/mydb",
		"postgres://admin:s3cret@dbhost/production",
		"mysql://root:password@dbhost:3306/app",
		"mongodb+srv://user:pass@cluster.example.net/test",
		"redis://default:token@cachehost:6379",
	}
	entry := findEntry("SECRETS", "db_connection_string")
	if entry == nil {
		t.Fatal("db_connection_string entry not found in SECRETS pack")
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("db_conn pattern should match %q", tc)
		}
	}
}

func TestSecretsDBConnTrueNegatives(t *testing.T) {
	cases := []string{
		"http://example.com",
		"https://api.example.com",
		"ftp://files.example.com",
		"not a connection string",
		"sqlite:///path/to/db",
	}
	entry := findEntry("SECRETS", "db_connection_string")
	if entry == nil {
		t.Fatal("db_connection_string entry not found in SECRETS pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("db_conn pattern should NOT match %q", tc)
		}
	}
}

func TestSecretsAWSKeyTruePositives(t *testing.T) {
	cases := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"AKIAABCDEFGHIJKLMNOP",
		"AKIAXYZXYZXYZXYZXYZX",
		"AKIAQQQQWWWWEEEERRRR",
		"AKIATTTTYYYYUUUUIIII",
	}
	entry := findEntry("SECRETS", "aws_access_key")
	if entry == nil {
		t.Fatal("aws_access_key entry not found in SECRETS pack")
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("AWS key pattern should match %q", tc)
		}
	}
}

func TestSecretsAWSKeyTrueNegatives(t *testing.T) {
	cases := []string{
		"AKIA123",
		"AKIAshort",
		"BKIAABCDEFGHIJKLMNOP",
		"not an aws key",
		"AKIA",
	}
	entry := findEntry("SECRETS", "aws_access_key")
	if entry == nil {
		t.Fatal("aws_access_key entry not found in SECRETS pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("AWS key pattern should NOT match %q", tc)
		}
	}
}

func TestSecretsGitHubTokenTruePositives(t *testing.T) {
	cases := []string{
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		"gho_aaaaaabbbbbbccccccddddddeeeeeeffffffgg",
		"ghu_AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEE",
		"ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"ghr_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
	}
	entry := findEntry("SECRETS", "github_token")
	if entry == nil {
		t.Fatal("github_token entry not found in SECRETS pack")
	}
	for _, tc := range cases {
		if !entry.Re.MatchString(tc) {
			t.Errorf("GitHub token pattern should match %q", tc)
		}
	}
}

func TestSecretsGitHubTokenTrueNegatives(t *testing.T) {
	cases := []string{
		"ghp_short",
		"ghx_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		"not a token",
		"ghp_",
		"github_pat_XXXXX",
	}
	entry := findEntry("SECRETS", "github_token")
	if entry == nil {
		t.Fatal("github_token entry not found in SECRETS pack")
	}
	for _, tc := range cases {
		if entry.Re.MatchString(tc) {
			t.Errorf("GitHub token pattern should NOT match %q", tc)
		}
	}
}
