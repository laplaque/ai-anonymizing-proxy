package domainmatch

import "testing"

// TestDomainGlob_Match exhaustively covers segment-glob matching: bare "*"
// segments (Azure prefix, Bedrock infix), label-substring wildcards
// (Vertex AI hyphen-prefix), case folding, and trailing-dot normalization.
func TestDomainGlob_Match(t *testing.T) {
	cases := []struct {
		pattern string
		domain  string
		want    bool
	}{
		// Prefix wildcard (Azure)
		{"*.openai.azure.com", "myresource.openai.azure.com", true},
		{"*.openai.azure.com", "another.openai.azure.com", true},
		{"*.openai.azure.com", "openai.azure.com", false},              // too few segments
		{"*.openai.azure.com", "deep.sub.openai.azure.com", false},     // too many segments
		{"*.openai.azure.com", "evil.openai.azure.com.bad.com", false}, // different segment count

		// Infix wildcard (Bedrock)
		{"bedrock-runtime.*.amazonaws.com", "bedrock-runtime.us-east-1.amazonaws.com", true},
		{"bedrock-runtime.*.amazonaws.com", "bedrock-runtime.eu-west-1.amazonaws.com", true},
		{"bedrock-runtime.*.amazonaws.com", "bedrock-runtime.ap-southeast-1.amazonaws.com", true},
		{"bedrock-runtime.*.amazonaws.com", "ec2.us-east-1.amazonaws.com", false},                // wrong prefix
		{"bedrock-runtime.*.amazonaws.com", "bedrock-runtime.amazonaws.com", false},              // missing region
		{"bedrock-runtime.*.amazonaws.com", "bedrock-runtime.us-east-1.s3.amazonaws.com", false}, // extra segment

		// Bedrock agent runtime
		{"bedrock-agent-runtime.*.amazonaws.com", "bedrock-agent-runtime.us-east-1.amazonaws.com", true},
		{"bedrock-agent-runtime.*.amazonaws.com", "bedrock-runtime.us-east-1.amazonaws.com", false},

		// Vertex AI hyphen-prefix label-substring wildcard.
		// Real Vertex regional URLs are {region}-aiplatform.googleapis.com (3 labels).
		{"*-aiplatform.googleapis.com", "us-central1-aiplatform.googleapis.com", true},
		{"*-aiplatform.googleapis.com", "europe-west1-aiplatform.googleapis.com", true},
		{"*-aiplatform.googleapis.com", "us-east4-aiplatform.googleapis.com", true},
		{"*-aiplatform.googleapis.com", "asia-northeast1-aiplatform.googleapis.com", true},
		{"*-aiplatform.googleapis.com", "aiplatform.googleapis.com", false},   // no prefix to fill *
		{"*-aiplatform.googleapis.com", "-aiplatform.googleapis.com", false},  // empty prefix
		{"*-aiplatform.googleapis.com", "ec2.amazonaws.com", false},           // wrong segment count
		{"*-aiplatform.googleapis.com", "us-aiplatform.googleapis.com", true}, // minimal prefix

		// Defensive 4-label Vertex glob (kept for any future host using a 4-label form)
		{"*.aiplatform.googleapis.com", "anything.aiplatform.googleapis.com", true},
		{"*.aiplatform.googleapis.com", "us-central1-aiplatform.googleapis.com", false}, // 3 labels
		{"*.aiplatform.googleapis.com", "aiplatform.googleapis.com", false},

		// Label-substring wildcard variants (suffix, infix)
		{"foo-*.example.com", "foo-bar.example.com", true},
		{"foo-*.example.com", "foo-.example.com", false}, // empty wildcard fill
		{"foo-*.example.com", "fox-bar.example.com", false},
		{"foo*bar.example.com", "fooXYZbar.example.com", true},
		{"foo*bar.example.com", "foobar.example.com", false}, // overlap — needs at least one char
		{"foo*bar.example.com", "fooabar.example.com", true},

		// Case folding (DNS is case-insensitive — RFC 1035 §2.3.3).
		{"*.openai.azure.com", "Foo.OPENAI.azure.com", true},
		{"api.openai.com", "API.OpenAI.COM", true},
		{"*-aiplatform.googleapis.com", "US-EAST4-aiplatform.googleapis.com", true},

		// Trailing-dot normalization (RFC 1035 §3.1 root-zone canonical form).
		{"api.openai.com", "api.openai.com.", true},
		{"*.openai.azure.com", "myresource.openai.azure.com.", true},
		{"bedrock-runtime.*.amazonaws.com", "bedrock-runtime.us-east-1.amazonaws.com.", true},

		// Bare "*" must reject an empty label (consecutive dots produce
		// an empty segment via strings.Split).
		{"foo.*.bar", "foo..bar", false},

		// No wildcard (should not be used as glob, but verify it works)
		{"api.openai.com", "api.openai.com", true},
		{"api.openai.com", "other.openai.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.pattern+"/"+tc.domain, func(t *testing.T) {
			g := Parse(tc.pattern)
			if got := g.Match(tc.domain); got != tc.want {
				t.Errorf("Parse(%q).Match(%q) = %v, want %v",
					tc.pattern, tc.domain, got, tc.want)
			}
		})
	}
}

func TestIsGlob(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{"*.openai.azure.com", true},
		{"bedrock-runtime.*.amazonaws.com", true},
		{"api.openai.com", false},
		{"*", true},         // single segment glob
		{"a.*.b.*.c", true}, // multiple wildcards
		{"", false},         // empty
		// Label-substring wildcards now count as globs (Phase-3 follow-up).
		{"*foo.bar", true},
		{"foo*.bar", true},
		{"*-aiplatform.googleapis.com", true},
	}
	for _, tc := range cases {
		if got := IsGlob(tc.pattern); got != tc.want {
			t.Errorf("IsGlob(%q) = %v, want %v", tc.pattern, got, tc.want)
		}
	}
}

func TestDomainGlob_Raw(t *testing.T) {
	pattern := "bedrock-runtime.*.amazonaws.com"
	g := Parse(pattern)
	if g.Raw() != pattern {
		t.Errorf("Raw() = %q, want %q", g.Raw(), pattern)
	}
}

// TestDomainGlob_DoubleWildcardLiteral ensures that a segment containing
// two or more "*" is treated as a literal string (no second-class glob
// semantics), so a typo can't silently over-match.
func TestDomainGlob_DoubleWildcardLiteral(t *testing.T) {
	g := Parse("**foo.bar")
	if g.Match("anything.bar") {
		t.Error("double wildcard should not match arbitrary labels")
	}
	if !g.Match("**foo.bar") {
		t.Error("double-wildcard segment should match its literal form")
	}
}
