package domainmatch

import "testing"

// TestDomainGlob_Match exhaustively covers segment-glob matching for the
// patterns the proxy ships with: prefix wildcards (Azure, Vertex) and
// infix wildcards (Bedrock).
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

		// Vertex AI. NOTE: real Vertex regional URLs use hyphens
		// ({region}-aiplatform.googleapis.com — 3 labels), not dots, so
		// the *.aiplatform.googleapis.com glob (4 labels) does NOT match
		// them under strict segment-glob. Users with Vertex regional
		// endpoints must register the exact domain. The synthetic
		// 4-label cases below verify the matcher itself.
		{"*.aiplatform.googleapis.com", "anything.aiplatform.googleapis.com", true},
		{"*.aiplatform.googleapis.com", "region.aiplatform.googleapis.com", true},
		{"*.aiplatform.googleapis.com", "us-central1-aiplatform.googleapis.com", false}, // 3 labels — see note above
		{"*.aiplatform.googleapis.com", "europe-west1-aiplatform.googleapis.com", false},
		{"*.aiplatform.googleapis.com", "aiplatform.googleapis.com", false},

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
		{"*foo.bar", false}, // partial wildcard is NOT a glob — must be entire segment
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

// TestDomainGlob_PartialWildcardSegmentLiteral ensures that "*" inside
// a segment (e.g. "*foo") is treated as a literal label and not a wildcard.
// Only a bare "*" segment matches arbitrarily.
func TestDomainGlob_PartialWildcardSegmentLiteral(t *testing.T) {
	g := Parse("*foo.bar")
	if g.Match("anything.bar") {
		t.Error("partial wildcard should not match arbitrary labels")
	}
	if !g.Match("*foo.bar") {
		t.Error("partial wildcard segment should match its literal form")
	}
}
