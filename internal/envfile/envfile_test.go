package envfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApply(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    map[string]string
		wantErr string
	}{
		{
			name: "simple_pairs",
			content: `FOO=bar
BAZ=qux
`,
			want: map[string]string{"FOO": "bar", "BAZ": "qux"},
		},
		{
			name: "comments_and_blanks",
			content: `# header comment
FOO=bar

# another comment
BAZ=qux
`,
			want: map[string]string{"FOO": "bar", "BAZ": "qux"},
		},
		{
			name: "leading_trailing_whitespace",
			content: `  FOO  =  bar
BAZ=qux
`,
			want: map[string]string{"FOO": "bar", "BAZ": "qux"},
		},
		{
			name: "double_quoted_value",
			content: `FOO="hello world"
`,
			want: map[string]string{"FOO": "hello world"},
		},
		{
			name: "single_quoted_value",
			content: `FOO='hello world'
`,
			want: map[string]string{"FOO": "hello world"},
		},
		{
			name: "value_with_equals_sign",
			content: `URL=https://example.com/?a=1&b=2
`,
			want: map[string]string{"URL": "https://example.com/?a=1&b=2"},
		},
		{
			name: "empty_value",
			content: `FOO=
`,
			want: map[string]string{"FOO": ""},
		},
		{
			name:    "missing_equals",
			content: "FOOBAR\n",
			wantErr: "missing '='",
		},
		{
			name:    "empty_key",
			content: "=value\n",
			wantErr: "empty key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear vars and restore.
			for k := range tt.want {
				original, hadValue := os.LookupEnv(k)
				t.Cleanup(func() {
					if hadValue {
						_ = os.Setenv(k, original)
					} else {
						_ = os.Unsetenv(k)
					}
				})
				_ = os.Unsetenv(k)
			}

			path := writeTempFile(t, tt.content)
			err := Apply(path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Apply() err = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Apply() unexpected err: %v", err)
			}
			for k, want := range tt.want {
				if got := os.Getenv(k); got != want {
					t.Errorf("env[%s] = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestApplyMissingFile(t *testing.T) {
	err := Apply(filepath.Join(t.TempDir(), "does-not-exist.env"))
	if err == nil {
		t.Fatal("Apply() on missing file = nil, want error")
	}
	if !strings.Contains(err.Error(), "open env file") {
		t.Errorf("err = %v, want substring 'open env file'", err)
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}
