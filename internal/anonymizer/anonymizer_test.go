package anonymizer

import (
	"io"
	"strings"
	"testing"

	"ai-anonymizing-proxy/internal/metrics"
)

func newTestAnonymizer() *Anonymizer {
	return New("http://localhost:11434", "test-model", false, 0.8, nil)
}

func TestAnonymizeTextEmail(t *testing.T) {
	a := newTestAnonymizer()
	result := a.AnonymizeText("Contact me at alice@example.com please", "sess1")
	if strings.Contains(result, "alice@example.com") {
		t.Errorf("email not anonymized: %q", result)
	}
}

func TestDeanonymizeTextRoundTrip(t *testing.T) {
	a := newTestAnonymizer()
	original := "Call me at 555-867-5309 or email bob@corp.io"
	sessionID := "sess-rt-1"

	anonymized := a.AnonymizeText(original, sessionID)
	if anonymized == original {
		t.Fatal("AnonymizeText did not change the text")
	}

	restored := a.DeanonymizeText(anonymized, sessionID)
	if restored != original {
		t.Errorf("round-trip failed\n  want: %q\n   got: %q", original, restored)
	}
}

func TestDeanonymizeJSONRoundTrip(t *testing.T) {
	a := newTestAnonymizer()
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}`)
	sessionID := "sess-json-1"

	anonymized := a.AnonymizeJSON(body, sessionID)
	if strings.Contains(string(anonymized), "123-45-6789") {
		t.Errorf("SSN not anonymized in JSON: %s", anonymized)
	}

	restored := a.DeanonymizeText(string(anonymized), sessionID)
	if !strings.Contains(restored, "123-45-6789") {
		t.Errorf("SSN not restored after deanonymization: %s", restored)
	}
}

func TestDeleteSessionClearsMap(t *testing.T) {
	a := newTestAnonymizer()
	sessionID := "sess-del-1"

	a.AnonymizeText("reach me at tester@example.com", sessionID)
	a.DeleteSession(sessionID)

	a.sessionMu.RLock()
	_, exists := a.sessions[sessionID]
	a.sessionMu.RUnlock()

	if exists {
		t.Error("session was not deleted")
	}
}

func TestDeanonymizeUnknownSessionReturnsOriginal(t *testing.T) {
	a := newTestAnonymizer()
	text := "some text with no session"
	result := a.DeanonymizeText(text, "nonexistent-session")
	if result != text {
		t.Errorf("expected unchanged text, got %q", result)
	}
}

func TestDeanonymizeEmptySessionID(t *testing.T) {
	a := newTestAnonymizer()
	text := "some text"
	result := a.DeanonymizeText(text, "")
	if result != text {
		t.Errorf("expected unchanged text for empty sessionID, got %q", result)
	}
}

func TestStreamingDeanonymizeRoundTrip(t *testing.T) {
	a := newTestAnonymizer()
	sessionID := "sess-stream-1"

	original := `data: {"content":"call user9aab5a23@example.com or +1-555-d2df"}` + "\n\n"
	anonymized := a.AnonymizeText(original, sessionID)
	if anonymized == original {
		t.Fatal("AnonymizeText did not change the text")
	}

	src := io.NopCloser(strings.NewReader(anonymized))
	rc := a.StreamingDeanonymize(src, sessionID)
	defer rc.Close() //nolint:errcheck // test cleanup

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	if string(got) != original {
		t.Errorf("streaming round-trip failed\n  want: %q\n   got: %q", original, string(got))
	}
}

func TestStreamingDeanonymizeNoTokens(t *testing.T) {
	a := newTestAnonymizer()
	text := "data: {\"content\":\"hello world\"}\n\n"

	src := io.NopCloser(strings.NewReader(text))
	// session with no replacements: should get back the original reader unchanged
	rc := a.StreamingDeanonymize(src, "empty-session")
	defer rc.Close() //nolint:errcheck // test cleanup

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	if string(got) != text {
		t.Errorf("expected passthrough, got %q", string(got))
	}
}

func TestMultipleSessionsIsolated(t *testing.T) {
	a := newTestAnonymizer()

	a.AnonymizeText("alice@example.com", "sess-a")
	a.AnonymizeText("bob@example.com", "sess-b")

	a.sessionMu.RLock()
	mapA := a.sessions["sess-a"]
	mapB := a.sessions["sess-b"]
	a.sessionMu.RUnlock()

	for token := range mapA {
		if _, collision := mapB[token]; collision {
			// Collision is possible for same PII type but different values;
			// ensure the originals differ.
			if mapA[token] == mapB[token] {
				t.Errorf("sessions share identical token mapping for token %q", token)
			}
		}
	}
}

func TestMetricsCountersIncrement(t *testing.T) {
	m := metrics.New()
	a := New("http://localhost:[ADDRESS_c13ffb79]", "test-model", false, 0.8, m)

	sessionID := "sess-metrics-1"
	a.AnonymizeText("userc160f8cc@example.com and XXX-XX-1e87", sessionID)

	replaced := m.TokensReplaced.Load()
	if replaced == 0 {
		t.Error("expected TokensReplaced > 0 after anonymization")
	}

	a.DeanonymizeText("anything", sessionID)
	deanon := m.TokensDeanonymized.Load()
	if deanon == 0 {
		t.Error("expected TokensDeanonymized > 0 after deanonymization")
	}
}

// bytewiseReader simulates a slow byte-at-a-time stream for testing that
// token replacement works correctly regardless of chunk boundaries.
type bytewiseReader struct {
	data []byte
	pos  int
}

func (r *bytewiseReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

func (r *bytewiseReader) Close() error { return nil }

func TestStreamingDeanonymizeChunkBoundary(t *testing.T) {
	a := newTestAnonymizer()
	sessionID := "sess-boundary-1"

	// Text with multiple PII types; the resulting tokens are multi-character
	// ASCII strings that will straddle Read() boundaries when delivered one
	// byte at a time.
	input := "My email is alice@company.org and phone +1-800-555-1234"
	anonymized := a.AnonymizeText(input, sessionID)
	if anonymized == input {
		t.Fatal("AnonymizeText did not change the text")
	}

	// Deliver the anonymized content one byte per Read to force every possible
	// token split across chunk boundaries.
	src := &bytewiseReader{data: []byte(anonymized)}
	rc := a.StreamingDeanonymize(src, sessionID)
	defer rc.Close() //nolint:errcheck // test cleanup

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	if string(got) != input {
		t.Errorf("chunk-boundary round-trip failed\n  want: %q\n   got: %q", input, string(got))
	}
}
