package anonymizer

import (
	"errors"
	"testing"
)

// TestLoadPacksUnknownPackWarning covers the warning branch in loadPacks that
// fires when an enabled pack name has no registered patterns. A bogus pack name
// is included alongside a real one ("GLOBAL"); the bogus name hits the
// len(entries)==0 branch while the real pack still loads patterns.
func TestLoadPacksUnknownPackWarning(t *testing.T) {
	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "test-model",
		EnabledPacks:   []string{"NONEXISTENT_PACK_XYZ", "GLOBAL"},
	})
	defer func() { _ = a.Close() }() // test cleanup

	if a == nil {
		t.Fatal("expected non-nil anonymizer despite unknown pack")
	}
	if len(a.patterns) == 0 {
		t.Fatal("expected patterns loaded from the real GLOBAL pack")
	}

	// The anonymizer must still anonymize using the real pack's patterns.
	result := a.AnonymizeText("Contact alice@example.com", "sess-loadpacks")
	if result == "Contact alice@example.com" {
		t.Error("anonymization failed with a mix of unknown and real packs")
	}
}

// TestAnonymizeJSONMarshalErrorFallback covers the marshal-error fallback in
// AnonymizeJSON via the jsonMarshal seam. When marshaling fails, AnonymizeJSON
// must return the original body bytes unchanged.
func TestAnonymizeJSONMarshalErrorFallback(t *testing.T) {
	orig := jsonMarshal
	defer func() { jsonMarshal = orig }()
	jsonMarshal = func(any) ([]byte, error) { return nil, errors.New("boom") }

	a := newTestAnonymizer()
	defer func() { _ = a.Close() }() // test cleanup

	body := []byte(`{"messages":[{"role":"user","content":"hi alice@example.com"}]}`)
	got := a.AnonymizeJSON(body, "req-1")

	if string(got) != string(body) {
		t.Errorf("expected original body on marshal error, got: %q", got)
	}
}
