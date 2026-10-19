package anonymizer

import (
	"strings"
	"testing"
)

// TestLoadPacksUnknownPackWarning covers the warning branch in loadPacks that
// fires when an enabled pack name has no registered patterns. A bogus pack name
// is included alongside a real one ("GLOBAL"); the bogus name hits the
// len(entries)==0 branch while the real pack still loads patterns.
func TestLoadPacksUnknownPackWarning(t *testing.T) {
	logs := captureLog(t)
	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "test-model",
		EnabledPacks:   []string{"NONEXISTENT_PACK_XYZ", "GLOBAL"},
	})
	defer func() { _ = a.Close() }() // test cleanup

	// Pin the warning branch: only the len(entries)==0 path logs this for the
	// bogus pack. Successful loading of GLOBAL (asserted below) would still hold
	// if that branch were removed, so it is not branch-specific on its own.
	if !strings.Contains(logs.String(), `enabled pack "NONEXISTENT_PACK_XYZ" has no registered patterns`) {
		t.Errorf("expected unknown-pack warning log, got: %q", logs.String())
	}

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
