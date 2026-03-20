package packs

import "testing"

func TestRegistryAllReturnsEntries(t *testing.T) {
	entries := All()
	if len(entries) == 0 {
		t.Fatal("expected non-empty registry from init() calls")
	}
}

func TestRegistryRegisterAddsEntries(t *testing.T) {
	before := len(All())
	Register(Entry{Name: "extra_test", Pack: "TESTONLY", PIIType: "XTRA", Confidence: 0.5})
	after := len(All())
	if after != before+1 {
		t.Errorf("Register should add 1 entry: before=%d after=%d", before, after)
	}
}

func TestRegistryResetAndRestore(t *testing.T) {
	// Save current registry state
	saved := make([]Entry, len(All()))
	copy(saved, All())

	Reset()
	if len(All()) != 0 {
		t.Errorf("expected empty registry after reset, got %d", len(All()))
	}

	// Restore
	Register(saved...)
	if len(All()) != len(saved) {
		t.Errorf("expected %d entries after restore, got %d", len(saved), len(All()))
	}
}
