package packs

import "testing"

func TestRegisterAndAll(t *testing.T) {
	saved := append([]Entry{}, All()...)
	t.Cleanup(func() { Reset(); Register(saved...) })

	Reset()
	if len(All()) != 0 {
		t.Fatal("expected empty registry after Reset")
	}

	Register(Entry{Name: "test1", Pack: "TEST", PIIType: "TESTTYPE", Confidence: 0.9})
	Register(Entry{Name: "test2", Pack: "TEST", PIIType: "TESTTYPE2", Confidence: 0.8})

	got := All()
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].Name != "test1" || got[1].Name != "test2" {
		t.Errorf("unexpected entries: %v", got)
	}
}

func TestResetClearsRegistry(t *testing.T) {
	saved := append([]Entry{}, All()...)
	t.Cleanup(func() { Reset(); Register(saved...) })

	Register(Entry{Name: "temp", Pack: "TEMP", PIIType: "X", Confidence: 1.0})
	Reset()
	if len(All()) != 0 {
		t.Error("expected empty registry after Reset")
	}
}

func TestRegistryResetAndRestore(t *testing.T) {
	saved := append([]Entry{}, All()...)
	t.Cleanup(func() { Reset(); Register(saved...) })

	before := len(All())
	Reset()
	Register(saved...)
	after := len(All())

	if before != after {
		t.Errorf("restore failed: before=%d after=%d", before, after)
	}
}
