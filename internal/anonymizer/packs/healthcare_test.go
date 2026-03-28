package packs

import "testing"

func TestHEALTHCAREPackRegistered(t *testing.T) {
	entries := All()
	packEntries := filterPack(entries, "HEALTHCARE")
	if len(packEntries) == 0 {
		t.Fatal("HEALTHCARE pack has no registered entries")
	}

	names := make(map[string]bool)
	for _, e := range packEntries {
		names[e.Name] = true
	}
	for _, want := range []string{"mrn", "icd10", "insurance_id"} {
		if !names[want] {
			t.Errorf("HEALTHCARE pack missing pattern %q", want)
		}
	}
}

func TestHEALTHCAREMRNPattern(t *testing.T) {
	entry := findEntry("mrn", "HEALTHCARE")
	if entry == nil {
		t.Fatal("mrn entry not found in HEALTHCARE pack")
	}

	positives := []string{
		"MRN123456",
		"MRN-1234567890",
		"MR 12345678",
		"PAT#987654",
		"mrn:123456",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("mrn pattern should match %q", s)
		}
	}

	negatives := []string{
		"MRN12345",     // too few digits (5)
		"MRN12345678901", // too many digits (11)
		"ABC123456",    // wrong prefix
	}
	for _, s := range negatives {
		if entry.Re.MatchString(s) {
			t.Errorf("mrn pattern should NOT match %q", s)
		}
	}
}

func TestHEALTHCAREICD10Pattern(t *testing.T) {
	entry := findEntry("icd10", "HEALTHCARE")
	if entry == nil {
		t.Fatal("icd10 entry not found in HEALTHCARE pack")
	}

	positives := []string{
		"diagnosis: A01",
		"ICD-10 J18.9",
		"dx: M54.5",
		"code E11.65",
		"ICD10 Z00",
		"Diagnosis:F32.1",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("icd10 pattern should match %q", s)
		}
	}

	negatives := []string{
		"A01.2",       // no context keyword
		"random Z00",  // no context keyword
	}
	for _, s := range negatives {
		if entry.Re.MatchString(s) {
			t.Errorf("icd10 pattern should NOT match %q", s)
		}
	}
}

func TestHEALTHCAREInsuranceIDPattern(t *testing.T) {
	entry := findEntry("insurance_id", "HEALTHCARE")
	if entry == nil {
		t.Fatal("insurance_id entry not found in HEALTHCARE pack")
	}

	positives := []string{
		"insurance ID12345678",
		"policy AB-123456789",
		"member XY12345678",
		"EHIC DE123456789012",
		"subscriber ID1234567890",
	}
	for _, s := range positives {
		if !entry.Re.MatchString(s) {
			t.Errorf("insurance_id pattern should match %q", s)
		}
	}

	negatives := []string{
		"ID12345678",       // no keyword prefix
		"insurance 12345",  // too few digits
	}
	for _, s := range negatives {
		if entry.Re.MatchString(s) {
			t.Errorf("insurance_id pattern should NOT match %q", s)
		}
	}
}
