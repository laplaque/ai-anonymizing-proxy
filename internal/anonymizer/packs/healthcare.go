package packs

import "regexp"

func init() {
	Register(
		// Medical Record Number (MRN) — common hospital formats:
		// Prefix (MRN, MR, PAT) followed by separator and 6-10 digits.
		// Source: HL7 FHIR identifier patterns, common EHR systems (Epic, Cerner).
		// Reference: silv3rshi3ld/gdpr-pii-scanner patient_id detector.
		// False-positive mitigation: requires known prefix keyword; high confidence.
		Entry{
			Name:       "mrn",
			Pack:       "HEALTHCARE",
			Re:         regexp.MustCompile(`(?i)\b(?:MRN|MR|PAT)[\s\-:#]?\d{6,10}\b`),
			PIIType:    "MRN",
			Confidence: 0.85,
		},
		// ICD-10 diagnostic code (International Classification of Diseases, 10th revision):
		// Letter + 2 digits, optionally followed by a dot and 1-4 alphanumeric characters.
		// Source: https://www.who.int/classifications/icd/en/
		// Reference: WHO ICD-10 code format documentation.
		// False-positive mitigation: requires keyword context prefix ("diagnosis", "ICD", "dx", "code")
		// to avoid matching arbitrary letter+digit sequences.
		Entry{
			Name:       "icd10",
			Pack:       "HEALTHCARE",
			Re:         regexp.MustCompile(`(?i)(?:diagnosis|icd[\s\-]?10?|dx|code)[\s:]*\b[A-Z]\d{2}(?:\.\d{1,4})?\b`),
			PIIType:    "ICD10",
			Confidence: 0.75,
		},
		// Health insurance policy/member ID — common EU and US formats:
		// Alphanumeric identifier typically 8-15 characters with optional prefix.
		// Source: EHIC (European Health Insurance Card) format, US CMS member ID formats.
		// Reference: silv3rshi3ld/gdpr-pii-scanner (GDPR special category: medical).
		// False-positive mitigation: requires keyword prefix ("insurance", "policy", "member",
		// "EHIC", "subscriber"); moderate confidence.
		Entry{
			Name:       "insurance_id",
			Pack:       "HEALTHCARE",
			Re:         regexp.MustCompile(`(?i)(?:insurance|policy|member|ehic|subscriber)[\s\-:#]*[A-Z0-9]{2,4}[\s\-]?\d{6,12}\b`),
			PIIType:    "INSURANCEID",
			Confidence: 0.70,
		},
	)
}
