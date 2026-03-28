# HEALTHCARE Pack Test Set

## Pack: HEALTHCARE (Medical Identifiers)

### Patterns

| Pattern | PII type | Validator | Confidence |
|---------|----------|-----------|------------|
| `mrn` | `MRN` | None (keyword-gated) | 0.85 |
| `icd10` | `ICD10` | None (keyword-gated) | 0.75 |
| `insurance_id` | `INSURANCEID` | None (keyword-gated) | 0.70 |

### Test Categories

#### 1. Happy Path
- `MRN123456` — MRN with contiguous prefix
- `MRN-1234567890` — MRN with dash separator, 10 digits
- `MR 12345678` — MR prefix with space
- `PAT#987654` — PAT prefix with hash separator
- `mrn:123456` — lowercase MRN prefix with colon
- `diagnosis: J18.9` — ICD-10 with diagnosis keyword
- `dx: M54.5` — ICD-10 with dx keyword
- `ICD-10 E11.65` — ICD-10 with explicit prefix
- `code E11.65` — ICD-10 with code keyword
- `insurance ID12345678` — insurance keyword + ID
- `policy AB-123456789` — policy keyword + alpha prefix
- `member XY12345678` — member keyword
- `EHIC DE123456789012` — European Health Insurance Card
- `subscriber ID1234567890` — subscriber keyword

#### 2. Spaced/Formatted
- `MRN 123456` — MRN with space separator (matched)
- `MR-12345678` — MR with dash separator (matched)

#### 3. Validator Reject
- N/A — HEALTHCARE patterns use keyword-gating instead of checksum validation.

#### 4. Boundary
- `MRN12345` — 5 digits: below 6-digit minimum, no match
- `MRN12345678901` — 11 digits: above 10-digit maximum, no match

#### 5. Negative
- `ABC123456` — wrong prefix for MRN
- `A01.2` — ICD-10 code without keyword context
- `random Z00` — ICD-10 code without keyword context
- `ID12345678` — no insurance/policy/member keyword

#### 6. Cross-Pattern
- MRN with 9 digits vs US SSN: MRN requires keyword prefix (MRN/MR/PAT), so bare 9-digit
  sequences are caught by SSN. MRN-prefixed 9-digit sequences are caught by MRN.
  FINDING: No interference. Keyword prefix differentiates MRN from SSN.

### Known Gaps
- KNOWN GAP: MRN format varies widely between hospital systems. The 3-prefix approach
  (MRN/MR/PAT) covers common cases but may miss institution-specific prefixes.
- KNOWN GAP: ICD-10 codes without keyword context are not detected. This is intentional
  to avoid false positives on arbitrary letter+digit sequences.
