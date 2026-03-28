# NL Pack Test Set

## Pack: NL (Netherlands)

### Patterns

| Pattern | PII type | Validator | Confidence |
|---------|----------|-----------|------------|
| `bsn`   | `BSN`    | elfproef (mod 11) | 0.70 |
| `kvk`   | `KVK`    | None | 0.45 |

### Test Categories

#### 1. Happy Path
- `123456782` — elfproef-valid BSN (sum=154, 154%11=0)
- `111222333` — elfproef-valid BSN (sum=66, 66%11=0)
- `010464554` — elfproef-valid BSN (sum=99, 99%11=0)
- `12345678` — 8-digit KvK number

#### 2. Spaced/Formatted
- N/A — BSN and KvK are contiguous digit sequences with no formatting variants.

#### 3. Validator Reject
- `123456789` — elfproef-invalid BSN (sum=147, 147%11=4)
- `000000000` — all zeros (sum=0, rejected by sum!=0 check)

#### 4. Boundary
- `12345678` — 8 digits: KvK match, not BSN
- `1234567890` — 10 digits: no match for either pattern

#### 5. Negative
- `1234567` — 7 digits: too short for KvK
- `12345678A` — non-numeric: no match

#### 6. Cross-Pattern
- `123456782` (BSN) vs FR SIREN (also 9 digits): BSN passes elfproef, may also match SIREN regex.
  FINDING: Both patterns match 9-digit sequences. Validators differentiate: elfproef for BSN,
  Luhn for SIREN. Pack order determines priority.

### Known Gaps
- KNOWN GAP: KvK 8-digit pattern is very broad, overlapping with many numeric sequences.
  Low confidence (0.45) mitigates via AI verification routing.
