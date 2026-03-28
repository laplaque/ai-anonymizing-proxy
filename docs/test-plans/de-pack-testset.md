# DE Pack Test Set

## Pack: DE (Germany)

### Patterns

| Pattern | PII type | Validator | Confidence |
|---------|----------|-----------|------------|
| `steuer_id` | `STEUERID` | ISO 7064 MOD 11,10 | 0.70 |
| `svnr` | `SVNR` | None | 0.80 |
| `kfz` | `KFZ` | None | 0.75 |

### Test Categories

#### 1. Happy Path
- `65929970489` — checksum-valid Steuer-ID (ISO 7064 MOD 11,10)
- `86095742719` — checksum-valid Steuer-ID
- `12150385A123` — synthetic SVNR: area(12) + DOB(150385) + letter(A) + seq(123)
- `B AB 1234` — Kfz registration plate

#### 2. Spaced/Formatted
- `659 299 704 89` — Steuer-ID with spaces (XXX XXX XXX XX format), detected and validated
- `659-299-704-89` — Steuer-ID with hyphens, detected and validated
- `860 957 427 19` — Steuer-ID spaced, second example
- `12 150385 A 123` — SVNR with spaces between area, DOB, letter, seq
- `12-150385-A-123` — SVNR with hyphens

#### 3. Validator Reject
- `65929970488` — Steuer-ID wrong check digit (fails MOD 11,10)
- `05929970489` — Steuer-ID starts with zero (rejected by first-digit check)

#### 4. Boundary
- `6592997048` — 10 digits: too short for Steuer-ID
- `659299704891` — 12 digits: too long for Steuer-ID
- `00000000000` — all zeros (rejected: starts with zero)

#### 5. Negative
- `6592997A489` — non-numeric character in middle: no match
- `12151385A123` — SVNR with invalid month (13): no match

#### 6. Cross-Pattern
- No known cross-pattern interference documented for DE pack patterns.

### Known Gaps
- None — all previously known gaps resolved in #67 (space-tolerant regexes).
