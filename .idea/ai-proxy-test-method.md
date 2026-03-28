# AI Proxy Test Method

## 1. Pipeline Semantics

The anonymization pipeline processes text in two stages:
1. **Regex pass** — fast, per-pattern detection with confidence scoring
2. **AI verification** — low-confidence matches routed to Ollama cache (async, never blocks)

Tests use `UseAI: false` to isolate the regex stage. Patterns with validators (checksum
algorithms) reject false positives before tokenization.

## 2. Test Harness Pattern

### 2.1 Pack Unit Tests
Located in `internal/anonymizer/packs/*_test.go`. Test individual validator functions
and regex pattern matching. Use `filterPack()` and `findEntry()` helpers.

### 2.2 Integration Tests
Located in `internal/anonymizer/*_report_test.go`. Test full pipeline round-trip:
`AnonymizeText` → verify PII removed → `DeanonymizeText` → verify PII restored.

### 2.3 Test Case Struct (`tc`)
```go
type tc struct {
    name  string
    input string
    pii   string // substring that must be anonymized (empty = negative case)
    notes string
}
```

Standard configuration for all report tests:
```go
Options{
    UseAI:        false,
    PackDecayRate: 0.0,
    EnabledPacks:  []string{"GLOBAL", "US", "DE", "FR", "NL", "FINANCE_EU", "HEALTHCARE", "SECRETS"},
}
```

## 3. Test Case Design Rules

### 3.1 Required Categories
Every pack test set must cover:
1. **Happy path** — valid values that should be detected and anonymized
2. **Spaced/formatted** — values with spaces, hyphens, or other formatting
3. **Validator reject** — regex matches that fail checksum validation
4. **Boundary** — edge cases at pattern length limits
5. **Negative** — values that should NOT match the pattern
6. **Cross-pattern** — values that could match patterns from other packs

### 3.2 Naming Conventions
- Validator reject notes: explain why the value fails (algorithm, specific check)
- Cross-pattern findings: prefix with `FINDING:` in notes
- Known gaps: prefix with `KNOWN GAP:` in notes

## 4. Cross-Pattern Interference Rules

When multiple packs are enabled, patterns may compete for the same input. Rules:
1. First matching pattern wins (patterns evaluated in pack registration order)
2. Validators prevent false matches (a value matching regex but failing checksum is skipped)
3. Pack decay rate reduces confidence for later packs (0.0 in tests to isolate behavior)
4. Document all cross-pattern interactions in testset docs with `FINDING:` prefix

## 5. Known Issues

| # | Issue | Packs | Status |
|---|-------|-------|--------|
| #67 | DE steuer_id/svnr lack space-tolerant regexes | DE | Open |
| #68 | US address_us false-positives on German "ist" | US x DE | Open |
| #69 | FR siren Luhn-invalid falls through to US ssn | FR x US | Open |
| #70 | GLOBAL api_key "token" keyword steals SECRETS ghp_ tokens | GLOBAL x SECRETS | Open |
| — | NL KvK 8-digit pattern is very broad | NL | By design (low confidence 0.45) |
| — | SWIFT/BIC 8-char may match all-caps words | FINANCE_EU | By design (moderate confidence 0.65) |
| — | ICD-10 without keyword context not detected | HEALTHCARE | By design (keyword gate) |
| — | MRN format varies between hospital systems | HEALTHCARE | By design (3 common prefixes) |

## 6. Test Inventory

| Pack | Unit test file | Report test file | Testset doc |
|------|---------------|-----------------|-------------|
| GLOBAL | `packs/global_test.go` | — | `.idea/global-pack-testset.md` |
| DE | `packs/de_test.go` | — | `.idea/de-pack-testset.md` |
| US | `packs/us_test.go` | — | `.idea/us-pack-testset.md` |
| FR | `packs/fr_test.go` | — | `.idea/phase-2a-pr2-testset.md` |
| SECRETS | `packs/secrets_test.go` | — | — |
| NL | `packs/nl_test.go` | `nl_report_test.go` | `.idea/nl-pack-testset.md` |
| FINANCE_EU | `packs/finance_eu_test.go` | `finance_eu_report_test.go` | `.idea/finance-eu-pack-testset.md` |
| HEALTHCARE | `packs/healthcare_test.go` | `healthcare_report_test.go` | `.idea/healthcare-pack-testset.md` |
| Cross-pack | — | all report tests | `.idea/multilang-integration-testset.md` |
