# Multi-Language Integration Test Set

## Purpose
Cross-pack integration tests verifying that patterns from different packs do not
interfere with each other when all packs are enabled simultaneously.

## Test Configuration
- `UseAI: false`
- `PackDecayRate: 0.0`
- `EnabledPacks: ["GLOBAL", "US", "DE", "FR", "NL", "FINANCE_EU", "HEALTHCARE", "SECRETS"]`

## Cross-Pack Interference Matrix

### Existing Issues (from prior PRs)

| # | Issue | Packs | Status |
|---|-------|-------|--------|
| #67 | DE steuer_id/svnr lack space-tolerant regexes | DE | Known, not fixed |
| #68 | US address_us false-positives on German "ist" | US x DE | Known, not fixed |
| #69 | FR siren Luhn-invalid falls through to US ssn | FR x US | Known, not fixed |
| #70 | GLOBAL api_key "token" keyword steals SECRETS ghp_ tokens | GLOBAL x SECRETS | Known, not fixed |

### New Cross-Pack Cases (PR 3)

| Test | Packs | Description | Finding |
|------|-------|-------------|---------|
| BSN vs SIREN | NL x FR | Both match 9-digit sequences. Elfproef (BSN) and Luhn (SIREN) validators differentiate. Pack order determines priority for values passing both. | FINDING: Validators prevent most cross-matches. |
| IBAN vs credit_card | FINANCE_EU x GLOBAL | IBAN starts with 2 letters; credit_card regex matches digits only. No overlap on full IBANs. | FINDING: No interference. Alpha prefix prevents credit_card match. |
| MRN vs SSN | HEALTHCARE x US | MRN requires keyword prefix (MRN/MR/PAT). Bare 9-digit sequences go to SSN. | FINDING: No interference. Keyword gate differentiates. |
| KvK vs other 8-digit | NL x various | KvK is 8 digits, very broad. Low confidence (0.45) routes to AI. | KNOWN GAP: Broad pattern, mitigated by low confidence. |
| SWIFT/BIC vs normal text | FINANCE_EU x prose | 8-char all-caps sequences may match SWIFT. Moderate confidence (0.65) routes to AI. | KNOWN GAP: May match all-caps words. |
| VAT ID vs DE Steuer-ID | FINANCE_EU x DE | VAT DE format (`DE\d{9}`) is 11 chars; Steuer-ID is 11 digits. VAT requires "DE" prefix. | FINDING: No interference. Alpha prefix differentiates. |
| Insurance ID vs credit_card | HEALTHCARE x GLOBAL | Insurance ID requires keyword prefix. No overlap with bare digit sequences. | FINDING: No interference. |
