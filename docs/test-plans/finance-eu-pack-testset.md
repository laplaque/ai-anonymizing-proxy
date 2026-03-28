# FINANCE_EU Pack Test Set

## Pack: FINANCE_EU (EU Financial Identifiers)

### Patterns

| Pattern | PII type | Validator | Confidence |
|---------|----------|-----------|------------|
| `iban` | `IBAN` | ISO 7064 MOD 97-10 | 0.85 |
| `swift_bic` | `SWIFTBIC` | None | 0.65 |
| `vat_eu` | `VATID` | None | 0.80 |

### Test Categories

#### 1. Happy Path
- `DE89370400440532013000` — valid German IBAN
- `GB29NWBK60161331926819` — valid British IBAN
- `NL91ABNA0417164300` — valid Dutch IBAN
- `FR7630006000011234567890189` — valid French IBAN
- `DEUTDEFF` — Deutsche Bank 8-char SWIFT/BIC
- `DEUTDEFF500` — Deutsche Bank 11-char SWIFT/BIC
- `COBADEFFXXX` — Commerzbank 11-char SWIFT/BIC
- `BNPAFRPPXXX` — BNP Paribas 11-char SWIFT/BIC
- `DE123456789` — German VAT ID
- `NL123456789B01` — Dutch VAT ID
- `FR12345678901` — French VAT ID
- `ATU12345678` — Austrian VAT ID
- `BE0123456789` — Belgian VAT ID
- `ES12345678A` — Spanish VAT ID

#### 2. Spaced/Formatted
- `DE89 3704 0044 0532 0130 00` — spaced IBAN (validator strips spaces)
- `GB29 NWBK 6016 1331 9268 19` — spaced IBAN

#### 3. Validator Reject
- `DE00370400440532013000` — wrong check digits (MOD 97-10 fails)

#### 4. Boundary
- `DE8937040044` — IBAN too short (below 15 char minimum)
- `DEUT` — SWIFT too short (4 chars, needs 8)
- `XX123456789` — VAT with unknown country code

#### 5. Negative
- `deutdeff` — lowercase SWIFT (regex requires uppercase)
- `12UTDEFF` — SWIFT starting with digits
- `US123456789` — non-EU country code for VAT

#### 6. Cross-Pattern
- IBAN numeric portion vs GLOBAL credit_card: IBAN starts with letters so full IBAN doesn't
  match credit_card regex. Numeric BBAN portion could theoretically match but is typically
  bounded by the IBAN structure.
  FINDING: No interference observed. The alpha country code prefix prevents credit_card matches.

### Known Gaps
- KNOWN GAP: SWIFT/BIC 8-char codes may match common English words in all-caps text
  (e.g., "TESTGBXX"). Moderate confidence (0.65) routes these to AI verification.
