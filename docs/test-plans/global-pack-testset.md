# GLOBAL Pack Test Set

Use these messages to test GLOBAL + US pack PII detection through the proxy. All checksum values are computed programmatically.

> **Test config:** `EnabledPacks: ["SECRETS", "GLOBAL", "US", "DE", "FR"]`, `UseAI: false`, `PackDecayRate: 0.0`

---

## Email

### Should detect

"Contact: alice@example.com for info."

"Send to user.name+tag@domain.co.uk please."

"Email: test@sub.domain.org."

"Input .user@example.com here."
> Note: regex skips the leading dot, matches "user@example.com". Validator passes because local part is clean.

### Should NOT detect

"Bad: user..name@example.com."
> Validator rejects consecutive dots in local part (RFC 5321).

"Not an email: just-a-string."
> No @ symbol -- regex does not match.

---

## API Key

### Should detect

"Config: api_key=abc123def456ghi789jklmno set."

"Header: token: sk-abc123def456ghi789jklmno sent."

`Use secret="xxxxxxxxxxxxxxxxxxxxxxxx" in config.`

"Auth: bearer XYZabc123def456ghi789jk applied."

### Should NOT detect

"Set api_key=abc in config."
> Token < 20 chars. Regex `[a-zA-Z0-9_\-.]{20,}` rejects.

"Value randomlongstringwithoutprefix123 here."
> No keyword prefix (api_key, token, secret, bearer).

---

## Credit Card (Luhn validated)

### Should detect

"Card: 4111111111111111 on file."
> Visa, 16 digits, Luhn valid.

"Card: 4111 1111 1111 1111 on file."
> Same, spaced format.

"Card: 4111-1111-1111-1111 on file."
> Same, dashed format.

"Card: 5500000000000004 saved."
> Mastercard, 16 digits, Luhn valid.

"Amex: 378282246310005 on file."
> American Express, 15 digits, Luhn valid.

### Should NOT detect

"Card: 1234567890123456 fake."
> 16 digits but Luhn check fails.

"Number 123456789012 short."
> 12 digits -- below 13-digit minimum.

---

## GLOBAL api_key vs SECRETS ordering (issue #70)

With SECRETS before GLOBAL in the pipeline, the `api_key` pattern's keywords
(`token`, `secret`, `bearer`) no longer steal matches from SECRETS patterns.
SECRETS patterns (ghp_, eyJ, AKIA, Bearer, DB URIs) run first and claim their
specific matches. GLOBAL `api_key` then claims remaining generic tokens.

See `secrets_priority_report_test.go` for full coverage.

---

## Cross-pattern interference tests

"Number 362521874 in the system."
> 9 digits, Luhn-valid. SIREN pattern claims it (registered first). SSN regex also matches (area 362 is valid), but SIREN replacement already consumed the match.

"Number 362521879 in file."
> 9 digits, Luhn-invalid. SIREN validator rejects. SSN regex requires hyphens (fix #69), so contiguous form is not matched. Not detected — correct behavior.

"Call 555-123-4567 for support."
> US phone format. Detected as PHONE.

"Code 12345 ist falsch."
> FINDING: US address regex `(?i)\d+\s+[A-Za-z\s]+St\b` matches "12345 ist" because German "ist" decomposes as "i" + "St" suffix. Detected as ADDRESS. This is a false positive when processing German text.

---

## Negatives -- should NOT trigger

"The weather today looks good."
> Plain text, no PII patterns.

"Running v1.234.567.8901 release."
> Version string. US phone validator rejects dot-only separators.

---

## Edge cases

### Multiple GLOBAL types in one message

"Email alice@example.com, card 4111111111111111, key api_key=abc123def456ghi789jklmno."
> Should detect: EMAIL + CREDITCARD + APIKEY

### Email adjacent to URL

"Visit https://site.com or email admin@site.com."
> Should detect: EMAIL (admin@site.com). URL is not a PII pattern.

---

## Checksum verification reference

### Credit Card (Luhn algorithm)

| Type | Number | Luhn valid |
|---|---|---|
| Visa | 4111111111111111 | Yes |
| Mastercard | 5500000000000004 | Yes |
| Amex | 378282246310005 | Yes |
| Invalid | 1234567890123456 | No |

### Cross-pattern SIREN/SSN overlap

| Value | SIREN Luhn | SSN area valid | Claimed by |
|---|---|---|---|
| 362521874 | Yes | Yes (362) | SIREN (runs first) |
| 362521879 | No | Yes (362) | None (SSN requires hyphens, fix #69) |

## Test results (verified against commit f2fb6ea)

**27 passed, 0 warned, 0 failed out of 27**
