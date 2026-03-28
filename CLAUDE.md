# AI Anonymizing Proxy — Project Invariants

## Token Format

- Pattern: `[PII_TYPE_XXXXXXXXXXXXXXXX]` — 16 hex characters
- Maximum token length: **33 bytes** — `[PII_` (5) + `CREDITCARD` (10) + `_` (1) + 16 hex + `]` (1)
- `tokenSuffixLen`: **33 bytes** (streaming accumulator guard)
- Hash algorithm: MD5, first 16 hex characters (deterministic, not cryptographic)
- Token must never match any compiled regex pattern (`TestTokenFormatNonRetriggering` enforces this)

## Pack System

- All PII detection patterns live in `internal/anonymizer/packs/`
- Packs self-register via `init()` calling `packs.Register()`
- Pack loader in `anonymizer.go` imports packs via blank import
- Configuration: `enabledPacks` in `proxy-config.json` (default: `["GLOBAL", "DE", "SECRETS"]`)
- Zero enabled packs at startup is fatal (`log.Fatalf` in `cmd/proxy/main.go`)
- Likelihood multiplier: `effectiveConfidence = baseConfidence * (1.0 - (position-1) * packDecayRate)`

## Available Packs

| Pack | Status | Content |
|---|---|---|
| GLOBAL | Enabled by default | Email, API key, credit card (Luhn validated) |
| DE | Enabled by default | Steuer-ID (ISO 7064 MOD 11,10), SVNR, KFZ |
| SECRETS | Enabled by default | SSH keys, JWT, bearer tokens, DB connection strings, AWS keys, GitHub tokens |
| US | Available | Phone, SSN, ZIP, address, IPv4, IPv6 |
| FR | Available | NIR (mod 97 validated, Corsica 2A/2B), SIRET, SIREN |
| NL | Planned (PR 3) | BSN, KvK |
| FINANCE_EU | Planned (PR 3) | IBAN, SWIFT/BIC, VAT IDs |
| HEALTHCARE | Planned (PR 3) | MRN, ICD-10, insurance identifiers |

## Architecture Constraints

- Every source file lives in its `internal/` package (never at repo root)
- Re-hydration happens in local memory only — no PII leaves the process
- No real PII in test corpus — synthetic, checksum-valid values only
- `validate` field on pack `Entry` is nilable — nil means no validation required
- Persistent cache uses bbolt with S3-FIFO eviction layer

## Quality Gates

- `go test -race ./...` must pass
- `TestTokenFormatNonRetriggering` must pass for every PII type
- Coverage minimums: `internal/anonymizer` 95%, `internal/config` 95%, `internal/anonymizer/packs` 95%, overall 85%
- Delta coverage: 90% on all changed/new files
