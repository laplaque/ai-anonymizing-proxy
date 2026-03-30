# SECRETS Pack — Expanded Test Set (Issue #77)

## Overview

Test set for 18 new token detection patterns added to the SECRETS pack.
Each pattern has unit tests in `packs/secrets_test.go` (regex matching)
and integration tests in `anonymizer/secrets_report_test.go` (full pipeline round-trip).

## Test Categories

### Happy Path

Each pattern is tested with a synthetic token that matches the documented format.

| Pattern | Test Value | Expected PIIType |
|---------|-----------|------------------|
| `gitlab_pat` | `glpat-XXXXXXXXXXXXXXXXXXXX` | GLTOKEN |
| `gitlab_deploy` | `gldt-XXXXXXXXXXXXXXXXXXXX` | GLTOKEN |
| `slack_token` | `xoxb-123456789012-1234567890123-AbCdEfGhIjKl` | SLACKTOKEN |
| `stripe_key` | `sk_live_ABCDEFghijklmnopqrst` | STRIPEKEY |
| `npm_token` | `npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij` | NPMTOKEN |
| `pypi_token` | `pypi-[85+ chars]` | PYPITOKEN |
| `openai_key` | `sk-ABCDEFghijklmnopqrst` | OPENAIKEY |
| `docker_pat` | `dckr_pat_ABCDEFghijklmnopqrst` | DOCKERTOKEN |
| `google_api_key` | `AIzaSyD-example-key-value_1234567890ABC` | GOOGLEKEY |
| `shopify_token` | `shpat_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef` | SHOPIFYTOKEN |
| `sendgrid_key` | `SG.abcdefghij1234567890` | SENDGRIDKEY |
| `groq_key` | `gsk_ABCDEFghijklmnopqrst` | GROQKEY |
| `twilio_sid` | `AC00000000000000000000000000000000` | TWILIOTOKEN |
| `twilio_auth` | `SK00000000000000000000000000000000` | TWILIOTOKEN |
| `facebook_token` | `EAACEdEose0cBAabcdef1234567890` | FBTOKEN |
| `amazon_mws` | `amzn.mws.12345678-1234-1234-1234-123456789012` | AMZTOKEN |
| `cloudinary_url` | `cloudinary://123456789012345:abcdefGHIJ@cloud_name` | CLOUDINARYTOKEN |
| `pgp_private_key` | `-----BEGIN PGP PRIVATE KEY BLOCK-----` | PGPKEY |

### Negative Cases

Each pattern has at least one negative test verifying rejection of similar but invalid input.

| Pattern | Negative Value | Reason |
|---------|---------------|--------|
| `gitlab_pat` | `glpat-short` | <20 chars after prefix |
| `gitlab_deploy` | `gldt-tiny` | <20 chars after prefix |
| `slack_token` | `xoxz-123456789012` | `z` is not a valid Slack variant letter |
| `stripe_key` | `sk_prod_ABCDEFghijklmnopqrst` | `prod` is not live/test |
| `npm_token` | `npm_shorttoken` | <36 chars after prefix |
| `pypi_token` | `pypi-short` | <85 chars after prefix |
| `openai_key` | `sk-short` | <20 chars after prefix |
| `docker_pat` | `dckr_pat_short` | <20 chars after prefix |
| `google_api_key` | `AIzashort` | <35 chars after prefix |
| `shopify_token` | `shpxx_ABCDEF...` | `xx` is not at/ca/ss |
| `sendgrid_key` | `SG.short` | <20 chars after prefix |
| `groq_key` | `gsk_short` | <20 chars after prefix |
| `twilio_sid` | `ACzzzz...` | Non-hex chars after AC |
| `twilio_auth` | `SK1234` | <32 hex chars |
| `facebook_token` | `EAACEdEose0cBA` (alone) | No trailing chars |
| `amazon_mws` | `amzn.mws.short` | <36 chars |
| `cloudinary_url` | `cloudinary://short` | <10 chars after scheme |
| `pgp_private_key` | `-----BEGIN PGP PUBLIC KEY BLOCK-----` | PUBLIC, not PRIVATE |

### Cross-Pattern Findings

| Finding | Patterns | Notes |
|---------|----------|-------|
| FINDING: OpenAI `sk-` vs Stripe `sk_` | openai_key, stripe_key | No collision — hyphen vs underscore after `sk` |
| FINDING: Groq `gsk_` vs GitHub `ghs_` | groq_key, github_token | No collision — different 3-char prefixes |
| FINDING: Twilio `AC`/`SK` short prefix | twilio_sid, twilio_auth | Tight 32-hex requirement prevents false positives on common words |
| FINDING: `sk-` now claimed by SECRETS | openai_key vs GLOBAL api_key | `sk-` tokens with 20+ chars are now detected as OPENAIKEY by SECRETS instead of falling through to GLOBAL api_key. Updated secrets_priority_report_test.go accordingly. |

## Test Files

| File | Type | Count |
|------|------|-------|
| `internal/anonymizer/packs/secrets_test.go` | Unit (regex) | 28 tests |
| `internal/anonymizer/secrets_report_test.go` | Integration (pipeline) | 41 sub-tests |
| `internal/anonymizer/secrets_priority_report_test.go` | Cross-pack priority | Updated for sk- behavior |
