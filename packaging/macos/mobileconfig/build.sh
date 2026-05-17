#!/usr/bin/env bash
set -euo pipefail

# Render and (optionally) sign the ai-proxy .mobileconfig profile.
#
# Required env vars:
#   VERSION              — semver for output filename
#   CA_CERT              — path to the CA cert (PEM) to embed
#
# Required when SKIP_SIGN is unset (the release path):
#   APPLICATION_IDENTITY — "Developer ID Application: ..." cert name in keychain
#
# Optional:
#   SKIP_SIGN=1          — produce an unsigned .mobileconfig. Used by
#                          PR-event CI to exercise the template substitution,
#                          base64 CA encoding, and plutil-lint path without
#                          requiring Apple signing secrets. The resulting
#                          profile cannot be installed on a real Mac; it is
#                          for structural verification only.

: "${VERSION:?VERSION required}"
: "${CA_CERT:?CA_CERT required (path to PEM)}"
SKIP_SIGN="${SKIP_SIGN:-0}"

if [ "$SKIP_SIGN" != "1" ]; then
  : "${APPLICATION_IDENTITY:?APPLICATION_IDENTITY required (set SKIP_SIGN=1 for unsigned dry-run)}"
fi

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
TMPL="$ROOT/packaging/macos/mobileconfig/ai-proxy.mobileconfig.tmpl"
DIST="$ROOT/dist"
mkdir -p "$DIST"
OUT="$DIST/ai-proxy-${VERSION}.mobileconfig"

CA_DER_BASE64=$(openssl x509 -in "$CA_CERT" -outform DER | base64 | tr -d '\n')

sed \
  -e "s/__PROFILE_UUID__/$(uuidgen)/" \
  -e "s/__CA_PAYLOAD_UUID__/$(uuidgen)/" \
  -e "s/__PROXY_PAYLOAD_UUID__/$(uuidgen)/" \
  -e "s|__CA_DER_BASE64__|$CA_DER_BASE64|" \
  "$TMPL" > "$OUT.unsigned"

plutil -lint "$OUT.unsigned"

if [ "$SKIP_SIGN" = "1" ]; then
  echo "SKIP_SIGN=1 — leaving .mobileconfig unsigned."
  mv "$OUT.unsigned" "$OUT"
  echo "Built $OUT (unsigned, for structural verification only — do NOT distribute)."
else
  # CMS-sign the profile. Same Developer ID Application cert used for the binary.
  /usr/bin/security cms -S -N "$APPLICATION_IDENTITY" -i "$OUT.unsigned" -o "$OUT"
  rm "$OUT.unsigned"
  echo "Signed $OUT"
fi
