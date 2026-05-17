#!/usr/bin/env bash
set -euo pipefail

# Render and sign the ai-proxy .mobileconfig profile.
#
# Required env vars:
#   VERSION              — semver for output filename
#   CA_CERT              — path to the release CA cert (PEM) to embed
#   APPLICATION_IDENTITY — "Developer ID Application: ..." cert name in keychain

: "${VERSION:?VERSION required}"
: "${CA_CERT:?CA_CERT required (path to PEM)}"
: "${APPLICATION_IDENTITY:?APPLICATION_IDENTITY required}"

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

# CMS-sign the profile. Same Developer ID Application cert used for the binary.
/usr/bin/security cms -S -N "$APPLICATION_IDENTITY" -i "$OUT.unsigned" -o "$OUT"
rm "$OUT.unsigned"

echo "Signed $OUT"
