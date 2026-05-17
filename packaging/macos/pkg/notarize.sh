#!/usr/bin/env bash
set -euo pipefail

# Submit a signed .pkg for Apple notarization, then staple the ticket.
# Stapling is what lets the package install offline — without it, every install
# host has to call out to Apple to verify the notarization status.
#
# Required env vars:
#   PKG_PATH        — path to the signed .pkg
#   NOTARY_PROFILE  — name of a keychain profile previously created via
#                     `xcrun notarytool store-credentials`

: "${PKG_PATH:?PKG_PATH required}"
: "${NOTARY_PROFILE:?NOTARY_PROFILE required (created via 'notarytool store-credentials')}"

xcrun notarytool submit "$PKG_PATH" \
  --keychain-profile "$NOTARY_PROFILE" \
  --wait

xcrun stapler staple "$PKG_PATH"
xcrun stapler validate "$PKG_PATH"
spctl --assess --type install --verbose=2 "$PKG_PATH"

echo "Notarized + stapled: $PKG_PATH"
