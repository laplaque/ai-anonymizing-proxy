#!/usr/bin/env bash
set -euo pipefail

# Build a signed Apple Installer .pkg for ai-proxy.
#
# Required env vars (set by Makefile or CI):
#   VERSION              — semver, no 'v' prefix
#   ARCH                 — universal | arm64 | amd64 (default: universal)
#   INSTALLER_IDENTITY   — name of "Developer ID Installer: ..." cert in keychain
#   APPLICATION_IDENTITY — name of "Developer ID Application: ..." cert
#
# Notarization is performed separately by notarize.sh.

: "${VERSION:?VERSION required}"
: "${ARCH:=universal}"

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
STAGING="$ROOT/build/macos/pkg-staging"
DIST="$ROOT/dist"
PKG_ID="com.ai-anonymizing-proxy.pkg"

rm -rf "$STAGING"
mkdir -p "$STAGING" "$DIST" "$ROOT/bin"

# 1. Build binary (universal by default)
case "$ARCH" in
  universal)
    GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" \
      -o "$ROOT/bin/ai-proxy-amd64" ./cmd/proxy
    GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" \
      -o "$ROOT/bin/ai-proxy-arm64" ./cmd/proxy
    lipo -create -output "$ROOT/bin/ai-proxy" \
      "$ROOT/bin/ai-proxy-amd64" "$ROOT/bin/ai-proxy-arm64"
    ;;
  arm64|amd64)
    GOOS=darwin GOARCH="$ARCH" CGO_ENABLED=0 go build -ldflags="-s -w" \
      -o "$ROOT/bin/ai-proxy" ./cmd/proxy
    ;;
  *)
    echo "Unknown ARCH: $ARCH" >&2
    exit 1
    ;;
esac

# 2. Sign the binary with Developer ID Application + hardened runtime
codesign --sign "${APPLICATION_IDENTITY:?APPLICATION_IDENTITY required}" \
  --options runtime --timestamp --force \
  "$ROOT/bin/ai-proxy"

# 3. Stage payload
install -d -m 0755 "$STAGING/usr/local/bin"
install -m 0755 "$ROOT/bin/ai-proxy" "$STAGING/usr/local/bin/ai-proxy"

install -d -m 0755 "$STAGING/Library/LaunchDaemons"
install -m 0644 "$ROOT/packaging/macos/pkg/com.ai-anonymizing-proxy.plist" \
  "$STAGING/Library/LaunchDaemons/com.ai-anonymizing-proxy.plist"

install -d -m 0755 "$STAGING/etc/ai-proxy"
install -m 0644 "$ROOT/packaging/macos/pkg/proxy-config.json.default" \
  "$STAGING/etc/ai-proxy/proxy-config.json"
install -m 0644 "$ROOT/packaging/macos/pkg/ai-proxy.env" \
  "$STAGING/etc/ai-proxy/ai-proxy.env"

# Ship the uninstall script — pkgbuild has no native uninstall hook on macOS.
install -d -m 0755 "$STAGING/usr/local/share/ai-proxy"
install -m 0755 "$ROOT/packaging/macos/pkg/scripts/preuninstall" \
  "$STAGING/usr/local/share/ai-proxy/uninstall.sh"

# 4. Build the component package
COMPONENT="$DIST/ai-proxy-component.pkg"
pkgbuild \
  --root "$STAGING" \
  --identifier "$PKG_ID" \
  --version "$VERSION" \
  --install-location "/" \
  --scripts "$ROOT/packaging/macos/pkg/scripts" \
  "$COMPONENT"

# 5. Build the distribution package, signed with Developer ID Installer
PRODUCT="$DIST/ai-proxy-${VERSION}-${ARCH}.pkg"
productbuild \
  --distribution "$ROOT/packaging/macos/pkg/distribution.xml" \
  --package-path "$DIST" \
  --sign "${INSTALLER_IDENTITY:?INSTALLER_IDENTITY required}" \
  "$PRODUCT"

# Component package is an intermediate; the distribution PKG is the deliverable.
rm -f "$COMPONENT"

# 6. Verify signature
pkgutil --check-signature "$PRODUCT"

echo "Built $PRODUCT"
echo "Next: notarize.sh"
