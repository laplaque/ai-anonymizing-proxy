#!/bin/sh
set -eu

# Detect distro family for trust-store integration
TRUST_DIR=""
TRUST_NAME=ai-proxy.crt
TRUST_UPDATE=""
if command -v update-ca-certificates >/dev/null 2>&1; then
  TRUST_DIR=/usr/local/share/ca-certificates
  TRUST_UPDATE=update-ca-certificates
elif command -v update-ca-trust >/dev/null 2>&1; then
  TRUST_DIR=/etc/pki/ca-trust/source/anchors
  TRUST_UPDATE=update-ca-trust
else
  echo "WARN: no trust-store tool found (update-ca-certificates / update-ca-trust). Skipping CA trust install." >&2
fi

# Create system user if missing
if ! getent passwd ai-proxy >/dev/null 2>&1; then
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin --home-dir /var/lib/ai-proxy ai-proxy
  elif command -v adduser >/dev/null 2>&1; then
    # busybox/Alpine-style fallback
    adduser -S -H -h /var/lib/ai-proxy -s /sbin/nologin ai-proxy
  fi
fi

# Set up runtime dirs (owned by service user)
install -d -m 0755 /etc/ai-proxy
install -d -m 0750 -o ai-proxy -g ai-proxy /var/lib/ai-proxy
install -d -m 0750 -o ai-proxy -g ai-proxy /var/log/ai-proxy

# Generate CA if not already present (idempotent — preserves user CA on upgrade)
if [ ! -f /etc/ai-proxy/ca-cert.pem ] || [ ! -f /etc/ai-proxy/ca-key.pem ]; then
  /usr/bin/ai-proxy --generate-ca \
    --ca-cert /etc/ai-proxy/ca-cert.pem \
    --ca-key /etc/ai-proxy/ca-key.pem
  chmod 0644 /etc/ai-proxy/ca-cert.pem
  chmod 0640 /etc/ai-proxy/ca-key.pem
  chown ai-proxy:ai-proxy /etc/ai-proxy/ca-key.pem
fi

# Install CA into the OS trust store
if [ -n "$TRUST_UPDATE" ] && [ -n "$TRUST_DIR" ] && [ -f /etc/ai-proxy/ca-cert.pem ]; then
  install -d -m 0755 "$TRUST_DIR"
  cp /etc/ai-proxy/ca-cert.pem "$TRUST_DIR/$TRUST_NAME"
  "$TRUST_UPDATE" >/dev/null 2>&1 || "$TRUST_UPDATE"
fi

# Enable + start the service via systemd (if available)
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable ai-proxy.service >/dev/null 2>&1 || true
  # Don't fail the install if the service can't start in a chroot/container
  # without /run/systemd; the unit is enabled either way.
  systemctl start ai-proxy.service >/dev/null 2>&1 || true
fi

exit 0
