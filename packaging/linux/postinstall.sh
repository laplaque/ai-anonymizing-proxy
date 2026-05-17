#!/bin/sh
set -eu

# Detect distro family for trust-store integration. Debian and openSUSE both
# ship `update-ca-certificates` but use different anchor directories; RHEL
# uses `update-ca-trust` with a third path. Pick by the presence of the
# distro-specific anchor directory rather than by tool name alone.
TRUST_DIR=""
TRUST_NAME=ai-proxy.crt
TRUST_UPDATE=""
if [ -d /usr/local/share/ca-certificates ] && command -v update-ca-certificates >/dev/null 2>&1; then
  # Debian / Ubuntu
  TRUST_DIR=/usr/local/share/ca-certificates
  TRUST_UPDATE=update-ca-certificates
elif [ -d /etc/pki/trust/anchors ] && command -v update-ca-certificates >/dev/null 2>&1; then
  # openSUSE / SLES
  TRUST_DIR=/etc/pki/trust/anchors
  TRUST_UPDATE=update-ca-certificates
elif [ -d /etc/pki/ca-trust/source/anchors ] && command -v update-ca-trust >/dev/null 2>&1; then
  # RHEL / Fedora / Alma / Rocky
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

in_systemd_host() {
  # /run/systemd/system is the canonical "systemd is running as PID 1 right now"
  # marker. Absent inside container/chroot package-build phases (where systemctl
  # exists but cannot start services), present on a real installed host.
  [ -d /run/systemd/system ]
}

rollback_ca_trust() {
  # The CA was installed into the OS trust store but the proxy is not running
  # to intercept HTTPS traffic. Leaving the CA trusted would silently turn the
  # host into one where any holder of /etc/ai-proxy/ca-key.pem can MITM, while
  # PII flows out unanonymized. Pull the anchor before we exit non-zero.
  if [ -n "$TRUST_DIR" ] && [ -f "$TRUST_DIR/$TRUST_NAME" ]; then
    rm -f "$TRUST_DIR/$TRUST_NAME"
    if [ -n "$TRUST_UPDATE" ]; then
      "$TRUST_UPDATE" >/dev/null 2>&1 || true
    fi
    echo "ai-proxy: CA anchor removed from $TRUST_DIR to prevent trust-without-interception." >&2
  fi
}

# Install CA into the OS trust store
if [ -n "$TRUST_UPDATE" ] && [ -n "$TRUST_DIR" ] && [ -f /etc/ai-proxy/ca-cert.pem ]; then
  install -d -m 0755 "$TRUST_DIR"
  cp /etc/ai-proxy/ca-cert.pem "$TRUST_DIR/$TRUST_NAME"
  "$TRUST_UPDATE" >/dev/null 2>&1 || "$TRUST_UPDATE"
fi

# Enable + start the service via systemd. The chroot/container build case is
# distinguished from a real-host failure: in the former (no PID-1 systemd),
# enable suffices and the host's first boot will start the service; in the
# latter, a failed start MUST roll back the CA install — see CLAUDE.md
# Invariant #1 "No PII leaves the process". A package-manager SUCCESS with a
# trusted CA but no running proxy is precisely the failure mode that lets
# HTTPS LLM-API traffic carry PII off the host unanonymized.
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable ai-proxy.service >/dev/null 2>&1 || true
  if in_systemd_host; then
    if ! systemctl start ai-proxy.service; then
      echo "ai-proxy: service failed to start on a systemd-managed host." >&2
      echo "ai-proxy:   - check 'systemctl status ai-proxy' and 'journalctl -u ai-proxy'" >&2
      echo "ai-proxy:   - common causes: port collision, bad config, SELinux/AppArmor denial" >&2
      rollback_ca_trust
      exit 1
    fi
  fi
fi

exit 0
