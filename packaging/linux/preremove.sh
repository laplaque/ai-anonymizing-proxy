#!/bin/sh
set -eu

# On Debian, $1 is "remove" or "purge". On RPM, $1 is the count of remaining
# instances. Either way the action is the same: stop + disable the service.
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet ai-proxy.service 2>/dev/null; then
    systemctl stop ai-proxy.service || true
  fi
  if systemctl is-enabled --quiet ai-proxy.service 2>/dev/null; then
    systemctl disable ai-proxy.service >/dev/null 2>&1 || true
  fi
fi

# Remove CA from trust store. The cert+key under /etc/ai-proxy/ stay — they
# are user data and conffile semantics handle their removal on purge.
# Cover all three anchor directories since the file may have been placed in
# any one of them depending on the distro family detected at install time.
if command -v update-ca-certificates >/dev/null 2>&1; then
  rm -f /usr/local/share/ca-certificates/ai-proxy.crt
  rm -f /etc/pki/trust/anchors/ai-proxy.crt
  update-ca-certificates --fresh >/dev/null 2>&1 || update-ca-certificates >/dev/null 2>&1 || true
elif command -v update-ca-trust >/dev/null 2>&1; then
  rm -f /etc/pki/ca-trust/source/anchors/ai-proxy.crt
  update-ca-trust >/dev/null 2>&1 || true
fi

exit 0
