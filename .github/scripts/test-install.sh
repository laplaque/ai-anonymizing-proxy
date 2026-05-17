#!/bin/bash
# Install/uninstall round-trip verification for ai-proxy packages.
# Mounted into a privileged systemd-capable container by the CI workflow.
set -euo pipefail

# --- Install --------------------------------------------------------------

if command -v apt-get >/dev/null 2>&1; then
  PKG="$(ls /dist/*_amd64.deb 2>/dev/null | head -1)"
  test -n "$PKG" || { echo "no .deb in /dist" >&2; exit 1; }
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq systemd-sysv ca-certificates
  dpkg -i "$PKG" || apt-get -f install -y -qq
  FAMILY=deb
elif command -v dnf >/dev/null 2>&1; then
  PKG="$(ls /dist/*.x86_64.rpm 2>/dev/null | head -1)"
  test -n "$PKG" || { echo "no .rpm in /dist" >&2; exit 1; }
  dnf install -y --nogpgcheck "$PKG"
  FAMILY=rpm
elif command -v yum >/dev/null 2>&1; then
  PKG="$(ls /dist/*.x86_64.rpm 2>/dev/null | head -1)"
  test -n "$PKG" || { echo "no .rpm in /dist" >&2; exit 1; }
  yum install -y --nogpgcheck "$PKG"
  FAMILY=rpm
elif command -v zypper >/dev/null 2>&1; then
  PKG="$(ls /dist/*.x86_64.rpm 2>/dev/null | head -1)"
  test -n "$PKG" || { echo "no .rpm in /dist" >&2; exit 1; }
  zypper --non-interactive install --allow-unsigned-rpm "$PKG"
  FAMILY=rpm
else
  echo "Unknown distro — none of apt-get/dnf/yum/zypper present" >&2
  exit 1
fi

# --- Verify install -------------------------------------------------------

test -x /usr/bin/ai-proxy
test -f /etc/ai-proxy/proxy-config.json
test -f /etc/ai-proxy/ca-cert.pem
test -f /etc/ai-proxy/ca-key.pem

# Env file: Debian uses /etc/default, RHEL uses /etc/sysconfig
test -s /etc/default/ai-proxy || test -s /etc/sysconfig/ai-proxy

# CA should be in the OS trust store. The anchor directory varies by distro
# family (Debian, openSUSE, RHEL); accept any of them.
trust_found=0
[ -f /usr/local/share/ca-certificates/ai-proxy.crt ] && trust_found=1
[ -f /etc/pki/trust/anchors/ai-proxy.crt ] && trust_found=1
[ -f /etc/pki/ca-trust/source/anchors/ai-proxy.crt ] && trust_found=1
if [ "$trust_found" != "1" ]; then
  echo "CA not installed into trust store" >&2
  exit 1
fi

# systemd unit installed + enabled
test -f /lib/systemd/system/ai-proxy.service
systemctl daemon-reload || true
systemctl is-enabled ai-proxy.service

# Verify the binary's --generate-ca flag is wired up (smoke)
/usr/bin/ai-proxy --generate-ca --ca-cert /tmp/test-ca.pem --ca-key /tmp/test-ca.key
test -f /tmp/test-ca.pem
test -f /tmp/test-ca.key

# --- Uninstall ------------------------------------------------------------

if [ "$FAMILY" = "deb" ]; then
  apt-get remove -y -qq ai-proxy
else
  if command -v dnf >/dev/null 2>&1; then
    dnf remove -y ai-proxy
  elif command -v yum >/dev/null 2>&1; then
    yum remove -y ai-proxy
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive remove ai-proxy
  fi
fi

# Trust-store entry and binary must be gone after remove
test ! -f /usr/local/share/ca-certificates/ai-proxy.crt
test ! -f /etc/pki/trust/anchors/ai-proxy.crt
test ! -f /etc/pki/ca-trust/source/anchors/ai-proxy.crt
test ! -x /usr/bin/ai-proxy

# Conffile semantics: /etc/ai-proxy/* stays on `remove` (purge would clean it)
echo "Install/uninstall round-trip OK on $(cat /etc/os-release | grep ^PRETTY_NAME= | cut -d= -f2)"
