#!/usr/bin/env bash
# Optional: manual pf anchor install. Split mode auto-installs on first run.
set -euo pipefail

ANCHOR="/etc/pf.anchors/shadowpipe.split"
PF_CONF="/etc/pf.conf"
MARKER="shadowpipe.split"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

mkdir -p /etc/pf.anchors
if [[ ! -f "$ANCHOR" ]]; then
  echo "# shadowpipe split DNS leak guard — rules loaded at runtime" >"$ANCHOR"
  echo "created $ANCHOR"
fi

if grep -q "$MARKER" "$PF_CONF" 2>/dev/null; then
  echo "pf.conf already references $MARKER"
else
  cp -a "$PF_CONF" "${PF_CONF}.bak.$(date +%Y%m%d-%H%M%S)"
  cat >>"$PF_CONF" <<EOF

# shadowpipe split DNS leak guard
anchor "$MARKER"
load anchor "$MARKER" from "$ANCHOR"
EOF
  echo "appended anchor to $PF_CONF (backup created)"
fi

pfctl -f "$PF_CONF" 2>/dev/null || true
pfctl -e 2>/dev/null || true
echo "OK: pf anchor ready"
