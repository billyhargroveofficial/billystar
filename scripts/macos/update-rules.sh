#!/usr/bin/env bash
# Download runetfreedom rule data for shadowpipe split (native Rust, no sing-box).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONFIG_DIR="${SHADOWPIPE_MACOS_CONFIG:-$HOME/.config/shadowpipe-macos}"
RULES_DIR="${RULES_DIR:-$CONFIG_DIR/rules}"
RULES_LIST="${RULES_LIST:-$ROOT/scripts/macos/proxy-rules.list}"
BASE="${RULES_BASE:-https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release}"

mkdir -p "$RULES_DIR" "$CONFIG_DIR"

echo "== geosite.dat + geoip.dat (v2ray protobuf, used by shadowpipe --split) =="
for f in geosite.dat geoip.dat; do
  tmp="${RULES_DIR}/${f}.part"
  curl -fsSL --retry 3 "${BASE}/${f}" -o "$tmp"
  mv "$tmp" "${RULES_DIR}/${f}"
  echo "  OK  ${f} ($(wc -c < "${RULES_DIR}/${f}") bytes)"
done

echo "== proxy list: $RULES_LIST =="
date -u +%Y-%m-%dT%H:%M:%SZ > "$CONFIG_DIR/.updated"
echo "== done → $RULES_DIR + $CONFIG_DIR =="
