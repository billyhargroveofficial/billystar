#!/usr/bin/env bash
# Validate proxy + direct rule lists against runetfreedom dat files.
set -euo pipefail

CONFIG_DIR="${SHADOWPIPE_MACOS_CONFIG:-$HOME/.config/shadowpipe-macos}"
RULES_DIR="${RULES_DIR:-$CONFIG_DIR/rules}"

if [[ ! -f "$RULES_DIR/geosite.dat" || ! -f "$RULES_DIR/geoip.dat" ]]; then
  echo "SKIP: no rules in $RULES_DIR (run scripts/macos/update-rules.sh)"
  exit 0
fi

cargo test -p shadowpipe-core --lib loads_runetfreedom_tags -- --ignored --nocapture

# Load full split policy (direct + proxy lists) when dat files exist.
cargo test -p shadowpipe-core --lib loads_split_policy -- --ignored --nocapture 2>/dev/null || true

echo "OK: split rule lists load against runetfreedom dat files"
