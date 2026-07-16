#!/usr/bin/env bash
# Connect the shadowpipe client from a one-paste REALITY URI.
# This is a fail-closed *manual single-endpoint* path for enrollment/diagnosis;
# it is not the signed endpoint-policy production service or a rotation plane.
#
#   sudo ./examples/connect-client.sh \
#     'shadowpipe://<pubkey>@host:port?sni=..&sid=..&fp=..' \
#     /etc/shadowpipe/client-credential.json [extra client flags]
#
# The URI (printed by the server / install-vps.sh) fills server, REALITY pubkey,
# short-id, SNI and the inner ML-KEM fingerprint. The separate private per-device
# credential is mandatory and is deliberately never embedded in the URI.
# Needs root: it creates a TUN device and installs split-default routes.
#
# The helper deliberately enables the Linux fail-closed requirements instead
# of offering an unsafe convenient default. Override the in-tunnel resolver
# only with a separately reviewed value:
#   SHADOWPIPE_TUN_DNS=10.8.0.1 sudo -E ./examples/connect-client.sh ...
set -euo pipefail

URI="${1:?usage: connect-client.sh 'shadowpipe://...' /path/to/client-credential.json [extra client flags]}"
CREDENTIAL="${2:?usage: connect-client.sh 'shadowpipe://...' /path/to/client-credential.json [extra client flags]}"
shift 2
TUN_DNS="${SHADOWPIPE_TUN_DNS:-1.1.1.1}"

# Prefer an installed binary; fall back to a local release build.
BIN="$(command -v shadowpipe-client || true)"
if [[ -z "$BIN" ]]; then
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  BIN="$ROOT/target/release/shadowpipe-client"
  [[ -x "$BIN" ]] || { echo "shadowpipe-client not found (install it or 'cargo build --release -p shadowpipe-client')"; exit 1; }
fi

exec "$BIN" --uri "$URI" --client-credential "$CREDENTIAL" \
  --tunnel --ipv6-mode block --auto-route --kill-switch --dns "$TUN_DNS" "$@"
