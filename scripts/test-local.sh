#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export SHADOWPIPE_MAGIC="${SHADOWPIPE_MAGIC:-0xcafebabe}"

echo "== build =="
cargo build -q

echo "== unit + e2e tests =="
cargo test -q

echo "== raw echo =="
TEST_DIR="$(mktemp -d -t shadowpipe-test-local.XXXXXX)"
TEST_DIR="$(cd "$TEST_DIR" && pwd -P)"
SERVER_LOG="${TEST_DIR}/server.log"
SERVER_KEYS="${TEST_DIR}/keys.json"
CLIENT_CREDENTIAL="${TEST_DIR}/client-credential.json"
CLIENT_ENROLLMENT="${TEST_DIR}/client-enrollment.json"
CLIENT_ALLOWLIST="${TEST_DIR}/client-allowlist.json"
PORT="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
SP=""
cleanup() {
  if [[ -n "$SP" ]]; then
    kill "$SP" 2>/dev/null || true
    wait "$SP" 2>/dev/null || true
  fi
  rm -rf "$TEST_DIR"
}
trap cleanup EXIT

./target/debug/shadowpipe-client \
  --generate-client-credential \
  --client-credential "$CLIENT_CREDENTIAL" \
  --write-client-enrollment "$CLIENT_ENROLLMENT"
./target/debug/shadowpipe-server \
  --development-user-allowlist \
  --client-allowlist "$CLIENT_ALLOWLIST" \
  --enroll-client "$CLIENT_ENROLLMENT"

RUST_LOG=warn ./target/debug/shadowpipe-server \
  --listen "127.0.0.1:${PORT}" --keys "$SERVER_KEYS" \
  --development-user-allowlist --allow-insecure-lab-carriers \
  --client-allowlist "$CLIENT_ALLOWLIST" \
  >"$SERVER_LOG" 2>&1 &
SP=$!
SERVER_FP=""
for _ in $(seq 1 50); do
  SERVER_FP="$(awk '/^server-fp: [0-9a-f]{64}$/{print $2; exit}' "$SERVER_LOG")"
  [[ -n "$SERVER_FP" ]] && break
  if ! kill -0 "$SP" 2>/dev/null; then
    echo "FAIL: server exited before publishing fingerprint" >&2
    sed -n '1,120p' "$SERVER_LOG" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ ! "$SERVER_FP" =~ ^[0-9a-f]{64}$ ]]; then
  echo "FAIL: server did not publish a valid fingerprint" >&2
  sed -n '1,120p' "$SERVER_LOG" >&2
  exit 1
fi

OUT=$(RUST_LOG=info ./target/debug/shadowpipe-client \
  --server "127.0.0.1:${PORT}" --server-fp "$SERVER_FP" \
  --development-user-credential --client-credential "$CLIENT_CREDENTIAL" \
  --camouflage raw --message "it-works" 2>&1)
echo "$OUT"
echo "$OUT" | grep -q 'echo: it-works'

echo "== h2 echo =="
OUT2=$(RUST_LOG=info ./target/debug/shadowpipe-client \
  --server "127.0.0.1:${PORT}" --server-fp "$SERVER_FP" \
  --development-user-credential --client-credential "$CLIENT_CREDENTIAL" \
  --camouflage h2 --message "h2-works" 2>&1)
echo "$OUT2"
echo "$OUT2" | grep -q 'echo: h2-works'

echo ""
echo "ALL OK: raw + h2 echo + mux/session e2e"
echo "TUN (isolated Linux only): production server/client must use --reality; raw/h2/tls/quic daemon carriers are no-TUN lab-only"
