#!/usr/bin/env bash
# Live service checks through RU netns tunnel (requires running shadowpipe client).
# Usage:
#   ./scripts/test-live-services.sh
#   NL_SERVER=203.0.113.10:47845 RU_HOST=example-host ./scripts/test-live-services.sh
# Remote command strings intentionally expand locally validated parameters.
# shellcheck disable=SC2029
set -euo pipefail

RU_HOST="${RU_HOST:-example-host}"
NL_SERVER="${NL_SERVER:-203.0.113.10:47845}"
NETNS="${NETNS:-sptest}"
MIN_BYTES="${MIN_BYTES:-8192}"
SERVER_FP="${SERVER_FP:?set SERVER_FP to the independently verified 64-hex server fingerprint}"
TUN_DNS="${TUN_DNS:-1.1.1.1}"
CLIENT_CREDENTIAL="${CLIENT_CREDENTIAL:-/etc/shadowpipe/client-credential.json}"
[[ "$RU_HOST" =~ ^[A-Za-z0-9_.:@-]+$ && "$RU_HOST" != -* ]] || { echo "unsafe RU_HOST" >&2; exit 1; }
[[ "$MIN_BYTES" =~ ^[0-9]+$ ]] || { echo "MIN_BYTES must be an integer" >&2; exit 1; }
[[ "$SERVER_FP" =~ ^[0-9a-f]{64}$ ]] || { echo "SERVER_FP must be 64 lowercase hex" >&2; exit 1; }
[[ "$NETNS" =~ ^[A-Za-z0-9_.:-]+$ ]] || { echo "unsafe NETNS" >&2; exit 1; }
[[ "$NL_SERVER" =~ ^[A-Za-z0-9_.:-]+$ ]] || { echo "unsafe NL_SERVER" >&2; exit 1; }
[[ "$TUN_DNS" =~ ^[0-9a-fA-F:.]+$ ]] || { echo "TUN_DNS must be a literal IP" >&2; exit 1; }
[[ "$CLIENT_CREDENTIAL" =~ ^/[A-Za-z0-9_./-]+$ && "$CLIENT_CREDENTIAL" != *'/../'* ]] \
  || { echo "CLIENT_CREDENTIAL must be an absolute normalized path" >&2; exit 1; }

run_in_netns() {
  ssh "$RU_HOST" "ip netns exec ${NETNS} $*"
}

ensure_client() {
  ssh "$RU_HOST" "
    set -e
    test -f '$CLIENT_CREDENTIAL'
    test ! -L '$CLIENT_CREDENTIAL'
    test \"\$(stat -c '%u:%a:%h' -- '$CLIENT_CREDENTIAL')\" = 0:600:1
    /usr/local/bin/shadowpipe-client --help 2>&1 | grep -Fq -- '--client-credential'
  " || {
    echo "Refusing live test: mandatory root-owned 0600 single-link client credential is missing/unsafe on $RU_HOST" >&2
    exit 1
  }
  if ! ssh "$RU_HOST" "pgrep -f 'shadowpipe-client --server'" >/dev/null 2>&1; then
    echo "Starting shadowpipe client on ${RU_HOST} netns ${NETNS}..."
    ssh "$RU_HOST" "nohup ip netns exec ${NETNS} /usr/local/bin/shadowpipe-client \
      --server ${NL_SERVER} --server-fp ${SERVER_FP} --client-credential ${CLIENT_CREDENTIAL} \
      --tunnel --auto-route \
      --kill-switch --dns ${TUN_DNS} --camouflage h2 --guard-bytes 8192 \
      >> /tmp/sp-live.log 2>&1 &"
    sleep 4
  elif ! ssh "$RU_HOST" "pgrep -af 'shadowpipe-client --server' | grep -Fq -- '--client-credential ${CLIENT_CREDENTIAL}'"; then
    echo "Refusing live test: an existing client was not started with the expected mandatory credential" >&2
    exit 1
  fi
}

check() {
  local name="$1"
  shift
  echo ""
  echo "=== ${name} ==="
  if run_in_netns "$@"; then
    echo "OK: ${name}"
  else
    echo "FAIL: ${name}" >&2
    return 1
  fi
}

ensure_client

check "exit IP (NL)" \
  curl -4 -s --max-time 20 ifconfig.me | grep -E '^[0-9]+\.' || true

check "DNS google.com" \
  getent ahostsv4 google.com

check "YouTube (googlevideo redirect HEAD)" \
  curl -4 -sI --max-time 25 https://www.youtube.com | head -1

check "YouTube watch page (first 16KB+)" \
  curl -4 -s --max-time 30 -o /dev/null -w "bytes:%{size_download}\n" \
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ" | awk -v m="$MIN_BYTES" '{gsub(/bytes:/,""); if ($1>=m) exit 0; exit 1}'

check "ChatGPT (chatgpt.com TLS)" \
  curl -4 -sI --max-time 25 https://chatgpt.com | head -1

check "OpenAI API endpoint TLS" \
  curl -4 -sI --max-time 25 https://api.openai.com | head -1

check "Claude (claude.ai TLS)" \
  curl -4 -sI --max-time 25 https://claude.ai | head -1

check "Anthropic API TLS" \
  curl -4 -sI --max-time 25 https://api.anthropic.com | head -1

check "Gemini (gemini.google.com TLS)" \
  curl -4 -sI --max-time 25 https://gemini.google.com | head -1

check "Large download (Tele2 100KB zip, byte-floor)" \
  curl -4 -s --max-time 40 -o /dev/null -w "bytes:%{size_download}\n" \
    http://speedtest.tele2.net/100KB.zip | awk -v m="100000" '{gsub(/bytes:/,""); if ($1>=m) exit 0; exit 1}'

echo ""
echo "Live service sweep done."
