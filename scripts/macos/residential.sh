#!/usr/bin/env bash
# macOS residential split — only start / stop. Everything else is automatic.
#
#   sudo ./scripts/macos/residential.sh start
#   sudo ./scripts/macos/residential.sh stop
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo ~"$REAL_USER")"
export SHADOWPIPE_ROOT="$ROOT"
export REAL_HOME

CONFIG_DIR="${SHADOWPIPE_MACOS_CONFIG:-$REAL_HOME/.config/shadowpipe-macos}"
ENV_FILE="$CONFIG_DIR/residential.env"
RUN_DIR="$CONFIG_DIR/run"
RULES_DIR="$CONFIG_DIR/rules"
PID_FILE="$RUN_DIR/shadowpipe.pid"
LOG_FILE="$RUN_DIR/shadowpipe.log"
BIN="${SHADOWPIPE_BIN:-$ROOT/target/release/shadowpipe-client}"
URI_FILE="/private/etc/shadowpipe/client-endpoint.uri"
export SHADOWPIPE_URI_FILE="$URI_FILE"

# shellcheck source=scripts/macos/ensure-uri.sh
source "$ROOT/scripts/macos/ensure-uri.sh"

log() { echo "== $*"; }

run_as_user() {
  if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" "$@"
  else
    "$@"
  fi
}

ensure_dirs() {
  mkdir -p "$CONFIG_DIR" "$RUN_DIR" "$RULES_DIR"
  chown -R "$REAL_USER" "$CONFIG_DIR" 2>/dev/null || true
  if [[ ! -f "$ENV_FILE" ]]; then
    cp "$ROOT/scripts/macos/residential.env.example" "$ENV_FILE"
    chown "$REAL_USER" "$ENV_FILE" 2>/dev/null || true
  fi
}

ensure_rules() {
  if [[ -f "$RULES_DIR/geosite.dat" && -f "$RULES_DIR/geoip.dat" ]]; then
    local sz
    sz=$(wc -c <"$RULES_DIR/geosite.dat" | tr -d ' ')
    if [[ "$sz" -gt 1000000 ]]; then
      return 0
    fi
  fi
  log "downloading runetfreedom rules"
  RULES_DIR="$RULES_DIR" "$ROOT/scripts/macos/update-rules.sh"
  chown -R "$REAL_USER" "$RULES_DIR" 2>/dev/null || true
}

ensure_binary() {
  if [[ -x "$BIN" ]]; then
    if ! find "$ROOT/crates/shadowpipe-client" "$ROOT/crates/shadowpipe-core" \
        -name '*.rs' -newer "$BIN" 2>/dev/null | grep -q .; then
      return 0
    fi
    log "rebuilding shadowpipe-client (sources changed)"
  else
    log "building shadowpipe-client (release)"
  fi
  run_as_user bash -c "cd '$ROOT' && cargo build --release -p shadowpipe-client"
  [[ -x "$BIN" ]] || { echo "ERROR: build failed: $BIN" >&2; exit 1; }
}

save_system_state() {
  "$ROOT/scripts/macos/save-dns-state.sh"
  "$ROOT/scripts/macos/save-proxy-state.sh"
}

healthcheck() {
  local ok=0
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if run_as_user dig +time=2 +tries=1 +short @127.0.0.1 -p 1053 yandex.ru 2>/dev/null | grep -qE '^[0-9]'; then
      ok=1
      break
    fi
    sleep 1
  done
  if [[ "$ok" -ne 1 ]]; then
    echo "WARN: split DNS not responding on 127.0.0.1:1053" >&2
    tail -20 "$LOG_FILE" >&2 || true
    return 1
  fi
  if ! grep -q "handshake ok" "$LOG_FILE" 2>/dev/null; then
    echo "WARN: NL tunnel handshake not seen yet — see $LOG_FILE" >&2
  fi
  local ip
  ip="$(run_as_user dig +short @127.0.0.1 -p 1053 twitter.com 2>/dev/null | head -1)"
  if [[ -n "$ip" ]]; then
    if route -n get "$ip" 2>/dev/null | grep -q utun; then
      log "proxy route OK twitter.com -> $ip via utun"
    else
      echo "WARN: $ip (twitter.com) not routed via utun — proxy may fail" >&2
    fi
  fi
}

cmd_start() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: run with sudo: sudo $0 start" >&2
    exit 1
  fi

  ensure_dirs
  ensure_rules
  ensure_binary
  save_system_state

  local uri
  uri="$(resolve_shadowpipe_uri)" || {
    echo "ERROR: could not resolve SHADOWPIPE_URI automatically." >&2
    echo "Check SSH to ${SHADOWPIPE_NL_HOST:-203.0.113.10} or put shadowpipe://… into $ENV_FILE" >&2
    exit 1
  }
  persist_uri "$uri" "$ENV_FILE" "$URI_FILE"

  if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "already running pid $(cat "$PID_FILE") — stop first"
    exit 1
  fi

  local args=(
    --tunnel --no-guard --split
    --uri-file "$URI_FILE"
    --split-rules-dir "$RULES_DIR"
    --split-rules-list "$ROOT/scripts/macos/proxy-rules.list"
    --split-direct-rules-list "$ROOT/scripts/macos/direct-rules.list"
    --split-dns "127.0.0.1:1053"
    --split-dns-upstream "8.8.8.8:53"
    --split-dns-direct-upstream "77.88.8.8:53"
    --split-preload-list "$ROOT/scripts/macos/proxy-preload.list"
  )
  [[ "${SHADOWPIPE_SPLIT_DNS_GUARD:-1}" == "1" ]] && args+=(--split-dns-guard)
  [[ "${SHADOWPIPE_SPLIT_LEAK_GUARD:-1}" == "1" ]] && args+=(--split-leak-guard)
  [[ -n "${SHADOWPIPE_SPLIT_DNS_SERVICE:-}" ]] && args+=(--split-dns-service "$SHADOWPIPE_SPLIT_DNS_SERVICE")

  local extra=()
  if [[ -n "${SHADOWPIPE_EXTRA_ARGS:-}" ]]; then
    # shellcheck disable=SC2206
    extra=( ${SHADOWPIPE_EXTRA_ARGS} )
  fi

  log "starting split tunnel"
  : >"$LOG_FILE"
  env -u SHADOWPIPE_URI RUST_LOG="${RUST_LOG:-info}" \
    "$BIN" "${args[@]}" ${extra[@]+"${extra[@]}"} >>"$LOG_FILE" 2>&1 &
  echo $! >"$PID_FILE"
  chown "$REAL_USER" "$PID_FILE" "$LOG_FILE" 2>/dev/null || true

  if ! healthcheck; then
    echo "ERROR: split tunnel unhealthy — run: sudo $0 stop" >&2
    tail -30 "$LOG_FILE" >&2
    exit 1
  fi
  echo "OK pid $(cat "$PID_FILE") log $LOG_FILE"
}

cmd_stop() {
  if [[ -f "$PID_FILE" ]]; then
    local pid
    pid="$(cat "$PID_FILE")"
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.5
      done
      kill -KILL "$pid" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
  fi
  pkill -TERM -f "$BIN --tunnel" 2>/dev/null || true
  sleep 1
  "$ROOT/scripts/macos/cleanup-split.sh" 2>/dev/null || true
  "$ROOT/scripts/macos/repair-network.sh"
  echo "stopped"
}

cmd_repair() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: run with sudo: sudo $0 repair" >&2
    exit 1
  fi
  "$ROOT/scripts/macos/repair-network.sh"
}

case "${1:-start}" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  repair) cmd_repair ;;
  *)
    echo "Usage: sudo $0 {start|stop|repair}"
    exit 1
    ;;
esac
