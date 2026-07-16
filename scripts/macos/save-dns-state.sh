#!/usr/bin/env bash
# Save network DNS settings before split pins 127.0.0.1 (for cleanup on stop).
set -euo pipefail

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo ~"$REAL_USER")"
CONFIG_DIR="${SHADOWPIPE_MACOS_CONFIG:-$REAL_HOME/.config/shadowpipe-macos}"
STATE_FILE="$CONFIG_DIR/dns-restore.env"
SERVICE="${SHADOWPIPE_SPLIT_DNS_SERVICE:-}"

run_as_user() {
  if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" "$@"
  else
    "$@"
  fi
}

detect_service() {
  if [[ -n "$SERVICE" ]]; then
    echo "$SERVICE"
    return 0
  fi
  local iface
  iface="$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')"
  [[ -n "$iface" ]] || return 1
  networksetup -listallhardwareports | awk -v dev="$iface" '
    /^Hardware Port: / { hp=$0; sub(/^Hardware Port: /, "", hp) }
    /^Device: / && $2 == dev { print hp; exit }
  '
}

save_v4() {
  local svc="$1"
  local out
  out="$(run_as_user networksetup -getdnsservers "$svc" 2>/dev/null || true)"
  if printf '%s\n' "$out" | grep -qi "there aren't any dns servers"; then
    echo "V4_MODE=empty"
  else
    local servers
    servers="$(printf '%s\n' "$out" | sed '/^$/d' | tr '\n' ' ' | sed 's/ $//')"
    printf 'V4_MODE=servers\nV4_SERVERS=%q\n' "$servers"
  fi
}

save_v6() {
  local svc="$1"
  local out
  out="$(run_as_user networksetup -getv6dnsservers "$svc" 2>/dev/null || true)"
  if [[ -z "$out" ]] || printf '%s\n' "$out" | grep -qi "there aren't any dns servers"; then
    echo "V6_MODE=empty"
  else
    local servers
    servers="$(printf '%s\n' "$out" | sed '/^$/d' | tr '\n' ' ' | sed 's/ $//')"
    printf 'V6_MODE=servers\nV6_SERVERS=%q\n' "$servers"
  fi
}

main() {
  mkdir -p "$CONFIG_DIR"
  local svc
  svc="$(detect_service)" || { echo "WARN: could not detect network service for DNS backup" >&2; return 0; }
  {
    echo "SERVICE=$(printf '%q' "$svc")"
    save_v4 "$svc"
    save_v6 "$svc"
  } >"$STATE_FILE"
  chown "$REAL_USER" "$STATE_FILE" 2>/dev/null || true
}

main "$@"
