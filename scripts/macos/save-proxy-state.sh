#!/usr/bin/env bash
# Save macOS system HTTP/SOCKS proxy state (Clash/V2Ray often sets 127.0.0.1:7890).
set -euo pipefail

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo ~"$REAL_USER")"
CONFIG_DIR="${SHADOWPIPE_MACOS_CONFIG:-$REAL_HOME/.config/shadowpipe-macos}"
STATE_FILE="$CONFIG_DIR/proxy-restore.env"
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

read_proxy() {
  local svc="$1" kind="$2"
  run_as_user networksetup -"$kind" "$svc" 2>/dev/null || true
}

main() {
  local svc
  svc="$(detect_service)" || return 0
  mkdir -p "$CONFIG_DIR"
  {
    echo "SERVICE=$(printf '%q' "$svc")"
    echo "---WEB---"
    read_proxy "$svc" getwebproxy
    echo "---SECURE---"
    read_proxy "$svc" getsecurewebproxy
    echo "---SOCKS---"
    read_proxy "$svc" getsocksfirewallproxy
  } >"$STATE_FILE"
  chown "$REAL_USER" "$STATE_FILE" 2>/dev/null || true

  # Disable system proxy while shadowpipe split is active (browser was hitting dead :7890).
  run_as_user networksetup -setwebproxystate "$svc" off >/dev/null 2>&1 || true
  run_as_user networksetup -setsecurewebproxystate "$svc" off >/dev/null 2>&1 || true
  run_as_user networksetup -setsocksfirewallproxystate "$svc" off >/dev/null 2>&1 || true
}

main "$@"
