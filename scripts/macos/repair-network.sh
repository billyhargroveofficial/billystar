#!/usr/bin/env bash
# Force-fix network after shadowpipe/Clash left DNS=127.0.0.1 or dead :7890 proxy.
# Safe to run anytime: sudo ./scripts/macos/repair-network.sh
set -euo pipefail

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo ~"$REAL_USER")"
CONFIG_DIR="${SHADOWPIPE_MACOS_CONFIG:-$REAL_HOME/.config/shadowpipe-macos}"
DNS_STATE="$CONFIG_DIR/dns-restore.env"
PROXY_STATE="$CONFIG_DIR/proxy-restore.env"

run_as_user() {
  if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" "$@"
  else
    "$@"
  fi
}

detect_services() {
  networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | while IFS= read -r svc; do
    [[ "$svc" == *"asterisk"* ]] && continue
    [[ -z "$svc" ]] && continue
    printf '%s\n' "$svc"
  done
}

port_listening() {
  local port="$1"
  lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 \
    || lsof -nP -iUDP:"$port" >/dev/null 2>&1
}

restore_dns_from_backup() {
  [[ -f "$DNS_STATE" ]] || return 1
  # shellcheck disable=SC1090
  source "$DNS_STATE"
  [[ -n "${SERVICE:-}" ]] || return 1
  if [[ "${V4_MODE:-}" == "empty" ]]; then
    run_as_user networksetup -setdnsservers "$SERVICE" Empty
  elif [[ -n "${V4_SERVERS:-}" ]]; then
    # shellcheck disable=SC2206
    local arr=( ${V4_SERVERS} )
    run_as_user networksetup -setdnsservers "$SERVICE" "${arr[@]}"
  fi
  if [[ "${V6_MODE:-}" == "empty" ]]; then
    run_as_user networksetup -setv6dnsservers "$SERVICE" Empty >/dev/null 2>&1 || true
  elif [[ -n "${V6_SERVERS:-}" ]]; then
    # shellcheck disable=SC2206
    local arr6=( ${V6_SERVERS} )
    run_as_user networksetup -setv6dnsservers "$SERVICE" "${arr6[@]}" >/dev/null 2>&1 || true
  fi
  echo "  DNS restored from backup ($SERVICE)"
  return 0
}

fix_dns_service() {
  local svc="$1"
  local cur
  cur="$(run_as_user networksetup -getdnsservers "$svc" 2>/dev/null | head -1 || true)"
  if [[ "$cur" != "127.0.0.1" && "$cur" != "127.0.0.1 "* ]]; then
    return 0
  fi
  if port_listening 1053; then
    echo "  $svc: DNS 127.0.0.1 + split DNS active — OK"
    return 0
  fi
  run_as_user networksetup -setdnsservers "$svc" Empty
  run_as_user networksetup -setv6dnsservers "$svc" Empty >/dev/null 2>&1 || true
  echo "  $svc: DNS reset (was 127.0.0.1, nothing on :1053)"
}

fix_proxy_service() {
  local svc="$1"
  local web socks host port

  web="$(run_as_user networksetup -getwebproxy "$svc" 2>/dev/null || true)"
  socks="$(run_as_user networksetup -getsocksfirewallproxy "$svc" 2>/dev/null || true)"

  if printf '%s\n' "$web" | grep -q "Enabled: Yes"; then
    host="$(printf '%s\n' "$web" | awk '/^Server:/{print $2}')"
    port="$(printf '%s\n' "$web" | awk '/^Port:/{print $2}')"
    if [[ "$host" == "127.0.0.1" ]] && [[ -n "$port" ]] && ! port_listening "$port"; then
      run_as_user networksetup -setwebproxystate "$svc" off
      run_as_user networksetup -setsecurewebproxystate "$svc" off
      echo "  $svc: HTTP proxy off (dead $host:$port)"
    fi
  fi

  if printf '%s\n' "$socks" | grep -q "Enabled: Yes"; then
    host="$(printf '%s\n' "$socks" | awk '/^Server:/{print $2}')"
    port="$(printf '%s\n' "$socks" | awk '/^Port:/{print $2}')"
    if [[ "$host" == "127.0.0.1" ]] && [[ -n "$port" ]] && ! port_listening "$port"; then
      run_as_user networksetup -setsocksfirewallproxystate "$svc" off
      echo "  $svc: SOCKS proxy off (dead $host:$port)"
    fi
  fi
}

main() {
  echo "== repair network (shadowpipe/Clash leftovers) =="

  pkill -TERM -f shadowpipe-client 2>/dev/null || true
  rm -f "$CONFIG_DIR/run/shadowpipe.pid" 2>/dev/null || true
  pfctl -a shadowpipe.split -F all >/dev/null 2>&1 || true

  if restore_dns_from_backup; then
    :
  else
    while IFS= read -r svc; do
      fix_dns_service "$svc"
    done < <(detect_services)
  fi

  if [[ -f "$PROXY_STATE" ]]; then
    "$(dirname "$0")/cleanup-split.sh" >/dev/null 2>&1 || true
  else
    while IFS= read -r svc; do
      fix_proxy_service "$svc"
    done < <(detect_services)
  fi

  echo "== done — DNS/proxy should be normal (router/Clash when you start it) =="
}

main "$@"
