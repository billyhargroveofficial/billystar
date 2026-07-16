#!/usr/bin/env bash
# Best-effort restore after shadowpipe split (DNS, system proxy, pf anchor).
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

restore_dns() {
  [[ -f "$DNS_STATE" ]] || return 0
  # shellcheck disable=SC1090
  source "$DNS_STATE"
  [[ -n "${SERVICE:-}" ]] || return 0
  if [[ "${V4_MODE:-}" == "empty" ]]; then
    run_as_user networksetup -setdnsservers "$SERVICE" Empty >/dev/null 2>&1 || true
  elif [[ -n "${V4_SERVERS:-}" ]]; then
    # shellcheck disable=SC2206
    local arr=( ${V4_SERVERS} )
    run_as_user networksetup -setdnsservers "$SERVICE" "${arr[@]}" >/dev/null 2>&1 || true
  fi
  if [[ "${V6_MODE:-}" == "empty" ]]; then
    run_as_user networksetup -setv6dnsservers "$SERVICE" Empty >/dev/null 2>&1 || true
  elif [[ -n "${V6_SERVERS:-}" ]]; then
    # shellcheck disable=SC2206
    local arr6=( ${V6_SERVERS} )
    run_as_user networksetup -setv6dnsservers "$SERVICE" "${arr6[@]}" >/dev/null 2>&1 || true
  fi
}

restore_proxy() {
  [[ -f "$PROXY_STATE" ]] || return 0
  local svc web_on web_host web_port sec_on sec_host sec_port socks_on socks_host socks_port
  svc="$(sed -n 's/^SERVICE=//p' "$PROXY_STATE" | head -1 | tr -d "\"'")"
  [[ -n "$svc" ]] || return 0

  parse_block() {
    local tag="$1" line
    while IFS= read -r line; do
      [[ "$line" == "---"* ]] && break
      case "$line" in
        "Enabled: Yes") eval "${tag}_on=1" ;;
        "Enabled: No") eval "${tag}_on=0" ;;
        "Server:"*) eval "${tag}_host=$(printf '%s' "$line" | awk '{print $2}')" ;;
        "Port:"*) eval "${tag}_port=$(printf '%s' "$line" | awk '{print $2}')" ;;
      esac
    done
  }

  local section=""
  while IFS= read -r line; do
    case "$line" in
      "---WEB---") section=web; web_on=0; web_host=; web_port=0 ;;
      "---SECURE---") section=sec; sec_on=0; sec_host=; sec_port=0 ;;
      "---SOCKS---") section=socks; socks_on=0; socks_host=; socks_port=0 ;;
      *)
        case "$section" in
          web)
            case "$line" in
              "Enabled: Yes") web_on=1 ;;
              "Enabled: No") web_on=0 ;;
              Server:*) web_host=$(printf '%s' "$line" | awk '{print $2}') ;;
              Port:*) web_port=$(printf '%s' "$line" | awk '{print $2}') ;;
            esac ;;
          sec)
            case "$line" in
              "Enabled: Yes") sec_on=1 ;;
              "Enabled: No") sec_on=0 ;;
              Server:*) sec_host=$(printf '%s' "$line" | awk '{print $2}') ;;
              Port:*) sec_port=$(printf '%s' "$line" | awk '{print $2}') ;;
            esac ;;
          socks)
            case "$line" in
              "Enabled: Yes") socks_on=1 ;;
              "Enabled: No") socks_on=0 ;;
              Server:*) socks_host=$(printf '%s' "$line" | awk '{print $2}') ;;
              Port:*) socks_port=$(printf '%s' "$line" | awk '{print $2}') ;;
            esac ;;
        esac
        ;;
    esac
  done <"$PROXY_STATE"

  if [[ "${web_on:-0}" == "1" && -n "${web_host:-}" ]]; then
    run_as_user networksetup -setwebproxy "$svc" "$web_host" "$web_port" off >/dev/null 2>&1 || true
    run_as_user networksetup -setwebproxystate "$svc" on >/dev/null 2>&1 || true
  else
    run_as_user networksetup -setwebproxystate "$svc" off >/dev/null 2>&1 || true
  fi
  if [[ "${sec_on:-0}" == "1" && -n "${sec_host:-}" ]]; then
    run_as_user networksetup -setsecurewebproxy "$svc" "$sec_host" "$sec_port" off >/dev/null 2>&1 || true
    run_as_user networksetup -setsecurewebproxystate "$svc" on >/dev/null 2>&1 || true
  else
    run_as_user networksetup -setsecurewebproxystate "$svc" off >/dev/null 2>&1 || true
  fi
  if [[ "${socks_on:-0}" == "1" && -n "${socks_host:-}" ]]; then
    run_as_user networksetup -setsocksfirewallproxy "$svc" "$socks_host" "$socks_port" >/dev/null 2>&1 || true
    run_as_user networksetup -setsocksfirewallproxystate "$svc" on >/dev/null 2>&1 || true
  else
    run_as_user networksetup -setsocksfirewallproxystate "$svc" off >/dev/null 2>&1 || true
  fi
}

pf_flush() {
  pfctl -a shadowpipe.split -F all >/dev/null 2>&1 || true
  rm -f /tmp/shadowpipe-split.pf /tmp/shadowpipe-split.pf.conf 2>/dev/null || true
}

restore_dns
restore_proxy
pf_flush
