#!/usr/bin/env bash
# Resolve SHADOWPIPE_URI from env files, local uri file, or NL server (SSH).
set -euo pipefail

ROOT="${SHADOWPIPE_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
REAL_HOME="${REAL_HOME:-}"
if [[ -z "$REAL_HOME" ]]; then
  if [[ -n "${SUDO_USER:-}" ]]; then
    REAL_HOME="$(eval echo ~"$SUDO_USER")"
  else
    REAL_HOME="$HOME"
  fi
fi

# When invoked via sudo, SSH must run as the real user (agent/keys don't work as root).
run_as_user() {
  if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" "$@"
  else
    "$@"
  fi
}

uri_valid() {
  local u="$1"
  [[ -n "$u" ]] || return 1
  [[ "$u" == shadowpipe://* ]] || return 1
  [[ "$u" != *PUBKEY* ]] || return 1
  [[ "$u" != *SERVER_FP* ]] || return 1
  [[ "$u" != *'@host'* ]] || return 1
  return 0
}

read_uri_file() {
  local f="$1"
  [[ -f "$f" ]] || return 1
  local line
  line="$(grep -E '^[^#]*shadowpipe://' "$f" | head -1 | sed -n 's/.*\(shadowpipe:\/\/[^ "'\'' ]*\).*/\1/p')"
  uri_valid "$line" && { echo "$line"; return 0; }
  return 1
}

try_env_file() {
  local f="$1"
  [[ -f "$f" ]] || return 1
  # shellcheck disable=SC1090
  source "$f" 2>/dev/null || true
  uri_valid "${SHADOWPIPE_URI:-}" && { echo "$SHADOWPIPE_URI"; return 0; }
  return 1
}

fetch_uri_print() {
  local host="${SHADOWPIPE_NL_HOST:-203.0.113.10}"
  local user="${SHADOWPIPE_NL_USER:-root}"
  local port="${SHADOWPIPE_NL_PORT:-47845}"
  local keys="${SHADOWPIPE_KEYS_PATH:-/etc/shadowpipe/keys.json}"
  local rkey="${keys%/*}/reality.key"
  local cover="${SHADOWPIPE_COVER:-www.microsoft.com:443}"
  local advertise="${SHADOWPIPE_ADVERTISE:-${host}:${port}}"
  local ssh_opts=(-o ConnectTimeout=12 -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
  local out uri=""

  out=$(run_as_user ssh "${ssh_opts[@]}" "${user}@${host}" \
    "/usr/local/bin/shadowpipe-server --print-uri --reality --no-cover-profile \
      --keys ${keys} --reality-key ${rkey} --cover ${cover} \
      --listen 0.0.0.0:${port} --advertise ${advertise} 2>/dev/null" || true)
  uri=$(printf '%s\n' "$out" | sed -n 's/^reality-uri: //p' | tail -1)
  uri_valid "$uri" && { echo "$uri"; return 0; }
  return 1
}

fetch_uri_ssh() {
  local uri=""

  uri="$(fetch_uri_print 2>/dev/null)" && { echo "$uri"; return 0; }
  # Production daemons deliberately never log complete URIs/short IDs. Do not
  # revive a stale token from legacy /tmp logs or journald; only the explicit
  # root-only --print-uri one-shot above is authoritative for manual bootstrap.
  return 1
}

resolve_shadowpipe_uri() {
  local u=""
  local config_dir="${SHADOWPIPE_MACOS_CONFIG:-$REAL_HOME/.config/shadowpipe-macos}"
  local env_file="$config_dir/residential.env"

  uri_valid "${SHADOWPIPE_URI:-}" && { echo "$SHADOWPIPE_URI"; return 0; }

  u="$(read_uri_file "${SHADOWPIPE_URI_FILE:-/private/etc/shadowpipe/client-endpoint.uri}" 2>/dev/null)" \
    && { echo "$u"; return 0; }
  u="$(try_env_file "$env_file" 2>/dev/null)" && { echo "$u"; return 0; }
  u="$(read_uri_file "$config_dir/uri" 2>/dev/null)" && { echo "$u"; return 0; }
  u="$(read_uri_file "$REAL_HOME/Documents/billynotes/vpn/shadowpipe.uri" 2>/dev/null)" && { echo "$u"; return 0; }
  u="$(read_uri_file "$REAL_HOME/Documents/billynotes/vpn/shadowpipe-uri.txt" 2>/dev/null)" && { echo "$u"; return 0; }

  u="$(fetch_uri_ssh 2>/dev/null)" && { echo "$u"; return 0; }

  # Auto-deploy NL server and retry (zero-config path).
  # shellcheck source=scripts/macos/ensure-nl-server.sh
  source "$ROOT/scripts/macos/ensure-nl-server.sh"
  ensure_nl_server
  u="$(fetch_uri_ssh 2>/dev/null)" && { echo "$u"; return 0; }

  return 1
}

persist_uri() {
  local uri="$1"
  local env_file="$2"
  local uri_file="$3"
  local uri_dir tmp
  uri_dir="$(dirname "$uri_file")"
  [[ "$uri_dir" == /private/etc/shadowpipe ]] || {
    echo "refusing private URI publication outside /private/etc/shadowpipe" >&2
    return 1
  }
  [[ ! -L "$uri_dir" && ( ! -e "$uri_dir" || -d "$uri_dir" ) ]] || {
    echo "refusing unsafe private URI directory $uri_dir" >&2
    return 1
  }
  mkdir -p -- "$uri_dir"
  [[ -d "$uri_dir" && ! -L "$uri_dir" ]] || return 1
  chown 0:0 "$uri_dir"
  chmod 0700 "$uri_dir"
  tmp="${uri_file}.tmp.$$.${RANDOM}"
  ( umask 077; set -C; printf '%s\n' "$uri" >"$tmp" )
  chmod 0600 "$tmp"
  chown 0:0 "$tmp"
  mv -f -- "$tmp" "$uri_file"

  [[ -f "$env_file" ]] || return 0
  local tmp
  tmp="$(mktemp)"
  grep -v '^SHADOWPIPE_URI=' "$env_file" >"$tmp" 2>/dev/null || true
  mv "$tmp" "$env_file"
}
