#!/usr/bin/env bash
# Ensure the NL mandatory-v3 REALITY server through the same authorization-first
# transactional installer used for fresh VPS provisioning. This script changes
# only the remote VPS; it never mutates macOS routes, DNS, PF, TUN, or sing-box.
set -euo pipefail

ROOT="${SHADOWPIPE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
REAL_HOME="${REAL_HOME:-$HOME}"
if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]]; then
  REAL_HOME="$(eval echo ~"$SUDO_USER")"
fi

NL_HOST="${SHADOWPIPE_NL_HOST:-203.0.113.10}"
NL_USER="${SHADOWPIPE_NL_USER:-root}"
NL_PORT="${SHADOWPIPE_NL_PORT:-47845}"
NL_EGRESS="${SHADOWPIPE_NL_EGRESS:-ens3}"
CLIENT_ALLOWLIST="${SHADOWPIPE_CLIENT_ALLOWLIST:-/etc/shadowpipe/client-allowlist.json}"
CLIENT_CREDENTIAL="${SHADOWPIPE_CLIENT_CREDENTIAL:-/etc/shadowpipe/client-credential.json}"
CLIENT_ENROLLMENT="${SHADOWPIPE_CLIENT_ENROLLMENT:-}"
COVER="${SHADOWPIPE_COVER:-www.microsoft.com:443}"
ADVERTISE="${SHADOWPIPE_ADVERTISE:-${NL_HOST}:${NL_PORT}}"

run_as_user() {
  if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" "$@"
  else
    "$@"
  fi
}

SSH=(ssh -o ConnectTimeout=12 -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${NL_USER}@${NL_HOST}")
SCP=(scp -o ConnectTimeout=12 -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
log() { echo "== ensure-nl-server: $*"; }
die() { echo "ERROR: ensure-nl-server: $*" >&2; return 1; }

private_file_tuple() {
  local path="$1"
  if stat -f '%u:%Lp:%l' -- "$path" >/dev/null 2>&1; then
    stat -f '%u:%Lp:%l' -- "$path"
  else
    stat -c '%u:%a:%h' -- "$path"
  fi
}

validate_inputs() {
  [[ "$NL_USER" == root ]] || die "remote management requires SHADOWPIPE_NL_USER=root"
  [[ "$NL_HOST" =~ ^[A-Za-z0-9_.:-]+$ && "$NL_HOST" != -* ]] || die "unsafe NL host"
  [[ "$NL_PORT" =~ ^[0-9]+$ ]] || die "invalid port"
  (( NL_PORT >= 1 && NL_PORT <= 65535 )) || die "invalid port"
  [[ "$NL_EGRESS" =~ ^[A-Za-z0-9_.:-]+$ ]] || die "unsafe egress interface"
  [[ "$COVER" =~ ^[A-Za-z0-9_.:-]+$ ]] || die "unsafe cover"
  [[ "$ADVERTISE" =~ ^[A-Za-z0-9_.\[\]:-]+$ ]] || die "unsafe advertise address"
  [[ "$CLIENT_ALLOWLIST" =~ ^/[A-Za-z0-9_./-]+$ && "$CLIENT_ALLOWLIST" != *'/../'* ]] \
    || die "client allowlist path must be absolute and normalized"

  # Existing remote v3 installations need no transfer artifact: the installer
  # revalidates their allowlist. Fresh enrollment requires both matching local
  # artifacts, and nothing secret is ever printed.
  if [[ -n "$CLIENT_ENROLLMENT" ]]; then
    [[ -f "$CLIENT_CREDENTIAL" && ! -L "$CLIENT_CREDENTIAL" ]] \
      || die "local production client credential is missing or is a symlink: $CLIENT_CREDENTIAL"
    [[ -f "$CLIENT_ENROLLMENT" && ! -L "$CLIENT_ENROLLMENT" ]] \
      || die "local enrollment is missing or is a symlink: $CLIENT_ENROLLMENT"
    [[ "$(private_file_tuple "$CLIENT_CREDENTIAL")" == "0:600:1" ]] \
      || die "local production credential must be root-owned, mode 0600, single-link"
    local enrollment_tuple
    enrollment_tuple="$(private_file_tuple "$CLIENT_ENROLLMENT")"
    [[ "$enrollment_tuple" == "$(id -u):600:1" \
       || -n "${SUDO_USER:-}" && "$enrollment_tuple" == "$(id -u "$SUDO_USER"):600:1" ]] \
      || die "local enrollment must be owner/root-owned, mode 0600, single-link"
    command -v jq >/dev/null || die "jq is required to verify credential/enrollment pairing"
    jq -e -s '
      .[0].schema == "shadowpipe-client-credential-v1" and
      .[1].schema == "shadowpipe-client-enrollment-v1" and
      .[0].key_id == .[1].key_id and
      .[0].ed25519_public_key == .[1].ed25519_public_key and
      .[0].psk == .[1].psk
    ' "$CLIENT_CREDENTIAL" "$CLIENT_ENROLLMENT" >/dev/null \
      || die "credential and enrollment do not describe the same client"
  fi
}

ensure_linux_server_bin() {
  local bin="$ROOT/target/x86_64-unknown-linux-gnu/release/shadowpipe-server"
  if [[ -x "$bin" ]] && ! find "$ROOT/crates/shadowpipe-server" "$ROOT/crates/shadowpipe-core" \
      "$ROOT/crates/shadowpipe-reality" -name '*.rs' -newer "$bin" -print -quit 2>/dev/null | grep -q .; then
    return 0
  fi
  log "cross-building mandatory-v3 server for Linux"
  export SHADOWPIPE_MAGIC="${SHADOWPIPE_MAGIC:-0xcafebabe}"
  export PATH="/opt/homebrew/opt/x86_64-unknown-linux-gnu/bin:${PATH:-}"
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-x86_64-unknown-linux-gnu-gcc}"
  local sysroot="${SP_SYSROOT:-/opt/homebrew/opt/x86_64-unknown-linux-gnu/toolchain/x86_64-unknown-linux-gnu/sysroot}"
  export CC_x86_64_unknown_linux_gnu="${CC_x86_64_unknown_linux_gnu:-x86_64-unknown-linux-gnu-gcc}"
  export CXX_x86_64_unknown_linux_gnu="${CXX_x86_64_unknown_linux_gnu:-x86_64-unknown-linux-gnu-g++}"
  export BINDGEN_EXTRA_CLANG_ARGS="${BINDGEN_EXTRA_CLANG_ARGS:---sysroot=$sysroot --target=x86_64-unknown-linux-gnu}"
  export RUSTFLAGS="${RUSTFLAGS:--C link-arg=-static-libstdc++ -C link-arg=-static-libgcc}"
  (cd "$ROOT" && cargo build --release --locked --target x86_64-unknown-linux-gnu -p shadowpipe-server)
  [[ -x "$bin" ]] || die "Linux server build failed"
}

ensure_nl_server() (
  validate_inputs
  ensure_linux_server_bin
  [[ "$(run_as_user "${SSH[@]}" 'id -u')" == 0 ]] || die "remote SSH principal is not root"

  local token server_stage installer_stage enrollment_stage output
  token="$(openssl rand -hex 12)"
  server_stage="/root/.shadowpipe-server-$token"
  installer_stage="/root/.shadowpipe-installer-$token"
  enrollment_stage="/root/.shadowpipe-enrollment-$token"
  # The function runs in a subshell, so this cleanup cannot leak into a caller
  # that sourced ensure-nl-server.sh (as ensure-uri.sh does).
  # shellcheck disable=SC2064
  trap "run_as_user \"\${SSH[@]}\" \"rm -f -- '$server_stage' '$installer_stage' '$enrollment_stage'\" >/dev/null 2>&1 || true" EXIT

  log "uploading staged server and transactional installer"
  run_as_user "${SCP[@]}" "$ROOT/target/x86_64-unknown-linux-gnu/release/shadowpipe-server" \
    "${NL_USER}@${NL_HOST}:$server_stage"
  run_as_user "${SCP[@]}" "$ROOT/deploy/install-vps.sh" \
    "${NL_USER}@${NL_HOST}:$installer_stage"
  run_as_user "${SSH[@]}" "chmod 0755 '$server_stage'; chmod 0700 '$installer_stage'"

  local enrollment_arg=""
  if [[ -n "$CLIENT_ENROLLMENT" ]]; then
    run_as_user "${SCP[@]}" "$CLIENT_ENROLLMENT" \
      "${NL_USER}@${NL_HOST}:$enrollment_stage"
    run_as_user "${SSH[@]}" "chmod 0600 '$enrollment_stage'"
    enrollment_arg="--client-enrollment '$enrollment_stage'"
  fi

  log "running authorization-first remote installer"
  output="$(run_as_user "${SSH[@]}" "
    '$installer_stage' \\
      --binary '$server_stage' \\
      --port '$NL_PORT' \\
      --egress '$NL_EGRESS' \\
      --cover '$COVER' \\
      --advertise '$ADVERTISE' \\
      --client-allowlist '$CLIENT_ALLOWLIST' \\
      $enrollment_arg
  ")"
  printf '%s\n' "$output"
  run_as_user "${SSH[@]}" "/usr/local/bin/shadowpipe-server --validate-client-allowlist --client-allowlist '$CLIENT_ALLOWLIST'"
  run_as_user "${SSH[@]}" "systemctl is-active --quiet shadowpipe"
  run_as_user "${SSH[@]}" "rm -f -- '$server_stage' '$installer_stage' '$enrollment_stage'" >/dev/null 2>&1 || true
)

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  ensure_nl_server
  echo "OK NL mandatory-v3 server ready on ${NL_HOST}:${NL_PORT}; no secret was printed"
fi
