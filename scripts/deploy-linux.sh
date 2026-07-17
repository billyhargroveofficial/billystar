#!/usr/bin/env bash
# Build and provision the mandatory-v3 REALITY server on NL plus one enrolled
# client credential on RU. This is an explicit rotation workflow: every run
# requires a matching local credential/enrollment pair. An exact repeated
# enrollment is idempotent; a conflicting artifact fails before the installer
# switches binaries, NAT, unit, or listener state.
# Remote command strings below deliberately expand validated local paths/tokens.
# shellcheck disable=SC2029
set -euo pipefail
cd "$(dirname "$0")/.."

die() {
  echo "ERROR: $*" >&2
  exit 1
}

valid_ipv4_literal() {
  local value="$1" octet
  local -a octets=()
  [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -r -a octets <<<"$value"
  (( ${#octets[@]} == 4 )) || return 1
  for octet in "${octets[@]}"; do
    (( 10#$octet <= 255 )) || return 1
  done
}

valid_advertise() {
  local value="$1" address port
  if [[ "$value" =~ ^([A-Za-z0-9_.-]+):([0-9]{1,5})$ ]]; then
    address="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
  else
    return 1
  fi
  if [[ "$address" =~ ^[0-9.]+$ ]]; then
    valid_ipv4_literal "$address" || return 1
  fi
  (( 10#$port >= 1 && 10#$port <= 65535 ))
}

NL_HOST="${NL_HOST:-example-nl}"
RU_HOST="${RU_HOST:-example-ru}"
NL_PORT="${NL_PORT:-47845}"
NL_EGRESS="${NL_EGRESS:-ens3}"
SP_COVER="${SP_COVER:-www.microsoft.com:443}"
SP_ADVERTISE="${SP_ADVERTISE:-203.0.113.10:$NL_PORT}"
CLIENT_ALLOWLIST_PATH="${CLIENT_ALLOWLIST_PATH:-/etc/shadowpipe/client-allowlist.json}"
CLIENT_CREDENTIAL_PATH="${CLIENT_CREDENTIAL_PATH:-/etc/shadowpipe/client-credential.json}"
CLIENT_CREDENTIAL_LOCAL="${SP_CLIENT_CREDENTIAL_LOCAL:-}"
CLIENT_ENROLLMENT_LOCAL="${SP_CLIENT_ENROLLMENT_LOCAL:-}"

[[ -z "${SP_TLS:-}" ]] || die "production deploy is mandatory-v3 REALITY; --tls lab deployment is intentionally not automated here"
[[ "$NL_HOST" =~ ^[A-Za-z0-9_.:@-]+$ && "$NL_HOST" != -* ]] || die "unsafe NL_HOST"
[[ "$RU_HOST" =~ ^[A-Za-z0-9_.:@-]+$ && "$RU_HOST" != -* ]] || die "unsafe RU_HOST"
if [[ ! "$NL_PORT" =~ ^[0-9]+$ ]] || (( NL_PORT < 1 || NL_PORT > 65535 )); then
  die "NL_PORT must be 1..65535"
fi
[[ "$NL_EGRESS" =~ ^[A-Za-z0-9_.:-]+$ ]] || die "unsafe NL_EGRESS"
[[ "$SP_COVER" =~ ^[A-Za-z0-9_.:-]+$ ]] || die "unsafe SP_COVER"
valid_advertise "$SP_ADVERTISE" \
  || die "unsafe SP_ADVERTISE"
[[ "$CLIENT_ALLOWLIST_PATH" =~ ^/[A-Za-z0-9_./-]+$ \
   && "$CLIENT_ALLOWLIST_PATH" != *'/../'* ]] \
  || die "CLIENT_ALLOWLIST_PATH must be absolute and normalized"
[[ "$CLIENT_CREDENTIAL_PATH" =~ ^/[A-Za-z0-9_./-]+$ \
   && "$CLIENT_CREDENTIAL_PATH" != *'/../'* ]] \
  || die "CLIENT_CREDENTIAL_PATH must be absolute and normalized"
CLIENT_CREDENTIAL_DIR="${CLIENT_CREDENTIAL_PATH%/*}"
[[ -n "$CLIENT_CREDENTIAL_DIR" ]] || CLIENT_CREDENTIAL_DIR=/
[[ "$CLIENT_CREDENTIAL_DIR" == /etc/shadowpipe ]] \
  || die "automated paired credential transaction is restricted to /etc/shadowpipe"
[[ -n "$CLIENT_CREDENTIAL_LOCAL" && -n "$CLIENT_ENROLLMENT_LOCAL" ]] || {
  cat >&2 <<'EOF'
ERROR: set both SP_CLIENT_CREDENTIAL_LOCAL and SP_CLIENT_ENROLLMENT_LOCAL.
Generate a fresh pair on the client without printing secrets:
  sudo shadowpipe-client --generate-client-credential \
    --client-credential /root/shadowpipe-client-credential.json \
    --write-client-enrollment /root/shadowpipe-client-enrollment.json
EOF
  exit 1
}

private_file_tuple() {
  local path="$1"
  if stat -f '%u:%Lp:%l' -- "$path" >/dev/null 2>&1; then
    stat -f '%u:%Lp:%l' -- "$path"
  else
    stat -c '%u:%a:%h' -- "$path"
  fi
}

EXPECTED_UID="$(id -u)"
for secret in "$CLIENT_CREDENTIAL_LOCAL" "$CLIENT_ENROLLMENT_LOCAL"; do
  [[ "$secret" == /* && "$secret" != *'/../'* ]] \
    || die "secret artifact path must be absolute and normalized: $secret"
  [[ -f "$secret" && ! -L "$secret" ]] \
    || die "secret artifact must be a regular file, not a symlink: $secret"
  tuple="$(private_file_tuple "$secret")"
  [[ "$tuple" == "$EXPECTED_UID:600:1" || "$tuple" == "0:600:1" ]] \
    || die "secret artifact must be owner/root-owned, mode 0600, single-link: $secret"
done

command -v jq >/dev/null || die "jq is required to verify that credential and enrollment match"
jq -e -s '
  .[0].schema == "shadowpipe-client-credential-v1" and
  .[1].schema == "shadowpipe-client-enrollment-v1" and
  .[0].key_id == .[1].key_id and
  .[0].ed25519_public_key == .[1].ed25519_public_key and
  .[0].psk == .[1].psk
' -- "$CLIENT_CREDENTIAL_LOCAL" "$CLIENT_ENROLLMENT_LOCAL" >/dev/null \
  || die "credential and enrollment are malformed or do not describe the same client"

[[ "${SHADOWPIPE_MAGIC:-}" =~ ^0x[0-9A-Fa-f]{8}$ ]] \
  || die "set one explicit SHADOWPIPE_MAGIC, for example 0x53504731"
export SHADOWPIPE_MAGIC
export PATH="/opt/homebrew/opt/x86_64-unknown-linux-gnu/bin:${PATH:-}"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-x86_64-unknown-linux-gnu-gcc}"
SP_SYSROOT="${SP_SYSROOT:-/opt/homebrew/opt/x86_64-unknown-linux-gnu/toolchain/x86_64-unknown-linux-gnu/sysroot}"
export CC_x86_64_unknown_linux_gnu="${CC_x86_64_unknown_linux_gnu:-x86_64-unknown-linux-gnu-gcc}"
export CXX_x86_64_unknown_linux_gnu="${CXX_x86_64_unknown_linux_gnu:-x86_64-unknown-linux-gnu-g++}"
export BINDGEN_EXTRA_CLANG_ARGS="${BINDGEN_EXTRA_CLANG_ARGS:---sysroot=$SP_SYSROOT --target=x86_64-unknown-linux-gnu}"
export RUSTFLAGS="${RUSTFLAGS:--C link-arg=-static-libstdc++ -C link-arg=-static-libgcc}"

echo "== build mandatory-v3 artifacts (magic=${SHADOWPIPE_MAGIC}) =="
cargo build --release --locked --target x86_64-unknown-linux-gnu \
  -p shadowpipe-server -p shadowpipe-client
BIN_DIR=target/x86_64-unknown-linux-gnu/release
SERVER_BIN="$BIN_DIR/shadowpipe-server"
CLIENT_BIN="$BIN_DIR/shadowpipe-client"
# These are Linux artifacts and cannot be executed on the macOS build host.
# The remote installer and the RU re-export preflight execute and validate the
# exact uploaded binaries before any listener/network activation.

[[ "$(ssh "$NL_HOST" 'id -u')" == 0 ]] || die "NL_HOST SSH principal must be root"
[[ "$(ssh "$RU_HOST" 'id -u')" == 0 ]] || die "RU_HOST SSH principal must be root"
TOKEN="$(openssl rand -hex 12)"
NL_SERVER_STAGE="/root/.shadowpipe-server-$TOKEN"
NL_INSTALLER_STAGE="/root/.shadowpipe-installer-$TOKEN"
NL_ENROLLMENT_STAGE="/root/.shadowpipe-enrollment-$TOKEN"
RU_CLIENT_STAGE="/root/.shadowpipe-client-$TOKEN"
RU_CREDENTIAL_STAGE="/root/.shadowpipe-credential-$TOKEN"
RU_ENROLLMENT_STAGE="/root/.shadowpipe-enrollment-$TOKEN"

cleanup_remote_stages() {
  set +e
  ssh "$NL_HOST" "rm -f -- '$NL_SERVER_STAGE' '$NL_INSTALLER_STAGE' '$NL_ENROLLMENT_STAGE'" >/dev/null 2>&1
  ssh "$RU_HOST" "rm -f -- '$RU_CLIENT_STAGE' '$RU_CREDENTIAL_STAGE' '$RU_ENROLLMENT_STAGE' /root/.shadowpipe-reexport-$TOKEN" >/dev/null 2>&1
}
trap cleanup_remote_stages EXIT

echo "== upload root-private staged artifacts =="
ssh "$NL_HOST" \
  "set -e; \
   test -d /root; test ! -L /root; test \"\$(stat -c '%u' -- /root)\" = 0; \
   root_mode=\$(stat -c '%a' -- /root); test \$((8#\$root_mode & 8#22)) -eq 0; \
   install -o root -g root -m 0600 /dev/null '$NL_SERVER_STAGE'; \
   install -o root -g root -m 0600 /dev/null '$NL_INSTALLER_STAGE'; \
   install -o root -g root -m 0600 /dev/null '$NL_ENROLLMENT_STAGE'"
ssh "$RU_HOST" \
  "set -e; \
   test -d /root; test ! -L /root; test \"\$(stat -c '%u' -- /root)\" = 0; \
   root_mode=\$(stat -c '%a' -- /root); test \$((8#\$root_mode & 8#22)) -eq 0; \
   install -o root -g root -m 0600 /dev/null '$RU_CLIENT_STAGE'; \
   install -o root -g root -m 0600 /dev/null '$RU_CREDENTIAL_STAGE'; \
   install -o root -g root -m 0600 /dev/null '$RU_ENROLLMENT_STAGE'"
scp "$SERVER_BIN" "$NL_HOST:$NL_SERVER_STAGE"
scp deploy/install-vps.sh "$NL_HOST:$NL_INSTALLER_STAGE"
scp "$CLIENT_ENROLLMENT_LOCAL" "$NL_HOST:$NL_ENROLLMENT_STAGE"
scp "$CLIENT_BIN" "$RU_HOST:$RU_CLIENT_STAGE"
scp "$CLIENT_CREDENTIAL_LOCAL" "$RU_HOST:$RU_CREDENTIAL_STAGE"
scp "$CLIENT_ENROLLMENT_LOCAL" "$RU_HOST:$RU_ENROLLMENT_STAGE"
ssh "$NL_HOST" "chmod 0755 '$NL_SERVER_STAGE'; chmod 0700 '$NL_INSTALLER_STAGE'; chmod 0600 '$NL_ENROLLMENT_STAGE'"
ssh "$RU_HOST" "chmod 0755 '$RU_CLIENT_STAGE'; chmod 0600 '$RU_CREDENTIAL_STAGE' '$RU_ENROLLMENT_STAGE'"
ssh "$NL_HOST" \
  "set -e; \
   test \"\$(stat -c '%u:%g:%a:%h' -- '$NL_SERVER_STAGE')\" = 0:0:755:1; \
   test \"\$(stat -c '%u:%g:%a:%h' -- '$NL_INSTALLER_STAGE')\" = 0:0:700:1; \
   test \"\$(stat -c '%u:%g:%a:%h' -- '$NL_ENROLLMENT_STAGE')\" = 0:0:600:1"
ssh "$RU_HOST" \
  "set -e; \
   test \"\$(stat -c '%u:%g:%a:%h' -- '$RU_CLIENT_STAGE')\" = 0:0:755:1; \
   test \"\$(stat -c '%u:%g:%a:%h' -- '$RU_CREDENTIAL_STAGE')\" = 0:0:600:1; \
   test \"\$(stat -c '%u:%g:%a:%h' -- '$RU_ENROLLMENT_STAGE')\" = 0:0:600:1"

# Validate the complete private credential and its exported enrollment on the
# client host before enrolling or changing any server listener/network state.
ssh "$RU_HOST" "
  set -euo pipefail
  rm -f /root/.shadowpipe-reexport-$TOKEN
  '$RU_CLIENT_STAGE' --client-credential '$RU_CREDENTIAL_STAGE' \\
    --write-client-enrollment /root/.shadowpipe-reexport-$TOKEN >/dev/null
  cmp -s /root/.shadowpipe-reexport-$TOKEN '$RU_ENROLLMENT_STAGE'
  rm -f /root/.shadowpipe-reexport-$TOKEN
"

echo "== provision NL through the transactional authorization-first installer =="
INSTALL_OUTPUT="$(ssh "$NL_HOST" "
  '$NL_INSTALLER_STAGE' \\
    --binary '$NL_SERVER_STAGE' \\
    --port '$NL_PORT' \\
    --egress '$NL_EGRESS' \\
    --cover '$SP_COVER' \\
    --advertise '$SP_ADVERTISE' \\
    --client-allowlist '$CLIENT_ALLOWLIST_PATH' \\
    --client-enrollment '$NL_ENROLLMENT_STAGE'
")"
printf '%s\n' "$INSTALL_OUTPUT"
NL_BOOTSTRAP_PATH="$(printf '%s\n' "$INSTALL_OUTPUT" \
  | awk '$1 == "Bootstrap:" { print $2 }' | tail -1)"
[[ "$NL_BOOTSTRAP_PATH" =~ ^/root/shadowpipe-client-bootstrap\.[A-Za-z0-9]+$ ]] \
  || die "installer started safely but did not return a safe root-only bootstrap path"
ssh "$NL_HOST" \
  "test \"\$(stat -c '%u:%g:%a:%h' -- '$NL_BOOTSTRAP_PATH')\" = 0:0:600:1" \
  || die "server bootstrap artifact is not root:root 0600 single-link"

# The server now authorizes both the old client (if any) and this new one. Only
# now atomically switch the RU client binary/credential paths.
echo "== activate enrolled RU client artifact =="
ssh "$RU_HOST" "
  set -euo pipefail
  if [ -e '$CLIENT_CREDENTIAL_DIR' ]; then
    test -d '$CLIENT_CREDENTIAL_DIR'
    test ! -L '$CLIENT_CREDENTIAL_DIR'
    test \"\$(stat -c '%u' -- '$CLIENT_CREDENTIAL_DIR')\" = 0
    mode=\$(stat -c '%a' -- '$CLIENT_CREDENTIAL_DIR')
    test \$((8#\$mode & 8#22)) -eq 0
  else
    install -d -o root -g root -m 0700 '$CLIENT_CREDENTIAL_DIR'
  fi
  client_tmp=\$(mktemp /usr/local/bin/.shadowpipe-client.stage.XXXXXX)
  credential_tmp=\$(mktemp '$CLIENT_CREDENTIAL_DIR/.client-credential.stage.XXXXXX')
  client_backup=''
  credential_backup=''
  client_had=0
  credential_had=0
  client_published=0
  credential_published=0
  committed=0
  reexport=/root/.shadowpipe-reexport-$TOKEN

  finish() {
    status=\$?
    trap - EXIT
    set +e
    if [ \"\$status\" -ne 0 ] && [ \"\$committed\" -ne 1 ]; then
      if [ \"\$client_published\" -eq 1 ]; then
        if [ \"\$client_had\" -eq 1 ]; then
          mv -f -- \"\$client_backup\" /usr/local/bin/shadowpipe-client
          client_backup=''
        else
          rm -f -- /usr/local/bin/shadowpipe-client
        fi
      fi
      if [ \"\$credential_published\" -eq 1 ]; then
        if [ \"\$credential_had\" -eq 1 ]; then
          mv -f -- \"\$credential_backup\" '$CLIENT_CREDENTIAL_PATH'
          credential_backup=''
        else
          rm -f -- '$CLIENT_CREDENTIAL_PATH'
        fi
      fi
      sync -f /usr/local/bin '$CLIENT_CREDENTIAL_DIR' 2>/dev/null || sync
    fi
    rm -f -- \"\$client_tmp\" \"\$credential_tmp\" \"\$client_backup\" \
      \"\$credential_backup\" \"\$reexport\"
    exit \"\$status\"
  }
  trap finish EXIT

  if [ -e /usr/local/bin/shadowpipe-client ]; then
    test -f /usr/local/bin/shadowpipe-client
    test ! -L /usr/local/bin/shadowpipe-client
    client_had=1
    client_backup=\$(mktemp /usr/local/bin/.shadowpipe-client.backup.XXXXXX)
    cp -a -- /usr/local/bin/shadowpipe-client \"\$client_backup\"
  fi
  if [ -e '$CLIENT_CREDENTIAL_PATH' ]; then
    test -f '$CLIENT_CREDENTIAL_PATH'
    test ! -L '$CLIENT_CREDENTIAL_PATH'
    test \"\$(stat -c '%u:%a:%h' -- '$CLIENT_CREDENTIAL_PATH')\" = 0:600:1
    credential_had=1
    credential_backup=\$(mktemp '$CLIENT_CREDENTIAL_DIR/.client-credential.backup.XXXXXX')
    cp -a -- '$CLIENT_CREDENTIAL_PATH' \"\$credential_backup\"
  fi

  install -o root -g root -m 0755 '$RU_CLIENT_STAGE' \"\$client_tmp\"
  install -o root -g root -m 0600 '$RU_CREDENTIAL_STAGE' \"\$credential_tmp\"
  sync -f \"\$client_tmp\" \"\$credential_tmp\" 2>/dev/null || sync
  mv -f -- \"\$credential_tmp\" '$CLIENT_CREDENTIAL_PATH'
  credential_tmp=''
  credential_published=1
  mv -f -- \"\$client_tmp\" /usr/local/bin/shadowpipe-client
  client_tmp=''
  client_published=1
  sync -f /usr/local/bin '$CLIENT_CREDENTIAL_DIR' 2>/dev/null || sync

  rm -f -- \"\$reexport\"
  /usr/local/bin/shadowpipe-client \\
    --client-credential '$CLIENT_CREDENTIAL_PATH' \\
    --write-client-enrollment \"\$reexport\" >/dev/null
  cmp -s -- \"\$reexport\" '$RU_ENROLLMENT_STAGE'
  committed=1
  if rm -f -- \"\$client_backup\"; then
    client_backup=''
  else
    echo \"WARN: remove stale client binary backup manually: \$client_backup\" >&2
  fi
  if rm -f -- \"\$credential_backup\"; then
    credential_backup=''
  else
    echo \"WARN: remove stale private credential backup manually: \$credential_backup\" >&2
  fi
  if ! rm -f -- \"\$reexport\"; then
    echo \"WARN: remove stale private enrollment re-export manually: \$reexport\" >&2
  fi
"

echo
echo "Deploy complete: mandatory-v3 allowlist validated before service/NAT activation."
echo "No credential, PSK, private seed, or enrollment payload was printed."
echo "Root-only manual bootstrap remains on NL: $NL_BOOTSTRAP_PATH"
echo "Transfer it over an authenticated confidential channel, run only inside a disposable RU netns, then delete both copies."
echo "Production activation still requires a separately enrolled signed endpoint-policy bundle; the bootstrap is not endpoint authority."
echo "After validating the rotated client, revoke the old key explicitly; never revoke the final entry."
