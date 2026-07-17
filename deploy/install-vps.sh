#!/usr/bin/env bash
# Fail-closed REALITY bringup for shadowpipe-server on a Debian/Ubuntu VPS.
# The client credential is generated on the client. Only its one-time secret
# enrollment artifact crosses the provisioning channel.
set -euo pipefail
export LC_ALL=C

PORT=47843
EGRESS="${EGRESS:-eth0}"
COVER="${COVER:-www.microsoft.com:443}"
ADVERTISE=""
INSTALL_DIR=/usr/local/bin
BIN="$INSTALL_DIR/shadowpipe-server"
KEYS=/etc/shadowpipe/keys.json
RKEY=/etc/shadowpipe/reality.key
CONFIG_DIR=/etc/shadowpipe
CLIENT_ALLOWLIST=/etc/shadowpipe/client-allowlist.json
SHORT_ID_FILE=/etc/shadowpipe/reality-short-ids
REPLAY_STORE=/var/lib/shadowpipe/reality-replay-v1.bin
CLIENT_ENROLLMENT=""
UNIT=/etc/systemd/system/shadowpipe.service
SYSCTL_DROPIN=/etc/sysctl.d/90-shadowpipe-forwarding.conf
TUN_SUBNET=10.8.0.0/24
TUN_IFACE=shadowpipe0
BINARY=""
SHORT_IDS=()
SHORT_IDS_FROM_EXISTING=0
EXISTING_SHORT_IDS=()

# Transaction state. Only artifacts and host state owned by this invocation are
# rolled back; pre-existing iptables rules and sysctls are preserved exactly.
TX_ACTIVE=0
COMMITTED=0
BIN_STAGE=""
BIN_BACKUP=""
BIN_HAD_EXISTING=0
UNIT_STAGE=""
UNIT_BACKUP=""
UNIT_HAD_EXISTING=0
ALLOWLIST_BACKUP=""
ALLOWLIST_HAD_EXISTING=0
ALLOWLIST_MUTATION_ATTEMPTED=0
ALLOWLIST_LOCK=""
ALLOWLIST_LOCK_HAD_EXISTING=0
SHORT_ID_STAGE=""
SHORT_ID_BACKUP=""
SHORT_ID_HAD_EXISTING=0
SHORT_ID_MUTATION_ATTEMPTED=0
CONFIG_DIR_CREATED=0
KEYS_CREATION_ATTEMPTED=0
RKEY_CREATION_ATTEMPTED=0
SYSCTL_STAGE=""
SYSCTL_DROPIN_CREATED=0
IP_FORWARD_BEFORE=""
ALL_FORWARDING_BEFORE=""
NAT_RULE_ADDED=0
FORWARD_OUT_RULE_ADDED=0
FORWARD_IN_RULE_ADDED=0
SERVICE_WAS_ACTIVE=0
SERVICE_WAS_ENABLED=0
OLD_RUNTIME_MANDATORY_V3=0
SERVICE_STOPPED_BY_US=0
ARTIFACTS_SWITCHED=0

usage() {
  cat <<'EOF'
Usage:
  sudo ./deploy/install-vps.sh --binary /root/shadowpipe-server \
    --client-enrollment /root/client-enrollment.json \
    [--port 47843] [--egress eth0] [--cover www.microsoft.com:443] \
    [--advertise public.example:47843] [--short-id 16_lower_hex]

Fresh install requires --client-enrollment. Generate both artifacts on the
CLIENT; never generate the client credential on the VPS:

  sudo install -d -o root -g root -m 0700 /etc/shadowpipe /root/shadowpipe-enroll
  sudo shadowpipe-client --generate-client-credential \
    --client-credential /etc/shadowpipe/client-credential.json \
    --write-client-enrollment /root/shadowpipe-enroll/client.json
  sudo scp /root/shadowpipe-enroll/client.json root@VPS:/root/client-enrollment.json

Then pass the VPS copy to this installer. It is removed only after the service
has restarted successfully. No credential, PSK, or private seed is printed.

An upgrade may omit --client-enrollment only when the existing root-owned 0600
allowlist passes the new binary's --validate-client-allowlist gate. Supplying a
new artifact performs overlap enrollment before activation; duplicate key IDs
with identical public key + PSK are idempotent retries; conflicting same-ID
artifacts are rejected before binary/unit/network changes.

REALITY short IDs are carrier selectors, not client identity. A fresh install
generates one full-width random 8-byte value and stores it only in the
root-owned 0600 file /etc/shadowpipe/reality-short-ids. Repeated --short-id
values replace that bounded sorted set explicitly; an existing legacy install
without the file must pass its intended full-width value(s) during migration.
EOF
}

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

path_present() {
  [[ -e "$1" || -L "$1" ]]
}

require_trusted_root_ancestors() {
  local source="$1" current tuple owner mode
  current="${source%/*}"
  [[ -n "$current" ]] || current=/
  while :; do
    [[ -d "$current" && ! -L "$current" ]] \
      || die "untrusted server binary ancestor: $current"
    tuple="$(stat -c '%u:%a' -- "$current")"
    IFS=: read -r owner mode <<<"$tuple"
    [[ "$owner" == 0 ]] \
      || die "server binary ancestor must be root-owned: $current"
    (( (8#$mode & 8#22) == 0 )) \
      || die "server binary ancestor must not be group/world writable: $current"
    [[ "$current" == / ]] && break
    current="${current%/*}"
    [[ -n "$current" ]] || current=/
  done
}

cleanup_owned_temps() {
  local path
  for path in "$BIN_STAGE" "$BIN_BACKUP" "$UNIT_STAGE" "$UNIT_BACKUP" \
      "$SYSCTL_STAGE" "$ALLOWLIST_BACKUP" "$SHORT_ID_STAGE" \
      "$SHORT_ID_BACKUP"; do
    if [[ -n "$path" ]]; then
      rm -f -- "$path" || true
    fi
  done
  # An empty final slot makes the `[[ -n ]] && rm` list return 1.  This helper
  # is also called directly under `set -e` after COMMITTED=1, so always report
  # the cleanup operation itself as successful after best-effort iteration.
  return 0
}

rollback_transaction() {
  echo "ERROR: provisioning failed; rolling back changes owned by this run" >&2

  if (( FORWARD_IN_RULE_ADDED )); then
    iptables -D FORWARD -i "$EGRESS" -o "$TUN_IFACE" -d "$TUN_SUBNET" \
      -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  fi
  if (( FORWARD_OUT_RULE_ADDED )); then
    iptables -D FORWARD -i "$TUN_IFACE" -o "$EGRESS" -j ACCEPT 2>/dev/null || true
  fi
  if (( NAT_RULE_ADDED )); then
    iptables -t nat -D POSTROUTING -s "$TUN_SUBNET" -o "$EGRESS" -j MASQUERADE 2>/dev/null || true
  fi
  [[ -n "$ALL_FORWARDING_BEFORE" ]] \
    && sysctl -w "net.ipv4.conf.all.forwarding=$ALL_FORWARDING_BEFORE" >/dev/null 2>&1 || true
  [[ -n "$IP_FORWARD_BEFORE" ]] \
    && sysctl -w "net.ipv4.ip_forward=$IP_FORWARD_BEFORE" >/dev/null 2>&1 || true
  if (( SYSCTL_DROPIN_CREATED )); then
    rm -f -- "$SYSCTL_DROPIN"
  fi

  if (( ALLOWLIST_MUTATION_ATTEMPTED )); then
    if (( ALLOWLIST_HAD_EXISTING )) \
        && [[ -n "$ALLOWLIST_BACKUP" && -f "$ALLOWLIST_BACKUP" ]]; then
      mv -f -- "$ALLOWLIST_BACKUP" "$CLIENT_ALLOWLIST"
      ALLOWLIST_BACKUP=""
      sync -f "$CLIENT_ALLOWLIST" 2>/dev/null || true
    elif (( ! ALLOWLIST_HAD_EXISTING )); then
      rm -f -- "$CLIENT_ALLOWLIST"
    fi
    if (( ! ALLOWLIST_LOCK_HAD_EXISTING )) && [[ -n "$ALLOWLIST_LOCK" ]]; then
      rm -f -- "$ALLOWLIST_LOCK"
    fi
  fi
  if (( RKEY_CREATION_ATTEMPTED )); then
    rm -f -- "$RKEY"
  fi
  if (( KEYS_CREATION_ATTEMPTED )); then
    rm -f -- "$KEYS"
  fi

  if (( SHORT_ID_MUTATION_ATTEMPTED )); then
    if (( SHORT_ID_HAD_EXISTING )) \
        && [[ -n "$SHORT_ID_BACKUP" && -f "$SHORT_ID_BACKUP" ]]; then
      mv -f -- "$SHORT_ID_BACKUP" "$SHORT_ID_FILE"
      SHORT_ID_BACKUP=""
      sync -f "$SHORT_ID_FILE" 2>/dev/null || true
    elif (( ! SHORT_ID_HAD_EXISTING )); then
      rm -f -- "$SHORT_ID_FILE"
    fi
  fi

  if (( UNIT_HAD_EXISTING )) && [[ -n "$UNIT_BACKUP" && -f "$UNIT_BACKUP" ]]; then
    mv -f -- "$UNIT_BACKUP" "$UNIT"
    UNIT_BACKUP=""
  elif (( ! UNIT_HAD_EXISTING )); then
    rm -f -- "$UNIT"
  fi
  if (( BIN_HAD_EXISTING )) && [[ -n "$BIN_BACKUP" && -f "$BIN_BACKUP" ]]; then
    mv -f -- "$BIN_BACKUP" "$BIN"
    BIN_BACKUP=""
  elif (( ! BIN_HAD_EXISTING )); then
    rm -f -- "$BIN"
  fi

  if (( ARTIFACTS_SWITCHED || SERVICE_STOPPED_BY_US )); then
    systemctl daemon-reload >/dev/null 2>&1 || true
    if (( ! SERVICE_WAS_ENABLED )); then
      systemctl disable shadowpipe >/dev/null 2>&1 || true
    fi
    if (( SERVICE_WAS_ACTIVE && OLD_RUNTIME_MANDATORY_V3 )); then
      systemctl restart shadowpipe >/dev/null 2>&1 || true
    else
      # Never resurrect a pre-v3/open runtime after a failed upgrade.
      systemctl stop shadowpipe >/dev/null 2>&1 || true
    fi
  fi
  if (( CONFIG_DIR_CREATED )); then
    if [[ -n "$SHORT_ID_STAGE" ]]; then
      rm -f -- "$SHORT_ID_STAGE"
      SHORT_ID_STAGE=""
    fi
    rmdir -- "$CONFIG_DIR" 2>/dev/null || true
  fi
}

on_exit() {
  local status=$?
  trap - EXIT
  set +e
  if (( status != 0 && TX_ACTIVE && ! COMMITTED )); then
    rollback_transaction
  fi
  cleanup_owned_temps
  exit "$status"
}
trap on_exit EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) [[ $# -ge 2 ]] || die "--port requires a value"; PORT="$2"; shift 2 ;;
    --egress) [[ $# -ge 2 ]] || die "--egress requires a value"; EGRESS="$2"; shift 2 ;;
    --cover) [[ $# -ge 2 ]] || die "--cover requires a value"; COVER="$2"; shift 2 ;;
    --advertise) [[ $# -ge 2 ]] || die "--advertise requires a value"; ADVERTISE="$2"; shift 2 ;;
    --short-id) [[ $# -ge 2 ]] || die "--short-id requires a value"; SHORT_IDS+=("$2"); shift 2 ;;
    --binary) [[ $# -ge 2 ]] || die "--binary requires a value"; BINARY="$2"; shift 2 ;;
    --client-allowlist) [[ $# -ge 2 ]] || die "--client-allowlist requires a value"; CLIENT_ALLOWLIST="$2"; shift 2 ;;
    --client-enrollment) [[ $# -ge 2 ]] || die "--client-enrollment requires a value"; CLIENT_ENROLLMENT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "run as root"
for command in install mktemp stat systemctl sysctl iptables grep curl cmp cp mv sync ss awk tr journalctl rmdir dirname seq sleep timeout od sort; do
  command -v "$command" >/dev/null || die "required command not found: $command"
done
if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
  die "--port must be 1..65535"
fi
[[ "$EGRESS" =~ ^[A-Za-z0-9_.:-]+$ ]] || die "unsafe --egress value"
[[ "$COVER" =~ ^[A-Za-z0-9_.:-]+$ ]] || die "unsafe --cover value"
[[ -z "$ADVERTISE" ]] || valid_advertise "$ADVERTISE" \
  || die "unsafe --advertise value"
[[ "$CLIENT_ALLOWLIST" =~ ^/[A-Za-z0-9_./-]+$ \
   && "$CLIENT_ALLOWLIST" != *'/../'* ]] \
  || die "--client-allowlist must be an absolute normalized path"
(( ${#SHORT_IDS[@]} <= 16 )) || die "at most 16 --short-id values are accepted"
for sid in "${SHORT_IDS[@]}"; do
  [[ "$sid" =~ ^[0-9a-f]{16}$ ]] \
    || die "--short-id must be exactly 16 lowercase hex characters (8 bytes)"
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -n "$BINARY" ]]; then
  SOURCE_BINARY="$BINARY"
elif [[ -x "$ROOT/target/release/shadowpipe-server" ]]; then
  SOURCE_BINARY="$ROOT/target/release/shadowpipe-server"
else
  usage >&2
  die "no executable server binary; pass --binary"
fi
[[ -f "$SOURCE_BINARY" && ! -L "$SOURCE_BINARY" && -x "$SOURCE_BINARY" ]] \
  || die "server binary must be an executable regular file, not a symlink: $SOURCE_BINARY"
[[ "$SOURCE_BINARY" == /* \
   && "$SOURCE_BINARY" != *'//'* \
   && "$SOURCE_BINARY" != *'/./'* \
   && "$SOURCE_BINARY" != */. \
   && "$SOURCE_BINARY" != *'/../'* \
   && "$SOURCE_BINARY" != */.. ]] \
  || die "server binary path must be absolute and normalized"
require_trusted_root_ancestors "$SOURCE_BINARY"
require_trusted_root_ancestors "$BIN"
SOURCE_BINARY_TUPLE="$(stat -c '%u:%a:%h' -- "$SOURCE_BINARY")"
IFS=: read -r SOURCE_BINARY_UID SOURCE_BINARY_MODE SOURCE_BINARY_LINKS \
  <<<"$SOURCE_BINARY_TUPLE"
[[ "$SOURCE_BINARY_UID" == 0 && "$SOURCE_BINARY_LINKS" == 1 ]] \
  || die "server binary must be root-owned and single-link"
(( (8#$SOURCE_BINARY_MODE & 8#22) == 0 )) \
  || die "server binary must not be group/world writable"
BIN_STAGE="$(mktemp "$INSTALL_DIR/.shadowpipe-server.stage.XXXXXX")"
install -o root -g root -m 0755 -- "$SOURCE_BINARY" "$BIN_STAGE"
[[ "$(stat -c '%u:%g:%a:%h' -- "$BIN_STAGE")" == "0:0:755:1" ]] \
  || die "trusted server binary staging failed"
for flag in --client-allowlist --enroll-client --validate-client-allowlist \
  --allow-insecure-lab-carriers --reality-short-id-file \
  --reality-replay-store; do
  timeout 5s "$BIN_STAGE" --help 2>&1 | grep -Fq -- "$flag" \
    || die "server binary lacks mandatory v3 management flag $flag"
done

if path_present "$BIN"; then
  BIN_HAD_EXISTING=1
  [[ -f "$BIN" && ! -L "$BIN" && -x "$BIN" ]] \
    || die "$BIN must be an executable regular file, not a symlink"
  [[ "$(stat -c '%u' -- "$BIN")" == 0 ]] || die "$BIN must be root-owned"
  BIN_MODE="$(stat -c '%a' -- "$BIN")"
  (( (8#$BIN_MODE & 8#22) == 0 )) || die "$BIN must not be group/world writable"
fi
if path_present "$UNIT"; then
  UNIT_HAD_EXISTING=1
  [[ -f "$UNIT" && ! -L "$UNIT" ]] || die "$UNIT must be a regular file, not a symlink"
  [[ "$(stat -c '%u' -- "$UNIT")" == 0 ]] || die "$UNIT must be root-owned"
  UNIT_MODE="$(stat -c '%a' -- "$UNIT")"
  (( (8#$UNIT_MODE & 8#22) == 0 )) || die "$UNIT must not be group/world writable"
fi
systemctl is-enabled --quiet shadowpipe 2>/dev/null && SERVICE_WAS_ENABLED=1 || true
TX_ACTIVE=1

# Identify and close a pre-v3/pre-access-gate/unverifiable live runtime before
# any later preflight can fail. A failed upgrade must leave an old enumerable
# or open relay down, not keep serving while merely reporting that enrollment
# was missing.
if systemctl is-active --quiet shadowpipe; then
  SERVICE_WAS_ACTIVE=1
  MAIN_PID="$(systemctl show -p MainPID --value shadowpipe)"
  if [[ "$MAIN_PID" =~ ^[1-9][0-9]*$ ]] \
      && timeout 5s "/proc/$MAIN_PID/exe" --help 2>&1 | grep -Fq -- '--validate-client-allowlist' \
      && timeout 5s "/proc/$MAIN_PID/exe" --help 2>&1 | grep -Fq -- '--allow-insecure-lab-carriers' \
      && timeout 5s "/proc/$MAIN_PID/exe" --help 2>&1 | grep -Fq -- '--reality-short-id-file' \
      && timeout 5s "/proc/$MAIN_PID/exe" --help 2>&1 | grep -Fq -- '--reality-replay-store' \
      && tr '\0' '\n' <"/proc/$MAIN_PID/cmdline" | grep -Fx -- '--reality-replay-store' >/dev/null \
      && tr '\0' '\n' <"/proc/$MAIN_PID/cmdline" | grep -Fx -- "$REPLAY_STORE" >/dev/null; then
    OLD_RUNTIME_MANDATORY_V3=1
  else
    echo "WARN: stopping pre-v3/unverifiable live service before upgrade" >&2
    SERVICE_STOPPED_BY_US=1
    systemctl stop shadowpipe
  fi
fi

if iptables -C FORWARD -i "$EGRESS" -o "$TUN_IFACE" -d "$TUN_SUBNET" \
    -j ACCEPT 2>/dev/null; then
  die "broad pre-v3 inbound FORWARD rule exists; remove it explicitly before retrying (the replacement is conntrack RELATED,ESTABLISHED only)"
fi

if ! path_present "$CLIENT_ALLOWLIST" && [[ -z "$CLIENT_ENROLLMENT" ]]; then
  usage >&2
  die "fresh install refuses NAT/service activation without explicit client enrollment"
fi
if [[ -n "$CLIENT_ENROLLMENT" ]]; then
  [[ -f "$CLIENT_ENROLLMENT" && ! -L "$CLIENT_ENROLLMENT" ]] \
    || die "client enrollment must be a regular file, not a symlink"
  [[ "$(stat -c '%u:%a:%h' -- "$CLIENT_ENROLLMENT")" == "0:600:1" ]] \
    || die "client enrollment must be root-owned, mode 0600, and single-link"
fi

if path_present "$CONFIG_DIR"; then
  [[ -d "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]] \
    || die "$CONFIG_DIR must be a real directory"
  [[ "$(stat -c '%u' -- "$CONFIG_DIR")" == 0 ]] \
    || die "$CONFIG_DIR must be root-owned"
  CONFIG_MODE="$(stat -c '%a' -- "$CONFIG_DIR")"
  (( (8#$CONFIG_MODE & 8#22) == 0 )) \
    || die "$CONFIG_DIR must not be group/world writable"
else
  install -d -o root -g root -m 0700 "$CONFIG_DIR"
  CONFIG_DIR_CREATED=1
fi

# Resolve the production REALITY selector set before any artifact or network
# mutation. The daemon requires an exact root-only file and never accepts these
# values in its production argv. Explicit values are normalized to a strict
# sorted unique set; otherwise reuse the existing safe file. Only a truly fresh
# install may generate a new selector implicitly.
if path_present "$SHORT_ID_FILE"; then
  SHORT_ID_HAD_EXISTING=1
  [[ -f "$SHORT_ID_FILE" && ! -L "$SHORT_ID_FILE" ]] \
    || die "$SHORT_ID_FILE must be a regular file, not a symlink"
  [[ "$(stat -c '%u:%g:%a:%h' -- "$SHORT_ID_FILE")" == "0:0:600:1" ]] \
    || die "$SHORT_ID_FILE must be root:root, mode 0600, and single-link"
  (( $(stat -c '%s' -- "$SHORT_ID_FILE") <= 1024 )) \
    || die "$SHORT_ID_FILE exceeds the 1024-byte parser bound"
  mapfile -t EXISTING_SHORT_IDS <"$SHORT_ID_FILE"
  (( ${#EXISTING_SHORT_IDS[@]} >= 1 && ${#EXISTING_SHORT_IDS[@]} <= 16 )) \
    || die "$SHORT_ID_FILE must contain 1..16 entries"
  for (( i=0; i<${#EXISTING_SHORT_IDS[@]}; i++ )); do
    [[ "${EXISTING_SHORT_IDS[i]}" =~ ^[0-9a-f]{16}$ ]] \
      || die "$SHORT_ID_FILE contains a non-canonical entry"
    if (( i > 0 )); then
      [[ "${EXISTING_SHORT_IDS[i-1]}" < "${EXISTING_SHORT_IDS[i]}" ]] \
        || die "$SHORT_ID_FILE must already be strictly sorted and unique"
    fi
  done
fi
if (( ${#SHORT_IDS[@]} == 0 )); then
  if (( SHORT_ID_HAD_EXISTING )); then
    SHORT_IDS=("${EXISTING_SHORT_IDS[@]}")
    SHORT_IDS_FROM_EXISTING=1
  elif (( UNIT_HAD_EXISTING )); then
    die "legacy install has no $SHORT_ID_FILE; pass the intended full-width --short-id value(s) explicitly"
  else
    GENERATED_SHORT_ID="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    [[ "$GENERATED_SHORT_ID" =~ ^[0-9a-f]{16}$ ]] \
      || die "OS random source did not produce one full-width REALITY short ID"
    SHORT_IDS=("$GENERATED_SHORT_ID")
  fi
fi
(( ${#SHORT_IDS[@]} >= 1 && ${#SHORT_IDS[@]} <= 16 )) \
  || die "REALITY short-id file must contain 1..16 entries"
for sid in "${SHORT_IDS[@]}"; do
  [[ "$sid" =~ ^[0-9a-f]{16}$ ]] \
    || die "REALITY short IDs must each be exactly 16 lowercase hex characters"
done
mapfile -t SORTED_SHORT_IDS < <(printf '%s\n' "${SHORT_IDS[@]}" | LC_ALL=C sort)
[[ ${#SORTED_SHORT_IDS[@]} -eq ${#SHORT_IDS[@]} ]] \
  || die "failed to normalize REALITY short IDs"
for (( i=1; i<${#SORTED_SHORT_IDS[@]}; i++ )); do
  [[ "${SORTED_SHORT_IDS[i-1]}" != "${SORTED_SHORT_IDS[i]}" ]] \
    || die "duplicate REALITY short ID"
done
if (( SHORT_IDS_FROM_EXISTING )); then
  for (( i=0; i<${#SORTED_SHORT_IDS[@]}; i++ )); do
    [[ "${SHORT_IDS[i]}" == "${SORTED_SHORT_IDS[i]}" ]] \
      || die "$SHORT_ID_FILE must already be strictly sorted"
  done
elif (( SHORT_ID_HAD_EXISTING )); then
  SHORT_ID_OVERLAP=0
  for old_sid in "${EXISTING_SHORT_IDS[@]}"; do
    for new_sid in "${SORTED_SHORT_IDS[@]}"; do
      [[ "$old_sid" == "$new_sid" ]] && SHORT_ID_OVERLAP=1
    done
  done
  (( SHORT_ID_OVERLAP )) \
    || die "REALITY short-id rotation requires an overlap release before retiring the last old selector"
fi
SHORT_IDS=("${SORTED_SHORT_IDS[@]}")
SHORT_ID_STAGE="$(mktemp "$CONFIG_DIR/.reality-short-ids.stage.XXXXXX")"
printf '%s\n' "${SHORT_IDS[@]}" >"$SHORT_ID_STAGE"
chown root:root "$SHORT_ID_STAGE"
chmod 0600 "$SHORT_ID_STAGE"
[[ "$(stat -c '%u:%g:%a:%h' -- "$SHORT_ID_STAGE")" == "0:0:600:1" ]] \
  || die "failed to stage exact root-owned REALITY short-id file"

# The staged new binary performs every authorization mutation/check. The live
# install path, unit, sysctls, iptables, and service are still untouched.
if path_present "$CLIENT_ALLOWLIST"; then
  "$BIN_STAGE" --validate-client-allowlist --client-allowlist "$CLIENT_ALLOWLIST" \
    || die "existing client allowlist is unsafe or invalid"
fi
if [[ -n "$CLIENT_ENROLLMENT" ]]; then
  ALLOWLIST_DIR="$(dirname "$CLIENT_ALLOWLIST")"
  ALLOWLIST_LOCK="$ALLOWLIST_DIR/.${CLIENT_ALLOWLIST##*/}.shadowpipe-mutation-lock"
  path_present "$ALLOWLIST_LOCK" && ALLOWLIST_LOCK_HAD_EXISTING=1
  if path_present "$CLIENT_ALLOWLIST"; then
    ALLOWLIST_HAD_EXISTING=1
    ALLOWLIST_BACKUP="$(mktemp "$(dirname "$CLIENT_ALLOWLIST")/.client-allowlist.backup.XXXXXX")"
    cp -a -- "$CLIENT_ALLOWLIST" "$ALLOWLIST_BACKUP"
    [[ "$(stat -c '%u:%a:%h' -- "$ALLOWLIST_BACKUP")" == "0:600:1" ]] \
      || die "failed to create an exact private allowlist rollback snapshot"
  fi
  ALLOWLIST_MUTATION_ATTEMPTED=1
  "$BIN_STAGE" --enroll-client "$CLIENT_ENROLLMENT" --client-allowlist "$CLIENT_ALLOWLIST"
fi
"$BIN_STAGE" --validate-client-allowlist --client-allowlist "$CLIENT_ALLOWLIST" \
  || die "client authorization gate failed"

# Server identities may be created after authorization, but still before any
# forwarding/NAT or listener activation.
path_present "$KEYS" || KEYS_CREATION_ATTEMPTED=1
"$BIN_STAGE" --gen-keys --keys "$KEYS"
path_present "$RKEY" || RKEY_CREATION_ATTEMPTED=1
"$BIN_STAGE" --gen-reality-key --reality-key "$RKEY"
if [[ -z "$ADVERTISE" ]]; then
  PUBIP="$(curl -4fsS --max-time 8 https://ifconfig.me/ip)" \
    || die "public endpoint discovery failed; pass --advertise explicitly"
  valid_ipv4_literal "$PUBIP" \
    || die "public IPv4 discovery returned an unsafe address; pass --advertise explicitly"
  ADVERTISE="$PUBIP:$PORT"
fi

UNIT_STAGE="$(mktemp "$(dirname "$UNIT")/.shadowpipe.service.stage.XXXXXX")"
cat >"$UNIT_STAGE" <<EOF
[Unit]
Description=shadowpipe mandatory-v3 REALITY tunnel server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
UMask=0077
StateDirectory=shadowpipe
StateDirectoryMode=0700
Environment=RUST_LOG=info
ExecStart=$BIN \\
  --listen 0.0.0.0:$PORT \\
  --tunnel --reality \\
  --keys $KEYS \\
  --client-allowlist $CLIENT_ALLOWLIST \\
  --reality-key $RKEY \\
  --reality-short-id-file $SHORT_ID_FILE \\
  --reality-replay-store $REPLAY_STORE \\
  --cover $COVER \\
  --advertise $ADVERTISE \\
  --egress-iface $EGRESS
Restart=on-failure
RestartSec=1s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
chown root:root "$UNIT_STAGE"
chmod 0644 "$UNIT_STAGE"

# Refuse to overwrite an unrelated persistent sysctl policy. An absent file is
# created atomically and is removed by rollback if activation later fails.
SYSCTL_STAGE="$(mktemp "$(dirname "$SYSCTL_DROPIN")/.shadowpipe-sysctl.stage.XXXXXX")"
cat >"$SYSCTL_STAGE" <<'EOF'
# Managed by deploy/install-vps.sh
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
EOF
chown root:root "$SYSCTL_STAGE"
chmod 0644 "$SYSCTL_STAGE"
if path_present "$SYSCTL_DROPIN"; then
  [[ -f "$SYSCTL_DROPIN" && ! -L "$SYSCTL_DROPIN" ]] \
    || die "$SYSCTL_DROPIN must be a regular file, not a symlink"
  [[ "$(stat -c '%u:%a:%h' -- "$SYSCTL_DROPIN")" == "0:644:1" ]] \
    || die "$SYSCTL_DROPIN must be root-owned, mode 0644, and single-link"
  cmp -s -- "$SYSCTL_STAGE" "$SYSCTL_DROPIN" \
    || die "refusing to replace existing non-matching $SYSCTL_DROPIN"
else
  mv -- "$SYSCTL_STAGE" "$SYSCTL_DROPIN"
  SYSCTL_STAGE=""
  SYSCTL_DROPIN_CREATED=1
fi

# Preserve exact previous artifacts for scoped rollback, then atomically switch
# names only after the staged binary has accepted the authorization database.
if (( BIN_HAD_EXISTING )); then
  BIN_BACKUP="$(mktemp "$INSTALL_DIR/.shadowpipe-server.backup.XXXXXX")"
  cp -a -- "$BIN" "$BIN_BACKUP"
fi
if (( UNIT_HAD_EXISTING )); then
  UNIT_BACKUP="$(mktemp "$(dirname "$UNIT")/.shadowpipe.service.backup.XXXXXX")"
  cp -a -- "$UNIT" "$UNIT_BACKUP"
fi
if (( SHORT_ID_HAD_EXISTING )); then
  SHORT_ID_BACKUP="$(mktemp "$CONFIG_DIR/.reality-short-ids.backup.XXXXXX")"
  cp -a -- "$SHORT_ID_FILE" "$SHORT_ID_BACKUP"
  [[ "$(stat -c '%u:%g:%a:%h' -- "$SHORT_ID_BACKUP")" == "0:0:600:1" ]] \
    || die "failed to create an exact private REALITY short-id rollback snapshot"
fi
mv -f -- "$BIN_STAGE" "$BIN"
BIN_STAGE=""
mv -f -- "$UNIT_STAGE" "$UNIT"
UNIT_STAGE=""
SHORT_ID_MUTATION_ATTEMPTED=1
mv -f -- "$SHORT_ID_STAGE" "$SHORT_ID_FILE"
SHORT_ID_STAGE=""
ARTIFACTS_SWITCHED=1
sync -f "$BIN" "$UNIT" "$SHORT_ID_FILE" "$SYSCTL_DROPIN" 2>/dev/null || sync

IP_FORWARD_BEFORE="$(sysctl -n net.ipv4.ip_forward)"
ALL_FORWARDING_BEFORE="$(sysctl -n net.ipv4.conf.all.forwarding)"
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.forwarding=1
if ! iptables -t nat -C POSTROUTING -s "$TUN_SUBNET" -o "$EGRESS" -j MASQUERADE 2>/dev/null; then
  iptables -t nat -I POSTROUTING 1 -s "$TUN_SUBNET" -o "$EGRESS" -j MASQUERADE
  NAT_RULE_ADDED=1
fi
if ! iptables -C FORWARD -i "$TUN_IFACE" -o "$EGRESS" -j ACCEPT 2>/dev/null; then
  iptables -I FORWARD 1 -i "$TUN_IFACE" -o "$EGRESS" -j ACCEPT
  FORWARD_OUT_RULE_ADDED=1
fi
if ! iptables -C FORWARD -i "$EGRESS" -o "$TUN_IFACE" -d "$TUN_SUBNET" \
    -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
  iptables -I FORWARD 2 -i "$EGRESS" -o "$TUN_IFACE" -d "$TUN_SUBNET" \
    -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  FORWARD_IN_RULE_ADDED=1
fi

systemctl daemon-reload
systemctl enable shadowpipe
systemctl restart shadowpipe
STABLE_ACTIVE_SAMPLES=0
for _ in $(seq 1 20); do
  CURRENT_PID="$(systemctl show -p MainPID --value shadowpipe 2>/dev/null || true)"
  if systemctl is-active --quiet shadowpipe \
      && [[ "$CURRENT_PID" =~ ^[1-9][0-9]*$ ]] \
      && cmp -s -- "/proc/$CURRENT_PID/exe" "$BIN" \
      && tr '\0' '\n' <"/proc/$CURRENT_PID/cmdline" | grep -Fx -- '--client-allowlist' >/dev/null \
      && tr '\0' '\n' <"/proc/$CURRENT_PID/cmdline" | grep -Fx -- "$CLIENT_ALLOWLIST" >/dev/null \
      && tr '\0' '\n' <"/proc/$CURRENT_PID/cmdline" | grep -Fx -- '--reality-short-id-file' >/dev/null \
      && tr '\0' '\n' <"/proc/$CURRENT_PID/cmdline" | grep -Fx -- "$SHORT_ID_FILE" >/dev/null \
      && tr '\0' '\n' <"/proc/$CURRENT_PID/cmdline" | grep -Fx -- '--reality-replay-store' >/dev/null \
      && tr '\0' '\n' <"/proc/$CURRENT_PID/cmdline" | grep -Fx -- "$REPLAY_STORE" >/dev/null \
      && ! tr '\0' '\n' <"/proc/$CURRENT_PID/cmdline" | grep -Fx -- '--reality-short-id' >/dev/null \
      && [[ "$(stat -c '%u:%g:%a:%h' -- "$REPLAY_STORE" 2>/dev/null || true)" == "0:0:600:1" ]] \
      && [[ "$(stat -c '%u:%g:%a:%h' -- "$REPLAY_STORE.lock" 2>/dev/null || true)" == "0:0:600:1" ]] \
      && ss -H -ltn | awk '{print $4}' | grep -E "(^|[:.])${PORT}$" >/dev/null \
      && journalctl -u shadowpipe "_PID=$CURRENT_PID" -n 80 --no-pager 2>/dev/null \
           | grep -F 'listening' >/dev/null; then
    STABLE_ACTIVE_SAMPLES=$((STABLE_ACTIVE_SAMPLES + 1))
    (( STABLE_ACTIVE_SAMPLES >= 3 )) && break
  else
    STABLE_ACTIVE_SAMPLES=0
  fi
  sleep 1
done
(( STABLE_ACTIVE_SAMPLES >= 3 )) \
  || die "new mandatory-v3 process did not remain active/listening for three consecutive samples"
"$BIN" --validate-client-allowlist --client-allowlist "$CLIENT_ALLOWLIST" \
  || die "post-activation allowlist validation failed"
COMMITTED=1

# Consume the transported enrollment only after successful activation. Failure
# to remove it is reported but cannot undo an already healthy service.
if [[ -n "$CLIENT_ENROLLMENT" ]] && ! rm -f -- "$CLIENT_ENROLLMENT"; then
  echo "WARN: remove the one-time enrollment artifact manually: $CLIENT_ENROLLMENT" >&2
fi
cleanup_owned_temps

# The normal daemon deliberately never logs the short ID or a complete URI.
# Create a one-time root-only bootstrap artifact through the explicit one-shot
# command instead. This file is a manual diagnostic input, not signed endpoint
# authority; transfer it over an authenticated confidential channel and delete
# both copies after the signed policy has been enrolled.
BOOTSTRAP_FILE="$(mktemp /root/shadowpipe-client-bootstrap.XXXXXX)"
chmod 0600 "$BOOTSTRAP_FILE"
PRINT_URI_ARGS=(
  --print-uri --reality
  --keys "$KEYS"
  --reality-key "$RKEY"
  --reality-short-id-file "$SHORT_ID_FILE"
  --cover "$COVER"
  --advertise "$ADVERTISE"
)
if ! "$BIN" "${PRINT_URI_ARGS[@]}" \
    | awk '/^reality-uri: shadowpipe:\/\// && !found { sub(/^reality-uri: /, ""); print; found=1 } END { exit !found }' \
    >"$BOOTSTRAP_FILE"; then
  rm -f -- "$BOOTSTRAP_FILE"
  BOOTSTRAP_FILE=""
  echo "WARN: explicit one-shot URI export failed; service remains healthy and no URI was logged" >&2
elif [[ "$(stat -c '%u:%g:%a:%h' -- "$BOOTSTRAP_FILE")" != "0:0:600:1" ]]; then
  rm -f -- "$BOOTSTRAP_FILE"
  BOOTSTRAP_FILE=""
  echo "WARN: refusing unsafe bootstrap artifact; service remains healthy" >&2
fi

echo
echo "== shadowpipe mandatory-v3 REALITY server installed =="
echo "Binary:     $BIN"
echo "Allowlist:  $CLIENT_ALLOWLIST (validated root:0600, non-empty)"
echo "Keys:       $KEYS (ML-KEM)   $RKEY (REALITY X25519)"
echo "Port:       $PORT/tcp"
echo "Cover:      $COVER"
echo "Advertise:  $ADVERTISE"
echo "Credential: remains only on the client; no secret was printed"
echo "Short IDs:  $SHORT_ID_FILE (root:0600; values absent from daemon argv/journal)"
echo "Replay:     $REPLAY_STORE (root:0600 fixed-slot state; exclusive same-host lease)"
if [[ -n "$BOOTSTRAP_FILE" ]]; then
  echo
  echo "Bootstrap:  $BOOTSTRAP_FILE (root:0600; securely transfer, then delete)"
  echo "Manual single-endpoint diagnostic only: read that URI inside a disposable client/netns."
  echo "Production clients must use the separately enrolled root key + signed endpoint-policy service configuration."
else
  echo "WARN: no bootstrap artifact was published; invoke the explicit root-only --print-uri one-shot manually." >&2
fi
