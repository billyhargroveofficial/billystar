#!/usr/bin/env bash
# Mac-testable render check for the mandatory-v3 deploy scripts. This checks
# security-critical wiring only; it performs no root, Linux, SSH or network
# action and is not runtime evidence for systemd/iptables rollback.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "FAIL: $1" >&2; exit 1; }

# 1. Syntax.
for f in deploy/install-vps.sh scripts/deploy-linux.sh \
  scripts/macos/ensure-nl-server.sh examples/connect-client.sh; do
  bash -n "$f" || fail "bash -n $f"
done

# 2. install-vps.sh wires mandatory REALITY + authorization-first activation.
I=deploy/install-vps.sh
grep -q -- '--gen-reality-key'                 "$I" || fail "install-vps: no reality key gen"
grep -q -- '--tunnel --reality'                "$I" || fail "install-vps: unit not running --reality"
grep -q -- '--cover'                           "$I" || fail "install-vps: no --cover"
grep -q -- '--advertise'                       "$I" || fail "install-vps: no --advertise"
grep -q -- '--client-enrollment'                "$I" || fail "install-vps: no explicit enrollment input"
grep -q -- '--validate-client-allowlist'        "$I" || fail "install-vps: no staged allowlist validation"
grep -q -- '--enroll-client'                    "$I" || fail "install-vps: staged binary does not enroll"
grep -q -- '--allow-insecure-lab-carriers'      "$I" || fail "install-vps: no mandatory access-gate capability check"
grep -q -- '--reality-short-id-file'            "$I" || fail "install-vps: no root-only REALITY selector file"
grep -q 'reality-short-ids'                     "$I" || fail "install-vps: no persisted REALITY selector state"
grep -q -- '--reality-replay-store'             "$I" || fail "install-vps: no durable REALITY replay store"
grep -q 'StateDirectory=shadowpipe'             "$I" || fail "install-vps: no private replay state directory"
grep -q 'StateDirectoryMode=0700'               "$I" || fail "install-vps: replay state directory mode is not 0700"
grep -q 'REPLAY_STORE.lock'                     "$I" || fail "install-vps: no replay lease-file health proof"
grep -q 'fresh install refuses NAT/service activation without explicit client enrollment' \
  "$I" || fail "install-vps: fresh install is not fail-closed on missing enrollment"
grep -q 'RELATED,ESTABLISHED'                  "$I" || fail "install-vps: inbound return path is not conntrack-bounded"
grep -q 'POSTROUTING.*MASQUERADE'              "$I" || fail "install-vps: NAT not applied (only hinted?)"
grep -q 'Bootstrap:'                            "$I" || fail "install-vps: no root-only explicit bootstrap artifact"
grep -q "journalctl.*shadowpipe://"            "$I" && fail "install-vps: still scrapes a secret URI from journald"
grep -q 'nat-hint' "$I" && fail "install-vps: still only HINTS NAT (should apply it)"

# 3. deploy-linux.sh is no longer an opt-in legacy path: it requires a matched
# credential/enrollment pair and sends the enrollment only to the server.
D=scripts/deploy-linux.sh
grep -q 'mandatory-v3 REALITY'                 "$D" || fail "deploy-linux: mandatory REALITY boundary missing"
grep -q 'SP_CLIENT_CREDENTIAL_LOCAL'           "$D" || fail "deploy-linux: no local credential input"
grep -q 'SP_CLIENT_ENROLLMENT_LOCAL'           "$D" || fail "deploy-linux: no local enrollment input"
grep -q 'credential and enrollment are malformed or do not describe the same client' \
  "$D" || fail "deploy-linux: no credential/enrollment pairing gate"
grep -q -- '--client-enrollment'               "$D" || fail "deploy-linux: enrollment not passed to installer"
grep -q -- '--write-client-enrollment'         "$D" || fail "deploy-linux: installed credential is not re-export verified"
grep -q 'NL_BOOTSTRAP_PATH'                     "$D" || fail "deploy-linux: does not preserve the root-only bootstrap path"
grep -q "grep -o 'shadowpipe://"               "$D" && fail "deploy-linux: still copies a secret URI through shell output"
grep -q 'SP_REALITY' "$D" && fail "deploy-linux: stale optional SP_REALITY path remains"

# 4. Client helper requires both the public URI and the private credential.
grep -q -- '--uri' examples/connect-client.sh   || fail "connect-client: not using --uri"
grep -q -- '--client-credential' examples/connect-client.sh \
  || fail "connect-client: mandatory credential is not passed"
grep -q -- '--kill-switch' examples/connect-client.sh \
  || fail "connect-client: fail-closed firewall is not enabled"
grep -q -- '--dns' examples/connect-client.sh \
  || fail "connect-client: tunnel DNS pin is not enabled"

# 5. The paired Linux units preserve the host mount/network namespace identity
# required by WAL adoption while bounding every independent privilege/resource
# surface. This is a static render check; Linux systemd-analyze and VM runtime
# validation remain deployment gates.
CLIENT_UNIT=deploy/shadowpipe-client-full-tunnel.service
RESTORE_UNIT=deploy/shadowpipe-lockdown-restore.service

require_unit_line() {
  local unit=$1 line=$2
  grep -Fqx -- "$line" "$unit" \
    || fail "$unit: missing exact hardening directive: $line"
}

reject_unit_key() {
  local unit=$1 key=$2
  if grep -Eq "^[[:space:]]*${key}=" "$unit"; then
    fail "$unit: $key would change the WAL-bound mount/network namespace model"
  fi
}

for unit in "$CLIENT_UNIT" "$RESTORE_UNIT"; do
  require_unit_line "$unit" 'LimitCORE=0'
  require_unit_line "$unit" 'NoNewPrivileges=yes'
  require_unit_line "$unit" 'DevicePolicy=closed'
  require_unit_line "$unit" 'KeyringMode=private'
  require_unit_line "$unit" 'RestrictNamespaces=yes'
  require_unit_line "$unit" 'RestrictRealtime=yes'
  require_unit_line "$unit" 'RestrictSUIDSGID=yes'
  require_unit_line "$unit" 'LockPersonality=yes'
  require_unit_line "$unit" 'MemoryDenyWriteExecute=yes'
  require_unit_line "$unit" 'SystemCallArchitectures=native'
  require_unit_line "$unit" 'SystemCallErrorNumber=EPERM'
  require_unit_line "$unit" \
    'SystemCallFilter=~@clock @cpu-emulation @debug @keyring @module @mount @obsolete @raw-io @reboot @swap'

  for key in PrivateMounts PrivateTmp PrivateDevices ProtectSystem ProtectHome \
    ReadWritePaths ReadOnlyPaths InaccessiblePaths PrivateIPC; do
    reject_unit_key "$unit" "$key"
  done
done

require_unit_line "$CLIENT_UNIT" 'StateDirectory=shadowpipe'
require_unit_line "$CLIENT_UNIT" 'StateDirectoryMode=0700'
require_unit_line "$CLIENT_UNIT" 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_FOWNER'
require_unit_line "$CLIENT_UNIT" 'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_FOWNER'
require_unit_line "$CLIENT_UNIT" 'DeviceAllow=/dev/net/tun rw'
require_unit_line "$CLIENT_UNIT" 'RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET'
require_unit_line "$CLIENT_UNIT" 'LimitNOFILE=65536'
require_unit_line "$CLIENT_UNIT" 'TasksMax=512'
require_unit_line "$CLIENT_UNIT" 'MemoryHigh=768M'
require_unit_line "$CLIENT_UNIT" 'MemoryMax=1G'
require_unit_line "$CLIENT_UNIT" 'MemorySwapMax=256M'

require_unit_line "$RESTORE_UNIT" 'CapabilityBoundingSet=CAP_NET_ADMIN'
require_unit_line "$RESTORE_UNIT" 'AmbientCapabilities=CAP_NET_ADMIN'
require_unit_line "$RESTORE_UNIT" 'RestrictAddressFamilies=AF_UNIX AF_NETLINK'
require_unit_line "$RESTORE_UNIT" 'LimitNOFILE=1024'
require_unit_line "$RESTORE_UNIT" 'TasksMax=64'
require_unit_line "$RESTORE_UNIT" 'MemoryHigh=192M'
require_unit_line "$RESTORE_UNIT" 'MemoryMax=256M'
require_unit_line "$RESTORE_UNIT" 'MemorySwapMax=64M'
grep -Eq '^[[:space:]]*DeviceAllow=' "$RESTORE_UNIT" \
  && fail "$RESTORE_UNIT: restore oneshot must not receive any extra device"

echo "OK: deploy scripts render mandatory-v3 REALITY + enrollment gates"
