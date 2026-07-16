#!/usr/bin/env bash
set -euo pipefail

# Destructive only inside two disposable Linux network namespaces. Never run
# this against the host namespace. Pass an already-built Linux client binary.
BIN=${1:?usage: run-netns-lockdown.sh /path/to/shadowpipe-client}
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
[[ -x $BIN ]] || { echo "client binary is not executable: $BIN" >&2; exit 2; }

suffix=$$
client_ns="sp-lock-c-${suffix}"
peer_ns="sp-lock-p-${suffix}"
client_if="spc${suffix: -6}"
peer_if="spp${suffix: -6}"
state="/tmp/shadowpipe-lockdown-${suffix}"
work="/tmp/shadowpipe-lockdown-work-${suffix}"
client_pid=
server_pid=
exact_server_pid=

cleanup() {
  local rc=$?
  set +e
  if ((rc != 0)); then
    echo "lockdown netns harness failed with exit ${rc}" >&2
    for log in "$work"/*.log; do
      [[ -f $log ]] || continue
      echo "===== ${log##*/} =====" >&2
      sed -n '1,240p' "$log" >&2
    done
    if [[ -d $state ]]; then
      echo "===== retained state entries before cleanup =====" >&2
      find "$state" -maxdepth 1 -mindepth 1 -printf '%f %y %m %u:%g %s bytes\n' >&2
    fi
  fi
  [[ -n $client_pid ]] && kill "$client_pid" 2>/dev/null
  [[ -n $server_pid ]] && kill "$server_pid" 2>/dev/null
  [[ -n $exact_server_pid ]] && kill "$exact_server_pid" 2>/dev/null
  ip netns del "$client_ns" 2>/dev/null
  ip netns del "$peer_ns" 2>/dev/null
  rm -rf "$state" "$work"
  return "$rc"
}
trap cleanup EXIT INT TERM

mkdir -m 0700 "$state" "$work"
ip netns add "$client_ns"
ip netns add "$peer_ns"
ip link add "$client_if" type veth peer name "$peer_if"
ip link set "$client_if" netns "$client_ns"
ip link set "$peer_if" netns "$peer_ns"
ip -n "$client_ns" link set lo up
ip -n "$peer_ns" link set lo up
ip -n "$client_ns" addr add 198.18.0.2/24 dev "$client_if"
ip -n "$peer_ns" addr add 198.18.0.1/24 dev "$peer_if"
ip -n "$client_ns" -6 addr add 2001:db8:228::2/64 dev "$client_if"
ip -n "$peer_ns" -6 addr add 2001:db8:228::1/64 dev "$peer_if"
ip -n "$client_ns" link set "$client_if" up
ip -n "$peer_ns" link set "$peer_if" up

# A genuinely fresh host has no continuity authority. Early restore must be a
# zero-ruleset-mutation no-op instead of unexpectedly bricking direct mode.
fresh_state="$work/fresh-state"
mkdir -m 0700 "$fresh_state"
fresh_before=$(ip netns exec "$client_ns" nft -j list ruleset | sha256sum)
nsenter --net="/run/netns/$client_ns" "$BIN" --restore-lockdown \
  --host-state-dir "$fresh_state" >"$work/fresh.log" 2>&1
fresh_after=$(ip netns exec "$client_ns" nft -j list ruleset | sha256sum)
[[ $fresh_before == "$fresh_after" ]] || {
  echo "fresh early-boot restore mutated the nft ruleset" >&2
  exit 1
}
[[ ! -e $fresh_state/handoff-lockdown-v1.json ]] || {
  echo "fresh early-boot restore unexpectedly created a barrier" >&2
  exit 1
}

# Establish an unrelated TCP flow before the barrier. The server must receive
# the first byte but not the byte sent after lockdown engagement: there is no
# broad ct state established allowance.
ip netns exec "$peer_ns" python3 - "$work/server-listen" "$work/server-pre" "$work/server-result" <<'PY' &
import pathlib, socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.18.0.1", 54000))
s.listen(1)
pathlib.Path(sys.argv[1]).touch()
c, _ = s.accept()
assert c.recv(1) == b"A"
pathlib.Path(sys.argv[2]).touch()
c.settimeout(1.5)
try:
    post = c.recv(1)
except TimeoutError:
    post = b""
pathlib.Path(sys.argv[3]).write_bytes(post)
PY
server_pid=$!

for _ in $(seq 1 500); do
  [[ -e $work/server-listen ]] && break
  sleep 0.01
done
[[ -e $work/server-listen ]] || {
  echo "pre-lockdown server did not listen" >&2
  exit 1
}

ip netns exec "$client_ns" python3 - "$work/client-ready" "$work/go" <<'PY' &
import pathlib, socket, sys, time
s = socket.socket()
s.bind(("198.18.0.2", 54001))
s.connect(("198.18.0.1", 54000))
s.sendall(b"A")
pathlib.Path(sys.argv[1]).touch()
deadline = time.monotonic() + 5
while not pathlib.Path(sys.argv[2]).exists():
    if time.monotonic() >= deadline:
        raise RuntimeError("barrier test coordination timed out")
    time.sleep(0.01)
s.sendall(b"B")
time.sleep(0.2)
PY
client_pid=$!

for _ in $(seq 1 500); do
  [[ -e $work/client-ready && -e $work/server-pre ]] && break
  sleep 0.01
done
[[ -e $work/client-ready && -e $work/server-pre ]] || {
  echo "pre-lockdown established flow did not become ready" >&2
  exit 1
}

# Any main-WAL entry is conservative protection evidence. The intentionally
# invalid file makes ordinary startup stop after the independent barrier has
# been durably armed, without creating a TUN or touching host routes/DNS.
: >"$state/host-state-v2.json"
chmod 0600 "$state/host-state-v2.json"
fp=$(printf '11%.0s' $(seq 1 32))
if nsenter --net="/run/netns/$client_ns" env \
  SSH_CONNECTION="198.18.0.1 53000 198.18.0.2 22" \
  "$BIN" --tunnel --server 192.0.2.9:443 --server-fp "$fp" \
  --host-state-dir "$state" >"$work/arm.log" 2>&1; then
  echo "invalid main WAL unexpectedly allowed ordinary startup" >&2
  exit 1
fi

[[ -s $state/handoff-lockdown-v1.json ]] || {
  echo "barrier WAL was not durably created" >&2
  exit 1
}
table=$(python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); print("sp_lock_" + j["identity"])' \
  "$state/handoff-lockdown-v1.json")
handle_before=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["table_handle"])' \
  "$state/handoff-lockdown-v1.json")
ip netns exec "$client_ns" nft -j -a list table inet "$table" >"$work/table-before.json"

touch "$work/go"
wait "$client_pid"
client_pid=
wait "$server_pid"
server_pid=
[[ ! -s $work/server-result ]] || {
  echo "unrelated established TCP flow escaped the lockdown" >&2
  exit 1
}

# Family-neutral loopback remains usable; all non-loopback IPv4 and IPv6 are
# dropped unless the exact four-field SSH flow matches.
ip netns exec "$client_ns" ping -q -c 1 -W 1 127.0.0.1 >/dev/null
ip netns exec "$client_ns" ping -q -6 -c 1 -W 1 ::1 >/dev/null
if ip netns exec "$client_ns" ping -q -c 1 -W 1 198.18.0.1 >/dev/null 2>&1; then
  echo "non-loopback IPv4 escaped the lockdown" >&2
  exit 1
fi
if ip netns exec "$client_ns" ping -q -6 -c 1 -W 1 2001:db8:228::1 >/dev/null 2>&1; then
  echo "non-loopback IPv6 escaped the lockdown" >&2
  exit 1
fi

# Exact server->SSH-client IPv4/TCP source+destination address+port survives.
ip netns exec "$peer_ns" python3 - "$work/exact-result" <<'PY' &
import pathlib, socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.18.0.1", 53000))
s.listen(1)
s.settimeout(3)
c, _ = s.accept()
pathlib.Path(sys.argv[1]).write_bytes(c.recv(16))
PY
exact_server_pid=$!
sleep 0.05
ip netns exec "$client_ns" python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("198.18.0.2", 22))
s.settimeout(2)
s.connect(("198.18.0.1", 53000))
s.sendall(b"exact-ssh")
PY
wait "$exact_server_pid"
exact_server_pid=
[[ $(<"$work/exact-result") == exact-ssh ]] || {
  echo "exact SSH control tuple was not admitted" >&2
  exit 1
}

# A one-field port deviation is denied.
if ip netns exec "$client_ns" python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("198.18.0.2", 23))
s.settimeout(0.4)
try:
    s.connect(("198.18.0.1", 53000))
except TimeoutError:
    raise SystemExit(1)
PY
then
  echo "non-exact SSH tuple escaped the lockdown" >&2
  exit 1
fi

# A second process adopts the exact Active table instead of reinstalling it.
nsenter --net="/run/netns/$client_ns" "$BIN" --restore-lockdown \
  --host-state-dir "$state" >"$work/adopt.log" 2>&1
handle_after=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["table_handle"])' \
  "$state/handoff-lockdown-v1.json")
[[ $handle_before == "$handle_after" ]] || {
  echo "next process reinstalled instead of adopting the barrier" >&2
  exit 1
}

# Explicit operator release is the only direct-network restoration path.
rm "$state/host-state-v2.json"
nsenter --net="/run/netns/$client_ns" env -u SSH_CONNECTION -u SSH_CLIENT \
  "$BIN" --release-lockdown \
  --host-state-dir "$state" >"$work/release.log" 2>&1
[[ ! -e $state/handoff-lockdown-v1.json ]] || {
  echo "explicit release left the barrier WAL" >&2
  exit 1
}
if ip netns exec "$client_ns" nft list table inet "$table" >/dev/null 2>&1; then
  echo "explicit release left the barrier table" >&2
  exit 1
fi
ip netns exec "$client_ns" ping -q -c 1 -W 1 198.18.0.1 >/dev/null
ip netns exec "$client_ns" ping -q -6 -c 1 -W 1 2001:db8:228::1 >/dev/null

# A foreign/drifted rule is a zero-mutation conflict: recovery neither adopts
# nor deletes it. Cleanup below is lab-only and destroys the whole namespace.
conflict_state="$work/conflict-state"
mkdir -m 0700 "$conflict_state"
: >"$conflict_state/host-state-v2.json"
chmod 0600 "$conflict_state/host-state-v2.json"
nsenter --net="/run/netns/$client_ns" "$BIN" --restore-lockdown \
  --host-state-dir "$conflict_state" >"$work/conflict-arm.log" 2>&1
conflict_table=$(python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); print("sp_lock_" + j["identity"])' \
  "$conflict_state/handoff-lockdown-v1.json")
ip netns exec "$client_ns" nft add rule inet "$conflict_table" sp_output counter accept \
  comment foreign-test
conflict_before=$(ip netns exec "$client_ns" nft -j -a list table inet "$conflict_table" | sha256sum)
if nsenter --net="/run/netns/$client_ns" "$BIN" --restore-lockdown \
  --host-state-dir "$conflict_state" >"$work/conflict-adopt.log" 2>&1; then
  echo "foreign lockdown rule was unexpectedly adopted" >&2
  exit 1
fi
conflict_after=$(ip netns exec "$client_ns" nft -j -a list table inet "$conflict_table" | sha256sum)
[[ $conflict_before == "$conflict_after" ]] || {
  echo "conflict recovery mutated the foreign table" >&2
  exit 1
}
ip netns exec "$client_ns" nft delete table inet "$conflict_table"

echo "PASS: fresh no-op, durable WAL/adoption, exact SSH, established-flow denial, IPv4/IPv6/loopback, conflict zero-mutation, explicit release"
