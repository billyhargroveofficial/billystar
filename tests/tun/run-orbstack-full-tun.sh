#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Full OS-TUN correctness/leak lab for Shadowpipe.
#
# Host mode runs only OrbStack lifecycle commands, bounded stdin/stdout streams
# and read-only macOS safety snapshots. It clones a stopped capability-isolated
# source VM, streams a pinned Git archive into the disposable clone, builds and
# runs entirely on guest-local storage, streams sealed evidence back, then
# destroys the clone. No Mac directory is mounted or shared with the guest.
#
# Guest mode owns all privileged network changes. Every veth, route, firewall
# rule, TUN and listener lives in one of four Linux network namespaces. The
# client has two isolated IPv4/IPv6 underlay links: IPv4 is tunneled, while
# connected IPv6 is retained only as a fail-closed OUTPUT-block canary. No lab
# link is connected to the guest management interface or the public Internet.

readonly EX_USAGE=64
readonly EX_UNAVAILABLE=69
readonly EX_NOPERM=77
readonly MAGIC_DEFAULT=0x50334852
readonly HOST_COMMAND_TIMEOUT=30
readonly GUEST_COMMAND_TIMEOUT=180
readonly ORB_CLONE_TIMEOUT=900
readonly ORB_START_TIMEOUT=180
readonly ORB_DELETE_TIMEOUT=300
readonly BUILD_TIMEOUT=1800
readonly LAB_TIMEOUT=1200
readonly SOURCE_TRANSFER_TIMEOUT=300
readonly EVIDENCE_TRANSFER_TIMEOUT=300
readonly RECORDED_STDOUT_MAX_BYTES=$((16 * 1024 * 1024))
readonly RECORDED_STDERR_MAX_BYTES=$((16 * 1024 * 1024))
readonly MAX_SOURCE_ARCHIVE_BYTES=$((64 * 1024 * 1024))
readonly MAX_EVIDENCE_BYTES=$((256 * 1024 * 1024))
readonly MAX_EVIDENCE_ARCHIVE_BYTES=$((320 * 1024 * 1024))
readonly MAX_ARCHIVE_MEMBERS=20000
readonly CLONE_MARKER=/var/lib/shadowpipe-full-tun-lab-owner
readonly CLONE_QUIESCENCE_SAMPLES=60
readonly CLONE_QUIESCENCE_REQUIRED_STABLE=4
readonly EXPECTED_SINGBOX_CONFIG="${SHADOWPIPE_HOST_SINGBOX_CONFIG:-${HOME}/sing-box/config.json}"
readonly EXPECTED_SINGBOX_DIRECTORY="${SHADOWPIPE_HOST_SINGBOX_DIRECTORY:-${EXPECTED_SINGBOX_CONFIG%/*}}"

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
  local status="$1"
  shift
  printf 'error: %s\n' "$*" >&2
  exit "${status}"
}

usage() {
  cat <<'EOF'
Usage (macOS host):
  ZATMENIE_DISPOSABLE_LAB=1 tests/tun/run-orbstack-full-tun.sh [SOURCE_VM]

Static safety self-test (no VM/network):
  tests/tun/run-orbstack-full-tun.sh --self-test

SOURCE_VM defaults to "shadowpipe-lab-base" and must already be stopped. Its
OrbStack config, and the config inherited by every clone, must prove:
isolated=true, isolate_network=true, forward_ssh_agent=false, no mounts, and
zero HTTP/HTTPS forwarding ports. The script always clones SOURCE_VM to a new
disposable VM and never runs the lab in SOURCE_VM itself.

The repository must be clean `main`, with HEAD equal to both origin/main and a
live `git ls-remote origin refs/heads/main` result. Only a `git archive` of that
pinned commit is streamed into the clone. No `orb -p`, `orb -w`, shared folder,
SSH-agent forwarding, or /mnt/mac path is used.

The --guest mode is private to the host orchestrator and refuses macOS.
EOF
}

sanitize_component() {
  case "$1" in
    ''|*[!a-zA-Z0-9._-]*|*..*|*/*) return 1 ;;
    *) printf '%s\n' "$1" ;;
  esac
}

validate_magic() {
  python3 -I -S - "$1" <<'PY'
import re
import sys
text = sys.argv[1]
if re.fullmatch(r"(?:0x[0-9a-fA-F]{1,8}|[0-9]{1,10})", text) is None:
    raise SystemExit("SHADOWPIPE_MAGIC must be one unsigned u32 literal")
value = int(text, 16 if text.startswith("0x") else 10)
if not 0 <= value <= 0xffffffff:
    raise SystemExit("SHADOWPIPE_MAGIC exceeds u32")
PY
}

snapshot_macos() {
  local out="$1"
  mkdir -p -- "${out}" || return 1
  capture_required "${out}/default-route-ipv4.txt" route -n get default || return 1
  capture_required "${out}/default-route-ipv6.txt" \
    route -n get -inet6 default || return 1
  # Preserve the raw tables for audit, but compare the stable routing plane
  # separately. Link-layer neighbor-cache rows (`L` flag) and their expiry/
  # interface-scope churn are not route-policy mutations; starting a disposable
  # OrbStack clone can legitimately refresh those rows.
  capture_required "${out}/routes-ipv4.raw.txt" \
    netstat -rn -f inet || return 1
  capture_required "${out}/routes-ipv6.raw.txt" \
    netstat -rn -f inet6 || return 1
  # shellcheck disable=SC2016
  capture_required "${out}/routes-ipv4.txt" /bin/sh -c \
    'awk '\''NR <= 4 || $3 !~ /L/'\'' "$1" | sed -E '\''s/[[:space:]]+[0-9]+$//'\''' \
    snapshot-normalize "${out}/routes-ipv4.raw.txt" || return 1
  # shellcheck disable=SC2016
  capture_required "${out}/routes-ipv6.txt" /bin/sh -c \
    'awk '\''NR <= 4 || $3 !~ /L/'\'' "$1" | sed -E '\''s/[[:space:]]+[0-9]+$//'\''' \
    snapshot-normalize "${out}/routes-ipv6.raw.txt" || return 1
  capture_required "${out}/dns.txt" scutil --dns || return 1
  # `ifconfig -l` is a read-only interface census. Keep a dedicated utun list
  # so an otherwise route-neutral host tunnel replacement cannot pass silently.
  # shellcheck disable=SC2016
  capture_required "${out}/utun-interfaces.txt" /bin/sh -c \
    'ifconfig -l | tr " " "\n" | awk '\''/^utun[0-9]+$/'\'' | LC_ALL=C sort' \
    snapshot-utun || return 1
  capture_required "${out}/pf-conf.sha256" \
    sha256sum /etc/pf.conf || return 1
  # shellcheck disable=SC2016
  capture_required "${out}/pf-anchors.sha256" /bin/sh -c \
    'find "$1" -type f -exec sha256sum {} + | LC_ALL=C sort' \
    snapshot-pf /etc/pf.anchors || return 1
  capture_pf_runtime "${out}/pf-runtime" || return 1
  capture_required "${out}/sing-box.pids.raw" pgrep -x sing-box || return 1
  capture_required "${out}/sing-box.pids.candidates" \
    sort -n "${out}/sing-box.pids.raw" || return 1
  capture_singbox_candidate_commands \
    "${out}/sing-box.pids.candidates" \
    "${out}/sing-box.candidate-commands.tsv" || return 1
  select_managed_singbox_candidates \
    "${out}/sing-box.candidate-commands.tsv" "${out}/sing-box.pids" \
    || return 1
  if [[ "$(wc -l <"${out}/sing-box.pids" | tr -d ' ')" != "1" ]]; then
    return 1
  fi
  local pid final_pid binary final_binary
  pid="$(<"${out}/sing-box.pids")"
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
  capture_required "${out}/sing-box.identity" \
    ps -ww -p "${pid}" -o pid= -o lstart= -o command= || return 1
  capture_required "${out}/sing-box.command" \
    ps -ww -p "${pid}" -o command= || return 1
  validate_singbox_command "${out}/sing-box.command" || return 1
  [[ -f "${EXPECTED_SINGBOX_CONFIG}" \
    && ! -L "${EXPECTED_SINGBOX_CONFIG}" ]] || return 1
  capture_required "${out}/sing-box-config.stat" \
    stat -f '%HT %Su %Sg %Sp %l %z %m %N' \
    "${EXPECTED_SINGBOX_CONFIG}" || return 1
  capture_required "${out}/sing-box-config.sha256" \
    sha256sum "${EXPECTED_SINGBOX_CONFIG}" || return 1
  capture_singbox_binary "${pid}" "${out}/sing-box-binary.path" || return 1
  binary="$(<"${out}/sing-box-binary.path")"
  capture_required "${out}/sing-box-binary.stat" \
    stat -f '%HT %Su %Sg %Sp %l %z %m %N' "${binary}" || return 1
  capture_required "${out}/sing-box-binary.sha256" \
    sha256sum "${binary}" || return 1

  # Bind all hashes to one stable live process generation. A restart in the
  # middle of collection is a failed baseline, not a mixed-generation proof.
  capture_required "${out}/sing-box.pids-final.raw" pgrep -x sing-box || return 1
  capture_required "${out}/sing-box.pids-final.candidates" \
    sort -n "${out}/sing-box.pids-final.raw" || return 1
  capture_singbox_candidate_commands \
    "${out}/sing-box.pids-final.candidates" \
    "${out}/sing-box.candidate-commands-final.tsv" || return 1
  select_managed_singbox_candidates \
    "${out}/sing-box.candidate-commands-final.tsv" \
    "${out}/sing-box.pids-final" || return 1
  final_pid="$(<"${out}/sing-box.pids-final")"
  [[ "${final_pid}" =~ ^[0-9]+$ ]] || return 1
  capture_required "${out}/sing-box.identity-final" \
    ps -ww -p "${final_pid}" -o pid= -o lstart= -o command= || return 1
  capture_required "${out}/sing-box.command-final" \
    ps -ww -p "${final_pid}" -o command= || return 1
  validate_singbox_command "${out}/sing-box.command-final" || return 1
  capture_singbox_binary \
    "${final_pid}" "${out}/sing-box-binary-final.path" || return 1
  final_binary="$(<"${out}/sing-box-binary-final.path")"
  capture_required "${out}/sing-box-config-final.stat" \
    stat -f '%HT %Su %Sg %Sp %l %z %m %N' \
    "${EXPECTED_SINGBOX_CONFIG}" || return 1
  capture_required "${out}/sing-box-binary-final.stat" \
    stat -f '%HT %Su %Sg %Sp %l %z %m %N' "${final_binary}" || return 1
  validate_singbox_reproof "${out}" || return 1
  local left right
  for left in sing-box-config.stat sing-box-binary.stat; do
    case "${left}" in
      sing-box-config.stat) right=sing-box-config-final.stat ;;
      sing-box-binary.stat) right=sing-box-binary-final.stat ;;
    esac
    run_bounded "${HOST_COMMAND_TIMEOUT}" \
      cmp -s -- "${out}/${left}" "${out}/${right}" || return 1
  done
  printf 'sing_box_snapshot_consistent=true\n' \
    >"${out}/sing-box-snapshot-consistency.env" || return 1

  local manifest
  manifest="$(mktemp "${out}.collector-manifest.XXXXXX")" || return 1
  # shellcheck disable=SC2016
  run_bounded "${HOST_COMMAND_TIMEOUT}" /bin/sh -c \
    'cd "$1" && find . -type f ! -name collector-manifest.txt ! -name stable-manifest.txt -print | LC_ALL=C sort' \
    snapshot-manifest "${out}" >"${manifest}" || return 1
  mv -- "${manifest}" "${out}/collector-manifest.txt" || return 1
  manifest="$(mktemp "${out}.stable-manifest.XXXXXX")" || return 1
  # shellcheck disable=SC2016
  run_bounded "${HOST_COMMAND_TIMEOUT}" /bin/sh -c \
    'cd "$1" && find . -type f ! -name routes-ipv4.raw.txt ! -name routes-ipv6.raw.txt ! -name collector-manifest.txt ! -name stable-manifest.txt -print | LC_ALL=C sort' \
    snapshot-manifest "${out}" >"${manifest}" || return 1
  mv -- "${manifest}" "${out}/stable-manifest.txt" || return 1
}

compare_macos_snapshots() {
  local before="$1" after="$2"
  local name status=0
  run_bounded "${HOST_COMMAND_TIMEOUT}" cmp -s -- \
    "${before}/collector-manifest.txt" "${after}/collector-manifest.txt" \
    || { warn 'macOS collector manifests differ'; return 1; }
  run_bounded "${HOST_COMMAND_TIMEOUT}" cmp -s -- \
    "${before}/stable-manifest.txt" "${after}/stable-manifest.txt" \
    || { warn 'macOS stable collector manifests differ'; return 1; }
  while IFS= read -r name; do
    name="${name#./}"
    if ! run_bounded "${HOST_COMMAND_TIMEOUT}" cmp -s -- \
      "${before}/${name}" "${after}/${name}"; then
      warn "macOS safety snapshot changed: ${name}"
      status=1
    fi
  done <"${before}/stable-manifest.txt"
  return "${status}"
}

seal_evidence() {
  local root="$1"
  python3 -I -S - "${root}" <<'PY'
import hashlib
import os
import stat
import sys

requested = os.path.abspath(sys.argv[1])
requested_info = os.lstat(requested)
if not stat.S_ISDIR(requested_info.st_mode) or stat.S_ISLNK(requested_info.st_mode):
    raise SystemExit("evidence root is not a real directory")
root = os.path.realpath(requested)
if root != requested:
    raise SystemExit("evidence root is not canonical")

def census_and_hash():
    records = {}
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        files.sort()
        for name in directories:
            path = os.path.join(current, name)
            info = os.lstat(path)
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise SystemExit(
                    f"non-directory evidence subtree: {os.path.relpath(path, root)}"
                )
        for name in files:
            path = os.path.join(current, name)
            relative = os.path.relpath(path, root)
            if relative == "checksums.sha256":
                continue
            if any(character in relative for character in ("\n", "\r", "\0")):
                raise SystemExit("unsafe evidence filename")
            before = os.lstat(path)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise SystemExit(f"non-regular or multiply-linked evidence: {relative}")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                ):
                    raise SystemExit(f"evidence identity raced while opening: {relative}")
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                after = os.fstat(descriptor)
                if (
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                    or after.st_nlink != 1
                ):
                    raise SystemExit(f"evidence changed while hashing: {relative}")
            finally:
                os.close(descriptor)
            records[relative] = digest.hexdigest()
    return records

first = census_and_hash()
temporary = os.path.join(root, ".checksums.sha256.tmp")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
try:
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
            descriptor = -1
            for relative in sorted(first):
                stream.write(f"{first[relative]}  {relative}\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    os.replace(temporary, os.path.join(root, "checksums.sha256"))
finally:
    if os.path.lexists(temporary):
        os.unlink(temporary)
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)

second = census_and_hash()
if second != first:
    raise SystemExit("evidence file census or digest changed during sealing")
manifest = os.path.join(root, "checksums.sha256")
manifest_info = os.lstat(manifest)
if not stat.S_ISREG(manifest_info.st_mode) or manifest_info.st_nlink != 1:
    raise SystemExit("checksum manifest is not a single-link regular file")
with open(manifest, "r", encoding="ascii", newline="") as stream:
    observed = stream.read()
expected = "".join(f"{first[path]}  {path}\n" for path in sorted(first))
if observed != expected:
    raise SystemExit("checksum manifest content differs from the verified census")
PY
}

# Run one host command in its own process group. Signals and hard deadlines
# terminate the complete recorded group, so no OrbStack/Cargo helper owned by
# this invocation can silently outlive its step.
run_bounded() {
  local seconds="$1"
  shift
  python3 -I -S - "${seconds}" "$@" <<'PY'
import os
import signal
import subprocess
import sys
import time

timeout = float(sys.argv[1])
if not (0.0 < timeout <= 3600.0) or len(sys.argv) < 3:
    raise SystemExit("invalid bounded-command invocation")
process = subprocess.Popen(
    sys.argv[2:], stdin=subprocess.DEVNULL, start_new_session=True
)

def group_exists():
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True

def stop_and_reap_group():
    if group_exists():
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 2.0
    while group_exists() and time.monotonic() < deadline:
        if process.poll() is None:
            try:
                process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                pass
        else:
            time.sleep(0.05)
    if group_exists():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                return False
    deadline = time.monotonic() + 2.0
    while group_exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    return not group_exists()

def terminate_group(signum, _frame):
    clean = stop_and_reap_group()
    raise SystemExit(128 + signum if clean else 125)

for caught in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(caught, terminate_group)
try:
    status = process.wait(timeout=timeout)
except subprocess.TimeoutExpired:
    print(f"hard timeout after {timeout:g}s", file=sys.stderr)
    clean = stop_and_reap_group()
    raise SystemExit(124 if clean else 125)
if group_exists():
    print("bounded command left live process-group descendants", file=sys.stderr)
    stop_and_reap_group()
    raise SystemExit(125)
raise SystemExit(status if status >= 0 else 128 - status)
PY
}

run_recorded_limited() {
  local seconds="$1" output="$2" stdout_limit="$3" stderr_limit="$4"
  shift 4
  [[ "${stdout_limit}" =~ ^[1-9][0-9]*$ \
    && "${stderr_limit}" =~ ^[1-9][0-9]*$ ]] || return 1
  local pipe_dir status stdout_size stderr_size recorder_stderr
  pipe_dir="$(mktemp -d "${output}.pipes.XXXXXX")" || return 1
  recorder_stderr="${pipe_dir}/recorder.stderr"
  # Positional parameters intentionally expand in the bounded recorder shell.
  # shellcheck disable=SC2016
  if run_bounded "${seconds}" /bin/bash -c '
      set -Eeuo pipefail
      stdout_fifo="$1"
      stderr_fifo="$2"
      stdout_path="$3"
      stderr_path="$4"
      stdout_limit="$5"
      stderr_limit="$6"
      shift 6
      mkfifo -m 0600 "${stdout_fifo}" "${stderr_fifo}"
      head -c "$((stdout_limit + 1))" <"${stdout_fifo}" >"${stdout_path}" &
      stdout_reader=$!
      head -c "$((stderr_limit + 1))" <"${stderr_fifo}" >"${stderr_path}" &
      stderr_reader=$!
      set +e
      "$@" >"${stdout_fifo}" 2>"${stderr_fifo}"
      command_status=$?
      wait "${stdout_reader}"
      stdout_status=$?
      wait "${stderr_reader}"
      stderr_status=$?
      set -e
      (( stdout_status == 0 && stderr_status == 0 )) || exit 125
      exit "${command_status}"
    ' recorded-command \
    "${pipe_dir}/stdout.fifo" "${pipe_dir}/stderr.fifo" \
    "${output}" "${output}.stderr" "${stdout_limit}" "${stderr_limit}" \
    "$@" >/dev/null 2>"${recorder_stderr}"; then
    status=0
  else
    status=$?
  fi
  [[ -f "${output}" && ! -L "${output}" \
    && -f "${output}.stderr" && ! -L "${output}.stderr" ]] || status=125
  stdout_size="$(stat -f '%z' "${output}" 2>/dev/null || printf '%s' 0)"
  stderr_size="$(stat -f '%z' "${output}.stderr" 2>/dev/null || printf '%s' 0)"
  [[ "${stdout_size}" =~ ^[0-9]+$ && "${stderr_size}" =~ ^[0-9]+$ ]] \
    || status=125
  if (( stdout_size > stdout_limit || stderr_size > stderr_limit )); then
    status=125
  fi
  if [[ -s "${recorder_stderr}" ]] && (( stderr_size < stderr_limit )); then
    local remaining wrapper_prefix wrapper_prefix_size wrapper_bytes
    wrapper_prefix=$'\n[recording wrapper]\n'
    remaining=$((stderr_limit - stderr_size))
    wrapper_prefix_size="${#wrapper_prefix}"
    if (( remaining <= wrapper_prefix_size )); then
      printf '%s' "${wrapper_prefix:0:remaining}" >>"${output}.stderr"
    else
      printf '%s' "${wrapper_prefix}" >>"${output}.stderr"
      wrapper_bytes=$((remaining - wrapper_prefix_size))
      head -c "$((wrapper_bytes > 4096 ? 4096 : wrapper_bytes))" \
        "${recorder_stderr}" >>"${output}.stderr"
    fi
  fi
  rm -r -- "${pipe_dir}" || status=125
  printf '%s\n' "${status}" >"${output}.status" || return 1
  return "${status}"
}

run_recorded() {
  local seconds="$1" output="$2"
  shift 2
  run_recorded_limited "${seconds}" "${output}" \
    "${RECORDED_STDOUT_MAX_BYTES}" "${RECORDED_STDERR_MAX_BYTES}" "$@"
}

capture_required() {
  local output="$1"
  shift
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${output}" "$@"
}

vm_count_in_listing() {
  local listing="$1" vm="$2"
  awk -v vm="${vm}" '$1 == vm { count += 1 } END { print count + 0 }' \
    "${listing}"
}

vm_state_in_listing() {
  local listing="$1" vm="$2"
  awk -v vm="${vm}" \
    '$1 == vm { count += 1; state = $2 } END { if (count != 1) exit 1; print state }' \
    "${listing}"
}

orb_info_field() {
  local info_file="$1" expected_name="$2" expected_id="$3"
  local expected_state="$4" field="$5"
  [[ -f "${info_file}" && ! -L "${info_file}" ]] || return 1
  python3 -I -S - "${info_file}" "${expected_name}" "${expected_id}" \
    "${expected_state}" "${field}" <<'PY'
import json
import os
import re
import stat
import sys

path, expected_name, expected_id, expected_state, field = sys.argv[1:]

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result

info = os.lstat(path)
if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
    raise SystemExit("OrbStack info is not a single-link regular file")
if info.st_size <= 0 or info.st_size > 1024 * 1024:
    raise SystemExit("OrbStack info JSON size is invalid")
with open(path, "r", encoding="utf-8") as stream:
    root = json.load(
        stream,
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON constant: {value}")
        ),
    )
if not isinstance(root, dict) or not isinstance(root.get("record"), dict):
    raise SystemExit("OrbStack info lacks an object record")
record = root["record"]
machine_id = record.get("id")
name = record.get("name")
state = record.get("state")
for label, value in (("id", machine_id), ("name", name), ("state", state)):
    if not isinstance(value, str) or not value or len(value) > 512:
        raise SystemExit(f"OrbStack {label} is absent or unsafe")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise SystemExit(f"OrbStack {label} contains a control character")
if any(ord(character) < 0x21 or ord(character) == 0x7F for character in machine_id):
    raise SystemExit("OrbStack ID contains a control or space byte")
if expected_name and name != expected_name:
    raise SystemExit("OrbStack machine name differs from the bound name")
if expected_id and machine_id != expected_id:
    raise SystemExit("OrbStack machine ID differs from the bound ID")
if expected_state and state != expected_state:
    raise SystemExit("OrbStack machine state differs from the expected state")
config = record.get("config")
if type(config) is not dict:
    raise SystemExit("OrbStack record lacks an exact config object")
if config.get("isolated") is not True:
    raise SystemExit("OrbStack machine is not capability-isolated")
if config.get("isolate_network") is not True:
    raise SystemExit("OrbStack machine network isolation is not enabled")
if config.get("forward_ssh_agent") is not False:
    raise SystemExit("OrbStack SSH-agent forwarding is not disabled")
for port_name in ("http_port", "https_port"):
    port = config.get(port_name)
    if type(port) is not int or port != 0:
        raise SystemExit(f"OrbStack {port_name} is not exactly zero")
for container, label in ((record, "record"), (config, "config")):
    for key in ("mount", "mounts", "ports", "port_forwards"):
        if key not in container:
            continue
        value = container[key]
        if not (
            (type(value) is list and not value)
            or (type(value) is dict and not value)
        ):
            raise SystemExit(f"OrbStack {label}.{key} is not empty")
default_username = config.get("default_username")
if (
    type(default_username) is not str
    or re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", default_username) is None
):
    raise SystemExit("OrbStack default_username is absent or unsafe")
values = {
    "id": machine_id,
    "name": name,
    "state": state,
    "default_username": default_username,
}
if field not in values:
    raise SystemExit("unknown OrbStack info field")
print(values[field])
PY
}

capture_bound_orb_info() {
  local reference="$1" expected_name="$2" expected_id="$3"
  local expected_state="$4" output="$5"
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${output}" \
    orbctl info "${reference}" --format json || return 1
  orb_info_field "${output}" "${expected_name}" "${expected_id}" \
    "${expected_state}" id >/dev/null
}

validate_orb_info_absence() {
  local output="$1" reference="$2" status
  [[ -f "${output}" && ! -L "${output}" \
    && -f "${output}.status" && ! -L "${output}.status" \
    && -f "${output}.stderr" && ! -L "${output}.stderr" ]] || return 1
  status="$(<"${output}.status")"
  [[ "${status}" == 1 && ! -s "${output}" ]] || return 1
  [[ "$(<"${output}.stderr")" == "[-32098] machine not found: '${reference}'" ]]
}

validate_clone_quiescence_trace() {
  local trace="$1" required="$2" mode="$3"
  [[ "${required}" =~ ^[1-9][0-9]*$ \
    && ( "${mode}" == stable_any || "${mode}" == absent_all ) ]] || return 1
  awk -F '\t' -v required="${required}" -v mode="${mode}" '
    NF != 3 || $1 != NR || $2 !~ /^[a-zA-Z0-9._-]+$/ || $3 != "stopped" {
      bad = 1
      next
    }
    {
      if (NR == 1 || $2 != previous) consecutive = 1
      else consecutive += 1
      previous = $2
      if (mode == "absent_all" && $2 != "absent") bad = 1
    }
    END {
      if (NR < required || consecutive < required) bad = 1
      exit bad
    }
  ' "${trace}"
}

observe_clone_quiescence() {
  local vm="$1" source_vm="$2" evidence_dir="$3" mode="$4"
  local trace state source_state sample listing count
  mkdir -p -- "${evidence_dir}" || return 1
  trace="${evidence_dir}/trace.tsv"
  : >"${trace}" || return 1
  for ((sample = 1; sample <= CLONE_QUIESCENCE_SAMPLES; sample++)); do
    listing="${evidence_dir}/orb-list-${sample}.txt"
    run_recorded "${HOST_COMMAND_TIMEOUT}" "${listing}" orbctl list || return 1
    source_state="$(vm_state_in_listing "${listing}" "${source_vm}")" || return 1
    [[ "${source_state}" == stopped ]] || return 1
    count="$(vm_count_in_listing "${listing}" "${vm}")" || return 1
    if [[ "${count}" == 0 ]]; then
      state=absent
    elif [[ "${count}" == 1 ]]; then
      state="$(vm_state_in_listing "${listing}" "${vm}")" || return 1
    else
      return 1
    fi
    printf '%s\t%s\t%s\n' "${sample}" "${state}" "${source_state}" \
      >>"${trace}" || return 1
    if (( sample < CLONE_QUIESCENCE_SAMPLES )); then
      run_bounded 3 sleep 1 >/dev/null 2>&1 || return 1
    fi
  done
  validate_clone_quiescence_trace \
    "${trace}" "${CLONE_QUIESCENCE_REQUIRED_STABLE}" "${mode}" || return 1
  printf '%s\n' "${state}"
}

create_source_provenance_manifest() {
  local repo_root="$1" output="$2" runner="$3"
  python3 -I -S - "${repo_root}" "${output}" "${runner}" <<'PY'
import hashlib
import os
import stat
import sys

root = os.path.realpath(sys.argv[1])
output = sys.argv[2]
runner = sys.argv[3]
fixed = [".cargo/config.toml", "Cargo.lock", "Cargo.toml", runner]
paths = []
crates = os.path.join(root, "crates")
for current, directories, files in os.walk(crates, followlinks=False):
    directories.sort()
    files.sort()
    for name in files:
        if name.endswith((".rs", ".toml")):
            paths.append(os.path.relpath(os.path.join(current, name), root))
paths.extend(fixed)
paths = sorted(set(paths))
if not paths:
    raise SystemExit("empty source provenance set")
with open(output, "x", encoding="ascii", newline="\n") as destination:
    for relative in paths:
        path = os.path.join(root, relative)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit(
                f"provenance input is not a single-link regular file: {relative}"
            )
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        destination.write(f"{digest.hexdigest()}  {relative}\n")
PY
}

verify_source_provenance_manifest() {
  local repo_root="$1" expected="$2" observed="$3" runner="$4"
  create_source_provenance_manifest \
    "${repo_root}" "${observed}" "${runner}" || return 1
  cmp -s -- "${expected}" "${observed}"
}

capture_git_checkout_proof() {
  local repo_root="$1" output="$2" expected_head="${3:-}"
  mkdir -m 0700 -- "${output}" || return 1
  # Prove cleanliness without ever materializing a dirty path in evidence.
  # shellcheck disable=SC2016
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${output}/status.clean" \
    /bin/bash -c '
      set -o pipefail
      repo=$1
      git -C "${repo}" diff --quiet --no-ext-diff -- || exit 3
      git -C "${repo}" diff --cached --quiet --no-ext-diff -- || exit 3
      untracked_bytes="$(
        git -C "${repo}" ls-files --others --exclude-standard 2>/dev/null \
          | wc -c
      )" || exit 2
      untracked_bytes="${untracked_bytes//[[:space:]]/}"
      [[ "${untracked_bytes}" =~ ^[0-9]+$ ]] || exit 2
      (( untracked_bytes == 0 )) || exit 3
      printf "clean\n"
    ' quiet-git-status "${repo_root}" \
    || return 1
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${output}/inside-work-tree.txt" \
    git -C "${repo_root}" rev-parse --is-inside-work-tree || return 1
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${output}/top-level.txt" \
    git -C "${repo_root}" rev-parse --show-toplevel || return 1
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${output}/branch.txt" \
    git -C "${repo_root}" symbolic-ref --quiet --short HEAD || return 1
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${output}/head.txt" \
    git -C "${repo_root}" rev-parse --verify 'HEAD^{commit}' || return 1
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${output}/origin-main.txt" \
    git -C "${repo_root}" rev-parse --verify \
    'refs/remotes/origin/main^{commit}' || return 1
  # A remote failure can echo a credential-bearing HTTPS URL. Publish only the
  # safe hash/ref stdout and numeric status, never raw remote stderr.
  # shellcheck disable=SC2016
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${output}/origin-main-live.txt" \
    /bin/sh -c \
    'GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="ssh -oBatchMode=yes -oConnectionAttempts=1" git -C "$1" ls-remote --refs origin refs/heads/main 2>/dev/null' \
    live-origin-main "${repo_root}" \
    || return 1
  python3 -I -S - "${repo_root}" "${output}" "${expected_head}" <<'PY'
import os
import re
import stat
import sys

repo, root, expected = sys.argv[1:]

def one_line(name, allow_tab=False):
    path = os.path.join(root, name)
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(f"unsafe Git proof file: {name}")
    with open(path, "r", encoding="utf-8", newline="") as stream:
        lines = stream.read().splitlines()
    if len(lines) != 1 or not lines[0]:
        raise SystemExit(f"Git proof is not one nonempty line: {name}")
    if any(
        (ord(character) < 0x20 and not (allow_tab and character == "\t"))
        or ord(character) == 0x7f
        for character in lines[0]
    ):
        raise SystemExit(f"Git proof contains a control byte: {name}")
    return lines[0]

if one_line("status.clean") != "clean":
    raise SystemExit("repository working tree or index is not clean")
if one_line("inside-work-tree.txt") != "true":
    raise SystemExit("repository is not a Git work tree")
if os.path.realpath(one_line("top-level.txt")) != os.path.realpath(repo):
    raise SystemExit("Git top-level differs from the bound repository")
if one_line("branch.txt") != "main":
    raise SystemExit("repository HEAD is not attached to main")
head = one_line("head.txt")
origin = one_line("origin-main.txt")
if re.fullmatch(r"[0-9a-f]{40,64}", head) is None:
    raise SystemExit("Git HEAD is not one canonical object ID")
if origin != head:
    raise SystemExit("Git HEAD differs from local origin/main")
if expected and head != expected:
    raise SystemExit("Git HEAD changed during the lab")
live = one_line("origin-main-live.txt", allow_tab=True).split("\t")
if live != [head, "refs/heads/main"]:
    raise SystemExit("Git HEAD differs from live pushed origin/main")
with open(os.path.join(root, "checkout.env"), "x", encoding="ascii", newline="\n") as stream:
    stream.write("git_checkout=clean_pushed_main\n")
    stream.write(f"pinned_head={head}\n")
    stream.write("live_origin_main_match=true\n")
    stream.write("archive_source=git_object_database\n")
PY
}

create_pinned_source_archive() {
  local repo_root="$1" pinned_head="$2" archive="$3" metadata="$4"
  run_recorded_limited "${HOST_COMMAND_TIMEOUT}" "${archive}" \
    "${MAX_SOURCE_ARCHIVE_BYTES}" "${RECORDED_STDERR_MAX_BYTES}" \
    git -C "${repo_root}" archive --format=tar --prefix=shadowpipe/ \
    "${pinned_head}" || return 1
  # shellcheck disable=SC2016
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${metadata}.commit" /bin/sh -c \
    'git -C "$1" get-tar-commit-id <"$2"' \
    source-archive "${repo_root}" "${archive}" || return 1
  python3 -I -S - "${archive}" "${metadata}.commit" "${metadata}" \
    "${pinned_head}" "${MAX_SOURCE_ARCHIVE_BYTES}" <<'PY'
import hashlib
import os
import re
import stat
import sys

archive, commit_path, output, expected, maximum_text = sys.argv[1:]
maximum = int(maximum_text, 10)
info = os.lstat(archive)
if (
    not stat.S_ISREG(info.st_mode)
    or stat.S_ISLNK(info.st_mode)
    or info.st_nlink != 1
    or stat.S_IMODE(info.st_mode) != 0o600
    or info.st_size <= 0
    or info.st_size > maximum
):
    raise SystemExit("pinned source archive metadata or size is unsafe")
with open(commit_path, "r", encoding="ascii", newline="") as stream:
    lines = stream.read().splitlines()
if lines != [expected] or re.fullmatch(r"[0-9a-f]{40,64}", expected) is None:
    raise SystemExit("git archive commit identity differs from pinned HEAD")
digest = hashlib.sha256()
with open(archive, "rb", buffering=0) as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
with open(output, "x", encoding="ascii", newline="\n") as stream:
    stream.write("source_archive=git_archive\n")
    stream.write(f"pinned_head={expected}\n")
    stream.write(f"source_archive_bytes={info.st_size}\n")
    stream.write(f"source_archive_sha256={digest.hexdigest()}\n")
PY
}

source_archive_field() {
  local metadata="$1" field="$2"
  awk -F= -v field="${field}" \
    '$1 == field { count += 1; value = substr($0, index($0, "=") + 1) }
     END { if (count != 1 || value == "") exit 1; print value }' \
    "${metadata}"
}

run_recorded_with_stdin() {
  local seconds="$1" output="$2" input="$3"
  shift 3
  # shellcheck disable=SC2016
  run_recorded "${seconds}" "${output}" /bin/sh -c \
    'input=$1; shift; exec "$@" <"$input"' \
    shadowpipe-bounded-stream "${input}" "$@"
}

stream_source_archive_to_guest() {
  local clone_id="$1" archive="$2" guest_root="$3" guest_archive="$4"
  local expected_size="$5" expected_hash="$6" output="$7"
  run_recorded_with_stdin "${SOURCE_TRANSFER_TIMEOUT}" "${output}" "${archive}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import hashlib
import os
import stat
import sys

root, destination, size_text, expected = sys.argv[1:]
size = int(size_text, 10)
if size <= 0 or size > 64 * 1024 * 1024:
    raise SystemExit("invalid bounded source archive size")
if os.path.dirname(destination) != root or os.path.basename(destination) != "source.tar":
    raise SystemExit("unsafe guest source archive path")
if os.path.lexists(root):
    raise SystemExit("guest source root already exists")
os.mkdir(root, 0o700)
flags = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
descriptor = os.open(destination, flags, 0o600)
digest = hashlib.sha256()
observed = 0
try:
    while observed <= size:
        chunk = sys.stdin.buffer.read(min(1024 * 1024, size + 1 - observed))
        if not chunk:
            break
        observed += len(chunk)
        if observed > size:
            raise SystemExit("source archive stream exceeded its declared size")
        digest.update(chunk)
        offset = 0
        while offset < len(chunk):
            offset += os.write(descriptor, chunk[offset:])
    os.fsync(descriptor)
finally:
    os.close(descriptor)
if observed != size or digest.hexdigest() != expected:
    raise SystemExit("source archive stream size or digest mismatch")
info = os.lstat(destination)
if (
    not stat.S_ISREG(info.st_mode)
    or info.st_nlink != 1
    or stat.S_IMODE(info.st_mode) != 0o600
    or info.st_uid != 0
    or info.st_gid != 0
    or info.st_size != size
):
    raise SystemExit("guest source archive metadata differs")
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
print(f"source_archive_bytes={size}")
print(f"source_archive_sha256={expected}")
' "${guest_root}" "${guest_archive}" "${expected_size}" "${expected_hash}"
}

capture_guest_isolation_preflight() {
  local clone_id="$1" guest_user="$2" output="$3"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${output}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import os
import pwd
import shutil
import subprocess
import sys

username = sys.argv[1]
pwd.getpwnam(username)
if os.path.lexists("/mnt/mac"):
    raise SystemExit("isolated guest unexpectedly exposes /mnt/mac")
if os.environ.get("SSH_AUTH_SOCK"):
    raise SystemExit("isolated guest unexpectedly received SSH_AUTH_SOCK")
mac_command = shutil.which("mac")
known_mac_commands = (
    "/usr/bin/mac",
    "/usr/local/bin/mac",
    "/opt/orbstack/bin/mac",
    "/opt/orbstack-guest/bin/mac",
)
candidates = []
if mac_command:
    candidates.append(mac_command)
for path in known_mac_commands:
    if os.path.lexists(path) and path not in candidates:
        candidates.append(path)
if candidates:
    # Preserve each original argv[0]. The OrbStack multi-call binary changes
    # behavior when invoked through its mac symlink versus the resolved
    # macctl path, so realpath-based execution is not an equivalent probe.
    for candidate in candidates:
        probe = subprocess.run(
            [candidate, "uname", "-s"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        if (
            probe.returncode != 1
            or probe.stdout != b""
            or probe.stderr != b"dial: no such file or directory\n"
        ):
            raise SystemExit("OrbStack mac-command channel is not proved fail-closed")
    mac_channel = "disabled"
else:
    mac_channel = "absent"
with open("/proc/self/mountinfo", "r", encoding="utf-8") as stream:
    for raw in stream:
        fields = raw.split()
        if len(fields) < 5:
            raise SystemExit("malformed guest mountinfo")
        mountpoint = fields[4].replace("\\040", " ")
        if mountpoint == "/mnt/mac" or mountpoint.startswith("/mnt/mac/"):
            raise SystemExit("isolated guest mountinfo exposes a Mac share")
print("guest_runtime_isolation=valid")
print("mnt_mac=absent")
print("ssh_auth_sock=absent")
print(f"mac_command_channel={mac_channel}")
print(f"default_username={username}")
' "${guest_user}"
}

extract_guest_source_archive() {
  local clone_id="$1" guest_root="$2" guest_archive="$3"
  local guest_repo="$4" guest_result="$5" run_id="$6" clone_vm="$7"
  local token="$8" expected_size="$9" expected_hash="${10}" output="${11}"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${output}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import hashlib
import os
import stat
import sys
import tarfile

(root, archive, repo, result, run_id, clone_vm, token,
 size_text, expected_hash) = sys.argv[1:]
size = int(size_text, 10)
if repo != os.path.join(root, "shadowpipe"):
    raise SystemExit("unsafe guest repository path")
expected_result = os.path.join(repo, "tests", "tun", "results", run_id)
if result != expected_result:
    raise SystemExit("unsafe guest result path")
archive_info = os.lstat(archive)
if (
    not stat.S_ISREG(archive_info.st_mode)
    or archive_info.st_nlink != 1
    or stat.S_IMODE(archive_info.st_mode) != 0o600
    or archive_info.st_uid != 0
    or archive_info.st_gid != 0
    or archive_info.st_size != size
):
    raise SystemExit("guest source archive identity changed before extraction")
digest = hashlib.sha256()
with open(archive, "rb", buffering=0) as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest() != expected_hash:
    raise SystemExit("guest source archive digest changed before extraction")
seen = set()
members = 0
total = 0
with tarfile.open(archive, "r:") as source:
    for member in source:
        members += 1
        if members > 20000:
            raise SystemExit("source archive member count exceeded")
        name = member.name.rstrip("/")
        parts = name.split("/")
        if (
            not name
            or name.startswith("/")
            or any(part in ("", ".", "..") for part in parts)
            or parts[0] != "shadowpipe"
            or any(ord(character) < 0x20 or ord(character) == 0x7f for character in name)
            or name in seen
        ):
            raise SystemExit("source archive contains an unsafe or duplicate path")
        seen.add(name)
        destination = os.path.join(root, *parts)
        if os.path.commonpath((root, destination)) != root:
            raise SystemExit("source archive escaped the guest root")
        if member.isdir():
            if os.path.lexists(destination):
                if not stat.S_ISDIR(os.lstat(destination).st_mode):
                    raise SystemExit("source archive directory collided with a file")
            else:
                os.makedirs(destination, mode=0o700, exist_ok=False)
            os.chmod(destination, 0o700)
            continue
        if not member.isfile() or member.size < 0:
            raise SystemExit("source archive contains a link or special member")
        total += member.size
        if total > 64 * 1024 * 1024:
            raise SystemExit("source archive expanded bytes exceeded")
        parent = os.path.dirname(destination)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        if os.path.lexists(destination):
            raise SystemExit("source archive file path already exists")
        incoming = source.extractfile(member)
        if incoming is None:
            raise SystemExit("source archive regular member is unreadable")
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(destination, flags, 0o700 if member.mode & 0o111 else 0o600)
        written = 0
        try:
            while written < member.size:
                chunk = incoming.read(min(1024 * 1024, member.size - written))
                if not chunk:
                    raise SystemExit("source archive member ended early")
                offset = 0
                while offset < len(chunk):
                    offset += os.write(descriptor, chunk[offset:])
                written += len(chunk)
            if incoming.read(1):
                raise SystemExit("source archive member exceeded declared size")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
if not os.path.isfile(os.path.join(repo, "Cargo.lock")):
    raise SystemExit("extracted source lacks Cargo.lock")
runner = os.path.join(repo, "tests", "tun", "run-orbstack-full-tun.sh")
if not os.path.isfile(runner):
    raise SystemExit("extracted source lacks the full-TUN runner")
os.makedirs(os.path.dirname(result), mode=0o700, exist_ok=True)
os.mkdir(result, 0o700)
owner = os.path.join(result, ".shadowpipe-full-tun-owner")
content = (
    "shadowpipe-full-tun-result-owner-v1\n"
    f"run_id={run_id}\nclone_vm={clone_vm}\ntoken={token}\n"
).encode("ascii")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(owner, flags, 0o600)
try:
    os.write(descriptor, content)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
os.unlink(archive)
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
print(f"guest_repo_root={repo}")
print(f"source_archive_sha256={expected_hash}")
print(f"source_archive_members={members}")
print(f"source_archive_expanded_bytes={total}")
' "${guest_root}" "${guest_archive}" "${guest_repo}" "${guest_result}" \
    "${run_id}" "${clone_vm}" "${token}" "${expected_size}" "${expected_hash}"
}

stream_guest_evidence_archive() {
  local clone_id="$1" guest_result="$2" run_id="$3" clone_vm="$4"
  local token="$5" output="$6"
  run_recorded_limited "${EVIDENCE_TRANSFER_TIMEOUT}" "${output}" \
    "${MAX_EVIDENCE_ARCHIVE_BYTES}" "${RECORDED_STDERR_MAX_BYTES}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import hashlib
import os
import stat
import sys
import tarfile

root, run_id, clone_vm, token = sys.argv[1:]
root = os.path.abspath(root)
if os.path.realpath(root) != root:
    raise SystemExit("guest evidence root is not canonical")
info = os.lstat(root)
if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
    raise SystemExit("guest evidence root is unsafe")
owner_content = (
    "shadowpipe-full-tun-result-owner-v1\n"
    f"run_id={run_id}\nclone_vm={clone_vm}\ntoken={token}\n"
).encode("ascii")
owner_path = os.path.join(root, ".shadowpipe-full-tun-owner")
with open(owner_path, "rb", buffering=0) as stream:
    if stream.read() != owner_content:
        raise SystemExit("guest evidence owner differs")
manifest_path = os.path.join(root, "checksums.sha256")
with open(manifest_path, "r", encoding="ascii", newline="") as stream:
    manifest_lines = stream.read().splitlines()
manifest = {}
for line in manifest_lines:
    if len(line) < 67 or line[64:66] != "  ":
        raise SystemExit("guest checksum manifest is malformed")
    digest, relative = line[:64], line[66:]
    if (
        len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or not relative
        or relative.startswith("/")
        or any(part in ("", ".", "..") for part in relative.split("/"))
        or relative == "checksums.sha256"
        or relative in manifest
    ):
        raise SystemExit("guest checksum manifest contains an unsafe record")
    manifest[relative] = digest
if list(manifest) != sorted(manifest):
    raise SystemExit("guest checksum manifest is not sorted")
directories = set()
files = {}
total = 0
for current, dirnames, filenames in os.walk(root, followlinks=False):
    dirnames.sort()
    filenames.sort()
    relative_current = os.path.relpath(current, root)
    if relative_current != ".":
        directories.add(relative_current)
    for name in dirnames:
        path = os.path.join(current, name)
        child = os.lstat(path)
        if not stat.S_ISDIR(child.st_mode) or stat.S_ISLNK(child.st_mode):
            raise SystemExit("guest evidence contains a symlinked subtree")
    for name in filenames:
        path = os.path.join(current, name)
        relative = os.path.relpath(path, root)
        child = os.lstat(path)
        if not stat.S_ISREG(child.st_mode) or child.st_nlink != 1:
            raise SystemExit("guest evidence contains a link or special file")
        total += child.st_size
        if total > 256 * 1024 * 1024 or len(files) >= 20000:
            raise SystemExit("guest evidence exceeds the streaming bound")
        digest = hashlib.sha256()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (child.st_dev, child.st_ino):
                raise SystemExit("guest evidence identity raced while opening")
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            raise SystemExit("guest evidence changed while hashing")
        files[relative] = (path, child, digest.hexdigest())
census = set(files)
if "checksums.sha256" not in census:
    raise SystemExit("guest evidence checksum manifest is absent")
if census - {"checksums.sha256"} != set(manifest):
    raise SystemExit("guest evidence checksum census differs")
for relative, expected in manifest.items():
    if files[relative][2] != expected:
        raise SystemExit("guest evidence checksum mismatch")
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|", format=tarfile.PAX_FORMAT) as archive:
    for relative in sorted(directories):
        item = tarfile.TarInfo(relative)
        item.type = tarfile.DIRTYPE
        item.mode = 0o700
        item.uid = item.gid = 0
        item.mtime = 0
        item.uname = item.gname = ""
        archive.addfile(item)
    for relative in sorted(files):
        path, before, _digest = files[relative]
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        ):
            os.close(descriptor)
            raise SystemExit("guest evidence changed before streaming")
        item = tarfile.TarInfo(relative)
        item.size = opened.st_size
        item.mode = 0o600
        item.uid = item.gid = 0
        item.mtime = 0
        item.uname = item.gname = ""
        with os.fdopen(descriptor, "rb", buffering=0) as incoming:
            archive.addfile(item, incoming)
            after = os.fstat(incoming.fileno())
            if (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            ):
                raise SystemExit("guest evidence changed while streaming")
' "${guest_result}" "${run_id}" "${clone_vm}" "${token}"
}

extract_guest_evidence_archive() {
  local archive="$1" destination="$2" run_id="$3" clone_vm="$4" token="$5"
  python3 -I -S - "${archive}" "${destination}" "${run_id}" "${clone_vm}" \
    "${token}" "${MAX_EVIDENCE_BYTES}" "${MAX_EVIDENCE_ARCHIVE_BYTES}" \
    "${MAX_ARCHIVE_MEMBERS}" <<'PY'
import hashlib
import os
import stat
import sys
import tarfile

(archive_path, destination, run_id, clone_vm, token,
 max_bytes_text, max_archive_text, max_members_text) = sys.argv[1:]
max_bytes = int(max_bytes_text, 10)
max_archive = int(max_archive_text, 10)
max_members = int(max_members_text, 10)
archive_info = os.lstat(archive_path)
if (
    not stat.S_ISREG(archive_info.st_mode)
    or stat.S_ISLNK(archive_info.st_mode)
    or archive_info.st_nlink != 1
    or stat.S_IMODE(archive_info.st_mode) != 0o600
    or archive_info.st_uid != os.geteuid()
    or archive_info.st_size <= 0
    or archive_info.st_size > max_archive
):
    raise SystemExit("returned guest evidence archive size or metadata is unsafe")
if os.path.lexists(destination):
    raise SystemExit("guest evidence staging destination already exists")
os.mkdir(destination, 0o700)
seen = set()
total = 0
members = 0
with tarfile.open(archive_path, "r:") as source:
    for member in source:
        members += 1
        name = member.name.rstrip("/")
        parts = name.split("/")
        if (
            members > max_members
            or not name
            or name.startswith("/")
            or any(part in ("", ".", "..") for part in parts)
            or any(ord(character) < 0x20 or ord(character) == 0x7f for character in name)
            or name in seen
        ):
            raise SystemExit("returned guest evidence contains an unsafe path/census")
        seen.add(name)
        target = os.path.join(destination, *parts)
        if os.path.commonpath((destination, target)) != destination:
            raise SystemExit("returned guest evidence escaped staging")
        if member.isdir():
            if member.mode != 0o700 or member.uid != 0 or member.gid != 0:
                raise SystemExit("returned evidence directory metadata differs")
            if os.path.lexists(target):
                if not stat.S_ISDIR(os.lstat(target).st_mode):
                    raise SystemExit("returned evidence directory collided with a file")
            else:
                os.makedirs(target, mode=0o700, exist_ok=False)
            continue
        if (
            not member.isfile()
            or member.mode != 0o600
            or member.uid != 0
            or member.gid != 0
            or member.size < 0
        ):
            raise SystemExit("returned evidence contains a link or special member")
        total += member.size
        if total > max_bytes:
            raise SystemExit("returned evidence expanded bytes exceeded")
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        if os.path.lexists(target):
            raise SystemExit("returned evidence file path already exists")
        incoming = source.extractfile(member)
        if incoming is None:
            raise SystemExit("returned evidence regular member is unreadable")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags, 0o600)
        written = 0
        try:
            while written < member.size:
                chunk = incoming.read(min(1024 * 1024, member.size - written))
                if not chunk:
                    raise SystemExit("returned evidence member ended early")
                offset = 0
                while offset < len(chunk):
                    offset += os.write(descriptor, chunk[offset:])
                written += len(chunk)
            if incoming.read(1):
                raise SystemExit("returned evidence member exceeded declared size")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
owner_expected = (
    "shadowpipe-full-tun-result-owner-v1\n"
    f"run_id={run_id}\nclone_vm={clone_vm}\ntoken={token}\n"
).encode("ascii")
owner_path = os.path.join(destination, ".shadowpipe-full-tun-owner")
with open(owner_path, "rb", buffering=0) as stream:
    if stream.read() != owner_expected:
        raise SystemExit("returned guest evidence owner marker differs")
manifest_path = os.path.join(destination, "checksums.sha256")
with open(manifest_path, "r", encoding="ascii", newline="") as stream:
    lines = stream.read().splitlines()
manifest = {}
for line in lines:
    if len(line) < 67 or line[64:66] != "  ":
        raise SystemExit("returned checksum manifest is malformed")
    digest, relative = line[:64], line[66:]
    if (
        len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or not relative
        or relative.startswith("/")
        or any(part in ("", ".", "..") for part in relative.split("/"))
        or relative == "checksums.sha256"
        or relative in manifest
    ):
        raise SystemExit("returned checksum manifest contains an unsafe record")
    manifest[relative] = digest
if list(manifest) != sorted(manifest):
    raise SystemExit("returned checksum manifest is not sorted")
census = {}
for current, directories, files in os.walk(destination, followlinks=False):
    directories.sort()
    files.sort()
    for name in directories:
        path = os.path.join(current, name)
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            raise SystemExit("returned evidence staging contains a symlinked subtree")
    for name in files:
        path = os.path.join(current, name)
        relative = os.path.relpath(path, destination)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit("returned evidence staging contains an unsafe file")
        if relative == "checksums.sha256":
            continue
        digest = hashlib.sha256()
        with open(path, "rb", buffering=0) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        census[relative] = digest.hexdigest()
if census != manifest:
    raise SystemExit("returned evidence checksum census or digest differs")
PY
}

merge_guest_evidence_stage() {
  local source="$1" destination="$2" owner_file="$3"
  python3 -I -S - "${source}" "${destination}" "${owner_file}" <<'PY'
import os
import shutil
import stat
import sys

source, destination, owner_file = map(os.path.abspath, sys.argv[1:])
for path, label in ((source, "source"), (destination, "destination")):
    info = os.lstat(path)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or os.path.realpath(path) != path
    ):
        raise SystemExit(f"guest evidence merge {label} is unsafe")
if os.path.dirname(owner_file) != destination:
    raise SystemExit("reserved owner file escaped the result directory")
if sorted(os.listdir(destination)) != [os.path.basename(owner_file)]:
    raise SystemExit("reserved host result directory is not empty")
source_owner = os.path.join(source, os.path.basename(owner_file))
with open(source_owner, "rb", buffering=0) as left, \
     open(owner_file, "rb", buffering=0) as right:
    if left.read() != right.read():
        raise SystemExit("guest and host result owner markers differ")
for current, directories, files in os.walk(source, followlinks=False):
    directories.sort()
    files.sort()
    relative_current = os.path.relpath(current, source)
    target_current = (
        destination
        if relative_current == "."
        else os.path.join(destination, relative_current)
    )
    if relative_current != ".":
        if os.path.lexists(target_current):
            raise SystemExit("guest evidence destination directory collision")
        os.mkdir(target_current, 0o700)
    for name in directories:
        path = os.path.join(current, name)
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SystemExit("guest evidence stage contains a symlinked subtree")
    for name in files:
        if relative_current == "." and name == os.path.basename(owner_file):
            continue
        path = os.path.join(current, name)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit("guest evidence stage contains an unsafe file")
        target = os.path.join(target_current, name)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        output = os.open(target, flags, 0o600)
        incoming = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(incoming, "rb") as source_stream, \
             os.fdopen(output, "wb") as target_stream:
            shutil.copyfileobj(source_stream, target_stream, 1024 * 1024)
            target_stream.flush()
            os.fsync(target_stream.fileno())
PY
}

exact_files_equal() {
  python3 -I -S - "$1" "$2" <<'PY'
import sys

with open(sys.argv[1], "rb", buffering=0) as left, \
     open(sys.argv[2], "rb", buffering=0) as right:
    while True:
        a = left.read(1024 * 1024)
        b = right.read(1024 * 1024)
        if a != b:
            raise SystemExit(1)
        if not a:
            raise SystemExit(0)
PY
}

exact_private_regular_file() {
  local path="$1" expected_uid="$2" expected_gid="$3" expected_size="$4"
  python3 -I -S - "${path}" "${expected_uid}" "${expected_gid}" \
    "${expected_size}" <<'PY'
import os
import stat
import sys

path, expected_uid_text, expected_gid_text, expected_size_text = sys.argv[1:]
expected_uid = int(expected_uid_text, 10)
expected_gid = int(expected_gid_text, 10)
expected_size = (
    None if expected_size_text == "any" else int(expected_size_text, 10)
)
if min(expected_uid, expected_gid) < 0 or (
    expected_size is not None and expected_size < 0
):
    raise SystemExit("negative private-file invariant")

def validate(info):
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_uid == expected_uid
        and info.st_gid == expected_gid
        and info.st_nlink == 1
        and (expected_size is None or info.st_size == expected_size)
    )

before = os.lstat(path)
if not validate(before):
    raise SystemExit("private file metadata differs")
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
descriptor = os.open(path, flags)
try:
    opened = os.fstat(descriptor)
    if (
        not validate(opened)
        or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise SystemExit("private file identity raced while opening")
    observed_size = 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        observed_size += len(chunk)
        if expected_size is not None and observed_size > expected_size:
            raise SystemExit("private file exceeded its expected size")
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
final = os.lstat(path)
stable = (
    opened.st_dev,
    opened.st_ino,
    opened.st_size,
    opened.st_mtime_ns,
    opened.st_ctime_ns,
)
if (
    observed_size != opened.st_size
    or (expected_size is not None and observed_size != expected_size)
    or not validate(after)
    or not validate(final)
):
    raise SystemExit("private file content or final metadata differs")
if (
    (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    != stable
    or (
        final.st_dev,
        final.st_ino,
        final.st_size,
        final.st_mtime_ns,
        final.st_ctime_ns,
    )
    != stable
):
    raise SystemExit("private file changed while validating")
PY
}

exact_empty_private_regular_file() {
  exact_private_regular_file "$1" "$2" "$3" 0
}

create_empty_private_regular_file() {
  local path="$1"
  python3 -I -S - "${path}" <<'PY'
import os
import sys

path = os.path.abspath(sys.argv[1])
flags = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
descriptor = os.open(path, flags, 0o600)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(
    os.path.dirname(path),
    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

create_private_material_scan_canary() {
  local path="$1"
  python3 -I -S - "${path}" <<'PY'
import os
import sys

path = os.path.abspath(sys.argv[1])
flags = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
descriptor = os.open(path, flags, 0o600)
try:
    value = os.urandom(32)
    written = 0
    while written < len(value):
        written += os.write(descriptor, value[written:])
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

publish_replay_store_stage_marker() {
  local path="$1"
  python3 -I -S - "${path}" <<'PY'
import os
import sys

path = os.path.abspath(sys.argv[1])
content = (
    b"schema_version=1\n"
    b"replay_store_stage=created_and_validated\n"
    b"replay_store_bytes=1572960\n"
    b"replay_store_lock_bytes=0\n"
)
flags = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
descriptor = os.open(path, flags, 0o600)
try:
    written = 0
    while written < len(content):
        written += os.write(descriptor, content[written:])
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

validate_replay_store_stage_marker() {
  local path="$1" expected_uid="$2" expected_gid="$3"
  python3 -I -S - "${path}" "${expected_uid}" "${expected_gid}" <<'PY'
import os
import stat
import sys

path, expected_uid_text, expected_gid_text = sys.argv[1:]
expected_uid = int(expected_uid_text, 10)
expected_gid = int(expected_gid_text, 10)
content = (
    b"schema_version=1\n"
    b"replay_store_stage=created_and_validated\n"
    b"replay_store_bytes=1572960\n"
    b"replay_store_lock_bytes=0\n"
)

def validate(info):
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_uid == expected_uid
        and info.st_gid == expected_gid
        and info.st_nlink == 1
        and info.st_size == len(content)
    )

before = os.lstat(path)
if not validate(before):
    raise SystemExit("replay-store stage marker metadata differs")
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
descriptor = os.open(path, flags)
try:
    opened = os.fstat(descriptor)
    if (
        not validate(opened)
        or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise SystemExit("replay-store stage marker raced while opening")
    observed = bytearray()
    while len(observed) <= len(content):
        chunk = os.read(descriptor, len(content) + 1 - len(observed))
        if not chunk:
            break
        observed.extend(chunk)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
final = os.lstat(path)
stable = (
    opened.st_dev,
    opened.st_ino,
    opened.st_size,
    opened.st_mtime_ns,
    opened.st_ctime_ns,
)
if bytes(observed) != content or not validate(after) or not validate(final):
    raise SystemExit("replay-store stage marker content or metadata differs")
if (
    (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    != stable
    or (
        final.st_dev,
        final.st_ino,
        final.st_size,
        final.st_mtime_ns,
        final.st_ctime_ns,
    )
    != stable
):
    raise SystemExit("replay-store stage marker changed while validating")
PY
}

verify_guest_marker_proof() {
  local proof="$1" token="$2"
  python3 -I -S - "${proof}" "${token}" <<'PY'
import sys
with open(sys.argv[1], "r", encoding="ascii") as stream:
    lines = stream.read().splitlines()
if lines != ["0 0 600 1 regular file", sys.argv[2]]:
    raise SystemExit("guest marker identity/mode/content differs")
PY
}

validate_live_guest_marker() {
  local marker="$1" token="$2"
  python3 -I -S - "${marker}" "${token}" <<'PY'
import os
import stat
import sys

path, token = sys.argv[1:]
if path != "/var/lib/shadowpipe-full-tun-lab-owner":
    raise SystemExit("unexpected guest ownership-marker path")
if len(token) != 64 or any(character not in "0123456789abcdef" for character in token):
    raise SystemExit("invalid guest ownership token")
before = os.lstat(path)
if (
    not stat.S_ISREG(before.st_mode)
    or stat.S_ISLNK(before.st_mode)
    or before.st_uid != 0
    or before.st_gid != 0
    or stat.S_IMODE(before.st_mode) != 0o600
    or before.st_nlink != 1
):
    raise SystemExit("guest ownership marker metadata differs")
descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
        raise SystemExit("guest ownership marker raced while opening")
    chunks = []
    while True:
        chunk = os.read(descriptor, 4096)
        if not chunk:
            break
        chunks.append(chunk)
        if sum(map(len, chunks)) > 65:
            raise SystemExit("guest ownership marker is oversized")
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
if (
    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    or after.st_nlink != 1
):
    raise SystemExit("guest ownership marker changed while reading")
if b"".join(chunks) != (token + "\n").encode("ascii"):
    raise SystemExit("guest ownership marker token differs")
PY
}

validate_singbox_command() {
  local command_file="$1"
  python3 -I -S - "${command_file}" "${EXPECTED_SINGBOX_CONFIG}" \
    "${EXPECTED_SINGBOX_DIRECTORY}" <<'PY'
import re
import sys
command_file, expected_config, expected_directory = sys.argv[1:]
with open(command_file, "r", encoding="utf-8") as stream:
    command = stream.read().strip()
pattern = re.compile(
    r"^(?:\S*/)?sing-box run -c " + re.escape(expected_config)
    + r" -D " + re.escape(expected_directory) + r"$"
)
if pattern.fullmatch(command) is None:
    raise SystemExit("sing-box argv is not the protected live configuration")
PY
}

capture_singbox_candidate_commands() {
  local candidates_file="$1" output="$2"
  local status=0 pid command temporary ps_status
  : >"${output}"
  : >"${output}.stderr"
  if [[ ! -f "${candidates_file}" || -L "${candidates_file}" ]]; then
    printf 'candidate PID evidence is absent, nonregular, or a symlink\n' \
      >"${output}.stderr"
    status=1
  else
    while IFS= read -r pid || [[ -n "${pid}" ]]; do
      if [[ ! "${pid}" =~ ^[1-9][0-9]*$ ]]; then
        printf 'invalid exact-name sing-box candidate PID: %s\n' "${pid}" \
          >>"${output}.stderr"
        status=1
        continue
      fi
      temporary="$(mktemp "${output}.ps.XXXXXX")" || {
        printf 'could not allocate candidate command capture\n' \
          >>"${output}.stderr"
        status=1
        break
      }
      if run_bounded "${HOST_COMMAND_TIMEOUT}" \
        ps -ww -p "${pid}" -o command= \
        >"${temporary}" 2>>"${output}.stderr"; then
        if [[ "$(wc -l <"${temporary}" | tr -d ' ')" == 1 ]] \
          && IFS= read -r command <"${temporary}" \
          && [[ -n "${command}" ]]; then
          printf '%s\t%s\n' "${pid}" "${command}" >>"${output}"
        else
          printf 'candidate PID %s did not yield one nonempty argv line\n' \
            "${pid}" >>"${output}.stderr"
          status=1
        fi
      else
        ps_status=$?
        printf 'candidate PID %s argv capture failed with status %s\n' \
          "${pid}" "${ps_status}" >>"${output}.stderr"
        status=1
      fi
      rm -f -- "${temporary}"
    done <"${candidates_file}"
  fi
  printf '%s\n' "${status}" >"${output}.status"
  return "${status}"
}

select_managed_singbox_candidates() {
  local records_file="$1" output="$2"
  local status=0 record pid command temporary accepted_count previous_pid=0
  : >"${output}"
  : >"${output}.stderr"
  if [[ ! -f "${records_file}" || -L "${records_file}" ]]; then
    printf 'candidate argv evidence is absent, nonregular, or a symlink\n' \
      >"${output}.stderr"
    status=1
  else
    while IFS= read -r record || [[ -n "${record}" ]]; do
      if [[ "${record}" != *$'\t'* ]]; then
        printf 'candidate argv record lacks a PID delimiter\n' \
          >>"${output}.stderr"
        status=1
        continue
      fi
      pid="${record%%$'\t'*}"
      command="${record#*$'\t'}"
      if [[ ! "${pid}" =~ ^[1-9][0-9]*$ || -z "${command}" ]]; then
        printf 'candidate argv record is malformed\n' >>"${output}.stderr"
        status=1
        continue
      fi
      if (( pid <= previous_pid )); then
        printf 'candidate PID census is duplicate or unsorted at: %s\n' "${pid}" \
          >>"${output}.stderr"
        status=1
        continue
      fi
      previous_pid="${pid}"
      temporary="$(mktemp "${output}.command.XXXXXX")" || {
        printf 'could not allocate candidate validator input\n' \
          >>"${output}.stderr"
        status=1
        break
      }
      printf '%s\n' "${command}" >"${temporary}"
      if validate_singbox_command "${temporary}" 2>>"${output}.stderr"; then
        printf '%s\n' "${pid}" >>"${output}"
      else
        printf 'candidate PID %s rejected by exact argv validation\n' \
          "${pid}" >>"${output}.stderr"
      fi
      rm -f -- "${temporary}"
    done <"${records_file}"
  fi
  accepted_count="$(wc -l <"${output}" | tr -d ' ')"
  if [[ "${accepted_count}" != 1 ]]; then
    printf 'expected exactly one accepted sing-box PID, observed %s\n' \
      "${accepted_count}" >>"${output}.stderr"
    status=1
  fi
  printf '%s\n' "${status}" >"${output}.status"
  return "${status}"
}

validate_singbox_reproof() {
  local root="$1" left right
  for left in sing-box.pids.candidates sing-box.candidate-commands.tsv \
    sing-box.pids sing-box.identity sing-box.command \
    sing-box-binary.path; do
    case "${left}" in
      sing-box.pids.candidates) right=sing-box.pids-final.candidates ;;
      sing-box.candidate-commands.tsv) right=sing-box.candidate-commands-final.tsv ;;
      sing-box-binary.path) right=sing-box-binary-final.path ;;
      *) right="${left}-final" ;;
    esac
    run_bounded "${HOST_COMMAND_TIMEOUT}" \
      cmp -s -- "${root}/${left}" "${root}/${right}" || return 1
  done
}

self_test_singbox_observer() {
  local root="$1" exact unrelated foreign
  mkdir -p -- "${root}" || return 1
  exact="/opt/homebrew/bin/sing-box run -c ${EXPECTED_SINGBOX_CONFIG} -D ${EXPECTED_SINGBOX_DIRECTORY}"
  unrelated="/Applications/SkyComputerUseClient turn-ended payload=sing-box run -c ${EXPECTED_SINGBOX_CONFIG} -D ${EXPECTED_SINGBOX_DIRECTORY}"
  foreign='/opt/homebrew/bin/sing-box run -c /tmp/foreign.json -D /tmp/foreign'

  printf '101\t%s\n' "${exact}" >"${root}/records"
  select_managed_singbox_candidates \
    "${root}/records" "${root}/accepted" || return 1
  grep -qx 101 "${root}/accepted" || return 1
  printf '101\t%s\n102\t%s\n' "${exact}" "${foreign}" >"${root}/records"
  select_managed_singbox_candidates \
    "${root}/records" "${root}/accepted" || return 1
  grep -qx 101 "${root}/accepted" || return 1
  printf '201\t%s\n' "${unrelated}" >"${root}/records"
  if select_managed_singbox_candidates \
    "${root}/records" "${root}/accepted"; then
    return 1
  fi
  : >"${root}/records"
  if select_managed_singbox_candidates \
    "${root}/records" "${root}/accepted"; then
    return 1
  fi
  printf '301\t%s\n302\t%s\n' "${exact}" "${exact}" >"${root}/records"
  if select_managed_singbox_candidates \
    "${root}/records" "${root}/accepted"; then
    return 1
  fi
  printf '401\t%s\n401\t%s\n' "${exact}" "${exact}" >"${root}/records"
  if select_managed_singbox_candidates \
    "${root}/records" "${root}/accepted"; then
    return 1
  fi
  printf '0\t%s\n' "${exact}" >"${root}/records"
  if select_managed_singbox_candidates \
    "${root}/records" "${root}/accepted"; then
    return 1
  fi

  printf '101\n' >"${root}/sing-box.pids.candidates"
  printf '101\n' >"${root}/sing-box.pids-final.candidates"
  printf '101\t%s\n' "${exact}" >"${root}/sing-box.candidate-commands.tsv"
  printf '101\t%s\n' "${exact}" \
    >"${root}/sing-box.candidate-commands-final.tsv"
  printf '101\n' >"${root}/sing-box.pids"
  printf '101\n' >"${root}/sing-box.pids-final"
  printf '101 Mon Jan  1 00:00:00 2024 %s\n' "${exact}" \
    >"${root}/sing-box.identity"
  printf '101 Mon Jan  1 00:00:00 2024 %s\n' "${exact}" \
    >"${root}/sing-box.identity-final"
  printf '%s\n' "${exact}" >"${root}/sing-box.command"
  printf '%s\n' "${exact}" >"${root}/sing-box.command-final"
  printf '/opt/homebrew/bin/sing-box\n' >"${root}/sing-box-binary.path"
  printf '/opt/homebrew/bin/sing-box\n' \
    >"${root}/sing-box-binary-final.path"
  validate_singbox_reproof "${root}" || return 1
  printf '101 Mon Jan  1 00:00:01 2024 %s\n' "${exact}" \
    >"${root}/sing-box.identity-final"
  if validate_singbox_reproof "${root}"; then
    return 1
  fi
  [[ -f "${root}/accepted.status" && -f "${root}/accepted.stderr" ]]
}

classify_pf_runtime() {
  local output="$1"
  python3 -I -S - "${output}" <<'PY'
import os
import sys
root = sys.argv[1]
states = []
for name in ("rules", "nat", "info"):
    with open(os.path.join(root, name + ".status"), "r", encoding="ascii") as stream:
        status = int(stream.read().strip(), 10)
    with open(os.path.join(root, name + ".stdout"), "rb") as stream:
        stdout = stream.read()
    with open(os.path.join(root, name + ".stderr"), "rb") as stream:
        stderr = stream.read()
    if status == 0:
        states.append("observed")
    elif status == 1 and stdout == b"" and stderr == b"pfctl: /dev/pf: Permission denied\n":
        states.append("permission-denied")
    else:
        raise SystemExit(f"unrecognized read-only pfctl outcome for {name}")
if len(set(states)) != 1:
    raise SystemExit("read-only PF collector changed privilege state across views")
observed = states[0] == "observed"
with open(os.path.join(root, "scope.env"), "x", encoding="ascii") as stream:
    stream.write(f"pf_runtime_observed={'true' if observed else 'false'}\n")
    stream.write("pf_runtime_permission_denied_recognized="
                 f"{'false' if observed else 'true'}\n")
PY
}

capture_pf_runtime() {
  local output="$1" name status
  mkdir -- "${output}" || return 1
  for name in rules nat info; do
    local -a arguments=(-sr)
    [[ "${name}" == nat ]] && arguments=(-sn)
    [[ "${name}" == info ]] && arguments=(-si)
    if run_bounded "${HOST_COMMAND_TIMEOUT}" pfctl "${arguments[@]}" \
      >"${output}/${name}.stdout" \
      2>"${output}/${name}.stderr"; then
      status=0
    else
      status=$?
    fi
    printf '%s\n' "${status}" >"${output}/${name}.status" || return 1
  done
  classify_pf_runtime "${output}"
}

validate_singbox_binary_path() {
  local output="$1"
  python3 -I -S - "${output}" <<'PY'
import os
import stat
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    lines = stream.read().splitlines()
if len(lines) != 1 or not os.path.isabs(lines[0]):
    raise SystemExit("sing-box PID path is not one absolute path")
info = os.lstat(lines[0])
if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
    raise SystemExit("sing-box PID path is not a real regular executable")
if not os.access(lines[0], os.X_OK):
    raise SystemExit("sing-box PID path is not executable")
PY
}

capture_singbox_binary() {
  local pid="$1" output="$2"
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${output}" \
    python3 -I -S -c '
import ctypes
import os
import sys
pid = int(sys.argv[1], 10)
buffer = ctypes.create_string_buffer(4096)
library = ctypes.CDLL("/usr/lib/libproc.dylib")
length = library.proc_pidpath(pid, buffer, len(buffer))
path = buffer.value.decode("utf-8") if length > 0 else ""
if not os.path.isabs(path):
    raise SystemExit("could not bind live executable path to sing-box PID")
print(path)
' "${pid}" || return 1
  validate_singbox_binary_path "${output}"
}

acquire_lifecycle_lock() {
  local token="$1" parent lock
  parent="$(cd -- /tmp && pwd -P)" || return 1
  lock="${parent}/shadowpipe-orbstack-lifecycle.lock"
  mkdir -m 0700 -- "${lock}" || return 1
  if ! python3 -I -S - "${lock}" "${token}" <<'PY'
import os
import sys
lock, token = sys.argv[1:]
path = os.path.join(lock, "owner")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags, 0o600)
with os.fdopen(fd, "w", encoding="ascii", newline="\n") as stream:
    stream.write(token + "\n")
    stream.flush()
    os.fsync(stream.fileno())
directory = os.open(lock, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
  then
    rmdir -- "${lock}" 2>/dev/null || true
    return 1
  fi
  printf '%s\n' "${lock}"
}

release_lifecycle_lock() {
  local lock="$1" token="$2"
  python3 -I -S - "${lock}" "${token}" <<'PY'
import os
import stat
import sys
lock, token = sys.argv[1:]
info = os.lstat(lock)
if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
    raise SystemExit("lifecycle lock directory identity changed")
if sorted(os.listdir(lock)) != ["owner"]:
    raise SystemExit("lifecycle lock directory census changed")
owner = os.path.join(lock, "owner")
owner_info = os.lstat(owner)
if (not stat.S_ISREG(owner_info.st_mode) or owner_info.st_nlink != 1
        or owner_info.st_uid != os.geteuid()
        or stat.S_IMODE(owner_info.st_mode) != 0o600):
    raise SystemExit("lifecycle lock marker identity changed")
fd = os.open(owner, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
with os.fdopen(fd, "r", encoding="ascii") as stream:
    if stream.read() != token + "\n":
        raise SystemExit("lifecycle lock token changed")
os.unlink(owner)
os.rmdir(lock)
PY
}

copy_tree_no_follow() {
  local source="$1" destination="$2"
  python3 -I -S - "${source}" "${destination}" <<'PY'
import os
import shutil
import stat
import sys

source = os.path.abspath(sys.argv[1])
destination = os.path.abspath(sys.argv[2])
if os.path.lexists(destination):
    raise SystemExit("destination already exists")
source_info = os.lstat(source)
if stat.S_ISREG(source_info.st_mode):
    if source_info.st_nlink != 1:
        raise SystemExit("source file is multiply linked")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    output = os.open(destination, flags, 0o600)
    input_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(input_fd, "rb") as incoming, os.fdopen(output, "wb") as outgoing:
            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            outgoing.flush()
            os.fsync(outgoing.fileno())
    finally:
        pass
elif stat.S_ISDIR(source_info.st_mode) and not stat.S_ISLNK(source_info.st_mode):
    os.mkdir(destination, 0o700)
    for current, directories, files in os.walk(source, followlinks=False):
        directories.sort()
        files.sort()
        relative = os.path.relpath(current, source)
        target_current = destination if relative == "." else os.path.join(destination, relative)
        for name in directories:
            path = os.path.join(current, name)
            info = os.lstat(path)
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise SystemExit("source tree contains a non-directory subtree")
            os.mkdir(os.path.join(target_current, name), 0o700)
        for name in files:
            path = os.path.join(current, name)
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SystemExit("source tree contains a non-regular/multilink file")
            target = os.path.join(target_current, name)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            output = os.open(target, flags, 0o600)
            input_fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(input_fd, "rb") as incoming, os.fdopen(output, "wb") as outgoing:
                shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
                outgoing.flush()
                os.fsync(outgoing.fileno())
else:
    raise SystemExit("source is not a real regular file/directory")
PY
}

replace_regular_from_file() {
  local source="$1" destination="$2"
  python3 -I -S - "${source}" "${destination}" <<'PY'
import os
import secrets
import shutil
import stat
import sys

source, destination = map(os.path.abspath, sys.argv[1:])
source_info = os.lstat(source)
if not stat.S_ISREG(source_info.st_mode) or source_info.st_nlink != 1:
    raise SystemExit("publication source is unsafe")
if os.path.lexists(destination):
    info = os.lstat(destination)
    if stat.S_ISDIR(info.st_mode):
        raise SystemExit("refusing to replace a destination directory")
temporary = destination + f".host-final.{os.getpid()}.{secrets.token_hex(8)}.tmp"
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
output = os.open(temporary, flags, 0o600)
input_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    with os.fdopen(input_fd, "rb") as incoming, os.fdopen(output, "wb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    os.replace(temporary, destination)
finally:
    if os.path.lexists(temporary):
        os.unlink(temporary)
PY
}

remove_regular_no_follow() {
  local path="$1"
  python3 -I -S - "${path}" <<'PY'
import os
import stat
import sys
path = os.path.abspath(sys.argv[1])
info = os.lstat(path)
if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
    raise SystemExit("refusing to remove unsafe file")
os.unlink(path)
PY
}

scan_fingerprinted_material() {
  local fingerprint_file="$1" output="$2"
  shift 2
  python3 -I -S - "${fingerprint_file}" "${output}" "$@" <<'PY'
import hashlib
import os
import stat
import sys

fingerprint_path, output_path, *roots = sys.argv[1:]
fingerprints = {}
with open(fingerprint_path, "r", encoding="ascii") as stream:
    for raw in stream:
        fields = raw.split()
        if len(fields) != 2:
            raise SystemExit("malformed private-material fingerprint")
        length = int(fields[0], 10)
        digest = fields[1]
        if length <= 0 or len(digest) != 64:
            raise SystemExit("invalid private-material fingerprint")
        fingerprints.setdefault(length, set()).add(digest)
if not fingerprints:
    raise SystemExit("empty private-material fingerprint set")

paths = []
for root in roots:
    info = os.lstat(root)
    if stat.S_ISREG(info.st_mode):
        if info.st_nlink != 1:
            raise SystemExit("host-added evidence is multiply linked")
        paths.append(root)
    elif stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
        for current, directories, files in os.walk(root, followlinks=False):
            directories.sort()
            files.sort()
            for name in directories:
                subdir = os.path.join(current, name)
                if not stat.S_ISDIR(os.lstat(subdir).st_mode):
                    raise SystemExit("host-added evidence contains a symlinked subtree")
            for name in files:
                path = os.path.join(current, name)
                file_info = os.lstat(path)
                if not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1:
                    raise SystemExit("host-added evidence contains an unsafe file")
                paths.append(path)
    else:
        raise SystemExit("host-added evidence root is unsafe")

leaks = []
for path in paths:
    with open(path, "rb") as stream:
        data = stream.read()
    for length, digests in fingerprints.items():
        if length > len(data):
            continue
        for offset in range(0, len(data) - length + 1):
            candidate = hashlib.sha256(data[offset:offset + length]).hexdigest()
            if candidate in digests:
                leaks.append(f"{path}:{offset}:{length}")
                break
        if leaks and leaks[-1].startswith(path + ":"):
            break
with open(output_path, "x", encoding="utf-8") as stream:
    for leak in leaks:
        stream.write(leak + "\n")
if leaks:
    raise SystemExit(1)
PY
}

write_full_status() {
  local output="$1" guest_test="$2" guest_cleanup="$3" host_safety="$4"
  local clone_cleanup="$5" clone_deleted="$6" secret_scan="$7"
  local evidence_status="$8" overall="$9" source_state="${10}"
  local pf_runtime_observed="${11}"
  local lifecycle_lock_status="${12}"
  local clone_attempted_status="${13}"
  {
    printf 'test_status=%s\n' "${guest_test}"
    printf 'cleanup_status=%s\n' "${guest_cleanup}"
    printf 'scope=synthetic_orbstack_ipv4_tunnel_ipv6_block_netns_only\n'
    printf 'field_evidence=false\n'
    printf 'host_safety_status=%s\n' "${host_safety}"
    printf 'clone_cleanup_status=%s\n' "${clone_cleanup}"
    printf 'clone_attempted=%s\n' "${clone_attempted_status}"
    printf 'clone_deleted=%s\n' "${clone_deleted}"
    printf 'final_private_material_scan=%s\n' "${secret_scan}"
    printf 'evidence_bundle_status=%s\n' "${evidence_status}"
    printf 'overall_status=%s\n' "${overall}"
    printf 'source_vm_final_state=%s\n' "${source_state}"
    printf 'pf_runtime_observed=%s\n' "${pf_runtime_observed}"
    printf 'same_host_lifecycle_lock=%s\n' "${lifecycle_lock_status}"
    if [[ "${lifecycle_lock_status}" == released ]]; then
      printf 'concurrent_shadowpipe_orbstack_lifecycle_runners=excluded\n'
    else
      printf 'concurrent_shadowpipe_orbstack_lifecycle_runners=not_proved\n'
    fi
    printf 'unrelated_orbstack_lifecycle_operators=outside_trust_boundary\n'
  } >"${output}"
}

write_full_result() {
  local output="$1" verdict="$2" clone_vm="$3" pf_observed="$4"
  if [[ "${verdict}" == valid ]]; then
    {
      printf '# OrbStack isolated OS-TUN result\n\n'
      printf -- '- Verdict: **PASS**\n'
      # shellcheck disable=SC2016
      printf -- '- Disposable clone: `%s` (opaque OrbStack ID bound before start/run, guest marker re-proved, delete-by-name preceded immediately by name-to-ID rebinding, then a late-appearance window plus ID/name absence proved)\n' "${clone_vm}"
      # shellcheck disable=SC2016
      printf -- '- Host/guest boundary: isolated + network-isolated config, no mounts/forwarded ports/SSH agent, `/mnt/mac` absent, and every discovered `mac` command channel proved fail-closed\n'
      # shellcheck disable=SC2016
      printf -- '- Source/evidence channel: clean live-pushed `main` was pinned by commit-bearing `git archive`; source entered by bounded stdin and sealed evidence returned by validated stdout tar, with no shared checkout\n'
      printf -- '- Scope: synthetic OrbStack Linux IPv4 tunnel plus connected IPv6 OUTPUT-block/netns only; no IPv6 tunnel or L2 claim; field evidence: false\n'
      printf -- '- Network-change handoff: real c0-to-c1 default-route replacement with exact DefaultRouteChanged cause, strict intermediate lockdown/main-WAL proof, then generation-2 Active adoption through c1 before workloads\n'
      printf -- '- Observer regression: a real promiscuous packet capture toggled IFF_PROMISC without replacing generation 2; evidence captures otherwise used non-promiscuous directional capture\n'
      printf -- '- Carrier/authentication: production REALITY TLS 1.3 URI with X25519 short-id and ML-KEM pin, then mandatory protocol-v3 credential and enrolled allowlist\n'
      printf -- '- Final secret check: guest evidence scanned against stored/raw/hex/base64 variants; all host-added logs scanned against non-reversible fingerprints\n'
      printf -- '- Host safety: exact live sing-box PID/argv/config/executable plus stable routes, DNS and PF config files\n'
      printf -- '- Host-safety timing: consistent before/after endpoint snapshots; no continuous host mutation monitor\n'
      printf -- '- Exclusion: the shared lifecycle lock serializes Shadowpipe runners; unrelated same-host OrbStack operators remain outside the trust boundary and make the run fail on any name/ID/state drift\n'
      if [[ "${pf_observed}" == true ]]; then
        printf -- '- macOS PF runtime exact read-only rules/NAT/info snapshots were unchanged\n'
      else
        printf -- '- macOS PF runtime exact unprivileged permission denial was unchanged; loaded runtime remains explicitly unobserved\n'
      fi
    } >"${output}"
  else
    {
      printf '# OrbStack isolated OS-TUN failure\n\n'
      printf 'No PASS claim is present. Inspect status.env and the sealed evidence.\n'
    } >"${output}"
  fi
}

verify_no_control_lockdown_snapshot() {
  local wal="$1" listing="$2" census="$3"
  python3 -I -S - "${wal}" "${listing}" "${census}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    journal = json.load(stream)
with open(sys.argv[2], "r", encoding="utf-8") as stream:
    listing = json.load(stream)
with open(sys.argv[3], "r", encoding="utf-8") as stream:
    census = json.load(stream)
identity = journal["identity"]
table = "sp_lock_" + identity
owner = "shadowpipe-lockdown-v1:" + identity
expected_handle = journal["table_handle"]

def integer(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SystemExit(f"{label} is not a positive integer")
    return value

def entries(root, label):
    if not isinstance(root, dict) or set(root) != {"nftables"}:
        raise SystemExit(f"{label} root is not exact")
    if not isinstance(root["nftables"], list):
        raise SystemExit(f"{label} nftables member is not an array")
    return root["nftables"]

def one(entry, label):
    if not isinstance(entry, dict) or len(entry) != 1:
        raise SystemExit(f"{label} entry is not one-kind")
    kind, body = next(iter(entry.items()))
    if not isinstance(body, dict):
        raise SystemExit(f"{label} body is not an object")
    return kind, body

table_count = 0
chain_count = 0
rules = []
for entry in entries(listing, "lockdown listing"):
    kind, body = one(entry, "lockdown listing")
    if kind == "metainfo":
        continue
    if kind == "table":
        if set(body) != {"family", "name", "handle", "comment"}:
            raise SystemExit("lockdown table fields are not exact")
        if (
            body["family"] != "inet" or body["name"] != table
            or body["comment"] != owner
            or integer(body["handle"], "table handle") != integer(expected_handle, "WAL handle")
        ):
            raise SystemExit("lockdown table differs from WAL")
        table_count += 1
    elif kind == "chain":
        required = {
            "family", "table", "name", "handle", "type", "hook", "prio",
            "policy", "comment",
        }
        if set(body) != required:
            raise SystemExit("lockdown chain fields are not exact")
        if (
            body["family"] != "inet" or body["table"] != table
            or body["name"] != "sp_output" or body["type"] != "filter"
            or body["hook"] != "output" or body["prio"] != -400
            or body["policy"] != "drop" or body["comment"] != owner + ":chain"
        ):
            raise SystemExit("lockdown chain shape is not fail closed")
        integer(body["handle"], "chain handle")
        chain_count += 1
    elif kind == "rule":
        if set(body) != {"family", "table", "chain", "handle", "expr", "comment"}:
            raise SystemExit("lockdown rule fields are not exact")
        if body["family"] != "inet" or body["table"] != table or body["chain"] != "sp_output":
            raise SystemExit("lockdown rule coordinates are foreign")
        integer(body["handle"], "rule handle")
        rules.append((body["comment"], body["expr"]))
    else:
        raise SystemExit(f"foreign object in lockdown table: {kind}")
if table_count != 1 or chain_count != 1:
    raise SystemExit("lockdown table/chain census differs from one")
expected_rules = [
    (
        owner + ":loopback",
        [
            {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}},
            {"accept": None},
        ],
    ),
    (owner + ":terminal-drop", [{"drop": None}]),
]
if rules != expected_rules:
    raise SystemExit("lockdown rule comments/order/expressions differ")

lockdown = []
for entry in entries(census, "table census"):
    kind, body = one(entry, "table census")
    if kind == "metainfo":
        continue
    if kind != "table":
        raise SystemExit("table census contains a foreign object")
    family, name = body.get("family"), body.get("name")
    if not isinstance(family, str) or not isinstance(name, str):
        raise SystemExit("table census lacks coordinates")
    if name.startswith("sp_lock_"):
        lockdown.append((family, name))
if lockdown != [("inet", table)]:
    raise SystemExit("global census does not contain exactly the WAL lockdown")
PY
}

strict_active_lockdown_snapshot() {
  local wal="$1" retained_wrapper_pid="$2" evidence_stem="$3"
  local table handle
  [[ -f "${wal}" && ! -L "${wal}" ]] || return 1
  [[ "$(LC_ALL=C stat -c '%a:%u:%g:%h:%F' "${wal}")" \
    == "600:0:0:1:regular file" ]] || return 1
  cat /proc/sys/kernel/random/boot_id >"${evidence_stem}-boot-id.txt"
  stat -Lc '%d %i' "/proc/${retained_wrapper_pid}/ns/net" \
    >"${evidence_stem}-netns.identity" || return 1
  stat -Lc '%d %i' "/proc/${retained_wrapper_pid}/ns/mnt" \
    >"${evidence_stem}-mntns.identity" || return 1
  if ! read -r table handle < <(
    python3 -I -S - "${wal}" \
      "${evidence_stem}-boot-id.txt" \
      "${evidence_stem}-netns.identity" \
      "${evidence_stem}-mntns.identity" <<'PY'
import json
import re
import sys

wal_path, boot_path, net_path, mount_path = sys.argv[1:]
with open(wal_path, "r", encoding="utf-8") as stream:
    value = json.load(stream)
required = {
    "schema_version", "generation", "identity", "boot_id", "uid",
    "network_namespace", "mount_namespace", "control_flow", "phase",
    "table_handle", "release_reason",
}
if set(value) != required:
    raise SystemExit("unexpected lockdown WAL schema")
identity = value["identity"]
handle = value["table_handle"]
if value["schema_version"] != 1 or value["phase"] != "active":
    raise SystemExit("lockdown WAL is not schema-v1 Active")
generation = value["generation"]
if (not isinstance(generation, int) or isinstance(generation, bool)
        or generation <= 0):
    raise SystemExit("lockdown WAL generation is invalid")
if not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{32}", identity) is None:
    raise SystemExit("lockdown identity is not canonical lowercase hex")
if identity == "0" * 32:
    raise SystemExit("lockdown identity is zero")
if (not isinstance(value["boot_id"], str)
        or re.fullmatch(r"[0-9a-f]{32}", value["boot_id"]) is None):
    raise SystemExit("lockdown boot identity is not canonical lowercase hex")
with open(boot_path, "r", encoding="ascii") as stream:
    boot_id = stream.read().strip().replace("-", "").lower()
if value["boot_id"] != boot_id or boot_id == "0" * 32:
    raise SystemExit("lockdown WAL boot identity differs from the live kernel")
for label, observed_path in (
    ("network_namespace", net_path), ("mount_namespace", mount_path)
):
    namespace = value[label]
    if not isinstance(namespace, dict) or set(namespace) != {"device", "inode"}:
        raise SystemExit(f"{label} has an unexpected schema")
    if any(not isinstance(namespace[field], int)
           or isinstance(namespace[field], bool)
           or namespace[field] <= 0 for field in ("device", "inode")):
        raise SystemExit(f"{label} has an invalid identity")
    with open(observed_path, "r", encoding="ascii") as stream:
        fields = stream.read().split()
    if len(fields) != 2 or any(not field.isdigit() for field in fields):
        raise SystemExit(f"live {label} identity is malformed")
    if namespace != {"device": int(fields[0]), "inode": int(fields[1])}:
        raise SystemExit(f"{label} differs from the retained wrapper namespace")
if not isinstance(handle, int) or isinstance(handle, bool) or handle <= 0:
    raise SystemExit("lockdown table handle is invalid")
if value["uid"] != 0 or value["control_flow"] is not None:
    raise SystemExit("lockdown owner/control-flow scope is unexpected")
if value["release_reason"] is not None:
    raise SystemExit("Active lockdown unexpectedly has a release reason")
print(f"sp_lock_{identity} {handle}")
PY
  ); then
    return 1
  fi
  [[ "${table}" =~ ^sp_lock_[0-9a-f]{32}$ \
    && "${handle}" =~ ^[1-9][0-9]*$ ]] || return 1
  ip netns exec "${ns_client}" nft -j -a list table inet "${table}" \
    >"${evidence_stem}-active.json" || return 1
  ip netns exec "${ns_client}" nft -j -a list tables \
    >"${evidence_stem}-census-active.json" || return 1
  verify_no_control_lockdown_snapshot "${wal}" \
    "${evidence_stem}-active.json" "${evidence_stem}-census-active.json" \
    || return 1
  printf '%s %s\n' "${table}" "${handle}"
}

strict_active_main_wal_snapshot() {
  local wal="$1" expected_pid="$2" retained_wrapper_pid="$3"
  local expected_bypass_iface="$4" evidence_stem="$5"
  [[ -f "${wal}" && ! -L "${wal}" ]] || return 1
  [[ "$(LC_ALL=C stat -c '%a:%u:%g:%h:%F' "${wal}")" \
    == "600:0:0:1:regular file" ]] || return 1
  cat /proc/sys/kernel/random/boot_id >"${evidence_stem}-boot-id.txt"
  stat -Lc '%d %i' "/proc/${retained_wrapper_pid}/ns/net" \
    >"${evidence_stem}-netns.identity" || return 1
  stat -Lc '%d %i' "/proc/${retained_wrapper_pid}/ns/mnt" \
    >"${evidence_stem}-mntns.identity" || return 1
  proc_starttime "${expected_pid}" >"${evidence_stem}-pid-start-ticks.txt" \
    || return 1
  python3 -I -S - "${wal}" "${expected_pid}" "${expected_bypass_iface}" \
    "${evidence_stem}-boot-id.txt" "${evidence_stem}-netns.identity" \
    "${evidence_stem}-mntns.identity" \
    "${evidence_stem}-pid-start-ticks.txt" \
    "${evidence_stem}-summary.json" <<'PY'
import collections
import json
import re
import sys

(
    wal_path, expected_pid_text, expected_iface, boot_path, net_path,
    mount_path, start_path, output_path,
) = sys.argv[1:]
expected_pid = int(expected_pid_text)
with open(wal_path, "r", encoding="utf-8") as stream:
    value = json.load(stream)
if set(value) != {"schema_version", "generation", "phase", "owner", "operations"}:
    raise SystemExit("unexpected main WAL schema")
if value["schema_version"] != 3 or value["phase"] != "active":
    raise SystemExit("main WAL is not schema-v3 Active")
if (not isinstance(value["generation"], int)
        or isinstance(value["generation"], bool)
        or value["generation"] <= 0):
    raise SystemExit("main WAL generation is invalid")

owner = value["owner"]
owner_fields = {
    "session_id", "boot_id", "uid", "pid", "pid_start_ticks",
    "network_namespace", "mount_namespace",
}
if not isinstance(owner, dict) or set(owner) != owner_fields:
    raise SystemExit("main WAL owner schema is unexpected")
for key in ("session_id", "boot_id"):
    if (not isinstance(owner[key], str)
            or re.fullmatch(r"[0-9a-f]{32}", owner[key]) is None
            or owner[key] == "0" * 32):
        raise SystemExit(f"main WAL {key} is invalid")
with open(boot_path, "r", encoding="ascii") as stream:
    boot_id = stream.read().strip().replace("-", "").lower()
if owner["boot_id"] != boot_id:
    raise SystemExit("main WAL boot identity differs from the live kernel")
with open(start_path, "r", encoding="ascii") as stream:
    start_ticks = int(stream.read().strip())
if owner["uid"] != 0 or owner["pid"] != expected_pid:
    raise SystemExit("main WAL process owner differs from replacement")
if owner["pid_start_ticks"] != start_ticks or start_ticks <= 0:
    raise SystemExit("main WAL process start identity differs from replacement")
for label, observed_path in (
    ("network_namespace", net_path), ("mount_namespace", mount_path)
):
    namespace = owner[label]
    if not isinstance(namespace, dict) or set(namespace) != {"device", "inode"}:
        raise SystemExit(f"main WAL {label} schema is unexpected")
    with open(observed_path, "r", encoding="ascii") as stream:
        fields = stream.read().split()
    if len(fields) != 2 or any(not field.isdigit() for field in fields):
        raise SystemExit(f"live {label} identity is malformed")
    expected = {"device": int(fields[0]), "inode": int(fields[1])}
    if namespace != expected or min(namespace.values()) <= 0:
        raise SystemExit(f"main WAL {label} differs from retained wrapper")

operations = value["operations"]
if not isinstance(operations, list) or len(operations) != 8:
    raise SystemExit("replacement main WAL operation census differs from eight")
if [entry.get("id") for entry in operations] != list(range(1, 9)):
    raise SystemExit("replacement main WAL operation IDs are not contiguous")
if any(not isinstance(entry, dict)
       or set(entry) != {"id", "state", "resource"}
       or entry["state"] != "applied" for entry in operations):
    raise SystemExit("replacement main WAL contains a non-Applied operation")

expected_resource_fields = {
    "tun": {"interface"},
    "route": {
        "purpose", "family", "table", "destination", "gateway", "output",
        "protocol", "metric",
    },
    "dns": {
        "target", "original", "original_sha256", "pinned", "pinned_sha256",
    },
    "firewall": {
        "family", "backend", "chain_token", "filter_table_origin",
        "output_chain_origin", "expected_rule_count",
    },
    "firewall_endpoint": {
        "family", "backend", "chain_token", "address", "transport", "port",
    },
}
kinds = collections.Counter()
resources = []
for entry in operations:
    wrapped = entry["resource"]
    if not isinstance(wrapped, dict) or set(wrapped) != {"kind", "resource"}:
        raise SystemExit("replacement main WAL resource wrapper is unexpected")
    kind = wrapped["kind"]
    body = wrapped["resource"]
    if kind not in expected_resource_fields:
        raise SystemExit("replacement main WAL resource kind is foreign")
    if not isinstance(body, dict) or set(body) != expected_resource_fields[kind]:
        raise SystemExit(f"replacement main WAL {kind} schema is unexpected")
    kinds[kind] += 1
    resources.append((kind, body))
if kinds != {
    "tun": 1, "route": 3, "dns": 1, "firewall": 2,
    "firewall_endpoint": 1,
}:
    raise SystemExit("replacement main WAL resource census is unexpected")

tun = next(body for kind, body in resources if kind == "tun")
if (not isinstance(tun["interface"], dict)
        or set(tun["interface"]) != {"name", "ifindex"}
        or tun["interface"]["name"] != "sptunc"
        or not isinstance(tun["interface"]["ifindex"], int)
        or tun["interface"]["ifindex"] <= 0):
    raise SystemExit("replacement main WAL TUN identity is invalid")

routes = [body for kind, body in resources if kind == "route"]
split = [route for route in routes if route["purpose"] == "split_default"]
bypass = [route for route in routes if route["purpose"] == "endpoint_bypass"]
if len(split) != 2 or len(bypass) != 1:
    raise SystemExit("replacement main WAL route purpose census is unexpected")
if {
    (route["destination"].get("address"), route["destination"].get("prefix_len"))
    for route in split
} != {("0.0.0.0", 1), ("128.0.0.0", 1)}:
    raise SystemExit("replacement split-default resources are unexpected")
if any(route["gateway"] is not None
       or route["output"].get("name") != "sptunc"
       or route["family"] != "ipv4"
       or route["protocol"] != 186 for route in split):
    raise SystemExit("replacement split-default ownership differs")
bypass = bypass[0]
if (bypass["destination"] != {"address": "10.232.0.2", "prefix_len": 32}
        or bypass["gateway"] != "10.233.0.1"
        or bypass["output"].get("name") != expected_iface
        or bypass["family"] != "ipv4"
        or bypass["protocol"] != 186):
    raise SystemExit("replacement bypass is not bound to the c1 underlay")

firewalls = [body for kind, body in resources if kind == "firewall"]
if {(item["family"], item["expected_rule_count"]) for item in firewalls} \
        != {("ipv4", 4), ("ipv6", 3)}:
    raise SystemExit("replacement firewall family/rule census is unexpected")
endpoint = next(body for kind, body in resources if kind == "firewall_endpoint")
if (endpoint["family"], endpoint["address"], endpoint["transport"], endpoint["port"]) \
        != ("ipv4", "10.232.0.2", "tcp", 47843):
    raise SystemExit("replacement firewall endpoint differs")
dns = next(body for kind, body in resources if kind == "dns")
if dns["target"] != "etc_resolv_conf":
    raise SystemExit("replacement DNS resource target differs")

with open(output_path, "x", encoding="ascii", newline="\n") as stream:
    json.dump(
        {
            "schema_version": value["schema_version"],
            "generation": value["generation"],
            "phase": value["phase"],
            "operation_count": len(operations),
            "resource_census": dict(sorted(kinds.items())),
            "bypass_interface": expected_iface,
            "bypass_gateway": bypass["gateway"],
        },
        stream,
        sort_keys=True,
        separators=(",", ":"),
    )
    stream.write("\n")
PY
}

validate_active_killswitch_saves() {
  local ipv4="$1" ipv6="$2" output="$3"
  python3 -I -S - "${ipv4}" "${ipv6}" "${output}" <<'PY'
import json
import re
import shlex
import sys

ipv4_path, ipv6_path, output_path = sys.argv[1:]
owner_pattern = re.compile(r"shadowpipe:[0-9a-f]{32}\Z")

def parse(path, prefix):
    with open(path, "r", encoding="utf-8") as stream:
        lines = [line.rstrip("\n") for line in stream]
    declarations = []
    rules = []
    for line in lines:
        match = re.fullmatch(rf":({prefix}_[0-9a-f]{{20}}) - \[0:0\]", line)
        if match:
            declarations.append(match.group(1))
        if line.startswith("-A "):
            rules.append(shlex.split(line, posix=True))
    if len(declarations) != 1:
        raise SystemExit(f"{prefix} chain declaration count differs from one")
    return declarations[0], rules

chain4, rules4 = parse(ipv4_path, "SP4")
chain6, rules6 = parse(ipv6_path, "SP6")
if chain4[4:] == chain6[4:]:
    raise SystemExit("IPv4 and IPv6 chain tokens are equal")

owners = []
for rule in rules4 + rules6:
    positions = [index for index, value in enumerate(rule) if value == "--comment"]
    if len(positions) == 1 and positions[0] + 1 < len(rule):
        owners.append(rule[positions[0] + 1])
if len(set(owners)) != 1 or not owners or owner_pattern.fullmatch(owners[0]) is None:
    raise SystemExit("kill-switch rules do not share one canonical owner comment")
owner = owners[0]

def owned(chain, matches, target):
    return ["-A", chain, *matches, "-m", "comment", "--comment", owner, "-j", target]

expected4 = [
    owned("OUTPUT", [], chain4),
    owned(chain4, ["-o", "lo"], "ACCEPT"),
    owned(chain4, ["-o", "sptunc"], "ACCEPT"),
    owned(
        chain4,
        ["-d", "10.232.0.2/32", "-p", "tcp", "-m", "tcp", "--dport", "47843"],
        "ACCEPT",
    ),
    owned(chain4, [], "DROP"),
]
expected6 = [
    owned("OUTPUT", [], chain6),
    owned(chain6, ["-o", "lo"], "ACCEPT"),
    owned(chain6, [], "DROP"),
]
if rules4 != expected4:
    raise SystemExit("IPv4 kill-switch rules differ from the exact fail-closed contract")
if rules6 != expected6:
    raise SystemExit("IPv6 kill-switch rules differ from the exact fail-closed contract")

with open(output_path, "x", encoding="ascii", newline="\n") as stream:
    json.dump(
        {
            "schema_version": 1,
            "owner": owner,
            "ipv4_chain": chain4,
            "ipv6_chain": chain6,
            "ipv4_rule_count": len(rules4),
            "ipv6_rule_count": len(rules6),
        },
        stream,
        sort_keys=True,
        separators=(",", ":"),
    )
    stream.write("\n")
PY
}

capture_positive_ipv6_drop_counter() {
  local identity="$1" output="$2" chain listing packets
  chain="$(jq -er '
    if type == "object"
      and keys == ["ipv4_chain", "ipv4_rule_count", "ipv6_chain",
        "ipv6_rule_count", "owner", "schema_version"]
      and (.ipv6_chain | type == "string")
      and (.ipv6_chain | test("^SP6_[0-9a-f]{20}$"))
    then .ipv6_chain
    else error("invalid kill-switch identity")
    end
  ' "${identity}")" || return 1
  listing="${output}.listing"
  ip netns exec "${ns_client}" ip6tables -L "${chain}" -v -n -x \
    >"${listing}" || return 1
  packets="$(awk '
    $3 == "DROP" && $1 ~ /^[0-9]+$/ {
      count += 1
      packets = $1
    }
    END {
      if (count != 1 || packets + 0 <= 0) exit 1
      print packets
    }
  ' "${listing}")" || return 1
  printf 'ipv6_chain=%s\nipv6_drop_packets=%s\n' "${chain}" "${packets}" \
    >"${output}"
}

host_main() {
  [[ "$(uname -s)" == Darwin ]] || die "${EX_USAGE}" "host mode must run on macOS"
  [[ "${ZATMENIE_DISPOSABLE_LAB:-}" == 1 ]] \
    || die "${EX_USAGE}" "set ZATMENIE_DISPOSABLE_LAB=1"
  [[ "$#" -le 1 ]] || { usage >&2; exit "${EX_USAGE}"; }

  local tool
  for tool in orb orbctl git route netstat ifconfig scutil pfctl pgrep ps cmp \
    mktemp awk sed tr wc date sha256sum find sort head mv rm stat id python3; do
    command -v "${tool}" >/dev/null \
      || die "${EX_UNAVAILABLE}" "missing host dependency: ${tool}"
  done

  local source_vm="${1:-shadowpipe-lab-base}"
  source_vm="$(sanitize_component "${source_vm}")" \
    || die "${EX_USAGE}" "unsafe source VM name"
  local script_dir repo_root result_root magic
  script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
  repo_root="$(cd -- "${script_dir}/../.." && pwd -P)"
  result_root="${script_dir}/results"
  [[ ! -L "${result_root}" ]] || die "${EX_UNAVAILABLE}" "result root is a symlink"
  mkdir -p -- "${result_root}"
  result_root="$(cd -- "${result_root}" && pwd -P)"
  [[ "${result_root}" == "${script_dir}/results" ]] \
    || die "${EX_UNAVAILABLE}" "result root escaped the repository"
  magic="${SHADOWPIPE_MAGIC:-${MAGIC_DEFAULT}}"
  validate_magic "${magic}" \
    || die "${EX_USAGE}" "SHADOWPIPE_MAGIC must be one value in the u32 range"

  local host_tmp host_artifacts before_dir after_dir build_log guest_log
  local source_archive guest_evidence_archive guest_evidence_stage
  host_tmp="$(mktemp -d "${TMPDIR:-/tmp}/shadowpipe-tun-host.XXXXXX")"
  host_tmp="$(cd -- "${host_tmp}" && pwd -P)"
  host_artifacts="${host_tmp}/host-artifacts"
  mkdir -m 0700 -- "${host_artifacts}"
  before_dir="${host_tmp}/mac-before"
  after_dir="${host_tmp}/mac-after"
  build_log="${host_artifacts}/build.log"
  guest_log="${host_artifacts}/guest.log"
  source_archive="${host_tmp}/source.tar"
  guest_evidence_archive="${host_tmp}/guest-evidence.tar"
  guest_evidence_stage="${host_tmp}/guest-evidence-stage"

  local run_dir run_id clone_vm result_owner_token result_owner_file
  local pinned_head source_archive_size source_archive_hash
  local guest_root guest_archive guest_repo guest_result
  run_dir="$(mktemp -d "${result_root}/$(date -u +%Y%m%dT%H%M%SZ)-$$-XXXXXX")"
  run_dir="$(cd -- "${run_dir}" && pwd -P)"
  run_id="$(sanitize_component "${run_dir##*/}")" \
    || die "${EX_UNAVAILABLE}" "mktemp produced an unsafe run id"
  clone_vm="$(printf 'sptun-%s' "${run_id}" | tr '[:upper:]' '[:lower:]')"
  result_owner_token="$(printf '%s\n%s\n%s\n' \
    "${run_id}" "${clone_vm}" "${host_tmp}" | sha256sum | awk '{print $1}')"
  [[ "${result_owner_token}" =~ ^[0-9a-f]{64}$ ]] \
    || die "${EX_UNAVAILABLE}" "could not derive result ownership token"
  result_owner_file="${run_dir}/.shadowpipe-full-tun-owner"
  guest_root="/var/lib/shadowpipe-full-tun-${run_id}"
  guest_archive="${guest_root}/source.tar"
  guest_repo="${guest_root}/shadowpipe"
  guest_result="${guest_repo}/tests/tun/results/${run_id}"
  python3 -I -S - "${result_owner_file}" "${run_id}" "${clone_vm}" \
    "${result_owner_token}" <<'PY'
import os
import sys
path, run_id, clone_vm, token = sys.argv[1:]
data = (
    "shadowpipe-full-tun-result-owner-v1\n"
    f"run_id={run_id}\nclone_vm={clone_vm}\ntoken={token}\n"
).encode("ascii")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags, 0o600)
try:
    os.write(descriptor, data)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  copy_tree_no_follow "${result_owner_file}" "${host_tmp}/expected-result-owner"

  host_result_owned() {
    local actual
    [[ -d "${run_dir}" && ! -L "${run_dir}" \
      && -f "${result_owner_file}" && ! -L "${result_owner_file}" ]] || return 1
    actual="$(cd -- "${run_dir}" 2>/dev/null && pwd -P)" || return 1
    [[ "${actual}" == "${result_root}/${run_id}" ]] || return 1
    cmp -s -- "${result_owner_file}" "${host_tmp}/expected-result-owner"
  }

  local final_status=0 clone_attempted=0 clone_owned=0 guest_result_valid=0
  local clone_completion_uncertain=0
  local guest_test_status=not_run guest_cleanup_status=not_run
  local host_safety_status=failed clone_cleanup_status=not_run
  local clone_deleted=not_attempted final_secret_scan=not_run
  local source_final_state=unknown baseline_valid=0 guest_user=""
  local pf_runtime_observed=unknown
  local lifecycle_lock='' lifecycle_lock_status=not_acquired
  local clone_deletion_pending=0
  local source_orb_id='' clone_orb_id='' clone_identity_bound=0

  host_cleanup() {
    local incoming=$? count state candidate_success=0 overall=failed
    local cleanup_listing final_listing census_ok=0
    local clone_step_failed=0 deletion_allowed=0 id_absent=0 name_absent=0
    local evidence_status=valid seal_ok=0
    trap - EXIT INT TERM HUP
    set +e
    (( incoming == 0 )) || final_status="${incoming}"

    if (( clone_attempted != 0 )); then
      clone_deleted=unknown
      clone_cleanup_status=failed
      cleanup_listing="${host_artifacts}/orb-list-cleanup-before.txt"
      if (( clone_completion_uncertain != 0 )); then
        if observe_clone_quiescence "${clone_vm}" "${source_vm}" \
          "${host_artifacts}/clone-quiescence-before-cleanup" stable_any \
          >"${host_artifacts}/clone-quiescence-before-cleanup.state"; then
          cleanup_listing="${host_artifacts}/clone-quiescence-before-cleanup/orb-list-${CLONE_QUIESCENCE_SAMPLES}.txt"
          census_ok=1
        fi
      elif run_recorded "${HOST_COMMAND_TIMEOUT}" "${cleanup_listing}" orbctl list; then
        census_ok=1
      fi
      if (( census_ok != 0 )); then
        count="$(vm_count_in_listing "${cleanup_listing}" "${clone_vm}")"
        if [[ "${count}" == 1 ]]; then
          if (( clone_identity_bound != 0 )) \
            && capture_bound_orb_info "${clone_vm}" "${clone_vm}" \
              "${clone_orb_id}" '' \
              "${host_artifacts}/clone-info-cleanup-before-marker.raw.json"; then
            state="$(orb_info_field \
              "${host_artifacts}/clone-info-cleanup-before-marker.raw.json" \
              "${clone_vm}" "${clone_orb_id}" '' state)" || state=''
            if [[ -n "${state}" ]]; then
              deletion_allowed=1
            else
              warn "refusing clone deletion: bound clone state was not parsed"
              clone_step_failed=1
              final_status=1
            fi
            if (( deletion_allowed != 0 && clone_owned != 0 )) \
              && [[ "${state}" != stopped ]]; then
              if ! run_recorded "${GUEST_COMMAND_TIMEOUT}" \
                "${host_artifacts}/clone-owner-cleanup-proof.txt" \
                orb -m "${clone_orb_id}" -u root sh -lc \
                "LC_ALL=C stat -c '%u %g %a %h %F' '${CLONE_MARKER}' && cat '${CLONE_MARKER}'" \
                || ! verify_guest_marker_proof \
                  "${host_artifacts}/clone-owner-cleanup-proof.txt" \
                  "${result_owner_token}"; then
                warn "refusing clone deletion: guest ownership marker was not re-proved"
                deletion_allowed=0
                clone_step_failed=1
                final_status=1
              fi
            fi
            if (( deletion_allowed != 0 )); then
              if capture_bound_orb_info "${clone_vm}" "${clone_vm}" \
                "${clone_orb_id}" '' \
                "${host_artifacts}/clone-info-cleanup-before-delete.raw.json"; then
                if run_recorded "${ORB_DELETE_TIMEOUT}" \
                  "${host_artifacts}/clone-delete.log" \
                  orbctl delete -f "${clone_vm}"; then
                  clone_deletion_pending=1
                  {
                    printf 'start_and_guest_selector=opaque_id\n'
                    printf 'delete_selector=name\n'
                    printf 'delete_precondition=fresh_name_to_bound_id_validation\n'
                    printf 'reason=OrbStack_2.2.1_delete_by_ID_panicked_in_observed_lab_run\n'
                  } >"${host_artifacts}/clone-delete-addressing.env"
                else
                  clone_step_failed=1
                  final_status=1
                fi
              else
                warn "refusing clone deletion: clone name was absent or reused"
                clone_step_failed=1
                final_status=1
              fi
            fi
          else
            warn "refusing clone deletion: opaque clone ID was never bound or no longer matches the name"
            clone_step_failed=1
            final_status=1
          fi
        elif [[ "${count}" == 0 ]]; then
          clone_deleted=true
          if (( clone_identity_bound != 0 )); then
            warn "bound clone disappeared before owned cleanup"
            clone_step_failed=1
            final_status=1
          fi
        else
          warn "clone census contains duplicate names"
          clone_step_failed=1
          final_status=1
        fi
      else
        warn "could not enumerate OrbStack clones before cleanup"
        clone_step_failed=1
        final_status=1
      fi
      census_ok=0
      final_listing="${host_artifacts}/orb-list-cleanup-after.txt"
      if (( clone_completion_uncertain != 0 || clone_deletion_pending != 0 )); then
        if observe_clone_quiescence "${clone_vm}" "${source_vm}" \
          "${host_artifacts}/clone-quiescence-after-cleanup" absent_all \
          >"${host_artifacts}/clone-quiescence-after-cleanup.state"; then
          final_listing="${host_artifacts}/clone-quiescence-after-cleanup/orb-list-${CLONE_QUIESCENCE_SAMPLES}.txt"
          census_ok=1
        fi
      elif run_recorded "${HOST_COMMAND_TIMEOUT}" "${final_listing}" orbctl list; then
        census_ok=1
      fi
      if (( census_ok != 0 )); then
        count="$(vm_count_in_listing "${final_listing}" "${clone_vm}")"
        if [[ "${count}" == 0 ]]; then
          name_absent=1
        fi
        if (( clone_identity_bound != 0 )); then
          if run_recorded "${HOST_COMMAND_TIMEOUT}" \
            "${host_artifacts}/clone-info-final-id.raw.json" \
            orbctl info "${clone_orb_id}" --format json; then
            warn "deleted clone ID still resolves"
          elif validate_orb_info_absence \
            "${host_artifacts}/clone-info-final-id.raw.json" "${clone_orb_id}"; then
            id_absent=1
          fi
          if run_recorded "${HOST_COMMAND_TIMEOUT}" \
            "${host_artifacts}/clone-info-final-name.raw.json" \
            orbctl info "${clone_vm}" --format json; then
            warn "deleted clone name still resolves"
          elif validate_orb_info_absence \
            "${host_artifacts}/clone-info-final-name.raw.json" "${clone_vm}"; then
            name_absent=1
          fi
        else
          id_absent=1
        fi
        if [[ "${count}" == 0 && "${name_absent}" == 1 \
          && "${id_absent}" == 1 ]]; then
          clone_deleted=true
          (( clone_step_failed == 0 )) && clone_cleanup_status=valid
        else
          clone_deleted=false
          warn "disposable clone absence was not proved: ${clone_vm}"
          clone_step_failed=1
          final_status=1
        fi
      else
        clone_deleted=unknown
        warn "could not prove disposable clone absence"
        clone_step_failed=1
        final_status=1
      fi
    fi

    if run_recorded "${HOST_COMMAND_TIMEOUT}" \
      "${host_artifacts}/orb-list-source-final.txt" orbctl list \
      && [[ "$(vm_state_in_listing \
        "${host_artifacts}/orb-list-source-final.txt" "${source_vm}")" == stopped ]] \
      && [[ -n "${source_orb_id}" ]] \
      && capture_bound_orb_info "${source_vm}" "${source_vm}" \
        "${source_orb_id}" stopped \
        "${host_artifacts}/source-info-final.raw.json"; then
      source_final_state=stopped
    else
      warn "source VM is no longer proved uniquely stopped"
      final_status=1
    fi

    if (( baseline_valid != 0 )) && snapshot_macos "${after_dir}" \
      && compare_macos_snapshots "${before_dir}" "${after_dir}"; then
      host_safety_status=valid
      if grep -qx 'pf_runtime_observed=true' \
        "${before_dir}/pf-runtime/scope.env"; then
        pf_runtime_observed=true
      elif grep -qx 'pf_runtime_observed=false' \
        "${before_dir}/pf-runtime/scope.env"; then
        pf_runtime_observed=false
      else
        host_safety_status=failed
        final_status=1
      fi
    else
      warn "macOS safety snapshot is incomplete or changed"
      final_status=1
    fi

    if [[ -n "${lifecycle_lock}" ]]; then
      if release_lifecycle_lock "${lifecycle_lock}" "${result_owner_token}"; then
        lifecycle_lock_status=released
        lifecycle_lock=''
      else
        warn "same-host OrbStack lifecycle lock identity changed or could not be released"
        lifecycle_lock_status=release_failed
        final_status=1
      fi
    fi

    if host_result_owned; then
      copy_tree_no_follow "${host_artifacts}" "${run_dir}/host-artifacts" \
        || final_status=1
      [[ -d "${before_dir}" ]] \
        && copy_tree_no_follow "${before_dir}" "${run_dir}/mac-before" \
        || final_status=1
      [[ -d "${after_dir}" ]] \
        && copy_tree_no_follow "${after_dir}" "${run_dir}/mac-after" \
        || final_status=1

      local fingerprints="${run_dir}/.private-material-fingerprints"
      local final_leaks="${host_tmp}/final-private-material-leaks.txt"
      if [[ -f "${fingerprints}" && ! -L "${fingerprints}" \
        && -d "${run_dir}/host-artifacts" && -d "${run_dir}/mac-before" \
        && -d "${run_dir}/mac-after" ]] \
        && scan_fingerprinted_material "${fingerprints}" "${final_leaks}" \
          "${run_dir}/host-artifacts" "${run_dir}/mac-before" "${run_dir}/mac-after"; then
        final_secret_scan=valid
        : >"${host_tmp}/final-private-material-scan.ok"
        copy_tree_no_follow "${host_tmp}/final-private-material-scan.ok" \
          "${run_dir}/private-material-final-scan.ok" || final_status=1
      else
        final_secret_scan=failed
        final_status=1
        if [[ -f "${final_leaks}" && ! -L "${final_leaks}" ]]; then
          copy_tree_no_follow "${final_leaks}" \
            "${run_dir}/final-private-material-leak-paths.txt" || final_status=1
        fi
      fi
      if [[ -e "${fingerprints}" || -L "${fingerprints}" ]]; then
        remove_regular_no_follow "${fingerprints}" || final_status=1
      fi

      if (( final_status == 0 && guest_result_valid != 0 \
        && clone_attempted != 0 )) \
        && [[ "${guest_test_status}" == valid \
          && "${guest_cleanup_status}" == valid \
          && "${host_safety_status}" == valid \
          && "${clone_cleanup_status}" == valid \
          && "${clone_deleted}" == true \
          && "${final_secret_scan}" == valid \
          && "${source_final_state}" == stopped \
          && "${lifecycle_lock_status}" == released ]]; then
        candidate_success=1
        overall=valid
      else
        final_status=1
      fi

      write_full_status "${host_tmp}/status.final" \
        "${guest_test_status}" "${guest_cleanup_status}" "${host_safety_status}" \
        "${clone_cleanup_status}" "${clone_deleted}" "${final_secret_scan}" \
        "${evidence_status}" "${overall}" "${source_final_state}" \
        "${pf_runtime_observed}" "${lifecycle_lock_status}" "${clone_attempted}"
      write_full_result "${host_tmp}/result.final" "${overall}" "${clone_vm}" \
        "${pf_runtime_observed}"
      replace_regular_from_file "${host_tmp}/status.final" "${run_dir}/status.env" \
        || final_status=1
      replace_regular_from_file "${host_tmp}/result.final" "${run_dir}/RESULT.md" \
        || final_status=1

      if (( candidate_success != 0 && final_status != 0 )); then
        candidate_success=0
        overall=failed
        write_full_status "${host_tmp}/status.failed-publication" \
          "${guest_test_status}" "${guest_cleanup_status}" "${host_safety_status}" \
          "${clone_cleanup_status}" "${clone_deleted}" "${final_secret_scan}" \
          valid failed "${source_final_state}" "${pf_runtime_observed}" \
          "${lifecycle_lock_status}" "${clone_attempted}"
        write_full_result "${host_tmp}/result.failed-publication" failed "${clone_vm}" \
          "${pf_runtime_observed}"
        replace_regular_from_file "${host_tmp}/status.failed-publication" \
          "${run_dir}/status.env" || true
        replace_regular_from_file "${host_tmp}/result.failed-publication" \
          "${run_dir}/RESULT.md" || true
      fi

      if seal_evidence "${run_dir}" \
        && (cd -- "${run_dir}" && sha256sum -c checksums.sha256 >/dev/null); then
        seal_ok=1
      else
        final_status=1
        candidate_success=0
        overall=failed
        evidence_status=failed
        [[ ! -e "${run_dir}/checksums.sha256" ]] \
          || remove_regular_no_follow "${run_dir}/checksums.sha256" || true
        write_full_status "${host_tmp}/status.seal-failed" \
          "${guest_test_status}" "${guest_cleanup_status}" "${host_safety_status}" \
          "${clone_cleanup_status}" "${clone_deleted}" "${final_secret_scan}" \
          failed failed "${source_final_state}" "${pf_runtime_observed}" \
          "${lifecycle_lock_status}" "${clone_attempted}"
        write_full_result "${host_tmp}/result.seal-failed" failed "${clone_vm}" \
          "${pf_runtime_observed}"
        replace_regular_from_file "${host_tmp}/status.seal-failed" \
          "${run_dir}/status.env" || true
        replace_regular_from_file "${host_tmp}/result.seal-failed" \
          "${run_dir}/RESULT.md" || true
        seal_evidence "${run_dir}" \
          && (cd -- "${run_dir}" && sha256sum -c checksums.sha256 >/dev/null) \
          && seal_ok=1
      fi
      (( seal_ok != 0 )) || final_status=1
      (( candidate_success != 0 )) || final_status=1
    else
      warn "result ownership changed; refusing result writes: ${run_dir}"
      final_status=1
    fi

    rm -rf -- "${host_tmp}"
    printf 'result: %s\n' "${run_dir}"
    trap - EXIT
    exit "${final_status}"
  }
  trap host_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP

  lifecycle_lock="$(acquire_lifecycle_lock "${result_owner_token}")" \
    || die 75 "another same-host OrbStack lifecycle runner is active or left a conservative stale lock"
  lifecycle_lock_status=held

  capture_git_checkout_proof \
    "${repo_root}" "${host_artifacts}/git-checkout-before" \
    || die "${EX_UNAVAILABLE}" \
      "repository must be clean pushed main before creating the guest archive"
  pinned_head="$(<"${host_artifacts}/git-checkout-before/head.txt")"
  create_pinned_source_archive "${repo_root}" "${pinned_head}" \
    "${source_archive}" "${host_artifacts}/source-archive.env" \
    || die "${EX_UNAVAILABLE}" "could not create a bounded pinned Git archive"
  source_archive_size="$(source_archive_field \
    "${host_artifacts}/source-archive.env" source_archive_bytes)" \
    || die "${EX_UNAVAILABLE}" "source archive size proof is malformed"
  source_archive_hash="$(source_archive_field \
    "${host_artifacts}/source-archive.env" source_archive_sha256)" \
    || die "${EX_UNAVAILABLE}" "source archive digest proof is malformed"

  run_recorded "${HOST_COMMAND_TIMEOUT}" "${host_artifacts}/orb-list-initial.txt" \
    orbctl list
  local source_state
  source_state="$(vm_state_in_listing \
    "${host_artifacts}/orb-list-initial.txt" "${source_vm}")" \
    || die "${EX_USAGE}" "source VM is absent or duplicated"
  [[ "${source_state}" == stopped ]] \
    || die "${EX_USAGE}" "source VM ${source_vm} must be stopped"
  [[ "$(vm_count_in_listing \
    "${host_artifacts}/orb-list-initial.txt" "${clone_vm}")" == 0 ]] \
    || die "${EX_UNAVAILABLE}" "generated clone name already exists"
  capture_bound_orb_info "${source_vm}" "${source_vm}" '' stopped \
    "${host_artifacts}/source-info-before.raw.json" \
    || die "${EX_UNAVAILABLE}" "could not bind the stopped source VM opaque ID"
  source_orb_id="$(orb_info_field \
    "${host_artifacts}/source-info-before.raw.json" "${source_vm}" '' stopped id)" \
    || die "${EX_UNAVAILABLE}" "could not extract the source VM opaque ID"
  if run_recorded "${HOST_COMMAND_TIMEOUT}" \
    "${host_artifacts}/clone-info-before.raw.json" \
    orbctl info "${clone_vm}" --format json; then
    die "${EX_UNAVAILABLE}" "generated clone name unexpectedly resolves before clone"
  fi
  validate_orb_info_absence \
    "${host_artifacts}/clone-info-before.raw.json" "${clone_vm}" \
    || die "${EX_UNAVAILABLE}" "generated clone absence was not proved by OrbStack ID lookup"
  snapshot_macos "${before_dir}" \
    || die "${EX_UNAVAILABLE}" "live macOS sing-box baseline is absent or ambiguous"
  baseline_valid=1

  say "cloning stopped ${source_vm} -> disposable ${clone_vm}"
  clone_attempted=1
  clone_completion_uncertain=1
  run_recorded "${ORB_CLONE_TIMEOUT}" "${host_artifacts}/clone.log" \
    orbctl clone "${source_vm}" "${clone_vm}"
  run_recorded "${HOST_COMMAND_TIMEOUT}" \
    "${host_artifacts}/orb-list-after-clone.txt" orbctl list
  [[ "$(vm_count_in_listing \
    "${host_artifacts}/orb-list-after-clone.txt" "${clone_vm}")" == 1 ]] \
    || die 1 "clone command did not yield exactly one clone"
  [[ "$(vm_state_in_listing \
    "${host_artifacts}/orb-list-after-clone.txt" "${source_vm}")" == stopped ]] \
    || die 1 "source VM changed state during clone creation"
  capture_bound_orb_info "${source_vm}" "${source_vm}" "${source_orb_id}" stopped \
    "${host_artifacts}/source-info-after-clone.raw.json" \
    || die 1 "source VM identity or state changed during clone creation"
  capture_bound_orb_info "${clone_vm}" "${clone_vm}" '' stopped \
    "${host_artifacts}/clone-info-after-clone.raw.json" \
    || die 1 "could not bind the new clone opaque ID"
  clone_orb_id="$(orb_info_field \
    "${host_artifacts}/clone-info-after-clone.raw.json" \
    "${clone_vm}" '' stopped id)" \
    || die 1 "could not extract the new clone opaque ID"
  clone_identity_bound=1
  clone_completion_uncertain=0
  capture_bound_orb_info "${clone_vm}" "${clone_vm}" "${clone_orb_id}" stopped \
    "${host_artifacts}/clone-info-before-start.raw.json" \
    || die 1 "clone name was absent or reused before start"
  run_recorded "${ORB_START_TIMEOUT}" "${host_artifacts}/clone-start.log" \
    orbctl start "${clone_orb_id}"
  capture_bound_orb_info "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
    "${host_artifacts}/clone-info-before-owner-marker.raw.json" \
    || die 1 "clone identity changed before ownership marking"
  guest_user="$(orb_info_field \
    "${host_artifacts}/clone-info-before-owner-marker.raw.json" \
    "${clone_vm}" "${clone_orb_id}" running default_username)" \
    || die "${EX_UNAVAILABLE}" \
      "isolated clone default_username is absent or unsafe"

  # Keep this as the first `orb` guest command after clone start. The identity
  # and capability check above is an orbctl host-side metadata read.
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${host_artifacts}/clone-owner-install.log" \
    orb -m "${clone_orb_id}" -u root python3 -I -S -c \
    'import os,sys; p=sys.argv[1]; data=(sys.argv[2]+"\n").encode("ascii"); flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0); fd=os.open(p,flags,0o600); os.write(fd,data); os.fsync(fd); os.close(fd); d=os.open(os.path.dirname(p),os.O_RDONLY|os.O_DIRECTORY); os.fsync(d); os.close(d)' \
    "${CLONE_MARKER}" "${result_owner_token}"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${host_artifacts}/clone-owner-proof.txt" \
    orb -m "${clone_orb_id}" -u root sh -lc \
    "LC_ALL=C stat -c '%u %g %a %h %F' '${CLONE_MARKER}' && cat '${CLONE_MARKER}'"
  verify_guest_marker_proof "${host_artifacts}/clone-owner-proof.txt" \
    "${result_owner_token}"
  clone_owned=1
  capture_bound_orb_info "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
    "${host_artifacts}/clone-info-after-owner-marker.raw.json" \
    || die 1 \
      "clone identity or isolated capabilities changed after ownership marking"
  capture_guest_isolation_preflight "${clone_orb_id}" "${guest_user}" \
    "${host_artifacts}/guest-isolation-preflight.env" \
    || die "${EX_UNAVAILABLE}" \
      "clone runtime exposes Mac sharing, SSH agent, or mac-command integration"

  stream_source_archive_to_guest "${clone_orb_id}" "${source_archive}" \
    "${guest_root}" "${guest_archive}" "${source_archive_size}" \
    "${source_archive_hash}" "${host_artifacts}/source-transfer.env" \
    || die 1 "bounded pinned source archive transfer into the clone failed"
  extract_guest_source_archive "${clone_orb_id}" "${guest_root}" \
    "${guest_archive}" "${guest_repo}" "${guest_result}" "${run_id}" \
    "${clone_vm}" "${result_owner_token}" "${source_archive_size}" \
    "${source_archive_hash}" "${host_artifacts}/source-extract.env" \
    || die 1 "guest-local source extraction or result ownership setup failed"

  say "building current tree inside ${clone_vm} with explicit magic ${magic}"
  # shellcheck disable=SC2016
  run_recorded "${BUILD_TIMEOUT}" "${build_log}" \
    orb -m "${clone_orb_id}" -u root env \
    SHADOWPIPE_MAGIC="${magic}" CARGO_NET_OFFLINE=true \
    CARGO_TARGET_DIR="${guest_repo}/target/full-tun-lab-${run_id}" \
    bash -lc 'set -Eeuo pipefail; cd -- "$1"; exec cargo build --offline --release --locked --no-default-features -p shadowpipe-client -p shadowpipe-server' \
    shadowpipe-guest-build "${guest_repo}"
  capture_git_checkout_proof "${repo_root}" \
    "${host_artifacts}/git-checkout-after-build" "${pinned_head}" \
    || die 1 "host checkout or pushed origin/main changed during guest-local build"

  say "running isolated full-TUN lab in ${clone_vm}"
  local guest_status
  set +e
  run_recorded "${LAB_TIMEOUT}" "${guest_log}" \
    orb -m "${clone_orb_id}" -u root env \
    ZATMENIE_TUN_GUEST=1 \
    ZATMENIE_EXPECTED_DISPOSABLE_VM="${clone_vm}" \
    ZATMENIE_RESULT_OWNER_TOKEN="${result_owner_token}" \
    SHADOWPIPE_MAGIC="${magic}" \
    bash "${guest_repo}/tests/tun/run-orbstack-full-tun.sh" \
    --guest "${run_id}" "${guest_user}"
  guest_status=$?
  set -e
  local evidence_transfer_status=0
  if stream_guest_evidence_archive "${clone_orb_id}" "${guest_result}" \
      "${run_id}" "${clone_vm}" "${result_owner_token}" \
      "${guest_evidence_archive}"; then
    copy_tree_no_follow "${guest_evidence_archive}.status" \
      "${host_artifacts}/guest-evidence-transfer.status" \
      || evidence_transfer_status=1
    copy_tree_no_follow "${guest_evidence_archive}.stderr" \
      "${host_artifacts}/guest-evidence-transfer.stderr" \
      || evidence_transfer_status=1
    if (( evidence_transfer_status == 0 )) \
      && extract_guest_evidence_archive "${guest_evidence_archive}" \
        "${guest_evidence_stage}" "${run_id}" "${clone_vm}" \
        "${result_owner_token}" \
      && merge_guest_evidence_stage "${guest_evidence_stage}" "${run_dir}" \
        "${result_owner_file}"; then
      {
        printf 'guest_evidence_transfer=validated_stream\n'
        printf 'guest_evidence_archive_bytes=%s\n' \
          "$(stat -f '%z' "${guest_evidence_archive}")"
        printf 'guest_evidence_archive_sha256=%s\n' \
          "$(sha256sum "${guest_evidence_archive}" | awk '{print $1}')"
      } >"${host_artifacts}/guest-evidence-transfer.env"
    else
      evidence_transfer_status=1
    fi
  else
    evidence_transfer_status=1
    [[ ! -e "${guest_evidence_archive}.status" ]] \
      || copy_tree_no_follow "${guest_evidence_archive}.status" \
        "${host_artifacts}/guest-evidence-transfer.status" || true
    [[ ! -e "${guest_evidence_archive}.stderr" ]] \
      || copy_tree_no_follow "${guest_evidence_archive}.stderr" \
        "${host_artifacts}/guest-evidence-transfer.stderr" || true
  fi
  if (( evidence_transfer_status != 0 )); then
    warn "sealed guest evidence could not be safely streamed and merged"
    final_status=1
  fi
  # Preserve the guest's detailed failure and cleanup report before the host
  # publishes its aggregate verdict under the canonical filenames.
  if [[ -f "${run_dir}/RESULT.md" && ! -L "${run_dir}/RESULT.md" ]]; then
    copy_tree_no_follow "${run_dir}/RESULT.md" "${run_dir}/guest-RESULT.md" \
      || final_status=1
  fi
  if [[ -f "${run_dir}/status.env" && ! -L "${run_dir}/status.env" ]]; then
    copy_tree_no_follow "${run_dir}/status.env" "${run_dir}/guest-status.env" \
      || final_status=1
  fi
  local sealed_guest_status=0 parsed_guest_test parsed_guest_cleanup
  if [[ -f "${run_dir}/status.env" && ! -L "${run_dir}/status.env" ]] \
    && awk '
      NR == 1 && $0 !~ /^test_status=(valid|failed)$/ { exit 1 }
      NR == 2 && $0 !~ /^cleanup_status=(valid|failed)$/ { exit 1 }
      NR == 3 && $0 != "scope=synthetic_orbstack_ipv4_tunnel_ipv6_block_netns_only" {
        exit 1
      }
      NR == 4 && $0 != "field_evidence=false" { exit 1 }
      END { if (NR != 4) exit 1 }
    ' "${run_dir}/status.env" \
    && (cd -- "${run_dir}" && sha256sum -c checksums.sha256 >/dev/null); then
    parsed_guest_test="$(source_archive_field \
      "${run_dir}/status.env" test_status)" || parsed_guest_test=""
    parsed_guest_cleanup="$(source_archive_field \
      "${run_dir}/status.env" cleanup_status)" || parsed_guest_cleanup=""
    if [[ ( "${parsed_guest_test}" == valid \
          || "${parsed_guest_test}" == failed ) \
        && ( "${parsed_guest_cleanup}" == valid \
          || "${parsed_guest_cleanup}" == failed ) \
        && ( ( "${guest_status}" == 0 \
              && "${parsed_guest_test}" == valid \
              && "${parsed_guest_cleanup}" == valid ) \
          || ( "${guest_status}" != 0 \
              && ( "${parsed_guest_test}" == failed \
                || "${parsed_guest_cleanup}" == failed ) ) ) ]]; then
      sealed_guest_status=1
      guest_test_status="${parsed_guest_test}"
      guest_cleanup_status="${parsed_guest_cleanup}"
    fi
  fi
  if (( sealed_guest_status == 0 )); then
    warn "guest published malformed, inconsistent, or unsealed evidence"
    final_status=1
    guest_test_status=failed
    guest_cleanup_status=failed
  elif (( guest_status == 0 )); then
    guest_result_valid=1
  else
    final_status="${guest_status}"
  fi
  capture_git_checkout_proof "${repo_root}" \
    "${host_artifacts}/git-checkout-final" "${pinned_head}" \
    || die 1 "host checkout or pushed origin/main changed during the full-TUN experiment"
  host_cleanup
}

# ----------------------------- guest implementation -------------------------

guest_test_failed=0
guest_failures=""
guest_cleanup_failed=0
guest_cleanup_notes=""
guest_result_dir=""
guest_work_dir=""
guest_user=""
guest_run_id=""
guest_registry=""
guest_ns_dir=""
guest_link_dir=""
guest_before_dir=""
guest_after_dir=""
guest_result_owner_token=""
guest_work_owner_file=""
guest_sequence=0
guest_cut_installed=0
guest_cleanup_started=0
LAST_PID=""
LAST_RECORD=""

record_failure() {
  local message="$*"
  guest_test_failed=1
  guest_failures+="${message}"$'\n'
  printf 'FAIL: %s\n' "${message}" >&2
}

cleanup_note() {
  guest_cleanup_failed=1
  guest_cleanup_notes+="$*"$'\n'
  printf 'CLEANUP-FAIL: %s\n' "$*" >&2
}

guest_result_owned() {
  local owner_file expected actual result_root
  [[ -n "${guest_result_dir}" && -n "${guest_run_id}" \
    && -n "${guest_result_owner_token}" ]] || return 1
  owner_file="${guest_result_dir}/.shadowpipe-full-tun-owner"
  [[ -d "${guest_result_dir}" && ! -L "${guest_result_dir}" \
    && -f "${owner_file}" && ! -L "${owner_file}" ]] || return 1
  result_root="$(cd -- "$(dirname -- "${guest_result_dir}")" 2>/dev/null && pwd -P)" \
    || return 1
  actual="$(cd -- "${guest_result_dir}" 2>/dev/null && pwd -P)" || return 1
  [[ "${actual}" == "${result_root}/${guest_run_id}" ]] || return 1
  expected="$(printf 'shadowpipe-full-tun-result-owner-v1\nrun_id=%s\nclone_vm=%s\ntoken=%s\n' \
    "${guest_run_id}" "${ZATMENIE_EXPECTED_DISPOSABLE_VM:-}" \
    "${guest_result_owner_token}")"
  [[ "$(<"${owner_file}")" == "${expected}" ]]
}

guest_work_owned() {
  local actual expected
  [[ -n "${guest_work_dir}" && -n "${guest_work_owner_file}" \
    && -d "${guest_work_dir}" && ! -L "${guest_work_dir}" \
    && -f "${guest_work_owner_file}" && ! -L "${guest_work_owner_file}" ]] \
    || return 1
  actual="$(cd -- "${guest_work_dir}" 2>/dev/null && pwd -P)" || return 1
  [[ "${actual}" == "${guest_work_dir}" ]] || return 1
  expected="$(printf 'shadowpipe-full-tun-work-owner-v1\nrun_id=%s\ntoken=%s\n' \
    "${guest_run_id}" "${guest_result_owner_token}")"
  [[ "$(<"${guest_work_owner_file}")" == "${expected}" ]]
}

proc_starttime() {
  local pid="$1" line rest
  local -a fields
  [[ "${pid}" =~ ^[0-9]+$ && -r "/proc/${pid}/stat" ]] || return 1
  IFS= read -r line <"/proc/${pid}/stat" || return 1
  rest="${line##*) }"
  read -r -a fields <<<"${rest}"
  [[ "${#fields[@]}" -ge 20 && "${fields[19]}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${fields[19]}"
}

extract_log_suffix() {
  local log="$1" prior_lines="$2" output="$3"
  python3 -I -S - "${log}" "${prior_lines}" "${output}" <<'PY'
import os
import stat
import sys

source, prior_text, destination = sys.argv[1:]
prior = int(prior_text, 10)
if prior < 0:
    raise SystemExit("negative log line boundary")
info = os.lstat(source)
if (
    not stat.S_ISREG(info.st_mode)
    or info.st_nlink != 1
    or info.st_size > 16 * 1024 * 1024
):
    raise SystemExit("log suffix source metadata is unsafe")
with open(source, "r", encoding="utf-8", errors="strict", newline="") as stream:
    lines = stream.readlines()
if prior > len(lines):
    raise SystemExit("log line boundary exceeds the current log")
with open(destination, "x", encoding="utf-8", newline="") as stream:
    stream.writelines(lines[prior:])
PY
}

validate_exact_network_restart_suffix() {
  local suffix="$1" expected="$2" output="$3"
  python3 -I -S - "${suffix}" "${expected}" "${output}" <<'PY'
import os
import re
import stat
import sys

source, expected, destination = sys.argv[1:]
if re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", expected) is None:
    raise SystemExit("unsafe expected network restart cause")
info = os.lstat(source)
if (
    not stat.S_ISREG(info.st_mode)
    or info.st_nlink != 1
    or info.st_size <= 0
    or info.st_size > 16 * 1024 * 1024
):
    raise SystemExit("network restart log suffix metadata is unsafe")
with open(source, "r", encoding="utf-8", errors="strict", newline="") as stream:
    text = stream.read()
causes = re.findall(
    r"topology changed at network-event generation [1-9][0-9]* \(([^)]*)\)",
    text,
)
if not causes or any(cause != expected for cause in causes):
    raise SystemExit(f"network restart causes are not exactly {expected}: {causes!r}")
with open(destination, "x", encoding="ascii", newline="\n") as stream:
    stream.write(f"network_restart_cause={expected}\n")
    stream.write(f"cause_occurrences={len(causes)}\n")
PY
}

pidfd_signal() {
  local pid="$1" expected_start="$2" signal_name="$3"
  python3 - "${pid}" "${expected_start}" "${signal_name}" <<'PY'
import errno
import os
import signal
import sys

pid = int(sys.argv[1])
expected = sys.argv[2]
sig = getattr(signal, sys.argv[3])
try:
    fd = os.pidfd_open(pid)
except ProcessLookupError:
    raise SystemExit(4)
with os.fdopen(fd):
    try:
        line = open(f"/proc/{pid}/stat", "r", encoding="ascii").read()
    except FileNotFoundError:
        raise SystemExit(4)
    fields = line[line.rfind(") ") + 2:].split()
    if len(fields) < 20 or fields[19] != expected:
        raise SystemExit(3)
    try:
        signal.pidfd_send_signal(fd, sig)
    except ProcessLookupError:
        raise SystemExit(4)
PY
}

start_owned() {
  local role="$1" log="$2"
  shift 2
  [[ "${role}" =~ ^[a-zA-Z0-9._-]+$ ]] || return 1
  guest_sequence=$((guest_sequence + 1))
  local record
  record="${guest_registry}/$(printf '%04d' "${guest_sequence}")-${role}.owner"
  setsid "$@" >"${log}" 2>&1 &
  local pid=$!
  sleep 0.08
  local start
  start="$(proc_starttime "${pid}")" || {
    wait "${pid}" 2>/dev/null || true
    return 1
  }
  printf '%s %s %s\n' "${pid}" "${start}" "${role}" >"${record}"
  LAST_PID="${pid}"
  LAST_RECORD="${record}"
}

stop_record() {
  local record="$1"
  [[ -f "${record}" ]] || return 0
  local pid start role extra
  read -r pid start role extra <"${record}" || return 1
  [[ -z "${extra:-}" && "${pid}" =~ ^[0-9]+$ && "${start}" =~ ^[0-9]+$ \
    && "${role}" =~ ^[a-zA-Z0-9._-]+$ ]] || return 1

  local current
  if current="$(proc_starttime "${pid}" 2>/dev/null)"; then
    [[ "${current}" == "${start}" ]] || return 1
    pidfd_signal "${pid}" "${start}" SIGTERM || return 1
    local i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
      proc_starttime "${pid}" >/dev/null 2>&1 || break
      sleep 0.1
    done
    if current="$(proc_starttime "${pid}" 2>/dev/null)"; then
      [[ "${current}" == "${start}" ]] || return 1
      pidfd_signal "${pid}" "${start}" SIGKILL || return 1
    fi
  fi
  wait "${pid}" 2>/dev/null || true
  rm -f -- "${record}"
}

stop_role_record() {
  local record="$1"
  stop_record "${record}" || {
    cleanup_note "could not stop registered owner ${record##*/}"
    return 1
  }
}

stop_all_owned() {
  local record
  while IFS= read -r record; do
    [[ -n "${record}" ]] || continue
    stop_role_record "${record}" || true
  done < <(find "${guest_registry}" -maxdepth 1 -type f -name '*.owner' -print | sort -r)
}

capture_ns_identity() {
  local ns="$1" inode
  inode="$(stat -Lc '%i' "/run/netns/${ns}")" || return 1
  [[ "${inode}" =~ ^[0-9]+$ ]] || return 1
  printf '%s %s\n' "${ns}" "${inode}" >"${guest_ns_dir}/${ns}.identity"
}

verify_ns_identity() {
  local ns="$1" rec_name rec_inode extra current
  [[ -f "${guest_ns_dir}/${ns}.identity" ]] || return 1
  read -r rec_name rec_inode extra <"${guest_ns_dir}/${ns}.identity" || return 1
  [[ -z "${extra:-}" && "${rec_name}" == "${ns}" && "${rec_inode}" =~ ^[0-9]+$ ]] \
    || return 1
  current="$(stat -Lc '%i' "/run/netns/${ns}" 2>/dev/null)" || return 1
  [[ "${current}" == "${rec_inode}" ]]
}

capture_root_link_identity() {
  local link="$1" alias="$2" ifindex current_alias
  ifindex="$(<"/sys/class/net/${link}/ifindex")" || return 1
  current_alias="$(<"/sys/class/net/${link}/ifalias")" || return 1
  [[ "${current_alias}" == "${alias}" && "${ifindex}" =~ ^[0-9]+$ ]] || return 1
  printf '%s %s %s\n' "${link}" "${ifindex}" "${alias}" \
    >"${guest_link_dir}/${link}.identity"
}

verify_root_link_identity() {
  local link="$1" rec_link rec_index rec_alias extra cur_index cur_alias
  [[ -f "${guest_link_dir}/${link}.identity" ]] || return 1
  read -r rec_link rec_index rec_alias extra <"${guest_link_dir}/${link}.identity" || return 1
  [[ -z "${extra:-}" && "${rec_link}" == "${link}" && "${rec_index}" =~ ^[0-9]+$ ]] \
    || return 1
  cur_index="$(<"/sys/class/net/${link}/ifindex")" || return 1
  cur_alias="$(<"/sys/class/net/${link}/ifalias")" || return 1
  [[ "${cur_index}" == "${rec_index}" && "${cur_alias}" == "${rec_alias}" ]]
}

snapshot_guest_root() {
  local out="$1"
  mkdir -p -- "${out}"
  ip -j link show | jq -S . >"${out}/links.json"
  # Remove time-varying lifetime/cache fields and sort before comparing. DHCP/RA
  # expiry countdowns are not route mutations by this runner.
  ip -j route show table all | jq -S '
    map(del(.expires, .used, .age, .cache))
    | sort_by([(.table // "" | tostring), (.dst // ""), (.gateway // ""),
               (.dev // ""), (.protocol // "" | tostring),
               (.scope // ""), (.type // ""), (.metric // 0)])
  ' >"${out}/routes.json"
  tc -j qdisc show | jq -S . >"${out}/qdisc.json"
  nft list ruleset >"${out}/nft.txt"
  iptables-save >"${out}/iptables.txt"
  ip6tables-save >"${out}/ip6tables.txt"
  sha256sum /etc/resolv.conf >"${out}/resolv.sha256"
}

compare_guest_root() {
  local status=0 name
  for name in links.json routes.json qdisc.json nft.txt iptables.txt ip6tables.txt \
    resolv.sha256; do
    if [[ "$(sha256sum "${guest_before_dir}/${name}" 2>/dev/null | awk '{print $1}')" \
      != "$(sha256sum "${guest_after_dir}/${name}" 2>/dev/null | awk '{print $1}')" ]]; then
      cleanup_note "guest root snapshot changed: ${name}"
      status=1
    fi
  done
  return "${status}"
}

named_namespace_pids_absent() {
  local record ns inode extra pids status=0
  for record in "${guest_ns_dir}"/*.identity; do
    [[ -e "${record}" ]] || continue
    read -r ns inode extra <"${record}" || { status=1; continue; }
    [[ -z "${extra:-}" ]] || { status=1; continue; }
    if [[ -e "/run/netns/${ns}" ]]; then
      pids="$(ip netns pids "${ns}")" || { status=1; continue; }
      if [[ -n "${pids}" ]]; then
        cleanup_note "namespace ${ns} still has PIDs: ${pids//$'\n'/,}"
        status=1
      fi
    fi
  done
  return "${status}"
}

read_proc_symlink() {
  local path="$1" output
  if output="$(LC_ALL=C readlink "${path}" 2>&1)"; then
    printf '%s\n' "${output}"
    return 0
  fi
  # procfs can return ENOENT without a diagnostic while the magic symlink is
  # still lstat-visible (an exiting task has cleared nsproxy). Classify the
  # actual errno on a retry instead of parsing coreutils text.
  python3 -I -S - "${path}" 2>&1 <<'PY'
import errno
import os
import sys

try:
    print(os.readlink(sys.argv[1]))
except OSError as error:
    if error.errno in (errno.ENOENT, errno.ESRCH):
        raise SystemExit(2)
    name = errno.errorcode.get(error.errno, f"ERRNO_{error.errno}")
    print(f"{name}: {error.strerror}")
    raise SystemExit(1)
PY
}

scan_namespace_references() {
  local phase="$1" record ns inode extra proc task path target fd read_status
  local status=0
  for record in "${guest_ns_dir}"/*.identity; do
    [[ -e "${record}" ]] || continue
    read -r ns inode extra <"${record}" || { status=1; continue; }
    [[ -z "${extra:-}" && "${inode}" =~ ^[0-9]+$ ]] || { status=1; continue; }
    for proc in /proc/[0-9]*; do
      [[ -d "${proc}" ]] || continue
      for task in "${proc}"/task/[0-9]*; do
        [[ -d "${task}" ]] || continue
        for path in "${task}/ns/net" "${task}/ns/net_for_children"; do
          [[ -L "${path}" ]] || continue
          if target="$(read_proc_symlink "${path}")"; then
            :
          else
            read_status=$?
            if (( read_status == 2 )); then
              continue
            fi
            cleanup_note "${phase}: unreadable live namespace path: ${path}: ${target}"
            status=1
            continue
          fi
          if [[ "${target}" == "net:[${inode}]" ]]; then
            cleanup_note "${phase}: process namespace ref remains: ${path}"
            status=1
          fi
        done
        for fd in "${task}"/fd/*; do
          [[ -L "${fd}" ]] || continue
          if target="$(read_proc_symlink "${fd}")"; then
            :
          else
            read_status=$?
            if (( read_status == 2 )); then
              continue
            fi
            cleanup_note "${phase}: unreadable live namespace fd: ${fd}: ${target}"
            status=1
            continue
          fi
          if [[ "${target}" == "net:[${inode}]" ]]; then
            cleanup_note "${phase}: namespace fd remains: ${fd}"
            status=1
          fi
        done
      done
    done
    if [[ "${phase}" == "postdelete" && -e "/run/netns/${ns}" ]]; then
      cleanup_note "namespace mount remains after deletion: ${ns}"
      status=1
    fi
  done
  return "${status}"
}

delete_owned_namespaces() {
  local record ns inode extra status=0
  for record in "${guest_ns_dir}"/*.identity; do
    [[ -e "${record}" ]] || continue
    read -r ns inode extra <"${record}" || { status=1; continue; }
    [[ -z "${extra:-}" ]] || { status=1; continue; }
    [[ -e "/run/netns/${ns}" ]] || continue
    if ! verify_ns_identity "${ns}"; then
      cleanup_note "namespace identity mismatch: ${ns}"
      status=1
    elif ! ip netns del "${ns}"; then
      cleanup_note "failed to delete namespace: ${ns}"
      status=1
    fi
  done
  return "${status}"
}

delete_owned_root_links() {
  local record link rec_index rec_alias extra status=0
  for record in "${guest_link_dir}"/*.identity; do
    [[ -e "${record}" ]] || continue
    read -r link rec_index rec_alias extra <"${record}" || { status=1; continue; }
    [[ -z "${extra:-}" ]] || { status=1; continue; }
    [[ -e "/sys/class/net/${link}" ]] || continue
    if ! verify_root_link_identity "${link}"; then
      cleanup_note "root veth identity mismatch: ${link}"
      status=1
    elif ! ip link del "${link}"; then
      cleanup_note "failed to delete owned root veth: ${link}"
      status=1
    fi
  done
  return "${status}"
}

write_guest_result() {
  local status_word="VALID_CANDIDATE"
  (( guest_test_failed == 0 && guest_cleanup_failed == 0 )) || status_word="FAIL"
  {
    printf '# OrbStack isolated OS-TUN result\n\n'
    printf -- "- Run: \`%s\`\n" "${guest_run_id}"
    printf -- '- Scope: disposable OrbStack Linux clone, private netns only\n'
    printf -- '- Guest phase: **%s** (not a final host verdict)\n' "${status_word}"
    printf -- '- macOS host safety: evaluated after guest teardown; see status.env and mac-before/mac-after\n'
    printf -- '- Loaded macOS PF runtime rules: guest does not inspect them; host records either exact read-only state or exact permission-denied scope\n'
    if [[ "${status_word}" == VALID_CANDIDATE ]]; then
      printf -- '- Secret handling: credentials, allowlist, ML-KEM/REALITY identities and synthetic-cover private key stayed in the owned /run work tree and were excluded from evidence\n'
      printf -- '- IPv6: connected c0/c1 canaries stayed enabled; bound attempts were blocked at OUTPUT and directional captures contained no client-originated IPv6. IPv6 is not tunneled and no inbound/L2/ARP/ND claim is made\n'
      printf -- '- Carrier/authentication: production REALITY TLS 1.3 exact URI + X25519 short-id + ML-KEM pin, then protocol-v3 credential and enrolled allowlist\n'
      printf -- '- Active probe: bounded stock-TLS forward-on-fail to a synthetic local cover, with zero inner sessions before authenticated-client start; no wider indistinguishability claim\n'
      printf -- '- Handoff: a real c0-to-c1 default-route replacement produced the exact DefaultRouteChanged cause, forced generation 1 into a strictly verified durable L3/OUTPUT lockdown, then generation 2 adopted it and activated through c1 before release\n'
      printf -- '- Observer regression: a real promiscuous packet capture toggled IFF_PROMISC without replacing generation 2\n'
      printf -- '- Shutdown: a live generation 2 received the manager-gated SIGTERM, armed the durable L3/OUTPUT restart barrier, then explicit release restored c1 direct routing without generation 3\n'
      printf -- '- Workload gates: foreign persistent named-TUN exclusion, two-generation handoff, ICMP, TCP, UDP, DNS, 64 MiB SHA, cut/recovery, active IPv4/IPv6 leak probes and c0/c1 packet captures\n'
    else
      printf -- '- No secret-handling, handoff, shutdown, IPv6, observer-regression, functional-workload, or leak-proof PASS claim is made for this failed guest phase\n'
    fi
    printf "\n## Test failures\n\n\`\`\`text\n%s\n\`\`\`\n" \
      "${guest_failures:-<none>}"
    printf "\n## Cleanup failures\n\n\`\`\`text\n%s\n\`\`\`\n" \
      "${guest_cleanup_notes:-<none>}"
  } >"${guest_result_dir}/RESULT.md"
  {
    printf 'test_status=%s\n' \
      "$([[ "${status_word}" == VALID_CANDIDATE ]] && echo valid || echo failed)"
    if (( guest_cleanup_failed == 0 )); then
      printf 'cleanup_status=valid\n'
    else
      printf 'cleanup_status=failed\n'
    fi
    printf 'scope=synthetic_orbstack_ipv4_tunnel_ipv6_block_netns_only\n'
    printf 'field_evidence=false\n'
  } >"${guest_result_dir}/status.env"
}

guest_cleanup() {
  local incoming=$?
  (( guest_cleanup_started == 0 )) || exit "${incoming}"
  guest_cleanup_started=1
  trap - EXIT INT TERM HUP
  set +e
  (( incoming == 0 )) || record_failure "runner exited with status ${incoming}"

  if (( guest_cut_installed != 0 )) && [[ -n "${ns_router:-}" ]] \
    && [[ -e "/run/netns/${ns_router}" ]]; then
    ip netns exec "${ns_router}" nft delete table inet sptun_cut >/dev/null 2>&1 \
      || cleanup_note "could not remove owned carrier-cut nft table"
    guest_cut_installed=0
  fi

  stop_all_owned
  named_namespace_pids_absent || true

  local allow_delete=1
  (( guest_cleanup_failed == 0 )) || allow_delete=0
  if (( allow_delete != 0 )); then
    scan_namespace_references predelete || allow_delete=0
  fi
  if (( allow_delete != 0 )); then
    delete_owned_namespaces || allow_delete=0
  else
    cleanup_note "namespace deletion withheld; disposable VM destruction is required"
  fi
  delete_owned_root_links || true
  scan_namespace_references postdelete || true

  if [[ -n "${guest_after_dir}" && -n "${guest_before_dir}" ]]; then
    snapshot_guest_root "${guest_after_dir}" || cleanup_note "final guest-root snapshot failed"
    compare_guest_root || true
  fi

  if [[ -n "${guest_work_dir}" ]]; then
    if guest_work_owned; then
      if scan_cleanup_private_material "${guest_result_dir}" "${guest_work_dir}" \
        "${guest_result_dir}/reality-replay-store-stage.env" \
        "${guest_result_dir}/private-material-stage.env" \
        "${guest_result_dir}/.private-material-fingerprints" \
        "${guest_result_dir}/private-material-leak-paths.txt" 0 0; then
        : >"${guest_result_dir}/private-material-scan.ok"
      else
        cleanup_note \
          "private-material evidence scan or replay-store stage validation failed"
      fi
      rm -rf -- "${guest_work_dir}" \
        || cleanup_note "could not remove exact owned guest work directory"
    else
      cleanup_note "guest work ownership changed; refusing recursive deletion"
    fi
  fi
  if guest_result_owned; then
    # Credentials, enrollment material, and the server allowlist live only in
    # the separately owned /run work directory. Never admit those basenames to
    # the evidence tree even if a future edit accidentally copies one.
    if find "${guest_result_dir}" -type f \
      \( -name client-credential.json -o -name client-enrollment.json \
        -o -name client-allowlist.json -o -name keys.json \
        -o -name reality.key -o -name reality-short-ids \
        -o -name reality-replay-v1.bin -o -name reality-replay-v1.bin.lock \
        -o -name reality-uri -o -name reality-uri-missing-pin \
        -o -name cover.key \) \
      -print -quit | grep -q .; then
      cleanup_note "secret key or authentication material appeared in the evidence tree"
    fi
    write_guest_result
    if ! seal_evidence "${guest_result_dir}"; then
      cleanup_note "could not seal guest evidence checksums"
      # Rewrite the verdict after recording the sealing failure, then make one
      # best-effort final seal so a failed run still carries auditable evidence.
      write_guest_result
      seal_evidence "${guest_result_dir}" || true
    fi
  else
    guest_cleanup_failed=1
    warn "result ownership changed; refusing all guest result-path writes"
  fi

  local final=0
  (( guest_test_failed == 0 && guest_cleanup_failed == 0 )) || final=1
  exit "${final}"
}

wait_until() {
  local seconds="$1"
  shift
  local i
  for ((i = 0; i < seconds * 10; i++)); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

pcap_has() {
  local pcap="$1" filter="$2"
  tcpdump -nn -r "${pcap}" -c 1 "${filter}" 2>/dev/null | grep -q .
}

validate_pcap_file() {
  local pcap="$1"
  [[ -f "${pcap}" && ! -L "${pcap}" && -s "${pcap}" ]] || return 1
  tcpdump -nn -r "${pcap}" -w /dev/null >/dev/null 2>&1
}

capture_has_zero_kernel_drops() {
  local log="$1"
  grep -Eq '^[[:space:]]*0 packets dropped by kernel$' "${log}"
}

start_direct_canary_loop() {
  local role="$1" interface="$2" family="$3" address="$4" log="$5"
  [[ "${family}" == 4 || "${family}" == 6 ]] || return 1
  # Positional parameters intentionally expand in the namespace-local shell.
  # shellcheck disable=SC2016
  start_owned "${role}" "${log}" \
    ip netns exec "${ns_client}" bash -c '
      set -Eeuo pipefail
      interface="$1"
      family="$2"
      address="$3"
      sequence=0
      trap "exit 0" TERM INT HUP
      while :; do
        sequence=$((sequence + 1))
        printf "attempt sequence=%s realtime_ns=%s interface=%s family=%s address=%s\n" \
          "${sequence}" "$(date +%s%N)" "${interface}" "${family}" "${address}"
        status=blocked
        if [[ "${family}" == 6 ]]; then
          if ping -6 -I "${interface}" -c 1 -W 1 "${address}" \
            >/dev/null 2>&1; then
            status=success
          fi
        elif ping -I "${interface}" -c 1 -W 1 "${address}" \
          >/dev/null 2>&1; then
          status=success
        fi
        printf "result sequence=%s realtime_ns=%s interface=%s family=%s address=%s status=%s\n" \
          "${sequence}" "$(date +%s%N)" "${interface}" "${family}" \
          "${address}" "${status}"
        sleep 0.05
      done
    ' bash "${interface}" "${family}" "${address}"
}

direct_canary_result_count() {
  local log="$1"
  awk '/^result / { count += 1 } END { print count + 0 }' "${log}"
}

direct_canary_count_exceeds() {
  local log="$1" baseline="$2" current
  current="$(direct_canary_result_count "${log}")" || return 1
  [[ "${current}" =~ ^[0-9]+$ ]] || return 1
  (( current > baseline ))
}

capture_ipv6_canary_state() {
  local phase="$1"
  local output="${guest_result_dir}/ipv6-canary-state-${phase}"
  mkdir -m 0700 -- "${output}"
  ip -n "${ns_client}" -j link show dev c0 \
    | jq -S 'map({
        ifindex,
        ifname,
        flags: ((.flags // []) | sort),
        mtu,
        operstate,
        link_type,
        address,
        broadcast
      })' >"${output}/c0-link.json"
  ip -n "${ns_client}" -j link show dev c1 \
    | jq -S 'map({
        ifindex,
        ifname,
        flags: ((.flags // []) | sort),
        mtu,
        operstate,
        link_type,
        address,
        broadcast
      })' >"${output}/c1-link.json"
  ip -n "${ns_client}" -j -6 address show dev c0 \
    | jq -S 'map({
        ifindex,
        ifname,
        flags: ((.flags // []) | sort),
        mtu,
        operstate,
        addr_info: [
          (.addr_info // [])[] | {
            family,
            local,
            prefixlen,
            scope,
            label,
            flags: ((.flags // []) | sort)
          }
        ] | sort_by([.family, .local, .prefixlen, .scope, (.label // "")])
      })' >"${output}/c0-address.json"
  ip -n "${ns_client}" -j -6 address show dev c1 \
    | jq -S 'map({
        ifindex,
        ifname,
        flags: ((.flags // []) | sort),
        mtu,
        operstate,
        addr_info: [
          (.addr_info // [])[] | {
            family,
            local,
            prefixlen,
            scope,
            label,
            flags: ((.flags // []) | sort)
          }
        ] | sort_by([.family, .local, .prefixlen, .scope, (.label // "")])
      })' >"${output}/c1-address.json"
  ip -n "${ns_client}" -j -6 route show table main \
    | jq -S '[
        .[] | select(.dev == "c0" or .dev == "c1") | {
          dst,
          dev,
          protocol,
          scope,
          metric,
          pref,
          flags: ((.flags // []) | sort)
        }
      ] | sort_by([.dev, .dst, (.protocol // ""), (.scope // "")])' \
    >"${output}/routes.json"
}

require_ipv6_canary_state_unchanged() {
  local phase="$1" name
  capture_ipv6_canary_state "${phase}" || return 1
  for name in c0-link.json c1-link.json c0-address.json c1-address.json routes.json; do
    cmp -s -- \
      "${guest_result_dir}/ipv6-canary-state-preflight/${name}" \
      "${guest_result_dir}/ipv6-canary-state-${phase}/${name}" \
      || return 1
  done
}

validate_client_private_uri_argv() {
  local pid="$1" uri_file="$2" short_id_file="$3"
  python3 -I -S - "${pid}" "${uri_file}" "${short_id_file}" <<'PY'
import os
import sys

pid, uri_file, short_id_file = sys.argv[1:]
with open(short_id_file, "r", encoding="ascii") as stream:
    short_id = stream.read().strip()
with open(f"/proc/{pid}/cmdline", "rb") as stream:
    argv = [
        item.decode("utf-8", "strict")
        for item in stream.read().split(b"\0")
        if item
    ]
if any("shadowpipe://" in item or short_id in item for item in argv):
    raise SystemExit("client argv contains a REALITY URI or short_id")
if argv.count("--uri-file") != 1 or "--uri" in argv:
    raise SystemExit("client argv does not use exactly one --uri-file")
index = argv.index("--uri-file")
if index + 1 >= len(argv) or argv[index + 1] != uri_file:
    raise SystemExit("client argv does not bind the expected private URI path")
PY
}

probe_direct_canaries_blocked() {
  local phase="$1" address evidence_name
  local ipv4_blocked=true ipv6_blocked=true
  for address in 10.231.0.1 10.233.0.1; do
    if timeout 3 ip netns exec "${ns_client}" ping -c 1 -W 1 \
      "${address}" >/dev/null 2>&1; then
      ipv4_blocked=false
      record_failure "${phase}: direct IPv4 canary ${address} escaped"
    fi
  done
  for address in 2001:db8:231::1 2001:db8:233::1; do
    if timeout 3 ip netns exec "${ns_client}" ping -6 -c 1 -W 1 \
      "${address}" >/dev/null 2>&1; then
      ipv6_blocked=false
      record_failure "${phase}: direct IPv6 canary ${address} escaped"
    fi
  done
  # Preserve the phase in evidence without allowing it to become a path.
  evidence_name="${phase//[^a-zA-Z0-9._-]/_}"
  printf 'ipv4_canaries_blocked=%s\nipv6_canaries_blocked=%s\n' \
    "${ipv4_blocked}" "${ipv6_blocked}" \
    >"${guest_result_dir}/direct-canaries-${evidence_name}.env"
}

exclusive_tun_collision_failure() {
  local status="$1" stderr_file="$2"
  [[ "${status}" =~ ^[0-9]+$ ]] || return 1
  (( status != 0 && status != 124 && status != 137 && status != 143 )) \
    || return 1
  grep -Eiq \
    '(Device or resource busy|File exists)[[:space:]]+\(os error (16|17)\)|(^|[^[:alnum:]_])E(BUSY|EXIST)([^[:alnum:]_]|$)' \
    "${stderr_file}"
}

capture_preexisting_tun_state() {
  local namespace="$1" prefix="$2"
  LC_ALL=C ip -n "${namespace}" -details -j address show dev sptunc \
    | jq -S '
      map(
        if has("addr_info") then
          .addr_info |= sort_by([
            (.family // ""), (.local // ""), (.prefixlen // 0),
            (.scope // ""), (.label // "")
          ])
        else
          .
        end
      )
    ' >"${prefix}.link.json"
  LC_ALL=C ip -n "${namespace}" -details tuntap show dev sptunc \
    >"${prefix}.tuntap.txt"
  # The single-quoted program is evaluated by the namespace-local Bash.
  # shellcheck disable=SC2016
  ip netns exec "${namespace}" bash -ceu \
    'IFS= read -r value </sys/class/net/sptunc/ifalias || :; printf "%s\n" "${value:-}"' \
    >"${prefix}.alias.txt"
  LC_ALL=C ip -n "${namespace}" -j -4 route show table all protocol 186 \
    | jq -S 'sort_by([(.table // 254 | tostring), (.dst // ""),
                       (.gateway // ""), (.dev // ""), (.metric // 0)])' \
    >"${prefix}.routes-v4-proto-186.json"
  LC_ALL=C ip -n "${namespace}" -j -6 route show table all protocol 186 \
    | jq -S 'sort_by([(.table // 254 | tostring), (.dst // ""),
                       (.gateway // ""), (.dev // ""), (.metric // 0)])' \
    >"${prefix}.routes-v6-proto-186.json"
  ip netns exec "${namespace}" iptables-save \
    | awk '
        /^:SP4_[0-9a-f]{20}[[:space:]]/
        /(^|[[:space:]])-j SP4_[0-9a-f]{20}([[:space:]]|$)/
        /shadowpipe:[0-9a-f]{32}/
      ' >"${prefix}.sp4.txt"
  ip netns exec "${namespace}" ip6tables-save \
    | awk '
        /^:SP6_[0-9a-f]{20}[[:space:]]/
        /(^|[[:space:]])-j SP6_[0-9a-f]{20}([[:space:]]|$)/
        /shadowpipe:[0-9a-f]{32}/
      ' >"${prefix}.sp6.txt"
}

evidence_has_private_material() {
  local evidence_root="$1" fingerprints="$2" expected_uid="$3" expected_gid="$4"
  shift 4
  # Inspect bytes, not filenames: a future regression that copies a credential
  # under an innocuous name must still fail the lab. Only uniformly random
  # secret fields are needles; public keys, key ids and fingerprints remain
  # admissible evidence. The scanner never prints a secret value.
  python3 -I -S - "${evidence_root}" "${fingerprints}" "${expected_uid}" \
    "${expected_gid}" "$@" <<'PY'
import base64
import hashlib
import json
import os
import stat
import sys

evidence_root, fingerprint_path, expected_uid_text, expected_gid_text, *specs = (
    sys.argv[1:]
)
expected_uid = int(expected_uid_text, 10)
expected_gid = int(expected_gid_text, 10)
if min(expected_uid, expected_gid) < 0 or len(specs) % 2 != 0:
    raise SystemExit("invalid private-material scanner invocation")
needles = []

def add_secret_variants(value):
    if len(value) < 8:
        raise SystemExit("private material is unexpectedly short")
    variants = {value, value.lower(), value.upper()}
    stripped = value.strip()
    if len(stripped) >= 8:
        variants.update((stripped, stripped.lower(), stripped.upper()))
        try:
            decoded = bytes.fromhex(stripped.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            decoded = b""
        if decoded:
            variants.add(decoded)
            for encoder in (base64.b64encode, base64.urlsafe_b64encode):
                transformed = encoder(decoded)
                variants.update((transformed, transformed.rstrip(b"=")))
    needles.extend(item for item in variants if len(item) >= 8)

def safe_private_source(path):
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_uid != expected_uid
        or before.st_gid != expected_gid
        or before.st_nlink != 1
        or before.st_size > 64 * 1024 * 1024
    ):
        raise SystemExit("private-material source metadata is unsafe")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != expected_uid
            or opened.st_gid != expected_gid
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise SystemExit("private-material source raced while opening")
        chunks = []
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > 64 * 1024 * 1024:
                raise SystemExit("private-material source is oversized")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = os.lstat(path)
    stable = (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    )
    if observed != opened.st_size:
        raise SystemExit("private-material source size changed while reading")
    if (
        not stat.S_ISREG(after.st_mode)
        or not stat.S_ISREG(final.st_mode)
        or stat.S_ISLNK(final.st_mode)
        or stat.S_IMODE(after.st_mode) != 0o600
        or stat.S_IMODE(final.st_mode) != 0o600
        or after.st_uid != expected_uid
        or final.st_uid != expected_uid
        or after.st_gid != expected_gid
        or final.st_gid != expected_gid
        or after.st_nlink != 1
        or final.st_nlink != 1
        or (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        != stable
        or (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        )
        != stable
    ):
        raise SystemExit("private-material source changed while reading")
    return b"".join(chunks)

def reject_duplicates(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON member: {key}")
        document[key] = value
    return document

def parse_json_source(path):
    try:
        return json.loads(
            safe_private_source(path).decode("utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit("private JSON source is malformed") from error

def add_json_field(document, field):
    if not isinstance(document, dict):
        raise SystemExit("private JSON source is not an object")
    value = document.get(field)
    if not isinstance(value, str) or len(value) < 32:
        raise SystemExit(f"private field {field} is absent or malformed")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise SystemExit(f"private field {field} is not ASCII") from error
    add_secret_variants(encoded)

for index in range(0, len(specs), 2):
    kind, path = specs[index:index + 2]
    if kind == "credential":
        document = parse_json_source(path)
        add_json_field(document, "ed25519_seed")
        add_json_field(document, "psk")
    elif kind == "server_keys":
        add_json_field(parse_json_source(path), "mlkem_secret")
    elif kind == "enrollment":
        add_json_field(parse_json_source(path), "psk")
    elif kind == "allowlist":
        document = parse_json_source(path)
        clients = document.get("clients") if isinstance(document, dict) else None
        if not isinstance(clients, list) or not clients:
            raise SystemExit("client allowlist has no private entries")
        for client in clients:
            add_json_field(client, "psk")
    elif kind in ("raw", "raw_optional"):
        value = safe_private_source(path)
        if len(value) < 8 and kind == "raw_optional":
            continue
        add_secret_variants(value)
        # A PEM can be reserialized without its armor or line wrapping.
        # Fingerprint the concatenated body and decoded DER as well as the
        # exact source bytes.
        body_lines = [
            line.strip() for line in value.splitlines()
            if line and not line.startswith(b"-----")
        ]
        body = b"".join(body_lines)
        if len(body) >= 8:
            add_secret_variants(body)
            try:
                der = base64.b64decode(body, validate=True)
            except ValueError:
                der = b""
            if len(der) >= 8:
                add_secret_variants(der)
    else:
        raise SystemExit("unknown private-material source kind")

needles = tuple(sorted(set(needles), key=lambda value: (len(value), value)))
if not needles:
    raise SystemExit("no private material sources were available")
overlap = max(map(len, needles)) - 1
leaks = []
requested_root = os.path.abspath(evidence_root)
root_info = os.lstat(requested_root)
if (
    not stat.S_ISDIR(root_info.st_mode)
    or stat.S_ISLNK(root_info.st_mode)
    or os.path.realpath(requested_root) != requested_root
):
    raise SystemExit("evidence root is not a canonical real directory")
for directory, directories, files in os.walk(requested_root, followlinks=False):
    directories.sort()
    files.sort()
    safe_directories = []
    for name in list(directories):
        path = os.path.join(directory, name)
        info = os.lstat(path)
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            safe_directories.append(name)
        else:
            leaks.append(
                os.path.relpath(path, requested_root) + " (unsafe subtree)"
            )
    directories[:] = safe_directories
    for name in files:
        path = os.path.join(directory, name)
        relative = os.path.relpath(path, requested_root)
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
        ):
            leaks.append(relative + " (unsafe file)")
            continue
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(path, flags)
        except OSError:
            leaks.append(relative + " (open raced)")
            continue
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino)
                != (before.st_dev, before.st_ino)
            ):
                leaks.append(relative + " (identity raced)")
                continue
            tail = b""
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                window = tail + chunk
                if any(needle in window for needle in needles):
                    leaks.append(relative)
                    break
                tail = window[-overlap:]
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        final = os.lstat(path)
        stable = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if (
            after.st_nlink != 1
            or final.st_nlink != 1
            or not stat.S_ISREG(final.st_mode)
            or stat.S_ISLNK(final.st_mode)
            or (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            != stable
            or (
                final.st_dev,
                final.st_ino,
                final.st_size,
                final.st_mtime_ns,
                final.st_ctime_ns,
            )
            != stable
        ):
            leaks.append(relative + " (changed while scanning)")
if leaks:
    for path in sorted(set(leaks)):
        print(path)
    raise SystemExit(1)
records = sorted({(len(needle), hashlib.sha256(needle).hexdigest()) for needle in needles})
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(fingerprint_path, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
    for length, digest in records:
        stream.write(f"{length} {digest}\n")
    stream.flush()
    os.fsync(stream.fileno())
directory = os.open(os.path.dirname(fingerprint_path), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

write_private_material_scan_status() {
  local path="$1" stage="$2" marker="$3" store="$4" lock="$5"
  local sources="$6" stage_requirements="$7" byte_scan="$8" overall="$9"
  python3 -I -S - "${path}" "${stage}" "${marker}" "${store}" "${lock}" \
    "${sources}" "${stage_requirements}" "${byte_scan}" "${overall}" <<'PY'
import os
import re
import sys

(
    path,
    stage,
    marker,
    store,
    lock,
    sources_text,
    stage_requirements,
    byte_scan,
    overall,
) = sys.argv[1:]
values = (stage, marker, store, lock, stage_requirements, byte_scan, overall)
if any(re.fullmatch(r"[a-z0-9_]+", value) is None for value in values):
    raise SystemExit("unsafe private-material status value")
sources = int(sources_text, 10)
if sources < 0:
    raise SystemExit("negative private-material source count")
content = (
    "schema_version=1\n"
    f"replay_store_stage={stage}\n"
    f"replay_store_marker={marker}\n"
    f"replay_store_artifact={store}\n"
    f"replay_store_lock={lock}\n"
    f"private_source_artifacts={sources}\n"
    f"stage_requirements={stage_requirements}\n"
    f"private_material_byte_scan={byte_scan}\n"
    f"private_material_scan={overall}\n"
).encode("ascii")
flags = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
descriptor = os.open(path, flags, 0o600)
try:
    written = 0
    while written < len(content):
        written += os.write(descriptor, content[written:])
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

scan_cleanup_private_material() {
  local evidence_root="$1" work_root="$2" marker_path="$3" status_path="$4"
  local fingerprints="$5" leak_paths="$6" expected_uid="$7" expected_gid="$8"
  local replay_store="${work_root}/reality-replay-v1.bin"
  local replay_lock="${replay_store}.lock"
  local scan_canary="${work_root}/.private-material-scan-canary"
  local replay_stage=not_created_before_failure
  local marker_state=absent replay_state=absent replay_lock_state=absent
  local stage_requirements=valid byte_scan=failed overall=failed
  local source_count=0 index path
  local -a source_specs=()
  local -a candidate_kinds=(
    raw
    credential
    enrollment
    allowlist
    server_keys
    raw
    raw
    raw
    raw
    raw
  )
  local -a candidate_paths=(
    "${scan_canary}"
    "${work_root}/client-credential.json"
    "${work_root}/client-enrollment.json"
    "${work_root}/client-allowlist.json"
    "${work_root}/keys.json"
    "${work_root}/reality.key"
    "${work_root}/reality-short-ids"
    "${work_root}/reality-uri"
    "${work_root}/reality-uri-missing-pin"
    "${work_root}/cover.key"
  )

  if [[ -e "${marker_path}" || -L "${marker_path}" ]]; then
    if validate_replay_store_stage_marker \
      "${marker_path}" "${expected_uid}" "${expected_gid}"; then
      replay_stage=created_and_durably_marked
      marker_state=valid
    else
      replay_stage=invalid_durable_marker
      marker_state=invalid
      stage_requirements=failed
    fi
  fi

  if [[ -e "${replay_store}" || -L "${replay_store}" ]]; then
    if [[ "${marker_state}" == valid ]]; then
      if exact_private_regular_file \
        "${replay_store}" "${expected_uid}" "${expected_gid}" 1572960; then
        replay_state=present_valid
      else
        replay_state=present_unsafe
        stage_requirements=failed
      fi
    elif exact_private_regular_file \
      "${replay_store}" "${expected_uid}" "${expected_gid}" any; then
      replay_state=present_valid
    else
      replay_state=present_unsafe
      stage_requirements=failed
    fi
    source_specs+=(raw_optional "${replay_store}")
    source_count=$((source_count + 1))
  elif [[ "${marker_state}" == valid ]]; then
    replay_state=absent
    stage_requirements=failed
  fi

  if [[ -e "${replay_lock}" || -L "${replay_lock}" ]]; then
    if exact_empty_private_regular_file \
      "${replay_lock}" "${expected_uid}" "${expected_gid}"; then
      replay_lock_state=present_valid
    else
      replay_lock_state=present_unsafe
      stage_requirements=failed
    fi
  elif [[ "${marker_state}" == valid ]]; then
    replay_lock_state=absent
    stage_requirements=failed
  fi

  if [[ "${marker_state}" == absent \
    && ( "${replay_state}" != absent || "${replay_lock_state}" != absent ) ]]; then
    replay_stage=artifacts_present_before_durable_marker
  fi

  for ((index = 0; index < ${#candidate_paths[@]}; index++)); do
    path="${candidate_paths[index]}"
    if [[ -e "${path}" || -L "${path}" ]]; then
      source_specs+=("${candidate_kinds[index]}" "${path}")
      source_count=$((source_count + 1))
    fi
  done
  if [[ ! -e "${scan_canary}" && ! -L "${scan_canary}" ]]; then
    stage_requirements=failed
  fi

  if evidence_has_private_material "${evidence_root}" "${fingerprints}" \
    "${expected_uid}" "${expected_gid}" "${source_specs[@]}" >"${leak_paths}"; then
    byte_scan=valid
    rm -f -- "${leak_paths}"
  else
    byte_scan=failed
  fi
  if [[ "${stage_requirements}" == valid && "${byte_scan}" == valid ]]; then
    overall=valid
  fi
  write_private_material_scan_status "${status_path}" "${replay_stage}" \
    "${marker_state}" "${replay_state}" "${replay_lock_state}" \
    "${source_count}" "${stage_requirements}" "${byte_scan}" "${overall}" \
    || return 1
  [[ "${overall}" == valid ]]
}

guest_main() {
  [[ "$(uname -s)" == "Linux" ]] || die "${EX_USAGE}" "guest mode requires Linux"
  [[ "${EUID}" -eq 0 ]] || die "${EX_NOPERM}" "guest mode requires root"
  [[ "${ZATMENIE_TUN_GUEST:-}" == "1" ]] \
    || die "${EX_USAGE}" "guest mode requires orchestrator attestation"
  [[ "${ZATMENIE_EXPECTED_DISPOSABLE_VM:-}" == sptun-* ]] \
    || die "${EX_USAGE}" "guest is not marked as an explicitly disposable clone"
  [[ "${ZATMENIE_RESULT_OWNER_TOKEN:-}" =~ ^[0-9a-f]{64}$ ]] \
    || die "${EX_USAGE}" "guest result owner token is absent or malformed"
  validate_live_guest_marker "${CLONE_MARKER}" \
    "${ZATMENIE_RESULT_OWNER_TOKEN}" \
    || die "${EX_NOPERM}" \
      "guest clone ownership marker is absent, unsafe, or mismatched"
  [[ "$#" -eq 2 ]] || die "${EX_USAGE}" "guest mode expects RUN_ID and GUEST_USER"

  guest_run_id="$(sanitize_component "$1")" || die "${EX_USAGE}" "unsafe run id"
  guest_user="$(sanitize_component "$2")" || die "${EX_USAGE}" "unsafe guest user"
  guest_result_owner_token="${ZATMENIE_RESULT_OWNER_TOKEN}"
  local magic="${SHADOWPIPE_MAGIC:-}"
  validate_magic "${magic}" \
    || die "${EX_USAGE}" "guest SHADOWPIPE_MAGIC must be one value in the u32 range"
  id "${guest_user}" >/dev/null 2>&1 || die "${EX_UNAVAILABLE}" "guest user does not exist"

  local tool missing_tools=""
  for tool in ip iptables iptables-save ip6tables ip6tables-save nft tc tcpdump \
    ss ping curl iperf3 openssl python3 getent jq sha256sum timeout unshare \
    nsenter flock setsid mount \
    stat readlink sysctl find sort mktemp mv rm chown grep awk sed tr wc dd date; do
    command -v "${tool}" >/dev/null || missing_tools+="${tool} "
  done
  [[ -z "${missing_tools}" ]] \
    || die "${EX_UNAVAILABLE}" "missing guest dependencies (no installs allowed): ${missing_tools% }"
  [[ -c /dev/net/tun ]] || die "${EX_UNAVAILABLE}" "/dev/net/tun is unavailable"
  grep -qw overlay /proc/filesystems \
    || die "${EX_UNAVAILABLE}" "overlayfs is required for mount-private resolver testing"
  python3 - <<'PY' || die "${EX_UNAVAILABLE}" "Python pidfd support is required"
import os, signal
assert hasattr(os, "pidfd_open")
assert hasattr(signal, "pidfd_send_signal")
PY

  exec 9>/run/lock/shadowpipe-full-tun.lock
  flock -n 9 || die 75 "another full-TUN lab is active"
  if ip netns list | awk '$1 ~ /^spt[crsi]-/ { found=1 } END { exit !found }'; then
    die 75 "stale spt* lab namespace exists in disposable VM"
  fi

  local guest_script_dir guest_repo_root target_dir client server
  guest_script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
  guest_repo_root="$(cd -- "${guest_script_dir}/../.." && pwd -P)"
  target_dir="${guest_repo_root}/target/full-tun-lab-${guest_run_id}/release"
  client="${target_dir}/shadowpipe-client"
  server="${target_dir}/shadowpipe-server"
  [[ -x "${client}" && -x "${server}" ]] \
    || die "${EX_UNAVAILABLE}" "expected native release binaries are missing"

  guest_result_dir="${guest_script_dir}/results/${guest_run_id}"
  guest_work_dir="/run/shadowpipe-full-tun-${guest_run_id}"
  guest_result_owned \
    || die "${EX_USAGE}" "reserved result directory ownership is absent or inconsistent"
  if find "${guest_result_dir}" -mindepth 1 -maxdepth 1 \
    ! -name .shadowpipe-full-tun-owner -print -quit | grep -q .; then
    die "${EX_USAGE}" "reserved result directory is not empty"
  fi
  [[ ! -e "${guest_work_dir}" && ! -L "${guest_work_dir}" ]] \
    || die "${EX_USAGE}" "guest work path collision: ${guest_work_dir}"
  mkdir -m 0700 -- "${guest_work_dir}"
  guest_work_dir="$(cd -- "${guest_work_dir}" && pwd -P)"
  guest_work_owner_file="${guest_work_dir}/.shadowpipe-full-tun-owner"
  python3 -I -S - "${guest_work_owner_file}" "${guest_run_id}" \
    "${guest_result_owner_token}" <<'PY'
import os
import sys
path, run_id, token = sys.argv[1:]
data = (
    f"shadowpipe-full-tun-work-owner-v1\nrun_id={run_id}\ntoken={token}\n"
).encode("ascii")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags, 0o600)
try:
    os.write(descriptor, data)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  guest_work_owned || die 1 "could not establish exact guest work ownership"
  create_private_material_scan_canary \
    "${guest_work_dir}/.private-material-scan-canary" \
    || die 1 "could not create the private-material scan canary"
  exact_private_regular_file \
    "${guest_work_dir}/.private-material-scan-canary" 0 0 32 \
    || die 1 "private-material scan canary lacks exact root-private safety"
  guest_registry="${guest_result_dir}/owned-processes"
  guest_ns_dir="${guest_result_dir}/namespace-identities"
  guest_link_dir="${guest_result_dir}/root-link-identities"
  guest_before_dir="${guest_result_dir}/guest-root-before"
  guest_after_dir="${guest_result_dir}/guest-root-after"
  mkdir -m 0700 -- "${guest_registry}" "${guest_ns_dir}" "${guest_link_dir}" \
    "${guest_before_dir}" "${guest_after_dir}"
  cp -- "$0" "${guest_result_dir}/runner.sh"
  sha256sum "${client}" "${server}" >"${guest_result_dir}/binary-sha256.txt"
  printf 'SHADOWPIPE_MAGIC=%s\n' "${magic}" \
    >"${guest_result_dir}/build-contract.txt"
  snapshot_guest_root "${guest_before_dir}"

  trap guest_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP

  local tag owner_alias
  tag="$(printf '%06x' "$$")"
  tag="${tag: -6}"
  ns_client="sptc-${tag}"
  ns_router="sptr-${tag}"
  ns_server="spts-${tag}"
  ns_sink="spti-${tag}"
  local lc="zc${tag}a" lr="zc${tag}b"
  local lc1="zd${tag}a" lr2="zd${tag}b"
  local rs="zs${tag}a" ls="zs${tag}b"
  local se="ze${tag}a" si="ze${tag}b"

  local ns
  for ns in "${ns_client}" "${ns_router}" "${ns_server}" "${ns_sink}"; do
    ip netns add "${ns}"
    capture_ns_identity "${ns}" || die 1 "could not capture namespace identity: ${ns}"
  done

  ip link add "${lc}" type veth peer name "${lr}"
  ip link add "${lc1}" type veth peer name "${lr2}"
  ip link add "${rs}" type veth peer name "${ls}"
  ip link add "${se}" type veth peer name "${si}"
  local link
  for link in "${lc}" "${lr}" "${lc1}" "${lr2}" \
    "${rs}" "${ls}" "${se}" "${si}"; do
    owner_alias="shadowpipe-tun:${guest_run_id}:${link}"
    ip link set dev "${link}" alias "${owner_alias}"
    capture_root_link_identity "${link}" "${owner_alias}" \
      || die 1 "could not capture root-link identity: ${link}"
  done

  ip link set "${lc}" netns "${ns_client}"
  ip link set "${lr}" netns "${ns_router}"
  ip link set "${lc1}" netns "${ns_client}"
  ip link set "${lr2}" netns "${ns_router}"
  ip link set "${rs}" netns "${ns_router}"
  ip link set "${ls}" netns "${ns_server}"
  ip link set "${se}" netns "${ns_server}"
  ip link set "${si}" netns "${ns_sink}"
  ip -n "${ns_client}" link set "${lc}" name c0
  ip -n "${ns_router}" link set "${lr}" name r0
  ip -n "${ns_client}" link set "${lc1}" name c1
  ip -n "${ns_router}" link set "${lr2}" name r2
  ip -n "${ns_router}" link set "${rs}" name r1
  ip -n "${ns_server}" link set "${ls}" name s0
  ip -n "${ns_server}" link set "${se}" name e0
  ip -n "${ns_sink}" link set "${si}" name i0

  for ns in "${ns_client}" "${ns_router}" "${ns_server}" "${ns_sink}"; do
    ip -n "${ns}" link set lo up
  done
  ip -n "${ns_client}" addr add 10.231.0.2/30 dev c0
  ip -n "${ns_client}" addr add 2001:db8:231::2/64 dev c0 nodad
  ip -n "${ns_client}" link set c0 up
  ip -n "${ns_client}" addr add 10.233.0.2/30 dev c1
  ip -n "${ns_client}" addr add 2001:db8:233::2/64 dev c1 nodad
  ip -n "${ns_client}" link set c1 up
  ip -n "${ns_client}" route add default via 10.231.0.1
  ip -n "${ns_router}" addr add 10.231.0.1/30 dev r0
  ip -n "${ns_router}" addr add 2001:db8:231::1/64 dev r0 nodad
  ip -n "${ns_router}" addr add 10.233.0.1/30 dev r2
  ip -n "${ns_router}" addr add 2001:db8:233::1/64 dev r2 nodad
  ip -n "${ns_router}" addr add 10.232.0.1/30 dev r1
  ip -n "${ns_router}" link set r0 up
  ip -n "${ns_router}" link set r2 up
  ip -n "${ns_router}" link set r1 up
  ip netns exec "${ns_router}" sysctl -qw net.ipv4.ip_forward=1
  ip -n "${ns_server}" addr add 10.232.0.2/30 dev s0
  ip -n "${ns_server}" addr add 198.18.0.1/30 dev e0
  ip -n "${ns_server}" link set s0 up
  ip -n "${ns_server}" link set e0 up
  ip -n "${ns_server}" route add default via 10.232.0.1
  ip netns exec "${ns_server}" sysctl -qw net.ipv4.ip_forward=1
  ip -n "${ns_sink}" addr add 198.18.0.2/30 dev i0
  ip -n "${ns_sink}" link set i0 up
  ip -n "${ns_sink}" route add 10.8.0.0/24 via 198.18.0.1

  ip netns exec "${ns_client}" ping -c 2 -W 1 10.232.0.2 \
    >"${guest_result_dir}/underlay-preflight.txt"
  ip netns exec "${ns_client}" ping -c 1 -W 1 10.231.0.1 \
    >"${guest_result_dir}/c0-ipv4-canary-preflight.txt"
  ip netns exec "${ns_client}" ping -c 1 -W 1 10.233.0.1 \
    >"${guest_result_dir}/c1-ipv4-canary-preflight.txt"
  ip netns exec "${ns_client}" ping -6 -c 1 -W 1 2001:db8:231::1 \
    >"${guest_result_dir}/c0-ipv6-canary-preflight.txt"
  ip netns exec "${ns_client}" ping -6 -c 1 -W 1 2001:db8:233::1 \
    >"${guest_result_dir}/c1-ipv6-canary-preflight.txt"
  ip -n "${ns_client}" -6 route show \
    >"${guest_result_dir}/client-ipv6-connected-routes.txt"
  grep -q '^2001:db8:231::/64 dev c0' \
    "${guest_result_dir}/client-ipv6-connected-routes.txt" \
    || die 1 "c0 connected IPv6 canary route is absent"
  grep -q '^2001:db8:233::/64 dev c1' \
    "${guest_result_dir}/client-ipv6-connected-routes.txt" \
    || die 1 "c1 connected IPv6 canary route is absent"
  capture_ipv6_canary_state preflight \
    || die 1 "could not capture the preflight IPv6 canary state"
  if ip netns exec "${ns_client}" ping -c 1 -W 1 198.18.0.2 >/dev/null 2>&1; then
    die 1 "sink is reachable before the tunnel; topology is invalid"
  fi

  local marker payload health source_sha download_sha fp
  local client_credential client_enrollment client_allowlist client_host_state main_wal
  local reality_key reality_public reality_short_id reality_short_id_file
  local reality_replay_store reality_replay_stage_marker
  local reality_uri reality_uri_file missing_pin_uri missing_pin_uri_file uri_output
  local cover_key cover_cert
  client_credential="${guest_work_dir}/client-credential.json"
  client_enrollment="${guest_work_dir}/client-enrollment.json"
  client_allowlist="${guest_work_dir}/client-allowlist.json"
  client_host_state="${guest_work_dir}/client-host-state"
  main_wal="${client_host_state}/host-state-v2.json"
  reality_key="${guest_work_dir}/reality.key"
  reality_short_id_file="${guest_work_dir}/reality-short-ids"
  reality_replay_store="${guest_work_dir}/reality-replay-v1.bin"
  reality_replay_stage_marker="${guest_result_dir}/reality-replay-store-stage.env"
  reality_uri_file="${guest_work_dir}/reality-uri"
  missing_pin_uri_file="${guest_work_dir}/reality-uri-missing-pin"
  cover_key="${guest_work_dir}/cover.key"
  cover_cert="${guest_work_dir}/cover.crt"

  # Provision mandatory protocol-v3 identity entirely inside the owned /run
  # work directory. The enrollment file and allowlist both contain the PSK and
  # are secret too; none of these three files is copied or hashed into evidence.
  fp="$(${server} --gen-keys --keys "${guest_work_dir}/keys.json" 2>/dev/null \
    | awk '$1 == "server-fp:" { print $2 }')"
  [[ "${fp}" =~ ^[0-9a-f]{64}$ ]] || die 1 "failed to generate server fingerprint"
  reality_public="$(${server} --gen-reality-key --reality-key "${reality_key}" \
    2>/dev/null | awk '$1 == "reality-pubkey:" { print $2 }')"
  [[ "${reality_public}" =~ ^[0-9a-f]{64}$ ]] \
    || die 1 "failed to generate REALITY public identity"
  python3 -I -S - "${reality_short_id_file}" <<'PY'
import os
import sys
path = sys.argv[1]
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
    stream.write(os.urandom(8).hex() + "\n")
    stream.flush()
    os.fsync(stream.fileno())
directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
  reality_short_id="$(<"${reality_short_id_file}")"
  [[ "${reality_short_id}" =~ ^[0-9a-f]{16}$ ]] \
    || die 1 "generated REALITY short-id file is not one full-width token"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj '/CN=198.18.0.2' -addext 'subjectAltName=IP:198.18.0.2' \
    -keyout "${cover_key}" -out "${cover_cert}" >/dev/null 2>&1 \
    || die 1 "failed to provision bounded synthetic TLS cover"
  uri_output="$(${server} --print-uri --reality \
    --advertise 10.232.0.2:47843 --keys "${guest_work_dir}/keys.json" \
    --reality-key "${reality_key}" \
    --reality-short-id-file "${reality_short_id_file}" \
    --cover 198.18.0.2:443 --no-cover-profile 2>/dev/null)"
  reality_uri="$(awk '$1 == "reality-uri:" { print $2 }' <<<"${uri_output}")"
  [[ "${reality_uri}" == \
    "shadowpipe://${reality_public}@10.232.0.2:47843?sni=198.18.0.2&sid=${reality_short_id}&fp=${fp}" ]] \
    || die 1 "generated REALITY URI does not exactly bind endpoint, SNI, short-id and ML-KEM pin"
  [[ "${uri_output}" == \
    "reality-pubkey: ${reality_public}"$'\n'"reality-uri: ${reality_uri}" ]] \
    || die 1 "REALITY URI one-shot output line census is not exact"
  # Keep the carrier selector out of every client argv. Bash builtins publish
  # both strict root-only files without passing their contents to a child
  # process; the missing-pin variant is a bounded negative preflight fixture.
  ( umask 077; set -C; printf '%s\n' "${reality_uri}" >"${reality_uri_file}" ) \
    || die 1 "failed to create private client REALITY URI file"
  missing_pin_uri="${reality_uri%&fp=*}"
  [[ "${missing_pin_uri}" != "${reality_uri}" ]] \
    || die 1 "could not derive the missing-pin URI preflight fixture"
  ( umask 077; set -C; printf '%s\n' "${missing_pin_uri}" \
      >"${missing_pin_uri_file}" ) \
    || die 1 "failed to create private missing-pin URI file"
  unset reality_uri missing_pin_uri uri_output
  {
    printf 'uri_generated_and_exactly_validated=true\n'
    printf 'client_uri_source=root_owned_0600_single_link_file\n'
    printf 'client_argv_contains_uri_or_short_id=false\n'
    printf 'short_id_source=root_owned_0600_single_link_file\n'
    printf 'short_id_value_published=false\n'
    printf 'mlkem_pin_in_uri=true\n'
  } >"${guest_result_dir}/reality-endpoint-contract.env"
  "${client}" --generate-client-credential \
    --client-credential "${client_credential}" \
    --write-client-enrollment "${client_enrollment}" >/dev/null
  "${server}" --client-allowlist "${client_allowlist}" \
    --enroll-client "${client_enrollment}" >/dev/null
  local auth_file auth_metadata
  : >"${guest_result_dir}/authentication-file-safety.txt"
  for auth_file in "${client_credential}" "${client_enrollment}" \
    "${client_allowlist}" "${guest_work_dir}/keys.json" "${reality_key}" \
    "${reality_short_id_file}" "${reality_uri_file}" \
    "${missing_pin_uri_file}" "${cover_key}" "${cover_cert}"; do
    auth_metadata="$(LC_ALL=C stat -c '%a:%u:%g:%h:%F' "${auth_file}")" \
      || die 1 "could not inspect mandatory auth artifact"
    [[ "${auth_metadata}" == "600:0:0:1:regular file" ]] \
      || die 1 "mandatory auth artifact lacks exact root:root 0600 single-link safety"
    printf '%s %s\n' "${auth_file##*/}" "${auth_metadata}" \
      >>"${guest_result_dir}/authentication-file-safety.txt"
  done
  mkdir -m 0700 -- "${client_host_state}"
  [[ "$(LC_ALL=C stat -c '%a:%u:%g:%F' "${client_host_state}")" \
    == "700:0:0:directory" ]] \
    || die 1 "client host-state directory lacks exact root:root 0700 safety"

  # Missing client credentials must fail after the valid server pin preflight,
  # but before host-state creation, socket I/O, or TUN creation.
  start_owned missing-credential-capture \
    "${guest_result_dir}/missing-credential-capture.log" \
    ip netns exec "${ns_client}" tcpdump -p -Q out -U -nn -i c0 -w \
    "${guest_result_dir}/missing-credential-underlay.pcap" ip
  local missing_credential_capture_record="${LAST_RECORD}"
  sleep 0.25
  local missing_credential_state="${guest_work_dir}/missing-credential-host-state"
  set +e
  ip netns exec "${ns_client}" "${client}" --uri-file "${reality_uri_file}" \
    --client-credential "${guest_work_dir}/does-not-exist-client-credential.json" \
    --host-state-dir "${missing_credential_state}" \
    --tunnel --tun-name sptunc --ipv6-mode block \
    --auto-route --kill-switch --dns 198.18.0.2 \
    >"${guest_result_dir}/missing-credential.stdout" \
    2>"${guest_result_dir}/missing-credential.stderr"
  local missing_credential_status=$?
  set -e
  stop_role_record "${missing_credential_capture_record}" || true
  validate_pcap_file "${guest_result_dir}/missing-credential-underlay.pcap" \
    || die 1 "missing-credential pcap is missing, unreadable, or malformed"
  (( missing_credential_status != 0 )) \
    || die 1 "missing client credential invocation unexpectedly succeeded"
  grep -Fq 'load mandatory root-owned client credential before startup' \
    "${guest_result_dir}/missing-credential.stderr" \
    || die 1 "missing client credential did not report its credential preflight"
  [[ ! -e "${missing_credential_state}" && ! -L "${missing_credential_state}" ]] \
    || die 1 "missing client credential created host state"
  if ip -n "${ns_client}" link show sptunc >/dev/null 2>&1; then
    die 1 "missing client credential created a TUN"
  fi
  if pcap_has "${guest_result_dir}/missing-credential-underlay.pcap" ip; then
    die 1 "missing client credential emitted an underlay packet"
  fi
  capture_has_zero_kernel_drops \
    "${guest_result_dir}/missing-credential-capture.log" \
    || die 1 "missing-credential negative capture dropped packets"

  # Missing server identity is isolated from missing client identity by passing
  # the valid credential. It must still fail before credential/host-state use,
  # socket I/O, and TUN creation.
  start_owned missing-pin-capture "${guest_result_dir}/missing-pin-capture.log" \
    ip netns exec "${ns_client}" tcpdump -p -Q out -U -nn -i c0 -w \
    "${guest_result_dir}/missing-pin-underlay.pcap" ip
  local missing_capture_record="${LAST_RECORD}"
  sleep 0.25
  local missing_pin_state="${guest_work_dir}/missing-pin-host-state"
  set +e
  ip netns exec "${ns_client}" "${client}" --uri-file "${missing_pin_uri_file}" \
    --client-credential "${client_credential}" \
    --host-state-dir "${missing_pin_state}" \
    --tunnel --tun-name sptunc --ipv6-mode block \
    --auto-route --kill-switch --dns 198.18.0.2 \
    >"${guest_result_dir}/missing-pin.stdout" \
    2>"${guest_result_dir}/missing-pin.stderr"
  local missing_status=$?
  set -e
  stop_role_record "${missing_capture_record}" || true
  validate_pcap_file "${guest_result_dir}/missing-pin-underlay.pcap" \
    || die 1 "missing-pin pcap is missing, unreadable, or malformed"
  (( missing_status != 0 )) || die 1 "missing pin invocation unexpectedly succeeded"
  grep -Fq 'manual REALITY URI requires fp=<64-hex ML-KEM server fingerprint>' \
    "${guest_result_dir}/missing-pin.stderr" \
    || die 1 "missing pin did not report the authentication preflight"
  [[ ! -e "${missing_pin_state}" && ! -L "${missing_pin_state}" ]] \
    || die 1 "missing pin created host state"
  if ip -n "${ns_client}" link show sptunc >/dev/null 2>&1; then
    die 1 "missing pin created a TUN"
  fi
  if pcap_has "${guest_result_dir}/missing-pin-underlay.pcap" ip; then
    die 1 "missing pin emitted an underlay packet"
  fi
  capture_has_zero_kernel_drops "${guest_result_dir}/missing-pin-capture.log" \
    || die 1 "missing-pin negative capture dropped packets"

  # A fixed client TUN name is create-only authority, never attach authority.
  # Plant a persistent foreign TUN with an empty alias and a distinctive,
  # already-live configuration. A fully valid client invocation must fail at
  # the atomic IFF_TUN_EXCL ioctl before it can mutate the link, publish a TUN
  # resource, stage DNS/firewall/routes, or emit even one carrier packet.
  local collision_state collision_work collision_before collision_after
  collision_state="${guest_work_dir}/preexisting-tun-host-state"
  collision_work="${guest_work_dir}/preexisting-tun"
  collision_before="${guest_result_dir}/preexisting-tun-before"
  collision_after="${guest_result_dir}/preexisting-tun-after"
  mkdir -m 0700 -- "${collision_state}" "${collision_work}"
  mkdir -m 0700 -- "${collision_work}/etc-upper" \
    "${collision_work}/etc-work" "${collision_work}/etc-merged"
  ip -n "${ns_client}" tuntap add dev sptunc mode tun
  ip -n "${ns_client}" link set dev sptunc mtu 1421
  ip -n "${ns_client}" address add 192.0.2.77/32 dev sptunc
  ip -n "${ns_client}" link set dev sptunc up
  capture_preexisting_tun_state "${ns_client}" "${collision_before}"
  grep -Eq '^sptunc: tun .*persist' "${collision_before}.tuntap.txt" \
    || die 1 "pre-existing TUN fixture is not persistent"
  [[ -z "$(<"${collision_before}.alias.txt")" ]] \
    || die 1 "pre-existing TUN fixture unexpectedly has an alias"
  jq -e 'length == 1
    and .[0].ifname == "sptunc"
    and .[0].mtu == 1421
    and ((.[0].ifalias // "") == "")
    and any(.[0].addr_info[];
      .family == "inet" and .local == "192.0.2.77" and .prefixlen == 32)' \
    "${collision_before}.link.json" >/dev/null \
    || die 1 "pre-existing TUN fixture lacks its exact distinctive state"
  jq -e 'length == 0' "${collision_before}.routes-v4-proto-186.json" \
    >/dev/null || die 1 "pre-existing TUN fixture started with an IPv4 proto-186 route"
  jq -e 'length == 0' "${collision_before}.routes-v6-proto-186.json" \
    >/dev/null || die 1 "pre-existing TUN fixture started with an IPv6 proto-186 route"
  [[ ! -s "${collision_before}.sp4.txt" \
    && ! -s "${collision_before}.sp6.txt" ]] \
    || die 1 "pre-existing TUN fixture started with a Shadowpipe firewall object"

  start_owned preexisting-tun-capture \
    "${guest_result_dir}/preexisting-tun-capture.log" \
    ip netns exec "${ns_client}" tcpdump -p -Q out --immediate-mode -U -nn -i c0 \
    -w "${guest_result_dir}/preexisting-tun-underlay.pcap" ip
  local collision_capture_record="${LAST_RECORD}"
  sleep 0.25
  local collision_start_ns collision_end_ns collision_elapsed_ms
  local collision_status collision_census
  collision_start_ns="$(date +%s%N)"
  set +e
  # Positional parameters intentionally expand only in the mount-isolated
  # wrapper. The endpoint and credential are both valid, so the named-TUN
  # collision is the first expected startup failure.
  # shellcheck disable=SC2016
  timeout -k 2 8 ip netns exec "${ns_client}" \
    unshare --mount --propagation private bash -c '
      set -Eeuo pipefail
      client="$1"
      endpoint_file="$2"
      work="$3"
      credential="$4"
      host_state="$5"
      mount -t overlay overlay \
        -o "lowerdir=/etc,upperdir=${work}/etc-upper,workdir=${work}/etc-work" \
        "${work}/etc-merged"
      mount --bind "${work}/etc-merged" /etc
      snapshot_resolver() {
        local prefix="$1"
        stat -c "%F:%a:%u:%g:%h" /etc/resolv.conf >"${work}/${prefix}.lstat"
        readlink /etc/resolv.conf >"${work}/${prefix}.target" 2>/dev/null || :
        sha256sum /etc/resolv.conf >"${work}/${prefix}.sha256"
      }
      snapshot_resolver resolver-before
      set +e
      env -u SSH_CONNECTION -u SSH_CLIENT LC_ALL=C RUST_LOG=info "${client}" \
        --uri-file "${endpoint_file}" \
        --client-credential "${credential}" --host-state-dir "${host_state}" \
        --tunnel --tun-name sptunc --tun-addr 10.8.0.2 --tun-peer 10.8.0.1 \
        --mtu 1280 --ipv6-mode block --auto-route --kill-switch \
        --dns 198.18.0.2 --no-guard
      status=$?
      set -e
      snapshot_resolver resolver-after
      printf "%s\n" "${status}" >"${work}/client-exit-status"
      exit "${status}"
    ' bash "${client}" "${reality_uri_file}" "${collision_work}" \
    "${client_credential}" "${collision_state}" \
    >"${guest_result_dir}/preexisting-tun.stdout" \
    2>"${guest_result_dir}/preexisting-tun.stderr"
  collision_status=$?
  set -e
  collision_end_ns="$(date +%s%N)"
  collision_elapsed_ms=$(((collision_end_ns - collision_start_ns) / 1000000))
  stop_role_record "${collision_capture_record}" || true
  validate_pcap_file "${guest_result_dir}/preexisting-tun-underlay.pcap" \
    || die 1 "preexisting-TUN pcap is missing, unreadable, or malformed"

  exclusive_tun_collision_failure \
    "${collision_status}" "${guest_result_dir}/preexisting-tun.stderr" \
    || die 1 "valid client did not fail closed with EBUSY/EEXIST on the foreign named TUN"
  (( collision_elapsed_ms < 8000 )) \
    || die 1 "foreign named-TUN collision did not fail within the bounded startup window"
  grep -qx "${collision_status}" "${collision_work}/client-exit-status" \
    || die 1 "mount wrapper did not preserve the named-TUN collision status"
  capture_preexisting_tun_state "${ns_client}" "${collision_after}"
  local collision_component
  for collision_component in link.json tuntap.txt alias.txt \
    routes-v4-proto-186.json routes-v6-proto-186.json sp4.txt sp6.txt; do
    exact_files_equal "${collision_before}.${collision_component}" \
      "${collision_after}.${collision_component}" \
      || die 1 "foreign TUN collision changed ${collision_component}"
  done
  [[ -z "$(<"${collision_after}.alias.txt")" ]] \
    || die 1 "foreign empty-alias TUN was claimed by the client"
  jq -e 'length == 0' "${collision_after}.routes-v4-proto-186.json" \
    >/dev/null || die 1 "foreign TUN collision left an IPv4 proto-186 route"
  jq -e 'length == 0' "${collision_after}.routes-v6-proto-186.json" \
    >/dev/null || die 1 "foreign TUN collision left an IPv6 proto-186 route"
  [[ ! -s "${collision_after}.sp4.txt" \
    && ! -s "${collision_after}.sp6.txt" ]] \
    || die 1 "foreign TUN collision left a Shadowpipe firewall chain or jump"
  for collision_component in lstat target sha256; do
    exact_files_equal "${collision_work}/resolver-before.${collision_component}" \
      "${collision_work}/resolver-after.${collision_component}" \
      || die 1 "foreign TUN collision changed mount-private resolv.conf"
  done
  if pcap_has "${guest_result_dir}/preexisting-tun-underlay.pcap" \
    'host 10.232.0.2 and tcp port 47843'; then
    die 1 "foreign TUN collision emitted a carrier packet"
  fi
  if pcap_has "${guest_result_dir}/preexisting-tun-underlay.pcap" ip; then
    die 1 "foreign TUN collision emitted an underlay IPv4 packet"
  fi
  capture_has_zero_kernel_drops \
    "${guest_result_dir}/preexisting-tun-capture.log" \
    || die 1 "foreign TUN collision negative capture dropped packets"
  [[ ! -e "${collision_state}/host-state-v2.json" \
    && ! -L "${collision_state}/host-state-v2.json" ]] \
    || die 1 "foreign TUN collision left an empty main host-state WAL"
  [[ ! -e "${collision_state}/handoff-lockdown-v1.json" \
    && ! -L "${collision_state}/handoff-lockdown-v1.json" ]] \
    || die 1 "foreign TUN collision armed an unexpected restart lockdown"
  exact_empty_private_regular_file "${collision_state}/host.lock" 0 0 \
    || die 1 "foreign TUN collision left an unsafe singleton lease file"
  find "${collision_state}" -mindepth 1 -maxdepth 1 -printf '%f\n' \
    | LC_ALL=C sort >"${guest_result_dir}/preexisting-tun-state-census.txt"
  collision_census="$(<"${guest_result_dir}/preexisting-tun-state-census.txt")"
  [[ "${collision_census}" == host.lock ]] \
    || die 1 "foreign TUN collision left a journal temp or unexpected host-state artifact"
  {
    printf 'fixture=persistent_empty_alias_sptunc\n'
    printf 'client_exit_status=%s\n' "${collision_status}"
    printf 'elapsed_ms=%s\n' "${collision_elapsed_ms}"
    printf 'exclusive_collision_errno=EBUSY_or_EEXIST\n'
    printf 'foreign_link_exactly_unchanged=true\n'
    printf 'foreign_alias_remained_empty=true\n'
    printf 'proto_186_routes=0\n'
    printf 'shadowpipe_firewall_chains_or_jumps=0\n'
    printf 'resolver_exactly_unchanged=true\n'
    printf 'underlay_ipv4_packets=0\n'
    printf 'carrier_packets=0\n'
    printf 'main_wal_after_failure=absent\n'
  } >"${guest_result_dir}/preexisting-tun-collision.env"
  ip -n "${ns_client}" tuntap del dev sptunc mode tun
  if ip -n "${ns_client}" link show dev sptunc >/dev/null 2>&1; then
    die 1 "could not remove the owned pre-existing TUN fixture"
  fi

  marker="SPTUN_SYNTHETIC_${guest_run_id}"
  payload="${guest_work_dir}/payload.bin"
  health="${guest_work_dir}/health.txt"
  python3 - "${payload}" "${marker}" <<'PY'
import sys
path, marker = sys.argv[1:]
target = 64 * 1024 * 1024
chunk = (marker + "\n").encode()
block_size = 1024 * 1024
block = (chunk * (block_size // len(chunk) + 1))[:block_size]
with open(path, "wb") as f:
    left = target
    while left:
        part = block[:left]
        f.write(part)
        left -= len(part)
PY
  printf '%s\n' "${marker}" >"${health}"
  source_sha="$(sha256sum "${payload}" | awk '{print $1}')"
  printf '%s  payload.bin\n' "${source_sha}" >"${guest_result_dir}/payload-source.sha256"

  # Owned synthetic services. The router canary proves the physical underlay
  # path exists, then must become unreachable once the client kill-switch hooks.
  start_owned router-canary "${guest_result_dir}/router-canary.log" \
    ip netns exec "${ns_router}" python3 -m http.server 18081 \
    --bind 10.231.0.1 --directory "${guest_work_dir}"
  local canary_record="${LAST_RECORD}"
  start_owned sink-http "${guest_result_dir}/sink-http.log" \
    ip netns exec "${ns_sink}" python3 -m http.server 18080 \
    --bind 198.18.0.2 --directory "${guest_work_dir}"
  local http_record="${LAST_RECORD}"
  start_owned sink-iperf "${guest_result_dir}/sink-iperf.log" \
    ip netns exec "${ns_sink}" iperf3 -s -B 198.18.0.2
  local iperf_record="${LAST_RECORD}"
  start_owned sink-dns "${guest_result_dir}/sink-dns.log" \
    ip netns exec "${ns_sink}" python3 -u -c '
import socket
import struct

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("198.18.0.2", 53))
while True:
    data, peer = sock.recvfrom(4096)
    if len(data) < 17:
        continue
    pos = 12
    try:
        while data[pos] != 0:
            pos += data[pos] + 1
        question_end = pos + 5
        question = data[12:question_end]
    except (IndexError, ValueError):
        continue
    header = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) \
        + socket.inet_aton("198.18.0.2")
    sock.sendto(header + question + answer, peer)
    print(f"answered {peer[0]}:{peer[1]}", flush=True)
'
  local dns_record="${LAST_RECORD}"
  start_owned synthetic-cover-tls "${guest_result_dir}/cover-tls.log" \
    ip netns exec "${ns_sink}" openssl s_server \
    -accept 198.18.0.2:443 -cert "${cover_cert}" -key "${cover_key}" \
    -www -tls1_3
  local cover_record="${LAST_RECORD}"

  wait_until 5 ip netns exec "${ns_router}" ss -H -ltn sport = :18081 \
    || die 1 "router canary did not listen"
  wait_until 5 ip netns exec "${ns_sink}" ss -H -ltn sport = :18080 \
    || die 1 "sink HTTP did not listen"
  wait_until 5 ip netns exec "${ns_sink}" ss -H -ltn sport = :5201 \
    || die 1 "sink iperf did not listen"
  wait_until 5 ip netns exec "${ns_sink}" ss -H -lun sport = :53 \
    || die 1 "sink DNS did not listen"
  wait_until 5 ip netns exec "${ns_sink}" ss -H -ltn sport = :443 \
    || die 1 "synthetic TLS cover did not listen"
  timeout 5 ip netns exec "${ns_client}" curl -fsS \
    http://10.231.0.1:18081/health.txt >/dev/null \
    || die 1 "direct underlay canary is not reachable before kill-switch"

  start_owned shadowpipe-server "${guest_result_dir}/server.log" \
    ip netns exec "${ns_server}" env RUST_LOG=info "${server}" \
    --listen 10.232.0.2:47843 --reality --tunnel --tun-name sptuns \
    --tun-addr 10.8.0.1 --tun-peer 10.8.0.2 --mtu 1280 \
    --keys "${guest_work_dir}/keys.json" \
    --reality-key "${reality_key}" \
    --reality-short-id-file "${reality_short_id_file}" \
    --reality-replay-store "${reality_replay_store}" \
    --cover 198.18.0.2:443 --no-cover-profile \
    --client-allowlist "${client_allowlist}" --egress-iface e0
  local server_record="${LAST_RECORD}"
  wait_until 10 ip netns exec "${ns_server}" ip link show sptuns \
    || die 1 "server OS TUN did not appear"
  wait_until 10 ip netns exec "${ns_server}" ss -H -ltn sport = :47843 \
    || die 1 "server carrier did not listen"
  exact_private_regular_file "${reality_replay_store}" 0 0 1572960 \
    || die 1 "REALITY replay store lacks fixed-size root-private durable state"
  exact_empty_private_regular_file "${reality_replay_store}.lock" 0 0 \
    || die 1 "REALITY replay-store exclusive lease file is unsafe"
  publish_replay_store_stage_marker "${reality_replay_stage_marker}" \
    || die 1 "could not durably publish the validated replay-store stage"
  validate_replay_store_stage_marker \
    "${reality_replay_stage_marker}" 0 0 \
    || die 1 "durable replay-store stage marker did not revalidate"

  # A stock TLS client has no REALITY token. It must be spliced to the bounded
  # synthetic cover, while the inner v3/ML-KEM session stays completely absent.
  # This is an active-probe oracle for the production carrier gate, not a broad
  # indistinguishability claim about timing or cross-flow behavior.
  if ! timeout 8 ip netns exec "${ns_client}" curl \
      --noproxy '*' --insecure --fail --silent --show-error --http1.1 \
      --max-time 7 --dump-header \
      "${guest_result_dir}/unauthenticated-reality-probe.headers" \
      --output "${guest_result_dir}/unauthenticated-reality-probe.stdout" \
      https://10.232.0.2:47843/ \
      2>"${guest_result_dir}/unauthenticated-reality-probe.stderr"; then
    die 1 "unauthenticated TLS probe did not complete through the cover"
  fi
  grep -Eq '^HTTP/1\.[01] 200' \
    "${guest_result_dir}/unauthenticated-reality-probe.headers" \
    || die 1 "unauthenticated TLS probe did not receive the cover response"
  [[ -s "${guest_result_dir}/unauthenticated-reality-probe.stdout" ]] \
    || die 1 "unauthenticated TLS probe received an empty cover body"
  wait_until 5 grep -Fq 'reality token not accepted; cover splice established' \
    "${guest_result_dir}/server.log" \
    || die 1 "server did not attest the REALITY forward-on-fail path"
  if grep -q 'session established' "${guest_result_dir}/server.log"; then
    die 1 "unauthenticated REALITY probe reached an inner Shadowpipe session"
  fi
  {
    printf 'carrier=reality_tls13\n'
    printf 'production_gate=true\n'
    printf 'unauthenticated_probe_forwarded=true\n'
    printf 'cover_http_response=true\n'
    printf 'inner_session_count_before_authenticated_client=0\n'
    printf 'claim_scope=bounded_synthetic_forward_on_fail_oracle\n'
  } >"${guest_result_dir}/reality-forward-on-fail.env"

  start_owned underlay-c0-ipv4-capture \
    "${guest_result_dir}/underlay-c0-ipv4-capture.log" \
    ip netns exec "${ns_client}" tcpdump -p -Q out -U -nn -s 192 -i c0 \
    -w "${guest_result_dir}/client-c0-ipv4.pcap" ip
  local underlay_c0_ipv4_capture_record="${LAST_RECORD}"
  start_owned underlay-c1-ipv4-capture \
    "${guest_result_dir}/underlay-c1-ipv4-capture.log" \
    ip netns exec "${ns_client}" tcpdump -p -Q out -U -nn -s 192 -i c1 \
    -w "${guest_result_dir}/client-c1-ipv4.pcap" ip
  local underlay_c1_ipv4_capture_record="${LAST_RECORD}"
  local underlay_c0_ipv6_capture_record underlay_c1_ipv6_capture_record
  start_owned sink-capture "${guest_result_dir}/sink-capture.log" \
    ip netns exec "${ns_sink}" tcpdump -p -Q in -U -nn -s 192 -i i0 \
    -w "${guest_result_dir}/sink-inner.pcap" \
    'src host 10.8.0.2 and (icmp or (tcp dst port 18080 and (tcp[tcpflags] & tcp-syn != 0)) or udp dst port 5201 or udp dst port 53)'
  local sink_capture_record="${LAST_RECORD}"

  mkdir -p -- "${guest_work_dir}/etc-upper" "${guest_work_dir}/etc-work" \
    "${guest_work_dir}/etc-merged"
  # The wrapper constructs an overlay copy of /etc inside its private mount
  # namespace. DnsGuard may unlink/replace resolv.conf without touching the
  # guest root filesystem. SIGTERM reaches the wrapper through a pidfd; the
  # wrapper forwards it to the current client generation and retains the exact
  # mount+network namespaces across one controlled process replacement. The
  # generation-2 gate lets the orchestrator strictly inspect the intermediate
  # restart barrier before emulating systemd Restart=always/RestartSec=1s.
  # Positional parameters intentionally expand in the inner shell.
  # shellcheck disable=SC2016
  start_owned shadowpipe-client "${guest_result_dir}/client.log" \
    ip netns exec "${ns_client}" unshare --mount --propagation private bash -c '
      set -Eeuo pipefail
      client="$1"
      endpoint_file="$2"
      work="$3"
      credential="$4"
      host_state="$5"
      mount -t overlay overlay \
        -o "lowerdir=/etc,upperdir=${work}/etc-upper,workdir=${work}/etc-work" \
        "${work}/etc-merged"
      mount --bind "${work}/etc-merged" /etc
      snapshot_resolver() {
        local prefix="$1"
        stat -Lc "%F" /etc/resolv.conf >"${work}/${prefix}.type"
        stat -c "%F %a %u %g %h %s" /etc/resolv.conf \
          >"${work}/${prefix}.lstat"
        stat -Lc "%F %a %u %g %h %s" /etc/resolv.conf \
          >"${work}/${prefix}.target-stat"
        readlink /etc/resolv.conf >"${work}/${prefix}.target" 2>/dev/null || :
        sha256sum /etc/resolv.conf >"${work}/${prefix}.sha256"
      }
      child_start_ticks() {
        local pid="$1" line rest
        local -a fields
        [[ "${pid}" =~ ^[1-9][0-9]*$ && -r "/proc/${pid}/stat" ]] || return 1
        IFS= read -r line <"/proc/${pid}/stat" || return 1
        rest="${line##*) }"
        read -r -a fields <<<"${rest}"
        [[ "${#fields[@]}" -ge 20 && "${fields[19]}" =~ ^[0-9]+$ ]] \
          || return 1
        printf "%s\n" "${fields[19]}"
      }
      signal_child() {
        local signal_name="$1"
        [[ "${child:-}" =~ ^[1-9][0-9]*$ \
          && "${child_start:-}" =~ ^[0-9]+$ ]] || return 0
        python3 -I -S -c "
import os
import signal
import sys

pid = int(sys.argv[1])
expected = sys.argv[2]
sig = getattr(signal, sys.argv[3])
try:
    descriptor = os.pidfd_open(pid)
except ProcessLookupError:
    raise SystemExit(0)
with os.fdopen(descriptor):
    try:
        line = open(f\"/proc/{pid}/stat\", \"r\", encoding=\"ascii\").read()
    except FileNotFoundError:
        raise SystemExit(0)
    fields = line[line.rfind(\") \") + 2:].split()
    if len(fields) < 20 or fields[19] != expected:
        raise SystemExit(3)
    try:
        signal.pidfd_send_signal(descriptor, sig)
    except ProcessLookupError:
        pass
" "${child}" "${child_start}" "${signal_name}"
      }
      snapshot_resolver resolver-before
      wrapper_stop=0
      child=""
      child_start=""
      forward_term() {
        wrapper_stop=1
        signal_child SIGTERM || :
      }
      trap forward_term TERM INT HUP
      child_status=1
      completed_generations=0
      generation=1
      while :; do
        if (( generation > 1 )); then
          while [[ ! -e "${work}/start-generation-${generation}" \
            && ! -e "${work}/manager-stop" \
            && "${wrapper_stop}" == 0 ]]; do
            sleep 0.1
          done
          [[ ! -e "${work}/manager-stop" && "${wrapper_stop}" == 0 ]] || break
          sleep 1
          [[ ! -e "${work}/manager-stop" && "${wrapper_stop}" == 0 ]] || break
        fi
        env -u SSH_CONNECTION -u SSH_CLIENT RUST_LOG=info "${client}" \
          --uri-file "${endpoint_file}" \
          --client-credential "${credential}" --host-state-dir "${host_state}" \
          --tunnel --tun-name sptunc --tun-addr 10.8.0.2 --tun-peer 10.8.0.1 \
          --mtu 1280 --ipv6-mode block --auto-route --kill-switch \
          --dns 198.18.0.2 --no-guard &
        child=$!
        child_start="$(child_start_ticks "${child}")" || {
          wait "${child}" 2>/dev/null || :
          child=""
          break
        }
        if [[ -e "${work}/manager-stop" || "${wrapper_stop}" != 0 ]]; then
          signal_child SIGTERM || :
        fi
        printf "%s\n" "${child}" >"${work}/client.pid"
        printf "%s\n" "${child}" >"${work}/client-generation-${generation}.pid"
        printf "%s\n" "${child_start}" \
          >"${work}/client-generation-${generation}.start-ticks"
        child_status=0
        while true; do
          set +e
          wait "${child}"
          child_status=$?
          set -e
          current_child_start="$(child_start_ticks "${child}" 2>/dev/null)" \
            || break
          [[ "${current_child_start}" == "${child_start}" ]] || break
        done
        snapshot_resolver "resolver-after-generation-${generation}"
        if [[ "$(<"${work}/resolver-before.type")" \
          == "$(<"${work}/resolver-after-generation-${generation}.type")" \
          && "$(<"${work}/resolver-before.lstat")" \
          == "$(<"${work}/resolver-after-generation-${generation}.lstat")" \
          && "$(<"${work}/resolver-before.target-stat")" \
          == "$(<"${work}/resolver-after-generation-${generation}.target-stat")" \
          && "$(<"${work}/resolver-before.target")" \
          == "$(<"${work}/resolver-after-generation-${generation}.target")" \
          && "$(<"${work}/resolver-before.sha256")" \
          == "$(<"${work}/resolver-after-generation-${generation}.sha256")" ]]; then
          : >"${work}/resolver-restored-generation-${generation}.ok"
        else
          : >"${work}/resolver-restored-generation-${generation}.failed"
        fi
        printf "%s\n" "${child_status}" \
          >"${work}/client-generation-${generation}-exit-status"
        : >"${work}/client-generation-${generation}-stopped.ready"
        completed_generations="${generation}"
        child=""
        child_start=""
        if [[ -e "${work}/manager-stop" || "${wrapper_stop}" != 0 ]]; then
          break
        fi
        generation=$((generation + 1))
      done
      printf "%s\n" "${child_status}" >"${work}/client-exit-status"
      printf "%s\n" "${completed_generations}" \
        >"${work}/client-completed-generations"
      : >"${work}/client-stopped.ready"
      # Keep this exact mount+network namespace alive so the orchestrator can
      # inspect the durable barrier and invoke --release-lockdown against the
      # journal-bound namespace identity. A cleanup signal always breaks the
      # wait, so an interrupted lab cannot strand the wrapper in the clone.
      while [[ ! -e "${work}/wrapper-exit" && "${wrapper_stop}" == 0 ]]; do
        sleep 0.1
      done
      exit "${child_status}"
    ' bash "${client}" "${reality_uri_file}" "${guest_work_dir}" \
    "${client_credential}" "${client_host_state}"
  local client_pid="${LAST_PID}" client_record="${LAST_RECORD}"
  local real_client_pid real_client_starttime

  wait_until 15 ip netns exec "${ns_client}" ip link show sptunc \
    || die 1 "generation-1 client OS TUN did not appear"
  wait_until 5 test -s "${guest_work_dir}/client-generation-1.pid" \
    || die 1 "client wrapper did not publish the generation-1 client PID"
  real_client_pid="$(<"${guest_work_dir}/client-generation-1.pid")"
  [[ "${real_client_pid}" =~ ^[0-9]+$ ]] \
    || die 1 "client wrapper published a malformed generation-1 PID"
  real_client_starttime="$(proc_starttime "${real_client_pid}")" \
    || die 1 "could not bind the generation-1 client PID to its start time"
  validate_client_private_uri_argv "${real_client_pid}" \
    "${reality_uri_file}" "${reality_short_id_file}" \
    || die 1 "generation-1 client argv did not preserve the private URI boundary"
  wait_until 15 grep -q 'session established' "${guest_result_dir}/server.log" \
    || die 1 "authenticated session did not establish"
  grep -q 'reality token accepted; carrier established; awaiting v3 device proof' \
    "${guest_result_dir}/server.log" \
    || die 1 "authenticated client did not traverse the accepted REALITY path"
  nsenter -t "${client_pid}" -m -n -- grep -q '^nameserver 198.18.0.2$' \
    /etc/resolv.conf || die 1 "mount-private resolver was not pinned"
  ip -n "${ns_client}" route show \
    >"${guest_result_dir}/client-routes-generation-1-active.txt"
  ip netns exec "${ns_client}" iptables-save \
    >"${guest_result_dir}/client-iptables-generation-1-active.txt"
  ip netns exec "${ns_client}" ip6tables-save \
    >"${guest_result_dir}/client-ip6tables-generation-1-active.txt"
  grep -q '^0.0.0.0/1 dev sptunc' \
    "${guest_result_dir}/client-routes-generation-1-active.txt" \
    || die 1 "generation-1 lower split-default route missing"
  grep -q '^128.0.0.0/1 dev sptunc' \
    "${guest_result_dir}/client-routes-generation-1-active.txt" \
    || die 1 "generation-1 upper split-default route missing"
  grep -Eq '^10.232.0.2(/32)? via 10.231.0.1 dev c0' \
    "${guest_result_dir}/client-routes-generation-1-active.txt" \
    || die 1 "generation-1 c0 carrier bypass route missing"
  validate_active_killswitch_saves \
    "${guest_result_dir}/client-iptables-generation-1-active.txt" \
    "${guest_result_dir}/client-ip6tables-generation-1-active.txt" \
    "${guest_result_dir}/generation-1-active-killswitch-identity.json" \
    || die 1 "generation-1 kill-switch differs from the exact fail-closed contract"
  strict_active_main_wal_snapshot "${main_wal}" "${real_client_pid}" \
    "${client_pid}" c0 "${guest_result_dir}/generation-1-main-wal-active" \
    || die 1 "generation-1 main WAL failed strict Active/c0 proof"
  require_ipv6_canary_state_unchanged generation-1-active \
    || die 1 "generation-1 activation changed the connected IPv6 canary state"

  # IPv6 policy captures start only after the exact block policy is active, so
  # pre-policy ND/MLD/RS traffic cannot be mislabeled as a Shadowpipe leak.
  start_owned underlay-c0-ipv6-capture \
    "${guest_result_dir}/underlay-c0-ipv6-capture.log" \
    ip netns exec "${ns_client}" tcpdump -p -Q out -U -nn -s 192 -i c0 \
    -w "${guest_result_dir}/client-c0-ipv6.pcap" ip6
  underlay_c0_ipv6_capture_record="${LAST_RECORD}"
  start_owned underlay-c1-ipv6-capture \
    "${guest_result_dir}/underlay-c1-ipv6-capture.log" \
    ip netns exec "${ns_client}" tcpdump -p -Q out -U -nn -s 192 -i c1 \
    -w "${guest_result_dir}/client-c1-ipv6.pcap" ip6
  underlay_c1_ipv6_capture_record="${LAST_RECORD}"

  local canary_c0_ipv4_log="${guest_result_dir}/continuous-c0-ipv4-canary.log"
  local canary_c1_ipv4_log="${guest_result_dir}/continuous-c1-ipv4-canary.log"
  local canary_c0_ipv6_log="${guest_result_dir}/continuous-c0-ipv6-canary.log"
  local canary_c1_ipv6_log="${guest_result_dir}/continuous-c1-ipv6-canary.log"
  start_direct_canary_loop direct-c0-ipv4 c0 4 10.231.0.1 \
    "${canary_c0_ipv4_log}"
  local canary_c0_ipv4_record="${LAST_RECORD}"
  start_direct_canary_loop direct-c1-ipv4 c1 4 10.233.0.1 \
    "${canary_c1_ipv4_log}"
  local canary_c1_ipv4_record="${LAST_RECORD}"
  start_direct_canary_loop direct-c0-ipv6 c0 6 2001:db8:231::1 \
    "${canary_c0_ipv6_log}"
  local canary_c0_ipv6_record="${LAST_RECORD}"
  start_direct_canary_loop direct-c1-ipv6 c1 6 2001:db8:233::1 \
    "${canary_c1_ipv6_log}"
  local canary_c1_ipv6_record="${LAST_RECORD}"
  local canary_log
  for canary_log in \
    "${canary_c0_ipv4_log}" "${canary_c1_ipv4_log}" \
    "${canary_c0_ipv6_log}" "${canary_c1_ipv6_log}"; do
    wait_until 5 direct_canary_count_exceeds "${canary_log}" 0 \
      || die 1 "continuous direct-canary workload did not start: ${canary_log##*/}"
  done

  # Force a real underlay topology change while generation 1 is healthy. The
  # endpoint /32 still pins its live carrier to c0 until the client observes the
  # RTM route notification, arms the independent barrier, and removes its own
  # state. Generation 2 is deliberately gated so the exact intermediate state
  # can be inspected before the retained wrapper emulates systemd restart.
  probe_direct_canaries_blocked "generation-1-active"
  capture_positive_ipv6_drop_counter \
    "${guest_result_dir}/generation-1-active-killswitch-identity.json" \
    "${guest_result_dir}/generation-1-ipv6-drop-counter.env" \
    || die 1 "generation-1 IPv6 block attempts did not hit the exact DROP rule"
  local generation_one_pid="${real_client_pid}"
  local generation_one_starttime="${real_client_starttime}"
  local generation_one_session_count
  generation_one_session_count="$(grep -c 'session established' \
    "${guest_result_dir}/server.log")"
  [[ "${generation_one_session_count}" =~ ^[1-9][0-9]*$ ]] \
    || die 1 "generation-1 authenticated session count is invalid"
  local handoff_c0_ipv4_before handoff_c1_ipv4_before
  local handoff_c0_ipv6_before handoff_c1_ipv6_before
  handoff_c0_ipv4_before="$(direct_canary_result_count "${canary_c0_ipv4_log}")"
  handoff_c1_ipv4_before="$(direct_canary_result_count "${canary_c1_ipv4_log}")"
  handoff_c0_ipv6_before="$(direct_canary_result_count "${canary_c0_ipv6_log}")"
  handoff_c1_ipv6_before="$(direct_canary_result_count "${canary_c1_ipv6_log}")"
  local current_generation_one_start handoff_log_lines_before
  local handoff_mutation_realtime_ns
  current_generation_one_start="$(proc_starttime "${generation_one_pid}")" \
    || die 1 "generation 1 exited before the default-route mutation"
  [[ "${current_generation_one_start}" == "${generation_one_starttime}" ]] \
    || die 1 "generation-1 PID identity changed before the default-route mutation"
  [[ ! -e "${guest_work_dir}/client-generation-1-stopped.ready" \
    && ! -L "${guest_work_dir}/client-generation-1-stopped.ready" ]] \
    || die 1 "generation 1 had already stopped before the default-route mutation"
  ip -n "${ns_client}" link show sptunc >/dev/null 2>&1 \
    || die 1 "generation-1 TUN disappeared before the default-route mutation"
  handoff_log_lines_before="$(wc -l <"${guest_result_dir}/client.log")"
  [[ "${handoff_log_lines_before}" =~ ^[0-9]+$ ]] \
    || die 1 "could not bind the pre-handoff client log boundary"
  handoff_mutation_realtime_ns="$(date +%s%N)"
  ip -n "${ns_client}" route replace default via 10.233.0.1 dev c1
  ip -n "${ns_client}" route show \
    >"${guest_result_dir}/client-routes-after-default-replacement.txt"
  grep -q '^default via 10.233.0.1 dev c1' \
    "${guest_result_dir}/client-routes-after-default-replacement.txt" \
    || die 1 "real default-route replacement did not select c1"
  wait_until 20 test -f \
    "${guest_work_dir}/client-generation-1-stopped.ready" \
    || die 1 "generation 1 did not complete controlled network restart"
  if proc_starttime "${generation_one_pid}" >/dev/null 2>&1; then
    die 1 "generation-1 client remained after network invalidation"
  fi
  local generation_one_status
  generation_one_status="$(<"${guest_work_dir}/client-generation-1-exit-status")"
  [[ "${generation_one_status}" =~ ^[1-9][0-9]*$ \
    && "${generation_one_status}" != 124 \
    && "${generation_one_status}" != 137 \
    && "${generation_one_status}" != 143 ]] \
    || die 1 "generation-1 network restart did not return a bounded non-zero status"
  extract_log_suffix "${guest_result_dir}/client.log" \
    "${handoff_log_lines_before}" \
    "${guest_result_dir}/generation-1-network-restart.log" \
    || die 1 "could not extract the generation-1 post-route log suffix"
  validate_exact_network_restart_suffix \
    "${guest_result_dir}/generation-1-network-restart.log" \
    DefaultRouteChanged \
    "${guest_result_dir}/generation-1-network-restart.env" \
    || die 1 "generation 1 was not replaced by the exact default-route event"
  printf 'route_replace_realtime_ns=%s\n' "${handoff_mutation_realtime_ns}" \
    >"${guest_result_dir}/network-handoff-timing.env"
  grep -q \
    'network topology invalidated the captured underlay; replacing this process under durable lockdown' \
    "${guest_result_dir}/generation-1-network-restart.log" \
    || die 1 "generation 1 did not log topology-driven replacement"
  grep -q 'durable restart lockdown active before main host-state teardown' \
    "${guest_result_dir}/generation-1-network-restart.log" \
    || die 1 "generation 1 did not log strict restart-lockdown activation"
  if grep -Eq 'Conflict journal|journal.*Conflict|sealed.*Conflict' \
    "${guest_result_dir}/generation-1-network-restart.log"; then
    die 1 "ordinary network handoff was incorrectly sealed as Conflict"
  fi
  if ip -n "${ns_client}" link show sptunc >/dev/null 2>&1; then
    die 1 "generation-1 TUN remained under the intermediate lockdown"
  fi
  if ip -n "${ns_client}" route show \
    | grep -Eq '^(0\.0\.0\.0/1|128\.0\.0\.0/1) '; then
    die 1 "generation-1 split-default route remained during handoff"
  fi
  if ip -n "${ns_client}" route show 10.232.0.2/32 | grep -q .; then
    die 1 "generation-1 carrier bypass remained during handoff"
  fi
  if ip netns exec "${ns_client}" iptables-save \
    | grep -Eq 'SP4_[0-9a-f]{20}|-j SP4_[0-9a-f]{20}'; then
    die 1 "generation-1 IPv4 kill-switch remained during handoff"
  fi
  if ip netns exec "${ns_client}" ip6tables-save \
    | grep -Eq 'SP6_[0-9a-f]{20}|-j SP6_[0-9a-f]{20}'; then
    die 1 "generation-1 IPv6 kill-switch remained during handoff"
  fi
  [[ -f "${guest_work_dir}/resolver-restored-generation-1.ok" \
    && ! -e "${guest_work_dir}/resolver-restored-generation-1.failed" ]] \
    || die 1 "generation-1 mount-private resolver was not restored"

  local lockdown_wal="${client_host_state}/handoff-lockdown-v1.json"
  [[ ! -e "${main_wal}" && ! -L "${main_wal}" ]] \
    || die 1 "complete network handoff retained a main host-state WAL"
  local handoff_lockdown_table handoff_lockdown_handle
  if ! read -r handoff_lockdown_table handoff_lockdown_handle < <(
    strict_active_lockdown_snapshot "${lockdown_wal}" "${client_pid}" \
      "${guest_result_dir}/network-handoff-lockdown"
  ); then
    die 1 "intermediate network-handoff lockdown failed strict WAL/kernel proof"
  fi
  find "${client_host_state}" -mindepth 1 -maxdepth 1 -printf '%f\n' \
    | LC_ALL=C sort >"${guest_result_dir}/network-handoff-state-census.txt"
  [[ "$(<"${guest_result_dir}/network-handoff-state-census.txt")" \
    == $'handoff-lockdown-v1.json\nhost.lock' ]] \
    || die 1 "intermediate handoff state directory contains a foreign artifact"
  exact_empty_private_regular_file \
    "${client_host_state}/host.lock" 0 0 \
    || die 1 "intermediate host lock lacks exact root-private regular-file safety"
  require_ipv6_canary_state_unchanged network-handoff-lockdown \
    || die 1 "network handoff changed the connected IPv6 canary state"
  probe_direct_canaries_blocked "network-handoff-lockdown"

  create_empty_private_regular_file "${guest_work_dir}/start-generation-2" \
    || die 1 "could not publish the generation-2 restart gate"
  wait_until 20 test -s "${guest_work_dir}/client-generation-2.pid" \
    || die 1 "retained wrapper did not launch generation 2"
  real_client_pid="$(<"${guest_work_dir}/client-generation-2.pid")"
  [[ "${real_client_pid}" =~ ^[0-9]+$ \
    && "${real_client_pid}" != "${generation_one_pid}" ]] \
    || die 1 "client wrapper did not publish a distinct generation-2 PID"
  real_client_starttime="$(proc_starttime "${real_client_pid}")" \
    || die 1 "could not bind the generation-2 client PID to its start time"
  validate_client_private_uri_argv "${real_client_pid}" \
    "${reality_uri_file}" "${reality_short_id_file}" \
    || die 1 "generation-2 client argv did not preserve the private URI boundary"
  wait_until 20 ip netns exec "${ns_client}" ip link show sptunc \
    || die 1 "generation-2 client OS TUN did not appear"
  wait_until 20 awk -v baseline="${generation_one_session_count}" '
    /session established/ { count += 1 }
    END { exit count <= baseline }
  ' "${guest_result_dir}/server.log" \
    || die 1 "generation-2 authenticated session did not establish"
  local generation_two_session_count
  generation_two_session_count="$(grep -c 'session established' \
    "${guest_result_dir}/server.log")"
  (( generation_two_session_count > generation_one_session_count )) \
    || die 1 "generation-2 session count did not increase"
  wait_until 15 grep -q \
    'restart lockdown released after durable replacement Active proof' \
    "${guest_result_dir}/client.log" \
    || die 1 "generation 2 did not release lockdown after replacement Active proof"
  [[ ! -e "${lockdown_wal}" && ! -L "${lockdown_wal}" ]] \
    || die 1 "generation-2 activation retained the restart-lockdown WAL"
  if ip netns exec "${ns_client}" nft list table inet \
    "${handoff_lockdown_table}" >/dev/null 2>&1; then
    die 1 "generation-2 activation retained the intermediate lockdown table"
  fi
  if ip netns exec "${ns_client}" nft list tables \
    | grep -Eq '^table inet sp_lock_[0-9a-f]{32}$'; then
    die 1 "generation-2 activation left a foreign restart-lockdown table"
  fi
  strict_active_main_wal_snapshot "${main_wal}" "${real_client_pid}" \
    "${client_pid}" c1 "${guest_result_dir}/generation-2-main-wal-active" \
    || die 1 "generation-2 main WAL failed strict Active/c1 proof"
  ip -n "${ns_client}" route show \
    >"${guest_result_dir}/client-routes-generation-2-active.txt"
  grep -q '^default via 10.233.0.1 dev c1' \
    "${guest_result_dir}/client-routes-generation-2-active.txt" \
    || die 1 "generation-2 default route is not c1"
  grep -q '^0.0.0.0/1 dev sptunc' \
    "${guest_result_dir}/client-routes-generation-2-active.txt" \
    || die 1 "generation-2 lower split-default route missing"
  grep -q '^128.0.0.0/1 dev sptunc' \
    "${guest_result_dir}/client-routes-generation-2-active.txt" \
    || die 1 "generation-2 upper split-default route missing"
  grep -Eq '^10.232.0.2(/32)? via 10.233.0.1 dev c1' \
    "${guest_result_dir}/client-routes-generation-2-active.txt" \
    || die 1 "generation-2 c1 carrier bypass route missing"
  ip netns exec "${ns_client}" iptables-save \
    >"${guest_result_dir}/client-iptables-generation-2-active.txt"
  ip netns exec "${ns_client}" ip6tables-save \
    >"${guest_result_dir}/client-ip6tables-generation-2-active.txt"
  validate_active_killswitch_saves \
    "${guest_result_dir}/client-iptables-generation-2-active.txt" \
    "${guest_result_dir}/client-ip6tables-generation-2-active.txt" \
    "${guest_result_dir}/generation-2-active-killswitch-identity.json" \
    || die 1 "generation-2 kill-switch differs from the exact fail-closed contract"
  require_ipv6_canary_state_unchanged generation-2-active \
    || die 1 "generation-2 activation changed the connected IPv6 canary state"
  nsenter -t "${client_pid}" -m -n -- grep -q '^nameserver 198.18.0.2$' \
    /etc/resolv.conf || die 1 "generation-2 mount-private resolver was not pinned"
  probe_direct_canaries_blocked "generation-2-active"
  capture_positive_ipv6_drop_counter \
    "${guest_result_dir}/generation-2-active-killswitch-identity.json" \
    "${guest_result_dir}/generation-2-ipv6-drop-counter.env" \
    || die 1 "generation-2 IPv6 block attempts did not hit the exact DROP rule"
  wait_until 5 direct_canary_count_exceeds \
    "${canary_c0_ipv4_log}" "${handoff_c0_ipv4_before}" \
    || die 1 "c0 IPv4 canary attempts did not span the network handoff"
  wait_until 5 direct_canary_count_exceeds \
    "${canary_c1_ipv4_log}" "${handoff_c1_ipv4_before}" \
    || die 1 "c1 IPv4 canary attempts did not span the network handoff"
  wait_until 5 direct_canary_count_exceeds \
    "${canary_c0_ipv6_log}" "${handoff_c0_ipv6_before}" \
    || die 1 "c0 IPv6 canary attempts did not span the network handoff"
  wait_until 5 direct_canary_count_exceeds \
    "${canary_c1_ipv6_log}" "${handoff_c1_ipv6_before}" \
    || die 1 "c1 IPv6 canary attempts did not span the network handoff"
  local handoff_c0_ipv4_after handoff_c1_ipv4_after
  local handoff_c0_ipv6_after handoff_c1_ipv6_after
  handoff_c0_ipv4_after="$(direct_canary_result_count "${canary_c0_ipv4_log}")"
  handoff_c1_ipv4_after="$(direct_canary_result_count "${canary_c1_ipv4_log}")"
  handoff_c0_ipv6_after="$(direct_canary_result_count "${canary_c0_ipv6_log}")"
  handoff_c1_ipv6_after="$(direct_canary_result_count "${canary_c1_ipv6_log}")"
  {
    printf 'generation_1_pid=%s\n' "${generation_one_pid}"
    printf 'generation_1_start_ticks=%s\n' "${generation_one_starttime}"
    printf 'generation_1_exit_status=%s\n' "${generation_one_status}"
    printf 'generation_1_restart_cause=DefaultRouteChanged\n'
    printf 'default_route_transition=c0_to_c1\n'
    printf 'intermediate_main_wal=absent\n'
    printf 'intermediate_lockdown=active_strict\n'
    printf 'intermediate_lockdown_table=%s\n' "${handoff_lockdown_table}"
    printf 'intermediate_lockdown_handle=%s\n' "${handoff_lockdown_handle}"
    printf 'generation_2_pid=%s\n' "${real_client_pid}"
    printf 'generation_2_start_ticks=%s\n' "${real_client_starttime}"
    printf 'generation_1_session_count=%s\n' "${generation_one_session_count}"
    printf 'generation_2_session_count=%s\n' "${generation_two_session_count}"
    printf 'generation_2_bypass_interface=c1\n'
    printf 'generation_2_main_wal=active_strict\n'
    printf 'generation_2_lockdown=absent_after_active_proof\n'
    printf 'c0_ipv4_canary_results_before_handoff=%s\n' \
      "${handoff_c0_ipv4_before}"
    printf 'c0_ipv4_canary_results_after_handoff=%s\n' \
      "${handoff_c0_ipv4_after}"
    printf 'c1_ipv4_canary_results_before_handoff=%s\n' \
      "${handoff_c1_ipv4_before}"
    printf 'c1_ipv4_canary_results_after_handoff=%s\n' \
      "${handoff_c1_ipv4_after}"
    printf 'c0_ipv6_canary_results_before_handoff=%s\n' \
      "${handoff_c0_ipv6_before}"
    printf 'c0_ipv6_canary_results_after_handoff=%s\n' \
      "${handoff_c0_ipv6_after}"
    printf 'c1_ipv6_canary_results_before_handoff=%s\n' \
      "${handoff_c1_ipv6_before}"
    printf 'c1_ipv6_canary_results_after_handoff=%s\n' \
      "${handoff_c1_ipv6_after}"
  } >"${guest_result_dir}/network-handoff.env"

  # Production regression: a real packet observer may still request
  # PACKET_MR_PROMISC. Linux emits RTM_NEWLINK with exact
  # ifi_change=IFF_PROMISC on both refcount transitions; those observer-only
  # notifications must not replace an otherwise unchanged client generation.
  local promisc_restart_count_before promisc_restart_count_after
  local promisc_current_start
  promisc_restart_count_before="$(awk '
    /topology changed at network-event generation/ { count += 1 }
    END { print count + 0 }
  ' "${guest_result_dir}/client.log")"
  start_owned promisc-observer-regression-capture \
    "${guest_result_dir}/promisc-observer-regression-capture.log" \
    ip netns exec "${ns_client}" tcpdump -Q out --immediate-mode -U -nn \
    -s 96 -i c1 -w \
    "${guest_result_dir}/promisc-observer-regression.pcap" \
    'host 10.232.0.2 and tcp port 47843'
  local promisc_observer_record="${LAST_RECORD}"
  sleep 0.5
  ip -d -s -n "${ns_client}" link show dev c1 \
    >"${guest_result_dir}/promisc-observer-link-active.txt"
  grep -Eq 'promiscuity [1-9][0-9]*' \
    "${guest_result_dir}/promisc-observer-link-active.txt" \
    || die 1 "packet observer did not prove an active promiscuity refcount"
  stop_role_record "${promisc_observer_record}" \
    || die 1 "could not stop the promiscuous-observer regression capture"
  validate_pcap_file "${guest_result_dir}/promisc-observer-regression.pcap" \
    || die 1 "promiscuous-observer regression pcap is malformed"
  capture_has_zero_kernel_drops \
    "${guest_result_dir}/promisc-observer-regression-capture.log" \
    || die 1 "promiscuous-observer regression capture dropped packets"
  sleep 0.5
  ip -d -s -n "${ns_client}" link show dev c1 \
    >"${guest_result_dir}/promisc-observer-link-restored.txt"
  grep -Eq 'promiscuity 0([[:space:]]|$)' \
    "${guest_result_dir}/promisc-observer-link-restored.txt" \
    || die 1 "packet observer left a promiscuity refcount behind"
  promisc_current_start="$(proc_starttime "${real_client_pid}")" \
    || die 1 "promiscuous packet observer replaced generation 2"
  [[ "${promisc_current_start}" == "${real_client_starttime}" ]] \
    || die 1 "promiscuous packet observer changed generation-2 PID identity"
  [[ ! -e "${guest_work_dir}/client-generation-2-stopped.ready" \
    && ! -L "${guest_work_dir}/client-generation-2-stopped.ready" ]] \
    || die 1 "promiscuous packet observer stopped generation 2"
  promisc_restart_count_after="$(awk '
    /topology changed at network-event generation/ { count += 1 }
    END { print count + 0 }
  ' "${guest_result_dir}/client.log")"
  [[ "${promisc_restart_count_after}" == "${promisc_restart_count_before}" ]] \
    || die 1 "promiscuous packet observer produced a topology restart"
  {
    printf 'packet_membership=promiscuous\n'
    printf 'client_pid=%s\n' "${real_client_pid}"
    printf 'client_start_ticks=%s\n' "${real_client_starttime}"
    printf 'topology_restart_count_before=%s\n' \
      "${promisc_restart_count_before}"
    printf 'topology_restart_count_after=%s\n' \
      "${promisc_restart_count_after}"
    printf 'client_generation_unchanged=true\n'
  } >"${guest_result_dir}/promisc-observer-regression.env"

  # Keep confidentiality evidence separate from the negative leak BPF. This
  # bounded capture must contain the allowed carrier tuple, must not drop any
  # packets, and must not expose the known application payload in wire bytes.
  # It is a regression heuristic, not a substitute for AEAD security analysis.
  start_owned carrier-marker-capture \
    "${guest_result_dir}/carrier-marker-capture.log" \
    ip netns exec "${ns_client}" tcpdump -p -Q out --immediate-mode -U -nn -s 0 -i c1 \
    -w "${guest_result_dir}/carrier-marker.pcap" \
    'host 10.232.0.2 and tcp port 47843'
  local marker_capture_record="${LAST_RECORD}"
  sleep 0.25
  timeout 10 ip netns exec "${ns_client}" curl -fsS \
    http://198.18.0.2:18080/health.txt \
    >"${guest_result_dir}/marker-through-tunnel.txt" \
    || record_failure "bounded marker workload failed"
  sleep 0.25
  stop_role_record "${marker_capture_record}" || true
  validate_pcap_file "${guest_result_dir}/carrier-marker.pcap" \
    || record_failure "carrier-marker pcap is missing, unreadable, or malformed"
  grep -qxF "${marker}" "${guest_result_dir}/marker-through-tunnel.txt" 2>/dev/null \
    || record_failure "bounded marker response mismatch"
  capture_has_zero_kernel_drops \
    "${guest_result_dir}/carrier-marker-capture.log" \
    || record_failure "bounded carrier-marker capture dropped packets"
  pcap_has "${guest_result_dir}/carrier-marker.pcap" \
    'host 10.232.0.2 and tcp port 47843' \
    || record_failure "bounded carrier-marker capture contains no carrier packet"
  if grep -aFq -- "${marker}" "${guest_result_dir}/carrier-marker.pcap"; then
    record_failure "plaintext marker appeared on the allowed carrier tuple"
  fi

  # Functional gates.
  timeout 30 ip netns exec "${ns_client}" ping -M "do" -s 1200 -c 20 -W 1 \
    198.18.0.2 >"${guest_result_dir}/icmp.txt" \
    || record_failure "ICMP/MTU workload failed"
  timeout 120 ip netns exec "${ns_client}" curl -fsS \
    http://198.18.0.2:18080/payload.bin -o "${guest_work_dir}/download.bin" \
    || record_failure "64 MiB HTTP workload failed"
  if [[ -f "${guest_work_dir}/download.bin" ]]; then
    download_sha="$(sha256sum "${guest_work_dir}/download.bin" | awk '{print $1}')"
    printf '%s  download.bin\n' "${download_sha}" \
      >"${guest_result_dir}/payload-download.sha256"
    [[ "${download_sha}" == "${source_sha}" ]] \
      || record_failure "64 MiB SHA-256 mismatch"
  fi
  timeout 45 ip netns exec "${ns_client}" iperf3 -c 198.18.0.2 -t 10 -J \
    >"${guest_result_dir}/iperf-tcp.json" 2>"${guest_result_dir}/iperf-tcp.err" \
    || record_failure "TCP iperf invocation failed"
  jq -e '.error == null and (.end.sum_received.bytes // 0) >= 1048576' \
    "${guest_result_dir}/iperf-tcp.json" >/dev/null 2>&1 \
    || record_failure "TCP iperf receiver summary invalid"
  timeout 45 ip netns exec "${ns_client}" iperf3 -c 198.18.0.2 \
    -u -b 5M -t 10 -J >"${guest_result_dir}/iperf-udp.json" \
    2>"${guest_result_dir}/iperf-udp.err" \
    || record_failure "UDP iperf invocation failed"
  jq -e '.error == null and (.end.sum_received.bytes // 0) >= 1048576' \
    "${guest_result_dir}/iperf-udp.json" >/dev/null 2>&1 \
    || record_failure "UDP iperf receiver summary invalid"
  nsenter -t "${client_pid}" -m -n -- getent ahostsv4 probe.shadowpipe.invalid \
    >"${guest_result_dir}/dns-result.txt" \
    || record_failure "system resolver did not answer through tunnel"
  awk '$1 == "198.18.0.2" { found=1 } END { exit !found }' \
    "${guest_result_dir}/dns-result.txt" \
    || record_failure "DNS returned the wrong synthetic address"

  # The direct canary must now be blocked even while the carrier is healthy.
  if timeout 4 ip netns exec "${ns_client}" curl -fsS \
    http://10.231.0.1:18081/health.txt >/dev/null 2>&1; then
    record_failure "kill-switch allowed direct underlay HTTP"
  fi

  # Cut both directions of the owned carrier with TCP reset, prove no direct
  # fallback, then remove only our table and require bounded recovery.
  ip netns exec "${ns_router}" nft -f - <<'EOF'
table inet sptun_cut {
  chain forward {
    type filter hook forward priority -100; policy accept;
    tcp dport 47843 reject with tcp reset
    tcp sport 47843 reject with tcp reset
  }
}
EOF
  guest_cut_installed=1
  set +e
  timeout 5 ip netns exec "${ns_client}" curl -fsS \
    http://198.18.0.2:18080/health.txt >/dev/null 2>&1
  local cut_sink_status=$?
  set -e
  (( cut_sink_status != 0 )) || record_failure "sink stayed reachable during carrier cut"
  if timeout 4 ip netns exec "${ns_client}" curl -fsS \
    http://10.231.0.1:18081/health.txt >/dev/null 2>&1; then
    record_failure "direct fallback leaked during carrier cut"
  fi
  wait_until 12 grep -q 'session ended, reconnecting' "${guest_result_dir}/client.log" \
    || record_failure "client did not observe/retry the carrier cut"
  ip netns exec "${ns_router}" nft list table inet sptun_cut \
    >"${guest_result_dir}/carrier-cut-nft.txt"
  ip netns exec "${ns_router}" nft delete table inet sptun_cut
  guest_cut_installed=0
  local recovered=0 recovery_start recovery_deadline recovery_elapsed
  recovery_start="${SECONDS}"
  recovery_deadline=$((SECONDS + 45))
  while (( SECONDS < recovery_deadline )); do
    if timeout 1 ip netns exec "${ns_client}" curl -fsS \
      http://198.18.0.2:18080/health.txt \
      >"${guest_result_dir}/recovery-health.txt" 2>/dev/null; then
      recovered=1
      recovery_elapsed=$((SECONDS - recovery_start))
      printf '%s\n' "${recovery_elapsed}" \
        >"${guest_result_dir}/recovery-seconds-upper-bound.txt"
      break
    fi
    (( SECONDS < recovery_deadline )) && sleep 1
  done
  (( recovered != 0 )) || record_failure "authenticated tunnel did not recover within 45 seconds"
  grep -qxF "${marker}" "${guest_result_dir}/recovery-health.txt" 2>/dev/null \
    || record_failure "recovery payload mismatch"

  # The positive inner capture may close after the workload. Underlay captures
  # and continuous direct canaries deliberately remain active through the final
  # manager-stop/SIGTERM transition and strict lockdown proof.
  stop_role_record "${sink_capture_record}" || true
  capture_has_zero_kernel_drops "${guest_result_dir}/sink-capture.log" \
    || record_failure "positive sink capture dropped packets"
  validate_pcap_file "${guest_result_dir}/sink-inner.pcap" \
    || record_failure "positive sink pcap is missing, unreadable, or malformed"
  pcap_has "${guest_result_dir}/sink-inner.pcap" 'src host 10.8.0.2 and icmp' \
    || record_failure "sink capture lacks inner ICMP"
  pcap_has "${guest_result_dir}/sink-inner.pcap" \
    'src host 10.8.0.2 and tcp dst port 18080' \
    || record_failure "sink capture lacks inner HTTP"
  pcap_has "${guest_result_dir}/sink-inner.pcap" \
    'src host 10.8.0.2 and udp dst port 5201' \
    || record_failure "sink capture lacks inner UDP workload"
  pcap_has "${guest_result_dir}/sink-inner.pcap" \
    'src host 10.8.0.2 and udp dst port 53' \
    || record_failure "sink capture lacks tunneled DNS"

  # Model `systemctl stop`: the manager-level no-restart gate is durably
  # published before the exact child receives SIGTERM. The namespace holder
  # remains alive for strict lockdown inspection and explicit release, but the
  # restart supervisor may not create a generation 3.
  local manager_stop_log_lines_before manager_stop_current_start
  manager_stop_current_start="$(proc_starttime "${real_client_pid}")" \
    || die 1 "generation 2 exited before the manager-stop transition"
  [[ "${manager_stop_current_start}" == "${real_client_starttime}" ]] \
    || die 1 "generation-2 PID identity changed before manager stop"
  [[ ! -e "${guest_work_dir}/client-generation-2-stopped.ready" \
    && ! -L "${guest_work_dir}/client-generation-2-stopped.ready" ]] \
    || die 1 "generation 2 had already stopped before manager stop"
  manager_stop_log_lines_before="$(wc -l <"${guest_result_dir}/client.log")"
  [[ "${manager_stop_log_lines_before}" =~ ^[0-9]+$ ]] \
    || die 1 "could not bind the pre-manager-stop client log boundary"
  create_empty_private_regular_file "${guest_work_dir}/manager-stop" \
    || die 1 "could not publish the manager no-restart gate"
  [[ -f "${guest_work_dir}/manager-stop" \
    && ! -L "${guest_work_dir}/manager-stop" ]] \
    || die 1 "manager no-restart gate was not published"
  printf 'manager_stop_gate=present_before_generation_2_sigterm\n' \
    >"${guest_result_dir}/manager-stop.env"
  local shutdown_c0_ipv4_before shutdown_c1_ipv4_before
  local shutdown_c0_ipv6_before shutdown_c1_ipv6_before
  shutdown_c0_ipv4_before="$(direct_canary_result_count "${canary_c0_ipv4_log}")"
  shutdown_c1_ipv4_before="$(direct_canary_result_count "${canary_c1_ipv4_log}")"
  shutdown_c0_ipv6_before="$(direct_canary_result_count "${canary_c0_ipv6_log}")"
  shutdown_c1_ipv6_before="$(direct_canary_result_count "${canary_c1_ipv6_log}")"
  pidfd_signal "${real_client_pid}" "${real_client_starttime}" SIGTERM \
    || die 1 "could not signal the exact real client process"
  wait_until 20 test -f "${guest_work_dir}/client-stopped.ready" \
    || die 1 "client did not finish ordered teardown within 20 seconds"
  if proc_starttime "${real_client_pid}" >/dev/null 2>&1; then
    record_failure "real client process remained after forwarded SIGTERM"
  fi
  if [[ -e "${guest_work_dir}/client-generation-3.pid" \
    || -L "${guest_work_dir}/client-generation-3.pid" ]]; then
    record_failure "manager-stop gate allowed an unexpected generation 3"
  fi
  proc_starttime "${client_pid}" >/dev/null 2>&1 \
    || die 1 "namespace holder did not remain alive after manager stop"
  grep -qx '0' "${guest_work_dir}/client-exit-status" \
    || record_failure "client returned a non-zero status after graceful SIGTERM"
  extract_log_suffix "${guest_result_dir}/client.log" \
    "${manager_stop_log_lines_before}" \
    "${guest_result_dir}/generation-2-manager-stop.log" \
    || die 1 "could not extract the generation-2 manager-stop log suffix"
  grep -q 'shutdown requested; restoring routes, DNS and firewall' \
    "${guest_result_dir}/generation-2-manager-stop.log" \
    || record_failure "client did not log ordered SIGTERM teardown"
  grep -q 'durable restart lockdown active before main host-state teardown' \
    "${guest_result_dir}/generation-2-manager-stop.log" \
    || record_failure "client did not log the durable restart barrier handoff"
  if grep -q 'topology changed at network-event generation' \
    "${guest_result_dir}/generation-2-manager-stop.log"; then
    record_failure "manager stop was contaminated by a topology restart"
  fi
  if ip -n "${ns_client}" link show sptunc >/dev/null 2>&1; then
    record_failure "client TUN remained after graceful stop"
  fi
  if ip -n "${ns_client}" route show | grep -Eq '^(0\.0\.0\.0/1|128\.0\.0\.0/1) '; then
    record_failure "split-default route remained after graceful stop"
  fi
  if ip netns exec "${ns_client}" iptables-save \
    | grep -Eq 'SP4_[0-9a-f]{20}|-j SP4_[0-9a-f]{20}'; then
    record_failure "IPv4 kill-switch chain or hook remained after graceful stop"
  fi
  if ip netns exec "${ns_client}" ip6tables-save \
    | grep -Eq 'SP6_[0-9a-f]{20}|-j SP6_[0-9a-f]{20}'; then
    record_failure "IPv6 kill-switch chain or hook remained after graceful stop"
  fi
  if ip -n "${ns_client}" route show 10.232.0.2/32 | grep -q .; then
    record_failure "carrier bypass /32 remained after graceful stop"
  fi
  [[ -f "${guest_work_dir}/resolver-restored-generation-2.ok" \
    && ! -e "${guest_work_dir}/resolver-restored-generation-2.failed" ]] \
    || record_failure "generation-2 mount-private resolv.conf was not restored"

  local lockdown_table lockdown_handle
  [[ ! -e "${client_host_state}/host-state-v2.json" \
    && ! -L "${client_host_state}/host-state-v2.json" ]] \
    || record_failure "main host-state WAL remained after graceful teardown"
  [[ "$(LC_ALL=C stat -c '%a:%u:%g:%F' "${client_host_state}")" \
    == "700:0:0:directory" ]] \
    || die 1 "host-state directory lacks exact root:root 0700 real-directory safety"
  if ! read -r lockdown_table lockdown_handle < <(
    strict_active_lockdown_snapshot "${lockdown_wal}" "${client_pid}" \
      "${guest_result_dir}/restart-lockdown"
  ); then
    die 1 "post-SIGTERM restart lockdown failed strict WAL/kernel proof"
  fi
  exact_empty_private_regular_file \
    "${client_host_state}/host.lock" 0 0 \
    || die 1 "final host lock lacks exact root-private regular-file safety"
  exact_empty_private_regular_file "${guest_work_dir}/manager-stop" 0 0 \
    || die 1 "manager no-restart gate lacks exact root-private safety"
  require_ipv6_canary_state_unchanged generation-2-final-lockdown \
    || die 1 "final lockdown changed the connected IPv6 canary state"
  probe_direct_canaries_blocked "generation-2-final-lockdown"
  wait_until 5 direct_canary_count_exceeds \
    "${canary_c0_ipv4_log}" "${shutdown_c0_ipv4_before}" \
    || die 1 "c0 IPv4 canary attempts did not span final shutdown"
  wait_until 5 direct_canary_count_exceeds \
    "${canary_c1_ipv4_log}" "${shutdown_c1_ipv4_before}" \
    || die 1 "c1 IPv4 canary attempts did not span final shutdown"
  wait_until 5 direct_canary_count_exceeds \
    "${canary_c0_ipv6_log}" "${shutdown_c0_ipv6_before}" \
    || die 1 "c0 IPv6 canary attempts did not span final shutdown"
  wait_until 5 direct_canary_count_exceeds \
    "${canary_c1_ipv6_log}" "${shutdown_c1_ipv6_before}" \
    || die 1 "c1 IPv6 canary attempts did not span final shutdown"
  local shutdown_c0_ipv4_after shutdown_c1_ipv4_after
  local shutdown_c0_ipv6_after shutdown_c1_ipv6_after
  shutdown_c0_ipv4_after="$(direct_canary_result_count "${canary_c0_ipv4_log}")"
  shutdown_c1_ipv4_after="$(direct_canary_result_count "${canary_c1_ipv4_log}")"
  shutdown_c0_ipv6_after="$(direct_canary_result_count "${canary_c0_ipv6_log}")"
  shutdown_c1_ipv6_after="$(direct_canary_result_count "${canary_c1_ipv6_log}")"
  {
    printf 'manager_stop_gate=present_before_generation_2_sigterm\n'
    printf 'generation_3=absent\n'
    printf 'c0_ipv4_canary_results_before_shutdown=%s\n' \
      "${shutdown_c0_ipv4_before}"
    printf 'c0_ipv4_canary_results_after_lockdown=%s\n' \
      "${shutdown_c0_ipv4_after}"
    printf 'c1_ipv4_canary_results_before_shutdown=%s\n' \
      "${shutdown_c1_ipv4_before}"
    printf 'c1_ipv4_canary_results_after_lockdown=%s\n' \
      "${shutdown_c1_ipv4_after}"
    printf 'c0_ipv6_canary_results_before_shutdown=%s\n' \
      "${shutdown_c0_ipv6_before}"
    printf 'c0_ipv6_canary_results_after_lockdown=%s\n' \
      "${shutdown_c0_ipv6_after}"
    printf 'c1_ipv6_canary_results_before_shutdown=%s\n' \
      "${shutdown_c1_ipv6_before}"
    printf 'c1_ipv6_canary_results_after_lockdown=%s\n' \
      "${shutdown_c1_ipv6_after}"
  } >"${guest_result_dir}/manager-stop.env"

  stop_role_record "${canary_c0_ipv4_record}" || true
  stop_role_record "${canary_c1_ipv4_record}" || true
  stop_role_record "${canary_c0_ipv6_record}" || true
  stop_role_record "${canary_c1_ipv6_record}" || true
  for canary_log in \
    "${canary_c0_ipv4_log}" "${canary_c1_ipv4_log}" \
    "${canary_c0_ipv6_log}" "${canary_c1_ipv6_log}"; do
    if grep -q ' status=success$' "${canary_log}"; then
      record_failure "continuous direct canary escaped: ${canary_log##*/}"
    fi
  done

  stop_role_record "${underlay_c0_ipv4_capture_record}" || true
  stop_role_record "${underlay_c0_ipv6_capture_record}" || true
  stop_role_record "${underlay_c1_ipv4_capture_record}" || true
  stop_role_record "${underlay_c1_ipv6_capture_record}" || true
  capture_has_zero_kernel_drops \
    "${guest_result_dir}/underlay-c0-ipv4-capture.log" \
    || record_failure "c0 IPv4 underlay capture dropped packets"
  capture_has_zero_kernel_drops \
    "${guest_result_dir}/underlay-c0-ipv6-capture.log" \
    || record_failure "c0 IPv6 underlay capture dropped packets"
  capture_has_zero_kernel_drops \
    "${guest_result_dir}/underlay-c1-ipv4-capture.log" \
    || record_failure "c1 IPv4 underlay capture dropped packets"
  capture_has_zero_kernel_drops \
    "${guest_result_dir}/underlay-c1-ipv6-capture.log" \
    || record_failure "c1 IPv6 underlay capture dropped packets"
  local underlay_pcap
  for underlay_pcap in \
    "${guest_result_dir}/client-c0-ipv4.pcap" \
    "${guest_result_dir}/client-c1-ipv4.pcap" \
    "${guest_result_dir}/client-c0-ipv6.pcap" \
    "${guest_result_dir}/client-c1-ipv6.pcap"; do
    validate_pcap_file "${underlay_pcap}" \
      || record_failure "underlay pcap is missing, unreadable, or malformed: ${underlay_pcap##*/}"
  done
  pcap_has "${guest_result_dir}/client-c0-ipv4.pcap" \
    'host 10.232.0.2 and tcp port 47843' \
    || record_failure "c0 capture lacks generation-1 carrier traffic"
  pcap_has "${guest_result_dir}/client-c1-ipv4.pcap" \
    'host 10.232.0.2 and tcp port 47843' \
    || record_failure "c1 capture lacks generation-2 carrier traffic"
  if pcap_has "${guest_result_dir}/client-c0-ipv4.pcap" \
    'not (host 10.232.0.2 and tcp port 47843)'; then
    record_failure "c0 underlay carried non-carrier IPv4 traffic"
  fi
  if pcap_has "${guest_result_dir}/client-c1-ipv4.pcap" \
    'not (host 10.232.0.2 and tcp port 47843)'; then
    record_failure "c1 underlay carried non-carrier IPv4 traffic"
  fi
  if pcap_has "${guest_result_dir}/client-c0-ipv6.pcap" ip6; then
    record_failure "c0 emitted IPv6 while ipv6-mode=block was active"
  fi
  if pcap_has "${guest_result_dir}/client-c1-ipv6.pcap" ip6; then
    record_failure "c1 emitted IPv6 while ipv6-mode=block was active"
  fi

  # The barrier is L3/OUTPUT scoped. A blocked HTTP attempt must produce no IP
  # packet on the client underlay; this is deliberately not an L2/ARP claim.
  start_owned restart-lockdown-capture \
    "${guest_result_dir}/restart-lockdown-capture.log" \
    ip netns exec "${ns_client}" tcpdump -p -Q out -U -nn -i c0 -w \
    "${guest_result_dir}/restart-lockdown-underlay.pcap" \
    'ip and host 10.231.0.1 and tcp port 18081'
  local restart_lockdown_capture_record="${LAST_RECORD}"
  sleep 0.25
  if timeout 4 ip netns exec "${ns_client}" curl -fsS \
    http://10.231.0.1:18081/health.txt >/dev/null 2>&1; then
    record_failure "direct underlay escaped the durable post-SIGTERM barrier"
  fi
  stop_role_record "${restart_lockdown_capture_record}" || true
  validate_pcap_file "${guest_result_dir}/restart-lockdown-underlay.pcap" \
    || record_failure "restart-lockdown pcap is missing, unreadable, or malformed"
  if pcap_has "${guest_result_dir}/restart-lockdown-underlay.pcap" \
    'ip and host 10.231.0.1 and tcp port 18081'; then
    record_failure "post-SIGTERM barrier emitted direct underlay IPv4"
  fi
  capture_has_zero_kernel_drops \
    "${guest_result_dir}/restart-lockdown-capture.log" \
    || record_failure "restart-lockdown negative capture dropped packets"

  # Only the explicit standalone operator action may restore direct mode.
  nsenter -t "${client_pid}" -m -n -- env -u SSH_CONNECTION -u SSH_CLIENT \
    RUST_LOG=info \
    "${client}" --release-lockdown --host-state-dir "${client_host_state}" \
    >"${guest_result_dir}/release-lockdown.log" 2>&1 \
    || die 1 "explicit --release-lockdown failed in the journal-bound namespaces"
  grep -q 'durable restart lockdown explicitly released; direct networking restored' \
    "${guest_result_dir}/release-lockdown.log" \
    || record_failure "explicit release did not log direct-network restoration"
  local released_lockdown_wal="absent" released_main_wal="absent"
  local released_exact_table="absent" released_table_census="absent"
  if [[ -e "${lockdown_wal}" || -L "${lockdown_wal}" ]]; then
    released_lockdown_wal="present"
    record_failure "explicit release left the restart-lockdown WAL"
  fi
  if [[ -e "${client_host_state}/host-state-v2.json" \
    || -L "${client_host_state}/host-state-v2.json" ]]; then
    released_main_wal="present"
    record_failure "explicit release left the main host-state WAL"
  fi
  if ip netns exec "${ns_client}" nft list table inet "${lockdown_table}" \
    >/dev/null 2>&1; then
    released_exact_table="present"
    record_failure "explicit release left the journaled restart-lockdown table"
  fi
  if ip netns exec "${ns_client}" nft list tables \
    | grep -Eq '^table inet sp_lock_[0-9a-f]{32}$'; then
    released_table_census="present"
    record_failure "explicit release left an unexpected restart-lockdown table"
  fi
  {
    printf 'expected_table=%s\n' "${lockdown_table}"
    printf 'expected_table_handle=%s\n' "${lockdown_handle}"
    printf 'restart_lockdown_wal_after_release=%s\n' "${released_lockdown_wal}"
    printf 'main_host_wal_after_release=%s\n' "${released_main_wal}"
    printf 'exact_table_after_release=%s\n' "${released_exact_table}"
    printf 'sp_lock_table_census_after_release=%s\n' "${released_table_census}"
  } >"${guest_result_dir}/restart-lockdown-release.env"
  timeout 5 ip netns exec "${ns_client}" curl -fsS \
    http://10.231.0.1:18081/health.txt \
    >"${guest_result_dir}/direct-underlay-after-release.txt" \
    || record_failure "direct underlay baseline was not restored after explicit release"
  grep -qxF "${marker}" \
    "${guest_result_dir}/direct-underlay-after-release.txt" 2>/dev/null \
    || record_failure "direct underlay payload mismatched after explicit release"
  ip netns exec "${ns_client}" ping -c 1 -W 1 10.233.0.1 \
    >"${guest_result_dir}/c1-ipv4-canary-after-release.txt" \
    || record_failure "c1 IPv4 canary was not restored after explicit release"
  ip netns exec "${ns_client}" ping -6 -c 1 -W 1 2001:db8:231::1 \
    >"${guest_result_dir}/c0-ipv6-canary-after-release.txt" \
    || record_failure "c0 IPv6 canary was not restored after explicit release"
  ip netns exec "${ns_client}" ping -6 -c 1 -W 1 2001:db8:233::1 \
    >"${guest_result_dir}/c1-ipv6-canary-after-release.txt" \
    || record_failure "c1 IPv6 canary was not restored after explicit release"
  require_ipv6_canary_state_unchanged after-release \
    || record_failure "explicit release changed the connected IPv6 canary state"
  ip -n "${ns_client}" route show \
    >"${guest_result_dir}/client-routes-after-release.txt"
  grep -q '^default via 10.233.0.1 dev c1' \
    "${guest_result_dir}/client-routes-after-release.txt" \
    || record_failure "generation-2 c1 direct-route baseline was not restored"

  : >"${guest_work_dir}/wrapper-exit"
  stop_role_record "${client_record}" || true
  if proc_starttime "${client_pid}" >/dev/null 2>&1; then
    record_failure "client wrapper remained after explicit release"
  fi

  stop_role_record "${server_record}" || true
  stop_role_record "${cover_record}" || true
  stop_role_record "${dns_record}" || true
  stop_role_record "${iperf_record}" || true
  stop_role_record "${http_record}" || true
  stop_role_record "${canary_record}" || true
  if ip -n "${ns_server}" link show sptuns >/dev/null 2>&1; then
    record_failure "server TUN remained after graceful stop"
  fi
  local ss_output
  if ss_output="$(for ns in "${ns_client}" "${ns_router}" "${ns_server}" "${ns_sink}"; do \
      ip netns exec "${ns}" ss -H -lntup; done)" && [[ -n "${ss_output}" ]]; then
    printf '%s\n' "${ss_output}" >"${guest_result_dir}/unexpected-listeners.txt"
    record_failure "owned namespace listener remained after graceful stop"
  fi

  printf '%s\n' "${guest_failures:-<none>}" >"${guest_result_dir}/test-failures.txt"
  # The EXIT trap performs identity-checked namespace cleanup, guest-root
  # comparison, secret deletion, checksums and final verdict.
}

run_self_test() (
  set -Eeuo pipefail
  local temporary identity table owner status child_pid child_gone=0 repo_root
  local self_uid self_gid gnu_stat
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/shadowpipe-full-tun-selftest.XXXXXX")"
  temporary="$(cd -- "${temporary}" && pwd -P)"
  trap 'rm -rf -- "${temporary}"' EXIT
  repo_root="$(cd -- "$(dirname -- "$0")/../.." && pwd -P)"
  self_uid="$(id -u)"
  self_gid="$(id -g)"
  create_source_provenance_manifest "${repo_root}" \
    "${temporary}/source-before.sha256" "tests/tun/run-orbstack-full-tun.sh"
  verify_source_provenance_manifest "${repo_root}" \
    "${temporary}/source-before.sha256" "${temporary}/source-after.sha256" \
    "tests/tun/run-orbstack-full-tun.sh"

  printf '%s\n' \
    '{"record":{"id":"opaque-A","name":"sptun-fixture","state":"stopped","config":{"isolated":true,"isolate_network":true,"forward_ssh_agent":false,"http_port":0,"https_port":0,"default_username":"fixture","mounts":[]},"future":true},"future_root":1}' \
    >"${temporary}/orb-info.json"
  [[ "$(orb_info_field "${temporary}/orb-info.json" \
    sptun-fixture opaque-A stopped id)" == opaque-A ]] \
    || die 1 "self-test did not accept a bound opaque OrbStack ID"
  [[ "$(orb_info_field "${temporary}/orb-info.json" \
    sptun-fixture opaque-A stopped default_username)" == fixture ]] \
    || die 1 "self-test did not derive the bound safe default username"
  if orb_info_field "${temporary}/orb-info.json" \
    sptun-fixture opaque-B stopped id >/dev/null 2>&1; then
    die 1 "self-test accepted OrbStack name reuse with a different ID"
  fi
  if orb_info_field "${temporary}/orb-info.json" \
    sptun-fixture opaque-A running id >/dev/null 2>&1; then
    die 1 "self-test accepted an unexpected OrbStack state"
  fi
  printf '%s\n' \
    '{"record":{"id":"opaque-A","id":"opaque-B","name":"sptun-fixture","state":"stopped"}}' \
    >"${temporary}/orb-info-duplicate.json"
  if orb_info_field "${temporary}/orb-info-duplicate.json" \
    sptun-fixture '' stopped id >/dev/null 2>&1; then
    die 1 "self-test accepted duplicate OrbStack JSON members"
  fi
  printf '%s\n' \
    '{"record":{"id":"opaque ID","name":"sptun-fixture","state":"stopped"}}' \
    >"${temporary}/orb-info-space.json"
  if orb_info_field "${temporary}/orb-info-space.json" \
    sptun-fixture '' stopped id >/dev/null 2>&1; then
    die 1 "self-test accepted an OrbStack ID containing a space"
  fi
  printf '%s\n' \
    '{"record":{"id":"opaque-A","name":"sptun-fixture","state":"stopped","config":{"isolated":false,"isolate_network":true,"forward_ssh_agent":false,"http_port":0,"https_port":0,"default_username":"fixture"}}}' \
    >"${temporary}/orb-info-not-isolated.json"
  if orb_info_field "${temporary}/orb-info-not-isolated.json" \
    sptun-fixture opaque-A stopped id >/dev/null 2>&1; then
    die 1 "self-test accepted a non-isolated OrbStack machine"
  fi
  printf '%s\n' \
    '{"record":{"id":"opaque-A","name":"sptun-fixture","state":"stopped","config":{"isolated":true,"isolate_network":true,"forward_ssh_agent":false,"http_port":0,"https_port":0,"default_username":"fixture","mounts":["/Users"]}}}' \
    >"${temporary}/orb-info-host-mount.json"
  if orb_info_field "${temporary}/orb-info-host-mount.json" \
    sptun-fixture opaque-A stopped id >/dev/null 2>&1; then
    die 1 "self-test accepted an OrbStack machine with a host mount"
  fi
  : >"${temporary}/orb-absent"
  printf '1\n' >"${temporary}/orb-absent.status"
  printf "[-32098] machine not found: 'opaque-A'\n" \
    >"${temporary}/orb-absent.stderr"
  validate_orb_info_absence "${temporary}/orb-absent" opaque-A \
    || die 1 "self-test rejected an exact OrbStack absence record"

  cat >"${temporary}/iptables-save" <<'EOF'
*filter
:OUTPUT ACCEPT [0:0]
:SP4_00112233445566778899 - [0:0]
-A OUTPUT -m comment --comment "shadowpipe:00112233445566778899aabbccddeeff" -j SP4_00112233445566778899
-A SP4_00112233445566778899 -o lo -m comment --comment "shadowpipe:00112233445566778899aabbccddeeff" -j ACCEPT
-A SP4_00112233445566778899 -o sptunc -m comment --comment "shadowpipe:00112233445566778899aabbccddeeff" -j ACCEPT
-A SP4_00112233445566778899 -d 10.232.0.2/32 -p tcp -m tcp --dport 47843 -m comment --comment "shadowpipe:00112233445566778899aabbccddeeff" -j ACCEPT
-A SP4_00112233445566778899 -m comment --comment "shadowpipe:00112233445566778899aabbccddeeff" -j DROP
COMMIT
EOF
  cat >"${temporary}/ip6tables-save" <<'EOF'
*filter
:OUTPUT ACCEPT [0:0]
:SP6_ffeeddccbbaa99887766 - [0:0]
-A OUTPUT -m comment --comment "shadowpipe:00112233445566778899aabbccddeeff" -j SP6_ffeeddccbbaa99887766
-A SP6_ffeeddccbbaa99887766 -o lo -m comment --comment "shadowpipe:00112233445566778899aabbccddeeff" -j ACCEPT
-A SP6_ffeeddccbbaa99887766 -m comment --comment "shadowpipe:00112233445566778899aabbccddeeff" -j DROP
COMMIT
EOF
  validate_active_killswitch_saves \
    "${temporary}/iptables-save" "${temporary}/ip6tables-save" \
    "${temporary}/active-killswitch.json"
  sed 's/-j DROP/-j ACCEPT/' "${temporary}/ip6tables-save" \
    >"${temporary}/ip6tables-save-permissive"
  if validate_active_killswitch_saves \
    "${temporary}/iptables-save" "${temporary}/ip6tables-save-permissive" \
    "${temporary}/active-killswitch-permissive.json" >/dev/null 2>&1; then
    die 1 "self-test accepted a permissive IPv6 kill-switch"
  fi

  printf '%s\n' \
    'create Linux TUN "sptunc" exclusively; an existing interface is never attached or deleted' \
    'Caused by:' \
    '    Device or resource busy (os error 16)' \
    >"${temporary}/tun-collision-ebusy.stderr"
  exclusive_tun_collision_failure 1 \
    "${temporary}/tun-collision-ebusy.stderr" \
    || die 1 "self-test rejected an EBUSY exclusive-TUN collision"
  printf '%s\n' 'TUNSETIFF failed: EEXIST' \
    >"${temporary}/tun-collision-eexist.stderr"
  exclusive_tun_collision_failure 17 \
    "${temporary}/tun-collision-eexist.stderr" \
    || die 1 "self-test rejected an EEXIST exclusive-TUN collision"
  if exclusive_tun_collision_failure 124 \
    "${temporary}/tun-collision-ebusy.stderr"; then
    die 1 "self-test accepted a timed-out named-TUN startup"
  fi
  printf '%s\n' \
    'an existing interface is never attached or deleted' \
    >"${temporary}/tun-collision-context-only.stderr"
  if exclusive_tun_collision_failure 1 \
    "${temporary}/tun-collision-context-only.stderr"; then
    die 1 "self-test accepted context text without an EBUSY/EEXIST errno"
  fi

  if stat --version >/dev/null 2>&1; then
    gnu_stat="$(command -v stat)"
  elif command -v gstat >/dev/null 2>&1 \
    && gstat --version >/dev/null 2>&1; then
    gnu_stat="$(command -v gstat)"
  else
    die 1 "self-test requires GNU stat or gstat for the empty-file wording cell"
  fi
  : >"${temporary}/private-empty"
  chmod 0600 "${temporary}/private-empty"
  [[ "$(LC_ALL=C "${gnu_stat}" -c '%F' "${temporary}/private-empty")" \
    == "regular empty file" ]] \
    || die 1 "self-test did not reproduce GNU stat's regular-empty wording"
  exact_empty_private_regular_file \
    "${temporary}/private-empty" "${self_uid}" "${self_gid}" \
    || die 1 "self-test numeric validator rejected a safe GNU empty file"
  ln -s private-empty "${temporary}/private-empty-symlink"
  if exact_empty_private_regular_file \
    "${temporary}/private-empty-symlink" "${self_uid}" "${self_gid}" \
    2>/dev/null; then
    die 1 "self-test numeric validator accepted a symlink"
  fi
  rm -- "${temporary}/private-empty-symlink"
  chmod 0644 "${temporary}/private-empty"
  if exact_empty_private_regular_file \
    "${temporary}/private-empty" "${self_uid}" "${self_gid}" 2>/dev/null; then
    die 1 "self-test numeric validator accepted mode 0644"
  fi
  chmod 0600 "${temporary}/private-empty"
  printf x >"${temporary}/private-empty"
  if exact_empty_private_regular_file \
    "${temporary}/private-empty" "${self_uid}" "${self_gid}" 2>/dev/null; then
    die 1 "self-test numeric validator accepted non-empty content"
  fi
  : >"${temporary}/private-empty"
  ln "${temporary}/private-empty" "${temporary}/private-empty-hardlink"
  if exact_empty_private_regular_file \
    "${temporary}/private-empty" "${self_uid}" "${self_gid}" 2>/dev/null; then
    die 1 "self-test numeric validator accepted a multiply-linked file"
  fi
  rm -- "${temporary}/private-empty-hardlink"
  exact_empty_private_regular_file \
    "${temporary}/private-empty" "${self_uid}" "${self_gid}" \
    || die 1 "self-test numeric validator did not recover after hardlink removal"

  python3 -I -S - "${temporary}/valid-empty.pcap" \
    "${temporary}/truncated.pcap" <<'PY'
import os
import struct
import sys

valid, truncated = sys.argv[1:]
header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
for path, value in ((valid, header), (truncated, header[:11])):
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(descriptor, value)
    finally:
        os.close(descriptor)
PY
  validate_pcap_file "${temporary}/valid-empty.pcap" \
    || die 1 "self-test rejected a valid empty pcap"
  if validate_pcap_file "${temporary}/truncated.pcap" 2>/dev/null; then
    die 1 "self-test accepted a truncated pcap"
  fi

  printf '%s\n' \
    baseline-one \
    baseline-two \
    'topology changed at network-event generation 7 (DefaultRouteChanged)' \
    'topology changed at network-event generation 7 (DefaultRouteChanged)' \
    >"${temporary}/client.log"
  extract_log_suffix "${temporary}/client.log" 2 \
    "${temporary}/network-restart.log" \
    || die 1 "self-test could not extract a bounded log suffix"
  validate_exact_network_restart_suffix \
    "${temporary}/network-restart.log" DefaultRouteChanged \
    "${temporary}/network-restart.env" \
    || die 1 "self-test rejected an exact default-route restart suffix"
  [[ "$(<"${temporary}/network-restart.env")" \
    == $'network_restart_cause=DefaultRouteChanged\ncause_occurrences=2' ]] \
    || die 1 "self-test normalized the exact network restart cause incorrectly"
  printf '%s\n' \
    'topology changed at network-event generation 8 (InterfaceSetChanged, DefaultRouteChanged)' \
    >"${temporary}/mixed-network-restart.log"
  if validate_exact_network_restart_suffix \
    "${temporary}/mixed-network-restart.log" DefaultRouteChanged \
    "${temporary}/mixed-network-restart.env" 2>/dev/null; then
    die 1 "self-test accepted a mixed network restart cause"
  fi

  ln -s target "${temporary}/readlink-ok"
  [[ "$(read_proc_symlink "${temporary}/readlink-ok")" == target ]] \
    || die 1 "self-test proc symlink classifier lost a valid target"
  set +e
  read_proc_symlink "${temporary}/readlink-absent" >/dev/null 2>&1
  status=$?
  set -e
  (( status == 2 )) \
    || die 1 "self-test proc symlink classifier did not map ENOENT to absence"
  : >"${temporary}/readlink-not-a-link"
  set +e
  read_proc_symlink "${temporary}/readlink-not-a-link" >/dev/null 2>&1
  status=$?
  set -e
  (( status == 1 )) \
    || die 1 "self-test proc symlink classifier accepted a non-symlink"

  set +e
  # shellcheck disable=SC2016
  run_bounded 0.1 /bin/bash -c \
    'trap "exit 0" TERM; (trap "" TERM HUP; sleep 30) & printf "%s\n" "$!" >"$1"; wait' \
    _ "${temporary}/bounded-child.pid" \
    >"${temporary}/timeout.out" 2>"${temporary}/timeout.err"
  status=$?
  set -e
  [[ "${status}" == 124 ]] \
    || die 1 "self-test bounded process group did not reach a clean timeout"
  IFS= read -r child_pid <"${temporary}/bounded-child.pid"
  [[ "${child_pid}" =~ ^[1-9][0-9]*$ ]] \
    || die 1 "self-test did not record the TERM-resistant descendant"
  for _ in {1..20}; do
    if ! kill -0 "${child_pid}" 2>/dev/null; then
      child_gone=1
      break
    fi
    run_bounded 1 sleep 0.05 >/dev/null 2>&1 || true
  done
  [[ "${child_gone}" == 1 ]] \
    || die 1 "self-test left a TERM-resistant process-group descendant"

  set +e
  run_recorded_limited 5 "${temporary}/recorded-stdout-cap" 32 32 \
    python3 -I -S -c 'import sys; sys.stdout.write("x" * 4096)'
  status=$?
  set -e
  [[ "${status}" == 125 \
    && "$(stat -f '%z' "${temporary}/recorded-stdout-cap")" == 33 \
    && "$(stat -f '%z' "${temporary}/recorded-stdout-cap.stderr")" -le 32 ]] \
    || die 1 "self-test did not fail closed at the recorded stdout byte cap"
  set +e
  run_recorded_limited 5 "${temporary}/recorded-stderr-cap" 32 32 \
    python3 -I -S -c 'import sys; sys.stderr.write("y" * 4096)'
  status=$?
  set -e
  [[ "${status}" == 125 \
    && "$(stat -f '%z' "${temporary}/recorded-stderr-cap")" -le 32 \
    && "$(stat -f '%z' "${temporary}/recorded-stderr-cap.stderr")" == 33 ]] \
    || die 1 "self-test did not fail closed at the recorded stderr byte cap"
  set +e
  # shellcheck disable=SC2016
  run_recorded_limited 5 "${temporary}/recorded-exit" 32 32 \
    /bin/sh -c 'printf exact-output; printf exact-error >&2; exit 7'
  status=$?
  set -e
  [[ "${status}" == 7 \
    && "$(<"${temporary}/recorded-exit")" == exact-output \
    && "$(<"${temporary}/recorded-exit.stderr")" == exact-error \
    && "$(<"${temporary}/recorded-exit.status")" == 7 ]] \
    || die 1 "self-test lost the exact bounded command exit/output contract"
  if find "${temporary}" -maxdepth 1 -name '*.pipes.*' -print -quit \
    | grep -q .; then
    die 1 "self-test left a recorded-command FIFO directory"
  fi

  mkdir "${temporary}/dirty-git"
  git -C "${temporary}/dirty-git" init -q
  git -C "${temporary}/dirty-git" config user.name shadowpipe-selftest
  git -C "${temporary}/dirty-git" config user.email selftest@invalid
  printf tracked >"${temporary}/dirty-git/tracked"
  git -C "${temporary}/dirty-git" add tracked
  git -C "${temporary}/dirty-git" commit -qm initial
  printf secret >"${temporary}/dirty-git/private-token-name-do-not-publish"
  set +e
  capture_git_checkout_proof \
    "${temporary}/dirty-git" "${temporary}/dirty-git-proof" >/dev/null 2>&1
  status=$?
  set -e
  (( status != 0 )) \
    || die 1 "self-test accepted a dirty Git checkout"
  if grep -R -Fq 'private-token-name-do-not-publish' \
    "${temporary}/dirty-git-proof"; then
    die 1 "self-test leaked a dirty Git filename into failure evidence"
  fi

  printf '1\tabsent\tstopped\n2\tcreating\tstopped\n3\trunning\tstopped\n4\trunning\tstopped\n5\trunning\tstopped\n6\trunning\tstopped\n' \
    >"${temporary}/quiescence.tsv"
  validate_clone_quiescence_trace "${temporary}/quiescence.tsv" 4 stable_any
  printf '1\tabsent\tstopped\n2\tabsent\tstopped\n3\tabsent\tstopped\n4\tabsent\tstopped\n' \
    >"${temporary}/quiescence.tsv"
  validate_clone_quiescence_trace "${temporary}/quiescence.tsv" 4 absent_all
  printf '1\tabsent\tstopped\n2\tabsent\tstopped\n3\trunning\tstopped\n4\tabsent\tstopped\n5\tabsent\tstopped\n6\tabsent\tstopped\n7\tabsent\tstopped\n' \
    >"${temporary}/quiescence.tsv"
  if validate_clone_quiescence_trace \
    "${temporary}/quiescence.tsv" 4 absent_all; then
    die 1 "self-test accepted a late clone appearance"
  fi
  printf '1\tabsent\tstopped\n2\tabsent\trunning\n3\tabsent\tstopped\n4\tabsent\tstopped\n' \
    >"${temporary}/quiescence.tsv"
  if validate_clone_quiescence_trace \
    "${temporary}/quiescence.tsv" 4 absent_all; then
    die 1 "self-test accepted a source VM state transition"
  fi
  validate_magic "${MAGIC_DEFAULT}"
  if validate_magic 4294967296 2>/dev/null; then
    die 1 "self-test accepted a SHADOWPIPE_MAGIC value above u32"
  fi

  printf '%s\n' \
    "/opt/homebrew/bin/sing-box run -c ${EXPECTED_SINGBOX_CONFIG} -D ${EXPECTED_SINGBOX_DIRECTORY}" \
    >"${temporary}/sing-box.command"
  validate_singbox_command "${temporary}/sing-box.command"
  printf '%s\n' \
    "sing-box run -c ${EXPECTED_SINGBOX_CONFIG} -D ${EXPECTED_SINGBOX_DIRECTORY}" \
    >"${temporary}/sing-box.command"
  validate_singbox_command "${temporary}/sing-box.command"
  printf '%s\n' '/opt/homebrew/bin/sing-box run -c /tmp/foreign.json' \
    >"${temporary}/sing-box.foreign"
  if validate_singbox_command "${temporary}/sing-box.foreign" 2>/dev/null; then
    die 1 "self-test accepted a foreign sing-box argv"
  fi
  self_test_singbox_observer "${temporary}/singbox-observer"
  printf '#!/bin/sh\nexit 0\n' >"${temporary}/mock-sing-box"
  chmod 0700 "${temporary}/mock-sing-box"
  printf '%s\n' "${temporary}/mock-sing-box" \
    >"${temporary}/mock-proc-pidpath"
  validate_singbox_binary_path "${temporary}/mock-proc-pidpath"
  printf '%s\n' relative/sing-box >"${temporary}/foreign-proc-pidpath"
  if validate_singbox_binary_path "${temporary}/foreign-proc-pidpath" \
    2>/dev/null; then
    die 1 "self-test accepted a non-absolute mocked proc_pidpath result"
  fi

  local pf_case name
  for pf_case in pf-permission pf-observed pf-tampered; do
    mkdir "${temporary}/${pf_case}"
    for name in rules nat info; do
      : >"${temporary}/${pf_case}/${name}.stdout"
      : >"${temporary}/${pf_case}/${name}.stderr"
      printf '0\n' >"${temporary}/${pf_case}/${name}.status"
    done
  done
  for name in rules nat info; do
    printf 'pfctl: /dev/pf: Permission denied\n' \
      >"${temporary}/pf-permission/${name}.stderr"
    printf '1\n' >"${temporary}/pf-permission/${name}.status"
  done
  classify_pf_runtime "${temporary}/pf-permission"
  grep -qx 'pf_runtime_observed=false' \
    "${temporary}/pf-permission/scope.env"
  classify_pf_runtime "${temporary}/pf-observed"
  grep -qx 'pf_runtime_observed=true' "${temporary}/pf-observed/scope.env"
  printf 'pfctl: unexpected error\n' \
    >"${temporary}/pf-tampered/rules.stderr"
  printf '1\n' >"${temporary}/pf-tampered/rules.status"
  if classify_pf_runtime "${temporary}/pf-tampered" 2>/dev/null; then
    die 1 "self-test accepted an unrecognized PF observation outcome"
  fi

  mkdir "${temporary}/evidence"
  printf '%s\n' evidence >"${temporary}/evidence/value.txt"
  seal_evidence "${temporary}/evidence"
  (cd "${temporary}/evidence" && sha256sum -c checksums.sha256 >/dev/null)
  mkdir "${temporary}/symlink-evidence"
  ln -s /etc "${temporary}/symlink-evidence/foreign"
  if seal_evidence "${temporary}/symlink-evidence" 2>/dev/null; then
    die 1 "self-test sealed a symlinked evidence tree"
  fi
  mkdir "${temporary}/multilink-evidence"
  printf x >"${temporary}/multilink-source"
  ln "${temporary}/multilink-source" "${temporary}/multilink-evidence/value"
  if seal_evidence "${temporary}/multilink-evidence" 2>/dev/null; then
    die 1 "self-test sealed a multiply-linked evidence file"
  fi

  local stream_token stream_run stream_clone
  stream_token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  stream_run=selftest-stream
  stream_clone=sptun-selftest-stream
  mkdir "${temporary}/stream-source" "${temporary}/stream-source/subdir"
  printf 'shadowpipe-full-tun-result-owner-v1\nrun_id=%s\nclone_vm=%s\ntoken=%s\n' \
    "${stream_run}" "${stream_clone}" "${stream_token}" \
    >"${temporary}/stream-source/.shadowpipe-full-tun-owner"
  printf '%s\n' streamed-evidence \
    >"${temporary}/stream-source/subdir/value.txt"
  seal_evidence "${temporary}/stream-source"
  python3 -I -S - "${temporary}/stream-source" \
    "${temporary}/stream-valid.tar" "${temporary}/stream-link.tar" \
    "${temporary}/stream-traversal.tar" "${temporary}/stream-oversized.tar" \
    "${temporary}/stream-compressed.tar.gz" "${MAX_EVIDENCE_BYTES}" <<'PY'
import os
import sys
import tarfile

(source, valid_path, link_path, traversal_path, oversized_path,
 compressed_path, maximum) = sys.argv[1:]

def write_source(path, mode):
    with tarfile.open(path, mode, format=tarfile.PAX_FORMAT) as archive:
        for current, directories, files in os.walk(source):
            directories.sort()
            files.sort()
            relative_current = os.path.relpath(current, source)
            if relative_current != ".":
                item = tarfile.TarInfo(relative_current)
                item.type = tarfile.DIRTYPE
                item.mode = 0o700
                item.uid = item.gid = 0
                archive.addfile(item)
            for name in files:
                source_path = os.path.join(current, name)
                relative = os.path.relpath(source_path, source)
                item = archive.gettarinfo(source_path, arcname=relative)
                item.mode = 0o600
                item.uid = item.gid = 0
                with open(source_path, "rb") as stream:
                    archive.addfile(item, stream)

write_source(valid_path, "w")
write_source(compressed_path, "w:gz")
with tarfile.open(link_path, "w", format=tarfile.PAX_FORMAT) as archive:
    item = tarfile.TarInfo("foreign-link")
    item.type = tarfile.SYMTYPE
    item.linkname = "/etc"
    item.mode = 0o600
    item.uid = item.gid = 0
    archive.addfile(item)
with tarfile.open(traversal_path, "w", format=tarfile.PAX_FORMAT) as archive:
    item = tarfile.TarInfo("../escape")
    item.size = 0
    item.mode = 0o600
    item.uid = item.gid = 0
    archive.addfile(item, fileobj=None)
item = tarfile.TarInfo("oversized")
item.size = int(maximum, 10) + 1
item.mode = 0o600
item.uid = item.gid = 0
with open(oversized_path, "xb") as stream:
    stream.write(item.tobuf(format=tarfile.USTAR_FORMAT))
    stream.write(b"\0" * 1024)
PY
  extract_guest_evidence_archive "${temporary}/stream-valid.tar" \
    "${temporary}/stream-extracted" "${stream_run}" "${stream_clone}" \
    "${stream_token}"
  mkdir "${temporary}/stream-reserved"
  copy_tree_no_follow \
    "${temporary}/stream-source/.shadowpipe-full-tun-owner" \
    "${temporary}/stream-reserved/.shadowpipe-full-tun-owner"
  merge_guest_evidence_stage "${temporary}/stream-extracted" \
    "${temporary}/stream-reserved" \
    "${temporary}/stream-reserved/.shadowpipe-full-tun-owner"
  grep -qx streamed-evidence \
    "${temporary}/stream-reserved/subdir/value.txt" \
    || die 1 "self-test lost streamed guest evidence during safe merge"
  (cd "${temporary}/stream-reserved" \
    && sha256sum -c checksums.sha256 >/dev/null) \
    || die 1 "self-test merged guest evidence with invalid checksums"
  if extract_guest_evidence_archive "${temporary}/stream-link.tar" \
    "${temporary}/stream-link-extracted" "${stream_run}" "${stream_clone}" \
    "${stream_token}" 2>/dev/null; then
    die 1 "self-test extracted a symlink from returned guest evidence"
  fi
  if extract_guest_evidence_archive "${temporary}/stream-traversal.tar" \
    "${temporary}/stream-traversal-extracted" "${stream_run}" \
    "${stream_clone}" "${stream_token}" 2>/dev/null; then
    die 1 "self-test extracted a traversal path from returned guest evidence"
  fi
  if extract_guest_evidence_archive "${temporary}/stream-oversized.tar" \
    "${temporary}/stream-oversized-extracted" "${stream_run}" \
    "${stream_clone}" "${stream_token}" 2>/dev/null; then
    die 1 "self-test extracted returned guest evidence above the byte bound"
  fi
  if extract_guest_evidence_archive "${temporary}/stream-compressed.tar.gz" \
    "${temporary}/stream-compressed-extracted" "${stream_run}" \
    "${stream_clone}" "${stream_token}" 2>/dev/null; then
    die 1 "self-test accepted a compressed guest evidence archive"
  fi

  write_full_status "${temporary}/status.failed" failed valid valid valid true \
    valid valid failed stopped false released 1
  grep -qx 'overall_status=failed' "${temporary}/status.failed"
  write_full_result "${temporary}/published" valid sptun-selftest false
  write_full_result "${temporary}/failure-source" failed sptun-selftest false
  replace_regular_from_file "${temporary}/failure-source" "${temporary}/published"
  if grep -q 'Verdict: \*\*PASS\*\*' "${temporary}/published"; then
    die 1 "self-test retained a stale PASS after failure publication"
  fi

  printf '%s\n' '32 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    >"${temporary}/fingerprints"
  printf clean >"${temporary}/clean.log"
  scan_fingerprinted_material "${temporary}/fingerprints" \
    "${temporary}/clean.scan" "${temporary}/clean.log"

  mkdir "${temporary}/secret-scan-clean" "${temporary}/secret-scan-leak"
  printf '%s\n' \
    '{"ed25519_seed":"1111111111111111111111111111111111111111111111111111111111111111","psk":"2222222222222222222222222222222222222222222222222222222222222222"}' \
    >"${temporary}/credential.json"
  printf '%s\n' \
    '{"mlkem_secret":"3333333333333333333333333333333333333333333333333333333333333333"}' \
    >"${temporary}/keys.json"
  printf '%s\n' a1b2c3d4e5f60718 >"${temporary}/short-ids"
  printf '%s\n' \
    '-----BEGIN PRIVATE KEY-----' \
    'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB' \
    '-----END PRIVATE KEY-----' >"${temporary}/cover.key"
  printf clean >"${temporary}/secret-scan-clean/value"
  evidence_has_private_material "${temporary}/secret-scan-clean" \
    "${temporary}/generated-fingerprints" "${self_uid}" "${self_gid}" \
    credential "${temporary}/credential.json" \
    server_keys "${temporary}/keys.json" \
    raw "${temporary}/short-ids" raw "${temporary}/cover.key"
  printf '%s\n' A1B2C3D4E5F60718 \
    >"${temporary}/secret-scan-leak/renamed-public-looking.txt"
  printf '%s\n' \
    'shadowpipe://public@example.invalid:443?sni=cover.invalid&sid=a1b2c3d4e5f60718&fp=public' \
    >"${temporary}/secret-scan-leak/client-argv-looking.log"
  if evidence_has_private_material "${temporary}/secret-scan-leak" \
    "${temporary}/leak-fingerprints" "${self_uid}" "${self_gid}" \
    credential "${temporary}/credential.json" \
    server_keys "${temporary}/keys.json" \
    raw "${temporary}/short-ids" raw "${temporary}/cover.key" \
    >"${temporary}/expected-secret-leaks.txt"; then
    die 1 "self-test missed an encoded REALITY short-id in evidence"
  fi
  grep -qx 'renamed-public-looking.txt' \
    "${temporary}/expected-secret-leaks.txt"
  grep -qx 'client-argv-looking.log' \
    "${temporary}/expected-secret-leaks.txt"
  mkdir "${temporary}/secret-source-symlink-evidence"
  printf clean >"${temporary}/secret-source-symlink-evidence/value"
  ln -s credential.json "${temporary}/credential-symlink.json"
  if evidence_has_private_material \
    "${temporary}/secret-source-symlink-evidence" \
    "${temporary}/symlink-source-fingerprints" "${self_uid}" "${self_gid}" \
    credential "${temporary}/credential-symlink.json" \
    server_keys "${temporary}/keys.json" \
    raw "${temporary}/short-ids" 2>/dev/null; then
    die 1 "self-test private-material scanner followed a JSON source symlink"
  fi

  mkdir "${temporary}/pre-replay-work" "${temporary}/pre-replay-evidence"
  create_private_material_scan_canary \
    "${temporary}/pre-replay-work/.private-material-scan-canary"
  printf '%s\n' a1b2c3d4e5f60718 \
    >"${temporary}/pre-replay-work/reality-short-ids"
  printf clean >"${temporary}/pre-replay-evidence/value"
  scan_cleanup_private_material \
    "${temporary}/pre-replay-evidence" "${temporary}/pre-replay-work" \
    "${temporary}/pre-replay-evidence/reality-replay-store-stage.env" \
    "${temporary}/pre-replay-evidence/private-material-stage.env" \
    "${temporary}/pre-replay-evidence/.private-material-fingerprints" \
    "${temporary}/pre-replay-evidence/private-material-leak-paths.txt" \
    "${self_uid}" "${self_gid}" \
    || die 1 "self-test converted a clean pre-replay failure into cleanup failure"
  grep -qx 'replay_store_stage=not_created_before_failure' \
    "${temporary}/pre-replay-evidence/private-material-stage.env"
  grep -qx 'replay_store_marker=absent' \
    "${temporary}/pre-replay-evidence/private-material-stage.env"
  grep -qx 'replay_store_artifact=absent' \
    "${temporary}/pre-replay-evidence/private-material-stage.env"
  grep -qx 'replay_store_lock=absent' \
    "${temporary}/pre-replay-evidence/private-material-stage.env"
  grep -qx 'stage_requirements=valid' \
    "${temporary}/pre-replay-evidence/private-material-stage.env"
  grep -qx 'private_material_byte_scan=valid' \
    "${temporary}/pre-replay-evidence/private-material-stage.env"
  grep -qx 'private_material_scan=valid' \
    "${temporary}/pre-replay-evidence/private-material-stage.env"

  mkdir "${temporary}/pre-marker-lock-work" \
    "${temporary}/pre-marker-lock-evidence"
  create_private_material_scan_canary \
    "${temporary}/pre-marker-lock-work/.private-material-scan-canary"
  : >"${temporary}/pre-marker-lock-work/reality-replay-v1.bin.lock"
  printf clean >"${temporary}/pre-marker-lock-evidence/value"
  scan_cleanup_private_material \
    "${temporary}/pre-marker-lock-evidence" \
    "${temporary}/pre-marker-lock-work" \
    "${temporary}/pre-marker-lock-evidence/reality-replay-store-stage.env" \
    "${temporary}/pre-marker-lock-evidence/private-material-stage.env" \
    "${temporary}/pre-marker-lock-evidence/.private-material-fingerprints" \
    "${temporary}/pre-marker-lock-evidence/private-material-leak-paths.txt" \
    "${self_uid}" "${self_gid}" \
    || die 1 "self-test treated an empty replay lock as private material"
  grep -qx 'replay_store_stage=artifacts_present_before_durable_marker' \
    "${temporary}/pre-marker-lock-evidence/private-material-stage.env"
  grep -qx 'replay_store_lock=present_valid' \
    "${temporary}/pre-marker-lock-evidence/private-material-stage.env"
  grep -qx 'private_material_scan=valid' \
    "${temporary}/pre-marker-lock-evidence/private-material-stage.env"

  mkdir "${temporary}/pre-replay-leak-work" \
    "${temporary}/pre-replay-leak-evidence"
  create_private_material_scan_canary \
    "${temporary}/pre-replay-leak-work/.private-material-scan-canary"
  printf '%s\n' a1b2c3d4e5f60718 \
    >"${temporary}/pre-replay-leak-work/reality-short-ids"
  printf '%s\n' A1B2C3D4E5F60718 \
    >"${temporary}/pre-replay-leak-evidence/renamed-secret.log"
  if scan_cleanup_private_material \
    "${temporary}/pre-replay-leak-evidence" \
    "${temporary}/pre-replay-leak-work" \
    "${temporary}/pre-replay-leak-evidence/reality-replay-store-stage.env" \
    "${temporary}/pre-replay-leak-evidence/private-material-stage.env" \
    "${temporary}/pre-replay-leak-evidence/.private-material-fingerprints" \
    "${temporary}/pre-replay-leak-evidence/private-material-leak-paths.txt" \
    "${self_uid}" "${self_gid}"; then
    die 1 "self-test hid a pre-replay private-material leak"
  fi
  grep -qx 'renamed-secret.log' \
    "${temporary}/pre-replay-leak-evidence/private-material-leak-paths.txt"
  grep -qx 'replay_store_stage=not_created_before_failure' \
    "${temporary}/pre-replay-leak-evidence/private-material-stage.env"
  grep -qx 'private_material_byte_scan=failed' \
    "${temporary}/pre-replay-leak-evidence/private-material-stage.env"
  grep -qx 'private_material_scan=failed' \
    "${temporary}/pre-replay-leak-evidence/private-material-stage.env"

  mkdir "${temporary}/marked-missing-work" \
    "${temporary}/marked-missing-evidence"
  create_private_material_scan_canary \
    "${temporary}/marked-missing-work/.private-material-scan-canary"
  publish_replay_store_stage_marker \
    "${temporary}/marked-missing-evidence/reality-replay-store-stage.env"
  validate_replay_store_stage_marker \
    "${temporary}/marked-missing-evidence/reality-replay-store-stage.env" \
    "${self_uid}" "${self_gid}"
  printf clean >"${temporary}/marked-missing-evidence/value"
  if scan_cleanup_private_material \
    "${temporary}/marked-missing-evidence" "${temporary}/marked-missing-work" \
    "${temporary}/marked-missing-evidence/reality-replay-store-stage.env" \
    "${temporary}/marked-missing-evidence/private-material-stage.env" \
    "${temporary}/marked-missing-evidence/.private-material-fingerprints" \
    "${temporary}/marked-missing-evidence/private-material-leak-paths.txt" \
    "${self_uid}" "${self_gid}"; then
    die 1 "self-test accepted a durable replay marker without its artifacts"
  fi
  grep -qx 'replay_store_stage=created_and_durably_marked' \
    "${temporary}/marked-missing-evidence/private-material-stage.env"
  grep -qx 'replay_store_marker=valid' \
    "${temporary}/marked-missing-evidence/private-material-stage.env"
  grep -qx 'replay_store_artifact=absent' \
    "${temporary}/marked-missing-evidence/private-material-stage.env"
  grep -qx 'replay_store_lock=absent' \
    "${temporary}/marked-missing-evidence/private-material-stage.env"
  grep -qx 'stage_requirements=failed' \
    "${temporary}/marked-missing-evidence/private-material-stage.env"
  grep -qx 'private_material_byte_scan=valid' \
    "${temporary}/marked-missing-evidence/private-material-stage.env"
  grep -qx 'private_material_scan=failed' \
    "${temporary}/marked-missing-evidence/private-material-stage.env"

  identity=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  table="sp_lock_${identity}"
  owner="shadowpipe-lockdown-v1:${identity}"
  python3 -I -S - "${temporary}" "${identity}" "${table}" "${owner}" <<'PY'
import json
import os
import sys
root, identity, table, owner = sys.argv[1:]
wal = {"identity": identity, "table_handle": 7}
listing = {"nftables": [
    {"metainfo": {}},
    {"table": {"family": "inet", "name": table, "handle": 7, "comment": owner}},
    {"chain": {"family": "inet", "table": table, "name": "sp_output", "handle": 8,
               "type": "filter", "hook": "output", "prio": -400, "policy": "drop",
               "comment": owner + ":chain"}},
    {"rule": {"family": "inet", "table": table, "chain": "sp_output", "handle": 9,
              "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}},
                                    "right": "lo"}}, {"accept": None}],
              "comment": owner + ":loopback"}},
    {"rule": {"family": "inet", "table": table, "chain": "sp_output", "handle": 10,
              "expr": [{"drop": None}], "comment": owner + ":terminal-drop"}},
]}
census = {"nftables": [{"metainfo": {}}, {"table": {"family": "inet", "name": table}}]}
for name, value in (("wal.json", wal), ("nft.json", listing), ("census.json", census)):
    with open(os.path.join(root, name), "x", encoding="utf-8") as stream:
        json.dump(value, stream, separators=(",", ":"))
listing["nftables"][-1]["rule"]["expr"] = [{"accept": None}]
with open(os.path.join(root, "nft-tampered.json"), "x", encoding="utf-8") as stream:
    json.dump(listing, stream, separators=(",", ":"))
PY
  verify_no_control_lockdown_snapshot "${temporary}/wal.json" \
    "${temporary}/nft.json" "${temporary}/census.json"
  if verify_no_control_lockdown_snapshot "${temporary}/wal.json" \
    "${temporary}/nft-tampered.json" "${temporary}/census.json" \
    2>/dev/null; then
    die 1 "self-test accepted a permissive lockdown rule"
  fi
  say "run-orbstack-full-tun self-test: PASS"
)

main() {
  if [[ "${1:-}" == "--guest" ]]; then
    shift
    guest_main "$@"
  else
    if [[ "${1:-}" == "--self-test" ]]; then
      [[ "$#" == 1 ]] || die "${EX_USAGE}" "--self-test accepts no extra arguments"
      run_self_test
      return
    fi
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
      usage
      return 0
    fi
    host_main "$@"
  fi
}

main "$@"
