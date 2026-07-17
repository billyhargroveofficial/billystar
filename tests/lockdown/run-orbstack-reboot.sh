#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Real systemd-PID-1 userspace-boot validation for the durable Linux restart
# lockdown. OrbStack machines share a Linux kernel, so this is deliberately not
# described as a dedicated-kernel, initrd, power-loss, or hardware reboot test.
# The script is destructive only inside a uniquely named disposable isolated
# OrbStack clone. macOS networking and the live sing-box process are read-only
# evidence surfaces.

readonly EX_USAGE=64
readonly EX_UNAVAILABLE=69
readonly SOURCE_DEFAULT=shadowpipe-lab-base
readonly MAGIC_DEFAULT=0x50334852
readonly HOST_COMMAND_TIMEOUT=30
readonly GUEST_COMMAND_TIMEOUT=120
readonly ORB_CLONE_TIMEOUT=900
readonly ORB_START_TIMEOUT=180
readonly ORB_DELETE_TIMEOUT=300
readonly BUILD_TIMEOUT=1800
readonly BOOT_READY_TIMEOUT=180
readonly SOURCE_TRANSFER_TIMEOUT=300
readonly VENDOR_CREATE_TIMEOUT=1800
readonly VENDOR_TRANSFER_TIMEOUT=900
readonly VENDOR_EXTRACT_TIMEOUT=900
readonly CARGO_METADATA_TIMEOUT=300
readonly MAX_SOURCE_ARCHIVE_BYTES=$((64 * 1024 * 1024))
readonly MAX_SOURCE_EXPANDED_BYTES=$((128 * 1024 * 1024))
readonly MAX_SOURCE_ARCHIVE_STDERR_BYTES=$((64 * 1024))
readonly MAX_VENDOR_ARCHIVE_BYTES=$((256 * 1024 * 1024))
readonly MAX_VENDOR_EXPANDED_BYTES=$((768 * 1024 * 1024))
readonly MAX_VENDOR_MEMBERS=50000
readonly OWNERSHIP_MARKER=.shadowpipe-lockdown-reboot-owner
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
Usage:
  SHADOWPIPE_DISPOSABLE_LOCKDOWN_REBOOT=1 \
    tests/lockdown/run-orbstack-reboot.sh [shadowpipe-lab-base]

  tests/lockdown/run-orbstack-reboot.sh --self-test

Only the stopped capability-isolated and network-isolated
shadowpipe-lab-base is accepted. A pinned clean pushed-main git archive and a
separately provenance-bound, checksum-validated Cargo vendor bundle enter a
disposable clone over bounded stdin. Build and install stay guest-local under
a fresh private CARGO_HOME containing only generated config, frozen dependency
resolution, and a build network
namespace with no egress. An early-userspace L3
local-output lockdown is armed, the OrbStack
machine executes a new guest boot transaction under systemd PID 1, ordering is
measured, the barrier is explicitly released, and the owned clone is deleted.
OrbStack shares one Linux kernel, so this is not a dedicated-kernel reboot,
initrd, power-loss,
paired-tunnel, or production test.
EOF
}

sanitize_component() {
  case "$1" in
    ''|*[!a-zA-Z0-9._-]*|*..*|*/*) return 1 ;;
    *) printf '%s\n' "$1" ;;
  esac
}

validate_source_vm() {
  [[ "$1" == "${SOURCE_DEFAULT}" ]]
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

# Bound the direct command and its complete process group.  Python is invoked
# isolated from user/site configuration; no child inherits the harness stdin.
run_bounded() {
  local seconds="$1"
  shift
  python3 -I -S - "${seconds}" "$@" <<'PY'
import os
import signal
import subprocess
import sys
import time

if len(sys.argv) < 3:
    raise SystemExit("run_bounded requires a timeout and command")
try:
    timeout = float(sys.argv[1])
except ValueError as error:
    raise SystemExit(f"invalid timeout: {error}")
if not (0.0 < timeout <= 3600.0):
    raise SystemExit("timeout is outside (0, 3600]")
process = subprocess.Popen(
    sys.argv[2:],
    stdin=subprocess.DEVNULL,
    start_new_session=True,
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
    returncode = process.wait(timeout=timeout)
except subprocess.TimeoutExpired:
    print(
        f"hard timeout after {timeout:g}s: {' '.join(sys.argv[2:])}",
        file=sys.stderr,
    )
    clean = stop_and_reap_group()
    raise SystemExit(124 if clean else 125)
# The direct command may exit after daemonizing a descendant inside its fresh
# process group.  No harness command is allowed to outlive its recorded step.
if group_exists():
    print("bounded command left live process-group descendants", file=sys.stderr)
    stop_and_reap_group()
    raise SystemExit(125)
if returncode < 0:
    raise SystemExit(128 - returncode)
raise SystemExit(returncode)
PY
}

capture_readonly() {
  local output="$1"
  shift
  local status
  if run_bounded "${HOST_COMMAND_TIMEOUT}" "$@" \
    >"${output}" 2>"${output}.stderr"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "${status}" >"${output}.status" || return 1
}

capture_required() {
  local output="$1"
  shift
  capture_readonly "${output}" "$@" || return 1
  [[ "$(<"${output}.status")" == 0 ]] || {
    warn "read-only collector failed: ${output}"
    return 1
  }
}

canonical_owned_tree() {
  local path="$1" root="$2" token="$3"
  python3 -I -S - "${path}" "${root}" "${token}" "${OWNERSHIP_MARKER}" <<'PY'
import os
import stat
import sys

path, root, token, marker_name = sys.argv[1:]
real_path = os.path.realpath(path)
real_root = os.path.realpath(root)
try:
    common = os.path.commonpath((real_path, real_root))
except ValueError:
    raise SystemExit(1)
if common != real_root or real_path == real_root:
    raise SystemExit(1)
info = os.lstat(real_path)
if (
    not stat.S_ISDIR(info.st_mode)
    or info.st_uid != os.geteuid()
    or stat.S_IMODE(info.st_mode) != 0o700
):
    raise SystemExit(1)
marker = os.path.join(real_path, marker_name)
marker_info = os.lstat(marker)
if (
    not stat.S_ISREG(marker_info.st_mode)
    or marker_info.st_nlink != 1
    or marker_info.st_uid != os.geteuid()
    or stat.S_IMODE(marker_info.st_mode) != 0o600
):
    raise SystemExit(1)
descriptor = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
with os.fdopen(descriptor, "r", encoding="ascii") as stream:
    opened = os.fstat(stream.fileno())
    if (opened.st_dev, opened.st_ino) != (marker_info.st_dev, marker_info.st_ino):
        raise SystemExit(1)
    observed = stream.read()
if observed != token + "\n":
    raise SystemExit(1)
print(real_path)
PY
}

safe_remove_owned_tree() {
  local path="$1" root="$2" token="$3" canonical
  canonical="$(canonical_owned_tree "${path}" "${root}" "${token}")" \
    || return 1
  [[ "${canonical}" == "${path}" ]] || return 1
  /bin/rm -rf -- "${canonical}" || return 1
  [[ ! -e "${canonical}" ]]
}

write_ownership_marker() {
  local directory="$1" token="$2"
  local marker="${directory}/${OWNERSHIP_MARKER}"
  python3 -I -S - "${directory}" "${marker}" "${token}" <<'PY'
import os
import stat
import sys

directory, marker, token = sys.argv[1:]
info = os.lstat(directory)
if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
    raise SystemExit("ownership directory is unsafe")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(marker, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
    stream.write(token + "\n")
    stream.flush()
    os.fsync(stream.fileno())
parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY
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

validate_singbox_command() {
  local command_file="$1"
  python3 -I -S - "${command_file}" "${EXPECTED_SINGBOX_CONFIG}" \
    "${EXPECTED_SINGBOX_DIRECTORY}" <<'PY'
import re
import sys
command_file, expected_config, expected_directory = sys.argv[1:]
with open(command_file, "r", encoding="utf-8") as stream:
    command = stream.read().strip()
if re.fullmatch(
    r"^(?:\S*/)?sing-box run -c " + re.escape(expected_config)
    + r" -D " + re.escape(expected_directory) + r"$",
    command,
) is None:
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
  capture_required "${output}" python3 -I -S -c '
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
      >"${output}/${name}.stdout" 2>"${output}/${name}.stderr"; then
      status=0
    else
      status=$?
    fi
    printf '%s\n' "${status}" >"${output}/${name}.status" || return 1
  done
  classify_pf_runtime "${output}"
}

snapshot_macos() {
  local output="$1"
  mkdir -- "${output}" || return 1

  capture_required "${output}/default-route-ipv4.txt" route -n get default || return 1
  capture_required "${output}/default-route-ipv6.txt" route -n get -inet6 default || return 1
  capture_required "${output}/routes-ipv4.raw.txt" netstat -rn -f inet || return 1
  capture_required "${output}/routes-ipv6.raw.txt" netstat -rn -f inet6 || return 1
  # shellcheck disable=SC2016
  capture_required "${output}/routes-ipv4.txt" /bin/bash -c \
    'set -o pipefail; awk '\''NR <= 4 || $3 !~ /L/'\'' "$1" | sed -E '\''s/[[:space:]]+[0-9]+$//'\''' \
    snapshot-normalize "${output}/routes-ipv4.raw.txt" || return 1
  # shellcheck disable=SC2016
  capture_required "${output}/routes-ipv6.txt" /bin/bash -c \
    'set -o pipefail; awk '\''NR <= 4 || $3 !~ /L/'\'' "$1" | sed -E '\''s/[[:space:]]+[0-9]+$//'\''' \
    snapshot-normalize "${output}/routes-ipv6.raw.txt" || return 1
  capture_required "${output}/dns.txt" scutil --dns || return 1

  capture_required "${output}/pf-conf.sha256" sha256sum /etc/pf.conf || return 1
  # shellcheck disable=SC2016
  capture_required "${output}/pf-anchors.sha256" /bin/bash -c \
    'set -o pipefail; find "$1" -type f -exec sha256sum {} + | LC_ALL=C sort' \
    snapshot-pf /etc/pf.anchors || return 1
  capture_pf_runtime "${output}/pf-runtime" || return 1
  local pf_runtime_observed
  pf_runtime_observed="$(awk -F= '$1 == "pf_runtime_observed" { print $2 }' \
    "${output}/pf-runtime/scope.env")" || return 1
  [[ "${pf_runtime_observed}" == true || "${pf_runtime_observed}" == false ]] \
    || return 1
  {
    printf 'pf_runtime_observed=%s\n' "${pf_runtime_observed}"
    printf 'pf_config_files_observed=true\n'
    printf 'route_raw_output_compared=false\n'
    printf 'route_normalized_output_compared=true\n'
  } >"${output}/scope.env" || return 1

  capture_required "${output}/sing-box.pids.raw" pgrep -x sing-box || return 1
  capture_required "${output}/sing-box.pids.candidates" \
    sort -n "${output}/sing-box.pids.raw" || return 1
  capture_singbox_candidate_commands \
    "${output}/sing-box.pids.candidates" \
    "${output}/sing-box.candidate-commands.tsv" || return 1
  select_managed_singbox_candidates \
    "${output}/sing-box.candidate-commands.tsv" "${output}/sing-box.pids" \
    || return 1
  [[ "$(wc -l <"${output}/sing-box.pids" | tr -d ' ')" == 1 ]] || return 1
  local pid final_pid binary final_binary
  pid="$(<"${output}/sing-box.pids")"
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
  capture_required "${output}/sing-box.identity" \
    ps -ww -p "${pid}" -o pid= -o lstart= -o command= || return 1
  capture_required "${output}/sing-box.command" \
    ps -ww -p "${pid}" -o command= || return 1
  validate_singbox_command "${output}/sing-box.command" || return 1
  [[ -f "${EXPECTED_SINGBOX_CONFIG}" \
    && ! -L "${EXPECTED_SINGBOX_CONFIG}" ]] || return 1
  capture_required "${output}/sing-box-config.stat" \
    stat -f '%HT %Su %Sg %Sp %l %z %m %N' \
    "${EXPECTED_SINGBOX_CONFIG}" || return 1
  capture_required "${output}/sing-box-config.sha256" \
    sha256sum "${EXPECTED_SINGBOX_CONFIG}" || return 1
  capture_singbox_binary "${pid}" "${output}/sing-box-binary.path" || return 1
  binary="$(<"${output}/sing-box-binary.path")"
  [[ -n "${binary}" && -f "${binary}" ]] || return 1
  capture_required "${output}/sing-box-binary.stat" \
    stat -f '%HT %Su %Sg %Sp %l %z %m %N' "${binary}" || return 1
  capture_required "${output}/sing-box-binary.sha256" sha256sum "${binary}" || return 1

  # Prove this snapshot did not splice hashes from a restarted sing-box into
  # the identity captured at its beginning.
  capture_required "${output}/sing-box.pids-final.raw" pgrep -x sing-box \
    || return 1
  capture_required "${output}/sing-box.pids-final.candidates" \
    sort -n "${output}/sing-box.pids-final.raw" || return 1
  capture_singbox_candidate_commands \
    "${output}/sing-box.pids-final.candidates" \
    "${output}/sing-box.candidate-commands-final.tsv" || return 1
  select_managed_singbox_candidates \
    "${output}/sing-box.candidate-commands-final.tsv" \
    "${output}/sing-box.pids-final" || return 1
  final_pid="$(<"${output}/sing-box.pids-final")"
  [[ "${final_pid}" =~ ^[0-9]+$ ]] || return 1
  capture_required "${output}/sing-box.identity-final" \
    ps -ww -p "${final_pid}" -o pid= -o lstart= -o command= || return 1
  capture_required "${output}/sing-box.command-final" \
    ps -ww -p "${final_pid}" -o command= || return 1
  validate_singbox_command "${output}/sing-box.command-final" || return 1
  capture_singbox_binary \
    "${final_pid}" "${output}/sing-box-binary-final.path" || return 1
  final_binary="$(<"${output}/sing-box-binary-final.path")"
  capture_required "${output}/sing-box-config-final.stat" \
    stat -f '%HT %Su %Sg %Sp %l %z %m %N' \
    "${EXPECTED_SINGBOX_CONFIG}" || return 1
  capture_required "${output}/sing-box-binary-final.stat" \
    stat -f '%HT %Su %Sg %Sp %l %z %m %N' "${final_binary}" || return 1
  validate_singbox_reproof "${output}" || return 1
  local left right
  for left in sing-box-config.stat sing-box-binary.stat; do
    case "${left}" in
      sing-box-config.stat) right=sing-box-config-final.stat ;;
      sing-box-binary.stat) right=sing-box-binary-final.stat ;;
    esac
    run_bounded "${HOST_COMMAND_TIMEOUT}" \
      cmp -s -- "${output}/${left}" "${output}/${right}" || return 1
  done
  printf 'sing_box_snapshot_consistent=true\n' \
    >"${output}/sing-box-snapshot-consistency.env" || return 1

  local manifest
  manifest="$(mktemp "${output}.collector-manifest.XXXXXX")" || return 1
  # shellcheck disable=SC2016
  run_bounded "${HOST_COMMAND_TIMEOUT}" /bin/bash -c \
    'set -o pipefail; cd "$1" && find . -type f ! -name collector-manifest.txt ! -name stable-manifest.txt -print | LC_ALL=C sort' \
    snapshot-manifest "${output}" >"${manifest}" || return 1
  mv -- "${manifest}" "${output}/collector-manifest.txt" || return 1
  manifest="$(mktemp "${output}.stable-manifest.XXXXXX")" || return 1
  # shellcheck disable=SC2016
  run_bounded "${HOST_COMMAND_TIMEOUT}" /bin/bash -c \
    'set -o pipefail; cd "$1" && find . -type f ! -name routes-ipv4.raw.txt ! -name routes-ipv6.raw.txt ! -name collector-manifest.txt ! -name stable-manifest.txt -print | LC_ALL=C sort' \
    snapshot-manifest "${output}" >"${manifest}" || return 1
  mv -- "${manifest}" "${output}/stable-manifest.txt" || return 1
}

compare_macos_snapshots() {
  local before="$1" after="$2" report="$3" name status=0
  if ! run_bounded "${HOST_COMMAND_TIMEOUT}" cmp -s -- \
    "${before}/collector-manifest.txt" \
    "${after}/collector-manifest.txt"; then
    warn 'macOS collector manifests differ'
    return 1
  fi
  if ! run_bounded "${HOST_COMMAND_TIMEOUT}" cmp -s -- \
    "${before}/stable-manifest.txt" \
    "${after}/stable-manifest.txt"; then
    warn 'macOS stable collector manifests differ'
    return 1
  fi
  : >"${report}" || return 1
  while IFS= read -r name; do
    name="${name#./}"
    if ! run_bounded "${HOST_COMMAND_TIMEOUT}" cmp -s -- \
      "${before}/${name}" "${after}/${name}"; then
      warn "macOS safety snapshot changed: ${name}"
      local diff_status=0
      run_bounded "${HOST_COMMAND_TIMEOUT}" diff -u -- \
        "${before}/${name}" "${after}/${name}" >>"${report}" \
        || diff_status=$?
      [[ "${diff_status}" == 1 ]] || return 1
      status=1
    fi
  done <"${before}/stable-manifest.txt"
  return "${status}"
}

seal_bundle() {
  local directory="$1"
  python3 -I -S - "${directory}" <<'PY'
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
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
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
descriptor = os.open(temporary, flags, 0o600)
try:
    with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
        for relative in sorted(first):
            stream.write(f"{first[relative]}  {relative}\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, os.path.join(root, "checksums.sha256"))
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    if os.path.lexists(temporary):
        os.unlink(temporary)
second = census_and_hash()
if second != first:
    raise SystemExit("evidence file census or digest changed during sealing")
manifest = os.path.join(root, "checksums.sha256")
manifest_info = os.lstat(manifest)
if not stat.S_ISREG(manifest_info.st_mode) or manifest_info.st_nlink != 1:
    raise SystemExit("checksum manifest is not a single-link regular file")
descriptor = os.open(manifest, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
with os.fdopen(descriptor, "r", encoding="ascii", newline="") as stream:
    observed = stream.read()
expected = "".join(f"{first[path]}  {path}\n" for path in sorted(first))
if observed != expected:
    raise SystemExit("checksum manifest content differs from the verified census")
PY
}

wait_for_guest() {
  local vm="$1" evidence="$2" deadline=$((SECONDS + BOOT_READY_TIMEOUT))
  local attempts=0
  while (( SECONDS < deadline )); do
    attempts=$((attempts + 1))
    if run_recorded 5 "${evidence}" orb -m "${vm}" -u root true; then
      printf '%s\n' "${attempts}" >"${evidence}.attempts" || return 1
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "${attempts}" >"${evidence}.attempts" || return 1
  return 1
}

capture_guest_state_metadata() {
  local vm="$1" output="$2"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${output}" \
    orb -m "${vm}" -u root python3 -I -S -c '
import os, stat
root = "/var/lib/shadowpipe"
wal = root + "/handoff-lockdown-v1.json"
main = root + "/host-state-v2.json"
directory = os.lstat(root)
wal_info = os.lstat(wal)
main_info = os.lstat(main)
def kind(info):
    if stat.S_ISDIR(info.st_mode): return "directory"
    if stat.S_ISREG(info.st_mode): return "regular"
    return "other"
print(f"state_dir:{stat.S_IMODE(directory.st_mode):o}:{directory.st_uid}:{directory.st_gid}:{kind(directory)}")
print(f"wal:{stat.S_IMODE(wal_info.st_mode):o}:{wal_info.st_uid}:{wal_info.st_gid}:{wal_info.st_nlink}:{kind(wal_info)}")
print(f"possible_main:{stat.S_IMODE(main_info.st_mode):o}:{main_info.st_uid}:{main_info.st_gid}:{main_info.st_nlink}:{kind(main_info)}:{main_info.st_size}")
for label, path in (("network_namespace", "/proc/1/ns/net"), ("mount_namespace", "/proc/1/ns/mnt")):
    info = os.stat(path)
    print(f"{label}:{info.st_dev}:{info.st_ino}")
'
}

verify_guest_state_metadata() {
  local metadata="$1"
  python3 -I -S - "${metadata}" <<'PY'
import re
import sys
with open(sys.argv[1], "r", encoding="ascii") as stream:
    lines = stream.read().splitlines()
if len(lines) != 5:
    raise SystemExit("guest state metadata line census differs")
if lines[0] != "state_dir:700:0:0:directory":
    raise SystemExit("host-state directory is not exact root:root 0700")
if lines[1] != "wal:600:0:0:1:regular":
    raise SystemExit("lockdown WAL is not exact root:root 0600 single-link regular")
if lines[2] != "possible_main:600:0:0:1:regular:0":
    raise SystemExit("possible-main marker is not exact root:root empty regular")
for expected, line in zip(("network_namespace", "mount_namespace"), lines[3:]):
    match = re.fullmatch(expected + r":([1-9][0-9]*):([1-9][0-9]*)", line)
    if match is None:
        raise SystemExit(f"{expected} live identity is malformed")
PY
}

wal_table_name() {
  local wal="$1" boot_file="$2" expected_generation="$3" metadata="$4"
  python3 -I -S - "${wal}" "${boot_file}" "${expected_generation}" \
    "${metadata}" <<'PY'
import json
import re
import sys

wal_path, boot_path, generation_text, metadata_path = sys.argv[1:]
try:
    expected_generation = int(generation_text, 10)
except ValueError as error:
    raise SystemExit(f"invalid expected generation: {error}")
with open(wal_path, "r", encoding="utf-8") as stream:
    journal = json.load(stream)
if not isinstance(journal, dict):
    raise SystemExit("lockdown WAL is not an object")
expected_keys = {
    "schema_version", "generation", "identity", "boot_id", "uid",
    "network_namespace", "mount_namespace", "control_flow", "phase",
    "table_handle", "release_reason",
}
if set(journal) != expected_keys:
    raise SystemExit("lockdown WAL fields differ from schema v1")

def exact_integer(value, name, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise SystemExit(f"{name} is not an exact integer >= {minimum}")
    return value

def namespace(value, name, expected):
    if not isinstance(value, dict) or set(value) != {"device", "inode"}:
        raise SystemExit(f"{name} has unexpected fields")
    exact_integer(value["device"], f"{name}.device", 1)
    exact_integer(value["inode"], f"{name}.inode", 1)
    if value != expected:
        raise SystemExit(f"{name} differs from the live PID-1 namespace")

with open(metadata_path, "r", encoding="ascii") as stream:
    metadata_lines = stream.read().splitlines()
if len(metadata_lines) != 5:
    raise SystemExit("guest state metadata line census differs")
metadata = {}
for line in metadata_lines[3:]:
    fields = line.split(":")
    if len(fields) != 3 or fields[0] in metadata:
        raise SystemExit("guest namespace metadata is malformed")
    if any(re.fullmatch(r"[1-9][0-9]*", field) is None for field in fields[1:]):
        raise SystemExit("guest namespace identity is not positive decimal")
    metadata[fields[0]] = {"device": int(fields[1]), "inode": int(fields[2])}

if exact_integer(journal["schema_version"], "schema_version", 1) != 1:
    raise SystemExit("unexpected lockdown schema version")
if exact_integer(journal["generation"], "generation", 1) != expected_generation:
    raise SystemExit("unexpected lockdown generation")
if exact_integer(journal["uid"], "uid", 0) != 0:
    raise SystemExit("reboot harness WAL is not root-owned")
if journal["phase"] != "active":
    raise SystemExit("lockdown WAL is not Active")
if journal["control_flow"] is not None or journal["release_reason"] is not None:
    raise SystemExit("reboot WAL unexpectedly admits a control flow or release")
identity = journal["identity"]
if not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{32}", identity) is None:
    raise SystemExit("lockdown identity is not canonical 128-bit lowercase hex")
if identity == "0" * 32:
    raise SystemExit("lockdown identity is zero")
handle = exact_integer(journal["table_handle"], "table_handle", 1)
namespace(journal["network_namespace"], "network_namespace", metadata["network_namespace"])
namespace(journal["mount_namespace"], "mount_namespace", metadata["mount_namespace"])
with open(boot_path, "r", encoding="ascii") as stream:
    observed_boot = stream.read().strip().replace("-", "").lower()
wal_boot = journal["boot_id"]
if not isinstance(wal_boot, str):
    raise SystemExit("WAL boot identity is not a string")
wal_boot = wal_boot.replace("-", "").lower()
if re.fullmatch(r"[0-9a-f]{32}", observed_boot) is None:
    raise SystemExit("kernel boot identity is not canonical UUID hex")
if wal_boot != observed_boot or wal_boot == "0" * 32:
    raise SystemExit("WAL boot identity differs from current boot")
print(f"sp_lock_{identity}")
print(handle, file=sys.stderr)
PY
}

verify_nft_snapshot() {
  local wal="$1" listing="$2" census="$3" forbidden_table="$4"
  python3 -I -S - "${wal}" "${listing}" "${census}" "${forbidden_table}" <<'PY'
import json
import sys

wal_path, listing_path, census_path, forbidden = sys.argv[1:]
with open(wal_path, "r", encoding="utf-8") as stream:
    journal = json.load(stream)
with open(listing_path, "r", encoding="utf-8") as stream:
    listing = json.load(stream)
with open(census_path, "r", encoding="utf-8") as stream:
    census = json.load(stream)
identity = journal.get("identity")
table = "sp_lock_" + identity
owner = "shadowpipe-lockdown-v1:" + identity
wal_handle = journal.get("table_handle")

def integer(value, name, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise SystemExit(f"{name} is not an integer >= {minimum}")
    return value

def entries(root, name):
    if not isinstance(root, dict) or set(root) != {"nftables"}:
        raise SystemExit(f"{name} root fields are not exact")
    values = root["nftables"]
    if not isinstance(values, list):
        raise SystemExit(f"{name}.nftables is not an array")
    return values

def one(entry, context):
    if not isinstance(entry, dict) or len(entry) != 1:
        raise SystemExit(f"{context} entry is not a one-kind object")
    kind, body = next(iter(entry.items()))
    if not isinstance(body, dict):
        raise SystemExit(f"{context} {kind} body is not an object")
    return kind, body

table_count = 0
chain_count = 0
rules = []
for entry in entries(listing, "table listing"):
    kind, body = one(entry, "table listing")
    if kind == "metainfo":
        continue
    if kind == "table":
        required = {"family", "name", "handle", "comment"}
        if set(body) != required:
            raise SystemExit("table declaration fields are not exact")
        if body["family"] != "inet" or body["name"] != table or body["comment"] != owner:
            raise SystemExit("table identity/comment differs from WAL")
        if integer(body["handle"], "table handle", 1) != integer(wal_handle, "WAL handle", 1):
            raise SystemExit("kernel table handle differs from WAL")
        table_count += 1
    elif kind == "chain":
        required = {
            "family", "table", "name", "handle", "type", "hook", "prio",
            "policy", "comment",
        }
        if set(body) != required:
            raise SystemExit("chain declaration fields are not exact")
        if (
            body["family"] != "inet" or body["table"] != table
            or body["name"] != "sp_output" or body["type"] != "filter"
            or body["hook"] != "output" or body["prio"] != -400
            or body["policy"] != "drop" or body["comment"] != owner + ":chain"
        ):
            raise SystemExit("base-chain shape differs from fail-closed contract")
        integer(body["handle"], "chain handle", 1)
        chain_count += 1
    elif kind == "rule":
        required = {"family", "table", "chain", "handle", "expr", "comment"}
        if set(body) != required:
            raise SystemExit("rule declaration fields are not exact")
        if body["family"] != "inet" or body["table"] != table or body["chain"] != "sp_output":
            raise SystemExit("rule coordinates differ from WAL table")
        integer(body["handle"], "rule handle", 1)
        rules.append((body["comment"], body["expr"]))
    else:
        raise SystemExit(f"foreign nft object in lockdown table: {kind}")
if table_count != 1 or chain_count != 1:
    raise SystemExit("lockdown table/chain census is not exactly one")
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
    raise SystemExit("lockdown rule count/order/expressions are not exact")

lockdown_coordinates = []
all_names = []
for entry in entries(census, "table census"):
    kind, body = one(entry, "table census")
    if kind == "metainfo":
        continue
    if kind != "table":
        raise SystemExit(f"unexpected object in table census: {kind}")
    family = body.get("family")
    name = body.get("name")
    if not isinstance(family, str) or not isinstance(name, str):
        raise SystemExit("table census lacks family/name")
    coordinate = (family, name)
    if coordinate in all_names:
        raise SystemExit("duplicate table coordinate in nft census")
    all_names.append(coordinate)
    if name.startswith("sp_lock_"):
        lockdown_coordinates.append(coordinate)
if lockdown_coordinates != [("inet", table)]:
    raise SystemExit("global census does not contain exactly the WAL-owned sp_lock table")
if forbidden != "-" and ("inet", forbidden) in all_names:
    raise SystemExit("pre-reboot lockdown table survived the reboot")
PY
}

verify_no_lockdown_tables() {
  local census="$1"
  python3 -I -S - "${census}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    root = json.load(stream)
if not isinstance(root, dict) or set(root) != {"nftables"}:
    raise SystemExit("post-release nft census root is not exact")
for entry in root["nftables"]:
    if not isinstance(entry, dict) or len(entry) != 1:
        raise SystemExit("post-release census entry is not exact")
    kind, body = next(iter(entry.items()))
    if kind == "metainfo":
        continue
    if kind != "table" or not isinstance(body, dict):
        raise SystemExit("post-release census contains a non-table object")
    if str(body.get("name", "")).startswith("sp_lock_"):
        raise SystemExit("post-release census retains an sp_lock table")
PY
}

verify_systemd_evidence() {
  local version_file="$1" enabled_file="$2" restore_file="$3"
  local network_file="$4" dependency_file="$5"
  python3 -I -S - "${version_file}" "${enabled_file}" "${restore_file}" \
    "${network_file}" "${dependency_file}" <<'PY'
import re
import sys

version_path, enabled_path, restore_path, network_path, dependency_path = sys.argv[1:]
with open(version_path, "r", encoding="utf-8") as stream:
    first_line = stream.readline().strip()
match = re.match(r"^systemd\s+(\d+)(?:\s|$)", first_line)
if match is None or int(match.group(1), 10) < 254:
    raise SystemExit("systemd >=254 is required for RestartMode=direct semantics")
with open(enabled_path, "r", encoding="utf-8") as stream:
    if stream.read().strip() != "enabled":
        raise SystemExit("restore unit is not persistently enabled")

def properties(path, expected):
    values = {}
    with open(path, "r", encoding="utf-8") as stream:
        for raw in stream:
            line = raw.rstrip("\n")
            if "=" not in line:
                raise SystemExit(f"malformed systemd property in {path}")
            key, value = line.split("=", 1)
            if key in values:
                raise SystemExit(f"duplicate systemd property {key}")
            values[key] = value
    if set(values) != set(expected):
        raise SystemExit(f"systemd property set differs in {path}")
    return values

restore = properties(
    restore_path,
    {
        "LoadState", "UnitFileState", "ActiveState", "SubState", "Result",
        "ExecMainCode", "ExecMainStatus", "NRestarts",
        "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic",
        "ActiveEnterTimestampMonotonic", "InactiveExitTimestampMonotonic",
        "InvocationID", "Before", "FragmentPath", "DropInPaths",
        "ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost",
        "EnvironmentFiles",
    },
)
network = properties(
    network_path,
    {
        "LoadState", "ActiveState", "SubState",
        "ExecMainStartTimestampMonotonic", "InactiveExitTimestampMonotonic",
        "InvocationID", "NRestarts", "After", "Requires",
    },
)
required_restore = {
    "LoadState": "loaded", "UnitFileState": "enabled", "ActiveState": "active",
    "SubState": "exited", "Result": "success", "ExecMainCode": "1",
    "ExecMainStatus": "0", "NRestarts": "0",
}
for key, expected in required_restore.items():
    if restore[key] != expected:
        raise SystemExit(f"restore unit {key}={restore[key]!r}, expected {expected!r}")
if restore["FragmentPath"] != "/etc/systemd/system/shadowpipe-lockdown-restore.service":
    raise SystemExit("restore unit fragment path differs")
for key in (
    "DropInPaths", "ExecCondition", "ExecStartPre", "ExecStartPost",
    "EnvironmentFiles",
):
    if restore[key]:
        raise SystemExit(f"restore unit effective {key} is not empty")
restore_start = restore["ExecStart"]
if (
    restore_start.count("path=/usr/local/bin/shadowpipe-client") != 1
    or (
        "argv[]=/usr/local/bin/shadowpipe-client --restore-lockdown "
        "--host-state-dir /var/lib/shadowpipe"
    ) not in restore_start
):
    raise SystemExit("restore unit effective ExecStart differs")
if network["LoadState"] != "loaded" or network["ActiveState"] != "active":
    raise SystemExit("systemd-networkd is not loaded and active")
if network["SubState"] != "running":
    raise SystemExit("systemd-networkd is not running")
if network["NRestarts"] != "0":
    raise SystemExit("systemd-networkd unexpectedly restarted during the boot proof")
for label, value in (("restore", restore["InvocationID"]),
                     ("networkd", network["InvocationID"])):
    if re.fullmatch(r"[0-9a-f]{32}", value) is None or value == "0" * 32:
        raise SystemExit(f"{label} InvocationID is not one nonzero canonical ID")
if restore["InvocationID"] == network["InvocationID"]:
    raise SystemExit("restore and networkd unexpectedly share an InvocationID")
unit = "shadowpipe-lockdown-restore.service"
if "systemd-networkd.service" not in restore["Before"].split():
    raise SystemExit("restore unit lacks Before=systemd-networkd")
if unit not in network["After"].split() or unit not in network["Requires"].split():
    raise SystemExit("networkd does not have the enabled restore unit as Requires+After")

def positive_integer(value, name):
    if re.fullmatch(r"[0-9]+", value) is None:
        raise SystemExit(f"{name} is not an integer")
    parsed = int(value, 10)
    if parsed <= 0:
        raise SystemExit(f"{name} is not positive")
    return parsed

restore_start = positive_integer(
    restore["ExecMainStartTimestampMonotonic"], "restore start timestamp"
)
restore_inactive = positive_integer(
    restore["InactiveExitTimestampMonotonic"], "restore inactive-exit timestamp"
)
restore_exit = positive_integer(
    restore["ExecMainExitTimestampMonotonic"], "restore exit timestamp"
)
restore_active = positive_integer(
    restore["ActiveEnterTimestampMonotonic"], "restore active timestamp"
)
network_start = positive_integer(
    network["ExecMainStartTimestampMonotonic"], "networkd start timestamp"
)
network_inactive = positive_integer(
    network["InactiveExitTimestampMonotonic"], "networkd inactive-exit timestamp"
)
# InactiveExitTimestampMonotonic records the unit state transition from
# inactive to activating, while ExecMainStartTimestampMonotonic records main
# process creation. systemd does not specify an ordering between those two
# independently sampled properties; real boots published each unit's
# transition a few microseconds after process creation. The causal barrier is
# instead the explicit Requires+After/Before graph plus completion of the
# successful oneshot before networkd's main process is created.
if not (restore_start <= restore_exit <= restore_active):
    raise SystemExit("restore unit timestamp order is internally inconsistent")
if not (restore_exit < network_start and restore_active < network_start):
    raise SystemExit("restore completion was not proved before networkd process start")
if restore_inactive <= 0 or network_inactive <= 0:
    raise SystemExit("one unit inactive-exit timestamp was not recorded")
with open(dependency_path, "r", encoding="utf-8") as stream:
    dependencies = stream.read().splitlines()
if sum(unit in line for line in dependencies) != 1:
    raise SystemExit("networkd dependency tree lacks exactly one restore unit")
PY
}

capture_guest_client_network_state() {
  local clone_id="$1" output="$2"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${output}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import hashlib
import json
import os
import stat
import subprocess

def command(arguments):
    result = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
        env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if result.returncode != 0 or result.stderr:
        raise SystemExit(f"guest network snapshot command failed: {arguments[0]}")
    return result.stdout

volatile = {"age", "bytes", "expires", "lastuse", "packets", "used"}
def canonical(value):
    if isinstance(value, dict):
        return {
            key: ("<volatile>" if key in volatile else canonical(child))
            for key, child in sorted(value.items())
            if key != "metainfo"
        }
    if isinstance(value, list):
        return [canonical(child) for child in value]
    return value

def json_command(*arguments):
    return canonical(json.loads(command(list(arguments)).decode("utf-8")))

links = json_command("ip", "-j", "-details", "link", "show")
tun_interfaces = []
for link in links:
    if not isinstance(link, dict) or not isinstance(link.get("ifname"), str):
        raise SystemExit("ip link JSON is malformed")
    linkinfo = link.get("linkinfo")
    if isinstance(linkinfo, dict) and linkinfo.get("info_kind") == "tun":
        tun_interfaces.append(link["ifname"])

resolver = "/etc/resolv.conf"
resolver_info = os.lstat(resolver)
if not (stat.S_ISREG(resolver_info.st_mode) or stat.S_ISLNK(resolver_info.st_mode)):
    raise SystemExit("resolver path is neither a regular file nor a symlink")
with open(resolver, "rb") as stream:
    resolver_bytes = stream.read(1024 * 1024 + 1)
if len(resolver_bytes) > 1024 * 1024:
    raise SystemExit("resolver content exceeded one MiB")

client_pids = []
for name in os.listdir("/proc"):
    if not name.isdigit():
        continue
    try:
        executable = os.readlink(f"/proc/{name}/exe")
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        continue
    # Linux task comm is limited to 15 bytes, so shadowpipe-client is
    # truncated there. Bind the process census to the executable basename
    # instead of accepting a false empty result from the task comm file.
    if os.path.basename(executable).removesuffix(" (deleted)") == "shadowpipe-client":
        client_pids.append(int(name))

state = {
    "schema_version": 1,
    "ipv4_routes": json_command("ip", "-j", "-4", "route", "show", "table", "all"),
    "ipv6_routes": json_command("ip", "-j", "-6", "route", "show", "table", "all"),
    "ipv4_rules": json_command("ip", "-j", "-4", "rule", "show"),
    "ipv6_rules": json_command("ip", "-j", "-6", "rule", "show"),
    "links": links,
    "nft_ruleset": json_command("nft", "-j", "list", "ruleset"),
    "resolver": {
        "mode": stat.S_IMODE(resolver_info.st_mode),
        "uid": resolver_info.st_uid,
        "gid": resolver_info.st_gid,
        "nlink": resolver_info.st_nlink,
        "symlink_target": os.readlink(resolver) if stat.S_ISLNK(resolver_info.st_mode) else None,
        "content_sha256": hashlib.sha256(resolver_bytes).hexdigest(),
    },
    "tun_interfaces": sorted(tun_interfaces),
    "client_pids": sorted(client_pids),
    "lockdown_wal_absent": not os.path.lexists("/var/lib/shadowpipe/handoff-lockdown-v1.json"),
    "main_wal_absent": not os.path.lexists("/var/lib/shadowpipe/host-state-v2.json"),
}
if state["tun_interfaces"] or state["client_pids"]:
    raise SystemExit("guest baseline/final snapshot contains a TUN or live client")
if not state["lockdown_wal_absent"] or not state["main_wal_absent"]:
    raise SystemExit("guest baseline/final snapshot contains a Shadowpipe WAL")
print(json.dumps(state, sort_keys=True, separators=(",", ":")))
'
}

capture_guest_tree_manifest() {
  local clone_id="$1" root="$2" label="$3" max_entries="$4"
  local max_bytes="$5" output="$6"
  run_recorded "${VENDOR_EXTRACT_TIMEOUT}" "${output}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import hashlib
import json
import os
import stat
import sys

root, label, max_entries_text, max_bytes_text = sys.argv[1:]
max_entries = int(max_entries_text, 10)
max_bytes = int(max_bytes_text, 10)
if not os.path.isabs(root) or label not in ("source", "vendor"):
    raise SystemExit("unsafe guest tree-manifest identity")
if max_entries <= 0 or max_bytes <= 0:
    raise SystemExit("invalid guest tree-manifest bounds")
root_info = os.lstat(root)
if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
    raise SystemExit("guest tree-manifest root is unsafe")
if root_info.st_uid != 0 or root_info.st_gid != 0:
    raise SystemExit("guest tree-manifest root is not root-owned")

tree = hashlib.sha256()
entries = 1
directories = 1
files = 0
total = 0

def add_record(record):
    encoded = json.dumps(
        record,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    tree.update(len(encoded).to_bytes(8, "big"))
    tree.update(encoded)

add_record({
    "kind": "directory", "path": ".", "mode": stat.S_IMODE(root_info.st_mode),
    "uid": root_info.st_uid, "gid": root_info.st_gid,
})
for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
    dirnames.sort()
    filenames.sort()
    for name in dirnames:
        path = os.path.join(current, name)
        relative = os.path.relpath(path, root)
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SystemExit("guest manifest contains a linked/non-directory child")
        if info.st_uid != 0 or info.st_gid != 0:
            raise SystemExit("guest manifest directory is not root-owned")
        if any(ord(character) < 0x20 or ord(character) == 0x7f for character in relative):
            raise SystemExit("guest manifest directory path has a control byte")
        entries += 1
        directories += 1
        if entries > max_entries:
            raise SystemExit("guest tree-manifest entry bound exceeded")
        add_record({
            "kind": "directory", "path": relative,
            "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
            "gid": info.st_gid,
        })
    for name in filenames:
        path = os.path.join(current, name)
        relative = os.path.relpath(path, root)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit("guest manifest contains a linked/non-regular file")
        if info.st_uid != 0 or info.st_gid != 0:
            raise SystemExit("guest manifest file is not root-owned")
        if any(ord(character) < 0x20 or ord(character) == 0x7f for character in relative):
            raise SystemExit("guest manifest file path has a control byte")
        entries += 1
        files += 1
        total += info.st_size
        if entries > max_entries or total > max_bytes:
            raise SystemExit("guest tree-manifest bound exceeded")
        digest = hashlib.sha256()
        with open(path, "rb", buffering=0) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        add_record({
            "kind": "file", "path": relative,
            "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
            "gid": info.st_gid, "nlink": info.st_nlink,
            "size": info.st_size, "sha256": digest.hexdigest(),
        })
print(json.dumps({
    "schema_version": 1,
    "label": label,
    "tree_sha256": tree.hexdigest(),
    "entries": entries,
    "directories": directories,
    "files": files,
    "bytes": total,
}, sort_keys=True, separators=(",", ":")))
' "${root}" "${label}" "${max_entries}" "${max_bytes}"
}

verify_guest_tree_manifest() {
  local expected="$1" observed="$2" label="$3"
  python3 -I -S - "${expected}" "${observed}" "${label}" <<'PY'
import json
import re
import sys

expected_path, observed_path, label = sys.argv[1:]
def load(path):
    with open(path, "r", encoding="ascii") as stream:
        value = json.load(stream)
    if set(value) != {
        "schema_version", "label", "tree_sha256", "entries",
        "directories", "files", "bytes",
    }:
        raise SystemExit("guest tree-manifest schema differs")
    if value["schema_version"] != 1 or value["label"] != label:
        raise SystemExit("guest tree-manifest identity differs")
    if re.fullmatch(r"[0-9a-f]{64}", value["tree_sha256"] or "") is None:
        raise SystemExit("guest tree-manifest digest is malformed")
    for key in ("entries", "directories", "files"):
        if type(value[key]) is not int or value[key] <= 0:
            raise SystemExit("guest tree-manifest count is invalid")
    if type(value["bytes"]) is not int or value["bytes"] < 0:
        raise SystemExit("guest tree-manifest byte count is invalid")
    return value

if load(expected_path) != load(observed_path):
    raise SystemExit(f"guest {label} tree drifted after extraction")
PY
}

capture_guest_cargo_config_binding() {
  local clone_id="$1" cargo_home="$2" expected_hash="$3" output="$4"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${output}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import hashlib
import json
import os
import re
import stat
import sys

home, expected = sys.argv[1:]
if not os.path.isabs(home) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
    raise SystemExit("unsafe Cargo config binding identity")
home_info = os.lstat(home)
if (
    not stat.S_ISDIR(home_info.st_mode)
    or stat.S_ISLNK(home_info.st_mode)
    or home_info.st_uid != 0
    or home_info.st_gid != 0
):
    raise SystemExit("private CARGO_HOME metadata is unsafe")
path = os.path.join(home, "config.toml")
info = os.lstat(path)
if (
    not stat.S_ISREG(info.st_mode)
    or info.st_nlink != 1
    or info.st_uid != 0
    or info.st_gid != 0
    or stat.S_IMODE(info.st_mode) != 0o600
    or info.st_size <= 0
    or info.st_size > 64 * 1024
):
    raise SystemExit("private Cargo config metadata is unsafe")
digest = hashlib.sha256()
with open(path, "rb", buffering=0) as stream:
    for chunk in iter(lambda: stream.read(64 * 1024), b""):
        digest.update(chunk)
observed = digest.hexdigest()
if observed != expected:
    raise SystemExit("private Cargo config differs from the sealed vendor binding")
print(json.dumps({
    "schema_version": 1,
    "cargo_config_sha256": observed,
    "mode": stat.S_IMODE(info.st_mode),
    "uid": info.st_uid,
    "gid": info.st_gid,
    "nlink": info.st_nlink,
    "bytes": info.st_size,
}, sort_keys=True, separators=(",", ":")))
' "${cargo_home}" "${expected_hash}"
}

verify_guest_cargo_config_binding() {
  local expected="$1" observed="$2"
  cmp -s -- "${expected}" "${observed}"
}

verify_systemd_dbus_typed_empty_sidecar() {
  local sidecar="$1" kind="$2" unit="$3"
  python3 -I -S - "${sidecar}" "${kind}" "${unit}" <<'PY'
import json
import re
import sys

path, kind, unit = sys.argv[1:]
types = {
    "ExecCondition": "a(sasbttttuii)",
    "ExecStartPre": "a(sasbttttuii)",
    "ExecStartPost": "a(sasbttttuii)",
    "EnvironmentFiles": "a(sb)",
}
expected_by_kind = {
    "restore": {
        "ExecCondition", "ExecStartPre", "ExecStartPost", "EnvironmentFiles",
    },
    "client": {"ExecCondition", "ExecStartPre", "ExecStartPost"},
    "none": set(),
}
if kind not in expected_by_kind:
    raise SystemExit("unknown systemd typed-empty proof kind")
with open(path, "r", encoding="utf-8") as stream:
    proof = json.load(stream)
if set(proof) != {
    "schema_version", "unit", "object_path", "dbus_typed_empty",
    "unit_id_bound", "fragment_path_bound", "need_daemon_reload",
    "repeated_reads_identical", "unknown_property_rejected",
} or proof["schema_version"] != 1 or proof["unit"] != unit:
    raise SystemExit("systemd typed-empty proof schema differs")
expected = expected_by_kind[kind]
observed = proof["dbus_typed_empty"]
if not isinstance(observed, dict) or set(observed) != expected:
    raise SystemExit("systemd typed-empty property census differs")
if any(
    observed[name] != {"type": types[name], "data": []}
    for name in expected
):
    raise SystemExit("systemd typed-empty D-Bus signature differs")
object_path = proof["object_path"]
if expected:
    if (
        not isinstance(object_path, str)
        or re.fullmatch(
            r"/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+",
            object_path,
        )
        is None
    ):
        raise SystemExit("systemd typed-empty object path differs")
    if (
        proof["unit_id_bound"] is not True
        or proof["fragment_path_bound"] is not True
        or proof["need_daemon_reload"] is not False
        or proof["repeated_reads_identical"] is not True
        or proof["unknown_property_rejected"] is not True
    ):
        raise SystemExit("systemd typed-empty D-Bus binding proof differs")
elif object_path is not None:
    raise SystemExit("unexpected systemd object path without D-Bus proofs")
elif (
    proof["unit_id_bound"] is not False
    or proof["fragment_path_bound"] is not False
    or proof["need_daemon_reload"] is not None
    or proof["repeated_reads_identical"] is not False
    or proof["unknown_property_rejected"] is not False
):
    raise SystemExit("unexpected D-Bus binding claim without typed properties")
PY
}

capture_exact_systemd_properties() {
  local clone_id="$1" unit="$2" kind="$3" output="$4"
  shift 4
  (( "$#" > 0 )) || return 1
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${output}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import json
import re
import subprocess
import sys

unit, kind, *properties = sys.argv[1:]
if (
    re.fullmatch(r"[A-Za-z0-9_.@-]+", unit) is None
    or not properties
    or len(properties) != len(set(properties))
    or any(re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", name) is None for name in properties)
):
    raise SystemExit("unsafe exact systemd property request")
typed_empty_by_kind = {
    "restore": {
        "ExecCondition": "a(sasbttttuii)",
        "ExecStartPre": "a(sasbttttuii)",
        "ExecStartPost": "a(sasbttttuii)",
        "EnvironmentFiles": "a(sb)",
    },
    "client": {
        "ExecCondition": "a(sasbttttuii)",
        "ExecStartPre": "a(sasbttttuii)",
        "ExecStartPost": "a(sasbttttuii)",
    },
    "none": {},
}
if kind not in typed_empty_by_kind:
    raise SystemExit("unknown exact systemd property proof kind")
typed_empty = typed_empty_by_kind[kind]
if not set(typed_empty).issubset(properties):
    raise SystemExit("typed-empty proof is outside the requested property set")
environment = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
}

def run(arguments):
    result = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
        env=environment,
    )
    if result.returncode != 0 or result.stderr:
        raise SystemExit(f"exact systemd collector failed: {arguments[0]}")
    return result.stdout.decode("utf-8")

raw = run([
    "/usr/bin/systemctl", "show", "--all", unit,
    *[f"--property={name}" for name in properties],
])
values = {}
for line in raw.splitlines():
    key, separator, value = line.partition("=")
    if (
        not separator
        or key not in properties
        or key in values
    ):
        raise SystemExit("systemctl exact property output is malformed")
    values[key] = value

object_path = None
unit_id_bound = False
fragment_path_bound = False
need_daemon_reload = None
repeated_reads_identical = False
unknown_property_rejected = False
typed_empty_evidence = {}
if typed_empty:
    loaded = run([
        "/usr/bin/busctl", "--system", "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "LoadUnit", "s", unit,
    ]).strip()
    match = re.fullmatch(
        r"o \"(/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+)\"",
        loaded,
    )
    if match is None:
        raise SystemExit("systemd LoadUnit object path is malformed")
    object_path = match.group(1)

    def get_property(interface, name):
        payload = json.loads(run([
            "/usr/bin/busctl", "--system", "--json=short", "get-property",
            "org.freedesktop.systemd1", object_path,
            interface, name,
        ]))
        if (
            not isinstance(payload, dict)
            or set(payload) != {"type", "data"}
        ):
            raise SystemExit(f"systemd D-Bus property envelope differs: {name}")
        return payload

    def binding_snapshot():
        identifier = get_property("org.freedesktop.systemd1.Unit", "Id")
        fragment = get_property(
            "org.freedesktop.systemd1.Unit",
            "FragmentPath",
        )
        reload_state = get_property(
            "org.freedesktop.systemd1.Unit",
            "NeedDaemonReload",
        )
        if identifier != {"type": "s", "data": unit}:
            raise SystemExit("systemd D-Bus unit identity differs")
        if (
            "FragmentPath" not in values
            or fragment != {"type": "s", "data": values["FragmentPath"]}
        ):
            raise SystemExit("systemd D-Bus fragment binding differs")
        if reload_state != {"type": "b", "data": False}:
            raise SystemExit("systemd manager still requires daemon-reload")
        return identifier, fragment, reload_state

    binding_before = binding_snapshot()
    first_round = {}
    for name, signature in sorted(typed_empty.items()):
        payload = get_property("org.freedesktop.systemd1.Service", name)
        if payload != {"type": signature, "data": []}:
            raise SystemExit(f"systemd D-Bus typed-empty proof differs: {name}")
        first_round[name] = payload
        if name in values and values[name]:
            raise SystemExit(f"systemctl and D-Bus disagree for empty property: {name}")
        values[name] = ""
    unknown = subprocess.run(
        [
            "/usr/bin/busctl", "--system", "--json=short", "get-property",
            "org.freedesktop.systemd1", object_path,
            "org.freedesktop.systemd1.Service",
            "ShadowpipeUnknownPropertyProbe",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
        env=environment,
    )
    expected_unknown_error = (
        "Failed to get property ShadowpipeUnknownPropertyProbe on interface "
        "org.freedesktop.systemd1.Service: Unknown interface "
        "org.freedesktop.systemd1.Service or property "
        "ShadowpipeUnknownPropertyProbe.\n"
    ).encode("utf-8")
    if (
        unknown.returncode != 1
        or unknown.stdout
        or unknown.stderr != expected_unknown_error
    ):
        raise SystemExit("unknown systemd D-Bus property was not rejected")
    second_round = {
        name: get_property("org.freedesktop.systemd1.Service", name)
        for name in sorted(typed_empty)
    }
    binding_after = binding_snapshot()
    if first_round != second_round or binding_before != binding_after:
        raise SystemExit("systemd D-Bus properties changed across repeated reads")
    typed_empty_evidence = first_round
    unit_id_bound = True
    fragment_path_bound = True
    need_daemon_reload = False
    repeated_reads_identical = True
    unknown_property_rejected = True
if set(values) != set(properties):
    raise SystemExit("exact systemd property census differs after D-Bus proof")
for name in properties:
    print(f"{name}={values[name]}")
json.dump(
    {
        "schema_version": 1,
        "unit": unit,
        "object_path": object_path,
        "dbus_typed_empty": typed_empty_evidence,
        "unit_id_bound": unit_id_bound,
        "fragment_path_bound": fragment_path_bound,
        "need_daemon_reload": need_daemon_reload,
        "repeated_reads_identical": repeated_reads_identical,
        "unknown_property_rejected": unknown_property_rejected,
    },
    sys.stderr,
    ensure_ascii=True,
    sort_keys=True,
    separators=(",", ":"),
)
sys.stderr.write("\n")
' "${unit}" "${kind}" "$@" \
    || return 1
  verify_systemd_dbus_typed_empty_sidecar \
    "${output}.stderr" "${kind}" "${unit}"
}

capture_client_unit_loop() {
  local clone_id="$1" output="$2"
  run_recorded 45 "${output}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import json
import re
import subprocess
import time

unit = "shadowpipe-client-full-tunnel.service"
marker = "load mandatory root-owned client credential before startup"
property_names = (
    "LoadState", "FragmentPath", "UnitFileState", "ActiveState", "SubState",
    "Result", "ExecMainCode", "ExecMainStatus", "NRestarts", "MainPID",
    "Restart", "RestartUSec", "InvocationID", "After", "Requires",
    "ConditionResult", "DropInPaths", "ExecCondition", "ExecStart",
    "ExecStartPre", "ExecStartPost", "EnvironmentFiles",
)

def run(arguments):
    result = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
        env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if result.returncode != 0 or result.stderr:
        raise SystemExit(f"systemd lifecycle observation failed: {arguments[0]}")
    return result.stdout.decode("utf-8")

typed_empty_signatures = {
    "ExecCondition": "a(sasbttttuii)",
    "ExecStartPre": "a(sasbttttuii)",
    "ExecStartPost": "a(sasbttttuii)",
}

def typed_empty_proof():
    loaded = run([
        "/usr/bin/busctl", "--system", "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "LoadUnit", "s", unit,
    ]).strip()
    match = re.fullmatch(
        r"o \"(/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+)\"",
        loaded,
    )
    if match is None:
        raise SystemExit("client-loop LoadUnit object path is malformed")
    object_path = match.group(1)

    def get_property(interface, name):
        payload = json.loads(run([
            "/usr/bin/busctl", "--system", "--json=short", "get-property",
            "org.freedesktop.systemd1", object_path, interface, name,
        ]))
        if (
            not isinstance(payload, dict)
            or set(payload) != {"type", "data"}
        ):
            raise SystemExit(f"client-loop D-Bus envelope differs: {name}")
        return payload

    def binding_snapshot():
        identifier = get_property("org.freedesktop.systemd1.Unit", "Id")
        fragment = get_property(
            "org.freedesktop.systemd1.Unit",
            "FragmentPath",
        )
        reload_state = get_property(
            "org.freedesktop.systemd1.Unit",
            "NeedDaemonReload",
        )
        if identifier != {"type": "s", "data": unit}:
            raise SystemExit("client-loop D-Bus unit identity differs")
        if fragment != {
            "type": "s",
            "data": "/etc/systemd/system/shadowpipe-client-full-tunnel.service",
        }:
            raise SystemExit("client-loop D-Bus fragment differs")
        if reload_state != {"type": "b", "data": False}:
            raise SystemExit("client-loop manager still requires daemon-reload")
        return identifier, fragment, reload_state

    binding_before = binding_snapshot()
    first = {}
    for name, signature in sorted(typed_empty_signatures.items()):
        payload = get_property("org.freedesktop.systemd1.Service", name)
        if payload != {"type": signature, "data": []}:
            raise SystemExit(f"client-loop typed-empty proof differs: {name}")
        first[name] = payload
    unknown = subprocess.run(
        [
            "/usr/bin/busctl", "--system", "--json=short", "get-property",
            "org.freedesktop.systemd1", object_path,
            "org.freedesktop.systemd1.Service",
            "ShadowpipeUnknownPropertyProbe",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
        env={
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
        },
    )
    expected_unknown_error = (
        "Failed to get property ShadowpipeUnknownPropertyProbe on interface "
        "org.freedesktop.systemd1.Service: Unknown interface "
        "org.freedesktop.systemd1.Service or property "
        "ShadowpipeUnknownPropertyProbe.\n"
    ).encode("utf-8")
    if (
        unknown.returncode != 1
        or unknown.stdout
        or unknown.stderr != expected_unknown_error
    ):
        raise SystemExit("client-loop unknown D-Bus property was not rejected")
    second = {
        name: get_property("org.freedesktop.systemd1.Service", name)
        for name in sorted(typed_empty_signatures)
    }
    binding_after = binding_snapshot()
    if first != second or binding_before != binding_after:
        raise SystemExit("client-loop D-Bus proof changed across repeated reads")
    return {
        "properties": first,
        "unit_id_bound": True,
        "fragment_path_bound": True,
        "need_daemon_reload": False,
        "repeated_reads_identical": True,
        "unknown_property_rejected": True,
    }

dbus_proof = typed_empty_proof()

def properties():
    output = run([
        "/usr/bin/systemctl", "show", "--all", unit,
        *[f"--property={name}" for name in property_names],
    ])
    values = {}
    for line in output.splitlines():
        if "=" not in line:
            raise SystemExit("malformed systemctl show output")
        key, value = line.split("=", 1)
        if key in values:
            raise SystemExit("duplicate systemctl property")
        values[key] = value
    for name in typed_empty_signatures:
        if name in values and values[name]:
            raise SystemExit(f"client-loop systemctl empty property differs: {name}")
        values[name] = ""
    if set(values) != set(property_names):
        raise SystemExit("systemctl property census differs")
    return values

def credential_failure_ids():
    output = run([
        "/usr/bin/journalctl", "-b", "-u", unit, "--no-pager", "-o", "json",
    ])
    identifiers = []
    for line in output.splitlines():
        entry = json.loads(line)
        message = entry.get("MESSAGE")
        identifier = entry.get("_SYSTEMD_INVOCATION_ID")
        if isinstance(message, str) and marker in message:
            if not isinstance(identifier, str) or re.fullmatch(r"[0-9a-f]{32}", identifier) is None:
                raise SystemExit("credential failure journal entry lacks a canonical invocation ID")
            if identifier not in identifiers:
                identifiers.append(identifier)
    return identifiers

deadline = time.monotonic() + 30.0
restart_samples = []
final = None
identifiers = []
while time.monotonic() < deadline:
    observed = properties()
    restarts = observed["NRestarts"]
    if re.fullmatch(r"[0-9]+", restarts) is None:
        raise SystemExit("NRestarts is not an integer")
    restarts = int(restarts, 10)
    if not restart_samples or restarts != restart_samples[-1]:
        if restart_samples and restarts <= restart_samples[-1]:
            raise SystemExit("NRestarts did not increase monotonically")
        restart_samples.append(restarts)
    identifiers = credential_failure_ids()
    if (
        restarts >= 2
        and len(identifiers) >= 3
        and len(restart_samples) >= 2
        and observed["ActiveState"] == "activating"
        and observed["SubState"] == "auto-restart"
        and observed["MainPID"] == "0"
    ):
        final = observed
        break
    time.sleep(0.05)
if final is None:
    raise SystemExit("bounded systemd restart-loop observation did not converge")
if len(restart_samples) < 2:
    raise SystemExit("restart-loop sampler did not observe an increasing NRestarts transition")
proof = {
    "schema_version": 1,
    "credential_failure_marker": marker,
    "invocation_ids": identifiers,
    "restart_samples": restart_samples,
    "properties": final,
    "dbus_typed_empty_proof": dbus_proof,
}
print(json.dumps(proof, sort_keys=True, separators=(",", ":")))
'
}

capture_client_unit_status() {
  local clone_id="$1" output="$2"
  capture_exact_systemd_properties \
    "${clone_id}" shadowpipe-client-full-tunnel.service client "${output}" \
    LoadState FragmentPath UnitFileState ActiveState SubState \
    Result ExecMainCode ExecMainStatus NRestarts MainPID \
    Restart RestartUSec InvocationID After Requires \
    ConditionResult DropInPaths ExecCondition ExecStart ExecStartPre \
    ExecStartPost EnvironmentFiles
}

verify_client_unit_evidence() {
  local loop_file="$1" stopped_file="$2" stable_file="$3"
  local journal_stopped="$4" journal_stable="$5" enabled_file="$6"
  local baseline="$7" final="$8" wait_file="$9"
  python3 -I -S - "${loop_file}" "${stopped_file}" "${stable_file}" \
    "${journal_stopped}" "${journal_stable}" "${enabled_file}" \
    "${baseline}" "${final}" "${wait_file}" <<'PY'
import json
import re
import sys

(loop_path, stopped_path, stable_path, journal_stopped_path,
 journal_stable_path, enabled_path, baseline_path, final_path,
 wait_path) = sys.argv[1:]
expected_properties = {
    "LoadState", "FragmentPath", "UnitFileState", "ActiveState", "SubState",
    "Result", "ExecMainCode", "ExecMainStatus", "NRestarts", "MainPID",
    "Restart", "RestartUSec", "InvocationID", "After", "Requires",
    "ConditionResult", "DropInPaths", "ExecCondition", "ExecStart",
    "ExecStartPre", "ExecStartPost", "EnvironmentFiles",
}

def properties(path):
    values = {}
    with open(path, "r", encoding="utf-8") as stream:
        for raw in stream:
            line = raw.rstrip("\n")
            if "=" not in line:
                raise SystemExit(f"malformed client-unit property in {path}")
            key, value = line.split("=", 1)
            if key in values:
                raise SystemExit(f"duplicate client-unit property {key}")
            values[key] = value
    if set(values) != expected_properties:
        raise SystemExit(f"client-unit property set differs in {path}")
    return values

def validate_common(values, label):
    if values["LoadState"] != "loaded" or values["UnitFileState"] != "enabled":
        raise SystemExit(f"{label} client unit is not loaded and enabled")
    if values["FragmentPath"] != "/etc/systemd/system/shadowpipe-client-full-tunnel.service":
        raise SystemExit(f"{label} client unit fragment path differs")
    if values["Restart"] != "always" or values["RestartUSec"] != "1s":
        raise SystemExit(f"{label} client unit does not expose Restart=always/1s")
    if values["ConditionResult"] != "yes":
        raise SystemExit(f"{label} client unit conditions did not pass")
    if (
        values["DropInPaths"]
        or values["ExecCondition"]
        or values["ExecStartPre"]
        or values["ExecStartPost"]
    ):
        raise SystemExit(f"{label} client unit has an effective drop-in or hook")
    if values["EnvironmentFiles"] != "/etc/shadowpipe/client.env (ignore_errors=no)":
        raise SystemExit(f"{label} client unit environment-file binding differs")
    restore = "shadowpipe-lockdown-restore.service"
    if restore not in values["After"].split() or restore not in values["Requires"].split():
        raise SystemExit(f"{label} client unit lacks restore Requires+After")
    if "/usr/local/bin/shadowpipe-client" not in values["ExecStart"]:
        raise SystemExit(f"{label} client unit ExecStart differs")

with open(loop_path, "r", encoding="utf-8") as stream:
    loop = json.load(stream)
if set(loop) != {
    "schema_version", "credential_failure_marker", "invocation_ids",
    "restart_samples", "properties", "dbus_typed_empty_proof",
} or loop["schema_version"] != 1:
    raise SystemExit("restart-loop proof schema differs")
if loop["credential_failure_marker"] != "load mandatory root-owned client credential before startup":
    raise SystemExit("restart-loop credential failure marker differs")
dbus_proof = loop["dbus_typed_empty_proof"]
if (
    not isinstance(dbus_proof, dict)
    or set(dbus_proof)
    != {
        "properties", "unit_id_bound", "fragment_path_bound",
        "need_daemon_reload", "repeated_reads_identical",
        "unknown_property_rejected",
    }
    or dbus_proof["properties"]
    != {
        "ExecCondition": {"type": "a(sasbttttuii)", "data": []},
        "ExecStartPre": {"type": "a(sasbttttuii)", "data": []},
        "ExecStartPost": {"type": "a(sasbttttuii)", "data": []},
    }
    or dbus_proof["unit_id_bound"] is not True
    or dbus_proof["fragment_path_bound"] is not True
    or dbus_proof["need_daemon_reload"] is not False
    or dbus_proof["repeated_reads_identical"] is not True
    or dbus_proof["unknown_property_rejected"] is not True
):
    raise SystemExit("restart-loop D-Bus typed-empty proof differs")
looping = loop["properties"]
if set(looping) != expected_properties:
    raise SystemExit("restart-loop property set differs")
validate_common(looping, "looping")
if looping["ActiveState"] != "activating" or looping["SubState"] != "auto-restart":
    raise SystemExit("client unit was not captured inside auto-restart")
if looping["Result"] != "exit-code" or looping["ExecMainCode"] != "1":
    raise SystemExit("client unit did not fail through a normal process exit")
if re.fullmatch(r"[1-9][0-9]*", looping["ExecMainStatus"]) is None:
    raise SystemExit("client process did not exit nonzero")
if looping["MainPID"] != "0":
    raise SystemExit("restart-loop proof was not captured between generations")
samples = loop["restart_samples"]
if (
    not isinstance(samples, list)
    or len(samples) < 2
    or any(type(value) is not int or value < 0 for value in samples)
    or any(left >= right for left, right in zip(samples, samples[1:]))
    or samples[-1] < 2
):
    raise SystemExit("restart-loop NRestarts samples are not strictly increasing to >=2")
if int(looping["NRestarts"], 10) != samples[-1]:
    raise SystemExit("restart-loop properties and NRestarts samples disagree")
loop_ids = loop["invocation_ids"]
if (
    not isinstance(loop_ids, list)
    or len(loop_ids) < 3
    or len(set(loop_ids)) != len(loop_ids)
    or any(re.fullmatch(r"[0-9a-f]{32}", value or "") is None for value in loop_ids)
):
    raise SystemExit("restart-loop proof lacks three distinct canonical invocation IDs")

stopped = properties(stopped_path)
stable = properties(stable_path)
for label, values in (("stopped", stopped), ("stable", stable)):
    validate_common(values, label)
    if values["ActiveState"] != "inactive" or values["SubState"] != "dead":
        raise SystemExit(f"operator stop did not leave client {label} inactive/dead")
    if values["MainPID"] != "0":
        raise SystemExit(f"operator stop left a client MainPID in {label} proof")
if stopped["NRestarts"] != stable["NRestarts"]:
    raise SystemExit("a restart appeared after the stable operator-stop interval")

def journal_ids(path):
    identifiers = []
    marker = loop["credential_failure_marker"]
    with open(path, "r", encoding="utf-8") as stream:
        for raw in stream:
            entry = json.loads(raw)
            message = entry.get("MESSAGE")
            identifier = entry.get("_SYSTEMD_INVOCATION_ID")
            if isinstance(message, str) and marker in message:
                if not isinstance(identifier, str) or re.fullmatch(r"[0-9a-f]{32}", identifier) is None:
                    raise SystemExit("credential failure journal entry lacks invocation identity")
                if identifier not in identifiers:
                    identifiers.append(identifier)
    return identifiers

stopped_ids = journal_ids(journal_stopped_path)
stable_ids = journal_ids(journal_stable_path)
if len(stopped_ids) < 3 or not set(loop_ids).issubset(stopped_ids):
    raise SystemExit("operator-stop journal lacks the observed restart generations")
if stopped_ids != stable_ids:
    raise SystemExit("a credential-failure invocation appeared after operator stop")

with open(wait_path, "r", encoding="ascii") as stream:
    wait_lines = stream.read().splitlines()
if len(wait_lines) != 1 or not wait_lines[0].startswith("stable_wait_seconds="):
    raise SystemExit("operator-stop stability wait proof is malformed")
try:
    stable_wait = float(wait_lines[0].split("=", 1)[1])
except ValueError as error:
    raise SystemExit("operator-stop stability wait is not numeric") from error
if not stable_wait > 1.0:
    raise SystemExit("operator-stop stability wait did not exceed RestartSec=1s")

with open(enabled_path, "r", encoding="utf-8") as stream:
    if stream.read().strip() != "enabled":
        raise SystemExit("client unit is not persistently enabled")
with open(baseline_path, "rb") as stream:
    baseline = stream.read()
with open(final_path, "rb") as stream:
    final = stream.read()
if baseline != final:
    raise SystemExit("guest route/rule/nft/DNS/interface/WAL state changed")
state = json.loads(baseline)
if set(state) != {
    "schema_version", "ipv4_routes", "ipv6_routes", "ipv4_rules",
    "ipv6_rules", "links", "nft_ruleset", "resolver", "tun_interfaces",
    "client_pids", "lockdown_wal_absent", "main_wal_absent",
} or state["schema_version"] != 1:
    raise SystemExit("guest client network-state proof schema differs")
if state["tun_interfaces"] or state["client_pids"]:
    raise SystemExit("guest client network-state proof contains TUN/client residue")
if not state["lockdown_wal_absent"] or not state["main_wal_absent"]:
    raise SystemExit("guest client network-state proof contains a Shadowpipe WAL")
PY
}

run_recorded() {
  local timeout="$1" output="$2"
  shift 2
  local status
  if run_bounded "${timeout}" "$@" >"${output}" 2>"${output}.stderr"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "${status}" >"${output}.status" || return 1
  return "${status}"
}

file_size_bytes() {
  local path="$1" size
  [[ -f "${path}" && ! -L "${path}" ]] || return 1
  size="$(LC_ALL=C wc -c <"${path}" | tr -d '[:space:]')" || return 1
  [[ "${size}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${size}"
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
  stdout_size="$(file_size_bytes "${output}" 2>/dev/null || printf '%s' 0)"
  stderr_size="$(file_size_bytes "${output}.stderr" 2>/dev/null || printf '%s' 0)"
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

validate_git_metadata_safety() {
  local repo_root="$1" output="$2" revision="${3:-HEAD}"
  python3 -I -S - "${repo_root}" "${output}" "${revision}" <<'PY'
import json
import os
import re
import stat
import subprocess
import sys

repo = os.path.realpath(sys.argv[1])
output = sys.argv[2]
revision = sys.argv[3]
dangerous_exact = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_ATTR_NOSYSTEM",
    "GIT_ATTR_SOURCE",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
}
ambient = sorted(
    key
    for key in os.environ
    if key in dangerous_exact or key.startswith("GIT_CONFIG_")
)
if ambient:
    raise SystemExit("ambient Git metadata override variables are not allowed")
env = os.environ.copy()
for key in list(env):
    if key in dangerous_exact or key.startswith("GIT_CONFIG_"):
        env.pop(key, None)
env["GIT_NO_REPLACE_OBJECTS"] = "1"
env["GIT_CONFIG_NOSYSTEM"] = "1"
env["GIT_CONFIG_GLOBAL"] = os.devnull
env["GIT_ATTR_NOSYSTEM"] = "1"

def git(*arguments, statuses=(0,), text=True):
    process = subprocess.run(
        ["git", "-C", repo, *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
        env=env,
        text=text,
    )
    if process.returncode not in statuses:
        raise SystemExit(
            f"Git metadata proof failed for {arguments[0]} "
            f"with status {process.returncode}"
        )
    return process

top = os.path.realpath(git("rev-parse", "--show-toplevel").stdout.strip())
if top != repo:
    raise SystemExit("Git metadata proof top-level differs from repository")
git_dir_text = git("rev-parse", "--absolute-git-dir").stdout.strip()
if not os.path.isabs(git_dir_text):
    raise SystemExit("Git directory is not absolute")
git_dir = os.path.realpath(git_dir_text)
git_dir_info = os.lstat(git_dir)
if not stat.S_ISDIR(git_dir_info.st_mode) or stat.S_ISLNK(git_dir_info.st_mode):
    raise SystemExit("Git directory is not a real directory")
common_dir_text = git(
    "rev-parse", "--path-format=absolute", "--git-common-dir"
).stdout.strip()
if not os.path.isabs(common_dir_text):
    raise SystemExit("Git common directory is not absolute")
common_dir = os.path.realpath(common_dir_text)
common_dir_info = os.lstat(common_dir)
if (
    not stat.S_ISDIR(common_dir_info.st_mode)
    or stat.S_ISLNK(common_dir_info.st_mode)
):
    raise SystemExit("Git common directory is not a real directory")
metadata_paths = {
    os.path.join(git_dir, "info/grafts"),
    os.path.join(git_dir, "info/attributes"),
    os.path.join(common_dir, "info/grafts"),
    os.path.join(common_dir, "info/attributes"),
}
for relative in ("info/grafts", "info/attributes"):
    resolved_path = git(
        "rev-parse", "--path-format=absolute", "--git-path", relative
    ).stdout.strip()
    if not os.path.isabs(resolved_path):
        raise SystemExit(f"Git metadata path is not absolute: {relative}")
    metadata_paths.add(resolved_path)
for path in metadata_paths:
    if os.path.lexists(path):
        raise SystemExit(
            f"local Git metadata override exists: {os.path.basename(path)}"
        )
replacements = git(
    "for-each-ref", "--format=%(refname)", "refs/replace"
).stdout.splitlines()
if replacements:
    raise SystemExit("Git replacement refs are not allowed")
attributes = git(
    "config", "--get-all", "core.attributesFile", statuses=(0, 1)
)
if attributes.returncode == 0 or attributes.stdout:
    raise SystemExit("local/worktree core.attributesFile is not allowed")
resolved = git(
    "rev-parse", "--verify", f"{revision}^{{commit}}"
).stdout.strip()
if re.fullmatch(r"[0-9a-f]{40,64}", resolved) is None:
    raise SystemExit("Git metadata proof revision is not one commit object ID")
tree_raw = git(
    "ls-tree", "-rz", "--full-tree", resolved, text=False
).stdout
for record in tree_raw.split(b"\0"):
    if not record:
        continue
    metadata, separator, raw_path = record.partition(b"\t")
    fields = metadata.split()
    if not separator or len(fields) != 3:
        raise SystemExit("Git tree record is malformed")
    mode, kind, object_id = fields
    if (
        mode not in (b"100644", b"100755", b"040000")
        or kind not in (b"blob", b"tree")
        or len(object_id) not in (40, 64)
    ):
        raise SystemExit("Git tree contains a link, gitlink, or special entry")
    try:
        path = raw_path.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit("tracked path is not UTF-8") from error
    if os.path.basename(path) == ".gitattributes":
        raise SystemExit("tracked .gitattributes is not allowed in pinned archive input")
descriptor = os.open(
    output,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
    json.dump(
        {
            "git_metadata_safety": "valid",
            "replace_refs": "absent",
            "info_grafts": "absent",
            "info_attributes": "absent",
            "tracked_gitattributes": "absent",
            "core_attributes_file": "absent",
            "system_attributes": "disabled",
            "tree_entry_types": "regular_only",
            "validated_commit": resolved,
        },
        stream,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    stream.write("\n")
PY
}

run_recorded_with_stdin() {
  local timeout="$1" output="$2" input="$3"
  shift 3
  [[ -f "${input}" && ! -L "${input}" ]] || return 1
  # run_bounded deliberately gives its direct child /dev/null on stdin. This
  # host-side wrapper opens the already validated regular input file and then
  # execs the bounded command, preserving the process-group timeout contract.
  # shellcheck disable=SC2016
  run_recorded "${timeout}" "${output}" /bin/sh -c \
    'input=$1; shift; exec "$@" <"$input"' \
    shadowpipe-bounded-stdin "${input}" "$@"
}

capture_git_checkout_proof() {
  local repo_root="$1" output="$2" expected_head="${3:-}"
  mkdir -m 0700 -- "${output}" || return 1
  validate_git_metadata_safety "${repo_root}" \
    "${output}/git-metadata-safety.json" \
    "${expected_head:-HEAD}" || return 1
  # Prove cleanliness without materializing names of dirty paths in evidence.
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
    ' quiet-git-status "${repo_root}" || return 1
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
  # Suppress remote stderr: an HTTPS remote failure could echo credential
  # material. Only the expected object ID/ref pair is retained.
  # shellcheck disable=SC2016
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${output}/origin-main-live.txt" \
    /bin/sh -c \
    'GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="ssh -oBatchMode=yes -oConnectionAttempts=1" git -C "$1" ls-remote --refs origin refs/heads/main 2>/dev/null' \
    live-origin-main "${repo_root}" || return 1
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
    raise SystemExit("Git HEAD changed during the reboot lab")
live = one_line("origin-main-live.txt", allow_tab=True).split("\t")
if live != [head, "refs/heads/main"]:
    raise SystemExit("Git HEAD differs from live pushed origin/main")
with open(
    os.path.join(root, "checkout.env"),
    "x",
    encoding="ascii",
    newline="\n",
) as stream:
    stream.write("git_checkout=clean_pushed_main\n")
    stream.write(f"pinned_head={head}\n")
    stream.write("live_origin_main_match=true\n")
    stream.write("archive_source=git_object_database\n")
PY
}

create_pinned_source_archive() {
  local repo_root="$1" pinned_head="$2" archive="$3" metadata="$4"
  validate_git_metadata_safety "${repo_root}" \
    "${metadata}.git-metadata-safety-before.json" \
    "${pinned_head}" || return 1
  run_recorded_limited "${HOST_COMMAND_TIMEOUT}" "${archive}" \
    "${MAX_SOURCE_ARCHIVE_BYTES}" "${MAX_SOURCE_ARCHIVE_STDERR_BYTES}" \
    /usr/bin/env \
    -u GIT_ALTERNATE_OBJECT_DIRECTORIES \
    -u GIT_ATTR_NOSYSTEM \
    -u GIT_ATTR_SOURCE \
    -u GIT_COMMON_DIR \
    -u GIT_DIR \
    -u GIT_GRAFT_FILE \
    -u GIT_INDEX_FILE \
    -u GIT_NAMESPACE \
    -u GIT_OBJECT_DIRECTORY \
    -u GIT_REPLACE_REF_BASE \
    -u GIT_SHALLOW_FILE \
    -u GIT_WORK_TREE \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_ATTR_NOSYSTEM=1 \
    GIT_GRAFT_FILE=/dev/null \
    GIT_NO_LAZY_FETCH=1 \
    GIT_NO_REPLACE_OBJECTS=1 \
    git -c core.attributesFile=/dev/null \
    -C "${repo_root}" archive --format=tar --prefix=shadowpipe/ \
    "${pinned_head}" || return 1
  validate_git_metadata_safety "${repo_root}" \
    "${metadata}.git-metadata-safety-after.json" \
    "${pinned_head}" || return 1
  # shellcheck disable=SC2016
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${metadata}.commit" /bin/sh -c \
    'exec /usr/bin/env \
      -u GIT_ALTERNATE_OBJECT_DIRECTORIES \
      -u GIT_ATTR_NOSYSTEM \
      -u GIT_ATTR_SOURCE \
      -u GIT_COMMON_DIR \
      -u GIT_DIR \
      -u GIT_GRAFT_FILE \
      -u GIT_INDEX_FILE \
      -u GIT_NAMESPACE \
      -u GIT_OBJECT_DIRECTORY \
      -u GIT_REPLACE_REF_BASE \
      -u GIT_SHALLOW_FILE \
      -u GIT_WORK_TREE \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_ATTR_NOSYSTEM=1 \
      GIT_NO_LAZY_FETCH=1 \
      GIT_NO_REPLACE_OBJECTS=1 \
      git -c core.attributesFile=/dev/null \
      -C / get-tar-commit-id <"$1"' \
    source-archive "${archive}" || return 1
  python3 -I -S - "${archive}" "${metadata}.commit" "${metadata}" \
    "${pinned_head}" "${MAX_SOURCE_ARCHIVE_BYTES}" \
    "${MAX_SOURCE_EXPANDED_BYTES}" <<'PY'
import hashlib
import os
import re
import stat
import sys
import tarfile

archive, commit_path, output, expected, maximum_text, expanded_max_text = sys.argv[1:]
maximum = int(maximum_text, 10)
expanded_max = int(expanded_max_text, 10)
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
members = 0
expanded = 0
seen = set()
with tarfile.open(archive, "r:") as source:
    for member in source:
        members += 1
        name = member.name.rstrip("/")
        parts = name.split("/")
        if (
            members > 20000
            or not name
            or name.startswith("/")
            or any(part in ("", ".", "..") for part in parts)
            or parts[0] != "shadowpipe"
            or any(ord(character) < 0x20 or ord(character) == 0x7f for character in name)
            or name in seen
        ):
            raise SystemExit("pinned source archive member census is unsafe")
        seen.add(name)
        if member.isdir():
            continue
        if not member.isfile() or member.size < 0:
            raise SystemExit("pinned source archive contains a link or special member")
        expanded += member.size
        if expanded > expanded_max:
            raise SystemExit("pinned source archive expanded bytes exceeded")
with open(output, "x", encoding="ascii", newline="\n") as stream:
    stream.write("source_archive=git_archive\n")
    stream.write(f"pinned_head={expected}\n")
    stream.write(f"source_archive_bytes={info.st_size}\n")
    stream.write(f"source_archive_sha256={digest.hexdigest()}\n")
    stream.write(f"source_archive_members={members}\n")
    stream.write(f"source_expanded_bytes={expanded}\n")
PY
}

source_archive_field() {
  local metadata="$1" field="$2"
  awk -F= -v field="${field}" \
    '$1 == field { count += 1; value = substr($0, index($0, "=") + 1) }
     END { if (count != 1 || value == "") exit 1; print value }' \
    "${metadata}"
}

validate_host_cargo_boundary() {
  local cargo_home="$1" output="$2"
  python3 -I -S - "${cargo_home}" "${output}" <<'PY'
import os
import stat
import sys

cargo_home = os.path.realpath(sys.argv[1])
output = sys.argv[2]
dangerous_exact = {
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
}
ambient = sorted(
    key for key in os.environ
    if key.startswith("CARGO_") or key in dangerous_exact
)
if ambient:
    raise SystemExit("ambient Cargo or Rust override variables are not allowed")
info = os.lstat(cargo_home)
if (
    not stat.S_ISDIR(info.st_mode)
    or stat.S_ISLNK(info.st_mode)
    or info.st_uid != os.getuid()
    or stat.S_IMODE(info.st_mode) & 0o022
):
    raise SystemExit("default Cargo cache is not a private same-user directory")
for path in (
    os.path.join(cargo_home, "config"),
    os.path.join(cargo_home, "config.toml"),
    "/.cargo/config",
    "/.cargo/config.toml",
):
    if os.path.lexists(path):
        raise SystemExit("ambient Cargo configuration file is not allowed")
proxy_names = (
    "ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
    "all_proxy", "https_proxy", "http_proxy", "no_proxy",
)
proxy_count = sum(name in os.environ for name in proxy_names)
descriptor = os.open(
    output,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
    stream.write("cargo_environment_overrides=absent\n")
    stream.write("cargo_config_files=absent\n")
    stream.write("cargo_home_cache=trusted_same_user_input\n")
    stream.write("cargo_vendor_network=offline\n")
    stream.write("cargo_proxy_environment=sanitized\n")
    stream.write(f"ambient_proxy_variable_count={proxy_count}\n")
PY
}

extract_host_source_for_vendor() {
  local archive="$1" destination="$2" expected_size="$3" expected_hash="$4"
  local output="$5"
  python3 -I -S - \
    "${archive}" "${destination}" "${expected_size}" "${expected_hash}" \
    "${MAX_SOURCE_EXPANDED_BYTES}" "${output}" <<'PY'
import hashlib
import os
import stat
import sys
import tarfile

(archive, destination, size_text, expected_hash, expanded_text, output) = sys.argv[1:]
expected_size = int(size_text, 10)
expanded_max = int(expanded_text, 10)
if os.path.lexists(destination):
    raise SystemExit("private vendor source destination already exists")
archive_info = os.lstat(archive)
if (
    not stat.S_ISREG(archive_info.st_mode)
    or stat.S_ISLNK(archive_info.st_mode)
    or archive_info.st_nlink != 1
    or archive_info.st_size != expected_size
):
    raise SystemExit("source archive changed before private extraction")

def file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb", buffering=0) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

before_hash = file_hash(archive)
if before_hash != expected_hash:
    raise SystemExit("source archive digest changed before vendor extraction")
parent = os.path.dirname(destination)
parent_info = os.lstat(parent)
if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
    raise SystemExit("private vendor stage parent is unsafe")
os.mkdir(destination, 0o700)
seen = set()
required_directories = set()
regular_paths = set()
members = 0
expanded = 0
with tarfile.open(archive, "r:") as source:
    for member in source:
        members += 1
        name = member.name.rstrip("/")
        parts = name.split("/")
        if (
            members > 20000
            or not name
            or name.startswith("/")
            or "\\" in name
            or any(part in ("", ".", "..") for part in parts)
            or parts[0] != "shadowpipe"
            or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in name)
            or name in seen
            or any("/".join(parts[:index]) in regular_paths
                   for index in range(1, len(parts)))
            or (not member.isdir() and name in required_directories)
            or member.issparse()
        ):
            raise SystemExit("source archive has an unsafe member graph")
        seen.add(name)
        for index in range(1, len(parts)):
            required_directories.add("/".join(parts[:index]))
        relative_parts = parts[1:]
        if not relative_parts:
            if not member.isdir():
                raise SystemExit("source archive root is not a directory")
            continue
        target = os.path.join(destination, *relative_parts)
        if os.path.commonpath((destination, target)) != destination:
            raise SystemExit("source archive escaped private destination")
        if member.isdir():
            if os.path.lexists(target):
                if not stat.S_ISDIR(os.lstat(target).st_mode):
                    raise SystemExit("source directory collided with a file")
            else:
                os.makedirs(target, mode=0o700, exist_ok=False)
            continue
        if not member.isfile() or member.size < 0:
            raise SystemExit("source archive contains a link or special member")
        regular_paths.add(name)
        expanded += member.size
        if expanded > expanded_max:
            raise SystemExit("source archive expanded-byte bound exceeded")
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        if os.path.lexists(target):
            raise SystemExit("source archive file path already exists")
        incoming = source.extractfile(member)
        if incoming is None:
            raise SystemExit("source archive regular member is unreadable")
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o700 if member.mode & 0o111 else 0o600,
        )
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
        finally:
            os.close(descriptor)
after_hash = file_hash(archive)
if after_hash != before_hash:
    raise SystemExit("source archive changed during private extraction")
for required in ("Cargo.toml", "Cargo.lock"):
    path = os.path.join(destination, required)
    if not os.path.isfile(path) or os.path.islink(path):
        raise SystemExit(f"private pinned source lacks {required}")
with open(output, "x", encoding="ascii", newline="\n") as stream:
    stream.write("vendor_source=pinned_git_archive\n")
    stream.write(f"source_archive_sha256_before={before_hash}\n")
    stream.write(f"source_archive_sha256_after={after_hash}\n")
    stream.write(f"source_archive_members={members}\n")
    stream.write(f"source_expanded_bytes={expanded}\n")
PY
}

seal_cargo_vendor_tree() {
  local vendor="$1" lock="$2" archive="$3" metadata="$4"
  local pinned_head="$5" source_hash="$6" guest_vendor="$7"
  python3 -I -S - \
    "${vendor}" "${lock}" "${archive}" "${metadata}" \
    "${pinned_head}" "${source_hash}" "${guest_vendor}" \
    "${MAX_VENDOR_ARCHIVE_BYTES}" "${MAX_VENDOR_EXPANDED_BYTES}" \
    "${MAX_VENDOR_MEMBERS}" <<'PY'
import gzip
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile

(vendor, lock, archive, metadata, pinned_head, source_hash, guest_vendor,
 archive_max_text, expanded_max_text, members_max_text) = sys.argv[1:]
archive_max = int(archive_max_text, 10)
expanded_max = int(expanded_max_text, 10)
members_max = int(members_max_text, 10)
if re.fullmatch(r"[0-9a-f]{40,64}", pinned_head) is None:
    raise SystemExit("invalid pinned commit for Cargo vendor bundle")
if re.fullmatch(r"[0-9a-f]{64}", source_hash) is None:
    raise SystemExit("invalid source archive digest for Cargo vendor bundle")
if re.fullmatch(
    r"/var/tmp/shadowpipe-lockdown-reboot-[A-Za-z0-9._-]+/cargo-vendor/vendor",
    guest_vendor,
) is None:
    raise SystemExit("unsafe guest Cargo vendor path")

def sha256_path(path):
    digest = hashlib.sha256()
    with open(path, "rb", buffering=0) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

def load_lock(path):
    raw = open(path, "rb").read()
    if not raw or len(raw) > 16 * 1024 * 1024 or b"\0" in raw or b"\r" in raw:
        raise SystemExit("Cargo.lock bytes are unsafe")
    text = raw.decode("utf-8")
    packages = []
    current = None
    field_re = re.compile(r'^(name|version|source|checksum) = "([^"\\]*)"$')
    for line in text.splitlines():
        if line == "[[package]]":
            if current is not None:
                packages.append(current)
            current = {}
            continue
        if current is None:
            continue
        match = field_re.fullmatch(line)
        if match:
            key, value = match.groups()
            if key in current:
                raise SystemExit("duplicate Cargo.lock package field")
            current[key] = value
    if current is not None:
        packages.append(current)
    registry = {}
    for package in packages:
        if "name" not in package or "version" not in package:
            raise SystemExit("Cargo.lock package lacks name or version")
        source = package.get("source")
        if source is None:
            if "checksum" in package:
                raise SystemExit("workspace Cargo.lock package has a checksum")
            continue
        if source != "registry+https://github.com/rust-lang/crates.io-index":
            raise SystemExit("Cargo.lock contains an unsupported non-crates.io source")
        checksum = package.get("checksum", "")
        if re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
            raise SystemExit("registry Cargo.lock package lacks a checksum")
        name = package["name"]
        version = package["version"]
        if re.fullmatch(r"[A-Za-z0-9_+.-]+", name) is None or re.fullmatch(
            r"[A-Za-z0-9_+.-]+", version
        ) is None:
            raise SystemExit("Cargo.lock package identity is unsafe")
        directory = f"{name}-{version}"
        if directory in registry:
            raise SystemExit("Cargo.lock has a colliding versioned vendor directory")
        registry[directory] = (name, version, checksum)
    if not registry:
        raise SystemExit("Cargo.lock has no crates.io packages")
    return raw, registry

lock_bytes, expected_packages = load_lock(lock)
lock_hash = hashlib.sha256(lock_bytes).hexdigest()
vendor_info = os.lstat(vendor)
if not stat.S_ISDIR(vendor_info.st_mode) or stat.S_ISLNK(vendor_info.st_mode):
    raise SystemExit("Cargo vendor root is unsafe")
actual_roots = sorted(os.listdir(vendor))
if actual_roots != sorted(expected_packages):
    raise SystemExit("versioned vendor directories differ from Cargo.lock")
directories = []
files = []
total_bytes = 0
for package_dir in actual_roots:
    package_root = os.path.join(vendor, package_dir)
    package_info = os.lstat(package_root)
    if not stat.S_ISDIR(package_info.st_mode) or stat.S_ISLNK(package_info.st_mode):
        raise SystemExit("versioned vendor package root is unsafe")
    directories.append(package_dir)
    checksum_path = os.path.join(package_root, ".cargo-checksum.json")
    checksum_info = os.lstat(checksum_path)
    if not stat.S_ISREG(checksum_info.st_mode) or checksum_info.st_nlink != 1:
        raise SystemExit("vendor package checksum metadata is unsafe")
    with open(checksum_path, "r", encoding="utf-8") as stream:
        checksum_document = json.load(stream, object_pairs_hook=unique_object)
    if type(checksum_document) is not dict or set(checksum_document) != {"files", "package"}:
        raise SystemExit("vendor package checksum schema is invalid")
    if checksum_document["package"] != expected_packages[package_dir][2]:
        raise SystemExit("vendor package checksum differs from Cargo.lock")
    checksum_files = checksum_document["files"]
    if type(checksum_files) is not dict:
        raise SystemExit("vendor package file checksums are invalid")
    actual_checksum_files = {}
    for current, dirnames, filenames in os.walk(package_root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        for dirname in dirnames:
            path = os.path.join(current, dirname)
            info = os.lstat(path)
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise SystemExit("vendor tree contains a linked directory")
            relative = os.path.relpath(path, vendor)
            if "\\" in relative or any(part in ("", ".", "..") for part in relative.split("/")):
                raise SystemExit("vendor directory path is unsafe")
            directories.append(relative)
        for filename in filenames:
            path = os.path.join(current, filename)
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SystemExit("vendor tree contains a link or special file")
            relative = os.path.relpath(path, vendor)
            if "\\" in relative or any(part in ("", ".", "..") for part in relative.split("/")):
                raise SystemExit("vendor file path is unsafe")
            digest = sha256_path(path)
            files.append({
                "path": relative,
                "bytes": info.st_size,
                "executable": bool(stat.S_IMODE(info.st_mode) & 0o111),
                "sha256": digest,
            })
            total_bytes += info.st_size
            package_relative = os.path.relpath(path, package_root)
            if package_relative != ".cargo-checksum.json":
                actual_checksum_files[package_relative] = digest
    if checksum_files != actual_checksum_files:
        raise SystemExit("vendor package files differ from .cargo-checksum.json")
directories = sorted(set(directories))
files.sort(key=lambda item: item["path"])
if len(directories) + len(files) + 5 > members_max:
    raise SystemExit("Cargo vendor member bound exceeded before archiving")
if total_bytes > expanded_max:
    raise SystemExit("Cargo vendor expanded-byte bound exceeded before archiving")
manifest_document = {
    "schema_version": 1,
    "cargo_lock_sha256": lock_hash,
    "registry_packages": [
        {"directory": directory, "name": values[0], "version": values[1],
         "package_checksum": values[2]}
        for directory, values in sorted(expected_packages.items())
    ],
    "directories": directories,
    "files": files,
}
manifest_bytes = (
    json.dumps(manifest_document, ensure_ascii=True, sort_keys=True,
               separators=(",", ":")) + "\n"
).encode("ascii")
manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
config_bytes = (
    '[source.crates-io]\n'
    'replace-with = "shadowpipe-vendored-sources"\n\n'
    '[source.shadowpipe-vendored-sources]\n'
    f'directory = "{guest_vendor}"\n\n'
    '[net]\n'
    'offline = true\n'
).encode("ascii")
config_hash = hashlib.sha256(config_bytes).hexdigest()
binding_bytes = (
    "schema_version=1\n"
    f"pinned_head={pinned_head}\n"
    f"source_archive_sha256={source_hash}\n"
    f"cargo_lock_sha256={lock_hash}\n"
    f"vendor_manifest_sha256={manifest_hash}\n"
    f"cargo_config_sha256={config_hash}\n"
).encode("ascii")
auxiliary = {
    "cargo-vendor/binding.env": binding_bytes,
    "cargo-vendor/cargo-config.toml": config_bytes,
    "cargo-vendor/vendor-manifest.json": manifest_bytes,
}

if os.path.lexists(archive):
    raise SystemExit("Cargo vendor archive path already exists")
raw = open(archive, "xb", buffering=0)
class BoundedArchiveWriter:
    def __init__(self, destination, maximum):
        self.destination = destination
        self.maximum = maximum
    def write(self, content):
        if self.destination.tell() + len(content) > self.maximum:
            raise OSError("Cargo vendor compressed archive byte bound exceeded")
        return self.destination.write(content)
    def flush(self):
        return self.destination.flush()
    def tell(self):
        return self.destination.tell()

bounded_raw = BoundedArchiveWriter(raw, archive_max)
try:
    with gzip.GzipFile(filename="", mode="wb", fileobj=bounded_raw, compresslevel=6, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as target:
            def add_directory(name):
                item = tarfile.TarInfo(name)
                item.type = tarfile.DIRTYPE
                item.mode = 0o700
                item.uid = item.gid = item.mtime = 0
                item.uname = item.gname = "root"
                target.addfile(item)
            add_directory("cargo-vendor")
            add_directory("cargo-vendor/vendor")
            for relative in directories:
                add_directory(f"cargo-vendor/vendor/{relative}")
            for entry in files:
                path = os.path.join(vendor, *entry["path"].split("/"))
                info = tarfile.TarInfo(f"cargo-vendor/vendor/{entry['path']}")
                info.size = entry["bytes"]
                info.mode = 0o700 if entry["executable"] else 0o600
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = "root"
                with open(path, "rb", buffering=0) as source:
                    target.addfile(info, source)
            for name, content in sorted(auxiliary.items()):
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mode = 0o600
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = "root"
                target.addfile(info, io.BytesIO(content))
finally:
    raw.close()
os.chmod(archive, 0o600)
archive_info = os.lstat(archive)
if (
    not stat.S_ISREG(archive_info.st_mode)
    or archive_info.st_nlink != 1
    or stat.S_IMODE(archive_info.st_mode) != 0o600
    or archive_info.st_size <= 0
    or archive_info.st_size > archive_max
):
    raise SystemExit("Cargo vendor archive size or metadata is unsafe")
archive_hash = sha256_path(archive)
seen = set()
regular = set()
required_directories = set()
member_count = 0
expanded = 0
with tarfile.open(archive, "r:gz") as source:
    for member in source:
        member_count += 1
        name = member.name.rstrip("/")
        parts = name.split("/")
        if (
            member_count > members_max
            or not name
            or name.startswith("/")
            or "\\" in name
            or any(part in ("", ".", "..") for part in parts)
            or parts[0] != "cargo-vendor"
            or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in name)
            or name in seen
            or any("/".join(parts[:index]) in regular for index in range(1, len(parts)))
            or (not member.isdir() and name in required_directories)
            or member.issparse()
        ):
            raise SystemExit("Cargo vendor archive member graph is unsafe")
        seen.add(name)
        for index in range(1, len(parts)):
            required_directories.add("/".join(parts[:index]))
        if member.isdir():
            continue
        if not member.isfile() or member.size < 0:
            raise SystemExit("Cargo vendor archive contains a link or special member")
        regular.add(name)
        expanded += member.size
        if expanded > expanded_max:
            raise SystemExit("Cargo vendor archive expanded-byte bound exceeded")
with open(metadata, "x", encoding="ascii", newline="\n") as stream:
    stream.write("dependency_bundle=cargo_vendor_v1\n")
    stream.write("cargo_vendor_command=offline_locked_versioned_dirs\n")
    stream.write("cargo_cache_boundary=trusted_same_user_host_cache\n")
    stream.write(f"pinned_head={pinned_head}\n")
    stream.write(f"source_archive_sha256={source_hash}\n")
    stream.write(f"cargo_lock_sha256={lock_hash}\n")
    stream.write(f"vendor_manifest_sha256={manifest_hash}\n")
    stream.write(f"vendor_tree_sha256={manifest_hash}\n")
    stream.write(f"cargo_config_sha256={config_hash}\n")
    stream.write(f"vendor_archive_sha256={archive_hash}\n")
    stream.write(f"vendor_archive_bytes={archive_info.st_size}\n")
    stream.write(f"vendor_archive_members={member_count}\n")
    stream.write(f"vendor_expanded_bytes={expanded}\n")
    stream.write(f"vendor_registry_packages={len(expected_packages)}\n")
    stream.write(f"vendor_files={len(files)}\n")
    stream.write(f"vendor_directories={len(directories)}\n")
PY
}

validate_cargo_workspace_metadata() {
  local source_root="$1" lock="$2" metadata_json="$3" output="$4"
  python3 -I -S - \
    "${source_root}" "${lock}" "${metadata_json}" "${output}" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys

root = os.path.realpath(sys.argv[1])
lock_path, metadata_path, output = sys.argv[2:]

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

lock_bytes = open(lock_path, "rb").read()
if (
    not lock_bytes or len(lock_bytes) > 16 * 1024 * 1024
    or b"\0" in lock_bytes or b"\r" in lock_bytes
):
    raise SystemExit("Cargo.lock is unsafe before cargo metadata")
lock_hash = hashlib.sha256(lock_bytes).hexdigest()
source_less = set()
current = None
field_re = re.compile(r'^(name|version|source|checksum) = "([^"\\]*)"$')
packages = []
for line in lock_bytes.decode("utf-8").splitlines():
    if line == "[[package]]":
        if current is not None:
            packages.append(current)
        current = {}
        continue
    if current is None:
        continue
    match = field_re.fullmatch(line)
    if match:
        key, value = match.groups()
        if key in current:
            raise SystemExit("duplicate Cargo.lock field before metadata")
        current[key] = value
if current is not None:
    packages.append(current)
for package in packages:
    if "name" not in package or "version" not in package:
        raise SystemExit("Cargo.lock package identity is incomplete")
    source = package.get("source")
    if source is None:
        identity = (package["name"], package["version"])
        if identity in source_less:
            raise SystemExit("duplicate source-less Cargo.lock package identity")
        source_less.add(identity)
    elif source != "registry+https://github.com/rust-lang/crates.io-index":
        raise SystemExit("Cargo.lock contains an unsupported external source")
if not source_less:
    raise SystemExit("Cargo.lock has no pinned workspace packages")
metadata_info = os.lstat(metadata_path)
if (
    not stat.S_ISREG(metadata_info.st_mode) or metadata_info.st_nlink != 1
    or metadata_info.st_size <= 0 or metadata_info.st_size > 32 * 1024 * 1024
):
    raise SystemExit("bounded cargo metadata JSON is unsafe")
with open(metadata_path, "r", encoding="utf-8") as stream:
    document = json.load(stream, object_pairs_hook=unique_object)
if type(document) is not dict or type(document.get("packages")) is not list:
    raise SystemExit("cargo metadata schema is invalid")
if os.path.realpath(document.get("workspace_root", "")) != root:
    raise SystemExit("cargo metadata workspace root differs from pinned source")
observed_source_less = set()
for package in document["packages"]:
    if type(package) is not dict:
        raise SystemExit("cargo metadata package is not an object")
    source = package.get("source")
    if source is not None:
        continue
    name = package.get("name")
    version = package.get("version")
    manifest = package.get("manifest_path")
    if not all(type(value) is str and value for value in (name, version, manifest)):
        raise SystemExit("source-less cargo metadata package is malformed")
    real_manifest = os.path.realpath(manifest)
    try:
        contained = os.path.commonpath((root, real_manifest)) == root
    except ValueError:
        contained = False
    if not contained:
        raise SystemExit("source-less Cargo package escaped pinned source root")
    info = os.lstat(real_manifest)
    if (
        not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
    ):
        raise SystemExit("source-less Cargo manifest is unsafe")
    identity = (name, version)
    if identity in observed_source_less:
        raise SystemExit("duplicate source-less cargo metadata identity")
    observed_source_less.add(identity)
if observed_source_less != source_less:
    raise SystemExit("source-less cargo metadata differs from Cargo.lock")
with open(output, "x", encoding="ascii", newline="\n") as stream:
    stream.write("cargo_metadata=valid\n")
    stream.write("path_dependencies=inside_pinned_source_only\n")
    stream.write(f"workspace_packages={len(source_less)}\n")
    stream.write(f"cargo_lock_sha256={lock_hash}\n")
PY
}

create_cargo_vendor_bundle() {
  local repo_root="$1" source_archive="$2" source_size="$3" source_hash="$4"
  local pinned_head="$5" stage="$6" archive="$7" metadata="$8"
  local guest_vendor="$9" cargo_home cargo_bin cargo_path source_root vendor
  local lock_hash_before lock_hash_after
  cargo_home="${HOME}/.cargo"
  validate_host_cargo_boundary "${cargo_home}" "${metadata}.boundary.env" \
    || return 1
  [[ ! -e "${stage}" && ! -L "${stage}" ]] || return 1
  mkdir -m 0700 -- "${stage}" || return 1
  source_root="${stage}/shadowpipe"
  extract_host_source_for_vendor "${source_archive}" "${source_root}" \
    "${source_size}" "${source_hash}" "${metadata}.source-extract.env" \
    || return 1
  create_provenance_manifest "${source_root}" \
    "${metadata}.pinned-source-before.sha256" || return 1
  vendor="${stage}/vendor"
  cargo_bin="$(command -v cargo)" || return 1
  [[ "${cargo_bin}" == /* && -x "${cargo_bin}" ]] || return 1
  cargo_path="${cargo_bin%/*}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
  # Full, bounded metadata is required before vendoring so every source-less
  # workspace/path package is proved to live inside the pinned private source.
  # shellcheck disable=SC2016
  run_recorded_limited "${CARGO_METADATA_TIMEOUT}" \
    "${metadata}.cargo-metadata.json" "$((32 * 1024 * 1024))" \
    "$((1024 * 1024))" /bin/sh -c '
      cd /
      exec /usr/bin/env -i \
        HOME="$1" CARGO_HOME="$2" PATH="$3" \
        CARGO_NET_OFFLINE=true CARGO_TERM_COLOR=never COPYFILE_DISABLE=1 \
        "$4" metadata --offline --locked --format-version=1 \
        --manifest-path "$5"
    ' cargo-metadata "${HOME}" "${cargo_home}" "${cargo_path}" \
    "${cargo_bin}" "${source_root}/Cargo.toml" || return 1
  validate_cargo_workspace_metadata "${source_root}" \
    "${source_root}/Cargo.lock" "${metadata}.cargo-metadata.json" \
    "${metadata}.cargo-metadata.env" || return 1
  lock_hash_before="$(source_archive_field \
    "${metadata}.cargo-metadata.env" cargo_lock_sha256)" || return 1
  # Build the dependency input from the pinned source in a fresh cwd. env -i
  # strips proxy, Cargo, registry, source and compiler overrides. The validated
  # same-user Cargo cache is read only as an offline input to `cargo vendor`.
  # shellcheck disable=SC2016
  run_recorded_limited "${VENDOR_CREATE_TIMEOUT}" \
    "${metadata}.cargo-vendor.stdout" "$((1024 * 1024))" \
    "$((1024 * 1024))" /bin/sh -c '
      cd /
      exec /usr/bin/env -i \
        HOME="$1" CARGO_HOME="$2" PATH="$3" \
        CARGO_NET_OFFLINE=true CARGO_TERM_COLOR=never COPYFILE_DISABLE=1 \
        "$4" vendor --offline --locked --versioned-dirs \
        --manifest-path "$5" "$6"
    ' cargo-vendor "${HOME}" "${cargo_home}" "${cargo_path}" \
    "${cargo_bin}" "${source_root}/Cargo.toml" "${vendor}" || return 1
  [[ -d "${vendor}" && ! -L "${vendor}" ]] || return 1
  lock_hash_after="$(sha256sum "${source_root}/Cargo.lock" | awk '{print $1}')" \
    || return 1
  [[ "${lock_hash_after}" == "${lock_hash_before}" ]] || return 1
  {
    printf 'cargo_lock_sha256_before=%s\n' "${lock_hash_before}"
    printf 'cargo_lock_sha256_after=%s\n' "${lock_hash_after}"
    printf 'cargo_lock_drift=absent\n'
  } >"${metadata}.cargo-lock-drift.env" || return 1
  verify_provenance_manifest "${source_root}" \
    "${metadata}.pinned-source-before.sha256" \
    "${metadata}.pinned-source-after.sha256" || return 1
  seal_cargo_vendor_tree "${vendor}" "${source_root}/Cargo.lock" \
    "${archive}" "${metadata}" "${pinned_head}" "${source_hash}" \
    "${guest_vendor}" || return 1
  [[ "$(source_archive_field "${metadata}" cargo_lock_sha256)" \
      == "${lock_hash_before}" ]] || return 1
  validate_git_metadata_safety "${repo_root}" \
    "${metadata}.git-metadata-safety-after-vendor.json" \
    "${pinned_head}" || return 1
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

extract_guest_source_archive() {
  local clone_id="$1" guest_root="$2" guest_archive="$3" guest_repo="$4"
  local expected_size="$5" expected_hash="$6" output="$7"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${output}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import hashlib
import os
import stat
import sys
import tarfile

(root, archive, repo, size_text, expected_hash, expanded_max_text) = sys.argv[1:]
size = int(size_text, 10)
expanded_max = int(expanded_max_text, 10)
if repo != os.path.join(root, "shadowpipe"):
    raise SystemExit("unsafe guest repository path")
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
        if total > expanded_max:
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
        descriptor = os.open(
            destination,
            flags,
            0o700 if member.mode & 0o111 else 0o600,
        )
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
if not os.path.isfile(
    os.path.join(repo, "deploy", "shadowpipe-lockdown-restore.service")
):
    raise SystemExit("extracted source lacks the restore unit")
if not os.path.isfile(
    os.path.join(repo, "deploy", "shadowpipe-client-full-tunnel.service")
):
    raise SystemExit("extracted source lacks the client unit")
os.unlink(archive)
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
print(f"source_archive_members={members}")
print(f"source_expanded_bytes={total}")
print(f"source_archive_sha256={expected_hash}")
' "${guest_root}" "${guest_archive}" "${guest_repo}" \
    "${expected_size}" "${expected_hash}" "${MAX_SOURCE_EXPANDED_BYTES}"
}

stream_vendor_archive_to_guest() {
  local clone_id="$1" archive="$2" guest_root="$3" guest_archive="$4"
  local expected_size="$5" expected_hash="$6" output="$7"
  run_recorded_with_stdin "${VENDOR_TRANSFER_TIMEOUT}" "${output}" "${archive}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import hashlib
import os
import stat
import sys

root, destination, size_text, expected = sys.argv[1:]
size = int(size_text, 10)
if size <= 0 or size > 256 * 1024 * 1024:
    raise SystemExit("invalid bounded Cargo vendor archive size")
if os.path.dirname(destination) != root or os.path.basename(destination) != "cargo-vendor.tar.gz":
    raise SystemExit("unsafe guest Cargo vendor archive path")
root_info = os.lstat(root)
if (
    not stat.S_ISDIR(root_info.st_mode)
    or stat.S_ISLNK(root_info.st_mode)
    or root_info.st_uid != 0
    or root_info.st_gid != 0
    or stat.S_IMODE(root_info.st_mode) != 0o700
):
    raise SystemExit("guest source root identity differs before vendor transfer")
if os.path.lexists(destination) or os.path.lexists(os.path.join(root, "cargo-vendor")):
    raise SystemExit("guest Cargo vendor destination already exists")
flags = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
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
            raise SystemExit("Cargo vendor archive stream exceeded its declared size")
        digest.update(chunk)
        offset = 0
        while offset < len(chunk):
            offset += os.write(descriptor, chunk[offset:])
    os.fsync(descriptor)
finally:
    os.close(descriptor)
if observed != size or digest.hexdigest() != expected:
    raise SystemExit("Cargo vendor archive stream size or digest mismatch")
info = os.lstat(destination)
if (
    not stat.S_ISREG(info.st_mode)
    or info.st_nlink != 1
    or stat.S_IMODE(info.st_mode) != 0o600
    or info.st_uid != 0
    or info.st_gid != 0
    or info.st_size != size
):
    raise SystemExit("guest Cargo vendor archive metadata differs")
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
print(f"vendor_archive_bytes={size}")
print(f"vendor_archive_sha256={expected}")
' "${guest_root}" "${guest_archive}" "${expected_size}" "${expected_hash}"
}

extract_guest_vendor_archive() {
  local clone_id="$1" guest_root="$2" guest_archive="$3" guest_repo="$4"
  local guest_cargo_home="$5" expected_size="$6" expected_hash="$7"
  local expected_head="$8" source_hash="$9" lock_hash="${10}"
  local manifest_hash="${11}" config_hash="${12}"
  local host_members="${13}" host_expanded="${14}" output="${15}"
  run_recorded "${VENDOR_EXTRACT_TIMEOUT}" "${output}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import hashlib
import json
import os
import re
import stat
import sys
import tarfile

(root, archive, repo, cargo_home, size_text, expected_hash, expected_head,
 source_hash, lock_hash, manifest_hash, config_hash,
 host_members_text, host_expanded_text, expanded_text, members_text) = sys.argv[1:]
size = int(size_text, 10)
host_members = int(host_members_text, 10)
host_expanded = int(host_expanded_text, 10)
expanded_max = int(expanded_text, 10)
members_max = int(members_text, 10)
vendor_root = os.path.join(root, "cargo-vendor")
vendor = os.path.join(vendor_root, "vendor")
if size <= 0 or size > 256 * 1024 * 1024:
    raise SystemExit("guest Cargo vendor archive size is outside its bound")
if not (0 < host_members <= members_max and 0 < host_expanded <= expanded_max):
    raise SystemExit("host Cargo vendor archive census is outside its bound")
if re.fullmatch(r"[0-9a-f]{40,64}", expected_head) is None:
    raise SystemExit("guest Cargo vendor pinned commit is malformed")
for value in (expected_hash, source_hash, lock_hash, manifest_hash, config_hash):
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SystemExit("guest Cargo vendor provenance digest is malformed")
if repo != os.path.join(root, "shadowpipe"):
    raise SystemExit("unsafe guest repository path for Cargo vendor binding")
if cargo_home != os.path.join(root, "cargo-home"):
    raise SystemExit("unsafe private guest CARGO_HOME path")
if os.path.lexists(vendor_root) or os.path.lexists(cargo_home):
    raise SystemExit("guest Cargo vendor or CARGO_HOME already exists")
archive_info = os.lstat(archive)
if (
    not stat.S_ISREG(archive_info.st_mode)
    or archive_info.st_nlink != 1
    or stat.S_IMODE(archive_info.st_mode) != 0o600
    or archive_info.st_uid != 0
    or archive_info.st_gid != 0
    or archive_info.st_size != size
):
    raise SystemExit("guest Cargo vendor archive identity changed before extraction")

def sha256_path(path):
    digest = hashlib.sha256()
    with open(path, "rb", buffering=0) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

if sha256_path(archive) != expected_hash:
    raise SystemExit("guest Cargo vendor archive digest changed before extraction")
seen = set()
regular = set()
required_directories = set()
members = 0
expanded = 0
with tarfile.open(archive, "r:gz") as source:
    for member in source:
        members += 1
        name = member.name.rstrip("/")
        parts = name.split("/")
        if (
            members > members_max
            or not name
            or name.startswith("/")
            or "\\" in name
            or any(part in ("", ".", "..") for part in parts)
            or parts[0] != "cargo-vendor"
            or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in name)
            or name in seen
            or any("/".join(parts[:index]) in regular for index in range(1, len(parts)))
            or (not member.isdir() and name in required_directories)
            or member.issparse()
        ):
            raise SystemExit("Cargo vendor archive has an unsafe member graph")
        seen.add(name)
        for index in range(1, len(parts)):
            required_directories.add("/".join(parts[:index]))
        destination = os.path.join(root, *parts)
        if os.path.commonpath((root, destination)) != root:
            raise SystemExit("Cargo vendor archive escaped the guest root")
        if member.isdir():
            if os.path.lexists(destination):
                if not stat.S_ISDIR(os.lstat(destination).st_mode):
                    raise SystemExit("Cargo vendor directory collided with a file")
            else:
                os.makedirs(destination, mode=0o700, exist_ok=False)
            os.chmod(destination, 0o700)
            continue
        if not member.isfile() or member.size < 0:
            raise SystemExit("Cargo vendor archive contains a link or special member")
        regular.add(name)
        expanded += member.size
        if expanded > expanded_max:
            raise SystemExit("Cargo vendor archive expanded-byte bound exceeded")
        parent = os.path.dirname(destination)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        if os.path.lexists(destination):
            raise SystemExit("Cargo vendor archive file path already exists")
        incoming = source.extractfile(member)
        if incoming is None:
            raise SystemExit("Cargo vendor archive regular member is unreadable")
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            0o700 if member.mode & 0o111 else 0o600,
        )
        written = 0
        try:
            while written < member.size:
                chunk = incoming.read(min(1024 * 1024, member.size - written))
                if not chunk:
                    raise SystemExit("Cargo vendor archive member ended early")
                offset = 0
                while offset < len(chunk):
                    offset += os.write(descriptor, chunk[offset:])
                written += len(chunk)
            if incoming.read(1):
                raise SystemExit("Cargo vendor archive member exceeded declared size")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
os.unlink(archive)
if members != host_members or expanded != host_expanded:
    raise SystemExit("guest Cargo vendor archive census differs from host inspection")

def read_bytes(path, maximum):
    info = os.lstat(path)
    if (
        not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        or info.st_uid != 0 or info.st_gid != 0
        or info.st_size <= 0 or info.st_size > maximum
    ):
        raise SystemExit(f"unsafe Cargo vendor metadata: {os.path.basename(path)}")
    with open(path, "rb") as stream:
        return stream.read()

binding_path = os.path.join(vendor_root, "binding.env")
config_path = os.path.join(vendor_root, "cargo-config.toml")
manifest_path = os.path.join(vendor_root, "vendor-manifest.json")
binding = read_bytes(binding_path, 4096).decode("ascii").splitlines()
pairs = {}
for line in binding:
    key, separator, value = line.partition("=")
    if not separator or not key or not value or key in pairs:
        raise SystemExit("Cargo vendor binding is malformed")
    pairs[key] = value
expected_binding = {
    "schema_version": "1",
    "pinned_head": expected_head,
    "source_archive_sha256": source_hash,
    "cargo_lock_sha256": lock_hash,
    "vendor_manifest_sha256": manifest_hash,
    "cargo_config_sha256": config_hash,
}
if pairs != expected_binding:
    raise SystemExit("Cargo vendor binding differs from host provenance")
if sha256_path(os.path.join(repo, "Cargo.lock")) != lock_hash:
    raise SystemExit("guest pinned Cargo.lock differs from Cargo vendor binding")
config_bytes = read_bytes(config_path, 16 * 1024)
manifest_bytes = read_bytes(manifest_path, 32 * 1024 * 1024)
if hashlib.sha256(config_bytes).hexdigest() != config_hash:
    raise SystemExit("guest Cargo source replacement config digest differs")
if hashlib.sha256(manifest_bytes).hexdigest() != manifest_hash:
    raise SystemExit("guest Cargo vendor manifest digest differs")

def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object)
if type(manifest) is not dict or set(manifest) != {
    "schema_version", "cargo_lock_sha256", "registry_packages",
    "directories", "files",
}:
    raise SystemExit("Cargo vendor manifest schema is invalid")
if manifest["schema_version"] != 1 or manifest["cargo_lock_sha256"] != lock_hash:
    raise SystemExit("Cargo vendor manifest lock binding is invalid")
packages = manifest["registry_packages"]
if type(packages) is not list or not packages:
    raise SystemExit("Cargo vendor manifest package set is invalid")
package_map = {}
for package in packages:
    if type(package) is not dict or set(package) != {
        "directory", "name", "version", "package_checksum",
    }:
        raise SystemExit("Cargo vendor package record is invalid")
    directory = package["directory"]
    package_name = package["name"]
    package_version = package["version"]
    if (
        type(directory) is not str
        or directory != f"{package_name}-{package_version}"
        or re.fullmatch(r"[A-Za-z0-9_+.-]+", directory) is None
        or directory in package_map
        or re.fullmatch(r"[0-9a-f]{64}", package["package_checksum"]) is None
    ):
        raise SystemExit("Cargo vendor package identity is unsafe")
    package_map[directory] = package
if sorted(os.listdir(vendor)) != sorted(package_map):
    raise SystemExit("guest versioned vendor directories differ from manifest")
manifest_directories = manifest["directories"]
manifest_files = manifest["files"]
if type(manifest_directories) is not list or type(manifest_files) is not list:
    raise SystemExit("Cargo vendor manifest tree records are invalid")
expected_directories = set()
for relative in manifest_directories:
    if (
        type(relative) is not str or relative.startswith("/") or "\\" in relative
        or any(part in ("", ".", "..") for part in relative.split("/"))
        or relative in expected_directories
    ):
        raise SystemExit("Cargo vendor manifest directory path is unsafe")
    expected_directories.add(relative)
expected_files = {}
for entry in manifest_files:
    if type(entry) is not dict or set(entry) != {"path", "bytes", "executable", "sha256"}:
        raise SystemExit("Cargo vendor manifest file record is invalid")
    relative = entry["path"]
    if (
        type(relative) is not str or relative.startswith("/") or "\\" in relative
        or any(part in ("", ".", "..") for part in relative.split("/"))
        or relative in expected_files
        or type(entry["bytes"]) is not int or entry["bytes"] < 0
        or type(entry["executable"]) is not bool
        or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
    ):
        raise SystemExit("Cargo vendor manifest file identity is unsafe")
    expected_files[relative] = entry
actual_directories = set()
actual_files = {}
for current, dirnames, filenames in os.walk(vendor, followlinks=False):
    dirnames.sort()
    filenames.sort()
    for name in dirnames:
        path = os.path.join(current, name)
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SystemExit("extracted Cargo vendor tree contains a linked directory")
        actual_directories.add(os.path.relpath(path, vendor))
    for name in filenames:
        path = os.path.join(current, name)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit("extracted Cargo vendor tree contains a link or special file")
        relative = os.path.relpath(path, vendor)
        actual_files[relative] = {
            "path": relative,
            "bytes": info.st_size,
            "executable": bool(stat.S_IMODE(info.st_mode) & 0o111),
            "sha256": sha256_path(path),
        }
if actual_directories != expected_directories:
    raise SystemExit("extracted Cargo vendor directory graph differs from manifest")
if actual_files != expected_files:
    raise SystemExit("extracted Cargo vendor files differ from manifest")
for package_dir, package in package_map.items():
    package_root = os.path.join(vendor, package_dir)
    checksum_path = os.path.join(package_root, ".cargo-checksum.json")
    checksum = json.loads(read_bytes(checksum_path, 16 * 1024 * 1024),
                          object_pairs_hook=unique_object)
    if type(checksum) is not dict or set(checksum) != {"files", "package"}:
        raise SystemExit("extracted package checksum schema is invalid")
    if checksum["package"] != package["package_checksum"] or type(checksum["files"]) is not dict:
        raise SystemExit("extracted package checksum differs from Cargo.lock")
    observed = {}
    prefix = package_dir + "/"
    for relative, entry in actual_files.items():
        if relative.startswith(prefix):
            package_relative = relative[len(prefix):]
            if package_relative != ".cargo-checksum.json":
                observed[package_relative] = entry["sha256"]
    if checksum["files"] != observed:
        raise SystemExit("extracted package file hashes differ from .cargo-checksum.json")
os.mkdir(cargo_home, 0o700)
cargo_config = os.path.join(cargo_home, "config.toml")
descriptor = os.open(
    cargo_config,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
try:
    offset = 0
    while offset < len(config_bytes):
        offset += os.write(descriptor, config_bytes[offset:])
    os.fsync(descriptor)
finally:
    os.close(descriptor)
if os.listdir(cargo_home) != ["config.toml"]:
    raise SystemExit("private guest CARGO_HOME was not created empty")
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
print("vendor_binding=valid")
print(f"vendor_archive_sha256={expected_hash}")
print(f"vendor_archive_members={members}")
print(f"vendor_expanded_bytes={expanded}")
print(f"vendor_registry_packages={len(package_map)}")
print(f"vendor_files={len(actual_files)}")
print(f"vendor_manifest_sha256={manifest_hash}")
print(f"cargo_lock_sha256={lock_hash}")
print("guest_cargo_home_initial_entries=1")
' "${guest_root}" "${guest_archive}" "${guest_repo}" "${guest_cargo_home}" \
    "${expected_size}" "${expected_hash}" "${expected_head}" \
    "${source_hash}" "${lock_hash}" "${manifest_hash}" "${config_hash}" \
    "${host_members}" "${host_expanded}" \
    "${MAX_VENDOR_EXPANDED_BYTES}" "${MAX_VENDOR_MEMBERS}"
}

parse_orb_info_identity() {
  local raw="$1" expected_name="$2" expected_id="$3"
  local expected_state="$4" normalized="$5"
  python3 -I -S - \
    "${raw}" "${expected_name}" "${expected_id}" \
    "${expected_state}" "${normalized}" <<'PY'
import json
import os
import sys

raw_path, expected_name, expected_id, expected_state, normalized = sys.argv[1:]

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

def reject_constant(value):
    raise ValueError(f"non-finite JSON constant: {value}")

with open(raw_path, "rb") as stream:
    raw = stream.read()
if not raw or len(raw) > 1024 * 1024:
    raise SystemExit("orbctl info JSON size is invalid")
document = json.loads(
    raw.decode("utf-8"),
    object_pairs_hook=unique_object,
    parse_constant=reject_constant,
)
if type(document) is not dict or type(document.get("record")) is not dict:
    raise SystemExit("orbctl info lacks one record object")
record = document["record"]
for field in ("id", "name", "state"):
    if type(record.get(field)) is not str:
        raise SystemExit(f"orbctl record.{field} is not a string")
machine_id = record["id"]
name = record["name"]
state = record["state"]
encoded_id = machine_id.encode("utf-8")
if (
    not machine_id
    or len(encoded_id) > 512
    or any(ord(character) < 0x21 or ord(character) == 0x7F
           for character in machine_id)
):
    raise SystemExit("orbctl record.id is empty or contains control/space bytes")
if name != expected_name:
    raise SystemExit("orbctl name differs from the bound name")
if expected_id and machine_id != expected_id:
    raise SystemExit("orbctl ID mismatch or name reuse")
if expected_state and state != expected_state:
    raise SystemExit("orbctl state differs from the expected state")
config = record.get("config")
if type(config) is not dict:
    raise SystemExit("orbctl record lacks one config object")
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
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(normalized, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
    json.dump(
        {
            "schema_version": 1,
            "id": machine_id,
            "name": name,
            "state": state,
            "isolated": True,
            "isolate_network": True,
            "forward_ssh_agent": False,
            "http_port": 0,
            "https_port": 0,
            "mounts_and_forwards": "empty",
        },
        stream,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
print(machine_id)
PY
}

capture_orb_identity() {
  local timeout="$1" selector="$2" expected_name="$3"
  local expected_id="$4" expected_state="$5" base="$6"
  local identity status
  if run_recorded "${timeout}" "${base}.raw.json" \
    orbctl info -f json "${selector}"; then
    :
  else
    status=$?
    printf 'orb_identity_validation=not_run\n' >"${base}.validation.env"
    return "${status}"
  fi
  if identity="$(parse_orb_info_identity \
    "${base}.raw.json" "${expected_name}" "${expected_id}" \
    "${expected_state}" "${base}.identity.json" \
    2>"${base}.parse.stderr")"; then
    printf '0\n' >"${base}.parse.status"
    printf 'orb_identity_validation=valid\n' >"${base}.validation.env"
    printf '%s\n' "${identity}"
  else
    status=$?
    printf '%s\n' "${status}" >"${base}.parse.status"
    printf 'orb_identity_validation=invalid\n' >"${base}.validation.env"
    return 65
  fi
}

capture_orb_absence() {
  local timeout="$1" selector="$2" base="$3" status
  if run_recorded "${timeout}" "${base}.raw.json" \
    orbctl info -f json "${selector}"; then
    printf 'orb_absence_validation=invalid_present\n' >"${base}.validation.env"
    return 1
  else
    status=$?
  fi
  if [[ "${status}" == 1 && ! -s "${base}.raw.json" \
    && "$(<"${base}.raw.json.stderr")" \
      == "[-32098] machine not found: '${selector}'" ]]; then
    printf 'orb_absence_validation=valid\n' >"${base}.validation.env"
    return 0
  fi
  printf 'orb_absence_validation=invalid\n' >"${base}.validation.env"
  return 1
}

capture_guest_isolation_preflight() {
  local clone_id="$1" output="$2"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${output}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import os
import shutil
import subprocess

if os.path.lexists("/mnt/mac"):
    raise SystemExit("isolated guest unexpectedly exposes /mnt/mac")
if os.environ.get("SSH_AUTH_SOCK"):
    raise SystemExit("isolated guest unexpectedly received SSH_AUTH_SOCK")
busctl = shutil.which("busctl")
if not busctl or os.path.realpath(busctl) != "/usr/bin/busctl":
    raise SystemExit("isolated guest lacks the expected systemd busctl")
busctl_info = os.lstat("/usr/bin/busctl")
if (
    not os.path.isfile("/usr/bin/busctl")
    or busctl_info.st_uid != 0
    or busctl_info.st_gid != 0
    or not (busctl_info.st_mode & 0o111)
):
    raise SystemExit("isolated guest busctl identity differs")
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
            raise SystemExit("OrbStack mac-command channel is not fail-closed")
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
print(f"busctl_path={busctl}")
print("busctl_canonical=/usr/bin/busctl")
print(f"mac_command_channel={mac_channel}")
'
}

capture_pid1_systemd_proof() {
  local clone_id="$1" output="$2"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${output}" \
    orb -m "${clone_id}" -u root python3 -I -S -c '
import os
import re
import subprocess

def one_line(path):
    with open(path, "r", encoding="ascii", newline="") as stream:
        lines = stream.read().splitlines()
    if len(lines) != 1 or not lines[0]:
        raise SystemExit(f"{path} is not one nonempty line")
    return lines[0]

comm = one_line("/proc/1/comm")
if comm != "systemd":
    raise SystemExit("guest PID 1 comm is not systemd")
exe = os.path.realpath("/proc/1/exe")
if not os.path.isabs(exe) or os.path.basename(exe) != "systemd":
    raise SystemExit("guest PID 1 executable is not systemd")
status = {}
with open("/proc/1/status", "r", encoding="ascii") as stream:
    for raw in stream:
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        status[key] = value.strip()
for key, expected in (
    ("Name", "systemd"),
    ("Tgid", "1"),
    ("Pid", "1"),
    ("PPid", "0"),
):
    if status.get(key) != expected:
        raise SystemExit(f"guest PID 1 status {key} differs")
stat_line = one_line("/proc/1/stat")
right = stat_line.rfind(")")
if right <= 0:
    raise SystemExit("guest PID 1 stat comm is malformed")
fields = stat_line[right + 2:].split()
if len(fields) < 20:
    raise SystemExit("guest PID 1 stat field census is short")
start_ticks = int(fields[19], 10)
if start_ticks <= 0:
    raise SystemExit("guest PID 1 start ticks are not positive")
manager = subprocess.run(
    ["systemctl", "show", "--property=Version", "--value"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    timeout=10,
    check=False,
)
if manager.returncode != 0 or manager.stderr:
    raise SystemExit("systemd manager Version query failed")
manager_lines = manager.stdout.decode("utf-8").splitlines()
if len(manager_lines) != 1:
    raise SystemExit("systemd manager Version is not one line")
version_match = re.match(r"^([0-9]+)(?:[. -]|$)", manager_lines[0])
if version_match is None or int(version_match.group(1), 10) < 254:
    raise SystemExit("live systemd manager is older than 254")
boot_id = one_line("/proc/sys/kernel/random/boot_id").lower()
if re.fullmatch(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    boot_id,
) is None:
    raise SystemExit("guest boot ID is not canonical")
machine_id = one_line("/etc/machine-id").lower()
if re.fullmatch(r"[0-9a-f]{32}", machine_id) is None:
    raise SystemExit("guest machine ID is not canonical")
namespaces = {}
for label, path in (
    ("pid_namespace", "/proc/1/ns/pid"),
    ("network_namespace", "/proc/1/ns/net"),
    ("mount_namespace", "/proc/1/ns/mnt"),
):
    info = os.stat(path)
    if info.st_dev <= 0 or info.st_ino <= 0:
        raise SystemExit(f"{label} identity is not positive")
    namespaces[label] = f"{info.st_dev}:{info.st_ino}"
print("pid=1")
print("comm=systemd")
print(f"exe={exe}")
print("status_name=systemd")
print("ppid=0")
print(f"pid1_start_ticks={start_ticks}")
print(f"manager_version={manager_lines[0]}")
print(f"boot_id={boot_id}")
print(f"machine_id={machine_id}")
print(f"kernel_release={os.uname().release}")
for label in ("pid_namespace", "network_namespace", "mount_namespace"):
    print(f"{label}={namespaces[label]}")
'
}

verify_pid1_systemd_proof() {
  local proof="$1"
  python3 -I -S - "${proof}" <<'PY'
import os
import re
import sys

values = {}
with open(sys.argv[1], "r", encoding="utf-8", newline="") as stream:
    for raw in stream:
        line = raw.rstrip("\n")
        if "=" not in line:
            raise SystemExit("PID-1 proof contains a malformed line")
        key, value = line.split("=", 1)
        if key in values:
            raise SystemExit("PID-1 proof contains a duplicate field")
        values[key] = value
expected = {
    "pid", "comm", "exe", "status_name", "ppid", "pid1_start_ticks",
    "manager_version", "boot_id", "machine_id", "kernel_release",
    "pid_namespace", "network_namespace", "mount_namespace",
}
if set(values) != expected:
    raise SystemExit("PID-1 proof field set differs")
if (
    values["pid"] != "1"
    or values["comm"] != "systemd"
    or values["status_name"] != "systemd"
    or values["ppid"] != "0"
):
    raise SystemExit("PID-1 proof identity differs")
if not os.path.isabs(values["exe"]) or os.path.basename(values["exe"]) != "systemd":
    raise SystemExit("PID-1 executable proof differs")
if re.fullmatch(r"[1-9][0-9]*", values["pid1_start_ticks"]) is None:
    raise SystemExit("PID-1 start ticks are malformed")
version = re.match(r"^([0-9]+)(?:[. -]|$)", values["manager_version"])
if version is None or int(version.group(1), 10) < 254:
    raise SystemExit("PID-1 live systemd manager version is too old")
if re.fullmatch(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    values["boot_id"],
) is None:
    raise SystemExit("PID-1 boot ID is malformed")
if re.fullmatch(r"[0-9a-f]{32}", values["machine_id"]) is None:
    raise SystemExit("PID-1 machine ID is malformed")
if not values["kernel_release"] or any(
    ord(character) < 0x20 or ord(character) == 0x7f
    for character in values["kernel_release"]
):
    raise SystemExit("PID-1 kernel release is malformed")
for field in ("pid_namespace", "network_namespace", "mount_namespace"):
    if re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", values[field]) is None:
        raise SystemExit(f"{field} identity is malformed")
PY
}

verify_userspace_restart_transition() {
  local before="$1" after="$2" output="$3"
  python3 -I -S - "${before}" "${after}" "${output}" <<'PY'
import sys

def load(path):
    values = {}
    with open(path, "r", encoding="utf-8", newline="") as stream:
        for raw in stream:
            key, value = raw.rstrip("\n").split("=", 1)
            if key in values:
                raise SystemExit("duplicate userspace restart proof field")
            values[key] = value
    return values

before, after = load(sys.argv[1]), load(sys.argv[2])
if set(before) != set(after):
    raise SystemExit("pre/post PID-1 proof fields differ")
for field, label in (
    ("machine_id", "guest machine identity"),
    ("kernel_release", "shared OrbStack kernel release"),
    ("exe", "PID-1 executable"),
    ("manager_version", "systemd manager version"),
):
    if before[field] != after[field]:
        raise SystemExit(f"{label} changed across restart")
if before["boot_id"] == after["boot_id"]:
    raise SystemExit("guest boot identity did not change")
if before["network_namespace"] == after["network_namespace"]:
    raise SystemExit("guest network namespace was not recreated")
if before["comm"] != "systemd" or after["comm"] != "systemd":
    raise SystemExit("systemd was not PID 1 on both sides")
fields = ("pid1_start_ticks", "pid_namespace", "network_namespace", "mount_namespace")
with open(sys.argv[3], "x", encoding="ascii", newline="\n") as stream:
    stream.write("userspace_systemd_boot_transaction=valid\n")
    stream.write("boot_id_changed=true\n")
    stream.write("machine_id_stable=true\n")
    stream.write("kernel_release_stable=true\n")
    stream.write("pid1_executable_stable=true\n")
    stream.write("manager_version_stable=true\n")
    for field in fields:
        changed = before[field] != after[field]
        stream.write(f"{field}_changed={'true' if changed else 'false'}\n")
    stream.write("dedicated_kernel_reboot_claim=false\n")
    stream.write("orb_stack_shared_kernel_scope=true\n")
PY
}

orb_list_snapshot() {
  local output="$1"
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${output}" orbctl list
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

create_provenance_manifest() {
  local repo_root="$1" output="$2"
  python3 -I -S - "${repo_root}" "${output}" <<'PY'
import hashlib
import os
import stat
import sys

root = os.path.realpath(sys.argv[1])
output = sys.argv[2]
fixed = [
    ".cargo/config.toml",
    "Cargo.lock",
    "Cargo.toml",
    "deploy/shadowpipe-client-full-tunnel.service",
    "deploy/shadowpipe-lockdown-restore.service",
    "tests/lockdown/normalize-built-artifact.py",
    "tests/lockdown/run-orbstack-reboot.sh",
]
paths = []
directory = os.path.join(root, "crates")
for current, directories, files in os.walk(directory, followlinks=False):
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
            raise SystemExit(f"provenance input is not a single-link regular file: {relative}")
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        destination.write(f"{digest.hexdigest()}  {relative}\n")
PY
}

verify_provenance_manifest() {
  local repo_root="$1" expected="$2" observed="$3"
  create_provenance_manifest "${repo_root}" "${observed}" || return 1
  cmp -s -- "${expected}" "${observed}"
}

verify_systemd_minimum() {
  local version_file="$1"
  python3 -I -S - "${version_file}" <<'PY'
import re
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    first_line = stream.readline().strip()
match = re.match(r"^systemd\s+(\d+)(?:\s|$)", first_line)
if match is None or int(match.group(1), 10) < 254:
    raise SystemExit("systemd >=254 is required")
PY
}

verify_same_digest() {
  local first="$1" second="$2"
  python3 -I -S - "${first}" "${second}" <<'PY'
import re
import sys

digests = []
for path in sys.argv[1:]:
    with open(path, "r", encoding="ascii") as stream:
        line = stream.read().strip()
    match = re.fullmatch(r"([0-9a-f]{64})\s+\*?.+", line)
    if match is None:
        raise SystemExit(f"malformed SHA-256 record: {path}")
    digests.append(match.group(1))
if digests[0] != digests[1]:
    raise SystemExit("installed artifact digest differs from built/source artifact")
PY
}

capture_effective_unit_definition() {
  local clone_id="$1" unit="$2" output="$3"
  local kind
  case "${unit}" in
    shadowpipe-lockdown-restore.service) kind=restore ;;
    shadowpipe-client-full-tunnel.service) kind=client ;;
    *) return 1 ;;
  esac
  capture_exact_systemd_properties \
    "${clone_id}" "${unit}" "${kind}" "${output}" \
    LoadState FragmentPath DropInPaths ExecCondition \
    ExecStartPre ExecStart ExecStartPost EnvironmentFiles
}

verify_effective_unit_definition() {
  local evidence="$1" kind="$2"
  python3 -I -S - "${evidence}" "${kind}" <<'PY'
import sys

path, kind = sys.argv[1:]
if kind == "restore":
    fragment = "/etc/systemd/system/shadowpipe-lockdown-restore.service"
    argv = (
        "argv[]=/usr/local/bin/shadowpipe-client --restore-lockdown "
        "--host-state-dir /var/lib/shadowpipe"
    )
    environment = ""
elif kind == "client":
    fragment = "/etc/systemd/system/shadowpipe-client-full-tunnel.service"
    argv = (
        "argv[]=/usr/local/bin/shadowpipe-client "
        "$SHADOWPIPE_CLIENT_ARGS"
    )
    environment = "/etc/shadowpipe/client.env (ignore_errors=no)"
else:
    raise SystemExit("unknown effective-unit definition kind")

values = {}
with open(path, "r", encoding="utf-8") as stream:
    for raw in stream:
        line = raw.rstrip("\n")
        key, separator, value = line.partition("=")
        if not separator or not key or key in values:
            raise SystemExit("effective-unit definition is malformed")
        values[key] = value
expected = {
    "LoadState", "FragmentPath", "DropInPaths", "ExecCondition",
    "ExecStartPre", "ExecStart", "ExecStartPost", "EnvironmentFiles",
}
if set(values) != expected:
    raise SystemExit("effective-unit property census differs")
if values["LoadState"] != "loaded" or values["FragmentPath"] != fragment:
    raise SystemExit("effective-unit fragment identity differs")
if (
    values["DropInPaths"]
    or values["ExecCondition"]
    or values["ExecStartPre"]
    or values["ExecStartPost"]
):
    raise SystemExit("effective-unit definition contains a drop-in or hook")
if values["EnvironmentFiles"] != environment:
    raise SystemExit("effective-unit EnvironmentFiles differs")
start = values["ExecStart"]
if (
    start.count("path=/usr/local/bin/shadowpipe-client") != 1
    or start.count("argv[]=/usr/local/bin/shadowpipe-client") != 1
    or argv not in start
):
    raise SystemExit("effective-unit ExecStart differs")
PY
}

verify_guest_marker_proof() {
  local proof="$1" token="$2"
  python3 -I -S - "${proof}" "${token}" <<'PY'
import sys

with open(sys.argv[1], "r", encoding="ascii") as stream:
    lines = stream.read().splitlines()
if lines != ["0 0 600 1 regular file", sys.argv[2]]:
    raise SystemExit("guest ownership marker identity/mode/content differs")
PY
}

write_reboot_status() {
  local output="$1"
  shift
  python3 -I -S - "${output}" "$@" <<'PY'
import os
import secrets
import stat
import sys

output = os.path.abspath(sys.argv[1])
keys = (
    "guest_status", "client_unit_status", "host_safety_status",
    "clone_attempted", "clone_deleted",
    "clone_cleanup_status", "target_deleted", "host_tmp_deleted",
    "source_vm_final_state", "same_host_lifecycle_lock", "pf_runtime_observed",
    "evidence_bundle_status", "overall_status",
)
values = sys.argv[2:]
if len(values) != len(keys):
    raise SystemExit("status value census differs")
if os.path.lexists(output) and stat.S_ISDIR(os.lstat(output).st_mode):
    raise SystemExit("status destination is a directory")
temporary = output + f".new.{os.getpid()}.{secrets.token_hex(8)}"
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(temporary, flags, 0o600)
try:
    with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
        for key, value in zip(keys, values):
            if "\n" in value or "\r" in value:
                raise SystemExit("unsafe status value")
            stream.write(f"{key}={value}\n")
        stream.write("field_evidence=false\n")
        stream.write("paired_tunnel_evidence=false\n")
        stream.write("production_readiness_evidence=false\n")
        stream.write("initrd_or_static_loader_evidence=false\n")
        stream.write("dedicated_kernel_reboot_evidence=false\n")
        stream.write("power_loss_evidence=false\n")
        stream.write("orb_stack_shared_kernel_scope=true\n")
        stream.write("systemd_pid1_userspace_boot_scope=true\n")
        overall = values[keys.index("overall_status")]
        reboot = values[keys.index("guest_status")]
        client_unit = values[keys.index("client_unit_status")]
        stream.write(
            "systemd_pid1_userspace_boot_evidence="
            + ("true" if reboot == "valid" else "false")
            + "\n"
        )
        stream.write(
            "pinned_guest_local_source_evidence="
            + ("true" if overall == "valid" else "false")
            + "\n"
        )
        stream.write(
            "restore_before_systemd_networkd_evidence="
            + ("true" if reboot == "valid" else "false")
            + "\n"
        )
        stream.write(
            "installed_client_unit_pid1_evidence="
            + ("true" if client_unit == "valid" else "false")
            + "\n"
        )
        stream.write(
            "client_unit_network_state_unchanged_evidence="
            + ("true" if client_unit == "valid" else "false")
            + "\n"
        )
        stream.write("client_unit_successful_tunnel_evidence=false\n")
        stream.write("client_unit_active_lockdown_barrier_evidence=false\n")
        stream.write("client_unit_continuous_socket_monitor=false\n")
        stream.write("host_worktree_mount_used=false\n")
        stream.write("host_target_mount_used=false\n")
        stream.write("ssh_agent_forwarding_allowed=false\n")
        stream.write("cargo_dependency_resolution_offline=true\n")
        stream.write(
            "cargo_vendor_provenance_evidence="
            + ("true" if overall == "valid" else "false")
            + "\n"
        )
        stream.write(
            "cargo_build_frozen_evidence="
            + ("true" if overall == "valid" else "false")
            + "\n"
        )
        stream.write(
            "cargo_build_network_namespace_evidence="
            + ("true" if overall == "valid" else "false")
            + "\n"
        )
        stream.write("cargo_preexisting_guest_cache_used=false\n")
        stream.write("cargo_source_replacement_cli_precedence=true\n")
        stream.write("build_phase_egress_monitor=false\n")
        stream.write("continuous_boot_egress_monitor=false\n")
        stream.write("l2_forward_container_evidence=false\n")
        lifecycle = values[keys.index("same_host_lifecycle_lock")]
        stream.write("concurrent_shadowpipe_orbstack_lifecycle_runners="
                     + ("excluded" if lifecycle == "released" else "not_proved")
                     + "\n")
        stream.write("unrelated_orbstack_lifecycle_operators=outside_trust_boundary\n")
        stream.write("private_material_scan_scope=nonsecret_empty_json_credential_fixture_live_config_hash_only\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, output)
    parent = os.open(os.path.dirname(output), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
finally:
    if os.path.lexists(temporary):
        os.unlink(temporary)
PY
}

write_reboot_result() {
  local output="$1" verdict="$2" clone_vm="$3" pf_observed="$4"
  local source_vm="$5" pinned_head="$6" client_unit_verdict="$7"
  local reboot_verdict="$8"
  python3 -I -S - "${output}" "${verdict}" "${clone_vm}" \
    "${pf_observed}" "${source_vm}" "${pinned_head}" \
    "${client_unit_verdict}" "${reboot_verdict}" <<'PY'
import os
import secrets
import stat
import sys
output, verdict, clone, pf_observed, source, pinned_head, client_unit, reboot = sys.argv[1:]
if os.path.lexists(output) and stat.S_ISDIR(os.lstat(output).st_mode):
    raise SystemExit("result destination is a directory")
if client_unit not in ("valid", "failed") or reboot not in ("valid", "failed"):
    raise SystemExit("component result status is unknown")
if verdict == "valid" and (client_unit != "valid" or reboot != "valid"):
    raise SystemExit("overall PASS requires valid reboot and client-unit components")
if verdict == "valid":
    pf_line = (
        "- macOS PF runtime: exact read-only rules/NAT/info snapshots were unchanged"
        if pf_observed == "true" else
        "- macOS PF runtime: exact unprivileged permission-denied tuple was unchanged; runtime rules remain explicitly unobserved"
    )
    body = "\n".join((
        "# Shadowpipe early-userspace L3 lockdown systemd-boot result", "",
        "- Verdict: **PASS**",
        f"- Pinned source: clean pushed `main` commit `{pinned_head}` entered by bounded hash-verified stdin; guest-local build/install used no host worktree or target mount",
        "- Dependency provenance: a separate deterministic Cargo vendor archive was built offline from the pinned source; Cargo.lock package sources/checksums, every versioned crate directory, .cargo-checksum.json, and every vendored file hash were validated before and after transfer",
        "- Build isolation: Cargo ran `--frozen` from cwd `/` with a fresh private CARGO_HOME containing only generated config, highest-precedence CLI source replacement, an empty target, and a fresh network namespace without egress",
        "- Build-network limit: no continuous packet recorder was installed; the stronger build boundary is the fresh network namespace rather than an observational capture",
        f"- Isolated source: stopped `{source}`; source and clone config required capability/network isolation, disabled SSH-agent forwarding, zero forwarded ports, and empty mounts/forwards",
        f"- Disposable clone: `{clone}` (opaque ID bound for start/restart/guest operations; delete-by-name required a fresh name-to-ID revalidation, followed by ID/name absence proof)",
        "- Userspace boot scope: systemd was proved as live PID 1 before and after an OrbStack machine restart; distinct guest boot IDs and strict WAL PID-1 namespace binding were observed",
        "- Kernel scope: OrbStack machines share one Linux kernel; this is not a dedicated-kernel, initrd, power-loss, or hardware reboot claim",
        "- Durable WAL: exact schema v1 Active generation 2 -> 4, fresh identity, handle matched exact nft listing",
        "- Enforcement observed: exact native nft inet/output barrier; loopback passed and non-loopback IPv4 ping was denied",
        "- Ordering observed: systemd >=254; unique InvocationIDs, zero restarts and monotonic activation timestamps prove restore completion before networkd start",
        "- Ordering limit: there is no continuous external packet capture across the userspace restart; the cell proves restore-before-systemd-networkd plus post-boot enforcement, not universal zero-packet boot silence",
        "- Recovery observed: explicit operator release removed WAL and the only sp_lock table; guest IPv4 gateway became reachable",
        "- Installed client-unit verdict: **PASS** (separate subcell after explicit release)",
        "- Installed client-unit lifecycle: exact source unit and binary hashes matched; systemd PID 1 exposed Requires/After=restore plus Restart=always/RestartSec=1s; at least three credential-refusal InvocationIDs and increasing NRestarts were observed",
        "- Client operator-stop proof: after systemctl stop, a greater-than-RestartSec interval produced no new invocation and left the unit inactive with no client process",
        "- Client pre-mutation proof: a root-owned mode-0600 empty-JSON credential fixture failed at the mandatory credential loader; canonical routes, rules, nft ruleset, DNS, interfaces, TUN census and WAL absence were identical before/after",
        "- Client-unit scope limit: this is a fail-closed pre-mutation lifecycle test, not a successful session, tunnel, lockdown-barrier, transient-socket packet capture, or leak proof",
        "- macOS safety observed: routes, DNS, exact sing-box PID/argv/config/executable and PF configuration files were unchanged",
        "- Host-safety timing: consistent before/after endpoint snapshots; no continuous host mutation monitor",
        "- Exclusion: the shared lifecycle lock serializes Shadowpipe runners; unrelated same-host operators remain outside the trust boundary and any name/ID/state drift fails closed",
        pf_line,
        "- Build contract: a validated explicit SHADOWPIPE_MAGIC u32 was recorded and used for the binary build",
        "- Private-material scan scope: the experiment creates only a non-secret empty-JSON credential fixture and copies no live config bytes; the pre-existing Mac config is represented only by SHA-256",
        "- Scope: one disposable guest, early-userspace Linux L3 local OUTPUT, explicit release, and installed-client pre-mutation systemd lifecycle",
        "- No paired client/server tunnel, successful full-tunnel session, production, dedicated-kernel reboot, initrd, power loss, L2/AF_PACKET, FORWARD, container-netns, transient-socket capture, or censorship-field claim",
        "",
    ))
elif verdict == "failed":
    body = (
        "# Shadowpipe early-userspace lockdown systemd-boot failure\n\n"
        f"Component status: reboot={reboot}; client_unit={client_unit}; overall={verdict}.\n\n"
        "Inspect status.env and the sealed evidence. No overall PASS claim is present.\n"
    )
else:
    raise SystemExit("unknown reboot result verdict")
temporary = output + f".new.{os.getpid()}.{secrets.token_hex(8)}"
descriptor = os.open(
    temporary,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, output)
finally:
    if os.path.lexists(temporary):
        os.unlink(temporary)
PY
}

# EXIT may run after an implicit `set -e` failure has unwound main().  Bash
# function locals no longer exist at that point, so every value needed to
# identify and clean the owned clone/result/temp state is deliberately
# process-global.  Helper functions use their own locals and must not mutate
# this cleanup context.
source_vm=''
results_root=''
clone_vm=''
result_dir=''
ownership_token=''
host_tmp=''
host_tmp_root=''
before=''
after=''
final_status=1
clone_attempted=0
clone_owned=0
clone_completion_uncertain=0
guest_status=failed
client_unit_status=failed
host_safety=failed
clone_deleted=not_attempted
clone_cleanup_status=not_run
target_deleted=not_applicable
source_state_status=failed
host_tmp_deleted=false
lifecycle_lock=''
lifecycle_lock_status=not_acquired
pf_runtime_observed=unknown
source_orb_id=''
clone_orb_id=''
clone_identity_bound=0
clone_deletion_pending=0
pinned_head=unavailable

verify_cleanup_context_global_contract() {
  local source="$1"
  python3 -I -S - "${source}" \
    source_vm results_root clone_vm result_dir ownership_token \
    host_tmp host_tmp_root before after final_status clone_attempted \
    clone_owned clone_completion_uncertain guest_status client_unit_status \
    host_safety clone_deleted clone_cleanup_status target_deleted \
    source_state_status host_tmp_deleted lifecycle_lock \
    lifecycle_lock_status pf_runtime_observed source_orb_id clone_orb_id \
    clone_identity_bound clone_deletion_pending pinned_head <<'PY'
import re
import sys

source_path, *protected = sys.argv[1:]
with open(source_path, "r", encoding="utf-8") as stream:
    source = stream.read()
start_marker = "\nmain() {\n"
end_marker = "\nrun_self_test() (\n"
if source.count(start_marker) != 1 or source.count(end_marker) != 1:
    raise SystemExit("could not isolate the real main function")
main = source.split(start_marker, 1)[1].split(end_marker, 1)[0]
logical_lines = []
pending = ""
for physical in main.splitlines():
    pending += physical
    if pending.rstrip().endswith("\\"):
        pending = pending.rstrip()[:-1] + " "
        continue
    logical_lines.append(pending)
    pending = ""
if pending:
    logical_lines.append(pending)
violations = []
for line_number, line in enumerate(logical_lines, 1):
    match = re.match(
        r"^\s*(?:local|declare|typeset)\b(?P<body>.*)$",
        line,
    )
    if match is None:
        continue
    body = match.group("body")
    for name in protected:
        if re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(name)}(?=\s|=|$)",
            body,
        ):
            violations.append(f"{name}@logical-main-line-{line_number}")
if violations:
    raise SystemExit(
        "cleanup context is locally shadowed: " + ",".join(violations)
    )
print("cleanup_context_process_global=true")
print(f"cleanup_context_names={len(protected)}")
PY
}

verify_systemctl_show_all_contract() {
  local source="$1"
  python3 -I -S - "${source}" <<'PY'
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    source = stream.read()
start_marker = "\nverify_systemctl_show_all_contract() {\n"
end_marker = "\nmain() {\n"
if source.count(start_marker) != 1 or source.count(end_marker) != 1:
    raise SystemExit("could not isolate systemctl collector contract")
before, remainder = source.split(start_marker, 1)
_, after = remainder.split(end_marker, 1)
audited = before + end_marker + after
shell_collectors = audited.count("systemctl show --all")
embedded_collectors = audited.count(
    '"/usr/bin/systemctl", "show", "--all"'
)
if shell_collectors != 0 or embedded_collectors != 2:
    raise SystemExit(
        "exact-census systemctl collectors do not all retain --all"
    )
print("systemctl_show_all_shell_collectors=0")
print("systemctl_show_all_embedded_collectors=2")
PY
}

main() {
  [[ "$(uname -s)" == Darwin ]] \
    || die "${EX_USAGE}" 'host mode must run on macOS'
  [[ "${SHADOWPIPE_DISPOSABLE_LOCKDOWN_REBOOT:-}" == 1 ]] \
    || die "${EX_USAGE}" 'set SHADOWPIPE_DISPOSABLE_LOCKDOWN_REBOOT=1'
  local tool
  for tool in orbctl orb python3 sha256sum route netstat scutil pfctl pgrep ps \
    cmp diff find sort awk sed grep tr wc head mkfifo mktemp mv git stat cargo; do
    command -v "${tool}" >/dev/null \
      || die "${EX_UNAVAILABLE}" "missing host dependency: ${tool}"
  done

  source_vm="${1:-${SOURCE_DEFAULT}}"
  [[ "$#" -le 1 ]] || die "${EX_USAGE}" 'expected at most one source VM'
  source_vm="$(sanitize_component "${source_vm}")" \
    || die "${EX_USAGE}" 'unsafe source VM name'
  validate_source_vm "${source_vm}" \
    || die "${EX_USAGE}" "only stopped source VM ${SOURCE_DEFAULT} is allowed"
  local script_dir repo_root run_id magic
  local source_archive source_archive_size source_archive_hash
  local vendor_archive vendor_archive_size vendor_archive_hash vendor_stage
  local vendor_archive_members vendor_expanded_bytes
  local vendor_lock_hash vendor_manifest_hash vendor_config_hash
  local guest_root guest_archive guest_repo guest_target
  local guest_built_binary guest_binary guest_unit
  local guest_client_unit
  local guest_vendor_archive guest_vendor guest_cargo_home
  magic="${SHADOWPIPE_MAGIC:-${MAGIC_DEFAULT}}"
  validate_magic "${magic}" \
    || die "${EX_USAGE}" 'SHADOWPIPE_MAGIC must be one value in the u32 range'
  script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
  verify_cleanup_context_global_contract \
    "${script_dir}/run-orbstack-reboot.sh" \
    || die "${EX_UNAVAILABLE}" \
      'cleanup context is not process-global in the real main function'
  verify_systemctl_show_all_contract \
    "${script_dir}/run-orbstack-reboot.sh" \
    || die "${EX_UNAVAILABLE}" \
      'exact-census systemctl collectors must retain --all'
  repo_root="$(cd -- "${script_dir}/../.." && pwd -P)"
  results_root="${script_dir}/results"
  [[ ! -L "${results_root}" ]] \
    || die "${EX_UNAVAILABLE}" 'result root is a symlink'
  mkdir -p -- "${results_root}"
  results_root="$(cd -- "${results_root}" && pwd -P)"
  [[ "${results_root}" == "${script_dir}/results" ]] \
    || die "${EX_UNAVAILABLE}" 'result root escaped its repository path'
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  clone_vm="sphr-lock-$(printf '%s' "${run_id}" | tr '[:upper:]' '[:lower:]')"
  result_dir="${results_root}/${run_id}-reboot"
  [[ ! -e "${result_dir}" && ! -L "${result_dir}" ]] \
    || die "${EX_UNAVAILABLE}" "result path already exists: ${result_dir}"
  mkdir -- "${result_dir}"
  result_dir="$(cd -- "${result_dir}" && pwd -P)"
  host_tmp="$(mktemp -d "${TMPDIR:-/tmp}/shadowpipe-lockdown-reboot.XXXXXX")"
  host_tmp="$(cd -- "${host_tmp}" && pwd -P)"
  host_tmp_root="$(cd -- "$(dirname -- "${host_tmp}")" && pwd -P)"
  source_archive="${host_tmp}/source.tar"
  vendor_archive="${host_tmp}/cargo-vendor.tar.gz"
  vendor_stage="${host_tmp}/cargo-vendor-stage"
  pinned_head=unavailable
  guest_root="/var/tmp/shadowpipe-lockdown-reboot-${run_id}"
  guest_archive="${guest_root}/source.tar"
  guest_repo="${guest_root}/shadowpipe"
  guest_target="${guest_root}/target"
  guest_built_binary="${guest_target}/release/shadowpipe-client"
  guest_binary="${guest_root}/artifact/shadowpipe-client"
  guest_unit="${guest_repo}/deploy/shadowpipe-lockdown-restore.service"
  guest_client_unit="${guest_repo}/deploy/shadowpipe-client-full-tunnel.service"
  guest_vendor_archive="${guest_root}/cargo-vendor.tar.gz"
  guest_vendor="${guest_root}/cargo-vendor/vendor"
  guest_cargo_home="${guest_root}/cargo-home"
  ownership_token="$(printf '%s\0%s\0%s\n' \
    "${run_id}" "${clone_vm}" "${host_tmp}" | sha256sum | awk '{print $1}')"
  [[ "${ownership_token}" =~ ^[0-9a-f]{64}$ ]] \
    || die "${EX_UNAVAILABLE}" 'could not derive ownership token'
  write_ownership_marker "${result_dir}" "${ownership_token}" \
    || die "${EX_UNAVAILABLE}" 'could not mark result ownership'
  write_ownership_marker "${host_tmp}" "${ownership_token}" \
    || die "${EX_UNAVAILABLE}" 'could not mark temporary ownership'
  printf 'SHADOWPIPE_MAGIC=%s\n' "${magic}" \
    >"${result_dir}/build-contract.txt"
  before="${host_tmp}/mac-before"
  after="${host_tmp}/mac-after"
  final_status=0
  clone_attempted=0
  clone_owned=0
  clone_completion_uncertain=0
  guest_status=failed
  client_unit_status=failed
  host_safety=failed
  clone_deleted=not_attempted
  clone_cleanup_status=not_run
  target_deleted=not_applicable
  source_state_status=failed
  host_tmp_deleted=false
  lifecycle_lock=''
  lifecycle_lock_status=not_acquired
  pf_runtime_observed=unknown
  source_orb_id=''
  clone_orb_id=''
  clone_identity_bound=0
  clone_deletion_pending=0

  cleanup() {
    local incoming=$?
    trap - EXIT INT TERM HUP
    set +e
    (( incoming == 0 )) || final_status="${incoming}"
    local cleanup_listing="${result_dir}/orb-list-cleanup-before.txt"
    local final_listing="${result_dir}/orb-list-cleanup-after.txt"
    local cleanup_state='' marker_verified=0 clone_cleanup_failed=0 census_ok=0
    local delete_authorized=0
    if (( clone_attempted != 0 )); then
      clone_deleted=false
      clone_cleanup_status=failed
      if (( clone_completion_uncertain != 0 )); then
        if observe_clone_quiescence "${clone_vm}" "${source_vm}" \
          "${result_dir}/clone-quiescence-before-cleanup" stable_any \
          >"${result_dir}/clone-quiescence-before-cleanup.state"; then
          cleanup_listing="${result_dir}/clone-quiescence-before-cleanup/orb-list-${CLONE_QUIESCENCE_SAMPLES}.txt"
          census_ok=1
        fi
      elif orb_list_snapshot "${cleanup_listing}"; then
        census_ok=1
      fi
      if (( census_ok == 0 )); then
        warn 'could not enumerate OrbStack clones before cleanup'
        clone_cleanup_failed=1
        final_status=1
      elif [[ "$(vm_count_in_listing "${cleanup_listing}" "${clone_vm}")" == 1 ]]; then
        cleanup_state="$(vm_state_in_listing "${cleanup_listing}" "${clone_vm}")"
        if (( clone_identity_bound != 0 )) \
          && capture_orb_identity "${HOST_COMMAND_TIMEOUT}" \
            "${clone_vm}" "${clone_vm}" "${clone_orb_id}" '' \
            "${result_dir}/clone-info-cleanup-before-marker" >/dev/null; then
          delete_authorized=1
          if (( clone_owned != 0 )) && [[ "${cleanup_state}" != stopped ]]; then
            if run_recorded "${GUEST_COMMAND_TIMEOUT}" \
              "${result_dir}/clone-owner-cleanup-proof.txt" \
              orb -m "${clone_orb_id}" -u root sh -lc \
              "LC_ALL=C stat -c '%u %g %a %h %F' /var/lib/shadowpipe-reboot-lab-owner && cat /var/lib/shadowpipe-reboot-lab-owner" \
              && verify_guest_marker_proof \
                "${result_dir}/clone-owner-cleanup-proof.txt" "${ownership_token}"; then
              marker_verified=1
            else
              warn 'guest marker was not re-proved; exact bound ID still authorizes cleanup, but the run fails'
              clone_cleanup_failed=1
              final_status=1
            fi
          fi
        else
          warn 'refusing clone deletion: opaque clone ID was never bound or no longer matches the name'
          clone_cleanup_failed=1
          final_status=1
        fi
        if (( delete_authorized != 0 )); then
          if capture_orb_identity "${HOST_COMMAND_TIMEOUT}" \
            "${clone_vm}" "${clone_vm}" "${clone_orb_id}" '' \
            "${result_dir}/clone-info-cleanup-before-delete" >/dev/null; then
            if run_recorded "${ORB_DELETE_TIMEOUT}" \
              "${result_dir}/clone-delete.log" orbctl delete -f "${clone_vm}"; then
              clone_deletion_pending=1
              {
                printf 'delete_selector=name\n'
                printf 'delete_precondition=fresh_name_to_bound_id_validation\n'
                printf 'guest_marker_reproved=%s\n' "${marker_verified}"
              } >"${result_dir}/clone-delete-addressing.env"
            else
              clone_cleanup_failed=1
              final_status=1
            fi
          else
            clone_cleanup_failed=1
            final_status=1
          fi
        fi
      elif [[ "$(vm_count_in_listing "${cleanup_listing}" "${clone_vm}")" == 0 ]]; then
        clone_deleted=true
        if (( clone_owned != 0 )); then
          warn 'owned clone disappeared before owned cleanup'
          clone_cleanup_failed=1
          final_status=1
        fi
      else
        warn 'clone listing contains duplicate claimed names'
        clone_cleanup_failed=1
        final_status=1
      fi
      census_ok=0
      if (( clone_completion_uncertain != 0 || clone_deletion_pending != 0 )); then
        if observe_clone_quiescence "${clone_vm}" "${source_vm}" \
          "${result_dir}/clone-quiescence-after-cleanup" absent_all \
          >"${result_dir}/clone-quiescence-after-cleanup.state"; then
          final_listing="${result_dir}/clone-quiescence-after-cleanup/orb-list-${CLONE_QUIESCENCE_SAMPLES}.txt"
          census_ok=1
        fi
      elif orb_list_snapshot "${final_listing}"; then
        census_ok=1
      fi
      if (( census_ok == 0 )); then
        warn 'could not prove disposable OrbStack clone deletion'
        clone_cleanup_failed=1
        final_status=1
      elif [[ "$(vm_count_in_listing "${final_listing}" "${clone_vm}")" != 0 ]]; then
        warn "disposable OrbStack clone still exists: ${clone_vm}"
        clone_cleanup_failed=1
        final_status=1
      elif (( clone_identity_bound == 0 )) \
        || ! capture_orb_absence "${HOST_COMMAND_TIMEOUT}" \
          "${clone_orb_id}" "${result_dir}/clone-info-final-id" \
        || ! capture_orb_absence "${HOST_COMMAND_TIMEOUT}" \
          "${clone_vm}" "${result_dir}/clone-info-final-name"; then
        warn 'disposable clone name/ID absence was not proved'
        clone_cleanup_failed=1
        final_status=1
      else
        clone_deleted=true
        (( clone_cleanup_failed != 0 )) || clone_cleanup_status=valid
      fi
    fi

    if [[ -n "${source_orb_id}" ]]; then
      capture_orb_identity "${HOST_COMMAND_TIMEOUT}" \
        "${source_vm}" "${source_vm}" "${source_orb_id}" stopped \
        "${result_dir}/source-info-final" >/dev/null \
        || { source_state_status=failed; final_status=1; }
    fi

    if [[ -d "${before}" ]] && snapshot_macos "${after}" \
      && compare_macos_snapshots "${before}" "${after}" \
        "${result_dir}/mac-snapshot.diff"; then
      host_safety=valid
      if grep -qx 'pf_runtime_observed=true' "${before}/scope.env"; then
        pf_runtime_observed=true
      elif grep -qx 'pf_runtime_observed=false' "${before}/scope.env"; then
        pf_runtime_observed=false
      else
        host_safety=failed
        final_status=1
      fi
    else
      final_status=1
    fi
    if [[ -d "${before}" ]]; then
      cp -R -- "${before}" "${result_dir}/mac-before" || final_status=1
    fi
    if [[ -d "${after}" ]]; then
      cp -R -- "${after}" "${result_dir}/mac-after" || final_status=1
    fi
    if orb_list_snapshot "${result_dir}/orb-list-source-final.txt" \
      && [[ "$(vm_state_in_listing "${result_dir}/orb-list-source-final.txt" "${source_vm}")" == stopped ]]; then
      source_state_status=stopped
    else
      warn 'source VM is no longer proved uniquely stopped'
      final_status=1
    fi
    if [[ -n "${lifecycle_lock}" ]]; then
      if release_lifecycle_lock "${lifecycle_lock}" "${ownership_token}"; then
        lifecycle_lock_status=released
        lifecycle_lock=''
      else
        warn 'same-host OrbStack lifecycle lock identity changed or could not be released'
        lifecycle_lock_status=release_failed
        final_status=1
      fi
    fi
    if safe_remove_owned_tree "${host_tmp}" "${host_tmp_root}" "${ownership_token}"; then
      host_tmp_deleted=true
    else
      warn 'refusing or failing temporary cleanup: ownership/path proof failed'
      final_status=1
    fi

    local overall_status=failed evidence_bundle_status=valid candidate_success=0
    local publication_owned=1
    if [[ "${final_status}" == 0 && "${guest_status}" == valid \
      && "${client_unit_status}" == valid \
      && "${clone_attempted}" == 1 \
      && "${host_safety}" == valid && "${clone_deleted}" == true \
      && "${clone_cleanup_status}" == valid \
      && "${target_deleted}" == not_applicable \
      && "${host_tmp_deleted}" == true \
      && "${source_state_status}" == stopped \
      && "${lifecycle_lock_status}" == released \
      && ( "${pf_runtime_observed}" == true \
        || "${pf_runtime_observed}" == false ) ]]; then
      overall_status=valid
      candidate_success=1
    else
      final_status=1
    fi

    if ! canonical_owned_tree "${result_dir}" "${results_root}" \
      "${ownership_token}" >/dev/null; then
      warn 'result ownership changed before final publication'
      final_status=1
      candidate_success=0
      overall_status=failed
      publication_owned=0
    fi
    if (( publication_owned != 0 )); then
      local publication_ready=1
      if ! write_reboot_status "${result_dir}/status.env" \
      "${guest_status}" "${client_unit_status}" "${host_safety}" \
      "${clone_attempted}" "${clone_deleted}" \
      "${clone_cleanup_status}" \
      "${target_deleted}" "${host_tmp_deleted}" "${source_state_status}" \
      "${lifecycle_lock_status}" "${pf_runtime_observed}" \
      "${evidence_bundle_status}" "${overall_status}" \
        || ! write_reboot_result "${result_dir}/RESULT.md" \
        "${overall_status}" "${clone_vm}" "${pf_runtime_observed}" \
        "${source_vm}" "${pinned_head}" "${client_unit_status}" \
        "${guest_status}"; then
        final_status=1
        candidate_success=0
        overall_status=failed
        if ! rm -f -- "${result_dir}/status.env" "${result_dir}/RESULT.md" \
          "${result_dir}/checksums.sha256"; then
          publication_ready=0
        elif ! write_reboot_status "${result_dir}/status.env" \
          "${guest_status}" "${client_unit_status}" "${host_safety}" \
          "${clone_attempted}" "${clone_deleted}" \
          "${clone_cleanup_status}" \
          "${target_deleted}" "${host_tmp_deleted}" "${source_state_status}" \
          "${lifecycle_lock_status}" "${pf_runtime_observed}" \
          "${evidence_bundle_status}" failed \
          || ! write_reboot_result "${result_dir}/RESULT.md" failed \
          "${clone_vm}" "${pf_runtime_observed}" "${source_vm}" \
          "${pinned_head}" "${client_unit_status}" "${guest_status}" \
          || ! grep -qx 'overall_status=failed' "${result_dir}/status.env" \
          || grep -q 'Verdict: \*\*PASS\*\*' "${result_dir}/RESULT.md"; then
          publication_ready=0
        fi
      fi

      if (( publication_ready != 0 )) \
        && { ! seal_bundle "${result_dir}" \
        || ! (cd -- "${result_dir}" \
          && sha256sum -c checksums.sha256 >/dev/null); }; then
        final_status=1
        candidate_success=0
        overall_status=failed
        evidence_bundle_status=failed
        if ! rm -f -- "${result_dir}/status.env" "${result_dir}/RESULT.md" \
          "${result_dir}/checksums.sha256"; then
          publication_ready=0
        elif ! write_reboot_status "${result_dir}/status.env" \
          "${guest_status}" "${client_unit_status}" "${host_safety}" \
          "${clone_attempted}" "${clone_deleted}" \
          "${clone_cleanup_status}" \
          "${target_deleted}" "${host_tmp_deleted}" "${source_state_status}" \
          "${lifecycle_lock_status}" "${pf_runtime_observed}" failed failed \
          || ! write_reboot_result "${result_dir}/RESULT.md" failed \
          "${clone_vm}" "${pf_runtime_observed}" "${source_vm}" \
          "${pinned_head}" "${client_unit_status}" "${guest_status}" \
          || ! grep -qx 'overall_status=failed' "${result_dir}/status.env" \
          || grep -q 'Verdict: \*\*PASS\*\*' "${result_dir}/RESULT.md"; then
          publication_ready=0
        elif ! seal_bundle "${result_dir}" \
          || ! (cd -- "${result_dir}" \
            && sha256sum -c checksums.sha256 >/dev/null); then
          warn 'failed to seal even the failure bundle'
          publication_ready=0
        fi
      fi
      if (( publication_ready == 0 )); then
        rm -f -- "${result_dir}/checksums.sha256" || true
        warn 'failure publication was incomplete; evidence intentionally left unsealed'
        final_status=1
        candidate_success=0
      fi
    fi
    (( candidate_success != 0 )) || final_status=1
    printf 'result: %s\n' "${result_dir}"
    exit "${final_status}"
  }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP

  lifecycle_lock="$(acquire_lifecycle_lock "${ownership_token}")" \
    || die 75 'another same-host OrbStack lifecycle runner is active or left a conservative stale lock'
  lifecycle_lock_status=held

  capture_git_checkout_proof "${repo_root}" \
    "${result_dir}/git-checkout-before" \
    || die "${EX_UNAVAILABLE}" \
      'repository must be clean pushed main before creating the guest archive'
  pinned_head="$(<"${result_dir}/git-checkout-before/head.txt")"
  create_pinned_source_archive "${repo_root}" "${pinned_head}" \
    "${source_archive}" "${result_dir}/source-archive.env" \
    || die "${EX_UNAVAILABLE}" 'could not create a bounded pinned Git archive'
  source_archive_size="$(source_archive_field \
    "${result_dir}/source-archive.env" source_archive_bytes)" \
    || die "${EX_UNAVAILABLE}" 'source archive size proof is malformed'
  source_archive_hash="$(source_archive_field \
    "${result_dir}/source-archive.env" source_archive_sha256)" \
    || die "${EX_UNAVAILABLE}" 'source archive digest proof is malformed'

  create_provenance_manifest "${repo_root}" \
    "${result_dir}/source-provenance-before.sha256"
  # shellcheck disable=SC2016
  run_recorded "${HOST_COMMAND_TIMEOUT}" \
    "${result_dir}/critical-provenance.sha256" /bin/sh -c \
    'cd "$1" && sha256sum .cargo/config.toml Cargo.lock Cargo.toml crates/shadowpipe-core/Cargo.toml crates/shadowpipe-core/build.rs crates/shadowpipe-core/src/lockdown.rs crates/shadowpipe-client/Cargo.toml crates/shadowpipe-client/src/main.rs crates/shadowpipe-reality/Cargo.toml crates/shadowpipe-reality/src/lib.rs crates/shadowpipe-reality/src/auth.rs crates/shadowpipe-reality/src/reality.rs deploy/shadowpipe-client-full-tunnel.service deploy/shadowpipe-lockdown-restore.service tests/lockdown/normalize-built-artifact.py tests/lockdown/run-orbstack-reboot.sh' \
    provenance "${repo_root}"
  say 'creating a pinned, checksum-validated Cargo vendor bundle offline'
  create_cargo_vendor_bundle "${repo_root}" "${source_archive}" \
    "${source_archive_size}" "${source_archive_hash}" "${pinned_head}" \
    "${vendor_stage}" "${vendor_archive}" \
    "${result_dir}/cargo-vendor.env" "${guest_vendor}" \
    || die "${EX_UNAVAILABLE}" \
      'could not create the provenance-bound offline Cargo vendor bundle'
  vendor_archive_size="$(source_archive_field \
    "${result_dir}/cargo-vendor.env" vendor_archive_bytes)" \
    || die "${EX_UNAVAILABLE}" 'Cargo vendor archive size proof is malformed'
  vendor_archive_hash="$(source_archive_field \
    "${result_dir}/cargo-vendor.env" vendor_archive_sha256)" \
    || die "${EX_UNAVAILABLE}" 'Cargo vendor archive digest proof is malformed'
  vendor_lock_hash="$(source_archive_field \
    "${result_dir}/cargo-vendor.env" cargo_lock_sha256)" \
    || die "${EX_UNAVAILABLE}" 'Cargo vendor lock binding is malformed'
  vendor_manifest_hash="$(source_archive_field \
    "${result_dir}/cargo-vendor.env" vendor_manifest_sha256)" \
    || die "${EX_UNAVAILABLE}" 'Cargo vendor manifest binding is malformed'
  vendor_config_hash="$(source_archive_field \
    "${result_dir}/cargo-vendor.env" cargo_config_sha256)" \
    || die "${EX_UNAVAILABLE}" 'Cargo vendor config binding is malformed'
  vendor_archive_members="$(source_archive_field \
    "${result_dir}/cargo-vendor.env" vendor_archive_members)" \
    || die "${EX_UNAVAILABLE}" 'Cargo vendor member census is malformed'
  vendor_expanded_bytes="$(source_archive_field \
    "${result_dir}/cargo-vendor.env" vendor_expanded_bytes)" \
    || die "${EX_UNAVAILABLE}" 'Cargo vendor expanded-byte census is malformed'
  verify_provenance_manifest "${repo_root}" \
    "${result_dir}/source-provenance-before.sha256" \
    "${result_dir}/source-provenance-after-vendor.sha256" \
    || die 1 'source/unit/harness/Cargo.lock changed while dependencies were vendored'
  capture_git_checkout_proof "${repo_root}" \
    "${result_dir}/git-checkout-after-vendor" "${pinned_head}" \
    || die 1 'host checkout or pushed origin/main changed during dependency vendoring'
  orb_list_snapshot "${result_dir}/orb-list-initial.txt"
  local source_state
  source_state="$(vm_state_in_listing \
    "${result_dir}/orb-list-initial.txt" "${source_vm}")" \
    || die "${EX_USAGE}" "source VM ${source_vm} is missing or duplicated"
  [[ "${source_state}" == stopped ]] \
    || die "${EX_USAGE}" "source VM ${source_vm} must be stopped (state=${source_state})"
  [[ "$(vm_count_in_listing "${result_dir}/orb-list-initial.txt" "${clone_vm}")" == 0 ]] \
    || die "${EX_UNAVAILABLE}" "refusing to clobber existing clone ${clone_vm}"
  source_orb_id="$(capture_orb_identity "${HOST_COMMAND_TIMEOUT}" \
    "${source_vm}" "${source_vm}" '' stopped \
    "${result_dir}/source-info-before")" \
    || die "${EX_UNAVAILABLE}" 'could not bind the stopped source VM opaque ID'
  snapshot_macos "${before}" \
    || die "${EX_UNAVAILABLE}" 'live macOS safety baseline is incomplete or ambiguous'

  say "cloning stopped ${source_vm} -> disposable ${clone_vm}"
  clone_attempted=1
  clone_completion_uncertain=1
  run_recorded "${ORB_CLONE_TIMEOUT}" "${result_dir}/clone.log" \
    orbctl clone "${source_vm}" "${clone_vm}"
  orb_list_snapshot "${result_dir}/orb-list-after-clone.txt"
  [[ "$(vm_count_in_listing "${result_dir}/orb-list-after-clone.txt" "${clone_vm}")" == 1 ]] \
    || die 1 'clone command succeeded without an exact one-name census'
  [[ "$(vm_state_in_listing \
    "${result_dir}/orb-list-after-clone.txt" "${source_vm}")" == stopped ]] \
    || die 1 'source VM changed state during clone creation'
  capture_orb_identity "${HOST_COMMAND_TIMEOUT}" \
    "${source_vm}" "${source_vm}" "${source_orb_id}" stopped \
    "${result_dir}/source-info-after-clone" >/dev/null \
    || die 1 'source VM identity or state changed during clone creation'
  clone_orb_id="$(capture_orb_identity "${HOST_COMMAND_TIMEOUT}" \
    "${clone_vm}" "${clone_vm}" '' stopped \
    "${result_dir}/clone-info-after-clone")" \
    || die 1 'could not bind the disposable clone opaque ID'
  clone_identity_bound=1
  clone_completion_uncertain=0
  capture_orb_identity "${HOST_COMMAND_TIMEOUT}" \
    "${clone_vm}" "${clone_vm}" "${clone_orb_id}" stopped \
    "${result_dir}/clone-info-before-start" >/dev/null \
    || die 1 'clone name was absent or reused before start'
  run_recorded "${ORB_START_TIMEOUT}" "${result_dir}/clone-start.log" \
    orbctl start "${clone_orb_id}"
  wait_for_guest "${clone_orb_id}" "${result_dir}/guest-ready-after-start.txt" \
    || die "${EX_UNAVAILABLE}" 'disposable guest did not become ready within the hard deadline'
  capture_orb_identity "${HOST_COMMAND_TIMEOUT}" \
    "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
    "${result_dir}/clone-info-before-owner-marker" >/dev/null \
    || die 1 'clone identity changed before ownership marking'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/clone-owner-install.log" \
    orb -m "${clone_orb_id}" -u root python3 -I -S -c \
    'import os,sys; p=sys.argv[1]; data=(sys.argv[2]+"\n").encode("ascii"); flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0); fd=os.open(p,flags,0o600); os.write(fd,data); os.fsync(fd); os.close(fd); d=os.open(os.path.dirname(p),os.O_RDONLY|os.O_DIRECTORY); os.fsync(d); os.close(d)' \
    /var/lib/shadowpipe-reboot-lab-owner "${ownership_token}"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/clone-owner-proof.txt" \
    orb -m "${clone_orb_id}" -u root sh -lc \
    "LC_ALL=C stat -c '%u %g %a %h %F' /var/lib/shadowpipe-reboot-lab-owner && cat /var/lib/shadowpipe-reboot-lab-owner"
  verify_guest_marker_proof "${result_dir}/clone-owner-proof.txt" \
    "${ownership_token}" || die 1 'guest ownership marker differs immediately after creation'
  clone_owned=1
  capture_orb_identity "${HOST_COMMAND_TIMEOUT}" \
    "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
    "${result_dir}/clone-info-after-owner-marker" >/dev/null \
    || die 1 'clone identity or isolated configuration changed after ownership marking'
  capture_guest_isolation_preflight "${clone_orb_id}" \
    "${result_dir}/guest-isolation-preflight.env" \
    || die "${EX_UNAVAILABLE}" \
      'clone runtime exposes Mac sharing, SSH agent, or mac-command integration'
  capture_pid1_systemd_proof "${clone_orb_id}" \
    "${result_dir}/pid1-systemd-pre.env" \
    || die "${EX_UNAVAILABLE}" 'live guest PID 1 is not systemd >=254'
  verify_pid1_systemd_proof "${result_dir}/pid1-systemd-pre.env"
  # The unit/root variables below intentionally expand only in the guest shell.
  # shellcheck disable=SC2016
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/guest-state-preflight.txt" \
    orb -m "${clone_orb_id}" -u root sh -ceu \
    'test ! -e /var/lib/shadowpipe/handoff-lockdown-v1.json
     test ! -e /var/lib/shadowpipe/host-state-v2.json
     test ! -e /etc/systemd/system/shadowpipe-lockdown-restore.service
     test ! -e /etc/systemd/system/shadowpipe-client-full-tunnel.service
     for unit in shadowpipe-lockdown-restore.service shadowpipe-client-full-tunnel.service; do
       for root in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
         test ! -e "${root}/${unit}.d"
         test ! -e "${root}/${unit}.requires"
         test ! -e "${root}/${unit}.wants"
       done
     done
     test ! -e /etc/shadowpipe/client.env
     test ! -e /etc/shadowpipe/client-credential.json
     test ! -e /usr/local/bin/shadowpipe-client'

  stream_source_archive_to_guest "${clone_orb_id}" "${source_archive}" \
    "${guest_root}" "${guest_archive}" "${source_archive_size}" \
    "${source_archive_hash}" "${result_dir}/source-transfer.env" \
    || die 1 'bounded pinned source archive transfer into the clone failed'
  extract_guest_source_archive "${clone_orb_id}" "${guest_root}" \
    "${guest_archive}" "${guest_repo}" "${source_archive_size}" \
    "${source_archive_hash}" "${result_dir}/source-extract.env" \
    || die 1 'guest-local source extraction failed'
  capture_guest_tree_manifest "${clone_orb_id}" "${guest_repo}" source \
    20000 "${MAX_SOURCE_EXPANDED_BYTES}" \
    "${result_dir}/guest-source-manifest-baseline.json" \
    || die 1 'could not seal the exact guest source tree after extraction'

  stream_vendor_archive_to_guest "${clone_orb_id}" "${vendor_archive}" \
    "${guest_root}" "${guest_vendor_archive}" "${vendor_archive_size}" \
    "${vendor_archive_hash}" "${result_dir}/cargo-vendor-transfer.env" \
    || die 1 'bounded Cargo vendor archive transfer into the clone failed'
  extract_guest_vendor_archive "${clone_orb_id}" "${guest_root}" \
    "${guest_vendor_archive}" "${guest_repo}" "${guest_cargo_home}" \
    "${vendor_archive_size}" "${vendor_archive_hash}" "${pinned_head}" \
    "${source_archive_hash}" "${vendor_lock_hash}" \
    "${vendor_manifest_hash}" "${vendor_config_hash}" \
    "${vendor_archive_members}" "${vendor_expanded_bytes}" \
    "${result_dir}/cargo-vendor-extract.env" \
    || die 1 'guest Cargo vendor extraction or provenance validation failed'
  capture_guest_tree_manifest "${clone_orb_id}" \
    "${guest_root}/cargo-vendor" vendor \
    "$((MAX_VENDOR_MEMBERS + 100))" \
    "$((MAX_VENDOR_EXPANDED_BYTES + 16 * 1024 * 1024))" \
    "${result_dir}/guest-vendor-manifest-baseline.json" \
    || die 1 'could not seal the exact guest vendor tree after extraction'
  capture_guest_cargo_config_binding "${clone_orb_id}" \
    "${guest_cargo_home}" "${vendor_config_hash}" \
    "${result_dir}/guest-cargo-config-baseline.json" \
    || die 1 'private guest Cargo config is not bound to the sealed vendor bundle'

  say 'building pinned Linux ARM64 client from only the bound vendor tree'
  # The single-quoted program is intentionally evaluated by guest Bash.
  # shellcheck disable=SC2016
  run_recorded "${BUILD_TIMEOUT}" "${result_dir}/build.log" \
    orb -m "${clone_orb_id}" -u root bash -ceu '
      repo=$1
      binary=$2
      cargo_home=$3
      target=$4
      vendor=$5
      magic=$6
      test ! -e /.cargo/config
      test ! -e /.cargo/config.toml
      test "$(find "${cargo_home}" -mindepth 1 -maxdepth 1 -print | LC_ALL=C sort)" = "${cargo_home}/config.toml"
      test ! -e "${target}"
      cargo_bin=$(command -v cargo)
      unshare_bin=$(command -v unshare)
      test "${cargo_bin}" != "" && test "${unshare_bin}" != ""
      cd /
      exec "${unshare_bin}" --net -- /usr/bin/env -i \
        HOME="${cargo_home}" CARGO_HOME="${cargo_home}" \
        CARGO_TARGET_DIR="${target}" CARGO_NET_OFFLINE=true \
        CARGO_TERM_COLOR=never SHADOWPIPE_MAGIC="${magic}" \
        PATH="${cargo_bin%/*}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
        "${cargo_bin}" \
        --config "source.crates-io.replace-with=\"shadowpipe-vendored-sources\"" \
        --config "source.shadowpipe-vendored-sources.directory=\"${vendor}\"" \
        --config net.offline=true \
        build --frozen --release --no-default-features \
        -p shadowpipe-client --manifest-path "${repo}/Cargo.toml"
    ' shadowpipe-reboot-build "${guest_repo}" "${guest_built_binary}" \
    "${guest_cargo_home}" "${guest_target}" "${guest_vendor}" "${magic}" \
    || die 1 'frozen build from the bound Cargo vendor tree failed'
  capture_guest_tree_manifest "${clone_orb_id}" "${guest_repo}" source \
    20000 "${MAX_SOURCE_EXPANDED_BYTES}" \
    "${result_dir}/guest-source-manifest-post-build.json"
  verify_guest_tree_manifest \
    "${result_dir}/guest-source-manifest-baseline.json" \
    "${result_dir}/guest-source-manifest-post-build.json" source \
    || die 1 'guest source tree drifted during the frozen build'
  capture_guest_tree_manifest "${clone_orb_id}" \
    "${guest_root}/cargo-vendor" vendor \
    "$((MAX_VENDOR_MEMBERS + 100))" \
    "$((MAX_VENDOR_EXPANDED_BYTES + 16 * 1024 * 1024))" \
    "${result_dir}/guest-vendor-manifest-post-build.json"
  verify_guest_tree_manifest \
    "${result_dir}/guest-vendor-manifest-baseline.json" \
    "${result_dir}/guest-vendor-manifest-post-build.json" vendor \
    || die 1 'guest vendor tree drifted during the frozen build'
  capture_guest_cargo_config_binding "${clone_orb_id}" \
    "${guest_cargo_home}" "${vendor_config_hash}" \
    "${result_dir}/guest-cargo-config-post-build.json"
  verify_guest_cargo_config_binding \
    "${result_dir}/guest-cargo-config-baseline.json" \
    "${result_dir}/guest-cargo-config-post-build.json" \
    || die 1 'private guest Cargo config drifted during the frozen build'
  verify_provenance_manifest "${repo_root}" \
    "${result_dir}/source-provenance-before.sha256" \
    "${result_dir}/source-provenance-after-build.sha256" \
    || die 1 'source/unit/harness/Cargo.lock changed while the binary was built'
  capture_git_checkout_proof "${repo_root}" \
    "${result_dir}/git-checkout-after-build" "${pinned_head}" \
    || die 1 'host checkout or pushed origin/main changed during guest-local build'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/guest-build-boundary-post.env" \
    orb -m "${clone_orb_id}" -u root python3 -I -S \
    "${guest_repo}/tests/lockdown/normalize-built-artifact.py" \
    --require-root \
    "${guest_cargo_home}" "${guest_target}" "${guest_built_binary}" \
    "${guest_binary}" \
    || die 1 'built executable could not cross the single-link artifact boundary'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/built-binary.sha256" \
    orb -m "${clone_orb_id}" -u root sha256sum "${guest_binary}"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/guest-source-unit.sha256" \
    orb -m "${clone_orb_id}" -u root sha256sum "${guest_unit}"

  # The single-quoted install program is evaluated by the guest shell.
  # shellcheck disable=SC2016
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/install-binary.log" \
    orb -m "${clone_orb_id}" -u root sh -ceu \
    'install -m 0755 -- "$1" /usr/local/bin/shadowpipe-client' \
    _ "${guest_binary}"
  # The single-quoted install program is evaluated by the guest shell.
  # shellcheck disable=SC2016
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/install-unit.log" \
    orb -m "${clone_orb_id}" -u root sh -ceu \
    'install -m 0644 -- "$1" /etc/systemd/system/shadowpipe-lockdown-restore.service' \
    _ "${guest_unit}"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/state-dir-and-reload.log" \
    orb -m "${clone_orb_id}" -u root sh -lc \
    'install -d -o root -g root -m 0700 /var/lib/shadowpipe; systemctl daemon-reload'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/systemd-verify.txt" \
    orb -m "${clone_orb_id}" -u root systemd-analyze verify \
    /etc/systemd/system/shadowpipe-lockdown-restore.service
  capture_effective_unit_definition "${clone_orb_id}" \
    shadowpipe-lockdown-restore.service \
    "${result_dir}/restore-effective-definition-pre-reboot.txt"
  verify_effective_unit_definition \
    "${result_dir}/restore-effective-definition-pre-reboot.txt" restore
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/systemd-version.txt" \
    orb -m "${clone_orb_id}" -u root /sbin/init --version
  verify_systemd_minimum "${result_dir}/systemd-version.txt"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/installed-binary.sha256" \
    orb -m "${clone_orb_id}" -u root sha256sum /usr/local/bin/shadowpipe-client
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/installed-unit.sha256" \
    orb -m "${clone_orb_id}" -u root sha256sum \
    /etc/systemd/system/shadowpipe-lockdown-restore.service
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${result_dir}/source-unit.sha256" \
    sha256sum "${repo_root}/deploy/shadowpipe-lockdown-restore.service"
  verify_same_digest "${result_dir}/built-binary.sha256" \
    "${result_dir}/installed-binary.sha256"
  verify_same_digest "${result_dir}/source-unit.sha256" \
    "${result_dir}/guest-source-unit.sha256"
  verify_same_digest "${result_dir}/source-unit.sha256" \
    "${result_dir}/installed-unit.sha256"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/systemd-enable.txt" \
    orb -m "${clone_orb_id}" -u root systemctl enable \
    shadowpipe-lockdown-restore.service
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/systemd-is-enabled-pre.txt" \
    orb -m "${clone_orb_id}" -u root env LC_ALL=C systemctl is-enabled \
    shadowpipe-lockdown-restore.service
  [[ "$(<"${result_dir}/systemd-is-enabled-pre.txt")" == enabled ]] \
    || die 1 'restore unit is not enabled before reboot'

  local gateway
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/guest-default-route.txt" \
    orb -m "${clone_orb_id}" -u root ip -4 route show default
  gateway="$(awk 'NR == 1 { print $3 }' \
    "${result_dir}/guest-default-route.txt")"
  [[ "${gateway}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "${EX_UNAVAILABLE}" 'guest has no IPv4 default gateway for the oracle'
  printf '%s\n' "${gateway}" >"${result_dir}/guest-gateway.txt"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/pre-arm-ping.txt" \
    orb -m "${clone_orb_id}" -u root ping -q -c 1 -W 2 "${gateway}"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/boot-id-pre.txt" \
    orb -m "${clone_orb_id}" -u root cat /proc/sys/kernel/random/boot_id
  [[ "$(awk -F= '$1 == "boot_id" { print $2 }' \
    "${result_dir}/pid1-systemd-pre.env")" \
      == "$(<"${result_dir}/boot-id-pre.txt")" ]] \
    || die 1 'pre-restart boot ID collectors disagree'

  # The empty possible-main marker authorizes only cross-session continuity;
  # it contains no route, DNS, TUN, or firewall resource to recover.
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/possible-main-marker.log" \
    orb -m "${clone_orb_id}" -u root python3 -I -S -c \
    'import os; p="/var/lib/shadowpipe/host-state-v2.json"; flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0); fd=os.open(p,flags,0o600); os.fsync(fd); os.close(fd); d=os.open(os.path.dirname(p),os.O_RDONLY|os.O_DIRECTORY); os.fsync(d); os.close(d)'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/pre-reboot-arm.log" \
    orb -m "${clone_orb_id}" -u root env -u SSH_CONNECTION -u SSH_CLIENT \
    /usr/local/bin/shadowpipe-client --restore-lockdown \
    --host-state-dir /var/lib/shadowpipe
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/wal-pre-reboot.json" \
    orb -m "${clone_orb_id}" -u root cat \
    /var/lib/shadowpipe/handoff-lockdown-v1.json
  capture_guest_state_metadata "${clone_orb_id}" \
    "${result_dir}/state-metadata-pre-reboot.txt"
  verify_guest_state_metadata "${result_dir}/state-metadata-pre-reboot.txt"
  local table_pre
  table_pre="$(wal_table_name "${result_dir}/wal-pre-reboot.json" \
    "${result_dir}/boot-id-pre.txt" 2 \
    "${result_dir}/state-metadata-pre-reboot.txt" \
    2>"${result_dir}/wal-pre-reboot-handle.txt")"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/nft-pre-reboot.json" \
    orb -m "${clone_orb_id}" -u root nft -j -a list table inet "${table_pre}"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/nft-census-pre-reboot.json" \
    orb -m "${clone_orb_id}" -u root nft -j -a list tables
  verify_nft_snapshot "${result_dir}/wal-pre-reboot.json" \
    "${result_dir}/nft-pre-reboot.json" \
    "${result_dir}/nft-census-pre-reboot.json" -
  if run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/blocked-pre-reboot-ping.txt" \
    orb -m "${clone_orb_id}" -u root ping -q -c 1 -W 1 "${gateway}"; then
    die 1 'non-loopback IPv4 escaped the pre-reboot barrier'
  fi
  [[ "$(<"${result_dir}/blocked-pre-reboot-ping.txt.status")" != 124 ]] \
    || die 1 'pre-reboot denial oracle itself timed out'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/loopback-pre-reboot-ping.txt" \
    orb -m "${clone_orb_id}" -u root ping -q -c 1 -W 1 127.0.0.1

  say 'restarting disposable OrbStack userspace with an owned Active WAL'
  capture_orb_identity "${HOST_COMMAND_TIMEOUT}" \
    "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
    "${result_dir}/clone-info-before-restart" >/dev/null \
    || die 1 'clone identity changed before reboot'
  clone_completion_uncertain=1
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/reboot.log" \
    orbctl restart "${clone_orb_id}"
  wait_for_guest "${clone_orb_id}" "${result_dir}/guest-ready-after-reboot.txt" \
    || die 1 'guest did not return after the OrbStack userspace restart'
  capture_orb_identity "${HOST_COMMAND_TIMEOUT}" \
    "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
    "${result_dir}/clone-info-after-restart" >/dev/null \
    || die 1 'clone identity or isolated configuration changed across restart'
  clone_completion_uncertain=0
  capture_guest_isolation_preflight "${clone_orb_id}" \
    "${result_dir}/guest-isolation-post-restart.env" \
    || die 1 \
      'clone runtime exposed Mac sharing, SSH agent, or mac-command integration after restart'
  capture_pid1_systemd_proof "${clone_orb_id}" \
    "${result_dir}/pid1-systemd-post.env" \
    || die 1 'systemd was not live PID 1 after the OrbStack machine restart'
  verify_pid1_systemd_proof "${result_dir}/pid1-systemd-post.env"
  verify_userspace_restart_transition \
    "${result_dir}/pid1-systemd-pre.env" \
    "${result_dir}/pid1-systemd-post.env" \
    "${result_dir}/userspace-systemd-boot.env"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/boot-id-post.txt" \
    orb -m "${clone_orb_id}" -u root cat /proc/sys/kernel/random/boot_id
  [[ "$(awk -F= '$1 == "boot_id" { print $2 }' \
    "${result_dir}/pid1-systemd-post.env")" \
      == "$(<"${result_dir}/boot-id-post.txt")" ]] \
    || die 1 'post-restart boot ID collectors disagree'
  ! cmp -s "${result_dir}/boot-id-pre.txt" "${result_dir}/boot-id-post.txt" \
    || die 1 'boot identity did not change'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/clone-owner-post-reboot.txt" \
    orb -m "${clone_orb_id}" -u root sh -lc \
    "LC_ALL=C stat -c '%u %g %a %h %F' /var/lib/shadowpipe-reboot-lab-owner && cat /var/lib/shadowpipe-reboot-lab-owner"
  verify_guest_marker_proof "${result_dir}/clone-owner-post-reboot.txt" \
    "${ownership_token}" || die 1 'guest ownership marker did not survive reboot'

  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/systemd-is-enabled-post.txt" \
    orb -m "${clone_orb_id}" -u root env LC_ALL=C systemctl is-enabled \
    shadowpipe-lockdown-restore.service
  capture_exact_systemd_properties \
    "${clone_orb_id}" shadowpipe-lockdown-restore.service restore \
    "${result_dir}/systemd-restore-status.txt" \
    LoadState UnitFileState ActiveState SubState Result \
    ExecMainCode ExecMainStatus NRestarts \
    ExecMainStartTimestampMonotonic ExecMainExitTimestampMonotonic \
    ActiveEnterTimestampMonotonic InactiveExitTimestampMonotonic \
    InvocationID Before FragmentPath DropInPaths \
    ExecCondition ExecStartPre ExecStart ExecStartPost EnvironmentFiles
  capture_exact_systemd_properties \
    "${clone_orb_id}" systemd-networkd.service none \
    "${result_dir}/systemd-networkd-status.txt" \
    LoadState ActiveState SubState \
    ExecMainStartTimestampMonotonic InactiveExitTimestampMonotonic \
    InvocationID NRestarts After Requires
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/systemd-networkd-dependencies.txt" \
    orb -m "${clone_orb_id}" -u root env LC_ALL=C systemctl list-dependencies \
    systemd-networkd.service --plain --no-pager
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/systemd-critical-chain.txt" \
    orb -m "${clone_orb_id}" -u root env LC_ALL=C systemd-analyze critical-chain \
    systemd-networkd.service
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/systemd-journal.txt" \
    orb -m "${clone_orb_id}" -u root env LC_ALL=C journalctl -b \
    -u shadowpipe-lockdown-restore.service --no-pager -o short-monotonic
  verify_systemd_evidence "${result_dir}/systemd-version.txt" \
    "${result_dir}/systemd-is-enabled-post.txt" \
    "${result_dir}/systemd-restore-status.txt" \
    "${result_dir}/systemd-networkd-status.txt" \
    "${result_dir}/systemd-networkd-dependencies.txt"

  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/wal-post-reboot.json" \
    orb -m "${clone_orb_id}" -u root cat \
    /var/lib/shadowpipe/handoff-lockdown-v1.json
  capture_guest_state_metadata "${clone_orb_id}" \
    "${result_dir}/state-metadata-post-reboot.txt"
  verify_guest_state_metadata "${result_dir}/state-metadata-post-reboot.txt"
  local table_post
  table_post="$(wal_table_name "${result_dir}/wal-post-reboot.json" \
    "${result_dir}/boot-id-post.txt" 4 \
    "${result_dir}/state-metadata-post-reboot.txt" \
    2>"${result_dir}/wal-post-reboot-handle.txt")"
  [[ "${table_pre}" != "${table_post}" ]] \
    || die 1 'userspace restart did not renew the lockdown table identity'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/nft-post-reboot.json" \
    orb -m "${clone_orb_id}" -u root nft -j -a list table inet "${table_post}"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/nft-census-post-reboot.json" \
    orb -m "${clone_orb_id}" -u root nft -j -a list tables
  if run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/old-table-post-reboot.txt" \
    orb -m "${clone_orb_id}" -u root nft -j -a list table inet "${table_pre}"; then
    die 1 'pre-reboot lockdown table survived reboot'
  fi
  [[ "$(<"${result_dir}/old-table-post-reboot.txt.status")" != 124 ]] \
    || die 1 'old-table absence oracle timed out'
  verify_nft_snapshot "${result_dir}/wal-post-reboot.json" \
    "${result_dir}/nft-post-reboot.json" \
    "${result_dir}/nft-census-post-reboot.json" "${table_pre}"
  if run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/blocked-post-reboot-ping.txt" \
    orb -m "${clone_orb_id}" -u root ping -q -c 1 -W 1 "${gateway}"; then
    die 1 'non-loopback IPv4 escaped the post-reboot barrier'
  fi
  [[ "$(<"${result_dir}/blocked-post-reboot-ping.txt.status")" != 124 ]] \
    || die 1 'post-reboot denial oracle itself timed out'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/loopback-post-reboot-ping.txt" \
    orb -m "${clone_orb_id}" -u root ping -q -c 1 -W 1 127.0.0.1

  # This is an explicit operator release in a single-guest lab. It does not
  # prove a replacement full tunnel, tunnel handoff, or production readiness.
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/remove-main-marker.log" \
    orb -m "${clone_orb_id}" -u root rm \
    /var/lib/shadowpipe/host-state-v2.json
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/explicit-release.log" \
    orb -m "${clone_orb_id}" -u root env -u SSH_CONNECTION -u SSH_CLIENT \
    /usr/local/bin/shadowpipe-client --release-lockdown \
    --host-state-dir /var/lib/shadowpipe
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/wal-absent-after-release.txt" \
    orb -m "${clone_orb_id}" -u root test ! -e \
    /var/lib/shadowpipe/handoff-lockdown-v1.json
  if run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/nft-table-after-release.txt" \
    orb -m "${clone_orb_id}" -u root nft -j -a list table inet "${table_post}"; then
    die 1 'explicit release left the lockdown nft table'
  fi
  [[ "$(<"${result_dir}/nft-table-after-release.txt.status")" != 124 ]] \
    || die 1 'post-release table-absence oracle timed out'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/nft-census-after-release.json" \
    orb -m "${clone_orb_id}" -u root nft -j -a list tables
  verify_no_lockdown_tables "${result_dir}/nft-census-after-release.json"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/post-release-ping.txt" \
    orb -m "${clone_orb_id}" -u root ping -q -c 1 -W 2 "${gateway}"

  capture_guest_tree_manifest "${clone_orb_id}" "${guest_repo}" source \
    20000 "${MAX_SOURCE_EXPANDED_BYTES}" \
    "${result_dir}/guest-source-manifest-post-lockdown.json"
  verify_guest_tree_manifest \
    "${result_dir}/guest-source-manifest-baseline.json" \
    "${result_dir}/guest-source-manifest-post-lockdown.json" source \
    || die 1 'guest source tree drifted during the reboot/lockdown experiment'
  capture_guest_tree_manifest "${clone_orb_id}" \
    "${guest_root}/cargo-vendor" vendor \
    "$((MAX_VENDOR_MEMBERS + 100))" \
    "$((MAX_VENDOR_EXPANDED_BYTES + 16 * 1024 * 1024))" \
    "${result_dir}/guest-vendor-manifest-post-lockdown.json"
  verify_guest_tree_manifest \
    "${result_dir}/guest-vendor-manifest-baseline.json" \
    "${result_dir}/guest-vendor-manifest-post-lockdown.json" vendor \
    || die 1 'guest vendor tree drifted during the reboot/lockdown experiment'
  capture_guest_cargo_config_binding "${clone_orb_id}" \
    "${guest_cargo_home}" "${vendor_config_hash}" \
    "${result_dir}/guest-cargo-config-post-lockdown.json"
  verify_guest_cargo_config_binding \
    "${result_dir}/guest-cargo-config-baseline.json" \
    "${result_dir}/guest-cargo-config-post-lockdown.json" \
    || die 1 'private guest Cargo config drifted during the reboot/lockdown experiment'
  verify_provenance_manifest "${repo_root}" \
    "${result_dir}/source-provenance-before.sha256" \
    "${result_dir}/source-provenance-post-lockdown.sha256" \
    || die 1 'host source/unit/harness changed during the reboot/lockdown experiment'
  capture_git_checkout_proof "${repo_root}" \
    "${result_dir}/git-checkout-post-lockdown" "${pinned_head}" \
    || die 1 'host checkout or pushed origin/main changed during the reboot/lockdown experiment'
  guest_status=valid

  say 'testing the exact installed client unit under real systemd PID 1'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/guest-source-client-unit.sha256" \
    orb -m "${clone_orb_id}" -u root sha256sum "${guest_client_unit}"
  # The single-quoted install program is evaluated by the guest shell.
  # shellcheck disable=SC2016
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/install-client-unit.log" \
    orb -m "${clone_orb_id}" -u root sh -ceu \
    'install -m 0644 -- "$1" /etc/systemd/system/shadowpipe-client-full-tunnel.service' \
    _ "${guest_client_unit}"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/install-client-fixture.env" \
    orb -m "${clone_orb_id}" -u root python3 -I -S -c '
import os
import stat

root = "/etc/shadowpipe"
if os.path.lexists(root):
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise SystemExit("client fixture root is unsafe")
    if info.st_uid != 0 or info.st_gid != 0:
        raise SystemExit("client fixture root is not root-owned")
else:
    os.mkdir(root, 0o700)
os.chmod(root, 0o700)
credential = os.path.join(root, "client-credential.json")
environment = os.path.join(root, "client.env")
fixture = {
    credential: b"{}\n",
    environment: (
        b"SHADOWPIPE_CLIENT_ARGS="
        b"--client-credential /etc/shadowpipe/client-credential.json "
        b"--server 192.0.2.1:443 "
        b"--server-fp 0000000000000000000000000000000000000000000000000000000000000000 "
        b"--tunnel --ipv6-mode block --auto-route --kill-switch "
        b"--dns 10.8.0.1 --host-state-dir /var/lib/shadowpipe\n"
    ),
}
for path, body in fixture.items():
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, body)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    info = os.lstat(path)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise SystemExit("client fixture file metadata differs")
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
print("fixture_credential=empty_json_nonsecret")
print("fixture_credential_mode=0600")
print("fixture_environment_mode=0600")
print("expected_failure=mandatory_root_owned_credential_loader")
print("expected_mutation_boundary=before_host_lease_wal_tun_socket_route_dns_nft")
'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/client-systemd-reload.log" \
    orb -m "${clone_orb_id}" -u root systemctl daemon-reload
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/client-systemd-verify.txt" \
    orb -m "${clone_orb_id}" -u root systemd-analyze verify \
    /etc/systemd/system/shadowpipe-lockdown-restore.service \
    /etc/systemd/system/shadowpipe-client-full-tunnel.service
  capture_effective_unit_definition "${clone_orb_id}" \
    shadowpipe-client-full-tunnel.service \
    "${result_dir}/client-effective-definition-pre-start.txt"
  verify_effective_unit_definition \
    "${result_dir}/client-effective-definition-pre-start.txt" client
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/installed-client-unit.sha256" \
    orb -m "${clone_orb_id}" -u root sha256sum \
    /etc/systemd/system/shadowpipe-client-full-tunnel.service
  run_recorded "${HOST_COMMAND_TIMEOUT}" \
    "${result_dir}/source-client-unit.sha256" \
    sha256sum "${repo_root}/deploy/shadowpipe-client-full-tunnel.service"
  verify_same_digest "${result_dir}/source-client-unit.sha256" \
    "${result_dir}/guest-source-client-unit.sha256"
  verify_same_digest "${result_dir}/source-client-unit.sha256" \
    "${result_dir}/installed-client-unit.sha256"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/client-systemd-enable.txt" \
    orb -m "${clone_orb_id}" -u root systemctl enable \
    shadowpipe-client-full-tunnel.service
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/client-systemd-is-enabled.txt" \
    orb -m "${clone_orb_id}" -u root env LC_ALL=C systemctl is-enabled \
    shadowpipe-client-full-tunnel.service
  [[ "$(<"${result_dir}/client-systemd-is-enabled.txt")" == enabled ]] \
    || die 1 'client unit is not enabled'

  capture_guest_client_network_state "${clone_orb_id}" \
    "${result_dir}/client-network-state-baseline.json" \
    || die 1 'could not capture the post-release client-unit baseline'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/client-systemd-reset-failed.txt" \
    orb -m "${clone_orb_id}" -u root systemctl reset-failed \
    shadowpipe-client-full-tunnel.service
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/client-systemd-start.txt" \
    orb -m "${clone_orb_id}" -u root systemctl start --no-block \
    shadowpipe-client-full-tunnel.service
  capture_client_unit_loop "${clone_orb_id}" \
    "${result_dir}/client-systemd-loop.json" \
    || die 1 'client unit did not enter the bounded credential-refusal restart loop'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/client-systemd-stop.txt" \
    orb -m "${clone_orb_id}" -u root systemctl stop \
    shadowpipe-client-full-tunnel.service
  capture_client_unit_status "${clone_orb_id}" \
    "${result_dir}/client-systemd-stopped.txt"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/client-journal-stopped.jsonl" \
    orb -m "${clone_orb_id}" -u root env LC_ALL=C journalctl -b \
    -u shadowpipe-client-full-tunnel.service --no-pager -o json
  run_recorded 10 "${result_dir}/client-restart-stability-wait.env" \
    orb -m "${clone_orb_id}" -u root python3 -I -S -c '
import time
start = time.monotonic()
time.sleep(2.25)
print(f"stable_wait_seconds={time.monotonic() - start:.6f}")
'
  capture_client_unit_status "${clone_orb_id}" \
    "${result_dir}/client-systemd-stable.txt"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/client-journal-stable.jsonl" \
    orb -m "${clone_orb_id}" -u root env LC_ALL=C journalctl -b \
    -u shadowpipe-client-full-tunnel.service --no-pager -o json
  capture_guest_client_network_state "${clone_orb_id}" \
    "${result_dir}/client-network-state-final.json" \
    || die 1 'could not capture the post-stop client-unit state'
  verify_client_unit_evidence \
    "${result_dir}/client-systemd-loop.json" \
    "${result_dir}/client-systemd-stopped.txt" \
    "${result_dir}/client-systemd-stable.txt" \
    "${result_dir}/client-journal-stopped.jsonl" \
    "${result_dir}/client-journal-stable.jsonl" \
    "${result_dir}/client-systemd-is-enabled.txt" \
    "${result_dir}/client-network-state-baseline.json" \
    "${result_dir}/client-network-state-final.json" \
    "${result_dir}/client-restart-stability-wait.env" \
    || die 1 'installed client-unit lifecycle evidence is invalid'

  capture_guest_tree_manifest "${clone_orb_id}" "${guest_repo}" source \
    20000 "${MAX_SOURCE_EXPANDED_BYTES}" \
    "${result_dir}/guest-source-manifest-final.json"
  verify_guest_tree_manifest \
    "${result_dir}/guest-source-manifest-baseline.json" \
    "${result_dir}/guest-source-manifest-final.json" source \
    || die 1 'guest source tree drifted during the client-unit subcell'
  capture_guest_tree_manifest "${clone_orb_id}" \
    "${guest_root}/cargo-vendor" vendor \
    "$((MAX_VENDOR_MEMBERS + 100))" \
    "$((MAX_VENDOR_EXPANDED_BYTES + 16 * 1024 * 1024))" \
    "${result_dir}/guest-vendor-manifest-final.json"
  verify_guest_tree_manifest \
    "${result_dir}/guest-vendor-manifest-baseline.json" \
    "${result_dir}/guest-vendor-manifest-final.json" vendor \
    || die 1 'guest vendor tree drifted during the client-unit subcell'
  capture_guest_cargo_config_binding "${clone_orb_id}" \
    "${guest_cargo_home}" "${vendor_config_hash}" \
    "${result_dir}/guest-cargo-config-final.json"
  verify_guest_cargo_config_binding \
    "${result_dir}/guest-cargo-config-baseline.json" \
    "${result_dir}/guest-cargo-config-final.json" \
    || die 1 'private guest Cargo config drifted during the client-unit subcell'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/installed-binary-final.sha256" \
    orb -m "${clone_orb_id}" -u root sha256sum \
    /usr/local/bin/shadowpipe-client
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/installed-restore-unit-final.sha256" \
    orb -m "${clone_orb_id}" -u root sha256sum \
    /etc/systemd/system/shadowpipe-lockdown-restore.service
  run_recorded "${GUEST_COMMAND_TIMEOUT}" \
    "${result_dir}/installed-client-unit-final.sha256" \
    orb -m "${clone_orb_id}" -u root sha256sum \
    /etc/systemd/system/shadowpipe-client-full-tunnel.service
  verify_same_digest "${result_dir}/built-binary.sha256" \
    "${result_dir}/installed-binary-final.sha256"
  verify_same_digest "${result_dir}/source-unit.sha256" \
    "${result_dir}/installed-restore-unit-final.sha256"
  verify_same_digest "${result_dir}/source-client-unit.sha256" \
    "${result_dir}/installed-client-unit-final.sha256"
  client_unit_status=valid

  verify_provenance_manifest "${repo_root}" \
    "${result_dir}/source-provenance-before.sha256" \
    "${result_dir}/source-provenance-final.sha256" \
    || die 1 'source/unit/harness/Cargo.lock changed during the userspace restart experiment'
  capture_git_checkout_proof "${repo_root}" \
    "${result_dir}/git-checkout-final" "${pinned_head}" \
    || die 1 'host checkout or pushed origin/main changed during the experiment'

  guest_status=valid
  final_status=0
  cleanup
}

run_self_test() (
  set -Eeuo pipefail
  local temporary parent token owned table status child_pid scope_probe_path
  local self_source normalizer normalization_root raw normalized
  local symlink_root intermediate_symlink_root
  local child_gone=0
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/shadowpipe-reboot-selftest.XXXXXX")"
  temporary="$(cd -- "${temporary}" && pwd -P)"
  parent="$(cd -- "$(dirname -- "${temporary}")" && pwd -P)"
  token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  write_ownership_marker "${temporary}" "${token}"
  trap 'safe_remove_owned_tree "${temporary}" "${parent}" "${token}" >/dev/null' EXIT

  scope_probe_path="${temporary}/cleanup-scope-probe.txt"
  set +e
  (
    set -Eeuo pipefail
    result_dir=cleanup-context-survived
    cleanup_scope_probe_output="${scope_probe_path}"
    implicit_main_failure() {
      local result_dir=unwound-main-local
      # Invoked indirectly by the EXIT trap after this function unwinds.
      # shellcheck disable=SC2329
      cleanup_scope_exit() {
        printf '%s\n' "${result_dir}" >"${cleanup_scope_probe_output}"
      }
      trap cleanup_scope_exit EXIT
      return 23
    }
    implicit_main_failure
  ) >"${temporary}/cleanup-scope-probe.stdout" \
    2>"${temporary}/cleanup-scope-probe.stderr"
  status=$?
  set -e
  [[ "${status}" == 23 \
    && "$(<"${scope_probe_path}")" == cleanup-context-survived \
    && ! -s "${temporary}/cleanup-scope-probe.stderr" ]] \
    || die 1 'self-test cleanup context did not survive main-scope unwind'

  self_source="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/$(basename -- "${BASH_SOURCE[0]}")"
  verify_cleanup_context_global_contract "${self_source}" \
    >"${temporary}/cleanup-context-contract.env"
  grep -qx 'cleanup_context_process_global=true' \
    "${temporary}/cleanup-context-contract.env"
  grep -qx 'cleanup_context_names=29' \
    "${temporary}/cleanup-context-contract.env"
  verify_systemctl_show_all_contract "${self_source}" \
    >"${temporary}/systemctl-show-all-contract.env"
  grep -qx 'systemctl_show_all_shell_collectors=0' \
    "${temporary}/systemctl-show-all-contract.env"
  grep -qx 'systemctl_show_all_embedded_collectors=2' \
    "${temporary}/systemctl-show-all-contract.env"

  normalizer="$(cd -- "$(dirname -- "${self_source}")" && pwd -P)/normalize-built-artifact.py"
  [[ -f "${normalizer}" && ! -L "${normalizer}" ]] \
    || die 1 'self-test artifact normalizer is absent or symlinked'
  normalization_root="${temporary}/normalizer-fixture"
  mkdir -p -- \
    "${normalization_root}/cargo-home" "${normalization_root}/target"
  printf '%s\n' '[source.crates-io]' \
    >"${normalization_root}/cargo-home/config.toml"
  raw="${normalization_root}/target/shadowpipe-client"
  normalized="${normalization_root}/artifact/shadowpipe-client"
  printf '%s\n' '#!/bin/sh' 'exit 0' >"${raw}"
  chmod 0755 "${raw}"
  ln "${raw}" "${normalization_root}/target/cargo-hardlink-peer"
  run_recorded 10 "${temporary}/normalizer-hardlink.env" \
    python3 -I -S "${normalizer}" \
    "${normalization_root}/cargo-home" "${normalization_root}/target" \
    "${raw}" "${normalized}" \
    || die 1 'self-test normalizer rejected a valid Cargo hardlink'
  grep -qx 'cargo_artifact_source_nlink=2' \
    "${temporary}/normalizer-hardlink.env"
  grep -qx 'normalized_artifact_nlink=1' \
    "${temporary}/normalizer-hardlink.env"
  grep -qx 'normalized_artifact_mode=0755' \
    "${temporary}/normalizer-hardlink.env"
  python3 -I -S - "${raw}" "${normalized}" <<'PY'
import os
import stat
import sys

raw, normalized = sys.argv[1:]
with open(raw, "rb") as stream:
    raw_bytes = stream.read()
with open(normalized, "rb") as stream:
    normalized_bytes = stream.read()
raw_info = os.lstat(raw)
normalized_info = os.lstat(normalized)
if raw_bytes != normalized_bytes:
    raise SystemExit("normalized artifact bytes differ")
if raw_info.st_nlink != 2:
    raise SystemExit("self-test did not create a two-link Cargo fixture")
if (
    not stat.S_ISREG(normalized_info.st_mode)
    or normalized_info.st_nlink != 1
    or stat.S_IMODE(normalized_info.st_mode) != 0o755
    or normalized_info.st_uid != os.geteuid()
    or normalized_info.st_gid != os.getegid()
):
    raise SystemExit("normalized hardlink fixture metadata differs")
PY
  symlink_root="${temporary}/normalizer-symlink-fixture"
  mkdir -p -- "${symlink_root}/cargo-home" "${symlink_root}/target"
  printf '%s\n' '[source.crates-io]' \
    >"${symlink_root}/cargo-home/config.toml"
  printf '%s\n' '#!/bin/sh' 'exit 0' \
    >"${symlink_root}/target/shadowpipe-client"
  chmod 0755 "${symlink_root}/target/shadowpipe-client"
  ln -s shadowpipe-client "${symlink_root}/target/linked-client"
  if run_recorded 10 "${temporary}/normalizer-symlink.env" \
    python3 -I -S "${normalizer}" \
    "${symlink_root}/cargo-home" "${symlink_root}/target" \
    "${symlink_root}/target/linked-client" \
    "${symlink_root}/artifact/linked-client"; then
    die 1 'self-test normalizer followed a symlinked Cargo artifact'
  fi
  [[ "$(<"${temporary}/normalizer-symlink.env.status")" != 124 ]] \
    || die 1 'self-test normalizer symlink denial timed out'

  intermediate_symlink_root="${temporary}/normalizer-intermediate-symlink-fixture"
  mkdir -p -- \
    "${intermediate_symlink_root}/cargo-home" \
    "${intermediate_symlink_root}/target" \
    "${intermediate_symlink_root}/outside"
  printf '%s\n' '[source.crates-io]' \
    >"${intermediate_symlink_root}/cargo-home/config.toml"
  printf '%s\n' '#!/bin/sh' 'exit 0' \
    >"${intermediate_symlink_root}/outside/shadowpipe-client"
  chmod 0755 "${intermediate_symlink_root}/outside/shadowpipe-client"
  ln -s ../outside "${intermediate_symlink_root}/target/release"
  if run_recorded 10 "${temporary}/normalizer-intermediate-symlink.env" \
    python3 -I -S "${normalizer}" \
    "${intermediate_symlink_root}/cargo-home" \
    "${intermediate_symlink_root}/target" \
    "${intermediate_symlink_root}/target/release/shadowpipe-client" \
    "${intermediate_symlink_root}/artifact/shadowpipe-client"; then
    die 1 'self-test normalizer followed an intermediate target symlink'
  fi
  [[ "$(<"${temporary}/normalizer-intermediate-symlink.env.status")" != 124 ]] \
    || die 1 'self-test normalizer intermediate-symlink denial timed out'

  [[ "$(sanitize_component arch.test-1)" == arch.test-1 ]]
  if sanitize_component '../arch' >"${temporary}/unsafe-name.out" 2>"${temporary}/unsafe-name.err"; then
    die 1 'self-test accepted an unsafe VM component'
  fi
  validate_source_vm shadowpipe-lab-base
  if validate_source_vm arch; then
    die 1 'self-test accepted the legacy arch source VM'
  fi
  printf '%s\n' \
    '{"record":{"id":"opaque-A","name":"sphr-lock-fixture","state":"stopped","config":{"isolated":true,"isolate_network":true,"forward_ssh_agent":false,"http_port":0,"https_port":0,"mounts":[]},"future":true},"future_root":1}' \
    >"${temporary}/orb-info.json"
  [[ "$(parse_orb_info_identity "${temporary}/orb-info.json" \
    sphr-lock-fixture opaque-A stopped "${temporary}/orb-identity.json")" \
    == opaque-A ]]
  grep -qx \
    '{"forward_ssh_agent":false,"http_port":0,"https_port":0,"id":"opaque-A","isolate_network":true,"isolated":true,"mounts_and_forwards":"empty","name":"sphr-lock-fixture","schema_version":1,"state":"stopped"}' \
    "${temporary}/orb-identity.json"
  printf '%s\n' \
    '{"record":{"id":"opaque-A","name":"sphr-lock-fixture","state":"stopped","config":{"isolated":false,"isolate_network":false,"forward_ssh_agent":true,"http_port":0,"https_port":0}}}' \
    >"${temporary}/orb-info-legacy.json"
  if parse_orb_info_identity "${temporary}/orb-info-legacy.json" \
    sphr-lock-fixture opaque-A stopped "${temporary}/orb-identity-legacy.json" \
    >/dev/null 2>&1; then
    die 1 'self-test accepted a legacy non-isolated OrbStack profile'
  fi
  printf '%s\n' \
    '{"record":{"id":"opaque-A","name":"sphr-lock-fixture","state":"stopped","config":{"isolated":true,"isolate_network":true,"forward_ssh_agent":false,"http_port":0,"https_port":0,"mounts":["/Users"]}}}' \
    >"${temporary}/orb-info-mounted.json"
  if parse_orb_info_identity "${temporary}/orb-info-mounted.json" \
    sphr-lock-fixture opaque-A stopped "${temporary}/orb-identity-mounted.json" \
    >/dev/null 2>&1; then
    die 1 'self-test accepted an OrbStack host mount'
  fi
  printf '%s\n' \
    '{"record":{"id":"opaque-A","id":"opaque-B","name":"sphr-lock-fixture","state":"stopped"}}' \
    >"${temporary}/orb-info-duplicate.json"
  if parse_orb_info_identity "${temporary}/orb-info-duplicate.json" \
    sphr-lock-fixture '' stopped "${temporary}/orb-identity-duplicate.json" \
    >/dev/null 2>&1; then
    die 1 'self-test accepted duplicate OrbStack JSON members'
  fi
  if parse_orb_info_identity "${temporary}/orb-info.json" \
    sphr-lock-fixture opaque-B stopped "${temporary}/orb-identity-reuse.json" \
    >/dev/null 2>&1; then
    die 1 'self-test accepted OrbStack name reuse with a different ID'
  fi
  set +e
  # shellcheck disable=SC2016
  run_bounded 0.1 /bin/bash -c \
    'trap "exit 0" TERM; (trap "" TERM HUP; sleep 30) & printf "%s\n" "$!" >"$1"; wait' \
    _ "${temporary}/bounded-child.pid" \
    >"${temporary}/timeout.out" 2>"${temporary}/timeout.err"
  status=$?
  set -e
  [[ "${status}" == 124 ]] \
    || die 1 'self-test bounded process group did not reach a clean timeout'
  IFS= read -r child_pid <"${temporary}/bounded-child.pid"
  [[ "${child_pid}" =~ ^[1-9][0-9]*$ ]] \
    || die 1 'self-test did not record the TERM-resistant descendant'
  for _ in {1..20}; do
    if ! kill -0 "${child_pid}" 2>/dev/null; then
      child_gone=1
      break
    fi
    run_bounded 1 sleep 0.05 >/dev/null 2>&1 || true
  done
  [[ "${child_gone}" == 1 ]] \
    || die 1 'self-test left a TERM-resistant process-group descendant'
  set +e
  run_recorded_limited 5 "${temporary}/recorded-stdout-cap" 32 32 \
    python3 -I -S -c 'import sys; sys.stdout.write("x" * 4096)'
  status=$?
  set -e
  [[ "${status}" == 125 \
    && "$(file_size_bytes "${temporary}/recorded-stdout-cap")" == 33 \
    && "$(file_size_bytes \
      "${temporary}/recorded-stdout-cap.stderr")" -le 32 ]] \
    || die 1 'self-test did not fail closed at the recorded stdout byte cap'
  set +e
  run_recorded_limited 5 "${temporary}/recorded-stderr-cap" 32 32 \
    python3 -I -S -c 'import sys; sys.stderr.write("y" * 4096)'
  status=$?
  set -e
  [[ "${status}" == 125 \
    && "$(file_size_bytes "${temporary}/recorded-stderr-cap")" -le 32 \
    && "$(file_size_bytes \
      "${temporary}/recorded-stderr-cap.stderr")" == 33 ]] \
    || die 1 'self-test did not fail closed at the recorded stderr byte cap'
  if find "${temporary}" -maxdepth 1 -name '*.pipes.*' -print -quit \
    | grep -q .; then
    die 1 'self-test left a recorded-command FIFO directory'
  fi
  printf '%s\n' bounded-stdin-fixture >"${temporary}/bounded-stdin.in"
  run_recorded_with_stdin 5 "${temporary}/bounded-stdin.out" \
    "${temporary}/bounded-stdin.in" /bin/sh -c 'cat'
  cmp -s "${temporary}/bounded-stdin.in" "${temporary}/bounded-stdin.out"

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
    die 1 'self-test accepted a late clone appearance'
  fi
  printf '1\tabsent\tstopped\n2\tabsent\trunning\n3\tabsent\tstopped\n4\tabsent\tstopped\n' \
    >"${temporary}/quiescence.tsv"
  if validate_clone_quiescence_trace \
    "${temporary}/quiescence.tsv" 4 absent_all; then
    die 1 'self-test accepted a source VM state transition'
  fi
  validate_magic "${MAGIC_DEFAULT}"
  if validate_magic 4294967296 2>/dev/null; then
    die 1 'self-test accepted a SHADOWPIPE_MAGIC value above u32'
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
    die 1 'self-test accepted a foreign sing-box argv'
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
    die 1 'self-test accepted a non-absolute mocked proc_pidpath result'
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
    die 1 'self-test accepted an unrecognized PF observation outcome'
  fi

  owned="${temporary}/owned"
  mkdir -- "${owned}"
  write_ownership_marker "${owned}" "${token}"
  [[ "$(canonical_owned_tree "${owned}" "${temporary}" "${token}")" == "${owned}" ]]
  printf '%s\n' wrong >"${owned}/${OWNERSHIP_MARKER}"
  if canonical_owned_tree "${owned}" "${temporary}" "${token}" \
    >"${temporary}/tampered-owner.out" 2>"${temporary}/tampered-owner.err"; then
    die 1 'self-test accepted a tampered ownership marker'
  fi
  printf '%s\n' "${token}" >"${owned}/${OWNERSHIP_MARKER}"
  mkdir "${temporary}/symlink-marker"
  ln -s /dev/null "${temporary}/symlink-marker/${OWNERSHIP_MARKER}"
  if write_ownership_marker "${temporary}/symlink-marker" "${token}" \
    2>/dev/null; then
    die 1 'self-test followed or replaced a pre-existing ownership-marker symlink'
  fi

  printf '%s\n' 11111111-2222-3333-4444-555555555555 \
    >"${temporary}/boot.txt"
  printf '%s\n' \
    'state_dir:700:0:0:directory' \
    'wal:600:0:0:1:regular' \
    'possible_main:600:0:0:1:regular:0' \
    'network_namespace:5:100' \
    'mount_namespace:5:101' \
    >"${temporary}/state-metadata.txt"
  verify_guest_state_metadata "${temporary}/state-metadata.txt"
  python3 -I -S - "${temporary}" <<'PY'
import json
import os
import sys

root = sys.argv[1]
identity = "b" * 32
owner = "shadowpipe-lockdown-v1:" + identity
table = "sp_lock_" + identity
wal = {
    "schema_version": 1,
    "generation": 2,
    "identity": identity,
    "boot_id": "11111111222233334444555555555555",
    "uid": 0,
    "network_namespace": {"device": 5, "inode": 100},
    "mount_namespace": {"device": 5, "inode": 101},
    "control_flow": None,
    "phase": "active",
    "table_handle": 7,
    "release_reason": None,
}
listing = {
    "nftables": [
        {"metainfo": {}},
        {"table": {
            "family": "inet", "name": table, "handle": 7, "comment": owner,
        }},
        {"chain": {
            "family": "inet", "table": table, "name": "sp_output",
            "handle": 8, "type": "filter", "hook": "output", "prio": -400,
            "policy": "drop", "comment": owner + ":chain",
        }},
        {"rule": {
            "family": "inet", "table": table, "chain": "sp_output", "handle": 9,
            "expr": [
                {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}},
                {"accept": None},
            ],
            "comment": owner + ":loopback",
        }},
        {"rule": {
            "family": "inet", "table": table, "chain": "sp_output", "handle": 10,
            "expr": [{"drop": None}], "comment": owner + ":terminal-drop",
        }},
    ]
}
census = {"nftables": [{"metainfo": {}}, {"table": {"family": "inet", "name": table}}]}
for name, value in (("wal.json", wal), ("nft.json", listing), ("census.json", census)):
    with open(os.path.join(root, name), "x", encoding="utf-8") as stream:
        json.dump(value, stream, separators=(",", ":"))
        stream.write("\n")
tampered_wal = dict(wal)
tampered_wal["generation"] = 3
with open(os.path.join(root, "wal-tampered.json"), "x", encoding="utf-8") as stream:
    json.dump(tampered_wal, stream, separators=(",", ":"))
    stream.write("\n")
listing["nftables"][1]["table"]["comment"] = "foreign"
with open(os.path.join(root, "nft-tampered.json"), "x", encoding="utf-8") as stream:
    json.dump(listing, stream, separators=(",", ":"))
    stream.write("\n")
PY
  table="$(wal_table_name "${temporary}/wal.json" "${temporary}/boot.txt" 2 \
    "${temporary}/state-metadata.txt" \
    2>"${temporary}/wal-handle.txt")"
  [[ "${table}" == sp_lock_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ]]
  [[ "$(<"${temporary}/wal-handle.txt")" == 7 ]]
  if wal_table_name "${temporary}/wal-tampered.json" "${temporary}/boot.txt" 2 \
    "${temporary}/state-metadata.txt" \
    >"${temporary}/tampered-wal.out" 2>"${temporary}/tampered-wal.err"; then
    die 1 'self-test accepted a WAL generation mismatch'
  fi
  verify_nft_snapshot "${temporary}/wal.json" "${temporary}/nft.json" \
    "${temporary}/census.json" -
  if verify_nft_snapshot "${temporary}/wal.json" "${temporary}/nft-tampered.json" \
    "${temporary}/census.json" - \
    >"${temporary}/tampered-nft.out" 2>"${temporary}/tampered-nft.err"; then
    die 1 'self-test accepted a drifted nft table'
  fi

  printf '%s\n' \
    'pid=1' \
    'comm=systemd' \
    'exe=/usr/lib/systemd/systemd' \
    'status_name=systemd' \
    'ppid=0' \
    'pid1_start_ticks=10' \
    'manager_version=261.1-1-arch' \
    'boot_id=11111111-2222-3333-4444-555555555555' \
    'machine_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    'kernel_release=7.0.11-orbstack-test' \
    'pid_namespace=5:100' \
    'network_namespace=5:101' \
    'mount_namespace=5:102' \
    >"${temporary}/pid1-pre.env"
  printf '%s\n' \
    'pid=1' \
    'comm=systemd' \
    'exe=/usr/lib/systemd/systemd' \
    'status_name=systemd' \
    'ppid=0' \
    'pid1_start_ticks=20' \
    'manager_version=261.1-1-arch' \
    'boot_id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' \
    'machine_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    'kernel_release=7.0.11-orbstack-test' \
    'pid_namespace=5:200' \
    'network_namespace=5:201' \
    'mount_namespace=5:102' \
    >"${temporary}/pid1-post.env"
  verify_pid1_systemd_proof "${temporary}/pid1-pre.env"
  verify_pid1_systemd_proof "${temporary}/pid1-post.env"
  verify_userspace_restart_transition \
    "${temporary}/pid1-pre.env" "${temporary}/pid1-post.env" \
    "${temporary}/userspace-restart.env"
  grep -qx 'userspace_systemd_boot_transaction=valid' \
    "${temporary}/userspace-restart.env"
  grep -qx 'mount_namespace_changed=false' \
    "${temporary}/userspace-restart.env"
  sed 's/comm=systemd/comm=init/' "${temporary}/pid1-pre.env" \
    >"${temporary}/pid1-invalid.env"
  if verify_pid1_systemd_proof "${temporary}/pid1-invalid.env" \
    >"${temporary}/pid1-invalid.out" 2>"${temporary}/pid1-invalid.err"; then
    die 1 'self-test accepted a non-systemd PID 1 proof'
  fi
  sed \
    's/boot_id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/boot_id=11111111-2222-3333-4444-555555555555/' \
    "${temporary}/pid1-post.env" >"${temporary}/pid1-same-boot.env"
  if verify_userspace_restart_transition \
    "${temporary}/pid1-pre.env" "${temporary}/pid1-same-boot.env" \
    "${temporary}/userspace-same-boot.env" \
    >"${temporary}/same-boot.out" 2>"${temporary}/same-boot.err"; then
    die 1 'self-test accepted an unchanged guest boot identity'
  fi
  sed 's/network_namespace=5:201/network_namespace=5:101/' \
    "${temporary}/pid1-post.env" >"${temporary}/pid1-same-netns.env"
  if verify_userspace_restart_transition \
    "${temporary}/pid1-pre.env" "${temporary}/pid1-same-netns.env" \
    "${temporary}/userspace-same-netns.env" \
    >"${temporary}/same-netns.out" 2>"${temporary}/same-netns.err"; then
    die 1 'self-test accepted an unchanged guest network namespace'
  fi

  printf '%s\n' \
    'source_archive=git_archive' \
    'pinned_head=1111111111111111111111111111111111111111' \
    'source_archive_bytes=4096' \
    'source_archive_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    >"${temporary}/source-archive.env"
  [[ "$(source_archive_field \
    "${temporary}/source-archive.env" source_archive_bytes)" == 4096 ]]
  printf '%s\n' 'source_archive_bytes=1' \
    >>"${temporary}/source-archive.env"
  if source_archive_field "${temporary}/source-archive.env" \
    source_archive_bytes >"${temporary}/duplicate-field.out" \
    2>"${temporary}/duplicate-field.err"; then
    die 1 'self-test accepted duplicate source archive metadata'
  fi
  mkdir "${temporary}/git-fixture"
  git -C "${temporary}/git-fixture" init -q
  git -C "${temporary}/git-fixture" config user.name shadowpipe-selftest
  git -C "${temporary}/git-fixture" config user.email selftest@invalid
  git -C "${temporary}/git-fixture" config commit.gpgsign false
  git -C "${temporary}/git-fixture" config push.gpgSign false
  git -C "${temporary}/git-fixture" config protocol.file.allow always
  printf '%s\n' pinned-source-fixture \
    >"${temporary}/git-fixture/input.txt"
  git -C "${temporary}/git-fixture" add input.txt
  git -C "${temporary}/git-fixture" commit -q -m fixture
  git -C "${temporary}/git-fixture" branch -M main
  git init -q --bare "${temporary}/git-origin.git"
  git -C "${temporary}/git-fixture" remote add origin \
    "${temporary}/git-origin.git"
  git -C "${temporary}/git-fixture" push -q -u origin main
  local fixture_head
  fixture_head="$(git -C "${temporary}/git-fixture" rev-parse HEAD)"
  capture_git_checkout_proof "${temporary}/git-fixture" \
    "${temporary}/git-checkout-proof"
  [[ "$(<"${temporary}/git-checkout-proof/head.txt")" == "${fixture_head}" ]]
  local fixture_git_dir replacement_commit
  fixture_git_dir="$(
    git -C "${temporary}/git-fixture" rev-parse --absolute-git-dir
  )"
  replacement_commit="$(
    git -C "${temporary}/git-fixture" commit-tree \
      "${fixture_head}^{tree}" -p "${fixture_head}" -m replacement
  )"
  git -C "${temporary}/git-fixture" replace \
    "${fixture_head}" "${replacement_commit}"
  if capture_git_checkout_proof "${temporary}/git-fixture" \
    "${temporary}/git-checkout-replace-ref" \
    >"${temporary}/git-checkout-replace-ref.out" \
    2>"${temporary}/git-checkout-replace-ref.err"; then
    die 1 'self-test accepted a Git replacement ref'
  fi
  git -C "${temporary}/git-fixture" replace -d "${fixture_head}" \
    >/dev/null
  printf '%s\n' 'input.txt export-ignore' \
    >"${fixture_git_dir}/info/attributes"
  if capture_git_checkout_proof "${temporary}/git-fixture" \
    "${temporary}/git-checkout-info-attributes" \
    >"${temporary}/git-checkout-info-attributes.out" \
    2>"${temporary}/git-checkout-info-attributes.err"; then
    die 1 'self-test accepted Git info/attributes'
  fi
  rm -- "${fixture_git_dir}/info/attributes"
  git -C "${temporary}/git-fixture" worktree add --detach \
    "${temporary}/git-linked-worktree" "${fixture_head}" \
    >/dev/null 2>&1
  printf '%s\n' 'input.txt export-ignore' \
    >"${fixture_git_dir}/info/attributes"
  if validate_git_metadata_safety \
    "${temporary}/git-linked-worktree" \
    "${temporary}/git-linked-common-attributes.json" \
    "${fixture_head}" \
    >"${temporary}/git-linked-common-attributes.out" \
    2>"${temporary}/git-linked-common-attributes.err"; then
    die 1 'self-test accepted common-dir attributes from a linked worktree'
  fi
  rm -- "${fixture_git_dir}/info/attributes"
  git -C "${temporary}/git-fixture" worktree remove --force \
    "${temporary}/git-linked-worktree"
  : >"${fixture_git_dir}/info/grafts"
  if capture_git_checkout_proof "${temporary}/git-fixture" \
    "${temporary}/git-checkout-info-grafts" \
    >"${temporary}/git-checkout-info-grafts.out" \
    2>"${temporary}/git-checkout-info-grafts.err"; then
    die 1 'self-test accepted Git info/grafts'
  fi
  rm -- "${fixture_git_dir}/info/grafts"
  git -C "${temporary}/git-fixture" config \
    core.attributesFile /dev/null
  if capture_git_checkout_proof "${temporary}/git-fixture" \
    "${temporary}/git-checkout-core-attributes" \
    >"${temporary}/git-checkout-core-attributes.out" \
    2>"${temporary}/git-checkout-core-attributes.err"; then
    die 1 'self-test accepted a local core.attributesFile override'
  fi
  git -C "${temporary}/git-fixture" config --unset-all \
    core.attributesFile
  if GIT_CONFIG_COUNT=0 capture_git_checkout_proof \
    "${temporary}/git-fixture" \
    "${temporary}/git-checkout-ambient-config" \
    >"${temporary}/git-checkout-ambient-config.out" \
  2>"${temporary}/git-checkout-ambient-config.err"; then
    die 1 'self-test accepted an ambient Git config override'
  fi
  if GIT_ATTR_NOSYSTEM=0 capture_git_checkout_proof \
    "${temporary}/git-fixture" \
    "${temporary}/git-checkout-ambient-attributes" \
    >"${temporary}/git-checkout-ambient-attributes.out" \
    2>"${temporary}/git-checkout-ambient-attributes.err"; then
    die 1 'self-test accepted an ambient Git system-attributes override'
  fi
  printf '%s\n' dirty >"${temporary}/git-fixture/untracked.txt"
  if capture_git_checkout_proof "${temporary}/git-fixture" \
    "${temporary}/git-checkout-dirty" \
    >"${temporary}/git-checkout-dirty.out" \
    2>"${temporary}/git-checkout-dirty.err"; then
    die 1 'self-test accepted an untracked source file'
  fi
  rm "${temporary}/git-fixture/untracked.txt"
  set +e
  run_recorded_limited 5 "${temporary}/git-oversize.tar" 512 512 \
    git -C "${temporary}/git-fixture" archive --format=tar \
    --prefix=shadowpipe/ "${fixture_head}"
  status=$?
  set -e
  [[ "${status}" == 125 \
    && "$(file_size_bytes "${temporary}/git-oversize.tar")" == 513 \
    && "$(file_size_bytes "${temporary}/git-oversize.tar.stderr")" -le 512 ]] \
    || die 1 'self-test did not byte-bound an oversized git archive'
  create_pinned_source_archive "${temporary}/git-fixture" "${fixture_head}" \
    "${temporary}/git-fixture.tar" "${temporary}/git-fixture-archive.env"
  [[ "$(source_archive_field \
    "${temporary}/git-fixture-archive.env" pinned_head)" == "${fixture_head}" ]]
  [[ "$(git -C "${temporary}/git-fixture" get-tar-commit-id \
    <"${temporary}/git-fixture.tar")" == "${fixture_head}" ]]
  if find "${temporary}" -name '*.pipes.*' -print -quit | grep -q .; then
    die 1 'self-test left a source-archive FIFO directory'
  fi

  mkdir -m 0700 "${temporary}/cargo-home-fixture"
  if CARGO_REGISTRIES_CRATES_IO_INDEX=https://invalid.example \
    validate_host_cargo_boundary "${temporary}/cargo-home-fixture" \
      "${temporary}/cargo-boundary-ambient.env" \
      >"${temporary}/cargo-boundary-ambient.out" \
      2>"${temporary}/cargo-boundary-ambient.err"; then
    die 1 'self-test accepted an ambient Cargo registry override'
  fi
  mkdir -p "${temporary}/metadata-workspace/crates/local" \
    "${temporary}/metadata-external"
  printf '%s\n' \
    '[package]' \
    'name = "local"' \
    'version = "0.1.0"' \
    'edition = "2021"' \
    >"${temporary}/metadata-workspace/crates/local/Cargo.toml"
  cp "${temporary}/metadata-workspace/crates/local/Cargo.toml" \
    "${temporary}/metadata-external/Cargo.toml"
  printf '%s\n' \
    'version = 3' \
    '' \
    '[[package]]' \
    'name = "demo"' \
    'version = "1.2.3"' \
    'source = "registry+https://github.com/rust-lang/crates.io-index"' \
    'checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
    '' \
    '[[package]]' \
    'name = "local"' \
    'version = "0.1.0"' \
    >"${temporary}/metadata-workspace/Cargo.lock"
  python3 -I -S - "${temporary}" <<'PY'
import json
import os
import sys
root = os.path.realpath(sys.argv[1])
workspace = os.path.join(root, "metadata-workspace")
inside = os.path.join(workspace, "crates", "local", "Cargo.toml")
outside = os.path.join(root, "metadata-external", "Cargo.toml")
base = {
    "workspace_root": workspace,
    "packages": [
        {
            "name": "demo",
            "version": "1.2.3",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "manifest_path": "/registry/demo/Cargo.toml",
        },
        {"name": "local", "version": "0.1.0", "source": None,
         "manifest_path": inside},
    ],
}
for name, manifest in (("metadata-inside.json", inside),
                       ("metadata-outside.json", outside)):
    document = dict(base)
    document["packages"] = [dict(item) for item in base["packages"]]
    document["packages"][1]["manifest_path"] = manifest
    with open(os.path.join(root, name), "x", encoding="ascii") as stream:
        json.dump(document, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
PY
  validate_cargo_workspace_metadata "${temporary}/metadata-workspace" \
    "${temporary}/metadata-workspace/Cargo.lock" \
    "${temporary}/metadata-inside.json" \
    "${temporary}/metadata-inside.env"
  if validate_cargo_workspace_metadata "${temporary}/metadata-workspace" \
    "${temporary}/metadata-workspace/Cargo.lock" \
    "${temporary}/metadata-outside.json" \
    "${temporary}/metadata-outside.env" \
    >"${temporary}/metadata-outside.out" \
    2>"${temporary}/metadata-outside.err"; then
    die 1 'self-test accepted a path dependency outside pinned source'
  fi
  mkdir -p "${temporary}/vendor-fixture/demo-1.2.3/src"
  printf '%s\n' 'pub fn answer() -> u8 { 42 }' \
    >"${temporary}/vendor-fixture/demo-1.2.3/src/lib.rs"
  local vendor_file_hash vendor_package_hash
  vendor_file_hash="$(sha256sum \
    "${temporary}/vendor-fixture/demo-1.2.3/src/lib.rs" | awk '{print $1}')"
  vendor_package_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  printf '{"files":{"src/lib.rs":"%s"},"package":"%s"}\n' \
    "${vendor_file_hash}" "${vendor_package_hash}" \
    >"${temporary}/vendor-fixture/demo-1.2.3/.cargo-checksum.json"
  printf '%s\n' \
    'version = 3' \
    '' \
    '[[package]]' \
    'name = "demo"' \
    'version = "1.2.3"' \
    'source = "registry+https://github.com/rust-lang/crates.io-index"' \
    "checksum = \"${vendor_package_hash}\"" \
    >"${temporary}/vendor-fixture.lock"
  local selftest_guest_vendor
  selftest_guest_vendor=/var/tmp/shadowpipe-lockdown-reboot-selftest/cargo-vendor/vendor
  seal_cargo_vendor_tree "${temporary}/vendor-fixture" \
    "${temporary}/vendor-fixture.lock" \
    "${temporary}/vendor-fixture-a.tar.gz" \
    "${temporary}/vendor-fixture-a.env" "${fixture_head}" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    "${selftest_guest_vendor}"
  seal_cargo_vendor_tree "${temporary}/vendor-fixture" \
    "${temporary}/vendor-fixture.lock" \
    "${temporary}/vendor-fixture-b.tar.gz" \
    "${temporary}/vendor-fixture-b.env" "${fixture_head}" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    "${selftest_guest_vendor}"
  cmp -s "${temporary}/vendor-fixture-a.tar.gz" \
    "${temporary}/vendor-fixture-b.tar.gz" \
    || die 1 'self-test Cargo vendor archives are not deterministic'
  [[ "$(source_archive_field \
    "${temporary}/vendor-fixture-a.env" vendor_registry_packages)" == 1 ]]
  [[ "$(source_archive_field \
    "${temporary}/vendor-fixture-a.env" cargo_vendor_command)" \
      == offline_locked_versioned_dirs ]]
  ln -s src/lib.rs "${temporary}/vendor-fixture/demo-1.2.3/symlink"
  if seal_cargo_vendor_tree "${temporary}/vendor-fixture" \
    "${temporary}/vendor-fixture.lock" \
    "${temporary}/vendor-symlink.tar.gz" \
    "${temporary}/vendor-symlink.env" "${fixture_head}" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    "${selftest_guest_vendor}" \
    >"${temporary}/vendor-symlink.out" \
    2>"${temporary}/vendor-symlink.err"; then
    die 1 'self-test accepted a symlink in the Cargo vendor tree'
  fi
  rm "${temporary}/vendor-fixture/demo-1.2.3/symlink"
  ln "${temporary}/vendor-fixture/demo-1.2.3/src/lib.rs" \
    "${temporary}/vendor-fixture/demo-1.2.3/hardlink"
  if seal_cargo_vendor_tree "${temporary}/vendor-fixture" \
    "${temporary}/vendor-fixture.lock" \
    "${temporary}/vendor-hardlink.tar.gz" \
    "${temporary}/vendor-hardlink.env" "${fixture_head}" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    "${selftest_guest_vendor}" \
    >"${temporary}/vendor-hardlink.out" \
    2>"${temporary}/vendor-hardlink.err"; then
    die 1 'self-test accepted a hard link in the Cargo vendor tree'
  fi
  rm "${temporary}/vendor-fixture/demo-1.2.3/hardlink"
  printf '%s\n' \
    'version = 3' \
    '' \
    '[[package]]' \
    'name = "demo"' \
    'version = "1.2.3"' \
    'source = "git+https://invalid.example/demo"' \
    >"${temporary}/vendor-git.lock"
  if seal_cargo_vendor_tree "${temporary}/vendor-fixture" \
    "${temporary}/vendor-git.lock" \
    "${temporary}/vendor-git.tar.gz" \
    "${temporary}/vendor-git.env" "${fixture_head}" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    "${selftest_guest_vendor}" \
    >"${temporary}/vendor-git.out" 2>"${temporary}/vendor-git.err"; then
    die 1 'self-test accepted a non-crates.io Cargo.lock source'
  fi
  printf '%s\n' 'pub fn answer() -> u8 { 7 }' \
    >"${temporary}/vendor-fixture/demo-1.2.3/src/lib.rs"
  if seal_cargo_vendor_tree "${temporary}/vendor-fixture" \
    "${temporary}/vendor-fixture.lock" \
    "${temporary}/vendor-file-hash.tar.gz" \
    "${temporary}/vendor-file-hash.env" "${fixture_head}" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    "${selftest_guest_vendor}" \
    >"${temporary}/vendor-file-hash.out" \
    2>"${temporary}/vendor-file-hash.err"; then
    die 1 'self-test accepted a vendored file hash mismatch'
  fi
  printf '%s\n' 'pub fn answer() -> u8 { 42 }' \
    >"${temporary}/vendor-fixture/demo-1.2.3/src/lib.rs"
  printf '{"files":{"src/lib.rs":"%s"},"package":"%064d"}\n' \
    "${vendor_file_hash}" 0 \
    >"${temporary}/vendor-fixture/demo-1.2.3/.cargo-checksum.json"
  if seal_cargo_vendor_tree "${temporary}/vendor-fixture" \
    "${temporary}/vendor-fixture.lock" \
    "${temporary}/vendor-checksum.tar.gz" \
    "${temporary}/vendor-checksum.env" "${fixture_head}" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    "${selftest_guest_vendor}" \
    >"${temporary}/vendor-checksum.out" \
    2>"${temporary}/vendor-checksum.err"; then
    die 1 'self-test accepted a Cargo package checksum mismatch'
  fi

  printf '%s\n' 'systemd 261 (261.1-1)' >"${temporary}/systemd-version.txt"
  printf '%s\n' enabled >"${temporary}/enabled.txt"
  printf '%s\n' \
    'LoadState=loaded' \
    'UnitFileState=enabled' \
    'ActiveState=active' \
    'SubState=exited' \
    'Result=success' \
    'ExecMainCode=1' \
    'ExecMainStatus=0' \
    'NRestarts=0' \
    'ExecMainStartTimestampMonotonic=10' \
    'ExecMainExitTimestampMonotonic=20' \
    'ActiveEnterTimestampMonotonic=20' \
    'InactiveExitTimestampMonotonic=11' \
    'InvocationID=11111111111111111111111111111111' \
    'Before=sysinit.target systemd-networkd.service' \
    'FragmentPath=/etc/systemd/system/shadowpipe-lockdown-restore.service' \
    'DropInPaths=' \
    'ExecCondition=' \
    'ExecStartPre=' \
    'ExecStart={ path=/usr/local/bin/shadowpipe-client ; argv[]=/usr/local/bin/shadowpipe-client --restore-lockdown --host-state-dir /var/lib/shadowpipe ; }' \
    'ExecStartPost=' \
    'EnvironmentFiles=' \
    >"${temporary}/restore.txt"
  printf '%s\n' \
    'LoadState=loaded' \
    'ActiveState=active' \
    'SubState=running' \
    'ExecMainStartTimestampMonotonic=30' \
    'InactiveExitTimestampMonotonic=31' \
    'InvocationID=22222222222222222222222222222222' \
    'NRestarts=0' \
    'After=shadowpipe-lockdown-restore.service' \
    'Requires=shadowpipe-lockdown-restore.service' \
    >"${temporary}/network.txt"
  printf '%s\n' shadowpipe-lockdown-restore.service \
    >"${temporary}/dependencies.txt"
  verify_systemd_evidence "${temporary}/systemd-version.txt" \
    "${temporary}/enabled.txt" "${temporary}/restore.txt" \
    "${temporary}/network.txt" "${temporary}/dependencies.txt"
  sed 's/ExecMainStartTimestampMonotonic=30/ExecMainStartTimestampMonotonic=15/' \
    "${temporary}/network.txt" >"${temporary}/network-too-early.txt"
  if verify_systemd_evidence "${temporary}/systemd-version.txt" \
    "${temporary}/enabled.txt" "${temporary}/restore.txt" \
    "${temporary}/network-too-early.txt" "${temporary}/dependencies.txt" \
    >"${temporary}/ordering.out" 2>"${temporary}/ordering.err"; then
    die 1 'self-test accepted networkd starting before restore completion'
  fi
  python3 -I -S - "${temporary}" <<'PY'
import json
import os
import sys

root = sys.argv[1]
signatures = {
    "ExecCondition": "a(sasbttttuii)",
    "ExecStartPre": "a(sasbttttuii)",
    "ExecStartPost": "a(sasbttttuii)",
    "EnvironmentFiles": "a(sb)",
}
for kind, unit, names in (
    (
        "restore",
        "shadowpipe-lockdown-restore.service",
        ("ExecCondition", "ExecStartPre", "ExecStartPost", "EnvironmentFiles"),
    ),
    (
        "client",
        "shadowpipe-client-full-tunnel.service",
        ("ExecCondition", "ExecStartPre", "ExecStartPost"),
    ),
):
    proof = {
        "schema_version": 1,
        "unit": unit,
        "object_path": "/org/freedesktop/systemd1/unit/shadowpipe_fixture",
        "dbus_typed_empty": {
            name: {"type": signatures[name], "data": []}
            for name in names
        },
        "unit_id_bound": True,
        "fragment_path_bound": True,
        "need_daemon_reload": False,
        "repeated_reads_identical": True,
        "unknown_property_rejected": True,
    }
    with open(
        os.path.join(root, f"{kind}-typed-empty.json"),
        "x",
        encoding="ascii",
    ) as stream:
        json.dump(proof, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
none = {
    "schema_version": 1,
    "unit": "systemd-networkd.service",
    "object_path": None,
    "dbus_typed_empty": {},
    "unit_id_bound": False,
    "fragment_path_bound": False,
    "need_daemon_reload": None,
    "repeated_reads_identical": False,
    "unknown_property_rejected": False,
}
with open(
    os.path.join(root, "none-typed-empty.json"),
    "x",
    encoding="ascii",
) as stream:
    json.dump(none, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
PY
  verify_systemd_dbus_typed_empty_sidecar \
    "${temporary}/restore-typed-empty.json" restore \
    shadowpipe-lockdown-restore.service
  verify_systemd_dbus_typed_empty_sidecar \
    "${temporary}/client-typed-empty.json" client \
    shadowpipe-client-full-tunnel.service
  verify_systemd_dbus_typed_empty_sidecar \
    "${temporary}/none-typed-empty.json" none systemd-networkd.service
  sed 's/a(sb)/as/' "${temporary}/restore-typed-empty.json" \
    >"${temporary}/restore-typed-empty-wrong-signature.json"
  if verify_systemd_dbus_typed_empty_sidecar \
    "${temporary}/restore-typed-empty-wrong-signature.json" restore \
    shadowpipe-lockdown-restore.service \
    >"${temporary}/typed-empty-signature.out" \
    2>"${temporary}/typed-empty-signature.err"; then
    die 1 'self-test accepted a wrong systemd D-Bus signature'
  fi
  printf '%s\n' \
    'LoadState=loaded' \
    'FragmentPath=/etc/systemd/system/shadowpipe-lockdown-restore.service' \
    'DropInPaths=' \
    'ExecCondition=' \
    'ExecStartPre=' \
    'ExecStart={ path=/usr/local/bin/shadowpipe-client ; argv[]=/usr/local/bin/shadowpipe-client --restore-lockdown --host-state-dir /var/lib/shadowpipe ; }' \
    'ExecStartPost=' \
    'EnvironmentFiles=' \
    >"${temporary}/restore-effective.txt"
  verify_effective_unit_definition \
    "${temporary}/restore-effective.txt" restore
  # The dollar-prefixed argv token is intentionally literal unit syntax.
  # shellcheck disable=SC2016
  printf '%s\n' \
    'LoadState=loaded' \
    'FragmentPath=/etc/systemd/system/shadowpipe-client-full-tunnel.service' \
    'DropInPaths=' \
    'ExecCondition=' \
    'ExecStartPre=' \
    'ExecStart={ path=/usr/local/bin/shadowpipe-client ; argv[]=/usr/local/bin/shadowpipe-client $SHADOWPIPE_CLIENT_ARGS ; }' \
    'ExecStartPost=' \
    'EnvironmentFiles=/etc/shadowpipe/client.env (ignore_errors=no)' \
    >"${temporary}/client-effective.txt"
  verify_effective_unit_definition \
    "${temporary}/client-effective.txt" client
  sed 's#DropInPaths=#DropInPaths=/etc/systemd/system/shadowpipe-client-full-tunnel.service.d/override.conf#' \
    "${temporary}/client-effective.txt" \
    >"${temporary}/client-effective-dropin.txt"
  if verify_effective_unit_definition \
    "${temporary}/client-effective-dropin.txt" client \
    >"${temporary}/effective-dropin.out" \
    2>"${temporary}/effective-dropin.err"; then
    die 1 'self-test accepted an effective client-unit drop-in'
  fi

  python3 -I -S - "${temporary}" <<'PY'
import json
import os
import sys

root = sys.argv[1]
common = {
    "LoadState": "loaded",
    "FragmentPath": "/etc/systemd/system/shadowpipe-client-full-tunnel.service",
    "UnitFileState": "enabled",
    "Result": "exit-code",
    "ExecMainCode": "1",
    "ExecMainStatus": "1",
    "NRestarts": "2",
    "MainPID": "0",
    "Restart": "always",
    "RestartUSec": "1s",
    "InvocationID": "00000000000000000000000000000000",
    "After": "network.target shadowpipe-lockdown-restore.service",
    "Requires": "shadowpipe-lockdown-restore.service",
    "ConditionResult": "yes",
    "DropInPaths": "",
    "ExecCondition": "",
    "ExecStart": "{ path=/usr/local/bin/shadowpipe-client ; argv[]=/usr/local/bin/shadowpipe-client $SHADOWPIPE_CLIENT_ARGS ; }",
    "ExecStartPre": "",
    "ExecStartPost": "",
    "EnvironmentFiles": "/etc/shadowpipe/client.env (ignore_errors=no)",
}
looping = dict(common, ActiveState="activating", SubState="auto-restart")
loop = {
    "schema_version": 1,
    "credential_failure_marker": "load mandatory root-owned client credential before startup",
    "invocation_ids": ["1" * 32, "2" * 32, "3" * 32],
    "restart_samples": [0, 1, 2],
    "properties": looping,
    "dbus_typed_empty_proof": {
        "properties": {
            "ExecCondition": {"type": "a(sasbttttuii)", "data": []},
            "ExecStartPre": {"type": "a(sasbttttuii)", "data": []},
            "ExecStartPost": {"type": "a(sasbttttuii)", "data": []},
        },
        "unit_id_bound": True,
        "fragment_path_bound": True,
        "need_daemon_reload": False,
        "repeated_reads_identical": True,
        "unknown_property_rejected": True,
    },
}
with open(os.path.join(root, "client-loop.json"), "x", encoding="ascii") as stream:
    json.dump(loop, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
for name in ("client-stopped.txt", "client-stable.txt"):
    values = dict(common, ActiveState="inactive", SubState="dead")
    with open(os.path.join(root, name), "x", encoding="utf-8") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")
marker = "load mandatory root-owned client credential before startup"
with open(os.path.join(root, "client-journal-stopped.jsonl"), "x", encoding="utf-8") as stream:
    for identifier in ("1" * 32, "2" * 32, "3" * 32):
        stream.write(json.dumps({"MESSAGE": f"Error: {marker}", "_SYSTEMD_INVOCATION_ID": identifier}))
        stream.write("\n")
with open(os.path.join(root, "client-journal-stopped.jsonl"), "rb") as source:
    journal = source.read()
with open(os.path.join(root, "client-journal-stable.jsonl"), "xb") as stream:
    stream.write(journal)
state = {
    "schema_version": 1,
    "ipv4_routes": [], "ipv6_routes": [], "ipv4_rules": [], "ipv6_rules": [],
    "links": [{"ifname": "lo"}], "nft_ruleset": {},
    "resolver": {"content_sha256": "a" * 64},
    "tun_interfaces": [], "client_pids": [],
    "lockdown_wal_absent": True, "main_wal_absent": True,
}
for name in ("client-network-baseline.json", "client-network-final.json"):
    with open(os.path.join(root, name), "x", encoding="ascii") as stream:
        json.dump(state, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
manifest = {
    "schema_version": 1, "label": "source", "tree_sha256": "a" * 64,
    "entries": 3, "directories": 1, "files": 2, "bytes": 42,
}
for name in ("tree-baseline.json", "tree-observed.json"):
    with open(os.path.join(root, name), "x", encoding="ascii") as stream:
        json.dump(manifest, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
PY
  printf '%s\n' enabled >"${temporary}/client-enabled.txt"
  printf '%s\n' 'stable_wait_seconds=2.250001' \
    >"${temporary}/client-wait.env"
  verify_client_unit_evidence \
    "${temporary}/client-loop.json" \
    "${temporary}/client-stopped.txt" \
    "${temporary}/client-stable.txt" \
    "${temporary}/client-journal-stopped.jsonl" \
    "${temporary}/client-journal-stable.jsonl" \
    "${temporary}/client-enabled.txt" \
    "${temporary}/client-network-baseline.json" \
    "${temporary}/client-network-final.json" \
    "${temporary}/client-wait.env"
  verify_guest_tree_manifest "${temporary}/tree-baseline.json" \
    "${temporary}/tree-observed.json" source
  sed 's/"bytes":42/"bytes":43/' "${temporary}/tree-observed.json" \
    >"${temporary}/tree-tampered.json"
  if verify_guest_tree_manifest "${temporary}/tree-baseline.json" \
    "${temporary}/tree-tampered.json" source \
    >"${temporary}/tree-drift.out" 2>"${temporary}/tree-drift.err"; then
    die 1 'self-test accepted guest source-tree drift'
  fi
  sed 's/"main_wal_absent":true/"main_wal_absent":false/' \
    "${temporary}/client-network-final.json" \
    >"${temporary}/client-network-tampered.json"
  if verify_client_unit_evidence \
    "${temporary}/client-loop.json" \
    "${temporary}/client-stopped.txt" \
    "${temporary}/client-stable.txt" \
    "${temporary}/client-journal-stopped.jsonl" \
    "${temporary}/client-journal-stable.jsonl" \
    "${temporary}/client-enabled.txt" \
    "${temporary}/client-network-baseline.json" \
    "${temporary}/client-network-tampered.json" \
    "${temporary}/client-wait.env" \
    >"${temporary}/client-drift.out" 2>"${temporary}/client-drift.err"; then
    die 1 'self-test accepted client-unit guest network-state drift'
  fi

  write_reboot_status "${temporary}/status.env" valid valid valid 1 true valid \
    not_applicable true \
    stopped released false valid valid
  write_reboot_result "${temporary}/RESULT.md" valid sphr-selftest false \
    shadowpipe-lab-base 1111111111111111111111111111111111111111 valid valid
  [[ "$(grep -c '^cargo_vendor_provenance_evidence=true$' \
    "${temporary}/status.env")" == 1 ]] \
    || die 1 'self-test did not publish exactly one valid Cargo vendor evidence field'
  write_reboot_status "${temporary}/status.env" valid failed valid 1 true valid \
    not_applicable true \
    stopped released false valid failed
  write_reboot_result "${temporary}/RESULT.md" failed sphr-selftest false \
    shadowpipe-lab-base 1111111111111111111111111111111111111111 failed valid
  grep -qx 'overall_status=failed' "${temporary}/status.env"
  grep -Fqx 'Component status: reboot=valid; client_unit=failed; overall=failed.' \
    "${temporary}/RESULT.md"
  if grep -q 'Verdict: \*\*PASS\*\*' "${temporary}/RESULT.md"; then
    die 1 'self-test retained a stale PASS after failure publication'
  fi

  mkdir -- "${temporary}/evidence"
  printf '%s\n' evidence >"${temporary}/evidence/value.txt"
  seal_bundle "${temporary}/evidence"
  [[ -s "${temporary}/evidence/checksums.sha256" ]]
  (cd "${temporary}/evidence" && sha256sum -c checksums.sha256 >/dev/null)
  mkdir -- "${temporary}/symlink-evidence"
  ln -s /etc "${temporary}/symlink-evidence/foreign"
  if seal_bundle "${temporary}/symlink-evidence" \
    >"${temporary}/symlink-seal.out" 2>"${temporary}/symlink-seal.err"; then
    die 1 'self-test sealed a symlinked evidence subtree'
  fi
  mkdir -- "${temporary}/multilink-evidence"
  printf x >"${temporary}/multilink-source"
  ln "${temporary}/multilink-source" \
    "${temporary}/multilink-evidence/value"
  if seal_bundle "${temporary}/multilink-evidence" 2>/dev/null; then
    die 1 'self-test sealed a multiply-linked evidence file'
  fi
  say 'run-orbstack-reboot self-test: PASS'
)

case "${1:-}" in
  -h|--help)
    usage
    ;;
  --self-test)
    [[ "$#" == 1 ]] || die "${EX_USAGE}" '--self-test accepts no extra arguments'
    run_self_test
    ;;
  *)
    main "$@"
    ;;
esac
