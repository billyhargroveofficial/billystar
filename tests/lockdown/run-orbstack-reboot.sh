#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Real-boot validation for the durable Linux restart lockdown. This script is
# destructive only inside a uniquely named disposable OrbStack clone. macOS
# networking and the live sing-box process are read-only evidence surfaces.

readonly EX_USAGE=64
readonly EX_UNAVAILABLE=69
readonly SOURCE_DEFAULT=arch
readonly MAGIC_DEFAULT=0x50334852
readonly HOST_COMMAND_TIMEOUT=30
readonly GUEST_COMMAND_TIMEOUT=120
readonly ORB_CLONE_TIMEOUT=900
readonly ORB_START_TIMEOUT=180
readonly ORB_DELETE_TIMEOUT=300
readonly BUILD_TIMEOUT=1800
readonly BOOT_READY_TIMEOUT=180
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
    tests/lockdown/run-orbstack-reboot.sh [stopped-source-vm]

  tests/lockdown/run-orbstack-reboot.sh --self-test

The source VM is never started or changed. A disposable clone is built,
an early-userspace L3 local-output lockdown is armed, the clone is rebooted,
systemd ordering is measured, the barrier is explicitly released, and the
owned clone is deleted. This is not a paired tunnel or production test.
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
        "InvocationID", "Before",
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
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(normalized, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
    json.dump(
        {"schema_version": 1, "id": machine_id, "name": name, "state": state},
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
    "deploy/shadowpipe-lockdown-restore.service",
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
    "guest_status", "host_safety_status", "clone_attempted", "clone_deleted",
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
        stream.write("l2_forward_container_evidence=false\n")
        lifecycle = values[keys.index("same_host_lifecycle_lock")]
        stream.write("concurrent_shadowpipe_orbstack_lifecycle_runners="
                     + ("excluded" if lifecycle == "released" else "not_proved")
                     + "\n")
        stream.write("unrelated_orbstack_lifecycle_operators=outside_trust_boundary\n")
        stream.write("private_material_scan_scope=not_applicable_no_experiment_secrets_live_config_hash_only\n")
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
  python3 -I -S - "${output}" "${verdict}" "${clone_vm}" \
    "${pf_observed}" <<'PY'
import os
import secrets
import stat
import sys
output, verdict, clone, pf_observed = sys.argv[1:]
if os.path.lexists(output) and stat.S_ISDIR(os.lstat(output).st_mode):
    raise SystemExit("result destination is a directory")
if verdict == "valid":
    pf_line = (
        "- macOS PF runtime: exact read-only rules/NAT/info snapshots were unchanged"
        if pf_observed == "true" else
        "- macOS PF runtime: exact unprivileged permission-denied tuple was unchanged; runtime rules remain explicitly unobserved"
    )
    body = "\n".join((
        "# Shadowpipe early-userspace L3 lockdown reboot result", "",
        "- Verdict: **PASS**",
        f"- Disposable clone: `{clone}` (opaque ID bound for start/restart/guest operations; delete-by-name required a fresh name-to-ID revalidation, followed by ID/name absence proof)",
        "- Real kernel/systemd reboot: distinct boot IDs and strict WAL boot/PID-1 namespace binding",
        "- Durable WAL: exact schema v1 Active generation 2 -> 4, fresh identity, handle matched exact nft listing",
        "- Enforcement observed: exact native nft inet/output barrier; loopback passed and non-loopback IPv4 ping was denied",
        "- Ordering observed: systemd >=254; unique InvocationIDs, zero restarts and monotonic activation timestamps prove restore completion before networkd start",
        "- Recovery observed: explicit operator release removed WAL and the only sp_lock table; guest IPv4 gateway became reachable",
        "- macOS safety observed: routes, DNS, exact sing-box PID/argv/config/executable and PF configuration files were unchanged",
        "- Host-safety timing: consistent before/after endpoint snapshots; no continuous host mutation monitor",
        "- Exclusion: the shared lifecycle lock serializes Shadowpipe runners; unrelated same-host operators remain outside the trust boundary and any name/ID/state drift fails closed",
        pf_line,
        "- Build contract: a validated explicit SHADOWPIPE_MAGIC u32 was recorded and used for the binary build",
        "- Private-material scan scope: the reboot experiment creates no VPN credential/private-key values and copies no live config bytes; the pre-existing Mac config is represented only by SHA-256",
        "- Scope: one disposable guest, early-userspace Linux L3 local OUTPUT plus explicit release only",
        "- No paired client/server tunnel, production, initrd, L2/AF_PACKET, FORWARD, container-netns, or censorship-field claim",
        "",
    ))
elif verdict == "failed":
    body = (
        "# Shadowpipe early-userspace lockdown reboot failure\n\n"
        "Inspect status.env and the sealed evidence. No PASS claim is present.\n"
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

main() {
  [[ "$(uname -s)" == Darwin ]] \
    || die "${EX_USAGE}" 'host mode must run on macOS'
  [[ "${SHADOWPIPE_DISPOSABLE_LOCKDOWN_REBOOT:-}" == 1 ]] \
    || die "${EX_USAGE}" 'set SHADOWPIPE_DISPOSABLE_LOCKDOWN_REBOOT=1'
  local tool
  for tool in orbctl orb python3 sha256sum route netstat scutil pfctl pgrep ps \
    cmp diff find sort awk sed tr wc mktemp mv; do
    command -v "${tool}" >/dev/null \
      || die "${EX_UNAVAILABLE}" "missing host dependency: ${tool}"
  done

  local source_vm="${1:-${SOURCE_DEFAULT}}"
  [[ "$#" -le 1 ]] || die "${EX_USAGE}" 'expected at most one source VM'
  source_vm="$(sanitize_component "${source_vm}")" \
    || die "${EX_USAGE}" 'unsafe source VM name'
  local script_dir repo_root results_root target_root run_id clone_vm magic
  local result_dir target_dir binary ownership_token host_tmp host_tmp_root before after
  magic="${SHADOWPIPE_MAGIC:-${MAGIC_DEFAULT}}"
  validate_magic "${magic}" \
    || die "${EX_USAGE}" 'SHADOWPIPE_MAGIC must be one value in the u32 range'
  script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
  repo_root="$(cd -- "${script_dir}/../.." && pwd -P)"
  results_root="${script_dir}/results"
  target_root="${repo_root}/target"
  [[ ! -L "${results_root}" && ! -L "${target_root}" ]] \
    || die "${EX_UNAVAILABLE}" 'result or target root is a symlink'
  mkdir -p -- "${results_root}" "${target_root}"
  results_root="$(cd -- "${results_root}" && pwd -P)"
  target_root="$(cd -- "${target_root}" && pwd -P)"
  [[ "${results_root}" == "${script_dir}/results" \
    && "${target_root}" == "${repo_root}/target" ]] \
    || die "${EX_UNAVAILABLE}" 'result or target root escaped its repository path'
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  clone_vm="sphr-lock-$(printf '%s' "${run_id}" | tr '[:upper:]' '[:lower:]')"
  result_dir="${results_root}/${run_id}-reboot"
  target_dir="${target_root}/lockdown-reboot-${run_id}"
  binary="${target_dir}/release/shadowpipe-client"
  [[ ! -e "${result_dir}" && ! -L "${result_dir}" ]] \
    || die "${EX_UNAVAILABLE}" "result path already exists: ${result_dir}"
  [[ ! -e "${target_dir}" && ! -L "${target_dir}" ]] \
    || die "${EX_UNAVAILABLE}" "target path already exists: ${target_dir}"
  mkdir -- "${result_dir}"
  result_dir="$(cd -- "${result_dir}" && pwd -P)"
  mkdir -- "${target_dir}"
  target_dir="$(cd -- "${target_dir}" && pwd -P)"
  host_tmp="$(mktemp -d "${TMPDIR:-/tmp}/shadowpipe-lockdown-reboot.XXXXXX")"
  host_tmp="$(cd -- "${host_tmp}" && pwd -P)"
  host_tmp_root="$(cd -- "$(dirname -- "${host_tmp}")" && pwd -P)"
  ownership_token="$(printf '%s\0%s\0%s\n' \
    "${run_id}" "${clone_vm}" "${host_tmp}" | sha256sum | awk '{print $1}')"
  [[ "${ownership_token}" =~ ^[0-9a-f]{64}$ ]] \
    || die "${EX_UNAVAILABLE}" 'could not derive ownership token'
  write_ownership_marker "${result_dir}" "${ownership_token}" \
    || die "${EX_UNAVAILABLE}" 'could not mark result ownership'
  write_ownership_marker "${target_dir}" "${ownership_token}" \
    || die "${EX_UNAVAILABLE}" 'could not mark target ownership'
  write_ownership_marker "${host_tmp}" "${ownership_token}" \
    || die "${EX_UNAVAILABLE}" 'could not mark temporary ownership'
  printf 'SHADOWPIPE_MAGIC=%s\n' "${magic}" \
    >"${result_dir}/build-contract.txt"
  before="${host_tmp}/mac-before"
  after="${host_tmp}/mac-after"
  local final_status=0 clone_attempted=0 clone_owned=0
  local clone_completion_uncertain=0
  local guest_status=failed host_safety=failed clone_deleted=not_attempted
  local clone_cleanup_status=not_run
  local target_deleted=false source_state_status=failed host_tmp_deleted=false
  local lifecycle_lock='' lifecycle_lock_status=not_acquired
  local pf_runtime_observed=unknown
  local source_orb_id='' clone_orb_id='' clone_identity_bound=0
  local clone_deletion_pending=0

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

    if safe_remove_owned_tree "${target_dir}" "${target_root}" "${ownership_token}"; then
      target_deleted=true
    else
      warn 'refusing or failing target cleanup: ownership/path proof failed'
      final_status=1
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
      && "${clone_attempted}" == 1 \
      && "${host_safety}" == valid && "${clone_deleted}" == true \
      && "${clone_cleanup_status}" == valid \
      && "${target_deleted}" == true && "${host_tmp_deleted}" == true \
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
      if ! write_reboot_status "${result_dir}/status.env" \
      "${guest_status}" "${host_safety}" "${clone_attempted}" "${clone_deleted}" \
      "${clone_cleanup_status}" \
      "${target_deleted}" "${host_tmp_deleted}" "${source_state_status}" \
      "${lifecycle_lock_status}" "${pf_runtime_observed}" \
      "${evidence_bundle_status}" "${overall_status}" \
        || ! write_reboot_result "${result_dir}/RESULT.md" \
        "${overall_status}" "${clone_vm}" "${pf_runtime_observed}"; then
      final_status=1
      candidate_success=0
      overall_status=failed
      write_reboot_status "${result_dir}/status.env" \
        "${guest_status}" "${host_safety}" "${clone_attempted}" "${clone_deleted}" \
        "${clone_cleanup_status}" \
        "${target_deleted}" "${host_tmp_deleted}" "${source_state_status}" \
        "${lifecycle_lock_status}" "${pf_runtime_observed}" \
        "${evidence_bundle_status}" failed || true
      write_reboot_result "${result_dir}/RESULT.md" failed "${clone_vm}" \
        "${pf_runtime_observed}" || true
      fi

      if ! seal_bundle "${result_dir}" \
        || ! (cd -- "${result_dir}" && sha256sum -c checksums.sha256 >/dev/null); then
      final_status=1
      candidate_success=0
      overall_status=failed
      evidence_bundle_status=failed
      write_reboot_status "${result_dir}/status.env" \
        "${guest_status}" "${host_safety}" "${clone_attempted}" "${clone_deleted}" \
        "${clone_cleanup_status}" \
        "${target_deleted}" "${host_tmp_deleted}" "${source_state_status}" \
        "${lifecycle_lock_status}" "${pf_runtime_observed}" failed failed \
        || true
      write_reboot_result "${result_dir}/RESULT.md" failed "${clone_vm}" \
        "${pf_runtime_observed}" || true
        if ! seal_bundle "${result_dir}" \
          || ! (cd -- "${result_dir}" \
            && sha256sum -c checksums.sha256 >/dev/null); then
          warn 'failed to seal even the failure bundle'
        fi
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

  create_provenance_manifest "${repo_root}" \
    "${result_dir}/source-provenance-before.sha256"
  # shellcheck disable=SC2016
  run_recorded "${HOST_COMMAND_TIMEOUT}" \
    "${result_dir}/critical-provenance.sha256" /bin/sh -c \
    'cd "$1" && sha256sum .cargo/config.toml Cargo.lock Cargo.toml crates/shadowpipe-core/Cargo.toml crates/shadowpipe-core/build.rs crates/shadowpipe-core/src/lockdown.rs crates/shadowpipe-client/Cargo.toml crates/shadowpipe-client/src/main.rs crates/shadowpipe-reality/Cargo.toml crates/shadowpipe-reality/src/lib.rs crates/shadowpipe-reality/src/auth.rs crates/shadowpipe-reality/src/reality.rs deploy/shadowpipe-lockdown-restore.service tests/lockdown/run-orbstack-reboot.sh' \
    provenance "${repo_root}"
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

  say 'building Linux ARM64 client in disposable clone'
  run_recorded "${BUILD_TIMEOUT}" "${result_dir}/build.log" \
    orb -m "${clone_orb_id}" -p -w "${repo_root}" bash -lc \
    "SHADOWPIPE_MAGIC='${magic}' CARGO_TARGET_DIR='${target_dir}' cargo build --release --locked --no-default-features -p shadowpipe-client && test -x '${binary}'"
  verify_provenance_manifest "${repo_root}" \
    "${result_dir}/source-provenance-before.sha256" \
    "${result_dir}/source-provenance-after-build.sha256" \
    || die 1 'source/unit/harness/Cargo.lock changed while the binary was built'
  run_recorded "${HOST_COMMAND_TIMEOUT}" "${result_dir}/built-binary.sha256" \
    sha256sum "${binary}"

  # The single-quoted install program is evaluated by the guest shell.
  # shellcheck disable=SC2016
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/install-binary.log" \
    orb -m "${clone_orb_id}" -u root -p sh -ceu \
    'install -m 0755 -- "$1" /usr/local/bin/shadowpipe-client' \
    _ "${binary}"
  # The single-quoted install program is evaluated by the guest shell.
  # shellcheck disable=SC2016
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/install-unit.log" \
    orb -m "${clone_orb_id}" -u root -p sh -ceu \
    'install -m 0644 -- "$1" /etc/systemd/system/shadowpipe-lockdown-restore.service' \
    _ "${repo_root}/deploy/shadowpipe-lockdown-restore.service"
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/state-dir-and-reload.log" \
    orb -m "${clone_orb_id}" -u root sh -lc \
    'install -d -o root -g root -m 0700 /var/lib/shadowpipe; systemctl daemon-reload'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/systemd-verify.txt" \
    orb -m "${clone_orb_id}" -u root systemd-analyze verify \
    /etc/systemd/system/shadowpipe-lockdown-restore.service
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
  capture_guest_state_metadata "${clone_vm}" \
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

  say 'rebooting disposable clone with an owned Active WAL'
  capture_orb_identity "${HOST_COMMAND_TIMEOUT}" \
    "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
    "${result_dir}/clone-info-before-restart" >/dev/null \
    || die 1 'clone identity changed before reboot'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/reboot.log" \
    orbctl restart "${clone_orb_id}"
  wait_for_guest "${clone_orb_id}" "${result_dir}/guest-ready-after-reboot.txt" \
    || die 1 'guest did not return after lockdown reboot'
  capture_orb_identity "${HOST_COMMAND_TIMEOUT}" \
    "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
    "${result_dir}/clone-info-after-restart" >/dev/null \
    || die 1 'clone identity changed across reboot'
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/boot-id-post.txt" \
    orb -m "${clone_orb_id}" -u root cat /proc/sys/kernel/random/boot_id
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
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/systemd-restore-status.txt" \
    orb -m "${clone_orb_id}" -u root env LC_ALL=C systemctl show \
    shadowpipe-lockdown-restore.service \
    -p LoadState -p UnitFileState -p ActiveState -p SubState -p Result \
    -p ExecMainCode -p ExecMainStatus -p NRestarts \
    -p ExecMainStartTimestampMonotonic -p ExecMainExitTimestampMonotonic \
    -p ActiveEnterTimestampMonotonic -p InactiveExitTimestampMonotonic \
    -p InvocationID -p Before
  run_recorded "${GUEST_COMMAND_TIMEOUT}" "${result_dir}/systemd-networkd-status.txt" \
    orb -m "${clone_orb_id}" -u root env LC_ALL=C systemctl show systemd-networkd.service \
    -p LoadState -p ActiveState -p SubState \
    -p ExecMainStartTimestampMonotonic -p InactiveExitTimestampMonotonic \
    -p InvocationID -p NRestarts -p After -p Requires
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
  capture_guest_state_metadata "${clone_vm}" \
    "${result_dir}/state-metadata-post-reboot.txt"
  verify_guest_state_metadata "${result_dir}/state-metadata-post-reboot.txt"
  local table_post
  table_post="$(wal_table_name "${result_dir}/wal-post-reboot.json" \
    "${result_dir}/boot-id-post.txt" 4 \
    "${result_dir}/state-metadata-post-reboot.txt" \
    2>"${result_dir}/wal-post-reboot-handle.txt")"
  [[ "${table_pre}" != "${table_post}" ]] \
    || die 1 'reboot did not renew the lockdown table identity'
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

  verify_provenance_manifest "${repo_root}" \
    "${result_dir}/source-provenance-before.sha256" \
    "${result_dir}/source-provenance-final.sha256" \
    || die 1 'source/unit/harness/Cargo.lock changed during the reboot experiment'

  guest_status=valid
  final_status=0
  cleanup
}

run_self_test() (
  set -Eeuo pipefail
  local temporary parent token owned table status child_pid child_gone=0
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/shadowpipe-reboot-selftest.XXXXXX")"
  temporary="$(cd -- "${temporary}" && pwd -P)"
  parent="$(cd -- "$(dirname -- "${temporary}")" && pwd -P)"
  token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  write_ownership_marker "${temporary}" "${token}"
  trap 'safe_remove_owned_tree "${temporary}" "${parent}" "${token}" >/dev/null' EXIT

  [[ "$(sanitize_component arch.test-1)" == arch.test-1 ]]
  if sanitize_component '../arch' >"${temporary}/unsafe-name.out" 2>"${temporary}/unsafe-name.err"; then
    die 1 'self-test accepted an unsafe VM component'
  fi
  printf '%s\n' \
    '{"record":{"id":"opaque-A","name":"sphr-lock-fixture","state":"stopped","future":true},"future_root":1}' \
    >"${temporary}/orb-info.json"
  [[ "$(parse_orb_info_identity "${temporary}/orb-info.json" \
    sphr-lock-fixture opaque-A stopped "${temporary}/orb-identity.json")" \
    == opaque-A ]]
  grep -qx \
    '{"id":"opaque-A","name":"sphr-lock-fixture","schema_version":1,"state":"stopped"}' \
    "${temporary}/orb-identity.json"
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

  write_reboot_status "${temporary}/status.env" valid valid 1 true valid true true \
    stopped released false valid valid
  write_reboot_result "${temporary}/RESULT.md" valid sphr-selftest false
  write_reboot_status "${temporary}/status.env" failed valid 1 true valid true true \
    stopped released false valid failed
  write_reboot_result "${temporary}/RESULT.md" failed sphr-selftest false
  grep -qx 'overall_status=failed' "${temporary}/status.env"
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
