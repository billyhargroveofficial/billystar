#!/usr/bin/env bash
# Current dirty-worktree native Linux ARM64 portability matrix.
# Network-state mutation is out of scope: no route, DNS, firewall, TUN, netns,
# qdisc, sysctl, service, or privileged networking command is run.
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly REPO_ROOT
readonly RESULT_ROOT="${SCRIPT_DIR}/results"
readonly SOURCE_DEFAULT="shadowpipe-lab-base"
readonly WINDOWS_DEFAULT="Windows 11"
readonly MAGIC_DEFAULT="0x50334852"
readonly EXPECTED_SINGBOX_CONFIG="${SHADOWPIPE_HOST_SINGBOX_CONFIG:-${HOME}/sing-box/config.json}"
readonly EXPECTED_SINGBOX_DIRECTORY="${SHADOWPIPE_HOST_SINGBOX_DIRECTORY:-${EXPECTED_SINGBOX_CONFIG%/*}}"
readonly STATUS_SCHEMA_VERSION=1
readonly HOST_TIMEOUT=30
readonly CLONE_TIMEOUT=300
readonly ORB_START_TIMEOUT=180
readonly ORB_STOP_TIMEOUT=180
readonly ORB_DELETE_TIMEOUT=300
readonly GUEST_SETUP_TIMEOUT=1200
readonly CARGO_TIMEOUT=3600
readonly SELFTEST_TIMEOUT=300
readonly QUIESCENCE_SECONDS=60
readonly EX_USAGE=64
readonly EX_DATAERR=65
readonly EX_UNAVAILABLE=69
readonly EX_NOPERM=77
readonly -a GUEST_REQUIRED_TOOLS=(
  cargo rustc rustfmt cmake ninja clang go perl pkg-config nasm gcc make git
  python3
)
readonly -a GUEST_BUILD_PACKAGES=(
  base-devel cmake ninja clang go perl pkgconf nasm git
)
readonly -a HOST_RUNNER_SELFTESTS=(
  tests/windows/run-parallels-orbstack-h2.sh
)
readonly -a GUEST_RUNNER_SELFTESTS=(
  tests/portability/run-orbstack-arm64-current.sh
  tests/host-recovery/run-orbstack-phase3.sh
  tests/tun/run-orbstack-full-tun.sh
  tests/lockdown/run-orbstack-reboot.sh
)
readonly -a REQUIRED_RUNNER_SELFTESTS=(
  tests/portability/run-orbstack-arm64-current.sh
  tests/host-recovery/run-orbstack-phase3.sh
  tests/tun/run-orbstack-full-tun.sh
  tests/lockdown/run-orbstack-reboot.sh
  tests/windows/run-parallels-orbstack-h2.sh
)

say() {
  printf '[linux-arm64-current] %s\n' "$*"
}

# shellcheck disable=SC2329
warn() {
  printf '[linux-arm64-current] WARN: %s\n' "$*" >&2
}

die() {
  local status="$1"
  shift
  printf '[linux-arm64-current] ERROR: %s\n' "$*" >&2
  exit "${status}"
}

usage() {
  cat <<'EOF'
Usage:
  SHADOWPIPE_DISPOSABLE_ARM64_CURRENT=1 \
    tests/portability/run-orbstack-arm64-current.sh [shadowpipe-lab-base]
  tests/portability/run-orbstack-arm64-current.sh --self-test

The host performs filesystem/build-input preparation, ShellCheck against the
frozen source snapshot, read-only sing-box observation, Parallels state
observation, and OrbStack lifecycle operations. Cargo, rustfmt, Clippy, bash -n,
and Linux-compatible pure runner self-tests execute as the unprivileged Linux
ARM64 guest user; the Windows/Parallels runner self-test executes on the macOS
host against the same frozen snapshot.
EOF
}

sanitize_component() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+$ && ${#1} -le 96 ]] || return 1
  printf '%s\n' "$1"
}

validate_magic() {
  [[ "$1" =~ ^0[xX][0-9a-fA-F]{1,8}$ || "$1" =~ ^[0-9]{1,10}$ ]] || return 1
  /usr/bin/python3 -I -S - "$1" <<'PY'
import sys
value = int(sys.argv[1], 0)
if value < 0 or value > 0xffffffff:
    raise SystemExit(1)
PY
}

run_bounded() {
  local seconds="$1"
  shift
  timeout --foreground --signal=TERM --kill-after=10 "${seconds}" "$@"
}

capture_command() {
  local timeout_seconds="$1" output="$2"
  shift 2
  local status
  if run_bounded "${timeout_seconds}" "$@" \
    >"${output}" 2>"${output}.stderr"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "${status}" >"${output}.status"
  return "${status}"
}

capture_command_stdin() {
  local timeout_seconds="$1" output="$2" input="$3"
  shift 3
  local status
  [[ -f "${input}" && ! -L "${input}" ]] || return "${EX_DATAERR}"
  if run_bounded "${timeout_seconds}" "$@" \
    <"${input}" >"${output}" 2>"${output}.stderr"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "${status}" >"${output}.status"
  return "${status}"
}

# Invoked from the EXIT cleanup path, which ShellCheck cannot follow through trap.
# shellcheck disable=SC2329
capture_optional() {
  capture_command "$@" || true
}

# Invoked from the EXIT cleanup path, which ShellCheck cannot follow through trap.
# shellcheck disable=SC2329
bounded_cmp() {
  run_bounded "${HOST_TIMEOUT}" /usr/bin/python3 -I -S -c '
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
' "$1" "$2"
}

capture_pid_executable() {
  local pid="$1" output="$2"
  capture_command "${HOST_TIMEOUT}" "${output}" /usr/bin/python3 -I -S -c '
import ctypes
import os
import sys
pid = int(sys.argv[1], 10)
buffer = ctypes.create_string_buffer(4096)
library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
length = library.proc_pidpath(pid, buffer, len(buffer))
if length <= 0:
    raise OSError(ctypes.get_errno(), "proc_pidpath failed")
path = os.fsdecode(buffer.value)
if not os.path.isabs(path) or "\n" in path or "\r" in path:
    raise SystemExit("unsafe proc_pidpath result")
print(path)
' "${pid}"
}

validate_live_singbox_command() {
  local command_file="$1"
  /usr/bin/python3 -I -S - \
    "${command_file}" "${EXPECTED_SINGBOX_CONFIG}" \
    "${EXPECTED_SINGBOX_DIRECTORY}" <<'PY'
import os
import sys
path, expected_config, expected_directory = sys.argv[1:]
with open(path, "r", encoding="utf-8") as stream:
    lines = stream.read().splitlines()
if len(lines) != 1:
    raise SystemExit("sing-box command is not one line")
command = lines[0]
if any(character in command for character in ("'", '"', "\\")):
    raise SystemExit("sing-box command requires unsafe interpretation")
argv = command.split()
if len(argv) != 6:
    raise SystemExit("sing-box argv length changed")
if os.path.basename(argv[0]) != "sing-box" or argv[1] != "run":
    raise SystemExit("unexpected sing-box executable or action")
if argv[2:] != ["-c", expected_config, "-D", expected_directory]:
    raise SystemExit("sing-box is not using the protected live configuration")
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
      if run_bounded "${HOST_TIMEOUT}" ps -ww -p "${pid}" -o command= \
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
      if validate_live_singbox_command \
        "${temporary}" 2>>"${output}.stderr"; then
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
    sing-box-executable.path; do
    case "${left}" in
      sing-box.pids.candidates) right=sing-box.pids-final.candidates ;;
      sing-box.candidate-commands.tsv) right=sing-box.candidate-commands-final.tsv ;;
      sing-box-executable.path) right=sing-box-executable-final.path ;;
      *) right="${left}-final" ;;
    esac
    bounded_cmp "${root}/${left}" "${root}/${right}" || return 1
  done
}

self_test_singbox_observer() {
  local root="$1" exact unrelated foreign
  mkdir -p -- "${root}" || return 1
  exact="/opt/homebrew/bin/sing-box run -c ${EXPECTED_SINGBOX_CONFIG} -D ${EXPECTED_SINGBOX_DIRECTORY}"
  unrelated="/Applications/SkyComputerUseClient turn-ended payload=sing-box run -c ${EXPECTED_SINGBOX_CONFIG} -D ${EXPECTED_SINGBOX_DIRECTORY}"
  foreign="/opt/homebrew/bin/sing-box run -c /tmp/foreign.json -D /tmp/foreign"

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
  printf '/opt/homebrew/bin/sing-box\n' >"${root}/sing-box-executable.path"
  printf '/opt/homebrew/bin/sing-box\n' \
    >"${root}/sing-box-executable-final.path"
  validate_singbox_reproof "${root}" || return 1
  printf '101 Mon Jan  1 00:00:01 2024 %s\n' "${exact}" \
    >"${root}/sing-box.identity-final"
  if validate_singbox_reproof "${root}"; then
    return 1
  fi
  [[ -f "${root}/accepted.status" && -f "${root}/accepted.stderr" ]]
}

snapshot_macos_singbox() {
  local output="$1" status=0 pid final_pid executable
  mkdir -p -- "${output}"
  capture_command "${HOST_TIMEOUT}" "${output}/sing-box.pids.raw" \
    pgrep -x sing-box || status=1
  capture_command "${HOST_TIMEOUT}" "${output}/sing-box.pids.candidates" \
    sort -n "${output}/sing-box.pids.raw" || status=1
  capture_singbox_candidate_commands \
    "${output}/sing-box.pids.candidates" \
    "${output}/sing-box.candidate-commands.tsv" || status=1
  select_managed_singbox_candidates \
    "${output}/sing-box.candidate-commands.tsv" "${output}/sing-box.pids" \
    || status=1
  if [[ "$(wc -l <"${output}/sing-box.pids" | tr -d ' ')" != 1 ]]; then
    status=1
    pid=''
  else
    pid="$(<"${output}/sing-box.pids")"
  fi
  if [[ "${pid}" =~ ^[0-9]+$ ]]; then
    capture_command "${HOST_TIMEOUT}" "${output}/sing-box.identity" \
      ps -ww -p "${pid}" -o pid= -o lstart= -o command= || status=1
    capture_command "${HOST_TIMEOUT}" "${output}/sing-box.command" \
      ps -ww -p "${pid}" -o command= || status=1
    capture_pid_executable "${pid}" "${output}/sing-box-executable.path" \
      || status=1
  else
    status=1
    for name in sing-box.identity sing-box.command sing-box-executable.path; do
      : >"${output}/${name}"
      printf '1\n' >"${output}/${name}.status"
      printf 'invalid or ambiguous pid\n' >"${output}/${name}.stderr"
    done
  fi
  validate_live_singbox_command "${output}/sing-box.command" || status=1
  executable="$(<"${output}/sing-box-executable.path")"
  if [[ ! -f "${EXPECTED_SINGBOX_CONFIG}" \
    || -L "${EXPECTED_SINGBOX_CONFIG}" \
    || ! -f "${executable}" || -L "${executable}" ]]; then
    status=1
  else
    capture_command "${HOST_TIMEOUT}" "${output}/sing-box-config.sha256" \
      sha256sum "${EXPECTED_SINGBOX_CONFIG}" || status=1
    capture_command "${HOST_TIMEOUT}" "${output}/sing-box-binary.sha256" \
      sha256sum "${executable}" || status=1
    capture_command "${HOST_TIMEOUT}" "${output}/sing-box-config.stat" \
      stat -f '%HT %Su %Sg %Sp %l %z %N' "${EXPECTED_SINGBOX_CONFIG}" || status=1
    capture_command "${HOST_TIMEOUT}" "${output}/sing-box-binary.stat" \
      stat -f '%HT %Su %Sg %Sp %l %z %N' "${executable}" || status=1
  fi
  capture_command "${HOST_TIMEOUT}" "${output}/sing-box.pids-final.raw" \
    pgrep -x sing-box || status=1
  capture_command "${HOST_TIMEOUT}" "${output}/sing-box.pids-final.candidates" \
    sort -n "${output}/sing-box.pids-final.raw" || status=1
  capture_singbox_candidate_commands \
    "${output}/sing-box.pids-final.candidates" \
    "${output}/sing-box.candidate-commands-final.tsv" || status=1
  select_managed_singbox_candidates \
    "${output}/sing-box.candidate-commands-final.tsv" \
    "${output}/sing-box.pids-final" || status=1
  final_pid="$(<"${output}/sing-box.pids-final")"
  if [[ "${final_pid}" =~ ^[0-9]+$ ]]; then
    capture_command "${HOST_TIMEOUT}" "${output}/sing-box.identity-final" \
      ps -ww -p "${final_pid}" -o pid= -o lstart= -o command= || status=1
    capture_command "${HOST_TIMEOUT}" "${output}/sing-box.command-final" \
      ps -ww -p "${final_pid}" -o command= || status=1
    capture_pid_executable \
      "${final_pid}" "${output}/sing-box-executable-final.path" || status=1
  else
    status=1
    for name in sing-box.identity-final sing-box.command-final \
      sing-box-executable-final.path; do
      : >"${output}/${name}"
      printf '1\n' >"${output}/${name}.status"
      printf 'invalid or ambiguous final pid\n' >"${output}/${name}.stderr"
    done
  fi
  validate_live_singbox_command "${output}/sing-box.command-final" || status=1
  if validate_singbox_reproof "${output}"; then
    printf 'sing_box_snapshot_consistent=true\n' \
      >"${output}/sing-box-snapshot-consistency.env"
  else
    status=1
    printf 'sing_box_snapshot_consistent=false\n' \
      >"${output}/sing-box-snapshot-consistency.env"
  fi
  printf 'snapshot_status=%s\n' "$([[ "${status}" == 0 ]] && echo valid || echo failed)" \
    >"${output}/snapshot-status.env"
  return "${status}"
}

# Invoked from the EXIT cleanup path, which ShellCheck cannot follow through trap.
# shellcheck disable=SC2329
compare_macos_singbox() {
  local before="$1" after="$2" name status=0
  local -a files=(
    sing-box.pids.raw sing-box.pids.raw.stderr sing-box.pids.raw.status
    sing-box.pids.candidates sing-box.pids.candidates.stderr
    sing-box.pids.candidates.status
    sing-box.candidate-commands.tsv sing-box.candidate-commands.tsv.stderr
    sing-box.candidate-commands.tsv.status
    sing-box.pids sing-box.pids.stderr sing-box.pids.status
    sing-box.identity sing-box.identity.stderr sing-box.identity.status
    sing-box.command sing-box.command.stderr sing-box.command.status
    sing-box-executable.path sing-box-executable.path.stderr
    sing-box-executable.path.status
    sing-box-config.sha256 sing-box-config.sha256.stderr sing-box-config.sha256.status
    sing-box-binary.sha256 sing-box-binary.sha256.stderr sing-box-binary.sha256.status
    sing-box-config.stat sing-box-config.stat.stderr sing-box-config.stat.status
    sing-box-binary.stat sing-box-binary.stat.stderr sing-box-binary.stat.status
    sing-box.pids-final.raw sing-box.pids-final.raw.stderr
    sing-box.pids-final.raw.status
    sing-box.pids-final.candidates sing-box.pids-final.candidates.stderr
    sing-box.pids-final.candidates.status
    sing-box.candidate-commands-final.tsv
    sing-box.candidate-commands-final.tsv.stderr
    sing-box.candidate-commands-final.tsv.status
    sing-box.pids-final sing-box.pids-final.stderr sing-box.pids-final.status
    sing-box.identity-final sing-box.identity-final.stderr
    sing-box.identity-final.status
    sing-box.command-final sing-box.command-final.stderr
    sing-box.command-final.status
    sing-box-executable-final.path sing-box-executable-final.path.stderr
    sing-box-executable-final.path.status
    sing-box-snapshot-consistency.env
    snapshot-status.env
  )
  for name in "${files[@]}"; do
    bounded_cmp "${before}/${name}" "${after}/${name}" || status=1
  done
  return "${status}"
}

acquire_lifecycle_lock() {
  local token="$1" lock="/tmp/shadowpipe-orbstack-lifecycle.lock"
  mkdir -m 0700 -- "${lock}" || return 1
  if ! /usr/bin/python3 -I -S - "${lock}" "${token}" <<'PY'
import os
import sys
lock, token = sys.argv[1:]
path = os.path.join(lock, "owner")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
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

# Invoked from the EXIT cleanup path, which ShellCheck cannot follow through trap.
# shellcheck disable=SC2329
release_lifecycle_lock() {
  local lock="$1" token="$2"
  /usr/bin/python3 -I -S - "${lock}" "${token}" <<'PY'
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
descriptor = os.open(owner, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
with os.fdopen(descriptor, "r", encoding="ascii") as stream:
    if stream.read() != token + "\n":
        raise SystemExit("lifecycle lock token changed")
os.unlink(owner)
os.rmdir(lock)
PY
}

parse_orb_info_identity() {
  local raw="$1" expected_name="$2" expected_id="$3"
  local expected_state="$4" normalized="$5"
  /usr/bin/python3 -I -S - \
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
if (not machine_id or len(machine_id.encode("utf-8")) > 512
        or any(ord(character) < 0x21 or ord(character) == 0x7f
               for character in machine_id)):
    raise SystemExit("unsafe OrbStack opaque ID")
if record["name"] != expected_name:
    raise SystemExit("OrbStack name mismatch")
if expected_id and machine_id != expected_id:
    raise SystemExit("OrbStack opaque ID mismatch or name reuse")
if expected_state and record["state"] != expected_state:
    raise SystemExit("OrbStack state mismatch")
config = record.get("config")
if type(config) is not dict:
    raise SystemExit("OrbStack record lacks a config object")
if config.get("isolated") is not True:
    raise SystemExit("OrbStack machine is not capability-isolated")
if config.get("isolate_network") is not True:
    raise SystemExit("OrbStack machine network isolation is not enabled")
if config.get("forward_ssh_agent") is not False:
    raise SystemExit("OrbStack SSH-agent forwarding is not disabled")
for port_name in ("http_port", "https_port"):
    if type(config.get(port_name)) is not int or config[port_name] != 0:
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
        {"schema_version": 1, "id": machine_id, "name": record["name"],
         "state": record["state"]},
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
  local selector="$1" expected_name="$2" expected_id="$3"
  local expected_state="$4" base="$5" status identity
  capture_command "${HOST_TIMEOUT}" "${base}.raw.json" \
    orbctl info -f json "${selector}" || return $?
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
    return "${EX_DATAERR}"
  fi
}

orb_exact_absent() {
  local selector="$1" base="$2" status
  if capture_command "${HOST_TIMEOUT}" "${base}.raw.json" \
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

# Invoked from the EXIT cleanup path, which ShellCheck cannot follow through trap.
# shellcheck disable=SC2329
orb_absent_quiet() {
  local selector="$1" temporary status
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/shadowpipe-orb-absent.XXXXXX")" \
    || return 1
  if run_bounded "${HOST_TIMEOUT}" orbctl info -f json "${selector}" \
    >"${temporary}/stdout" 2>"${temporary}/stderr"; then
    status=0
  else
    status=$?
  fi
  if [[ "${status}" == 1 && ! -s "${temporary}/stdout" \
    && "$(<"${temporary}/stderr")" \
      == "[-32098] machine not found: '${selector}'" ]]; then
    rm -rf -- "${temporary}"
    return 0
  fi
  rm -rf -- "${temporary}"
  return 1
}

capture_parallels_suspended() {
  local output="$1"
  capture_command "${HOST_TIMEOUT}" "${output}.raw.json" prlctl list -a -j \
    || return 1
  /usr/bin/python3 -I -S - \
    "${output}.raw.json" "${WINDOWS_DEFAULT}" "${output}.identity.json" <<'PY'
import json
import os
import sys
raw_path, expected_name, normalized = sys.argv[1:]
def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result
with open(raw_path, "rb") as stream:
    raw = stream.read()
document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
matches = [item for item in document
           if type(item) is dict and item.get("name") == expected_name]
if len(matches) != 1:
    raise SystemExit("Windows VM is absent or ambiguous")
record = matches[0]
if record.get("status") != "suspended" or type(record.get("uuid")) is not str:
    raise SystemExit("Windows VM is not suspended")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(normalized, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
    json.dump(
        {"schema_version": 1, "uuid": record["uuid"],
         "name": record["name"], "status": record["status"]},
        stream,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
}

create_source_snapshot() {
  local destination="$1" manifest="$2"
  mkdir -m 0700 -- "${destination}"
  local file
  for file in Cargo.toml Cargo.lock README.md SECURITY.md .gitignore build.rs; do
    [[ -f "${REPO_ROOT}/${file}" && ! -L "${REPO_ROOT}/${file}" ]] \
      || return 1
    cp -p -- "${REPO_ROOT}/${file}" "${destination}/${file}"
  done
  local directory
  for directory in .cargo configs crates scripts tests deploy examples \
    experiments docs; do
    [[ -d "${REPO_ROOT}/${directory}" && ! -L "${REPO_ROOT}/${directory}" ]] \
      || return 1
    mkdir -p -- "${destination}/${directory}"
    rsync -a --exclude='results/' \
      "${REPO_ROOT}/${directory}/" "${destination}/${directory}/"
  done
  /usr/bin/python3 -I -S - "${destination}" "${manifest}" <<'PY'
import hashlib
import os
import stat
import sys
root, output = sys.argv[1:]
rows = []
for directory, names, files in os.walk(root, topdown=True, followlinks=False):
    names.sort()
    files.sort()
    for name in names:
        path = os.path.join(directory, name)
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SystemExit(f"source snapshot contains unsafe directory: {path}")
    for name in files:
        path = os.path.join(directory, name)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SystemExit(f"source snapshot contains non-regular file: {path}")
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        relative = os.path.relpath(path, root)
        if "\n" in relative or "\r" in relative or "\\" in relative:
            raise SystemExit("unsafe source snapshot path")
        rows.append((relative, digest.hexdigest()))
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(output, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
    for relative, digest in sorted(rows):
        stream.write(f"{digest}  {relative}\n")
    stream.flush()
    os.fsync(stream.fileno())
print(len(rows))
PY
}

write_source_metrics() {
  local source="$1" output="$2"
  /usr/bin/python3 -I -S - "${source}" "${output}" <<'PY'
import os
import sys
root, output = sys.argv[1:]
groups = {
    ".rs": "rust",
    ".sh": "shell",
    ".ps1": "powershell",
    ".py": "python",
    ".toml": "toml",
}
counts = {name: {"files": 0, "lines": 0, "bytes": 0}
          for name in sorted(set(groups.values()))}
all_files = 0
all_bytes = 0
text_files = 0
text_lines = 0
for directory, names, files in os.walk(root):
    names.sort()
    files.sort()
    for name in files:
        path = os.path.join(directory, name)
        with open(path, "rb") as stream:
            data = stream.read()
        size = len(data)
        lines = data.count(b"\n") + int(bool(data) and not data.endswith(b"\n"))
        all_files += 1
        all_bytes += size
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            if b"\0" not in data:
                text_files += 1
                text_lines += lines
        group = groups.get(os.path.splitext(name)[1].lower())
        if group is not None:
            counts[group]["files"] += 1
            counts[group]["lines"] += lines
            counts[group]["bytes"] += size
code_groups = ("rust", "shell", "powershell", "python")
code_files = sum(counts[name]["files"] for name in code_groups)
code_lines = sum(counts[name]["lines"] for name in code_groups)
code_bytes = sum(counts[name]["bytes"] for name in code_groups)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(output, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
    stream.write("schema_version=1\n")
    stream.write(
        "physical_line_definition=newline_count_plus_unterminated_final_line\n"
    )
    stream.write(f"snapshot_files={all_files}\n")
    stream.write(f"snapshot_bytes={all_bytes}\n")
    stream.write(f"utf8_text_files={text_files}\n")
    stream.write(f"utf8_text_physical_lines={text_lines}\n")
    for name in sorted(counts):
        stream.write(f"{name}_files={counts[name]['files']}\n")
        stream.write(f"{name}_physical_lines={counts[name]['lines']}\n")
        stream.write(f"{name}_bytes={counts[name]['bytes']}\n")
    stream.write(f"code_files={code_files}\n")
    stream.write(f"code_physical_lines={code_lines}\n")
    stream.write(f"code_bytes={code_bytes}\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
}

validate_guest_source_manifest() {
  local clone_id="$1" source="$2" manifest="$3" output="$4"
  capture_command "${HOST_TIMEOUT}" "${output}" \
    orb -m "${clone_id}" /usr/bin/python3 -I -S - \
    "${source}" "${manifest}" <<'PY'
import hashlib
import os
import stat
import sys
root, manifest = sys.argv[1:]
expected = {}
with open(manifest, "r", encoding="utf-8") as stream:
    for line in stream:
        digest, relative = line.rstrip("\n").split("  ", 1)
        if relative in expected:
            raise SystemExit("duplicate manifest path")
        expected[relative] = digest
actual = {}
for directory, names, files in os.walk(root):
    names.sort()
    files.sort()
    for name in names:
        path = os.path.join(directory, name)
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SystemExit(f"unsafe guest source directory: {path}")
    for name in files:
        path = os.path.join(directory, name)
        info = os.lstat(path)
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_nlink != 1):
            raise SystemExit(f"unsafe guest source file: {path}")
        relative = os.path.relpath(path, root)
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        actual[relative] = digest.hexdigest()
if actual != expected:
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    changed = sorted(key for key in expected.keys() & actual.keys()
                     if expected[key] != actual[key])
    raise SystemExit(
        f"source manifest mismatch missing={missing[:5]} "
        f"extra={extra[:5]} changed={changed[:5]}"
    )
print(f"manifest_entries={len(actual)}")
print("guest_source_manifest=valid")
PY
}

parse_test_summary() {
  local log="$1" output="$2" profile="$3"
  /usr/bin/python3 -I -S - "${log}" "${output}" "${profile}" <<'PY'
import os
import re
import sys
log, output, profile = sys.argv[1:]
pattern = re.compile(
    r"test result: (ok|FAILED)\. "
    r"(\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out"
)
blocks = []
with open(log, "r", encoding="utf-8", errors="replace") as stream:
    for line in stream:
        match = pattern.search(line)
        if match:
            blocks.append((match.group(1), *(int(value) for value in match.groups()[1:])))
if not blocks:
    raise SystemExit("cargo test output contains no result blocks")
if any(block[0] != "ok" or block[2] != 0 for block in blocks):
    raise SystemExit("cargo test output contains a failed result block")
passed = sum(block[1] for block in blocks)
failed = sum(block[2] for block in blocks)
ignored = sum(block[3] for block in blocks)
measured = sum(block[4] for block in blocks)
filtered = sum(block[5] for block in blocks)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(output, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
    stream.write("schema_version=1\n")
    stream.write(f"profile={profile}\n")
    stream.write(f"result_blocks={len(blocks)}\n")
    stream.write(f"passed={passed}\n")
    stream.write(f"failed={failed}\n")
    stream.write(f"ignored={ignored}\n")
    stream.write(f"measured={measured}\n")
    stream.write(f"filtered_out={filtered}\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
}

parse_metadata() {
  local metadata="$1" output="$2"
  /usr/bin/python3 -I -S - "${metadata}" "${output}" <<'PY'
import json
import os
import sys
metadata, output = sys.argv[1:]
with open(metadata, "r", encoding="utf-8") as stream:
    document = json.load(stream)
packages = document.get("packages")
members = document.get("workspace_members")
resolve = document.get("resolve")
if type(packages) is not list or type(members) is not list or type(resolve) is not dict:
    raise SystemExit("cargo metadata schema is incomplete")
targets = sum(len(package.get("targets", [])) for package in packages)
nodes = resolve.get("nodes")
if type(nodes) is not list:
    raise SystemExit("cargo metadata resolve nodes are absent")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(output, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
    stream.write("schema_version=1\n")
    stream.write(f"packages={len(packages)}\n")
    stream.write(f"workspace_members={len(members)}\n")
    stream.write(f"targets={targets}\n")
    stream.write(f"resolve_nodes={len(nodes)}\n")
PY
}

parse_environment() {
  local environment="$1" output="$2"
  /usr/bin/python3 -I -S - "${environment}" "${output}" <<'PY'
import os
import re
import sys
environment, output = sys.argv[1:]
with open(environment, "r", encoding="utf-8", errors="strict") as stream:
    text = stream.read()
architectures = re.findall(r"^kernel_arch=(\S+)$", text, re.MULTILINE)
hosts = re.findall(r"^host: (\S+)$", text, re.MULTILINE)
identities = re.findall(
    r"^uid=(\d+)\(([^)]+)\) gid=(\d+)\(([^)]+)\)(?: groups=.*)?$",
    text,
    re.MULTILINE,
)
if architectures != ["aarch64"]:
    raise SystemExit(f"unexpected kernel architecture evidence: {architectures!r}")
if hosts != ["aarch64-unknown-linux-gnu"]:
    raise SystemExit(f"unexpected Rust host evidence: {hosts!r}")
if len(identities) != 1:
    raise SystemExit("guest identity evidence is absent or ambiguous")
uid, user, gid, group = identities[0]
if int(uid) == 0 or int(gid) == 0:
    raise SystemExit("Cargo/shell gates would run with root identity")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(output, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
    stream.write("schema_version=1\n")
    stream.write("kernel_arch=aarch64\n")
    stream.write("rust_host=aarch64-unknown-linux-gnu\n")
    stream.write(f"guest_uid={uid}\n")
    stream.write(f"guest_user={user}\n")
    stream.write(f"guest_gid={gid}\n")
    stream.write(f"guest_group={group}\n")
    stream.write("guest_privilege=unprivileged\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
}

validate_result_tree() {
  local root="$1"
  /usr/bin/python3 -I -S - "${root}" <<'PY'
import os
import stat
import sys
root = sys.argv[1]
if not os.path.isdir(root) or os.path.islink(root):
    raise SystemExit("result root is unsafe")
for directory, names, files in os.walk(root, topdown=True, followlinks=False):
    for name in names + files:
        path = os.path.join(directory, name)
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            raise SystemExit(f"result contains symlink: {path}")
        if not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode):
            raise SystemExit(f"result contains special entry: {path}")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise SystemExit(f"result contains multiply-linked file: {path}")
PY
}

scan_result_for_private_material() {
  local root="$1" output="$2"
  /usr/bin/python3 -I -S - "${root}" "${output}" <<'PY'
import os
import re
import sys
root, output = sys.argv[1:]
forbidden_names = {
    "client-credential.json", "client-enrollment.json",
    "client-allowlist.json", "server-keys.json", "reality.key",
}
patterns = [
    re.compile(rb'"(?:ed25519_seed|private_seed|psk|secret_key)"\s*:'),
]
checked = 0
for directory, names, files in os.walk(root):
    for name in files:
        if name == os.path.basename(output):
            continue
        if name in forbidden_names:
            raise SystemExit(f"forbidden private filename in evidence: {name}")
        path = os.path.join(directory, name)
        with open(path, "rb") as stream:
            data = stream.read(32 * 1024 * 1024 + 1)
        if len(data) <= 32 * 1024 * 1024:
            for pattern in patterns:
                if pattern.search(data):
                    raise SystemExit(f"private-material JSON key in evidence: {path}")
        checked += 1
with open(output, "x", encoding="ascii", newline="\n") as stream:
    stream.write("private_material_scan=valid\n")
    stream.write(f"files_scanned={checked}\n")
PY
}

write_checksums() {
  local root="$1"
  /usr/bin/python3 -I -S - "${root}" <<'PY'
import hashlib
import os
import sys
root = sys.argv[1]
output = os.path.join(root, "checksums.sha256")
rows = []
for directory, names, files in os.walk(root):
    names.sort()
    files.sort()
    for name in files:
        path = os.path.join(directory, name)
        if path == output or name == "checksum-verification.log":
            continue
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        rows.append((os.path.relpath(path, root), digest.hexdigest()))
with open(output, "x", encoding="utf-8", newline="\n") as stream:
    for relative, digest in sorted(rows):
        stream.write(f"{digest}  {relative}\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
  (cd -- "${root}" && sha256sum -c checksums.sha256)
}

# Invoked from the EXIT cleanup path, which ShellCheck cannot follow through trap.
# shellcheck disable=SC2329
safe_remove_work_root() {
  local root="$1" token="$2"
  /usr/bin/python3 -I -S - "${root}" "${REPO_ROOT}/target" "${token}" <<'PY'
import os
import stat
import sys
root, target_root, token = sys.argv[1:]
real_root = os.path.realpath(root)
real_target = os.path.realpath(target_root)
if os.path.dirname(real_root) != real_target:
    raise SystemExit("work root escaped repository target")
info = os.lstat(real_root)
if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
    raise SystemExit("work root is unsafe")
marker = os.path.join(real_root, "owner")
marker_info = os.lstat(marker)
if (not stat.S_ISREG(marker_info.st_mode) or marker_info.st_nlink != 1
        or stat.S_IMODE(marker_info.st_mode) != 0o600):
    raise SystemExit("work owner marker is unsafe")
with open(marker, "r", encoding="ascii") as stream:
    if stream.read() != token + "\n":
        raise SystemExit("work owner token mismatch")
PY
  rm -rf -- "${root}"
}

run_self_test() {
  local actual count dependency expected temporary
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/shadowpipe-arm64-selftest.XXXXXX")"
  trap 'rm -rf -- "${temporary}"' RETURN
  for dependency in \
    "${GUEST_REQUIRED_TOOLS[@]}" "${GUEST_BUILD_PACKAGES[@]}"; do
    [[ "${dependency}" != shellcheck ]] \
      || die 1 "ShellCheck leaked into guest package/tool dependencies"
  done
  for expected in "${REQUIRED_RUNNER_SELFTESTS[@]}"; do
    count=0
    for actual in \
      "${HOST_RUNNER_SELFTESTS[@]}" "${GUEST_RUNNER_SELFTESTS[@]}"; do
      [[ "${actual}" == "${expected}" ]] && count=$((count + 1))
    done
    [[ "${count}" == 1 ]] \
      || die 1 "required runner self-test is dropped or duplicated: ${expected}"
  done
  for actual in \
    "${HOST_RUNNER_SELFTESTS[@]}" "${GUEST_RUNNER_SELFTESTS[@]}"; do
    count=0
    for expected in "${REQUIRED_RUNNER_SELFTESTS[@]}"; do
      [[ "${actual}" == "${expected}" ]] && count=$((count + 1))
    done
    [[ "${count}" == 1 ]] \
      || die 1 "runner self-test partition contains an unexpected entry: ${actual}"
  done
  validate_magic 0x50334852
  if validate_magic 0x100000000 2>/dev/null; then
    die 1 "oversized magic passed validation"
  fi
  self_test_singbox_observer "${temporary}/singbox-observer"
  mkdir -p "${temporary}/result"
  printf 'safe\n' >"${temporary}/result/file"
  printf 'stdin-transfer\n' >"${temporary}/stdin-input"
  capture_command_stdin \
    "${HOST_TIMEOUT}" "${temporary}/stdin-output" \
    "${temporary}/stdin-input" /bin/sh -c 'cat'
  bounded_cmp "${temporary}/stdin-input" "${temporary}/stdin-output"
  mkdir -p "${temporary}/metrics"
  printf 'fn main() {}\n// two\n' >"${temporary}/metrics/main.rs"
  printf '#!/usr/bin/env bash\n' >"${temporary}/metrics/check.sh"
  write_source_metrics \
    "${temporary}/metrics" "${temporary}/source-metrics.env"
  grep -qx 'snapshot_files=2' "${temporary}/source-metrics.env"
  grep -qx 'code_physical_lines=3' "${temporary}/source-metrics.env"
  {
    printf 'kernel_arch=aarch64\n'
    printf 'uid=501(billy) gid=20(staff) groups=20(staff)\n'
    printf 'host: aarch64-unknown-linux-gnu\n'
  } >"${temporary}/environment.txt"
  parse_environment \
    "${temporary}/environment.txt" "${temporary}/environment.env"
  grep -qx 'guest_privilege=unprivileged' "${temporary}/environment.env"
  {
    printf 'kernel_arch=aarch64\n'
    printf 'uid=0(root) gid=0(root) groups=0(root)\n'
    printf 'host: aarch64-unknown-linux-gnu\n'
  } >"${temporary}/root-environment.txt"
  if parse_environment \
    "${temporary}/root-environment.txt" "${temporary}/root-environment.env" \
    2>/dev/null; then
    die 1 "root guest identity passed environment validation"
  fi
  scan_result_for_private_material \
    "${temporary}/result" "${temporary}/result/private-material-scan.env"
  validate_result_tree "${temporary}/result"
  write_checksums "${temporary}/result" >/dev/null
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "${BASH_SOURCE[0]}"
    printf 'SELFTEST host-shellcheck: PASS\n'
  else
    printf 'SELFTEST host-shellcheck: EXTERNAL_GATE\n'
  fi
  printf 'SELFTEST PASS\n'
}

if [[ "${1:-}" == "--self-test" ]]; then
  run_self_test
  exit 0
fi

[[ "$(uname -s)" == Darwin ]] \
  || die "${EX_USAGE}" "host mode requires macOS"
[[ "${SHADOWPIPE_DISPOSABLE_ARM64_CURRENT:-}" == 1 ]] \
  || die "${EX_USAGE}" "set SHADOWPIPE_DISPOSABLE_ARM64_CURRENT=1"
[[ "$#" -le 1 ]] || { usage >&2; exit "${EX_USAGE}"; }

for tool in timeout orb orbctl prlctl rsync tar sha256sum openssl git \
  pgrep ps stat sort awk sed grep rg shellcheck /usr/bin/python3; do
  command -v "${tool}" >/dev/null \
    || die "${EX_UNAVAILABLE}" "missing host dependency: ${tool}"
done

source_vm="$(sanitize_component "${1:-${SOURCE_DEFAULT}}")" \
  || die "${EX_USAGE}" "unsafe source VM name"
[[ "${source_vm}" == "${SOURCE_DEFAULT}" ]] \
  || die "${EX_USAGE}" "only stopped source VM ${SOURCE_DEFAULT} is allowed"
magic="${SHADOWPIPE_MAGIC:-${MAGIC_DEFAULT}}"
validate_magic "${magic}" \
  || die "${EX_USAGE}" "SHADOWPIPE_MAGIC must be one explicit u32"

mkdir -p -- "${RESULT_ROOT}" "${REPO_ROOT}/target"
[[ -d "${RESULT_ROOT}" && ! -L "${RESULT_ROOT}" ]] \
  || die "${EX_NOPERM}" "unsafe result root"
[[ -d "${REPO_ROOT}/target" && ! -L "${REPO_ROOT}/target" ]] \
  || die "${EX_NOPERM}" "unsafe target root"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="${timestamp}-linux-arm64-current"
clone_vm="spa-$(printf '%s-%s' "${timestamp}" "$$" | tr '[:upper:]' '[:lower:]')"
ownership_token="$(openssl rand -hex 32)"
result_dir="${RESULT_ROOT}/${run_id}"
work_root="${REPO_ROOT}/target/portability-${run_id}"
source_snapshot="${work_root}/source"
source_manifest="${result_dir}/source-files.sha256"
source_archive="${work_root}/source.tar"
host_script_list="${work_root}/host-scripts.list0"
guest_owner_dir="/tmp/shadowpipe-portability-owner"
guest_owner_marker="${guest_owner_dir}/${clone_vm}.owner"

[[ ! -e "${result_dir}" && ! -L "${result_dir}" ]] \
  || die "${EX_USAGE}" "generated result directory already exists"
mkdir -m 0700 -- "${result_dir}" "${work_root}"
printf '%s\n' "${ownership_token}" >"${work_root}/owner"
chmod 0600 "${work_root}/owner"
mkdir -p -- "${result_dir}/orb" "${result_dir}/mac-before" \
  "${result_dir}/mac-after" "${result_dir}/cargo" \
  "${result_dir}/shell" "${result_dir}/selftests" "${result_dir}/setup"

{
  printf 'schema_version=1\n'
  printf 'run_id=%s\n' "${run_id}"
  printf 'source_vm=%s\n' "${source_vm}"
  printf 'clone_vm=%s\n' "${clone_vm}"
  printf 'shadowpipe_magic=%s\n' "${magic}"
  printf 'guest_network_privilege=unprivileged_only\n'
  printf 'shellcheck_execution=macos_host_frozen_snapshot\n'
  printf 'guest_shellcheck_required=false\n'
  printf 'bash_n_execution=native_linux_arm64_guest\n'
  printf 'host_runner_selftests=windows_parallels\n'
  printf 'guest_runner_selftests=portability_phase3_full_tun_reboot\n'
  printf 'mac_network_commands=false\n'
  printf 'windows_vm_action=none\n'
  printf 'field_evidence=false\n'
} >"${result_dir}/run-contract.env"

lock_dir=''
source_orb_id=''
clone_orb_id=''
clone_attempted=0
clone_created=0
guest_home=''
guest_root=''
source_status=failed
environment_status=failed
format_status=failed
metadata_status=failed
test_no_default_status=failed
test_all_features_status=failed
clippy_no_default_status=failed
clippy_all_features_status=failed
host_shellcheck_status=failed
guest_bash_n_status=failed
shell_status=failed
host_runner_selftests_status=failed
guest_runner_selftests_status=failed
runner_selftests_status=failed
host_script_count=''
cache_warmup_performed=false
package_install_performed=false
lifecycle_lock_status=not_acquired
clone_cleanup_status=failed
windows_state_status=failed
host_safety_status=failed
cleanup_running=0

# shellcheck disable=SC2329
host_cleanup() {
  local incoming=$?
  (( cleanup_running == 0 )) || exit 1
  cleanup_running=1
  trap - EXIT INT TERM HUP
  set +e
  local final_status="${incoming}" cleanup_status=valid

  if (( clone_attempted != 0 )) && [[ -z "${clone_orb_id}" ]]; then
    if clone_orb_id="$(capture_orb_identity \
      "${clone_vm}" "${clone_vm}" '' '' \
      "${result_dir}/orb/clone-cleanup-late-bind")"; then
      clone_created=1
    elif orb_exact_absent \
      "${clone_vm}" "${result_dir}/orb/clone-cleanup-late-absence"; then
      clone_cleanup_status=valid
    else
      cleanup_status=failed
    fi
  fi

  if (( clone_created != 0 )) && [[ -n "${clone_orb_id}" ]]; then
    local state=''
    if capture_orb_identity \
      "${clone_vm}" "${clone_vm}" "${clone_orb_id}" '' \
      "${result_dir}/orb/clone-before-delete" >/dev/null 2>&1; then
      state="$(/usr/bin/python3 -I -S -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["state"])' \
        "${result_dir}/orb/clone-before-delete.identity.json")"
      if [[ "${state}" != running ]]; then
        capture_optional "${ORB_START_TIMEOUT}" \
          "${result_dir}/orb/start-for-owner-verification.log" \
          orbctl start "${clone_orb_id}"
        for attempt in $(seq 1 "${ORB_START_TIMEOUT}"); do
          if capture_orb_identity \
            "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
            "${result_dir}/orb/clone-owner-wait-${attempt}" >/dev/null 2>&1; then
            state=running
            break
          fi
          sleep 1
        done
      fi
      if [[ "${state}" == running ]] \
        && capture_command "${HOST_TIMEOUT}" \
          "${result_dir}/orb/guest-owner-final.txt" \
          orb -m "${clone_orb_id}" cat "${guest_owner_marker}" \
        && [[ "$(<"${result_dir}/orb/guest-owner-final.txt")" == "${ownership_token}" ]] \
        && capture_orb_identity \
          "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
          "${result_dir}/orb/clone-owner-final" >/dev/null 2>&1; then
        if [[ -n "${guest_root}" ]]; then
          capture_optional "${HOST_TIMEOUT}" \
            "${result_dir}/orb/guest-scratch-before-delete.txt" \
            orb -m "${clone_orb_id}" bash -lc \
            "du -sh '${guest_root}' 2>/dev/null || true; find '${guest_root}' -maxdepth 2 -type d -print 2>/dev/null | sort || true"
        fi
        capture_optional "${ORB_STOP_TIMEOUT}" \
          "${result_dir}/orb/clone-stop.log" orbctl stop "${clone_orb_id}"
        if capture_orb_identity \
          "${clone_vm}" "${clone_vm}" "${clone_orb_id}" stopped \
          "${result_dir}/orb/clone-before-delete-fresh-name-bind" >/dev/null 2>&1 \
          && capture_command "${ORB_DELETE_TIMEOUT}" \
            "${result_dir}/orb/clone-delete.log" \
            orbctl delete -f "${clone_vm}"; then
          printf '%s\n' \
            'delete_selector=name_after_fresh_name_to_bound_id_validation_due_orbstack_2_2_1_id_delete_panic' \
            >"${result_dir}/orb/delete-addressing.env"
          local quiescent=1 second
          : >"${result_dir}/orb/post-delete-quiescence.tsv"
          orb_exact_absent \
            "${clone_vm}" "${result_dir}/orb/absence-name-first" \
            || quiescent=0
          orb_exact_absent \
            "${clone_orb_id}" "${result_dir}/orb/absence-id-first" \
            || quiescent=0
          for second in $(seq 1 "${QUIESCENCE_SECONDS}"); do
            if orb_absent_quiet "${clone_vm}" \
              && orb_absent_quiet "${clone_orb_id}"; then
              printf '%s\tabsent\n' "${second}" \
                >>"${result_dir}/orb/post-delete-quiescence.tsv"
            else
              printf '%s\tpresent_or_uncertain\n' "${second}" \
                >>"${result_dir}/orb/post-delete-quiescence.tsv"
              quiescent=0
            fi
            sleep 1
          done
          orb_exact_absent \
            "${clone_vm}" "${result_dir}/orb/absence-name-final" \
            || quiescent=0
          orb_exact_absent \
            "${clone_orb_id}" "${result_dir}/orb/absence-id-final" \
            || quiescent=0
          if (( quiescent != 0 )); then
            clone_cleanup_status=valid
          else
            cleanup_status=failed
          fi
        else
          cleanup_status=failed
        fi
      else
        cleanup_status=failed
      fi
    else
      cleanup_status=failed
    fi
  elif (( clone_attempted == 0 )); then
    clone_cleanup_status=valid
  fi

  if [[ -n "${source_orb_id}" ]]; then
    capture_orb_identity \
      "${source_vm}" "${source_vm}" "${source_orb_id}" stopped \
      "${result_dir}/orb/source-final" >/dev/null 2>&1 \
      || cleanup_status=failed
  fi
  capture_parallels_suspended "${result_dir}/windows-final" \
    && windows_state_status=valid \
    || cleanup_status=failed

  if [[ -e "${work_root}" || -L "${work_root}" ]]; then
    safe_remove_work_root "${work_root}" "${ownership_token}" \
      || cleanup_status=failed
  fi
  [[ ! -e "${work_root}" && ! -L "${work_root}" ]] \
    || cleanup_status=failed

  if snapshot_macos_singbox "${result_dir}/mac-after" \
    && compare_macos_singbox \
      "${result_dir}/mac-before" "${result_dir}/mac-after"; then
    host_safety_status=valid
  else
    cleanup_status=failed
  fi

  if [[ -n "${lock_dir}" ]]; then
    if release_lifecycle_lock "${lock_dir}" "${ownership_token}"; then
      lifecycle_lock_status=released
      lock_dir=''
    else
      lifecycle_lock_status=release_failed
      cleanup_status=failed
    fi
  fi

  if [[ "${clone_cleanup_status}" != valid \
    || "${windows_state_status}" != valid \
    || "${lifecycle_lock_status}" != released ]]; then
    cleanup_status=failed
  fi

  local overall=failed
  if [[ "${source_status}" == valid \
    && "${environment_status}" == valid \
    && "${format_status}" == valid \
    && "${metadata_status}" == valid \
    && "${test_no_default_status}" == valid \
    && "${test_all_features_status}" == valid \
    && "${clippy_no_default_status}" == valid \
    && "${clippy_all_features_status}" == valid \
    && "${host_shellcheck_status}" == valid \
    && "${guest_bash_n_status}" == valid \
    && "${shell_status}" == valid \
    && "${host_runner_selftests_status}" == valid \
    && "${guest_runner_selftests_status}" == valid \
    && "${runner_selftests_status}" == valid \
    && "${clone_cleanup_status}" == valid \
    && "${windows_state_status}" == valid \
    && "${host_safety_status}" == valid \
    && "${lifecycle_lock_status}" == released \
    && "${cleanup_status}" == valid ]]; then
    overall=valid
    final_status=0
  else
    (( final_status != 0 )) || final_status=1
  fi

  {
    printf 'schema_version=%s\n' "${STATUS_SCHEMA_VERSION}"
    printf 'run_id=%s\n' "${run_id}"
    printf 'source_status=%s\n' "${source_status}"
    printf 'environment_status=%s\n' "${environment_status}"
    printf 'format_status=%s\n' "${format_status}"
    printf 'metadata_status=%s\n' "${metadata_status}"
    printf 'test_no_default_status=%s\n' "${test_no_default_status}"
    printf 'test_all_features_status=%s\n' "${test_all_features_status}"
    printf 'clippy_no_default_status=%s\n' "${clippy_no_default_status}"
    printf 'clippy_all_features_status=%s\n' "${clippy_all_features_status}"
    printf 'host_shellcheck_status=%s\n' "${host_shellcheck_status}"
    printf 'host_shellcheck_scope=macos_host_frozen_snapshot\n'
    printf 'guest_bash_n_status=%s\n' "${guest_bash_n_status}"
    printf 'guest_bash_n_scope=native_linux_arm64_guest\n'
    printf 'guest_shellcheck_required=false\n'
    printf 'shell_status=%s\n' "${shell_status}"
    printf 'host_runner_selftests_status=%s\n' \
      "${host_runner_selftests_status}"
    printf 'host_runner_selftests_scope=macos_host_frozen_snapshot\n'
    printf 'host_runner_selftests_count=%s\n' \
      "${#HOST_RUNNER_SELFTESTS[@]}"
    printf 'guest_runner_selftests_status=%s\n' \
      "${guest_runner_selftests_status}"
    printf 'guest_runner_selftests_scope=native_linux_arm64_guest\n'
    printf 'guest_runner_selftests_count=%s\n' \
      "${#GUEST_RUNNER_SELFTESTS[@]}"
    printf 'runner_selftests_status=%s\n' "${runner_selftests_status}"
    printf 'clone_cleanup_status=%s\n' "${clone_cleanup_status}"
    printf 'windows_state_status=%s\n' "${windows_state_status}"
    printf 'host_safety_status=%s\n' "${host_safety_status}"
    printf 'lifecycle_lock_status=%s\n' "${lifecycle_lock_status}"
    printf 'evidence_status=valid\n'
    printf 'cache_warmup_performed=%s\n' "${cache_warmup_performed}"
    printf 'package_install_performed=%s\n' "${package_install_performed}"
    printf 'privileged_network_mutation=false\n'
    printf 'field_evidence=false\n'
    printf 'overall_status=%s\n' "${overall}"
  } >"${result_dir}/status.env"

  local no_default_counts='unavailable' all_features_counts='unavailable'
  local source_code_lines='unavailable' source_rust_lines='unavailable'
  if [[ -f "${result_dir}/cargo/test-no-default.env" ]]; then
    no_default_counts="$(
      awk -F= '$1 == "passed" || $1 == "failed" || $1 == "ignored" {
        printf "%s%s=%s", separator, $1, $2; separator=", "
      }' "${result_dir}/cargo/test-no-default.env"
    )"
  fi
  if [[ -f "${result_dir}/cargo/test-all-features.env" ]]; then
    all_features_counts="$(
      awk -F= '$1 == "passed" || $1 == "failed" || $1 == "ignored" {
        printf "%s%s=%s", separator, $1, $2; separator=", "
      }' "${result_dir}/cargo/test-all-features.env"
    )"
  fi
  if [[ -f "${result_dir}/source-metrics.env" ]]; then
    source_code_lines="$(awk -F= \
      '$1 == "code_physical_lines" {print $2}' \
      "${result_dir}/source-metrics.env")"
    source_rust_lines="$(awk -F= \
      '$1 == "rust_physical_lines" {print $2}' \
      "${result_dir}/source-metrics.env")"
  fi
  {
    printf '# Native Linux ARM64 current-source portability refresh\n\n'
    # Backticks are literal Markdown, while printf substitutes the argument.
    # shellcheck disable=SC2016
    printf -- '- Run: `%s`\n' "${run_id}"
    printf -- '- Snapshot: actual dirty-worktree contents selected for build/test, per-file SHA-256 manifest retained.\n'
    printf -- '- Frozen source size: %s code physical lines, including %s Rust lines; exact definition and per-language counts are in source-metrics.env.\n' \
      "${source_code_lines}" "${source_rust_lines}"
    printf -- '- no-default workspace/all-targets: %s.\n' "${no_default_counts}"
    printf -- '- all-features workspace/all-targets: %s.\n' "${all_features_counts}"
    printf -- '- Strict Clippy: no-default=%s, all-features=%s.\n' \
      "${clippy_no_default_status}" "${clippy_all_features_status}"
    printf -- '- Shell split gate: host ShellCheck on the frozen snapshot=%s; native Linux ARM64 guest bash -n=%s; guest ShellCheck package is not required.\n' \
      "${host_shellcheck_status}" "${guest_bash_n_status}"
    printf -- '- Runner self-test partition: macOS-host Windows/Parallels=%s (%d); native Linux ARM64 portability/Phase3/full-TUN/reboot=%s (%d); every required runner appears exactly once.\n' \
      "${host_runner_selftests_status}" "${#HOST_RUNNER_SELFTESTS[@]}" \
      "${guest_runner_selftests_status}" "${#GUEST_RUNNER_SELFTESTS[@]}"
    printf -- '- Format/metadata/shell/self-tests: %s/%s/%s/%s.\n' \
      "${format_status}" "${metadata_status}" \
      "${shell_status}" "${runner_selftests_status}"
    # Backticks are literal Markdown, while printf substitutes the argument.
    # shellcheck disable=SC2016
    printf -- '- Final Cargo gates used `--locked --offline`; cache warmup performed: `%s`.\n' \
      "${cache_warmup_performed}"
    # Backticks are literal Markdown, while printf substitutes the argument.
    # shellcheck disable=SC2016
    printf -- '- VM package/component installation performed: `%s`, only inside disposable clone.\n' \
      "${package_install_performed}"
    printf -- '- Scope: unprivileged CPU/filesystem portability only; no route, DNS, firewall, TUN, netns, qdisc, sysctl, or service mutation.\n'
    # Backticks are literal Markdown, while printf substitutes the argument.
    # shellcheck disable=SC2016
    printf -- '- Cleanup: clone ID/name absent for %d seconds, source `%s` stopped, Windows remained suspended, shared lifecycle lock released.\n' \
      "${QUIESCENCE_SECONDS}" "${source_vm}"
    printf -- '- macOS: live sing-box PID/start/argv/config/binary observed read-only and unchanged; no Mac network command executed.\n'
    printf -- '- Field evidence: false. This is native ARM64 portability evidence, not privileged networking or censorship evidence.\n'
    # Backticks are literal Markdown, while printf substitutes the argument.
    # shellcheck disable=SC2016
    printf -- '- Overall: `%s`.\n' "${overall}"
  } >"${result_dir}/RESULT.md"

  if ! validate_result_tree "${result_dir}" \
    || ! scan_result_for_private_material \
      "${result_dir}" "${result_dir}/private-material-scan.env" \
    || ! validate_result_tree "${result_dir}" \
    || ! write_checksums "${result_dir}" \
      >"${result_dir}/checksum-verification.log" 2>&1; then
    warn "evidence sealing failed"
    (( final_status != 0 )) || final_status=1
  fi
  if ! chmod -R a-w "${result_dir}" 2>/dev/null \
    || ! /usr/bin/python3 -I -S - "${result_dir}" <<'PY'
import os
import sys
root = sys.argv[1]
if os.lstat(root).st_mode & 0o222:
    raise SystemExit(f"sealed result root remains writable: {root}")
for directory, names, files in os.walk(root):
    for name in names + files:
        path = os.path.join(directory, name)
        if os.lstat(path).st_mode & 0o222:
            raise SystemExit(f"sealed result remains writable: {path}")
PY
  then
    warn "result permission sealing failed"
    (( final_status != 0 )) || final_status=1
  fi
  say "result: ${result_dir}"
  exit "${final_status}"
}
trap host_cleanup EXIT INT TERM HUP

lock_dir="$(acquire_lifecycle_lock "${ownership_token}")" \
  || die 75 "another Shadowpipe OrbStack lifecycle runner is active"
lifecycle_lock_status=held

source_orb_id="$(capture_orb_identity \
  "${source_vm}" "${source_vm}" '' stopped \
  "${result_dir}/orb/source-before")" \
  || die "${EX_UNAVAILABLE}" "cannot bind stopped source VM"
capture_parallels_suspended "${result_dir}/windows-before" \
  || die "${EX_UNAVAILABLE}" "Windows 11 must remain suspended"
orb_exact_absent "${clone_vm}" "${result_dir}/orb/clone-absence-before" \
  || die "${EX_USAGE}" "generated clone name already exists"
snapshot_macos_singbox "${result_dir}/mac-before" \
  || die "${EX_UNAVAILABLE}" "read-only sing-box baseline failed"

capture_command "${HOST_TIMEOUT}" "${result_dir}/git-status.txt" \
  git -C "${REPO_ROOT}" status --short --branch || true
capture_command "${HOST_TIMEOUT}" "${result_dir}/git-head.txt" \
  git -C "${REPO_ROOT}" rev-parse HEAD
capture_command "${HOST_TIMEOUT}" "${result_dir}/git-diff-stat.txt" \
  git -C "${REPO_ROOT}" diff --stat || true
capture_command "${HOST_TIMEOUT}" "${result_dir}/git-diff-numstat.txt" \
  git -C "${REPO_ROOT}" diff --numstat || true
capture_command "${HOST_TIMEOUT}" "${result_dir}/runner-selftest-host.txt" \
  /bin/bash "${BASH_SOURCE[0]}" --self-test

say "freezing actual dirty-worktree build/test inputs"
manifest_entries="$(create_source_snapshot "${source_snapshot}" "${source_manifest}")" \
  || die 1 "source snapshot failed"
[[ "${manifest_entries}" =~ ^[1-9][0-9]*$ ]] \
  || die 1 "source manifest entry count is invalid"
{
  printf 'schema_version=1\n'
  printf 'manifest_entries=%s\n' "${manifest_entries}"
  printf 'manifest_sha256=%s\n' \
    "$(sha256sum "${source_manifest}" | awk '{print $1}')"
  printf 'cargo_lock_sha256=%s\n' \
    "$(sha256sum "${source_snapshot}/Cargo.lock" | awk '{print $1}')"
} >"${result_dir}/source.env"
write_source_metrics \
  "${source_snapshot}" "${result_dir}/source-metrics.env"
metrics_snapshot_files="$(awk -F= '$1 == "snapshot_files" {print $2}' \
  "${result_dir}/source-metrics.env")"
[[ "${metrics_snapshot_files}" == "${manifest_entries}" ]] \
  || die 1 "source metrics and content manifest file counts disagree"

capture_command "${HOST_TIMEOUT}" \
  "${result_dir}/shell/host-shellcheck-version.txt" \
  shellcheck --version \
  || die 1 "host ShellCheck version capture failed"
# The single-quoted program is intentionally evaluated only by the child Bash.
# shellcheck disable=SC2016
capture_command "${SELFTEST_TIMEOUT}" \
  "${result_dir}/shell/host-shellcheck.log" \
  /usr/bin/env LC_ALL=C /bin/bash -c '
set -euo pipefail
source_root="$1"
script_list="$2"
cd "${source_root}"
find scripts tests deploy examples experiments \
  -path "*/results" -prune -o -type f -name "*.sh" -print0 \
  | sort -z >"${script_list}"
count="$(tr -cd "\0" <"${script_list}" | wc -c | tr -d " ")"
printf "script_count=%s\n" "${count}"
test "${count}" -gt 0
xargs -0 shellcheck -x <"${script_list}"
printf "shellcheck=valid\n"
tr "\0" "\n" <"${script_list}"
' host-shellcheck "${source_snapshot}" "${host_script_list}" \
  || die 1 "host ShellCheck failed on frozen source snapshot"
host_script_count="$(awk -F= '$1 == "script_count" {print $2; exit}' \
  "${result_dir}/shell/host-shellcheck.log")"
[[ "${host_script_count}" =~ ^[1-9][0-9]*$ ]] \
  || die 1 "host ShellCheck script count is invalid"
printf 'schema_version=1\nscript_count=%s\nscope=macos_host_frozen_snapshot\nshellcheck=valid\n' \
  "${host_script_count}" >"${result_dir}/shell/host-shellcheck.env"
host_shellcheck_status=valid

for runner in "${HOST_RUNNER_SELFTESTS[@]}"; do
  label="$(basename "${runner}" .sh)"
  capture_command "${SELFTEST_TIMEOUT}" \
    "${result_dir}/selftests/host-${label}.log" \
    /bin/bash "${source_snapshot}/${runner}" --self-test \
    || die 1 "macOS-host frozen runner self-test failed: ${runner}"
  grep -q 'PASS' "${result_dir}/selftests/host-${label}.log" \
    || die 1 "host runner self-test omitted PASS marker: ${runner}"
done
{
  printf 'schema_version=1\n'
  printf 'scope=macos_host_frozen_snapshot\n'
  printf 'runner_count=%s\n' "${#HOST_RUNNER_SELFTESTS[@]}"
  printf 'selftests=valid\n'
  for runner in "${HOST_RUNNER_SELFTESTS[@]}"; do
    printf 'runner=%s\n' "${runner}"
  done
} >"${result_dir}/selftests/host-status.env"
host_runner_selftests_status=valid

COPYFILE_DISABLE=1 tar -cf "${source_archive}" -C "${source_snapshot}" .
{
  printf 'archive_sha256=%s\n' "$(sha256sum "${source_archive}" | awk '{print $1}')"
  printf 'archive_size_bytes=%s\n' "$(stat -f '%z' "${source_archive}")"
} >"${result_dir}/source-archive.env"

say "cloning stopped ${source_vm} -> ${clone_vm}"
clone_attempted=1
capture_command "${CLONE_TIMEOUT}" "${result_dir}/orb/clone.log" \
  orbctl clone "${source_vm}" "${clone_vm}" \
  || die 1 "OrbStack clone failed"
clone_created=1
capture_orb_identity \
  "${source_vm}" "${source_vm}" "${source_orb_id}" stopped \
  "${result_dir}/orb/source-after-clone" >/dev/null \
  || die 1 "source VM changed during clone"
clone_orb_id="$(capture_orb_identity \
  "${clone_vm}" "${clone_vm}" '' stopped \
  "${result_dir}/orb/clone-after-clone")" \
  || die 1 "cannot bind clone opaque ID"
capture_orb_identity \
  "${clone_vm}" "${clone_vm}" "${clone_orb_id}" stopped \
  "${result_dir}/orb/clone-before-start" >/dev/null \
  || die 1 "clone identity changed before start"
capture_command "${ORB_START_TIMEOUT}" "${result_dir}/orb/clone-start.log" \
  orbctl start "${clone_orb_id}" \
  || die 1 "clone start failed"
for attempt in $(seq 1 "${ORB_START_TIMEOUT}"); do
  if capture_orb_identity \
    "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
    "${result_dir}/orb/clone-start-wait-${attempt}" >/dev/null 2>&1; then
    break
  fi
  (( attempt < ORB_START_TIMEOUT )) || die 1 "clone did not reach running"
  sleep 1
done

capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/owner-marker.log" \
  orb -m "${clone_orb_id}" bash -lc \
  "set -e; install -d -m 0700 '${guest_owner_dir}'; umask 077; test ! -e '${guest_owner_marker}'; printf '%s\\n' '${ownership_token}' >'${guest_owner_marker}'; chmod 0600 '${guest_owner_marker}'; test \"\$(cat '${guest_owner_marker}')\" = '${ownership_token}'" \
  || die "${EX_NOPERM}" "cannot establish guest owner marker"
capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/guest-home.txt" \
  orb -m "${clone_orb_id}" /usr/bin/python3 -I -S -c \
  'import os; print(os.path.expanduser("~"))'
guest_home="$(<"${result_dir}/orb/guest-home.txt")"
/usr/bin/python3 -I -S - "${guest_home}" <<'PY' \
  || die "${EX_NOPERM}" "guest home path is unsafe"
import os
import re
import sys
path = sys.argv[1]
if (not os.path.isabs(path) or not re.fullmatch(r"/[A-Za-z0-9._/-]+", path)
        or ".." in path.split("/") or path == "/"):
    raise SystemExit("unsafe guest home")
PY
guest_root="${guest_home}/.shadowpipe-arm64-${timestamp}"
guest_source="${guest_root}/source"
guest_target="${guest_root}/target"
guest_manifest="${guest_root}/source-files.sha256"

capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/guest-root-create.log" \
  orb -m "${clone_orb_id}" bash -lc \
  "set -e; umask 077; test ! -e '${guest_root}'; install -d -m 0700 '${guest_root}' '${guest_source}' '${guest_target}'; printf '%s\\n' '${ownership_token}' >'${guest_root}/owner'; chmod 0600 '${guest_root}/owner'"
capture_command_stdin \
  "${CLONE_TIMEOUT}" "${result_dir}/orb/source-push.log" \
  "${source_archive}" \
  orb -m "${clone_orb_id}" tar -xf - -C "${guest_source}" \
  || die 1 "source archive stream/extract failed"
capture_command_stdin \
  "${HOST_TIMEOUT}" "${result_dir}/orb/manifest-push.log" \
  "${source_manifest}" \
  orb -m "${clone_orb_id}" bash -lc \
  "set -e; umask 077; test ! -e '${guest_manifest}'; cat >'${guest_manifest}'; chmod 0600 '${guest_manifest}'" \
  || die 1 "source manifest stream failed"
validate_guest_source_manifest \
  "${clone_orb_id}" "${guest_source}" "${guest_manifest}" \
  "${result_dir}/source-guest-verification.env" \
  || die 1 "guest source manifest mismatch"
source_status=valid

say "checking guest toolchain and cache"
guest_required_tools="${GUEST_REQUIRED_TOOLS[*]}"
capture_command "${HOST_TIMEOUT}" "${result_dir}/setup/missing-tools.txt" \
  orb -m "${clone_orb_id}" bash -lc \
  "for tool in ${guest_required_tools}; do command -v \"\$tool\" >/dev/null 2>&1 || printf '%s\\n' \"\$tool\"; done"
if [[ -s "${result_dir}/setup/missing-tools.txt" ]]; then
  package_install_performed=true
  capture_command "${GUEST_SETUP_TIMEOUT}" "${result_dir}/setup/pacman.log" \
    orb -m "${clone_orb_id}" -u root pacman -Sy --noconfirm --needed \
    "${GUEST_BUILD_PACKAGES[@]}" \
    || die 1 "guest build dependency installation failed"
fi
# The single-quoted guest program is intentionally opaque to the host shell.
# shellcheck disable=SC2016
capture_command "${HOST_TIMEOUT}" "${result_dir}/setup/missing-rust-components.txt" \
  orb -m "${clone_orb_id}" bash -lc \
  'for tool in rustfmt cargo-clippy; do command -v "$tool" >/dev/null 2>&1 || printf "%s\n" "$tool"; done'
if [[ -s "${result_dir}/setup/missing-rust-components.txt" ]]; then
  package_install_performed=true
  capture_command "${GUEST_SETUP_TIMEOUT}" \
    "${result_dir}/setup/rust-components.log" \
    orb -m "${clone_orb_id}" rustup component add rustfmt clippy \
    || die 1 "guest Rust component installation failed"
fi

capture_command "${HOST_TIMEOUT}" "${result_dir}/environment.txt" \
  orb -m "${clone_orb_id}" bash -lc \
  "set -e; printf 'kernel_arch='; uname -m; uname -a; id; rustc -Vv; cargo -V; rustfmt --version; cargo clippy -V; cmake --version | head -1; ninja --version; clang --version | head -1; go version; perl -v | sed -n '2p'; pkg-config --version; nasm -v; gcc --version | head -1; make --version | head -1; git --version; printf 'guest_source=%s\\nguest_target=%s\\n' '${guest_source}' '${guest_target}'"
parse_environment \
  "${result_dir}/environment.txt" "${result_dir}/environment.env" \
  || die 1 "guest is not unprivileged native Linux ARM64"
environment_status=valid

common_env="env LC_ALL=C SHADOWPIPE_MAGIC='${magic}' CARGO_TARGET_DIR='${guest_target}' CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=4 RUST_BACKTRACE=1"
if ! capture_command "${GUEST_SETUP_TIMEOUT}" \
  "${result_dir}/setup/cargo-fetch-offline-preflight.log" \
  orb -m "${clone_orb_id}" bash -lc \
  "cd '${guest_source}' && ${common_env} cargo fetch --locked --offline"; then
  cache_warmup_performed=true
  capture_command "${GUEST_SETUP_TIMEOUT}" \
    "${result_dir}/setup/cargo-fetch-online-warmup.log" \
    orb -m "${clone_orb_id}" bash -lc \
    "cd '${guest_source}' && env LC_ALL=C cargo fetch --locked" \
    || die 1 "guest Cargo cache warmup failed"
fi
capture_command "${GUEST_SETUP_TIMEOUT}" \
  "${result_dir}/setup/cargo-fetch-offline-final.log" \
  orb -m "${clone_orb_id}" bash -lc \
  "cd '${guest_source}' && ${common_env} cargo fetch --locked --offline" \
  || die 1 "final offline Cargo fetch proof failed"

say "running native ARM64 Cargo matrix"
capture_command "${CARGO_TIMEOUT}" "${result_dir}/cargo/fmt.log" \
  orb -m "${clone_orb_id}" bash -lc \
  "cd '${guest_source}' && ${common_env} cargo fmt --all -- --check" \
  || die 1 "cargo fmt failed"
format_status=valid

capture_command "${CARGO_TIMEOUT}" "${result_dir}/cargo/metadata.json" \
  orb -m "${clone_orb_id}" bash -lc \
  "cd '${guest_source}' && ${common_env} cargo metadata --locked --offline --format-version 1" \
  || die 1 "locked offline cargo metadata failed"
parse_metadata \
  "${result_dir}/cargo/metadata.json" "${result_dir}/cargo/metadata.env"
metadata_status=valid

capture_command "${CARGO_TIMEOUT}" "${result_dir}/cargo/test-no-default.log" \
  orb -m "${clone_orb_id}" bash -lc \
  "cd '${guest_source}' && ${common_env} cargo test --workspace --all-targets --no-default-features --locked --offline -- --test-threads=2" \
  || die 1 "no-default ARM64 workspace tests failed"
parse_test_summary \
  "${result_dir}/cargo/test-no-default.log" \
  "${result_dir}/cargo/test-no-default.env" no-default
test_no_default_status=valid

capture_command "${CARGO_TIMEOUT}" "${result_dir}/cargo/test-all-features.log" \
  orb -m "${clone_orb_id}" bash -lc \
  "cd '${guest_source}' && ${common_env} cargo test --workspace --all-targets --all-features --locked --offline -- --test-threads=2" \
  || die 1 "all-features ARM64 workspace tests failed"
parse_test_summary \
  "${result_dir}/cargo/test-all-features.log" \
  "${result_dir}/cargo/test-all-features.env" all-features
test_all_features_status=valid

capture_command "${CARGO_TIMEOUT}" "${result_dir}/cargo/clippy-no-default.log" \
  orb -m "${clone_orb_id}" bash -lc \
  "cd '${guest_source}' && ${common_env} cargo clippy --workspace --all-targets --no-default-features --locked --offline -- -D warnings" \
  || die 1 "no-default strict Clippy failed"
clippy_no_default_status=valid

capture_command "${CARGO_TIMEOUT}" "${result_dir}/cargo/clippy-all-features.log" \
  orb -m "${clone_orb_id}" bash -lc \
  "cd '${guest_source}' && ${common_env} cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings" \
  || die 1 "all-features strict Clippy failed"
clippy_all_features_status=valid

say "running shell and pure runner self-tests"
capture_command "${SELFTEST_TIMEOUT}" "${result_dir}/shell/guest-bash-n.log" \
  orb -m "${clone_orb_id}" bash -lc \
  "set -e; cd '${guest_source}'; find scripts tests deploy examples experiments -path '*/results' -prune -o -type f -name '*.sh' -print0 | sort -z >'${guest_root}/scripts.list0'; count=\$(tr -cd '\\0' <'${guest_root}/scripts.list0' | wc -c); printf 'script_count=%s\\n' \"\$count\"; test \"\$count\" -gt 0; xargs -0 -n1 bash -n <'${guest_root}/scripts.list0'; printf 'bash_n=valid\\n'; tr '\\0' '\\n' <'${guest_root}/scripts.list0'" \
  || die 1 "native ARM64 non-result bash syntax matrix failed"
script_count="$(awk -F= '$1 == "script_count" {print $2; exit}' \
  "${result_dir}/shell/guest-bash-n.log")"
[[ "${script_count}" =~ ^[1-9][0-9]*$ ]] \
  || die 1 "guest bash -n script count is invalid"
[[ "${script_count}" == "${host_script_count}" ]] \
  || die 1 "host ShellCheck and guest bash -n script counts disagree"
guest_bash_n_status=valid
printf 'schema_version=1\nscript_count=%s\nhost_shellcheck_scope=macos_host_frozen_snapshot\nhost_shellcheck=valid\nguest_bash_n_scope=native_linux_arm64_guest\nguest_bash_n=valid\nguest_shellcheck_required=false\n' \
  "${script_count}" >"${result_dir}/shell/status.env"
shell_status=valid

for runner in "${GUEST_RUNNER_SELFTESTS[@]}"; do
  label="$(basename "${runner}" .sh)"
  capture_command "${SELFTEST_TIMEOUT}" \
    "${result_dir}/selftests/guest-${label}.log" \
    orb -m "${clone_orb_id}" bash -lc \
    "cd '${guest_source}' && bash '${runner}' --self-test" \
    || die 1 "native ARM64 runner self-test failed: ${runner}"
  grep -q 'PASS' "${result_dir}/selftests/guest-${label}.log" \
    || die 1 "guest runner self-test omitted PASS marker: ${runner}"
done
{
  printf 'schema_version=1\n'
  printf 'scope=native_linux_arm64_guest\n'
  printf 'runner_count=%s\n' "${#GUEST_RUNNER_SELFTESTS[@]}"
  printf 'selftests=valid\n'
  for runner in "${GUEST_RUNNER_SELFTESTS[@]}"; do
    printf 'runner=%s\n' "${runner}"
  done
} >"${result_dir}/selftests/guest-status.env"
guest_runner_selftests_status=valid
printf 'schema_version=1\nrequired_runner_count=%s\nhost_runner_count=%s\nguest_runner_count=%s\npartition=valid\nselftests=valid\n' \
  "${#REQUIRED_RUNNER_SELFTESTS[@]}" \
  "${#HOST_RUNNER_SELFTESTS[@]}" \
  "${#GUEST_RUNNER_SELFTESTS[@]}" \
  >"${result_dir}/selftests/status.env"
runner_selftests_status=valid

validate_guest_source_manifest \
  "${clone_orb_id}" "${guest_source}" "${guest_manifest}" \
  "${result_dir}/source-guest-verification-final.env" \
  || die 1 "guest source changed during ARM64 matrix"

capture_command "${HOST_TIMEOUT}" \
  "${result_dir}/cargo-lock-guest.sha256" \
  orb -m "${clone_orb_id}" sha256sum "${guest_source}/Cargo.lock" \
  || die 1 "cannot hash guest Cargo.lock after ARM64 matrix"
guest_lock_hash="$(awk '{print $1}' "${result_dir}/cargo-lock-guest.sha256")"
host_lock_hash="$(awk -F= '$1 == "cargo_lock_sha256" {print $2}' \
  "${result_dir}/source.env")"
[[ "${guest_lock_hash}" == "${host_lock_hash}" ]] \
  || die 1 "Cargo.lock changed during ARM64 matrix"

say "all native ARM64 gates passed; sealing cleanup evidence"
exit 0
