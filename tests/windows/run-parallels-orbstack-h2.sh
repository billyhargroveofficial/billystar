#!/usr/bin/env bash
# Native Windows 11 ARM64 -> disposable OrbStack Linux H2-over-TCP
# no-TUN gate. The macOS host is a build/read-only observer only.
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly REPO_ROOT
readonly RESULT_ROOT="${SCRIPT_DIR}/results"
readonly WINDOWS_SCRIPT="${SCRIPT_DIR}/native-arm64-h2-gate.ps1"
readonly SOURCE_DEFAULT="arch"
readonly WINDOWS_DEFAULT="Windows 11"
readonly MAGIC_DEFAULT="0x50334852"
readonly EXPECTED_SINGBOX_CONFIG="${SHADOWPIPE_HOST_SINGBOX_CONFIG:-${HOME}/sing-box/config.json}"
readonly EXPECTED_SINGBOX_DIRECTORY="${SHADOWPIPE_HOST_SINGBOX_DIRECTORY:-${EXPECTED_SINGBOX_CONFIG%/*}}"
readonly TARGET="aarch64-pc-windows-gnullvm"
readonly STATUS_SCHEMA_VERSION=1
readonly HOST_TIMEOUT=30
readonly CLONE_TIMEOUT=300
readonly ORB_START_TIMEOUT=180
readonly ORB_STOP_TIMEOUT=180
readonly ORB_DELETE_TIMEOUT=300
readonly ORB_BUILD_TIMEOUT=1200
readonly WINDOWS_POWER_TIMEOUT=180
readonly WINDOWS_COMMAND_TIMEOUT=180
readonly QUIESCENCE_SECONDS=60
readonly EX_USAGE=64
readonly EX_DATAERR=65
readonly EX_UNAVAILABLE=69
readonly EX_NOPERM=77

say() {
  printf '[windows-arm64-h2] %s\n' "$*"
}

# shellcheck disable=SC2329
warn() {
  printf '[windows-arm64-h2] WARN: %s\n' "$*" >&2
}

die() {
  local status="$1"
  shift
  printf '[windows-arm64-h2] ERROR: %s\n' "$*" >&2
  exit "${status}"
}

usage() {
  cat <<'EOF'
Usage:
  SHADOWPIPE_DISPOSABLE_WINDOWS_ARM64=1 \
    tests/windows/run-parallels-orbstack-h2.sh [arch] [Windows 11]
  tests/windows/run-parallels-orbstack-h2.sh --self-test

Safety:
  - never stops, restarts, signals, reloads, or reconfigures macOS sing-box;
  - never changes macOS route, DNS, PF, TUN, proxy, or NetworkExtension state;
  - never changes Windows routes, DNS, firewall, adapters, or TUN state;
  - starts only an opaque-ID-bound disposable clone of stopped OrbStack `arch`;
  - resumes an initially suspended Windows 11 VM only for the bounded smoke,
    then removes private artifacts and suspends it again.
EOF
}

sanitize_component() {
  [[ "$1" =~ ^[a-zA-Z0-9._-]+$ && ${#1} -le 96 ]] || return 1
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
  timeout --foreground --signal=TERM --kill-after=5 "${seconds}" "$@"
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

# shellcheck disable=SC2329
capture_optional() {
  capture_command "$@" || true
}

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
    raise SystemExit("sing-box command requires unsafe shell interpretation")
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

capture_normalized_routes() {
  local output="$1" raw="$2"
  # shellcheck disable=SC2016
  capture_command "${HOST_TIMEOUT}" "${output}" /bin/bash -c \
    'set -o pipefail; awk '\''NR <= 4 || $3 !~ /L/'\'' "$1" | sed -E '\''s/[[:space:]]+[0-9]+$//'\''' \
    _ "${raw}"
}

snapshot_macos() {
  local output="$1" status=0 pid final_pid config_path executable_path
  mkdir -p -- "${output}"
  capture_command "${HOST_TIMEOUT}" "${output}/default-route-ipv4.txt" \
    route -n get default || status=1
  capture_command "${HOST_TIMEOUT}" "${output}/default-route-ipv6.txt" \
    route -n get -inet6 default || status=1
  capture_command "${HOST_TIMEOUT}" "${output}/routes-ipv4.raw.txt" \
    netstat -rn -f inet || status=1
  capture_command "${HOST_TIMEOUT}" "${output}/routes-ipv6.raw.txt" \
    netstat -rn -f inet6 || status=1
  capture_normalized_routes \
    "${output}/routes-ipv4.txt" "${output}/routes-ipv4.raw.txt" || status=1
  capture_normalized_routes \
    "${output}/routes-ipv6.txt" "${output}/routes-ipv6.raw.txt" || status=1
  capture_command "${HOST_TIMEOUT}" "${output}/dns.txt" scutil --dns || status=1

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
  if ! validate_live_singbox_command "${output}/sing-box.command"; then
    status=1
  fi
  config_path="${EXPECTED_SINGBOX_CONFIG}"
  executable_path="$(<"${output}/sing-box-executable.path")"
  if [[ ! -f "${config_path}" || -L "${config_path}" \
    || ! -f "${executable_path}" || -L "${executable_path}" ]]; then
    status=1
  else
    capture_command "${HOST_TIMEOUT}" "${output}/sing-box-config.sha256" \
      sha256sum "${config_path}" || status=1
    capture_command "${HOST_TIMEOUT}" "${output}/sing-box-binary.sha256" \
      sha256sum "${executable_path}" || status=1
    capture_command "${HOST_TIMEOUT}" "${output}/sing-box-config.stat" \
      stat -f '%HT %Su %Sg %Sp %l %z %N' "${config_path}" || status=1
    capture_command "${HOST_TIMEOUT}" "${output}/sing-box-binary.stat" \
      stat -f '%HT %Su %Sg %Sp %l %z %N' "${executable_path}" || status=1
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

# shellcheck disable=SC2329
compare_macos_snapshots() {
  local before="$1" after="$2" status=0 name
  local -a stable=(
    default-route-ipv4.txt default-route-ipv4.txt.stderr default-route-ipv4.txt.status
    default-route-ipv6.txt default-route-ipv6.txt.stderr default-route-ipv6.txt.status
    routes-ipv4.raw.txt.stderr routes-ipv4.raw.txt.status
    routes-ipv6.raw.txt.stderr routes-ipv6.raw.txt.status
    routes-ipv4.txt routes-ipv4.txt.stderr routes-ipv4.txt.status
    routes-ipv6.txt routes-ipv6.txt.stderr routes-ipv6.txt.status
    dns.txt dns.txt.stderr dns.txt.status
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
    sing-box-config.sha256 sing-box-config.sha256.stderr
    sing-box-config.sha256.status
    sing-box-binary.sha256 sing-box-binary.sha256.stderr
    sing-box-binary.sha256.status
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
  for name in "${stable[@]}"; do
    if ! bounded_cmp "${before}/${name}" "${after}/${name}"; then
      warn "macOS safety snapshot changed: ${name}"
      status=1
    fi
  done
  return "${status}"
}

acquire_lifecycle_lock() {
  local token="$1" lock
  lock="/tmp/shadowpipe-orbstack-lifecycle.lock"
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
  if capture_command "${HOST_TIMEOUT}" "${base}.raw.json" \
    orbctl info -f json "${selector}"; then
    :
  else
    return $?
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

capture_parallels_identity() {
  local expected_name="$1" expected_uuid="$2" expected_status="$3" base="$4"
  capture_command "${HOST_TIMEOUT}" "${base}.raw.json" prlctl list -a -j || return 1
  /usr/bin/python3 -I -S - \
    "${base}.raw.json" "${expected_name}" "${expected_uuid}" \
    "${expected_status}" "${base}.identity.json" <<'PY'
import json
import os
import sys
raw_path, expected_name, expected_uuid, expected_status, normalized = sys.argv[1:]
def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result
with open(raw_path, "rb") as stream:
    raw = stream.read()
if not raw or len(raw) > 1024 * 1024:
    raise SystemExit("Parallels JSON size is invalid")
document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
if type(document) is not list:
    raise SystemExit("Parallels root is not a list")
matches = [
    record for record in document
    if type(record) is dict and record.get("name") == expected_name
]
if len(matches) != 1:
    raise SystemExit("Parallels VM name is absent or ambiguous")
record = matches[0]
for field in ("uuid", "name", "status"):
    if type(record.get(field)) is not str:
        raise SystemExit(f"Parallels {field} is not a string")
if expected_uuid and record["uuid"] != expected_uuid:
    raise SystemExit("Parallels UUID mismatch or name reuse")
if expected_status and record["status"] != expected_status:
    raise SystemExit("Parallels status mismatch")
if not record["uuid"] or any(ord(c) < 0x21 or ord(c) == 0x7f for c in record["uuid"]):
    raise SystemExit("unsafe Parallels UUID")
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
print(record["uuid"])
PY
}

wait_parallels_status() {
  local name="$1" uuid="$2" expected="$3" base="$4"
  local attempt
  : >"${base}.trace"
  for attempt in $(seq 1 "${WINDOWS_POWER_TIMEOUT}"); do
    if capture_parallels_identity \
      "${name}" "${uuid}" "${expected}" "${base}-${attempt}" >/dev/null 2>&1; then
      printf '%s\t%s\n' "${attempt}" "${expected}" >>"${base}.trace"
      return 0
    fi
    printf '%s\tpending\n' "${attempt}" >>"${base}.trace"
    sleep 1
  done
  return 1
}

validate_private_ipv4() {
  /usr/bin/python3 -I -S - "$1" <<'PY'
import ipaddress
import sys
address = ipaddress.ip_address(sys.argv[1])
if address.version != 4 or not address.is_private:
    raise SystemExit("endpoint is not private IPv4")
if address.is_loopback or address.is_link_local or address.is_multicast:
    raise SystemExit("endpoint is not a routable RFC1918 VM address")
PY
}

validate_clone_route_not_utun() {
  local address="$1" output="$2" interface
  capture_command "${HOST_TIMEOUT}" "${output}" route -n get "${address}" || return 1
  interface="$(awk '$1 == "interface:" {print $2}' "${output}")"
  [[ -n "${interface}" && "${interface}" != utun* ]] || return 1
  printf 'clone_private_ip=%s\nroute_interface=%s\nroute_via_live_vpn=false\n' \
    "${address}" "${interface}" >"${output}.validation.env"
}

create_source_snapshot() {
  local destination="$1" manifest="$2"
  mkdir -m 0700 -- "${destination}"
  cp -p -- "${REPO_ROOT}/Cargo.toml" "${REPO_ROOT}/Cargo.lock" "${destination}/"
  mkdir -p -- "${destination}/.cargo" "${destination}/crates" \
    "${destination}/tests/windows"
  rsync -a -- "${REPO_ROOT}/.cargo/" "${destination}/.cargo/"
  rsync -a -- "${REPO_ROOT}/crates/" "${destination}/crates/"
  cp -p -- "${WINDOWS_SCRIPT}" \
    "${destination}/tests/windows/native-arm64-h2-gate.ps1"
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
    "client-credential.json",
    "client-enrollment.json",
    "unauthorized-credential.json",
    "unauthorized-enrollment.json",
    "server-keys.json",
    "client-allowlist.json",
}
patterns = [
    re.compile(rb'"(?:private_seed|ed25519_private_seed|psk|secret_key)"\s*:'),
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
            data = stream.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024:
            continue
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
        relative = os.path.relpath(path, root)
        rows.append((relative, digest.hexdigest()))
with open(output, "x", encoding="utf-8", newline="\n") as stream:
    for relative, digest in sorted(rows):
        stream.write(f"{digest}  {relative}\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
  (cd -- "${root}" && sha256sum -c checksums.sha256)
}

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
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/shadowpipe-windows-selftest.XXXXXX")"
  trap 'rm -rf -- "${tmp}"' RETURN
  validate_magic 0x50334852
  if validate_magic 0x100000000 2>/dev/null; then
    die 1 "oversized magic passed validation"
  fi
  self_test_singbox_observer "${tmp}/singbox-observer"
  validate_private_ipv4 10.2.3.4
  validate_private_ipv4 172.31.1.2
  validate_private_ipv4 192.168.99.2
  if validate_private_ipv4 127.0.0.1 2>/dev/null; then
    die 1 "loopback passed private-VM address validation"
  fi
  if validate_private_ipv4 8.8.8.8 2>/dev/null; then
    die 1 "public address passed private-VM address validation"
  fi
  mkdir -p "${tmp}/result"
  printf 'safe\n' >"${tmp}/result/file.txt"
  scan_result_for_private_material \
    "${tmp}/result" "${tmp}/result/private-material-scan.env"
  validate_result_tree "${tmp}/result"
  write_checksums "${tmp}/result" >/dev/null
  if rg -n \
    '(Set-Net|New-NetRoute|Remove-NetRoute|Set-DnsClient|netsh|New-NetFirewall|Set-NetFirewall|Remove-NetFirewall|wintun|--tunnel|--auto-route|--kill-switch|--dns)' \
    "${WINDOWS_SCRIPT}" >/dev/null; then
    die 1 "Windows helper contains a forbidden network-mutation token"
  fi
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "${BASH_SOURCE[0]}"
  printf 'SELFTEST PASS\n'
}

if [[ "${1:-}" == "--self-test" ]]; then
  run_self_test
  exit 0
fi

[[ "$(uname -s)" == Darwin ]] \
  || die "${EX_USAGE}" "host mode requires macOS"
[[ "${SHADOWPIPE_DISPOSABLE_WINDOWS_ARM64:-}" == 1 ]] \
  || die "${EX_USAGE}" "set SHADOWPIPE_DISPOSABLE_WINDOWS_ARM64=1"
[[ "$#" -le 2 ]] || { usage >&2; exit "${EX_USAGE}"; }

for tool in timeout orb orbctl prlctl cargo zig file sha256sum rsync openssl git \
  route netstat scutil pgrep ps stat sort awk sed grep rg shellcheck \
  /usr/bin/python3; do
  command -v "${tool}" >/dev/null \
    || die "${EX_UNAVAILABLE}" "missing host dependency: ${tool}"
done
[[ -f "${WINDOWS_SCRIPT}" && ! -L "${WINDOWS_SCRIPT}" ]] \
  || die "${EX_UNAVAILABLE}" "Windows helper is absent or symlinked"

source_vm="$(sanitize_component "${1:-${SOURCE_DEFAULT}}")" \
  || die "${EX_USAGE}" "unsafe source VM name"
windows_vm="${2:-${WINDOWS_DEFAULT}}"
[[ "${source_vm}" == "${SOURCE_DEFAULT}" ]] \
  || die "${EX_USAGE}" "only stopped source VM ${SOURCE_DEFAULT} is allowed"
[[ "${windows_vm}" == "${WINDOWS_DEFAULT}" ]] \
  || die "${EX_USAGE}" "only ${WINDOWS_DEFAULT} is allowed"
magic="${SHADOWPIPE_MAGIC:-${MAGIC_DEFAULT}}"
validate_magic "${magic}" \
  || die "${EX_USAGE}" "SHADOWPIPE_MAGIC must be one explicit u32"

mkdir -p -- "${RESULT_ROOT}" "${REPO_ROOT}/target"
[[ -d "${RESULT_ROOT}" && ! -L "${RESULT_ROOT}" ]] \
  || die "${EX_NOPERM}" "unsafe result root"
[[ -d "${REPO_ROOT}/target" && ! -L "${REPO_ROOT}/target" ]] \
  || die "${EX_NOPERM}" "unsafe repository target root"

run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$-$(openssl rand -hex 4)"
run_component="$(printf '%s' "${run_id}" | tr '[:upper:]' '[:lower:]')"
clone_vm="spw-${run_component}"
ownership_token="$(openssl rand -hex 32)"
nonce="$(openssl rand -hex 16)"
result_dir="${RESULT_ROOT}/${run_id}"
work_root="${REPO_ROOT}/target/windows-arm64-gate-${run_id}"
source_snapshot="${work_root}/source"
pe_target="${work_root}/pe-target"
linux_target="${work_root}/linux-target"
pe_artifact="${pe_target}/${TARGET}/release/shadowpipe-client.exe"
linux_artifact="${linux_target}/release/shadowpipe-server"
shared_root="${HOME}/Downloads/shadowpipe-windows-${run_id}"
shared_input="${shared_root}/input"
shared_evidence="${shared_root}/evidence"
windows_shared_root="C:\\Mac\\Home\\Downloads\\shadowpipe-windows-${run_id}"
windows_script_path="${windows_shared_root}\\input\\native-arm64-h2-gate.ps1"
guest_root=''
guest_owner_dir="/tmp/shadowpipe-windows-owner"
guest_owner_marker="${guest_owner_dir}/${clone_vm}.owner"
server_unit="shadowpipe-windows-${run_component}.service"

mkdir -m 0700 -- "${result_dir}" "${work_root}"
printf '%s\n' "${ownership_token}" >"${work_root}/owner"
chmod 0600 "${work_root}/owner"
mkdir -p -- "${result_dir}/orb" "${result_dir}/windows" \
  "${result_dir}/mac-before" "${result_dir}/mac-after"
{
  printf 'schema_version=1\n'
  printf 'run_id=%s\n' "${run_id}"
  printf 'source_vm=%s\n' "${source_vm}"
  printf 'windows_vm=%s\n' "${windows_vm}"
  printf 'clone_vm=%s\n' "${clone_vm}"
  printf 'shadowpipe_magic=%s\n' "${magic}"
  printf 'target=%s\n' "${TARGET}"
  printf 'carrier=h2_chunk_tcp\n'
  printf 'tunnel=false\n'
  printf 'field_evidence=false\n'
} >"${result_dir}/run-contract.env"

lock_dir=''
source_orb_id=''
clone_orb_id=''
windows_uuid=''
clone_created=0
clone_attempted=0
clone_started=0
windows_resumed=0
server_pid=''
server_unit_started=0
test_status=failed
build_status=failed
windows_cleanup_status=failed
windows_state_status=failed
clone_cleanup_status=failed
host_safety_status=failed
lifecycle_lock_status=not_acquired
cleanup_running=0

# shellcheck disable=SC2329
host_cleanup() {
  local incoming=$?
  (( cleanup_running == 0 )) || exit 1
  cleanup_running=1
  trap - EXIT INT TERM HUP
  set +e
  local cleanup_status=valid final_status="${incoming}"
  local server_log_collected=false

  if (( clone_started != 0 )) && [[ -n "${clone_orb_id}" ]]; then
    if capture_orb_identity \
      "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
      "${result_dir}/orb/clone-before-server-cleanup" >/dev/null 2>&1; then
      if (( server_unit_started != 0 )); then
        capture_optional "${HOST_TIMEOUT}" \
          "${result_dir}/orb/server-stop.log" \
          orb -m "${clone_orb_id}" -u root \
          systemctl stop "${server_unit}"
        capture_optional "${HOST_TIMEOUT}" \
          "${result_dir}/orb/server-unit-final.txt" \
          orb -m "${clone_orb_id}" -u root \
          systemctl show "${server_unit}" \
          --property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MainPID
        capture_optional "${HOST_TIMEOUT}" \
          "${result_dir}/orb/server-unit-reset.log" \
          orb -m "${clone_orb_id}" -u root \
          systemctl reset-failed "${server_unit}"
      fi
      capture_optional "${HOST_TIMEOUT}" \
        "${result_dir}/server.log" \
        orb -m "${clone_orb_id}" -u root \
        journalctl -u "${server_unit}" --no-pager -o cat
      if [[ -s "${result_dir}/server.log" ]]; then
        server_log_collected=true
      fi
      if [[ -n "${guest_root}" ]]; then
        capture_optional "${HOST_TIMEOUT}" \
          "${result_dir}/orb/guest-residue-before-delete.txt" \
          orb -m "${clone_orb_id}" bash -lc \
          "find '${guest_root}' -maxdepth 2 -printf '%y %p\\n' 2>/dev/null | sort || true"
      fi
    else
      cleanup_status=failed
    fi
  fi

  if (( windows_resumed != 0 )) && [[ -n "${windows_uuid}" ]]; then
    if capture_parallels_identity \
      "${windows_vm}" "${windows_uuid}" running \
      "${result_dir}/windows/vm-before-cleanup" >/dev/null 2>&1; then
      capture_optional "${WINDOWS_COMMAND_TIMEOUT}" \
        "${result_dir}/windows/cleanup-command.log" \
        prlctl exec "${windows_uuid}" --current-user powershell.exe \
        -NoProfile -NonInteractive -ExecutionPolicy Bypass \
        -File "${windows_script_path}" \
        -Phase Cleanup -RunId "${run_component}" \
        -SharedRoot "${windows_shared_root}"
      if [[ -f "${shared_evidence}/windows-cleanup.env" ]] \
        && grep -qx 'windows_cleanup_status=valid' \
          "${shared_evidence}/windows-cleanup.env"; then
        windows_cleanup_status=valid
      else
        cleanup_status=failed
      fi
      capture_optional "${WINDOWS_POWER_TIMEOUT}" \
        "${result_dir}/windows/suspend.log" \
        prlctl suspend "${windows_uuid}"
      if wait_parallels_status \
        "${windows_vm}" "${windows_uuid}" suspended \
        "${result_dir}/windows/wait-suspended"; then
        windows_state_status=valid
      else
        cleanup_status=failed
      fi
    else
      cleanup_status=failed
    fi
  fi

  if [[ -d "${shared_evidence}" && ! -L "${shared_evidence}" ]]; then
    cp -pR -- "${shared_evidence}/." "${result_dir}/windows/" \
      || cleanup_status=failed
  fi
  if [[ -e "${shared_root}" || -L "${shared_root}" ]]; then
    if [[ -d "${shared_root}" && ! -L "${shared_root}" \
      && "${shared_root}" == "${HOME}/Downloads/shadowpipe-windows-"* ]]; then
      rm -rf -- "${shared_root}" || cleanup_status=failed
    else
      cleanup_status=failed
    fi
  fi
  [[ ! -e "${shared_root}" && ! -L "${shared_root}" ]] \
    || cleanup_status=failed

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
    local clone_state=''
    if capture_orb_identity \
      "${clone_vm}" "${clone_vm}" "${clone_orb_id}" '' \
      "${result_dir}/orb/clone-before-delete" >/dev/null 2>&1; then
      clone_state="$(/usr/bin/python3 -I -S -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["state"])' \
        "${result_dir}/orb/clone-before-delete.identity.json")"
      if [[ "${clone_state}" != running ]]; then
        capture_optional "${ORB_START_TIMEOUT}" \
          "${result_dir}/orb/start-for-owner-verification.log" \
          orbctl start "${clone_orb_id}"
        wait_orb_start=0
        for _ in $(seq 1 "${ORB_START_TIMEOUT}"); do
          if capture_orb_identity \
            "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
            "${result_dir}/orb/clone-owner-wait-${_}" >/dev/null 2>&1; then
            wait_orb_start=1
            break
          fi
          sleep 1
        done
        (( wait_orb_start != 0 )) || cleanup_status=failed
      fi
      if capture_command "${HOST_TIMEOUT}" \
        "${result_dir}/orb/guest-owner-final.txt" \
        orb -m "${clone_orb_id}" cat "${guest_owner_marker}" \
        && [[ "$(<"${result_dir}/orb/guest-owner-final.txt")" == "${ownership_token}" ]] \
        && capture_orb_identity \
          "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
          "${result_dir}/orb/clone-owner-final" >/dev/null 2>&1; then
        capture_optional "${ORB_STOP_TIMEOUT}" \
          "${result_dir}/orb/clone-stop.log" \
          orbctl stop "${clone_orb_id}"
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
          for second in $(seq 1 "${QUIESCENCE_SECONDS}"); do
            if orb_exact_absent \
              "${clone_vm}" "${result_dir}/orb/absence-name-${second}" \
              && orb_exact_absent \
                "${clone_orb_id}" "${result_dir}/orb/absence-id-${second}"; then
              printf '%s\tabsent\n' "${second}" \
                >>"${result_dir}/orb/post-delete-quiescence.tsv"
            else
              printf '%s\tpresent_or_uncertain\n' "${second}" \
                >>"${result_dir}/orb/post-delete-quiescence.tsv"
              quiescent=0
            fi
            sleep 1
          done
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
  else
    clone_cleanup_status=valid
  fi

  if [[ -n "${source_orb_id}" ]]; then
    capture_orb_identity \
      "${source_vm}" "${source_vm}" "${source_orb_id}" stopped \
      "${result_dir}/orb/source-final" >/dev/null 2>&1 \
      || cleanup_status=failed
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

  if [[ -e "${work_root}" || -L "${work_root}" ]]; then
    safe_remove_work_root "${work_root}" "${ownership_token}" \
      || cleanup_status=failed
  fi
  [[ ! -e "${work_root}" && ! -L "${work_root}" ]] \
    || cleanup_status=failed

  if snapshot_macos "${result_dir}/mac-after" \
    && compare_macos_snapshots \
      "${result_dir}/mac-before" "${result_dir}/mac-after"; then
    host_safety_status=valid
  else
    cleanup_status=failed
  fi

  if [[ "${windows_cleanup_status}" != valid \
    || "${windows_state_status}" != valid \
    || "${clone_cleanup_status}" != valid \
    || "${lifecycle_lock_status}" != released ]]; then
    cleanup_status=failed
  fi

  local server_session_count=0 server_rejection_count=0
  if [[ "${server_log_collected}" == true ]]; then
    server_session_count="$(grep -c 'session established' \
      "${result_dir}/server.log" 2>/dev/null || true)"
    server_rejection_count="$(grep -c 'client error' \
      "${result_dir}/server.log" 2>/dev/null || true)"
  fi
  if [[ "${test_status}" == valid \
    && ("${server_session_count}" != 2 || "${server_rejection_count}" -lt 1) ]]; then
    test_status=failed
    cleanup_status=failed
  fi
  {
    printf 'schema_version=%s\n' "${STATUS_SCHEMA_VERSION}"
    printf 'run_id=%s\n' "${run_id}"
    printf 'build_status=%s\n' "${build_status}"
    printf 'test_status=%s\n' "${test_status}"
    printf 'windows_cleanup_status=%s\n' "${windows_cleanup_status}"
    printf 'windows_state_status=%s\n' "${windows_state_status}"
    printf 'clone_cleanup_status=%s\n' "${clone_cleanup_status}"
    printf 'host_safety_status=%s\n' "${host_safety_status}"
    printf 'evidence_status=valid\n'
    printf 'lifecycle_lock_status=%s\n' "${lifecycle_lock_status}"
    printf 'server_authenticated_session_count=%s\n' "${server_session_count}"
    printf 'server_rejected_connection_count=%s\n' "${server_rejection_count}"
    printf 'field_evidence=false\n'
    printf 'scope=windows_arm64_private_socket_no_tun\n'
    if [[ "${build_status}" == valid && "${test_status}" == valid \
      && "${windows_cleanup_status}" == valid \
      && "${windows_state_status}" == valid \
      && "${clone_cleanup_status}" == valid \
      && "${host_safety_status}" == valid \
      && "${lifecycle_lock_status}" == released \
      && "${cleanup_status}" == valid ]]; then
      printf 'overall_status=valid\n'
      final_status=0
    else
      printf 'overall_status=failed\n'
      (( final_status != 0 )) || final_status=1
    fi
  } >"${result_dir}/status.env"

  {
    printf '# Windows ARM64 H2 no-TUN gate\n\n'
    # shellcheck disable=SC2016
    printf -- '- Run: `%s`\n' "${run_id}"
    printf -- '- Carrier: Shadowpipe H2 chunk framing over TCP; inner protocol: mandatory authenticated v3.\n'
    # shellcheck disable=SC2016
    printf -- '- Native client: Windows 11 ARM64 PE, `--no-default-features`, strict warnings.\n'
    printf -- '- Negative controls: missing pin opened 0 loopback TCP connections; unenrolled device credential received no echo.\n'
    printf -- '- Positive controls: exact nonce echo plus 1,048,576 bytes sent and echoed.\n'
    printf -- '- Windows state: route and DNS canonical digests must match before/after; no TUN/firewall/adapter mutation command exists in the helper.\n'
    # shellcheck disable=SC2016
    printf -- '- Endpoint: exact RFC1918 address on one opaque-ID-bound disposable OrbStack clone; Mac route-to-endpoint had to avoid every `utun*` interface.\n'
    # shellcheck disable=SC2016
    printf -- '- Cleanup: Windows private files removed and VM re-suspended; clone deleted by name only after a fresh name-to-bound-ID check because OrbStack 2.2.1 panics on delete-by-ID; ID and name remained absent for %d seconds; source `arch` stayed stopped.\n' \
      "${QUIESCENCE_SECONDS}"
    printf -- '- macOS: live sing-box PID/start/argv/config/binary plus stable IPv4/IPv6 routes and DNS were read-only and byte-compared before/after.\n'
    printf -- '- Field evidence: false. This is a private-VM implementation/portability gate, not censorship-resistance evidence.\n'
    # shellcheck disable=SC2016
    printf -- '- Overall: `%s`.\n' \
      "$(awk -F= '$1 == "overall_status" {print $2}' "${result_dir}/status.env")"
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
  chmod -R a-w -- "${result_dir}" 2>/dev/null || true
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
  || die "${EX_UNAVAILABLE}" "cannot bind stopped source OrbStack VM"
windows_uuid="$(capture_parallels_identity \
  "${windows_vm}" '' suspended \
  "${result_dir}/windows/vm-before")" \
  || die "${EX_UNAVAILABLE}" "Windows VM must exist and be initially suspended"
orb_exact_absent "${clone_vm}" "${result_dir}/orb/clone-absence-before" \
  || die "${EX_USAGE}" "generated clone name already exists"
[[ ! -e "${shared_root}" && ! -L "${shared_root}" ]] \
  || die "${EX_USAGE}" "generated shared artifact path already exists"

snapshot_macos "${result_dir}/mac-before" \
  || die "${EX_UNAVAILABLE}" "macOS read-only safety baseline failed"
capture_command "${HOST_TIMEOUT}" "${result_dir}/git-status.txt" \
  git -C "${REPO_ROOT}" status --short --branch || true
capture_command "${HOST_TIMEOUT}" "${result_dir}/git-head.txt" \
  git -C "${REPO_ROOT}" rev-parse HEAD
capture_command "${HOST_TIMEOUT}" "${result_dir}/tool-versions.txt" \
  /bin/bash -c \
  'set -e; rustc -Vv; cargo -V; zig version; orbctl version; prlctl --version'

say "freezing current build inputs"
create_source_snapshot \
  "${source_snapshot}" "${result_dir}/source-files.sha256"
printf '%s\n' "${magic}" >"${result_dir}/shadowpipe-magic.txt"

say "building strict Windows ARM64 H2 client"
if ! run_bounded "${ORB_BUILD_TIMEOUT}" /usr/bin/env \
  LC_ALL=C SHADOWPIPE_MAGIC="${magic}" CARGO_TARGET_DIR="${pe_target}" \
  RUSTFLAGS='-D warnings' \
  cargo zigbuild --release --locked -p shadowpipe-client \
    --no-default-features --target "${TARGET}" \
    --manifest-path "${source_snapshot}/Cargo.toml" \
    >"${result_dir}/windows-build.log" 2>&1; then
  die 1 "Windows ARM64 H2 build failed"
fi
[[ -f "${pe_artifact}" && ! -L "${pe_artifact}" ]] \
  || die 1 "Windows PE artifact is absent"
capture_command "${HOST_TIMEOUT}" "${result_dir}/windows-artifact.file.txt" \
  file "${pe_artifact}"
grep -Eq 'PE32\+ executable .* Aarch64|PE32\+ executable .* ARM64' \
  "${result_dir}/windows-artifact.file.txt" \
  || die 1 "artifact is not PE32+ AArch64"
if grep -Eq '(^|[[:space:]])warning:' "${result_dir}/windows-build.log"; then
  die 1 "strict Windows build unexpectedly emitted a warning"
fi
pe_sha="$(sha256sum "${pe_artifact}" | awk '{print $1}')"
pe_size="$(stat -f '%z' "${pe_artifact}")"
{
  printf 'schema_version=1\n'
  printf 'target=%s\n' "${TARGET}"
  printf 'features=none\n'
  printf 'default_features=false\n'
  printf 'rustflags=-D warnings\n'
  printf 'sha256=%s\n' "${pe_sha}"
  printf 'size_bytes=%s\n' "${pe_size}"
  printf 'warning_free=true\n'
} >"${result_dir}/windows-artifact.env"

say "cloning stopped ${source_vm} -> ${clone_vm}"
clone_attempted=1
capture_command "${CLONE_TIMEOUT}" "${result_dir}/orb/clone.log" \
  orbctl clone "${source_vm}" "${clone_vm}" \
  || die 1 "OrbStack clone failed"
clone_created=1
capture_orb_identity \
  "${source_vm}" "${source_vm}" "${source_orb_id}" stopped \
  "${result_dir}/orb/source-after-clone" >/dev/null \
  || die 1 "source VM identity/state changed during clone"
clone_orb_id="$(capture_orb_identity \
  "${clone_vm}" "${clone_vm}" '' stopped \
  "${result_dir}/orb/clone-after-clone")" \
  || die 1 "cannot bind disposable clone opaque ID"
capture_orb_identity \
  "${clone_vm}" "${clone_vm}" "${clone_orb_id}" stopped \
  "${result_dir}/orb/clone-before-start" >/dev/null \
  || die 1 "clone identity changed before start"
capture_command "${ORB_START_TIMEOUT}" "${result_dir}/orb/clone-start.log" \
  orbctl start "${clone_orb_id}" \
  || die 1 "clone start failed"
clone_started=1
for attempt in $(seq 1 "${ORB_START_TIMEOUT}"); do
  if capture_orb_identity \
    "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
    "${result_dir}/orb/clone-start-wait-${attempt}" >/dev/null 2>&1; then
    break
  fi
  (( attempt < ORB_START_TIMEOUT )) || die 1 "clone did not reach running state"
  sleep 1
done

capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/owner-marker.log" \
  orb -m "${clone_orb_id}" bash -lc \
  "set -e; install -d -m 0700 '${guest_owner_dir}'; umask 077; test ! -e '${guest_owner_marker}'; printf '%s\\n' '${ownership_token}' >'${guest_owner_marker}'; chmod 0600 '${guest_owner_marker}'; test \"\$(cat '${guest_owner_marker}')\" = '${ownership_token}'" \
  || die "${EX_NOPERM}" "cannot establish guest ownership marker"
capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/guest-home.txt" \
  orb -m "${clone_orb_id}" /usr/bin/python3 -I -S -c \
  'import os; print(os.path.expanduser("~"))' \
  || die "${EX_UNAVAILABLE}" "cannot bind guest user home"
guest_home="$(<"${result_dir}/orb/guest-home.txt")"
capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/guest-user.txt" \
  orb -m "${clone_orb_id}" id -un \
  || die "${EX_UNAVAILABLE}" "cannot bind guest user"
capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/guest-group.txt" \
  orb -m "${clone_orb_id}" id -gn \
  || die "${EX_UNAVAILABLE}" "cannot bind guest primary group"
guest_user="$(sanitize_component "$(<"${result_dir}/orb/guest-user.txt")")" \
  || die "${EX_NOPERM}" "guest user is unsafe"
guest_group="$(sanitize_component "$(<"${result_dir}/orb/guest-group.txt")")" \
  || die "${EX_NOPERM}" "guest group is unsafe"
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
guest_root="${guest_home}/.shadowpipe-windows-${run_id}"
capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/clone-ip.txt" \
  orb -m "${clone_orb_id}" /usr/bin/python3 -I -S -c \
  'import ipaddress,json,subprocess
routes=json.loads(subprocess.check_output(["ip","-j","-4","route","show","default"]))
if len(routes) != 1 or type(routes[0].get("dev")) is not str:
 raise SystemExit("default IPv4 route is absent or ambiguous")
device=routes[0]["dev"]
links=json.loads(subprocess.check_output(["ip","-j","-4","addr","show","dev",device]))
values=[]
for link in links:
 for item in link.get("addr_info",[]):
  if item.get("family") == "inet" and item.get("scope") == "global":
   values.append(item.get("local"))
private=[value for value in values if type(value) is str and ipaddress.ip_address(value).is_private]
if len(private) != 1:
 raise SystemExit("default-route interface lacks one RFC1918 IPv4 address")
print(private[0])' \
  || die 1 "cannot discover clone RFC1918 address"
clone_ip="$(<"${result_dir}/orb/clone-ip.txt")"
validate_private_ipv4 "${clone_ip}" \
  || die 1 "clone address is not exact RFC1918 IPv4"
validate_clone_route_not_utun \
  "${clone_ip}" "${result_dir}/mac-route-to-clone.txt" \
  || die 1 "Mac route to clone is absent or traverses live utun; refusing test"

say "building current-snapshot Linux ARM64 H2 server in disposable clone"
if ! capture_command "${ORB_BUILD_TIMEOUT}" "${result_dir}/linux-build.log" \
  orb -m "${clone_orb_id}" -p -w "${source_snapshot}" bash -lc \
  "env LC_ALL=C SHADOWPIPE_MAGIC='${magic}' CARGO_TARGET_DIR='${linux_target}' RUSTFLAGS='-D warnings' cargo build --release --locked -p shadowpipe-server --no-default-features && test -x '${linux_artifact}'"; then
  die 1 "Linux ARM64 H2 server build failed"
fi
if grep -Eq '(^|[[:space:]])warning:' "${result_dir}/linux-build.log"; then
  die 1 "strict Linux server build unexpectedly emitted a warning"
fi
capture_command "${HOST_TIMEOUT}" "${result_dir}/linux-artifact.file.txt" \
  file "${linux_artifact}"
linux_sha="$(sha256sum "${linux_artifact}" | awk '{print $1}')"
linux_size="$(stat -f '%z' "${linux_artifact}")"
{
  printf 'schema_version=1\n'
  printf 'platform=linux_arm64\n'
  printf 'features=none\n'
  printf 'default_features=false\n'
  printf 'rustflags=-D warnings\n'
  printf 'sha256=%s\n' "${linux_sha}"
  printf 'size_bytes=%s\n' "${linux_size}"
  printf 'warning_free=true\n'
} >"${result_dir}/linux-artifact.env"
build_status=valid

mkdir -m 0700 -- "${shared_root}" "${shared_input}" "${shared_evidence}"
cp -p -- "${pe_artifact}" "${shared_input}/shadowpipe-client.exe"
cp -p -- "${source_snapshot}/tests/windows/native-arm64-h2-gate.ps1" \
  "${shared_input}/native-arm64-h2-gate.ps1"
chmod 0600 "${shared_input}/shadowpipe-client.exe" \
  "${shared_input}/native-arm64-h2-gate.ps1"

capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/prepare-server-binary.log" \
  orb -m "${clone_orb_id}" bash -lc \
  "set -e; install -d -m 0700 '${guest_root}'; install -m 0700 '${linux_artifact}' '${guest_root}/shadowpipe-server'; test \"\$(sha256sum '${guest_root}/shadowpipe-server' | awk '{print \$1}')\" = '${linux_sha}'" \
  || die 1 "cannot stage exact Linux server artifact"

say "resuming bounded Windows ARM64 session"
capture_command "${WINDOWS_POWER_TIMEOUT}" "${result_dir}/windows/resume.log" \
  prlctl resume "${windows_uuid}" \
  || die 1 "Windows VM resume failed"
windows_resumed=1
wait_parallels_status \
  "${windows_vm}" "${windows_uuid}" running \
  "${result_dir}/windows/wait-running" \
  || die 1 "Windows VM did not reach running state"
capture_command "${WINDOWS_COMMAND_TIMEOUT}" \
  "${result_dir}/windows/current-user.txt" \
  prlctl exec "${windows_uuid}" --current-user cmd.exe /c whoami \
  || die 1 "Windows current-user guest execution is unavailable"

say "running missing-pin zero-connect and native credential preparation"
capture_command "${WINDOWS_COMMAND_TIMEOUT}" \
  "${result_dir}/windows/prepare-command.log" \
  prlctl exec "${windows_uuid}" --current-user powershell.exe \
  -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "${windows_script_path}" \
  -Phase Prepare -RunId "${run_component}" \
  -SharedRoot "${windows_shared_root}" \
  || die 1 "Windows prepare phase failed"
grep -Eq '^process_api_exit_code=[1-9][0-9]*$' \
  "${shared_evidence}/missing-pin-proof.env" \
  || die 1 "Process API did not record a failing missing-pin exit"
grep -qx 'process_api_tcp_connection_count=0' \
  "${shared_evidence}/missing-pin-proof.env" \
  || die 1 "Process API missing-pin oracle observed a TCP connect"
grep -Eq '^direct_native_exit_code=[1-9][0-9]*$' \
  "${shared_evidence}/missing-pin-proof.env" \
  || die 1 "direct native invocation did not record a failing missing-pin exit"
grep -qx 'direct_native_tcp_connection_count=0' \
  "${shared_evidence}/missing-pin-proof.env" \
  || die 1 "direct native missing-pin oracle observed a TCP connect"
[[ -f "${shared_input}/client-enrollment.json" \
  && ! -L "${shared_input}/client-enrollment.json" ]] \
  || die 1 "Windows prepare omitted enrollment artifact"
enrollment_sha="$(sha256sum \
  "${shared_input}/client-enrollment.json" | awk '{print $1}')"
grep -qx "enrollment_sha256=${enrollment_sha}" \
  "${shared_evidence}/prepare-status.env" \
  || die 1 "Windows enrollment hash contract mismatch"

capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/enroll-client.log" \
  orb -m "${clone_orb_id}" bash -lc \
  "set -e; umask 077; cp '${shared_input}/client-enrollment.json' '${guest_root}/client-enrollment.json'; chmod 0600 '${guest_root}/client-enrollment.json'; '${guest_root}/shadowpipe-server' --development-user-allowlist --client-allowlist '${guest_root}/client-allowlist.json' --enroll-client '${guest_root}/client-enrollment.json'; rm -f '${guest_root}/client-enrollment.json'" \
  || die 1 "Linux server enrollment failed"
rm -f -- "${shared_input}/client-enrollment.json"
[[ ! -e "${shared_input}/client-enrollment.json" ]] \
  || die 1 "shared secret enrollment cleanup failed"

capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/server-port.txt" \
  orb -m "${clone_orb_id}" /usr/bin/python3 -I -S -c \
  'import secrets,socket; ip=__import__("sys").argv[1]; result=None
for _ in range(256):
 p=40000+secrets.randbelow(20000)
 try:
  t=socket.socket()
  t.bind((ip,p)); result=p; t.close(); break
 except OSError:
  t.close()
if result is None: raise SystemExit("no private TCP port")
print(result)' "${clone_ip}" \
  || die 1 "cannot reserve exact private server port"
server_port="$(<"${result_dir}/orb/server-port.txt")"
[[ "${server_port}" =~ ^[0-9]+$ \
  && "${server_port}" -ge 1024 && "${server_port}" -le 65535 ]] \
  || die 1 "unsafe server port"

capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/server-start.log" \
  orb -m "${clone_orb_id}" -u root systemd-run \
  --unit="${server_unit}" \
  --collect \
  --service-type=exec \
  --uid="${guest_user}" \
  --gid="${guest_group}" \
  --working-directory="${guest_root}" \
  --setenv=RUST_LOG=info \
  --property=RuntimeMaxSec=600s \
  --property=TimeoutStopSec=10s \
  --property=KillSignal=SIGTERM \
  --property=FinalKillSignal=SIGKILL \
  --property=Restart=no \
  --property=UMask=0077 \
  --property=NoNewPrivileges=yes \
  --property=PrivateTmp=yes \
  --property=PrivateDevices=yes \
  --property=ProtectSystem=strict \
  --property=ProtectKernelTunables=yes \
  --property=ProtectKernelModules=yes \
  --property=ProtectControlGroups=yes \
  "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" \
  --property=CapabilityBoundingSet= \
  --property=AmbientCapabilities= \
  "${guest_root}/shadowpipe-server" \
  --listen "${clone_ip}:${server_port}" \
  --keys "${guest_root}/server-keys.json" \
  --development-user-allowlist \
  --allow-insecure-lab-carriers \
  --client-allowlist "${guest_root}/client-allowlist.json" \
  --max-connections 16 \
  --outer-handshake-timeout-secs 10 \
  --inner-handshake-timeout-secs 10 \
  --carrier-idle-timeout-secs 10 \
  --carrier-probe-timeout-secs 5 \
  --carrier-write-timeout-secs 5 \
  || die 1 "cannot start private H2 server"
server_unit_started=1
for attempt in $(seq 1 100); do
  if capture_command "${HOST_TIMEOUT}" \
    "${result_dir}/orb/server-ready-${attempt}.txt" \
    orb -m "${clone_orb_id}" -u root bash -lc \
    "set -e; systemctl is-active --quiet '${server_unit}'; journalctl -u '${server_unit}' --no-pager -o cat | grep -Eq '^server-fp: [0-9a-f]{64}\$'; ss -H -lnt \"sport = :${server_port}\" | grep -F '${clone_ip}:${server_port}'"; then
    break
  fi
  (( attempt < 100 )) || die 1 "private H2 server did not become ready"
  sleep 0.1
done
capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/server-pid.txt" \
  orb -m "${clone_orb_id}" -u root \
  systemctl show "${server_unit}" --property=MainPID --value
server_pid="$(<"${result_dir}/orb/server-pid.txt")"
[[ "${server_pid}" =~ ^[0-9]+$ ]] || die 1 "invalid server PID"
capture_command "${HOST_TIMEOUT}" "${result_dir}/orb/server-fingerprint.txt" \
  orb -m "${clone_orb_id}" -u root bash -lc \
  "journalctl -u '${server_unit}' --no-pager -o cat | awk '/^server-fp: [0-9a-f]{64}\$/{print \$2; exit}'"
server_fp="$(<"${result_dir}/orb/server-fingerprint.txt")"
[[ "${server_fp}" =~ ^[0-9a-f]{64}$ ]] \
  || die 1 "server fingerprint is malformed"

say "running authenticated v3 H2 nonce, rejection, and 1 MiB gates"
capture_command "${WINDOWS_COMMAND_TIMEOUT}" \
  "${result_dir}/windows/run-command.log" \
  prlctl exec "${windows_uuid}" --current-user powershell.exe \
  -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "${windows_script_path}" \
  -Phase Run -RunId "${run_component}" \
  -SharedRoot "${windows_shared_root}" \
  -Server "${clone_ip}:${server_port}" \
  -ServerFingerprint "${server_fp}" \
  -Nonce "${nonce}" \
  || die 1 "Windows authenticated H2 phase failed"

grep -qx 'run_status=valid' "${shared_evidence}/run-status.env" \
  || die 1 "Windows run status is not valid"
grep -qx 'authenticated_nonce_echo=valid' "${shared_evidence}/run-status.env" \
  || die 1 "nonce echo gate is not valid"
grep -qx 'unenrolled_credential_rejection=valid' \
  "${shared_evidence}/run-status.env" \
  || die 1 "unenrolled credential rejection is not valid"
grep -qx 'load_payload_bytes=1048576' "${shared_evidence}/run-status.env" \
  || die 1 "load payload accounting is not exact"
grep -qx 'load_echoed_bytes=1048576' "${shared_evidence}/run-status.env" \
  || die 1 "load echo accounting is not exact"
grep -qx 'windows_route_digest_match=true' \
  "${shared_evidence}/run-status.env" \
  || die 1 "Windows route digest changed"
grep -qx 'windows_dns_digest_match=true' \
  "${shared_evidence}/run-status.env" \
  || die 1 "Windows DNS digest changed"

test_status=valid
build_status=valid
say "all runtime gates passed; sealing cleanup evidence"
exit 0
