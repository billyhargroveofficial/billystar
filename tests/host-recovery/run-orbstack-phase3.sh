#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Privileged Phase-3 crash/recovery laboratory.
#
# Host mode is read-only with respect to macOS networking. It snapshots the
# live route/DNS/PF/sing-box identity, clones only a stopped OrbStack `arch`,
# runs the destructive phase in the clone, destroys the clone, then proves the
# stable host snapshot is unchanged.
#
# Guest scenarios run in fresh private network+mount+PID namespaces. `/run` is
# a namespace-private tmpfs, so DNS exchange never targets the clone's real
# `/etc/resolv.conf`. The Rust example contains lab-only SIGKILL checkpoints;
# production binaries expose no fault hooks.

readonly EX_USAGE=64
readonly EX_UNAVAILABLE=69
readonly EX_NOPERM=77
readonly SOURCE_DEFAULT=arch
readonly HELPER_NAME=phase3_recovery_lab
readonly EXPECTED_RECOVERY_STEPS=8
readonly STATUS_SCHEMA_VERSION=2
readonly MAGIC_DEFAULT=0x50334852
readonly HOST_COLLECTOR_TIMEOUT_SECONDS=30
readonly HOST_EVIDENCE_TIMEOUT_SECONDS=300
readonly ORB_LIST_TIMEOUT_SECONDS=20
readonly ORB_CLONE_TIMEOUT_SECONDS=900
readonly ORB_START_TIMEOUT_SECONDS=180
readonly ORB_STOP_TIMEOUT_SECONDS=180
readonly ORB_DELETE_TIMEOUT_SECONDS=300
readonly ORB_COMMAND_TIMEOUT_SECONDS=120
readonly ORB_BUILD_TIMEOUT_SECONDS=1800
readonly ORB_GUEST_TIMEOUT_SECONDS=2400
readonly FILE_CLEANUP_TIMEOUT_SECONDS=180
readonly CLONE_QUIESCENCE_SAMPLES=60
readonly CLONE_QUIESCENCE_REQUIRED_STABLE=4
readonly GUEST_OWNER_DIRECTORY=/var/lib/shadowpipe-phase3-lab
readonly PARENT_NETNS_FD=7
readonly PARENT_MNTNS_FD=8
readonly EXPECTED_SINGBOX_CONFIG=/Users/billy/sing-box/config.json
readonly EXPECTED_SINGBOX_DIRECTORY=/Users/billy/sing-box

MAC_PF_READER=unprivileged
SELFTEST_TEMPORARY=''

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
  SHADOWPIPE_DISPOSABLE_PHASE3=1 tests/host-recovery/run-orbstack-phase3.sh [arch]

Pure, non-privileged runner checks:
  tests/host-recovery/run-orbstack-phase3.sh --self-test

The source VM must exist and be stopped. It is never started or modified; the
script creates a uniquely named clone, runs the lab there, then deletes it.

Safety boundary: one shared lock serializes all Shadowpipe OrbStack lifecycle
runners, but an unrelated same-host operator must not create, rename, start,
stop, or delete OrbStack machines during the run. Every destructive delete
still requires an exact-name census plus either the clone's root-owned guest
marker or a pre-guest partial-clone causality proof. Failure to prove ownership
leaves the clone in place and the run failed.
EOF
}

sanitize_component() {
  case "$1" in
    ''|*[!a-zA-Z0-9._-]*|*..*|*/*) return 1 ;;
    *) printf '%s\n' "$1" ;;
  esac
}

validate_magic() {
  /usr/bin/python3 -I -S - "$1" <<'PY'
import re
import sys

text = sys.argv[1]
if re.fullmatch(r"(?:0x[0-9a-fA-F]{1,8}|[0-9]{1,10})", text) is None:
    raise SystemExit("SHADOWPIPE_MAGIC must be one unsigned u32 literal")
value = int(text, 16 if text.startswith("0x") else 10)
if not 0 <= value <= 0xFFFFFFFF:
    raise SystemExit("SHADOWPIPE_MAGIC exceeds u32")
PY
}

run_bounded() {
  local timeout_seconds="$1"
  shift
  [[ "${timeout_seconds}" =~ ^[1-9][0-9]*$ ]] || return 125
  (( $# > 0 )) || return 125
  /usr/bin/python3 -I -S - "${timeout_seconds}" "$@" <<'PY'
import os
import signal
import subprocess
import sys
import time

timeout = int(sys.argv[1])
command = sys.argv[2:]
process = subprocess.Popen(
    command,
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
    deadline = time.monotonic() + 5
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
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                return False
    deadline = time.monotonic() + 5
    while group_exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    return not group_exists()

def terminate_group(signum, _frame):
    clean = stop_and_reap_group()
    raise SystemExit(128 + signum if clean else 125)

for forwarded in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(forwarded, terminate_group)

try:
    status = process.wait(timeout=timeout)
except subprocess.TimeoutExpired:
    print(
        f"bounded command timed out after {timeout}s: {command[0]}",
        file=sys.stderr,
    )
    clean = stop_and_reap_group()
    raise SystemExit(124 if clean else 125)
if group_exists():
    print(
        f"bounded command exited with live process-group descendants: {command[0]}",
        file=sys.stderr,
    )
    stop_and_reap_group()
    raise SystemExit(125)
raise SystemExit(status if status >= 0 else 128 - status)
PY
}

orb_list_snapshot() {
  local output="$1" status
  if run_bounded "${ORB_LIST_TIMEOUT_SECONDS}" orbctl list \
    >"${output}" 2>"${output}.stderr"; then
    if validate_orb_listing "${output}"; then
      status=0
      printf 'orb_list_validation=valid\n' >"${output}.validation.env"
    else
      status=65
      printf 'orb_list_validation=invalid\n' >"${output}.validation.env"
    fi
  else
    status=$?
    printf 'orb_list_validation=not_run\n' >"${output}.validation.env"
  fi
  printf '%s\n' "${status}" >"${output}.status"
  return "${status}"
}

validate_orb_listing() {
  local listing="$1"
  awk -v source="${SOURCE_DEFAULT}" '
    NF < 2 { next }
    seen[$1]++ { bad = 1; next }
    $1 == source { source_count += 1; source_state = $2 }
    END {
      if (source_count != 1 || source_state != "stopped") bad = 1
      exit bad
    }
  ' "${listing}"
}

orb_exact_state_from_file() {
  local listing="$1" vm="$2"
  awk -v vm="${vm}" '
    $1 == vm { count += 1; state = $2 }
    END {
      if (count == 0) { print "absent"; exit 0 }
      if (count == 1 && state != "") { print state; exit 0 }
      exit 2
    }
  ' "${listing}"
}

orb_exact_state() {
  local vm="$1" output="$2"
  orb_list_snapshot "${output}" || return 1
  orb_exact_state_from_file "${output}" "${vm}"
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
try:
    document = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid orbctl info JSON: {error}")
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
  if run_bounded "${timeout}" orbctl info -f json "${selector}" \
    >"${base}.raw.json" 2>"${base}.raw.json.stderr"; then
    printf '0\n' >"${base}.raw.json.status"
  else
    status=$?
    printf '%s\n' "${status}" >"${base}.raw.json.status"
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
  if run_bounded "${timeout}" orbctl info -f json "${selector}" \
    >"${base}.raw.json" 2>"${base}.raw.json.stderr"; then
    printf '0\n' >"${base}.raw.json.status"
    printf 'orb_absence_validation=invalid_present\n' >"${base}.validation.env"
    return 1
  else
    status=$?
  fi
  printf '%s\n' "${status}" >"${base}.raw.json.status"
  if [[ "${status}" == 1 && ! -s "${base}.raw.json" \
    && "$(<"${base}.raw.json.stderr")" \
      == "[-32098] machine not found: '${selector}'" ]]; then
    printf 'orb_absence_validation=valid\n' >"${base}.validation.env"
    return 0
  fi
  printf 'orb_absence_validation=invalid\n' >"${base}.validation.env"
  return 1
}

validate_quiescence_trace() {
  local trace="$1" required="$2" mode="$3"
  [[ "${required}" =~ ^[1-9][0-9]*$ \
    && ("${mode}" == stable_any || "${mode}" == absent_all) ]] || return 1
  awk -F '\t' -v required="${required}" -v mode="${mode}" '
    NF != 2 || $1 != NR || $2 !~ /^[a-zA-Z0-9._-]+$/ { bad = 1; next }
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
  local vm="$1" evidence_dir="$2" mode="$3" trace state sample
  bounded_file_operation mkdir -p -- "${evidence_dir}" || return 1
  trace="${evidence_dir}/trace.tsv"
  : >"${trace}" || return 1
  for ((sample = 1; sample <= CLONE_QUIESCENCE_SAMPLES; sample++)); do
    state="$(orb_exact_state \
      "${vm}" "${evidence_dir}/orb-list-${sample}.txt")" || return 1
    printf '%s\t%s\n' "${sample}" "${state}" >>"${trace}" || return 1
    if (( sample < CLONE_QUIESCENCE_SAMPLES )); then
      run_bounded 3 sleep 1 >/dev/null 2>&1 || return 1
    fi
  done
  validate_quiescence_trace \
    "${trace}" "${CLONE_QUIESCENCE_REQUIRED_STABLE}" "${mode}" || return 1
  printf '%s\n' "${state}"
}

create_source_provenance_manifest() {
  local repo_root="$1" output="$2" runner="$3"
  /usr/bin/python3 -I -S - "${repo_root}" "${output}" "${runner}" <<'PY'
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
  bounded_cmp "${expected}" "${observed}"
}

compute_overall_status() {
  local guest="$1" host="$2" cleanup="$3" clone_absence="$4" evidence="$5"
  if [[ "${guest}" == valid && "${host}" == valid \
    && "${cleanup}" == valid && "${clone_absence}" == valid \
    && "${evidence}" == valid ]]; then
    printf 'valid\n'
  else
    printf 'failed\n'
  fi
}

validate_guest_status_file() {
  local file="$1" expected_run_id="$2"
  [[ -f "${file}" && ! -L "${file}" ]] || return 1
  awk -F= -v run_id="${expected_run_id}" -v schema="${STATUS_SCHEMA_VERSION}" '
    BEGIN {
      expected["schema_version"] = schema
      expected["run_id"] = run_id
      expected["host_safety_status"] = "pending"
      expected["cleanup_status"] = "pending"
      expected["clone_absence_status"] = "pending"
      expected["evidence_status"] = "pending"
      expected["overall_status"] = "pending"
      expected["pf_runtime_observed"] = "pending"
      expected["field_evidence"] = "false"
      expected["scope"] = "disposable_orbstack_private_namespaces"
    }
    NF != 2 || $1 == "" || seen[$1]++ { bad = 1; next }
    $1 == "guest_status" {
      if ($2 != "valid" && $2 != "failed") bad = 1
      guest = $2
      next
    }
    $1 in expected {
      if ($2 != expected[$1]) bad = 1
      delete expected[$1]
      next
    }
    { bad = 1 }
    END {
      for (key in expected) bad = 1
      if (guest == "") bad = 1
      exit bad
    }
  ' "${file}"
}

guest_status_value() {
  local file="$1"
  awk -F= '$1 == "guest_status" { print $2 }' "${file}"
}

write_final_status_file() {
  local file="$1" run_id="$2" guest="$3" host="$4" cleanup="$5"
  local clone_absence="$6" evidence="$7" pf_runtime_observed="$8" overall temporary
  [[ "${pf_runtime_observed}" == true || "${pf_runtime_observed}" == false ]] \
    || return 1
  overall="$(compute_overall_status \
    "${guest}" "${host}" "${cleanup}" "${clone_absence}" "${evidence}")"
  temporary="$(mktemp "${file}.tmp.XXXXXX")" || return 1
  {
    printf 'schema_version=%s\n' "${STATUS_SCHEMA_VERSION}"
    printf 'run_id=%s\n' "${run_id}"
    printf 'guest_status=%s\n' "${guest}"
    printf 'host_safety_status=%s\n' "${host}"
    printf 'cleanup_status=%s\n' "${cleanup}"
    printf 'clone_absence_status=%s\n' "${clone_absence}"
    printf 'evidence_status=%s\n' "${evidence}"
    printf 'overall_status=%s\n' "${overall}"
    printf 'pf_runtime_observed=%s\n' "${pf_runtime_observed}"
    printf 'field_evidence=false\n'
    printf 'scope=disposable_orbstack_private_namespaces\n'
  } >"${temporary}" || {
    bounded_file_operation rm -f -- "${temporary}"
    return 1
  }
  bounded_file_operation mv -- "${temporary}" "${file}"
}

validate_final_status_file() {
  local file="$1" expected_run_id="$2"
  [[ -f "${file}" && ! -L "${file}" ]] || return 1
  awk -F= -v run_id="${expected_run_id}" -v schema="${STATUS_SCHEMA_VERSION}" '
    BEGIN {
      allowed["schema_version"] = 1
      allowed["run_id"] = 1
      allowed["guest_status"] = 1
      allowed["host_safety_status"] = 1
      allowed["cleanup_status"] = 1
      allowed["clone_absence_status"] = 1
      allowed["evidence_status"] = 1
      allowed["overall_status"] = 1
      allowed["pf_runtime_observed"] = 1
      allowed["field_evidence"] = 1
      allowed["scope"] = 1
    }
    NF != 2 || !($1 in allowed) || seen[$1]++ { bad = 1; next }
    { value[$1] = $2 }
    END {
      for (key in allowed) if (!seen[key]) bad = 1
      if (value["schema_version"] != schema || value["run_id"] != run_id) bad = 1
      if (value["guest_status"] != "valid" && value["guest_status"] != "failed") bad = 1
      for (key in allowed) {
        if (key ~ /_status$/ && key != "guest_status" &&
          value[key] != "valid" && value[key] != "failed") bad = 1
      }
      if (value["field_evidence"] != "false" ||
        value["scope"] != "disposable_orbstack_private_namespaces") bad = 1
      if (value["pf_runtime_observed"] != "true" && value["pf_runtime_observed"] != "false") bad = 1
      expected_overall = (value["guest_status"] == "valid" && value["host_safety_status"] == "valid" && value["cleanup_status"] == "valid" && value["clone_absence_status"] == "valid" && value["evidence_status"] == "valid") ? "valid" : "failed"
      if (value["overall_status"] != expected_overall) bad = 1
      exit bad
    }
  ' "${file}"
}

capture_readonly() {
  local output="$1"
  shift
  local status
  if run_bounded "${HOST_COLLECTOR_TIMEOUT_SECONDS}" "$@" \
    >"${output}" 2>"${output}.stderr"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "${status}" >"${output}.status"
}

capture_succeeded() {
  local status_file="$1" status
  [[ -f "${status_file}" ]] || return 1
  IFS= read -r status <"${status_file}" || return 1
  [[ "${status}" == 0 ]]
}

bounded_cmp() {
  run_bounded "${HOST_COLLECTOR_TIMEOUT_SECONDS}" /usr/bin/python3 -I -S -c '
import sys

try:
    with open(sys.argv[1], "rb", buffering=0) as left, \
         open(sys.argv[2], "rb", buffering=0) as right:
        while True:
            left_chunk = left.read(1024 * 1024)
            right_chunk = right.read(1024 * 1024)
            if left_chunk != right_chunk:
                raise SystemExit(1)
            if not left_chunk:
                raise SystemExit(0)
except OSError:
    raise SystemExit(1)
' "$1" "$2"
}

bounded_file_operation() {
  run_bounded "${FILE_CLEANUP_TIMEOUT_SECONDS}" "$@"
}

capture_normalized_routes() {
  local output="$1" raw="$2"
  # The single-quoted program is intentionally evaluated by the child shell.
  # shellcheck disable=SC2016
  capture_readonly "${output}" /bin/bash -c \
    'set -o pipefail; awk '\''NR <= 4 || $3 !~ /L/'\'' "$1" | sed -E '\''s/[[:space:]]+[0-9]+$//'\''' \
    _ "${raw}"
}

classify_pf_capture() {
  local output="$1" status
  [[ -f "${output}" && -f "${output}.stderr" && -f "${output}.status" ]] \
    || return 1
  IFS= read -r status <"${output}.status" || return 1
  if [[ "${status}" == 0 ]]; then
    printf 'observed\n'
    return 0
  fi
  if [[ "${status}" == 1 && ! -s "${output}" \
    && "$(wc -l <"${output}.stderr" | tr -d ' ')" == 1 ]] \
    && grep -qx 'pfctl: /dev/pf: Permission denied' "${output}.stderr"; then
    printf 'permission_denied\n'
    return 0
  fi
  return 1
}

classify_pf_tuple() {
  local info="$1" filter="$2" nat="$3"
  if [[ "${info}" == observed && "${filter}" == observed \
    && "${nat}" == observed ]]; then
    printf 'true\n'
  elif [[ "${info}" == permission_denied \
    && "${filter}" == permission_denied && "${nat}" == permission_denied ]]; then
    printf 'false\n'
  else
    return 1
  fi
}

parse_singbox_command() {
  local command_file="$1" config_output="$2" command_line config='' value
  local config_count=0 index=2
  [[ -f "${command_file}" ]] || return 1
  [[ "$(wc -l <"${command_file}" | tr -d ' ')" == 1 ]] || return 1
  IFS= read -r command_line <"${command_file}" || return 1
  [[ -n "${command_line}" ]] || return 1
  # `ps command=` has no lossless quoting contract. Fail closed unless the
  # observed invocation is the simple whitespace-free argv shape used by this
  # managed service; quoted, escaped, or whitespace-containing paths are not
  # guessed.
  [[ "${command_line}" != *[\'\"\\]* ]] || return 1
  local -a argv=()
  read -r -a argv <<<"${command_line}"
  (( ${#argv[@]} >= 3 )) || return 1
  [[ "${argv[0]##*/}" == sing-box && "${argv[1]}" == run ]] || return 1
  while (( index < ${#argv[@]} )); do
    case "${argv[index]}" in
      -c|--config)
        index=$((index + 1))
        (( index < ${#argv[@]} )) || return 1
        config="${argv[index]}"
        config_count=$((config_count + 1))
        ;;
      --config=*)
        config="${argv[index]#--config=}"
        config_count=$((config_count + 1))
        ;;
      -D|--directory)
        index=$((index + 1))
        (( index < ${#argv[@]} )) || return 1
        value="${argv[index]}"
        [[ "${value}" == /* ]] || return 1
        ;;
      --directory=*)
        value="${argv[index]#--directory=}"
        [[ "${value}" == /* ]] || return 1
        ;;
      *)
        return 1
        ;;
    esac
    index=$((index + 1))
  done
  (( config_count == 1 )) || return 1
  [[ "${config}" == /* && "${config}" != *$'\n'* && "${config}" != *$'\r'* ]] \
    || return 1
  printf '%s\n' "${config}" >"${config_output}"
}

validate_managed_singbox_command() {
  local command_file="$1" command_line
  [[ -f "${command_file}" ]] || return 1
  [[ "$(wc -l <"${command_file}" | tr -d ' ')" == 1 ]] || return 1
  IFS= read -r command_line <"${command_file}" || return 1
  [[ -n "${command_line}" && "${command_line}" != *[\'\"\\]* ]] || return 1
  local -a argv=()
  read -r -a argv <<<"${command_line}"
  (( ${#argv[@]} == 6 )) || return 1
  [[ "${argv[0]##*/}" == sing-box \
    && "${argv[1]}" == run \
    && "${argv[2]}" == -c \
    && "${argv[3]}" == "${EXPECTED_SINGBOX_CONFIG}" \
    && "${argv[4]}" == -D \
    && "${argv[5]}" == "${EXPECTED_SINGBOX_DIRECTORY}" ]]
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
      if run_bounded "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
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
      if validate_managed_singbox_command \
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
  local root="$1" exact unrelated foreign name
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

capture_pid_executable() {
  local pid="$1" output="$2"
  capture_readonly "${output}" /usr/bin/python3 -I -S -c '
import ctypes, os, sys
pid = int(sys.argv[1])
buffer = ctypes.create_string_buffer(4096)
libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
size = libproc.proc_pidpath(pid, buffer, len(buffer))
if size <= 0:
    raise OSError(ctypes.get_errno(), "proc_pidpath failed")
path = os.fsdecode(buffer.value)
if not os.path.isabs(path) or "\n" in path or "\r" in path:
    raise RuntimeError("proc_pidpath returned an unsafe path")
print(path)
' "${pid}"
}

snapshot_macos() {
  local output="$1"
  bounded_file_operation mkdir -p -- "${output}" || return 1
  local status=0
  capture_readonly "${output}/default-route-ipv4.txt" route -n get default
  capture_readonly "${output}/default-route-ipv6.txt" route -n get -inet6 default
  capture_succeeded "${output}/default-route-ipv4.txt.status" || status=1
  capture_succeeded "${output}/default-route-ipv6.txt.status" || status=1

  capture_readonly "${output}/routes-ipv4.raw.txt" netstat -rn -f inet
  capture_readonly "${output}/routes-ipv6.raw.txt" netstat -rn -f inet6
  capture_succeeded "${output}/routes-ipv4.raw.txt.status" || status=1
  capture_succeeded "${output}/routes-ipv6.raw.txt.status" || status=1
  # Neighbor-cache rows and their expiry counters can legitimately change when
  # OrbStack starts. Preserve raw evidence but compare the stable route plane.
  if capture_succeeded "${output}/routes-ipv4.raw.txt.status"; then
    capture_normalized_routes \
      "${output}/routes-ipv4.txt" "${output}/routes-ipv4.raw.txt"
  else
    : >"${output}/routes-ipv4.txt"
    printf '1\n' >"${output}/routes-ipv4.txt.status"
    printf 'raw IPv4 collector failed\n' >"${output}/routes-ipv4.txt.stderr"
  fi
  if capture_succeeded "${output}/routes-ipv6.raw.txt.status"; then
    capture_normalized_routes \
      "${output}/routes-ipv6.txt" "${output}/routes-ipv6.raw.txt"
  else
    : >"${output}/routes-ipv6.txt"
    printf '1\n' >"${output}/routes-ipv6.txt.status"
    printf 'raw IPv6 collector failed\n' >"${output}/routes-ipv6.txt.stderr"
  fi
  capture_succeeded "${output}/routes-ipv4.txt.status" || status=1
  capture_succeeded "${output}/routes-ipv6.txt.status" || status=1
  capture_readonly "${output}/dns.txt" scutil --dns
  capture_succeeded "${output}/dns.txt.status" || status=1

  capture_readonly "${output}/pf-conf.sha256" sha256sum /etc/pf.conf
  capture_succeeded "${output}/pf-conf.sha256.status" || status=1
  # The single-quoted program is intentionally evaluated by the child shell.
  # shellcheck disable=SC2016
  capture_readonly "${output}/pf-anchors.sha256" /bin/bash -c \
    'set -o pipefail; find "$1" -type f -exec sha256sum {} + | sort' _ /etc/pf.anchors
  capture_succeeded "${output}/pf-anchors.sha256.status" || status=1
  # PF runtime reads never prompt for or obtain elevated host authority. The
  # exact unprivileged permission-denied tuple is an accepted scoped outcome;
  # it must remain byte-identical and is never called a loaded-rules proof.
  printf '%s\n' "${MAC_PF_READER}" >"${output}/pf-runtime-reader.txt"
  capture_readonly "${output}/pf-info.txt" pfctl -si
  capture_readonly "${output}/pf-filter-rules.txt" pfctl -sr
  capture_readonly "${output}/pf-nat-rules.txt" pfctl -sn
  local pf_info_class=invalid pf_filter_class=invalid pf_nat_class=invalid
  local pf_runtime_observed=false
  pf_info_class="$(classify_pf_capture "${output}/pf-info.txt")" || status=1
  pf_filter_class="$(classify_pf_capture "${output}/pf-filter-rules.txt")" \
    || status=1
  pf_nat_class="$(classify_pf_capture "${output}/pf-nat-rules.txt")" \
    || status=1
  if pf_runtime_observed="$(classify_pf_tuple \
    "${pf_info_class}" "${pf_filter_class}" "${pf_nat_class}")"; then
    # The exact predeclared unprivileged tuple is not misrepresented as a PF
    # runtime proof. Either way, all raw outputs/statuses must remain
    # byte-identical and the final claim publishes the observed scope.
    :
  else
    status=1
  fi
  {
    printf 'pf_info_collector=%s\n' "${pf_info_class}"
    printf 'pf_filter_collector=%s\n' "${pf_filter_class}"
    printf 'pf_nat_collector=%s\n' "${pf_nat_class}"
    printf 'pf_runtime_observed=%s\n' "${pf_runtime_observed}"
  } >"${output}/pf-runtime-observation.env"

  capture_readonly "${output}/sing-box.pids.raw" pgrep -x sing-box
  capture_succeeded "${output}/sing-box.pids.raw.status" || status=1
  capture_readonly "${output}/sing-box.pids.candidates" \
    sort -n "${output}/sing-box.pids.raw"
  capture_succeeded "${output}/sing-box.pids.candidates.status" || status=1
  capture_singbox_candidate_commands \
    "${output}/sing-box.pids.candidates" \
    "${output}/sing-box.candidate-commands.tsv" || status=1
  capture_succeeded "${output}/sing-box.candidate-commands.tsv.status" \
    || status=1
  select_managed_singbox_candidates \
    "${output}/sing-box.candidate-commands.tsv" "${output}/sing-box.pids" \
    || status=1
  capture_succeeded "${output}/sing-box.pids.status" || status=1
  [[ "$(wc -l <"${output}/sing-box.pids" | tr -d ' ')" == 1 ]] || status=1
  local pid final_pid
  pid="$(<"${output}/sing-box.pids")"
  if [[ "${pid}" =~ ^[0-9]+$ ]]; then
    capture_readonly "${output}/sing-box.identity" \
      ps -ww -p "${pid}" -o pid= -o lstart= -o command=
    capture_readonly "${output}/sing-box.command" \
      ps -ww -p "${pid}" -o command=
    capture_pid_executable "${pid}" "${output}/sing-box-executable.path"
  else
    status=1
    for name in sing-box.identity sing-box.command sing-box-executable.path; do
      : >"${output}/${name}"
      printf '1\n' >"${output}/${name}.status"
      printf 'invalid or ambiguous pid\n' >"${output}/${name}.stderr"
    done
  fi
  capture_succeeded "${output}/sing-box.identity.status" || status=1
  capture_succeeded "${output}/sing-box.command.status" || status=1
  capture_succeeded "${output}/sing-box-executable.path.status" || status=1
  validate_managed_singbox_command "${output}/sing-box.command" || status=1

  local config_path='' executable_path=''
  if capture_succeeded "${output}/sing-box.command.status" \
    && parse_singbox_command \
      "${output}/sing-box.command" "${output}/sing-box-config.path"; then
    config_path="$(<"${output}/sing-box-config.path")"
    [[ "${config_path}" == "${EXPECTED_SINGBOX_CONFIG}" ]] || status=1
  else
    status=1
    : >"${output}/sing-box-config.path"
  fi
  if capture_succeeded "${output}/sing-box-executable.path.status"; then
    executable_path="$(<"${output}/sing-box-executable.path")"
  fi
  if [[ -n "${config_path}" && -f "${config_path}" && ! -L "${config_path}" ]]; then
    capture_readonly "${output}/sing-box-config.sha256" sha256sum "${config_path}"
    capture_readonly "${output}/sing-box-config.stat" stat -f '%HT %Su %Sg %Sp %l %z %N' "${config_path}"
  else
    status=1
    for name in sing-box-config.sha256 sing-box-config.stat; do
      : >"${output}/${name}"
      printf '1\n' >"${output}/${name}.status"
      printf 'derived config is absent, nonregular, or a symlink\n' >"${output}/${name}.stderr"
    done
  fi
  if [[ -n "${executable_path}" && "${executable_path##*/}" == sing-box \
    && -f "${executable_path}" \
    && ! -L "${executable_path}" ]]; then
    capture_readonly "${output}/sing-box-binary.sha256" sha256sum "${executable_path}"
    capture_readonly "${output}/sing-box-binary.stat" stat -f '%HT %Su %Sg %Sp %l %z %N' "${executable_path}"
  else
    status=1
    for name in sing-box-binary.sha256 sing-box-binary.stat; do
      : >"${output}/${name}"
      printf '1\n' >"${output}/${name}.status"
      printf 'proc_pidpath executable is absent, nonregular, or a symlink\n' \
        >"${output}/${name}.stderr"
    done
  fi
  for name in sing-box-config.sha256 sing-box-config.stat \
    sing-box-binary.sha256 sing-box-binary.stat; do
    capture_succeeded "${output}/${name}.status" || status=1
  done
  capture_readonly "${output}/sing-box.pids-final.raw" pgrep -x sing-box
  capture_readonly "${output}/sing-box.pids-final.candidates" \
    sort -n "${output}/sing-box.pids-final.raw"
  capture_singbox_candidate_commands \
    "${output}/sing-box.pids-final.candidates" \
    "${output}/sing-box.candidate-commands-final.tsv" || status=1
  select_managed_singbox_candidates \
    "${output}/sing-box.candidate-commands-final.tsv" \
    "${output}/sing-box.pids-final" || status=1
  final_pid="$(<"${output}/sing-box.pids-final")"
  if [[ "${final_pid}" =~ ^[0-9]+$ ]]; then
    capture_readonly "${output}/sing-box.identity-final" \
      ps -ww -p "${final_pid}" -o pid= -o lstart= -o command=
    capture_readonly "${output}/sing-box.command-final" \
      ps -ww -p "${final_pid}" -o command=
    capture_pid_executable \
      "${final_pid}" "${output}/sing-box-executable-final.path"
  else
    status=1
    for name in sing-box.identity-final sing-box.command-final \
      sing-box-executable-final.path; do
      : >"${output}/${name}"
      printf '1\n' >"${output}/${name}.status"
      printf 'invalid or ambiguous final pid\n' >"${output}/${name}.stderr"
    done
  fi
  for name in sing-box.pids-final.raw sing-box.pids-final.candidates \
    sing-box.candidate-commands-final.tsv sing-box.pids-final \
    sing-box.identity-final sing-box.command-final \
    sing-box-executable-final.path; do
    capture_succeeded "${output}/${name}.status" || status=1
  done
  validate_managed_singbox_command "${output}/sing-box.command-final" || status=1
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
    pf-conf.sha256 pf-conf.sha256.stderr pf-conf.sha256.status
    pf-anchors.sha256 pf-anchors.sha256.stderr pf-anchors.sha256.status
    pf-runtime-reader.txt pf-runtime-observation.env
    pf-info.txt pf-info.txt.stderr pf-info.txt.status
    pf-filter-rules.txt pf-filter-rules.txt.stderr pf-filter-rules.txt.status
    pf-nat-rules.txt pf-nat-rules.txt.stderr pf-nat-rules.txt.status
    sing-box.pids.raw sing-box.pids.raw.stderr sing-box.pids.raw.status
    sing-box.pids.candidates sing-box.pids.candidates.stderr
    sing-box.pids.candidates.status
    sing-box.candidate-commands.tsv sing-box.candidate-commands.tsv.stderr
    sing-box.candidate-commands.tsv.status
    sing-box.pids sing-box.pids.stderr sing-box.pids.status
    sing-box.identity sing-box.identity.stderr sing-box.identity.status
    sing-box.command sing-box.command.stderr sing-box.command.status
    sing-box-executable.path sing-box-executable.path.stderr sing-box-executable.path.status
    sing-box-config.path
    sing-box-config.sha256 sing-box-config.sha256.stderr sing-box-config.sha256.status
    sing-box-config.stat sing-box-config.stat.stderr sing-box-config.stat.status
    sing-box-binary.sha256 sing-box-binary.sha256.stderr sing-box-binary.sha256.status
    sing-box-binary.stat sing-box-binary.stat.stderr sing-box-binary.stat.status
    sing-box.pids-final.raw sing-box.pids-final.raw.stderr sing-box.pids-final.raw.status
    sing-box.pids-final.candidates sing-box.pids-final.candidates.stderr
    sing-box.pids-final.candidates.status
    sing-box.candidate-commands-final.tsv
    sing-box.candidate-commands-final.tsv.stderr
    sing-box.candidate-commands-final.tsv.status
    sing-box.pids-final sing-box.pids-final.stderr sing-box.pids-final.status
    sing-box.identity-final sing-box.identity-final.stderr sing-box.identity-final.status
    sing-box.command-final sing-box.command-final.stderr sing-box.command-final.status
    sing-box-executable-final.path sing-box-executable-final.path.stderr
    sing-box-executable-final.path.status sing-box-snapshot-consistency.env
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

portable_nlink() {
  if [[ "$(uname -s)" == Darwin ]]; then
    stat -f '%l' -- "$1"
  else
    stat -c '%h' -- "$1"
  fi
}

validate_bundle_tree() {
  local directory="$1" entry relative nlink listing status=0
  [[ -d "${directory}" && ! -L "${directory}" ]] || return 1
  listing="$(mktemp "${TMPDIR:-/tmp}/shadowpipe-phase3-tree.XXXXXX")" \
    || return 1
  if ! find -P "${directory}" -mindepth 1 -print0 >"${listing}"; then
    rm -f -- "${listing}"
    warn "evidence tree census failed: ${directory}"
    return 1
  fi
  while IFS= read -r -d '' entry; do
    relative="${entry#"${directory}"/}"
    [[ -n "${relative}" && "${relative}" != *$'\n'* \
      && "${relative}" != *$'\r'* && "${relative}" != *$'\t'* \
      && "${relative}" != *\\* ]] || {
      status=1
      continue
    }
    if [[ -L "${entry}" || (! -d "${entry}" && ! -f "${entry}") ]]; then
      warn "evidence tree contains a symlink or special entry: ${relative}"
      status=1
      continue
    fi
    if [[ -d "${entry}" && (! -r "${entry}" || ! -x "${entry}") ]]; then
      warn "evidence directory is not readable/searchable: ${relative}"
      status=1
      continue
    fi
    if [[ -f "${entry}" ]]; then
      [[ -r "${entry}" ]] || {
        warn "evidence file is not readable: ${relative}"
        status=1
        continue
      }
      nlink="$(portable_nlink "${entry}")" || {
        status=1
        continue
      }
      [[ "${nlink}" == 1 ]] || {
        warn "evidence file has multiple hard links: ${relative}"
        status=1
      }
    fi
  done <"${listing}"
  rm -f -- "${listing}"
  return "${status}"
}

write_payload_census() {
  local directory="$1" output="$2" entry relative listing status=0
  listing="$(mktemp "${TMPDIR:-/tmp}/shadowpipe-phase3-payload.XXXXXX")" \
    || return 1
  if ! (
    cd -- "${directory}"
    find -P . -mindepth 1 -print0 | sort -z
  ) >"${listing}"; then
    rm -f -- "${listing}"
    return 1
  fi
  : >"${output}" || {
    rm -f -- "${listing}"
    return 1
  }
  while IFS= read -r -d '' entry; do
    relative="${entry#./}"
    if [[ "${relative}" == checksums.sha256 \
      || "${relative}" == evidence-census.txt ]]; then
      continue
    elif [[ -d "${directory}/${relative}" ]]; then
      printf 'D\t%s\n' "${relative}" >>"${output}" || status=1
    elif [[ -f "${directory}/${relative}" ]]; then
      printf 'F\t%s\n' "${relative}" >>"${output}" || status=1
    else
      status=1
    fi
    if (( status != 0 )); then
      status=1
      break
    fi
  done <"${listing}"
  rm -f -- "${listing}"
  return "${status}"
}

write_relative_checksums() {
  local directory="$1" output="$2" entry relative listing status=0
  listing="$(mktemp "${TMPDIR:-/tmp}/shadowpipe-phase3-checklist.XXXXXX")" \
    || return 1
  if ! (
    cd -- "${directory}"
    find -P . -type f ! -path ./checksums.sha256 -print0 | sort -z
  ) >"${listing}"; then
    rm -f -- "${listing}"
    return 1
  fi
  : >"${output}" || {
    rm -f -- "${listing}"
    return 1
  }
  while IFS= read -r -d '' entry; do
    relative="${entry#./}"
    (cd -- "${directory}" && sha256sum -- "${relative}") >>"${output}" \
      || {
        status=1
        break
      }
  done <"${listing}"
  rm -f -- "${listing}"
  return "${status}"
}

verify_sealed_bundle() {
  local directory="$1" temporary census checksums
  validate_bundle_tree "${directory}" || return 1
  [[ -f "${directory}/checksums.sha256" \
    && -f "${directory}/evidence-census.txt" ]] || return 1
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/shadowpipe-phase3-verify.XXXXXX")" \
    || return 1
  census="${temporary}/census"
  checksums="${temporary}/checksums"
  if ! write_payload_census "${directory}" "${census}" \
    || ! bounded_cmp "${census}" "${directory}/evidence-census.txt" \
    || ! write_relative_checksums "${directory}" "${checksums}" \
    || ! bounded_cmp "${checksums}" "${directory}/checksums.sha256" \
    || ! (cd -- "${directory}" && sha256sum -c checksums.sha256 >/dev/null); then
    rm -rf -- "${temporary}"
    return 1
  fi
  rm -rf -- "${temporary}"
}

seal_bundle() {
  local directory="$1" temporary census checksums
  validate_bundle_tree "${directory}" || return 1
  rm -f -- "${directory}/checksums.sha256" "${directory}/evidence-census.txt"
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/shadowpipe-phase3-seal.XXXXXX")" \
    || return 1
  census="${temporary}/census"
  checksums="${temporary}/checksums"
  if ! write_payload_census "${directory}" "${census}" \
    || ! mv -- "${census}" "${directory}/evidence-census.txt" \
    || ! validate_bundle_tree "${directory}" \
    || ! write_relative_checksums "${directory}" "${checksums}" \
    || ! mv -- "${checksums}" "${directory}/checksums.sha256" \
    || ! verify_sealed_bundle "${directory}"; then
    rm -f -- "${directory}/checksums.sha256" "${directory}/evidence-census.txt"
    rm -rf -- "${temporary}"
    return 1
  fi
  rm -rf -- "${temporary}"
}

bounded_bundle_operation() {
  local operation="$1" directory="$2" runner
  runner="$(cd -- "$(dirname -- "$0")" && pwd -P)/$(basename -- "$0")" \
    || return 1
  run_bounded "${HOST_EVIDENCE_TIMEOUT_SECONDS}" env \
    SHADOWPIPE_PHASE3_INTERNAL_BUNDLE=1 bash "${runner}" \
    "--internal-${operation}-bundle" "${directory}"
}

files_equal() {
  local first="$1" second="$2" first_hash second_hash
  first_hash="$(sha256sum "${first}" 2>/dev/null | awk '{print $1}')" || return 1
  second_hash="$(sha256sum "${second}" 2>/dev/null | awk '{print $1}')" || return 1
  [[ -n "${first_hash}" && "${first_hash}" == "${second_hash}" ]]
}

snapshot_guest_root() {
  local output="$1"
  mkdir -p -- "${output}"
  ip -j link show | jq -S '
    map({ifindex, ifname, flags, mtu, qdisc, operstate, linkmode, group,
         txqlen, address, broadcast, link_type, linkinfo, ifalias})
    | sort_by(.ifindex)
  ' >"${output}/links.json"
  ip -j -4 route show table all | jq -S '
    map(del(.expires, .used, .age, .cache))
    | sort_by([(.table // "" | tostring), (.dst // ""), (.gateway // ""),
               (.dev // ""), (.protocol // "" | tostring), (.metric // 0)])
  ' >"${output}/routes-ipv4.json"
  iptables-save | sed '/^#/d' >"${output}/iptables.txt"
  ip6tables-save | sed '/^#/d' >"${output}/ip6tables.txt"
  nft list ruleset >"${output}/nft.txt"
  stat -Lc '%d %i %u %g %f %h %s' /etc/resolv.conf \
    >"${output}/resolv.identity"
  sha256sum /etc/resolv.conf >"${output}/resolv.sha256"
}

snapshot_private_namespace() {
  local output="$1" resolver="$2"
  mkdir -p -- "${output}"
  ip -j link show | jq -S '
    map({ifindex, ifname, flags, mtu, qdisc, operstate, linkmode, group,
         txqlen, address, broadcast, link_type, linkinfo, ifalias})
    | sort_by(.ifindex)
  ' >"${output}/links.json"
  ip -j -4 route show table all | jq -S '
    map(del(.expires, .used, .age, .cache))
    | sort_by([(.table // "" | tostring), (.dst // ""), (.gateway // ""),
               (.dev // ""), (.protocol // "" | tostring), (.metric // 0)])
  ' >"${output}/routes-ipv4.json"
  iptables-save | sed '/^#/d' >"${output}/iptables.txt"
  ip6tables-save | sed '/^#/d' >"${output}/ip6tables.txt"
  nft list ruleset >"${output}/nft.txt"
  stat -Lc '%d %i %u %g %f %h %s' "${resolver}" >"${output}/resolver.identity"
  sha256sum "${resolver}" >"${output}/resolver.sha256"
  readlink /proc/thread-self/ns/net >"${output}/network-namespace.txt"
  readlink /proc/thread-self/ns/mnt >"${output}/mount-namespace.txt"
}

compare_snapshot_dirs() {
  local before="$1" after="$2" status=0 name
  for name in links.json routes-ipv4.json iptables.txt ip6tables.txt nft.txt \
    resolver.identity resolver.sha256; do
    if ! files_equal "${before}/${name}" "${after}/${name}"; then
      warn "private namespace snapshot changed: ${name}"
      status=1
    fi
  done
  return "${status}"
}

seed_checkpoint_label() {
  case "$1" in
    planned) printf 'wal-planned-before-host-ownership\n' ;;
    after-apply-1) printf 'tun-applied-before-wal-ack\n' ;;
    after-apply-2) printf 'route-zero-applied-before-wal-ack\n' ;;
    after-apply-3) printf 'route-high-applied-before-wal-ack\n' ;;
    after-apply-4) printf 'endpoint-bypass-applied-before-wal-ack\n' ;;
    dns-staged) printf 'dns-staged-after-link-before-rename-exchange\n' ;;
    after-apply-5) printf 'dns-applied-before-wal-ack\n' ;;
    after-apply-6) printf 'firewall-bundle-applied-before-wal-ack\n' ;;
    firewall-after-ipv4-ack) printf 'firewall-ipv4-applied-ipv6-endpoint-planned\n' ;;
    firewall-after-ipv6-ack) printf 'firewall-bases-applied-before-endpoint-wal-ack\n' ;;
    firewall-after-endpoint-ack) printf 'all-resources-applied-before-active-publication\n' ;;
    active) printf 'active-after-all-wal-acks\n' ;;
    *) return 1 ;;
  esac
}

seed_wal_expectation() {
  case "$1" in
    planned|after-apply-1)
      printf 'preparing|planned,planned,planned,planned,planned,planned,planned,planned\n' ;;
    after-apply-2)
      printf 'preparing|applied,planned,planned,planned,planned,planned,planned,planned\n' ;;
    after-apply-3)
      printf 'preparing|applied,applied,planned,planned,planned,planned,planned,planned\n' ;;
    after-apply-4)
      printf 'preparing|applied,applied,applied,planned,planned,planned,planned,planned\n' ;;
    dns-staged|after-apply-5)
      printf 'preparing|applied,applied,applied,applied,planned,planned,planned,planned\n' ;;
    after-apply-6)
      printf 'preparing|applied,applied,applied,applied,applied,planned,planned,planned\n' ;;
    firewall-after-ipv4-ack)
      printf 'preparing|applied,applied,applied,applied,applied,applied,planned,planned\n' ;;
    firewall-after-ipv6-ack)
      printf 'preparing|applied,applied,applied,applied,applied,applied,applied,planned\n' ;;
    firewall-after-endpoint-ack)
      printf 'preparing|applied,applied,applied,applied,applied,applied,applied,applied\n' ;;
    active)
      printf 'active|applied,applied,applied,applied,applied,applied,applied,applied\n' ;;
    *) return 1 ;;
  esac
}

recovery_step_from_cut() {
  case "$1" in
    before-step-[1-8]) printf '%s\n' "${1#before-step-}" ;;
    after-step-[1-8]) printf '%s\n' "${1#after-step-}" ;;
    *) return 1 ;;
  esac
}

recovery_wal_expectation() {
  local cut="$1" step index operation_id
  step="$(recovery_step_from_cut "${cut}")" || return 1
  local -a states=(applied applied applied applied applied applied applied applied)
  local -a convergence_order=(2 3 5 4 1 8 6 7)
  for ((index = 0; index < step - 1; index++)); do
    operation_id="${convergence_order[index]}"
    states[operation_id-1]=removed
  done
  local IFS=,
  printf 'cleaning|%s\n' "${states[*]}"
}

recovery_marker_regex() {
  case "$1" in
    1) printf '%s\n' '^Route\(RouteResource \{ purpose: SplitDefault, family: Ipv4, table: 254, destination: IpPrefix \{ address: 0\.0\.0\.0, prefix_len: 1 \}, gateway: None, output: InterfaceIdentity \{ name: "sp3tun0", ifindex: [1-9][0-9]* \}, protocol: 186, metric: [1-9][0-9]* \}\)$' ;;
    2) printf '%s\n' '^Route\(RouteResource \{ purpose: SplitDefault, family: Ipv4, table: 254, destination: IpPrefix \{ address: 128\.0\.0\.0, prefix_len: 1 \}, gateway: None, output: InterfaceIdentity \{ name: "sp3tun0", ifindex: [1-9][0-9]* \}, protocol: 186, metric: [1-9][0-9]* \}\)$' ;;
    3) printf '%s\n' '^Dns\(DnsResource \{ target: EtcResolvConf, original: FileIdentity \{ device: [1-9][0-9]*, inode: [1-9][0-9]*, uid: 0, gid: 0, mode: 33188, link_count: 1, kind: Regular \}, original_sha256: Some\(Sha256Digest\("[0-9a-f]{64}"\)\), pinned: FileIdentity \{ device: [1-9][0-9]*, inode: [1-9][0-9]*, uid: 0, gid: 0, mode: 33188, link_count: 1, kind: Regular \}, pinned_sha256: Sha256Digest\("[0-9a-f]{64}"\) \}\)$' ;;
    4) printf '%s\n' '^Route\(RouteResource \{ purpose: EndpointBypass, family: Ipv4, table: 254, destination: IpPrefix \{ address: 198\.51\.100\.77, prefix_len: 32 \}, gateway: None, output: InterfaceIdentity \{ name: "sp3wan0", ifindex: [1-9][0-9]* \}, protocol: 186, metric: [1-9][0-9]* \}\)$' ;;
    5) printf '%s\n' '^Tun\(TunResource \{ interface: InterfaceIdentity \{ name: "sp3tun0", ifindex: [1-9][0-9]* \} \}\)$' ;;
    6) printf '%s\n' '^FirewallEndpoint\(FirewallEndpointResource \{ family: Ipv4, backend: IptablesNft, chain_token: FirewallChainToken\("[0-9a-f]{20}"\), address: 198\.51\.100\.77, transport: Tcp, port: 443 \}\)$' ;;
    7) printf '%s\n' '^Firewall\(FirewallResource \{ family: Ipv4, backend: IptablesNft, chain_token: FirewallChainToken\("[0-9a-f]{20}"\), filter_table_origin: (Preexisting|AbsentBeforeInstall), output_chain_origin: (Preexisting|AbsentBeforeInstall), expected_rule_count: 4 \}\)$' ;;
    8) printf '%s\n' '^Firewall\(FirewallResource \{ family: Ipv6, backend: IptablesNft, chain_token: FirewallChainToken\("[0-9a-f]{20}"\), filter_table_origin: (Preexisting|AbsentBeforeInstall), output_chain_origin: (Preexisting|AbsentBeforeInstall), expected_rule_count: 3 \}\)$' ;;
    *) return 1 ;;
  esac
}

validate_recovery_marker_wal_binding() {
  local marker="$1" journal="$2" cut="$3"
  /usr/bin/python3 -I -S - "${marker}" "${journal}" "${cut}" <<'PY'
import json
import re
import sys

marker_path, journal_path, cut = sys.argv[1:]
match = re.fullmatch(r"(before|after)-step-([1-8])", cut)
if match is None:
    raise SystemExit("invalid recovery cut")
position, step_text = match.groups()
step = int(step_text)
with open(marker_path, "r", encoding="utf-8") as source:
    lines = source.read().splitlines()
if len(lines) != 2 or not lines[0].startswith("checkpoint="):
    raise SystemExit("invalid checkpoint marker")
with open(journal_path, "r", encoding="utf-8") as source:
    journal = json.load(source)

operation_index = (1, 2, 4, 3, 0, 7, 5, 6)[step - 1]
resource = journal["operations"][operation_index]["resource"]

def pascal(value):
    return "".join(part.capitalize() for part in value.split("_"))

def interface(value):
    return (
        'InterfaceIdentity { name: "' + value["name"]
        + '", ifindex: ' + str(value["ifindex"]) + " }"
    )

def file_identity(value):
    return (
        "FileIdentity { device: " + str(value["device"])
        + ", inode: " + str(value["inode"])
        + ", uid: " + str(value["uid"])
        + ", gid: " + str(value["gid"])
        + ", mode: " + str(value["mode"])
        + ", link_count: " + str(value["link_count"])
        + ", kind: " + pascal(value["kind"]) + " }"
    )

kind = resource["kind"]
value = resource["resource"]
if kind == "tun":
    debug = "Tun(TunResource { interface: " + interface(value["interface"]) + " })"
elif kind == "route":
    gateway = "None" if value["gateway"] is None else f'Some({value["gateway"]})'
    destination = value["destination"]
    debug = (
        "Route(RouteResource { purpose: " + pascal(value["purpose"])
        + ", family: " + pascal(value["family"])
        + ", table: " + str(value["table"])
        + ", destination: IpPrefix { address: " + destination["address"]
        + ", prefix_len: " + str(destination["prefix_len"]) + " }"
        + ", gateway: " + gateway
        + ", output: " + interface(value["output"])
        + ", protocol: " + str(value["protocol"])
        + ", metric: " + str(value["metric"]) + " })"
    )
elif kind == "dns":
    original_digest = (
        "None" if value["original_sha256"] is None
        else 'Some(Sha256Digest("' + value["original_sha256"] + '"))'
    )
    debug = (
        "Dns(DnsResource { target: " + pascal(value["target"])
        + ", original: " + file_identity(value["original"])
        + ", original_sha256: " + original_digest
        + ", pinned: " + file_identity(value["pinned"])
        + ', pinned_sha256: Sha256Digest("' + value["pinned_sha256"] + '") })'
    )
elif kind == "firewall":
    debug = (
        "Firewall(FirewallResource { family: " + pascal(value["family"])
        + ", backend: " + pascal(value["backend"])
        + ', chain_token: FirewallChainToken("' + value["chain_token"] + '")'
        + ", filter_table_origin: " + pascal(value["filter_table_origin"])
        + ", output_chain_origin: " + pascal(value["output_chain_origin"])
        + ", expected_rule_count: " + str(value["expected_rule_count"]) + " })"
    )
elif kind == "firewall_endpoint":
    debug = (
        "FirewallEndpoint(FirewallEndpointResource { family: " + pascal(value["family"])
        + ", backend: " + pascal(value["backend"])
        + ', chain_token: FirewallChainToken("' + value["chain_token"] + '")'
        + ", address: " + value["address"]
        + ", transport: " + pascal(value["transport"])
        + ", port: " + str(value["port"]) + " })"
    )
else:
    raise SystemExit("unknown resource kind")

prefix = (
    f"cleaning-before-converge-step-{step}-"
    if position == "before"
    else f"cleaning-after-converge-before-wal-ack-step-{step}-"
)
if lines[0] != "checkpoint=" + prefix + debug:
    raise SystemExit("checkpoint resource does not exactly match its WAL operation")
PY
}

validate_checkpoint_marker() {
  local marker="$1" log="$2" kind="$3" cut="$4" expected_pid="$5"
  local expected_uid="${6:-0}" expected_gid="${7:-0}"
  local checkpoint pid expected prefix step remainder regex nlink mode uid gid file_type
  [[ "${expected_uid}" =~ ^[0-9]+$ && "${expected_gid}" =~ ^[0-9]+$ ]] \
    || return 1
  [[ -f "${marker}" && ! -L "${marker}" && -f "${log}" && ! -L "${log}" ]] \
    || return 1
  nlink="$(portable_nlink "${marker}")" || return 1
  [[ "${nlink}" == 1 && "$(wc -l <"${marker}" | tr -d ' ')" == 2 ]] || return 1
  if [[ "$(uname -s)" == Linux ]]; then
    read -r mode uid gid nlink file_type < <(
      stat -c '%a %u %g %h %F' -- "${marker}"
    ) || return 1
    [[ "${mode}" == 600 && "${uid}" == "${expected_uid}" \
      && "${gid}" == "${expected_gid}" \
      && "${nlink}" == 1 && "${file_type}" == 'regular file' ]] || return 1
  fi
  checkpoint="$(sed -n '1s/^checkpoint=//p' "${marker}")"
  pid="$(sed -n '2s/^pid=//p' "${marker}")"
  [[ -n "${checkpoint}" && "${pid}" =~ ^[1-9][0-9]*$ \
    && "${pid}" == "${expected_pid}" ]] || return 1
  [[ "$(grep -c '^checkpoint=' "${marker}")" == 1 \
    && "$(grep -c '^pid=' "${marker}")" == 1 ]] || return 1
  case "${kind}" in
    seed)
      expected="$(seed_checkpoint_label "${cut}")" || return 1
      [[ "${checkpoint}" == "${expected}" ]] || return 1
      ;;
    recovery)
      step="$(recovery_step_from_cut "${cut}")" || return 1
      case "${cut}" in
        before-step-*) prefix="cleaning-before-converge-step-${step}-" ;;
        after-step-*) prefix="cleaning-after-converge-before-wal-ack-step-${step}-" ;;
        *) return 1 ;;
      esac
      [[ "${checkpoint}" == "${prefix}"* ]] || return 1
      remainder="${checkpoint#"${prefix}"}"
      regex="$(recovery_marker_regex "${step}")" || return 1
      [[ "${remainder}" =~ ${regex} ]] || return 1
      ;;
    *) return 1 ;;
  esac
  awk -v expected="PHASE3_CHECKPOINT ${checkpoint}" '
    index($0, "PHASE3_CHECKPOINT") {
      count += 1
      if ($0 != expected) bad = 1
    }
    END { exit bad || count != 1 }
  ' "${log}"
}

validate_wal_json() {
  local journal="$1" expected_phase="$2" expected_states="$3"
  jq -e --arg phase "${expected_phase}" --arg states "${expected_states}" '
    def positive_integer: type == "number" and floor == . and . > 0;
    def uint32: type == "number" and floor == . and . >= 0 and . <= 4294967295;
    ($states | split(",")) as $expected_states
    | type == "object"
    and ($expected_states | length == 8)
    and all($expected_states[]; . == "planned" or . == "applied" or . == "removed")
    and (keys | sort == ["generation", "operations", "owner", "phase", "schema_version"])
    and .schema_version == 3
    and (.generation | positive_integer)
    and .phase == $phase
    and (.owner | type == "object")
    and (.owner | keys | sort == ["boot_id", "mount_namespace", "network_namespace", "pid", "pid_start_ticks", "session_id", "uid"])
    and .owner.uid == 0
    and (.owner.pid | uint32 and . > 0)
    and (.owner.pid_start_ticks | positive_integer)
    and (.owner.boot_id | type == "string" and test("^[0-9a-f]{32}$") and . != "00000000000000000000000000000000")
    and (.owner.session_id | type == "string" and test("^[0-9a-f]{32}$") and . != "00000000000000000000000000000000")
    and (.owner.mount_namespace | keys | sort == ["device", "inode"])
    and (.owner.network_namespace | keys | sort == ["device", "inode"])
    and (.owner.mount_namespace.device | positive_integer)
    and (.owner.mount_namespace.inode | positive_integer)
    and (.owner.network_namespace.device | positive_integer)
    and (.owner.network_namespace.inode | positive_integer)
    and (.owner.mount_namespace != .owner.network_namespace)
    and (.operations | type == "array" and length == 8)
    and ([.operations[].id] == [1,2,3,4,5,6,7,8])
    and ([.operations[].state] == $expected_states)
    and ([.operations[].resource.kind] == ["tun","route","route","route","dns","firewall","firewall","firewall_endpoint"])
    and all(.operations[]; (keys | sort == ["id", "resource", "state"]))
    and all(.operations[].resource; (keys | sort == ["kind", "resource"]))
    and (.operations[0].resource.resource | keys | sort == ["interface"])
    and (.operations[0].resource.resource.interface | keys | sort == ["ifindex", "name"])
    and all(.operations[1:4][]; (.resource.resource | keys | sort == ["destination", "family", "gateway", "metric", "output", "protocol", "purpose", "table"]))
    and all(.operations[1:4][]; (.resource.resource.destination | keys | sort == ["address", "prefix_len"]))
    and all(.operations[1:4][]; (.resource.resource.output | keys | sort == ["ifindex", "name"]))
    and (.operations[4].resource.resource | keys | sort == ["original", "original_sha256", "pinned", "pinned_sha256", "target"])
    and (.operations[4].resource.resource.original | keys | sort == ["device", "gid", "inode", "kind", "link_count", "mode", "uid"])
    and (.operations[4].resource.resource.pinned | keys | sort == ["device", "gid", "inode", "kind", "link_count", "mode", "uid"])
    and all(.operations[5:7][]; (.resource.resource | keys | sort == ["backend", "chain_token", "expected_rule_count", "family", "filter_table_origin", "output_chain_origin"]))
    and (.operations[7].resource.resource | keys | sort == ["address", "backend", "chain_token", "family", "port", "transport"])
    and (.operations[0].resource.resource.interface.name == "sp3tun0")
    and (.operations[0].resource.resource.interface.ifindex | uint32 and . > 0)
    and (.operations[1].resource.resource | .purpose == "split_default" and .family == "ipv4" and .table == 254 and .destination == {"address":"0.0.0.0","prefix_len":1} and .gateway == null and .output.name == "sp3tun0" and (.output.ifindex | uint32 and . > 0) and .protocol == 186 and (.metric | uint32 and . > 0))
    and (.operations[2].resource.resource | .purpose == "split_default" and .family == "ipv4" and .table == 254 and .destination == {"address":"128.0.0.0","prefix_len":1} and .gateway == null and .output.name == "sp3tun0" and (.output.ifindex | uint32 and . > 0) and .protocol == 186 and (.metric | uint32 and . > 0))
    and (.operations[3].resource.resource | .purpose == "endpoint_bypass" and .family == "ipv4" and .table == 254 and .destination == {"address":"198.51.100.77","prefix_len":32} and .gateway == null and .output.name == "sp3wan0" and (.output.ifindex | uint32 and . > 0) and .protocol == 186 and (.metric | uint32 and . > 0))
    and (.operations[1].resource.resource.metric == .operations[2].resource.resource.metric and .operations[2].resource.resource.metric == .operations[3].resource.resource.metric)
    and (.operations[1].resource.resource.output.ifindex == .operations[0].resource.resource.interface.ifindex)
    and (.operations[2].resource.resource.output.ifindex == .operations[0].resource.resource.interface.ifindex)
    and (.operations[3].resource.resource.output.ifindex != .operations[0].resource.resource.interface.ifindex)
    and (.operations[4].resource.resource | .target == "etc_resolv_conf" and .original == {"device":.original.device,"inode":.original.inode,"uid":0,"gid":0,"mode":33188,"link_count":1,"kind":"regular"} and (.original.device | positive_integer) and (.original.inode | positive_integer) and .original_sha256 == "c8084f2d03e4a94fb2be6284c6d834f537d29df8a109b63978f6cb4821a26d14" and .pinned == {"device":.pinned.device,"inode":.pinned.inode,"uid":0,"gid":0,"mode":33188,"link_count":1,"kind":"regular"} and (.pinned.device | positive_integer) and (.pinned.inode | positive_integer) and .pinned_sha256 == "eb8ab10ec80696e3a7cd191b4bb4023666e948ebbb5c92b087c2b843a54bb6f5" and [.original.device,.original.inode] != [.pinned.device,.pinned.inode])
    and (.operations[5].resource.resource | .family == "ipv4" and .backend == "iptables_nft" and (.chain_token | test("^[0-9a-f]{20}$") and . != "00000000000000000000") and .expected_rule_count == 4 and (.filter_table_origin == "preexisting" or .filter_table_origin == "absent_before_install") and (.output_chain_origin == "preexisting" or .output_chain_origin == "absent_before_install") and (.filter_table_origin != "absent_before_install" or .output_chain_origin == "absent_before_install"))
    and (.operations[6].resource.resource | .family == "ipv6" and .backend == "iptables_nft" and (.chain_token | test("^[0-9a-f]{20}$") and . != "00000000000000000000") and .expected_rule_count == 3 and (.filter_table_origin == "preexisting" or .filter_table_origin == "absent_before_install") and (.output_chain_origin == "preexisting" or .output_chain_origin == "absent_before_install") and (.filter_table_origin != "absent_before_install" or .output_chain_origin == "absent_before_install"))
    and (.operations[7].resource.resource | .family == "ipv4" and .backend == "iptables_nft" and (.chain_token | test("^[0-9a-f]{20}$")) and .address == "198.51.100.77" and .transport == "tcp" and .port == 443)
    and (.operations[7].resource.resource.chain_token == .operations[5].resource.resource.chain_token)
    and (.operations[5].resource.resource.chain_token != .operations[6].resource.resource.chain_token)
  ' "${journal}" >/dev/null 2>&1
}

require_and_copy_journal() {
  local journal="$1" destination="$2" kind="$3" cut="$4" expectation phase states
  local recovery_marker="${5:-}"
  local mode uid gid nlink file_type
  [[ -f "${journal}" && ! -L "${journal}" ]] \
    || die 1 "mandatory v3 WAL is missing after ${kind} crash ${cut}"
  read -r mode uid gid nlink file_type < <(
    stat -c '%a %u %g %h %F' -- "${journal}"
  ) || die 1 "mandatory v3 WAL metadata is unreadable"
  [[ "${mode}" == 600 && "${uid}" == 0 && "${gid}" == 0 \
    && "${nlink}" == 1 && "${file_type}" == 'regular file' ]] \
    || die 1 "mandatory v3 WAL must be root:root 0600 regular nlink=1"
  case "${kind}" in
    seed) expectation="$(seed_wal_expectation "${cut}")" ;;
    recovery) expectation="$(recovery_wal_expectation "${cut}")" ;;
    conflict) expectation='conflict|applied,applied,applied,applied,applied,applied,applied,applied' ;;
    *) die 1 "unknown WAL expectation kind ${kind}" ;;
  esac
  phase="${expectation%%|*}"
  states="${expectation#*|}"
  validate_wal_json "${journal}" "${phase}" "${states}" \
    || die 1 "v3 WAL vocabulary/phase/states mismatch after ${kind} ${cut}"
  if [[ "${kind}" == recovery ]]; then
    [[ -n "${recovery_marker}" ]] \
      || die 1 "recovery WAL validation requires its exact checkpoint marker"
    validate_recovery_marker_wal_binding \
      "${recovery_marker}" "${journal}" "${cut}" \
      || die 1 "recovery checkpoint resource does not exactly bind to its WAL operation"
  fi
  cp -- "${journal}" "${destination}"
  jq -S . "${journal}" >"${destination%.json}.pretty.json"
}

require_journal_absent() {
  local journal="$1" destination="$2"
  [[ ! -e "${journal}" && ! -L "${journal}" ]] \
    || die 1 "successful recovery retained the mandatory crash WAL"
  printf 'journal_absent_after_successful_recovery\n' >"${destination}"
}

run_expect_sigkill() {
  local marker="$1" log="$2" kind="$3" cut="$4"
  local expected_uid="$5" expected_gid="$6"
  shift 6
  [[ "${expected_uid}" =~ ^[0-9]+$ && "${expected_gid}" =~ ^[0-9]+$ ]] \
    || return 1
  rm -f -- "${marker}"
  local status child_pid
  set +e
  "$@" >"${log}" 2>&1 &
  child_pid=$!
  wait "${child_pid}" 2>/dev/null
  status=$?
  set -e
  [[ "${status}" -eq 137 ]] || {
    warn "expected SIGKILL status 137, observed ${status}; see ${log}"
    return 1
  }
  [[ -s "${marker}" ]] || {
    warn "SIGKILL command did not persist checkpoint marker"
    return 1
  }
  validate_checkpoint_marker \
    "${marker}" "${log}" "${kind}" "${cut}" "${child_pid}" \
    "${expected_uid}" "${expected_gid}" || {
    warn "checkpoint marker/log failed exact ${kind}:${cut} mapping"
    return 1
  }
}

require_private_scenario_namespaces() {
  local current_net current_mnt parent_net parent_mnt
  local current_net_id current_mnt_id parent_net_id parent_mnt_id
  [[ "${SHADOWPIPE_PHASE3_PARENT_NETNS_FD:-}" == "${PARENT_NETNS_FD}" \
    && "${SHADOWPIPE_PHASE3_PARENT_MNTNS_FD:-}" == "${PARENT_MNTNS_FD}" ]] \
    || return 1
  current_net="$(readlink /proc/thread-self/ns/net)" || return 1
  current_mnt="$(readlink /proc/thread-self/ns/mnt)" || return 1
  parent_net="$(readlink "/proc/self/fd/${PARENT_NETNS_FD}")" || return 1
  parent_mnt="$(readlink "/proc/self/fd/${PARENT_MNTNS_FD}")" || return 1
  [[ "${current_net}" =~ ^net:\[[1-9][0-9]*\]$ \
    && "${parent_net}" =~ ^net:\[[1-9][0-9]*\]$ \
    && "${current_mnt}" =~ ^mnt:\[[1-9][0-9]*\]$ \
    && "${parent_mnt}" =~ ^mnt:\[[1-9][0-9]*\]$ ]] || return 1
  current_net_id="$(stat -Lc '%d:%i' /proc/thread-self/ns/net)" || return 1
  current_mnt_id="$(stat -Lc '%d:%i' /proc/thread-self/ns/mnt)" || return 1
  parent_net_id="$(stat -Lc '%d:%i' "/proc/self/fd/${PARENT_NETNS_FD}")" \
    || return 1
  parent_mnt_id="$(stat -Lc '%d:%i' "/proc/self/fd/${PARENT_MNTNS_FD}")" \
    || return 1
  [[ "${current_net_id}" != "${parent_net_id}" \
    && "${current_mnt_id}" != "${parent_mnt_id}" ]]
}

scenario_main() {
  [[ "$(uname -s)" == Linux ]] || die "${EX_USAGE}" "scenario mode is Linux-only"
  [[ "${EUID}" -eq 0 ]] || die "${EX_NOPERM}" "scenario mode requires root"
  [[ "${SHADOWPIPE_PHASE3_SCENARIO:-}" == 1 ]] \
    || die "${EX_USAGE}" "missing scenario attestation"
  require_private_scenario_namespaces \
    || die "${EX_NOPERM}" \
      "scenario is not proved inside fresh private network and mount namespaces"
  [[ "$#" -eq 7 ]] || die "${EX_USAGE}" "scenario mode expects seven arguments"

  local scenario run_id helper result_dir seed_cut recovery_cut expected tamper
  scenario="$(sanitize_component "$1")" || die "${EX_USAGE}" "unsafe scenario name"
  run_id="$(sanitize_component "$2")" || die "${EX_USAGE}" "unsafe run id"
  helper="$3"
  result_dir="$4"
  seed_cut="$5"
  recovery_cut="$6"
  expected="$7"
  tamper="${SHADOWPIPE_PHASE3_TAMPER:-none}"
  [[ -x "${helper}" ]] || die "${EX_UNAVAILABLE}" "helper is not executable"
  [[ "${expected}" == recovered || "${expected}" == conflict ]] \
    || die "${EX_USAGE}" "invalid scenario outcome"

  mount --make-rprivate /
  mount -t tmpfs -o mode=0755,size=64m,nosuid,nodev tmpfs /run
  mkdir -p /run/lock /run/shadowpipe-phase3/state /run/shadowpipe-phase3/resolver
  chmod 0700 /run/shadowpipe-phase3/state /run/shadowpipe-phase3/resolver
  local state_dir=/run/shadowpipe-phase3/state
  local resolver=/run/shadowpipe-phase3/resolver/resolv.conf
  local journal="${state_dir}/host-state-v2.json"
  printf '# Phase-3 original resolver\nnameserver 192.0.2.53\n' >"${resolver}"
  chmod 0644 "${resolver}"
  # A namespace-local physical-path stand-in lets the crash leave one real
  # protocol-186 endpoint bypass behind after the non-persistent TUN (and its
  # split-default routes) disappears. Recovery must delete that exact /32 and
  # preserve the dummy link/default route captured in the baseline.
  timeout 5s ip link add dev sp3wan0 type dummy
  timeout 5s ip link set dev sp3wan0 up
  timeout 5s ip route add default dev sp3wan0 metric 12345

  mkdir -p -- "${result_dir}"
  {
    printf 'scenario=%s\n' "${scenario}"
    printf 'run_id=%s\n' "${run_id}"
    printf 'seed_cut=%s\n' "${seed_cut}"
    printf 'recovery_cut=%s\n' "${recovery_cut}"
    printf 'expected=%s\n' "${expected}"
    printf 'tamper=%s\n' "${tamper}"
    printf 'network_namespace=%s\n' "$(readlink /proc/thread-self/ns/net)"
    printf 'mount_namespace=%s\n' "$(readlink /proc/thread-self/ns/mnt)"
  } >"${result_dir}/scenario.env"

  snapshot_private_namespace "${result_dir}/baseline" "${resolver}"

  local seed_marker=/run/shadowpipe-phase3/seed.marker
  run_expect_sigkill "${seed_marker}" "${result_dir}/seed.log" seed "${seed_cut}" \
    0 0 \
    env SHADOWPIPE_PHASE3_GUEST=1 SHADOWPIPE_PHASE3_PRIVATE_NS=1 \
    SHADOWPIPE_PHASE3_PARENT_NETNS_FD="${PARENT_NETNS_FD}" \
    SHADOWPIPE_PHASE3_PARENT_MNTNS_FD="${PARENT_MNTNS_FD}" \
    "${helper}" seed "${state_dir}" "${resolver}" "${seed_cut}" "${seed_marker}"
  cp -- "${seed_marker}" "${result_dir}/seed.marker"
  require_and_copy_journal \
    "${journal}" "${result_dir}/journal-after-seed.json" seed "${seed_cut}"

  if [[ "${tamper}" == tun-alias ]]; then
    # Production TUNs are non-persistent and disappear when the seed process
    # is SIGKILLed. Create a foreign persistent lookalike only after that crash
    # to prove the all-resource preflight refuses name/ifindex/alias reuse with
    # zero mutation; production recovery never deletes this object.
    ip tuntap add dev sp3tun0 mode tun
    ip link set dev sp3tun0 alias phase3-foreign-owner
  elif [[ "${tamper}" != none ]]; then
    die "${EX_USAGE}" "unknown tamper mode ${tamper}"
  fi

  if [[ "${expected}" == conflict ]]; then
    snapshot_private_namespace "${result_dir}/before-conflict-recovery" "${resolver}"
    env SHADOWPIPE_PHASE3_GUEST=1 SHADOWPIPE_PHASE3_PRIVATE_NS=1 \
      SHADOWPIPE_PHASE3_PARENT_NETNS_FD="${PARENT_NETNS_FD}" \
      SHADOWPIPE_PHASE3_PARENT_MNTNS_FD="${PARENT_MNTNS_FD}" \
      "${helper}" recover "${state_dir}" "${resolver}" none conflict \
      /run/shadowpipe-phase3/unexpected.marker \
      >"${result_dir}/recover-final.log" 2>&1
    snapshot_private_namespace "${result_dir}/after-conflict-recovery" "${resolver}"
    compare_snapshot_dirs \
      "${result_dir}/before-conflict-recovery" \
      "${result_dir}/after-conflict-recovery"
    jq -e '.phase == "conflict"' "${journal}" >/dev/null \
      || die 1 "conflict scenario did not retain a durable Conflict journal"
    require_and_copy_journal \
      "${journal}" "${result_dir}/journal-final.json" conflict conflict
  else
    if [[ "${recovery_cut}" != none ]]; then
      local recovery_marker=/run/shadowpipe-phase3/recovery.marker
      run_expect_sigkill \
        "${recovery_marker}" "${result_dir}/recover-cut.log" recovery "${recovery_cut}" \
        0 0 \
        env SHADOWPIPE_PHASE3_GUEST=1 SHADOWPIPE_PHASE3_PRIVATE_NS=1 \
        SHADOWPIPE_PHASE3_PARENT_NETNS_FD="${PARENT_NETNS_FD}" \
        SHADOWPIPE_PHASE3_PARENT_MNTNS_FD="${PARENT_MNTNS_FD}" \
        "${helper}" recover "${state_dir}" "${resolver}" "${recovery_cut}" recovered \
        "${recovery_marker}"
      cp -- "${recovery_marker}" "${result_dir}/recovery.marker"
      require_and_copy_journal \
        "${journal}" "${result_dir}/journal-after-recovery-cut.json" \
        recovery "${recovery_cut}" "${recovery_marker}"
    fi
    env SHADOWPIPE_PHASE3_GUEST=1 SHADOWPIPE_PHASE3_PRIVATE_NS=1 \
      SHADOWPIPE_PHASE3_PARENT_NETNS_FD="${PARENT_NETNS_FD}" \
      SHADOWPIPE_PHASE3_PARENT_MNTNS_FD="${PARENT_MNTNS_FD}" \
      "${helper}" recover "${state_dir}" "${resolver}" none recovered \
      /run/shadowpipe-phase3/unexpected.marker \
      >"${result_dir}/recover-final.log" 2>&1
    [[ ! -e "${journal}" ]] || die 1 "recovered scenario retained host journal"
    snapshot_private_namespace "${result_dir}/final" "${resolver}"
    compare_snapshot_dirs "${result_dir}/baseline" "${result_dir}/final"
    require_journal_absent "${journal}" "${result_dir}/journal-final.absent.txt"
  fi

  printf 'scenario_status=valid\n' >"${result_dir}/status.env"
  seal_bundle "${result_dir}"
}

guest_failures=''
guest_failed=0

record_guest_failure() {
  guest_failed=1
  guest_failures+="$*"$'\n'
  warn "$*"
}

run_guest_scenario() {
  local result_root="$1" run_id="$2" helper="$3" name="$4" seed_cut="$5"
  local recovery_cut="$6" expected="$7" tamper="$8"
  local scenario_result="${result_root}/scenarios/${name}"
  mkdir -p -- "${scenario_result}"
  say "scenario ${name}: seed=${seed_cut}, recovery=${recovery_cut}, expected=${expected}"
  if ! unshare --net --mount --pid --fork --mount-proc \
    env SHADOWPIPE_PHASE3_SCENARIO=1 SHADOWPIPE_PHASE3_TAMPER="${tamper}" \
    SHADOWPIPE_PHASE3_PARENT_NETNS_FD="${PARENT_NETNS_FD}" \
    SHADOWPIPE_PHASE3_PARENT_MNTNS_FD="${PARENT_MNTNS_FD}" \
    bash "$0" --scenario "${name}" "${run_id}" "${helper}" \
    "${scenario_result}" "${seed_cut}" "${recovery_cut}" "${expected}"; then
    record_guest_failure "scenario failed: ${name}"
    return 1
  fi
  if [[ ! -f "${scenario_result}/status.env" ]] \
    || [[ "$(wc -l <"${scenario_result}/status.env" | tr -d ' ')" != 1 ]] \
    || ! grep -qx 'scenario_status=valid' "${scenario_result}/status.env" \
    || ! verify_sealed_bundle "${scenario_result}"; then
    record_guest_failure "scenario did not publish a valid sealed status: ${name}"
    return 1
  fi
}

write_guest_result() {
  local result_root="$1" run_id="$2"
  local verdict=PASS
  (( guest_failed == 0 )) || verdict=FAIL
  {
    printf '# ShadowPipe privileged Phase-3 crash/recovery lab\n\n'
    printf -- '- Run: %s\n' "${run_id}"
    printf -- '- Guest verdict: **%s**\n' "${verdict}"
    printf -- '- Isolation: disposable OrbStack clone; fresh net+mount+PID namespace per scenario\n'
    printf -- '- Resolver: private tmpfs target, never guest /etc/resolv.conf\n'
    printf -- '- Runtime resources: two TUN split-default routes plus one persistent-underlay protocol-186 /32, non-persistent TUN+ifalias ownership, DNS rename exchange, iptables/ip6tables kill-switch\n'
    printf -- '- Crash cuts: WAL Planned; every resource-family apply; DNS Staged; partial firewall WAL acknowledgements; all-Applied/Preparing; Active; and both before mutation plus after convergence/before WAL ack for each of %d recovery steps\n' "${EXPECTED_RECOVERY_STEPS}"
    printf -- '- Crash evidence: every SIGKILL marker has one exact cut label/PID/log record; every crash retains a mandatory root-owned schema-v3 WAL with the exact eight-resource vocabulary, phase, per-operation states, and recovery-marker resource binding\n'
    printf -- '- Conflict oracle: exact pre/post network snapshot equality plus durable Conflict journal\n'
    printf -- '- Release helper build: explicit validated SHADOWPIPE_MAGIC=%s\n' \
      "${SHADOWPIPE_PHASE3_MAGIC:-missing}"
    printf '\n## Honest scope limits\n\n'
    printf -- '- Same-boot namespace recovery only; this does not simulate a kernel reboot.\n'
    printf -- '- SIGKILL tests process crashes, not torn filesystem writes or power-loss storage semantics.\n'
    printf -- '- Synthetic namespace state is not field evidence for hostile ISP/RKN networks.\n'
    printf -- '- The private resolver target validates exchange mechanics without touching systemd-resolved or the clone /etc.\n'
    printf -- '- A malicious same-UID/root writer remains outside the 0700-directory + singleton-lease trust boundary.\n'
    printf -- '- The shared lock excludes other Shadowpipe OrbStack runners; unrelated same-host lifecycle operators remain outside the trust boundary.\n'
    printf '\n## Failures\n\n~~~text\n%s~~~\n' "${guest_failures:-<none>$'\n'}"
  } >"${result_root}/RESULT.md"
  {
    printf 'schema_version=%s\n' "${STATUS_SCHEMA_VERSION}"
    printf 'run_id=%s\n' "${run_id}"
    printf 'guest_status=%s\n' "$([[ "${verdict}" == PASS ]] && echo valid || echo failed)"
    printf 'host_safety_status=pending\n'
    printf 'cleanup_status=pending\n'
    printf 'clone_absence_status=pending\n'
    printf 'evidence_status=pending\n'
    printf 'overall_status=pending\n'
    printf 'pf_runtime_observed=pending\n'
    printf 'field_evidence=false\n'
    printf 'scope=disposable_orbstack_private_namespaces\n'
  } >"${result_root}/status.env"
}

validate_guest_owner_marker() {
  local marker="$1" expected="$2" parent mode uid gid nlink parent_nlink
  [[ "${marker}" == "${GUEST_OWNER_DIRECTORY}"/* \
    && -f "${marker}" && ! -L "${marker}" \
    && -f "${expected}" && ! -L "${expected}" ]] || return 1
  parent="$(dirname -- "${marker}")"
  [[ "${parent}" == "${GUEST_OWNER_DIRECTORY}" \
    && -d "${parent}" && ! -L "${parent}" ]] || return 1
  read -r mode uid gid parent_nlink < <(stat -c '%a %u %g %h' -- "${parent}") \
    || return 1
  [[ "${mode}" == 700 && "${uid}" == 0 && "${gid}" == 0 \
    && "${parent_nlink}" =~ ^[1-9][0-9]*$ ]] \
    || return 1
  read -r mode uid gid nlink < <(stat -c '%a %u %g %h' -- "${marker}") || return 1
  [[ "${mode}" == 600 && "${uid}" == 0 && "${gid}" == 0 && "${nlink}" == 1 ]] \
    || return 1
  bounded_cmp "${marker}" "${expected}"
}

guest_main() {
  [[ "$(uname -s)" == Linux ]] || die "${EX_USAGE}" "guest mode is Linux-only"
  [[ "${EUID}" -eq 0 ]] || die "${EX_NOPERM}" "guest mode requires root"
  [[ "${SHADOWPIPE_PHASE3_GUEST_ORCHESTRATOR:-}" == 1 ]] \
    || die "${EX_USAGE}" "missing host orchestrator attestation"
  [[ "${SHADOWPIPE_PHASE3_CLONE_NAME:-}" == sphr-* ]] \
    || die "${EX_USAGE}" "guest is not marked as a disposable Phase-3 clone"
  [[ "$#" -eq 2 ]] || die "${EX_USAGE}" "guest mode expects RUN_ID and GUEST_USER"

  local run_id guest_user
  run_id="$(sanitize_component "$1")" || die "${EX_USAGE}" "unsafe run id"
  guest_user="$(sanitize_component "$2")" || die "${EX_USAGE}" "unsafe guest user"
  id "${guest_user}" >/dev/null || die "${EX_UNAVAILABLE}" "guest user is absent"
  local magic="${SHADOWPIPE_PHASE3_MAGIC:-}"
  validate_magic "${magic}" \
    || die "${EX_USAGE}" "guest build magic is missing or invalid"

  local owner_basename="${SHADOWPIPE_PHASE3_OWNER_BASENAME:-}"
  owner_basename="$(sanitize_component "${owner_basename}")" \
    || die "${EX_USAGE}" "unsafe clone ownership marker basename"
  [[ "${owner_basename}" == "${SHADOWPIPE_PHASE3_CLONE_NAME}.owner" ]] \
    || die "${EX_USAGE}" "clone ownership marker basename is not bound to the clone"
  local owner_marker="${GUEST_OWNER_DIRECTORY}/${owner_basename}"
  local expected_owner_file="${SHADOWPIPE_PHASE3_EXPECTED_OWNER_FILE:-}"
  validate_guest_owner_marker "${owner_marker}" "${expected_owner_file}" \
    || die "${EX_NOPERM}" "clone ownership marker is absent, unsafe, or mismatched"

  local tool missing=''
  for tool in ip iptables ip6tables iptables-save ip6tables-save nft jq \
    unshare mount stat readlink sha256sum find sort xargs sed grep awk \
    chmod chown cp mv rm env bash flock uname seq timeout dirname \
    mktemp wc tr id /usr/bin/python3; do
    command -v "${tool}" >/dev/null || missing+="${tool} "
  done
  [[ -z "${missing}" ]] \
    || die "${EX_UNAVAILABLE}" "missing guest tools: ${missing% }"
  [[ -c /dev/net/tun ]] || die "${EX_UNAVAILABLE}" "/dev/net/tun is unavailable"

  exec 9>/run/lock/shadowpipe-phase3.lock
  flock -n 9 || die 75 "another Phase-3 lab is active in this clone"
  # Namespace handles survive exec/unshare and let each child prove that its
  # destructive scenario is genuinely distinct from this clone's root net/mnt.
  exec 7</proc/thread-self/ns/net
  exec 8</proc/thread-self/ns/mnt

  local script_dir repo_root result_root helper
  script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
  repo_root="$(cd -- "${script_dir}/../.." && pwd -P)"
  result_root="${script_dir}/results/${run_id}"
  helper="${SHADOWPIPE_PHASE3_HELPER:-}"
  [[ -x "${helper}" ]] || die "${EX_UNAVAILABLE}" "built Phase-3 helper is absent"
  [[ ! -e "${result_root}" && ! -L "${result_root}" ]] \
    || die "${EX_USAGE}" "result directory already exists or is a dangling symlink"
  mkdir -p -- "${result_root}/scenarios"

  snapshot_guest_root "${result_root}/guest-root-before"
  {
    printf 'SHADOWPIPE_MAGIC=%s\n' "${magic}"
    uname -a
    "${helper}" --version 2>&1 || true
    ip -Version
    iptables --version
    ip6tables --version
    rustc --version 2>/dev/null || true
  } >"${result_root}/versions.txt"

  run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
    planned-all-absent planned none recovered none || true
  run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
    applied-tun after-apply-1 none recovered none || true
  run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
    applied-route-zero after-apply-2 none recovered none || true
  run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
    applied-route-high after-apply-3 none recovered none || true
  run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
    applied-endpoint-bypass after-apply-4 none recovered none || true
  run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
    dns-staged dns-staged none recovered none || true
  run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
    applied-dns after-apply-5 none recovered none || true
  run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
    applied-firewall after-apply-6 none recovered none || true
  run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
    firewall-ipv4-acked firewall-after-ipv4-ack none recovered none || true
  run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
    firewall-ipv6-acked-before-endpoint firewall-after-ipv6-ack none recovered none || true
  run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
    all-applied-before-active firewall-after-endpoint-ack none recovered none || true
  run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
    active-all active none recovered none || true
  local step
  for step in $(seq 1 "${EXPECTED_RECOVERY_STEPS}"); do
    run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
      "cleaning-before-${step}" active "before-step-${step}" recovered none || true
    run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
      "cleaning-after-${step}" active "after-step-${step}" recovered none || true
  done
  run_guest_scenario "${result_root}" "${run_id}" "${helper}" \
    all-or-nothing-conflict active none conflict tun-alias || true

  snapshot_guest_root "${result_root}/guest-root-after"
  local root_name
  for root_name in links.json routes-ipv4.json iptables.txt ip6tables.txt nft.txt \
    resolv.identity resolv.sha256; do
    if ! files_equal \
      "${result_root}/guest-root-before/${root_name}" \
      "${result_root}/guest-root-after/${root_name}"; then
      record_guest_failure "guest root snapshot changed: ${root_name}"
    fi
  done

  write_guest_result "${result_root}" "${run_id}"
  chown -R "${guest_user}:$(id -gn "${guest_user}")" "${result_root}" 2>/dev/null || true
  seal_bundle "${result_root}"
  (( guest_failed == 0 ))
}

validate_host_owner_file() {
  local file="$1" expected_uid="$2" mode uid nlink metadata
  [[ -f "${file}" && ! -L "${file}" ]] || return 1
  case "$(uname -s)" in
    Darwin)
      metadata="$(run_bounded "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
        stat -f '%Lp %u %l' -- "${file}")" || return 1
      ;;
    Linux)
      metadata="$(run_bounded "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
        stat -c '%a %u %h' -- "${file}")" || return 1
      ;;
    *) return 1 ;;
  esac
  read -r mode uid nlink <<<"${metadata}" || return 1
  [[ "${mode}" == 600 && "${uid}" == "${expected_uid}" && "${nlink}" == 1 ]]
}

create_guest_owner_marker() {
  local clone_vm="$1" repo_root="$2" marker="$3" expected="$4" output="$5"
  local marker_basename="${marker##*/}"
  [[ "${marker}" == "${GUEST_OWNER_DIRECTORY}/${marker_basename}" ]] || return 1
  marker_basename="$(sanitize_component "${marker_basename}")" || return 1
  # The single-quoted program is intentionally evaluated inside the guest.
  # shellcheck disable=SC2016
  run_bounded "${ORB_COMMAND_TIMEOUT_SECONDS}" \
    orb -m "${clone_vm}" -u root -p -w "${repo_root}" \
    bash -ceu '
      parent=/var/lib/shadowpipe-phase3-lab
      marker="$parent/$1"
      expected=$2
      [[ -f "$expected" && ! -L "$expected" ]]
      if [[ -e "$parent" || -L "$parent" ]]; then
        [[ -d "$parent" && ! -L "$parent" ]]
      else
        mkdir -m 0700 -- "$parent"
      fi
      chown root:root -- "$parent"
      chmod 0700 -- "$parent"
      read -r mode uid gid parent_nlink < <(stat -c "%a %u %g %h" -- "$parent")
      [[ "$mode" == 700 && "$uid" == 0 && "$gid" == 0 ]]
      [[ "$parent_nlink" =~ ^[1-9][0-9]*$ ]]
      [[ ! -e "$marker" && ! -L "$marker" ]]
      temporary="$parent/.owner.$$"
      [[ ! -e "$temporary" && ! -L "$temporary" ]]
      umask 077
      cp -- "$expected" "$temporary"
      chown root:root -- "$temporary"
      chmod 0600 -- "$temporary"
      ln -- "$temporary" "$marker"
      rm -- "$temporary"
      read -r mode uid gid nlink < <(stat -c "%a %u %g %h" -- "$marker")
      [[ "$mode" == 600 && "$uid" == 0 && "$gid" == 0 && "$nlink" == 1 ]]
      python3 -I -S -c '"'"'
import sys
with open(sys.argv[1], "rb") as left, open(sys.argv[2], "rb") as right:
    while True:
        a = left.read(1024 * 1024)
        b = right.read(1024 * 1024)
        if a != b:
            raise SystemExit(1)
        if not a:
            break
'"'"' "$marker" "$expected"
    ' _ "${marker_basename}" "${expected}" >"${output}" 2>"${output}.stderr"
}

verify_guest_owner_marker_from_host() {
  local clone_vm="$1" repo_root="$2" marker="$3" expected="$4" output="$5"
  local marker_basename="${marker##*/}"
  [[ "${marker}" == "${GUEST_OWNER_DIRECTORY}/${marker_basename}" ]] || return 1
  marker_basename="$(sanitize_component "${marker_basename}")" || return 1
  # The single-quoted program is intentionally evaluated inside the guest.
  # shellcheck disable=SC2016
  run_bounded "${ORB_COMMAND_TIMEOUT_SECONDS}" \
    orb -m "${clone_vm}" -u root -p -w "${repo_root}" \
    bash -ceu '
      parent=/var/lib/shadowpipe-phase3-lab
      marker="$parent/$1"
      expected=$2
      [[ -d "$parent" && ! -L "$parent" ]]
      [[ -f "$marker" && ! -L "$marker" ]]
      [[ -f "$expected" && ! -L "$expected" ]]
      read -r parent_mode parent_uid parent_gid parent_nlink < <(stat -c "%a %u %g %h" -- "$parent")
      read -r mode uid gid nlink < <(stat -c "%a %u %g %h" -- "$marker")
      [[ "$parent_mode" == 700 && "$parent_uid" == 0 && "$parent_gid" == 0 ]]
      [[ "$parent_nlink" =~ ^[1-9][0-9]*$ ]]
      [[ "$mode" == 600 && "$uid" == 0 && "$gid" == 0 && "$nlink" == 1 ]]
      python3 -I -S -c '"'"'
import sys
with open(sys.argv[1], "rb") as left, open(sys.argv[2], "rb") as right:
    while True:
        a = left.read(1024 * 1024)
        b = right.read(1024 * 1024)
        if a != b:
            raise SystemExit(1)
        if not a:
            break
'"'"' "$marker" "$expected"
      sha256sum -- "$marker"
    ' _ "${marker_basename}" "${expected}" >"${output}" 2>"${output}.stderr"
}

host_main() {
  [[ "$(uname -s)" == Darwin ]] || die "${EX_USAGE}" "host mode requires macOS"
  [[ "${SHADOWPIPE_DISPOSABLE_PHASE3:-}" == 1 ]] \
    || die "${EX_USAGE}" "set SHADOWPIPE_DISPOSABLE_PHASE3=1"
  [[ "$#" -le 1 ]] || { usage >&2; exit "${EX_USAGE}"; }

  local tool
  for tool in orb orbctl route netstat scutil pgrep ps mktemp awk sed tr wc \
    date sha256sum find sort pfctl stat grep /usr/bin/python3; do
    command -v "${tool}" >/dev/null \
      || die "${EX_UNAVAILABLE}" "missing host dependency: ${tool}"
  done

  local source_vm="${1:-${SOURCE_DEFAULT}}"
  source_vm="$(sanitize_component "${source_vm}")" \
    || die "${EX_USAGE}" "unsafe source VM name"
  [[ "${source_vm}" == "${SOURCE_DEFAULT}" ]] \
    || die "${EX_USAGE}" "Phase-3 may clone only the stopped ${SOURCE_DEFAULT} source VM"
  local magic_source=fixed_lab_default
  [[ "${SHADOWPIPE_MAGIC+x}" == x ]] && magic_source=environment
  local magic="${SHADOWPIPE_MAGIC:-${MAGIC_DEFAULT}}"
  validate_magic "${magic}" \
    || die "${EX_USAGE}" 'SHADOWPIPE_MAGIC must be one explicit u32 value'
  local script_dir repo_root result_root run_id clone_vm target_dir helper
  script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
  repo_root="$(cd -- "${script_dir}/../.." && pwd -P)"
  result_root="${script_dir}/results"
  mkdir -p -- "${result_root}"
  [[ -d "${result_root}" && ! -L "${result_root}" ]] \
    || die "${EX_NOPERM}" "result root is not a real directory"
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  clone_vm="sphr-$(printf '%s' "${run_id}" | tr '[:upper:]' '[:lower:]')"
  # Orb command sessions do not guarantee a shared guest /tmp view. Keep the
  # one-off target under the already shared repository, verify it in the build
  # session, and remove it during host cleanup.
  target_dir="${repo_root}/target/phase3-lab-${run_id}"
  helper="${target_dir}/release/examples/${HELPER_NAME}"

  local host_tmp before after build_log guest_log build_contract orb_evidence result_dir
  local private_owner_file shared_owner_file guest_owner_marker host_lock_dir
  host_tmp="$(mktemp -d "${TMPDIR:-/tmp}/shadowpipe-phase3-host.XXXXXX")"
  before="${host_tmp}/mac-before"
  after="${host_tmp}/mac-after"
  build_log="${host_tmp}/build.log"
  guest_log="${host_tmp}/guest.log"
  build_contract="${host_tmp}/build-contract.env"
  orb_evidence="${host_tmp}/orb-evidence"
  result_dir="${result_root}/${run_id}"
  private_owner_file="${host_tmp}/clone-owner.env"
  shared_owner_file="${target_dir}/clone-owner.env"
  guest_owner_marker="${GUEST_OWNER_DIRECTORY}/${clone_vm}.owner"
  # All privileged Shadowpipe OrbStack runners share this one conservative
  # lifecycle mutex. Different owner-file schemas are intentional: mkdir is
  # the cross-runner exclusion primitive, and each owner removes only its own.
  host_lock_dir="/tmp/shadowpipe-orbstack-lifecycle.lock"
  mkdir -p -- "${orb_evidence}"
  : >"${build_log}"
  : >"${guest_log}"
  {
    printf 'schema_version=1\n'
    printf 'profile=release\n'
    printf 'package=shadowpipe-core\n'
    printf 'example=%s\n' "${HELPER_NAME}"
    printf 'features=no-default-features\n'
    printf 'magic_source=%s\n' "${magic_source}"
    printf 'SHADOWPIPE_MAGIC=%s\n' "${magic}"
  } >"${build_contract}"

  local clone_attempted=0 clone_absent_before=0 clone_created_confirmed=0
  local clone_completion_uncertain=0
  local source_orb_id='' clone_orb_id='' clone_identity_bound=0
  local clone_deletion_pending=0
  local clone_started=0 guest_marker_attempted=0 guest_marker_valid=0
  local destructive_guest_started=0 baseline_valid=0 lock_acquired=0
  local final_status=0 guest_command_status=1 guest_user=''
  local cleanup_running=0 target_initialized=0
  host_cleanup() {
    local incoming=$?
    (( cleanup_running == 0 )) || exit 1
    cleanup_running=1
    trap - EXIT INT TERM HUP
    set +e
    (( incoming == 0 )) || final_status="${incoming}"
    local host_safety_status=failed cleanup_status=valid
    local clone_absence_status=failed evidence_status=failed guest_status=failed
    local clone_state=unknown delete_authorized=0 delete_proof=none
    local evidence_preflight=valid overall verdict quarantine=none
    local pf_runtime_observed=false

    if (( clone_completion_uncertain != 0 )); then
      clone_state="$(observe_clone_quiescence "${clone_vm}" \
        "${orb_evidence}/clone-quiescence-before-cleanup" stable_any)" \
        || clone_state=unknown
    else
      clone_state="$(orb_exact_state \
        "${clone_vm}" "${orb_evidence}/cleanup-before.list")" \
        || clone_state=unknown
    fi
    if [[ "${clone_state}" != unknown ]]; then
      printf 'clone_state_before_cleanup=%s\n' "${clone_state}" \
        >"${orb_evidence}/cleanup-state.env"
    else
      warn 'cannot census clone before cleanup'
      cleanup_status=failed
      clone_state=unknown
    fi

    if [[ "${clone_state}" == absent ]] && (( clone_created_confirmed != 0 )); then
      warn 'confirmed owned clone disappeared before authorized cleanup'
      cleanup_status=failed
    fi

    if [[ "${clone_state}" != absent && "${clone_state}" != unknown ]]; then
      if (( clone_identity_bound != 0 )) \
        && capture_orb_identity "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
          "${clone_vm}" "${clone_vm}" "${clone_orb_id}" '' \
          "${orb_evidence}/clone-info-cleanup-before-marker" >/dev/null \
        && validate_host_owner_file "${private_owner_file}" "$(id -u)" \
        && validate_host_owner_file "${shared_owner_file}" "$(id -u)" \
        && bounded_cmp "${private_owner_file}" "${shared_owner_file}" \
        && (( clone_attempted != 0 && clone_absent_before != 0 )); then
        if (( guest_marker_attempted != 0 )); then
          if [[ "${clone_state}" != running ]]; then
            if run_bounded "${ORB_START_TIMEOUT_SECONDS}" \
              orbctl start "${clone_orb_id}" \
              >"${orb_evidence}/cleanup-marker-start.log" 2>&1; then
              clone_state=running
            else
              cleanup_status=failed
            fi
          fi
          if [[ "${clone_state}" == running ]] \
            && capture_orb_identity "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
              "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
              "${orb_evidence}/clone-info-cleanup-before-owner-verify" >/dev/null \
            && verify_guest_owner_marker_from_host \
              "${clone_orb_id}" "${repo_root}" "${guest_owner_marker}" \
              "${shared_owner_file}" "${orb_evidence}/cleanup-owner-verify.log"; then
            delete_authorized=1
            delete_proof=opaque_id_and_host_and_guest_markers
          elif (( destructive_guest_started == 0 )); then
            delete_authorized=1
            delete_proof=opaque_id_bound_pre_destructive_clone
          else
            warn 'guest ownership marker cannot be revalidated after destructive work'
            cleanup_status=failed
          fi
        elif (( destructive_guest_started == 0 )); then
          delete_authorized=1
          delete_proof=opaque_id_bound_pre_guest_clone
        else
          warn 'destructive work started without a guest ownership marker'
          cleanup_status=failed
        fi
      else
        warn 'host clone ownership proof is absent or unsafe; refusing delete'
        cleanup_status=failed
      fi

      if (( delete_authorized != 0 )); then
        if [[ "${clone_state}" != stopped ]]; then
          if ! run_bounded "${ORB_STOP_TIMEOUT_SECONDS}" \
            orbctl stop "${clone_orb_id}" \
            >"${orb_evidence}/cleanup-stop.log" 2>&1; then
            cleanup_status=failed
          else
            clone_state=stopped
          fi
        fi
        if [[ "${cleanup_status}" == valid ]] \
          && capture_orb_identity "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
            "${clone_vm}" "${clone_vm}" "${clone_orb_id}" stopped \
            "${orb_evidence}/clone-info-cleanup-before-delete" >/dev/null; then
          if run_bounded "${ORB_DELETE_TIMEOUT_SECONDS}" \
            orbctl delete -f "${clone_vm}" \
            >"${orb_evidence}/cleanup-delete.log" 2>&1; then
            clone_deletion_pending=1
            printf '%s\n' \
              'delete_selector=name_after_fresh_name_to_bound_id_validation' \
              >"${orb_evidence}/clone-delete-addressing.env"
          else
            cleanup_status=failed
          fi
        else
          cleanup_status=failed
        fi
      fi
    fi
    {
      printf 'clone_attempted=%s\n' "${clone_attempted}"
      printf 'clone_absent_before=%s\n' "${clone_absent_before}"
      printf 'clone_created_confirmed=%s\n' "${clone_created_confirmed}"
      printf 'clone_completion_uncertain=%s\n' "${clone_completion_uncertain}"
      printf 'clone_started=%s\n' "${clone_started}"
      printf 'guest_marker_attempted=%s\n' "${guest_marker_attempted}"
      printf 'guest_marker_valid=%s\n' "${guest_marker_valid}"
      printf 'destructive_guest_started=%s\n' "${destructive_guest_started}"
      printf 'delete_authorized=%s\n' "${delete_authorized}"
      printf 'delete_proof=%s\n' "${delete_proof}"
    } >>"${orb_evidence}/cleanup-state.env"

    if (( clone_completion_uncertain != 0 || clone_deletion_pending != 0 )); then
      clone_state="$(observe_clone_quiescence "${clone_vm}" \
        "${orb_evidence}/clone-quiescence-after-cleanup" absent_all)" \
        || clone_state=unknown
    else
      clone_state="$(orb_exact_state \
        "${clone_vm}" "${orb_evidence}/cleanup-final.list")" \
        || clone_state=unknown
    fi
    if [[ "${clone_state}" == absent && "${clone_identity_bound}" == 1 ]] \
      && capture_orb_absence "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
        "${clone_orb_id}" "${orb_evidence}/clone-info-final-id" \
      && capture_orb_absence "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
        "${clone_vm}" "${orb_evidence}/clone-info-final-name"; then
      clone_absence_status=valid
    elif [[ "${clone_state}" == absent && "${clone_attempted}" == 0 \
      && "${clone_absent_before}" == 1 ]] \
      && capture_orb_absence "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
        "${clone_vm}" "${orb_evidence}/clone-info-final-name"; then
      # A failure before clone creation has no clone opaque ID to prove absent.
      # Exact-name absence before and after the failed preflight is the complete
      # lifecycle claim in that case; never fabricate an ID-level assertion.
      clone_absence_status=valid
    else
      warn "exact final clone absence is unproven (state=${clone_state:-collector_failed})"
      clone_absence_status=failed
      cleanup_status=failed
    fi
    if [[ -n "${source_orb_id}" ]]; then
      capture_orb_identity "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
        "${source_vm}" "${source_vm}" "${source_orb_id}" stopped \
        "${orb_evidence}/source-info-final" >/dev/null \
        || cleanup_status=failed
    else
      cleanup_status=failed
    fi

    if (( target_initialized == 0 )); then
      if [[ -e "${target_dir}" || -L "${target_dir}" ]]; then
        warn 'uninitialized target path unexpectedly exists; refusing removal'
        cleanup_status=failed
      fi
    elif [[ "${target_dir}" == "${repo_root}/target/phase3-lab-${run_id}" \
      && -d "${target_dir}" && ! -L "${target_dir}" ]] \
      && validate_host_owner_file "${shared_owner_file}" "$(id -u)" \
      && bounded_cmp "${private_owner_file}" "${shared_owner_file}"; then
      run_bounded "${FILE_CLEANUP_TIMEOUT_SECONDS}" rm -rf -- "${target_dir}" \
        >"${orb_evidence}/target-cleanup.log" 2>&1 || cleanup_status=failed
      [[ ! -e "${target_dir}" && ! -L "${target_dir}" ]] || cleanup_status=failed
      target_initialized=0
    else
      warn 'target cleanup path or ownership marker failed its exact proof'
      cleanup_status=failed
    fi

    if (( baseline_valid != 0 )) && snapshot_macos "${after}" \
      && compare_macos_snapshots "${before}" "${after}"; then
      host_safety_status=valid
      pf_runtime_observed="$(awk -F= '$1 == "pf_runtime_observed" { print $2 }' \
        "${before}/pf-runtime-observation.env")"
      if [[ "${pf_runtime_observed}" != true \
        && "${pf_runtime_observed}" != false ]]; then
        host_safety_status=failed
        pf_runtime_observed=false
      fi
    else
      if (( baseline_valid == 0 )); then
        snapshot_macos "${after}" || true
      fi
      warn 'macOS route/DNS/PF/sing-box safety comparison failed or baseline was invalid'
      host_safety_status=failed
    fi

    if (( lock_acquired != 0 )); then
      if [[ -d "${host_lock_dir}" && ! -L "${host_lock_dir}" \
        && -f "${host_lock_dir}/owner.env" && ! -L "${host_lock_dir}/owner.env" ]] \
        && bounded_cmp "${host_lock_dir}/owner.env" "${private_owner_file}"; then
        bounded_file_operation rm -- "${host_lock_dir}/owner.env" \
          && bounded_file_operation rmdir -- "${host_lock_dir}" \
          || cleanup_status=failed
      else
        warn 'host lifecycle lock ownership changed; refusing blind removal'
        cleanup_status=failed
      fi
      lock_acquired=0
    fi

    if [[ ! -d "${result_root}" || -L "${result_root}" ]]; then
      warn "result root became unsafe; refusing publication (raw host evidence retained at ${host_tmp})"
      trap - EXIT
      exit 1
    fi

    if [[ -e "${result_dir}" || -L "${result_dir}" ]]; then
      if bounded_bundle_operation validate "${result_dir}"; then
        if (( guest_command_status == 0 )) \
          && bounded_bundle_operation verify "${result_dir}" \
          && validate_guest_status_file "${result_dir}/status.env" "${run_id}"; then
          guest_status="$(guest_status_value "${result_dir}/status.env")"
        else
          guest_status=failed
        fi
      else
        quarantine="${result_root}/${run_id}.unsafe.$$"
        if [[ ! -e "${quarantine}" && ! -L "${quarantine}" ]] \
          && bounded_file_operation mv -- "${result_dir}" "${quarantine}"; then
          warn "unsafe guest evidence quarantined at ${quarantine}"
        else
          warn 'unsafe guest evidence could not be quarantined'
          quarantine=failed
          evidence_preflight=failed
          result_dir="${result_root}/${run_id}.host-failure.$$"
        fi
      fi
    fi
    if [[ ! -e "${result_dir}" && ! -L "${result_dir}" ]]; then
      bounded_file_operation mkdir -- "${result_dir}" || evidence_preflight=failed
    fi

    if bounded_bundle_operation validate "${result_dir}"; then
      bounded_file_operation rm -f -- \
        "${result_dir}/checksums.sha256" "${result_dir}/evidence-census.txt" \
        || evidence_preflight=failed
      bounded_file_operation rm -rf -- "${result_dir}/host-evidence" \
        || evidence_preflight=failed
      bounded_file_operation mkdir -- "${result_dir}/host-evidence" \
        || evidence_preflight=failed
      bounded_file_operation cp -- \
        "${build_log}" "${result_dir}/host-evidence/host-build.log" \
        || evidence_preflight=failed
      bounded_file_operation cp -- \
        "${guest_log}" "${result_dir}/host-evidence/host-guest.log" \
        || evidence_preflight=failed
      bounded_file_operation cp -- \
        "${build_contract}" "${result_dir}/host-evidence/build-contract.env" \
        || evidence_preflight=failed
      bounded_file_operation cp -- \
        "${private_owner_file}" "${result_dir}/host-evidence/clone-owner.env" \
        || evidence_preflight=failed
      bounded_file_operation cp -R -- \
        "${before}" "${result_dir}/host-evidence/mac-before" \
        || evidence_preflight=failed
      bounded_file_operation cp -R -- \
        "${after}" "${result_dir}/host-evidence/mac-after" \
        || evidence_preflight=failed
      bounded_file_operation cp -R -- \
        "${orb_evidence}" "${result_dir}/host-evidence/orb-lifecycle" \
        || evidence_preflight=failed
      printf 'unsafe_guest_quarantine=%s\n' "${quarantine}" \
        >"${result_dir}/host-evidence/publication.env" \
        || evidence_preflight=failed
    else
      evidence_preflight=failed
    fi

    # Never perform even failure-publication writes through an unsafe result
    # path. A same-root writer is outside the trust boundary, but this branch
    # still fails closed into a fresh sibling when possible.
    if ! bounded_bundle_operation validate "${result_dir}"; then
      result_dir="${result_root}/${run_id}.host-failure-safe.$$"
      if [[ ! -e "${result_dir}" && ! -L "${result_dir}" ]]; then
        bounded_file_operation mkdir -- "${result_dir}" || true
      fi
      evidence_preflight=failed
    fi
    if ! bounded_bundle_operation validate "${result_dir}"; then
      warn "no safe result path is available; raw host evidence retained at ${host_tmp}"
      trap - EXIT
      exit 1
    fi

    run_bounded "${FILE_CLEANUP_TIMEOUT_SECONDS}" rm -rf -- "${host_tmp}" \
      >/dev/null 2>&1 || cleanup_status=failed
    [[ ! -e "${host_tmp}" && ! -L "${host_tmp}" ]] || cleanup_status=failed

    bounded_file_operation rm -f -- "${result_dir}/HOST-FAILURE.md" \
      "${result_dir}/HOST-SAFETY-FAILURE.md" \
      "${result_dir}/CLEANUP-FAILURE.md" \
      "${result_dir}/EVIDENCE-FAILURE.md" \
      "${result_dir}/FINALIZED.env" 2>/dev/null || evidence_preflight=failed
    [[ "${host_safety_status}" == valid ]] || {
      printf '# Host safety failure\n\nStable macOS state changed or a required collector failed.\n' \
        >"${result_dir}/HOST-SAFETY-FAILURE.md" || evidence_preflight=failed
    }
    [[ "${cleanup_status}" == valid && "${clone_absence_status}" == valid ]] || {
      printf '# Cleanup failure\n\nClone cleanup or exact final absence was not proven.\n' \
        >"${result_dir}/CLEANUP-FAILURE.md" || evidence_preflight=failed
    }
    [[ "${guest_status}" == valid ]] || {
      printf '# Guest failure\n\nThe guest matrix, its status schema, or its initial seal was invalid.\n' \
        >"${result_dir}/HOST-FAILURE.md" || evidence_preflight=failed
    }

    if [[ "${evidence_preflight}" == valid ]] \
      && bounded_bundle_operation validate "${result_dir}"; then
      evidence_status=valid
    else
      evidence_status=failed
    fi
    overall="$(compute_overall_status "${guest_status}" "${host_safety_status}" \
      "${cleanup_status}" "${clone_absence_status}" "${evidence_status}")"
    verdict=FAIL
    [[ "${overall}" == valid ]] && verdict=PASS
    write_final_status_file "${result_dir}/status.env" "${run_id}" \
      "${guest_status}" "${host_safety_status}" "${cleanup_status}" \
      "${clone_absence_status}" "${evidence_status}" "${pf_runtime_observed}" \
      || evidence_status=failed
    {
      printf '# ShadowPipe Phase-3 final host verdict\n\n'
      printf -- '- Overall verdict: **%s**\n' "${verdict}"
      printf -- '- Guest matrix: %s\n' "${guest_status}"
      printf -- '- macOS safety: %s\n' "${host_safety_status}"
      printf -- '- Cleanup: %s\n' "${cleanup_status}"
      printf -- '- Exact clone absence: %s\n' "${clone_absence_status}"
      printf -- '- Evidence seal: %s\n' "${evidence_status}"
      printf -- '- Release helper SHADOWPIPE_MAGIC: %s\n' "${magic}"
      printf -- '- Release helper magic source: %s\n' "${magic_source}"
      printf -- '- Loaded PF runtime observed: %s\n' "${pf_runtime_observed}"
      printf -- '- Field evidence: false\n'
      if [[ "${pf_runtime_observed}" == false ]]; then
        printf -- '- Host-safety scope: PF files and the exact stable permission-denied collector outcome were compared; loaded PF runtime rules were not observed.\n'
      fi
      printf -- '- Host-safety timing: before/after endpoint snapshots, not a continuous mutation monitor.\n'
      printf -- '- Evidence authenticity: relative SHA-256 plus a final census; no external signature or timestamp authority.\n'
      printf -- '- VM identity: strict duplicate-key-rejecting OrbStack JSON bound opaque source/clone IDs; start/stop/guest operations used the clone ID, while delete-by-name required an immediate name-to-ID revalidation because OrbStack 2.2.1 panicked on delete-by-ID in an observed lab run.\n'
      printf '\nAn unrelated same-host OrbStack lifecycle operator is outside this run\047s trust boundary.\n'
    } >"${result_dir}/FINAL-RESULT.md" || evidence_status=failed
    printf 'finalization=complete\nrun_id=%s\n' "${run_id}" \
      >"${result_dir}/FINALIZED.env" || evidence_status=failed

    if [[ "${evidence_status}" != valid ]] \
      || ! validate_final_status_file "${result_dir}/status.env" "${run_id}" \
      || ! bounded_bundle_operation seal "${result_dir}"; then
      evidence_status=failed
      final_status=1
      bounded_file_operation rm -f -- "${result_dir}/checksums.sha256" \
        "${result_dir}/evidence-census.txt" "${result_dir}/FINALIZED.env" \
        "${result_dir}/status.env"
      printf '# Evidence failure\n\nThe final evidence tree could not be safely sealed and verified.\n' \
        >"${result_dir}/EVIDENCE-FAILURE.md" 2>/dev/null || true
      local failure_status_written=0
      if write_final_status_file "${result_dir}/status.env" "${run_id}" \
        "${guest_status}" "${host_safety_status}" "${cleanup_status}" \
        "${clone_absence_status}" failed "${pf_runtime_observed}" \
        2>/dev/null; then
        failure_status_written=1
      fi
      {
        printf '# ShadowPipe Phase-3 final host verdict\n\n'
        printf -- '- Overall verdict: **FAIL**\n'
        printf -- '- Evidence seal: failed\n'
      } >"${result_dir}/FINAL-RESULT.md" 2>/dev/null || true
      if (( failure_status_written != 0 )); then
        bounded_bundle_operation seal "${result_dir}" >/dev/null 2>&1 || true
      fi
    fi

    overall="$(awk -F= '$1 == "overall_status" { print $2 }' \
      "${result_dir}/status.env" 2>/dev/null)"
    [[ "${overall}" == valid ]] || final_status=1
    say "result: ${result_dir}"
    trap - EXIT
    exit "${final_status}"
  }
  trap host_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP

  if ! mkdir -- "${host_lock_dir}" 2>/dev/null; then
    die "${EX_UNAVAILABLE}" \
      "another Phase-3 host lifecycle may be active (lock=${host_lock_dir})"
  fi
  lock_acquired=1
  {
    printf 'schema_version=1\n'
    printf 'run_id=%s\n' "${run_id}"
    printf 'clone_vm=%s\n' "${clone_vm}"
    printf 'source_vm=%s\n' "${source_vm}"
    printf 'repo_root=%s\n' "${repo_root}"
    printf 'host_pid=%s\n' "$$"
    printf 'nonce=%s\n' "${host_tmp##*.}"
  } >"${private_owner_file}"
  chmod 0600 "${private_owner_file}"
  cp -- "${private_owner_file}" "${host_lock_dir}/owner.env"
  chmod 0600 "${host_lock_dir}/owner.env"

  create_source_provenance_manifest "${repo_root}" \
    "${orb_evidence}/source-provenance-before.sha256" \
    "tests/host-recovery/run-orbstack-phase3.sh"

  local source_state clone_state
  source_state="$(orb_exact_state "${source_vm}" "${orb_evidence}/initial.list")" \
    || die "${EX_UNAVAILABLE}" "cannot census OrbStack machines"
  [[ "${source_state}" == stopped ]] \
    || die "${EX_USAGE}" \
      "source VM ${source_vm} must be stopped (state=${source_state:-missing})"
  clone_state="$(orb_exact_state_from_file \
    "${orb_evidence}/initial.list" "${clone_vm}")" \
    || die "${EX_UNAVAILABLE}" "generated clone census is ambiguous"
  [[ "${clone_state}" == absent ]] \
    || die "${EX_USAGE}" "generated clone already exists: ${clone_vm}"
  clone_absent_before=1
  source_orb_id="$(capture_orb_identity \
    "${HOST_COLLECTOR_TIMEOUT_SECONDS}" "${source_vm}" "${source_vm}" \
    '' stopped "${orb_evidence}/source-info-before")" \
    || die "${EX_UNAVAILABLE}" "cannot bind stopped source VM opaque ID"

  snapshot_macos "${before}" \
    || die "${EX_UNAVAILABLE}" \
      "live macOS baseline collector failed; raw evidence will be preserved"
  baseline_valid=1

  [[ ! -e "${target_dir}" && ! -L "${target_dir}" ]] \
    || die "${EX_USAGE}" "generated target directory already exists"
  [[ -d "${repo_root}/target" && ! -L "${repo_root}/target" \
    && "$(cd -- "${repo_root}/target" && pwd -P)" == "${repo_root}/target" ]] \
    || die "${EX_NOPERM}" "shared target root is absent, symlinked, or redirected"
  mkdir -m 0700 -- "${target_dir}"
  cp -- "${private_owner_file}" "${shared_owner_file}"
  chmod 0600 "${shared_owner_file}"
  if ! validate_host_owner_file "${private_owner_file}" "$(id -u)" \
    || ! validate_host_owner_file "${shared_owner_file}" "$(id -u)" \
    || ! bounded_cmp "${private_owner_file}" "${shared_owner_file}"; then
    die "${EX_NOPERM}" "host ownership markers are unsafe"
  fi
  target_initialized=1

  say "cloning stopped ${source_vm} -> disposable ${clone_vm}"
  clone_attempted=1
  clone_completion_uncertain=1
  if ! run_bounded "${ORB_CLONE_TIMEOUT_SECONDS}" \
    orbctl clone "${source_vm}" "${clone_vm}" \
    >"${orb_evidence}/clone.log" 2>&1; then
    die 1 "bounded clone failed; cleanup will run two exact quiescence windows"
  fi
  clone_state="$(orb_exact_state "${clone_vm}" "${orb_evidence}/after-clone.list")" \
    || die 1 "cannot census clone after creation"
  [[ "${clone_state}" != absent ]] || die 1 "clone command returned without a clone"
  capture_orb_identity "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
    "${source_vm}" "${source_vm}" "${source_orb_id}" stopped \
    "${orb_evidence}/source-info-after-clone" >/dev/null \
    || die 1 "source VM identity or state changed during clone"
  clone_orb_id="$(capture_orb_identity \
    "${HOST_COLLECTOR_TIMEOUT_SECONDS}" "${clone_vm}" "${clone_vm}" \
    '' stopped "${orb_evidence}/clone-info-after-clone")" \
    || die 1 "cannot bind disposable clone opaque ID"
  clone_identity_bound=1
  clone_created_confirmed=1
  clone_completion_uncertain=0
  capture_orb_identity "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
    "${clone_vm}" "${clone_vm}" "${clone_orb_id}" stopped \
    "${orb_evidence}/clone-info-before-start" >/dev/null \
    || die 1 "clone name was absent or reused before start"
  run_bounded "${ORB_START_TIMEOUT_SECONDS}" orbctl start "${clone_orb_id}" \
    >"${orb_evidence}/start.log" 2>&1 \
    || die 1 "bounded clone start failed"
  clone_started=1
  run_bounded "${ORB_COMMAND_TIMEOUT_SECONDS}" orb -m "${clone_orb_id}" id -un \
    >"${orb_evidence}/guest-user.txt" 2>"${orb_evidence}/guest-user.txt.stderr" \
    || die "${EX_UNAVAILABLE}" "cannot identify guest user"
  guest_user="$(<"${orb_evidence}/guest-user.txt")"
  guest_user="$(sanitize_component "${guest_user}")" \
    || die "${EX_UNAVAILABLE}" "unsafe guest user"
  capture_orb_identity "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
    "${clone_vm}" "${clone_vm}" "${clone_orb_id}" running \
    "${orb_evidence}/clone-info-before-owner-marker" >/dev/null \
    || die 1 "clone identity changed before ownership marking"

  guest_marker_attempted=1
  create_guest_owner_marker "${clone_orb_id}" "${repo_root}" \
    "${guest_owner_marker}" "${shared_owner_file}" \
    "${orb_evidence}/owner-create.log" \
    || die "${EX_NOPERM}" "cannot create safe guest ownership marker"
  verify_guest_owner_marker_from_host "${clone_orb_id}" "${repo_root}" \
    "${guest_owner_marker}" "${shared_owner_file}" \
    "${orb_evidence}/owner-verify.log" \
    || die "${EX_NOPERM}" "cannot verify guest ownership marker"
  bounded_cmp "${private_owner_file}" "${shared_owner_file}" \
    || die "${EX_NOPERM}" "shared ownership marker changed"
  guest_marker_valid=1

  say "building lab-only helper inside ${clone_vm}"
  if ! run_bounded "${ORB_BUILD_TIMEOUT_SECONDS}" \
    orb -m "${clone_orb_id}" -p -w "${repo_root}" bash -lc \
    "SHADOWPIPE_MAGIC='${magic}' CARGO_TARGET_DIR='${target_dir}' cargo build --release --locked --no-default-features -p shadowpipe-core --example '${HELPER_NAME}' && test -x '${helper}' && printf 'shadowpipe_magic=%s\\n' '${magic}' && sha256sum '${helper}'" \
    >"${build_log}" 2>&1; then
    die 1 "guest helper build failed"
  fi
  [[ "$(run_bounded "${HOST_COLLECTOR_TIMEOUT_SECONDS}" \
    grep -Fxc -- "shadowpipe_magic=${magic}" "${build_log}")" == 1 ]] \
    || die 1 "release build log did not bind exactly one validated SHADOWPIPE_MAGIC"
  verify_source_provenance_manifest "${repo_root}" \
    "${orb_evidence}/source-provenance-before.sha256" \
    "${orb_evidence}/source-provenance-after-build.sha256" \
    "tests/host-recovery/run-orbstack-phase3.sh" \
    || die 1 "source, runner, manifests, or Cargo.lock changed during the Phase-3 build"

  say "running privileged private-namespace matrix inside ${clone_vm}"
  destructive_guest_started=1
  set +e
  run_bounded "${ORB_GUEST_TIMEOUT_SECONDS}" \
    orb -m "${clone_orb_id}" -u root -p -w "${repo_root}" env \
    SHADOWPIPE_PHASE3_GUEST_ORCHESTRATOR=1 \
    SHADOWPIPE_PHASE3_CLONE_NAME="${clone_vm}" \
    SHADOWPIPE_PHASE3_HELPER="${helper}" \
    SHADOWPIPE_PHASE3_MAGIC="${magic}" \
    SHADOWPIPE_PHASE3_OWNER_BASENAME="${guest_owner_marker##*/}" \
    SHADOWPIPE_PHASE3_EXPECTED_OWNER_FILE="${shared_owner_file}" \
    bash tests/host-recovery/run-orbstack-phase3.sh --guest "${run_id}" "${guest_user}" \
    >"${guest_log}" 2>&1
  guest_command_status=$?
  set -e
  (( guest_command_status == 0 )) || final_status="${guest_command_status}"
  [[ -d "${result_root}/${run_id}" ]] || {
    warn 'guest did not publish a result bundle'
    final_status=1
  }
  verify_source_provenance_manifest "${repo_root}" \
    "${orb_evidence}/source-provenance-before.sha256" \
    "${orb_evidence}/source-provenance-final.sha256" \
    "tests/host-recovery/run-orbstack-phase3.sh" \
    || die 1 "source, runner, manifests, or Cargo.lock changed during the Phase-3 experiment"
  host_cleanup
}

write_selftest_wal() {
  local output="$1" phase="$2" states="$3"
  jq -n --arg phase "${phase}" --arg states "${states}" '
    ($states | split(",")) as $s
    | {
        schema_version: 3,
        generation: 17,
        phase: $phase,
        owner: {
          boot_id: "11111111111111111111111111111111",
          mount_namespace: {device: 5, inode: 101},
          network_namespace: {device: 5, inode: 102},
          pid: 4242,
          pid_start_ticks: 9001,
          session_id: "22222222222222222222222222222222",
          uid: 0
        },
        operations: [
          {id:1,state:$s[0],resource:{kind:"tun",resource:{interface:{name:"sp3tun0",ifindex:3}}}},
          {id:2,state:$s[1],resource:{kind:"route",resource:{purpose:"split_default",family:"ipv4",table:254,destination:{address:"0.0.0.0",prefix_len:1},gateway:null,output:{name:"sp3tun0",ifindex:3},protocol:186,metric:77}}},
          {id:3,state:$s[2],resource:{kind:"route",resource:{purpose:"split_default",family:"ipv4",table:254,destination:{address:"128.0.0.0",prefix_len:1},gateway:null,output:{name:"sp3tun0",ifindex:3},protocol:186,metric:77}}},
          {id:4,state:$s[3],resource:{kind:"route",resource:{purpose:"endpoint_bypass",family:"ipv4",table:254,destination:{address:"198.51.100.77",prefix_len:32},gateway:null,output:{name:"sp3wan0",ifindex:2},protocol:186,metric:77}}},
          {id:5,state:$s[4],resource:{kind:"dns",resource:{target:"etc_resolv_conf",original:{device:1,inode:2,uid:0,gid:0,mode:33188,link_count:1,kind:"regular"},original_sha256:"c8084f2d03e4a94fb2be6284c6d834f537d29df8a109b63978f6cb4821a26d14",pinned:{device:1,inode:3,uid:0,gid:0,mode:33188,link_count:1,kind:"regular"},pinned_sha256:"eb8ab10ec80696e3a7cd191b4bb4023666e948ebbb5c92b087c2b843a54bb6f5"}}},
          {id:6,state:$s[5],resource:{kind:"firewall",resource:{family:"ipv4",backend:"iptables_nft",chain_token:"11111111111111111111",filter_table_origin:"preexisting",output_chain_origin:"preexisting",expected_rule_count:4}}},
          {id:7,state:$s[6],resource:{kind:"firewall",resource:{family:"ipv6",backend:"iptables_nft",chain_token:"22222222222222222222",filter_table_origin:"absent_before_install",output_chain_origin:"absent_before_install",expected_rule_count:3}}},
          {id:8,state:$s[7],resource:{kind:"firewall_endpoint",resource:{family:"ipv4",backend:"iptables_nft",chain_token:"11111111111111111111",address:"198.51.100.77",transport:"tcp",port:443}}}
        ]
      }
  ' >"${output}"
}

self_test() {
  local temporary status self_uid self_gid repo_root
  command -v jq >/dev/null || return 1
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/shadowpipe-phase3-selftest.XXXXXX")"
  SELFTEST_TEMPORARY="${temporary}"
  trap 'rm -rf -- "${SELFTEST_TEMPORARY}"' EXIT
  self_uid="$(id -u)"
  self_gid="$(id -g)"
  repo_root="$(cd -- "$(dirname -- "$0")/../.." && pwd -P)"
  create_source_provenance_manifest "${repo_root}" \
    "${temporary}/source-before.sha256" \
    "tests/host-recovery/run-orbstack-phase3.sh"
  verify_source_provenance_manifest "${repo_root}" \
    "${temporary}/source-before.sha256" "${temporary}/source-after.sha256" \
    "tests/host-recovery/run-orbstack-phase3.sh"

  [[ "$(sanitize_component valid-name_7)" == valid-name_7 ]]
  if sanitize_component '../bad' >/dev/null; then
    return 1
  fi
  if sanitize_component 'bad/name' >/dev/null; then
    return 1
  fi
  [[ "${MAGIC_DEFAULT}" == 0x50334852 ]]
  validate_magic "${MAGIC_DEFAULT}"
  validate_magic 4294967295
  if validate_magic 4294967296 >/dev/null 2>&1 \
    || validate_magic 0x100000000 >/dev/null 2>&1 \
    || validate_magic random >/dev/null 2>&1; then
    return 1
  fi

  local cut expectation phase states step
  for cut in planned after-apply-{1..6} dns-staged \
    firewall-after-ipv4-ack firewall-after-ipv6-ack \
    firewall-after-endpoint-ack active; do
    [[ -n "$(seed_checkpoint_label "${cut}")" ]]
    expectation="$(seed_wal_expectation "${cut}")"
    [[ "${expectation}" == *'|'* ]]
  done
  [[ "$(recovery_wal_expectation before-step-1)" \
    == 'cleaning|applied,applied,applied,applied,applied,applied,applied,applied' ]]
  [[ "$(recovery_wal_expectation after-step-4)" \
    == 'cleaning|applied,removed,removed,applied,removed,applied,applied,applied' ]]
  [[ "$(recovery_wal_expectation after-step-8)" \
    == 'cleaning|removed,removed,removed,removed,removed,removed,applied,removed' ]]
  for step in {1..8}; do
    [[ "$(recovery_wal_expectation "before-step-${step}")" \
      == "$(recovery_wal_expectation "after-step-${step}")" ]]
    [[ -n "$(recovery_marker_regex "${step}")" ]]
  done

  printf 'checkpoint=wal-planned-before-host-ownership\npid=4242\n' \
    >"${temporary}/marker"
  printf 'PHASE3_CHECKPOINT wal-planned-before-host-ownership\n' \
    >"${temporary}/marker.log"
  validate_checkpoint_marker \
    "${temporary}/marker" "${temporary}/marker.log" seed planned 4242 \
    "${self_uid}" "${self_gid}"
  if validate_checkpoint_marker \
    "${temporary}/marker" "${temporary}/marker.log" seed active 4242 \
    "${self_uid}" "${self_gid}"; then
    return 1
  fi
  printf 'checkpoint=cleaning-before-converge-step-5-Tun(TunResource { interface: InterfaceIdentity { name: "sp3tun0", ifindex: 3 } })\npid=4242\n' \
    >"${temporary}/marker"
  printf 'PHASE3_CHECKPOINT cleaning-before-converge-step-5-Tun(TunResource { interface: InterfaceIdentity { name: "sp3tun0", ifindex: 3 } })\n' \
    >"${temporary}/marker.log"
  validate_checkpoint_marker \
    "${temporary}/marker" "${temporary}/marker.log" recovery before-step-5 4242 \
    "${self_uid}" "${self_gid}"
  {
    printf 'PHASE3_CHECKPOINT cleaning-before-converge-step-5-Tun(TunResource { interface: InterfaceIdentity { name: "sp3tun0", ifindex: 3 } })\n'
    printf 'PHASE3_CHECKPOINT cleaning-before-converge-step-5-Tun(TunResource { interface: InterfaceIdentity { name: "sp3tun0", ifindex: 3 } })\n'
  } >"${temporary}/marker-duplicate.log"
  if validate_checkpoint_marker \
    "${temporary}/marker" "${temporary}/marker-duplicate.log" \
    recovery before-step-5 4242 "${self_uid}" "${self_gid}"; then
    return 1
  fi
  printf 'pid=4242\n' >>"${temporary}/marker"
  if validate_checkpoint_marker \
    "${temporary}/marker" "${temporary}/marker.log" recovery before-step-5 4242 \
    "${self_uid}" "${self_gid}"; then
    return 1
  fi
  # The single-quoted program is intentionally evaluated by the child shell.
  # shellcheck disable=SC2016
  run_expect_sigkill "${temporary}/sigkill.marker" "${temporary}/sigkill.log" \
    seed planned "${self_uid}" "${self_gid}" /bin/bash -c '
      printf "checkpoint=wal-planned-before-host-ownership\npid=%s\n" "$$" >"$1"
      printf "PHASE3_CHECKPOINT wal-planned-before-host-ownership\n" >&2
      kill -KILL "$$"
    ' _ "${temporary}/sigkill.marker"

  expectation="$(seed_wal_expectation active)"
  phase="${expectation%%|*}"
  states="${expectation#*|}"
  write_selftest_wal "${temporary}/wal.json" "${phase}" "${states}"
  validate_wal_json "${temporary}/wal.json" "${phase}" "${states}"
  printf 'checkpoint=cleaning-before-converge-step-5-Tun(TunResource { interface: InterfaceIdentity { name: "sp3tun0", ifindex: 3 } })\npid=4242\n' \
    >"${temporary}/marker"
  validate_recovery_marker_wal_binding \
    "${temporary}/marker" "${temporary}/wal.json" before-step-5
  sed 's/ifindex: 3/ifindex: 4/' "${temporary}/marker" \
    >"${temporary}/marker-wrong-resource"
  if validate_recovery_marker_wal_binding \
    "${temporary}/marker-wrong-resource" "${temporary}/wal.json" before-step-5 \
    2>/dev/null; then
    return 1
  fi
  jq '.schema_version = 2' "${temporary}/wal.json" >"${temporary}/wal-bad.json"
  if validate_wal_json "${temporary}/wal-bad.json" "${phase}" "${states}"; then
    return 1
  fi
  jq '.operations[1].resource.resource.metric = "77"' \
    "${temporary}/wal.json" >"${temporary}/wal-bad.json"
  if validate_wal_json "${temporary}/wal-bad.json" "${phase}" "${states}"; then
    return 1
  fi
  jq '.owner.mount_namespace.device = false' \
    "${temporary}/wal.json" >"${temporary}/wal-bad.json"
  if validate_wal_json "${temporary}/wal-bad.json" "${phase}" "${states}"; then
    return 1
  fi
  jq 'del(.operations[7])' "${temporary}/wal.json" >"${temporary}/wal-bad.json"
  if validate_wal_json "${temporary}/wal-bad.json" "${phase}" "${states}"; then
    return 1
  fi
  jq '.operations[6].id = 6' "${temporary}/wal.json" >"${temporary}/wal-bad.json"
  if validate_wal_json "${temporary}/wal-bad.json" "${phase}" "${states}"; then
    return 1
  fi
  jq '.operations[3].resource.resource.destination.address = "203.0.113.9"' \
    "${temporary}/wal.json" >"${temporary}/wal-bad.json"
  if validate_wal_json "${temporary}/wal-bad.json" "${phase}" "${states}"; then
    return 1
  fi
  jq '.operations[0].resource.resource.extra = true' \
    "${temporary}/wal.json" >"${temporary}/wal-bad.json"
  if validate_wal_json "${temporary}/wal-bad.json" "${phase}" "${states}"; then
    return 1
  fi
  expectation="$(recovery_wal_expectation after-step-4)"
  phase="${expectation%%|*}"
  states="${expectation#*|}"
  write_selftest_wal "${temporary}/wal-cleaning.json" "${phase}" "${states}"
  validate_wal_json "${temporary}/wal-cleaning.json" "${phase}" "${states}"
  if validate_wal_json "${temporary}/wal-cleaning.json" cleaning \
    'applied,applied,applied,applied,applied,applied,applied,applied'; then
    return 1
  fi
  if validate_wal_json "${temporary}/missing-wal.json" cleaning "${states}"; then
    return 1
  fi

  printf '1\tabsent\n2\tcreating\n3\trunning\n4\trunning\n5\trunning\n6\trunning\n' \
    >"${temporary}/quiescence.tsv"
  validate_quiescence_trace "${temporary}/quiescence.tsv" 4 stable_any
  printf '1\tabsent\n2\tabsent\n3\tabsent\n4\tabsent\n' \
    >"${temporary}/quiescence.tsv"
  validate_quiescence_trace "${temporary}/quiescence.tsv" 4 absent_all
  printf '1\tabsent\n2\tabsent\n3\trunning\n4\tabsent\n5\tabsent\n6\tabsent\n7\tabsent\n' \
    >"${temporary}/quiescence.tsv"
  if validate_quiescence_trace "${temporary}/quiescence.tsv" 4 absent_all; then
    return 1
  fi
  printf '1\tabsent\n1\tabsent\n2\tabsent\n3\tabsent\n4\tabsent\n' \
    >"${temporary}/quiescence.tsv"
  if validate_quiescence_trace "${temporary}/quiescence.tsv" 4 absent_all; then
    return 1
  fi

  printf '/opt/shadowpipe/sing-box run -c /private/etc/shadowpipe/config.json -D /var/lib/shadowpipe\n' \
    >"${temporary}/command"
  parse_singbox_command "${temporary}/command" "${temporary}/config-path"
  [[ "$(<"${temporary}/config-path")" == /private/etc/shadowpipe/config.json ]]
  printf 'sing-box run -c relative.json\n' >"${temporary}/command"
  if parse_singbox_command "${temporary}/command" "${temporary}/config-path"; then
    return 1
  fi

  printf '/opt/homebrew/bin/sing-box run -c %s -D %s\n' \
    "${EXPECTED_SINGBOX_CONFIG}" "${EXPECTED_SINGBOX_DIRECTORY}" \
    >"${temporary}/managed-command"
  validate_managed_singbox_command "${temporary}/managed-command"
  printf '/opt/homebrew/bin/sing-box run -c %s -D /tmp/foreign\n' \
    "${EXPECTED_SINGBOX_CONFIG}" >"${temporary}/managed-command"
  if validate_managed_singbox_command "${temporary}/managed-command"; then
    return 1
  fi
  self_test_singbox_observer "${temporary}/singbox-observer"
  printf 'sing-box run -c /one --config=/two\n' >"${temporary}/command"
  if parse_singbox_command "${temporary}/command" "${temporary}/config-path"; then
    return 1
  fi
  printf 'sing-box run -c "/path/that/was/quoted"\n' >"${temporary}/command"
  if parse_singbox_command "${temporary}/command" "${temporary}/config-path"; then
    return 1
  fi

  printf '%s\n' \
    '{"record":{"id":"opaque-A","name":"sphr-fixture","state":"stopped","future":true},"future_root":1}' \
    >"${temporary}/orb-info.json"
  [[ "$(parse_orb_info_identity "${temporary}/orb-info.json" \
    sphr-fixture opaque-A stopped "${temporary}/orb-identity.json")" \
    == opaque-A ]]
  grep -qx \
    '{"id":"opaque-A","name":"sphr-fixture","schema_version":1,"state":"stopped"}' \
    "${temporary}/orb-identity.json"
  printf '%s\n' \
    '{"record":{"id":"opaque-A","id":"opaque-B","name":"sphr-fixture","state":"stopped"}}' \
    >"${temporary}/orb-info-duplicate.json"
  if parse_orb_info_identity "${temporary}/orb-info-duplicate.json" \
    sphr-fixture '' stopped "${temporary}/orb-identity-duplicate.json" \
    >/dev/null 2>&1; then
    return 1
  fi
  if parse_orb_info_identity "${temporary}/orb-info.json" \
    sphr-fixture opaque-B stopped "${temporary}/orb-identity-reuse.json" \
    >/dev/null 2>&1; then
    return 1
  fi

  cat >"${temporary}/orb.list" <<'EOF'
NAME STATE
arch stopped
sphr-example running
EOF
  validate_orb_listing "${temporary}/orb.list"
  [[ "$(orb_exact_state_from_file "${temporary}/orb.list" arch)" == stopped ]]
  [[ "$(orb_exact_state_from_file "${temporary}/orb.list" absent-vm)" == absent ]]
  printf 'sphr-example stopped\n' >>"${temporary}/orb.list"
  if orb_exact_state_from_file "${temporary}/orb.list" sphr-example >/dev/null; then
    return 1
  fi
  if validate_orb_listing "${temporary}/orb.list"; then
    return 1
  fi
  printf 'NAME STATE\narch running\n' >"${temporary}/orb-invalid.list"
  if validate_orb_listing "${temporary}/orb-invalid.list"; then
    return 1
  fi

  : >"${temporary}/pf"
  printf 'pfctl: /dev/pf: Permission denied\n' >"${temporary}/pf.stderr"
  printf '1\n' >"${temporary}/pf.status"
  [[ "$(classify_pf_capture "${temporary}/pf")" == permission_denied ]]
  printf 'unexpected pf failure\n' >"${temporary}/pf.stderr"
  if classify_pf_capture "${temporary}/pf" >/dev/null; then
    return 1
  fi
  : >"${temporary}/pf.stderr"
  printf '0\n' >"${temporary}/pf.status"
  [[ "$(classify_pf_capture "${temporary}/pf")" == observed ]]
  [[ "$(classify_pf_tuple observed observed observed)" == true ]]
  [[ "$(classify_pf_tuple permission_denied permission_denied permission_denied)" \
    == false ]]
  if classify_pf_tuple observed permission_denied observed >/dev/null; then
    return 1
  fi

  cat >"${temporary}/routes.raw" <<'EOF'
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.0.2.1          UGSc                  en0 123
192.0.2.10         link#4             UHLWIir               en0 456
203.0.113/24       192.0.2.1          UGSc                  en0 789
EOF
  cat >"${temporary}/routes.expected" <<'EOF'
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.0.2.1          UGSc                  en0
203.0.113/24       192.0.2.1          UGSc                  en0
EOF
  capture_normalized_routes \
    "${temporary}/routes.normalized" "${temporary}/routes.raw"
  capture_succeeded "${temporary}/routes.normalized.status"
  [[ ! -s "${temporary}/routes.normalized.stderr" ]]
  bounded_cmp "${temporary}/routes.expected" "${temporary}/routes.normalized"

  mkdir -p "${temporary}/a" "${temporary}/b"
  local name
  for name in links.json routes-ipv4.json iptables.txt ip6tables.txt nft.txt \
    resolver.identity resolver.sha256; do
    printf 'stable:%s\n' "${name}" >"${temporary}/a/${name}"
    cp "${temporary}/a/${name}" "${temporary}/b/${name}"
  done
  compare_snapshot_dirs "${temporary}/a" "${temporary}/b"
  printf 'changed\n' >>"${temporary}/b/iptables.txt"
  if compare_snapshot_dirs "${temporary}/a" "${temporary}/b" 2>/dev/null; then
    return 1
  fi

  mkdir "${temporary}/a/nested"
  mkdir "${temporary}/a/empty-before-seal"
  printf 'nested manifest payload\n' >"${temporary}/a/nested/checksums.sha256"
  printf 'space-safe payload\n' >"${temporary}/a/nested/file with space.txt"

  seal_bundle "${temporary}/a"
  verify_sealed_bundle "${temporary}/a"
  bounded_bundle_operation validate "${temporary}/a"
  bounded_bundle_operation verify "${temporary}/a"
  grep -Fq 'nested/checksums.sha256' "${temporary}/a/checksums.sha256"
  grep -Fxq $'F\tnested/file with space.txt' "${temporary}/a/evidence-census.txt"
  grep -Fxq $'D\tempty-before-seal' "${temporary}/a/evidence-census.txt"
  if grep -Fq -- "${temporary}" "${temporary}/a/checksums.sha256"; then
    return 1
  fi
  printf 'unsealed addition\n' >"${temporary}/a/late-file"
  if verify_sealed_bundle "${temporary}/a"; then
    return 1
  fi
  rm -- "${temporary}/a/late-file"
  mkdir "${temporary}/a/late-empty-directory"
  if verify_sealed_bundle "${temporary}/a"; then
    return 1
  fi
  rmdir "${temporary}/a/late-empty-directory"
  rmdir "${temporary}/a/empty-before-seal"
  if verify_sealed_bundle "${temporary}/a"; then
    return 1
  fi
  mkdir "${temporary}/a/empty-before-seal"
  seal_bundle "${temporary}/a"

  mkdir "${temporary}/unsafe-symlink"
  ln -s /nonexistent "${temporary}/unsafe-symlink/dangling"
  if validate_bundle_tree "${temporary}/unsafe-symlink" 2>/dev/null; then
    return 1
  fi
  mkdir "${temporary}/unsafe-hardlink"
  printf 'same inode\n' >"${temporary}/unsafe-hardlink/one"
  ln "${temporary}/unsafe-hardlink/one" "${temporary}/unsafe-hardlink/two"
  if validate_bundle_tree "${temporary}/unsafe-hardlink" 2>/dev/null; then
    return 1
  fi
  mkdir "${temporary}/unsafe-special"
  mkfifo "${temporary}/unsafe-special/fifo"
  if validate_bundle_tree "${temporary}/unsafe-special" 2>/dev/null; then
    return 1
  fi
  mkdir "${temporary}/unsafe-unreadable"
  printf 'unreadable\n' >"${temporary}/unsafe-unreadable/file"
  chmod 0000 "${temporary}/unsafe-unreadable/file"
  if validate_bundle_tree "${temporary}/unsafe-unreadable" 2>/dev/null; then
    return 1
  fi
  chmod 0600 "${temporary}/unsafe-unreadable/file"

  printf 'owner\n' >"${temporary}/owner.env"
  chmod 0600 "${temporary}/owner.env"
  validate_host_owner_file "${temporary}/owner.env" "$(id -u)"
  ln "${temporary}/owner.env" "${temporary}/owner-hardlink"
  if validate_host_owner_file "${temporary}/owner.env" "$(id -u)"; then
    return 1
  fi

  local run_id=selftest-run status_file="${temporary}/status.env"
  {
    printf 'schema_version=%s\n' "${STATUS_SCHEMA_VERSION}"
    printf 'run_id=%s\n' "${run_id}"
    printf 'guest_status=valid\n'
    printf 'host_safety_status=pending\n'
    printf 'cleanup_status=pending\n'
    printf 'clone_absence_status=pending\n'
    printf 'evidence_status=pending\n'
    printf 'overall_status=pending\n'
    printf 'pf_runtime_observed=pending\n'
    printf 'field_evidence=false\n'
    printf 'scope=disposable_orbstack_private_namespaces\n'
  } >"${status_file}"
  validate_guest_status_file "${status_file}" "${run_id}"
  printf 'guest_status=valid\n' >>"${status_file}"
  if validate_guest_status_file "${status_file}" "${run_id}"; then
    return 1
  fi

  write_final_status_file "${status_file}" "${run_id}" \
    valid valid valid valid valid false
  validate_final_status_file "${status_file}" "${run_id}"
  grep -qx 'overall_status=valid' "${status_file}"
  local failed_dimension
  for failed_dimension in guest host cleanup clone evidence; do
    local guest=valid host=valid cleanup=valid clone=valid evidence=valid
    case "${failed_dimension}" in
      guest) guest=failed ;;
      host) host=failed ;;
      cleanup) cleanup=failed ;;
      clone) clone=failed ;;
      evidence) evidence=failed ;;
    esac
    write_final_status_file "${status_file}" "${run_id}" \
      "${guest}" "${host}" "${cleanup}" "${clone}" "${evidence}" false
    validate_final_status_file "${status_file}" "${run_id}"
    grep -qx 'overall_status=failed' "${status_file}"
  done
  # A cleanup failure must overwrite a previously valid overall result.
  write_final_status_file "${status_file}" "${run_id}" \
    valid valid valid valid valid false
  write_final_status_file "${status_file}" "${run_id}" \
    valid valid failed valid valid false
  grep -qx 'overall_status=failed' "${status_file}"
  sed 's/overall_status=failed/overall_status=valid/' "${status_file}" \
    >"${temporary}/status-inconsistent.env"
  if validate_final_status_file "${temporary}/status-inconsistent.env" "${run_id}"; then
    return 1
  fi

  set +e
  # The single-quoted program is intentionally evaluated by the child shell.
  # shellcheck disable=SC2016
  run_bounded 1 /bin/bash -c \
    'trap "exit 0" TERM; (trap "" TERM HUP; sleep 30) & printf "%s\n" "$!" >"$1"; wait' \
    _ "${temporary}/bounded-child.pid" \
    >"${temporary}/bounded.stdout" 2>"${temporary}/bounded.stderr"
  status=$?
  set -e
  [[ "${status}" == 124 ]]
  grep -q 'bounded command timed out' "${temporary}/bounded.stderr"
  local child_pid child_gone=0
  IFS= read -r child_pid <"${temporary}/bounded-child.pid"
  [[ "${child_pid}" =~ ^[1-9][0-9]*$ ]]
  for _ in {1..20}; do
    if ! kill -0 "${child_pid}" 2>/dev/null; then
      child_gone=1
      break
    fi
    run_bounded 1 sleep 0.05 >/dev/null 2>&1 || true
  done
  [[ "${child_gone}" == 1 ]]

  say 'phase3 runner self-test: PASS'
  rm -rf -- "${temporary}"
  SELFTEST_TEMPORARY=''
  trap - EXIT
}

case "${1:-}" in
  --internal-validate-bundle)
    shift
    [[ "${SHADOWPIPE_PHASE3_INTERNAL_BUNDLE:-}" == 1 && "$#" -eq 1 ]] \
      || die "${EX_USAGE}" 'invalid internal validate invocation'
    validate_bundle_tree "$1"
    ;;
  --internal-seal-bundle)
    shift
    [[ "${SHADOWPIPE_PHASE3_INTERNAL_BUNDLE:-}" == 1 && "$#" -eq 1 ]] \
      || die "${EX_USAGE}" 'invalid internal seal invocation'
    seal_bundle "$1"
    ;;
  --internal-verify-bundle)
    shift
    [[ "${SHADOWPIPE_PHASE3_INTERNAL_BUNDLE:-}" == 1 && "$#" -eq 1 ]] \
      || die "${EX_USAGE}" 'invalid internal verify invocation'
    verify_sealed_bundle "$1"
    ;;
  --self-test)
    shift
    [[ "$#" -eq 0 ]] || die "${EX_USAGE}" '--self-test takes no arguments'
    self_test
    ;;
  --guest)
    shift
    guest_main "$@"
    ;;
  --scenario)
    shift
    scenario_main "$@"
    ;;
  -h|--help)
    usage
    ;;
  *)
    host_main "$@"
    ;;
esac
