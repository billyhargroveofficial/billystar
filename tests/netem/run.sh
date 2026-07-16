#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# This script is intentionally Linux-VM-only. It must never mutate the macOS
# host carrying Billy's live sing-box TUN.
if [[ "${ZATMENIE_LAB:-}" != "1" ]]; then
  echo "refusing: set ZATMENIE_LAB=1 inside a disposable Linux VM" >&2
  exit 64
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "refusing: Linux network namespaces are required" >&2
  exit 64
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "refusing: run with sudo inside the lab VM" >&2
  exit 77
fi

for tool in ip tc nft iperf3 jq timeout flock sha256sum awk sysctl realpath \
  cp setsid readlink stat mkfifo mv python3; do
  command -v "${tool}" >/dev/null || {
    echo "missing lab dependency: ${tool}" >&2
    exit 69
  }
done
if ! python3 - <<'PY'
import os
import signal

if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
    raise SystemExit(1)
PY
then
  echo "missing lab dependency: Python pidfd support is required" >&2
  exit 69
fi

exec 9>/run/lock/zatmenie-netem.lock
if ! flock -n 9; then
  echo "refusing: another zatmenie netns lab is active" >&2
  exit 75
fi

if ! netns_listing="$(ip netns list)"; then
  echo "refusing: could not inspect existing network namespaces" >&2
  exit 74
fi
if awk '$1 ~ /^zt-(client|censor|server)-/ { found=1 } END { exit !found }' <<<"${netns_listing}"; then
  echo "refusing: stale zatmenie namespaces exist; inspect and remove them explicitly" >&2
  exit 75
fi

profile="${1:-baseline}"
# Validate the only user-controlled path component before constructing a run
# directory.  Quoting alone does not make embedded slashes or `..` safe.
case "${profile}" in
  baseline|wan|lossy|severe|udp-blackout|synthetic-byte-threshold) ;;
  *)
    echo "unknown profile: ${profile}" >&2
    exit 64
    ;;
esac
script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
allowed_result_root="$(realpath -m -- "${script_dir}/results")"
result_root="$(realpath -m -- "${2:-${allowed_result_root}}")"
case "${result_root}" in
  "${allowed_result_root}"|"${allowed_result_root}"/*) ;;
  *)
    echo "refusing: result root must stay under ${allowed_result_root}" >&2
    exit 64
    ;;
esac
mkdir -p -- "${result_root}"
if [[ "$(realpath -m -- "${result_root}")" != "${result_root}" ]]; then
  echo "refusing: result root resolves through an unexpected symlink" >&2
  exit 64
fi
run_id="$(date -u +%Y%m%dT%H%M%SZ)-${profile}-$$"
result_dir="${result_root%/}/${run_id}"
mkdir -- "${result_dir}"
cp -- "$0" "${result_dir}/runner.sh"

watchdog_seconds="${ZATMENIE_WATCHDOG_SECONDS:-90}"
if [[ ! "${watchdog_seconds}" =~ ^[0-9]+$ ]] \
  || (( watchdog_seconds < 30 || watchdog_seconds > 300 )); then
  echo "invalid watchdog: expected an integer in [30, 300] seconds" >&2
  exit 64
fi

netem_seed_forward="${ZATMENIE_NETEM_SEED:-2026071501}"
if [[ ! "${netem_seed_forward}" =~ ^[0-9]+$ ]] \
  || (( netem_seed_forward < 1 || netem_seed_forward > 4294967294 )); then
  echo "invalid netem seed: expected an integer in [1, 4294967294]" >&2
  exit 64
fi
netem_seed_reverse=$((netem_seed_forward + 1))

ns_client="zt-client-$$"
ns_censor="zt-censor-$$"
ns_server="zt-server-$$"
server_pid=""
watchdog_pid=""
watchdog_barrier_required=0
runner_pid="$$"
link_tag="$(printf '%x' "$$")"
link_client="zc${link_tag}a"
link_client_peer="zc${link_tag}b"
link_server_peer="zs${link_tag}a"
link_server="zs${link_tag}b"
owned_process_dir="${result_dir}/owned-processes"
netns_identity_dir="${result_dir}/netns-identities"
link_identity_dir="${result_dir}/link-identities"
watchdog_fifo="${result_dir}/watchdog-control.fifo"
watchdog_ack_fifo="${result_dir}/watchdog-ack.fifo"
link_owner_token="zatmenie:${run_id}"
mkdir -- "${owned_process_dir}" "${netns_identity_dir}" "${link_identity_dir}"
mkfifo -- "${watchdog_fifo}"
mkfifo -- "${watchdog_ack_fifo}"

read_proc_identity() {
  local pid="$1"
  local stat_line rest
  local -a fields

  [[ "${pid}" =~ ^[0-9]+$ ]] || return 2
  [[ -r "/proc/${pid}/stat" ]] || return 1
  IFS= read -r stat_line <"/proc/${pid}/stat" || return 2
  rest="${stat_line##*) }"
  read -r -a fields <<<"${rest}"
  ((${#fields[@]} >= 20)) || return 2
  # /proc/PID/stat fields after comm begin at field 3. These are pgrp (5),
  # session (6), and starttime (22). Starttime makes PID reuse detectable.
  printf '%s %s %s\n' "${fields[2]}" "${fields[3]}" "${fields[19]}"
}

if ! read -r runner_pgrp runner_sid runner_starttime \
  < <(read_proc_identity "${runner_pid}"); then
  echo "refusing: could not record runner process identity" >&2
  exit 74
fi
if [[ ! "${runner_pgrp}" =~ ^[0-9]+$ || ! "${runner_sid}" =~ ^[0-9]+$ \
  || ! "${runner_starttime}" =~ ^[0-9]+$ ]]; then
  echo "refusing: malformed runner process identity" >&2
  exit 74
fi

netns_exists() {
  local namespace="$1" listing
  listing="$(ip netns list)" || return 2
  awk -v namespace="${namespace}" '$1 == namespace { found=1 } END { exit !found }' \
    <<<"${listing}"
}

capture_netns_identity() {
  local namespace="$1" target inode record tmp existing_name existing_inode extra state
  record="${netns_identity_dir}/${namespace}.identity"

  if [[ -f "${record}" ]]; then
    read -r existing_name existing_inode extra <"${record}" || return 1
    [[ -z "${extra:-}" && "${existing_name}" == "${namespace}" \
      && "${existing_inode}" =~ ^[0-9]+$ ]] || return 1
  fi

  if netns_exists "${namespace}"; then
    state=0
  else
    state=$?
  fi
  [[ "${state}" -eq 1 ]] && return 0
  [[ "${state}" -eq 0 ]] || return 1
  target="$(ip netns exec "${namespace}" readlink /proc/self/ns/net)" || return 1
  if [[ ! "${target}" =~ ^net:\[([0-9]+)\]$ ]]; then
    return 1
  fi
  inode="${BASH_REMATCH[1]}"
  if [[ -f "${record}" && "${existing_inode}" != "${inode}" ]]; then
    return 1
  fi
  tmp="${record}.tmp.${BASHPID}"
  printf '%s %s\n' "${namespace}" "${inode}" >"${tmp}" || return 1
  chmod 600 "${tmp}" || return 1
  mv -f -- "${tmp}" "${record}" || return 1
}

read_root_link_state() {
  local link="$1" ifindex ifalias
  [[ "${link}" =~ ^[a-zA-Z0-9_.-]+$ ]] || return 2
  [[ -r "/sys/class/net/${link}/ifindex" \
    && -r "/sys/class/net/${link}/ifalias" ]] || return 1
  ifindex="$(<"/sys/class/net/${link}/ifindex")" || return 2
  ifalias="$(<"/sys/class/net/${link}/ifalias")" || return 2
  [[ "${ifindex}" =~ ^[0-9]+$ && -n "${ifalias}" ]] || return 2
  printf '%s %s\n' "${ifindex}" "${ifalias}"
}

capture_root_link_identity() {
  local link="$1" expected_alias state ifindex ifalias record tmp
  expected_alias="${link_owner_token}:${link}"
  record="${link_identity_dir}/${link}.identity"
  state="$(read_root_link_state "${link}")" || return 1
  read -r ifindex ifalias <<<"${state}"
  [[ "${ifalias}" == "${expected_alias}" ]] || return 1
  tmp="${record}.tmp.${BASHPID}"
  printf '%s %s %s\n' "${link}" "${ifindex}" "${ifalias}" >"${tmp}" || return 1
  chmod 600 "${tmp}" || return 1
  mv -f -- "${tmp}" "${record}" || return 1
}

read_link_record() {
  local record="$1" link ifindex ifalias extra
  [[ -f "${record}" ]] || return 1
  read -r link ifindex ifalias extra <"${record}" || return 2
  [[ -z "${extra:-}" && "${link}" =~ ^[a-zA-Z0-9_.-]+$ \
    && "${ifindex}" =~ ^[0-9]+$ && -n "${ifalias}" ]] || return 2
  printf '%s %s %s\n' "${link}" "${ifindex}" "${ifalias}"
}

read_owner_record() {
  local record="$1"
  local label pid pgid sid starttime extra
  [[ -f "${record}" ]] || return 1
  read -r label pid pgid sid starttime extra <"${record}" || return 2
  [[ -z "${extra:-}" && "${label}" =~ ^[a-z0-9-]+$ \
    && "${pid}" =~ ^[0-9]+$ && "${pgid}" =~ ^[0-9]+$ \
    && "${sid}" =~ ^[0-9]+$ && "${starttime}" =~ ^[0-9]+$ \
    && "${pid}" -gt 1 && "${pid}" == "${pgid}" \
    && "${pid}" == "${sid}" ]] || return 2
  printf '%s %s %s %s %s\n' \
    "${label}" "${pid}" "${pgid}" "${sid}" "${starttime}"
}

list_group_members() {
  local expected_pgid="$1" expected_sid="$2"
  local proc_dir pid identity pgid sid starttime
  local scan_failed=0

  for proc_dir in /proc/[0-9]*; do
    [[ -d "${proc_dir}" ]] || continue
    pid="${proc_dir##*/}"
    if identity="$(read_proc_identity "${pid}")"; then
      read -r pgid sid starttime <<<"${identity}"
      if [[ "${pgid}" == "${expected_pgid}" && "${sid}" == "${expected_sid}" ]]; then
        printf '%s\n' "${pid}"
      fi
    elif [[ -d "${proc_dir}" && -r "${proc_dir}/stat" ]]; then
      # Retry once to distinguish a normal /proc exit race from an unreadable
      # live process. An unreadable live entry invalidates the ownership proof.
      if identity="$(read_proc_identity "${pid}")"; then
        read -r pgid sid starttime <<<"${identity}"
        if [[ "${pgid}" == "${expected_pgid}" && "${sid}" == "${expected_sid}" ]]; then
          printf '%s\n' "${pid}"
        fi
      elif [[ -d "${proc_dir}" ]]; then
        scan_failed=1
      fi
    fi
  done
  return "${scan_failed}"
}

pidfd_signal_registered_owner() {
  local record="$1" signal_name="$2"
  local owner label pid pgid sid starttime

  owner="$(read_owner_record "${record}")" || return 1
  read -r label pid pgid sid starttime <<<"${owner}"
  python3 - "${pid}" "${pgid}" "${sid}" "${starttime}" "${signal_name}" <<'PY'
import os
import signal
import sys

pid, expected_pgid, expected_sid, expected_start = map(int, sys.argv[1:5])
signal_name = sys.argv[5]
signals = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL}
if signal_name not in signals:
    raise SystemExit(20)

try:
    pidfd = os.pidfd_open(pid, 0)
except ProcessLookupError:
    raise SystemExit(0)
except OSError:
    raise SystemExit(21)

try:
    try:
        stat_line = open(f"/proc/{pid}/stat", "r", encoding="ascii").read()
    except FileNotFoundError:
        raise SystemExit(0)
    split_at = stat_line.rfind(") ")
    if split_at < 0:
        raise SystemExit(22)
    fields = stat_line[split_at + 2 :].split()
    if len(fields) < 20:
        raise SystemExit(22)
    current_pgid = int(fields[2])
    current_sid = int(fields[3])
    current_start = int(fields[19])
    # pidfd_open happened before this validation.  An ordinary numeric-PID
    # reuse changes the recorded start time and is rejected; after validation,
    # pidfd_send_signal stays bound to that exact kernel process object.  This
    # is a fail-stop lab identity check, not protection from a concurrent
    # privileged actor deliberately recreating all recorded attributes.
    if current_start != expected_start:
        raise SystemExit(0)
    if current_pgid != expected_pgid or current_sid != expected_sid:
        raise SystemExit(23)
    try:
        signal.pidfd_send_signal(pidfd, signals[signal_name], None, 0)
    except ProcessLookupError:
        pass
    except OSError:
        raise SystemExit(24)
finally:
    os.close(pidfd)
PY
}

registered_owner_is_live() {
  local record="$1" owner label pid pgid sid starttime identity
  local current_pgid current_sid current_start
  owner="$(read_owner_record "${record}")" || return 2
  read -r label pid pgid sid starttime <<<"${owner}"
  [[ -d "/proc/${pid}" ]] || return 1
  identity="$(read_proc_identity "${pid}")" || {
    [[ -d "/proc/${pid}" ]] && return 2
    return 1
  }
  read -r current_pgid current_sid current_start <<<"${identity}"
  [[ "${current_start}" == "${starttime}" ]] || return 1
  [[ "${current_pgid}" == "${pgid}" && "${current_sid}" == "${sid}" ]] || return 2
}

terminate_registered_owners() {
  local record owner label pid pgid sid starttime members owner_state
  local status=0
  local -a records

  # A temporary owner record or a launch intent means publication did not reach
  # the parent acknowledgement barrier.  Do not infer ownership or unmount a
  # namespace in that state.
  for record in "${owned_process_dir}"/*.tmp.*; do
    [[ -e "${record}" ]] || continue
    printf 'fault=incomplete_owner_record path=%s\n' "${record}" >>"${cleanup_detail_file}"
    status=1
  done
  for record in "${owned_process_dir}"/*.intent; do
    [[ -e "${record}" ]] || continue
    printf 'fault=unresolved_launch_intent path=%s\n' "${record}" >>"${cleanup_detail_file}"
    status=1
  done

  records=("${owned_process_dir}"/*.owner)
  for record in "${records[@]}"; do
    [[ -e "${record}" ]] || continue
    if ! owner="$(read_owner_record "${record}")"; then
      printf 'fault=malformed_owner_record path=%s\n' "${record}" >>"${cleanup_detail_file}"
      status=1
      continue
    fi
    read -r label pid pgid sid starttime <<<"${owner}"
    if ! pidfd_signal_registered_owner "${record}" TERM; then
      printf 'fault=registered_owner_term label=%s pid=%s\n' "${label}" "${pid}" \
        >>"${cleanup_detail_file}"
      status=1
    fi
  done

  for _ in {1..20}; do
    registered_owners_remaining=""
    for record in "${records[@]}"; do
      [[ -e "${record}" ]] || continue
      owner="$(read_owner_record "${record}")" || {
        status=1
        continue
      }
      read -r label pid pgid sid starttime <<<"${owner}"
      if registered_owner_is_live "${record}"; then
        registered_owners_remaining+="${label}:${pid};"
      else
        owner_state=$?
        [[ "${owner_state}" -eq 1 ]] || status=1
      fi
    done
    [[ -z "${registered_owners_remaining}" ]] && break
    sleep 0.05
  done

  if [[ -n "${registered_owners_remaining}" ]]; then
    for record in "${records[@]}"; do
      [[ -e "${record}" ]] || continue
      pidfd_signal_registered_owner "${record}" KILL || status=1
    done
    for _ in {1..20}; do
      registered_owners_remaining=""
      for record in "${records[@]}"; do
        [[ -e "${record}" ]] || continue
        owner="$(read_owner_record "${record}")" || {
          status=1
          continue
        }
        read -r label pid pgid sid starttime <<<"${owner}"
        if registered_owner_is_live "${record}"; then
          registered_owners_remaining+="${label}:${pid};"
        else
          owner_state=$?
          [[ "${owner_state}" -eq 1 ]] || status=1
        fi
      done
      [[ -z "${registered_owners_remaining}" ]] && break
      sleep 0.05
    done
  fi
  if [[ -n "${registered_owners_remaining}" ]]; then
    printf 'fault=registered_owners_remaining owners=%s\n' \
      "${registered_owners_remaining}" >>"${cleanup_detail_file}"
    status=1
  fi

  # Descendants are never signalled by numeric PGID.  Their presence is only a
  # proof failure; named namespaces remain mounted for VM inspection/teardown.
  owned_groups_remaining=""
  for record in "${records[@]}"; do
    [[ -e "${record}" ]] || continue
    owner="$(read_owner_record "${record}")" || continue
    read -r label pid pgid sid starttime <<<"${owner}"
    members="$(list_group_members "${pgid}" "${sid}")" || {
      status=1
      continue
    }
    [[ -z "${members}" ]] || owned_groups_remaining+="${label}:${members//$'\n'/,};"
  done
  if [[ -n "${owned_groups_remaining}" ]]; then
    printf 'fault=owned_groups_remaining groups=%s\n' "${owned_groups_remaining}" \
      >>"${cleanup_detail_file}"
    status=1
  fi
  return "${status}"
}

prove_named_netns_processes_absent() {
  local namespace pids state
  local status=0
  local -a namespaces=("${ns_client}" "${ns_censor}" "${ns_server}")

  named_netns_pids_remaining=""
  for namespace in "${namespaces[@]}"; do
    netns_exists "${namespace}"
    state=$?
    [[ "${state}" -eq 1 ]] && continue
    if [[ "${state}" -ne 0 ]]; then
      printf 'fault=netns_listing namespace=%s\n' "${namespace}" >>"${cleanup_detail_file}"
      status=1
      continue
    fi
    if ! pids="$(ip netns pids "${namespace}")"; then
      printf 'fault=netns_pid_listing namespace=%s\n' "${namespace}" \
        >>"${cleanup_detail_file}"
      status=1
      continue
    fi
    [[ -z "${pids}" ]] \
      || named_netns_pids_remaining+="${namespace}:${pids//$'\n'/,};"
  done
  if [[ -n "${named_netns_pids_remaining}" ]]; then
    printf 'fault=netns_pids_remaining pids=%s\n' "${named_netns_pids_remaining}" \
      >>"${cleanup_detail_file}"
    status=1
  fi
  return "${status}"
}

scan_netns_references() {
  local phase="$1"
  local record namespace inode extra proc_dir pid task_dir tid path target fd
  local task_seen
  local status=0
  local -A target_inodes=()

  namespace_process_refs=""
  namespace_fd_refs=""
  namespace_mount_refs=""
  for record in "${netns_identity_dir}"/*.identity; do
    [[ -e "${record}" ]] || continue
    if ! read -r namespace inode extra <"${record}" \
      || [[ -n "${extra:-}" || ! "${inode}" =~ ^[0-9]+$ ]]; then
      printf 'fault=malformed_netns_identity path=%s\n' "${record}" \
        >>"${cleanup_detail_file}"
      status=1
      continue
    fi
    target_inodes["${inode}"]="${namespace}"
  done

  for proc_dir in /proc/[0-9]*; do
    [[ -d "${proc_dir}" ]] || continue
    pid="${proc_dir##*/}"
    task_seen=0
    # Network namespaces and file tables are task-visible state. Inspect every
    # live TID, not just /proc/PID's leader view: a non-leader may have called
    # setns/unshare or retained its own namespace FD table.
    for task_dir in "${proc_dir}"/task/[0-9]*; do
      [[ -d "${task_dir}" ]] || continue
      task_seen=1
      tid="${task_dir##*/}"
      for path in "${task_dir}/ns/net" "${task_dir}/ns/net_for_children"; do
        [[ -L "${path}" ]] || continue
        if target="$(readlink "${path}" 2>/dev/null)"; then
          if [[ "${target}" =~ ^net:\[([0-9]+)\]$ \
            && -n "${target_inodes[${BASH_REMATCH[1]}]:-}" ]]; then
            namespace_process_refs+="${pid}/${tid}:${path}:${target};"
          fi
        elif [[ -d "${task_dir}" && -L "${path}" ]]; then
          printf 'fault=unreadable_task_netns pid=%s tid=%s path=%s\n' \
            "${pid}" "${tid}" "${path}" >>"${cleanup_detail_file}"
          status=1
        fi
      done
      for fd in "${task_dir}"/fd/*; do
        [[ -L "${fd}" ]] || continue
        if target="$(readlink "${fd}" 2>/dev/null)"; then
          if [[ "${target}" =~ ^net:\[([0-9]+)\]$ \
            && -n "${target_inodes[${BASH_REMATCH[1]}]:-}" ]]; then
            namespace_fd_refs+="${pid}/${tid}:${fd}:${target};"
          fi
        elif [[ -d "${task_dir}" && -L "${fd}" ]]; then
          printf 'fault=unreadable_task_namespace_fd pid=%s tid=%s path=%s\n' \
            "${pid}" "${tid}" "${fd}" >>"${cleanup_detail_file}"
          status=1
        fi
      done
    done
    if [[ "${task_seen}" -eq 0 && -d "${proc_dir}" ]]; then
      # Retry-vs-exit races are deliberately conservative: a still-visible
      # process for which no task could be inspected is not proof of absence.
      printf 'fault=unreadable_process_tasks pid=%s\n' "${pid}" \
        >>"${cleanup_detail_file}"
      status=1
    fi
  done
  if [[ -d /run/netns ]]; then
    for path in /run/netns/*; do
      [[ -e "${path}" ]] || continue
      if inode="$(stat -Lc '%i' "${path}" 2>/dev/null)"; then
        if [[ -n "${target_inodes[${inode}]:-}" ]]; then
          namespace="${target_inodes[${inode}]}"
          # During the predelete phase the one canonical name created by this
          # run is expected.  Any second alias is already a deletion barrier.
          if [[ "${phase}" != "predelete" \
            || "${path}" != "/run/netns/${namespace}" ]]; then
            namespace_mount_refs+="${path}:net:[${inode}];"
          fi
        fi
      elif [[ -e "${path}" ]]; then
        printf 'fault=unreadable_netns_mount path=%s\n' "${path}" \
          >>"${cleanup_detail_file}"
        status=1
      fi
    done
  fi
  if [[ -n "${namespace_process_refs}" || -n "${namespace_fd_refs}" \
    || -n "${namespace_mount_refs}" ]]; then
    printf 'fault=namespace_references_remaining process=%s fd=%s mount=%s\n' \
      "${namespace_process_refs:-<empty>}" "${namespace_fd_refs:-<empty>}" \
      "${namespace_mount_refs:-<empty>}" \
      >>"${cleanup_detail_file}"
    status=1
  fi
  return "${status}"
}

verify_named_netns_identity() {
  local namespace="$1" record record_name expected_inode extra target
  record="${netns_identity_dir}/${namespace}.identity"
  [[ -f "${record}" ]] || return 1
  read -r record_name expected_inode extra <"${record}" || return 1
  [[ -z "${extra:-}" && "${record_name}" == "${namespace}" \
    && "${expected_inode}" =~ ^[0-9]+$ ]] || return 1
  target="$(ip netns exec "${namespace}" readlink /proc/self/ns/net)" || return 1
  [[ "${target}" == "net:[${expected_inode}]" ]]
}

verify_owned_root_link() {
  local link="$1" record record_state record_name expected_ifindex expected_alias
  local current_state current_ifindex current_alias
  record="${link_identity_dir}/${link}.identity"
  record_state="$(read_link_record "${record}")" || return 1
  read -r record_name expected_ifindex expected_alias <<<"${record_state}"
  [[ "${record_name}" == "${link}" \
    && "${expected_alias}" == "${link_owner_token}:${link}" ]] || return 1
  current_state="$(read_root_link_state "${link}")" || return 1
  read -r current_ifindex current_alias <<<"${current_state}"
  [[ "${current_ifindex}" == "${expected_ifindex}" \
    && "${current_alias}" == "${expected_alias}" ]]
}

delete_lab_objects() {
  local namespace state link
  local status=0

  # Prove every currently visible root link and named namespace belongs to this
  # run before deleting any object.  A name alone is never ownership evidence.
  for link in "${link_client}" "${link_client_peer}" \
    "${link_server_peer}" "${link_server}"; do
    if [[ -e "/sys/class/net/${link}" ]] \
      && ! verify_owned_root_link "${link}"; then
      printf 'fault=root_link_identity link=%s\n' "${link}" >>"${cleanup_detail_file}"
      status=1
    fi
  done
  for namespace in "${ns_client}" "${ns_censor}" "${ns_server}"; do
    netns_exists "${namespace}"
    state=$?
    [[ "${state}" -eq 1 ]] && continue
    if [[ "${state}" -ne 0 ]] || ! verify_named_netns_identity "${namespace}"; then
      printf 'fault=netns_delete_identity namespace=%s\n' "${namespace}" \
        >>"${cleanup_detail_file}"
      status=1
    fi
  done
  [[ "${status}" -eq 0 ]] || return "${status}"

  for link in "${link_client}" "${link_client_peer}" \
    "${link_server_peer}" "${link_server}"; do
    if [[ -e "/sys/class/net/${link}" ]]; then
      if ! verify_owned_root_link "${link}"; then
        printf 'fault=root_link_delete_identity link=%s\n' "${link}" \
          >>"${cleanup_detail_file}"
        status=1
      elif ! ip link del "${link}"; then
        printf 'fault=root_link_delete link=%s\n' "${link}" >>"${cleanup_detail_file}"
        status=1
      fi
    fi
  done
  [[ "${status}" -eq 0 ]] || return "${status}"

  for namespace in "${ns_client}" "${ns_censor}" "${ns_server}"; do
    netns_exists "${namespace}"
    state=$?
    [[ "${state}" -eq 1 ]] && continue
    if [[ "${state}" -ne 0 ]] || ! verify_named_netns_identity "${namespace}" \
      || ! ip netns del "${namespace}"; then
      printf 'fault=netns_delete namespace=%s\n' "${namespace}" >>"${cleanup_detail_file}"
      status=1
    fi
  done
  return "${status}"
}

cleanup_lab_state() {
  local mode="$1" report="$2"
  local namespace state link listing current_qdisc current_route identity_record
  local status=0
  local cleanup_lock_fd
  local cleanup_lock="${result_dir}/cleanup.lock"
  local detail_tmp="${report}.details.${BASHPID}"
  local report_tmp="${report}.tmp.${BASHPID}"
  local remaining_names="" remaining_links=""

  if ! exec {cleanup_lock_fd}>"${cleanup_lock}"; then
    printf 'cleanup_status=failed\nfault=cleanup_lock_open\n' >"${report}" 2>/dev/null || true
    return 1
  fi
  if ! flock -w 10 "${cleanup_lock_fd}"; then
    printf 'cleanup_status=failed\nfault=cleanup_lock_timeout\n' >"${report}" 2>/dev/null || true
    exec {cleanup_lock_fd}>&-
    return 1
  fi
  cleanup_detail_file="${detail_tmp}"
  owned_groups_remaining=""
  registered_owners_remaining=""
  named_netns_pids_remaining=""
  namespace_process_refs=""
  namespace_fd_refs=""
  namespace_mount_refs=""
  : >"${cleanup_detail_file}" || return 1
  if [[ "${watchdog_barrier_required}" -ne 0 ]]; then
    printf 'fault=watchdog_cleanup_barrier\n' >>"${cleanup_detail_file}"
    status=1
  fi
  if [[ ! -d /sys/class/net ]]; then
    printf 'fault=root_link_inventory_unavailable\n' >>"${cleanup_detail_file}"
    status=1
  fi

  for namespace in "${ns_client}" "${ns_censor}" "${ns_server}"; do
    identity_record="${netns_identity_dir}/${namespace}.identity"
    if [[ -f "${identity_record}" ]]; then
      capture_netns_identity "${namespace}" || {
        printf 'fault=netns_identity namespace=%s\n' "${namespace}" >>"${cleanup_detail_file}"
        status=1
      }
    elif netns_exists "${namespace}"; then
      # A name created before its identity record was durably published is
      # inspectable residue, not an object cleanup may claim by name.
      printf 'fault=netns_identity namespace=%s\n' "${namespace}" >>"${cleanup_detail_file}"
      status=1
    fi
  done
  terminate_registered_owners || status=1
  prove_named_netns_processes_absent || status=1
  # Scan while names are still mounted. This prevents turning a hidden fd or
  # process reference into an anonymous namespace by unmounting too early.
  scan_netns_references predelete || status=1

  # Fail closed: namespace names stay mounted for explicit inspection unless
  # both ownership mechanisms prove that every lab process is gone.
  if [[ "${status}" -eq 0 ]]; then
    delete_lab_objects || status=1
  else
    printf 'fault=namespace_deletion_withheld reason=process_or_identity_proof_failed\n' \
      >>"${cleanup_detail_file}"
  fi

  listing="$(ip netns list)" || status=1
  for namespace in "${ns_client}" "${ns_censor}" "${ns_server}"; do
    if awk -v namespace="${namespace}" '$1 == namespace { found=1 } END { exit !found }' \
      <<<"${listing}"; then
      remaining_names+="${namespace};"
    fi
  done
  for link in "${link_client}" "${link_client_peer}" \
    "${link_server_peer}" "${link_server}"; do
    if [[ -e "/sys/class/net/${link}" ]]; then
      remaining_links+="${link};"
    fi
  done
  if [[ -n "${remaining_names}" || -n "${remaining_links}" ]]; then
    status=1
  fi
  scan_netns_references postdelete || status=1

  current_route="$(ip route show default)" || status=1
  if [[ -z "${management_interface}" ]]; then
    current_qdisc="<unavailable>"
    status=1
  else
    current_qdisc="$(tc qdisc show dev "${management_interface}")" || status=1
  fi
  if [[ "${current_route}" != "${management_route_before}" \
    || "${current_qdisc}" != "${management_qdisc_before}" ]]; then
    printf 'fault=management_snapshot_changed\n' >>"${cleanup_detail_file}"
    status=1
  fi

  {
    if [[ "${status}" -eq 0 ]]; then
      printf 'cleanup_status=valid\n'
    else
      printf 'cleanup_status=failed\n'
    fi
    printf 'cleanup_mode=%s\n' "${mode}"
    printf 'registered_owners_remaining=%s\n' \
      "${registered_owners_remaining:-<empty>}"
    printf 'owned_groups_remaining=%s\n' "${owned_groups_remaining:-<empty>}"
    printf 'named_namespace_pids_remaining=%s\n' \
      "${named_netns_pids_remaining:-<empty>}"
    printf 'namespace_process_refs=%s\n' "${namespace_process_refs:-<empty>}"
    printf 'namespace_fd_refs=%s\n' "${namespace_fd_refs:-<empty>}"
    printf 'namespace_mount_refs=%s\n' "${namespace_mount_refs:-<empty>}"
    printf 'run_network_namespaces=%s\n' "${remaining_names:-<empty>}"
    printf 'root_run_links=%s\n' "${remaining_links:-<empty>}"
    printf 'management_interface=%s\n' "${management_interface:-<unknown>}"
    printf 'management_route_unchanged=%s\n' \
      "$([[ "${current_route}" == "${management_route_before}" ]] && echo true || echo false)"
    printf 'management_qdisc_unchanged=%s\n' \
      "$([[ "${current_qdisc}" == "${management_qdisc_before}" ]] && echo true || echo false)"
    while IFS= read -r detail; do
      [[ -z "${detail}" ]] || printf '%s\n' "${detail}"
    done <"${cleanup_detail_file}"
  } >"${report_tmp}" || status=1
  mv -f -- "${report_tmp}" "${report}" || status=1
  rm -f -- "${cleanup_detail_file}"
  exec {cleanup_lock_fd}>&-
  return "${status}"
}

runner_identity_is_live() {
  local identity pgid sid starttime
  [[ -d "/proc/${runner_pid}" ]] || return 1
  identity="$(read_proc_identity "${runner_pid}")" || return 2
  read -r pgid sid starttime <<<"${identity}"
  [[ "${starttime}" == "${runner_starttime}" ]]
}

start_owned_process() {
  local label="$1" stdout_path="$2" stderr_path="$3"
  shift 3
  local record="${owned_process_dir}/${label}.owner"
  local intent="${owned_process_dir}/${label}.intent"
  local launched_pid owner owner_label owner_pid _owner_pgid _owner_sid _owner_start
  local wrapper

  [[ "${label}" =~ ^[a-z0-9-]+$ && ! -e "${record}" && ! -e "${intent}" ]] \
    || return 1
  # Publish intent before spawning. If the runner dies in the otherwise
  # unobservable fork-to-owner-record window, cleanup fails closed and keeps
  # namespace names mounted rather than claiming that no owned PID exists.
  printf '%s\n' "${label}" >"${intent}" || return 1
  chmod 600 "${intent}" || return 1
  # This is intentionally a literal program evaluated by the owned Bash
  # session leader. Parent-side expansion would destroy the ownership barrier.
  # shellcheck disable=SC2016
  wrapper='
    set -Eeuo pipefail
    exec 7>&-
    exec 8>&-
    exec 9>&-
    label="$1"
    record="$2"
    intent="$3"
    expected_runner_pid="$4"
    expected_runner_start="$5"
    shift 5
    pid="${BASHPID}"
    IFS= read -r stat_line <"/proc/${pid}/stat"
    rest="${stat_line##*) }"
    read -r -a fields <<<"${rest}"
    ((${#fields[@]} >= 20))
    pgid="${fields[2]}"
    sid="${fields[3]}"
    starttime="${fields[19]}"
    [[ "${pid}" == "${pgid}" && "${pid}" == "${sid}" ]]
    tmp="${record}.tmp.${pid}"
    printf "%s %s %s %s %s\n" \
      "${label}" "${pid}" "${pgid}" "${sid}" "${starttime}" >"${tmp}"
    chmod 600 "${tmp}"
    mv -f -- "${tmp}" "${record}"
    [[ -r "/proc/${expected_runner_pid}/stat" ]]
    IFS= read -r runner_stat <"/proc/${expected_runner_pid}/stat"
    runner_rest="${runner_stat##*) }"
    read -r -a runner_fields <<<"${runner_rest}"
    ((${#runner_fields[@]} >= 20))
    [[ "${runner_fields[19]}" == "${expected_runner_start}" ]]
    exec "$@"
  '

  if [[ "${stderr_path}" == "@stdout" ]]; then
    setsid bash -c "${wrapper}" bash "${label}" "${record}" \
      "${intent}" "${runner_pid}" "${runner_starttime}" "$@" \
      >"${stdout_path}" 2>&1 &
  else
    setsid bash -c "${wrapper}" bash "${label}" "${record}" \
      "${intent}" "${runner_pid}" "${runner_starttime}" "$@" \
      >"${stdout_path}" 2>"${stderr_path}" &
  fi
  launched_pid=$!

  for _ in {1..200}; do
    [[ -f "${record}" ]] && break
    if [[ ! -d "/proc/${launched_pid}" ]]; then
      wait "${launched_pid}" 2>/dev/null || true
      return 1
    fi
    sleep 0.01
  done
  owner="$(read_owner_record "${record}")" || return 1
  read -r owner_label owner_pid _owner_pgid _owner_sid _owner_start <<<"${owner}"
  [[ "${owner_label}" == "${label}" && "${owner_pid}" == "${launched_pid}" ]] \
    || return 1
  # Only the parent may acknowledge publication by removing the intent.  If it
  # dies anywhere before this point, cleanup sees the marker and withholds all
  # namespace deletion.
  rm -f -- "${intent}" || return 1
  owned_pid="${launched_pid}"
}

stop_owned_process() {
  local label="$1" pid="$2"
  local record="${owned_process_dir}/${label}.owner"
  local state
  pidfd_signal_registered_owner "${record}" TERM || return 1
  for _ in {1..20}; do
    if registered_owner_is_live "${record}"; then
      sleep 0.05
      continue
    else
      state=$?
      [[ "${state}" -eq 1 ]] || return 1
      break
    fi
  done
  if registered_owner_is_live "${record}"; then
    pidfd_signal_registered_owner "${record}" KILL || return 1
    for _ in {1..20}; do
      if registered_owner_is_live "${record}"; then
        sleep 0.05
        continue
      else
        state=$?
        [[ "${state}" -eq 1 ]] || return 1
        break
      fi
    done
  else
    state=$?
    [[ "${state}" -eq 1 ]] || return 1
  fi
  if registered_owner_is_live "${record}"; then
    return 1
  else
    state=$?
    [[ "${state}" -eq 1 ]] || return 1
  fi
  # The exact child identity is gone, so Bash wait cannot block on a live PID.
  wait "${pid}" 2>/dev/null || true
}

cancel_watchdog() {
  local acknowledgement
  if [[ -n "${watchdog_pid}" ]]; then
    printf 'cancel\n' >&8 2>/dev/null || true
    if ! IFS= read -r -t 5 acknowledgement <&7 \
      || [[ "${acknowledgement}" != "watchdog_done" ]]; then
      return 1
    fi
    watchdog_pid=""
  fi
}

record_watchdog_cleanup_barrier() {
  local reason="$1"
  printf '%s\n' "${reason}" >"${owned_process_dir}/watchdog-barrier.intent" || return 1
  chmod 600 "${owned_process_dir}/watchdog-barrier.intent" || return 1
}

# Invoked through the EXIT trap installed below.
# shellcheck disable=SC2329
cleanup_on_exit() {
  local original_status=$?
  trap - EXIT
  if ! cancel_watchdog; then
    watchdog_barrier_required=1
    record_watchdog_cleanup_barrier watchdog-cancellation-unconfirmed || true
    [[ "${original_status}" -ne 0 ]] || original_status=2
  elif [[ -f "${result_dir}/watchdog-fired.txt" ]]; then
    watchdog_barrier_required=1
    record_watchdog_cleanup_barrier watchdog-expired || true
    [[ "${original_status}" -ne 0 ]] || original_status=2
  fi
  if ! (set +e; cleanup_lab_state trap "${result_dir}/cleanup-state.txt"); then
    [[ "${original_status}" -ne 0 ]] || original_status=2
  fi
  exec 7>&-
  exec 8>&-
  rm -f -- "${watchdog_fifo}" "${watchdog_ack_fifo}" "${result_dir}/cleanup.lock"
  exit "${original_status}"
}

management_interface="$(ip route show default | awk \
  'NR == 1 { for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }')"
management_route_before="$(ip route show default)"
if [[ -z "${management_interface}" ]]; then
  echo "refusing: could not identify the guest management interface" >&2
  exit 74
fi
management_qdisc_before="$(tc qdisc show dev "${management_interface}")" || {
  echo "refusing: could not snapshot the guest management qdisc" >&2
  exit 74
}
ip -o link show >/dev/null || {
  echo "refusing: could not inspect root-namespace links" >&2
  exit 74
}
for link in "${link_client}" "${link_client_peer}" \
  "${link_server_peer}" "${link_server}"; do
  if [[ -e "/sys/class/net/${link}" ]]; then
    echo "refusing: candidate lab link already exists: ${link}" >&2
    exit 75
  fi
done

# The FIFO waits use Bash builtins, so the watchdog has no untracked sleep
# child.  It is deliberately passive: timeout/crash records a failure barrier
# but never signals a PID or mutates/deletes networking.  Named residue is the
# safe outcome after runner SIGKILL; VM teardown is the final containment proof.
exec 7<>"${watchdog_ack_fifo}"
exec 8<>"${watchdog_fifo}"
(
  trap - EXIT INT TERM HUP
  exec 9>&-
  if IFS= read -r -t "${watchdog_seconds}" _ <&8; then
    watchdog_outcome=cancelled
  else
    runner_state=absent
    if runner_identity_is_live; then
      runner_state=exact_identity_still_live
    elif [[ -d "/proc/${runner_pid}" ]]; then
      runner_state=reused_or_unreadable_pid
    fi
    printf '%s\n' watchdog-expired \
      >"${owned_process_dir}/watchdog-barrier.intent" 2>/dev/null || true
    chmod 600 "${owned_process_dir}/watchdog-barrier.intent" 2>/dev/null || true
    watchdog_tmp="${result_dir}/watchdog-fired.txt.tmp.${BASHPID}"
    {
      printf 'watchdog_status=expired\n'
      printf 'watchdog_seconds=%s\n' "${watchdog_seconds}"
      printf 'runner_state=%s\n' "${runner_state}"
      printf 'automatic_signal=none\n'
      printf 'automatic_network_cleanup=none\n'
      printf 'namespace_deletion=withheld\n'
      printf 'required_recovery=inspect_named_residue_then_destroy_or_reprovision_vm\n'
    } >"${watchdog_tmp}" && mv -f -- "${watchdog_tmp}" \
      "${result_dir}/watchdog-fired.txt" || true
    watchdog_outcome=expired
  fi
  printf '%s\n' "${watchdog_outcome}" \
    >"${result_dir}/watchdog-outcome.txt" 2>/dev/null || true
  printf 'watchdog_done\n' >&7 2>/dev/null || true
  exec 7>&-
  exec 8>&-
) &
watchdog_pid=$!

trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

ip netns add "${ns_client}"
capture_netns_identity "${ns_client}"
ip netns add "${ns_censor}"
capture_netns_identity "${ns_censor}"
ip netns add "${ns_server}"
capture_netns_identity "${ns_server}"

ip link add "${link_client}" type veth peer name "${link_client_peer}"
for link in "${link_client}" "${link_client_peer}"; do
  ip link set dev "${link}" alias "${link_owner_token}:${link}"
  capture_root_link_identity "${link}"
done
ip link add "${link_server_peer}" type veth peer name "${link_server}"
for link in "${link_server_peer}" "${link_server}"; do
  ip link set dev "${link}" alias "${link_owner_token}:${link}"
  capture_root_link_identity "${link}"
done
ip link set "${link_client}" netns "${ns_client}"
ip link set "${link_client_peer}" netns "${ns_censor}"
ip link set "${link_server_peer}" netns "${ns_censor}"
ip link set "${link_server}" netns "${ns_server}"

ip -n "${ns_client}" link set "${link_client}" name ztc0
ip -n "${ns_censor}" link set "${link_client_peer}" name ztr0
ip -n "${ns_censor}" link set "${link_server_peer}" name ztr1
ip -n "${ns_server}" link set "${link_server}" name zts0

ip -n "${ns_client}" addr add 10.231.0.2/24 dev ztc0
ip -n "${ns_censor}" addr add 10.231.0.1/24 dev ztr0
ip -n "${ns_censor}" addr add 10.232.0.1/24 dev ztr1
ip -n "${ns_server}" addr add 10.232.0.2/24 dev zts0

for ns in "${ns_client}" "${ns_censor}" "${ns_server}"; do
  ip -n "${ns}" link set lo up
done
ip -n "${ns_client}" link set ztc0 up
ip -n "${ns_censor}" link set ztr0 up
ip -n "${ns_censor}" link set ztr1 up
ip -n "${ns_server}" link set zts0 up
ip -n "${ns_client}" route add default via 10.231.0.1
ip -n "${ns_server}" route add default via 10.232.0.1
ip netns exec "${ns_censor}" sysctl -q -w net.ipv4.ip_forward=1

delay="0ms"
jitter="0ms"
loss="0%"
reorder="0%"
rate="1000mbit"
threshold_bytes="0"
udp_blackout="false"
tcp_parallel="4"

case "${profile}" in
  baseline) ;;
  wan) delay="40ms"; jitter="5ms"; rate="100mbit" ;;
  lossy) delay="80ms"; jitter="20ms"; loss="3%"; reorder="0.5%"; rate="10mbit" ;;
  severe) delay="200ms"; jitter="80ms"; loss="10%"; reorder="5%"; rate="2mbit" ;;
  udp-blackout) delay="40ms"; jitter="5ms"; rate="100mbit"; udp_blackout="true" ;;
  synthetic-byte-threshold)
    delay="40ms"
    jitter="5ms"
    rate="100mbit"
    threshold_bytes="${ZATMENIE_SYNTHETIC_THRESHOLD_BYTES:-16384}"
    tcp_parallel="1"
    ;;
  *)
    echo "unknown profile: ${profile}" >&2
    exit 64
    ;;
esac

if [[ ! "${threshold_bytes}" =~ ^[0-9]+$ ]] \
  || (( threshold_bytes > 1073741824 )); then
  echo "invalid synthetic threshold: expected an integer in [0, 1073741824]" >&2
  exit 64
fi
if [[ "${profile}" == "synthetic-byte-threshold" ]] && (( threshold_bytes < 1024 )); then
  echo "invalid synthetic threshold: threshold profile requires at least 1024 bytes" >&2
  exit 64
fi

ip netns exec "${ns_censor}" tc qdisc replace dev ztr1 root netem \
  delay "${delay}" "${jitter}" loss "${loss}" reorder "${reorder}" rate "${rate}" \
  seed "${netem_seed_forward}"
ip netns exec "${ns_censor}" tc qdisc replace dev ztr0 root netem \
  delay "${delay}" "${jitter}" loss "${loss}" reorder "${reorder}" rate "${rate}" \
  seed "${netem_seed_reverse}"

if [[ "${udp_blackout}" == "true" || "${threshold_bytes}" != "0" ]]; then
  ip netns exec "${ns_censor}" nft -f - <<EOF
table inet zatmenie_lab {
  chain forward {
    type filter hook forward priority 0; policy accept;
  }
}
EOF
fi
if [[ "${udp_blackout}" == "true" ]]; then
  ip netns exec "${ns_censor}" nft add rule inet zatmenie_lab forward \
    meta l4proto udp counter drop comment "udp_blackout"
fi
if [[ "${threshold_bytes}" != "0" ]]; then
  # Synthetic TCP-only, bidirectional conntrack-byte gate. This is a primitive
  # single-flow fault injection, not an application-byte threshold and not
  # evidence for any real censor trigger unit.
  ip netns exec "${ns_censor}" nft add rule inet zatmenie_lab forward \
    meta l4proto tcp ct bytes ge "${threshold_bytes}" counter drop \
    comment "synthetic_tcp_threshold"
fi

start_owned_process tcp-server "${result_dir}/iperf-server-tcp.log" @stdout \
  ip netns exec "${ns_server}" iperf3 -s -1 -B 10.232.0.2
server_pid="${owned_pid}"
sleep 0.25

if ! start_owned_process tcp-client "${result_dir}/iperf-tcp.json" \
  "${result_dir}/iperf-client.err" timeout --signal=TERM --kill-after=2s 15s \
  ip netns exec "${ns_client}" \
  iperf3 -c 10.232.0.2 -t 3 -P "${tcp_parallel}" -J; then
  echo "failed to launch owned TCP client process group" >&2
  exit 74
fi
tcp_client_pid="${owned_pid}"
set +e
wait "${tcp_client_pid}"
iperf_status=$?
set -e
if ! stop_owned_process tcp-server "${server_pid}"; then
  echo "failed to stop the registered TCP server owner" >&2
  exit 74
fi
server_pid=""

start_owned_process udp-server "${result_dir}/iperf-server-udp.log" @stdout \
  ip netns exec "${ns_server}" iperf3 -s -1 -B 10.232.0.2
server_pid="${owned_pid}"
sleep 0.25
if ! start_owned_process udp-client "${result_dir}/iperf-udp.json" \
  "${result_dir}/iperf-udp.err" timeout --signal=TERM --kill-after=2s 15s \
  ip netns exec "${ns_client}" \
  iperf3 -c 10.232.0.2 -u -b 5M -t 2 -J; then
  echo "failed to launch owned UDP client process group" >&2
  exit 74
fi
udp_client_pid="${owned_pid}"
set +e
wait "${udp_client_pid}"
udp_status=$?
set -e
if ! stop_owned_process udp-server "${server_pid}"; then
  echo "failed to stop the registered UDP server owner" >&2
  exit 74
fi
server_pid=""

ip netns exec "${ns_censor}" tc -s qdisc show dev ztr1 \
  >"${result_dir}/tc-state.txt"
ip netns exec "${ns_censor}" tc -s qdisc show dev ztr0 \
  >"${result_dir}/tc-state-reverse.txt"
nft_instrumentation_status="not_applicable"
if [[ "${udp_blackout}" == "true" || "${threshold_bytes}" != "0" ]]; then
  if ip netns exec "${ns_censor}" nft list table inet zatmenie_lab \
    >"${result_dir}/nft-state.txt" 2>&1; then
    nft_instrumentation_status="valid"
  else
    nft_instrumentation_status="failed"
  fi
else
  printf '%s\n' 'no nft fault rules for this profile' >"${result_dir}/nft-state.txt"
fi

tcp_measurement_status="missing_end_summary"
tcp_received_bytes="null"
tcp_received_bps="null"
tcp_stalled="null"
if jq -e '.error == null and (.end.sum_received.seconds // 0) > 0 and (.end.sum_received.bytes | numbers) and (.end.sum_received.bits_per_second | numbers)' \
  "${result_dir}/iperf-tcp.json" >/dev/null 2>&1; then
  tcp_measurement_status="valid_receiver_summary"
  tcp_received_bytes="$(jq -r '.end.sum_received.bytes' "${result_dir}/iperf-tcp.json")"
  tcp_received_bps="$(jq -r '.end.sum_received.bits_per_second' "${result_dir}/iperf-tcp.json")"
  if [[ "${tcp_received_bytes}" -lt 65536 ]]; then tcp_stalled="true"; else tcp_stalled="false"; fi
fi

udp_measurement_status="missing_end_summary"
udp_received_bps="null"
udp_loss_percent="null"
udp_blocked_observed="null"
if jq -e '.error == null and (.end.sum_received.seconds // 0) > 0 and (.end.sum_received.bits_per_second | numbers) and (.end.sum_received.lost_percent | numbers)' \
  "${result_dir}/iperf-udp.json" >/dev/null 2>&1; then
  udp_measurement_status="valid_receiver_summary"
  udp_received_bps="$(jq -r '.end.sum_received.bits_per_second' "${result_dir}/iperf-udp.json")"
  udp_loss_percent="$(jq -r '.end.sum_received.lost_percent' "${result_dir}/iperf-udp.json")"
  if awk "BEGIN { exit !(${udp_received_bps} <= 1.0) }"; then udp_blocked_observed="true"; else udp_blocked_observed="false"; fi
fi

threshold_drop_packets="$(awk '/comment "synthetic_tcp_threshold"/ { for (i=1; i<=NF; i++) if ($i=="packets") { print $(i+1); exit } }' "${result_dir}/nft-state.txt")"
udp_drop_packets="$(awk '/comment "udp_blackout"/ { for (i=1; i<=NF; i++) if ($i=="packets") { print $(i+1); exit } }' "${result_dir}/nft-state.txt")"
threshold_drop_packets="${threshold_drop_packets:-0}"
udp_drop_packets="${udp_drop_packets:-0}"

forward_qdisc_packets="$(awk '$1 == "Sent" { print $4; exit }' "${result_dir}/tc-state.txt")"
reverse_qdisc_packets="$(awk '$1 == "Sent" { print $4; exit }' "${result_dir}/tc-state-reverse.txt")"
tc_instrumentation_status="valid"
if [[ ! "${forward_qdisc_packets}" =~ ^[0-9]+$ ]] \
  || [[ ! "${reverse_qdisc_packets}" =~ ^[0-9]+$ ]]; then
  tc_instrumentation_status="failed"
  forward_qdisc_packets="${forward_qdisc_packets:-0}"
  reverse_qdisc_packets="${reverse_qdisc_packets:-0}"
fi

verdict="MEASUREMENT_FAULT"
verdict_reason="required receiver summary is missing"
case "${profile}" in
  baseline|wan|lossy|severe)
    if [[ "${tc_instrumentation_status}" != "valid" \
      || "${forward_qdisc_packets}" -eq 0 || "${reverse_qdisc_packets}" -eq 0 ]]; then
      verdict_reason="could not prove traffic crossed both netem directions"
    elif [[ "${iperf_status}" -eq 0 && "${udp_status}" -eq 0 \
      && "${tcp_measurement_status}" == "valid_receiver_summary" \
      && "${udp_measurement_status}" == "valid_receiver_summary" \
      && "${tcp_stalled}" == "false" \
      && "${forward_qdisc_packets}" -gt 0 && "${reverse_qdisc_packets}" -gt 0 ]] \
      && awk "BEGIN { exit !(${udp_received_bps} > 1.0) }"; then
      verdict="PASS"
      verdict_reason="both transports made positive progress through both impairment directions"
    elif [[ "${iperf_status}" -eq 0 && "${udp_status}" -eq 0 \
      && "${tcp_measurement_status}" == "valid_receiver_summary" \
      && "${udp_measurement_status}" == "valid_receiver_summary" ]]; then
      verdict="FAIL"
      verdict_reason="a normal-profile control completed without required positive progress"
    fi
    ;;
  udp-blackout)
    if [[ "${tc_instrumentation_status}" != "valid" \
      || "${forward_qdisc_packets}" -eq 0 || "${reverse_qdisc_packets}" -eq 0 ]]; then
      verdict_reason="could not prove traffic crossed both netem directions"
    elif [[ "${nft_instrumentation_status}" == "failed" ]]; then
      verdict_reason="could not read the UDP fault-rule counter"
    elif [[ "${tcp_measurement_status}" != "valid_receiver_summary" \
      || "${iperf_status}" -ne 0 || "${tcp_stalled}" != "false" ]]; then
      verdict_reason="TCP negative control did not complete with positive progress"
    elif [[ "${udp_drop_packets}" -eq 0 ]]; then
      verdict="FAIL"
      verdict_reason="UDP fault rule did not activate"
    elif [[ "${udp_status}" -eq 124 ]]; then
      verdict="PASS"
      verdict_reason="TCP completed and counted UDP fault produced the expected timeout"
    elif [[ "${udp_status}" -eq 0 && "${udp_measurement_status}" == "valid_receiver_summary" \
      && "${udp_blocked_observed}" == "true" ]]; then
      verdict="PASS"
      verdict_reason="TCP completed and counted UDP fault produced a receiver-zero summary"
    elif [[ "${udp_status}" -eq 0 && "${udp_measurement_status}" == "valid_receiver_summary" ]]; then
      verdict="FAIL"
      verdict_reason="UDP made positive progress despite an activated blackout rule"
    else
      verdict_reason="UDP client ended with an unexpected status or malformed summary"
    fi
    ;;
  synthetic-byte-threshold)
    if [[ "${tc_instrumentation_status}" != "valid" \
      || "${forward_qdisc_packets}" -eq 0 || "${reverse_qdisc_packets}" -eq 0 ]]; then
      verdict_reason="could not prove traffic crossed both netem directions"
    elif [[ "${nft_instrumentation_status}" == "failed" ]]; then
      verdict_reason="could not read the synthetic TCP fault-rule counter"
    elif [[ "${threshold_drop_packets}" -eq 0 ]]; then
      verdict="FAIL"
      verdict_reason="synthetic TCP threshold rule did not activate"
    elif [[ "${udp_status}" -ne 0 || "${udp_measurement_status}" != "valid_receiver_summary" ]]; then
      verdict_reason="UDP negative control did not produce a valid receiver summary"
    elif ! awk "BEGIN { exit !(${udp_received_bps} > 1.0) }"; then
      verdict="FAIL"
      verdict_reason="UDP negative control made no positive progress"
    elif [[ "${iperf_status}" -eq 124 ]]; then
      verdict="PASS"
      verdict_reason="counted TCP fault produced the expected timeout while UDP completed"
    elif [[ "${iperf_status}" -eq 0 && "${tcp_measurement_status}" == "valid_receiver_summary" ]] \
      && awk "BEGIN { exit !(${tcp_received_bps} <= 1.0) }"; then
      verdict="PASS"
      verdict_reason="counted TCP fault produced a receiver-zero summary while UDP completed"
    elif [[ "${iperf_status}" -eq 0 && "${tcp_measurement_status}" == "valid_receiver_summary" ]]; then
      verdict="FAIL"
      verdict_reason="TCP made positive progress despite an activated synthetic threshold"
    else
      verdict_reason="TCP client ended with an unexpected status or malformed summary"
    fi
    ;;
esac

# Seal cleanup evidence inside the run rather than relying only on a later
# human attestation. All measurement state above has already been captured.
if ! cancel_watchdog; then
  watchdog_barrier_required=1
  record_watchdog_cleanup_barrier watchdog-cancellation-unconfirmed || true
elif [[ -f "${result_dir}/watchdog-fired.txt" ]]; then
  watchdog_barrier_required=1
  record_watchdog_cleanup_barrier watchdog-expired || true
fi
if (set +e; cleanup_lab_state normal "${result_dir}/cleanup-state.txt"); then
  cleanup_status="valid"
else
  cleanup_status="failed"
fi
server_pid=""
trap - EXIT
exec 7>&-
exec 8>&-
rm -f -- "${watchdog_fifo}" "${watchdog_ack_fifo}" "${result_dir}/cleanup.lock"
set -e

if [[ "${cleanup_status}" != "valid" ]]; then
  verdict="MEASUREMENT_FAULT"
  verdict_reason="post-run owned-process/namespace/inode cleanup proof failed"
fi

{
  printf 'kernel=%s\n' "$(uname -srmo)"
  printf 'iproute2=%s\n' "$(ip -V 2>&1)"
  printf 'tc=%s\n' "$(tc -V 2>&1)"
  printf 'nftables=%s\n' "$(nft --version 2>&1)"
  printf 'iperf3=%s\n' "$(iperf3 --version 2>&1 | head -n 1)"
  printf 'jq=%s\n' "$(jq --version 2>&1)"
  printf 'runner_sha256=%s\n' "$(sha256sum "$0" | awk '{print $1}')"
} >"${result_dir}/environment.txt"

cat >"${result_dir}/manifest.json" <<EOF
{
  "schema_version": 1,
  "run_id": "${run_id}",
  "profile": "${profile}",
  "scope": "synthetic_linux_netns_only",
  "field_evidence": false,
  "delay": "${delay}",
  "jitter": "${jitter}",
  "loss": "${loss}",
  "reorder": "${reorder}",
  "rate": "${rate}",
  "netem_seed_forward": ${netem_seed_forward},
  "netem_seed_reverse": ${netem_seed_reverse},
  "impairment_direction": "symmetric",
  "configured_delay_semantics": "one_way_per_direction",
  "watchdog_seconds": ${watchdog_seconds},
  "tcp_parallel_flows": ${tcp_parallel},
  "udp_blackout": ${udp_blackout},
  "synthetic_threshold_bytes": ${threshold_bytes},
  "iperf_tcp_exit_status": ${iperf_status},
  "iperf_udp_exit_status": ${udp_status},
  "verdict": "${verdict}",
  "verdict_reason": "${verdict_reason}",
  "cleanup_status": "${cleanup_status}",
  "instrumentation": {
    "tc_status": "${tc_instrumentation_status}",
    "forward_qdisc_packets": ${forward_qdisc_packets},
    "reverse_qdisc_packets": ${reverse_qdisc_packets},
    "nft_status": "${nft_instrumentation_status}"
  },
  "observed": {
    "tcp_measurement_status": "${tcp_measurement_status}",
    "tcp_received_bytes": ${tcp_received_bytes},
    "tcp_received_bps": ${tcp_received_bps},
    "tcp_stalled": ${tcp_stalled},
    "synthetic_tcp_threshold_drop_packets": ${threshold_drop_packets},
    "udp_measurement_status": "${udp_measurement_status}",
    "udp_received_bps": ${udp_received_bps},
    "udp_loss_percent": ${udp_loss_percent},
    "udp_blocked": ${udp_blocked_observed},
    "udp_blackout_drop_packets": ${udp_drop_packets}
  }
}
EOF

jq -e . "${result_dir}/manifest.json" >/dev/null
(cd "${result_dir}" && sha256sum \
  manifest.json environment.txt runner.sh cleanup-state.txt tc-state.txt tc-state-reverse.txt nft-state.txt \
  iperf-tcp.json iperf-udp.json iperf-client.err iperf-udp.err \
  iperf-server-tcp.log iperf-server-udp.log \
  watchdog-outcome.txt owned-processes/*.owner netns-identities/*.identity \
  link-identities/*.identity >checksums.txt)

echo "result_dir=${result_dir}"
echo "iperf_tcp_exit_status=${iperf_status}"
echo "iperf_udp_exit_status=${udp_status}"
echo "verdict=${verdict}"
if [[ "${verdict}" == "PASS" ]]; then exit 0; fi
if [[ "${verdict}" == "FAIL" ]]; then exit 1; fi
exit 2
