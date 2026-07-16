#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
runner="${script_dir}/run.sh"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

bash -n "${runner}"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -x "${runner}"
fi

if grep -Eq '(^|[^[:alnum:]_])(pkill|killall)([^[:alnum:]_]|$)' "${runner}"; then
  fail "runner contains a broad process-name kill"
fi
if grep -Eq '^[[:space:]]*kill([[:space:]]|$)' "${runner}"; then
  fail "runner contains a raw shell PID/PGID signal"
fi
for forbidden in \
  'terminate_named_netns_processes' \
  'signal_owned_group' \
  'cleanup_lab_state watchdog' \
  'kill -STOP' \
  'kill -CONT'; do
  grep -Fq -- "${forbidden}" "${runner}" \
    && fail "runner contains forbidden active-watchdog/raw-signal path: ${forbidden}"
done

for invariant in \
  'setsid bash -c' \
  'unresolved_launch_intent' \
  'ip netns pids' \
  'pidfd = os.pidfd_open' \
  'signal.pidfd_send_signal' \
  'terminate_registered_owners || status=1' \
  'prove_named_netns_processes_absent || status=1' \
  'scan_netns_references predelete || status=1' \
  'scan_netns_references postdelete || status=1' \
  'delete_lab_objects || status=1' \
  'namespace_deletion_withheld reason=process_or_identity_proof_failed' \
  '/ns/net_for_children' \
  '/task/[0-9]*' \
  "\${task_dir}\"/fd/*" \
  '/fd/*' \
  'verify_owned_root_link' \
  "/sys/class/net/\${link}/ifindex" \
  "/sys/class/net/\${link}/ifalias" \
  'candidate lab link already exists' \
  'automatic_signal=none' \
  'automatic_network_cleanup=none' \
  'namespace_deletion=withheld' \
  'watchdog-barrier.intent' \
  'read -r -t 5 acknowledgement' \
  'management_qdisc_unchanged'; do
  grep -Fq -- "${invariant}" "${runner}" \
    || fail "missing cleanup invariant: ${invariant}"
done

group_line="$(grep -nF '  terminate_registered_owners || status=1' "${runner}" \
  | tail -n 1 | cut -d: -f1)"
netns_pid_line="$(grep -nF '  prove_named_netns_processes_absent || status=1' "${runner}" \
  | tail -n 1 | cut -d: -f1)"
predelete_scan_line="$(grep -nF '  scan_netns_references predelete || status=1' "${runner}" \
  | head -n 1 | cut -d: -f1)"
delete_line="$(grep -nF '    delete_lab_objects || status=1' "${runner}" \
  | tail -n 1 | cut -d: -f1)"
if ! ((group_line < netns_pid_line \
  && netns_pid_line < predelete_scan_line \
  && predelete_scan_line < delete_line)); then
  fail "cleanup ordering is not registered-owners -> netns-PID absence -> ref-scan -> deletion"
fi

link_preflight_line="$(grep -nF 'candidate lab link already exists' "${runner}" \
  | head -n 1 | cut -d: -f1)"
link_create_line="$(grep -nF "ip link add \"\${link_client}\"" "${runner}" \
  | head -n 1 | cut -d: -f1)"
link_verify_line="$(grep -nF "verify_owned_root_link \"\${link}\"" "${runner}" \
  | tail -n 1 | cut -d: -f1)"
link_delete_line="$(grep -nF "ip link del \"\${link}\"" "${runner}" \
  | tail -n 1 | cut -d: -f1)"
if ! ((link_preflight_line < link_create_line \
  && link_verify_line < link_delete_line)); then
  fail "root-link preflight/identity proof does not precede creation/deletion"
fi

# This call is intentionally made without the opt-in token. It must return
# before Linux/root/tool/result setup and therefore cannot mutate networking.
set +e
gate_output="$(env -u ZATMENIE_LAB bash "${runner}" baseline 2>&1)"
gate_status=$?
set -e
[[ "${gate_status}" -eq 64 ]] || fail "missing-lab-token exit status is ${gate_status}, not 64"
grep -Fq 'refusing: set ZATMENIE_LAB=1 inside a disposable Linux VM' \
  <<<"${gate_output}" || fail "missing-lab-token refusal text changed"

if [[ "$(uname -s)" != "Linux" ]]; then
  set +e
  os_output="$(ZATMENIE_LAB=1 bash "${runner}" baseline 2>&1)"
  os_status=$?
  set -e
  [[ "${os_status}" -eq 64 ]] || fail "non-Linux exit status is ${os_status}, not 64"
  grep -Fq 'refusing: Linux network namespaces are required' <<<"${os_output}" \
    || fail "non-Linux refusal text changed"
fi

printf '%s\n' 'PASS: netem runner static safety invariants'
