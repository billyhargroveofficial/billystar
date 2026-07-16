# ZATMENIE netns impairment lab

This harness validates packet-path correctness under controlled faults. It does
**not** reproduce or prove the behaviour of a real censor.

The runner creates three disposable Linux network namespaces:

```text
client -- veth -- censor/router -- veth -- server
```

All addresses, routes, `tc` qdiscs, nftables rules, and packet captures live
inside those namespaces. The host default route, DNS, firewall, and TUN devices
are never changed.

Configured netem delay is one-way on each forwarding direction; its approximate
idle-path RTT contribution is twice the configured delay. The two qdiscs do not
double-apply a packet in one direction.

## Safety gate

Run only in a disposable Linux VM (the intended target is OrbStack `arch`):

```bash
sudo env ZATMENIE_LAB=1 ./run.sh baseline ./results
sudo env ZATMENIE_LAB=1 ./run.sh lossy ./results
sudo env ZATMENIE_LAB=1 ./run.sh udp-blackout ./results
sudo env ZATMENIE_LAB=1 ./run.sh synthetic-byte-threshold ./results
```

`synthetic-byte-threshold` drops a conntrack flow after a configured byte
count. It is a deterministic fault-injection control, **not a TSPU model** and
must never be cited as field evidence.

The runner refuses result paths outside this directory's `results/` tree. Every
raw run writes receiver-side iperf3 JSON, the effective `tc`/nftables state,
environment versions, the exact `runner.sh`, a manifest, logs, the cleanup
proof, watchdog outcome, process-ownership records, namespace-inode records,
root-link ifindex/ifalias records and checksums.
Netem uses a deterministic forward/reverse seed pair, records both in the
manifest, and accepts a bounded `ZATMENIE_NETEM_SEED` override for a frozen
experiment schedule.
These raw artifacts are local audit evidence and may expose fine-grained timing;
they are not automatically publication-safe. A separately reviewed sanitized
bundle contains only reduced aggregates and redacted provenance.

Normal cleanup is registered before setup and runs on normal exit, errors and
catchable signals. Every iperf server/client starts in a distinct `setsid`
session and publishes an ownership record containing PID, PGID, SID and
`/proc` start time. The parent removes the pre-spawn launch-intent marker only
after validating that record. An unresolved intent is therefore a deletion
barrier, not a process-discovery hint.

Only a registered session leader may be signalled. The runner first opens a
Linux pidfd, validates the recorded start time/PGID/SID, and then uses
`pidfd_send_signal`. An ordinary reused PID with different recorded identity is
rejected, and the pidfd prevents a post-open exit/reuse race from changing the
target. This is not an adversarial proof against a concurrent privileged actor
that can deliberately recreate all recorded attributes. The runner never
signals a numeric process group and never signals values returned by
`ip netns pids`. Descendants or named-namespace PIDs that remain after the
registered leader exits make cleanup fail closed and leave the names mounted.

The bounded watchdog is deliberately **passive**. It waits with a Bash builtin
over a private FIFO and, on expiry, writes a failure marker and launch-intent
barrier. It does not STOP/CONT/TERM/KILL the runner, terminate workloads, touch a
link/qdisc/rule, or delete a namespace. In particular, if the runner alone is
`SIGKILL`ed, the safe expected result is named residue for inspection followed
by VM destruction/reprovisioning. The next run refuses while a `zt-*` namespace
name remains. Watchdog cancellation uses a separate acknowledgement FIFO and a
five-second bounded wait.

Normal cleanup is intentionally conservative:

1. validate already-published namespace identities; a name without its record
   is not claimed;
2. TERM/KILL only exact registered leaders through pidfds, with bounded waits;
3. inspect `ip netns pids`; any PID is a proof failure and is never signalled;
4. scan every visible `/proc/PID/task/TID/ns/{net,net_for_children}`, each
   task-visible FD table and other `/run/netns` aliases; any reference or
   unreadable live entry withholds deletion;
5. delete a root veth only after its current ifindex and ifalias match the
   record captured immediately after creation; candidate names must be absent at
   preflight;
6. revalidate namespace inode records, remove names, rescan visible references,
   and compare the guest management route/qdisc to the preflight snapshot.

This is a fail-stop guard for runner-owned state, not a proof of the Linux
network-namespace object's global destruction. An external process can pin a
namespace through a socket/netlink object, or an nsfs bind mount can exist in
another mount namespace without appearing as a `net:[inode]` FD in this scan.
A concurrent privileged actor can also invalidate any userspace observation.
Consequently, successful name deletion means only that the runner's bounded
checks passed. Destroying/reprovisioning the disposable VM is the final isolation
boundary. An unreadable `/proc` entry is a proof failure; absence of a persisted
cleanup report is never inferred as success.

The watchdog also does not provide a liveness bound for the cleanup routine
itself. User-space waits for owned processes and the watchdog acknowledgement
are bounded, but a kernel/netlink operation stuck in uninterruptible sleep may
stall the runner indefinitely. That failure leaves the run unproven; stop or
destroy the disposable VM rather than expanding signal/delete scope.

Run the non-privileged static safety check with:

```bash
./test-runner-safety.sh
```

This substring/order check is a regression sentinel, not a semantic proof of a
privileged shell program. A changed mutator or cleanup path still requires
manual review that every `tc`/`nft`/`sysctl` action is namespace-scoped and
every root-link deletion revalidates ownership.

Historical checksummed result bundles intentionally retain the copied runner
that actually produced them. Hardening `run.sh` does not rewrite those sealed
artifacts; a new privileged run would record the new runner hash.
