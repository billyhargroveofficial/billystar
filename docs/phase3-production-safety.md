# Phase 3: signed endpoint authority and crash-safe Linux host state

Snapshot: 2026-07-17. This document describes implemented mechanisms and their
security invariants. It is not a production-readiness statement, an independent
audit, or evidence of resistance to a real censor.

## Evidence status

| Layer | Current status | This does not establish |
|---|---|---|
| Signed policy, endpoint coordinator, host journal and recovery adapters | Implemented with adversarial unit/component tests | Cryptographic review, fleet-safe rollout, or a green release pipeline |
| Current product-source Linux all-resource recovery | [`20260716T225901Z-98821`](../tests/host-recovery/results/20260716T225901Z-98821/FINAL-RESULT.md) plus compact [`PUBLISHED-EVIDENCE.md`](../tests/host-recovery/results/20260716T225901Z-98821/PUBLISHED-EVIDENCE.md), clean pushed `c9b60e7`: scoped PASS, 29/29 scenarios and 1,592 checksum entries; later `c9b60e7..d335682` changes are test-tooling-only | Kernel reboot, torn writes, power loss, production or field behavior |
| Current product-source PID-1 userspace reboot and installed client lifecycle | [`20260717T001923Z-52605-reboot`](../tests/lockdown/results/20260717T001923Z-52605-reboot/RESULT.md) plus compact [`PUBLISHED-EVIDENCE.md`](../tests/lockdown/results/20260717T001923Z-52605-reboot/PUBLISHED-EVIDENCE.md), clean pushed `e374075`: scoped PASS, 939 checksum entries | Successful tunnel, paired reboot recovery, dedicated-kernel/power-loss reboot, production or field behavior |
| Source-bound Linux full-TUN handoff | [`RESULT.md`](../tests/tun/results/20260716T173837Z-18283-m8K2po/RESULT.md) plus tracked compact [`PUBLISHED-EVIDENCE.md`](../tests/tun/results/20260716T173837Z-18283-m8K2po/PUBLISHED-EVIDENCE.md), commit `81f188f`: scoped PASS, 745 entries | Current-head successful tunnel, real systemd PID 1, native macOS/Windows, outer/inner IPv6 or field behavior |
| Source-bound native Linux ARM64 portability | [`20260716T180304Z-linux-arm64-current`](../tests/portability/results/20260716T180304Z-linux-arm64-current/RESULT.md), clean commit `726500f`: scoped PASS, 342 entries; tests 718/0/4 and 732/0/4 | Current-head portability after `2ece275`, privileged networking, production or field behavior |
| Earlier Linux full-TUN runtime | Snapshot-bound [`20260716T123535Z-91294-70zWb7`](../tests/tun/results/20260716T123535Z-91294-70zWb7/RESULT.md): scoped PASS, 573/573 checksum entries | Current network-handoff implementation, IPv6, native Windows/macOS TUN, production or field behavior |
| Earlier Linux same-boot crash recovery | Snapshot-bound [`20260716T124109Z-93828`](../tests/host-recovery/results/20260716T124109Z-93828/FINAL-RESULT.md): 29/29 scenarios, 1443/1443 checksum entries | Anything beyond its frozen source; the newer current product-source cell is listed above |
| Earlier Linux reboot lockdown | Snapshot-bound [`20260716T124706Z-34564-reboot`](../tests/lockdown/results/20260716T124706Z-34564-reboot/RESULT.md): distinct boot IDs, restore 2,995 us before networkd, 650/650 checksum entries | Anything beyond its frozen source; the newer PID-1 userspace cell is listed above |
| Windows 11 ARM64 no-TUN | Snapshot-bound [`20260716T125113Z-36840-dd0c2571`](../tests/windows/results/20260716T125113Z-36840-dd0c2571/RESULT.md): scoped PASS, 891/891 checksums | Current-head Windows portability, Wintun, route/DNS/firewall mutation safety, production or field behavior |
| Censorship resistance | Architecture and research hypotheses only | No current TSPU/GFW/operator result, unblockability, or indistinguishability |
| Platforms | Linux-first host-state implementation | IPv6 completeness, Windows Wintun safety, macOS TUN/route safety, Android VpnService, or mobility behavior |

These are synthetic disposable-guest implementation results with
`field_evidence=false`, not one combined production certification. At
`e374075`, current product-source lifecycle status is split between the
`c9b60e7` recovery cell and the `e374075` PID-1 userspace reboot/client-lifecycle
cell. Production Rust changed in `2ece275`, so the successful full-TUN result at
`81f188f`, native ARM64 result at `726500f` and Windows result remain valid only
for their exact frozen sources. No source-bound combination proves a successful
current-head VPN. None is field-censorship evidence.

## 1. Trust and policy object

The production endpoint path accepts one closed artifact chain:

```text
independently enrolled offline root identity
        |
        +-- Ed25519 COSE_Sign1: keyset schema v1
                |
                +-- authorized online Ed25519 key
                        |
                        +-- COSE_Sign1: endpoint-policy schema v2
                                |
                                +-- verified REALITY plan
```

The implementation uses a strict, fixed `COSE_Sign1` profile over deterministic
CBOR and Ed25519. Protected content types, algorithms, key identifiers and
schema versions are checked rather than negotiated. Verification rejects
non-canonical encodings, duplicate/unknown fields, malformed types, invalid
validity windows, unauthorized keys and unsupported schema versions before an
endpoint can become dialable.

Endpoint-policy **v2** is mandatory. Endpoint-policy v1 is rejected explicitly;
there is no compatibility decoder or silent fallback. Moving an enrolled client
from v1 to v2 is a new authenticated enrollment/trust-anchor distribution event,
not a v1 successor update. The public bundle envelope and root-signed keyset
remain schema v1.

Policy v2 deliberately separates two signed names:

- `locator_name` is the canonical lower-case DNS name used only to group and
  refresh endpoint address authority;
- `sni` is the independent canonical lower-case REALITY authentication/cover
  name used for the carrier handshake.

Both fields are mandatory and included in the authentication and authority
digests. Neither defaults to the other. Therefore a plausible cover SNI cannot
silently become DNS routing authority.

The durable policy state enforces independent keyset and policy epoch floors,
sequence continuity, predecessor hashes, same-coordinate fork rejection,
validity/expiry and a maximum observed wall-clock floor. On an orderly runtime
expiry, before sealing host state fail-closed, the client atomically checkpoints
a separate fixed 132-byte, `0600`, magic-tagged `SPPOLEX1` expiry tombstone at
`<policy-state>.expired-v1` under the policy lock. That tombstone is
checksum-protected, bound to the enrolled offline-root identity, and contains
the exact policy hash, `(policy_epoch, sequence)` and signed `expires_at`.
Loading or idempotently resubmitting that hash is then rejected even if the wall
clock is rolled back after restart. A different hash can still advance through
the ordinary authenticated successor chain; before publishing a tombstone the
store reloads the current anchor and requires an exact match, so a stale runtime
cannot retire a successor. Corrupt, unsafe, wrong-root or symlinked tombstone
state fails closed.

This is not trusted time across arbitrary failure. It closes the orderly
monotonic-expiry -> durable checkpoint -> restart case only. A crash or power
loss before the tombstone fsync, storage rollback, or a different boot whose
wall clock is rolled back before any orderly checkpoint remains outside the
claim and requires a trusted-time or monotonic hardware/fleet authority.

Key and server-pin rotation require explicit successor state and a complete
86,400-second overlap; a higher keyset epoch cannot reset the policy floor. New
pins/keys and `Active -> Retiring` transitions must remain usable until the end
of that overlap, including the containing policy/keyset lifetime. A candidate
policy must be signed by a currently `Active` online key; `Retiring` and
`Revoked` keys verify historical bundles only. Revoked keys may be removed in a
later contiguous keyset so the bounded keyset does not monotonically exhaust.

The exact sorted `service_id` set is immutable after the initial authenticated
enrollment. Adding, removing or renaming a service authority requires a new
authenticated enrollment/schema event and cannot bypass per-service pin
continuity. An exact already-accepted object is an idempotent no-op only while
it has not been durably tombstoned, while gaps, rollback, forks and expired
state fail closed.

The overlap mechanism protects rollout continuity, not containment of a
compromised `Active` online signer. Such a signer can still add an
attacker-controlled pin alongside the old pin. Containment requires a separate
offline-root/threshold-authorized service registry or equivalent binding of
service identity and pins; endpoint-policy v2 does not currently provide it.

These mechanisms are informed by, but do not claim conformance to, the entire
[The Update Framework specification](https://theupdateframework.github.io/specification/latest/).
The wire primitives are grounded in [RFC 9052 COSE](https://datatracker.ietf.org/doc/html/rfc9052),
[RFC 8949 deterministic CBOR](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2)
and [RFC 8032 Ed25519](https://www.rfc-editor.org/info/rfc8032). The canonical
JSON discipline in [RFC 8785](https://www.ietf.org/rfc/rfc8785.html) is analogous
background only: Shadowpipe does not sign JCS JSON.

Ed25519 is classical. The signed endpoint-policy control plane therefore does
not provide post-quantum signature security, and neither its KATs nor its strict
encoding profile constitute a formal proof or independent cryptographic audit.
The policy signer authorizes endpoint metadata and server-pin sets; it is not an
authenticated producer for causal measurement evidence.

## 2. Signed-authority-bounded endpoint lifecycle

DNS is a liveness signal, not a source of new authorization. A verified policy
creates an immutable IPv4 set for each exact tuple of `locator_name`, `sni`,
port, REALITY public key, short ID and server-pin set. A DNS answer may select a
subset of that set; it cannot introduce a new IP, move an IP between
authentication groups, change SNI or pins, or construct a dial target. Only the
private verified registry can release an immutable REALITY dial target.

A live refresh is a prepared transaction across the model and Linux host state.
For additions, the order is:

```text
firewall allow exact carrier tuple
  -> install exact endpoint /32 bypass route
  -> publish candidate in the dial snapshot
```

For removal, publication is reversed first so no new socket can acquire the
candidate. Existing sockets hold explicit endpoint leases. After the last lease
is released, the exact firewall tuple is denied and the exact route is removed.
Shared tuples/routes use reference counts. A policy-expiry race or model commit
failure compensates the already-applied host prefix before returning an error.

This ordering follows the same consistency objective as prior work on
[consistent network updates](https://www.usenix.org/conference/nsdi15/technical-sessions/presentation/zhou):
intermediate states are security properties, not cleanup trivia. It also treats
route exceptions as an attack surface, consistent with the demonstrated VPN
leak class in [Bypassing Tunnels](https://www.usenix.org/conference/usenixsecurity23/presentation/xue).

### Outage bootstrap without underlay DNS

The configured system resolver is inside the tunnel. Querying it while every
carrier is down would deadlock bootstrap; consulting an underlay resolver would
create a new leak and exfiltration channel. During reconnect backoff the client
therefore performs no DNS query.

After every candidate in the current DNS-selected subset has failed, the client
may once per failure epoch rehydrate the full immutable signed IPv4 authority.
Rehydration is addition-only and uses the same
`allow -> route -> publish` transaction. It preserves leases and tombstones,
cannot accept caller- or DNS-supplied addresses, and is an exact no-op when the
full authority is already live. Once a carrier succeeds, tunneled DNS refresh
resumes and may narrow the set again.

This is an availability fallback inside already authenticated authority. It is
not DNS-censorship circumvention and does not prove that any signed address is
reachable on a hostile path. DNS-specific adaptive selection already exists in
work such as [DPYProxy-DNS](https://www.petsymposium.org/foci/2026/foci-2026-0001.php);
Shadowpipe's bounded rehydration is a narrower host-safety mechanism.

## 3. Durable REALITY replay admission

Production REALITY has no process-local replay-cache fallback. Before listener
bind, the daemon opens and exclusively leases a root-private,
HMAC-authenticated, REALITY-static-key-bound fixed store. The exact data file is
1,572,960 bytes: a 96-byte header plus 16,384 fixed 96-byte slots, with a
separate `0600` lock. The persisted session identifier is a keyed digest rather
than the raw value. Each accepted token stores
`valid_until = token_time + skew_window` with positioned write and
`fdatasync` before the accepted carrier flight is sent.

A complete pre-bind scan rejects static-key mismatch and makes an existing
same-host owner a startup error. Exact replay, a torn/corrupt slot, runtime I/O
failure, saturated state or poisoned admission fails forward to the configured
cover instead of accepting the carrier. Expired-slot cleanup is bounded, so an
admission cannot trigger an unbounded scan/write loop.

This is deliberately not an availability or cross-host replication claim. A
party holding a valid online `short_id` can force sync work and fill all 16,384
slots, causing subsequent valid tokens to fail forward. Replicas that share one
REALITY static key require a strongly consistent shared SETNX+TTL-equivalent
replay authority; otherwise every replica must use a unique static key. The
inner protocol-v3 PSK/Ed25519 device authentication remains mandatory after
carrier admission.

## 4. Anchored write-ahead log and startup recovery

Every Linux TUN session acquires the global host-state lease and runs recovery
before policy loading, DNS, sockets or a new TUN. A new privileged session is
refused unless its owner evidence contains boot ID, PID start ticks, network
namespace identity and mount namespace identity. The WAL exists before the
first privileged mutation.

The journal is bounded and typed. It records planned/applied/removed operations
for the TUN identity, static firewall state, dynamic endpoint firewall tuples,
exact routes and the resolver exchange. Persistence is anchored to a validated
directory descriptor, uses no-follow/open-at style operations, bounded reads,
file and directory `fsync`, and atomic exchange/checkpoint publication. Path
replacement, oversized or malformed state and contradictory history fail
closed.

Host-state wire schema **v3** also records, per address family, whether the nft
`filter` table and its compatibility `OUTPUT` base chain existed before the
session. A single-use install token obtains two stable, complete, read-only
ruleset censuses before the WAL and is consumed only after another stable exact
recheck immediately before the first `-N`. Schema v2 is rejected explicitly:
it has no table/chain origin evidence and therefore cannot authorize exact
restoration. The historical `host-state-v2.json` filename is intentionally
retained so an old privileged journal is detected and rejected rather than
silently ignored by a filename migration.

Startup recovery reconstructs authority only from immutable journal history.
It preflights every resource group before mutation and distinguishes:

- `Operational`: incomplete observation, bounded-tool failure, timeout or other
  retryable inability to prove state; the journal remains retryable;
- `Conflict`: evidenced foreign/reused ownership or contradictory state; the
  journal is marked/refused and firewall protection is retained;
- exact present/absent state: converge only the resources that the journal can
  prove it owns.

The kill switch is released last. Each family's internal rules, exact OUTPUT
jump and private chain are removed by one bounded
`iptables{,6}-restore --noflush` transaction, with the jump last in the batch;
there is no observable partially unhooked family between commands. After that
commit, recovery deletes an nft table only when v3 says it was absent, the boot
is unchanged, and two complete censuses prove the current object is exactly the
empty iptables-nft compatibility shell. If only `OUTPUT` was absent in a
pre-existing foreign table, only an exact empty session-created OUTPUT shell is
deleted. Pre-existing objects and any drift are never deleted. A crash after
either native nft deletion but before WAL acknowledgement is an idempotent
double-absence case on retry. Partial cleanup therefore never authorizes broad
direct traffic merely to restore connectivity.

## 5. TUN ownership is non-destructive

The production Linux client TUN is non-persistent and disappears when the last
exact file descriptor closes. Normal shutdown closes the descriptor and proves
absence before releasing firewall protection. Crash recovery never issues
`RTM_DELLINK` and never deletes an interface merely because a name or ifindex
matches the journal. A surviving, reused or foreign interface is a conflict;
recovery retains the firewall and journal for inspection.

Named Linux TUN creation is atomic. Both client and server open every explicit
named Linux TUN with `IFF_TUN_EXCL`, so an existing name causes startup failure
instead of attaching to or deleting a pre-existing interface. Unnamed client
TUN creation remains kernel-allocated. This removes a name-based stale-device
cleanup authority from both production named-TUN paths.

## 6. Bounded route and firewall tools

Linux route and firewall probes/mutations run under explicit deadlines and
output caps. The parent places each tool in a new process group, drains stdout
and stderr non-blockingly, kills the group on timeout/overflow, kills and reaps
the direct child, and does not infer success from empty stderr. Exact pre/post
state is the success criterion for routes; recovery reports operational failure
when the state cannot be proved.

This bounds ordinary helper and inherited-pipe failure modes. It is not a
sandbox: a deliberately hostile executable may attempt to escape its process
group, so trusted absolute tool paths and OS-level confinement remain deployment
requirements.

## 7. Sealed implementation evidence

### Source-bound Linux full-TUN handoff cell

Run
[`20260716T173837Z-18283-m8K2po`](../tests/tun/results/20260716T173837Z-18283-m8K2po/RESULT.md)
has a tracked compact
[`PUBLISHED-EVIDENCE.md`](../tests/tun/results/20260716T173837Z-18283-m8K2po/PUBLISHED-EVIDENCE.md) and
used a clean `git archive` pinned to
`81f188f772cc6b674fde748a361691f1bda19691`. The source entered an isolated
disposable OrbStack clone through bounded stdin, and the sealed evidence left
through a validated stdout tar; there was no shared checkout, `/mnt/mac`, SSH
agent or working `mac` command channel. Overall, test, cleanup, host-safety,
evidence and clone-cleanup statuses were valid; all 745 checksum entries
verified, the clone was deleted and the source base ended stopped.
The complete 170,055,680-byte sealed bundle remains local/ignored and is not
claimed committed. Its 168,317,113-byte `client-c1-ipv4.pcap` remains local;
the compact tracked index publishes pcap hashes separately.

A real default-route replacement moved the underlay from `c0` to `c1` and
produced the exact `DefaultRouteChanged` cause. Generation 1 exited with status
1 only after strict durable restart lockdown was Active; its invalidated routes,
DNS, bypasses, TUN and main kill-switch were removed, and the main WAL was
absent. Generation 2 then re-observed the host, installed its bypass through
`c1`, reached `Active`, and only then released the intermediate barrier.

A real promiscuous capture toggled `IFF_PROMISC`, but generation-2 PID
`4587`, start ticks `10360288` and topology restart count `2` remained
unchanged. This proves only the structurally exact PROMISC-only observer
exclusion; mixed link changes remain invalidations. Before the final SIGTERM,
the manager-stop gate was present. Generation 2 armed the final strict durable
lockdown and no generation 3 appeared; explicit release later removed both WALs
and the exact table. The harness emulated service-manager restart/stop
semantics and did not run real systemd PID 1.

The authenticated path carried ICMP 20/20, TCP 530,317,312 receiver bytes, UDP
6,251,748 receiver bytes in 5,091 packets with zero loss, tunneled DNS and a
64 MiB transfer with matching SHA-256
`d29e4d088c91b35184c2102d796721c611834bb4e1599acc163797e3d32f8799`.
Carrier-cut recovery had a recorded upper bound of 7 seconds. Directional
client-originated IPv6 pcaps on `c0` and `c1` were empty while the exact
generation-specific SP6 chains counted 21 and 11 dropped packets.

This is a source-bound synthetic IPv4 tunnel plus connected-netns IPv6
OUTPUT-block result. It does not establish a successful current-head tunnel
after `2ece275`, outer or inner IPv6, inbound/L2/FORWARD behavior, native
macOS/Windows VPNs, production operation, censorship resistance or field
availability. The newer lifecycle cells below do not replay this tunnel.

### Source-bound native Linux ARM64 portability cell

Run
[`20260716T180304Z-linux-arm64-current`](../tests/portability/results/20260716T180304Z-linux-arm64-current/RESULT.md)
built and tested clean executable-source commit
`726500f1ff43e2b4fdcf9082abf05aa5a2513ab7` natively in a disposable isolated
Linux ARM64 clone. The no-default matrix passed 718 tests and the all-features
matrix passed 732, each with four ignored tests and zero failures; both strict
Clippy gates, format, metadata, shell syntax and all five partitioned runner
self-tests passed. All 342 checksum entries verified. The frozen snapshot
contained 193 files and 4,464,041 bytes, including 102,293 physical code lines
and 80,315 Rust lines.

This is source-bound unprivileged CPU/filesystem portability only: no route, DNS, firewall,
TUN, netns, qdisc, sysctl or service mutation occurred. Clone cleanup,
Windows-suspended state, host safety and evidence were valid;
`field_evidence=false`. Production Rust changed later in `2ece275`; it does not
establish current-head portability or refresh privileged networking, recovery,
reboot or Windows. The older
[`20260716T122834Z-linux-arm64-current`](../tests/portability/results/20260716T122834Z-linux-arm64-current/RESULT.md)
remains snapshot-bound history for its own 187-file capture.

### Snapshot-bound earlier full-TUN Linux IPv4/netns cell

Run
[`20260716T123535Z-91294-70zWb7`](../tests/tun/results/20260716T123535Z-91294-70zWb7/RESULT.md)
used a disposable OrbStack clone and private namespaces. Production-gated
REALITY plus mandatory protocol-v3 credential/allowlist carried ICMP 20/20,
TCP 561,905,664 receiver bytes at 446.785 Mbit/s, UDP 5,092/5,092 packets with
zero loss, tunneled DNS and a 64 MiB payload whose source/download SHA-256 was
`5ca1b38d0543084e1a1027831af37e3552e47ac34eb42bb8012c26ece4f67510`.
Carrier cut did not open direct fallback and the recorded recovery upper bound
was 8 seconds.

The daemon created and leased the 1,572,960-byte durable REALITY replay data
file before bind, with its separate lock/lifecycle marker, and private cleanup
removed them. A planted persistent empty-alias TUN with the requested client
name forced `EBUSY`/`EEXIST` in 172 ms: zero underlay/carrier packets, no main or
lockdown WAL, no protocol-186 routes or Shadowpipe firewall state, unchanged
resolver, and byte-exact unchanged foreign link/TUN/alias state. This is the
privileged proof that explicit named client TUN creation does not attach to a
foreign device.

Non-carrier underlay, missing-credential, missing-pin and
post-restart-lockdown captures were `0/0/0`; explicit release removed the
lockdown WAL/table. All 573 checksum entries verified. This remains IPv4
synthetic scope for its frozen source. The observed forward-on-fail response is
a bounded synthetic cover oracle, not general active-probe
indistinguishability. The newer source-bound handoff result is the cell above.

### Current product-source same-boot schema-v3 crash/recovery matrix

Run
[`20260716T225901Z-98821`](../tests/host-recovery/results/20260716T225901Z-98821/FINAL-RESULT.md),
with compact
[`PUBLISHED-EVIDENCE.md`](../tests/host-recovery/results/20260716T225901Z-98821/PUBLISHED-EVIDENCE.md),
used clean pushed source `c9b60e7` and passed all 29 fresh net+mount+PID
namespace scenarios. The later `c9b60e7..d335682` diff changes only
reboot/recovery test tooling, not product source. Cuts cover WAL Planned,
every resource-family apply, DNS Staged, partial firewall acknowledgements,
all-Applied/Preparing, Active, and both before mutation plus after convergence
before WAL acknowledgement for each of eight recovery steps. Every `SIGKILL`
cut retained a root-owned schema-v3 WAL with the exact eight-resource
vocabulary and recovery-marker binding; conflict cases retained durable
protection. The matrix result is 28 recovered scenarios plus one intentional
foreign-resource conflict, finalization is complete, and all 1,592 checksum
entries verified.

This is same-boot process-crash evidence. It does not simulate a kernel reboot,
torn filesystem writes or power loss, and its private tmpfs resolver is not a
systemd-resolved integration test.

The `SPPOLEX1` expiry tombstone is covered by adversarial policy-state/component
tests in the product source, not by this privileged namespace matrix. In
particular, the matrix does not upgrade the tombstone into trusted-time or
power-loss evidence.

### Current product-source PID-1 userspace reboot and installed-client cell

Run
[`20260717T001923Z-52605-reboot`](../tests/lockdown/results/20260717T001923Z-52605-reboot/RESULT.md),
with compact
[`PUBLISHED-EVIDENCE.md`](../tests/lockdown/results/20260717T001923Z-52605-reboot/PUBLISHED-EVIDENCE.md),
used clean pushed source `e374075` and verified all 939 checksum entries.
`systemd 261.1` ran as PID 1 before and after an OrbStack userspace machine
restart. Boot ID plus PID/network/mount namespace identities changed; machine
ID and the shared kernel remained stable. Restore completed before networkd.
The exact native nft `inet`/`output` barrier denied non-loopback IPv4 while
allowing loopback; explicit release removed the WAL and only owned `sp_lock`
table and restored gateway reachability.

After release, the exact installed client unit and binary hashes matched their
source. A mandatory credential refusal produced three distinct InvocationIDs
and `NRestarts 0 -> 1 -> 2`; operator stop suppressed further restart for
longer than `RestartSec`. Canonical routes, rules, nft state, resolver,
interfaces, TUN census and WAL absence were identical before and after.

This proves a real systemd PID-1 userspace boot transaction and an installed
client pre-mutation lifecycle. OrbStack retained one shared kernel, and there
was no successful paired tunnel, dedicated-kernel/power-loss reboot, initrd,
continuous packet monitor, L2/AF_PACKET, FORWARD, container-netns, production
or censorship claim.

### Snapshot-bound Windows 11 ARM64 H2 no-TUN cell

Run
[`20260716T125113Z-36840-dd0c2571`](../tests/windows/results/20260716T125113Z-36840-dd0c2571/RESULT.md)
executed a native Windows 11 ARM64 PE built with no default features and strict
warnings. The 5,072,384-byte artifact SHA-256 was
`2734e79f98866910aa8e0386af4ff630191b0a72fd1945177f078cb69d500bad`.
It established two authenticated H2 protocol-v3 sessions, rejected one
unenrolled credential, proved missing-pin pre-socket failure, echoed an exact
nonce and exactly 1,048,576 bytes. Windows route and DNS canonical digests were
identical before/after; the helper contains no TUN/firewall/adapter mutation
command. All 891 checksum entries verified.

This is a private-VM no-TUN portability/authentication cell. It does not prove
Wintun, Windows route/firewall/DNS mutation safety, leak prevention or censor
resistance, and later executable-source changes require a fresh Windows
portability run.

### Host and VM observation limits

In the source-bound handoff run, Mac routes, DNS, static PF files, utun list and exact
live sing-box identity matched at before/after endpoints. This is not a
continuous mutation monitor. Loaded PF runtime was unavailable to the
unprivileged collector and remains explicitly unobserved. OrbStack
start/stop/guest operations used bound opaque IDs; deletion by name occurred
only after a fresh name-to-ID equality check, followed by a late-appearance
window and ID/name absence proof. The dedicated source base was stopped after
the run. Unrelated same-host OrbStack operators remain outside the trust
boundary.

The observer discovers exact-name `sing-box` candidates, records every
candidate argv, selects exactly one protected managed argv and re-proves
PID/start time/argv/executable/config in the same stable process generation.
Substring-only discovery, ambiguity or restart invalidates the host snapshot.
The reason this Linux VM path is safe while a native macOS VPN test is not is
documented in the [host-isolated macOS lab design](mac-host-isolated-lab.md):
Darwin application sandboxing does not create a separate network stack, so
native NetworkExtension validation requires a separate macOS VM or sacrificial
Mac.

## 8. What remains open

- Refresh a successful paired Linux full-TUN session on current source under
  the installed PID-1 units, including carrier cut and post-reboot recovery.
- Refresh native Linux ARM64 and Windows portability after `2ece275`.
- Add resolver-configuration observation, explicit DHCP lease/lifetime
  invalidation and suspend/resume; then implement equivalent native macOS and
  Windows network-change sources.
- Prove IPv6 route/firewall/DNS behavior instead of extrapolating from IPv4.
- Run native Windows Wintun, macOS NetworkExtension/TUN and Android VpnService
  leak/recovery matrices.
- Exercise paired tunnel recovery across a dedicated-kernel reboot and separately
  test torn-write/power-loss durability on an explicitly disposable storage
  target.
- Define authenticated fleet enrollment, root-identity distribution, release
  manifests, rollback operations and independent cryptographic/security review.
- Bind causal measurement evidence to a trusted producer/artifact chain and
  integrate it with traffic-class activation. The current causal replay remains
  offline/shadow-only.
- Obtain separately authorized, preregistered field evidence before making any
  claim about TSPU, GFW, mobile allowlists, active probing or real availability.

The resident Mac and its live sing-box are not a test target. Destructive or
privileged network validation belongs only in disposable guests/netns under the
[VM runbook](lab-vm-runbook.md).
