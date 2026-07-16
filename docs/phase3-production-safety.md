# Phase 3: signed endpoint authority and crash-safe Linux host state

Snapshot: 2026-07-16. This document describes implemented mechanisms and their
security invariants. It is not a production-readiness statement, an independent
audit, or evidence of resistance to a real censor.

## Evidence status

| Layer | Current status | This does not establish |
|---|---|---|
| Signed policy, endpoint coordinator, host journal and recovery adapters | Implemented with adversarial unit/component tests | Cryptographic review, fleet-safe rollout, or a green release pipeline |
| Native Linux ARM64 portability | [`20260716T122834Z-linux-arm64-current`](../tests/portability/results/20260716T122834Z-linux-arm64-current/RESULT.md): scoped PASS, 342/342 checksums, 187/187 frozen-source manifest | Privileged networking, another architecture, production or field behavior |
| Linux full-TUN runtime | [`20260716T123535Z-91294-70zWb7`](../tests/tun/results/20260716T123535Z-91294-70zWb7/RESULT.md): scoped PASS, 573/573 checksum entries | IPv6, native Windows/macOS TUN, production or field behavior |
| Linux same-boot crash recovery | [`20260716T124109Z-93828`](../tests/host-recovery/results/20260716T124109Z-93828/FINAL-RESULT.md): 29/29 scenarios, 1443/1443 checksum entries | Kernel reboot, torn writes or power-loss storage semantics |
| Linux reboot lockdown | [`20260716T124706Z-34564-reboot`](../tests/lockdown/results/20260716T124706Z-34564-reboot/RESULT.md): distinct boot IDs, restore 2,995 us before networkd, 650/650 checksum entries | Paired tunnel recovery, production/initrd/L2/FORWARD behavior |
| Windows 11 ARM64 no-TUN | [`20260716T125113Z-36840-dd0c2571`](../tests/windows/results/20260716T125113Z-36840-dd0c2571/RESULT.md): scoped PASS, 891/891 checksums | Wintun, route/DNS/firewall mutation safety, production or field behavior |
| Censorship resistance | Architecture and research hypotheses only | No current TSPU/GFW/operator result, unblockability, or indistinguishability |
| Platforms | Linux-first host-state implementation | IPv6 completeness, Windows Wintun safety, macOS TUN/route safety, Android VpnService, or mobility behavior |

These are synthetic disposable-guest implementation results with
`field_evidence=false`, not one combined production certification. The full-TUN
cell proves the current IPv4/netns runtime path; the Phase-3 matrix proves
same-boot process-crash recovery; the reboot cell independently proves that an
early-userspace L3 OUTPUT barrier survives a real guest reboot and releases only
on explicit operator action. Linux ARM64 and Windows ARM64 are separate
portability gates; the Windows cell deliberately performs no TUN or Windows
network-state mutation. None of these synthetic results is field-censorship
evidence.

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

### Native Linux ARM64 portability cell

Run
[`20260716T122834Z-linux-arm64-current`](../tests/portability/results/20260716T122834Z-linux-arm64-current/RESULT.md)
built and tested the frozen current source natively in a disposable Linux ARM64
clone. The no-default matrix passed 671 tests and the all-features matrix passed
685, each with three ignored tests and zero failures; both strict Clippy gates,
format, metadata, shell syntax and runner self-test partitions passed. All
342 checksum entries verified. The frozen source manifest contained exactly
187 entries and its SHA-256 was
`fd5ebffc5b820ec8ac037aa3e9fea154c62576d7a276fa923168e5f4b4a84b95`.

This was unprivileged CPU/filesystem portability only: no route, DNS, firewall,
TUN, netns, qdisc, sysctl or service mutation occurred.

### Full-TUN Linux IPv4/netns cell

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
synthetic scope. The observed forward-on-fail response is a bounded synthetic
cover oracle, not general active-probe indistinguishability.

### Same-boot schema-v3 crash/recovery matrix

Run
[`20260716T124109Z-93828`](../tests/host-recovery/results/20260716T124109Z-93828/FINAL-RESULT.md)
passed all 29 fresh net+mount+PID namespace scenarios. Cuts cover WAL Planned,
every resource-family apply, DNS Staged, partial firewall acknowledgements,
all-Applied/Preparing, Active, and both before mutation plus after convergence
before WAL acknowledgement for each of eight recovery steps. Every `SIGKILL`
cut retained a root-owned schema-v3 WAL with the exact eight-resource
vocabulary and recovery-marker binding; conflict cases retained durable
protection. The matrix result is 28 recovered scenarios plus one intentional
foreign-resource conflict, finalization is complete, and all 1443 checksum
entries verified.

This is same-boot process-crash evidence. It does not simulate a kernel reboot,
torn filesystem writes or power loss, and its private tmpfs resolver is not a
systemd-resolved integration test.

The `SPPOLEX1` expiry tombstone is covered by adversarial policy-state/component
tests in the same current source, not by this privileged namespace matrix. In
particular, the matrix does not upgrade the tombstone into trusted-time or
power-loss evidence.

### Reboot lockdown cell

Run
[`20260716T124706Z-34564-reboot`](../tests/lockdown/results/20260716T124706Z-34564-reboot/RESULT.md)
recorded distinct pre/post boot IDs, strict WAL/PID-1 namespace binding and
restore completion before networkd activation. The exact native nft inet/output
barrier denied non-loopback IPv4 while allowing loopback; explicit release
removed the WAL and only owned `sp_lock` table and restored gateway reachability.
Monotonic unit timestamps put restore completion exactly 2,995 microseconds
before networkd start. All 650 checksum entries verified.

This cell proves early-userspace Linux L3 local OUTPUT lockdown only. It has no
paired client/server tunnel and makes no production, initrd, L2/AF_PACKET,
FORWARD, container-netns or censorship claim.

### Windows 11 ARM64 H2 no-TUN cell

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
resistance.

### Host and VM observation limits

Mac routes, DNS, static PF files and exact live sing-box identity matched at
before/after endpoints. This is not a continuous mutation monitor. Loaded PF
runtime was unavailable to the unprivileged collector and remains explicitly
unobserved. OrbStack start/stop/guest operations used bound opaque IDs; because
OrbStack 2.2.1 panicked on delete-by-ID in an observed lab run, deletion used
the name only after a fresh name-to-ID equality check, followed by a late
appearance window and ID/name absence proof. Unrelated same-host OrbStack
operators remain outside the trust boundary.

The observer discovers exact-name `sing-box` candidates, records every
candidate argv, selects exactly one protected managed argv and re-proves
PID/start time/argv/executable/config in the same stable process generation.
Substring-only discovery, ambiguity or restart invalidates the host snapshot.

## 8. What remains open

- Prove IPv6 route/firewall/DNS behavior instead of extrapolating from IPv4.
- Run native Windows Wintun, macOS NetworkExtension/TUN and Android VpnService
  leak/recovery matrices.
- Exercise paired tunnel recovery across a real kernel reboot and separately
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
