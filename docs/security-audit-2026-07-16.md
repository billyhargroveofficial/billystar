# Scoped security and current-source validation audit — 2026-07-16

Status: two separate executable-source Linux cells are current. Commit
`81f188f772cc6b674fde748a361691f1bda19691` has the privileged full-TUN
handoff **PASS**, scoped to an isolated disposable OrbStack clone and private
namespaces. Clean commit
`726500f1ff43e2b4fdcf9082abf05aa5a2513ab7` has the unprivileged native ARM64
CPU/filesystem portability **PASS**. Later edits to this audit are documentation
drift, not evidence that either tested executable baseline changed. Earlier
bundles remain valid captured-source snapshots for their own frozen commits;
they are not substitutes for either current cell. This is engineering evidence,
not an independent cryptographic audit, production certification, formal proof,
field-censorship result, or claim that Shadowpipe is unblockable or
indistinguishable.

This document supersedes the implementation-status conclusions in the
historical [2026-07-15 dependency and key-storage audit](security-audit-2026-07-15.md).
Older result bundles remain useful diagnostics and scoped historical evidence,
but only
[`20260716T173837Z-18283-m8K2po`](../tests/tun/results/20260716T173837Z-18283-m8K2po/RESULT.md)
supports a privileged current executable-source Linux full-TUN statement, while
[`20260716T180304Z-linux-arm64-current`](../tests/portability/results/20260716T180304Z-linux-arm64-current/RESULT.md)
supports a separate unprivileged current executable-source ARM64 portability
statement.

## Executive verdict

The current commit has credible scoped laboratory evidence for:

- an authenticated Linux IPv4 OS-TUN path over production-gated REALITY;
- fail-closed rejection of a foreign pre-existing named TUN;
- exact `c0 -> c1` default-route replacement causing process replacement:
  generation 1 exits nonzero under strict durable lockdown and generation 2
  reaches `Active` through `c1`;
- ignoring a PROMISC-only link notification while a real promiscuous observer
  leaves the active client PID/start time unchanged;
- connected IPv6 fail-closed egress blocking, with empty directional pcaps and
  positive `SP6` DROP counters, without claiming an IPv6 tunnel;
- manager-gated final shutdown with no generation 3, continued IPv4/IPv6
  lockdown and explicit release;
- ICMP/TCP/UDP/DNS, a verified 64 MiB transfer and carrier-cut recovery within
  a seven-second upper bound;
- native Linux ARM64 compilation/test portability of clean commit `726500f`,
  including both feature profiles, strict Clippy and all runner self-tests.

Captured snapshots additionally retain the older `122834` ARM64 run, a
same-boot eight-resource crash matrix, an early-userspace reboot lockdown cell,
an earlier full-TUN run and Windows 11 ARM64 H2/no-TUN behavior. They are not
validation of either current executable-source cell.

It does **not** yet have evidence for:

- native Windows Wintun, macOS Network Extension/TUN, Android VpnService, or
  complete IPv6 behavior;
- the tested handoff path under a real systemd PID 1 service manager, resolver
  or DHCP changes, or suspend/resume;
- paired tunnel recovery across reboot, filesystem/power-loss recovery, hostile
  same-UID/root races, or distributed replay consistency;
- fleet enrollment, offline-root ceremony, threshold authorization, staged
  production rollout, or rollback drills;
- formal verification, independent review, or resistance to any real censor.

The resident Mac was only an unprivileged observer, source/evidence stream
coordinator and VM orchestrator. Its live sing-box was not stopped, restarted,
signalled, reloaded, reconfigured or bypassed. A macOS sandbox is not treated as
a separate network stack; native macOS work remains assigned to the separate
[host-isolated macOS lab design](mac-host-isolated-lab.md).

## Evidence set and source drift

The current privileged bundle pinned an exact clean `git archive` of
`81f188f772cc6b674fde748a361691f1bda19691`, transferred it into the isolated
guest through bounded stdin, built and ran from guest-local storage, and
returned a validated sealed archive through bounded stdout. It contains 745
checksum entries and records valid host safety, clone cleanup, evidence sealing,
source isolation and private-material scans.

The current portability bundle captured clean commit
`726500f1ff43e2b4fdcf9082abf05aa5a2513ab7` into a 193-file,
4,464,041-byte frozen snapshot and verified 342 checksum entries. It counted
102,293 physical code lines, including 80,315 Rust lines. The no-default and
all-features matrices passed 718 and 732 tests respectively, with zero failures
and four ignored in each; both strict Clippy profiles and all five partitioned
runner self-tests were valid. Clone cleanup, Windows-suspended state, host
safety and evidence were valid. It made no privileged network mutation and has
`field_evidence=false`.

The older Linux ARM64 snapshot froze 187 files with manifest SHA-256
`fd5ebffc5b820ec8ac037aa3e9fea154c62576d7a276fa923168e5f4b4a84b95`.
It and the other pre-`81f188f` bundles remain evidence for the exact source they
captured. Subsequent executable network-change and runner changes mean they
must not be cited as validation of the current executable source, even when
their individual captured results remain internally valid.

| Evidence bundle | Source relation | Scope established | Explicit non-claim |
|---|---|---|---|
| [Linux full-TUN `20260716T173837Z-18283-m8K2po`](../tests/tun/results/20260716T173837Z-18283-m8K2po/RESULT.md) | **Current executable source `81f188f`; PASS; 745 checksum entries** | Isolated disposable Linux/private-netns IPv4 TUN; REALITY/v3 auth; exact default-route handoff and process replacement; PROMISC regression; connected-IPv6 OUTPUT blocking; manager-stop/no-generation-3; ICMP/TCP/UDP/DNS/64 MiB/cut recovery; host/source/secret/cleanup safety | No real systemd PID 1, resolver/DHCP/suspend event, IPv6 tunnel, native macOS/Windows, production, field or censorship result |
| [Linux ARM64 `20260716T180304Z-linux-arm64-current`](../tests/portability/results/20260716T180304Z-linux-arm64-current/RESULT.md) | **Current executable source `726500f`; PASS; 342 checksum entries; 193 files** | Native ARM64 CPU/filesystem portability; tests 718/0/4 and 732/0/4; strict Clippy; format/metadata/shell; all five runner self-tests; cleanup/host safety | No privileged route, DNS, firewall, TUN, namespace, service, recovery, reboot, Windows, production or field behavior |
| [Historical Linux ARM64 `20260716T122834Z-linux-arm64-current`](../tests/portability/results/20260716T122834Z-linux-arm64-current/RESULT.md) | Captured snapshot; `PASS`; 342/342 checksum entries | Native ARM64 CPU/filesystem portability, format, metadata and frozen test/Clippy matrices for its old source | Not current executable source; no privileged route, DNS, firewall, TUN, namespace, service or field behavior |
| [Earlier full-TUN `20260716T123535Z-91294-70zWb7`](../tests/tun/results/20260716T123535Z-91294-70zWb7/RESULT.md) | Captured snapshot; `PASS`; 573/573 checksum entries | Earlier disposable Linux IPv4/private-netns TUN, carrier cut/reconnect, explicit lockdown release and foreign named-TUN collision | Not current executable source; no network-change process-replacement proof |
| [Phase 3 `20260716T124109Z-93828`](../tests/host-recovery/results/20260716T124109Z-93828/FINAL-RESULT.md) | Captured snapshot; `PASS`; 1,443/1,443 checksum entries | Same-boot `SIGKILL` cuts across schema-v3 eight-resource apply and recovery boundaries | Not current executable source; no real reboot, power-loss or current handoff proof |
| [Reboot lockdown `20260716T124706Z-34564-reboot`](../tests/lockdown/results/20260716T124706Z-34564-reboot/RESULT.md) | Captured snapshot; `PASS`; 650/650 checksum entries | Early-userspace local Linux L3 OUTPUT barrier across one guest reboot | Not current executable source; no paired tunnel or current handoff proof |
| [Windows ARM64 `20260716T125113Z-36840-dd0c2571`](../tests/windows/results/20260716T125113Z-36840-dd0c2571/RESULT.md) | Captured snapshot; `PASS`; 891/891 checksum entries | Native Windows 11 ARM64 H2/no-TUN authentication and exact 1 MiB echo | Not current executable source; no Wintun, route/firewall/adapter mutation or leak proof |

The manifests are relative SHA-256 evidence inventories. They are not externally
signed, independently timestamped or laboratory-attested.

## Current portability and captured dependency gates

The clean `726500f` native ARM64 snapshot passed the following current
portability gate classes:

```text
cargo fmt --all -- --check
cargo test --workspace --no-default-features --all-targets --locked
cargo test --workspace --all-features --all-targets --locked
cargo clippy --workspace --all-targets --no-default-features --locked -- -D warnings
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
all non-result shell scripts: bash -n and ShellCheck 0.11.0
all five VM/Windows runners: --self-test
```

That current snapshot records 718 passed tests in the no-default profile and
732 in the all-features profile, with 0 failed and 4 ignored in each. The
historical `122834` ARM64 snapshot recorded 671 and 685 passed tests, with
0 failed and 3 ignored in each. A separate local release-suite run after the
security fixes registered 709 tests and passed. These counts describe different
source snapshots or harness aggregations and must not be added together.

The separately captured dependency gate used cargo-audit 0.22.2, scanned 276 locked
packages against a fetched RustSec database containing 1,160 advisories, and
returned success under `-D warnings`. This is a known-advisory, yanked-package
and unmaintained dependency check. It is not source review, provenance
verification, reproducible-build attestation or evidence against undisclosed
vulnerabilities.

`scripts/test-live-services.sh` was deliberately not run because it can start or
reuse a remote privileged tunnel and is not a read-only local regression gate.

## Component security invariants

### 1. Mandatory authenticated inner protocol

Protocol v3 has no anonymous mode. A fixed-width mutual PSK access exchange is
performed before ML-KEM publication/work is authorized. The accepted inner
session then combines ML-KEM-768 with ephemeral X25519, derives transcript-bound
keys, exchanges encrypted Ed25519+PSK Finished messages and protects
application frames with ChaCha20-Poly1305.

The design is informed by the separation and transcript-binding principles in
[TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446), and ML-KEM is the standardized
primitive in [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
Shadowpipe v3 is nevertheless a custom protocol: it is not TLS, Noise or HPKE,
and inherits no proof or conformance claim from them.

Every current client mode requires an independently distributed 32-byte server
ML-KEM fingerprint. Missing or malformed pins fail before reservation trace,
DNS, socket or TUN creation. Fingerprint mismatch fails before ML-KEM
encapsulation and application bytes.

### 2. Signed endpoint and pin authority

Endpoint authority is a closed chain:

```text
independently enrolled offline Ed25519 root
  -> root-signed keyset schema v1
    -> Active online Ed25519 signer
      -> strict COSE_Sign1 endpoint-policy schema v2
```

The profile uses deterministic CBOR, strict protected headers and canonical
re-encoding checks, following the data formats standardized by
[RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) and
[RFC 9052](https://www.rfc-editor.org/rfc/rfc9052). It is a deliberately
restricted custom profile, not full TUF conformance.

Enforced invariants include:

- rollback, fork, freeze, gap, expiry and unsupported-version rejection;
- the exact sorted `service_id` set is immutable after genesis; additions,
  removals and renames require a new authenticated enrollment/schema event;
- a candidate endpoint policy must be signed by an `Active` online key, never
  a `Retiring` or `Revoked` key;
- pin additions and `Active -> Retiring` transitions require the policy, key
  and pin to remain usable through the complete minimum overlap;
- a successor keyset counts only keys that remain usable for the full overlap;
- revoked online keys may be removed by a later contiguous keyset, avoiding an
  artificial permanent exhaustion of the bounded key list.

The overlap rule protects rollout continuity, not compromise containment. A
compromised `Active` online signer can still authorize an attacker-controlled
pin alongside the old pin. Containing that threat requires a separate
offline-root or threshold-authorized service registry that binds service IDs,
pins, identities and lifetimes.

Ed25519 is classical. The current control plane is therefore not
post-quantum-authenticated.

### 3. Policy expiry resurrection barrier

On observed orderly expiry, the client durably checkpoints a separate fixed
132-byte `SPPOLEX1` tombstone at `<policy-state>.expired-v1`. It binds the
enrolled root ID, exact policy hash, epoch, sequence and signed expiration time,
plus an integrity checksum. The checkpoint reloads the exact current anchor
under lock before writing, so a stale runtime cannot tombstone a genuine
successor.

Loading, enrollment and update reject the same tombstoned policy hash even if
the wall clock is rolled backward. A different correctly signed successor hash
remains possible. Corrupt, unsafe, wrong-root or replacement tombstones fail
closed.

This is not trusted time. A crash before the expiry checkpoint, power loss
before durable storage completion, whole-storage rollback or boot into an
untrusted earlier clock remains outside the claim.

### 4. Live DNS and endpoint transactions

DNS may only select a subset of signed IPv4 endpoint authority; it cannot add a
new address. Each addition converges in the order:

```text
firewall allow tuple -> exact /32 bypass route -> publish dial snapshot
```

Retirement depublishes first, waits for the last socket lease, then removes
firewall and route authority. Policy expiry is rechecked after synchronous host
work and immediately before publication. During carrier backoff the client
does not use underlay DNS; a bounded failure epoch may restore only the already
signed full address set.

This establishes an implementation ordering invariant, not DNS availability,
resolver integrity, IPv6 completeness or censor resistance.

### 5. Crash-safe Linux host-state journal

The anchored schema-v3 WAL records intent before mutation and exact
postcondition acknowledgement afterward for eight resource families:

1. non-persistent TUN identity;
2. low split-default route;
3. high split-default route;
4. exact persistent-underlay endpoint bypass route;
5. IPv4 static firewall state;
6. dynamic endpoint firewall state;
7. IPv6 firewall state;
8. resolver rename exchange.

Startup recovery occurs after singleton lease acquisition but before signed
policy acceptance, DNS, trace reservation, socket or TUN creation. A complete
read-only census precedes every recovery plan. Unknown, duplicated, modified,
reused or foreign resources produce durable conflict and suppress mutation.
Transient operational failures retain retryable state.

Production TUNs are non-persistent. Explicitly named Linux client and server
TUN creation uses exclusive kernel creation semantics. Recovery never issues a
link-delete request by name or ifindex; a present or reused interface is a
conflict while fail-closed protection remains.

The full-TUN negative cell planted a persistent foreign `sptunc` with distinctive
MTU/address state. Client startup failed on exclusive creation, the foreign
interface remained byte-for-byte equivalent under the runner's censuses, no
protocol-186 route or Shadowpipe firewall state appeared, no main/lockdown WAL
was created, and the underlay capture remained empty.

Route subprocesses and firewall helpers have deadlines, output bounds,
process-group termination and mandatory reap. The journal and lease use pinned
directory descriptors, no-follow opens, exact inode checks and no-clobber
replacement patterns.

Residual races remain:

- route recovery observes ifindex ownership and later executes a name-addressed
  `ip route del`, leaving a narrow TOCTOU if another `CAP_NET_ADMIN` writer is
  active;
- nft cleanup assumes one exclusive privileged Shadowpipe writer for its owned
  table between census and name-addressed deletion;
- Linux lacks a general conditional unlink-by-inode primitive for every final
  pathname operation;
- the same-boot crash matrix does not prove different-boot recovery of the main
  active-tunnel WAL or power-loss storage semantics.

### 6. Durable REALITY replay admission

Production REALITY no longer relies on process-local replay memory. Before
binding, it takes an exclusive lease and scans an HMAC-authenticated,
static-key-bound fixed file:

```text
96-byte header + 16,384 x 96-byte slots = 1,572,960 bytes
```

The stored session identifier is a keyed digest derived from the REALITY static
secret, not the raw identifier. Expiry is absolute
`valid_until = token_time + replay_window`, including future-skew handling.
Admission writes the selected slot positionally and synchronizes data before
the accepted flight is emitted.

Exact replay, corrupt/torn slots, runtime I/O failure, lock poisoning and store
saturation fail forward to cover behavior rather than accepting a Shadowpipe
session. A static-key/header mismatch aborts startup.

This is same-host state. Replicas sharing one REALITY static key need a strongly
consistent shared replay primitive; otherwise each replica must use a unique
static key. A holder of a valid online short ID can still cause sync work and
bounded-store saturation, so availability under authenticated abuse is an
explicit residual risk.

### 7. Reboot lockdown

The reboot cell validated a native nft local-OUTPUT barrier that was restored
in early userspace before networkd. The systemd unit declares ordering against
network-pre and network-management services; the measured run used unique
InvocationIDs, zero restarts and monotonic timestamps.

The relevant service-order semantics are specified by
[systemd.unit](https://www.freedesktop.org/software/systemd/man/devel/systemd.unit.html),
[systemd.service](https://www.freedesktop.org/software/systemd/man/devel/systemd.service.html)
and the
[systemd D-Bus interface](https://www.freedesktop.org/software/systemd/man/devel/org.freedesktop.systemd1.html).
This evidence covers the tested unit, guest and local L3 OUTPUT plane only.

Temporary lockdown-file cleanup now verifies the directory entry's device and
inode against the still-open file before unlinking. Dropping a pending writer
therefore does not delete an attacker-replaced inode under the same pathname.

## Trust boundaries

### Resident Mac

The final observation bound the live process to one stable PID/start/argv,
configuration-file hash and executable hash. Exact workstation paths, process
identifiers and hashes are retained only in the local sealed evidence and are
intentionally omitted from the public source repository.

Before/after snapshots compared stable routes, DNS, static PF configuration
files and the exact managed sing-box argv/config/executable identity. These are
bounded endpoint snapshots, not a continuous host monitor.

Loaded macOS PF runtime rules were not observable without privilege.
`pf_runtime_observed=false` is therefore part of every applicable verdict; no
claim is made about continuous loaded-runtime equality.

The observer originally used broad process matching and included unrelated
commands whose argv happened to contain `sing-box`. It now starts from
`pgrep -x sing-box`, captures each candidate's full argv and accepts only the
single exact managed command. This removed an observer false positive without
weakening the no-touch rule.

### VM lifecycle

The shared lifecycle lock serializes Shadowpipe runners. The current full-TUN
runner clones a dedicated stopped source base whose configuration is required
to be both VM-isolated and network-isolated, with no mounted Mac filesystem,
forwarded ports or SSH agent. The first guest action installs and re-proves an
ownership marker. Pinned source enters only through bounded stdin; validated
sealed evidence exits only through bounded stdout. Start, stop and guest
commands use a strictly parsed bound opaque clone ID. Deletion by name is
permitted only after an immediate name-to-bound-ID equality check and then a
name-and-ID absence proof.

An unrelated same-host OrbStack lifecycle operator remains outside the harness
trust boundary. The dedicated source base finished stopped. The current Linux
run made no statement about Windows VM state.

### Filesystem and operator

Root-owned `0700` state directories, `0600` single-link files, no-follow opens,
pinned directory descriptors and singleton locks treat root and the same
effective UID as trusted. They do not defend against a malicious kernel,
arbitrary root, storage rollback or concurrent privileged mutation deliberately
outside the singleton discipline.

## Bugs found and fixed during the final audit

The final PASS set was reached by preserving failed diagnostics and correcting
their causes:

1. **Foreign named-TUN attachment.** An explicit client `--tun-name` could use
   non-exclusive open semantics and attach to an existing persistent TUN. The
   client now requests exclusive named creation; unnamed kernel allocation
   remains supported. A pre-mutation abort removes an otherwise empty
   Preparing journal.
2. **Service-ID continuity bypass.** Policy evolution could alter service IDs
   without a new root enrollment. The exact sorted service set is now frozen
   after genesis.
3. **Insufficient overlap lifetime.** Rotation checks counted keys/pins that
   existed at transition time but expired before the minimum overlap ended.
   Full remaining lifetime is now required.
4. **Retiring signer acceptance.** A retiring online key could sign a new
   endpoint policy. Only `Active` signers are now accepted.
5. **Process-local REALITY replay state.** Restart could forget accepted
   handshakes, and future-skew expiry used the wrong reference. Admission now
   commits to the durable static-key-bound store with absolute validity before
   acceptance.
6. **Expired-policy resurrection.** Rolling the wall clock backward could make
   the same previously observed expired policy appear valid. The fixed
   tombstone blocks that exact hash.
7. **Lockdown temporary-file replacement.** Drop cleanup could unlink a
   replacement inode at the same pathname. It now unlinks only after exact
   open-file/directory-entry identity proof.
8. **Harness private-material scan.** Structured secret files and derived
   representations were not classified precisely enough. The scanner now
   extracts secret-bearing fields, checks raw/hex/base64 variants, uses
   non-reversible fingerprints for host-added logs, and validates evidence
   files against symlink/hardlink/change races.
9. **GNU empty-file `stat` wording.** `%F` reports `regular empty file`, so a
   string comparison incorrectly rejected a safe zero-byte lock. Validation is
   now numeric over type, mode, UID, GID, link count and size.
10. **Broad sing-box observer.** Broad process matching captured harness
    commands containing the string. Exact executable-name plus argv validation
    now identifies only the managed process.
11. **Windows replay-store cfg error.** Unix-only replay imports and positional
    write helper placement caused the Windows ARM64 strict build to fail. The
    implementation is now correctly target-gated and the native PE gate passes.

## Retained failed diagnostic bundles

Failures are not rewritten as passes. Important final-cycle diagnostics include:

| Bundle | Honest result | What it found |
|---|---|---|
| `20260716T095859Z-linux-arm64-current` | `failed` | Attempted source transfer into an OrbStack read-only path; cleanup and Mac safety still valid |
| `20260716T100426Z-linux-arm64-current` | `failed` | Guest package assumption incorrectly required unavailable `shellcheck` |
| `20260716T101043Z-linux-arm64-current` | `failed` | Cargo/Clippy passed, but runner self-test partition incorrectly tried macOS-only Windows tooling in the Linux guest |
| `20260716T102639Z-82478-l0Q1TO` | `failed` | The foreign-TUN security rejection worked, but the runner misclassified a safe empty singleton lock and therefore failed closed |
| `20260716T111737Z-29490` | `failed` | Broad sing-box observation included unrelated harness processes, invalidating host-safety classification |
| `20260716T121205Z-64081-0930a9ff` | `failed` | Windows ARM64 strict compilation exposed Unix-only replay-store cfg/import placement |

Earlier development failures also remain under the result directories. They are
diagnostics, not members of the final evidence set.

## Remaining production and research gates

- Complete IPv6 full-TUN route/firewall/DNS/leak/recovery coverage.
- Native Windows Wintun and macOS Network Extension/TUN matrices; Android
  VpnService implementation and mobile bootstrap/leak audit.
- Current executable-source validation under a real systemd PID 1 manager, plus
  resolver, DHCP and suspend/resume network-change matrices.
- Paired client/server recovery across reboot, plus torn-write, fsync-order,
  power-loss and whole-storage rollback experiments on disposable media.
- Threshold/offline-root service authorization that contains compromise of one
  online policy signer.
- Trusted-time or rollback-resistant monotonic authority for expiry decisions.
- Strongly consistent multi-replica replay state or enforced unique REALITY
  identity per replica.
- Concurrency hardening against other privileged route/nft writers.
- Authenticated release manifests, reproducible builds, fleet enrollment,
  staged rollout and revocation/rollback exercises.
- Formal protocol analysis and independent cryptographic/security review.
- Preregistered, explicitly authorized field experiments before any TSPU, GFW,
  operator-availability, active-probe indistinguishability or censorship claim.

The authoritative claim classification remains in the
[claims ledger](claims-ledger.md), and implementation ordering remains in
[Phase 3 production safety](phase3-production-safety.md).
