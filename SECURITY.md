# Security policy and research boundaries

ShadowPipe/ZATMENIE is an experimental censorship-measurement and encrypted
transport codebase. It is not an anonymity network, has not received an
independent security audit, and makes no claim of being unblockable.

## Non-negotiable deployment gates

- A production daemon requires REALITY. Raw/H2/TLS/QUIC expose a distinguishable
  ShadowPipe bootstrap/challenge to active probes and are allowed only with the
  explicit `--allow-insecure-lab-carriers --development-user-allowlist` no-TUN
  gate. The inner mutual PSK gate withholds ML-KEM bytes and KEM work; it does
  not provide genuine-service probe cover.
- Production REALITY requires 1..16 strictly sorted unique full-width 64-bit
  `short_id` carrier tokens in `--reality-short-id-file` (default
  `/etc/shadowpipe/reality-short-ids`). The file is opened no-follow, bounded,
  root-owned, single-link and exact mode `0600` below trusted root-owned
  directories. Inline tokens are development no-TUN only. A normal daemon never
  prints a token-bearing URI; only explicit `--print-uri` may do so. These online
  tokens are carrier admission, not client identity authentication.
- Every release client/server artifact pair must be built with the same explicit
  `SHADOWPIPE_MAGIC`. Release builds without it fail closed; random debug/test
  magic is not a deployable interoperability contract.
- Every current client mode, including isolated lab modes, requires a pinned
  server ML-KEM fingerprint; there is no unpinned exception. Lab scope changes
  evidence classification, not authentication.
- Long-term secrets, subscription URIs, real endpoint addresses, packet
  payloads, and unredacted error strings must not enter committed manifests or
  exported telemetry.
- Causal measurement/control outputs remain advisory (`shadow` mode). The
  separate Phase-3 endpoint path now enforces signed policy, bounded endpoint
  transactions and crash recovery, but it is not yet an evidence-authenticated
  causal activation layer and has no field authorization.
- A failed carrier must never silently fall back to direct traffic for a class
  marked tunnel-only. Direct fallback is allowed only for an explicitly
  declared direct-safe traffic class.
- VM/netns success is synthetic evidence. It must not be relabeled as an
  operator, TSPU, allowlist, or field result.

## Cryptographic boundary

The intended inner session uses hybrid ML-KEM/X25519 key establishment and a
mutual pre-key per-device PSK gate, Ed25519+PSK Finished authentication, and a
classical AEAD data channel with transcript binding. The client emits no access
proof until the server proves PSK possession; the server emits no static ML-KEM
key or performs KEM work until the client access MAC verifies. Post-quantum key
establishment does not make endpoint software, policy distribution, metadata,
traffic shape, or the AEAD itself post-quantum-proof. Carrier TLS/REALITY is an
outer transport/authentication surface; it does not replace the inner server
pin.

New custom cryptographic primitives or unauthenticated padding/framing schemes
are out of scope. Changes to transcript construction, key derivation, nonce
allocation, replay handling, or fingerprints require dedicated test vectors and
independent review.

## REALITY replay boundary

Production REALITY admission opens and exclusively leases an
HMAC-authenticated, REALITY-static-key-bound fixed store before listener bind.
The store has 16,384 fixed slots and an exact 1,572,960-byte data file plus a
separate lock; keyed session-ID digests and absolute
`valid_until = token_time + window` are committed and `fdatasync`ed before an
accepted carrier flight. Replay, corruption, torn slot, saturation, lock poison
and runtime I/O fail forward to cover rather than accept.

This is a same-host restart/concurrency guarantee, not an availability or fleet
guarantee. A holder of a valid online `short_id` can force sync work and saturate
the bounded store. Replicas sharing one REALITY static key need a strongly
consistent shared SETNX+TTL-equivalent replay authority; otherwise each replica
must use a unique static key. Inner PSK/Ed25519 authentication remains mandatory
even after carrier admission.

## Signed endpoint-policy boundary

The enrolled offline root authorizes a root-signed keyset v1; an authorized
online Ed25519 key signs endpoint-policy v2. The wire profile is strict
`COSE_Sign1` over deterministic CBOR. The verifier fixes algorithm, protected
content type, key identifier and schema; rejects non-canonical, unknown,
rollback, fork, gap and expired state; and durably maintains independent keyset
and policy floors. Rotation requires explicit predecessor state and overlap.
This is a project-specific profile informed by
[RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052),
[RFC 8032](https://www.rfc-editor.org/info/rfc8032) and
[TUF](https://theupdateframework.github.io/specification/latest/); it is not a
claim of full TUF conformance or independent cryptographic review. Ed25519 is a
classical signature scheme: the endpoint-policy control plane is not
post-quantum authenticated. Its enrolled root and online signer authorize
endpoint metadata and pins; they are not an authenticated evidence producer for
the offline causal selector.

Endpoint-policy v1 is unsupported and rejected without fallback. Version 2
requires separate canonical `locator_name` and REALITY `sni` values. DNS may
only select IPv4 addresses already present in the signed authority; it cannot
mint an address or authentication tuple. Invalid, expired or unverified policy
must not broaden direct reachability.

After the first authenticated enrollment, every successor policy must preserve
the exact sorted `service_id` set. Adding, removing or renaming a service
authority requires a new authenticated enrollment/schema event; it cannot be
used to bypass per-service pin rotation. A candidate policy must be signed by a
currently `Active` online key; `Retiring` and `Revoked` keys verify historical
state only. New pins/keys and `Active -> Retiring` transitions must remain
usable through the complete 86,400-second overlap, including enclosing
policy/keyset expiry.

This overlap is rollout-continuity protection, not compromised-online-signer
containment. A compromised `Active` signer can still add an attacker-controlled
pin alongside the old pin. Preventing that requires a separate
offline-root/threshold-authorized service registry or equivalent binding; the
current policy-v2 design does not claim it.

On orderly expiry the client writes the separate fixed 132-byte `SPPOLEX1`
`*.expired-v1` tombstone before sealing host state fail closed. It binds the
offline-root identity, exact policy hash, epoch/sequence and signed
`expires_at`, so the same policy cannot be reloaded after a wall-clock rollback.
It is not trusted time: crash/power loss before fsync, storage rollback, and a
different boot whose clock rolls back before any orderly checkpoint remain
outside the guarantee.

During a carrier outage the client does not consult underlay DNS. After the
current DNS-selected subset is exhausted, it may transactionally restore the
full immutable signed authority once per failure epoch. This is a liveness
fallback inside existing authorization, not permission to use arbitrary DNS
answers and not evidence that an address evades censorship.

## Measurement privacy

The committed measurement schema is closed and numeric/enum oriented. Public
IDs must be random or keyed, domain-separated pseudonyms; never hashes of raw
IPs, hostnames, credentials, or configuration blobs. Export timestamps should
be quantized to the minimum resolution required by the experiment. Raw local
diagnostics stay outside evidence bundles and are deleted or redacted after
aggregation.

An evidence producer is not trusted merely because it emits `supported`.
Consumers must validate schema semantics and derive health/statistics from the
events and preregistered window/block structure.

The offline replay envelope is not an authenticity boundary. Evidence scope,
timestamps/current time, carrier grouping/capabilities, failure domains, and
expected window references remain caller declarations; run-ID deduplication is
not producer or artifact provenance. A replay verdict is meaningful only after
binding those declarations to a trusted signed manifest and authenticated
producer/artifact identity. Until that exists, the result remains shadow-only.
For workload admission, direction-matched observed `Transfer` deltas are proof;
aggregate `Close` byte totals are only a consistency ceiling because filtered
traces may legitimately omit deltas.

## Linux host-state boundary

Every Linux TUN session takes the host-state lease and attempts startup recovery
before policy loading, DNS, sockets or a new TUN. A bounded, anchored WAL records
intent before privileged TUN, route, firewall or resolver mutation. Recovery
accepts only exact journal-derived identities and preflights all resource groups
before converging them. An operational inability to observe state leaves the
journal retryable; evidenced reuse or foreign ownership is a conflict and keeps
the kill switch in place.

Endpoint additions are ordered `allow exact tuple -> exact /32 bypass route ->
publish`. Retirement first prevents new leases, waits for existing socket
leases, then denies the tuple and removes the exact route. Partial transaction
failure must compensate the applied prefix rather than publish an incoherent
snapshot.

Production Linux TUNs are non-persistent. Recovery never issues `RTM_DELLINK`
and never deletes an interface based only on a name or ifindex. A present
interface after owner death is a conflict. Both client and server request
`IFF_TUN_EXCL` for explicit named Linux TUN creation and fail atomically on
collision; unnamed client TUN creation remains kernel-allocated. Route/firewall
helpers have bounded deadlines/output and are killed/reaped as process groups
on timeout; they are still trusted executables, not sandboxed adversarial code.

The privileged Phase-3 crash matrix is recorded as a scoped captured-source
Linux **PASS** in
[`20260716T124109Z-93828`](tests/host-recovery/results/20260716T124109Z-93828/FINAL-RESULT.md):
29/29 fresh-namespace scenarios (28 recovered plus one intentional conflict),
complete evidence finalization and 1443/1443 checksum entries. It proves
same-boot `SIGKILL` recovery boundaries for the schema-v3 eight-resource WAL;
it does not test a kernel reboot, torn filesystem writes or power-loss storage
semantics. A separate early-userspace
[`reboot-lockdown`](tests/lockdown/results/20260716T124706Z-34564-reboot/RESULT.md)
cell changed boot IDs and proved the exact Linux L3 OUTPUT barrier restored
2,995 microseconds before networkd start, loopback allowance, non-loopback
denial and explicit release; 650/650 checksums verified. That cell has no paired
client/server tunnel and is not a production claim. These two bundles remain
valid for their frozen captured source only; neither is a proof for the current
executable-source baseline.

For the executable-source baseline at commit
`81f188f772cc6b674fde748a361691f1bda19691`, the current scoped full-TUN proof is
[`20260716T173837Z-18283-m8K2po`](tests/tun/results/20260716T173837Z-18283-m8K2po/RESULT.md).
The isolated disposable Linux clone replaced its real default route from `c0`
to `c1`; the client emitted the exact `DefaultRouteChanged` cause, generation 1
exited with status 1 while a strict durable lockdown remained active, and a
separate generation 2 reached `Active` with its carrier bypass bound to `c1`.
A PROMISC-only `RTM_NEWLINK` notification was ignored: a real promiscuous
observer ran while generation 2 retained the same PID and start time. Connected
IPv6 canaries remained enabled but were not tunneled; directional client-egress
IPv6 captures were empty and the generation-specific `SP6` DROP counters
increased. Manager-gated shutdown stopped the live generation 2, produced no
generation 3, retained fail-closed IPv4/IPv6 protection, and required explicit
release. ICMP, TCP, UDP, DNS, a verified 64 MiB transfer and carrier-cut
recovery within a seven-second upper bound passed. All 745 checksum entries,
host-safety, clone cleanup, source/evidence isolation and secret scans were
valid.

This result is synthetic Linux IPv4/private-netns evidence. It is not a test of
a real systemd PID 1 service manager, resolver or DHCP change handling,
suspend/resume, an IPv6 tunnel, native macOS or Windows clients, production
deployment, field operation or censorship resistance.

The earlier full-TUN bundle
[`20260716T123535Z-91294-70zWb7`](tests/tun/results/20260716T123535Z-91294-70zWb7/RESULT.md)
and the native Linux ARM64 portability snapshot
[`20260716T122834Z-linux-arm64-current`](tests/portability/results/20260716T122834Z-linux-arm64-current/RESULT.md)
verified 342/342 checksums and a 187-entry frozen-source manifest with SHA-256
`fd5ebffc5b820ec8ac037aa3e9fea154c62576d7a276fa923168e5f4b4a84b95`.
Windows ARM64 H2 no-TUN
[`20260716T125113Z-36840-dd0c2571`](tests/windows/results/20260716T125113Z-36840-dd0c2571/RESULT.md)
verified 891/891 checksums, two authenticated sessions plus one rejection and
an exact 1 MiB echo without Windows route/DNS/firewall/adapter mutation. These
are retained captured-source snapshots with `field_evidence=false`, not
validation of the current executable-source baseline. They do not establish
IPv6, Windows Wintun, native macOS TUN safety, fleet rollout, hostile-network
behavior or a release claim.
See
[`docs/phase3-production-safety.md`](docs/phase3-production-safety.md) and the
[2026-07-16 scoped audit](docs/security-audit-2026-07-16.md).

## Lab safety

The Linux impairment harness refuses to run without its explicit VM gate and
root privileges. It uses Linux namespaces, unique veth devices, a singleton
lock, profile-specific acceptance checks, and a cleanup watchdog. It must never
be run on the macOS host.

For the validation workstation, the configured live `sing-box` file and
process, host routes, DNS, PF, TUN, and NetworkExtension state are `NO_TOUCH` for
all ZATMENIE experiments. A macOS process sandbox does not provide a second
Darwin network stack, so it is not an acceptable native-TUN containment
boundary. Linux mutation belongs in a disposable clone of the dedicated,
stopped, isolated OrbStack source base; native macOS testing requires a separate
macOS VM or physical Mac. See the
[host-isolated macOS lab design](docs/mac-host-isolated-lab.md).

The sealed Linux runs compare Mac state at bounded before/after observation
points; they are not continuous host-mutation monitors. Loaded PF runtime rules
could not be read without privilege and remain explicitly unobserved. The
current runner creates a disposable clone from the dedicated isolated base,
proves isolation and ownership before guest work, transfers pinned source only
through bounded stdin, returns a validated evidence archive through bounded
stdout, and requires `/mnt/mac`, SSH-agent forwarding and every discovered
guest-to-host `mac` command channel to be absent or fail closed. Guest operations
bind opaque IDs; deletion by name is permitted only after immediate
name-to-bound-ID revalidation followed by ID/name absence checks. Unrelated
same-host OrbStack lifecycle operators remain outside the harness trust
boundary.

The read-only Mac observer discovers exact-name `sing-box` candidates, captures
each argv, selects exactly one process whose argv matches the protected managed
configuration, and re-proves PID/start time/argv/executable/config within one
stable process generation. Substring matching, ambiguity, or an observed
restart invalidates the snapshot.

## Reporting a vulnerability

Do not include secrets, real subscriber links, private keys, or non-public
endpoint inventories in an issue. Provide a minimal synthetic reproducer,
affected commit/build hash, platform, and the security invariant that failed.
Treat authentication bypass, key/nonce reuse, transcript ambiguity, route/DNS
leaks, fail-open behavior, active-probe oracles, and unsafe cleanup as security
issues even when ordinary functional tests pass.
