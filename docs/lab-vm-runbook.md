# VM-only lab runbook

Статус: на 2026-07-16 запечатаны пять раздельных current-source synthetic
scopes: native Linux ARM64 portability
[`20260716T122834Z-linux-arm64-current`](../tests/portability/results/20260716T122834Z-linux-arm64-current/RESULT.md),
full-TUN IPv4/netns
[`20260716T123535Z-91294-70zWb7`](../tests/tun/results/20260716T123535Z-91294-70zWb7/RESULT.md),
same-boot Phase-3 crash/recovery
[`20260716T124109Z-93828`](../tests/host-recovery/results/20260716T124109Z-93828/FINAL-RESULT.md),
early-userspace reboot lockdown
[`20260716T124706Z-34564-reboot`](../tests/lockdown/results/20260716T124706Z-34564-reboot/RESULT.md)
и Windows 11 ARM64 H2 no-TUN
[`20260716T125113Z-36840-dd0c2571`](../tests/windows/results/20260716T125113Z-36840-dd0c2571/RESULT.md).
Stage A всё ещё частична: short-write/reorder/abrupt-close matrix, IPv6,
Windows Wintun/leak, macOS native TUN/route и default `tls-chrome` build
остаются отдельными gates; causal protocols 001–003 не запускались. Старые
bundles — historical/diagnostic, а не current-source замена. Любое отклонение
от invariant ниже останавливает эксперимент.

## Absolute invariant

> Живой sing-box на Mac нельзя останавливать, перезапускать, сигналить, перенастраивать или обходить. На Mac нельзя менять routes, DNS, PF, system proxy, NetworkExtension или TUN. Все privileged/persistent network-state и impairment mutations выполняются только внутри disposable VM/netns; единственное host-исключение — unprivileged ephemeral loopback socket smoke без state mutation.

Mac = build/read-only safety observer плюс unprivileged loopback-only
deterministic correctness smoke на ephemeral owned ports; non-loopback bind и
любая network mutation запрещены. OrbStack Arch = единственная Linux-машина для
netns/qdisc/nft mutation. Parallels Windows 11 ARM64 = native client/portability
и cross-VM socket control без Linux network mutation. Ни один тест не требует
отключения host VPN.

## 1. Роли

| Узел | Роль | Разрешённые действия |
|---|---|---|
| macOS host | Reproducible build, hash artefacts, read-only safety observation, loopback-only correctness smoke | `git`, compiler, checksums, просмотр process/route state; unprivileged bind only to `127.0.0.1`/`::1` on ephemeral owned ports; без `sudo` и network mutation |
| Parallels Windows 11 ARM64 | Native client/portability control | test client, private cross-VM sockets, hashes; без route/firewall/DNS mutation и impairment |
| OrbStack Arch VM | Client/relay/sink/censor emulator | disposable namespaces, veth, owned listeners, nftables/qdisc, result aggregation |
| External field endpoint | Отдельный будущий scope | Только после явной авторизации, bounded owned endpoint, без production credential reuse |

Если VM фактически разделяет host network stack для конкретной операции, эта операция запрещена. Проверить boundary до запуска, а не после.

## 2. Host preflight — read-only

До каждого lab block сохранить в session note, не меняя систему:

```text
timestamp UTC
git status --short (repo)
sing-box exact-name candidate list, per-candidate argv and selected exact managed process identity/state (read-only)
default route and active interface summary (read-only)
DNS summary (read-only)
Parallels/OrbStack guest names, power state, image/version and available rollback/reprovision identifier
```

Observer selection is exact and fail-closed: enumerate `pgrep -x sing-box`,
capture each candidate argv, require exactly one argv matching the protected
managed configuration, then re-prove PID/start/argv/executable/config in one
stable process generation. Substring-only matching, ambiguity or restart fails
the snapshot.

Запрещённый host command class: `kill*`, `pkill`, `launchctl`, `networksetup -set*`, `route add/delete`, `pfctl`, `scutil --set`, `ifconfig ... create/destroy`, host `tc`/packet injector, edit under the live sing-box directory.

Preflight fails if:

- sing-box is absent/unhealthy compared with baseline;
- test requires host default-route or DNS change;
- manifest содержит real credential, subscription URL, private key или production endpoint list;
- отсутствует проверенный snapshot **или** deterministic destroy/reprovision path для OrbStack lab state;
- другой агент уже меняет тот же experiment result directory.

## 3. Artefact preparation

1. Build только с lockfile (`--locked`) и в изолированный target directory, уникальный для experiment ID; не build на production servers и не reuse concurrent workspace target.
2. Record git SHA, dirty-state digest, lockfile SHA-256, compiler version, full build command и binary SHA-256.
3. Transfer only binaries, public configs and the immutable manifest to guests.
4. Guest endpoint names use reserved `.invalid` labels in documentation; real lab addresses remain in an untracked runtime file.
5. Never copy the Mac sing-box config, subscription cache or keychain material.

Минимальные Cargo patterns (со свежим `EXPERIMENT_ID`, без пробелов и `/`):

```sh
CARGO_TARGET_DIR="$PWD/target/lab-$EXPERIMENT_ID" cargo test --workspace --locked
CARGO_TARGET_DIR="$PWD/target/lab-$EXPERIMENT_ID" cargo build --release --locked
CARGO_TARGET_DIR="$PWD/target/win-$EXPERIMENT_ID" cargo zigbuild --release --locked --target aarch64-pc-windows-gnullvm
```

Guest-native rebuild использует тот же committed `Cargo.lock`, `--locked` и guest-local `CARGO_TARGET_DIR=/tmp/shadowpipe-target-$EXPERIMENT_ID`. Любое lockfile resolution/update во время lab run — preflight failure.

Если client и server собираются в разных target directories или на разных
OS, manifest задаёт один явный `SHADOWPIPE_MAGIC` для обеих сборок и
записывает его рядом с SHA-256 артефактов. Это compatibility tag, не
секрет и не замена server-fingerprint authentication. Тест с разными
magic должен fail closed до session establishment.

Каждый lab client получает fingerprint synthetic server key из immutable
artifact manifest и передаёт его через `--server-fp`/URI `fp=`. Unpinned lab
mode отсутствует: negative test проверяет early failure, а не включает bypass.

## 4. Guest network isolation

Preferred mutating test path is a dedicated namespace/veth topology entirely
inside the OrbStack Linux guest:

```text
OrbStack Arch root namespace (management only)
   |
lab bridge/veth (no public forwarding)
   +-- client netns
   +-- censor/bottleneck netns
   +-- relay netns
   +-- sink netns
```

Apply `tc netem`, rate limits and firewall classifiers only to recorded lab
veths, never to OrbStack's management interface. Bind listeners to
loopback/private lab interfaces. The guest watchdog is passive: on timeout it
writes a failure/deletion barrier and performs no signal or network mutation.
Named residue is inspected and the disposable VM is then destroyed or
reprovisioned. Management access must remain outside the impaired namespaces.
Parallels Windows never receives `netsh`, route, firewall, DNS or impairment
changes for this lab.

Cross-guest Windows→OrbStack is a portability smoke only: first prove reachability on the private VM network with an unprivileged bounded payload, then run the Windows binary against an owned OrbStack sink. It is not a censor topology and supplies no impairment/field evidence. Do not enable public forwarding or NAT unless a later authorized field protocol explicitly requires it.

## 5. Experiment order

### Stage A — deterministic correctness

- loopback echo and sustained transfer well above any tested byte floor;
- forced short writes, reorder at application framing boundary, abrupt close and reconnect;
- distinct classification of crypto/framing faults vs network stalls;
- manifest/result schema validation.
- Windows ARM64 binary starts, validates arguments and completes a bounded private-VM socket exchange with the same payload hash as the native control.
- Linux full-tunnel preflight rejects `--auto-route` unless
  `--tunnel --kill-switch --dns` are all present; the privileged cell then
  proves TCP/UDP/ICMP/DNS through the OS TUN, no plaintext on the client
  underlay, fail-closed carrier loss, recovery and exact route/firewall/DNS
  cleanup. Config/argv unit tests alone do not satisfy this cell.

Exit gate: zero unexplained data corruption; a local correctness error must never be labeled censor action.

#### Native Linux ARM64 current-source cell — PASS

Run
[`20260716T122834Z-linux-arm64-current`](../tests/portability/results/20260716T122834Z-linux-arm64-current/RESULT.md)
в disposable Linux ARM64 clone прошёл no-default 671/0 и all-features 685/0
test matrices, обе strict Clippy matrices, format/metadata/shell gates и
partitioned runner self-tests. Все 342/342 checksum entries проверены. Frozen
source manifest содержал 187/187 files и имел SHA-256
`fd5ebffc5b820ec8ac037aa3e9fea154c62576d7a276fa923168e5f4b4a84b95`.

Scope — native ARM64 CPU/filesystem portability без route, DNS, firewall, TUN,
netns, qdisc, sysctl или service mutation. Это не privileged network и не field
evidence.

#### Recorded Linux IPv4 OS-TUN cell — PASS

Run
[`20260716T123535Z-91294-70zWb7`](../tests/tun/results/20260716T123535Z-91294-70zWb7/RESULT.md)
использовал disposable OrbStack clone и private netns; его `status.env`
содержит `test_status=valid`, `cleanup_status=valid`,
`host_safety_status=valid` и `field_evidence=false`. Зафиксированы:

- production-gated REALITY URI/short-ID/pin и mandatory protocol-v3
  credential/allowlist; unauthenticated TLS probe получил synthetic cover
  response при нуле inner sessions до authenticated-client start;
- durable REALITY replay store leased до bind: data file 1,572,960 bytes,
  отдельный lock и lifecycle marker прошли private-state cleanup;
- planted persistent empty-alias TUN с requested client name дал atomic
  `EBUSY`/`EEXIST` за 172 ms: 0 underlay/carrier packets, foreign
  link/MTU/address/alias exact-state unchanged, resolver unchanged, 0
  protocol-186 routes, 0 Shadowpipe firewall state и no WAL;
- ICMP 20/20, 0% loss; TCP receiver 561,905,664 bytes при 446.785 Mbit/s;
  UDP 5,092/5,092 packets, 0 lost;
- 64 MiB source/download SHA-256
  `5ca1b38d0543084e1a1027831af37e3552e47ac34eb42bb8012c26ece4f67510`;
- tunneled DNS answer `198.18.0.2`; strict non-carrier underlay,
  missing-credential, missing-pin и restart-lockdown captures дали `0/0/0`;
- TCP-reset cut не дал direct fallback, recovery upper bound 8 s;
- после SIGTERM durable L3/OUTPUT restart barrier оставался активным; explicit
  release удалил его WAL и exact table, восстановил direct route, а guest-root
  snapshots/private resolver совпали с baseline;
- все 573/573 checksum manifest entries прошли `sha256sum -c`.

Stable Mac pre/post snapshots совпали для default/full IPv4+IPv6 routes, DNS,
static PF config/anchor hashes и exact sing-box PID/start/argv/config/binary.
Observer перечислял exact-name candidates, сохранял argv каждого, выбирал
ровно один protected managed argv и повторно доказывал ту же process generation.
Raw neighbor-cache snapshots сохранены, но исключены из stable comparison.
Runtime PF rules не инспектировались без host privilege
(`pf_runtime_observed=false`), поэтому этот слой не входит в proof. Сравнение —
before/after endpoints, не continuous monitor.

Start/run/guest addressing использовало bound opaque OrbStack ID. OrbStack 2.2.1
в observed lab run паниковал на delete-by-ID; delete-by-name был разрешён только
после fresh name-to-ID equality, затем проверены late-appearance window и
отсутствие ID/имени. Unrelated same-host OrbStack operators остаются вне trust
boundary.

Результат классифицируется как synthetic Linux IPv4 implementation evidence,
не production/field/censor evidence и не proof для IPv6, Windows или macOS.

#### Phase-3 crash/recovery cell — PASS, same-boot scope

Run
[`20260716T124109Z-93828`](../tests/host-recovery/results/20260716T124109Z-93828/FINAL-RESULT.md)
прошёл 29/29 fresh net+mount+PID namespace scenarios: 28 recovered и один
intentional foreign-resource Conflict. Все 1443/1443 checksum entries
проверены, evidence finalization=`complete`. Каждый `SIGKILL` marker связан с
exact cut/PID/log и mandatory root-owned schema-v3 WAL с восемью ресурсами.
Matrix охватывает:

- WAL Planned и apply каждого resource family;
- DNS Staged и partial IPv4/IPv6 firewall acknowledgements;
- all-Applied/Preparing и Active;
- до mutation и после convergence/до WAL acknowledgement для каждого из восьми
  recovery steps;
- all-or-nothing foreign-resource Conflict с durable journal и сохранённой
  protection.

Scope ограничен same-boot process crash. `SIGKILL` не моделирует kernel reboot,
torn filesystem write или power loss. Resolver target — private tmpfs, не
systemd-resolved и не guest `/etc`. `field_evidence=false`; Mac host наблюдался
только before/after, loaded PF runtime не наблюдался.

#### Early-userspace reboot lockdown cell — PASS, barrier-only scope

Run
[`20260716T124706Z-34564-reboot`](../tests/lockdown/results/20260716T124706Z-34564-reboot/RESULT.md)
прошёл real guest reboot с различными boot IDs. Strict WAL boot/PID-1 namespace
binding восстановил exact native nft inet/output barrier; monotonic timestamps
зафиксировали restore completion на 2,995 microseconds раньше networkd start.
Loopback работал, non-loopback IPv4 ping был denied. Explicit operator release
удалил WAL и единственную owned `sp_lock` table, после чего gateway снова стал
reachable. Все 650/650 checksum entries проверены.

Это отдельный early-userspace local L3 OUTPUT proof. В cell нет paired
client/server tunnel; она не доказывает production, initrd, L2/AF_PACKET,
FORWARD, container-netns или censorship behavior.

#### Windows 11 ARM64 H2 no-TUN cell — PASS

Run
[`20260716T125113Z-36840-dd0c2571`](../tests/windows/results/20260716T125113Z-36840-dd0c2571/RESULT.md)
проверил native Windows 11 ARM64 PE. Artifact size 5,072,384 bytes, SHA-256
`2734e79f98866910aa8e0386af4ff630191b0a72fd1945177f078cb69d500bad`.
Server recorded 2 authenticated sessions и 1 rejected connection; positive
gates вернули exact nonce и exact 1,048,576-byte echo, а missing pin отклонился
до socket. Все 891/891 checksum entries проверены.

Canonical Windows route/DNS digests совпали before/after; helper не содержит
TUN/firewall/adapter mutation command. Windows VM снова suspended, disposable
OrbStack clone удалён. Это private-socket no-TUN portability/authentication
evidence, не Wintun/leak/field-censorship proof.

### Stage B — trigger-unit harness (`001`)

- inject known VM rules for 5-tuple, destination aggregate and classifier-conditioned triggers;
- run randomized factor cells and confirm model selection recovers the injected truth;
- run a no-trigger condition and require verdict `NO_TRIGGER_OBSERVED`, not a fabricated threshold.

Exit gate: correct confusion matrix and event accounting. No-target-event at a preregistered fixed horizon is right-censored; successful completion and implementation failures are distinct terminal/competing outcomes, not generic censoring. This validates the harness only.

### Stage C — whitelist relay harness (`002`)

- emulate allowlist inside guest: direct destination denied, relay destination allowed;
- use the same inner payload/exit for A and B;
- randomize AB/BA, include genuine-cover and non-allowlisted-cloud controls;
- confirm payload floor, not TCP-connect, drives success.

Exit gate: the analysis attributes the injected policy correctly. It does not claim Yandex/any operator behavior.

### Stage D — RTT alignment (`003`)

- negative control: transport and application termination co-located;
- positive control: far backend behind near relay;
- reproduce an RTT-gap detector before testing co-location, deferred reply or lab-only scheduling;
- record throughput, queueing and new timing features.

Exit gate: mitigation is evaluated against the reproduced detector and does not merely move the threshold.

### Stage E — paired degradation controller

- apply multiple preregistered loss/delay/rate levels to a shared veth bottleneck;
- run cover and treatment pairs concurrently or tightly interleaved;
- calculate DiD and response curves;
- ensure FEC repair symbols consume congestion budget and pre-recovery loss remains visible.

Exit gate: preregistered non-inferiority in VM. Status remains `LAB_ONLY`.

## 6. Field gate — deliberately not automatic

No VM success authorizes a field mutation. A future field run needs explicit user authorization and a new manifest containing:

- owned disposable endpoints and legal/provider review;
- operator/path strata without personal identifiers;
- bounded bytes/rate/duration and stop conditions;
- AB/BA randomization seed and payload floor;
- proof the Mac route and sing-box remain untouched;
- cleanup owner and expiry time.

Field testing should originate from a dedicated guest/SIM/vantage, not by rerouting the Mac. Never scan third-party address space or test credentials that were not placed in scope.

## 7. Stop conditions

Immediately stop the current guest trial if any occurs:

- Mac sing-box PID/state changes or host connectivity deviates from read-only baseline;
- host route/DNS/PF mutation is requested by a script;
- guest management path enters the impaired namespace;
- payload appears in capture/logs;
- unexpected public listener or egress destination;
- crypto/framing errors contaminate availability measurement;
- rate/byte/time budget exceeded;
- result cannot distinguish implementation fault from policy effect.

The correct verdict after contamination is `INCONCLUSIVE`.

## 8. Cleanup and proof

Inside each guest only:

1. signal only atomically revalidated registered session leaders: open a Linux
   pidfd, validate PID + PGID + SID + `/proc` start time, then use
   `pidfd_send_signal`; the pidfd closes the post-open reuse race, while a
   concurrent privileged actor remains outside this proof; never signal a
   numeric PGID or process name;
2. treat every incomplete owner record or unresolved launch intent as a hard
   deletion barrier;
3. inspect the exact run-namespace names with `ip netns pids`, but never signal
   those raw numeric PIDs; any remaining PID withholds deletion;
4. scan every visible `/proc/PID/task/TID` namespace link and task-visible FD
   table, plus other `/run/netns` aliases, for the recorded inodes; unreadable
   state or any visible reference leaves names mounted;
5. delete a root veth only when its current ifindex and ifalias exactly match
   the run record, then revalidate the namespace inode before deleting its name;
6. repeat the visible reference scan and compare the guest management
   route/qdisc to the read-only preflight snapshot;
7. archive redacted aggregate result + manifest + hashes;
8. always restore/destroy the disposable snapshot or use the documented
   deterministic reprovision path.

The guest watchdog deliberately does **not** clean after `SIGKILL`. It records a
failure marker and leaves names/residue for inspection, without signalling a
PID or touching networking. A userspace `/proc`/FD scan cannot prove global
network-namespace destruction: an external socket/netlink object or nsfs mount
in another mount namespace may pin it invisibly. Namespace-name deletion is
therefore only a bounded runner-state check. VM destruction/reprovisioning is
the final containment proof, and absence of a persisted report is failure.
The watchdog does not bound cleanup liveness: an uninterruptible kernel/netlink
operation can stall the runner, in which case the result remains unproven and
the disposable VM must be stopped/destroyed rather than broadening cleanup.

On Mac perform read-only comparison to the preflight snapshot: sing-box
identity/state, default/full route summary, DNS summary and readable PF config
hashes must be unchanged. Runtime PF rules are not claimed unchanged when they
cannot be read without privilege. Do not «prove cleanup» by restarting anything.

## 9. Raw evidence versus publishable bundle

The VM-local **raw run directory** may contain exact timing and packet-path
instrumentation needed to audit the harness:

```text
manifest.json
environment.txt
runner.sh
iperf-*.json and bounded logs
tc-state*.txt
nft-state.txt
cleanup-state.txt
watchdog-outcome.txt
owned-processes/*.owner
netns-identities/*.identity
link-identities/*.identity
checksums.txt
```

It is access-controlled evidence, not an anonymous aggregate. After review, a
separate **publishable bundle** contains only:

```text
manifest.json
RESULT.md
aggregate.json
checksums.sha256
optional redacted plots
```

Raw pcaps stay ephemeral inside the guest unless manually reviewed for payload
and metadata leakage. A publishable bundle never contains IPs, credentials,
private keys, SNI inventory, stable client IDs, exact session traces or packet
payload.

## 10. Recommended execution cadence

- One experiment ID per VM image/snapshot/reprovision lineage and one isolated `CARGO_TARGET_DIR` per ID.
- One in-progress trial writer; observers are read-only.
- Commentary update at least once per 60 minutes during long runs.
- Commit documentation/results separately from hot-path implementation.
- Update [`claims-ledger.md`](claims-ledger.md) only after result classification and scope review.
