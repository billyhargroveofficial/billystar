# VM-only lab runbook

Статус: на 2026-07-17 и code/tool audit head `d335682` две current
product-source Linux lifecycle cells имеют
scoped PASS. Same-boot all-resource recovery
[`20260716T225901Z-98821`](../tests/host-recovery/results/20260716T225901Z-98821/FINAL-RESULT.md)
привязана к clean pushed `c9b60e7`; последующий diff до `d335682` меняет только
reboot/recovery test tooling. Real-systemd-PID-1 userspace reboot и installed-client
pre-mutation lifecycle
[`20260717T001923Z-52605-reboot`](../tests/lockdown/results/20260717T001923Z-52605-reboot/RESULT.md)
привязаны к clean pushed `e374075`.

Successful full-TUN handoff `81f188f`, native Linux ARM64 portability
`726500f`, Windows 11 ARM64 no-TUN и более ранние recovery/reboot bundles
остаются captured-source snapshots. Production Rust изменился в `2ece275`;
нельзя комбинировать их с current lifecycle results в current successful-VPN
claim.

Stage A всё ещё частична: current-source successful paired tunnel,
dedicated-kernel/power-loss reboot, resolver/DHCP/suspend event matrices, IPv6
tunnel, Windows Wintun/leak, macOS native TUN/route и portability refresh
остаются отдельными gates; causal protocols 001–003 не запускались. Любое
отклонение от invariant ниже останавливает эксперимент.

## Absolute invariant

> Живой sing-box на Mac нельзя останавливать, перезапускать, сигналить, перенастраивать или обходить. На Mac нельзя менять routes, DNS, PF, system proxy, NetworkExtension или TUN. Все privileged/persistent network-state и impairment mutations выполняются только внутри disposable VM/netns; единственное host-исключение — unprivileged ephemeral loopback socket smoke без state mutation.

Mac = build/read-only safety observer плюс unprivileged loopback-only
deterministic correctness smoke на ephemeral owned ports; non-loopback bind и
любая network mutation запрещены. Linux mutation выполняется только в
disposable clone выделенной остановленной isolated OrbStack base VM; исходная
base не является рабочим test guest. Parallels Windows 11 ARM64 = native
client/portability и cross-VM socket control без Linux network mutation. Ни один
тест не требует отключения host VPN. Детальный boundary для native macOS:
[`mac-host-isolated-lab.md`](mac-host-isolated-lab.md).

## 1. Роли

| Узел | Роль | Разрешённые действия |
|---|---|---|
| macOS host | Reproducible build, hash artefacts, read-only safety observation, loopback-only correctness smoke | `git`, compiler, checksums, просмотр process/route state; unprivileged bind only to `127.0.0.1`/`::1` on ephemeral owned ports; без `sudo` и network mutation |
| Parallels Windows 11 ARM64 | Native client/portability control | test client, private cross-VM sockets, hashes; без route/firewall/DNS mutation и impairment |
| Dedicated isolated OrbStack base + disposable clone | Client/relay/sink/censor emulator | base stays stopped outside cloning; clone uses private namespaces, veth, owned listeners, nftables/qdisc and sealed result aggregation |
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
inside a disposable clone of the isolated OrbStack base:

```text
Disposable isolated clone root namespace (management only)
   |
lab bridge/veth (no public forwarding)
   +-- client netns
   +-- censor/bottleneck netns
   +-- relay netns
   +-- sink netns
```

Apply `tc netem`, rate limits and firewall classifiers only to recorded lab
veths, never to the clone's management interface. Bind listeners to
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

#### Native Linux ARM64 source-bound cell — PASS

Run
[`20260716T180304Z-linux-arm64-current`](../tests/portability/results/20260716T180304Z-linux-arm64-current/RESULT.md)
в disposable isolated Linux ARM64 clone проверил clean executable-source commit
`726500f1ff43e2b4fdcf9082abf05aa5a2513ab7`. No-default matrix прошла
718 tests, all-features — 732; обе дали zero failures и four ignored. Обе
strict Clippy matrices, format/metadata/shell gates и все пять partitioned
runner self-tests были valid. Все 342 checksum entries проверены. Frozen source
snapshot содержал 193 files и 4,464,041 bytes: 102,293 physical code lines,
включая 80,315 Rust lines.

Scope — native ARM64 CPU/filesystem portability без route, DNS, firewall, TUN,
netns, qdisc, sysctl или service mutation. Это не privileged network и не field
evidence. Clone cleanup, Windows-suspended state, host safety and evidence were
valid; `field_evidence=false`.

Старый
[`20260716T122834Z-linux-arm64-current`](../tests/portability/results/20260716T122834Z-linux-arm64-current/RESULT.md)
остаётся валидной snapshot-bound историей своего 187-file capture. Run
`726500f` был более новым source-bound portability evidence, но production Rust
изменился после него в `2ece275`.

#### Source-bound Linux IPv4 OS-TUN + network handoff cell — PASS

Run
[`20260716T173837Z-18283-m8K2po`](../tests/tun/results/20260716T173837Z-18283-m8K2po/RESULT.md)
использовал pinned clean `git archive` commit
`81f188f772cc6b674fde748a361691f1bda19691`, dedicated isolated source base,
disposable clone и private netns; его `status.env`
содержит `test_status=valid`, `cleanup_status=valid`,
`host_safety_status=valid`, `clone_cleanup_status=valid`,
`evidence_bundle_status=valid` и `field_evidence=false`. Зафиксированы:

- production-gated REALITY URI/short-ID/pin и mandatory protocol-v3
  credential/allowlist; unauthenticated TLS probe получил synthetic cover
  response при нуле inner sessions до authenticated-client start;
- planted persistent empty-alias TUN с requested client name дал atomic
  `EBUSY`/`EEXIST` до host-state mutation и оставил foreign interface
  exact-state unchanged;
- реальный `ip route replace` сменил default route `c0 -> c1`; exact
  `DefaultRouteChanged` заставил generation 1 завершиться status 1, при этом
  intermediate main WAL отсутствовал, а strict durable lockdown оставался
  active;
- supervisor создал generation 2 с другим PID/start time; она достигла
  `Active`, записала strict main WAL и использовала exact bypass interface `c1`;
- PROMISC-only `RTM_NEWLINK` был проигнорирован: real promiscuous packet
  observer работал при неизменных PID/start time generation 2 и без нового
  topology restart;
- connected IPv6 c0/c1 canaries оставались подняты, directional client-egress
  pcaps были empty, а generation-specific `SP6` DROP counters стали positive;
  это fail-closed OUTPUT proof, не IPv6 tunnel;
- ICMP, TCP, UDP, DNS, verified 64 MiB transfer и carrier-cut recovery с upper
  bound не более 7 s прошли;
- manager-stop gate остановил live generation 2, generation 3 не появилась,
  IPv4/IPv6 canaries оставались blocked до explicit release;
- все 745 checksum manifest entries, source/evidence transfer, clone deletion,
  host safety и final private-material scans прошли.

Stable Mac pre/post snapshots совпали для default/full IPv4+IPv6 routes, DNS,
static PF config/anchor hashes и exact sing-box PID/start/argv/config/binary.
Observer перечислял exact-name candidates, сохранял argv каждого, выбирал
ровно один protected managed argv и повторно доказывал ту же process generation.
Raw neighbor-cache snapshots сохранены, но исключены из stable comparison.
Runtime PF rules не инспектировались без host privilege
(`pf_runtime_observed=false`), поэтому этот слой не входит в proof. Сравнение —
before/after endpoints, не continuous monitor.

Runner проверил isolated/network-isolated config source и clone, отсутствие
mounts/forwarded ports/SSH agent, `/mnt/mac` и работоспособного guest-to-host
`mac` command channel. Source передан bounded stdin, sealed evidence возвращён
validated bounded stdout tar; shared checkout не использовался. Start/run/guest
addressing использовало bound opaque OrbStack ID. Delete-by-name был разрешён
только после fresh name-to-ID equality, затем проверены late-appearance window
и отсутствие ID/имени. Unrelated same-host OrbStack operators остаются вне
trust boundary.

Результат классифицируется как synthetic Linux IPv4 implementation evidence,
не production/field/censor evidence и не proof для real systemd PID 1,
resolver/DHCP/suspend events, IPv6 tunnel, Windows или macOS.

#### Current product-source Phase-3 crash/recovery cell — PASS

Run
[`20260716T225901Z-98821`](../tests/host-recovery/results/20260716T225901Z-98821/FINAL-RESULT.md),
with compact
[`PUBLISHED-EVIDENCE.md`](../tests/host-recovery/results/20260716T225901Z-98821/PUBLISHED-EVIDENCE.md),
прошёл 29/29 fresh net+mount+PID namespace scenarios: 28 recovered и один
intentional foreign-resource Conflict. Все 1,592 checksum entries проверены.
Pinned clean pushed source — `c9b60e7`; последующий `c9b60e7..d335682` diff
изменяет только reboot/recovery test tooling, не product source. Каждый `SIGKILL` marker связан с exact
cut/PID/log и mandatory root-owned schema-v3 WAL с восемью ресурсами.
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

#### Current product-source PID-1 userspace reboot/client cell — PASS

Run
[`20260717T001923Z-52605-reboot`](../tests/lockdown/results/20260717T001923Z-52605-reboot/RESULT.md),
with compact
[`PUBLISHED-EVIDENCE.md`](../tests/lockdown/results/20260717T001923Z-52605-reboot/PUBLISHED-EVIDENCE.md),
прошёл OrbStack userspace machine restart с real `systemd 261.1` PID 1 и
различными boot/PID/net/mount namespace identities при неизменном shared
kernel. Strict WAL binding восстановил exact native nft `inet`/`output` barrier
раньше networkd start. Loopback работал, non-loopback IPv4 ping был denied.
Explicit release удалил WAL и единственную owned `sp_lock` table, после чего
gateway снова стал reachable. Все 939 checksum entries проверены.

После release точный installed client unit дал три distinct credential-refusal
InvocationID и `NRestarts 0 -> 1 -> 2`; operator stop подавил дальнейший
restart дольше `RestartSec`. Canonical network state до/после совпал.

Это userspace PID-1 reboot + installed-client pre-mutation lifecycle proof. В
cell нет successful paired tunnel, dedicated-kernel/hardware/power-loss reboot,
continuous packet proof, production, initrd, L2/AF_PACKET, FORWARD,
container-netns или censorship behavior.

#### Windows 11 ARM64 H2 no-TUN captured-source cell — PASS

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
