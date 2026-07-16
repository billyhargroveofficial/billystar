# Threat model 2026: causal carrier plane

Дата среза: 2026-07-16. Назначение системы — легитимный доступ к информации и исследование устойчивости транспорта в цензурируемых сетях. Документ не обещает «неуязвимый VPN»: он задаёт наблюдаемые атаки, границы доказательств и условия остановки.

## Защищаемые свойства

1. Доступность пользовательского трафика при protocol blocking, selective degradation и mobile allowlisting.
2. Конфиденциальность и аутентичность inner session при пассивном наблюдателе и on-path MITM.
3. Отсутствие DNS/route leaks при смене сети и отказе carrier.
4. Минимизация устойчивых wire/session invariants, пригодных для дешёвого блокирования с низким false-positive cost.
5. Проверяемость: каждый availability/stealth claim должен иметь scope, counterfactual и falsifier.
6. Безопасность рабочей станции: живой sing-box на Mac остаётся неизменным и непрерывным.

## Системная модель

```text
application/TUN
      |
hybrid-keyed, authenticated encrypted session (bytes plane)
      |
carrier adapter: direct | whitelisted relay | future serverless/cover carrier
      |
access ISP / TSPU / transit / provider edge
      |
relay or exit -> destination

observer plane (out of data path): paired cover + treatment measurements,
manifest, evidence ledger, policy gates
```

Bytes plane отвечает за криптографию и framing. Текущая конкретика: secrets от
ML-KEM-768 и ephemeral X25519, transcript/randoms подаются в HKDF-SHA-256;
frames защищает classical ChaCha20-Poly1305 AEAD. Это не «PQ AEAD» и не
самостоятельное доказательство formally robust hybrid combiner. Статический
ML-KEM public key аутентифицируется SHA-256 fingerprint pin. Текущий Rust client
не имеет unpinned mode: missing/malformed pin aborts до
reservation/DNS/socket/TUN, а mismatch — до encapsulation/ClientHello.

Перед static key идёт mutual per-device PSK gate: client сначала посылает только
128-bit pseudonymous `kid`; server отвечает fresh challenge + server HMAC; client
не выдаёт nonce/HMAC, пока server proof не проверен. Server делает fresh-dummy
RNG, полный bounded allowlist scan с constant-time selection и общий HMAC path,
и только после client MAC пишет ML-KEM key или делает KEM work. Три access flights
включены в H0; Finished `kid` обязан совпасть с pre-key identity. Это убирает
выбранный fake-server HMAC oracle и очевидную known/unknown timing branch, но не
является доказательством whole-system constant-time.

Production daemon принимает только REALITY с 1..16 full-width 64-bit online
`short_id` tokens из strict root-owned `0600` файла
`/etc/shadowpipe/reality-short-ids` (override:
`--reality-short-id-file`). Этот ACL — carrier admission, не client identity;
до bind daemon также exclusively загружает HMAC-authenticated durable
`--reality-replay-store`, связанный со static key. Обычный daemon не печатает
token-bearing URI. Raw/H2/TLS/QUIC имеют отличимый
ShadowPipe bootstrap/challenge и разрешены только explicit
`--allow-insecure-lab-carriers --development-user-allowlist` без TUN. Signed
endpoint-policy v2 поставляет overlap-rotated pin sets из независимо enrolled
root; future clients must preserve mandatory pinning and that trust separation.

Carrier plane отвечает за destination/topology. Observer plane не управляет live Mac routing; он допускает изменение политики только после лабораторного и полевого гейтов.

## Противник

### Наблюдает пассивно

- destination IP, prefix/ASN, port, transport, direction, byte/packet counts, duration и connection churn;
- TCP/QUIC/TLS fingerprints, record/packet-size sequences, burst и inter-arrival distributions;
- first-payload set-bit/printable-ASCII/protocol-exemption features у «looks-like-nothing» fully encrypted transports;
- encapsulated TLS handshake bursts в nested proxy stacks и RFC-like inner TCP behavior, проявляющееся в outer UDP tunnel;
- DNS и SNI там, где они видимы, а также несогласованность SNI/certificate/destination;
- QUIC Initial, который observer может дешифровать без endpoint secret и проверить SNI/ClientHello features;
- cross-layer RTT и flow correlation, когда transport и application sessions имеют разные endpoints;
- повторяемые handshake lengths, reconnect cadence, pool fan-out и одинаковые per-user/per-build параметры;
- state по destination host/service и результаты flow classifier на многих connections во времени, а не только per-flow DPI.

### Может активно влиять на путь

- default-deny IP/CIDR allowlist и protocol/endpoint blocklists;
- selective drop, delay, ACK suppression, rate limiting, UDP blackout и loss patterns;
- условия, при которых covert application деградирует сильнее legitimate cover;
- controlled loss/rate/delay interventions и классификация congestion response, включая aggressive custom CC, который не back off;
- кратковременные/селективные правила по оператору, региону, порту, ASN, flow class и времени;
- активное подключение к подозрительному endpoint. Массовое active probing не считается доказанным базовым механизмом TSPU, но endpoint не должен раскрывать proxy по probe response.

### Может атаковать control/supply plane

- replay корректно подписанной, но устаревшей policy, freeze на старом keyset и rollback после revocation;
- подмена unsigned endpoint/server-key pin, corruption cache/journal и часов для обхода expiry;
- compromise online policy-signing key, build/update channel, relay или provider account; offline root compromise считается disaster-recovery event, а не обычная rotation;
- Sybil/honeypot carrier может выдавать себя за healthy relay, логировать metadata и возвращать манипулируемую telemetry.

### Имеет организационные рычаги

- централизованное распространение правил и endpoint lists;
- запросы к domestic/cloud provider, KYC/SORM visibility, ToS enforcement и account termination;
- destination-side VPN detection у сервисов, независимо от качества carrier camouflage.

### Не входит в основной scope

- полностью скомпрометированный client/kernel, physical device seizure и целевой malware;
- глобальный пассивный наблюдатель, одновременно видящий оба конца всех путей;
- гарантированная доступность при полном отключении packet network;
- защита оператора domestic relay от законного/принудительного provider logging;
- обещание обхода любой будущей политики без смены topology/software.

## Приоритетные классы атак

| Класс | Evidence state | Последствие | Архитектурный ответ |
|---|---|---|---|
| Destination IP/CIDR allowlist | Field-supported, operator/time-specific | Flow не доходит до полезного handshake | Topological carrier внутри реально разрешённого destination set; paired field validation |
| Selective degradation / «16 KiB» family | Механизм на текущем repo scope **не воспроизведён**; внешние reports существуют | Silent stall или резкое снижение goodput | Сначала `001-trigger-unit`; никаких blanket per-flow claims; guard off by default |
| Protocol/session fingerprinting | Primary literature + field reports | Block/throttle с низкой collateral cost | Real protocol surface, minimized invariants, ephemeral defenses; не путать с topology fix |
| Fully-encrypted-traffic heuristics | USENIX 2023, measured GFW scope | Random-looking first payload попадает в non-exempt class | Не считать entropy camouflage; carrier-specific browser-real surface и classifier regression, без RU extrapolation |
| Encapsulated TLS / TCP-over-UDP | USENIX 2024 + FOCI 2024, оценённые scopes | Nested handshake или inner TCP dynamics выдают tunnel | Detector-in-CI, bound burst/RTT semantics; не обещать, что padding/mux достаточны |
| Temporal host aggregation | NDSS 2024, Tor-focused scope | Слабые per-flow signals накапливаются до точного host verdict | Ephemeral endpoints/parameters и long-window regression; no claim из одного flow |
| QUIC Initial/SNI censorship | USENIX 2025 GFW + [FOCI 2026 Russian TSPU](https://www.petsymposium.org/foci/2026/foci-2026-0010.php) | Public Initial keys allow SNI classifier/blocklist despite encrypted handshake; broad RU SNI-dependent deployment is documented for the paper's 2022–2023 timeline | ECH/fragmentation only where standards and current field evidence support them; TCP fallback; remeasure current operator/path rather than treating history as a universal live rule |
| Cross-layer RTT fingerprint | NDSS 2025, segmented-proxy scope | Protocol-agnostic timing tell | Co-locate terminations where possible; reproduce detector before any alignment mitigation |
| Differential degradation | Primary research | Cover остаётся usable, covert path нет | Same-destination paired measurement; bounded-response scheduler as hypothesis |
| Custom-CC response fingerprint | FOCI 2025, Hysteria/TCP-Brutal case studies | Censor induces/observes impairment and identifies non-backing-off response | Standard-conformant CC owns congestion; classifier gate for any override |
| Active probe/oracle | Primary research, RU scale uncertain | Endpoint confirmation or client PSK oracle | Production REALITY + mandatory full-width short-id ACL + durable exact-replay state loaded before bind; failed outer auth/replay forwards to genuine service. Inner mutual PSK gate gives a fixed cheap challenge and withholds ML-KEM/KEM, but raw/H2/TLS/QUIC remain explicit no-TUN lab carriers |
| Flow correlation / relay backhaul | Primary literature + [FOCI 2026 dual-role relay study](https://www.petsymposium.org/foci/2026/foci-2026-0008.php) | Carrier ingress linked to foreign exit; a relay's server+client role is observable even with encrypted payload | Avoid claiming anonymity; separate roles/topology where useful; reduce deterministic timing; independent legal/ops assessment |
| Ephemeral WebRTC proxy enumeration/classification | [Obscura, PoPETs 2026](https://petsymposium.org/popets/2026/popets-2026-0030.php), evaluated cost-effective-censor model | Static proxy identities and simplistic WebRTC data-channel use remain enumerable/classifiable | Treat media encapsulation + ephemeral proxies as a future carrier with its own artifact-backed evaluation, not a universal VPN disguise |
| DNS mechanism heterogeneity | [DPYProxy-DNS, FOCI 2026](https://www.petsymposium.org/foci/2026/foci-2026-0001.php) | Injection/drop and IP/port/SNI policy make one fixed resolver/transport brittle | Typed DNS sub-plane with bounded technique probes, cached decision expiry and re-verification; generic adaptive selection is prior art |
| Blind spoofed-packet / NAT-response oracle | [Architectural VPN Vulnerabilities, FOCI 2026](https://www.petsymposium.org/foci/2026/foci-2026-0007.php) | Infer internal VPN address/active flow and disrupt TCP from predictable encrypted responses without decrypting payload | Isolated-netns injection-oracle regression, strict source/interface validation, stateful response filtering and longitudinal re-test; no Internet spoofing experiment |
| Measurement-corpus blind spot | [Geedge Cases, FOCI 2026](https://www.petsymposium.org/foci/2026/foci-2026-0006.php) | Popularity/sensitive-domain lists miss vendor-relevant targets; TLS EOF is over-attributed | Record corpus provenance, mix public/vendor/incident strata, repeat each mechanism and keep DNS/TLS attribution separate |
| Transit-AS concentration | [Who Carries Tor?, FOCI 2026](https://www.petsymposium.org/foci/2026/foci-2026-0014.php) | Nominally distinct providers/endpoints share an observation or blocking chokepoint | Model `transit_asn` failure domains and reject shared-path diversity claims until route evidence exists |
| Shutdown/recovery infrastructure drift | [Iran shutdown study, FOCI 2026](https://www.petsymposium.org/foci/2026/foci-2026-0016.php) | Protocol health changes before/during/after a disruption; UDP failure may be generic infrastructure fault | Expiring time-stratified evidence, per-protocol state, change-point controls and `INCONCLUSIVE` attribution |
| Mobile bootstrap/config and DNS/route leak | [MVPNalyzer, NDSS 2026](https://www.ndss-symposium.org/ndss-paper/mvpnalyzer-an-investigative-framework-for-auditing-the-security-privacy-of-mobile-vpns/) + known implementation class | Cleartext or replaceable config, IPv4/IPv6/DNS bypass, tracker leakage or connectivity loss | Authenticated bootstrap, fail-closed guest/device route-change matrix, no stable ad ID, full leak audit before any mobile release |
| Signed-policy replay/compromise | Strict endpoint-policy path implemented; independent audit and fleet rollout absent | Rollback к vulnerable carrier/pin или silent authority expansion | Fixed COSE/CBOR profile, offline-root keysets, immutable enrolled `service_id` set, Active-only candidate signer, epochs/expiry/persistent floors and complete `86400 s` overlap. Это continuity, не containment: compromised Active signer всё ещё может добавить attacker pin рядом со старым; Phase-4 threshold service registry/transparency не реализованы |
| Destination-side VPN detection | Policy/field evidence | RU application rejects foreign/VPN exit | RU services direct where authorized; not solvable by carrier bytes alone |

DoS tradeoff is explicit. WireGuard authenticates its first initiator flight and
can use cookie replies under load. Shadowpipe instead sends a fixed cheap server
PSK proof first so a fake server cannot solicit a client PSK proof. Therefore an
unknown `kid` that already passed the REALITY carrier token receives one inner
response rather than a silence guarantee. Global admission and monotonic
deadlines bound concurrent RNG/full-scan/HMAC work; there is currently no per-IP
cookie, per-source quota, or silence-under-load guarantee. An authorized hostile
device can still reach KEM work.

The exact-replay store is a fixed `96 B` header plus 16,384 authenticated slots
of `96 B`, exactly `1,572,960 B`, with at most 64 expiry removals per admission.
It records keyed session-ID digests through slot write + `fdatasync` before the
accepted flight and uses absolute `token_time + skew_window` expiry, so
committed state survives a same-host restart. Replay, corruption, saturation,
lock poison and I/O failure all fail forward. This is not an availability
guarantee: a leaked short-ID holder can force sync work, saturate the store and
temporarily divert legitimate fresh admissions to cover. Nor is it a fleet
claim: loss/recreation of the store with the same static key is a cold-start
memory loss; replicas sharing one REALITY static secret require a linearizable
reserve-before-flight operation equivalent to `SETNX + TTL`, not eventual
consistency. Otherwise each replica must use a unique static secret.

## The 16 KiB contradiction is load-bearing

Repo evidence currently says:

- raw RU→NL: 155/155 flows × 2 MiB complete, including concurrency 16;
- Shadowpipe-shaped flow: passed about 0.8–2.5 MB (decimal) before implementation faults;
- two later manual Chrome-TLS sessions completed 20 MiB each without stall;
- volume guard caused roughly three orders of magnitude throughput loss.

Therefore the accepted state is `T0 / UNKNOWN_CONDITIONAL`, not «per-5-tuple proven». Plausible predicates include protocol classification, port, endpoint list, operator, ASN and time. A threshold observed in a third-party report is a prior for experiments, not a constant in production code. VM threshold emulation validates the harness only.

## Security boundaries

### Client / Mac boundary

The Mac is a protected production workstation. Forbidden during research:

- stop/restart/signal/config edit of sing-box;
- route, DNS, PF, NetworkExtension or system proxy mutation;
- host TUN creation, host `netem`, packet injection or `sudo` network commands;
- binding test services to public interfaces;
- reusing live subscription material in manifests or captures.

A macOS sandbox does not create an independent Darwin network stack and is not a
safe containment boundary for native TUN/route testing. The approved split is
read-only/build work on the resident Mac, Linux mutation in an isolated
disposable VM clone, and future native macOS mutation only in a separate macOS
VM or physical Mac. See
[`mac-host-isolated-lab.md`](mac-host-isolated-lab.md).

### VM boundary

All impairment, firewall, qdisc, namespaces, test routes and disposable
censor/relay services live inside a disposable clone of the dedicated stopped,
isolated OrbStack source base. Source enters through bounded stdin and sealed
evidence exits through validated bounded stdout; no Mac mount or forwarded SSH
agent is allowed. Parallels Windows 11 ARM64 is only a
portability/private-socket control and receives no
route/firewall/DNS/impairment mutation. Guest state is destroyed after the run;
the host network must not need rollback. Experiments use owned endpoints and
bounded rates; no Internet-wide probing.

### OS-TUN / route boundary

Current `--auto-route` is a Linux-first implementation. Configuration requires
`--tunnel --kill-switch --dns` and rejects invalid/non-Linux use before
DNS/socket/TUN or host mutation; runtime ordering arms the kill-switch before
bypass/default routes and DNS pinning. Run
[`20260716T173837Z-18283-m8K2po`](../tests/tun/results/20260716T173837Z-18283-m8K2po/RESULT.md)
pins tested executable commit `81f188f772cc6b674fde748a361691f1bda19691`
and adds scoped
V/S, E1 synthetic Linux evidence. A real `c0 -> c1` default-route replacement
produced exact `DefaultRouteChanged`; generation 1 exited status 1 while strict
durable lockdown remained active, then a distinct generation 2 reached
`Active` with its bypass on `c1`. A real promiscuous observer generated a
PROMISC-only link notification without changing the generation-2 PID/start time
or restart count. Directional client-egress IPv6 pcaps were empty while `SP6`
DROP counters increased. Manager-stop terminated the live generation 2,
suppressed generation 3 and preserved IPv4/IPv6 blocking until explicit
release. ICMP/TCP/UDP/DNS, a verified 64 MiB transfer and carrier-cut recovery
within a seven-second upper bound passed; 745 checksum entries, host safety,
clone cleanup, source isolation and secret scans were valid.

This is an IPv4 tunnel plus connected-IPv6 OUTPUT-block proof in a private
Linux namespace. It does not exercise a real systemd PID 1 manager,
resolver/DHCP changes, suspend/resume, an IPv6 tunnel, native Windows/macOS
networking, production paths or censor behavior. The earlier full-TUN run
[`20260716T123535Z-91294-70zWb7`](../tests/tun/results/20260716T123535Z-91294-70zWb7/RESULT.md)
remains a valid captured-source snapshot, not current executable-source
evidence. Delivered
marker absence from a bounded carrier pcap remains a regression heuristic, not
cryptographic proof.

### Signed endpoint-policy boundary — IMPLEMENTED, SCOPE-LIMITED

The trust anchor is a pinned offline root, separate from tunnel endpoints. It
signs keyset schema v1 containing authorized online Ed25519 policy keys (`kid`,
validity, status); an online key cannot replace the root. Endpoint-policy schema
v2 is strict `COSE_Sign1` over deterministic CBOR and binds keyset/policy epochs,
sequence, issue/not-before/expiry times, predecessor hash, endpoint authority,
REALITY authentication material and server-pin overlap. Version 1 endpoint
policy is rejected explicitly; migration requires a new authenticated enrollment
event rather than a fallback decoder.

Acceptance verifies the fixed protected profile, signature and canonical bytes
before semantics, enforces bounded validity, and atomically persists independent
keyset and policy floors plus accepted hashes and a wall-clock floor. Raising the
keyset epoch cannot reset the policy floor. Lower coordinates, same-coordinate
forks, gaps, broken predecessor chains, rollback and expired objects fail closed;
an exact accepted object is an idempotent no-op. Root/online key and server-pin
rotations have explicit predecessor and overlap constraints. The exact sorted
`service_id` set accepted at genesis is immutable across successors; adding,
removing or renaming service authority requires a new authenticated enrollment
or schema. A candidate policy signer must be `Active`; `Retiring`/`Revoked`
keys verify only historical state. New key/pin introduction and
`Active -> Retiring` require policy/keyset/material usability through the full
`86400 s` overlap. Removal/revocation follows only after elapsed overlap, and a
later contiguous keyset may omit already revoked keys.

Overlap is rollout continuity, not compromise containment. A compromised
`Active` online signer can add an attacker pin alongside an old valid pin while
obeying every overlap rule. A separately root/threshold-authorized service
registry, transparency log/witnessing and operational recovery are Phase-4
`E0`, not current properties.

Orderly runtime expiry writes `<policy-state>.expired-v1`, a fixed 132-byte
`SPPOLEX1` tombstone containing root identity, exact policy hash, coordinates,
signed expiry and a domain-separated checksum. The same hash cannot be
reactivated after wall-clock rollback once this same-storage checkpoint is
durable, and a stale runtime cannot tombstone a successor because it reloads the
exact current anchor under lock. This is not trusted time: storage
snapshot/rollback can revert state and tombstone together, and crash/power loss
before checkpoint remains open.

Policy v2 separates signed canonical `locator_name` from REALITY `sni`; neither
defaults to the other. DNS can only select a subset of the exact signed IPv4
authority and cannot construct authentication state. Host additions are staged
`allow -> exact route -> publish`; retirement depublishes first and waits for
socket leases before `deny -> route remove`. During total carrier outage there
is no underlay DNS. The client may restore the full signed authority once per
failure epoch and resumes tunneled DNS after a carrier succeeds.

This enforcement covers the current signed REALITY endpoint path. It does not
make the offline causal replay an authenticated policy producer, implement the
full `DENY`/`PROTECTED_ONLY`/`DIRECT_ALLOWED` activation state machine, or prove
censor availability. The fixed signer profile emits protected-only REALITY/TCP;
broader traffic-class activation remains a separate design gate.

### Crash-recovery boundary — IMPLEMENTED, SCOPED MATRIX PASS

Every Linux TUN run holds the host-state lease. An anchored bounded WAL records
TUN, exact routes, static/dynamic firewall and resolver-exchange intent before
mutation, and startup recovery runs before policy/DNS/socket/TUN creation.
Recovery accepts only complete journal-derived owner and namespace evidence,
preflights all resource groups, retains the firewall on conflict or incomplete
proof, and releases it last.

Production TUN is non-persistent. Recovery never uses `RTM_DELLINK` or deletes
by name/ifindex; a surviving or reused interface is a conflict. Server named TUN
creation and explicit named client TUN creation use `IFF_TUN_EXCL`; unnamed
client creation retains kernel name allocation. Route/firewall subprocesses
have bounded time and output, process-group termination and guaranteed child
reap; they remain trusted executables rather than a sandbox boundary.

Captured-source run
[`20260716T124109Z-93828`](../tests/host-recovery/results/20260716T124109Z-93828/FINAL-RESULT.md)
sealed 29/29 fresh-namespace scenarios and 1443/1443 checksum entries. It covers
schema-v3 eight-resource WAL cuts and recovery markers under same-boot
`SIGKILL`, including durable conflict behavior. It does not cover kernel reboot,
torn writes or power-loss storage semantics, and it is not validation of the
current executable source.

A separate
[`20260716T124706Z-34564-reboot`](../tests/lockdown/results/20260716T124706Z-34564-reboot/RESULT.md)
cell changed boot IDs and proved an early-userspace native-nft local OUTPUT
barrier before networkd, loopback allowance, non-loopback IPv4 denial and
explicit release across 650/650 checksum entries. It has no paired tunnel and no
production/initrd/L2/FORWARD claim. Both results are `field_evidence=false`. See
[`phase3-production-safety.md`](phase3-production-safety.md).

Native Linux ARM64 captured-source portability run
[`20260716T122834Z-linux-arm64-current`](../tests/portability/results/20260716T122834Z-linux-arm64-current/RESULT.md)
verified 342/342 entries for frozen source manifest
`fd5ebffc5b820ec8ac037aa3e9fea154c62576d7a276fa923168e5f4b4a84b95`,
including both workspace test feature sets and strict Clippy. Later
documentation-only finalization left the 165 non-Markdown source files
unchanged relative to that capture at the time of the recorded recheck. Later
executable network-change work means this is now a frozen snapshot rather than
current executable-source evidence. It made no privileged network mutation.
Windows 11 ARM64 run
[`20260716T125113Z-36840-dd0c2571`](../tests/windows/results/20260716T125113Z-36840-dd0c2571/RESULT.md)
verified 891/891 entries for H2 no-TUN v3 auth, missing-pin/unenrolled negative
controls and exact 1 MiB echo. Its 5,072,384-byte PE SHA-256 is
`2734e79f98866910aa8e0386af4ff630191b0a72fd1945177f078cb69d500bad`.
Neither run is current executable-source native Windows TUN, privileged Linux
networking, censorship or production evidence.

Mac host-safety evidence is bounded before/after observation, not continuous
monitoring. Loaded PF runtime remained unavailable without privilege and is not
claimed. The current runner binds opaque IDs, requires a dedicated isolated
source base and disposable clone, rejects Mac mounts/SSH forwarding/working
guest-to-host command channels, and allows clone deletion by name only after
fresh name-to-ID equality followed by absence proof. Unrelated same-host
lifecycle operators remain outside the trust boundary.

### Relay boundary

A domestic/cloud relay is assumed KYC-visible, revocable, observable and potentially malicious or compromised. It must not be a secrecy, authentication or anonymity anchor; it may log/correlate metadata, selectively fail and forge health reports. The research design stores no end-user identifiers or long-lived bytes-plane secrets on a relay, authenticates the end-to-end bytes plane independently, treats relay telemetry as untrusted input, and does not infer legal safety from technical success.

## Explicit non-goals

- «Uncatchable» or information-theoretically invisible bulk VPN.
- Solving an IP allowlist with a new byte pattern.
- Calling a separate-origin probe «degradation symmetry».
- Hiding congestion through FEC or sending repair traffic outside congestion control.
- Treating per-session randomization as protection from destination topology.
- Treating RTT padding as proof against a multi-feature detector.
- Shipping a relay/provider technique solely because it worked once.

## Claim gates

| Gate | Required evidence | What may be said afterwards |
|---|---|---|
| G0 — deterministic correctness | Unit/integration + sustained transfer in VM | «Implementation handles the tested trace» |
| G1 — censor-emulator discrimination | Harness distinguishes 5-tuple/destination/classifier models under preregistered VM rules | «Harness identifies the injected model» |
| G1F — single field observation | One authorized, timestamped bounded result with meaningful byte floor | «One observation on this path/operator/window»; no repeatability claim |
| G2 — repeated field scope | Independent repeat in the same declared path/operator/window stratum | «Repeatedly observed in this narrow stratum» |
| G3 — causal crossover | Randomized AB/BA, co-routed controls, multiple strata, effect CI | «Carrier change caused the scoped effect» |
| G4 — operational canary | Longitudinal, rollback-safe, independent replication | «Suitable as opt-in for measured strata» |

Failure taxonomy is mandatory: `connect_fail`, `policy_drop`, `silent_stall`, `rate_degrade`, `remote_close`, `crypto_error`, `framing_error`, `local_timeout`, `measurement_fault`. A no-target-event flow at a preregistered fixed horizon is right-censored. Successful payload completion and implementation failures are distinct terminal/competing causes; crypto/framing/process faults are not silently treated as non-informative censoring. Unknown attribution is `INCONCLUSIVE`.

## Primary references

- [WireGuard Protocol and Cryptography](https://www.wireguard.com/protocol/).
- Sun and Shmatikov, [Differential Degradation Vulnerabilities in Censorship Circumvention Systems](https://arxiv.org/abs/2409.06247).
- Fenske and Johnson, [Bytes to Schlep? Use a FEP](https://arxiv.org/abs/2405.13310).
- Fifield, [Comments on certain past cryptographic flaws affecting fully encrypted censorship circumvention protocols](https://eprint.iacr.org/2023/1362.pdf).
- Günther, Stebila and Veitch, [Obfuscated Key Exchange](https://eprint.iacr.org/2024/1086.pdf), CCS 2024.
- Wu et al., [How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic](https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi), USENIX Security 2023.
- Xue et al., [Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes](https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting), USENIX Security 2024.
- Sabzi et al., [NetShaper](https://www.usenix.org/conference/usenixsecurity24/presentation/sabzi), USENIX Security 2024.
- Wails et al., [On Precisely Detecting Censorship Circumvention in Real-World Networks](https://www.ndss-symposium.org/ndss-paper/on-precisely-detecting-censorship-circumvention-in-real-world-networks/), NDSS 2024.
- Hanlon et al., [Detecting VPN Traffic through Encapsulated TCP Behavior](https://www.petsymposium.org/foci/2024/foci-2024-0016.php), FOCI 2024.
- Zohaib et al., [Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of China](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib), USENIX Security 2025.
- Wang et al., [Is Custom Congestion Control a Bad Idea for Circumvention Tools?](https://www.petsymposium.org/foci/2025/foci-2025-0001.php), FOCI 2025.
- Xue et al., [The Discriminative Power of Cross-layer RTTs in Fingerprinting Proxy Traffic](https://www.ndss-symposium.org/wp-content/uploads/2025-966-paper.pdf), NDSS 2025.
- Kamali and Barradas, [Huma](https://www.ndss-symposium.org/wp-content/uploads/2026-f328-paper.pdf), NDSS 2026.
- Pulls et al., [Ephemeral Network-Layer Fingerprinting Defenses](https://petsymposium.org/popets/2026/popets-2026-0022.pdf), PoPETs 2026.
- Kuhn et al., [RFC 9265: FEC Coding and Congestion Control](https://www.rfc-editor.org/rfc/rfc9265.html).
- Cawthon and Fifield, [Fountain codes in censorship circumvention rendezvous](https://www.petsymposium.org/foci/2026/foci-2026-0011.php), FOCI 2026.
- Lange et al., [Towards Automated DNS Censorship Circumvention](https://www.petsymposium.org/foci/2026/foci-2026-0001.php), FOCI 2026.
- Seidenberger et al., [NinjaDoH](https://www.ndss-symposium.org/wp-content/uploads/madweb2026-6.pdf), MADWeb 2026.
- Tolley et al., [Architectural VPN Vulnerabilities, Disclosure Fatigue, and Structural Failures](https://www.petsymposium.org/foci/2026/foci-2026-0007.php), FOCI 2026.
- Jois et al., [Assemblage](https://www.petsymposium.org/foci/2026/foci-2026-0005.php), FOCI 2026.
- Sheffey et al., [Geedge Cases](https://www.petsymposium.org/foci/2026/foci-2026-0006.php), FOCI 2026.
- Wang et al., [MVPNalyzer](https://www.ndss-symposium.org/ndss-paper/mvpnalyzer-an-investigative-framework-for-auditing-the-security-privacy-of-mobile-vpns/), NDSS 2026.
- Wang and Cho, [Who Carries Tor?](https://www.petsymposium.org/foci/2026/foci-2026-0014.php), FOCI 2026.
- [Insights into an Iranian Internet Shutdown](https://www.petsymposium.org/foci/2026/foci-2026-0016.php), FOCI 2026.
- Habib et al., [Understanding the "Airport" Censorship Circumvention Ecosystem in China](https://arxiv.org/abs/2606.18427), 2026 preprint.
- Wampler et al., [ProtoScan: Measuring censorship in IPv6](https://arxiv.org/abs/2508.07194), 2025 preprint.
- Singh et al., [Not All Roads Lead to Rome](https://arxiv.org/abs/2605.30692), 2026 preprint.
- [TUF specification 1.0.35](https://theupdateframework.github.io/specification/latest/).
- [IETF Key Transparency Architecture draft-09](https://datatracker.ietf.org/doc/html/draft-ietf-keytrans-architecture-09).
- Brorsson et al., [Consistency-or-Die](https://eprint.iacr.org/2024/879.pdf).
- [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000.html),
  [RFC 8684: MPTCP](https://www.rfc-editor.org/rfc/rfc8684.html),
  [QUIC multipath draft-21](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/),
  [RFC 9049](https://www.rfc-editor.org/rfc/rfc9049.html),
  [RFC 9217](https://www.rfc-editor.org/rfc/rfc9217.html), and
  [RFC 8305](https://www.rfc-editor.org/rfc/rfc8305.html).
- Xue et al., [Bypassing Tunnels: Leaking VPN Client Traffic by Abusing Routing Tables](https://www.usenix.org/conference/usenixsecurity23/presentation/xue), USENIX Security 2023.
- [RFC 8032: EdDSA](https://www.rfc-editor.org/info/rfc8032), [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949.html), [RFC 9052: COSE](https://datatracker.ietf.org/doc/html/rfc9052), and [The Update Framework](https://theupdateframework.github.io/specification/latest/).

Project-specific claim status is normative only in [`claims-ledger.md`](claims-ledger.md).
