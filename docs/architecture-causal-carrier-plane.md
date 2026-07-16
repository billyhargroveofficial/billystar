# Architecture: Causal Carrier Plane

Статус: research architecture, не production claim. Центральная **гипотеза о новизне** — совместить выбор topology с причинно интерпретируемым доказательством того, почему carrier помог или не помог. Это не утверждение «first/new»: оно остаётся `E0`. Текущая [versioned related-work matrix](related-work-matrix-2026.md) задаёт первичные границы, но сама не закрывает novelty review: нужны воспроизводимый systematic search и независимая проверка.

## 1. Design thesis

Shadowpipe разделяется на три независимых плана:

```text
                         signed, secret-free policy snapshot
                                      |
                                      v
 +------------------+       +----------------------+       +------------------+
 | Causal Observer  |------>| Carrier Policy Gate  |------>| Carrier Adapters |
 | pairs/randomizes |       | OFF/LAB/CANARY/ON    |       | direct/relay/... |
 | measures/ledger  |       | fail-safe fallback   |       +---------+--------+
 +---------+--------+       +----------------------+                 |
           |                                                          v
           | aggregate telemetry                         +----------------------+
           +-------------------------------------------->| Bytes Plane          |
                                                        | hybrid key schedule  |
                                                        | + classical AEAD     |
                                                        | framing/mux/TUN       |
                                                        +----------------------+
```

- **Bytes plane** сохраняет confidentiality/authentication и переносит packets.
- **Carrier plane** определяет destination, relay chain и transport topology.
- **Causal observer plane** не находится в hot path: он preregisters pairs, рандомизирует порядок, собирает aggregate outcomes и открывает/закрывает policy gates.

Отказ observer/controller не должен менять живой маршрут. На Mac весь новый plane по умолчанию `OFF`; лабораторная политика применяется только внутри disposable VM.

### 1.1 Cryptographic boundary

Текущий bytes plane не использует «post-quantum AEAD». Он подаёт shared secrets от **ML-KEM-768 и ephemeral X25519**, вместе с transcript hash и обоими random, в HKDF-SHA-256, а payload защищает обычный **ChaCha20-Poly1305 AEAD**. Это гибридный key-establishment input и classical symmetric record protection; до формального analysis combiner не следует заявлять более сильное свойство.

Статический ML-KEM public key аутентифицируется SHA-256 fingerprint pin.
**Текущий universal client-инвариант:** каждый режим требует ровно один
32-byte fingerprint через `--server-fp` или `fp=` для каждого URI endpoint.
Missing/malformed pin отвергается до reservation trace, DNS, socket и TUN;
`ClientConfig` не представляет `None`, а mismatch проверяется constant-time и
обрывает inner handshake до encapsulation/application-controlled bytes. В
текущем клиенте нет unpinned lab-режима.

Runtime absence/mismatch gap закрыт. Текущая endpoint-policy v2 реализует signed
distribution, expiry, persistent anti-rollback floors и overlap rotation для
fixed protected-only REALITY/TCP endpoint profile. Remaining deployment debt —
authenticated fleet/root enrollment, root-identity distribution, release
manifests, rollback operations, compromised-online-signer containment и
independent review. Pin, полученный из той же неаутентифицированной tunnel
session, никогда не становится доверенным.

32-bit `SHADOWPIPE_MAGIC` только разделяет несовместимые wire builds: он
наблюдаем, не секретен и не заменяет ML-KEM fingerprint pin. Все
раздельные target/OS сборки одного release обязаны получать одинаковое
явное значение; independent random defaults ожидаемо fail closed на
handshake и не являются interoperable artifacts.

## 2. Components

### 2.1 Carrier Adapter

Минимальный интерфейс:

```text
prepare(trial_context) -> opaque_candidate
connect(opaque_candidate) -> bidirectional_stream
observe() -> transport_metrics
close(reason)
```

Adapter не получает host route privileges. Начальные реализации:

1. `direct`: single-hop exit, отрицательный/операционный baseline;
2. `whitelist-relay`: client → allowed-looking cloud relay → same controlled exit;
3. `serverless`: только после отдельного feasibility gate; CensorLess — design input, не RU-whitelist proof;
4. `cover-native/deferred`: Huma/Ciliate-inspired research adapter, не bulk default.

Capabilities описывают не только destination/provider, но и известные
`transit_asn` failure domains. Два nominally разных endpoint/provider не
считаются независимыми, пока route evidence не исключает общий транзитный
chokepoint; отсутствие route evidence остаётся `unknown`, а не diversity proof.

### 2.2 Pair Coordinator

Создаёт **treatment** и **real-cover control**, совпадающие по максимально возможным nuisance variables:

- один client VM, access network, time block и address family;
- один provider edge/destination class и, для symmetry claim, общий bottleneck;
- одинаковый payload class и observation floor;
- independent connection IDs, чтобы не спутать application state;
- AB/BA sequence выбирается seed из immutable manifest.

Если cover и treatment идут к разным origin/ASN/queues, результат можно использовать для availability comparison, но нельзя называть degradation symmetry.

### 2.3 Intervention Driver

В VM он создаёт loss/delay/rate/reordering только на scoped veth/netns. В field mode он не «атакует Интернет»: intervention — выбор carrier/topology или заранее разрешённое bounded test condition. Никаких host PF/route/DNS mutations.

### 2.4 Metrics Collector

Текущая schema v1 — **session-ephemeral raw trace**, а не анонимный aggregate.
Она закрыта для endpoint strings и free-form errors, но точные timings/byte
counts всё ещё коррелируемы. Реализованный v1 содержит только:

- dial duration/outcome и transport kind;
- path RTT, congestion window, loss ppm и delivered bytes/s, когда producer
  реально умеет их измерять;
- directional payload/wire bytes, transfer duration, stall lifecycle и
  terminal close taxonomy;
- opaque run/experiment/artifact IDs, exact start time, software version,
  node role и environment.

TTFB, retransmission/ECN counters, application RTT, carrier/topology, stratum,
UTC bucket и явные manifest/git/binary hashes — **planned v2/reducer fields**,
а не свойства текущей schema. `artifact_id` остаётся opaque pseudonym и сам по
себе не доказывает provenance.

Не сохраняются destination browsing history, packet payload, subscription URL,
keys, public production IP inventory или stable client identifier. Перед любым
export отдельный пока не реализованный reducer обязан bucket/clip timing и
volumes, применить retention policy, присоединить проверяемую provenance и
выпустить aggregate с manifest/git/binary hashes, UTC bucket, topology и
stratum. До этого raw schema не называется export-safe.

### 2.5 Policy Gate — endpoint enforcement implemented; causal promotion target

Здесь теперь разделены два разных статуса. Signed REALITY endpoint path
реализует строгую policy v2, persistent anti-rollback state, live bounded DNS
transactions и crash recovery. Causal selector всё ещё offline/shadow-only: он
не аутентифицирует producer/artifact evidence и не управляет live traffic-class
promotion. Следующая state machine остаётся target для causal activation, а не
описанием уже включённого controller.

State machine:

```text
OFF -> LAB_VALIDATED -> FIELD_SHADOW -> CANARY -> ENABLED_FOR_STRATUM
 ^          |                |             |              |
 +----------+----------------+-------------+--------------+
             any falsifier, drift, leak, or safety fault
```

Переходы требуют artefacts, а не ручного флага «looks good». Rollback означает выключение нового adapter внутри guest/client policy; он никогда не означает остановку Mac sing-box.

#### Signed-policy format and lifecycle — implemented endpoint profile

Реализованный wire chain использует одну строгую подписываемую форму:
`COSE_Sign1` по [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052)
над deterministic CBOR по
[RFC 8949 §4.2](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2),
с Ed25519 по [RFC 8032](https://www.rfc-editor.org/info/rfc8032). Float,
indefinite lengths, duplicate/unknown fields и альтернативные protected profiles
отвергаются. Root-signed keyset остаётся schema v1; endpoint-policy обязана быть
schema v2 и подписана авторизованным online key. Policy v1 отвергается явно без
fallback, поэтому v1→v2 требует нового authenticated enrollment.

```text
schema_version=2, policy_epoch, sequence,
issued_at, not_before, expires_at, previous_payload_hash,
services[].pins[], services[].endpoints[] {
  ipv4, port, locator_name, sni,
  reality_x25519_public_key, reality_short_id
}, experiment_evidence[]
```

Клиент сначала проверяет fixed protected profile, signature, canonical re-encoding,
schema, `not_before <= now <= expires_at` и bounded validity. Он атомарно хранит
**независимые** floors для keyset и policy coordinates, accepted payload hashes и
maximum observed wall-clock. Новый keyset epoch не может сбросить policy floor.
Lower coordinate, same-coordinate different hash, broken predecessor chain,
gap, rollback часов и expiry отвергаются; exact same coordinate/hash — только
idempotent no-op, пока этот hash не отмечен durable expiry tombstone. При
orderly runtime expiry клиент до sealing fail-closed host state атомарно
публикует под policy lock отдельный fixed-size `0600` tombstone: offline-root
identity, exact policy hash, `(policy_epoch, sequence)`, подписанный
`expires_at`, domain-separated checksum. Реализованный формат — ровно 132 байта,
magic `SPPOLEX1`, файл `<policy-state>.expired-v1` на том же storage, что и
основной policy state. После restart этот же hash не может снова стать active
даже при rollback wall clock; другой hash обязан пройти обычный authenticated
successor chain. Перед записью store перечитывает current anchor и требует exact
identity match, поэтому stale runtime не может tombstone уже принятый successor.
Cached last-known-safe policy действует лишь до `expires_at`.

Это не trusted-time claim для crash/power-loss/different boot. Гарантия требует,
чтобы orderly process действительно дошёл до expiry path и fsync tombstone
завершился. Snapshot/rollback или потеря того же storage может откатить основной
state и tombstone вместе; crash/power loss до checkpoint и rollback часов на
другом boot также остаются residual gates для отдельного trusted-time/monotonic
state source.

Отдельный offline root identity подписывает versioned keyset online policy keys
с `kid`, validity interval и status. После genesis exact sorted vector
`service_id` неизменяем между successor policies: add/remove/rename service
authority требует нового authenticated enrollment или новой schema, а не
обычного online update. Candidate policy обязан быть подписан ключом со status
`Active`; `Retiring`/`Revoked` keys остаются пригодны только для проверки
исторически принятого state. Rotation требует explicit predecessor и полный
`86400 s` overlap: новый key/pin публикуется заранее, policy/keyset и
перекрывающий material должны оставаться usable весь интервал, а
`Active -> Retiring` и последующее removal/revocation проходят только после
этих проверок. Уже `Revoked` online keys разрешено удалить в более позднем
contiguous keyset, чтобы bounded keyset не исчерпывался навсегда.

Эти правила доказывают continuity, а не containment компрометации. Владелец
скомпрометированного `Active` online signing key может выпустить successor,
который добавляет attacker-controlled pin рядом со старым pin и соблюдает
overlap. Поэтому root/threshold-authorized service registry и transparency/
witnessing — отдельный Phase-4 `E0` research gate, а не реализованное свойство.
Root rotation требует отдельного software/trust-store enrollment; online policy
не может заменить root. Модель заимствует threat categories у
[TUF 1.0.35](https://theupdateframework.github.io/specification/latest/), но
Shadowpipe не заявляет полную TUF-conformance, roles, thresholding или mirrors.
[RFC 8785 JCS](https://www.ietf.org/rfc/rfc8785.html) служит лишь аналогией
canonical-signing discipline: wire format здесь CBOR.

#### Durable REALITY replay admission — implemented, same-host only

Production server до bind открывает exclusive same-host lease и полностью
проверяет HMAC-authenticated replay file, связанный со static REALITY secret.
Формат фиксирован: header `96 B` плюс `16,384` slots по `96 B`, итого
`1,572,960 B`. В store попадает keyed digest session ID с абсолютным
`valid_until = token_time + skew_window`; slot write и `fdatasync` завершаются
до accepted REALITY flight. Replay, torn/corrupt state, runtime I/O error,
lock poison и saturation fail forward к genuine service.

Это не replicated replay service. Потеря/новый cold-start store при повторном
использовании того же static key забывает ещё живые admissions. Реплики с общим
static key требуют linearizable reserve-before-flight primitive, эквивалентного
`SETNX + TTL`; eventual consistency недостаточна. Имеющий валидный online
`short_id` противник может навязать sync work и заполнить bounded slots, временно
отправляя fresh legitimate clients к cover. Практический baseline — unique
REALITY static key и локальный store на replica, пока shared linearizable
admission не реализован.

#### Fail-closed by traffic class — causal activation target

Каждое rule явно задаёт один из трёх классов:

- `DENY`: ни один carrier не разрешён;
- `PROTECTED_ONLY`: новый flow блокируется, если нет подписанной непросроченной policy и healthy allowlisted carrier; direct fallback запрещён;
- `DIRECT_ALLOWED`: direct допустим только если это явно разрешает локальный static baseline; удалённая policy не может расширить это множество.

Unknown class/rule, invalid signature, rollback, expired policy и policy-engine fault должны выбирать более строгий compiled baseline, а не `direct`. Текущий signer выпускает единственный fixed `PROTECTED_ONLY` REALITY/TCP endpoint profile; general `DENY`/`DIRECT_ALLOWED` activation и evidence-driven promotion ещё не реализованы. После expiry current signed endpoint loop прекращает новые dials и сохраняет fail-closed host ordering.

## 3. Causal paired crossover

Для каждого block `i` измеряются treatment `T` и cover `C` до и после intervention `z`. Основная preregistered estimand:

```text
DiD_i = (Y_T,after - Y_T,before) - (Y_C,after - Y_C,before)
```

Для goodput предпочтителен `Y = log(goodput + epsilon)`, чтобы сравнивать относительное падение. Для loss/RTT знак и non-inferiority margin задаются в manifest заранее. Нулевая DiD означает одинаковую **измеренную response curve в этом диапазоне**, а не indistinguishability.

Порядок intervention/control рандомизируется (`AB`/`BA`), между periods есть washout, pairs co-route максимально близко по времени. Анализ учитывает block/operator/day как random or fixed effects; confidence interval и exclusion rules фиксируются до просмотра результата.

### Acceptance for a symmetry hypothesis

Нужны одновременно:

1. positive control подтверждает, что intervention реально изменил path condition;
2. cover и treatment имеют общий bottleneck/destination class;
3. `DiD` лежит внутри preregistered non-inferiority band на нескольких impairment levels;
4. нет compensating tell: extra flows, fixed probes, periodic reconnects, abnormal FEC overhead;
5. результат воспроизведён вне netem на авторизованном field scope.

Netem способен доказать только controller correctness и отсутствие self-induced collapse.

## 4. Trigger-unit model selection

Volume response не кодируется как константа `16 KiB`. Causal plane хранит categorical model:

```text
T0 UNKNOWN_CONDITIONAL   current state
T1 FIVE_TUPLE            candidate
T2 DESTINATION_IP_PORT   candidate
T3 PREFIX_OR_ASN         candidate
T4 CLASSIFIER_X_TOPOLOGY candidate
T5 PATH_GLOBAL_OR_TIME   candidate
```

Model selection начинается только после положительного trigger reproduction. Flow без target event на заранее фиксированном observation horizon — **right-censored at horizon**, а не «freeze at max bytes». Успешное payload completion до horizon есть terminal competing outcome, если target stall уже не может возникнуть в этом trial. `crypto_error`, `framing_error`, process crash и локальный timeout — **implementation competing risks**, а не автоматическое non-informative censoring. Для onset нужны cause-specific hazards/cumulative-incidence curves; исключать можно только preregistered measurement-invalid observations, отчитывая их отдельно.

До выбора модели:

- volume guard остаётся opt-in/off;
- logical mux не считается countermeasure;
- connection rotation не получает production gate;
- any byte threshold — experiment parameter, не protocol invariant.

## 5. Degradation controller: bounded hypothesis

Если существует real cover flow на том же path, controller оценивает cover delivery rate `g_c(t)` и задаёт верхнюю границу treatment rate:

```text
g_hat_c(t) = robust_EWMA(delivered_cover_bytes / window)
r_t(t) <= beta * g_hat_c(t),  0 < beta <= 1
```

Это safety clamp, не новый congestion control. Нижележащий TCP/QUIC CC остаётся главным владельцем congestion response. Controller не увеличивает rate поверх CC и не использует padding, чтобы «замаскировать» collapse.

Критическая causal проблема: отдельный probe создаёт новый flow и может видеть другую очередь. Поэтому допустимы в порядке предпочтения:

1. signal от genuine carrier/cover, который уже несёт traffic;
2. sibling flow к тому же provider edge с доказанным shared bottleneck;
3. external probe только как coarse health signal, без symmetry claim.

Square-root covert-capacity bounds применимы лишь к реальному embedding in aggregate cover volume. Они не оправдывают arbitrary `sqrt(goodput)` pacer для обычного encrypted proxy.

## 6. FEC and congestion coupling

FEC — reliability actuator, не обход DPI. В соответствии с RFC 9265:

- repair symbols входят в тот же congestion budget;
- sender получает pre-recovery loss/ECN information и не скрывает congestion от CC;
- coding rate меняется медленнее CC и ограничивается manifest budget;
- useless repair ratio измеряется отдельно;
- на TCP app-FEC по умолчанию отсутствует; на QUIC/partial-reliability mode он отдельный experiment.

Если FEC улучшает delivered bytes ценой большей нагрузки на congested path, symmetry gate считается проваленным.

## 7. RTT alignment is a topology gate, not padding

NDSS 2025 fingerprint возникает у segmented proxies из-за несовпадения transport- и application-layer endpoints. Поэтому adapter публикует topology metadata:

```text
outer_transport_termination
observable_application_termination
backend_distance_class
expected_rtt_gap
```

Предпочтительная mitigation — co-location/termination alignment. Искусственная задержка ACK или response разрешена только в `003-rtt-alignment` внутри VM: она может ослабить один threshold, ухудшить CC и создать новый timing feature. Huma-style deferred reply тестируется как отдельная application protocol, не как универсальный VPN patch.

## 8. Rendezvous/control plane

Rendezvous carries only small signed endpoint/policy objects. FOCI fountain rendezvous is a candidate for a future cold-start channel. **Huma PIR is not a rendezvous result**: it is a Pung-based private mailbox/read mechanism in Huma's national-Intranet mode, and can inform a future low-rate mailbox adapter only after separate analysis. Bounds are explicit:

- not bulk data;
- no fixed polling cadence;
- signature + freshness + rollback protection;
- fountain fragments are public/opaque and reveal no key material;
- any PIR mailbox privacy claim is implementation-specific, scope-limited to mailbox retrieval and independently tested;
- bootstrap under a full allowlist remains unsolved until field evidence exists.

Control-plane failure returns to an unexpired cached last-known-safe policy or the stricter compiled baseline; it never accepts expired state and never edits host networking.

## 9. Carrier-specific gates

### Direct

Baseline for correctness and availability. It is not a whitelist solution. A TLS-terminating single-hop is a negative control for the specific cross-layer RTT gap, not a claim of timing invisibility.

### Whitelist relay

One July field observation has the distinct `E1F` single-observation tier and justifies research priority, not an `E2` repeatability claim. Graduation requires `002-whitelist-relay`: same exit/payload, randomized direct-vs-relay crossover, genuine allowlisted cover control, negative cloud-IP control, multiple operator/time strata. Relay is KYC/provider-visible and never an anonymity anchor.

### Serverless

CensorLess validates refresh/migration mechanics and cost in its evaluation. It does not establish that an FaaS edge belongs to a target allowlist. No adapter ships until provider policy, payload limits, address reachability and field pair all pass.

### Deferred/cover-native

Huma and Ciliate motivate response causality and degradation testing. Huma's PIR result concerns private mailbox retrieval in its Intranet mode, not endpoint rendezvous or a generic bulk proxy. They do not justify carrying arbitrary low-latency bulk. Such adapter starts as low-rate research only.

## 10. Implementation seams

Текущий causal observer/control milestone остаётся shadow-only и не подключён к
live TUN selection. Отдельно от него production client теперь имеет signed
REALITY endpoint runtime и Linux host-safety layer; их нельзя принимать за
evidence-driven causal promotion. Observer подключён только opt-in к no-TUN
`--loadtest`. До DNS/socket он резервирует private same-directory temp и
проверяет no-clobber hard-link + directory-fsync;
единый bounded deadline охватывает DNS, outer TCP/QUIC/TLS/REALITY и inner
authentication. Наблюдаемые outer/auth/timeout failures выпускают валидный
terminal `Pending` trace (`Dial + Close`), а crash может оставить только hidden
temp, не partial final JSON. Directory-fsync durability здесь Unix-only;
Windows сохраняет file sync + no-clobber hard link, но отсутствие directory
fsync и неготовый полный Windows client остаются production blocker. Реальные и
proposed seams:

```text
shadowpipe-core::carrier      stream adapters
shadowpipe-core::measurement  closed raw schema + bounded recorder
shadowpipe-core::control      conservative estimator + pure shadow selector
shadowpipe-core::pacing       bounded rate clamp + metrics, opt-in
shadowpipe-core::signed_policy strict COSE/CBOR policy v2 + rotations/floors
shadowpipe-core::endpoint     signed-authority coordinator + socket leases
shadowpipe-core::host_state   bounded WAL + typed fail-closed recovery model
shadowpipe-client             signed endpoint runtime + Linux host transactions;
                              no causal-selector activation
shadowpipe-causal-replay      validated trace -> health -> shadow verdict
experiments/*                 draft protocols; frozen manifests/results later
```

Для existing full-tunnel path реализован отдельный fail-closed CLI preflight:
`--auto-route` сейчас Linux-only и требует одновременно `--tunnel`,
`--kill-switch` и `--dns`; invalid combination aborts до DNS/socket/TUN/host
mutation. Runtime сначала включает kill-switch, затем carrier/SSH bypass,
split-default routes и DNS guard. Помимо code/unit evidence, run
[`20260716T123535Z-91294-70zWb7`](../tests/tun/results/20260716T123535Z-91294-70zWb7/RESULT.md)
дал scoped V/S, E1 synthetic OrbStack Linux IPv4 proof для TCP/UDP/ICMP/DNS,
64 MiB payload, fail-closed carrier cut/recovery с recorded upper bound `8 s`,
explicit lockdown release и 573/573 checksum entries. Отдельный planted foreign
persistent named TUN с пустым alias был отвергнут до network mutation:
`IFF_TUN_EXCL` вернул collision, interface/resolver остались exact unchanged,
underlay/carrier packets и proto-186 routes были zero, WAL отсутствовал.
Explicit named client TUN и server TUN теперь оба используют
`IFF_TUN_EXCL`; только unnamed client path оставляет имя kernel allocation.
Delivered marker без plaintext marker bytes в bounded carrier pcap —
regression heuristic, не cryptographic proof. Phase-3 добавил
signed-authority-bounded live DNS refresh,
`allow -> route -> publish` transactions, outage rehydration without underlay
DNS и all-resource WAL recovery. Current-source same-boot matrix
[`20260716T124109Z-93828`](../tests/host-recovery/results/20260716T124109Z-93828/FINAL-RESULT.md)
sealed 29/29 scenarios and 1443/1443 checksum entries. Отдельный reboot-lockdown
run
[`20260716T124706Z-34564-reboot`](../tests/lockdown/results/20260716T124706Z-34564-reboot/RESULT.md)
proved early-userspace local OUTPUT barrier before networkd and explicit
release, 650/650 checksum entries. Native Linux ARM64 current-source run
[`20260716T122834Z-linux-arm64-current`](../tests/portability/results/20260716T122834Z-linux-arm64-current/RESULT.md)
sealed 342/342 entries against the frozen-at-capture source manifest
`fd5ebffc5b820ec8ac037aa3e9fea154c62576d7a276fa923168e5f4b4a84b95`;
subsequent documentation-only finalization did not change its 165 non-Markdown
source files. Это unprivileged CPU/filesystem portability, не network proof.
Native Windows
11 ARM64 no-TUN H2 run
[`20260716T125113Z-36840-dd0c2571`](../tests/windows/results/20260716T125113Z-36840-dd0c2571/RESULT.md)
sealed 891/891 entries, exact 1 MiB echo и negative auth controls для
5,072,384-byte PE SHA-256
`2734e79f98866910aa8e0386af4ff630191b0a72fd1945177f078cb69d500bad`.
Same-boot `SIGKILL` не является power-loss
proof, reboot cell не содержит paired tunnel, и все перечисленные bundles имеют
`field_evidence=false`. До operational claim также нужны production/field
replication, IPv6 и отдельные native Windows/macOS TUN matrices. Mac routing
остаётся `NO_TOUCH`. Полный статус:
[Phase-3 safety](phase3-production-safety.md).

`DialTarget` пока является только typed boundary, не разрешением на egress.
До первого relay/serverless adapter обязательна отдельная target policy:
deny loopback, link-local, private/special-use и cloud-metadata ranges по
умолчанию; resolve-and-pin все адреса; повторно проверять после DNS resolution;
защищаться от rebinding; аутентифицировать запрос и ограничивать bytes/rate/time.
Без этого adapter остаётся disabled, чтобы control plane нельзя было превратить
в SSRF/proxy к внутренней инфраструктуре.

Текущий offline replay v2 требует одинаковые explicit experiment/artifact IDs,
exact `expected_window_refs` и общий window cohort у всех сравниваемых carriers,
но не аутентифицирует evidence attribution: IDs, scope/outcome, timestamps,
carrier capabilities, failure domains и grouping сейчас caller-declared.
Run-ID uniqueness
предотвращает повторный replay одного ID, но не доказывает
producer, manifest или binary provenance. На admission может влиять
только result, связанный с trusted signed manifest, producer
identity и artifact hash. Direction-matched observed `Transfer` может
служить workload proof; aggregate `Close` bytes — только consistency
ceiling, а не admission evidence.

No experiment code may call macOS route/DNS/PF/service APIs. Compile-time target guards and runtime `--lab-vm-only` attestation should reject a Darwin host for mutating experiment modes.

## 11. Phase-4 research programme — `E0`, not implemented

Следующий слой нельзя описывать как «готовую новую технологию». Это список
проверяемых adaptations/inferences из prior art:

1. **Threshold service authority + transparency.** Заимствовать role separation,
   threshold/quorum и compromise framing из
   [TUF 1.0.35](https://theupdateframework.github.io/specification/latest/);
   исследовать label/version/monitor/fork semantics из
   [IETF KEYTRANS architecture draft-09](https://datatracker.ietf.org/doc/html/draft-ietf-keytrans-architecture-09)
   и split-view consistency из
   [Consistency-or-Die](https://eprint.iacr.org/2024/879.pdf). Проектная
   inference: root/threshold-signed registry должен отдельно bind
   `service_id`, allowed pins, lifetimes и, возможно, REALITY identity/SNI/port.
   Ничего из threshold/transparency/witnessing пока не реализовано.
2. **Formally scoped FEP/OKey exchange.** Проверить wire/error/minimum-message
   surface по [FEP definitions](https://arxiv.org/abs/2405.13310), исторические
   oracle/non-uniform/replay failures по
   [Fifield](https://eprint.iacr.org/2023/1362.pdf) и active-probing/key-exchange
   model по [Obfuscated Key Exchange](https://eprint.iacr.org/2024/1086.pdf).
   Текущий REALITY + custom v3 не является реализацией этих constructions и не
   наследует их proofs.
3. **Causal path portfolio.** QUIC migration в
   [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html), MPTCP в
   [RFC 8684](https://www.rfc-editor.org/rfc/rfc8684.html),
   [QUIC multipath draft-21](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/),
   [QUICstep](https://petsymposium.org/popets/2026/popets-2026-0014.php),
   [RFC 9049](https://www.rfc-editor.org/rfc/rfc9049.html),
   [RFC 9217](https://www.rfc-editor.org/rfc/rfc9217.html) и
   [Happy Eyeballs v2](https://www.rfc-editor.org/rfc/rfc8305.html) делают
   migration, concurrency, multipath и path selection prior art. Возможный
   research delta сужается до authenticated evidence provenance +
   preregistered causal promotion + fail-closed policy, если systematic review
   и independent reviewer не найдут более близкий loop.
4. **Shaping without stealth overclaim.**
   [NetShaper](https://www.usenix.org/conference/usenixsecurity24/presentation/sabzi)
   даёт workload-side differential-privacy shaping, а
   [Differential Degradation](https://arxiv.org/abs/2409.06247) показывает
   active-censor response trade-off. Adaptation может быть только bounded
   experiment; она не доказывает camouflage, path availability или
   degradation symmetry.
5. **IPv6 and vantage diversity.**
   [ProtoScan](https://arxiv.org/abs/2508.07194) и
   [Not All Roads Lead to Rome](https://arxiv.org/abs/2605.30692) требуют
   отдельных address-family/resolver/provider/peering strata. IPv4 VM PASS и
   country label не переносятся на IPv6 или другой transit path.

## 12. Definition of done for the research architecture

- Claims ledger links every enabled policy to an experiment artefact.
- Novelty remains a hypothesis under the [versioned related-work matrix](related-work-matrix-2026.md) until reproducible systematic search and independent review delimit overlap with prior adaptive selection, multipath and causal-measurement systems.
- Trigger-unit harness correctly identifies injected VM models without false certainty on no-trigger data.
- Whitelist relay causal effect survives AB/BA crossover in at least two independent field strata before opt-in canary.
- RTT detector is reproduced before mitigation is evaluated.
- Blind spoofed-packet/NAT-response oracle is tested only in the isolated
  [`005-blind-tunnel-oracle`](../experiments/005-blind-tunnel-oracle/README.md)
  netns design before any high-risk mobile/TUN claim; no Internet injection is
  permitted.
- Degradation controller passes paired non-inferiority under netem, then remains explicitly `LAB_ONLY` until field replication.
- Every current and future client preserves mandatory server-pin preflight;
  current policy v2 distributes expiring overlap-rotated pin sets from the
  independently enrolled root/online-key chain. Exact sorted `service_id` set
  remains immutable after enrollment, candidate signer is `Active` only, and
  `86400 s` overlap is a continuity rule, not compromised-signer containment.
- Linux IPv4 full-tunnel, same-boot schema-v3 crash recovery and early-userspace
  reboot lockdown have separate completed synthetic privileged bundles for the
  current source; Linux ARM64 and Windows ARM64 additionally have bounded
  portability/no-TUN evidence. They do not combine into a production/field
  claim: IPv6, power-loss/torn-write durability, paired-tunnel reboot recovery
  and every other OS native TUN/rollback proof remain open.
- Any failure restores guest state without touching the Mac or its sing-box.
- No artefact contains secrets or production IP credentials.
