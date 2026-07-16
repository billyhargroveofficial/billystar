# Upstream platform audit: sing-box, sing-tun and Xray-core

Дата среза: 2026-07-16.

Статус: архитектурный input и implementation backlog. Этот аудит не является
импортом кода, production evidence, security endorsement upstream-проектов или
доказательством готовности native macOS/Windows VPN.

## Итоговое решение

Shadowpipe не превращается в fork, wrapper или переписанную версию sing-box либо
Xray. Исходная архитектура остаётся без изменений:

- собственный protocol v3 с ML-KEM-768, X25519, Ed25519, device PSK и
  обязательным server pin;
- собственная подписанная endpoint/pin policy и anti-rollback state;
- собственный REALITY admission с durable replay state;
- собственный end-to-end IP packet tunnel;
- собственный causal carrier plane;
- собственный transactional host-state WAL, ownership proof и fail-closed
  recovery.

Из upstream переносятся только независимо описанные требования к поведению ОС,
failure modes, lifecycle patterns, public-API choices и идеи тестов. Их
реализация должна быть написана заново через документированные Linux, Apple и
Windows API за существующей Shadowpipe platform boundary.

Целевая продуктовая топология несимметрична:

- production `shadowpipe-server` существует только для Linux VPS;
- Linux использует отдельные server-side egress/NAT/service механизмы и
  client-side TUN/route/DNS/kill-switch механизмы;
- macOS и Windows являются только production client targets;
- переносимый no-TUN server допустим на других ОС исключительно как явный
  loopback/VM development harness для protocol interoperability. Он не должен
  получать production credentials, REALITY listener, TUN или host-network
  mutation authority.

Главное продуктово-инженерное решение по IPv6:

1. inner IPv6 payload не является P0 для Linux Production Alpha;
2. IPv6 leak prevention является P0 на всех трёх ОС;
3. режим по умолчанию сейчас — `block`;
4. после него добавляется outer-only IPv6, включая отдельно проверенный NAT64;
5. полный inner IPv6 tunnel появляется только после route/DNS/firewall/PMTUD,
   recovery и leak matrices.

## Зафиксированные audit inputs

| Проект | Ревизия | Роль в аудите | Лицензия и граница |
|---|---|---|---|
| [sing-box](https://github.com/SagerNet/sing-box/tree/c8ee3497b25027f5f73bd88aba96ecf5009c37e0) | `c8ee3497b25027f5f73bd88aba96ecf5009c37e0` | Core lifecycle, routing, DNS, interface monitoring and platform abstraction | [GPL-3.0-or-later](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/LICENSE); no copying, translation, linking or vendoring into the current non-GPL tree |
| [sing-tun](https://github.com/SagerNet/sing-tun/tree/79ea1ac88855ae1e66c96dc162555161708efcd3) | `79ea1ac88855ae1e66c96dc162555161708efcd3` | Linux netlink/nftables, Windows Wintun/IP Helper/WFP and OS monitors | [GPL-3.0-or-later](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/LICENSE); behavior/specification reference only |
| [sing-box for Apple](https://github.com/SagerNet/sing-box-for-apple/tree/794eb1741f91765a91f1513e5639296503f072b2) | `794eb1741f91765a91f1513e5639296503f072b2` | `NEPacketTunnelProvider`, routes, DNS, `NWPathMonitor`, sleep/wake | GPL-covered upstream client; no Swift source or documentation prose transfer |
| [sing-box for Desktop](https://github.com/SagerNet/sing-box-for-desktop/tree/cebee0d527c4e5d5500f971553628e0dfa8bae0f) | `cebee0d527c4e5d5500f971553628e0dfa8bae0f` | Windows service boundary, daemon authentication, ACLs and profile lifecycle | GPL-covered upstream client; design observations only |
| [Xray-core](https://github.com/XTLS/Xray-core/tree/50231eaff98ccc31b5cbd247a721c16e97fe5ec1) | `50231eaff98ccc31b5cbd247a721c16e97fe5ec1` | Independent comparison for Linux/macOS/Windows TUN, DNS and address racing | [MPL-2.0](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/LICENSE); no Xray file is used as an implementation base |

The checkouts remain outside this repository. They must not be staged, included
in source archives or used as hidden build inputs.

## Clean-room protocol

### Разрешено

1. Зафиксировать upstream revision и наблюдаемое поведение.
2. Переписать наблюдение как Shadowpipe requirement без upstream identifiers,
   internal type layout и implementation-specific constants.
3. Получить детали API из kernel, systemd, Apple Developer и Microsoft
   documentation.
4. Сначала написать black-box/adversarial test.
5. Независимо реализовать adapter за platform capability contract.
6. Проверить source similarity, license notices, secrets и release artifacts до
   commit.

### Запрещено

- копировать либо переводить Go/Swift/TypeScript source, comments или docs;
- переносить control flow построчно, даже с переименованными identifiers;
- vendor или link GPL sing-box/sing-tun code;
- брать MPL-covered Xray file и модифицировать его как Shadowpipe file;
- копировать vendored Wintun wrapper. Если Wintun будет распространяться,
  используется официальный API и отдельно выполняются его distribution-license
  obligations;
- заменять Shadowpipe protocol, policy, replay store, carrier selector или WAL
  upstream-механизмом;
- выдавать audit recommendation за уже работающую функцию.

Полная repository policy находится в
[`upstream-clean-room-policy.md`](upstream-clean-room-policy.md).

Decision labels used by this audit:

- `ADOPT` — принять поведенческое требование, например bounded event
  coalescing или re-observation после смены сети;
- `ADAPT` — независимо реализовать механизм через Shadowpipe contracts и
  усилить его signed authority, WAL и ownership proof;
- `REJECT` — не переносить механизм, если он ослабляет архитектуру, нарушает
  clean-room boundary или мутирует чужое host state.

Unless a finding is listed under explicit anti-patterns, the source observations
below are `ADAPT`, not source-code adoption.

## Что является архитектурой, а что platform mechanism

| Слой | Shadowpipe invariant | Что допустимо изучать у upstream |
|---|---|---|
| Identity and authentication | Protocol v3, device enrollment, server fingerprint pin | Только OS credential storage, process identity and IPC authorization |
| Endpoint authority | Signed policy может разрешить адрес; DNS может только сузить authority | Cache coalescing, TTL handling, A/AAAA scheduling and resolver lifecycle |
| Carrier | REALITY production gate, durable replay, no direct fallback | Socket binding, interface selection, Happy-Eyeballs-style bounded racing |
| Packet plane | Authenticated end-to-end IP packets | TUN/utun/Wintun public APIs, packet batching, MTU and backpressure |
| Host state | WAL-before-mutation, exact ownership, deterministic recovery | Netlink, nftables, NetworkExtension, IP Helper and WFP primitives |
| Selection | Causal carrier plane with evidence gates | Network-change events and availability telemetry, never policy promotion logic |

Platform adapters are not allowed to invent endpoints, weaken authentication or
silently select direct egress. Their output is an observed host-state snapshot;
privileged mutation is permitted only after the pure platform contract returns
a current, unambiguous, capability-complete decision.

## Source findings with exact references

The references below identify behavior at the pinned revisions. The wording and
requirements are original Shadowpipe synthesis.

### Cross-platform core and lifecycle

| ID | Upstream observation | Shadowpipe interpretation |
|---|---|---|
| `SB-PLAT-01` | sing-box separates platform-owned TUN opening, interface discovery, network monitoring and connection-owner lookup behind one interface: [`adapter/platform.go:11-58`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/adapter/platform.go#L11-L58). | Keep one pure capability contract, but split privileged backends by resource so a platform cannot claim unsupported safety properties. |
| `SB-LIFE-01` | TUN setup is staged: options are assembled before interface open, stack start and redirect activation: [`protocol/tun/inbound.go:197-287`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/protocol/tun/inbound.go#L197-L287), [`protocol/tun/inbound.go:402-497`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/protocol/tun/inbound.go#L402-L497). | Preserve staged startup, but bind every stage to a durable WAL transition and post-mutation observation. |
| `SB-MON-01` | The network manager installs native/default-interface monitors and feeds callbacks into a reset path: [`route/network.go:111-135`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/route/network.go#L111-L135), [`route/network.go:459-529`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/route/network.go#L459-L529). | An event is only a reconciliation trigger. Re-read kernel/OS state, bind it to a generation, then compute an idempotent delta. |
| `SB-PWR-01` | Windows suspend and resume cause device pause/wake and network reset: [`route/network.go:531-544`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/route/network.go#L531-L544). | Suspend/resume is a first-class crash-adjacent event: close carrier leases, retain lockdown, re-observe interface and re-establish only from signed authority. |
| `SB-BIND-01` | Default-interface binding and Linux routing marks are applied at socket creation: [`route/network.go:345-406`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/route/network.go#L345-L406). | Carrier sockets must be bound before `connect`; a bind/mark failure is terminal for that candidate and never falls back to an unbound socket. |

### DNS, endpoint choice and bounded racing

| ID | Upstream observation | Shadowpipe interpretation |
|---|---|---|
| `SB-DNS-01` | sing-box coalesces equivalent cache misses, computes positive/negative TTLs and can refresh a bounded stale entry in background: [`dns/client.go:110-224`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/dns/client.go#L110-L224), [`dns/client.go:397-455`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/dns/client.go#L397-L455), [`dns/client.go:483-498`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/dns/client.go#L483-L498). | Add singleflight and bounded stale-while-revalidate to the resolver, but stale DNS may never outlive signed policy/pin validity or add an unsigned address. |
| `SB-RACE-01` | sing-box races preferred and fallback address families after a delay and closes losing connections: [`common/dialer/default_parallel_network.go:47-129`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/common/dialer/default_parallel_network.go#L47-L129). | Race only candidates already admitted by the signed endpoint policy and already prepared in host allowlist/routes. Direct-system fallback is forbidden. |
| `XR-DNS-01` | Xray uses `singleflight` for same-key DNS work and separates stale response from background pull: [`app/dns/nameserver_cached.go:21-74`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/app/dns/nameserver_cached.go#L21-L74). | Confirms that coalescing belongs in the common resolver contract rather than an individual carrier. |
| `XR-DNS-02` | Xray bounds cache housekeeping and migrates a shrunken map in batches: [`app/dns/cache_controller.go:20-70`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/app/dns/cache_controller.go#L20-L70), [`app/dns/cache_controller.go:155-218`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/app/dns/cache_controller.go#L155-L218). | Every cache and migration needs explicit capacity, work budget, version and observable completion; it is not part of endpoint trust. |
| `XR-RACE-01` | Xray implements delayed, concurrency-bounded TCP racing and cancels/ closes losers: [`transport/internet/happy_eyeballs.go:17-97`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/transport/internet/happy_eyeballs.go#L17-L97), [`transport/internet/happy_eyeballs.go:100-156`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/transport/internet/happy_eyeballs.go#L100-L156). | Implement an authority-bounded racer with global deadline, maximum concurrency, attempt telemetry and deterministic loser cleanup. |

### Linux

| ID | Upstream observation | Shadowpipe interpretation |
|---|---|---|
| `ST-LNX-01` | sing-tun configures TUN address/MTU through netlink and performs route/rule setup before DNS integration: [`tun_linux.go:132-175`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_linux.go#L132-L175), [`tun_linux.go:317-368`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_linux.go#L317-L368). | Replace shell parsing with typed netlink/nftables/resolved backends, while retaining Shadowpipe WAL ordering and exact ownership evidence. |
| `ST-LNX-02` | Linux policy routing distinguishes address families, marks, exclusions and strict unreachable rules: [`tun_linux.go:684-785`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_linux.go#L684-L785), [`tun_linux.go:927-995`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_linux.go#L927-L995). | Model route rules as typed owned resources, including an explicit IPv6-block resource when inner IPv6 is disabled. |
| `ST-LNX-03` | nftables objects are assembled and committed through one `Flush`, with interface/address updates registered afterwards: [`redirect_nftables.go:21-125`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/redirect_nftables.go#L21-L125), [`redirect_nftables.go:283-300`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/redirect_nftables.go#L283-L300). | Use native nftables transactions, but write Shadowpipe intent first and verify exact post-state before publishing a carrier candidate. |
| `ST-LNX-04` | Route reconciliation compares desired interfaces with the current kernel table rather than trusting a cached interface snapshot: [`redirect_route_linux.go:94-177`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/redirect_route_linux.go#L94-L177). | This becomes the common reconciliation rule: events invalidate observations; only a fresh OS read can authorize a delta. |
| `ST-LNX-05` | Netlink route/link/address events use small buffers and one-second coalescing: [`monitor_linux.go:34-108`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/monitor_linux.go#L34-L108). | Use a bounded dirty-bit/event coalescer. Never enqueue an unbounded copy of every kernel event. |
| `ST-LNX-06` | DNS ownership is expressed through per-link `~.`, default-route and DNS settings, then reverted: [`tun_linux.go:1207-1229`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_linux.go#L1207-L1229). | Implement the same OS intent through a typed systemd-resolved adapter with deadlines, post-read verification and WAL state; do not fire-and-forget shell commands. |
| `XR-LNX-01` | Xray validates an inherited TUN fd with `TUNGETIFF`, interface type, `IFF_NO_PI` and expected name: [`proxy/tun/tun_linux.go:73-117`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/tun/tun_linux.go#L73-L117). | If fd inheritance is added, require fd identity plus a supervisor-issued ownership token and record it in recovery state. |
| `XR-LNX-02` | Xray subscribes to route/link changes and retries reconciliation through an updater: [`proxy/tun/tun_linux.go:304-336`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/tun/tun_linux.go#L304-L336). | Confirms event-driven reconciliation as a shared requirement, not a sing-box-specific design. |

### macOS

| ID | Upstream observation | Shadowpipe interpretation |
|---|---|---|
| `AP-NE-01` | The Apple client creates `NEPacketTunnelNetworkSettings`, DNS, IPv4/IPv6 included and excluded routes, then applies them through the provider: [`ExtensionPlatformInterface.swift:37-157`](https://github.com/SagerNet/sing-box-for-apple/blob/794eb1741f91765a91f1513e5639296503f072b2/Library/Network/ExtensionPlatformInterface.swift#L37-L157), [`ExtensionPlatformInterface.swift:194-207`](https://github.com/SagerNet/sing-box-for-apple/blob/794eb1741f91765a91f1513e5639296503f072b2/Library/Network/ExtensionPlatformInterface.swift#L194-L207). | Production macOS integration must be `NEPacketTunnelProvider`; standalone `utun` remains an isolated-lab backend only. |
| `AP-NE-02` | `NWPathMonitor` publishes default interface, expensive/constrained state and interface inventory: [`ExtensionPlatformInterface.swift:252-313`](https://github.com/SagerNet/sing-box-for-apple/blob/794eb1741f91765a91f1513e5639296503f072b2/Library/Network/ExtensionPlatformInterface.swift#L252-L313). | Convert every path update into a generation change, close old carrier leases and reconcile signed endpoints against the new underlay. |
| `AP-NE-03` | DNS cache refresh is induced by reasserting and reapplying saved network settings: [`ExtensionPlatformInterface.swift:345-362`](https://github.com/SagerNet/sing-box-for-apple/blob/794eb1741f91765a91f1513e5639296503f072b2/Library/Network/ExtensionPlatformInterface.swift#L345-L362). | Treat a settings reapply as a fallible transaction; capture completion, timeout and resulting settings rather than assuming success. |
| `AP-NE-04` | Provider lifecycle has explicit service startup, reload/reassert, stop, sleep and wake paths: [`ExtensionProvider.swift:83-203`](https://github.com/SagerNet/sing-box-for-apple/blob/794eb1741f91765a91f1513e5639296503f072b2/Library/Network/ExtensionProvider.swift#L83-L203), [`ExtensionProvider.swift:244-313`](https://github.com/SagerNet/sing-box-for-apple/blob/794eb1741f91765a91f1513e5639296503f072b2/Library/Network/ExtensionProvider.swift#L244-L313). | Map Apple lifecycle callbacks onto the same pause, lockdown, re-observe and recovery state machine used by other platforms. |
| `XR-MAC-01` | Xray distinguishes an fd owned by NetworkExtension from a standalone macOS-created utun and does not close the former: [`proxy/tun/tun_darwin.go:61-107`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/tun/tun_darwin.go#L61-L107), [`proxy/tun/tun_darwin.go:131-143`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/tun/tun_darwin.go#L131-L143). | Ownership must record whether the provider or Shadowpipe owns the fd; recovery may never close/delete a provider-owned resource. |
| `XR-MAC-02` | Darwin packet I/O accounts for the four-byte utun address-family header: [`proxy/tun/tun_darwin.go:176-242`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/tun/tun_darwin.go#L176-L242). | Add black-box framing tests for IPv4, rejected malformed family and eventual IPv6 before enabling a macOS packet backend. |

### Windows

| ID | Upstream observation | Shadowpipe interpretation |
|---|---|---|
| `ST-WIN-01` | sing-tun opens Wintun, configures addresses/DNS through adapter LUID and sets interface properties through IP Helper structures: [`tun_windows.go:39-162`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_windows.go#L39-L162). | Build a minimal Wintun adapter owned by a privileged Shadowpipe Windows Service; record adapter GUID/LUID and exact pre-state in the WAL. |
| `ST-WIN-02` | Strict routing uses a dynamic WFP session and explicitly blocks IPv6 when no IPv6 TUN address exists: [`tun_windows.go:169-215`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_windows.go#L169-L215), [`tun_windows.go:261-287`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_windows.go#L261-L287). | Windows Alpha can remain IPv4-only only if WFP proves non-loopback IPv6 is blocked before route/DNS publication. |
| `ST-WIN-03` | WFP filters bind allow rules to the TUN interface and can block port 53 for both families: [`tun_windows.go:289-366`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_windows.go#L289-L366). | Use a provider/sublayer identity unique to Shadowpipe and inventory exact filters during recovery; DNS blocking is additive to, not a substitute for, IPv6 blocking. |
| `ST-WIN-04` | Route update currently flushes all adapter routes before adding the desired list: [`tun_windows.go:571-597`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_windows.go#L571-L597). | Reject flush-and-replace. Compute exact owned-route add/delete deltas and preserve foreign routes. |
| `ST-WIN-05` | Route and interface notifications feed the Windows default-interface monitor, which selects a live lowest-metric default route: [`monitor_windows.go:29-58`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/monitor_windows.go#L29-L58), [`monitor_windows.go:60-114`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/monitor_windows.go#L60-L114). | Use IP Helper notifications only as triggers; re-read forward/interface tables and reject ambiguity. |
| `SB-WIN-IPC-01` | The desktop daemon fixes its named-pipe path, applies an ACL and nonzero buffers: [`experimental/boxdd/server_windows.go:12-37`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/experimental/boxdd/server_windows.go#L12-L37). | Use a fixed protected pipe, but authorize each request through client PID, token SID/session and executable signer rather than ACL alone. |
| `SB-WIN-ID-01` | The daemon compares Authenticode signers, rejects reparse points and validates protected working-directory ACLs: [`experimental/boxdd/security_windows.go:29-86`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/experimental/boxdd/security_windows.go#L29-L86), [`experimental/boxdd/security_windows.go:160-254`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/experimental/boxdd/security_windows.go#L160-L254). | Require signed GUI/service pairing, fixed NTFS, no reparse ancestors, SYSTEM ownership and explicit DACL validation before privileged startup. |
| `SB-WIN-SVC-01` | The service installer uses a service SID, automatic start, bounded restart actions and service ACL hardening: [`experimental/boxdd/cmd_service_windows.go:126-224`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/experimental/boxdd/cmd_service_windows.go#L126-L224). | Adopt service isolation and recovery policy, while keeping secrets and the Rust packet/carrier core outside the privileged process where possible. |
| `XR-WIN-01` | Xray independently demonstrates Wintun session I/O, route/address/DNS configuration and interface-change callbacks: [`proxy/tun/tun_windows.go:49-190`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/tun/tun_windows.go#L49-L190), [`proxy/tun/tun_windows.go:225-277`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/tun/tun_windows.go#L225-L277). | Confirms the public-API family, but its lifecycle is not sufficient evidence for Shadowpipe ownership/recovery guarantees. |

### Bounded state, queues and migrations

| ID | Upstream observation | Shadowpipe interpretation |
|---|---|---|
| `XR-QUEUE-01` | Xray uses a bounded UDP queue and explicitly drops when it is full: [`proxy/wireguard/tun.go:111-155`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/wireguard/tun.go#L111-L155). | Every packet/event queue needs a documented capacity and overload policy. Shadowpipe additionally requires counters by reason and no silent control-plane drop. |
| `XR-QUEUE-02` | Xray pub/sub and logging channels are bounded and nonblocking: [`common/signal/pubsub/pubsub.go:13-23`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/common/signal/pubsub/pubsub.go#L13-L23), [`common/log/logger.go:35-50`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/common/log/logger.go#L35-L50), [`common/log/logger.go:100-110`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/common/log/logger.go#L100-L110). | Data-plane observability may sample/drop under pressure; security and recovery state transitions may not. |
| `SB-STATE-01` | Desktop profiles use temp-file rename, serialize operations per profile and use database transactions: [`profiles.ts:50-75`](https://github.com/SagerNet/sing-box-for-desktop/blob/cebee0d527c4e5d5500f971553628e0dfa8bae0f/src/main/profiles.ts#L50-L75), [`database.ts:13-35`](https://github.com/SagerNet/sing-box-for-desktop/blob/cebee0d527c4e5d5500f971553628e0dfa8bae0f/src/main/database.ts#L13-L35). | All Shadowpipe platform state needs schema versioning, create-new migration, fsync/FlushFileBuffers, atomic publication and rollback tests; rename alone is not the durability contract. |

## Client platform matrix

Серверная матрица сюда намеренно не включена: production server target только
Linux. В строке Linux ниже перечислены именно client-side механизмы; VPS
egress/NAT/service hardening ведётся отдельно.

| Client platform | Что уже доказано в Shadowpipe | Clean-room mechanisms to adopt/adapt | Production Alpha gate |
|---|---|---|---|
| Linux client | Native ARM64 build/test; disposable IPv4 full-TUN; REALITY/v3; route/DNS/firewall transaction; same-boot WAL recovery; early reboot lockdown | Native netlink and nftables adapters; systemd-resolved control; `SO_MARK`/interface binding; netlink event coalescing; actual-kernel reconciliation; typed MTU/offload observation | IPv4 paired reboot recovery, power-loss/torn-write matrix, native adapters behind WAL, default IPv6 block, distro/kernel/network-manager matrix and 72-hour soak |
| macOS | Rust/core portability only; no native system VPN or host mutation evidence | `NEPacketTunnelProvider`; `NEPacketTunnelNetworkSettings`; provider-owned packet flow; `NWPathMonitor`; sleep/wake/reassert; Keychain; signed/notarized app plus minimal helper if required | Disposable macOS VM or sacrificial Mac proves routes, DNS, IPv6 block, path changes, sleep/wake, provider crash and uninstall without touching the live resident Mac VPN |
| Windows | Native ARM64 no-TUN H2/v3 client, auth negative controls and exact transfer; route/DNS unchanged | Wintun; IP Helper route/address/DNS APIs; WFP kill-switch; fixed authenticated named pipe; service SID/ACL; Authenticode pairing; power and interface notifications | Native Wintun packet path, exact owned-state WAL, IPv4 leak matrix, IPv6 block, DNS leak prevention, suspend/resume, service crash/reboot and clean uninstall in disposable Windows VM |

## Ranked implementation backlog

`P0` means required before any platform is called a system VPN. `P1` means
required for Production Alpha usability and safe operation. `P2` means broader
hardening, performance or later protocol scope.

### P0 — safety and native packet integration

| Rank | Mechanism | Required Shadowpipe behavior | Acceptance gate |
|---|---|---|---|
| `P0.1` | Platform capability/backend contract | Pure desired/observed state, stable interface identity, monotonic generation, explicit supported capabilities and fail-closed ambiguity | Missing, stale, future, ambiguous and capability-incomplete observations produce zero OS mutation |
| `P0.2` | Event-driven reconciliation | Linux netlink, Apple `NWPathMonitor`, Windows IP Helper/power events only mark state dirty; worker re-reads actual OS state | Event storms coalesce into bounded work; stale generations cannot publish routes, DNS or carrier sockets |
| `P0.3` | Default IPv6 block | Non-loopback IPv6 cannot bypass an IPv4-only tunnel; DNS filtering is not treated as sufficient | TCP/UDP/ICMPv6 and DNS/HTTPS IPv6-hint leak tests stay blocked before start, during carrier cut, after crash and through reboot |
| `P0.4` | Linux native backend | Typed netlink routes/rules/addresses, nftables transaction, resolved adapter and pre-connect mark/bind | Exact foreign-state preservation, WAL cuts around every operation and parity with the existing IPv4 full-TUN bundle |
| `P0.5` | macOS NetworkExtension backend | Provider owns network settings and packet flow; Rust core owns protocol/packet processing; no production standalone-utun path | IPv4 TUN, DNS, IPv6 block, provider crash, reassert, path change and sleep/wake pass in isolated Apple lab |
| `P0.6` | Windows privileged service/backend | Service owns Wintun/IP Helper/WFP; unprivileged client communicates through authenticated fixed IPC | Caller SID/session/signer negative controls, adapter collision, route/filter foreign ownership, crash/reboot and uninstall pass |
| `P0.7` | Authority-bounded DNS/racing | Singleflight, TTL/negative TTL, bounded stale refresh and delayed concurrent dialing only inside signed endpoint set | Resolver poisoning, stale-after-policy-expiry, unauthorized AAAA, loser leak and unbound fallback tests produce zero unauthorized connects |
| `P0.8` | Cross-platform recovery vocabulary | TUN/adapter, route, firewall/WFP/NE settings, DNS and carrier exceptions have typed identities and recovery steps | Every supported resource has Planned/Applied/Acknowledged/Active cuts and a durable Conflict outcome |

### P1 — operability, mobility and bounded resource use

| Rank | Mechanism | Required Shadowpipe behavior | Acceptance gate |
|---|---|---|---|
| `P1.1` | Privilege separation | Packet/carrier/protocol core runs unprivileged; a minimal helper performs only capability-approved operations | Malformed IPC cannot request arbitrary route, firewall, file or process operations |
| `P1.2` | Suspend/resume and network mobility | Pause carrier, retain leak barrier, invalidate leases, re-observe underlay, then re-resolve/reconnect within signed policy | Wi-Fi/Ethernet switch, DHCP renewal, gateway change and repeated sleep cycles leave no stale direct socket or host state |
| `P1.3` | Outer IPv6 and NAT64 | Carrier can use signed IPv6 endpoints while inner tunnel remains IPv4; NAT64 is explicit and policy-bounded | Dual-stack, IPv6-only and NAT64 labs pass without enabling inner IPv6 or allowing unsigned synthesis |
| `P1.4` | MTU, PMTUD and offload contract | Observe link MTU, clamp effective packet size, handle ICMP errors and explicitly negotiate/disable offloads | No fragmentation blackhole across Ethernet, Wi-Fi, cellular-like MTU and encapsulation overhead matrices |
| `P1.5` | Bounded queues and overload telemetry | Every queue has capacity, byte/packet budget, wait/drop policy and counters | Memory remains bounded under adversarial UDP/event/log floods; control/recovery transitions are never silently dropped |
| `P1.6` | Versioned durable migrations | State schemas migrate create-new, validate, sync and atomically publish; downgrade is explicit | Crash/power cut at each migration step preserves either old valid state or new valid state, never a hybrid |
| `P1.7` | Packaging and release identity | `.deb`/`.rpm`, signed/notarized macOS package and signed Windows installer bind core/helper/config schema versions | Upgrade, rollback and uninstall preserve lockdown semantics and reject incompatible helper/core pairs |
| `P1.8` | Structured operational telemetry | Per-stage latency, reason-coded failure, queue pressure, reconcile generation and recovery outcome without credentials/raw traffic | Bounded local telemetry survives restart and passes privacy/redaction review |

### P2 — later completeness and scale

| Rank | Mechanism | Required Shadowpipe behavior | Acceptance gate |
|---|---|---|---|
| `P2.1` | Full inner IPv6 | Authenticated IPv6 packets, routes, DNS, ICMPv6/PMTUD and kill-switch/recovery on all supported OSes | Same evidence depth as IPv4, including crash/reboot/power loss and dual-stack leak matrix |
| `P2.2` | Advanced multipath | Multiple authorized carrier paths with bounded racing/migration controlled by the causal plane | No generic “fastest wins” bypass of signed policy or causal promotion gates |
| `P2.3` | Fleet-safe platform rollout | Canary cohorts, signed compatibility manifest, rollback, revocation and platform capability inventory | Mixed-version fleet drills and compromised-helper containment |
| `P2.4` | Performance specialization | Batching, GSO/GRO where proven safe, multi-queue packet processing and per-platform profiling | Performance gains without changing wire identity, recovery semantics or leak guarantees |
| `P2.5` | Independent audit and field matrices | External review plus authorized operator/path experiments | Claims ledger advances only within the measured platform, address family and field stratum |

## IPv6 decision in detail

### Stage 0: `block` is the default now

An IPv4-only VPN is acceptable for an early alpha only when IPv6 is provably
unavailable as a bypass.

- Linux: install an owned nftables/route-policy barrier for non-loopback IPv6
  before publishing IPv4 routes or carrier sockets. Absence of an IPv6 TUN
  address is not itself a kill-switch.
- macOS: route IPv6 into `NEPacketTunnelProvider` and drop it in the controlled
  packet path, or use another Apple-supported configuration with equivalent
  proof. If the OS configuration cannot guarantee capture/block, startup fails.
- Windows: install WFP IPv6 block filters before adapter routes/DNS become
  active. A dynamic WFP session is useful for normal cleanup, but durable
  restart/reboot protection still needs Shadowpipe recovery state.
- DNS: reject direct AAAA and IPv6 `HTTPS`/SVCB hints for inner connections, but
  do not count this as leak prevention because literal IPv6 and cached sockets
  bypass DNS.

The `block` capability must be tested before start, after partial startup,
during carrier loss, after process death, after service restart and after
reboot.

### Stage 1: outer-only IPv6 before inner IPv6

Outer IPv6 can improve reachability without exposing IPv6 packets to the inner
VPN:

```text
inner application packet: IPv4
Shadowpipe packet tunnel:  IPv4
carrier socket:            IPv4 or authorized IPv6
```

Rules:

- endpoint policy gains a separate signed IPv6 authority;
- A and AAAA lookups run under one bounded resolver transaction;
- DNS output remains a subset of signed addresses;
- Happy-Eyeballs-style racing occurs only after firewall/route preparation;
- every loser is closed and its lease retired;
- carrier socket binding to the observed underlay is mandatory;
- direct/unbound fallback remains forbidden.

NAT64 is a distinct mode, not an accidental resolver behavior. A discovered
NAT64 prefix, synthesized destination and original signed service identity must
be bound into one authority decision. If that relationship cannot be proved,
the NAT64 candidate is rejected. Outer-only support needs IPv6-only and NAT64
VM/network labs before release.

### Stage 2: full inner IPv6 later

Full inner IPv6 is enabled only after all of the following exist:

- IPv6 TUN/utun/Wintun addressing and routes;
- ICMPv6 errors and Packet Too Big handling;
- IPv6 DNS and SVCB/HTTPS behavior;
- per-platform IPv6 kill-switch;
- signed IPv6 endpoint transactions;
- crash, reboot and power-loss recovery;
- no-leak tests for literal IPv6, cached connections and application fallback;
- independent performance and censorship measurements.

Until then, “IPv6 unsupported” must mean “blocked”, not “ignored”.

## Reconciliation algorithm to implement

Every OS backend should converge through the same abstract sequence:

1. Receive an OS event and mark observation dirty.
2. Coalesce duplicate events under a bounded timer/work queue.
3. Read interfaces, addresses, routes, DNS and owned firewall state from the OS.
4. Create an immutable observation with a desired-generation binding.
5. Fail closed if the underlay interface is missing, ambiguous or self-points to
   the Shadowpipe TUN.
6. Verify required platform capabilities, including the selected IPv6 mode.
7. Compute an exact resource delta against actual OS state.
8. Persist WAL intent before the first privileged mutation.
9. Apply operations in leak-safe order.
10. Re-read OS state and acknowledge only exact matches.
11. Publish new dial/DNS snapshot only after host preparation succeeds.
12. Retire old sockets first, then remove no-longer-leased host resources in
    reverse order.

No event callback may directly flush routes, replace DNS or reopen a carrier.

## Endpoint resolution and connect algorithm

The upstream DNS and racing mechanisms become safe for Shadowpipe only with the
following authority wrapper:

1. Load one verified policy generation and its signed IPv4/IPv6 address sets.
2. Coalesce equivalent resolver work by service, generation and address family.
3. Run A/AAAA work with one absolute deadline.
4. Apply negative TTL and bounded cache capacity.
5. Intersect answers with signed authority.
6. Permit bounded stale results only while both DNS TTL grace and policy/key/pin
   validity remain active.
7. Stage firewall and exact carrier routes for admitted candidates.
8. Publish an immutable candidate snapshot.
9. Race a bounded number with a fixed fallback delay.
10. Bind/mark every socket before connect.
11. Promote only a successfully authenticated REALITY + protocol-v3 session.
12. Close losers, decrement leases and transactionally retire unused host state.

This is connectivity selection, not causal carrier promotion. The causal plane
still decides which carrier classes are eligible for production traffic.

## Explicit anti-patterns

| Anti-pattern | Upstream evidence | Shadowpipe rule |
|---|---|---|
| Replacing Shadowpipe architecture with an upstream core | Both projects combine their own protocols, routers and platform implementations | Reject wholesale rewrite; adopt only platform behavior behind our contracts |
| Named Linux TUN attachment without exclusivity | sing-tun uses `IFF_TUN \| IFF_NO_PI` without `IFF_TUN_EXCL`: [`tun_linux.go:104-129`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_linux.go#L104-L129); Xray does the same: [`proxy/tun/tun_linux.go:120-147`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/tun/tun_linux.go#L120-L147) | Retain existing `IFF_TUN_EXCL`; collision is pre-mutation failure |
| Reusing a Windows adapter by name without durable ownership proof | sing-tun opens an existing adapter after create collision: [`tun_windows.go:39-53`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_windows.go#L39-L53) | Require recorded GUID/LUID, owner/service identity and exact adapter properties; otherwise Conflict |
| Flush-and-replace host routes | sing-tun Windows calls `FlushRoutes` before add: [`tun_windows.go:571-590`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_windows.go#L571-L590) | Delete/add only exact owned entries; foreign routes are immutable |
| Graceful `Close()` as recovery | sing-box TUN close delegates cleanup to in-process closers: [`protocol/tun/inbound.go:509-515`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/protocol/tun/inbound.go#L509-L515); Xray Linux cleanup is also close-driven: [`proxy/tun/tun_linux.go:195-212`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/tun/tun_linux.go#L195-L212) | WAL recovery remains authoritative after crash/reboot |
| Fire-and-forget DNS mutation | sing-tun launches resolved changes asynchronously: [`tun_linux.go:1207-1221`](https://github.com/SagerNet/sing-tun/blob/79ea1ac88855ae1e66c96dc162555161708efcd3/tun_linux.go#L1207-L1221) | Use bounded typed calls, observe completion and journal ownership |
| Broad unauthenticated local daemon socket | sing-box Unix daemon makes its socket mode `0666`: [`experimental/boxdd/server_unix.go:11-29`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/experimental/boxdd/server_unix.go#L11-L29) | Unix IPC is `0600` or protected socket activation plus peer credentials and request authorization |
| Broad service capabilities | shipped sing-box unit grants networking, ptrace and DAC-read capabilities: [`release/config/sing-box.service:6-15`](https://github.com/SagerNet/sing-box/blob/c8ee3497b25027f5f73bd88aba96ecf5009c37e0/release/config/sing-box.service#L6-L15) | Minimal helper, minimal capability set, `NoNewPrivileges` and filesystem/system-call sandbox |
| Standalone macOS utun as product architecture | Xray directly creates utun when no provider fd exists: [`proxy/tun/tun_darwin.go:83-107`](https://github.com/XTLS/Xray-core/blob/50231eaff98ccc31b5cbd247a721c16e97fe5ec1/proxy/tun/tun_darwin.go#L83-L107) | Standalone utun is lab-only; production uses NetworkExtension |
| Stale DNS overriding signed policy | Upstream stale caches are connectivity mechanisms, not signed endpoint authorities | Policy expiry/pin validity always wins; stale entry cannot expand or resurrect authority |
| Happy Eyeballs as direct fallback | Generic racing selects whichever address connects first | Race only authorized, host-prepared carrier candidates and still require full authentication |
| Silent loss of security events | Upstream nonblocking queues may discard on pressure | Packet/log sampling may drop with counters; WAL/recovery/policy events may not |

## Platform-specific test gates

### Linux gate

- x86_64 and ARM64;
- Ubuntu/Debian, Fedora and Arch;
- NetworkManager, systemd-networkd and systemd-resolved combinations;
- foreign TUN, route, nft table/chain and DNS ownership collisions;
- default-interface disappearance and replacement;
- carrier endpoint address rotation;
- IPv6 literal/DNS/application leaks while inner IPv6 is disabled;
- `SIGKILL`, reboot and power-cut points around every native backend operation;
- 72-hour soak with event storms, DHCP renewals, disk pressure and repeated
  carrier cuts.

### macOS gate

- disposable Apple environment only; never the resident Mac with live sing-box;
- app extension and system extension variants as applicable;
- provider start/stop/reassert/crash;
- Wi-Fi/Ethernet changes, constrained/expensive paths and sleep/wake;
- DNS and IPv4 route exactness;
- default IPv6 block;
- packet-flow framing and MTU;
- signed/notarized GUI/helper identity and Keychain ACLs;
- uninstall and upgrade without residual NetworkExtension configuration.

### Windows gate

- Windows 11 ARM64 and x86_64;
- Wintun create, collision, reopen, service crash and reboot;
- IP Helper route/DNS exact ownership;
- WFP provider/sublayer/filter inventory and IPv6/DNS block;
- named-pipe unauthorized SID/session/process/signer tests;
- suspend/resume, network category and default-route changes;
- adapter/route/filter foreign-state preservation;
- signed installer upgrade/rollback/uninstall;
- route/DNS/firewall canonical digests plus packet leak capture.

## What this audit does not claim

- It does not prove sing-box or Xray is secure or insecure overall.
- It does not claim complete line-by-line review of every protocol in either
  repository; the scan was repository-wide, with deep review of platform,
  routing, DNS, lifecycle, IPC and bounded-state paths relevant to Shadowpipe.
- It does not establish license compatibility for code reuse; the selected
  workflow intentionally avoids code reuse.
- It does not close native macOS or Windows TUN gates.
- It does not add IPv6 support merely by documenting the staged decision.
- It does not change the evidence tier of existing Linux VM or Windows no-TUN
  bundles.
- It does not authorize touching, restarting or replacing the live macOS
  sing-box.

The implementation rule is therefore strict: preserve the Shadowpipe
architecture, independently implement the best platform mechanisms, and retain
our stronger ownership, policy and recovery invariants wherever upstream is
weaker.
