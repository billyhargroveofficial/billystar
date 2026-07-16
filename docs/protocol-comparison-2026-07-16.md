# Protocol comparison: Shadowpipe, VLESS, Hysteria2 and AmneziaWG 2.0

Snapshot: 2026-07-16.

Status: bounded engineering comparison, not a benchmark, cryptographic proof,
security endorsement or censorship-resistance claim.

## Short verdict

Shadowpipe is not a VLESS, Hysteria2 or WireGuard derivative:

- it carries authenticated end-to-end IP packets rather than only proxy
  requests;
- its inner protocol has a per-device PSK access gate, ML-KEM-768 + ephemeral
  X25519 key agreement, Ed25519 + PSK Finished proofs and a mandatory server
  pin;
- endpoint authority is signed and rollback-protected;
- REALITY replay state and Linux host ownership survive process restart;
- carrier selection is separated from identity and packet semantics.

Those properties make the architecture stricter in several dimensions. They do
not make the current implementation a better product overall. Xray, Hysteria2
and AmneziaWG have mature clients, broad deployment experience, IPv6 and
substantially stronger performance evidence.

## Corrected comparison

| Dimension | Shadowpipe | Current VLESS/Xray | Hysteria2 | AmneziaWG 2.0 |
|---|---|---|---|---|
| Primary abstraction | Authenticated L3 packet tunnel | Stateless L4 proxy protocol and routing platform | QUIC-based TCP/UDP proxy | WireGuard-derived L3 tunnel |
| Production carrier | REALITY over TCP | REALITY/TLS with RAW, XHTTP or gRPC; Vision paths | QUIC/UDP with HTTP/3 masquerade | Obfuscated UDP |
| Client identity | Ed25519 proof plus independent per-device PSK | UUID bearer identity; VLESS Encryption hides it but does not make it a signing proof | Password/user auth inside TLS/QUIC | WireGuard static public key |
| PQ status | Static ML-KEM-768 server key combined with ephemeral X25519; classical Ed25519 control plane | VLESS Encryption supports ephemeral ML-KEM-768 + X25519; REALITY can negotiate X25519MLKEM768 and optionally verify ML-DSA-65 | Standard TLS 1.3; no protocol-specific PQ KEM | Noise IK with Curve25519; optional PSK is a symmetric hedge, not ML-KEM |
| Probe handling | REALITY forward-to-cover plus inner PSK gate and durable exact replay | Mature REALITY/uTLS ecosystem and forward-to-target | HTTP/3 masquerade plus Salamander/Gecko | WireGuard silence plus configurable header, size and CPS mimicry |
| Host safety | Signed authority, WAL-before-mutation, exact ownership and fail-closed Linux recovery | Broad platform support; host lifecycle safety depends on core/client/configuration | TUN lifecycle depends on client integration | Mature WireGuard-style interface lifecycle, usually simpler than a proxy stack |
| Loss-path behavior | Current production path is one reliable TCP carrier; nested TCP can amplify head-of-line blocking | Vision/direct-copy paths avoid carrying every inner TCP packet through another TCP stream | Strongest option here on lossy/high-BDP UDP paths | Low overhead; application TCP handles its own loss recovery |
| Roaming | Reconnect and endpoint rotation; native mobility integration is open | Mature reconnect/routing ecosystem | QUIC and port-hopping support | Authenticated roaming is a core WireGuard strength |
| Current product readiness | Current executable-source Linux IPv4 full-TUN/default-route handoff at `81f188f` plus separate unprivileged native ARM64 portability at `726500f`; recovery/reboot/Windows remain snapshot-bound; macOS native client absent | Mature cross-platform ecosystem | Mature cross-platform ecosystem | Mature cross-platform ecosystem |

## Where Shadowpipe is already stricter

### Per-device proof of possession

The client does not merely present an identifier. It proves an Ed25519 seed and
an independently sampled PSK. The server proves that PSK before disclosing its
static ML-KEM public key or performing KEM work.

This raises the cost of active enumeration and separates:

- carrier admission;
- enrolled device identity;
- server-key authentication.

It does not replace secure enrollment or protect a PSK copied from a
compromised device.

### Durable replay admission

Production REALITY admission reserves an authenticated, static-key-bound slot
and synchronizes it before emitting the accepted carrier flight. Exact replay,
corruption, saturation and I/O failure forward to cover rather than accept.

This is a same-host guarantee. Shared-key replicas still need a strongly
consistent replay authority or unique REALITY static keys.

### Signed endpoint authority

DNS may select only a subset of an already signed address set. It cannot invent
an endpoint, SNI or server pin. Policy state includes expiry, predecessor
continuity, rotation overlap and persistent rollback floors.

Xray has significantly broader routing and resolver functionality, but it does
not provide this exact monotonic signed endpoint/pin authority contract.

### Crash-safe host ownership

The Linux client journals intent before mutating TUN, firewall, routes or DNS.
Recovery acts only on exact resources whose ownership can be reconstructed from
the journal and host observations. A matching name or ifindex is insufficient.

### Conservative Linux network handoff

Linux network notifications now feed a fixed two-byte invalidation set. A real
default-route change does not directly rewrite routes or migrate sockets from
the callback. Instead, the active generation verifies a durable lockdown,
tears down invalidated main host state, exits nonzero, and relies on the paired
service to start a fresh process that re-observes the underlay. Exact
Shadowpipe-owned route events are suppressible only after a fresh live census;
only a structurally exact `IFF_PROMISC`-only observer transition is excluded.

The current isolated run
[`20260716T173837Z-18283-m8K2po`](../tests/tun/results/20260716T173837Z-18283-m8K2po/RESULT.md)
has a tracked compact
[`PUBLISHED-EVIDENCE.md`](../tests/tun/results/20260716T173837Z-18283-m8K2po/PUBLISHED-EVIDENCE.md) and
proved a real `c0 -> c1` default-route replacement, strict intermediate
lockdown, generation-2 adoption through `c1`, and no observer-induced restart.
It emulated `Restart=always`/`RestartSec=1s`; it did not run real systemd PID 1.
Resolver/DHCP/suspend integration, in-process migration and native macOS/Windows
mobility remain open. The full sealed bundle, including its large raw c1 pcap,
remains local/ignored; the compact index publishes pcap hashes.

Native Linux ARM64 portability is current separately at clean commit
`726500f1ff43e2b4fdcf9082abf05aa5a2513ab7`:
[`20260716T180304Z-linux-arm64-current`](../tests/portability/results/20260716T180304Z-linux-arm64-current/RESULT.md)
passed 718/0/4 no-default and 732/0/4 all-features tests, both strict Clippy
profiles and all five runner self-tests across a 193-file snapshot. This is
unprivileged CPU/filesystem evidence only. It does not establish a privileged
handoff at `726500f` or refresh recovery, reboot or Windows.

## Where current alternatives are stronger

### VLESS/Xray: current PQ and ecosystem

Post-quantum key exchange is no longer unique to Shadowpipe. Current
[VLESS Encryption](https://xtls.github.io/en/config/inbounds/vless.html)
supports an ML-KEM-768 + X25519 mode. Current
[REALITY](https://xtls.github.io/en/config/transports/reality.html) can use
`X25519MLKEM768` when the target supports it and can add an optional ML-DSA-65
certificate signature.

Shadowpipe currently uses a static ML-KEM server key. That protects recorded
traffic only while this key remains secret; it is not full post-compromise PQ
forward secrecy. The classical Ed25519 policy plane is another explicit gap.

Xray is also ahead in:

- client and platform availability;
- IPv6;
- transport diversity;
- direct/splice performance paths;
- deployment and operational experience.

### Hysteria2: lossy-network delivery

[Hysteria2](https://v2.hysteria.network/docs/developers/Protocol/) uses QUIC
streams and datagrams and offers BBR, Reno and Brutal congestion control.
Shadowpipe's current TCP/REALITY production carrier is unlikely to match it on
lossy or high-bandwidth-delay paths.

The tradeoff is that QUIC/UDP can be throttled or blocked as a class. Brutal's
aggressive fixed-rate behavior can also become an impairment-response signal
and wastes capacity when configured above the real path rate.

### AmneziaWG: speed, battery and roaming

[AmneziaWG 2.0](https://docs.amnezia.org/documentation/amnezia-wg/) preserves
WireGuard's compact Noise/ChaCha20-Poly1305 core while randomizing headers and
packet sizes and sending configurable CPS signature packets. Kernel
implementations retain the performance profile that makes WireGuard effective
on desktops, phones and routers.

Its obfuscation is not a formal indistinguishability result, and total UDP/IP
blocking remains decisive. It nevertheless has a much stronger current
throughput, battery and roaming story than Shadowpipe.

## Deployment verdict

| Need | Stronger current choice |
|---|---|
| Mature TLS-class censorship layer and broad clients | VLESS Encryption + REALITY/XHTTP |
| Lossy/high-BDP UDP path | Hysteria2 |
| Low overhead, battery efficiency and roaming | AmneziaWG 2.0 |
| Research-grade signed authority, durable replay and exact Linux host ownership | Shadowpipe |
| A VPN for ordinary Windows/macOS/Linux users today | Not yet Shadowpipe |

The mature protocols should remain available as independent layers while
Shadowpipe closes its product and evidence gaps. Replacing them before native
clients and comparative tests exist would reduce resilience rather than improve
it.

## Work required before a stronger claim

1. Native macOS Network Extension and Windows Wintun/WFP clients. The safe
   macOS validation boundary is defined in
   [`mac-host-isolated-lab.md`](mac-host-isolated-lab.md).
2. Explicit IPv6 leak gates, then outer IPv6/NAT64, then full inner IPv6.
3. Complete network-change reconciliation beyond the conservative Linux process
   replacement: resolver/DHCP/suspend events, real systemd PID-1 integration,
   in-process state migration where justified, and native macOS/Windows sources.
4. A reviewed ephemeral PQ handshake/combiner and PQ control-plane design.
5. A production QUIC carrier evaluated against Hysteria2 on identical netem
   matrices.
6. Throughput, latency, CPU, memory and battery comparisons.
7. Independent cryptographic and systems review.
8. Preregistered field experiments with negative controls and bounded claims.

Until those gates close, the accurate description is:

> Shadowpipe is more ambitious and stricter in selected control-plane and
> recovery properties, but less mature and not yet better as a complete VPN
> product.
