# Experiment 003 — cross-layer RTT alignment

Статус: design draft, не frozen preregistration и не запущен. Exact allocation,
feature implementation, detector hash and analysis plan must be frozen before
outcomes are inspected; see [`manifest.example.json`](manifest.example.json).

## Motivation and scope

[Xue et al., NDSS 2025](https://www.ndss-symposium.org/wp-content/uploads/2025-966-paper.pdf) показывают protocol-agnostic fingerprint у **segmented proxies**: transport-layer session заканчивается на proxy, а observable application-layer session продолжается до далёкого backend, создавая `RTTdiff`. В их evaluation 80% top-5k visits имели хотя бы один detectable flow, половина — в пределах 60 packets.

Это не универсальный verdict для любого tunnel. TLS-terminating single-hop, где обе наблюдаемые сессии заканчиваются в одном месте, служит negative control для именно этого fingerprint. Он не иммунен к другим timing features.

## Questions

1. Может ли наш harness воспроизвести RTTdiff между co-located и segmented topology?
2. Насколько whitelist relay → far exit увеличивает detectable gap?
3. Уменьшает ли co-location, deferred reply или synthetic scheduling этот gap без нового более дешёвого tell?
4. Как mitigation влияет на throughput, congestion control, burst structure и tail latency?

## Topology cells

| Cell | Outer transport termination | Observable app termination | Role |
|---|---|---|---|
| `N0` | Near endpoint | Same near endpoint | Negative control |
| `P1` | Near relay | Far backend | Positive segmented-proxy control |
| `M1` | Near relay | Co-located cache/exit | Topological alignment |
| `M2` | Near relay | Far backend with deferred response | Huma-inspired, application-specific |
| `M3` | Near relay | Far backend with synthetic delay/scheduling | Lab-only adversarial mitigation |

All cells use the same guest client, object class and randomized block order. The first implementation stays entirely on private VM links with controlled added delays.

## Metrics

- transport RTT distribution from TCP_INFO/QUIC path stats where available;
- application RTT defined by a fixed request/response boundary;
- `RTTdiff = RTT_app - RTT_transport` and normalized ratio;
- packets/time until classifier decision in a reproduced detector;
- TTFB, median/p95/p99 completion latency and goodput;
- retransmissions, queue occupancy proxy, burst/IAT features;
- accuracy/AUC/FPR/recall of the reproduced detector on held-out blocks;
- error taxonomy, never folded into timing.

Clock synchronization is not required for RTT measured at one endpoint. Cross-host one-way timestamps are forbidden unless clock error is bounded and reported.

## Procedure

1. Validate sustained transport correctness with no injected delay.
2. Generate randomized blocks across `N0` and `P1`; reproduce the qualitative NDSS fingerprint using an implementation faithful to published features.
3. Freeze detector and thresholds before testing `M1…M3`.
4. Run AB/BA crossover across multiple backend delays, loss and queue regimes.
5. Report both detector change and systems cost. A mitigation that lowers recall by destroying throughput fails.
6. Inspect whether the mitigation creates fixed delay, periodicity, ACK anomalies or flow-correlation features.

## Preferred mitigation order

1. **Topology:** co-locate outer and observable application termination (`M1`).
2. **Protocol causality:** Huma-like deferred response only for applications that naturally tolerate next-request delivery (`M2`). It is not a generic interactive VPN fix.
3. **Synthetic scheduling:** `M3` only to bound the detector's sensitivity. Never promote it directly to production.

Delaying transport ACKs fights congestion control and may create its own fingerprint. Application delay cannot make a far backend physically near; it can only reshape one observable.

## Falsifiers

- If `P1` is not distinguishable from `N0`, the harness/detector is not reproduced; mitigation results are uninterpretable.
- If `M1` retains the same gap after controlling queue/load, the endpoint model is incomplete.
- If `M2/M3` reduce RTTdiff but a held-out multi-feature classifier remains accurate, «alignment solves detection» is falsified.
- If throughput/tail latency crosses preregistered harm bounds, mitigation fails regardless of detector score.
- If improvement exists only at one fixed RTT, it is overfit and remains E1.

## 2026 caution

[Beyond RTT, NDSS 2026](https://www.ndss-symposium.org/wp-content/uploads/2026-f2086-paper.pdf) показывает в related residential-proxy setting, что простое scheduling может обрушить RTT-only recall, после чего дополнительные flow/correlation features восстанавливают detection. Scope другой, но design lesson прямой: **не оптимизировать один scalar feature и не объявлять stealth**.

## Acceptance gates

| Gate | Requirement |
|---|---|
| Reproduction | Frozen detector distinguishes `P1` from `N0` on held-out VM blocks |
| Mitigation | Preregistered reduction with CI plus bounded throughput/tail cost |
| Robustness | Multiple RTT/loss/queue regimes and held-out multi-feature detector |
| Field | Separate authorized paired experiment; netem result remains E1 |

## Safety

All qdisc, delay, capture and listener changes stay inside disposable VM/netns. The Mac sing-box, routes, DNS and PF are untouched. Captures contain synthetic payload only and are removed or redacted before export.

Related: [`architecture-causal-carrier-plane.md`](../../docs/architecture-causal-carrier-plane.md), [`claims-ledger.md`](../../docs/claims-ledger.md).
