# Experiment 005 — blind tunnel response oracle

Статус: **design draft, не frozen preregistration и не запущен**. Этот каталог
не содержит результата, field evidence, packet injector или разрешения на
полевой тест. Любой run требует отдельно материализованного и закоммиченного
schedule, hashes всех recipes/бинарей и disposable Linux VM. Интернет, живые
endpoint'ы и macOS host находятся вне scope.

## Motivation and exact claim boundary

[Tolley et al., FOCI 2026](https://www.petsymposium.org/foci/2026/foci-2026-0007.php)
повторно продемонстрировали класс архитектурных VPN-уязвимостей: blind
in/on-path adversary может посылать spoofed packets и использовать
предсказуемые NAT/routing/tunnel responses как oracle для tunnel address,
TCP-state/tuple inference и disruption. Их 2025 re-test охватывает конкретный
Pixel 10 Pro XL с Android 16 и шесть VPN/circumvention tools. Это серьёзный
attack class, но не доказательство уязвимости Shadowpipe, любого Linux kernel
или российского censor deployment.

Цель этого эксперимента уже и проверяема:

> В полностью изолированной synthetic VM topology входной пакет, совпадающий
> с заранее созданным tunnel/TCP state, вызывает отличимый victim-originated
> outer-tunnel response или application reset чаще, чем matched negative packet;
> strict ingress/interface/state policy устраняет этот differential без утечки
> legitimate traffic.

Результат может доказать только корректность harness и наличие/отсутствие
oracle в перечисленных guest kernel, tunnel implementation и config hashes.
Он не даёт права писать «Android/VPN/TSPU vulnerable».

## Questions

1. Возникает ли attacker-visible response differential между assigned и
   unassigned tunnel address при одинаковом injected packet?
2. Зависит ли differential от IPv4/IPv6, NAT/routed topology, TCP state и
   packet type?
3. Можно ли отличить active tuple/port и in-window state от matched negative,
   не используя payload или внутренний ground truth в detector?
4. Прерывает ли matching in-window reset заранее созданный synthetic flow
   чаще, чем out-of-window reset?
5. Устраняют ли strict interface scoping и stateful response filtering oracle,
   не ломая обычные tunnel flows?

## Lab-only topology

Все узлы — Linux network namespaces **внутри одной disposable VM**. Ни один
lab bridge/veth не соединяется с management NIC, host bridge, shared NAT или
default route VM.

```text
                         access segment (private veth only)
  ns-attacker ------------------------------------------------ ns-client
      | attacker-visible capture                                 | underlay
      |                                                           | encrypted outer tunnel
      +---------------- ns-transit --------------------------- ns-vpn
                                                                  | routed or synthetic NAT cell
                                                                  |
                                                             ns-destination
                                                                  |
                                                             fixed TCP object

  ns-observer: read-only ground-truth capture peers on access, tunnel and
               destination links; its data is forbidden to the attacker detector
```

Namespace roles:

- `ns-attacker`: emits only schedule-listed raw packets and observes only the
  access/outer direction visible to the modeled blind adversary;
- `ns-client`: owns one synthetic tunnel address, one underlay address and the
  preregistered TCP state;
- `ns-transit`: a pure private hop, used to keep the attacker on-path without
  granting access to guest management networking;
- `ns-vpn`: terminates the selected test tunnel and applies the frozen
  routed/SNAT recipe;
- `ns-destination`: deterministic TCP sink/source with nonce and object hash;
- `ns-observer`: captures packet-level ground truth and counters for causal
  validation; analysis of attacker visibility cannot read it.

IPv4 uses only `198.18.0.0/15` benchmark space. IPv6 uses only
`2001:db8::/32` documentation space. Names end in `.lab.invalid`. Every test
namespace has no default route and an allowlist for the exact lab prefixes and
ports. The root guest namespace never forwards lab traffic to a physical NIC.

## Valid topology cells

Factor arrays are not a Cartesian product. The frozen schedule contains only
these valid cells:

| Cell | Family | Egress state | Purpose |
|---|---|---|---|
| `V4-R0` | IPv4 | routed, no translation | isolate route/response behavior |
| `V4-NP` | IPv4 | SNAT44, port-preserving deterministic mapping | positive predictable-NAT contrast |
| `V4-NR` | IPv4 | SNAT44, bounded randomized port range | mapping-randomization contrast |
| `V6-R0` | IPv6 | routed, no translation | native IPv6 control |
| `V6-N66` | IPv6 | stateful NAT66, lab diagnostic only | translation contrast, not a deployment recommendation |

Each recipe freezes route tables, policy rules, neighbor state, conntrack/NAT
rules, relevant sysctls and tunnel configuration by hash. IPv4 and IPv6 are
reported separately. `V6-N66` cannot support a claim about ordinary native IPv6
deployments.

Ingress/security profiles:

- `V0_PERMISSIVE_REPRODUCTION`: deliberately permissive guest-only recipe used
  to ask whether the kernel/tunnel produces the described oracle;
- `H1_STRICT_INTERFACE_SCOPE`: packets arriving from the access interface for
  the virtual tunnel prefix are dropped before local delivery/forwarding;
- `H2_H1_PLUS_STATEFUL_RESPONSE_FILTER`: `H1` plus stateful policy that rejects
  unsolicited tuple/state transitions and suppresses externally distinguishable
  responses.

`V0` is not assumed vulnerable. A separate synthetic responder is the harness
positive control; if a real tunnel/profile does not reproduce the oracle, the
answer is scoped `NO_ORACLE_OBSERVED`, not a reason to loosen safety or tune the
system after looking at outcomes.

## TCP-state strata

State is constructed from an immutable recipe and verified from inside
`ns-client` immediately before treatment:

| State | Ground-truth condition | Eligible treatments |
|---|---|---|
| `NO_SOCKET` | no matching local socket or conntrack entry | address/tuple negative controls |
| `LISTEN` | bound listener, no accepted flow | SYN and SYN/ACK state probes |
| `SYN_SENT` | fixed synthetic connect is pending | SYN/ACK and ACK probes |
| `ESTABLISHED_IDLE` | authenticated test flow, no payload in observation window | tuple, ACK and RST probes |
| `ESTABLISHED_ACTIVE` | fixed-rate synthetic payload is moving | tuple, ACK and RST probes |
| `TIME_WAIT` | cleanly closed matching flow | late ACK/RST controls |

Fresh namespaces are created from the same recipe before every destructive
trial. Where a namespace cannot be recreated, a pair is invalid unless socket,
conntrack, route, neighbor and response-rate-limit state all return to the
recorded baseline. No adaptive port/address/sequence scan is permitted.

## Raw packet treatments and matched controls

Each trial emits at most **one** raw TCP packet. Addresses, ports, flags and
sequence/ack labels are drawn only from the frozen schedule. Candidate sets are
small synthetic sets (at most 16 addresses, 32 ports and 16 predeclared sequence
bins), not Internet ranges.

| Family | Treatment | Matched negative control | Primary outcome |
|---|---|---|---|
| Address | SYN/ACK to assigned synthetic tunnel address | same bytes to unassigned address in same lab prefix | victim-originated outer response |
| Remote identity | same packet with matching remote endpoint | wrong synthetic remote address, same local state | outer response differential |
| Local port | ACK/SYN-ACK to active/listening port | same bytes to unused scheduled port | outer response differential |
| TCP window | ACK or RST with preregistered in-window label | same tuple with far out-of-window label | outer response and kernel TCP action |
| Disruption | in-window RST against established synthetic flow | out-of-window RST | authenticated flow reset/interruption |
| Sham | no packet, identical observation window | n/a | background outer packets |
| Hardening | matching treatment under `H2` | same treatment under `V0`, paired with its own negative | mitigation difference-in-differences |

Additional negative controls are `NO_SOCKET`, wrong address family, an
unrouted documentation-prefix address and a scheduled wrong 4-tuple. The
attacker detector ignores the emitted frame and considers only packets in the
victim-to-tunnel-server direction after the treatment timestamp. Ground-truth
pcap, conntrack and kernel counters are used only to validate the causal chain.

## Experimental unit and frozen allocation

One causal unit is a **paired block** with immutable
`(family, topology cell, tunnel hash, ingress profile, TCP state, packet family,
load recipe)` and two independently recreated trials: matching treatment and
matched negative. Order is balanced `AB/BA` and chosen by a seeded ChaCha20 RNG.
Reset trials never reuse the connection from the previous trial.

Planned stages in [`manifest.example.json`](manifest.example.json):

1. `SAFETY_AND_STATE_CORRECTNESS`: 24 non-injection trials; verify isolation,
   legitimate tunnel completion, state recipes and capture direction.
2. `DETECTOR_CALIBRATION_AND_FREEZE`: 80 synthetic positive-oracle trials and
   60 null/sham trials. Freeze detector, threshold and analysis binary before
   any real-tunnel outcome is opened.
3. `ADDRESS_ORACLE_HELD_OUT`: 120 paired blocks (240 trials), with at least 60
   blocks each in primary `V0` and `H2` profiles.
4. `TUPLE_AND_TCP_STATE_HELD_OUT`: 240 paired blocks (480 trials); a frozen
   fractional allocation covers all state/family/topology cells, with
   preregistered interaction contrasts.
5. `RESET_OUTCOME_HELD_OUT`: 120 paired blocks (240 trials), with 60 primary
   `V0` and 60 primary `H2` blocks.

Total cap: 1,124 trials, of which at most 1,040 emit one raw packet. Schedule,
block IDs, treatment order, candidate values and exclusion rules are
materialized in `allocation-schedule.json` and hashed before main outcomes.
Factors not allocated there do not exist post hoc.

## Packet-level outcomes

Every trial has exactly one terminal class and a causal-chain record:

1. `injection_emitted` and hash of the header-only scheduled packet;
2. `access_ingress_seen` at ground truth;
3. `ingress_disposition`: `PRE_ROUTE_DROP`, `LOCAL_INPUT`, `FORWARDED`,
   `TUNNEL_INPUT`, or `UNKNOWN`;
4. `route_egress_interface` and policy-rule ID;
5. `conntrack_state` plus redacted NAT mapping class;
6. `kernel_tcp_action`: `SILENT`, `SYN_ACK`, `RST`, `CHALLENGE_ACK`, `ACK`,
   `RETRANSMIT`, or `UNKNOWN`;
7. attacker-visible outer packet-count/byte/size/timing delta after subtracting
   the paired sham baseline;
8. application outcome: `ALIVE`, `COMPLETE`, `RESET`, `TIMEOUT`, `CORRUPT`, or
   `NOT_APPLICABLE`.

Primary oracle event is defined by a detector frozen after calibration, using
only attacker-visible direction, packet sizes and monotonic relative times.
No payload, inner capture, socket table, conntrack state or namespace counter is
an attacker feature. Capture loss, state mismatch, clock anomaly, unexpected
background traffic or an incomplete causal chain yields `MEASUREMENT_FAULT`,
not a negative observation.

## Causal and statistical plan

Primary estimands:

```text
RD_address = P(outer_oracle | assigned address)
             - P(outer_oracle | unassigned matched address)

RD_tuple_state = P(outer_oracle | matching tuple/state)
                 - P(outer_oracle | matched wrong tuple/state)

RD_reset = P(application reset | in-window RST)
           - P(application reset | out-of-window RST)

DiD_hardening = RD_V0 - RD_H2
```

- Binary paired endpoints use exact McNemar tests and paired risk-difference
  intervals; the three primary families use Holm correction.
- Conditional logistic regression with block fixed effects is secondary and
  estimates frozen IPv4/IPv6, topology, TCP-state and order interactions.
- No family is pooled across address families or tunnel implementations for a
  protocol claim. Sparse interaction cells remain descriptive.
- Calibration must achieve a two-sided 95% Wilson sensitivity lower bound of
  at least 0.95 on 80 synthetic positives and a one-sided 95% null false-positive
  upper bound below 0.05 on 60 nulls.
- A mitigation passes only if its oracle-event upper bound is below the frozen
  limit, legitimate completion is non-inferior within the frozen margin, and
  no DNS/route leak or new response class appears.
- More than 2% `MEASUREMENT_FAULT`, any differential attrition by arm, or any
  schedule/hash mismatch makes the affected family `INCONCLUSIVE`.

Calibration proves only that the observer can see an injected synthetic oracle.
For a mitigation claim, `V0` must first show a held-out positive differential;
otherwise `H1/H2` results cannot be credited as having removed an oracle.

## Falsifiers and stop rules

- Synthetic positive and null controls fail their frozen sensitivity/FPR gates:
  detector/harness invalid; stop before main stage.
- The emitted packet is not observed at the expected private ingress, or the
  state recipe does not match: `MEASUREMENT_FAULT`, never silence.
- Assigned/matching and negative controls have the same response distribution
  in `V0`: no oracle reproduced in that scope.
- Apparent signal disappears after excluding the injected frame or is explained
  by background traffic, challenge-ACK rate limiting, order or capture loss:
  oracle claim falsified/inconclusive.
- `H2` still exposes a differential, or legitimate traffic fails the
  non-inferiority/leak gate: mitigation fails.
- IPv4-only evidence cannot support IPv6; NAT66 cannot support native-IPv6;
  one tunnel/config cannot support a cross-protocol claim.
- Any packet leaves a lab namespace toward a management/default interface, any
  unlisted target appears, or cleanup is incomplete: immediate abort and entire
  run invalid.

## Safety, caps and cleanup

- macOS sing-box, routes, DNS, PF, NetworkExtension, TUN and services are
  **NO_TOUCH**. The Mac is only a read-only build/observation coordinator.
- Runner must fail closed unless Linux VM attestation, explicit lab token,
  namespace isolation and the absence of lab-to-default routes all pass.
- No Internet socket, DNS lookup, public IP, cloud endpoint, production key,
  subscription or user traffic is allowed.
- Raw injection is limited to one packet/trial, 1 packet/s, burst 1; no adaptive
  scanning. Maximum duration is four hours and maximum synthetic application
  payload is 128 MiB across the run.
- A unique run prefix prevents namespace collisions. `EXIT`, `INT` and `TERM`
  cleanup removes only prefix-owned namespaces, veths, bridges, qdiscs,
  nftables tables, listeners and temporary files.
- Post-cleanup proof must show: no prefix-owned namespace/link/table/qdisc,
  no lab listener, no route for lab prefixes, no changed management-interface
  qdisc, and no live test process. Failure is recorded as
  `CLEANUP_INCOMPLETE` and blocks publication.

## Provenance and outputs

Before freeze, record hashes of the git/worktree state, VM image, kernel,
sysctls, route/policy/NAT/firewall recipes, tunnel/client/server binaries,
injector, capture filters, detector, analysis binary and allocation schedule.
Record UTC window and monotonic clock source. Raw header captures and ground
truth stay access-controlled; a publishable bundle contains aggregates,
redacted packet-header summaries, complete exclusions and checksums only.

Required result wording:

- before a run: `DESIGN_DRAFT_NOT_RUN`;
- successful synthetic calibration only: `HARNESS_ORACLE_RECOVERED`;
- successful held-out real-tunnel differential in a declared VM cell:
  `ORACLE_REPRODUCED_IN_SCOPED_VM_CELL`;
- no held-out real-tunnel differential: `NO_ORACLE_OBSERVED_IN_SCOPED_VM_CELL`;
- ambiguous attribution: `INCONCLUSIVE`;
- never: `FIELD_BYPASS`, `TSPU_VULNERABLE`, `ALL_VPNS_VULNERABLE` or
  `MITIGATION_PROVEN_GLOBALLY`.

Related: [`threat-model-2026.md`](../../docs/threat-model-2026.md),
[`claims-ledger.md`](../../docs/claims-ledger.md), and
[`architecture-causal-carrier-plane.md`](../../docs/architecture-causal-carrier-plane.md).
