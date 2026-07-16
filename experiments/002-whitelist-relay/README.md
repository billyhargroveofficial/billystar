# Experiment 002 — causal whitelist-relay crossover

Статус: design draft, не frozen preregistration. Этим изменением не создавались
cloud resources, relay listeners или field traffic. Точный field manifest,
allocation schedule, power calculation и hash должны быть заморожены отдельно
до первого field outcome.

## Prior and exact claim

Июльский vault содержит одно сильное scoped field observation: на одном
mobile-whitelist path candidate Yandex.Cloud relay провёл payload к
контролируемому foreign exit, а direct foreign endpoint не прошёл. Без
репликации и committed evidence bundle это не E2 и **не** доказывает
provider-wide или operator-wide allowlisting.

Целевая causal claim:

> В stratum `(operator, access mode, region, time window, address pool)` изменение только destination topology с direct на whitelisted relay увеличивает вероятность meaningful payload completion.

Нельзя подменять её слабой формулировкой «TCP port открылся».

## Topology

```text
                       A: direct
client VM ---------------------------------> controlled exit ----> test object

                       B: relay
client VM ---> candidate cloud relay ------> same exit ----------> same object

controls:
C1 genuine allowed service on candidate destination class
C2 non-allowlisted cloud address / pool control
C3 local/operator reachability control independent of tunnel
```

Inner crypto, object, payload length, client binary and exit remain identical for A/B. Relay is a dumb bounded forwarder and not a trust/anonymity anchor.

## Design

Within each short block:

1. Measure a tightly interleaved genuine-cover control in the same randomized
   block, but not concurrently with A/B. Simultaneous cover+treatment is allowed
   only in a separately budgeted interference cell; otherwise sharing a
   bottleneck violates no-interference assumptions.
2. Randomly assign sequence `AB` or `BA`.
3. Transfer an object above a preregistered byte floor; record success, TTFB, bytes, goodput, stall/close taxonomy.
4. Apply washout, repeat pairs.
5. Repeat on different time blocks and, only when available/authorized, different operators/address pools.

Primary estimand for ordinary A/B is the within-block paired difference
`Y_relay - Y_direct`, clustered by randomized block. Order/carryover is an
explicit covariate. A difference-in-differences estimand is used only for a
separately declared policy transition:

```text
DiD = (relay_after - relay_before) - (cover_after - cover_before)
```

Here `before/after` denote the policy/window transition or matched periods defined before the run. Ordinary A/B availability without an intervention is analyzed as a paired crossover, not forced into DiD.

The lab allocation in [`manifest.example.json`](manifest.example.json) uses 60
AB/BA blocks, one randomized-position C1 control in every block, C2 in every
fifth block, and one pre-block C3 eligibility probe that is not pooled as an
outcome arm. A future field manifest must freeze its minimum effect, binary
discordant-pair assumption, sample size, multiplicity plan, washout, and exact
schedule before traffic begins; a convenience sample can only produce a scoped
observation.

## Meaningful success

`PAYLOAD_COMPLETE` requires:

- authenticated tunnel/session established;
- at least the preregistered payload floor delivered end-to-end;
- no DNS/route escape from the guest;
- exit/object identity matches the controlled target;
- no local implementation fault.

TCP connect, TLS ServerHello or a few kilobytes are insufficient.

## VM phase

The first phase emulates allowlisting only inside private OrbStack Arch
namespaces. Parallels remains a portability/socket smoke and receives no
allowlist, route, firewall, DNS or impairment mutation:

- direct destination denied by a guest-local policy;
- relay destination allowed;
- negative cloud control denied;
- analyzer must recover the injected causal effect under AB/BA randomization.

This proves harness correctness. Result label must be `LAB_POLICY_RECOVERED`, never «TSPU bypassed».

## Field phase — separate authorization required

Prerequisites:

- explicit user authorization for the named owned disposable endpoints and mobile vantage;
- provider ToS/legal/KYC review and a cleanup deadline;
- no Mac routing: test originates inside a dedicated guest/SIM/vantage;
- per-operator address reachability checked in the same block;
- byte/rate/time caps and automatic listener expiry;
- no production key/subscription reuse;
- redacted result bundle without IPs or credentials.

## Confounders and controls

| Confounder | Control |
|---|---|
| Policy changed between A and B | Randomized AB/BA, short blocks, genuine cover interleaved in the same block; concurrency only in a declared interference cell |
| Exit itself unhealthy | Same exit/object for both arms; exit-side health control |
| TLS/protocol bytes differ | Same inner session and payload; document unavoidable outer differences |
| Provider routes relay differently | This is part of topology treatment; stratify by address pool/region |
| Crowd whitelist list stale/operator-specific | Treat list as sampling prior only; direct live reachability is decisive |
| Relay success due to cache/local response | End-to-end nonce/object hash from controlled exit |
| Local client bug | VM correctness gate and disjoint error taxonomy |

## Falsifiers

- Both A and B consistently succeed: no evidence relay is necessary in this stratum.
- Both fail while genuine cover succeeds: candidate relay is not an effective bypass.
- B effect vanishes under AB/BA or correlates with time order: likely policy drift/confounding.
- Candidate and negative cloud control behave identically: «whitelisted range» explanation weakened.
- Only handshake passes but payload floor stalls: claim fails.
- Result requires changing the Mac route/VPN: experiment is rejected, not adapted.

## Graduation

| Level | Requirement | Allowed wording |
|---|---|---|
| E1 | VM analyzer recovers injected allowlist effect | Harness works in lab |
| E1F | One authorized paired field observation | One scoped observation on this path/window |
| E2 | Independent replicated pairs in the same declared field stratum | Repeatable in this bounded stratum |
| E3 | Multiple operator/time/address-pool strata with effect interval | Opt-in canary for measured strata |
| E4 | Longitudinal + independent replication | Operational candidate, still revocable |

## Safety and ethics

Use only owned endpoints and bounded payloads. No address-space scanning, credential harvesting, provider-account evasion or concealment of cloud usage. A technically successful relay remains KYC-visible and revocable. The live Mac sing-box is `NO_TOUCH`.

Related: [`claims-ledger.md`](../../docs/claims-ledger.md), [`threat-model-2026.md`](../../docs/threat-model-2026.md), vault note `yandex-cloud-whitelist-relay-2026-07-10.md`.
