# Experiment 001 — trigger unit and the «16 KiB» contradiction

Статус: design draft, не запущен и ещё не preregistered. Он станет frozen
preregistration только после генерации и коммита точного allocation schedule,
manifest hash и analysis version **до** просмотра outcomes.

## Research question

Существует ли на заданном path/window устойчивый silent-degradation trigger, и если да, к какой единице он привязан: 5-tuple, destination, prefix/ASN, classified flow или compound policy?

Текущий prior — **`T0 / UNKNOWN_CONDITIONAL`**. На repo scope blanket/per-flow model не поддержана:

- 155/155 raw flows завершили nominal 2 MiB targets; observed counters summed
  to 328.409 MB (about 313.2 MiB) versus 310 MiB nominal payload;
- Shadowpipe прошёл примерно 0.8–2.5 MB (decimal) до собственных correctness faults;
- Chrome-TLS прошёл 20 MiB ×2 без stall;
- rotation guard дал примерно 1000× throughput penalty.

Следовательно, blanket-утверждение «per-5-tuple proven» противоречит этим
конкретным flows/path/window. Условная модель `T1` не фальсифицирована: в strata
без положительного trigger reset unit неидентифицируема. Эксперимент не ищет
подтверждение любимой модели; он сначала требует воспроизвести сам trigger.

## Competing models

| Code | Model | Observable prediction after trigger is reproduced |
|---|---|---|
| `T0` | Unknown/conditional or inactive in this stratum | Нет стабильного onset либо onset объясняется interaction factors |
| `T1` | Per 5-tuple | Новый transport connection к тому же destination получает независимый budget |
| `T2a` | Destination IP:port aggregate | Fresh tuples к той же socket destination делят budget; смена port сбрасывает effect |
| `T2b` | Destination IP aggregate | Разные ports того же IP коррелируют; смена IP сбрасывает effect |
| `T3a` | Prefix aggregate | Разные addresses одного controlled prefix коррелируют; другой prefix сбрасывает effect |
| `T3b` | ASN aggregate | Разные prefixes одного ASN коррелируют; другой ASN сбрасывает effect |
| `T4` | Classifier × topology | Raw negative, selected TLS/carrier/port positive при той же destination topology |
| `T5a` | Path-global policy | Разные controlled destinations меняются совместно в одном access-path block |
| `T5b` | Time policy | Один controlled path синхронно меняется между randomized time blocks |

## Experimental units and factors

Одна unit = один bounded transport flow с immutable pair/block ID. Factors:

- carrier shape: `raw`, `real_tls`, `shadowpipe_after_correctness_gate`;
- port class: `high`, `https-like`;
- concurrency `K`: 1, 2, 4, 8, 16;
- connection strategy плюс explicit contrasts: fresh tuple, same-IP/new-port,
  same-prefix/new-IP, same-ASN/new-prefix, different ASN и next-time-block;
- payload floor/ramp: 8 KiB … 4 MiB, but no fixed threshold is assumed;
- impairment model in VM: none, T1, T2, T3-emulated, T4-emulated;
- direction: downlink, uplink, balanced;
- randomized sequence and block.

Shadowpipe cell is inadmissible until sustained transfer correctness passes without AEAD/framing/EOF faults.

## Procedure

1. Load [`manifest.example.json`](manifest.example.json) only as a draft; first
   materialize and commit a secret-free allocation schedule, sensitivity/power
   calculation and hashes. Until then no outcome may be interpreted as a
   preregistered result.
2. Establish no-impairment baseline and positive local fault controls.
3. Материализовать staged fractional-factorial allocation; перечисленные factors
   — candidate universe, а не Cartesian product. Проверить, что 376 allocated
   trials, включая три warmup внутри 12-trial correctness stage, помещаются в
   time/payload caps, затем заморозить schedule + hash.
4. Run VM censor-emulator cells in randomized order. The harness must identify the injected model and return `NO_TRIGGER_OBSERVED` in the null cell.
5. Treat only flows with **no target event** by the fixed observation horizon as
   right-censored, not as onset at max bytes. Successful payload completion and
   crypto/framing/measurement failures are distinct terminal/competing outcomes
   or explicit missingness, never automatic non-informative censoring.
6. Record `bytes_before_event`, goodput windows, RTT/retrans/loss, close flags and disjoint error cause.
7. Analyze onset with competing-risk sensitivity analysis and block-clustered uncertainty; compare candidate models by preregistered predictive checks, not a single p-value.
8. Only after VM validation may a separately authorized field manifest be created.

## Event definition

Primary network event `silent_degradation` requires all:

- connection remains nominally established;
- delivered goodput drops below a preregistered fraction of its own baseline for a minimum duration;
- no local crypto/framing error, remote application close or measurement timeout explains it;
- positive control path remains observable.

Other outcomes are distinct: `complete`, `connect_fail`, `remote_close`, `rst`, `crypto_error`, `framing_error`, `local_timeout`, `measurement_fault`.

## Falsifiers

- `T1` is falsified in a stratum only after a positive trigger exists and fresh
  5-tuples demonstrably share the same onset/budget. With no trigger, `T1` is
  unidentifiable; assigning any reset unit is an analysis failure.
- `T2` is falsified if independent same-destination flows show independent budgets while measurement power is sufficient.
- `T4` is weakened if raw and shaped flows respond identically after controlling port/destination/time.
- Any censor attribution is invalid if implementation faults precede the network event.
- A VM result is never evidence that TSPU uses the injected model.

## Acceptance gates

| Gate | Requirement |
|---|---|
| Harness | Frozen confusion matrix over 30 held-out trials for each of eight injected positive models; ≥95% micro accuracy, ≥70% per-model Wilson lower recall bound, no unreported class collapse; null false-positive one-sided 95% upper bound <5% (requires ≥59 null trials when zero errors are observed) |
| Correctness | Sustained payload completes with no framing/crypto corruption before network inference |
| Field E1F | One bounded, authorized positive trigger observation with meaningful payload control |
| Field E2 | Independently replicated paired result in the same declared operator/path stratum |
| Model claim E3 | Randomized crossover and replication across at least two independent strata |

Thresholds may be adjusted only before outcome inspection and must change the manifest hash/version.

## Safety

- Mac sing-box, routes, DNS, PF and NetworkExtension are **NO_TOUCH**.
- All qdisc/firewall/listener mutations occur inside disposable VM/netns.
- New publishable experiment artefacts contain no production endpoints,
  secrets, subscriptions or real IPs; historical private notes are not evidence
  bundles.
- This experiment does not perform Internet-wide probing.

## Evidence links

- [`planeb-01-RESULT.md`](../../review/01/planeb-01-RESULT.md)
- [`planeb-02-shadowpipe-tunnel-RESULT.md`](../../review/01/planeb-02-shadowpipe-tunnel-RESULT.md)
- [`claims-ledger.md`](../../docs/claims-ledger.md)
