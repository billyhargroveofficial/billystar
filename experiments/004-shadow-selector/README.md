# Experiment 004: offline shadow selector

This fixture exercises the causal carrier selector without dialing a carrier,
changing a route, opening a socket, or touching the live VPN. The report is an
advisory `would_select` verdict, never an activation command.

From the `shadowpipe` repository root:

```bash
cargo run -p shadowpipe-core --example causal_shadow -- \
  experiments/004-shadow-selector/input.example.json
```

Use `-` instead of a path to read one JSON document from stdin. The runner
accepts schema version 1, caps input at 4 MiB, validates the selector policy,
and evaluates every candidate fail-closed against coherent Wilson evidence,
fresh successful representative workloads, access regime, topology, and
failure-domain constraints. Its deterministic JSON report
goes to stdout; parsing or validation errors go to stderr with exit status 2.
All selector/health goodput fields spell out `bytes_per_second`; the values are
not bit rates and require no implicit factor-of-eight conversion.

In the example, `domestic-relay-a` is eligible. The direct carrier is rejected
because its access regime and topology do not match the restricted-network
requirements. The second domestic relay is rejected because its evidence has
too few probes/windows and never crossed the configured one-MiB
representative-workload floor. That floor is a measurement-quality default, not
a claim about any censor byte threshold.
