# Shadowpipe causal replay

`sp-causal-replay` is a deterministic, offline transform from versioned
`MeasurementRun` traces to an advisory carrier-selection report. It has no
socket, route, DNS, TUN, carrier lifecycle, or activation API.

Safety and scientific boundaries:

- input is capped at 16 MiB and every trace passes semantic schema validation;
- replay v2 requires explicit expected experiment/artifact IDs and rejects any
  trace outside that caller-attested cohort;
- each carrier declares an exact positive `expected_window_refs` set and must
  provide exactly one client trace per declared independent window; every
  compared carrier must declare the same window cohort;
- a successful probe needs a connected dial, clean terminal close,
  representative payload and no unresolved stall;
- any pending, inconclusive or otherwise excluded retained trace forces carrier
  state to `unknown`, preventing survivorship-biased selection;
- health stays `unknown` until the selector's minimum probe/success/window gates;
- reachability uses Wilson bounds and goodput uses Welford moments with a
  small-sample Student-t interval.

The IDs, schedule and window-independence claims are caller-attested, not
cryptographically proven. Cohort validation prevents accidental mixing but a
malicious or incomplete producer can still lie unless the IDs and declared set
are bound to a separately frozen, signed manifest. The Student-t interval is
descriptive under independent-window, fixed-look and approximately normal mean
assumptions; this runner does not certify those assumptions or a multiplicity
plan. Therefore `would_select` means only “this validated input passes this
shadow policy,” never “activate a route.”

Run the complete trace-derived example from the workspace root:

```bash
cargo run -p shadowpipe-causal-replay -- \
  crates/shadowpipe-causal-replay/examples/scenario.example.json
```
