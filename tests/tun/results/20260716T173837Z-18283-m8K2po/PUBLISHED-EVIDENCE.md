# Published evidence summary

This is the compact, repository-safe index for the full local sealed result
`20260716T173837Z-18283-m8K2po`.

## Verdict and source

- Final verdict: `PASS`.
- Scope: disposable isolated OrbStack Linux ARM64 clone, private network
  namespaces, IPv4 Shadowpipe tunnel, explicit IPv6 OUTPUT blocking.
- Pinned source:
  `81f188f772cc6b674fde748a361691f1bda19691`.
- Pinned `git archive`:
  `4fa10de270f6e05118d187dd14affc5154aefa49097d9c9cdbf02ddb7c18da9b`,
  4,638,720 bytes, 268 extracted members.
- Full returned guest evidence stream:
  `bdbedc525193b1dd1271bd68f1d0c7c3531f9b385b018ea8a8b546074eacb67e`,
  170,055,680 bytes.
- The local sealed guest manifest contains 745 verified entries. The complete
  bundle remains under the ignored local result directory because its main
  directional carrier pcap is 168,317,113 bytes. The compact files committed
  beside this summary are exact files from that bundle; large pcaps are
  represented by `pcap-sha256.txt`.

## Causal network handoff

- Generation 1 was alive and durably Active on `c0/10.231.0.1` before the
  mutation.
- A real default-route replacement changed the underlay from `c0` to `c1`.
- The only normalized restart cause in the post-mutation log suffix was
  `DefaultRouteChanged`.
- Generation 1 exited with status 1 after arming and strictly verifying the
  durable restart lockdown; its main WAL and stale TUN/routes/bypass/DNS/main
  kill-switch were absent during the intermediate barrier.
- Generation 2 obtained a distinct PID/start identity, captured
  `c1/10.233.0.1`, reached durable Active state, and only then released the
  adopted barrier.

See `network-handoff.env`, `generation-1-network-restart.env`, the two
`generation-*-main-wal-active-summary.json` files, and
`network-handoff-lockdown-active.json`.

## Observer and leak regressions

- A real promiscuous packet capture raised and then restored the `c1`
  promiscuity refcount. Generation 2 retained the exact same PID/start identity
  and the topology-restart count stayed unchanged.
- Normal evidence captures were non-promiscuous and direction-bound.
- Client-originated IPv6 pcaps on both underlays were empty.
- The exact SP6 terminal DROP rule counted 21 packets in generation 1 and 11 in
  generation 2.
- Continuous direct IPv4 and IPv6 canaries spanned Active, intermediate
  lockdown, replacement Active, and final lockdown without a successful direct
  result.

See `promisc-observer-regression.env`,
`generation-1-ipv6-drop-counter.env`,
`generation-2-ipv6-drop-counter.env`, the four `direct-canaries-*.env` files,
and `pcap-sha256.txt`.

## Functional gates

- ICMP: 20/20, 0% loss, 1,200-byte payload.
- TCP iperf receiver bytes: 530,317,312.
- UDP iperf receiver bytes: 6,251,748; 0% loss.
- HTTP: 64 MiB source and download SHA-256 both
  `d29e4d088c91b35184c2102d796721c611834bb4e1599acc163797e3d32f8799`.
- DNS: `probe.shadowpipe.invalid` resolved to `198.18.0.2` through the
  mount-private pinned resolver.
- Forced carrier cut had no direct fallback; authenticated recovery completed
  within the recorded upper bound of 7 seconds.

## Shutdown, cleanup, and host boundary

- The manager no-restart gate was published before signaling the live
  generation-2 PID.
- Generation 3 was absent.
- Final strict lockdown remained active through the shutdown canaries.
- Explicit `--release-lockdown` removed both WALs and the exact nft table, then
  restored the expected direct `c1` baseline.
- Guest cleanup, clone deletion, source-base final stop, evidence validation,
  private-material scans, and macOS host-safety comparison were all `valid`.
- The working Mac's sing-box identity, IPv4/IPv6 default routes, DNS snapshot,
  and PF configuration hashes were unchanged. Unprivileged PF runtime
  inspection remained permission-denied before and after, so loaded PF runtime
  is not claimed.

## Non-claims

This does not prove real systemd PID-1 restart behavior, DNS-only resolver or
DHCP changes, suspend/resume, outer or tunneled IPv6, native macOS
NetworkExtension, native Windows Wintun/WFP, production deployment, hostile
operator availability, censorship resistance, or field performance.
