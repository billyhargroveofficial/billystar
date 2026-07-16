# OrbStack isolated OS-TUN result

- Verdict: **PASS**
- Disposable clone: `sptun-20260716t173837z-18283-m8k2po` (opaque OrbStack ID bound before start/run, guest marker re-proved, delete-by-name preceded immediately by name-to-ID rebinding, then a late-appearance window plus ID/name absence proved)
- Host/guest boundary: isolated + network-isolated config, no mounts/forwarded ports/SSH agent, `/mnt/mac` absent, and every discovered `mac` command channel proved fail-closed
- Source/evidence channel: clean live-pushed `main` was pinned by commit-bearing `git archive`; source entered by bounded stdin and sealed evidence returned by validated stdout tar, with no shared checkout
- Scope: synthetic OrbStack Linux IPv4 tunnel plus connected IPv6 OUTPUT-block/netns only; no IPv6 tunnel or L2 claim; field evidence: false
- Network-change handoff: real c0-to-c1 default-route replacement with exact DefaultRouteChanged cause, strict intermediate lockdown/main-WAL proof, then generation-2 Active adoption through c1 before workloads
- Observer regression: a real promiscuous packet capture toggled IFF_PROMISC without replacing generation 2; evidence captures otherwise used non-promiscuous directional capture
- Carrier/authentication: production REALITY TLS 1.3 URI with X25519 short-id and ML-KEM pin, then mandatory protocol-v3 credential and enrolled allowlist
- Final secret check: guest evidence scanned against stored/raw/hex/base64 variants; all host-added logs scanned against non-reversible fingerprints
- Host safety: exact live sing-box PID/argv/config/executable plus stable routes, DNS and PF config files
- Host-safety timing: consistent before/after endpoint snapshots; no continuous host mutation monitor
- Exclusion: the shared lifecycle lock serializes Shadowpipe runners; unrelated same-host OrbStack operators remain outside the trust boundary and make the run fail on any name/ID/state drift
- macOS PF runtime exact unprivileged permission denial was unchanged; loaded runtime remains explicitly unobserved
