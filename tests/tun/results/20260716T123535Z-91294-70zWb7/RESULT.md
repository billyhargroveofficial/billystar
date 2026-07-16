# OrbStack isolated OS-TUN result

- Verdict: **PASS**
- Disposable clone: `sptun-20260716t123535z-91294-70zwb7` (opaque OrbStack ID bound before start/run, guest marker re-proved, delete-by-name preceded immediately by name-to-ID rebinding, then a late-appearance window plus ID/name absence proved)
- Scope: synthetic OrbStack Linux IPv4/netns only; field evidence: false
- Carrier/authentication: production REALITY TLS 1.3 URI with X25519 short-id and ML-KEM pin, then mandatory protocol-v3 credential and enrolled allowlist
- Final secret check: guest evidence scanned against stored/raw/hex/base64 variants; all host-added logs scanned against non-reversible fingerprints
- Host safety: exact live sing-box PID/argv/config/executable plus stable routes, DNS and PF config files
- Host-safety timing: consistent before/after endpoint snapshots; no continuous host mutation monitor
- Exclusion: the shared lifecycle lock serializes Shadowpipe runners; unrelated same-host OrbStack operators remain outside the trust boundary and make the run fail on any name/ID/state drift
- macOS PF runtime exact unprivileged permission denial was unchanged; loaded runtime remains explicitly unobserved
