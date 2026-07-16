# Shadowpipe early-userspace L3 lockdown reboot result

- Verdict: **PASS**
- Disposable clone: `sphr-lock-20260716t124706z-34564` (opaque ID bound for start/restart/guest operations; delete-by-name required a fresh name-to-ID revalidation, followed by ID/name absence proof)
- Real kernel/systemd reboot: distinct boot IDs and strict WAL boot/PID-1 namespace binding
- Durable WAL: exact schema v1 Active generation 2 -> 4, fresh identity, handle matched exact nft listing
- Enforcement observed: exact native nft inet/output barrier; loopback passed and non-loopback IPv4 ping was denied
- Ordering observed: systemd >=254; unique InvocationIDs, zero restarts and monotonic activation timestamps prove restore completion before networkd start
- Recovery observed: explicit operator release removed WAL and the only sp_lock table; guest IPv4 gateway became reachable
- macOS safety observed: routes, DNS, exact sing-box PID/argv/config/executable and PF configuration files were unchanged
- Host-safety timing: consistent before/after endpoint snapshots; no continuous host mutation monitor
- Exclusion: the shared lifecycle lock serializes Shadowpipe runners; unrelated same-host operators remain outside the trust boundary and any name/ID/state drift fails closed
- macOS PF runtime: exact unprivileged permission-denied tuple was unchanged; runtime rules remain explicitly unobserved
- Build contract: a validated explicit SHADOWPIPE_MAGIC u32 was recorded and used for the binary build
- Private-material scan scope: the reboot experiment creates no VPN credential/private-key values and copies no live config bytes; the pre-existing Mac config is represented only by SHA-256
- Scope: one disposable guest, early-userspace Linux L3 local OUTPUT plus explicit release only
- No paired client/server tunnel, production, initrd, L2/AF_PACKET, FORWARD, container-netns, or censorship-field claim
