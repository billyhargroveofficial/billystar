# Native Linux ARM64 current-source portability refresh

- Run: `20260716T180304Z-linux-arm64-current`
- Snapshot: actual dirty-worktree contents selected for build/test, per-file SHA-256 manifest retained.
- Frozen source size: 102293 code physical lines, including 80315 Rust lines; exact definition and per-language counts are in source-metrics.env.
- no-default workspace/all-targets: passed=718, failed=0, ignored=4.
- all-features workspace/all-targets: passed=732, failed=0, ignored=4.
- Strict Clippy: no-default=valid, all-features=valid.
- Shell split gate: host ShellCheck on the frozen snapshot=valid; native Linux ARM64 guest bash -n=valid; guest ShellCheck package is not required.
- Runner self-test partition: macOS-host Windows/Parallels=valid (1); native Linux ARM64 portability/Phase3/full-TUN/reboot=valid (4); every required runner appears exactly once.
- Format/metadata/shell/self-tests: valid/valid/valid/valid.
- Final Cargo gates used `--locked --offline`; cache warmup performed: `true`.
- VM package/component installation performed: `true`, only inside disposable clone.
- Scope: unprivileged CPU/filesystem portability only; no route, DNS, firewall, TUN, netns, qdisc, sysctl, or service mutation.
- Cleanup: clone ID/name absent for 60 seconds, source `shadowpipe-lab-base` stopped, Windows remained suspended, shared lifecycle lock released.
- macOS: live sing-box PID/start/argv/config/binary observed read-only and unchanged; no Mac network command executed.
- Field evidence: false. This is native ARM64 portability evidence, not privileged networking or censorship evidence.
- Overall: `valid`.
