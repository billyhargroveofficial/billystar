# Shadowpipe lifecycle security audit — 2026-07-17

Status: scoped Linux Production Alpha lifecycle milestone **PASS**. This
document supersedes the lifecycle-evidence status in the
[2026-07-16 audit](security-audit-2026-07-16.md); it does not turn any
synthetic result into a production or censorship-field claim.

## Executive verdict

Two separate isolated cells now close the intended milestone:

| Cell | Source boundary | Verdict | What it proves |
|---|---|---|---|
| [All-resource crash/recovery `20260716T225901Z-98821`](../tests/host-recovery/results/20260716T225901Z-98821/FINAL-RESULT.md), [compact evidence](../tests/host-recovery/results/20260716T225901Z-98821/PUBLISHED-EVIDENCE.md) | Clean pushed `c9b60e76eda9806345d23c9ca323da23e85b02d8`; through code/tool audit head `d335682`, later changes affect only reboot/recovery test tooling | **PASS**, 29/29 scenarios, 1,592 checksum entries | Current product source survives same-boot `SIGKILL` at every schema-v3 eight-resource apply/recovery boundary, either converging exactly or retaining the intended durable foreign-state `Conflict` |
| [PID-1 userspace reboot and installed client `20260717T001923Z-52605-reboot`](../tests/lockdown/results/20260717T001923Z-52605-reboot/RESULT.md), [compact evidence](../tests/lockdown/results/20260717T001923Z-52605-reboot/PUBLISHED-EVIDENCE.md) | Clean pushed `e3740752a84d981421e95a567cdf11c12c7e88d7` | **PASS**, 939 checksum entries | Real `systemd 261.1` PID 1 userspace restart, restore-before-networkd, exact native nft barrier restoration/enforcement across the restart, release, and installed-client restart/operator-stop behavior before network mutation |

These cells are intentionally non-combinable with older successful-tunnel,
portability or Windows evidence. The HTTP-stream/QUIC production Rust changes
in `2ece275` postdate the full-TUN result at `81f188f` and the native ARM64
portability result at `726500f`. Those results remain valid only for their
captured sources. At audited code/tool head `d335682`, a successful paired full tunnel, native
ARM64 portability refresh and Windows portability refresh are still open.

## Evidence boundary

Both runners:

- pinned a clean pushed commit and transferred a commit-bearing `git archive`
  through bounded stdin;
- produced and checksummed a versioned Cargo vendor bundle, then built
  guest-locally with `--frozen`, explicit source replacement and a fresh Cargo
  home;
- required isolated and network-isolated OrbStack source/clone configuration,
  no mounts, no forwarded ports and no SSH-agent forwarding;
- addressed live guest operations through a bound opaque clone ID and permitted
  name-based deletion only after immediate name-to-ID revalidation;
- proved clone ID/name absence, source-base final stop, lifecycle-lock release
  and stable before/after Mac safety snapshots;
- copied no live VPN credentials into the guest.

The result directories remain ignored because they contain thousands of raw
files. Git carries the exact final verdict, selected machine-readable sidecars
and a compact post-seal evidence index. The full local manifests verify 1,592
and 939 entries respectively.

## Crash/recovery result

The current schema-v3 journal protects eight ordered operations: TUN, two
split-default routes, endpoint-bypass route, DNS exchange, IPv4 firewall, IPv6
firewall and carrier-endpoint firewall exception.

The 29 fresh namespace scenarios cover:

- `Planned`, every apply family, DNS `Staged`, partial firewall
  acknowledgements, all-`Applied`/`Preparing` and `Active`;
- both before mutation and after convergence but before WAL acknowledgement for
  each of the eight recovery steps;
- exact cut/PID/log binding and a root-owned WAL with exact phase,
  per-operation state and recovery-marker resource;
- 28 exact baseline convergences and one intentional all-or-nothing
  foreign-resource `Conflict`.

This is strong process-crash evidence, but `SIGKILL` is not a kernel reboot,
torn write or storage power cut. The resolver target was private tmpfs, not the
guest's resolver manager.

## PID-1 userspace reboot result

The reboot cell proved live `systemd 261.1-1-arch` as PID 1 before and after an
OrbStack machine restart. Guest boot ID, PID-1 start ticks and PID/network/mount
namespaces changed; machine ID, manager identity and the shared OrbStack kernel
stayed stable. Therefore the precise claim is a real PID-1 userspace boot
transaction, not a dedicated-kernel or hardware reboot.

The lockdown WAL advanced from `Active` generation 2 to a new `Active`
generation 4 bound to the new boot and namespaces. The exact native nft
`inet`/`output` barrier allowed loopback and blocked non-loopback IPv4 on both
sides of the restart. Restore exit/activation occurred before
`systemd-networkd` start, with distinct InvocationIDs and zero restore
restarts. Explicit release removed the WAL and only owned `sp_lock` table and
restored gateway reachability.

Unit inspection used two complementary query surfaces:

- `systemctl show` for effective scalar properties and execution state;
- typed `org.freedesktop.DBus.Properties.Get` reads for empty array-valued
  execution hooks and environment-file arrays, bound to the exact unit ID and
  fragment, repeated twice, with an unknown-property negative control.

This avoids treating `systemctl`'s human formatter omission of empty arrays as
proof of absence.

## Installed-client PID-1 result

The exact source unit and normalized source-built binary were installed into
the disposable guest. Source/installed/final hashes matched. PID 1 exposed the
restore dependency, `Restart=always` and `RestartSec=1s`.

A root-owned mode-0600 empty-JSON credential fixture reached the mandatory
credential loader and failed before host mutation. Three distinct InvocationIDs
were observed while `NRestarts` increased `0 -> 1 -> 2`. An operator
`systemctl stop` then held inactive longer than `RestartSec`, produced no new
invocation and left no client process.

Canonical IPv4/IPv6 routes and rules, nft ruleset, resolver, interfaces, TUN
census and both WALs were identical before and after. This is an installed-unit
pre-mutation lifecycle result, not a successful-tunnel or leak result.

## Defects found and fixed

The runtime campaign found defects in the evidence/cleanup machinery rather
than hiding them:

- `8a42dd8` accepts packaged systemd version strings such as
  `261.1-1-arch` without weakening the minimum-version check.
- `a4b2774` moves cleanup-critical state out of function-local scope so implicit
  `set -e` unwinding cannot orphan a clone; it also normalizes a Cargo hardlink
  through verified file-descriptor traversal, accepts and safely normalizes the
  valid Cargo source-hardlink case, and rejects symlink path substitution
  fixtures.
- `6791931` replaces unreliable empty-value formatter inference with typed
  D-Bus array evidence, repeated-read equality, exact unit binding and an
  unknown-property negative control.
- `e374075` accepts the canonical identity of Arch's merged-`/usr`
  `/bin/busctl -> /usr/bin/busctl` while executing absolute trusted tool paths.
- `d335682` stops executing the privileged recovery helper with a nonexistent
  `--version` flag; future `versions.txt` files record the verified helper
  SHA-256 instead of harmless but misleading attestation-error noise.

Failed disposable runs were sealed for diagnosis and cleaned. One clone created
before the cleanup-state fix required exact-marker manual removal; the fixed
runner subsequently proved automatic cleanup and late-appearance absence.

## Mac and Windows safety

The resident Mac remained an observer, not a VPN test target. Its live
sing-box process identity, routes, DNS and PF configuration files matched at
the before/after points. PF runtime inspection was consistently unavailable
without privilege and is not claimed. No host TUN, route, DNS, PF or
NetworkExtension mutation was performed.

A separate operator safety check kept Parallels Windows suspended; that state
is not part of either sealed Linux evidence bundle. All privileged execution
occurred inside disposable isolated Linux guests.

## Remaining release gates

This milestone does **not** make Shadowpipe production-ready. The next gates
are:

1. refresh a successful paired Linux full-TUN session on current source under
   the installed PID-1 units, including carrier cut and post-reboot recovery;
2. repeat on a dedicated-kernel VM and separately test torn-write/fsync/power
   loss on disposable storage;
3. add resolver-manager, DHCP lifetime and suspend/resume event matrices;
4. complete outer and inner IPv6 route, DNS, firewall, PMTUD and leak coverage;
5. implement and validate native macOS NetworkExtension and Windows
   Wintun/IP Helper/WFP lifecycle backends;
6. refresh native Linux ARM64 and Windows build/runtime portability after
   `2ece275`;
7. add continuous packet observation where a zero-packet interval is claimed,
   distro/kernel/network-manager coverage and soak/fleet rollback drills;
8. obtain independent cryptographic review and separately authorized,
   preregistered field evidence before any censorship-resistance claim.
