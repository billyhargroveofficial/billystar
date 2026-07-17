# Published evidence summary

This is the compact, repository-safe index for the full local sealed result
`20260717T001923Z-52605-reboot`.

## Verdict and provenance

- Final verdict: `PASS`.
- Pinned clean pushed source:
  `e3740752a84d981421e95a567cdf11c12c7e88d7`.
- Pinned `git archive`: SHA-256
  `aac1e6221ca38c8d005970586e9caf05167cf90c3ff89e6f1dc69dc4673eab35`,
  5,171,200 bytes and 335 extracted members.
- A separately checksummed Cargo vendor archive supplied 276 registry
  packages and 15,515 files. The guest built with `--frozen` in a fresh
  network namespace and fresh Cargo home, with CLI source replacement, no
  egress route and no pre-existing cache.
- The raw Cargo output was a source hardlink (`nlink=2`). A source-verified,
  no-symlink file-descriptor traversal normalized the installed artifact to a
  distinct regular file with `nlink=1`, mode `0755` and 10,387,424 bytes.
- The sealed local bundle contains 939 checksum entries. Its checksum manifest
  SHA-256 is
  `e3e35de4a76bbbe503d263821fcc8acc3ccfdda8203bcc0a7ee0ca5d2789cd33`.

The full 3.8 MiB result remains under the ignored local result directory. The
committed `RESULT.md` is copied exactly from that sealed result and is covered
by the manifest. This human summary was authored after finalization and is
intentionally not a member of the sealed bundle or its checksum census.
The repository also publishes the sealed `status.env`, `build-contract.txt`,
`userspace-systemd-boot.env`, `client-systemd-loop.json` and
`client-restart-stability-wait.env` sidecars; raw host/guest state remains
local.

## Real systemd PID 1 userspace boot transaction

- `systemd 261.1-1-arch` was the live PID 1 before and after the OrbStack
  machine restart.
- Boot ID, PID-1 start ticks, PID namespace, network namespace and mount
  namespace all changed. Machine ID, PID-1 executable, manager version and
  shared OrbStack kernel release stayed stable.
- The lockdown WAL moved from `Active` generation 2 to a fresh `Active`
  generation 4, bound to the new boot and namespace identities.
- The exact native nft `inet`/`output` barrier allowed loopback and denied
  non-loopback IPv4 before and after restart.
- The restore unit exited successfully at monotonic timestamp `127659723169`
  and entered active at `127659723409`; `systemd-networkd` started later at
  `127659729185`. It had a distinct InvocationID and zero restarts.
- Effective-unit checks bound the exact unit ID and fragment path, rejected
  drop-ins and daemon-reload drift, and used typed D-Bus reads to prove empty
  `ExecCondition`, `ExecStartPre`, `ExecStartPost` and `EnvironmentFiles`
  arrays. Two reads matched and an unknown-property negative control failed.
- Explicit operator release removed the WAL and the only owned `sp_lock` table,
  after which the guest gateway was reachable.

## Installed client unit under PID 1

- Source, installed and final binary SHA-256 were identical:
  `ddf50803483c7fabb84e82836429c40453c46afb8ce0ab10b13470c6a1b6c640`.
- Source, installed and final client-unit SHA-256 were identical:
  `9403d5ee9174671a21de616d2d7e8ce018d0d6a2aa36ad8c60af1a3e782ca590`.
- PID 1 exposed the required restore-unit dependency plus
  `Restart=always`/`RestartSec=1s`. A mandatory root-owned empty-JSON
  credential fixture failed before network mutation.
- Three distinct failure InvocationIDs were observed while `NRestarts`
  increased `0 -> 1 -> 2`. After `systemctl stop`, a 2.259366-second interval
  produced no new invocation and left the unit inactive with no client
  process.
- Canonical IPv4/IPv6 routes and rules, nft ruleset, resolver identity,
  interfaces, TUN census and both Shadowpipe WALs were byte-for-byte identical
  before and after this subcell.

## Isolation, cleanup and non-claims

The disposable clone was deleted, the exact ID/name stayed absent through the
late-appearance window, the source base finished stopped, and the Mac's live
sing-box identity, routes, DNS and PF files were unchanged at both endpoints.

This proves one shared-kernel OrbStack userspace reboot under a real systemd
PID 1 plus an installed-client fail-closed pre-mutation restart/stop lifecycle.
It does not prove a dedicated-kernel or hardware reboot, initrd behavior,
storage power loss, a successful paired tunnel, continuous zero-packet boot
silence, native macOS/Windows networking, production or field operation, or
censorship resistance.
