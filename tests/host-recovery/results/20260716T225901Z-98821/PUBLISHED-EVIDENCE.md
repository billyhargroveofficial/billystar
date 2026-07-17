# Published evidence summary

This is the compact, repository-safe index for the full local sealed result
`20260716T225901Z-98821`.

## Verdict and provenance

- Final verdict: `PASS`.
- Pinned clean pushed source:
  `c9b60e76eda9806345d23c9ca323da23e85b02d8`.
- Pinned `git archive`: SHA-256
  `55ddc42bb770d4626907ad0d7eaacfbd3f24dda035be6d92af5a2f5b7125399c`,
  5,130,240 bytes and 334 extracted members.
- The source archive and a separately checksummed Cargo vendor bundle entered
  guest-local storage through bounded stdin. The guest used a fresh Cargo home,
  CLI source replacement and `--frozen`; no shared checkout or host target
  mount was used.
- The vendor bundle contained 276 registry packages and 15,515 files. Its
  archive SHA-256 was
  `800ece44a103a2c5ff837c19b045117c72d42416ffe2184ce25ef9220453404c`.
- The sealed local bundle contains 1,592 checksum entries. Its checksum
  manifest SHA-256 is
  `419ca5db71d69dd6723c61bec3f7c2bf8bfac5b6dce0c54d08d57870c64a179d`.

The full 6.3 MiB result remains under the ignored local result directory. The
committed `FINAL-RESULT.md` is copied exactly from that sealed result and is
covered by the manifest. This human summary was authored after finalization and
is intentionally not a member of the sealed bundle or its checksum census.
The repository also publishes the sealed `RESULT.md`, `status.env` and
`host-evidence/build-contract.env` sidecars; raw scenario state remains local.

## Crash and recovery matrix

- All 29 fresh network, mount and PID namespace scenarios passed.
- Twenty-eight scenarios converged to the exact pre-test network snapshot and
  removed the completed journal. The remaining scenario intentionally planted
  foreign state and produced the expected durable `Conflict` without deleting
  it.
- Every `SIGKILL` marker was bound to one exact cut label, PID and log record.
  Every crash retained a mandatory root-owned schema-v3 WAL with exact phase,
  per-operation state and recovery-marker binding.
- The eight journal operations were the TUN, the two IPv4 split-default
  routes, one persistent-underlay endpoint-bypass route, DNS exchange, IPv4
  firewall, IPv6 firewall and the IPv4 carrier-endpoint firewall exception.
- Apply cuts covered `Planned`, every resource family, DNS `Staged`, partial
  firewall acknowledgements, all-`Applied`/`Preparing` and `Active`.
- Recovery cuts covered both before mutation and after convergence but before
  WAL acknowledgement for each of the eight cleanup steps.

## Isolation, cleanup and Mac boundary

- The source base and disposable clone were required to be capability-isolated
  and network-isolated, with no mounts, forwarded ports or SSH-agent
  forwarding.
- Guest operations used a previously bound opaque clone ID. Name-based
  deletion required an immediate name-to-ID revalidation, followed by exact
  ID/name absence proof.
- Guest cleanup, clone absence, source-base final stop, evidence validation and
  macOS host-safety comparison were all `valid`.
- The working Mac's routes, DNS, exact live sing-box identity and PF
  configuration files were unchanged at the before/after observation points.
  Unprivileged PF runtime inspection remained permission-denied, so loaded PF
  runtime state is not claimed.

## Non-claims

This is same-boot synthetic Linux namespace recovery under process `SIGKILL`.
It does not prove a kernel reboot, torn filesystem writes, storage power loss,
production or field operation, resolver-manager integration, native
macOS/Windows lifecycle safety, or censorship resistance.
