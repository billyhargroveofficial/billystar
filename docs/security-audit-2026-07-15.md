# Dependency and key-storage security audit — 2026-07-15

Status: **superseded** by the
[2026-07-16 scoped security and privileged-validation audit](security-audit-2026-07-16.md).
This file remains historical engineering evidence for the 2026-07-15 tree, not
a current-tree Phase-3 audit and not an independent protocol or cryptographic
review. No deployment, route, DNS, TUN, PF or live-VPN change was part of this
audit.

> **2026-07-16 status note:** the exact test counts below are a frozen
> 2026-07-15 snapshot. Current-source Phase-3 privileged evidence is recorded in
> the [superseding audit](security-audit-2026-07-16.md) and
> [Phase-3 production safety](phase3-production-safety.md). Do not combine the
> historical counts below with current-tree claims.

## Initial RustSec findings

`cargo-audit 0.22.2` scanned the locked workspace against a 1,160-advisory
RustSec snapshot and found one vulnerability plus four informational warnings:

| Dependency | Finding | Resolution |
|---|---|---|
| `quinn-proto 0.11.14` | [RUSTSEC-2026-0185](https://rustsec.org/advisories/RUSTSEC-2026-0185): high-severity remote memory exhaustion from unbounded out-of-order stream reassembly | Locked to `0.11.15`, the first patched release |
| `anyhow 1.0.102` | [RUSTSEC-2026-0190](https://rustsec.org/advisories/RUSTSEC-2026-0190): `Error::downcast_mut` soundness violation | Workspace lower bound and lock moved to `1.0.103` |
| `pqcrypto-mlkem`, `pqcrypto-internals`, `pqcrypto-traits` | [RUSTSEC-2026-0164](https://rustsec.org/advisories/RUSTSEC-2026-0164): the PQClean-backed ecosystem is unmaintained | Removed and replaced with exact `ml-kem 0.3.2` from the actively maintained [RustCrypto KEMs](https://github.com/RustCrypto/KEMs) project |

## ML-KEM migration invariants

- FIPS 203 ML-KEM-768 wire sizes remain 1,184-byte public key, 1,088-byte
  ciphertext and 32-byte shared secret.
- New server identities store the preferred 64-byte seed.
- A checked-in vector produced by the removed backend proves that a legacy
  2,400-byte expanded secret, public key and ciphertext decode to the same
  shared secret and stable server fingerprint under RustCrypto.
- Expanded keys are structurally validated and then run a deterministic
  encapsulate/decapsulate pairwise self-test. This additionally rejects a
  corrupted private-PKE component even when the embedded public key and its
  hash remain valid. Malformed encodings, unknown key-file fields and
  stored-public/derived-public mismatch fail closed.
- Secret seed, expanded encoding, decoded secret hex and serialized JSON
  buffers use zeroizing wrappers. KEM shared values return in zeroizing guards,
  key derivation borrows them without an extra array copy, HKDF seed/output are
  guarded, and session traffic keys zeroize on drop. This limits ordinary
  userspace copies; it is not a claim about swap, crash dumps, compiler-elided
  copies, library-internal cipher/HKDF state or hostile-kernel memory
  acquisition.

## Long-term key publication

Both the hybrid-session ML-KEM identity and REALITY X25519 identity now use the
same private-file rules:

1. create a random same-directory temporary pathname with `create_new`;
2. set mode `0600` before writing secret bytes;
3. write and `sync_all` the complete file;
4. explicit rotation atomically renames the complete temp over the destination;
5. first-run generation hard-links without clobbering, so concurrent processes
   load one winning identity instead of returning split identities;
6. sync the parent directory on Unix and remove losing/interrupted temps;
7. never open a final symlink for writing; replacement changes the directory
   entry rather than its target.

On load, Unix opens with `O_NOFOLLOW|O_NONBLOCK`, accepts only a regular file
owned by the effective UID with no group/other permission bits, and caps the
read at 16 KiB. The shared loader protects both ML-KEM JSON and the REALITY
X25519 secret. Tests cover concurrent first-run convergence, atomic replacement,
symlink non-following, owner/mode/type rejection, mismatched keys, malformed and
private-component-corrupted legacy keys, and cross-backend decapsulation.

Windows has no explicit private-key DACL hardening or directory-fsync barrier
in this implementation, and hard-link/replace behavior remains
filesystem-dependent; that is a production blocker, not silently treated as
Unix-equivalent durability.

## Final verification

- `cargo audit --file Cargo.lock --no-fetch`: **0 vulnerabilities, 0 warnings**
  across 274 locked crate dependencies in the recorded advisory snapshot;
- `cargo test --workspace --all-features --locked`: **288 passed, 2 ignored**;
- OrbStack ARM64 `cargo test --workspace --no-default-features --locked`:
  **260 passed, 2 ignored**;
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`:
  clean;
- `cargo fmt --all -- --check` and `git diff --check`: clean.
- fixed-magic cross-builds succeeded for Windows ARM64 no-default client and
  static x86-64 musl client/server; the build contract was also exercised with
  two successive env values and a malformed value that failed closed;
- all current `shadowpipe-client` modes require a valid server fingerprint
  before trace reservation, DNS, socket or TUN; the core client config is
  non-optional and mismatch fails before encapsulation/application bytes;
- `--auto-route` configuration is Linux-only and fail closed unless
  `--tunnel --kill-switch --dns` are present;
- subsequent local sealed run `20260715T205821Z-47847`
  closed the synthetic Linux IPv4 privileged OS-TUN cell with valid test,
  cleanup and host-safety status: ICMP 20/20 with 43.307 ms average RTT, TCP
  receiver 1,857,028,096 bytes (~1.4850366 Gbit/s), UDP receiver 6,251,748 bytes
  (~4.9797836 Mbit/s, 0% loss), and matching 64 MiB SHA-256
  `ca6d5d64f26e5993dfaafdb1eb026e4714eadd1a61c12dd721e88565a691a44c`;
- the strict non-carrier-only IPv4 underlay BPF and missing-pin capture each
  recorded `0 captured / 0 received by filter / 0 kernel drops`, while the
  separate bounded allowed-carrier marker capture recorded `17/17/0`; the
  marker payload was delivered and its plaintext bytes were absent from that
  pcap, which is an encapsulation regression heuristic, not cryptographic proof;
- the selective sink capture recorded 5115 captured, 5123 received by filter
  and 0 kernel drops; tunneled DNS returned `198.18.0.2`, reset/recovery
  completed in at most 7 s, and all 86/86 manifest entries passed
  `sha256sum -c`;
- stable Mac IPv4/IPv6/default-route, DNS, static PF and sing-box snapshots
  matched before and after that run; raw neighbor-cache snapshots were retained
  but excluded from the stable comparison. Loaded runtime PF rules were not
  inspected without host privilege and are not part of the claim;
- the final Windows client completed a pinned 1-MiB no-TUN measurement against
  the OrbStack server. The operator-specific raw cross-VM artifact remains
  private; its bounded conclusion is superseded by the public current-source
  Windows evidence in the 2026-07-16 audit.

## What this does not prove

RustSec checks known dependency advisories, not unknown vulnerabilities,
side-channel resistance, protocol composition or operational key custody. The
custom hybrid ML-KEM + X25519 transcript/key schedule still requires an
independent cryptographic review and test vectors before production. A clean
audit does not promote the carrier selector beyond shadow mode and does not
upgrade any VM result to field evidence.

The most important remaining implementation blockers are explicit:

- independently enrolled root + online-key endpoint-policy v2 now implements
  authenticated pin distribution, expiry, overlap rotation and persistent
  anti-rollback. Fleet enrollment, root disaster recovery and independent
  cryptographic review remain open;
- Linux auto-route has one older privileged disposable-VM synthetic IPv4 proof
  for TCP/UDP/ICMP/DNS, underlay leak capture, carrier failure/recovery and
  cleanup. Phase 3 now implements signed-authority-bounded DNS refresh and
  all-resource WAL recovery, but the fresh integrated privileged matrix is not
  yet sealed PASS. Neither result establishes IPv6, production/field behavior or
  censor resistance; Windows Wintun and macOS TUN/route behavior require
  separate native validation;
- explicit key rotation and readers have no interprocess read/write lock, so a
  reader may return the old complete inode while the pathname already names the
  new identity;
- rename/hard-link publication can have happened before a later temp cleanup or
  directory-sync error is returned, so callers must reconcile by rereading;
- Unix validation does not reject symlinked ancestor directories or multiple
  hard links; Windows ACL/durability behavior needs native implementation and
  tests;
- zeroization is best effort: X25519/import and library-internal state, page
  cache, swap, core dumps and `mlock` policy remain outside the proof.
