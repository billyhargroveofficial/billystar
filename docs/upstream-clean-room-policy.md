# Upstream clean-room and architecture policy

Status: required for all sing-box, sing-tun, Xray-core, Wintun and other
reference-implementation work.

## Architecture boundary

Shadowpipe remains an independent packet VPN architecture:

- protocol v3 and its ML-KEM/X25519/Ed25519/PSK authentication;
- signed endpoint and pin policy;
- REALITY admission and durable replay state;
- end-to-end IP packet tunnel;
- causal carrier plane;
- transactional host-state WAL, ownership proof and recovery.

Upstreams are used to discover operating-system requirements, failure modes,
test cases and public API behavior. They do not replace the Shadowpipe protocol,
policy, packet data plane or recovery model.

## Pinned audit inputs

The 2026-07-16 comparison used:

- sing-box `c8ee3497b25027f5f73bd88aba96ecf5009c37e0`;
- Xray-core `50231eaff98ccc31b5cbd247a721c16e97fe5ec1`;
- sing-box Apple client `794eb1741f91765a91f1513e5639296503f072b2`;
- sing-box Android client `aa686b2f1ac4ca9e888d4d068ce79ee1abd309fc`;
- sing-box Desktop client `cebee0d527c4e5d5500f971553628e0dfa8bae0f`;
- sing-tun `79ea1ac88855ae1e66c96dc162555161708efcd3`.

Reference checkouts live outside this repository and must never be staged or
bundled into a Shadowpipe release.

## License boundary

- sing-box and sing-tun are GPL-3.0-or-later. Their source must not be copied,
  translated, linked or vendored into the current non-GPL Shadowpipe tree.
- Xray-core is MPL-2.0. Copying or modifying covered files creates file-level
  source and notice obligations. Shadowpipe does not use Xray files as an
  implementation base.
- Wintun prebuilt binaries have a separate distribution license. A Windows
  release that distributes Wintun must retain its license and use only the
  official API.
- Shadowpipe currently declares `UNLICENSED`. No contribution or redistribution
  permission should be inferred until the project owner selects and publishes
  an explicit license and contribution policy.

## Allowed workflow

1. Record the upstream revision and the OS behavior being studied.
2. Write a requirement or black-box test in Shadowpipe terms.
3. Implement the behavior from OS documentation and public APIs without copying
   upstream code, comments, constants, layout or documentation prose.
4. Preserve stronger Shadowpipe invariants even when an upstream is weaker:
   exclusive TUN ownership, signed policy, WAL-before-mutation, exact rollback,
   fail-closed socket binding and no direct fallback.
5. Run license, secret, privacy and source-similarity review before commit.
6. Keep upstream paths, raw packet captures, credentials and operator-specific
   evidence out of Git.

## Platform direction

- Linux: native netlink/nftables/systemd-resolved adapters behind the existing
  transactional host-state controller.
- macOS: `NEPacketTunnelProvider` owns system integration and passes packet flow
  to the Rust core. Standalone `utun` remains lab-only.
- Windows: Wintun/IP Helper/WFP plus a minimal privileged Windows Service, with
  adapter and firewall state recorded in the Shadowpipe WAL.

IPv6 payload support may be deferred, but IPv6 leak prevention may not. The
Production Alpha default is `block`: permit loopback and explicitly deny
non-tunneled IPv6 until an authenticated IPv6 data plane is available.

## Explicit anti-patterns

Do not import:

- sing-box Unix daemon IPC with a world-writable socket and no peer credential
  authentication;
- non-transactional route flush-and-replace;
- fail-open physical-interface binding;
- in-memory-only replay protection;
- Linux TUN creation without exclusive ownership;
- unauthenticated remote configuration, metrics, pprof or admin endpoints;
- graceful `Close()` as the only crash-recovery mechanism.
