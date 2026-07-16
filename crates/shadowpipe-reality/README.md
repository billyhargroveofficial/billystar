# shadowpipe-reality

A **from-scratch TLS 1.3 + REALITY** implementation in Rust. No `rustls`, no
`boring` — we own every byte of the handshake.

## Why from scratch

REALITY needs control that no off-the-shelf Rust TLS stack exposes:

- It sets the ClientHello `legacy_session_id` to an **auth ciphertext** that must
  be *transcript-consistent* — TLS 1.3 folds the whole ClientHello into the
  transcript hash, so a post-hoc wire splice would break the Finished MAC.
- It needs the client's X25519 `key_share` **ephemeral private key** to derive the
  auth key (ECDH with the server's static key).
- The server must be able to **forward unauthenticated peers to a cover site**
  byte-for-byte.

`boring-sys` 4.22 exposes no client session_id setter, no key_share-private
access, and no custom-extension API; `rustls` is similarly closed. So we build the
handshake ourselves.

## What works today (milestones M0–M3)

| Milestone | Status | Implementation evidence |
|---|---|---|
| **M0** Chrome-JA4 ClientHello | ✅ | `tools/ja4-gate` (`t13d1516h2_…`) |
| **M1** REALITY auth channel (session_id seal/open) | ✅ | unit test, gates on the server key |
| **M2** TLS 1.3 **client** | ✅ | **interop with `openssl s_server`** |
| **M3** TLS 1.3 **server** + REALITY accept | ✅ | blocking/Tokio client↔server plus adversarial forwarding, replay, low-order-key and deadline coverage |

Blocking and Tokio drivers are covered by unit, adversarial and end-to-end
suites. Dated pass counts and warning status must come from a recorded
`cargo test`/clippy run rather than a volatile source count. The blocking path is
kept for the standalone bins. `reality_accept_async` bounds classification and
cover setup, then returns an established `ForwardedConnection`; the production
server drives that splice outside `--outer-handshake-timeout-secs` under
`--forward-idle-timeout-secs` (default 300 s). Read or write progress in either
direction resets the shared monotonic idle deadline, so an active asymmetric
HTTP/2 transfer is not killed at 15 s. The adversarial suite checks these scoped
implementation behaviours:

- a server with the wrong HMAC (no static key) is **rejected by the client**;
- a token sealed for the wrong static key is **forwarded** (no tell-tale error);
- an unknown `short_id` is **forwarded** (ACL enforced);
- a malformed ClientHello is **forwarded, never panics**;
- a configured non-contributory server key fails client construction before I/O;
- an incoming low-order client share follows **forward-to-cover**;
- a normal prober receives the **cover site's real bytes**.

### Crypto specifics (current)

- Cipher suites: **TLS_AES_128_GCM_SHA256**,
  **TLS_CHACHA20_POLY1305_SHA256**, and **TLS_AES_256_GCM_SHA384** (client
  negotiates from ServerHello; server selects). ECDHE group: **X25519** only;
  P-256 cover mirroring remains unimplemented.
- Every outer X25519 ECDH path rejects a non-contributory/all-zero result.
  Blocking and Tokio TLS client/server roles enforce the same check.
- Auth: `key = HKDF-SHA256(ECDH, salt=random[..20], info="REALITY")`,
  `AES-256-GCM` sealed into the 32-byte session_id, AAD = ClientHello with the
  session_id zeroed (matches XTLS/REALITY).
- Server→client auth: CertificateVerify "signature" = `HMAC-SHA512(auth_key,
  leaf_pub)` over a per-connection ephemeral 32-byte leaf. TLS 1.3 encrypts the
  whole Certificate flight, so the leaf+HMAC are never on the wire in clear.

## Laboratory binaries

These binaries are protocol diagnostics, not the production daemon. In
particular, `sp-reality-server` has no inner per-device identity layer. It now
requires an explicit `--insecure-lab-echo` acknowledgement, at least one
full-width sorted unique short ID, an explicit private durable replay-store
path, and a literal loopback listener. It cannot be exposed on a public or
private non-loopback interface. Production uses `shadowpipe-server --reality`,
a root-owned short-ID file, an explicit client allowlist and the mandatory
hybrid v3 session.

```sh
# 1. Generate the server's static keypair
sp-reality-keygen
#   private = <64 hex>    # server keeps this
#   public  = <64 hex>    # clients are configured with this

# 2. Run the server: authenticate REALITY clients (echo), forward everyone else
sp-reality-server --insecure-lab-echo 127.0.0.1:8443 <private_hex> \
  www.microsoft.com:443 ./reality-replay.bin 0123456789abcdef

# 3. Connect as an authenticated REALITY client
sp-reality-client 127.0.0.1:8443 <public_hex> www.microsoft.com 0123456789abcdef "hello"
#   REALITY HANDSHAKE OK (server HMAC verified) -> REALITY ECHO OK

# (interop) drive a handshake against a reference TLS server
sp-reality-handshake <host:port>     # uses CertVerify::Skip
```

## Implementation status and remaining gaps

1. **Cover mimicry** — **partial targeted mimicry, auto-wired.**
   `crate::cover::profile_cover` measures the cover's selected cipher, total
   first-flight length and record lengths from cleartext framing. The tunnel
   server profiles once at startup, best effort (skip with
   `--no-cover-profile`), then selects a supported matching suite and shapes the
   accepted encrypted flight toward that profile. It does not profile or mirror
   ServerHello extension ordering/content, P-256 ECDHE, timing, load-balanced
   cover variants or failure distributions. This is not an indistinguishability
   claim. See `DESIGN-cover-mimicry.md`.
2. **More suites/groups** — ✅ all three Chrome cipher suites done:
   TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, and now
   **TLS_AES_256_GCM_SHA384** (the key schedule is generalized over the hash —
   `kdf::Hash`, SHA-256/SHA-384, pinned by a SHA-384 known-answer test). Remaining:
   secp256r1 **ECDHE** for cover-mirror when the cover selects P-256 (ClientHello
   already advertises secp256r1/secp384r1 in `supported_groups`; REALITY auth stays
   X25519). P-256-selected covers therefore remain outside the current mimicry
   scope.
3. **Session_id replay store** — ✅ done (`ReplayCache`, gated on the skew window):
   an exact replay of an authed ClientHello is forwarded, not re-authed. Token
   retention ends at the absolute `token_time + window`, so a future-skew token
   cannot outlive a first-seen TTL. Production opens an HMAC-authenticated,
   static-key-bound fixed-slot file before listener bind, holds an exclusive
   same-host lease, and completes the slot write plus `fdatasync` before emitting
   the accepted ServerHello flight. Restart therefore preserves committed replay
   state; a torn/corrupt store, full store, poisoned lock, or runtime I/O failure
   fails forward. The store has 16,384 slots and a fixed 64-entry expiry-work
   budget per admission, so it never performs an attacker-amplified whole-file
   scan on the hot path. This bounds state/work, not availability: a holder of a
   valid online `short_id` can force disk syncs, fill the store, and temporarily
   send legitimate admissions to cover. A local file is not cross-host shared
   state: replicas must use a strongly consistent shared design or unique
   REALITY static keys. The in-memory constructor is test-only.
4. **Async (tokio) port** — ✅ done (`tls13::asio` +
   `reality_accept_async`). Forward setup returns an established splice; the
   caller owns its separate sliding idle policy.
5. **Carrier integration** — ✅ *done.* The REALITY carrier is wired into
   `shadowpipe-client`/`shadowpipe-server` behind a runtime `--reality` flag
   (alongside `--tls`). A `RealityStream` adapter exposes the post-handshake
   application channel as `AsyncRead + AsyncWrite` (driving `RecordCrypto::seal`/
   `open` in poll-land), so the existing PQ `SecureSession` (ML-KEM + X25519 pin)
   and the tunnel run *inside* REALITY unchanged — REALITY's X25519 auth +
   forward-on-fail on the outside, post-quantum confidentiality on the inside.
   Client: `reality_connect` → stream; server: `reality_accept` → authed stream
   **or** `None` (forwarded to the cover). See `shadowpipe_core::reality`,
   `tls13::RealityStream`, and `shadowpipe-core/tests/e2e_reality.rs`. Cutover
   Production daemon startup now requires `--reality`; raw/H2/TLS/QUIC
   carriers are available only behind the explicit no-TUN lab gate.

## Module map

- `lib.rs` — `build_client_hello` / `build_authed_client_hello`, GREASE/cipher tables.
- `auth.rs` — REALITY session_id seal/open + `reality_cert_hmac`.
- `parse.rs` — bounds-checked ClientHello field extractor.
- `wire.rs` — big-endian writer with length-prefix backpatching.
- `tls13/` — `kdf` (HKDF-Expand-Label, transcript), `record` (AEAD record layer),
  `schedule` (key schedule + Finished), `client`, `server`.
- `reality.rs` — `reality_accept`: auth-gate → authed takeover **or**
  forward-on-fail splice to the cover.
