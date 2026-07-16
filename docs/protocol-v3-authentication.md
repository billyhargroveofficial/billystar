# Shadowpipe inner protocol v3: hybrid authentication and key schedule

Status: implemented research protocol, **not** TLS, Noise, an IETF protocol, a
formal security proof, an independent audit, or a production-readiness claim.
This document describes the code as of 2026-07-16 and deliberately separates
implemented properties from hypotheses.

## Security objective and threat model

The inner session must construct an application-traffic object only when all of
the following are true:

1. the server proved possession of the enrolled per-device PSK before the
   client emitted its own PSK proof, and the server verified that client proof
   before disclosing its static ML-KEM key or performing KEM work;
2. the server presented one of a small authenticated set of pinned static
   ML-KEM-768 public keys;
3. both sides contributed a non-zero X25519 shared secret and the server
   decapsulated a valid-size ML-KEM-768 ciphertext;
4. the client proved possession of both a per-device Ed25519 seed and an
   independently generated uniform 256-bit PSK enrolled on the server;
5. the server proved possession of that same PSK again in ServerFinished;
6. access proofs bind roles/domains, version/build, the inner camouflage
   framing class, kid and
   challenge/nonces/server tag; encrypted Finished proofs commit `H0`, which
   contains the access flights and hybrid-handshake fields;
7. the outer adapter's observed `raw`/`h2` framing class equals the authenticated
   inner claim. This is not an outer-transport identity: direct TCP, TLS, QUIC
   and REALITY all currently terminate to `raw`.

The PSK HMAC is a symmetric post-quantum authentication hedge, conditional on a
secret authenticated provisioning channel. Ed25519 remains classical. The
composition has not been reduced to standard assumptions in a machine-checked
or peer-reviewed proof.

Same-root compromise, process-memory compromise, malicious release binaries,
endpoint traffic analysis, global timing correlation and denial of service are
outside this handshake's protection boundary.

## Long-lived material

Each client device stores, in a create-only private credential file:

- a random 32-byte Ed25519 seed;
- its derived 32-byte public key;
- `kid = Trunc128(SHA-256("shadowpipe-client-key-id-v3\\0" || public_key))`;
- a separately sampled random 32-byte PSK.

The server's bounded allowlist contains `kid`, the public key and the PSK, but
never the Ed25519 seed. Credential, enrollment and allowlist JSON use strict
schemas with unknown-field rejection and canonical lowercase fixed-width hex.
Production Unix loaders require a regular, single-link, non-symlink file with
exact mode `0600`, root ownership, and a path below non-symlinked,
root-owned, non-group/world-writable directories. The list contains 1..256
strictly sorted unique entries.

The enrollment artifact contains the public key and PSK, so it is secret even
though it omits the signing seed. It must cross a separately authenticated and
confidential provisioning channel and be removed after a verified allowlist
commit.

## Fixed v3 wire sequence

All integer fields below are network byte order. There is no v2 negotiation or
fallback.

| Flight | Bytes | Contents |
|---|---:|---|
| client -> server | 16 | `kid[16]` |
| server -> client | 64 | `challenge[32] || server_access_mac[32]` |
| client -> server | 64 | `client_nonce[32] || client_access_mac[32]` |
| server -> client | 1186 | `u16(1184) || static_mlkem768_public` |
| client -> server | 1145 | `magic:u32 || version:u8 || client_random[16] || client_x25519[32] || u16(1088) || mlkem768_ct[1088] || camouflage:u8 || padding:u8` |
| server -> client | 56 | `server_random[16] || server_x25519[32] || session_id[8]` |
| client -> server | 129 | encrypted fixed ClientFinished: 113-byte plaintext + 16-byte AEAD tag |
| server -> client | 49 | encrypted fixed ServerFinished: 33-byte plaintext + 16-byte AEAD tag |

The ML-KEM flights carry exact `u16` lengths checked before body allocation.
Access and Finished flights have no attacker-declared length at all: their
fixed-size buffers are read exactly. Frame varints are canonical and bounded;
unknown flags and trailing header bytes fail closed.

## Mutual pre-key PSK access gate

The access gate uses role-separated HMAC-SHA256 messages. Let `V` be the one-byte
protocol version, `B` the four-byte build magic, `C` the one-byte carrier mode,
`I` the 16-byte `kid`, `R_s` a fresh 32-byte server challenge, and `R_c` a fresh
32-byte client nonce:

```text
S = HMAC-SHA256(
  psk,
  "shadowpipe-v3/server-access-proof\0" || V || B || C || I || R_s
)

C_p = HMAC-SHA256(
  psk,
  "shadowpipe-v3/client-access-proof\0" || V || B || C || I || R_s || S || R_c
)
```

The client verifies `S` before sampling `R_c` or writing any client-proof byte.
The server verifies `C_p` before serializing the static ML-KEM public key and
before decapsulation or any other KEM operation. Binding the exact server tag in
`C_p` prevents a fake endpoint from turning the client into a chosen-challenge
PSK-MAC oracle. A captured client proof fails against a fresh server challenge.

For every `kid`, the server first samples a fresh secret dummy PSK, scans the
entire bounded allowlist, and uses constant-time byte selection to replace the
dummy only on a match. It then computes the same fixed 64-byte server flight and
performs the same client-HMAC verification path. For an unknown `kid`, the dummy
is neither fixed nor public, so the response is not a zero-key membership
oracle. Failure is the same typed `AuthFailed`, and zero ML-KEM bytes follow it.
This removes an obvious RNG/binary-search timing branch; it is not a claim of
whole-program constant-time behavior.

The 16-byte pseudonymous `kid` is necessarily visible to a peer that has already
reached this inner gate. Production daemon startup therefore requires REALITY
plus a 1..16-entry ACL of full-width 64-bit online `short_id` tokens. The ACL is
read from `--reality-short-id-file` (default
`/etc/shadowpipe/reality-short-ids`) before identity/allowlist loading or bind;
the root-owned `0600`, single-link, no-follow file contains strictly sorted
unique 16-lowercase-hex lines. A `short_id` is carrier admission, **not** client
identity; the inner mutual PSK and Finished proofs remain mandatory. Ordinary
daemon startup never prints a URI containing the token. Only explicit
`--print-uri` does so.

Before production bind, the server also opens
`--reality-replay-store` (default
`/var/lib/shadowpipe/reality-replay-v1.bin`) under an exclusive same-host
lease. The fixed file has a `96 B` header and 16,384 slots of `96 B`, exactly
`1,572,960 B`. It is HMAC-authenticated from the REALITY static secret and
stores keyed session-ID digests with absolute
`valid_until = token_time + skew_window`. A fresh slot write and `fdatasync`
complete before the accepted ServerHello flight. Restart therefore rejects a
committed replay; torn/corrupt/full/I/O state fails forward. Static-key/store
binding mismatch aborts startup. This is not a cross-host replica guarantee:
replicas sharing one static key need a linearizable reserve-before-flight
operation equivalent to `SETNX + TTL`; eventual consistency is insufficient.
Loss/recreation of the file with the same static key is a cold-start memory
loss. Until shared linearizable admission exists, each replica must use a
unique REALITY static key and local durable store.

On the production client, that URI is consumed through `--uri-file`, not argv.
The client opens the final component with `O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`,
requires trusted real non-group/world-writable ancestors plus a regular
single-link exact-`0600` file, bounds it to 64 KiB, and for
tunnel/production additionally requires effective UID 0 plus root:root
ownership. It reads and parses the whole URI pool before credential access,
host-state coordination, DNS, sockets, or TUN creation, without logging its
contents. Explicit no-TUN `--development-user-credential` may instead use an
exact effective-UID:GID file on Unix; non-Unix `--uri-file` fails closed. Manual
URI and individual-flag paths require one canonical full-width `sid` (exactly
16 lowercase hex characters) and cannot be mixed with each other or signed
policy authority. The URI query is closed and unique (`sni`, `sid`, `fp` only),
and a non-contributory low-order REALITY X25519 public key is rejected during
the same preflight. The legacy `--uri` diagnostic form necessarily exposes the
online carrier selector in process argv.

REALITY outer authentication and genuine-service forward-on-fail cover the
inner bootstrap. Raw/H2/TLS/QUIC answer active probes with a distinguishable
ShadowPipe bootstrap/challenge and are accepted only behind the explicit
`--allow-insecure-lab-carriers --development-user-allowlist` no-TUN gate.

Deterministic access-MAC vector (`B=0x01020304`, `V=3`, `C=h2`, PSK=`11` repeated
32 bytes, `kid=00..0f`, `R_s=20..3f`, `R_c=40..5f`):

```text
S   = 7be4628e91caad7b2c30d03a689da81218230129a3018eda91ce7db66b204f63
C_p = 77a2cfbc5798f50e0ff4b064d542a81f17b41947c9bff7c8ee513c206aeb5886
```

## Canonical transcript

`H0 = SHA-256(domain || field(1)..field(19))`, where each field is encoded as
`tag:u8 || length:u32 || value`. Unique tags and fixed-width lengths make the
encoding prefix-free for this schema. The committed values are:

1. protocol version;
2. literal client role;
3. literal server role;
4. build magic;
5. the complete suite identifier
   `ML-KEM-768+X25519+MUTUAL-PSK-ACCESS-HMAC-SHA256+Ed25519+HMAC-SHA256+HKDF-SHA256+ChaCha20Poly1305`;
6. the exact static server ML-KEM public key sent on the wire;
7. the exact ML-KEM ciphertext;
8. client random;
9. server random;
10. client X25519 share;
11. server X25519 share;
12. session id;
13. the ClientHello magic again;
14. the ClientHello version again;
15. claimed inner camouflage framing class (`raw` or `h2`), not a unique outer
    transport identifier;
16. padding profile;
17. the exact 16-byte client access hello (`kid`);
18. the exact 64-byte server access proof;
19. the exact 64-byte client access proof.

The duplication of version/build fields is intentional belt-and-suspenders
binding, not extra entropy.

The deterministic H0 vector in the implementation uses explicit build magic
`0x01020304`, server key `aa` repeated 1184 bytes, access flights `b0` repeated
16, `c1` repeated 64 and `d2` repeated 64 bytes, plus the fixed hello values in
the test. Its expected digest is:

```text
7f884dcae0c7afe0dd214dd6e028de55b5faef55e514e50cf940fea3759252b3
```

Production/release client and server artifacts must be compiled with the same
explicit `SHADOWPIPE_MAGIC`; release builds fail closed when it is absent. The
random default remains only for debug/test builds and is not an interoperability
contract.

## Hybrid key schedule and Finished proofs

Let `X` be the checked X25519 shared secret and `K` the ML-KEM-768 shared
secret. X25519 outputs are OR-reduced and the all-zero result is rejected on
both roles, following RFC 7748's contributory-behaviour check. Fixed component
lengths and domain labels make the concatenations unambiguous.

Handshake traffic keys are:

```text
PRK_h = HKDF-Extract(
  salt = H0,
  IKM  = "shadowpipe-v3/ikm\\0" || X || K || client_random || server_random
)
(c_h, s_h) = HKDF-Expand(
  PRK_h,
  "shadowpipe-v3/handshake-traffic-keys\\0",
  64
)
```

ClientFinished plaintext is fixed-width:

```text
format=1 || kid[16] ||
Ed25519.Sign(seed, "shadowpipe-v3/client-finished-proof\\0" || 1 || kid || H0) ||
HMAC-SHA256(psk, "shadowpipe-v3/client-finished-proof\\0" || 1 || kid || H0)
```

It is encrypted with the client-to-server handshake key, nonce zero, and AAD
`"shadowpipe-v3/client-finished-record\\0" || H0`. The server always performs
both Ed25519 and HMAC verification and requires the Finished `kid` to equal the
identity admitted by the pre-key gate. An unknown `kid` uses a valid RFC 8032
dummy public key plus a dummy HMAC key, returns the same typed `AuthFailed`, and
never creates a session. This narrows an avoidable invalid-point timing branch;
it is **not** a claim of end-to-end constant-time authentication.

ServerFinished plaintext is:

```text
format=1 || HMAC-SHA256(
  psk,
  "shadowpipe-v3/server-finished-proof\\0" || 1 || kid || H0 || ClientFinished
)
```

It is encrypted with the server-to-client handshake key, nonce zero, and a
role-specific AAD label. Independent directional keys and labels prevent a
ClientFinished ciphertext from being reflected as ServerFinished.

After both proofs verify:

```text
H1 = SHA-256(
  "shadowpipe-v3/finished-transcript\\0" || H0 ||
  u16(len(ClientFinished)) || ClientFinished ||
  u16(len(ServerFinished)) || ServerFinished
)

PRK_a = HKDF-Extract(
  salt = H1,
  IKM  = "shadowpipe-v3/ikm\\0" || X || K || psk ||
         client_random || server_random
)
(c_a, s_a) = HKDF-Expand(
  PRK_a,
  "shadowpipe-v3/application-traffic-keys\\0",
  64
)
```

Handshake and application AEAD keys are label-separated and instantiated as
different ChaCha20-Poly1305 objects, so their nonce-zero records do not reuse a
key/nonce pair. Application nonces are `0^32 || counter:u64`; send and receive
counters are independent and overflow is terminal. Application-record AAD is:

```text
"shadowpipe-v3/application-frame\0" ||
stream_id:u32 || flags:u8 || ciphertext_len:u64 ||
padding_len:u32 || padding_bytes
```

Padding stays outside the ciphertext for traffic shaping but not outside
integrity. Changing FIN/PING/PADDING, stream id, ciphertext boundary, padding
length, or any padding byte invalidates the tag. Any authentication failure
permanently poisons that receive direction; nonce exhaustion or an encryption
failure permanently poisons the send direction, so a caller cannot ignore an
error and continue under reused or desynchronized record state.

## Pin and credential rotation

Server identity rotation accepts a bounded set of 1..3 unique authenticated
ML-KEM fingerprints. In signed endpoint-policy v2, the exact sorted
`service_id` set established at genesis is immutable: service add/remove/rename
requires a new authenticated enrollment or schema. Candidate policies must be
signed by an `Active` online key; `Retiring` and `Revoked` keys verify only
historical accepted state. A safe release adds the new key/pin before switching
the server and requires policy/keyset plus overlapping material to remain usable
for the complete `86400 s` interval. `Active -> Retiring` has the same
full-overlap lifetime requirement; removal/revocation follows only after the
interval elapses. Already revoked online keys may be omitted in a later
contiguous keyset. There is no downgrade to an unpinned or v2 handshake.

This overlap is continuity, not compromised-signer containment. An attacker
holding an `Active` online policy key can sign a successor that adds an attacker
pin alongside the old pin while satisfying every overlap rule. A separately
root/threshold-authorized service registry, transparency/witnessing and recovery
procedure are Phase-4 `E0` research, not properties of protocol v3.

Orderly policy expiry is checkpointed separately in the 132-byte
`SPPOLEX1` `<policy-state>.expired-v1` tombstone. It prevents the exact expired
hash from being reactivated after wall-clock rollback once the same-storage
checkpoint is durable, but it is not trusted time: storage rollback can revert
policy state and tombstone together, and crash/power loss before checkpoint
remains a residual.

Client rotation is explicit:

1. create a new device credential and secret enrollment artifact on the client;
2. enroll it under the server's nonblocking sibling mutation lease;
3. strictly validate the non-empty allowlist and restart/reload the daemon;
4. move the client to the new credential and verify connectivity;
5. revoke the old `kid`, refusing removal of the last client;
6. validate and restart/reload again.

The current daemon takes an immutable startup snapshot of the allowlist, so a
management-file change is not active until daemon restart. Hot reload is not
implemented.

## Negative evidence implemented in tests

`crates/shadowpipe-core/tests/e2e_auth.rs` covers:

- valid mutual hybrid authentication;
- replayed client access proof against a fresh challenge with zero ML-KEM bytes;
- tampered fresh access proof and unknown `kid` with zero ML-KEM bytes;
- fake server without the PSK receiving zero client-proof bytes;
- wrong pin before ClientFinished;
- unknown/revoked clients with generic typed failure;
- bounded overlap pin rotation;
- explicit v2 rejection;
- captured ClientFinished replay against a fresh ServerHello;
- encrypted Finished bit flip;
- transcript mutation;
- truncated fixed Finished;
- cross-role Finished reflection;
- low-order/all-zero X25519 shares in both directions.

Unit tests additionally pin deterministic known-answer vectors for both access
HMACs and H0, exact access-flight widths, authenticated framing-class binding
(`raw` versus `h2`), access/Finished identity splice rejection, authenticated
padding, terminal AEAD poisoning, and the fixed known/unknown access-gate shape.

Reproducible local commands:

```bash
cargo test -p shadowpipe-core --test e2e_auth --no-default-features --locked
cargo test -p shadowpipe-core --all-features --locked
cargo test -p shadowpipe-client --all-features --locked
cargo test -p shadowpipe-server --all-features --locked
```

These tests establish implementation behaviour on the tested artifacts. They
do not establish computational security, side-channel resistance, censorship
resistance, or field performance.

Native Windows 11 ARM64 H2 no-TUN run
[`20260716T125113Z-36840-dd0c2571`](../tests/windows/results/20260716T125113Z-36840-dd0c2571/RESULT.md)
sealed 891/891 checksum entries: missing pin opened zero TCP connections,
unenrolled credentials received no echo, and the enrolled session returned an
exact nonce plus 1,048,576 echoed bytes. The warning-free 5,072,384-byte PE
SHA-256 was
`2734e79f98866910aa8e0386af4ff630191b0a72fd1945177f078cb69d500bad`.
This is private-socket portability evidence, not Windows TUN, censorship,
cryptographic-proof or production evidence.

## Residual security boundaries

- The static ML-KEM server key does not provide post-quantum forward secrecy
  after later compromise of that key plus a future break of recorded X25519.
- The protocol has no formal model, symbolic proof, proof of its hybrid
  combiner, independent audit, interoperability programme, or stable standards
  registry.
- Ed25519 signatures, including signed endpoint-policy control-plane
  signatures, are classical. ML-DSA/composite signatures are future work, not
  an implemented claim.
- PSK security depends on uniform independent generation and confidential
  enrollment. Reusing, logging or exposing the enrollment artifact destroys
  the symmetric authentication hedge.
- The server still accepts an outer connection and performs bounded fixed-width
  parsing, fresh RNG, a full bounded allowlist scan and HMAC work before client
  authorization. The pre-key gate withholds stable ML-KEM bytes and KEM work
  from unauthenticated peers; an authorized malicious client can still reach KEM
  work. Global admission semaphores and deadlines bound work, but there is no
  per-IP cookie, silence-under-load guarantee, or complete CPU/connection-state
  DoS defense.
- WireGuard authenticates its first initiator flight and can use cookie replies
  under load. Shadowpipe deliberately sends a fixed cheap server PSK proof first
  so a fake server cannot elicit a client PSK proof; the tradeoff is that an
  unknown `kid` receives one distinguishable fixed-width response after reaching
  the inner carrier. REALITY is therefore mandatory outer probe cover.
- The 64-bit REALITY `short_id` is an online carrier token, not device identity
  or a substitute for the 128-bit pseudonymous inner `kid`. Compromise permits
  producing fresh carrier-valid ClientHellos and reaching the cheap inner
  challenge. At sufficient rate, a holder can force per-admission disk syncs
  and fill the bounded 16,384-slot replay store, causing subsequent valid
  carrier admissions to fail forward until entries expire and bounded pruning
  catches up. The design bounds state and per-admission expiry work
  (64 removals), not carrier availability. The durable guarantee is same-host;
  cold-start state loss with the same key forgets live admissions, while sharing
  a REALITY static key across replicas without a linearizable
  reserve-before-flight primitive reopens cross-replica replay. An inner session
  still requires the device PSK and Ed25519 key.
- Endpoint IPs, ports, carrier choice, packet sizes and timing remain visible to
  an on-path observer unless an outer carrier hides a particular field.
- The authenticated camouflage field prevents `raw`/`h2` framing translation or
  stripping. It does **not** prevent replay across outer transports that share
  `raw`; transport identity would require a separately designed channel binding.
  Production mitigates the current exposure operationally by admitting only
  REALITY, while direct TCP/TLS/QUIC remain explicit no-TUN lab paths.
- Windows production credential/allowlist ACL verification is not implemented.
  Windows is restricted to explicit no-TUN development mode.
- Linux host-state ownership is outside the inner cryptographic protocol.
  Explicit named client and server TUN creation use `IFF_TUN_EXCL`; unnamed
  client creation uses kernel name allocation. This prevents attachment to an
  existing named TUN but is not a cryptographic or cross-OS property.

## Standards and design references

- [RFC 7748: Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748)
- [RFC 8032: Edwards-Curve Digital Signature Algorithm](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- [WireGuard Protocol and Cryptography](https://www.wireguard.com/protocol/)
- [Hybrid ECDHE-MLKEM Key Agreement for TLS 1.3, Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
- [Potential Risks of Standalone ML-KEM in TLS 1.3, June 2026 Internet-Draft](https://datatracker.ietf.org/doc/draft-usama-tls-risks-of-mlkem/)
- Fenske and Johnson, [Bytes to Schlep? Use a FEP](https://arxiv.org/abs/2405.13310)
- Fifield, [Comments on certain past cryptographic flaws affecting fully encrypted censorship circumvention protocols](https://eprint.iacr.org/2023/1362.pdf)
- Günther, Stebila and Veitch, [Obfuscated Key Exchange](https://eprint.iacr.org/2024/1086.pdf)

The references inform domain separation, transcript/Finished staging, hybrid
component handling and terminology. FEP and OKE work additionally define
random-looking/error/probing properties that the current REALITY + custom v3
composition has not instantiated or proved. The June 2026 risk draft is
especially relevant to the unresolved need for integration-level symbolic and
computational analysis; it is an Internet-Draft under discussion, not proof of
this protocol. Shadowpipe v3 does not claim conformance to TLS, Noise, the TLS
hybrid draft, OKE/FEP constructions or a NIST protocol profile.
