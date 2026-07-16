# Design: cover-ServerHello mimicry (task #9)

## Goal
Reduce specific measured passive mismatches between token-accepted and forwarded
cover handshakes: selected cipher and encrypted-flight size/record lengths. This
is not a claim of distributional, cryptographic, or whole-connection
indistinguishability.

## Threat model
- **Active prober without an accepted token** — `reality_accept` forwards it to
  the real cover, and integration tests verify receipt of cover bytes. This
  mitigates one direct response oracle; it does not establish equal timing,
  failure behaviour, or handshake populations.
- **Passive comparator** — *this remains the gap.* It watches connections to our IP
  (some authed = us, some forwarded = the real cover) and looks for a population
  split. Everything after ServerHello is encrypted, but selected cipher, record
  lengths, timing and failure behaviour remain visible. The current
  implementation targets the first two measured shape fields; it does not prove
  that the remaining distributions match.
- `server_random`, `session_id_echo`, and `key_share` are intended to be
  random-looking, but that intent is not a statistical indistinguishability
  result.

## Why we can't byte-copy the cover's ServerHello
To carry proxy traffic we must own the session keys, which derive from ECDHE with
**our** key_share — we do not have the cover's ephemeral private key. The
accepted path therefore synthesizes its own ServerHello and selects the profiled
cipher when supported. It currently uses a fixed `supported_versions` + X25519
`key_share` layout; ServerHello extension ordering/content is not profiled or
mirrored.

## Cover profiling
The cover's flight may be stable for one backend but can vary with certificate
rotation, load balancing and deployment changes. The current daemon dials the
cover once at startup, best effort, sends a Chrome ClientHello, and records from
the cleartext wire:
- the selected `cipher_suite`,
- the total byte size + per-record sizes of the server flight (ServerHello →
  just before it waits for us). Record lengths are cleartext, so no decryption is
  needed to measure sizes.

There is no TTL or periodic refresh in the current runtime.

## Implementation status
- **Suites — implemented:** AES-128-GCM/SHA-256, ChaCha20-Poly1305/SHA-256 and
  AES-256-GCM/SHA-384. ECDHE remains X25519-only, so a P-256-selected cover is
  outside the current mimicry scope.
- **Profiling — implemented with a startup-only scope:**
  `profile_cover(addresses, sni, limits) -> CoverProfile { cipher, flight_len,
  record_lens }` uses concrete resolved addresses plus bounded connect, I/O,
  overall-flight and record-count limits.
- **Accepted-flight shaping — partial:** the accepted path selects a supported
  profiled cipher, pads the encrypted Certificate flight toward the measured
  size, and derives a record split plan from `record_lens`. ServerHello extension
  layout, timing and failure distributions are not mirrored.

## Risks / open questions
- **Profile staleness** — current startup-only profiling does not track cover
  certificate rotation or load-balanced variants; bounded out-of-band refresh is
  future work.
- **HelloRetryRequest** from the cover (rare for X25519+Chrome) → fall back to
  forward-on-fail if profiling sees one.
- **EncryptedExtensions content** (ALPN echo etc.) is encrypted, so only its size
  is directly visible through record shape; content-dependent timing and later
  behaviour remain outside current shaping.

## Test plan
- Suites: per-suite record-layer round-trip + a full handshake negotiating each suite
  (interop vs `openssl s_server -ciphersuites <suite>`).
- Profiling: profile a local `openssl s_server`; assert measured cipher + flight
  size within the configured bounds.
- Shaping: assert the accepted flight selects the profiled supported cipher and
  targets its total/record sizes; retain the existing authenticated/HMAC tests.
- Remaining falsification: compare full ServerHello layouts, timing and
  multi-backend distributions before making any stronger mimicry claim.
