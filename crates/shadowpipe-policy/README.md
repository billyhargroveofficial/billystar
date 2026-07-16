# Shadowpipe policy signer

`shadowpipe-policy` is the custody-separated command-line tool for the strict
endpoint-policy v2 profile (with a keyset v1) implemented by `shadowpipe-core`.
It deliberately does not provide a command that can open both the offline root
seed and an online policy seed.

The artifact chain is:

```text
offline root seed -> root-signed keyset ----+
                                              +-> verified bundle
online policy seed + verified keyset -> policy+
```

All private keys are raw 32-byte Ed25519 seeds stored in files. Seed contents
are never accepted on the command line and are never written to stdout or log
messages. Key-generation and signing commands are silent on success. Only
`assemble` and `verify` print a public verification summary.

## Custody model

- Run `root-keygen` and `sign-keyset` on the offline root machine.
- Copy only the public root identity and the signed keyset out of offline
  custody.
- Run `online-keygen` and `sign-policy` on the online signer. Policy signing
  verifies the root-signed keyset against the explicit public root identity and
  binds the policy to its exact canonical payload hash and epoch.
- Run `assemble` on a machine with public artifacts only. Enrollment and
  successor release are explicit modes; successor mode requires the exact
  previous accepted bundle and calls the same transition rules as the client.

Seed input is accepted only when it is a regular file owned by the effective
UID, has exactly one hard link, mode `0600`, and length exactly 32 bytes.
Symlinks are not followed. New seeds and artifacts use create-new/no-clobber
semantics, mode `0600`, file `fsync`, and parent-directory `fsync`. Creation,
publication, rollback cleanup, and directory `fsync` stay anchored to one
validated directory file descriptor. Parent directories must be owned by the
effective UID and not group/world writable.

## Build

```sh
cargo build --release -p shadowpipe-policy
BIN=target/release/shadowpipe-policy
```

Use separate private directories on the relevant custody machines:

```sh
install -d -m 700 offline online public
```

## 1. Generate identities

On the offline root machine:

```sh
$BIN root-keygen \
  --seed-out offline/root.seed \
  --identity-out public/root.identity.json
```

On the online signer:

```sh
$BIN online-keygen \
  --seed-out online/policy.seed \
  --identity-out public/online.identity.json
```

The optional `--kid` argument accepts exactly 16 bytes encoded as 32 lower-case
hexadecimal characters. With no argument, the tool generates it from the OS
CSPRNG.

## 2. Sign a keyset offline

Create `keyset.json` using this strict schema. Unknown fields, non-canonical
hexadecimal strings, invalid time windows, duplicate or unsorted keys, and
invalid rotation state are rejected by the core verifier.

The numeric timestamps below are schema examples, not deployable defaults;
generate windows around the actual signing time.

```json
{
  "schema_version": 1,
  "keyset_epoch": 0,
  "issued_at": 2000000000,
  "not_before": 1999999940,
  "expires_at": 2005184000,
  "previous_payload_hash": null,
  "keys": [
    {
      "kid": "20202020202020202020202020202020",
      "ed25519_public_key": "<64 lower-case hex characters>",
      "not_before": 1999999940,
      "expires_at": 2005184000,
      "status": "active",
      "status_since": 1999999940
    }
  ]
}
```

Sign it in offline custody:

```sh
$BIN sign-keyset \
  --mode enrollment \
  --root-seed offline/root.seed \
  --root-identity public/root.identity.json \
  --spec keyset.json \
  --out public/keyset.cose
```

The command always uses the current system clock. It derives the public key from
the seed, matches it to the explicit root identity, requires enrollment epoch
`0` with no predecessor hash, signs deterministic CBOR in the fixed COSE
profile, and self-verifies the resulting artifact.

## 3. Sign an endpoint policy online

Create `policy.json`. The signer intentionally does not accept a caller-supplied
keyset epoch, keyset hash, transport, or routing rule: it copies the exact epoch
and domain-separated hash from the verified keyset and emits the sole supported
`REALITY/TCP` plus `PROTECTED_ONLY` profile.

Endpoint-policy schema 2 deliberately separates `locator_name` from `sni`.
`locator_name` is the canonical lower-case DNS name that the live scheduler
resolves to refresh the signed IPv4 authority; `sni` is the independent
canonical lower-case name authenticated by the REALITY handshake. They may be
equal, but neither field defaults to the other and both are mandatory. This
prevents a cover SNI from silently becoming DNS routing authority. Policy v1 is
rejected; there is no compatibility fallback. The keyset JSON and keyset wire
schema remain version 1.

Migration from an accepted policy v1 is therefore an explicit trust-anchor
distribution and enrollment event, not a successor release: a v1 bundle cannot
be supplied as `--previous-bundle` to authorize v2. Operators must publish v2
only after the client binary and independently authenticated enrollment state
have been rolled out.

```json
{
  "schema_version": 2,
  "policy_epoch": 0,
  "sequence": 0,
  "issued_at": 2000000000,
  "not_before": 1999999940,
  "expires_at": 2000518400,
  "previous_payload_hash": null,
  "services": [
    {
      "service_id": "30303030303030303030303030303030",
      "pins": [
        {
          "fingerprint": "<64 lower-case hex characters>",
          "not_before": 1999999940,
          "expires_at": 2005184000,
          "status": "active",
          "status_since": 1999999940
        }
      ],
      "endpoints": [
        {
          "endpoint_id": "40404040404040404040404040404040",
          "ipv4": "203.0.113.10",
          "port": 443,
          "locator_name": "edge.shadowpipe.example",
          "sni": "cdn.example.com",
          "reality_x25519_public_key": "<64 lower-case hex characters>",
          "reality_short_id": "7070707070707070"
        }
      ]
    }
  ],
  "experiment_evidence": []
}
```

Sign it in online custody:

```sh
$BIN sign-policy \
  --mode enrollment \
  --online-seed online/policy.seed \
  --online-identity public/online.identity.json \
  --root-identity public/root.identity.json \
  --keyset public/keyset.cose \
  --spec policy.json \
  --out public/policy.cose
```

The command rejects a key whose `kid`, public key, status, or validity does not
match the verified keyset. Before publishing, it assembles and verifies the
complete candidate bundle in memory and applies the core one-time enrollment
transition rules.

The fixed protected COSE content types are
`application/shadowpipe-keyset+cbor;v=1` and
`application/shadowpipe-endpoint-policy+cbor;v=2`. The policy payload carries
schema version 2 and uses deterministic CBOR; the enclosing public bundle
format remains version 1 because its two-artifact envelope did not
change. A v1 endpoint-policy content type or payload schema is rejected with an
explicit unsupported-schema error before any publication.

## 4. Assemble and verify public artifacts

```sh
$BIN assemble \
  --mode enrollment \
  --root-identity public/root.identity.json \
  --keyset public/keyset.cose \
  --policy public/policy.cose \
  --out public/bundle.cbor

$BIN verify \
  --root-identity public/root.identity.json \
  --bundle public/bundle.cbor
```

Both operations require an explicit root trust document. `assemble` verifies
signatures, canonical encodings, validity windows, exact keyset binding, key
authorization, and all schema semantics before atomically publishing a new
bundle. `assemble` and `verify` always use the current system clock; they do not
offer a backdating override that could make an expired artifact appear live.
Existing files and symlinks are never replaced.

## 5. Successor releases and rotation

Successor mode never discovers state from the filesystem or network. Every
private signing step and final assembly must receive the same explicit,
currently live, previously accepted bundle:

```sh
PREVIOUS=public/bundle.cbor
$BIN verify \
  --root-identity public/root.identity.json \
  --bundle "$PREVIOUS"
```

The public verification summary includes `keyset_payload_hash` and
`policy_payload_hash` as canonical lower-case hex for the successor specs.

For a new keyset, set `keyset_epoch` to exactly the previous epoch plus one,
set `previous_payload_hash` to the previous keyset payload hash, and preserve
the required live-key overlap. Then sign it offline:

```sh
$BIN sign-keyset \
  --mode successor \
  --previous-bundle "$PREVIOUS" \
  --root-seed offline/root.seed \
  --root-identity public/root.identity.json \
  --spec keyset-next.json \
  --out public/keyset-next.cose
```

The offline command verifies the predecessor and new root signature, then uses
the same epoch, hash-chain, immutable-key, status-transition, and overlap logic
as the client. A policy-only release reuses the already accepted keyset and
does not run `sign-keyset` again.

For the policy, advance exactly one sequence (or the next epoch at sequence
zero), set `previous_payload_hash` to the previous policy payload hash, and
sign online:

```sh
$BIN sign-policy \
  --mode successor \
  --previous-bundle "$PREVIOUS" \
  --online-seed online/policy.seed \
  --online-identity public/online.identity.json \
  --root-identity public/root.identity.json \
  --keyset public/keyset-next.cose \
  --spec policy-next.json \
  --out public/policy-next.cose
```

Finally, repeat the transition check before no-clobber publication:

```sh
$BIN assemble \
  --mode successor \
  --previous-bundle "$PREVIOUS" \
  --root-identity public/root.identity.json \
  --keyset public/keyset-next.cose \
  --policy public/policy-next.cose \
  --out public/bundle-next.cbor
```

The policy signer and assembler call the core successor helper, which delegates
to the same anti-rollback, fork, gap, hash-chain, key-rotation, pin-rotation,
and clock/liveness transition implementation used by client state updates.
Standalone-valid but client-unacceptable gaps and forks are rejected before an
output artifact is published. Idempotent bundles are not accepted as successor
releases.

The predecessor bundle is an explicit operator assertion of what clients have
accepted; the signer can authenticate and validate it but cannot prove fleet
deployment. The client durable state remains authoritative and additionally
preserves its local maximum wall-clock floor. Rotate while the predecessor is
still live: no command offers backdating, expiry bypass, or ambient state
auto-discovery.

Treat `root.identity.json` as a trust anchor distributed through an independent
authenticated channel. A correctly signed bundle under an attacker-selected
root is not trusted.
