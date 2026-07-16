mod custody;
mod documents;

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;
use shadowpipe_core::signed_policy::{
    apply_verified_successor, apply_verified_update, decode_bundle, encode_bundle,
    encode_keyset_payload, encode_policy_payload, encode_protected_header, encode_sign1,
    signature_structure, validate_keyset_successor, verify_bundle, verify_keyset_artifact,
    BundleBytes, ContentType, KeyStatus, Kid, ProtectedHeader, Transition, TrustedRoot,
    VerifiedBundle, MAX_BUNDLE_BYTES,
};

pub use documents::{EndpointPolicyDocument, IdentityDocument, IdentityKind, KeysetDocument};

use custody::{
    atomic_write_new, ensure_absent, read_public_file, read_secret_seed,
    write_secret_seed_create_new, SecretSeed, MAX_JSON_BYTES,
};
use documents::{parse_json, parse_optional_kid};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSummary {
    pub root_id: String,
    pub keyset_epoch: u64,
    pub keyset_payload_hash: String,
    pub policy_epoch: u64,
    pub sequence: u64,
    pub policy_payload_hash: String,
    pub signer_kid: String,
    pub endpoint_count: usize,
    pub expires_at: i64,
}

impl VerificationSummary {
    fn from_verified(verified: &VerifiedBundle) -> Self {
        Self {
            root_id: hex::encode(verified.root_id()),
            keyset_epoch: verified.keyset().keyset_epoch,
            keyset_payload_hash: hex::encode(verified.keyset_hash()),
            policy_epoch: verified.policy().policy_epoch,
            sequence: verified.policy().sequence,
            policy_payload_hash: hex::encode(verified.policy_hash()),
            signer_kid: hex::encode(verified.signer_kid().as_bytes()),
            endpoint_count: verified.plan().endpoints().len(),
            expires_at: verified.plan().expires_at(),
        }
    }

    pub fn to_pretty_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self).context("encode verification summary")?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

pub fn unix_now() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs()
        .try_into()
        .context("system clock does not fit signed-policy timestamp")
}

fn key_pair(seed: &SecretSeed) -> Result<Ed25519KeyPair> {
    Ed25519KeyPair::from_seed_unchecked(seed.as_bytes())
        .map_err(|_| anyhow::anyhow!("Ed25519 seed is not accepted by ring"))
}

fn public_key(pair: &Ed25519KeyPair) -> [u8; 32] {
    pair.public_key()
        .as_ref()
        .try_into()
        .expect("ring Ed25519 public keys are exactly 32 bytes")
}

fn random_kid() -> Result<Kid> {
    let mut kid = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut kid)
        .context("obtain kid entropy")?;
    Ok(Kid::new(kid))
}

fn ensure_distinct_paths(first: &Path, second: &Path, what: &str) -> Result<()> {
    anyhow::ensure!(first != second, "{what} paths must be distinct");
    Ok(())
}

fn load_identity(path: &Path) -> Result<IdentityDocument> {
    parse_json(
        &read_public_file(path, MAX_JSON_BYTES)?,
        "identity document",
    )
}

fn load_root(path: &Path) -> Result<TrustedRoot> {
    load_identity(path)?.as_root_trust()
}

fn load_verified_bundle(path: &Path, root: &TrustedRoot, now: i64) -> Result<VerifiedBundle> {
    let encoded = read_public_file(path, MAX_BUNDLE_BYTES)?;
    verify_bundle(&encoded, root, now)
        .with_context(|| format!("verify explicit predecessor bundle {}", path.display()))
}

fn validate_release_transition(
    previous_bundle_path: Option<&Path>,
    root: &TrustedRoot,
    candidate: &VerifiedBundle,
    now: i64,
) -> Result<()> {
    let transition = match previous_bundle_path {
        None => apply_verified_update(None, candidate.clone(), now)
            .context("validate explicit enrollment transition")?,
        Some(path) => {
            let previous = load_verified_bundle(path, root, now)?;
            apply_verified_successor(&previous, candidate.clone(), now)
                .context("validate explicit successor transition")?
        }
    };
    anyhow::ensure!(
        matches!(transition, Transition::Applied(_)),
        "successor mode requires a new client-applicable state, not an idempotent bundle"
    );
    Ok(())
}

fn sign_payload(
    seed: &SecretSeed,
    content_type: ContentType,
    kid: Kid,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let pair = key_pair(seed)?;
    let protected = encode_protected_header(&ProtectedHeader { content_type, kid })
        .context("encode protected COSE header")?;
    let signature_input =
        signature_structure(&protected, payload).context("encode COSE Signature1 structure")?;
    let signature: [u8; 64] = pair
        .sign(&signature_input)
        .as_ref()
        .try_into()
        .expect("ring Ed25519 signatures are exactly 64 bytes");
    encode_sign1(&protected, payload, &signature).context("encode COSE_Sign1")
}

pub fn generate_identity(
    kind: IdentityKind,
    requested_kid: Option<&str>,
    seed_output: &Path,
    identity_output: &Path,
) -> Result<IdentityDocument> {
    ensure_distinct_paths(seed_output, identity_output, "seed and identity output")?;
    ensure_absent(seed_output)?;
    ensure_absent(identity_output)?;
    let seed = SecretSeed::generate()?;
    let pair = key_pair(&seed)?;
    let kid = match parse_optional_kid(requested_kid)? {
        Some(kid) => kid,
        None => random_kid()?,
    };
    let identity = IdentityDocument::new(kind, kid, public_key(&pair));
    let identity_bytes = identity.to_pretty_json()?;

    // Publish the recoverable secret first.  A crash before the public sidecar
    // leaves a secure seed, never a public identity whose secret was lost.
    write_secret_seed_create_new(seed_output, &seed)?;
    atomic_write_new(identity_output, &identity_bytes).with_context(|| {
        format!(
            "publish public identity {}; seed remains securely stored at {}",
            identity_output.display(),
            seed_output.display()
        )
    })?;
    Ok(identity)
}

pub fn sign_keyset(
    root_seed_path: &Path,
    root_identity_path: &Path,
    keyset_json_path: &Path,
    output_path: &Path,
    previous_bundle_path: Option<&Path>,
) -> Result<()> {
    sign_keyset_at(
        root_seed_path,
        root_identity_path,
        keyset_json_path,
        output_path,
        previous_bundle_path,
        unix_now()?,
    )
}

fn sign_keyset_at(
    root_seed_path: &Path,
    root_identity_path: &Path,
    keyset_json_path: &Path,
    output_path: &Path,
    previous_bundle_path: Option<&Path>,
    now: i64,
) -> Result<()> {
    ensure_distinct_paths(
        root_seed_path,
        output_path,
        "root seed and signed keyset output",
    )?;
    let root = load_root(root_identity_path)?;
    let seed = read_secret_seed(root_seed_path)?;
    let pair = key_pair(&seed)?;
    anyhow::ensure!(
        public_key(&pair) == root.ed25519_public_key,
        "root seed does not match the explicit offline-root identity"
    );
    let document: KeysetDocument = parse_json(
        &read_public_file(keyset_json_path, MAX_JSON_BYTES)?,
        "keyset specification",
    )?;
    let keyset = document.into_core()?;
    let payload = encode_keyset_payload(&keyset).context("encode canonical keyset payload")?;
    let sign1 = sign_payload(&seed, ContentType::Keyset, root.kid, &payload)?;
    let verified = verify_keyset_artifact(&sign1, &root, now)
        .context("self-verify root-signed keyset artifact")?;
    anyhow::ensure!(
        verified.keyset() == &keyset,
        "self-verified keyset differs from requested canonical payload"
    );
    match previous_bundle_path {
        None => {
            anyhow::ensure!(
                verified.keyset().keyset_epoch == 0
                    && verified.keyset().previous_payload_hash.is_none(),
                "enrollment keyset must be epoch 0 without a predecessor hash"
            );
        }
        Some(path) => {
            ensure_distinct_paths(
                path,
                output_path,
                "predecessor bundle and signed keyset output",
            )?;
            let previous = load_verified_bundle(path, &root, now)?;
            validate_keyset_successor(&previous, &verified)
                .context("validate root-signed keyset successor")?;
        }
    }
    atomic_write_new(output_path, &sign1)
}

#[allow(clippy::too_many_arguments)]
pub fn sign_policy(
    online_seed_path: &Path,
    online_identity_path: &Path,
    root_identity_path: &Path,
    keyset_sign1_path: &Path,
    policy_json_path: &Path,
    output_path: &Path,
    previous_bundle_path: Option<&Path>,
) -> Result<()> {
    sign_policy_at(
        online_seed_path,
        online_identity_path,
        root_identity_path,
        keyset_sign1_path,
        policy_json_path,
        output_path,
        previous_bundle_path,
        unix_now()?,
    )
}

#[allow(clippy::too_many_arguments)]
fn sign_policy_at(
    online_seed_path: &Path,
    online_identity_path: &Path,
    root_identity_path: &Path,
    keyset_sign1_path: &Path,
    policy_json_path: &Path,
    output_path: &Path,
    previous_bundle_path: Option<&Path>,
    now: i64,
) -> Result<()> {
    ensure_distinct_paths(
        online_seed_path,
        output_path,
        "online seed and signed policy output",
    )?;
    let root = load_root(root_identity_path)?;
    let online_identity = load_identity(online_identity_path)?;
    let (online_kid, online_public_key) = online_identity.as_online_identity()?;
    let seed = read_secret_seed(online_seed_path)?;
    let pair = key_pair(&seed)?;
    anyhow::ensure!(
        public_key(&pair) == online_public_key,
        "online seed does not match the explicit online identity"
    );

    let keyset_sign1 = read_public_file(keyset_sign1_path, MAX_BUNDLE_BYTES)?;
    let verified_keyset = verify_keyset_artifact(&keyset_sign1, &root, now)
        .context("verify root-signed keyset before policy signing")?;
    let authorized_key = verified_keyset
        .keyset()
        .keys
        .iter()
        .find(|key| key.kid == online_kid)
        .context("online identity kid is absent from the verified keyset")?;
    anyhow::ensure!(
        authorized_key.ed25519_public_key == online_public_key,
        "verified keyset kid is bound to a different online public key"
    );
    anyhow::ensure!(
        authorized_key.status == KeyStatus::Active,
        "candidate policies must be signed by an active online key"
    );

    let document: EndpointPolicyDocument = parse_json(
        &read_public_file(policy_json_path, MAX_JSON_BYTES)?,
        "endpoint-policy specification",
    )?;
    let policy = document.into_core(&verified_keyset)?;
    let payload = encode_policy_payload(&policy).context("encode canonical policy payload")?;
    let policy_sign1 = sign_payload(&seed, ContentType::EndpointPolicy, online_kid, &payload)?;
    let candidate_bundle = encode_bundle(&BundleBytes {
        keyset_sign1,
        policy_sign1: policy_sign1.clone(),
    })
    .context("assemble policy self-verification bundle")?;
    let verified = verify_bundle(&candidate_bundle, &root, now)
        .context("self-verify online-signed endpoint policy")?;
    anyhow::ensure!(
        verified.policy() == &policy && verified.signer_kid() == online_kid,
        "self-verified policy differs from requested canonical payload or signer"
    );
    validate_release_transition(previous_bundle_path, &root, &verified, now)?;
    atomic_write_new(output_path, &policy_sign1)
}

pub fn assemble_bundle(
    root_identity_path: &Path,
    keyset_sign1_path: &Path,
    policy_sign1_path: &Path,
    output_path: &Path,
    previous_bundle_path: Option<&Path>,
) -> Result<VerificationSummary> {
    assemble_bundle_at(
        root_identity_path,
        keyset_sign1_path,
        policy_sign1_path,
        output_path,
        previous_bundle_path,
        unix_now()?,
    )
}

fn assemble_bundle_at(
    root_identity_path: &Path,
    keyset_sign1_path: &Path,
    policy_sign1_path: &Path,
    output_path: &Path,
    previous_bundle_path: Option<&Path>,
    now: i64,
) -> Result<VerificationSummary> {
    let root = load_root(root_identity_path)?;
    let bundle = BundleBytes {
        keyset_sign1: read_public_file(keyset_sign1_path, MAX_BUNDLE_BYTES)?,
        policy_sign1: read_public_file(policy_sign1_path, MAX_BUNDLE_BYTES)?,
    };
    let encoded = encode_bundle(&bundle).context("encode canonical signed-policy bundle")?;
    let verified =
        verify_bundle(&encoded, &root, now).context("verify complete bundle before publication")?;
    validate_release_transition(previous_bundle_path, &root, &verified, now)?;
    let summary = VerificationSummary::from_verified(&verified);
    atomic_write_new(output_path, &encoded)?;
    Ok(summary)
}

pub fn verify_bundle_file(
    root_identity_path: &Path,
    bundle_path: &Path,
) -> Result<VerificationSummary> {
    verify_bundle_file_at(root_identity_path, bundle_path, unix_now()?)
}

fn verify_bundle_file_at(
    root_identity_path: &Path,
    bundle_path: &Path,
    now: i64,
) -> Result<VerificationSummary> {
    let root = load_root(root_identity_path)?;
    let encoded = read_public_file(bundle_path, MAX_BUNDLE_BYTES)?;
    // Decode first only to make an outer-format failure explicit; verify_bundle
    // repeats this canonical check and is the sole authority constructor.
    decode_bundle(&encoded).context("decode canonical bundle envelope")?;
    let verified = verify_bundle(&encoded, &root, now).context("verify signed-policy bundle")?;
    Ok(VerificationSummary::from_verified(&verified))
}

#[cfg(test)]
mod tests;
