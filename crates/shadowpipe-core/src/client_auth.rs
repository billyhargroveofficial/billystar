//! Mandatory hybrid per-device authorization for the v3 inner handshake.
//!
//! Each device has two independent authenticators: an Ed25519 signing seed and
//! a uniformly random 256-bit PSK.  The server's bounded, root-owned allowlist
//! maps the key identifier derived from the Ed25519 public key to both exact
//! authenticators.  Ed25519 is classical authentication; the HMAC proof is a
//! symmetric post-quantum hedge.  This composition is intentionally built from
//! standard primitives and is not claimed as a novel cryptographic protocol.

use crate::session::{
    atomic_create_private_file, atomic_write_private_file, is_not_found,
    read_private_file_to_string_bounded, CreatePrivateFileOutcome, PrivateFileOwner,
};
use crate::{
    crypto::ct_eq,
    proto::{CamouflageMode, CarrierBinding},
    BUILD_MAGIC, PROTO_VERSION,
};
use anyhow::{anyhow, Context, Result};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

pub const CLIENT_KEY_ID_LEN: usize = 16;
pub const CLIENT_PUBLIC_KEY_LEN: usize = 32;
pub const CLIENT_PSK_LEN: usize = 32;
pub const CLIENT_SIGNATURE_LEN: usize = 64;
pub const CLIENT_MAC_LEN: usize = 32;
pub const SERVER_ACCESS_CHALLENGE_LEN: usize = 32;
pub const CLIENT_ACCESS_NONCE_LEN: usize = 32;
pub const CLIENT_ACCESS_HELLO_LEN: usize = CLIENT_KEY_ID_LEN;
pub const SERVER_ACCESS_PROOF_LEN: usize = SERVER_ACCESS_CHALLENGE_LEN + CLIENT_MAC_LEN;
pub const CLIENT_ACCESS_PROOF_LEN: usize = CLIENT_ACCESS_NONCE_LEN + CLIENT_MAC_LEN;
pub const CLIENT_FINISHED_LEN: usize =
    1 + CLIENT_KEY_ID_LEN + CLIENT_SIGNATURE_LEN + CLIENT_MAC_LEN;
pub const SERVER_FINISHED_LEN: usize = 1 + CLIENT_MAC_LEN;
pub const MAX_AUTHORIZED_CLIENTS: usize = 256;

const CLIENT_AUTH_FILE_LIMIT: u64 = 256 * 1024;
const CLIENT_FINISHED_FORMAT: u8 = 1;
const SERVER_FINISHED_FORMAT: u8 = 1;
const CLIENT_KEY_ID_DOMAIN: &[u8] = b"shadowpipe-client-key-id-v3\0";
const SERVER_ACCESS_PROOF_DOMAIN: &[u8] = b"shadowpipe-v3/server-access-proof\0";
const CLIENT_ACCESS_PROOF_DOMAIN: &[u8] = b"shadowpipe-v3/client-access-proof\0";
const CLIENT_PROOF_DOMAIN: &[u8] = b"shadowpipe-v3/client-finished-proof\0";
const SERVER_PROOF_DOMAIN: &[u8] = b"shadowpipe-v3/server-finished-proof\0";
// RFC 8032 test-vector public key. Unknown key ids still traverse Ed25519's
// normal valid-key verification path instead of taking a fast invalid-point
// failure on an all-zero dummy encoding. Key identifiers remain 128-bit
// unguessable values; this only narrows an avoidable membership-timing signal.
const DUMMY_ED25519_PUBLIC_KEY: ClientPublicKey = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const IDENTITY_SCHEMA: &str = "shadowpipe-client-credential-v1";
const ENROLLMENT_SCHEMA: &str = "shadowpipe-client-enrollment-v1";
const ALLOWLIST_SCHEMA: &str = "shadowpipe-client-allowlist-v1";

pub type ClientKeyId = [u8; CLIENT_KEY_ID_LEN];
pub type ClientPublicKey = [u8; CLIENT_PUBLIC_KEY_LEN];

#[cfg(unix)]
fn require_unix_production_private_files() -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn require_unix_production_private_files() -> Result<()> {
    Err(anyhow!(
        "root-owned production client credentials require Unix ownership and mode semantics; use explicit no-TUN development mode on this platform"
    ))
}

struct AllowlistMutationLease {
    file: File,
}

impl AllowlistMutationLease {
    fn acquire(allowlist_path: &Path, owner: PrivateFileOwner) -> Result<Self> {
        validate_trusted_parent(allowlist_path, owner)?;
        let file_name = allowlist_path.file_name().ok_or_else(|| {
            anyhow!(
                "client allowlist path has no file name: {}",
                allowlist_path.display()
            )
        })?;
        let lock_path = allowlist_path.with_file_name(format!(
            ".{}.shadowpipe-mutation-lock",
            file_name.to_string_lossy()
        ));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(&lock_path).with_context(|| {
            format!(
                "open client allowlist mutation lock {}",
                lock_path.display()
            )
        })?;
        let metadata = file.metadata().with_context(|| {
            format!(
                "stat client allowlist mutation lock {}",
                lock_path.display()
            )
        })?;
        if !metadata.is_file() {
            return Err(anyhow!(
                "client allowlist mutation lock is not a regular file: {}",
                lock_path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            // SAFETY: geteuid takes no arguments and has no preconditions.
            let effective_uid = unsafe { libc::geteuid() };
            let expected_uid = match owner {
                PrivateFileOwner::EffectiveUser => effective_uid,
                PrivateFileOwner::Root => 0,
            };
            let mode = metadata.permissions().mode() & 0o777;
            if metadata.uid() != expected_uid || mode != 0o600 || metadata.nlink() != 1 {
                return Err(anyhow!(
                    "client allowlist mutation lock {} must be single-link, UID {}, mode 0600",
                    lock_path.display(),
                    expected_uid
                ));
            }
        }

        // `std::fs::File::try_lock` maps to a nonblocking advisory lock on Unix
        // and LockFileEx on Windows. Development enrollment/revocation is thus
        // serialized on every supported host instead of silently becoming a
        // lost-update race outside Unix. Production ownership semantics remain
        // Unix-only and fail closed earlier on non-Unix targets.
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(anyhow!(
                    "client allowlist mutation is already in progress: {}",
                    allowlist_path.display()
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(error).with_context(|| {
                    format!(
                        "lock client allowlist mutation {}",
                        allowlist_path.display()
                    )
                });
            }
        }
        Ok(Self { file })
    }
}

impl Drop for AllowlistMutationLease {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("resolve current directory for private credential path")?
            .join(path))
    }
}

/// Refuse credential operations through symlinked or attacker-writable
/// directory components. Root-owned daemon artifacts must live entirely below
/// root-owned components; development credentials may additionally traverse
/// components owned by the current effective user. The final file itself is
/// still opened O_NOFOLLOW and checked through its descriptor.
fn validate_trusted_parent(path: &Path, _expected_owner: PrivateFileOwner) -> Result<()> {
    let absolute = absolute_path(path)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| anyhow!("private credential path has no parent: {}", path.display()))?;
    let mut cursor = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::Prefix(_) => {
                cursor.push(component.as_os_str());
                continue;
            }
            Component::RootDir => cursor.push(component.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(anyhow!(
                    "private credential path may not contain parent traversal: {}",
                    path.display()
                ));
            }
            Component::Normal(part) => cursor.push(part),
        }
        let metadata = std::fs::symlink_metadata(&cursor).with_context(|| {
            format!("inspect private credential directory {}", cursor.display())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(anyhow!(
                "private credential directory component is not a real directory: {}",
                cursor.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            // SAFETY: geteuid takes no arguments and has no preconditions.
            let effective_uid = unsafe { libc::geteuid() };
            let owner_allowed = match _expected_owner {
                PrivateFileOwner::Root => metadata.uid() == 0,
                PrivateFileOwner::EffectiveUser => {
                    metadata.uid() == 0 || metadata.uid() == effective_uid
                }
            };
            if !owner_allowed {
                return Err(anyhow!(
                    "private credential directory {} is owned by untrusted UID {}",
                    cursor.display(),
                    metadata.uid()
                ));
            }
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o022 != 0 {
                return Err(anyhow!(
                    "private credential directory {} is group/world writable ({:04o})",
                    cursor.display(),
                    mode
                ));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AuthFailed;

impl fmt::Display for AuthFailed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("client authentication failed")
    }
}

impl std::error::Error for AuthFailed {}

fn derive_key_id(public_key: &ClientPublicKey) -> ClientKeyId {
    let mut hash = Sha256::new();
    hash.update(CLIENT_KEY_ID_DOMAIN);
    hash.update(public_key);
    let digest = hash.finalize();
    let mut id = [0u8; CLIENT_KEY_ID_LEN];
    id.copy_from_slice(&digest[..CLIENT_KEY_ID_LEN]);
    id
}

fn proof_message(
    domain: &[u8],
    format: u8,
    key_id: &ClientKeyId,
    transcript: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + 1 + CLIENT_KEY_ID_LEN + transcript.len());
    message.extend_from_slice(domain);
    message.push(format);
    message.extend_from_slice(key_id);
    message.extend_from_slice(transcript);
    message
}

fn client_proof_message(key_id: &ClientKeyId, transcript: &[u8; 32]) -> Vec<u8> {
    proof_message(
        CLIENT_PROOF_DOMAIN,
        CLIENT_FINISHED_FORMAT,
        key_id,
        transcript,
    )
}

fn server_access_proof_message_with_magic(
    build_magic: u32,
    challenge: &[u8; SERVER_ACCESS_CHALLENGE_LEN],
    key_id: &ClientKeyId,
    camouflage: CamouflageMode,
    carrier_binding: CarrierBinding,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        SERVER_ACCESS_PROOF_DOMAIN.len()
            + 1
            + 4
            + 1
            + 1
            + CLIENT_KEY_ID_LEN
            + SERVER_ACCESS_CHALLENGE_LEN,
    );
    message.extend_from_slice(SERVER_ACCESS_PROOF_DOMAIN);
    message.push(PROTO_VERSION);
    message.extend_from_slice(&build_magic.to_be_bytes());
    message.push(camouflage as u8);
    message.push(carrier_binding as u8);
    message.extend_from_slice(key_id);
    message.extend_from_slice(challenge);
    message
}

fn server_access_proof_message(
    challenge: &[u8; SERVER_ACCESS_CHALLENGE_LEN],
    key_id: &ClientKeyId,
    camouflage: CamouflageMode,
    carrier_binding: CarrierBinding,
) -> Vec<u8> {
    server_access_proof_message_with_magic(
        BUILD_MAGIC,
        challenge,
        key_id,
        camouflage,
        carrier_binding,
    )
}

fn client_access_proof_message_with_magic(
    build_magic: u32,
    challenge: &[u8; SERVER_ACCESS_CHALLENGE_LEN],
    server_mac: &[u8; CLIENT_MAC_LEN],
    key_id: &ClientKeyId,
    client_nonce: &[u8; CLIENT_ACCESS_NONCE_LEN],
    camouflage: CamouflageMode,
    carrier_binding: CarrierBinding,
) -> Vec<u8> {
    // Every component has a fixed width. Role-specific domains plus the
    // protocol/build identity, inner framing and exact outer carrier prevent
    // cross-role, downgrade, cross-build, raw↔h2 and cross-carrier replay.
    // Binding the exact server tag turns this into mutual PSK possession rather
    // than a chosen-challenge MAC oracle.
    let mut message = Vec::with_capacity(
        CLIENT_ACCESS_PROOF_DOMAIN.len()
            + 1
            + 4
            + 1
            + 1
            + CLIENT_KEY_ID_LEN
            + SERVER_ACCESS_CHALLENGE_LEN
            + CLIENT_MAC_LEN
            + CLIENT_ACCESS_NONCE_LEN,
    );
    message.extend_from_slice(CLIENT_ACCESS_PROOF_DOMAIN);
    message.push(PROTO_VERSION);
    message.extend_from_slice(&build_magic.to_be_bytes());
    message.push(camouflage as u8);
    message.push(carrier_binding as u8);
    message.extend_from_slice(key_id);
    message.extend_from_slice(challenge);
    message.extend_from_slice(server_mac);
    message.extend_from_slice(client_nonce);
    message
}

fn client_access_proof_message(
    challenge: &[u8; SERVER_ACCESS_CHALLENGE_LEN],
    server_mac: &[u8; CLIENT_MAC_LEN],
    key_id: &ClientKeyId,
    client_nonce: &[u8; CLIENT_ACCESS_NONCE_LEN],
    camouflage: CamouflageMode,
    carrier_binding: CarrierBinding,
) -> Vec<u8> {
    client_access_proof_message_with_magic(
        BUILD_MAGIC,
        challenge,
        server_mac,
        key_id,
        client_nonce,
        camouflage,
        carrier_binding,
    )
}

fn server_proof_message(
    key_id: &ClientKeyId,
    transcript: &[u8; 32],
    client_finished: &[u8; CLIENT_FINISHED_LEN],
) -> Vec<u8> {
    let mut message = proof_message(
        SERVER_PROOF_DOMAIN,
        SERVER_FINISHED_FORMAT,
        key_id,
        transcript,
    );
    message.extend_from_slice(client_finished);
    message
}

fn hmac_sha256(psk: &[u8; CLIENT_PSK_LEN], message: &[u8]) -> [u8; CLIENT_MAC_LEN] {
    // ring's Key owns an expanded copy internally and does not implement
    // Zeroize.  Keep it scoped to this single operation; the source PSK itself
    // remains in Zeroizing storage for its full lifetime.
    let key = hmac::Key::new(hmac::HMAC_SHA256, psk);
    let tag = hmac::sign(&key, message);
    let mut output = [0u8; CLIENT_MAC_LEN];
    output.copy_from_slice(tag.as_ref());
    output
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct ServerAccessProof {
    pub challenge: [u8; SERVER_ACCESS_CHALLENGE_LEN],
    pub psk_mac: [u8; CLIENT_MAC_LEN],
}

impl ServerAccessProof {
    pub fn encode(self) -> [u8; SERVER_ACCESS_PROOF_LEN] {
        let mut encoded = [0u8; SERVER_ACCESS_PROOF_LEN];
        encoded[..SERVER_ACCESS_CHALLENGE_LEN].copy_from_slice(&self.challenge);
        encoded[SERVER_ACCESS_CHALLENGE_LEN..].copy_from_slice(&self.psk_mac);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> std::result::Result<Self, AuthFailed> {
        if encoded.len() != SERVER_ACCESS_PROOF_LEN {
            return Err(AuthFailed);
        }
        let mut challenge = [0u8; SERVER_ACCESS_CHALLENGE_LEN];
        challenge.copy_from_slice(&encoded[..SERVER_ACCESS_CHALLENGE_LEN]);
        let mut psk_mac = [0u8; CLIENT_MAC_LEN];
        psk_mac.copy_from_slice(&encoded[SERVER_ACCESS_CHALLENGE_LEN..]);
        Ok(Self { challenge, psk_mac })
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct ClientAccessProof {
    pub client_nonce: [u8; CLIENT_ACCESS_NONCE_LEN],
    pub psk_mac: [u8; CLIENT_MAC_LEN],
}

impl ClientAccessProof {
    pub fn encode(self) -> [u8; CLIENT_ACCESS_PROOF_LEN] {
        let mut encoded = [0u8; CLIENT_ACCESS_PROOF_LEN];
        encoded[..CLIENT_ACCESS_NONCE_LEN].copy_from_slice(&self.client_nonce);
        encoded[CLIENT_ACCESS_NONCE_LEN..].copy_from_slice(&self.psk_mac);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> std::result::Result<Self, AuthFailed> {
        if encoded.len() != CLIENT_ACCESS_PROOF_LEN {
            return Err(AuthFailed);
        }
        let mut client_nonce = [0u8; CLIENT_ACCESS_NONCE_LEN];
        client_nonce.copy_from_slice(&encoded[..CLIENT_ACCESS_NONCE_LEN]);
        let mut psk_mac = [0u8; CLIENT_MAC_LEN];
        psk_mac.copy_from_slice(&encoded[CLIENT_ACCESS_NONCE_LEN..]);
        Ok(Self {
            client_nonce,
            psk_mac,
        })
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct ClientFinished {
    pub key_id: ClientKeyId,
    pub signature: [u8; CLIENT_SIGNATURE_LEN],
    pub psk_mac: [u8; CLIENT_MAC_LEN],
}

impl ClientFinished {
    pub fn encode(self) -> [u8; CLIENT_FINISHED_LEN] {
        let mut encoded = [0u8; CLIENT_FINISHED_LEN];
        encoded[0] = CLIENT_FINISHED_FORMAT;
        let kid_end = 1 + CLIENT_KEY_ID_LEN;
        let signature_end = kid_end + CLIENT_SIGNATURE_LEN;
        encoded[1..kid_end].copy_from_slice(&self.key_id);
        encoded[kid_end..signature_end].copy_from_slice(&self.signature);
        encoded[signature_end..].copy_from_slice(&self.psk_mac);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> std::result::Result<Self, AuthFailed> {
        if encoded.len() != CLIENT_FINISHED_LEN || encoded[0] != CLIENT_FINISHED_FORMAT {
            return Err(AuthFailed);
        }
        let kid_end = 1 + CLIENT_KEY_ID_LEN;
        let signature_end = kid_end + CLIENT_SIGNATURE_LEN;
        let mut key_id = [0u8; CLIENT_KEY_ID_LEN];
        key_id.copy_from_slice(&encoded[1..kid_end]);
        let mut signature = [0u8; CLIENT_SIGNATURE_LEN];
        signature.copy_from_slice(&encoded[kid_end..signature_end]);
        let mut psk_mac = [0u8; CLIENT_MAC_LEN];
        psk_mac.copy_from_slice(&encoded[signature_end..]);
        Ok(Self {
            key_id,
            signature,
            psk_mac,
        })
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct ServerFinished {
    pub psk_mac: [u8; CLIENT_MAC_LEN],
}

impl ServerFinished {
    pub fn encode(self) -> [u8; SERVER_FINISHED_LEN] {
        let mut encoded = [0u8; SERVER_FINISHED_LEN];
        encoded[0] = SERVER_FINISHED_FORMAT;
        encoded[1..].copy_from_slice(&self.psk_mac);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> std::result::Result<Self, AuthFailed> {
        if encoded.len() != SERVER_FINISHED_LEN || encoded[0] != SERVER_FINISHED_FORMAT {
            return Err(AuthFailed);
        }
        let mut psk_mac = [0u8; CLIENT_MAC_LEN];
        psk_mac.copy_from_slice(&encoded[1..]);
        Ok(Self { psk_mac })
    }
}

pub struct ClientCredential {
    seed: Zeroizing<[u8; 32]>,
    public_key: ClientPublicKey,
    psk: Zeroizing<[u8; CLIENT_PSK_LEN]>,
    key_id: ClientKeyId,
}

impl fmt::Debug for ClientCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientCredential")
            .field("key_id", &hex::encode(self.key_id))
            .field("private_material", &"<redacted>")
            .finish()
    }
}

impl ClientCredential {
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut seed = Zeroizing::new([0u8; 32]);
        let mut psk = Zeroizing::new([0u8; CLIENT_PSK_LEN]);
        rng.fill(seed.as_mut())
            .map_err(|_| anyhow!("operating-system RNG failed while generating Ed25519 seed"))?;
        rng.fill(psk.as_mut())
            .map_err(|_| anyhow!("operating-system RNG failed while generating client PSK"))?;
        Self::from_parts(seed, psk)
    }

    fn from_parts(seed: Zeroizing<[u8; 32]>, psk: Zeroizing<[u8; CLIENT_PSK_LEN]>) -> Result<Self> {
        // ring's expanded Ed25519 keypair cannot be explicitly zeroized.  It is
        // therefore constructed only for public-key derivation/signing and
        // dropped at the end of that short scope; the seed remains Zeroizing.
        let pair = Ed25519KeyPair::from_seed_unchecked(seed.as_ref())
            .map_err(|_| anyhow!("invalid Ed25519 client seed"))?;
        let public_key: ClientPublicKey = pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| anyhow!("unexpected Ed25519 public-key length"))?;
        let key_id = derive_key_id(&public_key);
        Ok(Self {
            seed,
            public_key,
            psk,
            key_id,
        })
    }

    pub fn key_id(&self) -> ClientKeyId {
        self.key_id
    }

    pub fn public_key(&self) -> ClientPublicKey {
        self.public_key
    }

    pub fn authorized_clients(&self) -> Result<AuthorizedClients> {
        AuthorizedClients::from_credentials(&[self])
    }

    pub(crate) fn psk(&self) -> &[u8; CLIENT_PSK_LEN] {
        &self.psk
    }

    pub(crate) fn verify_server_access_and_prove(
        &self,
        server_proof: &ServerAccessProof,
        claimed_camouflage: CamouflageMode,
        claimed_carrier: CarrierBinding,
    ) -> Result<ClientAccessProof> {
        let server_message = server_access_proof_message(
            &server_proof.challenge,
            &self.key_id,
            claimed_camouflage,
            claimed_carrier,
        );
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.psk.as_ref());
        hmac::verify(&key, &server_message, &server_proof.psk_mac)
            .map_err(|_| anyhow::Error::from(AuthFailed))?;

        // Generate and MAC a client nonce only after the peer proves PSK
        // possession. A malicious outer endpoint can learn the pseudonymous kid
        // in lab modes, but it cannot solicit a chosen-challenge PSK MAC.
        let rng = SystemRandom::new();
        let mut client_nonce = [0u8; CLIENT_ACCESS_NONCE_LEN];
        rng.fill(&mut client_nonce)
            .map_err(|_| anyhow!("operating-system RNG failed while generating access nonce"))?;
        let message = client_access_proof_message(
            &server_proof.challenge,
            &server_proof.psk_mac,
            &self.key_id,
            &client_nonce,
            claimed_camouflage,
            claimed_carrier,
        );
        Ok(ClientAccessProof {
            client_nonce,
            psk_mac: hmac_sha256(&self.psk, &message),
        })
    }

    pub(crate) fn sign_finished(&self, transcript: &[u8; 32]) -> Result<ClientFinished> {
        let message = client_proof_message(&self.key_id, transcript);
        let pair = Ed25519KeyPair::from_seed_unchecked(self.seed.as_ref())
            .map_err(|_| anyhow!("invalid in-memory Ed25519 client seed"))?;
        let signature: [u8; CLIENT_SIGNATURE_LEN] = pair
            .sign(&message)
            .as_ref()
            .try_into()
            .map_err(|_| anyhow!("unexpected Ed25519 signature length"))?;
        let psk_mac = hmac_sha256(&self.psk, &message);
        Ok(ClientFinished {
            key_id: self.key_id,
            signature,
            psk_mac,
        })
    }

    pub(crate) fn verify_server_finished(
        &self,
        transcript: &[u8; 32],
        client_finished: &[u8; CLIENT_FINISHED_LEN],
        server_finished: &ServerFinished,
    ) -> std::result::Result<(), AuthFailed> {
        let message = server_proof_message(&self.key_id, transcript, client_finished);
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.psk.as_ref());
        hmac::verify(&key, &message, &server_finished.psk_mac).map_err(|_| AuthFailed)
    }

    fn serialized(&self) -> Result<Zeroizing<String>> {
        #[derive(Serialize)]
        struct CredentialFile<'a> {
            schema: &'static str,
            key_id: String,
            ed25519_public_key: String,
            ed25519_seed: &'a str,
            psk: &'a str,
        }

        let seed_hex = Zeroizing::new(hex::encode(self.seed.as_ref()));
        let psk_hex = Zeroizing::new(hex::encode(self.psk.as_ref()));
        let document = CredentialFile {
            schema: IDENTITY_SCHEMA,
            key_id: hex::encode(self.key_id),
            ed25519_public_key: hex::encode(self.public_key),
            ed25519_seed: seed_hex.as_str(),
            psk: psk_hex.as_str(),
        };
        Ok(Zeroizing::new(serde_json::to_string_pretty(&document)?))
    }

    /// Create a new 0600 credential without replacing any existing pathname.
    pub fn create(path: &Path) -> Result<Self> {
        validate_trusted_parent(path, PrivateFileOwner::EffectiveUser)?;
        let credential = Self::generate()?;
        let serialized = credential.serialized()?;
        match atomic_create_private_file(path, serialized.as_bytes())? {
            CreatePrivateFileOutcome::Created => Ok(credential),
            CreatePrivateFileOutcome::AlreadyExists => Err(anyhow!(
                "refusing to replace existing client credential {}",
                path.display()
            )),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::load_with_owner(path, PrivateFileOwner::EffectiveUser)
    }

    /// Production daemon loader: every path component and the file itself must
    /// be root-owned; the file must be a single-link regular file mode 0600.
    pub fn load_root_owned(path: &Path) -> Result<Self> {
        require_unix_production_private_files()?;
        Self::load_with_owner(path, PrivateFileOwner::Root)
    }

    fn load_with_owner(path: &Path, owner: PrivateFileOwner) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CredentialFile {
            schema: String,
            key_id: String,
            ed25519_public_key: String,
            ed25519_seed: Zeroizing<String>,
            psk: Zeroizing<String>,
        }

        validate_trusted_parent(path, owner)?;
        let json = read_private_file_to_string_bounded(path, CLIENT_AUTH_FILE_LIMIT, owner, true)?;
        let document: CredentialFile =
            serde_json::from_str(json.as_str()).context("parse client credential JSON")?;
        if document.schema != IDENTITY_SCHEMA {
            return Err(anyhow!(
                "unsupported client credential schema {:?}",
                document.schema
            ));
        }
        let seed = decode_secret_hex::<32>(&document.ed25519_seed, "Ed25519 seed")?;
        let psk = decode_secret_hex::<CLIENT_PSK_LEN>(&document.psk, "client PSK")?;
        let credential = Self::from_parts(seed, psk)?;
        let public_key = decode_public_hex::<CLIENT_PUBLIC_KEY_LEN>(
            &document.ed25519_public_key,
            "Ed25519 public key",
        )?;
        let key_id = decode_public_hex::<CLIENT_KEY_ID_LEN>(&document.key_id, "client key id")?;
        if public_key != credential.public_key || key_id != credential.key_id {
            return Err(anyhow!(
                "client credential public key or key id does not match its private seed"
            ));
        }
        Ok(credential)
    }

    /// Write a transfer artifact containing only the public Ed25519 key and the
    /// independent PSK needed by the server.  It is still secret and therefore
    /// created 0600 without replacement; the Ed25519 seed is never included.
    pub fn write_enrollment(&self, path: &Path) -> Result<()> {
        validate_trusted_parent(path, PrivateFileOwner::EffectiveUser)?;
        let enrollment = ClientEnrollment::from_credential(self);
        let serialized = enrollment.serialized()?;
        match atomic_create_private_file(path, serialized.as_bytes())? {
            CreatePrivateFileOutcome::Created => Ok(()),
            CreatePrivateFileOutcome::AlreadyExists => Err(anyhow!(
                "refusing to replace existing client enrollment {}",
                path.display()
            )),
        }
    }
}

pub struct ClientEnrollment {
    key_id: ClientKeyId,
    public_key: ClientPublicKey,
    psk: Zeroizing<[u8; CLIENT_PSK_LEN]>,
}

impl ClientEnrollment {
    fn from_credential(credential: &ClientCredential) -> Self {
        Self {
            key_id: credential.key_id,
            public_key: credential.public_key,
            psk: Zeroizing::new(*credential.psk),
        }
    }

    fn serialized(&self) -> Result<Zeroizing<String>> {
        #[derive(Serialize)]
        struct EnrollmentFile<'a> {
            schema: &'static str,
            key_id: String,
            ed25519_public_key: String,
            psk: &'a str,
        }
        let psk_hex = Zeroizing::new(hex::encode(self.psk.as_ref()));
        Ok(Zeroizing::new(serde_json::to_string_pretty(
            &EnrollmentFile {
                schema: ENROLLMENT_SCHEMA,
                key_id: hex::encode(self.key_id),
                ed25519_public_key: hex::encode(self.public_key),
                psk: psk_hex.as_str(),
            },
        )?))
    }

    fn load_with_owner(path: &Path, owner: PrivateFileOwner) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EnrollmentFile {
            schema: String,
            key_id: String,
            ed25519_public_key: String,
            psk: Zeroizing<String>,
        }
        validate_trusted_parent(path, owner)?;
        let json = read_private_file_to_string_bounded(path, CLIENT_AUTH_FILE_LIMIT, owner, true)?;
        let document: EnrollmentFile =
            serde_json::from_str(json.as_str()).context("parse client enrollment JSON")?;
        if document.schema != ENROLLMENT_SCHEMA {
            return Err(anyhow!(
                "unsupported client enrollment schema {:?}",
                document.schema
            ));
        }
        let public_key = decode_public_hex(&document.ed25519_public_key, "Ed25519 public key")?;
        let key_id = decode_public_hex(&document.key_id, "client key id")?;
        if key_id != derive_key_id(&public_key) {
            return Err(anyhow!(
                "client enrollment key id is not derived from its Ed25519 public key"
            ));
        }
        Ok(Self {
            key_id,
            public_key,
            psk: decode_secret_hex(&document.psk, "client PSK")?,
        })
    }

    pub fn load_root_owned(path: &Path) -> Result<Self> {
        require_unix_production_private_files()?;
        Self::load_with_owner(path, PrivateFileOwner::Root)
    }

    fn load_development_user_owned(path: &Path) -> Result<Self> {
        Self::load_with_owner(path, PrivateFileOwner::EffectiveUser)
    }
}

struct AuthorizedClient {
    key_id: ClientKeyId,
    public_key: ClientPublicKey,
    psk: Zeroizing<[u8; CLIENT_PSK_LEN]>,
}

impl Clone for AuthorizedClient {
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id,
            public_key: self.public_key,
            psk: Zeroizing::new(*self.psk),
        }
    }
}

#[derive(Clone)]
pub struct AuthorizedClients {
    entries: Vec<AuthorizedClient>,
}

impl fmt::Debug for AuthorizedClients {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedClients")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

pub(crate) struct VerifiedClient {
    pub key_id: ClientKeyId,
    pub psk: Zeroizing<[u8; CLIENT_PSK_LEN]>,
}

pub(crate) struct PendingClientAccess {
    key_id: ClientKeyId,
    psk: Zeroizing<[u8; CLIENT_PSK_LEN]>,
    authorized: Choice,
}

impl PendingClientAccess {
    pub(crate) fn verify(
        &self,
        server_proof: &ServerAccessProof,
        observed_camouflage: CamouflageMode,
        observed_carrier: CarrierBinding,
        proof: &ClientAccessProof,
    ) -> std::result::Result<ClientKeyId, AuthFailed> {
        let message = client_access_proof_message(
            &server_proof.challenge,
            &server_proof.psk_mac,
            &self.key_id,
            &proof.client_nonce,
            observed_camouflage,
            observed_carrier,
        );
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.psk.as_ref());
        let mac_valid = hmac::verify(&key, &message, &proof.psk_mac).is_ok();
        if bool::from(self.authorized & Choice::from(mac_valid as u8)) {
            Ok(self.key_id)
        } else {
            Err(AuthFailed)
        }
    }
}

impl AuthorizedClients {
    pub fn from_credentials(credentials: &[&ClientCredential]) -> Result<Self> {
        let entries = credentials
            .iter()
            .map(|credential| AuthorizedClient {
                key_id: credential.key_id,
                public_key: credential.public_key,
                psk: Zeroizing::new(*credential.psk),
            })
            .collect();
        Self::from_entries(entries)
    }

    fn from_entries(mut entries: Vec<AuthorizedClient>) -> Result<Self> {
        if entries.is_empty() || entries.len() > MAX_AUTHORIZED_CLIENTS {
            return Err(anyhow!(
                "client allowlist must contain 1..={MAX_AUTHORIZED_CLIENTS} entries (got {})",
                entries.len()
            ));
        }
        entries.sort_unstable_by_key(|entry| entry.key_id);
        if entries
            .windows(2)
            .any(|pair| pair[0].key_id == pair[1].key_id)
        {
            return Err(anyhow!("duplicate client key id in allowlist"));
        }
        Ok(Self { entries })
    }

    pub(crate) fn begin_access(
        &self,
        key_id: ClientKeyId,
        challenge: &[u8; SERVER_ACCESS_CHALLENGE_LEN],
        observed_camouflage: CamouflageMode,
        observed_carrier: CarrierBinding,
    ) -> Result<(ServerAccessProof, PendingClientAccess)> {
        // Always allocate a fresh secret dummy and scan the complete bounded
        // allowlist. This avoids the obvious known/unknown binary-search plus
        // RNG timing branch, and never indexes secret material by the match.
        let mut psk = Zeroizing::new([0u8; CLIENT_PSK_LEN]);
        SystemRandom::new().fill(psk.as_mut()).map_err(|_| {
            anyhow!("operating-system RNG failed while generating dummy access key")
        })?;
        let mut authorized = Choice::from(0);
        for entry in &self.entries {
            let matches = entry.key_id.ct_eq(&key_id);
            for (selected, candidate) in psk.iter_mut().zip(entry.psk.iter()) {
                *selected = u8::conditional_select(selected, candidate, matches);
            }
            authorized |= matches;
        }
        let message =
            server_access_proof_message(challenge, &key_id, observed_camouflage, observed_carrier);
        let server_proof = ServerAccessProof {
            challenge: *challenge,
            psk_mac: hmac_sha256(&psk, &message),
        };
        Ok((
            server_proof,
            PendingClientAccess {
                key_id,
                psk,
                authorized,
            },
        ))
    }

    #[cfg(test)]
    pub(crate) fn verify_finished(
        &self,
        transcript: &[u8; 32],
        finished: &ClientFinished,
    ) -> std::result::Result<VerifiedClient, AuthFailed> {
        self.verify_finished_for_key(transcript, finished, &finished.key_id)
    }

    pub(crate) fn verify_finished_for_key(
        &self,
        transcript: &[u8; 32],
        finished: &ClientFinished,
        access_key_id: &ClientKeyId,
    ) -> std::result::Result<VerifiedClient, AuthFailed> {
        let index = self
            .entries
            .binary_search_by_key(&finished.key_id, |entry| entry.key_id)
            .ok();
        let dummy_psk = [0u8; CLIENT_PSK_LEN];
        let (public_key, psk) = index
            .map(|index| {
                let entry = &self.entries[index];
                (&entry.public_key, entry.psk.as_ref())
            })
            .unwrap_or((&DUMMY_ED25519_PUBLIC_KEY, &dummy_psk));

        let message = client_proof_message(&finished.key_id, transcript);
        let signature_valid = signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(&message, &finished.signature)
            .is_ok();
        let psk_key = hmac::Key::new(hmac::HMAC_SHA256, psk);
        let mac_valid = hmac::verify(&psk_key, &message, &finished.psk_mac).is_ok();
        let same_access_identity = ct_eq(&finished.key_id, access_key_id);

        match (index, signature_valid, mac_valid, same_access_identity) {
            (Some(index), true, true, true) => Ok(VerifiedClient {
                key_id: finished.key_id,
                psk: Zeroizing::new(*self.entries[index].psk),
            }),
            _ => Err(AuthFailed),
        }
    }

    pub(crate) fn make_server_finished(
        verified: &VerifiedClient,
        transcript: &[u8; 32],
        client_finished: &[u8; CLIENT_FINISHED_LEN],
    ) -> ServerFinished {
        let message = server_proof_message(&verified.key_id, transcript, client_finished);
        ServerFinished {
            psk_mac: hmac_sha256(&verified.psk, &message),
        }
    }

    fn load_with_owner(path: &Path, owner: PrivateFileOwner) -> Result<Self> {
        validate_trusted_parent(path, owner)?;
        let json = read_private_file_to_string_bounded(path, CLIENT_AUTH_FILE_LIMIT, owner, true)?;
        Self::parse(json.as_str())
    }

    pub fn load_root_owned(path: &Path) -> Result<Self> {
        require_unix_production_private_files()?;
        Self::load_with_owner(path, PrivateFileOwner::Root)
    }

    /// Explicit no-TUN development loader. It retains the exact mode-0600,
    /// regular-file, single-link, O_NOFOLLOW, bounded-schema checks while
    /// permitting path components and the file to be owned by the effective
    /// user. Production daemon starts must use [`Self::load_root_owned`].
    pub fn load_development_user_owned(path: &Path) -> Result<Self> {
        Self::load_with_owner(path, PrivateFileOwner::EffectiveUser)
    }

    fn parse(json: &str) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AllowlistFile {
            schema: String,
            clients: Vec<AllowlistEntry>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AllowlistEntry {
            key_id: String,
            ed25519_public_key: String,
            psk: Zeroizing<String>,
        }

        let document: AllowlistFile =
            serde_json::from_str(json).context("parse client allowlist JSON")?;
        if document.schema != ALLOWLIST_SCHEMA {
            return Err(anyhow!(
                "unsupported client allowlist schema {:?}",
                document.schema
            ));
        }
        if document.clients.is_empty() || document.clients.len() > MAX_AUTHORIZED_CLIENTS {
            return Err(anyhow!(
                "client allowlist must contain 1..={MAX_AUTHORIZED_CLIENTS} entries (got {})",
                document.clients.len()
            ));
        }

        let mut entries = Vec::with_capacity(document.clients.len());
        for item in document.clients {
            let key_id = decode_public_hex(&item.key_id, "client key id")?;
            let public_key = decode_public_hex(&item.ed25519_public_key, "Ed25519 public key")?;
            if key_id != derive_key_id(&public_key) {
                return Err(anyhow!(
                    "client key id {} is not derived from its Ed25519 public key",
                    hex::encode(key_id)
                ));
            }
            entries.push(AuthorizedClient {
                key_id,
                public_key,
                psk: decode_secret_hex(&item.psk, "client PSK")?,
            });
        }
        if !entries
            .windows(2)
            .all(|pair| pair[0].key_id < pair[1].key_id)
        {
            return Err(anyhow!(
                "client allowlist entries must be strictly sorted by derived key id"
            ));
        }
        Ok(Self { entries })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn revoke(&mut self, key_id: ClientKeyId) -> Result<()> {
        let index = self
            .entries
            .binary_search_by_key(&key_id, |entry| entry.key_id)
            .map_err(|_| anyhow!("client key id {} is not enrolled", hex::encode(key_id)))?;
        if self.entries.len() == 1 {
            return Err(anyhow!(
                "refusing to revoke the last client: server allowlist may not be empty"
            ));
        }
        self.entries.remove(index);
        Ok(())
    }

    fn serialized(&self) -> Result<Zeroizing<String>> {
        #[derive(Serialize)]
        struct AllowlistFile<'a> {
            schema: &'static str,
            clients: Vec<AllowlistEntry<'a>>,
        }
        #[derive(Serialize)]
        struct AllowlistEntry<'a> {
            key_id: String,
            ed25519_public_key: String,
            psk: &'a str,
        }

        let psk_hex = self
            .entries
            .iter()
            .map(|entry| Zeroizing::new(hex::encode(entry.psk.as_ref())))
            .collect::<Vec<_>>();
        let clients = self
            .entries
            .iter()
            .zip(psk_hex.iter())
            .map(|(entry, psk)| AllowlistEntry {
                key_id: hex::encode(entry.key_id),
                ed25519_public_key: hex::encode(entry.public_key),
                psk: psk.as_str(),
            })
            .collect();
        Ok(Zeroizing::new(serde_json::to_string_pretty(
            &AllowlistFile {
                schema: ALLOWLIST_SCHEMA,
                clients,
            },
        )?))
    }

    /// Explicit enrollment transaction. Both input artifacts must be root-owned
    /// mode 0600. A missing allowlist is created without replacement; an
    /// existing one is atomically replaced only after strict validation.
    pub fn enroll_root_owned(allowlist_path: &Path, enrollment_path: &Path) -> Result<ClientKeyId> {
        require_unix_production_private_files()?;
        Self::enroll_with_owner(allowlist_path, enrollment_path, PrivateFileOwner::Root)
    }

    /// Explicit no-TUN development enrollment with the same create-only,
    /// serialized, exact-0600 rules as production but effective-user ownership.
    pub fn enroll_development_user_owned(
        allowlist_path: &Path,
        enrollment_path: &Path,
    ) -> Result<ClientKeyId> {
        Self::enroll_with_owner(
            allowlist_path,
            enrollment_path,
            PrivateFileOwner::EffectiveUser,
        )
    }

    fn enroll_with_owner(
        allowlist_path: &Path,
        enrollment_path: &Path,
        owner: PrivateFileOwner,
    ) -> Result<ClientKeyId> {
        validate_trusted_parent(allowlist_path, owner)?;
        validate_trusted_parent(enrollment_path, owner)?;
        let _lease = AllowlistMutationLease::acquire(allowlist_path, owner)?;
        let enrollment = match owner {
            PrivateFileOwner::Root => ClientEnrollment::load_root_owned(enrollment_path)?,
            PrivateFileOwner::EffectiveUser => {
                ClientEnrollment::load_development_user_owned(enrollment_path)?
            }
        };
        let mut allowlist = match Self::load_with_owner(allowlist_path, owner) {
            Ok(allowlist) => allowlist,
            Err(error) if is_not_found(&error) => Self {
                entries: Vec::new(),
            },
            Err(error) => return Err(error),
        };
        if let Some(existing) = allowlist
            .entries
            .iter()
            .find(|entry| entry.key_id == enrollment.key_id)
        {
            // Provisioning retries after the durable allowlist commit but
            // before service activation must be safe. The exact same public
            // key + PSK is an idempotent success; a same-kid/different-secret
            // artifact remains a hard failure and never mutates the database.
            if existing.public_key == enrollment.public_key
                && existing.psk.as_ref() == enrollment.psk.as_ref()
            {
                return Ok(enrollment.key_id);
            }
            return Err(anyhow!(
                "client key id conflicts with an existing enrollment"
            ));
        }
        if allowlist.entries.len() >= MAX_AUTHORIZED_CLIENTS {
            return Err(anyhow!(
                "client allowlist already has the maximum {MAX_AUTHORIZED_CLIENTS} entries"
            ));
        }
        allowlist.entries.push(AuthorizedClient {
            key_id: enrollment.key_id,
            public_key: enrollment.public_key,
            psk: enrollment.psk,
        });
        allowlist.entries.sort_unstable_by_key(|entry| entry.key_id);
        let serialized = allowlist.serialized()?;
        if allowlist.entries.len() == 1 {
            match atomic_create_private_file(allowlist_path, serialized.as_bytes())? {
                CreatePrivateFileOutcome::Created => {}
                CreatePrivateFileOutcome::AlreadyExists => {
                    return Err(anyhow!(
                        "client allowlist appeared concurrently; retry enrollment"
                    ));
                }
            }
        } else {
            atomic_write_private_file(allowlist_path, serialized.as_bytes())?;
        }
        Ok(enrollment.key_id)
    }

    /// Explicit revocation transaction. Refuses to create an empty allowlist,
    /// because an empty/missing database is a daemon startup failure rather
    /// than an implicit open mode.
    pub fn revoke_root_owned(allowlist_path: &Path, key_id: ClientKeyId) -> Result<()> {
        require_unix_production_private_files()?;
        Self::revoke_with_owner(allowlist_path, key_id, PrivateFileOwner::Root)
    }

    pub fn revoke_development_user_owned(allowlist_path: &Path, key_id: ClientKeyId) -> Result<()> {
        Self::revoke_with_owner(allowlist_path, key_id, PrivateFileOwner::EffectiveUser)
    }

    fn revoke_with_owner(
        allowlist_path: &Path,
        key_id: ClientKeyId,
        owner: PrivateFileOwner,
    ) -> Result<()> {
        validate_trusted_parent(allowlist_path, owner)?;
        let _lease = AllowlistMutationLease::acquire(allowlist_path, owner)?;
        let mut allowlist = Self::load_with_owner(allowlist_path, owner)?;
        allowlist.revoke(key_id)?;
        let serialized = allowlist.serialized()?;
        atomic_write_private_file(allowlist_path, serialized.as_bytes())
    }
}

pub fn parse_client_key_id(encoded: &str) -> Result<ClientKeyId> {
    decode_public_hex(encoded, "client key id")
}

fn validate_canonical_hex(encoded: &str, bytes: usize, name: &str) -> Result<()> {
    if encoded.len() != bytes * 2
        || !encoded
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(anyhow!(
            "{name} must be exactly {} canonical lowercase hex characters",
            bytes * 2
        ));
    }
    Ok(())
}

fn decode_public_hex<const N: usize>(encoded: &str, name: &str) -> Result<[u8; N]> {
    validate_canonical_hex(encoded, N, name)?;
    let mut output = [0u8; N];
    hex::decode_to_slice(encoded, &mut output).with_context(|| format!("decode {name} hex"))?;
    Ok(output)
}

fn decode_secret_hex<const N: usize>(encoded: &str, name: &str) -> Result<Zeroizing<[u8; N]>> {
    validate_canonical_hex(encoded, N, name)?;
    let mut output = Zeroizing::new([0u8; N]);
    hex::decode_to_slice(encoded, output.as_mut()).with_context(|| format!("decode {name} hex"))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TempPath {
        path: std::path::PathBuf,
        directory: std::path::PathBuf,
    }

    impl TempPath {
        fn new(label: &str) -> Self {
            let nonce: [u8; 16] = crate::crypto::random_bytes();
            // Keep strict private-file fixtures below a trusted ancestor. Native
            // Linux/ARM64 matrices stage source under world-writable `/var/tmp`,
            // which production validation must reject even when the final test
            // directory is 0700. A unique HOME child exercises the intended file
            // checks without weakening ancestor validation.
            let directory = std::path::PathBuf::from(
                std::env::var_os("HOME").expect("HOME for client-auth test"),
            )
            .join(format!(
                ".shadowpipe-client-auth-{label}-{}-{}",
                std::process::id(),
                hex::encode(nonce)
            ));
            fs::create_dir_all(&directory).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self {
                path: directory.join("artifact.json"),
                directory,
            }
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            if let Some(file_name) = self.path.file_name() {
                let lock = self.path.with_file_name(format!(
                    ".{}.shadowpipe-mutation-lock",
                    file_name.to_string_lossy()
                ));
                let _ = fs::remove_file(lock);
            }
            let _ = fs::remove_dir(&self.directory);
        }
    }

    #[test]
    fn mutual_access_mac_known_answer_is_stable() {
        // Explicit magic keeps this vector deterministic even though normal
        // developer builds intentionally generate BUILD_MAGIC at compile time.
        let build_magic = 0x0102_0304;
        let psk = [0x11; CLIENT_PSK_LEN];
        let key_id = std::array::from_fn(|index| index as u8);
        let challenge = std::array::from_fn(|index| 0x20 + index as u8);
        let client_nonce = std::array::from_fn(|index| 0x40 + index as u8);

        let server_message = server_access_proof_message_with_magic(
            build_magic,
            &challenge,
            &key_id,
            CamouflageMode::H2Chunk,
            CarrierBinding::DirectTcp,
        );
        assert_eq!(
            hex::encode(&server_message),
            "736861646f77706970652d76332f7365727665722d6163636573732d70726f6f660003010203040100000102030405060708090a0b0c0d0e0f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        );
        let server_mac = hmac_sha256(&psk, &server_message);
        assert_eq!(
            hex::encode(server_mac),
            "0ad1172ae902cdb298bebcf81845c52e029462dfed724cae9dfe5f45e3c6ea5c"
        );

        let client_message = client_access_proof_message_with_magic(
            build_magic,
            &challenge,
            &server_mac,
            &key_id,
            &client_nonce,
            CamouflageMode::H2Chunk,
            CarrierBinding::DirectTcp,
        );
        assert_eq!(
            hex::encode(&client_message),
            "736861646f77706970652d76332f636c69656e742d6163636573732d70726f6f660003010203040100000102030405060708090a0b0c0d0e0f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0ad1172ae902cdb298bebcf81845c52e029462dfed724cae9dfe5f45e3c6ea5c404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        );
        assert_eq!(
            hex::encode(hmac_sha256(&psk, &client_message)),
            "227dd695fd3a5d233b7efb959eb94ea9293fa22c24b1fb51e997ae5736c205cc"
        );
    }

    #[test]
    fn known_and_unknown_access_paths_share_fixed_shape_and_fresh_dummy_response() {
        let first = ClientCredential::generate().unwrap();
        let second = ClientCredential::generate().unwrap();
        let third = ClientCredential::generate().unwrap();
        let unknown = ClientCredential::generate().unwrap();
        let allowlist = AuthorizedClients::from_credentials(&[&first, &second, &third]).unwrap();
        let challenge = [0x5A; SERVER_ACCESS_CHALLENGE_LEN];

        let (known_one, known_pending) = allowlist
            .begin_access(
                second.key_id(),
                &challenge,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
            )
            .unwrap();
        let (known_two, _) = allowlist
            .begin_access(
                second.key_id(),
                &challenge,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
            )
            .unwrap();
        let (unknown_one, unknown_pending) = allowlist
            .begin_access(
                unknown.key_id(),
                &challenge,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
            )
            .unwrap();
        let (unknown_two, _) = allowlist
            .begin_access(
                unknown.key_id(),
                &challenge,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
            )
            .unwrap();

        assert_eq!(known_one.encode().len(), SERVER_ACCESS_PROOF_LEN);
        assert_eq!(unknown_one.encode().len(), SERVER_ACCESS_PROOF_LEN);
        assert_eq!(known_one, known_two, "real PSK selection must be stable");
        assert_ne!(
            unknown_one, unknown_two,
            "unknown attempts must use independently sampled dummy PSKs"
        );

        let known_client_proof = second
            .verify_server_access_and_prove(
                &known_one,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
            )
            .unwrap();
        assert_eq!(
            known_pending
                .verify(
                    &known_one,
                    CamouflageMode::H2Chunk,
                    CarrierBinding::DirectTcp,
                    &known_client_proof,
                )
                .unwrap(),
            second.key_id()
        );
        assert!(unknown
            .verify_server_access_and_prove(
                &unknown_one,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
            )
            .is_err());
        assert_eq!(
            unknown_pending.verify(
                &unknown_one,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
                &known_client_proof,
            ),
            Err(AuthFailed)
        );
    }

    #[test]
    fn mutual_access_gate_is_fixed_width_framing_bound_and_replay_safe() {
        let credential = ClientCredential::generate().unwrap();
        let allowlist = credential.authorized_clients().unwrap();
        let challenge = [0x41; SERVER_ACCESS_CHALLENGE_LEN];
        let (server_proof, pending) = allowlist
            .begin_access(
                credential.key_id(),
                &challenge,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
            )
            .unwrap();
        let encoded_server = server_proof.encode();
        assert_eq!(encoded_server.len(), SERVER_ACCESS_PROOF_LEN);
        assert_eq!(
            ServerAccessProof::decode(&encoded_server).unwrap(),
            server_proof
        );
        assert_eq!(
            ServerAccessProof::decode(&encoded_server[..SERVER_ACCESS_PROOF_LEN - 1]),
            Err(AuthFailed)
        );

        let proof = credential
            .verify_server_access_and_prove(
                &server_proof,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
            )
            .unwrap();
        let encoded_client = proof.encode();
        assert_eq!(encoded_client.len(), CLIENT_ACCESS_PROOF_LEN);
        assert_eq!(ClientAccessProof::decode(&encoded_client).unwrap(), proof);
        assert_eq!(
            ClientAccessProof::decode(&encoded_client[..CLIENT_ACCESS_PROOF_LEN - 1]),
            Err(AuthFailed)
        );
        assert_eq!(
            pending
                .verify(
                    &server_proof,
                    CamouflageMode::H2Chunk,
                    CarrierBinding::DirectTcp,
                    &proof,
                )
                .unwrap(),
            credential.key_id()
        );

        let mut fresh_challenge = challenge;
        fresh_challenge[0] ^= 1;
        let (fresh_server_proof, fresh_pending) = allowlist
            .begin_access(
                credential.key_id(),
                &fresh_challenge,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
            )
            .unwrap();
        assert_eq!(
            fresh_pending.verify(
                &fresh_server_proof,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
                &proof,
            ),
            Err(AuthFailed),
            "a captured access proof must not replay against a fresh challenge"
        );

        assert!(matches!(
            credential.verify_server_access_and_prove(
                &server_proof,
                CamouflageMode::Raw,
                CarrierBinding::DirectTcp,
            ),
            Err(error) if error.downcast_ref::<AuthFailed>().is_some()
        ));
        assert_eq!(
            pending.verify(
                &server_proof,
                CamouflageMode::Raw,
                CarrierBinding::DirectTcp,
                &proof,
            ),
            Err(AuthFailed),
            "the claimed and observed carriers must agree before static-key disclosure"
        );

        let mut tampered_server_proof = server_proof;
        tampered_server_proof.psk_mac[0] ^= 1;
        assert!(matches!(
            credential
                .verify_server_access_and_prove(
                    &tampered_server_proof,
                    CamouflageMode::H2Chunk,
                    CarrierBinding::DirectTcp,
                ),
            Err(error) if error.downcast_ref::<AuthFailed>().is_some()
        ));

        // An unknown kid receives the same fixed-width server flight, but that
        // flight is authenticated under a fresh secret dummy PSK. Therefore an
        // unknown client cannot validate it and emits no client proof.
        let stranger = ClientCredential::generate().unwrap();
        let (dummy_server_proof, dummy_pending) = allowlist
            .begin_access(
                stranger.key_id(),
                &challenge,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
            )
            .unwrap();
        assert_eq!(dummy_server_proof.encode().len(), SERVER_ACCESS_PROOF_LEN);
        assert!(matches!(
            stranger.verify_server_access_and_prove(
                &dummy_server_proof,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
            ),
            Err(error) if error.downcast_ref::<AuthFailed>().is_some()
        ));
        assert_eq!(
            dummy_pending.verify(
                &dummy_server_proof,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
                &proof,
            ),
            Err(AuthFailed),
        );

        let mut tampered_nonce = proof;
        tampered_nonce.client_nonce[0] ^= 1;
        assert_eq!(
            pending.verify(
                &server_proof,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
                &tampered_nonce,
            ),
            Err(AuthFailed)
        );
        let mut tampered_mac = proof;
        tampered_mac.psk_mac[0] ^= 1;
        assert_eq!(
            pending.verify(
                &server_proof,
                CamouflageMode::H2Chunk,
                CarrierBinding::DirectTcp,
                &tampered_mac,
            ),
            Err(AuthFailed)
        );

        assert!(matches!(
            credential.verify_server_access_and_prove(
                &server_proof,
                CamouflageMode::H2Chunk,
                CarrierBinding::RealityTcp,
            ),
            Err(error) if error.downcast_ref::<AuthFailed>().is_some()
        ));
        assert_eq!(
            pending.verify(
                &server_proof,
                CamouflageMode::H2Chunk,
                CarrierBinding::RealityTcp,
                &proof,
            ),
            Err(AuthFailed),
            "a captured access flight must not cross outer carriers"
        );
    }

    #[test]
    fn access_identity_and_finished_identity_cannot_be_spliced() {
        let first = ClientCredential::generate().unwrap();
        let second = ClientCredential::generate().unwrap();
        let allowlist = AuthorizedClients::from_credentials(&[&first, &second]).unwrap();
        let transcript = [0xA7; 32];
        let second_finished = second.sign_finished(&transcript).unwrap();
        assert!(allowlist
            .verify_finished_for_key(&transcript, &second_finished, &second.key_id())
            .is_ok());
        assert!(matches!(
            allowlist.verify_finished_for_key(&transcript, &second_finished, &first.key_id()),
            Err(AuthFailed)
        ));
    }

    #[test]
    fn both_signature_and_psk_are_transcript_and_kid_bound() {
        let credential = ClientCredential::generate().unwrap();
        let allowlist = credential.authorized_clients().unwrap();
        let transcript = [0x11; 32];
        let finished = credential.sign_finished(&transcript).unwrap();
        allowlist.verify_finished(&transcript, &finished).unwrap();

        let mut wrong_signature = finished;
        wrong_signature.signature[0] ^= 1;
        assert!(matches!(
            allowlist.verify_finished(&transcript, &wrong_signature),
            Err(AuthFailed)
        ));
        let mut wrong_psk = finished;
        wrong_psk.psk_mac[0] ^= 1;
        assert!(matches!(
            allowlist.verify_finished(&transcript, &wrong_psk),
            Err(AuthFailed)
        ));
        assert!(matches!(
            allowlist.verify_finished(&[0x12; 32], &finished),
            Err(AuthFailed)
        ));
        let mut wrong_kid = finished;
        wrong_kid.key_id[0] ^= 1;
        assert!(matches!(
            allowlist.verify_finished(&transcript, &wrong_kid),
            Err(AuthFailed)
        ));
    }

    #[test]
    fn unknown_and_revoked_clients_have_the_same_generic_failure() {
        let authorized = ClientCredential::generate().unwrap();
        let unknown = ClientCredential::generate().unwrap();
        let transcript = [0x42; 32];
        let proof = unknown.sign_finished(&transcript).unwrap();
        let live = authorized.authorized_clients().unwrap();
        let revoked = ClientCredential::generate()
            .unwrap()
            .authorized_clients()
            .unwrap();
        assert!(matches!(
            live.verify_finished(&transcript, &proof),
            Err(AuthFailed)
        ));
        assert!(matches!(
            revoked.verify_finished(&transcript, &proof),
            Err(AuthFailed)
        ));
    }

    #[test]
    fn role_domain_separation_rejects_server_domain_as_client_proof() {
        let credential = ClientCredential::generate().unwrap();
        let allowlist = credential.authorized_clients().unwrap();
        let transcript = [0x31; 32];
        let wrong_message = proof_message(
            SERVER_PROOF_DOMAIN,
            CLIENT_FINISHED_FORMAT,
            &credential.key_id,
            &transcript,
        );
        let pair = Ed25519KeyPair::from_seed_unchecked(credential.seed.as_ref()).unwrap();
        let signature = pair.sign(&wrong_message).as_ref().try_into().unwrap();
        let finished = ClientFinished {
            key_id: credential.key_id,
            signature,
            psk_mac: hmac_sha256(&credential.psk, &wrong_message),
        };
        assert!(matches!(
            allowlist.verify_finished(&transcript, &finished),
            Err(AuthFailed)
        ));
    }

    #[test]
    fn fixed_finished_formats_are_strict() {
        let credential = ClientCredential::generate().unwrap();
        let finished = credential.sign_finished(&[0x22; 32]).unwrap();
        assert_eq!(
            ClientFinished::decode(&finished.encode()).unwrap(),
            finished
        );
        let mut wrong_format = finished.encode();
        wrong_format[0] = 2;
        assert_eq!(ClientFinished::decode(&wrong_format), Err(AuthFailed));
        assert_eq!(
            ClientFinished::decode(&wrong_format[..wrong_format.len() - 1]),
            Err(AuthFailed)
        );
    }

    #[test]
    fn private_credential_create_is_non_overwriting_and_round_trips() {
        let path = TempPath::new("credential");
        let credential = ClientCredential::create(&path.path).unwrap();
        let loaded = ClientCredential::load(&path.path).unwrap();
        assert_eq!(loaded.key_id(), credential.key_id());
        assert_eq!(loaded.public_key(), credential.public_key());
        assert_eq!(loaded.psk(), credential.psk());
        assert!(ClientCredential::create(&path.path).is_err());
    }

    #[test]
    fn credential_rejects_noncanonical_hex_and_wrong_permissions() {
        let path = TempPath::new("canonical");
        let credential = ClientCredential::create(&path.path).unwrap();
        let mut document: serde_json::Value = serde_json::from_str(
            ClientCredential::load(&path.path)
                .unwrap()
                .serialized()
                .unwrap()
                .as_str(),
        )
        .unwrap();
        document["key_id"] =
            serde_json::Value::String(hex::encode(credential.key_id).to_uppercase());
        atomic_write_private_file(
            &path.path,
            serde_json::to_string(&document).unwrap().as_bytes(),
        )
        .unwrap();
        assert!(ClientCredential::load(&path.path).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path.path, fs::Permissions::from_mode(0o640)).unwrap();
            assert!(ClientCredential::load(&path.path).is_err());
        }
    }

    #[test]
    fn allowlist_serialization_is_sorted_bounded_and_strict() {
        let first = ClientCredential::generate().unwrap();
        let second = ClientCredential::generate().unwrap();
        let allowlist = AuthorizedClients::from_credentials(&[&second, &first]).unwrap();
        let serialized = allowlist.serialized().unwrap();
        let loaded = AuthorizedClients::parse(serialized.as_str()).unwrap();
        assert_eq!(loaded.len(), 2);

        let duplicate = AuthorizedClients::from_credentials(&[&first, &first]);
        assert!(duplicate.is_err());
        assert!(AuthorizedClients::from_credentials(&[]).is_err());
    }

    #[test]
    fn overlap_then_revoke_removes_only_the_selected_device() {
        let old = ClientCredential::generate().unwrap();
        let next = ClientCredential::generate().unwrap();
        let transcript = [0x58; 32];
        let mut allowlist = AuthorizedClients::from_credentials(&[&old, &next]).unwrap();
        allowlist
            .verify_finished(&transcript, &old.sign_finished(&transcript).unwrap())
            .unwrap();
        allowlist
            .verify_finished(&transcript, &next.sign_finished(&transcript).unwrap())
            .unwrap();

        allowlist.revoke(old.key_id()).unwrap();
        assert!(matches!(
            allowlist.verify_finished(&transcript, &old.sign_finished(&transcript).unwrap()),
            Err(AuthFailed)
        ));
        allowlist
            .verify_finished(&transcript, &next.sign_finished(&transcript).unwrap())
            .unwrap();
        assert!(allowlist.revoke(next.key_id()).is_err());
    }

    #[test]
    fn development_file_enrollment_and_revocation_are_strict_transactions() {
        let first_credential_path = TempPath::new("dev-credential-first");
        let first_enrollment_path = TempPath::new("dev-enrollment-first");
        let second_credential_path = TempPath::new("dev-credential-second");
        let second_enrollment_path = TempPath::new("dev-enrollment-second");
        let allowlist_path = TempPath::new("dev-allowlist");

        let first = ClientCredential::create(&first_credential_path.path).unwrap();
        first.write_enrollment(&first_enrollment_path.path).unwrap();
        let second = ClientCredential::create(&second_credential_path.path).unwrap();
        second
            .write_enrollment(&second_enrollment_path.path)
            .unwrap();

        let first_id = AuthorizedClients::enroll_development_user_owned(
            &allowlist_path.path,
            &first_enrollment_path.path,
        )
        .unwrap();
        assert_eq!(first_id, first.key_id());
        let retry_id = AuthorizedClients::enroll_development_user_owned(
            &allowlist_path.path,
            &first_enrollment_path.path,
        )
        .unwrap();
        assert_eq!(retry_id, first_id);
        assert_eq!(
            AuthorizedClients::load_development_user_owned(&allowlist_path.path)
                .unwrap()
                .len(),
            1
        );
        let second_id = AuthorizedClients::enroll_development_user_owned(
            &allowlist_path.path,
            &second_enrollment_path.path,
        )
        .unwrap();
        assert_eq!(second_id, second.key_id());
        assert_eq!(
            AuthorizedClients::load_development_user_owned(&allowlist_path.path)
                .unwrap()
                .len(),
            2
        );

        AuthorizedClients::revoke_development_user_owned(&allowlist_path.path, first_id).unwrap();
        let remaining =
            AuthorizedClients::load_development_user_owned(&allowlist_path.path).unwrap();
        assert_eq!(remaining.len(), 1);
        assert!(
            AuthorizedClients::revoke_development_user_owned(&allowlist_path.path, second_id)
                .is_err()
        );
    }

    #[test]
    fn concurrent_allowlist_mutation_fails_busy_instead_of_lost_update() {
        let path = TempPath::new("mutation-lock");
        let first =
            AllowlistMutationLease::acquire(&path.path, PrivateFileOwner::EffectiveUser).unwrap();
        let error =
            match AllowlistMutationLease::acquire(&path.path, PrivateFileOwner::EffectiveUser) {
                Ok(_) => panic!("second mutation lease unexpectedly succeeded"),
                Err(error) => error,
            };
        assert!(
            error.to_string().contains("already in progress"),
            "unexpected error: {error:#}"
        );
        drop(first);
        AllowlistMutationLease::acquire(&path.path, PrivateFileOwner::EffectiveUser).unwrap();
    }

    #[test]
    fn server_finished_is_bound_to_client_finished() {
        let credential = ClientCredential::generate().unwrap();
        let allowlist = credential.authorized_clients().unwrap();
        let transcript = [0x77; 32];
        let client = credential.sign_finished(&transcript).unwrap().encode();
        let parsed = ClientFinished::decode(&client).unwrap();
        let verified = allowlist.verify_finished(&transcript, &parsed).unwrap();
        let server = AuthorizedClients::make_server_finished(&verified, &transcript, &client);
        credential
            .verify_server_finished(&transcript, &client, &server)
            .unwrap();
        let mut tampered = client;
        tampered[CLIENT_FINISHED_LEN - 1] ^= 1;
        assert_eq!(
            credential.verify_server_finished(&transcript, &tampered, &server),
            Err(AuthFailed)
        );
    }
}
