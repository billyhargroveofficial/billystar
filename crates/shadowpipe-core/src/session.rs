use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::client_auth::{
    AuthFailed, AuthorizedClients, ClientAccessProof, ClientCredential, ClientFinished,
    ClientKeyId, ServerAccessProof, ServerFinished, CLIENT_ACCESS_HELLO_LEN,
    CLIENT_ACCESS_PROOF_LEN, CLIENT_FINISHED_LEN, SERVER_ACCESS_PROOF_LEN, SERVER_FINISHED_LEN,
};
use crate::crypto::{
    ct_eq, decapsulate_mlkem, derive_application_traffic_keys, derive_handshake_traffic_keys,
    encapsulate_mlkem, mlkem_ciphertext_from_bytes, mlkem_derived_public_bytes, mlkem_fingerprint,
    mlkem_public_bytes, mlkem_public_from_bytes, mlkem_secret_from_storage_bytes,
    mlkem_secret_storage_bytes, random_bytes, random_session_id, x25519_ephemeral_shared,
    x25519_public_from_bytes, AeadRx, AeadSession, AeadTx, MlkemKeypair, X25519Keypair,
};
use crate::proto::{
    random_padding, read_client_hello, read_frame, read_mlkem_public, read_server_hello,
    write_client_hello, write_frame, write_mlkem_public, write_server_hello, CamouflageMode,
    CarrierBinding, ClientHello, Frame, FrameFlags, PaddingProfile, ServerHello, MAX_FRAME_PAYLOAD,
    MAX_PADDING,
};
use crate::volume_guard::estimate_frame_wire_bytes;
use crate::{BUILD_MAGIC, PROTO_VERSION};

pub struct ServerState {
    mlkem: MlkemKeypair,
}

struct PendingPrivateFile {
    path: PathBuf,
    published: bool,
}

impl PendingPrivateFile {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            published: false,
        }
    }

    fn mark_published(&mut self) {
        self.published = true;
    }
}

impl Drop for PendingPrivateFile {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreatePrivateFileOutcome {
    Created,
    AlreadyExists,
}

fn private_file_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

const MAX_PRIVATE_KEY_FILE_BYTES: u64 = 16 * 1024;

#[derive(Clone, Copy)]
pub(crate) enum PrivateFileOwner {
    EffectiveUser,
    Root,
}

#[cfg(unix)]
fn ensure_private_file_owner(path: &Path, owner_uid: u32, expected_uid: u32) -> Result<()> {
    if owner_uid != expected_uid {
        return Err(anyhow!(
            "private-key file {} is owned by UID {}; expected UID {}",
            path.display(),
            owner_uid,
            expected_uid
        ));
    }
    Ok(())
}

/// Open and read a private-key file without following a final symlink on Unix.
/// Existing files must be regular files, owned by the process's effective Unix
/// user, and must not grant any group/other permission bits. Reads are bounded
/// so a hostile pathname cannot cause an unbounded allocation before JSON/hex
/// validation.
pub(crate) fn read_private_file_to_string(path: &Path) -> Result<Zeroizing<String>> {
    read_private_file_to_string_bounded(
        path,
        MAX_PRIVATE_KEY_FILE_BYTES,
        PrivateFileOwner::EffectiveUser,
        false,
    )
}

/// Strict variant used for client credentials and authorization databases.
/// The ownership/mode checks are performed on the already-open descriptor, not
/// by a second pathname lookup, and the final component is opened O_NOFOLLOW.
pub(crate) fn read_private_file_to_string_bounded(
    path: &Path,
    maximum_bytes: u64,
    _expected_owner: PrivateFileOwner,
    _require_mode_0600: bool,
) -> Result<Zeroizing<String>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let input = options
        .open(path)
        .with_context(|| format!("open private-key file {}", path.display()))?;
    let metadata = input
        .metadata()
        .with_context(|| format!("stat private-key file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "private-key path is not a regular file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        // SAFETY: `geteuid` takes no arguments and has no preconditions.
        let effective_uid = unsafe { libc::geteuid() };
        let expected_uid = match _expected_owner {
            PrivateFileOwner::EffectiveUser => effective_uid,
            PrivateFileOwner::Root => 0,
        };
        ensure_private_file_owner(path, metadata.uid(), expected_uid)?;
        let mode = metadata.permissions().mode() & 0o777;
        if _require_mode_0600 && mode != 0o600 {
            return Err(anyhow!(
                "private-key file {} has mode {:04o}; expected exactly 0600",
                path.display(),
                mode
            ));
        }
        if _require_mode_0600 && metadata.nlink() != 1 {
            return Err(anyhow!(
                "private-key file {} has {} hard links; expected exactly one",
                path.display(),
                metadata.nlink()
            ));
        }
        if !_require_mode_0600 && mode & 0o077 != 0 {
            return Err(anyhow!(
                "private-key file {} has unsafe group/other permissions {:04o}; expected no group/other bits",
                path.display(),
                mode
            ));
        }
    }
    if metadata.len() > maximum_bytes {
        return Err(anyhow!(
            "private-key file {} is too large: {} bytes (maximum {})",
            path.display(),
            metadata.len(),
            maximum_bytes
        ));
    }

    let mut contents = Zeroizing::new(String::with_capacity(metadata.len() as usize));
    input
        .take(maximum_bytes + 1)
        .read_to_string(&mut contents)
        .with_context(|| format!("read private-key file {}", path.display()))?;
    if contents.len() as u64 > maximum_bytes {
        return Err(anyhow!(
            "private-key file {} grew beyond the {} byte limit while reading",
            path.display(),
            maximum_bytes
        ));
    }
    Ok(contents)
}

fn stage_private_file(path: &Path, contents: &[u8]) -> Result<PendingPrivateFile> {
    let parent = private_file_parent(path);
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("private-key path has no file name: {}", path.display()))?
        .to_string_lossy();

    let (mut output, temp_path) = (0..16)
        .find_map(|_| {
            let nonce: [u8; 16] = random_bytes();
            let temp_path = parent.join(format!(
                ".{file_name}.shadowpipe-{}-{}.tmp",
                std::process::id(),
                hex::encode(nonce)
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&temp_path) {
                Ok(output) => Some(Ok((output, temp_path))),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error)),
            }
        })
        .transpose()
        .with_context(|| format!("create private-key temp file beside {}", path.display()))?
        .ok_or_else(|| anyhow!("could not allocate a unique private-key temp file"))?;
    let pending = PendingPrivateFile::new(temp_path.clone());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        output
            .set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", temp_path.display()))?;
    }
    output
        .write_all(contents)
        .with_context(|| format!("write private-key temp file {}", temp_path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync private-key temp file {}", temp_path.display()))?;
    drop(output);
    Ok(pending)
}

fn sync_private_file_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let parent = private_file_parent(path);
        let directory = fs::File::open(parent)
            .with_context(|| format!("open private-key directory {}", parent.display()))?;
        directory
            .sync_all()
            .with_context(|| format!("sync private-key directory {}", parent.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Replace a private key file without ever opening the final pathname for a
/// write. The same-directory staged file is synced before the atomic rename, so
/// explicit key rotation replaces the old complete identity with the new
/// complete identity and replaces, rather than follows, a final symlink.
pub(crate) fn atomic_write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut pending = stage_private_file(path, contents)?;
    // Same-directory rename is an atomic replacement on the Unix production
    // targets and replaces a final symlink itself rather than following it.
    fs::rename(&pending.path, path).with_context(|| {
        format!(
            "atomically publish private-key file {} as {}",
            pending.path.display(),
            path.display()
        )
    })?;
    pending.mark_published();
    sync_private_file_directory(path)
}

/// Create a private key file only if no pathname already occupies the final
/// name. Hard-linking a fully synced same-directory temp is the publication
/// linearization point: exactly one first-run generator wins, and losers never
/// overwrite or follow the winner.
pub(crate) fn atomic_create_private_file(
    path: &Path,
    contents: &[u8],
) -> Result<CreatePrivateFileOutcome> {
    let mut pending = stage_private_file(path, contents)?;
    match fs::hard_link(&pending.path, path) {
        Ok(()) => {
            fs::remove_file(&pending.path).with_context(|| {
                format!(
                    "remove linked private-key temp file {}",
                    pending.path.display()
                )
            })?;
            pending.mark_published();
            sync_private_file_directory(path)?;
            Ok(CreatePrivateFileOutcome::Created)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(&pending.path).with_context(|| {
                format!(
                    "remove losing private-key temp file {}",
                    pending.path.display()
                )
            })?;
            pending.mark_published();
            sync_private_file_directory(path)?;
            Ok(CreatePrivateFileOutcome::AlreadyExists)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "publish private-key file {} without replacing {}",
                pending.path.display(),
                path.display()
            )
        }),
    }
}

pub(crate) fn is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}

impl ServerState {
    pub fn generate() -> Self {
        Self {
            mlkem: MlkemKeypair::generate(),
        }
    }

    pub fn load_or_generate(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(state) => return Ok(state),
            Err(error) if is_not_found(&error) => {}
            Err(error) => return Err(error),
        }

        let candidate = Self::generate();
        let serialized = candidate.serialized_key_file()?;
        for _ in 0..16 {
            match atomic_create_private_file(path, serialized.as_bytes())? {
                CreatePrivateFileOutcome::Created => return Ok(candidate),
                CreatePrivateFileOutcome::AlreadyExists => match Self::load(path) {
                    Ok(winner) => return Ok(winner),
                    // A concurrent explicit rotation/removal can briefly win the
                    // name and remove it before this loser loads. Retry without
                    // ever replacing a pathname that does exist.
                    Err(error) if is_not_found(&error) => continue,
                    Err(error) => return Err(error),
                },
            }
        }
        Err(anyhow!(
            "private-key path kept disappearing during first-run generation: {}",
            path.display()
        ))
    }

    fn serialized_key_file(&self) -> Result<Zeroizing<String>> {
        #[derive(Serialize)]
        struct KeyFile<'a> {
            mlkem_public: String,
            mlkem_secret: &'a str,
        }
        let public_bytes = mlkem_public_bytes(&self.mlkem.public);
        let derived_public = mlkem_derived_public_bytes(&self.mlkem.secret);
        if !ct_eq(&public_bytes, &derived_public) {
            return Err(anyhow!(
                "refusing to save mismatched ML-KEM public and secret keys"
            ));
        }
        let secret_bytes = mlkem_secret_storage_bytes(&self.mlkem.secret);
        let secret_hex = Zeroizing::new(hex::encode(secret_bytes.as_slice()));
        let file = KeyFile {
            mlkem_public: hex::encode(public_bytes),
            mlkem_secret: secret_hex.as_str(),
        };
        Ok(Zeroizing::new(serde_json::to_string_pretty(&file)?))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let serialized = self.serialized_key_file()?;
        atomic_write_private_file(path, serialized.as_bytes())
    }

    fn load(path: &Path) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct KeyFile {
            mlkem_public: String,
            mlkem_secret: Zeroizing<String>,
        }
        let json = read_private_file_to_string(path)?;
        let file: KeyFile = serde_json::from_str(json.as_str())?;
        let pk_bytes = hex::decode(&file.mlkem_public).context("decode public key")?;
        let sk_bytes =
            Zeroizing::new(hex::decode(file.mlkem_secret.as_str()).context("decode secret key")?);
        let public = mlkem_public_from_bytes(&pk_bytes).context("invalid public key")?;
        let secret = mlkem_secret_from_storage_bytes(&sk_bytes).context("invalid secret key")?;
        let derived_public = mlkem_derived_public_bytes(&secret);
        if !ct_eq(&pk_bytes, &derived_public) {
            return Err(anyhow!(
                "ML-KEM public key does not match the stored secret key"
            ));
        }
        Ok(Self {
            mlkem: MlkemKeypair { public, secret },
        })
    }

    pub fn mlkem_public_bytes(&self) -> Vec<u8> {
        mlkem_public_bytes(&self.mlkem.public)
    }

    /// SHA-256 identity fingerprint of this server's static ML-KEM public key.
    /// Clients pin this (`--server-fp`) to authenticate the server (anti-MITM).
    pub fn fingerprint(&self) -> [u8; 32] {
        mlkem_fingerprint(&mlkem_public_bytes(&self.mlkem.public))
    }
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub camouflage: CamouflageMode,
    pub padding_profile: PaddingProfile,
    /// Required SHA-256 fingerprint of the server's static ML-KEM public key.
    /// The wire key is verified against it in constant time before the client
    /// encapsulates any secret or sends any application-controlled bytes.
    pub server_fingerprint: [u8; 32],
    /// Mandatory per-device Ed25519 + independent 256-bit PSK credential.  It
    /// has no default and is never serialized into an endpoint or URI.
    pub client_credential: Arc<ClientCredential>,
}

/// Maximum number of concurrently trusted server identities during a bounded
/// ML-KEM key rotation.  Three slots cover one active key plus an old and a new
/// overlap key without turning the pin set into an unbounded trust store.
pub const MAX_SERVER_PINS: usize = 3;

/// A small, immutable set of authenticated ML-KEM server fingerprints.
///
/// The number of active pins is public policy metadata.  Matching nevertheless
/// evaluates every fixed slot and never exits on the first matching pin, so the
/// selected server identity is not exposed through an application-level timing
/// branch before encapsulation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerPins {
    slots: [[u8; 32]; MAX_SERVER_PINS],
    len: u8,
}

impl ServerPins {
    pub fn single(pin: [u8; 32]) -> Self {
        let mut slots = [[0u8; 32]; MAX_SERVER_PINS];
        slots[0] = pin;
        Self { slots, len: 1 }
    }

    pub fn new(pins: &[[u8; 32]]) -> Result<Self> {
        if pins.is_empty() || pins.len() > MAX_SERVER_PINS {
            return Err(anyhow!(
                "server pin set must contain 1..={MAX_SERVER_PINS} fingerprints (got {})",
                pins.len()
            ));
        }
        for (index, pin) in pins.iter().enumerate() {
            if pins[..index].iter().any(|existing| ct_eq(existing, pin)) {
                return Err(anyhow!(
                    "server pin set contains duplicate fingerprint {}",
                    hex::encode(pin)
                ));
            }
        }

        let mut slots = [[0u8; 32]; MAX_SERVER_PINS];
        slots[..pins.len()].copy_from_slice(pins);
        Ok(Self {
            slots,
            len: pins.len() as u8,
        })
    }

    pub fn as_slice(&self) -> &[[u8; 32]] {
        &self.slots[..usize::from(self.len)]
    }

    pub fn matches(&self, fingerprint: &[u8; 32]) -> bool {
        let mut matched = 0u8;
        for (index, pin) in self.slots.iter().enumerate() {
            let equal = u8::from(ct_eq(fingerprint, pin));
            let active = u8::from(index < usize::from(self.len));
            matched |= equal & active;
        }
        matched != 0
    }
}

impl ClientConfig {
    pub fn pinned(server_fingerprint: [u8; 32], client_credential: Arc<ClientCredential>) -> Self {
        Self {
            camouflage: CamouflageMode::Raw,
            padding_profile: PaddingProfile::Balanced,
            server_fingerprint,
            client_credential,
        }
    }
}

const V3_SUITE: &[u8] = b"ML-KEM-768+X25519+MUTUAL-PSK-ACCESS-HMAC-SHA256+Ed25519+HMAC-SHA256+HKDF-SHA256+ChaCha20Poly1305";
const TRANSCRIPT_DOMAIN: &[u8] = b"shadowpipe-v3/canonical-handshake-transcript\0";
const FINISHED_TRANSCRIPT_DOMAIN: &[u8] = b"shadowpipe-v3/finished-transcript\0";
const CLIENT_FINISHED_AAD_DOMAIN: &[u8] = b"shadowpipe-v3/client-finished-record\0";
const SERVER_FINISHED_AAD_DOMAIN: &[u8] = b"shadowpipe-v3/server-finished-record\0";
const FRAME_AAD_DOMAIN: &[u8] = b"shadowpipe-v3/application-frame\0";
const CHACHA20_POLY1305_TAG_LEN: usize = 16;
const CLIENT_FINISHED_CIPHERTEXT_LEN: usize = CLIENT_FINISHED_LEN + CHACHA20_POLY1305_TAG_LEN;
const SERVER_FINISHED_CIPHERTEXT_LEN: usize = SERVER_FINISHED_LEN + CHACHA20_POLY1305_TAG_LEN;

fn append_transcript_field(transcript: &mut Vec<u8>, tag: u8, value: &[u8]) {
    transcript.push(tag);
    transcript.extend_from_slice(&(value.len() as u32).to_be_bytes());
    transcript.extend_from_slice(value);
}

/// SHA-256 commitment to the one canonical v3 handshake encoding.  Unique
/// one-byte tags plus fixed-width big-endian lengths make every boundary
/// unambiguous.  Roles, protocol/build version, suite, server public key,
/// ML-KEM ciphertext, both randoms, both X25519 shares, session id, and every
/// negotiation byte are committed before either encrypted Finished proof is
/// constructed.
fn pre_finished_transcript(
    access_hello: &[u8; CLIENT_ACCESS_HELLO_LEN],
    server_access_proof: &[u8; SERVER_ACCESS_PROOF_LEN],
    client_access_proof: &[u8; CLIENT_ACCESS_PROOF_LEN],
    server_pk: &[u8],
    client_hello: &ClientHello,
    server_hello: &ServerHello,
    carrier_binding: CarrierBinding,
) -> [u8; 32] {
    pre_finished_transcript_with_magic(
        BUILD_MAGIC,
        access_hello,
        server_access_proof,
        client_access_proof,
        server_pk,
        TranscriptCarrierContext {
            client_hello,
            server_hello,
            carrier_binding,
        },
    )
}

#[derive(Clone, Copy)]
struct TranscriptCarrierContext<'a> {
    client_hello: &'a ClientHello,
    server_hello: &'a ServerHello,
    carrier_binding: CarrierBinding,
}

fn pre_finished_transcript_with_magic(
    build_magic: u32,
    access_hello: &[u8; CLIENT_ACCESS_HELLO_LEN],
    server_access_proof: &[u8; SERVER_ACCESS_PROOF_LEN],
    client_access_proof: &[u8; CLIENT_ACCESS_PROOF_LEN],
    server_pk: &[u8],
    context: TranscriptCarrierContext<'_>,
) -> [u8; 32] {
    let TranscriptCarrierContext {
        client_hello,
        server_hello,
        carrier_binding,
    } = context;
    let mut canonical = Vec::with_capacity(TRANSCRIPT_DOMAIN.len() + server_pk.len() + 1400);
    canonical.extend_from_slice(TRANSCRIPT_DOMAIN);
    append_transcript_field(&mut canonical, 1, &[PROTO_VERSION]);
    append_transcript_field(&mut canonical, 2, b"client");
    append_transcript_field(&mut canonical, 3, b"server");
    append_transcript_field(&mut canonical, 4, &build_magic.to_be_bytes());
    append_transcript_field(&mut canonical, 5, V3_SUITE);
    append_transcript_field(&mut canonical, 6, server_pk);
    append_transcript_field(&mut canonical, 7, &client_hello.mlkem_ciphertext);
    append_transcript_field(&mut canonical, 8, &client_hello.client_random);
    append_transcript_field(&mut canonical, 9, &server_hello.server_random);
    append_transcript_field(&mut canonical, 10, &client_hello.x25519_public);
    append_transcript_field(&mut canonical, 11, &server_hello.x25519_public);
    append_transcript_field(&mut canonical, 12, &server_hello.session_id);
    append_transcript_field(&mut canonical, 13, &client_hello.magic.to_be_bytes());
    append_transcript_field(&mut canonical, 14, &[client_hello.version]);
    append_transcript_field(&mut canonical, 15, &[client_hello.camouflage as u8]);
    append_transcript_field(&mut canonical, 16, &[client_hello.padding_profile as u8]);
    append_transcript_field(&mut canonical, 17, access_hello);
    append_transcript_field(&mut canonical, 18, server_access_proof);
    append_transcript_field(&mut canonical, 19, client_access_proof);
    append_transcript_field(&mut canonical, 20, &[carrier_binding as u8]);
    let mut h = Sha256::new();
    h.update(&canonical);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn finished_transcript(
    pre_finished: &[u8; 32],
    client_finished: &[u8; CLIENT_FINISHED_LEN],
    server_finished: &[u8; SERVER_FINISHED_LEN],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(FINISHED_TRANSCRIPT_DOMAIN);
    h.update(pre_finished);
    h.update((client_finished.len() as u16).to_be_bytes());
    h.update(client_finished);
    h.update((server_finished.len() as u16).to_be_bytes());
    h.update(server_finished);
    h.finalize().into()
}

fn finished_aad(domain: &[u8], pre_finished: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain.len() + pre_finished.len());
    aad.extend_from_slice(domain);
    aad.extend_from_slice(pre_finished);
    aad
}

async fn write_fixed_finished<S>(stream: &mut S, ciphertext: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(ciphertext).await?;
    stream.flush().await?;
    Ok(())
}

async fn write_access_hello<S>(stream: &mut S, key_id: &[u8; CLIENT_ACCESS_HELLO_LEN]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(key_id).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_access_hello<S>(stream: &mut S) -> Result<[u8; CLIENT_ACCESS_HELLO_LEN]>
where
    S: AsyncRead + Unpin,
{
    let mut key_id = [0u8; CLIENT_ACCESS_HELLO_LEN];
    stream.read_exact(&mut key_id).await?;
    Ok(key_id)
}

async fn write_server_access_proof<S>(
    stream: &mut S,
    proof: &[u8; SERVER_ACCESS_PROOF_LEN],
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(proof).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_server_access_proof<S>(stream: &mut S) -> Result<[u8; SERVER_ACCESS_PROOF_LEN]>
where
    S: AsyncRead + Unpin,
{
    let mut proof = [0u8; SERVER_ACCESS_PROOF_LEN];
    stream.read_exact(&mut proof).await?;
    Ok(proof)
}

async fn write_access_proof<S>(stream: &mut S, proof: &[u8; CLIENT_ACCESS_PROOF_LEN]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(proof).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_access_proof<S>(stream: &mut S) -> Result<[u8; CLIENT_ACCESS_PROOF_LEN]>
where
    S: AsyncRead + Unpin,
{
    let mut proof = [0u8; CLIENT_ACCESS_PROOF_LEN];
    stream.read_exact(&mut proof).await?;
    Ok(proof)
}

async fn read_fixed_finished<S, const N: usize>(stream: &mut S) -> Result<[u8; N]>
where
    S: AsyncRead + Unpin,
{
    let mut ciphertext = [0u8; N];
    stream.read_exact(&mut ciphertext).await?;
    Ok(ciphertext)
}

/// Bind every cleartext application-record field into the AEAD tag. Padding is
/// deliberately outside the ciphertext for traffic shaping, but it is not
/// outside integrity: an on-path watermark that changes its length or bytes is
/// terminal. Committing the ciphertext length also authenticates the canonical
/// frame boundary instead of relying only on the parser's allocation bound.
fn frame_aad(stream_id: u32, flags: FrameFlags, ciphertext_len: usize, padding: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FRAME_AAD_DOMAIN.len() + 4 + 1 + 8 + 4 + padding.len());
    aad.extend_from_slice(FRAME_AAD_DOMAIN);
    aad.extend_from_slice(&stream_id.to_be_bytes());
    aad.push(flags.bits());
    aad.extend_from_slice(&(ciphertext_len as u64).to_be_bytes());
    aad.extend_from_slice(&(padding.len() as u32).to_be_bytes());
    aad.extend_from_slice(padding);
    aad
}

struct PreparedOutboundFrame {
    flags: FrameFlags,
    padding: Vec<u8>,
    wire_padding: Vec<u8>,
    ciphertext_len: usize,
}

/// Validate all caller-controlled frame metadata before consuming an AEAD
/// nonce. PADDING is owned exclusively by this layer; accepting it from a
/// caller when random padding happens to be empty would put a PADDING flag on
/// the wire without its mandatory u16 length and desynchronize the peer.
fn prepare_outbound_frame(
    padding_profile: PaddingProfile,
    flags: FrameFlags,
    plaintext_len: usize,
) -> Result<PreparedOutboundFrame> {
    anyhow::ensure!(
        matches!(
            flags.bits(),
            bits if bits == FrameFlags::DATA.bits()
                || bits == FrameFlags::FIN.bits()
                || bits == FrameFlags::PING.bits()
        ),
        "outbound application frame requires exactly one of DATA, FIN, or PING; caller-supplied PADDING and unknown bits are forbidden"
    );
    let ciphertext_len = plaintext_len
        .checked_add(CHACHA20_POLY1305_TAG_LEN)
        .ok_or_else(|| anyhow!("application frame ciphertext length overflow"))?;
    anyhow::ensure!(
        ciphertext_len <= MAX_FRAME_PAYLOAD,
        "application frame ciphertext length {ciphertext_len} exceeds the {MAX_FRAME_PAYLOAD}-byte receiver bound"
    );

    let padding = random_padding(padding_profile)?;
    anyhow::ensure!(padding.len() <= MAX_PADDING, "padding too large");
    let flags = if padding.is_empty() {
        flags
    } else {
        FrameFlags::from_bits(flags.bits() | FrameFlags::PADDING.bits())
    };
    let mut wire_padding = Vec::new();
    if !padding.is_empty() {
        wire_padding.extend_from_slice(&(padding.len() as u16).to_be_bytes());
        wire_padding.extend_from_slice(&padding);
    }
    Ok(PreparedOutboundFrame {
        flags,
        padding,
        wire_padding,
        ciphertext_len,
    })
}

/// The only application-traffic session type exposed by the library.  It can
/// only be constructed after the v3 ClientFinished and ServerFinished exchange
/// succeeds, and carries the authorized device's pseudonymous key id.
pub struct AuthenticatedSession {
    aead: AeadSession,
    padding_profile: PaddingProfile,
    client_key_id: ClientKeyId,
}

/// TX/RX halves for concurrent tunnel forwarding (avoids session mutex deadlock).
pub struct AuthenticatedSessionTx {
    aead: AeadTx,
    padding_profile: PaddingProfile,
}

pub struct AuthenticatedSessionRx {
    aead: AeadRx,
}

impl AuthenticatedSession {
    pub fn client_key_id(&self) -> ClientKeyId {
        self.client_key_id
    }

    pub fn split(self) -> (AuthenticatedSessionTx, AuthenticatedSessionRx) {
        let (tx, rx) = self.aead.split();
        (
            AuthenticatedSessionTx {
                aead: tx,
                padding_profile: self.padding_profile,
            },
            AuthenticatedSessionRx { aead: rx },
        )
    }
}

impl AuthenticatedSession {
    pub async fn client_connect<S>(stream: &mut S, config: &ClientConfig) -> Result<(Self, [u8; 8])>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self::client_connect_bound(stream, config, CarrierBinding::DirectTcp).await
    }

    /// Establish a session while authenticating the exact outer carrier.
    pub async fn client_connect_bound<S>(
        stream: &mut S,
        config: &ClientConfig,
        carrier_binding: CarrierBinding,
    ) -> Result<(Self, [u8; 8])>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let pins = ServerPins::single(config.server_fingerprint);
        Self::client_connect_pins_bound(stream, config, &pins, carrier_binding).await
    }

    /// Establish a session using a bounded authenticated pin set. The mutual
    /// fixed-width PSK gate necessarily precedes the static-key flight; pin
    /// verification still happens before ML-KEM encapsulation or ClientHello.
    pub async fn client_connect_pins<S>(
        stream: &mut S,
        config: &ClientConfig,
        server_pins: &ServerPins,
    ) -> Result<(Self, [u8; 8])>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self::client_connect_pins_bound(stream, config, server_pins, CarrierBinding::DirectTcp)
            .await
    }

    /// Pin-set variant of [`Self::client_connect_bound`].
    pub async fn client_connect_pins_bound<S>(
        stream: &mut S,
        config: &ClientConfig,
        server_pins: &ServerPins,
        carrier_binding: CarrierBinding,
    ) -> Result<(Self, [u8; 8])>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        anyhow::ensure!(
            config.camouflage != CamouflageMode::DnsChunk,
            "DnsChunk carrier is not implemented; refusing authenticated session"
        );
        let access_hello = config.client_credential.key_id();
        write_access_hello(stream, &access_hello).await?;
        let server_access_proof = read_server_access_proof(stream).await?;
        let decoded_server_access_proof =
            ServerAccessProof::decode(&server_access_proof).map_err(anyhow::Error::from)?;
        let client_access_proof = config
            .client_credential
            .verify_server_access_and_prove(
                &decoded_server_access_proof,
                config.camouflage,
                carrier_binding,
            )
            .context("verify server pre-key PSK proof")?
            .encode();
        write_access_proof(stream, &client_access_proof).await?;

        let pk_bytes = read_mlkem_public(stream).await?;
        // B1: authenticate the server before encapsulating to its key (active-MITM defense).
        let got = mlkem_fingerprint(&pk_bytes);
        if !server_pins.matches(&got) {
            let pinned = server_pins
                .as_slice()
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>()
                .join(",");
            return Err(anyhow!(
                "server key pin mismatch — possible active MITM (wire fp {}, pinned set [{}])",
                hex::encode(got),
                pinned
            ));
        }
        let server_pk = mlkem_public_from_bytes(&pk_bytes)?;

        let (x_secret, x_public) = X25519Keypair::ephemeral();
        let (pq_ct, pq_shared) = encapsulate_mlkem(&server_pk)?;

        let client_hello = ClientHello {
            magic: BUILD_MAGIC,
            version: PROTO_VERSION,
            client_random: random_bytes(),
            x25519_public: *x_public.as_bytes(),
            mlkem_ciphertext: pq_ct.as_slice().to_vec(),
            camouflage: config.camouflage,
            padding_profile: config.padding_profile,
        };
        write_client_hello(stream, &client_hello).await?;

        let server_hello = read_server_hello(stream).await?;
        let x_shared = x25519_ephemeral_shared(
            x_secret,
            &x25519_public_from_bytes(server_hello.x25519_public),
        )
        .context("reject non-contributory server X25519 share")?;

        // `pk_bytes` is what we received; if a MITM swapped the server key the
        // transcripts diverge here too (belt-and-suspenders with the B1 pin).
        let pre_finished = pre_finished_transcript(
            &access_hello,
            &server_access_proof,
            &client_access_proof,
            &pk_bytes,
            &client_hello,
            &server_hello,
            carrier_binding,
        );
        let handshake_keys = derive_handshake_traffic_keys(
            &x_shared,
            &pq_shared,
            client_hello.client_random,
            server_hello.server_random,
            &pre_finished,
            true,
        )?;
        let mut handshake_aead = AeadSession::new(&handshake_keys)?;

        let client_finished = config
            .client_credential
            .sign_finished(&pre_finished)
            .context("construct mandatory client authentication proof")?
            .encode();
        let encrypted_client_finished = handshake_aead.encrypt(
            &client_finished,
            &finished_aad(CLIENT_FINISHED_AAD_DOMAIN, &pre_finished),
        )?;
        anyhow::ensure!(
            encrypted_client_finished.len() == CLIENT_FINISHED_CIPHERTEXT_LEN,
            "internal ClientFinished ciphertext length invariant failed"
        );
        write_fixed_finished(stream, &encrypted_client_finished).await?;

        let encrypted_server_finished =
            read_fixed_finished::<_, SERVER_FINISHED_CIPHERTEXT_LEN>(stream).await?;
        let server_finished_plaintext = handshake_aead
            .decrypt(
                &encrypted_server_finished,
                &finished_aad(SERVER_FINISHED_AAD_DOMAIN, &pre_finished),
            )
            .map_err(|_| AuthFailed)?;
        let server_finished =
            ServerFinished::decode(&server_finished_plaintext).map_err(anyhow::Error::from)?;
        config
            .client_credential
            .verify_server_finished(&pre_finished, &client_finished, &server_finished)
            .map_err(anyhow::Error::from)?;
        let server_finished = server_finished.encode();
        let transcript = finished_transcript(&pre_finished, &client_finished, &server_finished);
        let application_keys = derive_application_traffic_keys(
            &x_shared,
            &pq_shared,
            config.client_credential.psk(),
            client_hello.client_random,
            server_hello.server_random,
            &transcript,
            true,
        )?;

        Ok((
            Self {
                aead: AeadSession::new(&application_keys)?,
                padding_profile: config.padding_profile,
                client_key_id: config.client_credential.key_id(),
            },
            server_hello.session_id,
        ))
    }

    pub async fn server_accept<S>(
        stream: &mut S,
        state: &ServerState,
        authorized_clients: &AuthorizedClients,
        observed_camouflage: CamouflageMode,
    ) -> Result<(Self, ClientHello, [u8; 8])>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self::server_accept_bound(
            stream,
            state,
            authorized_clients,
            observed_camouflage,
            CarrierBinding::DirectTcp,
        )
        .await
    }

    /// Accept a session while authenticating the exact locally observed outer
    /// carrier before the ML-KEM public-key flight.
    pub async fn server_accept_bound<S>(
        stream: &mut S,
        state: &ServerState,
        authorized_clients: &AuthorizedClients,
        observed_camouflage: CamouflageMode,
        observed_carrier: CarrierBinding,
    ) -> Result<(Self, ClientHello, [u8; 8])>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        anyhow::ensure!(
            observed_camouflage != CamouflageMode::DnsChunk,
            "DnsChunk carrier is not implemented; refusing authenticated session"
        );
        // Mutual, fixed-width PSK access gate. The client sends only its kid;
        // the server proves possession first using a fresh challenge. Only then
        // may the client emit its own nonce+MAC. Unknown ids receive the exact
        // same server flight under a fresh secret dummy PSK. No stable ML-KEM
        // bytes or KEM work are reachable until the final MAC verifies.
        let access_hello = read_access_hello(stream)
            .await
            .map_err(|_| anyhow::Error::from(AuthFailed))?;
        let access_challenge = random_bytes();
        let (server_access, pending_access) = authorized_clients.begin_access(
            access_hello,
            &access_challenge,
            observed_camouflage,
            observed_carrier,
        )?;
        let server_access_proof = server_access.encode();
        write_server_access_proof(stream, &server_access_proof).await?;
        let client_access_proof = read_access_proof(stream)
            .await
            .map_err(|_| anyhow::Error::from(AuthFailed))?;
        let decoded_client_access_proof =
            ClientAccessProof::decode(&client_access_proof).map_err(anyhow::Error::from)?;
        let access_key_id = pending_access
            .verify(
                &server_access,
                observed_camouflage,
                observed_carrier,
                &decoded_client_access_proof,
            )
            .map_err(anyhow::Error::from)?;

        let server_public = mlkem_public_bytes(&state.mlkem.public);
        write_mlkem_public(stream, &server_public).await?;

        let client_hello = read_client_hello(stream).await?;
        if client_hello.magic != BUILD_MAGIC {
            return Err(anyhow!(
                "magic mismatch: got {:#010x}, expected {:#010x}",
                client_hello.magic,
                BUILD_MAGIC
            ));
        }
        if client_hello.version != PROTO_VERSION {
            return Err(anyhow!("unsupported version {}", client_hello.version));
        }
        // The outer adapter supplies the observed inner framing class (raw or
        // h2). Reject a translated/stripped framing layer before decapsulation,
        // ServerHello, either Finished record, or construction of a typed
        // application session. This does not identify the outer transport:
        // direct TCP, TLS, QUIC and REALITY all currently terminate to raw.
        if client_hello.camouflage != observed_camouflage {
            return Err(anyhow!(
                "authenticated inner framing class {:?} does not match observed framing class {:?}",
                client_hello.camouflage,
                observed_camouflage
            ));
        }

        let pq_ct = mlkem_ciphertext_from_bytes(&client_hello.mlkem_ciphertext)?;
        let pq_shared = decapsulate_mlkem(&state.mlkem.secret, &pq_ct)?;

        let (x_secret, x_public) = X25519Keypair::ephemeral();
        let server_random = random_bytes();
        let session_id = random_session_id();

        let server_hello = ServerHello {
            server_random,
            x25519_public: *x_public.as_bytes(),
            session_id,
        };
        let x_shared = x25519_ephemeral_shared(
            x_secret,
            &x25519_public_from_bytes(client_hello.x25519_public),
        )
        .context("reject non-contributory client X25519 share")?;
        // Do not emit ServerHello for a non-contributory client share. This is
        // both cheaper to reject and keeps invalid hybrid handshakes fail-closed
        // before the next server flight.
        write_server_hello(stream, &server_hello).await?;

        // Server binds the key it actually sent and the hello it actually
        // received; a tampered cleartext field (e.g. padding_profile) makes this
        // differ from the client's transcript -> divergent keys -> AEAD abort.
        let pre_finished = pre_finished_transcript(
            &access_hello,
            &server_access_proof,
            &client_access_proof,
            &server_public,
            &client_hello,
            &server_hello,
            observed_carrier,
        );
        let handshake_keys = derive_handshake_traffic_keys(
            &x_shared,
            &pq_shared,
            client_hello.client_random,
            server_random,
            &pre_finished,
            false,
        )?;
        let mut handshake_aead = AeadSession::new(&handshake_keys)?;

        let encrypted_client_finished =
            read_fixed_finished::<_, CLIENT_FINISHED_CIPHERTEXT_LEN>(stream).await?;
        let client_finished_plaintext = handshake_aead
            .decrypt(
                &encrypted_client_finished,
                &finished_aad(CLIENT_FINISHED_AAD_DOMAIN, &pre_finished),
            )
            .map_err(|_| AuthFailed)?;
        let client_finished =
            ClientFinished::decode(&client_finished_plaintext).map_err(anyhow::Error::from)?;
        let verified = authorized_clients
            .verify_finished_for_key(&pre_finished, &client_finished, &access_key_id)
            .map_err(anyhow::Error::from)?;
        let client_finished = client_finished.encode();

        let server_finished =
            AuthorizedClients::make_server_finished(&verified, &pre_finished, &client_finished)
                .encode();
        let encrypted_server_finished = handshake_aead.encrypt(
            &server_finished,
            &finished_aad(SERVER_FINISHED_AAD_DOMAIN, &pre_finished),
        )?;
        anyhow::ensure!(
            encrypted_server_finished.len() == SERVER_FINISHED_CIPHERTEXT_LEN,
            "internal ServerFinished ciphertext length invariant failed"
        );
        write_fixed_finished(stream, &encrypted_server_finished).await?;

        let transcript = finished_transcript(&pre_finished, &client_finished, &server_finished);
        let application_keys = derive_application_traffic_keys(
            &x_shared,
            &pq_shared,
            &verified.psk,
            client_hello.client_random,
            server_random,
            &transcript,
            false,
        )?;

        Ok((
            Self {
                aead: AeadSession::new(&application_keys)?,
                padding_profile: client_hello.padding_profile,
                client_key_id: verified.key_id,
            },
            client_hello,
            session_id,
        ))
    }

    pub async fn send<S>(
        &mut self,
        stream: &mut S,
        stream_id: u32,
        flags: FrameFlags,
        payload: &[u8],
    ) -> Result<u64>
    where
        S: AsyncWrite + Unpin,
    {
        let prepared = prepare_outbound_frame(self.padding_profile, flags, payload.len())?;
        let encrypted = self.aead.encrypt(
            payload,
            &frame_aad(
                stream_id,
                prepared.flags,
                prepared.ciphertext_len,
                &prepared.padding,
            ),
        )?;
        anyhow::ensure!(
            encrypted.len() == prepared.ciphertext_len,
            "application frame ciphertext length invariant failed"
        );

        let wire =
            estimate_frame_wire_bytes(encrypted.len(), prepared.wire_padding.len(), stream_id);
        write_frame(
            stream,
            &Frame {
                stream_id,
                flags: prepared.flags,
                payload: encrypted,
                padding: prepared.wire_padding,
            },
        )
        .await?;
        Ok(wire)
    }

    pub async fn recv<S>(&mut self, stream: &mut S) -> Result<(u32, FrameFlags, Vec<u8>, u64)>
    where
        S: AsyncRead + Unpin,
    {
        let frame = read_frame(stream).await?;
        let pad_wire = if frame.flags.contains(FrameFlags::PADDING) {
            2 + frame.padding.len()
        } else {
            0
        };
        let wire = estimate_frame_wire_bytes(frame.payload.len(), pad_wire, frame.stream_id);
        let plaintext = self.aead.decrypt(
            &frame.payload,
            &frame_aad(
                frame.stream_id,
                frame.flags,
                frame.payload.len(),
                &frame.padding,
            ),
        )?;
        Ok((frame.stream_id, frame.flags, plaintext, wire))
    }
}

impl AuthenticatedSessionTx {
    pub async fn send<S>(
        &mut self,
        stream: &mut S,
        stream_id: u32,
        flags: FrameFlags,
        payload: &[u8],
    ) -> Result<u64>
    where
        S: AsyncWrite + Unpin,
    {
        let prepared = prepare_outbound_frame(self.padding_profile, flags, payload.len())?;
        let encrypted = self.aead.encrypt(
            payload,
            &frame_aad(
                stream_id,
                prepared.flags,
                prepared.ciphertext_len,
                &prepared.padding,
            ),
        )?;
        anyhow::ensure!(
            encrypted.len() == prepared.ciphertext_len,
            "application frame ciphertext length invariant failed"
        );

        let wire =
            estimate_frame_wire_bytes(encrypted.len(), prepared.wire_padding.len(), stream_id);
        write_frame(
            stream,
            &Frame {
                stream_id,
                flags: prepared.flags,
                payload: encrypted,
                padding: prepared.wire_padding,
            },
        )
        .await?;
        Ok(wire)
    }
}

impl AuthenticatedSessionRx {
    pub async fn recv<S>(&mut self, stream: &mut S) -> Result<(u32, FrameFlags, Vec<u8>, u64)>
    where
        S: AsyncRead + Unpin,
    {
        let frame = read_frame(stream).await?;
        let pad_wire = if frame.flags.contains(FrameFlags::PADDING) {
            2 + frame.padding.len()
        } else {
            0
        };
        let wire = estimate_frame_wire_bytes(frame.payload.len(), pad_wire, frame.stream_id);
        let plaintext = self.aead.decrypt(
            &frame.payload,
            &frame_aad(
                frame.stream_id,
                frame.flags,
                frame.payload.len(),
                &frame.padding,
            ),
        )?;
        Ok((frame.stream_id, frame.flags, plaintext, wire))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        KEY_SIZE, MLKEM_CIPHERTEXT_SIZE, MLKEM_LEGACY_EXPANDED_SECRET_SIZE, MLKEM_PUBLIC_KEY_SIZE,
        MLKEM_SEED_SIZE,
    };
    use std::path::PathBuf;

    struct TempKeyFile(PathBuf);

    impl TempKeyFile {
        fn new(label: &str) -> Self {
            let nonce: [u8; 8] = random_bytes();
            Self(std::env::temp_dir().join(format!(
                "shadowpipe-{label}-{}-{}.json",
                std::process::id(),
                hex::encode(nonce)
            )))
        }
    }

    impl Drop for TempKeyFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyPqcryptoFixture {
        mlkem_public: String,
        mlkem_secret: String,
        mlkem_ciphertext: String,
        shared_secret: String,
    }

    fn legacy_pqcrypto_fixture() -> LegacyPqcryptoFixture {
        serde_json::from_str(include_str!(
            "../tests/fixtures/pqcrypto_mlkem768_legacy_key.json"
        ))
        .expect("valid pqcrypto compatibility fixture")
    }

    #[test]
    fn generated_key_file_roundtrip_uses_seed_and_preserves_identity() {
        let path = TempKeyFile::new("mlkem-seed-roundtrip");
        let original = ServerState::generate();
        let original_public = original.mlkem_public_bytes();
        let original_fingerprint = original.fingerprint();

        original.save(&path.0).unwrap();

        let stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&path.0).unwrap()).unwrap();
        let stored_public = hex::decode(stored["mlkem_public"].as_str().unwrap()).unwrap();
        let stored_secret = hex::decode(stored["mlkem_secret"].as_str().unwrap()).unwrap();
        assert_eq!(stored_public.len(), MLKEM_PUBLIC_KEY_SIZE);
        assert_eq!(stored_secret.len(), MLKEM_SEED_SIZE);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path.0).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let loaded = ServerState::load(&path.0).unwrap();
        assert_eq!(loaded.mlkem_public_bytes(), original_public);
        assert_eq!(loaded.fingerprint(), original_fingerprint);
    }

    #[test]
    fn key_save_atomically_replaces_an_existing_file() {
        let path = TempKeyFile::new("mlkem-atomic-replace");
        let first = ServerState::generate();
        let second = ServerState::generate();
        first.save(&path.0).unwrap();
        let first_contents = fs::read(&path.0).unwrap();

        second.save(&path.0).unwrap();

        assert_ne!(fs::read(&path.0).unwrap(), first_contents);
        let loaded = ServerState::load(&path.0).unwrap();
        assert_eq!(loaded.mlkem_public_bytes(), second.mlkem_public_bytes());
    }

    #[test]
    fn concurrent_load_or_generate_returns_one_persisted_identity() {
        use std::sync::{Arc, Barrier};

        let path = TempKeyFile::new("mlkem-concurrent-create");
        let workers = 16;
        let barrier = Arc::new(Barrier::new(workers));
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let path = path.0.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    ServerState::load_or_generate(&path)
                        .unwrap()
                        .mlkem_public_bytes()
                })
            })
            .collect();
        let identities: Vec<Vec<u8>> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert!(identities.iter().all(|identity| identity == &identities[0]));
        assert_eq!(
            ServerState::load(&path.0).unwrap().mlkem_public_bytes(),
            identities[0]
        );

        let file_name = path.0.file_name().unwrap().to_string_lossy();
        let temp_prefix = format!(".{file_name}.shadowpipe-");
        let parent = private_file_parent(&path.0);
        let leaked_temps: Vec<_> = fs::read_dir(parent)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .filter(|name| name.to_string_lossy().starts_with(&temp_prefix))
            .collect();
        assert!(
            leaked_temps.is_empty(),
            "leaked temp files: {leaked_temps:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_key_owner_check_rejects_foreign_uid() {
        let path = Path::new("private-key-owner-test");
        ensure_private_file_owner(path, 1000, 1000).unwrap();
        let error = ensure_private_file_owner(path, 1000, 1001).unwrap_err();
        assert!(
            format!("{error:#}").contains("owned by UID 1000; expected UID 1001"),
            "unexpected error: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_load_rejects_group_or_other_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = TempKeyFile::new("mlkem-unsafe-mode");
        ServerState::generate().save(&path.0).unwrap();
        fs::set_permissions(&path.0, fs::Permissions::from_mode(0o640)).unwrap();

        let error = match ServerState::load_or_generate(&path.0) {
            Ok(_) => panic!("group-readable private key must fail closed"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("unsafe group/other permissions"),
            "unexpected error: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_load_rejects_final_symlink() {
        use std::os::unix::fs::symlink;

        let link = TempKeyFile::new("mlkem-load-symlink");
        let target = TempKeyFile::new("mlkem-load-symlink-target");
        ServerState::generate().save(&target.0).unwrap();
        symlink(&target.0, &link.0).unwrap();

        assert!(
            ServerState::load_or_generate(&link.0).is_err(),
            "loading must not follow a final private-key symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_load_rejects_non_regular_file() {
        let path = TempKeyFile::new("mlkem-load-directory");
        fs::create_dir(&path.0).unwrap();

        let error = match ServerState::load_or_generate(&path.0) {
            Ok(_) => panic!("directory private-key path must fail closed"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("not a regular file"),
            "unexpected error: {error:#}"
        );
        fs::remove_dir(&path.0).unwrap();
    }

    #[test]
    fn mismatched_in_memory_keypair_does_not_replace_existing_file() {
        let path = TempKeyFile::new("mlkem-failed-save");
        let existing = ServerState::generate();
        existing.save(&path.0).unwrap();
        let before = fs::read(&path.0).unwrap();

        let public = MlkemKeypair::generate().public;
        let secret = MlkemKeypair::generate().secret;
        let mismatched = ServerState {
            mlkem: MlkemKeypair { public, secret },
        };
        let error = mismatched
            .save(&path.0)
            .expect_err("mismatched in-memory keypair must fail before publication");

        assert!(
            error.to_string().contains("refusing to save mismatched"),
            "unexpected error: {error:#}"
        );
        assert_eq!(fs::read(&path.0).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn key_save_replaces_final_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let link = TempKeyFile::new("mlkem-symlink");
        let victim = TempKeyFile::new("mlkem-symlink-victim");
        let victim_contents = b"must-not-be-overwritten";
        fs::write(&victim.0, victim_contents).unwrap();
        symlink(&victim.0, &link.0).unwrap();

        let state = ServerState::generate();
        state.save(&link.0).unwrap();

        assert_eq!(fs::read(&victim.0).unwrap(), victim_contents);
        assert!(!fs::symlink_metadata(&link.0)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            ServerState::load(&link.0).unwrap().mlkem_public_bytes(),
            state.mlkem_public_bytes()
        );
    }

    #[test]
    fn kem_shared_secret_roundtrip_preserves_wire_sizes() {
        let state = ServerState::generate();
        let (ciphertext, sender_shared) = encapsulate_mlkem(&state.mlkem.public).unwrap();
        let receiver_shared = decapsulate_mlkem(&state.mlkem.secret, &ciphertext).unwrap();

        assert_eq!(state.mlkem_public_bytes().len(), MLKEM_PUBLIC_KEY_SIZE);
        assert_eq!(ciphertext.as_slice().len(), MLKEM_CIPHERTEXT_SIZE);
        assert_eq!(sender_shared.as_slice(), receiver_shared.as_slice());
    }

    #[test]
    fn loads_and_decapsulates_pqcrypto_expanded_key_fixture() {
        let path = TempKeyFile::new("mlkem-pqcrypto-legacy");
        let fixture = legacy_pqcrypto_fixture();
        let legacy_key_file = serde_json::json!({
            "mlkem_public": fixture.mlkem_public,
            "mlkem_secret": fixture.mlkem_secret,
        });
        atomic_write_private_file(
            &path.0,
            &serde_json::to_vec_pretty(&legacy_key_file).unwrap(),
        )
        .unwrap();

        let state = ServerState::load(&path.0).unwrap();
        let expected_public = hex::decode(&fixture.mlkem_public).unwrap();
        assert_eq!(expected_public.len(), MLKEM_PUBLIC_KEY_SIZE);
        assert_eq!(state.mlkem_public_bytes(), expected_public);
        assert_eq!(
            hex::encode(state.fingerprint()),
            "40812ce514be70f6616577113906487188c10ae54a3885827c1cbee810ed53f2"
        );

        let ciphertext_bytes = hex::decode(&fixture.mlkem_ciphertext).unwrap();
        let ciphertext = mlkem_ciphertext_from_bytes(&ciphertext_bytes).unwrap();
        let receiver_shared = decapsulate_mlkem(&state.mlkem.secret, &ciphertext).unwrap();
        assert_eq!(
            hex::encode(receiver_shared.as_slice()),
            fixture.shared_secret
        );

        let stored_secret = hex::decode(&fixture.mlkem_secret).unwrap();
        assert_eq!(stored_secret.len(), MLKEM_LEGACY_EXPANDED_SECRET_SIZE);
    }

    #[test]
    fn rejects_public_key_that_does_not_match_secret() {
        let path = TempKeyFile::new("mlkem-mismatched-public");
        let first = ServerState::generate();
        let second = ServerState::generate();
        first.save(&path.0).unwrap();

        let mut stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&path.0).unwrap()).unwrap();
        stored["mlkem_public"] =
            serde_json::Value::String(hex::encode(second.mlkem_public_bytes()));
        fs::write(&path.0, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();

        let error = match ServerState::load(&path.0) {
            Ok(_) => panic!("mismatched key file must fail closed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("public key does not match the stored secret key"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn rejects_malformed_legacy_expanded_secret() {
        let path = TempKeyFile::new("mlkem-malformed-expanded");
        let fixture = legacy_pqcrypto_fixture();
        let mut secret = hex::decode(&fixture.mlkem_secret).unwrap();
        // FIPS 203 expanded ML-KEM-768 layout ends with H(ek) || z. Corrupt
        // the first byte of H(ek); RustCrypto must reject it during validation.
        let embedded_public_hash_offset = MLKEM_LEGACY_EXPANDED_SECRET_SIZE - 64;
        secret[embedded_public_hash_offset] ^= 1;
        let malformed = serde_json::json!({
            "mlkem_public": fixture.mlkem_public,
            "mlkem_secret": hex::encode(secret),
        });
        atomic_write_private_file(&path.0, &serde_json::to_vec_pretty(&malformed).unwrap())
            .unwrap();

        let error = match ServerState::load(&path.0) {
            Ok(_) => panic!("malformed expanded key must fail closed"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("invalid expanded mlkem secret key encoding"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn rejects_legacy_expanded_secret_with_corrupted_private_component() {
        let path = TempKeyFile::new("mlkem-corrupted-private-component");
        let fixture = legacy_pqcrypto_fixture();
        let mut secret = hex::decode(&fixture.mlkem_secret).unwrap();
        // Expanded ML-KEM-768 is dk_pke || ek || H(ek) || z. RustCrypto can
        // validate ek and H(ek), but it cannot infer that dk_pke belongs to ek
        // without a pairwise operation. Destroy the full private-PKE component
        // while leaving the embedded public identity and hash untouched.
        let private_component_len = MLKEM_LEGACY_EXPANDED_SECRET_SIZE - MLKEM_PUBLIC_KEY_SIZE - 64;
        secret[..private_component_len].fill(0);
        let malformed = serde_json::json!({
            "mlkem_public": fixture.mlkem_public,
            "mlkem_secret": hex::encode(secret),
        });
        atomic_write_private_file(&path.0, &serde_json::to_vec_pretty(&malformed).unwrap())
            .unwrap();

        let error = match ServerState::load(&path.0) {
            Ok(_) => panic!("mismatched expanded private component must fail closed"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("pairwise encapsulation self-test"),
            "unexpected error: {error:#}"
        );
    }

    fn sample_hellos() -> (Vec<u8>, ClientHello, ServerHello) {
        let server_pk = vec![0xAAu8; 1184];
        let ch = ClientHello {
            magic: BUILD_MAGIC,
            version: PROTO_VERSION,
            client_random: [1u8; 16],
            x25519_public: [2u8; 32],
            mlkem_ciphertext: vec![3u8; 1088],
            camouflage: CamouflageMode::H2Chunk,
            padding_profile: PaddingProfile::Balanced,
        };
        let sh = ServerHello {
            server_random: [4u8; 16],
            x25519_public: [5u8; 32],
            session_id: [6u8; 8],
        };
        (server_pk, ch, sh)
    }

    #[test]
    fn pre_finished_h0_known_answer_is_stable() {
        // Explicit magic makes the vector independent of build.rs's random
        // debug/test default. The suite string and all 20 canonical fields are
        // therefore covered by a reproducible cross-implementation oracle.
        let build_magic = 0x0102_0304;
        let (pk, mut ch, sh) = sample_hellos();
        ch.magic = build_magic;
        let access_hello = [0xB0; CLIENT_ACCESS_HELLO_LEN];
        let server_access_proof = [0xC1; SERVER_ACCESS_PROOF_LEN];
        let client_access_proof = [0xD2; CLIENT_ACCESS_PROOF_LEN];
        let h0 = pre_finished_transcript_with_magic(
            build_magic,
            &access_hello,
            &server_access_proof,
            &client_access_proof,
            &pk,
            TranscriptCarrierContext {
                client_hello: &ch,
                server_hello: &sh,
                carrier_binding: CarrierBinding::DirectTcp,
            },
        );
        assert_eq!(
            hex::encode(h0),
            "4602407f409510dc99e0143c54d55ed5c5027e49af41fd138535fedb6a5f0573"
        );
    }

    #[test]
    fn transcript_is_deterministic_and_field_sensitive() {
        let (pk, ch, sh) = sample_hellos();
        let access_hello = [0xB0; CLIENT_ACCESS_HELLO_LEN];
        let server_access_proof = [0xC1; SERVER_ACCESS_PROOF_LEN];
        let client_access_proof = [0xD2; CLIENT_ACCESS_PROOF_LEN];
        let base = pre_finished_transcript(
            &access_hello,
            &server_access_proof,
            &client_access_proof,
            &pk,
            &ch,
            &sh,
            CarrierBinding::DirectTcp,
        );
        // Identical views -> identical transcript (the no-tamper case).
        assert_eq!(
            base,
            pre_finished_transcript(
                &access_hello,
                &server_access_proof,
                &client_access_proof,
                &pk,
                &ch,
                &sh,
                CarrierBinding::DirectTcp,
            )
        );

        let mut changed_access_hello = access_hello;
        changed_access_hello[0] ^= 1;
        assert_ne!(
            base,
            pre_finished_transcript(
                &changed_access_hello,
                &server_access_proof,
                &client_access_proof,
                &pk,
                &ch,
                &sh,
                CarrierBinding::DirectTcp,
            ),
            "access hello must bind"
        );
        let mut changed_server_access_proof = server_access_proof;
        changed_server_access_proof[SERVER_ACCESS_PROOF_LEN - 1] ^= 1;
        assert_ne!(
            base,
            pre_finished_transcript(
                &access_hello,
                &changed_server_access_proof,
                &client_access_proof,
                &pk,
                &ch,
                &sh,
                CarrierBinding::DirectTcp,
            ),
            "server access proof must bind"
        );
        let mut changed_client_access_proof = client_access_proof;
        changed_client_access_proof[CLIENT_ACCESS_PROOF_LEN - 1] ^= 1;
        assert_ne!(
            base,
            pre_finished_transcript(
                &access_hello,
                &server_access_proof,
                &changed_client_access_proof,
                &pk,
                &ch,
                &sh,
                CarrierBinding::DirectTcp,
            ),
            "client access proof must bind"
        );

        // The two fields a MITM could previously flip undetected:
        let mut ch_pad = ch.clone();
        ch_pad.padding_profile = PaddingProfile::PreferEntropy;
        assert_ne!(
            base,
            pre_finished_transcript(
                &access_hello,
                &server_access_proof,
                &client_access_proof,
                &pk,
                &ch_pad,
                &sh,
                CarrierBinding::DirectTcp,
            ),
            "padding must bind"
        );

        let mut ch_cam = ch.clone();
        ch_cam.camouflage = CamouflageMode::Raw;
        assert_ne!(
            base,
            pre_finished_transcript(
                &access_hello,
                &server_access_proof,
                &client_access_proof,
                &pk,
                &ch_cam,
                &sh,
                CarrierBinding::DirectTcp,
            ),
            "camouflage must bind"
        );

        // The server identity key and a server-hello field also bind.
        let mut pk2 = pk.clone();
        pk2[0] ^= 0xff;
        assert_ne!(
            base,
            pre_finished_transcript(
                &access_hello,
                &server_access_proof,
                &client_access_proof,
                &pk2,
                &ch,
                &sh,
                CarrierBinding::DirectTcp,
            ),
            "server key must bind"
        );

        let mut sh2 = sh.clone();
        sh2.session_id = [9u8; 8];
        assert_ne!(
            base,
            pre_finished_transcript(
                &access_hello,
                &server_access_proof,
                &client_access_proof,
                &pk,
                &ch,
                &sh2,
                CarrierBinding::DirectTcp,
            ),
            "server hello must bind"
        );
        assert_ne!(
            base,
            pre_finished_transcript(
                &access_hello,
                &server_access_proof,
                &client_access_proof,
                &pk,
                &ch,
                &sh,
                CarrierBinding::RealityTcp,
            ),
            "outer carrier identity must bind"
        );
    }

    #[test]
    fn tampered_transcript_diverges_keys() {
        // The actual security property: same secrets + randoms but a different
        // transcript (a MITM-downgraded field) yields different keys, so the
        // peers cannot talk and the first AEAD frame fails.
        let x = [7u8; KEY_SIZE];
        let pq = [8u8; KEY_SIZE];
        let cr = [1u8; 16];
        let sr = [2u8; 16];
        let t1 = [0u8; 32];
        let mut t2 = [0u8; 32];
        t2[0] = 1;
        let k1 = derive_handshake_traffic_keys(&x, &pq, cr, sr, &t1, true).unwrap();
        let k2 = derive_handshake_traffic_keys(&x, &pq, cr, sr, &t2, true).unwrap();
        assert_ne!(k1.send_key, k2.send_key);
        assert_ne!(k1.recv_key, k2.recv_key);
    }

    #[test]
    fn v3_key_schedule_inverts_direction_and_separates_finished_from_application() {
        let x = [0x17u8; KEY_SIZE];
        let pq = [0x28u8; KEY_SIZE];
        let psk_a = [0x39u8; KEY_SIZE];
        let psk_b = [0x4au8; KEY_SIZE];
        let client_random = [0x5bu8; 16];
        let server_random = [0x6cu8; 16];
        // Deliberately reuse one transcript value here: the independent HKDF
        // labels alone must still separate Finished traffic from application
        // traffic. Production additionally uses distinct transcript stages.
        let transcript = [0x7du8; 32];

        let client_handshake =
            derive_handshake_traffic_keys(&x, &pq, client_random, server_random, &transcript, true)
                .unwrap();
        let server_handshake = derive_handshake_traffic_keys(
            &x,
            &pq,
            client_random,
            server_random,
            &transcript,
            false,
        )
        .unwrap();
        assert_eq!(client_handshake.send_key, server_handshake.recv_key);
        assert_eq!(client_handshake.recv_key, server_handshake.send_key);

        let client_application = derive_application_traffic_keys(
            &x,
            &pq,
            &psk_a,
            client_random,
            server_random,
            &transcript,
            true,
        )
        .unwrap();
        let server_application = derive_application_traffic_keys(
            &x,
            &pq,
            &psk_a,
            client_random,
            server_random,
            &transcript,
            false,
        )
        .unwrap();
        assert_eq!(client_application.send_key, server_application.recv_key);
        assert_eq!(client_application.recv_key, server_application.send_key);
        assert_ne!(client_handshake.send_key, client_application.send_key);
        assert_ne!(client_handshake.recv_key, client_application.recv_key);

        let changed_psk_application = derive_application_traffic_keys(
            &x,
            &pq,
            &psk_b,
            client_random,
            server_random,
            &transcript,
            true,
        )
        .unwrap();
        assert_ne!(
            client_application.send_key,
            changed_psk_application.send_key
        );
        assert_ne!(
            client_application.recv_key,
            changed_psk_application.recv_key
        );

        let unchanged_handshake =
            derive_handshake_traffic_keys(&x, &pq, client_random, server_random, &transcript, true)
                .unwrap();
        assert_eq!(client_handshake.send_key, unchanged_handshake.send_key);
        assert_eq!(client_handshake.recv_key, unchanged_handshake.recv_key);
    }

    #[test]
    fn server_pin_set_is_bounded_unique_and_rotation_safe() {
        let old = [0x11; 32];
        let active = [0x22; 32];
        let next = [0x33; 32];
        let pins = ServerPins::new(&[old, active, next]).unwrap();
        assert_eq!(pins.as_slice(), &[old, active, next]);
        assert!(pins.matches(&old));
        assert!(pins.matches(&active));
        assert!(pins.matches(&next));
        assert!(!pins.matches(&[0x44; 32]));

        assert!(ServerPins::new(&[]).is_err());
        assert!(ServerPins::new(&[old, active, next, [0x44; 32]]).is_err());
        assert!(ServerPins::new(&[old, old]).is_err());
    }

    #[test]
    fn inactive_zero_slots_are_never_trusted() {
        let pins = ServerPins::single([0xA5; 32]);
        assert!(!pins.matches(&[0u8; 32]));
        assert_eq!(pins.as_slice(), &[[0xA5; 32]]);
    }

    #[tokio::test]
    async fn unimplemented_dns_carrier_fails_before_any_handshake_io() {
        let credential = Arc::new(ClientCredential::generate().unwrap());
        let authorized = credential.authorized_clients().unwrap();
        let config = ClientConfig {
            camouflage: CamouflageMode::DnsChunk,
            padding_profile: PaddingProfile::Balanced,
            server_fingerprint: [0x42; 32],
            client_credential: Arc::clone(&credential),
        };

        let (mut client_io, mut server_io) = tokio::io::duplex(1);
        let client_result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            AuthenticatedSession::client_connect(&mut client_io, &config),
        )
        .await
        .expect("client waited for wire input before rejecting DnsChunk");
        let client = match client_result {
            Ok(_) => panic!("client constructed an unimplemented DnsChunk session"),
            Err(error) => error,
        };
        assert!(client.to_string().contains("not implemented"));
        let mut probe = [0u8; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                server_io.read_exact(&mut probe),
            )
            .await
            .is_err(),
            "client wrote bytes before rejecting DnsChunk"
        );

        let state = ServerState::generate();
        let server_result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            AuthenticatedSession::server_accept(
                &mut server_io,
                &state,
                &authorized,
                CamouflageMode::DnsChunk,
            ),
        )
        .await
        .expect("server performed wire I/O before rejecting DnsChunk");
        let server = match server_result {
            Ok(_) => panic!("server constructed an unimplemented DnsChunk session"),
            Err(error) => error,
        };
        assert!(server.to_string().contains("not implemented"));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                client_io.read_exact(&mut probe),
            )
            .await
            .is_err(),
            "server wrote bytes before rejecting DnsChunk"
        );
    }

    #[tokio::test]
    async fn outbound_frame_preflight_rejects_invalid_metadata_without_consuming_aead_nonce() {
        use crate::crypto::{AeadSession, SessionKeys, KEY_SIZE};

        for invalid_flags in [
            FrameFlags::from_bits(0),
            FrameFlags::PADDING,
            FrameFlags::from_bits(0x80),
            FrameFlags::from_bits(FrameFlags::DATA.bits() | FrameFlags::FIN.bits()),
        ] {
            assert!(
                prepare_outbound_frame(PaddingProfile::Balanced, invalid_flags, 1).is_err(),
                "invalid caller flags {:#04x} reached frame construction",
                invalid_flags.bits()
            );
        }
        assert!(prepare_outbound_frame(
            PaddingProfile::Balanced,
            FrameFlags::DATA,
            MAX_FRAME_PAYLOAD - CHACHA20_POLY1305_TAG_LEN + 1,
        )
        .is_err());

        let keys = SessionKeys {
            send_key: [0x37; KEY_SIZE],
            recv_key: [0x37; KEY_SIZE],
        };
        let mut sender = AuthenticatedSession {
            aead: AeadSession::new(&keys).unwrap(),
            padding_profile: PaddingProfile::Balanced,
            client_key_id: [0u8; 16],
        };
        let mut receiver = AuthenticatedSession {
            aead: AeadSession::new(&keys).unwrap(),
            padding_profile: PaddingProfile::Balanced,
            client_key_id: [0u8; 16],
        };
        let (mut send_io, mut recv_io) = tokio::io::duplex(4096);
        let oversized = vec![0u8; MAX_FRAME_PAYLOAD - CHACHA20_POLY1305_TAG_LEN + 1];
        assert!(sender
            .send(&mut send_io, 7, FrameFlags::DATA, &oversized)
            .await
            .is_err());

        sender
            .send(&mut send_io, 7, FrameFlags::DATA, b"nonce-zero-still-live")
            .await
            .unwrap();
        let (stream_id, flags, payload, _) = receiver.recv(&mut recv_io).await.unwrap();
        assert_eq!(stream_id, 7);
        assert!(flags.contains(FrameFlags::DATA));
        assert_eq!(payload, b"nonce-zero-still-live");
    }

    #[test]
    fn frame_header_is_authenticated() {
        use crate::crypto::{AeadSession, SessionKeys};
        // Same key both ways so a fresh receiver can decrypt a fresh sender's
        // first frame (nonce 0 == nonce 0); the AAD is what we're testing.
        let keys = SessionKeys {
            send_key: [9u8; KEY_SIZE],
            recv_key: [9u8; KEY_SIZE],
        };
        let mut tx = AeadSession::new(&keys).unwrap();
        let ciphertext_len = b"payload".len() + CHACHA20_POLY1305_TAG_LEN;
        let aad_good = frame_aad(7, FrameFlags::DATA, ciphertext_len, &[]);
        let ct = tx.encrypt(b"payload", &aad_good).unwrap();

        // A flipped FIN bit -> different AAD -> decryption MUST fail.
        let tampered_flags =
            FrameFlags::from_bits(FrameFlags::DATA.bits() | FrameFlags::FIN.bits());
        let mut rx = AeadSession::new(&keys).unwrap();
        assert!(
            rx.decrypt(&ct, &frame_aad(7, tampered_flags, ciphertext_len, &[]))
                .is_err(),
            "a flipped flag bit must fail the AEAD tag"
        );

        // A changed stream id must also fail.
        let mut rx2 = AeadSession::new(&keys).unwrap();
        assert!(
            rx2.decrypt(&ct, &frame_aad(8, FrameFlags::DATA, ciphertext_len, &[]))
                .is_err(),
            "a changed stream_id must fail the AEAD tag"
        );

        // Ciphertext and external-padding lengths/bytes are authenticated too.
        let mut rx3 = AeadSession::new(&keys).unwrap();
        assert!(
            rx3.decrypt(
                &ct,
                &frame_aad(7, FrameFlags::DATA, ciphertext_len + 1, &[])
            )
            .is_err(),
            "a changed ciphertext length must fail the AEAD tag"
        );

        let padded_flags =
            FrameFlags::from_bits(FrameFlags::DATA.bits() | FrameFlags::PADDING.bits());
        let padding = [0x11, 0x22, 0x33];
        let mut padded_tx = AeadSession::new(&keys).unwrap();
        let padded_ct = padded_tx
            .encrypt(
                b"payload",
                &frame_aad(7, padded_flags, ciphertext_len, &padding),
            )
            .unwrap();
        let mut changed_padding = padding;
        changed_padding[1] ^= 0xff;
        let mut padded_rx = AeadSession::new(&keys).unwrap();
        assert!(
            padded_rx
                .decrypt(
                    &padded_ct,
                    &frame_aad(7, padded_flags, ciphertext_len, &changed_padding),
                )
                .is_err(),
            "a changed external padding byte must fail the AEAD tag"
        );
        let mut shortened_padding_rx = AeadSession::new(&keys).unwrap();
        assert!(
            shortened_padding_rx
                .decrypt(
                    &padded_ct,
                    &frame_aad(7, padded_flags, ciphertext_len, &padding[..2]),
                )
                .is_err(),
            "a changed external padding length must fail the AEAD tag"
        );

        // The untampered header decrypts cleanly.
        let mut rx4 = AeadSession::new(&keys).unwrap();
        assert_eq!(rx4.decrypt(&ct, &aad_good).unwrap(), b"payload");
    }
}
