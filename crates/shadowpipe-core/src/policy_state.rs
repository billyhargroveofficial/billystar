//! Crash-safe persistence for signed-policy anti-rollback floors and orderly
//! runtime-expiry retirement.
//!
//! The signed bundle is stored verbatim beside the maximum accepted issue and
//! wall-clock floors.  The envelope is bound to the configured offline root and
//! checksummed with a domain-separated SHA-256 digest.  Loading always
//! re-verifies the embedded bundle before reconstructing an
//! [`AcceptedPolicyState`]. A separate fixed-size expiry tombstone prevents an
//! orderly monotonic expiry from being resurrected by wall-clock rollback on a
//! later process restart.

use anyhow::{Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::crypto::ct_eq;
use crate::host_state::{HostStateLease, LeaseError};
use crate::signed_policy::{
    apply_verified_update, verify_bundle, AcceptedPolicyState, Transition, TrustedRoot,
    MAX_BUNDLE_BYTES,
};

const MAGIC: &[u8; 8] = b"SPPOLST1";
const VERSION: u16 = 1;
const RESERVED: u16 = 0;
const PREFIX_BYTES: usize = 8 + 2 + 2 + 32 + 8 + 8 + 4;
const CHECKSUM_BYTES: usize = 32;
const MIN_STATE_BYTES: usize = PREFIX_BYTES + CHECKSUM_BYTES;
const MAX_STATE_BYTES: u64 = (MIN_STATE_BYTES + MAX_BUNDLE_BYTES) as u64;
#[cfg(unix)]
const STATE_MODE: u32 = 0o600;
#[cfg(unix)]
const DIRECTORY_MODE: u32 = 0o700;
const ROOT_ID_DOMAIN: &[u8] = b"shadowpipe-policy-root-v1\0";
const STATE_HASH_DOMAIN: &[u8] = b"shadowpipe-policy-state-v1\0";
const EXPIRY_MAGIC: &[u8; 8] = b"SPPOLEX1";
const EXPIRY_VERSION: u16 = 1;
const EXPIRY_BYTES: usize = 8 + 2 + 2 + 32 + 32 + 8 + 8 + 8 + CHECKSUM_BYTES;
const EXPIRY_HASH_DOMAIN: &[u8] = b"shadowpipe-policy-expiry-v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
struct DiskState {
    root_id: [u8; 32],
    max_issued_at: i64,
    max_wall_clock_seen: i64,
    accepted_bundle: Vec<u8>,
}

/// Exact identity of one durably accepted endpoint policy.
///
/// A runtime keeps this private capability beside its verified plan.  Expiry
/// checkpointing reloads the durable policy anchor under the policy lock and
/// refuses publication unless every field still matches, so a delayed runtime
/// cannot retire a newer accepted successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyExpiryCheckpoint {
    root_id: [u8; 32],
    policy_hash: [u8; 32],
    policy_epoch: u64,
    sequence: u64,
    expires_at: i64,
}

impl PolicyExpiryCheckpoint {
    pub fn from_state(state: &AcceptedPolicyState) -> Self {
        let accepted = state.accepted();
        Self {
            root_id: *accepted.root_id(),
            policy_hash: *accepted.policy_hash(),
            policy_epoch: state.plan().policy_epoch(),
            sequence: state.plan().sequence(),
            expires_at: state.plan().expires_at(),
        }
    }
}

fn root_id(root: &TrustedRoot) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ROOT_ID_DOMAIN);
    digest.update(root.kid.as_bytes());
    digest.update(root.ed25519_public_key);
    digest.finalize().into()
}

fn state_checksum(contents_without_checksum: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(STATE_HASH_DOMAIN);
    digest.update(contents_without_checksum);
    digest.finalize().into()
}

fn expiry_checksum(contents_without_checksum: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(EXPIRY_HASH_DOMAIN);
    digest.update(contents_without_checksum);
    digest.finalize().into()
}

fn encode_expiry(checkpoint: &PolicyExpiryCheckpoint) -> Result<[u8; EXPIRY_BYTES]> {
    anyhow::ensure!(
        checkpoint.expires_at >= 0,
        "policy-expiry tombstone contains a negative signed expiry"
    );
    let mut bytes = [0u8; EXPIRY_BYTES];
    let mut cursor = 0usize;
    for field in [
        EXPIRY_MAGIC.as_slice(),
        &EXPIRY_VERSION.to_be_bytes(),
        &RESERVED.to_be_bytes(),
        &checkpoint.root_id,
        &checkpoint.policy_hash,
        &checkpoint.policy_epoch.to_be_bytes(),
        &checkpoint.sequence.to_be_bytes(),
        &checkpoint.expires_at.to_be_bytes(),
    ] {
        let end = cursor + field.len();
        bytes[cursor..end].copy_from_slice(field);
        cursor = end;
    }
    let checksum = expiry_checksum(&bytes[..cursor]);
    bytes[cursor..].copy_from_slice(&checksum);
    Ok(bytes)
}

fn decode_expiry(input: &[u8], expected_root_id: [u8; 32]) -> Result<PolicyExpiryCheckpoint> {
    anyhow::ensure!(
        input.len() == EXPIRY_BYTES,
        "policy-expiry tombstone has invalid length {}",
        input.len()
    );
    let authenticated_len = EXPIRY_BYTES - CHECKSUM_BYTES;
    let expected_checksum = expiry_checksum(&input[..authenticated_len]);
    anyhow::ensure!(
        ct_eq(&expected_checksum, &input[authenticated_len..]),
        "policy-expiry tombstone checksum mismatch"
    );

    let mut cursor = 0usize;
    anyhow::ensure!(
        take_array::<8>(input, &mut cursor)? == *EXPIRY_MAGIC,
        "bad policy-expiry tombstone magic"
    );
    anyhow::ensure!(
        u16::from_be_bytes(take_array(input, &mut cursor)?) == EXPIRY_VERSION,
        "unsupported policy-expiry tombstone version"
    );
    anyhow::ensure!(
        u16::from_be_bytes(take_array(input, &mut cursor)?) == RESERVED,
        "non-zero reserved policy-expiry tombstone field"
    );
    let actual_root_id = take_array::<32>(input, &mut cursor)?;
    anyhow::ensure!(
        ct_eq(&actual_root_id, &expected_root_id),
        "policy-expiry tombstone belongs to a different offline root"
    );
    let policy_hash = take_array::<32>(input, &mut cursor)?;
    let policy_epoch = u64::from_be_bytes(take_array(input, &mut cursor)?);
    let sequence = u64::from_be_bytes(take_array(input, &mut cursor)?);
    let expires_at = i64::from_be_bytes(take_array(input, &mut cursor)?);
    anyhow::ensure!(
        expires_at >= 0,
        "policy-expiry tombstone contains a negative signed expiry"
    );
    anyhow::ensure!(
        cursor == authenticated_len,
        "policy-expiry tombstone has trailing authenticated fields"
    );
    Ok(PolicyExpiryCheckpoint {
        root_id: actual_root_id,
        policy_hash,
        policy_epoch,
        sequence,
        expires_at,
    })
}

fn encode_disk(state: &DiskState) -> Result<Vec<u8>> {
    anyhow::ensure!(
        state.max_issued_at >= 0 && state.max_wall_clock_seen >= 0,
        "policy-state time floors must be non-negative"
    );
    anyhow::ensure!(
        !state.accepted_bundle.is_empty() && state.accepted_bundle.len() <= MAX_BUNDLE_BYTES,
        "accepted policy bundle must contain 1..={MAX_BUNDLE_BYTES} bytes"
    );
    let bundle_len: u32 = state
        .accepted_bundle
        .len()
        .try_into()
        .context("policy bundle length does not fit u32")?;
    let mut bytes = Vec::with_capacity(MIN_STATE_BYTES + state.accepted_bundle.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&RESERVED.to_be_bytes());
    bytes.extend_from_slice(&state.root_id);
    bytes.extend_from_slice(&state.max_issued_at.to_be_bytes());
    bytes.extend_from_slice(&state.max_wall_clock_seen.to_be_bytes());
    bytes.extend_from_slice(&bundle_len.to_be_bytes());
    bytes.extend_from_slice(&state.accepted_bundle);
    let checksum = state_checksum(&bytes);
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

fn take_array<const N: usize>(input: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    let end = cursor
        .checked_add(N)
        .context("policy-state cursor overflow")?;
    let value: [u8; N] = input
        .get(*cursor..end)
        .context("truncated policy-state envelope")?
        .try_into()
        .expect("slice length checked");
    *cursor = end;
    Ok(value)
}

fn decode_disk(input: &[u8], expected_root_id: [u8; 32]) -> Result<DiskState> {
    anyhow::ensure!(
        (MIN_STATE_BYTES..=MAX_STATE_BYTES as usize).contains(&input.len()),
        "policy-state envelope has invalid length {}",
        input.len()
    );
    let authenticated_len = input
        .len()
        .checked_sub(CHECKSUM_BYTES)
        .context("truncated policy-state checksum")?;
    let expected_checksum = state_checksum(&input[..authenticated_len]);
    anyhow::ensure!(
        ct_eq(&expected_checksum, &input[authenticated_len..]),
        "policy-state checksum mismatch"
    );

    let mut cursor = 0usize;
    anyhow::ensure!(
        take_array::<8>(input, &mut cursor)? == *MAGIC,
        "bad policy-state magic"
    );
    anyhow::ensure!(
        u16::from_be_bytes(take_array(input, &mut cursor)?) == VERSION,
        "unsupported policy-state version"
    );
    anyhow::ensure!(
        u16::from_be_bytes(take_array(input, &mut cursor)?) == RESERVED,
        "non-zero reserved policy-state field"
    );
    let actual_root_id = take_array::<32>(input, &mut cursor)?;
    anyhow::ensure!(
        ct_eq(&actual_root_id, &expected_root_id),
        "policy-state belongs to a different offline root"
    );
    let max_issued_at = i64::from_be_bytes(take_array(input, &mut cursor)?);
    let max_wall_clock_seen = i64::from_be_bytes(take_array(input, &mut cursor)?);
    anyhow::ensure!(
        max_issued_at >= 0 && max_wall_clock_seen >= 0,
        "policy-state contains a negative time floor"
    );
    let bundle_len = u32::from_be_bytes(take_array(input, &mut cursor)?) as usize;
    anyhow::ensure!(
        (1..=MAX_BUNDLE_BYTES).contains(&bundle_len),
        "policy-state bundle length is outside its bound"
    );
    let bundle_end = cursor
        .checked_add(bundle_len)
        .context("policy-state bundle length overflow")?;
    anyhow::ensure!(
        bundle_end == authenticated_len,
        "policy-state length is non-canonical or has trailing bytes"
    );
    let accepted_bundle = input
        .get(cursor..bundle_end)
        .context("truncated accepted policy bundle")?
        .to_vec();
    Ok(DiskState {
        root_id: actual_root_id,
        max_issued_at,
        max_wall_clock_seen,
        accepted_bundle,
    })
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn effective_uid() -> u32 {
    0
}

fn validate_directory(path: &Path, _expected_uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat policy-state directory {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "policy-state parent is not a directory: {}",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        anyhow::ensure!(
            metadata.uid() == _expected_uid,
            "policy-state directory {} is owned by UID {}, expected {}",
            path.display(),
            metadata.uid(),
            _expected_uid
        );
        let mode = metadata.permissions().mode() & 0o777;
        anyhow::ensure!(
            mode == DIRECTORY_MODE,
            "policy-state directory {} has mode {:04o}, expected {:04o}",
            path.display(),
            mode,
            DIRECTORY_MODE
        );
    }
    Ok(())
}

fn validate_file(path: &Path, metadata: &Metadata, _expected_uid: u32) -> Result<()> {
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "policy-state path is not a regular file: {}",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        anyhow::ensure!(
            metadata.uid() == _expected_uid,
            "policy-state {} is owned by UID {}, expected {}",
            path.display(),
            metadata.uid(),
            _expected_uid
        );
        let mode = metadata.permissions().mode() & 0o777;
        anyhow::ensure!(
            mode == STATE_MODE,
            "policy-state {} has mode {:04o}, expected {:04o}",
            path.display(),
            mode,
            STATE_MODE
        );
        anyhow::ensure!(
            metadata.nlink() == 1,
            "policy-state {} has {} hard links, expected one",
            path.display(),
            metadata.nlink()
        );
    }
    anyhow::ensure!(
        metadata.len() <= MAX_STATE_BYTES,
        "policy-state {} is too large: {} bytes",
        path.display(),
        metadata.len()
    );
    Ok(())
}

fn open_readonly_nofollow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    options
        .open(path)
        .with_context(|| format!("open policy-state {}", path.display()))
}

fn read_bounded(path: &Path, expected_uid: u32) -> Result<Vec<u8>> {
    validate_directory(parent(path)?, expected_uid)?;
    let file = open_readonly_nofollow(path)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat opened policy-state {}", path.display()))?;
    validate_file(path, &metadata, expected_uid)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read policy-state {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_STATE_BYTES,
        "policy-state grew beyond its read bound"
    );
    Ok(bytes)
}

struct PendingTemp {
    path: PathBuf,
    published: bool,
}

impl Drop for PendingTemp {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn parent(path: &Path) -> Result<&Path> {
    path.parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .context("policy-state path has no parent directory")
}

fn stage(path: &Path, bytes: &[u8], expected_uid: u32) -> Result<PendingTemp> {
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_STATE_BYTES,
        "policy-state is too large"
    );
    let directory = parent(path)?;
    validate_directory(directory, expected_uid)?;
    let file_name = path
        .file_name()
        .context("policy-state path has no file name")?
        .to_string_lossy();
    for _ in 0..32 {
        let mut nonce = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .context("obtain policy-state temp-name entropy")?;
        let temp = directory.join(format!(
            ".{file_name}.{}-{}.tmp",
            std::process::id(),
            hex::encode(nonce)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(STATE_MODE)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut output = match options.open(&temp) {
            Ok(output) => output,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("create policy-state temp file"),
        };
        let pending = PendingTemp {
            path: temp.clone(),
            published: false,
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            output
                .set_permissions(fs::Permissions::from_mode(STATE_MODE))
                .context("chmod policy-state temp file")?;
        }
        let metadata = output.metadata().context("stat policy-state temp file")?;
        validate_file(&temp, &metadata, expected_uid)?;
        output
            .write_all(bytes)
            .context("write policy-state temp file")?;
        output.sync_all().context("fsync policy-state temp file")?;
        drop(output);
        return Ok(pending);
    }
    anyhow::bail!("policy-state temp-name collision limit reached")
}

fn sync_parent(path: &Path) -> Result<()> {
    let directory = parent(path)?;
    File::open(directory)
        .and_then(|file| file.sync_all())
        .with_context(|| format!("fsync policy-state directory {}", directory.display()))
}

#[cfg(target_os = "linux")]
fn publish_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let from = CString::new(from.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "temp path contains NUL"))?;
    let to = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "state path contains NUL"))?;
    // SAFETY: both C strings live for the syscall and contain no interior NUL.
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn publish_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    fs::hard_link(from, to)?;
    fs::remove_file(from)
}

#[derive(Clone, Debug)]
pub struct PolicyStateStore {
    path: PathBuf,
    expected_uid: u32,
}

impl PolicyStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            expected_uid: effective_uid(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock_path(&self) -> Result<PathBuf> {
        let name = self
            .path
            .file_name()
            .context("policy-state path has no file name")?
            .to_string_lossy();
        Ok(parent(&self.path)?.join(format!(".{name}.lock")))
    }

    fn expiry_path(&self) -> Result<PathBuf> {
        let name = self
            .path
            .file_name()
            .context("policy-state path has no file name")?
            .to_string_lossy();
        Ok(parent(&self.path)?.join(format!("{name}.expired-v1")))
    }

    fn acquire_lock(&self) -> Result<HostStateLease> {
        validate_directory(parent(&self.path)?, self.expected_uid)?;
        let path = self.lock_path()?;
        HostStateLease::try_acquire(&path).map_err(|error| match error {
            LeaseError::Busy { .. } => anyhow::anyhow!(
                "another process is updating signed policy-state {}",
                self.path.display()
            ),
            other => anyhow::Error::new(other),
        })
    }

    fn load_expiry(&self, root: &TrustedRoot) -> Result<Option<PolicyExpiryCheckpoint>> {
        let path = self.expiry_path()?;
        let bytes = match read_bounded(&path, self.expected_uid) {
            Ok(bytes) => bytes,
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|source| source.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        decode_expiry(&bytes, root_id(root)).map(Some)
    }

    fn ensure_not_tombstoned(
        &self,
        root: &TrustedRoot,
        accepted: &crate::signed_policy::VerifiedBundle,
    ) -> Result<()> {
        let Some(tombstone) = self.load_expiry(root)? else {
            return Ok(());
        };
        if !ct_eq(&tombstone.policy_hash, accepted.policy_hash()) {
            return Ok(());
        }
        let plan = accepted.plan();
        anyhow::ensure!(
            tombstone.policy_epoch == plan.policy_epoch()
                && tombstone.sequence == plan.sequence()
                && tombstone.expires_at == plan.expires_at(),
            "policy-expiry tombstone identity conflicts with the accepted policy"
        );
        anyhow::bail!(
            "signed endpoint policy ({},{}) was durably retired at signed expiry {}",
            tombstone.policy_epoch,
            tombstone.sequence,
            tombstone.expires_at
        )
    }

    /// Historical anchor loader used only while applying a successor. The
    /// embedded bundle is re-verified at the recorded acceptance time so an
    /// expired predecessor can still authenticate a fresh hash-chain update.
    fn load_anchor(&self, root: &TrustedRoot) -> Result<Option<AcceptedPolicyState>> {
        let bytes = match read_bounded(&self.path, self.expected_uid) {
            Ok(bytes) => bytes,
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|source| source.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        let disk = decode_disk(&bytes, root_id(root))?;
        let accepted = verify_bundle(&disk.accepted_bundle, root, disk.max_wall_clock_seen)
            .context("re-verify accepted policy-state bundle")?;
        let accepted_max_issued = accepted.keyset.issued_at.max(accepted.policy.issued_at);
        anyhow::ensure!(
            accepted_max_issued <= disk.max_issued_at,
            "policy-state issued_at floor is below its accepted bundle"
        );
        Ok(Some(AcceptedPolicyState {
            accepted,
            max_issued_at: disk.max_issued_at,
            max_wall_clock_seen: disk.max_wall_clock_seen,
        }))
    }

    /// Load a policy for live use at `now`. Unlike transition-anchor recovery,
    /// this rejects expiry and a wall clock that moved behind the durable floor.
    pub fn load_active(&self, root: &TrustedRoot, now: i64) -> Result<AcceptedPolicyState> {
        let _lock = self.acquire_lock()?;
        let bytes = read_bounded(&self.path, self.expected_uid)?;
        let disk = decode_disk(&bytes, root_id(root))?;
        anyhow::ensure!(
            now.saturating_add(crate::signed_policy::MAX_CLOCK_SKEW_SECS)
                >= disk.max_wall_clock_seen,
            "current wall clock is behind the signed-policy floor"
        );
        let accepted = verify_bundle(&disk.accepted_bundle, root, now)
            .context("verify currently active policy-state bundle")?;
        let accepted_max_issued = accepted.keyset().issued_at.max(accepted.policy().issued_at);
        anyhow::ensure!(
            accepted_max_issued <= disk.max_issued_at,
            "policy-state issued_at floor is below its accepted bundle"
        );
        self.ensure_not_tombstoned(root, &accepted)?;
        Ok(AcceptedPolicyState {
            accepted,
            max_issued_at: disk.max_issued_at,
            max_wall_clock_seen: disk.max_wall_clock_seen,
        })
    }

    /// Verify, apply anti-rollback/rotation rules, then durably publish the new
    /// floor. Callers must complete this before DNS, sockets, TUN, or host
    /// mutations. The production client holds the global host-state lease while
    /// calling this method, serializing competing full-tunnel writers.
    pub fn enroll(
        &self,
        root: &TrustedRoot,
        candidate_bundle: &[u8],
        now: i64,
    ) -> Result<Transition> {
        let _lock = self.acquire_lock()?;
        anyhow::ensure!(
            self.load_anchor(root)?.is_none(),
            "policy-state already exists; enrollment is one-time"
        );
        let candidate = verify_bundle(candidate_bundle, root, now)
            .context("verify candidate signed endpoint policy")?;
        self.ensure_not_tombstoned(root, &candidate)?;
        let transition = apply_verified_update(None, candidate, now)
            .context("apply signed-policy anti-rollback transition")?;
        self.persist_transition(root, candidate_bundle, &transition, false)?;
        Ok(transition)
    }

    /// Apply a successor to an existing durable anchor. Missing state is a
    /// hard failure: callers must never silently reinterpret storage loss as a
    /// fresh trust enrollment.
    pub fn update(
        &self,
        root: &TrustedRoot,
        candidate_bundle: &[u8],
        now: i64,
    ) -> Result<Transition> {
        let _lock = self.acquire_lock()?;
        let previous = self.load_anchor(root)?.ok_or_else(|| {
            anyhow::anyhow!(
                "policy-state {} is missing; explicit one-time enrollment is required",
                self.path.display()
            )
        })?;
        let candidate = verify_bundle(candidate_bundle, root, now)
            .context("verify candidate signed endpoint policy")?;
        self.ensure_not_tombstoned(root, &candidate)?;
        let transition = apply_verified_update(Some(&previous), candidate, now)
            .context("apply signed-policy anti-rollback transition")?;
        self.persist_transition(root, candidate_bundle, &transition, true)?;
        Ok(transition)
    }

    /// Durably retire the exact policy identified by `checkpoint`.
    ///
    /// The current anchor is reloaded and matched under the same policy lock
    /// used by enrollment and updates. A stale runtime therefore cannot
    /// tombstone a successor. Existing tombstone corruption or unsafe file
    /// topology is a hard error rather than something this method overwrites.
    pub fn checkpoint_expired(
        &self,
        root: &TrustedRoot,
        checkpoint: &PolicyExpiryCheckpoint,
    ) -> Result<()> {
        let _lock = self.acquire_lock()?;
        anyhow::ensure!(
            ct_eq(&checkpoint.root_id, &root_id(root)),
            "policy-expiry checkpoint belongs to a different offline root"
        );
        let current = self.load_anchor(root)?.ok_or_else(|| {
            anyhow::anyhow!(
                "policy-state {} is missing; refusing expiry checkpoint",
                self.path.display()
            )
        })?;
        let exact_current = PolicyExpiryCheckpoint::from_state(&current);
        anyhow::ensure!(
            &exact_current == checkpoint,
            "policy-expiry checkpoint does not match the current durable policy"
        );

        if let Some(existing) = self.load_expiry(root)? {
            if existing == *checkpoint {
                return Ok(());
            }
            anyhow::ensure!(
                !ct_eq(&existing.policy_hash, &checkpoint.policy_hash),
                "policy-expiry tombstone has conflicting metadata for the same policy hash"
            );
        }

        let path = self.expiry_path()?;
        let bytes = encode_expiry(checkpoint)?;
        let mut pending = stage(&path, &bytes, self.expected_uid)?;
        fs::rename(&pending.path, &path).with_context(|| {
            format!(
                "atomically replace policy-expiry tombstone {}",
                path.display()
            )
        })?;
        pending.published = true;
        sync_parent(&path)
    }

    fn persist_transition(
        &self,
        root: &TrustedRoot,
        candidate_bundle: &[u8],
        transition: &Transition,
        replacing: bool,
    ) -> Result<()> {
        let state = transition.state();
        let disk = DiskState {
            root_id: root_id(root),
            max_issued_at: state.max_issued_at(),
            max_wall_clock_seen: state.max_wall_clock_seen(),
            accepted_bundle: candidate_bundle.to_vec(),
        };
        let encoded = encode_disk(&disk)?;
        self.publish(&encoded, replacing)
    }

    fn publish(&self, bytes: &[u8], replacing: bool) -> Result<()> {
        let mut pending = stage(&self.path, bytes, self.expected_uid)?;
        if replacing {
            fs::rename(&pending.path, &self.path).with_context(|| {
                format!("atomically replace policy-state {}", self.path.display())
            })?;
        } else {
            publish_noreplace(&pending.path, &self.path).with_context(|| {
                format!("atomically create policy-state {}", self.path.display())
            })?;
        }
        pending.published = true;
        sync_parent(&self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::TryInto;
    use std::net::Ipv4Addr;

    use minicbor::Encoder;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use crate::signed_policy::{
        encode_bundle, encode_keyset_payload, encode_policy_payload, encode_protected_header,
        keyset_payload_hash, signature_structure, BundleBytes, ContentType, EndpointId,
        EndpointPolicyV2, KeyStatus, OnlineKeyV1, PinStatus, PolicyRuleV2, ProtectedHeader,
        RealityEndpointV2, RuleAction, ServerPinV2, ServiceId, ServiceV2, TransportV2,
    };

    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};

    const FIXTURE_NOW: i64 = 2_000_000_000;
    const DAY: i64 = 24 * 60 * 60;
    const ROOT_KID: crate::signed_policy::Kid = crate::signed_policy::Kid::new([0x10; 16]);
    const ONLINE_KID: crate::signed_policy::Kid = crate::signed_policy::Kid::new([0x20; 16]);
    const SERVICE_ID: ServiceId = ServiceId::new([0x30; 16]);
    const ENDPOINT_ID: EndpointId = EndpointId::new([0x40; 16]);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let mut nonce = [0u8; 8];
            OsRng.fill_bytes(&mut nonce);
            let path = std::env::temp_dir().join(format!(
                "shadowpipe-policy-state-{}-{}",
                std::process::id(),
                hex::encode(nonce)
            ));
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn disk() -> DiskState {
        DiskState {
            root_id: [0xA5; 32],
            max_issued_at: 123,
            max_wall_clock_seen: 456,
            accepted_bundle: vec![1, 2, 3, 4],
        }
    }

    fn trust() -> TrustedRoot {
        TrustedRoot {
            kid: crate::signed_policy::Kid::new([0x11; 16]),
            ed25519_public_key: [0x22; 32],
        }
    }

    struct SignedFixture {
        root: Ed25519KeyPair,
        online: Ed25519KeyPair,
        trust: TrustedRoot,
        keyset: crate::signed_policy::KeysetV1,
        policy: EndpointPolicyV2,
    }

    impl SignedFixture {
        fn new() -> Self {
            let root = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).expect("fixed root test seed");
            let online =
                Ed25519KeyPair::from_seed_unchecked(&[2; 32]).expect("fixed online test seed");
            let public_key = |pair: &Ed25519KeyPair| -> [u8; 32] {
                pair.public_key().as_ref().try_into().unwrap()
            };
            let keyset_not_before = FIXTURE_NOW - 60;
            let keyset_expires_at = FIXTURE_NOW + 60 * DAY;
            let keyset = crate::signed_policy::KeysetV1 {
                keyset_epoch: 0,
                issued_at: FIXTURE_NOW,
                not_before: keyset_not_before,
                expires_at: keyset_expires_at,
                previous_payload_hash: None,
                keys: vec![OnlineKeyV1 {
                    kid: ONLINE_KID,
                    ed25519_public_key: public_key(&online),
                    not_before: keyset_not_before,
                    expires_at: keyset_expires_at,
                    status: KeyStatus::Active,
                    status_since: keyset_not_before,
                }],
            };
            let policy = EndpointPolicyV2 {
                keyset_epoch: 0,
                keyset_payload_hash: [0; 32],
                policy_epoch: 0,
                sequence: 0,
                issued_at: FIXTURE_NOW,
                not_before: FIXTURE_NOW - 60,
                expires_at: FIXTURE_NOW + 6 * DAY,
                previous_payload_hash: None,
                services: vec![ServiceV2 {
                    service_id: SERVICE_ID,
                    pins: vec![ServerPinV2 {
                        fingerprint: [0x50; 32],
                        not_before: FIXTURE_NOW - 60,
                        expires_at: keyset_expires_at,
                        status: PinStatus::Active,
                        status_since: FIXTURE_NOW - 60,
                    }],
                    endpoints: vec![RealityEndpointV2 {
                        endpoint_id: ENDPOINT_ID,
                        transport: TransportV2::RealityTcp,
                        ipv4: Ipv4Addr::new(203, 0, 113, 10),
                        port: 443,
                        locator_name: "edge.shadowpipe.example".into(),
                        sni: "cdn.example.com".into(),
                        reality_x25519_public_key: [0x60; 32],
                        reality_short_id: vec![0x70; 8],
                    }],
                }],
                rules: vec![PolicyRuleV2 {
                    action: RuleAction::ProtectedOnly,
                    service_ids: vec![SERVICE_ID],
                }],
                experiment_evidence: vec![],
            };
            let trust = TrustedRoot {
                kid: ROOT_KID,
                ed25519_public_key: public_key(&root),
            };
            Self {
                root,
                online,
                trust,
                keyset,
                policy,
            }
        }

        fn sign1(
            &self,
            content_type: ContentType,
            kid: crate::signed_policy::Kid,
            payload: &[u8],
            pair: &Ed25519KeyPair,
        ) -> Vec<u8> {
            let protected =
                encode_protected_header(&ProtectedHeader { content_type, kid }).unwrap();
            let signature_input = signature_structure(&protected, payload).unwrap();
            let signature = pair.sign(&signature_input);
            let mut output = vec![0xd2];
            let mut encoder = Encoder::new(output);
            encoder.array(4).unwrap();
            encoder.bytes(&protected).unwrap();
            encoder.map(0).unwrap();
            encoder.bytes(payload).unwrap();
            encoder.bytes(signature.as_ref()).unwrap();
            output = encoder.into_writer();
            output
        }

        fn bundle(&self, mut policy: EndpointPolicyV2) -> Vec<u8> {
            let keyset_payload = encode_keyset_payload(&self.keyset).unwrap();
            policy.keyset_epoch = self.keyset.keyset_epoch;
            policy.keyset_payload_hash = keyset_payload_hash(&keyset_payload);
            let policy_payload = encode_policy_payload(&policy).unwrap();
            encode_bundle(&BundleBytes {
                keyset_sign1: self.sign1(
                    ContentType::Keyset,
                    ROOT_KID,
                    &keyset_payload,
                    &self.root,
                ),
                policy_sign1: self.sign1(
                    ContentType::EndpointPolicy,
                    ONLINE_KID,
                    &policy_payload,
                    &self.online,
                ),
            })
            .unwrap()
        }

        fn genesis(&self) -> Vec<u8> {
            self.bundle(self.policy.clone())
        }

        fn successor(&self, previous_hash: [u8; 32]) -> Vec<u8> {
            let mut policy = self.policy.clone();
            policy.sequence = 1;
            policy.issued_at = FIXTURE_NOW + 60;
            policy.previous_payload_hash = Some(previous_hash);
            self.bundle(policy)
        }
    }

    #[test]
    fn absent_state_requires_explicit_enrollment() {
        let dir = TestDir::new();
        let store = PolicyStateStore::new(dir.path("missing.bin"));
        assert!(store.load_anchor(&trust()).unwrap().is_none());
        let error = store
            .update(&trust(), b"not-even-decoded", 123)
            .unwrap_err();
        assert!(error.to_string().contains("explicit one-time enrollment"));
        assert!(store.load_active(&trust(), 123).is_err());
    }

    #[test]
    fn binary_envelope_round_trips_and_is_root_bound() {
        let state = disk();
        let encoded = encode_disk(&state).unwrap();
        assert_eq!(decode_disk(&encoded, state.root_id).unwrap(), state);
        assert!(decode_disk(&encoded, [0x5A; 32])
            .unwrap_err()
            .to_string()
            .contains("different offline root"));
    }

    #[test]
    fn fixed_expiry_tombstone_round_trips_and_is_root_bound() {
        let checkpoint = PolicyExpiryCheckpoint {
            root_id: [0xA5; 32],
            policy_hash: [0x5A; 32],
            policy_epoch: 7,
            sequence: 11,
            expires_at: 456,
        };
        let encoded = encode_expiry(&checkpoint).unwrap();
        assert_eq!(encoded.len(), EXPIRY_BYTES);
        assert_eq!(
            decode_expiry(&encoded, checkpoint.root_id).unwrap(),
            checkpoint
        );
        assert!(decode_expiry(&encoded, [0x44; 32])
            .unwrap_err()
            .to_string()
            .contains("different offline root"));

        let mut tampered = encoded;
        tampered[EXPIRY_BYTES - 1] ^= 1;
        assert!(decode_expiry(&tampered, checkpoint.root_id)
            .unwrap_err()
            .to_string()
            .contains("checksum mismatch"));
    }

    #[test]
    fn envelope_rejects_tamper_truncation_trailing_and_noncanonical_length() {
        let state = disk();
        let encoded = encode_disk(&state).unwrap();
        for index in [0, PREFIX_BYTES, encoded.len() - 1] {
            let mut tampered = encoded.clone();
            tampered[index] ^= 1;
            assert!(decode_disk(&tampered, state.root_id).is_err());
        }
        assert!(decode_disk(&encoded[..encoded.len() - 1], state.root_id).is_err());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_disk(&trailing, state.root_id).is_err());

        let mut wrong_length = encoded.clone();
        let bundle_len_offset = PREFIX_BYTES - 4;
        wrong_length[bundle_len_offset..PREFIX_BYTES].copy_from_slice(&99u32.to_be_bytes());
        let authenticated_len = wrong_length.len() - CHECKSUM_BYTES;
        let checksum = state_checksum(&wrong_length[..authenticated_len]);
        wrong_length[authenticated_len..].copy_from_slice(&checksum);
        assert!(decode_disk(&wrong_length, state.root_id).is_err());
    }

    #[test]
    fn secure_publish_is_atomic_bounded_and_non_overwriting_on_create() {
        let dir = TestDir::new();
        let path = dir.path("state.bin");
        let store = PolicyStateStore::new(&path);
        let encoded = encode_disk(&disk()).unwrap();
        store.publish(&encoded, false).unwrap();
        assert_eq!(fs::read(&path).unwrap(), encoded);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            STATE_MODE
        );
        assert!(store.publish(b"replacement", false).is_err());
        assert_eq!(fs::read(&path).unwrap(), encoded);
    }

    #[cfg(unix)]
    #[test]
    fn read_rejects_symlink_wrong_mode_and_hardlink() {
        let dir = TestDir::new();
        let target = dir.path("target.bin");
        fs::write(&target, encode_disk(&disk()).unwrap()).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(STATE_MODE)).unwrap();

        let link = dir.path("link.bin");
        symlink(&target, &link).unwrap();
        assert!(read_bounded(&link, effective_uid()).is_err());

        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_bounded(&target, effective_uid()).is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(STATE_MODE)).unwrap();

        let hard = dir.path("hard.bin");
        fs::hard_link(&target, &hard).unwrap();
        assert!(read_bounded(&target, effective_uid()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_parent_mode_is_rejected_before_staging() {
        let dir = TestDir::new();
        let existing = dir.path("existing.bin");
        fs::write(&existing, encode_disk(&disk()).unwrap()).unwrap();
        fs::set_permissions(&existing, fs::Permissions::from_mode(STATE_MODE)).unwrap();
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.path("state.bin");
        assert!(stage(&path, &encode_disk(&disk()).unwrap(), effective_uid()).is_err());
        assert!(read_bounded(&existing, effective_uid()).is_err());
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn policy_lock_serializes_the_complete_read_verify_publish_window() {
        let dir = TestDir::new();
        let store = PolicyStateStore::new(dir.path("state.bin"));
        let first = store.acquire_lock().unwrap();
        assert!(store.acquire_lock().is_err());
        drop(first);
        store.acquire_lock().unwrap();
    }

    #[test]
    fn orderly_expiry_survives_wall_clock_rollback_and_allows_a_successor() {
        let dir = TestDir::new();
        let fixture = SignedFixture::new();
        let genesis = fixture.genesis();
        let store = PolicyStateStore::new(dir.path("state.bin"));
        let accepted = store
            .enroll(&fixture.trust, &genesis, FIXTURE_NOW)
            .unwrap()
            .into_state();
        let previous_hash = *accepted.accepted().policy_hash();
        let checkpoint = PolicyExpiryCheckpoint::from_state(&accepted);

        // Models an orderly long-running process reaching its monotonic signed
        // expiry and fsyncing the checkpoint before exit. The restarted process
        // then observes a rolled-back wall clock at which the bundle looks live.
        store
            .checkpoint_expired(&fixture.trust, &checkpoint)
            .unwrap();
        store
            .checkpoint_expired(&fixture.trust, &checkpoint)
            .unwrap();
        let expiry_path = store.expiry_path().unwrap();
        assert_eq!(
            fs::metadata(&expiry_path).unwrap().len(),
            EXPIRY_BYTES as u64
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::metadata(&expiry_path).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, STATE_MODE);
            assert_eq!(metadata.nlink(), 1);
        }
        let restarted = PolicyStateStore::new(store.path());
        let rolled_back_now = FIXTURE_NOW + 120;
        assert!(restarted
            .load_active(&fixture.trust, rolled_back_now)
            .unwrap_err()
            .to_string()
            .contains("durably retired"));
        assert!(restarted
            .update(&fixture.trust, &genesis, rolled_back_now)
            .unwrap_err()
            .to_string()
            .contains("durably retired"));

        let successor = fixture.successor(previous_hash);
        let transition = restarted
            .update(&fixture.trust, &successor, rolled_back_now)
            .unwrap();
        assert!(matches!(transition, Transition::Applied(_)));
        assert_eq!(
            restarted
                .load_active(&fixture.trust, rolled_back_now)
                .unwrap()
                .plan()
                .sequence(),
            1
        );
    }

    #[test]
    fn missing_anchor_cannot_reenroll_a_tombstoned_policy() {
        let dir = TestDir::new();
        let fixture = SignedFixture::new();
        let genesis = fixture.genesis();
        let store = PolicyStateStore::new(dir.path("state.bin"));
        let accepted = store
            .enroll(&fixture.trust, &genesis, FIXTURE_NOW)
            .unwrap()
            .into_state();
        store
            .checkpoint_expired(
                &fixture.trust,
                &PolicyExpiryCheckpoint::from_state(&accepted),
            )
            .unwrap();
        fs::remove_file(store.path()).unwrap();

        let error = store
            .enroll(&fixture.trust, &genesis, FIXTURE_NOW + 120)
            .unwrap_err();
        assert!(error.to_string().contains("durably retired"));
        assert!(!store.path().exists());
    }

    #[test]
    fn stale_checkpoint_cannot_tombstone_a_successor() {
        let dir = TestDir::new();
        let fixture = SignedFixture::new();
        let genesis = fixture.genesis();
        let store = PolicyStateStore::new(dir.path("state.bin"));
        let accepted = store
            .enroll(&fixture.trust, &genesis, FIXTURE_NOW)
            .unwrap()
            .into_state();
        let stale_checkpoint = PolicyExpiryCheckpoint::from_state(&accepted);
        let successor = fixture.successor(*accepted.accepted().policy_hash());
        store
            .update(&fixture.trust, &successor, FIXTURE_NOW + 120)
            .unwrap();

        let error = store
            .checkpoint_expired(&fixture.trust, &stale_checkpoint)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("does not match the current durable policy"));
        assert!(!store.expiry_path().unwrap().exists());
        assert_eq!(
            store
                .load_active(&fixture.trust, FIXTURE_NOW + 120)
                .unwrap()
                .plan()
                .sequence(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_symlink_hardlink_and_wrong_root_tombstones_fail_closed() {
        for case in ["corrupt", "symlink", "hardlink", "wrong-root"] {
            let dir = TestDir::new();
            let fixture = SignedFixture::new();
            let genesis = fixture.genesis();
            let store = PolicyStateStore::new(dir.path("state.bin"));
            let accepted = store
                .enroll(&fixture.trust, &genesis, FIXTURE_NOW)
                .unwrap()
                .into_state();
            let checkpoint = PolicyExpiryCheckpoint::from_state(&accepted);
            store
                .checkpoint_expired(&fixture.trust, &checkpoint)
                .unwrap();
            let expiry = store.expiry_path().unwrap();
            match case {
                "corrupt" => {
                    let mut bytes = fs::read(&expiry).unwrap();
                    bytes[EXPIRY_BYTES - 1] ^= 1;
                    fs::write(&expiry, bytes).unwrap();
                }
                "symlink" => {
                    let target = dir.path("expiry-target.bin");
                    fs::rename(&expiry, &target).unwrap();
                    symlink(&target, &expiry).unwrap();
                }
                "hardlink" => {
                    let target = dir.path("expiry-target.bin");
                    fs::rename(&expiry, &target).unwrap();
                    fs::hard_link(&target, &expiry).unwrap();
                }
                "wrong-root" => {
                    let mut wrong = checkpoint.clone();
                    wrong.root_id = [0x99; 32];
                    fs::write(&expiry, encode_expiry(&wrong).unwrap()).unwrap();
                    fs::set_permissions(&expiry, fs::Permissions::from_mode(STATE_MODE)).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                store
                    .load_active(&fixture.trust, FIXTURE_NOW + 120)
                    .is_err(),
                "{case} tombstone must fail closed"
            );
        }
    }
}
