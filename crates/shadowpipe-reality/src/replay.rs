//! Bounded REALITY exact-replay admission.
//!
//! Production uses an authenticated fixed-slot file.  A process holds an
//! exclusive same-host lease for the lifetime of the cache, validates every
//! slot before the listener can bind, and persists a fresh token with
//! `sync_data` before the accepted REALITY flight is emitted.  Any ambiguity
//! (corruption, saturation, lock poison, or runtime I/O failure) fails forward:
//! the caller treats the token exactly like an unauthenticated probe.

use hmac::{Hmac, Mac};
#[cfg(unix)]
use sha2::Digest;
use sha2::Sha256;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs::File;
use std::io;
use std::path::Path;
#[cfg(unix)]
use std::path::{Component, PathBuf};
use std::sync::Mutex;
#[cfg(unix)]
use subtle::ConstantTimeEq;
#[cfg(unix)]
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Maximum accepted tokens retained during the active replay window. At the
/// production 120-second window this permits a sustained 136 fresh carrier
/// handshakes/second before failing forward. Established VPN sessions do not
/// consume additional entries.
pub const DEFAULT_REPLAY_CACHE_CAPACITY: usize = 16_384;

/// A single admission prunes at most this many expired entries. Expiry work is
/// thus strictly bounded under the mutex; if old entries temporarily occupy all
/// slots, the cache fails forward and later calls continue the cleanup.
pub(crate) const REPLAY_PRUNE_BUDGET: usize = 64;

const HEADER_SIZE: usize = 96;
const SLOT_SIZE: usize = 96;
#[cfg(unix)]
const STORE_MAGIC: &[u8; 8] = b"SPRPv001";
#[cfg(unix)]
const STORE_VERSION: u16 = 1;
const SLOT_LIVE: u8 = 1;
#[cfg(unix)]
const KEY_DERIVE_DOMAIN: &[u8] = b"shadowpipe/reality/replay-store/key/v1\0";
#[cfg(unix)]
const KEY_BINDING_DOMAIN: &[u8] = b"shadowpipe/reality/replay-store/static-public/v1\0";
#[cfg(unix)]
const HEADER_MAC_DOMAIN: &[u8] = b"shadowpipe/reality/replay-store/header/v1\0";
const SLOT_MAC_DOMAIN: &[u8] = b"shadowpipe/reality/replay-store/slot/v1\0";
const SID_DIGEST_DOMAIN: &[u8] = b"shadowpipe/reality/replay-store/session-id/v1\0";

/// Ownership policy for a durable replay store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayStoreOwner {
    /// Production: effective UID must be zero; directories and files must be
    /// root-owned, with the final store and lease files exact mode 0600.
    Root,
    /// Explicit no-TUN development: directories may be root-owned or owned by
    /// the effective user; final files must be owned by that user, exact 0600.
    EffectiveUser,
}

#[derive(Clone, Copy)]
struct ReplayEntry {
    valid_until: u64,
    slot: Option<usize>,
}

struct PersistentBackend {
    file: Option<File>,
    // The separate lease closes the create/open race and remains locked even if
    // the data file later suffers an I/O error.
    _lease: File,
}

enum ReplayBackend {
    Memory,
    #[cfg_attr(not(unix), allow(dead_code))]
    Persistent(PersistentBackend),
}

struct ReplayState {
    seen: HashMap<[u8; 32], ReplayEntry>,
    expiries: BTreeSet<(u64, [u8; 32])>,
    free_slots: VecDeque<usize>,
    generations: Vec<u64>,
    backend: ReplayBackend,
    fail_forward_reason: Option<String>,
}

/// A bounded exact-replay cache.
///
/// Production callers must use [`ReplayCache::open_persistent`]. The explicit
/// in-memory constructor exists only for hermetic protocol tests; it has no
/// restart or replica guarantee.
pub struct ReplayCache {
    state: Mutex<ReplayState>,
    capacity: usize,
    digest_key: Option<[u8; 32]>,
}

impl Drop for ReplayCache {
    fn drop(&mut self) {
        if let Some(key) = &mut self.digest_key {
            key.zeroize();
        }
    }
}

impl ReplayCache {
    /// Open or create the default-size authenticated fixed-slot store.
    ///
    /// The parent chain and both the data and lease files are validated before
    /// use. The lease is exclusive for the process lifetime. Existing slots are
    /// fully authenticated and loaded before this function returns. Authenticated
    /// content corruption returns an intentionally poisoned cache (inspect
    /// [`ReplayCache::fail_forward_reason`]); a static-key binding mismatch,
    /// unsafe path/ownership, or lock contention returns an error and should
    /// abort startup.
    pub fn open_persistent(
        path: &Path,
        static_secret: &StaticSecret,
        owner: ReplayStoreOwner,
    ) -> io::Result<Self> {
        Self::open_persistent_with_capacity(
            path,
            static_secret,
            owner,
            DEFAULT_REPLAY_CACHE_CAPACITY,
        )
    }

    /// Explicit process-local cache for hermetic tests only.
    ///
    /// This constructor deliberately says what it is: production server
    /// callsites must never use it because restart and replica replay state
    /// would be lost.
    pub fn in_memory_for_tests() -> Self {
        Self::in_memory_with_capacity(DEFAULT_REPLAY_CACHE_CAPACITY)
    }

    fn in_memory_with_capacity(capacity: usize) -> Self {
        debug_assert!(capacity > 0);
        Self {
            state: Mutex::new(ReplayState {
                seen: HashMap::with_capacity(capacity),
                expiries: BTreeSet::new(),
                free_slots: VecDeque::new(),
                generations: Vec::new(),
                backend: ReplayBackend::Memory,
                fail_forward_reason: None,
            }),
            capacity,
            digest_key: None,
        }
    }

    fn open_persistent_with_capacity(
        path: &Path,
        static_secret: &StaticSecret,
        owner: ReplayStoreOwner,
        capacity: usize,
    ) -> io::Result<Self> {
        if capacity == 0 || capacity > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "REALITY replay-store capacity is outside 1..=u32::MAX",
            ));
        }

        #[cfg(not(unix))]
        {
            let _ = (path, static_secret, owner);
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "durable REALITY replay stores require Unix ownership and no-follow semantics",
            ));
        }

        #[cfg(unix)]
        {
            let absolute = validate_parent_chain(path, owner)?;
            let lease_path = sibling_lease_path(&absolute)?;
            let (lease, lease_created) = open_private_file(&lease_path, owner)?;
            if lease_created {
                lease.set_len(0)?;
                lease.sync_all()?;
                sync_parent(&lease_path)?;
            }
            if lease.metadata()?.len() != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "REALITY replay-store lease file must be empty: {}",
                        lease_path.display()
                    ),
                ));
            }
            lease.try_lock().map_err(|error| match error {
                std::fs::TryLockError::WouldBlock => io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "REALITY replay store already has a same-host owner: {}",
                        absolute.display()
                    ),
                ),
                std::fs::TryLockError::Error(error) => io::Error::new(
                    error.kind(),
                    format!(
                        "lock REALITY replay-store lease {}: {error}",
                        lease_path.display()
                    ),
                ),
            })?;

            let (file, created) = open_private_file(&absolute, owner)?;
            file.try_lock().map_err(|error| match error {
                std::fs::TryLockError::WouldBlock => io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "REALITY replay-store data file is already locked: {}",
                        absolute.display()
                    ),
                ),
                std::fs::TryLockError::Error(error) => io::Error::new(
                    error.kind(),
                    format!(
                        "lock REALITY replay-store data file {}: {error}",
                        absolute.display()
                    ),
                ),
            })?;

            let key = derive_store_key(static_secret);
            let binding = static_key_binding(static_secret);
            let expected_len = store_len(capacity)?;
            if created {
                file.set_len(expected_len)?;
                let header = encode_header(capacity, &binding, &key);
                write_all_at(&file, &header, 0)?;
                file.sync_all()?;
                sync_parent(&absolute)?;
            }

            let backend = PersistentBackend {
                file: Some(file),
                _lease: lease,
            };
            let now = unix_now_secs();
            let mut state = ReplayState {
                seen: HashMap::with_capacity(capacity),
                expiries: BTreeSet::new(),
                free_slots: VecDeque::with_capacity(capacity),
                generations: vec![0; capacity],
                backend: ReplayBackend::Persistent(backend),
                fail_forward_reason: None,
            };

            if let Err(error) = load_store(&mut state, capacity, expected_len, &binding, &key, now)
            {
                if let Some(reason) = error.strip_prefix("STATIC_KEY_MISMATCH: ") {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        reason.to_string(),
                    ));
                }
                state.fail_forward_reason = Some(error);
                state.seen.clear();
                state.expiries.clear();
                state.free_slots.clear();
            }

            Ok(Self {
                state: Mutex::new(state),
                capacity,
                digest_key: Some(key),
            })
        }
    }

    /// Reason every otherwise-valid token is currently being failed forward.
    ///
    /// `None` means the cache is operational. A poisoned mutex is reported even
    /// though its internal reason cannot safely be read.
    pub fn fail_forward_reason(&self) -> Option<String> {
        match self.state.lock() {
            Ok(state) => state.fail_forward_reason.clone(),
            Err(_) => Some("REALITY replay-cache mutex is poisoned".to_string()),
        }
    }

    /// True if `sid` is fresh and durably recorded. `valid_until` is the
    /// token-derived absolute last acceptable Unix second, not a first-seen TTL.
    ///
    /// False means replay, expired input, saturation, corruption, runtime I/O
    /// failure, or lock poison. Every false outcome takes the
    /// indistinguishable forward-to-cover path.
    pub(crate) fn check_and_record(&self, sid: &[u8; 32], now: u64, valid_until: u64) -> bool {
        if valid_until < now {
            return false;
        }
        let digest = self
            .digest_key
            .as_ref()
            .map_or(*sid, |key| digest_session_id(key, sid));
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.fail_forward_reason.is_some() {
            return false;
        }

        prune_expired(&mut state, now, REPLAY_PRUNE_BUDGET);
        if let Some(entry) = state.seen.get(&digest).copied() {
            if entry.valid_until >= now {
                return false;
            }
            remove_entry(&mut state, digest, entry);
        }

        let selected = match &state.backend {
            ReplayBackend::Memory => {
                if state.seen.len() >= self.capacity {
                    return false;
                }
                None
            }
            ReplayBackend::Persistent(_) => {
                let Some(slot) = state.free_slots.pop_front() else {
                    return false;
                };
                Some(slot)
            }
        };

        if let Some(slot) = selected {
            let Some(generation) = state.generations[slot].checked_add(1) else {
                poison(
                    &mut state,
                    "REALITY replay-store slot generation exhausted".to_string(),
                );
                return false;
            };
            let key = self
                .digest_key
                .as_ref()
                .expect("persistent replay cache must retain its digest key");
            let record = encode_slot(slot, generation, valid_until, &digest, key);
            let offset = slot_offset(slot);
            let write_result = match &mut state.backend {
                ReplayBackend::Persistent(backend) => backend
                    .file
                    .as_ref()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "REALITY replay-store data descriptor is unavailable",
                        )
                    })
                    .and_then(|file| {
                        write_all_at(file, &record, offset)?;
                        // This is the admission commit point. The caller may emit
                        // the accepted REALITY flight only after fdatasync succeeds.
                        file.sync_data()
                    }),
                ReplayBackend::Memory => unreachable!(),
            };
            if let Err(error) = write_result {
                poison(
                    &mut state,
                    format!("REALITY replay-store durable insert failed: {error}"),
                );
                return false;
            }
            state.generations[slot] = generation;
        }

        let entry = ReplayEntry {
            valid_until,
            slot: selected,
        };
        state.seen.insert(digest, entry);
        state.expiries.insert((valid_until, digest));
        true
    }

    #[cfg(test)]
    pub(crate) fn with_capacity_for_tests(capacity: usize) -> Self {
        Self::in_memory_with_capacity(capacity)
    }

    #[cfg(test)]
    pub(crate) fn len_for_tests(&self) -> usize {
        self.state
            .lock()
            .map_or(self.capacity, |state| state.seen.len())
    }

    #[cfg(test)]
    pub(crate) fn poison_mutex_for_test(&self) {
        let _guard = self.state.lock().unwrap();
        panic!("intentional replay-cache poison test");
    }

    #[cfg(test)]
    pub(crate) fn break_persistent_io_for_test(&self) {
        if let Ok(mut state) = self.state.lock() {
            if let ReplayBackend::Persistent(backend) = &mut state.backend {
                backend.file.take();
            }
        }
    }
}

fn prune_expired(state: &mut ReplayState, now: u64, budget: usize) {
    for _ in 0..budget {
        let Some((valid_until, digest)) = state.expiries.first().copied() else {
            break;
        };
        if valid_until >= now {
            break;
        }
        state.expiries.remove(&(valid_until, digest));
        if let Some(entry) = state.seen.get(&digest).copied() {
            if entry.valid_until == valid_until {
                state.seen.remove(&digest);
                if let Some(slot) = entry.slot {
                    state.free_slots.push_back(slot);
                }
            }
        }
    }
}

fn remove_entry(state: &mut ReplayState, digest: [u8; 32], entry: ReplayEntry) {
    state.seen.remove(&digest);
    state.expiries.remove(&(entry.valid_until, digest));
    if let Some(slot) = entry.slot {
        state.free_slots.push_back(slot);
    }
}

fn poison(state: &mut ReplayState, reason: String) {
    if state.fail_forward_reason.is_none() {
        state.fail_forward_reason = Some(reason);
    }
}

#[cfg(unix)]
fn unix_now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn derive_store_key(static_secret: &StaticSecret) -> [u8; 32] {
    let mut secret = static_secret.to_bytes();
    let key = hmac_bytes(&secret, &[KEY_DERIVE_DOMAIN]);
    secret.zeroize();
    key
}

#[cfg(unix)]
fn static_key_binding(static_secret: &StaticSecret) -> [u8; 32] {
    let public = PublicKey::from(static_secret).to_bytes();
    let mut digest = Sha256::new();
    digest.update(KEY_BINDING_DOMAIN);
    digest.update(public);
    digest.finalize().into()
}

fn digest_session_id(key: &[u8; 32], sid: &[u8; 32]) -> [u8; 32] {
    hmac_bytes(key, &[SID_DIGEST_DOMAIN, sid])
}

fn hmac_bytes(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

#[cfg(unix)]
fn encode_header(capacity: usize, binding: &[u8; 32], key: &[u8; 32]) -> [u8; HEADER_SIZE] {
    let mut header = [0u8; HEADER_SIZE];
    header[..8].copy_from_slice(STORE_MAGIC);
    header[8..10].copy_from_slice(&STORE_VERSION.to_be_bytes());
    header[12..16].copy_from_slice(&(capacity as u32).to_be_bytes());
    header[16..20].copy_from_slice(&(SLOT_SIZE as u32).to_be_bytes());
    header[20..24].copy_from_slice(&(HEADER_SIZE as u32).to_be_bytes());
    header[24..56].copy_from_slice(binding);
    let tag = hmac_bytes(key, &[HEADER_MAC_DOMAIN, &header[..64]]);
    header[64..].copy_from_slice(&tag);
    header
}

#[cfg(unix)]
fn validate_header(
    header: &[u8; HEADER_SIZE],
    capacity: usize,
    binding: &[u8; 32],
    key: &[u8; 32],
) -> Result<(), String> {
    if &header[..8] != STORE_MAGIC
        || u16::from_be_bytes([header[8], header[9]]) != STORE_VERSION
        || header[10..12] != [0, 0]
        || u32::from_be_bytes(header[12..16].try_into().expect("fixed slice")) as usize != capacity
        || u32::from_be_bytes(header[16..20].try_into().expect("fixed slice")) as usize != SLOT_SIZE
        || u32::from_be_bytes(header[20..24].try_into().expect("fixed slice")) as usize
            != HEADER_SIZE
        || header[56..64] != [0; 8]
    {
        return Err("REALITY replay-store header profile is invalid".into());
    }
    if !bool::from(header[24..56].ct_eq(binding)) {
        return Err(
            "STATIC_KEY_MISMATCH: REALITY replay store is bound to a different static key; use a fresh path only as part of an intentional key rotation"
                .into(),
        );
    }
    let expected = hmac_bytes(key, &[HEADER_MAC_DOMAIN, &header[..64]]);
    if !bool::from(header[64..].ct_eq(&expected)) {
        return Err("REALITY replay-store header authentication failed".into());
    }
    Ok(())
}

fn encode_slot(
    slot: usize,
    generation: u64,
    valid_until: u64,
    digest: &[u8; 32],
    key: &[u8; 32],
) -> [u8; SLOT_SIZE] {
    let mut record = [0u8; SLOT_SIZE];
    record[0] = SLOT_LIVE;
    record[8..16].copy_from_slice(&generation.to_be_bytes());
    record[16..24].copy_from_slice(&valid_until.to_be_bytes());
    record[24..56].copy_from_slice(digest);
    let slot_bytes = (slot as u64).to_be_bytes();
    let tag = hmac_bytes(key, &[SLOT_MAC_DOMAIN, &slot_bytes, &record[..64]]);
    record[64..].copy_from_slice(&tag);
    record
}

#[cfg(unix)]
fn decode_slot(
    slot: usize,
    record: &[u8; SLOT_SIZE],
    key: &[u8; 32],
) -> Result<Option<(u64, u64, [u8; 32])>, String> {
    if record.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    if record[0] != SLOT_LIVE || record[1..8] != [0; 7] || record[56..64] != [0; 8] {
        return Err(format!(
            "REALITY replay-store slot {slot} has an invalid fixed profile"
        ));
    }
    let generation = u64::from_be_bytes(record[8..16].try_into().expect("fixed slice"));
    let valid_until = u64::from_be_bytes(record[16..24].try_into().expect("fixed slice"));
    if generation == 0 || valid_until == 0 {
        return Err(format!(
            "REALITY replay-store slot {slot} has an invalid generation or expiry"
        ));
    }
    let slot_bytes = (slot as u64).to_be_bytes();
    let expected = hmac_bytes(key, &[SLOT_MAC_DOMAIN, &slot_bytes, &record[..64]]);
    if !bool::from(record[64..].ct_eq(&expected)) {
        return Err(format!(
            "REALITY replay-store slot {slot} authentication failed"
        ));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&record[24..56]);
    Ok(Some((generation, valid_until, digest)))
}

#[cfg(unix)]
fn load_store(
    state: &mut ReplayState,
    capacity: usize,
    expected_len: u64,
    binding: &[u8; 32],
    key: &[u8; 32],
    now: u64,
) -> Result<(), String> {
    let ReplayBackend::Persistent(backend) = &state.backend else {
        return Err("internal REALITY replay-store backend mismatch".into());
    };
    let file = backend
        .file
        .as_ref()
        .ok_or_else(|| "REALITY replay-store data descriptor is unavailable".to_string())?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("stat REALITY replay store: {error}"))?;
    if metadata.len() != expected_len {
        return Err(format!(
            "REALITY replay-store length {} does not match fixed profile {expected_len}",
            metadata.len()
        ));
    }

    let mut header = [0u8; HEADER_SIZE];
    read_exact_at(file, &mut header, 0)
        .map_err(|error| format!("read REALITY replay-store header: {error}"))?;
    validate_header(&header, capacity, binding, key)?;

    let mut active_digest_slots = HashMap::<[u8; 32], usize>::new();
    for slot in 0..capacity {
        let mut record = [0u8; SLOT_SIZE];
        read_exact_at(file, &mut record, slot_offset(slot))
            .map_err(|error| format!("read REALITY replay-store slot {slot}: {error}"))?;
        match decode_slot(slot, &record, key)? {
            None => state.free_slots.push_back(slot),
            Some((generation, valid_until, digest)) => {
                state.generations[slot] = generation;
                if valid_until < now {
                    state.free_slots.push_back(slot);
                    continue;
                }
                if let Some(previous_slot) = active_digest_slots.insert(digest, slot) {
                    return Err(format!(
                        "REALITY replay-store has duplicate live digest in slots {previous_slot} and {slot}"
                    ));
                }
                state.seen.insert(
                    digest,
                    ReplayEntry {
                        valid_until,
                        slot: Some(slot),
                    },
                );
                state.expiries.insert((valid_until, digest));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn store_len(capacity: usize) -> io::Result<u64> {
    let slots = (capacity as u64)
        .checked_mul(SLOT_SIZE as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "replay-store size overflow"))?;
    (HEADER_SIZE as u64)
        .checked_add(slots)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "replay-store size overflow"))
}

fn slot_offset(slot: usize) -> u64 {
    HEADER_SIZE as u64 + slot as u64 * SLOT_SIZE as u64
}

#[cfg(unix)]
fn read_exact_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buffer, offset)
}

#[cfg(unix)]
fn write_all_at(file: &File, buffer: &[u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buffer, offset)
}

#[cfg(not(unix))]
fn write_all_at(_file: &File, _buffer: &[u8], _offset: u64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable REALITY replay stores require Unix positioned-write semantics",
    ))
}

#[cfg(unix)]
fn expected_owner(owner: ReplayStoreOwner) -> io::Result<(u32, u32)> {
    // SAFETY: geteuid/getegid take no arguments and have no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    let effective_gid = unsafe { libc::getegid() };
    match owner {
        ReplayStoreOwner::Root if effective_uid != 0 => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "production REALITY replay store requires effective UID 0",
        )),
        ReplayStoreOwner::Root => Ok((0, 0)),
        ReplayStoreOwner::EffectiveUser => Ok((effective_uid, effective_gid)),
    }
}

#[cfg(unix)]
fn validate_parent_chain(path: &Path, owner: ReplayStoreOwner) -> io::Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let (expected_uid, expected_gid) = expected_owner(owner)?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = absolute.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "REALITY replay-store path has no parent",
        )
    })?;
    let mut cursor = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                cursor.push(component.as_os_str());
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "REALITY replay-store path may not contain parent traversal",
                ))
            }
        }
        let metadata = std::fs::symlink_metadata(&cursor)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "REALITY replay-store parent is not a real directory: {}",
                    cursor.display()
                ),
            ));
        }
        let trusted_owner = match owner {
            ReplayStoreOwner::Root => metadata.uid() == 0,
            ReplayStoreOwner::EffectiveUser => {
                metadata.uid() == 0
                    || (metadata.uid() == expected_uid && metadata.gid() == expected_gid)
            }
        };
        let mode = metadata.permissions().mode() & 0o7777;
        if !trusted_owner || mode & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "REALITY replay-store parent {} has unsafe owner/mode {:04o}",
                    cursor.display(),
                    mode
                ),
            ));
        }
    }
    Ok(absolute)
}

#[cfg(unix)]
fn open_private_file(path: &Path, owner: ReplayStoreOwner) -> io::Result<(File, bool)> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let (expected_uid, expected_gid) = expected_owner(owner)?;
    let new_file = || {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        options.open(path)
    };
    let (file, created) = match new_file() {
        Ok(file) => {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            (file, true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            (options.open(path)?, false)
        }
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "REALITY replay-store file {} is not a single-link exact-0600 private regular file",
                path.display()
            ),
        ));
    }
    Ok((file, created))
}

#[cfg(unix)]
fn sibling_lease_path(path: &Path) -> io::Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "REALITY replay-store path has no file name",
        )
    })?;
    let mut lease_name = file_name.to_os_string();
    lease_name.push(".lock");
    Ok(path.with_file_name(lease_name))
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "REALITY replay-store path has no parent",
        )
    })?;
    File::open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use std::fs::OpenOptions;
    use std::sync::{Arc, Barrier};

    #[cfg(unix)]
    fn private_test_path(label: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let mut random = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut random);
        let directory = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("replay-store-tests")
            .join(format!(
                "{label}-{}-{}",
                std::process::id(),
                hex::encode(random)
            ));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        directory.join("replay.bin")
    }

    #[cfg(unix)]
    fn cleanup_test_path(path: &Path) {
        if let Some(directory) = path.parent() {
            let _ = std::fs::remove_dir_all(directory);
        }
    }

    #[test]
    fn absolute_expiry_covers_the_complete_future_skew_window() {
        let cache = ReplayCache::with_capacity_for_tests(2);
        let sid = [0x41; 32];
        let first_seen = 1_000;
        let token_time = 1_120;
        let valid_until = token_time + 120;
        assert!(cache.check_and_record(&sid, first_seen, valid_until));
        assert!(
            !cache.check_and_record(&sid, 1_121, valid_until),
            "the cache must not forget at first_seen+window while the token is still valid"
        );
        assert!(!cache.check_and_record(&sid, valid_until, valid_until));
        assert!(cache.check_and_record(&sid, valid_until + 1, valid_until + 240));
    }

    #[test]
    fn concurrent_exact_insert_has_one_linearization_winner() {
        let cache = Arc::new(ReplayCache::with_capacity_for_tests(8));
        let barrier = Arc::new(Barrier::new(16));
        let mut workers = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                cache.check_and_record(&[0x52; 32], 10, 100)
            }));
        }
        let winners = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
    }

    #[cfg(unix)]
    #[test]
    fn persistent_concurrent_insert_has_one_durable_winner() {
        let path = private_test_path("persistent-concurrency");
        let secret = StaticSecret::from([0x57; 32]);
        let now = unix_now_secs();
        let cache = Arc::new(
            ReplayCache::open_persistent_with_capacity(
                &path,
                &secret,
                ReplayStoreOwner::EffectiveUser,
                8,
            )
            .unwrap(),
        );
        let barrier = Arc::new(Barrier::new(16));
        let mut workers = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                cache.check_and_record(&[0x58; 32], now, now + 120)
            }));
        }
        let winners = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
        drop(cache);

        let reopened = ReplayCache::open_persistent_with_capacity(
            &path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            8,
        )
        .unwrap();
        assert!(!reopened.check_and_record(&[0x58; 32], now + 1, now + 120));
        drop(reopened);
        cleanup_test_path(&path);
    }

    #[cfg(unix)]
    #[test]
    fn persistent_fixed_slot_saturation_fails_forward_without_growth() {
        let path = private_test_path("persistent-full");
        let secret = StaticSecret::from([0x59; 32]);
        let now = unix_now_secs();
        let cache = ReplayCache::open_persistent_with_capacity(
            &path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            2,
        )
        .unwrap();
        assert!(cache.check_and_record(&[0x5a; 32], now, now + 120));
        assert!(cache.check_and_record(&[0x5b; 32], now, now + 120));
        assert!(
            !cache.check_and_record(&[0x5c; 32], now, now + 120),
            "full durable store must fail forward"
        );
        assert!(cache.fail_forward_reason().is_none());
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            store_len(2).unwrap()
        );
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.windows(32).any(|window| window == [0x5a; 32]),
            "durable file must store a keyed digest, not the raw session_id"
        );
        drop(cache);
        cleanup_test_path(&path);
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_replay_store_files_and_parents_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let secret = StaticSecret::from([0x5d; 32]);

        let loose_path = private_test_path("unsafe-mode");
        let loose_file = File::create(&loose_path).unwrap();
        loose_file
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .unwrap();
        drop(loose_file);
        assert!(ReplayCache::open_persistent_with_capacity(
            &loose_path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            2,
        )
        .is_err());
        cleanup_test_path(&loose_path);

        let symlink_path = private_test_path("unsafe-symlink");
        let target = symlink_path.with_file_name("target.bin");
        let target_file = File::create(&target).unwrap();
        target_file
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        drop(target_file);
        symlink(&target, &symlink_path).unwrap();
        assert!(ReplayCache::open_persistent_with_capacity(
            &symlink_path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            2,
        )
        .is_err());
        cleanup_test_path(&symlink_path);

        let hardlink_path = private_test_path("unsafe-hardlink");
        let cache = ReplayCache::open_persistent_with_capacity(
            &hardlink_path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            2,
        )
        .unwrap();
        drop(cache);
        std::fs::hard_link(&hardlink_path, hardlink_path.with_file_name("alias.bin")).unwrap();
        assert!(ReplayCache::open_persistent_with_capacity(
            &hardlink_path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            2,
        )
        .is_err());
        cleanup_test_path(&hardlink_path);

        let lease_content_path = private_test_path("unsafe-lease-content");
        let cache = ReplayCache::open_persistent_with_capacity(
            &lease_content_path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            2,
        )
        .unwrap();
        drop(cache);
        std::fs::write(lease_content_path.with_file_name("replay.bin.lock"), b"x").unwrap();
        assert!(ReplayCache::open_persistent_with_capacity(
            &lease_content_path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            2,
        )
        .is_err());
        cleanup_test_path(&lease_content_path);

        let unsafe_parent_path = private_test_path("unsafe-parent");
        let parent = unsafe_parent_path.parent().unwrap();
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ReplayCache::open_persistent_with_capacity(
            &unsafe_parent_path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            2,
        )
        .is_err());
        cleanup_test_path(&unsafe_parent_path);
    }

    #[cfg(unix)]
    #[test]
    fn persistent_insert_survives_restart_and_same_host_lease_is_exclusive() {
        let path = private_test_path("restart-lock");
        let secret = StaticSecret::from([0x61; 32]);
        let now = unix_now_secs();
        let cache = ReplayCache::open_persistent_with_capacity(
            &path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            8,
        )
        .unwrap();
        assert!(cache.check_and_record(&[0x62; 32], now, now + 120));
        let locked = match ReplayCache::open_persistent_with_capacity(
            &path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            8,
        ) {
            Ok(_) => panic!("second same-host replay-store owner was accepted"),
            Err(error) => error,
        };
        assert_eq!(locked.kind(), io::ErrorKind::WouldBlock);
        drop(cache);

        let reopened = ReplayCache::open_persistent_with_capacity(
            &path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            8,
        )
        .unwrap();
        assert!(
            !reopened.check_and_record(&[0x62; 32], now + 1, now + 120),
            "a committed token must remain rejected after restart"
        );
        drop(reopened);
        cleanup_test_path(&path);
    }

    #[cfg(unix)]
    #[test]
    fn store_bound_to_another_static_key_aborts_open() {
        let path = private_test_path("key-binding");
        let first_secret = StaticSecret::from([0x66; 32]);
        let cache = ReplayCache::open_persistent_with_capacity(
            &path,
            &first_secret,
            ReplayStoreOwner::EffectiveUser,
            4,
        )
        .unwrap();
        drop(cache);

        let second_secret = StaticSecret::from([0x67; 32]);
        let error = match ReplayCache::open_persistent_with_capacity(
            &path,
            &second_secret,
            ReplayStoreOwner::EffectiveUser,
            4,
        ) {
            Ok(_) => panic!("replay store was silently reused across static keys"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("different static key"));
        cleanup_test_path(&path);
    }

    #[cfg(unix)]
    #[test]
    fn torn_slot_is_detected_and_store_permanently_fails_forward() {
        use std::os::unix::fs::FileExt;

        let path = private_test_path("torn");
        let secret = StaticSecret::from([0x71; 32]);
        let now = unix_now_secs();
        let cache = ReplayCache::open_persistent_with_capacity(
            &path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            4,
        )
        .unwrap();
        assert!(cache.check_and_record(&[0x72; 32], now, now + 120));
        drop(cache);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all_at(&[0xff; 7], slot_offset(0) + 17).unwrap();
        file.sync_data().unwrap();
        drop(file);

        let poisoned = ReplayCache::open_persistent_with_capacity(
            &path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            4,
        )
        .unwrap();
        assert!(poisoned.fail_forward_reason().is_some());
        assert!(!poisoned.check_and_record(&[0x73; 32], now + 1, now + 121));
        drop(poisoned);
        cleanup_test_path(&path);
    }

    #[cfg(unix)]
    #[test]
    fn runtime_io_failure_poison_is_fail_forward() {
        let path = private_test_path("io");
        let secret = StaticSecret::from([0x81; 32]);
        let now = unix_now_secs();
        let cache = ReplayCache::open_persistent_with_capacity(
            &path,
            &secret,
            ReplayStoreOwner::EffectiveUser,
            4,
        )
        .unwrap();
        cache.break_persistent_io_for_test();
        assert!(!cache.check_and_record(&[0x82; 32], now, now + 120));
        assert!(cache.fail_forward_reason().is_some());
        assert!(!cache.check_and_record(&[0x83; 32], now, now + 120));
        drop(cache);
        cleanup_test_path(&path);
    }
}
