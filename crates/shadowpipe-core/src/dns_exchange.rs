//! Crash-recoverable Linux resolver pinning.
//!
//! The live resolver object and a same-directory exchange name are swapped with
//! `renameat2(RENAME_EXCHANGE)`.  Both inode identities and regular-file
//! digests are journaled.  Recovery first classifies the complete two-name
//! topology without mutation and refuses every mixed or foreign state.
//!
//! Staging uses an unnamed `O_TMPFILE`: the pinned inode can be identified and
//! journaled before it is linked into the filesystem.  A crash before the link
//! therefore leaves no orphan; a crash after it is recoverable from the durable
//! journal and the deterministic session-scoped exchange name.

use anyhow::Result;
use std::path::Path;

#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use crate::host_state::{
    DnsResource, FileIdentity, ResourceObservationKind, SessionId, Sha256Digest,
};
#[cfg(any(test, target_os = "linux"))]
use crate::host_state::{FileKind, ResolverTarget};

pub const MAX_RESOLVER_OBJECT_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const PINNED_MODE: u32 = 0o644;

/// Recovery callers must distinguish an ownership/topology conflict from an
/// operational inability to inspect or mutate the resolver filesystem.  A
/// conflict must never be retried as if it were a transient syscall failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsExchangeFailureKind {
    Conflict,
    Operational,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsExchangeFailure {
    Conflict {
        operation: &'static str,
        detail: String,
    },
    Operational {
        operation: &'static str,
        detail: String,
    },
}

impl DnsExchangeFailure {
    fn conflict(operation: &'static str, detail: impl Into<String>) -> Self {
        Self::Conflict {
            operation,
            detail: detail.into(),
        }
    }

    fn operational(operation: &'static str, detail: impl Into<String>) -> Self {
        Self::Operational {
            operation,
            detail: detail.into(),
        }
    }

    pub fn kind(&self) -> DnsExchangeFailureKind {
        match self {
            Self::Conflict { .. } => DnsExchangeFailureKind::Conflict,
            Self::Operational { .. } => DnsExchangeFailureKind::Operational,
        }
    }

    pub fn operation(&self) -> &'static str {
        match self {
            Self::Conflict { operation, .. } | Self::Operational { operation, .. } => operation,
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::Conflict { detail, .. } | Self::Operational { detail, .. } => detail,
        }
    }
}

impl std::fmt::Display for DnsExchangeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { operation, detail } => {
                write!(
                    formatter,
                    "DNS ownership conflict during {operation}: {detail}"
                )
            }
            Self::Operational { operation, detail } => {
                write!(
                    formatter,
                    "DNS operational failure during {operation}: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for DnsExchangeFailure {}

pub type DnsExchangeResult<T> = std::result::Result<T, DnsExchangeFailure>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolverDirectoryIdentity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub link_count: u64,
}

/// Evidence collected without creating a named directory entry.
///
/// `linkat(AT_EMPTY_PATH)` and `renameat2(RENAME_EXCHANGE)` cannot be proved on
/// the resolver filesystem without first creating names there.  No Linux
/// syscall atomically creates, exercises, and removes those names, so a process
/// death could strand an unjournaled probe.  Those two operations are therefore
/// deliberately deferred until the real [`DnsResource`] is durable.  At that
/// point every possible result (absent, staged, or active) is recoverable from
/// the deterministic session name and journaled inode identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsExchangeCapabilities {
    pub parent: ResolverDirectoryIdentity,
    pub parent_mount_id: u64,
    pub target: ObservedDnsObject,
    pub target_size: u64,
    pub target_mount_id: u64,
    pub target_is_mountpoint: bool,
    pub unnamed_tmpfile: bool,
    pub named_mutations_deferred_until_journal: bool,
    pub durable_directory_fsync: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedDnsObject {
    pub identity: FileIdentity,
    pub sha256: Option<Sha256Digest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsExchangeTopology {
    /// Target is the pinned inode; exchange name holds the exact original.
    Active,
    /// Target is already original; exchange name holds the linked pinned inode.
    Staged,
    /// Target is original and the exchange name is absent.
    Absent,
    /// Any mixed, missing-original, foreign, or content-modified state.
    Conflict,
}

impl DnsExchangeTopology {
    pub fn observation_kind(self) -> ResourceObservationKind {
        match self {
            Self::Active | Self::Staged => ResourceObservationKind::ExactOwnedPresent,
            Self::Absent => ResourceObservationKind::Absent,
            Self::Conflict => ResourceObservationKind::Conflict,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsRecoveryAction {
    ExchangeThenUnlink,
    UnlinkStaged,
    AlreadyAbsent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRecoveryPlan {
    pub topology: DnsExchangeTopology,
    pub action: DnsRecoveryAction,
}

fn object_matches(
    observed: Option<&ObservedDnsObject>,
    expected_identity: FileIdentity,
    expected_digest: Option<Sha256Digest>,
) -> bool {
    let Some(observed) = observed else {
        return false;
    };
    observed.identity == expected_identity && observed.sha256 == expected_digest
}

/// Classify only exact, fully known name/inode arrangements.  In particular,
/// matching content under a new inode is a conflict, not ownership evidence.
pub fn classify_dns_exchange(
    resource: &DnsResource,
    target: Option<&ObservedDnsObject>,
    exchange: Option<&ObservedDnsObject>,
) -> DnsExchangeTopology {
    let target_is_original = object_matches(target, resource.original, resource.original_sha256);
    let target_is_pinned = object_matches(target, resource.pinned, Some(resource.pinned_sha256));
    let exchange_is_original =
        object_matches(exchange, resource.original, resource.original_sha256);
    let exchange_is_pinned =
        object_matches(exchange, resource.pinned, Some(resource.pinned_sha256));

    match (
        target_is_original,
        target_is_pinned,
        exchange_is_original,
        exchange_is_pinned,
        exchange.is_none(),
    ) {
        (false, true, true, false, false) => DnsExchangeTopology::Active,
        (true, false, false, true, false) => DnsExchangeTopology::Staged,
        (true, false, false, false, true) => DnsExchangeTopology::Absent,
        _ => DnsExchangeTopology::Conflict,
    }
}

pub fn plan_dns_recovery(topology: DnsExchangeTopology) -> DnsExchangeResult<DnsRecoveryPlan> {
    let action = match topology {
        DnsExchangeTopology::Active => DnsRecoveryAction::ExchangeThenUnlink,
        DnsExchangeTopology::Staged => DnsRecoveryAction::UnlinkStaged,
        DnsExchangeTopology::Absent => DnsRecoveryAction::AlreadyAbsent,
        DnsExchangeTopology::Conflict => {
            return Err(DnsExchangeFailure::conflict(
                "plan recovery",
                "two-name topology conflicts with journaled inode authority",
            ));
        }
    };
    Ok(DnsRecoveryPlan { topology, action })
}

#[cfg(target_os = "linux")]
fn exchange_name(session: SessionId) -> String {
    session.resolver_exchange_file_name()
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::{CStr, CString, OsStr};
    use std::io::{self, Write as _};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileExt as _;

    const STATX_MNT_ID_MASK: u32 = 0x0000_1000;

    fn conflict(operation: &'static str, detail: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(DnsExchangeFailure::conflict(operation, detail))
    }

    fn syscall_error(operation: &'static str, error: io::Error) -> anyhow::Error {
        match error.raw_os_error() {
            Some(libc::ENOENT) | Some(libc::ELOOP) | Some(libc::ENOTDIR) | Some(libc::EEXIST)
            | Some(libc::ESTALE) => {
                conflict(operation, format!("pathname raced or changed: {error}"))
            }
            _ => anyhow::Error::new(error).context(operation),
        }
    }

    fn typed<T>(operation: &'static str, result: Result<T>) -> DnsExchangeResult<T> {
        result.map_err(|error| {
            error
                .downcast_ref::<DnsExchangeFailure>()
                .cloned()
                .unwrap_or_else(|| DnsExchangeFailure::operational(operation, error.to_string()))
        })
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct StableStat {
        identity: FileIdentity,
        size: u64,
        mtime_seconds: i64,
        mtime_nanoseconds: i64,
        ctime_seconds: i64,
        ctime_nanoseconds: i64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct InspectedComponent {
        object: ObservedDnsObject,
        stable: StableStat,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum RecoveryBoundary {
        AfterTopologyBeforeExchangeRevalidation,
        AfterQuarantineOpenBeforeUnlink,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum ResidueFreeProbeBoundary {
        UnnamedFileSynced,
        DirectorySynced,
    }

    #[derive(Debug)]
    struct DirectoryAnchor {
        directory: File,
        display_path: PathBuf,
        identity: ResolverDirectoryIdentity,
        mount_id: u64,
    }

    impl DirectoryAnchor {
        fn open(path: &Path) -> Result<Self> {
            let bytes = path.as_os_str().as_bytes();
            let path_c = CString::new(bytes).context("resolver parent path contains NUL")?;
            // SAFETY: path_c is a live NUL-terminated string and open returns a
            // fresh descriptor or -1. O_NOFOLLOW rejects a final symlink.
            let fd = unsafe {
                libc::open(
                    path_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error()).with_context(|| {
                    format!("open anchored resolver directory {}", path.display())
                });
            }
            // SAFETY: fd is newly owned and non-negative.
            let directory = unsafe { File::from_raw_fd(fd) };
            let stat =
                fstat_fd(directory.as_raw_fd()).context("fstat anchored resolver directory")?;
            anyhow::ensure!(
                stat.st_mode & libc::S_IFMT == libc::S_IFDIR,
                "anchored resolver parent is not a directory"
            );
            let identity = directory_identity_from_stat(&stat);
            anyhow::ensure!(
                identity.uid == unsafe { libc::geteuid() },
                "resolver parent must be owned by the effective uid"
            );
            anyhow::ensure!(
                identity.mode & 0o022 == 0,
                "resolver parent must not be writable by group or other users"
            );
            let mount_id = statx_mount_id(
                directory.as_raw_fd(),
                c"",
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            )
            .context("statx mount identity for anchored resolver directory")?;
            Ok(Self {
                directory,
                display_path: path.to_path_buf(),
                identity,
                mount_id,
            })
        }

        fn fd(&self) -> RawFd {
            self.directory.as_raw_fd()
        }

        fn sync(&self) -> Result<()> {
            self.directory.sync_all().with_context(|| {
                format!("fsync resolver directory {}", self.display_path.display())
            })
        }

        fn revalidate(&self) -> Result<()> {
            let current = directory_identity_from_stat(
                &fstat_fd(self.fd()).context("re-fstat anchored resolver directory")?,
            );
            if current != self.identity {
                return Err(conflict(
                    "revalidate parent",
                    "anchored resolver directory identity or permissions changed",
                ));
            }
            let mount_id = statx_mount_id(
                self.fd(),
                c"",
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            )?;
            if mount_id != self.mount_id {
                return Err(conflict(
                    "revalidate parent",
                    "anchored resolver directory mount identity changed",
                ));
            }
            Ok(())
        }
    }

    fn fstat_fd(fd: RawFd) -> Result<libc::stat> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: stat is writable and fd remains open for the call.
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error()).context("fstat resolver object");
        }
        // SAFETY: successful fstat initialized stat.
        Ok(unsafe { stat.assume_init() })
    }

    fn directory_identity_from_stat(stat: &libc::stat) -> ResolverDirectoryIdentity {
        ResolverDirectoryIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode,
            link_count: u64::from(stat.st_nlink),
        }
    }

    fn statx_mount_id(dirfd: RawFd, name: &CStr, flags: i32) -> Result<u64> {
        let mut statx = MaybeUninit::<libc::statx>::zeroed();
        // SAFETY: name is NUL terminated, statx points to writable storage, and
        // dirfd remains live. A raw syscall avoids libc-version wrappers.
        let result = unsafe {
            libc::syscall(
                libc::SYS_statx,
                dirfd,
                name.as_ptr(),
                flags,
                libc::STATX_BASIC_STATS | STATX_MNT_ID_MASK,
                statx.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error()).context("statx resolver mount identity");
        }
        // SAFETY: successful statx initialized the structure.
        let statx = unsafe { statx.assume_init() };
        anyhow::ensure!(
            statx.stx_mask & STATX_MNT_ID_MASK != 0,
            "kernel/filesystem did not report STATX_MNT_ID"
        );
        Ok(statx.stx_mnt_id)
    }

    fn component(value: &OsStr, label: &str) -> Result<CString> {
        let bytes = value.as_bytes();
        anyhow::ensure!(
            !bytes.is_empty() && bytes != b"." && bytes != b".." && !bytes.contains(&b'/'),
            "{label} must be one non-special path component"
        );
        CString::new(bytes).with_context(|| format!("{label} contains NUL"))
    }

    fn identity_from_stat(stat: &libc::stat) -> Result<FileIdentity> {
        let file_type = stat.st_mode & libc::S_IFMT;
        let kind = if file_type == libc::S_IFREG {
            FileKind::Regular
        } else if file_type == libc::S_IFLNK {
            FileKind::Symlink
        } else {
            return Err(conflict(
                "inspect object type",
                "resolver object is neither a regular file nor a symlink",
            ));
        };
        Ok(FileIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode,
            link_count: u64::from(stat.st_nlink),
            kind,
        })
    }

    fn stable_stat_from_stat(stat: &libc::stat) -> Result<StableStat> {
        if stat.st_size < 0 {
            return Err(conflict(
                "inspect object size",
                "resolver object reported a negative size",
            ));
        }
        let size = stat.st_size as u64;
        if size > MAX_RESOLVER_OBJECT_BYTES {
            return Err(conflict(
                "inspect object size",
                format!("resolver object exceeds {MAX_RESOLVER_OBJECT_BYTES} bytes"),
            ));
        }
        Ok(StableStat {
            identity: identity_from_stat(stat)?,
            size,
            mtime_seconds: stat.st_mtime,
            mtime_nanoseconds: stat.st_mtime_nsec,
            ctime_seconds: stat.st_ctime,
            ctime_nanoseconds: stat.st_ctime_nsec,
        })
    }

    fn stat_component_stable(anchor: &DirectoryAnchor, name: &CStr) -> Result<Option<StableStat>> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: stat points to writable storage and name is NUL terminated.
        let result = unsafe {
            libc::fstatat(
                anchor.fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(error).context("fstatat resolver component");
        }
        // SAFETY: successful fstatat initialized stat.
        let stat = unsafe { stat.assume_init() };
        stable_stat_from_stat(&stat).map(Some)
    }

    fn digest_stable_file(file: &File, expected: StableStat) -> Result<Sha256Digest> {
        let before = stable_stat_from_stat(&fstat_fd(file.as_raw_fd())?)?;
        if before != expected {
            return Err(conflict(
                "digest object",
                "opened resolver inode/version differs from the pathname snapshot",
            ));
        }

        let mut bytes = vec![0u8; MAX_RESOLVER_OBJECT_BYTES as usize + 1];
        let mut used = 0usize;
        loop {
            let read = file
                .read_at(&mut bytes[used..], used as u64)
                .context("pread opened resolver object")?;
            if read == 0 {
                break;
            }
            used += read;
            if used > MAX_RESOLVER_OBJECT_BYTES as usize {
                return Err(conflict(
                    "digest object",
                    format!(
                        "resolver object grew beyond {MAX_RESOLVER_OBJECT_BYTES} bytes while reading"
                    ),
                ));
            }
        }
        bytes.truncate(used);
        let after = stable_stat_from_stat(&fstat_fd(file.as_raw_fd())?)?;
        if before != after || used as u64 != after.size {
            return Err(conflict(
                "digest object",
                "resolver inode size/mtime/ctime changed while hashing",
            ));
        }
        Ok(Sha256Digest::from_bytes(Sha256::digest(&bytes).into()))
    }

    fn inspect_component_detailed(
        anchor: &DirectoryAnchor,
        name: &CStr,
    ) -> Result<Option<InspectedComponent>> {
        anchor.revalidate()?;
        let Some(before) = stat_component_stable(anchor, name)? else {
            return Ok(None);
        };
        let sha256 = match before.identity.kind {
            FileKind::Symlink => None,
            FileKind::Regular => {
                // SAFETY: name is NUL terminated; returned fd is uniquely owned.
                let fd = unsafe {
                    libc::openat(
                        anchor.fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                    )
                };
                if fd < 0 {
                    return Err(syscall_error(
                        "open regular resolver object",
                        io::Error::last_os_error(),
                    ));
                }
                // SAFETY: fd is newly owned and non-negative.
                let file = unsafe { File::from_raw_fd(fd) };
                let digest = digest_stable_file(&file, before)?;
                Some(digest)
            }
        };
        let after_name = stat_component_stable(anchor, name)?;
        if after_name != Some(before) {
            return Err(conflict(
                "inspect pathname",
                "resolver pathname inode/version changed during read-only inspection",
            ));
        }
        Ok(Some(InspectedComponent {
            object: ObservedDnsObject {
                identity: before.identity,
                sha256,
            },
            stable: before,
        }))
    }

    fn inspect_component(
        anchor: &DirectoryAnchor,
        name: &CStr,
    ) -> Result<Option<ObservedDnsObject>> {
        Ok(inspect_component_detailed(anchor, name)?.map(|observed| observed.object))
    }

    fn expect_component(
        anchor: &DirectoryAnchor,
        name: &CStr,
        expected: &ObservedDnsObject,
        operation: &'static str,
    ) -> Result<StableStat> {
        let observed = inspect_component_detailed(anchor, name)?
            .ok_or_else(|| conflict(operation, "expected resolver pathname is absent"))?;
        if observed.object != *expected {
            return Err(conflict(
                operation,
                "resolver pathname no longer names the exact expected inode and digest",
            ));
        }
        Ok(observed.stable)
    }

    fn rename_exchange(anchor: &DirectoryAnchor, first: &CStr, second: &CStr) -> Result<()> {
        // SAFETY: descriptors and NUL-terminated component pointers remain live
        // for the syscall; both names are anchored to the same directory.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                anchor.fd(),
                first.as_ptr(),
                anchor.fd(),
                second.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(syscall_error(
                "renameat2(RENAME_EXCHANGE) resolver objects",
                io::Error::last_os_error(),
            ))
        }
    }

    fn rename_exchange_exact(
        anchor: &DirectoryAnchor,
        first: &CStr,
        first_expected: &ObservedDnsObject,
        second: &CStr,
        second_expected: &ObservedDnsObject,
    ) -> Result<()> {
        let first_stable =
            expect_component(anchor, first, first_expected, "pre-exchange revalidation")?;
        let second_stable =
            expect_component(anchor, second, second_expected, "pre-exchange revalidation")?;
        // Repeat the cheap inode/version observations immediately before the
        // syscall. This closes the digest-to-rename window for ordinary
        // resolver-manager writers; a malicious same-uid/root process remains
        // outside the filesystem API's conditional-rename guarantees.
        if stat_component_stable(anchor, first)? != Some(first_stable)
            || stat_component_stable(anchor, second)? != Some(second_stable)
        {
            return Err(conflict(
                "pre-exchange revalidation",
                "resolver inode/version changed immediately before renameat2",
            ));
        }
        rename_exchange(anchor, first, second)
    }

    fn unlink_component(anchor: &DirectoryAnchor, name: &CStr) -> Result<()> {
        // SAFETY: name is NUL terminated and relative to a live directory fd.
        let result = unsafe { libc::unlinkat(anchor.fd(), name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(syscall_error(
                "unlinkat staged resolver object",
                io::Error::last_os_error(),
            ))
        }
    }

    fn open_exact_regular(
        anchor: &DirectoryAnchor,
        name: &CStr,
        expected: &ObservedDnsObject,
    ) -> Result<(File, StableStat)> {
        anyhow::ensure!(
            expected.identity.kind == FileKind::Regular && expected.sha256.is_some(),
            "exact unlink authority must describe a digested regular file"
        );
        let before = expect_component(anchor, name, expected, "quarantine exact object")?;
        // SAFETY: name and anchor remain live, and returned fd is uniquely owned.
        let fd = unsafe {
            libc::openat(
                anchor.fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(syscall_error(
                "open exact quarantined object",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: fd is newly owned and non-negative.
        let file = unsafe { File::from_raw_fd(fd) };
        let digest = digest_stable_file(&file, before)?;
        if Some(digest) != expected.sha256 {
            return Err(conflict(
                "quarantine exact object",
                "opened object digest differs from journaled deletion authority",
            ));
        }
        if stat_component_stable(anchor, name)? != Some(before) {
            return Err(conflict(
                "quarantine exact object",
                "quarantine name changed after opening its exact inode",
            ));
        }
        Ok((file, before))
    }

    fn unlink_exact_regular_after_hook<F>(
        anchor: &DirectoryAnchor,
        name: &CStr,
        expected: &ObservedDnsObject,
        hook: &mut F,
    ) -> Result<()>
    where
        F: FnMut(RecoveryBoundary),
    {
        // The deterministic exchange name is the quarantine: it is outside the
        // live resolver pathname and can contain only the exact journaled
        // pinned inode before deletion is authorized.
        let (file, stable) = open_exact_regular(anchor, name, expected)?;
        hook(RecoveryBoundary::AfterQuarantineOpenBeforeUnlink);

        let reopened_digest = digest_stable_file(&file, stable)?;
        if Some(reopened_digest) != expected.sha256
            || stat_component_stable(anchor, name)? != Some(stable)
        {
            return Err(conflict(
                "final unlink revalidation",
                "quarantine path or opened inode/version changed before unlinkat",
            ));
        }
        // No pathname lookup or allocation is intentionally placed between the
        // final fstatat and unlinkat.
        unlink_component(anchor, name)?;
        let after = fstat_fd(file.as_raw_fd())?;
        if after.st_dev != stable.identity.device
            || after.st_ino != stable.identity.inode
            || after.st_nlink != 0
        {
            return Err(conflict(
                "post-unlink verification",
                "unlinkat did not remove the exact quarantined inode's final link",
            ));
        }
        anchor.sync()
    }

    fn topology(
        anchor: &DirectoryAnchor,
        target: &CStr,
        exchange: &CStr,
        resource: &DnsResource,
    ) -> Result<DnsExchangeTopology> {
        let target_observation = inspect_component(anchor, target)?;
        let exchange_observation = inspect_component(anchor, exchange)?;
        Ok(classify_dns_exchange(
            resource,
            target_observation.as_ref(),
            exchange_observation.as_ref(),
        ))
    }

    fn create_unnamed_file(anchor: &DirectoryAnchor, contents: &[u8]) -> Result<File> {
        let dot = c".";
        // SAFETY: dot is static and returned fd is uniquely owned. O_TMPFILE
        // creates no directory entry and therefore no crash residue.
        let fd = unsafe {
            libc::openat(
                anchor.fd(),
                dot.as_ptr(),
                libc::O_RDWR | libc::O_TMPFILE | libc::O_CLOEXEC,
                PINNED_MODE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context("create unnamed O_TMPFILE resolver object");
        }
        // SAFETY: fd is newly owned and non-negative.
        let mut file = unsafe { File::from_raw_fd(fd) };
        // SAFETY: file descriptor is live and fchmod has no pointer inputs.
        if unsafe { libc::fchmod(file.as_raw_fd(), PINNED_MODE) } != 0 {
            return Err(io::Error::last_os_error()).context("fchmod unnamed resolver object");
        }
        file.write_all(contents)
            .context("write unnamed resolver object")?;
        file.sync_all().context("fsync unnamed resolver object")?;
        let stable = stable_stat_from_stat(&fstat_fd(file.as_raw_fd())?)?;
        anyhow::ensure!(
            stable.identity.kind == FileKind::Regular
                && stable.identity.link_count == 0
                && stable.size == contents.len() as u64,
            "O_TMPFILE resolver object has unexpected type, link count, or size"
        );
        Ok(file)
    }

    fn expected_linked_object(file: &File, contents: &[u8]) -> Result<ObservedDnsObject> {
        let stable = stable_stat_from_stat(&fstat_fd(file.as_raw_fd())?)?;
        anyhow::ensure!(
            stable.identity.kind == FileKind::Regular && stable.identity.link_count == 0,
            "unnamed resolver object is not an unlinked regular inode"
        );
        let mut identity = stable.identity;
        identity.link_count = 1;
        Ok(ObservedDnsObject {
            identity,
            sha256: Some(Sha256Digest::from_bytes(Sha256::digest(contents).into())),
        })
    }

    fn link_unnamed(anchor: &DirectoryAnchor, file: &File, name: &CStr) -> Result<()> {
        if inspect_component(anchor, name)?.is_some() {
            return Err(conflict(
                "link unnamed object",
                "destination sibling name already exists",
            ));
        }
        // SAFETY: descriptors/names are live. AT_EMPTY_PATH links precisely the
        // already-open O_TMPFILE inode.
        let result = unsafe {
            libc::linkat(
                file.as_raw_fd(),
                c"".as_ptr(),
                anchor.fd(),
                name.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        if result != 0 {
            return Err(syscall_error(
                "linkat(AT_EMPTY_PATH) resolver object",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    /// Probe only operations whose every crash prefix is namespace-neutral.
    ///
    /// The unnamed inode is unreachable from the directory at every point. On
    /// process death the kernel closes the descriptor and reclaims it, so no
    /// restart cleanup authority is necessary. Named link/exchange operations
    /// are intentionally not performed here; they happen only after the real
    /// resource record is durable.
    fn probe_residue_free_primitives(anchor: &DirectoryAnchor) -> Result<()> {
        probe_residue_free_primitives_with_hook(anchor, |_| Ok(()))
    }

    fn probe_residue_free_primitives_with_hook<F>(
        anchor: &DirectoryAnchor,
        mut hook: F,
    ) -> Result<()>
    where
        F: FnMut(ResidueFreeProbeBoundary) -> Result<()>,
    {
        const CONTENTS: &[u8] = b"shadowpipe-residue-free-dns-preflight\n";
        let file = create_unnamed_file(anchor, CONTENTS)?;
        let stable = stable_stat_from_stat(&fstat_fd(file.as_raw_fd())?)?;
        anyhow::ensure!(
            stable.identity.kind == FileKind::Regular
                && stable.identity.link_count == 0
                && stable.size == CONTENTS.len() as u64,
            "residue-free DNS probe unexpectedly acquired a directory link"
        );
        hook(ResidueFreeProbeBoundary::UnnamedFileSynced)?;
        anchor.sync()?;
        hook(ResidueFreeProbeBoundary::DirectorySynced)?;
        let after = stable_stat_from_stat(&fstat_fd(file.as_raw_fd())?)?;
        anyhow::ensure!(
            after.identity.device == stable.identity.device
                && after.identity.inode == stable.identity.inode
                && after.identity.link_count == 0
                && after.size == stable.size,
            "residue-free DNS probe changed identity or acquired a directory link"
        );
        anchor.revalidate()
    }

    #[derive(Debug)]
    pub struct DnsExchangePreflight {
        anchor: DirectoryAnchor,
        target: CString,
        exchange: CString,
        baseline: InspectedComponent,
        capabilities: DnsExchangeCapabilities,
    }

    impl DnsExchangePreflight {
        pub fn capabilities(&self) -> &DnsExchangeCapabilities {
            &self.capabilities
        }
    }

    fn preflight_inner(target_path: &Path, session: SessionId) -> Result<DnsExchangePreflight> {
        let parent = target_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .context("resolver target has no parent directory")?;
        let target = component(
            target_path
                .file_name()
                .context("resolver target has no file name")?,
            "resolver target",
        )?;
        let exchange = component(
            OsStr::new(&super::exchange_name(session)),
            "resolver exchange name",
        )?;
        let anchor = DirectoryAnchor::open(parent)?;
        let baseline = inspect_component_detailed(&anchor, &target)?
            .context("resolver target is absent during DNS preflight")?;
        if inspect_component(&anchor, &exchange)?.is_some() {
            return Err(conflict(
                "preflight exchange name",
                "session exchange name is already present",
            ));
        }
        let target_mount_id = statx_mount_id(anchor.fd(), &target, libc::AT_SYMLINK_NOFOLLOW)?;
        let target_is_mountpoint = target_mount_id != anchor.mount_id;
        anyhow::ensure!(
            !target_is_mountpoint,
            "resolver target is a mountpoint or bind mount (target mount id {target_mount_id}, parent mount id {})",
            anchor.mount_id
        );

        probe_residue_free_primitives(&anchor)?;
        anchor.revalidate()?;
        let after_probe = inspect_component_detailed(&anchor, &target)?
            .context("resolver target disappeared during DNS preflight")?;
        if after_probe != baseline {
            return Err(conflict(
                "preflight target stability",
                "resolver target inode/version/digest changed during residue-free capability probe",
            ));
        }
        let after_mount_id = statx_mount_id(anchor.fd(), &target, libc::AT_SYMLINK_NOFOLLOW)?;
        if after_mount_id != target_mount_id {
            return Err(conflict(
                "preflight target stability",
                "resolver target mount identity changed during residue-free capability probe",
            ));
        }

        let capabilities = DnsExchangeCapabilities {
            parent: anchor.identity,
            parent_mount_id: anchor.mount_id,
            target: baseline.object.clone(),
            target_size: baseline.stable.size,
            target_mount_id,
            target_is_mountpoint,
            unnamed_tmpfile: true,
            named_mutations_deferred_until_journal: true,
            durable_directory_fsync: true,
        };
        Ok(DnsExchangePreflight {
            anchor,
            target,
            exchange,
            baseline,
            capabilities,
        })
    }

    pub fn preflight_dns_exchange(
        target_path: &Path,
        session: SessionId,
    ) -> DnsExchangeResult<DnsExchangePreflight> {
        typed(
            "preflight resolver exchange",
            preflight_inner(target_path, session),
        )
    }

    #[derive(Debug)]
    pub struct PreparedDnsExchange {
        anchor: DirectoryAnchor,
        target: CString,
        exchange: CString,
        staged: File,
        resource: DnsResource,
    }

    impl PreparedDnsExchange {
        /// Create and fsync an unnamed pinned inode. The caller must durably
        /// append `resource()` as Planned before calling `link_after_journal`.
        pub fn stage_unnamed(
            target_path: &Path,
            session: SessionId,
            contents: &[u8],
        ) -> Result<Self> {
            let preflight = preflight_inner(target_path, session)?;
            Self::stage_preflighted_anyhow(preflight, contents)
        }

        /// Consume a successful capability token. This lets the caller run all
        /// filesystem capability checks before installing firewall/routes/TUN,
        /// while retaining the exact anchored directory descriptor until stage.
        pub fn stage_preflighted(
            preflight: DnsExchangePreflight,
            contents: &[u8],
        ) -> DnsExchangeResult<Self> {
            typed(
                "stage preflighted resolver exchange",
                Self::stage_preflighted_anyhow(preflight, contents),
            )
        }

        fn stage_preflighted_anyhow(
            preflight: DnsExchangePreflight,
            contents: &[u8],
        ) -> Result<Self> {
            anyhow::ensure!(!contents.is_empty(), "pinned resolver content is empty");
            anyhow::ensure!(
                contents.len() as u64 <= MAX_RESOLVER_OBJECT_BYTES,
                "pinned resolver content exceeds {} bytes",
                MAX_RESOLVER_OBJECT_BYTES
            );
            let DnsExchangePreflight {
                anchor,
                target,
                exchange,
                baseline,
                capabilities: _,
            } = preflight;
            anchor.revalidate()?;
            let current = inspect_component_detailed(&anchor, &target)?
                .context("resolver target is absent before staging")?;
            if current != baseline {
                return Err(conflict(
                    "stage target revalidation",
                    "resolver target inode/version/digest changed after preflight",
                ));
            }
            if inspect_component(&anchor, &exchange)?.is_some() {
                return Err(conflict(
                    "stage exchange revalidation",
                    "resolver exchange name appeared after preflight",
                ));
            }

            let staged = create_unnamed_file(&anchor, contents)?;
            let expected_pinned = expected_linked_object(&staged, contents)?;
            let resource = DnsResource {
                target: ResolverTarget::EtcResolvConf,
                original: baseline.object.identity,
                original_sha256: baseline.object.sha256,
                pinned: expected_pinned.identity,
                pinned_sha256: Sha256Digest::from_bytes(Sha256::digest(contents).into()),
            };
            resource.validate().map_err(anyhow::Error::new)?;
            Ok(Self {
                anchor,
                target,
                exchange,
                staged,
                resource,
            })
        }

        pub fn resource(&self) -> &DnsResource {
            &self.resource
        }

        /// Link the already-journaled unnamed inode at the deterministic
        /// exchange name, then fsync the directory. Capability or I/O failures
        /// are operational; a raced/foreign pathname is an ownership conflict.
        pub fn link_after_journal(self) -> DnsExchangeResult<LinkedDnsExchange> {
            typed(
                "link journaled resolver stage",
                self.link_after_journal_anyhow(),
            )
        }

        fn link_after_journal_anyhow(self) -> Result<LinkedDnsExchange> {
            link_unnamed(&self.anchor, &self.staged, &self.exchange)
                .context("link journaled O_TMPFILE resolver stage")?;
            self.anchor.sync()?;
            let linked = topology(&self.anchor, &self.target, &self.exchange, &self.resource)?;
            if linked != DnsExchangeTopology::Staged {
                return Err(conflict(
                    "verify linked stage",
                    "linked resolver stage does not match journaled topology",
                ));
            }
            Ok(LinkedDnsExchange {
                anchor: self.anchor,
                target: self.target,
                exchange: self.exchange,
                resource: self.resource,
            })
        }
    }

    #[derive(Debug)]
    pub struct LinkedDnsExchange {
        anchor: DirectoryAnchor,
        target: CString,
        exchange: CString,
        resource: DnsResource,
    }

    impl LinkedDnsExchange {
        pub fn resource(&self) -> &DnsResource {
            &self.resource
        }

        /// Atomically activate only from the exact staged topology. Any
        /// directory-fsync ambiguity remains recoverable by the durable journal.
        pub fn activate_after_journal(self) -> DnsExchangeResult<ActiveDnsExchange> {
            typed(
                "activate journaled resolver exchange",
                self.activate_after_journal_anyhow(),
            )
        }

        fn activate_after_journal_anyhow(self) -> Result<ActiveDnsExchange> {
            if topology(&self.anchor, &self.target, &self.exchange, &self.resource)?
                != DnsExchangeTopology::Staged
            {
                return Err(conflict(
                    "activate resolver",
                    "staged topology conflicts before activation",
                ));
            }
            let original = ObservedDnsObject {
                identity: self.resource.original,
                sha256: self.resource.original_sha256,
            };
            let pinned = ObservedDnsObject {
                identity: self.resource.pinned,
                sha256: Some(self.resource.pinned_sha256),
            };
            rename_exchange_exact(
                &self.anchor,
                &self.target,
                &original,
                &self.exchange,
                &pinned,
            )?;
            self.anchor.sync()?;
            if topology(&self.anchor, &self.target, &self.exchange, &self.resource)?
                != DnsExchangeTopology::Active
            {
                return Err(conflict(
                    "verify resolver activation",
                    "rename did not produce the exact active topology",
                ));
            }
            Ok(ActiveDnsExchange {
                anchor: self.anchor,
                target: self.target,
                exchange: self.exchange,
                resource: self.resource,
            })
        }
    }

    #[derive(Debug)]
    pub struct ActiveDnsExchange {
        anchor: DirectoryAnchor,
        target: CString,
        exchange: CString,
        resource: DnsResource,
    }

    impl ActiveDnsExchange {
        pub fn resource(&self) -> &DnsResource {
            &self.resource
        }

        pub fn topology(&self) -> Result<DnsExchangeTopology> {
            topology(&self.anchor, &self.target, &self.exchange, &self.resource)
        }

        /// Restore by exact inode exchange, then unlink only the verified pinned
        /// inode. No mutation occurs if the initial topology is a conflict.
        pub fn restore_after_journal(&mut self) -> Result<()> {
            execute_recovery(&self.anchor, &self.target, &self.exchange, &self.resource)
        }
    }

    fn execute_recovery(
        anchor: &DirectoryAnchor,
        target: &CStr,
        exchange: &CStr,
        resource: &DnsResource,
    ) -> Result<()> {
        execute_recovery_with_hook(anchor, target, exchange, resource, |_| {})
    }

    fn execute_recovery_with_hook<F>(
        anchor: &DirectoryAnchor,
        target: &CStr,
        exchange: &CStr,
        resource: &DnsResource,
        mut hook: F,
    ) -> Result<()>
    where
        F: FnMut(RecoveryBoundary),
    {
        let before = topology(anchor, target, exchange, resource)?;
        let plan = plan_dns_recovery(before)?;
        let original = ObservedDnsObject {
            identity: resource.original,
            sha256: resource.original_sha256,
        };
        let pinned = ObservedDnsObject {
            identity: resource.pinned,
            sha256: Some(resource.pinned_sha256),
        };
        match plan.action {
            DnsRecoveryAction::ExchangeThenUnlink => {
                hook(RecoveryBoundary::AfterTopologyBeforeExchangeRevalidation);
                rename_exchange_exact(anchor, target, &pinned, exchange, &original)?;
                anchor.sync()?;
                if topology(anchor, target, exchange, resource)? != DnsExchangeTopology::Staged {
                    return Err(conflict(
                        "verify recovery exchange",
                        "exchange did not restore the exact staged topology",
                    ));
                }
                unlink_exact_regular_after_hook(anchor, exchange, &pinned, &mut hook)?;
            }
            DnsRecoveryAction::UnlinkStaged => {
                unlink_exact_regular_after_hook(anchor, exchange, &pinned, &mut hook)?;
            }
            DnsRecoveryAction::AlreadyAbsent => {}
        }
        if topology(anchor, target, exchange, resource)? != DnsExchangeTopology::Absent {
            return Err(conflict(
                "verify recovery completion",
                "resolver recovery did not reach exact absent topology",
            ));
        }
        Ok(())
    }

    pub fn inspect_exchange(
        target_path: &Path,
        session: SessionId,
        resource: &DnsResource,
    ) -> Result<DnsExchangeTopology> {
        let parent = target_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .context("resolver target has no parent directory")?;
        let target = component(
            target_path
                .file_name()
                .context("resolver target has no file name")?,
            "resolver target",
        )?;
        let exchange = component(
            OsStr::new(&super::exchange_name(session)),
            "resolver exchange name",
        )?;
        let anchor = DirectoryAnchor::open(parent)?;
        topology(&anchor, &target, &exchange, resource)
    }

    /// Execute one DNS recovery step after a higher-level all-resource planner
    /// has already authorized cleanup. The exact two-name topology is rechecked
    /// before the first mutation.
    pub fn recover_exchange(
        target_path: &Path,
        session: SessionId,
        resource: &DnsResource,
    ) -> Result<()> {
        let parent = target_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .context("resolver target has no parent directory")?;
        let target = component(
            target_path
                .file_name()
                .context("resolver target has no file name")?,
            "resolver target",
        )?;
        let exchange = component(
            OsStr::new(&super::exchange_name(session)),
            "resolver exchange name",
        )?;
        let anchor = DirectoryAnchor::open(parent)?;
        execute_recovery(&anchor, &target, &exchange, resource)
    }

    pub fn inspect_exchange_typed(
        target_path: &Path,
        session: SessionId,
        resource: &DnsResource,
    ) -> DnsExchangeResult<DnsExchangeTopology> {
        typed(
            "inspect resolver exchange",
            inspect_exchange(target_path, session, resource),
        )
    }

    pub fn recover_exchange_typed(
        target_path: &Path,
        session: SessionId,
        resource: &DnsResource,
    ) -> DnsExchangeResult<()> {
        typed(
            "recover resolver exchange",
            recover_exchange(target_path, session, resource),
        )
    }

    #[cfg(test)]
    pub(super) fn recover_exchange_with_test_hook<F>(
        target_path: &Path,
        session: SessionId,
        resource: &DnsResource,
        hook: F,
    ) -> Result<()>
    where
        F: FnMut(RecoveryBoundary),
    {
        let parent = target_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .context("resolver target has no parent directory")?;
        let target = component(
            target_path
                .file_name()
                .context("resolver target has no file name")?,
            "resolver target",
        )?;
        let exchange = component(
            OsStr::new(&super::exchange_name(session)),
            "resolver exchange name",
        )?;
        let anchor = DirectoryAnchor::open(parent)?;
        execute_recovery_with_hook(&anchor, &target, &exchange, resource, hook)
    }

    #[cfg(test)]
    pub(super) fn residue_free_probe_with_test_fault(
        parent: &Path,
        fail_at: ResidueFreeProbeBoundary,
    ) -> Result<()> {
        let anchor = DirectoryAnchor::open(parent)?;
        probe_residue_free_primitives_with_hook(&anchor, |boundary| {
            if boundary == fail_at {
                anyhow::bail!("injected residue-free DNS preflight fault at {boundary:?}")
            }
            Ok(())
        })
    }

    #[cfg(test)]
    pub(super) fn residue_free_probe_with_test_sigkill(
        parent: &Path,
        kill_at: ResidueFreeProbeBoundary,
    ) -> Result<()> {
        let anchor = DirectoryAnchor::open(parent)?;
        probe_residue_free_primitives_with_hook(&anchor, |boundary| {
            if boundary == kill_at {
                // SAFETY: getpid returns this process and SIGKILL has no
                // userspace cleanup path. If delivery unexpectedly fails, turn
                // that into an ordinary test failure rather than continuing.
                let result = unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
                anyhow::ensure!(result == 0, "inject SIGKILL into DNS probe child");
                unreachable!("successful SIGKILL delivery cannot return to userspace");
            }
            Ok(())
        })
    }

    pub use self::ActiveDnsExchange as Active;
    pub use self::DnsExchangePreflight as Preflight;
    pub use self::LinkedDnsExchange as Linked;
    pub use self::PreparedDnsExchange as Prepared;
}

#[cfg(target_os = "linux")]
pub use linux::{
    inspect_exchange, inspect_exchange_typed, preflight_dns_exchange, recover_exchange,
    recover_exchange_typed, Active as ActiveDnsExchange, Linked as LinkedDnsExchange,
    Preflight as DnsExchangePreflight, Prepared as PreparedDnsExchange,
};

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct DnsExchangePreflight {
    _private: (),
}

#[cfg(not(target_os = "linux"))]
pub fn preflight_dns_exchange(
    _target_path: &Path,
    _session: SessionId,
) -> DnsExchangeResult<DnsExchangePreflight> {
    Err(DnsExchangeFailure::operational(
        "preflight resolver exchange",
        "crash-recoverable DNS exchange runtime is Linux-only",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn inspect_exchange(
    _target_path: &Path,
    _session: SessionId,
    _resource: &DnsResource,
) -> Result<DnsExchangeTopology> {
    anyhow::bail!("crash-recoverable DNS exchange runtime is Linux-only")
}

#[cfg(not(target_os = "linux"))]
pub fn recover_exchange(
    _target_path: &Path,
    _session: SessionId,
    _resource: &DnsResource,
) -> Result<()> {
    anyhow::bail!("crash-recoverable DNS exchange runtime is Linux-only")
}

#[cfg(not(target_os = "linux"))]
pub fn inspect_exchange_typed(
    _target_path: &Path,
    _session: SessionId,
    _resource: &DnsResource,
) -> DnsExchangeResult<DnsExchangeTopology> {
    Err(DnsExchangeFailure::operational(
        "inspect resolver exchange",
        "crash-recoverable DNS exchange runtime is Linux-only",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn recover_exchange_typed(
    _target_path: &Path,
    _session: SessionId,
    _resource: &DnsResource,
) -> DnsExchangeResult<()> {
    Err(DnsExchangeFailure::operational(
        "recover resolver exchange",
        "crash-recoverable DNS exchange runtime is Linux-only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use std::fs;

    fn identity(inode: u64, kind: FileKind) -> FileIdentity {
        FileIdentity {
            device: 7,
            inode,
            uid: 0,
            gid: 0,
            mode: match kind {
                FileKind::Regular => 0o100644,
                FileKind::Symlink => 0o120777,
            },
            link_count: 1,
            kind,
        }
    }

    fn object(inode: u64, kind: FileKind, digest: Option<Sha256Digest>) -> ObservedDnsObject {
        ObservedDnsObject {
            identity: identity(inode, kind),
            sha256: digest,
        }
    }

    fn resource(original_kind: FileKind) -> DnsResource {
        DnsResource {
            target: ResolverTarget::EtcResolvConf,
            original: identity(10, original_kind),
            original_sha256: (original_kind == FileKind::Regular)
                .then_some(Sha256Digest::from_bytes([1; 32])),
            pinned: identity(11, FileKind::Regular),
            pinned_sha256: Sha256Digest::from_bytes([2; 32]),
        }
    }

    #[test]
    fn classifies_only_three_exact_recoverable_topologies() {
        let resource = resource(FileKind::Regular);
        let original = object(
            10,
            FileKind::Regular,
            Some(Sha256Digest::from_bytes([1; 32])),
        );
        let pinned = object(
            11,
            FileKind::Regular,
            Some(Sha256Digest::from_bytes([2; 32])),
        );

        assert_eq!(
            classify_dns_exchange(&resource, Some(&pinned), Some(&original)),
            DnsExchangeTopology::Active
        );
        assert_eq!(
            classify_dns_exchange(&resource, Some(&original), Some(&pinned)),
            DnsExchangeTopology::Staged
        );
        assert_eq!(
            classify_dns_exchange(&resource, Some(&original), None),
            DnsExchangeTopology::Absent
        );
    }

    #[test]
    fn same_contents_under_foreign_inode_is_conflict() {
        let resource = resource(FileKind::Regular);
        let foreign_original = object(
            99,
            FileKind::Regular,
            Some(Sha256Digest::from_bytes([1; 32])),
        );
        let pinned = object(
            11,
            FileKind::Regular,
            Some(Sha256Digest::from_bytes([2; 32])),
        );
        assert_eq!(
            classify_dns_exchange(&resource, Some(&foreign_original), Some(&pinned)),
            DnsExchangeTopology::Conflict
        );
    }

    #[test]
    fn same_inode_with_modified_contents_is_conflict() {
        let resource = resource(FileKind::Regular);
        let modified = object(
            10,
            FileKind::Regular,
            Some(Sha256Digest::from_bytes([9; 32])),
        );
        assert_eq!(
            classify_dns_exchange(&resource, Some(&modified), None),
            DnsExchangeTopology::Conflict
        );
    }

    #[test]
    fn missing_original_or_mixed_names_are_conflicts() {
        let resource = resource(FileKind::Regular);
        let original = object(
            10,
            FileKind::Regular,
            Some(Sha256Digest::from_bytes([1; 32])),
        );
        let pinned = object(
            11,
            FileKind::Regular,
            Some(Sha256Digest::from_bytes([2; 32])),
        );
        assert_eq!(
            classify_dns_exchange(&resource, None, Some(&original)),
            DnsExchangeTopology::Conflict
        );
        assert_eq!(
            classify_dns_exchange(&resource, Some(&pinned), None),
            DnsExchangeTopology::Conflict
        );
        assert_eq!(
            classify_dns_exchange(&resource, Some(&original), Some(&original)),
            DnsExchangeTopology::Conflict
        );
    }

    #[test]
    fn symlink_original_is_identity_bound_without_regular_digest() {
        let resource = resource(FileKind::Symlink);
        let original = object(10, FileKind::Symlink, None);
        let pinned = object(
            11,
            FileKind::Regular,
            Some(Sha256Digest::from_bytes([2; 32])),
        );
        assert_eq!(
            classify_dns_exchange(&resource, Some(&pinned), Some(&original)),
            DnsExchangeTopology::Active
        );
    }

    #[test]
    fn recovery_plan_refuses_conflict_before_exposing_an_action() {
        let failure = plan_dns_recovery(DnsExchangeTopology::Conflict).unwrap_err();
        assert_eq!(failure.kind(), DnsExchangeFailureKind::Conflict);
        assert_eq!(failure.operation(), "plan recovery");
        assert_eq!(
            plan_dns_recovery(DnsExchangeTopology::Active)
                .unwrap()
                .action,
            DnsRecoveryAction::ExchangeThenUnlink
        );
        assert_eq!(
            plan_dns_recovery(DnsExchangeTopology::Staged)
                .unwrap()
                .action,
            DnsRecoveryAction::UnlinkStaged
        );
        assert_eq!(
            plan_dns_recovery(DnsExchangeTopology::Absent)
                .unwrap()
                .action,
            DnsRecoveryAction::AlreadyAbsent
        );
    }

    #[cfg(target_os = "linux")]
    fn linux_test_directory(label: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let path = std::env::temp_dir().join(format!(
            "shadowpipe-dns-exchange-{label}-{}-{}",
            std::process::id(),
            SessionId::generate().unwrap()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[cfg(target_os = "linux")]
    fn directory_names(parent: &Path) -> Vec<String> {
        let mut names = fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    #[cfg(target_os = "linux")]
    fn failure_kind(error: &anyhow::Error) -> Option<DnsExchangeFailureKind> {
        error
            .downcast_ref::<DnsExchangeFailure>()
            .map(DnsExchangeFailure::kind)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_preflight_is_namespace_neutral_and_defers_named_mutations_until_journal() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = linux_test_directory("preflight");
        let target = directory.join("resolv.conf");
        let original = b"nameserver 192.0.2.53\n";
        fs::write(&target, original).unwrap();
        let before = fs::symlink_metadata(&target).unwrap();
        let session = SessionId::generate().unwrap();
        let names_before = directory_names(&directory);

        let preflight = preflight_dns_exchange(&target, session).unwrap();
        let capabilities = preflight.capabilities();
        assert!(capabilities.unnamed_tmpfile);
        assert!(capabilities.named_mutations_deferred_until_journal);
        assert!(capabilities.durable_directory_fsync);
        assert!(!capabilities.target_is_mountpoint);
        assert_eq!(capabilities.target_size, original.len() as u64);
        assert_eq!(fs::read(&target).unwrap(), original);
        assert_eq!(fs::symlink_metadata(&target).unwrap().ino(), before.ino());
        assert_eq!(directory_names(&directory), names_before);

        let prepared =
            PreparedDnsExchange::stage_preflighted(preflight, b"nameserver 10.8.0.1\n").unwrap();
        drop(prepared);
        assert_eq!(fs::read(&target).unwrap(), original);
        assert_eq!(directory_names(&directory), names_before);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_residue_free_preflight_faults_have_no_namespace_cleanup_obligation() {
        use super::linux::ResidueFreeProbeBoundary;

        let directory = linux_test_directory("probe-faults");
        for boundary in [
            ResidueFreeProbeBoundary::UnnamedFileSynced,
            ResidueFreeProbeBoundary::DirectorySynced,
        ] {
            assert!(
                super::linux::residue_free_probe_with_test_fault(&directory, boundary).is_err()
            );
            assert_eq!(
                directory_names(&directory),
                Vec::<String>::new(),
                "{boundary:?}"
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_sigkill_during_preflight_cannot_leave_a_named_residue() {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::Command;

        const CHILD_TEST: &str = "dns_exchange::tests::linux_residue_free_preflight_sigkill_child";
        for boundary in ["unnamed-file-synced", "directory-synced"] {
            let directory = linux_test_directory(&format!("sigkill-{boundary}"));
            let target = directory.join("resolv.conf");
            let original = b"nameserver 192.0.2.57\n";
            fs::write(&target, original).unwrap();
            let target_before = fs::symlink_metadata(&target).unwrap();
            let names_before = directory_names(&directory);

            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", CHILD_TEST, "--nocapture"])
                .env("SHADOWPIPE_DNS_PREFLIGHT_SIGKILL_DIR", &directory)
                .env("SHADOWPIPE_DNS_PREFLIGHT_SIGKILL_BOUNDARY", boundary)
                .status()
                .unwrap();

            assert_eq!(status.signal(), Some(libc::SIGKILL), "{boundary}: {status}");
            assert_eq!(directory_names(&directory), names_before, "{boundary}");
            assert_eq!(fs::read(&target).unwrap(), original, "{boundary}");
            let target_after = fs::symlink_metadata(&target).unwrap();
            assert_eq!(target_after.dev(), target_before.dev(), "{boundary}");
            assert_eq!(target_after.ino(), target_before.ino(), "{boundary}");

            // A fresh process can immediately preflight the same target. There
            // is no stale-probe scanner or best-effort deletion on restart
            // because the killed process never published a name to recover.
            let restart = preflight_dns_exchange(&target, SessionId::generate().unwrap())
                .unwrap_or_else(|error| panic!("restart after {boundary}: {error}"));
            drop(restart);
            assert_eq!(directory_names(&directory), names_before, "{boundary}");
            assert_eq!(fs::read(&target).unwrap(), original, "{boundary}");
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "SIGKILL subprocess helper; launched by the parent adversarial test"]
    fn linux_residue_free_preflight_sigkill_child() {
        use super::linux::ResidueFreeProbeBoundary;

        let Some(directory) = std::env::var_os("SHADOWPIPE_DNS_PREFLIGHT_SIGKILL_DIR") else {
            return;
        };
        let boundary = match std::env::var("SHADOWPIPE_DNS_PREFLIGHT_SIGKILL_BOUNDARY").as_deref() {
            Ok("unnamed-file-synced") => ResidueFreeProbeBoundary::UnnamedFileSynced,
            Ok("directory-synced") => ResidueFreeProbeBoundary::DirectorySynced,
            other => panic!("invalid SIGKILL helper boundary: {other:?}"),
        };
        super::linux::residue_free_probe_with_test_sigkill(Path::new(&directory), boundary)
            .unwrap();
        panic!("SIGKILL helper unexpectedly survived injected boundary");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unnamed_stage_exchange_and_restore_round_trip() {
        let directory = linux_test_directory("roundtrip");
        let target = directory.join("resolv.conf");
        let original = b"nameserver 192.0.2.53\n";
        let pinned = b"# shadowpipe\nnameserver 10.8.0.1\n";
        fs::write(&target, original).unwrap();
        let session = SessionId::generate().unwrap();

        let prepared = PreparedDnsExchange::stage_unnamed(&target, session, pinned).unwrap();
        let resource = prepared.resource().clone();
        assert_eq!(
            inspect_exchange(&target, session, &resource).unwrap(),
            DnsExchangeTopology::Absent,
            "unnamed pre-journal stage leaves no filesystem orphan"
        );
        let linked = prepared.link_after_journal().unwrap();
        assert_eq!(
            inspect_exchange(&target, session, &resource).unwrap(),
            DnsExchangeTopology::Staged
        );
        let mut active = linked.activate_after_journal().unwrap();
        assert_eq!(fs::read(&target).unwrap(), pinned);
        assert_eq!(active.topology().unwrap(), DnsExchangeTopology::Active);
        active.restore_after_journal().unwrap();
        assert_eq!(fs::read(&target).unwrap(), original);
        assert_eq!(
            inspect_exchange(&target, session, &resource).unwrap(),
            DnsExchangeTopology::Absent
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_link_after_journal_reports_typed_conflict_without_touching_foreign_name() {
        let directory = linux_test_directory("link-conflict");
        let target = directory.join("resolv.conf");
        let original = b"nameserver 192.0.2.58\n";
        let foreign = b"foreign exchange owner\n";
        fs::write(&target, original).unwrap();
        let session = SessionId::generate().unwrap();
        let prepared = PreparedDnsExchange::stage_unnamed(
            &target,
            session,
            b"# shadowpipe\nnameserver 10.8.0.1\n",
        )
        .unwrap();
        let exchange = directory.join(session.resolver_exchange_file_name());
        fs::write(&exchange, foreign).unwrap();

        let failure = prepared.link_after_journal().unwrap_err();
        assert_eq!(failure.kind(), DnsExchangeFailureKind::Conflict);
        assert_eq!(failure.operation(), "link unnamed object");
        assert_eq!(fs::read(&target).unwrap(), original);
        assert_eq!(fs::read(&exchange).unwrap(), foreign);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_activate_after_journal_reports_typed_conflict_without_renaming_foreign_target() {
        let directory = linux_test_directory("activate-conflict");
        let target = directory.join("resolv.conf");
        let original = b"nameserver 192.0.2.59\n";
        let pinned = b"# shadowpipe\nnameserver 10.8.0.1\n";
        let foreign = b"foreign resolver manager target\n";
        fs::write(&target, original).unwrap();
        let session = SessionId::generate().unwrap();
        let prepared = PreparedDnsExchange::stage_unnamed(&target, session, pinned).unwrap();
        let linked = prepared.link_after_journal().unwrap();
        let exchange = directory.join(session.resolver_exchange_file_name());
        let displaced = directory.join("displaced-original");
        fs::rename(&target, &displaced).unwrap();
        fs::write(&target, foreign).unwrap();

        let failure = linked.activate_after_journal().unwrap_err();
        assert_eq!(failure.kind(), DnsExchangeFailureKind::Conflict);
        assert_eq!(failure.operation(), "activate resolver");
        assert_eq!(fs::read(&target).unwrap(), foreign);
        assert_eq!(fs::read(&exchange).unwrap(), pinned);
        assert_eq!(fs::read(&displaced).unwrap(), original);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_modified_original_conflict_causes_zero_recovery_mutations() {
        let directory = linux_test_directory("conflict");
        let target = directory.join("resolv.conf");
        fs::write(&target, b"nameserver 192.0.2.54\n").unwrap();
        let session = SessionId::generate().unwrap();
        let prepared = PreparedDnsExchange::stage_unnamed(
            &target,
            session,
            b"# shadowpipe\nnameserver 10.8.0.1\n",
        )
        .unwrap();
        let resource = prepared.resource().clone();
        prepared.link_after_journal().unwrap();
        let exchange = directory.join(session.resolver_exchange_file_name());
        let exchange_before = fs::read(&exchange).unwrap();
        fs::write(&target, b"foreign mutation\n").unwrap();
        let target_before = fs::read(&target).unwrap();

        assert_eq!(
            inspect_exchange(&target, session, &resource).unwrap(),
            DnsExchangeTopology::Conflict
        );
        assert!(recover_exchange(&target, session, &resource).is_err());
        assert_eq!(fs::read(&target).unwrap(), target_before);
        assert_eq!(fs::read(&exchange).unwrap(), exchange_before);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_active_race_before_exchange_is_conflict_and_foreign_target_is_not_renamed() {
        use super::linux::RecoveryBoundary;

        let directory = linux_test_directory("active-race");
        let target = directory.join("resolv.conf");
        let original = b"nameserver 192.0.2.55\n";
        let pinned = b"nameserver 10.8.0.1\n";
        let foreign = b"foreign resolver manager target\n";
        fs::write(&target, original).unwrap();
        let session = SessionId::generate().unwrap();
        let prepared = PreparedDnsExchange::stage_unnamed(&target, session, pinned).unwrap();
        let resource = prepared.resource().clone();
        let linked = prepared.link_after_journal().unwrap();
        let active = linked.activate_after_journal().unwrap();
        drop(active);

        let displaced = directory.join("displaced-owned-pinned");
        let mut injected = false;
        let result = super::linux::recover_exchange_with_test_hook(
            &target,
            session,
            &resource,
            |boundary| {
                if boundary == RecoveryBoundary::AfterTopologyBeforeExchangeRevalidation {
                    assert!(!injected);
                    fs::rename(&target, &displaced).unwrap();
                    fs::write(&target, foreign).unwrap();
                    injected = true;
                }
            },
        );
        let error = result.unwrap_err();
        assert!(injected);
        assert_eq!(failure_kind(&error), Some(DnsExchangeFailureKind::Conflict));
        assert_eq!(fs::read(&target).unwrap(), foreign);
        assert_eq!(fs::read(&displaced).unwrap(), pinned);
        assert_eq!(
            fs::read(directory.join(session.resolver_exchange_file_name())).unwrap(),
            original
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unlink_race_never_unlinks_foreign_quarantine_replacement() {
        use super::linux::RecoveryBoundary;

        let directory = linux_test_directory("unlink-race");
        let target = directory.join("resolv.conf");
        let original = b"nameserver 192.0.2.56\n";
        let pinned = b"nameserver 10.8.0.1\n";
        let foreign = b"foreign sibling must survive\n";
        fs::write(&target, original).unwrap();
        let session = SessionId::generate().unwrap();
        let prepared = PreparedDnsExchange::stage_unnamed(&target, session, pinned).unwrap();
        let resource = prepared.resource().clone();
        let linked = prepared.link_after_journal().unwrap();
        drop(linked);

        let exchange = directory.join(session.resolver_exchange_file_name());
        let displaced = directory.join("displaced-owned-stage");
        let mut injected = false;
        let result = super::linux::recover_exchange_with_test_hook(
            &target,
            session,
            &resource,
            |boundary| {
                if boundary == RecoveryBoundary::AfterQuarantineOpenBeforeUnlink {
                    assert!(!injected);
                    fs::rename(&exchange, &displaced).unwrap();
                    fs::write(&exchange, foreign).unwrap();
                    injected = true;
                }
            },
        );
        let error = result.unwrap_err();
        assert!(injected);
        assert_eq!(failure_kind(&error), Some(DnsExchangeFailureKind::Conflict));
        assert_eq!(fs::read(&target).unwrap(), original);
        assert_eq!(fs::read(&exchange).unwrap(), foreign);
        assert_eq!(fs::read(&displaced).unwrap(), pinned);
        fs::remove_dir_all(directory).unwrap();
    }
}
