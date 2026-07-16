#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

//! Durable cross-session Linux output lockdown.
//!
//! The ordinary full-tunnel kill switch is owned by one client session.  Crash
//! recovery must eventually delete that session's routes, DNS exchange, TUN and
//! firewall objects, but deleting the old firewall before the replacement is
//! active creates a direct-egress handoff window.  This module owns a separate,
//! tiny native-nftables barrier whose lifetime spans that handoff:
//!
//! ```text
//! old kill switch -> arm lockdown -> recover old session -> arm new session
//!                 -> durable new Active -> release lockdown
//! ```
//!
//! A normal service stop performs the inverse transition but deliberately
//! leaves the lockdown active for the next process.  Only a successful new
//! full-tunnel activation or an explicit operator release may remove it.
//!
//! The barrier is intentionally independent from the main host-state schema.
//! Its own bounded, anchored WAL is written before every nft mutation.  Native
//! nft batches make table creation/deletion atomic across IPv4 and IPv6; exact
//! JSON census plus a kernel table-handle comparison immediately before the
//! name-based nft delete detects ordinary replacement/drift.  nft's delete
//! transaction does not itself provide a handle-CAS primitive; mutually
//! distrustful processes with the same root and network-namespace authority
//! are therefore outside this module's writer threat boundary.
//!
//! Scope is Linux L3 local output. An `inet output` base chain does not mediate
//! AF_PACKET/link-layer emission such as ARP or some DHCPv4 clients. A claim of
//! zero emitted frames needs an additional per-interface netdev/tc-BPF barrier;
//! that stronger L2 mechanism is not implemented here.

use crate::host_state::{BootId, NamespaceIdentity, OwnerIdentity, SessionId};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

pub const LOCKDOWN_JOURNAL_FILE: &str = "handoff-lockdown-v1.json";
const LOCKDOWN_SCHEMA_VERSION: u16 = 1;
const LOCKDOWN_CHAIN: &str = "sp_output";
const LOCKDOWN_PRIORITY: i64 = -400;
const MAX_LOCKDOWN_JOURNAL_BYTES: u64 = 16 * 1024;
const MAX_NFT_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_NFT_STDERR_BYTES: usize = 64 * 1024;
const NFT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const STATE_DIRECTORY_MODE: u32 = 0o700;
const JOURNAL_MODE: u32 = 0o600;

/// One already-established SSH server-to-client flow that may survive the
/// loopback-only handoff barrier.  All four fields are matched; there is no
/// conntrack or broad ESTABLISHED exception.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockdownControlFlow {
    pub source_ipv4: Ipv4Addr,
    pub source_port: u16,
    pub destination_ipv4: Ipv4Addr,
    pub destination_port: u16,
}

impl LockdownControlFlow {
    pub fn new(
        source_ipv4: Ipv4Addr,
        source_port: u16,
        destination_ipv4: Ipv4Addr,
        destination_port: u16,
    ) -> Result<Self> {
        let flow = Self {
            source_ipv4,
            source_port,
            destination_ipv4,
            destination_port,
        };
        flow.validate()?;
        Ok(flow)
    }

    fn validate(self) -> Result<()> {
        anyhow::ensure!(
            !self.source_ipv4.is_unspecified()
                && !self.source_ipv4.is_multicast()
                && !self.source_ipv4.is_broadcast(),
            "lockdown SSH source IPv4 is not a unicast address"
        );
        anyhow::ensure!(
            !self.destination_ipv4.is_unspecified()
                && !self.destination_ipv4.is_multicast()
                && !self.destination_ipv4.is_broadcast(),
            "lockdown SSH destination IPv4 is not a unicast address"
        );
        anyhow::ensure!(
            self.source_port != 0 && self.destination_port != 0,
            "lockdown SSH tuple contains a zero port"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LockdownPhase {
    Planned,
    Active,
    RemovePlanned,
}

/// Durable reason for crossing the barrier's release point.  Recovery never
/// infers authorization from kernel absence: an interrupted release is always
/// re-armed first, while this value explains which proof the caller supplied.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LockdownReleaseReason {
    ReplacementActive,
    ExplicitOperator,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LockdownJournalV1 {
    schema_version: u16,
    generation: u64,
    identity: SessionId,
    boot_id: BootId,
    uid: u32,
    network_namespace: NamespaceIdentity,
    mount_namespace: NamespaceIdentity,
    control_flow: Option<LockdownControlFlow>,
    phase: LockdownPhase,
    table_handle: Option<u64>,
    release_reason: Option<LockdownReleaseReason>,
}

impl LockdownJournalV1 {
    fn new_with_owner(
        control_flow: Option<LockdownControlFlow>,
        owner: &OwnerIdentity,
    ) -> Result<Self> {
        if let Some(flow) = control_flow {
            flow.validate()?;
        }
        let boot_id = owner
            .boot_id
            .context("Linux lockdown requires a readable boot identity")?;
        let network_namespace = owner
            .network_namespace
            .context("Linux lockdown requires a readable network namespace identity")?;
        let mount_namespace = owner
            .mount_namespace
            .context("Linux lockdown requires a readable mount namespace identity")?;
        let journal = Self {
            schema_version: LOCKDOWN_SCHEMA_VERSION,
            generation: 1,
            identity: SessionId::generate().context("generate lockdown table identity")?,
            boot_id,
            uid: owner.uid,
            network_namespace,
            mount_namespace,
            control_flow,
            phase: LockdownPhase::Planned,
            table_handle: None,
            release_reason: None,
        };
        journal.validate()?;
        Ok(journal)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == LOCKDOWN_SCHEMA_VERSION,
            "unsupported lockdown journal schema {}",
            self.schema_version
        );
        anyhow::ensure!(self.generation != 0, "lockdown generation is zero");
        anyhow::ensure!(
            self.identity.as_bytes() != &[0u8; 16],
            "lockdown identity is zero"
        );
        anyhow::ensure!(
            self.boot_id.as_bytes() != &[0u8; 16],
            "lockdown boot identity is zero"
        );
        if let Some(flow) = self.control_flow {
            flow.validate()?;
        }
        match self.phase {
            LockdownPhase::Planned => {
                anyhow::ensure!(
                    self.table_handle.is_none(),
                    "planned lockdown unexpectedly has a table handle"
                );
                anyhow::ensure!(
                    self.release_reason.is_none(),
                    "planned lockdown unexpectedly retains a release reason"
                );
            }
            LockdownPhase::Active => {
                anyhow::ensure!(
                    self.table_handle.is_some_and(|handle| handle != 0),
                    "active lockdown lacks a non-zero table handle"
                );
                anyhow::ensure!(
                    self.release_reason.is_none(),
                    "active lockdown unexpectedly retains a release reason"
                );
            }
            LockdownPhase::RemovePlanned => {
                anyhow::ensure!(
                    self.table_handle.is_some_and(|handle| handle != 0),
                    "removing lockdown lacks a non-zero table handle"
                );
                anyhow::ensure!(
                    self.release_reason.is_some(),
                    "removing lockdown lacks a typed release reason"
                );
            }
        }
        Ok(())
    }

    fn table_name(&self) -> String {
        format!("sp_lock_{}", self.identity.to_hex())
    }

    fn owner_comment(&self) -> String {
        format!("shadowpipe-lockdown-v1:{}", self.identity)
    }

    fn next(
        &self,
        phase: LockdownPhase,
        table_handle: Option<u64>,
        release_reason: Option<LockdownReleaseReason>,
    ) -> Result<Self> {
        let mut next = self.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .context("lockdown generation overflow")?;
        next.phase = phase;
        next.table_handle = table_handle;
        next.release_reason = release_reason;
        next.validate()?;
        Ok(next)
    }

    fn renewed_after_reboot(
        &self,
        control_flow: Option<LockdownControlFlow>,
        owner: &OwnerIdentity,
    ) -> Result<Self> {
        let mut next = self.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .context("lockdown generation overflow")?;
        next.identity = SessionId::generate().context("renew lockdown identity after reboot")?;
        next.boot_id = owner
            .boot_id
            .context("Linux lockdown requires a readable boot identity")?;
        next.uid = owner.uid;
        next.network_namespace = owner
            .network_namespace
            .context("Linux lockdown requires a readable network namespace identity")?;
        next.mount_namespace = owner
            .mount_namespace
            .context("Linux lockdown requires a readable mount namespace identity")?;
        next.control_flow = control_flow;
        next.phase = LockdownPhase::Planned;
        next.table_handle = None;
        next.release_reason = None;
        next.validate()?;
        Ok(next)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LockdownObservation {
    Absent,
    Exact { table_handle: u64 },
    Conflict,
}

trait LockdownStore {
    fn load_optional(&self) -> Result<Option<LockdownJournalV1>>;
    fn create(&mut self, journal: &LockdownJournalV1) -> Result<()>;
    fn replace(&mut self, current: &LockdownJournalV1, next: &LockdownJournalV1) -> Result<()>;
    fn remove(&mut self, current: &LockdownJournalV1) -> Result<()>;
}

trait LockdownKernel {
    fn inspect(&mut self, journal: &LockdownJournalV1) -> Result<LockdownObservation>;
    fn install(&mut self, journal: &LockdownJournalV1) -> Result<u64>;
    fn remove(&mut self, journal: &LockdownJournalV1, expected_handle: u64) -> Result<()>;
}

struct LockdownCoordinator<S, K> {
    store: S,
    kernel: K,
    journal: Option<LockdownJournalV1>,
    requested_control_flow: Option<LockdownControlFlow>,
}

impl<S: LockdownStore, K: LockdownKernel> LockdownCoordinator<S, K> {
    fn open(store: S, kernel: K, requested: Option<LockdownControlFlow>) -> Result<Self> {
        if let Some(flow) = requested {
            flow.validate()?;
        }
        let journal = store.load_optional()?;
        if let Some(existing) = &journal {
            existing.validate()?;
        }
        Ok(Self {
            store,
            kernel,
            journal,
            requested_control_flow: requested,
        })
    }

    fn has_journal(&self) -> bool {
        self.journal.is_some()
    }

    fn persist(&mut self, next: LockdownJournalV1) -> Result<()> {
        let current = self
            .journal
            .as_ref()
            .context("lockdown persistence has no current journal")?;
        self.store.replace(current, &next)?;
        self.journal = Some(next);
        Ok(())
    }

    fn install_planned(&mut self) -> Result<()> {
        let journal = self
            .journal
            .as_ref()
            .context("lockdown install has no planned journal")?
            .clone();
        anyhow::ensure!(
            journal.phase == LockdownPhase::Planned && journal.table_handle.is_none(),
            "lockdown install requires a Planned WAL"
        );
        let handle = self
            .kernel
            .install(&journal)
            .context("atomically install native-nft lockdown")?;
        anyhow::ensure!(handle != 0, "nft returned a zero lockdown table handle");
        self.persist(journal.next(LockdownPhase::Active, Some(handle), None)?)
            .context("acknowledge installed lockdown after kernel success")
    }

    fn create_and_install_with_owner(&mut self, owner: &OwnerIdentity) -> Result<()> {
        anyhow::ensure!(self.journal.is_none(), "lockdown WAL already exists");
        let journal = LockdownJournalV1::new_with_owner(self.requested_control_flow, owner)?;
        self.store
            .create(&journal)
            .context("WAL lockdown Planned before nft mutation")?;
        self.journal = Some(journal);
        self.install_planned()
    }

    fn arm(&mut self) -> Result<()> {
        let owner = OwnerIdentity::capture().context("capture current lockdown context")?;
        self.arm_with_owner(&owner)
    }

    fn arm_with_owner(&mut self, owner: &OwnerIdentity) -> Result<()> {
        if self.journal.is_none() {
            return self.create_and_install_with_owner(owner);
        }

        let current_boot = owner
            .boot_id
            .context("Linux lockdown requires a readable boot identity")?;
        let current_namespace = owner
            .network_namespace
            .context("Linux lockdown requires a readable network namespace identity")?;
        let current_mount_namespace = owner
            .mount_namespace
            .context("Linux lockdown requires a readable mount namespace identity")?;
        let current = self.journal.as_ref().expect("checked journal").clone();
        anyhow::ensure!(
            current.uid == owner.uid,
            "lockdown WAL UID {} differs from current UID {}",
            current.uid,
            owner.uid
        );

        if current.boot_id != current_boot {
            match self.kernel.inspect(&current)? {
                LockdownObservation::Absent => {
                    // Never carry a pre-reboot SSH tuple into the new boot.
                    // Only an exact tuple explicitly observed/requested by the
                    // current process may enter the renewed WAL.
                    let renewed =
                        current.renewed_after_reboot(self.requested_control_flow, owner)?;
                    self.persist(renewed)?;
                    return self.install_planned();
                }
                LockdownObservation::Exact { .. } | LockdownObservation::Conflict => {
                    anyhow::bail!(
                        "journal-named lockdown table exists after reboot; refusing to adopt or delete it"
                    )
                }
            }
        }

        anyhow::ensure!(
            current.network_namespace == current_namespace,
            "lockdown WAL belongs to a different same-boot network namespace"
        );
        anyhow::ensure!(
            current.mount_namespace == current_mount_namespace,
            "lockdown WAL belongs to a different same-boot mount namespace"
        );
        if let Some(requested) = self.requested_control_flow {
            anyhow::ensure!(
                current.control_flow == Some(requested),
                "active lockdown is bound to a different exact SSH control flow"
            );
        }
        let observation = self.kernel.inspect(&current)?;
        match (current.phase, observation) {
            (_, LockdownObservation::Conflict) => {
                anyhow::bail!("lockdown table differs from the complete journal-owned nft shape")
            }
            (LockdownPhase::Planned, LockdownObservation::Absent) => self.install_planned(),
            (LockdownPhase::Planned, LockdownObservation::Exact { table_handle }) => self
                .persist(current.next(LockdownPhase::Active, Some(table_handle), None)?)
                .context("acknowledge pre-existing exact lockdown after interrupted install"),
            (LockdownPhase::Active, LockdownObservation::Exact { table_handle }) => {
                anyhow::ensure!(
                    current.table_handle == Some(table_handle),
                    "lockdown nft table handle changed: WAL {:?}, kernel {table_handle}",
                    current.table_handle
                );
                Ok(())
            }
            (LockdownPhase::Active, LockdownObservation::Absent) => {
                let planned = current.next(LockdownPhase::Planned, None, None)?;
                self.persist(planned)?;
                self.install_planned()
            }
            (LockdownPhase::RemovePlanned, LockdownObservation::Exact { table_handle }) => {
                anyhow::ensure!(
                    current.table_handle == Some(table_handle),
                    "removing lockdown nft table handle changed: WAL {:?}, kernel {table_handle}",
                    current.table_handle
                );
                self.persist(current.next(LockdownPhase::Active, Some(table_handle), None)?)
                    .context("adopt exact lockdown instead of completing an old release")
            }
            (LockdownPhase::RemovePlanned, LockdownObservation::Absent) => {
                // A previous process deleted the barrier only after its replacement
                // kill switch was active, then crashed before WAL acknowledgement.
                // Re-arm before old-session recovery can remove that replacement.
                let planned = current.next(LockdownPhase::Planned, None, None)?;
                self.persist(planned)?;
                self.install_planned()
            }
        }
    }

    fn release(&mut self, reason: LockdownReleaseReason) -> Result<()> {
        let current = self
            .journal
            .as_ref()
            .context("no durable lockdown is active")?
            .clone();
        anyhow::ensure!(
            current.phase == LockdownPhase::Active,
            "lockdown release requires an Active WAL"
        );
        let expected_handle = current
            .table_handle
            .context("active lockdown lacks table handle")?;
        match self.kernel.inspect(&current)? {
            LockdownObservation::Exact { table_handle } if table_handle == expected_handle => {}
            LockdownObservation::Exact { table_handle } => anyhow::bail!(
                "lockdown table handle changed before release: expected {expected_handle}, found {table_handle}"
            ),
            LockdownObservation::Absent => {
                anyhow::bail!("active lockdown table is absent before authorized release")
            }
            LockdownObservation::Conflict => {
                anyhow::bail!("lockdown table changed before authorized release")
            }
        }
        let removing = current.next(
            LockdownPhase::RemovePlanned,
            Some(expected_handle),
            Some(reason),
        )?;
        self.persist(removing.clone())
            .context("WAL lockdown removal before nft mutation")?;
        self.kernel
            .remove(&removing, expected_handle)
            .context("atomically remove exact lockdown table")?;
        match self.kernel.inspect(&removing)? {
            LockdownObservation::Absent => {}
            LockdownObservation::Exact { .. } | LockdownObservation::Conflict => {
                anyhow::bail!("lockdown table remains or changed after exact removal")
            }
        }
        self.store
            .remove(&removing)
            .context("acknowledge lockdown removal by deleting its WAL")?;
        self.journal = None;
        Ok(())
    }

    fn prove_active(&mut self) -> Result<()> {
        let owner = OwnerIdentity::capture().context("capture lockdown proof context")?;
        let current = self
            .journal
            .as_ref()
            .context("lockdown Active proof has no WAL")?;
        anyhow::ensure!(
            current.phase == LockdownPhase::Active,
            "lockdown Active proof found a non-Active WAL"
        );
        anyhow::ensure!(
            current.uid == owner.uid
                && current.boot_id == owner.boot_id.context("Active proof lacks boot identity")?
                && current.network_namespace
                    == owner
                        .network_namespace
                        .context("Active proof lacks network namespace identity")?
                && current.mount_namespace
                    == owner
                        .mount_namespace
                        .context("Active proof lacks mount namespace identity")?,
            "lockdown Active proof owner/boot/namespace context differs"
        );
        let expected_handle = current
            .table_handle
            .context("Active lockdown WAL lacks a table handle")?;
        match self.kernel.inspect(current)? {
            LockdownObservation::Exact { table_handle } if table_handle == expected_handle => {
                Ok(())
            }
            LockdownObservation::Exact { table_handle } => anyhow::bail!(
                "lockdown Active proof handle changed: expected {expected_handle}, found {table_handle}"
            ),
            LockdownObservation::Absent => {
                anyhow::bail!("lockdown Active proof found no kernel table")
            }
            LockdownObservation::Conflict => {
                anyhow::bail!("lockdown Active proof found a foreign/drifted table")
            }
        }
    }
}

/// Process-local handle for a kernel/WAL barrier.  Drop is deliberately inert:
/// process failure must never authorize direct traffic.
pub struct LockdownBarrier {
    #[cfg(target_os = "linux")]
    coordinator: LockdownCoordinator<AnchoredLockdownStore, NativeNft>,
}

impl std::fmt::Debug for LockdownBarrier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LockdownBarrier")
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}

impl LockdownBarrier {
    /// Validate that the production native-nft binary and the exact inet/output
    /// transaction required for a future teardown barrier are available. The
    /// nft check mode performs no ruleset mutation and no packet I/O.
    pub fn preflight_native_nft(state_directory: &Path) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let _store = AnchoredLockdownStore::open(state_directory)?;
            let owner = OwnerIdentity::capture().context("capture nft preflight context")?;
            let journal = LockdownJournalV1::new_with_owner(None, &owner)?;
            let transaction = nft_preflight_transaction(&journal)?;
            run_nft(&["-c", "-j", "-f", "-"], Some(&transaction))
                .context("check native-nft lockdown transaction without applying it")?;
            let listing = run_nft(&["-j", "list", "tables"], None)
                .context("read native-nft table census during lockdown preflight")?;
            parse_nft_root(&listing).context("validate native-nft JSON capability")?;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = state_directory;
            anyhow::bail!("durable lockdown is implemented only on Linux")
        }
    }

    /// Open/adopt an existing barrier, or create one iff `stale_main_journal`
    /// proves a cross-session handoff is required.  A genuinely fresh first
    /// start returns `None` and is not blanket-blocked before validation/setup.
    pub fn engage_for_startup(
        state_directory: &Path,
        control_flow: Option<LockdownControlFlow>,
        stale_main_journal: bool,
    ) -> Result<Option<Self>> {
        #[cfg(target_os = "linux")]
        {
            let store = AnchoredLockdownStore::open(state_directory)?;
            let mut coordinator = LockdownCoordinator::open(store, NativeNft, control_flow)?;
            if !coordinator.has_journal() && !stale_main_journal {
                return Ok(None);
            }
            coordinator.arm()?;
            Ok(Some(Self { coordinator }))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (state_directory, control_flow, stale_main_journal);
            anyhow::bail!("durable lockdown is implemented only on Linux")
        }
    }

    /// Create or adopt a barrier before any kill-switch base hook is removed.
    pub fn engage_required(
        state_directory: &Path,
        control_flow: Option<LockdownControlFlow>,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let store = AnchoredLockdownStore::open(state_directory)?;
            let mut coordinator = LockdownCoordinator::open(store, NativeNft, control_flow)?;
            coordinator.arm()?;
            Ok(Self { coordinator })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (state_directory, control_flow);
            anyhow::bail!("durable lockdown is implemented only on Linux")
        }
    }

    pub fn arm_for_teardown(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.coordinator.arm()
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("durable lockdown is implemented only on Linux")
        }
    }

    /// Re-inspect the exact table shape/handle and owner namespace without
    /// changing either WAL or kernel state.
    pub fn verify_active(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.coordinator.prove_active()
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("durable lockdown is implemented only on Linux")
        }
    }

    /// Caller must first prove that the complete replacement kill switch,
    /// routes, TUN and DNS exchange are durably Active.
    pub fn release_after_full_tunnel_active(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.coordinator
                .release(LockdownReleaseReason::ReplacementActive)
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("durable lockdown is implemented only on Linux")
        }
    }

    /// Explicit operator-only release after proving the main host journal is
    /// completely absent.  Normal SIGINT/SIGTERM must not call this method.
    pub fn release_after_explicit_host_cleanup(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.coordinator
                .release(LockdownReleaseReason::ExplicitOperator)
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("durable lockdown is implemented only on Linux")
        }
    }

    pub fn is_active(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.coordinator.journal.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

// ---------------------------------------------------------------- anchored WAL

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[cfg(unix)]
struct DirectoryAnchor {
    directory: std::fs::File,
    identity: FileIdentity,
    expected_uid: u32,
}

#[cfg(unix)]
impl DirectoryAnchor {
    fn open(path: &Path) -> Result<Self> {
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::path::Component;

        let expected_uid = unsafe { libc::geteuid() };
        let start = if path.is_absolute() { b"/\0" } else { b".\0" };
        // SAFETY: static NUL-terminated path; successful descriptor is owned.
        let descriptor = unsafe {
            libc::open(
                start.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!("open lockdown state traversal root for {}", path.display())
            });
        }
        // SAFETY: descriptor is newly owned.
        let mut directory = unsafe { std::fs::File::from_raw_fd(descriptor) };
        for component in path.components() {
            let value = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(value) => value,
                Component::ParentDir | Component::Prefix(_) => {
                    anyhow::bail!("lockdown state path contains forbidden traversal component")
                }
            };
            let name = c_component(value)?;
            use std::os::fd::AsRawFd;
            // SAFETY: parent descriptor and component are live.
            let next = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if next < 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "open anchored lockdown state component in {}",
                        path.display()
                    )
                });
            }
            // SAFETY: next is newly owned.
            directory = unsafe { std::fs::File::from_raw_fd(next) };
        }
        let metadata = directory
            .metadata()
            .context("stat lockdown state directory")?;
        anyhow::ensure!(
            metadata.file_type().is_dir(),
            "lockdown state is not a directory"
        );
        anyhow::ensure!(
            metadata.uid() == expected_uid,
            "lockdown state directory UID {} differs from effective UID {}",
            metadata.uid(),
            expected_uid
        );
        anyhow::ensure!(
            metadata.permissions().mode() & 0o777 == STATE_DIRECTORY_MODE,
            "lockdown state directory mode is not 0700"
        );
        Ok(Self {
            identity: FileIdentity::from_metadata(&metadata),
            directory,
            expected_uid,
        })
    }

    fn verify(&self) -> Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = self
            .directory
            .metadata()
            .context("restat lockdown state directory")?;
        anyhow::ensure!(
            metadata.file_type().is_dir()
                && FileIdentity::from_metadata(&metadata) == self.identity,
            "anchored lockdown state directory identity changed"
        );
        anyhow::ensure!(
            metadata.uid() == self.expected_uid,
            "lockdown state owner changed"
        );
        anyhow::ensure!(
            metadata.permissions().mode() & 0o777 == STATE_DIRECTORY_MODE,
            "lockdown state mode changed"
        );
        Ok(())
    }

    fn fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.directory.as_raw_fd()
    }

    fn component_identity(&self, name: &std::ffi::CStr) -> Result<Option<FileIdentity>> {
        use std::mem::MaybeUninit;
        self.verify()?;
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: writable stat and live NUL-terminated name.
        let result = unsafe {
            libc::fstatat(
                self.fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(error).context("stat anchored lockdown component");
        }
        // SAFETY: fstatat succeeded.
        let stat = unsafe { stat.assume_init() };
        let mode = stat.st_mode as libc::mode_t;
        anyhow::ensure!(
            mode & libc::S_IFMT == libc::S_IFREG,
            "lockdown WAL is not regular"
        );
        Ok(Some(FileIdentity {
            device: {
                #[cfg(target_os = "linux")]
                {
                    stat.st_dev
                }
                #[cfg(not(target_os = "linux"))]
                {
                    stat.st_dev as u64
                }
            },
            inode: stat.st_ino,
        }))
    }

    fn ensure_name_identity(&self, name: &std::ffi::CStr, expected: FileIdentity) -> Result<()> {
        anyhow::ensure!(
            self.component_identity(name)? == Some(expected),
            "anchored lockdown component identity changed"
        );
        Ok(())
    }

    fn reopen_verified_regular(
        &self,
        name: &std::ffi::CStr,
        expected: FileIdentity,
    ) -> Result<std::fs::File> {
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        self.verify()?;
        // SAFETY: descriptor/name are live; a successful descriptor is newly
        // owned and O_NOFOLLOW rejects a symlink substituted at this name.
        let descriptor = unsafe {
            libc::openat(
                self.fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error())
                .context("reopen anchored lockdown component");
        }
        // SAFETY: descriptor is newly owned.
        let file = unsafe { std::fs::File::from_raw_fd(descriptor) };
        let metadata = file
            .metadata()
            .context("stat reopened anchored lockdown component")?;
        anyhow::ensure!(
            metadata.file_type().is_file(),
            "lockdown WAL is not regular"
        );
        anyhow::ensure!(
            metadata.uid() == self.expected_uid,
            "lockdown WAL owner changed"
        );
        anyhow::ensure!(
            metadata.permissions().mode() & 0o777 == JOURNAL_MODE,
            "lockdown WAL mode changed"
        );
        anyhow::ensure!(metadata.nlink() == 1, "lockdown WAL link count changed");
        anyhow::ensure!(
            FileIdentity::from_metadata(&metadata) == expected,
            "lockdown WAL inode changed"
        );
        self.ensure_name_identity(name, expected)?;
        Ok(file)
    }

    fn unlink_component(&self, name: &std::ffi::CStr) -> Result<()> {
        self.verify()?;
        // SAFETY: name is a live component below the anchored directory.
        let result = unsafe { libc::unlinkat(self.fd(), name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error()).context("unlink anchored lockdown component")
        }
    }

    fn sync(&self) -> Result<()> {
        self.verify()?;
        self.directory
            .sync_all()
            .context("fsync anchored lockdown directory")
    }
}

#[cfg(unix)]
fn c_component(value: &std::ffi::OsStr) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = value.as_bytes();
    anyhow::ensure!(
        !bytes.is_empty() && bytes != b"." && bytes != b".." && !bytes.contains(&b'/'),
        "invalid lockdown state component"
    );
    std::ffi::CString::new(bytes).context("lockdown state component contains NUL")
}

#[cfg(unix)]
struct AnchoredLockdownStore {
    anchor: DirectoryAnchor,
    journal_name: std::ffi::CString,
    journal_path: PathBuf,
}

#[cfg(unix)]
impl AnchoredLockdownStore {
    fn open(state_directory: &Path) -> Result<Self> {
        let anchor = DirectoryAnchor::open(state_directory)?;
        let journal_name = std::ffi::CString::new(LOCKDOWN_JOURNAL_FILE)
            .expect("static lockdown journal name has no NUL");
        let journal_path = state_directory.join(LOCKDOWN_JOURNAL_FILE);
        Ok(Self {
            anchor,
            journal_name,
            journal_path,
        })
    }

    fn read_current(&self) -> Result<Option<(LockdownJournalV1, FileIdentity)>> {
        use std::io::Read as _;
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        self.anchor.verify()?;
        // SAFETY: descriptor/name are live; successful descriptor is owned.
        let descriptor = unsafe {
            libc::openat(
                self.anchor.fd(),
                self.journal_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(error).with_context(|| format!("open {}", self.journal_path.display()));
        }
        // SAFETY: descriptor is newly owned.
        let mut file = unsafe { std::fs::File::from_raw_fd(descriptor) };
        let before = file.metadata().context("stat opened lockdown WAL")?;
        anyhow::ensure!(before.file_type().is_file(), "lockdown WAL is not regular");
        anyhow::ensure!(
            before.uid() == self.anchor.expected_uid,
            "lockdown WAL owner mismatch"
        );
        anyhow::ensure!(
            before.permissions().mode() & 0o777 == JOURNAL_MODE,
            "lockdown WAL mode is not 0600"
        );
        anyhow::ensure!(before.nlink() == 1, "lockdown WAL has multiple hard links");
        anyhow::ensure!(
            before.len() <= MAX_LOCKDOWN_JOURNAL_BYTES,
            "lockdown WAL exceeds bounded size"
        );
        let identity = FileIdentity::from_metadata(&before);
        anyhow::ensure!(
            self.anchor.component_identity(&self.journal_name)? == Some(identity),
            "lockdown WAL directory entry changed before read"
        );
        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&mut file)
            .take(MAX_LOCKDOWN_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("read bounded lockdown WAL")?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_LOCKDOWN_JOURNAL_BYTES,
            "lockdown WAL grew beyond bounded size"
        );
        let after = file.metadata().context("restat opened lockdown WAL")?;
        anyhow::ensure!(
            FileIdentity::from_metadata(&after) == identity
                && after.len() == before.len()
                && after.mtime() == before.mtime()
                && after.mtime_nsec() == before.mtime_nsec()
                && after.ctime() == before.ctime()
                && after.ctime_nsec() == before.ctime_nsec(),
            "lockdown WAL changed during bounded read"
        );
        anyhow::ensure!(
            self.anchor.component_identity(&self.journal_name)? == Some(identity),
            "lockdown WAL directory entry changed during read"
        );
        let journal: LockdownJournalV1 =
            serde_json::from_slice(&bytes).context("decode strict lockdown WAL")?;
        journal.validate()?;
        anyhow::ensure!(
            journal.uid == self.anchor.expected_uid,
            "lockdown WAL payload UID differs from file owner"
        );
        Ok(Some((journal, identity)))
    }

    fn stage(&self, bytes: &[u8]) -> Result<PendingLockdownFile> {
        use rand::RngCore as _;
        use std::io::Write as _;
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_LOCKDOWN_JOURNAL_BYTES,
            "serialized lockdown WAL exceeds bounded size"
        );
        for _ in 0..32 {
            let nonce = rand::rngs::OsRng.next_u64();
            let name_string = format!(".handoff-lockdown.{}.{}.tmp", std::process::id(), nonce);
            let name = std::ffi::CString::new(name_string.clone()).expect("ASCII temp name");
            // SAFETY: descriptor/name are live; successful descriptor is owned.
            let descriptor = unsafe {
                libc::openat(
                    self.anchor.fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    JOURNAL_MODE,
                )
            };
            if descriptor < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    continue;
                }
                return Err(error).context("create anchored lockdown WAL temp");
            }
            // SAFETY: descriptor is newly owned.
            let mut file = unsafe { std::fs::File::from_raw_fd(descriptor) };
            file.set_permissions(std::fs::Permissions::from_mode(JOURNAL_MODE))
                .context("chmod lockdown WAL temp")?;
            let metadata = file.metadata().context("stat lockdown WAL temp")?;
            anyhow::ensure!(
                metadata.file_type().is_file(),
                "lockdown WAL temp is not regular"
            );
            anyhow::ensure!(
                metadata.uid() == self.anchor.expected_uid,
                "lockdown WAL temp owner mismatch"
            );
            anyhow::ensure!(
                metadata.nlink() == 1,
                "lockdown WAL temp has multiple links"
            );
            let identity = FileIdentity::from_metadata(&metadata);
            anyhow::ensure!(
                self.anchor.component_identity(&name)? == Some(identity),
                "lockdown WAL temp name changed"
            );
            file.write_all(bytes).context("write lockdown WAL temp")?;
            file.sync_all().context("fsync lockdown WAL temp")?;
            return Ok(PendingLockdownFile {
                anchor_fd: self.anchor.fd(),
                name,
                identity,
                _file: file,
                published: false,
            });
        }
        anyhow::bail!("lockdown WAL temporary-name collision limit reached")
    }

    fn serialize(journal: &LockdownJournalV1) -> Result<Vec<u8>> {
        journal.validate()?;
        let mut bytes = serde_json::to_vec(journal).context("encode lockdown WAL")?;
        bytes.push(b'\n');
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_LOCKDOWN_JOURNAL_BYTES,
            "serialized lockdown WAL exceeds bounded size"
        );
        Ok(bytes)
    }
}

#[cfg(unix)]
struct PendingLockdownFile {
    anchor_fd: std::os::fd::RawFd,
    name: std::ffi::CString,
    identity: FileIdentity,
    // Keep the staged inode pinned across namespace publication/comparison.
    _file: std::fs::File,
    published: bool,
}

#[cfg(unix)]
impl PendingLockdownFile {
    fn verify_name(&self, anchor: &DirectoryAnchor) -> Result<()> {
        anchor.ensure_name_identity(&self.name, self.identity)
    }
}

#[cfg(unix)]
impl Drop for PendingLockdownFile {
    fn drop(&mut self) {
        if !self.published {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: descriptor/name and writable stat storage remain live.
            let status = unsafe {
                libc::fstatat(
                    self.anchor_fd,
                    self.name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if status == 0 {
                // SAFETY: fstatat initialized the complete stat value.
                let stat = unsafe { stat.assume_init() };
                let actual = FileIdentity {
                    device: {
                        #[cfg(target_os = "linux")]
                        {
                            stat.st_dev
                        }
                        #[cfg(not(target_os = "linux"))]
                        {
                            stat.st_dev as u64
                        }
                    },
                    inode: stat.st_ino,
                };
                let regular = (stat.st_mode as libc::mode_t) & libc::S_IFMT == libc::S_IFREG;
                if regular && actual == self.identity {
                    // SAFETY: the immediately re-observed name still selects
                    // the exact staged inode. Failure leaves a root-only inert
                    // temp instead of risking deletion of a replacement.
                    let _ = unsafe { libc::unlinkat(self.anchor_fd, self.name.as_ptr(), 0) };
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn publish_noreplace(
    directory: std::os::fd::RawFd,
    from: &std::ffi::CStr,
    to: &std::ffi::CStr,
) -> std::io::Result<()> {
    // SAFETY: names/descriptors are live and both entries share one directory.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory,
            from.as_ptr(),
            directory,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn exchange_entries(
    directory: std::os::fd::RawFd,
    first: &std::ffi::CStr,
    second: &std::ffi::CStr,
) -> std::io::Result<()> {
    // RENAME_EXCHANGE preserves the displaced inode under `first`, giving the
    // caller a post-syscall comparison point instead of destroying it.
    // SAFETY: both names are live components in the same anchored directory.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory,
            first.as_ptr(),
            directory,
            second.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn publish_noreplace(
    directory: std::os::fd::RawFd,
    from: &std::ffi::CStr,
    to: &std::ffi::CStr,
) -> std::io::Result<()> {
    // linkat is the no-clobber development-host fallback.
    // SAFETY: names/descriptors are live.
    let linked = unsafe { libc::linkat(directory, from.as_ptr(), directory, to.as_ptr(), 0) };
    if linked != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: source temp is still ours.
    if unsafe { libc::unlinkat(directory, from.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
impl LockdownStore for AnchoredLockdownStore {
    fn load_optional(&self) -> Result<Option<LockdownJournalV1>> {
        Ok(self.read_current()?.map(|(journal, _)| journal))
    }

    fn create(&mut self, journal: &LockdownJournalV1) -> Result<()> {
        anyhow::ensure!(
            self.read_current()?.is_none(),
            "lockdown WAL already exists"
        );
        let bytes = Self::serialize(journal)?;
        let mut pending = self.stage(&bytes)?;
        publish_noreplace(self.anchor.fd(), &pending.name, &self.journal_name)
            .context("atomically create lockdown WAL without replacement")?;
        pending.published = true;
        anyhow::ensure!(
            self.anchor.component_identity(&self.journal_name)? == Some(pending.identity),
            "published lockdown WAL identity differs from staged inode"
        );
        self.anchor.sync()
    }

    fn replace(&mut self, current: &LockdownJournalV1, next: &LockdownJournalV1) -> Result<()> {
        anyhow::ensure!(
            next.generation
                == current
                    .generation
                    .checked_add(1)
                    .context("lockdown generation overflow")?,
            "lockdown WAL replacement is not the next generation"
        );
        let (disk, identity) = self
            .read_current()?
            .context("lockdown WAL disappeared before replacement")?;
        anyhow::ensure!(&disk == current, "lockdown WAL changed before replacement");
        let bytes = Self::serialize(next)?;
        let mut pending = self.stage(&bytes)?;
        // Retain descriptors for both expected inodes through the namespace
        // operation. The 0700 same-UID directory and the process-wide host
        // lease define the cooperating-writer boundary; Linux still uses an
        // exchange-and-compare CAS pattern to avoid a pathname clobber race.
        let _current_guard = self
            .anchor
            .reopen_verified_regular(&self.journal_name, identity)?;
        pending.verify_name(&self.anchor)?;

        #[cfg(target_os = "linux")]
        {
            exchange_entries(self.anchor.fd(), &pending.name, &self.journal_name)
                .context("exchange anchored lockdown WAL generations")?;
            // From this point the pending name may hold a displaced target.
            // Never let Drop unlink it unless a successful rollback proves the
            // candidate has returned there.
            pending.published = true;
            let installed = self.anchor.component_identity(&self.journal_name)?;
            let displaced = self.anchor.component_identity(&pending.name)?;
            if installed != Some(pending.identity) || displaced != Some(identity) {
                if installed == Some(pending.identity) {
                    if let Some(displaced_identity) = displaced {
                        match exchange_entries(self.anchor.fd(), &pending.name, &self.journal_name)
                        {
                            Ok(()) => {
                                self.anchor
                                    .ensure_name_identity(&pending.name, pending.identity)?;
                                self.anchor
                                    .ensure_name_identity(&self.journal_name, displaced_identity)?;
                                self.anchor.sync()?;
                                // Rollback proved our staged inode is private again.
                                pending.published = false;
                            }
                            Err(error) => {
                                self.anchor.sync()?;
                                return Err(error)
                                    .context("roll back conflicted lockdown WAL exchange");
                            }
                        }
                    }
                }
                anyhow::bail!("lockdown WAL changed during atomic replacement");
            }

            self.anchor
                .ensure_name_identity(&self.journal_name, pending.identity)?;
            let _displaced_guard = self
                .anchor
                .reopen_verified_regular(&pending.name, identity)?;
            self.anchor.unlink_component(&pending.name)?;
            anyhow::ensure!(
                self.anchor.component_identity(&pending.name)?.is_none(),
                "displaced lockdown WAL remains after replacement"
            );
            self.anchor.sync()
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Development Unix fallback: immediate inode checks protect
            // against accidental races, but a hostile same-UID writer is
            // outside the production Linux threat model.
            // SAFETY: both names are live below the anchored descriptor.
            let renamed = unsafe {
                libc::renameat(
                    self.anchor.fd(),
                    pending.name.as_ptr(),
                    self.anchor.fd(),
                    self.journal_name.as_ptr(),
                )
            };
            if renamed != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("replace anchored lockdown WAL on development Unix");
            }
            pending.published = true;
            self.anchor
                .ensure_name_identity(&self.journal_name, pending.identity)?;
            self.anchor.sync()
        }
    }

    fn remove(&mut self, current: &LockdownJournalV1) -> Result<()> {
        let (disk, identity) = self
            .read_current()?
            .context("lockdown WAL disappeared before acknowledgement")?;
        anyhow::ensure!(&disk == current, "lockdown WAL changed before removal");
        let _current_guard = self
            .anchor
            .reopen_verified_regular(&self.journal_name, identity)?;

        #[cfg(target_os = "linux")]
        {
            // unlinkat cannot compare an inode. Atomically move the selected
            // name to a unique no-clobber quarantine, then unlink only if the
            // selected inode is exactly the one read above.
            use rand::RngCore as _;
            let (quarantine, _quarantine_path) = {
                let mut selected = None;
                for _ in 0..32 {
                    let nonce = rand::rngs::OsRng.next_u64();
                    let name = std::ffi::CString::new(format!(
                        ".handoff-lockdown-remove.{}.{}.tmp",
                        std::process::id(),
                        nonce
                    ))
                    .expect("ASCII lockdown quarantine name");
                    match publish_noreplace(self.anchor.fd(), &self.journal_name, &name) {
                        Ok(()) => {
                            selected = Some((name, self.journal_path.clone()));
                            break;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                        Err(error) => {
                            return Err(error).context("quarantine lockdown WAL before removal")
                        }
                    }
                }
                selected.context("lockdown WAL quarantine-name collision limit reached")?
            };
            let quarantined = self.anchor.component_identity(&quarantine)?;
            if quarantined != Some(identity) {
                // Restore without clobbering a concurrently installed name.
                // On EEXIST both entries remain recoverable and no foreign
                // inode is removed.
                match publish_noreplace(self.anchor.fd(), &quarantine, &self.journal_name) {
                    Ok(()) => self.anchor.sync()?,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        self.anchor.sync()?;
                    }
                    Err(error) => {
                        self.anchor.sync()?;
                        return Err(error).context("restore conflicted lockdown WAL");
                    }
                }
                anyhow::bail!("lockdown WAL changed during quarantined removal");
            }
            let _quarantine_guard = self.anchor.reopen_verified_regular(&quarantine, identity)?;
            self.anchor.unlink_component(&quarantine)?;
            anyhow::ensure!(
                self.anchor
                    .component_identity(&self.journal_name)?
                    .is_none()
                    && self.anchor.component_identity(&quarantine)?.is_none(),
                "lockdown WAL name remains after quarantined removal"
            );
            self.anchor.sync()
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Non-Linux Unix is a development fallback. Production Linux uses
            // the quarantine-and-compare path above.
            self.anchor.unlink_component(&self.journal_name)?;
            anyhow::ensure!(
                self.anchor
                    .component_identity(&self.journal_name)?
                    .is_none(),
                "lockdown WAL remains after removal"
            );
            self.anchor.sync()
        }
    }
}

// --------------------------------------------------------------- native nft I/O

#[cfg(target_os = "linux")]
struct NativeNft;

#[cfg(target_os = "linux")]
impl NativeNft {
    fn inspect_exact(&self, journal: &LockdownJournalV1) -> Result<LockdownObservation> {
        let table_name = journal.table_name();
        let tables = run_nft(&["-j", "list", "tables"], None)?;
        if !parse_table_presence(&tables, &table_name)? {
            return Ok(LockdownObservation::Absent);
        }
        let listing = run_nft(&["-j", "-a", "list", "table", "inet", &table_name], None)?;
        match parse_exact_table(&listing, journal) {
            Ok(handle) => Ok(LockdownObservation::Exact {
                table_handle: handle,
            }),
            Err(error) => {
                tracing::error!(%error, table = %table_name, "lockdown nft census found ownership conflict");
                Ok(LockdownObservation::Conflict)
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl LockdownKernel for NativeNft {
    fn inspect(&mut self, journal: &LockdownJournalV1) -> Result<LockdownObservation> {
        self.inspect_exact(journal)
    }

    fn install(&mut self, journal: &LockdownJournalV1) -> Result<u64> {
        anyhow::ensure!(
            self.inspect_exact(journal)? == LockdownObservation::Absent,
            "lockdown table name is not absent before atomic creation"
        );
        let transaction = nft_install_transaction(journal)?;
        run_nft(&["-j", "-f", "-"], Some(&transaction))?;
        match self.inspect_exact(journal)? {
            LockdownObservation::Exact { table_handle } => Ok(table_handle),
            LockdownObservation::Absent => {
                anyhow::bail!("nft reported success but lockdown is absent")
            }
            LockdownObservation::Conflict => {
                anyhow::bail!("nft-created lockdown differs from the exact expected shape")
            }
        }
    }

    fn remove(&mut self, journal: &LockdownJournalV1, expected_handle: u64) -> Result<()> {
        match self.inspect_exact(journal)? {
            LockdownObservation::Exact { table_handle } if table_handle == expected_handle => {}
            LockdownObservation::Exact { table_handle } => anyhow::bail!(
                "lockdown handle changed immediately before delete: expected {expected_handle}, found {table_handle}"
            ),
            LockdownObservation::Absent => anyhow::bail!("lockdown disappeared before exact delete"),
            LockdownObservation::Conflict => anyhow::bail!("lockdown changed before exact delete"),
        }
        let transaction = nft_delete_transaction(journal);
        run_nft(&["-j", "-f", "-"], Some(&transaction))?;
        anyhow::ensure!(
            self.inspect_exact(journal)? == LockdownObservation::Absent,
            "lockdown table remains after atomic delete"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn canonical_trusted_nft_executable(candidate: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    anyhow::ensure!(
        candidate.is_absolute(),
        "trusted nft candidate is not absolute: {}",
        candidate.display()
    );
    let metadata = std::fs::metadata(candidate)
        .with_context(|| format!("stat nft candidate {}", candidate.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o022 == 0,
        "nft candidate {} is not a root-owned, non-writable regular file",
        candidate.display()
    );
    // Validate the lexical path as well as the eventual canonical target. A
    // root-owned immediate parent is not sufficient when one of its parents is
    // attacker-writable: that ancestor can rename/replace the whole subtree.
    for ancestor in candidate.ancestors().skip(1) {
        let ancestor_metadata = std::fs::metadata(ancestor)
            .with_context(|| format!("stat nft candidate ancestor {}", ancestor.display()))?;
        anyhow::ensure!(
            ancestor_metadata.file_type().is_dir()
                && ancestor_metadata.uid() == 0
                && ancestor_metadata.permissions().mode() & 0o022 == 0,
            "nft candidate ancestor {} is not a root-owned, non-writable directory",
            ancestor.display()
        );
    }

    let canonical = std::fs::canonicalize(candidate)
        .with_context(|| format!("canonicalize nft candidate {}", candidate.display()))?;
    let canonical_metadata = std::fs::metadata(&canonical)
        .with_context(|| format!("stat canonical nft executable {}", canonical.display()))?;
    anyhow::ensure!(
        canonical_metadata.file_type().is_file()
            && canonical_metadata.uid() == 0
            && canonical_metadata.permissions().mode() & 0o022 == 0,
        "canonical nft executable {} is not a root-owned, non-writable regular file",
        canonical.display()
    );
    for ancestor in canonical.ancestors().skip(1) {
        let ancestor_metadata = std::fs::metadata(ancestor)
            .with_context(|| format!("stat canonical nft ancestor {}", ancestor.display()))?;
        anyhow::ensure!(
            ancestor_metadata.file_type().is_dir()
                && ancestor_metadata.uid() == 0
                && ancestor_metadata.permissions().mode() & 0o022 == 0,
            "canonical nft ancestor {} is not a root-owned, non-writable directory",
            ancestor.display()
        );
    }
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn nft_binary() -> Result<PathBuf> {
    let mut rejected = Vec::new();
    for candidate in [Path::new("/usr/bin/nft"), Path::new("/usr/sbin/nft")] {
        match canonical_trusted_nft_executable(candidate) {
            Ok(canonical) => return Ok(canonical),
            Err(error) => rejected.push(format!("{}: {error:#}", candidate.display())),
        }
    }
    anyhow::bail!(
        "no trusted native nft executable at /usr/bin/nft or /usr/sbin/nft: {}",
        rejected.join("; ")
    )
}

#[cfg(any(target_os = "linux", all(test, unix)))]
#[derive(Debug)]
struct BoundedOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_overflow: bool,
    stderr_overflow: bool,
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn drain_pipe<R>(
    mut reader: R,
    limit: usize,
    child_done: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<(Vec<u8>, bool)>
where
    R: std::io::Read + std::os::fd::AsRawFd,
{
    use std::sync::atomic::Ordering;
    let descriptor = reader.as_raw_fd();
    // A blocking read is not bounded by the direct child's lifetime: a forked
    // descendant can inherit the pipe, let the direct child exit, and keep its
    // copy open forever without producing a byte. Nonblocking drain lets the
    // reader stop at the first empty read after the direct child is reaped.
    // SAFETY: descriptor is the live pipe owned by `reader`.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: descriptor remains live and flags came from F_GETFL.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut captured = Vec::with_capacity(limit.min(8192));
    let mut overflow = false;
    let mut chunk = [0u8; 8192];
    loop {
        if overflow && child_done.load(Ordering::Acquire) {
            break;
        }
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                let remaining = limit.saturating_sub(captured.len());
                let retained = remaining.min(read);
                captured.extend_from_slice(&chunk[..retained]);
                overflow |= retained != read;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if child_done.load(Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
            Err(error) => return Err(error),
        }
        // While the direct child is live, continue draining/discarding excess
        // so it cannot block on a full pipe. Once it is reaped the checks above
        // bound both an idle inherited pipe and a descendant writing forever.
    }
    Ok((captured, overflow))
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn write_stdin_bounded<W>(
    mut writer: W,
    bytes: &[u8],
    child_done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    deadline: std::time::Instant,
) -> std::io::Result<()>
where
    W: std::io::Write + std::os::fd::AsRawFd,
{
    use std::sync::atomic::Ordering;
    let descriptor = writer.as_raw_fd();
    // A descendant can inherit stdin, let the direct child exit, and retain a
    // full unread pipe forever. Make input delivery obey the same direct-child
    // lifetime and monotonic deadline as output draining.
    // SAFETY: descriptor is the live pipe owned by `writer`.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: descriptor remains live and flags came from F_GETFL.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut offset = 0usize;
    while offset < bytes.len() {
        if child_done.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "direct child exited before bounded stdin was consumed",
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "bounded subprocess stdin deadline elapsed",
            ));
        }
        match writer.write(&bytes[offset..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "bounded subprocess stdin accepted zero bytes",
                ))
            }
            Ok(written) => offset += written,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
    writer.flush()
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn kill_process_group(pid: u32) -> Option<String> {
    let group = i32::try_from(pid).ok()?;
    // SAFETY: every runner child is created as the leader of a fresh process
    // group. The group may remain after its direct leader is reaped when a
    // descendant inherited stdin/stdout/stderr.
    if unsafe { libc::kill(-group, libc::SIGKILL) } == 0 {
        return None;
    }
    let error = std::io::Error::last_os_error();
    (error.raw_os_error() != Some(libc::ESRCH)).then(|| error.to_string())
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn terminate_group_and_reap(
    child: &mut std::process::Child,
) -> (Option<String>, std::io::Result<std::process::ExitStatus>) {
    let mut kill_error = kill_process_group(child.id());
    // Also target the direct child in case a compromised wrapper escaped the
    // original process group with setsid()/setpgid().
    if let Err(error) = child.kill() {
        if error.kind() != std::io::ErrorKind::InvalidInput
            && error.raw_os_error() != Some(libc::ESRCH)
        {
            kill_error = Some(match kill_error {
                Some(group_error) => {
                    format!("process-group kill: {group_error}; direct-child kill: {error}")
                }
                None => format!("direct-child kill: {error}"),
            });
        }
    }
    let wait_result = loop {
        match child.wait() {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => break result,
        }
    };
    (kill_error, wait_result)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn run_bounded_subprocess(
    program: &Path,
    args: &[&str],
    input: Option<&[u8]>,
    timeout: std::time::Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<BoundedOutput> {
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    let mut process = Command::new(program);
    process
        .args(args)
        // Never inherit privileged loader/plugin/parser controls from a sudo
        // caller. The executable was already resolved to a trusted absolute
        // canonical path, and child-side lookup gets a fixed system PATH.
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = process.spawn().with_context(|| {
        format!(
            "start bounded subprocess {} {}",
            program.display(),
            args.join(" ")
        )
    })?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = terminate_group_and_reap(&mut child);
            anyhow::bail!("bounded subprocess stdout pipe unavailable")
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            drop(stdout);
            let _ = terminate_group_and_reap(&mut child);
            anyhow::bail!("bounded subprocess stderr pipe unavailable")
        }
    };
    let stdin = if input.is_some() {
        match child.stdin.take() {
            Some(stdin) => Some(stdin),
            None => {
                drop(stdout);
                drop(stderr);
                let _ = terminate_group_and_reap(&mut child);
                anyhow::bail!("bounded subprocess stdin pipe unavailable")
            }
        }
    } else {
        None
    };
    let child_done = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let result = std::thread::scope(|scope| -> Result<_> {
        let writer = input.map(|bytes| {
            let stdin = stdin.expect("validated piped stdin exists with input");
            let done = Arc::clone(&child_done);
            let deadline = started + timeout;
            scope.spawn(move || write_stdin_bounded(stdin, bytes, done, deadline))
        });
        let stdout_reader = scope.spawn({
            let done = Arc::clone(&child_done);
            move || drain_pipe(stdout, stdout_limit, done)
        });
        let stderr_reader = scope.spawn({
            let done = Arc::clone(&child_done);
            move || drain_pipe(stderr, stderr_limit, done)
        });
        let mut terminal_error = None;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if let Some(error) = kill_process_group(child.id()) {
                        terminal_error = Some(anyhow::anyhow!(
                            "kill bounded subprocess descendants after direct-child exit: {error}"
                        ));
                    }
                    break Some(status);
                }
                Ok(None) if started.elapsed() >= timeout => {
                    let (kill_error, wait_result) = terminate_group_and_reap(&mut child);
                    let wait_detail = wait_result
                        .as_ref()
                        .map(|status| format!("reaped with {status}"))
                        .unwrap_or_else(|error| format!("wait failed: {error}"));
                    terminal_error = Some(anyhow::anyhow!(
                        "bounded subprocess {} {} timed out after {:?}; kill: {}; {wait_detail}",
                        program.display(),
                        args.join(" "),
                        timeout,
                        kill_error.as_deref().unwrap_or("ok")
                    ));
                    break wait_result.ok();
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(5)),
                Err(error) => {
                    let (kill_error, wait_result) = terminate_group_and_reap(&mut child);
                    terminal_error = Some(anyhow::anyhow!(
                        "poll bounded subprocess {} {}: {error}; kill: {}; wait: {}",
                        program.display(),
                        args.join(" "),
                        kill_error.as_deref().unwrap_or("ok"),
                        wait_result
                            .as_ref()
                            .map(|status| status.to_string())
                            .unwrap_or_else(|wait_error| wait_error.to_string())
                    ));
                    break wait_result.ok();
                }
            }
        };
        child_done.store(true, Ordering::Release);
        let stdout = stdout_reader
            .join()
            .map_err(|_| anyhow::anyhow!("bounded stdout reader panicked"))??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow::anyhow!("bounded stderr reader panicked"))??;
        if let Some(writer) = writer {
            match writer
                .join()
                .map_err(|_| anyhow::anyhow!("bounded stdin writer panicked"))?
            {
                Ok(()) => {}
                Err(error) => {
                    let descendant_kill = kill_process_group(child.id());
                    return Err(error).with_context(|| {
                        format!(
                            "write complete bounded subprocess stdin; descendant-group kill: {}",
                            descendant_kill.as_deref().unwrap_or("ok")
                        )
                    });
                }
            }
        }
        if let Some(error) = terminal_error {
            return Err(error);
        }
        let status = status.context("bounded subprocess had no exit status")?;
        Ok((status, stdout, stderr))
    })?;
    Ok(BoundedOutput {
        status: result.0,
        stdout: result.1 .0,
        stderr: result.2 .0,
        stdout_overflow: result.1 .1,
        stderr_overflow: result.2 .1,
    })
}

#[cfg(target_os = "linux")]
fn run_nft(args: &[&str], input: Option<&[u8]>) -> Result<String> {
    if let Some(bytes) = input {
        anyhow::ensure!(
            bytes.len() <= 64 * 1024,
            "nft transaction exceeds bounded input"
        );
    }
    let program = nft_binary()?;
    let output = run_bounded_subprocess(
        &program,
        args,
        input,
        NFT_TIMEOUT,
        MAX_NFT_JSON_BYTES,
        MAX_NFT_STDERR_BYTES,
    )?;
    anyhow::ensure!(
        !output.stdout_overflow,
        "nft stdout exceeded bounded capture"
    );
    anyhow::ensure!(
        !output.stderr_overflow,
        "nft stderr exceeded bounded capture"
    );
    anyhow::ensure!(
        output.status.success(),
        "nft {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8(output.stdout).context("nft returned non-UTF-8 JSON")
}

#[cfg(any(test, target_os = "linux"))]
fn parse_nft_root(listing: &str) -> Result<Vec<serde_json::Value>> {
    let mut root: serde_json::Value = serde_json::from_str(listing).context("parse nft JSON")?;
    let object = root
        .as_object_mut()
        .context("nft JSON root is not an object")?;
    anyhow::ensure!(object.len() == 1, "nft JSON root contains unknown fields");
    object
        .remove("nftables")
        .and_then(|value| value.as_array().cloned())
        .context("nft JSON root has no nftables array")
}

#[cfg(any(test, target_os = "linux"))]
fn single_entry(value: &serde_json::Value) -> Result<(&str, &serde_json::Value)> {
    let object = value.as_object().context("nft entry is not an object")?;
    anyhow::ensure!(
        object.len() == 1,
        "nft entry contains multiple object kinds"
    );
    let (kind, body) = object.iter().next().expect("one entry");
    anyhow::ensure!(body.is_object(), "nft {kind} body is not an object");
    Ok((kind.as_str(), body))
}

#[cfg(any(test, target_os = "linux"))]
fn parse_table_presence(listing: &str, table_name: &str) -> Result<bool> {
    let mut count = 0usize;
    for entry in parse_nft_root(listing)? {
        let (kind, body) = single_entry(&entry)?;
        if kind == "metainfo" {
            continue;
        }
        anyhow::ensure!(
            kind == "table",
            "nft list tables returned unexpected {kind} object"
        );
        let body = body.as_object().expect("checked object");
        let family = body.get("family").and_then(serde_json::Value::as_str);
        let name = body.get("name").and_then(serde_json::Value::as_str);
        if family == Some("inet") && name == Some(table_name) {
            count += 1;
        }
    }
    anyhow::ensure!(count <= 1, "duplicate lockdown table declarations");
    Ok(count == 1)
}

#[cfg(any(test, target_os = "linux"))]
fn exact_keys(object: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

#[cfg(any(test, target_os = "linux"))]
fn nft_loopback_expr() -> serde_json::Value {
    serde_json::json!([
        {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}},
        {"accept": null}
    ])
}

#[cfg(any(test, target_os = "linux"))]
fn nft_control_expr(flow: LockdownControlFlow) -> serde_json::Value {
    serde_json::json!([
        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": flow.source_ipv4.to_string()}},
        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": flow.destination_ipv4.to_string()}},
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "sport"}}, "right": flow.source_port}},
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": flow.destination_port}},
        {"accept": null}
    ])
}

#[cfg(any(test, target_os = "linux"))]
fn nft_terminal_expr() -> serde_json::Value {
    serde_json::json!([{"drop": null}])
}

#[cfg(any(test, target_os = "linux"))]
fn expected_rules(journal: &LockdownJournalV1) -> Vec<(String, serde_json::Value)> {
    let owner = journal.owner_comment();
    let mut rules = vec![(format!("{owner}:loopback"), nft_loopback_expr())];
    if let Some(flow) = journal.control_flow {
        rules.push((format!("{owner}:ssh-control"), nft_control_expr(flow)));
    }
    rules.push((format!("{owner}:terminal-drop"), nft_terminal_expr()));
    rules
}

#[cfg(any(test, target_os = "linux"))]
fn parse_exact_table(listing: &str, journal: &LockdownJournalV1) -> Result<u64> {
    let table_name = journal.table_name();
    let owner = journal.owner_comment();
    let mut table_handle = None;
    let mut chain_count = 0usize;
    let mut rules = Vec::new();
    for entry in parse_nft_root(listing)? {
        let (kind, body) = single_entry(&entry)?;
        if kind == "metainfo" {
            continue;
        }
        let body = body.as_object().expect("checked object");
        match kind {
            "table" => {
                anyhow::ensure!(
                    exact_keys(body, &["family", "name", "handle", "comment"]),
                    "lockdown table declaration has unknown/missing fields"
                );
                anyhow::ensure!(
                    body.get("family").and_then(serde_json::Value::as_str) == Some("inet")
                        && body.get("name").and_then(serde_json::Value::as_str)
                            == Some(table_name.as_str())
                        && body.get("comment").and_then(serde_json::Value::as_str)
                            == Some(owner.as_str()),
                    "lockdown table identity/comment mismatch"
                );
                let handle = body
                    .get("handle")
                    .and_then(serde_json::Value::as_u64)
                    .filter(|handle| *handle != 0)
                    .context("lockdown table lacks non-zero handle")?;
                anyhow::ensure!(
                    table_handle.replace(handle).is_none(),
                    "duplicate table object"
                );
            }
            "chain" => {
                anyhow::ensure!(
                    exact_keys(
                        body,
                        &[
                            "family", "table", "name", "handle", "type", "hook", "prio", "policy",
                            "comment"
                        ]
                    ),
                    "lockdown chain declaration has unknown/missing fields"
                );
                anyhow::ensure!(
                    body.get("family").and_then(serde_json::Value::as_str) == Some("inet")
                        && body.get("table").and_then(serde_json::Value::as_str)
                            == Some(table_name.as_str())
                        && body.get("name").and_then(serde_json::Value::as_str)
                            == Some(LOCKDOWN_CHAIN)
                        && body.get("type").and_then(serde_json::Value::as_str) == Some("filter")
                        && body.get("hook").and_then(serde_json::Value::as_str) == Some("output")
                        && body.get("prio").and_then(serde_json::Value::as_i64)
                            == Some(LOCKDOWN_PRIORITY)
                        && body.get("policy").and_then(serde_json::Value::as_str) == Some("drop")
                        && body.get("comment").and_then(serde_json::Value::as_str)
                            == Some(format!("{owner}:chain").as_str()),
                    "lockdown base chain shape mismatch"
                );
                anyhow::ensure!(
                    body.get("handle")
                        .and_then(serde_json::Value::as_u64)
                        .is_some(),
                    "lockdown chain lacks handle"
                );
                chain_count += 1;
            }
            "rule" => {
                anyhow::ensure!(
                    exact_keys(
                        body,
                        &["family", "table", "chain", "handle", "expr", "comment"]
                    ),
                    "lockdown rule has unknown/missing fields"
                );
                anyhow::ensure!(
                    body.get("family").and_then(serde_json::Value::as_str) == Some("inet")
                        && body.get("table").and_then(serde_json::Value::as_str)
                            == Some(table_name.as_str())
                        && body.get("chain").and_then(serde_json::Value::as_str)
                            == Some(LOCKDOWN_CHAIN)
                        && body
                            .get("handle")
                            .and_then(serde_json::Value::as_u64)
                            .is_some(),
                    "lockdown rule owner coordinates mismatch"
                );
                rules.push((
                    body.get("comment")
                        .and_then(serde_json::Value::as_str)
                        .context("lockdown rule lacks comment")?
                        .to_string(),
                    body.get("expr")
                        .context("lockdown rule lacks expression")?
                        .clone(),
                ));
            }
            other => anyhow::bail!("unexpected {other} object exists in lockdown table"),
        }
    }
    anyhow::ensure!(
        chain_count == 1,
        "lockdown must contain exactly one base chain"
    );
    anyhow::ensure!(
        rules == expected_rules(journal),
        "lockdown rules/order differ from WAL"
    );
    table_handle.context("lockdown listing lacks table declaration")
}

#[cfg(target_os = "linux")]
fn nft_install_transaction(journal: &LockdownJournalV1) -> Result<Vec<u8>> {
    let table = journal.table_name();
    let owner = journal.owner_comment();
    let mut commands = vec![
        serde_json::json!({"add": {"table": {
            "family": "inet", "name": table, "comment": owner
        }}}),
        serde_json::json!({"add": {"chain": {
            "family": "inet", "table": journal.table_name(), "name": LOCKDOWN_CHAIN,
            "type": "filter", "hook": "output", "prio": LOCKDOWN_PRIORITY,
            "policy": "drop", "comment": format!("{}:chain", journal.owner_comment())
        }}}),
    ];
    for (comment, expr) in expected_rules(journal) {
        commands.push(serde_json::json!({"add": {"rule": {
            "family": "inet", "table": journal.table_name(), "chain": LOCKDOWN_CHAIN,
            "expr": expr, "comment": comment
        }}}));
    }
    serde_json::to_vec(&serde_json::json!({"nftables": commands}))
        .context("encode nft lockdown install transaction")
}

#[cfg(target_os = "linux")]
fn nft_preflight_transaction(journal: &LockdownJournalV1) -> Result<Vec<u8>> {
    let install = nft_install_transaction(journal)?;
    let mut root: serde_json::Value =
        serde_json::from_slice(&install).context("decode generated nft preflight transaction")?;
    let commands = root
        .get_mut("nftables")
        .and_then(serde_json::Value::as_array_mut)
        .context("generated nft preflight transaction lacks command array")?;
    commands.push(serde_json::json!({"delete": {"table": {
        "family": "inet", "name": journal.table_name()
    }}}));
    serde_json::to_vec(&root).context("encode native-nft create/delete check transaction")
}

#[cfg(target_os = "linux")]
fn nft_delete_transaction(journal: &LockdownJournalV1) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "nftables": [{"delete": {"table": {
            "family": "inet", "name": journal.table_name()
        }}}]
    }))
    .expect("fixed nft delete transaction serializes")
}

// ----------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct MemoryStore {
        journal: Option<LockdownJournalV1>,
        writes: usize,
        removals: usize,
        fail_after_write: Option<usize>,
    }

    impl LockdownStore for MemoryStore {
        fn load_optional(&self) -> Result<Option<LockdownJournalV1>> {
            Ok(self.journal.clone())
        }

        fn create(&mut self, journal: &LockdownJournalV1) -> Result<()> {
            anyhow::ensure!(self.journal.is_none(), "exists");
            self.journal = Some(journal.clone());
            self.writes += 1;
            if self.fail_after_write == Some(self.writes) {
                anyhow::bail!("injected post-create acknowledgement failure")
            }
            Ok(())
        }

        fn replace(&mut self, current: &LockdownJournalV1, next: &LockdownJournalV1) -> Result<()> {
            anyhow::ensure!(self.journal.as_ref() == Some(current), "stale replace");
            self.journal = Some(next.clone());
            self.writes += 1;
            if self.fail_after_write == Some(self.writes) {
                anyhow::bail!("injected post-replace acknowledgement failure")
            }
            Ok(())
        }

        fn remove(&mut self, current: &LockdownJournalV1) -> Result<()> {
            anyhow::ensure!(self.journal.as_ref() == Some(current), "stale remove");
            self.journal = None;
            self.removals += 1;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeKernel {
        observation: Option<LockdownObservation>,
        handle: u64,
        installs: usize,
        removes: usize,
        scripted: VecDeque<LockdownObservation>,
        fail_install_after_effect: bool,
        fail_remove_after_effect: bool,
    }

    impl FakeKernel {
        fn absent() -> Self {
            Self {
                observation: Some(LockdownObservation::Absent),
                handle: 41,
                ..Self::default()
            }
        }
    }

    impl LockdownKernel for FakeKernel {
        fn inspect(&mut self, _journal: &LockdownJournalV1) -> Result<LockdownObservation> {
            Ok(self
                .scripted
                .pop_front()
                .or(self.observation)
                .unwrap_or(LockdownObservation::Absent))
        }

        fn install(&mut self, _journal: &LockdownJournalV1) -> Result<u64> {
            anyhow::ensure!(
                self.observation == Some(LockdownObservation::Absent),
                "not absent"
            );
            self.installs += 1;
            self.observation = Some(LockdownObservation::Exact {
                table_handle: self.handle,
            });
            if self.fail_install_after_effect {
                anyhow::bail!("injected install success before caller acknowledgement")
            }
            Ok(self.handle)
        }

        fn remove(&mut self, _journal: &LockdownJournalV1, expected_handle: u64) -> Result<()> {
            anyhow::ensure!(
                self.observation
                    == Some(LockdownObservation::Exact {
                        table_handle: expected_handle
                    }),
                "wrong exact state"
            );
            self.removes += 1;
            self.observation = Some(LockdownObservation::Absent);
            if self.fail_remove_after_effect {
                anyhow::bail!("injected delete success before caller acknowledgement")
            }
            Ok(())
        }
    }

    fn test_uid() -> u32 {
        #[cfg(unix)]
        {
            // SAFETY: geteuid has no preconditions.
            unsafe { libc::geteuid() }
        }
        #[cfg(not(unix))]
        {
            0
        }
    }

    fn test_owner() -> OwnerIdentity {
        OwnerIdentity {
            session_id: SessionId::from_bytes([9; 16]),
            boot_id: Some(BootId::from_bytes([8; 16])),
            uid: test_uid(),
            pid: 1,
            pid_start_ticks: Some(1),
            network_namespace: Some(NamespaceIdentity {
                device: 11,
                inode: 12,
            }),
            mount_namespace: Some(NamespaceIdentity {
                device: 13,
                inode: 14,
            }),
        }
    }

    fn planned() -> LockdownJournalV1 {
        let owner = test_owner();
        LockdownJournalV1 {
            schema_version: LOCKDOWN_SCHEMA_VERSION,
            generation: 1,
            identity: SessionId::from_bytes([7; 16]),
            boot_id: owner.boot_id.unwrap(),
            uid: owner.uid,
            network_namespace: owner.network_namespace.unwrap(),
            mount_namespace: owner.mount_namespace.unwrap(),
            control_flow: None,
            phase: LockdownPhase::Planned,
            table_handle: None,
            release_reason: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn pending_lockdown_drop_never_unlinks_a_replacement_inode() {
        use rand::RngCore as _;
        use std::os::unix::fs::PermissionsExt as _;

        let directory = std::env::temp_dir().join(format!(
            "shadowpipe-lockdown-pending-drop-{}-{}",
            std::process::id(),
            rand::rngs::OsRng.next_u64()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = std::fs::canonicalize(&directory).unwrap();

        let store = AnchoredLockdownStore::open(&directory).unwrap();
        let bytes = AnchoredLockdownStore::serialize(&planned()).unwrap();
        let pending = store.stage(&bytes).unwrap();
        let staged_name = pending.name.to_str().unwrap().to_owned();
        let staged_path = directory.join(&staged_name);
        let displaced_path = directory.join("displaced-original");
        std::fs::rename(&staged_path, &displaced_path).unwrap();
        std::fs::write(&staged_path, b"foreign replacement\n").unwrap();
        std::fs::set_permissions(&staged_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        drop(pending);

        assert_eq!(
            std::fs::read(&staged_path).unwrap(),
            b"foreign replacement\n",
            "drop deleted a replacement inode selected by the staged name"
        );
        assert!(displaced_path.is_file());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn linux_process_is_running(pid: libc::pid_t) -> bool {
        let path = format!("/proc/{pid}/stat");
        match std::fs::read_to_string(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => true,
            Ok(stat) => stat
                .rsplit_once(") ")
                .and_then(|(_, tail)| tail.chars().next())
                .is_some_and(|state| state != 'Z' && state != 'X'),
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_linux_process_not_running(pid: libc::pid_t) {
        for _ in 0..100 {
            if !linux_process_is_running(pid) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // SAFETY: the pid came from the isolated adversarial fixture. This is
        // best-effort cleanup before reporting the residue failure.
        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
        panic!("bounded runner left live descendant pid {pid}");
    }

    #[test]
    fn planned_before_apply_is_replayed_and_acked() {
        let journal = planned();
        let store = MemoryStore {
            journal: Some(journal),
            ..MemoryStore::default()
        };
        let mut coordinator = LockdownCoordinator::open(store, FakeKernel::absent(), None).unwrap();
        coordinator.arm_with_owner(&test_owner()).unwrap();
        let active = coordinator.journal.as_ref().unwrap();
        assert_eq!(active.phase, LockdownPhase::Active);
        assert_eq!(active.table_handle, Some(41));
        assert_eq!(coordinator.kernel.installs, 1);
    }

    #[test]
    fn process_exit_state_is_adopted_by_next_coordinator_without_reinstall() {
        let mut first =
            LockdownCoordinator::open(MemoryStore::default(), FakeKernel::absent(), None).unwrap();
        first.arm_with_owner(&test_owner()).unwrap();
        assert_eq!(first.kernel.installs, 1);
        let LockdownCoordinator { store, kernel, .. } = first;

        let mut next = LockdownCoordinator::open(store, kernel, None).unwrap();
        next.arm_with_owner(&test_owner()).unwrap();
        assert_eq!(next.kernel.installs, 1);
        assert_eq!(next.journal.as_ref().unwrap().phase, LockdownPhase::Active);
    }

    #[test]
    fn different_boot_rearms_without_preserving_old_ssh_tuple() {
        let mut journal = planned();
        journal.control_flow = Some(
            LockdownControlFlow::new(
                "192.0.2.10".parse().unwrap(),
                22,
                "198.51.100.8".parse().unwrap(),
                53000,
            )
            .unwrap(),
        );
        journal.phase = LockdownPhase::Active;
        journal.table_handle = Some(77);
        let old_identity = journal.identity;
        let store = MemoryStore {
            journal: Some(journal),
            ..MemoryStore::default()
        };
        let mut next_boot = test_owner();
        next_boot.boot_id = Some(BootId::from_bytes([0x44; 16]));
        next_boot.network_namespace = Some(NamespaceIdentity {
            device: 21,
            inode: 22,
        });
        next_boot.mount_namespace = Some(NamespaceIdentity {
            device: 23,
            inode: 24,
        });
        let mut coordinator = LockdownCoordinator::open(store, FakeKernel::absent(), None).unwrap();
        coordinator.arm_with_owner(&next_boot).unwrap();
        let active = coordinator.journal.as_ref().unwrap();
        assert_eq!(active.phase, LockdownPhase::Active);
        assert_eq!(active.control_flow, None);
        assert_ne!(active.identity, old_identity);
        assert_eq!(active.boot_id, next_boot.boot_id.unwrap());
        assert_eq!(coordinator.kernel.installs, 1);
    }

    #[test]
    fn same_boot_mount_namespace_mismatch_is_zero_mutation() {
        let journal = planned();
        let store = MemoryStore {
            journal: Some(journal),
            ..MemoryStore::default()
        };
        let mut other_mount = test_owner();
        other_mount.mount_namespace = Some(NamespaceIdentity {
            device: 999,
            inode: 1000,
        });
        let mut coordinator = LockdownCoordinator::open(store, FakeKernel::absent(), None).unwrap();
        assert!(coordinator.arm_with_owner(&other_mount).is_err());
        assert_eq!(coordinator.kernel.installs, 0);
        assert_eq!(coordinator.kernel.removes, 0);
        assert_eq!(coordinator.store.writes, 0);
    }

    #[test]
    fn applied_before_active_ack_is_adopted_without_second_install() {
        let journal = planned();
        let store = MemoryStore {
            journal: Some(journal),
            ..MemoryStore::default()
        };
        let kernel = FakeKernel {
            observation: Some(LockdownObservation::Exact { table_handle: 91 }),
            handle: 91,
            ..FakeKernel::default()
        };
        let mut coordinator = LockdownCoordinator::open(store, kernel, None).unwrap();
        coordinator.arm_with_owner(&test_owner()).unwrap();
        assert_eq!(coordinator.kernel.installs, 0);
        assert_eq!(coordinator.journal.as_ref().unwrap().table_handle, Some(91));
    }

    #[test]
    fn remove_planned_with_table_present_is_adopted_not_deleted() {
        let mut journal = planned();
        journal.phase = LockdownPhase::RemovePlanned;
        journal.table_handle = Some(55);
        journal.release_reason = Some(LockdownReleaseReason::ReplacementActive);
        let store = MemoryStore {
            journal: Some(journal),
            ..MemoryStore::default()
        };
        let kernel = FakeKernel {
            observation: Some(LockdownObservation::Exact { table_handle: 55 }),
            handle: 55,
            ..FakeKernel::default()
        };
        let mut coordinator = LockdownCoordinator::open(store, kernel, None).unwrap();
        coordinator.arm_with_owner(&test_owner()).unwrap();
        assert_eq!(coordinator.kernel.removes, 0);
        assert_eq!(
            coordinator.journal.as_ref().unwrap().phase,
            LockdownPhase::Active
        );
    }

    #[test]
    fn table_deleted_before_wal_ack_is_rearmed() {
        let mut journal = planned();
        journal.phase = LockdownPhase::RemovePlanned;
        journal.table_handle = Some(55);
        journal.release_reason = Some(LockdownReleaseReason::ReplacementActive);
        let store = MemoryStore {
            journal: Some(journal),
            ..MemoryStore::default()
        };
        let mut coordinator = LockdownCoordinator::open(store, FakeKernel::absent(), None).unwrap();
        coordinator.arm_with_owner(&test_owner()).unwrap();
        assert_eq!(coordinator.kernel.installs, 1);
        assert_eq!(
            coordinator.journal.as_ref().unwrap().phase,
            LockdownPhase::Active
        );
    }

    #[test]
    fn foreign_shape_is_zero_mutation_conflict() {
        let journal = planned();
        let store = MemoryStore {
            journal: Some(journal),
            ..MemoryStore::default()
        };
        let kernel = FakeKernel {
            observation: Some(LockdownObservation::Conflict),
            ..FakeKernel::default()
        };
        let mut coordinator = LockdownCoordinator::open(store, kernel, None).unwrap();
        assert!(coordinator.arm_with_owner(&test_owner()).is_err());
        assert_eq!(coordinator.kernel.installs, 0);
        assert_eq!(coordinator.kernel.removes, 0);
        assert_eq!(coordinator.store.writes, 0);
    }

    #[test]
    fn release_wals_before_delete_and_delete_before_wal_removal() {
        let mut journal = planned();
        journal.phase = LockdownPhase::Active;
        journal.table_handle = Some(77);
        journal.release_reason = None;
        let store = MemoryStore {
            journal: Some(journal),
            ..MemoryStore::default()
        };
        let kernel = FakeKernel {
            observation: Some(LockdownObservation::Exact { table_handle: 77 }),
            handle: 77,
            ..FakeKernel::default()
        };
        let mut coordinator = LockdownCoordinator::open(store, kernel, None).unwrap();
        coordinator
            .release(LockdownReleaseReason::ReplacementActive)
            .unwrap();
        assert!(coordinator.journal.is_none());
        assert_eq!(coordinator.kernel.removes, 1);
        assert_eq!(coordinator.store.writes, 1);
        assert_eq!(coordinator.store.removals, 1);
    }

    #[test]
    fn strict_nft_census_accepts_exact_and_rejects_extra_rule() {
        let mut journal = planned();
        journal.control_flow = Some(
            LockdownControlFlow::new(
                "192.0.2.10".parse().unwrap(),
                22,
                "198.51.100.8".parse().unwrap(),
                53000,
            )
            .unwrap(),
        );
        let table = journal.table_name();
        let owner = journal.owner_comment();
        let mut entries = vec![
            serde_json::json!({"metainfo": {"json_schema_version": 1}}),
            serde_json::json!({"table": {"family": "inet", "name": table, "handle": 8, "comment": owner}}),
            serde_json::json!({"chain": {
                "family": "inet", "table": journal.table_name(), "name": LOCKDOWN_CHAIN,
                "handle": 9, "type": "filter", "hook": "output", "prio": LOCKDOWN_PRIORITY,
                "policy": "drop", "comment": format!("{}:chain", journal.owner_comment())
            }}),
        ];
        for (index, (comment, expr)) in expected_rules(&journal).into_iter().enumerate() {
            entries.push(serde_json::json!({"rule": {
                "family": "inet", "table": journal.table_name(), "chain": LOCKDOWN_CHAIN,
                "handle": 10 + index, "expr": expr, "comment": comment
            }}));
        }
        let exact = serde_json::json!({"nftables": entries});
        assert_eq!(parse_exact_table(&exact.to_string(), &journal).unwrap(), 8);
        let entries = exact
            .get("nftables")
            .and_then(serde_json::Value::as_array)
            .unwrap();
        let mut drifted = entries.clone();
        drifted.push(serde_json::json!({"rule": {
            "family": "inet", "table": journal.table_name(), "chain": LOCKDOWN_CHAIN,
            "handle": 99, "expr": [{"accept": null}], "comment": "foreign"
        }}));
        assert!(parse_exact_table(
            &serde_json::json!({"nftables": drifted}).to_string(),
            &journal
        )
        .is_err());
    }

    #[test]
    fn lockdown_rules_allow_only_loopback_and_exact_ipv4_ssh_before_terminal_drop() {
        let mut journal = planned();
        let flow = LockdownControlFlow::new(
            "192.0.2.10".parse().unwrap(),
            22,
            "198.51.100.8".parse().unwrap(),
            53000,
        )
        .unwrap();
        journal.control_flow = Some(flow);
        let rules = expected_rules(&journal);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].1, nft_loopback_expr());
        assert_eq!(rules[1].1, nft_control_expr(flow));
        assert_eq!(rules[2].1, nft_terminal_expr());

        let encoded = serde_json::to_string(&rules).unwrap();
        assert!(
            !encoded.contains("ct"),
            "must not admit broad conntrack state"
        );
        assert!(!encoded.contains("established"));
        assert!(encoded.contains("oifname"));
        assert!(encoded.contains("terminal-drop"));
        // The exact control rule is IPv4-only. IPv6 has only the family-neutral
        // loopback allow before the inet-chain terminal drop/policy drop.
        assert!(!encoded.contains("ip6"));
    }

    #[cfg(unix)]
    #[test]
    fn anchored_store_is_bounded_and_requires_0700_0600() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "shadowpipe-lockdown-test-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = AnchoredLockdownStore::open(&root).unwrap();
        let journal = planned();
        store.create(&journal).unwrap();
        assert_eq!(store.load_optional().unwrap(), Some(journal.clone()));
        let next = journal.next(LockdownPhase::Active, Some(4), None).unwrap();
        store.replace(&journal, &next).unwrap();
        store.remove(&next).unwrap();
        assert!(store.load_optional().unwrap().is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn bounded_subprocess_times_out_and_reaps() {
        let error = run_bounded_subprocess(
            Path::new("/bin/sh"),
            &["-c", "sleep 5"],
            None,
            std::time::Duration::from_millis(50),
            128,
            128,
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_subprocess_kills_successful_childs_pipe_holder() {
        let started = std::time::Instant::now();
        let output = run_bounded_subprocess(
            Path::new("/bin/sh"),
            &["-c", "sleep 5 & printf '%s\\n' \"$!\""],
            None,
            std::time::Duration::from_secs(2),
            128,
            128,
        )
        .unwrap();
        assert!(output.status.success());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "runner waited for descendant pipe EOF: {:?}",
            started.elapsed()
        );
        if let Ok(pid) = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<libc::pid_t>()
        {
            #[cfg(target_os = "linux")]
            assert_linux_process_not_running(pid);
            #[cfg(not(target_os = "linux"))]
            {
                // SAFETY: pid is the fixture's `$!`; cleanup is best-effort on
                // non-Linux Unix where /proc state inspection is unavailable.
                let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn bounded_subprocess_rejects_incomplete_stdin_and_kills_holder() {
        let input = vec![b'x'; 1024 * 1024];
        let pid_path = std::env::temp_dir().join(format!(
            "shadowpipe-lockdown-stdin-holder-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let script = format!(
            "sleep 5 <&0 >/dev/null 2>&1 & printf '%s\\n' \"$!\" > '{}'",
            pid_path.display()
        );
        let started = std::time::Instant::now();
        let error = run_bounded_subprocess(
            Path::new("/bin/sh"),
            &["-c", &script],
            Some(&input),
            std::time::Duration::from_secs(2),
            128,
            128,
        )
        .expect_err("incomplete stdin delivery must be fatal");
        assert!(
            error.to_string().contains("stdin"),
            "unexpected error: {error:#}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "runner waited for descendant-held stdin: {:?}",
            started.elapsed()
        );
        let pid: libc::pid_t = std::fs::read_to_string(&pid_path)
            .expect("stdin-holder fixture did not publish its pid")
            .trim()
            .parse()
            .expect("stdin-holder fixture published an invalid pid");
        let _ = std::fs::remove_file(pid_path);
        #[cfg(target_os = "linux")]
        assert_linux_process_not_running(pid);
        #[cfg(not(target_os = "linux"))]
        {
            // SAFETY: pid is the fixture's `$!`; cleanup is best-effort.
            let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }

    #[cfg(unix)]
    #[test]
    fn bounded_subprocess_sterilizes_privileged_helper_environment() {
        let output = run_bounded_subprocess(
            Path::new("/bin/sh"),
            &[
                "-c",
                "test \"$PATH\" = /usr/sbin:/usr/bin:/sbin:/bin && \
                 test \"$LC_ALL\" = C && \
                 test -z \"${LD_PRELOAD+x}\" && \
                 test -z \"${XTABLES_LIBDIR+x}\" && \
                 test -z \"${BASH_ENV+x}\"",
            ],
            None,
            std::time::Duration::from_secs(2),
            128,
            128,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "sterile helper rejected its environment: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trusted_nft_resolver_rejects_writable_lexical_and_canonical_ancestors() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        // The production resolver requires root-owned paths. Keep this test
        // runnable for ordinary developers by exercising the privileged
        // fixture only in the disposable root test environment.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let real_nft = nft_binary().expect("privileged nft resolver fixture requires nft");
        let nonce = rand::random::<u64>();
        let unsafe_root = std::env::temp_dir().join(format!(
            "shadowpipe-lockdown-unsafe-helper-{}-{nonce}",
            std::process::id()
        ));
        let locked_child = unsafe_root.join("locked");
        let secure_root = Path::new("/root").join(format!(
            ".shadowpipe-lockdown-secure-helper-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&locked_child).unwrap();
        std::fs::create_dir_all(&secure_root).unwrap();
        std::fs::set_permissions(&unsafe_root, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::set_permissions(&locked_child, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&secure_root, std::fs::Permissions::from_mode(0o700)).unwrap();

        let lexical_candidate = locked_child.join("nft");
        symlink(&real_nft, &lexical_candidate).unwrap();
        let lexical_result = canonical_trusted_nft_executable(&lexical_candidate);

        let unsafe_target = unsafe_root.join("nft-copy");
        std::fs::copy(&real_nft, &unsafe_target).unwrap();
        std::fs::set_permissions(&unsafe_target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let canonical_candidate = secure_root.join("nft");
        symlink(&unsafe_target, &canonical_candidate).unwrap();
        let canonical_result = canonical_trusted_nft_executable(&canonical_candidate);

        std::fs::remove_dir_all(&secure_root).unwrap();
        std::fs::remove_dir_all(&unsafe_root).unwrap();
        assert!(
            lexical_result.is_err(),
            "resolver accepted a helper below a writable lexical ancestor"
        );
        assert!(
            canonical_result.is_err(),
            "resolver accepted a helper below a writable canonical ancestor"
        );
    }
}
