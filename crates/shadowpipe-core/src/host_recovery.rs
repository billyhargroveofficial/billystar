//! All-resource crash recovery driver.
//!
//! Inspection is a distinct phase: the adapter must return one observation for
//! every live journal record before this driver exposes the first removal call.
//! A single conflict suppresses all host mutation and is durably recorded.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::dns_exchange::{
    inspect_exchange_typed, recover_exchange_typed, DnsExchangeFailure, DnsExchangeFailureKind,
};
use crate::host_state::{
    decide_recovery, DnsResource, DurableHostJournal, HostStateJournalV2, JournalPhase,
    OperationState, OwnedResource, OwnerDisposition, RecoveryDecision, RecoveryRefusal,
    ResourceObservation, ResourceObservationKind, SessionId,
};
use crate::host_state::{NamespaceIdentity, RouteResource, TunResource};
use crate::routes::{
    LinuxOwnedRouteClassification, LinuxRouteConvergeError, LinuxRoutePrepareError,
    PreparedLinuxRouteRecovery,
};
use crate::tun_state::inspect_tun;

pub trait HostRecoveryAdapter {
    /// Perform the complete read-only inspection. Implementations may inspect
    /// resource groups jointly (notably firewall chains and endpoint rules).
    fn inspect_all(
        &mut self,
        journal: &crate::host_state::HostStateJournalV2,
    ) -> Result<Vec<ResourceObservation>>;

    /// Converge one authorized resource to Absent. Implementations must recheck
    /// immediately and use the resource family's safe primitive. Routes,
    /// firewall objects, and DNS exchanges have exact owned teardown; a
    /// non-persistent TUN may only have stable absence re-proved because Linux
    /// has no atomic compare-and-delete for name+ifindex+alias. Conflict aborts.
    /// This applies even when preflight saw Absent, so a resource cannot
    /// reappear between inspection and durable acknowledgement.
    fn converge_absent(
        &mut self,
        resource: &OwnedResource,
    ) -> std::result::Result<(), RecoveryConvergenceError>;
}

/// One stateful, fully preflighted resource family (routes, DNS, TUN, or
/// firewall). `observe` is a pure membership/classification lookup after the
/// family's constructor has completed all read-only host inspection.
pub trait PreparedResourceGroup {
    fn observe(&self, resource: &OwnedResource) -> Option<ResourceObservationKind>;

    fn converge_absent(
        &mut self,
        resource: &OwnedResource,
    ) -> Option<std::result::Result<(), RecoveryConvergenceError>>;
}

/// Composition layer that proves every live journal record belongs to exactly
/// one prepared resource group before the generic driver receives any
/// observations. It snapshots the journal generation and vocabulary, then
/// refuses a different journal at `inspect_all`.
pub struct PreparedHostRecoveryAdapter {
    session_id: SessionId,
    source_generation: u64,
    live_resources: Vec<(u32, OwnedResource)>,
    observations: Vec<ResourceObservation>,
    groups: Vec<Box<dyn PreparedResourceGroup>>,
    inspection_complete: bool,
}

impl PreparedHostRecoveryAdapter {
    pub fn new(
        journal: &HostStateJournalV2,
        groups: Vec<Box<dyn PreparedResourceGroup>>,
    ) -> Result<Self> {
        let live_resources: Vec<_> = journal
            .operations
            .iter()
            .filter(|operation| operation.state != OperationState::Removed)
            .map(|operation| (operation.id, operation.resource.clone()))
            .collect();
        let mut observations = Vec::with_capacity(live_resources.len());
        for (operation_id, resource) in &live_resources {
            let matches: Vec<_> = groups
                .iter()
                .filter_map(|group| group.observe(resource))
                .collect();
            anyhow::ensure!(
                matches.len() == 1,
                "journal operation {operation_id} is recognized by {} prepared resource groups",
                matches.len()
            );
            observations.push(ResourceObservation {
                operation_id: *operation_id,
                kind: matches[0],
            });
        }
        Ok(Self {
            session_id: journal.owner.session_id,
            source_generation: journal.generation,
            live_resources,
            observations,
            groups,
            inspection_complete: false,
        })
    }
}

impl HostRecoveryAdapter for PreparedHostRecoveryAdapter {
    fn inspect_all(&mut self, journal: &HostStateJournalV2) -> Result<Vec<ResourceObservation>> {
        let current_live: Vec<_> = journal
            .operations
            .iter()
            .filter(|operation| operation.state != OperationState::Removed)
            .map(|operation| (operation.id, operation.resource.clone()))
            .collect();
        anyhow::ensure!(
            journal.owner.session_id == self.session_id
                && journal.generation == self.source_generation
                && current_live == self.live_resources,
            "host journal changed after prepared all-resource preflight"
        );
        self.inspection_complete = true;
        Ok(self.observations.clone())
    }

    fn converge_absent(
        &mut self,
        resource: &OwnedResource,
    ) -> std::result::Result<(), RecoveryConvergenceError> {
        if !self.inspection_complete {
            return Err(RecoveryConvergenceError::operational(anyhow::anyhow!(
                "prepared host recovery mutation requested before inspect_all"
            )));
        }
        let mut matched = None;
        for group in &mut self.groups {
            if let Some(result) = group.converge_absent(resource) {
                if matched.is_some() {
                    return Err(RecoveryConvergenceError::conflict(anyhow::anyhow!(
                        "resource became supported by multiple prepared groups"
                    )));
                }
                matched = Some(result);
            }
        }
        matched.unwrap_or_else(|| {
            Err(RecoveryConvergenceError::conflict(anyhow::anyhow!(
                "resource is no longer supported by its prepared group"
            )))
        })
    }
}

/// Prepared adapter for all live route records in one journal. On a different
/// boot, volatile kernel routes cannot be attributed to the old process even
/// if their fields happen to match, so any present record is exposed as a
/// conflict and the all-resource planner performs zero mutation.
pub struct PreparedLinuxRouteGroup {
    prepared: PreparedLinuxRouteRecovery,
    observations: Vec<(RouteResource, ResourceObservationKind)>,
}

impl PreparedLinuxRouteGroup {
    pub fn prepare(
        session: SessionId,
        expected_namespace: NamespaceIdentity,
        resources: &[RouteResource],
        same_boot: bool,
    ) -> std::result::Result<Self, LinuxRoutePrepareError> {
        let prepared =
            PreparedLinuxRouteRecovery::prepare(session, expected_namespace, resources, same_boot)?;
        let observations = prepared
            .classifications()
            .into_iter()
            .map(|(resource, classification)| {
                let kind = match classification {
                    LinuxOwnedRouteClassification::Absent => ResourceObservationKind::Absent,
                    LinuxOwnedRouteClassification::ExactOwnedPresent if same_boot => {
                        ResourceObservationKind::ExactOwnedPresent
                    }
                    LinuxOwnedRouteClassification::ExactOwnedPresent
                    | LinuxOwnedRouteClassification::Conflict => ResourceObservationKind::Conflict,
                };
                (resource, kind)
            })
            .collect();
        Ok(Self {
            prepared,
            observations,
        })
    }
}

impl PreparedResourceGroup for PreparedLinuxRouteGroup {
    fn observe(&self, resource: &OwnedResource) -> Option<ResourceObservationKind> {
        let OwnedResource::Route(resource) = resource else {
            return None;
        };
        self.observations
            .iter()
            .find_map(|(candidate, kind)| (candidate == resource).then_some(*kind))
    }

    fn converge_absent(
        &mut self,
        resource: &OwnedResource,
    ) -> Option<std::result::Result<(), RecoveryConvergenceError>> {
        let OwnedResource::Route(resource) = resource else {
            return None;
        };
        if !self
            .observations
            .iter()
            .any(|(candidate, _)| candidate == resource)
        {
            return None;
        }
        Some(
            self.prepared
                .converge_absent(resource)
                .map_err(map_linux_route_convergence_error),
        )
    }
}

fn map_linux_route_convergence_error(error: LinuxRouteConvergeError) -> RecoveryConvergenceError {
    let is_conflict = error.is_conflict();
    let error = anyhow::Error::new(error);
    if is_conflict {
        RecoveryConvergenceError::conflict(error)
    } else {
        RecoveryConvergenceError::operational(error)
    }
}

pub struct PreparedTunGroup {
    session: SessionId,
    resource: TunResource,
    observation: ResourceObservationKind,
}

fn classify_crash_recovery_tun(observed: ResourceObservationKind) -> ResourceObservationKind {
    if observed == ResourceObservationKind::ExactOwnedPresent {
        ResourceObservationKind::Conflict
    } else {
        observed
    }
}

impl PreparedTunGroup {
    pub fn prepare(resource: TunResource, session: SessionId, _same_boot: bool) -> Result<Self> {
        let observed = inspect_tun(&resource, session).context("inspect journaled TUN")?;
        // A production TUN is non-persistent and must disappear with the last
        // owner FD. Rtnetlink offers no atomic "delete iff name+index+alias"
        // operation, so even an exactly matching survivor is not safe deletion
        // authority: ifindex could be reused between inspection and mutation.
        let observation = classify_crash_recovery_tun(observed);
        Ok(Self {
            session,
            resource,
            observation,
        })
    }

    fn prove_stable_absence_with<I>(
        &self,
        mut inspect: I,
    ) -> std::result::Result<(), RecoveryConvergenceError>
    where
        I: FnMut() -> Result<ResourceObservationKind>,
    {
        for boundary in ["first", "immediate"] {
            let observed = inspect().map_err(RecoveryConvergenceError::operational)?;
            if observed != ResourceObservationKind::Absent {
                return Err(RecoveryConvergenceError::conflict(anyhow::anyhow!(
                    "TUN {boundary} absence reinspection observed surviving/reused state: {observed:?}; refusing non-atomic RTM_DELLINK"
                )));
            }
        }
        Ok(())
    }
}

impl PreparedResourceGroup for PreparedTunGroup {
    fn observe(&self, resource: &OwnedResource) -> Option<ResourceObservationKind> {
        match resource {
            OwnedResource::Tun(resource) if resource == &self.resource => Some(self.observation),
            _ => None,
        }
    }

    fn converge_absent(
        &mut self,
        resource: &OwnedResource,
    ) -> Option<std::result::Result<(), RecoveryConvergenceError>> {
        let OwnedResource::Tun(resource) = resource else {
            return None;
        };
        if resource != &self.resource {
            return None;
        }
        Some(self.prove_stable_absence_with(|| {
            inspect_tun(resource, self.session).context("reinspect crash-recovered TUN absence")
        }))
    }
}

pub struct PreparedDnsGroup {
    target_path: PathBuf,
    session: SessionId,
    resource: DnsResource,
    observation: ResourceObservationKind,
}

impl PreparedDnsGroup {
    pub fn prepare(target_path: &Path, session: SessionId, resource: DnsResource) -> Result<Self> {
        let topology = inspect_exchange_typed(target_path, session, &resource)
            .map_err(anyhow::Error::new)
            .context("prepare exact DNS exchange recovery")?;
        Ok(Self {
            target_path: target_path.to_path_buf(),
            session,
            resource,
            observation: topology.observation_kind(),
        })
    }
}

fn map_dns_convergence_error(error: DnsExchangeFailure) -> RecoveryConvergenceError {
    match error.kind() {
        DnsExchangeFailureKind::Conflict => {
            RecoveryConvergenceError::conflict(anyhow::Error::new(error))
        }
        DnsExchangeFailureKind::Operational => {
            RecoveryConvergenceError::operational(anyhow::Error::new(error))
        }
    }
}

impl PreparedResourceGroup for PreparedDnsGroup {
    fn observe(&self, resource: &OwnedResource) -> Option<ResourceObservationKind> {
        match resource {
            OwnedResource::Dns(resource) if resource == &self.resource => Some(self.observation),
            _ => None,
        }
    }

    fn converge_absent(
        &mut self,
        resource: &OwnedResource,
    ) -> Option<std::result::Result<(), RecoveryConvergenceError>> {
        let OwnedResource::Dns(resource) = resource else {
            return None;
        };
        if resource != &self.resource {
            return None;
        }
        Some(
            recover_exchange_typed(&self.target_path, self.session, resource)
                .map_err(map_dns_convergence_error),
        )
    }
}

/// A late ownership conflict is not an ordinary retryable syscall failure. It
/// must poison the durable journal before recovery returns, while operational
/// failures retain the current Cleaning checkpoint for a safe retry.
#[derive(Debug)]
pub enum RecoveryConvergenceError {
    Conflict(anyhow::Error),
    Operational(anyhow::Error),
}

impl RecoveryConvergenceError {
    pub fn conflict(error: impl Into<anyhow::Error>) -> Self {
        Self::Conflict(error.into())
    }

    pub fn operational(error: impl Into<anyhow::Error>) -> Self {
        Self::Operational(error.into())
    }
}

impl std::fmt::Display for RecoveryConvergenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict(error) => write!(formatter, "late ownership conflict: {error:#}"),
            Self::Operational(error) => write!(formatter, "recovery operation failed: {error:#}"),
        }
    }
}

impl std::error::Error for RecoveryConvergenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Conflict(error) | Self::Operational(error) => Some(error.as_ref()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryRunOutcome {
    LeaveActive,
    Refused(RecoveryRefusal),
    Recovered { removed_records: usize },
}

pub fn recover_host_state<A: HostRecoveryAdapter>(
    durable: &mut DurableHostJournal,
    owner: OwnerDisposition,
    adapter: &mut A,
) -> Result<RecoveryRunOutcome> {
    match owner {
        OwnerDisposition::Active => return Ok(RecoveryRunOutcome::LeaveActive),
        OwnerDisposition::Ambiguous => {
            return Ok(RecoveryRunOutcome::Refused(RecoveryRefusal::AmbiguousOwner))
        }
        OwnerDisposition::Stale => {}
    }
    if durable.journal().phase == JournalPhase::Conflict {
        return Ok(RecoveryRunOutcome::Refused(
            RecoveryRefusal::JournalAlreadyInConflict,
        ));
    }
    // No mutating callback is reachable until inspect_all has returned and the
    // pure planner has accepted the complete observation set.
    let observations = adapter
        .inspect_all(durable.journal())
        .context("inspect complete journaled host-state vocabulary")?;
    let decision = decide_recovery(durable.journal(), owner, &observations)
        .context("construct all-or-nothing host recovery plan")?;
    match decision {
        RecoveryDecision::LeaveActive => Ok(RecoveryRunOutcome::LeaveActive),
        RecoveryDecision::Refuse(refusal) => {
            if matches!(
                refusal,
                RecoveryRefusal::ResourceConflict { .. }
                    | RecoveryRefusal::JournalAlreadyInConflict
            ) && durable.journal().phase != JournalPhase::Conflict
            {
                durable
                    .mark_conflict()
                    .context("durably mark conflicting host-state journal")?;
            }
            Ok(RecoveryRunOutcome::Refused(refusal))
        }
        RecoveryDecision::Execute(plan) => {
            anyhow::ensure!(
                plan.source_generation == durable.journal().generation,
                "recovery plan generation changed before execution"
            );
            durable
                .begin_cleaning()
                .context("persist Cleaning before first recovery mutation")?;
            let mut removed_records = 0usize;
            for step in plan.steps {
                match adapter.converge_absent(&step.resource) {
                    Ok(()) => {}
                    Err(RecoveryConvergenceError::Conflict(error)) => {
                        durable.mark_conflict().with_context(|| {
                            format!(
                                "durably mark late conflict at journal operation {}: {error:#}",
                                step.operation_id,
                            )
                        })?;
                        return Ok(RecoveryRunOutcome::Refused(
                            RecoveryRefusal::ResourceConflict {
                                operation_ids: vec![step.operation_id],
                            },
                        ));
                    }
                    Err(RecoveryConvergenceError::Operational(error)) => {
                        return Err(error).with_context(|| {
                            format!(
                                "converge journal operation {} from {:?} to absent",
                                step.operation_id, step.action
                            )
                        });
                    }
                }
                durable
                    .acknowledge_recovery_step(step.operation_id)
                    .with_context(|| {
                        format!("persist removal of journal operation {}", step.operation_id)
                    })?;
                removed_records += 1;
            }
            durable
                .remove_completed_file()
                .context("remove fully recovered host-state journal")?;
            Ok(RecoveryRunOutcome::Recovered { removed_records })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_state::{
        AddressFamily, FirewallBackend, FirewallChainToken, FirewallOutputChainOrigin,
        FirewallResource, FirewallTableOrigin, HostStateJournalV2, JournalStore, OperationState,
        OwnerIdentity, ResourceObservationKind, SessionId, IPV4_STATIC_FIREWALL_RULE_COUNT,
    };
    use std::cell::{Cell, RefCell};
    use std::fs;
    use std::path::PathBuf;
    use std::rc::Rc;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "shadowpipe-host-recovery-{}-{}",
                std::process::id(),
                SessionId::generate().unwrap()
            ));
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn owner() -> OwnerIdentity {
        OwnerIdentity {
            session_id: SessionId::from_bytes([7; 16]),
            boot_id: None,
            uid: {
                #[cfg(unix)]
                {
                    // SAFETY: geteuid has no arguments or preconditions.
                    unsafe { libc::geteuid() }
                }
                #[cfg(not(unix))]
                {
                    0
                }
            },
            pid: 1,
            pid_start_ticks: None,
            network_namespace: None,
            mount_namespace: None,
        }
    }

    fn firewall() -> OwnedResource {
        OwnedResource::Firewall(FirewallResource {
            family: AddressFamily::Ipv4,
            backend: FirewallBackend::IptablesNft,
            chain_token: FirewallChainToken::from_bytes([3; 10]),
            filter_table_origin: FirewallTableOrigin::Preexisting,
            output_chain_origin: FirewallOutputChainOrigin::Preexisting,
            expected_rule_count: IPV4_STATIC_FIREWALL_RULE_COUNT,
        })
    }

    fn active_runtime(path: PathBuf) -> DurableHostJournal {
        let store = JournalStore::new(path);
        let mut runtime = DurableHostJournal::create(store, owner()).unwrap();
        let operation = runtime.begin_add(firewall()).unwrap();
        runtime.acknowledge_add(operation).unwrap();
        runtime.publish_active().unwrap();
        runtime
    }

    struct FakeAdapter {
        observations: Vec<ResourceObservation>,
        inspection_complete: Rc<Cell<bool>>,
        removals: Vec<OwnedResource>,
        convergence: FakeConvergence,
    }

    #[derive(Clone, Copy)]
    enum FakeConvergence {
        Success,
        Conflict,
        Operational,
    }

    struct PreparedFirewallGroup {
        resource: OwnedResource,
        observation: ResourceObservationKind,
        calls: Rc<RefCell<Vec<OwnedResource>>>,
    }

    impl PreparedResourceGroup for PreparedFirewallGroup {
        fn observe(&self, resource: &OwnedResource) -> Option<ResourceObservationKind> {
            (resource == &self.resource).then_some(self.observation)
        }

        fn converge_absent(
            &mut self,
            resource: &OwnedResource,
        ) -> Option<std::result::Result<(), RecoveryConvergenceError>> {
            if resource != &self.resource {
                return None;
            }
            self.calls.borrow_mut().push(resource.clone());
            Some(Ok(()))
        }
    }

    impl HostRecoveryAdapter for FakeAdapter {
        fn inspect_all(
            &mut self,
            _journal: &HostStateJournalV2,
        ) -> Result<Vec<ResourceObservation>> {
            self.inspection_complete.set(true);
            Ok(self.observations.clone())
        }

        fn converge_absent(
            &mut self,
            resource: &OwnedResource,
        ) -> std::result::Result<(), RecoveryConvergenceError> {
            assert!(
                self.inspection_complete.get(),
                "mutation was exposed before complete inspection"
            );
            self.removals.push(resource.clone());
            match self.convergence {
                FakeConvergence::Success => Ok(()),
                FakeConvergence::Conflict => Err(RecoveryConvergenceError::conflict(
                    anyhow::anyhow!("resource reappeared with foreign identity"),
                )),
                FakeConvergence::Operational => Err(RecoveryConvergenceError::operational(
                    anyhow::anyhow!("temporary inspection I/O failure"),
                )),
            }
        }
    }

    #[test]
    fn conflict_makes_zero_host_mutations_and_is_durable() {
        let directory = Directory::new();
        let path = directory.0.join("host-state-v2.json");
        let mut runtime = active_runtime(path.clone());
        let complete = Rc::new(Cell::new(false));
        let mut adapter = FakeAdapter {
            observations: vec![ResourceObservation {
                operation_id: 1,
                kind: ResourceObservationKind::Conflict,
            }],
            inspection_complete: Rc::clone(&complete),
            removals: Vec::new(),
            convergence: FakeConvergence::Success,
        };
        let outcome = recover_host_state(&mut runtime, OwnerDisposition::Stale, &mut adapter)
            .expect("conflict is a typed refusal");
        assert!(matches!(
            outcome,
            RecoveryRunOutcome::Refused(RecoveryRefusal::ResourceConflict { .. })
        ));
        assert!(adapter.removals.is_empty());
        assert_eq!(runtime.journal().phase, JournalPhase::Conflict);
        assert!(path.exists());
    }

    #[test]
    fn exact_and_absent_steps_checkpoint_then_remove_journal() {
        let directory = Directory::new();
        let path = directory.0.join("host-state-v2.json");
        let mut runtime = active_runtime(path.clone());
        let complete = Rc::new(Cell::new(false));
        let mut adapter = FakeAdapter {
            observations: vec![ResourceObservation {
                operation_id: 1,
                kind: ResourceObservationKind::ExactOwnedPresent,
            }],
            inspection_complete: complete,
            removals: Vec::new(),
            convergence: FakeConvergence::Success,
        };
        assert_eq!(
            recover_host_state(&mut runtime, OwnerDisposition::Stale, &mut adapter).unwrap(),
            RecoveryRunOutcome::Recovered { removed_records: 1 }
        );
        assert_eq!(adapter.removals, vec![firewall()]);
        assert_eq!(
            runtime.journal().operations[0].state,
            OperationState::Removed
        );
        assert!(!path.exists());
    }

    #[test]
    fn ambiguous_owner_refuses_without_phase_or_host_change() {
        let directory = Directory::new();
        let path = directory.0.join("host-state-v2.json");
        let mut runtime = active_runtime(path);
        let mut adapter = FakeAdapter {
            observations: vec![ResourceObservation {
                operation_id: 1,
                kind: ResourceObservationKind::ExactOwnedPresent,
            }],
            inspection_complete: Rc::new(Cell::new(false)),
            removals: Vec::new(),
            convergence: FakeConvergence::Success,
        };
        assert_eq!(
            recover_host_state(&mut runtime, OwnerDisposition::Ambiguous, &mut adapter).unwrap(),
            RecoveryRunOutcome::Refused(RecoveryRefusal::AmbiguousOwner)
        );
        assert!(adapter.removals.is_empty());
        assert_eq!(runtime.journal().phase, JournalPhase::Active);
        assert!(!adapter.inspection_complete.get());
    }

    #[test]
    fn late_conflict_is_durably_poisoned_before_refusal() {
        let directory = Directory::new();
        let path = directory.0.join("host-state-v2.json");
        let mut runtime = active_runtime(path.clone());
        let mut adapter = FakeAdapter {
            observations: vec![ResourceObservation {
                operation_id: 1,
                kind: ResourceObservationKind::Absent,
            }],
            inspection_complete: Rc::new(Cell::new(false)),
            removals: Vec::new(),
            convergence: FakeConvergence::Conflict,
        };
        assert_eq!(
            recover_host_state(&mut runtime, OwnerDisposition::Stale, &mut adapter).unwrap(),
            RecoveryRunOutcome::Refused(RecoveryRefusal::ResourceConflict {
                operation_ids: vec![1]
            })
        );
        assert_eq!(runtime.journal().phase, JournalPhase::Conflict);
        assert_eq!(
            runtime.journal().operations[0].state,
            OperationState::Applied
        );
        assert!(path.exists());
    }

    #[test]
    fn operational_convergence_failure_keeps_retryable_cleaning_checkpoint() {
        let directory = Directory::new();
        let path = directory.0.join("host-state-v2.json");
        let mut runtime = active_runtime(path.clone());
        let mut adapter = FakeAdapter {
            observations: vec![ResourceObservation {
                operation_id: 1,
                kind: ResourceObservationKind::ExactOwnedPresent,
            }],
            inspection_complete: Rc::new(Cell::new(false)),
            removals: Vec::new(),
            convergence: FakeConvergence::Operational,
        };
        let error = recover_host_state(&mut runtime, OwnerDisposition::Stale, &mut adapter)
            .expect_err("operational failure remains retryable");
        assert!(error.to_string().contains("converge journal operation 1"));
        assert_eq!(runtime.journal().phase, JournalPhase::Cleaning);
        assert_eq!(
            runtime.journal().operations[0].state,
            OperationState::Applied
        );
        assert!(path.exists());
    }

    #[test]
    fn tun_convergence_can_only_reprove_stable_absence_without_delete() {
        assert_eq!(
            classify_crash_recovery_tun(ResourceObservationKind::ExactOwnedPresent),
            ResourceObservationKind::Conflict
        );
        assert_eq!(
            classify_crash_recovery_tun(ResourceObservationKind::Absent),
            ResourceObservationKind::Absent
        );
        assert_eq!(
            classify_crash_recovery_tun(ResourceObservationKind::Conflict),
            ResourceObservationKind::Conflict
        );

        let resource = TunResource {
            interface: crate::host_state::InterfaceIdentity {
                name: "sptun0".to_string(),
                ifindex: 17,
            },
        };
        let group = PreparedTunGroup {
            session: SessionId::from_bytes([9; 16]),
            resource,
            observation: ResourceObservationKind::Absent,
        };
        let calls = Cell::new(0usize);
        group
            .prove_stable_absence_with(|| {
                calls.set(calls.get() + 1);
                Ok(ResourceObservationKind::Absent)
            })
            .unwrap();
        assert_eq!(calls.get(), 2);

        let calls = Cell::new(0usize);
        let late_present = group.prove_stable_absence_with(|| {
            let call = calls.get();
            calls.set(call + 1);
            Ok(if call == 0 {
                ResourceObservationKind::Absent
            } else {
                ResourceObservationKind::ExactOwnedPresent
            })
        });
        assert!(matches!(
            late_present,
            Err(RecoveryConvergenceError::Conflict(_))
        ));
        assert_eq!(calls.get(), 2);

        let operational = group
            .prove_stable_absence_with(|| anyhow::bail!("injected TUN inspection syscall failure"));
        assert!(matches!(
            operational,
            Err(RecoveryConvergenceError::Operational(_))
        ));
    }

    #[test]
    fn prepared_route_group_mapping_preserves_durable_conflict_vs_retryable_operational() {
        let conflict = map_linux_route_convergence_error(LinuxRouteConvergeError::Conflict {
            detail: "late route ownership race".to_string(),
        });
        assert!(matches!(conflict, RecoveryConvergenceError::Conflict(_)));

        let operational = map_linux_route_convergence_error(LinuxRouteConvergeError::Operational {
            detail: "bounded ip subprocess timeout".to_string(),
        });
        assert!(matches!(
            operational,
            RecoveryConvergenceError::Operational(_)
        ));
    }

    #[test]
    fn prepared_composition_requires_exactly_one_group_per_live_resource() {
        let directory = Directory::new();
        let path = directory.0.join("host-state-v2.json");
        let mut runtime = active_runtime(path.clone());
        let calls = Rc::new(RefCell::new(Vec::new()));
        let group = || PreparedFirewallGroup {
            resource: firewall(),
            observation: ResourceObservationKind::ExactOwnedPresent,
            calls: Rc::clone(&calls),
        };
        assert!(PreparedHostRecoveryAdapter::new(runtime.journal(), Vec::new()).is_err());
        assert!(PreparedHostRecoveryAdapter::new(
            runtime.journal(),
            vec![Box::new(group()), Box::new(group())]
        )
        .is_err());

        let mut prepared =
            PreparedHostRecoveryAdapter::new(runtime.journal(), vec![Box::new(group())]).unwrap();
        assert_eq!(
            recover_host_state(&mut runtime, OwnerDisposition::Stale, &mut prepared).unwrap(),
            RecoveryRunOutcome::Recovered { removed_records: 1 }
        );
        assert_eq!(*calls.borrow(), vec![firewall()]);
        assert!(!path.exists());
    }
}
