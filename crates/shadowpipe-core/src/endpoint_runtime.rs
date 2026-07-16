//! Synchronous transactional execution of endpoint host mutations.
//!
//! This module is deliberately narrower than a firewall, routing, or journal
//! implementation.  It validates a pure [`TransitionPlan`], invokes exact host
//! mutations through [`EndpointHostAdapter`], and compensates a failed prefix
//! in exact reverse order.  It never publishes or commits an endpoint snapshot;
//! the coordinator commit remains a separate caller-owned step.
//!
//! There are no futures or callbacks in the transaction path.  A journal-aware
//! adapter can therefore write-ahead-log each exact method call and its
//! [`OwnedMutation`] result without an `await`/cancellation gap inside the host
//! transaction.

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;

use crate::endpoint::{
    CarrierTuple, FirewallOperation, RouteOperation, TransitionOperation, TransitionPlan,
};

/// One exact privileged mutation.  These values are suitable as WAL records:
/// they contain no shell fragments, wildcards, flushes, or implicit discovery.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExactHostOperation {
    FirewallAllow(CarrierTuple),
    FirewallDeny(CarrierTuple),
    RouteAddBypass(Ipv4Addr),
    RouteRemoveBypass(Ipv4Addr),
}

impl ExactHostOperation {
    pub fn inverse(self) -> Self {
        match self {
            Self::FirewallAllow(tuple) => Self::FirewallDeny(tuple),
            Self::FirewallDeny(tuple) => Self::FirewallAllow(tuple),
            Self::RouteAddBypass(ip) => Self::RouteRemoveBypass(ip),
            Self::RouteRemoveBypass(ip) => Self::RouteAddBypass(ip),
        }
    }

    fn ip(self) -> Ipv4Addr {
        match self {
            Self::FirewallAllow(tuple) | Self::FirewallDeny(tuple) => *tuple.address.ip(),
            Self::RouteAddBypass(ip) | Self::RouteRemoveBypass(ip) => ip,
        }
    }
}

/// Whether a successful exact method call changed state owned by this runtime
/// transaction.  Only `Changed` calls are eligible for compensation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnedMutation {
    Changed,
    AlreadyExact,
}

/// Minimal synchronous privileged boundary.
///
/// Implementations should WAL the exact intent before mutating and return
/// `Changed` only after they can prove this call created/deleted owned state.
/// An error is never treated as a successful mutation and is never guessed at
/// during compensation; ambiguous command outcomes belong in the adapter's WAL
/// recovery protocol.
pub trait EndpointHostAdapter {
    type Error;

    fn firewall_allow(&mut self, tuple: CarrierTuple) -> Result<OwnedMutation, Self::Error>;
    fn firewall_deny(&mut self, tuple: CarrierTuple) -> Result<OwnedMutation, Self::Error>;
    fn route_add_bypass(&mut self, ip: Ipv4Addr) -> Result<OwnedMutation, Self::Error>;
    fn route_remove_bypass(&mut self, ip: Ipv4Addr) -> Result<OwnedMutation, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostTransactionKind {
    ObservationStage,
    /// Restore candidates exclusively from the coordinator's immutable signed
    /// authority. This transaction is addition-only and must end in one
    /// snapshot publication; deny/remove operations are never valid here.
    AuthorityRehydration,
    Retirement,
    LeaseRelease,
}

impl HostTransactionKind {
    fn is_monotonic_stage(self) -> bool {
        matches!(self, Self::ObservationStage | Self::AuthorityRehydration)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotPublication {
    pub from: u64,
    pub to: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanRejection {
    MultiplePublishMarkers,
    PublishForbidden,
    PublishNotFinal,
    MissingPublishMarker,
    PublishTargetMismatch { marker_to: u64, plan_target: u64 },
    NonAdvancingPublish { from: u64, to: u64 },
    OperationNotAllowed(ExactHostOperation),
    DuplicateHostOperation(ExactHostOperation),
    UnsafeHostOrder,
    RouteWithoutMatchingFirewall(Ipv4Addr),
    ModelOrderRejected(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanValidationError {
    pub kind: HostTransactionKind,
    pub rejection: PlanRejection,
}

impl fmt::Display for PlanValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid {:?} endpoint transition plan: {:?}",
            self.kind, self.rejection
        )
    }
}

impl std::error::Error for PlanValidationError {}

#[derive(Debug, Eq, PartialEq)]
pub struct HostOperationFailure<E> {
    pub operation: ExactHostOperation,
    pub error: E,
}

#[derive(Debug, Eq, PartialEq)]
pub struct HostTransactionFailure<E> {
    pub kind: HostTransactionKind,
    pub primary: HostOperationFailure<E>,
    /// Inverses are attempted in this order, even after an earlier inverse
    /// fails.  An empty vector proves the changed prefix compensated cleanly.
    pub rollback_failures: Vec<HostOperationFailure<E>>,
    /// Forward operations that returned `Changed`, in original order.
    pub changed_prefix: Vec<ExactHostOperation>,
}

impl<E: fmt::Display> fmt::Display for HostTransactionFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} host operation {:?} failed: {}",
            self.kind, self.primary.operation, self.primary.error
        )?;
        if !self.rollback_failures.is_empty() {
            write!(
                f,
                "; {} rollback operation(s) also failed",
                self.rollback_failures.len()
            )?;
        }
        Ok(())
    }
}

impl<E: std::error::Error + 'static> std::error::Error for HostTransactionFailure<E> {}

#[derive(Debug, Eq, PartialEq)]
pub enum TransitionExecutionError<E> {
    InvalidPlan(PlanValidationError),
    Host(HostTransactionFailure<E>),
}

impl<E: fmt::Display> fmt::Display for TransitionExecutionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlan(error) => error.fmt(f),
            Self::Host(error) => error.fmt(f),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for TransitionExecutionError<E> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostOperationRecord {
    pub operation: ExactHostOperation,
    pub outcome: OwnedMutation,
}

/// Receipt for a fully successful host prefix.  It does not mean the endpoint
/// coordinator or its snapshot was committed.
#[derive(Debug)]
pub struct AppliedHostTransaction {
    kind: HostTransactionKind,
    operations: Vec<HostOperationRecord>,
    publication: Option<SnapshotPublication>,
}

impl AppliedHostTransaction {
    pub fn kind(&self) -> HostTransactionKind {
        self.kind
    }

    pub fn operations(&self) -> &[HostOperationRecord] {
        &self.operations
    }

    pub fn changed_operations(&self) -> impl DoubleEndedIterator<Item = ExactHostOperation> + '_ {
        self.operations.iter().filter_map(|record| {
            (record.outcome == OwnedMutation::Changed).then_some(record.operation)
        })
    }

    pub fn publication(&self) -> Option<SnapshotPublication> {
        self.publication
    }

    pub fn changed_host_state(&self) -> bool {
        self.changed_operations().next().is_some()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct RollbackError<E> {
    pub kind: HostTransactionKind,
    pub failures: Vec<HostOperationFailure<E>>,
}

impl<E: fmt::Display> fmt::Display for RollbackError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {:?} rollback operation(s) failed",
            self.failures.len(),
            self.kind
        )
    }
}

impl<E: std::error::Error + 'static> std::error::Error for RollbackError<E> {}

struct ValidatedHostPlan {
    operations: Vec<ExactHostOperation>,
    publication: Option<SnapshotPublication>,
}

/// Stateless synchronous executor.  Every method completes the entire host
/// transaction before returning; snapshot/model commit is intentionally absent.
pub struct EndpointTransitionExecutor;

impl EndpointTransitionExecutor {
    pub fn stage_observation<H: EndpointHostAdapter>(
        host: &mut H,
        plan: &TransitionPlan,
    ) -> Result<AppliedHostTransaction, TransitionExecutionError<H::Error>> {
        Self::execute(host, plan, HostTransactionKind::ObservationStage)
    }

    /// Execute the exact allow -> bypass-add prefix for a prepared restoration
    /// of the coordinator's complete signed authority.  The typed transaction
    /// kind rejects every deny/remove operation before the host adapter is
    /// called, so this path cannot be confused with DNS retirement cleanup.
    pub fn stage_authority_rehydration<H: EndpointHostAdapter>(
        host: &mut H,
        plan: &TransitionPlan,
    ) -> Result<AppliedHostTransaction, TransitionExecutionError<H::Error>> {
        Self::execute(host, plan, HostTransactionKind::AuthorityRehydration)
    }

    pub fn execute_retirement<H: EndpointHostAdapter>(
        host: &mut H,
        plan: &TransitionPlan,
    ) -> Result<AppliedHostTransaction, TransitionExecutionError<H::Error>> {
        Self::execute(host, plan, HostTransactionKind::Retirement)
    }

    pub fn execute_release<H: EndpointHostAdapter>(
        host: &mut H,
        plan: &TransitionPlan,
    ) -> Result<AppliedHostTransaction, TransitionExecutionError<H::Error>> {
        Self::execute(host, plan, HostTransactionKind::LeaseRelease)
    }

    /// Undo a previously successful host transaction after a later coordinator
    /// commit/validation failure.  The receipt is consumed to discourage an
    /// accidental second rollback.
    pub fn rollback_applied<H: EndpointHostAdapter>(
        host: &mut H,
        applied: AppliedHostTransaction,
    ) -> Result<(), RollbackError<H::Error>> {
        let changed: Vec<_> = applied.changed_operations().collect();
        let failures = rollback_changed(host, &changed);
        if failures.is_empty() {
            Ok(())
        } else {
            Err(RollbackError {
                kind: applied.kind,
                failures,
            })
        }
    }

    fn execute<H: EndpointHostAdapter>(
        host: &mut H,
        plan: &TransitionPlan,
        kind: HostTransactionKind,
    ) -> Result<AppliedHostTransaction, TransitionExecutionError<H::Error>> {
        let validated = validate_plan(plan, kind).map_err(TransitionExecutionError::InvalidPlan)?;
        let mut records = Vec::with_capacity(validated.operations.len());
        let mut changed = Vec::new();

        for operation in validated.operations {
            match apply_exact(host, operation) {
                Ok(outcome) => {
                    records.push(HostOperationRecord { operation, outcome });
                    if outcome == OwnedMutation::Changed {
                        changed.push(operation);
                    }
                }
                Err(error) => {
                    let rollback_failures = rollback_changed(host, &changed);
                    return Err(TransitionExecutionError::Host(HostTransactionFailure {
                        kind,
                        primary: HostOperationFailure { operation, error },
                        rollback_failures,
                        changed_prefix: changed,
                    }));
                }
            }
        }

        Ok(AppliedHostTransaction {
            kind,
            operations: records,
            publication: validated.publication,
        })
    }
}

fn validate_plan(
    plan: &TransitionPlan,
    kind: HostTransactionKind,
) -> Result<ValidatedHostPlan, PlanValidationError> {
    let reject = |rejection| PlanValidationError { kind, rejection };
    let publish_count = plan
        .operations
        .iter()
        .filter(|operation| matches!(operation, TransitionOperation::PublishSnapshot { .. }))
        .count();
    if publish_count > 1 {
        return Err(reject(PlanRejection::MultiplePublishMarkers));
    }

    let mut operations = Vec::new();
    let mut publication = None;
    let mut seen = BTreeSet::new();
    let mut firewall_ips = BTreeSet::new();
    let mut route_phase = false;

    for (index, operation) in plan.operations.iter().enumerate() {
        let exact = match operation {
            TransitionOperation::PublishSnapshot { from, to } => {
                if !kind.is_monotonic_stage() {
                    return Err(reject(PlanRejection::PublishForbidden));
                }
                if index + 1 != plan.operations.len() {
                    return Err(reject(PlanRejection::PublishNotFinal));
                }
                if *to != plan.target_generation() {
                    return Err(reject(PlanRejection::PublishTargetMismatch {
                        marker_to: *to,
                        plan_target: plan.target_generation(),
                    }));
                }
                if from >= to {
                    return Err(reject(PlanRejection::NonAdvancingPublish {
                        from: *from,
                        to: *to,
                    }));
                }
                publication = Some(SnapshotPublication {
                    from: *from,
                    to: *to,
                });
                continue;
            }
            TransitionOperation::Firewall(FirewallOperation::Allow(tuple))
                if kind.is_monotonic_stage() =>
            {
                if route_phase {
                    return Err(reject(PlanRejection::UnsafeHostOrder));
                }
                let exact = ExactHostOperation::FirewallAllow(*tuple);
                firewall_ips.insert(exact.ip());
                exact
            }
            TransitionOperation::Route(RouteOperation::AddBypass(ip))
                if kind.is_monotonic_stage() =>
            {
                route_phase = true;
                let exact = ExactHostOperation::RouteAddBypass(*ip);
                if !firewall_ips.contains(ip) {
                    return Err(reject(PlanRejection::RouteWithoutMatchingFirewall(*ip)));
                }
                exact
            }
            TransitionOperation::Firewall(FirewallOperation::Deny(tuple))
                if !kind.is_monotonic_stage() =>
            {
                if route_phase {
                    return Err(reject(PlanRejection::UnsafeHostOrder));
                }
                let exact = ExactHostOperation::FirewallDeny(*tuple);
                firewall_ips.insert(exact.ip());
                exact
            }
            TransitionOperation::Route(RouteOperation::RemoveBypass(ip))
                if !kind.is_monotonic_stage() =>
            {
                route_phase = true;
                let exact = ExactHostOperation::RouteRemoveBypass(*ip);
                if !firewall_ips.contains(ip) {
                    return Err(reject(PlanRejection::RouteWithoutMatchingFirewall(*ip)));
                }
                exact
            }
            TransitionOperation::Firewall(FirewallOperation::Allow(tuple)) => {
                return Err(reject(PlanRejection::OperationNotAllowed(
                    ExactHostOperation::FirewallAllow(*tuple),
                )))
            }
            TransitionOperation::Firewall(FirewallOperation::Deny(tuple)) => {
                return Err(reject(PlanRejection::OperationNotAllowed(
                    ExactHostOperation::FirewallDeny(*tuple),
                )))
            }
            TransitionOperation::Route(RouteOperation::AddBypass(ip)) => {
                return Err(reject(PlanRejection::OperationNotAllowed(
                    ExactHostOperation::RouteAddBypass(*ip),
                )))
            }
            TransitionOperation::Route(RouteOperation::RemoveBypass(ip)) => {
                return Err(reject(PlanRejection::OperationNotAllowed(
                    ExactHostOperation::RouteRemoveBypass(*ip),
                )))
            }
        };

        if !seen.insert(exact) {
            return Err(reject(PlanRejection::DuplicateHostOperation(exact)));
        }
        operations.push(exact);
    }

    if kind.is_monotonic_stage() && !operations.is_empty() && publication.is_none() {
        return Err(reject(PlanRejection::MissingPublishMarker));
    }
    plan.validate_order()
        .map_err(|error| reject(PlanRejection::ModelOrderRejected(error.to_string())))?;

    Ok(ValidatedHostPlan {
        operations,
        publication,
    })
}

fn apply_exact<H: EndpointHostAdapter>(
    host: &mut H,
    operation: ExactHostOperation,
) -> Result<OwnedMutation, H::Error> {
    match operation {
        ExactHostOperation::FirewallAllow(tuple) => host.firewall_allow(tuple),
        ExactHostOperation::FirewallDeny(tuple) => host.firewall_deny(tuple),
        ExactHostOperation::RouteAddBypass(ip) => host.route_add_bypass(ip),
        ExactHostOperation::RouteRemoveBypass(ip) => host.route_remove_bypass(ip),
    }
}

fn rollback_changed<H: EndpointHostAdapter>(
    host: &mut H,
    changed: &[ExactHostOperation],
) -> Vec<HostOperationFailure<H::Error>> {
    let mut failures = Vec::new();
    for operation in changed.iter().rev().map(|operation| operation.inverse()) {
        if let Err(error) = apply_exact(host, operation) {
            failures.push(HostOperationFailure { operation, error });
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{
        AddressPolicy, AddressRecord, AuthConfigRef, CandidateKey, CarrierProtocol,
        EndpointCoordinator, LogicalEndpoint, LogicalEndpointId, ResolutionObservation,
        SeedCandidate, VerifiedIpv4Authority,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::net::SocketAddrV4;

    const A: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    const B: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
    const C: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
    const LOGICAL: LogicalEndpointId = LogicalEndpointId(17);

    fn tuple(ip: Ipv4Addr) -> CarrierTuple {
        CarrierTuple {
            address: SocketAddrV4::new(ip, 443),
            protocol: CarrierProtocol::Tcp,
        }
    }

    fn coordinator(seeds: &[Ipv4Addr], authority: &[Ipv4Addr]) -> EndpointCoordinator {
        EndpointCoordinator::new(
            [LogicalEndpoint {
                id: LOGICAL,
                hostname: "runtime.example.com".into(),
                port: 443,
                protocol: CarrierProtocol::Tcp,
                auth: AuthConfigRef(9),
                authority: VerifiedIpv4Authority::from_preverified_manifest(
                    41,
                    authority.iter().copied(),
                )
                .unwrap(),
                address_policy: AddressPolicy::default(),
            }],
            seeds.iter().copied().map(|ip| SeedCandidate {
                logical: LOGICAL,
                ip,
            }),
            0,
        )
        .unwrap()
    }

    fn prepare_positive(
        coordinator: &mut EndpointCoordinator,
        observed: &[Ipv4Addr],
    ) -> crate::endpoint::PreparedObservation {
        let stamp = coordinator.begin_query(LOGICAL).unwrap();
        coordinator
            .prepare_observation(
                stamp,
                ResolutionObservation::Positive(
                    observed
                        .iter()
                        .copied()
                        .map(|ip| AddressRecord { ip, ttl_secs: 60 })
                        .collect(),
                ),
                10,
                0,
            )
            .unwrap()
    }

    fn addition_plan() -> TransitionPlan {
        let mut coordinator = coordinator(&[A], &[A, B, C]);
        prepare_positive(&mut coordinator, &[B, C]).plan().clone()
    }

    fn authority_rehydration_plan() -> TransitionPlan {
        coordinator(&[A], &[A, B, C])
            .prepare_authority_rehydration()
            .unwrap()
            .plan()
            .clone()
    }

    fn authority_rehydration_publish_only_plan() -> TransitionPlan {
        let mut coordinator = coordinator(&[A, B], &[A, B]);
        let narrowed = prepare_positive(&mut coordinator, &[B]);
        coordinator.commit_observation(narrowed).unwrap();
        coordinator
            .prepare_authority_rehydration()
            .unwrap()
            .plan()
            .clone()
    }

    fn empty_authority_rehydration_plan() -> TransitionPlan {
        coordinator(&[A, B], &[A, B])
            .prepare_authority_rehydration()
            .unwrap()
            .plan()
            .clone()
    }

    fn publish_only_plan() -> TransitionPlan {
        let mut coordinator = coordinator(&[A, B], &[A, B]);
        prepare_positive(&mut coordinator, &[B]).plan().clone()
    }

    fn empty_observation_plan() -> TransitionPlan {
        let mut coordinator = coordinator(&[A], &[A]);
        let stamp = coordinator.begin_query(LOGICAL).unwrap();
        coordinator
            .prepare_observation(stamp, ResolutionObservation::TransientFailure, 10, 0)
            .unwrap()
            .plan()
            .clone()
    }

    fn cleanup_plan() -> TransitionPlan {
        let mut coordinator = coordinator(&[A, B], &[A, B, C]);
        let prepared = prepare_positive(&mut coordinator, &[C]);
        coordinator.commit_observation(prepared).unwrap();
        coordinator
            .prepare_retirement()
            .unwrap()
            .unwrap()
            .plan()
            .clone()
    }

    fn empty_release_plan() -> TransitionPlan {
        let mut coordinator = coordinator(&[A], &[A]);
        let lease = coordinator
            .acquire(CandidateKey {
                logical: LOGICAL,
                ip: A,
            })
            .unwrap();
        coordinator.prepare_release(lease).unwrap().plan().clone()
    }

    fn plan_host_operations(plan: &TransitionPlan) -> Vec<ExactHostOperation> {
        plan.operations
            .iter()
            .filter_map(|operation| match operation {
                TransitionOperation::Firewall(FirewallOperation::Allow(tuple)) => {
                    Some(ExactHostOperation::FirewallAllow(*tuple))
                }
                TransitionOperation::Firewall(FirewallOperation::Deny(tuple)) => {
                    Some(ExactHostOperation::FirewallDeny(*tuple))
                }
                TransitionOperation::Route(RouteOperation::AddBypass(ip)) => {
                    Some(ExactHostOperation::RouteAddBypass(*ip))
                }
                TransitionOperation::Route(RouteOperation::RemoveBypass(ip)) => {
                    Some(ExactHostOperation::RouteRemoveBypass(*ip))
                }
                TransitionOperation::PublishSnapshot { .. } => None,
            })
            .collect()
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestError(&'static str);

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Error for TestError {}

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    struct OwnedState {
        firewall: BTreeSet<CarrierTuple>,
        routes: BTreeSet<Ipv4Addr>,
    }

    #[derive(Default)]
    struct FaultHost {
        state: OwnedState,
        calls: Vec<ExactHostOperation>,
        fail_calls: BTreeMap<usize, &'static str>,
    }

    impl FaultHost {
        fn owning(ips: &[Ipv4Addr]) -> Self {
            Self {
                state: OwnedState {
                    firewall: ips.iter().copied().map(tuple).collect(),
                    routes: ips.iter().copied().collect(),
                },
                ..Self::default()
            }
        }

        fn fail_at(mut self, call: usize, message: &'static str) -> Self {
            self.fail_calls.insert(call, message);
            self
        }

        fn before_call(&mut self, operation: ExactHostOperation) -> Result<(), TestError> {
            let index = self.calls.len();
            self.calls.push(operation);
            match self.fail_calls.get(&index).copied() {
                Some(message) => Err(TestError(message)),
                None => Ok(()),
            }
        }

        fn effect(changed: bool) -> OwnedMutation {
            if changed {
                OwnedMutation::Changed
            } else {
                OwnedMutation::AlreadyExact
            }
        }
    }

    impl EndpointHostAdapter for FaultHost {
        type Error = TestError;

        fn firewall_allow(&mut self, tuple: CarrierTuple) -> Result<OwnedMutation, Self::Error> {
            self.before_call(ExactHostOperation::FirewallAllow(tuple))?;
            Ok(Self::effect(self.state.firewall.insert(tuple)))
        }

        fn firewall_deny(&mut self, tuple: CarrierTuple) -> Result<OwnedMutation, Self::Error> {
            self.before_call(ExactHostOperation::FirewallDeny(tuple))?;
            Ok(Self::effect(self.state.firewall.remove(&tuple)))
        }

        fn route_add_bypass(&mut self, ip: Ipv4Addr) -> Result<OwnedMutation, Self::Error> {
            self.before_call(ExactHostOperation::RouteAddBypass(ip))?;
            Ok(Self::effect(self.state.routes.insert(ip)))
        }

        fn route_remove_bypass(&mut self, ip: Ipv4Addr) -> Result<OwnedMutation, Self::Error> {
            self.before_call(ExactHostOperation::RouteRemoveBypass(ip))?;
            Ok(Self::effect(self.state.routes.remove(&ip)))
        }
    }

    fn host_failure(
        result: Result<AppliedHostTransaction, TransitionExecutionError<TestError>>,
    ) -> HostTransactionFailure<TestError> {
        match result {
            Err(TransitionExecutionError::Host(failure)) => failure,
            Err(TransitionExecutionError::InvalidPlan(error)) => {
                panic!("unexpected invalid plan: {error}")
            }
            Ok(_) => panic!("host transaction unexpectedly succeeded"),
        }
    }

    fn invalid_plan(
        result: Result<AppliedHostTransaction, TransitionExecutionError<TestError>>,
    ) -> PlanRejection {
        match result {
            Err(TransitionExecutionError::InvalidPlan(error)) => error.rejection,
            Err(TransitionExecutionError::Host(_)) => panic!("invalid plan reached host"),
            Ok(_) => panic!("invalid plan unexpectedly succeeded"),
        }
    }

    #[test]
    fn observation_failure_at_every_prefix_compensates_exact_reverse() {
        let plan = addition_plan();
        let forward = plan_host_operations(&plan);
        assert_eq!(forward.len(), 4);

        for failure_index in 0..forward.len() {
            let mut host = FaultHost::default().fail_at(failure_index, "forward");
            let before = host.state.clone();
            let failure = host_failure(EndpointTransitionExecutor::stage_observation(
                &mut host, &plan,
            ));
            assert_eq!(failure.primary.operation, forward[failure_index]);
            assert_eq!(failure.primary.error, TestError("forward"));
            assert_eq!(failure.changed_prefix, forward[..failure_index]);
            assert!(failure.rollback_failures.is_empty());
            assert_eq!(host.state, before);

            let mut expected_calls = forward[..=failure_index].to_vec();
            expected_calls.extend(
                forward[..failure_index]
                    .iter()
                    .rev()
                    .map(|operation| operation.inverse()),
            );
            assert_eq!(host.calls, expected_calls);
        }
    }

    #[test]
    fn authority_rehydration_failure_at_every_prefix_compensates_exact_reverse() {
        let plan = authority_rehydration_plan();
        let forward = plan_host_operations(&plan);
        assert_eq!(forward.len(), 4);
        assert!(forward[..2]
            .iter()
            .all(|operation| matches!(operation, ExactHostOperation::FirewallAllow(_))));
        assert!(forward[2..]
            .iter()
            .all(|operation| matches!(operation, ExactHostOperation::RouteAddBypass(_))));

        for failure_index in 0..forward.len() {
            let mut host = FaultHost::default().fail_at(failure_index, "rehydration forward");
            let before = host.state.clone();
            let failure = host_failure(EndpointTransitionExecutor::stage_authority_rehydration(
                &mut host, &plan,
            ));
            assert_eq!(failure.kind, HostTransactionKind::AuthorityRehydration);
            assert_eq!(failure.primary.operation, forward[failure_index]);
            assert_eq!(failure.primary.error, TestError("rehydration forward"));
            assert_eq!(failure.changed_prefix, forward[..failure_index]);
            assert!(failure.rollback_failures.is_empty());
            assert_eq!(host.state, before);

            let mut expected_calls = forward[..=failure_index].to_vec();
            expected_calls.extend(
                forward[..failure_index]
                    .iter()
                    .rev()
                    .map(|operation| operation.inverse()),
            );
            assert_eq!(host.calls, expected_calls);
        }
    }

    #[test]
    fn authority_rehydration_is_typed_addition_only_and_rollbackable() {
        let plan = authority_rehydration_plan();
        let mut host = FaultHost::default();
        let baseline = host.state.clone();
        let applied =
            EndpointTransitionExecutor::stage_authority_rehydration(&mut host, &plan).unwrap();
        assert_eq!(applied.kind(), HostTransactionKind::AuthorityRehydration);
        assert!(applied.publication().is_some());
        assert_eq!(
            applied.changed_operations().collect::<Vec<_>>(),
            plan_host_operations(&plan)
        );
        EndpointTransitionExecutor::rollback_applied(&mut host, applied).unwrap();
        assert_eq!(host.state, baseline);

        let cleanup = cleanup_plan();
        let mut rejecting_host = FaultHost::owning(&[A, B, C]);
        assert!(matches!(
            invalid_plan(EndpointTransitionExecutor::stage_authority_rehydration(
                &mut rejecting_host,
                &cleanup,
            )),
            PlanRejection::OperationNotAllowed(ExactHostOperation::FirewallDeny(_))
        ));
        assert!(rejecting_host.calls.is_empty());

        let mut missing_publish = plan.clone();
        missing_publish.operations.pop();
        let mut missing_host = FaultHost::default();
        assert_eq!(
            invalid_plan(EndpointTransitionExecutor::stage_authority_rehydration(
                &mut missing_host,
                &missing_publish,
            )),
            PlanRejection::MissingPublishMarker
        );
        assert!(missing_host.calls.is_empty());
    }

    #[test]
    fn authority_rehydration_accepts_publish_only_tombstone_and_exact_noop() {
        let publish_only = authority_rehydration_publish_only_plan();
        let mut host = FaultHost::owning(&[A, B]);
        let receipt =
            EndpointTransitionExecutor::stage_authority_rehydration(&mut host, &publish_only)
                .unwrap();
        assert_eq!(receipt.kind(), HostTransactionKind::AuthorityRehydration);
        assert!(receipt.publication().is_some());
        assert!(receipt.operations().is_empty());
        assert!(host.calls.is_empty());

        let empty = empty_authority_rehydration_plan();
        let receipt =
            EndpointTransitionExecutor::stage_authority_rehydration(&mut host, &empty).unwrap();
        assert_eq!(receipt.kind(), HostTransactionKind::AuthorityRehydration);
        assert!(receipt.publication().is_none());
        assert!(receipt.operations().is_empty());
        assert!(host.calls.is_empty());
    }

    #[test]
    fn cleanup_failure_at_every_prefix_compensates_exact_reverse() {
        let plan = cleanup_plan();
        let forward = plan_host_operations(&plan);
        assert_eq!(forward.len(), 4);

        for failure_index in 0..forward.len() {
            let mut host = FaultHost::owning(&[A, B, C]).fail_at(failure_index, "forward");
            let before = host.state.clone();
            let failure = host_failure(EndpointTransitionExecutor::execute_retirement(
                &mut host, &plan,
            ));
            assert_eq!(failure.primary.operation, forward[failure_index]);
            assert_eq!(failure.changed_prefix, forward[..failure_index]);
            assert!(failure.rollback_failures.is_empty());
            assert_eq!(host.state, before);

            let mut expected_calls = forward[..=failure_index].to_vec();
            expected_calls.extend(
                forward[..failure_index]
                    .iter()
                    .rev()
                    .map(|operation| operation.inverse()),
            );
            assert_eq!(host.calls, expected_calls);
        }
    }

    #[test]
    fn already_exact_effects_are_never_compensated() {
        let plan = addition_plan();
        let mut host = FaultHost::owning(&[B]);
        host.fail_calls.insert(3, "last add");
        let before = host.state.clone();
        let failure = host_failure(EndpointTransitionExecutor::stage_observation(
            &mut host, &plan,
        ));
        assert_eq!(
            failure.changed_prefix,
            vec![ExactHostOperation::FirewallAllow(tuple(C))]
        );
        assert_eq!(
            host.calls,
            vec![
                ExactHostOperation::FirewallAllow(tuple(B)),
                ExactHostOperation::FirewallAllow(tuple(C)),
                ExactHostOperation::RouteAddBypass(B),
                ExactHostOperation::RouteAddBypass(C),
                ExactHostOperation::FirewallDeny(tuple(C)),
            ]
        );
        assert_eq!(host.state, before);

        let mut exact_host = FaultHost::owning(&[B, C]);
        let applied =
            EndpointTransitionExecutor::stage_observation(&mut exact_host, &plan).unwrap();
        assert!(!applied.changed_host_state());
        assert!(applied
            .operations()
            .iter()
            .all(|record| record.outcome == OwnedMutation::AlreadyExact));
        let calls_before_rollback = exact_host.calls.clone();
        EndpointTransitionExecutor::rollback_applied(&mut exact_host, applied).unwrap();
        assert_eq!(exact_host.calls, calls_before_rollback);

        let cleanup = cleanup_plan();
        let mut already_absent = FaultHost::owning(&[C]);
        let receipt =
            EndpointTransitionExecutor::execute_retirement(&mut already_absent, &cleanup).unwrap();
        assert!(!receipt.changed_host_state());
        assert!(receipt
            .operations()
            .iter()
            .all(|record| record.outcome == OwnedMutation::AlreadyExact));
    }

    #[test]
    fn primary_and_all_rollback_failures_are_preserved() {
        let plan = addition_plan();
        let mut host = FaultHost::default()
            .fail_at(2, "primary route failure")
            .fail_at(3, "rollback C failure")
            .fail_at(4, "rollback B failure");
        let failure = host_failure(EndpointTransitionExecutor::stage_observation(
            &mut host, &plan,
        ));
        assert_eq!(
            failure.primary,
            HostOperationFailure {
                operation: ExactHostOperation::RouteAddBypass(B),
                error: TestError("primary route failure"),
            }
        );
        assert_eq!(
            failure
                .rollback_failures
                .iter()
                .map(|failure| (failure.operation, failure.error.clone()))
                .collect::<Vec<_>>(),
            vec![
                (
                    ExactHostOperation::FirewallDeny(tuple(C)),
                    TestError("rollback C failure"),
                ),
                (
                    ExactHostOperation::FirewallDeny(tuple(B)),
                    TestError("rollback B failure"),
                ),
            ]
        );
        assert_eq!(host.state.firewall, BTreeSet::from([tuple(B), tuple(C)]));
        assert!(host.state.routes.is_empty());
    }

    #[test]
    fn successful_receipt_can_rollback_after_model_commit_failure() {
        let plan = addition_plan();
        let mut host = FaultHost::default();
        let baseline = host.state.clone();
        let applied = EndpointTransitionExecutor::stage_observation(&mut host, &plan).unwrap();
        let forward = plan_host_operations(&plan);
        assert_eq!(applied.changed_operations().collect::<Vec<_>>(), forward);
        EndpointTransitionExecutor::rollback_applied(&mut host, applied).unwrap();
        assert_eq!(host.state, baseline);

        let mut expected = forward.clone();
        expected.extend(forward.iter().rev().map(|operation| operation.inverse()));
        assert_eq!(host.calls, expected);
    }

    #[test]
    fn explicit_post_stage_rollback_collects_every_failure() {
        let plan = addition_plan();
        let mut host = FaultHost::default();
        let applied = EndpointTransitionExecutor::stage_observation(&mut host, &plan).unwrap();
        host.fail_calls.insert(4, "remove route C");
        host.fail_calls.insert(6, "deny C");
        let rollback = EndpointTransitionExecutor::rollback_applied(&mut host, applied)
            .expect_err("rollback failures must remain visible");
        assert_eq!(rollback.kind, HostTransactionKind::ObservationStage);
        assert_eq!(
            rollback
                .failures
                .iter()
                .map(|failure| (failure.operation, failure.error.clone()))
                .collect::<Vec<_>>(),
            vec![
                (
                    ExactHostOperation::RouteRemoveBypass(C),
                    TestError("remove route C"),
                ),
                (
                    ExactHostOperation::FirewallDeny(tuple(C)),
                    TestError("deny C"),
                ),
            ]
        );
        assert_eq!(host.calls.len(), 8, "all four inverses must be attempted");
    }

    #[test]
    fn publish_is_a_non_host_marker_and_model_is_not_committed() {
        let mut coordinator = coordinator(&[A], &[A, B]);
        let before = coordinator.snapshot();
        let prepared = prepare_positive(&mut coordinator, &[B]);
        let marker = prepared
            .plan()
            .operations
            .iter()
            .find_map(|operation| match operation {
                TransitionOperation::PublishSnapshot { from, to } => Some(SnapshotPublication {
                    from: *from,
                    to: *to,
                }),
                _ => None,
            })
            .unwrap();
        let mut host = FaultHost::default();
        let applied =
            EndpointTransitionExecutor::stage_observation(&mut host, prepared.plan()).unwrap();
        assert_eq!(applied.publication(), Some(marker));
        assert_eq!(host.calls, plan_host_operations(prepared.plan()));
        assert_eq!(coordinator.snapshot().as_ref(), before.as_ref());
        coordinator.abort_observation(prepared).unwrap();

        let publish_only = publish_only_plan();
        let mut host = FaultHost::default();
        let receipt =
            EndpointTransitionExecutor::stage_observation(&mut host, &publish_only).unwrap();
        assert!(receipt.publication().is_some());
        assert!(receipt.operations().is_empty());
        assert!(host.calls.is_empty());

        let empty = empty_observation_plan();
        let receipt = EndpointTransitionExecutor::stage_observation(&mut host, &empty).unwrap();
        assert!(receipt.publication().is_none());
        assert!(receipt.operations().is_empty());
    }

    #[test]
    fn release_and_retirement_share_strict_cleanup_shape() {
        let plan = cleanup_plan();
        let expected = plan_host_operations(&plan);
        let mut release_host = FaultHost::owning(&[A, B, C]);
        let release =
            EndpointTransitionExecutor::execute_release(&mut release_host, &plan).unwrap();
        assert_eq!(release.kind(), HostTransactionKind::LeaseRelease);
        assert_eq!(release_host.calls, expected);

        let empty = empty_release_plan();
        let mut empty_host = FaultHost::owning(&[A]);
        let receipt = EndpointTransitionExecutor::execute_release(&mut empty_host, &empty).unwrap();
        assert!(receipt.operations().is_empty());
        assert!(empty_host.calls.is_empty());
    }

    #[test]
    fn malformed_publish_and_mixed_plans_are_rejected_before_host_calls() {
        let valid = addition_plan();
        let marker = valid.operations.last().unwrap().clone();

        let mut multiple = valid.clone();
        multiple.operations.push(marker.clone());
        let mut host = FaultHost::default();
        assert_eq!(
            invalid_plan(EndpointTransitionExecutor::stage_observation(
                &mut host, &multiple,
            )),
            PlanRejection::MultiplePublishMarkers
        );

        let mut not_final = valid.clone();
        let last = not_final.operations.len() - 1;
        not_final.operations.swap(last, last - 1);
        assert_eq!(
            invalid_plan(EndpointTransitionExecutor::stage_observation(
                &mut host, &not_final,
            )),
            PlanRejection::PublishNotFinal
        );

        let mut missing = valid.clone();
        missing.operations.pop();
        assert_eq!(
            invalid_plan(EndpointTransitionExecutor::stage_observation(
                &mut host, &missing,
            )),
            PlanRejection::MissingPublishMarker
        );

        let mut nonadvancing = valid.clone();
        if let TransitionOperation::PublishSnapshot { from, to } =
            nonadvancing.operations.last_mut().unwrap()
        {
            *from = *to;
        }
        assert!(matches!(
            invalid_plan(EndpointTransitionExecutor::stage_observation(
                &mut host,
                &nonadvancing,
            )),
            PlanRejection::NonAdvancingPublish { .. }
        ));

        let mut wrong_target = valid.clone();
        if let TransitionOperation::PublishSnapshot { to, .. } =
            wrong_target.operations.last_mut().unwrap()
        {
            *to += 1;
        }
        assert!(matches!(
            invalid_plan(EndpointTransitionExecutor::stage_observation(
                &mut host,
                &wrong_target,
            )),
            PlanRejection::PublishTargetMismatch { .. }
        ));

        let mut mixed = valid.clone();
        mixed.operations.insert(
            mixed.operations.len() - 1,
            TransitionOperation::Firewall(FirewallOperation::Deny(tuple(A))),
        );
        assert!(matches!(
            invalid_plan(EndpointTransitionExecutor::stage_observation(
                &mut host, &mixed,
            )),
            PlanRejection::OperationNotAllowed(ExactHostOperation::FirewallDeny(_))
        ));

        let publish_only = publish_only_plan();
        assert_eq!(
            invalid_plan(EndpointTransitionExecutor::execute_retirement(
                &mut host,
                &publish_only,
            )),
            PlanRejection::PublishForbidden
        );
        assert!(host.calls.is_empty());
    }

    #[test]
    fn unsafe_duplicate_and_unpaired_operations_never_reach_host() {
        let valid = addition_plan();
        let marker = valid.operations.last().unwrap().clone();
        let forward = valid.operations[..valid.operations.len() - 1].to_vec();
        let mut host = FaultHost::default();

        let mut unsafe_observation = valid.clone();
        unsafe_observation.operations = vec![
            forward[0].clone(),
            forward[2].clone(),
            forward[1].clone(),
            forward[3].clone(),
            marker.clone(),
        ];
        assert_eq!(
            invalid_plan(EndpointTransitionExecutor::stage_observation(
                &mut host,
                &unsafe_observation,
            )),
            PlanRejection::UnsafeHostOrder
        );

        let mut duplicate = valid.clone();
        duplicate.operations.insert(1, forward[0].clone());
        assert!(matches!(
            invalid_plan(EndpointTransitionExecutor::stage_observation(
                &mut host, &duplicate,
            )),
            PlanRejection::DuplicateHostOperation(_)
        ));

        let mut unpaired = valid.clone();
        unpaired.operations.remove(0);
        assert_eq!(
            invalid_plan(EndpointTransitionExecutor::stage_observation(
                &mut host, &unpaired,
            )),
            PlanRejection::RouteWithoutMatchingFirewall(B)
        );

        let cleanup = cleanup_plan();
        let cleanup_forward = cleanup.operations.clone();
        let mut unsafe_cleanup = cleanup.clone();
        unsafe_cleanup.operations = vec![
            cleanup_forward[0].clone(),
            cleanup_forward[2].clone(),
            cleanup_forward[1].clone(),
            cleanup_forward[3].clone(),
        ];
        assert_eq!(
            invalid_plan(EndpointTransitionExecutor::execute_retirement(
                &mut host,
                &unsafe_cleanup,
            )),
            PlanRejection::UnsafeHostOrder
        );

        assert!(host.calls.is_empty());
    }

    #[test]
    fn successful_forward_order_is_always_fail_closed() {
        let observation = addition_plan();
        let mut host = FaultHost::default();
        EndpointTransitionExecutor::stage_observation(&mut host, &observation).unwrap();
        let first_route = host
            .calls
            .iter()
            .position(|operation| matches!(operation, ExactHostOperation::RouteAddBypass(_)))
            .unwrap();
        assert!(host.calls[..first_route]
            .iter()
            .all(|operation| matches!(operation, ExactHostOperation::FirewallAllow(_))));
        assert!(host.calls[first_route..]
            .iter()
            .all(|operation| matches!(operation, ExactHostOperation::RouteAddBypass(_))));

        let cleanup = cleanup_plan();
        let mut host = FaultHost::owning(&[A, B, C]);
        EndpointTransitionExecutor::execute_retirement(&mut host, &cleanup).unwrap();
        let first_route = host
            .calls
            .iter()
            .position(|operation| matches!(operation, ExactHostOperation::RouteRemoveBypass(_)))
            .unwrap();
        assert!(host.calls[..first_route]
            .iter()
            .all(|operation| matches!(operation, ExactHostOperation::FirewallDeny(_))));
        assert!(host.calls[first_route..]
            .iter()
            .all(|operation| matches!(operation, ExactHostOperation::RouteRemoveBypass(_))));
    }
}
