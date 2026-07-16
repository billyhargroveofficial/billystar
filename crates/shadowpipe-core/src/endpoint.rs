//! Pure live-endpoint coordination model.
//!
//! This module deliberately performs no DNS, route, or firewall I/O.  It turns
//! generation-stamped DNS observations into an ordered, typed transition plan
//! that a privileged runtime can execute transactionally:
//!
//! ```text
//! ADD:    firewall allow -> bypass route add -> snapshot publish -> dial
//! REMOVE: snapshot depublish -> lease quiescence -> firewall deny -> route delete
//! ```
//!
//! DNS is only a locator.  A response may select addresses from a pre-verified,
//! signed authority but can never expand that authority.  Signature parsing and
//! verification belong to the control plane; [`VerifiedIpv4Authority`] is the
//! narrow hand-off type for a manifest that has already passed that check.

use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

const MIN_TTL_SECS: u32 = 5;
const MAX_TTL_SECS: u32 = 3_600;
const DEFAULT_NEGATIVE_TTL_SECS: u32 = 30;
const MAX_NEGATIVE_TTL_SECS: u32 = 300;
const RETRY_BASE_MS: u64 = 1_000;
const RETRY_CAP_MS: u64 = 30_000;

/// Stable identity of a configured endpoint.  It identifies authentication
/// material as well as a hostname, so two descriptors that share an IP never
/// accidentally share a REALITY key or server fingerprint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalEndpointId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CarrierProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CarrierTuple {
    pub address: SocketAddrV4,
    pub protocol: CarrierProtocol,
}

/// Stable address key inside one logical/authenticated endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CandidateKey {
    pub logical: LogicalEndpointId,
    pub ip: Ipv4Addr,
}

/// Opaque reference to authentication configuration owned by the caller.
/// The coordinator never interprets or logs those bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthConfigRef(pub u32);

/// An IPv4 set obtained from a manifest whose signature, expiry, audience and
/// anti-rollback generation were verified before construction.
///
/// This type does not itself implement signature verification.  The explicit
/// `from_preverified_manifest` name prevents DNS data from being mistaken for
/// authority at the call site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedIpv4Authority {
    manifest_generation: u64,
    allowed: BTreeSet<Ipv4Addr>,
}

impl VerifiedIpv4Authority {
    pub fn from_preverified_manifest(
        manifest_generation: u64,
        allowed: impl IntoIterator<Item = Ipv4Addr>,
    ) -> Result<Self> {
        let allowed: BTreeSet<_> = allowed.into_iter().collect();
        anyhow::ensure!(!allowed.is_empty(), "verified endpoint authority is empty");
        Ok(Self {
            manifest_generation,
            allowed,
        })
    }

    pub fn manifest_generation(&self) -> u64 {
        self.manifest_generation
    }

    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        self.allowed.contains(ip)
    }

    pub fn addresses(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.allowed.iter().copied()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AddressPolicy {
    /// Lab-only escape hatch.  Production callers should keep this false.
    pub allow_private: bool,
}

impl AddressPolicy {
    fn permits(self, ip: Ipv4Addr) -> bool {
        if ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_link_local()
            || ip.is_multicast()
            || ip.is_broadcast()
        {
            return false;
        }
        self.allow_private || !ip.is_private()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalEndpoint {
    pub id: LogicalEndpointId,
    pub hostname: String,
    pub port: u16,
    pub protocol: CarrierProtocol,
    pub auth: AuthConfigRef,
    pub authority: VerifiedIpv4Authority,
    pub address_policy: AddressPolicy,
}

impl LogicalEndpoint {
    fn tuple(&self, ip: Ipv4Addr) -> CarrierTuple {
        CarrierTuple {
            address: SocketAddrV4::new(ip, self.port),
            protocol: self.protocol,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeedCandidate {
    pub logical: LogicalEndpointId,
    pub ip: Ipv4Addr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressRecord {
    pub ip: Ipv4Addr,
    pub ttl_secs: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolutionObservation {
    Positive(Vec<AddressRecord>),
    NxDomain { negative_ttl_secs: Option<u32> },
    NoData { negative_ttl_secs: Option<u32> },
    TransientFailure,
}

impl From<crate::endpoint_dns::ParsedDnsAnswer> for ResolutionObservation {
    fn from(answer: crate::endpoint_dns::ParsedDnsAnswer) -> Self {
        match answer {
            crate::endpoint_dns::ParsedDnsAnswer::Positive(records) => Self::Positive(
                records
                    .into_iter()
                    .map(|record| AddressRecord {
                        ip: record.ip,
                        ttl_secs: record.ttl_secs,
                    })
                    .collect(),
            ),
            crate::endpoint_dns::ParsedDnsAnswer::NxDomain { negative_ttl_secs } => {
                Self::NxDomain {
                    negative_ttl_secs: Some(negative_ttl_secs),
                }
            }
            crate::endpoint_dns::ParsedDnsAnswer::NoData { negative_ttl_secs } => Self::NoData {
                negative_ttl_secs: Some(negative_ttl_secs),
            },
            crate::endpoint_dns::ParsedDnsAnswer::TransientRcode { .. } => Self::TransientFailure,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryStamp {
    pub logical: LogicalEndpointId,
    pub sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DialCandidate {
    pub key: CandidateKey,
    pub address: SocketAddrV4,
    pub protocol: CarrierProtocol,
    pub auth: AuthConfigRef,
    pub authority_generation: u64,
}

/// Immutable view consumed by the dialer.  An address cannot become dialable
/// until the corresponding allow and bypass-add operations precede Publish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DialSnapshot {
    pub generation: u64,
    pub candidates: Vec<DialCandidate>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallOperation {
    Allow(CarrierTuple),
    Deny(CarrierTuple),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteOperation {
    AddBypass(Ipv4Addr),
    RemoveBypass(Ipv4Addr),
}

/// Typed ordering makes an unsafe `route add -> firewall allow` or
/// `route remove -> firewall deny` plan observable in pure tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransitionOperation {
    Firewall(FirewallOperation),
    Route(RouteOperation),
    PublishSnapshot { from: u64, to: u64 },
}

impl TransitionOperation {
    /// Exact model-level inverse for rollback of a successfully executed host
    /// prefix. Snapshot publication is a coordinator commit marker, not a host
    /// command, and therefore has no inverse here.
    pub fn host_inverse(&self) -> Option<Self> {
        match self {
            Self::Firewall(FirewallOperation::Allow(tuple)) => {
                Some(Self::Firewall(FirewallOperation::Deny(*tuple)))
            }
            Self::Firewall(FirewallOperation::Deny(tuple)) => {
                Some(Self::Firewall(FirewallOperation::Allow(*tuple)))
            }
            Self::Route(RouteOperation::AddBypass(ip)) => {
                Some(Self::Route(RouteOperation::RemoveBypass(*ip)))
            }
            Self::Route(RouteOperation::RemoveBypass(ip)) => {
                Some(Self::Route(RouteOperation::AddBypass(*ip)))
            }
            Self::PublishSnapshot { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionPlan {
    pub operations: Vec<TransitionOperation>,
    // Kept private so an integration layer cannot hand projected candidates to
    // a dialer before `commit_observation` publishes them.
    snapshot: Arc<DialSnapshot>,
}

impl TransitionPlan {
    fn unchanged(snapshot: Arc<DialSnapshot>) -> Self {
        Self {
            operations: Vec::new(),
            snapshot,
        }
    }

    pub fn target_generation(&self) -> u64 {
        self.snapshot.generation
    }

    /// Defensive validator for an integration layer before it executes host
    /// mutations.  It accepts plans without a publish (lease-only retirement).
    pub fn validate_order(&self) -> Result<()> {
        let publish = self
            .operations
            .iter()
            .position(|op| matches!(op, TransitionOperation::PublishSnapshot { .. }));
        for (index, operation) in self.operations.iter().enumerate() {
            match operation {
                TransitionOperation::Firewall(FirewallOperation::Allow(_)) => {
                    anyhow::ensure!(publish.is_some_and(|p| index < p), "allow after publish")
                }
                TransitionOperation::Route(RouteOperation::AddBypass(_)) => {
                    anyhow::ensure!(
                        publish.is_some_and(|p| index < p),
                        "route add after publish"
                    )
                }
                TransitionOperation::Firewall(FirewallOperation::Deny(_))
                | TransitionOperation::Route(RouteOperation::RemoveBypass(_)) => {
                    if let Some(publish) = publish {
                        anyhow::ensure!(index > publish, "removal before publish");
                    }
                }
                TransitionOperation::PublishSnapshot { .. } => {}
            }
        }

        let mut seen_route_add = false;
        let mut seen_route_remove = false;
        for operation in &self.operations {
            match operation {
                TransitionOperation::Route(RouteOperation::AddBypass(_)) => {
                    seen_route_add = true;
                }
                TransitionOperation::Firewall(FirewallOperation::Allow(_)) => {
                    anyhow::ensure!(!seen_route_add, "firewall allow must precede route adds");
                }
                TransitionOperation::Route(RouteOperation::RemoveBypass(_)) => {
                    seen_route_remove = true;
                }
                TransitionOperation::Firewall(FirewallOperation::Deny(_)) => {
                    anyhow::ensure!(
                        !seen_route_remove,
                        "firewall deny must precede route removal"
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationDisposition {
    Applied,
    RetainedNegative,
    RetainedEmptyPositive,
    RejectedOutsideAuthority(Vec<Ipv4Addr>),
    RejectedAddressPolicy(Vec<Ipv4Addr>),
    IgnoredOutOfOrder,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationResult {
    pub disposition: ObservationDisposition,
    pub plan: TransitionPlan,
    pub next_refresh_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointLease {
    id: u64,
    pub key: CandidateKey,
}

/// Two-phase DNS state transition.  Creating this value never changes the live
/// coordinator.  The integration layer must transactionally execute every host
/// addition before the `PublishSnapshot` marker, then call
/// [`EndpointCoordinator::commit_observation`].  On any staging error it must
/// roll back the applied host prefix and call `abort_observation`.
pub struct PreparedObservation {
    base_revision: u64,
    projected: Box<EndpointCoordinator>,
    result: ObservationResult,
}

impl PreparedObservation {
    pub fn result(&self) -> &ObservationResult {
        &self.result
    }

    pub fn plan(&self) -> &TransitionPlan {
        &self.result.plan
    }
}

/// Result of restoring every address in the coordinator's immutable,
/// pre-verified authority to the dialable snapshot.
///
/// No caller-supplied address participates in this transition.  The revived
/// keys are derived exclusively from the [`VerifiedIpv4Authority`] values held
/// inside the coordinator, so an unavailable locator cannot expand egress
/// authority while a carrier is down.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRehydrationResult {
    revived_candidates: Vec<CandidateKey>,
    plan: TransitionPlan,
}

impl AuthorityRehydrationResult {
    pub fn revived_candidates(&self) -> &[CandidateKey] {
        &self.revived_candidates
    }

    pub fn plan(&self) -> &TransitionPlan {
        &self.plan
    }

    pub fn changed_snapshot(&self) -> bool {
        !self.revived_candidates.is_empty()
    }
}

/// Two-phase, monotonic recovery of the complete signed address authority.
///
/// Preparing this value changes neither the live snapshot nor lease counts.
/// A privileged integration must first execute [`Self::plan`] in its typed
/// authority-rehydration transaction and only then commit this projection.
pub struct PreparedAuthorityRehydration {
    base_revision: u64,
    projected: Box<EndpointCoordinator>,
    result: AuthorityRehydrationResult,
}

impl PreparedAuthorityRehydration {
    pub fn result(&self) -> &AuthorityRehydrationResult {
        &self.result
    }

    pub fn revived_candidates(&self) -> &[CandidateKey] {
        self.result.revived_candidates()
    }

    pub fn plan(&self) -> &TransitionPlan {
        self.result.plan()
    }
}

/// Two-phase lease release.  A retiring candidate remains owned by the live
/// model until deny/remove host operations succeed and this transaction commits.
pub struct PreparedLeaseRelease {
    base_revision: u64,
    projected: Box<EndpointCoordinator>,
    plan: TransitionPlan,
}

impl PreparedLeaseRelease {
    pub fn plan(&self) -> &TransitionPlan {
        &self.plan
    }
}

/// Two-phase cleanup for DNS-depublished candidates that have no live leases.
/// Observation commit intentionally leaves these tombstones authorized until a
/// separate deny-before-route-remove transaction succeeds.
pub struct PreparedRetirement {
    base_revision: u64,
    projected: Box<EndpointCoordinator>,
    plan: TransitionPlan,
}

impl PreparedRetirement {
    pub fn plan(&self) -> &TransitionPlan {
        &self.plan
    }
}

#[derive(Clone, Debug)]
struct CandidateState {
    valid_until_ms: Option<u64>,
    dialable: bool,
    leases: u32,
}

#[derive(Clone, Debug)]
struct LogicalState {
    spec: LogicalEndpoint,
    latest_query_sequence: u64,
    last_applied_sequence: u64,
    failure_streak: u32,
    next_refresh_at_ms: u64,
}

/// Single-owner coordinator.  It intentionally contains no mutex: resolver
/// awaits and privileged commands must live outside this model, with one event
/// loop applying their results.
#[derive(Clone)]
pub struct EndpointCoordinator {
    revision: u64,
    logical: BTreeMap<LogicalEndpointId, LogicalState>,
    candidates: BTreeMap<CandidateKey, CandidateState>,
    leases: BTreeMap<u64, CandidateKey>,
    next_lease_id: u64,
    snapshot: Arc<DialSnapshot>,
}

impl EndpointCoordinator {
    pub fn new(
        endpoints: impl IntoIterator<Item = LogicalEndpoint>,
        seeds: impl IntoIterator<Item = SeedCandidate>,
        now_ms: u64,
    ) -> Result<Self> {
        let mut logical = BTreeMap::new();
        for spec in endpoints {
            validate_hostname(&spec.hostname)?;
            anyhow::ensure!(spec.port != 0, "endpoint port must be non-zero");
            for ip in spec.authority.addresses() {
                anyhow::ensure!(
                    spec.address_policy.permits(ip),
                    "authority for {:?} contains address rejected by policy: {ip}",
                    spec.id
                );
            }
            let id = spec.id;
            anyhow::ensure!(
                logical
                    .insert(
                        id,
                        LogicalState {
                            spec,
                            latest_query_sequence: 0,
                            last_applied_sequence: 0,
                            failure_streak: 0,
                            // Bootstrap resolution has no observable TTL.  Ask
                            // again soon, through the established tunnel.
                            next_refresh_at_ms: now_ms.saturating_add(5_000),
                        },
                    )
                    .is_none(),
                "duplicate logical endpoint id {:?}",
                id
            );
        }
        anyhow::ensure!(
            !logical.is_empty(),
            "endpoint coordinator has no logical endpoints"
        );

        let mut candidates = BTreeMap::new();
        for seed in seeds {
            let state = logical
                .get(&seed.logical)
                .with_context(|| format!("seed references unknown endpoint {:?}", seed.logical))?;
            anyhow::ensure!(
                state.spec.authority.contains(&seed.ip),
                "seed {} is outside verified authority for {:?}",
                seed.ip,
                seed.logical
            );
            anyhow::ensure!(
                state.spec.address_policy.permits(seed.ip),
                "seed {} is rejected by endpoint address policy",
                seed.ip
            );
            candidates.insert(
                CandidateKey {
                    logical: seed.logical,
                    ip: seed.ip,
                },
                CandidateState {
                    valid_until_ms: None,
                    dialable: true,
                    leases: 0,
                },
            );
        }
        anyhow::ensure!(
            !candidates.is_empty(),
            "endpoint coordinator cannot publish an empty seed snapshot"
        );

        let snapshot = Arc::new(build_snapshot(1, &logical, &candidates));
        debug_assert!(!snapshot.candidates.is_empty());
        Ok(Self {
            revision: 1,
            logical,
            candidates,
            leases: BTreeMap::new(),
            next_lease_id: 1,
            snapshot,
        })
    }

    pub fn snapshot(&self) -> Arc<DialSnapshot> {
        Arc::clone(&self.snapshot)
    }

    pub fn next_refresh_at_ms(&self, logical: LogicalEndpointId) -> Result<u64> {
        self.logical
            .get(&logical)
            .map(|state| state.next_refresh_at_ms)
            .with_context(|| format!("unknown logical endpoint {:?}", logical))
    }

    pub fn begin_query(&mut self, logical: LogicalEndpointId) -> Result<QueryStamp> {
        let next_revision = self
            .revision
            .checked_add(1)
            .context("endpoint coordinator revision exhausted")?;
        let state = self
            .logical
            .get_mut(&logical)
            .with_context(|| format!("unknown logical endpoint {:?}", logical))?;
        state.latest_query_sequence = state
            .latest_query_sequence
            .checked_add(1)
            .context("endpoint DNS query sequence exhausted")?;
        let sequence = state.latest_query_sequence;
        self.revision = next_revision;
        Ok(QueryStamp { logical, sequence })
    }

    /// Project an observation without changing the live snapshot, candidates,
    /// refresh schedule, or refcounts. `entropy` is caller-supplied randomness
    /// so TTL jitter and retry scheduling remain reproducible in tests.
    pub fn prepare_observation(
        &self,
        stamp: QueryStamp,
        observation: ResolutionObservation,
        now_ms: u64,
        entropy: u64,
    ) -> Result<PreparedObservation> {
        let mut projected = self.clone();
        let result = projected.apply_observation(stamp, observation, now_ms, entropy)?;
        projected.revision = self
            .revision
            .checked_add(1)
            .context("endpoint coordinator revision exhausted")?;
        Ok(PreparedObservation {
            base_revision: self.revision,
            projected: Box::new(projected),
            result,
        })
    }

    /// Publish a prepared observation after its firewall-allow and route-add
    /// prefix has completed successfully.  A concurrent query/lease mutation
    /// makes the transaction stale rather than merging incompatible refcounts.
    pub fn commit_observation(
        &mut self,
        prepared: PreparedObservation,
    ) -> Result<ObservationResult> {
        anyhow::ensure!(
            self.revision == prepared.base_revision,
            "stale prepared observation: coordinator revision changed"
        );
        let result = prepared.result;
        *self = *prepared.projected;
        Ok(result)
    }

    /// Abort is an exact no-op on live model state.  The caller is responsible
    /// for reversing any host operations already executed from the plan prefix.
    pub fn abort_observation(&self, prepared: PreparedObservation) -> Result<()> {
        anyhow::ensure!(
            self.revision == prepared.base_revision,
            "prepared observation was already made stale by another transition"
        );
        drop(prepared);
        Ok(())
    }

    /// Project restoration of every address in the immutable verified
    /// authority without accepting an address from DNS, configuration, or the
    /// caller.
    ///
    /// This is the fail-closed bootstrap for a carrier outage after DNS has
    /// narrowed the live snapshot.  Since DNS is only permitted to choose a
    /// subset of this same authority, restoring the full signed set provides
    /// every candidate a direct control resolver could return without opening
    /// a separate underlay DNS channel.
    ///
    /// The transition is monotonic: it may add exact firewall tuples and host
    /// routes before one final snapshot publication, but it can never deny a
    /// tuple or remove a route.  Existing candidate leases are preserved.  If
    /// the full authority is already dialable, the prepared transition is an
    /// exact no-op and does not consume a coordinator revision or snapshot
    /// generation.
    pub fn prepare_authority_rehydration(&self) -> Result<PreparedAuthorityRehydration> {
        // Materialize keys only from the coordinator's private verified
        // authority.  Deliberately accepting no address parameter is the
        // capability boundary that keeps DNS or an integration layer from
        // expanding the signed egress universe.
        let authority_keys: Vec<CandidateKey> = self
            .logical
            .iter()
            .flat_map(|(logical, state)| {
                state.spec.authority.addresses().map(|ip| CandidateKey {
                    logical: *logical,
                    ip,
                })
            })
            .collect();

        let mut projected = self.clone();
        let old_candidates = projected.candidates.clone();
        let old_snapshot = projected.snapshot();
        let mut revived_candidates = Vec::new();

        for key in authority_keys {
            match projected.candidates.get_mut(&key) {
                Some(candidate) if !candidate.dialable => {
                    // A leased DNS-depublished tombstone still owns its exact
                    // host access.  Rehydration republishes it without
                    // disturbing the refcount or generating duplicate host
                    // mutations.
                    candidate.dialable = true;
                    candidate.valid_until_ms = None;
                    revived_candidates.push(key);
                }
                Some(_) => {}
                None => {
                    projected.candidates.insert(
                        key,
                        CandidateState {
                            valid_until_ms: None,
                            dialable: true,
                            leases: 0,
                        },
                    );
                    revived_candidates.push(key);
                }
            }
        }

        // BTree iteration above already yields stable logical/IP order; keep
        // the explicit sort as a defensive invariant if authority storage ever
        // changes representation.
        revived_candidates.sort_unstable();

        if revived_candidates.is_empty() {
            return Ok(PreparedAuthorityRehydration {
                base_revision: self.revision,
                projected: Box::new(projected),
                result: AuthorityRehydrationResult {
                    revived_candidates,
                    plan: TransitionPlan::unchanged(old_snapshot),
                },
            });
        }

        let candidate_view = build_snapshot(
            old_snapshot.generation,
            &projected.logical,
            &projected.candidates,
        );
        anyhow::ensure!(
            candidate_view.candidates != old_snapshot.candidates,
            "authority rehydration revived candidates without changing the dial snapshot"
        );
        let next_generation = old_snapshot
            .generation
            .checked_add(1)
            .context("endpoint snapshot generation exhausted during authority rehydration")?;
        let next_snapshot = Arc::new(DialSnapshot {
            generation: next_generation,
            candidates: candidate_view.candidates,
        });
        let plan = transition_plan(
            &projected.logical,
            &old_candidates,
            &projected.candidates,
            old_snapshot.generation,
            Arc::clone(&next_snapshot),
            true,
        );
        anyhow::ensure!(
            plan.operations.iter().all(|operation| !matches!(
                operation,
                TransitionOperation::Firewall(FirewallOperation::Deny(_))
                    | TransitionOperation::Route(RouteOperation::RemoveBypass(_))
            )),
            "authority rehydration constructed a non-monotonic host removal"
        );
        plan.validate_order()?;

        projected.snapshot = next_snapshot;
        projected.revision = self
            .revision
            .checked_add(1)
            .context("endpoint coordinator revision exhausted during authority rehydration")?;
        Ok(PreparedAuthorityRehydration {
            base_revision: self.revision,
            projected: Box::new(projected),
            result: AuthorityRehydrationResult {
                revived_candidates,
                plan,
            },
        })
    }

    /// Publish a prepared full-authority snapshot after its exact host prefix
    /// has completed.  Any intervening query, lease, or cleanup transition
    /// makes the projection stale instead of merging incompatible refcounts.
    pub fn commit_authority_rehydration(
        &mut self,
        prepared: PreparedAuthorityRehydration,
    ) -> Result<AuthorityRehydrationResult> {
        anyhow::ensure!(
            self.revision == prepared.base_revision,
            "stale prepared authority rehydration: coordinator revision changed"
        );
        let PreparedAuthorityRehydration {
            projected, result, ..
        } = prepared;
        *self = *projected;
        Ok(result)
    }

    /// Abort is an exact no-op on the live snapshot, tombstones, and leases.
    /// A caller that already executed part of the host prefix must compensate
    /// that prefix separately before dropping the projection.
    pub fn abort_authority_rehydration(
        &self,
        prepared: PreparedAuthorityRehydration,
    ) -> Result<()> {
        anyhow::ensure!(
            self.revision == prepared.base_revision,
            "prepared authority rehydration was already made stale by another transition"
        );
        drop(prepared);
        Ok(())
    }

    #[cfg(test)]
    fn observe(
        &mut self,
        stamp: QueryStamp,
        observation: ResolutionObservation,
        now_ms: u64,
        entropy: u64,
    ) -> Result<ObservationResult> {
        let prepared = self.prepare_observation(stamp, observation, now_ms, entropy)?;
        self.commit_observation(prepared)
    }

    fn apply_observation(
        &mut self,
        stamp: QueryStamp,
        observation: ResolutionObservation,
        now_ms: u64,
        entropy: u64,
    ) -> Result<ObservationResult> {
        let state = self
            .logical
            .get(&stamp.logical)
            .with_context(|| format!("unknown logical endpoint {:?}", stamp.logical))?;
        if stamp.sequence != state.latest_query_sequence
            || stamp.sequence <= state.last_applied_sequence
        {
            let next_refresh_at_ms = self.next_refresh_at_ms(stamp.logical)?;
            return Ok(ObservationResult {
                disposition: ObservationDisposition::IgnoredOutOfOrder,
                plan: TransitionPlan::unchanged(self.snapshot()),
                next_refresh_at_ms,
            });
        }
        self.logical
            .get_mut(&stamp.logical)
            .expect("logical existence checked above")
            .last_applied_sequence = stamp.sequence;

        match observation {
            ResolutionObservation::Positive(records) if records.is_empty() => self
                .retain_with_negative_schedule(
                    stamp.logical,
                    now_ms,
                    entropy,
                    None,
                    ObservationDisposition::RetainedEmptyPositive,
                ),
            ResolutionObservation::Positive(records) => {
                self.apply_positive(stamp.logical, records, now_ms, entropy)
            }
            ResolutionObservation::NxDomain { negative_ttl_secs }
            | ResolutionObservation::NoData { negative_ttl_secs } => self
                .retain_with_negative_schedule(
                    stamp.logical,
                    now_ms,
                    entropy,
                    negative_ttl_secs,
                    ObservationDisposition::RetainedNegative,
                ),
            ResolutionObservation::TransientFailure => {
                let state = self
                    .logical
                    .get_mut(&stamp.logical)
                    .expect("logical existence checked above");
                state.failure_streak = state.failure_streak.saturating_add(1);
                let delay = retry_delay_ms(state.failure_streak, entropy);
                state.next_refresh_at_ms = now_ms.saturating_add(delay);
                let next_refresh_at_ms = state.next_refresh_at_ms;
                Ok(ObservationResult {
                    disposition: ObservationDisposition::RetainedNegative,
                    plan: TransitionPlan::unchanged(self.snapshot()),
                    next_refresh_at_ms,
                })
            }
        }
    }

    fn retain_with_negative_schedule(
        &mut self,
        logical: LogicalEndpointId,
        now_ms: u64,
        entropy: u64,
        ttl: Option<u32>,
        disposition: ObservationDisposition,
    ) -> Result<ObservationResult> {
        let ttl = ttl
            .unwrap_or(DEFAULT_NEGATIVE_TTL_SECS)
            .clamp(MIN_TTL_SECS, MAX_NEGATIVE_TTL_SECS);
        let delay = jittered_ttl_ms(ttl, entropy);
        let state = self
            .logical
            .get_mut(&logical)
            .expect("logical existence checked by caller");
        state.failure_streak = 0;
        state.next_refresh_at_ms = now_ms.saturating_add(delay);
        let next_refresh_at_ms = state.next_refresh_at_ms;
        Ok(ObservationResult {
            disposition,
            plan: TransitionPlan::unchanged(self.snapshot()),
            next_refresh_at_ms,
        })
    }

    fn apply_positive(
        &mut self,
        logical_id: LogicalEndpointId,
        records: Vec<AddressRecord>,
        now_ms: u64,
        entropy: u64,
    ) -> Result<ObservationResult> {
        let spec = &self
            .logical
            .get(&logical_id)
            .expect("logical existence checked by caller")
            .spec;

        let mut dedup = BTreeMap::<Ipv4Addr, u32>::new();
        for record in records {
            dedup
                .entry(record.ip)
                .and_modify(|ttl| *ttl = (*ttl).min(record.ttl_secs))
                .or_insert(record.ttl_secs);
        }
        let outside: Vec<_> = dedup
            .keys()
            .copied()
            .filter(|ip| !spec.authority.contains(ip))
            .collect();
        if !outside.is_empty() {
            return self.reject_observation(
                logical_id,
                now_ms,
                entropy,
                ObservationDisposition::RejectedOutsideAuthority(outside),
            );
        }
        let rejected: Vec<_> = dedup
            .keys()
            .copied()
            .filter(|ip| !spec.address_policy.permits(*ip))
            .collect();
        if !rejected.is_empty() {
            return self.reject_observation(
                logical_id,
                now_ms,
                entropy,
                ObservationDisposition::RejectedAddressPolicy(rejected),
            );
        }

        let old_candidates = self.candidates.clone();
        let old_snapshot = self.snapshot();
        let observed: BTreeSet<_> = dedup.keys().copied().collect();

        for (ip, ttl) in &dedup {
            let ttl = (*ttl).clamp(MIN_TTL_SECS, MAX_TTL_SECS);
            let key = CandidateKey {
                logical: logical_id,
                ip: *ip,
            };
            let candidate = self.candidates.entry(key).or_insert(CandidateState {
                valid_until_ms: None,
                dialable: true,
                leases: 0,
            });
            candidate.dialable = true;
            candidate.valid_until_ms =
                Some(now_ms.saturating_add(u64::from(ttl).saturating_mul(1_000)));
        }

        let existing_keys: Vec<_> = self
            .candidates
            .keys()
            .copied()
            .filter(|key| key.logical == logical_id && !observed.contains(&key.ip))
            .collect();
        for key in existing_keys {
            if let Some(candidate) = self.candidates.get_mut(&key) {
                candidate.dialable = false;
            }
        }

        // A DNS response may never strand the daemon.  This guard also covers
        // a future policy filter that removes all records after parsing.
        if !self.candidates.values().any(|candidate| candidate.dialable) {
            self.candidates = old_candidates;
            return self.retain_with_negative_schedule(
                logical_id,
                now_ms,
                entropy,
                None,
                ObservationDisposition::RetainedEmptyPositive,
            );
        }

        let min_ttl = dedup.values().copied().min().unwrap_or(MIN_TTL_SECS);
        let refresh_delay = jittered_ttl_ms(min_ttl, entropy);
        let state = self
            .logical
            .get_mut(&logical_id)
            .expect("logical existence checked by caller");
        state.failure_streak = 0;
        state.next_refresh_at_ms = now_ms.saturating_add(refresh_delay);
        let next_refresh_at_ms = state.next_refresh_at_ms;

        let candidate_view =
            build_snapshot(old_snapshot.generation, &self.logical, &self.candidates);
        debug_assert!(!candidate_view.candidates.is_empty());
        let snapshot_changed = old_snapshot.candidates != candidate_view.candidates;
        let new_snapshot = if snapshot_changed {
            Arc::new(DialSnapshot {
                generation: old_snapshot.generation.saturating_add(1),
                candidates: candidate_view.candidates,
            })
        } else {
            Arc::clone(&old_snapshot)
        };
        let plan = transition_plan(
            &self.logical,
            &old_candidates,
            &self.candidates,
            old_snapshot.generation,
            Arc::clone(&new_snapshot),
            snapshot_changed,
        );
        plan.validate_order()?;
        self.snapshot = new_snapshot;

        Ok(ObservationResult {
            disposition: ObservationDisposition::Applied,
            plan,
            next_refresh_at_ms,
        })
    }

    fn reject_observation(
        &mut self,
        logical: LogicalEndpointId,
        now_ms: u64,
        entropy: u64,
        disposition: ObservationDisposition,
    ) -> Result<ObservationResult> {
        let state = self
            .logical
            .get_mut(&logical)
            .expect("logical existence checked by caller");
        state.failure_streak = state.failure_streak.saturating_add(1);
        state.next_refresh_at_ms =
            now_ms.saturating_add(retry_delay_ms(state.failure_streak, entropy));
        let next_refresh_at_ms = state.next_refresh_at_ms;
        Ok(ObservationResult {
            disposition,
            plan: TransitionPlan::unchanged(self.snapshot()),
            next_refresh_at_ms,
        })
    }

    pub fn acquire(&mut self, key: CandidateKey) -> Result<EndpointLease> {
        let next_revision = self
            .revision
            .checked_add(1)
            .context("endpoint coordinator revision exhausted")?;
        let next_lease_id = self
            .next_lease_id
            .checked_add(1)
            .context("endpoint lease id exhausted")?;
        anyhow::ensure!(
            !self.leases.contains_key(&self.next_lease_id),
            "duplicate lease id"
        );
        let candidate = self
            .candidates
            .get_mut(&key)
            .with_context(|| format!("candidate {key:?} is absent"))?;
        anyhow::ensure!(candidate.dialable, "candidate {key:?} is retiring");
        candidate.leases = candidate
            .leases
            .checked_add(1)
            .context("candidate lease counter overflow")?;
        let id = self.next_lease_id;
        self.next_lease_id = next_lease_id;
        self.leases.insert(id, key);
        self.revision = next_revision;
        Ok(EndpointLease { id, key })
    }

    /// Prepare release after the carrier socket has been dropped.  If this was
    /// the final lease of a DNS-depublished candidate, the plan denies its tuple
    /// before removing its route.  Live state still owns the lease until commit.
    pub fn prepare_release(&self, lease: EndpointLease) -> Result<PreparedLeaseRelease> {
        let mut projected = self.clone();
        let plan = projected.apply_release(lease)?;
        projected.revision = self
            .revision
            .checked_add(1)
            .context("endpoint coordinator revision exhausted")?;
        Ok(PreparedLeaseRelease {
            base_revision: self.revision,
            projected: Box::new(projected),
            plan,
        })
    }

    pub fn commit_release(&mut self, prepared: PreparedLeaseRelease) -> Result<TransitionPlan> {
        anyhow::ensure!(
            self.revision == prepared.base_revision,
            "stale prepared lease release: coordinator revision changed"
        );
        let plan = prepared.plan;
        *self = *prepared.projected;
        Ok(plan)
    }

    pub fn abort_release(&self, prepared: PreparedLeaseRelease) -> Result<()> {
        anyhow::ensure!(
            self.revision == prepared.base_revision,
            "prepared lease release was made stale by another transition"
        );
        drop(prepared);
        Ok(())
    }

    /// Prepare cleanup of all depublished candidates that already have zero
    /// leases.  This is intentionally separate from observation commit: kernel
    /// denial/removal can fail without losing the model's ownership tombstone.
    pub fn prepare_retirement(&self) -> Result<Option<PreparedRetirement>> {
        let mut projected = self.clone();
        let old_candidates = projected.candidates.clone();
        projected
            .candidates
            .retain(|_, candidate| candidate.dialable || candidate.leases != 0);
        if projected.candidates.len() == old_candidates.len() {
            return Ok(None);
        }
        let plan = transition_plan(
            &projected.logical,
            &old_candidates,
            &projected.candidates,
            projected.snapshot.generation,
            projected.snapshot(),
            false,
        );
        plan.validate_order()?;
        projected.revision = self
            .revision
            .checked_add(1)
            .context("endpoint coordinator revision exhausted")?;
        Ok(Some(PreparedRetirement {
            base_revision: self.revision,
            projected: Box::new(projected),
            plan,
        }))
    }

    pub fn commit_retirement(&mut self, prepared: PreparedRetirement) -> Result<TransitionPlan> {
        anyhow::ensure!(
            self.revision == prepared.base_revision,
            "stale prepared retirement: coordinator revision changed"
        );
        let plan = prepared.plan;
        *self = *prepared.projected;
        Ok(plan)
    }

    pub fn abort_retirement(&self, prepared: PreparedRetirement) -> Result<()> {
        anyhow::ensure!(
            self.revision == prepared.base_revision,
            "prepared retirement was made stale by another transition"
        );
        drop(prepared);
        Ok(())
    }

    #[cfg(test)]
    fn release(&mut self, lease: EndpointLease) -> Result<TransitionPlan> {
        let prepared = self.prepare_release(lease)?;
        self.commit_release(prepared)
    }

    fn apply_release(&mut self, lease: EndpointLease) -> Result<TransitionPlan> {
        let key = self
            .leases
            .remove(&lease.id)
            .with_context(|| format!("unknown or already released lease {}", lease.id))?;
        anyhow::ensure!(key == lease.key, "lease key mismatch");
        let old_candidates = self.candidates.clone();
        let candidate = self
            .candidates
            .get_mut(&key)
            .context("leased candidate disappeared")?;
        candidate.leases = candidate
            .leases
            .checked_sub(1)
            .context("candidate lease counter underflow")?;
        if candidate.leases == 0 && !candidate.dialable {
            self.candidates.remove(&key);
        }
        let plan = transition_plan(
            &self.logical,
            &old_candidates,
            &self.candidates,
            self.snapshot.generation,
            self.snapshot(),
            false,
        );
        plan.validate_order()?;
        Ok(plan)
    }
}

fn validate_hostname(hostname: &str) -> Result<()> {
    let hostname = hostname.trim_end_matches('.');
    anyhow::ensure!(!hostname.is_empty(), "endpoint hostname is empty");
    anyhow::ensure!(hostname.len() <= 253, "endpoint hostname exceeds 253 bytes");
    for label in hostname.split('.') {
        anyhow::ensure!(
            !label.is_empty(),
            "endpoint hostname contains an empty label"
        );
        anyhow::ensure!(
            label.len() <= 63,
            "endpoint hostname label exceeds 63 bytes"
        );
    }
    Ok(())
}

fn build_snapshot(
    generation: u64,
    logical: &BTreeMap<LogicalEndpointId, LogicalState>,
    candidates: &BTreeMap<CandidateKey, CandidateState>,
) -> DialSnapshot {
    let candidates = candidates
        .iter()
        .filter(|(_, candidate)| candidate.dialable)
        .map(|(key, _)| {
            let spec = &logical
                .get(&key.logical)
                .expect("candidate references known logical endpoint")
                .spec;
            DialCandidate {
                key: *key,
                address: SocketAddrV4::new(key.ip, spec.port),
                protocol: spec.protocol,
                auth: spec.auth,
                authority_generation: spec.authority.manifest_generation(),
            }
        })
        .collect();
    DialSnapshot {
        generation,
        candidates,
    }
}

type TupleRefs = BTreeMap<CarrierTuple, usize>;
type IpRefs = BTreeMap<Ipv4Addr, usize>;

fn access_refs(
    logical: &BTreeMap<LogicalEndpointId, LogicalState>,
    candidates: &BTreeMap<CandidateKey, CandidateState>,
) -> (TupleRefs, IpRefs) {
    let mut tuples = BTreeMap::new();
    let mut ips = BTreeMap::new();
    for key in candidates.keys() {
        let tuple = logical
            .get(&key.logical)
            .expect("candidate references known logical endpoint")
            .spec
            .tuple(key.ip);
        *tuples.entry(tuple).or_insert(0) += 1;
        *ips.entry(key.ip).or_insert(0) += 1;
    }
    (tuples, ips)
}

fn transition_plan(
    logical: &BTreeMap<LogicalEndpointId, LogicalState>,
    old: &BTreeMap<CandidateKey, CandidateState>,
    new: &BTreeMap<CandidateKey, CandidateState>,
    old_generation: u64,
    snapshot: Arc<DialSnapshot>,
    publish: bool,
) -> TransitionPlan {
    let (old_tuples, old_ips) = access_refs(logical, old);
    let (new_tuples, new_ips) = access_refs(logical, new);
    let mut operations = Vec::new();

    // Every allow precedes every bypass route addition.
    for tuple in new_tuples.keys() {
        if !old_tuples.contains_key(tuple) {
            operations.push(TransitionOperation::Firewall(FirewallOperation::Allow(
                *tuple,
            )));
        }
    }
    for ip in new_ips.keys() {
        if !old_ips.contains_key(ip) {
            operations.push(TransitionOperation::Route(RouteOperation::AddBypass(*ip)));
        }
    }
    if publish {
        operations.push(TransitionOperation::PublishSnapshot {
            from: old_generation,
            to: snapshot.generation,
        });
    }
    // Every deny precedes every bypass route removal.
    for tuple in old_tuples.keys() {
        if !new_tuples.contains_key(tuple) {
            operations.push(TransitionOperation::Firewall(FirewallOperation::Deny(
                *tuple,
            )));
        }
    }
    for ip in old_ips.keys() {
        if !new_ips.contains_key(ip) {
            operations.push(TransitionOperation::Route(RouteOperation::RemoveBypass(
                *ip,
            )));
        }
    }
    TransitionPlan {
        operations,
        snapshot,
    }
}

fn jittered_ttl_ms(ttl_secs: u32, entropy: u64) -> u64 {
    let ttl = u64::from(ttl_secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS));
    // Refresh in [70%, 90%] of TTL.  Inclusive integer arithmetic keeps the
    // result reproducible and always strictly ahead of `now`.
    let basis_points = 7_000 + (entropy % 2_001);
    ttl.saturating_mul(1_000).saturating_mul(basis_points) / 10_000
}

fn retry_delay_ms(streak: u32, entropy: u64) -> u64 {
    let shift = streak.saturating_sub(1).min(31);
    let ceiling = RETRY_BASE_MS
        .saturating_mul(1u64 << shift)
        .min(RETRY_CAP_MS);
    // Full jitter with a small non-zero floor avoids both a busy loop and a
    // synchronized retry wave.
    250 + entropy % ceiling.saturating_sub(249).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    const B: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
    const C: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);

    fn endpoint(
        id: u64,
        port: u16,
        protocol: CarrierProtocol,
        authority: &[Ipv4Addr],
    ) -> LogicalEndpoint {
        LogicalEndpoint {
            id: LogicalEndpointId(id),
            hostname: format!("vpn{id}.example"),
            port,
            protocol,
            auth: AuthConfigRef(id as u32),
            authority: VerifiedIpv4Authority::from_preverified_manifest(
                7,
                authority.iter().copied(),
            )
            .unwrap(),
            address_policy: AddressPolicy::default(),
        }
    }

    fn coordinator() -> EndpointCoordinator {
        EndpointCoordinator::new(
            [endpoint(1, 443, CarrierProtocol::Tcp, &[A, B, C])],
            [SeedCandidate {
                logical: LogicalEndpointId(1),
                ip: A,
            }],
            0,
        )
        .unwrap()
    }

    fn positive(ip: Ipv4Addr, ttl: u32) -> ResolutionObservation {
        ResolutionObservation::Positive(vec![AddressRecord { ip, ttl_secs: ttl }])
    }

    #[test]
    fn strict_dns_output_converts_without_losing_ttl_or_negative_semantics() {
        let positive: ResolutionObservation = crate::endpoint_dns::ParsedDnsAnswer::Positive(vec![
            crate::endpoint_dns::ParsedARecord {
                ip: B,
                ttl_secs: 17,
            },
        ])
        .into();
        assert_eq!(
            positive,
            ResolutionObservation::Positive(vec![AddressRecord {
                ip: B,
                ttl_secs: 17
            }])
        );
        let negative: ResolutionObservation = crate::endpoint_dns::ParsedDnsAnswer::NxDomain {
            negative_ttl_secs: 29,
        }
        .into();
        assert_eq!(
            negative,
            ResolutionObservation::NxDomain {
                negative_ttl_secs: Some(29)
            }
        );
    }

    fn ordered_kinds(plan: &TransitionPlan) -> Vec<&'static str> {
        plan.operations
            .iter()
            .map(|op| match op {
                TransitionOperation::Firewall(FirewallOperation::Allow(_)) => "allow",
                TransitionOperation::Route(RouteOperation::AddBypass(_)) => "route-add",
                TransitionOperation::PublishSnapshot { .. } => "publish",
                TransitionOperation::Firewall(FirewallOperation::Deny(_)) => "deny",
                TransitionOperation::Route(RouteOperation::RemoveBypass(_)) => "route-remove",
            })
            .collect()
    }

    #[test]
    fn addition_commits_before_separate_deny_then_route_retirement() {
        let mut c = coordinator();
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        let result = c.observe(stamp, positive(B, 60), 10_000, 0).unwrap();
        assert_eq!(
            ordered_kinds(&result.plan),
            ["allow", "route-add", "publish"]
        );
        result.plan.validate_order().unwrap();
        assert_eq!(result.plan.snapshot.candidates[0].key.ip, B);

        let retirement = c.prepare_retirement().unwrap().unwrap();
        assert_eq!(ordered_kinds(retirement.plan()), ["deny", "route-remove"]);
        retirement.plan().validate_order().unwrap();
        c.commit_retirement(retirement).unwrap();
        assert!(c.prepare_retirement().unwrap().is_none());
    }

    #[test]
    fn prepare_and_abort_leave_exact_prior_snapshot_and_allow_retry() {
        let mut c = coordinator();
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        let before = c.snapshot();
        let before_refresh = c.next_refresh_at_ms(LogicalEndpointId(1)).unwrap();
        let prepared = c
            .prepare_observation(stamp, positive(B, 60), 10_000, 0)
            .unwrap();
        assert_eq!(
            ordered_kinds(prepared.plan()),
            ["allow", "route-add", "publish"]
        );
        assert!(Arc::ptr_eq(&before, &c.snapshot()));
        assert_eq!(
            c.next_refresh_at_ms(LogicalEndpointId(1)).unwrap(),
            before_refresh
        );
        c.abort_observation(prepared).unwrap();
        assert!(Arc::ptr_eq(&before, &c.snapshot()));

        let retry = c
            .prepare_observation(stamp, positive(B, 60), 10_000, 0)
            .unwrap();
        c.commit_observation(retry).unwrap();
        assert_eq!(c.snapshot().candidates[0].key.ip, B);
    }

    #[test]
    fn prepared_observation_cannot_commit_after_lease_revision_race() {
        let mut c = coordinator();
        let key = c.snapshot().candidates[0].key;
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        let prepared = c
            .prepare_observation(stamp, positive(B, 60), 10_000, 0)
            .unwrap();
        let _lease = c.acquire(key).unwrap();
        assert!(c.commit_observation(prepared).is_err());
        assert_eq!(c.snapshot().candidates[0].key.ip, A);
    }

    #[test]
    fn multiple_a_are_deduplicated_and_ttl_uses_minimum() {
        let mut c = coordinator();
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        let result = c
            .observe(
                stamp,
                ResolutionObservation::Positive(vec![
                    AddressRecord {
                        ip: B,
                        ttl_secs: 120,
                    },
                    AddressRecord {
                        ip: A,
                        ttl_secs: 60,
                    },
                    AddressRecord {
                        ip: B,
                        ttl_secs: 30,
                    },
                ]),
                1_000,
                0,
            )
            .unwrap();
        assert_eq!(result.plan.snapshot.candidates.len(), 2);
        assert_eq!(result.next_refresh_at_ms, 1_000 + 21_000); // 70% of 30s
    }

    #[test]
    fn dns_cannot_expand_signed_authority() {
        let mut c = coordinator();
        let before = c.snapshot();
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        let bad = Ipv4Addr::new(4, 4, 4, 4);
        let result = c.observe(stamp, positive(bad, 60), 0, 0).unwrap();
        assert_eq!(
            result.disposition,
            ObservationDisposition::RejectedOutsideAuthority(vec![bad])
        );
        assert!(result.plan.operations.is_empty());
        assert_eq!(c.snapshot(), before);
    }

    #[test]
    fn one_unauthorized_address_rejects_the_entire_mixed_rrset() {
        let mut c = coordinator();
        let before = c.snapshot();
        let unauthorized = Ipv4Addr::new(4, 4, 4, 4);
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        let result = c
            .observe(
                stamp,
                ResolutionObservation::Positive(vec![
                    AddressRecord {
                        ip: B,
                        ttl_secs: 60,
                    },
                    AddressRecord {
                        ip: unauthorized,
                        ttl_secs: 60,
                    },
                ]),
                0,
                0,
            )
            .unwrap();
        assert!(matches!(
            result.disposition,
            ObservationDisposition::RejectedOutsideAuthority(ref rejected)
                if rejected == &[unauthorized]
        ));
        assert_eq!(c.snapshot(), before);
        assert!(result.plan.operations.is_empty());
    }

    #[test]
    fn private_rebinding_is_rejected_even_if_manifest_contains_it() {
        let private = Ipv4Addr::new(10, 0, 0, 7);
        let spec = LogicalEndpoint {
            id: LogicalEndpointId(1),
            hostname: "vpn.example".into(),
            port: 443,
            protocol: CarrierProtocol::Tcp,
            auth: AuthConfigRef(1),
            authority: VerifiedIpv4Authority::from_preverified_manifest(1, [A, private]).unwrap(),
            address_policy: AddressPolicy::default(),
        };
        assert!(EndpointCoordinator::new(
            [spec],
            [SeedCandidate {
                logical: LogicalEndpointId(1),
                ip: A,
            }],
            0
        )
        .is_err());
    }

    #[test]
    fn explicit_lab_policy_can_authorize_private_seed() {
        let private = Ipv4Addr::new(10, 0, 0, 7);
        let mut spec = endpoint(1, 443, CarrierProtocol::Tcp, &[A]);
        spec.authority = VerifiedIpv4Authority::from_preverified_manifest(1, [private]).unwrap();
        spec.address_policy.allow_private = true;
        EndpointCoordinator::new(
            [spec],
            [SeedCandidate {
                logical: LogicalEndpointId(1),
                ip: private,
            }],
            0,
        )
        .unwrap();
    }

    #[test]
    fn nxdomain_nodata_and_empty_positive_retain_last_known_good() {
        for observation in [
            ResolutionObservation::NxDomain {
                negative_ttl_secs: Some(20),
            },
            ResolutionObservation::NoData {
                negative_ttl_secs: None,
            },
            ResolutionObservation::Positive(Vec::new()),
        ] {
            let mut c = coordinator();
            let before = c.snapshot();
            let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
            let result = c.observe(stamp, observation, 100, 0).unwrap();
            assert!(result.plan.operations.is_empty());
            assert_eq!(c.snapshot(), before);
            assert!(!c.snapshot().candidates.is_empty());
        }
    }

    #[test]
    fn stale_answer_is_ignored_without_changing_schedule_or_snapshot() {
        let mut c = coordinator();
        let old = c.begin_query(LogicalEndpointId(1)).unwrap();
        let newest = c.begin_query(LogicalEndpointId(1)).unwrap();
        let before = c.snapshot();
        let schedule = c.next_refresh_at_ms(LogicalEndpointId(1)).unwrap();
        let ignored = c.observe(old, positive(B, 60), 9_000, 0).unwrap();
        assert_eq!(
            ignored.disposition,
            ObservationDisposition::IgnoredOutOfOrder
        );
        assert_eq!(ignored.next_refresh_at_ms, schedule);
        assert_eq!(c.snapshot(), before);
        let applied = c.observe(newest, positive(B, 60), 9_000, 0).unwrap();
        assert_eq!(applied.disposition, ObservationDisposition::Applied);
    }

    #[test]
    fn duplicate_answer_is_ignored_after_first_application() {
        let mut c = coordinator();
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        c.observe(stamp, positive(B, 60), 9_000, 0).unwrap();
        let before = c.snapshot();
        let duplicate = c.observe(stamp, positive(C, 60), 10_000, 0).unwrap();
        assert_eq!(
            duplicate.disposition,
            ObservationDisposition::IgnoredOutOfOrder
        );
        assert_eq!(c.snapshot(), before);
    }

    #[test]
    fn unchanged_rrset_does_not_bump_snapshot_generation() {
        let mut c = coordinator();
        let before = c.snapshot();
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        let result = c.observe(stamp, positive(A, 120), 1_000, 0).unwrap();
        assert!(result.plan.operations.is_empty());
        assert_eq!(result.plan.snapshot.generation, before.generation);
        assert_eq!(c.snapshot().generation, before.generation);
        assert!(Arc::ptr_eq(&before, &c.snapshot()));
    }

    #[test]
    fn lease_keeps_retired_tuple_and_route_until_quiescence() {
        let mut c = coordinator();
        let key = c.snapshot().candidates[0].key;
        let lease = c.acquire(key).unwrap();
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        let update = c.observe(stamp, positive(B, 60), 0, 0).unwrap();
        assert_eq!(
            ordered_kinds(&update.plan),
            ["allow", "route-add", "publish"]
        );
        assert_eq!(update.plan.snapshot.candidates.len(), 1);
        assert_eq!(update.plan.snapshot.candidates[0].key.ip, B);

        let retire = c.release(lease).unwrap();
        assert_eq!(ordered_kinds(&retire), ["deny", "route-remove"]);
        retire.validate_order().unwrap();
    }

    #[test]
    fn aborted_release_keeps_lease_and_host_ownership_for_retry() {
        let mut c = coordinator();
        let key = c.snapshot().candidates[0].key;
        let lease = c.acquire(key).unwrap();
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        c.observe(stamp, positive(B, 60), 0, 0).unwrap();

        let prepared = c.prepare_release(lease).unwrap();
        assert_eq!(ordered_kinds(prepared.plan()), ["deny", "route-remove"]);
        c.abort_release(prepared).unwrap();

        let retry = c.prepare_release(lease).unwrap();
        assert_eq!(ordered_kinds(retry.plan()), ["deny", "route-remove"]);
        c.commit_release(retry).unwrap();
        assert!(c.prepare_retirement().unwrap().is_none());
    }

    #[test]
    fn aborted_unleased_retirement_preserves_cleanup_tombstone() {
        let mut c = coordinator();
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        c.observe(stamp, positive(B, 60), 0, 0).unwrap();
        let prepared = c.prepare_retirement().unwrap().unwrap();
        assert_eq!(ordered_kinds(prepared.plan()), ["deny", "route-remove"]);
        c.abort_retirement(prepared).unwrap();
        let retry = c.prepare_retirement().unwrap().unwrap();
        c.commit_retirement(retry).unwrap();
        assert!(c.prepare_retirement().unwrap().is_none());
    }

    #[test]
    fn authority_rehydration_adds_only_internal_authority_in_fail_closed_order() {
        let mut c = EndpointCoordinator::new(
            [endpoint(1, 443, CarrierProtocol::Tcp, &[A, B, C])],
            [SeedCandidate {
                logical: LogicalEndpointId(1),
                ip: A,
            }],
            0,
        )
        .unwrap();
        let before = c.snapshot();
        let prepared = c.prepare_authority_rehydration().unwrap();
        assert_eq!(
            prepared.revived_candidates(),
            [
                CandidateKey {
                    logical: LogicalEndpointId(1),
                    ip: B,
                },
                CandidateKey {
                    logical: LogicalEndpointId(1),
                    ip: C,
                },
            ]
        );
        assert_eq!(
            ordered_kinds(prepared.plan()),
            ["allow", "allow", "route-add", "route-add", "publish"]
        );
        assert!(prepared.plan().operations.iter().all(|operation| !matches!(
            operation,
            TransitionOperation::Firewall(FirewallOperation::Deny(_))
                | TransitionOperation::Route(RouteOperation::RemoveBypass(_))
        )));
        assert_eq!(c.snapshot().as_ref(), before.as_ref());

        let result = c.commit_authority_rehydration(prepared).unwrap();
        assert!(result.changed_snapshot());
        assert_eq!(
            c.snapshot()
                .candidates
                .iter()
                .map(|candidate| candidate.key.ip)
                .collect::<Vec<_>>(),
            [A, B, C]
        );
    }

    #[test]
    fn authority_rehydration_restores_tombstone_and_removed_candidate_without_losing_lease() {
        let mut c = EndpointCoordinator::new(
            [endpoint(1, 443, CarrierProtocol::Tcp, &[A, B, C])],
            [
                SeedCandidate {
                    logical: LogicalEndpointId(1),
                    ip: A,
                },
                SeedCandidate {
                    logical: LogicalEndpointId(1),
                    ip: B,
                },
                SeedCandidate {
                    logical: LogicalEndpointId(1),
                    ip: C,
                },
            ],
            0,
        )
        .unwrap();
        let b_key = CandidateKey {
            logical: LogicalEndpointId(1),
            ip: B,
        };
        let c_key = CandidateKey {
            logical: LogicalEndpointId(1),
            ip: C,
        };
        let b_lease = c.acquire(b_key).unwrap();
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        c.observe(stamp, positive(A, 60), 0, 0).unwrap();

        // C has no lease and can complete retirement; B remains as an owned,
        // non-dialable tombstone until its socket lease is released.
        let retirement = c.prepare_retirement().unwrap().unwrap();
        c.commit_retirement(retirement).unwrap();
        assert!(!c.candidates.get(&b_key).unwrap().dialable);
        assert_eq!(c.candidates.get(&b_key).unwrap().leases, 1);
        assert!(!c.candidates.contains_key(&c_key));

        let prepared = c.prepare_authority_rehydration().unwrap();
        assert_eq!(prepared.revived_candidates(), [b_key, c_key]);
        // B's host tuple/route are still owned by its lease. Only completely
        // retired C needs new host access before the snapshot publication.
        assert_eq!(
            ordered_kinds(prepared.plan()),
            ["allow", "route-add", "publish"]
        );
        assert_eq!(prepared.projected.candidates.get(&b_key).unwrap().leases, 1);
        c.commit_authority_rehydration(prepared).unwrap();

        let release = c.release(b_lease).unwrap();
        assert!(release.operations.is_empty());
        assert!(c.candidates.get(&b_key).unwrap().dialable);
        assert_eq!(c.candidates.get(&b_key).unwrap().leases, 0);
    }

    #[test]
    fn full_authority_rehydration_is_an_exact_noop() {
        let mut c = EndpointCoordinator::new(
            [endpoint(1, 443, CarrierProtocol::Tcp, &[A, B, C])],
            [
                SeedCandidate {
                    logical: LogicalEndpointId(1),
                    ip: A,
                },
                SeedCandidate {
                    logical: LogicalEndpointId(1),
                    ip: B,
                },
                SeedCandidate {
                    logical: LogicalEndpointId(1),
                    ip: C,
                },
            ],
            0,
        )
        .unwrap();
        let before = c.snapshot();
        let before_revision = c.revision;
        let prepared = c.prepare_authority_rehydration().unwrap();
        assert!(prepared.revived_candidates().is_empty());
        assert!(prepared.plan().operations.is_empty());
        assert!(!prepared.result().changed_snapshot());
        let result = c.commit_authority_rehydration(prepared).unwrap();
        assert!(!result.changed_snapshot());
        assert_eq!(c.revision, before_revision);
        assert!(Arc::ptr_eq(&before, &c.snapshot()));
    }

    #[test]
    fn prepared_authority_rehydration_aborts_exactly_and_rejects_revision_race() {
        let mut c = coordinator();
        let before = c.snapshot();
        let prepared = c.prepare_authority_rehydration().unwrap();
        c.abort_authority_rehydration(prepared).unwrap();
        assert!(Arc::ptr_eq(&before, &c.snapshot()));

        let stale = c.prepare_authority_rehydration().unwrap();
        let live_key = c.snapshot().candidates[0].key;
        let _lease = c.acquire(live_key).unwrap();
        assert!(c.commit_authority_rehydration(stale).is_err());
        assert!(Arc::ptr_eq(&before, &c.snapshot()));
    }

    #[test]
    fn authority_rehydration_respects_shared_tuple_and_route_refcounts() {
        let mut c = EndpointCoordinator::new(
            [
                endpoint(1, 443, CarrierProtocol::Tcp, &[A, B]),
                endpoint(2, 443, CarrierProtocol::Tcp, &[B]),
            ],
            [
                SeedCandidate {
                    logical: LogicalEndpointId(1),
                    ip: A,
                },
                SeedCandidate {
                    logical: LogicalEndpointId(2),
                    ip: B,
                },
            ],
            0,
        )
        .unwrap();
        let prepared = c.prepare_authority_rehydration().unwrap();
        assert_eq!(
            prepared.revived_candidates(),
            [CandidateKey {
                logical: LogicalEndpointId(1),
                ip: B,
            }]
        );
        // Logical endpoint 2 already owns the identical B:443/TCP tuple and
        // B/32 route, so rehydrating endpoint 1 needs only model publication.
        assert_eq!(ordered_kinds(prepared.plan()), ["publish"]);
        c.commit_authority_rehydration(prepared).unwrap();
        assert_eq!(c.snapshot().candidates.len(), 3);
    }

    #[test]
    fn tuple_and_route_refcounts_avoid_duplicate_host_mutations() {
        let specs = [
            endpoint(1, 443, CarrierProtocol::Tcp, &[A, B]),
            endpoint(2, 443, CarrierProtocol::Tcp, &[A, B]),
        ];
        let mut c = EndpointCoordinator::new(
            specs,
            [
                SeedCandidate {
                    logical: LogicalEndpointId(1),
                    ip: A,
                },
                SeedCandidate {
                    logical: LogicalEndpointId(2),
                    ip: A,
                },
            ],
            0,
        )
        .unwrap();
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        let result = c.observe(stamp, positive(B, 60), 0, 0).unwrap();
        // Endpoint 2 still owns A, so A's shared tuple and route are not removed.
        assert_eq!(
            ordered_kinds(&result.plan),
            ["allow", "route-add", "publish"]
        );
    }

    #[test]
    fn same_ip_different_auth_remains_two_stable_dial_candidates() {
        let specs = [
            endpoint(1, 443, CarrierProtocol::Tcp, &[A]),
            endpoint(2, 443, CarrierProtocol::Tcp, &[A]),
        ];
        let c = EndpointCoordinator::new(
            specs,
            [
                SeedCandidate {
                    logical: LogicalEndpointId(1),
                    ip: A,
                },
                SeedCandidate {
                    logical: LogicalEndpointId(2),
                    ip: A,
                },
            ],
            0,
        )
        .unwrap();
        assert_eq!(c.snapshot().candidates.len(), 2);
        assert_ne!(
            c.snapshot().candidates[0].auth,
            c.snapshot().candidates[1].auth
        );
    }

    #[test]
    fn duplicate_lease_release_is_rejected() {
        let mut c = coordinator();
        let lease = c.acquire(c.snapshot().candidates[0].key).unwrap();
        c.release(lease).unwrap();
        assert!(c.release(lease).is_err());
    }

    #[test]
    fn ttl_jitter_and_backoff_are_bounded() {
        assert_eq!(jittered_ttl_ms(1, 0), 3_500); // min TTL 5s, 70%
        assert!(jittered_ttl_ms(u32::MAX, u64::MAX) <= 3_240_000); // 90% of 1h
        for streak in 1..100 {
            let delay = retry_delay_ms(streak, u64::MAX);
            assert!((250..=RETRY_CAP_MS).contains(&delay));
        }
    }

    #[test]
    fn transient_failures_back_off_but_never_empty_snapshot() {
        let mut c = coordinator();
        for now in [0, 1_000, 2_000, 3_000] {
            let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
            let result = c
                .observe(stamp, ResolutionObservation::TransientFailure, now, 17)
                .unwrap();
            assert!(result.next_refresh_at_ms > now);
            assert!(!c.snapshot().candidates.is_empty());
        }
    }

    #[test]
    fn ttl_expiry_alone_does_not_delete_last_known_good() {
        let mut c = coordinator();
        let stamp = c.begin_query(LogicalEndpointId(1)).unwrap();
        c.observe(stamp, positive(A, 5), 0, 0).unwrap();
        let after_expiry = 60_000;
        assert!(c
            .snapshot()
            .candidates
            .iter()
            .any(|candidate| candidate.key.ip == A));
        assert!(after_expiry > 5_000);
    }

    #[test]
    fn constructor_rejects_empty_snapshot_and_unknown_or_unauthorized_seed() {
        let spec = endpoint(1, 443, CarrierProtocol::Tcp, &[A]);
        assert!(EndpointCoordinator::new([spec.clone()], [], 0).is_err());
        assert!(EndpointCoordinator::new(
            [spec.clone()],
            [SeedCandidate {
                logical: LogicalEndpointId(99),
                ip: A,
            }],
            0
        )
        .is_err());
        assert!(EndpointCoordinator::new(
            [spec],
            [SeedCandidate {
                logical: LogicalEndpointId(1),
                ip: B,
            }],
            0
        )
        .is_err());
    }

    #[test]
    fn invalid_manual_order_is_detected() {
        let snapshot = Arc::new(DialSnapshot {
            generation: 2,
            candidates: Vec::new(),
        });
        let tuple = CarrierTuple {
            address: SocketAddrV4::new(A, 443),
            protocol: CarrierProtocol::Tcp,
        };
        let bad = TransitionPlan {
            operations: vec![
                TransitionOperation::Route(RouteOperation::AddBypass(A)),
                TransitionOperation::Firewall(FirewallOperation::Allow(tuple)),
                TransitionOperation::PublishSnapshot { from: 1, to: 2 },
            ],
            snapshot,
        };
        assert!(bad.validate_order().is_err());
    }

    #[test]
    fn host_prefix_inverse_is_exact_and_publish_is_only_a_marker() {
        let tuple = CarrierTuple {
            address: SocketAddrV4::new(A, 443),
            protocol: CarrierProtocol::Tcp,
        };
        assert_eq!(
            TransitionOperation::Firewall(FirewallOperation::Allow(tuple)).host_inverse(),
            Some(TransitionOperation::Firewall(FirewallOperation::Deny(
                tuple
            )))
        );
        assert_eq!(
            TransitionOperation::Route(RouteOperation::AddBypass(A)).host_inverse(),
            Some(TransitionOperation::Route(RouteOperation::RemoveBypass(A)))
        );
        assert_eq!(
            TransitionOperation::PublishSnapshot { from: 1, to: 2 }.host_inverse(),
            None
        );
    }
}
