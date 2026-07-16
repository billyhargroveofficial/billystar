//! Pure platform capability and reconciliation contract.
//!
//! This module deliberately contains no operating-system calls. Platform
//! adapters observe host state, serialize it into these types, and may perform
//! privileged reconciliation only after [`reconcile_platform`] returns
//! [`ReconcileDecision::Ready`].

use std::collections::BTreeSet;
use std::iter::FromIterator;

use serde::{Deserialize, Serialize};

/// Host operating-system family implementing the platform adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformKind {
    Linux,
    Macos,
    Windows,
}

/// Deliberate IPv6 handling policy.
///
/// IPv6 is blocked by default. It must never become an implicit bypass merely
/// because a host happens to have IPv6 connectivity.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6Mode {
    #[default]
    Block,
    OuterOnly,
    Tunnel,
}

/// A primitive that a platform adapter can prove it implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostCapability {
    StableInterfaceIdentity,
    NetworkChangeEvents,
    TunIpv4,
    RoutesIpv4,
    DnsControl,
    KillSwitchIpv4,
    DurableRecovery,
    Ipv6Block,
    OuterIpv6Transport,
    TunIpv6,
    RoutesIpv6,
    KillSwitchIpv6,
}

/// Canonically ordered set of host capabilities.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostCapabilitySet(BTreeSet<HostCapability>);

impl HostCapabilitySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, capability: HostCapability) -> bool {
        self.0.insert(capability)
    }

    pub fn contains(&self, capability: &HostCapability) -> bool {
        self.0.contains(capability)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &HostCapability> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    fn union_with(&mut self, other: &Self) {
        self.0.extend(other.0.iter().copied());
    }

    fn difference(&self, observed: &Self) -> Self {
        Self(self.0.difference(&observed.0).copied().collect())
    }
}

impl FromIterator<HostCapability> for HostCapabilitySet {
    fn from_iter<T: IntoIterator<Item = HostCapability>>(iter: T) -> Self {
        Self(BTreeSet::from_iter(iter))
    }
}

impl<const N: usize> From<[HostCapability; N]> for HostCapabilitySet {
    fn from(value: [HostCapability; N]) -> Self {
        value.into_iter().collect()
    }
}

impl IntoIterator for HostCapabilitySet {
    type Item = HostCapability;
    type IntoIter = std::collections::btree_set::IntoIter<HostCapability>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Minimum capabilities required by the invariant-preserving core.
///
/// Callers may require additional capabilities in [`DesiredHostState`], but
/// they cannot remove these baseline requirements.
pub fn minimum_capabilities(ipv6_mode: Ipv6Mode) -> HostCapabilitySet {
    let mut required = HostCapabilitySet::from([
        HostCapability::StableInterfaceIdentity,
        HostCapability::NetworkChangeEvents,
        HostCapability::TunIpv4,
        HostCapability::RoutesIpv4,
        HostCapability::DnsControl,
        HostCapability::KillSwitchIpv4,
        HostCapability::DurableRecovery,
    ]);

    match ipv6_mode {
        Ipv6Mode::Block => {
            required.insert(HostCapability::Ipv6Block);
        }
        Ipv6Mode::OuterOnly => {
            required.insert(HostCapability::Ipv6Block);
            required.insert(HostCapability::OuterIpv6Transport);
        }
        Ipv6Mode::Tunnel => {
            required.insert(HostCapability::TunIpv6);
            required.insert(HostCapability::RoutesIpv6);
            required.insert(HostCapability::KillSwitchIpv6);
        }
    }

    required
}

/// Host event that caused a fresh observation and reconciliation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkChangeKind {
    InitialObservation,
    InterfaceSetChanged,
    InterfaceAddressChanged,
    DefaultRouteChanged,
    RoutingPolicyChanged,
    OwnedRouteChanged,
    DnsConfigurationChanged,
    ConnectivityChanged,
    Suspend,
    Resume,
}

/// Generation of the desired state snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DesiredGeneration(pub u64);

impl DesiredGeneration {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Generation against which the host observation was collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObservedGeneration(pub u64);

impl ObservedGeneration {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Result of resolving the host interface used for underlay connectivity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum InterfaceObservation {
    Missing,
    Unique { stable_id: String },
    Ambiguous { candidate_ids: BTreeSet<String> },
}

/// Configuration the architecture wants a platform adapter to enforce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredHostState {
    pub platform: PlatformKind,
    pub generation: DesiredGeneration,
    #[serde(default)]
    pub ipv6_mode: Ipv6Mode,
    #[serde(default)]
    pub required_capabilities: HostCapabilitySet,
}

/// Immutable observation produced by a platform adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedHostState {
    pub platform: PlatformKind,
    pub generation: ObservedGeneration,
    pub capabilities: HostCapabilitySet,
    pub supported_ipv6_modes: BTreeSet<Ipv6Mode>,
    pub interface: InterfaceObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_change: Option<NetworkChangeKind>,
}

/// Safety reason that prevents privileged platform reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum FailClosedReason {
    PlatformMismatch {
        desired: PlatformKind,
        observed: PlatformKind,
    },
    StaleObservedGeneration {
        desired: DesiredGeneration,
        observed: ObservedGeneration,
    },
    FutureObservedGeneration {
        desired: DesiredGeneration,
        observed: ObservedGeneration,
    },
    MissingInterface,
    AmbiguousInterface {
        candidate_ids: BTreeSet<String>,
    },
    InvalidInterfaceIdentity,
    UnsupportedIpv6Mode {
        requested: Ipv6Mode,
        supported: BTreeSet<Ipv6Mode>,
    },
    MissingCapabilities {
        missing: HostCapabilitySet,
    },
}

/// Pure decision returned before an adapter may touch host network state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReconcileDecision {
    Ready {
        generation: DesiredGeneration,
        interface_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trigger: Option<NetworkChangeKind>,
    },
    FailClosed {
        generation: DesiredGeneration,
        blocker: FailClosedReason,
    },
}

fn fail_closed(generation: DesiredGeneration, blocker: FailClosedReason) -> ReconcileDecision {
    ReconcileDecision::FailClosed {
        generation,
        blocker,
    }
}

/// Decide whether a platform adapter has enough current, unambiguous evidence
/// to reconcile privileged network state.
///
/// This function never performs I/O. Any uncertainty is represented as
/// [`ReconcileDecision::FailClosed`].
pub fn reconcile_platform(
    desired: &DesiredHostState,
    observed: &ObservedHostState,
) -> ReconcileDecision {
    if desired.platform != observed.platform {
        return fail_closed(
            desired.generation,
            FailClosedReason::PlatformMismatch {
                desired: desired.platform,
                observed: observed.platform,
            },
        );
    }

    if observed.generation.get() < desired.generation.get() {
        return fail_closed(
            desired.generation,
            FailClosedReason::StaleObservedGeneration {
                desired: desired.generation,
                observed: observed.generation,
            },
        );
    }

    if observed.generation.get() > desired.generation.get() {
        return fail_closed(
            desired.generation,
            FailClosedReason::FutureObservedGeneration {
                desired: desired.generation,
                observed: observed.generation,
            },
        );
    }

    let interface_id = match &observed.interface {
        InterfaceObservation::Missing => {
            return fail_closed(desired.generation, FailClosedReason::MissingInterface);
        }
        InterfaceObservation::Unique { stable_id } if stable_id.trim().is_empty() => {
            return fail_closed(
                desired.generation,
                FailClosedReason::InvalidInterfaceIdentity,
            );
        }
        InterfaceObservation::Unique { stable_id } => stable_id.clone(),
        InterfaceObservation::Ambiguous { candidate_ids } => {
            return fail_closed(
                desired.generation,
                FailClosedReason::AmbiguousInterface {
                    candidate_ids: candidate_ids.clone(),
                },
            );
        }
    };

    if !observed.supported_ipv6_modes.contains(&desired.ipv6_mode) {
        return fail_closed(
            desired.generation,
            FailClosedReason::UnsupportedIpv6Mode {
                requested: desired.ipv6_mode,
                supported: observed.supported_ipv6_modes.clone(),
            },
        );
    }

    let mut required = minimum_capabilities(desired.ipv6_mode);
    required.union_with(&desired.required_capabilities);
    let missing = required.difference(&observed.capabilities);
    if !missing.is_empty() {
        return fail_closed(
            desired.generation,
            FailClosedReason::MissingCapabilities { missing },
        );
    }

    ReconcileDecision::Ready {
        generation: desired.generation,
        interface_id,
        trigger: observed.last_change,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn desired(ipv6_mode: Ipv6Mode) -> DesiredHostState {
        DesiredHostState {
            platform: PlatformKind::Linux,
            generation: DesiredGeneration::new(7),
            ipv6_mode,
            required_capabilities: HostCapabilitySet::new(),
        }
    }

    fn observed(ipv6_mode: Ipv6Mode) -> ObservedHostState {
        ObservedHostState {
            platform: PlatformKind::Linux,
            generation: ObservedGeneration::new(7),
            capabilities: minimum_capabilities(ipv6_mode),
            supported_ipv6_modes: BTreeSet::from([ipv6_mode]),
            interface: InterfaceObservation::Unique {
                stable_id: "ifindex:2".to_owned(),
            },
            last_change: Some(NetworkChangeKind::InitialObservation),
        }
    }

    #[test]
    fn ipv6_defaults_to_block_when_omitted() {
        let decoded: DesiredHostState = serde_json::from_value(json!({
            "platform": "linux",
            "generation": 1
        }))
        .unwrap();

        assert_eq!(decoded.ipv6_mode, Ipv6Mode::Block);
        assert!(decoded.required_capabilities.is_empty());
    }

    #[test]
    fn strict_structs_and_enums_reject_unknown_input() {
        assert!(serde_json::from_value::<DesiredHostState>(json!({
            "platform": "linux",
            "generation": 1,
            "unexpected": true
        }))
        .is_err());
        assert!(serde_json::from_value::<ObservedHostState>(json!({
            "platform": "linux",
            "generation": 1,
            "capabilities": [],
            "supported_ipv6_modes": ["block"],
            "interface": {"status": "missing"},
            "unexpected": true
        }))
        .is_err());
        assert!(serde_json::from_value::<InterfaceObservation>(json!({
            "status": "unique",
            "stable_id": "ifindex:2",
            "unexpected": true
        }))
        .is_err());
        assert!(
            serde_json::from_value::<HostCapabilitySet>(json!(["unknown_capability"])).is_err()
        );
        assert!(serde_json::from_value::<Ipv6Mode>(json!("automatic")).is_err());
    }

    #[test]
    fn capability_set_serializes_in_canonical_order() {
        let capabilities = HostCapabilitySet::from([
            HostCapability::KillSwitchIpv4,
            HostCapability::TunIpv4,
            HostCapability::DnsControl,
            HostCapability::TunIpv4,
        ]);

        assert_eq!(
            serde_json::to_value(capabilities).unwrap(),
            json!(["tun_ipv4", "dns_control", "kill_switch_ipv4"])
        );
    }

    #[test]
    fn matching_evidence_is_ready_and_preserves_trigger() {
        let desired = desired(Ipv6Mode::Block);
        let observed = observed(Ipv6Mode::Block);

        assert_eq!(
            reconcile_platform(&desired, &observed),
            ReconcileDecision::Ready {
                generation: DesiredGeneration::new(7),
                interface_id: "ifindex:2".to_owned(),
                trigger: Some(NetworkChangeKind::InitialObservation),
            }
        );
    }

    #[test]
    fn platform_mismatch_is_fail_closed() {
        let desired = desired(Ipv6Mode::Block);
        let mut observed = observed(Ipv6Mode::Block);
        observed.platform = PlatformKind::Windows;

        assert_eq!(
            reconcile_platform(&desired, &observed),
            ReconcileDecision::FailClosed {
                generation: DesiredGeneration::new(7),
                blocker: FailClosedReason::PlatformMismatch {
                    desired: PlatformKind::Linux,
                    observed: PlatformKind::Windows,
                },
            }
        );
    }

    #[test]
    fn stale_observation_is_fail_closed() {
        let desired = desired(Ipv6Mode::Block);
        let mut observed = observed(Ipv6Mode::Block);
        observed.generation = ObservedGeneration::new(6);

        assert_eq!(
            reconcile_platform(&desired, &observed),
            ReconcileDecision::FailClosed {
                generation: DesiredGeneration::new(7),
                blocker: FailClosedReason::StaleObservedGeneration {
                    desired: DesiredGeneration::new(7),
                    observed: ObservedGeneration::new(6),
                },
            }
        );
    }

    #[test]
    fn future_observation_is_also_fail_closed() {
        let desired = desired(Ipv6Mode::Block);
        let mut observed = observed(Ipv6Mode::Block);
        observed.generation = ObservedGeneration::new(8);

        assert_eq!(
            reconcile_platform(&desired, &observed),
            ReconcileDecision::FailClosed {
                generation: DesiredGeneration::new(7),
                blocker: FailClosedReason::FutureObservedGeneration {
                    desired: DesiredGeneration::new(7),
                    observed: ObservedGeneration::new(8),
                },
            }
        );
    }

    #[test]
    fn missing_and_ambiguous_interfaces_are_fail_closed() {
        let desired = desired(Ipv6Mode::Block);
        let mut observed = observed(Ipv6Mode::Block);
        observed.interface = InterfaceObservation::Missing;
        assert_eq!(
            reconcile_platform(&desired, &observed),
            ReconcileDecision::FailClosed {
                generation: DesiredGeneration::new(7),
                blocker: FailClosedReason::MissingInterface,
            }
        );

        let candidates = BTreeSet::from(["ifindex:2".to_owned(), "ifindex:3".to_owned()]);
        observed.interface = InterfaceObservation::Ambiguous {
            candidate_ids: candidates.clone(),
        };
        assert_eq!(
            reconcile_platform(&desired, &observed),
            ReconcileDecision::FailClosed {
                generation: DesiredGeneration::new(7),
                blocker: FailClosedReason::AmbiguousInterface {
                    candidate_ids: candidates,
                },
            }
        );
    }

    #[test]
    fn blank_interface_identity_is_fail_closed() {
        let desired = desired(Ipv6Mode::Block);
        let mut observed = observed(Ipv6Mode::Block);
        observed.interface = InterfaceObservation::Unique {
            stable_id: " \t".to_owned(),
        };

        assert_eq!(
            reconcile_platform(&desired, &observed),
            ReconcileDecision::FailClosed {
                generation: DesiredGeneration::new(7),
                blocker: FailClosedReason::InvalidInterfaceIdentity,
            }
        );
    }

    #[test]
    fn unsupported_ipv6_mode_is_fail_closed() {
        let desired = desired(Ipv6Mode::Tunnel);
        let mut observed = observed(Ipv6Mode::Tunnel);
        observed.supported_ipv6_modes = BTreeSet::from([Ipv6Mode::Block]);

        assert_eq!(
            reconcile_platform(&desired, &observed),
            ReconcileDecision::FailClosed {
                generation: DesiredGeneration::new(7),
                blocker: FailClosedReason::UnsupportedIpv6Mode {
                    requested: Ipv6Mode::Tunnel,
                    supported: BTreeSet::from([Ipv6Mode::Block]),
                },
            }
        );
    }

    #[test]
    fn missing_baseline_and_requested_capabilities_are_fail_closed() {
        let mut desired = desired(Ipv6Mode::Block);
        desired
            .required_capabilities
            .insert(HostCapability::OuterIpv6Transport);
        let mut observed = observed(Ipv6Mode::Block);
        observed.capabilities = HostCapabilitySet::from([HostCapability::TunIpv4]);

        let decision = reconcile_platform(&desired, &observed);
        let ReconcileDecision::FailClosed {
            blocker: FailClosedReason::MissingCapabilities { missing },
            ..
        } = decision
        else {
            panic!("missing capabilities must fail closed");
        };

        assert!(missing.contains(&HostCapability::StableInterfaceIdentity));
        assert!(missing.contains(&HostCapability::KillSwitchIpv4));
        assert!(missing.contains(&HostCapability::Ipv6Block));
        assert!(missing.contains(&HostCapability::OuterIpv6Transport));
        assert!(!missing.contains(&HostCapability::TunIpv4));
    }

    #[test]
    fn outer_only_requires_blocking_inner_ipv6_and_outer_transport() {
        let required = minimum_capabilities(Ipv6Mode::OuterOnly);

        assert!(required.contains(&HostCapability::Ipv6Block));
        assert!(required.contains(&HostCapability::OuterIpv6Transport));
        assert!(!required.contains(&HostCapability::TunIpv6));
        assert_eq!(
            reconcile_platform(
                &desired(Ipv6Mode::OuterOnly),
                &observed(Ipv6Mode::OuterOnly)
            ),
            ReconcileDecision::Ready {
                generation: DesiredGeneration::new(7),
                interface_id: "ifindex:2".to_owned(),
                trigger: Some(NetworkChangeKind::InitialObservation),
            }
        );
    }

    #[test]
    fn tunnel_mode_requires_complete_ipv6_tunnel_safety_set() {
        let desired = desired(Ipv6Mode::Tunnel);
        let mut observed = observed(Ipv6Mode::Tunnel);
        observed
            .capabilities
            .0
            .remove(&HostCapability::KillSwitchIpv6);

        assert_eq!(
            reconcile_platform(&desired, &observed),
            ReconcileDecision::FailClosed {
                generation: DesiredGeneration::new(7),
                blocker: FailClosedReason::MissingCapabilities {
                    missing: HostCapabilitySet::from([HostCapability::KillSwitchIpv6]),
                },
            }
        );
    }

    #[test]
    fn reconcile_decision_round_trips_strictly() {
        let decision = reconcile_platform(
            &desired(Ipv6Mode::OuterOnly),
            &observed(Ipv6Mode::OuterOnly),
        );
        let encoded = serde_json::to_value(&decision).unwrap();
        let decoded: ReconcileDecision = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded, decision);

        let mut malformed = encoded;
        malformed["unexpected"] = json!(true);
        assert!(serde_json::from_value::<ReconcileDecision>(malformed).is_err());
    }
}
