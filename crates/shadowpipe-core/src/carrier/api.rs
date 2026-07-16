//! Object-safe carrier boundary for the ZATMENIE A-plane.
//!
//! A carrier owns *where* a byte stream travels.  It does not own routing and it
//! does not decide when it should become active.  The control plane may compare
//! immutable capability/health snapshots, while the caller remains responsible
//! for every lifecycle and route change.

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// The I/O contract returned by every stream-oriented carrier.
///
/// Keeping `Unpin` in the boundary makes the boxed stream directly usable by
/// the existing tunnel/session code without carrier-specific pin projections.
pub trait CarrierIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> CarrierIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A type-erased, owned carrier byte stream.
pub type BoxedCarrierStream = Box<dyn CarrierIo + 'static>;

/// Object-safe future used instead of `async_trait`.
pub type CarrierFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Stable identifier used to join capabilities, observations, and health.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CarrierId(String);

impl CarrierId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for CarrierId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for CarrierId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for CarrierId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// Coarse topology classes.  They intentionally describe placement rather
/// than a wire protocol: multiple implementations may share one topology.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierTopology {
    Direct,
    CloudEdge,
    ServerlessEdge,
    DomesticCloudRelay,
    TurnRelay,
    PeerRelay,
    Other,
}

/// Access policy observed on the client network.
///
/// Compatibility is deliberately explicit rather than inferred by ordering:
/// a carrier must list every regime in which it has been designed to operate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessRegime {
    OpenInternet,
    DestinationIpAllowlist,
    DestinationIpAndNameAllowlist,
    UnknownRestricted,
}

/// Optional carrier features visible at the common boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierFeature {
    NativeMultiplexing,
    HalfDuplexStreaming,
    DatagramSideChannel,
    ConnectionMigration,
    CoverPathProbe,
}

/// Scope in which two carrier failures are expected to correlate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureDomainScope {
    LocalNetwork,
    DestinationPrefix,
    DestinationAsn,
    TransitAsn,
    Provider,
    Region,
    Endpoint,
    Relay,
    Origin,
    Protocol,
    Credential,
    Other,
}

/// A stable correlation key, e.g. `(provider, "yandex-cloud")`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureDomain {
    pub scope: FailureDomainScope,
    pub key: String,
}

impl FailureDomain {
    pub fn new(scope: FailureDomainScope, key: impl Into<String>) -> Self {
        Self {
            scope,
            key: key.into(),
        }
    }
}

/// Static facts about one carrier implementation/instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierCapabilities {
    pub carrier_id: CarrierId,
    pub topology: CarrierTopology,
    /// Regimes supported by design.  An empty list means "not established" and
    /// is therefore incompatible with every selection request.
    pub access_regimes: Vec<AccessRegime>,
    pub features: Vec<CarrierFeature>,
    /// Correlation domains used to avoid recommending a path whose shared
    /// provider/prefix/protocol is already known to be impaired.
    pub failure_domains: Vec<FailureDomain>,
    /// An operational cap, not a promise that all streams are independent.
    pub max_parallel_streams: Option<u32>,
}

impl CarrierCapabilities {
    pub fn supports_access_regime(&self, regime: AccessRegime) -> bool {
        self.access_regimes.contains(&regime)
    }
}

/// Lower/point/upper estimate.  The control plane validates the interval before
/// using it; malformed or non-finite telemetry is fail-closed.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EstimateBounds {
    pub lower: f64,
    pub point: f64,
    pub upper: f64,
}

impl EstimateBounds {
    pub const fn new(lower: f64, point: f64, upper: f64) -> Self {
        Self {
            lower,
            point,
            upper,
        }
    }

    pub fn is_ordered_and_finite(&self) -> bool {
        self.lower.is_finite()
            && self.point.is_finite()
            && self.upper.is_finite()
            && self.lower <= self.point
            && self.point <= self.upper
    }

    pub fn is_probability(&self) -> bool {
        self.is_ordered_and_finite() && self.lower >= 0.0 && self.upper <= 1.0
    }

    pub fn is_non_negative(&self) -> bool {
        self.is_ordered_and_finite() && self.lower >= 0.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierHealthState {
    Unknown,
    Healthy,
    Degraded,
    Unreachable,
    Closing,
    Closed,
}

/// Evidence backing an aggregated health estimate.
///
/// `minimum_successful_workload_bytes` is deliberately the *minimum* across
/// successful representative-workload probes.  Aggregators must report zero
/// when there are no successful probes.  This fail-closed statistic prevents a
/// single large success from hiding a collection of tiny successes; it is a
/// workload-quality check, not evidence of a censor byte threshold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSummary {
    pub probe_count: u32,
    pub successful_probes: u32,
    pub independent_windows: u32,
    pub successful_independent_windows: u32,
    pub minimum_successful_workload_bytes: u64,
    pub last_observation_unix_ms: Option<u64>,
    /// Newest successful representative workload in the retained evidence.
    /// Fresh failures must not make an old success appear fresh.
    pub last_successful_probe_unix_ms: Option<u64>,
}

/// Immutable health view consumed by the shadow selector.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierHealthSnapshot {
    pub carrier_id: CarrierId,
    /// Monotonic per-carrier sequence for diagnosing stale/reordered snapshots.
    pub sequence: u64,
    pub state: CarrierHealthState,
    /// Probability of completing the configured representative workload.
    pub reachability: EstimateBounds,
    /// Application goodput in bytes/second, measured through the carrier.
    pub goodput_bytes_per_second: EstimateBounds,
    pub evidence: EvidenceSummary,
    pub active_failure_domains: Vec<FailureDomain>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    Upload,
    Download,
    Bidirectional,
}

/// Raw observation accepted by a carrier-local estimator.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ObservationKind {
    Dial {
        succeeded: bool,
        latency_ms: Option<u64>,
    },
    VolumeProbe {
        succeeded: bool,
        bytes_received: u64,
        elapsed_ms: u64,
    },
    Transfer {
        direction: TransferDirection,
        bytes: u64,
        elapsed_ms: u64,
        completed: bool,
    },
    Failure {
        domain: FailureDomain,
        transient: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierObservation {
    pub carrier_id: CarrierId,
    pub observed_at_unix_ms: u64,
    pub observation: ObservationKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DialPurpose {
    UserTraffic,
    HealthProbe,
    CoverProbe,
    ControlPlane,
}

/// Logical stream target.  Carrier-specific rendezvous/relay endpoints remain
/// private to the carrier implementation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DialTarget {
    pub host: String,
    pub port: u16,
    pub server_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DialRequest {
    pub target: DialTarget,
    pub purpose: DialPurpose,
    pub deadline_unix_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierErrorKind {
    InvalidRequest,
    Unsupported,
    Timeout,
    Unreachable,
    Authentication,
    RateLimited,
    Closed,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierError {
    pub kind: CarrierErrorKind,
    pub message: String,
    pub failure_domain: Option<FailureDomain>,
}

impl CarrierError {
    pub fn new(kind: CarrierErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            failure_domain: None,
        }
    }

    pub fn in_domain(mut self, failure_domain: FailureDomain) -> Self {
        self.failure_domain = Some(failure_domain);
        self
    }
}

impl fmt::Display for CarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl Error for CarrierError {}

/// Object-safe carrier lifecycle.
///
/// There is intentionally no `activate`, `apply`, or route-mutating operation.
/// A control-plane recommendation cannot change traffic merely by holding a
/// `dyn Carrier`.
pub trait Carrier: Send + Sync {
    fn id(&self) -> &CarrierId;

    fn capabilities(&self) -> CarrierCapabilities;

    fn health_snapshot(&self) -> CarrierHealthSnapshot;

    /// Feed telemetry into the carrier-local estimator.  This is synchronous so
    /// observation ingestion cannot secretly become a lifecycle transition.
    fn observe(&self, observation: CarrierObservation) -> Result<(), CarrierError>;

    fn dial<'a>(
        &'a self,
        request: DialRequest,
    ) -> CarrierFuture<'a, Result<BoxedCarrierStream, CarrierError>>;

    fn close<'a>(&'a self) -> CarrierFuture<'a, Result<(), CarrierError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct TestCarrier {
        id: CarrierId,
        observations: Mutex<Vec<CarrierObservation>>,
    }

    impl TestCarrier {
        fn new() -> Self {
            Self {
                id: CarrierId::from("test"),
                observations: Mutex::new(Vec::new()),
            }
        }
    }

    impl Carrier for TestCarrier {
        fn id(&self) -> &CarrierId {
            &self.id
        }

        fn capabilities(&self) -> CarrierCapabilities {
            CarrierCapabilities {
                carrier_id: self.id.clone(),
                topology: CarrierTopology::Direct,
                access_regimes: vec![AccessRegime::OpenInternet],
                features: Vec::new(),
                failure_domains: Vec::new(),
                max_parallel_streams: Some(1),
            }
        }

        fn health_snapshot(&self) -> CarrierHealthSnapshot {
            CarrierHealthSnapshot {
                carrier_id: self.id.clone(),
                sequence: 1,
                state: CarrierHealthState::Healthy,
                reachability: EstimateBounds::new(0.8, 0.9, 1.0),
                goodput_bytes_per_second: EstimateBounds::new(1_000.0, 2_000.0, 3_000.0),
                evidence: EvidenceSummary {
                    probe_count: 3,
                    successful_probes: 3,
                    independent_windows: 2,
                    successful_independent_windows: 2,
                    minimum_successful_workload_bytes: 2 * 1024 * 1024,
                    last_observation_unix_ms: Some(1),
                    last_successful_probe_unix_ms: Some(1),
                },
                active_failure_domains: Vec::new(),
            }
        }

        fn observe(&self, observation: CarrierObservation) -> Result<(), CarrierError> {
            self.observations.lock().unwrap().push(observation);
            Ok(())
        }

        fn dial<'a>(
            &'a self,
            _request: DialRequest,
        ) -> CarrierFuture<'a, Result<BoxedCarrierStream, CarrierError>> {
            Box::pin(async move {
                let (stream, _peer) = tokio::io::duplex(64);
                Ok(Box::new(stream) as BoxedCarrierStream)
            })
        }

        fn close<'a>(&'a self) -> CarrierFuture<'a, Result<(), CarrierError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn trait_is_object_safe_without_async_trait() {
        fn accepts_object(_: &dyn Carrier) {}

        let carrier = TestCarrier::new();
        accepts_object(&carrier);
    }

    #[tokio::test]
    async fn dial_returns_type_erased_async_io() {
        let carrier = TestCarrier::new();
        let request = DialRequest {
            target: DialTarget {
                host: "example.test".into(),
                port: 443,
                server_name: Some("example.test".into()),
            },
            purpose: DialPurpose::HealthProbe,
            deadline_unix_ms: None,
        };

        let mut stream = carrier.dial(request).await.unwrap();
        use tokio::io::AsyncWriteExt;
        stream.shutdown().await.unwrap();
    }

    #[test]
    fn estimate_validation_is_fail_closed() {
        assert!(EstimateBounds::new(0.7, 0.8, 0.9).is_probability());
        assert!(!EstimateBounds::new(f64::NAN, 0.8, 0.9).is_probability());
        assert!(!EstimateBounds::new(0.9, 0.8, 1.0).is_probability());
        assert!(!EstimateBounds::new(-1.0, 0.0, 1.0).is_non_negative());
    }

    #[test]
    fn evidence_summary_rejects_unknown_fields() {
        let evidence = EvidenceSummary {
            probe_count: 3,
            successful_probes: 2,
            independent_windows: 2,
            successful_independent_windows: 1,
            minimum_successful_workload_bytes: 1024 * 1024,
            last_observation_unix_ms: Some(1),
            last_successful_probe_unix_ms: Some(1),
        };
        let mut value = serde_json::to_value(evidence).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("endpoint_ip".into(), serde_json::json!("192.0.2.1"));

        assert!(serde_json::from_value::<EvidenceSummary>(value).is_err());
    }
}
