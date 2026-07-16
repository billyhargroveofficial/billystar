use std::net::Ipv4Addr;

pub const MAX_BUNDLE_BYTES: usize = 64 * 1024;
pub const MAX_SIGN1_BYTES: usize = 60 * 1024;
pub const MAX_KEYSET_KEYS: usize = 16;
pub const MAX_SERVICES: usize = 16;
pub const MAX_ENDPOINTS_PER_SERVICE: usize = 16;
pub const MAX_TOTAL_ENDPOINTS: usize = 32;
pub const MAX_PINS_PER_SERVICE: usize = 3;
pub const MAX_EVIDENCE_REFS: usize = 16;
pub const MAX_SNI_BYTES: usize = 253;
pub const MAX_LOCATOR_NAME_BYTES: usize = 253;
pub const MAX_SHORT_ID_BYTES: usize = 8;

pub const MAX_CLOCK_SKEW_SECS: i64 = 5 * 60;
pub const POLICY_MAX_TTL_SECS: i64 = 7 * 24 * 60 * 60;
pub const KEYSET_MAX_TTL_SECS: i64 = 90 * 24 * 60 * 60;
pub const MIN_ROTATION_OVERLAP_SECS: i64 = 24 * 60 * 60;

pub const KEYSET_SCHEMA_VERSION: u64 = 1;
pub const POLICY_SCHEMA_VERSION: u64 = 2;
pub const KEYSET_OBJECT_KIND: u64 = 1;
pub const POLICY_OBJECT_KIND: u64 = 2;

macro_rules! fixed_id {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub const fn new(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }
    };
}

fixed_id!(Kid, 16);
fixed_id!(ServiceId, 16);
fixed_id!(EndpointId, 16);
fixed_id!(EvidenceHash, 32);

pub type PayloadHash = [u8; 32];
pub type Ed25519PublicKey = [u8; 32];
pub type MlKemFingerprint = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KeyStatus {
    Active = 1,
    Retiring = 2,
    Revoked = 3,
}

impl TryFrom<u64> for KeyStatus {
    type Error = ();

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Retiring),
            3 => Ok(Self::Revoked),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PinStatus {
    Active = 1,
    Retiring = 2,
}

impl TryFrom<u64> for PinStatus {
    type Error = ();

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Retiring),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TransportV2 {
    RealityTcp = 1,
}

impl TryFrom<u64> for TransportV2 {
    type Error = ();

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::RealityTcp),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuleAction {
    ProtectedOnly = 1,
}

impl TryFrom<u64> for RuleAction {
    type Error = ();

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ProtectedOnly),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedRoot {
    pub kid: Kid,
    pub ed25519_public_key: Ed25519PublicKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnlineKeyV1 {
    pub kid: Kid,
    pub ed25519_public_key: Ed25519PublicKey,
    pub not_before: i64,
    pub expires_at: i64,
    pub status: KeyStatus,
    /// Signed time at which the current status began.  Rotation transitions
    /// require this to equal the containing keyset's `issued_at`.
    pub status_since: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeysetV1 {
    pub keyset_epoch: u64,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub previous_payload_hash: Option<PayloadHash>,
    pub keys: Vec<OnlineKeyV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerPinV2 {
    pub fingerprint: MlKemFingerprint,
    pub not_before: i64,
    pub expires_at: i64,
    pub status: PinStatus,
    pub status_since: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealityEndpointV2 {
    pub endpoint_id: EndpointId,
    pub transport: TransportV2,
    pub ipv4: Ipv4Addr,
    pub port: u16,
    /// Canonical DNS name used only to locate signed endpoint addresses.
    pub locator_name: String,
    /// Canonical REALITY server name used only by the authenticated handshake.
    pub sni: String,
    pub reality_x25519_public_key: [u8; 32],
    pub reality_short_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceV2 {
    pub service_id: ServiceId,
    pub pins: Vec<ServerPinV2>,
    pub endpoints: Vec<RealityEndpointV2>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRuleV2 {
    pub action: RuleAction,
    pub service_ids: Vec<ServiceId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointPolicyV2 {
    pub keyset_epoch: u64,
    pub keyset_payload_hash: PayloadHash,
    pub policy_epoch: u64,
    pub sequence: u64,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub previous_payload_hash: Option<PayloadHash>,
    pub services: Vec<ServiceV2>,
    pub rules: Vec<PolicyRuleV2>,
    pub experiment_evidence: Vec<EvidenceHash>,
}
