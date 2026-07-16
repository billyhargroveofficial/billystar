//! Strict, fail-closed signed endpoint policy for the production REALITY/TCP path.
//!
//! This module deliberately implements one small protocol profile rather than a
//! general-purpose COSE stack.  A bundle contains an offline-root-signed keyset
//! and an online-key-signed endpoint-policy v2. The keyset remains v1. Both
//! payloads use deterministic CBOR, and the verifier requires byte-for-byte
//! canonical re-encoding before a value can reach the state-transition or
//! connection-plan layers. Policy v2 keeps DNS `locator_name` authority
//! separate from the REALITY handshake `sni`; policy v1 is never upgraded or
//! interpreted by fallback.

mod cbor;
mod cose;
mod error;
mod plan;
mod schema;
mod state;
mod verify;

pub use cbor::{
    decode_bundle, decode_keyset_payload, decode_policy_payload, encode_bundle,
    encode_keyset_payload, encode_policy_payload, BundleBytes,
};
pub use cose::{
    encode_protected_header, encode_sign1, signature_structure, ContentType, ProtectedHeader,
};
pub use error::{PolicyError, Result};
pub use plan::{VerifiedRealityEndpoint, VerifiedRealityPlan, VerifiedServerPins};
pub use schema::{
    EndpointId, EndpointPolicyV2, EvidenceHash, KeyStatus, KeysetV1, Kid, OnlineKeyV1, PinStatus,
    PolicyRuleV2, RealityEndpointV2, RuleAction, ServerPinV2, ServiceId, ServiceV2, TransportV2,
    TrustedRoot, KEYSET_MAX_TTL_SECS, KEYSET_SCHEMA_VERSION, MAX_BUNDLE_BYTES, MAX_CLOCK_SKEW_SECS,
    MAX_SHORT_ID_BYTES, MIN_ROTATION_OVERLAP_SECS, POLICY_MAX_TTL_SECS, POLICY_SCHEMA_VERSION,
};
pub use state::{
    apply_verified_successor, apply_verified_update, validate_keyset_successor,
    AcceptedPolicyState, Transition,
};
pub use verify::{
    keyset_payload_hash, policy_payload_hash, trusted_root_id, verify_bundle,
    verify_keyset_artifact, VerifiedBundle, VerifiedKeysetArtifact,
};

#[cfg(test)]
mod tests;
