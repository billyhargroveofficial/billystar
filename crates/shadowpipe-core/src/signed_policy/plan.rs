use std::net::SocketAddrV4;

use super::error::{PolicyError, Result};
use super::schema::{
    EndpointId, EndpointPolicyV2, MlKemFingerprint, ServiceId, MAX_PINS_PER_SERVICE,
    MAX_SHORT_ID_BYTES,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedServerPins {
    fingerprints: [MlKemFingerprint; MAX_PINS_PER_SERVICE],
    len: u8,
}

impl VerifiedServerPins {
    pub(crate) fn new(pins: &[MlKemFingerprint]) -> Result<Self> {
        if pins.is_empty() || pins.len() > MAX_PINS_PER_SERVICE {
            return Err(PolicyError::invalid(format!(
                "verified plan requires 1..={MAX_PINS_PER_SERVICE} server pins"
            )));
        }
        let mut fingerprints = [[0u8; 32]; MAX_PINS_PER_SERVICE];
        fingerprints[..pins.len()].copy_from_slice(pins);
        Ok(Self {
            fingerprints,
            len: pins.len() as u8,
        })
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn as_slice(&self) -> &[MlKemFingerprint] {
        &self.fingerprints[..self.len()]
    }

    /// Matches every configured pin without an early return.  This avoids
    /// disclosing the matching overlap slot through comparison timing.
    pub fn matches(&self, candidate: &MlKemFingerprint) -> bool {
        let mut matched = 0u8;
        for fingerprint in self.as_slice() {
            matched |= crate::crypto::ct_eq(fingerprint, candidate) as u8;
        }
        matched != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRealityEndpoint {
    service_id: ServiceId,
    endpoint_id: EndpointId,
    socket_addr: SocketAddrV4,
    locator_name: String,
    sni: String,
    reality_x25519_public_key: [u8; 32],
    reality_short_id: [u8; MAX_SHORT_ID_BYTES],
    reality_short_id_len: u8,
    server_pins: VerifiedServerPins,
}

impl VerifiedRealityEndpoint {
    pub fn service_id(&self) -> ServiceId {
        self.service_id
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    pub fn socket_addr(&self) -> SocketAddrV4 {
        self.socket_addr
    }

    /// Signed DNS locator used by the scheduler. This is deliberately
    /// independent from the REALITY handshake SNI.
    pub fn locator_name(&self) -> &str {
        &self.locator_name
    }

    pub fn sni(&self) -> &str {
        &self.sni
    }

    pub fn reality_x25519_public_key(&self) -> &[u8; 32] {
        &self.reality_x25519_public_key
    }

    pub fn reality_short_id(&self) -> &[u8] {
        &self.reality_short_id[..self.reality_short_id_len as usize]
    }

    pub fn server_pins(&self) -> &VerifiedServerPins {
        &self.server_pins
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRealityPlan {
    policy_epoch: u64,
    sequence: u64,
    expires_at: i64,
    endpoints: Vec<VerifiedRealityEndpoint>,
}

impl VerifiedRealityPlan {
    pub fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub fn endpoints(&self) -> &[VerifiedRealityEndpoint] {
        &self.endpoints
    }
}

pub(crate) fn build_verified_plan(policy: &EndpointPolicyV2) -> Result<VerifiedRealityPlan> {
    let endpoint_count: usize = policy
        .services
        .iter()
        .map(|service| service.endpoints.len())
        .sum();
    let mut endpoints = Vec::with_capacity(endpoint_count);

    for service in &policy.services {
        let fingerprints: Vec<_> = service.pins.iter().map(|pin| pin.fingerprint).collect();
        let server_pins = VerifiedServerPins::new(&fingerprints)?;
        for endpoint in &service.endpoints {
            let mut short_id = [0u8; MAX_SHORT_ID_BYTES];
            short_id[..endpoint.reality_short_id.len()].copy_from_slice(&endpoint.reality_short_id);
            endpoints.push(VerifiedRealityEndpoint {
                service_id: service.service_id,
                endpoint_id: endpoint.endpoint_id,
                socket_addr: SocketAddrV4::new(endpoint.ipv4, endpoint.port),
                locator_name: endpoint.locator_name.clone(),
                sni: endpoint.sni.clone(),
                reality_x25519_public_key: endpoint.reality_x25519_public_key,
                reality_short_id: short_id,
                reality_short_id_len: endpoint.reality_short_id.len() as u8,
                server_pins: server_pins.clone(),
            });
        }
    }

    Ok(VerifiedRealityPlan {
        policy_epoch: policy.policy_epoch,
        sequence: policy.sequence,
        expires_at: policy.expires_at,
        endpoints,
    })
}
