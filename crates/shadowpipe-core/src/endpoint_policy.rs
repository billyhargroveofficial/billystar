//! Capability-safe adapter from a verified signed REALITY plan to live DNS
//! endpoint coordination.
//!
//! A [`VerifiedRealityPlan`] is the only construction input.  DNS can select an
//! address already present in the signed authority for one logical endpoint,
//! but it cannot construct authentication material, move an address between
//! authentication groups, or create a new registry entry.  The dialer receives
//! immutable [`VerifiedRealityDialTarget`] values only after a complete
//! [`DialCandidate`] has been checked against the private registry.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::endpoint::{
    AddressPolicy, AuthConfigRef, CarrierProtocol, DialCandidate, EndpointCoordinator,
    LogicalEndpoint, LogicalEndpointId, SeedCandidate, VerifiedIpv4Authority,
};
use crate::session::ServerPins;
use crate::signed_policy::{VerifiedRealityEndpoint, VerifiedRealityPlan};

const AUTH_REF_DOMAIN: &[u8] = b"shadowpipe-endpoint-auth-ref-v2\0";
const LOGICAL_ID_DOMAIN: &[u8] = b"shadowpipe-logical-endpoint-id-v2\0";
const AUTHORITY_DOMAIN: &[u8] = b"shadowpipe-endpoint-authority-v2\0";

/// Full, collision-free signed-policy generation retained beside the
/// coordinator's compact `u64` compatibility token.
///
/// Epoch and sequence are deliberately not packed into a `u64`: doing so would
/// either truncate one component or impose an artificial 32-bit policy limit.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VerifiedPolicyGeneration {
    policy_epoch: u64,
    sequence: u64,
}

impl VerifiedPolicyGeneration {
    fn from_plan(plan: &VerifiedRealityPlan) -> Self {
        Self {
            policy_epoch: plan.policy_epoch(),
            sequence: plan.sequence(),
        }
    }

    pub fn policy_epoch(self) -> u64 {
        self.policy_epoch
    }

    pub fn sequence(self) -> u64 {
        self.sequence
    }

    pub fn as_tuple(self) -> (u64, u64) {
        (self.policy_epoch, self.sequence)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AuthGroupKey {
    locator_name: String,
    sni: String,
    port: u16,
    reality_x25519_public_key: [u8; 32],
    reality_short_id: Vec<u8>,
    server_pins: Vec<[u8; 32]>,
}

impl AuthGroupKey {
    fn from_verified_endpoint(endpoint: &VerifiedRealityEndpoint) -> Result<Self> {
        anyhow::ensure!(
            !endpoint.locator_name().is_empty(),
            "verified REALITY endpoint unexpectedly has empty locator name"
        );
        anyhow::ensure!(
            !endpoint.sni().is_empty(),
            "verified REALITY endpoint unexpectedly has empty SNI"
        );
        anyhow::ensure!(
            endpoint.socket_addr().port() != 0,
            "verified REALITY endpoint unexpectedly has zero port"
        );
        anyhow::ensure!(
            endpoint.reality_short_id().len() == crate::signed_policy::MAX_SHORT_ID_BYTES,
            "verified REALITY endpoint unexpectedly lacks a full-width short id"
        );
        anyhow::ensure!(
            !endpoint.server_pins().is_empty(),
            "verified REALITY endpoint unexpectedly has empty server-pin set"
        );
        Ok(Self {
            locator_name: endpoint.locator_name().to_owned(),
            sni: endpoint.sni().to_owned(),
            port: endpoint.socket_addr().port(),
            reality_x25519_public_key: *endpoint.reality_x25519_public_key(),
            reality_short_id: endpoint.reality_short_id().to_vec(),
            server_pins: endpoint.server_pins().as_slice().to_vec(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegistryEntry {
    logical: LogicalEndpointId,
    auth: AuthConfigRef,
    authority_generation: u64,
    authority_digest: [u8; 32],
    authorized_addresses: BTreeSet<Ipv4Addr>,
    sni: String,
    port: u16,
    reality_x25519_public_key: [u8; 32],
    reality_short_id: Vec<u8>,
    server_pins: ServerPins,
}

/// Immutable authentication registry created only from a verified signed plan.
///
/// `AuthConfigRef` is an identifier, not ambient authority.  A caller cannot
/// gain a dial target by inventing a reference: [`Self::lookup`] checks every
/// candidate field, the logical-to-auth binding, the exact signed address set,
/// the transport, port, and authority generation before releasing material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRealityAuthRegistry {
    policy_generation: VerifiedPolicyGeneration,
    entries: BTreeMap<AuthConfigRef, RegistryEntry>,
    logical_to_auth: BTreeMap<LogicalEndpointId, AuthConfigRef>,
}

impl VerifiedRealityAuthRegistry {
    pub fn policy_generation(&self) -> VerifiedPolicyGeneration {
        self.policy_generation
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn auth_refs(&self) -> impl Iterator<Item = AuthConfigRef> + '_ {
        self.entries.keys().copied()
    }

    /// Convert a coordinator candidate into an authenticated, immutable dial
    /// target.  No partial target is returned on a failed check.
    pub fn lookup(&self, candidate: &DialCandidate) -> Result<VerifiedRealityDialTarget> {
        let entry = self.entries.get(&candidate.auth).with_context(|| {
            format!(
                "dial candidate references unknown authentication config {:?}",
                candidate.auth
            )
        })?;
        anyhow::ensure!(
            self.logical_to_auth.get(&candidate.key.logical) == Some(&candidate.auth),
            "dial candidate logical endpoint is not bound to its authentication config"
        );
        anyhow::ensure!(
            entry.logical == candidate.key.logical && entry.auth == candidate.auth,
            "dial candidate crosses a logical/authentication group boundary"
        );
        anyhow::ensure!(
            candidate.protocol == CarrierProtocol::Tcp,
            "verified REALITY target requires TCP"
        );
        anyhow::ensure!(
            candidate.key.ip == *candidate.address.ip(),
            "dial candidate key/address IPv4 mismatch"
        );
        anyhow::ensure!(
            candidate.address.port() == entry.port,
            "dial candidate port differs from signed REALITY port"
        );
        anyhow::ensure!(
            entry.authorized_addresses.contains(&candidate.key.ip),
            "dial candidate IPv4 is outside the exact signed authority"
        );
        anyhow::ensure!(
            candidate.authority_generation == entry.authority_generation,
            "dial candidate authority generation is stale or foreign"
        );

        Ok(VerifiedRealityDialTarget {
            policy_generation: self.policy_generation,
            logical: entry.logical,
            auth: entry.auth,
            authority_digest: entry.authority_digest,
            address: candidate.address,
            sni: entry.sni.clone(),
            reality_x25519_public_key: entry.reality_x25519_public_key,
            reality_short_id: entry.reality_short_id.clone(),
            server_pins: entry.server_pins,
        })
    }
}

/// A fully checked REALITY/TCP dial target.  All fields are private and there
/// is intentionally no public constructor or mutator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRealityDialTarget {
    policy_generation: VerifiedPolicyGeneration,
    logical: LogicalEndpointId,
    auth: AuthConfigRef,
    authority_digest: [u8; 32],
    address: SocketAddrV4,
    sni: String,
    reality_x25519_public_key: [u8; 32],
    reality_short_id: Vec<u8>,
    server_pins: ServerPins,
}

impl VerifiedRealityDialTarget {
    pub fn policy_generation(&self) -> VerifiedPolicyGeneration {
        self.policy_generation
    }

    pub fn logical_endpoint_id(&self) -> LogicalEndpointId {
        self.logical
    }

    pub fn auth_config_ref(&self) -> AuthConfigRef {
        self.auth
    }

    /// Full SHA-256 authority identity, binding epoch, sequence, authentication
    /// group and the complete sorted signed IPv4 set.
    pub fn authority_digest(&self) -> &[u8; 32] {
        &self.authority_digest
    }

    pub fn address(&self) -> SocketAddrV4 {
        self.address
    }

    pub fn sni(&self) -> &str {
        &self.sni
    }

    pub fn reality_x25519_public_key(&self) -> &[u8; 32] {
        &self.reality_x25519_public_key
    }

    pub fn reality_short_id(&self) -> &[u8] {
        &self.reality_short_id
    }

    pub fn server_pins(&self) -> &ServerPins {
        &self.server_pins
    }
}

/// Coordinator, immutable authentication registry and DNS scheduling metadata
/// derived atomically from one verified plan.
pub struct VerifiedEndpointPolicy {
    policy_generation: VerifiedPolicyGeneration,
    coordinator: EndpointCoordinator,
    auth_registry: VerifiedRealityAuthRegistry,
    scheduler_endpoints: Vec<(LogicalEndpointId, String)>,
}

impl VerifiedEndpointPolicy {
    pub fn from_verified_plan(plan: &VerifiedRealityPlan, now_ms: u64) -> Result<Self> {
        anyhow::ensure!(
            !plan.endpoints().is_empty(),
            "verified REALITY plan has no endpoints"
        );
        let policy_generation = VerifiedPolicyGeneration::from_plan(plan);
        let mut seen_endpoint_ids = BTreeSet::new();
        let mut groups = BTreeMap::<AuthGroupKey, BTreeSet<Ipv4Addr>>::new();

        for endpoint in plan.endpoints() {
            anyhow::ensure!(
                seen_endpoint_ids.insert(endpoint.endpoint_id()),
                "duplicate verified endpoint id {:?}",
                endpoint.endpoint_id()
            );
            let group = AuthGroupKey::from_verified_endpoint(endpoint)?;
            let inserted = groups
                .entry(group)
                .or_default()
                .insert(*endpoint.socket_addr().ip());
            anyhow::ensure!(
                inserted,
                "duplicate signed IPv4 mapping inside one REALITY authentication group"
            );
        }
        anyhow::ensure!(!groups.is_empty(), "verified REALITY plan grouped to empty");

        let mut auth_ref_digests = BTreeMap::<AuthConfigRef, [u8; 32]>::new();
        let mut logical_id_digests = BTreeMap::<LogicalEndpointId, [u8; 32]>::new();
        let mut authority_token_digests = BTreeMap::<u64, [u8; 32]>::new();
        let mut entries = BTreeMap::new();
        let mut logical_to_auth = BTreeMap::new();
        let mut endpoints = Vec::with_capacity(groups.len());
        let mut seeds = Vec::with_capacity(plan.endpoints().len());
        let mut scheduler_endpoints = Vec::with_capacity(groups.len());

        for (group, addresses) in groups {
            let auth_digest = auth_group_digest(AUTH_REF_DOMAIN, &group);
            let auth = AuthConfigRef(first_u32(&auth_digest));
            reject_identifier_collision(&mut auth_ref_digests, auth, auth_digest, "AuthConfigRef")?;

            let logical_digest = auth_group_digest(LOGICAL_ID_DOMAIN, &group);
            let logical = LogicalEndpointId(first_u64(&logical_digest));
            reject_identifier_collision(
                &mut logical_id_digests,
                logical,
                logical_digest,
                "LogicalEndpointId",
            )?;

            let authority_digest = authority_digest(policy_generation, &group, &addresses);
            let authority_generation = first_u64(&authority_digest);
            reject_identifier_collision(
                &mut authority_token_digests,
                authority_generation,
                authority_digest,
                "authority generation token",
            )?;

            let authority = VerifiedIpv4Authority::from_preverified_manifest(
                authority_generation,
                addresses.iter().copied(),
            )?;
            let server_pins = ServerPins::new(&group.server_pins)
                .context("verified plan produced an invalid runtime server-pin set")?;

            endpoints.push(LogicalEndpoint {
                id: logical,
                hostname: group.locator_name.clone(),
                port: group.port,
                protocol: CarrierProtocol::Tcp,
                auth,
                authority,
                address_policy: AddressPolicy::default(),
            });
            seeds.extend(
                addresses
                    .iter()
                    .copied()
                    .map(|ip| SeedCandidate { logical, ip }),
            );
            scheduler_endpoints.push((logical, group.locator_name.clone()));

            let entry = RegistryEntry {
                logical,
                auth,
                authority_generation,
                authority_digest,
                authorized_addresses: addresses,
                sni: group.sni,
                port: group.port,
                reality_x25519_public_key: group.reality_x25519_public_key,
                reality_short_id: group.reality_short_id,
                server_pins,
            };
            anyhow::ensure!(
                entries.insert(auth, entry).is_none(),
                "duplicate or ambiguous authentication registry mapping"
            );
            anyhow::ensure!(
                logical_to_auth.insert(logical, auth).is_none(),
                "duplicate or ambiguous logical endpoint mapping"
            );
        }

        scheduler_endpoints.sort();
        let coordinator = EndpointCoordinator::new(endpoints, seeds, now_ms)?;
        let auth_registry = VerifiedRealityAuthRegistry {
            policy_generation,
            entries,
            logical_to_auth,
        };
        debug_assert!(!auth_registry.is_empty());
        debug_assert!(!scheduler_endpoints.is_empty());

        Ok(Self {
            policy_generation,
            coordinator,
            auth_registry,
            scheduler_endpoints,
        })
    }

    pub fn policy_generation(&self) -> VerifiedPolicyGeneration {
        self.policy_generation
    }

    pub fn coordinator(&self) -> &EndpointCoordinator {
        &self.coordinator
    }

    pub fn coordinator_mut(&mut self) -> &mut EndpointCoordinator {
        &mut self.coordinator
    }

    pub fn auth_registry(&self) -> &VerifiedRealityAuthRegistry {
        &self.auth_registry
    }

    pub fn scheduler_endpoints(&self) -> &[(LogicalEndpointId, String)] {
        &self.scheduler_endpoints
    }

    pub fn into_parts(
        self,
    ) -> (
        EndpointCoordinator,
        VerifiedRealityAuthRegistry,
        Vec<(LogicalEndpointId, String)>,
    ) {
        (
            self.coordinator,
            self.auth_registry,
            self.scheduler_endpoints,
        )
    }
}

fn reject_identifier_collision<K: Copy + Ord + std::fmt::Debug>(
    occupied: &mut BTreeMap<K, [u8; 32]>,
    compact: K,
    full_digest: [u8; 32],
    what: &str,
) -> Result<()> {
    if let Some(previous) = occupied.insert(compact, full_digest) {
        anyhow::bail!(
            "duplicate or truncated-digest collision for {what} {compact:?}: {} versus {}",
            hex::encode(previous),
            hex::encode(full_digest)
        );
    }
    Ok(())
}

fn auth_group_digest(domain: &[u8], group: &AuthGroupKey) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    update_auth_group(&mut digest, group);
    digest.finalize().into()
}

fn authority_digest(
    generation: VerifiedPolicyGeneration,
    group: &AuthGroupKey,
    addresses: &BTreeSet<Ipv4Addr>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(AUTHORITY_DOMAIN);
    digest.update(generation.policy_epoch.to_be_bytes());
    digest.update(generation.sequence.to_be_bytes());
    update_auth_group(&mut digest, group);
    digest.update((addresses.len() as u64).to_be_bytes());
    for address in addresses {
        digest.update(address.octets());
    }
    digest.finalize().into()
}

fn update_auth_group(digest: &mut Sha256, group: &AuthGroupKey) {
    update_length_prefixed(digest, group.locator_name.as_bytes());
    update_length_prefixed(digest, group.sni.as_bytes());
    digest.update(group.port.to_be_bytes());
    digest.update(group.reality_x25519_public_key);
    update_length_prefixed(digest, &group.reality_short_id);
    digest.update((group.server_pins.len() as u64).to_be_bytes());
    for pin in &group.server_pins {
        digest.update(pin);
    }
}

fn update_length_prefixed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn first_u32(digest: &[u8; 32]) -> u32 {
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

fn first_u64(digest: &[u8; 32]) -> u64 {
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{AddressRecord, ObservationDisposition, ResolutionObservation};
    use crate::signed_policy::{
        encode_bundle, encode_keyset_payload, encode_policy_payload, encode_protected_header,
        encode_sign1, keyset_payload_hash, signature_structure, verify_bundle, BundleBytes,
        ContentType, EndpointId, EndpointPolicyV2, KeyStatus, KeysetV1, Kid, OnlineKeyV1,
        PinStatus, PolicyRuleV2, ProtectedHeader, RealityEndpointV2, RuleAction, ServerPinV2,
        ServiceId, ServiceV2, TransportV2, TrustedRoot, VerifiedBundle,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::convert::TryInto;

    const NOW: i64 = 2_000_000_000;
    const DAY: i64 = 24 * 60 * 60;
    const ROOT_KID: Kid = Kid([0x10; 16]);
    const ONLINE_KID: Kid = Kid([0x20; 16]);
    const PIN_A: [u8; 32] = [0x50; 32];
    const PIN_B: [u8; 32] = [0x51; 32];
    const KEY_A: [u8; 32] = [0x60; 32];
    const KEY_B: [u8; 32] = [0x61; 32];

    fn key_pair(byte: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[byte; 32]).unwrap()
    }

    fn public_key(pair: &Ed25519KeyPair) -> [u8; 32] {
        pair.public_key().as_ref().try_into().unwrap()
    }

    fn sign1(
        content_type: ContentType,
        kid: Kid,
        payload: &[u8],
        pair: &Ed25519KeyPair,
    ) -> Vec<u8> {
        let protected = encode_protected_header(&ProtectedHeader { content_type, kid }).unwrap();
        let input = signature_structure(&protected, payload).unwrap();
        let signature: [u8; 64] = pair.sign(&input).as_ref().try_into().unwrap();
        encode_sign1(&protected, payload, &signature).unwrap()
    }

    fn pin(fingerprint: [u8; 32]) -> ServerPinV2 {
        ServerPinV2 {
            fingerprint,
            not_before: NOW - 60,
            expires_at: NOW + 60 * DAY,
            status: PinStatus::Active,
            status_since: NOW - 60,
        }
    }

    fn endpoint(
        id: u8,
        ip: Ipv4Addr,
        sni: &str,
        port: u16,
        public_key: [u8; 32],
        short_id: &[u8],
    ) -> RealityEndpointV2 {
        endpoint_with_locator(id, ip, sni, sni, port, public_key, short_id)
    }

    fn endpoint_with_locator(
        id: u8,
        ip: Ipv4Addr,
        locator_name: &str,
        sni: &str,
        port: u16,
        public_key: [u8; 32],
        short_id: &[u8],
    ) -> RealityEndpointV2 {
        RealityEndpointV2 {
            endpoint_id: EndpointId([id; 16]),
            transport: TransportV2::RealityTcp,
            ipv4: ip,
            port,
            locator_name: locator_name.into(),
            sni: sni.into(),
            reality_x25519_public_key: public_key,
            reality_short_id: short_id.to_vec(),
        }
    }

    fn service(id: u8, pins: Vec<[u8; 32]>, endpoints: Vec<RealityEndpointV2>) -> ServiceV2 {
        ServiceV2 {
            service_id: ServiceId([id; 16]),
            pins: pins.into_iter().map(pin).collect(),
            endpoints,
        }
    }

    fn policy(services: Vec<ServiceV2>) -> EndpointPolicyV2 {
        let service_ids = services.iter().map(|service| service.service_id).collect();
        EndpointPolicyV2 {
            keyset_epoch: 3,
            keyset_payload_hash: [0; 32],
            policy_epoch: 7,
            sequence: 9,
            issued_at: NOW,
            not_before: NOW - 60,
            expires_at: NOW + 6 * DAY,
            previous_payload_hash: None,
            services,
            rules: vec![PolicyRuleV2 {
                action: RuleAction::ProtectedOnly,
                service_ids,
            }],
            experiment_evidence: Vec::new(),
        }
    }

    fn verify_policy(mut policy: EndpointPolicyV2) -> crate::signed_policy::Result<VerifiedBundle> {
        let root = key_pair(1);
        let online = key_pair(2);
        let keyset = KeysetV1 {
            keyset_epoch: 3,
            issued_at: NOW,
            not_before: NOW - 60,
            expires_at: NOW + 60 * DAY,
            previous_payload_hash: None,
            keys: vec![OnlineKeyV1 {
                kid: ONLINE_KID,
                ed25519_public_key: public_key(&online),
                not_before: NOW - 60,
                expires_at: NOW + 60 * DAY,
                status: KeyStatus::Active,
                status_since: NOW - 60,
            }],
        };
        let keyset_payload = encode_keyset_payload(&keyset)?;
        policy.keyset_epoch = keyset.keyset_epoch;
        policy.keyset_payload_hash = keyset_payload_hash(&keyset_payload);
        let policy_payload = encode_policy_payload(&policy)?;
        let bundle = encode_bundle(&BundleBytes {
            keyset_sign1: sign1(ContentType::Keyset, ROOT_KID, &keyset_payload, &root),
            policy_sign1: sign1(
                ContentType::EndpointPolicy,
                ONLINE_KID,
                &policy_payload,
                &online,
            ),
        })?;
        verify_bundle(
            &bundle,
            &TrustedRoot {
                kid: ROOT_KID,
                ed25519_public_key: public_key(&root),
            },
            NOW,
        )
    }

    #[test]
    fn identical_authentication_material_groups_all_signed_ips() {
        let first = Ipv4Addr::new(203, 0, 113, 10);
        let second = Ipv4Addr::new(203, 0, 113, 11);
        let verified = verify_policy(policy(vec![service(
            0x30,
            vec![PIN_A],
            vec![
                endpoint(0x40, first, "cdn.example.com", 443, KEY_A, &[0x70; 8]),
                endpoint(0x41, second, "cdn.example.com", 443, KEY_A, &[0x70; 8]),
            ],
        )]))
        .unwrap();
        let adapter = VerifiedEndpointPolicy::from_verified_plan(verified.plan(), 1_000).unwrap();

        assert_eq!(adapter.policy_generation().as_tuple(), (7, 9));
        assert_eq!(adapter.scheduler_endpoints().len(), 1);
        assert_eq!(adapter.auth_registry().len(), 1);
        let snapshot = adapter.coordinator().snapshot();
        assert_eq!(snapshot.candidates.len(), 2);
        let ips: BTreeSet<_> = snapshot
            .candidates
            .iter()
            .map(|candidate| candidate.key.ip)
            .collect();
        assert_eq!(ips, BTreeSet::from([first, second]));
        assert_eq!(
            snapshot.candidates[0].key.logical,
            snapshot.candidates[1].key.logical
        );
        assert_eq!(snapshot.candidates[0].auth, snapshot.candidates[1].auth);
        for candidate in &snapshot.candidates {
            let target = adapter.auth_registry().lookup(candidate).unwrap();
            assert_eq!(target.address(), candidate.address);
            assert_eq!(target.sni(), "cdn.example.com");
            assert_eq!(target.reality_x25519_public_key(), &KEY_A);
            assert_eq!(target.reality_short_id(), &[0x70; 8]);
            assert_eq!(target.policy_generation().as_tuple(), (7, 9));
        }
    }

    #[test]
    fn scheduler_resolves_locator_while_dial_target_retains_distinct_sni() {
        let ip = Ipv4Addr::new(203, 0, 113, 15);
        let verified = verify_policy(policy(vec![service(
            0x30,
            vec![PIN_A],
            vec![endpoint_with_locator(
                0x40,
                ip,
                "locator.shadowpipe.example",
                "cover.example.com",
                443,
                KEY_A,
                &[0x70; 8],
            )],
        )]))
        .unwrap();
        let adapter = VerifiedEndpointPolicy::from_verified_plan(verified.plan(), 0).unwrap();

        assert_eq!(
            adapter.scheduler_endpoints()[0].1,
            "locator.shadowpipe.example"
        );
        let candidate = &adapter.coordinator().snapshot().candidates[0];
        let target = adapter.auth_registry().lookup(candidate).unwrap();
        assert_eq!(target.sni(), "cover.example.com");
        assert_ne!(adapter.scheduler_endpoints()[0].1, target.sni());
    }

    #[test]
    fn locator_and_handshake_auth_each_define_group_boundaries() {
        let ip = Ipv4Addr::new(203, 0, 113, 16);
        let verified = verify_policy(policy(vec![service(
            0x30,
            vec![PIN_A],
            vec![
                endpoint_with_locator(
                    0x40,
                    ip,
                    "one.shadowpipe.example",
                    "cover.example.com",
                    443,
                    KEY_A,
                    &[0x70; 8],
                ),
                endpoint_with_locator(
                    0x41,
                    ip,
                    "two.shadowpipe.example",
                    "cover.example.com",
                    443,
                    KEY_A,
                    &[0x70; 8],
                ),
                endpoint_with_locator(
                    0x42,
                    ip,
                    "one.shadowpipe.example",
                    "other-cover.example.com",
                    443,
                    KEY_A,
                    &[0x70; 8],
                ),
            ],
        )]))
        .unwrap();
        let adapter = VerifiedEndpointPolicy::from_verified_plan(verified.plan(), 0).unwrap();
        let snapshot = adapter.coordinator().snapshot();

        assert_eq!(adapter.scheduler_endpoints().len(), 3);
        assert_eq!(adapter.auth_registry().len(), 3);
        assert_eq!(snapshot.candidates.len(), 3);
        assert_eq!(
            snapshot
                .candidates
                .iter()
                .map(|candidate| candidate.auth)
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
        assert_eq!(
            snapshot
                .candidates
                .iter()
                .map(|candidate| candidate.key.logical)
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
        assert_eq!(
            snapshot
                .candidates
                .iter()
                .map(|candidate| candidate.authority_generation)
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
        assert_eq!(
            snapshot
                .candidates
                .iter()
                .map(|candidate| *adapter
                    .auth_registry()
                    .lookup(candidate)
                    .unwrap()
                    .authority_digest())
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
    }

    #[test]
    fn same_ip_with_different_auth_remains_distinct() {
        let shared_ip = Ipv4Addr::new(203, 0, 113, 20);
        let verified = verify_policy(policy(vec![service(
            0x30,
            vec![PIN_A],
            vec![
                endpoint(0x40, shared_ip, "alpha.example.com", 443, KEY_A, &[0x70; 8]),
                endpoint(0x41, shared_ip, "beta.example.com", 443, KEY_B, &[0x71; 8]),
            ],
        )]))
        .unwrap();
        let adapter = VerifiedEndpointPolicy::from_verified_plan(verified.plan(), 0).unwrap();
        let snapshot = adapter.coordinator().snapshot();
        assert_eq!(snapshot.candidates.len(), 2);
        assert_ne!(
            snapshot.candidates[0].key.logical,
            snapshot.candidates[1].key.logical
        );
        assert_ne!(snapshot.candidates[0].auth, snapshot.candidates[1].auth);
        assert!(snapshot
            .candidates
            .iter()
            .all(|candidate| candidate.key.ip == shared_ip));

        let targets: BTreeSet<_> = snapshot
            .candidates
            .iter()
            .map(|candidate| {
                let target = adapter.auth_registry().lookup(candidate).unwrap();
                (target.sni().to_owned(), *target.reality_x25519_public_key())
            })
            .collect();
        assert_eq!(
            targets,
            BTreeSet::from([
                ("alpha.example.com".to_owned(), KEY_A),
                ("beta.example.com".to_owned(), KEY_B),
            ])
        );
    }

    #[test]
    fn dns_cannot_cross_an_authentication_group_or_forge_a_target() {
        let alpha_ip = Ipv4Addr::new(203, 0, 113, 30);
        let beta_ip = Ipv4Addr::new(203, 0, 113, 31);
        let verified = verify_policy(policy(vec![service(
            0x30,
            vec![PIN_A],
            vec![
                endpoint(0x40, alpha_ip, "alpha.example.com", 443, KEY_A, &[0x70; 8]),
                endpoint(0x41, beta_ip, "beta.example.com", 443, KEY_B, &[0x71; 8]),
            ],
        )]))
        .unwrap();
        let mut adapter = VerifiedEndpointPolicy::from_verified_plan(verified.plan(), 0).unwrap();
        let alpha_logical = adapter
            .scheduler_endpoints()
            .iter()
            .find(|(_, hostname)| hostname == "alpha.example.com")
            .unwrap()
            .0;
        let registry_before = adapter.auth_registry().clone();
        let snapshot_before = adapter.coordinator().snapshot();
        let stamp = adapter
            .coordinator_mut()
            .begin_query(alpha_logical)
            .unwrap();
        let prepared = adapter
            .coordinator()
            .prepare_observation(
                stamp,
                ResolutionObservation::Positive(vec![AddressRecord {
                    ip: beta_ip,
                    ttl_secs: 60,
                }]),
                10,
                0,
            )
            .unwrap();
        assert_eq!(
            prepared.result().disposition,
            ObservationDisposition::RejectedOutsideAuthority(vec![beta_ip])
        );
        adapter.coordinator().abort_observation(prepared).unwrap();
        assert_eq!(
            adapter.coordinator().snapshot().as_ref(),
            snapshot_before.as_ref()
        );
        assert_eq!(adapter.auth_registry(), &registry_before);

        let candidates = &snapshot_before.candidates;
        let alpha = candidates
            .iter()
            .find(|candidate| candidate.key.logical == alpha_logical)
            .unwrap();
        let beta = candidates
            .iter()
            .find(|candidate| candidate.key.logical != alpha_logical)
            .unwrap();
        let mut forged = alpha.clone();
        forged.auth = beta.auth;
        assert!(adapter.auth_registry().lookup(&forged).is_err());
        forged = alpha.clone();
        forged.address = SocketAddrV4::new(beta_ip, forged.address.port());
        forged.key.ip = beta_ip;
        assert!(adapter.auth_registry().lookup(&forged).is_err());
    }

    #[test]
    fn pin_set_is_preserved_exactly_in_order_and_cardinality() {
        let verified = verify_policy(policy(vec![service(
            0x30,
            vec![PIN_A, PIN_B],
            vec![endpoint(
                0x40,
                Ipv4Addr::new(203, 0, 113, 40),
                "pins.example.com",
                443,
                KEY_A,
                &[0x70; 8],
            )],
        )]))
        .unwrap();
        let adapter = VerifiedEndpointPolicy::from_verified_plan(verified.plan(), 0).unwrap();
        let snapshot = adapter.coordinator().snapshot();
        let target = adapter
            .auth_registry()
            .lookup(&snapshot.candidates[0])
            .unwrap();
        assert_eq!(target.server_pins().as_slice(), &[PIN_A, PIN_B]);
        assert!(target.server_pins().matches(&PIN_A));
        assert!(target.server_pins().matches(&PIN_B));
        assert!(!target.server_pins().matches(&[0x52; 32]));
    }

    #[test]
    fn registry_and_identifiers_are_deterministic() {
        let verified = verify_policy(policy(vec![service(
            0x30,
            vec![PIN_A],
            vec![
                endpoint(
                    0x40,
                    Ipv4Addr::new(203, 0, 113, 50),
                    "one.example.com",
                    443,
                    KEY_A,
                    &[0x70; 8],
                ),
                endpoint(
                    0x41,
                    Ipv4Addr::new(203, 0, 113, 51),
                    "two.example.com",
                    8443,
                    KEY_B,
                    &[0x71; 8],
                ),
            ],
        )]))
        .unwrap();
        let first = VerifiedEndpointPolicy::from_verified_plan(verified.plan(), 123).unwrap();
        let second = VerifiedEndpointPolicy::from_verified_plan(verified.plan(), 123).unwrap();
        assert_eq!(first.policy_generation(), second.policy_generation());
        assert_eq!(first.scheduler_endpoints(), second.scheduler_endpoints());
        assert_eq!(first.auth_registry(), second.auth_registry());
        assert_eq!(
            first.coordinator().snapshot().as_ref(),
            second.coordinator().snapshot().as_ref()
        );
        assert_eq!(
            first.auth_registry().auth_refs().collect::<Vec<_>>(),
            second.auth_registry().auth_refs().collect::<Vec<_>>()
        );
    }

    #[test]
    fn auth_ref_stays_stable_while_policy_generation_remains_full_width() {
        let make_policy = || {
            policy(vec![service(
                0x30,
                vec![PIN_A],
                vec![endpoint(
                    0x40,
                    Ipv4Addr::new(203, 0, 113, 55),
                    "stable.example.com",
                    443,
                    KEY_A,
                    &[0x70; 8],
                )],
            )])
        };
        let first_verified = verify_policy(make_policy()).unwrap();
        let mut next_policy = make_policy();
        next_policy.policy_epoch = u64::MAX;
        next_policy.sequence = u64::MAX - 1;
        let next_verified = verify_policy(next_policy).unwrap();
        let first = VerifiedEndpointPolicy::from_verified_plan(first_verified.plan(), 0).unwrap();
        let next = VerifiedEndpointPolicy::from_verified_plan(next_verified.plan(), 0).unwrap();
        let first_snapshot = first.coordinator().snapshot();
        let next_snapshot = next.coordinator().snapshot();
        let first_candidate = &first_snapshot.candidates[0];
        let next_candidate = &next_snapshot.candidates[0];

        assert_eq!(first_candidate.auth, next_candidate.auth);
        assert_eq!(first_candidate.key.logical, next_candidate.key.logical);
        assert_ne!(
            first_candidate.authority_generation,
            next_candidate.authority_generation
        );
        let next_target = next.auth_registry().lookup(next_candidate).unwrap();
        assert_eq!(
            next_target.policy_generation().as_tuple(),
            (u64::MAX, u64::MAX - 1)
        );
        assert_ne!(
            first
                .auth_registry()
                .lookup(first_candidate)
                .unwrap()
                .authority_digest(),
            next_target.authority_digest()
        );
    }

    #[test]
    fn empty_and_duplicate_mapping_cannot_reach_the_adapter() {
        assert!(verify_policy(policy(Vec::new())).is_err());

        let duplicate_ip = Ipv4Addr::new(203, 0, 113, 60);
        let duplicate = policy(vec![service(
            0x30,
            vec![PIN_A],
            vec![
                endpoint(
                    0x40,
                    duplicate_ip,
                    "duplicate.example.com",
                    443,
                    KEY_A,
                    &[0x70; 8],
                ),
                endpoint(
                    0x41,
                    duplicate_ip,
                    "duplicate.example.com",
                    443,
                    KEY_A,
                    &[0x70; 8],
                ),
            ],
        )]);
        assert!(verify_policy(duplicate).is_err());
    }
}
