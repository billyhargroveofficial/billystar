use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::cbor::{decode_bundle, decode_keyset_payload, decode_policy_payload};
use super::cose::{inspect_sign1, verify_sign1, ContentType};
use super::error::{PolicyError, Result};
use super::plan::{build_verified_plan, VerifiedRealityPlan};
use super::schema::{
    EndpointId, EndpointPolicyV2, KeyStatus, KeysetV1, Kid, PinStatus, ServiceId, TrustedRoot,
    KEYSET_MAX_TTL_SECS, MAX_CLOCK_SKEW_SECS, MAX_SHORT_ID_BYTES, MAX_TOTAL_ENDPOINTS,
    POLICY_MAX_TTL_SECS,
};

const KEYSET_HASH_DOMAIN: &[u8] = b"shadowpipe-keyset-v1\0";
const POLICY_HASH_DOMAIN: &[u8] = b"shadowpipe-policy-v2\0";
const ROOT_ID_DOMAIN: &[u8] = b"shadowpipe-policy-root-v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBundle {
    pub(crate) root_id: [u8; 32],
    pub(crate) keyset: KeysetV1,
    pub(crate) policy: EndpointPolicyV2,
    pub(crate) keyset_hash: [u8; 32],
    pub(crate) policy_hash: [u8; 32],
    pub(crate) signer_kid: Kid,
    pub(crate) plan: VerifiedRealityPlan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedKeysetArtifact {
    root_id: [u8; 32],
    keyset: KeysetV1,
    payload_hash: [u8; 32],
}

impl VerifiedKeysetArtifact {
    pub fn root_id(&self) -> &[u8; 32] {
        &self.root_id
    }

    pub fn keyset(&self) -> &KeysetV1 {
        &self.keyset
    }

    pub fn payload_hash(&self) -> &[u8; 32] {
        &self.payload_hash
    }
}

impl VerifiedBundle {
    pub fn root_id(&self) -> &[u8; 32] {
        &self.root_id
    }

    pub fn keyset(&self) -> &KeysetV1 {
        &self.keyset
    }

    pub fn policy(&self) -> &EndpointPolicyV2 {
        &self.policy
    }

    pub fn keyset_hash(&self) -> &[u8; 32] {
        &self.keyset_hash
    }

    pub fn policy_hash(&self) -> &[u8; 32] {
        &self.policy_hash
    }

    pub fn signer_kid(&self) -> Kid {
        self.signer_kid
    }

    pub fn plan(&self) -> &VerifiedRealityPlan {
        &self.plan
    }

    pub fn into_plan(self) -> VerifiedRealityPlan {
        self.plan
    }
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(payload);
    hash.finalize().into()
}

pub fn keyset_payload_hash(canonical_payload: &[u8]) -> [u8; 32] {
    domain_hash(KEYSET_HASH_DOMAIN, canonical_payload)
}

pub fn policy_payload_hash(canonical_payload: &[u8]) -> [u8; 32] {
    domain_hash(POLICY_HASH_DOMAIN, canonical_payload)
}

pub fn trusted_root_id(root: &TrustedRoot) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(ROOT_ID_DOMAIN);
    hash.update(root.kid.as_bytes());
    hash.update(root.ed25519_public_key);
    hash.finalize().into()
}

fn validate_window(
    what: &'static str,
    issued_at: i64,
    not_before: i64,
    expires_at: i64,
    now: i64,
    maximum_ttl: i64,
) -> Result<()> {
    if issued_at < 0 || not_before < 0 || expires_at < 0 {
        return Err(PolicyError::invalid(format!(
            "{what} timestamps must be non-negative Unix seconds"
        )));
    }
    if issued_at < not_before || issued_at >= expires_at {
        return Err(PolicyError::invalid(format!(
            "{what} issued_at must fall inside its validity window"
        )));
    }
    let ttl = expires_at
        .checked_sub(not_before)
        .ok_or_else(|| PolicyError::invalid(format!("{what} validity window overflows i64")))?;
    if ttl <= 0 || ttl > maximum_ttl {
        return Err(PolicyError::invalid(format!(
            "{what} TTL is {ttl} seconds; permitted range is 1..={maximum_ttl}"
        )));
    }
    if issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(PolicyError::invalid(format!(
            "{what} issued_at exceeds the allowed future-clock skew"
        )));
    }
    if now < not_before {
        return Err(PolicyError::NotYetValid(what));
    }
    if now >= expires_at {
        return Err(PolicyError::Expired(what));
    }
    Ok(())
}

fn validate_keyset(keyset: &KeysetV1, now: i64) -> Result<()> {
    validate_window(
        "online-key set",
        keyset.issued_at,
        keyset.not_before,
        keyset.expires_at,
        now,
        KEYSET_MAX_TTL_SECS,
    )?;
    if keyset.keys.is_empty() {
        return Err(PolicyError::invalid("online-key set is empty"));
    }

    let mut previous_kid = None;
    let mut public_keys = BTreeSet::new();
    let mut usable_active_key = false;
    for key in &keyset.keys {
        if let Some(previous) = previous_kid {
            if key.kid <= previous {
                return Err(PolicyError::invalid(
                    "online keys must be strictly sorted by unique kid",
                ));
            }
        }
        previous_kid = Some(key.kid);
        if !public_keys.insert(key.ed25519_public_key) {
            return Err(PolicyError::invalid(
                "the same Ed25519 public key appears under multiple kids",
            ));
        }
        if key.ed25519_public_key == [0u8; 32] {
            return Err(PolicyError::invalid(
                "online Ed25519 public key is all zero",
            ));
        }
        if key.not_before < keyset.not_before || key.expires_at > keyset.expires_at {
            return Err(PolicyError::invalid(
                "online-key lifetime is not contained by its root-signed keyset",
            ));
        }
        if key.not_before >= key.expires_at {
            return Err(PolicyError::invalid(
                "online-key not_before must precede expires_at",
            ));
        }
        if key.status_since < key.not_before || key.status_since > keyset.issued_at {
            return Err(PolicyError::invalid(
                "online-key status_since is outside its signed history",
            ));
        }
        if key.status == KeyStatus::Active && now >= key.not_before && now < key.expires_at {
            usable_active_key = true;
        }
    }
    if !usable_active_key {
        return Err(PolicyError::invalid(
            "online-key set has no currently usable active key",
        ));
    }
    Ok(())
}

pub fn verify_keyset_artifact(
    sign1: &[u8],
    root: &TrustedRoot,
    now: i64,
) -> Result<VerifiedKeysetArtifact> {
    if root.ed25519_public_key == [0u8; 32] {
        return Err(PolicyError::invalid(
            "offline root Ed25519 public key is all zero",
        ));
    }
    let payload = verify_sign1(
        sign1,
        ContentType::Keyset,
        root.kid,
        &root.ed25519_public_key,
    )?;
    let keyset = decode_keyset_payload(&payload)?;
    validate_keyset(&keyset, now)?;
    Ok(VerifiedKeysetArtifact {
        root_id: trusted_root_id(root),
        keyset,
        payload_hash: keyset_payload_hash(&payload),
    })
}

fn validate_canonical_dns_name(value: &str, what: &'static str) -> Result<()> {
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return Err(PolicyError::invalid(format!(
            "{what} must be a non-empty ASCII DNS name of at most 253 bytes"
        )));
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) || value.ends_with('.') {
        return Err(PolicyError::invalid(format!(
            "{what} must be lower-case canonical DNS form without a trailing dot"
        )));
    }
    let labels: Vec<_> = value.split('.').collect();
    if labels.len() < 2 {
        return Err(PolicyError::invalid(format!(
            "{what} must contain at least two DNS labels"
        )));
    }
    for label in labels {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || !bytes[0].is_ascii_alphanumeric()
            || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
            || bytes
                .iter()
                .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && *byte != b'-')
        {
            return Err(PolicyError::invalid(format!(
                "{what} contains an invalid DNS label {label:?}"
            )));
        }
    }
    Ok(())
}

fn validate_policy(policy: &EndpointPolicyV2, now: i64) -> Result<()> {
    validate_window(
        "endpoint policy",
        policy.issued_at,
        policy.not_before,
        policy.expires_at,
        now,
        POLICY_MAX_TTL_SECS,
    )?;
    if policy.services.is_empty() {
        return Err(PolicyError::invalid("endpoint policy has no services"));
    }

    let mut previous_service_id: Option<ServiceId> = None;
    let mut service_ids = Vec::with_capacity(policy.services.len());
    let mut endpoint_ids = BTreeSet::<EndpointId>::new();
    let mut endpoint_tuples = BTreeSet::new();
    let mut total_endpoints = 0usize;
    for service in &policy.services {
        if let Some(previous) = previous_service_id {
            if service.service_id <= previous {
                return Err(PolicyError::invalid(
                    "services must be strictly sorted by unique service_id",
                ));
            }
        }
        previous_service_id = Some(service.service_id);
        service_ids.push(service.service_id);

        if service.pins.is_empty() {
            return Err(PolicyError::invalid("service has no ML-KEM server pin"));
        }
        let mut previous_fingerprint = None;
        let mut has_active_pin = false;
        for pin in &service.pins {
            if let Some(previous) = previous_fingerprint {
                if pin.fingerprint <= previous {
                    return Err(PolicyError::invalid(
                        "server pins must be strictly sorted by unique fingerprint",
                    ));
                }
            }
            previous_fingerprint = Some(pin.fingerprint);
            if pin.fingerprint == [0u8; 32] {
                return Err(PolicyError::invalid("ML-KEM server pin is all zero"));
            }
            if pin.not_before > policy.not_before || pin.expires_at < policy.expires_at {
                return Err(PolicyError::invalid(
                    "ML-KEM server-pin lifetime must cover the complete policy lifetime",
                ));
            }
            if pin.not_before >= pin.expires_at
                || pin.status_since < pin.not_before
                || pin.status_since > policy.issued_at
            {
                return Err(PolicyError::invalid(
                    "ML-KEM server-pin timestamps are inconsistent",
                ));
            }
            has_active_pin |= pin.status == PinStatus::Active;
        }
        if !has_active_pin {
            return Err(PolicyError::invalid(
                "service has no active ML-KEM server pin",
            ));
        }

        if service.endpoints.is_empty() {
            return Err(PolicyError::invalid("service has no REALITY/TCP endpoint"));
        }
        let mut previous_endpoint_id = None;
        for endpoint in &service.endpoints {
            if let Some(previous) = previous_endpoint_id {
                if endpoint.endpoint_id <= previous {
                    return Err(PolicyError::invalid(
                        "service endpoints must be strictly sorted by unique endpoint_id",
                    ));
                }
            }
            previous_endpoint_id = Some(endpoint.endpoint_id);
            if !endpoint_ids.insert(endpoint.endpoint_id) {
                return Err(PolicyError::invalid(
                    "endpoint_id must be globally unique across the policy",
                ));
            }
            total_endpoints += 1;
            if total_endpoints > MAX_TOTAL_ENDPOINTS {
                return Err(PolicyError::invalid(format!(
                    "endpoint policy exceeds the global {MAX_TOTAL_ENDPOINTS}-endpoint bound"
                )));
            }
            if endpoint.port == 0 {
                return Err(PolicyError::invalid("REALITY/TCP endpoint port is zero"));
            }
            if endpoint.ipv4.is_unspecified()
                || endpoint.ipv4.is_loopback()
                || endpoint.ipv4.is_link_local()
                || endpoint.ipv4.is_multicast()
                || endpoint.ipv4.octets() == [255, 255, 255, 255]
            {
                return Err(PolicyError::invalid(
                    "REALITY/TCP endpoint uses a non-routable special IPv4 address",
                ));
            }
            validate_canonical_dns_name(&endpoint.locator_name, "locator_name")?;
            validate_canonical_dns_name(&endpoint.sni, "SNI")?;
            if !crate::reality::reality_public_key_is_contributory(
                &endpoint.reality_x25519_public_key,
            ) {
                return Err(PolicyError::invalid(
                    "REALITY X25519 public key is a non-contributory low-order point",
                ));
            }
            if endpoint.reality_short_id.len() != MAX_SHORT_ID_BYTES {
                return Err(PolicyError::invalid(format!(
                    "production REALITY short id must be exactly {MAX_SHORT_ID_BYTES} bytes"
                )));
            }
            if !endpoint_tuples.insert((
                endpoint.locator_name.clone(),
                endpoint.ipv4,
                endpoint.port,
                endpoint.sni.clone(),
            )) {
                return Err(PolicyError::invalid(
                    "duplicate REALITY/TCP locator, IPv4, port, and SNI tuple",
                ));
            }
        }
    }

    if policy.rules.len() != 1 {
        return Err(PolicyError::invalid(
            "v2 policy must contain exactly one PROTECTED_ONLY rule",
        ));
    }
    let rule = &policy.rules[0];
    if rule.service_ids != service_ids {
        return Err(PolicyError::invalid(
            "PROTECTED_ONLY rule must name every service exactly once in sorted order",
        ));
    }
    if policy
        .experiment_evidence
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(PolicyError::invalid(
            "experiment evidence hashes must be strictly sorted and unique",
        ));
    }
    Ok(())
}

pub fn verify_bundle(input: &[u8], root: &TrustedRoot, now: i64) -> Result<VerifiedBundle> {
    let bundle = decode_bundle(input)?;
    let verified_keyset = verify_keyset_artifact(&bundle.keyset_sign1, root, now)?;
    let keyset = verified_keyset.keyset;
    let keyset_hash = verified_keyset.payload_hash;

    let policy_envelope = inspect_sign1(&bundle.policy_sign1)?;
    if policy_envelope.header.content_type != ContentType::EndpointPolicy {
        return Err(PolicyError::invalid(
            "policy COSE_Sign1 carries the wrong content type",
        ));
    }
    let signer_kid = policy_envelope.header.kid;
    let signer = keyset
        .keys
        .iter()
        .find(|key| key.kid == signer_kid)
        .ok_or_else(|| PolicyError::invalid("policy signer kid is absent from the keyset"))?;
    if signer.status != KeyStatus::Active {
        return Err(PolicyError::invalid(
            "candidate policy signer key must be active; retiring/revoked keys verify only historical bundles",
        ));
    }
    if now < signer.not_before {
        return Err(PolicyError::NotYetValid("policy signer key"));
    }
    if now >= signer.expires_at {
        return Err(PolicyError::Expired("policy signer key"));
    }
    let policy_payload = verify_sign1(
        &bundle.policy_sign1,
        ContentType::EndpointPolicy,
        signer_kid,
        &signer.ed25519_public_key,
    )?;
    let policy = decode_policy_payload(&policy_payload)?;
    validate_policy(&policy, now)?;

    if policy.keyset_epoch != keyset.keyset_epoch {
        return Err(PolicyError::invalid(
            "policy references a different keyset epoch",
        ));
    }
    if policy.keyset_payload_hash != keyset_hash {
        return Err(PolicyError::invalid(
            "policy keyset hash does not match the root-signed keyset payload",
        ));
    }
    if policy.issued_at < keyset.issued_at
        || policy.not_before < keyset.not_before
        || policy.expires_at > keyset.expires_at
    {
        return Err(PolicyError::invalid(
            "policy lifetime is not contained by its root-signed keyset",
        ));
    }
    if policy.not_before < signer.not_before || policy.expires_at > signer.expires_at {
        return Err(PolicyError::invalid(
            "policy lifetime is not contained by its online signing key",
        ));
    }

    let policy_hash = policy_payload_hash(&policy_payload);
    let plan = build_verified_plan(&policy)?;
    Ok(VerifiedBundle {
        root_id: verified_keyset.root_id,
        keyset,
        policy,
        keyset_hash,
        policy_hash,
        signer_kid,
        plan,
    })
}
