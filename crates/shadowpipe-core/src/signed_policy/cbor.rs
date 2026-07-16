use std::convert::TryInto;

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};

use super::error::{PolicyError, Result};
use super::schema::{
    EndpointId, EndpointPolicyV2, EvidenceHash, KeyStatus, KeysetV1, Kid, OnlineKeyV1, PinStatus,
    PolicyRuleV2, RealityEndpointV2, RuleAction, ServerPinV2, ServiceId, ServiceV2, TransportV2,
    KEYSET_OBJECT_KIND, KEYSET_SCHEMA_VERSION, MAX_BUNDLE_BYTES, MAX_ENDPOINTS_PER_SERVICE,
    MAX_EVIDENCE_REFS, MAX_KEYSET_KEYS, MAX_LOCATOR_NAME_BYTES, MAX_PINS_PER_SERVICE, MAX_SERVICES,
    MAX_SHORT_ID_BYTES, MAX_SIGN1_BYTES, MAX_SNI_BYTES, MAX_TOTAL_ENDPOINTS, POLICY_OBJECT_KIND,
    POLICY_SCHEMA_VERSION,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleBytes {
    pub keyset_sign1: Vec<u8>,
    pub policy_sign1: Vec<u8>,
}

fn enc<T, E: std::fmt::Display>(value: std::result::Result<T, E>) -> Result<T> {
    value.map_err(PolicyError::decode)
}

fn dec<T>(value: std::result::Result<T, minicbor::decode::Error>) -> Result<T> {
    value.map_err(PolicyError::decode)
}

fn expect_map(decoder: &mut Decoder<'_>, expected: u64, what: &'static str) -> Result<()> {
    match dec(decoder.map())? {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(PolicyError::invalid(format!(
            "{what} map has {actual} fields; expected {expected}"
        ))),
        None => Err(PolicyError::invalid(format!(
            "{what} uses an indefinite-length map"
        ))),
    }
}

fn expect_array(decoder: &mut Decoder<'_>, maximum: usize, what: &'static str) -> Result<usize> {
    match dec(decoder.array())? {
        Some(actual) if actual as usize <= maximum => Ok(actual as usize),
        Some(actual) => Err(PolicyError::invalid(format!(
            "{what} has {actual} entries; maximum is {maximum}"
        ))),
        None => Err(PolicyError::invalid(format!(
            "{what} uses an indefinite-length array"
        ))),
    }
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u64, what: &'static str) -> Result<()> {
    let actual = dec(decoder.u64())?;
    if actual != expected {
        return Err(PolicyError::invalid(format!(
            "{what} expected field {expected}, found {actual}; unknown, duplicate, or out-of-order field"
        )));
    }
    Ok(())
}

fn fixed_bytes<const N: usize>(decoder: &mut Decoder<'_>, what: &'static str) -> Result<[u8; N]> {
    let value = dec(decoder.bytes())?;
    value.try_into().map_err(|_| {
        PolicyError::invalid(format!(
            "{what} is {} bytes; expected exactly {N}",
            value.len()
        ))
    })
}

fn optional_hash(decoder: &mut Decoder<'_>, what: &'static str) -> Result<Option<[u8; 32]>> {
    match dec(decoder.datatype())? {
        Type::Null => {
            dec(decoder.null())?;
            Ok(None)
        }
        Type::Bytes => Ok(Some(fixed_bytes(decoder, what)?)),
        other => Err(PolicyError::invalid(format!(
            "{what} must be null or bstr32, found {other:?}"
        ))),
    }
}

fn finish(decoder: &Decoder<'_>, input: &[u8], what: &'static str) -> Result<()> {
    if decoder.position() != input.len() {
        return Err(PolicyError::invalid(format!(
            "{what} has {} trailing bytes",
            input.len() - decoder.position()
        )));
    }
    Ok(())
}

fn ensure_canonical(actual: &[u8], canonical: Vec<u8>, what: &'static str) -> Result<()> {
    if actual != canonical {
        return Err(PolicyError::NonCanonical(what));
    }
    Ok(())
}

fn encode_online_key(encoder: &mut Encoder<Vec<u8>>, key: &OnlineKeyV1) -> Result<()> {
    enc(encoder.map(6))?;
    enc(encoder.u8(1))?;
    enc(encoder.bytes(key.kid.as_bytes()))?;
    enc(encoder.u8(2))?;
    enc(encoder.bytes(&key.ed25519_public_key))?;
    enc(encoder.u8(3))?;
    enc(encoder.i64(key.not_before))?;
    enc(encoder.u8(4))?;
    enc(encoder.i64(key.expires_at))?;
    enc(encoder.u8(5))?;
    enc(encoder.u8(key.status as u8))?;
    enc(encoder.u8(6))?;
    enc(encoder.i64(key.status_since))?;
    Ok(())
}

fn decode_online_key(decoder: &mut Decoder<'_>) -> Result<OnlineKeyV1> {
    expect_map(decoder, 6, "online key")?;
    expect_key(decoder, 1, "online key")?;
    let kid = Kid(fixed_bytes(decoder, "online key kid")?);
    expect_key(decoder, 2, "online key")?;
    let ed25519_public_key = fixed_bytes(decoder, "online Ed25519 public key")?;
    expect_key(decoder, 3, "online key")?;
    let not_before = dec(decoder.i64())?;
    expect_key(decoder, 4, "online key")?;
    let expires_at = dec(decoder.i64())?;
    expect_key(decoder, 5, "online key")?;
    let raw_status = dec(decoder.u64())?;
    let status = KeyStatus::try_from(raw_status)
        .map_err(|_| PolicyError::invalid(format!("unknown online key status {raw_status}")))?;
    expect_key(decoder, 6, "online key")?;
    let status_since = dec(decoder.i64())?;
    Ok(OnlineKeyV1 {
        kid,
        ed25519_public_key,
        not_before,
        expires_at,
        status,
        status_since,
    })
}

pub fn encode_keyset_payload(keyset: &KeysetV1) -> Result<Vec<u8>> {
    if keyset.keys.len() > MAX_KEYSET_KEYS {
        return Err(PolicyError::invalid(format!(
            "online key array has {} entries; maximum is {MAX_KEYSET_KEYS}",
            keyset.keys.len()
        )));
    }
    let mut encoder = Encoder::new(Vec::new());
    enc(encoder.map(8))?;
    enc(encoder.u8(1))?;
    enc(encoder.u8(KEYSET_SCHEMA_VERSION as u8))?;
    enc(encoder.u8(2))?;
    enc(encoder.u8(KEYSET_OBJECT_KIND as u8))?;
    enc(encoder.u8(3))?;
    enc(encoder.u64(keyset.keyset_epoch))?;
    enc(encoder.u8(4))?;
    enc(encoder.i64(keyset.issued_at))?;
    enc(encoder.u8(5))?;
    enc(encoder.i64(keyset.not_before))?;
    enc(encoder.u8(6))?;
    enc(encoder.i64(keyset.expires_at))?;
    enc(encoder.u8(7))?;
    match keyset.previous_payload_hash {
        Some(hash) => {
            enc(encoder.bytes(&hash))?;
        }
        None => {
            enc(encoder.null())?;
        }
    }
    enc(encoder.u8(8))?;
    enc(encoder.array(keyset.keys.len() as u64))?;
    for key in &keyset.keys {
        encode_online_key(&mut encoder, key)?;
    }
    let encoded = encoder.into_writer();
    if encoded.len() > MAX_SIGN1_BYTES {
        return Err(PolicyError::TooLarge {
            what: "keyset payload",
            actual: encoded.len(),
            maximum: MAX_SIGN1_BYTES,
        });
    }
    Ok(encoded)
}

pub fn decode_keyset_payload(input: &[u8]) -> Result<KeysetV1> {
    if input.len() > MAX_SIGN1_BYTES {
        return Err(PolicyError::TooLarge {
            what: "keyset payload",
            actual: input.len(),
            maximum: MAX_SIGN1_BYTES,
        });
    }
    let mut decoder = Decoder::new(input);
    expect_map(&mut decoder, 8, "keyset")?;
    expect_key(&mut decoder, 1, "keyset")?;
    let schema = dec(decoder.u64())?;
    if schema != KEYSET_SCHEMA_VERSION {
        return Err(PolicyError::invalid(format!(
            "unsupported keyset schema {schema}"
        )));
    }
    expect_key(&mut decoder, 2, "keyset")?;
    let kind = dec(decoder.u64())?;
    if kind != KEYSET_OBJECT_KIND {
        return Err(PolicyError::invalid(format!(
            "keyset object kind is {kind}, expected {KEYSET_OBJECT_KIND}"
        )));
    }
    expect_key(&mut decoder, 3, "keyset")?;
    let keyset_epoch = dec(decoder.u64())?;
    expect_key(&mut decoder, 4, "keyset")?;
    let issued_at = dec(decoder.i64())?;
    expect_key(&mut decoder, 5, "keyset")?;
    let not_before = dec(decoder.i64())?;
    expect_key(&mut decoder, 6, "keyset")?;
    let expires_at = dec(decoder.i64())?;
    expect_key(&mut decoder, 7, "keyset")?;
    let previous_payload_hash = optional_hash(&mut decoder, "previous keyset payload hash")?;
    expect_key(&mut decoder, 8, "keyset")?;
    let count = expect_array(&mut decoder, MAX_KEYSET_KEYS, "online key array")?;
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        keys.push(decode_online_key(&mut decoder)?);
    }
    finish(&decoder, input, "keyset payload")?;
    let value = KeysetV1 {
        keyset_epoch,
        issued_at,
        not_before,
        expires_at,
        previous_payload_hash,
        keys,
    };
    ensure_canonical(input, encode_keyset_payload(&value)?, "keyset payload")?;
    Ok(value)
}

fn encode_pin(encoder: &mut Encoder<Vec<u8>>, pin: &ServerPinV2) -> Result<()> {
    enc(encoder.map(5))?;
    enc(encoder.u8(1))?;
    enc(encoder.bytes(&pin.fingerprint))?;
    enc(encoder.u8(2))?;
    enc(encoder.i64(pin.not_before))?;
    enc(encoder.u8(3))?;
    enc(encoder.i64(pin.expires_at))?;
    enc(encoder.u8(4))?;
    enc(encoder.u8(pin.status as u8))?;
    enc(encoder.u8(5))?;
    enc(encoder.i64(pin.status_since))?;
    Ok(())
}

fn decode_pin(decoder: &mut Decoder<'_>) -> Result<ServerPinV2> {
    expect_map(decoder, 5, "server pin")?;
    expect_key(decoder, 1, "server pin")?;
    let fingerprint = fixed_bytes(decoder, "ML-KEM fingerprint")?;
    expect_key(decoder, 2, "server pin")?;
    let not_before = dec(decoder.i64())?;
    expect_key(decoder, 3, "server pin")?;
    let expires_at = dec(decoder.i64())?;
    expect_key(decoder, 4, "server pin")?;
    let raw_status = dec(decoder.u64())?;
    let status = PinStatus::try_from(raw_status)
        .map_err(|_| PolicyError::invalid(format!("unknown server pin status {raw_status}")))?;
    expect_key(decoder, 5, "server pin")?;
    let status_since = dec(decoder.i64())?;
    Ok(ServerPinV2 {
        fingerprint,
        not_before,
        expires_at,
        status,
        status_since,
    })
}

fn encode_endpoint(encoder: &mut Encoder<Vec<u8>>, endpoint: &RealityEndpointV2) -> Result<()> {
    enc(encoder.map(8))?;
    enc(encoder.u8(1))?;
    enc(encoder.bytes(endpoint.endpoint_id.as_bytes()))?;
    enc(encoder.u8(2))?;
    enc(encoder.u8(endpoint.transport as u8))?;
    enc(encoder.u8(3))?;
    enc(encoder.bytes(&endpoint.ipv4.octets()))?;
    enc(encoder.u8(4))?;
    enc(encoder.u16(endpoint.port))?;
    enc(encoder.u8(5))?;
    enc(encoder.str(&endpoint.locator_name))?;
    enc(encoder.u8(6))?;
    enc(encoder.str(&endpoint.sni))?;
    enc(encoder.u8(7))?;
    enc(encoder.bytes(&endpoint.reality_x25519_public_key))?;
    enc(encoder.u8(8))?;
    enc(encoder.bytes(&endpoint.reality_short_id))?;
    Ok(())
}

fn decode_endpoint(decoder: &mut Decoder<'_>) -> Result<RealityEndpointV2> {
    expect_map(decoder, 8, "REALITY endpoint")?;
    expect_key(decoder, 1, "REALITY endpoint")?;
    let endpoint_id = EndpointId(fixed_bytes(decoder, "endpoint id")?);
    expect_key(decoder, 2, "REALITY endpoint")?;
    let raw_transport = dec(decoder.u64())?;
    let transport = TransportV2::try_from(raw_transport).map_err(|_| {
        PolicyError::invalid(format!(
            "unsupported transport {raw_transport}; v2 permits REALITY_TCP only"
        ))
    })?;
    expect_key(decoder, 3, "REALITY endpoint")?;
    let ipv4 = std::net::Ipv4Addr::from(fixed_bytes(decoder, "endpoint IPv4")?);
    expect_key(decoder, 4, "REALITY endpoint")?;
    let port = dec(decoder.u16())?;
    expect_key(decoder, 5, "REALITY endpoint")?;
    let locator_name = dec(decoder.str())?;
    if locator_name.len() > MAX_LOCATOR_NAME_BYTES {
        return Err(PolicyError::invalid(format!(
            "locator name is {} bytes; maximum is {MAX_LOCATOR_NAME_BYTES}",
            locator_name.len()
        )));
    }
    let locator_name = locator_name.to_owned();
    expect_key(decoder, 6, "REALITY endpoint")?;
    let sni = dec(decoder.str())?;
    if sni.len() > MAX_SNI_BYTES {
        return Err(PolicyError::invalid(format!(
            "SNI is {} bytes; maximum is {MAX_SNI_BYTES}",
            sni.len()
        )));
    }
    let sni = sni.to_owned();
    expect_key(decoder, 7, "REALITY endpoint")?;
    let reality_x25519_public_key = fixed_bytes(decoder, "REALITY X25519 public key")?;
    expect_key(decoder, 8, "REALITY endpoint")?;
    let reality_short_id = dec(decoder.bytes())?;
    if reality_short_id.len() > MAX_SHORT_ID_BYTES {
        return Err(PolicyError::invalid(format!(
            "REALITY short id is {} bytes; maximum is {MAX_SHORT_ID_BYTES}",
            reality_short_id.len()
        )));
    }
    Ok(RealityEndpointV2 {
        endpoint_id,
        transport,
        ipv4,
        port,
        locator_name,
        sni,
        reality_x25519_public_key,
        reality_short_id: reality_short_id.to_vec(),
    })
}

fn encode_service(encoder: &mut Encoder<Vec<u8>>, service: &ServiceV2) -> Result<()> {
    enc(encoder.map(3))?;
    enc(encoder.u8(1))?;
    enc(encoder.bytes(service.service_id.as_bytes()))?;
    enc(encoder.u8(2))?;
    enc(encoder.array(service.pins.len() as u64))?;
    for pin in &service.pins {
        encode_pin(encoder, pin)?;
    }
    enc(encoder.u8(3))?;
    enc(encoder.array(service.endpoints.len() as u64))?;
    for endpoint in &service.endpoints {
        encode_endpoint(encoder, endpoint)?;
    }
    Ok(())
}

fn decode_service(decoder: &mut Decoder<'_>) -> Result<ServiceV2> {
    expect_map(decoder, 3, "service")?;
    expect_key(decoder, 1, "service")?;
    let service_id = ServiceId(fixed_bytes(decoder, "service id")?);
    expect_key(decoder, 2, "service")?;
    let pin_count = expect_array(decoder, MAX_PINS_PER_SERVICE, "server pin array")?;
    let mut pins = Vec::with_capacity(pin_count);
    for _ in 0..pin_count {
        pins.push(decode_pin(decoder)?);
    }
    expect_key(decoder, 3, "service")?;
    let endpoint_count =
        expect_array(decoder, MAX_ENDPOINTS_PER_SERVICE, "REALITY endpoint array")?;
    let mut endpoints = Vec::with_capacity(endpoint_count);
    for _ in 0..endpoint_count {
        endpoints.push(decode_endpoint(decoder)?);
    }
    Ok(ServiceV2 {
        service_id,
        pins,
        endpoints,
    })
}

fn encode_rule(encoder: &mut Encoder<Vec<u8>>, rule: &PolicyRuleV2) -> Result<()> {
    enc(encoder.map(2))?;
    enc(encoder.u8(1))?;
    enc(encoder.u8(rule.action as u8))?;
    enc(encoder.u8(2))?;
    enc(encoder.array(rule.service_ids.len() as u64))?;
    for service_id in &rule.service_ids {
        enc(encoder.bytes(service_id.as_bytes()))?;
    }
    Ok(())
}

fn decode_rule(decoder: &mut Decoder<'_>) -> Result<PolicyRuleV2> {
    expect_map(decoder, 2, "policy rule")?;
    expect_key(decoder, 1, "policy rule")?;
    let raw_action = dec(decoder.u64())?;
    let action = RuleAction::try_from(raw_action).map_err(|_| {
        PolicyError::invalid(format!(
            "unsupported rule action {raw_action}; v2 permits PROTECTED_ONLY only"
        ))
    })?;
    expect_key(decoder, 2, "policy rule")?;
    let count = expect_array(decoder, MAX_SERVICES, "rule service-id array")?;
    let mut service_ids = Vec::with_capacity(count);
    for _ in 0..count {
        service_ids.push(ServiceId(fixed_bytes(decoder, "rule service id")?));
    }
    Ok(PolicyRuleV2 {
        action,
        service_ids,
    })
}

pub fn encode_policy_payload(policy: &EndpointPolicyV2) -> Result<Vec<u8>> {
    if policy.services.len() > MAX_SERVICES {
        return Err(PolicyError::invalid(format!(
            "service array has {} entries; maximum is {MAX_SERVICES}",
            policy.services.len()
        )));
    }
    if policy.rules.len() > 1 {
        return Err(PolicyError::invalid(format!(
            "policy rule array has {} entries; maximum is 1",
            policy.rules.len()
        )));
    }
    if policy.experiment_evidence.len() > MAX_EVIDENCE_REFS {
        return Err(PolicyError::invalid(format!(
            "experiment evidence array has {} entries; maximum is {MAX_EVIDENCE_REFS}",
            policy.experiment_evidence.len()
        )));
    }
    let mut total_endpoints = 0usize;
    for service in &policy.services {
        if service.pins.len() > MAX_PINS_PER_SERVICE {
            return Err(PolicyError::invalid(format!(
                "server pin array has {} entries; maximum is {MAX_PINS_PER_SERVICE}",
                service.pins.len()
            )));
        }
        if service.endpoints.len() > MAX_ENDPOINTS_PER_SERVICE {
            return Err(PolicyError::invalid(format!(
                "REALITY endpoint array has {} entries; maximum is {MAX_ENDPOINTS_PER_SERVICE}",
                service.endpoints.len()
            )));
        }
        total_endpoints = total_endpoints
            .checked_add(service.endpoints.len())
            .ok_or_else(|| PolicyError::invalid("total endpoint count overflow"))?;
        if total_endpoints > MAX_TOTAL_ENDPOINTS {
            return Err(PolicyError::invalid(format!(
                "endpoint policy exceeds the global {MAX_TOTAL_ENDPOINTS}-endpoint bound"
            )));
        }
        for endpoint in &service.endpoints {
            if endpoint.locator_name.len() > MAX_LOCATOR_NAME_BYTES {
                return Err(PolicyError::invalid(format!(
                    "locator name is {} bytes; maximum is {MAX_LOCATOR_NAME_BYTES}",
                    endpoint.locator_name.len()
                )));
            }
            if endpoint.sni.len() > MAX_SNI_BYTES {
                return Err(PolicyError::invalid(format!(
                    "SNI is {} bytes; maximum is {MAX_SNI_BYTES}",
                    endpoint.sni.len()
                )));
            }
            if endpoint.reality_short_id.len() > MAX_SHORT_ID_BYTES {
                return Err(PolicyError::invalid(format!(
                    "REALITY short id is {} bytes; maximum is {MAX_SHORT_ID_BYTES}",
                    endpoint.reality_short_id.len()
                )));
            }
        }
    }
    let mut encoder = Encoder::new(Vec::new());
    enc(encoder.map(13))?;
    enc(encoder.u8(1))?;
    enc(encoder.u8(POLICY_SCHEMA_VERSION as u8))?;
    enc(encoder.u8(2))?;
    enc(encoder.u8(POLICY_OBJECT_KIND as u8))?;
    enc(encoder.u8(3))?;
    enc(encoder.u64(policy.keyset_epoch))?;
    enc(encoder.u8(4))?;
    enc(encoder.bytes(&policy.keyset_payload_hash))?;
    enc(encoder.u8(5))?;
    enc(encoder.u64(policy.policy_epoch))?;
    enc(encoder.u8(6))?;
    enc(encoder.u64(policy.sequence))?;
    enc(encoder.u8(7))?;
    enc(encoder.i64(policy.issued_at))?;
    enc(encoder.u8(8))?;
    enc(encoder.i64(policy.not_before))?;
    enc(encoder.u8(9))?;
    enc(encoder.i64(policy.expires_at))?;
    enc(encoder.u8(10))?;
    match policy.previous_payload_hash {
        Some(hash) => {
            enc(encoder.bytes(&hash))?;
        }
        None => {
            enc(encoder.null())?;
        }
    }
    enc(encoder.u8(11))?;
    enc(encoder.array(policy.services.len() as u64))?;
    for service in &policy.services {
        encode_service(&mut encoder, service)?;
    }
    enc(encoder.u8(12))?;
    enc(encoder.array(policy.rules.len() as u64))?;
    for rule in &policy.rules {
        encode_rule(&mut encoder, rule)?;
    }
    enc(encoder.u8(13))?;
    enc(encoder.array(policy.experiment_evidence.len() as u64))?;
    for evidence in &policy.experiment_evidence {
        enc(encoder.bytes(evidence.as_bytes()))?;
    }
    let encoded = encoder.into_writer();
    if encoded.len() > MAX_SIGN1_BYTES {
        return Err(PolicyError::TooLarge {
            what: "policy payload",
            actual: encoded.len(),
            maximum: MAX_SIGN1_BYTES,
        });
    }
    Ok(encoded)
}

pub fn decode_policy_payload(input: &[u8]) -> Result<EndpointPolicyV2> {
    if input.len() > MAX_SIGN1_BYTES {
        return Err(PolicyError::TooLarge {
            what: "policy payload",
            actual: input.len(),
            maximum: MAX_SIGN1_BYTES,
        });
    }
    let mut decoder = Decoder::new(input);
    expect_map(&mut decoder, 13, "endpoint policy")?;
    expect_key(&mut decoder, 1, "endpoint policy")?;
    let schema = dec(decoder.u64())?;
    if schema != POLICY_SCHEMA_VERSION {
        return Err(PolicyError::invalid(format!(
            "unsupported endpoint-policy schema {schema}; only schema {POLICY_SCHEMA_VERSION} is accepted"
        )));
    }
    expect_key(&mut decoder, 2, "endpoint policy")?;
    let kind = dec(decoder.u64())?;
    if kind != POLICY_OBJECT_KIND {
        return Err(PolicyError::invalid(format!(
            "policy object kind is {kind}, expected {POLICY_OBJECT_KIND}"
        )));
    }
    expect_key(&mut decoder, 3, "endpoint policy")?;
    let keyset_epoch = dec(decoder.u64())?;
    expect_key(&mut decoder, 4, "endpoint policy")?;
    let keyset_payload_hash = fixed_bytes(&mut decoder, "keyset payload hash")?;
    expect_key(&mut decoder, 5, "endpoint policy")?;
    let policy_epoch = dec(decoder.u64())?;
    expect_key(&mut decoder, 6, "endpoint policy")?;
    let sequence = dec(decoder.u64())?;
    expect_key(&mut decoder, 7, "endpoint policy")?;
    let issued_at = dec(decoder.i64())?;
    expect_key(&mut decoder, 8, "endpoint policy")?;
    let not_before = dec(decoder.i64())?;
    expect_key(&mut decoder, 9, "endpoint policy")?;
    let expires_at = dec(decoder.i64())?;
    expect_key(&mut decoder, 10, "endpoint policy")?;
    let previous_payload_hash = optional_hash(&mut decoder, "previous policy payload hash")?;
    expect_key(&mut decoder, 11, "endpoint policy")?;
    let service_count = expect_array(&mut decoder, MAX_SERVICES, "service array")?;
    let mut services = Vec::with_capacity(service_count);
    for _ in 0..service_count {
        services.push(decode_service(&mut decoder)?);
    }
    expect_key(&mut decoder, 12, "endpoint policy")?;
    let rule_count = expect_array(&mut decoder, 1, "policy rule array")?;
    let mut rules = Vec::with_capacity(rule_count);
    for _ in 0..rule_count {
        rules.push(decode_rule(&mut decoder)?);
    }
    expect_key(&mut decoder, 13, "endpoint policy")?;
    let evidence_count =
        expect_array(&mut decoder, MAX_EVIDENCE_REFS, "experiment evidence array")?;
    let mut experiment_evidence = Vec::with_capacity(evidence_count);
    for _ in 0..evidence_count {
        experiment_evidence.push(EvidenceHash(fixed_bytes(
            &mut decoder,
            "experiment evidence hash",
        )?));
    }
    finish(&decoder, input, "endpoint policy payload")?;
    let value = EndpointPolicyV2 {
        keyset_epoch,
        keyset_payload_hash,
        policy_epoch,
        sequence,
        issued_at,
        not_before,
        expires_at,
        previous_payload_hash,
        services,
        rules,
        experiment_evidence,
    };
    ensure_canonical(
        input,
        encode_policy_payload(&value)?,
        "endpoint policy payload",
    )?;
    Ok(value)
}

pub fn encode_bundle(bundle: &BundleBytes) -> Result<Vec<u8>> {
    if bundle.keyset_sign1.len() > MAX_SIGN1_BYTES {
        return Err(PolicyError::TooLarge {
            what: "keyset COSE_Sign1",
            actual: bundle.keyset_sign1.len(),
            maximum: MAX_SIGN1_BYTES,
        });
    }
    if bundle.policy_sign1.len() > MAX_SIGN1_BYTES {
        return Err(PolicyError::TooLarge {
            what: "policy COSE_Sign1",
            actual: bundle.policy_sign1.len(),
            maximum: MAX_SIGN1_BYTES,
        });
    }
    let mut encoder = Encoder::new(Vec::new());
    enc(encoder.map(3))?;
    enc(encoder.u8(1))?;
    enc(encoder.u8(1))?;
    enc(encoder.u8(2))?;
    enc(encoder.bytes(&bundle.keyset_sign1))?;
    enc(encoder.u8(3))?;
    enc(encoder.bytes(&bundle.policy_sign1))?;
    let encoded = encoder.into_writer();
    if encoded.len() > MAX_BUNDLE_BYTES {
        return Err(PolicyError::TooLarge {
            what: "policy bundle",
            actual: encoded.len(),
            maximum: MAX_BUNDLE_BYTES,
        });
    }
    Ok(encoded)
}

pub fn decode_bundle(input: &[u8]) -> Result<BundleBytes> {
    if input.len() > MAX_BUNDLE_BYTES {
        return Err(PolicyError::TooLarge {
            what: "policy bundle",
            actual: input.len(),
            maximum: MAX_BUNDLE_BYTES,
        });
    }
    let mut decoder = Decoder::new(input);
    expect_map(&mut decoder, 3, "policy bundle")?;
    expect_key(&mut decoder, 1, "policy bundle")?;
    let schema = dec(decoder.u64())?;
    if schema != 1 {
        return Err(PolicyError::invalid(format!(
            "unsupported policy bundle schema {schema}"
        )));
    }
    expect_key(&mut decoder, 2, "policy bundle")?;
    let keyset_sign1 = dec(decoder.bytes())?;
    if keyset_sign1.len() > MAX_SIGN1_BYTES {
        return Err(PolicyError::TooLarge {
            what: "keyset COSE_Sign1",
            actual: keyset_sign1.len(),
            maximum: MAX_SIGN1_BYTES,
        });
    }
    let keyset_sign1 = keyset_sign1.to_vec();
    expect_key(&mut decoder, 3, "policy bundle")?;
    let policy_sign1 = dec(decoder.bytes())?;
    if policy_sign1.len() > MAX_SIGN1_BYTES {
        return Err(PolicyError::TooLarge {
            what: "policy COSE_Sign1",
            actual: policy_sign1.len(),
            maximum: MAX_SIGN1_BYTES,
        });
    }
    let policy_sign1 = policy_sign1.to_vec();
    finish(&decoder, input, "policy bundle")?;
    let value = BundleBytes {
        keyset_sign1,
        policy_sign1,
    };
    ensure_canonical(input, encode_bundle(&value)?, "policy bundle")?;
    Ok(value)
}
