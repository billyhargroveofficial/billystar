use std::convert::TryInto;
use std::net::Ipv4Addr;

use minicbor::Encoder;
use ring::signature::{Ed25519KeyPair, KeyPair};

use super::*;
use crate::signed_policy::schema::{KEYSET_MAX_TTL_SECS, MAX_SIGN1_BYTES, POLICY_MAX_TTL_SECS};

const NOW: i64 = 2_000_000_000;
const DAY: i64 = 24 * 60 * 60;
const ROOT_KID: Kid = Kid([0x10; 16]);
const ONLINE_KID: Kid = Kid([0x20; 16]);
const ONLINE_KID_2: Kid = Kid([0x21; 16]);
const SERVICE_ID: ServiceId = ServiceId([0x30; 16]);
const ENDPOINT_ID: EndpointId = EndpointId([0x40; 16]);
const OLD_PIN: [u8; 32] = [0x50; 32];
const NEW_PIN: [u8; 32] = [0x51; 32];

fn key_pair(seed_byte: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed_byte; 32]).expect("fixed test seed")
}

fn public_key(pair: &Ed25519KeyPair) -> [u8; 32] {
    pair.public_key().as_ref().try_into().unwrap()
}

fn root_trust(root: &Ed25519KeyPair) -> TrustedRoot {
    TrustedRoot {
        kid: ROOT_KID,
        ed25519_public_key: public_key(root),
    }
}

fn sign1(content_type: ContentType, kid: Kid, payload: &[u8], pair: &Ed25519KeyPair) -> Vec<u8> {
    let protected = encode_protected_header(&ProtectedHeader { content_type, kid }).unwrap();
    raw_sign1(&protected, payload, pair, false, true)
}

fn raw_sign1(
    protected: &[u8],
    payload: &[u8],
    pair: &Ed25519KeyPair,
    nonempty_unprotected: bool,
    tagged: bool,
) -> Vec<u8> {
    let signature_input = signature_structure(protected, payload).unwrap();
    let signature = pair.sign(&signature_input);
    let mut output = Vec::new();
    if tagged {
        output.push(0xd2);
    }
    let mut encoder = Encoder::new(output);
    encoder.array(4).unwrap();
    encoder.bytes(protected).unwrap();
    if nonempty_unprotected {
        encoder.map(1).unwrap();
        encoder.u8(42).unwrap();
        encoder.u8(1).unwrap();
    } else {
        encoder.map(0).unwrap();
    }
    encoder.bytes(payload).unwrap();
    encoder.bytes(signature.as_ref()).unwrap();
    encoder.into_writer()
}

fn bad_protected_header(alg: i64, crit: u64, private_label: u64, fields: u64) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(fields).unwrap();
    encoder.u8(1).unwrap();
    encoder.i64(alg).unwrap();
    encoder.u8(2).unwrap();
    encoder.array(1).unwrap();
    encoder.u64(crit).unwrap();
    encoder.u8(3).unwrap();
    encoder
        .str("application/shadowpipe-endpoint-policy+cbor;v=2")
        .unwrap();
    encoder.u8(4).unwrap();
    encoder.bytes(ONLINE_KID.as_bytes()).unwrap();
    encoder.u64(private_label).unwrap();
    encoder.u8(1).unwrap();
    if fields == 6 {
        encoder.u64(private_label).unwrap();
        encoder.u8(1).unwrap();
    }
    encoder.into_writer()
}

fn legacy_v1_policy_protected_header() -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(5).unwrap();
    encoder.u8(1).unwrap();
    encoder.i8(-8).unwrap();
    encoder.u8(2).unwrap();
    encoder.array(1).unwrap();
    encoder.u16(1001).unwrap();
    encoder.u8(3).unwrap();
    encoder
        .str("application/shadowpipe-endpoint-policy+cbor;v=1")
        .unwrap();
    encoder.u8(4).unwrap();
    encoder.bytes(ONLINE_KID.as_bytes()).unwrap();
    encoder.u16(1001).unwrap();
    encoder.u8(1).unwrap();
    encoder.into_writer()
}

fn base_objects(online: &Ed25519KeyPair) -> (KeysetV1, EndpointPolicyV2) {
    let keyset_not_before = NOW - 60;
    let keyset_expires = NOW + 60 * DAY;
    let keyset = KeysetV1 {
        keyset_epoch: 0,
        issued_at: NOW,
        not_before: keyset_not_before,
        expires_at: keyset_expires,
        previous_payload_hash: None,
        keys: vec![OnlineKeyV1 {
            kid: ONLINE_KID,
            ed25519_public_key: public_key(online),
            not_before: keyset_not_before,
            expires_at: keyset_expires,
            status: KeyStatus::Active,
            status_since: keyset_not_before,
        }],
    };
    let policy = EndpointPolicyV2 {
        keyset_epoch: 0,
        keyset_payload_hash: [0u8; 32],
        policy_epoch: 0,
        sequence: 0,
        issued_at: NOW,
        not_before: NOW - 60,
        expires_at: NOW + 6 * DAY,
        previous_payload_hash: None,
        services: vec![ServiceV2 {
            service_id: SERVICE_ID,
            pins: vec![ServerPinV2 {
                fingerprint: OLD_PIN,
                not_before: NOW - 60,
                expires_at: keyset_expires,
                status: PinStatus::Active,
                status_since: NOW - 60,
            }],
            endpoints: vec![RealityEndpointV2 {
                endpoint_id: ENDPOINT_ID,
                transport: TransportV2::RealityTcp,
                ipv4: Ipv4Addr::new(203, 0, 113, 10),
                port: 443,
                locator_name: "edge.shadowpipe.example".into(),
                sni: "cdn.example.com".into(),
                reality_x25519_public_key: [0x60; 32],
                reality_short_id: vec![0x70; 8],
            }],
        }],
        rules: vec![PolicyRuleV2 {
            action: RuleAction::ProtectedOnly,
            service_ids: vec![SERVICE_ID],
        }],
        experiment_evidence: vec![],
    };
    (keyset, policy)
}

fn bind_policy(keyset: &KeysetV1, policy: &mut EndpointPolicyV2) -> Vec<u8> {
    let keyset_payload = encode_keyset_payload(keyset).unwrap();
    policy.keyset_epoch = keyset.keyset_epoch;
    policy.keyset_payload_hash = keyset_payload_hash(&keyset_payload);
    keyset_payload
}

fn bundle_bytes(
    keyset: &KeysetV1,
    mut policy: EndpointPolicyV2,
    root: &Ed25519KeyPair,
    online: &Ed25519KeyPair,
    online_kid: Kid,
) -> Vec<u8> {
    let keyset_payload = bind_policy(keyset, &mut policy);
    let policy_payload = encode_policy_payload(&policy).unwrap();
    encode_bundle(&BundleBytes {
        keyset_sign1: sign1(ContentType::Keyset, ROOT_KID, &keyset_payload, root),
        policy_sign1: sign1(
            ContentType::EndpointPolicy,
            online_kid,
            &policy_payload,
            online,
        ),
    })
    .unwrap()
}

fn verified(
    keyset: &KeysetV1,
    policy: EndpointPolicyV2,
    root: &Ed25519KeyPair,
    online: &Ed25519KeyPair,
    online_kid: Kid,
    now: i64,
) -> VerifiedBundle {
    verify_bundle(
        &bundle_bytes(keyset, policy, root, online, online_kid),
        &root_trust(root),
        now,
    )
    .unwrap()
}

fn valid_fixture() -> (Vec<u8>, TrustedRoot) {
    let root = key_pair(1);
    let online = key_pair(2);
    let (keyset, policy) = base_objects(&online);
    (
        bundle_bytes(&keyset, policy, &root, &online, ONLINE_KID),
        root_trust(&root),
    )
}

fn bundle_replacing_policy_sign1(policy_sign1: Vec<u8>) -> (Vec<u8>, TrustedRoot) {
    let (valid, root) = valid_fixture();
    let mut bundle = decode_bundle(&valid).unwrap();
    bundle.policy_sign1 = policy_sign1;
    (encode_bundle(&bundle).unwrap(), root)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("fixture byte pattern")
}

fn next_policy(previous: &VerifiedBundle, issued_at: i64) -> EndpointPolicyV2 {
    let mut policy = previous.policy.clone();
    policy.sequence = policy.sequence.checked_add(1).unwrap();
    policy.issued_at = issued_at;
    policy.previous_payload_hash = Some(previous.policy_hash);
    policy
}

#[test]
fn verifies_valid_bundle_and_builds_exact_connection_plan() {
    let (bytes, root) = valid_fixture();
    let verified = verify_bundle(&bytes, &root, NOW).unwrap();
    assert_eq!(verified.keyset.keyset_epoch, 0);
    assert_eq!(verified.policy.sequence, 0);
    assert_eq!(verified.plan().endpoints().len(), 1);
    let endpoint = &verified.plan().endpoints()[0];
    assert_eq!(endpoint.socket_addr().ip(), &Ipv4Addr::new(203, 0, 113, 10));
    assert_eq!(endpoint.socket_addr().port(), 443);
    assert_eq!(endpoint.locator_name(), "edge.shadowpipe.example");
    assert_eq!(endpoint.sni(), "cdn.example.com");
    assert_eq!(endpoint.reality_short_id(), &[0x70; 8]);
    assert_eq!(endpoint.server_pins().len(), 1);
    assert!(endpoint.server_pins().matches(&OLD_PIN));
    assert!(!endpoint.server_pins().matches(&NEW_PIN));
}

#[test]
fn policy_v2_canonical_round_trip_preserves_locator_and_rejects_v1_without_fallback() {
    let online = key_pair(2);
    let (_, policy) = base_objects(&online);
    let canonical = encode_policy_payload(&policy).unwrap();
    let decoded = decode_policy_payload(&canonical).unwrap();
    assert_eq!(decoded, policy);
    assert_eq!(
        decoded.services[0].endpoints[0].locator_name,
        "edge.shadowpipe.example"
    );
    assert_eq!(encode_policy_payload(&decoded).unwrap(), canonical);

    let mut legacy_schema = canonical;
    assert_eq!(&legacy_schema[..3], &[0xad, 0x01, 0x02]);
    legacy_schema[2] = 1;
    assert_eq!(
        decode_policy_payload(&legacy_schema),
        Err(PolicyError::Invalid(
            "unsupported endpoint-policy schema 1; only schema 2 is accepted".into()
        ))
    );
}

#[test]
fn legacy_v1_policy_content_type_is_explicitly_rejected() {
    let root = key_pair(1);
    let online = key_pair(2);
    let (keyset, mut policy) = base_objects(&online);
    let keyset_payload = bind_policy(&keyset, &mut policy);
    let payload = encode_policy_payload(&policy).unwrap();
    let legacy = raw_sign1(
        &legacy_v1_policy_protected_header(),
        &payload,
        &online,
        false,
        true,
    );
    let bundle = encode_bundle(&BundleBytes {
        keyset_sign1: sign1(ContentType::Keyset, ROOT_KID, &keyset_payload, &root),
        policy_sign1: legacy,
    })
    .unwrap();

    assert_eq!(
        verify_bundle(&bundle, &root_trust(&root), NOW),
        Err(PolicyError::Invalid(
            "unsupported endpoint-policy schema 1; only schema 2 is accepted".into()
        ))
    );
}

#[test]
fn standalone_keyset_verification_has_bundle_parity_and_is_fail_closed() {
    let (bytes, root) = valid_fixture();
    let bundle_bytes = decode_bundle(&bytes).unwrap();
    let standalone = verify_keyset_artifact(&bundle_bytes.keyset_sign1, &root, NOW).unwrap();
    let verified_bundle = verify_bundle(&bytes, &root, NOW).unwrap();
    assert_eq!(standalone.keyset(), verified_bundle.keyset());
    assert_eq!(standalone.payload_hash(), verified_bundle.keyset_hash());
    assert_eq!(standalone.root_id(), verified_bundle.root_id());

    let mut tampered = bundle_bytes.keyset_sign1.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        verify_keyset_artifact(&tampered, &root, NOW),
        Err(PolicyError::Signature)
    );

    let wrong_root_pair = key_pair(9);
    let wrong_root = TrustedRoot {
        kid: ROOT_KID,
        ed25519_public_key: public_key(&wrong_root_pair),
    };
    assert_eq!(
        verify_keyset_artifact(&bundle_bytes.keyset_sign1, &wrong_root, NOW),
        Err(PolicyError::Signature)
    );
    assert_eq!(
        verify_keyset_artifact(
            &bundle_bytes.keyset_sign1,
            &root,
            verified_bundle.keyset().expires_at,
        ),
        Err(PolicyError::Expired("online-key set"))
    );
}

#[test]
fn release_transition_helpers_have_runtime_state_machine_parity() {
    let root = key_pair(1);
    let online = key_pair(2);
    let (keyset0, policy0) = base_objects(&online);
    let previous = verified(&keyset0, policy0, &root, &online, ONLINE_KID, NOW);

    let mut keyset1 = keyset0.clone();
    keyset1.keyset_epoch = 1;
    keyset1.previous_payload_hash = Some(*previous.keyset_hash());
    let keyset1_payload = encode_keyset_payload(&keyset1).unwrap();
    let keyset1_sign1 = sign1(ContentType::Keyset, ROOT_KID, &keyset1_payload, &root);
    let keyset1_artifact = verify_keyset_artifact(&keyset1_sign1, &root_trust(&root), NOW).unwrap();
    validate_keyset_successor(&previous, &keyset1_artifact).unwrap();

    let mut gap_keyset = keyset1.clone();
    gap_keyset.keyset_epoch = 2;
    let gap_payload = encode_keyset_payload(&gap_keyset).unwrap();
    let gap_sign1 = sign1(ContentType::Keyset, ROOT_KID, &gap_payload, &root);
    let gap_artifact = verify_keyset_artifact(&gap_sign1, &root_trust(&root), NOW).unwrap();
    assert!(matches!(
        validate_keyset_successor(&previous, &gap_artifact),
        Err(PolicyError::Gap(_))
    ));

    let policy1 = next_policy(&previous, NOW);
    let candidate = verified(&keyset1, policy1, &root, &online, ONLINE_KID, NOW);
    let accepted = apply_verified_update(None, previous.clone(), NOW)
        .unwrap()
        .into_state();
    let runtime = apply_verified_update(Some(&accepted), candidate.clone(), NOW).unwrap();
    let release = apply_verified_successor(&previous, candidate, NOW).unwrap();
    assert_eq!(release, runtime);

    let mut gap_policy = next_policy(&previous, NOW);
    gap_policy.sequence = 2;
    let standalone_valid_gap = verified(&keyset0, gap_policy, &root, &online, ONLINE_KID, NOW);
    assert!(matches!(
        apply_verified_successor(&previous, standalone_valid_gap, NOW),
        Err(PolicyError::Gap(_))
    ));
}

#[test]
fn protected_header_and_domain_hashes_match_stable_wire_vectors() {
    let keyset_protected = encode_protected_header(&ProtectedHeader {
        content_type: ContentType::Keyset,
        kid: ROOT_KID,
    })
    .unwrap();
    assert_eq!(
        hex::encode(keyset_protected),
        concat!(
            "a5012702811903e9037826",
            "6170706c69636174696f6e2f736861646f77706970652d6b65797365742b63626f723b763d31",
            "0450101010101010101010101010101010101903e901"
        )
    );
    let policy_protected = encode_protected_header(&ProtectedHeader {
        content_type: ContentType::EndpointPolicy,
        kid: ONLINE_KID,
    })
    .unwrap();
    assert_eq!(
        hex::encode(policy_protected),
        concat!(
            "a5012702811903e903782f",
            "6170706c69636174696f6e2f736861646f77706970652d656e64706f696e742d706f6c6963792b63626f723b763d32",
            "0450202020202020202020202020202020201903e901"
        )
    );
    assert_eq!(
        hex::encode(keyset_payload_hash(b"")),
        "747272a90dce3236b777cacc3d8f4209cdfcc73cdc47fc3e60862daad55475cd"
    );
    assert_eq!(
        hex::encode(policy_payload_hash(b"")),
        "904c9bf960fe381b790167c1a058a8d14edb9c480a63c4b479a2c2a5765795e6"
    );
}

#[test]
fn rejects_signature_tampering_of_an_exact_endpoint_binding() {
    for signed_name in [b"edge.shadowpipe.example".as_slice(), b"cdn.example.com"] {
        let (valid, root) = valid_fixture();
        let mut bundle = decode_bundle(&valid).unwrap();
        let offset = find_bytes(&bundle.policy_sign1, signed_name);
        bundle.policy_sign1[offset] ^= 1;
        let tampered = encode_bundle(&bundle).unwrap();
        assert_eq!(
            verify_bundle(&tampered, &root, NOW),
            Err(PolicyError::Signature)
        );
    }
}

#[test]
fn rejects_wrong_alg_critical_label_and_unknown_or_duplicate_headers() {
    let online = key_pair(2);
    let (_, mut policy) = base_objects(&online);
    let root_pair = key_pair(1);
    let (keyset, _) = base_objects(&online);
    let keyset_payload = bind_policy(&keyset, &mut policy);
    let payload = encode_policy_payload(&policy).unwrap();
    let keyset_sign1 = sign1(ContentType::Keyset, ROOT_KID, &keyset_payload, &root_pair);

    for protected in [
        bad_protected_header(-7, 1001, 1001, 5),
        bad_protected_header(-8, 1002, 1001, 5),
        bad_protected_header(-8, 1001, 1002, 5),
        bad_protected_header(-8, 1001, 1001, 6),
    ] {
        let bytes = encode_bundle(&BundleBytes {
            keyset_sign1: keyset_sign1.clone(),
            policy_sign1: raw_sign1(&protected, &payload, &online, false, true),
        })
        .unwrap();
        assert!(matches!(
            verify_bundle(&bytes, &root_trust(&root_pair), NOW),
            Err(PolicyError::Invalid(_))
        ));
    }
}

#[test]
fn rejects_wrong_kid_and_content_type() {
    let online = key_pair(2);
    let root_pair = key_pair(1);
    let (keyset, mut policy) = base_objects(&online);
    bind_policy(&keyset, &mut policy);
    let payload = encode_policy_payload(&policy).unwrap();

    let wrong_kid = sign1(
        ContentType::EndpointPolicy,
        Kid([0xaa; 16]),
        &payload,
        &online,
    );
    let (bytes, root) = bundle_replacing_policy_sign1(wrong_kid);
    assert!(matches!(
        verify_bundle(&bytes, &root, NOW),
        Err(PolicyError::Invalid(_))
    ));

    let wrong_type = sign1(ContentType::Keyset, ONLINE_KID, &payload, &online);
    let keyset_payload = encode_keyset_payload(&keyset).unwrap();
    let bytes = encode_bundle(&BundleBytes {
        keyset_sign1: sign1(ContentType::Keyset, ROOT_KID, &keyset_payload, &root_pair),
        policy_sign1: wrong_type,
    })
    .unwrap();
    assert!(matches!(
        verify_bundle(&bytes, &root_trust(&root_pair), NOW),
        Err(PolicyError::Invalid(_))
    ));
}

#[test]
fn rejects_missing_tag_and_nonempty_unprotected_header() {
    let online = key_pair(2);
    let (keyset, mut policy) = base_objects(&online);
    bind_policy(&keyset, &mut policy);
    let payload = encode_policy_payload(&policy).unwrap();
    let protected = encode_protected_header(&ProtectedHeader {
        content_type: ContentType::EndpointPolicy,
        kid: ONLINE_KID,
    })
    .unwrap();

    for sign1 in [
        raw_sign1(&protected, &payload, &online, false, false),
        raw_sign1(&protected, &payload, &online, true, true),
    ] {
        let (bytes, root) = bundle_replacing_policy_sign1(sign1);
        assert!(matches!(
            verify_bundle(&bytes, &root, NOW),
            Err(PolicyError::Invalid(_))
        ));
    }
}

#[test]
fn rejects_noncanonical_payload_and_bundle_encodings() {
    let root = key_pair(1);
    let online = key_pair(2);
    let (keyset, mut policy) = base_objects(&online);
    let keyset_payload = bind_policy(&keyset, &mut policy);
    let canonical = encode_policy_payload(&policy).unwrap();
    assert_eq!(canonical[0], 0xad);
    let mut noncanonical = vec![0xb8, 0x0d];
    noncanonical.extend_from_slice(&canonical[1..]);
    let bytes = encode_bundle(&BundleBytes {
        keyset_sign1: sign1(ContentType::Keyset, ROOT_KID, &keyset_payload, &root),
        policy_sign1: sign1(
            ContentType::EndpointPolicy,
            ONLINE_KID,
            &noncanonical,
            &online,
        ),
    })
    .unwrap();
    assert_eq!(
        verify_bundle(&bytes, &root_trust(&root), NOW),
        Err(PolicyError::NonCanonical("endpoint policy payload"))
    );

    let (canonical_bundle, _) = valid_fixture();
    assert_eq!(canonical_bundle[0], 0xa3);
    let mut noncanonical_bundle = vec![0xb8, 0x03];
    noncanonical_bundle.extend_from_slice(&canonical_bundle[1..]);
    assert_eq!(
        decode_bundle(&noncanonical_bundle),
        Err(PolicyError::NonCanonical("policy bundle"))
    );
}

#[test]
fn rejects_unknown_and_duplicate_payload_fields() {
    let root = key_pair(1);
    let online = key_pair(2);
    let (keyset, mut policy) = base_objects(&online);
    let keyset_payload = bind_policy(&keyset, &mut policy);
    let canonical = encode_policy_payload(&policy).unwrap();
    assert_eq!(&canonical[canonical.len() - 2..], &[13, 0x80]);

    for replacement in [14, 12] {
        let mut malformed = canonical.clone();
        let end = malformed.len();
        malformed[end - 2] = replacement;
        let bytes = encode_bundle(&BundleBytes {
            keyset_sign1: sign1(ContentType::Keyset, ROOT_KID, &keyset_payload, &root),
            policy_sign1: sign1(ContentType::EndpointPolicy, ONLINE_KID, &malformed, &online),
        })
        .unwrap();
        assert!(matches!(
            verify_bundle(&bytes, &root_trust(&root), NOW),
            Err(PolicyError::Invalid(_))
        ));
    }
}

#[test]
fn enforces_bundle_and_sign1_size_bounds() {
    let root = key_pair(1);
    let trust = root_trust(&root);
    let too_large = vec![0u8; MAX_BUNDLE_BYTES + 1];
    assert!(matches!(
        verify_bundle(&too_large, &trust, NOW),
        Err(PolicyError::TooLarge {
            what: "policy bundle",
            ..
        })
    ));
    let bundle = BundleBytes {
        keyset_sign1: vec![0u8; MAX_SIGN1_BYTES + 1],
        policy_sign1: vec![],
    };
    assert!(matches!(
        encode_bundle(&bundle),
        Err(PolicyError::TooLarge {
            what: "keyset COSE_Sign1",
            ..
        })
    ));
}

#[test]
fn enforces_not_before_expiry_future_issuance_and_ttl() {
    let root = key_pair(1);
    let online = key_pair(2);
    let (keyset, base) = base_objects(&online);

    let mut not_yet = base.clone();
    not_yet.not_before = NOW + 1;
    not_yet.issued_at = NOW + 1;
    assert_eq!(
        verify_bundle(
            &bundle_bytes(&keyset, not_yet, &root, &online, ONLINE_KID),
            &root_trust(&root),
            NOW,
        ),
        Err(PolicyError::NotYetValid("endpoint policy"))
    );

    let mut expired = base.clone();
    expired.expires_at = NOW;
    expired.issued_at = NOW - 1;
    assert_eq!(
        verify_bundle(
            &bundle_bytes(&keyset, expired, &root, &online, ONLINE_KID),
            &root_trust(&root),
            NOW,
        ),
        Err(PolicyError::Expired("endpoint policy"))
    );

    let mut future = base.clone();
    future.issued_at = NOW + MAX_CLOCK_SKEW_SECS + 1;
    assert!(matches!(
        verify_bundle(
            &bundle_bytes(&keyset, future, &root, &online, ONLINE_KID),
            &root_trust(&root),
            NOW,
        ),
        Err(PolicyError::Invalid(_))
    ));

    let mut excessive_ttl = base;
    excessive_ttl.expires_at = excessive_ttl.not_before + POLICY_MAX_TTL_SECS + 1;
    assert!(matches!(
        verify_bundle(
            &bundle_bytes(&keyset, excessive_ttl, &root, &online, ONLINE_KID),
            &root_trust(&root),
            NOW,
        ),
        Err(PolicyError::Invalid(_))
    ));

    let mut excessive_keyset = keyset.clone();
    excessive_keyset.expires_at = excessive_keyset.not_before + KEYSET_MAX_TTL_SECS + 1;
    excessive_keyset.keys[0].expires_at = excessive_keyset.expires_at;
    assert!(matches!(
        verify_bundle(
            &bundle_bytes(
                &excessive_keyset,
                base_objects(&online).1,
                &root,
                &online,
                ONLINE_KID,
            ),
            &root_trust(&root),
            NOW,
        ),
        Err(PolicyError::Invalid(_))
    ));
}

#[test]
fn rejects_invalid_locator_sni_special_ip_duplicate_tuple_and_transport() {
    let root = key_pair(1);
    let online = key_pair(2);
    let (keyset, base) = base_objects(&online);

    for locator_name in [
        "",
        "EDGE.shadowpipe.example",
        "edge.shadowpipe.example.",
        "localhost",
        "edge_name.shadowpipe.example",
        "-edge.shadowpipe.example",
    ] {
        let mut policy = base.clone();
        policy.services[0].endpoints[0].locator_name = locator_name.into();
        let error = verify_bundle(
            &bundle_bytes(&keyset, policy, &root, &online, ONLINE_KID),
            &root_trust(&root),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(error, PolicyError::Invalid(_)));
        assert!(error.to_string().contains("locator_name"));
    }

    let mut overlong_locator = base.clone();
    overlong_locator.services[0].endpoints[0].locator_name = format!(
        "{}.example",
        "a".repeat(super::schema::MAX_LOCATOR_NAME_BYTES)
    );
    let error = encode_policy_payload(&overlong_locator).unwrap_err();
    assert!(matches!(error, PolicyError::Invalid(_)));
    assert!(error.to_string().contains("locator name"));

    for mutate in [0u8, 1u8] {
        let mut policy = base.clone();
        let endpoint = &mut policy.services[0].endpoints[0];
        if mutate == 0 {
            endpoint.sni = "CDN.example.com".into();
        } else {
            endpoint.ipv4 = Ipv4Addr::LOCALHOST;
        }
        assert!(matches!(
            verify_bundle(
                &bundle_bytes(&keyset, policy, &root, &online, ONLINE_KID),
                &root_trust(&root),
                NOW,
            ),
            Err(PolicyError::Invalid(_))
        ));
    }

    let mut low_order = base.clone();
    low_order.services[0].endpoints[0].reality_x25519_public_key = {
        let mut point = [0u8; 32];
        point[0] = 1;
        point
    };
    assert!(matches!(
        verify_bundle(
            &bundle_bytes(&keyset, low_order, &root, &online, ONLINE_KID),
            &root_trust(&root),
            NOW,
        ),
        Err(PolicyError::Invalid(_))
    ));

    let mut short_reality_id = base.clone();
    short_reality_id.services[0].endpoints[0].reality_short_id = vec![0x70; 7];
    let error = verify_bundle(
        &bundle_bytes(&keyset, short_reality_id, &root, &online, ONLINE_KID),
        &root_trust(&root),
        NOW,
    )
    .unwrap_err();
    assert!(error.to_string().contains("exactly 8 bytes"));

    let mut duplicate = base.clone();
    let mut service = duplicate.services[0].clone();
    service.service_id = ServiceId([0x31; 16]);
    service.endpoints[0].endpoint_id = EndpointId([0x41; 16]);
    duplicate.services.push(service);
    duplicate.rules[0].service_ids.push(ServiceId([0x31; 16]));
    assert!(matches!(
        verify_bundle(
            &bundle_bytes(&keyset, duplicate, &root, &online, ONLINE_KID),
            &root_trust(&root),
            NOW,
        ),
        Err(PolicyError::Invalid(_))
    ));

    let mut bound = base;
    let keyset_payload = bind_policy(&keyset, &mut bound);
    let mut payload = encode_policy_payload(&bound).unwrap();
    let mut needle = vec![0x50];
    needle.extend_from_slice(ENDPOINT_ID.as_bytes());
    needle.extend_from_slice(&[0x02, 0x01, 0x03]);
    let offset = find_bytes(&payload, &needle);
    payload[offset + 18] = 2;
    let bytes = encode_bundle(&BundleBytes {
        keyset_sign1: sign1(ContentType::Keyset, ROOT_KID, &keyset_payload, &root),
        policy_sign1: sign1(ContentType::EndpointPolicy, ONLINE_KID, &payload, &online),
    })
    .unwrap();
    assert!(matches!(
        verify_bundle(&bytes, &root_trust(&root), NOW),
        Err(PolicyError::Invalid(_))
    ));
}

#[test]
fn rejects_unsorted_or_duplicate_semantic_collections() {
    let root = key_pair(1);
    let online = key_pair(2);
    let (keyset, base) = base_objects(&online);

    let mut duplicate_pin = base.clone();
    let repeated_pin = duplicate_pin.services[0].pins[0].clone();
    duplicate_pin.services[0].pins.push(repeated_pin);

    let mut duplicate_evidence = base.clone();
    duplicate_evidence.experiment_evidence = vec![EvidenceHash([1u8; 32]); 2];

    let mut rule_mismatch = base.clone();
    rule_mismatch.rules[0].service_ids.clear();

    let mut unsorted_services = base.clone();
    let mut second = unsorted_services.services[0].clone();
    second.service_id = ServiceId([0x2f; 16]);
    second.endpoints[0].endpoint_id = EndpointId([0x41; 16]);
    second.endpoints[0].ipv4 = Ipv4Addr::new(203, 0, 113, 11);
    unsorted_services.services.push(second);

    for policy in [
        duplicate_pin,
        duplicate_evidence,
        rule_mismatch,
        unsorted_services,
    ] {
        assert!(matches!(
            verify_bundle(
                &bundle_bytes(&keyset, policy, &root, &online, ONLINE_KID),
                &root_trust(&root),
                NOW,
            ),
            Err(PolicyError::Invalid(_))
        ));
    }

    let mut duplicate_kid = keyset.clone();
    duplicate_kid.keys.push(duplicate_kid.keys[0].clone());
    assert!(matches!(
        verify_bundle(
            &bundle_bytes(&duplicate_kid, base, &root, &online, ONLINE_KID),
            &root_trust(&root),
            NOW,
        ),
        Err(PolicyError::Invalid(_))
    ));
}

#[test]
fn rejects_policy_not_bound_to_exact_keyset_and_revoked_signer() {
    let root = key_pair(1);
    let online1 = key_pair(2);
    let online2 = key_pair(3);
    let (mut keyset, mut policy) = base_objects(&online1);
    let keyset_payload = encode_keyset_payload(&keyset).unwrap();
    policy.keyset_payload_hash = [0xaa; 32];
    let unbound_payload = encode_policy_payload(&policy).unwrap();
    let unbound = encode_bundle(&BundleBytes {
        keyset_sign1: sign1(ContentType::Keyset, ROOT_KID, &keyset_payload, &root),
        policy_sign1: sign1(
            ContentType::EndpointPolicy,
            ONLINE_KID,
            &unbound_payload,
            &online1,
        ),
    })
    .unwrap();
    assert!(matches!(
        verify_bundle(&unbound, &root_trust(&root), NOW),
        Err(PolicyError::Invalid(_))
    ));

    keyset.keys[0].status = KeyStatus::Revoked;
    keyset.keys[0].status_since = NOW;
    keyset.keys.push(OnlineKeyV1 {
        kid: ONLINE_KID_2,
        ed25519_public_key: public_key(&online2),
        not_before: NOW - 60,
        expires_at: keyset.expires_at,
        status: KeyStatus::Active,
        status_since: NOW - 60,
    });
    assert!(matches!(
        verify_bundle(
            &bundle_bytes(&keyset, policy, &root, &online1, ONLINE_KID),
            &root_trust(&root),
            NOW,
        ),
        Err(PolicyError::Invalid(_))
    ));
}

#[test]
fn state_machine_enforces_genesis_idempotence_rollback_gap_fork_chain_and_clock_floor() {
    let root = key_pair(1);
    let online = key_pair(2);
    let (keyset, policy) = base_objects(&online);
    let genesis = verified(&keyset, policy, &root, &online, ONLINE_KID, NOW);

    let bad_genesis = {
        let mut value = genesis.clone();
        value.policy.sequence = 1;
        value
    };
    assert!(matches!(
        apply_verified_update(None, bad_genesis, NOW),
        Err(PolicyError::Gap(_))
    ));

    let state0 = apply_verified_update(None, genesis.clone(), NOW)
        .unwrap()
        .into_state();
    assert_eq!(
        apply_verified_update(None, genesis.clone(), genesis.policy.expires_at),
        Err(PolicyError::Expired("endpoint policy"))
    );
    let idempotent = apply_verified_update(Some(&state0), genesis.clone(), NOW + 10).unwrap();
    assert!(matches!(idempotent, Transition::Idempotent(_)));
    let state0 = idempotent.into_state();
    assert_eq!(state0.max_wall_clock_seen, NOW + 10);

    let policy1 = next_policy(&genesis, NOW + 20);
    let update1 = verified(&keyset, policy1, &root, &online, ONLINE_KID, NOW + 20);
    let state1 = apply_verified_update(Some(&state0), update1.clone(), NOW + 20)
        .unwrap()
        .into_state();

    assert!(matches!(
        apply_verified_update(Some(&state1), genesis.clone(), NOW + 21),
        Err(PolicyError::Rollback(_))
    ));

    let mut gap_policy = next_policy(&update1, NOW + 21);
    gap_policy.sequence += 1;
    let gap = verified(&keyset, gap_policy, &root, &online, ONLINE_KID, NOW + 21);
    assert!(matches!(
        apply_verified_update(Some(&state1), gap, NOW + 21),
        Err(PolicyError::Gap(_))
    ));

    let mut fork_policy = update1.policy.clone();
    fork_policy.issued_at = NOW + 21;
    fork_policy.services[0].endpoints[0].port = 8443;
    let fork = verified(&keyset, fork_policy, &root, &online, ONLINE_KID, NOW + 21);
    assert!(matches!(
        apply_verified_update(Some(&state1), fork, NOW + 21),
        Err(PolicyError::Fork(_))
    ));

    let mut broken_policy = next_policy(&update1, NOW + 22);
    broken_policy.previous_payload_hash = Some([0xee; 32]);
    let broken = verified(&keyset, broken_policy, &root, &online, ONLINE_KID, NOW + 22);
    assert!(matches!(
        apply_verified_update(Some(&state1), broken, NOW + 22),
        Err(PolicyError::Chain(_))
    ));

    let mut wrong_epoch_start = next_policy(&update1, NOW + 23);
    wrong_epoch_start.policy_epoch = 1;
    wrong_epoch_start.sequence = 1;
    let wrong_epoch_start = verified(
        &keyset,
        wrong_epoch_start,
        &root,
        &online,
        ONLINE_KID,
        NOW + 23,
    );
    assert!(matches!(
        apply_verified_update(Some(&state1), wrong_epoch_start, NOW + 23),
        Err(PolicyError::Gap(_))
    ));

    let mut next_epoch = next_policy(&update1, NOW + 23);
    next_epoch.policy_epoch = 1;
    next_epoch.sequence = 0;
    let next_epoch = verified(&keyset, next_epoch, &root, &online, ONLINE_KID, NOW + 23);
    assert!(matches!(
        apply_verified_update(Some(&state1), next_epoch, NOW + 23),
        Ok(Transition::Applied(_))
    ));

    assert!(matches!(
        apply_verified_update(
            Some(&state1),
            update1,
            state1.max_wall_clock_seen - MAX_CLOCK_SKEW_SECS - 1,
        ),
        Err(PolicyError::Rollback(_))
    ));
}

#[test]
fn keyset_epoch_bump_does_not_reset_the_policy_sequence_floor() {
    let root = key_pair(1);
    let online = key_pair(2);
    let (keyset0, policy0) = base_objects(&online);
    let genesis = verified(&keyset0, policy0, &root, &online, ONLINE_KID, NOW);
    let state0 = apply_verified_update(None, genesis.clone(), NOW)
        .unwrap()
        .into_state();

    let mut skipped_keyset = keyset0.clone();
    skipped_keyset.keyset_epoch = 2;
    skipped_keyset.issued_at = NOW + 1;
    skipped_keyset.previous_payload_hash = Some(genesis.keyset_hash);
    let skipped_policy = next_policy(&genesis, NOW + 1);
    let skipped = verified(
        &skipped_keyset,
        skipped_policy,
        &root,
        &online,
        ONLINE_KID,
        NOW + 1,
    );
    assert!(matches!(
        apply_verified_update(Some(&state0), skipped, NOW + 1),
        Err(PolicyError::Gap(_))
    ));

    let mut keyset1 = keyset0.clone();
    keyset1.keyset_epoch = 1;
    keyset1.issued_at = NOW + 1;
    keyset1.previous_payload_hash = Some(genesis.keyset_hash);
    let policy1 = next_policy(&genesis, NOW + 1);
    let update = verified(&keyset1, policy1, &root, &online, ONLINE_KID, NOW + 1);
    let state1 = apply_verified_update(Some(&state0), update, NOW + 1)
        .unwrap()
        .into_state();

    let mut stale = genesis.policy.clone();
    stale.issued_at = NOW + 2;
    stale.keyset_epoch = 1;
    stale.previous_payload_hash = None;
    let stale = verified(&keyset1, stale, &root, &online, ONLINE_KID, NOW + 2);
    assert!(matches!(
        apply_verified_update(Some(&state1), stale, NOW + 2),
        Err(PolicyError::Rollback(_))
    ));
}

#[test]
fn pure_transition_cannot_silently_rotate_the_offline_root() {
    let root1 = key_pair(1);
    let root2 = key_pair(9);
    let online = key_pair(2);
    let (keyset, policy) = base_objects(&online);
    let genesis = verified(&keyset, policy, &root1, &online, ONLINE_KID, NOW);
    let state = apply_verified_update(None, genesis.clone(), NOW)
        .unwrap()
        .into_state();
    let successor = verified(
        &keyset,
        next_policy(&genesis, NOW + 1),
        &root2,
        &online,
        ONLINE_KID,
        NOW + 1,
    );
    assert!(matches!(
        apply_verified_update(Some(&state), successor, NOW + 1),
        Err(PolicyError::Rotation(_))
    ));
}

#[test]
fn rejects_direct_pin_swap_but_accepts_add_retire_and_delayed_remove() {
    let root = key_pair(1);
    let online = key_pair(2);
    let (keyset, policy0) = base_objects(&online);
    let genesis = verified(&keyset, policy0, &root, &online, ONLINE_KID, NOW);
    let state0 = apply_verified_update(None, genesis.clone(), NOW)
        .unwrap()
        .into_state();

    let mut direct = next_policy(&genesis, NOW + 1);
    direct.services[0].pins = vec![ServerPinV2 {
        fingerprint: NEW_PIN,
        not_before: NOW - 60,
        expires_at: NOW + 60 * DAY,
        status: PinStatus::Active,
        status_since: NOW + 1,
    }];
    let direct = verified(&keyset, direct, &root, &online, ONLINE_KID, NOW + 1);
    assert!(matches!(
        apply_verified_update(Some(&state0), direct, NOW + 1),
        Err(PolicyError::Rotation(_))
    ));

    let mut short_add = next_policy(&genesis, NOW + 1);
    short_add.expires_at = NOW + 60 * 60;
    short_add.services[0].pins.push(ServerPinV2 {
        fingerprint: NEW_PIN,
        not_before: NOW - 60,
        expires_at: NOW + 60 * DAY,
        status: PinStatus::Active,
        status_since: NOW + 1,
    });
    let short_add = verified(&keyset, short_add, &root, &online, ONLINE_KID, NOW + 1);
    assert!(matches!(
        apply_verified_update(Some(&state0), short_add, NOW + 1),
        Err(PolicyError::Rotation(_))
    ));

    let mut add = next_policy(&genesis, NOW + 1);
    add.services[0].pins.push(ServerPinV2 {
        fingerprint: NEW_PIN,
        not_before: NOW - 60,
        expires_at: NOW + 60 * DAY,
        status: PinStatus::Active,
        status_since: NOW + 1,
    });
    let add = verified(&keyset, add, &root, &online, ONLINE_KID, NOW + 1);
    let state1 = apply_verified_update(Some(&state0), add.clone(), NOW + 1)
        .unwrap()
        .into_state();

    let retire_at = NOW + 2;
    let mut short_retire = next_policy(&add, retire_at);
    short_retire.expires_at = retire_at + 60 * 60;
    short_retire.services[0].pins[0].status = PinStatus::Retiring;
    short_retire.services[0].pins[0].status_since = retire_at;
    let short_retire = verified(&keyset, short_retire, &root, &online, ONLINE_KID, retire_at);
    assert!(matches!(
        apply_verified_update(Some(&state1), short_retire, retire_at),
        Err(PolicyError::Rotation(_))
    ));

    let mut retire = next_policy(&add, retire_at);
    retire.services[0].pins[0].status = PinStatus::Retiring;
    retire.services[0].pins[0].status_since = retire_at;
    let retire = verified(&keyset, retire, &root, &online, ONLINE_KID, retire_at);
    let state2 = apply_verified_update(Some(&state1), retire.clone(), retire_at)
        .unwrap()
        .into_state();

    let mut too_early = next_policy(&retire, retire_at + 1);
    too_early.services[0].pins.remove(0);
    let too_early = verified(
        &keyset,
        too_early,
        &root,
        &online,
        ONLINE_KID,
        retire_at + 1,
    );
    assert!(matches!(
        apply_verified_update(Some(&state2), too_early, retire_at + 1),
        Err(PolicyError::Rotation(_))
    ));

    let remove_at = retire_at + MIN_ROTATION_OVERLAP_SECS;
    let mut remove = next_policy(&retire, remove_at);
    remove.services[0].pins.remove(0);
    let remove = verified(&keyset, remove, &root, &online, ONLINE_KID, remove_at);
    let final_state = apply_verified_update(Some(&state2), remove, remove_at)
        .unwrap()
        .into_state();
    assert_eq!(
        final_state.plan().endpoints()[0].server_pins().as_slice(),
        &[NEW_PIN]
    );
}

#[test]
fn successor_cannot_bypass_pin_overlap_by_changing_the_service_id_set() {
    let root = key_pair(1);
    let online = key_pair(2);
    let (keyset, policy0) = base_objects(&online);
    let genesis = verified(&keyset, policy0, &root, &online, ONLINE_KID, NOW);
    let state0 = apply_verified_update(None, genesis.clone(), NOW)
        .unwrap()
        .into_state();

    let mut renamed = next_policy(&genesis, NOW + 1);
    let renamed_id = ServiceId([0x31; 16]);
    renamed.services[0].service_id = renamed_id;
    renamed.rules[0].service_ids = vec![renamed_id];
    renamed.services[0].pins = vec![ServerPinV2 {
        fingerprint: NEW_PIN,
        not_before: NOW - 60,
        expires_at: NOW + 60 * DAY,
        status: PinStatus::Active,
        status_since: NOW + 1,
    }];
    let renamed = verified(&keyset, renamed, &root, &online, ONLINE_KID, NOW + 1);
    assert!(matches!(
        apply_verified_update(Some(&state0), renamed, NOW + 1),
        Err(PolicyError::Rotation(_))
    ));

    let mut added = next_policy(&genesis, NOW + 1);
    let mut new_service = added.services[0].clone();
    new_service.service_id = renamed_id;
    new_service.pins = vec![ServerPinV2 {
        fingerprint: NEW_PIN,
        not_before: NOW - 60,
        expires_at: NOW + 60 * DAY,
        status: PinStatus::Active,
        status_since: NOW + 1,
    }];
    new_service.endpoints[0].endpoint_id = EndpointId([0x41; 16]);
    new_service.endpoints[0].ipv4 = Ipv4Addr::new(203, 0, 113, 11);
    added.services.push(new_service);
    added.rules[0].service_ids.push(renamed_id);
    let added = verified(&keyset, added, &root, &online, ONLINE_KID, NOW + 1);
    assert!(matches!(
        apply_verified_update(Some(&state0), added, NOW + 1),
        Err(PolicyError::Rotation(_))
    ));

    let (_, mut two_service_policy) = base_objects(&online);
    let mut second = two_service_policy.services[0].clone();
    second.service_id = renamed_id;
    second.endpoints[0].endpoint_id = EndpointId([0x41; 16]);
    second.endpoints[0].ipv4 = Ipv4Addr::new(203, 0, 113, 11);
    two_service_policy.services.push(second);
    two_service_policy.rules[0].service_ids.push(renamed_id);
    let two_service_genesis =
        verified(&keyset, two_service_policy, &root, &online, ONLINE_KID, NOW);
    let two_service_state = apply_verified_update(None, two_service_genesis.clone(), NOW)
        .unwrap()
        .into_state();
    let mut removed = next_policy(&two_service_genesis, NOW + 1);
    removed.services.pop();
    removed.rules[0].service_ids.pop();
    let removed = verified(&keyset, removed, &root, &online, ONLINE_KID, NOW + 1);
    assert!(matches!(
        apply_verified_update(Some(&two_service_state), removed, NOW + 1),
        Err(PolicyError::Rotation(_))
    ));
}

#[test]
fn online_key_rotation_requires_overlap_and_delays_revocation() {
    let root = key_pair(1);
    let online1 = key_pair(2);
    let online2 = key_pair(3);
    let (keyset0, policy0) = base_objects(&online1);
    let genesis = verified(&keyset0, policy0, &root, &online1, ONLINE_KID, NOW);
    let state0 = apply_verified_update(None, genesis.clone(), NOW)
        .unwrap()
        .into_state();

    let rotate_at = NOW + 1;
    let mut keyset1 = keyset0.clone();
    keyset1.keyset_epoch = 1;
    keyset1.issued_at = rotate_at;
    keyset1.previous_payload_hash = Some(genesis.keyset_hash);
    keyset1.keys[0].status = KeyStatus::Retiring;
    keyset1.keys[0].status_since = rotate_at;
    keyset1.keys.push(OnlineKeyV1 {
        kid: ONLINE_KID_2,
        ed25519_public_key: public_key(&online2),
        not_before: rotate_at,
        expires_at: keyset1.expires_at,
        status: KeyStatus::Active,
        status_since: rotate_at,
    });
    let mut policy1 = next_policy(&genesis, rotate_at);
    policy1.not_before = rotate_at;
    let retiring_signer_bundle =
        bundle_bytes(&keyset1, policy1.clone(), &root, &online1, ONLINE_KID);
    assert!(matches!(
        verify_bundle(&retiring_signer_bundle, &root_trust(&root), rotate_at),
        Err(PolicyError::Invalid(_))
    ));

    let (mut short_old_keyset, mut short_old_policy) = base_objects(&online1);
    short_old_keyset.keys[0].expires_at = NOW + 2 * 60 * 60;
    short_old_policy.expires_at = short_old_keyset.keys[0].expires_at;
    let short_old_genesis = verified(
        &short_old_keyset,
        short_old_policy,
        &root,
        &online1,
        ONLINE_KID,
        NOW,
    );
    let short_old_state = apply_verified_update(None, short_old_genesis.clone(), NOW)
        .unwrap()
        .into_state();
    let mut short_overlap_keyset = short_old_keyset.clone();
    short_overlap_keyset.keyset_epoch = 1;
    short_overlap_keyset.issued_at = rotate_at;
    short_overlap_keyset.previous_payload_hash = Some(short_old_genesis.keyset_hash);
    short_overlap_keyset.keys[0].status = KeyStatus::Retiring;
    short_overlap_keyset.keys[0].status_since = rotate_at;
    short_overlap_keyset.keys.push(OnlineKeyV1 {
        kid: ONLINE_KID_2,
        ed25519_public_key: public_key(&online2),
        not_before: rotate_at,
        expires_at: short_overlap_keyset.expires_at,
        status: KeyStatus::Active,
        status_since: rotate_at,
    });
    let mut short_overlap_policy = next_policy(&short_old_genesis, rotate_at);
    short_overlap_policy.not_before = rotate_at;
    short_overlap_policy.expires_at = NOW + 6 * DAY;
    let short_rotation = verified(
        &short_overlap_keyset,
        short_overlap_policy,
        &root,
        &online2,
        ONLINE_KID_2,
        rotate_at,
    );
    assert!(matches!(
        apply_verified_update(Some(&short_old_state), short_rotation, rotate_at),
        Err(PolicyError::Rotation(_))
    ));

    let rotate = verified(&keyset1, policy1, &root, &online2, ONLINE_KID_2, rotate_at);
    let state1 = apply_verified_update(Some(&state0), rotate.clone(), rotate_at)
        .unwrap()
        .into_state();

    let mut premature_keyset = keyset1.clone();
    premature_keyset.keyset_epoch = 2;
    premature_keyset.issued_at = rotate_at + 1;
    premature_keyset.previous_payload_hash = Some(rotate.keyset_hash);
    premature_keyset.keys[0].status = KeyStatus::Revoked;
    premature_keyset.keys[0].status_since = rotate_at + 1;
    let premature_policy = next_policy(&rotate, rotate_at + 1);
    let premature = verified(
        &premature_keyset,
        premature_policy,
        &root,
        &online2,
        ONLINE_KID_2,
        rotate_at + 1,
    );
    assert!(matches!(
        apply_verified_update(Some(&state1), premature, rotate_at + 1),
        Err(PolicyError::Rotation(_))
    ));

    let revoke_at = rotate_at + MIN_ROTATION_OVERLAP_SECS;
    let mut keyset2 = keyset1.clone();
    keyset2.keyset_epoch = 2;
    keyset2.issued_at = revoke_at;
    keyset2.previous_payload_hash = Some(rotate.keyset_hash);
    keyset2.keys[0].status = KeyStatus::Revoked;
    keyset2.keys[0].status_since = revoke_at;
    let policy2 = next_policy(&rotate, revoke_at);
    let revoke = verified(&keyset2, policy2, &root, &online2, ONLINE_KID_2, revoke_at);
    let state2 = apply_verified_update(Some(&state1), revoke, revoke_at)
        .unwrap()
        .into_state();
    assert_eq!(state2.accepted.keyset.keys[0].status, KeyStatus::Revoked);
    assert_eq!(state2.accepted.signer_kid, ONLINE_KID_2);

    let remove_revoked_at = revoke_at + 1;
    let mut keyset3 = state2.accepted.keyset.clone();
    keyset3.keyset_epoch = 3;
    keyset3.issued_at = remove_revoked_at;
    keyset3.previous_payload_hash = Some(state2.accepted.keyset_hash);
    keyset3.keys.remove(0);
    let policy3 = next_policy(&state2.accepted, remove_revoked_at);
    let remove_revoked = verified(
        &keyset3,
        policy3,
        &root,
        &online2,
        ONLINE_KID_2,
        remove_revoked_at,
    );
    let state3 = apply_verified_update(Some(&state2), remove_revoked, remove_revoked_at)
        .unwrap()
        .into_state();
    assert_eq!(state3.accepted.keyset.keys.len(), 1);
    assert_eq!(state3.accepted.keyset.keys[0].kid, ONLINE_KID_2);
}
