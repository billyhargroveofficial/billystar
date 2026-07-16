use std::fs;
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::*;
use crate::custody::{
    atomic_write_new, read_public_file, read_secret_seed, write_secret_seed_create_new, SecretSeed,
};

const NOW: i64 = 2_000_000_000;
const DAY: i64 = 24 * 60 * 60;
const ROOT_KID_HEX: &str = "10101010101010101010101010101010";
const ONLINE_KID_HEX: &str = "20202020202020202020202020202020";

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let path = std::env::temp_dir().join(format!(
            "shadowpipe-policy-test-{}-{}",
            std::process::id(),
            hex::encode(nonce)
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    directory: TestDir,
    root_seed: PathBuf,
    root_identity: PathBuf,
    online_seed: PathBuf,
    online_identity: PathBuf,
    keyset_spec: PathBuf,
    policy_spec: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = TestDir::new();
        let root_seed = directory.path("root.seed");
        let root_identity = directory.path("root.json");
        let online_seed = directory.path("online.seed");
        let online_identity = directory.path("online.json");
        let keyset_spec = directory.path("keyset.json");
        let policy_spec = directory.path("policy.json");

        let root_secret = SecretSeed::from_test_bytes([1u8; 32]);
        let online_secret = SecretSeed::from_test_bytes([2u8; 32]);
        write_secret_seed_create_new(&root_seed, &root_secret).unwrap();
        write_secret_seed_create_new(&online_seed, &online_secret).unwrap();
        let root_document = IdentityDocument::new(
            IdentityKind::OfflineRoot,
            Kid::new([0x10; 16]),
            public_key(&key_pair(&root_secret).unwrap()),
        );
        let online_document = IdentityDocument::new(
            IdentityKind::OnlinePolicy,
            Kid::new([0x20; 16]),
            public_key(&key_pair(&online_secret).unwrap()),
        );
        atomic_write_new(&root_identity, &root_document.to_pretty_json().unwrap()).unwrap();
        atomic_write_new(&online_identity, &online_document.to_pretty_json().unwrap()).unwrap();
        write_json(
            &keyset_spec,
            &keyset_value(&online_document, 0, Value::Null),
        );
        write_json(&policy_spec, &policy_value());

        Self {
            directory,
            root_seed,
            root_identity,
            online_seed,
            online_identity,
            keyset_spec,
            policy_spec,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path(name)
    }

    fn sign_keyset_at(&self, output: &Path) {
        sign_keyset_at(
            &self.root_seed,
            &self.root_identity,
            &self.keyset_spec,
            output,
            None,
            NOW,
        )
        .unwrap();
    }

    fn sign_policy_at(&self, keyset: &Path, output: &Path) {
        sign_policy_at(
            &self.online_seed,
            &self.online_identity,
            &self.root_identity,
            keyset,
            &self.policy_spec,
            output,
            None,
            NOW,
        )
        .unwrap();
    }
}

fn write_json(path: &Path, value: &Value) {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    atomic_write_new(path, &bytes).unwrap();
}

fn keyset_value(online: &IdentityDocument, epoch: u64, previous: Value) -> Value {
    json!({
        "schema_version": 1,
        "keyset_epoch": epoch,
        "issued_at": NOW,
        "not_before": NOW - 60,
        "expires_at": NOW + 60 * DAY,
        "previous_payload_hash": previous,
        "keys": [{
            "kid": online.kid,
            "ed25519_public_key": online.ed25519_public_key,
            "not_before": NOW - 60,
            "expires_at": NOW + 60 * DAY,
            "status": "active",
            "status_since": NOW - 60
        }]
    })
}

fn policy_value() -> Value {
    json!({
        "schema_version": 2,
        "policy_epoch": 0,
        "sequence": 0,
        "issued_at": NOW,
        "not_before": NOW - 60,
        "expires_at": NOW + 6 * DAY,
        "previous_payload_hash": null,
        "services": [{
            "service_id": "30303030303030303030303030303030",
            "pins": [{
                "fingerprint": "5050505050505050505050505050505050505050505050505050505050505050",
                "not_before": NOW - 60,
                "expires_at": NOW + 60 * DAY,
                "status": "active",
                "status_since": NOW - 60
            }],
            "endpoints": [{
                "endpoint_id": "40404040404040404040404040404040",
                "ipv4": "203.0.113.10",
                "port": 443,
                "locator_name": "edge.shadowpipe.example",
                "sni": "cdn.example.com",
                "reality_x25519_public_key": "6060606060606060606060606060606060606060606060606060606060606060",
                "reality_short_id": "7070707070707070"
            }]
        }],
        "experiment_evidence": []
    })
}

#[test]
fn deterministic_signatures_and_complete_round_trip_match_golden_vector() {
    let fixture = Fixture::new();
    let keyset_a = fixture.path("keyset-a.cose");
    let keyset_b = fixture.path("keyset-b.cose");
    fixture.sign_keyset_at(&keyset_a);
    fixture.sign_keyset_at(&keyset_b);
    let keyset_bytes = read_public_file(&keyset_a, MAX_BUNDLE_BYTES).unwrap();
    assert_eq!(
        keyset_bytes,
        read_public_file(&keyset_b, MAX_BUNDLE_BYTES).unwrap()
    );
    assert_eq!(
        hex::encode(Sha256::digest(&keyset_bytes)),
        "dad9ca8346754421b673b1f42669640ca09c50d8724b9a2ede8dd6479c47aa1e"
    );

    let policy = fixture.path("policy.cose");
    fixture.sign_policy_at(&keyset_a, &policy);
    let bundle = fixture.path("bundle.cbor");
    let summary = assemble_bundle_at(
        &fixture.root_identity,
        &keyset_a,
        &policy,
        &bundle,
        None,
        NOW,
    )
    .unwrap();
    assert_eq!(summary.keyset_epoch, 0);
    assert_eq!(summary.keyset_payload_hash.len(), 64);
    assert_eq!(summary.policy_epoch, 0);
    assert_eq!(summary.sequence, 0);
    assert_eq!(summary.policy_payload_hash.len(), 64);
    assert_eq!(summary.signer_kid, ONLINE_KID_HEX);
    assert_eq!(summary.endpoint_count, 1);
    assert_eq!(
        verify_bundle_file_at(&fixture.root_identity, &bundle, NOW).unwrap(),
        summary
    );
    let decoded = decode_bundle(&read_public_file(&bundle, MAX_BUNDLE_BYTES).unwrap()).unwrap();
    assert_eq!(decoded.keyset_sign1, keyset_bytes);
    assert_eq!(
        decoded.policy_sign1,
        read_public_file(&policy, MAX_BUNDLE_BYTES).unwrap()
    );
}

#[test]
fn keygen_creates_exact_secure_seed_and_never_overwrites() {
    let directory = TestDir::new();
    let seed = directory.path("root.seed");
    let identity = directory.path("root.json");
    let generated = generate_identity(
        IdentityKind::OfflineRoot,
        Some(ROOT_KID_HEX),
        &seed,
        &identity,
    )
    .unwrap();
    assert_eq!(generated.kid, ROOT_KID_HEX);
    assert_eq!(fs::metadata(&seed).unwrap().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&seed).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&identity).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let loaded = load_identity(&identity).unwrap();
    assert_eq!(loaded, generated);
    let seed_before = read_public_file(&seed, 32).unwrap();
    let unused_identity = directory.path("must-not-exist.json");
    assert!(generate_identity(
        IdentityKind::OfflineRoot,
        Some(ROOT_KID_HEX),
        &seed,
        &unused_identity,
    )
    .is_err());
    assert_eq!(read_public_file(&seed, 32).unwrap(), seed_before);
    assert!(!unused_identity.exists());
}

#[test]
#[cfg(unix)]
fn malformed_symlink_mode_and_hardlinked_seeds_are_rejected() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = TestDir::new();
    let short = directory.path("short.seed");
    fs::write(&short, [1u8; 31]).unwrap();
    fs::set_permissions(&short, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_secret_seed(&short).is_err());

    let permissive = directory.path("permissive.seed");
    fs::write(&permissive, [2u8; 32]).unwrap();
    fs::set_permissions(&permissive, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_secret_seed(&permissive).is_err());

    let original = directory.path("original.seed");
    fs::write(&original, [3u8; 32]).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
    let hardlink = directory.path("hardlink.seed");
    fs::hard_link(&original, &hardlink).unwrap();
    assert!(read_secret_seed(&original).is_err());
    assert!(read_secret_seed(&hardlink).is_err());

    let symlink_path = directory.path("symlink.seed");
    symlink(&permissive, &symlink_path).unwrap();
    assert!(read_secret_seed(&symlink_path).is_err());
}

#[test]
fn strict_json_rejects_unknown_top_level_and_nested_fields() {
    let fixture = Fixture::new();
    let mut top_level = keyset_value(
        &load_identity(&fixture.online_identity).unwrap(),
        0,
        Value::Null,
    );
    top_level
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), json!(true));
    let top_path = fixture.path("unknown-top.json");
    write_json(&top_path, &top_level);
    assert!(sign_keyset_at(
        &fixture.root_seed,
        &fixture.root_identity,
        &top_path,
        &fixture.path("unknown-top.cose"),
        None,
        NOW,
    )
    .is_err());

    let mut nested = policy_value();
    nested["services"][0]["endpoints"][0]["unsigned_dns"] = json!("evil.example");
    let nested_path = fixture.path("unknown-nested.json");
    write_json(&nested_path, &nested);
    let keyset = fixture.path("valid-keyset.cose");
    fixture.sign_keyset_at(&keyset);
    assert!(sign_policy_at(
        &fixture.online_seed,
        &fixture.online_identity,
        &fixture.root_identity,
        &keyset,
        &nested_path,
        &fixture.path("unknown-nested.cose"),
        None,
        NOW,
    )
    .is_err());
}

#[test]
fn policy_signer_requires_v2_and_an_explicit_locator_name() {
    let fixture = Fixture::new();
    let keyset = fixture.path("valid-keyset.cose");
    fixture.sign_keyset_at(&keyset);

    let mut legacy = policy_value();
    legacy["schema_version"] = json!(1);
    let legacy_path = fixture.path("legacy-v1-policy.json");
    write_json(&legacy_path, &legacy);
    let legacy_output = fixture.path("legacy-v1-policy.cose");
    let error = sign_policy_at(
        &fixture.online_seed,
        &fixture.online_identity,
        &fixture.root_identity,
        &keyset,
        &legacy_path,
        &legacy_output,
        None,
        NOW,
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("unsupported endpoint-policy document schema 1; only schema 2 is accepted"));
    assert!(!legacy_output.exists());

    let mut missing_locator = policy_value();
    missing_locator["services"][0]["endpoints"][0]
        .as_object_mut()
        .unwrap()
        .remove("locator_name");
    let missing_path = fixture.path("missing-locator-policy.json");
    write_json(&missing_path, &missing_locator);
    let missing_output = fixture.path("missing-locator-policy.cose");
    let error = sign_policy_at(
        &fixture.online_seed,
        &fixture.online_identity,
        &fixture.root_identity,
        &keyset,
        &missing_path,
        &missing_output,
        None,
        NOW,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("locator_name"));
    assert!(!missing_output.exists());

    let mut short_reality_id = policy_value();
    short_reality_id["services"][0]["endpoints"][0]["reality_short_id"] = json!("70");
    let short_id_path = fixture.path("short-reality-id-policy.json");
    write_json(&short_id_path, &short_reality_id);
    let short_id_output = fixture.path("short-reality-id-policy.cose");
    let error = sign_policy_at(
        &fixture.online_seed,
        &fixture.online_identity,
        &fixture.root_identity,
        &keyset,
        &short_id_path,
        &short_id_output,
        None,
        NOW,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("exactly 8 bytes"));
    assert!(!short_id_output.exists());
}

#[test]
fn mismatched_root_seed_online_kid_and_public_entry_are_rejected() {
    let fixture = Fixture::new();
    let wrong_root_secret = SecretSeed::from_test_bytes([9u8; 32]);
    let wrong_root_document = IdentityDocument::new(
        IdentityKind::OfflineRoot,
        Kid::new([0x10; 16]),
        public_key(&key_pair(&wrong_root_secret).unwrap()),
    );
    let wrong_root = fixture.path("wrong-root.json");
    atomic_write_new(&wrong_root, &wrong_root_document.to_pretty_json().unwrap()).unwrap();
    assert!(sign_keyset_at(
        &fixture.root_seed,
        &wrong_root,
        &fixture.keyset_spec,
        &fixture.path("wrong-root.cose"),
        None,
        NOW,
    )
    .is_err());

    let keyset = fixture.path("valid-keyset.cose");
    fixture.sign_keyset_at(&keyset);
    let mut wrong_kid_identity = load_identity(&fixture.online_identity).unwrap();
    wrong_kid_identity.kid = "21212121212121212121212121212121".into();
    let wrong_kid = fixture.path("wrong-kid.json");
    atomic_write_new(&wrong_kid, &wrong_kid_identity.to_pretty_json().unwrap()).unwrap();
    assert!(sign_policy_at(
        &fixture.online_seed,
        &wrong_kid,
        &fixture.root_identity,
        &keyset,
        &fixture.policy_spec,
        &fixture.path("wrong-kid.cose"),
        None,
        NOW,
    )
    .is_err());

    let different_online_secret = SecretSeed::from_test_bytes([3u8; 32]);
    let mut wrong_public_spec = keyset_value(
        &load_identity(&fixture.online_identity).unwrap(),
        0,
        Value::Null,
    );
    wrong_public_spec["keys"][0]["ed25519_public_key"] = json!(hex::encode(public_key(
        &key_pair(&different_online_secret).unwrap()
    )));
    let wrong_public_spec_path = fixture.path("wrong-public-keyset.json");
    write_json(&wrong_public_spec_path, &wrong_public_spec);
    let wrong_public_keyset = fixture.path("wrong-public-keyset.cose");
    sign_keyset_at(
        &fixture.root_seed,
        &fixture.root_identity,
        &wrong_public_spec_path,
        &wrong_public_keyset,
        None,
        NOW,
    )
    .unwrap();
    assert!(sign_policy_at(
        &fixture.online_seed,
        &fixture.online_identity,
        &fixture.root_identity,
        &wrong_public_keyset,
        &fixture.policy_spec,
        &fixture.path("wrong-public-policy.cose"),
        None,
        NOW,
    )
    .is_err());
}

#[test]
fn assemble_rejects_wrong_keyset_binding_before_output_publication() {
    let fixture = Fixture::new();
    let keyset0 = fixture.path("keyset0.cose");
    fixture.sign_keyset_at(&keyset0);
    let policy0 = fixture.path("policy0.cose");
    fixture.sign_policy_at(&keyset0, &policy0);

    let alternate_spec = fixture.path("keyset1.json");
    let mut alternate = keyset_value(
        &load_identity(&fixture.online_identity).unwrap(),
        0,
        Value::Null,
    );
    alternate["expires_at"] = json!(NOW + 59 * DAY);
    alternate["keys"][0]["expires_at"] = json!(NOW + 59 * DAY);
    write_json(&alternate_spec, &alternate);
    let keyset1 = fixture.path("keyset1.cose");
    sign_keyset_at(
        &fixture.root_seed,
        &fixture.root_identity,
        &alternate_spec,
        &keyset1,
        None,
        NOW,
    )
    .unwrap();
    let output = fixture.path("must-not-publish.cbor");
    assert!(assemble_bundle_at(
        &fixture.root_identity,
        &keyset1,
        &policy0,
        &output,
        None,
        NOW,
    )
    .is_err());
    assert!(!output.exists());
}

#[test]
fn successor_release_round_trips_through_the_exact_client_transition_rules() {
    let fixture = Fixture::new();
    let keyset0 = fixture.path("transition-keyset0.cose");
    fixture.sign_keyset_at(&keyset0);
    let policy0 = fixture.path("transition-policy0.cose");
    fixture.sign_policy_at(&keyset0, &policy0);
    let bundle0 = fixture.path("transition-bundle0.cbor");
    assemble_bundle_at(
        &fixture.root_identity,
        &keyset0,
        &policy0,
        &bundle0,
        None,
        NOW,
    )
    .unwrap();

    let root = load_root(&fixture.root_identity).unwrap();
    let previous = verify_bundle(
        &read_public_file(&bundle0, MAX_BUNDLE_BYTES).unwrap(),
        &root,
        NOW,
    )
    .unwrap();
    let keyset1_spec = fixture.path("transition-keyset1.json");
    write_json(
        &keyset1_spec,
        &keyset_value(
            &load_identity(&fixture.online_identity).unwrap(),
            1,
            json!(hex::encode(previous.keyset_hash())),
        ),
    );
    let keyset1 = fixture.path("transition-keyset1.cose");
    sign_keyset_at(
        &fixture.root_seed,
        &fixture.root_identity,
        &keyset1_spec,
        &keyset1,
        Some(&bundle0),
        NOW,
    )
    .unwrap();

    let mut policy1_value = policy_value();
    policy1_value["sequence"] = json!(1);
    policy1_value["previous_payload_hash"] = json!(hex::encode(previous.policy_hash()));
    let policy1_spec = fixture.path("transition-policy1.json");
    write_json(&policy1_spec, &policy1_value);
    let policy1 = fixture.path("transition-policy1.cose");
    sign_policy_at(
        &fixture.online_seed,
        &fixture.online_identity,
        &fixture.root_identity,
        &keyset1,
        &policy1_spec,
        &policy1,
        Some(&bundle0),
        NOW,
    )
    .unwrap();

    let bundle1 = fixture.path("transition-bundle1.cbor");
    let summary = assemble_bundle_at(
        &fixture.root_identity,
        &keyset1,
        &policy1,
        &bundle1,
        Some(&bundle0),
        NOW,
    )
    .unwrap();
    assert_eq!(summary.keyset_epoch, 1);
    assert_eq!(summary.policy_epoch, 0);
    assert_eq!(summary.sequence, 1);
}

#[test]
fn successor_mode_rejects_gap_bad_chain_and_idempotence_before_publication() {
    let fixture = Fixture::new();
    let keyset0 = fixture.path("adversarial-keyset0.cose");
    fixture.sign_keyset_at(&keyset0);
    let policy0 = fixture.path("adversarial-policy0.cose");
    fixture.sign_policy_at(&keyset0, &policy0);
    let bundle0 = fixture.path("adversarial-bundle0.cbor");
    assemble_bundle_at(
        &fixture.root_identity,
        &keyset0,
        &policy0,
        &bundle0,
        None,
        NOW,
    )
    .unwrap();
    let root = load_root(&fixture.root_identity).unwrap();
    let previous = verify_bundle(
        &read_public_file(&bundle0, MAX_BUNDLE_BYTES).unwrap(),
        &root,
        NOW,
    )
    .unwrap();

    let keyset_gap_spec = fixture.path("keyset-gap.json");
    write_json(
        &keyset_gap_spec,
        &keyset_value(
            &load_identity(&fixture.online_identity).unwrap(),
            2,
            json!(hex::encode(previous.keyset_hash())),
        ),
    );
    let keyset_gap = fixture.path("keyset-gap.cose");
    assert!(sign_keyset_at(
        &fixture.root_seed,
        &fixture.root_identity,
        &keyset_gap_spec,
        &keyset_gap,
        Some(&bundle0),
        NOW,
    )
    .is_err());
    assert!(!keyset_gap.exists());

    let mut policy_gap_value = policy_value();
    policy_gap_value["sequence"] = json!(2);
    policy_gap_value["previous_payload_hash"] = json!(hex::encode(previous.policy_hash()));
    let policy_gap_spec = fixture.path("policy-gap.json");
    write_json(&policy_gap_spec, &policy_gap_value);
    let policy_gap = fixture.path("policy-gap.cose");
    assert!(sign_policy_at(
        &fixture.online_seed,
        &fixture.online_identity,
        &fixture.root_identity,
        &keyset0,
        &policy_gap_spec,
        &policy_gap,
        Some(&bundle0),
        NOW,
    )
    .is_err());
    assert!(!policy_gap.exists());

    let mut wrong_chain_value = policy_value();
    wrong_chain_value["sequence"] = json!(1);
    wrong_chain_value["previous_payload_hash"] =
        json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let wrong_chain_spec = fixture.path("wrong-chain.json");
    write_json(&wrong_chain_spec, &wrong_chain_value);
    let wrong_chain = fixture.path("wrong-chain.cose");
    assert!(sign_policy_at(
        &fixture.online_seed,
        &fixture.online_identity,
        &fixture.root_identity,
        &keyset0,
        &wrong_chain_spec,
        &wrong_chain,
        Some(&bundle0),
        NOW,
    )
    .is_err());
    assert!(!wrong_chain.exists());

    let idempotent = fixture.path("idempotent-policy.cose");
    assert!(sign_policy_at(
        &fixture.online_seed,
        &fixture.online_identity,
        &fixture.root_identity,
        &keyset0,
        &fixture.policy_spec,
        &idempotent,
        Some(&bundle0),
        NOW,
    )
    .is_err());
    assert!(!idempotent.exists());
}

#[test]
fn every_output_is_no_clobber_including_existing_symlinks() {
    let fixture = Fixture::new();
    let keyset = fixture.path("keyset.cose");
    fixture.sign_keyset_at(&keyset);
    let policy = fixture.path("policy.cose");
    fixture.sign_policy_at(&keyset, &policy);

    let output = fixture.path("existing-bundle.cbor");
    atomic_write_new(&output, b"sentinel").unwrap();
    assert!(
        assemble_bundle_at(&fixture.root_identity, &keyset, &policy, &output, None, NOW,).is_err()
    );
    assert_eq!(read_public_file(&output, 32).unwrap(), b"sentinel");

    let existing_keyset = fixture.path("existing-keyset.cose");
    atomic_write_new(&existing_keyset, b"root-sentinel").unwrap();
    assert!(sign_keyset_at(
        &fixture.root_seed,
        &fixture.root_identity,
        &fixture.keyset_spec,
        &existing_keyset,
        None,
        NOW,
    )
    .is_err());
    assert_eq!(
        read_public_file(&existing_keyset, 32).unwrap(),
        b"root-sentinel"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let victim = fixture.path("victim");
        atomic_write_new(&victim, b"victim").unwrap();
        let symlink_output = fixture.path("symlink-output");
        symlink(&victim, &symlink_output).unwrap();
        assert!(atomic_write_new(&symlink_output, b"attacker").is_err());
        assert_eq!(read_public_file(&victim, 32).unwrap(), b"victim");

        let real_directory = fixture.path("real-output-directory");
        fs::create_dir(&real_directory).unwrap();
        fs::set_permissions(&real_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let linked_directory = fixture.path("linked-output-directory");
        symlink(&real_directory, &linked_directory).unwrap();
        assert!(atomic_write_new(&linked_directory.join("artifact"), b"payload").is_err());
        assert!(!real_directory.join("artifact").exists());

        let writable_directory = fixture.path("writable-output-directory");
        fs::create_dir(&writable_directory).unwrap();
        fs::set_permissions(&writable_directory, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(atomic_write_new(&writable_directory.join("artifact"), b"payload").is_err());
        assert!(!writable_directory.join("artifact").exists());
    }
}
