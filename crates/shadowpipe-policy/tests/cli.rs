use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};

const ROOT_KID: &str = "10101010101010101010101010101010";
const ONLINE_KID: &str = "20202020202020202020202020202020";
const DAY: i64 = 24 * 60 * 60;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let path = std::env::temp_dir().join(format!(
            "shadowpipe-policy-cli-test-{}-{}",
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

fn policy_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_shadowpipe-policy"))
}

fn help(subcommand: &str) -> Output {
    policy_command()
        .args([subcommand, "--help"])
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).unwrap()
}

fn assert_success(output: &Output, command: &str) {
    assert!(
        output.status.success(),
        "{command} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_json(path: &PathBuf, value: &Value) {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    fs::write(path, bytes).unwrap();
}

#[test]
fn subcommands_expose_only_their_custody_domain() {
    let top = policy_command().arg("--help").output().unwrap();
    assert!(top.status.success());
    assert!(stdout(&top).contains("endpoint-policy v2"));
    assert!(stdout(&top).contains("keyset v1"));

    let keyset = help("sign-keyset");
    assert!(keyset.status.success());
    assert!(stdout(&keyset).contains("--root-seed"));
    assert!(!stdout(&keyset).contains("--online-seed"));
    assert!(stdout(&keyset).contains("--mode"));
    assert!(stdout(&keyset).contains("--previous-bundle"));
    assert!(!stdout(&keyset).contains("--verify-at"));

    let policy = help("sign-policy");
    assert!(policy.status.success());
    assert!(stdout(&policy).contains("--online-seed"));
    assert!(!stdout(&policy).contains("--root-seed"));
    assert!(stdout(&policy).contains("--mode"));
    assert!(!stdout(&policy).contains("--verify-at"));

    for public_only in ["assemble", "verify"] {
        let output = help(public_only);
        assert!(output.status.success());
        assert!(!stdout(&output).contains("--root-seed"));
        assert!(!stdout(&output).contains("--online-seed"));
        assert!(!stdout(&output).contains("--seed-out"));
        assert!(!stdout(&output).contains("--verify-at"));
    }
}

#[test]
fn release_mode_never_infers_or_silently_ignores_a_predecessor() {
    let successor_without_previous = policy_command()
        .args([
            "sign-keyset",
            "--mode",
            "successor",
            "--root-seed",
            "missing.seed",
            "--root-identity",
            "missing-root.json",
            "--spec",
            "missing-spec.json",
            "--out",
            "missing-output.cose",
        ])
        .output()
        .unwrap();
    assert!(!successor_without_previous.status.success());
    assert!(String::from_utf8_lossy(&successor_without_previous.stderr)
        .contains("successor mode requires --previous-bundle"));

    let enrollment_with_previous = policy_command()
        .args([
            "assemble",
            "--mode",
            "enrollment",
            "--previous-bundle",
            "unexpected.cbor",
            "--root-identity",
            "missing-root.json",
            "--keyset",
            "missing-keyset.cose",
            "--policy",
            "missing-policy.cose",
            "--out",
            "missing-bundle.cbor",
        ])
        .output()
        .unwrap();
    assert!(!enrollment_with_previous.status.success());
    assert!(String::from_utf8_lossy(&enrollment_with_previous.stderr)
        .contains("enrollment mode forbids --previous-bundle"));
}

#[test]
fn key_generation_is_silent_and_writes_only_to_requested_files() {
    let directory = TestDir::new();
    let seed = directory.path("root.seed");
    let identity = directory.path("root.identity.json");
    let output = policy_command()
        .args([
            "root-keygen",
            "--seed-out",
            seed.to_str().unwrap(),
            "--identity-out",
            identity.to_str().unwrap(),
            "--kid",
            ROOT_KID,
        ])
        .output()
        .unwrap();
    assert_success(&output, "root-keygen");
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert_eq!(fs::metadata(&seed).unwrap().len(), 32);
    assert!(identity.is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(seed).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(identity).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
#[cfg(unix)]
fn complete_cli_workflow_round_trips_public_artifacts() {
    let now: i64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();
    let directory = TestDir::new();
    let root_seed = directory.path("root.seed");
    let root_identity = directory.path("root.identity.json");
    let online_seed = directory.path("online.seed");
    let online_identity = directory.path("online.identity.json");

    let root_keygen = policy_command()
        .args(["root-keygen", "--seed-out"])
        .arg(&root_seed)
        .arg("--identity-out")
        .arg(&root_identity)
        .args(["--kid", ROOT_KID])
        .output()
        .unwrap();
    assert_success(&root_keygen, "root-keygen");

    let online_keygen = policy_command()
        .args(["online-keygen", "--seed-out"])
        .arg(&online_seed)
        .arg("--identity-out")
        .arg(&online_identity)
        .args(["--kid", ONLINE_KID])
        .output()
        .unwrap();
    assert_success(&online_keygen, "online-keygen");

    let online: Value = serde_json::from_slice(&fs::read(&online_identity).unwrap()).unwrap();
    let keyset_spec = directory.path("keyset.json");
    write_json(
        &keyset_spec,
        &json!({
            "schema_version": 1,
            "keyset_epoch": 0,
            "issued_at": now,
            "not_before": now - 60,
            "expires_at": now + 60 * DAY,
            "previous_payload_hash": null,
            "keys": [{
                "kid": online["kid"],
                "ed25519_public_key": online["ed25519_public_key"],
                "not_before": now - 60,
                "expires_at": now + 60 * DAY,
                "status": "active",
                "status_since": now - 60
            }]
        }),
    );
    let keyset = directory.path("keyset.cose");
    let sign_keyset = policy_command()
        .arg("sign-keyset")
        .args(["--mode", "enrollment"])
        .arg("--root-seed")
        .arg(&root_seed)
        .arg("--root-identity")
        .arg(&root_identity)
        .arg("--spec")
        .arg(&keyset_spec)
        .arg("--out")
        .arg(&keyset)
        .output()
        .unwrap();
    assert_success(&sign_keyset, "sign-keyset");
    assert!(sign_keyset.stdout.is_empty());
    assert!(sign_keyset.stderr.is_empty());

    let policy_spec = directory.path("policy.json");
    write_json(
        &policy_spec,
        &json!({
            "schema_version": 2,
            "policy_epoch": 0,
            "sequence": 0,
            "issued_at": now,
            "not_before": now - 60,
            "expires_at": now + 6 * DAY,
            "previous_payload_hash": null,
            "services": [{
                "service_id": "30303030303030303030303030303030",
                "pins": [{
                    "fingerprint": "5050505050505050505050505050505050505050505050505050505050505050",
                    "not_before": now - 60,
                    "expires_at": now + 60 * DAY,
                    "status": "active",
                    "status_since": now - 60
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
        }),
    );
    let policy = directory.path("policy.cose");
    let sign_policy = policy_command()
        .arg("sign-policy")
        .args(["--mode", "enrollment"])
        .arg("--online-seed")
        .arg(&online_seed)
        .arg("--online-identity")
        .arg(&online_identity)
        .arg("--root-identity")
        .arg(&root_identity)
        .arg("--keyset")
        .arg(&keyset)
        .arg("--spec")
        .arg(&policy_spec)
        .arg("--out")
        .arg(&policy)
        .output()
        .unwrap();
    assert_success(&sign_policy, "sign-policy");
    assert!(sign_policy.stdout.is_empty());
    assert!(sign_policy.stderr.is_empty());

    let bundle = directory.path("bundle.cbor");
    let assemble = policy_command()
        .arg("assemble")
        .args(["--mode", "enrollment"])
        .arg("--root-identity")
        .arg(&root_identity)
        .arg("--keyset")
        .arg(&keyset)
        .arg("--policy")
        .arg(&policy)
        .arg("--out")
        .arg(&bundle)
        .output()
        .unwrap();
    assert_success(&assemble, "assemble");
    let assembled_summary: Value = serde_json::from_slice(&assemble.stdout).unwrap();
    assert_eq!(assembled_summary["root_id"].as_str().unwrap().len(), 64);
    assert_eq!(
        assembled_summary["keyset_payload_hash"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        assembled_summary["policy_payload_hash"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(assembled_summary["signer_kid"], ONLINE_KID);
    assert_eq!(assembled_summary["endpoint_count"], 1);

    let verify = policy_command()
        .arg("verify")
        .arg("--root-identity")
        .arg(&root_identity)
        .arg("--bundle")
        .arg(&bundle)
        .output()
        .unwrap();
    assert_success(&verify, "verify");
    let verified_summary: Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verified_summary, assembled_summary);

    let keyset_next_spec = directory.path("keyset-next.json");
    write_json(
        &keyset_next_spec,
        &json!({
            "schema_version": 1,
            "keyset_epoch": 1,
            "issued_at": now,
            "not_before": now - 60,
            "expires_at": now + 60 * DAY,
            "previous_payload_hash": assembled_summary["keyset_payload_hash"],
            "keys": [{
                "kid": online["kid"],
                "ed25519_public_key": online["ed25519_public_key"],
                "not_before": now - 60,
                "expires_at": now + 60 * DAY,
                "status": "active",
                "status_since": now - 60
            }]
        }),
    );
    let keyset_next = directory.path("keyset-next.cose");
    let sign_keyset_next = policy_command()
        .arg("sign-keyset")
        .args(["--mode", "successor"])
        .arg("--previous-bundle")
        .arg(&bundle)
        .arg("--root-seed")
        .arg(&root_seed)
        .arg("--root-identity")
        .arg(&root_identity)
        .arg("--spec")
        .arg(&keyset_next_spec)
        .arg("--out")
        .arg(&keyset_next)
        .output()
        .unwrap();
    assert_success(&sign_keyset_next, "sign-keyset successor");
    assert!(sign_keyset_next.stdout.is_empty());
    assert!(sign_keyset_next.stderr.is_empty());

    let mut policy_next_value: Value =
        serde_json::from_slice(&fs::read(&policy_spec).unwrap()).unwrap();
    policy_next_value["sequence"] = json!(1);
    policy_next_value["previous_payload_hash"] = assembled_summary["policy_payload_hash"].clone();
    let policy_next_spec = directory.path("policy-next.json");
    write_json(&policy_next_spec, &policy_next_value);
    let policy_next = directory.path("policy-next.cose");
    let sign_policy_next = policy_command()
        .arg("sign-policy")
        .args(["--mode", "successor"])
        .arg("--previous-bundle")
        .arg(&bundle)
        .arg("--online-seed")
        .arg(&online_seed)
        .arg("--online-identity")
        .arg(&online_identity)
        .arg("--root-identity")
        .arg(&root_identity)
        .arg("--keyset")
        .arg(&keyset_next)
        .arg("--spec")
        .arg(&policy_next_spec)
        .arg("--out")
        .arg(&policy_next)
        .output()
        .unwrap();
    assert_success(&sign_policy_next, "sign-policy successor");
    assert!(sign_policy_next.stdout.is_empty());
    assert!(sign_policy_next.stderr.is_empty());

    let bundle_next = directory.path("bundle-next.cbor");
    let assemble_next = policy_command()
        .arg("assemble")
        .args(["--mode", "successor"])
        .arg("--previous-bundle")
        .arg(&bundle)
        .arg("--root-identity")
        .arg(&root_identity)
        .arg("--keyset")
        .arg(&keyset_next)
        .arg("--policy")
        .arg(&policy_next)
        .arg("--out")
        .arg(&bundle_next)
        .output()
        .unwrap();
    assert_success(&assemble_next, "assemble successor");
    let successor_summary: Value = serde_json::from_slice(&assemble_next.stdout).unwrap();
    assert_eq!(successor_summary["keyset_epoch"], 1);
    assert_eq!(successor_summary["policy_epoch"], 0);
    assert_eq!(successor_summary["sequence"], 1);
}
