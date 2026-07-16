use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

const SCENARIO: &str = include_str!("../examples/scenario.example.json");
const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

fn run_cli() -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sp-causal-replay"))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(SCENARIO.as_bytes())
        .expect("write scenario");
    child.wait_with_output().expect("wait for CLI")
}

#[test]
fn stdin_replay_is_shadow_only_and_byte_deterministic() {
    let first = run_cli();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = run_cli();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(first.stdout, second.stdout);

    let report: Value = serde_json::from_slice(&first.stdout).expect("valid report JSON");
    assert_eq!(report["selection"]["mode"], "shadow");
    assert_eq!(report["selection"]["verdict"]["verdict"], "would_select");
    assert_eq!(
        report["selection"]["verdict"]["candidate"]["carrier_id"],
        "relay"
    );
}

#[test]
fn oversized_stdin_is_rejected_before_json_parsing() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sp-causal-replay"))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(&vec![b' '; MAX_INPUT_BYTES + 1])
        .expect("write bounded oversize input");

    let output = child.wait_with_output().expect("wait for CLI");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("input limit"));
}
