//! Offline runner for the read-only causal carrier selector.
//!
//! This example accepts only immutable JSON snapshots. It has no carrier
//! handles, sockets, route APIs, or activation path, so its result is advisory.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use shadowpipe_core::control::{
    CarrierCandidate, SelectionRequirements, SelectorPolicy, ShadowSelectionReport, ShadowSelector,
};
use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

const SCHEMA_VERSION: u32 = 1;
const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowSelectionInput {
    schema_version: u32,
    policy: SelectorPolicy,
    requirements: SelectionRequirements,
    candidates: Vec<CarrierCandidate>,
}

#[derive(Debug, Serialize)]
struct ShadowSelectionOutput {
    schema_version: u32,
    report: ShadowSelectionReport,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("causal-shadow: {error:#}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let Some(input_arg) = args.next() else {
        bail!(
            "usage: {} <snapshot.json|->",
            Path::new(&program)
                .file_name()
                .unwrap_or_else(|| OsStr::new("causal_shadow"))
                .to_string_lossy()
        );
    };
    if args.next().is_some() {
        bail!("expected exactly one JSON input path (or - for stdin)");
    }

    let bytes = if input_arg == OsStr::new("-") {
        read_limited(io::stdin().lock()).context("read JSON snapshot from stdin")?
    } else {
        let path = Path::new(&input_arg);
        let file =
            File::open(path).with_context(|| format!("open JSON snapshot {}", path.display()))?;
        read_limited(file).with_context(|| format!("read JSON snapshot {}", path.display()))?
    };

    let input: ShadowSelectionInput =
        serde_json::from_slice(&bytes).context("parse JSON snapshot")?;
    if input.schema_version != SCHEMA_VERSION {
        bail!(
            "unsupported schema_version {}; expected {}",
            input.schema_version,
            SCHEMA_VERSION
        );
    }

    let selector = ShadowSelector::new(input.policy).context("validate selector policy")?;
    let output = ShadowSelectionOutput {
        schema_version: SCHEMA_VERSION,
        report: selector.evaluate(&input.requirements, &input.candidates),
    };

    let stdout = io::stdout();
    let mut writer = stdout.lock();
    serde_json::to_writer_pretty(&mut writer, &output).context("serialize selection report")?;
    writer.write_all(b"\n").context("write selection report")?;
    Ok(())
}

fn read_limited(reader: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read input bytes")?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        bail!("input exceeds {MAX_INPUT_BYTES} byte safety limit");
    }
    Ok(bytes)
}
