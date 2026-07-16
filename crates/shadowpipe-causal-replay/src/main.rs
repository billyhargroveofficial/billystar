#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use clap::Parser;
use shadowpipe_causal_replay::{replay, ReplayScenario};
use std::fs::File;
use std::io::{self, Read, Write};

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "sp-causal-replay",
    about = "Offline shadow replay: derive carrier health from closed-schema raw measurements",
    long_about = "Validate versioned measurement traces, derive conservative carrier health, and emit an advisory shadow recommendation. This program has no networking or route-application mode."
)]
struct Cli {
    /// JSON scenario file, or '-' for stdin.
    #[arg(default_value = "-")]
    input: String,

    /// Emit compact JSON instead of the default stable pretty form.
    #[arg(long)]
    compact: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let input = if cli.input == "-" {
        read_limited(io::stdin().lock(), "stdin")?
    } else {
        let file = File::open(&cli.input)
            .with_context(|| format!("open replay scenario {}", cli.input))?;
        read_limited(file, &cli.input)?
    };

    let scenario: ReplayScenario =
        serde_json::from_slice(&input).context("parse replay scenario JSON")?;
    let report = replay(scenario).context("replay scenario")?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if cli.compact {
        serde_json::to_writer(&mut output, &report).context("serialize replay report")?;
    } else {
        serde_json::to_writer_pretty(&mut output, &report).context("serialize replay report")?;
    }
    output.write_all(b"\n").context("write replay report")?;
    Ok(())
}

fn read_limited(reader: impl Read, label: &str) -> Result<Vec<u8>> {
    let mut input = Vec::new();
    reader
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut input)
        .with_context(|| format!("read replay scenario from {label}"))?;
    if input.len() as u64 > MAX_INPUT_BYTES {
        bail!(
            "replay scenario exceeds the {}-byte input limit",
            MAX_INPUT_BYTES
        );
    }
    Ok(input)
}
