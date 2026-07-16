use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use shadowpipe_policy::{
    assemble_bundle, generate_identity, sign_keyset, sign_policy, verify_bundle_file, IdentityKind,
};

#[derive(Parser)]
#[command(
    name = "shadowpipe-policy",
    about = "Offline/online custody-separated signer for Shadowpipe endpoint-policy v2 and keyset v1"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an offline-root Ed25519 seed and its public trust document.
    RootKeygen(KeygenArgs),
    /// Generate an online-policy Ed25519 seed and its public identity document.
    OnlineKeygen(KeygenArgs),
    /// Sign a canonical keyset using only offline-root private custody.
    SignKeyset(SignKeysetArgs),
    /// Sign a policy using only online private custody and a verified keyset.
    SignPolicy(SignPolicyArgs),
    /// Verify public artifacts, assemble a bundle, and publish without overwrite.
    Assemble(AssembleArgs),
    /// Verify an existing bundle against an explicit offline-root trust document.
    Verify(VerifyArgs),
}

#[derive(Args)]
struct KeygenArgs {
    /// New raw 32-byte seed file. Created with mode 0600 and never overwritten.
    #[arg(long)]
    seed_out: PathBuf,
    /// New public JSON identity file. Published atomically and never overwritten.
    #[arg(long)]
    identity_out: PathBuf,
    /// Optional public 16-byte kid as 32 lower-case hex characters.
    #[arg(long)]
    kid: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ReleaseMode {
    /// One-time client enrollment; no predecessor is permitted.
    Enrollment,
    /// Immediate update of an explicit previously accepted bundle.
    Successor,
}

#[derive(Args)]
struct TransitionArgs {
    /// Explicit release mode. There is no inferred or ambient predecessor.
    #[arg(long, value_enum)]
    mode: ReleaseMode,
    /// Currently live, previously accepted bundle; required only for successor.
    #[arg(long)]
    previous_bundle: Option<PathBuf>,
}

impl TransitionArgs {
    fn predecessor(&self) -> Result<Option<&Path>> {
        match (self.mode, self.previous_bundle.as_deref()) {
            (ReleaseMode::Enrollment, None) => Ok(None),
            (ReleaseMode::Enrollment, Some(_)) => {
                anyhow::bail!("enrollment mode forbids --previous-bundle")
            }
            (ReleaseMode::Successor, Some(path)) => Ok(Some(path)),
            (ReleaseMode::Successor, None) => {
                anyhow::bail!("successor mode requires --previous-bundle")
            }
        }
    }
}

#[derive(Args)]
struct SignKeysetArgs {
    #[command(flatten)]
    transition: TransitionArgs,
    /// Raw 32-byte offline-root seed file; the path is opened securely.
    #[arg(long)]
    root_seed: PathBuf,
    /// Public offline-root identity JSON distributed as the trust anchor.
    #[arg(long)]
    root_identity: PathBuf,
    /// Strict keyset specification JSON.
    #[arg(long)]
    spec: PathBuf,
    /// New root-signed COSE keyset artifact; never overwritten.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct SignPolicyArgs {
    #[command(flatten)]
    transition: TransitionArgs,
    /// Raw 32-byte online-policy seed file; the path is opened securely.
    #[arg(long)]
    online_seed: PathBuf,
    /// Public identity for the online signer.
    #[arg(long)]
    online_identity: PathBuf,
    /// Public offline-root identity used to authenticate the keyset.
    #[arg(long)]
    root_identity: PathBuf,
    /// Root-signed COSE keyset authorizing the online signer.
    #[arg(long)]
    keyset: PathBuf,
    /// Strict endpoint-policy specification JSON.
    #[arg(long)]
    spec: PathBuf,
    /// New online-signed COSE endpoint-policy artifact; never overwritten.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct AssembleArgs {
    #[command(flatten)]
    transition: TransitionArgs,
    /// Public offline-root identity used as the explicit trust anchor.
    #[arg(long)]
    root_identity: PathBuf,
    /// Root-signed COSE keyset artifact.
    #[arg(long)]
    keyset: PathBuf,
    /// Online-signed COSE endpoint-policy artifact.
    #[arg(long)]
    policy: PathBuf,
    /// New verified canonical bundle; never overwritten.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct VerifyArgs {
    /// Public offline-root identity used as the explicit trust anchor.
    #[arg(long)]
    root_identity: PathBuf,
    /// Canonical signed-policy bundle to verify at the current system time.
    #[arg(long)]
    bundle: PathBuf,
}

fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(bytes)?;
    stdout.flush()?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::RootKeygen(args) => {
            generate_identity(
                IdentityKind::OfflineRoot,
                args.kid.as_deref(),
                &args.seed_out,
                &args.identity_out,
            )?;
        }
        Command::OnlineKeygen(args) => {
            generate_identity(
                IdentityKind::OnlinePolicy,
                args.kid.as_deref(),
                &args.seed_out,
                &args.identity_out,
            )?;
        }
        Command::SignKeyset(args) => {
            let previous = args.transition.predecessor()?;
            sign_keyset(
                &args.root_seed,
                &args.root_identity,
                &args.spec,
                &args.out,
                previous,
            )?;
        }
        Command::SignPolicy(args) => {
            let previous = args.transition.predecessor()?;
            sign_policy(
                &args.online_seed,
                &args.online_identity,
                &args.root_identity,
                &args.keyset,
                &args.spec,
                &args.out,
                previous,
            )?;
        }
        Command::Assemble(args) => {
            let previous = args.transition.predecessor()?;
            let summary = assemble_bundle(
                &args.root_identity,
                &args.keyset,
                &args.policy,
                &args.out,
                previous,
            )?;
            write_stdout(&summary.to_pretty_json()?)?;
        }
        Command::Verify(args) => {
            let summary = verify_bundle_file(&args.root_identity, &args.bundle)?;
            write_stdout(&summary.to_pretty_json()?)?;
        }
    }
    Ok(())
}
