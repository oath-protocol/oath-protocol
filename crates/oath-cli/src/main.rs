mod commands;
mod store_path;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// Oath — cryptographically verifiable human intent attestation.
///
/// Sign your intent before an AI agent acts. Prove what you authorized — after the fact.
#[derive(Parser)]
#[command(name = "oath", version, about)]
#[command(propagate_version = true)]
struct Cli {
    /// Override the Oath data directory (default: ~/.oath/)
    #[arg(long, env = "OATH_DIR", global = true)]
    dir: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new keypair in the Oath data directory.
    Init(commands::init::InitArgs),

    /// Sign a human intent attestation for an action class.
    ///
    /// Example: oath attest --action "database:delete_records:project_alpha" --context "cleanup approved"
    Attest(commands::attest::AttestArgs),

    /// Verify whether a valid attestation exists for an action class.
    ///
    /// Example: oath verify --action "database:delete_records:project_alpha"
    Verify(commands::verify::VerifyArgs),

    /// Show the full attestation history from the local store.
    History(commands::history::HistoryArgs),

    /// Show the local keypair fingerprint.
    Whoami,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let oath_dir = store_path::resolve_oath_dir(cli.dir)?;

    match cli.command {
        Commands::Init(args) => commands::init::run(args, &oath_dir),
        Commands::Attest(args) => commands::attest::run(args, &oath_dir),
        Commands::Verify(args) => commands::verify::run(args, &oath_dir),
        Commands::History(args) => commands::history::run(args, &oath_dir),
        Commands::Whoami => commands::whoami::run(&oath_dir),
    }
}
