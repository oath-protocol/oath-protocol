use anyhow::Result;
use clap::Args;
use std::path::Path;

#[derive(Args)]
pub struct AttestArgs {
    /// The action class to attest (format: namespace:action:scope)
    #[arg(long, short)]
    action: String,

    /// Human-readable context / reason for this attestation
    #[arg(long, short)]
    context: String,

    /// Optional expiry duration in seconds from now
    #[arg(long)]
    expires_in: Option<u64>,

    /// Output as JSON instead of human-readable
    #[arg(long)]
    json: bool,
}

pub fn run(args: AttestArgs, oath_dir: &Path) -> Result<()> {
    let keypair = super::load_keypair(oath_dir)?;
    let mut store = super::load_store(oath_dir)?;

    let expires_in_ms = args.expires_in.map(|s| s * 1000);

    let attestation = store
        .attest(&keypair, &args.action, &args.context, expires_in_ms)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Persist to store file
    super::append_to_store(oath_dir, &attestation)?;
    super::save_context(oath_dir, &attestation.id.to_string(), &args.context)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&attestation)?);
        return Ok(());
    }

    println!("✓ ATTESTED");
    println!();
    println!("  Action:      {}", args.action);
    println!("  Context:     {}", args.context);
    println!("  ID:          {}", attestation.id);
    println!(
        "  Proof:       {}",
        &attestation.context_hash[..16]
    );
    println!(
        "  Signed:      {}",
        format_timestamp(attestation.timestamp_ms)
    );
    if let Some(exp) = attestation.expires_at_ms {
        println!("  Expires:     {}", format_timestamp(exp));
    }
    println!("  Key:         {}", keypair.fingerprint());

    Ok(())
}

fn format_timestamp(ms: u64) -> String {
    use chrono::{DateTime, Utc};
    let secs = (ms / 1000) as i64;
    let nsecs = ((ms % 1000) * 1_000_000) as u32;
    match DateTime::from_timestamp(secs, nsecs) {
        Some(dt) => {
            let dt: DateTime<Utc> = dt;
            dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
        }
        None => ms.to_string(),
    }
}
