use anyhow::Result;
use clap::Args;
use oathkit_core::VerifyReason;
use std::path::Path;

#[derive(Args)]
pub struct VerifyArgs {
    /// The action class to verify (format: namespace:action:scope)
    #[arg(long, short)]
    action: String,

    /// Output as JSON instead of human-readable
    #[arg(long)]
    json: bool,
}

pub fn run(args: VerifyArgs, oath_dir: &Path) -> Result<()> {
    let store = super::load_store(oath_dir)?;

    let result = store
        .verify(&args.action)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        // Exit with code 1 if not verified — useful for scripting
        if !result.verified {
            std::process::exit(1);
        }
        return Ok(());
    }

    match result.reason {
        VerifyReason::Attested => {
            println!("✓ ATTESTED");
            println!();
            println!("  Action:  {}", args.action);
            if let Some(id) = &result.attestation_id {
                // Try to load context
                if let Ok(Some(ctx)) = super::load_context(oath_dir, id) {
                    println!("  Context: {}", ctx);
                }
                println!("  ID:      {}", id);
            }
            println!("  At:      {}", format_timestamp(result.checked_at_ms));
        }
        VerifyReason::NoAttestation => {
            eprintln!("✗ NO PROOF");
            eprintln!();
            eprintln!("  Action:  {}", args.action);
            eprintln!("  Reason:  no attestation found for this action class");
            eprintln!();
            eprintln!("  Sign an attestation with:");
            eprintln!(
                "    oath attest --action \"{}\" --context \"<reason>\"",
                args.action
            );
            std::process::exit(1);
        }
        VerifyReason::Expired => {
            eprintln!("✗ EXPIRED");
            eprintln!();
            eprintln!("  Action:  {}", args.action);
            eprintln!("  Reason:  attestation found but has passed its expiry time");
            if let Some(id) = &result.attestation_id {
                eprintln!("  ID:      {}", id);
            }
            std::process::exit(1);
        }
        VerifyReason::Revoked => {
            eprintln!("✗ REVOKED");
            eprintln!();
            eprintln!("  Action:  {}", args.action);
            eprintln!("  Reason:  attestation was explicitly revoked");
            if let Some(id) = &result.attestation_id {
                eprintln!("  ID:      {}", id);
            }
            std::process::exit(1);
        }
        VerifyReason::InvalidSignature => {
            eprintln!("✗ INVALID SIGNATURE");
            eprintln!();
            eprintln!("  Action:  {}", args.action);
            eprintln!("  Reason:  attestation found but signature verification failed");
            eprintln!("  This may indicate tampering with the local store.");
            std::process::exit(1);
        }
        VerifyReason::InvalidActionClass => {
            eprintln!("✗ INVALID ACTION CLASS");
            eprintln!();
            eprintln!("  '{}' is not a valid action class.", args.action);
            eprintln!("  Format: namespace:action:scope (all lowercase)");
            eprintln!("  Example: database:delete_records:project_alpha");
            std::process::exit(1);
        }
    }

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
