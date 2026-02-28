use anyhow::Result;
use clap::Args;
use std::path::Path;

#[derive(Args)]
pub struct HistoryArgs {
    /// Filter by action class (shows only matching attestations)
    #[arg(long, short)]
    action: Option<String>,

    /// Show only the last N entries
    #[arg(long, short, default_value = "20")]
    limit: usize,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

pub fn run(args: HistoryArgs, oath_dir: &Path) -> Result<()> {
    let store = super::load_store(oath_dir)?;

    let history = store.history();

    let filtered: Vec<_> = history
        .into_iter()
        .filter(|a| {
            args.action
                .as_deref()
                .map(|ac| a.action_class.as_str() == ac)
                .unwrap_or(true)
        })
        .take(args.limit)
        .collect();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&filtered)?);
        return Ok(());
    }

    if filtered.is_empty() {
        println!("No attestations found.");
        return Ok(());
    }

    println!(
        "ATTESTATION HISTORY (showing {} of {} total)",
        filtered.len(),
        store.size()
    );
    println!("{}", "─".repeat(72));

    for attestation in &filtered {
        let id_short = &attestation.id.to_string()[..8];
        let timestamp = format_timestamp(attestation.timestamp_ms);
        let is_revocation = attestation.action_class.is_revocation();

        let prefix = if is_revocation { "↩ REVOKE" } else { "✓ ATTEST" };

        print!("{}  {}  {}", prefix, timestamp, attestation.action_class);

        if let Some(exp) = attestation.expires_at_ms {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            if exp < now {
                print!("  [EXPIRED]");
            } else {
                print!("  [expires {}]", format_timestamp(exp));
            }
        }

        println!();
        println!("         id:{}", attestation.id);

        // Try to show context
        if let Ok(Some(ctx)) = super::load_context(oath_dir, &attestation.id.to_string()) {
            println!("         \"{}\"|", ctx);
        }

        let _ = id_short; // suppress unused warning
        println!();
    }

    println!("{}", "─".repeat(72));
    println!(
        "Integrity hash: {}",
        hex::encode(store.integrity_hash())
    );

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
