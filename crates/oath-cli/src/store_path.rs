use anyhow::{Context, Result};
use std::path::PathBuf;

/// Resolve the Oath data directory.
///
/// Priority: CLI --dir flag > OATH_DIR env var > ~/.oath/
pub fn resolve_oath_dir(override_dir: Option<PathBuf>) -> Result<PathBuf> {
    let dir = match override_dir {
        Some(d) => d,
        None => {
            let home = dirs_next()
                .context("could not determine home directory; set OATH_DIR to override")?;
            home.join(".oath")
        }
    };

    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create oath directory: {}", dir.display()))?;

    Ok(dir)
}

fn dirs_next() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            // Fallback for Windows
            std::env::var("USERPROFILE").ok().map(PathBuf::from)
        })
}

/// Path to the private key file within the oath directory.
pub fn private_key_path(oath_dir: &std::path::Path) -> PathBuf {
    oath_dir.join("private_key.hex")
}

/// Path to the public key file within the oath directory.
pub fn public_key_path(oath_dir: &std::path::Path) -> PathBuf {
    oath_dir.join("public_key.b64")
}

/// Path to the attestation store file within the oath directory.
pub fn store_path(oath_dir: &std::path::Path) -> PathBuf {
    oath_dir.join("store.jsonl")
}

/// Path to the context store file within the oath directory.
pub fn context_store_path(oath_dir: &std::path::Path) -> PathBuf {
    oath_dir.join("contexts.json")
}
