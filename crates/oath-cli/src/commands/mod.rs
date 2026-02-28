pub mod attest;
pub mod history;
pub mod init;
pub mod verify;
pub mod whoami;

use anyhow::{Context, Result};
use oathkit_core::{AttestationStore, KeyPair};
use std::path::Path;

/// Load the keypair from the oath directory.
pub(crate) fn load_keypair(oath_dir: &Path) -> Result<KeyPair> {
    let key_path = crate::store_path::private_key_path(oath_dir);
    if !key_path.exists() {
        anyhow::bail!(
            "no keypair found at {}\nRun `oath init` to generate one.",
            key_path.display()
        );
    }
    let hex_seed = std::fs::read_to_string(&key_path)
        .with_context(|| format!("failed to read key file: {}", key_path.display()))?;
    KeyPair::from_hex_seed(hex_seed.trim())
        .map_err(|e| anyhow::anyhow!("failed to load keypair: {}", e))
}

/// Load the attestation store from the oath directory.
pub(crate) fn load_store(oath_dir: &Path) -> Result<AttestationStore> {
    let store_path = crate::store_path::store_path(oath_dir);
    let mut store = AttestationStore::new();

    if !store_path.exists() {
        return Ok(store);
    }

    let content = std::fs::read_to_string(&store_path)
        .with_context(|| format!("failed to read store: {}", store_path.display()))?;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let attestation: oathkit_core::Attestation = serde_json::from_str(line)
            .with_context(|| format!("failed to parse attestation on line {}", line_num + 1))?;
        store
            .append(attestation)
            .with_context(|| format!("failed to load attestation on line {}", line_num + 1))?;
    }

    Ok(store)
}

/// Append an attestation to the store file (JSONL format).
pub(crate) fn append_to_store(oath_dir: &Path, attestation: &oathkit_core::Attestation) -> Result<()> {
    use std::io::Write;
    let store_path = crate::store_path::store_path(oath_dir);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&store_path)
        .with_context(|| format!("failed to open store: {}", store_path.display()))?;

    let line = serde_json::to_string(attestation)?;
    writeln!(file, "{}", line)?;
    Ok(())
}

/// Save the context string for an attestation.
pub(crate) fn save_context(oath_dir: &Path, id: &str, context: &str) -> Result<()> {
    let ctx_path = crate::store_path::context_store_path(oath_dir);
    let mut contexts: std::collections::HashMap<String, String> = if ctx_path.exists() {
        let content = std::fs::read_to_string(&ctx_path)?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };

    contexts.insert(id.to_string(), context.to_string());
    let content = serde_json::to_string_pretty(&contexts)?;
    std::fs::write(&ctx_path, content)?;
    Ok(())
}

/// Load a context string by attestation ID.
pub(crate) fn load_context(oath_dir: &Path, id: &str) -> Result<Option<String>> {
    let ctx_path = crate::store_path::context_store_path(oath_dir);
    if !ctx_path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&ctx_path)?;
    let contexts: std::collections::HashMap<String, String> =
        serde_json::from_str(&content).unwrap_or_default();
    Ok(contexts.get(id).cloned())
}
