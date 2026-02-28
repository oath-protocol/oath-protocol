use anyhow::{Context, Result};
use clap::Args;
use oathkit_core::KeyPair;
use std::path::Path;

#[derive(Args)]
pub struct InitArgs {
    /// Overwrite an existing keypair (warning: old attestations remain valid under the old key)
    #[arg(long)]
    force: bool,
}

pub fn run(args: InitArgs, oath_dir: &Path) -> Result<()> {
    let key_path = crate::store_path::private_key_path(oath_dir);

    if key_path.exists() && !args.force {
        anyhow::bail!(
            "keypair already exists at {}\nUse --force to overwrite. Old attestations remain valid under the old key.",
            key_path.display()
        );
    }

    let keypair = KeyPair::generate();
    let fingerprint = keypair.fingerprint();
    let public_key_b64 = keypair.public_key_b64();
    let hex_seed = keypair.to_hex_seed();

    // Store private key seed as hex
    // NOTE v0.1: stored as plain hex. Future versions will encrypt with system keychain.
    std::fs::write(&key_path, &hex_seed)
        .with_context(|| format!("failed to write key file: {}", key_path.display()))?;

    // Set restrictive permissions on Unix (600 = owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&key_path, perms)
            .with_context(|| "failed to set key file permissions")?;
    }

    // Store public key
    let pub_path = crate::store_path::public_key_path(oath_dir);
    std::fs::write(&pub_path, &public_key_b64)?;

    println!("Oath keypair initialized.");
    println!();
    println!("  Directory:   {}", oath_dir.display());
    println!("  Fingerprint: {}", fingerprint);
    println!("  Public key:  {}", public_key_b64);
    println!();
    println!("Private key stored at: {}", key_path.display());
    println!("Keep this file safe. Loss means you cannot sign new attestations.");
    println!("Old attestations remain verifiable — they carry their own public key.");

    Ok(())
}
