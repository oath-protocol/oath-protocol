use anyhow::Result;
use std::path::Path;

pub fn run(oath_dir: &Path) -> Result<()> {
    let keypair = super::load_keypair(oath_dir)?;

    println!("Oath Keypair");
    println!();
    println!("  Fingerprint: {}", keypair.fingerprint());
    println!("  Public key:  {}", keypair.public_key_b64());
    println!("  Key file:    {}", crate::store_path::private_key_path(oath_dir).display());

    Ok(())
}
