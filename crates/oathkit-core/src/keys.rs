use base64ct::{Base64Url, Encoding};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::error::OathError;

/// An Ed25519 keypair for signing attestations.
///
/// ed25519-dalek's `SigningKey` implements `Zeroize` and zeroes the key
/// material when dropped, satisfying the spec requirement in Section 12.2.
pub struct KeyPair {
    signing_key: SigningKey,
    /// The Ed25519 public key.
    pub verifying_key: VerifyingKey,
}

impl KeyPair {
    /// Generate a new Ed25519 keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        KeyPair {
            signing_key,
            verifying_key,
        }
    }

    /// Reconstruct a keypair from raw seed bytes (32 bytes).
    ///
    /// Used for testing with deterministic seeds and for loading from storage.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, OathError> {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        Ok(KeyPair {
            signing_key,
            verifying_key,
        })
    }

    /// Load a keypair from a hex-encoded seed string (64 hex chars = 32 bytes).
    pub fn from_hex_seed(hex_seed: &str) -> Result<Self, OathError> {
        let bytes = hex::decode(hex_seed)
            .map_err(|e: hex::FromHexError| OathError::KeyGenerationFailed(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(OathError::KeyGenerationFailed(
                "seed must be exactly 32 bytes".to_string(),
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Self::from_seed(&seed)
    }

    /// Sign a message and return the 64-byte signature.
    ///
    /// The private key material is held in `SigningKey` which zeroes itself
    /// on drop per the ed25519-dalek Zeroize implementation.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        let sig = self.signing_key.sign(message);
        sig.to_bytes()
    }

    /// The public key encoded as base64url without padding.
    pub fn public_key_b64(&self) -> String {
        Base64Url::encode_string(self.verifying_key.as_bytes())
    }

    /// The key fingerprint: first 16 bytes of SHA-256(public_key_bytes), hex-encoded.
    ///
    /// Produces a 32-character lowercase hex string for human-readable identification.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.verifying_key.as_bytes());
        let hash = hasher.finalize();
        hex::encode(&hash[..16])
    }

    /// Export the private key seed as a hex string for storage.
    ///
    /// The seed is 32 bytes (256 bits). Store this securely.
    pub fn to_hex_seed(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    /// Verify a signature against this keypair's public key.
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8; 64]) -> bool {
        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(signature_bytes);
        self.verifying_key.verify(message, &sig).is_ok()
    }
}

/// Verify an Ed25519 signature given a raw public key and signature (both base64url encoded).
///
/// This is the free-standing verification function used by the store
/// when verifying attestations from external sources.
pub fn verify_signature(
    public_key_b64: &str,
    message: &[u8],
    signature_b64: &str,
) -> Result<bool, OathError> {
    let pk_bytes = Base64Url::decode_vec(public_key_b64)
        .map_err(|_| OathError::SignatureVerificationFailed {
            id: "unknown".to_string(),
        })?;

    if pk_bytes.len() != 32 {
        return Ok(false);
    }

    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&pk_bytes);

    let verifying_key = VerifyingKey::from_bytes(&pk_array)
        .map_err(|_| OathError::SignatureVerificationFailed {
            id: "unknown".to_string(),
        })?;

    let sig_bytes = Base64Url::decode_vec(signature_b64)
        .map_err(|_| OathError::SignatureVerificationFailed {
            id: "unknown".to_string(),
        })?;

    if sig_bytes.len() != 64 {
        return Ok(false);
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);

    use ed25519_dalek::Verifier;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
    Ok(verifying_key.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        assert!(!kp.public_key_b64().is_empty());
        assert_eq!(kp.fingerprint().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = KeyPair::generate();
        let message = b"test message for signing";
        let sig = kp.sign(message);
        assert!(kp.verify(message, &sig));
    }

    #[test]
    fn test_verify_wrong_message() {
        let kp = KeyPair::generate();
        let sig = kp.sign(b"original message");
        assert!(!kp.verify(b"tampered message", &sig));
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let sig = kp1.sign(b"message");
        assert!(!kp2.verify(b"message", &sig));
    }

    #[test]
    fn test_deterministic_from_seed() {
        let seed = [1u8; 32];
        let kp1 = KeyPair::from_seed(&seed).unwrap();
        let kp2 = KeyPair::from_seed(&seed).unwrap();
        assert_eq!(kp1.public_key_b64(), kp2.public_key_b64());
        assert_eq!(kp1.fingerprint(), kp2.fingerprint());
    }

    #[test]
    fn test_verify_signature_standalone() {
        let kp = KeyPair::generate();
        let message = b"standalone verify test";
        let sig_bytes = kp.sign(message);
        let sig_b64 = Base64Url::encode_string(&sig_bytes);
        let pk_b64 = kp.public_key_b64();

        assert!(verify_signature(&pk_b64, message, &sig_b64).unwrap());
    }

    #[test]
    fn test_verify_signature_tampered() {
        let kp = KeyPair::generate();
        let message = b"standalone verify test";
        let mut sig_bytes = kp.sign(message);
        sig_bytes[63] ^= 0x01; // flip one bit
        let sig_b64 = Base64Url::encode_string(&sig_bytes);
        let pk_b64 = kp.public_key_b64();

        assert!(!verify_signature(&pk_b64, message, &sig_b64).unwrap());
    }
}
