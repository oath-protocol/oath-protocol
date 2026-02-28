use thiserror::Error;

/// All errors that can occur in OathKit operations.
#[derive(Error, Debug)]
pub enum OathError {
    // --- Action class errors ---
    #[error("invalid action class '{0}': must be in format 'namespace:action:scope' with lowercase alphanumeric characters")]
    InvalidActionClass(String),

    // --- Signing errors ---
    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("no keypair available: run `oath init` to generate a keypair")]
    NoKeypair,

    #[error("invalid expiry: expires_at_ms ({expires}) must be greater than timestamp_ms ({timestamp})")]
    InvalidExpiry { expires: u64, timestamp: u64 },

    // --- Verification errors ---
    #[error("signature verification failed for attestation {id}")]
    SignatureVerificationFailed { id: String },

    #[error("unsupported protocol version '{0}'")]
    UnsupportedProtocolVersion(String),

    // --- Store errors ---
    #[error("attestation with id {0} already exists in store")]
    DuplicateId(String),

    #[error("attestation signature rejected: {0}")]
    SignatureRejected(String),

    // --- Key management errors ---
    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("key not found at path: {0}")]
    KeyNotFound(String),

    #[error("key decryption failed")]
    KeyDecryptionFailed,

    #[error("key storage failed: {0}")]
    KeyStorageFailed(String),

    // --- IO errors ---
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // --- Serialization errors ---
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    // --- Revocation errors ---
    #[error("revocation must be signed by the same key as the original attestation")]
    RevocationKeyMismatch,

    #[error("attestation {0} not found — cannot revoke")]
    RevocationTargetNotFound(String),
}
