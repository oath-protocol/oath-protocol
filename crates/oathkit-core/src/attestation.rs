use base64ct::{Base64Url, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::OathError;

/// The Oath Protocol version string embedded in every attestation.
pub const PROTOCOL_VERSION: &str = "oath/1.0";

/// A structured three-part action class identifier.
///
/// Format: `namespace:action:scope`
///
/// Example: `database:delete_records:project_alpha`
///
/// See Oath Protocol Specification Section 5 for the full spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActionClass(String);

impl ActionClass {
    /// Parse and validate an action class string.
    ///
    /// Returns `Err(OathError::InvalidActionClass)` if the string does not
    /// conform to the `namespace:action:scope` format defined in the spec.
    pub fn parse(s: &str) -> Result<Self, OathError> {
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() != 3 {
            return Err(OathError::InvalidActionClass(s.to_string()));
        }

        let namespace = parts[0];
        let action = parts[1];
        let scope = parts[2];

        // Validate namespace and action: [a-z0-9_]+
        if namespace.is_empty() || !namespace.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(OathError::InvalidActionClass(s.to_string()));
        }

        if action.is_empty() || !action.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(OathError::InvalidActionClass(s.to_string()));
        }

        // Validate scope: [a-z0-9_\-\.]+
        if scope.is_empty() || !scope.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' || c == '.') {
            return Err(OathError::InvalidActionClass(s.to_string()));
        }

        Ok(ActionClass(s.to_string()))
    }

    /// The namespace component (first part).
    pub fn namespace(&self) -> &str {
        self.0.split(':').next().unwrap_or("")
    }

    /// The action component (second part).
    pub fn action(&self) -> &str {
        self.0.split(':').nth(1).unwrap_or("")
    }

    /// The scope component (third part).
    pub fn scope(&self) -> &str {
        self.0.split(':').nth(2).unwrap_or("")
    }

    /// The full action class string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True if this is a revocation action class.
    pub fn is_revocation(&self) -> bool {
        self.namespace() == "oath" && self.action() == "revoke"
    }

    /// Extract the target ID from a revocation action class.
    /// Returns None if this is not a revocation.
    pub fn revocation_target(&self) -> Option<&str> {
        if self.is_revocation() {
            Some(self.scope())
        } else {
            None
        }
    }
}

impl std::fmt::Display for ActionClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A cryptographically signed human intent attestation.
///
/// This is the atomic unit of the Oath Protocol. See `spec/OATH_SPEC.md`
/// Section 4 for the full specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// UUID v4. Globally unique identifier, generated at signing time.
    pub id: Uuid,

    /// Protocol version. Always `"oath/1.0"` for this implementation.
    pub protocol_version: String,

    /// Three-part action class: `namespace:action:scope`.
    pub action_class: ActionClass,

    /// SHA-256 hash of the human-readable context string, base64url no padding.
    pub context_hash: String,

    /// Unix timestamp in milliseconds at signing time.
    pub timestamp_ms: u64,

    /// Ed25519 public key of the attestor, base64url no padding.
    pub public_key: String,

    /// Ed25519 signature over canonical serialization, base64url no padding.
    pub signature: String,

    /// Optional expiry timestamp (Unix ms). Verification returns EXPIRED after this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,

    /// Optional nonce for uniqueness beyond UUID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl Attestation {
    /// Compute the SHA-256 hash of a context string, encoded as base64url without padding.
    pub fn hash_context(context: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(context.as_bytes());
        let hash = hasher.finalize();
        Base64Url::encode_string(&hash)
    }

    /// Produce the canonical serialization for signing.
    ///
    /// This MUST match the procedure in Section 6 of the spec exactly.
    /// Fields are in a fixed order. Optional absent fields are omitted.
    /// No whitespace. Compact JSON.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Build the canonical JSON manually to guarantee field ordering.
        // We MUST NOT use serde_json object serialization which may reorder fields.
        let mut parts = Vec::new();

        parts.push(format!(r#""id":"{}""#, self.id));
        parts.push(format!(r#""protocol_version":"{}""#, self.protocol_version));
        parts.push(format!(r#""action_class":"{}""#, self.action_class.as_str()));
        parts.push(format!(r#""context_hash":"{}""#, self.context_hash));
        parts.push(format!(r#""timestamp_ms":{}"#, self.timestamp_ms));
        parts.push(format!(r#""public_key":"{}""#, self.public_key));

        // Optional fields, in spec order
        if let Some(expires) = self.expires_at_ms {
            parts.push(format!(r#""expires_at_ms":{}"#, expires));
        }
        if let Some(ref nonce) = self.nonce {
            parts.push(format!(r#""nonce":"{}""#, nonce));
        }

        let inner = parts.join(",");
        format!("{{{}}}", inner).into_bytes()
    }

    /// Check whether this attestation has expired at the given time (Unix ms).
    pub fn is_expired(&self, now_ms: u64) -> bool {
        match self.expires_at_ms {
            Some(exp) => now_ms > exp,
            None => false,
        }
    }

    /// Compute the store integrity contribution of this attestation.
    /// This is the raw UUID bytes used in the integrity hash computation.
    pub fn id_bytes(&self) -> [u8; 16] {
        *self.id.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_class_valid() {
        let ac = ActionClass::parse("database:delete_records:project_alpha").unwrap();
        assert_eq!(ac.namespace(), "database");
        assert_eq!(ac.action(), "delete_records");
        assert_eq!(ac.scope(), "project_alpha");
    }

    #[test]
    fn test_action_class_valid_with_dash_dot_in_scope() {
        let ac = ActionClass::parse("email:send:team.status-updates").unwrap();
        assert_eq!(ac.scope(), "team.status-updates");
    }

    #[test]
    fn test_action_class_invalid_uppercase() {
        assert!(ActionClass::parse("Database:delete_records:project_alpha").is_err());
    }

    #[test]
    fn test_action_class_invalid_missing_scope() {
        assert!(ActionClass::parse("database:delete_records").is_err());
    }

    #[test]
    fn test_action_class_invalid_empty_action() {
        assert!(ActionClass::parse("database::project_alpha").is_err());
    }

    #[test]
    fn test_action_class_invalid_wildcard() {
        assert!(ActionClass::parse("*:*:*").is_err());
    }

    #[test]
    fn test_action_class_revocation() {
        let ac = ActionClass::parse("oath:revoke:7f3d9a2e-1b4c-4e8f-a5d6-2c9e0f1a3b7d").unwrap();
        assert!(ac.is_revocation());
        assert_eq!(ac.revocation_target(), Some("7f3d9a2e-1b4c-4e8f-a5d6-2c9e0f1a3b7d"));
    }

    #[test]
    fn test_context_hash_is_deterministic() {
        let h1 = Attestation::hash_context("cleanup approved");
        let h2 = Attestation::hash_context("cleanup approved");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_context_hash_differs_for_different_context() {
        let h1 = Attestation::hash_context("cleanup approved");
        let h2 = Attestation::hash_context("not approved");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_canonical_bytes_field_order() {
        // Build a minimal attestation and check the canonical JSON field order
        let attestation = Attestation {
            id: Uuid::parse_str("7f3d9a2e-1b4c-4e8f-a5d6-2c9e0f1a3b7d").unwrap(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            action_class: ActionClass::parse("database:delete_records:project_alpha").unwrap(),
            context_hash: "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg".to_string(),
            timestamp_ms: 1740384723000,
            public_key: "MCowBQYDK2VwAyEA2a9LjxjIL1J7Z8Kqm3PvNt5XwYhR6mD4cE0sF9pQ3Uk".to_string(),
            signature: String::new(), // not included in canonical bytes
            expires_at_ms: Some(1740388323000),
            nonce: None,
        };

        let canonical = String::from_utf8(attestation.canonical_bytes()).unwrap();
        let expected = r#"{"id":"7f3d9a2e-1b4c-4e8f-a5d6-2c9e0f1a3b7d","protocol_version":"oath/1.0","action_class":"database:delete_records:project_alpha","context_hash":"n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg","timestamp_ms":1740384723000,"public_key":"MCowBQYDK2VwAyEA2a9LjxjIL1J7Z8Kqm3PvNt5XwYhR6mD4cE0sF9pQ3Uk","expires_at_ms":1740388323000}"#;
        assert_eq!(canonical, expected);
    }

    #[test]
    fn test_canonical_bytes_omits_absent_optional_fields() {
        let attestation = Attestation {
            id: Uuid::parse_str("7f3d9a2e-1b4c-4e8f-a5d6-2c9e0f1a3b7d").unwrap(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            action_class: ActionClass::parse("database:delete_records:project_alpha").unwrap(),
            context_hash: "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg".to_string(),
            timestamp_ms: 1740384723000,
            public_key: "MCowBQYDK2VwAyEA2a9LjxjIL1J7Z8Kqm3PvNt5XwYhR6mD4cE0sF9pQ3Uk".to_string(),
            signature: String::new(),
            expires_at_ms: None,
            nonce: None,
        };

        let canonical = String::from_utf8(attestation.canonical_bytes()).unwrap();
        assert!(!canonical.contains("expires_at_ms"));
        assert!(!canonical.contains("nonce"));
    }
}
