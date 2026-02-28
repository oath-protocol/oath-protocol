use base64ct::{Base64Url, Encoding};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::attestation::{ActionClass, Attestation, PROTOCOL_VERSION};
use crate::error::OathError;
use crate::keys::{verify_signature, KeyPair};
use crate::verify::{VerifyReason, VerifyResult};

/// Current Unix timestamp in milliseconds.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_millis() as u64
}

/// A G-Set CRDT attestation store.
///
/// The store is grow-only: attestations are only ever added, never removed.
/// This maps exactly to the G-Set CRDT model. Revocations are added as new
/// attestations, not as deletions.
///
/// See Oath Protocol Specification Section 9 for the full spec.
pub struct AttestationStore {
    /// All attestations indexed by ID (UUID string).
    attestations: HashMap<String, Attestation>,

    /// Insertion order for history and integrity hash computation.
    insertion_order: Vec<String>,

    /// Locally stored context strings, keyed by attestation ID.
    /// These are NOT part of the protocol — application data only.
    contexts: HashMap<String, String>,
}

impl AttestationStore {
    /// Create a new empty attestation store.
    pub fn new() -> Self {
        AttestationStore {
            attestations: HashMap::new(),
            insertion_order: Vec::new(),
            contexts: HashMap::new(),
        }
    }

    /// Sign and append a new attestation to the store.
    ///
    /// This is the primary API for human intent attestation.
    ///
    /// # Arguments
    ///
    /// * `keypair` — The Ed25519 keypair to sign with
    /// * `action_class` — The action class string (e.g. `"database:delete_records:project_alpha"`)
    /// * `context` — Human-readable reason for this attestation
    /// * `expires_in_ms` — Optional duration in milliseconds until expiry
    pub fn attest(
        &mut self,
        keypair: &KeyPair,
        action_class: &str,
        context: &str,
        expires_in_ms: Option<u64>,
    ) -> Result<Attestation, OathError> {
        // Validate action class
        let action_class = ActionClass::parse(action_class)?;

        let now = now_ms();
        let id = Uuid::new_v4();

        // Hash the context string
        let context_hash = Attestation::hash_context(context);

        // Compute optional expiry
        let expires_at_ms = expires_in_ms.map(|duration| now + duration);
        if let Some(exp) = expires_at_ms {
            if exp <= now {
                return Err(OathError::InvalidExpiry {
                    expires: exp,
                    timestamp: now,
                });
            }
        }

        // Build the unsigned attestation
        let mut attestation = Attestation {
            id,
            protocol_version: PROTOCOL_VERSION.to_string(),
            action_class,
            context_hash,
            timestamp_ms: now,
            public_key: keypair.public_key_b64(),
            signature: String::new(), // filled in below
            expires_at_ms,
            nonce: None,
        };

        // Produce canonical bytes and sign
        let canonical = attestation.canonical_bytes();
        let sig_bytes = keypair.sign(&canonical);
        attestation.signature = Base64Url::encode_string(&sig_bytes);

        // Store the context string (application data, not protocol data)
        self.contexts.insert(id.to_string(), context.to_string());

        // Append to store
        self.append_validated(attestation.clone())?;

        Ok(attestation)
    }

    /// Append an already-signed attestation to the store.
    ///
    /// The signature MUST be valid. Returns an error if verification fails.
    /// This is used when receiving attestations from other nodes during sync.
    pub fn append(&mut self, attestation: Attestation) -> Result<(), OathError> {
        // Validate protocol version
        if attestation.protocol_version != PROTOCOL_VERSION {
            return Err(OathError::UnsupportedProtocolVersion(
                attestation.protocol_version.clone(),
            ));
        }

        // Validate expiry consistency
        if let Some(exp) = attestation.expires_at_ms {
            if exp <= attestation.timestamp_ms {
                return Err(OathError::InvalidExpiry {
                    expires: exp,
                    timestamp: attestation.timestamp_ms,
                });
            }
        }

        // Verify signature
        let canonical = attestation.canonical_bytes();
        let valid = verify_signature(
            &attestation.public_key,
            &canonical,
            &attestation.signature,
        )
        .map_err(|_| OathError::SignatureRejected(attestation.id.to_string()))?;

        if !valid {
            return Err(OathError::SignatureRejected(attestation.id.to_string()));
        }

        self.append_validated(attestation)
    }

    /// Append an attestation that has already been validated.
    fn append_validated(&mut self, attestation: Attestation) -> Result<(), OathError> {
        let id = attestation.id.to_string();

        // Check for duplicate IDs (astronomically unlikely with UUID v4)
        if self.attestations.contains_key(&id) {
            return Err(OathError::DuplicateId(id));
        }

        self.insertion_order.push(id.clone());
        self.attestations.insert(id, attestation);

        Ok(())
    }

    /// Retrieve a specific attestation by ID.
    pub fn get(&self, id: &str) -> Option<&Attestation> {
        self.attestations.get(id)
    }

    /// Retrieve the context string for an attestation, if stored locally.
    pub fn get_context(&self, id: &str) -> Option<&str> {
        self.contexts.get(id).map(String::as_str)
    }

    /// Retrieve all attestations matching a given action class.
    pub fn query(&self, action_class: &str) -> Vec<&Attestation> {
        self.attestations
            .values()
            .filter(|a| a.action_class.as_str() == action_class)
            .collect()
    }

    /// Return all attestations in the store, ordered by timestamp descending.
    pub fn history(&self) -> Vec<&Attestation> {
        let mut all: Vec<&Attestation> = self.attestations.values().collect();
        all.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
        all
    }

    /// Return the number of attestations in the store.
    pub fn size(&self) -> usize {
        self.attestations.len()
    }

    /// Compute the store integrity hash.
    ///
    /// This is SHA-256 of the concatenated IDs in insertion order, as raw bytes.
    /// Used during sync to detect divergence without transmitting full data.
    pub fn integrity_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for id in &self.insertion_order {
            // Parse back to UUID to get raw bytes (16 bytes per UUID)
            if let Ok(uuid) = Uuid::parse_str(id) {
                hasher.update(uuid.as_bytes());
            }
        }
        hasher.finalize().into()
    }

    /// Return all attestation IDs in insertion order.
    pub fn all_ids(&self) -> &[String] {
        &self.insertion_order
    }

    /// Merge a set of attestations from a remote store.
    ///
    /// G-Set merge: the result is the union of both stores.
    /// Each received attestation is individually signature-verified before
    /// being appended. Invalid attestations are silently skipped.
    ///
    /// Returns the number of new attestations added.
    pub fn merge(&mut self, remote_attestations: Vec<Attestation>) -> usize {
        let mut added = 0;
        for attestation in remote_attestations {
            let id = attestation.id.to_string();
            if !self.attestations.contains_key(&id) {
                if self.append(attestation).is_ok() {
                    added += 1;
                }
            }
        }
        added
    }

    /// Revoke an existing attestation.
    ///
    /// Creates and appends a revocation attestation. The revocation MUST be
    /// signed by the same keypair that signed the original.
    pub fn revoke(
        &mut self,
        keypair: &KeyPair,
        target_id: &str,
        reason: &str,
    ) -> Result<Attestation, OathError> {
        // Verify target exists
        let target = self
            .attestations
            .get(target_id)
            .ok_or_else(|| OathError::RevocationTargetNotFound(target_id.to_string()))?;

        // Verify same keypair
        if target.public_key != keypair.public_key_b64() {
            return Err(OathError::RevocationKeyMismatch);
        }

        // Create revocation action class: oath:revoke:<target_id>
        let revocation_action = format!("oath:revoke:{}", target_id);

        self.attest(keypair, &revocation_action, reason, None)
    }

    /// Check if an attestation has been revoked.
    fn is_revoked(&self, attestation_id: &str) -> bool {
        let revocation_action = format!("oath:revoke:{}", attestation_id);
        self.attestations.values().any(|a| {
            a.action_class.as_str() == revocation_action
                && a.public_key
                    == self
                        .attestations
                        .get(attestation_id)
                        .map(|orig| orig.public_key.as_str())
                        .unwrap_or("")
        })
    }

    /// Verify an action class.
    ///
    /// Returns a `VerifyResult` describing whether a valid, non-expired,
    /// non-revoked attestation exists for the given action class.
    ///
    /// See Oath Protocol Specification Section 8.2.
    pub fn verify(&self, action_class: &str) -> Result<VerifyResult, OathError> {
        let now = now_ms();

        // Step 1: Validate action class
        let ac = match ActionClass::parse(action_class) {
            Ok(ac) => ac,
            Err(_) => return Ok(VerifyResult::invalid_action_class(now)),
        };

        // Step 2: Query store
        let mut candidates: Vec<&Attestation> = self
            .attestations
            .values()
            .filter(|a| a.action_class.as_str() == ac.as_str())
            .collect();

        if candidates.is_empty() {
            return Ok(VerifyResult::no_attestation(now));
        }

        // Sort descending by timestamp (check newest first)
        candidates.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));

        // Track the most specific failure reason seen
        let mut best_failure = VerifyReason::NoAttestation;

        // Step 4: Check each candidate
        for attestation in candidates {
            // 4a: Check revocation
            if self.is_revoked(&attestation.id.to_string()) {
                best_failure = VerifyReason::Revoked;
                // Don't return yet — another attestation for same action may be valid
                // (user may have re-attested after revoking)
                // Actually per spec: if revoked, return revoked immediately for this attestation,
                // but continue checking others
                continue;
            }

            // 4b: Check expiry
            if attestation.is_expired(now) {
                if best_failure == VerifyReason::NoAttestation || best_failure == VerifyReason::InvalidSignature {
                    best_failure = VerifyReason::Expired;
                }
                continue;
            }

            // 4c: Verify signature
            let canonical = attestation.canonical_bytes();
            match verify_signature(&attestation.public_key, &canonical, &attestation.signature) {
                Ok(true) => {
                    // Step 4d: Success
                    return Ok(VerifyResult::attested(attestation, now));
                }
                _ => {
                    if best_failure == VerifyReason::NoAttestation {
                        best_failure = VerifyReason::InvalidSignature;
                    }
                    continue;
                }
            }
        }

        // Step 5: Return most specific failure. Priority: REVOKED > EXPIRED > INVALID_SIGNATURE > NO_ATTESTATION
        let result = match best_failure {
            VerifyReason::Revoked => {
                // Find the first revoked attestation for display
                let revoked_att = self.attestations.values()
                    .find(|a| a.action_class.as_str() == ac.as_str() && self.is_revoked(&a.id.to_string()));
                match revoked_att {
                    Some(a) => VerifyResult::revoked(a, now),
                    None => VerifyResult::no_attestation(now),
                }
            }
            VerifyReason::Expired => {
                let exp_att = self.attestations.values()
                    .find(|a| a.action_class.as_str() == ac.as_str());
                match exp_att {
                    Some(a) => VerifyResult::expired(a, now),
                    None => VerifyResult::no_attestation(now),
                }
            }
            VerifyReason::InvalidSignature => {
                let inv_att = self.attestations.values()
                    .find(|a| a.action_class.as_str() == ac.as_str());
                match inv_att {
                    Some(a) => VerifyResult::invalid_signature(a, now),
                    None => VerifyResult::no_attestation(now),
                }
            }
            _ => VerifyResult::no_attestation(now),
        };

        Ok(result)
    }

    /// Verify a specific attestation by ID.
    ///
    /// See Oath Protocol Specification Section 8.3.
    pub fn verify_by_id(&self, id: &str) -> Result<VerifyResult, OathError> {
        let now = now_ms();

        let attestation = match self.attestations.get(id) {
            Some(a) => a,
            None => return Ok(VerifyResult::no_attestation(now)),
        };

        if self.is_revoked(id) {
            return Ok(VerifyResult::revoked(attestation, now));
        }

        if attestation.is_expired(now) {
            return Ok(VerifyResult::expired(attestation, now));
        }

        let canonical = attestation.canonical_bytes();
        match verify_signature(&attestation.public_key, &canonical, &attestation.signature) {
            Ok(true) => Ok(VerifyResult::attested(attestation, now)),
            _ => Ok(VerifyResult::invalid_signature(attestation, now)),
        }
    }
}

impl Default for AttestationStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    fn make_store_with_attestation(action_class: &str) -> (AttestationStore, KeyPair) {
        let keypair = KeyPair::generate();
        let mut store = AttestationStore::new();
        store
            .attest(&keypair, action_class, "test context", None)
            .unwrap();
        (store, keypair)
    }

    #[test]
    fn test_attest_and_verify_success() {
        let (store, _) = make_store_with_attestation("database:delete_records:project_alpha");
        let result = store.verify("database:delete_records:project_alpha").unwrap();
        assert!(result.verified);
        assert_eq!(result.reason, VerifyReason::Attested);
    }

    #[test]
    fn test_verify_no_attestation() {
        let store = AttestationStore::new();
        let result = store.verify("database:delete_records:project_alpha").unwrap();
        assert!(!result.verified);
        assert_eq!(result.reason, VerifyReason::NoAttestation);
    }

    #[test]
    fn test_verify_wrong_action_class() {
        let (store, _) = make_store_with_attestation("database:delete_records:project_alpha");
        let result = store.verify("database:delete_records:project_beta").unwrap();
        assert!(!result.verified);
        assert_eq!(result.reason, VerifyReason::NoAttestation);
    }

    #[test]
    fn test_verify_invalid_action_class() {
        let store = AttestationStore::new();
        let result = store.verify("bad_action_class").unwrap();
        assert!(!result.verified);
        assert_eq!(result.reason, VerifyReason::InvalidActionClass);
    }

    #[test]
    fn test_verify_expired() {
        let keypair = KeyPair::generate();
        let mut store = AttestationStore::new();
        // Expire in 1ms — will be expired by the time we verify
        store
            .attest(&keypair, "database:delete_records:project_alpha", "test", Some(1))
            .unwrap();

        // Small sleep to ensure expiry
        std::thread::sleep(std::time::Duration::from_millis(10));

        let result = store.verify("database:delete_records:project_alpha").unwrap();
        assert!(!result.verified);
        assert_eq!(result.reason, VerifyReason::Expired);
    }

    #[test]
    fn test_revoke() {
        let keypair = KeyPair::generate();
        let mut store = AttestationStore::new();
        let attestation = store
            .attest(&keypair, "database:delete_records:project_alpha", "approved", None)
            .unwrap();

        // Verify it works before revocation
        let result = store.verify("database:delete_records:project_alpha").unwrap();
        assert!(result.verified);

        // Revoke it
        store.revoke(&keypair, &attestation.id.to_string(), "changed my mind").unwrap();

        // Verify it's now revoked
        let result = store.verify("database:delete_records:project_alpha").unwrap();
        assert!(!result.verified);
        assert_eq!(result.reason, VerifyReason::Revoked);
    }

    #[test]
    fn test_revoke_wrong_key() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let mut store = AttestationStore::new();
        let attestation = store
            .attest(&keypair1, "database:delete_records:project_alpha", "approved", None)
            .unwrap();

        let err = store.revoke(&keypair2, &attestation.id.to_string(), "wrong key");
        assert!(matches!(err, Err(OathError::RevocationKeyMismatch)));
    }

    #[test]
    fn test_store_rejects_tampered_attestation() {
        let keypair = KeyPair::generate();
        let mut store = AttestationStore::new();
        let mut attestation = store
            .attest(&keypair, "database:delete_records:project_alpha", "approved", None)
            .unwrap();

        // Tamper with the attestation
        let mut sig_bytes = Base64Url::decode_vec(&attestation.signature).unwrap();
        sig_bytes[63] ^= 0x01;
        attestation.signature = Base64Url::encode_string(&sig_bytes);

        // Remove from store and try to re-append the tampered version
        let mut store2 = AttestationStore::new();
        let err = store2.append(attestation);
        assert!(matches!(err, Err(OathError::SignatureRejected(_))));
    }

    #[test]
    fn test_integrity_hash_changes_on_append() {
        let keypair = KeyPair::generate();
        let mut store = AttestationStore::new();
        let h1 = store.integrity_hash();

        store.attest(&keypair, "database:delete_records:alpha", "test", None).unwrap();
        let h2 = store.integrity_hash();

        assert_ne!(h1, h2);
    }

    #[test]
    fn test_merge() {
        let keypair = KeyPair::generate();
        let mut store1 = AttestationStore::new();
        let mut store2 = AttestationStore::new();

        store1.attest(&keypair, "database:delete_records:alpha", "approved", None).unwrap();
        store2.attest(&keypair, "email:send:team_status", "approved", None).unwrap();

        // Merge store2's attestations into store1
        let store2_attestations: Vec<Attestation> = store2.history()
            .into_iter()
            .cloned()
            .collect();
        let added = store1.merge(store2_attestations);

        assert_eq!(added, 1);
        assert_eq!(store1.size(), 2);
    }

    #[test]
    fn test_history_ordered_newest_first() {
        let keypair = KeyPair::generate();
        let mut store = AttestationStore::new();

        store.attest(&keypair, "database:delete_records:alpha", "first", None).unwrap();
        // Small sleep to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(5));
        store.attest(&keypair, "email:send:team_status", "second", None).unwrap();

        let history = store.history();
        assert_eq!(history.len(), 2);
        assert!(history[0].timestamp_ms >= history[1].timestamp_ms);
    }
}
