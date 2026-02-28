use serde::{Deserialize, Serialize};

use crate::attestation::Attestation;

/// The reason a verification succeeded or failed.
///
/// See Oath Protocol Specification Section 14.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerifyReason {
    /// Valid attestation found. `verified` is `true`.
    Attested,
    /// No attestation found for this action class.
    NoAttestation,
    /// Attestation found but `expires_at_ms` has passed.
    Expired,
    /// Attestation found but a valid revocation exists.
    Revoked,
    /// Attestation found but signature verification failed.
    InvalidSignature,
    /// The queried action class string is malformed.
    InvalidActionClass,
}

impl std::fmt::Display for VerifyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyReason::Attested => write!(f, "ATTESTED"),
            VerifyReason::NoAttestation => write!(f, "NO_ATTESTATION"),
            VerifyReason::Expired => write!(f, "EXPIRED"),
            VerifyReason::Revoked => write!(f, "REVOKED"),
            VerifyReason::InvalidSignature => write!(f, "INVALID_SIGNATURE"),
            VerifyReason::InvalidActionClass => write!(f, "INVALID_ACTION_CLASS"),
        }
    }
}

/// The result of a verification operation.
///
/// `verified` is `true` only when `reason` is `Attested`.
///
/// See Oath Protocol Specification Section 8.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Whether a valid attestation was found. True only when reason is `Attested`.
    pub verified: bool,

    /// The ID of the attestation that was checked, if any was found.
    pub attestation_id: Option<String>,

    /// The specific reason for the verification result.
    pub reason: VerifyReason,

    /// Unix timestamp in milliseconds when this check was performed.
    pub checked_at_ms: u64,
}

impl VerifyResult {
    pub(crate) fn attested(attestation: &Attestation, now_ms: u64) -> Self {
        VerifyResult {
            verified: true,
            attestation_id: Some(attestation.id.to_string()),
            reason: VerifyReason::Attested,
            checked_at_ms: now_ms,
        }
    }

    pub(crate) fn no_attestation(now_ms: u64) -> Self {
        VerifyResult {
            verified: false,
            attestation_id: None,
            reason: VerifyReason::NoAttestation,
            checked_at_ms: now_ms,
        }
    }

    pub(crate) fn expired(attestation: &Attestation, now_ms: u64) -> Self {
        VerifyResult {
            verified: false,
            attestation_id: Some(attestation.id.to_string()),
            reason: VerifyReason::Expired,
            checked_at_ms: now_ms,
        }
    }

    pub(crate) fn revoked(attestation: &Attestation, now_ms: u64) -> Self {
        VerifyResult {
            verified: false,
            attestation_id: Some(attestation.id.to_string()),
            reason: VerifyReason::Revoked,
            checked_at_ms: now_ms,
        }
    }

    pub(crate) fn invalid_signature(attestation: &Attestation, now_ms: u64) -> Self {
        VerifyResult {
            verified: false,
            attestation_id: Some(attestation.id.to_string()),
            reason: VerifyReason::InvalidSignature,
            checked_at_ms: now_ms,
        }
    }

    pub(crate) fn invalid_action_class(now_ms: u64) -> Self {
        VerifyResult {
            verified: false,
            attestation_id: None,
            reason: VerifyReason::InvalidActionClass,
            checked_at_ms: now_ms,
        }
    }
}
