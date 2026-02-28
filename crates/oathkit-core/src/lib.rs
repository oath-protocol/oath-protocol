//! # OathKit Core
//!
//! The reference implementation of the Oath Protocol — an open protocol for
//! cryptographically verifiable human intent attestation.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use oathkit_core::{KeyPair, AttestationStore, OathError};
//!
//! # fn main() -> Result<(), OathError> {
//! // Generate a keypair (typically done once via `oath init`)
//! let keypair = KeyPair::generate();
//!
//! // Create a store and attest an action
//! let mut store = AttestationStore::new();
//! let attestation = store.attest(
//!     &keypair,
//!     "database:delete_records:project_alpha",
//!     "cleanup approved by team lead",
//!     None, // no expiry
//! )?;
//!
//! // Verify before an agent acts
//! let result = store.verify("database:delete_records:project_alpha")?;
//! assert!(result.verified);
//! # Ok(())
//! # }
//! ```
//!
//! ## Protocol
//!
//! See the Oath Protocol Specification at `spec/OATH_SPEC.md` for the full
//! canonical reference. This library is the reference implementation.

pub mod attestation;
pub mod error;
pub mod keys;
pub mod store;
pub mod verify;

pub use attestation::{ActionClass, Attestation, PROTOCOL_VERSION};
pub use error::OathError;
pub use keys::KeyPair;
pub use store::AttestationStore;
pub use verify::{VerifyReason, VerifyResult};
