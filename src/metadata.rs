//! The fixed ATL adaptor metadata object (adaptor profile §4.2).
//!
//! Every AHL entry anchored under `ahl-adaptor-atl-v1` carries the same constant ATL
//! metadata object, and the log leaf hash is a pure function of the entry bytes and that
//! constant. [`METADATA_HASH`] is derived at process start from the literal JSON object
//! rather than transcribed from the profile's published hex constant, so a transcription
//! error cannot silently diverge from it; `tests::metadata_hash_matches_profile_constant`
//! cross-checks the two.

use std::sync::LazyLock;

use atl_core::core::merkle::{compute_leaf_hash, Hash};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

/// The fixed ATL metadata object every AHL entry under this profile carries (§4.2).
#[must_use]
pub fn adaptor_metadata_object() -> Value {
    json!({ "ahl_adaptor": "ahl-adaptor-atl-v1" })
}

/// `JCS` bytes of the fixed adaptor metadata object — 36 bytes, constant for the process.
#[must_use]
pub fn adaptor_metadata_bytes() -> Vec<u8> {
    ahl_core::jcs(&adaptor_metadata_object())
}

/// The digest the profile publishes as `metadata_hash` (§4.2).
pub static METADATA_HASH: LazyLock<Hash> =
    LazyLock::new(|| Sha256::digest(adaptor_metadata_bytes()).into());

/// The ATL log-tree leaf hash for an AHL entry (adaptor profile §4.2):
/// `SHA-256(0x00 || SHA-256(JCS(envelope)) || METADATA_HASH)`.
///
/// `envelope_bytes` MUST be `JCS(envelope)` — the exact bytes anchored as the entry.
#[must_use]
pub fn log_leaf_hash(envelope_bytes: &[u8]) -> Hash {
    let payload_hash: Hash = Sha256::digest(envelope_bytes).into();
    compute_leaf_hash(&payload_hash, &METADATA_HASH)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The profile (§4.2) publishes this hash for the 36-byte JCS form of
    /// `{"ahl_adaptor":"ahl-adaptor-atl-v1"}`. It is restated here, once, purely as a
    /// cross-check against the value this module *derives*; the derivation is what the rest
    /// of the crate actually uses.
    const PUBLISHED_METADATA_HASH_HEX: &str =
        "bb4f98461f062d897980c9050f8f859c3b83c84486c5e6857262f6dfa97468a4";

    #[test]
    fn adaptor_metadata_bytes_are_the_documented_36_bytes() {
        assert_eq!(adaptor_metadata_bytes().len(), 36);
        assert_eq!(adaptor_metadata_bytes(), br#"{"ahl_adaptor":"ahl-adaptor-atl-v1"}"#);
    }

    #[test]
    fn metadata_hash_matches_profile_constant() {
        assert_eq!(hex::encode(*METADATA_HASH), PUBLISHED_METADATA_HASH_HEX);
    }

    #[test]
    fn log_leaf_hash_is_deterministic_and_input_sensitive() {
        let a = log_leaf_hash(b"{}");
        let b = log_leaf_hash(b"{}");
        let c = log_leaf_hash(b"{\"x\":1}");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
