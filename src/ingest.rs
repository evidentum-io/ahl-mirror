//! Ingest: verify entry bytes before they enter the store (core spec §2.1, §2.4-§2.5;
//! adaptor profile §4.2).

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::error::{MirrorError, MirrorResult};
use crate::metadata::adaptor_metadata_bytes;
use crate::store::{InsertOutcome, Store};

/// Verify `bytes` against the profile's ingest checks and, if they all pass, store them at
/// `entry_index`.
///
/// Checks, in order:
///
/// 1. `SHA-256(bytes)` equals `claimed_entry_id` (core spec §2.1).
/// 2. `bytes` parse as JSON.
/// 3. the parsed value is envelope-shaped: a JSON object with an object `payload` field and
///    a non-empty array `signatures` field (core spec §2.1: unsigned objects are not AHL
///    statements).
/// 4. re-serializing the parsed value under JCS reproduces `bytes` exactly (core spec §2.4,
///    RFC 8785) — `bytes` are JCS-canonical.
/// 5. `atl_metadata`, JCS-canonicalized, equals the fixed adaptor metadata object (adaptor
///    profile §4.2).
///
/// Only after every check passes does the entry reach the store, where index sequencing and
/// content-addressing are enforced (see [`Store::insert_entry`]).
///
/// # Errors
///
/// A specific [`MirrorError`] variant naming the failed check, or a store error.
pub fn ingest_entry(
    store: &Store,
    entry_index: u64,
    claimed_entry_id: &str,
    bytes: &[u8],
    atl_metadata: &Value,
) -> MirrorResult<InsertOutcome> {
    let computed_id = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
    if computed_id != claimed_entry_id {
        return Err(MirrorError::EntryIdMismatch {
            claimed: claimed_entry_id.to_owned(),
            computed: computed_id,
        });
    }

    let value: Value = serde_json::from_slice(bytes)?;
    let obj =
        value.as_object().ok_or(MirrorError::MalformedEnvelope { reason: "not a JSON object" })?;
    if !obj.get("payload").is_some_and(Value::is_object) {
        return Err(MirrorError::MalformedEnvelope { reason: "missing object field `payload`" });
    }
    if obj.get("signatures").and_then(Value::as_array).is_none_or(Vec::is_empty) {
        return Err(MirrorError::MalformedEnvelope {
            reason: "missing non-empty array field `signatures`",
        });
    }

    let canonical = ahl_core::jcs(&value);
    if canonical != bytes {
        return Err(MirrorError::NotCanonical);
    }

    let metadata_canonical = ahl_core::jcs(atl_metadata);
    if metadata_canonical != adaptor_metadata_bytes() {
        return Err(MirrorError::WrongAdaptorMetadata {
            got: String::from_utf8_lossy(&metadata_canonical).into_owned(),
        });
    }

    store.insert_entry(entry_index, &computed_id, bytes)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::metadata::adaptor_metadata_object;

    fn envelope_bytes() -> Vec<u8> {
        let env = json!({
            "payload": { "type": "key" },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        });
        ahl_core::jcs(&env)
    }

    fn entry_id_of(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }

    #[test]
    fn a_well_formed_entry_is_stored() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = envelope_bytes();
        let id = entry_id_of(&bytes);
        let outcome =
            ingest_entry(&store, 0, &id, &bytes, &adaptor_metadata_object()).expect("valid entry");
        assert_eq!(outcome, InsertOutcome::Inserted);
        assert!(store.get_entry_by_id(&id).expect("query").is_some());
    }

    #[test]
    fn a_wrong_claimed_id_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = envelope_bytes();
        let wrong_id = format!("sha256:{}", "00".repeat(32));
        assert!(matches!(
            ingest_entry(&store, 0, &wrong_id, &bytes, &adaptor_metadata_object()),
            Err(MirrorError::EntryIdMismatch { .. })
        ));
    }

    #[test]
    fn non_json_bytes_are_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = b"not json".to_vec();
        let id = entry_id_of(&bytes);
        assert!(matches!(
            ingest_entry(&store, 0, &id, &bytes, &adaptor_metadata_object()),
            Err(MirrorError::Json(_))
        ));
    }

    #[test]
    fn a_missing_payload_field_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = ahl_core::jcs(&json!({ "signatures": [ { "key_id": "a", "sig": "b" } ] }));
        let id = entry_id_of(&bytes);
        assert!(matches!(
            ingest_entry(&store, 0, &id, &bytes, &adaptor_metadata_object()),
            Err(MirrorError::MalformedEnvelope { .. })
        ));
    }

    #[test]
    fn an_unsigned_envelope_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = ahl_core::jcs(&json!({ "payload": {}, "signatures": [] }));
        let id = entry_id_of(&bytes);
        assert!(matches!(
            ingest_entry(&store, 0, &id, &bytes, &adaptor_metadata_object()),
            Err(MirrorError::MalformedEnvelope { .. })
        ));
    }

    #[test]
    fn a_non_canonical_envelope_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        // Well-formed JSON, correctly hashed, but with insignificant whitespace JCS would
        // strip: not byte-identical to its own canonicalization.
        let bytes = br#"{"payload": {"type":"key"}, "signatures":[{"key_id":"sha256:aa","sig":"base64:bb"}]}"#.to_vec();
        let id = entry_id_of(&bytes);
        assert!(matches!(
            ingest_entry(&store, 0, &id, &bytes, &adaptor_metadata_object()),
            Err(MirrorError::NotCanonical)
        ));
    }

    #[test]
    fn wrong_adaptor_metadata_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = envelope_bytes();
        let id = entry_id_of(&bytes);
        assert!(matches!(
            ingest_entry(&store, 0, &id, &bytes, &json!({ "ahl_adaptor": "ahl-adaptor-atl-v2" })),
            Err(MirrorError::WrongAdaptorMetadata { .. })
        ));
    }

    #[test]
    fn repeated_identical_ingest_is_idempotent() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = envelope_bytes();
        let id = entry_id_of(&bytes);
        ingest_entry(&store, 0, &id, &bytes, &adaptor_metadata_object()).expect("first");
        let outcome = ingest_entry(&store, 0, &id, &bytes, &adaptor_metadata_object())
            .expect("repeat of the same entry");
        assert_eq!(outcome, InsertOutcome::AlreadyPresent);
    }

    #[test]
    fn an_out_of_order_index_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = envelope_bytes();
        let id = entry_id_of(&bytes);
        assert!(matches!(
            ingest_entry(&store, 1, &id, &bytes, &adaptor_metadata_object()),
            Err(MirrorError::OutOfOrderIndex { expected: 0, got: 1 })
        ));
    }
}
