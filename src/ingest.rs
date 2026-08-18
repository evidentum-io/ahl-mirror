//! Staging and promotion.
//!
//! Verify entry bytes before they may even be staged (core spec §2.1, §2.4-§2.5; adaptor
//! profile §4.2), then admit a staged candidate to canonical storage only once it carries
//! cryptographic evidence of anchoring — a Merkle inclusion proof against a checkpoint this
//! mirror has already authenticated (adaptor profile §8.2; core spec §3 contract item 3).
//!
//! Splitting these into two steps is the fix for a standing denial of service: bytes that
//! merely pass the format checks below prove nothing about what the log anchored, so
//! admitting them straight into the position-indexed canonical table would let a party with
//! no authority over the log permanently occupy an index the genuine entry needs. See the
//! `store` module docs for the storage-level half of this design.

use atl_core::core::merkle::{verify_inclusion, Hash};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::checkpoint::Checkpoint;
use crate::error::{MirrorError, MirrorResult};
use crate::metadata::{adaptor_metadata_bytes, log_leaf_hash};
use crate::store::{InsertOutcome, Store};

/// Verify `bytes` against the profile's format checks and, if they all pass, stage them
/// under their entry id.
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
/// Staging carries **no** claim about position or anchoring — see [`promote_entry`] for what
/// does.
///
/// # Errors
///
/// A specific [`MirrorError`] variant naming the failed check, or a store error.
pub fn stage_entry(
    store: &Store,
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

    store.stage_entry(&computed_id, bytes)
}

/// Verify a Merkle inclusion proof of `bytes`' log leaf at `leaf_index`, under a tree of
/// `tree_size` with root `root` (adaptor profile §8.2).
///
/// A pure check: it neither reads nor writes the store, and does not require `root` to have
/// been authenticated — it only establishes "if this root is genuine, these bytes truly sit
/// at this position", which is safe to evaluate before that root's signature has been
/// checked (see [`crate::checkpoint::ingest_checkpoint`], which relies on exactly that to
/// resolve governance material from entries not yet committed).
///
/// # Errors
///
/// A parsing error if `inclusion_path` is malformed, or [`MirrorError::Atl`] if the
/// underlying Merkle verification cannot run. A structurally valid proof that simply does
/// not open the root yields `Ok(false)`, not an error.
pub fn verify_inclusion_for(
    bytes: &[u8],
    leaf_index: u64,
    tree_size: u64,
    inclusion_path: &[String],
    root: &Hash,
) -> MirrorResult<bool> {
    let leaf: Hash = log_leaf_hash(bytes);
    let proof = ahl_core::proof_from_hex(leaf_index, tree_size, inclusion_path)?;
    Ok(verify_inclusion(&leaf, &proof, root)?)
}

/// Promote a staged entry to canonical storage, given a Merkle inclusion proof of its log
/// leaf under `checkpoint` (adaptor profile §8.2).
///
/// `checkpoint` MUST already be authenticated by the caller (signature verified against a
/// properly resolved key — see [`crate::checkpoint::ingest_checkpoint`]); this function
/// trusts `checkpoint.root_hash` as given and only checks that the staged bytes are included
/// under it at `leaf_index`. Unverified bytes are never promoted on the strength of a claim
/// alone: a party who has only staged garbage cannot produce a proof that opens a genuine
/// root, so garbage simply never promotes.
///
/// # Errors
///
/// [`MirrorError::NotStaged`] if `entry_id` was never staged;
/// [`MirrorError::InclusionProofInvalid`] if the proof does not open `checkpoint.root_hash`;
/// or a parsing/store error.
pub fn promote_entry(
    store: &Store,
    checkpoint: &Checkpoint,
    entry_id: &str,
    leaf_index: u64,
    inclusion_path: &[String],
) -> MirrorResult<InsertOutcome> {
    let bytes = store
        .get_staged(entry_id)?
        .ok_or_else(|| MirrorError::NotStaged { entry_id: entry_id.to_owned() })?;

    let root: Hash = ahl_core::parse_hash_hex(&checkpoint.root_hash)?;
    if !verify_inclusion_for(&bytes, leaf_index, checkpoint.tree_size, inclusion_path, &root)? {
        return Err(MirrorError::InclusionProofInvalid {
            entry_id: entry_id.to_owned(),
            leaf_index,
            tree_size: checkpoint.tree_size,
        });
    }

    store.promote_entry(leaf_index, entry_id)
}

#[cfg(test)]
mod tests {
    use atl_core::core::merkle::generate_inclusion_proof;
    use serde_json::json;

    use super::*;
    use crate::metadata::adaptor_metadata_object;

    fn envelope_bytes(n: u8) -> Vec<u8> {
        let env = json!({
            "payload": { "n": n },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        });
        ahl_core::jcs(&env)
    }

    fn entry_id_of(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }

    #[test]
    fn a_well_formed_entry_is_staged_but_not_canonical() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = envelope_bytes(1);
        let id = entry_id_of(&bytes);
        let outcome =
            stage_entry(&store, &id, &bytes, &adaptor_metadata_object()).expect("valid entry");
        assert_eq!(outcome, InsertOutcome::Inserted);
        assert!(store.get_staged(&id).expect("query").is_some());
        assert!(store.get_entry_by_id(&id).expect("query").is_none());
    }

    #[test]
    fn a_wrong_claimed_id_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = envelope_bytes(1);
        let wrong_id = format!("sha256:{}", "00".repeat(32));
        assert!(matches!(
            stage_entry(&store, &wrong_id, &bytes, &adaptor_metadata_object()),
            Err(MirrorError::EntryIdMismatch { .. })
        ));
    }

    #[test]
    fn non_json_bytes_are_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = b"not json".to_vec();
        let id = entry_id_of(&bytes);
        assert!(matches!(
            stage_entry(&store, &id, &bytes, &adaptor_metadata_object()),
            Err(MirrorError::Json(_))
        ));
    }

    #[test]
    fn a_missing_payload_field_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = ahl_core::jcs(&json!({ "signatures": [ { "key_id": "a", "sig": "b" } ] }));
        let id = entry_id_of(&bytes);
        assert!(matches!(
            stage_entry(&store, &id, &bytes, &adaptor_metadata_object()),
            Err(MirrorError::MalformedEnvelope { .. })
        ));
    }

    #[test]
    fn an_unsigned_envelope_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = ahl_core::jcs(&json!({ "payload": {}, "signatures": [] }));
        let id = entry_id_of(&bytes);
        assert!(matches!(
            stage_entry(&store, &id, &bytes, &adaptor_metadata_object()),
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
            stage_entry(&store, &id, &bytes, &adaptor_metadata_object()),
            Err(MirrorError::NotCanonical)
        ));
    }

    #[test]
    fn wrong_adaptor_metadata_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = envelope_bytes(1);
        let id = entry_id_of(&bytes);
        assert!(matches!(
            stage_entry(&store, &id, &bytes, &json!({ "ahl_adaptor": "ahl-adaptor-atl-v2" })),
            Err(MirrorError::WrongAdaptorMetadata { .. })
        ));
    }

    #[test]
    fn repeated_identical_staging_is_idempotent() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = envelope_bytes(1);
        let id = entry_id_of(&bytes);
        stage_entry(&store, &id, &bytes, &adaptor_metadata_object()).expect("first");
        let outcome = stage_entry(&store, &id, &bytes, &adaptor_metadata_object())
            .expect("repeat of the same entry");
        assert_eq!(outcome, InsertOutcome::AlreadyPresent);
    }

    /// Builds a checkpoint whose root genuinely commits `entries`, and the inclusion path
    /// for `entries[index]` under it, so promotion tests exercise the real Merkle math
    /// rather than a stub.
    fn checkpoint_and_proof(entries: &[Vec<u8>], index: usize) -> (Checkpoint, u64, Vec<String>) {
        let leaves: Vec<Hash> = entries.iter().map(|b| log_leaf_hash(b)).collect();
        let root = atl_core::core::merkle::compute_root(&leaves);
        let checkpoint = Checkpoint {
            log_id: "sha256:aa".to_owned(),
            tree_size: u64::try_from(entries.len()).expect("small test size"),
            root_hash: format!("sha256:{}", hex::encode(root)),
            checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
            key_id: "sha256:bb".to_owned(),
            signature: "base64:AAAA".to_owned(),
        };
        let index_u64 = u64::try_from(index).expect("small test index");
        let tree_size = u64::try_from(leaves.len()).expect("small test size");
        let proof = generate_inclusion_proof(index_u64, tree_size, |level, i| {
            if level == 0 {
                leaves.get(usize::try_from(i).ok()?).copied()
            } else {
                None
            }
        })
        .expect("index within tree");
        let path = ahl_core::proof_path_hex(&proof);
        (checkpoint, index_u64, path)
    }

    #[test]
    fn a_staged_entry_with_a_valid_proof_is_promoted() {
        let store = Store::open_in_memory().expect("in-memory store");
        let entries: Vec<Vec<u8>> = (0u8..4).map(envelope_bytes).collect();
        for bytes in &entries {
            store.stage_entry(&entry_id_of(bytes), bytes).expect("stage");
        }
        let (checkpoint, index, path) = checkpoint_and_proof(&entries, 0);
        let outcome = promote_entry(&store, &checkpoint, &entry_id_of(&entries[0]), index, &path)
            .expect("valid inclusion proof");
        assert_eq!(outcome, InsertOutcome::Inserted);
        assert!(store.get_entry_by_id(&entry_id_of(&entries[0])).expect("query").is_some());
    }

    #[test]
    fn promotion_without_staging_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let entries: Vec<Vec<u8>> = (0u8..4).map(envelope_bytes).collect();
        let (checkpoint, index, path) = checkpoint_and_proof(&entries, 0);
        // Never staged: no amount of proof material admits it (there is nothing to promote).
        assert!(matches!(
            promote_entry(&store, &checkpoint, &entry_id_of(&entries[0]), index, &path),
            Err(MirrorError::NotStaged { .. })
        ));
    }

    #[test]
    fn a_forged_checkpoint_cannot_promote_unrelated_staged_bytes() {
        // This is the admission-without-evidence attack directly: an attacker with no
        // authority over the log stages arbitrary (but well-formed) bytes, then tries to
        // promote them under a checkpoint whose root has nothing to do with what they
        // staged. No proof they can construct opens that root.
        let store = Store::open_in_memory().expect("in-memory store");
        let genuine: Vec<Vec<u8>> = (0u8..4).map(envelope_bytes).collect();
        let attacker_bytes = ahl_core::jcs(&json!({
            "payload": { "attacker": true },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }));
        store.stage_entry(&entry_id_of(&attacker_bytes), &attacker_bytes).expect("stage");

        let (checkpoint, index, path) = checkpoint_and_proof(&genuine, 0);
        assert!(matches!(
            promote_entry(&store, &checkpoint, &entry_id_of(&attacker_bytes), index, &path),
            Err(MirrorError::InclusionProofInvalid { .. })
        ));
        assert!(store.get_entry_by_id(&entry_id_of(&attacker_bytes)).expect("query").is_none());
    }

    #[test]
    fn a_proof_for_the_wrong_index_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let entries: Vec<Vec<u8>> = (0u8..4).map(envelope_bytes).collect();
        for bytes in &entries {
            store.stage_entry(&entry_id_of(bytes), bytes).expect("stage");
        }
        // A genuine proof for index 1, offered for entry 0's bytes at claimed index 1.
        let (checkpoint, index, path) = checkpoint_and_proof(&entries, 1);
        assert!(matches!(
            promote_entry(&store, &checkpoint, &entry_id_of(&entries[0]), index, &path),
            Err(MirrorError::InclusionProofInvalid { .. })
        ));
    }
}
