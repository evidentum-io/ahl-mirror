//! Authenticated range enumeration and the `AHLRP1` proof (adaptor profile §10.2-§10.5).

use ahl_core::range_proof;
use atl_core::core::merkle::{compute_root, Hash};
use serde::{Deserialize, Serialize};

use crate::checkpoint::Checkpoint;
use crate::error::{MirrorError, MirrorResult};
use crate::metadata::log_leaf_hash;

/// One enumerated entry: its index and its full envelope, verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumeratedEntry {
    /// The entry's position in the log.
    pub entry_index: u64,
    /// The entry's envelope, parsed. The wire bytes this was parsed from are exactly
    /// `JCS(envelope)`, and re-serializing this value under JCS reproduces them, because
    /// only entries that already passed [`crate::ingest::stage_entry`]'s canonical-form
    /// check are ever staged, and only proof-verified staged entries are ever promoted to
    /// canonical storage (see [`crate::ingest::promote_entry`]).
    pub envelope: serde_json::Value,
}

/// The requested range, echoed back (adaptor profile §10.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeEnvelope {
    /// First entry index in the proven range, inclusive.
    pub from_index: u64,
    /// End of the proven range, exclusive.
    pub to_index: u64,
}

/// The wire form of the range proof (adaptor profile §10.3, §10.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProofWire {
    /// `"base64:" || base64(AHLRP1 bytes)` (§10.5).
    pub adaptor_form: String,
}

/// The complete authenticated-enumeration response (adaptor profile §10.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeResponse {
    /// The range this response proves.
    pub range: RangeEnvelope,
    /// The entries of the range, in ascending entry-index order.
    pub entries: Vec<EnumeratedEntry>,
    /// The proof that `entries` is exactly and completely the leaf set of `range` under
    /// `checkpoint`.
    pub range_proof: RangeProofWire,
    /// The signed checkpoint the proof opens.
    pub checkpoint: Checkpoint,
}

/// Build a range response for `[from_index, to_index)` under `checkpoint`.
///
/// `all_entries` MUST be the entry bytes covering `[0, checkpoint.tree_size)`, in ascending
/// index order — the range proof's subtree hashes for material outside `[from_index,
/// to_index)` are computed from it, so the full prefix is required even though only the
/// requested sub-range is returned in `entries`.
///
/// Before returning, this function verifies its own output: it recomputes the checkpoint's
/// root from `all_entries` and confirms the freshly generated proof actually verifies
/// against it. A mismatch is reported as [`MirrorError::CheckpointRootMismatch`] rather than
/// served — this deployment does not hand out a proof it cannot itself verify.
///
/// # Errors
///
/// [`MirrorError::IncompleteEntries`], [`MirrorError::InvalidRange`],
/// [`MirrorError::CheckpointRootMismatch`], or an underlying parsing/JSON error.
pub fn build_range_response(
    checkpoint: &Checkpoint,
    from_index: u64,
    to_index: u64,
    all_entries: &[Vec<u8>],
) -> MirrorResult<RangeResponse> {
    let have = u64::try_from(all_entries.len())
        .map_err(|_| MirrorError::IndexOverflow { what: "all_entries.len()" })?;
    if have != checkpoint.tree_size {
        return Err(MirrorError::IncompleteEntries { have, need: checkpoint.tree_size });
    }
    if from_index >= to_index || to_index > checkpoint.tree_size {
        return Err(MirrorError::InvalidRange {
            from_index,
            to_index,
            tree_size: checkpoint.tree_size,
        });
    }

    let leaf_hashes: Vec<Hash> = all_entries.iter().map(|bytes| log_leaf_hash(bytes)).collect();
    let root: Hash = ahl_core::parse_hash_hex(&checkpoint.root_hash)?;
    if compute_root(&leaf_hashes) != root {
        return Err(MirrorError::CheckpointRootMismatch { tree_size: checkpoint.tree_size });
    }

    let proof = range_proof::generate(&leaf_hashes, from_index, to_index)?;

    let from = usize::try_from(from_index)
        .map_err(|_| MirrorError::IndexOverflow { what: "from_index" })?;
    let to =
        usize::try_from(to_index).map_err(|_| MirrorError::IndexOverflow { what: "to_index" })?;
    // `leaf_hashes` has one element per entry, `have == checkpoint.tree_size` was checked
    // above, and the range guard established `from < to <= tree_size`; these lookups restate
    // that rather than trusting it, because `from`/`to` originate in a client's query.
    let out_of_range =
        || MirrorError::InvalidRange { from_index, to_index, tree_size: checkpoint.tree_size };
    let span = leaf_hashes.get(from..to).ok_or_else(out_of_range)?;
    if !range_proof::verify(&proof, span, &root)? {
        // Generation and the checkpoint root both checked out individually; a proof that
        // still fails to verify indicates a defect in this crate, not bad input. Surfaced
        // the same way as a storage integrity fault: never served.
        return Err(MirrorError::CheckpointRootMismatch { tree_size: checkpoint.tree_size });
    }

    let entries = all_entries
        .get(from..to)
        .ok_or_else(out_of_range)?
        .iter()
        .enumerate()
        .map(|(offset, bytes)| -> MirrorResult<EnumeratedEntry> {
            let offset = u64::try_from(offset)
                .map_err(|_| MirrorError::IndexOverflow { what: "range offset" })?;
            let entry_index = from_index
                .checked_add(offset)
                .ok_or(MirrorError::IndexOverflow { what: "entry_index" })?;
            let envelope: serde_json::Value = serde_json::from_slice(bytes)?;
            Ok(EnumeratedEntry { entry_index, envelope })
        })
        .collect::<MirrorResult<Vec<_>>>()?;

    Ok(RangeResponse {
        range: RangeEnvelope { from_index, to_index },
        entries,
        range_proof: RangeProofWire { adaptor_form: range_proof::encode(&proof) },
        checkpoint: checkpoint.clone(),
    })
}

/// Verify a [`RangeResponse`] entirely offline.
///
/// Replays exactly what a receiving verifier would do: recompute each entry's log leaf hash
/// and check the carried proof opens the checkpoint's root (adaptor profile §10.4).
///
/// # Errors
///
/// Returns [`MirrorError::InvalidRange`] if `entries` is not contiguous ascending from
/// `range.from_index`, a decode error for a malformed `range_proof.adaptor_form`, or
/// propagates [`range_proof::verify`]'s errors.
pub fn verify_range_response(response: &RangeResponse) -> MirrorResult<bool> {
    for (offset, entry) in response.entries.iter().enumerate() {
        let offset = u64::try_from(offset)
            .map_err(|_| MirrorError::IndexOverflow { what: "range offset" })?;
        let expected = response
            .range
            .from_index
            .checked_add(offset)
            .ok_or(MirrorError::IndexOverflow { what: "entry_index" })?;
        if entry.entry_index != expected {
            return Err(MirrorError::InvalidRange {
                from_index: response.range.from_index,
                to_index: response.range.to_index,
                tree_size: response.checkpoint.tree_size,
            });
        }
    }

    let leaf_hashes: MirrorResult<Vec<Hash>> = response
        .entries
        .iter()
        .map(|entry| Ok(log_leaf_hash(&ahl_core::jcs(&entry.envelope))))
        .collect();
    let leaf_hashes = leaf_hashes?;

    let proof = range_proof::decode(&response.range_proof.adaptor_form)?;
    if proof.tree_size != response.checkpoint.tree_size
        || proof.from_index != response.range.from_index
        || proof.to_index != response.range.to_index
    {
        return Err(MirrorError::InvalidRange {
            from_index: response.range.from_index,
            to_index: response.range.to_index,
            tree_size: response.checkpoint.tree_size,
        });
    }

    let root: Hash = ahl_core::parse_hash_hex(&response.checkpoint.root_hash)?;
    Ok(range_proof::verify(&proof, &leaf_hashes, &root)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u8) -> Vec<u8> {
        ahl_core::jcs(&serde_json::json!({
            "payload": { "n": n },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }))
    }

    fn checkpoint_for(entries: &[Vec<u8>]) -> Checkpoint {
        let leaves: Vec<Hash> = entries.iter().map(|b| log_leaf_hash(b)).collect();
        let root = compute_root(&leaves);
        Checkpoint {
            log_id: "sha256:aa".to_owned(),
            tree_size: u64::try_from(entries.len()).expect("small test size"),
            root_hash: format!("sha256:{}", hex::encode(root)),
            checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
            key_id: "sha256:bb".to_owned(),
            signature: "base64:AAAA".to_owned(),
        }
    }

    #[test]
    fn a_full_range_response_round_trips_through_generate_serialize_deserialize_verify() {
        let entries: Vec<Vec<u8>> = (0u8..12).map(entry).collect();
        let checkpoint = checkpoint_for(&entries);

        let response = build_range_response(&checkpoint, 3, 9, &entries).expect("valid sub-range");
        let wire = serde_json::to_vec(&response).expect("serialize");
        let round_tripped: RangeResponse = serde_json::from_slice(&wire).expect("deserialize");

        assert_eq!(round_tripped.entries.len(), 6);
        assert!(verify_range_response(&round_tripped).expect("well-formed"));
    }

    #[test]
    fn the_full_range_needs_no_subtree_hashes_and_still_verifies() {
        let entries: Vec<Vec<u8>> = (0u8..5).map(entry).collect();
        let checkpoint = checkpoint_for(&entries);
        let response = build_range_response(&checkpoint, 0, 5, &entries).expect("full range");
        assert!(verify_range_response(&response).expect("well-formed"));
    }

    #[test]
    fn an_incomplete_prefix_is_rejected_before_any_proof_is_built() {
        let entries: Vec<Vec<u8>> = (0u8..12).map(entry).collect();
        let checkpoint = checkpoint_for(&entries);
        let short = &entries[..10];
        assert!(matches!(
            build_range_response(&checkpoint, 0, 5, short),
            Err(MirrorError::IncompleteEntries { have: 10, need: 12 })
        ));
    }

    #[test]
    fn an_out_of_bounds_range_is_rejected() {
        let entries: Vec<Vec<u8>> = (0u8..5).map(entry).collect();
        let checkpoint = checkpoint_for(&entries);
        assert!(matches!(
            build_range_response(&checkpoint, 3, 3, &entries),
            Err(MirrorError::InvalidRange { .. })
        ));
        assert!(matches!(
            build_range_response(&checkpoint, 0, 6, &entries),
            Err(MirrorError::InvalidRange { .. })
        ));
    }

    #[test]
    fn a_checkpoint_whose_root_disagrees_with_the_entries_is_rejected() {
        let entries: Vec<Vec<u8>> = (0u8..5).map(entry).collect();
        let mut checkpoint = checkpoint_for(&entries);
        checkpoint.root_hash = format!("sha256:{}", "00".repeat(32));
        assert!(matches!(
            build_range_response(&checkpoint, 0, 5, &entries),
            Err(MirrorError::CheckpointRootMismatch { .. })
        ));
    }

    #[test]
    fn a_reordered_response_does_not_verify() {
        let entries: Vec<Vec<u8>> = (0u8..6).map(entry).collect();
        let checkpoint = checkpoint_for(&entries);
        let mut response = build_range_response(&checkpoint, 1, 5, &entries).expect("valid");
        response.entries.swap(0, 1);
        // Swapping breaks the entry_index/offset contract before the proof is even consulted.
        assert!(matches!(verify_range_response(&response), Err(MirrorError::InvalidRange { .. })));
    }

    #[test]
    fn a_substituted_entry_fails_verification_without_erroring() {
        let entries: Vec<Vec<u8>> = (0u8..6).map(entry).collect();
        let checkpoint = checkpoint_for(&entries);
        let mut response = build_range_response(&checkpoint, 1, 5, &entries).expect("valid");
        let substituted: serde_json::Value =
            serde_json::from_slice(&entry(99)).expect("well-formed test fixture");
        response.entries[0].envelope = substituted;
        assert!(!verify_range_response(&response).expect("well-formed proof"));
    }
}
