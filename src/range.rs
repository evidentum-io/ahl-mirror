//! Authenticated range enumeration and the `AHLRP1` proof (adaptor profile §10.2-§10.5).
//!
//! # What a range response costs to build
//!
//! A range proof carries the subtree hashes covering everything OUTSIDE the requested window
//! (§10.4), so a naive builder reads the whole `[0, tree_size)` prefix to hash it. It need
//! not. Generation walks the RFC 6962 decomposition of `[0, tree_size)` and emits the root of
//! every maximal subtree lying entirely outside the window; each of those roots is either a
//! COMPLETE power-of-two subtree — which the store already holds (see [`crate::store`]) — or
//! a right-spine remainder, whose own decomposition splits into one complete subtree and a
//! shorter remainder. Every node the walk needs is therefore one stored hash or a fold over
//! `O(log n)` of them.
//!
//! What remains is the window itself: `to_index - from_index` leaf hashes to check the freshly
//! built proof against, and the same number of entry envelopes to carry in the response. So
//! [`build_range_response`] reads entry BYTES for `[from_index, to_index)` and for nothing
//! else, and [`build_range_response_measured`] reports exactly what it read — see
//! [`RangeReadCost`].
//!
//! The response bytes are unchanged by any of this: the proof nodes are the same hashes in the
//! same order a full-prefix build produces, and `tests::the_windowed_builder_agrees_with_a_full_prefix_build`
//! holds the two together over a randomly shaped log.

use ahl_core::range_proof;
use ahl_core::range_proof::RangeProof;
use atl_core::core::merkle::{largest_power_of_2_less_than, Hash};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::checkpoint::Checkpoint;
use crate::error::{MirrorError, MirrorResult};
use crate::metadata::log_leaf_hash;
use crate::store::Store;

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

/// What one range response actually read out of the store.
///
/// Reported rather than asserted: the enumeration path's whole point is that it does not read
/// the log to answer a question about a window of it, and a number a caller can print is the
/// only form of that claim which cannot quietly stop being true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeReadCost {
    /// Entry envelopes read, in bytes. Only `[from_index, to_index)` is ever read.
    pub entry_bytes: u64,
    /// Stored 32-octet log-tree nodes read: the window's leaf hashes plus every complete
    /// subtree root the proof's outside nodes were folded from.
    pub tree_nodes: u64,
}

impl RangeReadCost {
    /// Total octets read from the store.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.entry_bytes.saturating_add(self.tree_nodes.saturating_mul(32))
    }
}

/// Where a subtree sits relative to the proven range (adaptor profile §10.4's `recompute`).
enum Span {
    /// Entirely outside — one carried subtree hash covers it.
    Outside,
    /// Entirely inside — recomputed by the verifier from the carried leaves.
    Inside,
    /// Straddles a boundary — split further.
    Straddles,
}

/// The classification §10.4 fixes before any proof node is read, restated here because
/// generation and verification MUST agree on it node for node.
const fn classify(offset: u64, size: u64, from: u64, to: u64) -> Span {
    // Every `(offset, size)` this walk produces satisfies `offset + size <= tree_size`, so the
    // sum is in range; saturating keeps that provable without a panicking operator.
    let end = offset.saturating_add(size);
    if end <= from || offset >= to {
        Span::Outside
    } else if offset >= from && end <= to {
        Span::Inside
    } else {
        Span::Straddles
    }
}

/// Collect the `(offset, size)` of every maximal subtree of `[0, tree_size)` lying entirely
/// outside `[from, to)`, in left-to-right order — exactly the nodes §10.4's generation emits.
fn outside_subtrees(offset: u64, size: u64, from: u64, to: u64, out: &mut Vec<(u64, u64)>) {
    match classify(offset, size, from, to) {
        Span::Outside => out.push((offset, size)),
        Span::Inside => {}
        Span::Straddles => {
            let k = largest_power_of_2_less_than(size);
            outside_subtrees(offset, k, from, to, out);
            outside_subtrees(offset.saturating_add(k), size.saturating_sub(k), from, to, out);
        }
    }
}

/// Build a range response for `[from_index, to_index)` under `checkpoint`, reading entry bytes
/// for that window and for nothing else.
///
/// Before returning, this function verifies its own output: it opens the checkpoint's root
/// through the store's tree material and confirms the freshly generated proof actually
/// verifies against it over the window's leaf hashes. A mismatch is reported as
/// [`MirrorError::CheckpointRootMismatch`] rather than served — this deployment does not hand
/// out a proof it cannot itself verify.
///
/// # Errors
///
/// [`MirrorError::IncompleteEntries`] if the store does not reach `checkpoint.tree_size`,
/// [`MirrorError::InvalidRange`], [`MirrorError::CheckpointRootMismatch`], or an underlying
/// storage/parsing error.
pub fn build_range_response(
    store: &Store,
    checkpoint: &Checkpoint,
    from_index: u64,
    to_index: u64,
) -> MirrorResult<RangeResponse> {
    build_range_response_measured(store, checkpoint, from_index, to_index).map(|(r, _)| r)
}

/// [`build_range_response`], additionally reporting what it read (see [`RangeReadCost`]).
///
/// # Errors
///
/// As [`build_range_response`].
pub fn build_range_response_measured(
    store: &Store,
    checkpoint: &Checkpoint,
    from_index: u64,
    to_index: u64,
) -> MirrorResult<(RangeResponse, RangeReadCost)> {
    store.with_conn(|conn| build_range_response_in(conn, checkpoint, from_index, to_index))
}

/// The `&Connection` core of [`build_range_response_measured`], so every read below happens
/// under one acquisition of the store's lock and sees one consistent state.
fn build_range_response_in(
    conn: &Connection,
    checkpoint: &Checkpoint,
    from_index: u64,
    to_index: u64,
) -> MirrorResult<(RangeResponse, RangeReadCost)> {
    let have = crate::store::count_entries_raw(conn, 0, checkpoint.tree_size)?;
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

    let root: Hash = ahl_core::parse_hash_hex(&checkpoint.root_hash)?;
    let mut tree_nodes: u64 = 0;
    let mut open = |offset: u64, size: u64| -> MirrorResult<Hash> {
        // Every complete power-of-two subtree of the span is one stored node, and the right
        // spine folds `O(log size)` of them; counting `size` would over-report, counting one
        // would under-report, so count what the geometry actually costs.
        tree_nodes = tree_nodes.saturating_add(u64::from(size.count_ones()));
        crate::store::subtree_root_raw(conn, offset, size)
    };

    if open(0, checkpoint.tree_size)? != root {
        return Err(MirrorError::CheckpointRootMismatch { tree_size: checkpoint.tree_size });
    }

    let mut spans = Vec::new();
    outside_subtrees(0, checkpoint.tree_size, from_index, to_index, &mut spans);
    let mut nodes = Vec::with_capacity(spans.len());
    for (offset, size) in spans {
        nodes.push(open(offset, size)?);
    }
    let proof = RangeProof { tree_size: checkpoint.tree_size, from_index, to_index, nodes };

    let window_leaves = crate::store::leaf_hashes_range_raw(conn, from_index, to_index)?;
    tree_nodes = tree_nodes.saturating_add(
        u64::try_from(window_leaves.len())
            .map_err(|_| MirrorError::IndexOverflow { what: "window width" })?,
    );
    if !range_proof::verify(&proof, &window_leaves, &root)? {
        // Generation and the checkpoint root both checked out individually; a proof that
        // still fails to verify indicates a defect in this crate, not bad input. Surfaced
        // the same way as a storage integrity fault: never served.
        return Err(MirrorError::CheckpointRootMismatch { tree_size: checkpoint.tree_size });
    }

    let window = crate::store::get_entries_range_raw(conn, from_index, to_index)?;
    let mut entry_bytes: u64 = 0;
    let entries = window
        .iter()
        .enumerate()
        .map(|(offset, bytes)| -> MirrorResult<EnumeratedEntry> {
            entry_bytes = entry_bytes.saturating_add(
                u64::try_from(bytes.len())
                    .map_err(|_| MirrorError::IndexOverflow { what: "entry length" })?,
            );
            let offset = u64::try_from(offset)
                .map_err(|_| MirrorError::IndexOverflow { what: "range offset" })?;
            let entry_index = from_index
                .checked_add(offset)
                .ok_or(MirrorError::IndexOverflow { what: "entry_index" })?;
            let envelope: serde_json::Value = serde_json::from_slice(bytes)?;
            Ok(EnumeratedEntry { entry_index, envelope })
        })
        .collect::<MirrorResult<Vec<_>>>()?;

    Ok((
        RangeResponse {
            range: RangeEnvelope { from_index, to_index },
            entries,
            range_proof: RangeProofWire { adaptor_form: range_proof::encode(&proof) },
            checkpoint: checkpoint.clone(),
        },
        RangeReadCost { entry_bytes, tree_nodes },
    ))
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

/// The full-prefix range builder this module replaced, kept as a TEST ORACLE.
///
/// It hashes every entry of `[0, tree_size)` and hands the whole leaf sequence to
/// `ahl_core::range_proof::generate`, which is the reference construction of adaptor profile
/// §10.4. `tests::the_windowed_builder_agrees_with_a_full_prefix_build` holds the windowed
/// builder's output against it byte for byte, so a divergence in node choice, node order or
/// any other member is a test failure rather than something a reader has to take on trust.
#[cfg(test)]
fn build_range_response_from_prefix(
    checkpoint: &Checkpoint,
    from_index: u64,
    to_index: u64,
    all_entries: &[Vec<u8>],
) -> MirrorResult<RangeResponse> {
    use atl_core::core::merkle::compute_root;

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
    let out_of_range =
        || MirrorError::InvalidRange { from_index, to_index, tree_size: checkpoint.tree_size };
    let span = leaf_hashes.get(from..to).ok_or_else(out_of_range)?;
    if !range_proof::verify(&proof, span, &root)? {
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

#[cfg(test)]
mod tests {
    use atl_core::core::merkle::compute_root;

    use super::*;

    fn entry(n: u64) -> Vec<u8> {
        ahl_core::jcs(&serde_json::json!({
            "payload": { "n": n },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }))
    }

    fn checkpoint_over(entries: &[Vec<u8>]) -> Checkpoint {
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

    /// A store holding `count` canonical entries, and the entry bytes themselves.
    fn store_over(count: u64) -> (Store, Vec<Vec<u8>>) {
        let store = Store::open_in_memory().expect("in-memory store");
        let mut entries = Vec::new();
        for index in 0..count {
            let bytes = entry(index);
            let id = ahl_core::sha256_hex(&bytes);
            store.stage_entry(&id, &bytes).expect("stage");
            store.promote_entry(index, &id).expect("promote");
            entries.push(bytes);
        }
        (store, entries)
    }

    #[test]
    fn a_full_range_response_round_trips_through_generate_serialize_deserialize_verify() {
        let (store, entries) = store_over(12);
        let checkpoint = checkpoint_over(&entries);

        let response = build_range_response(&store, &checkpoint, 3, 9).expect("valid sub-range");
        let wire = serde_json::to_vec(&response).expect("serialize");
        let round_tripped: RangeResponse = serde_json::from_slice(&wire).expect("deserialize");

        assert_eq!(round_tripped.entries.len(), 6);
        assert!(verify_range_response(&round_tripped).expect("well-formed"));
    }

    #[test]
    fn the_full_range_needs_no_subtree_hashes_and_still_verifies() {
        let (store, entries) = store_over(5);
        let checkpoint = checkpoint_over(&entries);
        let response = build_range_response(&store, &checkpoint, 0, 5).expect("full range");
        assert!(verify_range_response(&response).expect("well-formed"));
        assert_eq!(
            range_proof::decode(&response.range_proof.adaptor_form).expect("decode").nodes.len(),
            0
        );
    }

    #[test]
    fn an_incomplete_prefix_is_rejected_before_any_proof_is_built() {
        let (store, entries) = store_over(10);
        // A checkpoint claiming twelve entries over a store holding ten.
        let mut checkpoint = checkpoint_over(&entries);
        checkpoint.tree_size = 12;
        assert!(matches!(
            build_range_response(&store, &checkpoint, 0, 5),
            Err(MirrorError::IncompleteEntries { have: 10, need: 12 })
        ));
    }

    #[test]
    fn an_out_of_bounds_range_is_rejected() {
        let (store, entries) = store_over(5);
        let checkpoint = checkpoint_over(&entries);
        assert!(matches!(
            build_range_response(&store, &checkpoint, 3, 3),
            Err(MirrorError::InvalidRange { .. })
        ));
        assert!(matches!(
            build_range_response(&store, &checkpoint, 0, 6),
            Err(MirrorError::InvalidRange { .. })
        ));
    }

    #[test]
    fn a_checkpoint_whose_root_disagrees_with_the_entries_is_rejected() {
        let (store, entries) = store_over(5);
        let mut checkpoint = checkpoint_over(&entries);
        checkpoint.root_hash = format!("sha256:{}", "00".repeat(32));
        assert!(matches!(
            build_range_response(&store, &checkpoint, 0, 5),
            Err(MirrorError::CheckpointRootMismatch { .. })
        ));
    }

    #[test]
    fn a_reordered_response_does_not_verify() {
        let (store, entries) = store_over(6);
        let checkpoint = checkpoint_over(&entries);
        let mut response = build_range_response(&store, &checkpoint, 1, 5).expect("valid");
        response.entries.swap(0, 1);
        // Swapping breaks the entry_index/offset contract before the proof is even consulted.
        assert!(matches!(verify_range_response(&response), Err(MirrorError::InvalidRange { .. })));
    }

    #[test]
    fn a_substituted_entry_fails_verification_without_erroring() {
        let (store, entries) = store_over(6);
        let checkpoint = checkpoint_over(&entries);
        let mut response = build_range_response(&store, &checkpoint, 1, 5).expect("valid");
        let substituted: serde_json::Value =
            serde_json::from_slice(&entry(99)).expect("well-formed test fixture");
        response.entries[0].envelope = substituted;
        assert!(!verify_range_response(&response).expect("well-formed proof"));
    }

    /// A cache row missing behind the store's back is refused by name, not answered by
    /// recomputing that subtree from leaf hashes: the window promise is `O(window + log n)`
    /// reads, and a silent fold over `[0, 8)` would break it on material the deployment can
    /// no longer vouch for. Reopening the store rebuilds the cache and restores service.
    #[test]
    fn a_missing_cache_node_is_refused_rather_than_recomputed() {
        let (store, entries) = store_over(9);
        let checkpoint = checkpoint_over(&entries);
        store
            .with_conn(|conn| {
                conn.execute("DELETE FROM subtree_roots WHERE level = 3", [])
                    .map(|_| ())
                    .map_err(MirrorError::from)
            })
            .expect("drop one cached node behind the store's back");

        assert!(matches!(
            build_range_response(&store, &checkpoint, 0, 3),
            Err(MirrorError::TreeMaterialMissing { level: 3, node_index: 0 })
        ));
    }

    /// The windowed builder and the full-prefix oracle MUST produce the same bytes, for every
    /// window of every tree shape — the same proof nodes in the same order, the same entries,
    /// the same checkpoint. Tree sizes 1..=33 cover every ragged right spine a log can have at
    /// small scale (powers of two, one either side of them, and the odd sizes between), and the
    /// windows are every non-empty sub-range of each.
    #[test]
    fn the_windowed_builder_agrees_with_a_full_prefix_build() {
        for size in 1..=33u64 {
            let (store, entries) = store_over(size);
            let checkpoint = checkpoint_over(&entries);
            for from in 0..size {
                for to in (from + 1)..=size {
                    let windowed =
                        build_range_response(&store, &checkpoint, from, to).expect("windowed");
                    let oracle = build_range_response_from_prefix(&checkpoint, from, to, &entries)
                        .expect("oracle");
                    assert_eq!(
                        serde_json::to_vec(&windowed).expect("serialize windowed"),
                        serde_json::to_vec(&oracle).expect("serialize oracle"),
                        "tree_size {size}, window [{from}, {to})"
                    );
                }
            }
        }
    }

    /// The measurement adaptor profile §10.3 makes worth stating: a ten-entry window over a
    /// ten-thousand-entry log reads the ten envelopes and nothing else.
    ///
    /// The full-prefix build is what the same request cost before, and is measured here in the
    /// same run rather than quoted, so the comparison is of two numbers this test produced.
    #[test]
    fn a_ten_entry_window_over_a_ten_thousand_entry_log_reads_only_the_window() {
        const LOG: u64 = 10_000;
        let (store, entries) = store_over(LOG);
        let checkpoint = checkpoint_over(&entries);

        let (response, cost) =
            build_range_response_measured(&store, &checkpoint, 5_000, 5_010).expect("valid window");
        assert!(verify_range_response(&response).expect("well-formed"));

        let window_bytes: u64 = entries[5_000..5_010].iter().map(|b| b.len() as u64).sum();
        assert_eq!(cost.entry_bytes, window_bytes, "entry bytes read are exactly the window's");

        // What the full-prefix build read for the same request: every entry in `[0, 10_000)`.
        let full_prefix_bytes: u64 = entries.iter().map(|b| b.len() as u64).sum();
        assert!(
            cost.total_bytes() * 50 < full_prefix_bytes,
            "windowed build read {} bytes; the full-prefix build read {full_prefix_bytes}",
            cost.total_bytes()
        );

        // Recorded so the report quotes numbers this test produced rather than an estimate.
        println!(
            "range read cost, 10-entry window over a {LOG}-entry log: \
             before {full_prefix_bytes} bytes (entry bytes for the whole prefix), \
             after {} bytes ({} entry bytes + {} tree nodes x 32)",
            cost.total_bytes(),
            cost.entry_bytes,
            cost.tree_nodes
        );
    }
}
