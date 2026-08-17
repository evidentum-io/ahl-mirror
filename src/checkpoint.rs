//! Checkpoints, the canonical checkpoint series, and `ITUB` (adaptor profile §5.2, §6).

use atl_core::core::merkle::{compute_root, generate_consistency_proof, verify_consistency, Hash};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::config::Config;
use crate::error::{MirrorError, MirrorResult};
use crate::metadata::log_leaf_hash;
use crate::store::Store;

/// ATL's fixed 98-byte checkpoint magic (adaptor profile §6.1).
const CHECKPOINT_MAGIC: &[u8; 18] = b"ATL-Protocol-v1-CP";

/// The 98-byte signed checkpoint blob layout (adaptor profile §6.1).
const CHECKPOINT_BLOB_LEN: usize = 98;

/// A signed AHL checkpoint object (adaptor profile §6.2), field for field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// `"sha256:" || hex(Origin ID)`.
    pub log_id: String,
    /// Number of entries this checkpoint commits, `[0, tree_size)`.
    pub tree_size: u64,
    /// `"sha256:" || hex(root)`.
    pub root_hash: String,
    /// The exact nine-fractional-digit RFC 3339 rendering of §6.3.
    pub checkpoint_time: String,
    /// `"sha256:" || hex(SHA-256(raw pubkey))` of the signing key.
    pub key_id: String,
    /// `"base64:" || base64(raw 64-byte Ed25519 signature)`.
    pub signature: String,
}

/// One staged entry to promote atomically alongside checkpoint admission.
///
/// Carries a Merkle inclusion proof of its log leaf under the checkpoint being admitted
/// (adaptor profile §8.2). See [`ingest_checkpoint`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPromotion {
    /// The staged entry's id.
    pub entry_id: String,
    /// Its claimed position — becomes its canonical `entry_index` if the proof verifies.
    pub leaf_index: u64,
    /// The inclusion proof path, leaf to root, as `sha256:<hex>` strings (adaptor profile
    /// §8.2).
    pub inclusion_path: Vec<String>,
}

const CHECKPOINT_TIME_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:9]Z");

/// Render a unix-nanosecond value in the exact form adaptor profile §6.3 requires.
///
/// # Errors
///
/// Returns [`MirrorError::BadCheckpointTime`] if `nanos` is outside the range a calendar
/// date can represent (it never is, for any value a real checkpoint carries).
pub fn render_checkpoint_time(nanos: u64) -> MirrorResult<String> {
    let dt = OffsetDateTime::from_unix_timestamp_nanos(i128::from(nanos))
        .map_err(|_| MirrorError::BadCheckpointTime { value: nanos.to_string() })?;
    dt.format(CHECKPOINT_TIME_FORMAT)
        .map_err(|_| MirrorError::BadCheckpointTime { value: nanos.to_string() })
}

/// Parse `checkpoint_time` to its exact unix-nanosecond value.
///
/// Rejects anything that is not exactly the rendering adaptor profile §6.3 specifies —
/// including a value that parses but whose canonical re-rendering differs from the input
/// (millisecond truncation, dropped trailing zeros, a non-`Z` offset spelled some other
/// way), which is the failure mode §6.3 calls out explicitly.
///
/// # Errors
///
/// Returns [`MirrorError::BadCheckpointTime`] if `value` does not parse, or does not
/// round-trip back to itself.
pub fn parse_checkpoint_time(value: &str) -> MirrorResult<u64> {
    let bad = || MirrorError::BadCheckpointTime { value: value.to_owned() };
    let parsed = PrimitiveDateTime::parse(value, CHECKPOINT_TIME_FORMAT).map_err(|_| bad())?;
    let nanos = parsed.assume_utc().unix_timestamp_nanos();
    let nanos = u64::try_from(nanos).map_err(|_| bad())?;
    if render_checkpoint_time(nanos)? != value {
        return Err(bad());
    }
    Ok(nanos)
}

/// Assemble the 98-byte signed blob for `cp` (adaptor profile §6.1).
///
/// # Errors
///
/// Returns [`MirrorError::Ahl`] if `log_id` or `root_hash` are not well-formed
/// `sha256:<hex>` family strings, or [`MirrorError::BadCheckpointTime`] if
/// `checkpoint_time` is not the exact form §6.3 requires.
pub fn checkpoint_blob(cp: &Checkpoint) -> MirrorResult<[u8; CHECKPOINT_BLOB_LEN]> {
    let origin: Hash = ahl_core::parse_hash_hex(&cp.log_id)?;
    let root: Hash = ahl_core::parse_hash_hex(&cp.root_hash)?;
    let nanos = parse_checkpoint_time(&cp.checkpoint_time)?;

    let mut blob = [0u8; CHECKPOINT_BLOB_LEN];
    blob[0..18].copy_from_slice(CHECKPOINT_MAGIC);
    blob[18..50].copy_from_slice(&origin);
    blob[50..58].copy_from_slice(&cp.tree_size.to_le_bytes());
    blob[58..66].copy_from_slice(&nanos.to_le_bytes());
    blob[66..98].copy_from_slice(&root);
    Ok(blob)
}

/// Verify `cp`'s identity and signature against a specific, already-resolved key (adaptor
/// profile §6.5, steps 1-5).
///
/// This function performs no key *resolution* — see [`crate::manifest::resolve`] for that —
/// and no series-level checks (ordering, consistency, completeness); see
/// [`ingest_checkpoint`] for the full admission pipeline.
///
/// If `raw` is given, it is checked byte for byte against the assembled blob first (§6.4).
///
/// # Errors
///
/// [`MirrorError::WrongLogId`], [`MirrorError::RawBlobMismatch`],
/// [`MirrorError::SignatureInvalid`], or a parsing error from [`checkpoint_blob`].
pub fn verify_checkpoint_signature(
    cp: &Checkpoint,
    raw: Option<&[u8]>,
    log_id: &str,
    key: &VerifyingKey,
) -> MirrorResult<()> {
    if cp.log_id != log_id {
        return Err(MirrorError::WrongLogId {
            expected: log_id.to_owned(),
            got: cp.log_id.clone(),
        });
    }
    let blob = checkpoint_blob(cp)?;
    if let Some(raw) = raw {
        if raw != blob {
            return Err(MirrorError::RawBlobMismatch);
        }
    }
    if !ahl_core::verify_signature(key, &blob, &cp.signature)? {
        return Err(MirrorError::SignatureInvalid { key_id: cp.key_id.clone() });
    }
    Ok(())
}

/// Verify that `to_cp` is consistent with `from_cp`.
///
/// That is: `from_cp` is exactly the size-`from_cp.tree_size` prefix of the tree `to_cp`
/// commits, given the leaf hashes covering `[0, to_cp.tree_size)` (adaptor profile §5.2.2
/// item 1; core spec §3 contract item 3). `from_cp.tree_size` MUST be less than
/// `to_cp.tree_size` — this checks extension in one direction only; callers with two
/// checkpoints in unknown order MUST establish which is smaller first.
///
/// # Errors
///
/// A parsing error if either root is malformed, or [`MirrorError::Atl`] if the consistency
/// proof cannot be generated from the supplied leaves.
pub fn verify_series_consistency(
    from_cp: &Checkpoint,
    to_cp: &Checkpoint,
    leaf_hashes: &[Hash],
) -> MirrorResult<bool> {
    let from_root: Hash = ahl_core::parse_hash_hex(&from_cp.root_hash)?;
    let to_root: Hash = ahl_core::parse_hash_hex(&to_cp.root_hash)?;
    let proof = generate_consistency_proof(from_cp.tree_size, to_cp.tree_size, |level, index| {
        if level == 0 {
            leaf_hashes.get(usize::try_from(index).ok()?).copied()
        } else {
            None
        }
    })?;
    Ok(verify_consistency(&proof, &from_root, &to_root)?)
}

/// Fetch the complete, contiguous log-leaf-hash sequence for `[0, tree_size)`, or report how
/// far short the store is.
fn leaf_hashes_for(store: &Store, tree_size: u64) -> MirrorResult<Vec<Hash>> {
    let entries = store.get_entries_range(0, tree_size)?;
    let have = u64::try_from(entries.len())
        .map_err(|_| MirrorError::IndexOverflow { what: "entries.len()" })?;
    if have != tree_size {
        return Err(MirrorError::IncompleteEntries { have, need: tree_size });
    }
    Ok(entries.iter().map(|bytes| log_leaf_hash(bytes)).collect())
}

/// Verify and admit `cp` into the canonical checkpoint series (adaptor profile §5.2.2).
///
/// The pipeline, in order:
///
/// 1. Resolve the checkpoint-signing key via [`crate::manifest::resolve`], using **only**
///    entries already canonical before this call — never `entries_to_promote`, which are not
///    yet trusted at this point. A checkpoint can therefore never validate itself by way of
///    governance material it is simultaneously trying to introduce.
/// 2. Verify the signature against that key (adaptor profile §6.5). Only once this passes is
///    `cp.root_hash` treated as authenticated — a checkpoint's admission to the series rests
///    on this alone, not on entry availability (see below).
/// 3. Promote every entry in `entries_to_promote`, each checked by Merkle inclusion proof
///    against the now-authenticated root (adaptor profile §8.2) — the "or admitted in the
///    same operation" half of retrieval/enumeration's evidence requirement.
/// 4. **Opportunistically**, if `[0, cp.tree_size)` happens to be complete after step 3 (via
///    `entries_to_promote` just now, or already, via earlier standalone
///    [`crate::ingest::promote_entry`] calls against a checkpoint admitted previously): check
///    it recomputes to `cp.root_hash`, and check consistency against **both** series
///    neighbours that already exist — predecessor and successor by `tree_size`, so a
///    checkpoint backfilled between two admitted members is checked against both sides
///    (adaptor profile §5.2.2 item 1). If the range is *not* yet complete, these checks are
///    skipped rather than blocking admission — checkpoints and entry bytes routinely arrive
///    on different schedules (adaptor profile §10.1 discusses exactly this split), and
///    entry-level correctness is never weakened by skipping them here: no entry is ever
///    promoted without its own inclusion proof verifying, regardless of whether this
///    opportunistic check ran.
/// 5. Insert `cp` into the series (any `tree_size` order is accepted; see
///    [`crate::store::Store::insert_checkpoint`]).
///
/// # Errors
///
/// Any [`MirrorError`] from the steps above. Governance material this mirror has not yet
/// seen never causes a distinct "unresolvable" error — resolution against a stale key set
/// fails naturally via [`MirrorError::UnknownSigningKey`]; see the `manifest` module for why
/// that is safe. [`MirrorError::KeyNotYetActive`], [`MirrorError::InclusionProofInvalid`],
/// [`MirrorError::CheckpointRootMismatch`] and [`MirrorError::InconsistentWithNeighbour`] are
/// all live outcomes.
pub fn ingest_checkpoint(
    store: &Store,
    config: &Config,
    cp: &Checkpoint,
    raw: Option<&[u8]>,
    entries_to_promote: &[PendingPromotion],
) -> MirrorResult<()> {
    let snapshot = crate::manifest::resolve(store, config, cp.tree_size)?;
    let key = snapshot.resolve_key(&cp.key_id, cp.tree_size)?;
    verify_checkpoint_signature(cp, raw, &config.log_id, key)?;

    for pending in entries_to_promote {
        crate::ingest::promote_entry(
            store,
            cp,
            &pending.entry_id,
            pending.leaf_index,
            &pending.inclusion_path,
        )?;
    }

    if let Ok(leaf_hashes) = leaf_hashes_for(store, cp.tree_size) {
        let root: Hash = ahl_core::parse_hash_hex(&cp.root_hash)?;
        if compute_root(&leaf_hashes) != root {
            return Err(MirrorError::CheckpointRootMismatch { tree_size: cp.tree_size });
        }

        let crate::store::Neighbours { predecessor, successor } = store.neighbours(cp.tree_size)?;
        if let Some(predecessor) = predecessor {
            if !verify_series_consistency(&predecessor, cp, &leaf_hashes)? {
                return Err(MirrorError::InconsistentWithNeighbour {
                    neighbour_tree_size: predecessor.tree_size,
                    tree_size: cp.tree_size,
                });
            }
        }
        if let Some(successor) = successor {
            if let Ok(successor_leaves) = leaf_hashes_for(store, successor.tree_size) {
                if !verify_series_consistency(cp, &successor, &successor_leaves)? {
                    return Err(MirrorError::InconsistentWithNeighbour {
                        neighbour_tree_size: successor.tree_size,
                        tree_size: cp.tree_size,
                    });
                }
            }
        }
    }

    store.insert_checkpoint(cp)?;
    Ok(())
}

/// The `tree_size` up to and including which `series` is proven gap-free.
///
/// "Gap-free" at `cadence_seconds` (adaptor profile §5.2.2) means: every adjacent pair of
/// members, by `tree_size`, is no further apart in `checkpoint_time` than the declared
/// cadence. `series` MUST already be ascending by `tree_size`.
///
/// Returns `None` if `cadence_seconds` is `None` (cadence itself undeclared) or `series` is
/// empty — in either case nothing can be proven gap-free.
///
/// # Errors
///
/// Propagates a [`MirrorError::BadCheckpointTime`] if any member's `checkpoint_time` is
/// malformed (should not occur for admitted members, which are checked at admission time).
pub fn gap_free_frontier(
    series: &[Checkpoint],
    cadence_seconds: Option<u64>,
) -> MirrorResult<Option<u64>> {
    let Some(cadence_seconds) = cadence_seconds else { return Ok(None) };
    let Some(first) = series.first() else { return Ok(None) };

    let cadence_nanos = cadence_seconds.saturating_mul(1_000_000_000);
    let mut frontier = first.tree_size;
    let mut previous_nanos = parse_checkpoint_time(&first.checkpoint_time)?;

    for cp in &series[1..] {
        let nanos = parse_checkpoint_time(&cp.checkpoint_time)?;
        if nanos.saturating_sub(previous_nanos) > cadence_nanos {
            break;
        }
        frontier = cp.tree_size;
        previous_nanos = nanos;
    }

    Ok(Some(frontier))
}

/// `ITUB(index)`: the checkpoint carrying the time the profile allows treating as `index`'s
/// incorporation-time upper bound.
///
/// That checkpoint is the smallest-`tree_size` series member with `tree_size > index`
/// (adaptor profile §5.2.1) — but returned **only** if the series is proven gap-free, per
/// [`gap_free_frontier`], up to and including that member. `series` MUST already be
/// ascending by `tree_size`.
///
/// Returns `None` — unavailable, never a computed value — if no covering member exists, or
/// if the series is not proven gap-free that far. Adaptor profile §5.2.2 states `ITUB` is
/// undefined without a canonical (complete) checkpoint series, and pairwise consistency
/// between the members this mirror happens to hold does not establish completeness: it
/// proves each pair is a valid extension of the other, never that nothing was omitted
/// between them.
///
/// # Errors
///
/// Propagates a [`MirrorError`] from [`gap_free_frontier`].
pub fn itub(
    series: &[Checkpoint],
    index: u64,
    cadence_seconds: Option<u64>,
) -> MirrorResult<Option<&Checkpoint>> {
    let Some(frontier) = gap_free_frontier(series, cadence_seconds)? else { return Ok(None) };
    Ok(series.iter().find(|cp| cp.tree_size > index && cp.tree_size <= frontier))
}

#[cfg(test)]
mod tests {
    use sha2::Digest as _;

    use super::*;
    use crate::config::{ConfigSpec, TrustedLogKeySpec};

    fn signed_checkpoint(
        key: &ahl_core::TestKey,
        log_id: &str,
        tree_size: u64,
        root_hash: &str,
        checkpoint_time: &str,
    ) -> Checkpoint {
        let mut cp = Checkpoint {
            log_id: log_id.to_owned(),
            tree_size,
            root_hash: root_hash.to_owned(),
            checkpoint_time: checkpoint_time.to_owned(),
            key_id: key.key_id(),
            signature: String::new(),
        };
        let blob = checkpoint_blob(&cp).expect("well-formed fields");
        cp.signature = key.sign(&blob);
        cp
    }

    #[test]
    fn checkpoint_time_matches_the_profile_worked_example() {
        // Adaptor profile §6.3: 1767225600123456789 -> "2026-01-01T00:00:00.123456789Z".
        let nanos = 1_767_225_600_123_456_789u64;
        let rendered = render_checkpoint_time(nanos).expect("in-range value");
        assert_eq!(rendered, "2026-01-01T00:00:00.123456789Z");
        assert_eq!(parse_checkpoint_time(&rendered).expect("well-formed"), nanos);
    }

    #[test]
    fn checkpoint_time_round_trips_at_the_epoch_and_with_trailing_zeros() {
        assert_eq!(render_checkpoint_time(0).expect("epoch"), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(parse_checkpoint_time("1970-01-01T00:00:00.000000000Z").expect("epoch"), 0);
    }

    #[test]
    fn truncated_or_malformed_checkpoint_times_are_rejected() {
        assert!(parse_checkpoint_time("2026-01-01T00:00:00.123Z").is_err());
        assert!(parse_checkpoint_time("2026-01-01T00:00:00Z").is_err());
        assert!(parse_checkpoint_time("not-a-time").is_err());
    }

    #[test]
    fn blob_assembly_matches_the_documented_layout() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"01".repeat(32)).expect("seed");
        let cp = signed_checkpoint(
            &key,
            &format!("sha256:{}", "22".repeat(32)),
            10,
            &format!("sha256:{}", "33".repeat(32)),
            "2026-01-01T00:00:00.000000000Z",
        );
        let blob = checkpoint_blob(&cp).expect("well-formed");
        assert_eq!(&blob[0..18], CHECKPOINT_MAGIC);
        assert_eq!(&blob[18..50], [0x22u8; 32]);
        assert_eq!(&blob[50..58], 10u64.to_le_bytes());
        assert_eq!(&blob[66..98], [0x33u8; 32]);
    }

    fn config_with(key: &ahl_core::TestKey, log_id: &str) -> Config {
        Config::resolve(&ConfigSpec {
            log_id: log_id.to_owned(),
            keys: vec![TrustedLogKeySpec {
                key_id: key.key_id(),
                pubkey: key.pubkey(),
                valid_from_index: 0,
            }],
            genesis_manifest_entry_id: None,
            genesis_checkpoint_cadence_seconds: Some(300),
            store_path: ":memory:".to_owned(),
        })
        .expect("valid config")
    }

    #[test]
    fn a_correctly_signed_checkpoint_verifies() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"04".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "55".repeat(32));
        let cp = signed_checkpoint(
            &key,
            &log_id,
            10,
            &format!("sha256:{}", "66".repeat(32)),
            "2026-01-01T00:00:00.000000000Z",
        );
        verify_checkpoint_signature(&cp, None, &log_id, &key.verifying_key())
            .expect("valid signature and log_id");
    }

    #[test]
    fn a_wrong_log_id_is_rejected() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"05".repeat(32)).expect("seed");
        let cp = signed_checkpoint(
            &key,
            &format!("sha256:{}", "aa".repeat(32)),
            10,
            &format!("sha256:{}", "bb".repeat(32)),
            "2026-01-01T00:00:00.000000000Z",
        );
        let other_log_id = format!("sha256:{}", "cc".repeat(32));
        assert!(matches!(
            verify_checkpoint_signature(&cp, None, &other_log_id, &key.verifying_key()),
            Err(MirrorError::WrongLogId { .. })
        ));
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"08".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "ff".repeat(32));
        let mut cp = signed_checkpoint(
            &key,
            &log_id,
            10,
            &format!("sha256:{}", "11".repeat(32)),
            "2026-01-01T00:00:00.000000000Z",
        );
        cp.tree_size = 11; // mutate a signed field without re-signing
        assert!(matches!(
            verify_checkpoint_signature(&cp, None, &log_id, &key.verifying_key()),
            Err(MirrorError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn a_mismatched_raw_blob_is_rejected() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"09".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "12".repeat(32));
        let cp = signed_checkpoint(
            &key,
            &log_id,
            10,
            &format!("sha256:{}", "13".repeat(32)),
            "2026-01-01T00:00:00.000000000Z",
        );
        let bad_raw = [0u8; CHECKPOINT_BLOB_LEN];
        assert!(matches!(
            verify_checkpoint_signature(&cp, Some(&bad_raw), &log_id, &key.verifying_key()),
            Err(MirrorError::RawBlobMismatch)
        ));
    }

    #[test]
    fn a_checkpoint_signed_by_a_key_below_its_activation_bound_is_rejected() {
        // The "checkpoint signed by a key outside its validity range" required negative
        // test, exercised at the genesis-key path: the key exists and the signature is
        // mathematically valid, but it is not yet active for this tree_size.
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"0d".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "17".repeat(32));
        let config = Config::resolve(&ConfigSpec {
            log_id: log_id.clone(),
            keys: vec![TrustedLogKeySpec {
                key_id: key.key_id(),
                pubkey: key.pubkey(),
                valid_from_index: 100,
            }],
            genesis_manifest_entry_id: None,
            genesis_checkpoint_cadence_seconds: None,
            store_path: ":memory:".to_owned(),
        })
        .expect("valid config");
        let store = Store::open_in_memory().expect("in-memory store");
        let cp = signed_checkpoint(
            &key,
            &log_id,
            10,
            &format!("sha256:{}", "18".repeat(32)),
            "2026-01-01T00:00:00.000000000Z",
        );
        assert!(matches!(
            ingest_checkpoint(&store, &config, &cp, None, &[]),
            Err(MirrorError::KeyNotYetActive { valid_from_index: 100, tree_size: 10, .. })
        ));
        assert!(store.latest_checkpoint().expect("query").is_none());
    }

    #[test]
    fn itub_picks_the_smallest_covering_checkpoint_when_the_series_is_gap_free() {
        let series = vec![
            Checkpoint {
                log_id: "sha256:aa".to_owned(),
                tree_size: 5,
                root_hash: "sha256:aa".to_owned(),
                checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
                key_id: "sha256:aa".to_owned(),
                signature: "base64:AAAA".to_owned(),
            },
            Checkpoint {
                log_id: "sha256:aa".to_owned(),
                tree_size: 10,
                root_hash: "sha256:bb".to_owned(),
                checkpoint_time: "2026-01-01T00:04:00.000000000Z".to_owned(),
                key_id: "sha256:aa".to_owned(),
                signature: "base64:AAAA".to_owned(),
            },
        ];
        let cadence = Some(300); // 5 minutes; the two members are 4 minutes apart.
        assert_eq!(itub(&series, 3, cadence).expect("well-formed").expect("covered").tree_size, 5);
        assert_eq!(itub(&series, 5, cadence).expect("well-formed").expect("covered").tree_size, 10);
        assert_eq!(itub(&series, 9, cadence).expect("well-formed").expect("covered").tree_size, 10);
        assert!(itub(&series, 10, cadence).expect("well-formed").is_none());
    }

    #[test]
    fn itub_is_unavailable_across_an_undetected_time_gap() {
        // Two checkpoints that are individually perfectly well-formed, and mutually
        // consistent (each is a real prefix of the other's tree) — but the second arrives
        // far later than the declared cadence allows, meaning checkpoints the cadence
        // implies should exist in between were never shown to this mirror. Pairwise
        // consistency cannot detect that; only the cadence check can.
        let series = vec![
            Checkpoint {
                log_id: "sha256:aa".to_owned(),
                tree_size: 4,
                root_hash: "sha256:aa".to_owned(),
                checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
                key_id: "sha256:aa".to_owned(),
                signature: "base64:AAAA".to_owned(),
            },
            Checkpoint {
                log_id: "sha256:aa".to_owned(),
                tree_size: 9,
                root_hash: "sha256:bb".to_owned(),
                checkpoint_time: "2026-01-01T03:00:00.000000000Z".to_owned(), // 3 hours later
                key_id: "sha256:aa".to_owned(),
                signature: "base64:AAAA".to_owned(),
            },
        ];
        let cadence = Some(300); // 5 minutes — the 3-hour jump is a gap.
        assert_eq!(gap_free_frontier(&series, cadence).expect("well-formed"), Some(4));
        assert_eq!(itub(&series, 5, cadence).expect("well-formed"), None);
        assert_eq!(itub(&series, 3, cadence).expect("well-formed").expect("covered").tree_size, 4);
    }

    #[test]
    fn itub_is_unavailable_without_a_known_cadence() {
        let series = vec![Checkpoint {
            log_id: "sha256:aa".to_owned(),
            tree_size: 5,
            root_hash: "sha256:aa".to_owned(),
            checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
            key_id: "sha256:aa".to_owned(),
            signature: "base64:AAAA".to_owned(),
        }];
        assert_eq!(itub(&series, 0, None).expect("well-formed"), None);
        assert_eq!(gap_free_frontier(&series, None).expect("well-formed"), None);
        assert_eq!(gap_free_frontier(&[], Some(300)).expect("well-formed"), None);
    }

    #[test]
    fn consistency_holds_for_a_true_prefix_and_fails_for_a_tampered_one() {
        let leaves: Vec<Hash> = (0u8..8).map(|i| ahl_core::leaf_hash(&[i])).collect();
        let root_of = |n: usize| atl_core::core::merkle::compute_root(&leaves[..n]);

        let from_cp = Checkpoint {
            log_id: "sha256:aa".to_owned(),
            tree_size: 4,
            root_hash: format!("sha256:{}", hex::encode(root_of(4))),
            checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
            key_id: "sha256:aa".to_owned(),
            signature: "base64:AAAA".to_owned(),
        };
        let to_cp = Checkpoint {
            tree_size: 8,
            root_hash: format!("sha256:{}", hex::encode(root_of(8))),
            checkpoint_time: "2026-01-02T00:00:00.000000000Z".to_owned(),
            ..from_cp.clone()
        };
        assert!(verify_series_consistency(&from_cp, &to_cp, &leaves).expect("well-formed"));

        let mut tampered = to_cp;
        tampered.root_hash = format!("sha256:{}", "00".repeat(32));
        assert!(!verify_series_consistency(&from_cp, &tampered, &leaves).expect("well-formed"));
    }

    fn stored_entry(n: u8) -> Vec<u8> {
        ahl_core::jcs(&serde_json::json!({
            "payload": { "n": n },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }))
    }

    fn checkpoint_for(key: &ahl_core::TestKey, log_id: &str, entries: &[Vec<u8>]) -> Checkpoint {
        let leaves: Vec<Hash> = entries.iter().map(|b| log_leaf_hash(b)).collect();
        let root = compute_root(&leaves);
        signed_checkpoint(
            key,
            log_id,
            u64::try_from(entries.len()).expect("small test size"),
            &format!("sha256:{}", hex::encode(root)),
            "2026-01-01T00:00:00.000000000Z",
        )
    }

    fn stage_and_promote_from(store: &Store, start_index: u64, entries: &[Vec<u8>]) {
        for (offset, bytes) in entries.iter().enumerate() {
            let id = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
            store.stage_entry(&id, bytes).expect("stage");
            let index = start_index + u64::try_from(offset).expect("small test size");
            store.promote_entry(index, &id).expect("promote");
        }
    }

    fn stage_and_promote_all(store: &Store, entries: &[Vec<u8>]) {
        stage_and_promote_from(store, 0, entries);
    }

    #[test]
    fn a_checkpoint_over_fully_canonical_entries_is_admitted() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"0a".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "14".repeat(32));
        let store = Store::open_in_memory().expect("in-memory store");
        let entries: Vec<Vec<u8>> = (0u8..4).map(stored_entry).collect();
        stage_and_promote_all(&store, &entries);
        let cp = checkpoint_for(&key, &log_id, &entries);
        let config = config_with(&key, &log_id);
        ingest_checkpoint(&store, &config, &cp, None, &[])
            .expect("complete, well-formed checkpoint");
        assert_eq!(store.latest_checkpoint().expect("query").expect("present").tree_size, 4);
    }

    #[test]
    fn a_checkpoint_can_be_admitted_ahead_of_its_own_entries() {
        // A checkpoint's admission to the series rests on its signature, not on this mirror
        // already holding every entry it commits — checkpoints and entry bytes routinely
        // arrive on different schedules (adaptor profile §10.1). Nothing about the entries
        // is trusted here; only the checkpoint's authenticated root enters the series.
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"0b".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "15".repeat(32));
        let store = Store::open_in_memory().expect("in-memory store");
        let all_eight: Vec<Vec<u8>> = (0u8..8).map(stored_entry).collect();
        let cp = checkpoint_for(&key, &log_id, &all_eight);
        let config = config_with(&key, &log_id);
        ingest_checkpoint(&store, &config, &cp, None, &[])
            .expect("valid signature admits the checkpoint regardless of entry lag");
        assert_eq!(store.latest_checkpoint().expect("query").expect("present").tree_size, 8);
        // The entries themselves remain unavailable until proof-verified promotion.
        assert_eq!(store.next_index().expect("query"), 0);
    }

    #[test]
    fn a_checkpoint_whose_available_entries_disagree_with_its_root_is_rejected() {
        // The opportunistic self-check: when the full entry range genuinely is already
        // canonical, an admitted checkpoint's claimed root MUST still recompute from it —
        // catching a validly-signed checkpoint over the wrong root the moment the data to
        // check it against exists.
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"1b".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "1c".repeat(32));
        let store = Store::open_in_memory().expect("in-memory store");
        let entries: Vec<Vec<u8>> = (0u8..4).map(stored_entry).collect();
        stage_and_promote_all(&store, &entries);
        let wrong_root_entries: Vec<Vec<u8>> = (10u8..14).map(stored_entry).collect();
        let cp = checkpoint_for(&key, &log_id, &wrong_root_entries); // same count, different root
        let config = config_with(&key, &log_id);
        assert!(matches!(
            ingest_checkpoint(&store, &config, &cp, None, &[]),
            Err(MirrorError::CheckpointRootMismatch { tree_size: 4 })
        ));
        assert!(store.latest_checkpoint().expect("query").is_none());
    }

    #[test]
    fn a_second_checkpoint_extends_the_series() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"0c".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "16".repeat(32));
        let store = Store::open_in_memory().expect("in-memory store");
        let first: Vec<Vec<u8>> = (0u8..4).map(stored_entry).collect();
        stage_and_promote_all(&store, &first);
        let config = config_with(&key, &log_id);
        let cp1 = checkpoint_for(&key, &log_id, &first);
        ingest_checkpoint(&store, &config, &cp1, None, &[]).expect("first checkpoint");

        let all_nine: Vec<Vec<u8>> = (0u8..9).map(stored_entry).collect();
        stage_and_promote_from(&store, 4, &all_nine[4..]);
        let cp2 = checkpoint_for(&key, &log_id, &all_nine);
        ingest_checkpoint(&store, &config, &cp2, None, &[])
            .expect("second checkpoint extends the series");

        let series = store.checkpoint_series().expect("series");
        assert_eq!(series.iter().map(|c| c.tree_size).collect::<Vec<_>>(), vec![4, 9]);
    }

    #[test]
    fn entries_to_promote_admits_a_checkpoint_and_its_entries_in_one_call() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"0e".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "19".repeat(32));
        let store = Store::open_in_memory().expect("in-memory store");
        let entries: Vec<Vec<u8>> = (0u8..4).map(stored_entry).collect();
        let leaves: Vec<Hash> = entries.iter().map(|b| log_leaf_hash(b)).collect();

        let tree_size = u64::try_from(leaves.len()).expect("small test size");
        let mut pending = Vec::new();
        for (i, bytes) in entries.iter().enumerate() {
            let id = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
            store.stage_entry(&id, bytes).expect("stage");
            let index = u64::try_from(i).expect("small test size");
            let proof =
                atl_core::core::merkle::generate_inclusion_proof(index, tree_size, |level, at| {
                    if level == 0 {
                        leaves.get(usize::try_from(at).ok()?).copied()
                    } else {
                        None
                    }
                })
                .expect("index within tree");
            pending.push(PendingPromotion {
                entry_id: id,
                leaf_index: index,
                inclusion_path: ahl_core::proof_path_hex(&proof),
            });
        }

        let cp = checkpoint_for(&key, &log_id, &entries);
        let config = config_with(&key, &log_id);
        ingest_checkpoint(&store, &config, &cp, None, &pending)
            .expect("checkpoint and its entries admitted together");
        assert_eq!(store.next_index().expect("query"), 4);
        assert_eq!(store.latest_checkpoint().expect("query").expect("present").tree_size, 4);
    }

    #[test]
    fn a_backfilled_checkpoint_is_checked_against_both_neighbours() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"0f".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "1a".repeat(32));
        let store = Store::open_in_memory().expect("in-memory store");
        let config = config_with(&key, &log_id);

        let all_nine: Vec<Vec<u8>> = (0u8..9).map(stored_entry).collect();
        stage_and_promote_all(&store, &all_nine);

        let cp4 = checkpoint_for(&key, &log_id, &all_nine[..4]);
        let cp9 = checkpoint_for(&key, &log_id, &all_nine);
        // Admit the larger one first, then backfill the smaller — exercises the successor
        // side of the neighbour check, not just the predecessor side.
        ingest_checkpoint(&store, &config, &cp9, None, &[]).expect("larger checkpoint first");
        ingest_checkpoint(&store, &config, &cp4, None, &[]).expect("backfilled checkpoint");

        let series = store.checkpoint_series().expect("series");
        assert_eq!(series.iter().map(|c| c.tree_size).collect::<Vec<_>>(), vec![4, 9]);
    }
}
