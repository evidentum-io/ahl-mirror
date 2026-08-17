//! Checkpoints, the canonical checkpoint series, and `ITUB` (adaptor profile §5.2, §6).

use atl_core::core::merkle::{compute_root, generate_consistency_proof, verify_consistency, Hash};
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

/// Verify `cp`'s identity and signature against this mirror's configured trust (adaptor
/// profile §6.5, steps 1-5, restricted to the single configured `log_id`).
///
/// If `raw` is given, it is checked byte for byte against the assembled blob first (§6.4).
///
/// This function checks signature validity only — it does not check series ordering or
/// consistency with a predecessor; see [`verify_series_consistency`] and
/// [`crate::store::Store::insert_checkpoint`] for that.
///
/// # Errors
///
/// [`MirrorError::WrongLogId`], [`MirrorError::RawBlobMismatch`],
/// [`MirrorError::UnknownSigningKey`], [`MirrorError::SignatureInvalid`], or a parsing
/// error from [`checkpoint_blob`].
pub fn verify_checkpoint(cp: &Checkpoint, raw: Option<&[u8]>, config: &Config) -> MirrorResult<()> {
    if cp.log_id != config.log_id {
        return Err(MirrorError::WrongLogId {
            expected: config.log_id.clone(),
            got: cp.log_id.clone(),
        });
    }
    let blob = checkpoint_blob(cp)?;
    if let Some(raw) = raw {
        if raw != blob {
            return Err(MirrorError::RawBlobMismatch);
        }
    }
    let key = config
        .key(&cp.key_id)
        .ok_or_else(|| MirrorError::UnknownSigningKey { key_id: cp.key_id.clone() })?;
    if !ahl_core::verify_signature(&key.verifying_key, &blob, &cp.signature)? {
        return Err(MirrorError::SignatureInvalid { key_id: cp.key_id.clone() });
    }
    Ok(())
}

/// Verify that `to_cp` is consistent with `from_cp`.
///
/// That is: `from_cp` is exactly the size-`from_cp.tree_size` prefix of the tree `to_cp`
/// commits, given the leaf hashes covering `[0, to_cp.tree_size)` (adaptor profile §5.2.2
/// item 1; core spec §3 contract item 3).
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

/// Verify and admit `cp` into the canonical checkpoint series (adaptor profile §5.2.2).
///
/// Requires, in order: a valid signature under the configured `log_id` (see
/// [`verify_checkpoint`]); complete, contiguous entries for `[0, cp.tree_size)` in `store`;
/// those entries to recompute to `cp.root_hash`; and — if the series already has a member —
/// a verified consistency proof from the latest existing member to `cp` (see
/// [`verify_series_consistency`]), which is what keeps the series gap-free in publication
/// (adaptor profile §5.2.2 item 1). Only after every check passes is `cp` inserted.
///
/// # Errors
///
/// [`MirrorError::IncompleteEntries`] if the mirror has not yet caught up to `cp.tree_size`;
/// [`MirrorError::CheckpointRootMismatch`] if the stored entries do not open `cp.root_hash`;
/// [`MirrorError::InconsistentWithPredecessor`] if `cp` is not a valid extension of the
/// series; or a signature/store error from the checks above.
pub fn ingest_checkpoint(
    store: &Store,
    config: &Config,
    cp: &Checkpoint,
    raw: Option<&[u8]>,
) -> MirrorResult<()> {
    verify_checkpoint(cp, raw, config)?;

    let all_entries = store.get_entries_range(0, cp.tree_size)?;
    let have = u64::try_from(all_entries.len())
        .map_err(|_| MirrorError::IndexOverflow { what: "all_entries.len()" })?;
    if have != cp.tree_size {
        return Err(MirrorError::IncompleteEntries { have, need: cp.tree_size });
    }

    let leaf_hashes: Vec<Hash> = all_entries.iter().map(|bytes| log_leaf_hash(bytes)).collect();
    let root: Hash = ahl_core::parse_hash_hex(&cp.root_hash)?;
    if compute_root(&leaf_hashes) != root {
        return Err(MirrorError::CheckpointRootMismatch { tree_size: cp.tree_size });
    }

    if let Some(predecessor) = store.latest_checkpoint()? {
        if !verify_series_consistency(&predecessor, cp, &leaf_hashes)? {
            return Err(MirrorError::InconsistentWithPredecessor {
                predecessor_tree_size: predecessor.tree_size,
                tree_size: cp.tree_size,
            });
        }
    }

    store.insert_checkpoint(cp)
}

/// `ITUB(index)`: the `checkpoint_time` of the smallest-`tree_size` series member with
/// `tree_size > index` (adaptor profile §5.2.1). `series` MUST already be ascending by
/// `tree_size`.
///
/// Returns `None` if the series does not yet contain a member covering `index` — `ITUB` is
/// then undefined under the profile, and callers MUST report incorporation time as
/// unavailable rather than substitute a value.
#[must_use]
pub fn itub(series: &[Checkpoint], index: u64) -> Option<&Checkpoint> {
    series.iter().find(|cp| cp.tree_size > index)
}

#[cfg(test)]
mod tests {
    use sha2::Digest as _;

    use super::*;
    use crate::config::{Config, ConfigSpec, TrustedLogKeySpec};

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
        let config = config_with(&key, &log_id);
        verify_checkpoint(&cp, None, &config).expect("valid signature and log_id");
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
        let config = config_with(&key, &format!("sha256:{}", "cc".repeat(32)));
        assert!(matches!(
            verify_checkpoint(&cp, None, &config),
            Err(MirrorError::WrongLogId { .. })
        ));
    }

    #[test]
    fn an_untrusted_signing_key_is_rejected() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"06".repeat(32)).expect("seed");
        let other = ahl_core::TestKey::from_seed_hex("other", &"07".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "dd".repeat(32));
        let cp = signed_checkpoint(
            &key,
            &log_id,
            10,
            &format!("sha256:{}", "ee".repeat(32)),
            "2026-01-01T00:00:00.000000000Z",
        );
        let config = config_with(&other, &log_id);
        assert!(matches!(
            verify_checkpoint(&cp, None, &config),
            Err(MirrorError::UnknownSigningKey { .. })
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
        let config = config_with(&key, &log_id);
        assert!(matches!(
            verify_checkpoint(&cp, None, &config),
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
        let config = config_with(&key, &log_id);
        let bad_raw = [0u8; CHECKPOINT_BLOB_LEN];
        assert!(matches!(
            verify_checkpoint(&cp, Some(&bad_raw), &config),
            Err(MirrorError::RawBlobMismatch)
        ));
    }

    #[test]
    fn itub_picks_the_smallest_covering_checkpoint() {
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
                checkpoint_time: "2026-01-02T00:00:00.000000000Z".to_owned(),
                key_id: "sha256:aa".to_owned(),
                signature: "base64:AAAA".to_owned(),
            },
        ];
        assert_eq!(itub(&series, 3).expect("covered").tree_size, 5);
        assert_eq!(itub(&series, 5).expect("covered").tree_size, 10);
        assert_eq!(itub(&series, 9).expect("covered").tree_size, 10);
        assert!(itub(&series, 10).is_none());
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

    #[test]
    fn a_checkpoint_over_fully_stored_entries_is_admitted() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"0a".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "14".repeat(32));
        let store = Store::open_in_memory().expect("in-memory store");
        let entries: Vec<Vec<u8>> = (0u8..4).map(stored_entry).collect();
        for (i, bytes) in entries.iter().enumerate() {
            let id = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
            store.insert_entry(i as u64, &id, bytes).expect("insert");
        }
        let cp = checkpoint_for(&key, &log_id, &entries);
        let config = config_with(&key, &log_id);
        ingest_checkpoint(&store, &config, &cp, None).expect("complete, well-formed checkpoint");
        assert_eq!(store.latest_checkpoint().expect("query").expect("present").tree_size, 4);
    }

    #[test]
    fn a_checkpoint_ahead_of_stored_entries_leaves_a_gap_and_is_rejected() {
        // The checkpoint commits 8 entries but the mirror has only received 4 — exactly the
        // "gap in the checkpoint series" the task brief asks to be tested: the series must
        // never advertise a member the store cannot yet back with complete entries.
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"0b".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "15".repeat(32));
        let store = Store::open_in_memory().expect("in-memory store");
        let received: Vec<Vec<u8>> = (0u8..4).map(stored_entry).collect();
        for (i, bytes) in received.iter().enumerate() {
            let id = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
            store.insert_entry(i as u64, &id, bytes).expect("insert");
        }
        let all_eight: Vec<Vec<u8>> = (0u8..8).map(stored_entry).collect();
        let cp = checkpoint_for(&key, &log_id, &all_eight);
        let config = config_with(&key, &log_id);
        assert!(matches!(
            ingest_checkpoint(&store, &config, &cp, None),
            Err(MirrorError::IncompleteEntries { have: 4, need: 8 })
        ));
        assert!(store.latest_checkpoint().expect("query").is_none());
    }

    #[test]
    fn a_second_checkpoint_extends_the_series() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"0c".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "16".repeat(32));
        let store = Store::open_in_memory().expect("in-memory store");
        let first: Vec<Vec<u8>> = (0u8..4).map(stored_entry).collect();
        for (i, bytes) in first.iter().enumerate() {
            let id = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
            store.insert_entry(i as u64, &id, bytes).expect("insert");
        }
        let config = config_with(&key, &log_id);
        let cp1 = checkpoint_for(&key, &log_id, &first);
        ingest_checkpoint(&store, &config, &cp1, None).expect("first checkpoint");

        let more: Vec<Vec<u8>> = (4u8..9).map(stored_entry).collect();
        for (offset, bytes) in more.iter().enumerate() {
            let index = 4 + offset as u64;
            let id = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
            store.insert_entry(index, &id, bytes).expect("insert");
        }
        let all_nine: Vec<Vec<u8>> = (0u8..9).map(stored_entry).collect();
        let cp2 = checkpoint_for(&key, &log_id, &all_nine);
        ingest_checkpoint(&store, &config, &cp2, None)
            .expect("second checkpoint extends the series");

        let series = store.checkpoint_series().expect("series");
        assert_eq!(series.iter().map(|c| c.tree_size).collect::<Vec<_>>(), vec![4, 9]);
    }
}
