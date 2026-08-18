//! Checkpoints, the canonical checkpoint series, and `ITUB` (core spec §7.3; adaptor profile
//! §5.2, §6).

use atl_core::core::merkle::{compute_root, generate_consistency_proof, verify_consistency, Hash};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::config::Config;
use crate::error::{MirrorError, MirrorResult};
use crate::manifest::{self, GovernanceState};
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

/// A checkpoint's verification state (core spec §7.3, "Verification states").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointState {
    /// Its log signature verifies under the key set resolved from the governing manifest.
    /// MAY be retained, MUST be reported as such, and MUST NOT be counted toward the series.
    Authenticated,
    /// Additionally: its root has been recomputed against the entries held for its
    /// `tree_size`, and its consistency relationship with its preceding series member
    /// verifies (and with a following member, where one exists). The only state that may
    /// ground an incorporation-time bound, an enumeration response, or a completeness claim.
    SeriesUsable,
}

/// A checkpoint together with its computed verification state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportedCheckpoint {
    /// The checkpoint object.
    #[serde(flatten)]
    pub checkpoint: Checkpoint,
    /// Its current state (core spec §7.3).
    pub state: CheckpointState,
}

/// Why gap-free-frontier extension stopped short of the end of the series-usable set, if it
/// did (core spec §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum FrontierStop {
    /// No series-usable member could establish a valid start: neither within cadence of
    /// `cadence_epoch` nor at a `tree_size` whose predecessor is the genesis state.
    NoValidStart,
    /// `checkpoint_time` decreased between two adjacent series-usable members — a violation
    /// and a finding, never treated as a zero-length gap (core spec §7.3).
    DecreasingTime {
        /// The `tree_size` of the member after which the decrease was observed.
        after_tree_size: u64,
    },
    /// The cadence obligation was violated between two adjacent members.
    CadenceExceeded {
        /// The `tree_size` of the member after which the gap was observed.
        after_tree_size: u64,
    },
    /// Governance could not be resolved for a member needed to judge the next interval.
    GovernanceUnresolvable {
        /// The `tree_size` governance resolution was attempted for.
        at_tree_size: u64,
    },
}

/// The computed view of the checkpoint series at the current moment (core spec §7.3).
#[derive(Debug, Clone)]
pub struct SeriesView {
    /// Every authenticated checkpoint, in ascending `(tree_size, checkpoint_time)` order,
    /// each labelled with its current state.
    pub members: Vec<ReportedCheckpoint>,
    /// The `tree_size` up to and including which the series-usable subset is proven
    /// gap-free, if any prefix of it is.
    pub gap_free_frontier: Option<u64>,
    /// Why extension stopped short of the newest series-usable member, if it did. `None`
    /// alongside a `Some` frontier means extension reached the newest member cleanly; `None`
    /// alongside a `None` frontier means no member could even start a range.
    pub frontier_stop: Option<FrontierStop>,
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
/// commits, given the leaf hashes covering `[0, to_cp.tree_size)` (core spec §7.3; adaptor
/// profile §5.2.2 item 1). `from_cp.tree_size` MUST be less than `to_cp.tree_size`.
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

/// Build the best-effort entry prefix a governance resolution can use: canonical storage,
/// overlaid with `pending` promotions whose inclusion proof verifies against `claimed_root`
/// — safe to inspect even though `claimed_root` is not yet authenticated (see
/// [`crate::ingest::verify_inclusion_for`]'s docs). Nothing here commits `pending` to
/// canonical storage; see [`ingest_checkpoint`] for when that happens.
///
/// Deliberately does **not** require the prefix to reach `target_tree_size`: a checkpoint's
/// own signature MUST be verifiable from whatever governance material this mirror can
/// already see, even if this mirror does not yet hold every entry the checkpoint commits —
/// core spec §7.3 lets a checkpoint be admitted as merely *authenticated* in that case (see
/// [`ingest_checkpoint`]). The returned prefix is therefore the longest contiguous run
/// starting at index 0, which may be shorter than `target_tree_size`; only a genuinely bad
/// `pending` item (wrong proof, or naming bytes never staged) is an error — a plain gap this
/// call cannot fill is not.
///
/// # Errors
///
/// [`MirrorError::InclusionProofInvalid`] if a relevant `pending` entry's proof does not
/// verify, or [`MirrorError::NotStaged`] if it names an entry never staged.
fn build_visible_prefix(
    store: &Store,
    pending: &[PendingPromotion],
    target_tree_size: u64,
    claimed_root: &Hash,
) -> MirrorResult<Vec<Vec<u8>>> {
    let canonical = store.get_entries_range(0, target_tree_size)?;
    let target_usize = usize::try_from(target_tree_size)
        .map_err(|_| MirrorError::IndexOverflow { what: "target_tree_size" })?;
    let mut slots: Vec<Option<Vec<u8>>> = canonical.into_iter().map(Some).collect();
    slots.resize(target_usize, None);

    for p in pending {
        if p.leaf_index >= target_tree_size {
            continue; // irrelevant to this resolution; real promotion still validates it later
        }
        let idx = usize::try_from(p.leaf_index)
            .map_err(|_| MirrorError::IndexOverflow { what: "leaf_index" })?;
        if slots[idx].is_some() {
            continue; // already canonical; a tentative duplicate is not consulted
        }
        let bytes = store
            .get_staged(&p.entry_id)?
            .ok_or_else(|| MirrorError::NotStaged { entry_id: p.entry_id.clone() })?;
        if !crate::ingest::verify_inclusion_for(
            &bytes,
            p.leaf_index,
            target_tree_size,
            &p.inclusion_path,
            claimed_root,
        )? {
            return Err(MirrorError::InclusionProofInvalid {
                entry_id: p.entry_id.clone(),
                leaf_index: p.leaf_index,
                tree_size: target_tree_size,
            });
        }
        slots[idx] = Some(bytes);
    }

    let mut result = Vec::with_capacity(target_usize);
    for slot in slots {
        match slot {
            Some(bytes) => result.push(bytes),
            None => break, // a plain gap: stop here, not an error (see docs above)
        }
    }
    Ok(result)
}

/// Verify and admit `cp` as an **authenticated** checkpoint (core spec §7.3).
///
/// The pipeline, in order:
///
/// 1. Build the visible entry prefix for `cp.tree_size`: canonical storage, overlaid with
///    `entries_to_promote` wherever their inclusion proofs verify against `cp`'s *claimed*
///    root. This is safe before authentication — the checkpoint's own root is never trusted
///    for anything but this proof-gated overlay until step 2 passes — and is what lets
///    governance material introduced by this very checkpoint (e.g. a rotation anchored in
///    the same batch) be visible to step 2, which reading only already-canonical entries
///    could not see.
/// 2. Resolve governance from that prefix and verify `cp`'s signature against the resolved
///    key (core spec §7.3, §6.5). Only once this passes is `cp.root_hash` treated as
///    authenticated.
/// 3. Commit every entry in `entries_to_promote` for real (each re-verified by
///    [`crate::ingest::promote_entry`] against canonical storage).
/// 4. If the full range is *already* canonical after step 3, opportunistically confirm the
///    root recomputes, rejecting outright on a clear mismatch — a checkpoint whose root
///    provably disagrees with entries this mirror already holds is never even recorded as
///    authenticated.
/// 5. Record `cp` as authenticated (core spec §7.3, §5.2.2 item 4: append-only in
///    publication; a `(tree_size, checkpoint_time)` already present with different content
///    is rejected, but a different `checkpoint_time` at the same `tree_size` is a legitimate
///    additional member — see [`crate::store::Store::insert_checkpoint`]).
///
/// Series-usability is **not** decided here: it is computed on demand from the full current
/// state by [`series_view`], since entries (and other checkpoints) can arrive after `cp`
/// does.
///
/// # Errors
///
/// Any [`MirrorError`] from the steps above — most notably
/// [`MirrorError::GovernanceChainUnresolvable`] if no verified governance snapshot covers
/// `cp.tree_size`, refused rather than resolved from a stale or partial one.
pub fn ingest_checkpoint(
    store: &Store,
    config: &Config,
    cp: &Checkpoint,
    raw: Option<&[u8]>,
    entries_to_promote: &[PendingPromotion],
) -> MirrorResult<()> {
    let claimed_root: Hash = ahl_core::parse_hash_hex(&cp.root_hash)?;
    let prefix = build_visible_prefix(store, entries_to_promote, cp.tree_size, &claimed_root)?;

    let governance = manifest::resolve(&prefix, config)?;
    let key = governance.resolve_log_key(&cp.key_id, cp.tree_size)?;
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
        if compute_root(&leaf_hashes) != claimed_root {
            return Err(MirrorError::CheckpointRootMismatch { tree_size: cp.tree_size });
        }
    }

    store.insert_checkpoint(cp)?;
    Ok(())
}

/// Resolve governance for `tree_size` from canonical storage alone, treating an unresolvable
/// chain as `None` rather than propagating — used by gap-free-frontier computation, where a
/// currently-unresolvable governing version means "cannot judge this interval yet", not a
/// hard failure of the whole series view.
///
/// # Errors
///
/// Propagates any error other than [`MirrorError::GovernanceChainUnresolvable`].
fn resolve_governance_for(
    store: &Store,
    config: &Config,
    tree_size: u64,
) -> MirrorResult<Option<GovernanceState>> {
    let entries = store.get_entries_range(0, tree_size)?;
    let have = u64::try_from(entries.len())
        .map_err(|_| MirrorError::IndexOverflow { what: "entries.len()" })?;
    if have != tree_size {
        return Ok(None);
    }
    match manifest::resolve(&entries, config) {
        Ok(state) => Ok(Some(state)),
        Err(MirrorError::GovernanceChainUnresolvable { .. }) => Ok(None),
        Err(other) => Err(other),
    }
}

/// The result of [`compute_gap_free_frontier`]: how far the series-usable subset is proven
/// gap-free, and why extension stopped short of the newest member, if it did.
struct GapFreeResult {
    frontier: Option<u64>,
    stop: Option<FrontierStop>,
}

/// Compute the gap-free frontier and its stop reason over an already-ordered series-usable
/// slice (core spec §7.3).
///
/// The range must begin at `cadence_epoch` or at a checkpoint whose predecessor is the
/// genesis state; every interval is judged by the cadence in force when it began (the
/// earlier member's governing version); `checkpoint_time` MUST be non-decreasing, a decrease
/// is a violation, never a zero-length gap.
fn compute_gap_free_frontier(
    store: &Store,
    config: &Config,
    usable: &[Checkpoint],
) -> MirrorResult<GapFreeResult> {
    let Some(first) = usable.first() else {
        return Ok(GapFreeResult { frontier: None, stop: None });
    };

    let Some(first_governance) = resolve_governance_for(store, config, first.tree_size)? else {
        return Ok(GapFreeResult {
            frontier: None,
            stop: Some(FrontierStop::GovernanceUnresolvable { at_tree_size: first.tree_size }),
        });
    };
    let genesis_entry_index = first_governance.genesis_entry_index();
    let Some(genesis_governance) = resolve_governance_for(store, config, genesis_entry_index + 1)?
    else {
        return Ok(GapFreeResult {
            frontier: None,
            stop: Some(FrontierStop::GovernanceUnresolvable {
                at_tree_size: genesis_entry_index + 1,
            }),
        });
    };
    let epoch_nanos = genesis_governance.cadence_epoch_nanos();
    let genesis_cadence_nanos = genesis_governance.cadence_nanos();

    let first_time = parse_checkpoint_time(&first.checkpoint_time)?;
    let starts_at_genesis_state = first.tree_size == genesis_entry_index + 1;
    let starts_at_epoch =
        first_time >= epoch_nanos && first_time - epoch_nanos <= genesis_cadence_nanos;
    if !starts_at_genesis_state && !starts_at_epoch {
        return Ok(GapFreeResult { frontier: None, stop: Some(FrontierStop::NoValidStart) });
    }

    let mut frontier = first.tree_size;
    let mut prev = first;
    let mut prev_time = first_time;
    for cp in &usable[1..] {
        let cp_time = parse_checkpoint_time(&cp.checkpoint_time)?;
        if cp_time < prev_time {
            return Ok(GapFreeResult {
                frontier: Some(frontier),
                stop: Some(FrontierStop::DecreasingTime { after_tree_size: prev.tree_size }),
            });
        }
        let Some(prev_governance) = resolve_governance_for(store, config, prev.tree_size)? else {
            return Ok(GapFreeResult {
                frontier: Some(frontier),
                stop: Some(FrontierStop::GovernanceUnresolvable { at_tree_size: prev.tree_size }),
            });
        };
        let delta = cp_time - prev_time;
        if delta > prev_governance.cadence_nanos() {
            return Ok(GapFreeResult {
                frontier: Some(frontier),
                stop: Some(FrontierStop::CadenceExceeded { after_tree_size: prev.tree_size }),
            });
        }
        frontier = cp.tree_size;
        prev = cp;
        prev_time = cp_time;
    }
    Ok(GapFreeResult { frontier: Some(frontier), stop: None })
}

/// Whether the root recomputed from `leaves` matches `cp.root_hash`.
fn root_matches(leaves: &[Hash], cp: &Checkpoint) -> bool {
    ahl_core::parse_hash_hex(&cp.root_hash).is_ok_and(|root| compute_root(leaves) == root)
}

/// Compute the current [`SeriesView`]: every authenticated checkpoint labelled with its state
/// (core spec §7.3), and the gap-free frontier of the series-usable subset.
///
/// Series-usability is recomputed from the store's current state on every call — never
/// cached — because entries used for root recomputation, and later checkpoints establishing
/// a consistency relationship, can both arrive after a given checkpoint was admitted. A
/// checkpoint becomes series-usable once its root recomputes against held entries and it is
/// consistent with the nearest earlier series-usable member (vacuously true if there is
/// none) — its relationship to a *following* member is that following member's own
/// consistency check, so it never needs to be revisited.
///
/// # Errors
///
/// Propagates a [`MirrorError`] from the store or from checkpoint-time parsing.
pub fn series_view(store: &Store, config: &Config) -> MirrorResult<SeriesView> {
    let all = store.all_checkpoints()?;
    let mut members = Vec::with_capacity(all.len());
    let mut last_usable: Option<Checkpoint> = None;

    for cp in &all {
        let usable = leaf_hashes_for(store, cp.tree_size).is_ok_and(|leaves| {
            root_matches(&leaves, cp)
                && last_usable.as_ref().is_none_or(|pred| {
                    verify_series_consistency(pred, cp, &leaves).unwrap_or(false)
                })
        });

        members.push(ReportedCheckpoint {
            checkpoint: cp.clone(),
            state: if usable {
                CheckpointState::SeriesUsable
            } else {
                CheckpointState::Authenticated
            },
        });
        if usable {
            last_usable = Some(cp.clone());
        }
    }

    let usable_checkpoints: Vec<Checkpoint> = members
        .iter()
        .filter(|m| m.state == CheckpointState::SeriesUsable)
        .map(|m| m.checkpoint.clone())
        .collect();
    let GapFreeResult { frontier: gap_free_frontier, stop: frontier_stop } =
        compute_gap_free_frontier(store, config, &usable_checkpoints)?;

    Ok(SeriesView { members, gap_free_frontier, frontier_stop })
}

/// `ITUB(index)`: the series-usable checkpoint with the smallest `tree_size > index`, but
/// only if it falls within `view`'s gap-free frontier (core spec §7.3, §5.2.1-§5.2.2).
///
/// Returns `None` — unavailable, never a computed value — if no covering member exists, or
/// if the series is not proven gap-free that far. Pairwise consistency between the members
/// this mirror happens to hold does not establish completeness: it proves each pair is a
/// valid extension of the other, never that nothing was omitted between them.
#[must_use]
pub fn itub(view: &SeriesView, index: u64) -> Option<&Checkpoint> {
    let frontier = view.gap_free_frontier?;
    view.members
        .iter()
        .filter(|m| m.state == CheckpointState::SeriesUsable)
        .map(|m| &m.checkpoint)
        .find(|cp| cp.tree_size > index && cp.tree_size <= frontier)
}

#[cfg(test)]
mod tests {
    use sha2::Digest as _;

    use super::*;
    use crate::config::{ConfigSpec, KeyObjectSpec};

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

    // ---- fixtures for the full ingest_checkpoint / series_view pipeline ----

    struct Fixture {
        store: Store,
        config: Config,
        producer: ahl_core::TestKey,
        genesis_id: String,
    }

    fn stored_entry(payload: serde_json::Value, key: &ahl_core::TestKey) -> Vec<u8> {
        ahl_core::jcs(&ahl_core::envelope(payload, key))
    }

    fn entry_id_of(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
    }

    /// A throwaway checkpoint carrying only a trusted `(tree_size, root)` pair, used purely
    /// as the root reference [`crate::ingest::promote_entry`] checks proofs against — its
    /// other fields are never consulted by that function.
    fn root_vehicle(tree_size: u64, root: Hash) -> Checkpoint {
        Checkpoint {
            log_id: "sha256:00".to_owned(),
            tree_size,
            root_hash: format!("sha256:{}", hex::encode(root)),
            checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
            key_id: "sha256:00".to_owned(),
            signature: "base64:AAAA".to_owned(),
        }
    }

    /// Stage and promote `entries` at indices `[start_index, start_index + entries.len())`,
    /// proving each against `root` over a tree of `tree_size` (which MUST already cover the
    /// prefix `[0, start_index)` plus `entries`, in that order, for the proofs to verify).
    fn stage_and_promote_at(
        store: &Store,
        tree_size: u64,
        root: Hash,
        entries: &[Vec<u8>],
        start_index: u64,
    ) {
        let vehicle = root_vehicle(tree_size, root);
        let leaves: Vec<Hash> = {
            let existing = store.get_entries_range(0, start_index).expect("existing prefix");
            existing
                .iter()
                .map(|b| log_leaf_hash(b))
                .chain(entries.iter().map(|b| log_leaf_hash(b)))
                .collect()
        };
        for (offset, bytes) in entries.iter().enumerate() {
            let id = entry_id_of(bytes);
            store.stage_entry(&id, bytes).expect("stage");
            let index = start_index + u64::try_from(offset).expect("small test size");
            let proof =
                atl_core::core::merkle::generate_inclusion_proof(index, tree_size, |level, at| {
                    if level == 0 {
                        leaves.get(usize::try_from(at).ok()?).copied()
                    } else {
                        None
                    }
                })
                .expect("index within tree");
            let path = ahl_core::proof_path_hex(&proof);
            crate::ingest::promote_entry(store, &vehicle, &id, index, &path).expect("promote");
        }
    }

    fn genesis_manifest_payload(
        log_id: &str,
        producer: &ahl_core::TestKey,
        log_key: &ahl_core::TestKey,
        cadence: &str,
        epoch: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "type": "manifest",
            "producer": "producer-1",
            "keys": [
                { "key_id": producer.key_id(), "pubkey": producer.pubkey(), "valid_from_index": 0 }
            ],
            "log": {
                "log_id": log_id,
                "operator": "op-1",
                "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
                "checkpoint_cadence": cadence,
                "cadence_epoch": epoch,
                "witness_grace_period": "PT10M",
                "keys": [
                    { "key_id": log_key.key_id(), "pubkey": log_key.pubkey(), "valid_from_index": 0 }
                ],
            },
        })
    }

    /// A fresh store already holding a verified genesis manifest at index 0, whose `log.keys`
    /// is `log_key` and whose cadence is 5 minutes starting at `epoch`.
    fn fixture(log_key: &ahl_core::TestKey, epoch: &str) -> Fixture {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"77".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "aa".repeat(32));
        let genesis_bytes = stored_entry(
            genesis_manifest_payload(&log_id, &producer, log_key, "PT5M", epoch),
            &producer,
        );
        let genesis_id = entry_id_of(&genesis_bytes);

        let store = Store::open_in_memory().expect("in-memory store");
        store.stage_entry(&genesis_id, &genesis_bytes).expect("stage genesis");
        store.promote_entry(0, &genesis_id).expect("promote genesis");

        let config = Config::resolve(&ConfigSpec {
            log_id,
            genesis_manifest_entry_id: genesis_id.clone(),
            genesis_producer_keys: vec![KeyObjectSpec {
                key_id: producer.key_id(),
                pubkey: producer.pubkey(),
                valid_from_index: 0,
            }],
            store_path: ":memory:".to_owned(),
        })
        .expect("valid config");

        Fixture { store, config, producer, genesis_id }
    }

    fn checkpoint_for(
        key: &ahl_core::TestKey,
        log_id: &str,
        tree_size: u64,
        root: Hash,
        time: &str,
    ) -> Checkpoint {
        signed_checkpoint(key, log_id, tree_size, &format!("sha256:{}", hex::encode(root)), time)
    }

    #[test]
    fn a_checkpoint_over_the_genesis_manifest_alone_is_authenticated_and_series_usable() {
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"78".repeat(32)).expect("seed");
        let fx = fixture(&log_key, "2026-01-01T00:00:00Z");
        let leaves = [log_leaf_hash(&fx.store.get_entries_range(0, 1).expect("range")[0])];
        let root = compute_root(&leaves);
        let cp =
            checkpoint_for(&log_key, &fx.config.log_id, 1, root, "2026-01-01T00:00:00.000000000Z");

        ingest_checkpoint(&fx.store, &fx.config, &cp, None, &[]).expect("admits");
        let view = series_view(&fx.store, &fx.config).expect("view");
        assert_eq!(view.members.len(), 1);
        assert_eq!(view.members[0].state, CheckpointState::SeriesUsable);
        assert_eq!(view.gap_free_frontier, Some(1));
    }

    #[test]
    fn a_manifest_with_an_invalid_signature_is_not_governance_and_admission_fails() {
        // Round 3, defect 1: a manifest-typed entry that is merely anchored, with no valid
        // producer signature under the trusted genesis anchor, must not become governance.
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"79".repeat(32)).expect("seed");
        let impostor =
            ahl_core::TestKey::from_seed_hex("impostor", &"7a".repeat(32)).expect("seed");
        let real_producer =
            ahl_core::TestKey::from_seed_hex("producer", &"7b".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "bb".repeat(32));
        // Signed by an impostor, not the configured genesis producer.
        let genesis_bytes = stored_entry(
            genesis_manifest_payload(
                &log_id,
                &real_producer,
                &log_key,
                "PT5M",
                "2026-01-01T00:00:00Z",
            ),
            &impostor,
        );
        let genesis_id = entry_id_of(&genesis_bytes);
        let store = Store::open_in_memory().expect("in-memory store");
        store.stage_entry(&genesis_id, &genesis_bytes).expect("stage");
        store.promote_entry(0, &genesis_id).expect("promote");
        let config = Config::resolve(&ConfigSpec {
            log_id: log_id.clone(),
            genesis_manifest_entry_id: genesis_id,
            genesis_producer_keys: vec![KeyObjectSpec {
                key_id: real_producer.key_id(),
                pubkey: real_producer.pubkey(),
                valid_from_index: 0,
            }],
            store_path: ":memory:".to_owned(),
        })
        .expect("valid config");

        let leaves = [log_leaf_hash(&store.get_entries_range(0, 1).expect("range")[0])];
        let root = compute_root(&leaves);
        let cp = checkpoint_for(&log_key, &log_id, 1, root, "2026-01-01T00:00:00.000000000Z");
        assert!(matches!(
            ingest_checkpoint(&store, &config, &cp, None, &[]),
            Err(MirrorError::GovernanceChainUnresolvable { .. })
        ));
    }

    #[test]
    fn a_manifest_with_a_bad_predecessor_link_does_not_rotate_governance() {
        // Round 3, defect 1: predecessor linkage is required for a non-genesis manifest.
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"7c".repeat(32)).expect("seed");
        let fx = fixture(&log_key, "2026-01-01T00:00:00Z");
        let rotated_log_key =
            ahl_core::TestKey::from_seed_hex("log-2", &"7d".repeat(32)).expect("seed");
        let bad_next = stored_entry(
            serde_json::json!({
                "type": "manifest",
                "producer": "producer-1",
                "predecessor": "sha256:not-the-genesis-entry-id",
                "keys": [
                    { "key_id": fx.producer.key_id(), "pubkey": fx.producer.pubkey(), "valid_from_index": 0 }
                ],
                "log": {
                    "log_id": fx.config.log_id,
                    "operator": "op-1",
                    "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
                    "checkpoint_cadence": "PT5M",
                    "cadence_epoch": "2026-01-01T00:00:00Z",
                    "witness_grace_period": "PT10M",
                    "keys": [
                        { "key_id": rotated_log_key.key_id(), "pubkey": rotated_log_key.pubkey(), "valid_from_index": 0 }
                    ],
                },
            }),
            &fx.producer,
        );

        let genesis_leaf = log_leaf_hash(&fx.store.get_entries_range(0, 1).expect("range")[0]);
        let leaves = [genesis_leaf, log_leaf_hash(&bad_next)];
        let root = compute_root(&leaves);
        stage_and_promote_at(&fx.store, 2, root, &[bad_next], 1);

        // Still verifiable with the ORIGINAL (never-rotated) log key, since the bad manifest
        // never took effect.
        let cp =
            checkpoint_for(&log_key, &fx.config.log_id, 2, root, "2026-01-01T00:01:00.000000000Z");
        ingest_checkpoint(&fx.store, &fx.config, &cp, None, &[])
            .expect("admits: governance never rotated");
    }

    #[test]
    fn governance_material_can_bootstrap_via_entries_to_promote_in_the_same_operation() {
        // Round 3, defect 2 (ordering): a checkpoint whose OWN range introduces a manifest
        // rotation can still resolve its signing key, because entries_to_promote are visible
        // to governance resolution before the checkpoint's signature is checked.
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"7e".repeat(32)).expect("seed");
        let fx = fixture(&log_key, "2026-01-01T00:00:00Z");
        let rotated_log_key =
            ahl_core::TestKey::from_seed_hex("log-2", &"7f".repeat(32)).expect("seed");
        let rotation = stored_entry(
            serde_json::json!({
                "type": "manifest",
                "producer": "producer-1",
                "predecessor": fx.genesis_id,
                "keys": [
                    { "key_id": fx.producer.key_id(), "pubkey": fx.producer.pubkey(), "valid_from_index": 0 }
                ],
                "log": {
                    "log_id": fx.config.log_id,
                    "operator": "op-1",
                    "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
                    "checkpoint_cadence": "PT5M",
                    "cadence_epoch": "2026-01-01T00:00:00Z",
                    "witness_grace_period": "PT10M",
                    "keys": [
                        { "key_id": rotated_log_key.key_id(), "pubkey": rotated_log_key.pubkey(), "valid_from_index": 1 }
                    ],
                },
            }),
            &fx.producer,
        );
        let rotation_id = entry_id_of(&rotation);
        fx.store.stage_entry(&rotation_id, &rotation).expect("stage rotation");

        let leaves: Vec<Hash> = vec![
            log_leaf_hash(&fx.store.get_entries_range(0, 1).expect("range")[0]),
            log_leaf_hash(&rotation),
        ];
        let root = compute_root(&leaves);
        let proof = atl_core::core::merkle::generate_inclusion_proof(1, 2, |level, at| {
            if level == 0 {
                leaves.get(usize::try_from(at).ok()?).copied()
            } else {
                None
            }
        })
        .expect("index within tree");
        let pending = vec![PendingPromotion {
            entry_id: rotation_id,
            leaf_index: 1,
            inclusion_path: ahl_core::proof_path_hex(&proof),
        }];
        // Signed with the ROTATED key, which only the entries_to_promote overlay reveals.
        let cp = checkpoint_for(
            &rotated_log_key,
            &fx.config.log_id,
            2,
            root,
            "2026-01-01T00:00:00.000000000Z",
        );
        ingest_checkpoint(&fx.store, &fx.config, &cp, None, &pending)
            .expect("bootstraps its own governing rotation");
        assert_eq!(fx.store.next_index().expect("query"), 2);
    }

    #[test]
    fn a_checkpoint_whose_governing_manifest_is_not_yet_visible_is_refused() {
        // Round 3, defect 2 (refusal): with nothing canonical yet, no genesis is resolvable,
        // so admission must refuse — never fall back to any default.
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"80".repeat(32)).expect("seed");
        let store = Store::open_in_memory().expect("in-memory store");
        let log_id = format!("sha256:{}", "aa".repeat(32));
        let config = Config::resolve(&ConfigSpec {
            log_id: log_id.clone(),
            genesis_manifest_entry_id: "sha256:never-seen".to_owned(),
            genesis_producer_keys: vec![KeyObjectSpec {
                key_id: log_key.key_id(),
                pubkey: log_key.pubkey(),
                valid_from_index: 0,
            }],
            store_path: ":memory:".to_owned(),
        })
        .expect("valid config");
        let cp = checkpoint_for(&log_key, &log_id, 0, [0u8; 32], "2026-01-01T00:00:00.000000000Z");
        assert!(matches!(
            ingest_checkpoint(&store, &config, &cp, None, &[]),
            Err(MirrorError::GovernanceChainUnresolvable { .. })
        ));
    }

    #[test]
    fn two_individually_signed_but_inconsistent_checkpoints_do_not_both_become_series_usable() {
        // Round 3, defect 3: both admitted (each authenticated on its own signature), but
        // their roots are mutually incompatible once the entries needed to check them exist.
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"81".repeat(32)).expect("seed");
        let fx = fixture(&log_key, "2026-01-01T00:00:00Z");

        let genesis_leaf = log_leaf_hash(&fx.store.get_entries_range(0, 1).expect("range")[0]);
        let genuine_root_1 = compute_root(&[genesis_leaf]);
        let cp_a = checkpoint_for(
            &log_key,
            &fx.config.log_id,
            1,
            genuine_root_1,
            "2026-01-01T00:00:00.000000000Z",
        );
        ingest_checkpoint(&fx.store, &fx.config, &cp_a, None, &[])
            .expect("first checkpoint admits");

        // A second, later checkpoint at a larger tree_size, but with a root that is not a
        // true extension of cp_a's tree — the root of unrelated content of the same count.
        // This mirror does not yet have the entries to catch that at admission time.
        let unrelated: Vec<Vec<u8>> =
            (90u8..92).map(|n| stored_entry(serde_json::json!({ "n": n }), &fx.producer)).collect();
        let bogus_root =
            compute_root(&unrelated.iter().map(|b| log_leaf_hash(b)).collect::<Vec<_>>());
        let cp_b = checkpoint_for(
            &log_key,
            &fx.config.log_id,
            2,
            bogus_root,
            "2026-01-01T00:01:00.000000000Z",
        );
        ingest_checkpoint(&fx.store, &fx.config, &cp_b, None, &[])
            .expect("second checkpoint admits");

        // Now the real second entry arrives, promoted against cp_a's genuine extension —
        // never against cp_b's bogus one.
        let genuine_second = stored_entry(serde_json::json!({ "n": 1 }), &fx.producer);
        let genuine_root_2 = compute_root(&[genesis_leaf, log_leaf_hash(&genuine_second)]);
        stage_and_promote_at(&fx.store, 2, genuine_root_2, &[genuine_second], 1);

        let view = series_view(&fx.store, &fx.config).expect("view");
        let state_of = |tree_size: u64| {
            view.members
                .iter()
                .find(|m| m.checkpoint.tree_size == tree_size)
                .expect("present")
                .state
        };
        assert_eq!(state_of(1), CheckpointState::SeriesUsable);
        assert_eq!(state_of(2), CheckpointState::Authenticated);
    }

    #[test]
    fn a_decreasing_checkpoint_time_is_reported_as_a_violation() {
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"82".repeat(32)).expect("seed");
        let fx = fixture(&log_key, "2026-01-01T00:00:00Z");
        let genesis_leaf = log_leaf_hash(&fx.store.get_entries_range(0, 1).expect("range")[0]);
        let root_1 = compute_root(&[genesis_leaf]);
        let cp_a = checkpoint_for(
            &log_key,
            &fx.config.log_id,
            1,
            root_1,
            "2026-01-01T00:05:00.000000000Z",
        );
        ingest_checkpoint(&fx.store, &fx.config, &cp_a, None, &[]).expect("admits");

        let second = stored_entry(serde_json::json!({ "n": 1 }), &fx.producer);
        let root_2 = compute_root(&[genesis_leaf, log_leaf_hash(&second)]);
        stage_and_promote_at(&fx.store, 2, root_2, &[second], 1);
        // Earlier checkpoint_time than cp_a, despite the larger tree_size: a violation.
        let cp_b = checkpoint_for(
            &log_key,
            &fx.config.log_id,
            2,
            root_2,
            "2026-01-01T00:04:00.000000000Z",
        );
        ingest_checkpoint(&fx.store, &fx.config, &cp_b, None, &[]).expect("admits");

        let view = series_view(&fx.store, &fx.config).expect("view");
        assert_eq!(view.gap_free_frontier, Some(1));
        assert_eq!(view.frontier_stop, Some(FrontierStop::DecreasingTime { after_tree_size: 1 }));
    }

    #[test]
    fn a_cadence_change_does_not_retroactively_validate_an_earlier_gap() {
        // A first interval that violates the ORIGINAL (tight) cadence must not be excused by
        // a LATER manifest version relaxing the cadence — the earlier interval is judged by
        // the cadence in force when it began (core spec §7.3).
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"83".repeat(32)).expect("seed");
        let fx = fixture(&log_key, "2026-01-01T00:00:00Z"); // genesis cadence: 5 minutes

        let genesis_leaf = log_leaf_hash(&fx.store.get_entries_range(0, 1).expect("range")[0]);
        let root_1 = compute_root(&[genesis_leaf]);
        // Starts the range validly (within 5 minutes of epoch).
        let cp_a = checkpoint_for(
            &log_key,
            &fx.config.log_id,
            1,
            root_1,
            "2026-01-01T00:01:00.000000000Z",
        );
        ingest_checkpoint(&fx.store, &fx.config, &cp_a, None, &[]).expect("admits");

        // A relaxed-cadence manifest version (1 hour) anchored next, rotating nothing else.
        let relaxed = stored_entry(
            serde_json::json!({
                "type": "manifest",
                "producer": "producer-1",
                "predecessor": fx.genesis_id,
                "keys": [
                    { "key_id": fx.producer.key_id(), "pubkey": fx.producer.pubkey(), "valid_from_index": 0 }
                ],
                "log": {
                    "log_id": fx.config.log_id,
                    "operator": "op-1",
                    "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
                    "checkpoint_cadence": "PT1H",
                    "cadence_epoch": "2026-01-01T00:00:00Z",
                    "witness_grace_period": "PT10M",
                    "keys": [
                        { "key_id": log_key.key_id(), "pubkey": log_key.pubkey(), "valid_from_index": 0 }
                    ],
                },
            }),
            &fx.producer,
        );
        let root_2 = compute_root(&[genesis_leaf, log_leaf_hash(&relaxed)]);
        stage_and_promote_at(&fx.store, 2, root_2, &[relaxed], 1);

        // 40 minutes after cp_a: fine under the NEW 1-hour cadence, but the cp_a -> cp_b
        // interval is judged by cp_a's GOVERNING version (still genesis, 5 minutes) per the
        // "earlier member governs" rule — the rotation is at index 1, not below cp_a's own
        // tree_size of 1, so it does not govern cp_a.
        let cp_b = checkpoint_for(
            &log_key,
            &fx.config.log_id,
            2,
            root_2,
            "2026-01-01T00:41:00.000000000Z",
        );
        ingest_checkpoint(&fx.store, &fx.config, &cp_b, None, &[]).expect("admits");

        let view = series_view(&fx.store, &fx.config).expect("view");
        assert_eq!(view.gap_free_frontier, Some(1));
        assert_eq!(view.frontier_stop, Some(FrontierStop::CadenceExceeded { after_tree_size: 1 }));
    }
}
