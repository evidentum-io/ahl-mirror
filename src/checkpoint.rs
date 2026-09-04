//! Checkpoints, the canonical checkpoint series, and `ITUB` (core spec §7.3; adaptor profile
//! §5.2, §6).
//!
//! # Series order
//!
//! The series is ordered by `(tree_size, checkpoint_time)` ascending, **not** `tree_size`
//! alone: a quiet log republishes at unchanged `tree_size`, so `tree_size` does not totally
//! order the series (core spec §7.3). [`crate::store::Store::all_checkpoints`] returns members
//! in exactly this order — every consumer here ([`series_view`], [`itub`], and the private
//! `compute_gap_free_frontier`) relies on it directly rather than re-sorting, and
//! [`SeriesView::root_divergences`] makes explicit the corollary the ordering exists to
//! support: members sharing a `tree_size` MUST carry the same `root_hash`.

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
    /// The series has exactly one start: `cadence_epoch` (core spec §7.3). No series-usable
    /// member could establish it, either because none exists yet, or because the earliest
    /// series-usable checkpoint committing the genesis manifest carries a `checkpoint_time`
    /// outside `[cadence_epoch, cadence_epoch + checkpoint_cadence]` of the genesis manifest
    /// version — reaching back over an interval the corpus did not exist for, or leaving the
    /// opening interval unjudged.
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
    /// Two authenticated members share `at_tree_size` with different `root_hash` values —
    /// equivocation, not a tie (core spec §7.3: "Equivocation ends the series"). Frontier
    /// extension never reaches `at_tree_size` or beyond; see [`SeriesView::equivocation_floor`].
    Equivocation {
        /// The lowest `tree_size` at which two authenticated members diverge in `root_hash`.
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
    /// `tree_size` values at which two or more authenticated members declare different
    /// `root_hash` values — a finding: core spec §7.3 requires members sharing a `tree_size`
    /// to carry the same `root_hash`, since a quiet log republishing at unchanged `tree_size`
    /// is legitimate but must still commit to one root. Detected purely from checkpoint
    /// metadata (no entries need be held).
    pub root_divergences: Vec<u64>,
    /// The lowest `tree_size` in `root_divergences`, if any — core spec §7.3: "from the
    /// lowest `tree_size` at which it occurs, the series is no longer canonical: no
    /// incorporation bound, enumeration response or completeness claim may be grounded at or
    /// beyond that point … members below the divergence remain usable." `gap_free_frontier`
    /// (and therefore `itub`) never reaches or passes this value — see
    /// `compute_gap_free_frontier`'s `equivocation_floor` parameter — and callers grounding an
    /// enumeration or consistency response MUST independently refuse any `tree_size >=` this
    /// value, since a checkpoint's own root recomputing correctly against entries this mirror
    /// happens to hold does not un-equivocate a log that published a conflicting root too.
    pub equivocation_floor: Option<u64>,
}

/// Find every `tree_size` at which two adjacent members of `checkpoints` (ordered ascending
/// by `(tree_size, checkpoint_time)`, as [`Store::all_checkpoints`] returns them) declare
/// different `root_hash` values — core spec §7.3's "members sharing a `tree_size` MUST carry
/// the same `root_hash`" rule, made explicit rather than left as an implicit consequence of
/// root recomputation (which only ever confirms one candidate right, never flags the other as
/// specifically *conflicting*).
fn find_root_divergences(checkpoints: &[Checkpoint]) -> Vec<u64> {
    let mut divergences = Vec::new();
    for window in checkpoints.windows(2) {
        let [a, b] = window else { continue };
        if a.tree_size == b.tree_size
            && a.root_hash != b.root_hash
            && divergences.last() != Some(&a.tree_size)
        {
            divergences.push(a.tree_size);
        }
    }
    divergences
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

/// The exact byte positions of the seven literal characters in the rendering adaptor profile
/// §6.3 fixes, `YYYY-MM-DDTHH:MM:SS.fffffffffZ`.
const CHECKPOINT_TIME_LITERALS: [(usize, u8); 7] =
    [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':'), (19, b'.'), (29, b'Z')];

/// The length of that rendering.
const CHECKPOINT_TIME_LEN: usize = 30;

/// Whether `value` has exactly that shape: thirty ASCII characters, the seven literals in
/// their fixed positions, and a digit everywhere else — nine of them in the subsecond field.
///
/// Checked before `value` reaches the datetime parser rather than left to it. That parser's
/// subsecond combinator is told to expect exactly nine digits and derives a width by
/// subtraction from the digits it actually consumed, which underflows when it is handed
/// fewer — so a value of the wrong shape must never reach it. `checkpoint_time` arrives in a
/// request body, so the wrong shape is an ordinary input, not a remote possibility.
fn has_profile_time_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != CHECKPOINT_TIME_LEN {
        return false;
    }
    bytes.iter().enumerate().all(|(at, byte)| {
        CHECKPOINT_TIME_LITERALS
            .iter()
            .find_map(|(position, literal)| (*position == at).then_some(*byte == *literal))
            .unwrap_or_else(|| byte.is_ascii_digit())
    })
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
    if !has_profile_time_shape(value) {
        return Err(bad());
    }
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

/// Fetch the complete, contiguous log-leaf-hash sequence for `[0, tree_size)` from an
/// already-open connection, or report how far short the store is.
///
/// The `&Connection` core of [`leaf_hashes_for`] — usable inside a transaction (see
/// [`ingest_checkpoint`]), where calling [`leaf_hashes_for`] itself would deadlock by
/// re-locking the store's mutex.
fn leaf_hashes_for_conn(conn: &rusqlite::Connection, tree_size: u64) -> MirrorResult<Vec<Hash>> {
    let entries = crate::store::get_entries_range_raw(conn, 0, tree_size)?;
    let have = u64::try_from(entries.len())
        .map_err(|_| MirrorError::IndexOverflow { what: "entries.len()" })?;
    if have != tree_size {
        return Err(MirrorError::IncompleteEntries { have, need: tree_size });
    }
    Ok(entries.iter().map(|bytes| log_leaf_hash(bytes)).collect())
}

/// Fetch the complete, contiguous log-leaf-hash sequence for `[0, tree_size)`, or report how
/// far short the store is.
fn leaf_hashes_for(store: &Store, tree_size: u64) -> MirrorResult<Vec<Hash>> {
    store.with_conn(|conn| leaf_hashes_for_conn(conn, tree_size))
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
        // `slots` has exactly `target_usize` elements and the guard above established
        // `p.leaf_index < target_tree_size`, so the slot is present. Reading and writing it
        // through the one `get_mut` keeps that reasoning next to the access rather than
        // spread over two bare indexings.
        let Some(slot) = slots.get_mut(idx) else {
            return Err(MirrorError::IndexOverflow { what: "leaf_index" });
        };
        if slot.is_some() {
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
        *slot = Some(bytes);
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
///    [`crate::ingest::promote_entry_in`] against canonical storage) and, if the full range is
///    *already* canonical afterward, opportunistically confirm the root recomputes, rejecting
///    outright on a clear mismatch — a checkpoint whose root provably disagrees with entries
///    this mirror already holds is never even recorded as authenticated.
/// 4. Record `cp` as authenticated (core spec §7.3, §5.2.2 item 4: append-only in
///    publication; a `(tree_size, checkpoint_time)` already present with different content
///    is rejected, but a different `checkpoint_time` at the same `tree_size` is a legitimate
///    additional member — see [`crate::store::Store::insert_checkpoint`]).
///
/// Steps 3 and 4 run inside one `SQLite` transaction (the crate-private
/// `Store::with_transaction`): a batch
/// that fails partway — a bad proof on the third of five `entries_to_promote`, say — leaves
/// the store exactly as it was before the call, never partially promoted. Steps 1 and 2 are
/// read-only (governance resolution, signature verification) and need no such wrapping.
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

    store.with_transaction(|conn| {
        for pending in entries_to_promote {
            crate::ingest::promote_entry_in(
                conn,
                cp,
                &pending.entry_id,
                pending.leaf_index,
                &pending.inclusion_path,
            )?;
        }

        if let Ok(leaf_hashes) = leaf_hashes_for_conn(conn, cp.tree_size) {
            if compute_root(&leaf_hashes) != claimed_root {
                return Err(MirrorError::CheckpointRootMismatch { tree_size: cp.tree_size });
            }
        }

        crate::store::insert_checkpoint_raw(conn, cp)?;
        Ok(())
    })
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
/// slice, per core spec §7.3's "Series completeness" and "Which version governs" paragraphs,
/// quoted here verbatim because they are normative rather than an inferred reading:
///
/// - "A published checkpoint series is **gap-free over a range** iff, within that range:
///   every adjacent pair satisfies the cadence rule above; `checkpoint_time` is non-decreasing
///   across the series (a decreasing time is a violation and a finding, never a zero-length
///   gap); and the range begins at `cadence_epoch` — the single start of the obligation,
///   judged under the genesis manifest version's cadence since no earlier version exists to
///   govern it. The epoch is not free-floating: the earliest checkpoint committing the genesis
///   manifest MUST carry a `checkpoint_time` that is at or after `cadence_epoch` and no later
///   than `cadence_epoch` plus that version's `checkpoint_cadence`. An epoch preceding that
///   window would reach back over an interval the corpus did not exist for; an epoch following
///   it would leave the corpus's opening interval unjudged. (A corpus's *genesis checkpoint* —
///   the checkpoint whose `tree_size` equals the genesis manifest's entry index plus one — need
///   not be published, and is not a start point.)";
/// - "A gap that straddles a cadence change is judged under the version governing its
///   **earlier** member, so every interval is judged by the cadence in force when it began.";
/// - "members sharing a `tree_size` MUST carry the same `root_hash`" (the ordering paragraph;
///   see [`SeriesView::root_divergences`], computed separately in [`series_view`], since it
///   applies to authenticated members generally, not only the series-usable subset this
///   function walks) — and "Equivocation ends the series": "from the lowest `tree_size` at
///   which it occurs, the series is no longer canonical: no incorporation bound, enumeration
///   response or completeness claim may be grounded at or beyond that point … Members below
///   the divergence remain usable." `equivocation_floor` (the lowest divergent `tree_size`,
///   `None` if there is none) implements exactly this: frontier extension refuses to start at
///   or reach a member whose `tree_size >= equivocation_floor`, so `gap_free_frontier` (and
///   therefore [`itub`]) never grounds anything at or beyond it, while members strictly below
///   it are judged exactly as before.
///
/// "`checkpoint_cadence` values are compared by normalized value, not by spelling: `PT60M` and
/// `PT1H` are the same cadence. A later manifest version repeating `cadence_epoch` repeats it
/// by value." — [`crate::manifest::GovernanceState`] already stores every duration and
/// timestamp field as parsed nanoseconds, so every comparison below is a plain `u64`
/// comparison, never a string comparison.
///
/// `usable`'s first member is, by construction, always the earliest series-usable checkpoint
/// committing the genesis manifest: governance resolves at `first.tree_size` only if the
/// genesis manifest entry lies within `[0, first.tree_size)`, so `genesis_entry_index + 1 <=
/// first.tree_size` always holds, and `usable` is ascending, so no earlier series-usable
/// member could also commit it.
fn compute_gap_free_frontier(
    store: &Store,
    config: &Config,
    usable: &[Checkpoint],
    equivocation_floor: Option<u64>,
) -> MirrorResult<GapFreeResult> {
    // No future arrival of entries or checkpoints can un-equivocate a log that already
    // published two conflicting roots (core spec §7.3): once `equivocation_floor` is known,
    // it is the reason nothing at or beyond it will ever be reported clean — not silence —
    // even where a plain lack of series-usable members would otherwise explain the stop just
    // as well. This governs both early returns below (`usable` empty, or its first member
    // already at or beyond the floor) and the "reached the end of `usable` cleanly" case at
    // the bottom of this function.
    let equivocation_stop =
        equivocation_floor.map(|floor| FrontierStop::Equivocation { at_tree_size: floor });

    let Some(first) = usable.first() else {
        return Ok(GapFreeResult { frontier: None, stop: equivocation_stop });
    };

    if let Some(floor) = equivocation_floor {
        if first.tree_size >= floor {
            return Ok(GapFreeResult { frontier: None, stop: equivocation_stop });
        }
    }

    let Some(first_governance) = resolve_governance_for(store, config, first.tree_size)? else {
        return Ok(GapFreeResult {
            frontier: None,
            stop: Some(FrontierStop::GovernanceUnresolvable { at_tree_size: first.tree_size }),
        });
    };
    let genesis_entry_index = first_governance.genesis_entry_index();
    // The genesis checkpoint's `tree_size`. `genesis_entry_index` is a position in this
    // store's own canonical entry sequence, so the successor exists for every log this
    // deployment can hold; a store large enough to make it overflow could not be addressed.
    let genesis_tree_size = genesis_entry_index
        .checked_add(1)
        .ok_or(MirrorError::IndexOverflow { what: "genesis_entry_index" })?;
    let Some(genesis_governance) = resolve_governance_for(store, config, genesis_tree_size)? else {
        return Ok(GapFreeResult {
            frontier: None,
            stop: Some(FrontierStop::GovernanceUnresolvable { at_tree_size: genesis_tree_size }),
        });
    };
    let epoch_nanos = genesis_governance.cadence_epoch_nanos();
    let genesis_cadence_nanos = genesis_governance.cadence_nanos();

    // The series' one and only start: `first` (the earliest checkpoint committing the genesis
    // manifest, among series-usable members) MUST fall within the genesis version's cadence
    // window of `cadence_epoch` — core spec §7.3. Neither earlier (reaching back over an
    // interval the corpus did not exist for) nor later (leaving the opening interval
    // unjudged) is valid; the genesis checkpoint's `tree_size` plays no role in this check.
    let first_time = parse_checkpoint_time(&first.checkpoint_time)?;
    // `checked_sub` carries the "not earlier than the epoch" half of the window test: `None`
    // is exactly `first_time < epoch_nanos`.
    let starts_within_epoch_window =
        first_time.checked_sub(epoch_nanos).is_some_and(|since| since <= genesis_cadence_nanos);
    if !starts_within_epoch_window {
        return Ok(GapFreeResult { frontier: None, stop: Some(FrontierStop::NoValidStart) });
    }

    let mut frontier = first.tree_size;
    let mut prev = first;
    let mut prev_time = first_time;
    // `first` was taken off the front above, so the remaining members start at index 1.
    for cp in usable.iter().skip(1) {
        if let Some(floor) = equivocation_floor {
            if cp.tree_size >= floor {
                return Ok(GapFreeResult { frontier: Some(frontier), stop: equivocation_stop });
            }
        }
        let cp_time = parse_checkpoint_time(&cp.checkpoint_time)?;
        // `checked_sub` is also the monotonicity test: `None` is exactly `cp_time <
        // prev_time`, which stops the series here rather than measuring a cadence backwards.
        let Some(delta) = cp_time.checked_sub(prev_time) else {
            return Ok(GapFreeResult {
                frontier: Some(frontier),
                stop: Some(FrontierStop::DecreasingTime { after_tree_size: prev.tree_size }),
            });
        };
        let Some(prev_governance) = resolve_governance_for(store, config, prev.tree_size)? else {
            return Ok(GapFreeResult {
                frontier: Some(frontier),
                stop: Some(FrontierStop::GovernanceUnresolvable { at_tree_size: prev.tree_size }),
            });
        };
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
    Ok(GapFreeResult { frontier: Some(frontier), stop: equivocation_stop })
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
    let root_divergences = find_root_divergences(&all);
    let equivocation_floor = root_divergences.iter().min().copied();
    let GapFreeResult { frontier: gap_free_frontier, stop: frontier_stop } =
        compute_gap_free_frontier(store, config, &usable_checkpoints, equivocation_floor)?;

    Ok(SeriesView {
        members,
        gap_free_frontier,
        frontier_stop,
        root_divergences,
        equivocation_floor,
    })
}

/// `ITUB(index)`: the series-usable checkpoint with the smallest `tree_size > index`, but
/// only if it falls within `view`'s gap-free frontier (core spec §7.3, §5.2.1-§5.2.2).
///
/// Where that `tree_size` carries several series-usable members (a quiet log republishing at
/// unchanged `tree_size`), the one with the **earliest** `checkpoint_time` governs — the
/// tightest bound the series supports (core spec §7.3). `view.members` is already ordered
/// `(tree_size, checkpoint_time)` ascending (see the module docs), so the first match
/// `.find()` reaches is exactly that member; this function does not re-sort or otherwise
/// select among ties itself.
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
    fn a_non_digit_in_the_subsecond_field_is_rejected_not_a_panic() {
        // Found by the `text` and `checkpoint` fuzz targets. The datetime parser's subsecond
        // combinator is told to expect nine digits and derives a width by subtracting what it
        // consumed, which underflows on anything shorter — so these reached an abort rather
        // than a rejection before the shape check ran first. `checkpoint_time` comes out of a
        // request body, so this is an ordinary input to `POST /v1/checkpoints`.
        assert!(parse_checkpoint_time("2026-01-01T00:01:00.0000&0000Z").is_err());
        assert!(parse_checkpoint_time("2026-01-01T00:01:00.000&0000Z").is_err());
        assert!(parse_checkpoint_time("2026-01-01T00:01:00.00+0000000Z").is_err());
        assert!(parse_checkpoint_time("2026-01-01T00:01:00.        Z").is_err());
        // A well-formed value still parses, and still round-trips.
        assert!(parse_checkpoint_time("2026-01-01T00:01:00.000000000Z").is_ok());
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
            "ahl_version": ahl_core::AHL_VERSION,
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
                "ahl_version": ahl_core::AHL_VERSION,
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
                "ahl_version": ahl_core::AHL_VERSION,
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
                "ahl_version": ahl_core::AHL_VERSION,
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

    // ---- round 4.5 (commit 9962750): the series has exactly one start, `cadence_epoch` ----

    #[test]
    fn a_checkpoint_at_the_genesis_checkpoint_size_outside_the_epoch_window_does_not_start_the_series(
    ) {
        // Core spec §7.3: "the genesis checkpoint is no longer an alternative start point —
        // it need never have been published, so it cannot anchor anything." This checkpoint
        // sits exactly at the genesis checkpoint's `tree_size` (genesis_entry_index + 1 = 1),
        // which the now-superseded reading of the spec would have accepted regardless of
        // `checkpoint_time`. Under the current text, only the epoch window matters, and this
        // checkpoint's time (one hour after epoch, cadence five minutes) falls well outside it.
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"86".repeat(32)).expect("seed");
        let fx = fixture(&log_key, "2026-01-01T00:00:00Z"); // genesis cadence: 5 minutes
        let leaves = [log_leaf_hash(&fx.store.get_entries_range(0, 1).expect("range")[0])];
        let root = compute_root(&leaves);
        let cp =
            checkpoint_for(&log_key, &fx.config.log_id, 1, root, "2026-01-01T01:00:00.000000000Z");

        ingest_checkpoint(&fx.store, &fx.config, &cp, None, &[])
            .expect("authentication does not require a valid series start");
        let view = series_view(&fx.store, &fx.config).expect("view");
        assert_eq!(view.members[0].state, CheckpointState::SeriesUsable);
        assert_eq!(view.gap_free_frontier, None);
        assert_eq!(view.frontier_stop, Some(FrontierStop::NoValidStart));
    }

    #[test]
    fn the_series_may_start_at_any_series_usable_member_within_the_epoch_window_not_only_the_genesis_checkpoint(
    ) {
        // Core spec §7.3: the genesis checkpoint "need not be published, and is not a start
        // point." Here no checkpoint is ever published at tree_size 1 (the genesis checkpoint
        // size); the series starts directly at tree_size 2, whose checkpoint_time still falls
        // within the genesis version's cadence window of `cadence_epoch`.
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"87".repeat(32)).expect("seed");
        let fx = fixture(&log_key, "2026-01-01T00:00:00Z"); // genesis cadence: 5 minutes
        let genesis_leaf = log_leaf_hash(&fx.store.get_entries_range(0, 1).expect("range")[0]);

        let second = stored_entry(serde_json::json!({ "n": 1 }), &fx.producer);
        let root = compute_root(&[genesis_leaf, log_leaf_hash(&second)]);
        stage_and_promote_at(&fx.store, 2, root, &[second], 1);
        let cp =
            checkpoint_for(&log_key, &fx.config.log_id, 2, root, "2026-01-01T00:01:00.000000000Z");
        ingest_checkpoint(&fx.store, &fx.config, &cp, None, &[])
            .expect("admits: the genesis checkpoint itself was never published");

        let view = series_view(&fx.store, &fx.config).expect("view");
        assert_eq!(view.gap_free_frontier, Some(2));
        assert_eq!(view.frontier_stop, None);
    }

    #[test]
    fn checkpoints_sharing_a_tree_size_with_different_roots_are_a_root_divergence_finding() {
        // Core spec §7.3: "members sharing a `tree_size` MUST carry the same `root_hash`; a
        // divergent root at equal size is a finding." Neither checkpoint's full range is held
        // yet (only the genesis entry exists), so the opportunistic root-mismatch check in
        // `ingest_checkpoint` cannot catch a bad root at admission time — both are merely
        // authenticated, which is exactly the situation a purely-metadata divergence check
        // exists for.
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"88".repeat(32)).expect("seed");
        let fx = fixture(&log_key, "2026-01-01T00:00:00Z");
        let cp_a = checkpoint_for(
            &log_key,
            &fx.config.log_id,
            2,
            [0x01u8; 32],
            "2026-01-01T00:01:00.000000000Z",
        );
        let cp_b = checkpoint_for(
            &log_key,
            &fx.config.log_id,
            2,
            [0x02u8; 32],
            "2026-01-01T00:02:00.000000000Z",
        );
        ingest_checkpoint(&fx.store, &fx.config, &cp_a, None, &[])
            .expect("admits: entries not yet complete for tree_size 2");
        ingest_checkpoint(&fx.store, &fx.config, &cp_b, None, &[])
            .expect("admits: same reason, and a different checkpoint_time avoids the series-member conflict check");

        let view = series_view(&fx.store, &fx.config).expect("view");
        assert_eq!(view.root_divergences, vec![2]);
    }

    // ---- round 4: batch checkpoint admission is transactional ----

    #[test]
    fn a_batch_failing_on_its_last_entry_leaves_the_store_byte_identical() {
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"89".repeat(32)).expect("seed");
        let fx = fixture(&log_key, "2026-01-01T00:00:00Z");
        let genesis_leaf = log_leaf_hash(&fx.store.get_entries_range(0, 1).expect("range")[0]);

        let e1 = stored_entry(serde_json::json!({ "n": 1 }), &fx.producer);
        let e2 = stored_entry(serde_json::json!({ "n": 2 }), &fx.producer);
        let e3 = stored_entry(serde_json::json!({ "n": 3 }), &fx.producer);
        let leaves = [genesis_leaf, log_leaf_hash(&e1), log_leaf_hash(&e2), log_leaf_hash(&e3)];
        let root = compute_root(&leaves);
        let cp =
            checkpoint_for(&log_key, &fx.config.log_id, 4, root, "2026-01-01T00:01:00.000000000Z");

        fx.store.stage_entry(&entry_id_of(&e1), &e1).expect("stage e1");
        fx.store.stage_entry(&entry_id_of(&e2), &e2).expect("stage e2");
        fx.store.stage_entry(&entry_id_of(&e3), &e3).expect("stage e3");

        let proof_for = |index: u64| {
            let proof = atl_core::core::merkle::generate_inclusion_proof(index, 4, |level, at| {
                if level == 0 {
                    leaves.get(usize::try_from(at).ok()?).copied()
                } else {
                    None
                }
            })
            .expect("index within tree");
            ahl_core::proof_path_hex(&proof)
        };

        let pending = vec![
            PendingPromotion {
                entry_id: entry_id_of(&e1),
                leaf_index: 1,
                inclusion_path: proof_for(1),
            },
            PendingPromotion {
                entry_id: entry_id_of(&e2),
                leaf_index: 2,
                inclusion_path: proof_for(2),
            },
            // The batch's LAST item: it claims the SAME position as e2 above. Because e2's
            // pending entry lists first and genuinely fills that slot, `build_visible_prefix`
            // treats this one as an already-filled, uninspected duplicate and never checks its
            // proof (see its docs: "already canonical; a tentative duplicate is not
            // consulted") — so nothing catches this before the transaction opens. Only inside
            // it, when `promote_entry_in` genuinely tries to promote e3 at e2's position, does
            // e3's proof fail to open the root (it was built for e2's leaf, not e3's) — after
            // e1 and e2 have already been promoted within that same, still-uncommitted
            // transaction.
            PendingPromotion {
                entry_id: entry_id_of(&e3),
                leaf_index: 2,
                inclusion_path: proof_for(2),
            },
        ];

        let next_index_before = fx.store.next_index().expect("query");
        let entries_before = fx.store.get_entries_range(0, next_index_before).expect("query");
        let checkpoints_before = fx.store.all_checkpoints().expect("query");

        let result = ingest_checkpoint(&fx.store, &fx.config, &cp, None, &pending);
        assert!(result.is_err(), "e3's proof, built for e2's leaf, must not open the root");

        assert_eq!(fx.store.next_index().expect("query"), next_index_before);
        assert_eq!(
            fx.store.get_entries_range(0, next_index_before).expect("query"),
            entries_before,
            "e1 and e2, promoted earlier in the same failed transaction, must not persist"
        );
        assert_eq!(fx.store.all_checkpoints().expect("query"), checkpoints_before);
    }

    // ---- round 5 (commit 82b96c0): equivocation is a hard boundary, not a mere finding ----

    #[test]
    fn equivocation_leaves_members_below_the_floor_usable_and_refuses_at_and_beyond_it() {
        // Core spec §7.3: "Equivocation ends the series ... From the lowest tree_size at
        // which it occurs, the series is no longer canonical ... Members below the divergence
        // remain usable."
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"8a".repeat(32)).expect("seed");
        let fx = fixture(&log_key, "2026-01-01T00:00:00Z");
        let genesis_leaf = log_leaf_hash(&fx.store.get_entries_range(0, 1).expect("range")[0]);
        let root_1 = compute_root(&[genesis_leaf]);
        let cp_1 = checkpoint_for(
            &log_key,
            &fx.config.log_id,
            1,
            root_1,
            "2026-01-01T00:00:00.000000000Z",
        );
        ingest_checkpoint(&fx.store, &fx.config, &cp_1, None, &[]).expect("admits");

        // Two authenticated checkpoints at tree_size 2 disagree on root_hash — equivocation,
        // not a tie. Detected regardless of whether this mirror holds entries for tree_size 2
        // at all (it does not, here): purely a metadata comparison.
        let branch_a = checkpoint_for(
            &log_key,
            &fx.config.log_id,
            2,
            [0x01u8; 32],
            "2026-01-01T00:01:00.000000000Z",
        );
        let branch_b = checkpoint_for(
            &log_key,
            &fx.config.log_id,
            2,
            [0x02u8; 32],
            "2026-01-01T00:02:00.000000000Z",
        );
        ingest_checkpoint(&fx.store, &fx.config, &branch_a, None, &[]).expect("admits");
        ingest_checkpoint(&fx.store, &fx.config, &branch_b, None, &[]).expect("admits");

        let view = series_view(&fx.store, &fx.config).expect("view");
        assert_eq!(view.root_divergences, vec![2]);
        assert_eq!(view.equivocation_floor, Some(2));
        // Below the floor: the genesis-only checkpoint still grounds the gap-free frontier.
        assert_eq!(view.gap_free_frontier, Some(1));
        assert_eq!(view.frontier_stop, Some(FrontierStop::Equivocation { at_tree_size: 2 }));

        // ITUB below the floor still answers...
        assert_eq!(itub(&view, 0).map(|cp| cp.tree_size), Some(1));
        // ...but refuses at or beyond it, rather than silently picking cp_2a or cp_2b.
        assert!(itub(&view, 1).is_none());
    }
}
