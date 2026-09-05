//! Error type for `ahl-mirror`.

use thiserror::Error;

/// Convenience alias for results carrying [`MirrorError`].
pub type MirrorResult<T> = core::result::Result<T, MirrorError>;

/// Errors produced by `ahl-mirror`.
///
/// Every variant names the specific check that failed rather than collapsing into a generic
/// "invalid entry" — the ingest and verification paths depend on a caller being able to tell
/// *which* profile requirement was violated (core spec §2.1, §2.5; adaptor profile §4.2,
/// §5.2.2, §6, §10.1.1, §10.4).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MirrorError {
    // ---- ingest (adaptor profile §10.1.1 prerequisites; core spec §2.1) ----
    /// The submitted bytes do not hash to the claimed AHL entry id.
    #[error("submitted bytes hash to `{computed}`, not the claimed entry id `{claimed}`")]
    EntryIdMismatch {
        /// The entry id the caller claimed.
        claimed: String,
        /// The entry id actually computed from the bytes.
        computed: String,
    },

    /// The submitted bytes parse as JSON but are not envelope-shaped (core spec §2.1: an
    /// object with a `payload` object and a non-empty `signatures` array).
    #[error("not an AHL envelope: {reason}")]
    MalformedEnvelope {
        /// Which structural requirement was missing.
        reason: &'static str,
    },

    /// The submitted bytes parse as a well-formed envelope but do not re-serialize to
    /// themselves under JCS — they are not canonical (core spec §2.4, RFC 8785).
    #[error("submitted bytes are not JCS-canonical")]
    NotCanonical,

    /// The submitted ATL metadata is not the fixed adaptor metadata object (adaptor
    /// profile §4.2).
    #[error("ATL metadata `{got}` is not the fixed adaptor metadata object")]
    WrongAdaptorMetadata {
        /// The (JCS-canonical, lossily-rendered) metadata bytes actually submitted.
        got: String,
    },

    /// `entry_index` is not the next index this mirror expects (append-only ingest).
    #[error("entry index {got} is out of order; the next expected index is {expected}")]
    OutOfOrderIndex {
        /// The index the mirror expects next.
        expected: u64,
        /// The index actually submitted.
        got: u64,
    },

    /// `entry_index` is already occupied by different bytes than the ones submitted.
    #[error("entry index {index} already holds entry `{existing_entry_id}`, not `{new_entry_id}`")]
    IndexConflict {
        /// The conflicting index.
        index: u64,
        /// The entry id already stored at that index.
        existing_entry_id: String,
        /// The entry id the caller attempted to store there.
        new_entry_id: String,
    },

    /// The submitted entry id is already stored under a different index than the one
    /// submitted (content-addressing requires one index per entry id).
    #[error(
        "entry `{entry_id}` is already stored at index {existing_index}, not {requested_index}"
    )]
    EntryIdAtDifferentIndex {
        /// The entry id in question.
        entry_id: String,
        /// The index it is already stored at.
        existing_index: u64,
        /// The index the caller attempted to store it at.
        requested_index: u64,
    },

    // ---- staging and promotion (fix for admission without evidence of anchoring) ----
    /// No staged candidate with this entry id exists; it must be staged before it can be
    /// promoted.
    #[error("no staged entry `{entry_id}`; stage it before promoting it")]
    NotStaged {
        /// The entry id that was not found in staging.
        entry_id: String,
    },

    /// The inclusion proof offered for a staged entry does not verify against the named
    /// checkpoint's root. Unverified bytes are never admitted to canonical storage on the
    /// strength of a claim alone (adaptor profile §8.2; core spec §3 contract item 3).
    #[error("inclusion proof for `{entry_id}` at index {leaf_index} does not verify under tree_size {tree_size}")]
    InclusionProofInvalid {
        /// The entry id whose inclusion was claimed.
        entry_id: String,
        /// The claimed entry index.
        leaf_index: u64,
        /// The checkpoint's tree size the proof was checked against.
        tree_size: u64,
    },

    // ---- retrieval (adaptor profile §10.1.1) ----
    /// Bytes on disk no longer hash to the entry id they are filed under. A storage
    /// integrity fault; never served to a caller as if it were the entry.
    #[error("stored bytes for `{entry_id}` no longer hash to that id")]
    StoredEntryCorrupt {
        /// The entry id whose stored bytes failed the defensive re-check.
        entry_id: String,
    },

    // ---- range enumeration (adaptor profile §10.2-10.5) ----
    /// `[from_index, to_index)` is not a non-empty sub-range of `[0, tree_size)`.
    #[error("range [{from_index}, {to_index}) is not a non-empty sub-range of [0, {tree_size})")]
    InvalidRange {
        /// Requested start, inclusive.
        from_index: u64,
        /// Requested end, exclusive.
        to_index: u64,
        /// The checkpoint's tree size.
        tree_size: u64,
    },

    /// A consistency proof was requested from a larger tree to a smaller one.
    ///
    /// RFC 9162 §2.1.4 defines the proof for `from ≤ to` only; the trivial `from == to`
    /// proof (an empty path) is served, the reverse order is the client's error.
    #[error("consistency proof from tree_size {from} to tree_size {to} is not from ≤ to")]
    ConsistencyOrder {
        /// Requested first tree size.
        from: u64,
        /// Requested second tree size.
        to: u64,
    },

    /// No checkpoint with this `tree_size` is authenticated at all.
    #[error("no authenticated checkpoint with tree_size {tree_size}")]
    UnknownCheckpoint {
        /// The requested tree size.
        tree_size: u64,
    },

    /// A checkpoint with this `tree_size` exists but is not (yet) series-usable — core spec
    /// §7.3 permits only series-usable checkpoints to ground an enumeration response, an
    /// incorporation-time bound, or a completeness claim.
    #[error("checkpoint with tree_size {tree_size} is authenticated but not series-usable")]
    CheckpointNotSeriesUsable {
        /// The requested tree size.
        tree_size: u64,
    },

    /// `tree_size` is at or beyond the series' equivocation floor: two authenticated members
    /// share some `tree_size <= this one` with different `root_hash` values, which core spec
    /// §7.3 calls equivocation, not a tie. From the floor onward the series is no longer
    /// canonical, so nothing may be grounded here — never served by silently picking a branch
    /// (core spec §7.3: "Detecting equivocation and then continuing to serve one branch is a
    /// conformance violation").
    #[error(
        "tree_size {tree_size} cannot ground a completeness claim: the series equivocates at \
         tree_size {floor}"
    )]
    SeriesEquivocated {
        /// The `tree_size` a caller asked to ground something at.
        tree_size: u64,
        /// The lowest `tree_size` at which two authenticated members diverge in `root_hash`.
        floor: u64,
    },

    /// Fewer entries are stored than the checkpoint commits; a range proof under it cannot
    /// be built until the gap is filled (adaptor profile §10.3, §10.4).
    #[error("checkpoint commits {need} entries but only {have} are stored")]
    IncompleteEntries {
        /// Entries actually stored, contiguously from index 0.
        have: u64,
        /// Entries the checkpoint's `tree_size` commits.
        need: u64,
    },

    /// A node of the log tree the store should hold is absent: an entry row carrying no log
    /// leaf hash (`level` 0), or a complete-subtree root missing from the cache. Both are
    /// derived from entry bytes the store already holds and are rebuilt by the migration on
    /// open, so an absence at serving time is a storage integrity fault, not a client mistake.
    #[error("log tree material at level {level}, node {node_index} is missing from the store")]
    TreeMaterialMissing {
        /// The tree level (0 for a leaf hash).
        level: u32,
        /// The node's index at that level.
        node_index: u64,
    },

    /// A stored log-tree node is present but is not 32 octets. A storage integrity fault.
    #[error("log tree material at level {level}, node {node_index} is not a 32-octet hash")]
    TreeMaterialCorrupt {
        /// The tree level (0 for a leaf hash).
        level: u32,
        /// The node's index at that level.
        node_index: u64,
    },

    /// The stored entries for `[0, tree_size)` do not recompute to the checkpoint's
    /// `root_hash`. A storage integrity fault; never served to a caller.
    #[error("stored entries for tree_size {tree_size} do not recompute to its root_hash")]
    CheckpointRootMismatch {
        /// The tree size whose root failed to recompute.
        tree_size: u64,
    },

    // ---- checkpoints (adaptor profile §5.2.2, §6) ----
    /// A checkpoint claimed a `tree_size` larger than this mirror could ever address.
    ///
    /// Entry indices are stored as `SQLite` `INTEGER`, so `i64::MAX` bounds the index space
    /// that exists here at all. A claim above it is malformed rather than merely unmet — no
    /// store could hold it — and is refused before any of it is read or allocated for.
    #[error("`tree_size` {tree_size} exceeds the largest addressable log size {max}")]
    TreeSizeUnrepresentable {
        /// The `tree_size` the checkpoint claimed.
        tree_size: u64,
        /// The largest `tree_size` this mirror can address.
        max: u64,
    },

    /// A `checkpoint_time` value is not the exact nine-fractional-digit RFC 3339 rendering
    /// adaptor profile §6.3 requires.
    #[error("`{value}` is not a valid adaptor-profile §6.3 checkpoint_time")]
    BadCheckpointTime {
        /// The value as submitted.
        value: String,
    },

    /// A checkpoint's `log_id` does not match the log this mirror is configured for.
    #[error("checkpoint log_id `{got}` does not match the configured log_id `{expected}`")]
    WrongLogId {
        /// The configured `log_id`.
        expected: String,
        /// The `log_id` carried by the checkpoint.
        got: String,
    },

    /// A checkpoint is signed by a key this mirror does not trust — not present in the
    /// active governance snapshot (genesis configuration, or the manifest version active
    /// for the checkpoint's `tree_size`; adaptor profile §7.3).
    #[error("checkpoint signed by untrusted key `{key_id}`")]
    UnknownSigningKey {
        /// The untrusted `key_id`.
        key_id: String,
    },

    /// The resolved key exists but is not yet active at this checkpoint's `tree_size`
    /// (adaptor profile §7.3 activation bound: `valid_from_index`).
    #[error("key `{key_id}` is not valid until index {valid_from_index}, checkpoint tree_size is {tree_size}")]
    KeyNotYetActive {
        /// The key in question.
        key_id: String,
        /// The index the key becomes valid at.
        valid_from_index: u64,
        /// The checkpoint's `tree_size`.
        tree_size: u64,
    },

    /// No verified governance snapshot (genesis manifest plus every subsequent verified
    /// `manifest`/`key` statement) can be established up to this `tree_size` — either
    /// because entries are not yet visible that far, or because no valid genesis manifest
    /// (signature-verified against the configured out-of-band anchor) has been found. Refused
    /// rather than resolved from an older or partial snapshot (core spec §7.3).
    #[error("governance chain is not resolvable up to tree_size {tree_size}")]
    GovernanceChainUnresolvable {
        /// The `tree_size` governance resolution was attempted for.
        tree_size: u64,
    },

    /// A governance statement that is otherwise authentic declares an `ahl_version` this
    /// revision does not verify — or declares none at all.
    ///
    /// I-D §2.2 and §7.1: revision 0.4 verifies no material issued under an earlier revision,
    /// and §7.5 step 1 orders the read "version first, then parse". A `manifest` or `key`
    /// statement whose producer signature has already verified under the key set in force is
    /// therefore read for its declared revision before its content is allowed to establish
    /// anything, and a statement declaring anything other than [`ahl_core::AHL_VERSION`] is
    /// refused here rather than skipped: skipping would silently leave the previous governance
    /// version in force, which is a decision about material this revision has no rules for.
    /// The check runs only after the signature verifies, so an unsigned or forged entry of type
    /// `manifest` cannot abort a walk by declaring an old revision.
    #[error(
        "governance statement at entry index {entry_index} declares ahl_version `{}`, but this \
         revision verifies only `{expected}` (I-D §2.2, §7.1)",
        declared.as_deref().unwrap_or("(absent)")
    )]
    UnsupportedStatementVersion {
        /// The entry index the statement was read at.
        entry_index: u64,
        /// The `ahl_version` the statement declared, or `None` if it declared none.
        declared: Option<String>,
        /// The revision this build verifies: [`ahl_core::AHL_VERSION`].
        expected: &'static str,
    },

    /// A duration string is not a well-formed ISO 8601 duration of the time-only subset core
    /// spec §7.3 requires (`P[n]DT[n]H[n]M[n]S`).
    #[error("`{value}` is not a valid ISO 8601 duration")]
    BadDuration {
        /// The value as submitted.
        value: String,
    },

    /// A duration string carries a calendar component (`Y`, or `M` in the date part) core
    /// spec §7.3 PROHIBITS in `checkpoint_cadence`/`witness_grace_period`, because years and
    /// calendar months have no fixed length — admitting them would make cadence, frontier,
    /// completeness and incorporation bounds implementation-dependent. Rejected outright,
    /// never approximated.
    #[error("`{value}` carries a prohibited calendar component (`{component}`); core spec §7.3 restricts durations to days/hours/minutes/seconds")]
    ProhibitedDurationComponent {
        /// The value as submitted.
        value: String,
        /// Which prohibited component was found (`'Y'` or `'M'`).
        component: char,
    },

    /// A duration's fractional-seconds component carries more than nine digits — core spec
    /// §7.3 allows "at most nine digits"; a value with more is malformed and MUST be
    /// rejected, never truncated or rounded, since either would make the parsed value
    /// implementation-dependent in exactly the way the calendar-component restriction above
    /// exists to prevent (a different conformant parser could reject, round, or truncate the
    /// same input to a different nanosecond total).
    #[error("`{value}` carries more than nine fractional-second digits")]
    DurationFractionTooLong {
        /// The value as submitted.
        value: String,
    },

    /// `checkpoint_cadence` parses to zero nanoseconds — core spec §7.3 requires it to be
    /// greater than zero: a zero-length cadence is not a maximum-gap obligation at all, and
    /// would make every interval trivially "exceeded" or trivially satisfied depending on
    /// implementation, exactly the kind of implementation-dependence the duration rules exist
    /// to foreclose.
    #[error("`{value}` is not a valid checkpoint_cadence: it MUST be greater than zero")]
    NonPositiveCadence {
        /// The value as submitted.
        value: String,
    },

    /// A `cadence_epoch` value is not a valid RFC 3339 timestamp (core spec §7.3 schema).
    #[error("`{value}` is not a valid RFC 3339 cadence_epoch")]
    BadCadenceEpoch {
        /// The value as submitted.
        value: String,
    },

    /// A configuration's genesis producer key set is empty; no governance chain can ever
    /// start without at least one out-of-band trusted producer key (core spec §2.3.5).
    #[error("configuration declares no genesis producer keys")]
    NoGenesisProducerKeys,

    /// A checkpoint that did not verify under the state active for its own `tree_size` is
    /// not ROTATION-ANCHORING material either, so I-D §7.1's transition exception does not
    /// reach it.
    ///
    /// Never the error a submission is refused with: the exception is a second chance, so a
    /// checkpoint that fails it is reported with the failure it earned under the ordinary rule
    /// (see [`crate::checkpoint::ingest_checkpoint`]). This variant names why the second chance
    /// did not apply, for the caller that asks the classification directly.
    #[error(
        "checkpoint at tree_size {tree_size} is not rotation-anchoring material for the \
         manifest at entry index {manifest_entry_index}: {reason}"
    )]
    NotRotationMaterial {
        /// The submitted checkpoint's `tree_size`.
        tree_size: u64,
        /// The entry index of the manifest version active for that `tree_size`.
        manifest_entry_index: u64,
        /// Which condition of I-D §7.1 was not met.
        reason: &'static str,
    },

    /// No rotation-anchoring checkpoint is held for the rotation anchored at this entry index
    /// (I-D §7.1).
    #[error("no rotation-anchoring checkpoint is held for the manifest at entry index {manifest_entry_index}")]
    UnknownRotationProof {
        /// The requested rotating manifest's entry index.
        manifest_entry_index: u64,
    },

    /// A checkpoint's signature does not verify against its resolved key.
    #[error("checkpoint signature does not verify against key `{key_id}`")]
    SignatureInvalid {
        /// The key the signature was checked against.
        key_id: String,
    },

    /// `checkpoint.raw` does not match the blob assembled from the parsed checkpoint object
    /// (adaptor profile §6.4).
    #[error("checkpoint.raw does not match the assembled 98-byte blob")]
    RawBlobMismatch,

    /// A checkpoint with this `(tree_size, checkpoint_time)` is already recorded with
    /// different content (adaptor profile §5.2.2 item 4: append-only in publication — a
    /// published member is never withdrawn or replaced). A *different* `checkpoint_time` at
    /// the same `tree_size` is not a conflict — core spec §7.3 requires a quiet log to keep
    /// publishing checkpoints at unchanged `tree_size`, so repeated sizes are legitimate,
    /// distinct members.
    #[error(
        "tree_size {tree_size} at {checkpoint_time} is already recorded with different content"
    )]
    SeriesMemberConflict {
        /// The conflicting `tree_size`.
        tree_size: u64,
        /// The conflicting `checkpoint_time`.
        checkpoint_time: String,
    },

    /// A new checkpoint is not consistent with an already-admitted neighbour (predecessor
    /// or successor by `tree_size`) — the gap-free requirement of adaptor profile §5.2.2
    /// item 1 cannot be met.
    #[error("checkpoint at tree_size {tree_size} is not consistent with the neighbour at {neighbour_tree_size}")]
    InconsistentWithNeighbour {
        /// The neighbour's `tree_size`.
        neighbour_tree_size: u64,
        /// The new checkpoint's `tree_size`.
        tree_size: u64,
    },

    // ---- configuration ----
    /// A configured trusted key's `key_id` does not match the id recomputed from its
    /// `pubkey` (adaptor profile §7.2: a verifier MUST recompute, never trust the carried
    /// value).
    #[error("configured key_id `{configured}` does not match the id recomputed from pubkey: `{computed}`")]
    ConfigKeyIdMismatch {
        /// The `key_id` given in configuration.
        configured: String,
        /// The `key_id` recomputed from the configured public key.
        computed: String,
    },

    // ---- infrastructure ----
    /// A value that must fit a narrower integer type does not.
    #[error("{what} does not fit the required integer type")]
    IndexOverflow {
        /// What was being converted.
        what: &'static str,
    },

    /// JSON (de)serialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A primitive from `ahl-core` (family-string parsing, signature verification, JCS)
    /// failed.
    #[error("ahl-core error: {0}")]
    Ahl(#[from] ahl_core::AhlError),

    /// A Merkle operation delegated to `atl-core` failed.
    #[error("atl-core error: {0}")]
    Atl(#[from] atl_core::AtlError),

    /// The local store failed.
    #[error("store error: {0}")]
    Store(#[from] rusqlite::Error),

    /// The store could not be opened or migrated.
    #[error("store initialization failed: {0}")]
    StoreInit(String),
}
