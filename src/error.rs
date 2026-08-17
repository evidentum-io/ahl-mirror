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

    /// No checkpoint with this `tree_size` is in the canonical series.
    #[error("no checkpoint with tree_size {tree_size} is in the canonical checkpoint series")]
    UnknownCheckpoint {
        /// The requested tree size.
        tree_size: u64,
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

    /// The stored entries for `[0, tree_size)` do not recompute to the checkpoint's
    /// `root_hash`. A storage integrity fault; never served to a caller.
    #[error("stored entries for tree_size {tree_size} do not recompute to its root_hash")]
    CheckpointRootMismatch {
        /// The tree size whose root failed to recompute.
        tree_size: u64,
    },

    // ---- checkpoints (adaptor profile §5.2.2, §6) ----
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

    /// A checkpoint is signed by a key this mirror does not trust.
    #[error("checkpoint signed by untrusted key `{key_id}`")]
    UnknownSigningKey {
        /// The untrusted `key_id`.
        key_id: String,
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

    /// A new checkpoint's `tree_size` does not strictly exceed the series' current maximum
    /// (adaptor profile §5.2.2 item 4: append-only, ordered by `tree_size`).
    #[error("checkpoint tree_size {got} does not exceed the series maximum {maximum}")]
    NonMonotonicTreeSize {
        /// The series' current maximum `tree_size`.
        maximum: u64,
        /// The submitted checkpoint's `tree_size`.
        got: u64,
    },

    /// A new checkpoint is not consistent with the series' predecessor — the gap-free
    /// requirement of adaptor profile §5.2.2 item 1 cannot be met.
    #[error(
        "checkpoint at tree_size {tree_size} is not consistent with the predecessor at {predecessor_tree_size}"
    )]
    InconsistentWithPredecessor {
        /// The predecessor's `tree_size`.
        predecessor_tree_size: u64,
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
