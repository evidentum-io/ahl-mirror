//! Durable local storage.
//!
//! Staged (unverified) and canonical (proof-admitted) entry bytes, content-addressed by AHL
//! entry id and indexed by entry position, plus the canonical checkpoint series (adaptor
//! profile §5.2.2, §10).
//!
//! # Staging and canonical admission
//!
//! Bytes that merely pass the format checks of [`crate::ingest`] are not yet evidence of
//! anything the log actually anchored — a party with no authority over the log can submit
//! any canonical, correctly hashed envelope. Admitting such bytes straight into the
//! position-indexed table would let that party occupy an index permanently (the index is a
//! primary key; an occupied index can never be reused), which is a standing denial of
//! service against the entry the log actually anchored there.
//!
//! So there are two tables. `staged_entries` is keyed only by `entry_id` — content-addressed,
//! not index-exclusive, so any number of candidates may sit there without blocking each
//! other. `entries` is the canonical, index-keyed table; a row lands there only via
//! [`Store::promote_entry`], which the caller (see [`crate::ingest::promote_entry`]) may call
//! only after checking a Merkle inclusion proof of the staged bytes against a checkpoint
//! already trusted (signature-verified, per [`crate::checkpoint`]). Garbage staged under a
//! contested index simply never has a valid proof and is never promoted; it costs disk, not
//! the genuine entry's place in line.
//!
//! # Why `SQLite`
//!
//! The store needs three things a plain content-addressed directory does not give for free:
//! (1) an atomic, crash-safe link between "this entry index" and "these exact bytes" so
//! promotion can never leave a torn write behind; (2) an efficient "smallest `tree_size`
//! strictly greater than `i`" query for `ITUB` (adaptor profile §5.2.1); (3) an efficient
//! contiguous-range scan for enumeration (§10.3). A single-file `SQLite` database gives all
//! three with one dependency, no server process, and one file to back up — which is what
//! "simple durable local store" (task brief) asks for. Every row is still keyed by the AHL
//! entry id and the entry index exactly as the brief specifies; `SQLite` is the file format,
//! not an architectural commitment beyond that.
//!
//! # Rotation-anchoring checkpoints are stored apart
//!
//! `rotation_checkpoints` is a second, separate checkpoint table, and separateness is the
//! point. A rotation-anchoring checkpoint verifies under the OUTGOING log key set rather than
//! the state active for its own `tree_size` (I-D §7.1's transition exception), so it is not a
//! member of the canonical series and MUST NOT be served as one — not by `GET /v1/checkpoints`,
//! not as an `ITUB` bound, not as a consistency neighbour. Holding it in the same table as the
//! series and filtering on read would make every one of those call sites responsible for
//! remembering the distinction; holding it apart means none of them can forget. What the two
//! tables DO share is the equivocation scan (see [`crate::checkpoint::series_view`]): a
//! rotation-anchoring checkpoint that contradicts a series member at the same `tree_size` is a
//! divergence like any other.
//!
//! # Tree material beside the entries
//!
//! Two derived columns/tables exist so that an enumeration response costs `O(window + log n)`
//! reads rather than `O(n)` (adaptor profile §10.3-§10.5), and so that a root or a
//! consistency proof costs `O(log n)` reads and no entry bytes at all. Neither is authority:
//! both are recomputable from the entry bytes, and the migration below rebuilds either on
//! demand.
//!
//! - `entries.leaf_hash` holds each canonical entry's ATL log leaf hash (adaptor profile
//!   §4.2), written at promotion. Existing rows are backfilled once, on open.
//! - `subtree_roots` holds the root of every COMPLETE power-of-two subtree of the log tree
//!   (RFC 6962 geometry), for levels 1 and above; level 0 is `entries.leaf_hash` itself, so
//!   no hash is stored twice. A node at `(level, node_index)` covers the leaves
//!   `[node_index * 2^level, (node_index + 1) * 2^level)` and is written the moment that
//!   range becomes complete — which, because promotion is append-only and gap-free, is the
//!   promotion of its last leaf. `compute_subtree_root` then opens any span of the tree
//!   through these two, descending only the right spine.
//!
//! Every root and every proof this crate computes is opened through those two and nothing
//! else — `subtree_root_raw` and `log_root_raw` for a root, `inclusion_proof_raw` for an RFC
//! 6962 inclusion path, `consistency_proof_measured_raw` for an RFC 9162 consistency path
//! (the `&Connection` cores below, surfaced as [`Store::subtree_root`], [`Store::log_root`],
//! [`Store::inclusion_proof`] and [`Store::consistency_proof`]). No caller re-derives a leaf
//! hash from entry bytes to answer a question about the tree: entry bytes are read to be
//! **served** (retrieval, an enumeration window) and to be **parsed** (the governance chain's
//! `manifest`/`key` statements), never to rebuild a root.
//!
//! Concurrency: the store serializes all access behind one connection and one mutex.
//! Governance resolution and signature verification (read-only) happen before any write; the
//! writes themselves — promoting every entry in a checkpoint's `entries_to_promote` batch and
//! recording the checkpoint — run inside one `SQLite` transaction (see the crate-private
//! `Store::with_transaction` and [`crate::checkpoint::ingest_checkpoint`]), so a batch that
//! fails partway (a bad proof on the third of five entries, say) leaves the store exactly as
//! it was before the request, not partially applied. A mirror is single-writer by
//! construction (one producer, one log, per adaptor profile §3), so cross-request
//! transactions are not needed on top of this.

use std::cell::{Cell, RefCell};
use std::path::Path;
use std::sync::Mutex;

use atl_core::core::merkle::{
    compute_root, compute_subtree_root, generate_consistency_proof, generate_inclusion_proof,
    hash_children, ConsistencyProof, Hash, InclusionProof,
};
use rusqlite::{params, Connection, OptionalExtension as _};

use crate::checkpoint::Checkpoint;
use crate::error::{MirrorError, MirrorResult};
use crate::metadata::log_leaf_hash;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS staged_entries (
    entry_id TEXT PRIMARY KEY,
    envelope BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    entry_index INTEGER PRIMARY KEY,
    entry_id    TEXT NOT NULL UNIQUE,
    envelope    BLOB NOT NULL,
    leaf_hash   BLOB
);
CREATE TABLE IF NOT EXISTS checkpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_size       INTEGER NOT NULL,
    log_id          TEXT NOT NULL,
    root_hash       TEXT NOT NULL,
    checkpoint_time TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    signature       TEXT NOT NULL,
    UNIQUE(tree_size, checkpoint_time)
);
CREATE TABLE IF NOT EXISTS rotation_checkpoints (
    manifest_entry_index INTEGER NOT NULL,
    tree_size            INTEGER NOT NULL,
    log_id               TEXT NOT NULL,
    root_hash            TEXT NOT NULL,
    checkpoint_time      TEXT NOT NULL,
    key_id               TEXT NOT NULL,
    signature            TEXT NOT NULL,
    PRIMARY KEY (manifest_entry_index, tree_size, checkpoint_time)
);
CREATE TABLE IF NOT EXISTS subtree_roots (
    level      INTEGER NOT NULL,
    node_index INTEGER NOT NULL,
    hash       BLOB NOT NULL,
    PRIMARY KEY (level, node_index)
) WITHOUT ROWID;
";

/// How many rows the leaf-hash backfill reads at a time (see `backfill_leaf_hashes`).
const BACKFILL_BATCH: i64 = 1024;

/// The highest subtree level a `u64` tree size can complete: a level-`L` node covers `2^L`
/// leaves, so `L` never exceeds 63.
const MAX_SUBTREE_LEVEL: u32 = 63;

/// The outcome of staging or promoting an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The entry was newly stored.
    Inserted,
    /// The exact same entry id (and, where applicable, bytes) was already stored; the
    /// operation is idempotent for a repeated, identical submission.
    AlreadyPresent,
}

/// A stored entry: its position in the log and its exact anchored bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEntry {
    /// The entry's position in the log.
    pub entry_index: u64,
    /// The exact bytes anchored as this entry (`JCS(envelope)`).
    pub envelope: Vec<u8>,
}

/// The mirror's durable store.
pub struct Store {
    conn: Mutex<Connection>,
}

/// Convert a domain `u64` index to `SQLite`'s `i64` storage type.
fn to_i64(what: &'static str, value: u64) -> MirrorResult<i64> {
    i64::try_from(value).map_err(|_| MirrorError::IndexOverflow { what })
}

/// Convert a value read back from `SQLite` to the domain's `u64`.
fn to_u64(what: &'static str, value: i64) -> MirrorResult<u64> {
    u64::try_from(value).map_err(|_| MirrorError::IndexOverflow { what })
}

/// One past a stored `MAX(entry_index)`: the next canonical index the store expects.
///
/// `SQLite` holds an entry index as an `i64`, so the successor of anything this can read back
/// is representable; the check is here so that no arithmetic in this module can wrap silently
/// if a row ever carries a value outside that range.
fn next_after(what: &'static str, value: i64) -> MirrorResult<u64> {
    to_u64(what, value)?.checked_add(1).ok_or(MirrorError::IndexOverflow { what })
}

impl Store {
    /// Open (creating if absent) a store backed by the `SQLite` file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::StoreInit`] if the file cannot be opened or migrated.
    pub fn open(path: &Path) -> MirrorResult<Self> {
        let conn = Connection::open(path).map_err(|e| MirrorError::StoreInit(e.to_string()))?;
        Self::from_connection(conn)
    }

    /// Open a private in-memory store. Intended for tests.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::StoreInit`] if the in-memory database cannot be created.
    pub fn open_in_memory() -> MirrorResult<Self> {
        let conn =
            Connection::open_in_memory().map_err(|e| MirrorError::StoreInit(e.to_string()))?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> MirrorResult<Self> {
        conn.execute_batch(SCHEMA).map_err(|e| MirrorError::StoreInit(e.to_string()))?;
        migrate(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Run `f` with the locked connection, then drop the lock before returning `f`'s result —
    /// every store method funnels through here so the mutex guard's scope never outlives its
    /// last use.
    ///
    /// `pub(crate)` so callers elsewhere in the crate (see [`crate::checkpoint`]) can compose
    /// the lower-level `*_raw` functions below without going through a dedicated `Store`
    /// method for every combination they need.
    pub(crate) fn with_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> MirrorResult<T>,
    ) -> MirrorResult<T> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| MirrorError::StoreInit("store mutex poisoned".to_owned()))?;
        let result = f(&conn);
        drop(conn);
        result
    }

    /// Run `f` inside one `SQLite` transaction: commit if `f` returns `Ok`, roll back if it
    /// returns `Err`, so `f`'s writes are all-or-nothing.
    ///
    /// This is what makes multi-step admission — promoting every entry in a checkpoint's
    /// `entries_to_promote` batch, then recording the checkpoint itself (see
    /// [`crate::checkpoint::ingest_checkpoint`]) — leave no trace on failure. `f` MUST use the
    /// `*_raw` functions in this module (or other `&Connection`-based helpers) rather than
    /// calling back into any `&Store`-based method: this method already holds the store's
    /// single connection mutex for the duration of `f`, and `std::sync::Mutex` is not
    /// reentrant, so a nested `Store` method call would deadlock.
    ///
    /// # Errors
    ///
    /// [`MirrorError::StoreInit`] if the mutex is poisoned, [`MirrorError::Store`] if starting
    /// or committing the transaction fails, or whatever `f` itself returns (in which case the
    /// transaction is rolled back before the error propagates).
    // `significant_drop_tightening` wants the mutex guard `conn` dropped as soon as possible,
    // but `tx` borrows `conn` mutably for its entire lifetime (`rusqlite::Transaction<'_>`), so
    // the guard cannot be released before `tx` is committed or rolled back — the lint's
    // suggested fix does not type-check. Holding the lock for the whole transaction is exactly
    // the point of this method, not an oversight.
    #[allow(clippy::significant_drop_tightening)]
    pub(crate) fn with_transaction<T>(
        &self,
        f: impl FnOnce(&Connection) -> MirrorResult<T>,
    ) -> MirrorResult<T> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| MirrorError::StoreInit("store mutex poisoned".to_owned()))?;
        let tx = conn.transaction().map_err(MirrorError::from)?;
        match f(&tx) {
            Ok(value) => {
                tx.commit().map_err(MirrorError::from)?;
                Ok(value)
            }
            Err(err) => {
                // A rollback failure here does not leave the writes committed: an uncommitted
                // `Transaction` also rolls back on drop, so `err` (the original failure) is
                // always the right thing to report either way.
                let _ = tx.rollback();
                Err(err)
            }
        }
    }

    // -----------------------------------------------------------------------------------
    // Staging
    // -----------------------------------------------------------------------------------

    /// Stage `bytes` under `entry_id`, with no claim about position or anchoring.
    ///
    /// Idempotent for a repeated, byte-identical submission. Staging never fails on a
    /// contested position, because staged rows are not index-exclusive — see the module
    /// docs.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::EntryIdAtDifferentIndex`]-shaped conflict as
    /// [`MirrorError::IndexConflict`] only in the practically-unreachable case of the same
    /// `entry_id` staged with different bytes (which would require a `SHA-256` collision,
    /// since `entry_id` is a hash of the bytes — checked by the caller before this is
    /// reached), or [`MirrorError::Store`] on a database failure.
    pub fn stage_entry(&self, entry_id: &str, bytes: &[u8]) -> MirrorResult<InsertOutcome> {
        self.with_conn(|conn| {
            let existing: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT envelope FROM staged_entries WHERE entry_id = ?1",
                    [entry_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing_bytes) = existing {
                if existing_bytes == bytes {
                    return Ok(InsertOutcome::AlreadyPresent);
                }
                return Err(MirrorError::IndexConflict {
                    index: 0,
                    existing_entry_id: entry_id.to_owned(),
                    new_entry_id: entry_id.to_owned(),
                });
            }
            conn.execute(
                "INSERT INTO staged_entries (entry_id, envelope) VALUES (?1, ?2)",
                params![entry_id, bytes],
            )?;
            Ok(InsertOutcome::Inserted)
        })
    }

    /// Fetch a staged candidate's bytes by entry id.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Store`] on a database failure.
    pub fn get_staged(&self, entry_id: &str) -> MirrorResult<Option<Vec<u8>>> {
        self.with_conn(|conn| get_staged_raw(conn, entry_id))
    }

    // -----------------------------------------------------------------------------------
    // Canonical entries
    // -----------------------------------------------------------------------------------

    /// The next entry index this store expects (one past the greatest canonical index, or 0
    /// for an empty store).
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Store`] on a database failure.
    pub fn next_index(&self) -> MirrorResult<u64> {
        self.with_conn(|conn| {
            let max: Option<i64> =
                conn.query_row("SELECT MAX(entry_index) FROM entries", [], |row| row.get(0))?;
            max.map_or(Ok(0), |m| next_after("next_index", m))
        })
    }

    /// Promote a staged entry into canonical storage at `entry_index`.
    ///
    /// This performs no proof verification of its own — the caller (see
    /// [`crate::ingest::promote_entry`]) MUST already have checked a Merkle inclusion proof
    /// of the staged bytes against a trusted checkpoint before calling this. What this method
    /// enforces is storage-level integrity: the entry must actually be staged; idempotent for
    /// a repeated, byte-identical promotion at the same index; rejects a gap (`entry_index` is
    /// not the next expected canonical index), a conflicting occupant at that index, and the
    /// same `entry_id` claimed at a second index.
    ///
    /// Runs inside a transaction, because promotion is two writes and not one: the canonical
    /// row and the complete-subtree roots it completes (see the module docs). Committing the
    /// row and then failing to extend the cache would leave a log whose stored tree material
    /// disagrees with its entries — the migration would rebuild it on the next open, but until
    /// then every range and inclusion proof over that span would open the wrong root, so the
    /// two writes land together or not at all.
    ///
    /// # Errors
    ///
    /// [`MirrorError::NotStaged`], [`MirrorError::OutOfOrderIndex`],
    /// [`MirrorError::IndexConflict`], [`MirrorError::EntryIdAtDifferentIndex`], or
    /// [`MirrorError::Store`].
    pub fn promote_entry(&self, entry_index: u64, entry_id: &str) -> MirrorResult<InsertOutcome> {
        self.with_transaction(|conn| promote_entry_raw(conn, entry_index, entry_id))
    }

    /// Fetch an entry by its AHL entry id.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Store`] on a database failure.
    pub fn get_entry_by_id(&self, entry_id: &str) -> MirrorResult<Option<StoredEntry>> {
        self.with_conn(|conn| {
            let row: Option<(i64, Vec<u8>)> = conn
                .query_row(
                    "SELECT entry_index, envelope FROM entries WHERE entry_id = ?1",
                    [entry_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            row.map(|(index, envelope)| {
                Ok(StoredEntry { entry_index: to_u64("entry_index", index)?, envelope })
            })
            .transpose()
        })
    }

    /// Fetch every entry in `[from_index, to_index)`, in ascending index order.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Store`] on a database failure. Does **not** itself detect a gap
    /// inside the range; callers that need completeness (range enumeration, consistency
    /// proofs) MUST check the returned count against the expected width.
    pub fn get_entries_range(&self, from_index: u64, to_index: u64) -> MirrorResult<Vec<Vec<u8>>> {
        self.with_conn(|conn| get_entries_range_raw(conn, from_index, to_index))
    }

    /// How many canonical entries are stored in `[from_index, to_index)`.
    ///
    /// Canonical storage is contiguous from index 0 (promotion refuses any other index), so
    /// this answers "does the store reach `to_index`" without reading a single entry's bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Store`] on a database failure.
    pub fn count_entries(&self, from_index: u64, to_index: u64) -> MirrorResult<u64> {
        self.with_conn(|conn| count_entries_raw(conn, from_index, to_index))
    }

    /// The stored log leaf hashes for `[from_index, to_index)`, in ascending index order
    /// (adaptor profile §4.2) — 32 bytes per entry instead of the entry itself.
    ///
    /// # Errors
    ///
    /// [`MirrorError::TreeMaterialMissing`] or [`MirrorError::TreeMaterialCorrupt`] if a
    /// stored row carries no usable leaf hash, or [`MirrorError::Store`].
    pub fn leaf_hashes_range(&self, from_index: u64, to_index: u64) -> MirrorResult<Vec<Hash>> {
        self.with_conn(|conn| leaf_hashes_range_raw(conn, from_index, to_index))
    }

    /// An RFC 6962 inclusion proof of the leaf at `leaf_index` under a tree of `tree_size`
    /// (adaptor profile §8.2), opened through the stored tree material.
    ///
    /// # Errors
    ///
    /// [`MirrorError::Atl`] if the index or size is outside the stored material,
    /// [`MirrorError::TreeMaterialMissing`]/[`MirrorError::TreeMaterialCorrupt`] for an
    /// unusable stored node, or [`MirrorError::Store`].
    pub fn inclusion_proof(&self, leaf_index: u64, tree_size: u64) -> MirrorResult<InclusionProof> {
        self.with_conn(|conn| inclusion_proof_raw(conn, leaf_index, tree_size))
    }

    /// The RFC 6962 root of the subtree spanning leaves `[offset, offset + size)`, opened
    /// through the stored complete-subtree roots (see the module docs).
    ///
    /// # Errors
    ///
    /// [`MirrorError::Atl`] if the span is not inside the stored material,
    /// [`MirrorError::TreeMaterialMissing`]/[`MirrorError::TreeMaterialCorrupt`] for an
    /// unusable stored node, or [`MirrorError::Store`].
    pub fn subtree_root(&self, offset: u64, size: u64) -> MirrorResult<Hash> {
        self.with_conn(|conn| subtree_root_raw(conn, offset, size))
    }

    /// The RFC 6962 root of the whole stored prefix `[0, tree_size)`, opened through the
    /// stored complete-subtree roots — `O(log tree_size)` node reads, no entry bytes. A
    /// `tree_size` of zero is the empty tree, whose root is `SHA-256("")`.
    ///
    /// # Errors
    ///
    /// [`MirrorError::Atl`] if the prefix is not inside the stored material,
    /// [`MirrorError::TreeMaterialMissing`]/[`MirrorError::TreeMaterialCorrupt`] for an
    /// unusable stored node, or [`MirrorError::Store`].
    pub fn log_root(&self, tree_size: u64) -> MirrorResult<Hash> {
        self.with_conn(|conn| log_root_raw(conn, tree_size))
    }

    /// An RFC 9162 consistency proof between tree sizes `from_size` and `to_size`, opened
    /// through the stored tree material in `O(log to_size)` node reads and no entry bytes.
    ///
    /// The store MUST hold the full `[0, to_size)` prefix — a proof over leaves this mirror
    /// does not have would be a claim about a tree it cannot see.
    ///
    /// # Errors
    ///
    /// [`MirrorError::IncompleteEntries`] if the store does not hold the whole `[0, to_size)`
    /// prefix, [`MirrorError::Atl`] if `from_size > to_size`,
    /// [`MirrorError::TreeMaterialMissing`]/[`MirrorError::TreeMaterialCorrupt`] for an
    /// unusable stored node, or [`MirrorError::Store`].
    pub fn consistency_proof(
        &self,
        from_size: u64,
        to_size: u64,
    ) -> MirrorResult<ConsistencyProof> {
        self.consistency_proof_measured(from_size, to_size).map(|(proof, _)| proof)
    }

    /// [`Store::consistency_proof`], additionally reporting what it read (see
    /// [`TreeReadCost`]).
    ///
    /// # Errors
    ///
    /// As [`Store::consistency_proof`].
    pub fn consistency_proof_measured(
        &self,
        from_size: u64,
        to_size: u64,
    ) -> MirrorResult<(ConsistencyProof, TreeReadCost)> {
        self.with_conn(|conn| consistency_proof_measured_raw(conn, from_size, to_size))
    }

    // -----------------------------------------------------------------------------------
    // Checkpoints
    // -----------------------------------------------------------------------------------

    /// Record an *authenticated* checkpoint (adaptor profile §6.5; core spec §7.3) — a
    /// signature-verified claim, not yet necessarily series-usable.
    ///
    /// This performs no signature or consistency verification of its own — callers (see
    /// [`crate::checkpoint::ingest_checkpoint`]) MUST authenticate first. Series members may
    /// be admitted in any `tree_size` order, so a gap can be backfilled later; whether the
    /// series is provably gap-free, and which members are *series-usable*, is computed on
    /// demand from the full set (see [`crate::checkpoint::series_view`]), never stored as a
    /// static flag here, so it always reflects the store's current state (entries can arrive
    /// after a checkpoint does). A `(tree_size, checkpoint_time)` pair already present is
    /// accepted idempotently if the content is byte-identical, and rejected otherwise —
    /// adaptor profile §5.2.2 item 4 requires the series to be append-only in publication.
    /// The *same* `tree_size` at a *different* `checkpoint_time` is not a conflict: core spec
    /// §7.3 requires a quiet log to keep publishing checkpoints at unchanged `tree_size`, so
    /// repeated sizes are legitimate, distinct members.
    ///
    /// # Errors
    ///
    /// [`MirrorError::SeriesMemberConflict`] or [`MirrorError::Store`].
    pub fn insert_checkpoint(&self, cp: &Checkpoint) -> MirrorResult<InsertOutcome> {
        self.with_conn(|conn| insert_checkpoint_raw(conn, cp))
    }

    /// Fetch the most recently declared authenticated checkpoint at exactly `tree_size`
    /// (largest `checkpoint_time`) — any one of them opens the same root, since root is a
    /// pure function of `tree_size` for a genuine tree, so this is sufficient for range and
    /// retrieval purposes. Callers needing series-usability (adaptor profile enumeration,
    /// `ITUB`) MUST check it via [`crate::checkpoint::series_view`], never assume it from
    /// mere presence here.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Store`] on a database failure.
    pub fn get_checkpoint(&self, tree_size: u64) -> MirrorResult<Option<Checkpoint>> {
        let tree_size_i64 = to_i64("tree_size", tree_size)?;
        self.with_conn(|conn| {
            row_to_checkpoint(conn.query_row(
                "SELECT tree_size, log_id, root_hash, checkpoint_time, key_id, signature \
                 FROM checkpoints WHERE tree_size = ?1 ORDER BY checkpoint_time DESC LIMIT 1",
                [tree_size_i64],
                checkpoint_row,
            ))
        })
    }

    /// Record a rotation-anchoring checkpoint for the rotation anchored at
    /// `manifest_entry_index`, apart from the canonical series (see the module docs).
    ///
    /// Performs no verification of its own: the caller (see
    /// [`crate::checkpoint::ingest_checkpoint`]) MUST already have established that the
    /// checkpoint verifies under the OUTGOING log key set and that the version at
    /// `manifest_entry_index` is a governance-key rotation. Idempotent for a byte-identical
    /// resubmission; a different checkpoint at the same `(manifest_entry_index, tree_size,
    /// checkpoint_time)` is a conflict, on the same append-only footing as the series.
    /// SEVERAL rotation-anchoring checkpoints for one rotation are legitimate — any checkpoint
    /// of size greater than the rotating index and signed by the outgoing key is one — so
    /// distinct sizes and times coexist, and [`Self::get_rotation_checkpoint`] chooses among
    /// them deterministically.
    ///
    /// # Errors
    ///
    /// [`MirrorError::SeriesMemberConflict`] or [`MirrorError::Store`].
    pub fn insert_rotation_checkpoint(
        &self,
        manifest_entry_index: u64,
        cp: &Checkpoint,
    ) -> MirrorResult<InsertOutcome> {
        self.with_conn(|conn| insert_rotation_checkpoint_raw(conn, manifest_entry_index, cp))
    }

    /// The rotation-anchoring checkpoint held for the rotation anchored at
    /// `manifest_entry_index`, or `None`.
    ///
    /// Where several are held, the one with the smallest `(tree_size, checkpoint_time)` is
    /// returned: it is the earliest attestation of the handover, and it is the cheapest to
    /// serve, since the inclusion path it grounds runs over the smallest tree. Deterministic
    /// either way — a route that returned "some member" would let two mirrors holding the same
    /// material answer differently.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Store`] on a database failure.
    pub fn get_rotation_checkpoint(
        &self,
        manifest_entry_index: u64,
    ) -> MirrorResult<Option<Checkpoint>> {
        let index_i64 = to_i64("manifest_entry_index", manifest_entry_index)?;
        self.with_conn(|conn| {
            row_to_checkpoint(conn.query_row(
                "SELECT tree_size, log_id, root_hash, checkpoint_time, key_id, signature \
                 FROM rotation_checkpoints WHERE manifest_entry_index = ?1 \
                 ORDER BY tree_size ASC, checkpoint_time ASC LIMIT 1",
                [index_i64],
                checkpoint_row,
            ))
        })
    }

    /// Every rotation-anchoring checkpoint held, with the rotation it anchors, ordered
    /// ascending by `(tree_size, checkpoint_time)`.
    ///
    /// The equivocation scan of [`crate::checkpoint::series_view`] reads this: material held
    /// apart from the series is still material this log published, and a root it contradicts a
    /// series member with is a divergence.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Store`] on a database failure.
    pub fn all_rotation_checkpoints(&self) -> MirrorResult<Vec<(u64, Checkpoint)>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT manifest_entry_index, tree_size, log_id, root_hash, checkpoint_time, \
                 key_id, signature FROM rotation_checkpoints \
                 ORDER BY tree_size ASC, checkpoint_time ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                let index: i64 = row.get(0)?;
                Ok((index, checkpoint_row_from(row, 1)?))
            })?;
            rows.map(|row| {
                let (index, cp) = row?;
                Ok((to_u64("manifest_entry_index", index)?, cp))
            })
            .collect()
        })
    }

    /// Every authenticated checkpoint, ordered ascending by `(tree_size, checkpoint_time)` —
    /// the raw material [`crate::checkpoint::series_view`] computes series-usability and
    /// gap-freeness from. Includes checkpoints that are not (or not yet) series-usable; see
    /// core spec §7.3: an authenticated checkpoint that is not series-usable MAY be retained
    /// and MUST be reported as such.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Store`] on a database failure.
    pub fn all_checkpoints(&self) -> MirrorResult<Vec<Checkpoint>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT tree_size, log_id, root_hash, checkpoint_time, key_id, signature \
                 FROM checkpoints ORDER BY tree_size ASC, checkpoint_time ASC",
            )?;
            let rows = stmt.query_map([], checkpoint_row)?;
            rows.collect::<Result<Vec<Checkpoint>, _>>().map_err(MirrorError::from)
        })
    }
}

// -----------------------------------------------------------------------------------
// `&Connection`-based cores, usable both standalone (via `Store::with_conn`) and inside a
// transaction (via `Store::with_transaction`) — see the module docs' "Concurrency" section.
// -----------------------------------------------------------------------------------

/// The `&Connection` core of [`Store::get_staged`].
pub(crate) fn get_staged_raw(conn: &Connection, entry_id: &str) -> MirrorResult<Option<Vec<u8>>> {
    conn.query_row("SELECT envelope FROM staged_entries WHERE entry_id = ?1", [entry_id], |row| {
        row.get(0)
    })
    .optional()
    .map_err(MirrorError::from)
}

/// The `&Connection` core of [`Store::promote_entry`].
///
/// For callers ALREADY inside a transaction: it performs the canonical insert and the
/// complete-subtree cache extension as two statements, and only the caller's transaction makes
/// them one write. [`Store::promote_entry`] supplies that transaction for a standalone caller.
pub(crate) fn promote_entry_raw(
    conn: &Connection,
    entry_index: u64,
    entry_id: &str,
) -> MirrorResult<InsertOutcome> {
    let index_i64 = to_i64("entry_index", entry_index)?;
    let bytes: Vec<u8> = conn
        .query_row("SELECT envelope FROM staged_entries WHERE entry_id = ?1", [entry_id], |row| {
            row.get(0)
        })
        .optional()?
        .ok_or_else(|| MirrorError::NotStaged { entry_id: entry_id.to_owned() })?;

    let existing_at_index: Option<(String, Vec<u8>)> = conn
        .query_row(
            "SELECT entry_id, envelope FROM entries WHERE entry_index = ?1",
            [index_i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((existing_id, existing_bytes)) = existing_at_index {
        if existing_id == entry_id && existing_bytes == bytes {
            return Ok(InsertOutcome::AlreadyPresent);
        }
        return Err(MirrorError::IndexConflict {
            index: entry_index,
            existing_entry_id: existing_id,
            new_entry_id: entry_id.to_owned(),
        });
    }

    let existing_index_for_id: Option<i64> = conn
        .query_row("SELECT entry_index FROM entries WHERE entry_id = ?1", [entry_id], |row| {
            row.get(0)
        })
        .optional()?;
    if let Some(existing_index) = existing_index_for_id {
        return Err(MirrorError::EntryIdAtDifferentIndex {
            entry_id: entry_id.to_owned(),
            existing_index: to_u64("existing_index", existing_index)?,
            requested_index: entry_index,
        });
    }

    let max: Option<i64> =
        conn.query_row("SELECT MAX(entry_index) FROM entries", [], |row| row.get(0))?;
    let expected = match max {
        None => 0,
        Some(m) => next_after("next_index", m)?,
    };
    if entry_index != expected {
        return Err(MirrorError::OutOfOrderIndex { expected, got: entry_index });
    }

    let leaf: Hash = log_leaf_hash(&bytes);
    conn.execute(
        "INSERT INTO entries (entry_index, entry_id, envelope, leaf_hash) VALUES (?1, ?2, ?3, ?4)",
        params![index_i64, entry_id, bytes, leaf.as_slice()],
    )?;
    extend_subtree_cache(conn, entry_index)?;
    Ok(InsertOutcome::Inserted)
}

// -----------------------------------------------------------------------------------
// Derived tree material: leaf hashes and complete-subtree roots (see the module docs).
// -----------------------------------------------------------------------------------

/// One node of the log tree: level 0 from `entries.leaf_hash`, higher levels from
/// `subtree_roots`.
///
/// `None` means the node is not stored, which for level 0 means the entry is not held and for
/// a higher level means the subtree is not yet complete. Neither is an error here — callers
/// decide what an absence means.
pub(crate) fn tree_node_raw(
    conn: &Connection,
    level: u32,
    index: u64,
) -> MirrorResult<Option<Hash>> {
    let index_i64 = to_i64("tree node index", index)?;
    let blob: Option<Vec<u8>> = if level == 0 {
        conn.query_row("SELECT leaf_hash FROM entries WHERE entry_index = ?1", [index_i64], |row| {
            row.get(0)
        })
        .optional()?
        .flatten()
    } else {
        conn.query_row(
            "SELECT hash FROM subtree_roots WHERE level = ?1 AND node_index = ?2",
            params![level, index_i64],
            |row| row.get(0),
        )
        .optional()?
    };
    blob.map(|bytes| {
        Hash::try_from(bytes.as_slice())
            .map_err(|_| MirrorError::TreeMaterialCorrupt { level, node_index: index })
    })
    .transpose()
}

/// Record the perfect subtrees that the promotion of `entry_index` completed.
///
/// Promotion is append-only and gap-free, so promoting index `i` makes the leaf count `i + 1`,
/// and a level-`L` node completes exactly when that count is a multiple of `2^L`. Its index is
/// then `count / 2^L - 1` and its children are the two level-`L-1` nodes below it, both of
/// which completed earlier. The loop therefore climbs one level per trailing zero of `count`:
/// amortized `O(1)` writes per promotion, `O(log n)` worst case.
fn extend_subtree_cache(conn: &Connection, entry_index: u64) -> MirrorResult<()> {
    let overflow = || MirrorError::IndexOverflow { what: "subtree cache index" };
    let count = entry_index.checked_add(1).ok_or_else(overflow)?;
    let mut level: u32 = 1;
    let mut width: u64 = 2;
    while level <= MAX_SUBTREE_LEVEL && width <= count {
        if count.checked_rem(width).ok_or_else(overflow)? != 0 {
            break;
        }
        let node_index =
            count.checked_div(width).ok_or_else(overflow)?.checked_sub(1).ok_or_else(overflow)?;
        let left_index = node_index.checked_mul(2).ok_or_else(overflow)?;
        let right_index = left_index.checked_add(1).ok_or_else(overflow)?;
        let child_level = level.checked_sub(1).ok_or_else(overflow)?;
        let missing =
            |index: u64| MirrorError::TreeMaterialMissing { level: child_level, node_index: index };
        let left =
            tree_node_raw(conn, child_level, left_index)?.ok_or_else(|| missing(left_index))?;
        let right =
            tree_node_raw(conn, child_level, right_index)?.ok_or_else(|| missing(right_index))?;
        conn.execute(
            "INSERT OR REPLACE INTO subtree_roots (level, node_index, hash) VALUES (?1, ?2, ?3)",
            params![
                level,
                to_i64("subtree node index", node_index)?,
                hash_children(&left, &right).as_slice()
            ],
        )?;
        level = level.checked_add(1).ok_or_else(overflow)?;
        let Some(next_width) = width.checked_mul(2) else { break };
        width = next_width;
    }
    Ok(())
}

/// The number of canonical entries stored in `[from_index, to_index)`.
pub(crate) fn count_entries_raw(
    conn: &Connection,
    from_index: u64,
    to_index: u64,
) -> MirrorResult<u64> {
    let from_i64 = to_i64("from_index", from_index)?;
    let to_i64 = to_i64("to_index", to_index)?;
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM entries WHERE entry_index >= ?1 AND entry_index < ?2",
        params![from_i64, to_i64],
        |row| row.get(0),
    )?;
    to_u64("entry count", count)
}

/// Every stored log leaf hash in `[from_index, to_index)`, in ascending index order.
///
/// Reads 32 bytes per entry rather than the entry bytes themselves. Does **not** itself detect
/// a gap inside the range; callers needing completeness MUST check the returned count.
pub(crate) fn leaf_hashes_range_raw(
    conn: &Connection,
    from_index: u64,
    to_index: u64,
) -> MirrorResult<Vec<Hash>> {
    let from_i64 = to_i64("from_index", from_index)?;
    let to_i64 = to_i64("to_index", to_index)?;
    let mut stmt = conn.prepare(
        "SELECT entry_index, leaf_hash FROM entries WHERE entry_index >= ?1 AND entry_index < ?2 \
         ORDER BY entry_index ASC",
    )?;
    let rows = stmt.query_map(params![from_i64, to_i64], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
    })?;
    let mut hashes = Vec::new();
    for row in rows {
        let (index, blob) = row?;
        let index = to_u64("entry_index", index)?;
        let blob = blob.ok_or(MirrorError::TreeMaterialMissing { level: 0, node_index: index })?;
        hashes.push(
            Hash::try_from(blob.as_slice())
                .map_err(|_| MirrorError::TreeMaterialCorrupt { level: 0, node_index: index })?,
        );
    }
    Ok(hashes)
}

/// What opening one proof or root cost to read out of the store.
///
/// Reported rather than asserted, for the same reason [`crate::range::RangeReadCost`] is: the
/// point of the stored tree material is that a proof about a log does not read the log, and a
/// number a caller can print is the only form of that claim which cannot quietly stop being
/// true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TreeReadCost {
    /// Stored 32-octet log-tree nodes read: leaf hashes and complete-subtree roots alike.
    pub tree_nodes: u64,
}

impl TreeReadCost {
    /// Octets read from the store: 32 per node.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.tree_nodes.saturating_mul(32)
    }
}

/// Run `f` over a reader of the stored tree material, counting the nodes it reads.
///
/// `atl_core`'s proof and root builders take a `(level, index) -> Option<Hash>` callback and
/// treat `None` as "not stored, descend instead", which leaves no channel for a storage
/// failure. So a failure is captured here and re-raised after the call, rather than being
/// silently reported to the builder as an absent node and answered by a descent that reads
/// bytes it should not have had to.
fn with_tree_nodes<T>(
    conn: &Connection,
    f: impl FnOnce(&dyn Fn(u32, u64) -> Option<Hash>) -> Result<T, atl_core::AtlError>,
) -> MirrorResult<(T, TreeReadCost)> {
    let failure: RefCell<Option<MirrorError>> = RefCell::new(None);
    let reads = Cell::new(0_u64);
    let get_node = |level: u32, index: u64| -> Option<Hash> {
        match tree_node_raw(conn, level, index) {
            Ok(node) => {
                if node.is_some() {
                    reads.set(reads.get().saturating_add(1));
                }
                node
            }
            Err(err) => {
                let mut slot = failure.borrow_mut();
                if slot.is_none() {
                    *slot = Some(err);
                }
                None
            }
        }
    };
    let computed = f(&get_node);
    if let Some(err) = failure.borrow_mut().take() {
        return Err(err);
    }
    Ok((computed?, TreeReadCost { tree_nodes: reads.get() }))
}

/// An RFC 6962 inclusion proof of the leaf at `leaf_index` under a tree of `tree_size`,
/// opened through the stored tree material (adaptor profile §8.2).
///
/// Costs `O(log tree_size)` stored nodes for the same reason [`subtree_root_raw`] does: every
/// sibling on the path is either a complete power-of-two subtree the cache holds or a short
/// fold over ones it does.
pub(crate) fn inclusion_proof_raw(
    conn: &Connection,
    leaf_index: u64,
    tree_size: u64,
) -> MirrorResult<InclusionProof> {
    with_tree_nodes(conn, |get_node| generate_inclusion_proof(leaf_index, tree_size, get_node))
        .map(|(proof, _)| proof)
}

/// The RFC 6962 root of the subtree spanning leaves `[offset, offset + size)`, opened through
/// the stored tree material.
///
/// `atl_core`'s own recursion does the walking: it takes a complete power-of-two aligned
/// subtree straight from `subtree_roots` where one is stored, and descends only where it is
/// not — which, for a store whose cache is current, is the right spine alone.
pub(crate) fn subtree_root_raw(conn: &Connection, offset: u64, size: u64) -> MirrorResult<Hash> {
    with_tree_nodes(conn, |get_node| compute_subtree_root(offset, size, &get_node))
        .map(|(root, _)| root)
}

/// The RFC 6962 root of the whole stored prefix `[0, tree_size)`, opened through the stored
/// tree material — `O(log tree_size)` node reads, no entry bytes.
///
/// A `tree_size` of zero is the empty tree, whose root is `SHA-256("")` and reads nothing.
/// This is what every root check in this crate compares a checkpoint's `root_hash` against
/// (see [`crate::checkpoint`]); nothing re-derives a root by hashing entry envelopes.
pub(crate) fn log_root_raw(conn: &Connection, tree_size: u64) -> MirrorResult<Hash> {
    if tree_size == 0 {
        return Ok(compute_root(&[]));
    }
    subtree_root_raw(conn, 0, tree_size)
}

/// An RFC 9162 consistency proof between tree sizes `from_size` and `to_size`, opened through
/// the stored tree material, with what it read.
///
/// The proof is the RFC 9162 SUBPROOF path: `O(log to_size)` subtree roots, each of which the
/// cache answers with one read where it is a complete power-of-two subtree and a fold over
/// the right spine where it is not. So the whole proof costs `O(log to_size)` node reads and
/// no entry bytes at all.
///
/// The store MUST hold the full `[0, to_size)` prefix — a proof over leaves this mirror does
/// not have would be a claim about a tree it cannot see.
pub(crate) fn consistency_proof_measured_raw(
    conn: &Connection,
    from_size: u64,
    to_size: u64,
) -> MirrorResult<(ConsistencyProof, TreeReadCost)> {
    let have = count_entries_raw(conn, 0, to_size)?;
    if have != to_size {
        return Err(MirrorError::IncompleteEntries { have, need: to_size });
    }
    with_tree_nodes(conn, |get_node| generate_consistency_proof(from_size, to_size, get_node))
}

/// The entry-bytes prover this module replaced, kept as a TEST ORACLE.
///
/// It re-derives every leaf hash of `[0, to_size)` from the entry envelopes and hands the
/// sequence to `atl_core::core::merkle::generate_consistency_proof` through a level-0-only
/// node reader — which is exactly what `http::consistency_handler` and
/// `checkpoint::series_view` did before the cached prover above existed.
/// `tests::the_cached_prover_agrees_with_an_entry_bytes_build` holds the two together for
/// every `(m, n)` pair over every tree shape up to 33 entries, so a divergence in node
/// choice or node order is a test failure rather than something a reader has to take on
/// trust.
#[cfg(test)]
fn consistency_proof_from_entry_bytes(
    all_entries: &[Vec<u8>],
    from_size: u64,
    to_size: u64,
) -> MirrorResult<ConsistencyProof> {
    let to = usize::try_from(to_size).expect("small test size");
    let leaf_hashes: Vec<Hash> =
        all_entries[..to].iter().map(|bytes| log_leaf_hash(bytes)).collect();
    Ok(generate_consistency_proof(from_size, to_size, |level, index| {
        if level == 0 {
            leaf_hashes.get(usize::try_from(index).ok()?).copied()
        } else {
            None
        }
    })?)
}

// -----------------------------------------------------------------------------------
// Migration: bring an existing database up to the derived tree material above.
// -----------------------------------------------------------------------------------

/// Bring `conn` up to the current schema. Idempotent, and safe to run on an empty database.
fn migrate(conn: &Connection) -> MirrorResult<()> {
    add_leaf_hash_column(conn)?;
    backfill_leaf_hashes(conn)?;
    rebuild_subtree_cache_if_incomplete(conn)?;
    Ok(())
}

/// Add `entries.leaf_hash` to a database created before it existed.
fn add_leaf_hash_column(conn: &Connection) -> MirrorResult<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(entries)")?;
    let mut names = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let present = names.any(|name| name.is_ok_and(|name| name == "leaf_hash"));
    drop(names);
    drop(stmt);
    if !present {
        conn.execute("ALTER TABLE entries ADD COLUMN leaf_hash BLOB", [])?;
    }
    Ok(())
}

/// Compute the missing log leaf hash of every canonical row that has none.
///
/// Read in batches rather than all at once: the entry bytes of a large log do not have to be
/// resident together to derive 32 bytes each. Every write is the same pure function of bytes
/// already stored, so an interrupted run simply resumes where it stopped.
fn backfill_leaf_hashes(conn: &Connection) -> MirrorResult<()> {
    loop {
        let batch: Vec<(i64, Vec<u8>)> = {
            let mut stmt = conn.prepare(
                "SELECT entry_index, envelope FROM entries WHERE leaf_hash IS NULL \
                 ORDER BY entry_index ASC LIMIT ?1",
            )?;
            let rows = stmt.query_map([BACKFILL_BATCH], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        if batch.is_empty() {
            return Ok(());
        }
        for (index, envelope) in batch {
            let leaf: Hash = log_leaf_hash(&envelope);
            conn.execute(
                "UPDATE entries SET leaf_hash = ?1 WHERE entry_index = ?2",
                params![leaf.as_slice(), index],
            )?;
        }
    }
}

/// Rebuild `subtree_roots` from the leaf hashes wherever it does not hold exactly the nodes a
/// log of the stored size completes.
///
/// The expected population is arithmetic, not a guess: a log of `n` entries completes
/// `n / 2^level` nodes at each level, so comparing the total against the stored row count
/// detects both a cache that predates this schema and one left short by an interrupted run.
/// A mismatch rebuilds the whole table, which is cheap relative to the entry bytes already
/// read to reach it and removes any question of a partially-correct cache.
fn rebuild_subtree_cache_if_incomplete(conn: &Connection) -> MirrorResult<()> {
    let overflow = || MirrorError::IndexOverflow { what: "subtree cache population" };
    let entries: i64 = conn.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))?;
    let entries = to_u64("entry count", entries)?;
    let mut expected: u64 = 0;
    let mut width: u64 = 2;
    while width <= entries {
        expected = expected
            .checked_add(entries.checked_div(width).ok_or_else(overflow)?)
            .ok_or_else(overflow)?;
        let Some(next) = width.checked_mul(2) else { break };
        width = next;
    }
    let stored: i64 = conn.query_row("SELECT COUNT(*) FROM subtree_roots", [], |row| row.get(0))?;
    if to_u64("subtree row count", stored)? == expected {
        return Ok(());
    }

    conn.execute("DELETE FROM subtree_roots", [])?;
    let mut current = leaf_hashes_range_raw(conn, 0, entries)?;
    let mut level: u32 = 1;
    while current.len() >= 2 && level <= MAX_SUBTREE_LEVEL {
        let mut next = Vec::with_capacity(current.len().checked_div(2).unwrap_or(0));
        for (node_index, [left, right]) in current.as_chunks::<2>().0.iter().enumerate() {
            let node = hash_children(left, right);
            conn.execute(
                "INSERT INTO subtree_roots (level, node_index, hash) VALUES (?1, ?2, ?3)",
                params![
                    level,
                    to_i64(
                        "subtree node index",
                        u64::try_from(node_index).map_err(|_| overflow())?
                    )?,
                    node.as_slice()
                ],
            )?;
            next.push(node);
        }
        current = next;
        level = level.checked_add(1).ok_or_else(overflow)?;
    }
    Ok(())
}

/// The `&Connection` core of [`Store::get_entries_range`].
pub(crate) fn get_entries_range_raw(
    conn: &Connection,
    from_index: u64,
    to_index: u64,
) -> MirrorResult<Vec<Vec<u8>>> {
    let from_i64 = to_i64("from_index", from_index)?;
    let to_i64 = to_i64("to_index", to_index)?;
    let mut stmt = conn.prepare(
        "SELECT envelope FROM entries WHERE entry_index >= ?1 AND entry_index < ?2 \
         ORDER BY entry_index ASC",
    )?;
    let rows = stmt.query_map(params![from_i64, to_i64], |row| row.get(0))?;
    rows.collect::<Result<Vec<Vec<u8>>, _>>().map_err(MirrorError::from)
}

/// The `&Connection` core of [`Store::insert_checkpoint`].
pub(crate) fn insert_checkpoint_raw(
    conn: &Connection,
    cp: &Checkpoint,
) -> MirrorResult<InsertOutcome> {
    let tree_size_i64 = to_i64("tree_size", cp.tree_size)?;
    let existing = row_to_checkpoint(conn.query_row(
        "SELECT tree_size, log_id, root_hash, checkpoint_time, key_id, signature \
         FROM checkpoints WHERE tree_size = ?1 AND checkpoint_time = ?2",
        params![tree_size_i64, cp.checkpoint_time],
        checkpoint_row,
    ))?;
    if let Some(existing) = existing {
        if &existing == cp {
            return Ok(InsertOutcome::AlreadyPresent);
        }
        return Err(MirrorError::SeriesMemberConflict {
            tree_size: cp.tree_size,
            checkpoint_time: cp.checkpoint_time.clone(),
        });
    }
    conn.execute(
        "INSERT INTO checkpoints (tree_size, log_id, root_hash, checkpoint_time, \
         key_id, signature) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            tree_size_i64,
            cp.log_id,
            cp.root_hash,
            cp.checkpoint_time,
            cp.key_id,
            cp.signature
        ],
    )?;
    Ok(InsertOutcome::Inserted)
}

/// The `&Connection` core of [`Store::insert_rotation_checkpoint`].
pub(crate) fn insert_rotation_checkpoint_raw(
    conn: &Connection,
    manifest_entry_index: u64,
    cp: &Checkpoint,
) -> MirrorResult<InsertOutcome> {
    let index_i64 = to_i64("manifest_entry_index", manifest_entry_index)?;
    let tree_size_i64 = to_i64("tree_size", cp.tree_size)?;
    let existing = row_to_checkpoint(conn.query_row(
        "SELECT tree_size, log_id, root_hash, checkpoint_time, key_id, signature \
         FROM rotation_checkpoints WHERE manifest_entry_index = ?1 AND tree_size = ?2 \
         AND checkpoint_time = ?3",
        params![index_i64, tree_size_i64, cp.checkpoint_time],
        checkpoint_row,
    ))?;
    if let Some(existing) = existing {
        if &existing == cp {
            return Ok(InsertOutcome::AlreadyPresent);
        }
        return Err(MirrorError::SeriesMemberConflict {
            tree_size: cp.tree_size,
            checkpoint_time: cp.checkpoint_time.clone(),
        });
    }

    // Keep only anchors that could be served. After a rotation that left the LOG key set alone —
    // I-D §7.1 makes a change to the witness key objects a rotation on its own — every later
    // checkpoint of the series qualifies as that rotation's anchor, so recording each one would
    // grow this table with the series to no purpose: [`Store::get_rotation_checkpoint`] serves
    // the smallest `(tree_size, checkpoint_time)` and nothing else. A candidate no earlier than
    // one already held is therefore superseded rather than stored. What IS stored stays: an
    // earlier candidate arriving later is recorded beside the one it supersedes, never over it,
    // so the served anchor is the minimum over everything ever offered and does not depend on
    // the order submissions arrived in.
    let held: Option<(i64, String)> = conn
        .query_row(
            "SELECT tree_size, checkpoint_time FROM rotation_checkpoints \
             WHERE manifest_entry_index = ?1 ORDER BY tree_size ASC, checkpoint_time ASC LIMIT 1",
            [index_i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((held_size, held_time)) = held {
        if (held_size, held_time.as_str()) <= (tree_size_i64, cp.checkpoint_time.as_str()) {
            return Ok(InsertOutcome::AlreadyPresent);
        }
    }

    conn.execute(
        "INSERT INTO rotation_checkpoints (manifest_entry_index, tree_size, log_id, root_hash, \
         checkpoint_time, key_id, signature) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            index_i64,
            tree_size_i64,
            cp.log_id,
            cp.root_hash,
            cp.checkpoint_time,
            cp.key_id,
            cp.signature
        ],
    )?;
    Ok(InsertOutcome::Inserted)
}

fn checkpoint_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Checkpoint> {
    checkpoint_row_from(row, 0)
}

/// Read a checkpoint from six consecutive columns beginning at `base`, in the order every
/// query in this module selects them: `tree_size, log_id, root_hash, checkpoint_time, key_id,
/// signature`.
fn checkpoint_row_from(row: &rusqlite::Row<'_>, base: usize) -> rusqlite::Result<Checkpoint> {
    let at = |offset: usize| base.saturating_add(offset);
    let tree_size: i64 = row.get(at(0))?;
    let tree_size = u64::try_from(tree_size).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::other("tree_size does not fit u64")),
        )
    })?;
    Ok(Checkpoint {
        log_id: row.get(at(1))?,
        tree_size,
        root_hash: row.get(at(2))?,
        checkpoint_time: row.get(at(3))?,
        key_id: row.get(at(4))?,
        signature: row.get(at(5))?,
    })
}

fn row_to_checkpoint(
    result: Result<Checkpoint, rusqlite::Error>,
) -> MirrorResult<Option<Checkpoint>> {
    match result {
        Ok(cp) => Ok(Some(cp)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(MirrorError::from(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(tree_size: u64) -> Checkpoint {
        Checkpoint {
            log_id: "sha256:aa".to_owned(),
            tree_size,
            root_hash: format!("sha256:{tree_size:064x}"),
            checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
            key_id: "sha256:bb".to_owned(),
            signature: "base64:AAAA".to_owned(),
        }
    }

    fn entry_bytes(n: u64) -> Vec<u8> {
        ahl_core::jcs(&serde_json::json!({
            "payload": { "n": n },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }))
    }

    /// A store holding `count` canonical entries, promoted in order.
    fn store_with(count: u64) -> (Store, Vec<Vec<u8>>) {
        let store = Store::open_in_memory().expect("in-memory store");
        let mut entries = Vec::new();
        for index in 0..count {
            let bytes = entry_bytes(index);
            let id = ahl_core::sha256_hex(&bytes);
            store.stage_entry(&id, &bytes).expect("stage");
            store.promote_entry(index, &id).expect("promote");
            entries.push(bytes);
        }
        (store, entries)
    }

    #[test]
    fn promotion_records_the_log_leaf_hash_beside_the_entry() {
        let (store, entries) = store_with(5);
        let stored = store.leaf_hashes_range(0, 5).expect("leaf hashes");
        let expected: Vec<Hash> = entries.iter().map(|b| log_leaf_hash(b)).collect();
        assert_eq!(stored, expected);
        // And the count is answerable without reading a single envelope.
        assert_eq!(store.count_entries(0, 5).expect("count"), 5);
        assert_eq!(store.count_entries(0, 99).expect("count"), 5);
    }

    #[test]
    fn the_subtree_cache_opens_every_span_of_the_tree() {
        // 13 is deliberately neither a power of two nor one less than one, so the tree has a
        // ragged right spine and the cache is exercised alongside the recursion that descends it.
        let (store, entries) = store_with(13);
        let leaves: Vec<Hash> = entries.iter().map(|b| log_leaf_hash(b)).collect();
        for offset in 0..13usize {
            let offset_u64 = u64::try_from(offset).expect("small test offset");
            for size in 1..=(13 - offset) {
                let expected = atl_core::core::merkle::compute_root(&leaves[offset..offset + size]);
                let opened = store
                    .subtree_root(offset_u64, u64::try_from(size).expect("small test size"))
                    .expect("the store holds every leaf of this span");
                assert_eq!(opened, expected, "span [{offset}, {})", offset + size);
            }
        }
    }

    /// The cached prover and the entry-bytes oracle MUST agree: the same root for every
    /// prefix, and the same RFC 9162 consistency path — node for node, in the same order —
    /// for every `(m, n)` pair. Tree sizes 1..=33 cover every ragged right spine a log can
    /// have at small scale (powers of two, one either side of them, and the odd sizes
    /// between), and `m` runs over `0..=n`, so the trivial pairs (`m == 0`, `m == n`) are
    /// covered alongside the rest.
    #[test]
    fn the_cached_prover_agrees_with_an_entry_bytes_build() {
        for size in 1..=33_u64 {
            let (store, entries) = store_with(size);
            let leaves: Vec<Hash> = entries.iter().map(|b| log_leaf_hash(b)).collect();
            for n in 1..=size {
                let end = usize::try_from(n).expect("small test size");
                assert_eq!(
                    store.log_root(n).expect("the store holds this prefix"),
                    compute_root(&leaves[..end]),
                    "tree_size {size}, root over [0, {n})"
                );
                for m in 0..=n {
                    assert_eq!(
                        store.consistency_proof(m, n).expect("the store holds this prefix"),
                        consistency_proof_from_entry_bytes(&entries, m, n).expect("oracle"),
                        "tree_size {size}, consistency ({m}, {n})"
                    );
                }
            }
        }
    }

    #[test]
    fn the_empty_tree_root_is_the_hash_of_no_bytes_and_reads_nothing() {
        let (store, _) = store_with(0);
        assert_eq!(store.log_root(0).expect("the empty tree"), compute_root(&[]));
    }

    #[test]
    fn a_consistency_proof_over_a_prefix_the_store_does_not_hold_is_refused() {
        let (store, _) = store_with(4);
        assert!(matches!(
            store.consistency_proof(2, 9),
            Err(MirrorError::IncompleteEntries { have: 4, need: 9 })
        ));
    }

    /// The measurement this cached prover exists for: a consistency proof between sizes
    /// 5 000 and 10 000 over a ten-thousand-entry log reads a handful of stored 32-octet
    /// nodes and not one entry envelope.
    ///
    /// The entry-bytes build is what the same proof cost before, and is measured here in the
    /// same run rather than quoted, so the comparison is of two numbers this test produced.
    #[test]
    fn a_consistency_proof_over_a_ten_thousand_entry_log_reads_no_entry_bytes() {
        const LOG: u64 = 10_000;
        let (store, entries) = store_with(LOG);

        let (proof, cost) =
            store.consistency_proof_measured(5_000, LOG).expect("the store holds the prefix");
        assert_eq!(
            proof,
            consistency_proof_from_entry_bytes(&entries, 5_000, LOG).expect("oracle"),
            "the cached proof is the entry-bytes proof"
        );

        // What the entry-bytes build read for the same proof: every envelope in [0, 10 000).
        let before: u64 = entries.iter().map(|b| b.len() as u64).sum();
        assert!(
            cost.total_bytes().saturating_mul(500) < before,
            "cached prover read {} bytes; the entry-bytes build read {before}",
            cost.total_bytes()
        );

        // Recorded so the report quotes numbers this test produced rather than an estimate.
        println!(
            "consistency read cost, sizes 5000 -> {LOG} over a {LOG}-entry log: \
             before {before} bytes (entry bytes for the whole prefix), \
             after {} bytes ({} stored tree nodes x 32)",
            cost.total_bytes(),
            cost.tree_nodes
        );
    }

    #[test]
    fn a_store_written_before_the_leaf_hash_column_is_migrated_on_open() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("legacy.sqlite3");
        let entries: Vec<Vec<u8>> = (0..7u64).map(entry_bytes).collect();

        // The schema exactly as it stood before the derived tree material existed: no
        // `leaf_hash` column and no `subtree_roots` table at all.
        {
            let conn = Connection::open(&path).expect("open legacy database");
            conn.execute_batch(
                "CREATE TABLE entries (entry_index INTEGER PRIMARY KEY, \
                 entry_id TEXT NOT NULL UNIQUE, envelope BLOB NOT NULL);",
            )
            .expect("legacy schema");
            for (index, bytes) in entries.iter().enumerate() {
                conn.execute(
                    "INSERT INTO entries (entry_index, entry_id, envelope) VALUES (?1, ?2, ?3)",
                    params![
                        i64::try_from(index).expect("small test index"),
                        ahl_core::sha256_hex(bytes),
                        bytes
                    ],
                )
                .expect("legacy row");
            }
        }

        let store = Store::open(&path).expect("migrate on open");
        let expected: Vec<Hash> = entries.iter().map(|b| log_leaf_hash(b)).collect();
        assert_eq!(store.leaf_hashes_range(0, 7).expect("backfilled"), expected);
        assert_eq!(
            store.subtree_root(0, 7).expect("cache rebuilt"),
            atl_core::core::merkle::compute_root(&expected)
        );
        // Running the migration again is a no-op rather than a second rebuild.
        let reopened = Store::open(&path).expect("reopen");
        assert_eq!(
            reopened.subtree_root(0, 7).expect("cache"),
            atl_core::core::merkle::compute_root(&expected)
        );
    }

    #[test]
    fn a_truncated_subtree_cache_is_rebuilt_on_open() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("short-cache.sqlite3");
        let entries: Vec<Vec<u8>> = (0..9u64).map(entry_bytes).collect();
        {
            let store = Store::open(&path).expect("open");
            for (index, bytes) in entries.iter().enumerate() {
                let id = ahl_core::sha256_hex(bytes);
                store.stage_entry(&id, bytes).expect("stage");
                store
                    .promote_entry(u64::try_from(index).expect("small test index"), &id)
                    .expect("promote");
            }
            store
                .with_conn(|conn| {
                    conn.execute("DELETE FROM subtree_roots WHERE level = 1", [])?;
                    Ok(())
                })
                .expect("truncate the cache behind the store's back");
        }
        let store = Store::open(&path).expect("reopen");
        let expected: Vec<Hash> = entries.iter().map(|b| log_leaf_hash(b)).collect();
        assert_eq!(
            store.subtree_root(0, 9).expect("cache rebuilt"),
            atl_core::core::merkle::compute_root(&expected)
        );
    }

    /// Promotion is two writes — the canonical row and the complete-subtree roots it completes
    /// — and they land together or not at all. Injected here by removing the cache table behind
    /// the store's back, which is the one failure the second write can have that the first
    /// cannot: without the transaction the entry row would commit and the store would carry a
    /// leaf whose tree material never recorded it.
    #[test]
    fn a_failed_cache_write_rolls_the_promotion_back() {
        let store = Store::open_in_memory().expect("in-memory store");
        let first = entry_bytes(0);
        let first_id = ahl_core::sha256_hex(&first);
        store.stage_entry(&first_id, &first).expect("stage");
        store.promote_entry(0, &first_id).expect("promote the first entry");

        // Promoting index 1 makes the leaf count 2, which completes the level-1 node — so this
        // is the promotion whose second write has somewhere to fail.
        store
            .with_conn(|conn| {
                conn.execute("DROP TABLE subtree_roots", [])?;
                Ok(())
            })
            .expect("remove the cache table");

        let second = entry_bytes(1);
        let second_id = ahl_core::sha256_hex(&second);
        store.stage_entry(&second_id, &second).expect("stage");
        assert!(
            store.promote_entry(1, &second_id).is_err(),
            "the cache write fails, so the promotion fails"
        );

        // And it left nothing behind: the index is still free, and the store still ends at 1.
        assert_eq!(store.next_index().expect("next index"), 1);
        assert!(store.get_entry_by_id(&second_id).expect("query").is_none());
        assert_eq!(store.count_entries(0, 99).expect("count"), 1);
    }

    #[test]
    fn a_file_backed_store_persists_across_reopen() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("mirror.sqlite3");

        {
            let store = Store::open(&path).expect("open file-backed store");
            store.stage_entry("sha256:e0", b"a").expect("stage");
            store.promote_entry(0, "sha256:e0").expect("promote");
        }

        let reopened = Store::open(&path).expect("reopen file-backed store");
        assert_eq!(reopened.next_index().expect("next index"), 1);
        assert!(reopened.get_entry_by_id("sha256:e0").expect("query").is_some());
    }

    #[test]
    fn staging_is_not_index_exclusive() {
        let store = Store::open_in_memory().expect("in-memory store");
        // Two different candidates may both be staged even though only one can ever be
        // promoted to a given index — staging never blocks on position.
        store.stage_entry("sha256:genuine", b"genuine bytes").expect("stage genuine");
        store.stage_entry("sha256:garbage", b"garbage bytes").expect("stage garbage");
        assert!(store.get_staged("sha256:genuine").expect("query").is_some());
        assert!(store.get_staged("sha256:garbage").expect("query").is_some());
    }

    #[test]
    fn promotion_requires_a_prior_staged_candidate() {
        let store = Store::open_in_memory().expect("in-memory store");
        assert!(matches!(
            store.promote_entry(0, "sha256:never-staged"),
            Err(MirrorError::NotStaged { .. })
        ));
    }

    #[test]
    fn entries_are_stored_and_fetched_by_id_and_range() {
        let store = Store::open_in_memory().expect("in-memory store");
        assert_eq!(store.next_index().expect("empty store"), 0);
        store.stage_entry("sha256:e0", b"a").expect("stage");
        store.stage_entry("sha256:e1", b"b").expect("stage");
        assert_eq!(
            store.promote_entry(0, "sha256:e0").expect("first promote"),
            InsertOutcome::Inserted
        );
        assert_eq!(
            store.promote_entry(1, "sha256:e1").expect("second promote"),
            InsertOutcome::Inserted
        );
        assert_eq!(store.next_index().expect("two entries stored"), 2);

        let found = store.get_entry_by_id("sha256:e1").expect("query").expect("present");
        assert_eq!(found.entry_index, 1);
        assert_eq!(found.envelope, b"b");

        let range = store.get_entries_range(0, 2).expect("full range");
        assert_eq!(range, vec![b"a".to_vec(), b"b".to_vec()]);

        assert!(store.get_entry_by_id("sha256:missing").expect("query").is_none());
    }

    #[test]
    fn repeated_identical_promotion_is_idempotent() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.stage_entry("sha256:e0", b"a").expect("stage");
        store.promote_entry(0, "sha256:e0").expect("first promote");
        assert_eq!(
            store.promote_entry(0, "sha256:e0").expect("repeat"),
            InsertOutcome::AlreadyPresent
        );
    }

    #[test]
    fn a_conflicting_occupant_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.stage_entry("sha256:e0", b"a").expect("stage first");
        store.stage_entry("sha256:other", b"different").expect("stage second");
        store.promote_entry(0, "sha256:e0").expect("first promote");
        assert!(matches!(
            store.promote_entry(0, "sha256:other"),
            Err(MirrorError::IndexConflict { .. })
        ));
    }

    #[test]
    fn a_gap_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.stage_entry("sha256:e1", b"b").expect("stage");
        assert!(matches!(
            store.promote_entry(1, "sha256:e1"),
            Err(MirrorError::OutOfOrderIndex { expected: 0, got: 1 })
        ));
    }

    #[test]
    fn the_same_entry_id_at_a_second_index_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.stage_entry("sha256:e0", b"a").expect("stage");
        store.promote_entry(0, "sha256:e0").expect("first promote");
        assert!(matches!(
            store.promote_entry(1, "sha256:e0"),
            Err(MirrorError::EntryIdAtDifferentIndex { .. })
        ));
    }

    #[test]
    fn checkpoints_round_trip_and_admit_out_of_order() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.insert_checkpoint(&checkpoint(10)).expect("second checkpoint, admitted first");
        store.insert_checkpoint(&checkpoint(5)).expect("first checkpoint, backfilled");

        assert_eq!(store.get_checkpoint(5).expect("query").expect("present").tree_size, 5);
        assert_eq!(
            store
                .all_checkpoints()
                .expect("series")
                .iter()
                .map(|c| c.tree_size)
                .collect::<Vec<_>>(),
            vec![5, 10]
        );
    }

    #[test]
    fn a_quiet_log_may_republish_the_same_tree_size_at_a_later_time() {
        let store = Store::open_in_memory().expect("in-memory store");
        let mut idle = checkpoint(5);
        idle.checkpoint_time = "2026-01-01T00:05:00.000000000Z".to_owned();
        store.insert_checkpoint(&checkpoint(5)).expect("first publication");
        store.insert_checkpoint(&idle).expect("idle republication at the same tree_size");

        let series = store.all_checkpoints().expect("series");
        assert_eq!(series.len(), 2);
        assert!(series.iter().all(|cp| cp.tree_size == 5));
    }

    #[test]
    fn a_conflicting_series_member_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.insert_checkpoint(&checkpoint(10)).expect("first checkpoint");
        assert_eq!(
            store.insert_checkpoint(&checkpoint(10)).expect("identical repeat"),
            InsertOutcome::AlreadyPresent
        );
        let mut different = checkpoint(10);
        different.root_hash = format!("sha256:{}", "ff".repeat(32));
        assert!(matches!(
            store.insert_checkpoint(&different),
            Err(MirrorError::SeriesMemberConflict { tree_size: 10, .. })
        ));
    }
}
