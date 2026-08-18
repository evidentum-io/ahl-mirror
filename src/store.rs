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
//! Concurrency: the store serializes all access behind one connection and one mutex.
//! Governance resolution and signature verification (read-only) happen before any write; the
//! writes themselves — promoting every entry in a checkpoint's `entries_to_promote` batch and
//! recording the checkpoint — run inside one `SQLite` transaction (see the crate-private
//! `Store::with_transaction` and [`crate::checkpoint::ingest_checkpoint`]), so a batch that
//! fails partway (a bad proof on the third of five entries, say) leaves the store exactly as
//! it was before the request, not partially applied. A mirror is single-writer by
//! construction (one producer, one log, per adaptor profile §3), so cross-request
//! transactions are not needed on top of this.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension as _};

use crate::checkpoint::Checkpoint;
use crate::error::{MirrorError, MirrorResult};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS staged_entries (
    entry_id TEXT PRIMARY KEY,
    envelope BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    entry_index INTEGER PRIMARY KEY,
    entry_id    TEXT NOT NULL UNIQUE,
    envelope    BLOB NOT NULL
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
";

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
            max.map_or(Ok(0), |m| Ok(to_u64("next_index", m)? + 1))
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
    /// # Errors
    ///
    /// [`MirrorError::NotStaged`], [`MirrorError::OutOfOrderIndex`],
    /// [`MirrorError::IndexConflict`], [`MirrorError::EntryIdAtDifferentIndex`], or
    /// [`MirrorError::Store`].
    pub fn promote_entry(&self, entry_index: u64, entry_id: &str) -> MirrorResult<InsertOutcome> {
        self.with_conn(|conn| promote_entry_raw(conn, entry_index, entry_id))
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
        Some(m) => to_u64("next_index", m)? + 1,
    };
    if entry_index != expected {
        return Err(MirrorError::OutOfOrderIndex { expected, got: entry_index });
    }

    conn.execute(
        "INSERT INTO entries (entry_index, entry_id, envelope) VALUES (?1, ?2, ?3)",
        params![index_i64, entry_id, bytes],
    )?;
    Ok(InsertOutcome::Inserted)
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

fn checkpoint_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Checkpoint> {
    let tree_size: i64 = row.get(0)?;
    let tree_size = u64::try_from(tree_size).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::other("tree_size does not fit u64")),
        )
    })?;
    Ok(Checkpoint {
        log_id: row.get(1)?,
        tree_size,
        root_hash: row.get(2)?,
        checkpoint_time: row.get(3)?,
        key_id: row.get(4)?,
        signature: row.get(5)?,
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
