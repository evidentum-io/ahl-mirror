//! Durable local storage: entry bytes content-addressed by AHL entry id, indexed by entry
//! position, plus the canonical checkpoint series (adaptor profile §5.2.2, §10).
//!
//! # Why `SQLite`
//!
//! The store needs three things a plain content-addressed directory does not give for free:
//! (1) an atomic, crash-safe link between "this entry index" and "these exact bytes" so
//! ingest can never leave a torn write behind; (2) an efficient "smallest `tree_size`
//! strictly greater than `i`" query for `ITUB` (adaptor profile §5.2.1); (3) an efficient
//! contiguous-range scan for enumeration (§10.3). A single-file `SQLite` database gives all
//! three with one dependency, no server process, and one file to back up — which is what
//! "simple durable local store" (task brief) asks for. Every row is still keyed by the AHL
//! entry id and the entry index exactly as the brief specifies; `SQLite` is the file format,
//! not an architectural commitment beyond that.
//!
//! Concurrency: the store serializes all access behind one connection and one mutex. A
//! mirror is read-heavy and single-writer by construction (one producer, one log, per
//! adaptor profile §3), so this is not a throughput compromise for the workload; it is a
//! correctness simplification the README states plainly.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension as _};

use crate::checkpoint::Checkpoint;
use crate::error::{MirrorError, MirrorResult};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS entries (
    entry_index INTEGER PRIMARY KEY,
    entry_id    TEXT NOT NULL UNIQUE,
    envelope    BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoints (
    tree_size       INTEGER PRIMARY KEY,
    log_id          TEXT NOT NULL,
    root_hash       TEXT NOT NULL,
    checkpoint_time TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    signature       TEXT NOT NULL
);
";

/// The outcome of inserting an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The entry was newly stored.
    Inserted,
    /// The exact same entry id and bytes were already stored at this index; ingest is
    /// idempotent for a repeated, identical submission.
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
    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> MirrorResult<T>) -> MirrorResult<T> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| MirrorError::StoreInit("store mutex poisoned".to_owned()))?;
        let result = f(&conn);
        drop(conn);
        result
    }

    /// The next entry index this store expects (one past the greatest stored index, or 0 for
    /// an empty store).
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

    /// Insert `bytes` at `entry_index` under `entry_id`.
    ///
    /// Idempotent for a repeated, byte-identical submission at the same index. Rejects a gap
    /// (`entry_index` is not the next expected index), a conflicting occupant at that index,
    /// and the same `entry_id` claimed at a second index.
    ///
    /// # Errors
    ///
    /// [`MirrorError::OutOfOrderIndex`], [`MirrorError::IndexConflict`],
    /// [`MirrorError::EntryIdAtDifferentIndex`], or [`MirrorError::Store`].
    pub fn insert_entry(
        &self,
        entry_index: u64,
        entry_id: &str,
        bytes: &[u8],
    ) -> MirrorResult<InsertOutcome> {
        let index_i64 = to_i64("entry_index", entry_index)?;
        self.with_conn(|conn| {
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
                .query_row(
                    "SELECT entry_index FROM entries WHERE entry_id = ?1",
                    [entry_id],
                    |row| row.get(0),
                )
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
        })
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
        let from_i64 = to_i64("from_index", from_index)?;
        let to_i64 = to_i64("to_index", to_index)?;
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT envelope FROM entries WHERE entry_index >= ?1 AND entry_index < ?2 \
                 ORDER BY entry_index ASC",
            )?;
            let rows = stmt.query_map(params![from_i64, to_i64], |row| row.get(0))?;
            rows.collect::<Result<Vec<Vec<u8>>, _>>().map_err(MirrorError::from)
        })
    }

    /// Insert a checkpoint into the canonical series.
    ///
    /// This performs no verification of its own — callers MUST validate the checkpoint's
    /// signature and consistency with the series predecessor (see
    /// [`crate::checkpoint::verify_checkpoint`] and
    /// [`crate::checkpoint::verify_series_consistency`]) before calling it. Rejects a
    /// `tree_size` that is not strictly greater than the series maximum, keeping the series
    /// append-only and ordered (adaptor profile §5.2.2 item 4).
    ///
    /// # Errors
    ///
    /// [`MirrorError::NonMonotonicTreeSize`] or [`MirrorError::Store`].
    pub fn insert_checkpoint(&self, cp: &Checkpoint) -> MirrorResult<()> {
        let tree_size_i64 = to_i64("tree_size", cp.tree_size)?;
        self.with_conn(|conn| {
            let max: Option<i64> =
                conn.query_row("SELECT MAX(tree_size) FROM checkpoints", [], |row| row.get(0))?;
            if let Some(m) = max {
                let maximum = to_u64("tree_size", m)?;
                if cp.tree_size <= maximum {
                    return Err(MirrorError::NonMonotonicTreeSize { maximum, got: cp.tree_size });
                }
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
            Ok(())
        })
    }

    /// Fetch the checkpoint series member with the greatest `tree_size`, i.e. the latest
    /// published checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Store`] on a database failure.
    pub fn latest_checkpoint(&self) -> MirrorResult<Option<Checkpoint>> {
        self.with_conn(|conn| {
            row_to_checkpoint(conn.query_row(
                "SELECT tree_size, log_id, root_hash, checkpoint_time, key_id, signature \
                 FROM checkpoints ORDER BY tree_size DESC LIMIT 1",
                [],
                checkpoint_row,
            ))
        })
    }

    /// Fetch the checkpoint at exactly `tree_size`.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Store`] on a database failure.
    pub fn get_checkpoint(&self, tree_size: u64) -> MirrorResult<Option<Checkpoint>> {
        let tree_size_i64 = to_i64("tree_size", tree_size)?;
        self.with_conn(|conn| {
            row_to_checkpoint(conn.query_row(
                "SELECT tree_size, log_id, root_hash, checkpoint_time, key_id, signature \
                 FROM checkpoints WHERE tree_size = ?1",
                [tree_size_i64],
                checkpoint_row,
            ))
        })
    }

    /// Fetch the checkpoint series member with the smallest `tree_size` strictly greater than
    /// `index` — the checkpoint `ITUB(index)` reads its time from (adaptor profile §5.2.1).
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Store`] on a database failure.
    pub fn itub_checkpoint(&self, index: u64) -> MirrorResult<Option<Checkpoint>> {
        let index_i64 = to_i64("index", index)?;
        self.with_conn(|conn| {
            row_to_checkpoint(conn.query_row(
                "SELECT tree_size, log_id, root_hash, checkpoint_time, key_id, signature \
                 FROM checkpoints WHERE tree_size > ?1 ORDER BY tree_size ASC LIMIT 1",
                [index_i64],
                checkpoint_row,
            ))
        })
    }

    /// The full canonical checkpoint series, ascending by `tree_size` (adaptor profile
    /// §5.2.2).
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Store`] on a database failure.
    pub fn checkpoint_series(&self) -> MirrorResult<Vec<Checkpoint>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT tree_size, log_id, root_hash, checkpoint_time, key_id, signature \
                 FROM checkpoints ORDER BY tree_size ASC",
            )?;
            let rows = stmt.query_map([], checkpoint_row)?;
            rows.collect::<Result<Vec<Checkpoint>, _>>().map_err(MirrorError::from)
        })
    }
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
            store.insert_entry(0, "sha256:e0", b"a").expect("insert");
        }

        let reopened = Store::open(&path).expect("reopen file-backed store");
        assert_eq!(reopened.next_index().expect("next index"), 1);
        assert!(reopened.get_entry_by_id("sha256:e0").expect("query").is_some());
    }

    #[test]
    fn entries_are_stored_and_fetched_by_id_and_range() {
        let store = Store::open_in_memory().expect("in-memory store");
        assert_eq!(store.next_index().expect("empty store"), 0);
        assert_eq!(
            store.insert_entry(0, "sha256:e0", b"a").expect("first insert"),
            InsertOutcome::Inserted
        );
        assert_eq!(
            store.insert_entry(1, "sha256:e1", b"b").expect("second insert"),
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
    fn repeated_identical_ingest_is_idempotent() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.insert_entry(0, "sha256:e0", b"a").expect("first insert");
        assert_eq!(
            store.insert_entry(0, "sha256:e0", b"a").expect("repeat"),
            InsertOutcome::AlreadyPresent
        );
    }

    #[test]
    fn a_conflicting_occupant_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.insert_entry(0, "sha256:e0", b"a").expect("first insert");
        assert!(matches!(
            store.insert_entry(0, "sha256:e0", b"different"),
            Err(MirrorError::IndexConflict { .. })
        ));
    }

    #[test]
    fn a_gap_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        assert!(matches!(
            store.insert_entry(1, "sha256:e1", b"b"),
            Err(MirrorError::OutOfOrderIndex { expected: 0, got: 1 })
        ));
    }

    #[test]
    fn the_same_entry_id_at_a_second_index_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.insert_entry(0, "sha256:e0", b"a").expect("first insert");
        assert!(matches!(
            store.insert_entry(1, "sha256:e0", b"a"),
            Err(MirrorError::EntryIdAtDifferentIndex { .. })
        ));
    }

    #[test]
    fn checkpoints_round_trip_and_stay_ordered() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.insert_checkpoint(&checkpoint(5)).expect("first checkpoint");
        store.insert_checkpoint(&checkpoint(10)).expect("second checkpoint");

        assert_eq!(store.get_checkpoint(5).expect("query").expect("present").tree_size, 5);
        assert_eq!(store.latest_checkpoint().expect("query").expect("present").tree_size, 10);
        assert_eq!(
            store
                .checkpoint_series()
                .expect("series")
                .iter()
                .map(|c| c.tree_size)
                .collect::<Vec<_>>(),
            vec![5, 10]
        );
        assert_eq!(store.itub_checkpoint(7).expect("query").expect("present").tree_size, 10);
        assert_eq!(store.itub_checkpoint(3).expect("query").expect("present").tree_size, 5);
        assert!(store.itub_checkpoint(10).expect("query").is_none());
    }

    #[test]
    fn a_non_monotonic_tree_size_is_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.insert_checkpoint(&checkpoint(10)).expect("first checkpoint");
        assert!(matches!(
            store.insert_checkpoint(&checkpoint(10)),
            Err(MirrorError::NonMonotonicTreeSize { maximum: 10, got: 10 })
        ));
        assert!(matches!(
            store.insert_checkpoint(&checkpoint(5)),
            Err(MirrorError::NonMonotonicTreeSize { maximum: 10, got: 5 })
        ));
    }
}
