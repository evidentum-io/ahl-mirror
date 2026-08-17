//! Retrieval by AHL entry id (adaptor profile §10.1.1).

use sha2::{Digest as _, Sha256};

use crate::error::{MirrorError, MirrorResult};
use crate::store::Store;

/// What retrieval by entry id returns: exactly one entry, or an explicit absence.
///
/// Adaptor profile §10.1.1: absence is a fact about the interface, not about the corpus —
/// it MUST NOT be read as evidence that no such entry was ever anchored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retrieved {
    /// The entry bytes (`JCS(envelope)`, unaltered) and the index they were stored at.
    Present {
        /// The entry's position in the log.
        entry_index: u64,
        /// The exact bytes anchored as this entry.
        envelope: Vec<u8>,
    },
    /// This deployment holds no entry with the requested id.
    Absent,
}

/// Retrieve an entry by its AHL entry id.
///
/// Defensively re-checks that the stored bytes still hash to the id they are filed under
/// before returning them — bytes that fail this check are never served, even though
/// promotion (see [`crate::ingest::promote_entry`]) already checked it once, because storage
/// integrity is a separate concern from promotion-time validation.
///
/// # Errors
///
/// Returns [`MirrorError::StoredEntryCorrupt`] if the stored bytes no longer hash to their
/// own key, or a store error.
pub fn retrieve_by_id(store: &Store, entry_id: &str) -> MirrorResult<Retrieved> {
    let Some(crate::store::StoredEntry { entry_index, envelope }) =
        store.get_entry_by_id(entry_id)?
    else {
        return Ok(Retrieved::Absent);
    };
    let recomputed = format!("sha256:{}", hex::encode(Sha256::digest(&envelope)));
    if recomputed != entry_id {
        return Err(MirrorError::StoredEntryCorrupt { entry_id: entry_id.to_owned() });
    }
    Ok(Retrieved::Present { entry_index, envelope })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_entry_is_reported_as_absent_not_an_error() {
        let store = Store::open_in_memory().expect("in-memory store");
        assert_eq!(retrieve_by_id(&store, "sha256:missing").expect("no error"), Retrieved::Absent);
    }

    #[test]
    fn a_present_entry_is_returned_byte_exact() {
        let store = Store::open_in_memory().expect("in-memory store");
        let bytes = b"{\"payload\":{},\"signatures\":[]}".to_vec();
        let id = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        store.stage_entry(&id, &bytes).expect("stage");
        store.promote_entry(0, &id).expect("promote");

        match retrieve_by_id(&store, &id).expect("no error") {
            Retrieved::Present { entry_index, envelope } => {
                assert_eq!(entry_index, 0);
                assert_eq!(envelope, bytes);
            }
            Retrieved::Absent => panic!("expected the entry to be present"),
        }
    }
}
