//! Arbitrary bytes as the body of `POST /v1/entries/stage`.
//!
//! The body carries an entry id, the entry envelope as `base64:`-prefixed bytes, and an ATL
//! metadata object — all three attacker-chosen. Behind the parse sits `ingest::stage_entry`,
//! which recomputes the entry id over the decoded bytes, parses them as JSON, checks the
//! envelope shape, re-canonicalizes under JCS and compares byte for byte, then compares the
//! metadata object's canonical form against the profile constant. Every one of those steps
//! reads attacker bytes and must reject rather than abort.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A fresh store per input: staging writes, and a crash must reproduce from this input
    // alone rather than from what earlier inputs left in the database.
    let Some(store) = ahl_mirror_fuzz::fresh_store() else { return };
    let _ = ahl_mirror::http::seam::stage(&store, data);
});
