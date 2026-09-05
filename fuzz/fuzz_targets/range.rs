//! Arbitrary bytes as the body of `POST /v1/range`.
//!
//! `{tree_size, from_index, to_index}`, all three client-chosen `u64` values, drive the
//! series-usable checkpoint lookup and then `range::build_range_response`, which opens the
//! stored subtree material outside `[from_index, to_index)`, reads the window's leaf hashes
//! and entry bytes, and generates and re-verifies an `AHLRP1` proof over that span. The range
//! bounds are the crate's clearest untrusted arithmetic and its clearest untrusted slice.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Read-only: the shared store is opened once, so an input is not charged for SQLite setup.
    let Some(store) = ahl_mirror_fuzz::shared_store() else { return };
    let Some(config) = ahl_mirror_fuzz::config() else { return };
    let _ = ahl_mirror::http::seam::range(store, config, data);
});
