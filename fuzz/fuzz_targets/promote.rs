//! Arbitrary bytes as the body of `POST /v1/entries/promote`.
//!
//! The body names a checkpoint by `tree_size` and asserts that a staged entry sits at
//! `leaf_index` under it, with an inclusion path of arbitrary `sha256:<hex>` strings. That
//! path goes through `proof_from_hex` and then RFC 6962 inclusion verification against a root
//! this mirror has already authenticated: a path of any length, with any hex, at any index,
//! against any tree size, must come back as a rejection.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(store) = ahl_mirror_fuzz::fresh_store() else { return };
    let _ = ahl_mirror::http::seam::promote(&store, data);
});
