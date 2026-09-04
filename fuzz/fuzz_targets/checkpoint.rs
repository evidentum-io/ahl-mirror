//! Arbitrary bytes as the body of `POST /v1/checkpoints`.
//!
//! The widest ingest path the mirror has: a full checkpoint object (log id, tree size, root
//! hash, the nine-fractional-digit time of adaptor profile §6.3, key id and signature), an
//! optional `base64:` 98-byte raw blob reconciled against it, and a batch of pending
//! promotions each carrying its own inclusion path. Admission resolves governance from the
//! stored manifest chain, rebuilds the visible entry prefix, recomputes the root and checks
//! the log signature — parsing untrusted text and arithmetic over untrusted indices
//! throughout.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(store) = ahl_mirror_fuzz::fresh_store() else { return };
    let Some(config) = ahl_mirror_fuzz::config() else { return };
    let _ = ahl_mirror::http::seam::checkpoint_ingest(&store, config, data);
});
