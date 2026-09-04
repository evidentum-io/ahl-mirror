//! Arbitrary bytes as the path segment and query string of the mirror's `GET` endpoints.
//!
//! The input is split on the first NUL byte: the left half stands in for a path segment
//! (`/v1/entries/{entry_id}`, `/v1/checkpoints/{tree_size}`, `/v1/itub/{index}`,
//! `/v1/rotation-proofs/{manifest_entry_index}`), the right
//! half for a query string (`?encoding=…` on retrieval, `?from=…&to=…` on consistency). Both
//! halves reach the real extractors — `axum`'s `Query` over the module's own private query
//! types — and then the lookups the handlers perform with what comes out.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(store) = ahl_mirror_fuzz::shared_store() else { return };
    let Some(config) = ahl_mirror_fuzz::config() else { return };

    let (path_bytes, query_bytes) = match data.iter().position(|b| *b == 0) {
        Some(at) => (data.get(..at).unwrap_or_default(), data.get(at.saturating_add(1)..)),
        None => (data, None),
    };
    let path = String::from_utf8_lossy(path_bytes);
    let query = String::from_utf8_lossy(query_bytes.unwrap_or_default());

    let _ = ahl_mirror::http::seam::retrieve(store, &path, &query);
    let _ = ahl_mirror::http::seam::consistency(store, config, &query);

    // The numeric path parameters, as `axum` renders them before the handler sees them.
    if let Ok(index) = path.parse::<u64>() {
        let _ = ahl_mirror::http::seam::rotation_proof(store, config, index);
        let Ok(view) = ahl_mirror::checkpoint::series_view(store, config) else { return };
        let _ = ahl_mirror::checkpoint::itub(&view, index);
    }
});
