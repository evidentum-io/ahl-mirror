//! Arbitrary bytes as an anchored governance statement.
//!
//! The manifest chain is walked over canonical entry bytes, so anything that reaches storage
//! reaches this parser. Each input is offered twice: once as the genesis statement itself,
//! and once appended after the fixture's real genesis manifest, which is the position where a
//! rotation is read — producer key objects, the `log` block, the ISO 8601 cadence and grace
//! period, the RFC 3339 cadence epoch and the `predecessor` link.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(config) = ahl_mirror_fuzz::config() else { return };

    // As the genesis statement: reaches the entry-id and producer-signature gate.
    let _ = ahl_mirror::manifest::resolve(&[data.to_vec()], config);

    // As the statement after a genuine genesis: reaches the rotation branch.
    let Some(prefix) = ahl_mirror_fuzz::genesis_prefix() else { return };
    let mut entries = prefix.to_vec();
    entries.push(data.to_vec());
    let _ = ahl_mirror::manifest::resolve(&entries, config);
});
