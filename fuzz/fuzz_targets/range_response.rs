//! Arbitrary bytes as a range-enumeration response document, verified offline.
//!
//! This is what a client runs against a *foreign* mirror's answer, so the whole document is
//! untrusted: the echoed range, the entry list, the `base64:`-wrapped `AHLRP1` proof and the
//! checkpoint it claims to open. `verify_range_response` decodes the proof, re-canonicalizes
//! every carried envelope to recompute its log leaf hash, and checks the proof against the
//! checkpoint's root — reached here without any store at all.

#![no_main]

use ahl_mirror::range::RangeResponse;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(response) = serde_json::from_slice::<RangeResponse>(data) else { return };
    let _ = ahl_mirror::range::verify_range_response(&response);
});
