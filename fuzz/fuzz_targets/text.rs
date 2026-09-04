//! Arbitrary text through the crate's two scalar parsers.
//!
//! `checkpoint_cadence` and `witness_grace_period` are ISO 8601 durations read out of a
//! manifest; `checkpoint_time` is the nine-fractional-digit RFC 3339 rendering read out of a
//! checkpoint. Both accumulate into `u64` nanoseconds, which is where this crate's untrusted
//! multiplication and addition live, and both are reached from documents an outside party
//! supplies. Driving them directly costs one parse per input, so they get far more coverage
//! here than they would behind a whole manifest.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    let _ = ahl_mirror::duration::parse_iso8601_duration_nanos(&text);
    let _ = ahl_mirror::duration::parse_checkpoint_cadence_nanos(&text);
    let _ = ahl_mirror::checkpoint::parse_checkpoint_time(&text);

    // The rendering direction too: it converts a nanosecond count to a calendar date, and the
    // out-of-range end of that conversion is an error rather than a panic.
    let nanos = data
        .get(..8)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map_or(0, u64::from_le_bytes);
    let _ = ahl_mirror::checkpoint::render_checkpoint_time(nanos);
});
