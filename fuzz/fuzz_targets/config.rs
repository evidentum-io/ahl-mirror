//! Arbitrary bytes as the deployment configuration document.
//!
//! The mirror reads this file at startup and `Config::resolve` checks every configured key
//! object: the `base64:` public key is decoded and its `key_id` recomputed and compared,
//! rather than trusted as written. A malformed configuration must be reported to the operator
//! as an error, not raised as a panic out of `main`.

#![no_main]

use ahl_mirror::config::{Config, ConfigSpec};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(spec) = serde_json::from_slice::<ConfigSpec>(data) else { return };
    let _ = Config::resolve(&spec);
});
