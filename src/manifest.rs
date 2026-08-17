//! Governance: resolving checkpoint-signing keys and cadence.
//!
//! Reads the `manifest` entries this mirror already holds canonically (adaptor profile
//! §7.3; core spec §2.3.5, §7.2), bootstrapped from the genesis anchor in
//! [`crate::config::Config`].
//!
//! # Schema assumption — reported, not quietly picked
//!
//! Core spec §7.2 describes the manifest object's `log` block in prose — "the log's
//! checkpoint-signing key objects `{key_id, pubkey, valid_from_index}`" and "checkpoint
//! cadence" — without a literal JSON example, unlike the statement types of §2.3.1-§2.3.6,
//! which all get one. This module reads a manifest payload shaped:
//!
//! ```text
//! { "type": "manifest",
//!   "log": { "keys": [ { "key_id", "pubkey", "valid_from_index" }, ... ],
//!            "checkpoint_cadence_seconds": <u64> } }
//! ```
//!
//! `log.keys` uses the key-object shape the profile gives verbatim elsewhere. The field
//! names `log.keys` and `log.checkpoint_cadence_seconds` (a plain count of seconds, rather
//! than an ISO 8601 duration or some other encoding) are this crate's own reasonable
//! reading, not a quotation — flagged here and in `README.md` as a gap the next profile
//! revision should close with an actual JSON example, the same way §2.3.1-§2.3.6 have one.
//!
//! # What is, and is not, checked
//!
//! A `manifest` entry is trusted here purely because of *where* it sits: at an entry index
//! below the checkpoint being resolved, in the canonical (proof-admitted) sequence this
//! mirror holds. That is exactly the resolution rule core spec §2.3.5 states — "the manifest
//! version active at entry index i is mechanically resolvable from the log" is a claim about
//! *position*, not about signature chains. This module does **not** validate the manifest's
//! own producer signature, its `predecessor` linkage back to genesis, or that it was itself
//! issued by a key valid under the previous manifest version — those are statement-graph and
//! producer-signature concerns core spec §6 assigns to a verifier, outside this crate's
//! declared scope (see `README.md`, "What this crate is not"). Trusting anchoring position
//! rather than the full governance chain is the cost of resolving checkpoint keys without a
//! verifier in the loop; it is reported here as the narrowest reading that discharges the
//! requirement, not offered as a full manifest verifier.

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::Value;

use crate::config::{Config, TrustedLogKey, TrustedLogKeySpec};
use crate::error::{MirrorError, MirrorResult};
use crate::store::Store;

/// The `log` block of a `manifest` payload, per this module's schema assumption above.
#[derive(Debug, Clone, Deserialize)]
struct ManifestLogBlock {
    #[serde(default)]
    keys: Vec<TrustedLogKeySpec>,
    #[serde(default)]
    checkpoint_cadence_seconds: Option<u64>,
}

/// A resolved governance snapshot: the checkpoint-signing key set and cadence active at some
/// `tree_size`, whether from an anchored manifest or from genesis configuration.
#[derive(Debug, Clone)]
pub struct GovernanceSnapshot {
    keys: Vec<TrustedLogKey>,
    cadence_seconds: Option<u64>,
}

impl GovernanceSnapshot {
    /// Resolve the signing key for `key_id`, honouring the activation bound (adaptor profile
    /// §7.3): retirement is implicit, since a key not present in the *active* snapshot —
    /// because a later manifest version replaced the set without it — is simply not found.
    ///
    /// # Errors
    ///
    /// [`MirrorError::UnknownSigningKey`] if no key with this id is in the active set, or
    /// [`MirrorError::KeyNotYetActive`] if it is present but its `valid_from_index` exceeds
    /// `tree_size`.
    pub fn resolve_key(&self, key_id: &str, tree_size: u64) -> MirrorResult<&VerifyingKey> {
        let key = self
            .keys
            .iter()
            .find(|k| k.key_id == key_id)
            .ok_or_else(|| MirrorError::UnknownSigningKey { key_id: key_id.to_owned() })?;
        if tree_size < key.valid_from_index {
            return Err(MirrorError::KeyNotYetActive {
                key_id: key_id.to_owned(),
                valid_from_index: key.valid_from_index,
                tree_size,
            });
        }
        Ok(&key.verifying_key)
    }

    /// The declared checkpoint cadence, if this snapshot's source declares one. `None` means
    /// cadence is unknown, which makes `ITUB` unavailable (adaptor profile §5.2.2).
    #[must_use]
    pub const fn cadence_seconds(&self) -> Option<u64> {
        self.cadence_seconds
    }
}

/// Resolve the governance snapshot active for a checkpoint at `tree_size`.
///
/// That snapshot comes from the `manifest` entry with the greatest entry index below
/// `tree_size` among this mirror's *canonical* entries, or from the genesis configuration if
/// none has been anchored yet.
///
/// Scans only entries already promoted via [`crate::store::Store::promote_entry`] — never
/// staged, unverified bytes — so a party with no authority over the log cannot influence
/// which keys or cadence this function returns.
///
/// If `tree_size` exceeds how many entries are canonical, this deliberately does **not**
/// error: it resolves against whatever prefix of `[0, tree_size)` the mirror actually holds
/// canonically (possibly a strict, shorter prefix — [`crate::store::Store::get_entries_range`]
/// never errors on an incomplete range, it just returns fewer rows). A manifest rotation
/// could in principle be hiding in the unseen remainder, but that cannot make this function
/// resolve against something *false*: it can only make it resolve against a set that is
/// stale (missing a rotation that truly happened later in the range) or, if the rotation
/// hides a retirement, no longer current. Either way the checkpoint being verified with this
/// snapshot then fails signature/activation checking on its own, safely and without a
/// separate "unresolvable" error class — see [`crate::checkpoint::ingest_checkpoint`]'s docs
/// for why entries a checkpoint submission is simultaneously trying to promote must never be
/// consulted here regardless.
///
/// # Errors
///
/// [`MirrorError::GenesisMismatch`] if a configured genesis entry id is set and the first
/// manifest entry found does not match it, or a store error.
pub fn resolve(store: &Store, config: &Config, tree_size: u64) -> MirrorResult<GovernanceSnapshot> {
    let entries = store.get_entries_range(0, tree_size)?;
    let mut first_manifest_entry_id: Option<String> = None;
    let mut active: Option<ManifestLogBlock> = None;

    for bytes in &entries {
        let Ok(value) = serde_json::from_slice::<Value>(bytes) else { continue };
        let Some(payload) = value.get("payload") else { continue };
        let Some(kind) = payload.get("type").and_then(Value::as_str) else { continue };
        if kind != "manifest" {
            continue;
        }
        if first_manifest_entry_id.is_none() {
            first_manifest_entry_id = Some(ahl_core::entry_id(&value));
        }
        if let Some(log_value) = payload.get("log") {
            if let Ok(log) = serde_json::from_value::<ManifestLogBlock>(log_value.clone()) {
                active = Some(log);
            }
        }
    }

    if let (Some(expected), Some(found)) =
        (&config.genesis_manifest_entry_id, &first_manifest_entry_id)
    {
        if expected != found {
            return Err(MirrorError::GenesisMismatch {
                expected: expected.clone(),
                found: found.clone(),
            });
        }
    }

    match active {
        Some(log) => {
            let keys =
                log.keys.iter().map(TrustedLogKey::resolve).collect::<MirrorResult<Vec<_>>>()?;
            Ok(GovernanceSnapshot { keys, cadence_seconds: log.checkpoint_cadence_seconds })
        }
        None => Ok(GovernanceSnapshot {
            keys: config.keys.clone(),
            cadence_seconds: config.genesis_checkpoint_cadence_seconds,
        }),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sha2::Digest as _;

    use super::*;
    use crate::config::ConfigSpec;

    fn key() -> ahl_core::TestKey {
        ahl_core::TestKey::from_seed_hex("log-1", &"aa".repeat(32)).expect("32-byte seed")
    }

    fn config_with_genesis(k: &ahl_core::TestKey, genesis_id: Option<&str>) -> Config {
        Config::resolve(&ConfigSpec {
            log_id: "sha256:aa".to_owned(),
            keys: vec![TrustedLogKeySpec {
                key_id: k.key_id(),
                pubkey: k.pubkey(),
                valid_from_index: 0,
            }],
            genesis_manifest_entry_id: genesis_id.map(str::to_owned),
            genesis_checkpoint_cadence_seconds: Some(60),
            store_path: ":memory:".to_owned(),
        })
        .expect("valid config")
    }

    fn manifest_entry(producer_key: &ahl_core::TestKey, log_keys: &Value) -> Vec<u8> {
        let payload = json!({
            "type": "manifest",
            "log": { "keys": log_keys, "checkpoint_cadence_seconds": 120 },
        });
        ahl_core::jcs(&ahl_core::envelope(payload, producer_key))
    }

    #[test]
    fn with_no_manifest_yet_genesis_configuration_governs() {
        let k = key();
        let store = Store::open_in_memory().expect("in-memory store");
        let config = config_with_genesis(&k, None);
        let snapshot = resolve(&store, &config, 0).expect("empty range resolves");
        assert_eq!(snapshot.cadence_seconds(), Some(60));
        assert!(snapshot.resolve_key(&k.key_id(), 0).is_ok());
    }

    #[test]
    fn resolving_past_what_is_canonical_falls_back_to_genesis_safely() {
        // No entries are canonical yet, so there is nothing to find a manifest rotation in;
        // resolution does not error, it just uses genesis — and a checkpoint verified
        // against that snapshot will fail its own signature check if it was really signed
        // under a rotation this mirror has not seen (see `ingest_checkpoint`'s docs).
        let store = Store::open_in_memory().expect("in-memory store");
        let k = key();
        let config = config_with_genesis(&k, None);
        let snapshot = resolve(&store, &config, 5).expect("resolves against genesis");
        assert!(snapshot.resolve_key(&k.key_id(), 5).is_ok());
    }

    #[test]
    fn a_manifest_rotation_replaces_the_genesis_set_in_full() {
        let genesis_key = key();
        let rotated_key =
            ahl_core::TestKey::from_seed_hex("log-2", &"bb".repeat(32)).expect("seed");
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"cc".repeat(32)).expect("producer seed");

        let store = Store::open_in_memory().expect("in-memory store");
        let manifest_bytes = manifest_entry(
            &producer,
            &json!([{
                "key_id": rotated_key.key_id(),
                "pubkey": rotated_key.pubkey(),
                "valid_from_index": 1,
            }]),
        );
        let manifest_id = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&manifest_bytes)));
        store.stage_entry(&manifest_id, &manifest_bytes).expect("stage");
        store.promote_entry(0, &manifest_id).expect("promote");

        let config = config_with_genesis(&genesis_key, None);

        // Below the manifest entry: genesis key set still governs.
        let before = resolve(&store, &config, 0).expect("resolves");
        assert!(before.resolve_key(&genesis_key.key_id(), 0).is_ok());

        // At or above it: only the rotated key is recognised.
        let after = resolve(&store, &config, 1).expect("resolves");
        assert!(matches!(
            after.resolve_key(&genesis_key.key_id(), 1),
            Err(MirrorError::UnknownSigningKey { .. })
        ));
        assert!(after.resolve_key(&rotated_key.key_id(), 1).is_ok());
        assert_eq!(after.cadence_seconds(), Some(120));
    }

    #[test]
    fn a_key_below_its_activation_bound_is_rejected() {
        let genesis_key = key();
        let rotated_key =
            ahl_core::TestKey::from_seed_hex("log-2", &"dd".repeat(32)).expect("seed");
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"ee".repeat(32)).expect("producer seed");

        let store = Store::open_in_memory().expect("in-memory store");
        let manifest_bytes = manifest_entry(
            &producer,
            &json!([{
                "key_id": rotated_key.key_id(),
                "pubkey": rotated_key.pubkey(),
                "valid_from_index": 100,
            }]),
        );
        let manifest_id = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&manifest_bytes)));
        store.stage_entry(&manifest_id, &manifest_bytes).expect("stage");
        store.promote_entry(0, &manifest_id).expect("promote");

        let config = config_with_genesis(&genesis_key, None);
        let snapshot = resolve(&store, &config, 1).expect("resolves");
        assert!(matches!(
            snapshot.resolve_key(&rotated_key.key_id(), 1),
            Err(MirrorError::KeyNotYetActive { valid_from_index: 100, tree_size: 1, .. })
        ));
    }

    #[test]
    fn a_genesis_mismatch_refuses_resolution() {
        let genesis_key = key();
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"ff".repeat(32)).expect("producer seed");
        let store = Store::open_in_memory().expect("in-memory store");
        let manifest_bytes = manifest_entry(&producer, &json!([]));
        let manifest_id = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&manifest_bytes)));
        store.stage_entry(&manifest_id, &manifest_bytes).expect("stage");
        store.promote_entry(0, &manifest_id).expect("promote");

        let config = config_with_genesis(&genesis_key, Some("sha256:not-the-real-genesis"));
        assert!(matches!(resolve(&store, &config, 1), Err(MirrorError::GenesisMismatch { .. })));
    }
}
