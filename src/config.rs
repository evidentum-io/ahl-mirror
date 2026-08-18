//! Deployment configuration: the Data Tree this mirror serves, and the genesis governance
//! anchor it bootstraps the verified manifest chain from (core spec §2.3.5, §7.3).
//!
//! A mirror does not walk the statement graph or verify statement *semantics* — that remains
//! a verifier's job (core spec §6). What it does verify, narrowly, is the governance chain
//! itself: every `manifest`/`key` statement's producer signature and (for non-genesis
//! manifests) `predecessor` linkage, exactly as core spec §7.3 requires of anyone resolving a
//! checkpoint-signing key from it (see [`crate::manifest`]). That verification has to start
//! somewhere un-anchored, and per core spec §2.3.5 the genesis manifest's identity and initial
//! key fingerprints are "distributed out-of-band" — the receipt format's local-policy rule for
//! a trust anchor an offline party cannot self-authenticate. This module is that out-of-band
//! configuration: the genesis manifest's entry id, and the **producer** key(s) that must have
//! signed it (not checkpoint-signing keys — those, like everything past genesis, are read only
//! from a verified manifest's own `log.keys`).

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

use crate::error::{MirrorError, MirrorResult};

/// A key object in the shape the specification uses throughout.
///
/// `{key_id, pubkey, valid_from_index}` (core spec §2.3.6, §7.2; adaptor profile §7.2-§7.3)
/// — for a producer key, a log/checkpoint-signing key, or a witness key alike.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyObjectSpec {
    /// `sha256:<hex of SHA-256 over the raw 32-byte public key>`.
    pub key_id: String,
    /// `base64:<raw 32-byte Ed25519 public key>`.
    pub pubkey: String,
    /// The entry index from which this key is valid. For a producer key this gates when it
    /// may sign statements; for a checkpoint-signing key, when it may sign checkpoints — in
    /// both cases a use at a smaller index is rejected even though the signature itself
    /// verifies.
    #[serde(default)]
    pub valid_from_index: u64,
}

/// A key object, resolved and self-checked once: its carried `key_id` recomputes from its
/// `pubkey`.
#[derive(Debug, Clone)]
pub struct ResolvedKeyObject {
    /// The key's id, equal to the id recomputed from `verifying_key`.
    pub key_id: String,
    /// The decoded Ed25519 public key.
    pub verifying_key: VerifyingKey,
    /// The original `base64:...` public key string, kept for [`ahl_core::verify_envelope`]'s
    /// resolver interface, which takes the encoded form rather than a decoded key.
    pub pubkey: String,
    /// See [`KeyObjectSpec::valid_from_index`].
    pub valid_from_index: u64,
}

impl ResolvedKeyObject {
    /// Resolve and self-check a configured or manifest-declared key object.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Ahl`] if `pubkey` is malformed, or
    /// [`MirrorError::ConfigKeyIdMismatch`] if the carried `key_id` disagrees with the id
    /// recomputed from `pubkey` (adaptor profile §7.2: recompute, never trust the carried
    /// value).
    pub fn resolve(spec: &KeyObjectSpec) -> MirrorResult<Self> {
        let verifying_key = ahl_core::decode_pubkey(&spec.pubkey)?;
        let computed =
            format!("sha256:{}", hex::encode(atl_core::compute_key_id(verifying_key.as_bytes())));
        if computed != spec.key_id {
            return Err(MirrorError::ConfigKeyIdMismatch {
                configured: spec.key_id.clone(),
                computed,
            });
        }
        Ok(Self {
            key_id: spec.key_id.clone(),
            verifying_key,
            pubkey: spec.pubkey.clone(),
            valid_from_index: spec.valid_from_index,
        })
    }
}

/// Deployment configuration for one mirror instance, as loaded from file or environment.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigSpec {
    /// `sha256:<hex of the Origin ID>` — the single Data Tree this mirror is bound to
    /// (adaptor profile §3, §7.1).
    pub log_id: String,
    /// The entry id of the trusted genesis manifest (core spec §2.3.5), distributed
    /// out-of-band. The governance chain walk never treats any entry as genesis unless its
    /// entry id equals this.
    pub genesis_manifest_entry_id: String,
    /// The producer key(s) trusted, out-of-band, to have signed the genesis manifest itself.
    /// MUST be non-empty — without at least one, no governance chain can ever start (core spec
    /// §2.3.5).
    pub genesis_producer_keys: Vec<KeyObjectSpec>,
    /// Filesystem path to the `SQLite` store.
    pub store_path: String,
}

/// Resolved configuration: every configured key checked once, up front.
#[derive(Debug, Clone)]
pub struct Config {
    /// The single Data Tree this mirror is bound to.
    pub log_id: String,
    /// The genesis manifest's required entry id.
    pub genesis_manifest_entry_id: String,
    /// The resolved genesis producer key set.
    pub genesis_producer_keys: Vec<ResolvedKeyObject>,
    /// Filesystem path to the `SQLite` store.
    pub store_path: String,
}

impl Config {
    /// Resolve a [`ConfigSpec`], checking every key's `key_id` against its `pubkey`.
    ///
    /// # Errors
    ///
    /// As [`ResolvedKeyObject::resolve`], for the first key that fails, or
    /// [`MirrorError::NoGenesisProducerKeys`] if `genesis_producer_keys` is empty.
    pub fn resolve(spec: &ConfigSpec) -> MirrorResult<Self> {
        if spec.genesis_producer_keys.is_empty() {
            return Err(MirrorError::NoGenesisProducerKeys);
        }
        let genesis_producer_keys = spec
            .genesis_producer_keys
            .iter()
            .map(ResolvedKeyObject::resolve)
            .collect::<MirrorResult<Vec<_>>>()?;
        Ok(Self {
            log_id: spec.log_id.clone(),
            genesis_manifest_entry_id: spec.genesis_manifest_entry_id.clone(),
            genesis_producer_keys,
            store_path: spec.store_path.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_key(seed: &str) -> ahl_core::TestKey {
        ahl_core::TestKey::from_seed_hex("producer", seed).expect("32-byte test seed")
    }

    fn spec_with(genesis_producer_keys: Vec<KeyObjectSpec>) -> ConfigSpec {
        ConfigSpec {
            log_id: "sha256:aa".to_owned(),
            genesis_manifest_entry_id: "sha256:genesis".to_owned(),
            genesis_producer_keys,
            store_path: ":memory:".to_owned(),
        }
    }

    #[test]
    fn a_correctly_derived_key_resolves() {
        let k = seed_key(&"11".repeat(32));
        let spec = KeyObjectSpec { key_id: k.key_id(), pubkey: k.pubkey(), valid_from_index: 0 };
        let resolved = ResolvedKeyObject::resolve(&spec).expect("matching key_id");
        assert_eq!(resolved.key_id, k.key_id());
    }

    #[test]
    fn a_mismatched_key_id_is_rejected() {
        let k = seed_key(&"22".repeat(32));
        let spec = KeyObjectSpec {
            key_id: "sha256:00".to_owned(),
            pubkey: k.pubkey(),
            valid_from_index: 0,
        };
        assert!(matches!(
            ResolvedKeyObject::resolve(&spec),
            Err(MirrorError::ConfigKeyIdMismatch { .. })
        ));
    }

    #[test]
    fn config_resolves_its_genesis_producer_keys() {
        let k = seed_key(&"33".repeat(32));
        let spec = spec_with(vec![KeyObjectSpec {
            key_id: k.key_id(),
            pubkey: k.pubkey(),
            valid_from_index: 0,
        }]);
        let config = Config::resolve(&spec).expect("valid spec");
        assert_eq!(config.genesis_producer_keys.len(), 1);
        assert_eq!(config.genesis_producer_keys[0].key_id, k.key_id());
        assert_eq!(config.genesis_manifest_entry_id, "sha256:genesis");
    }

    #[test]
    fn an_empty_genesis_producer_key_set_is_rejected() {
        let spec = spec_with(vec![]);
        assert!(matches!(Config::resolve(&spec), Err(MirrorError::NoGenesisProducerKeys)));
    }
}
