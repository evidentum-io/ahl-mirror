//! Deployment configuration: the Data Tree this mirror serves and the checkpoint-signing
//! keys it trusts (adaptor profile §3, §7.3).
//!
//! A mirror has no access to the AHL manifest chain — it is a storage and proof component,
//! not a corpus verifier (core spec §3.5). Where the profile resolves a checkpoint-signing
//! key against "the manifest version active for the checkpoint's `tree_size`" (§7.3), this
//! crate instead resolves against a small operator-configured trust set. See the README
//! ("Scope and honest gaps") for what that simplification costs.

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

use crate::error::{MirrorError, MirrorResult};

/// A checkpoint-signing key as configured, in the manifest key-object shape (adaptor
/// profile §7.2-§7.3) minus any private material.
#[derive(Debug, Clone, Deserialize)]
pub struct TrustedLogKeySpec {
    /// `sha256:<hex of SHA-256 over the raw 32-byte public key>` (adaptor profile §7.2).
    pub key_id: String,
    /// `base64:<raw 32-byte Ed25519 public key>` (adaptor profile §7.2).
    pub pubkey: String,
    /// Informative in this crate; carried through for parity with the manifest key-object
    /// shape. See the module docs for why currency is not enforced from it.
    #[serde(default)]
    pub valid_from_index: u64,
}

/// A trusted checkpoint-signing key, resolved and self-checked once at load time.
#[derive(Debug, Clone)]
pub struct TrustedLogKey {
    /// The key's id, equal to the id recomputed from `verifying_key`.
    pub key_id: String,
    /// The decoded Ed25519 public key.
    pub verifying_key: VerifyingKey,
    /// Carried through from configuration; see [`TrustedLogKeySpec::valid_from_index`].
    pub valid_from_index: u64,
}

impl TrustedLogKey {
    /// Resolve and self-check a configured key.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Ahl`] if `pubkey` is malformed, or
    /// [`MirrorError::ConfigKeyIdMismatch`] if the carried `key_id` disagrees with the id
    /// recomputed from `pubkey` (adaptor profile §7.2: a verifier MUST recompute a key id
    /// from the public key it is given and MUST reject a mismatch).
    pub fn resolve(spec: &TrustedLogKeySpec) -> MirrorResult<Self> {
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
    /// Checkpoint-signing keys this mirror accepts checkpoints from.
    pub keys: Vec<TrustedLogKeySpec>,
    /// Filesystem path to the `SQLite` store.
    pub store_path: String,
}

/// Resolved configuration: every configured key checked once, up front.
#[derive(Debug, Clone)]
pub struct Config {
    /// The single Data Tree this mirror is bound to.
    pub log_id: String,
    /// Trusted checkpoint-signing keys.
    pub keys: Vec<TrustedLogKey>,
    /// Filesystem path to the `SQLite` store.
    pub store_path: String,
}

impl Config {
    /// Resolve a [`ConfigSpec`], checking every key's `key_id` against its `pubkey`.
    ///
    /// # Errors
    ///
    /// As [`TrustedLogKey::resolve`], for the first key that fails.
    pub fn resolve(spec: &ConfigSpec) -> MirrorResult<Self> {
        let keys =
            spec.keys.iter().map(TrustedLogKey::resolve).collect::<MirrorResult<Vec<_>>>()?;
        Ok(Self { log_id: spec.log_id.clone(), keys, store_path: spec.store_path.clone() })
    }

    /// Look up a trusted key by its `key_id`.
    #[must_use]
    pub fn key(&self, key_id: &str) -> Option<&TrustedLogKey> {
        self.keys.iter().find(|k| k.key_id == key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_key(seed: &str) -> ahl_core::TestKey {
        ahl_core::TestKey::from_seed_hex("log-1", seed).expect("32-byte test seed")
    }

    #[test]
    fn a_correctly_derived_key_resolves() {
        let k = seed_key(&"11".repeat(32));
        let spec =
            TrustedLogKeySpec { key_id: k.key_id(), pubkey: k.pubkey(), valid_from_index: 0 };
        let resolved = TrustedLogKey::resolve(&spec).expect("matching key_id");
        assert_eq!(resolved.key_id, k.key_id());
    }

    #[test]
    fn a_mismatched_key_id_is_rejected() {
        let k = seed_key(&"22".repeat(32));
        let spec = TrustedLogKeySpec {
            key_id: "sha256:00".to_owned(),
            pubkey: k.pubkey(),
            valid_from_index: 0,
        };
        assert!(matches!(
            TrustedLogKey::resolve(&spec),
            Err(MirrorError::ConfigKeyIdMismatch { .. })
        ));
    }

    #[test]
    fn config_resolves_and_looks_up_by_key_id() {
        let k = seed_key(&"33".repeat(32));
        let spec = ConfigSpec {
            log_id: "sha256:aa".to_owned(),
            keys: vec![TrustedLogKeySpec {
                key_id: k.key_id(),
                pubkey: k.pubkey(),
                valid_from_index: 0,
            }],
            store_path: ":memory:".to_owned(),
        };
        let config = Config::resolve(&spec).expect("valid spec");
        assert!(config.key(&k.key_id()).is_some());
        assert!(config.key("sha256:not-present").is_none());
    }
}
