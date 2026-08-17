//! Deployment configuration: the Data Tree this mirror serves, and the genesis governance
//! anchor it bootstraps key and cadence resolution from (adaptor profile §3, §7.3; core spec
//! §2.3.5).
//!
//! A mirror does not verify producer signatures, walk the statement graph, or validate
//! manifest-chain linkage — that remains a verifier's job (core spec §6). What it *does* do,
//! narrowly, is what adaptor profile §7.3 requires of anyone resolving a checkpoint-signing
//! key: read `manifest`-typed entries it already holds canonically, and use the one active
//! for a given checkpoint's `tree_size` (see [`crate::manifest`]). That resolution has to
//! start somewhere, and per core spec §2.3.5 the genesis manifest's identity and initial key
//! fingerprints are "distributed out-of-band" — exactly the receipt format's local-policy
//! rule for a trust anchor an offline party cannot self-authenticate. This module is that
//! out-of-band configuration.

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
    /// The entry index from which this key may sign checkpoints (adaptor profile §7.3
    /// activation bound). A checkpoint whose `tree_size` is smaller is rejected even if the
    /// signature itself verifies.
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
    /// The entry index from which this key may sign checkpoints; see
    /// [`TrustedLogKeySpec::valid_from_index`].
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
    /// The genesis (index-0) checkpoint-signing key set — trusted directly, not read from
    /// any entry. Superseded in full the moment a `manifest`-typed entry is found canonical
    /// below a checkpoint's `tree_size` (adaptor profile §7.2: "each manifest version's log
    /// ... key objects replace the prior set in full").
    pub keys: Vec<TrustedLogKeySpec>,
    /// The entry id of the trusted genesis manifest (core spec §2.3.5), distributed
    /// out-of-band. When set, the first `manifest`-typed canonical entry this mirror ever
    /// finds MUST carry this entry id, or governance resolution refuses rather than trusting
    /// an unexpected chain start. Strongly recommended; optional only so a deployment without
    /// a published genesis yet can still run in genesis-key-only mode.
    #[serde(default)]
    pub genesis_manifest_entry_id: Option<String>,
    /// The declared checkpoint cadence, in seconds, to assume before any manifest declares
    /// one (adaptor profile §7.2's "checkpoint cadence"; see [`crate::manifest`] for the
    /// field-name/format assumption this crate makes, since the profile gives no literal
    /// JSON schema for the manifest's `log` object). `None` means cadence is unknown until a
    /// manifest supplies it, in which case `ITUB` is unavailable until then (adaptor profile
    /// §5.2.2).
    #[serde(default)]
    pub genesis_checkpoint_cadence_seconds: Option<u64>,
    /// Filesystem path to the `SQLite` store.
    pub store_path: String,
}

/// Resolved configuration: every configured key checked once, up front.
#[derive(Debug, Clone)]
pub struct Config {
    /// The single Data Tree this mirror is bound to.
    pub log_id: String,
    /// The genesis checkpoint-signing key set.
    pub keys: Vec<TrustedLogKey>,
    /// See [`ConfigSpec::genesis_manifest_entry_id`].
    pub genesis_manifest_entry_id: Option<String>,
    /// See [`ConfigSpec::genesis_checkpoint_cadence_seconds`].
    pub genesis_checkpoint_cadence_seconds: Option<u64>,
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
        Ok(Self {
            log_id: spec.log_id.clone(),
            keys,
            genesis_manifest_entry_id: spec.genesis_manifest_entry_id.clone(),
            genesis_checkpoint_cadence_seconds: spec.genesis_checkpoint_cadence_seconds,
            store_path: spec.store_path.clone(),
        })
    }

    /// Look up a genesis-set trusted key by its `key_id`.
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

    fn spec_with(keys: Vec<TrustedLogKeySpec>) -> ConfigSpec {
        ConfigSpec {
            log_id: "sha256:aa".to_owned(),
            keys,
            genesis_manifest_entry_id: None,
            genesis_checkpoint_cadence_seconds: None,
            store_path: ":memory:".to_owned(),
        }
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
        let spec = spec_with(vec![TrustedLogKeySpec {
            key_id: k.key_id(),
            pubkey: k.pubkey(),
            valid_from_index: 0,
        }]);
        let config = Config::resolve(&spec).expect("valid spec");
        assert!(config.key(&k.key_id()).is_some());
        assert!(config.key("sha256:not-present").is_none());
    }

    #[test]
    fn genesis_governance_fields_round_trip() {
        let spec = ConfigSpec {
            log_id: "sha256:aa".to_owned(),
            keys: vec![],
            genesis_manifest_entry_id: Some("sha256:genesis".to_owned()),
            genesis_checkpoint_cadence_seconds: Some(300),
            store_path: ":memory:".to_owned(),
        };
        let config = Config::resolve(&spec).expect("valid spec");
        assert_eq!(config.genesis_manifest_entry_id.as_deref(), Some("sha256:genesis"));
        assert_eq!(config.genesis_checkpoint_cadence_seconds, Some(300));
    }
}
