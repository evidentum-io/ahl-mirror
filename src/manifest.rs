//! Governance: a verified chain of `manifest`/`key` statements, rooted at a configured
//! genesis anchor, giving checkpoint-signing keys and cadence (core spec §7.3; §2.3.5).
//!
//! # Governance statements are not self-authorizing
//!
//! Anchoring proves bytes existed at a position; it does not make a governance statement
//! effective (core spec §7.3, "Governance statements are not self-authorizing"). This module
//! therefore does not trust a `manifest`-typed entry merely because it is canonical. A
//! candidate counts only if:
//!
//! - it is the **genesis** manifest — its entry id equals
//!   [`crate::config::Config::genesis_manifest_entry_id`] and its producer signature verifies
//!   under [`crate::config::Config::genesis_producer_keys`] (the out-of-band trust anchor,
//!   core spec §2.3.5) — or
//! - it is a **non-genesis** manifest whose `predecessor` field names the entry id of the
//!   currently active version and whose producer signature verifies under *that* version's
//!   current producer key set, and whose `log.cadence_epoch` is unchanged from genesis (core
//!   spec §7.3: "the epoch anchors the start of the series and never moves");
//!
//! and a `key` statement counts only if its producer signature verifies under the producer
//! key set currently in force. A candidate failing its check is not governance: it is simply
//! skipped, and the walk continues from whatever the last genuinely verified state was.
//!
//! # Schema
//!
//! Core spec §7.3 gives the manifest `log` object's schema normatively:
//! `{ "log_id", "operator", "adaptor": {"id","hash"}, "checkpoint_cadence", "cadence_epoch",
//! "witness_grace_period", "keys": [{"key_id","pubkey","valid_from_index"}] }`, every member
//! required; `checkpoint_cadence`/`witness_grace_period` are ISO 8601 durations (see
//! [`crate::duration`] for the parsed subset), `cadence_epoch` is RFC 3339. The manifest's
//! top-level `keys` array (core spec §7.2) is the producer-key snapshot, in the same
//! `{key_id, pubkey, valid_from_index}` shape.

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::{Config, KeyObjectSpec, ResolvedKeyObject};
use crate::duration::parse_iso8601_duration_nanos;
use crate::error::{MirrorError, MirrorResult};

#[derive(Debug, Deserialize)]
struct AdaptorBlock {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    hash: String,
}

#[derive(Debug, Deserialize)]
struct LogBlock {
    log_id: String,
    #[allow(dead_code)]
    operator: String,
    #[allow(dead_code)]
    adaptor: AdaptorBlock,
    checkpoint_cadence: String,
    cadence_epoch: String,
    #[allow(dead_code)]
    witness_grace_period: String,
    keys: Vec<KeyObjectSpec>,
}

/// A verified governance snapshot: the producer and checkpoint-signing key sets, and cadence
/// material, in force at the point a chain walk reached.
#[derive(Debug, Clone)]
pub struct GovernanceState {
    producer_keys: HashMap<String, ResolvedKeyObject>,
    log_keys: Vec<ResolvedKeyObject>,
    cadence_nanos: u64,
    cadence_epoch_nanos: u64,
    governing_manifest_entry_index: u64,
    governing_manifest_entry_id: String,
    genesis_entry_index: u64,
}

impl GovernanceState {
    /// Resolve the checkpoint-signing key for `key_id`, honouring its activation bound (core
    /// spec §7.3). Retirement is implicit: a key absent from the *current* version's
    /// `log.keys` — because a later version replaced the set without it — is simply not
    /// found.
    ///
    /// # Errors
    ///
    /// [`MirrorError::UnknownSigningKey`] or [`MirrorError::KeyNotYetActive`].
    pub fn resolve_log_key(&self, key_id: &str, tree_size: u64) -> MirrorResult<&VerifyingKey> {
        let key = self
            .log_keys
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

    /// The `checkpoint_cadence` in force, as a nanosecond duration (core spec §7.3).
    #[must_use]
    pub const fn cadence_nanos(&self) -> u64 {
        self.cadence_nanos
    }

    /// `cadence_epoch`, as unix nanoseconds — fixed for the whole corpus by the genesis
    /// manifest (core spec §7.3).
    #[must_use]
    pub const fn cadence_epoch_nanos(&self) -> u64 {
        self.cadence_epoch_nanos
    }

    /// The entry index of the manifest version currently governing.
    #[must_use]
    pub const fn governing_manifest_entry_index(&self) -> u64 {
        self.governing_manifest_entry_index
    }

    /// The entry index of the verified genesis manifest — fixed for the whole corpus.
    ///
    /// `genesis_entry_index + 1` is the `tree_size` of the corpus's *genesis checkpoint* —
    /// core spec §7.3 defines it as "the checkpoint whose `tree_size` equals the genesis
    /// manifest's entry index plus one" — but that checkpoint "need not be published, and is
    /// not a start point" (§7.3): it plays no role in judging series completeness. What this
    /// value grounds instead is the corpus-validity window check: the *earliest* checkpoint
    /// that *commits* the genesis manifest (any series-usable checkpoint with `tree_size >=
    /// genesis_entry_index + 1`) MUST fall within `[cadence_epoch, cadence_epoch +
    /// checkpoint_cadence]` of the genesis manifest version (see the private
    /// `compute_gap_free_frontier` in [`crate::checkpoint`]).
    #[must_use]
    pub const fn genesis_entry_index(&self) -> u64 {
        self.genesis_entry_index
    }
}

fn resolver_from_map(
    keys: &HashMap<String, ResolvedKeyObject>,
    at_index: u64,
) -> impl Fn(&str) -> Option<String> + '_ {
    move |key_id| {
        let key = keys.get(key_id)?;
        (key.valid_from_index <= at_index).then(|| key.pubkey.clone())
    }
}

fn resolver_from_slice(
    keys: &[ResolvedKeyObject],
    at_index: u64,
) -> impl Fn(&str) -> Option<String> + '_ {
    move |key_id| {
        let key = keys.iter().find(|k| k.key_id == key_id)?;
        (key.valid_from_index <= at_index).then(|| key.pubkey.clone())
    }
}

/// Parse an RFC 3339 timestamp to unix nanoseconds.
fn parse_rfc3339_nanos(value: &str) -> MirrorResult<u64> {
    let bad = || MirrorError::BadCadenceEpoch { value: value.to_owned() };
    let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| bad())?;
    u64::try_from(parsed.unix_timestamp_nanos()).map_err(|_| bad())
}

/// Try to build a [`GovernanceState`] from a candidate manifest payload's `log` block and
/// top-level producer `keys` array. Returns `None` (not an error) for any schema or content
/// defect — a malformed manifest is simply not valid governance, core spec §7.3.
fn parse_governance(
    payload: &Value,
    entry_index: u64,
    entry_id: String,
    log_id: &str,
    genesis_entry_index: u64,
    required_epoch_nanos: Option<u64>,
) -> Option<GovernanceState> {
    let producer_keys_value = payload.get("keys")?.clone();
    let producer_key_specs: Vec<KeyObjectSpec> =
        serde_json::from_value(producer_keys_value).ok()?;
    let mut producer_keys = HashMap::new();
    for spec in &producer_key_specs {
        let resolved = ResolvedKeyObject::resolve(spec).ok()?;
        producer_keys.insert(resolved.key_id.clone(), resolved);
    }

    let log_value = payload.get("log")?.clone();
    let log_block: LogBlock = serde_json::from_value(log_value).ok()?;
    if log_block.log_id != log_id {
        return None;
    }
    let cadence_nanos = parse_iso8601_duration_nanos(&log_block.checkpoint_cadence).ok()?;
    // Required present and parseable, though this crate does not otherwise act on it.
    let _witness_grace_period =
        parse_iso8601_duration_nanos(&log_block.witness_grace_period).ok()?;
    let cadence_epoch_nanos = parse_rfc3339_nanos(&log_block.cadence_epoch).ok()?;
    if let Some(required) = required_epoch_nanos {
        if cadence_epoch_nanos != required {
            return None; // "a later version declaring a different epoch is malformed"
        }
    }

    let mut log_keys = Vec::with_capacity(log_block.keys.len());
    for spec in &log_block.keys {
        log_keys.push(ResolvedKeyObject::resolve(spec).ok()?);
    }

    Some(GovernanceState {
        producer_keys,
        log_keys,
        cadence_nanos,
        cadence_epoch_nanos,
        governing_manifest_entry_index: entry_index,
        governing_manifest_entry_id: entry_id,
        genesis_entry_index,
    })
}

fn try_apply_manifest(
    state: &mut Option<GovernanceState>,
    envelope: &Value,
    payload: &Value,
    entry_index: u64,
    config: &Config,
) -> MirrorResult<()> {
    let entry_id = ahl_core::entry_id(envelope);
    match state {
        None => {
            if entry_id != config.genesis_manifest_entry_id {
                return Ok(());
            }
            if payload.get("predecessor").is_some() {
                return Ok(()); // predecessor is forbidden for genesis
            }
            let resolve = resolver_from_slice(&config.genesis_producer_keys, entry_index);
            if !ahl_core::verify_envelope(envelope, resolve)? {
                return Ok(());
            }
            *state =
                parse_governance(payload, entry_index, entry_id, &config.log_id, entry_index, None);
        }
        Some(current) => {
            let Some(predecessor) = payload.get("predecessor").and_then(Value::as_str) else {
                return Ok(());
            };
            if predecessor != current.governing_manifest_entry_id {
                return Ok(());
            }
            let resolve = resolver_from_map(&current.producer_keys, entry_index);
            if !ahl_core::verify_envelope(envelope, resolve)? {
                return Ok(());
            }
            let next = parse_governance(
                payload,
                entry_index,
                entry_id,
                &config.log_id,
                current.genesis_entry_index,
                Some(current.cadence_epoch_nanos),
            );
            if let Some(next) = next {
                *state = Some(next);
            }
        }
    }
    Ok(())
}

fn try_apply_key(
    state: &mut GovernanceState,
    envelope: &Value,
    payload: &Value,
    entry_index: u64,
) -> MirrorResult<()> {
    let Some(action) = payload.get("action").and_then(Value::as_str) else { return Ok(()) };
    let Some(key_value) = payload.get("key") else { return Ok(()) };
    let Ok(key_spec) = serde_json::from_value::<KeyObjectSpec>(key_value.clone()) else {
        return Ok(());
    };

    let resolve = resolver_from_map(&state.producer_keys, entry_index);
    if !ahl_core::verify_envelope(envelope, resolve)? {
        return Ok(());
    }

    match action {
        "add" => {
            if let Ok(resolved) = ResolvedKeyObject::resolve(&key_spec) {
                state.producer_keys.insert(resolved.key_id.clone(), resolved);
            }
        }
        "retire" => {
            state.producer_keys.remove(&key_spec.key_id);
        }
        _ => {}
    }
    Ok(())
}

/// Walk `entries_prefix` and return the governance state active at the end of it.
///
/// `entries_prefix` MUST be the complete, contiguous entry sequence
/// `[0, entries_prefix.len())`; every `manifest`/`key` statement it contains is verified
/// along the way.
///
/// # Errors
///
/// Returns [`MirrorError::GovernanceChainUnresolvable`] if no verified genesis manifest is
/// reached within `entries_prefix` (whether because it is not there yet, or because no entry
/// verifies as the configured genesis anchor).
pub fn resolve(entries_prefix: &[Vec<u8>], config: &Config) -> MirrorResult<GovernanceState> {
    let mut state: Option<GovernanceState> = None;
    for (i, bytes) in entries_prefix.iter().enumerate() {
        let index =
            u64::try_from(i).map_err(|_| MirrorError::IndexOverflow { what: "entry index" })?;
        let Ok(envelope) = serde_json::from_slice::<Value>(bytes) else { continue };
        let Some(payload) = envelope.get("payload") else { continue };
        let Some(kind) = payload.get("type").and_then(Value::as_str) else { continue };
        match kind {
            "manifest" => try_apply_manifest(&mut state, &envelope, payload, index, config)?,
            "key" => {
                if let Some(current) = state.as_mut() {
                    try_apply_key(current, &envelope, payload, index)?;
                }
            }
            _ => {}
        }
    }
    let tree_size = u64::try_from(entries_prefix.len())
        .map_err(|_| MirrorError::IndexOverflow { what: "entries_prefix.len()" })?;
    state.ok_or(MirrorError::GovernanceChainUnresolvable { tree_size })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::config::ConfigSpec;

    fn config_with(genesis: &ahl_core::TestKey, genesis_entry_id: &str) -> Config {
        Config::resolve(&ConfigSpec {
            log_id: "sha256:aa".to_owned(),
            genesis_manifest_entry_id: genesis_entry_id.to_owned(),
            genesis_producer_keys: vec![KeyObjectSpec {
                key_id: genesis.key_id(),
                pubkey: genesis.pubkey(),
                valid_from_index: 0,
            }],
            store_path: ":memory:".to_owned(),
        })
        .expect("valid config")
    }

    fn log_block(log_id: &str, cadence: &str, epoch: &str, keys: &Value) -> Value {
        json!({
            "log_id": log_id,
            "operator": "op-1",
            "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
            "checkpoint_cadence": cadence,
            "cadence_epoch": epoch,
            "witness_grace_period": "PT10M",
            "keys": keys,
        })
    }

    fn genesis_manifest(
        producer: &ahl_core::TestKey,
        log_id: &str,
        producer_keys: &Value,
        log_keys: &Value,
        epoch: &str,
    ) -> Value {
        let payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "keys": producer_keys,
            "log": log_block(log_id, "PT5M", epoch, log_keys),
        });
        ahl_core::envelope(payload, producer)
    }

    fn entry_id_of(envelope: &Value) -> String {
        ahl_core::entry_id(envelope)
    }

    fn producer_key_array(k: &ahl_core::TestKey) -> Value {
        json!([{ "key_id": k.key_id(), "pubkey": k.pubkey(), "valid_from_index": 0 }])
    }

    #[test]
    fn a_verified_genesis_manifest_establishes_governance() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"01".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"02".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &producer,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let genesis_id = entry_id_of(&genesis_env);
        let config = config_with(&producer, &genesis_id);
        let bytes = ahl_core::jcs(&genesis_env);

        let state = resolve(&[bytes], &config).expect("genesis verifies");
        assert_eq!(state.genesis_entry_index(), 0);
        assert_eq!(state.governing_manifest_entry_index(), 0);
        assert!(state.resolve_log_key(&log_key.key_id(), 0).is_ok());
        assert_eq!(state.cadence_nanos(), 300_000_000_000);
    }

    #[test]
    fn a_manifest_with_an_invalid_producer_signature_is_not_governance() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"03".repeat(32)).expect("seed");
        let impostor =
            ahl_core::TestKey::from_seed_hex("impostor", &"04".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"05".repeat(32)).expect("seed");
        // Signed by a key never trusted as the genesis producer.
        let genesis_env = genesis_manifest(
            &impostor,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let genesis_id = entry_id_of(&genesis_env);
        let config = config_with(&producer, &genesis_id);
        let bytes = ahl_core::jcs(&genesis_env);

        assert!(matches!(
            resolve(&[bytes], &config),
            Err(MirrorError::GovernanceChainUnresolvable { .. })
        ));
    }

    #[test]
    fn a_manifest_with_a_bad_predecessor_link_is_not_governance() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"06".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"07".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &producer,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let genesis_id = entry_id_of(&genesis_env);
        let config = config_with(&producer, &genesis_id);

        let rotated_log_key =
            ahl_core::TestKey::from_seed_hex("log-2", &"08".repeat(32)).expect("seed");
        let bad_next_payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "predecessor": "sha256:not-the-genesis-entry-id",
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT5M", "2026-01-01T00:00:00Z", &producer_key_array(&rotated_log_key)
            ),
        });
        let bad_next_env = ahl_core::envelope(bad_next_payload, &producer);

        let entries = vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&bad_next_env)];
        let state = resolve(&entries, &config).expect("genesis alone still resolves");
        // The bad rotation never took effect: the genesis log key is still the active one.
        assert!(state.resolve_log_key(&log_key.key_id(), 1).is_ok());
        assert!(state.resolve_log_key(&rotated_log_key.key_id(), 1).is_err());
    }

    #[test]
    fn a_later_manifest_changing_the_epoch_is_malformed_and_ignored() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"09".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"0a".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &producer,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let genesis_id = entry_id_of(&genesis_env);
        let config = config_with(&producer, &genesis_id);

        let rotated_log_key =
            ahl_core::TestKey::from_seed_hex("log-2", &"0b".repeat(32)).expect("seed");
        let next_payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "predecessor": genesis_id,
            "keys": producer_key_array(&producer),
            // Different epoch than genesis declared: malformed per core spec §7.3.
            "log": log_block(
                "sha256:aa", "PT5M", "2026-06-01T00:00:00Z", &producer_key_array(&rotated_log_key)
            ),
        });
        let next_env = ahl_core::envelope(next_payload, &producer);

        let entries = vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&next_env)];
        let state = resolve(&entries, &config).expect("genesis still resolves");
        assert!(state.resolve_log_key(&log_key.key_id(), 1).is_ok());
        assert!(state.resolve_log_key(&rotated_log_key.key_id(), 1).is_err());
    }

    #[test]
    fn a_valid_rotation_replaces_the_log_key_set_and_keeps_the_epoch() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"0c".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"0d".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &producer,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let genesis_id = entry_id_of(&genesis_env);
        let config = config_with(&producer, &genesis_id);

        let rotated_log_key =
            ahl_core::TestKey::from_seed_hex("log-2", &"0e".repeat(32)).expect("seed");
        let next_payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "predecessor": genesis_id,
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT1M", "2026-01-01T00:00:00Z", &producer_key_array(&rotated_log_key)
            ),
        });
        let next_env = ahl_core::envelope(next_payload, &producer);

        let entries = vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&next_env)];
        let state = resolve(&entries, &config).expect("valid rotation resolves");
        assert_eq!(state.governing_manifest_entry_index(), 1);
        assert_eq!(state.genesis_entry_index(), 0);
        assert_eq!(state.cadence_nanos(), 60_000_000_000);
        assert!(state.resolve_log_key(&rotated_log_key.key_id(), 1).is_ok());
        // Retired: the version-1 manifest replaced the log key set in full.
        assert!(state.resolve_log_key(&log_key.key_id(), 1).is_err());
    }

    #[test]
    fn an_empty_prefix_is_unresolvable() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"0f".repeat(32)).expect("seed");
        let config = config_with(&producer, "sha256:never-seen");
        assert!(matches!(
            resolve(&[], &config),
            Err(MirrorError::GovernanceChainUnresolvable { tree_size: 0 })
        ));
    }

    #[test]
    fn a_key_statement_rotates_producer_keys_and_gates_later_manifests() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"10".repeat(32)).expect("seed");
        let producer_2 =
            ahl_core::TestKey::from_seed_hex("producer-2", &"11".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"12".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &producer,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let genesis_id = entry_id_of(&genesis_env);
        let config = config_with(&producer, &genesis_id);

        // A `key` statement adds producer_2, signed by the currently-valid producer.
        let key_payload = json!({
            "type": "key",
            "action": "add",
            "key": {
                "key_id": producer_2.key_id(), "pubkey": producer_2.pubkey(), "valid_from_index": 1
            },
        });
        let key_env = ahl_core::envelope(key_payload, &producer);

        // A later manifest, signed by the newly added producer_2, links to genesis.
        let rotated_log_key =
            ahl_core::TestKey::from_seed_hex("log-2", &"13".repeat(32)).expect("seed");
        let next_payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "predecessor": genesis_id,
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT5M", "2026-01-01T00:00:00Z", &producer_key_array(&rotated_log_key)
            ),
        });
        let next_env = ahl_core::envelope(next_payload, &producer_2);

        let entries =
            vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&key_env), ahl_core::jcs(&next_env)];
        let state = resolve(&entries, &config).expect("chain resolves");
        assert_eq!(state.governing_manifest_entry_index(), 2);
        assert!(state.resolve_log_key(&rotated_log_key.key_id(), 2).is_ok());
    }
}
