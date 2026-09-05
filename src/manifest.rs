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

use std::collections::{BTreeSet, HashMap};

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::{Config, KeyObjectSpec, ResolvedKeyObject};
use crate::duration::{parse_checkpoint_cadence_nanos, parse_iso8601_duration_nanos};
use crate::error::{MirrorError, MirrorResult};

#[derive(Debug, Deserialize)]
struct AdaptorBlock {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    hash: String,
}

/// One entry of the manifest's top-level `witnesses` array (core spec §6.2).
#[derive(Debug, Deserialize)]
struct WitnessBlock {
    witness_id: String,
    keys: Vec<KeyObjectSpec>,
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
    witness_keys: Vec<(String, ResolvedKeyObject)>,
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

    /// This version's LOG checkpoint-signing key objects as a SET of
    /// `(key_id, pubkey, valid_from_index)`.
    ///
    /// A set, not a sequence: core spec §6.2 says "each manifest version's log and witness key
    /// objects replace the prior set in full", so re-listing the same objects in a different
    /// order declares the same state and is not a rotation.
    fn log_key_set(&self) -> BTreeSet<(String, String, u64)> {
        self.log_keys
            .iter()
            .map(|k| (k.key_id.clone(), k.pubkey.clone(), k.valid_from_index))
            .collect()
    }

    /// This version's WITNESS key objects as a SET of
    /// `(witness_id, key_id, pubkey, valid_from_index)`.
    ///
    /// `witness_id` is part of the object's identity (I-D §7.1: "A witness key object
    /// additionally carries `witness_id`, the identity under which the manifest declares that
    /// witness"), so the same key declared under a different identity is a different object.
    fn witness_key_set(&self) -> BTreeSet<(String, String, String, u64)> {
        self.witness_keys
            .iter()
            .map(|(witness_id, k)| {
                (witness_id.clone(), k.key_id.clone(), k.pubkey.clone(), k.valid_from_index)
            })
            .collect()
    }

    /// Whether this manifest version is a GOVERNANCE-KEY ROTATION of `predecessor` (I-D §7.1):
    /// "a manifest version whose LOG checkpoint-signing key objects OR whose WITNESS key
    /// objects differ from those of its predecessor in the chain".
    ///
    /// Either set alone is enough, and the I-D says why: "either substitution defeats a
    /// guarantee this document makes".
    #[must_use]
    pub fn rotates(&self, predecessor: &Self) -> bool {
        self.log_key_set() != predecessor.log_key_set()
            || self.witness_key_set() != predecessor.witness_key_set()
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
    // `parse_checkpoint_cadence_nanos`, not the bare duration parser: core spec §7.3 requires
    // `checkpoint_cadence` to be greater than zero, on top of the ordinary duration grammar —
    // a manifest declaring a zero cadence is malformed and simply is not governance, exactly
    // like any other schema defect this function returns `None` for.
    let cadence_nanos = parse_checkpoint_cadence_nanos(&log_block.checkpoint_cadence).ok()?;
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

    // The manifest's WITNESS key objects (core spec §6.2). A mirror neither cosigns nor
    // verifies a cosignature, so it never uses these keys; it reads them because I-D §7.1's
    // governance-key-rotation test is over the log key objects OR the witness key objects, and
    // a comparison that cannot see one half cannot make it. The member is OPTIONAL — §6.2
    // requires it only at L3 — but where present it MUST parse and every key object in it MUST
    // self-check, because treating a schema-invalid witness object as simply absent is exactly
    // how a rotation would hide from the test.
    let witness_keys = match payload.get("witnesses") {
        None => Vec::new(),
        Some(value) => {
            let blocks: Vec<WitnessBlock> = serde_json::from_value(value.clone()).ok()?;
            let mut resolved = Vec::new();
            for block in &blocks {
                for spec in &block.keys {
                    resolved
                        .push((block.witness_id.clone(), ResolvedKeyObject::resolve(spec).ok()?));
                }
            }
            resolved
        }
    };

    Some(GovernanceState {
        producer_keys,
        log_keys,
        witness_keys,
        cadence_nanos,
        cadence_epoch_nanos,
        governing_manifest_entry_index: entry_index,
        governing_manifest_entry_id: entry_id,
        genesis_entry_index,
    })
}

/// Check a governance statement's declared revision before its content is read.
///
/// I-D §7.5 step 1 orders the read "version first, then parse", and §2.2 fixes what the read
/// decides: this revision verifies no material issued under an earlier one. Called only once a
/// statement's producer signature has verified under the key set in force, so that an entry
/// anyone can append cannot abort a walk merely by carrying `type: "manifest"` and an old
/// `ahl_version`.
///
/// # Errors
///
/// [`MirrorError::UnsupportedStatementVersion`] if the statement declares an `ahl_version`
/// other than [`ahl_core::AHL_VERSION`], or declares none.
fn check_statement_version(payload: &Value, entry_index: u64) -> MirrorResult<()> {
    let declared = payload.get("ahl_version").and_then(Value::as_str);
    if declared == Some(ahl_core::AHL_VERSION) {
        return Ok(());
    }
    Err(MirrorError::UnsupportedStatementVersion {
        entry_index,
        declared: declared.map(ToOwned::to_owned),
        expected: ahl_core::AHL_VERSION,
    })
}

/// Evaluate one `manifest` entry against the governance state reached so far.
///
/// Order is fixed and load-bearing: select the candidate by identity (the anchored genesis
/// entry id, or nothing for a successor), authenticate it under the key set in force, check the
/// declared revision, and only then read `predecessor` or any other payload semantics. Reading
/// semantics earlier would let a malformed or non-successor statement return "candidate
/// ignored" before the revision gate ran, so an authentic statement from an earlier revision
/// would leave the previous governance version in force and the walk would report success.
/// An envelope that does not verify stays "candidate ignored": bytes anyone can append must
/// not abort resolution.
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
            let resolve = resolver_from_slice(&config.genesis_producer_keys, entry_index);
            if !ahl_core::verify_envelope(envelope, resolve)? {
                return Ok(());
            }
            check_statement_version(payload, entry_index)?;
            if payload.get("predecessor").is_some() {
                return Ok(()); // predecessor is forbidden for genesis
            }
            *state =
                parse_governance(payload, entry_index, entry_id, &config.log_id, entry_index, None);
        }
        Some(current) => {
            let resolve = resolver_from_map(&current.producer_keys, entry_index);
            if !ahl_core::verify_envelope(envelope, resolve)? {
                return Ok(());
            }
            check_statement_version(payload, entry_index)?;
            let Some(predecessor) = payload.get("predecessor").and_then(Value::as_str) else {
                return Ok(());
            };
            if predecessor != current.governing_manifest_entry_id {
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

/// Evaluate one `key` entry against the governance state reached so far.
///
/// Same fixed order as [`try_apply_manifest`]: authenticate under the producer key set in
/// force, check the declared revision, and only then read `action` and `key`. Reading them
/// first would let an authentic earlier-revision statement that merely omits `action` — or
/// carries an unparsable key object — be skipped instead of refused.
fn try_apply_key(
    state: &mut GovernanceState,
    envelope: &Value,
    payload: &Value,
    entry_index: u64,
) -> MirrorResult<()> {
    let resolve = resolver_from_map(&state.producer_keys, entry_index);
    if !ahl_core::verify_envelope(envelope, resolve)? {
        return Ok(());
    }
    check_statement_version(payload, entry_index)?;

    let Some(action) = payload.get("action").and_then(Value::as_str) else { return Ok(()) };
    let Some(key_value) = payload.get("key") else { return Ok(()) };
    let Ok(key_spec) = serde_json::from_value::<KeyObjectSpec>(key_value.clone()) else {
        return Ok(());
    };

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

/// The one walk of `entries_prefix` both [`resolve`] and [`versions`] are views of.
///
/// `snapshots`, where given, collects the governance state as each manifest version leaves it —
/// after phase 3, so a version that failed its checks contributes nothing. A `key` statement
/// modifies the producer key set and never the log or witness key sets (core spec §2.4.6), so it
/// is applied to the running state but starts no new version.
fn walk(
    entries_prefix: &[Vec<u8>],
    config: &Config,
    mut snapshots: Option<&mut Vec<GovernanceState>>,
) -> MirrorResult<Option<GovernanceState>> {
    let mut state: Option<GovernanceState> = None;
    for (i, bytes) in entries_prefix.iter().enumerate() {
        let index =
            u64::try_from(i).map_err(|_| MirrorError::IndexOverflow { what: "entry index" })?;
        let Ok(envelope) = serde_json::from_slice::<Value>(bytes) else { continue };
        let Some(payload) = envelope.get("payload") else { continue };
        let Some(kind) = payload.get("type").and_then(Value::as_str) else { continue };
        match kind {
            "manifest" => {
                let before = state.as_ref().map(GovernanceState::governing_manifest_entry_index);
                try_apply_manifest(&mut state, &envelope, payload, index, config)?;
                let after = state.as_ref().map(GovernanceState::governing_manifest_entry_index);
                // The governing index moves if and only if a version was actually installed:
                // a candidate that failed selection, authentication or validation leaves it
                // where it was, and two versions can never share an index.
                if before != after {
                    if let (Some(list), Some(current)) = (snapshots.as_deref_mut(), state.as_ref())
                    {
                        list.push(current.clone());
                    }
                }
            }
            "key" => {
                if let Some(current) = state.as_mut() {
                    try_apply_key(current, &envelope, payload, index)?;
                }
            }
            _ => {}
        }
    }
    Ok(state)
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
    let tree_size = u64::try_from(entries_prefix.len())
        .map_err(|_| MirrorError::IndexOverflow { what: "entries_prefix.len()" })?;
    walk(entries_prefix, config, None)?
        .ok_or(MirrorError::GovernanceChainUnresolvable { tree_size })
}

/// Every verified manifest VERSION in `entries_prefix`, in ascending entry-index order: the
/// governance state as each one leaves it, beginning with the genesis manifest.
///
/// This is what a rotation search needs and [`resolve`] cannot give. I-D §7.1 defines a
/// governance-key rotation by comparing a version against ITS PREDECESSOR IN THE CHAIN, and a
/// `rotation_proofs[]` checkpoint's own active version may be "the rotating manifest or a later
/// one" — so a checkpoint far past several rotations still has to be matched against each
/// candidate rotation's own predecessor, not against the state at the end of the prefix.
/// Consecutive elements here are exactly those (predecessor, rotating) pairs.
///
/// # Errors
///
/// As [`resolve`].
pub fn versions(entries_prefix: &[Vec<u8>], config: &Config) -> MirrorResult<Vec<GovernanceState>> {
    let tree_size = u64::try_from(entries_prefix.len())
        .map_err(|_| MirrorError::IndexOverflow { what: "entries_prefix.len()" })?;
    let mut collected = Vec::new();
    walk(entries_prefix, config, Some(&mut collected))?;
    if collected.is_empty() {
        return Err(MirrorError::GovernanceChainUnresolvable { tree_size });
    }
    Ok(collected)
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
            "ahl_version": ahl_core::AHL_VERSION,
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
            "ahl_version": ahl_core::AHL_VERSION,
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
            "ahl_version": ahl_core::AHL_VERSION,
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
            "ahl_version": ahl_core::AHL_VERSION,
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

    /// I-D §7.1: a governance-key rotation is a manifest version "whose LOG checkpoint-signing
    /// key objects OR whose WITNESS key objects differ from those of its predecessor". Either
    /// set alone, and the witness set is the half a log-key comparison alone would miss.
    #[test]
    fn a_manifest_replacing_only_the_witness_set_is_still_a_rotation() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"3a".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"3b".repeat(32)).expect("seed");
        let witness_1 = ahl_core::TestKey::from_seed_hex("w1", &"3c".repeat(32)).expect("seed");
        let witness_2 = ahl_core::TestKey::from_seed_hex("w2", &"3d".repeat(32)).expect("seed");
        let witnesses = |key: &ahl_core::TestKey| json!([{ "witness_id": "witness-1", "keys": producer_key_array(key) }]);

        let mut genesis_payload = json!({
            "type": "manifest",
            "ahl_version": ahl_core::AHL_VERSION,
            "producer": "producer-1",
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT5M", "2026-01-01T00:00:00Z", &producer_key_array(&log_key)
            ),
        });
        genesis_payload["witnesses"] = witnesses(&witness_1);
        let genesis_env = ahl_core::envelope(genesis_payload, &producer);
        let genesis_id = entry_id_of(&genesis_env);
        let config = config_with(&producer, &genesis_id);

        // The LOG key set is untouched; only the witness key object changes.
        let next_payload = json!({
            "type": "manifest",
            "ahl_version": ahl_core::AHL_VERSION,
            "producer": "producer-1",
            "predecessor": genesis_id,
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT5M", "2026-01-01T00:00:00Z", &producer_key_array(&log_key)
            ),
            "witnesses": witnesses(&witness_2),
        });
        let next_env = ahl_core::envelope(next_payload, &producer);

        let entries = vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&next_env)];
        let chain = versions(&entries, &config).expect("valid successor");
        let [outgoing, incoming] = chain.as_slice() else { panic!("two versions") };
        assert_eq!(incoming.governing_manifest_entry_index(), 1);
        assert_eq!(outgoing.governing_manifest_entry_index(), 0);
        assert!(incoming.rotates(outgoing), "the witness key objects differ");

        // And a version that re-declares BOTH sets unchanged is not a rotation, however much
        // else about it moves — the comparison is over the two key sets and nothing else.
        let unchanged_payload = json!({
            "type": "manifest",
            "ahl_version": ahl_core::AHL_VERSION,
            "producer": "producer-1",
            "predecessor": genesis_id,
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT1M", "2026-01-01T00:00:00Z", &producer_key_array(&log_key)
            ),
            "witnesses": witnesses(&witness_1),
        });
        let unchanged_env = ahl_core::envelope(unchanged_payload, &producer);
        let entries = vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&unchanged_env)];
        let chain = versions(&entries, &config).expect("valid successor");
        let [outgoing, incoming] = chain.as_slice() else { panic!("two versions") };
        assert_eq!(incoming.cadence_nanos(), 60_000_000_000, "the cadence did change");
        assert!(!incoming.rotates(outgoing), "neither key set did");
    }

    /// A `witnesses` member that is present but malformed makes the manifest invalid
    /// governance, rather than being read as "no witnesses": treating it as absent is exactly
    /// how a witness-set rotation would escape the comparison above.
    #[test]
    fn a_malformed_witnesses_member_is_not_governance() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"3e".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"3f".repeat(32)).expect("seed");
        let mut payload = json!({
            "type": "manifest",
            "ahl_version": ahl_core::AHL_VERSION,
            "producer": "producer-1",
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT5M", "2026-01-01T00:00:00Z", &producer_key_array(&log_key)
            ),
        });
        payload["witnesses"] = json!([{ "keys": producer_key_array(&log_key) }]);
        let env = ahl_core::envelope(payload, &producer);
        let config = config_with(&producer, &entry_id_of(&env));
        assert!(matches!(
            resolve(&[ahl_core::jcs(&env)], &config),
            Err(MirrorError::GovernanceChainUnresolvable { .. })
        ));
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
            "ahl_version": ahl_core::AHL_VERSION,
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
            "ahl_version": ahl_core::AHL_VERSION,
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

    #[test]
    fn a_genesis_manifest_declaring_a_zero_cadence_is_not_governance() {
        // Core spec §7.3: `checkpoint_cadence` MUST be greater than zero. A manifest
        // declaring `PT0S` is malformed, exactly like a missing field or a bad signature —
        // simply never becomes governance, rather than being accepted with a degenerate
        // cadence.
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"14".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"15".repeat(32)).expect("seed");
        let payload = json!({
            "type": "manifest",
            "ahl_version": ahl_core::AHL_VERSION,
            "producer": "producer-1",
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT0S", "2026-01-01T00:00:00Z", &producer_key_array(&log_key)
            ),
        });
        let genesis_env = ahl_core::envelope(payload, &producer);
        let genesis_id = entry_id_of(&genesis_env);
        let config = config_with(&producer, &genesis_id);
        let bytes = ahl_core::jcs(&genesis_env);

        assert!(matches!(
            resolve(&[bytes], &config),
            Err(MirrorError::GovernanceChainUnresolvable { .. })
        ));
    }

    /// Revision 0.4 verifies no material issued under an earlier revision (I-D §2.2, §7.1).
    ///
    /// This genesis manifest is authentic in every other respect: it is the entry id the
    /// config names, it carries no `predecessor`, and its signature is a well-formed 0.4-shape
    /// entry that verifies under the config's genesis producer key. It declares
    /// `ahl_version: "0.3"`. Governance resolution refuses it and names the declared revision
    /// — it is neither accepted as governance nor skipped the way an unverified candidate is.
    /// The control at the end re-runs the identical fixture with the declared revision changed
    /// to [`ahl_core::AHL_VERSION`] and nothing else changed, so the refusal is attributable to
    /// the declared revision alone rather than to any other property of the fixture.
    #[test]
    fn a_genesis_manifest_declaring_an_earlier_revision_is_refused() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"20".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"21".repeat(32)).expect("seed");
        let payload_at = |version: &str| {
            json!({
                "type": "manifest",
                "ahl_version": version,
                "producer": "producer-1",
                "keys": producer_key_array(&producer),
                "log": log_block(
                    "sha256:aa", "PT5M", "2026-01-01T00:00:00Z",
                    &producer_key_array(&log_key)
                ),
            })
        };

        let legacy_env = ahl_core::envelope(payload_at("0.3"), &producer);
        let legacy_config = config_with(&producer, &entry_id_of(&legacy_env));
        let error = resolve(&[ahl_core::jcs(&legacy_env)], &legacy_config)
            .expect_err("a genesis declaring 0.3 is refused");
        assert!(
            matches!(
                &error,
                MirrorError::UnsupportedStatementVersion {
                    entry_index: 0,
                    declared: Some(declared),
                    expected,
                } if declared == "0.3" && *expected == ahl_core::AHL_VERSION
            ),
            "expected a refusal naming the declared revision, got: {error}"
        );

        // Control: the same fixture differing only in the declared revision.
        let current_env = ahl_core::envelope(payload_at(ahl_core::AHL_VERSION), &producer);
        let current_config = config_with(&producer, &entry_id_of(&current_env));
        let state = resolve(&[ahl_core::jcs(&current_env)], &current_config)
            .expect("the same genesis at the current revision resolves");
        assert_eq!(state.governing_manifest_entry_index(), 0);
    }

    /// Revision 0.4 verifies no material issued under an earlier revision (I-D §2.2, §7.1).
    ///
    /// The successor manifest here is built exactly like the one in
    /// `a_valid_rotation_replaces_the_log_key_set_and_keeps_the_epoch` — correct `predecessor`,
    /// a signature that verifies under the producer key set the genesis put in force — and
    /// differs only in declaring `ahl_version: "0.3"`. It is refused rather than ignored:
    /// ignoring it would leave the genesis governance in force and report success, which is a
    /// ruling on material this revision has no rules for.
    #[test]
    fn a_later_manifest_declaring_an_earlier_revision_is_refused() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"22".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"23".repeat(32)).expect("seed");
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
            ahl_core::TestKey::from_seed_hex("log-2", &"24".repeat(32)).expect("seed");
        let next_payload = json!({
            "type": "manifest",
            "ahl_version": "0.3",
            "producer": "producer-1",
            "predecessor": genesis_id,
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT1M", "2026-01-01T00:00:00Z",
                &producer_key_array(&rotated_log_key)
            ),
        });
        let next_env = ahl_core::envelope(next_payload, &producer);

        let entries = vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&next_env)];
        let error = resolve(&entries, &config).expect_err("a successor declaring 0.3 is refused");
        assert!(
            matches!(
                &error,
                MirrorError::UnsupportedStatementVersion {
                    entry_index: 1,
                    declared: Some(declared),
                    expected,
                } if declared == "0.3" && *expected == ahl_core::AHL_VERSION
            ),
            "expected a refusal at the successor naming the declared revision, got: {error}"
        );
    }

    /// Revision 0.4 verifies no material issued under an earlier revision (I-D §2.2, §7.1).
    ///
    /// The rule covers every governance statement, not just manifests. This `key` statement
    /// adds a producer key and is signed by the producer the genesis put in force, so its
    /// signature verifies and its content would otherwise take effect; it declares
    /// `ahl_version: "0.3"` and is refused at its own entry index instead.
    #[test]
    fn a_key_statement_declaring_an_earlier_revision_is_refused() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"25".repeat(32)).expect("seed");
        let producer_2 =
            ahl_core::TestKey::from_seed_hex("producer-2", &"26".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"27".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &producer,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let config = config_with(&producer, &entry_id_of(&genesis_env));

        let key_payload = json!({
            "type": "key",
            "ahl_version": "0.3",
            "action": "add",
            "key": {
                "key_id": producer_2.key_id(), "pubkey": producer_2.pubkey(), "valid_from_index": 1
            },
        });
        let key_env = ahl_core::envelope(key_payload, &producer);

        let entries = vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&key_env)];
        let error =
            resolve(&entries, &config).expect_err("a key statement declaring 0.3 is refused");
        assert!(
            matches!(
                &error,
                MirrorError::UnsupportedStatementVersion {
                    entry_index: 1,
                    declared: Some(declared),
                    expected,
                } if declared == "0.3" && *expected == ahl_core::AHL_VERSION
            ),
            "expected a refusal at the key statement naming the declared revision, got: {error}"
        );
    }

    /// A statement that declares no revision at all is refused, not read (I-D §7.5 step 1).
    ///
    /// Step 1 of the read is "version first, then parse", so a statement with no
    /// `ahl_version` member never reaches the parse: there is nothing to compare against the
    /// revision this build verifies, and treating the absence as an implicit "current" would
    /// admit exactly the material §2.2 excludes. The refusal reports the absence rather than
    /// inventing a declared value.
    #[test]
    fn a_genesis_manifest_declaring_no_revision_is_refused() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"28".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"29".repeat(32)).expect("seed");
        let payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT5M", "2026-01-01T00:00:00Z",
                &producer_key_array(&log_key)
            ),
        });
        let genesis_env = ahl_core::envelope(payload, &producer);
        let config = config_with(&producer, &entry_id_of(&genesis_env));

        let error = resolve(&[ahl_core::jcs(&genesis_env)], &config)
            .expect_err("a genesis declaring no revision is refused");
        assert!(
            matches!(
                &error,
                MirrorError::UnsupportedStatementVersion {
                    entry_index: 0,
                    declared: None,
                    expected,
                } if *expected == ahl_core::AHL_VERSION
            ),
            "expected a refusal reporting the absent declaration, got: {error}"
        );
    }

    /// A signature entry in the 0.1-era member shape fails envelope verification.
    ///
    /// This fixture declares the current revision and defects only in the signature entry: the
    /// signing key is named by the member `keyid`, as 0.1.x wrote it, where
    /// `ahl_core::verify_envelope` reads `key_id`. The refusal therefore comes out of envelope
    /// verification, before the declared-revision check runs, and names the member it could not
    /// read. What this pins is the consequence of the member rename alone — the revision gate
    /// is pinned by the tests above, which use well-formed signatures.
    #[test]
    fn a_signature_in_the_earlier_member_shape_fails_envelope_verification() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"2a".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"2b".repeat(32)).expect("seed");
        let payload = json!({
            "type": "manifest",
            "ahl_version": ahl_core::AHL_VERSION,
            "producer": "producer-1",
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT5M", "2026-01-01T00:00:00Z",
                &producer_key_array(&log_key)
            ),
        });
        let mut genesis_env = ahl_core::envelope(payload, &producer);
        let signature = genesis_env["signatures"][0]
            .as_object_mut()
            .expect("the envelope helper writes one signature object");
        let key_id = signature.remove("key_id").expect("written under the current member name");
        signature.insert("keyid".to_owned(), key_id);

        let config = config_with(&producer, &entry_id_of(&genesis_env));
        let error = resolve(&[ahl_core::jcs(&genesis_env)], &config)
            .expect_err("an unreadable signature entry is refused");
        assert!(
            matches!(&error, MirrorError::Ahl(ahl_core::AhlError::Field(field)) if field == "key_id"),
            "expected an error naming the unreadable `key_id` member, got: {error}"
        );
    }

    /// The revision gate runs before `action` and `key` are read (I-D §7.5 step 1).
    ///
    /// This `key` statement is genuinely signed by the producer the genesis put in force and
    /// declares `ahl_version: "0.3"`, but carries no `action`. Reading `action` first would
    /// return "candidate ignored" and let the walk finish on the genesis state, reporting
    /// success over material this revision does not verify; authentication and the revision
    /// check therefore come first, and the statement is refused.
    #[test]
    fn a_key_statement_at_an_earlier_revision_is_refused_before_its_action_is_read() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"2c".repeat(32)).expect("seed");
        let producer_2 =
            ahl_core::TestKey::from_seed_hex("producer-2", &"2d".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"2e".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &producer,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let config = config_with(&producer, &entry_id_of(&genesis_env));

        let key_payload = json!({
            "type": "key",
            "ahl_version": "0.3",
            "key": {
                "key_id": producer_2.key_id(), "pubkey": producer_2.pubkey(), "valid_from_index": 1
            },
        });
        let key_env = ahl_core::envelope(key_payload, &producer);

        let entries = vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&key_env)];
        let error = resolve(&entries, &config).expect_err(
            "an authentic 0.3 key statement is refused, not skipped for want of an action",
        );
        assert!(
            matches!(
                &error,
                MirrorError::UnsupportedStatementVersion {
                    entry_index: 1,
                    declared: Some(declared),
                    expected,
                } if declared == "0.3" && *expected == ahl_core::AHL_VERSION
            ),
            "expected a refusal at the key statement naming the declared revision, got: {error}"
        );
    }

    /// The revision gate runs before `predecessor` is read (I-D §7.5 step 1).
    ///
    /// Both fixtures are manifests the producer in force really signed, declaring
    /// `ahl_version: "0.3"`, that would fail the successor link — one carries no `predecessor`,
    /// the other names one that is in no chain. Reading the link first would return "candidate
    /// ignored" and leave the genesis governance standing, so `resolve` would return `Ok` on
    /// the earlier state and the caller would never learn that earlier-revision material was
    /// present. Both are refused instead.
    #[test]
    fn a_later_manifest_at_an_earlier_revision_is_refused_before_predecessor_is_read() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"2f".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"30".repeat(32)).expect("seed");
        let rotated_log_key =
            ahl_core::TestKey::from_seed_hex("log-2", &"31".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &producer,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let config = config_with(&producer, &entry_id_of(&genesis_env));

        let manifest_at_0_3 = |predecessor: Option<&str>| {
            let mut payload = json!({
                "type": "manifest",
                "ahl_version": "0.3",
                "producer": "producer-1",
                "keys": producer_key_array(&producer),
                "log": log_block(
                    "sha256:aa", "PT1M", "2026-01-01T00:00:00Z",
                    &producer_key_array(&rotated_log_key)
                ),
            });
            if let Some(predecessor) = predecessor {
                payload["predecessor"] = json!(predecessor);
            }
            ahl_core::envelope(payload, &producer)
        };

        for (case, next_env) in [
            ("no predecessor at all", manifest_at_0_3(None)),
            (
                "a predecessor naming nothing in the chain",
                manifest_at_0_3(Some("sha256:not-the-genesis-entry-id")),
            ),
        ] {
            let entries = vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&next_env)];
            let error = resolve(&entries, &config)
                .expect_err("an authentic 0.3 successor is refused, not skipped");
            assert!(
                matches!(
                    &error,
                    MirrorError::UnsupportedStatementVersion {
                        entry_index: 1,
                        declared: Some(declared),
                        expected,
                    } if declared == "0.3" && *expected == ahl_core::AHL_VERSION
                ),
                "case `{case}`: expected a refusal at the successor, got: {error}"
            );
        }
    }

    /// The revision gate runs before the genesis `predecessor` prohibition (I-D §7.5 step 1).
    ///
    /// This entry is the one the config names and its signature verifies under the anchored
    /// genesis producer key, so it is the genesis candidate and nothing else can be; it
    /// declares `ahl_version: "0.3"` and, being from an earlier revision, also carries a
    /// `predecessor` that revision 0.4 forbids at genesis. The refusal names the revision — the
    /// gate that decides whether this material is verifiable at all — rather than reporting the
    /// chain unresolvable, which is what silently dropping the candidate on the `predecessor`
    /// prohibition would have produced.
    #[test]
    fn a_genesis_manifest_at_an_earlier_revision_is_refused_before_predecessor_is_read() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"32".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"33".repeat(32)).expect("seed");
        let payload = json!({
            "type": "manifest",
            "ahl_version": "0.3",
            "producer": "producer-1",
            "predecessor": "sha256:a-genesis-may-not-name-one",
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT5M", "2026-01-01T00:00:00Z",
                &producer_key_array(&log_key)
            ),
        });
        let genesis_env = ahl_core::envelope(payload, &producer);
        let config = config_with(&producer, &entry_id_of(&genesis_env));

        let error = resolve(&[ahl_core::jcs(&genesis_env)], &config)
            .expect_err("an authentic 0.3 genesis candidate is refused");
        assert!(
            matches!(
                &error,
                MirrorError::UnsupportedStatementVersion {
                    entry_index: 0,
                    declared: Some(declared),
                    expected,
                } if declared == "0.3" && *expected == ahl_core::AHL_VERSION
            ),
            "expected a refusal naming the declared revision, got: {error}"
        );
    }
}
