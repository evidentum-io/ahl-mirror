//! Shared fixtures for the `ahl-mirror` fuzz targets.
//!
//! Unlike `ahl-core`, this crate ships no `test_data/` directory — its corpus is a live
//! `SQLite` store, so the fixture is built rather than read. Everything here is derived from
//! two fixed key seeds and a fixed genesis manifest, so it is deterministic, allocates no
//! files and does no I/O: the store is `SQLite`'s in-memory backend.
//!
//! Every accessor returns an `Option` rather than asserting. A fixture that failed to build
//! must not be reported as a crash in the library under test — the target simply does less
//! work for that input.

use std::sync::OnceLock;

use ahl_core::TestKey;
use ahl_mirror::checkpoint::Checkpoint;
use ahl_mirror::config::{Config, ConfigSpec, KeyObjectSpec};
use ahl_mirror::metadata::log_leaf_hash;
use ahl_mirror::store::Store;
use serde_json::{json, Value};

/// The cadence epoch the fixture's genesis manifest declares.
const CADENCE_EPOCH: &str = "2026-01-01T00:00:00Z";
/// A checkpoint time one minute into the genesis manifest's five-minute opening window, in
/// the exact nine-fractional-digit rendering the adaptor profile requires.
const CHECKPOINT_TIME: &str = "2026-01-01T00:01:00.000000000Z";

/// The built fixture: a resolved configuration, the genesis manifest entry it anchors, and a
/// signed checkpoint that commits exactly that one entry.
pub struct Fixture {
    /// Resolved deployment configuration naming `genesis_id` as the trust anchor.
    pub config: Config,
    /// `JCS(envelope)` of the genesis manifest statement.
    pub genesis_bytes: Vec<u8>,
    /// `sha256:<hex>` entry id of `genesis_bytes`.
    pub genesis_id: String,
    /// A checkpoint at `tree_size` 1, signed by the log key the genesis manifest declares.
    pub checkpoint: Checkpoint,
    /// The Data Tree id both the configuration and the checkpoint carry.
    pub log_id: String,
}

fn entry_id_of(bytes: &[u8]) -> String {
    ahl_core::sha256_hex(bytes)
}

fn genesis_manifest_payload(log_id: &str, producer: &TestKey, log_key: &TestKey) -> Value {
    json!({
        "type": "manifest",
        "ahl_version": ahl_core::AHL_VERSION,
        "producer": "producer-1",
        "keys": [
            { "key_id": producer.key_id(), "pubkey": producer.pubkey(), "valid_from_index": 0 }
        ],
        "log": {
            "log_id": log_id,
            "operator": "op-1",
            "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
            "checkpoint_cadence": "PT5M",
            "cadence_epoch": CADENCE_EPOCH,
            "witness_grace_period": "PT10M",
            "keys": [
                { "key_id": log_key.key_id(), "pubkey": log_key.pubkey(), "valid_from_index": 0 }
            ],
        },
    })
}

fn build_fixture() -> Option<Fixture> {
    let producer = TestKey::from_seed_hex("producer", &"90".repeat(32)).ok()?;
    let log_key = TestKey::from_seed_hex("log-1", &"42".repeat(32)).ok()?;
    let log_id = format!("sha256:{}", "77".repeat(32));

    let payload = genesis_manifest_payload(&log_id, &producer, &log_key);
    let genesis_bytes = ahl_core::jcs(&ahl_core::envelope(payload, &producer));
    let genesis_id = entry_id_of(&genesis_bytes);

    let config = Config::resolve(&ConfigSpec {
        log_id: log_id.clone(),
        genesis_manifest_entry_id: genesis_id.clone(),
        genesis_producer_keys: vec![KeyObjectSpec {
            key_id: producer.key_id(),
            pubkey: producer.pubkey(),
            valid_from_index: 0,
        }],
        store_path: ":memory:".to_owned(),
    })
    .ok()?;

    let leaves = [log_leaf_hash(&genesis_bytes)];
    let root = atl_core::core::merkle::compute_root(&leaves);
    let mut checkpoint = Checkpoint {
        log_id: log_id.clone(),
        tree_size: 1,
        root_hash: ahl_core::hash_hex(&root),
        checkpoint_time: CHECKPOINT_TIME.to_owned(),
        key_id: log_key.key_id(),
        signature: String::new(),
    };
    let blob = ahl_mirror::checkpoint::checkpoint_blob(&checkpoint).ok()?;
    checkpoint.signature = log_key.sign(&blob);

    Some(Fixture { config, genesis_bytes, genesis_id, checkpoint, log_id })
}

/// The process-wide fixture, built once.
pub fn fixture() -> Option<&'static Fixture> {
    static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();
    FIXTURE.get_or_init(build_fixture).as_ref()
}

/// The fixture's resolved configuration.
pub fn config() -> Option<&'static Config> {
    Some(&fixture()?.config)
}

/// A fresh in-memory store holding the genesis manifest as canonical entry 0, with the
/// fixture checkpoint admitted through the ordinary ingest path.
///
/// Built per input for the targets that write, so a crash reproduces from the input alone
/// rather than from whatever the preceding inputs happened to leave behind.
pub fn fresh_store() -> Option<Store> {
    let fx = fixture()?;
    let store = Store::open_in_memory().ok()?;
    store.stage_entry(&fx.genesis_id, &fx.genesis_bytes).ok()?;
    store.promote_entry(0, &fx.genesis_id).ok()?;
    ahl_mirror::checkpoint::ingest_checkpoint(&store, &fx.config, &fx.checkpoint, None, &[])
        .ok()?;
    Some(store)
}

/// One shared store, for the targets that only read: the same content [`fresh_store`] builds,
/// opened once so an input is not charged for `SQLite` setup.
pub fn shared_store() -> Option<&'static Store> {
    static STORE: OnceLock<Option<Store>> = OnceLock::new();
    STORE.get_or_init(fresh_store).as_ref()
}

/// The canonical entry bytes held by [`shared_store`], as `manifest::resolve` wants them.
pub fn genesis_prefix() -> Option<&'static [Vec<u8>]> {
    static PREFIX: OnceLock<Option<Vec<Vec<u8>>>> = OnceLock::new();
    PREFIX.get_or_init(|| Some(vec![fixture()?.genesis_bytes.clone()])).as_ref().map(Vec::as_slice)
}
