//! One `governance.rotation_proofs[]` element, assembled from both components and verified.
//!
//! I-D §7.1 splits that element between two parties by construction. A mirror holds the
//! rotation-anchoring checkpoint and can open its `inclusion_path` from its own tree material,
//! but it does not cosign, so the `witnesses` member it serves is empty. A witness produces the
//! cosignature, under the OUTGOING witness set, but holds no entries and opens no path. Neither
//! crate's own tests can show that the two halves compose, because each holds only its own —
//! which is exactly why this file runs both servers over one corpus and hands the composed
//! element to `ahl_core`'s verifier without editing a byte of it.
//!
//! The corpus is L3 and rotates the LOG key at entry index 1, so the rotation proof is required
//! (§7.5.1 4b(M)) and its cosignature requirement is live.

// Test code favours `.expect()` messages that document the fixture and direct indexing over
// shapes it fixes itself: an assertion that fires IS the failure report here. `lib.rs` grants
// the same allowance to the crate's inline test modules under `cfg(test)`; an integration test
// is a separate crate, so it carries it itself. Production code paths are held to the
// manifest's deny without exception.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use ahl_core::receipt::{
    verify_receipt_report, AdaptorCapabilities, AdaptorProfile, Limits, Outcome, TrustPolicy,
};
use ahl_mirror::checkpoint::{checkpoint_blob, Checkpoint};
use ahl_mirror::config::{Config, ConfigSpec, KeyObjectSpec};
use ahl_mirror::metadata::log_leaf_hash;
use ahl_witness::config::{
    Ed25519WitnessSigner, KeyObjectSpec as WitnessKeySpec, LogAnchor, LogAnchorSpec,
    WitnessSigner as _,
};
use atl_core::core::merkle::{compute_root, Hash};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use tower::ServiceExt as _;

/// The artifact a verifier holds under `ahl-adaptor-atl-v1` here. Its bytes are what the
/// manifests' `log.adaptor.hash` pins, recomputed rather than transcribed.
const PROFILE_DOCUMENT: &[u8] = b"ahl-adaptor-atl-v1 test artifact";

/// The entry index the rotating manifest is anchored at.
const ROTATING_INDEX: u64 = 1;

/// The raw Ed25519 seed the witness signs with.
const WITNESS_SEED: [u8; 32] = [0x0e; 32];

fn key(tag: &'static str, byte: u8) -> ahl_core::TestKey {
    ahl_core::TestKey::from_seed_hex(tag, &format!("{byte:02x}").repeat(32)).expect("32-byte seed")
}

fn manifest_payload(
    log_id: &str,
    producer: &ahl_core::TestKey,
    log_key: &ahl_core::TestKey,
    witness: &ahl_core::TestKey,
    predecessor: Option<&str>,
) -> Value {
    let mut payload = json!({
        "ahl_version": ahl_core::AHL_VERSION,
        "type": "manifest",
        "producer": "producer-1",
        "issued_at": "2026-01-01T00:00:00Z",
        "valid_time": "2026-01-01T00:00:00Z",
        "keys": [ { "key_id": producer.key_id(), "pubkey": producer.pubkey() } ],
        "log": {
            "log_id": log_id,
            "operator": "log-operator-1",
            "adaptor": {
                "id": ahl_core::ATL_PROFILE_ID,
                "hash": ahl_core::sha256_hex(PROFILE_DOCUMENT),
            },
            "checkpoint_cadence": "PT1H",
            "cadence_epoch": "2026-01-01T00:00:00Z",
            "witness_grace_period": "PT15M",
            "keys": [ {
                "key_id": log_key.key_id(),
                "pubkey": log_key.pubkey(),
                "valid_from_index": 0,
            } ],
        },
        "witnesses": [ {
            "witness_id": "witness-1",
            "keys": [ {
                "key_id": witness.key_id(),
                "pubkey": witness.pubkey(),
                "valid_from_index": 0,
            } ],
        } ],
        "datasets": {
            "records": {
                "canonicalization": "jcs",
                "commitment_mode": "plain",
                "key_access": "not-applicable",
                "authority": { "producer": "producer-1", "key_ids": [ producer.key_id() ] },
            },
        },
        "pipelines": { "include": [], "exclude": [] },
        "windows": { "anchoring": "PT24H", "propagation": "P30D" },
        "retention": { "statements": "P10Y" },
        "properties": { "reproducible_reconstruction": false },
        "level": "L3",
    });
    if let Some(predecessor) = predecessor {
        payload["predecessor"] = json!(predecessor);
    }
    payload
}

/// One corpus, served by both components.
struct Deployment {
    mirror: Router,
    witness: Router,
    producer: ahl_core::TestKey,
    outgoing: ahl_core::TestKey,
    incoming: ahl_core::TestKey,
    witness_key: ahl_core::TestKey,
    log_id: String,
    genesis_entry_id: String,
    envelopes: Vec<Value>,
    entries: Vec<Vec<u8>>,
    leaves: Vec<Hash>,
    root: Hash,
}

impl Deployment {
    /// A checkpoint over the whole three-entry tree, signed by `key`.
    fn checkpoint(&self, key: &ahl_core::TestKey, time: &str) -> Checkpoint {
        let mut cp = Checkpoint {
            log_id: self.log_id.clone(),
            tree_size: 3,
            root_hash: format!("sha256:{}", hex::encode(self.root)),
            checkpoint_time: time.to_owned(),
            key_id: key.key_id(),
            signature: String::new(),
        };
        cp.signature = key.sign(&checkpoint_blob(&cp).expect("well-formed fields"));
        cp
    }

    /// A genuine RFC 6962 inclusion path (leaf to root) for `leaves[index]`.
    fn path_for(&self, index: u64) -> Vec<String> {
        let tree_size = u64::try_from(self.leaves.len()).expect("small test size");
        let proof =
            atl_core::core::merkle::generate_inclusion_proof(index, tree_size, |level, at| {
                if level == 0 {
                    self.leaves.get(usize::try_from(at).ok()?).copied()
                } else {
                    None
                }
            })
            .expect("index within tree");
        ahl_core::proof_path_hex(&proof)
    }
}

fn deployment() -> Deployment {
    let producer = key("producer", 0xe1);
    let outgoing = key("log-out", 0xe2);
    let incoming = key("log-in", 0xe3);
    let witness_key =
        ahl_core::TestKey::from_seed_hex("witness-1", &hex::encode(WITNESS_SEED)).expect("seed");
    let log_id = format!("sha256:{}", "e4".repeat(32));

    let genesis = ahl_core::envelope(
        manifest_payload(&log_id, &producer, &outgoing, &witness_key, None),
        &producer,
    );
    let genesis_entry_id = ahl_core::entry_id(&genesis);
    let rotating = ahl_core::envelope(
        manifest_payload(&log_id, &producer, &incoming, &witness_key, Some(&genesis_entry_id)),
        &producer,
    );
    let subject = ahl_core::envelope(
        json!({
            "ahl_version": ahl_core::AHL_VERSION,
            "type": "ingestion",
            "producer": "producer-1",
            "issued_at": "2026-01-01T00:00:00Z",
            "valid_time": "2026-01-01T00:00:00Z",
            "manifest": ahl_core::statement_id(&rotating).expect("well-formed envelope"),
            "dataset": "records",
            "origin": "batch:2026-01-01/records-01",
            "record": format!("sha256:{}", "e5".repeat(32)),
        }),
        &producer,
    );

    let envelopes = vec![genesis, rotating, subject];
    let entries: Vec<Vec<u8>> = envelopes.iter().map(ahl_core::jcs).collect();
    let leaves: Vec<Hash> = entries.iter().map(|bytes| log_leaf_hash(bytes)).collect();
    let root = compute_root(&leaves);

    // The mirror holds the entries; the witness is handed them with every submission.
    let store = ahl_mirror::Store::open_in_memory().expect("in-memory store");
    for (index, bytes) in entries.iter().enumerate() {
        let id = ahl_core::sha256_hex(bytes);
        store.stage_entry(&id, bytes).expect("stage");
        store.promote_entry(u64::try_from(index).expect("small test index"), &id).expect("promote");
    }
    let config = Config::resolve(&ConfigSpec {
        log_id: log_id.clone(),
        genesis_manifest_entry_id: genesis_entry_id.clone(),
        genesis_producer_keys: vec![KeyObjectSpec {
            key_id: producer.key_id(),
            pubkey: producer.pubkey(),
            valid_from_index: 0,
        }],
        store_path: ":memory:".to_owned(),
    })
    .expect("valid config");
    let mirror = ahl_mirror::http::router(ahl_mirror::http::AppState {
        store: Arc::new(store),
        config: Arc::new(config),
    });

    let anchor = LogAnchor::resolve(&LogAnchorSpec {
        log_id: log_id.clone(),
        genesis_manifest_entry_id: genesis_entry_id.clone(),
        genesis_producer_keys: vec![WitnessKeySpec {
            key_id: producer.key_id(),
            pubkey: producer.pubkey(),
            valid_from_index: 0,
        }],
    })
    .expect("valid anchor");
    let mut anchors = HashMap::new();
    anchors.insert(log_id.clone(), anchor);
    let signer = Ed25519WitnessSigner::from_seed("witness-1", &WITNESS_SEED).expect("32 bytes");
    assert_eq!(signer.key_id(), witness_key.key_id(), "the manifests declare this key");
    let witness = ahl_witness::http::router(ahl_witness::http::AppState {
        store: Arc::new(ahl_witness::store::Store::open_in_memory().expect("in-memory store")),
        signer: Arc::new(signer),
        anchors: Arc::new(anchors),
    });

    Deployment {
        mirror,
        witness,
        producer,
        outgoing,
        incoming,
        witness_key,
        log_id,
        genesis_entry_id,
        envelopes,
        entries,
        leaves,
        root,
    }
}

async fn json_request(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.expect("service call");
    let status = response.status();
    let body = response.into_body().collect().await.expect("body").to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn get_json(app: &Router, uri: &str) -> (StatusCode, Value) {
    json_request(app, Request::get(uri).body(Body::empty()).expect("valid request")).await
}

async fn post_json(app: &Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    json_request(
        app,
        Request::post(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).expect("serialize")))
            .expect("valid request"),
    )
    .await
}

/// Offer `cp` to both components, naming the rotation it anchors.
async fn offer_rotation(deployment: &Deployment, cp: &Checkpoint) {
    let (status, body) = post_json(
        &deployment.mirror,
        "/v1/checkpoints",
        &json!({ "checkpoint": cp, "rotation_for": ROTATING_INDEX }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["rotation_anchors"], json!([ROTATING_INDEX]));

    let (status, body) = post_json(
        &deployment.witness,
        &format!("/v1/logs/{}/witness", deployment.log_id),
        &json!({
            "checkpoint": cp,
            "entries": deployment
                .entries
                .iter()
                .map(|bytes| Value::String(format!("base64:{}", B64.encode(bytes))))
                .collect::<Vec<_>>(),
            "rotation_for": ROTATING_INDEX,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["rotation_anchors"], json!([ROTATING_INDEX]));
}

/// Assemble the `statement-anchored` receipt this deployment's material earns, carrying
/// `element` as its one `governance.rotation_proofs[]` element.
fn receipt_over(
    deployment: &Deployment,
    anchoring: &Checkpoint,
    cosigned: &Value,
    element: &Value,
) -> Value {
    let key_object = |key_id: String, pubkey: String, entry_index: u64| {
        json!({
            "key_id": key_id,
            "pubkey": pubkey,
            "source": "manifest-chain",
            "binding": { "entry_index": entry_index },
        })
    };
    let witness_key_object = |entry_index: u64| {
        json!({
            "witness_id": "witness-1",
            "key_id": deployment.witness_key.key_id(),
            "pubkey": deployment.witness_key.pubkey(),
            "source": "manifest-chain",
            "binding": { "entry_index": entry_index },
        })
    };
    json!({
        "ahl_receipt_version": "2",
        "spec_version": "0.4.0",
        "claim": {
            "type": "statement-anchored",
            "assurance": {
                "governance": "declared",
                "competing_triggers": "not-checked",
                "witnessed": true,
                "continued_history": false,
                "content_binding": "none",
            },
        },
        "subject": {
            "statement_id": ahl_core::statement_id(&deployment.envelopes[2]).expect("id"),
            "entry_id": ahl_core::entry_id(&deployment.envelopes[2]),
            "entry_index": 2,
            "manifest": ahl_core::statement_id(&deployment.envelopes[1]).expect("id"),
        },
        "envelope": deployment.envelopes[2],
        "keys": {
            // The same physical key is listed once per manifest version it is drawn from: the
            // version active for the anchoring checkpoint, and — for the rotation material
            // alone — the predecessor version §7.1's transition exception names.
            "log": [
                key_object(
                    deployment.incoming.key_id(),
                    deployment.incoming.pubkey(),
                    ROTATING_INDEX,
                ),
                key_object(deployment.outgoing.key_id(), deployment.outgoing.pubkey(), 0),
            ],
            "witness": [ witness_key_object(ROTATING_INDEX), witness_key_object(0) ],
            "producer": [ key_object(
                deployment.producer.key_id(),
                deployment.producer.pubkey(),
                ROTATING_INDEX,
            ) ],
        },
        "anchoring": {
            "adaptor": {
                "id": ahl_core::ATL_PROFILE_ID,
                "hash": ahl_core::sha256_hex(PROFILE_DOCUMENT),
            },
            "checkpoint": anchoring,
            "inclusion_path": deployment.path_for(2),
            "witnesses": [ {
                "witness_id": cosigned["witness_id"],
                "key_id": cosigned["key_id"],
                "cosignature": cosigned["cosignature"],
                "cosigned_at": cosigned["cosigned_at"],
            } ],
        },
        "governance": {
            "genesis_entry_id": deployment.genesis_entry_id,
            "chain": [
                {
                    "envelope": deployment.envelopes[0],
                    "entry_index": 0,
                    "inclusion_path": deployment.path_for(0),
                },
                {
                    "envelope": deployment.envelopes[1],
                    "entry_index": ROTATING_INDEX,
                    "inclusion_path": deployment.path_for(ROTATING_INDEX),
                },
            ],
            "rotation_proofs": [ element ],
            "currency": { "mode": "declared" },
        },
    })
}

/// The whole point of the file: the two halves of one `rotation_proofs[]` element are fetched
/// from the two components that hold them, joined, and verified — with SEVERAL anchors held for
/// the rotation, so the join is only sound if both sides pick the same one.
#[tokio::test]
async fn the_two_components_compose_one_verifying_rotation_proof() {
    let deployment = deployment();

    // Two qualifying anchors, offered LATEST FIRST so that "the one both sides pick" cannot be
    // "the one that happened to arrive first".
    let later = deployment.checkpoint(&deployment.outgoing, "2026-01-01T09:00:00.000000000Z");
    let earlier = deployment.checkpoint(&deployment.outgoing, "2026-01-01T01:00:00.000000000Z");
    offer_rotation(&deployment, &later).await;
    offer_rotation(&deployment, &earlier).await;

    // And the ordinary series checkpoint the receipt is anchored under, cosigned as such.
    let anchoring = deployment.checkpoint(&deployment.incoming, "2026-01-01T10:00:00.000000000Z");
    let (status, body) =
        post_json(&deployment.mirror, "/v1/checkpoints", &json!({ "checkpoint": &anchoring }))
            .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["series_member"], true);
    let (status, cosigned) = post_json(
        &deployment.witness,
        &format!("/v1/logs/{}/witness", deployment.log_id),
        &json!({
            "checkpoint": &anchoring,
            "entries": deployment
                .entries
                .iter()
                .map(|bytes| Value::String(format!("base64:{}", B64.encode(bytes))))
                .collect::<Vec<_>>(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{cosigned}");
    assert_eq!(cosigned["series_member"], true);

    // Half one: the mirror's element, `witnesses` empty because a mirror does not cosign.
    let (status, mut element) =
        get_json(&deployment.mirror, &format!("/v1/rotation-proofs/{ROTATING_INDEX}")).await;
    assert_eq!(status, StatusCode::OK, "{element}");
    assert_eq!(element["witnesses"], json!([]));

    // Half two: the witness's cosignatures, in the `anchoring.witnesses[]` shape.
    let (status, served) = get_json(
        &deployment.witness,
        &format!("/v1/logs/{}/rotation-cosignatures/{ROTATING_INDEX}", deployment.log_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{served}");

    // Deterministic pairing: two anchors are held on each side, and both sides serve the
    // EARLIEST — not the first submitted, which was the later one.
    assert_eq!(
        element["checkpoint"], served["checkpoint"],
        "the cosignatures must be over the very checkpoint the element carries"
    );
    assert_eq!(
        element["checkpoint"],
        serde_json::to_value(&earlier).expect("json"),
        "the earliest anchor is what both sides serve, whatever order they arrived in"
    );

    // The join, and nothing else: no member of either half is edited.
    element["witnesses"] = served["witnesses"].clone();
    assert_eq!(element["witnesses"].as_array().map(Vec::len), Some(1));

    let receipt = receipt_over(&deployment, &anchoring, &cosigned, &element);

    let policy = TrustPolicy {
        genesis_entry_id: deployment.genesis_entry_id.clone(),
        genesis_key_ids: None,
        adaptor_profiles: BTreeMap::from([(
            ahl_core::ATL_PROFILE_ID.to_owned(),
            AdaptorProfile {
                document: PROFILE_DOCUMENT.to_vec(),
                capabilities: AdaptorCapabilities {
                    checkpoint_raw: false,
                    consistency_proofs: false,
                },
            },
        )]),
        dataset_keys: BTreeMap::new(),
        trusted_witness_keys: BTreeMap::new(),
        limits: Limits::default(),
    };

    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified, "findings: {:?}", report.findings);
}
