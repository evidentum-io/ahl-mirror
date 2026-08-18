//! The HTTP surface: thin handlers over the library functions in [`crate::ingest`],
//! [`crate::retrieval`], [`crate::range`], [`crate::checkpoint`] and [`crate::manifest`].
//!
//! Every handler blocks on [`crate::store::Store`] (`SQLite`) inside
//! [`tokio::task::spawn_blocking`], so a slow database call never stalls the async runtime.
//! Business rules live in the modules above and are unit-tested there directly; the tests in
//! this module check wiring — status codes, byte-exactness of the retrieval response, and
//! request/response shapes — not the rules themselves.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::checkpoint::{Checkpoint, PendingPromotion, ReportedCheckpoint};
use crate::config::Config;
use crate::error::MirrorError;
use crate::range::RangeResponse;
use crate::store::{InsertOutcome, Store};

/// Shared application state, cheap to clone (both fields are `Arc`-backed).
#[derive(Clone)]
pub struct AppState {
    /// The durable store.
    pub store: Arc<Store>,
    /// The mirror's configuration and genesis governance anchor.
    pub config: Arc<Config>,
}

/// Build the mirror's router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/entries/stage", post(stage_handler))
        .route("/v1/entries/promote", post(promote_handler))
        .route("/v1/entries/{entry_id}", get(retrieve_handler))
        .route("/v1/range", post(range_handler))
        .route("/v1/checkpoints", post(checkpoint_ingest_handler).get(list_checkpoints_handler))
        .route("/v1/checkpoints/{tree_size}", get(get_checkpoint_handler))
        .route("/v1/itub/{index}", get(itub_handler))
        .route("/v1/consistency", get(consistency_handler))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

/// A [`MirrorError`] wrapped for [`IntoResponse`], mapping each variant to the HTTP status
/// that best matches its meaning: a specific client mistake (400/404/409) or an internal
/// integrity fault this deployment cannot serve past (500).
struct ApiError(MirrorError);

impl From<MirrorError> for ApiError {
    fn from(value: MirrorError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            MirrorError::UnknownCheckpoint { .. } | MirrorError::NotStaged { .. } => {
                StatusCode::NOT_FOUND
            }
            MirrorError::IncompleteEntries { .. }
            | MirrorError::CheckpointNotSeriesUsable { .. }
            | MirrorError::SeriesEquivocated { .. } => StatusCode::CONFLICT,
            MirrorError::StoredEntryCorrupt { .. }
            | MirrorError::CheckpointRootMismatch { .. }
            | MirrorError::IndexOverflow { .. }
            | MirrorError::Atl(_)
            | MirrorError::Store(_)
            | MirrorError::StoreInit(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        };
        (status, Json(json!({ "error": self.0.to_string() }))).into_response()
    }
}

/// Run a blocking [`Store`] operation off the async runtime.
///
/// # Errors
///
/// Returns [`MirrorError::StoreInit`] if the blocking task itself panics or is cancelled
/// (never propagated as a panic to the caller), otherwise the inner operation's result.
async fn blocking<T, F>(f: F) -> Result<T, ApiError>
where
    F: FnOnce() -> Result<T, MirrorError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result.map_err(ApiError::from),
        Err(_join_error) => {
            Err(ApiError::from(MirrorError::StoreInit("blocking task did not complete".to_owned())))
        }
    }
}

fn decode_base64_field(value: &str, reason: &'static str) -> Result<Vec<u8>, ApiError> {
    let stripped = value
        .strip_prefix("base64:")
        .ok_or_else(|| ApiError::from(MirrorError::MalformedEnvelope { reason }))?;
    B64.decode(stripped).map_err(|_| ApiError::from(MirrorError::MalformedEnvelope { reason }))
}

// ---------------------------------------------------------------------------
// Staging and promotion (adaptor profile §4.2, §8.2; core spec §2.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct StageRequest {
    entry_id: String,
    /// `"base64:" || base64(JCS(envelope))` — carried as base64 so the exact bytes survive
    /// JSON transport unaltered; re-parsing JSON would not preserve byte-exactness.
    envelope_base64: String,
    atl_metadata: Value,
}

#[derive(Debug, Serialize)]
struct StageResponse {
    status: &'static str,
    entry_id: String,
}

async fn stage_handler(
    State(state): State<AppState>,
    Json(req): Json<StageRequest>,
) -> Result<Response, ApiError> {
    let bytes = decode_base64_field(&req.envelope_base64, "envelope_base64 must be `base64:...`")?;

    let store = Arc::clone(&state.store);
    let entry_id = req.entry_id.clone();
    let outcome =
        blocking(move || crate::ingest::stage_entry(&store, &entry_id, &bytes, &req.atl_metadata))
            .await?;

    let status = match outcome {
        InsertOutcome::Inserted => StatusCode::CREATED,
        InsertOutcome::AlreadyPresent => StatusCode::OK,
    };
    let body = StageResponse {
        status: match outcome {
            InsertOutcome::Inserted => "staged",
            InsertOutcome::AlreadyPresent => "already_staged",
        },
        entry_id: req.entry_id,
    };
    Ok((status, Json(body)).into_response())
}

#[derive(Debug, Deserialize)]
struct PromoteRequest {
    entry_id: String,
    /// The `tree_size` of an already-authenticated checkpoint the inclusion proof is checked
    /// against (the most recently declared one at that size, if more than one exists).
    tree_size: u64,
    leaf_index: u64,
    inclusion_path: Vec<String>,
}

async fn promote_handler(
    State(state): State<AppState>,
    Json(req): Json<PromoteRequest>,
) -> Result<StatusCode, ApiError> {
    let store = Arc::clone(&state.store);
    let outcome = blocking(move || {
        let checkpoint = store
            .get_checkpoint(req.tree_size)?
            .ok_or(MirrorError::UnknownCheckpoint { tree_size: req.tree_size })?;
        crate::ingest::promote_entry(
            &store,
            &checkpoint,
            &req.entry_id,
            req.leaf_index,
            &req.inclusion_path,
        )
    })
    .await?;
    Ok(match outcome {
        InsertOutcome::Inserted => StatusCode::CREATED,
        InsertOutcome::AlreadyPresent => StatusCode::OK,
    })
}

// ---------------------------------------------------------------------------
// Retrieval by entry id (adaptor profile §10.1.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RetrieveQuery {
    encoding: Option<String>,
}

async fn retrieve_handler(
    State(state): State<AppState>,
    Path(entry_id): Path<String>,
    Query(query): Query<RetrieveQuery>,
) -> Result<Response, ApiError> {
    let store = Arc::clone(&state.store);
    let lookup_id = entry_id.clone();
    let retrieved = blocking(move || crate::retrieval::retrieve_by_id(&store, &lookup_id)).await?;

    match retrieved {
        crate::retrieval::Retrieved::Absent => Ok((
            StatusCode::NOT_FOUND,
            Json(json!({
                "status": "absent",
                "entry_id": entry_id,
                "note": "unavailability, not evidence of non-existence (adaptor profile §10.1.1)",
            })),
        )
            .into_response()),
        crate::retrieval::Retrieved::Present { entry_index, envelope } => {
            if query.encoding.as_deref() == Some("base64") {
                Ok(Json(json!({
                    "entry_id": entry_id,
                    "entry_index": entry_index,
                    "encoding": "base64",
                    "envelope": format!("base64:{}", B64.encode(&envelope)),
                }))
                .into_response())
            } else {
                // Byte-exact: the response body is exactly the stored bytes, never
                // re-serialized (adaptor profile §10.1.1).
                Ok((
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, "application/json".to_owned()),
                        (
                            axum::http::HeaderName::from_static("x-ahl-entry-index"),
                            entry_index.to_string(),
                        ),
                    ],
                    envelope,
                )
                    .into_response())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Range enumeration (adaptor profile §10.2-§10.5)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RangeRequest {
    tree_size: u64,
    from_index: u64,
    to_index: u64,
}

/// Fetch the series-usable checkpoint at `tree_size`, or a specific error distinguishing
/// "no such checkpoint at all", "authenticated, but not (yet) series-usable", and "the series
/// equivocates at or below `tree_size`" — core spec §7.3 permits grounding an enumeration
/// response or completeness claim only on a series-usable checkpoint strictly below the
/// equivocation floor, if the series has one (see [`crate::checkpoint::SeriesView`]'s
/// `equivocation_floor` docs). Checked first, and unconditionally on whether a checkpoint
/// happens to exist at exactly `tree_size`: the whole region at or beyond the floor is
/// off-limits, not merely the divergent members themselves.
fn series_usable_checkpoint(
    store: &Store,
    config: &Config,
    tree_size: u64,
) -> Result<Checkpoint, MirrorError> {
    let view = crate::checkpoint::series_view(store, config)?;
    if let Some(floor) = view.equivocation_floor {
        if tree_size >= floor {
            return Err(MirrorError::SeriesEquivocated { tree_size, floor });
        }
    }
    let mut candidates =
        view.members.into_iter().filter(|m| m.checkpoint.tree_size == tree_size).peekable();
    if candidates.peek().is_none() {
        return Err(MirrorError::UnknownCheckpoint { tree_size });
    }
    candidates
        .find(|m| m.state == crate::checkpoint::CheckpointState::SeriesUsable)
        .map(|m| m.checkpoint)
        .ok_or(MirrorError::CheckpointNotSeriesUsable { tree_size })
}

async fn range_handler(
    State(state): State<AppState>,
    Json(req): Json<RangeRequest>,
) -> Result<Json<RangeResponse>, ApiError> {
    let store = Arc::clone(&state.store);
    let config = Arc::clone(&state.config);
    let checkpoint = blocking({
        let store = Arc::clone(&store);
        move || series_usable_checkpoint(&store, &config, req.tree_size)
    })
    .await?;

    let response = blocking(move || {
        let all_entries = store.get_entries_range(0, checkpoint.tree_size)?;
        crate::range::build_range_response(&checkpoint, req.from_index, req.to_index, &all_entries)
    })
    .await?;

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// Checkpoints and ITUB (adaptor profile §5.2, §6; core spec §7.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CheckpointIngestRequest {
    checkpoint: Checkpoint,
    /// `"base64:" || base64(the 98-byte blob)` (adaptor profile §6.4), optional.
    raw: Option<String>,
    /// Staged entries to promote atomically alongside this checkpoint, each with a Merkle
    /// inclusion proof against it (adaptor profile §8.2). MAY include governance material
    /// (e.g. a manifest rotation) this very checkpoint depends on to resolve its own signing
    /// key (core spec §7.3).
    #[serde(default)]
    entries_to_promote: Vec<PendingPromotion>,
}

async fn checkpoint_ingest_handler(
    State(state): State<AppState>,
    Json(req): Json<CheckpointIngestRequest>,
) -> Result<StatusCode, ApiError> {
    let raw_bytes = req
        .raw
        .as_deref()
        .map(|value| decode_base64_field(value, "raw must be `base64:...`"))
        .transpose()?;

    let store = Arc::clone(&state.store);
    let config = Arc::clone(&state.config);
    blocking(move || {
        crate::checkpoint::ingest_checkpoint(
            &store,
            &config,
            &req.checkpoint,
            raw_bytes.as_deref(),
            &req.entries_to_promote,
        )
    })
    .await?;
    Ok(StatusCode::CREATED)
}

async fn list_checkpoints_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<ReportedCheckpoint>>, ApiError> {
    let store = Arc::clone(&state.store);
    let config = Arc::clone(&state.config);
    let view = blocking(move || crate::checkpoint::series_view(&store, &config)).await?;
    Ok(Json(view.members))
}

async fn get_checkpoint_handler(
    State(state): State<AppState>,
    Path(tree_size): Path<u64>,
) -> Result<Json<ReportedCheckpoint>, ApiError> {
    let store = Arc::clone(&state.store);
    let config = Arc::clone(&state.config);
    let reported = blocking(move || {
        let view = crate::checkpoint::series_view(&store, &config)?;
        // Picking the latest-`checkpoint_time` member by `max_by` below is exactly "choosing
        // a branch" if `tree_size` sits at or beyond the equivocation floor (core spec §7.3):
        // report the divergence instead of silently returning one of the conflicting members.
        // `GET /v1/checkpoints` (no `tree_size`) still lists every authenticated member with
        // its own state, divergence included — nothing is hidden there.
        if let Some(floor) = view.equivocation_floor {
            if tree_size >= floor {
                return Err(MirrorError::SeriesEquivocated { tree_size, floor });
            }
        }
        view.members
            .into_iter()
            .filter(|m| m.checkpoint.tree_size == tree_size)
            .max_by(|a, b| a.checkpoint.checkpoint_time.cmp(&b.checkpoint.checkpoint_time))
            .ok_or(MirrorError::UnknownCheckpoint { tree_size })
    })
    .await?;
    Ok(Json(reported))
}

async fn itub_handler(
    State(state): State<AppState>,
    Path(index): Path<u64>,
) -> Result<Response, ApiError> {
    let store = Arc::clone(&state.store);
    let config = Arc::clone(&state.config);
    let view = blocking(move || crate::checkpoint::series_view(&store, &config)).await?;
    let found = crate::checkpoint::itub(&view, index).cloned();
    Ok(found.map_or_else(
        || {
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "index": index,
                    "note": "ITUB is undefined: no series-usable member yet covers this \
                             index, or the series is not proven gap-free that far (core spec \
                             §7.3; adaptor profile §5.2.1)",
                    "frontier_stop": view.frontier_stop,
                })),
            )
                .into_response()
        },
        |cp| {
            Json(json!({
                "index": index,
                "itub": cp.checkpoint_time,
                "checkpoint": cp,
            }))
            .into_response()
        },
    ))
}

#[derive(Debug, Deserialize)]
struct ConsistencyQuery {
    from: u64,
    to: u64,
}

async fn consistency_handler(
    State(state): State<AppState>,
    Query(query): Query<ConsistencyQuery>,
) -> Result<Json<Value>, ApiError> {
    let store = Arc::clone(&state.store);
    let config = Arc::clone(&state.config);
    let (from_cp, to_cp) = blocking({
        let store = Arc::clone(&store);
        move || {
            let from_cp = series_usable_checkpoint(&store, &config, query.from)?;
            let to_cp = series_usable_checkpoint(&store, &config, query.to)?;
            Ok((from_cp, to_cp))
        }
    })
    .await?;

    let path = blocking(move || {
        let entries = store.get_entries_range(0, to_cp.tree_size)?;
        let have = u64::try_from(entries.len())
            .map_err(|_| MirrorError::IndexOverflow { what: "entries.len()" })?;
        if have != to_cp.tree_size {
            return Err(MirrorError::IncompleteEntries { have, need: to_cp.tree_size });
        }
        let leaf_hashes: Vec<_> =
            entries.iter().map(|bytes| crate::metadata::log_leaf_hash(bytes)).collect();
        let proof = atl_core::core::merkle::generate_consistency_proof(
            from_cp.tree_size,
            to_cp.tree_size,
            |level, i| {
                if level == 0 {
                    leaf_hashes.get(usize::try_from(i).ok()?).copied()
                } else {
                    None
                }
            },
        )?;
        Ok::<_, MirrorError>(
            proof.path.iter().map(|h| format!("sha256:{}", hex::encode(h))).collect::<Vec<_>>(),
        )
    })
    .await?;

    Ok(Json(json!({
        "from": query.from,
        "to": query.to,
        "consistency_path": path,
    })))
}

#[cfg(test)]
mod tests {
    use atl_core::core::merkle::Hash;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use sha2::Digest as _;
    use tower::ServiceExt as _;

    use super::*;
    use crate::config::{ConfigSpec, KeyObjectSpec};
    use crate::metadata::{adaptor_metadata_object, log_leaf_hash};

    /// A fresh store with a verified genesis manifest already canonical at index 0 (5-minute
    /// cadence from `epoch`), plus everything needed to build and admit further checkpoints.
    struct TestHarness {
        state: AppState,
        log_key: ahl_core::TestKey,
        log_id: String,
        genesis_leaf: Hash,
    }

    fn entry_id_of(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
    }

    fn genesis_manifest_bytes(
        log_id: &str,
        producer: &ahl_core::TestKey,
        log_key: &ahl_core::TestKey,
        epoch: &str,
    ) -> Vec<u8> {
        let payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "keys": [
                { "key_id": producer.key_id(), "pubkey": producer.pubkey(), "valid_from_index": 0 }
            ],
            "log": {
                "log_id": log_id,
                "operator": "op-1",
                "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
                "checkpoint_cadence": "PT5M",
                "cadence_epoch": epoch,
                "witness_grace_period": "PT10M",
                "keys": [
                    { "key_id": log_key.key_id(), "pubkey": log_key.pubkey(), "valid_from_index": 0 }
                ],
            },
        });
        ahl_core::jcs(&ahl_core::envelope(payload, producer))
    }

    fn harness() -> TestHarness {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"90".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log-1", &"42".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "77".repeat(32));
        let genesis_bytes =
            genesis_manifest_bytes(&log_id, &producer, &log_key, "2026-01-01T00:00:00Z");
        let genesis_id = entry_id_of(&genesis_bytes);
        let genesis_leaf = log_leaf_hash(&genesis_bytes);

        let store = Store::open_in_memory().expect("in-memory store");
        store.stage_entry(&genesis_id, &genesis_bytes).expect("stage genesis");
        store.promote_entry(0, &genesis_id).expect("promote genesis");

        let config = Config::resolve(&ConfigSpec {
            log_id: log_id.clone(),
            genesis_manifest_entry_id: genesis_id,
            genesis_producer_keys: vec![KeyObjectSpec {
                key_id: producer.key_id(),
                pubkey: producer.pubkey(),
                valid_from_index: 0,
            }],
            store_path: ":memory:".to_owned(),
        })
        .expect("valid config");

        TestHarness {
            state: AppState { store: Arc::new(store), config: Arc::new(config) },
            log_key,
            log_id,
            genesis_leaf,
        }
    }

    fn envelope_bytes(n: u8) -> Vec<u8> {
        ahl_core::jcs(&json!({
            "payload": { "n": n },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }))
    }

    async fn stage(app: &Router, bytes: &[u8]) -> StatusCode {
        let body = json!({
            "entry_id": entry_id_of(bytes),
            "envelope_base64": format!("base64:{}", B64.encode(bytes)),
            "atl_metadata": adaptor_metadata_object(),
        });
        let request = Request::post("/v1/entries/stage")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
            .expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        response.status()
    }

    /// A genuine RFC 6962 inclusion path (leaf to root) for `leaves[index]`.
    fn inclusion_path_for(leaves: &[Hash], index: u64) -> Vec<String> {
        let tree_size = u64::try_from(leaves.len()).expect("small test size");
        let proof =
            atl_core::core::merkle::generate_inclusion_proof(index, tree_size, |level, at| {
                if level == 0 {
                    leaves.get(usize::try_from(at).ok()?).copied()
                } else {
                    None
                }
            })
            .expect("index within tree");
        ahl_core::proof_path_hex(&proof)
    }

    /// Signs a checkpoint whose root genuinely commits `harness.genesis_leaf` followed by
    /// `new_entries` (indices `[1, 1+new_entries.len())`), and (if `with_proofs`) attaches an
    /// inclusion proof for every new entry so the checkpoint POST promotes them in the same
    /// call.
    fn signed_checkpoint_for(
        harness: &TestHarness,
        new_entries: &[Vec<u8>],
        time: &str,
        with_proofs: bool,
    ) -> (Checkpoint, Vec<PendingPromotion>) {
        let mut leaves = vec![harness.genesis_leaf];
        leaves.extend(new_entries.iter().map(|b| log_leaf_hash(b)));
        let tree_size = u64::try_from(leaves.len()).expect("small test size");
        let root = atl_core::core::merkle::compute_root(&leaves);
        let mut cp = Checkpoint {
            log_id: harness.log_id.clone(),
            tree_size,
            root_hash: format!("sha256:{}", hex::encode(root)),
            checkpoint_time: time.to_owned(),
            key_id: harness.log_key.key_id(),
            signature: String::new(),
        };
        let blob = crate::checkpoint::checkpoint_blob(&cp).expect("well-formed");
        cp.signature = harness.log_key.sign(&blob);

        let pending = if with_proofs {
            new_entries
                .iter()
                .enumerate()
                .map(|(i, bytes)| {
                    let index = 1 + u64::try_from(i).expect("small test size");
                    PendingPromotion {
                        entry_id: entry_id_of(bytes),
                        leaf_index: index,
                        inclusion_path: inclusion_path_for(&leaves, index),
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        (cp, pending)
    }

    async fn submit_checkpoint(
        app: &Router,
        cp: &Checkpoint,
        pending: &[PendingPromotion],
    ) -> StatusCode {
        let body = json!({ "checkpoint": cp, "raw": null, "entries_to_promote": pending });
        let request = Request::post("/v1/checkpoints")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
            .expect("valid request");
        app.clone().oneshot(request).await.expect("service call").status()
    }

    #[tokio::test]
    async fn health_reports_ok() {
        let app = router(harness().state);
        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).expect("valid request"))
            .await
            .expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn staging_alone_never_makes_an_entry_retrievable() {
        // The admission-without-evidence fix, at the HTTP boundary: staging succeeds, but
        // retrieval reports the entry absent until it is promoted with a proof.
        let app = router(harness().state);
        let bytes = envelope_bytes(1);
        assert_eq!(stage(&app, &bytes).await, StatusCode::CREATED);

        let request = Request::get(format!("/v1/entries/{}", entry_id_of(&bytes)))
            .body(Body::empty())
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn stage_promote_and_retrieve_round_trips_byte_exact() {
        let hx = harness();
        let app = router(hx.state.clone());
        let bytes = envelope_bytes(1);
        assert_eq!(stage(&app, &bytes).await, StatusCode::CREATED);

        let (cp, pending) = signed_checkpoint_for(
            &hx,
            std::slice::from_ref(&bytes),
            "2026-01-01T00:00:00.000000000Z",
            true,
        );
        assert_eq!(submit_checkpoint(&app, &cp, &pending).await, StatusCode::CREATED);

        let request = Request::get(format!("/v1/entries/{}", entry_id_of(&bytes)))
            .body(Body::empty())
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(body.as_ref(), bytes.as_slice());
    }

    #[tokio::test]
    async fn a_checkpoint_cannot_promote_bytes_it_was_never_actually_anchored_over() {
        // Direct HTTP-level version of the fixed denial of service: stage bytes with no
        // authority behind them, then try to promote them under a checkpoint whose root
        // does not commit them. No proof exists, so promotion — and thus retrievability —
        // never happens, and the index remains free for the genuine entry.
        let hx = harness();
        let app = router(hx.state.clone());
        let attacker_bytes = envelope_bytes(0xAA);
        assert_eq!(stage(&app, &attacker_bytes).await, StatusCode::CREATED);

        let genuine_bytes = envelope_bytes(1);
        let (cp, genuine_pending) = signed_checkpoint_for(
            &hx,
            std::slice::from_ref(&genuine_bytes),
            "2026-01-01T00:00:00.000000000Z",
            true,
        );
        // Splice the attacker's entry id onto the genuine proof material.
        let forged_pending = vec![PendingPromotion {
            entry_id: entry_id_of(&attacker_bytes),
            ..genuine_pending[0].clone()
        }];
        assert_eq!(submit_checkpoint(&app, &cp, &forged_pending).await, StatusCode::BAD_REQUEST);

        let request = Request::get(format!("/v1/entries/{}", entry_id_of(&attacker_bytes)))
            .body(Body::empty())
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn standalone_promotion_works_against_an_already_admitted_checkpoint() {
        let hx = harness();
        let app = router(hx.state.clone());
        let bytes = envelope_bytes(1);
        assert_eq!(stage(&app, &bytes).await, StatusCode::CREATED);

        let (cp, pending) = signed_checkpoint_for(
            &hx,
            std::slice::from_ref(&bytes),
            "2026-01-01T00:00:00.000000000Z",
            false,
        );
        assert_eq!(submit_checkpoint(&app, &cp, &pending).await, StatusCode::CREATED);

        let leaves = [hx.genesis_leaf, log_leaf_hash(&bytes)];
        let path = inclusion_path_for(&leaves, 1);
        let body = json!({
            "entry_id": entry_id_of(&bytes),
            "tree_size": 2,
            "leaf_index": 1,
            "inclusion_path": path,
        });
        let request = Request::post("/v1/entries/promote")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
            .expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::CREATED);

        let request = Request::get(format!("/v1/entries/{}", entry_id_of(&bytes)))
            .body(Body::empty())
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn promoting_against_an_unknown_checkpoint_is_a_404() {
        let app = router(harness().state);
        let bytes = envelope_bytes(1);
        assert_eq!(stage(&app, &bytes).await, StatusCode::CREATED);
        let body = json!({
            "entry_id": entry_id_of(&bytes),
            "tree_size": 99,
            "leaf_index": 0,
            "inclusion_path": Vec::<String>::new(),
        });
        let request = Request::post("/v1/entries/promote")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn retrieving_an_absent_entry_is_a_404_not_an_error() {
        let app = router(harness().state);
        let request =
            Request::get("/v1/entries/sha256:missing").body(Body::empty()).expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_malformed_stage_request_is_a_400() {
        let app = router(harness().state);
        let body = json!({
            "entry_id": "sha256:00",
            "envelope_base64": "not-base64-prefixed",
            "atl_metadata": adaptor_metadata_object(),
        });
        let request = Request::post("/v1/entries/stage")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn range_and_checkpoint_round_trip_over_http() {
        let hx = harness();
        let app = router(hx.state.clone());

        let entries: Vec<Vec<u8>> = (0u8..6).map(envelope_bytes).collect();
        for bytes in &entries {
            assert_eq!(stage(&app, bytes).await, StatusCode::CREATED);
        }
        let (cp, pending) =
            signed_checkpoint_for(&hx, &entries, "2026-01-01T00:00:00.000000000Z", true);
        assert_eq!(submit_checkpoint(&app, &cp, &pending).await, StatusCode::CREATED);

        // tree_size is 7: the genesis manifest plus the 6 staged entries.
        let range_body = json!({ "tree_size": 7, "from_index": 2, "to_index": 5 });
        let request = Request::post("/v1/range")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&range_body).expect("serialize")))
            .expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let range_response: RangeResponse = serde_json::from_slice(&body).expect("json");
        assert_eq!(range_response.entries.len(), 3);
        assert!(crate::range::verify_range_response(&range_response).expect("well-formed"));

        let request = Request::get("/v1/itub/2").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);

        let request = Request::get("/v1/itub/99").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let request = Request::get("/v1/checkpoints/7").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let reported: ReportedCheckpoint = serde_json::from_slice(&body).expect("json");
        assert_eq!(reported.state, crate::checkpoint::CheckpointState::SeriesUsable);

        let request =
            Request::get("/v1/checkpoints/99").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let request = Request::get("/v1/checkpoints").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let series: Vec<ReportedCheckpoint> = serde_json::from_slice(&body).expect("json");
        assert_eq!(series.len(), 1);

        let request =
            Request::get("/v1/consistency?from=7&to=7").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let value: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(value["consistency_path"].as_array().expect("array").len(), 0);

        let request =
            Request::get(format!("/v1/entries/{}?encoding=base64", entry_id_of(&entries[0])))
                .body(Body::empty())
                .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let value: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(value["encoding"], "base64");
    }

    #[tokio::test]
    async fn an_unknown_checkpoint_range_request_is_a_404() {
        let app = router(harness().state);
        let range_body = json!({ "tree_size": 99, "from_index": 0, "to_index": 1 });
        let request = Request::post("/v1/range")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&range_body).expect("serialize")))
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_range_request_against_an_authenticated_but_not_series_usable_checkpoint_is_a_409() {
        let hx = harness();
        let app = router(hx.state.clone());
        // Never stage/promote the new entry: cp is admitted (signature-only), but its root
        // can never be recomputed, so it stays merely authenticated.
        let unrelated: Vec<Vec<u8>> = (90u8..91).map(envelope_bytes).collect();
        let (cp, _pending) =
            signed_checkpoint_for(&hx, &unrelated, "2026-01-01T00:00:00.000000000Z", false);
        assert_eq!(submit_checkpoint(&app, &cp, &[]).await, StatusCode::CREATED);

        let range_body = json!({ "tree_size": 2, "from_index": 0, "to_index": 1 });
        let request = Request::post("/v1/range")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&range_body).expect("serialize")))
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn a_checkpoint_ingest_with_a_bad_signature_is_a_400() {
        let hx = harness();
        let app = router(hx.state.clone());
        let cp = crate::checkpoint::Checkpoint {
            log_id: hx.log_id.clone(),
            tree_size: 1,
            root_hash: format!("sha256:{}", hex::encode(hx.genesis_leaf)),
            checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
            key_id: hx.log_key.key_id(),
            signature: "base64:AAAA".to_owned(),
        };
        assert_eq!(submit_checkpoint(&app, &cp, &[]).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_checkpoint_signed_outside_its_key_validity_range_is_a_400() {
        // The "checkpoint signed by a key outside its validity range" negative test,
        // exercised end to end over HTTP: the log key is declared valid only from index 5,
        // and the bootstrap checkpoint commits just the genesis manifest (tree_size 1).
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"91".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log-1", &"92".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "93".repeat(32));
        let genesis_payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "keys": [
                { "key_id": producer.key_id(), "pubkey": producer.pubkey(), "valid_from_index": 0 }
            ],
            "log": {
                "log_id": log_id,
                "operator": "op-1",
                "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
                "checkpoint_cadence": "PT5M",
                "cadence_epoch": "2026-01-01T00:00:00Z",
                "witness_grace_period": "PT10M",
                "keys": [
                    { "key_id": log_key.key_id(), "pubkey": log_key.pubkey(), "valid_from_index": 5 }
                ],
            },
        });
        let genesis_bytes = ahl_core::jcs(&ahl_core::envelope(genesis_payload, &producer));
        let genesis_id = entry_id_of(&genesis_bytes);
        let genesis_leaf = log_leaf_hash(&genesis_bytes);

        let store = Store::open_in_memory().expect("in-memory store");
        store.stage_entry(&genesis_id, &genesis_bytes).expect("stage genesis");
        store.promote_entry(0, &genesis_id).expect("promote genesis");
        let config = Config::resolve(&ConfigSpec {
            log_id: log_id.clone(),
            genesis_manifest_entry_id: genesis_id,
            genesis_producer_keys: vec![KeyObjectSpec {
                key_id: producer.key_id(),
                pubkey: producer.pubkey(),
                valid_from_index: 0,
            }],
            store_path: ":memory:".to_owned(),
        })
        .expect("valid config");
        let app = router(AppState { store: Arc::new(store), config: Arc::new(config) });

        let root = atl_core::core::merkle::compute_root(&[genesis_leaf]);
        let mut cp = Checkpoint {
            log_id,
            tree_size: 1,
            root_hash: format!("sha256:{}", hex::encode(root)),
            checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
            key_id: log_key.key_id(),
            signature: String::new(),
        };
        let blob = crate::checkpoint::checkpoint_blob(&cp).expect("well-formed");
        cp.signature = log_key.sign(&blob);
        assert_eq!(submit_checkpoint(&app, &cp, &[]).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn itub_against_an_incomplete_series_is_unavailable() {
        // The "ITUB query against an incomplete series" negative test, over HTTP: two
        // checkpoints admitted whose time gap exceeds the declared cadence, so no covering
        // member is within the proven-gap-free frontier.
        let hx = harness(); // cadence: 5 minutes
        let app = router(hx.state.clone());

        let first: Vec<Vec<u8>> = (0u8..4).map(envelope_bytes).collect();
        for bytes in &first {
            assert_eq!(stage(&app, bytes).await, StatusCode::CREATED);
        }
        let (cp1, pending1) =
            signed_checkpoint_for(&hx, &first, "2026-01-01T00:00:00.000000000Z", true);
        assert_eq!(submit_checkpoint(&app, &cp1, &pending1).await, StatusCode::CREATED);

        let more: Vec<Vec<u8>> = (4u8..9).map(envelope_bytes).collect();
        for bytes in &more {
            assert_eq!(stage(&app, bytes).await, StatusCode::CREATED);
        }
        let all_new: Vec<Vec<u8>> = first.iter().chain(more.iter()).cloned().collect();
        // Three hours after cp1, far beyond the 5-minute cadence: an undetected-by-
        // consistency-alone gap.
        let (cp2, pending2) =
            signed_checkpoint_for(&hx, &all_new, "2026-01-01T03:00:00.000000000Z", true);
        assert_eq!(submit_checkpoint(&app, &cp2, &pending2).await, StatusCode::CREATED);

        // Covered by cp2's tree_size, but beyond the gap-free frontier (which stops at cp1).
        let request = Request::get("/v1/itub/6").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Within the gap-free prefix: available.
        let request = Request::get("/v1/itub/2").body(Body::empty()).expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// A checkpoint signed for `tree_size`/`root`/`time` with no claim about what the root
    /// actually commits — used to construct equivocating pairs (two checkpoints, one
    /// `tree_size`, different `root_hash`).
    fn signed_checkpoint_with_root(
        harness: &TestHarness,
        tree_size: u64,
        root: Hash,
        time: &str,
    ) -> Checkpoint {
        let mut cp = Checkpoint {
            log_id: harness.log_id.clone(),
            tree_size,
            root_hash: format!("sha256:{}", hex::encode(root)),
            checkpoint_time: time.to_owned(),
            key_id: harness.log_key.key_id(),
            signature: String::new(),
        };
        let blob = crate::checkpoint::checkpoint_blob(&cp).expect("well-formed");
        cp.signature = harness.log_key.sign(&blob);
        cp
    }

    #[tokio::test]
    async fn equivocation_refuses_at_and_beyond_the_floor_but_not_below_it() {
        // Core spec §7.3: "Equivocation ends the series ... a party serving series-dependent
        // material MUST report the divergence rather than choosing a branch." Exercised over
        // every HTTP path the coordinator named, plus the single-checkpoint lookup, which
        // exhibits the same "pick a branch" pattern via its `max_by(checkpoint_time)`.
        let hx = harness(); // cadence: 5 minutes
        let app = router(hx.state.clone());

        // A genuine checkpoint over the genesis manifest alone: tree_size 1, stays usable.
        let (cp1, pending1) =
            signed_checkpoint_for(&hx, &[], "2026-01-01T00:00:00.000000000Z", true);
        assert_eq!(submit_checkpoint(&app, &cp1, &pending1).await, StatusCode::CREATED);

        // Two checkpoints at tree_size 2 disagree on root_hash: equivocation.
        let branch_a =
            signed_checkpoint_with_root(&hx, 2, [0x01u8; 32], "2026-01-01T00:01:00.000000000Z");
        let branch_b =
            signed_checkpoint_with_root(&hx, 2, [0x02u8; 32], "2026-01-01T00:02:00.000000000Z");
        assert_eq!(submit_checkpoint(&app, &branch_a, &[]).await, StatusCode::CREATED);
        assert_eq!(submit_checkpoint(&app, &branch_b, &[]).await, StatusCode::CREATED);

        // Below the floor: single-checkpoint lookup still answers.
        let request = Request::get("/v1/checkpoints/1").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);

        // At the floor: refused outright, never one of the two conflicting branches.
        let request = Request::get("/v1/checkpoints/2").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // ITUB below the floor still answers; at or beyond it, refuses.
        let request = Request::get("/v1/itub/0").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
        let request = Request::get("/v1/itub/1").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Range enumeration at the floor is refused, not silently answered from one branch.
        let range_body = json!({ "tree_size": 2, "from_index": 0, "to_index": 1 });
        let request = Request::post("/v1/range")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&range_body).expect("serialize")))
            .expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // The consistency endpoint at the floor is refused the same way.
        let request = Request::get("/v1/consistency?from=1&to=2").body(Body::empty()).expect("req");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn a_consistency_request_for_an_unknown_checkpoint_is_a_404() {
        let app = router(harness().state);
        let request =
            Request::get("/v1/consistency?from=0&to=5").body(Body::empty()).expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
