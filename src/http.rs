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

use crate::checkpoint::{Checkpoint, PendingPromotion};
use crate::config::Config;
use crate::error::MirrorError;
use crate::range::RangeResponse;
use crate::store::{InsertOutcome, Store};

/// Shared application state, cheap to clone (both fields are `Arc`-backed).
#[derive(Clone)]
pub struct AppState {
    /// The durable store.
    pub store: Arc<Store>,
    /// The mirror's configuration and trusted keys.
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
            MirrorError::IncompleteEntries { .. } => StatusCode::CONFLICT,
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
    /// The already-canonical checkpoint the inclusion proof is checked against.
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

async fn range_handler(
    State(state): State<AppState>,
    Json(req): Json<RangeRequest>,
) -> Result<Json<RangeResponse>, ApiError> {
    let store = Arc::clone(&state.store);
    let checkpoint = blocking({
        let store = Arc::clone(&store);
        move || store.get_checkpoint(req.tree_size)
    })
    .await?
    .ok_or(MirrorError::UnknownCheckpoint { tree_size: req.tree_size })?;

    let response = blocking(move || {
        let all_entries = store.get_entries_range(0, checkpoint.tree_size)?;
        crate::range::build_range_response(&checkpoint, req.from_index, req.to_index, &all_entries)
    })
    .await?;

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// Checkpoints and ITUB (adaptor profile §5.2, §6, §7.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CheckpointIngestRequest {
    checkpoint: Checkpoint,
    /// `"base64:" || base64(the 98-byte blob)` (adaptor profile §6.4), optional.
    raw: Option<String>,
    /// Staged entries to promote atomically alongside this checkpoint, each with a Merkle
    /// inclusion proof against it (adaptor profile §8.2).
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
) -> Result<Json<Vec<Checkpoint>>, ApiError> {
    let store = Arc::clone(&state.store);
    let series = blocking(move || store.checkpoint_series()).await?;
    Ok(Json(series))
}

async fn get_checkpoint_handler(
    State(state): State<AppState>,
    Path(tree_size): Path<u64>,
) -> Result<Json<Checkpoint>, ApiError> {
    let store = Arc::clone(&state.store);
    let checkpoint = blocking(move || store.get_checkpoint(tree_size))
        .await?
        .ok_or(MirrorError::UnknownCheckpoint { tree_size })?;
    Ok(Json(checkpoint))
}

/// Resolve the series and the cadence declared for its latest member, in one blocking call.
async fn series_with_cadence(state: &AppState) -> Result<(Vec<Checkpoint>, Option<u64>), ApiError> {
    let store = Arc::clone(&state.store);
    let config = Arc::clone(&state.config);
    blocking(move || {
        let series = store.checkpoint_series()?;
        let cadence = match series.last() {
            Some(latest) => {
                crate::manifest::resolve(&store, &config, latest.tree_size)?.cadence_seconds()
            }
            None => None,
        };
        Ok((series, cadence))
    })
    .await
}

async fn itub_handler(
    State(state): State<AppState>,
    Path(index): Path<u64>,
) -> Result<Response, ApiError> {
    let (series, cadence) = series_with_cadence(&state).await?;
    let found = crate::checkpoint::itub(&series, index, cadence)?.cloned();
    Ok(found.map_or_else(
        || {
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "index": index,
                    "note": "ITUB is undefined: no series member yet covers this index, or \
                             the series is not proven gap-free that far (adaptor profile \
                             §5.2.1-§5.2.2)",
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
    let (from_cp, to_cp) = blocking({
        let store = Arc::clone(&store);
        move || {
            let from_cp = store
                .get_checkpoint(query.from)?
                .ok_or(MirrorError::UnknownCheckpoint { tree_size: query.from })?;
            let to_cp = store
                .get_checkpoint(query.to)?
                .ok_or(MirrorError::UnknownCheckpoint { tree_size: query.to })?;
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
    use crate::config::{ConfigSpec, TrustedLogKeySpec};
    use crate::metadata::{adaptor_metadata_object, log_leaf_hash};

    fn test_state() -> (AppState, ahl_core::TestKey, String) {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"42".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "77".repeat(32));
        let config = Config::resolve(&ConfigSpec {
            log_id: log_id.clone(),
            keys: vec![TrustedLogKeySpec {
                key_id: key.key_id(),
                pubkey: key.pubkey(),
                valid_from_index: 0,
            }],
            genesis_manifest_entry_id: None,
            genesis_checkpoint_cadence_seconds: Some(300),
            store_path: ":memory:".to_owned(),
        })
        .expect("valid config");
        let store = Store::open_in_memory().expect("in-memory store");
        (AppState { store: Arc::new(store), config: Arc::new(config) }, key, log_id)
    }

    fn envelope_bytes(n: u8) -> Vec<u8> {
        ahl_core::jcs(&json!({
            "payload": { "n": n },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }))
    }

    fn entry_id_of(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
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

    /// A genuine RFC 6962 inclusion path (leaf to root) for `leaves[index]`, rendered as
    /// `sha256:<hex>` strings — what a real Merkle inclusion proof looks like on the wire,
    /// as opposed to a range proof's internal (differently ordered) node list.
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

    /// Signs a checkpoint whose root genuinely commits `entries`, and (if `with_proofs`)
    /// attaches an inclusion proof for every entry so the checkpoint POST promotes them in
    /// the same call.
    fn signed_checkpoint_for(
        key: &ahl_core::TestKey,
        log_id: &str,
        entries: &[Vec<u8>],
        with_proofs: bool,
    ) -> (Checkpoint, Vec<PendingPromotion>) {
        let leaves: Vec<Hash> = entries.iter().map(|b| log_leaf_hash(b)).collect();
        let root = atl_core::core::merkle::compute_root(&leaves);
        let mut cp = Checkpoint {
            log_id: log_id.to_owned(),
            tree_size: u64::try_from(entries.len()).expect("small test size"),
            root_hash: format!("sha256:{}", hex::encode(root)),
            checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
            key_id: key.key_id(),
            signature: String::new(),
        };
        let blob = crate::checkpoint::checkpoint_blob(&cp).expect("well-formed");
        cp.signature = key.sign(&blob);

        let pending = if with_proofs {
            entries
                .iter()
                .enumerate()
                .map(|(i, bytes)| {
                    let index = u64::try_from(i).expect("small test size");
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
        let (state, _, _) = test_state();
        let app = router(state);
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
        let (state, _, _) = test_state();
        let app = router(state);
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
        let (state, key, log_id) = test_state();
        let app = router(state);
        let bytes = envelope_bytes(1);
        assert_eq!(stage(&app, &bytes).await, StatusCode::CREATED);

        let (cp, pending) =
            signed_checkpoint_for(&key, &log_id, std::slice::from_ref(&bytes), true);
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
        let (state, key, log_id) = test_state();
        let app = router(state);
        let attacker_bytes = envelope_bytes(0xAA);
        assert_eq!(stage(&app, &attacker_bytes).await, StatusCode::CREATED);

        let genuine_bytes = envelope_bytes(1);
        let (cp, genuine_pending) =
            signed_checkpoint_for(&key, &log_id, std::slice::from_ref(&genuine_bytes), true);
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
        let (state, key, log_id) = test_state();
        let app = router(state);
        let bytes = envelope_bytes(1);
        assert_eq!(stage(&app, &bytes).await, StatusCode::CREATED);

        let (cp, pending) =
            signed_checkpoint_for(&key, &log_id, std::slice::from_ref(&bytes), false);
        assert_eq!(submit_checkpoint(&app, &cp, &pending).await, StatusCode::CREATED);

        let leaves = [log_leaf_hash(&bytes)];
        let path = inclusion_path_for(&leaves, 0);
        let body = json!({
            "entry_id": entry_id_of(&bytes),
            "tree_size": 1,
            "leaf_index": 0,
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
        let (state, _, _) = test_state();
        let app = router(state);
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
        let (state, _, _) = test_state();
        let app = router(state);
        let request =
            Request::get("/v1/entries/sha256:missing").body(Body::empty()).expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_malformed_stage_request_is_a_400() {
        let (state, _, _) = test_state();
        let app = router(state);
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
        let (state, key, log_id) = test_state();
        let app = router(state);

        let entries: Vec<Vec<u8>> = (0u8..6).map(envelope_bytes).collect();
        for bytes in &entries {
            assert_eq!(stage(&app, bytes).await, StatusCode::CREATED);
        }
        let (cp, pending) = signed_checkpoint_for(&key, &log_id, &entries, true);
        assert_eq!(submit_checkpoint(&app, &cp, &pending).await, StatusCode::CREATED);

        let range_body = json!({ "tree_size": 6, "from_index": 1, "to_index": 4 });
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

        let request = Request::get("/v1/checkpoints/6").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);

        let request =
            Request::get("/v1/checkpoints/99").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let request = Request::get("/v1/checkpoints").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let series: Vec<crate::checkpoint::Checkpoint> =
            serde_json::from_slice(&body).expect("json");
        assert_eq!(series.len(), 1);

        let request =
            Request::get("/v1/consistency?from=6&to=6").body(Body::empty()).expect("valid request");
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
        let (state, _, _) = test_state();
        let app = router(state);
        let range_body = json!({ "tree_size": 99, "from_index": 0, "to_index": 1 });
        let request = Request::post("/v1/range")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&range_body).expect("serialize")))
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_checkpoint_ingest_with_a_bad_signature_is_a_400() {
        let (state, key, log_id) = test_state();
        let app = router(state);
        let cp = crate::checkpoint::Checkpoint {
            log_id,
            tree_size: 1,
            root_hash: format!("sha256:{}", "00".repeat(32)),
            checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
            key_id: key.key_id(),
            signature: "base64:AAAA".to_owned(),
        };
        assert_eq!(submit_checkpoint(&app, &cp, &[]).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_checkpoint_signed_outside_its_key_validity_range_is_a_400() {
        // The "checkpoint signed by a key outside its validity range" negative test,
        // exercised end to end over HTTP: the genesis key is configured valid only from
        // index 5, and the checkpoint commits just 1 entry.
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"aa".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "88".repeat(32));
        let config = Config::resolve(&ConfigSpec {
            log_id: log_id.clone(),
            keys: vec![TrustedLogKeySpec {
                key_id: key.key_id(),
                pubkey: key.pubkey(),
                valid_from_index: 5,
            }],
            genesis_manifest_entry_id: None,
            genesis_checkpoint_cadence_seconds: None,
            store_path: ":memory:".to_owned(),
        })
        .expect("valid config");
        let store = Store::open_in_memory().expect("in-memory store");
        let app = router(AppState { store: Arc::new(store), config: Arc::new(config) });

        let bytes = envelope_bytes(1);
        assert_eq!(stage(&app, &bytes).await, StatusCode::CREATED);
        let (cp, pending) = signed_checkpoint_for(&key, &log_id, &[bytes], true);
        assert_eq!(submit_checkpoint(&app, &cp, &pending).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn itub_against_an_incomplete_series_is_unavailable() {
        // The "ITUB query against an incomplete series" negative test, over HTTP: two
        // checkpoints admitted whose time gap exceeds the declared cadence, so no covering
        // member is within the proven-gap-free frontier.
        let (state, key, log_id) = test_state(); // cadence: 300 seconds
        let app = router(state);

        let first: Vec<Vec<u8>> = (0u8..4).map(envelope_bytes).collect();
        for bytes in &first {
            assert_eq!(stage(&app, bytes).await, StatusCode::CREATED);
        }
        let (cp1, pending1) = signed_checkpoint_for(&key, &log_id, &first, true);
        assert_eq!(submit_checkpoint(&app, &cp1, &pending1).await, StatusCode::CREATED);

        let all_nine: Vec<Vec<u8>> = (0u8..9).map(envelope_bytes).collect();
        for bytes in &all_nine[4..] {
            assert_eq!(stage(&app, bytes).await, StatusCode::CREATED);
        }
        let leaves: Vec<Hash> = all_nine.iter().map(|b| log_leaf_hash(b)).collect();
        let root = atl_core::core::merkle::compute_root(&leaves);
        let mut cp2 = Checkpoint {
            log_id: log_id.clone(),
            tree_size: 9,
            root_hash: format!("sha256:{}", hex::encode(root)),
            // Three hours after cp1, far beyond the 300-second cadence: an undetected-by-
            // consistency-alone gap.
            checkpoint_time: "2026-01-01T03:00:00.000000000Z".to_owned(),
            key_id: key.key_id(),
            signature: String::new(),
        };
        let blob = crate::checkpoint::checkpoint_blob(&cp2).expect("well-formed");
        cp2.signature = key.sign(&blob);
        let pending2: Vec<PendingPromotion> = all_nine[4..]
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let index = 4 + u64::try_from(offset).expect("small test size");
                PendingPromotion {
                    entry_id: entry_id_of(bytes),
                    leaf_index: index,
                    inclusion_path: inclusion_path_for(&leaves, index),
                }
            })
            .collect();
        assert_eq!(submit_checkpoint(&app, &cp2, &pending2).await, StatusCode::CREATED);

        // Covered by cp2's tree_size, but beyond the gap-free frontier (which stops at cp1).
        let request = Request::get("/v1/itub/5").body(Body::empty()).expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Within the gap-free prefix: available.
        let request = Request::get("/v1/itub/2").body(Body::empty()).expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_consistency_request_for_an_unknown_checkpoint_is_a_404() {
        let (state, _, _) = test_state();
        let app = router(state);
        let request =
            Request::get("/v1/consistency?from=0&to=5").body(Body::empty()).expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
