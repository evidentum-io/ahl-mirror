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
        .route("/v1/rotation-proofs/{manifest_entry_index}", get(rotation_proof_handler))
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
            MirrorError::UnknownCheckpoint { .. }
            | MirrorError::UnknownRotationProof { .. }
            | MirrorError::NotStaged { .. } => StatusCode::NOT_FOUND,
            MirrorError::IncompleteEntries { .. }
            | MirrorError::CheckpointNotSeriesUsable { .. }
            | MirrorError::SeriesEquivocated { .. } => StatusCode::CONFLICT,
            MirrorError::StoredEntryCorrupt { .. }
            | MirrorError::TreeMaterialMissing { .. }
            | MirrorError::TreeMaterialCorrupt { .. }
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
        crate::range::build_range_response(&store, &checkpoint, req.from_index, req.to_index)
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
    /// The rotating manifest's entry index this checkpoint is offered as ROTATION-ANCHORING
    /// material for (I-D §7.1), where the submitter names one.
    ///
    /// Optional, and naming it changes nothing about what is accepted: the server detects every
    /// rotation a checkpoint qualifies for either way. What it changes is the REPORT — a named
    /// rotation the checkpoint does not in fact anchor is refused with the reason, instead of
    /// being silently admitted as an ordinary series member and quietly anchoring nothing.
    #[serde(default)]
    rotation_for: Option<u64>,
}

/// What `POST /v1/checkpoints` admitted a submission as.
///
/// Reported rather than left implicit, and reported as two independent facts rather than one
/// choice: a rotation-anchoring checkpoint is deliberately absent from every series route (see
/// [`crate::store`]), and a checkpoint can be BOTH a series member and a rotation anchor — which
/// is what a rotation replacing only the witness key objects produces (I-D §7.1; see
/// [`crate::checkpoint::Admission`]). A submitter told only "created" could tell none of those
/// cases apart except by where the checkpoint later showed up.
#[derive(Debug, Serialize)]
struct AdmissionResponse {
    /// Whether it entered the canonical checkpoint series.
    series_member: bool,
    /// The rotating-manifest entry indexes it anchors, served from
    /// `GET /v1/rotation-proofs/{manifest_entry_index}` and from nowhere else.
    rotation_anchors: Vec<u64>,
}

impl From<crate::checkpoint::Admission> for AdmissionResponse {
    fn from(value: crate::checkpoint::Admission) -> Self {
        Self { series_member: value.series_member, rotation_anchors: value.rotation_anchors }
    }
}

async fn checkpoint_ingest_handler(
    State(state): State<AppState>,
    Json(req): Json<CheckpointIngestRequest>,
) -> Result<(StatusCode, Json<AdmissionResponse>), ApiError> {
    let raw_bytes = req
        .raw
        .as_deref()
        .map(|value| decode_base64_field(value, "raw must be `base64:...`"))
        .transpose()?;

    let store = Arc::clone(&state.store);
    let config = Arc::clone(&state.config);
    let admission = blocking(move || {
        crate::checkpoint::ingest_checkpoint(
            &store,
            &config,
            &req.checkpoint,
            raw_bytes.as_deref(),
            &req.entries_to_promote,
            req.rotation_for,
        )
    })
    .await?;
    Ok((StatusCode::CREATED, Json(AdmissionResponse::from(admission))))
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

// ---------------------------------------------------------------------------
// Rotation-anchoring proofs (I-D §7.1)
// ---------------------------------------------------------------------------

/// One `governance.rotation_proofs[]` element, in the shape I-D §7.1 defines for it.
///
/// The member names and their meanings are the I-D's, not this crate's, so a receipt producer
/// copies this object into `governance.rotation_proofs[]` unchanged rather than translating it.
#[derive(Debug, Serialize)]
struct RotationProofElement {
    /// The entry index of the ROTATING manifest, which a receipt MUST match against that
    /// manifest's own `governance.chain[]` element.
    manifest_entry_index: u64,
    /// The rotation-anchoring checkpoint: `tree_size` greater than `manifest_entry_index`, and
    /// verifying under a log key of the OUTGOING set.
    checkpoint: Checkpoint,
    /// The path proving the rotating manifest's envelope entry id, AT `manifest_entry_index`,
    /// to THIS checkpoint's `root_hash` — not to `anchoring.checkpoint.root_hash`.
    inclusion_path: Vec<String>,
    /// Cosignatures over this checkpoint under the OUTGOING witness set, REQUIRED at L3.
    ///
    /// Always empty here, and empty for a reason rather than as a gap: a mirror does not
    /// cosign and holds no cosignature, so the only honest value it can serve is the empty
    /// array. A deployment claiming L3 fills this member from its witness, which serves the
    /// same element shape at its own rotation-cosignature route (`ahl-witness`), before the
    /// element goes into a receipt.
    witnesses: Vec<Value>,
}

async fn rotation_proof_handler(
    State(state): State<AppState>,
    Path(manifest_entry_index): Path<u64>,
) -> Result<Json<RotationProofElement>, ApiError> {
    let store = Arc::clone(&state.store);
    let config = Arc::clone(&state.config);
    let element =
        blocking(move || rotation_proof_element(&store, &config, manifest_entry_index)).await?;
    Ok(Json(element))
}

/// Assemble the `governance.rotation_proofs[]` element for the rotation anchored at
/// `manifest_entry_index` from this mirror's own material (I-D §7.1).
fn rotation_proof_element(
    store: &Store,
    config: &Config,
    manifest_entry_index: u64,
) -> Result<RotationProofElement, MirrorError> {
    let element = {
        let checkpoint = store
            .get_rotation_checkpoint(manifest_entry_index)?
            .ok_or(MirrorError::UnknownRotationProof { manifest_entry_index })?;

        // Core spec §7.3: at or beyond the lowest divergent `tree_size` the log's checkpoints
        // no longer describe one tree, and the rotation table is inside that scan (see
        // `checkpoint::series_view`). Serving a path opened against one of two conflicting
        // roots would be choosing a branch.
        let view = crate::checkpoint::series_view(store, config)?;
        if let Some(floor) = view.equivocation_floor {
            if checkpoint.tree_size >= floor {
                return Err(MirrorError::SeriesEquivocated {
                    tree_size: checkpoint.tree_size,
                    floor,
                });
            }
        }

        let have = store.count_entries(0, checkpoint.tree_size)?;
        if have != checkpoint.tree_size {
            return Err(MirrorError::IncompleteEntries { have, need: checkpoint.tree_size });
        }
        let proof = store.inclusion_proof(manifest_entry_index, checkpoint.tree_size)?;

        // Self-check before serving, as the enumeration path does: the path this mirror hands
        // out is one it has itself opened against the checkpoint's own root.
        let root = ahl_core::parse_hash_hex(&checkpoint.root_hash)?;
        let leaf = store
            .leaf_hashes_range(manifest_entry_index, manifest_entry_index.saturating_add(1))?
            .first()
            .copied()
            .ok_or(MirrorError::TreeMaterialMissing {
                level: 0,
                node_index: manifest_entry_index,
            })?;
        if !atl_core::core::merkle::verify_inclusion(&leaf, &proof, &root)? {
            return Err(MirrorError::CheckpointRootMismatch { tree_size: checkpoint.tree_size });
        }

        Ok(RotationProofElement {
            manifest_entry_index,
            checkpoint,
            inclusion_path: ahl_core::proof_path_hex(&proof),
            witnesses: Vec::new(),
        })
    };
    element
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

    // The proof comes out of the store's cached tree material: `O(log to_size)` stored
    // 32-octet nodes, no entry bytes at all. The path is the same RFC 9162 path a build over
    // the whole leaf sequence produces — `store::tests::the_cached_prover_agrees_with_an_entry_bytes_build`
    // holds the two together node for node.
    let path = blocking(move || {
        let proof = store.consistency_proof(from_cp.tree_size, to_cp.tree_size)?;
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

#[cfg(feature = "fuzzing")]
pub mod seam {
    //! Synchronous entry points onto this module's request parsers, for the fuzz harness in
    //! `fuzz/`.
    //!
    //! Each function takes the bytes a client sends and runs exactly what the corresponding
    //! handler runs: the same private request type, the same field decoding, and the same
    //! library call — minus `axum`'s routing and the `spawn_blocking` hop, neither of which
    //! parses anything. The request types are private because they are wire shapes rather
    //! than API, so a fuzz target cannot name them; this module is the narrowest way to reach
    //! them without publishing them. Off by default, and the API it adds carries no stability
    //! promise.
    //!
    //! Every function returns `true` if the body parsed and the library call was reached, so
    //! a target can tell an early reject apart from a completed run. Errors are outcomes, not
    //! failures: the property under test is that neither ever panics.

    use axum::extract::Query;
    use axum::http::Uri;

    use super::{
        decode_base64_field, series_usable_checkpoint, CheckpointIngestRequest, ConsistencyQuery,
        PromoteRequest, RangeRequest, RetrieveQuery, StageRequest,
    };
    use crate::config::Config;
    use crate::error::MirrorError;
    use crate::store::Store;

    /// `POST /v1/entries/stage`.
    pub fn stage(store: &Store, body: &[u8]) -> bool {
        let Ok(req) = serde_json::from_slice::<StageRequest>(body) else { return false };
        let Ok(bytes) = decode_base64_field(&req.envelope_base64, "envelope_base64") else {
            return false;
        };
        let _ = crate::ingest::stage_entry(store, &req.entry_id, &bytes, &req.atl_metadata);
        true
    }

    /// `POST /v1/entries/promote`.
    pub fn promote(store: &Store, body: &[u8]) -> bool {
        let Ok(req) = serde_json::from_slice::<PromoteRequest>(body) else { return false };
        let _ = store.get_checkpoint(req.tree_size).map(|found| {
            found.map(|checkpoint| {
                crate::ingest::promote_entry(
                    store,
                    &checkpoint,
                    &req.entry_id,
                    req.leaf_index,
                    &req.inclusion_path,
                )
            })
        });
        true
    }

    /// `POST /v1/range`.
    pub fn range(store: &Store, config: &Config, body: &[u8]) -> bool {
        let Ok(req) = serde_json::from_slice::<RangeRequest>(body) else { return false };
        let Ok(checkpoint) = series_usable_checkpoint(store, config, req.tree_size) else {
            return true;
        };
        let _ =
            crate::range::build_range_response(store, &checkpoint, req.from_index, req.to_index);
        true
    }

    /// `POST /v1/checkpoints`.
    pub fn checkpoint_ingest(store: &Store, config: &Config, body: &[u8]) -> bool {
        let Ok(req) = serde_json::from_slice::<CheckpointIngestRequest>(body) else {
            return false;
        };
        let raw = match req.raw.as_deref().map(|value| decode_base64_field(value, "raw")) {
            Some(Ok(bytes)) => Some(bytes),
            Some(Err(_)) => return false,
            None => None,
        };
        let _ = crate::checkpoint::ingest_checkpoint(
            store,
            config,
            &req.checkpoint,
            raw.as_deref(),
            &req.entries_to_promote,
            req.rotation_for,
        );
        true
    }

    /// `GET /v1/rotation-proofs/{manifest_entry_index}`: the numeric path parameter, as
    /// `axum` renders it before the handler sees it.
    ///
    /// The whole handler runs — the lookup, the equivocation floor, the completeness check,
    /// the inclusion-path opening and the self-check — because the parameter is a client-chosen
    /// `u64` that reaches the store's tree geometry directly.
    pub fn rotation_proof(store: &Store, config: &Config, manifest_entry_index: u64) -> bool {
        let _ = super::rotation_proof_element(store, config, manifest_entry_index);
        true
    }

    /// `GET /v1/entries/{entry_id}?encoding=…`: the path segment and the query string.
    pub fn retrieve(store: &Store, entry_id: &str, query: &str) -> bool {
        let Ok(uri) = format!("/?{query}").parse::<Uri>() else { return false };
        let Ok(Query(parsed)) = Query::<RetrieveQuery>::try_from_uri(&uri) else { return false };
        let _base64_form = parsed.encoding.as_deref() == Some("base64");
        let _ = crate::retrieval::retrieve_by_id(store, entry_id);
        true
    }

    /// `GET /v1/consistency?from=…&to=…`.
    pub fn consistency(store: &Store, config: &Config, query: &str) -> bool {
        let Ok(uri) = format!("/?{query}").parse::<Uri>() else { return false };
        let Ok(Query(parsed)) = Query::<ConsistencyQuery>::try_from_uri(&uri) else { return false };
        let _: Result<_, MirrorError> = series_usable_checkpoint(store, config, parsed.from);
        let _: Result<_, MirrorError> = series_usable_checkpoint(store, config, parsed.to);
        true
    }
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

    /// A checkpoint may claim any `tree_size` it likes, and the claim is read before its
    /// signature is verified. Sizing an allocation by that claim let an unauthenticated
    /// `POST /v1/checkpoints` abort the process: `i64::MAX` overflowed the capacity
    /// computation outright, and merely large values exhausted memory first. Both are
    /// rejections now, and the work stays proportional to the entries actually held.
    #[tokio::test]
    async fn an_oversized_tree_size_claim_is_rejected_not_allocated_for() {
        let hx = harness();
        let app = router(hx.state.clone());
        for tree_size in [u64::try_from(i64::MAX).expect("positive"), 1u64 << 40, u64::MAX] {
            let cp = crate::checkpoint::Checkpoint {
                log_id: hx.log_id.clone(),
                tree_size,
                root_hash: format!("sha256:{}", hex::encode(hx.genesis_leaf)),
                checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
                key_id: hx.log_key.key_id(),
                signature: "base64:AAAA".to_owned(),
            };
            let status = submit_checkpoint(&app, &cp, &[]).await;
            assert!(status.is_client_error(), "tree_size {tree_size} gave {status}");
        }
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

    /// The served `consistency_path` is byte for byte the path an entry-bytes build produces
    /// — the route now opens the proof through the store's cached tree material, and the
    /// response is unchanged by that.
    #[tokio::test]
    async fn the_served_consistency_path_is_the_entry_bytes_path() {
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
        let (cp2, pending2) =
            signed_checkpoint_for(&hx, &all_new, "2026-01-01T00:03:00.000000000Z", true);
        assert_eq!(submit_checkpoint(&app, &cp2, &pending2).await, StatusCode::CREATED);

        // tree sizes 5 and 10: the genesis manifest, then four entries, then five more.
        let request = Request::get("/v1/consistency?from=5&to=10")
            .body(Body::empty())
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let value: Value = serde_json::from_slice(&body).expect("json");

        // The oracle: the same RFC 9162 proof generated from leaf hashes re-derived from the
        // entry bytes, which is what this route did before.
        let mut leaves = vec![hx.genesis_leaf];
        leaves.extend(all_new.iter().map(|b| log_leaf_hash(b)));
        let oracle = atl_core::core::merkle::generate_consistency_proof(5, 10, |level, at| {
            if level == 0 {
                leaves.get(usize::try_from(at).ok()?).copied()
            } else {
                None
            }
        })
        .expect("well-formed sizes");
        let expected: Vec<Value> = oracle
            .path
            .iter()
            .map(|h| Value::String(format!("sha256:{}", hex::encode(h))))
            .collect();
        assert!(!expected.is_empty(), "a 5 -> 10 proof is not the trivial empty path");
        assert_eq!(value["consistency_path"].as_array().expect("array"), &expected);
    }

    /// The fuzz seam runs the same parsers the handlers above run, so it is exercised the
    /// same way once each: a body a client would send, and bytes no client would send.
    #[cfg(feature = "fuzzing")]
    mod seam {
        use super::super::seam;
        use super::*;

        /// The same unauthenticated oversized-claim input, driven through the seam the
        /// `checkpoint` fuzz target uses, so a regression is caught by the harness too.
        #[test]
        fn an_oversized_tree_size_claim_does_not_abort_the_seam() {
            let fx = harness();
            for tree_size in [u64::try_from(i64::MAX).expect("positive"), 1u64 << 40, u64::MAX] {
                let body = json!({ "checkpoint": {
                    "log_id": fx.log_id.clone(),
                    "tree_size": tree_size,
                    "root_hash": format!("sha256:{}", hex::encode(fx.genesis_leaf)),
                    "checkpoint_time": "2026-01-01T00:00:00.000000000Z",
                    "key_id": fx.log_key.key_id(),
                    "signature": "base64:AAAA",
                }});
                assert!(seam::checkpoint_ingest(
                    &fx.state.store,
                    &fx.state.config,
                    &serde_json::to_vec(&body).expect("serialize")
                ));
            }
        }

        #[test]
        fn every_seam_entry_point_parses_a_request_and_refuses_garbage() {
            let fx = harness();
            let store = &fx.state.store;
            let config = &fx.state.config;
            let bytes = envelope_bytes(1);
            let entry_id = entry_id_of(&bytes);

            let stage_body = json!({
                "entry_id": entry_id,
                "envelope_base64": format!("base64:{}", B64.encode(&bytes)),
                "atl_metadata": adaptor_metadata_object(),
            });
            assert!(seam::stage(store, &serde_json::to_vec(&stage_body).expect("serialize")));

            let promote_body = json!({ "entry_id": entry_id, "tree_size": 1, "leaf_index": 0,
                        "inclusion_path": [] });
            assert!(seam::promote(store, &serde_json::to_vec(&promote_body).expect("serialize")));

            let range_body = json!({ "tree_size": 1, "from_index": 0, "to_index": 1 });
            assert!(seam::range(
                store,
                config,
                &serde_json::to_vec(&range_body).expect("serialize")
            ));

            let (cp, _) = signed_checkpoint_for(&fx, &[], "2026-01-01T00:01:00.000000000Z", false);
            let ingest_body = json!({ "checkpoint": cp });
            assert!(seam::checkpoint_ingest(
                store,
                config,
                &serde_json::to_vec(&ingest_body).expect("serialize")
            ));

            assert!(seam::retrieve(store, &entry_id, "encoding=base64"));
            assert!(seam::consistency(store, config, "from=0&to=1"));

            // Nothing here parses, and nothing here aborts.
            assert!(!seam::stage(store, b"\xff\xfe"));
            assert!(!seam::promote(store, b"{"));
            assert!(!seam::range(store, config, b"[]"));
            assert!(!seam::checkpoint_ingest(store, config, b"null"));
            assert!(!seam::consistency(store, config, "from=&to="));
        }
    }
    // -----------------------------------------------------------------------
    // Rotation-anchoring proofs (I-D §7.1)
    // -----------------------------------------------------------------------

    /// A log that has performed a log-key rotation, served through the real router.
    ///
    /// Three entries: the genesis manifest at index 0 under the OUTGOING log key, a successor
    /// manifest at index 1 that replaces the log key set with the INCOMING one, and a subject
    /// statement at index 2. Every payload is a complete I-D §6.2/§2.2 statement rather than
    /// the minimum this crate itself reads, because
    /// `a_receipt_carrying_the_served_element_verifies` hands the whole corpus to
    /// `ahl_core::receipt::verify_receipt_report`, which reads all of it.
    mod rotation {
        use std::collections::BTreeMap;

        use ahl_core::receipt::{
            verify_receipt_report, AdaptorCapabilities, AdaptorProfile, Limits, Outcome,
            TrustPolicy,
        };

        use super::*;

        /// The artifact a verifier holds under `ahl-adaptor-atl-v1` in these tests. Its bytes
        /// are what the manifests' `log.adaptor.hash` pins, recomputed rather than transcribed.
        const PROFILE_DOCUMENT: &[u8] = b"ahl-adaptor-atl-v1 test artifact";

        /// The entry index the rotating manifest is anchored at.
        const ROTATING_INDEX: u64 = 1;

        fn manifest_payload(
            log_id: &str,
            producer: &ahl_core::TestKey,
            log_key: &ahl_core::TestKey,
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
                "datasets": {
                    "records": {
                        "canonicalization": "jcs",
                        "commitment_mode": "plain",
                        "key_access": "not-applicable",
                        "authority": {
                            "producer": "producer-1",
                            "key_ids": [ producer.key_id() ],
                        },
                    },
                },
                "pipelines": { "include": [], "exclude": [] },
                "windows": { "anchoring": "PT24H", "propagation": "P30D" },
                "retention": { "statements": "P10Y" },
                "properties": { "reproducible_reconstruction": false },
                "level": "L2",
            });
            if let Some(predecessor) = predecessor {
                payload["predecessor"] = json!(predecessor);
            }
            payload
        }

        struct Corpus {
            state: AppState,
            outgoing: ahl_core::TestKey,
            incoming: ahl_core::TestKey,
            producer: ahl_core::TestKey,
            log_id: String,
            genesis_entry_id: String,
            envelopes: Vec<Value>,
            leaves: Vec<Hash>,
            root: Hash,
        }

        impl Corpus {
            fn app(&self) -> Router {
                router(self.state.clone())
            }

            /// A checkpoint over the whole three-entry tree, signed by `key`.
            fn checkpoint(&self, key: &ahl_core::TestKey, time: &str) -> Checkpoint {
                self.checkpoint_at(key, 3, self.root, time)
            }

            /// A checkpoint claiming `tree_size` and `root`, signed by `key`.
            fn checkpoint_at(
                &self,
                key: &ahl_core::TestKey,
                tree_size: u64,
                root: Hash,
                time: &str,
            ) -> Checkpoint {
                let mut cp = Checkpoint {
                    log_id: self.log_id.clone(),
                    tree_size,
                    root_hash: format!("sha256:{}", hex::encode(root)),
                    checkpoint_time: time.to_owned(),
                    key_id: key.key_id(),
                    signature: String::new(),
                };
                let blob = crate::checkpoint::checkpoint_blob(&cp).expect("well-formed");
                cp.signature = key.sign(&blob);
                cp
            }
        }

        fn corpus() -> Corpus {
            let producer =
                ahl_core::TestKey::from_seed_hex("producer", &"a1".repeat(32)).expect("seed");
            let outgoing =
                ahl_core::TestKey::from_seed_hex("log-out", &"a2".repeat(32)).expect("seed");
            let incoming =
                ahl_core::TestKey::from_seed_hex("log-in", &"a3".repeat(32)).expect("seed");
            let log_id = format!("sha256:{}", "a4".repeat(32));

            let genesis = ahl_core::envelope(
                manifest_payload(&log_id, &producer, &outgoing, None),
                &producer,
            );
            let genesis_entry_id = ahl_core::entry_id(&genesis);
            let rotating = ahl_core::envelope(
                manifest_payload(&log_id, &producer, &incoming, Some(&genesis_entry_id)),
                &producer,
            );
            let rotating_statement_id =
                ahl_core::statement_id(&rotating).expect("well-formed envelope");
            let subject = ahl_core::envelope(
                json!({
                    "ahl_version": ahl_core::AHL_VERSION,
                    "type": "ingestion",
                    "producer": "producer-1",
                    "issued_at": "2026-01-01T00:00:00Z",
                    "valid_time": "2026-01-01T00:00:00Z",
                    "manifest": rotating_statement_id,
                    "dataset": "records",
                    "origin": "batch:2026-01-01/records-01",
                    "record": format!("sha256:{}", "b1".repeat(32)),
                }),
                &producer,
            );

            let envelopes = vec![genesis, rotating, subject];
            let entries: Vec<Vec<u8>> = envelopes.iter().map(ahl_core::jcs).collect();
            let leaves: Vec<Hash> = entries.iter().map(|b| log_leaf_hash(b)).collect();
            let root = atl_core::core::merkle::compute_root(&leaves);

            let store = Store::open_in_memory().expect("in-memory store");
            for (index, bytes) in entries.iter().enumerate() {
                let id = entry_id_of(bytes);
                store.stage_entry(&id, bytes).expect("stage");
                store
                    .promote_entry(u64::try_from(index).expect("small test index"), &id)
                    .expect("promote");
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

            Corpus {
                state: AppState { store: Arc::new(store), config: Arc::new(config) },
                outgoing,
                incoming,
                producer,
                log_id,
                genesis_entry_id,
                envelopes,
                leaves,
                root,
            }
        }

        async fn post_checkpoint(app: &Router, cp: &Checkpoint) -> (StatusCode, Value) {
            let request = Request::post("/v1/checkpoints")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "checkpoint": cp })).expect("serialize"),
                ))
                .expect("valid request");
            let response = app.clone().oneshot(request).await.expect("service call");
            let status = response.status();
            let body = response.into_body().collect().await.expect("body").to_bytes();
            (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
        }

        async fn get_json(app: &Router, uri: &str) -> (StatusCode, Value) {
            let request = Request::get(uri).body(Body::empty()).expect("valid request");
            let response = app.clone().oneshot(request).await.expect("service call");
            let status = response.status();
            let body = response.into_body().collect().await.expect("body").to_bytes();
            (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
        }

        /// A genuine inclusion path for `leaves[index]` under the whole tree.
        fn path_for(corpus: &Corpus, index: u64) -> Vec<String> {
            inclusion_path_for(&corpus.leaves, index)
        }

        #[tokio::test]
        async fn the_rotation_route_serves_the_element_and_the_series_routes_do_not() {
            let corpus = corpus();
            let app = corpus.app();
            let rotation_cp = corpus.checkpoint(&corpus.outgoing, "2026-01-01T01:00:00.000000000Z");

            let (status, body) = post_checkpoint(&app, &rotation_cp).await;
            assert_eq!(status, StatusCode::CREATED);
            assert_eq!(body["series_member"], false);
            assert_eq!(body["rotation_anchors"], json!([ROTATING_INDEX]));

            // Served on the rotation route, in the `rotation_proofs[]` element shape.
            let (status, element) =
                get_json(&app, &format!("/v1/rotation-proofs/{ROTATING_INDEX}")).await;
            assert_eq!(status, StatusCode::OK, "{element}");
            assert_eq!(element["manifest_entry_index"], ROTATING_INDEX);
            assert_eq!(element["checkpoint"], serde_json::to_value(&rotation_cp).expect("json"));
            assert_eq!(element["inclusion_path"], json!(path_for(&corpus, ROTATING_INDEX)));
            assert_eq!(element["witnesses"], json!([]));

            // And nowhere else: not in the series listing, not at its own tree_size, not as
            // an ITUB bound, not as a consistency endpoint.
            let (status, members) = get_json(&app, "/v1/checkpoints").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(members, json!([]), "rotation material is not a series member");
            assert_eq!(get_json(&app, "/v1/checkpoints/3").await.0, StatusCode::NOT_FOUND);
            assert_eq!(get_json(&app, "/v1/itub/0").await.0, StatusCode::NOT_FOUND);
            assert_eq!(
                get_json(&app, "/v1/consistency?from=1&to=3").await.0,
                StatusCode::NOT_FOUND
            );

            // A rotation this log did not perform has no proof to serve.
            assert_eq!(get_json(&app, "/v1/rotation-proofs/0").await.0, StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn an_incoming_key_checkpoint_is_an_ordinary_series_member() {
            let corpus = corpus();
            let app = corpus.app();
            let series_cp = corpus.checkpoint(&corpus.incoming, "2026-01-01T01:00:00.000000000Z");

            let (status, body) = post_checkpoint(&app, &series_cp).await;
            assert_eq!(status, StatusCode::CREATED);
            assert_eq!(body["series_member"], true);
            assert_eq!(body["rotation_anchors"], json!([]));

            let (status, members) = get_json(&app, "/v1/checkpoints").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(members.as_array().map(Vec::len), Some(1));
            assert_eq!(members[0]["state"], "series_usable");
            assert_eq!(
                get_json(&app, &format!("/v1/rotation-proofs/{ROTATING_INDEX}")).await.0,
                StatusCode::NOT_FOUND
            );
        }

        /// Held apart is not held outside the rules. A rotation-anchoring checkpoint that
        /// contradicts a series member at the same `tree_size` is equivocation (core spec
        /// §7.3), and from the lowest divergent size onward nothing may be grounded — the
        /// rotation route included.
        #[tokio::test]
        async fn a_rotation_checkpoint_diverging_from_a_series_member_is_reported() {
            let corpus = corpus();
            let app = corpus.app();
            // A size this store does not reach, so neither root is recomputable and both
            // checkpoints are admitted as merely authenticated.
            let series = corpus.checkpoint_at(
                &corpus.incoming,
                5,
                [0x11; 32],
                "2026-01-01T03:00:00.000000000Z",
            );
            let rotation = corpus.checkpoint_at(
                &corpus.outgoing,
                5,
                [0x22; 32],
                "2026-01-01T04:00:00.000000000Z",
            );
            assert_eq!(post_checkpoint(&app, &series).await.1["series_member"], true);
            assert_eq!(
                post_checkpoint(&app, &rotation).await.1["rotation_anchors"],
                json!([ROTATING_INDEX])
            );

            let (status, body) =
                get_json(&app, &format!("/v1/rotation-proofs/{ROTATING_INDEX}")).await;
            assert_eq!(status, StatusCode::CONFLICT, "{body}");
            assert!(
                body["error"].as_str().is_some_and(|e| e.contains("equivocates")),
                "the divergence is named, not swallowed: {body}"
            );
            // And the series itself reports the same floor.
            assert_eq!(get_json(&app, "/v1/checkpoints/5").await.0, StatusCode::CONFLICT);
        }

        /// The cross-check that decides whether the element this mirror serves is the thing
        /// I-D §7.1 defines: a receipt carrying it, verified by `ahl-core`'s own verifier.
        ///
        /// Nothing in the element is edited on the way in — the bytes the route returned are
        /// the bytes `governance.rotation_proofs[0]` carries. If the mirror had chosen the
        /// wrong checkpoint, opened the path against the wrong root, or named the wrong
        /// rotating index, §7.5.1 4b(M)'s rotation-anchoring rule would reject the receipt.
        #[tokio::test]
        async fn a_receipt_carrying_the_served_element_verifies() {
            let corpus = corpus();
            let app = corpus.app();
            let rotation_cp = corpus.checkpoint(&corpus.outgoing, "2026-01-01T01:00:00.000000000Z");
            let anchoring_cp =
                corpus.checkpoint(&corpus.incoming, "2026-01-01T02:00:00.000000000Z");
            assert_eq!(post_checkpoint(&app, &rotation_cp).await.0, StatusCode::CREATED);
            assert_eq!(post_checkpoint(&app, &anchoring_cp).await.0, StatusCode::CREATED);

            let (status, element) =
                get_json(&app, &format!("/v1/rotation-proofs/{ROTATING_INDEX}")).await;
            assert_eq!(status, StatusCode::OK);

            let key_object = |key: &ahl_core::TestKey, entry_index: u64| {
                json!({
                    "key_id": key.key_id(),
                    "pubkey": key.pubkey(),
                    "source": "manifest-chain",
                    "binding": { "entry_index": entry_index },
                })
            };
            let receipt = json!({
                "ahl_receipt_version": "2",
                "spec_version": "0.4.0",
                "claim": {
                    "type": "statement-anchored",
                    "assurance": {
                        "governance": "declared",
                        "competing_triggers": "not-checked",
                        "witnessed": false,
                        "continued_history": false,
                        "content_binding": "none",
                    },
                },
                "subject": {
                    "statement_id": ahl_core::statement_id(&corpus.envelopes[2]).expect("id"),
                    "entry_id": ahl_core::entry_id(&corpus.envelopes[2]),
                    "entry_index": 2,
                    "manifest": ahl_core::statement_id(&corpus.envelopes[1]).expect("id"),
                },
                "envelope": corpus.envelopes[2],
                "keys": {
                    // The INCOMING log key binds to the version active for the anchoring
                    // checkpoint's tree_size; the OUTGOING one binds to the predecessor, which
                    // is what §7.1's transition exception requires of rotation material.
                    "log": [
                        key_object(&corpus.incoming, ROTATING_INDEX),
                        key_object(&corpus.outgoing, 0),
                    ],
                    "witness": [],
                    "producer": [ key_object(&corpus.producer, ROTATING_INDEX) ],
                },
                "anchoring": {
                    "adaptor": {
                        "id": ahl_core::ATL_PROFILE_ID,
                        "hash": ahl_core::sha256_hex(PROFILE_DOCUMENT),
                    },
                    "checkpoint": anchoring_cp,
                    "inclusion_path": path_for(&corpus, 2),
                    "witnesses": [],
                },
                "governance": {
                    "genesis_entry_id": corpus.genesis_entry_id,
                    "chain": [
                        {
                            "envelope": corpus.envelopes[0],
                            "entry_index": 0,
                            "inclusion_path": path_for(&corpus, 0),
                        },
                        {
                            "envelope": corpus.envelopes[1],
                            "entry_index": ROTATING_INDEX,
                            "inclusion_path": path_for(&corpus, ROTATING_INDEX),
                        },
                    ],
                    "rotation_proofs": [ element ],
                    "currency": { "mode": "declared" },
                },
            });

            let policy = TrustPolicy {
                genesis_entry_id: corpus.genesis_entry_id.clone(),
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
    }
}
