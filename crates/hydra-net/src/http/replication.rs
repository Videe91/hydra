//! V2 patch 3A — leader-side replication read/export HTTP.
//!
//! This is the **first external replication surface**. It is strictly
//! read/export: a follower (or any operator) can ask the leader for
//! its head, its registered peers, and pages of commits to replay.
//! Follower apply (`POST /replication/apply`) is intentionally
//! deferred to patch 3B because applying commit tails safely is
//! engine-correctness work and is best landed separately.
//!
//! Routes:
//!
//! - `GET  /replication/status`               — head + role + peers
//! - `GET  /replication/commits`              — paged commit export
//! - `GET  /replication/peers`                — all registered peers
//! - `GET  /replication/peers/:peer_id`       — single peer, 404 on miss
//! - `GET  /replication/peers/:peer_id/lag`   — V2 polish: observed
//!   lag for the peer. Returns `200 {peer_id, lag: null}` when no
//!   observation has been recorded yet (or the peer is unknown to
//!   the in-memory ReplicationStore). This route never 404s — a
//!   non-recorded peer is a valid "no data yet" state, not an error.
//! - `POST /replication/apply`                — V2 patch 3B: follower
//!   applies a leader-supplied page of committed batches. Body is
//!   `ApplyReplicationRequest`. Validation failures map to 400 with
//!   `{error: "..."}`. See `Hydra::apply_replication_commits` for
//!   the validation contract.
//! - `GET  /replication/snapshot/latest`      — V2 patch 4B: latest
//!   snapshot manifest. Returns `{"manifest": null}` (200) when the
//!   leader has no snapshots yet, so followers don't have to treat
//!   "fresh leader" as an error.
//! - `GET  /replication/snapshot/:snapshot_id` — V2 patch 4B: full
//!   `SnapshotBody` for bootstrap. 404 on miss. These are
//!   **replication-specific exports** — the admin `/snapshots/*`
//!   surface stays separate so the two can evolve independently.
//!
//! Auth / tenant policy:
//!
//! - Replication is **cluster control plane** — `X-Hydra-Tenant` is
//!   NOT required on any of these routes.
//! - Scope gating lives in `hydra-api::auth::required_scopes_for`:
//!   `GET /replication/*` → `read:replication`,
//!   `POST /replication/*` → `admin:replication`.
//!
//! Role is hardcoded `ReplicationRole::Leader` for both `/status` and
//! `/apply` in this patch. A runtime "what role am I" config is a
//! follow-up.

use crate::http::pagination::normalized_limit;
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hydra_core::{
    CommitBatch, CommitId, ReplicaId, ReplicationLag, ReplicationPeer, ReplicationRole, SnapshotBody,
    SnapshotId, SnapshotManifest,
};
use serde::{Deserialize, Serialize};

/// Shared HTTP state for the replication read routes.
#[derive(Clone)]
pub struct ReplicationHttpState {
    pub runtime: RuntimeHandle,
}

impl ReplicationHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the leader-side replication HTTP router.
pub fn replication_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/replication/status", get(get_replication_status))
        .route("/replication/commits", get(get_replication_commits))
        .route("/replication/peers", get(list_replication_peers))
        .route("/replication/peers/:peer_id", get(get_replication_peer))
        .route(
            "/replication/peers/:peer_id/lag",
            get(get_replication_peer_lag),
        )
        .route("/replication/apply", post(post_replication_apply))
        .route(
            "/replication/snapshot/latest",
            get(get_replication_snapshot_latest),
        )
        .route(
            "/replication/snapshot/:snapshot_id",
            get(get_replication_snapshot_body),
        )
        .with_state(ReplicationHttpState::new(runtime))
}

// === DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationCommitsQuery {
    pub after_sequence: Option<u64>,
    pub limit: Option<usize>,
}

/// Paged commit export response.
///
/// `next_after_sequence`:
///   - `Some(seq)` — pass this as `after_sequence` on the next call to
///     continue; there are more commits past the current page.
///   - `None`      — this page reached the leader's current tail.
///
/// Client pull loop:
///
/// ```text
/// while let Some(cursor) = page.next_after_sequence {
///     page = GET /replication/commits?after_sequence={cursor}
///     apply(page.commits)
/// }
/// ```
///
/// `leader_head_sequence` / `leader_head_commit_id` are always populated
/// from the leader's latest commit (or `0` / `None` on an empty ledger),
/// so follower lag is observable even on a page that returned zero
/// commits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationCommitPage {
    pub commits: Vec<CommitBatch>,
    pub next_after_sequence: Option<u64>,
    pub leader_head_sequence: u64,
    pub leader_head_commit_id: Option<CommitId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationStatusResponse {
    /// Hardcoded `Leader` in patch 3A — runtime role config lands later.
    pub role: ReplicationRole,
    pub head_sequence: u64,
    pub head_commit_id: Option<CommitId>,
    pub peers: Vec<ReplicationPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPeersResponse {
    pub peers: Vec<ReplicationPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPeerResponse {
    pub peer: ReplicationPeer,
}

/// V2 polish — observed lag for a peer. `lag: None` when no
/// observation has been recorded yet (or the peer_id is unknown
/// to the in-memory ReplicationStore). The route always returns
/// `200`; "no data yet" is `lag: null`, not 404.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationLagResponse {
    pub peer_id: ReplicaId,
    pub lag: Option<ReplicationLag>,
}

/// V2 patch 3B — follower apply request body.
///
/// `peer_id` identifies the source/leader peer (echoed back on the
/// response for audit). `commits` is the leader-supplied page from
/// `GET /replication/commits` — order MUST be strictly ascending by
/// sequence, with the first batch chaining onto the follower's
/// current head.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyReplicationRequest {
    pub peer_id: ReplicaId,
    pub commits: Vec<CommitBatch>,
}

/// V2 patch 3B — follower apply response.
///
/// Always populated regardless of `applied_count` so pull loops learn
/// the follower's cursor in one round trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyReplicationResponse {
    pub peer_id: ReplicaId,
    pub applied_count: usize,
    pub latest_sequence: Option<u64>,
    pub latest_commit_id: Option<CommitId>,
}

/// V2 patch 4B — leader's latest snapshot manifest, used by follower
/// bootstrap to decide whether to restore-then-tail-pull or fall back
/// to commits-only.
///
/// `manifest` is `Option` so an empty leader returns 200 with
/// `{"manifest": null}`, not 404 — "fresh leader" isn't an error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationSnapshotManifestResponse {
    pub manifest: Option<SnapshotManifest>,
}

/// V2 patch 4B — full snapshot body for bootstrap. Returned only when
/// the snapshot id resolves; missing ids → 404.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationSnapshotBodyResponse {
    pub body: SnapshotBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

fn error_response(status: StatusCode, error: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: error.into(),
        }),
    )
        .into_response()
}

// === Handlers ===

async fn get_replication_status(State(state): State<ReplicationHttpState>) -> Response {
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let (head_sequence, head_commit_id) = match hydra.latest_commit() {
        Some(record) => (record.sequence, Some(record.id.clone())),
        None => (0, None),
    };
    let peers = hydra
        .replication_store()
        .all_peers()
        .cloned()
        .collect::<Vec<_>>();
    Json(ReplicationStatusResponse {
        role: ReplicationRole::Leader,
        head_sequence,
        head_commit_id,
        peers,
    })
    .into_response()
}

async fn get_replication_commits(
    State(state): State<ReplicationHttpState>,
    Query(query): Query<ReplicationCommitsQuery>,
) -> Response {
    let after_sequence = query.after_sequence.unwrap_or(0);
    let limit = normalized_limit(query.limit);

    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let (leader_head_sequence, leader_head_commit_id) = match hydra.latest_commit() {
        Some(record) => (record.sequence, Some(record.id.clone())),
        None => (0, None),
    };

    // batches_in_sequence() returns batches ordered ascending by sequence.
    // Filter out anything <= after_sequence, then take `limit` of them.
    // We need to know whether more remain past the page to compute
    // `next_after_sequence`, so collect into a Vec and inspect the
    // remainder explicitly.
    let batches: Vec<CommitBatch> = hydra
        .commit_ledger()
        .batches_in_sequence()
        .into_iter()
        .filter(|batch| batch.sequence > after_sequence)
        .cloned()
        .collect();

    let total_after_filter = batches.len();
    let commits: Vec<CommitBatch> = batches.into_iter().take(limit).collect();
    let next_after_sequence = if commits.len() < total_after_filter {
        commits.last().map(|batch| batch.sequence)
    } else {
        None
    };

    Json(ReplicationCommitPage {
        commits,
        next_after_sequence,
        leader_head_sequence,
        leader_head_commit_id,
    })
    .into_response()
}

async fn list_replication_peers(State(state): State<ReplicationHttpState>) -> Response {
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let peers = hydra
        .replication_store()
        .all_peers()
        .cloned()
        .collect::<Vec<_>>();
    Json(ReplicationPeersResponse { peers }).into_response()
}

async fn get_replication_peer(
    State(state): State<ReplicationHttpState>,
    Path(peer_id): Path<String>,
) -> Response {
    let peer_id = ReplicaId::from_str(&peer_id);
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    match hydra.replication_peer(&peer_id) {
        Some(peer) => Json(ReplicationPeerResponse {
            peer: peer.clone(),
        })
        .into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("replication peer not found: {peer_id}"),
        ),
    }
}

async fn get_replication_peer_lag(
    State(state): State<ReplicationHttpState>,
    Path(peer_id): Path<String>,
) -> Response {
    let peer_id = ReplicaId::from_str(&peer_id);
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let lag = hydra.latest_replication_lag(&peer_id).cloned();
    // Always 200 — no observation yet is `lag: null`, not 404. The
    // puller writes a heartbeat on every pull (including empty
    // pages), so absent lag here means either nothing has pulled
    // yet, or the peer_id doesn't match the puller's configured
    // identity. Both are legitimate "no data" states.
    Json(ReplicationLagResponse { peer_id, lag }).into_response()
}

async fn post_replication_apply(
    State(state): State<ReplicationHttpState>,
    Json(request): Json<ApplyReplicationRequest>,
) -> Response {
    let ApplyReplicationRequest { peer_id, commits } = request;
    let hydra = state.runtime.hydra();
    let mut hydra = hydra.write().await;
    match hydra.apply_replication_commits(peer_id, commits) {
        Ok(report) => Json(ApplyReplicationResponse {
            peer_id: report.peer_id,
            applied_count: report.applied_count,
            latest_sequence: report.latest_sequence,
            latest_commit_id: report.latest_commit_id,
        })
        .into_response(),
        // All validation failures from apply_replication_commits surface
        // as HydraError::QueryError; map uniformly to 400. Engine doesn't
        // need a dedicated error variant for replication-input failures.
        Err(err) => error_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

async fn get_replication_snapshot_latest(
    State(state): State<ReplicationHttpState>,
) -> Response {
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let manifest = hydra.latest_snapshot_manifest().cloned();
    Json(ReplicationSnapshotManifestResponse { manifest }).into_response()
}

async fn get_replication_snapshot_body(
    State(state): State<ReplicationHttpState>,
    Path(snapshot_id): Path<String>,
) -> Response {
    let snapshot_id = SnapshotId::from_str(&snapshot_id);
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    match hydra.snapshot_body(&snapshot_id) {
        Some(body) => Json(ReplicationSnapshotBodyResponse {
            body: body.clone(),
        })
        .into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("replication snapshot not found: {snapshot_id}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use hydra_core::{
        ActorId, EventKind, NodeId, ReplicationMode, ReplicationPeer, ReplicationRole,
    };
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn empty_get(uri: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    async fn read_json<T: for<'de> Deserialize<'de>>(response: Response) -> T {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn signal(name: &str) -> EventKind {
        EventKind::Signal {
            source: NodeId::from_str("test.replication"),
            name: name.to_string(),
            payload: HashMap::new(),
        }
    }

    fn peer_event(id: &str) -> EventKind {
        EventKind::ReplicaRegistered {
            peer: ReplicationPeer::registered(
                ReplicaId::from_str(id),
                ReplicationRole::Follower,
                ReplicationMode::SnapshotThenTail,
                ActorId::from_str("actor_replication_test"),
            ),
        }
    }

    #[tokio::test]
    async fn status_on_empty_ledger_returns_zero_head_and_leader_role() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = replication_router(runtime);
        let response = app.oneshot(empty_get("/replication/status")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationStatusResponse = read_json(response).await;
        assert_eq!(decoded.role, ReplicationRole::Leader);
        assert_eq!(decoded.head_sequence, 0);
        assert!(decoded.head_commit_id.is_none());
        assert!(decoded.peers.is_empty());
    }

    #[tokio::test]
    async fn status_after_ingest_returns_head_and_includes_peers() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(peer_event("replica_acme")).unwrap();
        }
        let app = replication_router(runtime);
        let response = app.oneshot(empty_get("/replication/status")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationStatusResponse = read_json(response).await;
        // Two cascades ingested → head_sequence is 2 (signal + peer_registered).
        assert_eq!(decoded.head_sequence, 2);
        assert!(decoded.head_commit_id.is_some());
        assert_eq!(decoded.peers.len(), 1);
        assert_eq!(decoded.peers[0].id.as_str(), "replica_acme");
    }

    #[tokio::test]
    async fn commits_after_sequence_returns_all_when_after_zero() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/commits?after_sequence=0"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationCommitPage = read_json(response).await;
        assert_eq!(decoded.commits.len(), 2);
        assert_eq!(decoded.leader_head_sequence, 2);
        assert!(decoded.next_after_sequence.is_none()); // reached tail
    }

    #[tokio::test]
    async fn commits_after_sequence_skips_earlier_commits() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/commits?after_sequence=1"))
            .await
            .unwrap();
        let decoded: ReplicationCommitPage = read_json(response).await;
        assert_eq!(decoded.commits.len(), 1);
        assert_eq!(decoded.commits[0].sequence, 2);
        assert!(decoded.next_after_sequence.is_none());
    }

    #[tokio::test]
    async fn commits_respects_limit_and_returns_next_after_sequence() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
            hydra.ingest(signal("three")).unwrap();
        }
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/commits?after_sequence=0&limit=2"))
            .await
            .unwrap();
        let decoded: ReplicationCommitPage = read_json(response).await;
        assert_eq!(decoded.commits.len(), 2);
        assert_eq!(decoded.commits[0].sequence, 1);
        assert_eq!(decoded.commits[1].sequence, 2);
        // More remain after seq=2 (seq=3 is unfetched).
        assert_eq!(decoded.next_after_sequence, Some(2));
        assert_eq!(decoded.leader_head_sequence, 3);
    }

    #[tokio::test]
    async fn peers_list_returns_registered_peers() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(peer_event("replica_acme")).unwrap();
            hydra.ingest(peer_event("replica_beta")).unwrap();
        }
        let app = replication_router(runtime);
        let response = app.oneshot(empty_get("/replication/peers")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationPeersResponse = read_json(response).await;
        assert_eq!(decoded.peers.len(), 2);
        let ids: Vec<&str> = decoded.peers.iter().map(|p| p.id.as_str()).collect();
        assert!(ids.contains(&"replica_acme"));
        assert!(ids.contains(&"replica_beta"));
    }

    #[tokio::test]
    async fn peer_by_id_returns_404_for_unknown() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/peers/replica_ghost"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // === V2 patch 3B — POST /replication/apply ===

    fn json_post(uri: &str, body: &impl Serialize) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    fn follower_peer_id() -> ReplicaId {
        ReplicaId::from_str("replica_follower_http")
    }

    #[tokio::test]
    async fn apply_empty_commits_returns_200_noop() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = replication_router(runtime);
        let request = ApplyReplicationRequest {
            peer_id: follower_peer_id(),
            commits: vec![],
        };
        let response = app
            .oneshot(json_post("/replication/apply", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ApplyReplicationResponse = read_json(response).await;
        assert_eq!(decoded.applied_count, 0);
        assert!(decoded.latest_sequence.is_none());
        assert!(decoded.latest_commit_id.is_none());
        assert_eq!(decoded.peer_id, follower_peer_id());
    }

    #[tokio::test]
    async fn apply_full_export_round_trip() {
        // Leader runs in its own runtime. Ingest two signals, export
        // commit batches, then POST them to a fresh follower's
        // /replication/apply.
        let (leader_runtime, _leader_processor) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let commits = {
            let hydra = leader_runtime.hydra();
            let hydra = hydra.read().await;
            hydra
                .commit_ledger()
                .batches_in_sequence()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };

        let (follower_runtime, _follower_processor) = RuntimeBuilder::new().build();
        let app = replication_router(follower_runtime.clone());
        let request = ApplyReplicationRequest {
            peer_id: follower_peer_id(),
            commits,
        };
        let response = app
            .oneshot(json_post("/replication/apply", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ApplyReplicationResponse = read_json(response).await;
        assert_eq!(decoded.applied_count, 2);
        assert_eq!(decoded.latest_sequence, Some(2));
        assert!(decoded.latest_commit_id.is_some());

        // Follower state should now match the leader.
        let follower_hydra = follower_runtime.hydra();
        let follower_hydra = follower_hydra.read().await;
        assert_eq!(follower_hydra.commit_count(), 2);
        assert_eq!(follower_hydra.events().len(), 2);
    }

    #[tokio::test]
    async fn apply_sequence_gap_returns_400() {
        // Build a leader chain of 3 commits, then drop the middle one to
        // manufacture a gap. The router must reject with 400.
        let (leader_runtime, _leader_processor) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("a")).unwrap();
            hydra.ingest(signal("b")).unwrap();
            hydra.ingest(signal("c")).unwrap();
        }
        let mut commits = {
            let hydra = leader_runtime.hydra();
            let hydra = hydra.read().await;
            hydra
                .commit_ledger()
                .batches_in_sequence()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        commits.remove(1); // [seq=1, seq=3] — gap at 2

        let (follower_runtime, _follower_processor) = RuntimeBuilder::new().build();
        let app = replication_router(follower_runtime);
        let request = ApplyReplicationRequest {
            peer_id: follower_peer_id(),
            commits,
        };
        let response = app
            .oneshot(json_post("/replication/apply", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let err: ErrorResponse = read_json(response).await;
        assert!(err.error.contains("sequence"), "got {}", err.error);
    }

    // === V2 patch 4B — snapshot bootstrap routes ===

    #[tokio::test]
    async fn replication_latest_snapshot_returns_none_when_empty() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/snapshot/latest"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationSnapshotManifestResponse = read_json(response).await;
        assert!(decoded.manifest.is_none());
    }

    #[tokio::test]
    async fn replication_latest_snapshot_returns_manifest_after_snapshot() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let snapshot_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("seed")).unwrap();
            let manifest = hydra
                .snapshot(ActorId::from_str("actor_test_snapshot"))
                .unwrap();
            snapshot_id = manifest.id.clone();
        }
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/snapshot/latest"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationSnapshotManifestResponse = read_json(response).await;
        let manifest = decoded.manifest.expect("manifest must be Some");
        assert_eq!(manifest.id, snapshot_id);
    }

    #[tokio::test]
    async fn replication_snapshot_body_returns_body() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let snapshot_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("seed")).unwrap();
            let manifest = hydra
                .snapshot(ActorId::from_str("actor_test_snapshot"))
                .unwrap();
            snapshot_id = manifest.id.clone();
        }
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/replication/snapshot/{snapshot_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationSnapshotBodyResponse = read_json(response).await;
        assert_eq!(decoded.body.manifest.id, snapshot_id);
        // Seed signal lives in the body events.
        assert!(!decoded.body.events.is_empty());
    }

    #[tokio::test]
    async fn replication_snapshot_body_missing_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/snapshot/snap_does_not_exist"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // === V2 polish — GET /replication/peers/:peer_id/lag ===

    #[tokio::test]
    async fn replication_peer_lag_returns_null_when_absent() {
        // No puller has run yet, no peer has been observed. The
        // route still returns 200 with `lag: null` rather than 404.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/peers/replica_never_seen/lag"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationLagResponse = read_json(response).await;
        assert_eq!(decoded.peer_id.as_str(), "replica_never_seen");
        assert!(decoded.lag.is_none());
    }

    #[tokio::test]
    async fn replication_peer_lag_returns_recorded_lag() {
        // Stamp a lag observation directly into Hydra (simulates
        // what the puller does after each pull). HTTP route reads
        // it back.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let peer = ReplicaId::from_str("replica_observed");
        let lag = ReplicationLag::observe(100, 75, chrono::Utc::now());
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.record_replication_heartbeat(peer.clone(), lag.clone());
        }
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get(&format!(
                "/replication/peers/{peer}/lag"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationLagResponse = read_json(response).await;
        assert_eq!(decoded.peer_id, peer);
        let returned = decoded.lag.expect("lag must be Some after record");
        assert_eq!(returned.leader_sequence, 100);
        assert_eq!(returned.follower_sequence, 75);
        assert_eq!(returned.lag_commits, 25);
    }
}
