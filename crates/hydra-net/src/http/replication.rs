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
//! - `GET /replication/status`             — head + role + peers
//! - `GET /replication/commits`            — paged commit export
//! - `GET /replication/peers`              — all registered peers
//! - `GET /replication/peers/:peer_id`     — single peer, 404 on miss
//!
//! Auth / tenant policy:
//!
//! - Replication is **cluster control plane** — `X-Hydra-Tenant` is
//!   NOT required on any of these routes.
//! - Scope gating lives in `hydra-api::auth::required_scopes_for`:
//!   `GET /replication/*` → `read:replication`,
//!   `POST /replication/*` → `admin:replication` (pre-wired for 3B).
//!
//! Role is hardcoded `ReplicationRole::Leader` in this patch. A
//! runtime "what role am I" config (loaded at startup or set via
//! admin route) is a follow-up.

use crate::http::pagination::normalized_limit;
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hydra_core::{
    CommitBatch, CommitId, ReplicaId, ReplicationPeer, ReplicationRole,
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
}
