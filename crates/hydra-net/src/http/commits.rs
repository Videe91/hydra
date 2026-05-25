use crate::http::pagination::normalized_limit;
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hydra_core::{CommitBatch, CommitHash, CommitId, CommitRecord, IdempotencyKey};
use serde::{Deserialize, Serialize};

/// Shared HTTP state for the commit audit routes.
#[derive(Clone)]
pub struct CommitsHttpState {
    pub runtime: RuntimeHandle,
}

impl CommitsHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the commit audit HTTP router.
///
/// Routes:
/// - GET /commits/verify       — chain integrity check (must come before
///                                the `:commit_id` route so "verify" isn't
///                                captured as an id).
/// - GET /commits              — paginated list of commit summaries.
/// - GET /commits/:commit_id   — full commit batch (events included).
pub fn commits_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/commits/verify", get(verify_commits))
        .route("/commits", get(list_commits))
        .route("/commits/:commit_id", get(get_commit))
        .with_state(CommitsHttpState::new(runtime))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListCommitsQuery {
    pub after: Option<String>,
    pub limit: Option<usize>,
}

/// Lightweight commit metadata for list views.
///
/// `commit_hash` and `committed_at` are non-Option because every recorded
/// commit in the in-memory ledger has both. `previous_hash` is None only
/// for the chain genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitSummary {
    pub id: CommitId,
    pub sequence: u64,
    pub previous_hash: Option<CommitHash>,
    pub commit_hash: CommitHash,
    pub event_count: usize,
    pub idempotency_key: Option<IdempotencyKey>,
    pub committed_at: chrono::DateTime<chrono::Utc>,
}

impl From<&CommitRecord> for CommitSummary {
    fn from(record: &CommitRecord) -> Self {
        Self {
            id: record.id.clone(),
            sequence: record.sequence,
            previous_hash: record.previous_hash.clone(),
            commit_hash: record.commit_hash.clone(),
            event_count: record.event_count,
            idempotency_key: record.idempotency_key.clone(),
            committed_at: record.committed_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitListResponse {
    pub commits: Vec<CommitSummary>,
    pub next_cursor: Option<CommitId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitDetailResponse {
    pub commit: CommitBatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyCommitsResponse {
    pub valid: bool,
    pub head_commit_id: Option<CommitId>,
    pub total_commits: usize,
    pub message: Option<String>,
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

async fn list_commits(
    State(state): State<CommitsHttpState>,
    Query(query): Query<ListCommitsQuery>,
) -> Response {
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let records = hydra.commit_records();

    let mut start_index = 0;
    if let Some(after) = query.after.as_deref() {
        let after_id = CommitId::from_str(after);
        match records.iter().position(|record| record.id == after_id) {
            Some(index) => start_index = index + 1,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!("unknown commit cursor: {after}"),
                );
            }
        }
    }

    let limit = normalized_limit(query.limit);
    let commits: Vec<CommitSummary> = records
        .iter()
        .skip(start_index)
        .take(limit)
        .map(CommitSummary::from)
        .collect();
    let next_cursor = if start_index + commits.len() < records.len() {
        commits.last().map(|summary| summary.id.clone())
    } else {
        None
    };
    Json(CommitListResponse {
        commits,
        next_cursor,
    })
    .into_response()
}

async fn get_commit(
    State(state): State<CommitsHttpState>,
    Path(commit_id): Path<String>,
) -> Response {
    let commit_id = CommitId::from_str(&commit_id);
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    match hydra.commit_batch(&commit_id) {
        Some(batch) => Json(CommitDetailResponse {
            commit: batch.clone(),
        })
        .into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("commit not found: {commit_id}"),
        ),
    }
}

async fn verify_commits(State(state): State<CommitsHttpState>) -> Response {
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let total_commits = hydra.commit_count();
    let head_commit_id = hydra.latest_commit().map(|record| record.id.clone());
    match hydra.verify_commit_chain() {
        Ok(()) => Json(VerifyCommitsResponse {
            valid: true,
            head_commit_id,
            total_commits,
            message: None,
        })
        .into_response(),
        Err(error) => Json(VerifyCommitsResponse {
            valid: false,
            head_commit_id,
            total_commits,
            message: Some(error.to_string()),
        })
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use hydra_core::{EventKind, NodeId};
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn signal(name: &str) -> EventKind {
        EventKind::Signal {
            source: NodeId::from_str("test.commits"),
            name: name.to_string(),
            payload: HashMap::new(),
        }
    }

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

    #[tokio::test]
    async fn commits_list_is_empty_initially() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = commits_router(runtime);
        let response = app.oneshot(empty_get("/commits")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: CommitListResponse = read_json(response).await;
        assert_eq!(decoded.commits.len(), 0);
        assert_eq!(decoded.next_cursor, None);
    }

    #[tokio::test]
    async fn commits_list_shows_ingested_commit() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
        }
        let app = commits_router(runtime);
        let response = app.oneshot(empty_get("/commits")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: CommitListResponse = read_json(response).await;
        assert_eq!(decoded.commits.len(), 1);
        // CommitHash is a tuple struct around a String — assert it's non-empty.
        assert!(!decoded.commits[0].commit_hash.0.is_empty());
        assert_eq!(decoded.commits[0].event_count, 1);
        // Chain genesis: no previous_hash.
        assert_eq!(decoded.commits[0].previous_hash, None);
    }

    #[tokio::test]
    async fn commits_list_supports_after_cursor() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let first_commit_id = {
            let hydra = runtime.hydra();
            let hydra = hydra.read().await;
            hydra.commit_records()[0].id.clone()
        };
        let app = commits_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/commits?after={first_commit_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: CommitListResponse = read_json(response).await;
        assert_eq!(decoded.commits.len(), 1);
        assert_eq!(decoded.commits[0].sequence, 2);
    }

    #[tokio::test]
    async fn commits_list_unknown_cursor_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = commits_router(runtime);
        let response = app
            .oneshot(empty_get("/commits?after=commit_does_not_exist"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn commit_detail_returns_full_batch() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let commit_id = {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.latest_commit().unwrap().id.clone()
        };
        let app = commits_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/commits/{commit_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: CommitDetailResponse = read_json(response).await;
        assert_eq!(decoded.commit.id, commit_id);
        assert_eq!(decoded.commit.events.len(), 1);
        assert!(decoded.commit.commit_hash.is_some());
    }

    #[tokio::test]
    async fn missing_commit_detail_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = commits_router(runtime);
        let response = app
            .oneshot(empty_get("/commits/commit_missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn verify_commits_returns_valid_for_clean_chain() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let app = commits_router(runtime);
        let response = app.oneshot(empty_get("/commits/verify")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: VerifyCommitsResponse = read_json(response).await;
        assert!(decoded.valid);
        assert_eq!(decoded.total_commits, 2);
        assert!(decoded.head_commit_id.is_some());
        assert_eq!(decoded.message, None);
    }
}
