use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hydra_core::{ActorId, SnapshotBody, SnapshotId, SnapshotManifest};
use serde::{Deserialize, Serialize};

/// Shared HTTP state for the snapshot routes.
#[derive(Clone)]
pub struct SnapshotsHttpState {
    pub runtime: RuntimeHandle,
}

impl SnapshotsHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the snapshot HTTP router.
///
/// Routes:
/// - POST /snapshots                       — take a new snapshot
/// - GET  /snapshots                       — list manifests + latest
/// - GET  /snapshots/:snapshot_id          — full snapshot body
/// - POST /snapshots/:snapshot_id/restore  — restore from a snapshot
///
/// **Security note**: `/snapshots/:id/restore` is destructive to non-
/// snapshotted state. Production deployments must gate this route
/// behind authentication. Auth middleware is a future patch — for now
/// callers should not expose this router on a public network unless
/// they fully trust their clients.
pub fn snapshots_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/snapshots", post(create_snapshot).get(list_snapshots))
        .route("/snapshots/:snapshot_id", get(get_snapshot))
        .route("/snapshots/:snapshot_id/restore", post(restore_snapshot))
        .with_state(SnapshotsHttpState::new(runtime))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSnapshotRequest {
    pub created_by: ActorId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreSnapshotRequest {
    pub restored_by: ActorId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifestResponse {
    pub manifest: SnapshotManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotsListResponse {
    pub snapshots: Vec<SnapshotManifest>,
    pub latest: Option<SnapshotManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDetailResponse {
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

async fn create_snapshot(
    State(state): State<SnapshotsHttpState>,
    Json(request): Json<CreateSnapshotRequest>,
) -> Response {
    let hydra_arc = state.runtime.hydra();
    let mut hydra = hydra_arc.write().await;
    match hydra.snapshot(request.created_by) {
        Ok(manifest) => (
            StatusCode::CREATED,
            Json(SnapshotManifestResponse { manifest }),
        )
            .into_response(),
        Err(error) => error_response(
            StatusCode::BAD_REQUEST,
            format!("failed to create snapshot: {error}"),
        ),
    }
}

async fn list_snapshots(State(state): State<SnapshotsHttpState>) -> Response {
    let hydra_arc = state.runtime.hydra();
    let hydra = hydra_arc.read().await;
    let snapshots = hydra
        .snapshot_manifests()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let latest = hydra.latest_snapshot_manifest().cloned();
    Json(SnapshotsListResponse { snapshots, latest }).into_response()
}

async fn get_snapshot(
    State(state): State<SnapshotsHttpState>,
    Path(snapshot_id): Path<String>,
) -> Response {
    let snapshot_id = SnapshotId::from_str(&snapshot_id);
    let hydra_arc = state.runtime.hydra();
    let hydra = hydra_arc.read().await;
    match hydra.snapshot_body(&snapshot_id) {
        Some(body) => Json(SnapshotDetailResponse { body: body.clone() }).into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("snapshot not found: {snapshot_id}"),
        ),
    }
}

async fn restore_snapshot(
    State(state): State<SnapshotsHttpState>,
    Path(snapshot_id): Path<String>,
    Json(request): Json<RestoreSnapshotRequest>,
) -> Response {
    let snapshot_id = SnapshotId::from_str(&snapshot_id);
    let hydra_arc = state.runtime.hydra();
    let mut hydra = hydra_arc.write().await;
    match hydra.restore_from_snapshot(&snapshot_id, request.restored_by) {
        Ok(manifest) => Json(SnapshotManifestResponse { manifest }).into_response(),
        Err(error) => error_response(
            StatusCode::BAD_REQUEST,
            format!("failed to restore snapshot: {error}"),
        ),
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

    fn actor() -> ActorId {
        ActorId::from_str("actor_http_snapshot")
    }

    fn signal(name: &str) -> EventKind {
        EventKind::Signal {
            source: NodeId::from_str("test.snapshots"),
            name: name.to_string(),
            payload: HashMap::new(),
        }
    }

    fn request_json<T: Serialize>(method: Method, uri: &str, body: &T) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
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
    async fn post_snapshot_creates_manifest() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra_arc = runtime.hydra();
            let mut hydra = hydra_arc.write().await;
            hydra.ingest(signal("before")).unwrap();
        }
        let app = snapshots_router(runtime.clone());
        let response = app
            .oneshot(request_json(
                Method::POST,
                "/snapshots",
                &CreateSnapshotRequest {
                    created_by: actor(),
                },
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let decoded: SnapshotManifestResponse = read_json(response).await;
        assert_eq!(decoded.manifest.total_events, 1);
        assert_eq!(decoded.manifest.total_commits, 1);

        let hydra_arc = runtime.hydra();
        let hydra = hydra_arc.read().await;
        assert!(hydra.snapshot_body(&decoded.manifest.id).is_some());
    }

    #[tokio::test]
    async fn get_snapshots_lists_created_snapshot() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = snapshots_router(runtime.clone());
        let create_response = app
            .clone()
            .oneshot(request_json(
                Method::POST,
                "/snapshots",
                &CreateSnapshotRequest {
                    created_by: actor(),
                },
            ))
            .await
            .unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);

        let response = app.oneshot(empty_get("/snapshots")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: SnapshotsListResponse = read_json(response).await;
        assert_eq!(decoded.snapshots.len(), 1);
        assert!(decoded.latest.is_some());
    }

    #[tokio::test]
    async fn get_snapshot_returns_full_body() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = snapshots_router(runtime);
        let create_response = app
            .clone()
            .oneshot(request_json(
                Method::POST,
                "/snapshots",
                &CreateSnapshotRequest {
                    created_by: actor(),
                },
            ))
            .await
            .unwrap();
        let created: SnapshotManifestResponse = read_json(create_response).await;

        let response = app
            .oneshot(empty_get(&format!("/snapshots/{}", created.manifest.id)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: SnapshotDetailResponse = read_json(response).await;
        assert_eq!(decoded.body.manifest.id, created.manifest.id);
    }

    #[tokio::test]
    async fn missing_snapshot_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = snapshots_router(runtime);
        let response = app
            .oneshot(empty_get("/snapshots/snap_missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn post_restore_snapshot_restores_state() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra_arc = runtime.hydra();
            let mut hydra = hydra_arc.write().await;
            hydra.ingest(signal("before")).unwrap();
        }
        let app = snapshots_router(runtime.clone());

        let create_response = app
            .clone()
            .oneshot(request_json(
                Method::POST,
                "/snapshots",
                &CreateSnapshotRequest {
                    created_by: actor(),
                },
            ))
            .await
            .unwrap();
        let created: SnapshotManifestResponse = read_json(create_response).await;

        {
            let hydra_arc = runtime.hydra();
            let mut hydra = hydra_arc.write().await;
            hydra.ingest(signal("after")).unwrap();
        }

        let response = app
            .oneshot(request_json(
                Method::POST,
                &format!("/snapshots/{}/restore", created.manifest.id),
                &RestoreSnapshotRequest {
                    restored_by: actor(),
                },
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let restored: SnapshotManifestResponse = read_json(response).await;
        assert_eq!(restored.manifest.id, created.manifest.id);

        // After restore: event log has the "before" signal (replayed from
        // the snapshot body) and a SnapshotRestored audit event. The
        // SnapshotTaken event was committed at sequence N+1 (after the
        // snapshot body's captured sequence), so it is NOT in the body
        // and not in the restored log. The post-snapshot "after" signal
        // is also gone.
        let hydra_arc = runtime.hydra();
        let hydra = hydra_arc.read().await;
        let names = hydra
            .events()
            .into_iter()
            .map(|event| event.kind.kind_name().to_string())
            .collect::<Vec<_>>();
        assert!(names.contains(&"signal".to_string()));
        assert!(names.contains(&"snapshot_restored".to_string()));
        assert!(!names.iter().any(|name| name == "snapshot_taken"));
        assert!(!hydra.events().iter().any(|event| matches!(
            &event.kind,
            EventKind::Signal { name, .. } if name == "after"
        )));
    }
}
