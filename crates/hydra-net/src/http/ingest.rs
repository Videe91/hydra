use crate::runtime::RuntimeHandle;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use hydra_core::{CascadeId, EventId, EventKind, IdempotencyKey};
use serde::{Deserialize, Serialize};

/// Shared HTTP state for ingest routes.
#[derive(Clone)]
pub struct IngestHttpState {
    pub runtime: RuntimeHandle,
}

impl IngestHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the ingest HTTP router.
///
/// Routes:
/// - POST /ingest — accepts an [`EventKind`] in JSON; optional
///   `Idempotency-Key` HTTP header routes through
///   `Hydra::ingest_with_idempotency_key`, otherwise plain
///   `Hydra::ingest`. Strict SchemaGate rejections return 400.
pub fn ingest_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/ingest", post(ingest_event))
        .with_state(IngestHttpState::new(runtime))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestRequest {
    pub event_kind: EventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResponse {
    pub cascade_id: Option<CascadeId>,
    pub event_ids: Vec<EventId>,
    pub event_count: usize,
    /// `true` iff the request carried an `Idempotency-Key` AND the engine's
    /// commit ledger short-circuited because the key was already committed.
    /// `false` for fresh ingests (whether or not a key was supplied).
    pub idempotent_hit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

async fn ingest_event(
    State(state): State<IngestHttpState>,
    headers: HeaderMap,
    Json(request): Json<IngestRequest>,
) -> Response {
    let idempotency_key = headers
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(IdempotencyKey::new);
    let had_key = idempotency_key.is_some();

    let hydra_arc = state.runtime.hydra();
    let mut hydra = hydra_arc.write().await;
    let commit_count_before = hydra.commit_count();
    let result = match idempotency_key {
        Some(key) => hydra.ingest_with_idempotency_key(request.event_kind, key),
        None => hydra.ingest(request.event_kind),
    };
    match result {
        Ok(cascade) => {
            let commit_count_after = hydra.commit_count();
            let idempotent_hit = had_key && commit_count_after == commit_count_before;
            let cascade_id = cascade.events.first().map(|event| event.cascade_id.clone());
            let event_ids = cascade
                .events
                .iter()
                .map(|event| event.id.clone())
                .collect::<Vec<_>>();
            Json(IngestResponse {
                cascade_id,
                event_count: event_ids.len(),
                event_ids,
                idempotent_hit,
            })
            .into_response()
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: error.to_string(),
            }),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use hydra_core::NodeId;
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn request_json<T: Serialize>(uri: &str, body: &T) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    fn request_json_with_key<T: Serialize>(
        uri: &str,
        key: &str,
        body: &T,
    ) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json")
            .header("Idempotency-Key", key)
            .body(Body::from(serde_json::to_vec(body).unwrap()))
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
            source: NodeId::from_str("test.http"),
            name: name.to_string(),
            payload: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn post_ingest_without_key_commits_every_time() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = ingest_router(runtime.clone());

        let request = IngestRequest {
            event_kind: signal("first"),
        };
        let response = app
            .clone()
            .oneshot(request_json("/ingest", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let first: IngestResponse = read_json(response).await;
        assert!(!first.idempotent_hit);
        assert_eq!(first.event_count, 1);
        assert_eq!(runtime.hydra().read().await.commit_count(), 1);

        let response = app
            .oneshot(request_json("/ingest", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let second: IngestResponse = read_json(response).await;
        assert!(!second.idempotent_hit);
        assert_eq!(second.event_count, 1);
        assert_eq!(runtime.hydra().read().await.commit_count(), 2);
        assert_ne!(first.event_ids, second.event_ids);
    }

    #[tokio::test]
    async fn post_ingest_with_same_idempotency_key_returns_original_events() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = ingest_router(runtime.clone());

        let first_request = IngestRequest {
            event_kind: signal("first"),
        };
        let response = app
            .clone()
            .oneshot(request_json_with_key(
                "/ingest",
                "request-123",
                &first_request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let first: IngestResponse = read_json(response).await;
        assert!(!first.idempotent_hit);
        assert_eq!(runtime.hydra().read().await.commit_count(), 1);

        // Different payload, same key: the original commit short-circuits
        // any new work and the response carries the original event ids.
        let second_request = IngestRequest {
            event_kind: signal("second-should-not-run"),
        };
        let response = app
            .oneshot(request_json_with_key(
                "/ingest",
                "request-123",
                &second_request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let second: IngestResponse = read_json(response).await;
        assert!(second.idempotent_hit);
        assert_eq!(runtime.hydra().read().await.commit_count(), 1);
        assert_eq!(second.event_ids, first.event_ids);
    }

    #[tokio::test]
    async fn post_ingest_with_blank_idempotency_key_falls_through_to_plain_ingest() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = ingest_router(runtime.clone());

        let request = IngestRequest {
            event_kind: signal("blank-key"),
        };
        // Whitespace-only key should be treated as no key (header guard).
        let response = app
            .oneshot(request_json_with_key("/ingest", "   ", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: IngestResponse = read_json(response).await;
        assert!(!decoded.idempotent_hit);
        assert_eq!(runtime.hydra().read().await.commit_count(), 1);
    }
}
