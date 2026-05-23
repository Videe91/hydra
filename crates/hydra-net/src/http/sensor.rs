use crate::runtime::RuntimeHandle;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use hydra_core::{
    EventKind, SensorCheckpoint, SensorCheckpointId, SensorId, SensorRunId, SourceCursor,
};
use serde::{Deserialize, Serialize};

/// Shared HTTP state for the sensor observation route.
#[derive(Clone)]
pub struct SensorHttpState {
    pub runtime: RuntimeHandle,
}

impl SensorHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the sensor HTTP router.
///
/// Routes:
/// - POST /sensor/observation — reliable external-source write. Derives
///   the idempotency key from `source_cursor.stable_key_material()`,
///   commits the business event, records a `SensorCheckpointRecorded`
///   event, and returns the resulting checkpoint. Retry with the same
///   cursor returns the original checkpoint with `idempotent_hit: true`.
pub fn sensor_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/sensor/observation", post(record_sensor_observation))
        .with_state(SensorHttpState::new(runtime))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorObservationRequest {
    pub sensor_id: SensorId,
    pub source_system: String,
    pub source_cursor: SourceCursor,
    pub event_kind: EventKind,
    pub run_id: Option<SensorRunId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorObservationResponse {
    pub checkpoint_id: SensorCheckpointId,
    pub checkpoint: SensorCheckpoint,
    /// `true` iff a checkpoint already existed for this cursor's
    /// idempotency key — the engine short-circuited and no new commits
    /// were produced.
    pub idempotent_hit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

async fn record_sensor_observation(
    State(state): State<SensorHttpState>,
    Json(request): Json<SensorObservationRequest>,
) -> Response {
    let hydra_arc = state.runtime.hydra();
    let mut hydra = hydra_arc.write().await;

    // Derive the same key Hydra::record_sensor_observation will use, so we
    // can detect whether the engine short-circuited an existing checkpoint.
    let key = hydra_core::IdempotencyKey::new(request.source_cursor.stable_key_material());
    let existing_checkpoint_id = hydra
        .checkpoint_for_idempotency_key(&key)
        .map(|checkpoint| checkpoint.id.clone());

    let result = match request.run_id {
        Some(run_id) => hydra.record_sensor_observation_for_run(
            Some(run_id),
            request.sensor_id,
            request.source_system,
            request.source_cursor,
            request.event_kind,
        ),
        None => hydra.record_sensor_observation(
            request.sensor_id,
            request.source_system,
            request.source_cursor,
            request.event_kind,
        ),
    };

    match result {
        Ok(checkpoint) => {
            let idempotent_hit = existing_checkpoint_id
                .as_ref()
                .map(|id| id == &checkpoint.id)
                .unwrap_or(false);
            Json(SensorObservationResponse {
                checkpoint_id: checkpoint.id.clone(),
                checkpoint,
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

    fn signal(name: &str) -> EventKind {
        EventKind::Signal {
            source: NodeId::from_str("test.sensor"),
            name: name.to_string(),
            payload: HashMap::new(),
        }
    }

    fn cursor(value: &str) -> SourceCursor {
        SourceCursor::DeliveryId {
            source: "stripe".to_string(),
            delivery_id: value.to_string(),
        }
    }

    fn request_json<T: Serialize>(uri: &str, body: &T) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    async fn read_json<T: for<'de> Deserialize<'de>>(response: Response) -> T {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn sensor_observation_records_checkpoint() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = sensor_router(runtime.clone());

        let sensor_id = SensorId::from_str("sensor_stripe");
        let source_cursor = cursor("evt_1");
        let request = SensorObservationRequest {
            sensor_id: sensor_id.clone(),
            source_system: "stripe".to_string(),
            source_cursor: source_cursor.clone(),
            event_kind: signal("stripe_event_observed"),
            run_id: None,
        };
        let response = app
            .oneshot(request_json("/sensor/observation", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: SensorObservationResponse = read_json(response).await;
        assert!(!decoded.idempotent_hit);
        assert_eq!(decoded.checkpoint.sensor_id, sensor_id);
        assert_eq!(decoded.checkpoint.cursor, source_cursor);

        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        assert!(hydra.sensor_checkpoint(&decoded.checkpoint_id).is_some());
        assert!(hydra
            .checkpoint_for_idempotency_key(&decoded.checkpoint.idempotency_key)
            .is_some());
        // One commit for the business event, one for SensorCheckpointRecorded.
        assert_eq!(hydra.commit_count(), 2);
    }

    #[tokio::test]
    async fn duplicate_sensor_observation_returns_same_checkpoint() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = sensor_router(runtime.clone());

        let sensor_id = SensorId::from_str("sensor_stripe");
        let source_cursor = cursor("evt_duplicate");

        let first_request = SensorObservationRequest {
            sensor_id: sensor_id.clone(),
            source_system: "stripe".to_string(),
            source_cursor: source_cursor.clone(),
            event_kind: signal("first"),
            run_id: None,
        };
        let response = app
            .clone()
            .oneshot(request_json("/sensor/observation", &first_request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let first: SensorObservationResponse = read_json(response).await;
        assert!(!first.idempotent_hit);

        // Different event kind, same cursor: the engine short-circuits and
        // returns the original checkpoint.
        let duplicate_request = SensorObservationRequest {
            sensor_id,
            source_system: "stripe".to_string(),
            source_cursor,
            event_kind: signal("second_should_not_run"),
            run_id: None,
        };
        let response = app
            .oneshot(request_json("/sensor/observation", &duplicate_request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let second: SensorObservationResponse = read_json(response).await;
        assert!(second.idempotent_hit);
        assert_eq!(second.checkpoint_id, first.checkpoint_id);
        assert_eq!(second.checkpoint.event_id, first.checkpoint.event_id);

        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        // Still only the original two commits.
        assert_eq!(hydra.commit_count(), 2);
    }

    #[tokio::test]
    async fn different_sensor_cursors_create_distinct_checkpoints() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = sensor_router(runtime.clone());

        let first_request = SensorObservationRequest {
            sensor_id: SensorId::from_str("sensor_stripe"),
            source_system: "stripe".to_string(),
            source_cursor: cursor("evt_1"),
            event_kind: signal("first"),
            run_id: None,
        };
        let second_request = SensorObservationRequest {
            sensor_id: SensorId::from_str("sensor_stripe"),
            source_system: "stripe".to_string(),
            source_cursor: cursor("evt_2"),
            event_kind: signal("second"),
            run_id: None,
        };

        let first_response = app
            .clone()
            .oneshot(request_json("/sensor/observation", &first_request))
            .await
            .unwrap();
        let first: SensorObservationResponse = read_json(first_response).await;

        let second_response = app
            .oneshot(request_json("/sensor/observation", &second_request))
            .await
            .unwrap();
        let second: SensorObservationResponse = read_json(second_response).await;

        assert_ne!(first.checkpoint_id, second.checkpoint_id);
        assert!(!second.idempotent_hit);

        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        // Two observations × (business commit + checkpoint commit)
        assert_eq!(hydra.commit_count(), 4);
    }
}
