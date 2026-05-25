use crate::http::pagination::normalized_limit;
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hydra_core::{CascadeId, Event, EventId};
use serde::{Deserialize, Serialize};

/// Shared HTTP state for the event audit routes.
#[derive(Clone)]
pub struct EventsHttpState {
    pub runtime: RuntimeHandle,
}

impl EventsHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the event audit HTTP router.
///
/// Routes:
/// - GET /events/cascade/:cascade_id  — every event sharing this cascade id
///                                       (registered first so "cascade" is
///                                       not captured as an event id).
/// - GET /events                       — paginated list of event summaries.
/// - GET /events/:event_id             — full Event body.
pub fn events_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/events/cascade/:cascade_id", get(events_for_cascade))
        .route("/events", get(list_events))
        .route("/events/:event_id", get(get_event))
        .with_state(EventsHttpState::new(runtime))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListEventsQuery {
    pub after: Option<String>,
    pub limit: Option<usize>,
}

/// Lightweight event metadata for list views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSummary {
    pub id: EventId,
    pub kind: String,
    pub cascade_id: CascadeId,
    pub cascade_depth: u32,
    pub cascade_breadth_index: u32,
    pub caused_by: Vec<EventId>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl From<&Event> for EventSummary {
    fn from(event: &Event) -> Self {
        Self {
            id: event.id.clone(),
            kind: event.kind.kind_name().to_string(),
            cascade_id: event.cascade_id.clone(),
            cascade_depth: event.cascade_depth,
            cascade_breadth_index: event.cascade_breadth_index,
            caused_by: event.caused_by.clone(),
            timestamp: event.timestamp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventListResponse {
    pub events: Vec<EventSummary>,
    pub next_cursor: Option<EventId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDetailResponse {
    pub event: Event,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CascadeEventsResponse {
    pub cascade_id: CascadeId,
    pub events: Vec<Event>,
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

async fn list_events(
    State(state): State<EventsHttpState>,
    Query(query): Query<ListEventsQuery>,
) -> Response {
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let events = hydra.events();

    let mut start_index = 0;
    if let Some(after) = query.after.as_deref() {
        let after_id = EventId::from_str(after);
        match events.iter().position(|event| event.id == after_id) {
            Some(index) => start_index = index + 1,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!("unknown event cursor: {after}"),
                );
            }
        }
    }

    let limit = normalized_limit(query.limit);
    let response_events: Vec<EventSummary> = events
        .iter()
        .skip(start_index)
        .take(limit)
        .map(|event| EventSummary::from(*event))
        .collect();
    let next_cursor = if start_index + response_events.len() < events.len() {
        response_events.last().map(|event| event.id.clone())
    } else {
        None
    };
    Json(EventListResponse {
        events: response_events,
        next_cursor,
    })
    .into_response()
}

async fn get_event(
    State(state): State<EventsHttpState>,
    Path(event_id): Path<String>,
) -> Response {
    let event_id = EventId::from_str(&event_id);
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    match hydra.event(&event_id) {
        Some(event) => Json(EventDetailResponse {
            event: event.clone(),
        })
        .into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("event not found: {event_id}"),
        ),
    }
}

async fn events_for_cascade(
    State(state): State<EventsHttpState>,
    Path(cascade_id): Path<String>,
) -> Response {
    let cascade_id = CascadeId::from_str(&cascade_id);
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let events: Vec<Event> = hydra
        .events_for_cascade(&cascade_id)
        .into_iter()
        .cloned()
        .collect();
    if events.is_empty() {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("cascade not found: {cascade_id}"),
        );
    }
    Json(CascadeEventsResponse { cascade_id, events }).into_response()
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
            source: NodeId::from_str("test.events"),
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
    async fn events_list_is_empty_initially() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = events_router(runtime);
        let response = app.oneshot(empty_get("/events")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: EventListResponse = read_json(response).await;
        assert_eq!(decoded.events.len(), 0);
        assert_eq!(decoded.next_cursor, None);
    }

    #[tokio::test]
    async fn events_list_shows_ingested_event() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
        }
        let app = events_router(runtime);
        let response = app.oneshot(empty_get("/events")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: EventListResponse = read_json(response).await;
        assert_eq!(decoded.events.len(), 1);
        assert_eq!(decoded.events[0].kind, "signal");
    }

    #[tokio::test]
    async fn events_list_supports_after_cursor() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let first_event_id = {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let first = hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
            first.events[0].id.clone()
        };
        let app = events_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/events?after={first_event_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: EventListResponse = read_json(response).await;
        assert_eq!(decoded.events.len(), 1);
        assert_eq!(decoded.events[0].kind, "signal");
    }

    #[tokio::test]
    async fn unknown_event_cursor_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = events_router(runtime);
        let response = app
            .oneshot(empty_get("/events?after=evt_missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn event_detail_returns_event() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let event_id = {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra.ingest(signal("one")).unwrap();
            result.events[0].id.clone()
        };
        let app = events_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/events/{event_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: EventDetailResponse = read_json(response).await;
        assert_eq!(decoded.event.id, event_id);
        assert_eq!(decoded.event.kind.kind_name(), "signal");
    }

    #[tokio::test]
    async fn missing_event_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = events_router(runtime);
        let response = app
            .oneshot(empty_get("/events/evt_missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn events_for_cascade_returns_all_events_in_cascade() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let cascade_id = {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra.ingest(signal("one")).unwrap();
            result.events[0].cascade_id.clone()
        };
        let app = events_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/events/cascade/{cascade_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: CascadeEventsResponse = read_json(response).await;
        assert_eq!(decoded.cascade_id, cascade_id);
        assert_eq!(decoded.events.len(), 1);
    }

    #[tokio::test]
    async fn unknown_cascade_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = events_router(runtime);
        let response = app
            .oneshot(empty_get("/events/cascade/cas_missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
