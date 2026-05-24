//! # HTTP query router — Query API v0, patch 1
//!
//! Thin GET-only HTTP surface over [`crate::QueryService`].
//!
//! This is the first slice of the Query API: enough endpoints to let an
//! end user inspect the materialized graph state, the claims it has formed,
//! and the actions it has proposed/approved/executed — without dropping
//! down to commit-log/event-log routes (which are auditing surfaces).
//!
//! Routes (registered specific-before-generic so axum picks the right
//! handler for paths like `/query/claims/status/Verified`):
//!
//! - `GET /query/nodes/:node_id/neighbors`         — undirected neighbors of a node
//! - `GET /query/nodes/:node_id`                   — single node lookup
//! - `GET /query/nodes`                            — list all alive nodes
//! - `GET /query/claims/status/:status`            — claims filtered by lifecycle status
//! - `GET /query/claims/:claim_id`                 — single claim lookup
//! - `GET /query/claims`                           — list all claims
//! - `GET /query/actions/status/:status`           — actions filtered by lifecycle status
//! - `GET /query/actions/:action_id/outcomes`      — every outcome recorded for an action
//! - `GET /query/actions/:action_id`               — single action lookup
//! - `GET /query/actions`                          — list all actions
//!
//! Responses are JSON. Lookups return `404` on miss; status routes return
//! `400` on an unknown status variant; list routes always return `200`.
//! Single-object responses are wrapped (`NodeResponse { node }`, …) so
//! callers can extend the shape without breaking deserialization.

use crate::query::QueryService;
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hydra_core::{
    Action, ActionId, ActionStatus, Claim, ClaimId, ClaimStatus, NodeId, Outcome,
};
use hydra_core::node::Node;
use serde::{Deserialize, Serialize};

/// Shared HTTP state for the query routes.
#[derive(Clone)]
pub struct QueryHttpState {
    pub service: QueryService,
}

impl QueryHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self {
            service: QueryService::new(runtime.hydra()),
        }
    }
}

/// Build the read-side query HTTP router.
///
/// See module docs for the full route list and the required
/// specific-before-generic registration order.
pub fn query_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/query/nodes/:node_id/neighbors", get(node_neighbors))
        .route("/query/nodes/:node_id", get(get_node))
        .route("/query/nodes", get(list_nodes))
        .route("/query/claims/status/:status", get(claims_by_status))
        .route("/query/claims/:claim_id", get(get_claim))
        .route("/query/claims", get(list_claims))
        .route("/query/actions/status/:status", get(actions_by_status))
        .route("/query/actions/:action_id/outcomes", get(outcomes_for_action))
        .route("/query/actions/:action_id", get(get_action))
        .route("/query/actions", get(list_actions))
        .with_state(QueryHttpState::new(runtime))
}

// === DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodesResponse {
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeResponse {
    pub node: Node,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsResponse {
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimResponse {
    pub claim: Claim,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionsResponse {
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResponse {
    pub action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomesResponse {
    pub outcomes: Vec<Outcome>,
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

// === Status parsers (return None on unknown variant → 400) ===

fn parse_claim_status(status: &str) -> Option<ClaimStatus> {
    match status {
        "Proposed" => Some(ClaimStatus::Proposed),
        "Supported" => Some(ClaimStatus::Supported),
        "Verified" => Some(ClaimStatus::Verified),
        "Operational" => Some(ClaimStatus::Operational),
        "Disputed" => Some(ClaimStatus::Disputed),
        "Stale" => Some(ClaimStatus::Stale),
        "Retracted" => Some(ClaimStatus::Retracted),
        "Archived" => Some(ClaimStatus::Archived),
        _ => None,
    }
}

fn parse_action_status(status: &str) -> Option<ActionStatus> {
    match status {
        "Proposed" => Some(ActionStatus::Proposed),
        "Approved" => Some(ActionStatus::Approved),
        "Rejected" => Some(ActionStatus::Rejected),
        "Executing" => Some(ActionStatus::Executing),
        "Executed" => Some(ActionStatus::Executed),
        "Failed" => Some(ActionStatus::Failed),
        "Cancelled" => Some(ActionStatus::Cancelled),
        _ => None,
    }
}

// === Node handlers ===

async fn list_nodes(State(state): State<QueryHttpState>) -> Response {
    let nodes = state.service.nodes().await;
    Json(NodesResponse { nodes }).into_response()
}

async fn get_node(
    State(state): State<QueryHttpState>,
    Path(node_id): Path<String>,
) -> Response {
    let id = NodeId::from_str(&node_id);
    match state.service.node(&id).await {
        Some(node) => Json(NodeResponse { node }).into_response(),
        None => error_response(StatusCode::NOT_FOUND, format!("node not found: {node_id}")),
    }
}

async fn node_neighbors(
    State(state): State<QueryHttpState>,
    Path(node_id): Path<String>,
) -> Response {
    let id = NodeId::from_str(&node_id);
    if state.service.node(&id).await.is_none() {
        return error_response(StatusCode::NOT_FOUND, format!("node not found: {node_id}"));
    }
    let nodes = state.service.neighbors(&id).await;
    Json(NodesResponse { nodes }).into_response()
}

// === Claim handlers ===

async fn list_claims(State(state): State<QueryHttpState>) -> Response {
    let claims = state.service.claims().await;
    Json(ClaimsResponse { claims }).into_response()
}

async fn get_claim(
    State(state): State<QueryHttpState>,
    Path(claim_id): Path<String>,
) -> Response {
    let id = ClaimId::from_str(&claim_id);
    match state.service.claim(&id).await {
        Some(claim) => Json(ClaimResponse { claim }).into_response(),
        None => error_response(StatusCode::NOT_FOUND, format!("claim not found: {claim_id}")),
    }
}

async fn claims_by_status(
    State(state): State<QueryHttpState>,
    Path(status): Path<String>,
) -> Response {
    let status_enum = match parse_claim_status(&status) {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("unknown claim status: {status}"),
            );
        }
    };
    let claims = state.service.claims_with_status(status_enum).await;
    Json(ClaimsResponse { claims }).into_response()
}

// === Action handlers ===

async fn list_actions(State(state): State<QueryHttpState>) -> Response {
    let actions = state.service.actions().await;
    Json(ActionsResponse { actions }).into_response()
}

async fn get_action(
    State(state): State<QueryHttpState>,
    Path(action_id): Path<String>,
) -> Response {
    let id = ActionId::from_str(&action_id);
    match state.service.action(&id).await {
        Some(action) => Json(ActionResponse { action }).into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("action not found: {action_id}"),
        ),
    }
}

async fn actions_by_status(
    State(state): State<QueryHttpState>,
    Path(status): Path<String>,
) -> Response {
    let status_enum = match parse_action_status(&status) {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("unknown action status: {status}"),
            );
        }
    };
    let actions = state.service.actions_with_status(status_enum).await;
    Json(ActionsResponse { actions }).into_response()
}

async fn outcomes_for_action(
    State(state): State<QueryHttpState>,
    Path(action_id): Path<String>,
) -> Response {
    let id = ActionId::from_str(&action_id);
    if state.service.action(&id).await.is_none() {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("action not found: {action_id}"),
        );
    }
    let outcomes = state.service.outcomes_for_action(&id).await;
    Json(OutcomesResponse { outcomes }).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use hydra_core::{
        Action, ActionKind, ActionStatus, ActionTarget, ActorId, CascadeId, Claim, ClaimId,
        ClaimKind, ClaimObject, ClaimStatus, ClaimSubject, Confidence, Event, EventId, EventKind,
        Evidence, EvidenceId, EvidencePayload, EvidenceSource, NodeId, TenantId, Value,
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

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_http_query_test")
    }

    fn actor() -> ActorId {
        ActorId::from_str("actor_http_query_test")
    }

    fn evidence() -> Evidence {
        let mut data = HashMap::new();
        data.insert("dataset".to_string(), Value::String("ds".to_string()));
        Evidence {
            id: EvidenceId::new(),
            tenant_id: Some(tenant()),
            source: EvidenceSource::Warehouse {
                system: "snowflake".to_string(),
                database: None,
                schema: None,
                table: None,
            },
            payload: EvidencePayload {
                kind: "freshness_check".to_string(),
                data,
            },
            reliability: Confidence::new(0.9),
            observed_at: chrono::Utc::now(),
            recorded_at: chrono::Utc::now(),
            caused_by: None,
        }
    }

    fn claim(evidence_id: EvidenceId) -> Claim {
        let now = chrono::Utc::now();
        Claim {
            id: ClaimId::new(),
            tenant_id: Some(tenant()),
            kind: ClaimKind::AnomalyFinding,
            subject: ClaimSubject::Dataset("ds".to_string()),
            predicate: "is_stale".to_string(),
            object: ClaimObject::Value(Value::Bool(true)),
            confidence: Confidence::new(0.9),
            status: ClaimStatus::Proposed,
            evidence_for: vec![evidence_id],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: actor(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn event(kind: EventKind) -> Event {
        Event {
            id: EventId::new(),
            tenant_id: Some(tenant()),
            timestamp: chrono::Utc::now(),
            kind,
            caused_by: vec![],
            cascade_id: CascadeId::new(),
            cascade_depth: 0,
            cascade_breadth_index: 0,
        }
    }

    fn action() -> Action {
        let now = chrono::Utc::now();
        Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::Backfill,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::Dataset("ds".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor(),
            approved_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        }
    }

    // === Nodes ===

    #[tokio::test]
    async fn list_nodes_returns_empty_when_no_nodes() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app.oneshot(empty_get("/query/nodes")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: NodesResponse = read_json(response).await;
        assert_eq!(decoded.nodes.len(), 0);
    }

    #[tokio::test]
    async fn list_nodes_returns_ingested_nodes() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let node_id = NodeId::new();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest(EventKind::NodeCreated {
                    node_id: node_id.clone(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
        }
        let app = query_router(runtime);
        let response = app.oneshot(empty_get("/query/nodes")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: NodesResponse = read_json(response).await;
        assert_eq!(decoded.nodes.len(), 1);
        assert_eq!(decoded.nodes[0].id(), &node_id);
    }

    #[tokio::test]
    async fn get_node_returns_node_when_present() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let node_id = NodeId::new();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest(EventKind::NodeCreated {
                    node_id: node_id.clone(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/query/nodes/{node_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: NodeResponse = read_json(response).await;
        assert_eq!(decoded.node.id(), &node_id);
        assert_eq!(decoded.node.type_id(), "ec2");
    }

    #[tokio::test]
    async fn get_node_returns_404_when_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/nodes/node_missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn node_neighbors_returns_connected_nodes() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let a = NodeId::new();
        let b = NodeId::new();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest(EventKind::NodeCreated {
                    node_id: a.clone(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
            hydra
                .ingest(EventKind::NodeCreated {
                    node_id: b.clone(),
                    type_id: "vpc".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
            hydra
                .ingest(EventKind::EdgeCreated {
                    edge_id: hydra_core::EdgeId::new(),
                    source: a.clone(),
                    target: b.clone(),
                    type_id: "in_vpc".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/query/nodes/{a}/neighbors")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: NodesResponse = read_json(response).await;
        assert_eq!(decoded.nodes.len(), 1);
        assert_eq!(decoded.nodes[0].id(), &b);
    }

    #[tokio::test]
    async fn node_neighbors_returns_404_when_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/nodes/node_missing/neighbors"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // === Claims ===

    #[tokio::test]
    async fn list_claims_returns_empty_when_no_claims() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app.oneshot(empty_get("/query/claims")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ClaimsResponse = read_json(response).await;
        assert_eq!(decoded.claims.len(), 0);
    }

    #[tokio::test]
    async fn list_and_get_claim_round_trip() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let ev = evidence();
        let cl = claim(ev.id.clone());
        let claim_id = cl.id.clone();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest_event(event(EventKind::EvidenceAdded { evidence: ev }))
                .unwrap();
            hydra
                .ingest_event(event(EventKind::ClaimProposed { claim: cl }))
                .unwrap();
        }
        let app = query_router(runtime);

        let response = app
            .clone()
            .oneshot(empty_get("/query/claims"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ClaimsResponse = read_json(response).await;
        assert_eq!(decoded.claims.len(), 1);
        assert_eq!(decoded.claims[0].id, claim_id);

        let response = app
            .oneshot(empty_get(&format!("/query/claims/{claim_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ClaimResponse = read_json(response).await;
        assert_eq!(decoded.claim.id, claim_id);
    }

    #[tokio::test]
    async fn get_claim_returns_404_when_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/claims/clm_missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn claims_by_status_filters() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let ev = evidence();
        let cl = claim(ev.id.clone());
        let claim_id = cl.id.clone();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest_event(event(EventKind::EvidenceAdded { evidence: ev }))
                .unwrap();
            hydra
                .ingest_event(event(EventKind::ClaimProposed { claim: cl }))
                .unwrap();
            hydra
                .ingest_event(event(EventKind::ClaimVerified {
                    claim_id: claim_id.clone(),
                    verified_by: actor(),
                }))
                .unwrap();
        }
        let app = query_router(runtime);
        let response = app
            .clone()
            .oneshot(empty_get("/query/claims/status/Verified"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ClaimsResponse = read_json(response).await;
        assert_eq!(decoded.claims.len(), 1);
        assert_eq!(decoded.claims[0].id, claim_id);

        let response = app
            .oneshot(empty_get("/query/claims/status/Disputed"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ClaimsResponse = read_json(response).await;
        assert_eq!(decoded.claims.len(), 0);
    }

    #[tokio::test]
    async fn claims_by_status_returns_400_on_unknown_status() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/claims/status/bogus"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // === Actions ===

    #[tokio::test]
    async fn list_and_get_action_round_trip() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let act = action();
        let action_id = act.id.clone();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(EventKind::ActionProposed { action: act }).unwrap();
        }
        let app = query_router(runtime);

        let response = app
            .clone()
            .oneshot(empty_get("/query/actions"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ActionsResponse = read_json(response).await;
        assert_eq!(decoded.actions.len(), 1);
        assert_eq!(decoded.actions[0].id, action_id);

        let response = app
            .oneshot(empty_get(&format!("/query/actions/{action_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ActionResponse = read_json(response).await;
        assert_eq!(decoded.action.id, action_id);
    }

    #[tokio::test]
    async fn get_action_returns_404_when_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/actions/act_missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn actions_by_status_filters() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let act = action();
        let action_id = act.id.clone();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            // PolicyAgent auto-approves when no policy matches.
            hydra.ingest(EventKind::ActionProposed { action: act }).unwrap();
        }
        let app = query_router(runtime);
        let response = app
            .clone()
            .oneshot(empty_get("/query/actions/status/Approved"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ActionsResponse = read_json(response).await;
        assert_eq!(decoded.actions.len(), 1);
        assert_eq!(decoded.actions[0].id, action_id);

        let response = app
            .oneshot(empty_get("/query/actions/status/Failed"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ActionsResponse = read_json(response).await;
        assert_eq!(decoded.actions.len(), 0);
    }

    #[tokio::test]
    async fn actions_by_status_returns_400_on_unknown_status() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/actions/status/bogus"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn outcomes_for_action_returns_outcomes() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let act = action();
        let action_id = act.id.clone();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(EventKind::ActionProposed { action: act }).unwrap();
            hydra
                .ingest(EventKind::ActionExecuting {
                    action_id: action_id.clone(),
                })
                .unwrap();
            // ActionExecuted triggers OutcomeAgent which emits an Unknown
            // outcome for Backfill actions.
            hydra
                .ingest(EventKind::ActionExecuted {
                    action_id: action_id.clone(),
                })
                .unwrap();
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/query/actions/{action_id}/outcomes")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: OutcomesResponse = read_json(response).await;
        assert_eq!(decoded.outcomes.len(), 1);
    }

    #[tokio::test]
    async fn outcomes_for_action_returns_404_when_action_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/actions/act_missing/outcomes"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // === Status route registration ordering ===

    #[tokio::test]
    async fn status_routes_resolve_specific_before_generic() {
        // `/query/claims/status/Proposed` must hit `claims_by_status`,
        // not `get_claim` (which would 404 because "status" is not a real
        // claim id). The router file registers status before :claim_id,
        // and the URL is 4 segments vs 3 — this test pins both behaviors
        // in the same call.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/claims/status/Proposed"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ClaimsResponse = read_json(response).await;
        assert_eq!(decoded.claims.len(), 0);
    }
}
