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
//! - `GET /query/nodes/:node_id/outgoing-edges`    — edges with this node as source
//! - `GET /query/nodes/:node_id/incoming-edges`    — edges with this node as target
//! - `GET /query/nodes/:node_id/neighbors`         — undirected neighbors of a node
//! - `GET /query/nodes/:node_id`                   — single node lookup
//! - `GET /query/nodes`                            — list all alive nodes
//! - `GET /query/edges/:edge_id`                   — single edge lookup
//! - `GET /query/edges`                            — list all alive edges
//! - `GET /query/evidence/:evidence_id`            — single evidence lookup
//! - `GET /query/evidence`                         — list all evidence
//! - `GET /query/claims/status/:status`            — claims filtered by lifecycle status
//! - `GET /query/claims/:claim_id`                 — single claim lookup
//! - `GET /query/claims`                           — list all claims
//! - `GET /query/actions/status/:status`           — actions filtered by lifecycle status
//! - `GET /query/actions/:action_id/outcomes`      — every outcome recorded for an action
//! - `GET /query/actions/:action_id`               — single action lookup
//! - `GET /query/actions`                          — list all actions
//! - `GET /query/sensors/:sensor_id/sources/:source/latest-checkpoint`
//!                                                 — latest checkpoint for (sensor, source)
//! - `GET /query/sensors/:sensor_id/checkpoints`   — every recorded checkpoint for a sensor
//! - `GET /query/sensors/:sensor_id/runs`          — every run recorded for a sensor
//!
//! Responses are JSON. Lookups return `404` on miss; status routes return
//! `400` on an unknown status variant; list routes always return `200`.
//! Single-object responses are wrapped (`NodeResponse { node }`, …) so
//! callers can extend the shape without breaking deserialization.

use crate::http::pagination::{paginate_by_cursor, PaginationQuery};
use crate::query::QueryService;
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hydra_core::edge::Edge;
use hydra_core::graph::TraversalDirection;
use hydra_core::node::Node;
use hydra_core::{
    Action, ActionId, ActionStatus, Claim, ClaimId, ClaimKind, ClaimStatus, ClaimSubject, EdgeId,
    Event, EventId, Evidence, EvidenceId, NodeId, Outcome, OutcomeId, SensorCheckpoint, SensorId,
};
use hydra_engine::counterfactual::{GraphDiff, ImpactScore};
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
        // Node sub-paths first — these are 4-segment URIs but axum still
        // benefits from explicit-before-generic ordering for clarity.
        .route(
            "/query/nodes/:node_id/outgoing-edges",
            get(node_outgoing_edges),
        )
        .route(
            "/query/nodes/:node_id/incoming-edges",
            get(node_incoming_edges),
        )
        .route("/query/nodes/:node_id/neighbors", get(node_neighbors))
        .route("/query/nodes/:node_id/bfs", get(node_bfs))
        .route("/query/nodes/:node_id", get(get_node))
        .route("/query/nodes", get(list_nodes))
        .route("/query/edges/:edge_id", get(get_edge))
        .route("/query/edges", get(list_edges))
        .route("/query/evidence/:evidence_id/claims", get(claims_using_evidence))
        .route("/query/evidence/:evidence_id", get(get_evidence))
        .route("/query/evidence", get(list_evidence))
        .route("/query/claims-for-subject", get(claims_for_subject))
        .route("/query/claims/kind/:kind", get(claims_by_kind))
        .route("/query/claims/status/:status", get(claims_by_status))
        .route("/query/claims/:claim_id", get(get_claim))
        .route("/query/claims", get(list_claims))
        .route("/query/actions/status/:status", get(actions_by_status))
        .route("/query/actions/:action_id/outcomes", get(outcomes_for_action))
        .route("/query/actions/:action_id", get(get_action))
        .route("/query/actions", get(list_actions))
        .route("/query/outcomes/:outcome_id", get(get_outcome))
        .route("/query/events/:event_id/causal-chain", get(event_causal_chain))
        .route("/query/events/:event_id/root-cause", get(event_root_cause))
        .route("/query/events/:event_id/counterfactual", get(event_counterfactual))
        .route("/query/events/:event_id/impact-score", get(event_impact_score))
        .route("/query/stats", get(query_stats))
        .route(
            "/query/sensors/:sensor_id/sources/:source/latest-checkpoint",
            get(latest_sensor_checkpoint),
        )
        .route(
            "/query/sensors/:sensor_id/checkpoints",
            get(sensor_checkpoints),
        )
        .route("/query/sensors/:sensor_id/runs", get(sensor_runs))
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
pub struct EdgesResponse {
    pub edges: Vec<Edge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeResponse {
    pub edge: Edge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceResponse {
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorCheckpointResponse {
    pub checkpoint: SensorCheckpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

// === Advanced Reads DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeResponse {
    pub outcome: Outcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsResponse {
    pub events: Vec<Event>,
}

/// BFS result: a list of node IDs in traversal order plus the total
/// count. Clients fetch full node bodies via `/query/nodes/:id` as
/// needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BfsResponse {
    pub node_ids: Vec<NodeId>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterfactualResponse {
    pub diff: GraphDiff,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactScoreResponse {
    pub score: ImpactScore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    pub node_count: usize,
    pub edge_count: usize,
    pub total_events: usize,
    pub subscription_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BfsQuery {
    /// `outgoing`, `incoming`, or `both`. Case-insensitive.
    pub direction: Option<String>,
    /// Optional type_id filter — restricts BFS to nodes whose
    /// `type_id` matches.
    pub type_filter: Option<String>,
    pub limit: Option<usize>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsForSubjectQuery {
    pub subject_kind: String,
    pub subject_value: String,
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

fn parse_claim_kind(kind: &str) -> Option<ClaimKind> {
    match kind {
        "Fact" => Some(ClaimKind::Fact),
        "Inference" => Some(ClaimKind::Inference),
        "Hypothesis" => Some(ClaimKind::Hypothesis),
        "Prediction" => Some(ClaimKind::Prediction),
        "Recommendation" => Some(ClaimKind::Recommendation),
        "PolicyFinding" => Some(ClaimKind::PolicyFinding),
        "AnomalyFinding" => Some(ClaimKind::AnomalyFinding),
        "LineageFinding" => Some(ClaimKind::LineageFinding),
        _ => None,
    }
}

/// Parse `?direction=outgoing|incoming|both` (case-insensitive,
/// defaulting to `both` when not supplied).
fn parse_traversal_direction(value: Option<&str>) -> Option<TraversalDirection> {
    match value.map(|s| s.to_ascii_lowercase()).as_deref() {
        None | Some("both") => Some(TraversalDirection::Both),
        Some("outgoing") => Some(TraversalDirection::Outgoing),
        Some("incoming") => Some(TraversalDirection::Incoming),
        Some(_) => None,
    }
}

/// Parse `?subject_kind=X&subject_value=Y` into a `ClaimSubject`. The
/// value semantics differ by kind: for `Node` / `Edge` it is the
/// canonical id string; for `Dataset` / `Metric` / `System` /
/// `ExternalRef` it is the free-form identifier.
fn parse_claim_subject(subject_kind: &str, subject_value: &str) -> Option<ClaimSubject> {
    match subject_kind {
        "Node" => Some(ClaimSubject::Node(NodeId::from_str(subject_value))),
        "Edge" => Some(ClaimSubject::Edge(EdgeId::from_str(subject_value))),
        "ExternalRef" => Some(ClaimSubject::ExternalRef(subject_value.to_string())),
        "Dataset" => Some(ClaimSubject::Dataset(subject_value.to_string())),
        "Metric" => Some(ClaimSubject::Metric(subject_value.to_string())),
        "System" => Some(ClaimSubject::System(subject_value.to_string())),
        _ => None,
    }
}

// === Node handlers ===

async fn list_nodes(
    State(state): State<QueryHttpState>,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let nodes = state.service.nodes().await;
    match paginate_by_cursor(&nodes, query.after.as_deref(), query.limit, |node| {
        node.id().to_string()
    }) {
        Ok(page) => Json(page).into_response(),
        Err(_) => error_response(
            StatusCode::BAD_REQUEST,
            format!("unknown node cursor: {}", query.after.unwrap_or_default()),
        ),
    }
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

async fn node_outgoing_edges(
    State(state): State<QueryHttpState>,
    Path(node_id): Path<String>,
) -> Response {
    let id = NodeId::from_str(&node_id);
    if state.service.node(&id).await.is_none() {
        return error_response(StatusCode::NOT_FOUND, format!("node not found: {node_id}"));
    }
    let edges = state.service.outgoing_edges(&id).await;
    Json(EdgesResponse { edges }).into_response()
}

async fn node_incoming_edges(
    State(state): State<QueryHttpState>,
    Path(node_id): Path<String>,
) -> Response {
    let id = NodeId::from_str(&node_id);
    if state.service.node(&id).await.is_none() {
        return error_response(StatusCode::NOT_FOUND, format!("node not found: {node_id}"));
    }
    let edges = state.service.incoming_edges(&id).await;
    Json(EdgesResponse { edges }).into_response()
}

// === Edge handlers ===

async fn list_edges(
    State(state): State<QueryHttpState>,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let edges = state.service.edges().await;
    match paginate_by_cursor(&edges, query.after.as_deref(), query.limit, |edge| {
        edge.id().to_string()
    }) {
        Ok(page) => Json(page).into_response(),
        Err(_) => error_response(
            StatusCode::BAD_REQUEST,
            format!("unknown edge cursor: {}", query.after.unwrap_or_default()),
        ),
    }
}

async fn get_edge(
    State(state): State<QueryHttpState>,
    Path(edge_id): Path<String>,
) -> Response {
    let id = EdgeId::from_str(&edge_id);
    match state.service.edge(&id).await {
        Some(edge) => Json(EdgeResponse { edge }).into_response(),
        None => error_response(StatusCode::NOT_FOUND, format!("edge not found: {edge_id}")),
    }
}

// === Evidence handlers ===

async fn list_evidence(
    State(state): State<QueryHttpState>,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let evidence = state.service.evidence_items().await;
    match paginate_by_cursor(&evidence, query.after.as_deref(), query.limit, |evidence| {
        evidence.id.to_string()
    }) {
        Ok(page) => Json(page).into_response(),
        Err(_) => error_response(
            StatusCode::BAD_REQUEST,
            format!("unknown evidence cursor: {}", query.after.unwrap_or_default()),
        ),
    }
}

async fn get_evidence(
    State(state): State<QueryHttpState>,
    Path(evidence_id): Path<String>,
) -> Response {
    let id = EvidenceId::from_str(&evidence_id);
    match state.service.evidence(&id).await {
        Some(evidence) => Json(EvidenceResponse { evidence }).into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("evidence not found: {evidence_id}"),
        ),
    }
}

// === Claim handlers ===

async fn list_claims(
    State(state): State<QueryHttpState>,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let claims = state.service.claims().await;
    match paginate_by_cursor(&claims, query.after.as_deref(), query.limit, |claim| {
        claim.id.to_string()
    }) {
        Ok(page) => Json(page).into_response(),
        Err(_) => error_response(
            StatusCode::BAD_REQUEST,
            format!("unknown claim cursor: {}", query.after.unwrap_or_default()),
        ),
    }
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

async fn list_actions(
    State(state): State<QueryHttpState>,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let actions = state.service.actions().await;
    match paginate_by_cursor(&actions, query.after.as_deref(), query.limit, |action| {
        action.id.to_string()
    }) {
        Ok(page) => Json(page).into_response(),
        Err(_) => error_response(
            StatusCode::BAD_REQUEST,
            format!("unknown action cursor: {}", query.after.unwrap_or_default()),
        ),
    }
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

// === Sensor handlers ===
//
// The list routes return 200 with an empty list when the sensor has no
// matching rows; sensor_id is just a string key and there is no global
// "this sensor exists" registry to gate against. The latest-checkpoint
// route returns 404 when no checkpoint exists for the (sensor, source)
// pair — consistent with single-lookup contracts elsewhere.

async fn sensor_runs(
    State(state): State<QueryHttpState>,
    Path(sensor_id): Path<String>,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let id = SensorId::from_str(&sensor_id);
    let runs = state.service.runs_for_sensor(&id).await;
    match paginate_by_cursor(&runs, query.after.as_deref(), query.limit, |run| {
        run.id.to_string()
    }) {
        Ok(page) => Json(page).into_response(),
        Err(_) => error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "unknown sensor run cursor: {}",
                query.after.unwrap_or_default()
            ),
        ),
    }
}

async fn sensor_checkpoints(
    State(state): State<QueryHttpState>,
    Path(sensor_id): Path<String>,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let id = SensorId::from_str(&sensor_id);
    let checkpoints = state.service.checkpoints_for_sensor(&id).await;
    match paginate_by_cursor(
        &checkpoints,
        query.after.as_deref(),
        query.limit,
        |checkpoint| checkpoint.id.to_string(),
    ) {
        Ok(page) => Json(page).into_response(),
        Err(_) => error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "unknown sensor checkpoint cursor: {}",
                query.after.unwrap_or_default()
            ),
        ),
    }
}

async fn latest_sensor_checkpoint(
    State(state): State<QueryHttpState>,
    Path((sensor_id, source)): Path<(String, String)>,
) -> Response {
    let id = SensorId::from_str(&sensor_id);
    match state
        .service
        .latest_sensor_checkpoint(&id, &source)
        .await
    {
        Some(checkpoint) => Json(SensorCheckpointResponse { checkpoint }).into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("no checkpoint for sensor {sensor_id} source {source}"),
        ),
    }
}

// === Advanced reads handlers ===
//
// Engine already implements every method here — these handlers are
// thin HTTP shims over QueryService. The only non-trivial parts are
// the query-string parsers (TraversalDirection, ClaimKind,
// ClaimSubject) and the BFS pagination via the shared helper.

async fn query_stats(State(state): State<QueryHttpState>) -> Response {
    let stats = state.service.stats().await;
    Json(StatsResponse {
        node_count: stats.node_count,
        edge_count: stats.edge_count,
        total_events: stats.total_events,
        subscription_count: stats.subscription_count,
    })
    .into_response()
}

async fn node_bfs(
    State(state): State<QueryHttpState>,
    Path(node_id): Path<String>,
    Query(query): Query<BfsQuery>,
) -> Response {
    let id = NodeId::from_str(&node_id);
    if state.service.node(&id).await.is_none() {
        return error_response(StatusCode::NOT_FOUND, format!("node not found: {node_id}"));
    }
    let direction = match parse_traversal_direction(query.direction.as_deref()) {
        Some(d) => d,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "unknown direction: {} (expected outgoing|incoming|both)",
                    query.direction.unwrap_or_default()
                ),
            );
        }
    };
    let traversal: Vec<NodeId> = match query.type_filter {
        Some(type_filter) => state.service.bfs_by_type(&id, direction, type_filter).await,
        None => state.service.bfs(&id, direction).await,
    };
    // Paginate the resulting NodeId list — BFS from a hub node can
    // return thousands of ids and the response would otherwise be
    // unbounded.
    match paginate_by_cursor(
        &traversal,
        query.after.as_deref(),
        query.limit,
        |node_id| node_id.to_string(),
    ) {
        Ok(page) => Json(page).into_response(),
        Err(_) => error_response(
            StatusCode::BAD_REQUEST,
            format!("unknown bfs cursor: {}", query.after.unwrap_or_default()),
        ),
    }
}

async fn event_causal_chain(
    State(state): State<QueryHttpState>,
    Path(event_id): Path<String>,
) -> Response {
    let id = EventId::from_str(&event_id);
    // Existence check up front — `causal_chain` returns an empty Vec
    // both for "leaf event with no descendants" and "unknown event",
    // so we can't infer 404 from emptiness alone.
    if state.service.event(&id).await.is_none() {
        return error_response(StatusCode::NOT_FOUND, format!("event not found: {event_id}"));
    }
    let events = state.service.causal_chain(&id).await;
    Json(EventsResponse { events }).into_response()
}

async fn event_root_cause(
    State(state): State<QueryHttpState>,
    Path(event_id): Path<String>,
) -> Response {
    let id = EventId::from_str(&event_id);
    if state.service.event(&id).await.is_none() {
        return error_response(StatusCode::NOT_FOUND, format!("event not found: {event_id}"));
    }
    let events = state.service.root_cause(&id).await;
    Json(EventsResponse { events }).into_response()
}

async fn event_counterfactual(
    State(state): State<QueryHttpState>,
    Path(event_id): Path<String>,
) -> Response {
    let id = EventId::from_str(&event_id);
    match state.service.counterfactual(&id).await {
        Ok(diff) => Json(CounterfactualResponse { diff }).into_response(),
        Err(err) => error_response(
            StatusCode::NOT_FOUND,
            format!("counterfactual failed for {event_id}: {err}"),
        ),
    }
}

async fn event_impact_score(
    State(state): State<QueryHttpState>,
    Path(event_id): Path<String>,
) -> Response {
    let id = EventId::from_str(&event_id);
    match state.service.impact_score(&id).await {
        Ok(score) => Json(ImpactScoreResponse { score }).into_response(),
        Err(err) => error_response(
            StatusCode::NOT_FOUND,
            format!("impact_score failed for {event_id}: {err}"),
        ),
    }
}

async fn claims_using_evidence(
    State(state): State<QueryHttpState>,
    Path(evidence_id): Path<String>,
) -> Response {
    let id = EvidenceId::from_str(&evidence_id);
    if state.service.evidence(&id).await.is_none() {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("evidence not found: {evidence_id}"),
        );
    }
    let claims = state.service.claims_using_evidence(&id).await;
    Json(ClaimsResponse { claims }).into_response()
}

async fn get_outcome(
    State(state): State<QueryHttpState>,
    Path(outcome_id): Path<String>,
) -> Response {
    let id = OutcomeId::from_str(&outcome_id);
    match state.service.outcome(&id).await {
        Some(outcome) => Json(OutcomeResponse { outcome }).into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("outcome not found: {outcome_id}"),
        ),
    }
}

async fn claims_by_kind(
    State(state): State<QueryHttpState>,
    Path(kind): Path<String>,
) -> Response {
    let kind_enum = match parse_claim_kind(&kind) {
        Some(k) => k,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("unknown claim kind: {kind}"),
            );
        }
    };
    let claims = state.service.claims_with_kind(kind_enum).await;
    Json(ClaimsResponse { claims }).into_response()
}

async fn claims_for_subject(
    State(state): State<QueryHttpState>,
    Query(query): Query<ClaimsForSubjectQuery>,
) -> Response {
    let subject = match parse_claim_subject(&query.subject_kind, &query.subject_value) {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "unknown subject_kind: {} (expected Node|Edge|ExternalRef|Dataset|Metric|System)",
                    query.subject_kind
                ),
            );
        }
    };
    let claims = state.service.claims_for_subject(subject).await;
    Json(ClaimsResponse { claims }).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::pagination::Page;
    use crate::runtime::RuntimeBuilder;
    use hydra_core::SensorRun;
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
        let decoded: Page<Node> = read_json(response).await;
        assert_eq!(decoded.items.len(), 0);
        assert_eq!(decoded.next_cursor, None);
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
        let decoded: Page<Node> = read_json(response).await;
        assert_eq!(decoded.items.len(), 1);
        assert_eq!(decoded.items[0].id(), &node_id);
        assert_eq!(decoded.next_cursor, None);
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
        let decoded: Page<Claim> = read_json(response).await;
        assert_eq!(decoded.items.len(), 0);
        assert_eq!(decoded.next_cursor, None);
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
        let decoded: Page<Claim> = read_json(response).await;
        assert_eq!(decoded.items.len(), 1);
        assert_eq!(decoded.items[0].id, claim_id);

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
        let decoded: Page<Action> = read_json(response).await;
        assert_eq!(decoded.items.len(), 1);
        assert_eq!(decoded.items[0].id, action_id);

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

    // === Edges ===

    #[tokio::test]
    async fn list_edges_returns_empty_when_no_edges() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app.oneshot(empty_get("/query/edges")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<Edge> = read_json(response).await;
        assert_eq!(decoded.items.len(), 0);
        assert_eq!(decoded.next_cursor, None);
    }

    #[tokio::test]
    async fn list_and_get_edge_round_trip() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let a = NodeId::new();
        let b = NodeId::new();
        let edge_id = hydra_core::EdgeId::new();
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
                    edge_id: edge_id.clone(),
                    source: a.clone(),
                    target: b.clone(),
                    type_id: "in_vpc".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
        }
        let app = query_router(runtime);

        let response = app
            .clone()
            .oneshot(empty_get("/query/edges"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<Edge> = read_json(response).await;
        assert_eq!(decoded.items.len(), 1);
        assert_eq!(decoded.items[0].id(), &edge_id);

        let response = app
            .oneshot(empty_get(&format!("/query/edges/{edge_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: EdgeResponse = read_json(response).await;
        assert_eq!(decoded.edge.id(), &edge_id);
        assert_eq!(decoded.edge.source(), &a);
        assert_eq!(decoded.edge.target(), &b);
    }

    #[tokio::test]
    async fn get_edge_returns_404_when_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/edges/edg_missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn node_outgoing_and_incoming_edges() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let a = NodeId::new();
        let b = NodeId::new();
        let edge_id = hydra_core::EdgeId::new();
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
                    edge_id: edge_id.clone(),
                    source: a.clone(),
                    target: b.clone(),
                    type_id: "in_vpc".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
        }
        let app = query_router(runtime);

        let response = app
            .clone()
            .oneshot(empty_get(&format!("/query/nodes/{a}/outgoing-edges")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: EdgesResponse = read_json(response).await;
        assert_eq!(decoded.edges.len(), 1);
        assert_eq!(decoded.edges[0].id(), &edge_id);

        let response = app
            .clone()
            .oneshot(empty_get(&format!("/query/nodes/{b}/incoming-edges")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: EdgesResponse = read_json(response).await;
        assert_eq!(decoded.edges.len(), 1);
        assert_eq!(decoded.edges[0].id(), &edge_id);

        // Source has no incoming, target has no outgoing.
        let response = app
            .clone()
            .oneshot(empty_get(&format!("/query/nodes/{a}/incoming-edges")))
            .await
            .unwrap();
        let decoded: EdgesResponse = read_json(response).await;
        assert_eq!(decoded.edges.len(), 0);

        let response = app
            .oneshot(empty_get(&format!("/query/nodes/{b}/outgoing-edges")))
            .await
            .unwrap();
        let decoded: EdgesResponse = read_json(response).await;
        assert_eq!(decoded.edges.len(), 0);
    }

    #[tokio::test]
    async fn node_outgoing_edges_returns_404_when_node_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/nodes/node_missing/outgoing-edges"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn node_incoming_edges_returns_404_when_node_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/nodes/node_missing/incoming-edges"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // === Evidence ===

    #[tokio::test]
    async fn list_evidence_returns_empty_when_none() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app.oneshot(empty_get("/query/evidence")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<Evidence> = read_json(response).await;
        assert_eq!(decoded.items.len(), 0);
        assert_eq!(decoded.next_cursor, None);
    }

    #[tokio::test]
    async fn list_and_get_evidence_round_trip() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let ev = evidence();
        let evidence_id = ev.id.clone();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest_event(event(EventKind::EvidenceAdded { evidence: ev }))
                .unwrap();
        }
        let app = query_router(runtime);

        let response = app
            .clone()
            .oneshot(empty_get("/query/evidence"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<Evidence> = read_json(response).await;
        assert_eq!(decoded.items.len(), 1);
        assert_eq!(decoded.items[0].id, evidence_id);

        let response = app
            .oneshot(empty_get(&format!("/query/evidence/{evidence_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: EvidenceResponse = read_json(response).await;
        assert_eq!(decoded.evidence.id, evidence_id);
    }

    #[tokio::test]
    async fn get_evidence_returns_404_when_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/evidence/evd_missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // === Sensors ===

    fn observe(
        hydra: &mut hydra_engine::hydra::Hydra,
        sensor_id: &SensorId,
        offset: &str,
    ) -> hydra_core::SensorCheckpoint {
        use hydra_core::{NodeId, SourceCursor};
        hydra
            .record_sensor_observation(
                sensor_id.clone(),
                "bank",
                SourceCursor::Offset {
                    stream: "bank.transactions".to_string(),
                    partition: Some("acct-9001".to_string()),
                    offset: offset.to_string(),
                },
                EventKind::Signal {
                    source: NodeId::from_str("sensor.test"),
                    name: format!("obs_{offset}"),
                    payload: HashMap::new(),
                },
            )
            .unwrap()
    }

    #[tokio::test]
    async fn sensor_runs_returns_empty_when_no_runs_for_sensor() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/sensors/sensor_bank/runs"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<SensorRun> = read_json(response).await;
        assert_eq!(decoded.items.len(), 0);
        assert_eq!(decoded.next_cursor, None);
    }

    #[tokio::test]
    async fn sensor_checkpoints_returns_empty_when_no_checkpoints_for_sensor() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/sensors/sensor_bank/checkpoints"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<SensorCheckpoint> = read_json(response).await;
        assert_eq!(decoded.items.len(), 0);
        assert_eq!(decoded.next_cursor, None);
    }

    #[tokio::test]
    async fn sensor_checkpoints_returns_recorded_checkpoints() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let sensor = SensorId::from_str("sensor_bank");
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            observe(&mut hydra, &sensor, "1");
            observe(&mut hydra, &sensor, "2");
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/sensors/sensor_bank/checkpoints"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<SensorCheckpoint> = read_json(response).await;
        assert_eq!(decoded.items.len(), 2);
    }

    #[tokio::test]
    async fn latest_checkpoint_returns_most_recent_for_sensor_and_source() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let sensor = SensorId::from_str("sensor_bank");
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            observe(&mut hydra, &sensor, "1");
            observe(&mut hydra, &sensor, "2");
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(
                "/query/sensors/sensor_bank/sources/bank.transactions/latest-checkpoint",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: SensorCheckpointResponse = read_json(response).await;
        let offset = match &decoded.checkpoint.cursor {
            hydra_core::SourceCursor::Offset { offset, .. } => offset.clone(),
            other => panic!("unexpected cursor: {other:?}"),
        };
        assert_eq!(offset, "2");
    }

    #[tokio::test]
    async fn latest_checkpoint_returns_404_when_none_exists() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(
                "/query/sensors/sensor_missing/sources/nowhere/latest-checkpoint",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn latest_checkpoint_404_when_sensor_has_checkpoints_for_other_source() {
        // Sensor exists and has checkpoints, but for a different source.
        // The route is sensor+source scoped, so this must 404 — not return
        // an unrelated checkpoint.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let sensor = SensorId::from_str("sensor_bank");
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            observe(&mut hydra, &sensor, "1");
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(
                "/query/sensors/sensor_bank/sources/other.stream/latest-checkpoint",
            ))
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

    // === Pagination ===

    #[tokio::test]
    async fn list_nodes_respects_limit_and_returns_cursor() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            for _ in 0..3 {
                hydra
                    .ingest(EventKind::NodeCreated {
                        node_id: NodeId::new(),
                        type_id: "ec2".to_string(),
                        properties: HashMap::new(),
                    })
                    .unwrap();
            }
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/nodes?limit=2"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<Node> = read_json(response).await;
        assert_eq!(decoded.items.len(), 2);
        assert!(decoded.next_cursor.is_some());
    }

    #[tokio::test]
    async fn list_nodes_walks_full_set_with_after_cursor() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            for _ in 0..3 {
                hydra
                    .ingest(EventKind::NodeCreated {
                        node_id: NodeId::new(),
                        type_id: "ec2".to_string(),
                        properties: HashMap::new(),
                    })
                    .unwrap();
            }
        }
        let app = query_router(runtime);

        let response = app
            .clone()
            .oneshot(empty_get("/query/nodes?limit=2"))
            .await
            .unwrap();
        let first: Page<Node> = read_json(response).await;
        assert_eq!(first.items.len(), 2);
        let cursor = first.next_cursor.expect("first page must have cursor");

        let response = app
            .oneshot(empty_get(&format!("/query/nodes?limit=2&after={cursor}")))
            .await
            .unwrap();
        let second: Page<Node> = read_json(response).await;
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.next_cursor, None);
    }

    #[tokio::test]
    async fn list_nodes_unknown_cursor_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/nodes?after=node_bogus"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_edges_paginates() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let mut edge_ids = Vec::new();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let a = NodeId::new();
            let b = NodeId::new();
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
            for _ in 0..2 {
                let edge_id = hydra_core::EdgeId::new();
                hydra
                    .ingest(EventKind::EdgeCreated {
                        edge_id: edge_id.clone(),
                        source: a.clone(),
                        target: b.clone(),
                        type_id: "in_vpc".to_string(),
                        properties: HashMap::new(),
                    })
                    .unwrap();
                edge_ids.push(edge_id);
            }
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/edges?limit=1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<Edge> = read_json(response).await;
        assert_eq!(decoded.items.len(), 1);
        assert!(decoded.next_cursor.is_some());
    }

    #[tokio::test]
    async fn sensor_checkpoints_paginates() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let sensor = SensorId::from_str("sensor_bank");
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            observe(&mut hydra, &sensor, "1");
            observe(&mut hydra, &sensor, "2");
            observe(&mut hydra, &sensor, "3");
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(
                "/query/sensors/sensor_bank/checkpoints?limit=2",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<SensorCheckpoint> = read_json(response).await;
        assert_eq!(decoded.items.len(), 2);
        assert!(decoded.next_cursor.is_some());
    }

    #[tokio::test]
    async fn sensor_checkpoints_unknown_cursor_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(
                "/query/sensors/sensor_bank/checkpoints?after=chkpt_bogus",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // === Advanced reads ===

    #[tokio::test]
    async fn stats_returns_current_counts() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest(EventKind::NodeCreated {
                    node_id: NodeId::new(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
        }
        let app = query_router(runtime);
        let response = app.oneshot(empty_get("/query/stats")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: StatsResponse = read_json(response).await;
        assert_eq!(decoded.node_count, 1);
        assert_eq!(decoded.edge_count, 0);
        assert_eq!(decoded.total_events, 1);
    }

    #[tokio::test]
    async fn node_bfs_returns_outgoing_traversal() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let a = NodeId::new();
        let b = NodeId::new();
        let c = NodeId::new();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            for (id, type_id) in [(&a, "ec2"), (&b, "vpc"), (&c, "subnet")] {
                hydra
                    .ingest(EventKind::NodeCreated {
                        node_id: id.clone(),
                        type_id: type_id.to_string(),
                        properties: HashMap::new(),
                    })
                    .unwrap();
            }
            hydra
                .ingest(EventKind::EdgeCreated {
                    edge_id: hydra_core::EdgeId::new(),
                    source: a.clone(),
                    target: b.clone(),
                    type_id: "in_vpc".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
            hydra
                .ingest(EventKind::EdgeCreated {
                    edge_id: hydra_core::EdgeId::new(),
                    source: b.clone(),
                    target: c.clone(),
                    type_id: "in_vpc".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!(
                "/query/nodes/{a}/bfs?direction=outgoing"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<NodeId> = read_json(response).await;
        // bfs_dyn includes the start node, so the traversal from `a`
        // through the a -> b -> c chain returns [a, b, c].
        assert_eq!(decoded.items.len(), 3);
        assert!(decoded.items.contains(&a));
        assert!(decoded.items.contains(&b));
        assert!(decoded.items.contains(&c));
    }

    #[tokio::test]
    async fn node_bfs_returns_404_when_node_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/nodes/node_missing/bfs"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn node_bfs_returns_400_on_bad_direction() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let start = NodeId::new();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest(EventKind::NodeCreated {
                    node_id: start.clone(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!(
                "/query/nodes/{start}/bfs?direction=sideways"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn node_bfs_paginates_with_limit_and_cursor() {
        // Build a 4-node chain a -> b -> c -> d and walk the BFS in pages.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let a = NodeId::new();
        let b = NodeId::new();
        let c = NodeId::new();
        let d = NodeId::new();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            for id in [&a, &b, &c, &d] {
                hydra
                    .ingest(EventKind::NodeCreated {
                        node_id: id.clone(),
                        type_id: "ec2".to_string(),
                        properties: HashMap::new(),
                    })
                    .unwrap();
            }
            for (src, tgt) in [(&a, &b), (&b, &c), (&c, &d)] {
                hydra
                    .ingest(EventKind::EdgeCreated {
                        edge_id: hydra_core::EdgeId::new(),
                        source: src.clone(),
                        target: tgt.clone(),
                        type_id: "linked".to_string(),
                        properties: HashMap::new(),
                    })
                    .unwrap();
            }
        }
        let app = query_router(runtime);
        let response = app
            .clone()
            .oneshot(empty_get(&format!(
                "/query/nodes/{a}/bfs?direction=outgoing&limit=2"
            )))
            .await
            .unwrap();
        let first: Page<NodeId> = read_json(response).await;
        // bfs returns [a, b, c, d] — first page of 2 → [a, b].
        assert_eq!(first.items.len(), 2);
        let cursor = first.next_cursor.clone().expect("expected next_cursor");

        let response = app
            .oneshot(empty_get(&format!(
                "/query/nodes/{a}/bfs?direction=outgoing&limit=2&after={cursor}"
            )))
            .await
            .unwrap();
        let second: Page<NodeId> = read_json(response).await;
        assert_eq!(second.items.len(), 2);
        assert_eq!(second.next_cursor, None);
    }

    fn signal_event(name: &str) -> EventKind {
        EventKind::Signal {
            source: NodeId::from_str("advanced.reads"),
            name: name.to_string(),
            payload: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn event_causal_chain_returns_descendants() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let trigger_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra.ingest(signal_event("kickoff")).unwrap();
            trigger_id = result.events[0].id.clone();
        }
        let app = query_router(runtime);
        // Even leaf events return 200 with an empty list — the route
        // only 404s when the event itself doesn't exist.
        let response = app
            .oneshot(empty_get(&format!(
                "/query/events/{trigger_id}/causal-chain"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: EventsResponse = read_json(response).await;
        // No reflexes registered, so the kickoff signal has no
        // descendants — the chain is empty.
        assert_eq!(decoded.events.len(), 0);
    }

    #[tokio::test]
    async fn event_causal_chain_returns_404_when_event_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/events/evt_missing/causal-chain"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn event_root_cause_returns_chain_including_target() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let event_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra.ingest(signal_event("only")).unwrap();
            event_id = result.events[0].id.clone();
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/query/events/{event_id}/root-cause")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: EventsResponse = read_json(response).await;
        // Root-cause includes the event itself — chain length 1 for a
        // signal that has no cause.
        assert_eq!(decoded.events.len(), 1);
        assert_eq!(decoded.events[0].id, event_id);
    }

    #[tokio::test]
    async fn event_root_cause_returns_404_when_event_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/events/evt_missing/root-cause"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn event_counterfactual_returns_diff() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let create_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra
                .ingest(EventKind::NodeCreated {
                    node_id: NodeId::new(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
            create_id = result.events[0].id.clone();
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!(
                "/query/events/{create_id}/counterfactual"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: CounterfactualResponse = read_json(response).await;
        // Removing the create event from history would remove that
        // node — so the diff should show one node only in the actual
        // state.
        assert_eq!(decoded.diff.nodes_only_in_actual.len(), 1);
    }

    #[tokio::test]
    async fn event_counterfactual_returns_404_when_event_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(
                "/query/events/evt_missing/counterfactual",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn event_impact_score_returns_score() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let create_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra
                .ingest(EventKind::NodeCreated {
                    node_id: NodeId::new(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
            create_id = result.events[0].id.clone();
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!(
                "/query/events/{create_id}/impact-score"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ImpactScoreResponse = read_json(response).await;
        assert_eq!(decoded.score.event_id, create_id);
        assert!(decoded.score.nodes_affected >= 1);
    }

    #[tokio::test]
    async fn event_impact_score_returns_404_when_event_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/events/evt_missing/impact-score"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn evidence_claims_returns_supporting_claims() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let ev = evidence();
        let evidence_id = ev.id.clone();
        let cl = claim(evidence_id.clone());
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
            .oneshot(empty_get(&format!(
                "/query/evidence/{evidence_id}/claims"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ClaimsResponse = read_json(response).await;
        assert_eq!(decoded.claims.len(), 1);
    }

    #[tokio::test]
    async fn evidence_claims_returns_404_when_evidence_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/evidence/evd_missing/claims"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_outcome_returns_outcome_when_present() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_id;
        let outcome_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let act = action();
            action_id = act.id.clone();
            hydra
                .ingest(EventKind::ActionProposed { action: act })
                .unwrap();
            // ActionExecuted triggers OutcomeAgent which emits a
            // synthetic Unknown outcome.
            hydra
                .ingest(EventKind::ActionExecuting {
                    action_id: action_id.clone(),
                })
                .unwrap();
            hydra
                .ingest(EventKind::ActionExecuted {
                    action_id: action_id.clone(),
                })
                .unwrap();
            let outcomes = hydra
                .outcomes_for_action(&action_id)
                .into_iter()
                .cloned()
                .collect::<Vec<_>>();
            outcome_id = outcomes[0].id.clone();
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/query/outcomes/{outcome_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: OutcomeResponse = read_json(response).await;
        assert_eq!(decoded.outcome.id, outcome_id);
        assert_eq!(decoded.outcome.action_id, action_id);
    }

    #[tokio::test]
    async fn get_outcome_returns_404_when_missing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/outcomes/outc_missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn claims_by_kind_filters_results() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let ev = evidence();
        let cl = claim(ev.id.clone()); // claim() uses ClaimKind::AnomalyFinding
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
            .oneshot(empty_get("/query/claims/kind/AnomalyFinding"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ClaimsResponse = read_json(response).await;
        assert_eq!(decoded.claims.len(), 1);

        // A different kind that wasn't ingested returns 200 + empty.
        let response = app
            .oneshot(empty_get("/query/claims/kind/PolicyFinding"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ClaimsResponse = read_json(response).await;
        assert_eq!(decoded.claims.len(), 0);
    }

    #[tokio::test]
    async fn claims_by_kind_returns_400_on_unknown_kind() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/claims/kind/bogus"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn claims_for_subject_returns_claims_about_dataset() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let ev = evidence();
        // Build a claim with a known simple subject value so the URL
        // round-trip is trivially verifiable.
        let mut cl = claim(ev.id.clone());
        cl.subject = ClaimSubject::Dataset("demo_dataset".to_string());
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
            .oneshot(empty_get(
                "/query/claims-for-subject?subject_kind=Dataset&subject_value=demo_dataset",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ClaimsResponse = read_json(response).await;
        assert_eq!(decoded.claims.len(), 1);

        // Different subject value returns 200 with empty list.
        let response = app
            .oneshot(empty_get(
                "/query/claims-for-subject?subject_kind=Dataset&subject_value=other",
            ))
            .await
            .unwrap();
        let decoded: ClaimsResponse = read_json(response).await;
        assert_eq!(decoded.claims.len(), 0);
    }

    #[tokio::test]
    async fn claims_for_subject_returns_400_on_unknown_subject_kind() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(
                "/query/claims-for-subject?subject_kind=Galaxy&subject_value=milky_way",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
