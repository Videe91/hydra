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
use crate::http::tenant::{extract_tenant, tenant_error_response};
use crate::query::QueryService;
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
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

// === Node handlers (Patch 2B: real tenant-filtered handlers) ===
//
// NodeMeta.tenant_id is now populated by the projection from the
// creating Event's envelope. The 501 placeholder from Patch 2A is
// gone — these handlers strictly scope reads to the requesting
// tenant.

async fn list_nodes(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let nodes = state.service.nodes_for_tenant(&tenant).await;
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
    headers: HeaderMap,
    Path(node_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = NodeId::from_str(&node_id);
    match state.service.node_for_tenant(&id, &tenant).await {
        Some(node) => Json(NodeResponse { node }).into_response(),
        None => error_response(StatusCode::NOT_FOUND, format!("node not found: {node_id}")),
    }
}

async fn node_neighbors(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = NodeId::from_str(&node_id);
    if state.service.node_for_tenant(&id, &tenant).await.is_none() {
        return error_response(StatusCode::NOT_FOUND, format!("node not found: {node_id}"));
    }
    let nodes = state.service.neighbors_for_tenant(&id, &tenant).await;
    Json(NodesResponse { nodes }).into_response()
}

async fn node_outgoing_edges(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = NodeId::from_str(&node_id);
    if state.service.node_for_tenant(&id, &tenant).await.is_none() {
        return error_response(StatusCode::NOT_FOUND, format!("node not found: {node_id}"));
    }
    let edges = state.service.outgoing_edges_for_tenant(&id, &tenant).await;
    Json(EdgesResponse { edges }).into_response()
}

async fn node_incoming_edges(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = NodeId::from_str(&node_id);
    if state.service.node_for_tenant(&id, &tenant).await.is_none() {
        return error_response(StatusCode::NOT_FOUND, format!("node not found: {node_id}"));
    }
    let edges = state.service.incoming_edges_for_tenant(&id, &tenant).await;
    Json(EdgesResponse { edges }).into_response()
}

// === Edge handlers ===

async fn list_edges(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let edges = state.service.edges_for_tenant(&tenant).await;
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
    headers: HeaderMap,
    Path(edge_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = EdgeId::from_str(&edge_id);
    match state.service.edge_for_tenant(&id, &tenant).await {
        Some(edge) => Json(EdgeResponse { edge }).into_response(),
        None => error_response(StatusCode::NOT_FOUND, format!("edge not found: {edge_id}")),
    }
}

// === Evidence handlers ===

async fn list_evidence(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let evidence = state.service.evidence_items_for_tenant(&tenant).await;
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
    headers: HeaderMap,
    Path(evidence_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = EvidenceId::from_str(&evidence_id);
    match state.service.evidence_for_tenant(&id, &tenant).await {
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
    headers: HeaderMap,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let claims = state.service.claims_for_tenant(&tenant).await;
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
    headers: HeaderMap,
    Path(claim_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = ClaimId::from_str(&claim_id);
    match state.service.claim_for_tenant(&id, &tenant).await {
        Some(claim) => Json(ClaimResponse { claim }).into_response(),
        None => error_response(StatusCode::NOT_FOUND, format!("claim not found: {claim_id}")),
    }
}

async fn claims_by_status(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Path(status): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let status_enum = match parse_claim_status(&status) {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("unknown claim status: {status}"),
            );
        }
    };
    let claims = state
        .service
        .claims_with_status_for_tenant(status_enum, &tenant)
        .await;
    Json(ClaimsResponse { claims }).into_response()
}

// === Action handlers ===

async fn list_actions(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let actions = state.service.actions_for_tenant(&tenant).await;
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
    headers: HeaderMap,
    Path(action_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = ActionId::from_str(&action_id);
    match state.service.action_for_tenant(&id, &tenant).await {
        Some(action) => Json(ActionResponse { action }).into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("action not found: {action_id}"),
        ),
    }
}

async fn actions_by_status(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Path(status): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let status_enum = match parse_action_status(&status) {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("unknown action status: {status}"),
            );
        }
    };
    let actions = state
        .service
        .actions_with_status_for_tenant(status_enum, &tenant)
        .await;
    Json(ActionsResponse { actions }).into_response()
}

async fn outcomes_for_action(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Path(action_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = ActionId::from_str(&action_id);
    if state.service.action_for_tenant(&id, &tenant).await.is_none() {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("action not found: {action_id}"),
        );
    }
    let outcomes = state
        .service
        .outcomes_for_action_for_tenant(&id, &tenant)
        .await;
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
    headers: HeaderMap,
    Path(sensor_id): Path<String>,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = SensorId::from_str(&sensor_id);
    let runs = state.service.runs_for_sensor_for_tenant(&id, &tenant).await;
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
    headers: HeaderMap,
    Path(sensor_id): Path<String>,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = SensorId::from_str(&sensor_id);
    let checkpoints = state
        .service
        .checkpoints_for_sensor_for_tenant(&id, &tenant)
        .await;
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
    headers: HeaderMap,
    Path((sensor_id, source)): Path<(String, String)>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = SensorId::from_str(&sensor_id);
    match state
        .service
        .latest_sensor_checkpoint_for_tenant(&id, &source, &tenant)
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

async fn query_stats(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
) -> Response {
    // Tenant header is required but stats are global in v0 — counts
    // span all tenants. This is a control-plane convenience, not a
    // data-leak surface (no per-row data is exposed). Per-tenant
    // counts are a future patch alongside true tenant scoping for
    // graph topology.
    if let Err(error) = extract_tenant(&headers) {
        return tenant_error_response(error);
    }
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
    headers: HeaderMap,
    Path(node_id): Path<String>,
    Query(query): Query<BfsQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = NodeId::from_str(&node_id);
    // Existence + tenant ownership check up front. The strict BFS
    // would also short-circuit on this, but doing the check here
    // lets us return a clean 404 instead of an empty 200 page.
    if state.service.node_for_tenant(&id, &tenant).await.is_none() {
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
        Some(type_filter) => {
            state
                .service
                .bfs_by_type_for_tenant(&id, direction, type_filter, &tenant)
                .await
        }
        None => state.service.bfs_for_tenant(&id, direction, &tenant).await,
    };
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

// Causal/counterfactual routes are gated on the *seed* event's
// tenant ownership. v0 returns the engine's traversal result as-is —
// cross-tenant descendants are possible if the engine emitted them
// in the same causal chain (a cascade reflex producing a
// system-level event in response to a tenant event, for example).
// Strict descendant filtering is deferred to a future patch.

async fn event_causal_chain(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Path(event_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = EventId::from_str(&event_id);
    if state.service.event_for_tenant(&id, &tenant).await.is_none() {
        return error_response(StatusCode::NOT_FOUND, format!("event not found: {event_id}"));
    }
    let events = state.service.causal_chain(&id).await;
    Json(EventsResponse { events }).into_response()
}

async fn event_root_cause(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Path(event_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = EventId::from_str(&event_id);
    if state.service.event_for_tenant(&id, &tenant).await.is_none() {
        return error_response(StatusCode::NOT_FOUND, format!("event not found: {event_id}"));
    }
    let events = state.service.root_cause(&id).await;
    Json(EventsResponse { events }).into_response()
}

async fn event_counterfactual(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Path(event_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = EventId::from_str(&event_id);
    if state.service.event_for_tenant(&id, &tenant).await.is_none() {
        return error_response(StatusCode::NOT_FOUND, format!("event not found: {event_id}"));
    }
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
    headers: HeaderMap,
    Path(event_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = EventId::from_str(&event_id);
    if state.service.event_for_tenant(&id, &tenant).await.is_none() {
        return error_response(StatusCode::NOT_FOUND, format!("event not found: {event_id}"));
    }
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
    headers: HeaderMap,
    Path(evidence_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = EvidenceId::from_str(&evidence_id);
    if state
        .service
        .evidence_for_tenant(&id, &tenant)
        .await
        .is_none()
    {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("evidence not found: {evidence_id}"),
        );
    }
    let claims = state
        .service
        .claims_using_evidence_for_tenant(&id, &tenant)
        .await;
    Json(ClaimsResponse { claims }).into_response()
}

async fn get_outcome(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Path(outcome_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let id = OutcomeId::from_str(&outcome_id);
    match state.service.outcome_for_tenant(&id, &tenant).await {
        Some(outcome) => Json(OutcomeResponse { outcome }).into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("outcome not found: {outcome_id}"),
        ),
    }
}

async fn claims_by_kind(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Path(kind): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let kind_enum = match parse_claim_kind(&kind) {
        Some(k) => k,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("unknown claim kind: {kind}"),
            );
        }
    };
    let claims = state
        .service
        .claims_with_kind_for_tenant(kind_enum, &tenant)
        .await;
    Json(ClaimsResponse { claims }).into_response()
}

async fn claims_for_subject(
    State(state): State<QueryHttpState>,
    headers: HeaderMap,
    Query(query): Query<ClaimsForSubjectQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
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
    let claims = state
        .service
        .claims_for_subject_for_tenant(subject, &tenant)
        .await;
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

    const TEST_TENANT: &str = "tenant_http_query_test";

    /// Default GET helper that injects the canonical test tenant
    /// header. Existing tests that built data with the same tenant
    /// (via the `tenant()` helper) get tenant-filtered reads "for
    /// free" without modification.
    fn empty_get(uri: &str) -> Request<Body> {
        empty_get_for(uri, TEST_TENANT)
    }

    fn empty_get_for(uri: &str, tenant: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("X-Hydra-Tenant", tenant)
            .body(Body::empty())
            .unwrap()
    }

    fn empty_get_without_tenant(uri: &str) -> Request<Body> {
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
            tenant_id: Some(tenant()),
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

    // === Graph topology (Patch 2B: tenant-scoped) ===
    //
    // NodeMeta/EdgeMeta now carry tenant_id (stamped by the
    // projection from the Event envelope). These tests prove tenant
    // isolation end-to-end through the router.

    /// Helper: ingest a node under the canonical test tenant via the
    /// engine's `ingest_for_tenant` path. This is the same path the
    /// /ingest HTTP route takes for tenant-scoped writes.
    async fn ingest_node_for(
        runtime: &crate::runtime::RuntimeHandle,
        tenant: TenantId,
        type_id: &str,
    ) -> NodeId {
        let node_id = NodeId::new();
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra
            .ingest_for_tenant(
                EventKind::NodeCreated {
                    node_id: node_id.clone(),
                    type_id: type_id.to_string(),
                    properties: HashMap::new(),
                },
                tenant,
            )
            .unwrap();
        node_id
    }

    async fn ingest_edge_for(
        runtime: &crate::runtime::RuntimeHandle,
        tenant: TenantId,
        source: &NodeId,
        target: &NodeId,
    ) -> hydra_core::EdgeId {
        let edge_id = hydra_core::EdgeId::new();
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra
            .ingest_for_tenant(
                EventKind::EdgeCreated {
                    edge_id: edge_id.clone(),
                    source: source.clone(),
                    target: target.clone(),
                    type_id: "linked".to_string(),
                    properties: HashMap::new(),
                },
                tenant,
            )
            .unwrap();
        edge_id
    }

    fn tenant_id_a() -> TenantId {
        TenantId::from_str(TEST_TENANT)
    }

    fn tenant_id_b() -> TenantId {
        TenantId::from_str("tenant_other_graph_b")
    }

    #[tokio::test]
    async fn list_nodes_returns_only_own_tenant_nodes() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let a = ingest_node_for(&runtime, tenant_id_a(), "ec2").await;
        let _b = ingest_node_for(&runtime, tenant_id_b(), "ec2").await;
        let app = query_router(runtime);
        let response = app.oneshot(empty_get("/query/nodes")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<Node> = read_json(response).await;
        assert_eq!(decoded.items.len(), 1);
        assert_eq!(decoded.items[0].id(), &a);
        assert_eq!(decoded.items[0].tenant_id(), Some(&tenant_id_a()));
    }

    #[tokio::test]
    async fn get_node_returns_404_when_owned_by_other_tenant() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let b_node = ingest_node_for(&runtime, tenant_id_b(), "ec2").await;
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/query/nodes/{b_node}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_nodes_paginates() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        for _ in 0..3 {
            ingest_node_for(&runtime, tenant_id_a(), "ec2").await;
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
    async fn list_nodes_without_tenant_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get_without_tenant("/query/nodes"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn node_neighbors_returns_only_own_tenant_neighbors() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        // Build two parallel graphs: A's a→b, and B's b'→a (note:
        // edges can't cross tenants under v0 — the EdgeCreated
        // event's tenant scopes the edge — so A and B remain
        // strictly disjoint).
        let a_src = ingest_node_for(&runtime, tenant_id_a(), "ec2").await;
        let a_dst = ingest_node_for(&runtime, tenant_id_a(), "vpc").await;
        let _ = ingest_edge_for(&runtime, tenant_id_a(), &a_src, &a_dst).await;
        let _ = ingest_node_for(&runtime, tenant_id_b(), "ec2").await;
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/query/nodes/{a_src}/neighbors")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: NodesResponse = read_json(response).await;
        assert_eq!(decoded.nodes.len(), 1);
        assert_eq!(decoded.nodes[0].id(), &a_dst);
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

    // === Edges (Patch 2B) ===

    #[tokio::test]
    async fn list_edges_returns_only_own_tenant_edges() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let a_src = ingest_node_for(&runtime, tenant_id_a(), "ec2").await;
        let a_dst = ingest_node_for(&runtime, tenant_id_a(), "vpc").await;
        let a_edge = ingest_edge_for(&runtime, tenant_id_a(), &a_src, &a_dst).await;

        let b_src = ingest_node_for(&runtime, tenant_id_b(), "ec2").await;
        let b_dst = ingest_node_for(&runtime, tenant_id_b(), "vpc").await;
        let _ = ingest_edge_for(&runtime, tenant_id_b(), &b_src, &b_dst).await;

        let app = query_router(runtime);
        let response = app.oneshot(empty_get("/query/edges")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<Edge> = read_json(response).await;
        assert_eq!(decoded.items.len(), 1);
        assert_eq!(decoded.items[0].id(), &a_edge);
    }

    #[tokio::test]
    async fn get_edge_returns_404_when_owned_by_other_tenant() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let b_src = ingest_node_for(&runtime, tenant_id_b(), "ec2").await;
        let b_dst = ingest_node_for(&runtime, tenant_id_b(), "vpc").await;
        let b_edge = ingest_edge_for(&runtime, tenant_id_b(), &b_src, &b_dst).await;
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/query/edges/{b_edge}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn node_outgoing_and_incoming_edges_are_tenant_scoped() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let a = ingest_node_for(&runtime, tenant_id_a(), "ec2").await;
        let b = ingest_node_for(&runtime, tenant_id_a(), "vpc").await;
        let edge_a = ingest_edge_for(&runtime, tenant_id_a(), &a, &b).await;
        let app = query_router(runtime);

        let response = app
            .clone()
            .oneshot(empty_get(&format!("/query/nodes/{a}/outgoing-edges")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: EdgesResponse = read_json(response).await;
        assert_eq!(decoded.edges.len(), 1);
        assert_eq!(decoded.edges[0].id(), &edge_a);

        let response = app
            .oneshot(empty_get(&format!("/query/nodes/{b}/incoming-edges")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: EdgesResponse = read_json(response).await;
        assert_eq!(decoded.edges.len(), 1);
        assert_eq!(decoded.edges[0].id(), &edge_a);
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
        observe_for(hydra, sensor_id, offset, tenant())
    }

    fn observe_for(
        hydra: &mut hydra_engine::hydra::Hydra,
        sensor_id: &SensorId,
        offset: &str,
        owner: TenantId,
    ) -> hydra_core::SensorCheckpoint {
        use hydra_core::{NodeId, SourceCursor};
        hydra
            .record_sensor_observation_for_tenant(
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
                owner,
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
    //
    // Node/edge pagination tests are gone with Patch 2A — the routes
    // now 501. Tenant-scoped pagination over node/edge data lands in
    // Patch 2B together with NodeMeta.tenant_id. Sensor pagination
    // survives.

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
    async fn node_bfs_returns_tenant_scoped_traversal() {
        // Build a 3-node chain a -> b -> c under tenant A, plus a
        // disjoint node z under tenant B. BFS from `a` returns only
        // A's chain — z is unreachable and so is excluded.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let a = ingest_node_for(&runtime, tenant_id_a(), "ec2").await;
        let b = ingest_node_for(&runtime, tenant_id_a(), "vpc").await;
        let c = ingest_node_for(&runtime, tenant_id_a(), "subnet").await;
        let _ = ingest_edge_for(&runtime, tenant_id_a(), &a, &b).await;
        let _ = ingest_edge_for(&runtime, tenant_id_a(), &b, &c).await;
        let _ = ingest_node_for(&runtime, tenant_id_b(), "ec2").await;

        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!(
                "/query/nodes/{a}/bfs?direction=outgoing"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: Page<NodeId> = read_json(response).await;
        // a, b, c — start is always included; z is in another tenant
        // so it's never reachable.
        assert_eq!(decoded.items.len(), 3);
        assert!(decoded.items.contains(&a));
        assert!(decoded.items.contains(&b));
        assert!(decoded.items.contains(&c));
    }

    #[tokio::test]
    async fn node_bfs_returns_404_when_start_belongs_to_other_tenant() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let b_node = ingest_node_for(&runtime, tenant_id_b(), "ec2").await;
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!(
                "/query/nodes/{b_node}/bfs?direction=outgoing"
            )))
            .await
            .unwrap();
        // Tenant A asks for BFS from a node B owns — 404 (no
        // existence leak).
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn node_bfs_paginates() {
        // 4-node chain — confirm pagination still works after Patch 2B.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let a = ingest_node_for(&runtime, tenant_id_a(), "ec2").await;
        let b = ingest_node_for(&runtime, tenant_id_a(), "ec2").await;
        let c = ingest_node_for(&runtime, tenant_id_a(), "ec2").await;
        let d = ingest_node_for(&runtime, tenant_id_a(), "ec2").await;
        let _ = ingest_edge_for(&runtime, tenant_id_a(), &a, &b).await;
        let _ = ingest_edge_for(&runtime, tenant_id_a(), &b, &c).await;
        let _ = ingest_edge_for(&runtime, tenant_id_a(), &c, &d).await;
        let app = query_router(runtime);
        let response = app
            .clone()
            .oneshot(empty_get(&format!(
                "/query/nodes/{a}/bfs?direction=outgoing&limit=2"
            )))
            .await
            .unwrap();
        let first: Page<NodeId> = read_json(response).await;
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

    #[tokio::test]
    async fn node_bfs_returns_400_on_bad_direction() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let start = ingest_node_for(&runtime, tenant_id_a(), "ec2").await;
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!(
                "/query/nodes/{start}/bfs?direction=sideways"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
            let result = hydra
                .ingest_for_tenant(signal_event("kickoff"), tenant())
                .unwrap();
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
            let result = hydra
                .ingest_for_tenant(signal_event("only"), tenant())
                .unwrap();
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
                .ingest_for_tenant(
                    EventKind::NodeCreated {
                        node_id: NodeId::new(),
                        type_id: "ec2".to_string(),
                        properties: HashMap::new(),
                    },
                    tenant(),
                )
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
                .ingest_for_tenant(
                    EventKind::NodeCreated {
                        node_id: NodeId::new(),
                        type_id: "ec2".to_string(),
                        properties: HashMap::new(),
                    },
                    tenant(),
                )
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

    // === Tenant isolation (Multi-tenant Patch 2A) ===
    //
    // Focused tests that prove tenant A cannot see tenant B's data
    // across the main read families. Helper-test coverage (missing
    // tenant → 400, invalid tenant → 400) is centralized in
    // `http::tenant::tests` — these tests focus on isolation
    // behavior end-to-end through the router.

    fn tenant_b() -> TenantId {
        TenantId::from_str("tenant_other_b")
    }

    #[tokio::test]
    async fn list_claims_without_tenant_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get_without_tenant("/query/claims"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_claims_with_invalid_tenant_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get_for("/query/claims", "../../etc/passwd"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn tenant_a_sees_own_claim_not_tenant_b_claim() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let ev = evidence(); // tenant_id = tenant_http_query_test (tenant A)
        let claim_a = claim(ev.id.clone());
        let claim_a_id = claim_a.id.clone();

        let mut claim_b = claim(ev.id.clone());
        claim_b.tenant_id = Some(tenant_b());
        let claim_b_id = claim_b.id.clone();

        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest_event(event(EventKind::EvidenceAdded { evidence: ev }))
                .unwrap();
            hydra
                .ingest_event(event(EventKind::ClaimProposed { claim: claim_a }))
                .unwrap();
            // Build a tenant-B event envelope around the claim_b ingest.
            let event_b = Event {
                id: EventId::new(),
                tenant_id: Some(tenant_b()),
                timestamp: chrono::Utc::now(),
                kind: EventKind::ClaimProposed { claim: claim_b },
                caused_by: vec![],
                cascade_id: CascadeId::new(),
                cascade_depth: 0,
                cascade_breadth_index: 0,
            };
            hydra.ingest_event(event_b).unwrap();
        }
        let app = query_router(runtime);

        // Tenant A's list shows only claim_a.
        let response = app
            .clone()
            .oneshot(empty_get("/query/claims"))
            .await
            .unwrap();
        let decoded: Page<Claim> = read_json(response).await;
        assert_eq!(decoded.items.len(), 1);
        assert_eq!(decoded.items[0].id, claim_a_id);

        // Tenant A cannot get claim_b by id — 404, not 200 with body
        // and not 403 (no existence leak).
        let response = app
            .oneshot(empty_get(&format!("/query/claims/{claim_b_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn tenant_a_sees_own_evidence_only() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let ev_a = evidence(); // tenant A
        let ev_a_id = ev_a.id.clone();
        let ev_b = Evidence {
            id: EvidenceId::new(),
            tenant_id: Some(tenant_b()),
            ..evidence()
        };
        let ev_b_id = ev_b.id.clone();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest_event(event(EventKind::EvidenceAdded { evidence: ev_a }))
                .unwrap();
            let event_b = Event {
                id: EventId::new(),
                tenant_id: Some(tenant_b()),
                timestamp: chrono::Utc::now(),
                kind: EventKind::EvidenceAdded { evidence: ev_b },
                caused_by: vec![],
                cascade_id: CascadeId::new(),
                cascade_depth: 0,
                cascade_breadth_index: 0,
            };
            hydra.ingest_event(event_b).unwrap();
        }
        let app = query_router(runtime);

        let response = app
            .clone()
            .oneshot(empty_get("/query/evidence"))
            .await
            .unwrap();
        let decoded: Page<Evidence> = read_json(response).await;
        assert_eq!(decoded.items.len(), 1);
        assert_eq!(decoded.items[0].id, ev_a_id);

        let response = app
            .oneshot(empty_get(&format!("/query/evidence/{ev_b_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn tenant_a_sees_own_actions_only() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_a = action(); // tenant A (action() helper now stamps tenant)
        let action_a_id = action_a.id.clone();
        let action_b = Action {
            id: ActionId::new(),
            tenant_id: Some(tenant_b()),
            ..action()
        };
        let action_b_id = action_b.id.clone();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest_for_tenant(
                    EventKind::ActionProposed { action: action_a },
                    tenant(),
                )
                .unwrap();
            hydra
                .ingest_for_tenant(
                    EventKind::ActionProposed { action: action_b },
                    tenant_b(),
                )
                .unwrap();
        }
        let app = query_router(runtime);

        let response = app
            .clone()
            .oneshot(empty_get("/query/actions"))
            .await
            .unwrap();
        let decoded: Page<Action> = read_json(response).await;
        assert_eq!(decoded.items.len(), 1);
        assert_eq!(decoded.items[0].id, action_a_id);

        let response = app
            .oneshot(empty_get(&format!("/query/actions/{action_b_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn tenant_a_sees_own_sensor_checkpoints_only() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let sensor = SensorId::from_str("sensor_shared");
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            observe_for(&mut hydra, &sensor, "a1", tenant());
            observe_for(&mut hydra, &sensor, "b1", tenant_b());
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get("/query/sensors/sensor_shared/checkpoints"))
            .await
            .unwrap();
        let decoded: Page<SensorCheckpoint> = read_json(response).await;
        // Tenant A sees only their own checkpoint.
        assert_eq!(decoded.items.len(), 1);
        assert_eq!(
            decoded.items[0].tenant_id.as_ref().map(|t| t.to_string()),
            Some(tenant().to_string()),
        );
    }

    #[tokio::test]
    async fn causal_chain_seed_from_other_tenant_returns_404() {
        // Event ingested under tenant_b cannot be reached via
        // /query/events/:id/causal-chain by tenant_a (the default
        // header) — the seed lookup is gated by tenant ownership.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let seed_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra
                .ingest_for_tenant(
                    EventKind::Signal {
                        source: NodeId::from_str("other.tenant"),
                        name: "tenant_b_seed".to_string(),
                        payload: HashMap::new(),
                    },
                    tenant_b(),
                )
                .unwrap();
            seed_id = result.events[0].id.clone();
        }
        let app = query_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/query/events/{seed_id}/causal-chain")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn stats_returns_global_counts_with_any_tenant() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest_for_tenant(
                    EventKind::Signal {
                        source: NodeId::from_str("any"),
                        name: "a".to_string(),
                        payload: HashMap::new(),
                    },
                    tenant(),
                )
                .unwrap();
            hydra
                .ingest_for_tenant(
                    EventKind::Signal {
                        source: NodeId::from_str("any"),
                        name: "b".to_string(),
                        payload: HashMap::new(),
                    },
                    tenant_b(),
                )
                .unwrap();
        }
        let app = query_router(runtime);
        // Tenant A and tenant B both see the same global counts in v0.
        let response = app
            .clone()
            .oneshot(empty_get("/query/stats"))
            .await
            .unwrap();
        let a_view: StatsResponse = read_json(response).await;
        assert_eq!(a_view.total_events, 2);

        let response = app
            .oneshot(empty_get_for("/query/stats", "tenant_other_b"))
            .await
            .unwrap();
        let b_view: StatsResponse = read_json(response).await;
        assert_eq!(b_view.total_events, 2);
    }
}
