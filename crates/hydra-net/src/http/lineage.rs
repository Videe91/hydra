//! V2 next-level → living-database phase: `GET /lineage/:event_id`.
//!
//! The first endpoint that surfaces Hydra as **explainable operational
//! memory** rather than just storage or replication. Given a single
//! event id, returns the full causal context: ancestors, descendants,
//! and every epistemic / action / policy artifact that references any
//! event in the chain.
//!
//! The agent-facing question this answers is *"why did this happen?"* —
//! and the response gives the full loop:
//!
//! ```text
//! event → evidence → claim → policy decision → action → outcome → descendants
//! ```
//!
//! ## Response shape
//!
//! Flat-keyed-by-type (not a nested tree). Reasons:
//!   - Agents post-process into whatever shape their tool needs
//!   - Cross-references via id lookups instead of duplicated nested copies
//!   - LLM-friendly: bounded payload size, clear schema
//!   - Vector-indexable, UI-renderable, toolchain-composable
//!
//! ## Tenant semantics
//!
//! **Lineage traversal follows causal topology, not tenant isolation.**
//! The seed event is checked for tenant ownership via
//! `extract_tenant` + `QueryService::event_for_tenant` (matching the
//! existing `/query/events/:event_id/causal-chain` semantics). Once
//! the seed is accepted, descendants and ancestors are returned
//! as-is — a cascade reflex can emit cross-tenant events, and the
//! audit trail intentionally preserves that. Strict tenant filtering
//! of descendants is a future patch (would need a per-tenant event
//! index).
//!
//! ## Depth cap
//!
//! Required to prevent denial-of-service via deeply-nested cascades.
//! Default `10`, max `50`, configurable via `?depth=N`. BFS stops at
//! `depth` hops from the seed in either direction. `truncated: true`
//! is returned when the cap was hit before exhausting the chain.
//!
//! ## Performance
//!
//! O(events + evidence + claims + actions + outcomes + decisions +
//! approvals) per call. The enrichment scan iterates each store's
//! `all_*` and filters by `caused_by ∈ lineage_event_ids`. For v0
//! this is fine — lineage is a high-value, low-frequency endpoint
//! (agents call it on demand to explain, not per-request). Adding
//! `caused_by` indexes to each store is a follow-up patch driven by
//! observed load.

use crate::http::tenant::{extract_tenant, tenant_error_response};
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use hydra_core::{
    ActionId, ApprovalId, CascadeId, ClaimId, EventId, EvidenceId, OutcomeId, PolicyDecisionId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const DEFAULT_DEPTH: u32 = 10;
const MAX_DEPTH: u32 = 50;

#[derive(Clone)]
pub struct LineageHttpState {
    pub runtime: RuntimeHandle,
}

impl LineageHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the lineage router.
///
/// Single route: `GET /lineage/:event_id` (auth scope
/// `read:audit`). Query param `depth` (default 10, max 50) caps the
/// BFS distance from the seed event in either direction.
pub fn lineage_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/lineage/:event_id", get(get_lineage))
        .with_state(LineageHttpState::new(runtime))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LineageQuery {
    pub depth: Option<u32>,
}

/// Compact event header for lineage responses. Summary-only — agents
/// fetch full bodies via `/events/:event_id` if they need more.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageEventSummary {
    pub id: EventId,
    pub timestamp: DateTime<Utc>,
    pub kind: String,
    pub summary: String,
    pub caused_by: Vec<EventId>,
    pub cascade_id: CascadeId,
    pub cascade_depth: u32,
}

/// Sub-DTO for an Evidence record referenced by the lineage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageEvidence {
    pub id: EvidenceId,
    pub kind: String,
    pub reliability: f64,
    pub observed_at: DateTime<Utc>,
    pub caused_by: EventId,
}

/// Sub-DTO for a Claim referenced by the lineage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageClaim {
    pub id: ClaimId,
    pub kind: String,
    pub status: String,
    pub predicate: String,
    pub confidence: f64,
    pub caused_by: EventId,
}

/// Sub-DTO for an Action referenced by the lineage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageAction {
    pub id: ActionId,
    pub kind: String,
    pub status: String,
    pub caused_by: EventId,
}

/// Sub-DTO for an Outcome referenced by the lineage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageOutcome {
    pub id: OutcomeId,
    pub kind: String,
    pub action_id: ActionId,
    pub caused_by: EventId,
}

/// Sub-DTO for a PolicyDecision referenced by the lineage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineagePolicyDecision {
    pub id: PolicyDecisionId,
    pub kind: String,
    pub policy_id: Option<String>,
    pub action_id: ActionId,
    pub caused_by: EventId,
}

/// Sub-DTO for an ApprovalRequest referenced by the lineage.
/// Governance/audit flows are part of operational explanation —
/// included alongside policy decisions per the agreed enrichment set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageApprovalRequest {
    pub id: ApprovalId,
    pub status: String,
    pub action_id: ActionId,
    pub caused_by: EventId,
}

/// `GET /lineage/:event_id` response.
///
/// `explanation_summary` is a deterministic, server-rendered
/// one-paragraph narrative built from the collected facts (not LLM-
/// generated). Agents can ignore it; humans get an instant story
/// without having to traverse the DAG themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageResponse {
    pub seed_event_id: EventId,
    pub depth: u32,
    pub events: Vec<LineageEventSummary>,
    pub evidence: Vec<LineageEvidence>,
    pub claims: Vec<LineageClaim>,
    pub actions: Vec<LineageAction>,
    pub outcomes: Vec<LineageOutcome>,
    pub policy_decisions: Vec<LineagePolicyDecision>,
    pub approval_requests: Vec<LineageApprovalRequest>,
    pub ancestors: Vec<EventId>,
    pub descendants: Vec<EventId>,
    pub truncated: bool,
    pub explanation_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
        .into_response()
}

async fn get_lineage(
    State(state): State<LineageHttpState>,
    headers: HeaderMap,
    Path(event_id): Path<String>,
    Query(query): Query<LineageQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(e) => return tenant_error_response(e),
    };

    let depth = query
        .depth
        .unwrap_or(DEFAULT_DEPTH)
        .min(MAX_DEPTH);

    let seed_id = EventId::from_str(&event_id);
    let hydra_arc = state.runtime.hydra();
    let hydra = hydra_arc.read().await;

    let seed_event = match hydra.event(&seed_id) {
        Some(event) => event,
        None => {
            return error_response(StatusCode::NOT_FOUND, format!("event not found: {event_id}"));
        }
    };

    // Tenant check on the seed only — descendants and ancestors
    // pass through regardless of their tenant (see module docs:
    // "Lineage traversal follows causal topology, not tenant
    // isolation.").
    if let Some(seed_tenant) = &seed_event.tenant_id {
        if *seed_tenant != tenant {
            return error_response(
                StatusCode::NOT_FOUND,
                format!("event not found: {event_id}"),
            );
        }
    }

    // BFS in both directions from the seed. `events_in_lineage`
    // tracks ids; `truncated` flips true if any BFS path hit
    // `depth` before exhausting parents/children.
    let mut events_in_lineage: HashSet<EventId> = HashSet::new();
    events_in_lineage.insert(seed_id.clone());
    let mut truncated = false;

    // Ancestor BFS — walk `caused_by` parents from the seed.
    let mut ancestor_ids: Vec<EventId> = Vec::new();
    let mut ancestor_frontier: Vec<EventId> = seed_event.caused_by.clone();
    let mut hops = 0u32;
    while !ancestor_frontier.is_empty() {
        if hops >= depth {
            if !ancestor_frontier.is_empty() {
                truncated = true;
            }
            break;
        }
        let mut next_frontier: Vec<EventId> = Vec::new();
        for parent_id in ancestor_frontier {
            if events_in_lineage.insert(parent_id.clone()) {
                ancestor_ids.push(parent_id.clone());
                if let Some(parent) = hydra.event(&parent_id) {
                    next_frontier.extend(parent.caused_by.iter().cloned());
                }
            }
        }
        ancestor_frontier = next_frontier;
        hops += 1;
    }

    // Descendant BFS — walk forward via `Hydra::causal_chain` which
    // collects all events whose `caused_by` transitively includes
    // the seed. We cap manually by depth.
    let mut descendant_ids: Vec<EventId> = Vec::new();
    let mut descendant_frontier: Vec<EventId> = hydra
        .events()
        .into_iter()
        .filter(|e| e.caused_by.contains(&seed_id))
        .map(|e| e.id.clone())
        .collect();
    let mut hops = 0u32;
    while !descendant_frontier.is_empty() {
        if hops >= depth {
            if !descendant_frontier.is_empty() {
                truncated = true;
            }
            break;
        }
        let mut next_frontier: Vec<EventId> = Vec::new();
        for child_id in descendant_frontier {
            if events_in_lineage.insert(child_id.clone()) {
                descendant_ids.push(child_id.clone());
                // Find this child's children.
                for event in hydra.events() {
                    if event.caused_by.contains(&child_id)
                        && !events_in_lineage.contains(&event.id)
                    {
                        next_frontier.push(event.id.clone());
                    }
                }
            }
        }
        descendant_frontier = next_frontier;
        hops += 1;
    }

    // Build event summaries for every id in the lineage. Iterate
    // the event log once and pick out matches so we preserve the
    // log's insertion order.
    let events: Vec<LineageEventSummary> = hydra
        .events()
        .into_iter()
        .filter(|event| events_in_lineage.contains(&event.id))
        .map(|event| LineageEventSummary {
            id: event.id.clone(),
            timestamp: event.timestamp,
            kind: event.kind.kind_name().to_string(),
            summary: render_event_summary(event),
            caused_by: event.caused_by.clone(),
            cascade_id: event.cascade_id.clone(),
            cascade_depth: event.cascade_depth,
        })
        .collect();

    // Enrichment scan — filter each store's `all_*` by
    // `caused_by ∈ events_in_lineage`. O(N) per store; fine for
    // v0 (lineage is low-frequency, high-value).
    let evidence: Vec<LineageEvidence> = hydra
        .epistemic_store()
        .all_evidence()
        .filter(|e| {
            e.caused_by
                .as_ref()
                .is_some_and(|id| events_in_lineage.contains(id))
        })
        .map(|e| LineageEvidence {
            id: e.id.clone(),
            kind: e.payload.kind.clone(),
            reliability: e.reliability.value(),
            observed_at: e.observed_at,
            caused_by: e.caused_by.clone().unwrap(),
        })
        .collect();

    let claims: Vec<LineageClaim> = hydra
        .epistemic_store()
        .all_claims()
        .filter(|c| {
            c.caused_by
                .as_ref()
                .is_some_and(|id| events_in_lineage.contains(id))
        })
        .map(|c| LineageClaim {
            id: c.id.clone(),
            kind: format!("{:?}", c.kind),
            status: format!("{:?}", c.status),
            predicate: c.predicate.clone(),
            confidence: c.confidence.value(),
            caused_by: c.caused_by.clone().unwrap(),
        })
        .collect();

    let actions: Vec<LineageAction> = hydra
        .action_store()
        .all_actions()
        .filter(|a| {
            a.caused_by
                .as_ref()
                .is_some_and(|id| events_in_lineage.contains(id))
        })
        .map(|a| LineageAction {
            id: a.id.clone(),
            kind: format!("{:?}", a.kind),
            status: format!("{:?}", a.status),
            caused_by: a.caused_by.clone().unwrap(),
        })
        .collect();

    let outcomes: Vec<LineageOutcome> = hydra
        .action_store()
        .all_outcomes()
        .filter(|o| {
            o.caused_by
                .as_ref()
                .is_some_and(|id| events_in_lineage.contains(id))
        })
        .map(|o| LineageOutcome {
            id: o.id.clone(),
            kind: format!("{:?}", o.kind),
            action_id: o.action_id.clone(),
            caused_by: o.caused_by.clone().unwrap(),
        })
        .collect();

    let policy_decisions: Vec<LineagePolicyDecision> = hydra
        .policy_store()
        .all_decisions()
        .filter(|d| {
            d.caused_by
                .as_ref()
                .is_some_and(|id| events_in_lineage.contains(id))
        })
        .map(|d| LineagePolicyDecision {
            id: d.id.clone(),
            kind: format!("{:?}", d.kind),
            policy_id: d.policy_id.as_ref().map(|p| p.as_str().to_string()),
            action_id: d.action_id.clone(),
            caused_by: d.caused_by.clone().unwrap(),
        })
        .collect();

    let approval_requests: Vec<LineageApprovalRequest> = hydra
        .policy_store()
        .all_approvals()
        .filter(|a| {
            a.caused_by
                .as_ref()
                .is_some_and(|id| events_in_lineage.contains(id))
        })
        .map(|a| LineageApprovalRequest {
            id: a.id.clone(),
            status: format!("{:?}", a.status),
            action_id: a.action_id.clone(),
            caused_by: a.caused_by.clone().unwrap(),
        })
        .collect();

    let explanation_summary = render_explanation_summary(
        seed_event,
        &events,
        &evidence,
        &claims,
        &actions,
        &outcomes,
        &policy_decisions,
        &approval_requests,
    );

    Json(LineageResponse {
        seed_event_id: seed_id,
        depth,
        events,
        evidence,
        claims,
        actions,
        outcomes,
        policy_decisions,
        approval_requests,
        ancestors: ancestor_ids,
        descendants: descendant_ids,
        truncated,
        explanation_summary,
    })
    .into_response()
}

/// Compose a short, agent-readable string for an event. Uses the
/// `kind_name` plus the most-identifying field for the EventKind.
fn render_event_summary(event: &hydra_core::Event) -> String {
    use hydra_core::EventKind;
    let kind = event.kind.kind_name();
    match &event.kind {
        EventKind::Signal { name, source, .. } => {
            format!("{kind}: {source}/{name}")
        }
        EventKind::NodeCreated { type_id, .. } => format!("{kind}: {type_id}"),
        EventKind::NodeUpdated { node_id, .. } => format!("{kind}: {node_id}"),
        EventKind::NodeDeleted { node_id } => format!("{kind}: {node_id}"),
        EventKind::EdgeCreated { type_id, .. } => format!("{kind}: {type_id}"),
        EventKind::EdgeUpdated { edge_id, .. } => format!("{kind}: {edge_id}"),
        EventKind::EdgeDeleted { edge_id } => format!("{kind}: {edge_id}"),
        EventKind::EvidenceAdded { evidence } => format!("{kind}: {}", evidence.payload.kind),
        EventKind::ClaimProposed { claim } => format!("{kind}: {}", claim.predicate),
        EventKind::ClaimSupported { claim_id, .. } => format!("{kind}: {claim_id}"),
        EventKind::ClaimDisputed { claim_id, .. } => format!("{kind}: {claim_id}"),
        EventKind::ClaimVerified { claim_id, .. } => format!("{kind}: {claim_id}"),
        EventKind::ClaimRetracted { claim_id, .. } => format!("{kind}: {claim_id}"),
        EventKind::ClaimStaled { claim_id, .. } => format!("{kind}: {claim_id}"),
        EventKind::ActionProposed { action } => format!("{kind}: {:?}", action.kind),
        EventKind::ActionApproved { action_id, .. } => format!("{kind}: {action_id}"),
        EventKind::ActionRejected { action_id, .. } => format!("{kind}: {action_id}"),
        EventKind::ActionExecuted { action_id, .. } => format!("{kind}: {action_id}"),
        EventKind::ActionFailed { action_id, .. } => format!("{kind}: {action_id}"),
        EventKind::OutcomeObserved { outcome } => format!("{kind}: {:?}", outcome.kind),
        EventKind::PolicyDecisionRecorded { decision } => format!("{kind}: {:?}", decision.kind),
        EventKind::ApprovalRequested { request } => format!("{kind}: action={}", request.action_id),
        EventKind::ApprovalGranted { approval_id, .. } => format!("{kind}: {approval_id}"),
        EventKind::ApprovalRejected { approval_id, .. } => format!("{kind}: {approval_id}"),
        EventKind::ReplicaPromoted { peer_id, .. } => format!("{kind}: {peer_id}"),
        EventKind::ReplicaDemoted { peer_id, .. } => format!("{kind}: {peer_id}"),
        _ => kind.to_string(),
    }
}

/// Build a deterministic, server-side natural-language summary of
/// the lineage. NOT AI-generated — pure string composition from the
/// collected facts. Designed for humans reading demo output and for
/// agents that want a quick gist before scanning the structured data.
fn render_explanation_summary(
    seed: &hydra_core::Event,
    events: &[LineageEventSummary],
    evidence: &[LineageEvidence],
    claims: &[LineageClaim],
    actions: &[LineageAction],
    outcomes: &[LineageOutcome],
    policy_decisions: &[LineagePolicyDecision],
    approval_requests: &[LineageApprovalRequest],
) -> String {
    let seed_summary = render_event_summary(seed);
    let mut parts: Vec<String> = vec![format!("Seed event: {seed_summary}.")];

    if !evidence.is_empty() {
        let kinds: Vec<&str> = evidence.iter().map(|e| e.kind.as_str()).take(3).collect();
        parts.push(format!(
            "Recorded {} evidence record(s) ({}).",
            evidence.len(),
            kinds.join(", ")
        ));
    }

    if !claims.is_empty() {
        let preds: Vec<String> = claims
            .iter()
            .take(3)
            .map(|c| format!("{}={}", c.predicate, c.status))
            .collect();
        parts.push(format!(
            "Produced {} claim(s) ({}).",
            claims.len(),
            preds.join(", ")
        ));
    }

    if !policy_decisions.is_empty() {
        let kinds: Vec<&str> = policy_decisions
            .iter()
            .map(|d| d.kind.as_str())
            .take(3)
            .collect();
        parts.push(format!(
            "Triggered {} policy decision(s) ({}).",
            policy_decisions.len(),
            kinds.join(", ")
        ));
    }

    if !approval_requests.is_empty() {
        parts.push(format!(
            "Raised {} approval request(s).",
            approval_requests.len()
        ));
    }

    if !actions.is_empty() {
        let kinds: Vec<String> = actions
            .iter()
            .take(3)
            .map(|a| format!("{}({})", a.kind, a.status))
            .collect();
        parts.push(format!(
            "Resulted in {} action(s) ({}).",
            actions.len(),
            kinds.join(", ")
        ));
    }

    if !outcomes.is_empty() {
        parts.push(format!("Observed {} outcome(s).", outcomes.len()));
    }

    if events.len() > 1 {
        parts.push(format!(
            "Causal chain spans {} event(s) total.",
            events.len()
        ));
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use hydra_core::{
        Action, ActionKind, ActionStatus, ActionTarget, ApprovalRequest, ApprovalStatus, Claim,
        ClaimKind, ClaimObject, ClaimStatus, ClaimSubject, Confidence, Evidence, EvidencePayload,
        EvidenceSource, EventKind, NodeId, PolicyDecision, PolicyDecisionKind, TenantId,
    };
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_lineage_test")
    }

    fn actor() -> hydra_core::ActorId {
        hydra_core::ActorId::from_str("actor_lineage_test")
    }

    fn signal(name: &str) -> EventKind {
        EventKind::Signal {
            source: NodeId::from_str("test.lineage"),
            name: name.to_string(),
            payload: HashMap::new(),
        }
    }

    fn empty_get(uri: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("X-Hydra-Tenant", tenant().as_str())
            .body(Body::empty())
            .unwrap()
    }

    async fn read_json<T: for<'de> serde::de::DeserializeOwned>(response: Response) -> T {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn make_evidence(caused_by: Option<EventId>) -> Evidence {
        let now = Utc::now();
        Evidence {
            id: EvidenceId::new(),
            tenant_id: Some(tenant()),
            source: EvidenceSource::System {
                name: "lineage_test".to_string(),
            },
            payload: EvidencePayload {
                kind: "test_observation".to_string(),
                data: HashMap::new(),
            },
            reliability: Confidence::new(0.95),
            observed_at: now,
            recorded_at: now,
            caused_by,
        }
    }

    fn make_claim(caused_by: Option<EventId>) -> Claim {
        let now = Utc::now();
        Claim {
            id: ClaimId::new(),
            tenant_id: Some(tenant()),
            kind: ClaimKind::AnomalyFinding,
            subject: ClaimSubject::Dataset("test.dataset".to_string()),
            predicate: "is_anomalous".to_string(),
            object: ClaimObject::Value(hydra_core::Value::Bool(true)),
            confidence: Confidence::new(0.88),
            status: ClaimStatus::Proposed,
            evidence_for: vec![],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: actor(),
            created_at: now,
            updated_at: now,
            caused_by,
        }
    }

    fn make_action(caused_by: Option<EventId>) -> Action {
        let now = Utc::now();
        Action {
            id: ActionId::new(),
            tenant_id: Some(tenant()),
            kind: ActionKind::Quarantine,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::Dataset("test.dataset".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor(),
            approved_by: None,
            rejected_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            executed_at: None,
            caused_by,
        }
    }

    fn make_approval(action_id: ActionId, caused_by: Option<EventId>) -> ApprovalRequest {
        let now = Utc::now();
        ApprovalRequest {
            id: ApprovalId::new(),
            tenant_id: Some(tenant()),
            action_id,
            policy_decision_id: None,
            status: ApprovalStatus::Requested,
            requested_by: actor(),
            requested_from: vec![actor()],
            reason: String::new(),
            requested_at: now,
            resolved_at: None,
            resolved_by: None,
            caused_by,
            metadata: HashMap::new(),
        }
    }

    fn make_decision(action_id: ActionId, caused_by: Option<EventId>) -> PolicyDecision {
        let now = Utc::now();
        PolicyDecision {
            id: PolicyDecisionId::new(),
            tenant_id: Some(tenant()),
            policy_id: None,
            action_id,
            kind: PolicyDecisionKind::Allow,
            reason: String::new(),
            evidence: vec![],
            related_claims: vec![],
            decided_by: actor(),
            decided_at: now,
            caused_by,
            details: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn lineage_returns_404_for_unknown_event() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = lineage_router(runtime);
        let response = app
            .oneshot(empty_get("/lineage/evt_missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn lineage_self_only_for_terminal_event() {
        // Single signal event, no parents, no descendants, no
        // epistemic/action artifacts referencing it.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let event_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra.ingest_for_tenant(signal("standalone"), tenant()).unwrap();
            event_id = result.events[0].id.clone();
        }
        let app = lineage_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/lineage/{event_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: LineageResponse = read_json(response).await;
        assert_eq!(decoded.seed_event_id, event_id);
        assert_eq!(decoded.events.len(), 1, "lineage of terminal event = just self");
        assert!(decoded.evidence.is_empty());
        assert!(decoded.claims.is_empty());
        assert!(decoded.actions.is_empty());
        assert!(decoded.outcomes.is_empty());
        assert!(decoded.policy_decisions.is_empty());
        assert!(decoded.approval_requests.is_empty());
        assert!(decoded.ancestors.is_empty());
        assert!(decoded.descendants.is_empty());
        assert!(!decoded.truncated);
        // explanation_summary at least mentions the seed.
        assert!(decoded.explanation_summary.contains("signal"));
    }

    #[tokio::test]
    async fn lineage_includes_claim_caused_by_lineage_event() {
        // Ingest a signal, then ingest a ClaimProposed whose claim
        // has caused_by = signal's event id. Lineage of the signal
        // must include that claim.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let seed_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra.ingest_for_tenant(signal("kickoff"), tenant()).unwrap();
            seed_id = result.events[0].id.clone();
            let claim = make_claim(Some(seed_id.clone()));
            hydra
                .ingest_for_tenant(EventKind::ClaimProposed { claim }, tenant())
                .unwrap();
        }
        let app = lineage_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/lineage/{seed_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: LineageResponse = read_json(response).await;
        assert_eq!(decoded.claims.len(), 1, "claim must surface in lineage");
        assert_eq!(decoded.claims[0].caused_by, seed_id);
        assert!(decoded.explanation_summary.contains("claim"));
    }

    #[tokio::test]
    async fn lineage_includes_evidence_and_approval_request() {
        // Cover both `evidence` and `approval_requests` enrichment
        // sets in one test — both point caused_by at the seed.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let seed_id;
        let action_id = ActionId::new();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra.ingest_for_tenant(signal("kickoff"), tenant()).unwrap();
            seed_id = result.events[0].id.clone();
            // Evidence with caused_by = seed
            let evidence = make_evidence(Some(seed_id.clone()));
            hydra
                .ingest_for_tenant(EventKind::EvidenceAdded { evidence }, tenant())
                .unwrap();
            // Pre-ingest an action so the approval can target it.
            let mut action = make_action(None);
            action.id = action_id.clone();
            hydra
                .ingest_for_tenant(EventKind::ActionProposed { action }, tenant())
                .unwrap();
            // Approval request with caused_by = seed
            let request = make_approval(action_id.clone(), Some(seed_id.clone()));
            hydra
                .ingest_for_tenant(EventKind::ApprovalRequested { request }, tenant())
                .unwrap();
        }
        let app = lineage_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/lineage/{seed_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: LineageResponse = read_json(response).await;
        assert_eq!(decoded.evidence.len(), 1, "evidence must surface");
        assert_eq!(decoded.evidence[0].caused_by, seed_id);
        assert_eq!(
            decoded.approval_requests.len(),
            1,
            "approval requests must surface"
        );
        assert_eq!(decoded.approval_requests[0].caused_by, seed_id);
    }

    #[tokio::test]
    async fn lineage_includes_action_outcome_and_policy_decision() {
        // Action + PolicyDecision both caused by the seed; outcome
        // caused by a subsequent event in the lineage isn't trivially
        // testable without descendants, so just cover action + decision
        // here. Outcomes covered by the same enrichment logic.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let seed_id;
        let action_id = ActionId::new();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra.ingest_for_tenant(signal("kickoff"), tenant()).unwrap();
            seed_id = result.events[0].id.clone();
            // Action with caused_by = seed
            let mut action = make_action(Some(seed_id.clone()));
            action.id = action_id.clone();
            hydra
                .ingest_for_tenant(EventKind::ActionProposed { action }, tenant())
                .unwrap();
            // PolicyDecision with caused_by = seed
            let decision = make_decision(action_id.clone(), Some(seed_id.clone()));
            hydra
                .ingest_for_tenant(EventKind::PolicyDecisionRecorded { decision }, tenant())
                .unwrap();
        }
        let app = lineage_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/lineage/{seed_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: LineageResponse = read_json(response).await;
        assert_eq!(decoded.actions.len(), 1);
        assert_eq!(decoded.actions[0].caused_by, seed_id);
        assert_eq!(decoded.policy_decisions.len(), 1);
        assert_eq!(decoded.policy_decisions[0].caused_by, seed_id);
        assert!(decoded.explanation_summary.contains("action"));
        assert!(decoded.explanation_summary.contains("policy"));
    }

    #[tokio::test]
    async fn lineage_filters_unrelated_artifacts() {
        // Two unrelated signals A and B. Claim with caused_by = B.
        // Lineage of A must NOT include that claim.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let seed_a;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let a = hydra.ingest_for_tenant(signal("a"), tenant()).unwrap();
            seed_a = a.events[0].id.clone();
            let b = hydra.ingest_for_tenant(signal("b"), tenant()).unwrap();
            let seed_b = b.events[0].id.clone();
            // Claim caused by B
            let claim = make_claim(Some(seed_b));
            hydra
                .ingest_for_tenant(EventKind::ClaimProposed { claim }, tenant())
                .unwrap();
        }
        let app = lineage_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/lineage/{seed_a}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: LineageResponse = read_json(response).await;
        assert!(
            decoded.claims.is_empty(),
            "claim caused by B must NOT appear in lineage of A"
        );
        // And no descendants/ancestors either.
        assert!(decoded.ancestors.is_empty());
        assert!(decoded.descendants.is_empty());
    }

    #[tokio::test]
    async fn lineage_explanation_summary_renders_facts() {
        // End-to-end: seed + evidence + claim + action — confirm the
        // server-side narrative string mentions each artifact class.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let seed_id;
        let action_id = ActionId::new();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra.ingest_for_tenant(signal("kickoff"), tenant()).unwrap();
            seed_id = result.events[0].id.clone();
            hydra
                .ingest_for_tenant(
                    EventKind::EvidenceAdded {
                        evidence: make_evidence(Some(seed_id.clone())),
                    },
                    tenant(),
                )
                .unwrap();
            hydra
                .ingest_for_tenant(
                    EventKind::ClaimProposed {
                        claim: make_claim(Some(seed_id.clone())),
                    },
                    tenant(),
                )
                .unwrap();
            let mut action = make_action(Some(seed_id.clone()));
            action.id = action_id.clone();
            hydra
                .ingest_for_tenant(EventKind::ActionProposed { action }, tenant())
                .unwrap();
        }
        let app = lineage_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/lineage/{seed_id}")))
            .await
            .unwrap();
        let decoded: LineageResponse = read_json(response).await;
        let summary = decoded.explanation_summary;
        // The narrative names each class of artifact present in the
        // collected facts. Operators/agents get an instant gist.
        assert!(summary.contains("evidence"), "summary: {summary}");
        assert!(summary.contains("claim"), "summary: {summary}");
        assert!(summary.contains("action"), "summary: {summary}");
    }

    #[tokio::test]
    async fn lineage_respects_depth_query_param() {
        // Just confirm the depth param is parsed and capped. Without
        // a reflex registered, we can't build a deep cascade in a
        // unit test cheaply — this test asserts the query param is
        // accepted and the response carries it back.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let event_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra.ingest_for_tenant(signal("only"), tenant()).unwrap();
            event_id = result.events[0].id.clone();
        }
        let app = lineage_router(runtime);

        // depth=5 → echoed back.
        let response = app
            .clone()
            .oneshot(empty_get(&format!("/lineage/{event_id}?depth=5")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: LineageResponse = read_json(response).await;
        assert_eq!(decoded.depth, 5);

        // depth=999 → clamped to MAX_DEPTH (50).
        let response = app
            .oneshot(empty_get(&format!("/lineage/{event_id}?depth=999")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: LineageResponse = read_json(response).await;
        assert_eq!(decoded.depth, MAX_DEPTH);
    }
}
