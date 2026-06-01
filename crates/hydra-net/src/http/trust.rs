//! Trust Patch 2 (Patch 10) — Trust HTTP surface.
//!
//! Exposes the engine's `Hydra::assess_claim_trust` (Patch 9) as
//! an HTTP endpoint so agents and operators can read claim trust
//! judgments from outside Rust:
//!
//! ```text
//! GET /trust/claims/:claim_id
//! ```
//!
//! ## Namespace
//!
//! `/trust/*` is reserved for the whole Trust Layer. v0 (Patch 10)
//! mounts only `/trust/claims/:id`; future patches will add
//! `/trust/sources/*`, `/trust/datasets/*`, `/trust/actions/*`,
//! `/trust/models/*`, etc. All share the same `read:trust` scope.
//!
//! ## Auth
//!
//! New scope `read:trust` (added in `hydra-api::auth`). Trust is
//! not just query data — it's governance / intelligence state.
//! Separate scope so an operator granted `read:query` doesn't
//! automatically see trust judgments.
//!
//! ## Tenant isolation (strict)
//!
//! Mirrors `/query/claims/:id`. The `X-Hydra-Tenant` header is
//! REQUIRED; missing → 400. If the claim's tenant_id doesn't
//! match the header, the route returns 404 (not 403) — leaking
//! "this id exists but you can't see it" would itself be a
//! tenant-isolation breach.
//!
//! ## Wire form
//!
//! Returns `Json(TrustAssessment)` directly. `TrustLevel`
//! serializes as PascalCase (`"High"`, `"Medium"`, `"Low"`,
//! `"Unknown"`) via the default serde for `hydra_core::TrustLevel`.
//! No wire envelope — the response body IS the assessment.

use crate::http::tenant::{extract_tenant, tenant_error_response};
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hydra_core::{
    CausalCellId, ClaimId, IdentityAlias, IdentityEntityId, IdentityEntityKind,
};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct TrustHttpState {
    pub runtime: RuntimeHandle,
}

impl TrustHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the trust router. Routes:
///
/// - `/trust/claims/:claim_id`                — Patch 10 claim trust
/// - `/trust/cells/:cell_id`                  — Patch 24 cell trust
/// - `/trust/identity/entities/:entity_id`    — Patch 34 identity entity trust
/// - `/trust/identity/matches`                — Patch 34 identity match trust
///
/// **Auth scope precedence pin**: `/trust/identity/*` resolves to
/// `read:trust` via the `/trust/*` prefix clause in
/// `hydra-api::auth`, NOT to `read:identity` via the `/identity/*`
/// clause. The trust namespace wins because the trust-prefix
/// clause runs first. This is intentional — judgments over
/// identity are governance state, not graph data. Pinned by
/// auth tests.
///
/// Future patches mount alongside under the same `/trust/*`
/// prefix (Source Trust → `/trust/identity/sources/:id`, Link
/// Trust → `/trust/identity/links/:id`, etc.).
pub fn trust_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/trust/claims/:claim_id", get(get_claim_trust))
        .route("/trust/cells/:cell_id", get(get_cell_trust))
        .route(
            "/trust/identity/entities/:entity_id",
            get(get_identity_entity_trust),
        )
        .route(
            "/trust/identity/matches",
            get(get_identity_match_trust),
        )
        .with_state(TrustHttpState::new(runtime))
}

/// Query params for `GET /trust/identity/matches`. `source`,
/// `normalized`, and `candidate_entity_id` are REQUIRED; the
/// rest are optional. axum's `Query<T>` extractor returns 400
/// when required fields are absent.
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityMatchTrustQuery {
    pub source: String,
    pub normalized: String,
    pub candidate_entity_id: String,
    pub namespace: Option<String>,
    pub kind: Option<String>,
}

/// Parse a URL `?kind=<discriminant>` value into an
/// `IdentityEntityKind`. Duplicated from
/// `hydra-net/src/http/identity.rs::parse_identity_kind` for v0
/// — two callers with identical input shape but no coupling yet.
/// If a third caller appears, pull it up to a shared module.
fn parse_identity_kind(value: &str) -> Option<IdentityEntityKind> {
    if value.is_empty() {
        return None;
    }
    Some(match value {
        "dataset" => IdentityEntityKind::Dataset,
        "table" => IdentityEntityKind::Table,
        "dashboard" => IdentityEntityKind::Dashboard,
        "metric" => IdentityEntityKind::Metric,
        "service" => IdentityEntityKind::Service,
        "agent" => IdentityEntityKind::Agent,
        "workflow" => IdentityEntityKind::Workflow,
        "source" => IdentityEntityKind::Source,
        "user" => IdentityEntityKind::User,
        "system" => IdentityEntityKind::System,
        "incident" => IdentityEntityKind::Incident,
        other => IdentityEntityKind::Custom(other.to_string()),
    })
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

async fn get_claim_trust(
    State(state): State<TrustHttpState>,
    headers: HeaderMap,
    Path(claim_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };
    let id = ClaimId::from_str(&claim_id);

    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;

    // Strict tenant isolation: a claim that exists but belongs to
    // a different tenant is indistinguishable from "missing" from
    // the caller's perspective. Mirrors `/query/claims/:id`.
    match hydra.claim(&id) {
        Some(claim) if claim.tenant_id.as_ref() == Some(&tenant) => {}
        _ => {
            return error_response(
                StatusCode::NOT_FOUND,
                format!("claim not found: {claim_id}"),
            );
        }
    }

    match hydra.assess_claim_trust(&id) {
        Ok(assessment) => (StatusCode::OK, Json(assessment)).into_response(),
        Err(hydra_core::error::HydraError::QueryError(msg))
            if msg.contains("unknown claim") =>
        {
            // The tenant check above should have caught this, but
            // map defensively in case of race or future refactor.
            error_response(StatusCode::NOT_FOUND, msg)
        }
        Err(other) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("trust assessment failed: {other}"),
        ),
    }
}

/// `GET /trust/cells/:cell_id` — Patch 24 causal-cell trust
/// surface. Mirrors `/trust/claims/:claim_id` semantics:
///
/// - strict `X-Hydra-Tenant` required (400 if missing)
/// - unknown cell OR wrong tenant → 404 (indistinguishable)
/// - `None`-tenanted cells are INVISIBLE to tenanted queries
///   (no cross-tenant leakage by design)
/// - dangling child reference inside a composed cell (rare,
///   indicates store corruption) → 500
///
/// Returns `Json(CausalCellTrustAssessment)` directly — no wire
/// envelope. Reuses `TrustLevel` + `TrustFactor` serde via the
/// embedded factor list.
async fn get_cell_trust(
    State(state): State<TrustHttpState>,
    headers: HeaderMap,
    Path(cell_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };
    let id = CausalCellId::from_str(&cell_id);

    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;

    // Strict tenant isolation: a cell that exists but belongs to
    // a different tenant — OR a `None`-tenanted system cell —
    // is indistinguishable from "missing" from the caller's
    // perspective. Mirrors `/trust/claims/:id`.
    match hydra.causal_cell(&id) {
        Some(cell) if cell.tenant_id.as_ref() == Some(&tenant) => {}
        _ => {
            return error_response(
                StatusCode::NOT_FOUND,
                format!("causal cell not found: {cell_id}"),
            );
        }
    }

    match hydra.assess_causal_cell_trust(&id) {
        Ok(assessment) => (StatusCode::OK, Json(assessment)).into_response(),
        Err(hydra_core::error::HydraError::QueryError(msg))
            if msg.contains("unknown causal cell") =>
        {
            // Tenant pre-check should have caught this, but map
            // defensively in case of race or future refactor.
            error_response(StatusCode::NOT_FOUND, msg)
        }
        Err(hydra_core::error::HydraError::QueryError(msg))
            if msg.contains("references unknown child") =>
        {
            // Patch 23's defensive corruption error — a composed
            // cell that survived ingest references a child that
            // isn't in the store. 500 is the honest signal: the
            // request was well-formed; the engine state isn't.
            error_response(StatusCode::INTERNAL_SERVER_ERROR, msg)
        }
        Err(other) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cell trust assessment failed: {other}"),
        ),
    }
}

/// `GET /trust/identity/entities/:entity_id` — Patch 34
/// identity entity trust surface. Exposes the Patch 33
/// `Hydra::assess_identity_entity_trust` verdict over HTTP.
///
/// Strict tenant scoping carries forward from P33:
/// - missing `X-Hydra-Tenant` → 400
/// - unknown entity / wrong tenant / `None`-tenanted entity
///   under tenanted query → 404 with engine message
/// - happy path → 200 with bare `IdentityEntityTrustAssessment`
///   body (no envelope — matches `/trust/claims/:id` and
///   `/trust/cells/:id` conventions from P10/P24)
///
/// **Suggestion-only contract carries forward**: the verdict
/// judges the IDENTITY RECORD ITSELF, not operational truth.
/// See the engine method docstring for the full warning.
async fn get_identity_entity_trust(
    State(state): State<TrustHttpState>,
    headers: HeaderMap,
    Path(entity_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };
    let id = IdentityEntityId::from_str(&entity_id);

    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;

    match hydra.assess_identity_entity_trust(Some(&tenant), &id) {
        Ok(assessment) => (StatusCode::OK, Json(assessment)).into_response(),
        Err(hydra_core::error::HydraError::QueryError(msg))
            if msg.contains("unknown identity entity") =>
        {
            // Engine returns the same QueryError for genuine
            // miss + wrong tenant + None/Some slot mismatch.
            // Map to 404 with the engine message so operators
            // see the entity id but no cross-tenant existence
            // leak.
            error_response(StatusCode::NOT_FOUND, msg)
        }
        Err(other) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("identity entity trust assessment failed: {other}"),
        ),
    }
}

/// `GET /trust/identity/matches` — Patch 34 identity match
/// trust surface. Exposes the Patch 32
/// `Hydra::assess_identity_match_trust` verdict over HTTP.
///
/// Required query params (axum returns 400 if any are absent):
///
/// - `source`
/// - `normalized`
/// - `candidate_entity_id`
///
/// Optional:
///
/// - `namespace`
/// - `kind` — snake_case discriminant or `Custom(s)` fallback;
///   empty string → 400
///
/// Synthesizes the query alias server-side
/// (`external_id: None`, `label: normalized.clone()`) and
/// delegates to the engine. Strict tenant scoping carries
/// forward from P32.
///
/// Response: bare `IdentityMatchTrustAssessment` body (same
/// no-envelope convention as the other `/trust/*` routes).
/// Carries BOTH axes: `match_score`/`match_level` (P30
/// similarity) AND `score`/`level` (P32 trust verdict).
///
/// **Suggestion-only contract**: identity match trust is
/// calibrated for explainability, NOT correctness. False
/// positives expected. Auto-actions or auto-linking require
/// separate gates AND a durable `IdentityLink` audit event
/// (P36+).
async fn get_identity_match_trust(
    State(state): State<TrustHttpState>,
    headers: HeaderMap,
    Query(query): Query<IdentityMatchTrustQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };

    if query.source.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "source query parameter cannot be empty",
        );
    }
    if query.normalized.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "normalized query parameter cannot be empty",
        );
    }
    if query.candidate_entity_id.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "candidate_entity_id query parameter cannot be empty",
        );
    }

    let kind = match query.kind.as_deref() {
        Some(s) => match parse_identity_kind(s) {
            Some(k) => Some(k),
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "kind query parameter cannot be empty",
                );
            }
        },
        None => None,
    };

    // Synthesize the query alias from params — mirrors P31's
    // matcher handler. `external_id` is unused by the scorer;
    // `label` defaults to `normalized` so the alias passes
    // `validate()`.
    let alias = IdentityAlias {
        source: query.source.clone(),
        namespace: query.namespace.clone(),
        external_id: None,
        label: query.normalized.clone(),
        normalized: query.normalized.clone(),
    };
    let candidate_id =
        IdentityEntityId::from_str(&query.candidate_entity_id);

    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;

    match hydra.assess_identity_match_trust(
        Some(&tenant),
        &alias,
        &candidate_id,
        kind,
    ) {
        Ok(assessment) => (StatusCode::OK, Json(assessment)).into_response(),
        Err(hydra_core::error::HydraError::QueryError(msg))
            if msg.contains("unknown identity entity") =>
        {
            error_response(StatusCode::NOT_FOUND, msg)
        }
        Err(hydra_core::error::HydraError::QueryError(msg)) => {
            // Other engine validation failures — empty source
            // (caught above), sentinel collisions in the alias,
            // etc. — map to 400 with the engine message.
            error_response(StatusCode::BAD_REQUEST, msg)
        }
        Err(other) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("identity match trust assessment failed: {other}"),
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
        action::{Action, ActionKind, ActionStatus, ActionTarget},
        Claim, ClaimKind, ClaimObject, ClaimStatus, ClaimSubject, Confidence, EventKind,
        TenantId, TrustAssessment, Value,
    };
    use std::collections::HashMap;
    use tower::ServiceExt;

    const TEST_TENANT: &str = "tenant_trust_http_test";

    fn empty_get(uri: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("X-Hydra-Tenant", TEST_TENANT)
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

    fn empty_get_for_tenant(uri: &str, tenant: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("X-Hydra-Tenant", tenant)
            .body(Body::empty())
            .unwrap()
    }

    async fn read_body_bytes(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    /// Ingest a synthetic Verified claim with a related Approved-and-
    /// Executed Notify action so the trust assessor has a real chain
    /// to walk. The cascade auto-approves (no policies) and we
    /// explicitly execute via the Patch 7 helper to land an Outcome.
    /// Returns the claim id.
    async fn ingest_chain_for_tenant(
        runtime: &crate::runtime::RuntimeHandle,
        tenant: TenantId,
    ) -> hydra_core::ClaimId {
        let now = chrono::Utc::now();
        let claim_id = hydra_core::ClaimId::new();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let claim = Claim {
            id: claim_id.clone(),
            tenant_id: Some(tenant.clone()),
            kind: ClaimKind::AnomalyFinding,
            subject: ClaimSubject::System("hydra".to_string()),
            predicate: "under_test_load".to_string(),
            object: ClaimObject::Value(Value::Bool(true)),
            confidence: Confidence::new(0.92),
            status: ClaimStatus::Verified,
            evidence_for: vec![],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        let action_id = hydra_core::ActionId::new();
        let action = Action {
            id: action_id.clone(),
            tenant_id: Some(tenant.clone()),
            kind: ActionKind::Notify,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("hydra".to_string())],
            related_claims: vec![claim_id.clone()],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: None,
            rejected_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra
            .ingest_for_tenant(EventKind::ClaimProposed { claim }, tenant.clone())
            .unwrap();
        hydra
            .ingest_for_tenant(EventKind::ActionProposed { action }, tenant.clone())
            .unwrap();
        // Cascade auto-approved (no policies). Execute walks
        // Approved → Executed and emits OutcomeObserved.
        hydra
            .execute_notify_action(action_id, actor)
            .unwrap();
        claim_id
    }

    #[tokio::test]
    async fn get_trust_returns_assessment_for_known_claim() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let claim_id = ingest_chain_for_tenant(&runtime, tenant).await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!("/trust/claims/{claim_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: TrustAssessment =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.claim_id, claim_id);
        // Verified + executed + outcome chain should clear Medium
        // tier at minimum. Cascade-only approval keeps the score
        // just under or at High depending on the chain factors.
        assert!(
            body.score >= 0.50,
            "expected at least Medium tier; got {:.3} factors {:#?}",
            body.score,
            body.factors,
        );
        // 16 factors: Patch 9's 12 baseline + Patch 12's 3
        // historical reflex factors + Patch 13's
        // model_operator_rejected_historically.
        assert_eq!(body.factors.len(), 16);
        assert!(!body.related_action_ids.is_empty());
    }

    #[tokio::test]
    async fn get_trust_unknown_claim_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/trust/claims/claim_does_not_exist"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.error.contains("claim not found"), "got: {}", body.error);
    }

    #[tokio::test]
    async fn get_trust_missing_tenant_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get_without_tenant("/trust/claims/anything"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_trust_other_tenant_claim_returns_404() {
        // STRICT isolation pin: a claim that exists but belongs to
        // a different tenant must surface as 404, not 403. Returning
        // 403 would itself leak "this id exists" across tenant
        // boundaries.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let owning_tenant = TenantId::from_str("tenant_owner");
        let other_tenant = "tenant_other";
        let claim_id = ingest_chain_for_tenant(&runtime, owning_tenant).await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get_for_tenant(
                &format!("/trust/claims/{claim_id}"),
                other_tenant,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        // No leak of "wrong tenant" — message must look identical
        // to the unknown-claim case.
        assert!(body.error.contains("claim not found"));
    }

    #[tokio::test]
    async fn trust_route_serializes_level_as_pascal_case() {
        // Pin the wire form. TrustLevel uses serde default
        // (PascalCase) and the user spec / Patch 10 contract
        // both require `"level": "High"` / `"Medium"` etc.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let claim_id = ingest_chain_for_tenant(&runtime, tenant).await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!("/trust/claims/{claim_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        let level = body.get("level").and_then(|v| v.as_str()).unwrap();
        assert!(
            ["High", "Medium", "Low", "Unknown"].contains(&level),
            "level must be PascalCase; got {level:?}",
        );
    }

    // === Patch 24 — cell trust HTTP tests ===

    /// Ingest a tenant-scoped synthetic CausalCell directly via
    /// `EventKind::CausalCellCreated`. Used by Patch 24's cell
    /// trust tests for deterministic content control without
    /// driving a full reflex chain.
    #[allow(clippy::too_many_arguments)]
    async fn ingest_cell(
        runtime: &crate::runtime::RuntimeHandle,
        tenant: Option<TenantId>,
        subject: &str,
        child_cell_ids: Vec<hydra_core::CausalCellId>,
        trust_score: Option<f64>,
    ) -> hydra_core::CausalCell {
        let cell = hydra_core::CausalCell {
            id: hydra_core::CausalCellId::new(),
            tenant_id: tenant,
            kind: hydra_core::CausalCellKind::Reflex,
            subject: subject.to_string(),
            source_events: vec![],
            evidence_ids: vec![],
            claim_ids: vec![],
            action_ids: vec![],
            outcome_ids: vec![],
            observation_run_ids: vec![],
            child_cell_ids,
            trust_score,
            summary: None,
            created_by: hydra_core::ActorId::from_str("actor_test"),
            created_at: chrono::Utc::now(),
            caused_by: None,
        };
        let cell_clone = cell.clone();
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra
            .ingest(hydra_core::EventKind::CausalCellCreated { cell })
            .unwrap();
        cell_clone
    }

    #[tokio::test]
    async fn get_cell_trust_returns_assessment() {
        // Tenant-scoped cell → 200 with assessment body.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let cell = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            "hydra.health",
            vec![],
            Some(0.85),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!("/trust/cells/{}", cell.id)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.get("cell_id").and_then(|v| v.as_str()), Some(cell.id.as_str()));
        assert!(body.get("score").is_some());
        assert!(body.get("level").is_some());
        assert!(body.get("explanation").is_some());
        assert!(body.get("factors").is_some());
        assert!(body.get("child_scores").is_some());
    }

    #[tokio::test]
    async fn get_cell_trust_requires_tenant_header() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get_without_tenant("/trust/cells/anything"))
            .await
            .unwrap();
        // Missing X-Hydra-Tenant → 400 from tenant_error_response.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_cell_trust_unknown_cell_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/trust/cells/cell_does_not_exist"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.error.contains("not found"));
    }

    #[tokio::test]
    async fn get_cell_trust_wrong_tenant_returns_404() {
        // Cell belongs to tenant_a; request as tenant_b → 404
        // indistinguishable from "missing". No cross-tenant leak.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let cell = ingest_cell(
            &runtime,
            Some(TenantId::from_str("tenant_owner")),
            "hidden",
            vec![],
            Some(0.90),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get_for_tenant(
                &format!("/trust/cells/{}", cell.id),
                "tenant_other",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_cell_trust_none_tenanted_cell_invisible_to_tenanted_query() {
        // LOAD-BEARING strict-isolation pin: a system-wide
        // (`None`-tenanted) cell is INVISIBLE to a tenanted
        // query. If this ever changes, operators querying their
        // tenant could see global cells they didn't author.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let cell = ingest_cell(
            &runtime, None, "system.global", vec![], Some(0.90),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!("/trust/cells/{}", cell.id)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_cell_trust_response_preserves_pascal_case_level() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let cell = ingest_cell(
            &runtime, Some(tenant), "x", vec![], Some(0.85),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!("/trust/cells/{}", cell.id)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        let level = body.get("level").and_then(|v| v.as_str()).unwrap();
        assert!(
            ["High", "Medium", "Low", "Unknown"].contains(&level),
            "level must be PascalCase; got {level:?}",
        );
    }

    #[tokio::test]
    async fn get_cell_trust_response_includes_unapplied_factors() {
        // All 12 Patch 23 factors must appear in the response,
        // applied=true OR applied=false. Pin against accidental
        // filtering on the wire.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let cell = ingest_cell(
            &runtime, Some(tenant), "x", vec![], Some(0.50),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!("/trust/cells/{}", cell.id)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        let factors = body.get("factors").and_then(|v| v.as_array()).unwrap();
        assert_eq!(
            factors.len(),
            12,
            "all 12 Patch 23 factors must appear on the wire"
        );
        // Sanity: each entry has the load-bearing fields.
        for factor in factors {
            assert!(factor.get("kind").is_some());
            assert!(factor.get("weight").is_some());
            assert!(factor.get("applied").is_some());
            assert!(factor.get("detail").is_some());
        }
    }

    #[tokio::test]
    async fn get_cell_trust_response_includes_child_scores() {
        // Composed cell → child_scores array populated with each
        // direct child.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let child_a = ingest_cell(
            &runtime, Some(tenant.clone()), "child_a", vec![], Some(0.80),
        ).await;
        let child_b = ingest_cell(
            &runtime, Some(tenant.clone()), "child_b", vec![], Some(0.60),
        ).await;
        let parent = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            "parent",
            vec![child_a.id.clone(), child_b.id.clone()],
            Some(0.70),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!("/trust/cells/{}", parent.id)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        let child_scores = body
            .get("child_scores")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(child_scores.len(), 2);
        // Check at least the first child's shape.
        let first = &child_scores[0];
        assert!(first.get("cell_id").is_some());
        assert!(first.get("trust_score").is_some());
        assert!(first.get("claim_ids").is_some());
        assert!(first.get("outcome_ids").is_some());
    }

    #[tokio::test]
    async fn get_cell_trust_dangling_child_returns_500() {
        // Defensive pin: an ingested composed cell whose child id
        // is not in the store yields P23's "references unknown
        // child" error. HTTP maps to 500 (the request is fine;
        // the engine state isn't).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let fake_child = hydra_core::CausalCellId::from_str("cell_fake");
        let parent = ingest_cell(
            &runtime,
            Some(tenant),
            "dangling",
            vec![fake_child],
            None,
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!("/trust/cells/{}", parent.id)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(
            body.error.contains("references unknown child"),
            "msg: {}",
            body.error
        );
    }

    #[tokio::test]
    async fn get_cell_trust_route_lives_in_trust_router() {
        // Sanity: the route is mounted by `trust_router` (not by
        // a separate cell-trust router). If a future refactor
        // moves it elsewhere, this test fires.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let cell = ingest_cell(
            &runtime, Some(tenant), "x", vec![], Some(0.50),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!("/trust/cells/{}", cell.id)))
            .await
            .unwrap();
        // 200 means trust_router resolved the route.
        assert_eq!(response.status(), StatusCode::OK);
    }

    // === Patch 34 — Identity trust HTTP tests ===

    /// Build a minimal `IdentityEntity` for tenant-scoped tests.
    fn make_test_entity(
        tenant: Option<TenantId>,
        kind: hydra_core::IdentityEntityKind,
        canonical_key: &str,
        aliases: Vec<hydra_core::IdentityAlias>,
        confidence: hydra_core::Confidence,
    ) -> hydra_core::IdentityEntity {
        let now = chrono::Utc::now();
        hydra_core::IdentityEntity {
            id: hydra_core::IdentityEntityId::new(),
            tenant_id: tenant,
            kind,
            canonical_key: canonical_key.to_string(),
            display_name: canonical_key.to_string(),
            aliases,
            confidence,
            metadata: HashMap::new(),
            created_by: hydra_core::ActorId::from_str("actor_ops"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn snowflake_test_alias(ns: &str, name: &str) -> hydra_core::IdentityAlias {
        hydra_core::IdentityAlias {
            source: "snowflake".to_string(),
            namespace: Some(ns.to_string()),
            external_id: Some(format!("{ns}.{name}").to_uppercase()),
            label: format!("{ns}.{name}").to_uppercase(),
            normalized: format!("{}.{}", ns.to_lowercase(), name.to_lowercase()),
        }
    }

    async fn ingest_entity(
        runtime: &crate::runtime::RuntimeHandle,
        entity: hydra_core::IdentityEntity,
    ) -> hydra_core::IdentityEntity {
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra.create_identity_entity(entity).unwrap()
    }

    // === GET /trust/identity/entities/:entity_id ===

    #[tokio::test]
    async fn get_identity_entity_trust_returns_assessment() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let entity = ingest_entity(
            &runtime,
            make_test_entity(
                Some(tenant.clone()),
                hydra_core::IdentityEntityKind::Dataset,
                "dataset/revenue_daily",
                vec![
                    snowflake_test_alias("analytics", "revenue_daily"),
                    hydra_core::IdentityAlias {
                        source: "dbt".to_string(),
                        namespace: Some("models".to_string()),
                        external_id: None,
                        label: "models.revenue_daily".to_string(),
                        normalized: "models.revenue_daily".to_string(),
                    },
                ],
                hydra_core::Confidence::new(0.95),
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!(
                "/trust/identity/entities/{}",
                entity.id
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        // Bare wire body — assessment fields at the top level, no
        // `{assessment: ...}` envelope (mirrors /trust/claims and
        // /trust/cells).
        assert_eq!(
            body.get("entity_id").and_then(|v| v.as_str()),
            Some(entity.id.as_str())
        );
        assert!(body.get("score").is_some());
        assert!(body.get("level").is_some());
        assert!(body.get("explanation").is_some());
        assert!(body.get("factors").is_some());
    }

    #[tokio::test]
    async fn get_identity_entity_trust_requires_tenant_header() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get_without_tenant(
                "/trust/identity/entities/anything",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_identity_entity_trust_unknown_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/trust/identity/entities/ide_ghost"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.error.contains("unknown identity entity"));
    }

    #[tokio::test]
    async fn get_identity_entity_trust_wrong_tenant_returns_404() {
        // Strict isolation pin: same 404 body whether the entity
        // is missing OR exists in another tenant. No
        // cross-tenant existence leak.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let entity = ingest_entity(
            &runtime,
            make_test_entity(
                Some(TenantId::from_str("tenant_owner")),
                hydra_core::IdentityEntityKind::Dataset,
                "dataset/secret",
                vec![snowflake_test_alias("analytics", "secret")],
                hydra_core::Confidence::new(0.90),
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get_for_tenant(
                &format!("/trust/identity/entities/{}", entity.id),
                "tenant_other",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_identity_entity_trust_none_tenanted_invisible_to_tenanted_query()
    {
        // LOAD-BEARING strict isolation pin: a `None`-tenanted
        // (system-wide) entity is invisible to a tenanted query
        // through the trust surface. Mirrors P33's engine pin.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let entity = ingest_entity(
            &runtime,
            make_test_entity(
                None,
                hydra_core::IdentityEntityKind::Source,
                "source/system",
                vec![hydra_core::IdentityAlias {
                    source: "snowflake".to_string(),
                    namespace: None,
                    external_id: None,
                    label: "snowflake-prod".to_string(),
                    normalized: "snowflake-prod".to_string(),
                }],
                hydra_core::Confidence::new(0.90),
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!(
                "/trust/identity/entities/{}",
                entity.id
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_identity_entity_trust_includes_all_factors() {
        // Explainability contract: every assessment carries all
        // 12 P33 factor records — applied + unapplied. Pin so a
        // future refactor doesn't filter the list to "what fired".
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let entity = ingest_entity(
            &runtime,
            make_test_entity(
                Some(tenant),
                hydra_core::IdentityEntityKind::Dataset,
                "dataset/x",
                vec![snowflake_test_alias("analytics", "x")],
                hydra_core::Confidence::new(0.90),
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!(
                "/trust/identity/entities/{}",
                entity.id
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        let factors = body.get("factors").and_then(|v| v.as_array()).unwrap();
        assert_eq!(
            factors.len(),
            12,
            "all 12 P33 factor records must appear on the wire"
        );
        // At least one applied=false must survive (single-alias
        // entity has metadata=false, no multi-source).
        assert!(factors.iter().any(|f| f.get("applied")
            .and_then(|v| v.as_bool())
            == Some(false)));
    }

    // === GET /trust/identity/matches ===

    #[tokio::test]
    async fn get_identity_match_trust_returns_assessment() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let alias = snowflake_test_alias("analytics", "revenue_daily");
        let entity = ingest_entity(
            &runtime,
            make_test_entity(
                Some(tenant),
                hydra_core::IdentityEntityKind::Dataset,
                "dataset/revenue_daily",
                vec![alias.clone()],
                hydra_core::Confidence::new(0.95),
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let uri = format!(
            "/trust/identity/matches\
             ?source=snowflake\
             &namespace=analytics\
             &normalized=analytics.revenue_daily\
             &candidate_entity_id={}",
            entity.id
        );
        let response = app
            .oneshot(empty_get(&uri))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        // Bare wire body — both axes present.
        assert!(body.get("query_alias").is_some());
        assert!(body.get("candidate_entity_id").is_some());
        assert!(body.get("match_score").is_some());
        assert!(body.get("match_level").is_some());
        assert!(body.get("score").is_some());
        assert!(body.get("level").is_some());
        assert!(body.get("factors").is_some());
    }

    #[tokio::test]
    async fn get_identity_match_trust_requires_tenant_header() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get_without_tenant(
                "/trust/identity/matches\
                 ?source=x&normalized=y&candidate_entity_id=ide_x",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_identity_match_trust_missing_candidate_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(
                "/trust/identity/matches?source=snowflake&normalized=x",
            ))
            .await
            .unwrap();
        // axum Query<T> rejects when a required field is absent.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_identity_match_trust_missing_required_params_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        // Missing source.
        let r1 = app
            .clone()
            .oneshot(empty_get(
                "/trust/identity/matches\
                 ?normalized=x&candidate_entity_id=ide_x",
            ))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::BAD_REQUEST);
        // Missing normalized.
        let r2 = app
            .oneshot(empty_get(
                "/trust/identity/matches\
                 ?source=snowflake&candidate_entity_id=ide_x",
            ))
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_identity_match_trust_unknown_candidate_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(
                "/trust/identity/matches\
                 ?source=snowflake\
                 &normalized=x\
                 &candidate_entity_id=ide_ghost",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.error.contains("unknown identity entity"));
    }

    #[tokio::test]
    async fn get_identity_match_trust_wrong_tenant_invisible() {
        // LOAD-BEARING strict isolation: candidate exists in
        // tenant_owner but the query comes as tenant_other → 404
        // indistinguishable from a genuine miss.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let entity = ingest_entity(
            &runtime,
            make_test_entity(
                Some(TenantId::from_str("tenant_owner")),
                hydra_core::IdentityEntityKind::Dataset,
                "dataset/secret",
                vec![snowflake_test_alias("analytics", "secret")],
                hydra_core::Confidence::new(0.90),
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let uri = format!(
            "/trust/identity/matches\
             ?source=snowflake\
             &namespace=analytics\
             &normalized=analytics.secret\
             &candidate_entity_id={}",
            entity.id
        );
        let response = app
            .oneshot(empty_get_for_tenant(&uri, "tenant_other"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_identity_match_trust_preserves_match_level_distinct_from_trust_level(
    ) {
        // LOAD-BEARING: the wire carries BOTH `match_level` (P30
        // similarity) AND `level` (P32 trust verdict) as separate
        // fields. They are different axes — never conflate them.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let alias = snowflake_test_alias("analytics", "revenue_daily");
        let entity = ingest_entity(
            &runtime,
            make_test_entity(
                Some(tenant),
                hydra_core::IdentityEntityKind::Dataset,
                "dataset/revenue_daily",
                vec![alias.clone()],
                hydra_core::Confidence::new(0.95),
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let uri = format!(
            "/trust/identity/matches\
             ?source=snowflake\
             &namespace=analytics\
             &normalized=analytics.revenue_daily\
             &candidate_entity_id={}",
            entity.id
        );
        let response = app
            .oneshot(empty_get(&uri))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        // Both axes live at top-level. `match_level` uses
        // `MatchLevel` PascalCase ("Strong"/"Possible"/"Weak"/"None")
        // and `level` uses `TrustLevel` PascalCase
        // ("High"/"Medium"/"Low"/"Unknown") — distinct vocabularies.
        let match_level = body
            .get("match_level")
            .and_then(|v| v.as_str())
            .unwrap();
        let trust_level = body.get("level").and_then(|v| v.as_str()).unwrap();
        assert!(
            ["Strong", "Possible", "Weak", "None"].contains(&match_level),
            "match_level must be a MatchLevel; got {match_level}"
        );
        assert!(
            ["High", "Medium", "Low", "Unknown"].contains(&trust_level),
            "level must be a TrustLevel; got {trust_level}"
        );
    }

    #[tokio::test]
    async fn get_identity_match_trust_route_lives_in_trust_router() {
        // Sanity: the match-trust route is mounted by
        // `trust_router` itself (not by a separate identity
        // router). If a future refactor moves it, this fires.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let alias = snowflake_test_alias("analytics", "x");
        let entity = ingest_entity(
            &runtime,
            make_test_entity(
                Some(tenant),
                hydra_core::IdentityEntityKind::Dataset,
                "dataset/x",
                vec![alias.clone()],
                hydra_core::Confidence::new(0.90),
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let uri = format!(
            "/trust/identity/matches\
             ?source=snowflake\
             &namespace=analytics\
             &normalized=analytics.x\
             &candidate_entity_id={}",
            entity.id
        );
        let response = app
            .oneshot(empty_get(&uri))
            .await
            .unwrap();
        // 200 = trust_router resolved the route.
        assert_eq!(response.status(), StatusCode::OK);
    }
}
