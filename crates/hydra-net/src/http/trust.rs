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
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hydra_core::{CausalCellId, ClaimId};
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

/// Build the trust router. Two routes today:
///
/// - `/trust/claims/:claim_id` — Patch 10 claim trust
/// - `/trust/cells/:cell_id`   — Patch 24 causal-cell trust
///
/// Future patches mount alongside under the same `/trust/*`
/// prefix.
pub fn trust_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/trust/claims/:claim_id", get(get_claim_trust))
        .route("/trust/cells/:cell_id", get(get_cell_trust))
        .with_state(TrustHttpState::new(runtime))
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
}
