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
use hydra_core::ClaimId;
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

/// Build the trust router. One route in v0; future patches mount
/// alongside under the same `/trust/*` prefix.
pub fn trust_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/trust/claims/:claim_id", get(get_claim_trust))
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
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
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
        assert_eq!(body.factors.len(), 12);
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
}
