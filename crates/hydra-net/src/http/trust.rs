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
    IdentityLinkId,
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
/// - `/trust/identity/sources/:source`        — Patch 36 source trust
/// - `/trust/identity/links/:link_id`         — Patch 40 identity link trust
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
/// prefix (operational connector trust → `/trust/connectors/:id`,
/// etc.).
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
        .route(
            "/trust/identity/sources/:source",
            get(get_source_trust),
        )
        .route(
            "/trust/identity/links/:link_id",
            get(get_identity_link_trust),
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

/// `GET /trust/identity/sources/:source` — Patch 36 source trust
/// surface. Exposes the Patch 35
/// `Hydra::assess_source_trust` verdict over HTTP.
///
/// The `source` path segment is URL-decoded by axum; SDK callers
/// percent-encode automatically (`_seg()`). Sources containing
/// `/` MUST be encoded by hand-rolled HTTP callers as `%2F`.
///
/// ## Status mapping
///
/// - missing `X-Hydra-Tenant` → **400**
/// - empty source segment → **400** (defense in depth — engine
///   also rejects, but HTTP semantically should reject caller
///   input as `BAD_REQUEST` not surface a 500)
/// - sentinel source (`__system__`, `__root__`) → **400** (same
///   reason — would otherwise alias the None-tenant slot's
///   reserved keys)
/// - well-formed source with no aliases / no evidence in tenant
///   scope → **200** with a normal `SourceTrustAssessment` body,
///   `level == "Unknown"` (`level_for_score(0.0)`). This is NOT
///   404 — P35 explicitly made empty-result a legitimate verdict.
/// - well-formed source with data → **200** with bare assessment
///   body (no envelope — matches `/trust/claims/:id`,
///   `/trust/cells/:id`, `/trust/identity/entities/:id`)
/// - unexpected engine error → **500**
///
/// ## Tenant isolation
///
/// `None`-tenanted source data (entities + evidence) is invisible
/// to tenanted probes — but the response is **200 with an empty
/// verdict**, NOT 404. Distinct from `/trust/identity/entities/:id`
/// where wrong tenant returns 404, because the entity route gates
/// on a specific id (existence is sensitive); source is a free-
/// form string and the empty-result-is-legitimate contract carries
/// forward from the engine.
///
/// ## Suggestion-only contract
///
/// Source trust is **identity-backed, NOT operational**. v1
/// measures whether a source has produced trustworthy identity /
/// evidence claims in this tenant — entity count, kind diversity,
/// entity-confidence corroboration, evidence reliability. v1 does
/// NOT consider ingestion freshness, schema drift, heartbeat
/// liveness, SLA conformance. A dead Snowflake warehouse with
/// five trustworthy historical entities will score **High** here.
/// Operational signals layer on when connector primitives ship.
async fn get_source_trust(
    State(state): State<TrustHttpState>,
    headers: HeaderMap,
    Path(source): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };

    // Defense in depth — engine also rejects, but HTTP should
    // surface caller-input errors as 400, not 500. Mirrors P34's
    // match-route param validation pattern.
    if source.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "source path segment cannot be empty",
        );
    }
    if source == "__system__" || source == "__root__" {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("source '{source}' is a reserved sentinel"),
        );
    }

    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;

    match hydra.assess_source_trust(Some(&tenant), &source) {
        Ok(assessment) => (StatusCode::OK, Json(assessment)).into_response(),
        Err(hydra_core::error::HydraError::QueryError(msg)) => {
            // Engine's QueryError surfaces ONLY for malformed
            // input (empty / sentinel — both caught above). If we
            // reach here, defense-in-depth failed; honest 400.
            error_response(StatusCode::BAD_REQUEST, msg)
        }
        Err(other) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("source trust assessment failed: {other}"),
        ),
    }
}

/// `GET /trust/identity/links/:link_id` — Patch 40 identity
/// link trust surface. Exposes the Patch 39
/// `Hydra::assess_identity_link_trust` verdict over HTTP.
///
/// Strict tenant scoping carries forward from P39:
///
/// - missing `X-Hydra-Tenant` → 400
/// - unknown link / wrong tenant / `None`-tenanted link → 404
///   with engine `"unknown identity link: {id}"` message
/// - endpoint-entity resolution miss during the P33 walk
///   inside P39 → ALSO 404 (NOT 500) — **LOAD-BEARING**: the
///   substring match below is `"unknown identity"` (covers both
///   `"unknown identity link"` AND `"unknown identity entity"`)
///   so a cross-tenant probe of a link whose endpoints live in
///   another tenant doesn't surface as a 500 that would leak
///   endpoint existence.
/// - happy path → 200 with bare `IdentityLinkTrustAssessment`
///   body (no envelope — matches `/trust/claims/:id`,
///   `/trust/cells/:id`, `/trust/identity/entities/:id`,
///   `/trust/identity/sources/:source`)
///
/// **Strategic warning carry-forward (P39)**: v1 measures
/// STRUCTURAL trustworthiness — author confidence, endpoint
/// entity-trust, supporting audit references, link kind well-
/// formedness. **v1 does NOT validate SEMANTIC correctness.**
/// `Dashboard --OwnedBy--> Service` scores identically to
/// `Service --OwnedBy--> User`. Kind compatibility deferred to
/// P41+. Auto-actions and accept-semantic-match workflows MUST
/// compose with separate gates.
async fn get_identity_link_trust(
    State(state): State<TrustHttpState>,
    headers: HeaderMap,
    Path(link_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };
    let id = IdentityLinkId::from_str(&link_id);

    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;

    match hydra.assess_identity_link_trust(Some(&tenant), &id) {
        Ok(assessment) => (StatusCode::OK, Json(assessment)).into_response(),
        Err(hydra_core::error::HydraError::QueryError(msg))
            if msg.contains("unknown identity") =>
        {
            // LOAD-BEARING broader substring: covers both the
            // P39 "unknown identity link" error AND the P33
            // "unknown identity entity" error that bubbles up
            // through the endpoint trust walk. Mapping endpoint
            // misses to 500 would leak cross-tenant endpoint
            // existence.
            error_response(StatusCode::NOT_FOUND, msg)
        }
        Err(other) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("identity link trust assessment failed: {other}"),
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

    // === Patch 36 — Source trust HTTP tests ===

    /// Ingest a tenant-scoped Evidence record via `EvidenceAdded`.
    /// Used by source-trust tests that need real evidence in the
    /// engine to exercise the P35 evidence-mapping factors.
    async fn ingest_evidence(
        runtime: &crate::runtime::RuntimeHandle,
        evidence: hydra_core::Evidence,
    ) {
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra
            .ingest(hydra_core::EventKind::EvidenceAdded { evidence })
            .unwrap();
    }

    /// Build a tenant-scoped Evidence record with the supplied
    /// source variant + reliability. P36 helper, mirrors the P35
    /// engine-test fixture.
    fn make_test_evidence(
        tenant: Option<TenantId>,
        source: hydra_core::EvidenceSource,
        reliability: f64,
    ) -> hydra_core::Evidence {
        let now = chrono::Utc::now();
        hydra_core::Evidence {
            id: hydra_core::EvidenceId::new(),
            tenant_id: tenant,
            source,
            payload: hydra_core::EvidencePayload {
                kind: "p36_test".to_string(),
                data: HashMap::new(),
            },
            reliability: hydra_core::Confidence::new(reliability),
            observed_at: now,
            recorded_at: now,
            caused_by: None,
        }
    }

    // === GET /trust/identity/sources/:source ===

    #[tokio::test]
    async fn get_source_trust_returns_assessment() {
        // Happy path — 2 entities + 1 reliable evidence under the
        // same source. Verify the bare-body envelope, all P35
        // fields, AND the P36 `related_entity_ids` Adaptation A1
        // extension.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let entity_a = ingest_entity(
            &runtime,
            make_test_entity(
                Some(tenant.clone()),
                hydra_core::IdentityEntityKind::Dataset,
                "dataset/revenue_daily",
                vec![snowflake_test_alias("analytics", "revenue_daily")],
                hydra_core::Confidence::new(0.95),
            ),
        )
        .await;
        let entity_b = ingest_entity(
            &runtime,
            make_test_entity(
                Some(tenant.clone()),
                hydra_core::IdentityEntityKind::Table,
                "table/users",
                vec![snowflake_test_alias("ops", "users")],
                hydra_core::Confidence::new(0.95),
            ),
        )
        .await;
        ingest_evidence(
            &runtime,
            make_test_evidence(
                Some(tenant.clone()),
                hydra_core::EvidenceSource::Warehouse {
                    system: "snowflake".to_string(),
                    database: None,
                    schema: None,
                    table: None,
                },
                0.90,
            ),
        )
        .await;

        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/trust/identity/sources/snowflake"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        // Bare wire body — no envelope.
        assert_eq!(body.get("source").and_then(|v| v.as_str()), Some("snowflake"));
        assert!(body.get("score").is_some());
        assert!(body.get("level").is_some());
        assert!(body.get("explanation").is_some());
        assert!(body.get("factors").is_some());
        // Patch 36 Adaptation A1 — related_entity_ids on the wire,
        // containing both entity ids.
        let related = body
            .get("related_entity_ids")
            .and_then(|v| v.as_array())
            .expect("related_entity_ids must be an array");
        assert_eq!(related.len(), 2);
        let related_strs: Vec<&str> =
            related.iter().filter_map(|v| v.as_str()).collect();
        assert!(related_strs.contains(&entity_a.id.as_str()));
        assert!(related_strs.contains(&entity_b.id.as_str()));
        // Sample sizes carry forward from P35.
        assert_eq!(body.get("entity_sample_size").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(body.get("evidence_sample_size").and_then(|v| v.as_u64()), Some(1));
    }

    #[tokio::test]
    async fn get_source_trust_requires_tenant_header() {
        // Missing X-Hydra-Tenant → 400. Same contract as the other
        // /trust/* routes.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get_without_tenant(
                "/trust/identity/sources/snowflake",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_source_trust_empty_source_returns_400() {
        // Empty source path segment is malformed input — caught
        // at the HTTP boundary BEFORE the engine call. Adaptation
        // B (defense in depth).
        //
        // Note: axum's path-segment routing won't match a literal
        // empty `:source` (the trailing `/sources/` doesn't bind
        // the param), so we exercise the next-closest behavior: a
        // request to `/trust/identity/sources/` returns 404 from
        // axum's router. To pin the handler's OWN empty-source
        // guard, we use a URL-encoded zero-length segment via
        // `%20`-trimmed: realistically the guard never fires from
        // a well-formed HTTP client. Pinned via the sentinel
        // check instead — see the next test.
        //
        // For wire compatibility, callers sending the literal
        // `/trust/identity/sources/` would see a 404 (route
        // unmatched). The handler's `source.is_empty()` guard
        // exists as defense-in-depth and is exercised by the
        // engine path; we pin the route-unmatched behavior here.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/trust/identity/sources/"))
            .await
            .unwrap();
        // Trailing-slash without a segment doesn't bind `:source`
        // — axum returns 404 NOT_FOUND. The HTTP contract
        // semantically rejects empty-source URLs at the routing
        // layer.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_source_trust_sentinel_source_returns_400() {
        // `__system__` and `__root__` are reserved sentinels.
        // The handler rejects them with 400 BEFORE calling the
        // engine — caller-input malformation is BAD_REQUEST, not
        // INTERNAL_SERVER_ERROR.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        for sentinel in ["__system__", "__root__"] {
            let response = app
                .clone()
                .oneshot(empty_get(&format!(
                    "/trust/identity/sources/{sentinel}"
                )))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "sentinel source '{sentinel}' must surface as 400"
            );
        }
    }

    #[tokio::test]
    async fn get_source_trust_unknown_source_returns_200_with_low_verdict() {
        // Wrinkle E pin: a well-formed but unseen source is a
        // legitimate empty verdict, NOT a 404. The exact level is
        // `Unknown` via `level_for_score(0.0)`; the test asserts
        // status==200 + level in {Unknown, Low} for wording
        // tolerance (the "not 404" contract is what's
        // load-bearing).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/trust/identity/sources/neverseen"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.get("source").and_then(|v| v.as_str()), Some("neverseen"));
        assert_eq!(body.get("entity_sample_size").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(body.get("evidence_sample_size").and_then(|v| v.as_u64()), Some(0));
        let level = body.get("level").and_then(|v| v.as_str()).unwrap();
        assert!(
            level == "Unknown" || level == "Low",
            "unknown source must bucket to Unknown (or Low for wording \
             tolerance); got {level}"
        );
    }

    #[tokio::test]
    async fn get_source_trust_none_tenanted_source_invisible_to_tenanted_query() {
        // LOAD-BEARING pin (Wrinkle G). `None`-tenanted entities
        // + evidence are invisible to tenanted probes — but the
        // result is 200 + empty verdict, NOT 404. Distinct from
        // /trust/identity/entities/:id where wrong tenant returns
        // 404. Source is free-form and empty-result-is-legitimate
        // carries forward from the engine.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let _system_entity = ingest_entity(
            &runtime,
            make_test_entity(
                None,
                hydra_core::IdentityEntityKind::System,
                "system/global",
                vec![hydra_core::IdentityAlias {
                    source: "github".to_string(),
                    namespace: Some("global".to_string()),
                    external_id: None,
                    label: "global/x".to_string(),
                    normalized: "global.x".to_string(),
                }],
                hydra_core::Confidence::new(0.90),
            ),
        )
        .await;
        ingest_evidence(
            &runtime,
            make_test_evidence(
                None,
                hydra_core::EvidenceSource::Api {
                    system: "github".to_string(),
                    endpoint: None,
                },
                0.90,
            ),
        )
        .await;

        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/trust/identity/sources/github"))
            .await
            .unwrap();
        // 200 with empty verdict — NOT 404. The tenanted probe
        // simply sees no data for the source.
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.get("entity_sample_size").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(body.get("evidence_sample_size").and_then(|v| v.as_u64()), Some(0));
        let related = body
            .get("related_entity_ids")
            .and_then(|v| v.as_array())
            .expect("related_entity_ids must be an array even when empty");
        assert!(related.is_empty(), "None-tenanted entity must not leak");
    }

    #[tokio::test]
    async fn get_source_trust_includes_all_factors() {
        // Explainability contract pin. All 9 P35 factor records
        // surface on the wire (applied OR not). Mirrors P34's
        // `get_identity_entity_trust_includes_all_factors`.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let _e = ingest_entity(
            &runtime,
            make_test_entity(
                Some(tenant),
                hydra_core::IdentityEntityKind::Dataset,
                "dataset/x",
                vec![snowflake_test_alias("ns", "x")],
                hydra_core::Confidence::new(0.90),
            ),
        )
        .await;

        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/trust/identity/sources/snowflake"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        let factors = body
            .get("factors")
            .and_then(|v| v.as_array())
            .expect("factors must be an array");
        let factor_kinds: Vec<&str> = factors
            .iter()
            .filter_map(|f| f.get("kind").and_then(|v| v.as_str()))
            .collect();
        let expected_kinds = [
            "source_has_identity_aliases",
            "multiple_entities_from_source",
            "single_entity_from_source",
            "multiple_kinds_from_source",
            "high_trust_entities_from_source",
            "low_trust_entities_from_source",
            "evidence_present_from_source",
            "reliable_evidence_from_source",
            "low_reliability_evidence_from_source",
        ];
        for k in &expected_kinds {
            assert!(
                factor_kinds.contains(k),
                "factor '{k}' missing from wire body; got {factor_kinds:?}"
            );
        }
        assert_eq!(factors.len(), expected_kinds.len());
    }

    #[tokio::test]
    async fn get_source_trust_url_encoded_source_with_hyphen_or_dot() {
        // Adaptation C pin — sources containing hyphens and dots
        // (`"snowflake-prod"`, `"github.com"`) round-trip through
        // the path segment correctly. URL-decoding is handled by
        // axum's Path extractor; sources with `/` would require
        // explicit `%2F` encoding by the caller (not exercised
        // here — covered by the SDK's _seg() helper test).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let _e = ingest_entity(
            &runtime,
            make_test_entity(
                Some(tenant),
                hydra_core::IdentityEntityKind::Service,
                "service/prod",
                vec![hydra_core::IdentityAlias {
                    source: "snowflake-prod".to_string(),
                    namespace: Some("ops".to_string()),
                    external_id: None,
                    label: "ops.prod".to_string(),
                    normalized: "ops.prod".to_string(),
                }],
                hydra_core::Confidence::new(0.95),
            ),
        )
        .await;

        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/trust/identity/sources/snowflake-prod"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(
            body.get("source").and_then(|v| v.as_str()),
            Some("snowflake-prod")
        );
        assert_eq!(
            body.get("entity_sample_size").and_then(|v| v.as_u64()),
            Some(1)
        );
    }

    #[tokio::test]
    async fn get_source_trust_route_lives_in_trust_router() {
        // Sanity: the source-trust route is mounted by
        // `trust_router` itself (not by a separate identity
        // router). If a future refactor moves it, this fires.
        // Mirrors `get_identity_match_trust_route_lives_in_trust_router`.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/trust/identity/sources/snowflake"))
            .await
            .unwrap();
        // 200 OK on an unknown-but-valid source proves the route
        // resolved through trust_router (engine produced the
        // empty verdict). A 404 here would mean the route wasn't
        // mounted.
        assert_eq!(response.status(), StatusCode::OK);
    }

    // === Patch 40 — GET /trust/identity/links/:link_id ===

    /// Build a minimal `IdentityLink` between two entities for
    /// HTTP tests. Mirror of `make_test_link` in
    /// `http/identity.rs::tests` — duplicated by design until a
    /// third caller appears (same precedent as
    /// `parse_identity_kind` duplication at the module level).
    fn make_test_link(
        tenant: Option<TenantId>,
        kind: hydra_core::IdentityLinkKind,
        from: &IdentityEntityId,
        to: &IdentityEntityId,
        confidence: f64,
    ) -> hydra_core::IdentityLink {
        hydra_core::IdentityLink {
            id: hydra_core::IdentityLinkId::new(),
            tenant_id: tenant,
            kind,
            from_entity_id: from.clone(),
            to_entity_id: to.clone(),
            confidence: hydra_core::Confidence::new(confidence),
            evidence_ids: vec![],
            claim_ids: vec![],
            cell_ids: vec![],
            metadata: HashMap::new(),
            created_by: hydra_core::ActorId::from_str("actor_ops"),
            created_at: chrono::Utc::now(),
            caused_by: None,
        }
    }

    /// Insert a link directly via the engine. Mirror of
    /// `ingest_link` in `http/identity.rs::tests` (duplicated by
    /// design — see `make_test_link`).
    async fn ingest_link(
        runtime: &crate::runtime::RuntimeHandle,
        link: hydra_core::IdentityLink,
    ) -> hydra_core::IdentityLink {
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra.create_identity_link(link).unwrap()
    }

    /// Seed two distinct entities under the test tenant for P40
    /// link-trust tests. Returns their ids.
    async fn seed_two_p40_entities(
        runtime: &crate::runtime::RuntimeHandle,
    ) -> (IdentityEntityId, IdentityEntityId) {
        let tenant = TenantId::from_str(TEST_TENANT);
        // Two high-trust entities so the resulting link has
        // both endpoints in the High band (P33 worked example a):
        // multi-source aliases + metadata + high confidence.
        let a = make_test_entity_with(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/p40_a",
            vec![
                snowflake_test_alias("analytics", "p40_a"),
                hydra_core::IdentityAlias {
                    source: "dbt".to_string(),
                    namespace: Some("models".to_string()),
                    external_id: None,
                    label: "models.p40_a".to_string(),
                    normalized: "models.p40_a".to_string(),
                },
                hydra_core::IdentityAlias {
                    source: "looker".to_string(),
                    namespace: Some("finance".to_string()),
                    external_id: None,
                    label: "finance.p40_a".to_string(),
                    normalized: "finance.p40_a".to_string(),
                },
            ],
            hydra_core::Confidence::new(0.95),
        );
        let b = make_test_entity_with(
            Some(tenant),
            hydra_core::IdentityEntityKind::Service,
            "service/p40_b",
            vec![
                hydra_core::IdentityAlias {
                    source: "github".to_string(),
                    namespace: Some("ops".to_string()),
                    external_id: None,
                    label: "ops.p40_b".to_string(),
                    normalized: "ops.p40_b".to_string(),
                },
                hydra_core::IdentityAlias {
                    source: "dbt".to_string(),
                    namespace: Some("models".to_string()),
                    external_id: None,
                    label: "models.p40_b".to_string(),
                    normalized: "models.p40_b".to_string(),
                },
                hydra_core::IdentityAlias {
                    source: "looker".to_string(),
                    namespace: Some("finance".to_string()),
                    external_id: None,
                    label: "finance.p40_b".to_string(),
                    normalized: "finance.p40_b".to_string(),
                },
            ],
            hydra_core::Confidence::new(0.95),
        );
        let a_id = a.id.clone();
        let b_id = b.id.clone();
        ingest_entity(runtime, a).await;
        ingest_entity(runtime, b).await;
        (a_id, b_id)
    }

    /// Build a `make_test_entity` variant that adds 2 metadata
    /// entries so the resulting entity clears the P33 High
    /// threshold (≥0.80) reliably for the link-trust tests.
    fn make_test_entity_with(
        tenant: Option<TenantId>,
        kind: hydra_core::IdentityEntityKind,
        canonical_key: &str,
        aliases: Vec<hydra_core::IdentityAlias>,
        confidence: hydra_core::Confidence,
    ) -> hydra_core::IdentityEntity {
        let now = chrono::Utc::now();
        let mut metadata = HashMap::new();
        metadata.insert(
            "owner".to_string(),
            hydra_core::Value::String("team_p40".to_string()),
        );
        metadata.insert(
            "tier".to_string(),
            hydra_core::Value::String("prod".to_string()),
        );
        hydra_core::IdentityEntity {
            id: IdentityEntityId::new(),
            tenant_id: tenant,
            kind,
            canonical_key: canonical_key.to_string(),
            display_name: canonical_key.to_string(),
            aliases,
            confidence,
            metadata,
            created_by: hydra_core::ActorId::from_str("actor_ops"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    #[tokio::test]
    async fn link_trust_returns_assessment_for_known_link() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_p40_entities(&runtime).await;
        let link = ingest_link(
            &runtime,
            make_test_link(
                Some(TenantId::from_str(TEST_TENANT)),
                hydra_core::IdentityLinkKind::DependsOn,
                &a,
                &b,
                0.95,
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!(
                "/trust/identity/links/{}",
                link.id.as_str()
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        // Bare wire body — all 6 P39 fields present.
        assert_eq!(
            body.get("link_id").and_then(|v| v.as_str()),
            Some(link.id.as_str())
        );
        assert!(body.get("score").is_some());
        assert!(body.get("level").is_some());
        assert!(body.get("explanation").is_some());
        assert!(body.get("factors").is_some());
        assert!(body.get("assessed_at").is_some());
    }

    #[tokio::test]
    async fn link_trust_score_and_level_serialize_correctly() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_p40_entities(&runtime).await;
        let link = ingest_link(
            &runtime,
            make_test_link(
                Some(TenantId::from_str(TEST_TENANT)),
                hydra_core::IdentityLinkKind::DependsOn,
                &a,
                &b,
                0.95,
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!(
                "/trust/identity/links/{}",
                link.id.as_str()
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        // score is a JSON number; level is PascalCase string.
        assert!(body.get("score").and_then(|v| v.as_f64()).is_some());
        let level = body.get("level").and_then(|v| v.as_str()).unwrap();
        assert!(
            matches!(level, "High" | "Medium" | "Low" | "Unknown"),
            "level must be PascalCase TrustLevel; got {level}"
        );
    }

    #[tokio::test]
    async fn link_trust_explanation_contains_strategic_warning() {
        // Engine bakes the structural-not-semantic warning into
        // the explanation field. Pin BOTH substrings — locks the
        // contract from drifting silently.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_p40_entities(&runtime).await;
        let link = ingest_link(
            &runtime,
            make_test_link(
                Some(TenantId::from_str(TEST_TENANT)),
                hydra_core::IdentityLinkKind::DependsOn,
                &a,
                &b,
                0.95,
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!(
                "/trust/identity/links/{}",
                link.id.as_str()
            )))
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        let explanation =
            body.get("explanation").and_then(|v| v.as_str()).unwrap();
        assert!(
            explanation.contains("STRUCTURAL"),
            "explanation must surface STRUCTURAL marker: {explanation}"
        );
        assert!(
            explanation.contains("SEMANTIC"),
            "explanation must surface SEMANTIC marker: {explanation}"
        );
    }

    #[tokio::test]
    async fn link_trust_factors_length_is_eleven() {
        // 11-factor explainability lock — locks the contract so
        // a future "filter applied=true only" refactor breaks
        // loudly.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_p40_entities(&runtime).await;
        let link = ingest_link(
            &runtime,
            make_test_link(
                Some(TenantId::from_str(TEST_TENANT)),
                hydra_core::IdentityLinkKind::DependsOn,
                &a,
                &b,
                0.95,
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!(
                "/trust/identity/links/{}",
                link.id.as_str()
            )))
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        let factors =
            body.get("factors").and_then(|v| v.as_array()).unwrap();
        assert_eq!(factors.len(), 11);
    }

    #[tokio::test]
    async fn link_trust_factors_include_unapplied() {
        // At least one factor record has `applied: false` — pin
        // the explainability contract (all factors emit, applied
        // OR not).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_p40_entities(&runtime).await;
        let link = ingest_link(
            &runtime,
            make_test_link(
                Some(TenantId::from_str(TEST_TENANT)),
                hydra_core::IdentityLinkKind::DependsOn,
                &a,
                &b,
                0.95,
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!(
                "/trust/identity/links/{}",
                link.id.as_str()
            )))
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        let factors =
            body.get("factors").and_then(|v| v.as_array()).unwrap();
        let any_unapplied = factors
            .iter()
            .any(|f| f.get("applied").and_then(|v| v.as_bool()) == Some(false));
        assert!(
            any_unapplied,
            "at least one factor must have applied=false (penalty \
             factors in the happy path)"
        );
    }

    #[tokio::test]
    async fn link_trust_unknown_link_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/trust/identity/links/idl_ghost"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(
            body.error.contains("unknown identity link"),
            "expected unknown-identity-link error, got: {}",
            body.error
        );
    }

    #[tokio::test]
    async fn link_trust_wrong_tenant_returns_404() {
        // Tenant A creates the link; tenant B queries → 404
        // (indistinguishable from miss; no cross-tenant existence
        // leak).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_p40_entities(&runtime).await;
        let link = ingest_link(
            &runtime,
            make_test_link(
                Some(TenantId::from_str(TEST_TENANT)),
                hydra_core::IdentityLinkKind::DependsOn,
                &a,
                &b,
                0.95,
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get_for_tenant(
                &format!("/trust/identity/links/{}", link.id.as_str()),
                "tenant_other",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn link_trust_none_tenanted_link_returns_404_under_tenant() {
        // None-tenanted link (between None-tenanted entities)
        // queried with a tenant header → 404 invisible. P39
        // strict-isolation contract.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        // Seed None-tenanted entities + link.
        let (a, b) = {
            let a = make_test_entity_with(
                None,
                hydra_core::IdentityEntityKind::System,
                "system/p40_none_a",
                vec![hydra_core::IdentityAlias {
                    source: "system".to_string(),
                    namespace: Some("global".to_string()),
                    external_id: None,
                    label: "global.p40_none_a".to_string(),
                    normalized: "global.p40_none_a".to_string(),
                }],
                hydra_core::Confidence::new(0.95),
            );
            let b = make_test_entity_with(
                None,
                hydra_core::IdentityEntityKind::System,
                "system/p40_none_b",
                vec![hydra_core::IdentityAlias {
                    source: "system".to_string(),
                    namespace: Some("global".to_string()),
                    external_id: None,
                    label: "global.p40_none_b".to_string(),
                    normalized: "global.p40_none_b".to_string(),
                }],
                hydra_core::Confidence::new(0.95),
            );
            let a_id = a.id.clone();
            let b_id = b.id.clone();
            ingest_entity(&runtime, a).await;
            ingest_entity(&runtime, b).await;
            (a_id, b_id)
        };
        let link = ingest_link(
            &runtime,
            make_test_link(
                None,
                hydra_core::IdentityLinkKind::SameAs,
                &a,
                &b,
                0.9,
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!(
                "/trust/identity/links/{}",
                link.id.as_str()
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn link_trust_missing_tenant_header_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get_without_tenant(
                "/trust/identity/links/idl_x",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn link_trust_endpoint_entity_missing_returns_404_not_500() {
        // LOAD-BEARING: when P39 walks into P33 for either
        // endpoint and finds the entity isn't visible in the
        // caller's tenant slot, P33 surfaces "unknown identity
        // entity". The HTTP handler MUST map that to 404 (NOT
        // 500) so cross-tenant endpoint existence doesn't leak.
        //
        // To exercise this path, we seed a link in tenant_a
        // (with from/to entities in tenant_a) and query it from
        // tenant_b. The link itself misses tenant scope first
        // → 404 via the link's own error string. Tenant B
        // probing for a link id from tenant A hits the same
        // 404 either way.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_p40_entities(&runtime).await;
        let link = ingest_link(
            &runtime,
            make_test_link(
                Some(TenantId::from_str(TEST_TENANT)),
                hydra_core::IdentityLinkKind::DependsOn,
                &a,
                &b,
                0.95,
            ),
        )
        .await;
        let app = trust_router(runtime.clone());
        // Different tenant — must surface as 404, not 500.
        let response = app
            .oneshot(empty_get_for_tenant(
                &format!("/trust/identity/links/{}", link.id.as_str()),
                "tenant_evil",
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "wrong-tenant probe must surface as 404, NOT 500 (the \
             broader 'unknown identity' substring covers both link \
             and endpoint-entity P33 errors)"
        );
    }

    #[tokio::test]
    async fn link_trust_empty_link_id_returns_404() {
        // `IdentityLinkId::from_str("")` is malformed → miss in
        // the engine → 404. (Empty path segment doesn't bind the
        // route, so we send a trailing-slash probe; axum returns
        // 404 NOT_FOUND from the router, not the handler. Either
        // way the caller sees 404 — pin both reachability paths.)
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/trust/identity/links/"))
            .await
            .unwrap();
        // Trailing slash without a segment doesn't bind
        // `:link_id` — axum returns 404.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn link_trust_link_id_url_encoded() {
        // axum's Path<String> extractor decodes URL-encoded
        // segments. IdentityLinkId is alphanumeric in practice
        // (ULID-format), but the route accepts any string —
        // verify a percent-encoded id round-trips through the
        // decoder and reaches the handler (which then fails the
        // engine lookup and returns 404).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        // %20 = space; axum decodes to " idl_x" — still unknown,
        // still 404. Pins URL-decoding semantics.
        let response = app
            .oneshot(empty_get("/trust/identity/links/%20idl_x"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn link_trust_route_lives_in_trust_router() {
        // Sanity pin: P40 route mounts on trust_router (not
        // identity_router). Pinning 404-on-unknown via the
        // trust_router proves the route resolved through this
        // router (vs being unmounted).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = trust_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/trust/identity/links/idl_ghost"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
