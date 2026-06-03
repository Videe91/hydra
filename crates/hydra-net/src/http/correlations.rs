//! # Patch 46 — Correlation HTTP surface
//!
//! Exposes the Patch 45 engine method
//! `Hydra::assess_correlation_candidate` as one route:
//!
//! ```text
//! POST /correlations/assess
//! ```
//!
//! ## Auth
//!
//! New scope: `read:correlation`.
//!
//! The route is `&self` read-only at the engine (pinned by
//! `assess_correlation_candidate_no_persistence`), but the
//! request body shape (a vector of `CorrelationSignalRef`)
//! requires `POST` over `GET`. Correlation can reveal
//! cross-object relationships, so the dedicated scope is
//! correct — it is NOT covered by `read:query` /
//! `read:identity` / `read:trust`.
//!
//! ## Tenant isolation (anti-smuggling)
//!
//! `X-Hydra-Tenant` REQUIRED. The handler **overwrites every
//! signal's `tenant_id`** with the header value before calling
//! the engine. This neutralizes any cross-tenant smuggling
//! attempt via the body; the engine's per-signal tenant
//! equality check (load-bearing tenant rule) remains as
//! defense-in-depth.
//!
//! ## Response shape
//!
//! - 200: `{ "candidate": CorrelationCandidate }`
//! - 400: bad input (too few signals, invalid signal kind,
//!   tenant header missing, tenant validation residual)
//! - 404: any referenced entity / cell / claim / evidence
//!   missing or cross-tenant (collapsed into the same
//!   `"unknown {kind}: {id}"` error string by the engine to
//!   prevent cross-tenant existence enumeration)
//! - 500: unexpected engine error
//!
//! ## Boundary held
//!
//! Patch 46 is HTTP/SDK over P45. **NO** persistence, **NO**
//! `CorrelationCandidateId`, **NO** `CausalCell` creation,
//! **NO** new engine behavior. Future P47 layers anchoring on
//! top of this wire surface.

use crate::http::tenant::{extract_tenant, tenant_error_response};
use crate::runtime::RuntimeHandle;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use crate::http::causal_cells::CausalCellResponse;
use hydra_core::{CorrelationCandidate, CorrelationSignalRef};
use serde::{Deserialize, Serialize};

/// Shared HTTP state for the correlations router.
///
/// Only `runtime` — `assess_correlation_candidate` is a
/// `&self` engine method, so a `RuntimeHandle` + `read().await`
/// is sufficient. No `QueryService` needed because we don't
/// hit the projection layer.
#[derive(Clone)]
pub struct CorrelationsHttpState {
    pub runtime: RuntimeHandle,
}

impl CorrelationsHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the correlations router. Two routes:
///
/// - `POST /correlations/assess` — Patch 46 over P45
///   (`&self` engine method, anti-smuggling OVERWRITE).
/// - `POST /correlations/anchor` — Patch 48 over P47
///   (`&mut self` engine method, anti-smuggling VALIDATE).
///
/// **The two routes intentionally take OPPOSITE tenant-handling
/// stances.** `assess` overwrites because it computes a fresh
/// verdict from raw signals; `anchor` validates (rejects on
/// mismatch) because it anchors a PRE-assessed verdict —
/// overwriting tenant on an already-scored candidate would let
/// tenant_A's verdict get smuggled into tenant_B's anchor by
/// header swap.
pub fn correlations_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/correlations/assess", post(assess_correlation_candidate))
        .route("/correlations/anchor", post(anchor_correlation_candidate))
        .with_state(CorrelationsHttpState::new(runtime))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Request body for `POST /correlations/assess`.
///
/// Carries a list of `CorrelationSignalRef`s. The handler
/// overwrites every `signal.tenant_id` from the
/// `X-Hydra-Tenant` header before calling the engine — any
/// body-supplied tenant value is ignored / replaced.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AssessCorrelationCandidateRequest {
    pub signals: Vec<CorrelationSignalRef>,
}

/// Request body for `POST /correlations/anchor` — Patch 48.
///
/// Carries a PRE-assessed `CorrelationCandidate` (whose
/// `trust` verdict has already been computed and reviewed)
/// plus the `actor` performing the anchor.
///
/// **The handler VALIDATES (does NOT overwrite) the
/// candidate's `tenant_id` and every `signal.tenant_id`
/// against the `X-Hydra-Tenant` header.** This is the
/// load-bearing deviation from P46 — overwriting tenant on
/// a pre-assessed verdict would let tenant_A's verdict get
/// smuggled into tenant_B's anchor.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnchorCorrelationCandidateRequest {
    pub candidate: CorrelationCandidate,
    pub actor: String,
}

/// 200 envelope for `POST /correlations/assess`.
///
/// Mirrors P31 `{entity: ...}` / P38 `{link: ...}` shape —
/// dedicated envelope key under a one-object response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationCandidateResponse {
    pub candidate: CorrelationCandidate,
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

/// `POST /correlations/assess` — Patch 46 wire over P45.
///
/// ## Flow
///
/// 1. Extract `X-Hydra-Tenant`. Missing → 400.
/// 2. **Overwrite** every `signal.tenant_id` from the header
///    value (anti-smuggling — mirrors P31/P38 entity/link
///    tenant overwrite).
/// 3. Acquire engine read lock (`&self` method).
/// 4. Call `assess_correlation_candidate`.
/// 5. Map `QueryError(msg)`:
///    - `msg.contains("unknown")` (entity/cell/claim/evidence
///      miss; collapsed by the engine to avoid cross-tenant
///      enumeration) → **404**
///    - otherwise (too-few signals, invalid kind, residual
///      tenant validation) → **400**
/// 6. Anything else → 500.
///
/// ## Suggestion-only contract carry-forward (from P45)
///
/// v1 assesses caller-provided groupings, NOT discovers them.
/// Weights are calibrated for explainability; auto-actions
/// MUST compose `trust.level == High AND trust.score >=
/// ACCEPT_CORRELATION_FLOOR` with a dedicated audit event —
/// never act on this response alone.
async fn assess_correlation_candidate(
    State(state): State<CorrelationsHttpState>,
    headers: HeaderMap,
    Json(req): Json<AssessCorrelationCandidateRequest>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };

    // Anti-smuggling: stamp the tenant from the header onto
    // every signal. The engine's per-signal tenant equality
    // check (load-bearing tenant rule) then becomes a
    // tautology — kept as defense-in-depth at the engine
    // boundary.
    let mut signals = req.signals;
    for signal in &mut signals {
        signal.tenant_id = Some(tenant.clone());
    }

    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    match hydra.assess_correlation_candidate(Some(&tenant), signals) {
        Ok(candidate) => (
            StatusCode::OK,
            Json(CorrelationCandidateResponse { candidate }),
        )
            .into_response(),
        Err(hydra_core::error::HydraError::QueryError(msg))
            if msg.contains("unknown") =>
        {
            // Engine miss vocabulary collapses wrong-tenant
            // + miss into one unified "unknown {kind}: {id}"
            // error — single substring discriminator covers
            // all four reference kinds (entity / cell /
            // claim / evidence).
            error_response(StatusCode::NOT_FOUND, msg)
        }
        Err(hydra_core::error::HydraError::QueryError(msg)) => {
            // Too-few signals, invalid signal kind, residual
            // tenant validation (cannot fire after the
            // overwrite above, but kept for completeness).
            error_response(StatusCode::BAD_REQUEST, msg)
        }
        Err(other) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("assess_correlation_candidate failed: {other}"),
        ),
    }
}

/// `POST /correlations/anchor` — Patch 48 wire over Patch 47.
///
/// Anchors a trust-gated `CorrelationCandidate` as a durable
/// `CausalCellKind::Incident`. Reuses the existing
/// `CausalCellResponse { cell: ... }` envelope from P25 to
/// keep cell-returning routes consistent.
///
/// ## Load-bearing tenant rule: VALIDATE, do NOT overwrite
///
/// Unlike `assess` (which overwrites every `signal.tenant_id`
/// from the header because the verdict is computed AFTER
/// normalization), `anchor` VALIDATES strict equality between
/// the header tenant and BOTH the candidate's `tenant_id` AND
/// every `signal.tenant_id`. Overwriting on a pre-assessed
/// verdict would let tenant_A's verdict get smuggled into
/// tenant_B's anchor by header swap.
///
/// Validation runs BEFORE acquiring the engine write lock —
/// rejected requests never reach the lock.
///
/// ## Flow
///
/// 1. Extract `X-Hydra-Tenant`. Missing → 400.
/// 2. Validate `candidate.tenant_id == Some(header)`. Mismatch → 400.
/// 3. Validate every `signal.tenant_id == Some(header)`. Mismatch → 400.
/// 4. Parse `actor` as `ActorId` (engine rejects empty).
/// 5. Acquire engine WRITE lock (P47 method is `&mut self`).
/// 6. Call `Hydra::anchor_correlation_candidate`.
/// 7. Map `QueryError(msg)` → **400** (every engine rejection
///    is caller-fixable — there is no 404 path because P47
///    performs NO entity/cell/claim/evidence lookups).
/// 8. Anything else → 500.
///
/// ## v1 boundary
///
/// No dedup / fingerprint — repeated POSTs of the same body
/// intentionally produce DISTINCT `CausalCell`s. Caller is the
/// policy authority. Pinned by
/// `anchor_correlation_creates_distinct_cells_on_repeat`.
async fn anchor_correlation_candidate(
    State(state): State<CorrelationsHttpState>,
    headers: HeaderMap,
    Json(req): Json<AnchorCorrelationCandidateRequest>,
) -> Response {
    // 1. Tenant from header (REQUIRED).
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };

    // 2. LOAD-BEARING: VALIDATE, do NOT overwrite. Anchoring a
    //    pre-assessed verdict means tenant_A's verdict cannot
    //    be smuggled into tenant_B by header swap. Both
    //    candidate-level and per-signal tenants must equal the
    //    header tenant strictly.
    if req.candidate.tenant_id.as_ref() != Some(&tenant) {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "candidate tenant mismatch (header {:?} vs \
                 candidate {:?})",
                tenant, req.candidate.tenant_id,
            ),
        );
    }
    for (idx, signal) in req.candidate.signals.iter().enumerate() {
        if signal.tenant_id.as_ref() != Some(&tenant) {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "signal[{idx}] tenant mismatch (header {:?} vs \
                     signal {:?})",
                    tenant, signal.tenant_id,
                ),
            );
        }
    }

    // 3. Parse actor (engine validates non-empty).
    let actor = hydra_core::ActorId::from_str(&req.actor);

    // 4. Acquire WRITE lock — P47 engine method is &mut self.
    let hydra = state.runtime.hydra();
    let mut hydra = hydra.write().await;
    match hydra.anchor_correlation_candidate(
        Some(&tenant),
        req.candidate,
        actor,
    ) {
        Ok(cell) => {
            (StatusCode::OK, Json(CausalCellResponse { cell })).into_response()
        }
        Err(hydra_core::error::HydraError::QueryError(msg)) => {
            // Every engine rejection is caller-fixable: invalid
            // actor, tenant mismatch (residual; can't fire after
            // the wire-level validation above), validate_*,
            // < 2 signals, trust below gate. No 404 path
            // because P47 does no store lookups.
            error_response(StatusCode::BAD_REQUEST, msg)
        }
        Err(other) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("anchor_correlation_candidate failed: {other}"),
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
        ActorId, Confidence, EvidenceId, IdentityAlias, IdentityEntity,
        IdentityEntityId, IdentityEntityKind, IdentityLink,
        IdentityLinkKind, TenantId, Value,
    };
    use std::collections::HashMap;
    use tower::ServiceExt;

    const TEST_TENANT: &str = "tenant_correlations_http_test";

    fn json_post(uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("X-Hydra-Tenant", TEST_TENANT)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn json_post_for_tenant(
        uri: &str,
        tenant: &str,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("X-Hydra-Tenant", tenant)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn json_post_without_tenant(
        uri: &str,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    async fn read_body_bytes(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    fn minimal_signal_json(id: &str, tenant: Option<&str>) -> serde_json::Value {
        serde_json::json!({
            "kind": "External",
            "id": id,
            "tenant_id": tenant,
            "observed_at": null,
            "entity_ids": [],
            "cell_ids": [],
            "claim_ids": [],
            "evidence_ids": [],
            "metadata": {},
        })
    }

    /// Seed a single high-trust entity so `entity_ids` references
    /// in signals resolve. Same shape as the P45 helper
    /// `p39_seed_high_trust_pair` but single-entity.
    fn make_entity(tenant: &TenantId, key: &str) -> IdentityEntity {
        let now = chrono::Utc::now();
        IdentityEntity {
            id: IdentityEntityId::new(),
            tenant_id: Some(tenant.clone()),
            kind: IdentityEntityKind::Dataset,
            canonical_key: key.to_string(),
            display_name: key.to_string(),
            aliases: vec![
                IdentityAlias {
                    source: "snowflake".to_string(),
                    namespace: Some("analytics".to_string()),
                    external_id: Some(format!("{key}_X").to_uppercase()),
                    label: key.to_string(),
                    normalized: key.to_lowercase(),
                },
                IdentityAlias {
                    source: "dbt".to_string(),
                    namespace: Some("models".to_string()),
                    external_id: Some(format!("{key}_Y").to_uppercase()),
                    label: key.to_string(),
                    normalized: key.to_lowercase(),
                },
                IdentityAlias {
                    source: "looker".to_string(),
                    namespace: Some("finance".to_string()),
                    external_id: Some(format!("{key}_Z").to_uppercase()),
                    label: key.to_string(),
                    normalized: key.to_lowercase(),
                },
            ],
            confidence: Confidence::new(0.95),
            metadata: {
                let mut m = HashMap::new();
                m.insert(
                    "owner".to_string(),
                    Value::String("ops".to_string()),
                );
                m
            },
            created_by: ActorId::from_str("actor_ops"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    async fn ingest_entity(
        runtime: &crate::runtime::RuntimeHandle,
        entity: IdentityEntity,
    ) -> IdentityEntity {
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra.create_identity_entity(entity).unwrap()
    }

    async fn ingest_link(
        runtime: &crate::runtime::RuntimeHandle,
        link: IdentityLink,
    ) -> IdentityLink {
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra.create_identity_link(link).unwrap()
    }

    // === Tests ===

    #[tokio::test]
    async fn assess_correlation_candidate_returns_candidate() {
        // Happy path: two minimal External signals → 200 with
        // the `{candidate: ...}` envelope; 11 reasons + 11
        // factors emitted (explainability contract).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let body = serde_json::json!({
            "signals": [
                minimal_signal_json("ext_a", Some(TEST_TENANT)),
                minimal_signal_json("ext_b", Some(TEST_TENANT)),
            ],
        });
        let response = router
            .oneshot(json_post("/correlations/assess", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = read_body_bytes(response).await;
        let envelope: CorrelationCandidateResponse =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(envelope.candidate.reasons.len(), 11);
        assert_eq!(envelope.candidate.trust.factors.len(), 11);
        // Tenant slot mirrored on the candidate.
        assert_eq!(
            envelope.candidate.tenant_id.as_ref().map(|t| t.as_str()),
            Some(TEST_TENANT)
        );
    }

    #[tokio::test]
    async fn assess_correlation_candidate_requires_tenant() {
        // Missing `X-Hydra-Tenant` → 400 (anti-smuggling — the
        // tenant header is the SOLE authoritative source for
        // correlation tenancy).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let body = serde_json::json!({
            "signals": [
                minimal_signal_json("ext_a", Some(TEST_TENANT)),
                minimal_signal_json("ext_b", Some(TEST_TENANT)),
            ],
        });
        let response = router
            .oneshot(json_post_without_tenant("/correlations/assess", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn assess_correlation_candidate_overwrites_signal_tenants() {
        // LOAD-BEARING anti-smuggling pin: even when the body
        // signals carry a DIFFERENT tenant_id, the handler
        // overwrites every one with the X-Hydra-Tenant value
        // BEFORE the engine sees them. The returned candidate
        // (and every signal inside it) must carry the header
        // tenant, NOT the smuggled body tenant.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let body = serde_json::json!({
            "signals": [
                minimal_signal_json("ext_a", Some("tenant_smuggled")),
                minimal_signal_json("ext_b", Some("tenant_smuggled")),
            ],
        });
        let response = router
            .oneshot(json_post("/correlations/assess", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = read_body_bytes(response).await;
        let envelope: CorrelationCandidateResponse =
            serde_json::from_slice(&bytes).unwrap();
        // Candidate tenant matches header.
        assert_eq!(
            envelope.candidate.tenant_id.as_ref().map(|t| t.as_str()),
            Some(TEST_TENANT)
        );
        // Every signal's tenant was overwritten.
        for signal in &envelope.candidate.signals {
            assert_eq!(
                signal.tenant_id.as_ref().map(|t| t.as_str()),
                Some(TEST_TENANT),
                "smuggled body tenant must be overwritten by header"
            );
        }
    }

    #[tokio::test]
    async fn assess_correlation_candidate_rejects_too_few_signals() {
        // Engine policy (NOT P44 vocab policy, which treats
        // empty signals as vacuously consistent): assess
        // requires ≥ 2 signals. Surface as 400.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let body = serde_json::json!({
            "signals": [
                minimal_signal_json("ext_solo", Some(TEST_TENANT)),
            ],
        });
        let response = router
            .oneshot(json_post("/correlations/assess", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = read_body_bytes(response).await;
        let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(
            err.error.contains("at least two signals"),
            "expected too-few-signals message, got: {}",
            err.error
        );
    }

    #[tokio::test]
    async fn assess_correlation_candidate_rejects_unknown_reference() {
        // Wrong-tenant + miss collapse into a single
        // "unknown identity entity" error → 404. Pins the
        // anti-enumeration boundary.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        // Signal references an entity that doesn't exist.
        let ghost = "ide_ghost";
        let body = serde_json::json!({
            "signals": [
                {
                    "kind": "External",
                    "id": "ext_a",
                    "tenant_id": TEST_TENANT,
                    "observed_at": null,
                    "entity_ids": [ghost],
                    "cell_ids": [],
                    "claim_ids": [],
                    "evidence_ids": [],
                    "metadata": {},
                },
                minimal_signal_json("ext_b", Some(TEST_TENANT)),
            ],
        });
        let response = router
            .oneshot(json_post("/correlations/assess", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let bytes = read_body_bytes(response).await;
        let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(
            err.error.contains("unknown identity entity"),
            "expected unknown-entity error, got: {}",
            err.error
        );
    }

    #[tokio::test]
    async fn assess_correlation_candidate_preserves_reasons_and_factors() {
        // Reasons and trust.factors stay 1:1 (same length, same
        // kind discriminants per index, same applied bits +
        // weights + details). Pinned so any future refactor
        // that drifts the mirror fires here.
        let expected_kinds: &[&str] = &[
            "same_identity_entity",
            "trusted_identity_link",
            "same_source",
            "source_trust_high",
            "entity_trust_high",
            "cell_trust_high",
            "time_proximity",
            "semantic_similarity",
            "claim_predicate_similarity",
            "contradiction",
            "operator_confirmed",
        ];
        let (runtime, _processor) = RuntimeBuilder::new().build();
        // Seed a high-trust entity + link so a few positive
        // factors fire (exercises the wire path beyond the
        // all-stub case).
        let tenant = TenantId::from_str(TEST_TENANT);
        let a = ingest_entity(&runtime, make_entity(&tenant, "ds_a")).await;
        let b = ingest_entity(&runtime, make_entity(&tenant, "ds_b")).await;
        let link = IdentityLink {
            id: hydra_core::IdentityLinkId::new(),
            tenant_id: Some(tenant.clone()),
            kind: IdentityLinkKind::DependsOn,
            from_entity_id: a.id.clone(),
            to_entity_id: b.id.clone(),
            confidence: Confidence::new(0.95),
            evidence_ids: vec![EvidenceId::from_str("evd_link")],
            claim_ids: vec![],
            cell_ids: vec![],
            metadata: HashMap::new(),
            created_by: ActorId::from_str("actor_ops"),
            created_at: chrono::Utc::now(),
            caused_by: None,
        };
        ingest_link(&runtime, link).await;

        let router = correlations_router(runtime);
        let body = serde_json::json!({
            "signals": [
                {
                    "kind": "IdentityEntity",
                    "id": a.id.as_str(),
                    "tenant_id": TEST_TENANT,
                    "observed_at": null,
                    "entity_ids": [a.id.as_str()],
                    "cell_ids": [],
                    "claim_ids": [],
                    "evidence_ids": [],
                    "metadata": {},
                },
                {
                    "kind": "IdentityEntity",
                    "id": b.id.as_str(),
                    "tenant_id": TEST_TENANT,
                    "observed_at": null,
                    "entity_ids": [b.id.as_str()],
                    "cell_ids": [],
                    "claim_ids": [],
                    "evidence_ids": [],
                    "metadata": {},
                },
            ],
        });
        let response = router
            .oneshot(json_post("/correlations/assess", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = read_body_bytes(response).await;
        let envelope: CorrelationCandidateResponse =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(envelope.candidate.reasons.len(), 11);
        assert_eq!(envelope.candidate.trust.factors.len(), 11);
        for (i, expected) in expected_kinds.iter().enumerate() {
            assert_eq!(
                envelope.candidate.reasons[i].kind.discriminant(),
                *expected,
                "reason[{i}] must be {expected}"
            );
            assert_eq!(
                envelope.candidate.trust.factors[i].kind,
                *expected,
                "factor[{i}] must mirror reason kind"
            );
            assert_eq!(
                envelope.candidate.reasons[i].applied,
                envelope.candidate.trust.factors[i].applied
            );
            assert_eq!(
                envelope.candidate.reasons[i].weight,
                envelope.candidate.trust.factors[i].weight
            );
            assert_eq!(
                envelope.candidate.reasons[i].detail,
                envelope.candidate.trust.factors[i].detail
            );
        }
        // Trusted link fired (entities seeded + link assessed
        // High in P39) — exercises a positive factor through
        // the wire surface.
        assert!(
            envelope
                .candidate
                .reasons
                .iter()
                .find(|r| r.kind.discriminant() == "trusted_identity_link")
                .unwrap()
                .applied,
            "trusted_identity_link should fire over seeded link"
        );
    }

    #[tokio::test]
    async fn assess_correlation_candidate_returns_strength_none_as_string() {
        // Wire serde pin: `CorrelationStrength::None` MUST be
        // the STRING `"None"`, never JSON null. Same gotcha as
        // MatchLevel — SDK callers compare against `"None"`,
        // not Python None.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let body = serde_json::json!({
            "signals": [
                minimal_signal_json("ext_a", Some(TEST_TENANT)),
                minimal_signal_json("ext_b", Some(TEST_TENANT)),
            ],
        });
        let response = router
            .oneshot(json_post("/correlations/assess", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = read_body_bytes(response).await;
        let raw: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap();
        let strength = &raw["candidate"]["trust"]["strength"];
        // PascalCase string, NOT JSON null. Two empty signals
        // score 0.0 → CorrelationStrength::None.
        assert_eq!(strength, &serde_json::json!("None"));
        assert!(!strength.is_null());
    }

    #[tokio::test]
    async fn assess_correlation_candidate_rejects_wrong_header_tenant() {
        // A caller with header tenant_X cannot pivot to see
        // tenant_Y's entities: even if the body smuggles
        // tenant_Y-valid entity ids, the handler overwrites
        // signal.tenant_id with the header tenant. The engine
        // then looks up entity_ids strictly within the header
        // tenant — and resolves "unknown identity entity" for
        // a cross-tenant reference (collapsed with miss; no
        // enumeration).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let other_tenant = TenantId::from_str("tenant_other");
        let other_entity = ingest_entity(
            &runtime,
            make_entity(&other_tenant, "other_ds"),
        )
        .await;
        let router = correlations_router(runtime);
        let body = serde_json::json!({
            "signals": [
                {
                    "kind": "IdentityEntity",
                    "id": other_entity.id.as_str(),
                    "tenant_id": "tenant_other",
                    "observed_at": null,
                    "entity_ids": [other_entity.id.as_str()],
                    "cell_ids": [],
                    "claim_ids": [],
                    "evidence_ids": [],
                    "metadata": {},
                },
                minimal_signal_json("ext_b", Some(TEST_TENANT)),
            ],
        });
        let response = router
            .oneshot(json_post_for_tenant(
                "/correlations/assess",
                TEST_TENANT,
                body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let bytes = read_body_bytes(response).await;
        let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        // Same unified "unknown" error — wrong tenant ≡ miss.
        assert!(err.error.contains("unknown identity entity"));
    }

    // === Patch 48 — `POST /correlations/anchor` =====================
    //
    // Pins the new anchor wire surface over the P47 engine method.
    // The critical adaptation versus P46 assess: VALIDATE the
    // candidate + signal tenants against the header (do NOT
    // overwrite). Two tests pin the inverse-of-P46 behavior:
    // `rejects_tenant_mismatch_candidate` + `rejects_signal_tenant_mismatch`.

    /// Build a `CorrelationCandidate` JSON literal with caller-
    /// controlled trust verdict. Mirrors the P47 engine helper
    /// `p47_synthetic_candidate` but produces wire-form JSON
    /// suitable for the request body.
    #[allow(clippy::too_many_arguments)]
    fn p48_candidate_json(
        tenant: &str,
        signal_tenants: &[&str],
        score: f64,
        level: &str,
        strength: &str,
    ) -> serde_json::Value {
        let signals: Vec<serde_json::Value> = signal_tenants
            .iter()
            .enumerate()
            .map(|(i, t)| {
                serde_json::json!({
                    "kind": "External",
                    "id": format!("ext_p48_{i}"),
                    "tenant_id": t,
                    "observed_at": null,
                    "entity_ids": [],
                    "cell_ids": [],
                    "claim_ids": [],
                    "evidence_ids": [],
                    "metadata": {},
                })
            })
            .collect();
        // All 11 reason discriminants — engine doesn't inspect
        // these on anchor, but the wire form must round-trip
        // through serde::Deserialize<CorrelationCandidate>.
        let reasons: Vec<serde_json::Value> = [
            "SameIdentityEntity",
            "TrustedIdentityLink",
            "SameSource",
            "SourceTrustHigh",
            "EntityTrustHigh",
            "CellTrustHigh",
            "TimeProximity",
            "SemanticSimilarity",
            "ClaimPredicateSimilarity",
            "Contradiction",
            "OperatorConfirmed",
        ]
        .iter()
        .map(|k| {
            serde_json::json!({
                "kind": k,
                "weight": 0.0,
                "applied": false,
                "detail": "p48 fixture stub",
            })
        })
        .collect();
        let factors: Vec<serde_json::Value> = [
            "same_identity_entity",
            "trusted_identity_link",
            "same_source",
            "source_trust_high",
            "entity_trust_high",
            "cell_trust_high",
            "time_proximity",
            "semantic_similarity",
            "claim_predicate_similarity",
            "contradiction",
            "operator_confirmed",
        ]
        .iter()
        .map(|k| {
            serde_json::json!({
                "kind": k,
                "weight": 0.0,
                "applied": false,
                "detail": "p48 fixture stub",
            })
        })
        .collect();
        serde_json::json!({
            "tenant_id": tenant,
            "signals": signals,
            "entity_ids": [],
            "cell_ids": [],
            "time_window_start": null,
            "time_window_end": null,
            "reasons": reasons,
            "trust": {
                "correlation_id": null,
                "score": score,
                "level": level,
                "strength": strength,
                "explanation": "p48 fixture verdict",
                "factors": factors,
                "assessed_at": "2026-06-02T12:00:00Z",
            },
            "created_at": "2026-06-02T12:00:00Z",
        })
    }

    #[tokio::test]
    async fn anchor_correlation_returns_cell() {
        // Happy path: synthetic High/Strong candidate with two
        // signals → 200 + `{cell: CausalCell}` envelope; cell is
        // an Incident and survives in the store.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let candidate = p48_candidate_json(
            TEST_TENANT,
            &[TEST_TENANT, TEST_TENANT],
            0.95,
            "High",
            "Strong",
        );
        let body = serde_json::json!({
            "candidate": candidate,
            "actor": "actor_ops",
        });
        let response = router
            .oneshot(json_post("/correlations/anchor", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = read_body_bytes(response).await;
        // Envelope is `{cell: ...}`; deserialize through the
        // wire shape, then assert kind + trust score
        // preservation.
        let raw: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(raw["cell"]["kind"], serde_json::json!("Incident"));
        assert_eq!(
            raw["cell"]["tenant_id"],
            serde_json::json!(TEST_TENANT)
        );
        assert_eq!(
            raw["cell"]["trust_score"],
            serde_json::json!(0.95)
        );
    }

    #[tokio::test]
    async fn anchor_correlation_requires_tenant() {
        // Missing `X-Hydra-Tenant` → 400.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let candidate = p48_candidate_json(
            TEST_TENANT,
            &[TEST_TENANT, TEST_TENANT],
            0.95,
            "High",
            "Strong",
        );
        let body = serde_json::json!({
            "candidate": candidate,
            "actor": "actor_ops",
        });
        let response = router
            .oneshot(json_post_without_tenant(
                "/correlations/anchor",
                body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn anchor_correlation_rejects_empty_actor() {
        // `actor: ""` → engine rejects with "invalid actor"; wire
        // surfaces 400.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let candidate = p48_candidate_json(
            TEST_TENANT,
            &[TEST_TENANT, TEST_TENANT],
            0.95,
            "High",
            "Strong",
        );
        let body = serde_json::json!({
            "candidate": candidate,
            "actor": "",
        });
        let response = router
            .oneshot(json_post("/correlations/anchor", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = read_body_bytes(response).await;
        let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(
            err.error.contains("invalid actor"),
            "expected 'invalid actor', got: {}",
            err.error
        );
    }

    #[tokio::test]
    async fn anchor_correlation_rejects_tenant_mismatch_candidate() {
        // LOAD-BEARING anti-smuggling pin: candidate.tenant_id =
        // "tenant_smuggled" while header = TEST_TENANT must be
        // REJECTED at the wire layer (NOT overwritten). This is
        // the INVERSE of the P46 `assess` overwrite pin.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let candidate = p48_candidate_json(
            "tenant_smuggled",
            &["tenant_smuggled", "tenant_smuggled"],
            0.95,
            "High",
            "Strong",
        );
        let body = serde_json::json!({
            "candidate": candidate,
            "actor": "actor_ops",
        });
        let response = router
            .oneshot(json_post("/correlations/anchor", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = read_body_bytes(response).await;
        let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(
            err.error.contains("candidate tenant mismatch"),
            "expected candidate-tenant-mismatch message, got: {}",
            err.error
        );
    }

    #[tokio::test]
    async fn anchor_correlation_rejects_signal_tenant_mismatch() {
        // LOAD-BEARING: even when candidate.tenant_id matches
        // the header, a single mismatched signal.tenant_id MUST
        // be rejected (NOT overwritten). The validation runs
        // before the write lock — engine never sees the request.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let candidate = p48_candidate_json(
            TEST_TENANT,
            // First signal valid, second smuggles a different
            // tenant — wire layer must reject.
            &[TEST_TENANT, "tenant_smuggled"],
            0.95,
            "High",
            "Strong",
        );
        let body = serde_json::json!({
            "candidate": candidate,
            "actor": "actor_ops",
        });
        let response = router
            .oneshot(json_post("/correlations/anchor", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = read_body_bytes(response).await;
        let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(
            err.error.contains("signal[1] tenant mismatch"),
            "expected signal-tenant-mismatch message, got: {}",
            err.error
        );
    }

    #[tokio::test]
    async fn anchor_correlation_rejects_low_trust() {
        // Synthetic verdict below the gate (Low / Weak / 0.30)
        // → engine rejects with "trust below"; wire surfaces 400.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let candidate = p48_candidate_json(
            TEST_TENANT,
            &[TEST_TENANT, TEST_TENANT],
            0.30,
            "Low",
            "Weak",
        );
        let body = serde_json::json!({
            "candidate": candidate,
            "actor": "actor_ops",
        });
        let response = router
            .oneshot(json_post("/correlations/anchor", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = read_body_bytes(response).await;
        let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(
            err.error.contains("trust below"),
            "expected 'trust below', got: {}",
            err.error
        );
    }

    #[tokio::test]
    async fn anchor_correlation_rejects_too_few_signals() {
        // Single-signal candidate → engine min-2 check fires;
        // wire surfaces 400.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let candidate = p48_candidate_json(
            TEST_TENANT,
            &[TEST_TENANT],
            0.95,
            "High",
            "Strong",
        );
        let body = serde_json::json!({
            "candidate": candidate,
            "actor": "actor_ops",
        });
        let response = router
            .oneshot(json_post("/correlations/anchor", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = read_body_bytes(response).await;
        let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(
            err.error.contains("at least two signals"),
            "expected 'at least two signals', got: {}",
            err.error
        );
    }

    #[tokio::test]
    async fn anchor_correlation_preserves_trust_score() {
        // The candidate's trust.score lands on cell.trust_score
        // verbatim — P47's "trust the supplied verdict"
        // contract surfaces through the wire.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let candidate = p48_candidate_json(
            TEST_TENANT,
            &[TEST_TENANT, TEST_TENANT],
            0.93,
            "High",
            "Strong",
        );
        let body = serde_json::json!({
            "candidate": candidate,
            "actor": "actor_ops",
        });
        let response = router
            .oneshot(json_post("/correlations/anchor", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = read_body_bytes(response).await;
        let raw: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap();
        // 0.93 must round-trip exactly through serde — pin
        // against float-coercion drift.
        let stored = raw["cell"]["trust_score"]
            .as_f64()
            .expect("trust_score present");
        assert!(
            (stored - 0.93).abs() < 1e-9,
            "expected 0.93 verbatim, got {stored}"
        );
    }

    #[tokio::test]
    async fn anchor_correlation_creates_distinct_cells_on_repeat() {
        // No dedup / fingerprint in v1 — POSTing the same body
        // twice produces distinct CausalCell ids. Caller is the
        // policy authority. Mirrors P47's
        // "no dedup / fingerprint" boundary.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let router = correlations_router(runtime);
        let candidate = p48_candidate_json(
            TEST_TENANT,
            &[TEST_TENANT, TEST_TENANT],
            0.95,
            "High",
            "Strong",
        );
        let body = serde_json::json!({
            "candidate": candidate,
            "actor": "actor_ops",
        });
        let first = router
            .clone()
            .oneshot(json_post("/correlations/anchor", body.clone()))
            .await
            .unwrap();
        let second = router
            .oneshot(json_post("/correlations/anchor", body))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        let first_bytes = read_body_bytes(first).await;
        let second_bytes = read_body_bytes(second).await;
        let first_raw: serde_json::Value =
            serde_json::from_slice(&first_bytes).unwrap();
        let second_raw: serde_json::Value =
            serde_json::from_slice(&second_bytes).unwrap();
        let first_id = first_raw["cell"]["id"].as_str().unwrap();
        let second_id = second_raw["cell"]["id"].as_str().unwrap();
        assert_ne!(
            first_id, second_id,
            "P47 v1 has no dedup — repeated anchors must produce \
             distinct cell ids"
        );
    }
}
