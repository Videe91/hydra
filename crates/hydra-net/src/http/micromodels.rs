//! Living-database phase → MicroModel Patch 5: external evaluation surface.
//!
//! Exposes the engine's commit-rate anomaly micro-model as an HTTP
//! endpoint so agents and operators can drive evaluations from
//! outside Rust. Composes Patches 2 / 3 / 4 — the engine method
//! routed depends on the request's `mode`:
//!
//! ```text
//!   mode = "prediction_only"  → Hydra::evaluate_commit_rate_anomaly
//!   mode = "claim"            → Hydra::evaluate_commit_rate_anomaly_and_propose_claim
//!   mode = "action" (default) → Hydra::evaluate_commit_rate_anomaly_and_propose_action
//! ```
//!
//! ## Route
//!
//! ```text
//! POST /diagnostics/micromodels/commit-rate/evaluate
//! ```
//!
//! ## Auth
//!
//! New scope `write:diagnostics` (added in `hydra-api::auth`).
//! Diagnostic reads stay on `read:query`; *evaluations* mutate
//! Hydra's causal memory (prediction event, maybe evidence + claim,
//! maybe Notify action) so they get their own write scope.
//!
//! ## What is NOT in this patch
//!
//! - No action execution. `ActionStatus::Proposed` is the highest
//!   state the engine reaches from this route — execution,
//!   delivery, throttling, and snapshot are explicit future patches.
//! - No background scheduler. The endpoint is invoked on demand.
//! - No automatic model evaluation on incoming commits. Patch 5
//!   surfaces the existing engine helpers; it does not change when
//!   they fire.

use crate::runtime::RuntimeHandle;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use hydra_core::{
    ActionId, ActorId, ClaimId, EventId, EvidenceId, MicroModelPrediction,
};
use hydra_engine::micromodels::AnomalyLevel;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct MicroModelsHttpState {
    pub runtime: RuntimeHandle,
}

impl MicroModelsHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the micro-model HTTP router.
///
/// Single route in v0:
/// `POST /diagnostics/micromodels/commit-rate/evaluate`.
/// Future micro-models (Patch 6+) will mount alongside.
pub fn micromodels_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route(
            "/diagnostics/micromodels/commit-rate/evaluate",
            post(evaluate_commit_rate),
        )
        .with_state(MicroModelsHttpState::new(runtime))
}

/// Request body for the commit-rate evaluate endpoint.
///
/// `mode` controls how far down the reflex chain the engine walks.
/// Defaults to `Action` so the most useful path is reached when the
/// caller omits the field.
///
/// `requested_by` is captured into the engine call's `actor`
/// argument. The Patch 2/3/4 helpers stash this for future audit
/// surfaces; today it isn't yet written into event bodies, but
/// the field is required so clients learn to send it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateCommitRateRequest {
    #[serde(default)]
    pub mode: EvaluationMode,
    pub requested_by: ActorId,
}

/// How far down the reflex chain the engine walks for one
/// evaluation. Wire form is snake_case strings:
/// `"prediction_only"`, `"claim"`, `"action"`. Default `"action"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationMode {
    /// Run only the model and record the prediction. No evidence,
    /// no claim, no action — even at Warning/Critical levels.
    PredictionOnly,
    /// Prediction + (on Warning/Critical) Evidence + Claim. No
    /// action.
    Claim,
    /// Prediction + (on Warning/Critical) Evidence + Claim + (gate
    /// permitting) one Notify action. The full reflex.
    Action,
}

impl Default for EvaluationMode {
    fn default() -> Self {
        EvaluationMode::Action
    }
}

/// Response body for the commit-rate evaluate endpoint.
///
/// The shape is stable across modes — fields not produced by the
/// caller's chosen mode (or not produced at all due to level /
/// gate decisions) are emitted as JSON `null` for ids and empty
/// vec for `action_ids`. The `level`, `prediction`, and
/// `prediction_event_id` fields are always populated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateCommitRateResponse {
    /// Snake-case anomaly level: `"warming_up"`, `"normal"`,
    /// `"warning"`, `"critical"`.
    pub level: String,
    /// Full MicroModelPrediction record as recorded in the engine.
    pub prediction: MicroModelPrediction,
    pub prediction_event_id: EventId,
    pub evidence_id: Option<EvidenceId>,
    pub evidence_event_id: Option<EventId>,
    pub claim_id: Option<ClaimId>,
    pub claim_event_id: Option<EventId>,
    /// One-element vec for Patch 5 Critical-tier (Notify only).
    /// Patch 6+ may add `snapshot_now`/`throttle_agents` here.
    pub action_ids: Vec<ActionId>,
    /// Deterministic prose summary keyed off `(level, has_claim,
    /// has_action)`. Agents can pattern-match on it safely.
    pub summary: String,
    /// Relative URL pointing at the prediction event's lineage
    /// view. Caller concatenates with their own base URL.
    pub lineage_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

async fn evaluate_commit_rate(
    State(state): State<MicroModelsHttpState>,
    request: Result<Json<EvaluateCommitRateRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    // Manual rejection handling — axum's default response for
    // Json<T> rejection is a plain 400 with no body. We want a
    // structured `{error: ...}` payload so SDKs can parse it.
    let request = match request {
        Ok(Json(req)) => req,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("invalid request body: {err}"),
                }),
            )
                .into_response();
        }
    };

    let hydra = state.runtime.hydra();
    let mut hydra = hydra.write().await;

    // Dispatch by mode. Each engine helper returns a different
    // type; we normalize into the same response shape below.
    let outcome = match request.mode {
        EvaluationMode::PredictionOnly => {
            // Use the engine's shared helper (made public in Patch 5)
            // so the prediction event id is returned alongside the
            // prediction itself.
            match hydra.record_commit_rate_prediction(request.requested_by.clone()) {
                Ok((prediction, event_id, output)) => {
                    EvaluationOutcome::from_prediction_only(prediction, event_id, output.level)
                }
                Err(err) => return engine_error_response(err),
            }
        }
        EvaluationMode::Claim => {
            match hydra
                .evaluate_commit_rate_anomaly_and_propose_claim(request.requested_by.clone())
            {
                Ok(assessment) => EvaluationOutcome::from_claim_assessment(assessment),
                Err(err) => return engine_error_response(err),
            }
        }
        EvaluationMode::Action => {
            match hydra
                .evaluate_commit_rate_anomaly_and_propose_action(request.requested_by.clone())
            {
                Ok(assessment) => EvaluationOutcome::from_action_assessment(assessment),
                Err(err) => return engine_error_response(err),
            }
        }
    };

    let response = build_response(outcome);
    (StatusCode::OK, Json(response)).into_response()
}

fn engine_error_response(err: hydra_core::error::HydraError) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: format!("engine error: {err}"),
        }),
    )
        .into_response()
}

/// Normalized intermediate so the response builder doesn't have to
/// fan out per mode. Always carries the prediction + event id;
/// optional fields reflect what the mode + level actually produced.
struct EvaluationOutcome {
    level: AnomalyLevel,
    prediction: MicroModelPrediction,
    prediction_event_id: EventId,
    evidence_id: Option<EvidenceId>,
    evidence_event_id: Option<EventId>,
    claim_id: Option<ClaimId>,
    claim_event_id: Option<EventId>,
    action_ids: Vec<ActionId>,
}

impl EvaluationOutcome {
    fn from_prediction_only(
        prediction: MicroModelPrediction,
        prediction_event_id: EventId,
        level: AnomalyLevel,
    ) -> Self {
        Self {
            level,
            prediction,
            prediction_event_id,
            evidence_id: None,
            evidence_event_id: None,
            claim_id: None,
            claim_event_id: None,
            action_ids: vec![],
        }
    }

    fn from_claim_assessment(
        assessment: hydra_engine::micromodels::CommitRateAnomalyAssessment,
    ) -> Self {
        Self {
            level: assessment.level,
            prediction: assessment.prediction,
            prediction_event_id: assessment.prediction_event_id,
            evidence_id: assessment.evidence_id,
            evidence_event_id: assessment.evidence_event_id,
            claim_id: assessment.claim_id,
            claim_event_id: assessment.claim_event_id,
            action_ids: vec![],
        }
    }

    fn from_action_assessment(
        assessment: hydra_engine::micromodels::CommitRateAnomalyActionAssessment,
    ) -> Self {
        // `CommitRateAnomalyActionAssessment` drops the
        // `evidence_event_id` field for brevity. The HTTP response
        // surface still wants it (clients building tools on the
        // event chain may need both event ids). We don't have it
        // here from the action assessment; the bridge captured it
        // inside the engine but discarded it from the outer return
        // type. Returning None is honest about that — the action
        // assessment is the Patch 4 "loop closed" type, not the
        // "all event ids" type.
        Self {
            level: assessment.level,
            prediction: assessment.prediction,
            prediction_event_id: assessment.prediction_event_id,
            evidence_id: assessment.evidence_id,
            evidence_event_id: None,
            claim_id: assessment.claim_id,
            claim_event_id: assessment.claim_event_id,
            action_ids: assessment.action_ids,
        }
    }
}

fn build_response(outcome: EvaluationOutcome) -> EvaluateCommitRateResponse {
    let summary = render_summary(
        outcome.level,
        outcome.claim_id.is_some(),
        !outcome.action_ids.is_empty(),
    );
    let lineage_url = format!("/lineage/{}", outcome.prediction_event_id);
    EvaluateCommitRateResponse {
        level: outcome.level.wire_name().to_string(),
        prediction: outcome.prediction,
        prediction_event_id: outcome.prediction_event_id,
        evidence_id: outcome.evidence_id,
        evidence_event_id: outcome.evidence_event_id,
        claim_id: outcome.claim_id,
        claim_event_id: outcome.claim_event_id,
        action_ids: outcome.action_ids,
        summary,
        lineage_url,
    }
}

/// Deterministic 8-case summary table keyed off level + what was
/// actually recorded. Agents can safely pattern-match on these
/// strings.
fn render_summary(level: AnomalyLevel, has_claim: bool, has_action: bool) -> String {
    match (level, has_claim, has_action) {
        (AnomalyLevel::WarmingUp, _, _) => "Model warming up; no claim or action.".to_string(),
        (AnomalyLevel::Normal, _, _) => {
            "Commit rate within expected range; no claim or action.".to_string()
        }
        (AnomalyLevel::Warning, false, _) => {
            "Warning: commit rate elevated; no claim or action recorded.".to_string()
        }
        (AnomalyLevel::Warning, true, false) => {
            "Warning: commit rate elevated; claim recorded, action not proposed \
             under current verification threshold."
                .to_string()
        }
        (AnomalyLevel::Warning, true, true) => {
            "Warning: commit rate elevated; claim recorded and Notify action \
             proposed."
                .to_string()
        }
        (AnomalyLevel::Critical, false, _) => {
            "Critical: commit rate anomalous; no claim or action recorded.".to_string()
        }
        (AnomalyLevel::Critical, true, false) => {
            "Critical: commit rate anomalous; claim recorded, action not proposed."
                .to_string()
        }
        (AnomalyLevel::Critical, true, true) => {
            "Critical: commit rate anomalous; Notify action proposed.".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use hydra_core::EventKind;
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn actor() -> String {
        "actor_http_evaluate_test".to_string()
    }

    async fn read_body_bytes(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    fn request_body(body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri("/diagnostics/micromodels/commit-rate/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    /// Pre-prime the engine so the model lands Critical on the
    /// next evaluation. Mirrors the engine-test priming pattern:
    /// force auto-register, then overwrite the model state with a
    /// known baseline (`ewma_rate=10`, `samples_seen=10` past
    /// warmup), then ingest enough signals to push observed rate
    /// well above the critical z-threshold.
    async fn prime_critical(runtime: &crate::runtime::RuntimeHandle) {
        let hydra_handle = runtime.hydra();
        // Force auto-register via one prediction-only call so the
        // registry events don't surprise the count.
        {
            let mut hydra = hydra_handle.write().await;
            let _ = hydra
                .evaluate_commit_rate_anomaly(hydra_core::ActorId::from_str(&actor()))
                .unwrap();
        }
        // Replace the engine's model with a primed baseline.
        {
            let mut hydra = hydra_handle.write().await;
            let config = hydra_engine::micromodels::CommitRateAnomalyConfig::default();
            let state = hydra_engine::micromodels::CommitRateAnomalyState {
                ewma_rate: 10.0,
                ewma_variance: 1.0,
                samples_seen: 10, // past default warmup_samples = 5
                last_observed_at: Some(chrono::Utc::now()),
            };
            let primed = hydra_engine::micromodels::CommitRateAnomalyModel::with_state(
                config, state,
            );
            hydra.set_commit_rate_anomaly_model(primed);
        }
        // Drive observed rate to ~100/min by ingesting 97 more
        // signals on top of the existing ledger.
        {
            let mut hydra = hydra_handle.write().await;
            for i in 0..97 {
                hydra
                    .ingest(EventKind::Signal {
                        source: hydra_core::NodeId::from_str("test.http"),
                        name: format!("noise-{i}"),
                        payload: HashMap::new(),
                    })
                    .unwrap();
            }
        }
    }

    #[tokio::test]
    async fn evaluate_default_mode_is_action() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(request_body(
                serde_json::json!({ "requested_by": actor() }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = read_body_bytes(response).await;
        let decoded: EvaluateCommitRateResponse =
            serde_json::from_slice(&bytes).unwrap();
        // Default mode is `action`; cold engine returns WarmingUp.
        assert_eq!(decoded.level, "warming_up");
        // Cold-start summary is deterministic.
        assert!(decoded.summary.contains("warming up"));
    }

    #[tokio::test]
    async fn evaluate_explicit_prediction_only_mode() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(request_body(serde_json::json!({
                "mode": "prediction_only",
                "requested_by": actor(),
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = read_body_bytes(response).await;
        let decoded: EvaluateCommitRateResponse =
            serde_json::from_slice(&bytes).unwrap();
        // Prediction-only mode: no evidence/claim/action ever,
        // regardless of level.
        assert!(decoded.evidence_id.is_none());
        assert!(decoded.claim_id.is_none());
        assert!(decoded.action_ids.is_empty());
    }

    #[tokio::test]
    async fn evaluate_invalid_mode_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(request_body(serde_json::json!({
                "mode": "totally_made_up",
                "requested_by": actor(),
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = read_body_bytes(response).await;
        let decoded: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(decoded.error.contains("invalid request body"));
    }

    #[tokio::test]
    async fn evaluate_missing_requested_by_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(request_body(serde_json::json!({
                "mode": "action",
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn evaluate_response_lineage_url_points_at_prediction_event() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(request_body(serde_json::json!({
                "mode": "claim",
                "requested_by": actor(),
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = read_body_bytes(response).await;
        let decoded: EvaluateCommitRateResponse =
            serde_json::from_slice(&bytes).unwrap();
        // The lineage URL is /lineage/<prediction_event_id>.
        // Note: prediction_only mode uses a placeholder event id
        // (engine method doesn't return it); claim and action
        // modes return the real id.
        assert!(decoded.lineage_url.starts_with("/lineage/"));
        let suffix = &decoded.lineage_url["/lineage/".len()..];
        assert_eq!(suffix, decoded.prediction_event_id.as_str());
    }

    #[tokio::test]
    async fn evaluate_action_mode_full_chain_on_critical() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        prime_critical(&runtime).await;
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(request_body(serde_json::json!({
                "mode": "action",
                "requested_by": actor(),
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = read_body_bytes(response).await;
        let decoded: EvaluateCommitRateResponse =
            serde_json::from_slice(&bytes).unwrap();
        // High signal volume → Critical level → full chain.
        assert_eq!(decoded.level, "critical");
        assert!(decoded.evidence_id.is_some());
        assert!(decoded.claim_id.is_some());
        assert!(decoded.claim_event_id.is_some());
        assert_eq!(decoded.action_ids.len(), 1);
        // The Critical+action summary is the canonical string.
        assert_eq!(
            decoded.summary,
            "Critical: commit rate anomalous; Notify action proposed."
        );
    }

    #[tokio::test]
    async fn evaluate_claim_mode_records_no_action() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        prime_critical(&runtime).await;
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(request_body(serde_json::json!({
                "mode": "claim",
                "requested_by": actor(),
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = read_body_bytes(response).await;
        let decoded: EvaluateCommitRateResponse =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.level, "critical");
        assert!(decoded.evidence_id.is_some());
        assert!(decoded.claim_id.is_some());
        // Claim mode never proposes actions.
        assert!(decoded.action_ids.is_empty());
        assert_eq!(
            decoded.summary,
            "Critical: commit rate anomalous; claim recorded, action not proposed."
        );
    }

    #[test]
    fn summary_table_pins_all_eight_cases() {
        // Pin the deterministic 8-case table so a future patch
        // doesn't accidentally drift the prose. Agents may
        // pattern-match on these strings.
        assert!(render_summary(AnomalyLevel::WarmingUp, false, false)
            .contains("warming up"));
        assert!(render_summary(AnomalyLevel::Normal, false, false)
            .contains("within expected range"));
        assert!(render_summary(AnomalyLevel::Warning, false, false)
            .contains("no claim or action recorded"));
        assert!(render_summary(AnomalyLevel::Warning, true, false)
            .contains("under current verification threshold"));
        assert!(render_summary(AnomalyLevel::Warning, true, true)
            .contains("claim recorded and Notify action proposed"));
        assert!(render_summary(AnomalyLevel::Critical, false, false)
            .contains("no claim or action recorded"));
        assert!(render_summary(AnomalyLevel::Critical, true, false)
            .contains("action not proposed"));
        assert_eq!(
            render_summary(AnomalyLevel::Critical, true, true),
            "Critical: commit rate anomalous; Notify action proposed."
        );
    }

    #[test]
    fn evaluation_mode_default_is_action() {
        assert_eq!(EvaluationMode::default(), EvaluationMode::Action);
    }

    #[test]
    fn evaluation_mode_serde_snake_case() {
        // Wire form is snake_case strings, lower-bound for SDK
        // parity. Round-trip both ways.
        for (mode, expected) in [
            (EvaluationMode::PredictionOnly, "\"prediction_only\""),
            (EvaluationMode::Claim, "\"claim\""),
            (EvaluationMode::Action, "\"action\""),
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, expected);
            let parsed: EvaluationMode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, mode);
        }
    }
}
