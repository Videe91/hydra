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
//! ## Routes
//!
//! ```text
//! POST /diagnostics/micromodels/commit-rate/evaluate       (Patch 5)
//! POST /diagnostics/micromodels/replication-lag/evaluate   (Patch 16)
//! POST /diagnostics/micromodels/agent-loop-storm/evaluate  (Patch 18)
//! ```
//!
//! Each model uses the same dispatch (`mode = prediction_only |
//! claim | action`) but its own typed request + response. The
//! `level` wire string union across all models is
//! `{warming_up, normal, warning, critical}`; only commit-rate
//! emits `warming_up`. Storm + replication-lag are threshold
//! models with no warmup. SDKs treat the union as the allowed set.
//!
//! ## Auth
//!
//! All routes are POSTs under `/diagnostics/` and pick up
//! `write:diagnostics` from the existing prefix clause in
//! `hydra-api::auth`. No new scope.
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
    ReplicaId,
};
use hydra_engine::micromodels::{
    AgentLoopStormLevel, AnomalyLevel, ReplicationLagAnomalyLevel,
};
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
        .route(
            "/diagnostics/micromodels/replication-lag/evaluate",
            post(evaluate_replication_lag),
        )
        .route(
            "/diagnostics/micromodels/agent-loop-storm/evaluate",
            post(evaluate_agent_loop_storm),
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

// === MicroModel Patch 16 — replication-lag evaluation surface ===
//
// Parallel structure to the commit-rate route above. Patch 17 may
// extract a shared `MicroModelEvaluateResponse<L>` generic; until
// then the parallel structure IS the proof that the framework
// generalizes.

/// Request body for `POST /diagnostics/micromodels/replication-lag/evaluate`.
///
/// `peer_id` selects the follower. Unknown peer → 404 (the engine
/// surfaces this as `QueryError("unknown replication peer: ...")`,
/// which the handler maps).
///
/// `mode` defaults to `Action` for symmetry with commit-rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateReplicationLagRequest {
    #[serde(default)]
    pub mode: EvaluationMode,
    pub peer_id: ReplicaId,
    pub requested_by: ActorId,
}

/// Response body for the replication-lag evaluate endpoint. Mirrors
/// `EvaluateCommitRateResponse` field-for-field PLUS echoes the
/// `peer_id` so callers don't have to keep a side mapping when
/// fanning evaluations across peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateReplicationLagResponse {
    /// Snake-case anomaly level: `"normal"`, `"warning"`, or
    /// `"critical"`. NEVER `"warming_up"` for this model (no warmup).
    pub level: String,
    pub prediction: MicroModelPrediction,
    pub prediction_event_id: EventId,
    pub evidence_id: Option<EvidenceId>,
    pub evidence_event_id: Option<EventId>,
    pub claim_id: Option<ClaimId>,
    pub claim_event_id: Option<EventId>,
    /// One-element vec for Warning/Critical (Notify only). Patch
    /// 16+ may add `quarantine_peer`/`pause_writes_to_peer` here.
    pub action_ids: Vec<ActionId>,
    /// Peer this evaluation targeted. Echoed from the request so
    /// callers don't have to keep a side mapping when fanning.
    pub peer_id: ReplicaId,
    /// Deterministic prose summary keyed off `(level, has_claim,
    /// has_action)`. Agents can pattern-match on it safely.
    pub summary: String,
    pub lineage_url: String,
}

async fn evaluate_replication_lag(
    State(state): State<MicroModelsHttpState>,
    request: Result<Json<EvaluateReplicationLagRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
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

    // Dispatch by mode. Each engine helper returns a slightly
    // different type; normalize into the same response shape.
    let outcome = match request.mode {
        EvaluationMode::PredictionOnly => {
            match hydra.record_replication_lag_prediction(
                request.peer_id.clone(),
                request.requested_by.clone(),
            ) {
                Ok((prediction, event_id, output)) => {
                    ReplicationLagEvaluationOutcome::from_prediction_only(
                        prediction,
                        event_id,
                        output.level,
                        request.peer_id.clone(),
                    )
                }
                Err(err) => return replication_lag_error_response(err),
            }
        }
        EvaluationMode::Claim => {
            match hydra.evaluate_replication_lag_anomaly_and_propose_claim(
                request.peer_id.clone(),
                request.requested_by.clone(),
            ) {
                Ok(assessment) => {
                    ReplicationLagEvaluationOutcome::from_claim_assessment(
                        assessment,
                    )
                }
                Err(err) => return replication_lag_error_response(err),
            }
        }
        EvaluationMode::Action => {
            match hydra.evaluate_replication_lag_anomaly_and_propose_action(
                request.peer_id.clone(),
                request.requested_by.clone(),
            ) {
                Ok(assessment) => {
                    ReplicationLagEvaluationOutcome::from_action_assessment(
                        assessment,
                    )
                }
                Err(err) => return replication_lag_error_response(err),
            }
        }
    };

    let response = build_replication_lag_response(outcome);
    (StatusCode::OK, Json(response)).into_response()
}

/// Map engine errors. Patch 16's only structured engine error is
/// `QueryError("unknown replication peer: ...")` from the peer
/// lookup — surface as 404. Anything else falls through to 500.
fn replication_lag_error_response(err: hydra_core::error::HydraError) -> Response {
    use hydra_core::error::HydraError;
    match err {
        HydraError::QueryError(msg) if msg.contains("unknown replication peer") => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: msg }),
        )
            .into_response(),
        other => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("engine error: {other}"),
            }),
        )
            .into_response(),
    }
}

struct ReplicationLagEvaluationOutcome {
    level: ReplicationLagAnomalyLevel,
    prediction: MicroModelPrediction,
    prediction_event_id: EventId,
    evidence_id: Option<EvidenceId>,
    evidence_event_id: Option<EventId>,
    claim_id: Option<ClaimId>,
    claim_event_id: Option<EventId>,
    action_ids: Vec<ActionId>,
    peer_id: ReplicaId,
}

impl ReplicationLagEvaluationOutcome {
    fn from_prediction_only(
        prediction: MicroModelPrediction,
        prediction_event_id: EventId,
        level: ReplicationLagAnomalyLevel,
        peer_id: ReplicaId,
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
            peer_id,
        }
    }

    fn from_claim_assessment(
        assessment: hydra_engine::micromodels::ReplicationLagAnomalyAssessment,
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
            peer_id: assessment.peer_id,
        }
    }

    fn from_action_assessment(
        assessment: hydra_engine::micromodels::ReplicationLagAnomalyActionAssessment,
    ) -> Self {
        // Same evidence_event_id-drop note as commit-rate: the
        // action assessment is the loop-closed type, not the all-
        // event-ids type. Returning None is honest.
        Self {
            level: assessment.level,
            prediction: assessment.prediction,
            prediction_event_id: assessment.prediction_event_id,
            evidence_id: assessment.evidence_id,
            evidence_event_id: None,
            claim_id: assessment.claim_id,
            claim_event_id: assessment.claim_event_id,
            action_ids: assessment.action_ids,
            peer_id: assessment.peer_id,
        }
    }
}

fn build_replication_lag_response(
    outcome: ReplicationLagEvaluationOutcome,
) -> EvaluateReplicationLagResponse {
    let summary = render_replication_lag_summary(
        outcome.level,
        outcome.claim_id.is_some(),
        !outcome.action_ids.is_empty(),
    );
    let lineage_url = format!("/lineage/{}", outcome.prediction_event_id);
    EvaluateReplicationLagResponse {
        level: outcome.level.wire_name().to_string(),
        prediction: outcome.prediction,
        prediction_event_id: outcome.prediction_event_id,
        evidence_id: outcome.evidence_id,
        evidence_event_id: outcome.evidence_event_id,
        claim_id: outcome.claim_id,
        claim_event_id: outcome.claim_event_id,
        action_ids: outcome.action_ids,
        peer_id: outcome.peer_id,
        summary,
        lineage_url,
    }
}

/// Deterministic 6-case summary table (no `warming_up` row because
/// this model never warms up).
fn render_replication_lag_summary(
    level: ReplicationLagAnomalyLevel,
    has_claim: bool,
    has_action: bool,
) -> String {
    match (level, has_claim, has_action) {
        (ReplicationLagAnomalyLevel::Normal, _, _) => {
            "Replication lag within thresholds; no claim or action.".to_string()
        }
        (ReplicationLagAnomalyLevel::Warning, false, _) => {
            "Warning: replication lag elevated; no claim or action recorded.".to_string()
        }
        (ReplicationLagAnomalyLevel::Warning, true, false) => {
            "Warning: replication lag elevated; claim recorded, action not proposed \
             under current verification threshold."
                .to_string()
        }
        (ReplicationLagAnomalyLevel::Warning, true, true) => {
            "Warning: replication lag elevated; claim recorded and Notify action \
             proposed."
                .to_string()
        }
        (ReplicationLagAnomalyLevel::Critical, false, _) => {
            "Critical: replication lag anomalous; no claim or action recorded.".to_string()
        }
        (ReplicationLagAnomalyLevel::Critical, true, false) => {
            "Critical: replication lag anomalous; claim recorded, action not proposed."
                .to_string()
        }
        (ReplicationLagAnomalyLevel::Critical, true, true) => {
            "Critical: replication lag anomalous; Notify action proposed.".to_string()
        }
    }
}

// === MicroModel Patch 18 — agent-loop-storm evaluation surface ===
//
// Third model surface. Same dispatch + envelope shape as Patches 5
// + 16; differs in level vocabulary (no `warming_up`) and the
// per-model output fields (top_actor, agent_event_count, etc.).

/// Request body for `POST /diagnostics/micromodels/agent-loop-storm/evaluate`.
///
/// No `peer_id` or other per-instance selector — the storm model
/// watches the global recent event log, not a specific replica.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateAgentLoopStormRequest {
    #[serde(default)]
    pub mode: EvaluationMode,
    pub requested_by: ActorId,
}

/// Response body for the storm evaluate endpoint. Same envelope
/// shape as the other two models, minus per-instance fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateAgentLoopStormResponse {
    /// Snake-case anomaly level: `"normal"`, `"warning"`, or
    /// `"critical"`. NEVER `"warming_up"` for this model.
    pub level: String,
    pub prediction: MicroModelPrediction,
    pub prediction_event_id: EventId,
    pub evidence_id: Option<EvidenceId>,
    pub evidence_event_id: Option<EventId>,
    pub claim_id: Option<ClaimId>,
    pub claim_event_id: Option<EventId>,
    /// One-element vec on Warning/Critical (Notify only).
    pub action_ids: Vec<ActionId>,
    /// Deterministic prose summary keyed off `(level, has_claim,
    /// has_action)`.
    pub summary: String,
    pub lineage_url: String,
}

async fn evaluate_agent_loop_storm(
    State(state): State<MicroModelsHttpState>,
    request: Result<Json<EvaluateAgentLoopStormRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
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

    let outcome = match request.mode {
        EvaluationMode::PredictionOnly => {
            match hydra
                .record_agent_loop_storm_prediction(request.requested_by.clone())
            {
                Ok((prediction, event_id, output)) => {
                    AgentLoopStormEvaluationOutcome::from_prediction_only(
                        prediction,
                        event_id,
                        output.level,
                    )
                }
                Err(err) => return engine_error_response(err),
            }
        }
        EvaluationMode::Claim => {
            match hydra
                .evaluate_agent_loop_storm_and_propose_claim(request.requested_by.clone())
            {
                Ok(assessment) => {
                    AgentLoopStormEvaluationOutcome::from_claim_assessment(assessment)
                }
                Err(err) => return engine_error_response(err),
            }
        }
        EvaluationMode::Action => {
            match hydra
                .evaluate_agent_loop_storm_and_propose_action(request.requested_by.clone())
            {
                Ok(assessment) => {
                    AgentLoopStormEvaluationOutcome::from_action_assessment(assessment)
                }
                Err(err) => return engine_error_response(err),
            }
        }
    };

    let response = build_agent_loop_storm_response(outcome);
    (StatusCode::OK, Json(response)).into_response()
}

struct AgentLoopStormEvaluationOutcome {
    level: AgentLoopStormLevel,
    prediction: MicroModelPrediction,
    prediction_event_id: EventId,
    evidence_id: Option<EvidenceId>,
    evidence_event_id: Option<EventId>,
    claim_id: Option<ClaimId>,
    claim_event_id: Option<EventId>,
    action_ids: Vec<ActionId>,
}

impl AgentLoopStormEvaluationOutcome {
    fn from_prediction_only(
        prediction: MicroModelPrediction,
        prediction_event_id: EventId,
        level: AgentLoopStormLevel,
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
        assessment: hydra_engine::micromodels::AgentLoopStormAssessment,
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
        assessment: hydra_engine::micromodels::AgentLoopStormActionAssessment,
    ) -> Self {
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

fn build_agent_loop_storm_response(
    outcome: AgentLoopStormEvaluationOutcome,
) -> EvaluateAgentLoopStormResponse {
    let summary = render_agent_loop_storm_summary(
        outcome.level,
        outcome.claim_id.is_some(),
        !outcome.action_ids.is_empty(),
    );
    let lineage_url = format!("/lineage/{}", outcome.prediction_event_id);
    EvaluateAgentLoopStormResponse {
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

/// Deterministic 6-case summary (no `warming_up` row).
fn render_agent_loop_storm_summary(
    level: AgentLoopStormLevel,
    has_claim: bool,
    has_action: bool,
) -> String {
    match (level, has_claim, has_action) {
        (AgentLoopStormLevel::Normal, _, _) => {
            "Agent activity within thresholds; no claim or action.".to_string()
        }
        (AgentLoopStormLevel::Warning, false, _) => {
            "Warning: agent activity elevated; no claim or action recorded.".to_string()
        }
        (AgentLoopStormLevel::Warning, true, false) => {
            "Warning: agent activity elevated; claim recorded, action not \
             proposed under current verification threshold."
                .to_string()
        }
        (AgentLoopStormLevel::Warning, true, true) => {
            "Warning: agent activity elevated; claim recorded and Notify \
             action proposed."
                .to_string()
        }
        (AgentLoopStormLevel::Critical, false, _) => {
            "Critical: agent loop storm detected; no claim or action recorded."
                .to_string()
        }
        (AgentLoopStormLevel::Critical, true, false) => {
            "Critical: agent loop storm detected; claim recorded, action \
             not proposed."
                .to_string()
        }
        (AgentLoopStormLevel::Critical, true, true) => {
            "Critical: agent loop storm detected; Notify action proposed.".to_string()
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

    // === Patch 16 — replication-lag HTTP tests ===

    fn replication_lag_request(body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri("/diagnostics/micromodels/replication-lag/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    async fn register_peer_with_lag(
        runtime: &crate::runtime::RuntimeHandle,
        peer_id: &hydra_core::ReplicaId,
        lag_commits: Option<u64>,
    ) {
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        let peer = hydra_core::ReplicationPeer::registered(
            peer_id.clone(),
            hydra_core::ReplicationRole::Follower,
            hydra_core::ReplicationMode::CommitLogStreaming,
            hydra_core::ActorId::from_str("actor_ops"),
        );
        hydra
            .ingest(EventKind::ReplicaRegistered { peer })
            .unwrap();
        if let Some(lag) = lag_commits {
            let leader = 1_000u64;
            let follower = leader.saturating_sub(lag);
            let offset = hydra_core::ReplicationOffset::from_sequence(follower);
            let observed = hydra_core::ReplicationLag::observe(
                leader,
                follower,
                chrono::Utc::now(),
            );
            hydra
                .ingest(EventKind::ReplicaHeartbeatRecorded {
                    peer_id: peer_id.clone(),
                    offset,
                    lag: Some(observed),
                })
                .unwrap();
        }
    }

    #[tokio::test]
    async fn replication_lag_evaluate_unknown_peer_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(replication_lag_request(serde_json::json!({
                "peer_id": "replica_ghost",
                "requested_by": actor(),
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.error.contains("unknown replication peer"));
    }

    #[tokio::test]
    async fn replication_lag_evaluate_normal_when_lag_low_and_fresh() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let peer_id = hydra_core::ReplicaId::from_str("replica_normal");
        register_peer_with_lag(&runtime, &peer_id, Some(2)).await;
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(replication_lag_request(serde_json::json!({
                "peer_id": peer_id.as_str(),
                "requested_by": actor(),
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: EvaluateReplicationLagResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.level, "normal");
        assert!(body.summary.contains("within thresholds"));
        assert!(body.claim_id.is_none());
        assert!(body.action_ids.is_empty());
        assert_eq!(body.peer_id, peer_id);
        assert!(body.lineage_url.starts_with("/lineage/"));
    }

    #[tokio::test]
    async fn replication_lag_evaluate_critical_with_default_action_mode() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let peer_id = hydra_core::ReplicaId::from_str("replica_critical");
        register_peer_with_lag(&runtime, &peer_id, Some(500)).await;
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(replication_lag_request(serde_json::json!({
                "peer_id": peer_id.as_str(),
                "requested_by": actor(),
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: EvaluateReplicationLagResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.level, "critical");
        assert!(body.claim_id.is_some());
        assert_eq!(body.action_ids.len(), 1);
        assert_eq!(body.peer_id, peer_id);
        assert!(body.summary.contains("Critical"));
    }

    #[tokio::test]
    async fn replication_lag_evaluate_prediction_only_skips_claim_and_action() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let peer_id = hydra_core::ReplicaId::from_str("replica_pred_only");
        register_peer_with_lag(&runtime, &peer_id, Some(500)).await;
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(replication_lag_request(serde_json::json!({
                "peer_id": peer_id.as_str(),
                "requested_by": actor(),
                "mode": "prediction_only",
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: EvaluateReplicationLagResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.level, "critical");
        assert!(body.claim_id.is_none());
        assert!(body.evidence_id.is_none());
        assert!(body.action_ids.is_empty());
    }

    #[tokio::test]
    async fn replication_lag_evaluate_claim_mode_skips_action() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let peer_id = hydra_core::ReplicaId::from_str("replica_claim_mode");
        register_peer_with_lag(&runtime, &peer_id, Some(500)).await;
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(replication_lag_request(serde_json::json!({
                "peer_id": peer_id.as_str(),
                "requested_by": actor(),
                "mode": "claim",
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: EvaluateReplicationLagResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.level, "critical");
        assert!(body.claim_id.is_some());
        assert!(body.evidence_id.is_some());
        // Mode=claim → no action even on Critical.
        assert!(body.action_ids.is_empty());
    }

    #[test]
    fn replication_lag_summary_table_pinned() {
        // Pin the user-visible strings so a deliberate change is
        // required to break SDK pattern-matching.
        assert!(render_replication_lag_summary(
            ReplicationLagAnomalyLevel::Normal,
            false,
            false
        )
        .contains("within thresholds"));
        assert!(render_replication_lag_summary(
            ReplicationLagAnomalyLevel::Critical,
            true,
            true
        )
        .contains("Notify action proposed"));
    }

    // === Patch 18 — agent-loop-storm HTTP tests ===

    fn storm_request(body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri("/diagnostics/micromodels/agent-loop-storm/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    /// Ingest `n` ActionProposed events with `proposed_by` so the
    /// engine's storm window walk counts them.
    async fn drive_storm(
        runtime: &crate::runtime::RuntimeHandle,
        n: u64,
        proposed_by: &str,
    ) {
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        for _ in 0..n {
            let now = chrono::Utc::now();
            let action = hydra_core::Action {
                id: hydra_core::ActionId::new(),
                tenant_id: None,
                kind: hydra_core::ActionKind::Notify,
                status: hydra_core::action::ActionStatus::Proposed,
                targets: vec![hydra_core::action::ActionTarget::System(
                    "hydra".to_string(),
                )],
                related_claims: vec![],
                supporting_evidence: vec![],
                proposed_by: hydra_core::ActorId::from_str(proposed_by),
                approved_by: None,
                rejected_by: None,
                policy_id: None,
                payload: std::collections::HashMap::new(),
                created_at: now,
                updated_at: now,
                approved_at: None,
                rejected_at: None,
                executed_at: None,
                caused_by: None,
            };
            hydra
                .ingest(EventKind::ActionProposed { action })
                .unwrap();
        }
    }

    #[tokio::test]
    async fn storm_evaluate_empty_engine_is_normal() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(storm_request(serde_json::json!({
                "requested_by": actor(),
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: EvaluateAgentLoopStormResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.level, "normal");
        assert!(body.summary.contains("within thresholds"));
        assert!(body.claim_id.is_none());
        assert!(body.action_ids.is_empty());
        assert!(body.lineage_url.starts_with("/lineage/"));
    }

    #[tokio::test]
    async fn storm_evaluate_critical_with_default_action_mode() {
        // 60 ActionProposed by one external agent → Critical via
        // the actions_proposed threshold. Full chain fires.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        drive_storm(&runtime, 60, "actor_data_quality_agent").await;
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(storm_request(serde_json::json!({
                "requested_by": actor(),
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: EvaluateAgentLoopStormResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.level, "critical");
        assert!(body.summary.contains("Critical"));
        assert!(body.claim_id.is_some());
        assert_eq!(body.action_ids.len(), 1);
    }

    #[tokio::test]
    async fn storm_evaluate_prediction_only_skips_claim_and_action() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        drive_storm(&runtime, 60, "actor_chatty_agent").await;
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(storm_request(serde_json::json!({
                "requested_by": actor(),
                "mode": "prediction_only",
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: EvaluateAgentLoopStormResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.level, "critical");
        assert!(body.claim_id.is_none());
        assert!(body.evidence_id.is_none());
        assert!(body.action_ids.is_empty());
    }

    #[tokio::test]
    async fn storm_evaluate_claim_mode_skips_action() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        drive_storm(&runtime, 60, "actor_chatty_agent").await;
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(storm_request(serde_json::json!({
                "requested_by": actor(),
                "mode": "claim",
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: EvaluateAgentLoopStormResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.level, "critical");
        assert!(body.claim_id.is_some());
        assert!(body.evidence_id.is_some());
        // Mode=claim → no action even on Critical.
        assert!(body.action_ids.is_empty());
    }

    #[tokio::test]
    async fn storm_evaluate_filters_hydra_system_actors_via_http() {
        // 80 ActionProposed by actor_hydra_policy (Hydra-system).
        // The HTTP surface should see Normal — the storm filter
        // works end-to-end through the route.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        drive_storm(&runtime, 80, "actor_hydra_policy").await;
        let app = micromodels_router(runtime.clone());
        let response = app
            .oneshot(storm_request(serde_json::json!({
                "requested_by": actor(),
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: EvaluateAgentLoopStormResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(
            body.level, "normal",
            "Hydra-system actor activity must NOT trigger storms via HTTP"
        );
    }

    #[test]
    fn storm_summary_table_pinned() {
        assert!(render_agent_loop_storm_summary(
            AgentLoopStormLevel::Normal,
            false,
            false
        )
        .contains("within thresholds"));
        assert!(render_agent_loop_storm_summary(
            AgentLoopStormLevel::Critical,
            true,
            true
        )
        .contains("Notify action proposed"));
    }
}
