//! MicroModel Patch 8 — outcome learning loop.
//!
//! Exposes the engine's outcome-to-observation chain walk as an
//! HTTP endpoint so operators can close the reflex loop from
//! outside Rust:
//!
//! ```text
//! POST /diagnostics/micromodels/observations/from-outcome/:outcome_id
//! ```
//!
//! Walks the causal chain
//!
//! ```text
//!   Outcome
//!     → Outcome.caused_by → ActionExecuted event
//!     → Action.related_claims[0]
//!     → Claim.caused_by → MicroModelPredictionRecorded event
//!     → prediction.run_id
//! ```
//!
//! and records a `MicroModelObservation` matched by that `run_id`.
//! The audit linkage (outcome_id, action_id, claim_id, etc.)
//! lives in `observed_outcome: serde_json::Value` for v0; the
//! struct's 4 fields stay unchanged.
//!
//! ## Auth
//!
//! Reuses `write:diagnostics` (Patch 5's existing scope) — this
//! is a diagnostic surface that mutates Hydra's causal memory.
//!
//! ## Status mapping
//!
//! ```text
//!   200 → observation recorded; envelope mirrors the engine's
//!         `MicroModelObservation`.
//!   400 → engine returned `QueryError("outcome not traceable: ...")`
//!         — the outcome exists but the chain walk failed (e.g.,
//!         the outcome wasn't produced by a MicroModel reflex).
//!   404 → unknown outcome_id.
//! ```
//!
//! ## v0 boundary
//!
//! - Walks executed outcomes only; rejection-path is a future patch.
//! - No automatic trust scoring, no retraining.
//! - `error: None` — no scalar loss metric in v0.

use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Utc};
use hydra_core::{ActionId, ActorId, MicroModelRunId, OutcomeId};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct ObservationsHttpState {
    pub runtime: RuntimeHandle,
}

impl ObservationsHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the observations router. Two routes:
/// - `/from-outcome/:outcome_id` (Patch 8 — positive learning)
/// - `/from-rejected-action/:action_id` (Patch 13 — corrective
///   learning)
pub fn observations_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route(
            "/diagnostics/micromodels/observations/from-outcome/:outcome_id",
            post(record_observation_from_outcome),
        )
        .route(
            "/diagnostics/micromodels/observations/from-rejected-action/:action_id",
            post(record_observation_from_rejected_action),
        )
        .with_state(ObservationsHttpState::new(runtime))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordObservationFromOutcomeRequest {
    pub observed_by: ActorId,
}

/// Body for `POST /diagnostics/micromodels/observations/from-rejected-action/:action_id`
/// (Trust Patch 5 / Patch 13).
///
/// Field shape is identical to the from-outcome request — Patch 13
/// reuses the SDK / wire vocabulary deliberately so callers can
/// learn one shape and use it for both positive and corrective
/// observation recording.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordObservationFromRejectedActionRequest {
    pub observed_by: ActorId,
}

/// Wire response mirroring `hydra_core::MicroModelObservation`.
///
/// The Pydantic SDK type uses the same field names so the response
/// validates against the SDK's `MicroModelObservation` model
/// without translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroModelObservationResponse {
    pub run_id: MicroModelRunId,
    pub observed_outcome: serde_json::Value,
    pub error: Option<f64>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

async fn record_observation_from_outcome(
    State(state): State<ObservationsHttpState>,
    Path(outcome_id): Path<String>,
    request: Result<
        Json<RecordObservationFromOutcomeRequest>,
        axum::extract::rejection::JsonRejection,
    >,
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
    let outcome_id = OutcomeId::from_str(&outcome_id);

    let hydra = state.runtime.hydra();
    let mut hydra = hydra.write().await;

    let observation = match hydra
        .record_micro_model_observation_from_action_outcome(
            outcome_id.clone(),
            request.observed_by.clone(),
        ) {
        Ok(obs) => obs,
        Err(err) => return engine_error_response(err),
    };

    let body = MicroModelObservationResponse {
        run_id: observation.run_id,
        observed_outcome: observation.observed_outcome,
        error: observation.error,
        observed_at: observation.observed_at,
    };
    (StatusCode::OK, Json(body)).into_response()
}

async fn record_observation_from_rejected_action(
    State(state): State<ObservationsHttpState>,
    Path(action_id): Path<String>,
    request: Result<
        Json<RecordObservationFromRejectedActionRequest>,
        axum::extract::rejection::JsonRejection,
    >,
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
    let action_id = ActionId::from_str(&action_id);

    let hydra = state.runtime.hydra();
    let mut hydra = hydra.write().await;

    let observation = match hydra.record_micro_model_observation_from_rejected_action(
        action_id,
        request.observed_by.clone(),
    ) {
        Ok(obs) => obs,
        Err(err) => return engine_error_response(err),
    };
    let body = MicroModelObservationResponse {
        run_id: observation.run_id,
        observed_outcome: observation.observed_outcome,
        error: observation.error,
        observed_at: observation.observed_at,
    };
    (StatusCode::OK, Json(body)).into_response()
}

fn engine_error_response(err: hydra_core::error::HydraError) -> Response {
    use hydra_core::error::HydraError;
    match err {
        // Unknown outcome (Patch 8) or action (Patch 13) → 404.
        HydraError::QueryError(msg)
            if msg.contains("unknown outcome") || msg.contains("unknown action") =>
        {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: msg }),
            )
                .into_response()
        }
        // Chain-walk failures and Patch 13's state-machine /
        // cascade-rejector guards → 400. The client made a
        // semantically wrong call (this outcome / action isn't a
        // learning signal), not a server error.
        HydraError::QueryError(msg)
            if msg.contains("outcome not traceable")
                || msg.contains("action not traceable")
                || msg.contains("invalid action state")
                || msg.contains("rejected by cascade") =>
        {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: msg }),
            )
                .into_response()
        }
        other => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("engine error: {other}"),
            }),
        )
            .into_response(),
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
        EventKind,
    };
    use std::collections::HashMap;
    use tower::ServiceExt;

    async fn read_body_bytes(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    fn json_request(method: Method, uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    /// Drive the full MicroModel reflex chain end-to-end, including
    /// execute, so a real OutcomeObserved exists for the handler to
    /// consume. Returns the outcome_id.
    async fn drive_full_reflex_to_outcome(
        runtime: &crate::runtime::RuntimeHandle,
    ) -> hydra_core::OutcomeId {
        use hydra_core::ActorId;
        let requester = ActorId::from_str("actor_test_requester");
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;

        // Warm the model: first evaluate auto-registers + seeds an
        // observation so the next call's window count is honest.
        hydra
            .evaluate_commit_rate_anomaly(requester.clone())
            .unwrap();
        // Replace the model with one primed to a hot baseline so the
        // next ingest pushes into Critical. Mirrors the engine tests'
        // primed_hydra helper but inline so the HTTP tests don't need
        // to reach into the engine's test module.
        hydra.set_commit_rate_anomaly_model(primed_test_model());
        // Push commit count into Critical territory.
        let need = 100u64.saturating_sub(hydra.commit_count() as u64);
        for i in 0..need {
            hydra
                .ingest(EventKind::Signal {
                    source: hydra_core::NodeId::from_str("test.signal"),
                    name: format!("test_signal_{i}"),
                    payload: HashMap::new(),
                })
                .unwrap();
        }
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester.clone())
            .unwrap();
        let action_id = assessment
            .action_ids
            .into_iter()
            .next()
            .expect("critical produced an action");
        // No policies registered → cascade auto-approved. Execute
        // walks Approved → Executed and emits OutcomeObserved.
        let report = hydra
            .execute_notify_action(
                action_id,
                ActorId::from_str("actor_ops"),
            )
            .unwrap();
        report.outcome_id
    }

    fn primed_test_model() -> hydra_engine::micromodels::CommitRateAnomalyModel {
        use hydra_engine::micromodels::{CommitRateAnomalyConfig, CommitRateAnomalyModel};
        let config = CommitRateAnomalyConfig::default();
        let mut state = hydra_engine::micromodels::CommitRateAnomalyState::default();
        state.ewma_rate = 10.0;
        state.ewma_variance = 1.0;
        state.samples_seen = (config.warmup_samples + 5) as u64;
        state.last_observed_at = Some(chrono::Utc::now() - chrono::Duration::seconds(120));
        CommitRateAnomalyModel::with_state(config, state)
    }

    #[tokio::test]
    async fn record_observation_from_outcome_returns_micro_model_observation() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let outcome_id = drive_full_reflex_to_outcome(&runtime).await;
        let app = observations_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!(
                    "/diagnostics/micromodels/observations/from-outcome/{outcome_id}"
                ),
                serde_json::json!({ "observed_by": "actor_ops" }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: MicroModelObservationResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        // run_id is non-empty (matched against the prediction).
        assert!(!body.run_id.to_string().is_empty());
        // observed_outcome carries the audit linkage.
        let obj = body.observed_outcome.as_object().unwrap();
        assert_eq!(
            obj.get("outcome_id").and_then(|v| v.as_str()),
            Some(outcome_id.to_string().as_str())
        );
        assert_eq!(
            obj.get("observed_by").and_then(|v| v.as_str()),
            Some("actor_ops")
        );
        assert!(body.error.is_none());
    }

    #[tokio::test]
    async fn record_observation_unknown_outcome_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = observations_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                "/diagnostics/micromodels/observations/from-outcome/out_ghost",
                serde_json::json!({ "observed_by": "actor_ops" }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.error.contains("unknown outcome"), "got: {}", body.error);
    }

    #[tokio::test]
    async fn record_observation_chain_break_returns_400() {
        // Ingest a Notify action with NO related_claims so the chain
        // walk fails at "action has no related_claims" — the HTTP
        // layer should surface this as 400, not 500.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test_proposer");
        let action_id = hydra_core::ActionId::new();
        let action = Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: ActionKind::Notify,
            status: ActionStatus::Approved,
            targets: vec![ActionTarget::System("hydra".to_string())],
            related_claims: vec![], // ← the break
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: Some(actor.clone()),
            rejected_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: Some(now),
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        let outcome_id = {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest(EventKind::ActionProposed { action })
                .unwrap();
            let report = hydra
                .execute_notify_action(action_id, actor)
                .unwrap();
            report.outcome_id
        };
        let app = observations_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!(
                    "/diagnostics/micromodels/observations/from-outcome/{outcome_id}"
                ),
                serde_json::json!({ "observed_by": "actor_ops" }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(
            body.error.contains("outcome not traceable"),
            "got: {}",
            body.error
        );
    }

    #[tokio::test]
    async fn record_observation_missing_observed_by_returns_400() {
        // Body schema requires `observed_by`. Omitting it is a
        // schema-validation error and surfaces as 400 (axum
        // JSON-rejection) — not 500.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = observations_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                "/diagnostics/micromodels/observations/from-outcome/out_anything",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn record_observation_full_round_trip_includes_audit_linkage() {
        // End-to-end pin: the response body must include every
        // field Patch 9's trust scoring will rely on.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let outcome_id = drive_full_reflex_to_outcome(&runtime).await;
        let app = observations_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!(
                    "/diagnostics/micromodels/observations/from-outcome/{outcome_id}"
                ),
                serde_json::json!({ "observed_by": "actor_ops" }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: MicroModelObservationResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        let obj = body.observed_outcome.as_object().unwrap();
        assert!(obj.get("outcome_id").is_some());
        assert!(obj.get("action_id").is_some());
        assert!(obj.get("claim_id").is_some());
        assert_eq!(
            obj.get("outcome_kind").and_then(|v| v.as_str()),
            Some("Custom(notification_recorded)")
        );
        assert_eq!(
            obj.get("action_lifecycle").and_then(|v| v.as_str()),
            Some("executed")
        );
        assert_eq!(
            obj.get("operator_approved").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            obj.get("operator_rejected").and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    // === Trust Patch 5 (Patch 13) — rejection-path observations ===

    /// Drive a model-derived chain, then OPERATOR-reject the
    /// proposed action. Returns the rejected action_id.
    async fn drive_chain_and_operator_reject(
        runtime: &crate::runtime::RuntimeHandle,
    ) -> hydra_core::ActionId {
        let actor = hydra_core::ActorId::from_str("actor_test_requester");
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        // HumanApproval policy so cascade leaves it Proposed.
        let now = chrono::Utc::now();
        let policy = hydra_core::Policy {
            id: hydra_core::PolicyId::new(),
            tenant_id: None,
            name: "Require human".to_string(),
            kind: hydra_core::PolicyKind::HumanApproval,
            status: hydra_core::PolicyStatus::Active,
            scope: hydra_core::PolicyScope::AnyAction,
            condition: HashMap::new(),
            metadata: HashMap::new(),
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        hydra
            .ingest(EventKind::PolicyRegistered { policy })
            .unwrap();
        hydra
            .evaluate_commit_rate_anomaly(actor.clone())
            .unwrap();
        hydra.set_commit_rate_anomaly_model(primed_test_model());
        let need = 100u64.saturating_sub(hydra.commit_count() as u64);
        for i in 0..need {
            hydra
                .ingest(EventKind::Signal {
                    source: hydra_core::NodeId::from_str("test.signal"),
                    name: format!("test_signal_{i}"),
                    payload: HashMap::new(),
                })
                .unwrap();
        }
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(actor)
            .unwrap();
        let action_id = assessment.action_ids[0].clone();
        let operator = hydra_core::ActorId::from_str("actor_oncall_alice");
        hydra
            .reject_action(
                action_id.clone(),
                operator,
                "maintenance window".to_string(),
            )
            .unwrap();
        action_id
    }

    #[tokio::test]
    async fn record_observation_from_rejected_action_returns_envelope() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_id = drive_chain_and_operator_reject(&runtime).await;
        let app = observations_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!(
                    "/diagnostics/micromodels/observations/from-rejected-action/{action_id}"
                ),
                serde_json::json!({ "observed_by": "actor_oncall_alice" }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: MicroModelObservationResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        let obj = body.observed_outcome.as_object().unwrap();
        assert_eq!(
            obj.get("action_lifecycle").and_then(|v| v.as_str()),
            Some("rejected")
        );
        assert_eq!(
            obj.get("operator_rejected").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            obj.get("rejection_reason").and_then(|v| v.as_str()),
            Some("maintenance window")
        );
    }

    #[tokio::test]
    async fn record_observation_from_rejected_action_unknown_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = observations_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                "/diagnostics/micromodels/observations/from-rejected-action/act_ghost",
                serde_json::json!({ "observed_by": "actor_oncall" }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn record_observation_from_rejected_action_wrong_status_returns_400() {
        // Action exists but is Approved (not Rejected) — must
        // surface as 400.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let now = chrono::Utc::now();
        let action_id = hydra_core::ActionId::new();
        let action = Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: ActionKind::Notify,
            status: ActionStatus::Approved,
            targets: vec![ActionTarget::System("hydra".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: Some(actor.clone()),
            rejected_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: Some(now),
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest(EventKind::ActionProposed { action })
                .unwrap();
        }
        let app = observations_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!(
                    "/diagnostics/micromodels/observations/from-rejected-action/{action_id}"
                ),
                serde_json::json!({ "observed_by": "actor_ops" }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(
            body.error.contains("invalid action state"),
            "got: {}",
            body.error
        );
    }

    #[tokio::test]
    async fn record_observation_from_rejected_action_cascade_rejection_returns_400() {
        // Register a Block policy so the cascade rejects with the
        // cascade actor. Then the operator-recorded observation
        // request must be refused (400 with "rejected by cascade").
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let now = chrono::Utc::now();
        let policy = hydra_core::Policy {
            id: hydra_core::PolicyId::new(),
            tenant_id: None,
            name: "Block".to_string(),
            kind: hydra_core::PolicyKind::Block,
            status: hydra_core::PolicyStatus::Active,
            scope: hydra_core::PolicyScope::AnyAction,
            condition: HashMap::new(),
            metadata: HashMap::new(),
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        let action_id = {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest(EventKind::PolicyRegistered { policy })
                .unwrap();
            hydra
                .evaluate_commit_rate_anomaly(actor.clone())
                .unwrap();
            hydra.set_commit_rate_anomaly_model(primed_test_model());
            let need = 100u64.saturating_sub(hydra.commit_count() as u64);
            for i in 0..need {
                hydra
                    .ingest(EventKind::Signal {
                        source: hydra_core::NodeId::from_str("test.signal"),
                        name: format!("test_signal_{i}"),
                        payload: HashMap::new(),
                    })
                    .unwrap();
            }
            let assessment = hydra
                .evaluate_commit_rate_anomaly_and_propose_action(actor)
                .unwrap();
            assessment.action_ids[0].clone()
        };
        let app = observations_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!(
                    "/diagnostics/micromodels/observations/from-rejected-action/{action_id}"
                ),
                serde_json::json!({ "observed_by": "actor_ops" }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(
            body.error.contains("rejected by cascade"),
            "got: {}",
            body.error
        );
    }

    #[tokio::test]
    async fn record_observation_from_rejected_action_missing_observed_by_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = observations_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                "/diagnostics/micromodels/observations/from-rejected-action/act_x",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
