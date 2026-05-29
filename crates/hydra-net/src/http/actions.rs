//! Operator approval workflow — MicroModel Patch 6.
//!
//! Two routes that let an operator approve or reject any
//! existing `Action`:
//!
//! ```text
//! POST /actions/:action_id/approve
//! POST /actions/:action_id/reject
//! ```
//!
//! Patch 6 is the first **human governance gate** in the
//! micro-model arc:
//!
//! ```text
//!   ActionProposed
//!     → operator approves or rejects
//!     → audit records who decided and why
//! ```
//!
//! No execution. No real delivery. The action's status flips and
//! the audit log captures the operator + reason. Execution
//! (Patch 7) and outcome learning (Patch 8) follow.
//!
//! ## Auth
//!
//! New scope `write:approvals` (mapped in `hydra-api::auth`).
//! Separate from `write:diagnostics` (model evaluations) and
//! `admin:ops` (snapshots / maintenance) so operator roles can
//! be granted approval authority without anything else.
//!
//! ## State-machine
//!
//! v0 does NOT enforce terminal action states. An already-Approved
//! action can be approved again (audit captures both events); a
//! Rejected action can be re-approved. The response surfaces
//! `previous_status` so callers see the flip and can detect
//! idempotent calls. Terminal-state guards are a future patch.

use crate::notify_delivery::NotifyAdapter;
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Utc};
use hydra_core::{action::ActionStatus, ActionId, ActorId, OutcomeId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// HTTP state for the actions router.
///
/// `notify_delivery` is `None` for **Stub mode** (Patch 7
/// behavior: the engine emits the stub outcome itself), and
/// `Some(adapter)` for **Webhook mode** (Patch 14: the handler
/// does the real network delivery outside the engine lock, then
/// calls `execute_notify_action_with_delivery`).
#[derive(Clone)]
pub struct ActionsHttpState {
    pub runtime: RuntimeHandle,
    pub notify_delivery: Option<Arc<NotifyAdapter>>,
}

impl ActionsHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self {
            runtime,
            notify_delivery: None,
        }
    }

    pub fn with_notify_delivery(
        runtime: RuntimeHandle,
        notify_delivery: Option<Arc<NotifyAdapter>>,
    ) -> Self {
        Self {
            runtime,
            notify_delivery,
        }
    }
}

/// Build the actions router. Four routes today: `/approve` +
/// `/reject` (Patch 6 — governance gate), `/execute` (Patch 7
/// stub or Patch 14 webhook depending on `notify_delivery`),
/// and `/auto-execute` (Patch 11 — trust-aware auto-execution
/// gate).
///
/// Stub mode (Patch 14 default) is bit-identical to Patch 7 — the
/// handler calls `Hydra::execute_notify_action` directly. When
/// `notify_delivery` is Some, the handler orchestrates a real
/// adapter call before invoking the new engine method.
pub fn actions_router(runtime: RuntimeHandle) -> Router {
    actions_router_with_notify(runtime, None)
}

/// Like `actions_router` but accepts an optional notify adapter.
/// Used by hydra-api when `NotifyDeliveryConfig` is `Webhook(...)`.
pub fn actions_router_with_notify(
    runtime: RuntimeHandle,
    notify_delivery: Option<Arc<NotifyAdapter>>,
) -> Router {
    Router::new()
        .route("/actions/:action_id/approve", post(approve_action))
        .route("/actions/:action_id/reject", post(reject_action))
        .route("/actions/:action_id/execute", post(execute_action))
        .route(
            "/actions/:action_id/auto-execute",
            post(auto_execute_action),
        )
        .with_state(ActionsHttpState::with_notify_delivery(
            runtime,
            notify_delivery,
        ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveActionRequest {
    pub actor: ActorId,
    /// Optional rationale. Stored in the `ActionApproved` event for
    /// audit; not yet projected onto `Action.payload` (future
    /// enhancement).
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectActionRequest {
    pub actor: ActorId,
    /// Required rationale. Explicit rejection reason is
    /// load-bearing for audit + future outcome learning.
    pub reason: String,
}

/// Unified transition envelope used for both approve and reject.
///
/// `approved_by` is populated on approve; `rejected_by` on reject;
/// the other is `null`. `previous_status` surfaces the action's
/// state BEFORE the transition so callers can detect idempotent
/// flips ("I approved, but it was already Approved").
///
/// Lowercase wire form for the status fields so they read like log
/// labels (`"approved"`, `"rejected"`, `"proposed"`, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTransitionResponse {
    pub action_id: ActionId,
    pub status: String,
    pub previous_status: String,
    pub approved_by: Option<ActorId>,
    pub rejected_by: Option<ActorId>,
    pub reason: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

async fn approve_action(
    State(state): State<ActionsHttpState>,
    Path(action_id): Path<String>,
    request: Result<Json<ApproveActionRequest>, axum::extract::rejection::JsonRejection>,
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

    // Capture the pre-transition status BEFORE the engine flips it
    // so the response can surface idempotent flips.
    let previous_status = match hydra.action(&action_id) {
        Some(action) => status_wire_name(&action.status),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("unknown action: {action_id}"),
                }),
            )
                .into_response();
        }
    };

    let action = match hydra.approve_action(
        action_id.clone(),
        request.actor.clone(),
        request.reason.clone(),
    ) {
        Ok(action) => action,
        Err(err) => return engine_error_response(err),
    };

    let body = ActionTransitionResponse {
        action_id: action.id.clone(),
        status: status_wire_name(&action.status).to_string(),
        previous_status: previous_status.to_string(),
        approved_by: action.approved_by.clone(),
        rejected_by: None,
        reason: request.reason,
        approved_at: action.approved_at,
        updated_at: action.updated_at,
    };
    (StatusCode::OK, Json(body)).into_response()
}

async fn reject_action(
    State(state): State<ActionsHttpState>,
    Path(action_id): Path<String>,
    request: Result<Json<RejectActionRequest>, axum::extract::rejection::JsonRejection>,
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

    let previous_status = match hydra.action(&action_id) {
        Some(action) => status_wire_name(&action.status),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("unknown action: {action_id}"),
                }),
            )
                .into_response();
        }
    };

    let action = match hydra.reject_action(
        action_id.clone(),
        request.actor.clone(),
        request.reason.clone(),
    ) {
        Ok(action) => action,
        Err(err) => return engine_error_response(err),
    };

    let body = ActionTransitionResponse {
        action_id: action.id.clone(),
        status: status_wire_name(&action.status).to_string(),
        previous_status: previous_status.to_string(),
        approved_by: None,
        rejected_by: Some(request.actor),
        reason: Some(request.reason),
        approved_at: None,
        updated_at: action.updated_at,
    };
    (StatusCode::OK, Json(body)).into_response()
}

fn engine_error_response(err: hydra_core::error::HydraError) -> Response {
    use hydra_core::error::HydraError;
    match err {
        // QueryError("unknown action: ...") is the canonical
        // missing-id signal from the engine. Surface as 404.
        HydraError::QueryError(msg) if msg.contains("unknown action") => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: msg }),
        )
            .into_response(),
        // Patch 7 — state-machine + kind preconditions. The engine
        // returns QueryError with structured prefixes; map to 400
        // so operators can distinguish "you can't do that here"
        // from "the server hit an unexpected error."
        HydraError::QueryError(msg)
            if msg.contains("invalid action state")
                || msg.contains("invalid action kind") =>
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

// === MicroModel Patch 7 — execution stub =====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteActionRequest {
    pub actor: ActorId,
}

/// Wire response for `POST /actions/{id}/execute`.
///
/// Mirrors `hydra_core::ActionExecutionReport` but uses lowercase
/// status names on the wire (consistent with `ActionTransitionResponse`
/// from Patch 6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionExecutionResponse {
    pub action_id: ActionId,
    pub previous_status: String,
    pub final_status: String,
    pub outcome_id: OutcomeId,
    pub executed_by: ActorId,
    pub executed_at: DateTime<Utc>,
}

async fn execute_action(
    State(state): State<ActionsHttpState>,
    Path(action_id): Path<String>,
    request: Result<Json<ExecuteActionRequest>, axum::extract::rejection::JsonRejection>,
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

    // Patch 14 dispatch: Stub mode (no adapter configured)
    // preserves bit-identical Patch 7 behavior; Webhook mode does
    // real delivery outside the engine lock and then ingests the
    // outcome-aware terminal events.
    let report_result = match &state.notify_delivery {
        None => execute_action_stub_mode(&state, action_id.clone(), request.actor).await,
        Some(adapter) => {
            execute_action_with_delivery_mode(
                &state,
                action_id.clone(),
                request.actor,
                adapter.clone(),
            )
            .await
        }
    };

    let report = match report_result {
        Ok(report) => report,
        Err(err) => return engine_error_response(err),
    };
    let body = ActionExecutionResponse {
        action_id: report.action_id,
        previous_status: status_wire_name(&report.previous_status).to_string(),
        final_status: status_wire_name(&report.final_status).to_string(),
        outcome_id: report.outcome_id,
        executed_by: report.executed_by,
        executed_at: report.executed_at,
    };
    (StatusCode::OK, Json(body)).into_response()
}

/// Patch 7 path — call `execute_notify_action` under the engine
/// write lock. No network I/O.
async fn execute_action_stub_mode(
    state: &ActionsHttpState,
    action_id: ActionId,
    actor: ActorId,
) -> hydra_core::error::Result<hydra_core::ActionExecutionReport> {
    let hydra = state.runtime.hydra();
    let mut hydra = hydra.write().await;
    hydra.execute_notify_action(action_id, actor)
}

/// Patch 14 path — short-locked orchestration:
///   1. read+clone action (read lock), validate kind/status,
///      release lock
///   2. call adapter (no lock held)
///   3. write lock → execute_notify_action_with_delivery → release
async fn execute_action_with_delivery_mode(
    state: &ActionsHttpState,
    action_id: ActionId,
    actor: ActorId,
    adapter: std::sync::Arc<NotifyAdapter>,
) -> hydra_core::error::Result<hydra_core::ActionExecutionReport> {
    use hydra_core::error::HydraError;

    // Step 1: read action under READ lock so we can release fast.
    let action = {
        let hydra = state.runtime.hydra();
        let hydra = hydra.read().await;
        hydra.action(&action_id).cloned()
    };
    let action = match action {
        Some(a) => a,
        None => {
            return Err(HydraError::QueryError(format!(
                "unknown action: {action_id}"
            )));
        }
    };
    if action.kind != hydra_core::ActionKind::Notify {
        return Err(HydraError::QueryError(format!(
            "invalid action kind: {action_id} is not Notify (Patch 14 only \
             executes Notify actions; got {:?})",
            action.kind
        )));
    }
    if action.status != hydra_core::ActionStatus::Approved {
        return Err(HydraError::QueryError(format!(
            "invalid action state: {action_id} is {:?}, expected Approved",
            action.status
        )));
    }

    // Step 2: deliver via adapter — NO engine lock held.
    let delivery = adapter.deliver(&action).await;

    // Step 3: re-acquire write lock and ingest the outcome.
    let hydra = state.runtime.hydra();
    let mut hydra = hydra.write().await;
    hydra.execute_notify_action_with_delivery(action_id, actor, delivery)
}

// === Trust Patch 3 (Patch 11) — auto-execution gate ============

/// Body for `POST /actions/{id}/auto-execute`.
///
/// `min_trust_score` is the floor — auto-execute requires BOTH
/// `trust.level == High` AND `trust.score >= min_trust_score`.
/// Defaults to `0.80` on the SDK side; the wire format requires
/// the caller to send it explicitly so deployments can pick their
/// own minimum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoExecuteActionRequest {
    pub actor: ActorId,
    pub min_trust_score: f64,
}

/// Wire response for `POST /actions/{id}/auto-execute`.
///
/// Mirrors `hydra_core::AutoExecutionDecision`. Returns 200 in
/// every non-error case — the `executed` boolean is the binding
/// decision, not the HTTP status. `trust` is populated whenever
/// the assessor ran (i.e., the action passed kind+status+claim
/// preconditions); `execution` is populated only when
/// `executed == true`.
///
/// `previous_status` / `final_status` inside the embedded
/// execution use lowercase wire form for consistency with the
/// Patch 7 execute envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoExecuteActionResponse {
    pub executed: bool,
    pub reason: String,
    pub trust: Option<hydra_core::TrustAssessment>,
    pub execution: Option<ActionExecutionResponse>,
}

async fn auto_execute_action(
    State(state): State<ActionsHttpState>,
    Path(action_id): Path<String>,
    request: Result<Json<AutoExecuteActionRequest>, axum::extract::rejection::JsonRejection>,
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

    let decision = match hydra.auto_execute_trusted_notify_action(
        action_id,
        request.actor.clone(),
        request.min_trust_score,
    ) {
        Ok(d) => d,
        Err(err) => return engine_error_response(err),
    };

    // Translate the embedded ActionExecutionReport into the wire
    // envelope's lowercase-status form, mirroring Patch 7.
    let execution_wire = decision.execution.map(|report| ActionExecutionResponse {
        action_id: report.action_id,
        previous_status: status_wire_name(&report.previous_status).to_string(),
        final_status: status_wire_name(&report.final_status).to_string(),
        outcome_id: report.outcome_id,
        executed_by: report.executed_by,
        executed_at: report.executed_at,
    });
    let body = AutoExecuteActionResponse {
        executed: decision.executed,
        reason: decision.reason,
        trust: decision.trust,
        execution: execution_wire,
    };
    (StatusCode::OK, Json(body)).into_response()
}

/// Lowercase wire-form name for ActionStatus. Hydra's wire form
/// for `ActionStatus` is PascalCase via serde default; the
/// transition response uses lowercase so it reads naturally
/// alongside other low-level state labels.
fn status_wire_name(status: &ActionStatus) -> &'static str {
    match status {
        ActionStatus::Proposed => "proposed",
        ActionStatus::Approved => "approved",
        ActionStatus::Rejected => "rejected",
        ActionStatus::Executing => "executing",
        ActionStatus::Executed => "executed",
        ActionStatus::Failed => "failed",
        ActionStatus::Cancelled => "cancelled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use hydra_core::{
        action::{Action, ActionKind, ActionTarget},
        EventKind, Policy, PolicyId, PolicyKind, PolicyScope, PolicyStatus,
    };
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn actor_id(name: &str) -> String {
        name.to_string()
    }

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

    async fn ingest_one_proposed_action(
        runtime: &crate::runtime::RuntimeHandle,
    ) -> hydra_core::ActionId {
        // Register a HumanApproval policy with AnyAction scope so
        // the policy cascade emits ApprovalRequested instead of
        // auto-approving via the default Allow path. Without this,
        // a fresh Hydra has no policies and every ActionProposed
        // is immediately Approved by the cascade — which would
        // leave nothing for Patch 6's operator endpoints to flip.
        let action_id = hydra_core::ActionId::new();
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test_proposer");
        let policy = Policy {
            id: PolicyId::new(),
            tenant_id: None,
            name: "Patch 6 test — require human approval".to_string(),
            kind: PolicyKind::HumanApproval,
            status: PolicyStatus::Active,
            scope: PolicyScope::AnyAction,
            condition: HashMap::new(),
            metadata: HashMap::new(),
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        let action = Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: ActionKind::Notify,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("hydra".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor,
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
            .ingest(EventKind::PolicyRegistered { policy })
            .unwrap();
        hydra
            .ingest(EventKind::ActionProposed { action })
            .unwrap();
        action_id
    }

    #[tokio::test]
    async fn approve_action_flips_proposed_to_approved() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_id = ingest_one_proposed_action(&runtime).await;
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/approve"),
                serde_json::json!({
                    "actor": actor_id("actor_oncall_alice"),
                    "reason": "confirmed by alice",
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: ActionTransitionResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.action_id, action_id);
        assert_eq!(body.status, "approved");
        assert_eq!(body.previous_status, "proposed");
        assert_eq!(
            body.approved_by,
            Some(hydra_core::ActorId::from_str("actor_oncall_alice"))
        );
        assert!(body.rejected_by.is_none());
        assert_eq!(body.reason.as_deref(), Some("confirmed by alice"));
        assert!(body.approved_at.is_some());
    }

    #[tokio::test]
    async fn reject_action_flips_proposed_to_rejected() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_id = ingest_one_proposed_action(&runtime).await;
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/reject"),
                serde_json::json!({
                    "actor": actor_id("actor_oncall_alice"),
                    "reason": "false alarm — planned maintenance",
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: ActionTransitionResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.status, "rejected");
        assert_eq!(body.previous_status, "proposed");
        assert_eq!(
            body.rejected_by,
            Some(hydra_core::ActorId::from_str("actor_oncall_alice"))
        );
        assert!(body.approved_by.is_none());
        assert_eq!(body.reason.as_deref(), Some("false alarm — planned maintenance"));
    }

    #[tokio::test]
    async fn approve_missing_action_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                "/actions/act_does_not_exist/approve",
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.error.contains("unknown action"));
    }

    #[tokio::test]
    async fn reject_missing_action_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                "/actions/act_does_not_exist/reject",
                serde_json::json!({
                    "actor": actor_id("actor_ops"),
                    "reason": "ghost",
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn approve_without_reason_succeeds() {
        // `reason` is optional on approve. Omitting it must work.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_id = ingest_one_proposed_action(&runtime).await;
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/approve"),
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: ActionTransitionResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.status, "approved");
        assert!(body.reason.is_none());
    }

    #[tokio::test]
    async fn reject_requires_reason_in_body() {
        // Reject's `reason` is required by the body schema. Omitting
        // it must surface as 400.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_id = ingest_one_proposed_action(&runtime).await;
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/reject"),
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn approve_already_approved_is_idempotent() {
        // v0 does NOT enforce terminal states. A second approve
        // surfaces previous_status="approved" — the caller can
        // detect the idempotent flip.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_id = ingest_one_proposed_action(&runtime).await;
        let app = actions_router(runtime.clone());
        let first = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/approve"),
                serde_json::json!({ "actor": actor_id("actor_first") }),
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/approve"),
                serde_json::json!({ "actor": actor_id("actor_second") }),
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let body: ActionTransitionResponse =
            serde_json::from_slice(&read_body_bytes(second).await).unwrap();
        assert_eq!(body.previous_status, "approved");
        assert_eq!(body.status, "approved");
        // Second approver overrides the first — the audit log
        // captured both events.
        assert_eq!(
            body.approved_by,
            Some(hydra_core::ActorId::from_str("actor_second"))
        );
    }

    #[test]
    fn status_wire_name_uses_lowercase() {
        // Pinned because the response uses lowercase across the
        // status enum even though the engine's serde default is
        // PascalCase.
        assert_eq!(status_wire_name(&ActionStatus::Proposed), "proposed");
        assert_eq!(status_wire_name(&ActionStatus::Approved), "approved");
        assert_eq!(status_wire_name(&ActionStatus::Rejected), "rejected");
        assert_eq!(status_wire_name(&ActionStatus::Executing), "executing");
        assert_eq!(status_wire_name(&ActionStatus::Executed), "executed");
        assert_eq!(status_wire_name(&ActionStatus::Failed), "failed");
        assert_eq!(status_wire_name(&ActionStatus::Cancelled), "cancelled");
    }

    // === MicroModel Patch 7 — execution stub ===

    /// Ingest a Proposed Notify action with NO policy registered.
    /// The cascade auto-approves it (default Allow), so the action
    /// lands in Approved status — ready for /execute to consume.
    async fn ingest_one_approved_action(
        runtime: &crate::runtime::RuntimeHandle,
    ) -> hydra_core::ActionId {
        let action_id = hydra_core::ActionId::new();
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test_proposer");
        let action = Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: ActionKind::Notify,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("hydra".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor,
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
            .ingest(EventKind::ActionProposed { action })
            .unwrap();
        action_id
    }

    #[tokio::test]
    async fn execute_action_flips_approved_to_executed() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_id = ingest_one_approved_action(&runtime).await;
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/execute"),
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: ActionExecutionResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.action_id, action_id);
        assert_eq!(body.previous_status, "approved");
        assert_eq!(body.final_status, "executed");
        assert_eq!(
            body.executed_by,
            hydra_core::ActorId::from_str("actor_ops")
        );
    }

    #[tokio::test]
    async fn execute_action_returns_outcome_id() {
        // The execute endpoint must surface the outcome_id so
        // callers can fetch the recorded outcome without a follow-up
        // list-by-action query. The outcome itself lives in the
        // action_store under the action_id.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_id = ingest_one_approved_action(&runtime).await;
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/execute"),
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: ActionExecutionResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        // Verify the outcome lives in the store under this action.
        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        let outcomes = hydra.outcomes_for_action(&action_id);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].id, body.outcome_id);
    }

    #[tokio::test]
    async fn execute_missing_action_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                "/actions/act_does_not_exist/execute",
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn execute_action_refuses_proposed_status() {
        // Register HumanApproval/AnyAction so the cascade leaves the
        // action in Proposed; execute must return 400.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let now = chrono::Utc::now();
        let policy_actor = hydra_core::ActorId::from_str("actor_test_policy_admin");
        let policy = Policy {
            id: PolicyId::new(),
            tenant_id: None,
            name: "Patch 7 HTTP test — require human approval".to_string(),
            kind: PolicyKind::HumanApproval,
            status: PolicyStatus::Active,
            scope: PolicyScope::AnyAction,
            condition: HashMap::new(),
            metadata: HashMap::new(),
            created_by: policy_actor,
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        let action_id = hydra_core::ActionId::new();
        let actor = hydra_core::ActorId::from_str("actor_test_proposer");
        let action = Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: ActionKind::Notify,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("hydra".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor,
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
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest(EventKind::PolicyRegistered { policy })
                .unwrap();
            hydra
                .ingest(EventKind::ActionProposed { action })
                .unwrap();
        }
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/execute"),
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.error.contains("invalid action state"), "got: {}", body.error);
    }

    #[tokio::test]
    async fn execute_action_refuses_non_notify_kind() {
        // Backfill kind in Approved state — must surface 400 with
        // "invalid action kind" message.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test_proposer");
        let action_id = hydra_core::ActionId::new();
        let action = Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: ActionKind::Backfill,
            status: ActionStatus::Approved,
            targets: vec![ActionTarget::Dataset("orders".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: Some(actor),
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
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/execute"),
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.error.contains("invalid action kind"), "got: {}", body.error);
        assert!(body.error.contains("Notify"), "got: {}", body.error);
    }

    #[tokio::test]
    async fn approve_then_execute_full_round_trip() {
        // The realistic operator flow: register HumanApproval so the
        // action stays Proposed, then approve via /approve, then
        // execute via /execute. Pins the joint Patch 6 + Patch 7
        // surface against regression.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let now = chrono::Utc::now();
        let policy_actor = hydra_core::ActorId::from_str("actor_test_policy_admin");
        let policy = Policy {
            id: PolicyId::new(),
            tenant_id: None,
            name: "Patch 7 round-trip — require human approval".to_string(),
            kind: PolicyKind::HumanApproval,
            status: PolicyStatus::Active,
            scope: PolicyScope::AnyAction,
            condition: HashMap::new(),
            metadata: HashMap::new(),
            created_by: policy_actor,
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        let action_id = hydra_core::ActionId::new();
        let proposer = hydra_core::ActorId::from_str("actor_test_proposer");
        let action = Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: ActionKind::Notify,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("hydra".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: proposer,
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
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest(EventKind::PolicyRegistered { policy })
                .unwrap();
            hydra
                .ingest(EventKind::ActionProposed { action })
                .unwrap();
        }
        let app = actions_router(runtime.clone());

        // Step 1: approve.
        let approve_resp = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/approve"),
                serde_json::json!({ "actor": actor_id("actor_oncall_alice") }),
            ))
            .await
            .unwrap();
        assert_eq!(approve_resp.status(), StatusCode::OK);

        // Step 2: execute.
        let exec_resp = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/execute"),
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(exec_resp.status(), StatusCode::OK);
        let body: ActionExecutionResponse =
            serde_json::from_slice(&read_body_bytes(exec_resp).await).unwrap();
        assert_eq!(body.previous_status, "approved");
        assert_eq!(body.final_status, "executed");
    }

    // === Trust Patch 3 (Patch 11) — auto-execution gate ===

    /// Ingest a fresh model-derived Approved Notify action. Trust on
    /// its claim will be Medium (~0.50) — auto-execute must skip.
    /// Returns (action_id, claim_id).
    async fn ingest_fresh_model_chain(
        runtime: &crate::runtime::RuntimeHandle,
    ) -> (hydra_core::ActionId, hydra_core::ClaimId) {
        let actor = hydra_core::ActorId::from_str("actor_test");
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        // Warm the model + prime to a hot baseline (inline so this
        // file doesn't reach into the engine test module's
        // helpers).
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
        (
            assessment.action_ids[0].clone(),
            assessment.claim_id.unwrap(),
        )
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

    /// Drive a full chain (execute + observe to get to High trust)
    /// then propose a SECOND Notify action sharing the claim. The
    /// new action is Approved with High-trust signals inherited
    /// from the sibling's execution history.
    async fn ingest_high_trust_sibling(
        runtime: &crate::runtime::RuntimeHandle,
    ) -> hydra_core::ActionId {
        let (first_action_id, claim_id) = ingest_fresh_model_chain(runtime).await;
        let actor = hydra_core::ActorId::from_str("actor_test");
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        // Execute the first action + observe → trust High on claim.
        let report = hydra
            .execute_notify_action(first_action_id, actor.clone())
            .unwrap();
        hydra
            .record_micro_model_observation_from_action_outcome(
                report.outcome_id,
                actor.clone(),
            )
            .unwrap();
        // Sanity: trust on shared claim is High.
        let trust = hydra.assess_claim_trust(&claim_id).unwrap();
        assert_eq!(trust.level, hydra_core::TrustLevel::High);

        // Propose a sibling action linked to the same claim.
        let now = chrono::Utc::now();
        let sibling_id = hydra_core::ActionId::new();
        let sibling = Action {
            id: sibling_id.clone(),
            tenant_id: None,
            kind: ActionKind::Notify,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("hydra".to_string())],
            related_claims: vec![claim_id],
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
        hydra
            .ingest(EventKind::ActionProposed { action: sibling })
            .unwrap();
        // Cascade auto-approves (no HumanApproval policy registered).
        assert_eq!(
            hydra.action(&sibling_id).unwrap().status,
            ActionStatus::Approved
        );
        sibling_id
    }

    #[tokio::test]
    async fn auto_execute_with_high_trust_returns_full_envelope() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let sibling_id = ingest_high_trust_sibling(&runtime).await;
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{sibling_id}/auto-execute"),
                serde_json::json!({
                    "actor": actor_id("actor_hydra_trust_gate"),
                    "min_trust_score": 0.80,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: AutoExecuteActionResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.executed, "decision: {body:#?}");
        assert!(body.reason.contains("trust High"));
        let trust = body.trust.as_ref().unwrap();
        assert_eq!(trust.level, hydra_core::TrustLevel::High);
        assert!(trust.score >= 0.80);
        let execution = body.execution.as_ref().unwrap();
        assert_eq!(execution.previous_status, "approved");
        assert_eq!(execution.final_status, "executed");
    }

    #[tokio::test]
    async fn auto_execute_with_low_trust_returns_200_skip_envelope() {
        // The decision endpoint contract: trust below threshold
        // returns 200 with executed=false. NOT 400 or 409 — the
        // decision is the data.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (action_id, _) = ingest_fresh_model_chain(&runtime).await;
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/auto-execute"),
                serde_json::json!({
                    "actor": actor_id("actor_hydra_trust_gate"),
                    "min_trust_score": 0.80,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: AutoExecuteActionResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(!body.executed);
        assert!(body.reason.contains("trust insufficient"));
        assert!(body.trust.is_some(), "trust populated on skip");
        assert!(body.execution.is_none());
    }

    #[tokio::test]
    async fn auto_execute_unknown_action_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                "/actions/act_ghost/auto-execute",
                serde_json::json!({
                    "actor": actor_id("actor_hydra_trust_gate"),
                    "min_trust_score": 0.80,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn auto_execute_refuses_non_notify_kind_with_400() {
        // KIND is the hard contract: a Backfill can NEVER be
        // auto-executed by this method. Returns 400, NOT a
        // 200 skip envelope.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let action_id = hydra_core::ActionId::new();
        let now = chrono::Utc::now();
        let action = Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: ActionKind::Backfill,
            status: ActionStatus::Approved,
            targets: vec![ActionTarget::Dataset("orders".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: Some(actor),
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
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/auto-execute"),
                serde_json::json!({
                    "actor": actor_id("actor_hydra_trust_gate"),
                    "min_trust_score": 0.80,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.error.contains("invalid action kind"), "got: {}", body.error);
    }

    #[tokio::test]
    async fn auto_execute_with_no_related_claims_returns_200_skip() {
        // Approved Notify action with no claim → 200 skip with
        // trust=null. Different from kind error (which is 400)
        // because operators may pre-ingest non-model Notify
        // actions that need fall-back to manual execute.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let action_id = hydra_core::ActionId::new();
        let now = chrono::Utc::now();
        let action = Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: ActionKind::Notify,
            status: ActionStatus::Approved,
            targets: vec![ActionTarget::System("hydra".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: Some(actor),
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
        let app = actions_router(runtime.clone());
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/auto-execute"),
                serde_json::json!({
                    "actor": actor_id("actor_hydra_trust_gate"),
                    "min_trust_score": 0.80,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: AutoExecuteActionResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(!body.executed);
        assert!(body.reason.contains("no related_claims"));
        assert!(body.trust.is_none());
        assert!(body.execution.is_none());
    }

    // === Patch 14 — Notify Delivery Adapter (HTTP integration) ===

    use crate::notify_delivery::{NotifyAdapter, StubAdapter, WebhookAdapter};
    use axum::routing::post as axum_post;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration as StdDuration;
    use tokio::net::TcpListener;

    /// Minimal fake webhook server reused for Patch 14 HTTP tests.
    /// Spins up on a loopback port; returns the URL plus knobs for
    /// the response status code + a "sleep before response" delay.
    struct WebhookServer {
        url: String,
        bodies: Arc<Mutex<Vec<serde_json::Value>>>,
        next_status: Arc<AtomicUsize>,
        sleep_ms: Arc<AtomicUsize>,
    }

    impl WebhookServer {
        async fn start() -> Self {
            let bodies = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
            let next_status = Arc::new(AtomicUsize::new(200));
            let sleep_ms = Arc::new(AtomicUsize::new(0));
            let b = bodies.clone();
            let ns = next_status.clone();
            let sm = sleep_ms.clone();
            let app = axum::Router::new().route(
                "/hook",
                axum_post(move |body: Json<serde_json::Value>| {
                    let b = b.clone();
                    let ns = ns.clone();
                    let sm = sm.clone();
                    async move {
                        let s = sm.load(Ordering::SeqCst);
                        if s > 0 {
                            tokio::time::sleep(StdDuration::from_millis(s as u64))
                                .await;
                        }
                        b.lock().unwrap().push(body.0);
                        axum::http::StatusCode::from_u16(
                            ns.load(Ordering::SeqCst) as u16,
                        )
                        .unwrap_or(axum::http::StatusCode::OK)
                    }
                }),
            );
            let listener =
                TcpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                    .await
                    .unwrap();
            let addr = listener.local_addr().unwrap();
            let url = format!("http://{addr}/hook");
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                url,
                bodies,
                next_status,
                sleep_ms,
            }
        }

        fn url(&self) -> &str {
            &self.url
        }

        fn set_status(&self, s: u16) {
            self.next_status.store(s as usize, Ordering::SeqCst);
        }

        fn set_sleep(&self, ms: u64) {
            self.sleep_ms.store(ms as usize, Ordering::SeqCst);
        }

        fn body_count(&self) -> usize {
            self.bodies.lock().unwrap().len()
        }
    }

    /// Drive a chain end-to-end: prime + Critical + propose
    /// (cascade auto-approves the Notify action). Returns the
    /// Approved action_id ready for `/execute`.
    async fn drive_chain_to_approved_action(
        runtime: &crate::runtime::RuntimeHandle,
    ) -> hydra_core::ActionId {
        let actor = hydra_core::ActorId::from_str("actor_test");
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
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
    }

    #[tokio::test]
    async fn execute_action_with_stub_adapter_preserves_patch_7_behavior() {
        // When notify_delivery is None (the actions_router default),
        // execute_action emits the Patch 7 stub outcome.
        // Bit-identical to existing
        // `execute_action_flips_approved_to_executed`.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_id = drive_chain_to_approved_action(&runtime).await;
        let app = actions_router(runtime.clone()); // None
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/execute"),
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: ActionExecutionResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.final_status, "executed");
        // The outcome carries the Patch 7 stub marker.
        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        let outcome = hydra.outcome(&body.outcome_id).unwrap();
        assert!(matches!(
            outcome.impact.get("stub"),
            Some(hydra_core::Value::Bool(true))
        ));
    }

    #[tokio::test]
    async fn execute_action_with_webhook_succeeded_returns_executed_envelope() {
        // Spin up a fake webhook server that returns 200. Configure
        // actions_router with a WebhookAdapter pointing at it.
        // After execute, the action is Executed AND the webhook
        // server received the deterministic payload.
        let server = WebhookServer::start().await;
        let adapter = Arc::new(NotifyAdapter::Webhook(WebhookAdapter::new(
            server.url(),
            StdDuration::from_secs(2),
        )));
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_id = drive_chain_to_approved_action(&runtime).await;
        let app = actions_router_with_notify(runtime.clone(), Some(adapter));
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/execute"),
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: ActionExecutionResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.final_status, "executed");
        // The outcome carries the Patch 14 NON-stub marker + adapter id.
        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        let outcome = hydra.outcome(&body.outcome_id).unwrap();
        assert!(matches!(
            outcome.impact.get("stub"),
            Some(hydra_core::Value::Bool(false))
        ));
        assert_eq!(
            outcome.impact.get("adapter").and_then(|v| v.as_str()),
            Some("webhook")
        );
        assert_eq!(outcome.kind, hydra_core::OutcomeKind::Success);
        // Webhook server received exactly one payload.
        assert_eq!(server.body_count(), 1);
    }

    #[tokio::test]
    async fn execute_action_with_webhook_failure_returns_failure_outcome() {
        // Webhook server returns 500 → action ends Failed, outcome
        // kind Failure. HTTP response is still 200 because the
        // delivery DID complete (just unsuccessfully).
        let server = WebhookServer::start().await;
        server.set_status(500);
        let adapter = Arc::new(NotifyAdapter::Webhook(WebhookAdapter::new(
            server.url(),
            StdDuration::from_secs(2),
        )));
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_id = drive_chain_to_approved_action(&runtime).await;
        let app = actions_router_with_notify(runtime.clone(), Some(adapter));
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/execute"),
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: ActionExecutionResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.final_status, "failed");
        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        let outcome = hydra.outcome(&body.outcome_id).unwrap();
        assert_eq!(outcome.kind, hydra_core::OutcomeKind::Failure);
        assert_eq!(
            outcome.impact.get("status_code").and_then(|v| v.as_i64()),
            Some(500)
        );
    }

    #[tokio::test]
    async fn execute_action_with_webhook_timeout_returns_failure_outcome() {
        // Webhook receiver sleeps past adapter timeout → Failed
        // outcome with status_code unset (we never got a response).
        let server = WebhookServer::start().await;
        server.set_sleep(500);
        let adapter = Arc::new(NotifyAdapter::Webhook(WebhookAdapter::new(
            server.url(),
            StdDuration::from_millis(100),
        )));
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let action_id = drive_chain_to_approved_action(&runtime).await;
        let app = actions_router_with_notify(runtime.clone(), Some(adapter));
        let response = app
            .oneshot(json_request(
                Method::POST,
                &format!("/actions/{action_id}/execute"),
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: ActionExecutionResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.final_status, "failed");
        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        let outcome = hydra.outcome(&body.outcome_id).unwrap();
        assert_eq!(outcome.kind, hydra_core::OutcomeKind::Failure);
        // No status_code (we never got a response).
        assert!(outcome.impact.get("status_code").is_none());
        let reason = outcome
            .impact
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(reason.contains("timeout"), "reason: {reason}");
    }

    #[tokio::test]
    async fn execute_action_webhook_mode_returns_404_on_unknown_action() {
        // Webhook mode still produces 404 on unknown id — the
        // validation in execute_action_with_delivery_mode catches
        // it before any network call.
        let server = WebhookServer::start().await;
        let adapter = Arc::new(NotifyAdapter::Webhook(WebhookAdapter::new(
            server.url(),
            StdDuration::from_secs(2),
        )));
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = actions_router_with_notify(runtime, Some(adapter));
        let response = app
            .oneshot(json_request(
                Method::POST,
                "/actions/act_ghost/execute",
                serde_json::json!({ "actor": actor_id("actor_ops") }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        // Webhook server received NOTHING — we short-circuited.
        assert_eq!(server.body_count(), 0);
    }

    // `StubAdapter` is unused in the HTTP tests (None-on-state is
    // the canonical stub mode) but we reference it for compile
    // coverage so the import isn't dead.
    #[allow(dead_code)]
    fn _stub_adapter_compile_check() -> StubAdapter {
        StubAdapter::new()
    }
}
