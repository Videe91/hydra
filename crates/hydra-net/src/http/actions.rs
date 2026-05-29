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

#[derive(Clone)]
pub struct ActionsHttpState {
    pub runtime: RuntimeHandle,
}

impl ActionsHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the actions router. Three routes today: `/approve` +
/// `/reject` (Patch 6 — governance gate) and `/execute` (Patch 7 —
/// internal execution stub for Notify actions).
pub fn actions_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/actions/:action_id/approve", post(approve_action))
        .route("/actions/:action_id/reject", post(reject_action))
        .route("/actions/:action_id/execute", post(execute_action))
        .with_state(ActionsHttpState::new(runtime))
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
    let hydra = state.runtime.hydra();
    let mut hydra = hydra.write().await;

    let report = match hydra.execute_notify_action(action_id.clone(), request.actor.clone()) {
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
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
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
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: Some(now),
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
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
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
}
