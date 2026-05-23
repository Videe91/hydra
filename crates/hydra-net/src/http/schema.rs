use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hydra_core::{
    Action, FieldSchema, SchemaDefinition, SchemaId,
};
use hydra_engine::schema_validator::{SchemaValidationError, SchemaValidationReport};
use serde::{Deserialize, Serialize};

/// Shared HTTP state for schema routes.
#[derive(Clone)]
pub struct SchemaHttpState {
    pub runtime: RuntimeHandle,
}

impl SchemaHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the schema HTTP router.
///
/// Mounted route shape:
/// - GET  /schemas/active
/// - POST /schemas/action
/// - POST /schemas/validate/action
/// - POST /schemas/:schema_id/disable
pub fn schema_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/schemas/active", get(active_schemas))
        .route("/schemas/action", post(register_action_schema))
        .route("/schemas/validate/action", post(validate_action))
        .route("/schemas/:schema_id/disable", post(disable_schema))
        .with_state(SchemaHttpState::new(runtime))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterActionSchemaRequest {
    pub action_kind: String,
    pub fields: Vec<FieldSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisableSchemaRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateActionRequest {
    pub action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaIdResponse {
    pub schema_id: SchemaId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSchemasResponse {
    pub schemas: Vec<SchemaDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaValidationErrorResponse {
    pub schema_id: Option<SchemaId>,
    pub path: String,
    pub message: String,
}

impl From<SchemaValidationError> for SchemaValidationErrorResponse {
    fn from(error: SchemaValidationError) -> Self {
        Self {
            schema_id: error.schema_id,
            path: error.path,
            message: error.message,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResponse {
    pub valid: bool,
    pub schema_id: Option<SchemaId>,
    pub errors: Vec<SchemaValidationErrorResponse>,
}

impl From<SchemaValidationReport> for ValidationResponse {
    fn from(report: SchemaValidationReport) -> Self {
        Self {
            valid: report.valid,
            schema_id: report.schema_id,
            errors: report
                .errors
                .into_iter()
                .map(SchemaValidationErrorResponse::from)
                .collect(),
        }
    }
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

async fn active_schemas(State(state): State<SchemaHttpState>) -> Response {
    let schemas = state.runtime.schema().active_schemas().await;
    Json(ActiveSchemasResponse { schemas }).into_response()
}

async fn register_action_schema(
    State(state): State<SchemaHttpState>,
    Json(request): Json<RegisterActionSchemaRequest>,
) -> Response {
    match state
        .runtime
        .schema_admin()
        .register_action_payload_schema(request.action_kind, request.fields)
        .await
    {
        Ok(schema_id) => {
            (StatusCode::CREATED, Json(SchemaIdResponse { schema_id })).into_response()
        }
        Err(error) => error_response(
            StatusCode::BAD_REQUEST,
            format!("failed to register action schema: {error}"),
        ),
    }
}

async fn validate_action(
    State(state): State<SchemaHttpState>,
    Json(request): Json<ValidateActionRequest>,
) -> Response {
    let report = state
        .runtime
        .schema()
        .validate_action_payload(&request.action)
        .await;
    Json(ValidationResponse::from(report)).into_response()
}

async fn disable_schema(
    State(state): State<SchemaHttpState>,
    Path(schema_id): Path<String>,
    Json(request): Json<DisableSchemaRequest>,
) -> Response {
    let schema_id = SchemaId::from_str(&schema_id);
    match state
        .runtime
        .schema_admin()
        .disable_schema(schema_id, request.reason)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(
            StatusCode::BAD_REQUEST,
            format!("failed to disable schema: {error}"),
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
        ActionId, ActionKind, ActionStatus, ActionTarget, ActorId, FieldSchema, SchemaStatus,
        Value, ValueType,
    };
    use tower::ServiceExt;

    fn actor() -> ActorId {
        ActorId::from_str("actor_http_schema")
    }

    fn post_ledger_action(amount: Value) -> Action {
        let now = chrono::Utc::now();
        let mut payload = std::collections::HashMap::new();
        payload.insert("account".to_string(), Value::String("Cash".to_string()));
        payload.insert("amount".to_string(), amount);
        Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::PostLedgerEntry,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("ledger".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor(),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        }
    }

    fn request_json<T: Serialize>(method: Method, uri: &str, body: &T) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    async fn read_body_bytes(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn get_active_schemas_returns_empty_then_one() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = schema_router(runtime.clone());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/schemas/active")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body_bytes(response).await;
        let decoded: ActiveSchemasResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(decoded.schemas.len(), 0);

        runtime
            .schema_admin()
            .register_action_payload_schema(
                "PostLedgerEntry",
                vec![
                    FieldSchema::required("account", ValueType::String),
                    FieldSchema::required("amount", ValueType::Float),
                ],
            )
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/schemas/active")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body_bytes(response).await;
        let decoded: ActiveSchemasResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(decoded.schemas.len(), 1);
    }

    #[tokio::test]
    async fn post_action_schema_registers_schema() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = schema_router(runtime.clone());
        let request = RegisterActionSchemaRequest {
            action_kind: "PostLedgerEntry".to_string(),
            fields: vec![
                FieldSchema::required("account", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
            ],
        };
        let response = app
            .oneshot(request_json(Method::POST, "/schemas/action", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = read_body_bytes(response).await;
        let decoded: SchemaIdResponse = serde_json::from_slice(&body).unwrap();
        assert!(runtime.schema().schema(&decoded.schema_id).await.is_some());
        assert!(runtime
            .schema()
            .action_payload_schema("PostLedgerEntry")
            .await
            .is_some());
    }

    #[tokio::test]
    async fn validate_action_returns_valid_for_good_payload() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        runtime
            .schema_admin()
            .register_action_payload_schema(
                "PostLedgerEntry",
                vec![
                    FieldSchema::required("account", ValueType::String),
                    FieldSchema::required("amount", ValueType::Float),
                ],
            )
            .await
            .unwrap();
        let app = schema_router(runtime);
        let request = ValidateActionRequest {
            action: post_ledger_action(Value::Float(100.0)),
        };
        let response = app
            .oneshot(request_json(
                Method::POST,
                "/schemas/validate/action",
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body_bytes(response).await;
        let decoded: ValidationResponse = serde_json::from_slice(&body).unwrap();
        assert!(decoded.valid);
        assert!(decoded.schema_id.is_some());
        assert!(decoded.errors.is_empty());
    }

    #[tokio::test]
    async fn validate_action_returns_invalid_for_bad_payload() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        runtime
            .schema_admin()
            .register_action_payload_schema(
                "PostLedgerEntry",
                vec![
                    FieldSchema::required("account", ValueType::String),
                    FieldSchema::required("amount", ValueType::Float),
                ],
            )
            .await
            .unwrap();
        let app = schema_router(runtime);
        let request = ValidateActionRequest {
            action: post_ledger_action(Value::String("bad".to_string())),
        };
        let response = app
            .oneshot(request_json(
                Method::POST,
                "/schemas/validate/action",
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body_bytes(response).await;
        let decoded: ValidationResponse = serde_json::from_slice(&body).unwrap();
        assert!(!decoded.valid);
        assert_eq!(decoded.errors.len(), 1);
        assert_eq!(decoded.errors[0].path, "amount");
    }

    #[tokio::test]
    async fn post_disable_schema_removes_from_active() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let schema_id = runtime
            .schema_admin()
            .register_action_payload_schema(
                "PostLedgerEntry",
                vec![
                    FieldSchema::required("account", ValueType::String),
                    FieldSchema::required("amount", ValueType::Float),
                ],
            )
            .await
            .unwrap();
        let app = schema_router(runtime.clone());
        let request = DisableSchemaRequest {
            reason: Some("deprecated".to_string()),
        };
        let response = app
            .oneshot(request_json(
                Method::POST,
                &format!("/schemas/{schema_id}/disable"),
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(runtime.schema().active_schemas().await.len(), 0);
        assert_eq!(runtime.schema().disabled_schemas().await.len(), 1);
        match runtime.schema().schema(&schema_id).await.unwrap() {
            SchemaDefinition::ActionPayload(schema) => {
                assert_eq!(schema.status, SchemaStatus::Disabled);
            }
            other => panic!("expected action payload schema, got {other:?}"),
        }
    }
}
