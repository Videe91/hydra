use crate::http::tenant::{extract_tenant, tenant_error_response};
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hydra_core::{
    Action, Claim, EdgeId, Evidence, FieldSchema, Policy, SchemaDefinition, SchemaId, TypeId,
    Value, ValueType,
};
use hydra_engine::schema_validator::{SchemaValidationError, SchemaValidationReport};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
/// Mounted route shape (full schema HTTP surface — 25 routes after
/// Edge Gating Patch 2 added 4 edge routes):
///
/// Read:
/// - GET  /schemas/active
/// - GET  /schemas/disabled
/// - GET  /schemas/archived
/// - GET  /schemas/entity/:type_id
/// - GET  /schemas/edge/:type_id
/// - GET  /schemas/evidence/:kind
/// - GET  /schemas/claim/:predicate
/// - GET  /schemas/action/:action_kind
/// - GET  /schemas/policy/:policy_kind
///
/// Register:
/// - POST /schemas/entity
/// - POST /schemas/edge
/// - POST /schemas/evidence
/// - POST /schemas/claim-predicate
/// - POST /schemas/action
/// - POST /schemas/policy-condition
///
/// Lifecycle:
/// - POST /schemas/:schema_id/disable
/// - POST /schemas/:schema_id/archive
///
/// Validate:
/// - POST /schemas/validate/action
/// - POST /schemas/validate/evidence
/// - POST /schemas/validate/claim
/// - POST /schemas/validate/policy
/// - POST /schemas/validate/node-create
/// - POST /schemas/validate/node-update
/// - POST /schemas/validate/edge-create
/// - POST /schemas/validate/edge-update
pub fn schema_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        // Read
        .route("/schemas/active", get(active_schemas))
        .route("/schemas/disabled", get(disabled_schemas))
        .route("/schemas/archived", get(archived_schemas))
        .route("/schemas/entity/:type_id", get(get_entity_schema))
        .route("/schemas/edge/:type_id", get(get_edge_schema))
        .route("/schemas/evidence/:kind", get(get_evidence_schema))
        .route("/schemas/claim/:predicate", get(get_claim_predicate_schema))
        .route("/schemas/action/:action_kind", get(get_action_payload_schema))
        .route(
            "/schemas/policy/:policy_kind",
            get(get_policy_condition_schema),
        )
        // Register
        .route("/schemas/entity", post(register_entity_schema))
        .route("/schemas/edge", post(register_edge_schema))
        .route("/schemas/evidence", post(register_evidence_schema))
        .route(
            "/schemas/claim-predicate",
            post(register_claim_predicate_schema),
        )
        .route("/schemas/action", post(register_action_schema))
        .route(
            "/schemas/policy-condition",
            post(register_policy_condition_schema),
        )
        // Lifecycle
        .route("/schemas/:schema_id/disable", post(disable_schema))
        .route("/schemas/:schema_id/archive", post(archive_schema))
        // Validate
        .route("/schemas/validate/action", post(validate_action))
        .route("/schemas/validate/evidence", post(validate_evidence))
        .route("/schemas/validate/claim", post(validate_claim))
        .route("/schemas/validate/policy", post(validate_policy))
        .route("/schemas/validate/node-create", post(validate_node_create))
        .route("/schemas/validate/node-update", post(validate_node_update))
        .route("/schemas/validate/edge-create", post(validate_edge_create))
        .route("/schemas/validate/edge-update", post(validate_edge_update))
        .with_state(SchemaHttpState::new(runtime))
}

// === Register request DTOs (one per SchemaDefinition variant) ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterEntitySchemaRequest {
    pub type_id: TypeId,
    pub name: String,
    pub fields: Vec<FieldSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterEvidenceSchemaRequest {
    pub kind: String,
    pub fields: Vec<FieldSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterClaimPredicateSchemaRequest {
    pub predicate: String,
    pub subject_type: Option<TypeId>,
    pub object_type: ValueType,
    pub allowed_claim_kinds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterActionSchemaRequest {
    pub action_kind: String,
    pub fields: Vec<FieldSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPolicyConditionSchemaRequest {
    pub policy_kind: String,
    pub fields: Vec<FieldSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterEdgeSchemaRequest {
    pub type_id: TypeId,
    pub name: String,
    pub fields: Vec<FieldSchema>,
}

// === Lifecycle request DTO (shared by disable + archive) ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaLifecycleRequest {
    pub reason: Option<String>,
}

// === Validate request DTOs (one per typed write surface) ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateActionRequest {
    pub action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateEvidenceRequest {
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateClaimRequest {
    pub claim: Claim,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatePolicyRequest {
    pub policy: Policy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateNodeCreateRequest {
    pub type_id: TypeId,
    pub properties: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateNodeUpdateRequest {
    pub type_id: TypeId,
    pub changes: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateEdgeCreateRequest {
    pub type_id: TypeId,
    pub properties: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateEdgeUpdateRequest {
    pub edge_id: EdgeId,
    pub changes: HashMap<String, Value>,
}

// === Response DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaIdResponse {
    pub schema_id: SchemaId,
}

/// Shared response shape for any list-of-schemas endpoint
/// (active / disabled / archived).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemasResponse {
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

// === Read handlers ===

async fn active_schemas(State(state): State<SchemaHttpState>) -> Response {
    Json(SchemasResponse {
        schemas: state.runtime.schema().active_schemas().await,
    })
    .into_response()
}

async fn disabled_schemas(State(state): State<SchemaHttpState>) -> Response {
    Json(SchemasResponse {
        schemas: state.runtime.schema().disabled_schemas().await,
    })
    .into_response()
}

async fn archived_schemas(State(state): State<SchemaHttpState>) -> Response {
    Json(SchemasResponse {
        schemas: state.runtime.schema().archived_schemas().await,
    })
    .into_response()
}

async fn get_entity_schema(
    State(state): State<SchemaHttpState>,
    Path(type_id): Path<String>,
) -> Response {
    let type_id = TypeId::from_str(&type_id);
    match state.runtime.schema().entity_schema(&type_id).await {
        Some(schema) => Json(schema).into_response(),
        None => error_response(StatusCode::NOT_FOUND, "entity schema not found"),
    }
}

async fn get_edge_schema(
    State(state): State<SchemaHttpState>,
    Path(type_id): Path<String>,
) -> Response {
    let type_id = TypeId::from_str(&type_id);
    match state.runtime.schema().edge_schema(&type_id).await {
        Some(schema) => Json(schema).into_response(),
        None => error_response(StatusCode::NOT_FOUND, "edge schema not found"),
    }
}

async fn get_evidence_schema(
    State(state): State<SchemaHttpState>,
    Path(kind): Path<String>,
) -> Response {
    match state.runtime.schema().evidence_schema(&kind).await {
        Some(schema) => Json(schema).into_response(),
        None => error_response(StatusCode::NOT_FOUND, "evidence schema not found"),
    }
}

async fn get_claim_predicate_schema(
    State(state): State<SchemaHttpState>,
    Path(predicate): Path<String>,
) -> Response {
    match state.runtime.schema().claim_predicate_schema(&predicate).await {
        Some(schema) => Json(schema).into_response(),
        None => error_response(StatusCode::NOT_FOUND, "claim predicate schema not found"),
    }
}

async fn get_action_payload_schema(
    State(state): State<SchemaHttpState>,
    Path(action_kind): Path<String>,
) -> Response {
    match state.runtime.schema().action_payload_schema(&action_kind).await {
        Some(schema) => Json(schema).into_response(),
        None => error_response(StatusCode::NOT_FOUND, "action payload schema not found"),
    }
}

async fn get_policy_condition_schema(
    State(state): State<SchemaHttpState>,
    Path(policy_kind): Path<String>,
) -> Response {
    match state.runtime.schema().policy_condition_schema(&policy_kind).await {
        Some(schema) => Json(schema).into_response(),
        None => error_response(StatusCode::NOT_FOUND, "policy condition schema not found"),
    }
}

// === Register handlers ===

async fn register_entity_schema(
    State(state): State<SchemaHttpState>,
    headers: HeaderMap,
    Json(request): Json<RegisterEntitySchemaRequest>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    match state
        .runtime
        .schema_admin()
        .for_tenant(tenant)
        .register_entity_schema(request.type_id, request.name, request.fields)
        .await
    {
        Ok(schema_id) => {
            (StatusCode::CREATED, Json(SchemaIdResponse { schema_id })).into_response()
        }
        Err(error) => error_response(
            StatusCode::BAD_REQUEST,
            format!("failed to register entity schema: {error}"),
        ),
    }
}

async fn register_edge_schema(
    State(state): State<SchemaHttpState>,
    headers: HeaderMap,
    Json(request): Json<RegisterEdgeSchemaRequest>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    match state
        .runtime
        .schema_admin()
        .for_tenant(tenant)
        .register_edge_schema(request.type_id, request.name, request.fields)
        .await
    {
        Ok(schema_id) => {
            (StatusCode::CREATED, Json(SchemaIdResponse { schema_id })).into_response()
        }
        Err(error) => error_response(
            StatusCode::BAD_REQUEST,
            format!("failed to register edge schema: {error}"),
        ),
    }
}

async fn register_evidence_schema(
    State(state): State<SchemaHttpState>,
    headers: HeaderMap,
    Json(request): Json<RegisterEvidenceSchemaRequest>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    match state
        .runtime
        .schema_admin()
        .for_tenant(tenant)
        .register_evidence_schema(request.kind, request.fields)
        .await
    {
        Ok(schema_id) => {
            (StatusCode::CREATED, Json(SchemaIdResponse { schema_id })).into_response()
        }
        Err(error) => error_response(
            StatusCode::BAD_REQUEST,
            format!("failed to register evidence schema: {error}"),
        ),
    }
}

async fn register_claim_predicate_schema(
    State(state): State<SchemaHttpState>,
    headers: HeaderMap,
    Json(request): Json<RegisterClaimPredicateSchemaRequest>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    match state
        .runtime
        .schema_admin()
        .for_tenant(tenant)
        .register_claim_predicate_schema(
            request.predicate,
            request.subject_type,
            request.object_type,
            request.allowed_claim_kinds,
        )
        .await
    {
        Ok(schema_id) => {
            (StatusCode::CREATED, Json(SchemaIdResponse { schema_id })).into_response()
        }
        Err(error) => error_response(
            StatusCode::BAD_REQUEST,
            format!("failed to register claim predicate schema: {error}"),
        ),
    }
}

async fn register_action_schema(
    State(state): State<SchemaHttpState>,
    headers: HeaderMap,
    Json(request): Json<RegisterActionSchemaRequest>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    match state
        .runtime
        .schema_admin()
        .for_tenant(tenant)
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

async fn register_policy_condition_schema(
    State(state): State<SchemaHttpState>,
    headers: HeaderMap,
    Json(request): Json<RegisterPolicyConditionSchemaRequest>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    match state
        .runtime
        .schema_admin()
        .for_tenant(tenant)
        .register_policy_condition_schema(request.policy_kind, request.fields)
        .await
    {
        Ok(schema_id) => {
            (StatusCode::CREATED, Json(SchemaIdResponse { schema_id })).into_response()
        }
        Err(error) => error_response(
            StatusCode::BAD_REQUEST,
            format!("failed to register policy condition schema: {error}"),
        ),
    }
}

// === Lifecycle handlers ===

async fn disable_schema(
    State(state): State<SchemaHttpState>,
    headers: HeaderMap,
    Path(schema_id): Path<String>,
    Json(request): Json<SchemaLifecycleRequest>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let schema_id = SchemaId::from_str(&schema_id);
    match state
        .runtime
        .schema_admin()
        .for_tenant(tenant)
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

async fn archive_schema(
    State(state): State<SchemaHttpState>,
    headers: HeaderMap,
    Path(schema_id): Path<String>,
    Json(request): Json<SchemaLifecycleRequest>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(tenant) => tenant,
        Err(error) => return tenant_error_response(error),
    };
    let schema_id = SchemaId::from_str(&schema_id);
    match state
        .runtime
        .schema_admin()
        .for_tenant(tenant)
        .archive_schema(schema_id, request.reason)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(
            StatusCode::BAD_REQUEST,
            format!("failed to archive schema: {error}"),
        ),
    }
}

// === Validate handlers ===

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

async fn validate_evidence(
    State(state): State<SchemaHttpState>,
    Json(request): Json<ValidateEvidenceRequest>,
) -> Response {
    let report = state
        .runtime
        .schema()
        .validate_evidence(&request.evidence)
        .await;
    Json(ValidationResponse::from(report)).into_response()
}

async fn validate_claim(
    State(state): State<SchemaHttpState>,
    Json(request): Json<ValidateClaimRequest>,
) -> Response {
    let report = state.runtime.schema().validate_claim(&request.claim).await;
    Json(ValidationResponse::from(report)).into_response()
}

async fn validate_policy(
    State(state): State<SchemaHttpState>,
    Json(request): Json<ValidatePolicyRequest>,
) -> Response {
    let report = state
        .runtime
        .schema()
        .validate_policy_condition(&request.policy)
        .await;
    Json(ValidationResponse::from(report)).into_response()
}

async fn validate_node_create(
    State(state): State<SchemaHttpState>,
    Json(request): Json<ValidateNodeCreateRequest>,
) -> Response {
    let report = state
        .runtime
        .schema()
        .validate_node_create(&request.type_id, &request.properties)
        .await;
    Json(ValidationResponse::from(report)).into_response()
}

async fn validate_node_update(
    State(state): State<SchemaHttpState>,
    Json(request): Json<ValidateNodeUpdateRequest>,
) -> Response {
    let report = state
        .runtime
        .schema()
        .validate_node_update(&request.type_id, &request.changes)
        .await;
    Json(ValidationResponse::from(report)).into_response()
}

async fn validate_edge_create(
    State(state): State<SchemaHttpState>,
    Json(request): Json<ValidateEdgeCreateRequest>,
) -> Response {
    let report = state
        .runtime
        .schema()
        .validate_edge_create(&request.type_id, &request.properties)
        .await;
    Json(ValidationResponse::from(report)).into_response()
}

/// Validate an edge update. Returns 404 when the engine cannot find
/// the edge (`Hydra::validate_edge_update` returns `None`); otherwise
/// returns the validation report.
async fn validate_edge_update(
    State(state): State<SchemaHttpState>,
    Json(request): Json<ValidateEdgeUpdateRequest>,
) -> Response {
    match state
        .runtime
        .schema()
        .validate_edge_update(&request.edge_id, &request.changes)
        .await
    {
        Some(report) => Json(ValidationResponse::from(report)).into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("edge not found: {}", request.edge_id),
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

    const TEST_TENANT: &str = "tenant_schema_http_test";

    fn request_json<T: Serialize>(method: Method, uri: &str, body: &T) -> Request<Body> {
        // GET requests don't need the tenant header (no enforcement on
        // reads in Tenant v0 Patch 1), but adding it on every test
        // request keeps the helper uniform and matches the SDK
        // contract of always sending it.
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("X-Hydra-Tenant", TEST_TENANT)
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    fn request_json_without_tenant<T: Serialize>(
        method: Method,
        uri: &str,
        body: &T,
    ) -> Request<Body> {
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
        let decoded: SchemasResponse = serde_json::from_slice(&body).unwrap();
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
        let decoded: SchemasResponse = serde_json::from_slice(&body).unwrap();
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
        let request = SchemaLifecycleRequest {
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

    // === Read-route tests ===

    #[tokio::test]
    async fn get_disabled_schemas_returns_one_after_disable() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let schema_id = runtime
            .schema_admin()
            .register_action_payload_schema(
                "PostLedgerEntry",
                vec![FieldSchema::required("amount", ValueType::Float)],
            )
            .await
            .unwrap();
        runtime
            .schema_admin()
            .disable_schema(schema_id, None)
            .await
            .unwrap();
        let app = schema_router(runtime);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/schemas/disabled")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body_bytes(response).await;
        let decoded: SchemasResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(decoded.schemas.len(), 1);
    }

    #[tokio::test]
    async fn get_action_schema_by_kind_returns_schema() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        runtime
            .schema_admin()
            .register_action_payload_schema(
                "PostLedgerEntry",
                vec![FieldSchema::required("amount", ValueType::Float)],
            )
            .await
            .unwrap();
        let app = schema_router(runtime);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/schemas/action/PostLedgerEntry")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_entity_schema_returns_schema() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        runtime
            .schema_admin()
            .register_entity_schema(
                TypeId::from_str("type_invoice"),
                "Invoice",
                vec![
                    FieldSchema::required("invoice_number", ValueType::String),
                    FieldSchema::required("amount", ValueType::Float),
                ],
            )
            .await
            .unwrap();
        let app = schema_router(runtime);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/schemas/entity/type_invoice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_missing_schema_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = schema_router(runtime);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/schemas/entity/type_does_not_exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // === Register-route tests ===

    #[tokio::test]
    async fn post_entity_schema_registers_schema() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = schema_router(runtime.clone());
        let request = RegisterEntitySchemaRequest {
            type_id: TypeId::from_str("type_invoice"),
            name: "Invoice".to_string(),
            fields: vec![FieldSchema::required("invoice_number", ValueType::String)],
        };
        let response = app
            .oneshot(request_json(Method::POST, "/schemas/entity", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(runtime
            .schema()
            .entity_schema(&TypeId::from_str("type_invoice"))
            .await
            .is_some());
    }

    #[tokio::test]
    async fn post_evidence_schema_registers_schema() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = schema_router(runtime.clone());
        let request = RegisterEvidenceSchemaRequest {
            kind: "bank_transaction".to_string(),
            fields: vec![
                FieldSchema::required("amount", ValueType::Float),
                FieldSchema::required("currency", ValueType::String),
            ],
        };
        let response = app
            .oneshot(request_json(Method::POST, "/schemas/evidence", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(runtime
            .schema()
            .evidence_schema("bank_transaction")
            .await
            .is_some());
    }

    #[tokio::test]
    async fn post_claim_predicate_schema_registers_schema() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = schema_router(runtime.clone());
        let request = RegisterClaimPredicateSchemaRequest {
            predicate: "is_stale".to_string(),
            subject_type: Some(TypeId::from_str("type_dataset")),
            object_type: ValueType::Bool,
            allowed_claim_kinds: vec!["AnomalyFinding".to_string()],
        };
        let response = app
            .oneshot(request_json(
                Method::POST,
                "/schemas/claim-predicate",
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(runtime
            .schema()
            .claim_predicate_schema("is_stale")
            .await
            .is_some());
    }

    #[tokio::test]
    async fn post_policy_condition_schema_registers_schema() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = schema_router(runtime.clone());
        let request = RegisterPolicyConditionSchemaRequest {
            policy_kind: "AutoApproval".to_string(),
            fields: vec![FieldSchema::required("max_amount", ValueType::Float)],
        };
        let response = app
            .oneshot(request_json(
                Method::POST,
                "/schemas/policy-condition",
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(runtime
            .schema()
            .policy_condition_schema("AutoApproval")
            .await
            .is_some());
    }

    // === Validate-route tests ===

    #[tokio::test]
    async fn validate_node_create_returns_valid_for_good_payload() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        runtime
            .schema_admin()
            .register_entity_schema(
                TypeId::from_str("type_invoice"),
                "Invoice",
                vec![
                    FieldSchema::required("invoice_number", ValueType::String),
                    FieldSchema::required("amount", ValueType::Float),
                ],
            )
            .await
            .unwrap();
        let app = schema_router(runtime);
        let mut properties = HashMap::new();
        properties.insert(
            "invoice_number".to_string(),
            Value::String("INV-001".to_string()),
        );
        properties.insert("amount".to_string(), Value::Float(100.0));
        let request = ValidateNodeCreateRequest {
            type_id: TypeId::from_str("type_invoice"),
            properties,
        };
        let response = app
            .oneshot(request_json(
                Method::POST,
                "/schemas/validate/node-create",
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body_bytes(response).await;
        let decoded: ValidationResponse = serde_json::from_slice(&body).unwrap();
        assert!(decoded.valid);
        assert!(decoded.schema_id.is_some());
    }

    #[tokio::test]
    async fn validate_node_update_reports_unknown_field() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        runtime
            .schema_admin()
            .register_entity_schema(
                TypeId::from_str("type_invoice"),
                "Invoice",
                vec![
                    FieldSchema::required("invoice_number", ValueType::String),
                    FieldSchema::required("amount", ValueType::Float),
                ],
            )
            .await
            .unwrap();
        let app = schema_router(runtime);
        let mut changes = HashMap::new();
        changes.insert("unknown".to_string(), Value::String("x".to_string()));
        let request = ValidateNodeUpdateRequest {
            type_id: TypeId::from_str("type_invoice"),
            changes,
        };
        let response = app
            .oneshot(request_json(
                Method::POST,
                "/schemas/validate/node-update",
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body_bytes(response).await;
        let decoded: ValidationResponse = serde_json::from_slice(&body).unwrap();
        assert!(!decoded.valid);
        assert_eq!(decoded.errors[0].path, "unknown");
    }

    #[tokio::test]
    async fn validate_policy_reports_missing_max_amount() {
        use hydra_core::{PolicyId, PolicyKind, PolicyScope, PolicyStatus};
        let (runtime, _processor) = RuntimeBuilder::new().build();
        runtime
            .schema_admin()
            .register_policy_condition_schema(
                "AutoApproval",
                vec![FieldSchema::required("max_amount", ValueType::Float)],
            )
            .await
            .unwrap();
        let app = schema_router(runtime);
        let now = chrono::Utc::now();
        let policy = Policy {
            id: PolicyId::new(),
            tenant_id: None,
            name: "missing condition".to_string(),
            kind: PolicyKind::AutoApproval,
            status: PolicyStatus::Active,
            scope: PolicyScope::AnyAction,
            condition: HashMap::new(),
            metadata: HashMap::new(),
            created_by: actor(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        let request = ValidatePolicyRequest { policy };
        let response = app
            .oneshot(request_json(
                Method::POST,
                "/schemas/validate/policy",
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body_bytes(response).await;
        let decoded: ValidationResponse = serde_json::from_slice(&body).unwrap();
        assert!(!decoded.valid);
        assert_eq!(decoded.errors[0].path, "max_amount");
    }

    // === Lifecycle-route tests ===

    #[tokio::test]
    async fn post_archive_schema_moves_schema_to_archived() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let schema_id = runtime
            .schema_admin()
            .register_action_payload_schema(
                "PostLedgerEntry",
                vec![FieldSchema::required("amount", ValueType::Float)],
            )
            .await
            .unwrap();
        let app = schema_router(runtime.clone());
        let request = SchemaLifecycleRequest {
            reason: Some("end of life".to_string()),
        };
        let response = app
            .oneshot(request_json(
                Method::POST,
                &format!("/schemas/{schema_id}/archive"),
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(runtime.schema().active_schemas().await.len(), 0);
        assert_eq!(runtime.schema().archived_schemas().await.len(), 1);
    }

    // === Tenant v0 patch 1 ===

    #[tokio::test]
    async fn post_entity_schema_without_tenant_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = schema_router(runtime);
        let request = RegisterEntitySchemaRequest {
            type_id: TypeId::from_str("Account"),
            name: "Account".to_string(),
            fields: vec![FieldSchema::required("id", ValueType::String)],
        };
        let response = app
            .oneshot(request_json_without_tenant(
                Method::POST,
                "/schemas/entity",
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn registered_schema_carries_tenant_id() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = schema_router(runtime.clone());
        let request = RegisterEntitySchemaRequest {
            type_id: TypeId::from_str("Customer"),
            name: "Customer".to_string(),
            fields: vec![FieldSchema::required("id", ValueType::String)],
        };
        let response = app
            .oneshot(request_json(Method::POST, "/schemas/entity", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // The schema registry should hold the schema with the tenant_id
        // we supplied — verify via the underlying schema service.
        let schemas = runtime.schema().active_schemas().await;
        let schema = schemas
            .iter()
            .find(|s| matches!(s, SchemaDefinition::EntityType(_)))
            .expect("registered entity schema must exist");
        assert_eq!(
            schema.tenant_id().map(|t| t.to_string()),
            Some(TEST_TENANT.to_string()),
        );
    }

    // === Edge Gating Patch 2 ===

    fn edge_schema_fields() -> Vec<FieldSchema> {
        vec![
            FieldSchema::required("dependency_type", ValueType::String),
            FieldSchema::optional("confidence", ValueType::Float),
        ]
    }

    #[tokio::test]
    async fn register_edge_schema_http_round_trip() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = schema_router(runtime.clone());
        let request = RegisterEdgeSchemaRequest {
            type_id: TypeId::from_str("edge_depends_on"),
            name: "DependsOn".to_string(),
            fields: edge_schema_fields(),
        };
        let response = app
            .oneshot(request_json(Method::POST, "/schemas/edge", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = read_body_bytes(response).await;
        let decoded: SchemaIdResponse = serde_json::from_slice(&body).unwrap();
        // Schema must be in the edge index after registration.
        let stored = runtime
            .schema()
            .edge_schema(&TypeId::from_str("edge_depends_on"))
            .await
            .expect("edge schema must exist");
        assert_eq!(stored.id, decoded.schema_id);
        assert_eq!(stored.name, "DependsOn");
    }

    #[tokio::test]
    async fn register_edge_schema_without_tenant_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = schema_router(runtime);
        let request = RegisterEdgeSchemaRequest {
            type_id: TypeId::from_str("edge_x"),
            name: "X".to_string(),
            fields: edge_schema_fields(),
        };
        let response = app
            .oneshot(request_json_without_tenant(
                Method::POST,
                "/schemas/edge",
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_edge_schema_by_type_id() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        runtime
            .schema_admin()
            .register_edge_schema(
                TypeId::from_str("edge_depends_on"),
                "DependsOn",
                edge_schema_fields(),
            )
            .await
            .unwrap();
        let app = schema_router(runtime);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/schemas/edge/edge_depends_on")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_edge_schema_missing_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = schema_router(runtime);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/schemas/edge/edge_does_not_exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn validate_edge_create_returns_valid_for_good_payload() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        runtime
            .schema_admin()
            .register_edge_schema(
                TypeId::from_str("edge_depends_on"),
                "DependsOn",
                edge_schema_fields(),
            )
            .await
            .unwrap();
        let app = schema_router(runtime);
        let mut properties = HashMap::new();
        properties.insert(
            "dependency_type".to_string(),
            Value::String("hard".to_string()),
        );
        let request = ValidateEdgeCreateRequest {
            type_id: TypeId::from_str("edge_depends_on"),
            properties,
        };
        let response = app
            .oneshot(request_json(
                Method::POST,
                "/schemas/validate/edge-create",
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body_bytes(response).await;
        let decoded: ValidationResponse = serde_json::from_slice(&body).unwrap();
        assert!(decoded.valid);
        assert!(decoded.schema_id.is_some());
    }

    #[tokio::test]
    async fn validate_edge_create_invalid_missing_required() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        runtime
            .schema_admin()
            .register_edge_schema(
                TypeId::from_str("edge_depends_on"),
                "DependsOn",
                edge_schema_fields(),
            )
            .await
            .unwrap();
        let app = schema_router(runtime);
        let request = ValidateEdgeCreateRequest {
            type_id: TypeId::from_str("edge_depends_on"),
            properties: HashMap::new(), // missing required dependency_type
        };
        let response = app
            .oneshot(request_json(
                Method::POST,
                "/schemas/validate/edge-create",
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body_bytes(response).await;
        let decoded: ValidationResponse = serde_json::from_slice(&body).unwrap();
        assert!(!decoded.valid);
        assert_eq!(decoded.errors[0].path, "dependency_type");
    }

    #[tokio::test]
    async fn validate_edge_update_invalid_unknown_field() {
        // First ingest a real edge so validate_edge_update can resolve
        // it via the projection (the engine returns None for missing
        // edges — that's the 404 path).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        runtime
            .schema_admin()
            .register_edge_schema(
                TypeId::from_str("edge_depends_on"),
                "DependsOn",
                edge_schema_fields(),
            )
            .await
            .unwrap();
        let edge_id = hydra_core::EdgeId::new();
        {
            use hydra_core::{EventKind, NodeId};
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let source = NodeId::new();
            let target = NodeId::new();
            hydra
                .ingest(EventKind::NodeCreated {
                    node_id: source.clone(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
            hydra
                .ingest(EventKind::NodeCreated {
                    node_id: target.clone(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
            let mut props = HashMap::new();
            props.insert(
                "dependency_type".to_string(),
                Value::String("hard".to_string()),
            );
            hydra
                .ingest(EventKind::EdgeCreated {
                    edge_id: edge_id.clone(),
                    source,
                    target,
                    type_id: "edge_depends_on".to_string(),
                    properties: props,
                })
                .unwrap();
        }
        let app = schema_router(runtime);
        let mut changes = HashMap::new();
        changes.insert("bogus".to_string(), Value::String("x".to_string()));
        let request = ValidateEdgeUpdateRequest {
            edge_id: edge_id.clone(),
            changes,
        };
        let response = app
            .oneshot(request_json(
                Method::POST,
                "/schemas/validate/edge-update",
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body_bytes(response).await;
        let decoded: ValidationResponse = serde_json::from_slice(&body).unwrap();
        assert!(!decoded.valid);
        assert_eq!(decoded.errors[0].path, "bogus");
    }

    #[tokio::test]
    async fn validate_edge_update_missing_edge_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = schema_router(runtime);
        let request = ValidateEdgeUpdateRequest {
            edge_id: hydra_core::EdgeId::new(),
            changes: HashMap::new(),
        };
        let response = app
            .oneshot(request_json(
                Method::POST,
                "/schemas/validate/edge-update",
                &request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
