//! # HTTP Server
//!
//! Axum server with all routes, CORS, security middleware.

use crate::auth::{auth_middleware, AuthConfig, AuthState};
use crate::routes;
use crate::state::AppState;
use axum::http::{header, HeaderValue, Method};
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use hydra_core::ActorId;
use hydra_net::http::{
    commits_router, events_router, ingest_router, query_router, schema_router, sensor_router,
    snapshots_router,
};
use hydra_net::runtime::{RuntimeBuilder, RuntimeHandle};
use hydra_sdk::HydraRuntime;
use std::path::Path;
use tower_http::cors::CorsLayer;

/// Shared CORS policy used by every hydra-api router build.
fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_origin("*".parse::<HeaderValue>().unwrap())
        .max_age(std::time::Duration::from_secs(3600))
}

/// Legacy CloudTrail/Sentinel routes, parameterised by the shared
/// `AppState`. Kept as a separate builder so the unified `build_router`
/// can `.merge(...)` it alongside the schema routes.
fn legacy_routes(state: AppState) -> Router {
    Router::new()
        // Health & Stats
        .route("/health", get(routes::health))
        .route("/stats", get(routes::stats))
        .route("/metrics", get(routes::metrics))
        // Graph queries
        .route("/nodes", get(routes::list_nodes))
        .route("/nodes/:id", get(routes::get_node))
        // Sentinel queries
        .route("/blast-radius/:node_id", get(routes::blast_radius))
        .route("/protection-status", get(routes::protection_status))
        .route("/compliance-gaps", get(routes::compliance_gaps))
        .route("/confidence-report", get(routes::confidence_report))
        .route("/recovery-plan/:node_id", get(routes::recovery_plan))
        // Ingestion
        .route("/sensor/cloudtrail", post(routes::ingest_cloudtrail))
        .with_state(state)
}

/// Build the unified Axum router exposing every hydra-api endpoint:
/// legacy CloudTrail/Sentinel routes **and** the `/schemas/*` surface from
/// `hydra-net`. Both layers share the same [`RuntimeHandle`], which means
/// CloudTrail ingestion writes are immediately visible to schema reads
/// and vice versa.
pub fn build_router(runtime: RuntimeHandle) -> Router {
    build_router_with_auth(runtime, AuthConfig::off())
}

/// Build the unified Axum router with optional bearer-token authentication.
///
/// `AuthConfig::off()` preserves the existing public-by-default behavior.
/// `AuthConfig::require_for_mutations(tokens)` gates POST/PUT/PATCH/DELETE.
/// `AuthConfig::require_for_all(tokens)` gates everything except OPTIONS.
///
/// Auth is layered AFTER CORS so the auth check runs first on inbound
/// requests; rejected requests never reach the route handlers.
pub fn build_router_with_auth(runtime: RuntimeHandle, auth: AuthConfig) -> Router {
    let state = AppState::new(runtime.clone());
    let app = legacy_routes(state)
        .merge(schema_router(runtime.clone()))
        .merge(ingest_router(runtime.clone()))
        .merge(sensor_router(runtime.clone()))
        .merge(commits_router(runtime.clone()))
        .merge(events_router(runtime.clone()))
        .merge(query_router(runtime.clone()))
        .merge(snapshots_router(runtime))
        .layer(cors_layer());
    if auth.is_enabled() {
        app.layer(middleware::from_fn_with_state(
            AuthState::new(auth),
            auth_middleware,
        ))
    } else {
        app
    }
}

/// Start the HTTP server on the given address (no auth).
pub async fn serve(
    runtime: RuntimeHandle,
    addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    serve_with_auth(runtime, addr, AuthConfig::off()).await
}

/// Start the HTTP server on the given address with the supplied auth
/// configuration.
pub async fn serve_with_auth(
    runtime: RuntimeHandle,
    addr: &str,
    auth: AuthConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let router = build_router_with_auth(runtime, auth);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

/// Build a router exposing only the schema HTTP surface
/// (introspection + preflight validation + register/disable/archive).
///
/// Convenience for schema-only deployments that don't want the legacy
/// CloudTrail/Sentinel routes mounted.
pub fn build_schema_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .merge(schema_router(runtime))
        .layer(cors_layer())
}

/// Start an HTTP server exposing only the schema routes.
pub async fn serve_schema(
    runtime: RuntimeHandle,
    addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let router = build_schema_router(runtime);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

/// Build a fully persistent router: recovers `Hydra` from disk at `root`,
/// wraps it in a `RuntimeHandle`, and composes the unified router. Both
/// the commit log and snapshot backend are attached so subsequent writes
/// and snapshots persist automatically.
///
/// No auth (matches `build_router`). Use
/// [`build_persistent_router_with_auth`] for gated deployments.
pub fn build_persistent_router(
    root: impl AsRef<Path>,
    actor: ActorId,
) -> hydra_core::error::Result<Router> {
    build_persistent_router_with_auth(root, actor, AuthConfig::off())
}

/// Build a fully persistent router with the supplied auth configuration.
///
/// Bootstrap order:
/// 1. `HydraRuntime::open_persistent(root, actor)` — opens commit log +
///    snapshot store, recovers, attaches both backends.
/// 2. `RuntimeBuilder::from_hydra(hydra).build()` — wraps the recovered
///    Hydra in a `RuntimeHandle`.
/// 3. `build_router_with_auth(runtime, auth)` — composes legacy + schema
///    + ingest + sensor + commits + events + snapshots routers, layers
///    CORS, and (if `auth.is_enabled()`) layers the auth middleware.
pub fn build_persistent_router_with_auth(
    root: impl AsRef<Path>,
    actor: ActorId,
    auth: AuthConfig,
) -> hydra_core::error::Result<Router> {
    let (hydra, _report) = HydraRuntime::open_persistent(root, actor)?;
    let (runtime, _processor) = RuntimeBuilder::from_hydra(hydra).build();
    Ok(build_router_with_auth(runtime, auth))
}

/// Start a persistent HTTP server on the given address (no auth).
pub async fn serve_persistent(
    root: impl AsRef<Path>,
    addr: &str,
    actor: ActorId,
) -> Result<(), Box<dyn std::error::Error>> {
    serve_persistent_with_auth(root, addr, actor, AuthConfig::off()).await
}

/// Start a persistent HTTP server with the supplied auth configuration.
///
/// This is the one-call production startup:
/// recovers `Hydra` from `<root>/commits.jsonl` + `<root>/snapshots/`,
/// wraps it in a runtime, and serves the full route surface on `addr`.
/// Logs the recovery mode + commit counts to stderr at startup.
pub async fn serve_persistent_with_auth(
    root: impl AsRef<Path>,
    addr: &str,
    actor: ActorId,
    auth: AuthConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let (hydra, report) = HydraRuntime::open_persistent(root, actor)?;
    eprintln!(
        "hydra persistent recovery: mode={:?} commits_loaded={} replayed={}",
        report.mode, report.total_commits_loaded, report.replayed_commit_count,
    );
    let (runtime, _processor) = RuntimeBuilder::from_hydra(hydra).build();
    let router = build_router_with_auth(runtime, auth);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use hydra_engine::prelude::*;
    use tower::ServiceExt;

    fn test_runtime() -> hydra_net::runtime::RuntimeHandle {
        let (runtime, _processor) = hydra_net::runtime::RuntimeBuilder::new().build();
        runtime
    }

    #[tokio::test]
    async fn health_endpoint() {
        let app = build_router(test_runtime());
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn stats_endpoint() {
        let app = build_router(test_runtime());
        let req = Request::builder()
            .uri("/stats")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn node_not_found() {
        let app = build_router(test_runtime());
        let req = Request::builder()
            .uri("/nodes/nonexistent")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_nodes_empty() {
        let app = build_router(test_runtime());
        let req = Request::builder()
            .uri("/nodes")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protection_status_empty() {
        let app = build_router(test_runtime());
        let req = Request::builder()
            .uri("/protection-status")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_endpoint() {
        let app = build_router(test_runtime());
        let req = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // === Schema HTTP route mounting ===
    //
    // These tests prove `/schemas/*` is reachable through hydra-api's
    // server scaffold. The schema router is built from a hydra-net
    // RuntimeHandle, so it owns a different engine than the legacy
    // AppState path — see build_schema_router doc.

    fn schema_test_app() -> (Router, hydra_net::runtime::RuntimeHandle) {
        use hydra_net::runtime::RuntimeBuilder;
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = build_schema_router(runtime.clone());
        (app, runtime)
    }

    #[tokio::test]
    async fn schema_active_endpoint_is_empty_initially() {
        use hydra_net::http::schema::SchemasResponse;
        let (app, _runtime) = schema_test_app();
        let req = Request::builder()
            .method("GET")
            .uri("/schemas/active")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let decoded: SchemasResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(decoded.schemas.len(), 0);
    }

    #[tokio::test]
    async fn schema_register_action_then_list() {
        use hydra_core::{FieldSchema, ValueType};
        use hydra_net::http::schema::{
            RegisterActionSchemaRequest, SchemaIdResponse, SchemasResponse,
        };
        let (app, _runtime) = schema_test_app();

        let register = RegisterActionSchemaRequest {
            action_kind: "PostLedgerEntry".to_string(),
            fields: vec![
                FieldSchema::required("account", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
            ],
        };
        let register_req = Request::builder()
            .method("POST")
            .uri("/schemas/action")
            .header("content-type", "application/json")
            .header("X-Hydra-Tenant", "tenant_api_test")
            .body(Body::from(serde_json::to_vec(&register).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(register_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let registered: SchemaIdResponse = serde_json::from_slice(&body).unwrap();
        assert!(!registered.schema_id.to_string().is_empty());

        let list_req = Request::builder()
            .method("GET")
            .uri("/schemas/active")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(list_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let listed: SchemasResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(listed.schemas.len(), 1);
    }

    #[tokio::test]
    async fn schema_validate_action_route_is_mounted() {
        use hydra_core::{
            Action, ActionId, ActionKind, ActionStatus, ActionTarget, ActorId, FieldSchema,
            Value, ValueType,
        };
        use hydra_net::http::schema::{
            RegisterActionSchemaRequest, ValidateActionRequest, ValidationResponse,
        };
        let (app, _runtime) = schema_test_app();

        // Register the schema first.
        let register = RegisterActionSchemaRequest {
            action_kind: "PostLedgerEntry".to_string(),
            fields: vec![
                FieldSchema::required("account", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
            ],
        };
        let req = Request::builder()
            .method("POST")
            .uri("/schemas/action")
            .header("content-type", "application/json")
            .header("X-Hydra-Tenant", "tenant_api_test")
            .body(Body::from(serde_json::to_vec(&register).unwrap()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::CREATED
        );

        // Build a bad action and POST to validate route.
        let now = chrono::Utc::now();
        let mut payload = std::collections::HashMap::new();
        payload.insert("account".to_string(), Value::String("Cash".to_string()));
        payload.insert("amount".to_string(), Value::String("bad".to_string()));
        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::PostLedgerEntry,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("ledger".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_api_schema_test"),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };
        let validate = ValidateActionRequest { action };
        let req = Request::builder()
            .method("POST")
            .uri("/schemas/validate/action")
            .header("content-type", "application/json")
            .header("X-Hydra-Tenant", "tenant_api_test")
            .body(Body::from(serde_json::to_vec(&validate).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let decoded: ValidationResponse = serde_json::from_slice(&body).unwrap();
        assert!(!decoded.valid);
        assert_eq!(decoded.errors[0].path, "amount");
    }

    #[tokio::test]
    async fn ingest_cloudtrail_and_query() {
        use hydra_core::subscription::{EventFilter, Subscription};
        use hydra_net::runtime::RuntimeBuilder;
        use hydra_sentinel::arms::*;

        // Build a runtime with the full Sentinel arm pipeline registered as
        // subscriptions. RuntimeBuilder owns Hydra construction now.
        let (runtime, _processor) = RuntimeBuilder::new()
            .cascade_config(CascadeConfig {
                max_depth: 15,
                max_events: 200,
            })
            .subscription(Subscription::new(
                "discovery",
                EventFilter::Or(vec![
                    EventFilter::SignalName("resource_discovered".into()),
                    EventFilter::SignalName("resource_deleted".into()),
                ]),
                200,
                Box::new(DiscoveryArm::new()),
            ))
            .subscription(Subscription::new(
                "classification",
                EventFilter::Or(vec![EventFilter::NodeCreated]),
                190,
                Box::new(ClassificationArm::with_defaults()),
            ))
            .subscription(Subscription::new(
                "policy",
                EventFilter::NodeUpdated,
                180,
                Box::new(PolicyArm::new()),
            ))
            .subscription(Subscription::new(
                "execution",
                EventFilter::Or(vec![EventFilter::SignalName("policy_computed".into())]),
                170,
                Box::new(ExecutionArm::new()),
            ))
            .subscription(Subscription::new(
                "verification",
                EventFilter::SignalName("backup_completed".into()),
                160,
                Box::new(VerificationArm::new()),
            ))
            .subscription(Subscription::new(
                "trust",
                EventFilter::Or(vec![
                    EventFilter::SignalName("trust_penalty".into()),
                    EventFilter::NodeUpdated,
                    EventFilter::EdgeCreated,
                ]),
                100,
                Box::new(TrustArm::new()),
            ))
            .build();

        let app = build_router(runtime.clone());

        // POST CloudTrail event
        let cloudtrail = r#"{"Records": [{
            "eventSource": "rds.amazonaws.com",
            "eventName": "CreateDBInstance",
            "awsRegion": "us-east-1",
            "eventID": "evt-api-test-001",
            "requestParameters": {"dBInstanceIdentifier": "api-test-db"},
            "responseElements": {
                "dBInstanceIdentifier": "api-test-db",
                "engine": "postgres"
            }
        }]}"#;

        let req = Request::builder()
            .method("POST")
            .uri("/sensor/cloudtrail")
            .header("content-type", "application/json")
            .header("X-Hydra-Tenant", "tenant_api_test")
            .body(Body::from(cloudtrail))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // GET the node
        let app = build_router(runtime.clone());
        let req = Request::builder()
            .uri("/nodes/api-test-db")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // GET protection status
        let app = build_router(runtime.clone());
        let req = Request::builder()
            .uri("/protection-status")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // GET blast radius
        let app = build_router(runtime.clone());
        let req = Request::builder()
            .uri("/blast-radius/api-test-db")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Unification test: the legacy `/stats` endpoint and the new
    /// `/schemas/active` endpoint share a single `Hydra` instance via the
    /// same `RuntimeHandle`. A schema registered through `/schemas/action`
    /// is visible to the legacy route's `state.runtime.hydra().read().await`
    /// path because both sides hold the same `Arc<RwLock<Hydra>>`.
    #[tokio::test]
    async fn legacy_and_schema_routes_share_one_runtime() {
        use hydra_core::{FieldSchema, ValueType};
        use hydra_net::http::schema::{
            RegisterActionSchemaRequest, SchemasResponse,
        };

        let runtime = test_runtime();
        let app = build_router(runtime.clone());

        // Register a schema via /schemas/action
        let register = RegisterActionSchemaRequest {
            action_kind: "PostLedgerEntry".to_string(),
            fields: vec![
                FieldSchema::required("account", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
            ],
        };
        let req = Request::builder()
            .method("POST")
            .uri("/schemas/action")
            .header("content-type", "application/json")
            .header("X-Hydra-Tenant", "tenant_api_test")
            .body(Body::from(serde_json::to_vec(&register).unwrap()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::CREATED
        );

        // The same RuntimeHandle that backs every legacy route sees it
        // immediately.
        assert!(runtime
            .schema()
            .action_payload_schema("PostLedgerEntry")
            .await
            .is_some());

        // /schemas/active over the unified router sees it.
        let req = Request::builder()
            .method("GET")
            .uri("/schemas/active")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let decoded: SchemasResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(decoded.schemas.len(), 1);

        // Legacy route still works against the same runtime.
        let req = Request::builder()
            .method("GET")
            .uri("/stats")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_ingest_route_is_mounted_and_idempotent() {
        use hydra_core::{EventKind, NodeId};
        use hydra_net::http::ingest::{IngestRequest, IngestResponse};
        use std::collections::HashMap;

        let runtime = test_runtime();
        let app = build_router(runtime.clone());

        let request = IngestRequest {
            event_kind: EventKind::Signal {
                source: NodeId::from_str("test.api"),
                name: "api_ingest".to_string(),
                payload: HashMap::new(),
            },
        };

        let http_request = Request::builder()
            .method("POST")
            .uri("/ingest")
            .header("content-type", "application/json")
            .header("X-Hydra-Tenant", "tenant_api_test")
            .header("Idempotency-Key", "api-ingest-1")
            .body(Body::from(serde_json::to_vec(&request).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(http_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let first: IngestResponse = serde_json::from_slice(&body).unwrap();
        assert!(!first.idempotent_hit);
        assert_eq!(runtime.hydra().read().await.commit_count(), 1);

        let duplicate = Request::builder()
            .method("POST")
            .uri("/ingest")
            .header("content-type", "application/json")
            .header("X-Hydra-Tenant", "tenant_api_test")
            .header("Idempotency-Key", "api-ingest-1")
            .body(Body::from(serde_json::to_vec(&request).unwrap()))
            .unwrap();
        let response = app.oneshot(duplicate).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let second: IngestResponse = serde_json::from_slice(&body).unwrap();
        assert!(second.idempotent_hit);
        assert_eq!(runtime.hydra().read().await.commit_count(), 1);
        assert_eq!(second.event_ids, first.event_ids);
    }

    /// Schema gate failures surface over the public /ingest route — proves
    /// schema preflight (POST /schemas/validate/*) and ingest enforcement
    /// (POST /ingest) talk to the same engine and use the same gate.
    #[tokio::test]
    async fn api_ingest_strict_schema_gate_rejection_returns_400() {
        use hydra_core::{
            Action, ActionId, ActionKind, ActionPayloadSchema, ActionStatus, ActionTarget,
            ActorId, EventKind, FieldSchema, SchemaDefinition, SchemaId, SchemaStatus, Value,
            ValueType,
        };
        use hydra_engine::schema_gate::{
            SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy,
        };
        use hydra_net::http::ingest::IngestRequest;
        use std::collections::HashMap;

        let runtime = test_runtime();

        // Register an action schema and flip strict mode on, all via the
        // RuntimeHandle so the test doesn't depend on POST /schemas/action
        // working in this test.
        {
            let hydra_arc = runtime.hydra();
            let mut hydra = hydra_arc.write().await;
            let now = chrono::Utc::now();
            let schema = ActionPayloadSchema {
                id: SchemaId::new(),
                tenant_id: None,
                action_kind: "PostLedgerEntry".to_string(),
                status: SchemaStatus::Active,
                fields: vec![
                    FieldSchema::required("account", ValueType::String),
                    FieldSchema::required("amount", ValueType::Float),
                ],
                created_by: ActorId::from_str("actor_schema_gate_api_test"),
                created_at: now,
                updated_at: now,
                metadata: HashMap::new(),
            };
            hydra
                .ingest(EventKind::SchemaRegistered {
                    schema: SchemaDefinition::ActionPayload(schema),
                })
                .unwrap();
            hydra.set_schema_gate_config(SchemaGateConfig {
                mode: SchemaGateMode::Strict,
                unknown_schema_policy: UnknownSchemaPolicy::Allow,
            });
        }
        let commit_count_after_schema = runtime.hydra().read().await.commit_count();

        let app = build_router(runtime.clone());

        // Build an ActionProposed event whose payload fails the schema:
        // amount is a String, not a Float.
        let now = chrono::Utc::now();
        let mut payload = HashMap::new();
        payload.insert("account".to_string(), Value::String("Cash".to_string()));
        payload.insert("amount".to_string(), Value::String("bad".to_string()));
        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::PostLedgerEntry,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("ledger".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_ingest_api_test"),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };
        let request = IngestRequest {
            event_kind: EventKind::ActionProposed { action },
        };

        let http_request = Request::builder()
            .method("POST")
            .uri("/ingest")
            .header("content-type", "application/json")
            .header("X-Hydra-Tenant", "tenant_api_test")
            .body(Body::from(serde_json::to_vec(&request).unwrap()))
            .unwrap();
        let response = app.oneshot(http_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // No new commit — strict gate rejected before commit_ledger was
        // touched.
        assert_eq!(
            runtime.hydra().read().await.commit_count(),
            commit_count_after_schema
        );
    }

    #[tokio::test]
    async fn api_sensor_observation_route_is_mounted_and_idempotent() {
        use hydra_core::{EventKind, NodeId, SensorId, SourceCursor};
        use hydra_net::http::sensor::{SensorObservationRequest, SensorObservationResponse};
        use std::collections::HashMap;

        let runtime = test_runtime();
        let app = build_router(runtime.clone());

        let request = SensorObservationRequest {
            sensor_id: SensorId::from_str("sensor_api"),
            source_system: "api-test".to_string(),
            source_cursor: SourceCursor::DeliveryId {
                source: "api-test".to_string(),
                delivery_id: "delivery-1".to_string(),
            },
            event_kind: EventKind::Signal {
                source: NodeId::from_str("api.sensor"),
                name: "observation".to_string(),
                payload: HashMap::new(),
            },
            run_id: None,
        };
        let body = serde_json::to_vec(&request).unwrap();

        let http_request = Request::builder()
            .method("POST")
            .uri("/sensor/observation")
            .header("content-type", "application/json")
            .header("X-Hydra-Tenant", "tenant_api_test")
            .body(Body::from(body.clone()))
            .unwrap();
        let response = app.clone().oneshot(http_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let first: SensorObservationResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!first.idempotent_hit);

        let duplicate = Request::builder()
            .method("POST")
            .uri("/sensor/observation")
            .header("content-type", "application/json")
            .header("X-Hydra-Tenant", "tenant_api_test")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(duplicate).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let second: SensorObservationResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(second.idempotent_hit);
        assert_eq!(second.checkpoint_id, first.checkpoint_id);

        // Business event commit + checkpoint commit. Duplicate adds nothing.
        assert_eq!(runtime.hydra().read().await.commit_count(), 2);
    }

    #[tokio::test]
    async fn api_commits_routes_are_mounted_and_verify_clean_chain() {
        use hydra_core::{EventKind, NodeId};
        use hydra_net::http::commits::{CommitListResponse, VerifyCommitsResponse};
        use std::collections::HashMap;

        let runtime = test_runtime();
        {
            let hydra_arc = runtime.hydra();
            let mut hydra = hydra_arc.write().await;
            hydra
                .ingest(EventKind::Signal {
                    source: NodeId::from_str("api.commits"),
                    name: "commit_test".to_string(),
                    payload: HashMap::new(),
                })
                .unwrap();
        }
        let app = build_router(runtime.clone());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/commits")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list: CommitListResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.commits.len(), 1);
        assert!(!list.commits[0].commit_hash.0.is_empty());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/commits/verify")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let verify: VerifyCommitsResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(verify.valid);
        assert_eq!(verify.total_commits, 1);
    }

    #[tokio::test]
    async fn api_events_routes_are_mounted_and_return_ingested_events() {
        use hydra_core::{EventKind, NodeId};
        use hydra_net::http::events::EventListResponse;
        use std::collections::HashMap;

        let runtime = test_runtime();
        {
            let hydra_arc = runtime.hydra();
            let mut hydra = hydra_arc.write().await;
            hydra
                .ingest(EventKind::Signal {
                    source: NodeId::from_str("api.events"),
                    name: "event_test".to_string(),
                    payload: HashMap::new(),
                })
                .unwrap();
        }
        let app = build_router(runtime);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list: EventListResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.events.len(), 1);
        assert_eq!(list.events[0].kind, "signal");
    }

    #[tokio::test]
    async fn api_snapshots_routes_are_mounted() {
        use hydra_core::ActorId;
        use hydra_net::http::snapshots::{
            CreateSnapshotRequest, SnapshotManifestResponse, SnapshotsListResponse,
        };

        let runtime = test_runtime();
        let app = build_router(runtime.clone());

        let create = CreateSnapshotRequest {
            created_by: ActorId::from_str("actor_api_snapshot"),
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/snapshots")
                    .header("content-type", "application/json")
                    .header("X-Hydra-Tenant", "tenant_api_test")
            .header("X-Hydra-Tenant", "tenant_api_test")
                    .body(Body::from(serde_json::to_vec(&create).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: SnapshotManifestResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(runtime
            .hydra()
            .read()
            .await
            .snapshot_body(&created.manifest.id)
            .is_some());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/snapshots")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list: SnapshotsListResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.snapshots.len(), 1);
    }

    /// End-to-end pipeline test: HTTP POST /snapshots → engine snapshot
    /// → FileSnapshotStore backend → disk. Reopen the same backend at the
    /// same root and confirm the manifest + body survive process restart.
    #[tokio::test]
    async fn api_snapshot_route_writes_to_file_backend() {
        use hydra_core::ActorId;
        use hydra_net::http::snapshots::{CreateSnapshotRequest, SnapshotManifestResponse};
        use hydra_storage::snapshot::FileSnapshotStore;

        let root = std::env::temp_dir().join(format!(
            "hydra_api_snapshot_route_test_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let runtime = test_runtime();
        {
            let hydra_arc = runtime.hydra();
            let mut hydra = hydra_arc.write().await;
            hydra.set_snapshot_backend(FileSnapshotStore::open(&root).unwrap());
        }

        let app = build_router(runtime.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/snapshots")
                    .header("content-type", "application/json")
                    .header("X-Hydra-Tenant", "tenant_api_test")
            .header("X-Hydra-Tenant", "tenant_api_test")
                    .body(Body::from(
                        serde_json::to_vec(&CreateSnapshotRequest {
                            created_by: ActorId::from_str("actor_api_snapshot"),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: SnapshotManifestResponse = serde_json::from_slice(&bytes).unwrap();

        // Reopen the backend at the same root — simulates process restart.
        let reopened = FileSnapshotStore::open(&root).unwrap();
        let manifests = reopened.list_snapshot_manifests().unwrap();
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].id, created.manifest.id);
        let body = reopened.read_snapshot(&created.manifest.id).unwrap();
        assert_eq!(body.manifest.id, created.manifest.id);

        let _ = std::fs::remove_dir_all(&root);
    }

    // === Auth middleware ===

    fn empty_request(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    fn json_request<T: serde::Serialize>(method: &str, uri: &str, body: &T) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("X-Hydra-Tenant", "tenant_api_test")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    fn with_bearer(mut request: Request<Body>, token: &str) -> Request<Body> {
        request.headers_mut().insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        request
    }

    #[tokio::test]
    async fn auth_default_off_does_not_block_routes() {
        let runtime = test_runtime();
        let app = build_router(runtime);
        let response = app
            .oneshot(empty_request("GET", "/health"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_require_for_mutations_allows_get_without_token() {
        let runtime = test_runtime();
        let app = build_router_with_auth(
            runtime,
            AuthConfig::require_for_mutations(["secret-token"]),
        );
        let response = app
            .oneshot(empty_request("GET", "/health"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_require_for_mutations_rejects_post_without_token() {
        use hydra_core::ActorId;
        use hydra_net::http::snapshots::CreateSnapshotRequest;

        let runtime = test_runtime();
        let app = build_router_with_auth(
            runtime,
            AuthConfig::require_for_mutations(["secret-token"]),
        );
        let request = json_request(
            "POST",
            "/snapshots",
            &CreateSnapshotRequest {
                created_by: ActorId::from_str("actor_auth_test"),
            },
        );
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_valid_bearer_token_allows_post() {
        use hydra_core::ActorId;
        use hydra_net::http::snapshots::CreateSnapshotRequest;

        let runtime = test_runtime();
        let app = build_router_with_auth(
            runtime,
            AuthConfig::require_for_mutations(["secret-token"]),
        );
        let request = json_request(
            "POST",
            "/snapshots",
            &CreateSnapshotRequest {
                created_by: ActorId::from_str("actor_auth_test"),
            },
        );
        let response = app
            .oneshot(with_bearer(request, "secret-token"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn auth_invalid_bearer_token_rejects_post() {
        use hydra_core::ActorId;
        use hydra_net::http::snapshots::CreateSnapshotRequest;

        let runtime = test_runtime();
        let app = build_router_with_auth(
            runtime,
            AuthConfig::require_for_mutations(["secret-token"]),
        );
        let request = json_request(
            "POST",
            "/snapshots",
            &CreateSnapshotRequest {
                created_by: ActorId::from_str("actor_auth_test"),
            },
        );
        let response = app
            .oneshot(with_bearer(request, "wrong-token"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_require_for_all_rejects_get_without_token() {
        let runtime = test_runtime();
        let app = build_router_with_auth(
            runtime,
            AuthConfig::require_for_all(["secret-token"]),
        );
        let response = app
            .oneshot(empty_request("GET", "/health"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_require_for_all_allows_options_for_cors_preflight() {
        let runtime = test_runtime();
        let app = build_router_with_auth(
            runtime,
            AuthConfig::require_for_all(["secret-token"]),
        );
        let response = app
            .oneshot(empty_request("OPTIONS", "/health"))
            .await
            .unwrap();
        // OPTIONS must NOT be 401 — the CORS layer below auth handles it.
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // === Persistent server bootstrap ===

    fn persistent_temp_root(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "hydra_api_persistent_{name}_{}_{}",
            std::process::id(),
            chrono::Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
        ))
    }

    #[tokio::test]
    async fn build_persistent_router_starts_from_empty_root() {
        let root = persistent_temp_root("fresh");
        let app = build_persistent_router(
            &root,
            hydra_core::ActorId::from_str("actor_api_persistent"),
        )
        .unwrap();
        let response = app
            .oneshot(empty_request("GET", "/health"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// End-to-end persistence proof: open persistent router, POST an
    /// event with idempotency-key, drop. Reopen at the same root and GET
    /// /events — the event must still be there. Proves the full
    /// HTTP → engine → commit_log → disk → restart → recovery → HTTP
    /// pipeline survives a process restart.
    #[tokio::test]
    async fn persistent_router_recovers_events_after_restart() {
        use hydra_core::{ActorId, EventKind, NodeId};
        use hydra_net::http::events::EventListResponse;
        use hydra_net::http::ingest::IngestRequest;
        use std::collections::HashMap;

        let root = persistent_temp_root("restart");
        let actor = ActorId::from_str("actor_api_persistent");

        // Phase 1: open, POST event, drop router.
        {
            let app = build_persistent_router(&root, actor.clone()).unwrap();
            let request = IngestRequest {
                event_kind: EventKind::Signal {
                    source: NodeId::from_str("api.persistent"),
                    name: "persist_me".to_string(),
                    payload: HashMap::new(),
                },
            };
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/ingest")
                        .header("content-type", "application/json")
                        .header("X-Hydra-Tenant", "tenant_api_test")
                    .header("X-Hydra-Tenant", "tenant_api_test")
            .header("X-Hydra-Tenant", "tenant_api_test")
                        .header("Idempotency-Key", "persistent-test-1")
                        .body(Body::from(serde_json::to_vec(&request).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        // Phase 2: reopen the same root — the event should still be there.
        {
            let app = build_persistent_router(&root, actor).unwrap();
            let response = app
                .oneshot(empty_request("GET", "/events"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let events: EventListResponse = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(events.events.len(), 1);
            assert_eq!(events.events[0].kind, "signal");
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn persistent_router_with_auth_gates_mutations() {
        use hydra_core::{ActorId, EventKind, NodeId};
        use hydra_net::http::ingest::IngestRequest;
        use std::collections::HashMap;

        let root = persistent_temp_root("auth");
        let app = build_persistent_router_with_auth(
            &root,
            ActorId::from_str("actor_api_persistent"),
            AuthConfig::require_for_mutations(["secret"]),
        )
        .unwrap();

        let request = IngestRequest {
            event_kind: EventKind::Signal {
                source: NodeId::from_str("api.persistent"),
                name: "blocked".to_string(),
                payload: HashMap::new(),
            },
        };
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ingest")
                    .header("content-type", "application/json")
                    .header("X-Hydra-Tenant", "tenant_api_test")
            .header("X-Hydra-Tenant", "tenant_api_test")
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn query_router_is_mounted_in_unified_build() {
        // Proves `/query/*` is reachable through `build_router_with_auth`
        // (and therefore through `serve_persistent_with_auth`), and that
        // ingested state is immediately readable via the query surface —
        // i.e. the query router shares the runtime engine, not a separate
        // one.
        use hydra_core::{EventKind, NodeId};
        use hydra_net::http::query::StatsResponse;
        use std::collections::HashMap;

        let runtime = test_runtime();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .ingest_for_tenant(
                    EventKind::NodeCreated {
                        node_id: NodeId::new(),
                        type_id: "ec2".to_string(),
                        properties: HashMap::new(),
                    },
                    hydra_core::TenantId::from_str("tenant_api_test"),
                )
                .unwrap();
        }

        let app = build_router(runtime);

        // After Multi-tenant Patch 2B, /query/nodes is tenant-scoped
        // and returns the requesting tenant's nodes. Patch 2A's 501
        // path is gone — graph topology is now a real read surface.
        use hydra_core::node::Node;
        use hydra_net::http::pagination::Page;
        let list_req = Request::builder()
            .uri("/query/nodes?limit=10")
            .header("X-Hydra-Tenant", "tenant_api_test")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(list_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let nodes: Page<Node> = serde_json::from_slice(&body).unwrap();
        assert_eq!(nodes.items.len(), 1);
        assert_eq!(
            nodes.items[0].tenant_id().map(|t| t.to_string()),
            Some("tenant_api_test".to_string())
        );

        // /query/stats still confirms shared engine state across the
        // unified router — global counts include the node we ingested.
        let stats_req = Request::builder()
            .uri("/query/stats")
            .header("X-Hydra-Tenant", "tenant_api_test")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(stats_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let stats: StatsResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(stats.node_count, 1);
        assert!(stats.total_events >= 1);
    }
}
