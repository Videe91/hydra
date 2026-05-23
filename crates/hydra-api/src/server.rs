//! # HTTP Server
//!
//! Axum server with all routes, CORS, security middleware.

use crate::routes;
use crate::state::AppState;
use axum::http::{header, HeaderValue, Method};
use axum::routing::{get, post};
use axum::Router;
use hydra_net::http::{ingest_router, schema_router, sensor_router};
use hydra_net::runtime::RuntimeHandle;
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
    let state = AppState::new(runtime.clone());
    legacy_routes(state)
        .merge(schema_router(runtime.clone()))
        .merge(ingest_router(runtime.clone()))
        .merge(sensor_router(runtime))
        .layer(cors_layer())
}

/// Start the HTTP server on the given address.
pub async fn serve(
    runtime: RuntimeHandle,
    addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let router = build_router(runtime);
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
}
