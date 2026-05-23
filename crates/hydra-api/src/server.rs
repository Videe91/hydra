//! # HTTP Server
//!
//! Axum server with all routes, CORS, security middleware.

use crate::routes;
use crate::state::AppState;
use axum::http::{header, HeaderValue, Method};
use axum::routing::{get, post};
use axum::Router;
use hydra_net::http::schema_router;
use hydra_net::runtime::RuntimeHandle;
use tower_http::cors::CorsLayer;

fn schema_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_origin("*".parse::<HeaderValue>().unwrap())
        .max_age(std::time::Duration::from_secs(3600))
}

/// Build the Axum router with all endpoints.
pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_origin("*".parse::<HeaderValue>().unwrap())
        .max_age(std::time::Duration::from_secs(3600));

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
        // Middleware
        .layer(cors)
        .with_state(state)
}

/// Start the HTTP server on the given address.
pub async fn serve(state: AppState, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

/// Build a router that exposes the schema HTTP surface
/// (introspection + preflight validation + register/disable/archive).
///
/// Mounts the full `/schemas/*` route tree from `hydra-net` behind the same
/// CORS policy as the legacy CloudTrail server.
///
/// **Note on engine ownership.** The legacy [`AppState`]-backed server uses
/// `Arc<std::sync::Mutex<Hydra>>`; this entrypoint uses
/// [`RuntimeHandle`], which holds `Arc<tokio::sync::RwLock<Hydra>>`. They
/// cannot share a single `Hydra` instance today. Unifying the two ownership
/// models so legacy routes and schema routes hit the same engine is a
/// dedicated follow-up patch.
pub fn build_schema_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .merge(schema_router(runtime))
        .layer(schema_cors_layer())
}

/// Start an HTTP server exposing only the schema routes.
///
/// Convenience for a clean "schema database" deployment that does not also
/// want the Sentinel/CloudTrail surface.
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

    fn test_state() -> AppState {
        AppState::new(Hydra::new())
    }

    #[tokio::test]
    async fn health_endpoint() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn stats_endpoint() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/stats")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn node_not_found() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/nodes/nonexistent")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_nodes_empty() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/nodes")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protection_status_empty() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/protection-status")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_endpoint() {
        let app = build_router(test_state());
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
        use hydra_core::subscription::{Subscription, EventFilter};
        use hydra_sentinel::arms::*;

        // Build Hydra with Arms
        let mut hydra = Hydra::with_config(CascadeConfig {
            max_depth: 15,
            max_events: 200,
        });
        hydra.register(Subscription::new("discovery", EventFilter::Or(vec![
            EventFilter::SignalName("resource_discovered".into()),
            EventFilter::SignalName("resource_deleted".into()),
        ]), 200, Box::new(DiscoveryArm::new())));
        hydra.register(Subscription::new("classification", EventFilter::Or(vec![
            EventFilter::NodeCreated,
        ]), 190, Box::new(ClassificationArm::with_defaults())));
        hydra.register(Subscription::new("policy", EventFilter::NodeUpdated,
            180, Box::new(PolicyArm::new())));
        hydra.register(Subscription::new("execution", EventFilter::Or(vec![
            EventFilter::SignalName("policy_computed".into()),
        ]), 170, Box::new(ExecutionArm::new())));
        hydra.register(Subscription::new("verification",
            EventFilter::SignalName("backup_completed".into()),
            160, Box::new(VerificationArm::new())));
        hydra.register(Subscription::new("trust", EventFilter::Or(vec![
            EventFilter::SignalName("trust_penalty".into()),
            EventFilter::NodeUpdated,
            EventFilter::EdgeCreated,
        ]), 100, Box::new(TrustArm::new())));

        let state = AppState::new(hydra);
        let app = build_router(state.clone());

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
        let app = build_router(state.clone());
        let req = Request::builder()
            .uri("/nodes/api-test-db")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // GET protection status
        let app = build_router(state.clone());
        let req = Request::builder()
            .uri("/protection-status")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // GET blast radius
        let app = build_router(state.clone());
        let req = Request::builder()
            .uri("/blast-radius/api-test-db")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
