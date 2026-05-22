//! # HTTP Server
//!
//! Axum server with all routes, CORS, security middleware.

use crate::routes;
use crate::state::AppState;
use axum::http::{header, HeaderValue, Method};
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;

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
