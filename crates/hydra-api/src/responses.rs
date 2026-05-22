//! # API Response Types
//!
//! Serializable response structs for all HTTP endpoints.
//! These are the JSON shapes that the API consumer sees.

use serde::Serialize;

/// GET /health
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
}

/// GET /stats
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub node_count: usize,
    pub edge_count: usize,
    pub event_count: usize,
    pub subscription_count: usize,
    pub sensor_events_processed: u64,
    pub sensor_signals_emitted: u64,
}

/// GET /nodes/:id
#[derive(Debug, Serialize)]
pub struct NodeResponse {
    pub id: String,
    pub type_id: String,
    pub alive: bool,
    pub properties: std::collections::HashMap<String, serde_json::Value>,
    pub incoming_edge_count: usize,
    pub outgoing_edge_count: usize,
}

/// GET /nodes?type=...
#[derive(Debug, Serialize)]
pub struct NodeListResponse {
    pub nodes: Vec<NodeSummary>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct NodeSummary {
    pub id: String,
    pub type_id: String,
    pub name: Option<String>,
    pub protection_status: Option<String>,
    pub business_criticality: Option<i64>,
}

/// GET /blast-radius/:node_id
#[derive(Debug, Serialize)]
pub struct BlastRadiusResponse {
    pub origin: String,
    pub total_affected: usize,
    pub max_depth: usize,
    pub affected_nodes: Vec<AffectedNode>,
    pub risk_score: f64,
}

#[derive(Debug, Serialize)]
pub struct AffectedNode {
    pub id: String,
    pub type_id: String,
    pub depth: usize,
    pub path: Vec<String>,
}

/// GET /protection-status
#[derive(Debug, Serialize)]
pub struct ProtectionStatusResponse {
    pub total_resources: usize,
    pub protected: usize,
    pub unprotected: usize,
    pub protection_percentage: f64,
    pub unprotected_cost_cents: i64,
    pub by_type: Vec<TypeProtection>,
}

#[derive(Debug, Serialize)]
pub struct TypeProtection {
    pub resource_type: String,
    pub total: usize,
    pub protected: usize,
    pub unprotected: usize,
}

/// GET /compliance-gaps
#[derive(Debug, Serialize)]
pub struct ComplianceGapsResponse {
    pub total_gaps: usize,
    pub critical_gaps: usize,
    pub gaps: Vec<ComplianceGap>,
}

#[derive(Debug, Serialize)]
pub struct ComplianceGap {
    pub rule_name: String,
    pub severity: String,
    pub affected_nodes: Vec<String>,
    pub description: String,
}

/// GET /confidence-report
#[derive(Debug, Serialize)]
pub struct ConfidenceReportResponse {
    pub overall_grade: String,
    pub overall_score: f64,
    pub weak_links: Vec<WeakLink>,
    pub dimension_averages: std::collections::HashMap<String, f64>,
}

#[derive(Debug, Serialize)]
pub struct WeakLink {
    pub node_id: String,
    pub score: f64,
    pub weakest_dimension: String,
}

/// GET /recovery-plan/:node_id
#[derive(Debug, Serialize)]
pub struct RecoveryPlanResponse {
    pub origin: String,
    pub total_steps: usize,
    pub has_cycles: bool,
    pub steps: Vec<RecoveryStep>,
}

#[derive(Debug, Serialize)]
pub struct RecoveryStep {
    pub order: usize,
    pub node_id: String,
    pub action: String,
    pub priority: usize,
}

/// POST /sensor/cloudtrail
#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub signals_processed: usize,
    pub signals_skipped: usize,
    pub parse_errors: Vec<String>,
    pub unrecognized_events: Vec<(String, String)>,
    pub cascade_events_generated: usize,
}

/// GET /metrics (Prometheus-compatible text format)
#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub hydra_nodes_total: usize,
    pub hydra_edges_total: usize,
    pub hydra_events_total: usize,
    pub hydra_cascade_truncations: u64,
    pub hydra_sensor_events_processed: u64,
    pub hydra_sensor_signals_emitted: u64,
    pub hydra_protection_percentage: f64,
    pub hydra_unprotected_cost_cents: i64,
}

/// Generic error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}
