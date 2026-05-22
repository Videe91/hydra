//! # HTTP Routes

use crate::responses::*;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use hydra_core::id::NodeId;
use serde::Deserialize;

pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let uptime = state.started_at.elapsed().as_secs();
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: uptime,
    })
}

pub async fn stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let hydra = state.hydra.lock().unwrap();
    let (sensor_processed, sensor_signals) = state.transport.stats();
    Json(StatsResponse {
        node_count: hydra.node_count(),
        edge_count: hydra.edge_count(),
        event_count: hydra.event_log().len(),
        subscription_count: hydra.subscription_count(),
        sensor_events_processed: sensor_processed,
        sensor_signals_emitted: sensor_signals,
    })
}

pub async fn get_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<NodeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let hydra = state.hydra.lock().unwrap();
    let node_id = NodeId::from_str(&id);
    match hydra.graph().node(&node_id) {
        Some(node) => {
            let mut properties = std::collections::HashMap::new();
            // Extract known properties via typed accessors
            for key in &["name", "protection_status", "classification", "region",
                        "cloud_provider", "environment", "engine", "status",
                        "data_sensitivity", "instance_type", "storage_tier"] {
                if let Some(s) = node.get_str(key) {
                    properties.insert(key.to_string(), serde_json::Value::String(s.to_string()));
                }
            }
            for key in &["business_criticality", "monthly_cost_cents",
                        "backup_frequency_hours", "retention_days"] {
                if let Some(i) = node.get_i64(key) {
                    properties.insert(key.to_string(), serde_json::json!(i));
                }
            }
            for key in &["trust_composite", "trust_backup_freshness", "trust_backup_verified",
                        "trust_recovery_tested", "trust_anomaly_free"] {
                if let Some(f) = node.get_f64(key) {
                    properties.insert(key.to_string(), serde_json::json!(f));
                }
            }
            for key in &["replication_enabled", "encryption_required"] {
                if let Some(b) = node.get_bool(key) {
                    properties.insert(key.to_string(), serde_json::json!(b));
                }
            }

            Ok(Json(NodeResponse {
                id: node.id().as_str().to_string(),
                type_id: node.type_id().to_string(),
                alive: node.is_alive(),
                incoming_edge_count: hydra.graph().incoming_edges(node.id()).len(),
                outgoing_edge_count: hydra.graph().outgoing_edges(node.id()).len(),
                properties,
            }))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: format!("Node '{}' not found", id), code: 404 }),
        )),
    }
}

#[derive(Deserialize)]
pub struct NodeListParams {
    #[serde(rename = "type")]
    pub type_filter: Option<String>,
    pub limit: Option<usize>,
}

pub async fn list_nodes(
    State(state): State<AppState>,
    Query(params): Query<NodeListParams>,
) -> Json<NodeListResponse> {
    let hydra = state.hydra.lock().unwrap();
    let limit = params.limit.unwrap_or(100).min(1000);

    let nodes: Vec<NodeSummary> = match &params.type_filter {
        Some(type_id) => hydra.graph().nodes_by_type(type_id).into_iter()
            .take(limit)
            .map(node_to_summary)
            .collect(),
        None => {
            // Scan all protectable types
            let mut all = Vec::new();
            for t in hydra_sentinel::queries::protection_status::PROTECTABLE_TYPES {
                for n in hydra.graph().nodes_by_type(t) {
                    if n.is_alive() {
                        all.push(node_to_summary(n));
                        if all.len() >= limit { break; }
                    }
                }
                if all.len() >= limit { break; }
            }
            all
        }
    };
    let total = nodes.len();
    Json(NodeListResponse { nodes, total })
}

fn node_to_summary(n: &hydra_core::node::Node) -> NodeSummary {
    NodeSummary {
        id: n.id().as_str().to_string(),
        type_id: n.type_id().to_string(),
        name: n.get_str("name").map(|s| s.to_string()),
        protection_status: n.get_str("protection_status").map(|s| s.to_string()),
        business_criticality: n.get_i64("business_criticality"),
    }
}

pub async fn blast_radius(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<Json<BlastRadiusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let hydra = state.hydra.lock().unwrap();
    let id = NodeId::from_str(&node_id);
    if hydra.graph().node(&id).is_none() {
        return Err((StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: format!("Node '{}' not found", node_id), code: 404 })));
    }
    let config = hydra_sentinel::queries::blast_radius::BlastRadiusConfig::default();
    let report = match hydra_sentinel::queries::blast_radius::blast_radius(hydra.graph(), &id, &config) { Some(r) => r, None => return Err((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Could not compute blast radius".into(), code: 404 }))), };

    let affected_nodes: Vec<AffectedNode> = report.affected.iter().map(|a| AffectedNode {
        id: a.node_id.as_str().to_string(),
        type_id: a.node_type.clone(),
        depth: a.depth as usize,
        path: vec![format!("{:?}", a.impact_path)],
    }).collect();

    Ok(Json(BlastRadiusResponse {
        origin: node_id,
        total_affected: report.total_affected,
        max_depth: report.affected.iter().map(|a| a.depth as usize).max().unwrap_or(0),
        affected_nodes,
        risk_score: report.risk_score,
    }))
}

pub async fn protection_status(State(state): State<AppState>) -> Json<ProtectionStatusResponse> {
    let hydra = state.hydra.lock().unwrap();
    let summary = hydra_sentinel::queries::protection_status::protection_summary(hydra.graph());

    // Aggregate by type
    let mut type_map: std::collections::HashMap<String, (usize, usize, usize)> = std::collections::HashMap::new();
    let mut unprotected_cost = 0i64;
    for r in &summary.resources {
        let entry = type_map.entry(r.node_type.clone()).or_insert((0, 0, 0));
        entry.0 += 1;
        if r.protection_status == "protected" { entry.1 += 1; }
        else {
            entry.2 += 1;
            unprotected_cost += r.monthly_cost_cents;
        }
    }
    let by_type = type_map.into_iter().map(|(t, (total, prot, unprot))| TypeProtection {
        resource_type: t, total, protected: prot, unprotected: unprot,
    }).collect();
    let pct = if summary.total > 0 { (summary.protected as f64 / summary.total as f64) * 100.0 } else { 0.0 };

    Json(ProtectionStatusResponse {
        total_resources: summary.total,
        protected: summary.protected,
        unprotected: summary.unprotected,
        protection_percentage: pct,
        unprotected_cost_cents: unprotected_cost,
        by_type,
    })
}

pub async fn compliance_gaps(State(state): State<AppState>) -> Json<ComplianceGapsResponse> {
    let hydra = state.hydra.lock().unwrap();
    // Use the same rules as ComplianceArm
    let rules = vec![]; // Use empty rules for now — compliance checks run via ComplianceArm
    let report = hydra_sentinel::queries::compliance_gaps::compliance_gaps(hydra.graph(), &rules);

    let gaps: Vec<ComplianceGap> = report.gaps.iter().map(|g| ComplianceGap {
        rule_name: Some(format!("{:?}", g.requirement)).unwrap_or_default(),
        severity: format!("{:?}", g.requirement),
        affected_nodes: vec![g.node_id.as_str().to_string()],
        description: format!("Expected: {}, Actual: {}", g.required, g.actual),
    }).collect();

    let critical_count = report.gaps.iter()
        .filter(|g| matches!(g.requirement,
            hydra_sentinel::queries::compliance_gaps::ComplianceRequirement::BackupRequired))
        .count();

    Json(ComplianceGapsResponse {
        total_gaps: report.gaps.len(),
        critical_gaps: critical_count,
        gaps,
    })
}

pub async fn confidence_report(State(state): State<AppState>) -> Json<ConfidenceReportResponse> {
    let hydra = state.hydra.lock().unwrap();
    let report = hydra_sentinel::queries::confidence_report::confidence_report(hydra.graph(), 10);

    let weak_links: Vec<WeakLink> = report.weakest_links.iter().map(|wl| WeakLink {
        node_id: wl.node_id.as_str().to_string(),
        score: wl.trust_composite,
        weakest_dimension: wl.weakest_dimension.clone(),
    }).collect();

    Json(ConfidenceReportResponse {
        overall_grade: format!("{:?}", report.grade),
        overall_score: report.overall_score,
        weak_links,
        dimension_averages: std::collections::HashMap::new(), // TODO: extract from dimensions
    })
}

pub async fn recovery_plan(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<Json<RecoveryPlanResponse>, (StatusCode, Json<ErrorResponse>)> {
    let hydra = state.hydra.lock().unwrap();
    let id = NodeId::from_str(&node_id);
    match hydra_sentinel::queries::recovery_plan::recovery_plan(hydra.graph(), &id) {
        Some(plan) => {
            let steps: Vec<RecoveryStep> = plan.steps.iter().enumerate().map(|(i, s)| RecoveryStep {
                order: i + 1,
                node_id: s.node_id.as_str().to_string(),
                action: format!("{:?}", s.action),
                priority: s.criticality as usize,
            }).collect();
            Ok(Json(RecoveryPlanResponse {
                origin: node_id,
                total_steps: plan.steps.len(),
                has_cycles: plan.has_cycles,
                steps,
            }))
        }
        None => Err((StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: format!("No recovery plan for '{}'", node_id), code: 404 }))),
    }
}

pub async fn ingest_cloudtrail(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<IngestResponse>, (StatusCode, Json<ErrorResponse>)> {
    if body.len() > 10 * 1024 * 1024 {
        return Err((StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse { error: "Payload exceeds 10MB".into(), code: 413 })));
    }
    let transport_result = state.transport.parse_batch(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: format!("Parse error: {}", e), code: 400 })))?;

    let signal_count = transport_result.signals.len();
    let skipped = transport_result.skipped;
    let parse_errors = transport_result.parse_errors;
    let unrecognized = transport_result.unrecognized;

    let mut cascade_events = 0;
    {
        let mut hydra = state.hydra.lock().unwrap();
        for signal in transport_result.signals {
            match hydra.ingest(signal) {
                Ok(result) => cascade_events += result.events.len(),
                Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse { error: format!("Ingest error: {}", e), code: 500 }))),
            }
        }
    }

    Ok(Json(IngestResponse {
        signals_processed: signal_count,
        signals_skipped: skipped,
        parse_errors,
        unrecognized_events: unrecognized,
        cascade_events_generated: cascade_events,
    }))
}

pub async fn metrics(State(state): State<AppState>) -> String {
    let hydra = state.hydra.lock().unwrap();
    let (sensor_processed, sensor_signals) = state.transport.stats();
    format!(
        "# HELP hydra_nodes_total Total graph nodes\n# TYPE hydra_nodes_total gauge\nhydra_nodes_total {}\n\
         # HELP hydra_edges_total Total graph edges\n# TYPE hydra_edges_total gauge\nhydra_edges_total {}\n\
         # HELP hydra_events_total Total events in log\n# TYPE hydra_events_total gauge\nhydra_events_total {}\n\
         # HELP hydra_sensor_processed_total CloudTrail events processed\n# TYPE hydra_sensor_processed_total counter\nhydra_sensor_processed_total {}\n\
         # HELP hydra_sensor_signals_total Hydra signals emitted\n# TYPE hydra_sensor_signals_total counter\nhydra_sensor_signals_total {}\n",
        hydra.node_count(), hydra.edge_count(), hydra.event_log().len(),
        sensor_processed, sensor_signals,
    )
}
