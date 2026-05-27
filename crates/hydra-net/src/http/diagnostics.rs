//! V2 next-level → living-database phase: `/diagnostics/*` routes.
//!
//! Externalises Hydra's reasoning surfaces — anomaly detection,
//! coverage scoring, counterfactual analysis, subscription evolution
//! — as HTTP. This module starts with the first one,
//! `GET /diagnostics/anomaly`, and is structured to accumulate the
//! rest in the same place.
//!
//! Where lineage answers *"why did this happen?"*, diagnostics
//! answers *"what looks wrong right now?"* — different cognitive
//! capability, different endpoint family.
//!
//! ## Routes
//!
//! - `GET /diagnostics/anomaly` — calls `Hydra::analyze_batch()`,
//!   returns the current set of anomalies, filterable by
//!   `severity_min` / `kind` / `limit`.
//!
//! ## Auth
//!
//! All diagnostics routes gate on `read:query` — current-state
//! introspection, not historical audit. Operators with `read:query`
//! for monitoring dashboards should be able to poll diagnostics
//! without escalating to `read:audit`.
//!
//! ## Tenant semantics
//!
//! A tenant header is required (consistent with the rest of the
//! HTTP surface), but the underlying engine's `analyze_batch`
//! operates **globally** — anomaly rules currently scan the entire
//! graph regardless of tenant. The response includes
//! `analysis_scope: "global"` so clients can detect when this
//! limitation is lifted (a future patch may add tenant-scoped
//! analysis without a breaking change).
//!
//! ## No caching
//!
//! Each request computes fresh against the current engine state.
//! Diagnostics is a low-frequency, high-value endpoint (operators
//! and agents call it on demand to introspect, not per-request).
//! If perf becomes an issue later, a TTL cache can be added in
//! this handler without changing the response shape.

use crate::http::tenant::{extract_tenant, tenant_error_response};
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hydra_core::EventId;
use hydra_engine::anomaly::Anomaly;
use hydra_engine::counterfactual::GraphDiff;
use hydra_engine::coverage::CoverageReport;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

#[derive(Clone)]
pub struct DiagnosticsHttpState {
    pub runtime: RuntimeHandle,
}

impl DiagnosticsHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the diagnostics router. Exposes the reasoning surfaces
/// of the engine as HTTP. Future patches add `/counterfactual`
/// and `/evolution` here.
pub fn diagnostics_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/diagnostics/anomaly", get(get_anomaly))
        .route("/diagnostics/coverage", get(get_coverage))
        .route(
            "/diagnostics/counterfactual/:event_id",
            get(get_counterfactual),
        )
        .with_state(DiagnosticsHttpState::new(runtime))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnomalyQuery {
    /// Filter: only anomalies with `severity >= severity_min`.
    /// Default 0.0 (no filter). Values outside [0.0, 1.0] are
    /// clamped.
    pub severity_min: Option<f64>,
    /// Filter: only this AnomalyKind discriminant
    /// (snake_case — e.g. `topology_degree`, `cascade_amplification`).
    /// Invalid discriminants return 400.
    pub kind: Option<String>,
    /// Cap the number of anomalies returned. Default 100, max 1000.
    pub limit: Option<usize>,
}

/// One anomaly entry in the response. Wraps the engine's `Anomaly`
/// with a stable `anomaly_id` (deterministic content hash, see
/// `Anomaly::stable_id`). Operators can use the id to acknowledge /
/// mute / track / correlate across calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEntry {
    pub anomaly_id: String,
    #[serde(flatten)]
    pub anomaly: Anomaly,
}

/// `GET /diagnostics/anomaly` response.
///
/// Fields:
///   - `anomalies` — filtered + capped list of anomaly entries
///   - `rule_count` — total rules configured in the engine (signal
///     to operators that the engine is actually instrumented)
///   - `anomaly_count` — count BEFORE the `limit` was applied;
///     compare against `anomalies.len()` to know if results were
///     trimmed
///   - `truncated` — `anomaly_count > anomalies.len()`
///   - `summary` — deterministic, server-side natural-language
///     narrative of the result (counts, top category, most-severe
///     entry). Same pattern as lineage's `explanation_summary` —
///     agents can ignore; humans understand instantly.
///   - `engine_duration_ms` — time spent inside
///     `Hydra::analyze_batch`. Operator trust surface.
///   - `analysis_scope` — `"global"` today. Future tenant-scoped
///     analysis will return `"tenant"`. Clients should NOT assume
///     a value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResponse {
    pub anomalies: Vec<AnomalyEntry>,
    pub rule_count: usize,
    pub anomaly_count: usize,
    pub truncated: bool,
    pub summary: String,
    pub engine_duration_ms: u64,
    pub analysis_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
        .into_response()
}

async fn get_anomaly(
    State(state): State<DiagnosticsHttpState>,
    headers: HeaderMap,
    Query(query): Query<AnomalyQuery>,
) -> Response {
    // Tenant header is required for consistency with the rest of
    // the HTTP surface. The underlying engine analysis is global —
    // see module docs.
    if let Err(e) = extract_tenant(&headers) {
        return tenant_error_response(e);
    }

    let severity_min = query.severity_min.unwrap_or(0.0).clamp(0.0, 1.0);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let kind_filter = query.kind.as_deref();

    // Validate `kind` filter early so we can 400 BEFORE running the
    // expensive batch analysis. Maintained list of valid snake_case
    // discriminants — kept in sync with `AnomalyKind::kind_name`.
    if let Some(k) = kind_filter {
        if !is_known_kind(k) {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "unknown anomaly kind '{k}': valid values are topology_degree, cascade_amplification, temporal_drift, change_rate_anomaly, structural_orphan, time_window_violation, counterfactual_outlier, forbidden_pattern"
                ),
            );
        }
    }

    let hydra_arc = state.runtime.hydra();
    let hydra = hydra_arc.read().await;

    let start = Instant::now();
    let all_anomalies = hydra.analyze_batch();
    let engine_duration_ms = start.elapsed().as_millis() as u64;

    let rule_count = hydra.anomaly_engine().rule_count();

    // Filter (severity, kind), then count, then cap.
    let filtered: Vec<Anomaly> = all_anomalies
        .into_iter()
        .filter(|a| a.severity >= severity_min)
        .filter(|a| match kind_filter {
            Some(k) => a.kind.kind_name() == k,
            None => true,
        })
        .collect();

    let anomaly_count = filtered.len();
    let truncated = anomaly_count > limit;

    let summary = render_anomaly_summary(&filtered, severity_min, kind_filter);

    let anomalies: Vec<AnomalyEntry> = filtered
        .into_iter()
        .take(limit)
        .map(|a| AnomalyEntry {
            anomaly_id: a.stable_id(),
            anomaly: a,
        })
        .collect();

    Json(AnomalyResponse {
        anomalies,
        rule_count,
        anomaly_count,
        truncated,
        summary,
        engine_duration_ms,
        analysis_scope: "global".to_string(),
    })
    .into_response()
}

fn is_known_kind(name: &str) -> bool {
    matches!(
        name,
        "topology_degree"
            | "cascade_amplification"
            | "temporal_drift"
            | "change_rate_anomaly"
            | "structural_orphan"
            | "time_window_violation"
            | "counterfactual_outlier"
            | "forbidden_pattern"
    )
}

/// Compose a one-line, deterministic narrative of the filtered
/// anomaly set. Pattern matches lineage's `explanation_summary`:
/// agents can ignore; humans/operators get an instant gist without
/// scanning the structured `anomalies[]`.
fn render_anomaly_summary(
    anomalies: &[Anomaly],
    severity_min: f64,
    kind_filter: Option<&str>,
) -> String {
    if anomalies.is_empty() {
        let mut parts = vec!["Found 0 anomalies.".to_string()];
        if severity_min > 0.0 {
            parts.push(format!("(severity_min={severity_min:.2})"));
        }
        if let Some(k) = kind_filter {
            parts.push(format!("(kind={k})"));
        }
        return parts.join(" ");
    }

    let mut parts: Vec<String> = vec![format!("Found {} anomaly(ies).", anomalies.len())];

    // Severity buckets — critical (≥0.8), warning (≥0.5), info (<0.5).
    let critical = anomalies.iter().filter(|a| a.severity >= 0.8).count();
    let warning = anomalies
        .iter()
        .filter(|a| a.severity >= 0.5 && a.severity < 0.8)
        .count();
    let info = anomalies.iter().filter(|a| a.severity < 0.5).count();
    parts.push(format!(
        "Severity: {critical} critical, {warning} warning, {info} info."
    ));

    // Top category by count.
    let mut by_kind: std::collections::HashMap<&'static str, usize> =
        std::collections::HashMap::new();
    for a in anomalies {
        *by_kind.entry(a.kind.kind_name()).or_insert(0) += 1;
    }
    if let Some((top_kind, top_count)) = by_kind.iter().max_by_key(|(_, c)| **c) {
        parts.push(format!("Top category: {top_kind} ({top_count})."));
    }

    // Most severe entry's description (truncated).
    if let Some(most_severe) = anomalies
        .iter()
        .max_by(|a, b| a.severity.partial_cmp(&b.severity).unwrap_or(std::cmp::Ordering::Equal))
    {
        let desc = if most_severe.description.len() > 120 {
            format!("{}…", &most_severe.description[..120])
        } else {
            most_severe.description.clone()
        };
        parts.push(format!(
            "Most severe: '{desc}' (severity {:.2}).",
            most_severe.severity
        ));
    }

    parts.join(" ")
}

// === GET /diagnostics/coverage ===

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoverageQuery {
    /// Filter: only return the report for this model_name. Unknown
    /// names return 200 with `reports: []` (not 404) — matches the
    /// `/replication/peers/:peer_id/lag` convention so monitoring
    /// loops don't have to special-case missing models.
    pub model: Option<String>,
    /// Filter: only return reports where `score < 1.0` (the
    /// "what's broken" view). Default false (return all reports).
    pub failing_only: Option<bool>,
    /// Cap on the number of reports returned. Default 100, max 1000.
    pub limit: Option<usize>,
}

/// `GET /diagnostics/coverage` response.
///
/// Fields parallel the anomaly response. `reports[]` is the
/// filtered + capped list of `CoverageReport`s from
/// `Hydra::evaluate_coverage`. `report_count` is the count BEFORE
/// `limit` was applied; compare with `reports.len()` to detect
/// truncation. `model_count` is the number of models registered
/// in the engine (signal to operators that the engine is actually
/// instrumented). `analysis_scope: "global"` future-proofs for
/// tenant-scoped coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageDiagnosticsResponse {
    pub reports: Vec<CoverageReport>,
    pub model_count: usize,
    pub report_count: usize,
    pub truncated: bool,
    pub summary: String,
    pub engine_duration_ms: u64,
    pub analysis_scope: String,
}

async fn get_coverage(
    State(state): State<DiagnosticsHttpState>,
    headers: HeaderMap,
    Query(query): Query<CoverageQuery>,
) -> Response {
    if let Err(e) = extract_tenant(&headers) {
        return tenant_error_response(e);
    }

    let model_filter = query.model.as_deref();
    let failing_only = query.failing_only.unwrap_or(false);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);

    let hydra_arc = state.runtime.hydra();
    let hydra = hydra_arc.read().await;

    let start = Instant::now();
    let all_reports = hydra.evaluate_coverage();
    let engine_duration_ms = start.elapsed().as_millis() as u64;

    let model_count = hydra.coverage_engine().model_count();

    let filtered: Vec<CoverageReport> = all_reports
        .into_iter()
        .filter(|r| match model_filter {
            Some(name) => r.model_name == name,
            None => true,
        })
        .filter(|r| !failing_only || r.score < 1.0)
        .collect();

    let report_count = filtered.len();
    let truncated = report_count > limit;

    let summary = render_coverage_summary(&filtered, model_filter, failing_only);

    let reports: Vec<CoverageReport> = filtered.into_iter().take(limit).collect();

    Json(CoverageDiagnosticsResponse {
        reports,
        model_count,
        report_count,
        truncated,
        summary,
        engine_duration_ms,
        analysis_scope: "global".to_string(),
    })
    .into_response()
}

/// Deterministic narrative of the filtered coverage set. Same
/// pattern as `render_anomaly_summary`: agents can ignore; humans
/// get an instant gist without scanning `reports[]`.
fn render_coverage_summary(
    reports: &[CoverageReport],
    model_filter: Option<&str>,
    failing_only: bool,
) -> String {
    if reports.is_empty() {
        if let Some(name) = model_filter {
            return format!("Coverage evaluated 0 reports for model '{name}'.");
        }
        return "Coverage evaluated 0 models.".to_string();
    }

    let mut parts: Vec<String> = vec![format!(
        "Coverage evaluated {} model(s).",
        reports.len()
    )];

    // Per-model summary line for the first few — keep bounded so
    // the summary string doesn't explode on big deployments.
    for report in reports.iter().take(3) {
        let pct = (report.score * 100.0).round() as u32;
        parts.push(format!(
            "{}: {pct}% complete ({} of {} expectations met).",
            report.model_name, report.met, report.total_expectations
        ));
    }
    if reports.len() > 3 {
        parts.push(format!("(+{} more report(s))", reports.len() - 3));
    }

    // Highlight the top gap from the lowest-scoring report — the
    // operator's first investigative target.
    if let Some(worst) = reports
        .iter()
        .min_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal))
    {
        if let Some(top_gap) = worst.gaps.first() {
            let desc = if top_gap.description.len() > 120 {
                format!("{}…", &top_gap.description[..120])
            } else {
                top_gap.description.clone()
            };
            parts.push(format!("Top gap: '{desc}'."));
        }
    }

    if failing_only {
        parts.push("(failing_only=true)".to_string());
    }

    parts.join(" ")
}

// === GET /diagnostics/counterfactual/:event_id ===

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CounterfactualQuery {
    /// When false, the response sets `diff: null` rather than
    /// returning the full GraphDiff body. Aggregate counters
    /// (nodes_affected / edges_affected / etc.) are always
    /// returned. Default true (include diff).
    ///
    /// **Semantic note**: `diff: null` (omitted) is DIFFERENT
    /// from `diff: { all-empty-arrays }` (zero-impact event).
    /// Agents must distinguish these — see DTO doc-comments.
    pub include_diff: Option<bool>,
}

/// `GET /diagnostics/counterfactual/:event_id` response.
///
/// Explicit transport DTO — does NOT `#[serde(flatten)]` the
/// engine's `ImpactScore`. This separation lets the diagnostics
/// contract evolve independently of the engine type (e.g., V3
/// might add `confidence`, `simulation_depth`, `cascade_frontier`,
/// `causal_clusters` to ImpactScore without forcing every
/// diagnostics client to handle them).
///
/// **`diff` semantics**:
///   - `Some(GraphDiff { all-empty-vecs })` → removing this event
///     would change NOTHING. The event had zero observable graph
///     impact. Meaningful answer.
///   - `Some(GraphDiff { non-empty })` → here's the delta.
///   - `None` → client asked for `?include_diff=false`. The diff
///     was NOT computed for transport. Transport-level omission,
///     not zero impact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterfactualDiagnosticsResponse {
    /// Echoes the path-param event_id, in the same shape every
    /// other diagnostics surface uses for identification.
    pub event_id: EventId,
    /// Always true for the single-event endpoint (200 path).
    /// Reserved for future batch-counterfactual APIs where each
    /// requested event may or may not exist; clients keeping a
    /// uniform parse path across single and batch shapes benefit.
    pub event_found: bool,
    /// Mode discriminant. Today: only `"single_event_removal"`.
    /// Future modes (`"multi_event_removal"`,
    /// `"constraint_based"`, `"policy_filtered"`, etc.) MUST get
    /// distinct discriminants so clients don't silently
    /// reinterpret semantics.
    pub counterfactual_mode: String,
    /// How many events were in the removed causal subtree
    /// (target event + its descendants).
    pub causal_subtree_size: usize,
    /// Aggregate counters from the diff.
    pub nodes_affected: usize,
    pub edges_affected: usize,
    pub properties_changed: usize,
    /// Per-type breakdown — `type_id -> count_of_affected_nodes`.
    /// Useful for "which kinds of things did this event touch?"
    /// queries without iterating the full diff.
    pub affected_types: HashMap<String, usize>,
    /// Deterministic magnitude heuristic from the engine:
    /// `10 * nodes + 5 * edges + 1 * properties`. Stable so
    /// agents/dashboards can rank events by impact.
    pub magnitude: f64,
    /// See struct doc-comment for the three-state semantics
    /// (some-non-empty / some-empty / none).
    pub diff: Option<GraphDiff>,
    /// Server-rendered natural-language gist. Same convention as
    /// anomaly + coverage summaries.
    pub summary: String,
    pub engine_duration_ms: u64,
    pub analysis_scope: String,
}

async fn get_counterfactual(
    State(state): State<DiagnosticsHttpState>,
    headers: HeaderMap,
    Path(event_id_str): Path<String>,
    Query(query): Query<CounterfactualQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(e) => return tenant_error_response(e),
    };
    let include_diff = query.include_diff.unwrap_or(true);
    let event_id = EventId::from_str(&event_id_str);

    let hydra_arc = state.runtime.hydra();
    let hydra = hydra_arc.read().await;

    // Tenant check on the seed event (matches lineage /
    // /query/events/:event_id/counterfactual existing semantics).
    let seed = match hydra.event(&event_id) {
        Some(e) => e,
        None => {
            return error_response(
                StatusCode::NOT_FOUND,
                format!("event not found: {event_id_str}"),
            );
        }
    };
    if let Some(seed_tenant) = &seed.tenant_id {
        if *seed_tenant != tenant {
            return error_response(
                StatusCode::NOT_FOUND,
                format!("event not found: {event_id_str}"),
            );
        }
    }

    let start = Instant::now();
    let impact = match hydra.impact_score(&event_id) {
        Ok(s) => s,
        Err(err) => {
            return error_response(
                StatusCode::NOT_FOUND,
                format!("counterfactual failed for {event_id_str}: {err}"),
            );
        }
    };
    let engine_duration_ms = start.elapsed().as_millis() as u64;

    let magnitude = impact.magnitude();
    let summary = render_counterfactual_summary(&impact, include_diff);

    let diff = if include_diff { Some(impact.diff) } else { None };

    Json(CounterfactualDiagnosticsResponse {
        event_id: impact.event_id,
        event_found: true,
        counterfactual_mode: "single_event_removal".to_string(),
        causal_subtree_size: impact.causal_subtree_size,
        nodes_affected: impact.nodes_affected,
        edges_affected: impact.edges_affected,
        properties_changed: impact.properties_changed,
        affected_types: impact.affected_types,
        magnitude,
        diff,
        summary,
        engine_duration_ms,
        analysis_scope: "global".to_string(),
    })
    .into_response()
}

fn render_counterfactual_summary(
    impact: &hydra_engine::counterfactual::ImpactScore,
    include_diff: bool,
) -> String {
    let mut parts: Vec<String> = vec![format!(
        "Removing event {} would undo {} cascaded event(s).",
        impact.event_id, impact.causal_subtree_size
    )];

    parts.push(format!(
        "Graph impact: {} node(s) affected, {} edge(s) affected, {} property change(s) (magnitude {:.1}).",
        impact.nodes_affected,
        impact.edges_affected,
        impact.properties_changed,
        impact.magnitude()
    ));

    // Top 3 affected types by count.
    if !impact.affected_types.is_empty() {
        let mut pairs: Vec<(&String, &usize)> = impact.affected_types.iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(a.1));
        let top: Vec<String> = pairs
            .iter()
            .take(3)
            .map(|(t, c)| format!("{t} ({c})"))
            .collect();
        parts.push(format!("Affected types: {}.", top.join(", ")));
    }

    if !include_diff {
        parts.push("(diff omitted via include_diff=false)".to_string());
    } else if impact.nodes_affected == 0
        && impact.edges_affected == 0
        && impact.properties_changed == 0
    {
        parts.push("Zero-impact event: removing it changes nothing.".to_string());
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use hydra_core::{EventKind, NodeId, TenantId};
    use hydra_engine::anomaly::{AnomalyKind, TopologyRule};
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_diag_test")
    }

    fn empty_get(uri: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("X-Hydra-Tenant", tenant().as_str())
            .body(Body::empty())
            .unwrap()
    }

    async fn read_json<T: for<'de> serde::de::DeserializeOwned>(response: Response) -> T {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn anomaly_returns_empty_when_no_rules_configured() {
        // Fresh engine has only the default CascadeRule (no events
        // to trigger it). Response is well-formed with zero
        // anomalies and rule_count >= 1.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get("/diagnostics/anomaly"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: AnomalyResponse = read_json(response).await;
        assert!(decoded.anomalies.is_empty());
        assert_eq!(decoded.anomaly_count, 0);
        assert!(!decoded.truncated);
        assert!(decoded.rule_count >= 1, "default cascade rule expected");
        assert_eq!(decoded.analysis_scope, "global");
        assert!(decoded.summary.starts_with("Found 0 anomalies"));
    }

    #[tokio::test]
    async fn anomaly_returns_topology_violations_when_configured() {
        // Register a topology rule requiring `dataset` nodes to have
        // at least 1 `depends_on` edge. Create an isolated dataset
        // node → batch analysis surfaces a StructuralOrphan (the
        // engine specializes degree==0+min>0 into that variant; see
        // `check_topology_batch`).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.anomaly_engine_mut().add_topology_rule(TopologyRule {
                node_type: "dataset".to_string(),
                edge_type: "depends_on".to_string(),
                min_degree: 1,
                max_degree: 100,
                severity: 0.7,
            });
            hydra
                .ingest_for_tenant(
                    EventKind::NodeCreated {
                        node_id: NodeId::from_str("node_isolated_dataset"),
                        type_id: "dataset".to_string(),
                        properties: HashMap::new(),
                    },
                    tenant(),
                )
                .unwrap();
        }
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get("/diagnostics/anomaly"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: AnomalyResponse = read_json(response).await;
        assert!(
            !decoded.anomalies.is_empty(),
            "topology violation must surface"
        );
        let first = &decoded.anomalies[0];
        assert_eq!(first.anomaly.kind.kind_name(), "structural_orphan");
        assert!(first.anomaly_id.starts_with("anom_"));
        assert!(decoded.summary.contains("structural_orphan"));
    }

    #[tokio::test]
    async fn anomaly_filters_by_severity_min() {
        // Register one severity=0.2 (info) topology rule + one
        // severity=0.9 (critical) rule, both violated. Request with
        // severity_min=0.5 → only the critical surfaces.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.anomaly_engine_mut().add_topology_rule(TopologyRule {
                node_type: "low_node".to_string(),
                edge_type: "x".to_string(),
                min_degree: 1,
                max_degree: 100,
                severity: 0.2,
            });
            hydra.anomaly_engine_mut().add_topology_rule(TopologyRule {
                node_type: "high_node".to_string(),
                edge_type: "y".to_string(),
                min_degree: 1,
                max_degree: 100,
                severity: 0.9,
            });
            hydra
                .ingest_for_tenant(
                    EventKind::NodeCreated {
                        node_id: NodeId::from_str("node_a"),
                        type_id: "low_node".to_string(),
                        properties: HashMap::new(),
                    },
                    tenant(),
                )
                .unwrap();
            hydra
                .ingest_for_tenant(
                    EventKind::NodeCreated {
                        node_id: NodeId::from_str("node_b"),
                        type_id: "high_node".to_string(),
                        properties: HashMap::new(),
                    },
                    tenant(),
                )
                .unwrap();
        }
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get("/diagnostics/anomaly?severity_min=0.5"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: AnomalyResponse = read_json(response).await;
        assert_eq!(decoded.anomalies.len(), 1, "only critical survives the 0.5 floor");
        assert!(decoded.anomalies[0].anomaly.severity >= 0.5);
    }

    #[tokio::test]
    async fn anomaly_filters_by_kind() {
        // Register a topology rule + a custom pattern check would
        // require pattern setup. Simpler: register topology and
        // request a DIFFERENT kind via filter — response should be
        // empty even though topology anomalies exist.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.anomaly_engine_mut().add_topology_rule(TopologyRule {
                node_type: "dataset".to_string(),
                edge_type: "depends_on".to_string(),
                min_degree: 1,
                max_degree: 100,
                severity: 0.5,
            });
            hydra
                .ingest_for_tenant(
                    EventKind::NodeCreated {
                        node_id: NodeId::from_str("node_d"),
                        type_id: "dataset".to_string(),
                        properties: HashMap::new(),
                    },
                    tenant(),
                )
                .unwrap();
        }
        let app = diagnostics_router(runtime);
        // Filter to a kind that won't match.
        let response = app
            .clone()
            .oneshot(empty_get("/diagnostics/anomaly?kind=forbidden_pattern"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: AnomalyResponse = read_json(response).await;
        assert!(
            decoded.anomalies.is_empty(),
            "kind filter must exclude non-matching anomalies"
        );
        // Filter to the matching kind (orphan, since the isolated
        // dataset triggers StructuralOrphan, not TopologyDegree —
        // see `check_topology_batch`).
        let response = app
            .oneshot(empty_get("/diagnostics/anomaly?kind=structural_orphan"))
            .await
            .unwrap();
        let decoded: AnomalyResponse = read_json(response).await;
        assert!(
            !decoded.anomalies.is_empty(),
            "matching kind filter must keep anomalies"
        );
    }

    #[tokio::test]
    async fn anomaly_rejects_unknown_kind_with_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get("/diagnostics/anomaly?kind=nonsense"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn anomaly_respects_limit_with_truncated_flag() {
        // Three topology rules → three anomalies. limit=2 → 2
        // entries returned, anomaly_count=3, truncated=true.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            for (type_id, severity) in [("type_a", 0.5), ("type_b", 0.6), ("type_c", 0.7)] {
                hydra.anomaly_engine_mut().add_topology_rule(TopologyRule {
                    node_type: type_id.to_string(),
                    edge_type: "x".to_string(),
                    min_degree: 1,
                    max_degree: 100,
                    severity,
                });
                hydra
                    .ingest_for_tenant(
                        EventKind::NodeCreated {
                            node_id: NodeId::from_str(&format!("node_{type_id}")),
                            type_id: type_id.to_string(),
                            properties: HashMap::new(),
                        },
                        tenant(),
                    )
                    .unwrap();
            }
        }
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get("/diagnostics/anomaly?limit=2"))
            .await
            .unwrap();
        let decoded: AnomalyResponse = read_json(response).await;
        assert_eq!(decoded.anomalies.len(), 2);
        assert_eq!(decoded.anomaly_count, 3);
        assert!(decoded.truncated);
    }

    #[tokio::test]
    async fn anomaly_id_is_stable_across_calls() {
        // Same anomaly recomputed in a second call must return the
        // same `anomaly_id` — proves the deterministic hash works
        // and operators can mute/track by id.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.anomaly_engine_mut().add_topology_rule(TopologyRule {
                node_type: "dataset".to_string(),
                edge_type: "depends_on".to_string(),
                min_degree: 1,
                max_degree: 100,
                severity: 0.7,
            });
            hydra
                .ingest_for_tenant(
                    EventKind::NodeCreated {
                        node_id: NodeId::from_str("node_stable"),
                        type_id: "dataset".to_string(),
                        properties: HashMap::new(),
                    },
                    tenant(),
                )
                .unwrap();
        }
        let app = diagnostics_router(runtime);
        let r1 = app
            .clone()
            .oneshot(empty_get("/diagnostics/anomaly"))
            .await
            .unwrap();
        let d1: AnomalyResponse = read_json(r1).await;
        let r2 = app
            .oneshot(empty_get("/diagnostics/anomaly"))
            .await
            .unwrap();
        let d2: AnomalyResponse = read_json(r2).await;
        assert!(!d1.anomalies.is_empty());
        assert_eq!(d1.anomalies[0].anomaly_id, d2.anomalies[0].anomaly_id);
    }

    #[tokio::test]
    async fn anomaly_response_carries_metadata_fields() {
        // analysis_scope == "global", engine_duration_ms set (could
        // be 0 on a very fast scan but the field is always present
        // since it's a u64).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get("/diagnostics/anomaly"))
            .await
            .unwrap();
        let decoded: AnomalyResponse = read_json(response).await;
        assert_eq!(decoded.analysis_scope, "global");
        // engine_duration_ms is non-negative by virtue of u64; we
        // mostly want to confirm the field is present in the wire
        // form. Re-decode to JSON Value and check the key exists.
        let raw = serde_json::to_value(&decoded).unwrap();
        assert!(raw.get("engine_duration_ms").is_some());
        assert!(raw.get("analysis_scope").is_some());
        assert!(raw.get("rule_count").is_some());
    }

    // === GET /diagnostics/coverage ===

    use hydra_engine::coverage::{CoverageExpectation, CoverageModel};

    fn min_node_model(name: &str, node_type: &str, min: usize) -> CoverageModel {
        CoverageModel {
            name: name.to_string(),
            expectations: vec![CoverageExpectation::MinNodeCount {
                node_type: node_type.to_string(),
                min_count: min,
            }],
            scope_node_type: None,
        }
    }

    #[tokio::test]
    async fn coverage_returns_empty_when_no_models() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get("/diagnostics/coverage"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: CoverageDiagnosticsResponse = read_json(response).await;
        assert!(decoded.reports.is_empty());
        assert_eq!(decoded.model_count, 0);
        assert_eq!(decoded.report_count, 0);
        assert!(!decoded.truncated);
        assert_eq!(decoded.analysis_scope, "global");
        assert_eq!(decoded.summary, "Coverage evaluated 0 models.");
    }

    #[tokio::test]
    async fn coverage_returns_complete_score_when_all_met() {
        // MinNodeCount(0) is trivially met by any graph state. Score
        // should be 1.0, gaps empty, met == total.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .coverage_engine_mut()
                .add_model(min_node_model("trivially_complete", "dataset", 0));
        }
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get("/diagnostics/coverage"))
            .await
            .unwrap();
        let decoded: CoverageDiagnosticsResponse = read_json(response).await;
        assert_eq!(decoded.reports.len(), 1);
        let report = &decoded.reports[0];
        assert_eq!(report.model_name, "trivially_complete");
        assert_eq!(report.score, 1.0);
        assert_eq!(report.met, 1);
        assert!(report.gaps.is_empty());
        assert!(decoded.summary.contains("100% complete"));
    }

    #[tokio::test]
    async fn coverage_returns_gaps_when_unmet() {
        // MinNodeCount(5) on `dataset` with 0 dataset nodes → score
        // 0.0, one gap with a non-empty description.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .coverage_engine_mut()
                .add_model(min_node_model("needs_5_datasets", "dataset", 5));
        }
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get("/diagnostics/coverage"))
            .await
            .unwrap();
        let decoded: CoverageDiagnosticsResponse = read_json(response).await;
        assert_eq!(decoded.reports.len(), 1);
        let report = &decoded.reports[0];
        assert_eq!(report.model_name, "needs_5_datasets");
        assert!(report.score < 1.0);
        assert_eq!(report.gaps.len(), 1);
        assert!(!report.gaps[0].description.is_empty());
    }

    #[tokio::test]
    async fn coverage_filters_by_model_name() {
        // Register two models; `?model=alpha` returns only alpha's
        // report. Unknown name returns empty (200, not 404).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .coverage_engine_mut()
                .add_model(min_node_model("alpha", "type_a", 0));
            hydra
                .coverage_engine_mut()
                .add_model(min_node_model("beta", "type_b", 0));
        }
        let app = diagnostics_router(runtime);

        let response = app
            .clone()
            .oneshot(empty_get("/diagnostics/coverage?model=alpha"))
            .await
            .unwrap();
        let decoded: CoverageDiagnosticsResponse = read_json(response).await;
        assert_eq!(decoded.reports.len(), 1);
        assert_eq!(decoded.reports[0].model_name, "alpha");
        // model_count is the engine-wide count (2), unaffected by filter
        assert_eq!(decoded.model_count, 2);

        // Unknown model name → empty reports, 200 OK, summary
        // mentions the name so operators can see why they got
        // zero results.
        let response = app
            .oneshot(empty_get("/diagnostics/coverage?model=nonexistent"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: CoverageDiagnosticsResponse = read_json(response).await;
        assert!(decoded.reports.is_empty());
        assert!(decoded.summary.contains("nonexistent"));
    }

    #[tokio::test]
    async fn coverage_filters_failing_only() {
        // Register one complete model (MinNodeCount 0) + one failing
        // model (MinNodeCount 5 with 0 nodes). ?failing_only=true
        // returns only the failing one.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .coverage_engine_mut()
                .add_model(min_node_model("complete_one", "type_a", 0));
            hydra
                .coverage_engine_mut()
                .add_model(min_node_model("failing_one", "type_b", 5));
        }
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get("/diagnostics/coverage?failing_only=true"))
            .await
            .unwrap();
        let decoded: CoverageDiagnosticsResponse = read_json(response).await;
        assert_eq!(decoded.reports.len(), 1);
        assert_eq!(decoded.reports[0].model_name, "failing_one");
        assert!(decoded.reports[0].score < 1.0);
    }

    #[tokio::test]
    async fn coverage_respects_limit_with_truncated_flag() {
        // Register 3 models, ?limit=2 → 2 reports + truncated=true,
        // report_count reflects the pre-limit count.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            for name in ["m1", "m2", "m3"] {
                hydra
                    .coverage_engine_mut()
                    .add_model(min_node_model(name, "any", 0));
            }
        }
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get("/diagnostics/coverage?limit=2"))
            .await
            .unwrap();
        let decoded: CoverageDiagnosticsResponse = read_json(response).await;
        assert_eq!(decoded.reports.len(), 2);
        assert_eq!(decoded.report_count, 3);
        assert!(decoded.truncated);
        assert_eq!(decoded.model_count, 3);
    }

    #[tokio::test]
    async fn coverage_response_carries_metadata_fields() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get("/diagnostics/coverage"))
            .await
            .unwrap();
        let decoded: CoverageDiagnosticsResponse = read_json(response).await;
        assert_eq!(decoded.analysis_scope, "global");
        let raw = serde_json::to_value(&decoded).unwrap();
        assert!(raw.get("engine_duration_ms").is_some());
        assert!(raw.get("analysis_scope").is_some());
        assert!(raw.get("model_count").is_some());
        assert!(raw.get("report_count").is_some());
        assert!(raw.get("summary").is_some());
    }

    // === GET /diagnostics/counterfactual/:event_id ===

    /// Ingest a NodeCreated event; return (runtime_handle, event_id).
    /// A NodeCreated has a measurable graph impact (the node exists
    /// only because of this event), so counterfactual analysis
    /// returns a non-empty diff.
    async fn ingest_node_created(name: &str, type_id: &str) -> (crate::runtime::RuntimeHandle, EventId) {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let event_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            let result = hydra
                .ingest_for_tenant(
                    EventKind::NodeCreated {
                        node_id: NodeId::from_str(name),
                        type_id: type_id.to_string(),
                        properties: HashMap::new(),
                    },
                    tenant(),
                )
                .unwrap();
            event_id = result.events[0].id.clone();
        }
        // Leak the processor so the runtime stays alive across the test
        // body (matches other tests in this module).
        std::mem::forget(_processor);
        (runtime, event_id)
    }

    #[tokio::test]
    async fn counterfactual_returns_404_for_unknown_event() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get("/diagnostics/counterfactual/evt_missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn counterfactual_returns_full_impact_for_known_event() {
        let (runtime, event_id) = ingest_node_created("node_cf", "type_cf").await;
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/diagnostics/counterfactual/{event_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: CounterfactualDiagnosticsResponse = read_json(response).await;
        assert_eq!(decoded.event_id, event_id);
        assert!(decoded.event_found);
        assert_eq!(decoded.counterfactual_mode, "single_event_removal");
        // Removing a NodeCreated event with no descendants → subtree
        // size of 1.
        assert!(decoded.causal_subtree_size >= 1);
        // The diff should report node_cf as only-in-actual.
        assert_eq!(decoded.nodes_affected, 1);
        assert!(decoded.diff.is_some());
        let diff = decoded.diff.unwrap();
        assert_eq!(diff.nodes_only_in_actual.len(), 1);
    }

    #[tokio::test]
    async fn counterfactual_magnitude_matches_heuristic() {
        // magnitude = 10 * nodes + 5 * edges + 1 * properties.
        // For our NodeCreated (1 node, 0 edges, 0 properties),
        // magnitude must be 10.0.
        let (runtime, event_id) = ingest_node_created("node_mag", "type_mag").await;
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/diagnostics/counterfactual/{event_id}")))
            .await
            .unwrap();
        let decoded: CounterfactualDiagnosticsResponse = read_json(response).await;
        let expected = (decoded.nodes_affected as f64) * 10.0
            + (decoded.edges_affected as f64) * 5.0
            + (decoded.properties_changed as f64) * 1.0;
        assert!(
            (decoded.magnitude - expected).abs() < f64::EPSILON,
            "magnitude {} != expected {expected}",
            decoded.magnitude
        );
    }

    #[tokio::test]
    async fn counterfactual_include_diff_false_returns_null_diff() {
        // Critical semantic test: `diff: null` is DIFFERENT from
        // `diff: { all-empty-arrays }`. With include_diff=false the
        // server returns null (transport-level omission), NOT zero
        // impact (which would be Some with empty vecs).
        let (runtime, event_id) = ingest_node_created("node_nodiff", "type_nodiff").await;
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get(&format!(
                "/diagnostics/counterfactual/{event_id}?include_diff=false"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: CounterfactualDiagnosticsResponse = read_json(response).await;
        assert!(decoded.diff.is_none(), "include_diff=false must null the diff");
        // Aggregates are still populated.
        assert_eq!(decoded.nodes_affected, 1);
        assert!(decoded.summary.contains("include_diff=false"));
        // Confirm the wire form is `null`, not `{}` — re-decode raw.
        let raw = serde_json::to_value(&decoded).unwrap();
        assert!(
            raw.get("diff").map(|v| v.is_null()).unwrap_or(false),
            "diff field must serialize as JSON null, got: {:?}",
            raw.get("diff")
        );
    }

    #[tokio::test]
    async fn counterfactual_summary_renders_facts() {
        let (runtime, event_id) = ingest_node_created("node_sum", "type_sum").await;
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/diagnostics/counterfactual/{event_id}")))
            .await
            .unwrap();
        let decoded: CounterfactualDiagnosticsResponse = read_json(response).await;
        let s = &decoded.summary;
        // Narrative covers each major axis.
        assert!(s.contains("node"), "summary must mention nodes: {s}");
        assert!(s.contains("magnitude"), "summary must mention magnitude: {s}");
        assert!(s.contains("Removing event"), "summary must lead with the seed: {s}");
    }

    #[tokio::test]
    async fn counterfactual_response_carries_metadata_fields() {
        let (runtime, event_id) = ingest_node_created("node_meta", "type_meta").await;
        let app = diagnostics_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/diagnostics/counterfactual/{event_id}")))
            .await
            .unwrap();
        let decoded: CounterfactualDiagnosticsResponse = read_json(response).await;
        assert_eq!(decoded.analysis_scope, "global");
        assert!(decoded.event_found);
        assert_eq!(decoded.counterfactual_mode, "single_event_removal");
        let raw = serde_json::to_value(&decoded).unwrap();
        assert!(raw.get("engine_duration_ms").is_some());
        assert!(raw.get("analysis_scope").is_some());
        assert!(raw.get("counterfactual_mode").is_some());
        assert!(raw.get("event_found").is_some());
        assert!(raw.get("magnitude").is_some());
        assert!(raw.get("affected_types").is_some());
    }
}
