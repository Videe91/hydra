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
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hydra_engine::anomaly::Anomaly;
use serde::{Deserialize, Serialize};
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

/// Build the diagnostics router. Currently exposes
/// `GET /diagnostics/anomaly`; future patches add `/coverage`,
/// `/counterfactual`, `/evolution` to the same router.
pub fn diagnostics_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/diagnostics/anomaly", get(get_anomaly))
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
}
