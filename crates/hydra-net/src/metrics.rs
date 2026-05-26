//! V2 polish — metrics recorder hooks.
//!
//! Hydra emits replication observability via a dumb 2-method trait
//! [`MetricsRecorder`]. Operators bring their own backend (OTel,
//! Datadog statsd, Prometheus client lib, custom) via a small
//! adapter — we don't depend on any of those crates ourselves.
//!
//! For operators who just want a working `/metrics` endpoint
//! without external deps, [`PrometheusTextRecorder`] is a stdlib-only
//! in-process aggregator that renders the Prometheus text exposition
//! format. Pair it with [`metrics_router`] to expose `/metrics`.
//!
//! ## What's emitted (V2 polish)
//!
//! The replication puller emits these series when configured with a
//! recorder. All carry a `peer_id` label.
//!
//! **Counters**:
//!   - `hydra_replication_pull_attempts_total{outcome="ok|transient|fatal"}`
//!   - `hydra_replication_commits_fetched_total`
//!   - `hydra_replication_commits_applied_total`
//!   - `hydra_replication_bootstraps_total{outcome="ok|fatal"}`
//!
//! **Gauges**:
//!   - `hydra_replication_lag_commits`
//!   - `hydra_replication_leader_head_sequence`
//!   - `hydra_replication_follower_cursor_sequence`
//!   - `hydra_replication_consecutive_failures`
//!
//! ## What's NOT here (deferred)
//!
//!   - Histograms (pull / bootstrap durations) — need bucket config
//!   - OTel adapter — separate crate / module
//!   - Engine-level metrics (commit_count, node_count, schema_count)
//!   - `# HELP` registry — only `# TYPE` for v0
//!   - Metric-name validation (recorder accepts what callers pass)
//!   - Auth gating on `/metrics` — operators add to
//!     `required_scopes_for` themselves if exposing externally

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// V2 polish — metrics-emission interface used by the replication
/// puller (and future engine-side emitters). Implementations decide
/// how to aggregate and expose: in-memory + Prometheus text, OTel
/// meter providers, Datadog dogstatsd, custom log line per call,
/// etc.
///
/// **Two methods only**. No histograms. Bulk counters are accumulated
/// by calling `increment_counter` once per event (typical
/// per-iteration counts are 1; commit application is bounded by the
/// puller's `page_limit` which clamps to 500).
///
/// Implementations must be `Send + Sync` so `Arc<dyn MetricsRecorder>`
/// can be cloned into the puller and other emitters.
pub trait MetricsRecorder: Send + Sync + std::fmt::Debug {
    /// Increment a counter by 1. Use repeated calls for bulk events.
    fn increment_counter(&self, name: &str, labels: &[(&str, &str)]);
    /// Set a gauge to a current value. Subsequent calls overwrite.
    fn set_gauge(&self, name: &str, labels: &[(&str, &str)], value: f64);
}

/// V2 polish — no-op recorder. Used as the default when no recorder
/// is configured on the puller; lets the puller's recording sites
/// `Option::map`-out cleanly without `if let` branching at every
/// call.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopRecorder;

impl MetricsRecorder for NoopRecorder {
    fn increment_counter(&self, _name: &str, _labels: &[(&str, &str)]) {}
    fn set_gauge(&self, _name: &str, _labels: &[(&str, &str)], _value: f64) {}
}

/// Canonicalized series identity. Labels are sorted lexicographically
/// by key so `(peer_id, outcome)` and `(outcome, peer_id)` map to the
/// same series.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SeriesKey {
    name: String,
    labels: Vec<(String, String)>,
}

impl SeriesKey {
    fn build(name: &str, labels: &[(&str, &str)]) -> Self {
        let mut labels: Vec<(String, String)> = labels
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        labels.sort_by(|a, b| a.0.cmp(&b.0));
        Self {
            name: name.to_string(),
            labels,
        }
    }
}

#[derive(Debug, Default)]
struct MetricsState {
    counters: HashMap<SeriesKey, f64>,
    gauges: HashMap<SeriesKey, f64>,
}

/// V2 polish — in-process Prometheus-text exposition recorder.
///
/// Aggregates counters and gauges in memory; `render()` emits the
/// standard Prometheus text exposition format
/// (`text/plain; version=0.0.4`).
///
/// Storage: two `HashMap<SeriesKey, f64>` keyed by canonicalized
/// (name + sorted labels). `std::sync::Mutex` is fine here — the
/// trait methods never hold the lock across an `.await`.
///
/// Operators wire it via:
///
/// ```ignore
/// let recorder = Arc::new(PrometheusTextRecorder::new());
/// config.metrics = Some(recorder.clone());
/// router.merge(metrics_router(recorder))
/// ```
#[derive(Debug)]
pub struct PrometheusTextRecorder {
    state: Mutex<MetricsState>,
}

impl PrometheusTextRecorder {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MetricsState::default()),
        }
    }

    /// Render the current snapshot as Prometheus text. Groups by
    /// metric name; emits one `# TYPE` line per series followed by
    /// one sample per labelset. Sample lines are deterministically
    /// ordered (sorted by canonical label key) so tests can
    /// string-compare and operators see stable output.
    pub fn render(&self) -> String {
        let state = self.state.lock().unwrap();
        // Group by metric name. Within each name, collect all
        // labelsets + values.
        let mut counter_by_name: HashMap<&str, Vec<(&[(String, String)], f64)>> =
            HashMap::new();
        for (key, value) in &state.counters {
            counter_by_name
                .entry(key.name.as_str())
                .or_default()
                .push((&key.labels, *value));
        }
        let mut gauge_by_name: HashMap<&str, Vec<(&[(String, String)], f64)>> =
            HashMap::new();
        for (key, value) in &state.gauges {
            gauge_by_name
                .entry(key.name.as_str())
                .or_default()
                .push((&key.labels, *value));
        }

        // Deterministic ordering for stable output.
        let mut counter_names: Vec<&str> = counter_by_name.keys().copied().collect();
        counter_names.sort_unstable();
        let mut gauge_names: Vec<&str> = gauge_by_name.keys().copied().collect();
        gauge_names.sort_unstable();

        let mut out = String::new();
        for name in counter_names {
            out.push_str(&format!("# TYPE {name} counter\n"));
            let mut series = counter_by_name.remove(name).unwrap();
            series.sort_by(|a, b| a.0.cmp(b.0));
            for (labels, value) in series {
                emit_sample(&mut out, name, labels, value);
            }
        }
        for name in gauge_names {
            out.push_str(&format!("# TYPE {name} gauge\n"));
            let mut series = gauge_by_name.remove(name).unwrap();
            series.sort_by(|a, b| a.0.cmp(b.0));
            for (labels, value) in series {
                emit_sample(&mut out, name, labels, value);
            }
        }
        out
    }
}

impl Default for PrometheusTextRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRecorder for PrometheusTextRecorder {
    fn increment_counter(&self, name: &str, labels: &[(&str, &str)]) {
        let key = SeriesKey::build(name, labels);
        let mut state = self.state.lock().unwrap();
        *state.counters.entry(key).or_insert(0.0) += 1.0;
    }

    fn set_gauge(&self, name: &str, labels: &[(&str, &str)], value: f64) {
        let key = SeriesKey::build(name, labels);
        let mut state = self.state.lock().unwrap();
        state.gauges.insert(key, value);
    }
}

fn emit_sample(out: &mut String, name: &str, labels: &[(String, String)], value: f64) {
    if labels.is_empty() {
        out.push_str(&format!("{name} {value}\n"));
        return;
    }
    out.push_str(name);
    out.push('{');
    for (i, (k, v)) in labels.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(k);
        out.push_str("=\"");
        out.push_str(&escape_label_value(v));
        out.push('"');
    }
    out.push_str(&format!("}} {value}\n"));
}

/// Prometheus exposition requires escaping backslash, quote, and
/// newline in label values.
fn escape_label_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// V2 polish — mount `GET /metrics` on a router fronted by the given
/// recorder. Returns `text/plain; version=0.0.4` (the Prometheus
/// exposition content-type) and a body produced by
/// [`PrometheusTextRecorder::render`].
///
/// Auth gating is NOT applied here — operators who expose `/metrics`
/// externally should add it to their `required_scopes_for` table
/// (e.g. require a `read:metrics` or `read:audit` scope).
pub fn metrics_router(recorder: Arc<PrometheusTextRecorder>) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(recorder)
}

async fn metrics_handler(
    State(recorder): State<Arc<PrometheusTextRecorder>>,
) -> impl IntoResponse {
    let body = recorder.render();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tower::ServiceExt;

    #[test]
    fn prometheus_text_recorder_renders_counters_and_gauges() {
        let r = PrometheusTextRecorder::new();
        r.increment_counter(
            "hydra_replication_pull_attempts_total",
            &[("peer_id", "replica_acme"), ("outcome", "ok")],
        );
        r.increment_counter(
            "hydra_replication_pull_attempts_total",
            &[("peer_id", "replica_acme"), ("outcome", "ok")],
        );
        r.increment_counter(
            "hydra_replication_pull_attempts_total",
            &[("peer_id", "replica_acme"), ("outcome", "transient")],
        );
        r.set_gauge(
            "hydra_replication_lag_commits",
            &[("peer_id", "replica_acme")],
            42.0,
        );
        // Overwrite with a fresher value — gauge replaces.
        r.set_gauge(
            "hydra_replication_lag_commits",
            &[("peer_id", "replica_acme")],
            7.0,
        );

        let rendered = r.render();

        // # TYPE header per series name.
        assert!(rendered.contains("# TYPE hydra_replication_pull_attempts_total counter\n"));
        assert!(rendered.contains("# TYPE hydra_replication_lag_commits gauge\n"));

        // Counter samples: 2 hits at outcome=ok, 1 at transient.
        // Labels canonicalized alphabetically (outcome, peer_id).
        assert!(rendered.contains(
            "hydra_replication_pull_attempts_total{outcome=\"ok\",peer_id=\"replica_acme\"} 2\n"
        ));
        assert!(rendered.contains(
            "hydra_replication_pull_attempts_total{outcome=\"transient\",peer_id=\"replica_acme\"} 1\n"
        ));

        // Gauge sample reflects the LATEST set, not the first.
        assert!(rendered.contains(
            "hydra_replication_lag_commits{peer_id=\"replica_acme\"} 7\n"
        ));
    }

    #[test]
    fn prometheus_text_recorder_label_cardinality_bounded() {
        let r = PrometheusTextRecorder::new();

        // Same name + same labels (any order) → one series.
        r.increment_counter("hydra_foo", &[("a", "1"), ("b", "2")]);
        r.increment_counter("hydra_foo", &[("b", "2"), ("a", "1")]); // reverse order
        r.increment_counter("hydra_foo", &[("a", "1"), ("b", "2")]);

        // Different labels → distinct series.
        r.increment_counter("hydra_foo", &[("a", "1"), ("b", "3")]);

        let rendered = r.render();
        // Three increments to {a=1,b=2} (the order-swap canonicalized
        // to the same key) and one to {a=1,b=3}.
        assert!(rendered.contains("hydra_foo{a=\"1\",b=\"2\"} 3\n"));
        assert!(rendered.contains("hydra_foo{a=\"1\",b=\"3\"} 1\n"));
        // Exactly one TYPE header for the series name.
        assert_eq!(
            rendered.matches("# TYPE hydra_foo counter").count(),
            1
        );
    }

    #[tokio::test]
    async fn metrics_router_serves_prometheus_text() {
        let recorder = Arc::new(PrometheusTextRecorder::new());
        recorder.set_gauge("hydra_test_gauge", &[("peer_id", "replica_x")], 5.0);

        let app = metrics_router(recorder);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(content_type, "text/plain; version=0.0.4");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(body_str.contains("# TYPE hydra_test_gauge gauge\n"));
        assert!(body_str
            .contains("hydra_test_gauge{peer_id=\"replica_x\"} 5\n"));
    }

    #[test]
    fn noop_recorder_is_zero_cost() {
        // Sanity: NoopRecorder accepts all calls and produces nothing.
        let r = NoopRecorder;
        r.increment_counter("anything", &[("k", "v")]);
        r.set_gauge("anything", &[("k", "v")], 1.0);
    }

    #[test]
    fn label_values_get_escaped() {
        let r = PrometheusTextRecorder::new();
        // Backslash, quote, and newline must be escaped per the
        // Prometheus exposition format.
        r.set_gauge(
            "hydra_test_escape",
            &[("peer_id", "tricky\\value\"with\nnewline")],
            1.0,
        );
        let rendered = r.render();
        assert!(rendered.contains(
            "hydra_test_escape{peer_id=\"tricky\\\\value\\\"with\\nnewline\"} 1\n"
        ));
    }
}
