//! Notify Delivery Adapter — Patch 14.
//!
//! Bridges Hydra's deterministic engine (which owns the action
//! lifecycle) and the real outside world (which receives the
//! notification over HTTP). The adapter does the network call
//! OUTSIDE the engine's write lock; the engine's
//! `execute_notify_action_with_delivery` then ingests the right
//! terminal events based on the result.
//!
//! ## Mode dispatch
//!
//! `NotifyAdapter` is an enum, not a `dyn Trait`. This avoids the
//! `async-trait` dependency (and trait-object dispatch overhead)
//! while keeping the surface extensible — future patches add new
//! variants (Slack, PagerDuty) without changing call sites.
//!
//! Hydra-api selects the mode at server-build time via
//! `NotifyDeliveryConfig`. The HTTP handler in `actions.rs`
//! either calls the original Patch 7
//! `Hydra::execute_notify_action` (Stub config) or constructs an
//! adapter, calls `deliver(...)`, and then
//! `Hydra::execute_notify_action_with_delivery(...)` (Webhook).
//!
//! ## Boundary
//!
//! - No retries, no backoff, no dead-letter queue.
//! - No secrets management (URL is plain config; auth headers
//!   are a future patch).
//! - No Slack/Discord/PagerDuty-specific code. Generic HTTP POST.
//! - Failure semantics: any non-2xx response, timeout, or network
//!   error → `DeliveryOutcome::Failed`. The `status_code` field
//!   distinguishes "receiver rejected us" (Some(...)) from "we
//!   never reached the receiver" (None).

use hydra_core::{Action, DeliveryOutcome};
use serde::Serialize;
use std::time::{Duration, Instant};

/// Idempotent process-wide install of rustls's `ring` crypto
/// provider. Required before constructing a `reqwest::Client`
/// because the workspace pulls in both `ring` (via rcgen) and
/// `aws-lc-rs` (via rustls defaults). Mirrors
/// `replication_worker::ensure_crypto_provider_installed`.
fn ensure_crypto_provider_installed() {
    static INSTALL_PROVIDER: std::sync::Once = std::sync::Once::new();
    INSTALL_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Adapter dispatcher. Mode is fixed at server-build time per
/// `NotifyDeliveryConfig`. Variants:
///
/// - `Stub`: included for symmetry with `WebhookAdapter` (returns
///   an immediate `Succeeded` outcome). The "true stub" mode in
///   `hydra-api`'s config bypasses adapters entirely and calls
///   `Hydra::execute_notify_action` (Patch 7). This variant is
///   useful for tests that exercise the Patch 14 lifecycle
///   without a real webhook server.
/// - `Webhook`: HTTP POST to the configured URL, timeout-bounded.
#[derive(Debug, Clone)]
pub enum NotifyAdapter {
    Stub(StubAdapter),
    Webhook(WebhookAdapter),
}

impl NotifyAdapter {
    /// The adapter's stable string id, projected onto the
    /// resulting Outcome's `impact.adapter`. Patch 12+ trust
    /// calibration may eventually filter by this.
    pub fn id(&self) -> &'static str {
        match self {
            NotifyAdapter::Stub(_) => "stub",
            NotifyAdapter::Webhook(_) => "webhook",
        }
    }

    /// Run delivery for `action` and produce a `DeliveryOutcome`.
    /// Async because real adapters perform HTTP I/O.
    pub async fn deliver(&self, action: &Action) -> DeliveryOutcome {
        match self {
            NotifyAdapter::Stub(s) => s.deliver(action).await,
            NotifyAdapter::Webhook(w) => w.deliver(action).await,
        }
    }
}

/// Patch 14 stub adapter — returns an immediate `Succeeded`
/// outcome with `status_code = 200` and zero latency. The
/// canonical "stub" mode in hydra-api skips this and uses
/// Patch 7's engine method directly; this type exists so the
/// Patch 14 lifecycle (engine method, HTTP orchestration, trust
/// signal) can be exercised in tests without a real webhook
/// server.
#[derive(Debug, Clone, Default)]
pub struct StubAdapter;

impl StubAdapter {
    pub fn new() -> Self {
        Self
    }

    pub async fn deliver(&self, _action: &Action) -> DeliveryOutcome {
        DeliveryOutcome::Succeeded {
            adapter: "stub".to_string(),
            status_code: 200,
            latency_ms: 0,
        }
    }
}

/// Generic webhook adapter. POSTs a deterministic JSON payload to
/// the configured URL with a hard timeout. No retries. No auth
/// headers. No template language.
#[derive(Debug, Clone)]
pub struct WebhookAdapter {
    url: String,
    timeout: Duration,
    client: reqwest::Client,
}

impl WebhookAdapter {
    /// Construct an adapter with a fresh `reqwest::Client`. For
    /// repeated use across requests prefer cloning an existing
    /// adapter rather than constructing new ones (the client
    /// reuses connections).
    ///
    /// Idempotently installs the rustls `ring` crypto provider
    /// per the workspace convention (see
    /// `replication_worker::ensure_crypto_provider_installed`).
    pub fn new(url: impl Into<String>, timeout: Duration) -> Self {
        ensure_crypto_provider_installed();
        Self {
            url: url.into(),
            timeout,
            client: reqwest::Client::new(),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Deliver `action` to the configured webhook URL. Always
    /// returns a `DeliveryOutcome` — never panics, never returns
    /// `Result::Err`. Network errors, timeouts, and non-2xx
    /// responses all map to `DeliveryOutcome::Failed`.
    pub async fn deliver(&self, action: &Action) -> DeliveryOutcome {
        let payload = build_webhook_payload(action);
        let start = Instant::now();
        let request_future = self
            .client
            .post(&self.url)
            .json(&payload)
            .send();
        let response_result = tokio::time::timeout(self.timeout, request_future).await;
        let latency_ms = start.elapsed().as_millis() as u64;

        match response_result {
            // Timeout — never got a response.
            Err(_) => DeliveryOutcome::Failed {
                adapter: "webhook".to_string(),
                reason: format!(
                    "webhook timeout after {}ms",
                    self.timeout.as_millis()
                ),
                status_code: None,
                latency_ms,
            },
            // Network / connection error — never got a response.
            Ok(Err(err)) => DeliveryOutcome::Failed {
                adapter: "webhook".to_string(),
                reason: format!("webhook network error: {err}"),
                status_code: None,
                latency_ms,
            },
            // Got an HTTP response.
            Ok(Ok(response)) => {
                let status_code = response.status().as_u16();
                if response.status().is_success() {
                    DeliveryOutcome::Succeeded {
                        adapter: "webhook".to_string(),
                        status_code,
                        latency_ms,
                    }
                } else {
                    DeliveryOutcome::Failed {
                        adapter: "webhook".to_string(),
                        reason: format!("webhook returned status {status_code}"),
                        status_code: Some(status_code),
                        latency_ms,
                    }
                }
            }
        }
    }
}

/// Deterministic JSON payload for the webhook POST.
///
/// Keep it small and predictable. Receivers see a stable shape;
/// future patches may extend with new fields but MUST NOT remove
/// or rename existing ones without a wire-format version bump.
///
/// The `targets` field is serialized as the Action's externally-
/// tagged enum form (`[{"System": "hydra"}]`, `[{"Dataset":
/// "..."}]` etc.) so receivers can pattern-match without parsing
/// a free-form list.
#[derive(Debug, Clone, Serialize)]
struct WebhookPayload<'a> {
    action_id: String,
    kind: String,
    severity: Option<&'a str>,
    reason: Option<&'a str>,
    model_id: Option<&'a str>,
    run_id: Option<&'a str>,
    targets: Vec<serde_json::Value>,
    claim_id: Option<String>,
    proposed_at: String,
}

fn build_webhook_payload(action: &Action) -> WebhookPayload<'_> {
    // Patch 4's Notify action payload carries severity, reason,
    // model_id, run_id as Value::String entries. Read defensively
    // so non-Patch-4 actions don't blow up.
    let severity = action
        .payload
        .get("severity")
        .and_then(|v| v.as_str());
    let reason = action.payload.get("reason").and_then(|v| v.as_str());
    let model_id = action.payload.get("model_id").and_then(|v| v.as_str());
    let run_id = action.payload.get("run_id").and_then(|v| v.as_str());
    let claim_id = action.related_claims.first().map(|c| c.to_string());
    let targets = action
        .targets
        .iter()
        .map(|t| serde_json::to_value(t).unwrap_or(serde_json::Value::Null))
        .collect();
    let kind = match &action.kind {
        hydra_core::ActionKind::Notify => "Notify".to_string(),
        // The Patch 14 engine method refuses non-Notify before
        // reaching the adapter, but we keep the formatting honest
        // in case a future patch broadens the adapter surface.
        other => format!("{other:?}"),
    };
    WebhookPayload {
        action_id: action.id.to_string(),
        kind,
        severity,
        reason,
        model_id,
        run_id,
        targets,
        claim_id,
        proposed_at: action.created_at.to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Router};
    use hydra_core::{ActionKind, ActionStatus, ActionTarget, ActorId, Value};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use tokio::net::TcpListener;

    fn sample_notify_action() -> Action {
        let mut payload = HashMap::new();
        payload.insert(
            "severity".to_string(),
            Value::String("critical".to_string()),
        );
        payload.insert(
            "reason".to_string(),
            Value::String("commit rate spike detected".to_string()),
        );
        payload.insert(
            "model_id".to_string(),
            Value::String("mm_builtin_commit_rate_v0".to_string()),
        );
        payload.insert(
            "run_id".to_string(),
            Value::String("mmrun_abc".to_string()),
        );
        let actor = ActorId::from_str("actor_test");
        let now = chrono::Utc::now();
        Action {
            id: hydra_core::ActionId::from_str("act_webhook_test"),
            tenant_id: None,
            kind: ActionKind::Notify,
            status: ActionStatus::Approved,
            targets: vec![ActionTarget::System("hydra".to_string())],
            related_claims: vec![hydra_core::ClaimId::from_str("claim_xyz")],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: Some(actor),
            rejected_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: Some(now),
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        }
    }

    /// Spin up a one-route axum server on a loopback port; returns
    /// the bound URL plus a handle for inspecting received bodies
    /// and configuring the response. Used to verify webhook
    /// behavior end-to-end without hardcoding ports.
    struct FakeWebhookServer {
        url: String,
        bodies: Arc<Mutex<Vec<serde_json::Value>>>,
        next_status: Arc<AtomicUsize>,
        sleep_before_response_ms: Arc<AtomicUsize>,
    }

    impl FakeWebhookServer {
        async fn start() -> Self {
            let bodies = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
            let next_status = Arc::new(AtomicUsize::new(204));
            let sleep_ms = Arc::new(AtomicUsize::new(0));
            let bodies_clone = bodies.clone();
            let next_status_clone = next_status.clone();
            let sleep_ms_clone = sleep_ms.clone();
            let app = Router::new().route(
                "/hook",
                post(move |body: axum::Json<serde_json::Value>| {
                    let bodies = bodies_clone.clone();
                    let status_ref = next_status_clone.clone();
                    let sleep_ref = sleep_ms_clone.clone();
                    async move {
                        let sleep_ms = sleep_ref.load(Ordering::SeqCst);
                        if sleep_ms > 0 {
                            tokio::time::sleep(Duration::from_millis(
                                sleep_ms as u64,
                            ))
                            .await;
                        }
                        bodies.lock().unwrap().push(body.0);
                        let status_code = status_ref.load(Ordering::SeqCst) as u16;
                        axum::http::StatusCode::from_u16(status_code)
                            .unwrap_or(axum::http::StatusCode::OK)
                    }
                }),
            );
            let listener =
                TcpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                    .await
                    .unwrap();
            let addr = listener.local_addr().unwrap();
            let url = format!("http://{addr}/hook");
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                url,
                bodies,
                next_status,
                sleep_before_response_ms: sleep_ms,
            }
        }

        fn url(&self) -> &str {
            &self.url
        }

        fn set_next_status(&self, status: u16) {
            self.next_status.store(status as usize, Ordering::SeqCst);
        }

        fn set_sleep_ms(&self, ms: u64) {
            self.sleep_before_response_ms
                .store(ms as usize, Ordering::SeqCst);
        }

        fn received_bodies(&self) -> Vec<serde_json::Value> {
            self.bodies.lock().unwrap().clone()
        }
    }

    #[tokio::test]
    async fn webhook_adapter_receives_expected_payload_shape() {
        let server = FakeWebhookServer::start().await;
        let adapter = WebhookAdapter::new(server.url(), Duration::from_secs(2));
        let action = sample_notify_action();
        let outcome = adapter.deliver(&action).await;

        assert!(outcome.is_succeeded(), "outcome: {outcome:?}");
        let bodies = server.received_bodies();
        assert_eq!(bodies.len(), 1);
        let body = &bodies[0];
        assert_eq!(body["action_id"], "act_webhook_test");
        assert_eq!(body["kind"], "Notify");
        assert_eq!(body["severity"], "critical");
        assert_eq!(body["reason"], "commit rate spike detected");
        assert_eq!(body["model_id"], "mm_builtin_commit_rate_v0");
        assert_eq!(body["run_id"], "mmrun_abc");
        assert_eq!(body["claim_id"], "claim_xyz");
        // targets is the externally-tagged enum form.
        assert_eq!(body["targets"][0]["System"], "hydra");
    }

    #[tokio::test]
    async fn webhook_adapter_2xx_returns_succeeded() {
        let server = FakeWebhookServer::start().await;
        server.set_next_status(202);
        let adapter = WebhookAdapter::new(server.url(), Duration::from_secs(2));
        let outcome = adapter.deliver(&sample_notify_action()).await;
        match outcome {
            DeliveryOutcome::Succeeded {
                status_code,
                latency_ms,
                ..
            } => {
                assert_eq!(status_code, 202);
                // latency is measured; even a fast localhost POST
                // has at least 1ms. Just assert it's bounded.
                assert!(latency_ms < 5000);
            }
            other => panic!("expected Succeeded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn webhook_adapter_5xx_returns_failed_with_status_code() {
        let server = FakeWebhookServer::start().await;
        server.set_next_status(500);
        let adapter = WebhookAdapter::new(server.url(), Duration::from_secs(2));
        let outcome = adapter.deliver(&sample_notify_action()).await;
        match outcome {
            DeliveryOutcome::Failed {
                status_code,
                reason,
                ..
            } => {
                assert_eq!(status_code, Some(500));
                assert!(reason.contains("500"), "reason: {reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn webhook_adapter_4xx_returns_failed_with_status_code() {
        // 4xx (receiver rejected the payload) is also a delivery
        // failure for v0. The status_code carries the semantic.
        let server = FakeWebhookServer::start().await;
        server.set_next_status(400);
        let adapter = WebhookAdapter::new(server.url(), Duration::from_secs(2));
        let outcome = adapter.deliver(&sample_notify_action()).await;
        match outcome {
            DeliveryOutcome::Failed {
                status_code, ..
            } => assert_eq!(status_code, Some(400)),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn webhook_adapter_timeout_returns_failed_with_no_status_code() {
        // Server sleeps past the timeout — adapter must return
        // Failed with status_code=None (we never got a response).
        let server = FakeWebhookServer::start().await;
        server.set_sleep_ms(500);
        let adapter = WebhookAdapter::new(server.url(), Duration::from_millis(100));
        let outcome = adapter.deliver(&sample_notify_action()).await;
        match outcome {
            DeliveryOutcome::Failed {
                status_code,
                reason,
                ..
            } => {
                assert_eq!(status_code, None);
                assert!(reason.contains("timeout"), "reason: {reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stub_adapter_returns_succeeded() {
        let adapter = StubAdapter::new();
        let outcome = adapter.deliver(&sample_notify_action()).await;
        match outcome {
            DeliveryOutcome::Succeeded {
                adapter,
                status_code,
                ..
            } => {
                assert_eq!(adapter, "stub");
                assert_eq!(status_code, 200);
            }
            other => panic!("expected Succeeded, got {other:?}"),
        }
    }
}
