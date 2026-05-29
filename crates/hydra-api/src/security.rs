//! # Server security configuration
//!
//! Single config bundle covering the three security knobs every
//! production deployment of hydra-api cares about:
//!
//!   - **Auth** — bearer-token gate (delegated to [`AuthConfig`]).
//!   - **TLS** — file-backed cert + key (placeholder in this patch;
//!     wired up by TLS patch).
//!   - **Rate limit** — per-IP token bucket via `tower_governor`.
//!
//! [`ServerSecurityConfig`] replaces the matrix of `serve_*` /
//! `serve_*_with_auth` / `serve_persistent_*` etc. signatures that
//! would otherwise explode as TLS, rate limiting, and any future
//! security knob land. Existing `*_with_auth` entry points become
//! thin wrappers over the unified config.

use crate::auth::AuthConfig;
use hydra_core::ReplicaId;
use hydra_net::replication_worker::ReplicationPullerConfig;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// File-backed TLS configuration. PEM-encoded cert + key paths.
///
/// `serve_with_security` and `serve_persistent_with_security` route
/// requests through `axum-server` + `rustls` when this is `Some`.
/// PEM-string-only config is intentionally not supported in v0 —
/// operators usually mount files; adding a separate
/// "from-string" path doubles the test surface for a feature nobody
/// has asked for yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Rate-limit policy applied to inbound requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitMode {
    /// No rate limiting. Default; preserves pre-Rate-Limiting
    /// behavior.
    Off,
    /// Per-peer-IP token bucket. `per_second` is the steady-state
    /// refill rate (tokens / second); `burst` is the bucket
    /// capacity. Requests beyond `burst` within the refill window
    /// get a `429 Too Many Requests` with a `Retry-After` header.
    ///
    /// Important: "peer IP" is the TCP peer the server actually
    /// accepted. If hydra-api sits behind a reverse proxy, every
    /// request looks like the proxy IP and this mode becomes a
    /// global limit. Operators with a trusted proxy should switch
    /// to an `X-Forwarded-For`-aware extractor in a future patch;
    /// it's not in v0 because trusted-proxy configuration is its
    /// own design surface.
    PerIp {
        per_second: u64,
        burst: u32,
    },
}

/// V2 patch 4H — node role in the replication cluster.
///
/// `Leader` (default) accepts every route — pre-4H behavior.
/// `Follower` rejects engine-mutating POST/PUT/PATCH/DELETE routes
/// with `409 Conflict` ({"error": "follower is read-only"}). The
/// follower still accepts `POST /replication/apply` (its primary
/// receiving route) and `POST /schemas/validate/*` (preflight, no
/// mutation), plus all `GET`/`OPTIONS`.
///
/// Enforcement is HTTP-layer (4H) **and** engine-layer (polish #5).
/// The two roles (`RuntimeRole` here, `hydra_engine::EngineRole`)
/// are independent types in independent crates; polish #6's
/// role-flip route keeps them in lockstep.
///
/// V2 polish #6 — the canonical definition moved to
/// `hydra_net::role::RuntimeRole` so both the HTTP middleware
/// (here in hydra-api) and the role-flip handler (in hydra-net)
/// can share a single atomic. Re-exported for backward compat with
/// pre-#6 callers that imported `hydra_api::security::RuntimeRole`.
pub use hydra_net::role::RuntimeRole;

/// V2 patch 4I — server-side replication worker config.
///
/// Wraps a `ReplicationPullerConfig` plus an optional shutdown
/// `CancellationToken`. When attached to `ServerSecurityConfig` via
/// `with_replication`, `serve_with_security` auto-spawns the puller
/// loop and cancels it on server shutdown.
///
/// **Role coupling is intentional NOT-automatic**: a Leader may
/// configure replication (upstream-chained node), and a Follower
/// without replication is technically valid (read-only mirror with
/// no replication source). Operators decide.
///
/// **Worker fatal does NOT kill the server**: if the puller exits
/// with a `ReplicationLoopError`, the HTTP server keeps serving so
/// operators can fix the upstream and restart. The exit is logged
/// via `tracing::warn`.
#[derive(Debug, Clone)]
pub struct ReplicationServerConfig {
    pub puller: ReplicationPullerConfig,
    /// Operator-supplied shutdown token. `None` means
    /// `serve_with_security` creates an internal token tied to the
    /// server's lifecycle. `Some(token)` lets operators coordinate
    /// multi-worker shutdown.
    pub shutdown: Option<CancellationToken>,
}

impl ReplicationServerConfig {
    pub fn new(puller: ReplicationPullerConfig) -> Self {
        Self {
            puller,
            shutdown: None,
        }
    }

    /// Attach a caller-supplied cancellation token. When the operator
    /// fires it, the worker drains; when `serve_with_security`
    /// returns, the server fires its own internal token too — both
    /// paths trigger the same shutdown handler.
    pub fn with_shutdown(mut self, token: CancellationToken) -> Self {
        self.shutdown = Some(token);
        self
    }
}

/// Notify delivery mode (Patch 14).
///
/// `Stub` → `POST /actions/:id/execute` calls
/// `Hydra::execute_notify_action` (Patch 7 stub semantic; no
/// network I/O). Default on `off()` to preserve back-compat.
///
/// `Webhook { url, timeout_ms }` → the route's HTTP handler builds
/// a `WebhookAdapter` and orchestrates real delivery before
/// invoking `Hydra::execute_notify_action_with_delivery`.
///
/// No retries / backoff / DLQ. No auth headers. No template
/// language. Future patches add adapter variants (Slack,
/// PagerDuty) and adapter-side config.
#[derive(Debug, Clone)]
pub enum NotifyDeliveryConfig {
    Stub,
    Webhook { url: String, timeout_ms: u64 },
}

impl Default for NotifyDeliveryConfig {
    fn default() -> Self {
        NotifyDeliveryConfig::Stub
    }
}

/// Unified server-security bundle. Construct via [`Self::off`],
/// [`Self::with_auth`], or by building the struct directly when more
/// than one knob needs to be set.
#[derive(Debug, Clone)]
pub struct ServerSecurityConfig {
    pub auth: AuthConfig,
    pub tls: Option<TlsConfig>,
    pub rate_limit: RateLimitMode,
    /// V2 patch 4H — runtime role gate. Defaults to `Leader`
    /// (pre-4H behavior).
    pub role: RuntimeRole,
    /// V2 patch 4I — optional replication worker. When `Some`,
    /// `serve_with_security` spawns the puller and drains it on
    /// shutdown. Default `None` for back-compat.
    pub replication: Option<ReplicationServerConfig>,
    /// V2 next-level — this node's own `ReplicaId`, used by the
    /// `POST /replication/promote` admin route to stamp the
    /// `ReplicaPromoted` audit commit with the right peer id.
    /// `None` (default) → the promote route is NOT installed (the
    /// node has no identity in the cluster yet, so promotion is
    /// meaningless). Operators wanting failover capability set
    /// this explicitly at boot.
    pub self_peer_id: Option<ReplicaId>,
    /// Patch 14 — Notify delivery mode. Default `Stub` preserves
    /// Patch 7 behavior; operators opt into real webhook delivery
    /// via `.with_notify_webhook(url, timeout_ms)`.
    pub notify_delivery: NotifyDeliveryConfig,
}

impl ServerSecurityConfig {
    /// All knobs off: no auth, no TLS, no rate limit. Matches the
    /// pre-`ServerSecurityConfig` `build_router` / `serve` default.
    pub fn off() -> Self {
        Self {
            auth: AuthConfig::off(),
            tls: None,
            rate_limit: RateLimitMode::Off,
            role: RuntimeRole::Leader,
            replication: None,
            self_peer_id: None,
            notify_delivery: NotifyDeliveryConfig::Stub,
        }
    }

    /// Auth only. Replaces the explicit
    /// `build_router_with_auth(runtime, auth)` for callers that want
    /// to compose more knobs later without changing call sites.
    pub fn with_auth(auth: AuthConfig) -> Self {
        Self {
            auth,
            tls: None,
            rate_limit: RateLimitMode::Off,
            role: RuntimeRole::Leader,
            replication: None,
            self_peer_id: None,
            notify_delivery: NotifyDeliveryConfig::Stub,
        }
    }

    /// Patch 14 — opt into real webhook Notify delivery. Sets
    /// `notify_delivery = Webhook { url, timeout_ms }`. The HTTP
    /// handler at `POST /actions/:id/execute` will build a
    /// `WebhookAdapter` and orchestrate delivery before invoking
    /// the engine's `execute_notify_action_with_delivery`.
    pub fn with_notify_webhook(mut self, url: impl Into<String>, timeout_ms: u64) -> Self {
        self.notify_delivery = NotifyDeliveryConfig::Webhook {
            url: url.into(),
            timeout_ms,
        };
        self
    }

    /// Builder: attach a TLS configuration. Chainable with the other
    /// constructors so production wire-up reads top-to-bottom:
    ///
    /// ```ignore
    /// ServerSecurityConfig::with_auth(auth)
    ///     .with_tls(TlsConfig { cert_path, key_path })
    ///     .with_rate_limit(RateLimitMode::PerIp { per_second: 50, burst: 100 })
    /// ```
    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Builder: attach a rate-limit policy. See [`Self::with_tls`]
    /// for the chaining pattern.
    pub fn with_rate_limit(mut self, rate_limit: RateLimitMode) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    /// V2 patch 4H — set the runtime role (Leader / Follower).
    /// `Follower` gates engine-mutating POST/PUT/PATCH/DELETE
    /// routes with `409 Conflict`. See [`RuntimeRole`].
    pub fn with_role(mut self, role: RuntimeRole) -> Self {
        self.role = role;
        self
    }

    /// V2 patch 4I — attach a replication worker config. When set,
    /// `serve_with_security` spawns the puller and drains it on
    /// server shutdown. Worker fatal does NOT tear down the server.
    pub fn with_replication(mut self, replication: ReplicationServerConfig) -> Self {
        self.replication = Some(replication);
        self
    }

    /// V2 next-level — set this node's own `ReplicaId`. Required
    /// for the `POST /replication/promote` admin route; absent it
    /// the promote route is not installed. The id is stamped into
    /// the `ReplicaPromoted` audit commit emitted on a successful
    /// promotion.
    pub fn with_self_peer_id(mut self, id: ReplicaId) -> Self {
        self.self_peer_id = Some(id);
        self
    }
}

impl Default for ServerSecurityConfig {
    fn default() -> Self {
        Self::off()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_security_config_off_defaults_to_stub_notify_delivery() {
        // Patch 14 — `off()` MUST default to Stub so existing
        // deployments preserve Patch 7 behavior bit-identically.
        // Pinned so a future refactor can't silently flip the
        // default to Webhook (which would require a URL).
        let cfg = ServerSecurityConfig::off();
        assert!(matches!(cfg.notify_delivery, NotifyDeliveryConfig::Stub));
    }

    #[test]
    fn server_security_config_with_notify_webhook_builder_sets_config() {
        let cfg = ServerSecurityConfig::off()
            .with_notify_webhook("http://localhost:9000/hook", 1500);
        match cfg.notify_delivery {
            NotifyDeliveryConfig::Webhook { url, timeout_ms } => {
                assert_eq!(url, "http://localhost:9000/hook");
                assert_eq!(timeout_ms, 1500);
            }
            other => panic!("expected Webhook, got {other:?}"),
        }
    }
}
