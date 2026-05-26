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
use std::path::PathBuf;

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
/// Enforcement is **HTTP-layer only** in this patch. In-process
/// writes (sensor bus, direct engine calls, SDK) bypass the role
/// check; an engine-level role guard is a future hardening patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeRole {
    Leader,
    Follower,
}

impl Default for RuntimeRole {
    fn default() -> Self {
        Self::Leader
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
        }
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
}

impl Default for ServerSecurityConfig {
    fn default() -> Self {
        Self::off()
    }
}
