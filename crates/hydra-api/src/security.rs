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

/// File-backed TLS configuration.
///
/// **Status**: this is a placeholder in the Rate Limiting patch.
/// The TLS patch wires `axum-server` + `rustls` and starts serving
/// HTTPS when `tls = Some(...)`. Until then `tls` MUST be `None` on
/// every [`ServerSecurityConfig`] passed to `serve_*` — non-`None`
/// values return an `Err` at server start.
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

/// Unified server-security bundle. Construct via [`Self::off`],
/// [`Self::with_auth`], or by building the struct directly when more
/// than one knob needs to be set.
#[derive(Debug, Clone)]
pub struct ServerSecurityConfig {
    pub auth: AuthConfig,
    pub tls: Option<TlsConfig>,
    pub rate_limit: RateLimitMode,
}

impl ServerSecurityConfig {
    /// All knobs off: no auth, no TLS, no rate limit. Matches the
    /// pre-`ServerSecurityConfig` `build_router` / `serve` default.
    pub fn off() -> Self {
        Self {
            auth: AuthConfig::off(),
            tls: None,
            rate_limit: RateLimitMode::Off,
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
        }
    }
}

impl Default for ServerSecurityConfig {
    fn default() -> Self {
        Self::off()
    }
}
