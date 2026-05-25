//! # Authentication middleware
//!
//! Minimum-viable bearer-token gate for hydra-api. Three modes, opt-in:
//!
//! - [`AuthMode::Off`]                  default. Non-breaking.
//! - [`AuthMode::RequireForMutations`]  protect POST / PUT / PATCH / DELETE.
//! - [`AuthMode::RequireForAll`]        protect every method except `OPTIONS`.
//!
//! `OPTIONS` is always allowed through so CORS preflight from browsers
//! keeps working under `RequireForAll`.
//!
//! Token check uses a constant-time comparison so timing analysis cannot
//! leak the configured secret.
//!
//! ## Tenant binding (Multi-tenant Patch 3)
//!
//! Each token can optionally bind to a [`TenantId`]. When bound:
//!
//! - The request must still carry `X-Hydra-Tenant`.
//! - The header value must equal the token's bound tenant.
//! - Token-bound tenants do NOT silently override the header — that
//!   would create the worst possible audit story (client thinks they
//!   wrote to tenant_b, server actually wrote tenant_a).
//!
//! Status codes layer cleanly:
//! - 400 — header missing or malformed (`X-Hydra-Tenant`)
//! - 401 — missing or invalid bearer token
//! - 403 — token authenticated but bound tenant ≠ header tenant
//!
//! Tenant binding is enforced only for requests that pass through the
//! auth middleware. Under `RequireForMutations`, GET requests skip auth
//! and therefore skip binding too — production deployments that want
//! per-token read isolation should use `RequireForAll`.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use hydra_core::TenantId;
use hydra_net::http::tenant::{extract_tenant, tenant_error_response};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    Off,
    RequireForMutations,
    RequireForAll,
}

/// A configured bearer token, optionally bound to a tenant.
///
/// Unbound tokens (`tenant_id = None`) authenticate any tenant
/// reachable via the `X-Hydra-Tenant` header. Bound tokens require the
/// header to equal the token's tenant — see the module docs for the
/// rationale.
#[derive(Debug, Clone)]
pub struct AuthToken {
    pub token: String,
    pub tenant_id: Option<TenantId>,
}

impl AuthToken {
    /// Token with no tenant binding — the `X-Hydra-Tenant` header
    /// alone determines the scope for the request.
    pub fn unbound(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            tenant_id: None,
        }
    }

    /// Token bound to a specific tenant. Requests using this token
    /// must carry `X-Hydra-Tenant: <tenant>` matching the binding; a
    /// mismatch returns 403.
    pub fn bound(token: impl Into<String>, tenant: TenantId) -> Self {
        Self {
            token: token.into(),
            tenant_id: Some(tenant),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub mode: AuthMode,
    tokens: Vec<AuthToken>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Off,
            tokens: Vec::new(),
        }
    }
}

impl AuthConfig {
    pub fn off() -> Self {
        Self::default()
    }

    /// Build a config with **unbound** string tokens. Backwards-
    /// compatible with pre-Patch-3 callers; tokens registered this
    /// way carry no tenant binding so any tenant header is accepted.
    pub fn require_for_mutations(tokens: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            mode: AuthMode::RequireForMutations,
            tokens: tokens.into_iter().map(AuthToken::unbound).collect(),
        }
    }

    /// Build a config with **unbound** string tokens, gating every
    /// non-OPTIONS request. Backwards-compatible.
    pub fn require_for_all(tokens: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            mode: AuthMode::RequireForAll,
            tokens: tokens.into_iter().map(AuthToken::unbound).collect(),
        }
    }

    /// Build a config with explicit [`AuthToken`]s — use this when
    /// any token needs a tenant binding.
    pub fn require_for_mutations_with_tokens(
        tokens: impl IntoIterator<Item = AuthToken>,
    ) -> Self {
        Self {
            mode: AuthMode::RequireForMutations,
            tokens: tokens.into_iter().collect(),
        }
    }

    pub fn require_for_all_with_tokens(tokens: impl IntoIterator<Item = AuthToken>) -> Self {
        Self {
            mode: AuthMode::RequireForAll,
            tokens: tokens.into_iter().collect(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.mode != AuthMode::Off
    }

    /// Should the middleware authenticate a request with this method?
    ///
    /// `OPTIONS` is exempt regardless of mode so CORS preflight passes
    /// without a bearer token.
    pub fn should_authenticate(&self, method: &Method) -> bool {
        if *method == Method::OPTIONS {
            return false;
        }
        match self.mode {
            AuthMode::Off => false,
            AuthMode::RequireForAll => true,
            AuthMode::RequireForMutations => is_mutating_method(method),
        }
    }

    pub fn has_tokens(&self) -> bool {
        !self.tokens.is_empty()
    }

    /// Look up a candidate string against the configured tokens.
    /// Returns the matching [`AuthToken`] (with its tenant binding)
    /// on hit, `None` on miss.
    ///
    /// The comparison is constant-time per token via
    /// [`constant_time_eq`]. Whether *any* token matched leaks
    /// (return is `Some` vs `None`), but the value of the matched
    /// token does not.
    pub fn token_lookup(&self, candidate: &str) -> Option<&AuthToken> {
        for token in &self.tokens {
            if constant_time_eq(token.token.as_bytes(), candidate.as_bytes()) {
                return Some(token);
            }
        }
        None
    }

    /// Convenience predicate for callers that only need "is this
    /// token configured?" Backwards-compatible with pre-Patch-3
    /// tests.
    pub fn token_is_allowed(&self, candidate: &str) -> bool {
        self.token_lookup(candidate).is_some()
    }
}

fn is_mutating_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    let value = value.trim();
    value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// Constant-time equality for token comparison.
///
/// Folds length mismatch into the difference accumulator so callers do
/// not get a trivial timing oracle off the length check alone. Walks
/// both buffers to the max length; bytes past the end of the shorter
/// buffer are compared against 0.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..max_len {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        diff |= (a ^ b) as usize;
    }
    diff == 0
}

#[derive(Debug, Clone)]
pub struct AuthState {
    pub config: AuthConfig,
}

impl AuthState {
    pub fn new(config: AuthConfig) -> Self {
        Self { config }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthErrorResponse {
    pub error: String,
}

fn auth_error(status: StatusCode, error: impl Into<String>) -> Response {
    (
        status,
        Json(AuthErrorResponse {
            error: error.into(),
        }),
    )
        .into_response()
}

/// Per-request authentication context, attached by [`auth_middleware`]
/// to the request's extensions after successful token validation.
/// Downstream layers (notably [`tenant_binding_middleware`]) read this
/// to enforce token-bound tenant scope.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub tenant_id: Option<TenantId>,
}

pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if !state.config.should_authenticate(request.method()) {
        return next.run(request).await;
    }
    if !state.config.has_tokens() {
        return auth_error(
            StatusCode::UNAUTHORIZED,
            "authentication is required but no bearer tokens are configured",
        );
    }
    let Some(token) = bearer_token(request.headers()) else {
        return auth_error(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    match state.config.token_lookup(token) {
        Some(matched) => {
            // Hand the tenant binding (if any) downstream so the
            // tenant-binding middleware can enforce match-not-override.
            request.extensions_mut().insert(AuthContext {
                tenant_id: matched.tenant_id.clone(),
            });
            next.run(request).await
        }
        None => auth_error(StatusCode::UNAUTHORIZED, "invalid bearer token"),
    }
}

/// Tenant-binding middleware (Multi-tenant Patch 3).
///
/// Runs after [`auth_middleware`] and before the route handlers.
/// Reads the [`AuthContext`] from request extensions; if the
/// authenticated token is bound to a tenant, validates that the
/// `X-Hydra-Tenant` header is present, valid, and equal to the bound
/// tenant. On mismatch returns 403 — token-bound tenants do NOT
/// silently override the header, since that would create a
/// catastrophic audit story (client thinks they wrote to tenant_b,
/// server actually wrote tenant_a).
///
/// No-op when:
/// - the request didn't pass through auth (e.g. `RequireForMutations`
///   mode on a GET), so no `AuthContext` exists
/// - the matched token has no tenant binding
pub async fn tenant_binding_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    let bound_tenant = request
        .extensions()
        .get::<AuthContext>()
        .and_then(|ctx| ctx.tenant_id.clone());
    let Some(bound) = bound_tenant else {
        return next.run(request).await;
    };
    // Token is bound — header is required and must match. Reuse the
    // same parser hydra-net handlers use so the 400 contract stays
    // consistent.
    let header_tenant = match extract_tenant(request.headers()) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };
    if header_tenant != bound {
        return auth_error(
            StatusCode::FORBIDDEN,
            format!(
                "bearer token is bound to tenant {bound}; X-Hydra-Tenant header is {header_tenant}"
            ),
        );
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equal_values() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"wrong"));
        assert!(!constant_time_eq(b"secret", b"secret-longer"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn auth_mode_require_for_mutations_only_gates_writes() {
        let config = AuthConfig::require_for_mutations(["token"]);
        assert!(!config.should_authenticate(&Method::GET));
        assert!(!config.should_authenticate(&Method::HEAD));
        assert!(config.should_authenticate(&Method::POST));
        assert!(config.should_authenticate(&Method::PUT));
        assert!(config.should_authenticate(&Method::PATCH));
        assert!(config.should_authenticate(&Method::DELETE));
    }

    #[test]
    fn options_is_exempt_in_all_modes() {
        let off = AuthConfig::off();
        let mutations = AuthConfig::require_for_mutations(["token"]);
        let all = AuthConfig::require_for_all(["token"]);
        assert!(!off.should_authenticate(&Method::OPTIONS));
        assert!(!mutations.should_authenticate(&Method::OPTIONS));
        assert!(!all.should_authenticate(&Method::OPTIONS));
    }

    #[test]
    fn token_lookup_accepts_configured_token() {
        let config = AuthConfig::require_for_all(["alpha", "beta"]);
        assert!(config.token_is_allowed("alpha"));
        assert!(config.token_is_allowed("beta"));
        assert!(!config.token_is_allowed("gamma"));
        assert!(!config.token_is_allowed(""));
    }

    #[test]
    fn bearer_token_extracts_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer abc123".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers), Some("abc123"));
    }

    #[test]
    fn bearer_token_rejects_missing_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "abc123".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn bearer_token_rejects_empty_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer ".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers), None);
    }

    // === Multi-tenant Patch 3: token binding ===

    #[test]
    fn string_token_builder_creates_unbound_tokens() {
        // Backwards-compat: pre-Patch-3 callers using the string
        // builder get tokens with no tenant binding.
        let config = AuthConfig::require_for_mutations(["alpha"]);
        let token = config.token_lookup("alpha").expect("token must match");
        assert_eq!(token.token, "alpha");
        assert!(token.tenant_id.is_none());
    }

    #[test]
    fn bound_token_builder_stores_tenant_binding() {
        let tenant = TenantId::from_str("tenant_acme");
        let config = AuthConfig::require_for_all_with_tokens([
            AuthToken::bound("alpha", tenant.clone()),
            AuthToken::unbound("beta"),
        ]);
        let alpha = config.token_lookup("alpha").expect("alpha must match");
        assert_eq!(alpha.tenant_id.as_ref(), Some(&tenant));
        let beta = config.token_lookup("beta").expect("beta must match");
        assert!(beta.tenant_id.is_none());
    }

    #[test]
    fn token_lookup_returns_none_for_unconfigured() {
        let config = AuthConfig::require_for_all(["alpha"]);
        assert!(config.token_lookup("beta").is_none());
        assert!(config.token_lookup("").is_none());
    }
}
