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

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    Off,
    RequireForMutations,
    RequireForAll,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub mode: AuthMode,
    tokens: HashSet<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Off,
            tokens: HashSet::new(),
        }
    }
}

impl AuthConfig {
    pub fn off() -> Self {
        Self::default()
    }

    pub fn require_for_mutations(tokens: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            mode: AuthMode::RequireForMutations,
            tokens: tokens.into_iter().map(Into::into).collect(),
        }
    }

    pub fn require_for_all(tokens: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            mode: AuthMode::RequireForAll,
            tokens: tokens.into_iter().map(Into::into).collect(),
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

    pub fn token_is_allowed(&self, candidate: &str) -> bool {
        self.tokens
            .iter()
            .any(|token| constant_time_eq(token.as_bytes(), candidate.as_bytes()))
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

pub async fn auth_middleware(
    State(state): State<AuthState>,
    request: Request<Body>,
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
    if !state.config.token_is_allowed(token) {
        return auth_error(StatusCode::UNAUTHORIZED, "invalid bearer token");
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
}
