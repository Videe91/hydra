//! # Tenant v0 — write-boundary guard
//!
//! All mutating HTTP routes carry a tenant header. This module is the
//! single source of truth for header name, parsing, validation, and
//! error response — every route handler that mutates state extracts
//! tenant via [`extract_tenant`] and threads the result into the
//! engine's tenant-scoped methods.
//!
//! v0 contract:
//!
//! ```text
//! POST <route>
//! X-Hydra-Tenant: tenant_acme_corp
//! ```
//!
//! - Missing header → 400 with `{"error": "missing X-Hydra-Tenant header"}`
//! - Invalid value (path traversal, blank, etc) → 400 with the
//!   validator's diagnostic. `TenantId::from_str_validated` already
//!   rejects unsafe inputs (`../../...`, empty strings, etc).
//! - Valid value → the parsed [`TenantId`] is returned and the route
//!   threads it into the write (event, checkpoint, schema, snapshot).
//!
//! Read routes are not enforced in this patch. Tenant-scoped reads
//! land in Patch 2.

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hydra_core::TenantId;
use serde::{Deserialize, Serialize};

/// Canonical tenant header name. All clients use this casing; HTTP
/// header lookups are case-insensitive but tests should not rely on it.
pub const TENANT_HEADER: &str = "X-Hydra-Tenant";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantError {
    /// Header was absent from the request.
    Missing,
    /// Header was present but its value failed validation. The string
    /// is the validator's diagnostic — safe to include in the
    /// response body.
    Invalid(String),
}

/// Extract a validated `TenantId` from request headers.
///
/// Returns `Err` if the header is absent OR if its value is not a
/// safe id under [`TenantId::from_str_validated`]. Header value bytes
/// that are not UTF-8 are treated as `Invalid` (no header in the wire
/// protocol should ever be non-UTF-8 for an id, so this is the
/// honest classification).
pub fn extract_tenant(headers: &HeaderMap) -> Result<TenantId, TenantError> {
    let Some(value) = headers.get(TENANT_HEADER) else {
        return Err(TenantError::Missing);
    };
    let Ok(value) = value.to_str() else {
        return Err(TenantError::Invalid(
            "header value is not valid UTF-8".to_string(),
        ));
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(TenantError::Invalid("header value is empty".to_string()));
    }
    TenantId::from_str_validated(trimmed).map_err(TenantError::Invalid)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantErrorResponse {
    pub error: String,
}

/// Render a tenant error as an HTTP response. Always 400 — tenant
/// problems are malformed-write problems, not authentication problems
/// (auth is orthogonal and gated separately by the auth middleware).
pub fn tenant_error_response(error: TenantError) -> Response {
    let message = match error {
        TenantError::Missing => format!("missing {TENANT_HEADER} header"),
        TenantError::Invalid(reason) => format!("invalid tenant id: {reason}"),
    };
    (
        StatusCode::BAD_REQUEST,
        Json(TenantErrorResponse { error: message }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(TENANT_HEADER, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn extract_missing_header_is_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_tenant(&headers), Err(TenantError::Missing));
    }

    #[test]
    fn extract_valid_header_returns_tenant_id() {
        let headers = headers_with("tenant_acme_corp");
        let id = extract_tenant(&headers).unwrap();
        assert_eq!(id.to_string(), "tenant_acme_corp");
    }

    #[test]
    fn extract_empty_value_is_invalid() {
        let headers = headers_with("");
        assert!(matches!(
            extract_tenant(&headers),
            Err(TenantError::Invalid(_))
        ));
    }

    #[test]
    fn extract_whitespace_value_is_invalid() {
        let headers = headers_with("   ");
        assert!(matches!(
            extract_tenant(&headers),
            Err(TenantError::Invalid(_))
        ));
    }

    #[test]
    fn extract_path_traversal_value_is_invalid() {
        // TenantId::from_str_validated rejects path traversal in the
        // id itself — this guards against an attacker stashing
        // tenant-shaped strings into file paths anywhere downstream
        // (snapshot directories, commit log paths, etc).
        let headers = headers_with("../../etc/passwd");
        assert!(matches!(
            extract_tenant(&headers),
            Err(TenantError::Invalid(_))
        ));
    }

    #[test]
    fn extract_trims_surrounding_whitespace() {
        let headers = headers_with("  tenant_demo  ");
        let id = extract_tenant(&headers).unwrap();
        assert_eq!(id.to_string(), "tenant_demo");
    }

    #[test]
    fn tenant_error_response_is_400() {
        let response = tenant_error_response(TenantError::Missing);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
