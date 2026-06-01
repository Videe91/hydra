//! # Patch 31 — Identity Graph HTTP surface
//!
//! Exposes the Patch 29 / Patch 30 engine surface as four routes:
//!
//! ```text
//! POST /identity/entities                 — create a canonical entity
//! GET  /identity/entities/:entity_id      — single-entity lookup
//! GET  /identity/entities                  — paginated list (or ?kind= filter)
//! GET  /identity/matches                   — semantic suggestion (P30)
//! ```
//!
//! ## Auth
//!
//! Two new scopes:
//!
//! - `read:identity` — `GET /identity/*`
//! - `write:identity` — `POST /identity/entities` (and any future
//!   POSTs under the `/identity/*` namespace)
//!
//! Identity is its own concern (not graph data, not trust) so the
//! scopes are dedicated rather than reusing `read:query` /
//! `write:diagnostics`.
//!
//! ## Tenant isolation (strict)
//!
//! `X-Hydra-Tenant` REQUIRED on every route. `None`-tenanted
//! (system) entities are INVISIBLE to all public routes —
//! mirrors P25/P29. The engine method
//! `Hydra::create_identity_entity` accepts `Option<TenantId>` but
//! the HTTP layer overwrites the body's `tenant_id` with the
//! header value so a caller can't smuggle `None` or a different
//! tenant.
//!
//! ## Response shapes
//!
//! - Single: `{ "entity": IdentityEntity }`
//! - Paginated list: `{ "entities": [...], "next_cursor": "id|null" }`
//! - Filtered list (kind=): `{ "entities": [...] }`
//! - Matcher: `{ "assessment": SemanticIdentityMatchAssessment }`

use crate::http::pagination::{normalized_limit, PaginationQuery};
use crate::http::tenant::{extract_tenant, tenant_error_response};
use crate::query::QueryService;
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hydra_core::{
    IdentityAlias, IdentityEntity, IdentityEntityId, IdentityEntityKind,
    IdentityLink, IdentityLinkId, IdentityLinkKind,
    SemanticIdentityMatchAssessment,
};
use serde::{Deserialize, Serialize};

/// Shared HTTP state for the identity routes.
///
/// `service` for the reads (P25 pattern), `runtime` for the
/// write path (P27 pattern — handler acquires the engine write
/// lock to call `Hydra::create_identity_entity`).
#[derive(Clone)]
pub struct IdentityHttpState {
    pub service: QueryService,
    pub runtime: RuntimeHandle,
}

impl IdentityHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self {
            service: QueryService::new(runtime.hydra()),
            runtime,
        }
    }
}

/// Build the identity router. Eight routes (Patch 31 entities +
/// matches; Patch 38 links + entity-scoped links):
///
/// - `POST /identity/entities`                     — P31 create
/// - `GET  /identity/entities/:entity_id`          — P31 single read
/// - `GET  /identity/entities/:entity_id/links`    — P38 entity link neighborhood
/// - `GET  /identity/entities` (with `?kind=`/`?after=`/`?limit=`) — P31 list
/// - `GET  /identity/matches` (required `?source=`+`?normalized=`) — P31 matcher
/// - `POST /identity/links`                        — P38 create link
/// - `GET  /identity/links/:link_id`               — P38 single read
/// - `GET  /identity/links` (with filter/pagination) — P38 list
///
/// **Route ordering note** (LOAD-BEARING): the entity-scoped link
/// route `/identity/entities/:entity_id/links` is registered
/// alongside the bare `:entity_id` route. Axum's trie correctly
/// prefers the longer literal-segment match, but we pin both
/// routes hit distinct handlers via test.
pub fn identity_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route(
            "/identity/entities/:entity_id/links",
            get(list_links_for_entity),
        )
        .route(
            "/identity/entities/:entity_id",
            get(get_identity_entity),
        )
        .route(
            "/identity/entities",
            get(list_identity_entities).post(create_identity_entity),
        )
        .route("/identity/matches", get(suggest_identity_matches))
        .route("/identity/links/:link_id", get(get_identity_link))
        .route(
            "/identity/links",
            get(list_identity_links).post(create_identity_link),
        )
        .with_state(IdentityHttpState::new(runtime))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEntityResponse {
    pub entity: IdentityEntity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEntitiesListResponse {
    pub entities: Vec<IdentityEntity>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEntitiesFilteredResponse {
    pub entities: Vec<IdentityEntity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMatchesResponse {
    pub assessment: SemanticIdentityMatchAssessment,
}

/// Request body for `POST /identity/entities`. The full
/// `IdentityEntity` lives under an `entity` envelope so the
/// shape is symmetric with the response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CreateIdentityEntityRequest {
    pub entity: IdentityEntity,
}

/// Combined query params for the entity list endpoint. `kind`
/// optional; when present, the response uses
/// `IdentityEntitiesFilteredResponse` (unpaginated) instead of
/// the paginated list shape.
#[derive(Debug, Clone, Deserialize)]
pub struct ListIdentityEntitiesQuery {
    pub kind: Option<String>,
    pub limit: Option<usize>,
    pub after: Option<String>,
}

/// Query params for the matcher endpoint. `source` + `normalized`
/// are required; the rest are optional. `kind` accepts the same
/// snake_case discriminants as `?kind=` on the entities list,
/// with the `Custom(s)` fallback for unknown labels.
#[derive(Debug, Clone, Deserialize)]
pub struct SuggestMatchesQuery {
    pub source: String,
    pub normalized: String,
    pub namespace: Option<String>,
    pub kind: Option<String>,
    pub limit: Option<usize>,
}

fn error_response(status: StatusCode, error: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: error.into(),
        }),
    )
        .into_response()
}

/// Parse a URL `?kind=<discriminant>` value into an
/// `IdentityEntityKind`. Snake_case built-ins round-trip;
/// any other non-empty string maps to `Custom(s)`. Empty
/// string → caller maps to 400.
///
/// Mirrors the P25 `parse_cell_kind` contract.
fn parse_identity_kind(value: &str) -> Option<IdentityEntityKind> {
    if value.is_empty() {
        return None;
    }
    Some(match value {
        "dataset" => IdentityEntityKind::Dataset,
        "table" => IdentityEntityKind::Table,
        "dashboard" => IdentityEntityKind::Dashboard,
        "metric" => IdentityEntityKind::Metric,
        "service" => IdentityEntityKind::Service,
        "agent" => IdentityEntityKind::Agent,
        "workflow" => IdentityEntityKind::Workflow,
        "source" => IdentityEntityKind::Source,
        "user" => IdentityEntityKind::User,
        "system" => IdentityEntityKind::System,
        "incident" => IdentityEntityKind::Incident,
        other => IdentityEntityKind::Custom(other.to_string()),
    })
}

async fn get_identity_entity(
    State(state): State<IdentityHttpState>,
    headers: HeaderMap,
    Path(entity_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };
    let id = IdentityEntityId::from_str(&entity_id);
    match state.service.identity_entity_for_tenant(&id, &tenant).await {
        Some(entity) => {
            Json(IdentityEntityResponse { entity }).into_response()
        }
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("identity entity not found: {entity_id}"),
        ),
    }
}

async fn list_identity_entities(
    State(state): State<IdentityHttpState>,
    headers: HeaderMap,
    Query(query): Query<ListIdentityEntitiesQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };

    // Filtered branch — kind present → unpaginated.
    if let Some(kind_str) = query.kind.as_deref() {
        let kind = match parse_identity_kind(kind_str) {
            Some(k) => k,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "kind query parameter cannot be empty",
                );
            }
        };
        let entities = state
            .service
            .identity_entities_with_kind_for_tenant(kind, &tenant)
            .await;
        return Json(IdentityEntitiesFilteredResponse { entities })
            .into_response();
    }

    // Paginated branch.
    let entities = state.service.identity_entities_for_tenant(&tenant).await;
    let pagination = PaginationQuery {
        limit: query.limit,
        after: query.after.clone(),
    };
    let limit = normalized_limit(pagination.limit);

    let mut start_index = 0usize;
    if let Some(after) = pagination.after.as_deref() {
        match entities.iter().position(|e| e.id.as_str() == after) {
            Some(idx) => start_index = idx + 1,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!("unknown identity entity cursor: {after}"),
                );
            }
        }
    }
    let page_items: Vec<IdentityEntity> = entities
        .iter()
        .skip(start_index)
        .take(limit)
        .cloned()
        .collect();
    let next_cursor = if start_index + page_items.len() < entities.len() {
        page_items.last().map(|e| e.id.as_str().to_string())
    } else {
        None
    };
    Json(IdentityEntitiesListResponse {
        entities: page_items,
        next_cursor,
    })
    .into_response()
}

/// `POST /identity/entities` — Patch 31 create handler.
///
/// **Server overwrites `entity.tenant_id` with the header value.**
/// This prevents a caller from smuggling `None` (system entity)
/// or a different tenant into the body. Mirrors how
/// `Event::trigger_for_tenant` stamps tenant from the request
/// context.
///
/// ## Status mapping
///
/// - 200 + `{entity: IdentityEntity}` — created successfully
/// - 400 — missing `X-Hydra-Tenant` OR duplicate alias / canonical
///   key / sentinel-validation failure (engine `QueryError`)
/// - 500 — any other engine error
async fn create_identity_entity(
    State(state): State<IdentityHttpState>,
    headers: HeaderMap,
    Json(req): Json<CreateIdentityEntityRequest>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };
    // Overwrite the body's tenant_id with the header. The
    // header is authoritative — this is the LOAD-BEARING
    // anti-smuggling rule.
    let mut entity = req.entity;
    entity.tenant_id = Some(tenant);

    let hydra = state.runtime.hydra();
    let mut hydra = hydra.write().await;
    match hydra.create_identity_entity(entity) {
        Ok(stored) => (
            StatusCode::OK,
            Json(IdentityEntityResponse { entity: stored }),
        )
            .into_response(),
        Err(hydra_core::error::HydraError::QueryError(msg)) => {
            // Engine validation failed: duplicate alias / duplicate
            // canonical key / sentinel collision / empty source.
            // Surface the engine message so operators see WHY.
            error_response(StatusCode::BAD_REQUEST, msg)
        }
        Err(other) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("create_identity_entity failed: {other}"),
        ),
    }
}

/// `GET /identity/matches` — Patch 31 semantic-match endpoint.
///
/// Read-only. Synthesizes an `IdentityAlias` from the URL query
/// params and calls `Hydra::suggest_identity_matches` with
/// `Some(tenant)` from the header. Strict tenant scoping —
/// `None`-tenanted entities never appear in results.
///
/// Query params:
///
/// - `source` (REQUIRED)
/// - `normalized` (REQUIRED)
/// - `namespace` (optional; `None` matches `None`-namespace
///   aliases by design)
/// - `kind` (optional; snake_case discriminant or `Custom(s)`
///   fallback)
/// - `limit` (optional; default 10, clamped by engine)
async fn suggest_identity_matches(
    State(state): State<IdentityHttpState>,
    headers: HeaderMap,
    Query(query): Query<SuggestMatchesQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };

    if query.source.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "source query parameter cannot be empty",
        );
    }
    if query.normalized.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "normalized query parameter cannot be empty",
        );
    }

    let kind = match query.kind.as_deref() {
        Some(s) => match parse_identity_kind(s) {
            Some(k) => Some(k),
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "kind query parameter cannot be empty",
                );
            }
        },
        None => None,
    };

    // Synthesize a query alias from the params. `external_id`
    // and `label` are not used by the scorer; we set `label`
    // to `normalized` so validate() is happy (non-empty) and
    // leave `external_id` as None.
    let alias = IdentityAlias {
        source: query.source.clone(),
        namespace: query.namespace.clone(),
        external_id: None,
        label: query.normalized.clone(),
        normalized: query.normalized.clone(),
    };

    let limit = query.limit.unwrap_or(10);

    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    match hydra.suggest_identity_matches(Some(&tenant), &alias, kind, limit) {
        Ok(assessment) => {
            Json(IdentityMatchesResponse { assessment }).into_response()
        }
        Err(hydra_core::error::HydraError::QueryError(msg)) => {
            // Engine alias validation can fail (e.g., reserved
            // sentinel in source). Map to 400.
            error_response(StatusCode::BAD_REQUEST, msg)
        }
        Err(other) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("suggest_identity_matches failed: {other}"),
        ),
    }
}

// === Patch 38 — IdentityLink HTTP surface =========================
//
// Expose the P37 IdentityLink vocabulary over HTTP. Read shape
// mirrors the P31 entity surface (wrapped `{"link": ...}` singular
// + wrapped `{"links": [...], "next_cursor": ...}` paginated).
//
// **LOAD-BEARING contracts** (all pinned by tests):
//
// 1. POST overwrites `link.tenant_id` from the X-Hydra-Tenant
//    header. Caller cannot smuggle a different tenant via the
//    body. Mirrors `create_identity_entity` (P31).
// 2. Tenant filtering happens at the QueryService boundary, NOT
//    the engine. Engine accessors are cross-tenant. None-tenanted
//    links are invisible to public routes.
// 3. Entity-scoped link route probes entity ownership FIRST via
//    `identity_entity_for_tenant`; missing/wrong-tenant entity →
//    404 unified-error to prevent existence enumeration through
//    link counts.
// 4. Single envelope shape for list — `{"links": [...],
//    "next_cursor": ...}` regardless of filter combinations.
//    Diverges from P31 entities-kind-filter two-mode response.
// 5. `?kind=` URL param accepts snake_case discriminants ONLY;
//    `?kind=DownstreamOf` becomes `Custom("DownstreamOf")` and
//    almost always returns empty (parsing/intent wart pinned by
//    test).
// 6. Error mapping splits on `QueryError` substring: a message
//    containing `"unknown identity entity"` → 404; everything
//    else → 400. Brittle; pin substring as constant.

const UNKNOWN_ENTITY_ERROR_PREFIX: &str = "unknown identity entity";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityLinkResponse {
    pub link: IdentityLink,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityLinksListResponse {
    pub links: Vec<IdentityLink>,
    pub next_cursor: Option<String>,
}

/// Request body for `POST /identity/links`. Full `IdentityLink`
/// lives under a `link` envelope so request + response are
/// symmetric (mirrors `CreateIdentityEntityRequest`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CreateIdentityLinkRequest {
    pub link: IdentityLink,
}

/// Combined query params for `GET /identity/links`. All optional;
/// when all absent, returns the full tenant link list paginated
/// under the default page size.
#[derive(Debug, Clone, Deserialize)]
pub struct ListIdentityLinksQuery {
    pub from_entity_id: Option<String>,
    pub to_entity_id: Option<String>,
    pub kind: Option<String>,
    pub limit: Option<usize>,
    pub after: Option<String>,
}

/// Query params for `GET /identity/entities/:entity_id/links`.
/// Pagination identical to the global list route; `kind` filter
/// optional and follows the same snake_case-only convention.
#[derive(Debug, Clone, Deserialize)]
pub struct ListLinksForEntityQuery {
    pub kind: Option<String>,
    pub limit: Option<usize>,
    pub after: Option<String>,
}

/// Parse a URL `?kind=<discriminant>` value into an
/// `IdentityLinkKind`. Snake_case built-ins round-trip; any other
/// non-empty string maps to `Custom(s)`. Empty string → caller
/// maps to 400.
///
/// **Wart pinned by test**: `?kind=DownstreamOf` becomes
/// `Custom("DownstreamOf")`, NOT the `DownstreamOf` built-in
/// (its discriminant is the snake_case `"downstream_of"`). Mirrors
/// `parse_identity_kind` (P31) — uniform across all `/identity/*`
/// routes.
fn parse_identity_link_kind(value: &str) -> Option<IdentityLinkKind> {
    if value.is_empty() {
        return None;
    }
    Some(match value {
        "same_as" => IdentityLinkKind::SameAs,
        "depends_on" => IdentityLinkKind::DependsOn,
        "downstream_of" => IdentityLinkKind::DownstreamOf,
        "owned_by" => IdentityLinkKind::OwnedBy,
        "produced_by" => IdentityLinkKind::ProducedBy,
        "consumed_by" => IdentityLinkKind::ConsumedBy,
        "derived_from" => IdentityLinkKind::DerivedFrom,
        "observed_in" => IdentityLinkKind::ObservedIn,
        "part_of" => IdentityLinkKind::PartOf,
        "related_to" => IdentityLinkKind::RelatedTo,
        other => IdentityLinkKind::Custom(other.to_string()),
    })
}

/// Map a `QueryError` message to (status, body). 404 for the
/// unified "unknown identity entity" prefix; 400 for everything
/// else (self-link, invalid kind, duplicate pair+kind, duplicate
/// id). Mirrors the P37 engine error vocabulary.
fn map_link_query_error(msg: String) -> Response {
    if msg.starts_with(UNKNOWN_ENTITY_ERROR_PREFIX) {
        error_response(StatusCode::NOT_FOUND, msg)
    } else {
        error_response(StatusCode::BAD_REQUEST, msg)
    }
}

/// `POST /identity/links` — Patch 38 create handler.
///
/// **Server overwrites `link.tenant_id` with the header value.**
/// Anti-smuggling rule mirrors `create_identity_entity` (P31).
/// `id`, `created_by`, `created_at`, `caused_by` pass through —
/// callers can supply stable ids for idempotent-retry semantics.
///
/// ## Strategic warning carry-forward (P37)
///
/// IdentityLink is a DURABLE assertion. v0 has NO trust verdict
/// over the link itself; `confidence` is informational only.
/// Auto-actions MUST gate on a future `IdentityLinkTrustAssessment`
/// (P39+), NOT on raw confidence. There is NO update or delete
/// in v0 — wrong links are corrected by creating new links.
///
/// ## Status mapping
///
/// - 200 + `{link: IdentityLink}` — created successfully
/// - 400 — missing tenant; self-link; invalid kind (empty /
///   sentinel / built-in collision Custom); duplicate pair+kind;
///   duplicate id
/// - 404 — unknown from/to entity, wrong-tenant entity, or
///   `None`-tenanted entity (unified error per P37)
/// - 500 — any other engine error
async fn create_identity_link(
    State(state): State<IdentityHttpState>,
    headers: HeaderMap,
    Json(req): Json<CreateIdentityLinkRequest>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };
    // LOAD-BEARING anti-smuggling: header is authoritative.
    let mut link = req.link;
    link.tenant_id = Some(tenant);

    let hydra = state.runtime.hydra();
    let mut hydra = hydra.write().await;
    match hydra.create_identity_link(link) {
        Ok(stored) => {
            (StatusCode::OK, Json(IdentityLinkResponse { link: stored }))
                .into_response()
        }
        Err(hydra_core::error::HydraError::QueryError(msg)) => {
            map_link_query_error(msg)
        }
        Err(other) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("create_identity_link failed: {other}"),
        ),
    }
}

/// `GET /identity/links/:link_id` — Patch 38 single-link read.
///
/// Strict tenant scoping via QueryService: unknown id, wrong
/// tenant, OR `None`-tenanted link all surface as 404 with the
/// same message (no cross-tenant existence leak; mirrors
/// `get_identity_entity`).
async fn get_identity_link(
    State(state): State<IdentityHttpState>,
    headers: HeaderMap,
    Path(link_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };
    let id = IdentityLinkId::from_str(&link_id);
    match state.service.identity_link_for_tenant(&id, &tenant).await {
        Some(link) => {
            Json(IdentityLinkResponse { link }).into_response()
        }
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("identity link not found: {link_id}"),
        ),
    }
}

/// `GET /identity/links` — Patch 38 paginated/filtered list.
///
/// All filters optional. Single envelope shape regardless of
/// filter combination. Sort by `IdentityLinkId` for stable
/// cursor pagination. Cursor is the raw id string (not base64).
async fn list_identity_links(
    State(state): State<IdentityHttpState>,
    headers: HeaderMap,
    Query(query): Query<ListIdentityLinksQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };

    let from = query
        .from_entity_id
        .as_deref()
        .map(IdentityEntityId::from_str);
    let to = query
        .to_entity_id
        .as_deref()
        .map(IdentityEntityId::from_str);

    let kind = match query.kind.as_deref() {
        Some(s) => match parse_identity_link_kind(s) {
            Some(k) => Some(k),
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "kind query parameter cannot be empty",
                );
            }
        },
        None => None,
    };

    let links = state
        .service
        .identity_links_for_tenant_filtered(
            &tenant,
            from.as_ref(),
            to.as_ref(),
            kind.as_ref(),
        )
        .await;

    paginate_links_response(links, query.limit, query.after.as_deref())
}

/// `GET /identity/entities/:entity_id/links` — Patch 38 entity-
/// scoped link neighborhood. Returns both incoming AND outgoing
/// links for the entity in one envelope.
///
/// **LOAD-BEARING ordering**: tenant probe FIRST via
/// `identity_entity_for_tenant`. If the entity doesn't exist OR
/// belongs to a different tenant OR is `None`-tenanted → 404
/// unified-error. Otherwise an attacker could enumerate which
/// entity ids exist under other tenants via link counts.
async fn list_links_for_entity(
    State(state): State<IdentityHttpState>,
    headers: HeaderMap,
    Path(entity_id): Path<String>,
    Query(query): Query<ListLinksForEntityQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };

    let eid = IdentityEntityId::from_str(&entity_id);
    // LOAD-BEARING tenant probe FIRST.
    if state
        .service
        .identity_entity_for_tenant(&eid, &tenant)
        .await
        .is_none()
    {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("identity entity not found: {entity_id}"),
        );
    }

    let kind = match query.kind.as_deref() {
        Some(s) => match parse_identity_link_kind(s) {
            Some(k) => Some(k),
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "kind query parameter cannot be empty",
                );
            }
        },
        None => None,
    };

    let links = state
        .service
        .identity_links_for_entity_for_tenant(&eid, &tenant, kind.as_ref())
        .await;

    paginate_links_response(links, query.limit, query.after.as_deref())
}

/// Apply cursor pagination to a tenant-filtered link list.
/// Shared by both list routes — same envelope, same cursor
/// semantics, same 400-on-unknown-cursor behavior.
fn paginate_links_response(
    links: Vec<IdentityLink>,
    limit: Option<usize>,
    after: Option<&str>,
) -> Response {
    let pagination = PaginationQuery {
        limit,
        after: after.map(|s| s.to_string()),
    };
    let limit = normalized_limit(pagination.limit);

    let mut start_index = 0usize;
    if let Some(cursor) = pagination.after.as_deref() {
        match links.iter().position(|l| l.id.as_str() == cursor) {
            Some(idx) => start_index = idx + 1,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!("unknown identity link cursor: {cursor}"),
                );
            }
        }
    }
    let page_items: Vec<IdentityLink> = links
        .iter()
        .skip(start_index)
        .take(limit)
        .cloned()
        .collect();
    let next_cursor = if start_index + page_items.len() < links.len() {
        page_items.last().map(|l| l.id.as_str().to_string())
    } else {
        None
    };
    Json(IdentityLinksListResponse {
        links: page_items,
        next_cursor,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use hydra_core::{
        ActorId, Confidence, IdentityAlias, IdentityEntity, IdentityEntityId,
        IdentityEntityKind, MatchLevel, TenantId,
    };
    use std::collections::HashMap;
    use tower::ServiceExt;

    const TEST_TENANT: &str = "tenant_identity_http_test";

    fn actor() -> ActorId {
        ActorId::from_str("actor_ops")
    }

    fn empty_get(uri: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("X-Hydra-Tenant", TEST_TENANT)
            .body(Body::empty())
            .unwrap()
    }

    fn empty_get_for_tenant(uri: &str, tenant: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("X-Hydra-Tenant", tenant)
            .body(Body::empty())
            .unwrap()
    }

    fn empty_get_without_tenant(uri: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    fn json_post(uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("X-Hydra-Tenant", TEST_TENANT)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn json_post_for_tenant(
        uri: &str,
        tenant: &str,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("X-Hydra-Tenant", tenant)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn json_post_without_tenant(
        uri: &str,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    async fn read_body_bytes(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    fn snowflake_alias(ns: &str, table: &str) -> IdentityAlias {
        IdentityAlias {
            source: "snowflake".to_string(),
            namespace: Some(ns.to_string()),
            external_id: Some(format!("{ns}.{table}").to_uppercase()),
            label: format!("{ns}.{table}").to_uppercase(),
            normalized: format!(
                "{}.{}",
                ns.to_lowercase(),
                table.to_lowercase()
            ),
        }
    }

    fn make_entity(
        tenant: Option<TenantId>,
        kind: IdentityEntityKind,
        canonical_key: &str,
        aliases: Vec<IdentityAlias>,
    ) -> IdentityEntity {
        let now = chrono::Utc::now();
        IdentityEntity {
            id: IdentityEntityId::new(),
            tenant_id: tenant,
            kind,
            canonical_key: canonical_key.to_string(),
            display_name: canonical_key.to_string(),
            aliases,
            confidence: Confidence::new(1.0),
            metadata: HashMap::new(),
            created_by: actor(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    /// Ingest an entity directly via the engine — used by the
    /// read-side HTTP tests so they don't have to drive a POST
    /// first.
    async fn ingest_entity(
        runtime: &crate::runtime::RuntimeHandle,
        entity: IdentityEntity,
    ) -> IdentityEntity {
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra.create_identity_entity(entity).unwrap()
    }

    // === GET /identity/entities/:id ===

    #[tokio::test]
    async fn get_identity_entity_returns_for_owning_tenant() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let entity = ingest_entity(
            &runtime,
            make_entity(
                Some(tenant.clone()),
                IdentityEntityKind::Dataset,
                "dataset/revenue_daily",
                vec![snowflake_alias("analytics", "revenue_daily")],
            ),
        )
        .await;
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!("/identity/entities/{}", entity.id)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: IdentityEntityResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.entity.id.as_str(), entity.id.as_str());
        assert_eq!(body.entity.canonical_key, "dataset/revenue_daily");
    }

    #[tokio::test]
    async fn get_identity_entity_missing_tenant_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get_without_tenant("/identity/entities/anything"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_identity_entity_wrong_tenant_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let entity = ingest_entity(
            &runtime,
            make_entity(
                Some(TenantId::from_str("tenant_owner")),
                IdentityEntityKind::Dataset,
                "dataset/secret",
                vec![snowflake_alias("analytics", "secret")],
            ),
        )
        .await;
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get_for_tenant(
                &format!("/identity/entities/{}", entity.id),
                "tenant_other",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_identity_entity_none_tenanted_invisible_to_tenanted_query() {
        // LOAD-BEARING: a `None`-tenanted (system) entity is
        // invisible to public tenant-scoped HTTP routes. Mirrors
        // P25 / P29 strict isolation.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let entity = ingest_entity(
            &runtime,
            make_entity(
                None,
                IdentityEntityKind::Source,
                "source/system_global",
                vec![IdentityAlias {
                    source: "snowflake".to_string(),
                    namespace: None,
                    external_id: None,
                    label: "snowflake-prod".to_string(),
                    normalized: "snowflake-prod".to_string(),
                }],
            ),
        )
        .await;
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!("/identity/entities/{}", entity.id)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // === GET /identity/entities ===

    #[tokio::test]
    async fn list_identity_entities_returns_only_owning_tenant() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let mine = ingest_entity(
            &runtime,
            make_entity(
                Some(tenant.clone()),
                IdentityEntityKind::Dataset,
                "dataset/ours",
                vec![snowflake_alias("ours", "ours")],
            ),
        )
        .await;
        let _theirs = ingest_entity(
            &runtime,
            make_entity(
                Some(TenantId::from_str("tenant_other")),
                IdentityEntityKind::Dataset,
                "dataset/theirs",
                vec![snowflake_alias("theirs", "theirs")],
            ),
        )
        .await;
        let _system = ingest_entity(
            &runtime,
            make_entity(
                None,
                IdentityEntityKind::Dataset,
                "dataset/system",
                vec![snowflake_alias("system", "system")],
            ),
        )
        .await;

        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/identity/entities"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: IdentityEntitiesListResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.entities.len(), 1);
        assert_eq!(body.entities[0].id.as_str(), mine.id.as_str());
        assert!(body.next_cursor.is_none());
    }

    #[tokio::test]
    async fn list_identity_entities_kind_filter() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let dataset = ingest_entity(
            &runtime,
            make_entity(
                Some(tenant.clone()),
                IdentityEntityKind::Dataset,
                "dataset/x",
                vec![snowflake_alias("a", "x")],
            ),
        )
        .await;
        let _service = ingest_entity(
            &runtime,
            make_entity(
                Some(tenant.clone()),
                IdentityEntityKind::Service,
                "service/y",
                vec![snowflake_alias("b", "y")],
            ),
        )
        .await;
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/identity/entities?kind=dataset"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: IdentityEntitiesFilteredResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.entities.len(), 1);
        assert_eq!(body.entities[0].id.as_str(), dataset.id.as_str());
    }

    #[tokio::test]
    async fn list_identity_entities_unknown_kind_returns_empty() {
        // Parser falls back to `Custom(s)` for unknown labels; no
        // entities of that custom kind exist → empty list (NOT
        // 400). Mirrors P25.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let _e = ingest_entity(
            &runtime,
            make_entity(
                Some(tenant.clone()),
                IdentityEntityKind::Dataset,
                "dataset/x",
                vec![snowflake_alias("a", "x")],
            ),
        )
        .await;
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get(
                "/identity/entities?kind=this_kind_does_not_exist",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: IdentityEntitiesFilteredResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.entities.is_empty());
    }

    #[tokio::test]
    async fn list_identity_entities_bad_cursor_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let _e = ingest_entity(
            &runtime,
            make_entity(
                Some(tenant),
                IdentityEntityKind::Dataset,
                "dataset/x",
                vec![snowflake_alias("a", "x")],
            ),
        )
        .await;
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get(
                "/identity/entities?after=ide_does_not_exist",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // === POST /identity/entities ===

    #[tokio::test]
    async fn create_identity_entity_returns_entity() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let body_entity = make_entity(
            Some(TenantId::from_str(TEST_TENANT)),
            IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(json_post(
                "/identity/entities",
                serde_json::json!({ "entity": body_entity }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: IdentityEntityResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.entity.canonical_key, "dataset/revenue_daily");
    }

    #[tokio::test]
    async fn create_identity_entity_missing_tenant_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let body_entity = make_entity(
            Some(TenantId::from_str("tenant_x")),
            IdentityEntityKind::Dataset,
            "dataset/x",
            vec![snowflake_alias("a", "x")],
        );
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(json_post_without_tenant(
                "/identity/entities",
                serde_json::json!({ "entity": body_entity }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_identity_entity_server_overwrites_body_tenant_id() {
        // LOAD-BEARING anti-smuggling pin: caller sets
        // `tenant_id=tenant_b` in the body BUT the header is
        // `tenant_a`. Server must persist with tenant_a (the
        // header) and ignore the body's tenant_id. Otherwise a
        // caller could write into a tenant they don't own.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant_a = "tenant_anti_smuggle_a";
        // Body's tenant_id is `tenant_b` — should be ignored.
        let body_entity = make_entity(
            Some(TenantId::from_str("tenant_anti_smuggle_b")),
            IdentityEntityKind::Dataset,
            "dataset/x",
            vec![snowflake_alias("a", "x")],
        );
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(json_post_for_tenant(
                "/identity/entities",
                tenant_a,
                serde_json::json!({ "entity": body_entity }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: IdentityEntityResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        // Persisted tenant is the HEADER value, not the body.
        assert_eq!(
            body.entity.tenant_id.as_ref().map(|t| t.as_str()),
            Some(tenant_a)
        );
    }

    #[tokio::test]
    async fn create_identity_entity_duplicate_alias_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let a = make_entity(
            Some(TenantId::from_str(TEST_TENANT)),
            IdentityEntityKind::Dataset,
            "dataset/a",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        let _ = ingest_entity(&runtime, a).await;
        // Try to create a second entity with the same alias triple.
        let b = make_entity(
            Some(TenantId::from_str(TEST_TENANT)),
            IdentityEntityKind::Dataset,
            "dataset/b",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(json_post(
                "/identity/entities",
                serde_json::json!({ "entity": b }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let err: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(
            err.error.contains("duplicate alias"),
            "expected duplicate-alias error; got {}",
            err.error
        );
    }

    // === GET /identity/matches ===

    #[tokio::test]
    async fn suggest_identity_matches_returns_assessment_for_exact_alias() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let entity = ingest_entity(
            &runtime,
            make_entity(
                Some(tenant),
                IdentityEntityKind::Dataset,
                "dataset/revenue_daily",
                vec![snowflake_alias("analytics", "revenue_daily")],
            ),
        )
        .await;
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get(
                "/identity/matches\
                 ?source=snowflake\
                 &namespace=analytics\
                 &normalized=analytics.revenue_daily",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: IdentityMatchesResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(!body.assessment.candidates.is_empty());
        let top = &body.assessment.candidates[0];
        assert_eq!(top.entity_id.as_str(), entity.id.as_str());
        assert_eq!(top.level, MatchLevel::Strong);
    }

    #[tokio::test]
    async fn suggest_identity_matches_wrong_tenant_invisible() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let _theirs = ingest_entity(
            &runtime,
            make_entity(
                Some(TenantId::from_str("tenant_a")),
                IdentityEntityKind::Dataset,
                "dataset/secret",
                vec![snowflake_alias("analytics", "revenue_daily")],
            ),
        )
        .await;
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get_for_tenant(
                "/identity/matches\
                 ?source=snowflake\
                 &namespace=analytics\
                 &normalized=analytics.revenue_daily",
                "tenant_b",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: IdentityMatchesResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.assessment.candidates.is_empty());
    }

    #[tokio::test]
    async fn suggest_identity_matches_requires_source_and_normalized() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = identity_router(runtime.clone());
        // Missing source.
        let r1 = app
            .clone()
            .oneshot(empty_get(
                "/identity/matches?normalized=foo",
            ))
            .await;
        // axum Query rejection produces a 400 when required
        // fields are missing.
        assert!(r1.is_ok());
        assert_eq!(r1.unwrap().status(), StatusCode::BAD_REQUEST);
        // Missing normalized.
        let r2 = app
            .oneshot(empty_get("/identity/matches?source=snowflake"))
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::BAD_REQUEST);
    }

    // === Patch 38 — IdentityLink HTTP tests ===

    /// Build a minimal `IdentityLink` between two entities for
    /// HTTP tests. Caller supplies tenant + kind + from/to.
    fn make_link(
        tenant: Option<TenantId>,
        kind: IdentityLinkKind,
        from: &IdentityEntityId,
        to: &IdentityEntityId,
    ) -> IdentityLink {
        IdentityLink {
            id: hydra_core::IdentityLinkId::new(),
            tenant_id: tenant,
            kind,
            from_entity_id: from.clone(),
            to_entity_id: to.clone(),
            confidence: Confidence::new(0.9),
            evidence_ids: vec![],
            claim_ids: vec![],
            cell_ids: vec![],
            metadata: HashMap::new(),
            created_by: actor(),
            created_at: chrono::Utc::now(),
            caused_by: None,
        }
    }

    async fn ingest_link(
        runtime: &crate::runtime::RuntimeHandle,
        link: IdentityLink,
    ) -> IdentityLink {
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra.create_identity_link(link).unwrap()
    }

    /// Seed two entities under the test tenant + return their ids.
    async fn seed_two_entities(
        runtime: &crate::runtime::RuntimeHandle,
    ) -> (IdentityEntityId, IdentityEntityId) {
        let tenant = TenantId::from_str(TEST_TENANT);
        let a = make_entity(
            Some(tenant.clone()),
            IdentityEntityKind::Dataset,
            "dataset/p38_a",
            vec![snowflake_alias("analytics", "p38_a")],
        );
        let mut b = make_entity(
            Some(tenant),
            IdentityEntityKind::Service,
            "service/p38_b",
            vec![snowflake_alias("ops", "p38_b")],
        );
        // Distinct alias so it doesn't collide with `a`'s (P29
        // alias uniqueness check).
        b.aliases[0].namespace = Some("ops".to_string());
        b.aliases[0].normalized = "ops.p38_b".to_string();
        b.aliases[0].label = "ops.p38_b".to_string();
        b.aliases[0].external_id = Some("ops.p38_b".to_string());
        let a_id = a.id.clone();
        let b_id = b.id.clone();
        ingest_entity(runtime, a).await;
        ingest_entity(runtime, b).await;
        (a_id, b_id)
    }

    // === POST /identity/links ===

    #[tokio::test]
    async fn create_identity_link_happy_path() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_entities(&runtime).await;
        let link = make_link(
            Some(TenantId::from_str(TEST_TENANT)),
            IdentityLinkKind::DependsOn,
            &a,
            &b,
        );
        let app = identity_router(runtime.clone());
        let body = serde_json::json!({ "link": link });
        let response = app
            .oneshot(json_post("/identity/links", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: IdentityLinkResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(parsed.link.from_entity_id, a);
        assert_eq!(parsed.link.to_entity_id, b);
        assert_eq!(parsed.link.kind, IdentityLinkKind::DependsOn);
        assert_eq!(
            parsed.link.tenant_id,
            Some(TenantId::from_str(TEST_TENANT))
        );
    }

    #[tokio::test]
    async fn create_identity_link_missing_tenant_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_entities(&runtime).await;
        let link = make_link(None, IdentityLinkKind::DependsOn, &a, &b);
        let app = identity_router(runtime.clone());
        let body = serde_json::json!({ "link": link });
        let response = app
            .oneshot(json_post_without_tenant("/identity/links", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_identity_link_server_overwrites_body_tenant_id() {
        // LOAD-BEARING anti-smuggling pin: body claims tenant_x,
        // header says tenant_y, from/to entities live in tenant_x.
        // Server overwrites link.tenant_id to tenant_y → engine
        // sees mismatch → "unknown identity entity" → 404. Pins
        // BOTH tenant overwrite AND strict isolation in one test.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_entities(&runtime).await;
        let body_tenant = TenantId::from_str("tenant_smuggled");
        let link = make_link(
            Some(body_tenant), // caller claims this in body
            IdentityLinkKind::DependsOn,
            &a,
            &b,
        );
        let app = identity_router(runtime.clone());
        let body = serde_json::json!({ "link": link });
        // Header tenant DIFFERS from body tenant AND from entity
        // tenant. The handler overwrites with header value
        // ("tenant_evil"); engine then rejects because entities
        // are in TEST_TENANT, not "tenant_evil".
        let response = app
            .oneshot(json_post_for_tenant(
                "/identity/links",
                "tenant_evil",
                body,
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "header tenant must overwrite body AND mismatch isolates"
        );
        let parsed: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(
            parsed.error.starts_with("unknown identity entity"),
            "unified error must surface; got {}",
            parsed.error
        );
    }

    #[tokio::test]
    async fn create_identity_link_self_link_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, _b) = seed_two_entities(&runtime).await;
        let link = make_link(
            Some(TenantId::from_str(TEST_TENANT)),
            IdentityLinkKind::SameAs,
            &a,
            &a,
        );
        let app = identity_router(runtime.clone());
        let body = serde_json::json!({ "link": link });
        let response = app
            .oneshot(json_post("/identity/links", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let parsed: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(parsed.error.contains("self-link"));
    }

    #[tokio::test]
    async fn create_identity_link_duplicate_pair_kind_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_entities(&runtime).await;
        let tenant = Some(TenantId::from_str(TEST_TENANT));
        ingest_link(
            &runtime,
            make_link(tenant.clone(), IdentityLinkKind::DependsOn, &a, &b),
        )
        .await;
        // Second create — same tenant, same from, same to, same kind.
        let dup = make_link(tenant, IdentityLinkKind::DependsOn, &a, &b);
        let app = identity_router(runtime.clone());
        let body = serde_json::json!({ "link": dup });
        let response = app
            .oneshot(json_post("/identity/links", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let parsed: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(parsed.error.contains("duplicate link"));
    }

    #[tokio::test]
    async fn create_identity_link_unknown_from_entity_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (_a, b) = seed_two_entities(&runtime).await;
        let ghost = IdentityEntityId::new();
        let link = make_link(
            Some(TenantId::from_str(TEST_TENANT)),
            IdentityLinkKind::DependsOn,
            &ghost,
            &b,
        );
        let app = identity_router(runtime.clone());
        let body = serde_json::json!({ "link": link });
        let response = app
            .oneshot(json_post("/identity/links", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // === GET /identity/links/:link_id ===

    #[tokio::test]
    async fn get_identity_link_happy_path() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_entities(&runtime).await;
        let link = ingest_link(
            &runtime,
            make_link(
                Some(TenantId::from_str(TEST_TENANT)),
                IdentityLinkKind::DependsOn,
                &a,
                &b,
            ),
        )
        .await;
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!(
                "/identity/links/{}",
                link.id.as_str()
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: IdentityLinkResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(parsed.link.id, link.id);
        assert_eq!(parsed.link.kind, IdentityLinkKind::DependsOn);
    }

    #[tokio::test]
    async fn get_identity_link_wrong_tenant_invisible() {
        // LOAD-BEARING: link exists in TEST_TENANT but queried
        // from a different tenant → 404 indistinguishable.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_entities(&runtime).await;
        let link = ingest_link(
            &runtime,
            make_link(
                Some(TenantId::from_str(TEST_TENANT)),
                IdentityLinkKind::DependsOn,
                &a,
                &b,
            ),
        )
        .await;
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get_for_tenant(
                &format!("/identity/links/{}", link.id.as_str()),
                "tenant_other",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // === GET /identity/links (list with filters + pagination) ===

    #[tokio::test]
    async fn list_identity_links_happy_paginated() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_entities(&runtime).await;
        let tenant = Some(TenantId::from_str(TEST_TENANT));
        ingest_link(
            &runtime,
            make_link(tenant.clone(), IdentityLinkKind::DependsOn, &a, &b),
        )
        .await;
        ingest_link(
            &runtime,
            make_link(tenant, IdentityLinkKind::OwnedBy, &b, &a),
        )
        .await;
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/identity/links"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: IdentityLinksListResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(parsed.links.len(), 2);
        // Sort stability — by id ascending.
        let ids: Vec<&str> = parsed.links.iter().map(|l| l.id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    #[tokio::test]
    async fn list_identity_links_filters_propagate() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_entities(&runtime).await;
        let tenant = Some(TenantId::from_str(TEST_TENANT));
        let depends = ingest_link(
            &runtime,
            make_link(tenant.clone(), IdentityLinkKind::DependsOn, &a, &b),
        )
        .await;
        ingest_link(
            &runtime,
            make_link(tenant, IdentityLinkKind::OwnedBy, &b, &a),
        )
        .await;
        let app = identity_router(runtime.clone());

        // Filter by from.
        let r = app
            .clone()
            .oneshot(empty_get(&format!(
                "/identity/links?from_entity_id={}",
                a.as_str()
            )))
            .await
            .unwrap();
        let parsed: IdentityLinksListResponse =
            serde_json::from_slice(&read_body_bytes(r).await).unwrap();
        assert_eq!(parsed.links.len(), 1);
        assert_eq!(parsed.links[0].id, depends.id);

        // Filter by kind (snake_case).
        let r = app
            .clone()
            .oneshot(empty_get("/identity/links?kind=depends_on"))
            .await
            .unwrap();
        let parsed: IdentityLinksListResponse =
            serde_json::from_slice(&read_body_bytes(r).await).unwrap();
        assert_eq!(parsed.links.len(), 1);
        assert_eq!(parsed.links[0].kind, IdentityLinkKind::DependsOn);
    }

    #[tokio::test]
    async fn list_identity_links_kind_pascal_vs_snake_url_param_wart() {
        // Pin the documented wart: ?kind=DependsOn is treated as
        // Custom("DependsOn") and almost always returns empty.
        // Snake_case is the canonical URL form.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_entities(&runtime).await;
        let tenant = Some(TenantId::from_str(TEST_TENANT));
        ingest_link(
            &runtime,
            make_link(tenant, IdentityLinkKind::DependsOn, &a, &b),
        )
        .await;
        let app = identity_router(runtime.clone());
        // PascalCase silently filters Custom("DependsOn") → empty.
        let r = app
            .clone()
            .oneshot(empty_get("/identity/links?kind=DependsOn"))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let parsed: IdentityLinksListResponse =
            serde_json::from_slice(&read_body_bytes(r).await).unwrap();
        assert!(
            parsed.links.is_empty(),
            "PascalCase kind must filter empty (custom-kind wart pin)"
        );
        // snake_case finds the link.
        let r = app
            .oneshot(empty_get("/identity/links?kind=depends_on"))
            .await
            .unwrap();
        let parsed: IdentityLinksListResponse =
            serde_json::from_slice(&read_body_bytes(r).await).unwrap();
        assert_eq!(parsed.links.len(), 1);
    }

    #[tokio::test]
    async fn list_identity_links_bad_cursor_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get(
                "/identity/links?after=idl_nonexistent",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_identity_links_none_tenanted_invisible() {
        // LOAD-BEARING: None-tenanted links are physically
        // invisible to tenanted callers (mirrors P29/P31).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        // Seed None-tenanted entities + link directly via engine.
        let (a, b) = {
            let mut a = make_entity(
                None,
                IdentityEntityKind::System,
                "system/none_a",
                vec![IdentityAlias {
                    source: "system".to_string(),
                    namespace: Some("global".to_string()),
                    external_id: None,
                    label: "none_a".to_string(),
                    normalized: "none_a".to_string(),
                }],
            );
            let mut b = make_entity(
                None,
                IdentityEntityKind::System,
                "system/none_b",
                vec![IdentityAlias {
                    source: "system".to_string(),
                    namespace: Some("global".to_string()),
                    external_id: None,
                    label: "none_b".to_string(),
                    normalized: "none_b".to_string(),
                }],
            );
            // Ensure canonical key + alias are distinct.
            a.aliases[0].normalized = "global.none_a".to_string();
            a.aliases[0].label = "global.none_a".to_string();
            b.aliases[0].normalized = "global.none_b".to_string();
            b.aliases[0].label = "global.none_b".to_string();
            let a_id = a.id.clone();
            let b_id = b.id.clone();
            ingest_entity(&runtime, a).await;
            ingest_entity(&runtime, b).await;
            (a_id, b_id)
        };
        ingest_link(
            &runtime,
            make_link(None, IdentityLinkKind::SameAs, &a, &b),
        )
        .await;
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/identity/links"))
            .await
            .unwrap();
        let parsed: IdentityLinksListResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(
            parsed.links.is_empty(),
            "None-tenanted links must NOT leak to tenanted caller"
        );
    }

    // === GET /identity/entities/:entity_id/links ===

    #[tokio::test]
    async fn list_links_for_entity_returns_incoming_and_outgoing() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, b) = seed_two_entities(&runtime).await;
        let tenant = Some(TenantId::from_str(TEST_TENANT));
        // a --DependsOn--> b   (outgoing from a)
        ingest_link(
            &runtime,
            make_link(tenant.clone(), IdentityLinkKind::DependsOn, &a, &b),
        )
        .await;
        // b --OwnedBy--> a     (incoming to a)
        ingest_link(
            &runtime,
            make_link(tenant, IdentityLinkKind::OwnedBy, &b, &a),
        )
        .await;
        let app = identity_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!(
                "/identity/entities/{}/links",
                a.as_str()
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: IdentityLinksListResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(parsed.links.len(), 2);
        let kinds: Vec<&IdentityLinkKind> =
            parsed.links.iter().map(|l| &l.kind).collect();
        assert!(kinds.contains(&&IdentityLinkKind::DependsOn));
        assert!(kinds.contains(&&IdentityLinkKind::OwnedBy));
    }

    #[tokio::test]
    async fn list_links_for_entity_tenant_probe_first_blocks_existence_leak() {
        // LOAD-BEARING: entity-scoped route MUST probe entity
        // ownership before listing links — otherwise wrong-tenant
        // entity-id enumeration leaks via link counts.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, _b) = seed_two_entities(&runtime).await;
        let app = identity_router(runtime.clone());
        // Probe `a` from a different tenant — entity exists in
        // TEST_TENANT but not in "tenant_other", so 404
        // indistinguishable from "id doesn't exist".
        let response = app
            .oneshot(empty_get_for_tenant(
                &format!("/identity/entities/{}/links", a.as_str()),
                "tenant_other",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn entity_id_with_links_suffix_routes_distinct_handler() {
        // Sanity pin for route ordering: the trie correctly
        // selects the longer literal-segment match. Probe both
        // /identity/entities/:id and /identity/entities/:id/links
        // and confirm they hit different handlers (responses
        // have different envelope shapes).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let (a, _b) = seed_two_entities(&runtime).await;
        let app = identity_router(runtime.clone());

        // Bare :entity_id → IdentityEntityResponse (has "entity").
        let r = app
            .clone()
            .oneshot(empty_get(&format!(
                "/identity/entities/{}",
                a.as_str()
            )))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(r).await).unwrap();
        assert!(body.get("entity").is_some());

        // :entity_id/links → IdentityLinksListResponse (has "links").
        let r = app
            .oneshot(empty_get(&format!(
                "/identity/entities/{}/links",
                a.as_str()
            )))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(r).await).unwrap();
        assert!(body.get("links").is_some());
    }
}
