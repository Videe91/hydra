//! # Patch 25 — CausalCell Read/Query HTTP surface
//!
//! Exposes the engine's `causal_cell` / `causal_cells` / `causal_cells_by_kind`
//! reads (via `QueryService`) as HTTP endpoints. Patch 24 made cell trust
//! externally legible; Patch 25 makes the cells themselves legible.
//!
//! Routes:
//!
//! - `GET /causal-cells/:cell_id`               — single cell lookup
//! - `GET /causal-cells`                        — paginated list (per-tenant)
//! - `GET /causal-cells?kind=<discriminant>`    — filter by kind (unpaginated)
//!
//! ## Auth
//!
//! Reuses `read:query` scope (handled at `hydra-api::auth` via a new
//! `/causal-cells/*` prefix clause). Cells are graph data, not trust
//! judgments — the `read:trust` scope stays reserved for `/trust/*`.
//!
//! ## Tenant isolation (strict)
//!
//! Mirrors `/trust/cells/:id`:
//!
//! - `X-Hydra-Tenant` REQUIRED on every route → 400 if missing
//! - cell exists but wrong tenant OR `None`-tenanted (system cell) →
//!   404, indistinguishable from "unknown"
//! - list endpoints return ONLY the caller's tenant cells; `None`-
//!   tenanted cells are NEVER included
//!
//! ## Response shape
//!
//! Single cell: `{ "cell": CausalCell }`
//!
//! List (paginated): `{ "cells": [...], "next_cursor": "id|null" }`
//!
//! List (kind-filtered): `{ "cells": [...] }` — unpaginated. Patch 25
//! does not paginate filtered lists; future patches may add it.
//!
//! Resource-keyed `{cells}` instead of generic `{items}` (per user spec).

use crate::http::pagination::{normalized_limit, PaginationQuery};
use crate::http::tenant::{extract_tenant, tenant_error_response};
use crate::query::QueryService;
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hydra_core::{ActorId, CausalCell, CausalCellId, CausalCellKind};
use serde::{Deserialize, Serialize};

/// Shared HTTP state for the causal-cells routes.
///
/// `service` is used by the read-side handlers (Patch 25); the
/// `runtime` handle is held alongside so the Patch 27 POST
/// handler can acquire the engine write lock for
/// `compose_hydra_health_cell`. Storing both is cheap — the
/// QueryService is a thin Arc wrapper over the same engine.
#[derive(Clone)]
pub struct CausalCellsHttpState {
    pub service: QueryService,
    pub runtime: RuntimeHandle,
}

impl CausalCellsHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self {
            service: QueryService::new(runtime.hydra()),
            runtime,
        }
    }
}

/// Build the causal-cells router. Routes:
///
/// - `GET  /causal-cells/:cell_id` (Patch 25) — single-cell lookup
/// - `GET  /causal-cells`          (Patch 25) — list w/ optional
///                                  `?kind=` filter +
///                                  `?after=/?limit=` pagination
/// - `POST /causal-cells/hydra-health/compose` (Patch 27) —
///   compose the canonical `hydra.health` parent cell from the
///   tenant's latest self-health reflex cells
pub fn causal_cells_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/causal-cells/:cell_id", get(get_causal_cell))
        .route("/causal-cells", get(list_causal_cells))
        .route(
            "/causal-cells/hydra-health/compose",
            post(compose_hydra_health_cell),
        )
        .with_state(CausalCellsHttpState::new(runtime))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalCellResponse {
    pub cell: CausalCell,
}

/// Paginated list response. `next_cursor` is absent (None →
/// serialized as `null`) when no more pages remain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalCellsListResponse {
    pub cells: Vec<CausalCell>,
    pub next_cursor: Option<String>,
}

/// Filtered list response — kind queries return the full filtered
/// set, no pagination cursor. Distinct from `CausalCellsListResponse`
/// so the wire shapes are honest about which form is paginated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalCellsFilteredResponse {
    pub cells: Vec<CausalCell>,
}

/// Combined query params for the list endpoint. `kind` is optional;
/// when present, results are filtered AND pagination params are
/// ignored (Patch 25 contract — filtered lists are unpaginated).
#[derive(Debug, Clone, Deserialize)]
pub struct ListCausalCellsQuery {
    pub kind: Option<String>,
    pub limit: Option<usize>,
    pub after: Option<String>,
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

/// Parse a URL `?kind=<discriminant>` value into a `CausalCellKind`.
///
/// Built-in discriminants (snake_case, matching
/// `CausalCellKind::discriminant()`) round-trip to the typed
/// variant. Any other non-empty string maps to
/// `CausalCellKind::Custom(s)` — deployments can register their
/// own labels and they are queryable here without a hard-coded
/// allowlist.
///
/// Returns `None` only for an empty kind string (caller maps to
/// 400).
fn parse_cell_kind(value: &str) -> Option<CausalCellKind> {
    if value.is_empty() {
        return None;
    }
    match value {
        "reflex" => Some(CausalCellKind::Reflex),
        "health" => Some(CausalCellKind::Health),
        "incident" => Some(CausalCellKind::Incident),
        "dataset" => Some(CausalCellKind::Dataset),
        "agent" => Some(CausalCellKind::Agent),
        "workflow" => Some(CausalCellKind::Workflow),
        "source" => Some(CausalCellKind::Source),
        "tenant" => Some(CausalCellKind::Tenant),
        "case" => Some(CausalCellKind::Case),
        other => Some(CausalCellKind::Custom(other.to_string())),
    }
}

async fn get_causal_cell(
    State(state): State<CausalCellsHttpState>,
    headers: HeaderMap,
    Path(cell_id): Path<String>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };
    let id = CausalCellId::from_str(&cell_id);
    match state.service.cell_for_tenant(&id, &tenant).await {
        Some(cell) => Json(CausalCellResponse { cell }).into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("causal cell not found: {cell_id}"),
        ),
    }
}

async fn list_causal_cells(
    State(state): State<CausalCellsHttpState>,
    headers: HeaderMap,
    Query(query): Query<ListCausalCellsQuery>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };

    // Filtered branch — kind present → unpaginated full filtered set.
    if let Some(kind_str) = query.kind.as_deref() {
        let kind = match parse_cell_kind(kind_str) {
            Some(k) => k,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "kind query parameter cannot be empty",
                );
            }
        };
        let cells = state
            .service
            .cells_with_kind_for_tenant(kind, &tenant)
            .await;
        return Json(CausalCellsFilteredResponse { cells }).into_response();
    }

    // Paginated branch — unfiltered list, cursor over sorted-by-id.
    let cells = state.service.cells_for_tenant(&tenant).await;
    let pagination = PaginationQuery {
        limit: query.limit,
        after: query.after.clone(),
    };
    let limit = normalized_limit(pagination.limit);

    let mut start_index = 0usize;
    if let Some(after) = pagination.after.as_deref() {
        match cells.iter().position(|cell| cell.id.as_str() == after) {
            Some(idx) => start_index = idx + 1,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!("unknown causal cell cursor: {after}"),
                );
            }
        }
    }
    let page_items: Vec<CausalCell> = cells
        .iter()
        .skip(start_index)
        .take(limit)
        .cloned()
        .collect();
    let next_cursor = if start_index + page_items.len() < cells.len() {
        page_items.last().map(|c| c.id.as_str().to_string())
    } else {
        None
    };
    Json(CausalCellsListResponse {
        cells: page_items,
        next_cursor,
    })
    .into_response()
}

/// Request body for `POST /causal-cells/hydra-health/compose`
/// (Patch 27). `actor` is the operator/agent that initiated the
/// composition; it appears as `cell.created_by` on the composed
/// `hydra.health` parent.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ComposeHydraHealthCellRequest {
    pub actor: String,
}

/// `POST /causal-cells/hydra-health/compose` — Patch 27.
///
/// Exposes the Patch 26 engine helper
/// `Hydra::compose_hydra_health_cell` over HTTP. Composes the
/// canonical `hydra.health` parent cell from the calling
/// tenant's latest self-health reflex cells (commit-rate,
/// replication-lag, agent-loop-storm, action-failure-rate).
///
/// ## Tenant scoping (strict)
///
/// `X-Hydra-Tenant` is REQUIRED; missing → 400. The header
/// value is passed to the engine as `Some(tenant)` so only
/// THAT tenant's reflex cells participate. `None`-tenanted
/// (system) reflex cells are INVISIBLE to this route — a
/// system-wide admin route is a future patch.
///
/// ## Status mapping
///
/// - 200 + `{cell: CausalCell}` — composed (1-4 children found)
/// - 400                         — missing `X-Hydra-Tenant`
/// - 404 + engine error message  — zero reflex cells found for
///                                 the tenant (precondition
///                                 absent, not a server error)
/// - 500                         — any other engine error
///
/// ## Precondition
///
/// The reflex pipeline does NOT auto-create reflex cells today
/// (`create_reflex_causal_cell_from_claim` is explicit — Patch
/// 21). A fresh tenant calling this route immediately gets 404
/// until something seeds reflex cells. Patch 28 (auto-create
/// during model evaluation) is what removes this manual step.
async fn compose_hydra_health_cell(
    State(state): State<CausalCellsHttpState>,
    headers: HeaderMap,
    Json(req): Json<ComposeHydraHealthCellRequest>,
) -> Response {
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(err) => return tenant_error_response(err),
    };
    let actor = ActorId::from_str(&req.actor);
    let hydra = state.runtime.hydra();
    let mut hydra = hydra.write().await;
    match hydra.compose_hydra_health_cell(actor, Some(tenant)) {
        Ok(cell) => (StatusCode::OK, Json(CausalCellResponse { cell }))
            .into_response(),
        Err(hydra_core::error::HydraError::QueryError(msg))
            if msg.contains("no self-health reflex cells found") =>
        {
            // Precondition absent. Echo the engine message
            // verbatim so operators see WHICH tenant + expected
            // subjects in the body, not a generic "not found".
            error_response(StatusCode::NOT_FOUND, msg)
        }
        Err(other) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("compose_hydra_health_cell failed: {other}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use hydra_core::{ActorId, CausalCell, CausalCellId, CausalCellKind, EventKind, TenantId};
    use tower::ServiceExt;

    const TEST_TENANT: &str = "tenant_causal_cells_http_test";

    fn empty_get(uri: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("X-Hydra-Tenant", TEST_TENANT)
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

    fn empty_get_for_tenant(uri: &str, tenant: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("X-Hydra-Tenant", tenant)
            .body(Body::empty())
            .unwrap()
    }

    async fn read_body_bytes(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    /// Ingest a synthetic CausalCell. Mirrors the helper used in
    /// `http::trust` tests; lets each Patch 25 test control kind,
    /// tenant, and subject precisely.
    async fn ingest_cell(
        runtime: &crate::runtime::RuntimeHandle,
        tenant: Option<TenantId>,
        kind: CausalCellKind,
        subject: &str,
    ) -> CausalCell {
        let cell = CausalCell {
            id: CausalCellId::new(),
            tenant_id: tenant,
            kind,
            subject: subject.to_string(),
            source_events: vec![],
            evidence_ids: vec![],
            claim_ids: vec![],
            action_ids: vec![],
            outcome_ids: vec![],
            observation_run_ids: vec![],
            child_cell_ids: vec![],
            trust_score: None,
            summary: None,
            created_by: ActorId::from_str("actor_test"),
            created_at: chrono::Utc::now(),
            caused_by: None,
        };
        let cell_clone = cell.clone();
        let hydra = runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra
            .ingest(EventKind::CausalCellCreated { cell })
            .unwrap();
        cell_clone
    }

    #[tokio::test]
    async fn get_causal_cell_returns_cell_for_owning_tenant() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let cell = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "hydra.commit-rate",
        )
        .await;
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!("/causal-cells/{}", cell.id)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        let returned_cell = body.get("cell").unwrap();
        assert_eq!(
            returned_cell.get("id").and_then(|v| v.as_str()),
            Some(cell.id.as_str())
        );
        assert_eq!(
            returned_cell.get("subject").and_then(|v| v.as_str()),
            Some("hydra.commit-rate")
        );
        // PascalCase wire form for kind preserved.
        assert_eq!(
            returned_cell.get("kind").and_then(|v| v.as_str()),
            Some("Reflex"),
        );
    }

    #[tokio::test]
    async fn get_causal_cell_missing_tenant_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(empty_get_without_tenant("/causal-cells/anything"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_causal_cell_unknown_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/causal-cells/cell_does_not_exist"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.error.contains("causal cell not found"));
    }

    #[tokio::test]
    async fn get_causal_cell_wrong_tenant_returns_404() {
        // Strict isolation pin: a cell owned by tenant_owner queried
        // as tenant_other surfaces as 404, not 403. Returning 403
        // would itself leak existence across tenant boundaries.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let cell = ingest_cell(
            &runtime,
            Some(TenantId::from_str("tenant_owner")),
            CausalCellKind::Reflex,
            "secret",
        )
        .await;
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(empty_get_for_tenant(
                &format!("/causal-cells/{}", cell.id),
                "tenant_other",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_causal_cell_none_tenanted_invisible_to_tenanted_query() {
        // LOAD-BEARING strict-isolation pin: `None`-tenanted (system)
        // cells are INVISIBLE to a tenanted query. If this flips,
        // operators querying their tenant could see global cells
        // they didn't author. Mirrors `/trust/cells/:id` semantics.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let cell = ingest_cell(
            &runtime,
            None,
            CausalCellKind::Reflex,
            "system.global",
        )
        .await;
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(empty_get(&format!("/causal-cells/{}", cell.id)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_causal_cells_returns_only_owning_tenant() {
        // Tenant scoping pin: lists never include other tenants'
        // cells, AND never include `None`-tenanted (system) cells.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let mine_a = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "mine.a",
        )
        .await;
        let mine_b = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "mine.b",
        )
        .await;
        let _theirs = ingest_cell(
            &runtime,
            Some(TenantId::from_str("tenant_other")),
            CausalCellKind::Reflex,
            "theirs",
        )
        .await;
        let _system = ingest_cell(
            &runtime,
            None,
            CausalCellKind::Reflex,
            "system",
        )
        .await;
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/causal-cells"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: CausalCellsListResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.cells.len(), 2);
        let ids: Vec<&str> = body.cells.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&mine_a.id.as_str()));
        assert!(ids.contains(&mine_b.id.as_str()));
        // No more pages.
        assert!(body.next_cursor.is_none());
    }

    #[tokio::test]
    async fn list_causal_cells_filter_by_builtin_kind() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let reflex = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "r",
        )
        .await;
        let _health = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Health,
            "h",
        )
        .await;
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/causal-cells?kind=reflex"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: CausalCellsFilteredResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.cells.len(), 1);
        assert_eq!(body.cells[0].id.as_str(), reflex.id.as_str());
    }

    #[tokio::test]
    async fn list_causal_cells_filter_by_custom_kind() {
        // LOAD-BEARING: a `Custom("invoice_anomaly")` cell must be
        // findable via `?kind=invoice_anomaly`. The parser falls
        // back to `Custom(s)` for any non-built-in label; the
        // engine's `cells_by_kind` index keys on the same
        // discriminant string, so this round-trip works.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let custom = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Custom("invoice_anomaly".to_string()),
            "invoice.42",
        )
        .await;
        let _other = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "other",
        )
        .await;
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/causal-cells?kind=invoice_anomaly"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: CausalCellsFilteredResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.cells.len(), 1);
        assert_eq!(body.cells[0].id.as_str(), custom.id.as_str());
    }

    #[tokio::test]
    async fn list_causal_cells_unknown_kind_returns_empty() {
        // An unknown kind label (no cells of that kind exist) returns
        // an empty result with 200 — NOT a 400. The parser maps
        // any non-empty string to `Custom(s)`, so "doesn't exist"
        // and "no cells match" are the same answer.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let _r = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "r",
        )
        .await;
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/causal-cells?kind=this_kind_does_not_exist"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: CausalCellsFilteredResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.cells.is_empty());
    }

    #[tokio::test]
    async fn list_causal_cells_paginates_with_cursor() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        // Ingest 3 cells. They'll sort deterministically by id (ULID
        // monotonicity within the same generation order).
        let _c1 = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "a",
        )
        .await;
        let _c2 = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "b",
        )
        .await;
        let _c3 = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "c",
        )
        .await;
        let app = causal_cells_router(runtime.clone());
        // First page — limit=2 → 2 results + next_cursor pointing
        // at the second item's id.
        let response = app
            .clone()
            .oneshot(empty_get("/causal-cells?limit=2"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let page1: CausalCellsListResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(page1.cells.len(), 2);
        let cursor = page1.next_cursor.as_ref().expect("expected next_cursor");
        assert_eq!(cursor, page1.cells[1].id.as_str());

        // Second page — after the cursor → 1 result, no more.
        let response2 = app
            .oneshot(empty_get(&format!(
                "/causal-cells?limit=2&after={cursor}",
            )))
            .await
            .unwrap();
        assert_eq!(response2.status(), StatusCode::OK);
        let page2: CausalCellsListResponse =
            serde_json::from_slice(&read_body_bytes(response2).await).unwrap();
        assert_eq!(page2.cells.len(), 1);
        assert!(page2.next_cursor.is_none());
    }

    #[tokio::test]
    async fn list_causal_cells_bad_cursor_returns_400() {
        // Mirrors `paginate_by_cursor` semantics: an unknown
        // `after` cursor is a client bug, not silent empty page.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let _c = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "a",
        )
        .await;
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/causal-cells?after=cell_does_not_exist"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(body.error.contains("unknown causal cell cursor"));
    }

    #[tokio::test]
    async fn list_causal_cells_order_is_deterministic_by_id() {
        // QueryService sorts by id before returning so cursor
        // pagination is stable. Pin the contract: list output must
        // be in ascending id order regardless of ingest order.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let c1 = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "a",
        )
        .await;
        let c2 = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "b",
        )
        .await;
        let c3 = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "c",
        )
        .await;
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(empty_get("/causal-cells"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: CausalCellsListResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        let mut expected = vec![c1.id.as_str(), c2.id.as_str(), c3.id.as_str()];
        expected.sort();
        let actual: Vec<&str> = body.cells.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn list_causal_cells_missing_tenant_returns_400() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(empty_get_without_tenant("/causal-cells"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn causal_cells_routes_live_in_causal_cells_router() {
        // Sanity: both routes are mounted by `causal_cells_router`.
        // If a future refactor moves them elsewhere, this fires.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let cell = ingest_cell(
            &runtime,
            Some(tenant.clone()),
            CausalCellKind::Reflex,
            "x",
        )
        .await;
        let app = causal_cells_router(runtime.clone());
        let single = app
            .clone()
            .oneshot(empty_get(&format!("/causal-cells/{}", cell.id)))
            .await
            .unwrap();
        assert_eq!(single.status(), StatusCode::OK);
        let list = app
            .oneshot(empty_get("/causal-cells"))
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
    }

    // === Patch 27 — HydraHealthCell HTTP surface ===

    /// POST helper with default tenant header set.
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

    /// Seed a Reflex cell at one of the canonical self-health
    /// subjects so P27 tests can drive partial / full / wrong-
    /// tenant compositions without rebuilding the full reflex
    /// chain.
    async fn ingest_self_health_reflex(
        runtime: &crate::runtime::RuntimeHandle,
        tenant: Option<TenantId>,
        subject: &str,
    ) -> CausalCell {
        ingest_cell(runtime, tenant, CausalCellKind::Reflex, subject).await
    }

    /// Seed all 4 self-health reflex subjects under a single
    /// tenant. Mirrors the engine-side
    /// `seed_all_four_self_health_reflexes` test helper.
    async fn seed_all_four(
        runtime: &crate::runtime::RuntimeHandle,
        tenant: Option<TenantId>,
    ) -> [CausalCell; 4] {
        [
            ingest_self_health_reflex(
                runtime,
                tenant.clone(),
                "hydra/under_abnormal_load",
            )
            .await,
            ingest_self_health_reflex(
                runtime,
                tenant.clone(),
                "hydra.replication/replica_lagging",
            )
            .await,
            ingest_self_health_reflex(
                runtime,
                tenant.clone(),
                "hydra.agents/agent_loop_storm",
            )
            .await,
            ingest_self_health_reflex(
                runtime,
                tenant,
                "hydra.actions/action_failure_rate_high",
            )
            .await,
        ]
    }

    #[tokio::test]
    async fn compose_hydra_health_cell_returns_cell() {
        // Happy path: seed 4 reflex cells, POST → 200 with the
        // composed `hydra.health` cell in `{cell: ...}` envelope.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let _children = seed_all_four(&runtime, Some(tenant.clone())).await;
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(json_post(
                "/causal-cells/hydra-health/compose",
                serde_json::json!({"actor": "actor_ops"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: CausalCellResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.cell.kind, CausalCellKind::Health);
        assert_eq!(body.cell.subject, "hydra.health");
        assert_eq!(body.cell.tenant_id, Some(tenant));
        assert_eq!(body.cell.child_cell_ids.len(), 4);
        let summary = body.cell.summary.as_ref().expect("summary set");
        assert!(
            summary.contains("4 of 4 self-health reflexes"),
            "summary: {summary}"
        );
    }

    #[tokio::test]
    async fn compose_hydra_health_cell_requires_tenant_header() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(json_post_without_tenant(
                "/causal-cells/hydra-health/compose",
                serde_json::json!({"actor": "actor_ops"}),
            ))
            .await
            .unwrap();
        // Missing X-Hydra-Tenant → 400 from tenant_error_response.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn compose_hydra_health_cell_zero_found_returns_404() {
        // No reflex cells in the store → engine returns
        // QueryError("no self-health reflex cells found ..."),
        // mapped to 404 with the engine message in the body
        // (precondition explainer — operator sees WHY).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(json_post(
                "/causal-cells/hydra-health/compose",
                serde_json::json!({"actor": "actor_ops"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert!(
            body.error.contains("no self-health reflex cells found"),
            "error: {}",
            body.error
        );
        // Engine message names the tenant — pin so the operator-
        // friendly body shape doesn't drift to generic "not found".
        assert!(
            body.error.contains(TEST_TENANT),
            "tenant should appear in 404 body: {}",
            body.error
        );
    }

    #[tokio::test]
    async fn compose_hydra_health_cell_partial_returns_200() {
        // Seed 2 of 4 reflex subjects → 200 with a partial
        // health cell. Summary calls out the missing subjects.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let _a = ingest_self_health_reflex(
            &runtime,
            Some(tenant.clone()),
            "hydra/under_abnormal_load",
        )
        .await;
        let _b = ingest_self_health_reflex(
            &runtime,
            Some(tenant.clone()),
            "hydra.actions/action_failure_rate_high",
        )
        .await;
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(json_post(
                "/causal-cells/hydra-health/compose",
                serde_json::json!({"actor": "actor_ops"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: CausalCellResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.cell.child_cell_ids.len(), 2);
        let summary = body.cell.summary.as_ref().unwrap();
        assert!(
            summary.contains("2 of 4 self-health reflexes"),
            "summary: {summary}"
        );
        assert!(
            summary.contains("Missing: replication-lag, agent-loop-storm"),
            "summary: {summary}"
        );
    }

    #[tokio::test]
    async fn compose_hydra_health_cell_uses_tenant_scoped_reflex_cells_only() {
        // LOAD-BEARING isolation pin: reflex cells exist for
        // BOTH tenant_a and tenant_b. POSTing as tenant_a must
        // produce a parent that references ONLY tenant_a's
        // children — tenant_b's cells must be invisible.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant_a = TenantId::from_str("tenant_a_health");
        let tenant_b = TenantId::from_str("tenant_b_health");
        let theirs =
            seed_all_four(&runtime, Some(tenant_b.clone())).await;
        let ours =
            seed_all_four(&runtime, Some(tenant_a.clone())).await;
        let theirs_ids: Vec<&str> =
            theirs.iter().map(|c| c.id.as_str()).collect();
        let ours_ids: Vec<&str> =
            ours.iter().map(|c| c.id.as_str()).collect();
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(json_post_for_tenant(
                "/causal-cells/hydra-health/compose",
                tenant_a.as_str(),
                serde_json::json!({"actor": "actor_ops"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: CausalCellResponse =
            serde_json::from_slice(&read_body_bytes(response).await).unwrap();
        assert_eq!(body.cell.tenant_id, Some(tenant_a));
        for child_id in &body.cell.child_cell_ids {
            let id_str = child_id.as_str();
            assert!(
                ours_ids.contains(&id_str),
                "child {id_str} must belong to tenant_a"
            );
            assert!(
                !theirs_ids.contains(&id_str),
                "child {id_str} leaked from tenant_b"
            );
        }
    }

    #[tokio::test]
    async fn compose_hydra_health_cell_none_tenanted_reflexes_invisible() {
        // Mirror of the engine `none_tenanted_only` pin from the
        // OTHER direction. `None`-tenanted reflex cells with
        // matching subjects must NOT be composed via a tenanted
        // POST. Seed all 4 system-wide cells; then POST as a
        // tenant → 404 (no tenant-owned cells exist).
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let _system = seed_all_four(&runtime, None).await;
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(json_post(
                "/causal-cells/hydra-health/compose",
                serde_json::json!({"actor": "actor_ops"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn compose_hydra_health_cell_route_lives_in_causal_cells_router() {
        // Sanity: the new POST is mounted by the existing
        // causal_cells_router. If a future refactor moves it
        // elsewhere, this fires.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let tenant = TenantId::from_str(TEST_TENANT);
        let _children =
            seed_all_four(&runtime, Some(tenant.clone())).await;
        let app = causal_cells_router(runtime.clone());
        let response = app
            .oneshot(json_post(
                "/causal-cells/hydra-health/compose",
                serde_json::json!({"actor": "actor_ops"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
