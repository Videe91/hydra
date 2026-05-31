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
use chrono::{DateTime, Utc};
use hydra_core::TenantId;
use hydra_net::http::tenant::{extract_tenant, tenant_error_response};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    Off,
    RequireForMutations,
    RequireForAll,
}

/// A configured bearer token, optionally bound to a tenant, with
/// optional scope and expiry constraints (Auth hardening).
///
/// Unbound tokens (`tenant_id = None`) authenticate any tenant
/// reachable via the `X-Hydra-Tenant` header. Bound tokens require the
/// header to equal the token's tenant.
///
/// **Scopes** are additive and backwards-compatible:
/// - Empty `scopes` (the default) = legacy "super-token" that bypasses
///   scope checks entirely on every route.
/// - Non-empty `scopes` = the token must contain every scope listed by
///   [`required_scopes_for`] for the requested (method, path). Missing
///   any required scope → 403.
///
/// **Expiry** is checked at lookup time. `expires_at = None` = the
/// token never expires. Otherwise the request must be served at a
/// time `<= expires_at`. Expired token → 401.
#[derive(Debug, Clone)]
pub struct AuthToken {
    pub token: String,
    pub tenant_id: Option<TenantId>,
    pub scopes: HashSet<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl AuthToken {
    /// Token with no tenant binding — the `X-Hydra-Tenant` header
    /// alone determines the scope for the request.
    pub fn unbound(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            tenant_id: None,
            scopes: HashSet::new(),
            expires_at: None,
        }
    }

    /// Token bound to a specific tenant. Requests using this token
    /// must carry `X-Hydra-Tenant: <tenant>` matching the binding; a
    /// mismatch returns 403.
    pub fn bound(token: impl Into<String>, tenant: TenantId) -> Self {
        Self {
            token: token.into(),
            tenant_id: Some(tenant),
            scopes: HashSet::new(),
            expires_at: None,
        }
    }

    /// Builder: attach a scope set. Non-empty `scopes` opt the token
    /// into per-route scope enforcement; empty `scopes` keeps the
    /// legacy bypass behavior.
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Builder: attach an expiry timestamp. Requests at or before
    /// this time succeed; after it the token returns 401.
    pub fn with_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Has this token's `expires_at` (if any) already passed at `now`?
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            Some(deadline) => now > deadline,
            None => false,
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

    /// Look up a candidate token against the configured tokens at a
    /// specific point in time. Returns:
    ///
    /// - `Valid(&AuthToken)` — token matched and is unexpired
    /// - `Expired` — token matched but its `expires_at` has passed
    /// - `NotFound` — no token matched
    ///
    /// The byte comparison is constant-time per token via
    /// [`constant_time_eq`] (whether *any* token matched does leak —
    /// the result is `Valid` vs `NotFound` — but the matched token's
    /// value does not).
    pub fn token_lookup(&self, candidate: &str, now: DateTime<Utc>) -> TokenLookupResult<'_> {
        let mut matched: Option<&AuthToken> = None;
        for token in &self.tokens {
            if constant_time_eq(token.token.as_bytes(), candidate.as_bytes()) {
                matched = Some(token);
                break;
            }
        }
        match matched {
            Some(token) if token.is_expired_at(now) => TokenLookupResult::Expired,
            Some(token) => TokenLookupResult::Valid(token),
            None => TokenLookupResult::NotFound,
        }
    }

    /// Convenience predicate for callers that only need "is this
    /// token configured *right now*?". Pre-Auth-Hardening tests use
    /// this; new code should prefer [`Self::token_lookup`].
    pub fn token_is_allowed(&self, candidate: &str) -> bool {
        matches!(
            self.token_lookup(candidate, Utc::now()),
            TokenLookupResult::Valid(_)
        )
    }
}

/// Result of looking up a candidate bearer token in [`AuthConfig`].
///
/// Three-way outcome so the middleware can map cleanly:
/// - `Valid` → 200 + AuthContext insertion
/// - `Expired` → 401 with `expired bearer token`
/// - `NotFound` → 401 with `invalid bearer token`
#[derive(Debug, Clone)]
pub enum TokenLookupResult<'a> {
    Valid(&'a AuthToken),
    Expired,
    NotFound,
}

/// Per-(method, path) required scopes table.
///
/// Returns the scopes any *scoped* token must contain to be allowed
/// to invoke this route. Empty result means "no scope requirement"
/// — either the route is open or scope grain doesn't matter yet.
///
/// Path matching is **prefix** so future sub-routes (e.g.
/// `/query/nodes/:id/bfs`) inherit their parent's scopes without an
/// entry per leaf.
///
/// Important: this table is consulted only when the matched token
/// has non-empty `scopes`. Empty-scope tokens (the default for
/// pre-Auth-Hardening builders) bypass scope checks entirely.
pub fn required_scopes_for(method: &Method, path: &str) -> Vec<&'static str> {
    if *method == Method::OPTIONS {
        return Vec::new();
    }
    let mutating = matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    if mutating {
        // Mutating routes — most specific paths first because
        // `starts_with` is a prefix test.
        if path == "/ingest" {
            return vec!["write:ingest"];
        }
        if path.starts_with("/sensor/") {
            return vec!["write:sensor"];
        }
        if path.starts_with("/schemas/") {
            return vec!["admin:schemas"];
        }
        if path == "/snapshots" || path.starts_with("/snapshots/") {
            return vec!["admin:ops"];
        }
        if path.starts_with("/maintenance/") {
            return vec!["admin:ops"];
        }
        // MicroModel Patch 5 — diagnostic evaluations mutate Hydra's
        // causal memory (prediction event, maybe evidence + claim,
        // maybe Notify action). Separate write scope so operators
        // can grant model evaluation access without granting general
        // ingest. GETs under /diagnostics/* stay at read:query (see
        // the reads block below); POSTs land here.
        if path.starts_with("/diagnostics/") {
            return vec!["write:diagnostics"];
        }
        // Trust Patch 3 (Patch 11) — trust-aware auto-execution.
        // **CRITICAL ORDERING**: this match MUST come before the
        // general `/actions/.../execute` clause below, because
        // `/auto-execute` also ends with `"execute"` — the more
        // permissive ends_with check would otherwise catch it
        // and return only `write:execute`, leaking the trust-read
        // gate.
        //
        // Auto-execute requires BOTH scopes because the route both
        // READS trust judgments (read:trust) AND may MUTATE state
        // (write:execute). A token granted execute-only can't
        // probe the trust assessment surface; a token granted
        // trust-read alone can't trigger execution.
        if path.starts_with("/actions/") && path.ends_with("/auto-execute") {
            return vec!["read:trust", "write:execute"];
        }
        // MicroModel Patch 7 — operator-triggered execution stub.
        // Match BEFORE the general /actions/* approve/reject block
        // so /actions/{id}/execute routes through `write:execute`
        // — a SEPARATE power from approval. Approval and execution
        // are distinct authorities (an operator may have one
        // without the other; future patches may also let an agent
        // execute auto-approved low-risk actions while humans
        // retain approval).
        if path.starts_with("/actions/") && path.ends_with("/execute") {
            return vec!["write:execute"];
        }
        // Trust Patch 7 (Patch 15) — trust-gated auto-approval.
        // **CRITICAL ORDERING**: this match MUST come before the
        // general /actions/* approve/reject clause below, because
        // `/auto-approve` also ends with `"approve"` — the more
        // permissive starts-with check would otherwise catch it
        // and return only `write:approvals`, leaking the trust-read
        // gate.
        //
        // Auto-approve requires BOTH scopes because the route both
        // READS trust judgments (read:trust) AND MAY MUTATE state
        // (write:approvals). A token granted approvals-only can't
        // probe the trust assessment surface; a token granted
        // trust-read alone can't trigger an auto-approval.
        if path.starts_with("/actions/") && path.ends_with("/auto-approve") {
            return vec!["read:trust", "write:approvals"];
        }
        // MicroModel Patch 6 — operator approval workflow. The
        // first human governance gate. Mutates Action status
        // (Proposed → Approved/Rejected) and records the operator
        // + reason in the audit log. Separate scope so operator
        // roles can be granted approval authority without ingest
        // or diagnostics access.
        if path == "/actions" || path.starts_with("/actions/") {
            return vec!["write:approvals"];
        }
        // V2 patch 3A: replication is cluster control plane — gate writes
        // with `admin:replication`. The POST entry is pre-wired now so V2
        // patch 3B's `POST /replication/apply` lands without re-touching
        // this function. Patch 3A itself adds no POST routes.
        if path == "/replication" || path.starts_with("/replication/") {
            return vec!["admin:replication"];
        }
        // Patch 27 — POSTs under `/causal-cells/*` mutate the
        // causal-cell store (today: `compose_hydra_health_cell`;
        // tomorrow: scheduled health auto-fire, manual reflex
        // seeding, etc.). Prefix-based so future POST routes
        // inherit the same scope automatically. GETs under the
        // same prefix stay at `read:query` (see the reads block
        // below). The two clauses keep the namespace honest:
        // reading cells is graph-query; mutating cells is its
        // own write authority.
        if path == "/causal-cells" || path.starts_with("/causal-cells/") {
            return vec!["write:causal-cells"];
        }
        // Patch 31 — POSTs under `/identity/*` mutate the Identity
        // Graph store (today: `create_identity_entity`; future:
        // identity link routes, alias-add events, etc.).
        // Prefix-based so future POST routes inherit
        // automatically. Reading identities stays at
        // `read:identity` below — identities are their own
        // concern (a meaning layer), not graph data or trust.
        if path == "/identity" || path.starts_with("/identity/") {
            return vec!["write:identity"];
        }
        return Vec::new();
    }
    // Reads.
    if path.starts_with("/query/") {
        return vec!["read:query"];
    }
    if path == "/events" || path.starts_with("/events/") {
        return vec!["read:audit"];
    }
    if path == "/commits" || path.starts_with("/commits/") {
        return vec!["read:audit"];
    }
    // V2 next-level — lineage is fundamentally an audit/explain
    // operation, not a graph query. Gate under read:audit alongside
    // events and commits.
    if path.starts_with("/lineage/") {
        return vec!["read:audit"];
    }
    // Living-database phase — diagnostics is current-state
    // introspection (anomaly detection, coverage, counterfactual,
    // evolution metrics). Operators with `read:query` for
    // monitoring dashboards should poll diagnostics without
    // escalating to `read:audit`.
    if path.starts_with("/diagnostics/") {
        return vec!["read:query"];
    }
    if path == "/snapshots" || path.starts_with("/snapshots/") {
        return vec!["read:ops"];
    }
    if path.starts_with("/schemas/") || path == "/schemas" {
        return vec!["read:schemas"];
    }
    if path == "/replication" || path.starts_with("/replication/") {
        return vec!["read:replication"];
    }
    // Trust Patch 2 (Patch 10) — trust is governance / intelligence
    // state, not generic query data. Granting `read:query` should
    // NOT automatically grant visibility into trust judgments
    // (which may eventually expose source / agent / model risk).
    // Reserved for the whole `/trust/*` namespace so future
    // `/trust/sources/*`, `/trust/actions/*` etc. inherit the
    // same scope without re-touching this map.
    if path.starts_with("/trust/") {
        return vec!["read:trust"];
    }
    // Patch 25 — CausalCell read/query surface. Cells ARE graph
    // data (composition primitive over events / claims / actions),
    // so they gate under `read:query` alongside `/query/*` and
    // `/diagnostics/*`. Trust over cells stays under `/trust/cells/*`
    // and `read:trust` — separation preserved.
    if path == "/causal-cells" || path.starts_with("/causal-cells/") {
        return vec!["read:query"];
    }
    // Patch 31 — Identity Graph read surface. Distinct from
    // `read:query` (graph data) and `read:trust` (governance) —
    // identities are the meaning layer, semantic resolution of
    // "same real thing, many names". Future GET routes under
    // `/identity/*` (identity links, alias diff, etc.) inherit
    // automatically via this prefix.
    if path == "/identity" || path.starts_with("/identity/") {
        return vec!["read:identity"];
    }
    Vec::new()
}

fn is_mutating_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// V2 patch 4H — classify whether a route should be rejected on a
/// Follower node.
///
/// Returns `true` for engine-mutating routes a Follower must NOT
/// serve (the Leader is the source of truth for these writes).
/// Returns `false` for:
///   - `POST /replication/apply` — the follower's primary receiving
///     route; rejecting it would break replication.
///   - `POST /schemas/validate/*` — preflight validation, no mutation.
///   - all `GET` / `OPTIONS`.
///
/// Mirrors the shape of `required_scopes_for`: a single function that
/// classifies (method, path) by policy. Followers running behind a
/// reverse proxy that wants to short-circuit writes can also consult
/// this rule.
pub fn rejected_on_follower(method: &Method, path: &str) -> bool {
    // Reads + CORS preflight always pass.
    if matches!(*method, Method::GET | Method::OPTIONS | Method::HEAD) {
        return false;
    }
    // Any other mutating method on any path is fatal to a follower
    // unless explicitly allowed below.
    if !is_mutating_method(method) {
        // Unknown method — let the inner router decide. Don't gate.
        return false;
    }
    // `POST /replication/apply` — primary follower-receiving route.
    if path == "/replication/apply" {
        return false;
    }
    // Preflight schema validation — read-only.
    if path.starts_with("/schemas/validate/") {
        return false;
    }
    // Mutating engine routes that only a Leader should handle.
    if path == "/ingest" {
        return true;
    }
    if path.starts_with("/sensor/") {
        return true;
    }
    if path == "/snapshots" || path.starts_with("/snapshots/") {
        return true;
    }
    if path.starts_with("/schemas/") || path == "/schemas" {
        return true;
    }
    if path.starts_with("/maintenance/") {
        return true;
    }
    // Everything else: keep open (unknown routes return 404 from the
    // inner router; gating them at the role layer would be confusing).
    false
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
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    if !state.config.has_tokens() {
        tracing::warn!(
            target: "hydra::auth",
            reason = "no configured tokens",
            method = %method,
            path = %path,
            "auth failure"
        );
        return auth_error(
            StatusCode::UNAUTHORIZED,
            "authentication is required but no bearer tokens are configured",
        );
    }
    let Some(token) = bearer_token(request.headers()) else {
        tracing::warn!(
            target: "hydra::auth",
            reason = "missing bearer token",
            method = %method,
            path = %path,
            "auth failure"
        );
        return auth_error(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    let now = Utc::now();
    match state.config.token_lookup(token, now) {
        TokenLookupResult::Valid(matched) => {
            // Scope check — only enforced when the matched token has
            // non-empty `scopes`. Empty-scope tokens preserve legacy
            // bypass behavior so pre-Auth-Hardening configurations
            // keep working unchanged.
            if !matched.scopes.is_empty() {
                let required = required_scopes_for(&method, &path);
                if !required.is_empty()
                    && !required.iter().all(|scope| matched.scopes.contains(*scope))
                {
                    tracing::warn!(
                        target: "hydra::auth",
                        reason = "missing required scope",
                        method = %method,
                        path = %path,
                        required = ?required,
                        "auth failure"
                    );
                    return auth_error(
                        StatusCode::FORBIDDEN,
                        format!(
                            "bearer token is missing required scope(s) for {method} {path}"
                        ),
                    );
                }
            }
            // Hand the tenant binding (if any) downstream so the
            // tenant-binding middleware can enforce match-not-override.
            request.extensions_mut().insert(AuthContext {
                tenant_id: matched.tenant_id.clone(),
            });
            next.run(request).await
        }
        TokenLookupResult::Expired => {
            tracing::warn!(
                target: "hydra::auth",
                reason = "expired bearer token",
                method = %method,
                path = %path,
                "auth failure"
            );
            auth_error(StatusCode::UNAUTHORIZED, "expired bearer token")
        }
        TokenLookupResult::NotFound => {
            tracing::warn!(
                target: "hydra::auth",
                reason = "invalid bearer token",
                method = %method,
                path = %path,
                "auth failure"
            );
            auth_error(StatusCode::UNAUTHORIZED, "invalid bearer token")
        }
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
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    // Token is bound — header is required and must match. Reuse the
    // same parser hydra-net handlers use so the 400 contract stays
    // consistent.
    let header_tenant = match extract_tenant(request.headers()) {
        Ok(t) => t,
        Err(err) => {
            tracing::warn!(
                target: "hydra::auth",
                reason = ?err,
                method = %method,
                path = %path,
                "tenant header invalid on bound-token request"
            );
            return tenant_error_response(err);
        }
    };
    if header_tenant != bound {
        tracing::warn!(
            target: "hydra::auth",
            reason = "tenant binding mismatch",
            method = %method,
            path = %path,
            bound = %bound,
            header = %header_tenant,
            "auth failure"
        );
        return auth_error(
            StatusCode::FORBIDDEN,
            format!(
                "bearer token is bound to tenant {bound}; X-Hydra-Tenant header is {header_tenant}"
            ),
        );
    }
    next.run(request).await
}

/// V2 patch 4H — shared state for the role middleware.
///
/// V2 polish #6 — the role is now runtime-mutable via the
/// `POST /replication/role` admin route. `RoleState` is re-exported
/// from `hydra_net::role` and wraps an `Arc<AtomicU8>` so the
/// middleware and the role-flip handler share storage. The
/// middleware reads via `state.get()` (single `Ordering::Acquire`
/// load per request).
pub use hydra_net::role::RoleState;

/// V2 patch 4H — Follower-write-rejection middleware.
///
/// When the shared [`RoleState`] currently reads `Follower`,
/// rejects engine-mutating routes (per [`rejected_on_follower`])
/// with `409 Conflict` and `{"error": "follower is read-only"}`.
/// Leaders pass everything through unchanged.
///
/// Always-allowed even on a Follower:
///   - `POST /replication/apply` (primary receiving route)
///   - `POST /replication/role` (self-promotion target — falls
///     through to the role-flip handler)
///   - `POST /schemas/validate/*` (preflight, no mutation)
///   - `GET` / `OPTIONS` / `HEAD`
///
/// V2 polish #6 — the layer is now **always installed**, not
/// conditional on `role == Follower` at boot. The hot Leader path
/// is a single `Ordering::Acquire` atomic load + branch. This is
/// what makes runtime role flipping work: the middleware sees the
/// flipped value immediately after the admin route returns.
///
/// Audit logging via `tracing::warn!` on every rejection, matching
/// the auth / tenant-binding pattern. Combined with the engine-level
/// role guard from polish #5, this closes both the HTTP and the
/// in-process write paths.
pub async fn role_middleware(
    State(state): State<RoleState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if matches!(state.get(), crate::security::RuntimeRole::Leader) {
        return next.run(request).await;
    }
    // Follower path.
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    if !rejected_on_follower(&method, &path) {
        return next.run(request).await;
    }
    tracing::warn!(
        target: "hydra::role",
        role = "Follower",
        method = %method,
        path = %path,
        "follower rejected mutating route"
    );
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error": "follower is read-only"})),
    )
        .into_response()
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

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    fn matched_token<'a>(result: TokenLookupResult<'a>) -> &'a AuthToken {
        match result {
            TokenLookupResult::Valid(token) => token,
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn string_token_builder_creates_unbound_tokens() {
        // Backwards-compat: pre-Patch-3 callers using the string
        // builder get tokens with no tenant binding, no scopes, and
        // no expiry.
        let config = AuthConfig::require_for_mutations(["alpha"]);
        let token = matched_token(config.token_lookup("alpha", now()));
        assert_eq!(token.token, "alpha");
        assert!(token.tenant_id.is_none());
        assert!(token.scopes.is_empty());
        assert!(token.expires_at.is_none());
    }

    #[test]
    fn bound_token_builder_stores_tenant_binding() {
        let tenant = TenantId::from_str("tenant_acme");
        let config = AuthConfig::require_for_all_with_tokens([
            AuthToken::bound("alpha", tenant.clone()),
            AuthToken::unbound("beta"),
        ]);
        let alpha = matched_token(config.token_lookup("alpha", now()));
        assert_eq!(alpha.tenant_id.as_ref(), Some(&tenant));
        let beta = matched_token(config.token_lookup("beta", now()));
        assert!(beta.tenant_id.is_none());
    }

    #[test]
    fn token_lookup_returns_not_found_for_unconfigured() {
        let config = AuthConfig::require_for_all(["alpha"]);
        assert!(matches!(
            config.token_lookup("beta", now()),
            TokenLookupResult::NotFound
        ));
        assert!(matches!(
            config.token_lookup("", now()),
            TokenLookupResult::NotFound
        ));
    }

    // === Auth Hardening ===

    #[test]
    fn token_lookup_reports_expired_when_past_deadline() {
        let now_ts = Utc::now();
        let past = now_ts - chrono::Duration::seconds(60);
        let config = AuthConfig::require_for_all_with_tokens([
            AuthToken::unbound("alpha").with_expiry(past),
        ]);
        assert!(matches!(
            config.token_lookup("alpha", now_ts),
            TokenLookupResult::Expired
        ));
    }

    #[test]
    fn token_lookup_is_valid_before_deadline() {
        let now_ts = Utc::now();
        let future = now_ts + chrono::Duration::seconds(60);
        let config = AuthConfig::require_for_all_with_tokens([
            AuthToken::unbound("alpha").with_expiry(future),
        ]);
        assert!(matches!(
            config.token_lookup("alpha", now_ts),
            TokenLookupResult::Valid(_)
        ));
    }

    #[test]
    fn token_lookup_with_no_expiry_is_always_valid() {
        // expires_at = None means "never expires" — token_lookup
        // returns Valid even at far-future timestamps.
        let config = AuthConfig::require_for_all(["alpha"]);
        let far_future = Utc::now() + chrono::Duration::days(365 * 10);
        assert!(matches!(
            config.token_lookup("alpha", far_future),
            TokenLookupResult::Valid(_)
        ));
    }

    #[test]
    fn required_scopes_table_covers_write_and_read_buckets() {
        // Spot-check the policy without being exhaustive.
        assert_eq!(
            required_scopes_for(&Method::POST, "/ingest"),
            vec!["write:ingest"]
        );
        assert_eq!(
            required_scopes_for(&Method::POST, "/sensor/observation"),
            vec!["write:sensor"]
        );
        assert_eq!(
            required_scopes_for(&Method::POST, "/schemas/entity"),
            vec!["admin:schemas"]
        );
        assert_eq!(
            required_scopes_for(&Method::POST, "/snapshots"),
            vec!["admin:ops"]
        );
        // MicroModel Patch 5 — POSTs under /diagnostics/* require
        // the new `write:diagnostics` scope. GETs under the same
        // prefix keep `read:query` (asserted below). The split is
        // load-bearing: diagnostic reads are safe; diagnostic
        // evaluations mutate Hydra's causal memory.
        assert_eq!(
            required_scopes_for(
                &Method::POST,
                "/diagnostics/micromodels/commit-rate/evaluate",
            ),
            vec!["write:diagnostics"]
        );
        assert_eq!(
            required_scopes_for(&Method::GET, "/diagnostics/anomaly"),
            vec!["read:query"]
        );
        // MicroModel Patch 6 — operator approval workflow. POSTs to
        // /actions/{id}/approve and /actions/{id}/reject require
        // the new `write:approvals` scope. Separate from
        // write:diagnostics so operator roles can be granted
        // approval authority without anything else.
        assert_eq!(
            required_scopes_for(&Method::POST, "/actions/act-123/approve"),
            vec!["write:approvals"]
        );
        assert_eq!(
            required_scopes_for(&Method::POST, "/actions/act-123/reject"),
            vec!["write:approvals"]
        );
        // MicroModel Patch 7 — execution stub. /actions/{id}/execute
        // requires the new `write:execute` scope, distinct from
        // write:approvals. Match must come BEFORE the general
        // /actions/* approve/reject block (asserted here so any
        // future ordering regression is caught).
        assert_eq!(
            required_scopes_for(&Method::POST, "/actions/act-123/execute"),
            vec!["write:execute"]
        );
        // MicroModel Patch 8 — outcome learning loop. Observation
        // recording is a diagnostic surface (it mutates Hydra's
        // causal memory by writing a MicroModelObservationRecorded
        // event), so it reuses `write:diagnostics` — same scope as
        // Patch 5's commit-rate evaluation. No new scope.
        assert_eq!(
            required_scopes_for(
                &Method::POST,
                "/diagnostics/micromodels/observations/from-outcome/out-123",
            ),
            vec!["write:diagnostics"]
        );
        // Trust Patch 3 (Patch 11) — trust-aware auto-execute
        // requires BOTH read:trust and write:execute. CRITICAL:
        // the path match MUST come before the general
        // /actions/.../execute clause because /auto-execute also
        // ends with "execute". This pin catches ordering
        // regressions immediately — if a future refactor reorders
        // these clauses, this test fires before the route's
        // security envelope silently drops to write:execute only.
        assert_eq!(
            required_scopes_for(
                &Method::POST,
                "/actions/act-123/auto-execute",
            ),
            vec!["read:trust", "write:execute"]
        );
        // Trust Patch 7 (Patch 15) — trust-gated auto-approval
        // requires BOTH read:trust and write:approvals. Same
        // ordering trap as auto-execute: /auto-approve starts with
        // /actions/ and would otherwise be caught by the general
        // /actions/* → write:approvals clause, silently dropping
        // the trust-read gate. This pin catches that regression.
        assert_eq!(
            required_scopes_for(
                &Method::POST,
                "/actions/act-123/auto-approve",
            ),
            vec!["read:trust", "write:approvals"]
        );
        assert_eq!(
            required_scopes_for(&Method::GET, "/query/nodes"),
            vec!["read:query"]
        );
        assert_eq!(
            required_scopes_for(&Method::GET, "/events"),
            vec!["read:audit"]
        );
        assert_eq!(
            required_scopes_for(&Method::GET, "/commits"),
            vec!["read:audit"]
        );
        // V2 patch 3A — replication routes. GET → read:replication.
        assert_eq!(
            required_scopes_for(&Method::GET, "/replication/status"),
            vec!["read:replication"]
        );
        assert_eq!(
            required_scopes_for(&Method::GET, "/replication/commits"),
            vec!["read:replication"]
        );
        assert_eq!(
            required_scopes_for(&Method::GET, "/replication/peers"),
            vec!["read:replication"]
        );
        // POST is pre-wired to admin:replication for 3B even though
        // no POST route exists yet.
        assert_eq!(
            required_scopes_for(&Method::POST, "/replication/apply"),
            vec!["admin:replication"]
        );
        // Trust Patch 2 (Patch 10) — /trust/* gets its own
        // `read:trust` scope, separate from read:query, because
        // trust is governance/intelligence state. The whole
        // namespace is reserved up front so future
        // `/trust/sources/*` etc. inherit automatically.
        assert_eq!(
            required_scopes_for(&Method::GET, "/trust/claims/claim_abc"),
            vec!["read:trust"]
        );
        // Patch 24 — cell trust inherits the same `read:trust`
        // scope automatically via the `/trust/*` prefix clause.
        // This pin catches a regression where a future refactor
        // accidentally narrows the prefix or splits the namespace.
        assert_eq!(
            required_scopes_for(&Method::GET, "/trust/cells/cell_abc"),
            vec!["read:trust"]
        );
        // Patch 25 — CausalCell read/query routes. Cells are graph
        // data (composition primitive), gated under `read:query`.
        // Cell TRUST stays under `/trust/cells/*` → `read:trust`;
        // these pins keep the two namespaces visibly separate so a
        // future refactor can't collapse them silently.
        assert_eq!(
            required_scopes_for(&Method::GET, "/causal-cells"),
            vec!["read:query"]
        );
        assert_eq!(
            required_scopes_for(&Method::GET, "/causal-cells/cell_abc"),
            vec!["read:query"]
        );
        // Patch 27 — POSTs under /causal-cells/* are gated by
        // the new `write:causal-cells` scope. The prefix clause
        // covers `POST /causal-cells/hydra-health/compose` and
        // any future POST routes (scheduled health auto-fire,
        // manual reflex seeding, etc.). This pin keeps GET vs
        // POST scopes visibly separate so a future refactor
        // can't collapse them silently.
        assert_eq!(
            required_scopes_for(
                &Method::POST,
                "/causal-cells/hydra-health/compose"
            ),
            vec!["write:causal-cells"]
        );
        // Patch 31 — Identity Graph HTTP surface. Distinct
        // scopes from `read:query` / `write:causal-cells` since
        // identities are the meaning layer (canonical entities +
        // semantic resolution), not graph data.
        // GET routes:
        assert_eq!(
            required_scopes_for(&Method::GET, "/identity/entities"),
            vec!["read:identity"]
        );
        assert_eq!(
            required_scopes_for(&Method::GET, "/identity/entities/ide_x"),
            vec!["read:identity"]
        );
        assert_eq!(
            required_scopes_for(&Method::GET, "/identity/matches"),
            vec!["read:identity"]
        );
        // POST routes:
        assert_eq!(
            required_scopes_for(&Method::POST, "/identity/entities"),
            vec!["write:identity"]
        );
        // OPTIONS always has no scope requirement (CORS preflight).
        assert!(required_scopes_for(&Method::OPTIONS, "/ingest").is_empty());
        // Routes with no entry don't require any scope.
        assert!(required_scopes_for(&Method::GET, "/health").is_empty());
    }

    #[test]
    fn rejected_on_follower_classifier_covers_mutation_buckets() {
        // V2 patch 4H — locks the classifier table.

        // Reject on Follower (engine-mutating POST routes):
        assert!(rejected_on_follower(&Method::POST, "/ingest"));
        assert!(rejected_on_follower(&Method::POST, "/sensor/observation"));
        assert!(rejected_on_follower(&Method::POST, "/sensor/cloudtrail"));
        assert!(rejected_on_follower(&Method::POST, "/snapshots"));
        assert!(rejected_on_follower(
            &Method::POST,
            "/snapshots/snap_x/restore"
        ));
        assert!(rejected_on_follower(&Method::POST, "/schemas/entity"));
        assert!(rejected_on_follower(&Method::POST, "/schemas/edge"));
        assert!(rejected_on_follower(
            &Method::POST,
            "/schemas/snap_x/disable"
        ));
        assert!(rejected_on_follower(
            &Method::POST,
            "/maintenance/compact"
        ));
        // Any PUT / PATCH / DELETE on an unknown path is also rejected
        // because the classifier defaults to blocking mutating methods
        // unless explicitly allowed.
        assert!(rejected_on_follower(&Method::PUT, "/ingest"));
        assert!(rejected_on_follower(&Method::DELETE, "/snapshots/snap_x"));

        // Allow on Follower:
        assert!(!rejected_on_follower(
            &Method::POST,
            "/replication/apply"
        ));
        assert!(!rejected_on_follower(
            &Method::POST,
            "/schemas/validate/node-create"
        ));
        assert!(!rejected_on_follower(
            &Method::POST,
            "/schemas/validate/edge-create"
        ));
        // Reads always pass.
        assert!(!rejected_on_follower(&Method::GET, "/ingest"));
        assert!(!rejected_on_follower(&Method::GET, "/schemas/entity"));
        assert!(!rejected_on_follower(&Method::OPTIONS, "/ingest"));
        assert!(!rejected_on_follower(&Method::HEAD, "/ingest"));
    }

    #[test]
    fn auth_token_with_scopes_builder_round_trips() {
        let token = AuthToken::unbound("alpha")
            .with_scopes(["read:query", "write:ingest"]);
        assert_eq!(token.scopes.len(), 2);
        assert!(token.scopes.contains("read:query"));
        assert!(token.scopes.contains("write:ingest"));
    }

    #[test]
    fn auth_token_is_expired_at_checks_deadline() {
        let now_ts = Utc::now();
        let unexpired = AuthToken::unbound("a")
            .with_expiry(now_ts + chrono::Duration::seconds(60));
        let expired = AuthToken::unbound("b")
            .with_expiry(now_ts - chrono::Duration::seconds(60));
        let no_expiry = AuthToken::unbound("c");
        assert!(!unexpired.is_expired_at(now_ts));
        assert!(expired.is_expired_at(now_ts));
        assert!(!no_expiry.is_expired_at(now_ts));
    }
}
