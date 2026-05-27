//! V2 patch 3A — leader-side replication read/export HTTP.
//!
//! This is the **first external replication surface**. It is strictly
//! read/export: a follower (or any operator) can ask the leader for
//! its head, its registered peers, and pages of commits to replay.
//! Follower apply (`POST /replication/apply`) is intentionally
//! deferred to patch 3B because applying commit tails safely is
//! engine-correctness work and is best landed separately.
//!
//! Routes:
//!
//! - `GET  /replication/status`               — head + role + peers
//! - `GET  /replication/commits`              — paged commit export
//! - `GET  /replication/peers`                — all registered peers
//! - `GET  /replication/peers/:peer_id`       — single peer, 404 on miss
//! - `GET  /replication/peers/:peer_id/lag`   — V2 polish: observed
//!   lag for the peer. Returns `200 {peer_id, lag: null}` when no
//!   observation has been recorded yet (or the peer is unknown to
//!   the in-memory ReplicationStore). This route never 404s — a
//!   non-recorded peer is a valid "no data yet" state, not an error.
//! - `POST /replication/apply`                — V2 patch 3B: follower
//!   applies a leader-supplied page of committed batches. Body is
//!   `ApplyReplicationRequest`. Validation failures map to 400 with
//!   `{error: "..."}`. See `Hydra::apply_replication_commits` for
//!   the validation contract.
//! - `GET  /replication/snapshot/latest`      — V2 patch 4B: latest
//!   snapshot manifest. Returns `{"manifest": null}` (200) when the
//!   leader has no snapshots yet, so followers don't have to treat
//!   "fresh leader" as an error.
//! - `GET  /replication/snapshot/:snapshot_id` — V2 patch 4B: full
//!   `SnapshotBody` for bootstrap. 404 on miss. These are
//!   **replication-specific exports** — the admin `/snapshots/*`
//!   surface stays separate so the two can evolve independently.
//!
//! Auth / tenant policy:
//!
//! - Replication is **cluster control plane** — `X-Hydra-Tenant` is
//!   NOT required on any of these routes.
//! - Scope gating lives in `hydra-api::auth::required_scopes_for`:
//!   `GET /replication/*` → `read:replication`,
//!   `POST /replication/*` → `admin:replication`.
//!
//! Role is hardcoded `ReplicationRole::Leader` for both `/status` and
//! `/apply` in this patch. A runtime "what role am I" config is a
//! follow-up.

use crate::http::pagination::normalized_limit;
use crate::role::{RoleState, RuntimeRole};
use crate::runtime::RuntimeHandle;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use hydra_core::{
    ActorId, CommitBatch, CommitId, ReplicaId, ReplicationLag, ReplicationPeer, ReplicationRole,
    SnapshotBody, SnapshotId, SnapshotManifest,
};
use hydra_engine::prelude::EngineRole;
use serde::{Deserialize, Serialize};

/// Shared HTTP state for the replication read routes.
#[derive(Clone)]
pub struct ReplicationHttpState {
    pub runtime: RuntimeHandle,
}

impl ReplicationHttpState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self { runtime }
    }
}

/// Build the leader-side replication HTTP router.
pub fn replication_router(runtime: RuntimeHandle) -> Router {
    Router::new()
        .route("/replication/status", get(get_replication_status))
        .route("/replication/commits", get(get_replication_commits))
        .route("/replication/peers", get(list_replication_peers))
        .route("/replication/peers/:peer_id", get(get_replication_peer))
        .route(
            "/replication/peers/:peer_id/lag",
            get(get_replication_peer_lag),
        )
        .route("/replication/apply", post(post_replication_apply))
        .route(
            "/replication/snapshot/latest",
            get(get_replication_snapshot_latest),
        )
        .route(
            "/replication/snapshot/:snapshot_id",
            get(get_replication_snapshot_body),
        )
        .with_state(ReplicationHttpState::new(runtime))
}

// === DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationCommitsQuery {
    pub after_sequence: Option<u64>,
    pub limit: Option<usize>,
}

/// Paged commit export response.
///
/// `next_after_sequence`:
///   - `Some(seq)` — pass this as `after_sequence` on the next call to
///     continue; there are more commits past the current page.
///   - `None`      — this page reached the leader's current tail.
///
/// Client pull loop:
///
/// ```text
/// while let Some(cursor) = page.next_after_sequence {
///     page = GET /replication/commits?after_sequence={cursor}
///     apply(page.commits)
/// }
/// ```
///
/// `leader_head_sequence` / `leader_head_commit_id` are always populated
/// from the leader's latest commit (or `0` / `None` on an empty ledger),
/// so follower lag is observable even on a page that returned zero
/// commits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationCommitPage {
    pub commits: Vec<CommitBatch>,
    pub next_after_sequence: Option<u64>,
    pub leader_head_sequence: u64,
    pub leader_head_commit_id: Option<CommitId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationStatusResponse {
    /// Hardcoded `Leader` in patch 3A — runtime role config lands later.
    pub role: ReplicationRole,
    pub head_sequence: u64,
    pub head_commit_id: Option<CommitId>,
    pub peers: Vec<ReplicationPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPeersResponse {
    pub peers: Vec<ReplicationPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPeerResponse {
    pub peer: ReplicationPeer,
}

/// V2 polish — observed lag for a peer. `lag: None` when no
/// observation has been recorded yet (or the peer_id is unknown
/// to the in-memory ReplicationStore). The route always returns
/// `200`; "no data yet" is `lag: null`, not 404.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationLagResponse {
    pub peer_id: ReplicaId,
    pub lag: Option<ReplicationLag>,
}

/// V2 patch 3B — follower apply request body.
///
/// `peer_id` identifies the source/leader peer (echoed back on the
/// response for audit). `commits` is the leader-supplied page from
/// `GET /replication/commits` — order MUST be strictly ascending by
/// sequence, with the first batch chaining onto the follower's
/// current head.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyReplicationRequest {
    pub peer_id: ReplicaId,
    pub commits: Vec<CommitBatch>,
}

/// V2 patch 3B — follower apply response.
///
/// Always populated regardless of `applied_count` so pull loops learn
/// the follower's cursor in one round trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyReplicationResponse {
    pub peer_id: ReplicaId,
    pub applied_count: usize,
    pub latest_sequence: Option<u64>,
    pub latest_commit_id: Option<CommitId>,
}

/// V2 patch 4B — leader's latest snapshot manifest, used by follower
/// bootstrap to decide whether to restore-then-tail-pull or fall back
/// to commits-only.
///
/// `manifest` is `Option` so an empty leader returns 200 with
/// `{"manifest": null}`, not 404 — "fresh leader" isn't an error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationSnapshotManifestResponse {
    pub manifest: Option<SnapshotManifest>,
}

/// V2 patch 4B — full snapshot body for bootstrap. Returned only when
/// the snapshot id resolves; missing ids → 404.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationSnapshotBodyResponse {
    pub body: SnapshotBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
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

// === Handlers ===

async fn get_replication_status(State(state): State<ReplicationHttpState>) -> Response {
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let (head_sequence, head_commit_id) = match hydra.latest_commit() {
        Some(record) => (record.sequence, Some(record.id.clone())),
        None => (0, None),
    };
    let peers = hydra
        .replication_store()
        .all_peers()
        .cloned()
        .collect::<Vec<_>>();
    Json(ReplicationStatusResponse {
        role: ReplicationRole::Leader,
        head_sequence,
        head_commit_id,
        peers,
    })
    .into_response()
}

async fn get_replication_commits(
    State(state): State<ReplicationHttpState>,
    Query(query): Query<ReplicationCommitsQuery>,
) -> Response {
    let after_sequence = query.after_sequence.unwrap_or(0);
    let limit = normalized_limit(query.limit);

    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let (leader_head_sequence, leader_head_commit_id) = match hydra.latest_commit() {
        Some(record) => (record.sequence, Some(record.id.clone())),
        None => (0, None),
    };

    // batches_in_sequence() returns batches ordered ascending by sequence.
    // Filter out anything <= after_sequence, then take `limit` of them.
    // We need to know whether more remain past the page to compute
    // `next_after_sequence`, so collect into a Vec and inspect the
    // remainder explicitly.
    let batches: Vec<CommitBatch> = hydra
        .commit_ledger()
        .batches_in_sequence()
        .into_iter()
        .filter(|batch| batch.sequence > after_sequence)
        .cloned()
        .collect();

    let total_after_filter = batches.len();
    let commits: Vec<CommitBatch> = batches.into_iter().take(limit).collect();
    let next_after_sequence = if commits.len() < total_after_filter {
        commits.last().map(|batch| batch.sequence)
    } else {
        None
    };

    Json(ReplicationCommitPage {
        commits,
        next_after_sequence,
        leader_head_sequence,
        leader_head_commit_id,
    })
    .into_response()
}

async fn list_replication_peers(State(state): State<ReplicationHttpState>) -> Response {
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let peers = hydra
        .replication_store()
        .all_peers()
        .cloned()
        .collect::<Vec<_>>();
    Json(ReplicationPeersResponse { peers }).into_response()
}

async fn get_replication_peer(
    State(state): State<ReplicationHttpState>,
    Path(peer_id): Path<String>,
) -> Response {
    let peer_id = ReplicaId::from_str(&peer_id);
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    match hydra.replication_peer(&peer_id) {
        Some(peer) => Json(ReplicationPeerResponse {
            peer: peer.clone(),
        })
        .into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("replication peer not found: {peer_id}"),
        ),
    }
}

async fn get_replication_peer_lag(
    State(state): State<ReplicationHttpState>,
    Path(peer_id): Path<String>,
) -> Response {
    let peer_id = ReplicaId::from_str(&peer_id);
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let lag = hydra.latest_replication_lag(&peer_id).cloned();
    // Always 200 — no observation yet is `lag: null`, not 404. The
    // puller writes a heartbeat on every pull (including empty
    // pages), so absent lag here means either nothing has pulled
    // yet, or the peer_id doesn't match the puller's configured
    // identity. Both are legitimate "no data" states.
    Json(ReplicationLagResponse { peer_id, lag }).into_response()
}

async fn post_replication_apply(
    State(state): State<ReplicationHttpState>,
    Json(request): Json<ApplyReplicationRequest>,
) -> Response {
    let ApplyReplicationRequest { peer_id, commits } = request;
    let hydra = state.runtime.hydra();
    let mut hydra = hydra.write().await;
    match hydra.apply_replication_commits(peer_id, commits) {
        Ok(report) => Json(ApplyReplicationResponse {
            peer_id: report.peer_id,
            applied_count: report.applied_count,
            latest_sequence: report.latest_sequence,
            latest_commit_id: report.latest_commit_id,
        })
        .into_response(),
        // All validation failures from apply_replication_commits surface
        // as HydraError::QueryError; map uniformly to 400. Engine doesn't
        // need a dedicated error variant for replication-input failures.
        Err(err) => error_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

async fn get_replication_snapshot_latest(
    State(state): State<ReplicationHttpState>,
) -> Response {
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let manifest = hydra.latest_snapshot_manifest().cloned();
    Json(ReplicationSnapshotManifestResponse { manifest }).into_response()
}

async fn get_replication_snapshot_body(
    State(state): State<ReplicationHttpState>,
    Path(snapshot_id): Path<String>,
) -> Response {
    let snapshot_id = SnapshotId::from_str(&snapshot_id);
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    match hydra.snapshot_body(&snapshot_id) {
        Some(body) => Json(ReplicationSnapshotBodyResponse {
            body: body.clone(),
        })
        .into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("replication snapshot not found: {snapshot_id}"),
        ),
    }
}

// === V2 polish #6 — runtime role-flip admin route ===

/// Shared state for the role-flip and role-inspection routes.
///
/// Bundles the same `RoleState` instance that hydra-api's
/// `role_middleware` reads on every request, so the HTTP middleware
/// sees a flip the instant the handler returns. Also carries the
/// `RuntimeHandle` so the handler can acquire the engine write lock
/// and call `Hydra::set_role` — keeping the HTTP role and the engine
/// role (polish #5) in lockstep.
#[derive(Clone)]
pub struct ReplicationRoleHttpState {
    pub runtime: RuntimeHandle,
    pub role_state: RoleState,
}

impl ReplicationRoleHttpState {
    pub fn new(runtime: RuntimeHandle, role_state: RoleState) -> Self {
        Self { runtime, role_state }
    }
}

/// V2 polish #6 — build the runtime role-flip + inspection router.
///
/// Routes (both gated by `admin:replication` / `read:replication`
/// in hydra-api's `required_scopes_for`):
///   - `GET  /replication/role` → 200 `{"role": "leader" | "follower"}`
///   - `POST /replication/role` → body `{"role": "..."}`, returns
///     `{previous_role, new_role, changed, at}`. Idempotent — a flip
///     to the current role returns 200 with `changed: false`.
///
/// The POST handler is the source of truth for keeping the HTTP
/// (`RoleState`) and engine (`Hydra::set_role`) roles in lockstep.
/// Replication worker coordination (auto-start/stop on flip) is
/// intentionally deferred — operators manage the puller lifecycle
/// separately.
pub fn replication_role_router(
    runtime: RuntimeHandle,
    role_state: RoleState,
) -> Router {
    Router::new()
        .route(
            "/replication/role",
            get(get_replication_role).post(post_replication_role),
        )
        .with_state(ReplicationRoleHttpState::new(runtime, role_state))
}

/// `GET /replication/role` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationRoleGetResponse {
    pub role: RuntimeRole,
}

/// `POST /replication/role` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationRoleSetRequest {
    pub role: RuntimeRole,
}

/// `POST /replication/role` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationRoleSetResponse {
    pub previous_role: RuntimeRole,
    pub new_role: RuntimeRole,
    pub changed: bool,
    pub at: DateTime<Utc>,
}

async fn get_replication_role(
    State(state): State<ReplicationRoleHttpState>,
) -> Response {
    Json(ReplicationRoleGetResponse {
        role: state.role_state.get(),
    })
    .into_response()
}

async fn post_replication_role(
    State(state): State<ReplicationRoleHttpState>,
    Json(request): Json<ReplicationRoleSetRequest>,
) -> Response {
    let target = request.role;
    let target_engine = engine_role_for(target);

    // Source of truth: the HTTP RoleState. Read previous role from
    // it BEFORE mutating, so the response reflects what the operator
    // is replacing (not what the engine happened to have, which
    // should match anyway after V2 P4H + polish #5 + this patch).
    let previous = state.role_state.get();

    // Engine-side flip first. If a future patch makes set_role
    // fallible (it doesn't today), we want to short-circuit before
    // committing the HTTP-side flip.
    {
        let hydra = state.runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra.set_role(target_engine);
    }

    // HTTP-side flip. From this Release store onward, every
    // middleware request load sees the new role.
    state.role_state.set(target);

    let changed = previous != target;
    let at = Utc::now();
    tracing::info!(
        target: "hydra::role",
        previous = ?previous,
        new = ?target,
        changed,
        "runtime role flipped"
    );

    Json(ReplicationRoleSetResponse {
        previous_role: previous,
        new_role: target,
        changed,
        at,
    })
    .into_response()
}

/// Map `RuntimeRole` (HTTP) → `EngineRole` (engine). The two enums
/// live in separate crates and are deliberately kept independent;
/// this is the only place they get translated.
fn engine_role_for(role: RuntimeRole) -> EngineRole {
    match role {
        RuntimeRole::Leader => EngineRole::Leader,
        RuntimeRole::Follower => EngineRole::Follower,
    }
}

// === V2 next-level — failover / promotion admin route ===

/// Shared state for `POST /replication/promote`.
///
/// Bundles:
///   - `runtime` — for engine write lock + `Hydra::set_role` + audit
///     event ingest + lag inspection
///   - `role_state` — same shared atomic that hydra-api's
///     `role_middleware` reads, so the HTTP role flips in lockstep
///     with the engine role (polish #6 pattern)
///   - `self_peer_id` — this node's `ReplicaId`, stamped into the
///     `ReplicaPromoted` audit commit
///   - `leader_peer_id` — the peer the follower is replicating from;
///     used by the catch-up check (lag inspection)
#[derive(Clone)]
pub struct ReplicationPromoteHttpState {
    pub runtime: RuntimeHandle,
    pub role_state: RoleState,
    pub self_peer_id: ReplicaId,
    pub leader_peer_id: ReplicaId,
}

impl ReplicationPromoteHttpState {
    pub fn new(
        runtime: RuntimeHandle,
        role_state: RoleState,
        self_peer_id: ReplicaId,
        leader_peer_id: ReplicaId,
    ) -> Self {
        Self {
            runtime,
            role_state,
            self_peer_id,
            leader_peer_id,
        }
    }
}

/// V2 next-level — build the failover/promotion router.
///
/// Single route: `POST /replication/promote` (auth gate
/// `admin:replication`). Idempotent on already-Leader (returns
/// `changed: false`). Catch-up enforced by default (rejected with
/// 409 if `lag_commits > 0`); operator can override with
/// `force: true`.
///
/// The handler is the source of truth for keeping all three
/// state surfaces in lockstep:
///   1. Engine role (`Hydra::set_role(EngineRole::Leader)`)
///   2. HTTP role (`role_state.set(RuntimeRole::Leader)`)
///   3. Cluster audit (`ReplicaPromoted` commit)
///
/// Replication worker self-exits on the next loop iteration via
/// the engine-role check at the top of `run_until_cancelled`
/// (added in this same patch).
pub fn replication_promote_router(
    runtime: RuntimeHandle,
    role_state: RoleState,
    self_peer_id: ReplicaId,
    leader_peer_id: ReplicaId,
) -> Router {
    Router::new()
        .route("/replication/promote", post(post_replication_promote))
        .route(
            "/replication/promotion-status",
            get(get_replication_promotion_status),
        )
        .with_state(ReplicationPromoteHttpState::new(
            runtime,
            role_state,
            self_peer_id,
            leader_peer_id,
        ))
}

/// `POST /replication/promote` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPromoteRequest {
    /// Required — actor responsible for the promotion (e.g.
    /// `"actor_oncall_alice"`). Audit attribution.
    pub promoted_by: ActorId,
    /// Optional human-readable reason. Stamped into the
    /// `ReplicaPromoted.reason` field. Forced promotions append
    /// `" (FORCED)"`.
    #[serde(default)]
    pub reason: Option<String>,
    /// Optional — skip the catch-up check. Use only when the leader
    /// is truly unreachable and accepting divergence is preferable
    /// to staying degraded.
    #[serde(default)]
    pub force: bool,
}

/// `POST /replication/promote` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPromoteResponse {
    pub previous_role: RuntimeRole,
    pub new_role: RuntimeRole,
    pub promoted_at: Option<DateTime<Utc>>,
    pub promotion_sequence: Option<u64>,
    pub applied_sequence_before_promotion: Option<u64>,
    pub lag_at_promotion: Option<u64>,
    pub forced: bool,
    pub changed: bool,
}

/// 409 response shape when the follower is not caught up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPromoteLagError {
    pub error: String,
    pub applied_sequence: Option<u64>,
    pub lag_commits: u64,
    pub hint: String,
}

async fn post_replication_promote(
    State(state): State<ReplicationPromoteHttpState>,
    Json(request): Json<ReplicationPromoteRequest>,
) -> Response {
    let ReplicationPromoteRequest {
        promoted_by,
        reason,
        force,
    } = request;

    // Acquire the engine write lock for the whole promotion
    // sequence so role flip + audit commit are observed atomically
    // by everything reading through the engine.
    let hydra_arc = state.runtime.hydra();
    let mut hydra = hydra_arc.write().await;

    // Idempotent path — already Leader.
    if hydra.role() == EngineRole::Leader {
        // HTTP role may be stale (operator might have flipped engine
        // role directly via set_role). Sync it on the way out.
        drop(hydra);
        state.role_state.set(RuntimeRole::Leader);
        return Json(ReplicationPromoteResponse {
            previous_role: RuntimeRole::Leader,
            new_role: RuntimeRole::Leader,
            promoted_at: None,
            promotion_sequence: None,
            applied_sequence_before_promotion: None,
            lag_at_promotion: None,
            forced: false,
            changed: false,
        })
        .into_response();
    }

    // Catch-up check — observed lag must be 0 unless force=true.
    let lag_observation = hydra
        .latest_replication_lag(&state.leader_peer_id)
        .cloned();
    let lag_commits = lag_observation
        .as_ref()
        .map(|l| l.lag_commits)
        .unwrap_or(0);
    let follower_sequence = lag_observation.as_ref().map(|l| l.follower_sequence);

    if !force && lag_commits > 0 {
        drop(hydra);
        return (
            StatusCode::CONFLICT,
            Json(ReplicationPromoteLagError {
                error: "follower not caught up".to_string(),
                applied_sequence: follower_sequence,
                lag_commits,
                hint: "wait until lag=0 or retry with force=true (accepts divergence risk)"
                    .to_string(),
            }),
        )
            .into_response();
    }

    // Step 1: flip engine role to Leader FIRST. The audit ingest
    // below would otherwise be rejected by the polish-#5 follower
    // write guard. Semantically: by the time the audit commit
    // lands, this node IS the Leader.
    hydra.set_role(EngineRole::Leader);

    // Step 2: emit the `ReplicaPromoted` audit commit through the
    // standard ingest path. The engine's `ReplicationStore` handler
    // updates the peer's status to `Promoted` as a side-effect.
    let audit_reason = match (force, reason.as_deref()) {
        (true, Some(r)) => Some(format!("{r} (FORCED)")),
        (true, None) => Some("(FORCED)".to_string()),
        (false, r) => r.map(str::to_string),
    };
    let audit_event = hydra_core::EventKind::ReplicaPromoted {
        peer_id: state.self_peer_id.clone(),
        promoted_by: promoted_by.clone(),
        reason: audit_reason.clone(),
    };
    let ingest_result = hydra.ingest(audit_event);
    let promotion_sequence = hydra.latest_commit().map(|c| c.sequence);
    drop(hydra);

    if let Err(err) = ingest_result {
        // Failed to emit audit — leave the engine role flipped
        // (operator can still write) but surface the audit failure.
        tracing::warn!(
            target: "hydra::promotion",
            error = %err,
            self_peer_id = %state.self_peer_id,
            "ReplicaPromoted audit ingest failed; engine role still flipped to Leader"
        );
        // HTTP role flip still happens so subsequent requests align.
        state.role_state.set(RuntimeRole::Leader);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("ReplicaPromoted audit ingest failed: {err}"),
        );
    }

    // Step 3: flip HTTP role (same Arc<AtomicU8> the middleware reads).
    state.role_state.set(RuntimeRole::Leader);

    if force {
        tracing::warn!(
            target: "hydra::promotion",
            self_peer_id = %state.self_peer_id,
            promoted_by = %promoted_by,
            lag_commits,
            "forced promotion — catch-up check bypassed (divergence accepted)"
        );
    } else {
        tracing::info!(
            target: "hydra::promotion",
            self_peer_id = %state.self_peer_id,
            promoted_by = %promoted_by,
            promotion_sequence = ?promotion_sequence,
            "node promoted to Leader"
        );
    }

    Json(ReplicationPromoteResponse {
        previous_role: RuntimeRole::Follower,
        new_role: RuntimeRole::Leader,
        promoted_at: Some(Utc::now()),
        promotion_sequence,
        applied_sequence_before_promotion: follower_sequence,
        lag_at_promotion: Some(lag_commits),
        forced: force,
        changed: true,
    })
    .into_response()
}

/// Audit detail for a single past promotion of this node. Returned
/// as the `last_promotion` field of `ReplicationPromotionStatusResponse`
/// when the local ledger contains at least one `ReplicaPromoted`
/// event for `self_peer_id`. Sourced from the durable commit ledger
/// (NOT the replication store), so the data survives any future
/// status mutations.
///
/// `reason` carries the operator-supplied string. Forced promotions
/// append a `(FORCED)` marker (set by the promote handler) — there
/// is no separate `forced` boolean so callers can't bypass the
/// audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastPromotionInfo {
    pub promoted_at: DateTime<Utc>,
    pub promotion_sequence: u64,
    pub promoted_by: ActorId,
    pub reason: Option<String>,
}

/// `GET /replication/promotion-status` response.
///
/// `current_role` is live engine state; `last_promotion` is durable
/// audit history. They don't have to agree — a node that was
/// promoted then demoted via `POST /replication/role` reports
/// `current_role: "follower"` AND a non-null `last_promotion`.
///
/// `last_promotion: null` when no `ReplicaPromoted` event for
/// `self_peer_id` exists in the local ledger. Always 200 (matches
/// the convention from `GET /replication/peers/:peer_id/lag` —
/// monitoring loops don't have to special-case 404 for fresh
/// deployments).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPromotionStatusResponse {
    pub self_peer_id: ReplicaId,
    pub current_role: RuntimeRole,
    pub last_promotion: Option<LastPromotionInfo>,
}

async fn get_replication_promotion_status(
    State(state): State<ReplicationPromoteHttpState>,
) -> Response {
    let hydra = state.runtime.hydra();
    let hydra = hydra.read().await;
    let current_role = match hydra.role() {
        EngineRole::Leader => RuntimeRole::Leader,
        EngineRole::Follower => RuntimeRole::Follower,
    };

    // Walk the commit ledger in reverse and stop at the most recent
    // batch carrying a `ReplicaPromoted` for `self_peer_id`. Gives
    // us both the audit fields AND the commit sequence in one pass.
    // O(events) worst case; usually finds a hit early or returns
    // None quickly on never-promoted nodes.
    let batches = hydra.commit_ledger().batches_in_sequence();
    let last_promotion = batches.iter().rev().find_map(|batch| {
        batch.events.iter().find_map(|event| {
            if let hydra_core::EventKind::ReplicaPromoted {
                peer_id,
                promoted_by,
                reason,
            } = &event.kind
            {
                if peer_id == &state.self_peer_id {
                    return Some(LastPromotionInfo {
                        promoted_at: event.timestamp,
                        promotion_sequence: batch.sequence,
                        promoted_by: promoted_by.clone(),
                        reason: reason.clone(),
                    });
                }
            }
            None
        })
    });

    Json(ReplicationPromotionStatusResponse {
        self_peer_id: state.self_peer_id.clone(),
        current_role,
        last_promotion,
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
        ActorId, EventKind, NodeId, ReplicationMode, ReplicationPeer, ReplicationRole,
    };
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn empty_get(uri: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    async fn read_json<T: for<'de> Deserialize<'de>>(response: Response) -> T {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn signal(name: &str) -> EventKind {
        EventKind::Signal {
            source: NodeId::from_str("test.replication"),
            name: name.to_string(),
            payload: HashMap::new(),
        }
    }

    fn peer_event(id: &str) -> EventKind {
        EventKind::ReplicaRegistered {
            peer: ReplicationPeer::registered(
                ReplicaId::from_str(id),
                ReplicationRole::Follower,
                ReplicationMode::SnapshotThenTail,
                ActorId::from_str("actor_replication_test"),
            ),
        }
    }

    #[tokio::test]
    async fn status_on_empty_ledger_returns_zero_head_and_leader_role() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = replication_router(runtime);
        let response = app.oneshot(empty_get("/replication/status")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationStatusResponse = read_json(response).await;
        assert_eq!(decoded.role, ReplicationRole::Leader);
        assert_eq!(decoded.head_sequence, 0);
        assert!(decoded.head_commit_id.is_none());
        assert!(decoded.peers.is_empty());
    }

    #[tokio::test]
    async fn status_after_ingest_returns_head_and_includes_peers() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(peer_event("replica_acme")).unwrap();
        }
        let app = replication_router(runtime);
        let response = app.oneshot(empty_get("/replication/status")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationStatusResponse = read_json(response).await;
        // Two cascades ingested → head_sequence is 2 (signal + peer_registered).
        assert_eq!(decoded.head_sequence, 2);
        assert!(decoded.head_commit_id.is_some());
        assert_eq!(decoded.peers.len(), 1);
        assert_eq!(decoded.peers[0].id.as_str(), "replica_acme");
    }

    #[tokio::test]
    async fn commits_after_sequence_returns_all_when_after_zero() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/commits?after_sequence=0"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationCommitPage = read_json(response).await;
        assert_eq!(decoded.commits.len(), 2);
        assert_eq!(decoded.leader_head_sequence, 2);
        assert!(decoded.next_after_sequence.is_none()); // reached tail
    }

    #[tokio::test]
    async fn commits_after_sequence_skips_earlier_commits() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/commits?after_sequence=1"))
            .await
            .unwrap();
        let decoded: ReplicationCommitPage = read_json(response).await;
        assert_eq!(decoded.commits.len(), 1);
        assert_eq!(decoded.commits[0].sequence, 2);
        assert!(decoded.next_after_sequence.is_none());
    }

    #[tokio::test]
    async fn commits_respects_limit_and_returns_next_after_sequence() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
            hydra.ingest(signal("three")).unwrap();
        }
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/commits?after_sequence=0&limit=2"))
            .await
            .unwrap();
        let decoded: ReplicationCommitPage = read_json(response).await;
        assert_eq!(decoded.commits.len(), 2);
        assert_eq!(decoded.commits[0].sequence, 1);
        assert_eq!(decoded.commits[1].sequence, 2);
        // More remain after seq=2 (seq=3 is unfetched).
        assert_eq!(decoded.next_after_sequence, Some(2));
        assert_eq!(decoded.leader_head_sequence, 3);
    }

    #[tokio::test]
    async fn peers_list_returns_registered_peers() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(peer_event("replica_acme")).unwrap();
            hydra.ingest(peer_event("replica_beta")).unwrap();
        }
        let app = replication_router(runtime);
        let response = app.oneshot(empty_get("/replication/peers")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationPeersResponse = read_json(response).await;
        assert_eq!(decoded.peers.len(), 2);
        let ids: Vec<&str> = decoded.peers.iter().map(|p| p.id.as_str()).collect();
        assert!(ids.contains(&"replica_acme"));
        assert!(ids.contains(&"replica_beta"));
    }

    #[tokio::test]
    async fn peer_by_id_returns_404_for_unknown() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/peers/replica_ghost"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // === V2 patch 3B — POST /replication/apply ===

    fn json_post(uri: &str, body: &impl Serialize) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    fn follower_peer_id() -> ReplicaId {
        ReplicaId::from_str("replica_follower_http")
    }

    #[tokio::test]
    async fn apply_empty_commits_returns_200_noop() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = replication_router(runtime);
        let request = ApplyReplicationRequest {
            peer_id: follower_peer_id(),
            commits: vec![],
        };
        let response = app
            .oneshot(json_post("/replication/apply", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ApplyReplicationResponse = read_json(response).await;
        assert_eq!(decoded.applied_count, 0);
        assert!(decoded.latest_sequence.is_none());
        assert!(decoded.latest_commit_id.is_none());
        assert_eq!(decoded.peer_id, follower_peer_id());
    }

    #[tokio::test]
    async fn apply_full_export_round_trip() {
        // Leader runs in its own runtime. Ingest two signals, export
        // commit batches, then POST them to a fresh follower's
        // /replication/apply.
        let (leader_runtime, _leader_processor) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let commits = {
            let hydra = leader_runtime.hydra();
            let hydra = hydra.read().await;
            hydra
                .commit_ledger()
                .batches_in_sequence()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };

        let (follower_runtime, _follower_processor) = RuntimeBuilder::new().build();
        let app = replication_router(follower_runtime.clone());
        let request = ApplyReplicationRequest {
            peer_id: follower_peer_id(),
            commits,
        };
        let response = app
            .oneshot(json_post("/replication/apply", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ApplyReplicationResponse = read_json(response).await;
        assert_eq!(decoded.applied_count, 2);
        assert_eq!(decoded.latest_sequence, Some(2));
        assert!(decoded.latest_commit_id.is_some());

        // Follower state should now match the leader.
        let follower_hydra = follower_runtime.hydra();
        let follower_hydra = follower_hydra.read().await;
        assert_eq!(follower_hydra.commit_count(), 2);
        assert_eq!(follower_hydra.events().len(), 2);
    }

    #[tokio::test]
    async fn apply_sequence_gap_returns_400() {
        // Build a leader chain of 3 commits, then drop the middle one to
        // manufacture a gap. The router must reject with 400.
        let (leader_runtime, _leader_processor) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("a")).unwrap();
            hydra.ingest(signal("b")).unwrap();
            hydra.ingest(signal("c")).unwrap();
        }
        let mut commits = {
            let hydra = leader_runtime.hydra();
            let hydra = hydra.read().await;
            hydra
                .commit_ledger()
                .batches_in_sequence()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        commits.remove(1); // [seq=1, seq=3] — gap at 2

        let (follower_runtime, _follower_processor) = RuntimeBuilder::new().build();
        let app = replication_router(follower_runtime);
        let request = ApplyReplicationRequest {
            peer_id: follower_peer_id(),
            commits,
        };
        let response = app
            .oneshot(json_post("/replication/apply", &request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let err: ErrorResponse = read_json(response).await;
        assert!(err.error.contains("sequence"), "got {}", err.error);
    }

    // === V2 patch 4B — snapshot bootstrap routes ===

    #[tokio::test]
    async fn replication_latest_snapshot_returns_none_when_empty() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/snapshot/latest"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationSnapshotManifestResponse = read_json(response).await;
        assert!(decoded.manifest.is_none());
    }

    #[tokio::test]
    async fn replication_latest_snapshot_returns_manifest_after_snapshot() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let snapshot_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("seed")).unwrap();
            let manifest = hydra
                .snapshot(ActorId::from_str("actor_test_snapshot"))
                .unwrap();
            snapshot_id = manifest.id.clone();
        }
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/snapshot/latest"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationSnapshotManifestResponse = read_json(response).await;
        let manifest = decoded.manifest.expect("manifest must be Some");
        assert_eq!(manifest.id, snapshot_id);
    }

    #[tokio::test]
    async fn replication_snapshot_body_returns_body() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let snapshot_id;
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("seed")).unwrap();
            let manifest = hydra
                .snapshot(ActorId::from_str("actor_test_snapshot"))
                .unwrap();
            snapshot_id = manifest.id.clone();
        }
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get(&format!("/replication/snapshot/{snapshot_id}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationSnapshotBodyResponse = read_json(response).await;
        assert_eq!(decoded.body.manifest.id, snapshot_id);
        // Seed signal lives in the body events.
        assert!(!decoded.body.events.is_empty());
    }

    #[tokio::test]
    async fn replication_snapshot_body_missing_returns_404() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/snapshot/snap_does_not_exist"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // === V2 polish — GET /replication/peers/:peer_id/lag ===

    #[tokio::test]
    async fn replication_peer_lag_returns_null_when_absent() {
        // No puller has run yet, no peer has been observed. The
        // route still returns 200 with `lag: null` rather than 404.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get("/replication/peers/replica_never_seen/lag"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationLagResponse = read_json(response).await;
        assert_eq!(decoded.peer_id.as_str(), "replica_never_seen");
        assert!(decoded.lag.is_none());
    }

    #[tokio::test]
    async fn replication_peer_lag_returns_recorded_lag() {
        // Stamp a lag observation directly into Hydra (simulates
        // what the puller does after each pull). HTTP route reads
        // it back.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let peer = ReplicaId::from_str("replica_observed");
        let lag = ReplicationLag::observe(100, 75, chrono::Utc::now());
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.record_replication_heartbeat(peer.clone(), lag.clone());
        }
        let app = replication_router(runtime);
        let response = app
            .oneshot(empty_get(&format!(
                "/replication/peers/{peer}/lag"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationLagResponse = read_json(response).await;
        assert_eq!(decoded.peer_id, peer);
        let returned = decoded.lag.expect("lag must be Some after record");
        assert_eq!(returned.leader_sequence, 100);
        assert_eq!(returned.follower_sequence, 75);
        assert_eq!(returned.lag_commits, 25);
    }

    // === V2 polish #6 — runtime role-flip admin route ===

    #[tokio::test]
    async fn replication_role_get_returns_current_role() {
        // RoleState seeded with Follower; GET must reflect that.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let role_state = RoleState::new(RuntimeRole::Follower);
        let app = replication_role_router(runtime, role_state);
        let response = app
            .oneshot(empty_get("/replication/role"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationRoleGetResponse = read_json(response).await;
        assert_eq!(decoded.role, RuntimeRole::Follower);
    }

    #[tokio::test]
    async fn replication_role_flips_leader_to_follower() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        // Seed engine + HTTP role as Leader.
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.set_role(EngineRole::Leader);
        }
        let role_state = RoleState::new(RuntimeRole::Leader);
        let app = replication_role_router(runtime.clone(), role_state.clone());

        let response = app
            .oneshot(json_post(
                "/replication/role",
                &serde_json::json!({"role": "follower"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationRoleSetResponse = read_json(response).await;
        assert_eq!(decoded.previous_role, RuntimeRole::Leader);
        assert_eq!(decoded.new_role, RuntimeRole::Follower);
        assert!(decoded.changed);

        // HTTP RoleState reflects the flip.
        assert_eq!(role_state.get(), RuntimeRole::Follower);
        // Engine role mirrors it.
        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        assert_eq!(hydra.role(), EngineRole::Follower);
    }

    #[tokio::test]
    async fn replication_role_flips_follower_to_leader() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.set_role(EngineRole::Follower);
        }
        let role_state = RoleState::new(RuntimeRole::Follower);
        let app = replication_role_router(runtime.clone(), role_state.clone());

        let response = app
            .oneshot(json_post(
                "/replication/role",
                &serde_json::json!({"role": "leader"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationRoleSetResponse = read_json(response).await;
        assert_eq!(decoded.previous_role, RuntimeRole::Follower);
        assert_eq!(decoded.new_role, RuntimeRole::Leader);
        assert!(decoded.changed);

        assert_eq!(role_state.get(), RuntimeRole::Leader);
        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        assert_eq!(hydra.role(), EngineRole::Leader);
    }

    #[tokio::test]
    async fn replication_role_noop_returns_changed_false() {
        // Same target as current role → 200 OK, changed=false.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let role_state = RoleState::new(RuntimeRole::Leader);
        let app = replication_role_router(runtime, role_state);

        let response = app
            .oneshot(json_post(
                "/replication/role",
                &serde_json::json!({"role": "leader"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationRoleSetResponse = read_json(response).await;
        assert_eq!(decoded.previous_role, RuntimeRole::Leader);
        assert_eq!(decoded.new_role, RuntimeRole::Leader);
        assert!(!decoded.changed);
    }

    // === V2 next-level — failover / promotion admin route ===

    fn promote_self_id() -> ReplicaId {
        ReplicaId::from_str("replica_self_test")
    }

    fn promote_leader_id() -> ReplicaId {
        ReplicaId::from_str("replica_leader_test")
    }

    fn promoter_actor() -> ActorId {
        ActorId::from_str("actor_oncall_promote_test")
    }

    /// Seed a Hydra with:
    ///   - `self_peer_id` registered as a `Follower` peer (matches
    ///     what cluster bootstrap would do — every node ingests
    ///     `ReplicaRegistered` events for every peer including
    ///     itself before the cluster is operational)
    ///   - observed lag against `leader_peer_id` set to the given
    ///     value (this is what the promote handler reads for
    ///     catch-up enforcement)
    /// Engine role left as Follower.
    async fn seed_follower_with_lag(
        runtime: &RuntimeHandle,
        leader_peer_id: &ReplicaId,
        lag_commits: u64,
    ) {
        let hydra_arc = runtime.hydra();
        let mut hydra = hydra_arc.write().await;
        // Register self in the local replication store. Real-world
        // deployments do this via the leader's commit log; tests do
        // it directly.
        let self_peer = ReplicationPeer::registered(
            promote_self_id(),
            ReplicationRole::Follower,
            hydra_core::ReplicationMode::SnapshotThenTail,
            ActorId::from_str("actor_cluster_bootstrap"),
        );
        hydra
            .ingest(hydra_core::EventKind::ReplicaRegistered { peer: self_peer })
            .unwrap();
        hydra.set_role(EngineRole::Follower);
        let leader_seq = 100u64;
        let follower_seq = leader_seq.saturating_sub(lag_commits);
        let lag = ReplicationLag::observe(leader_seq, follower_seq, chrono::Utc::now());
        hydra.record_replication_heartbeat(leader_peer_id.clone(), lag);
    }

    #[tokio::test]
    async fn promote_catch_up_blocks_with_409_when_lagging() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        seed_follower_with_lag(&runtime, &promote_leader_id(), 3).await;
        let role_state = RoleState::new(RuntimeRole::Follower);
        let app = replication_promote_router(
            runtime.clone(),
            role_state.clone(),
            promote_self_id(),
            promote_leader_id(),
        );

        let response = app
            .oneshot(json_post(
                "/replication/promote",
                &serde_json::json!({
                    "promoted_by": promoter_actor().as_str(),
                    "reason": "test catch-up block"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let decoded: ReplicationPromoteLagError = read_json(response).await;
        assert_eq!(decoded.lag_commits, 3);
        assert!(decoded.error.contains("not caught up"));
        // Engine role unchanged.
        assert_eq!(
            runtime.hydra().read().await.role(),
            EngineRole::Follower,
            "engine role must not flip on rejected promotion"
        );
        assert_eq!(role_state.get(), RuntimeRole::Follower);
    }

    #[tokio::test]
    async fn promote_succeeds_when_caught_up() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        seed_follower_with_lag(&runtime, &promote_leader_id(), 0).await;
        let role_state = RoleState::new(RuntimeRole::Follower);
        let app = replication_promote_router(
            runtime.clone(),
            role_state.clone(),
            promote_self_id(),
            promote_leader_id(),
        );

        let response = app
            .oneshot(json_post(
                "/replication/promote",
                &serde_json::json!({
                    "promoted_by": promoter_actor().as_str(),
                    "reason": "leader unreachable"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationPromoteResponse = read_json(response).await;
        assert_eq!(decoded.previous_role, RuntimeRole::Follower);
        assert_eq!(decoded.new_role, RuntimeRole::Leader);
        assert!(decoded.changed);
        assert!(!decoded.forced);
        assert!(decoded.promotion_sequence.is_some());

        // Engine + HTTP both flipped.
        assert_eq!(runtime.hydra().read().await.role(), EngineRole::Leader);
        assert_eq!(role_state.get(), RuntimeRole::Leader);
    }

    #[tokio::test]
    async fn promote_with_force_skips_catch_up_check() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        seed_follower_with_lag(&runtime, &promote_leader_id(), 12).await;
        let role_state = RoleState::new(RuntimeRole::Follower);
        let app = replication_promote_router(
            runtime.clone(),
            role_state.clone(),
            promote_self_id(),
            promote_leader_id(),
        );

        let response = app
            .oneshot(json_post(
                "/replication/promote",
                &serde_json::json!({
                    "promoted_by": promoter_actor().as_str(),
                    "reason": "split-brain accepted",
                    "force": true
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationPromoteResponse = read_json(response).await;
        assert_eq!(decoded.new_role, RuntimeRole::Leader);
        assert!(decoded.forced);
        assert_eq!(decoded.lag_at_promotion, Some(12));
        assert_eq!(runtime.hydra().read().await.role(), EngineRole::Leader);
    }

    #[tokio::test]
    async fn promote_is_idempotent_when_already_leader() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        // Already a Leader (engine + HTTP both Leader).
        let role_state = RoleState::new(RuntimeRole::Leader);
        let app = replication_promote_router(
            runtime.clone(),
            role_state.clone(),
            promote_self_id(),
            promote_leader_id(),
        );
        // Engine already starts as Leader (default for Hydra::new()).

        let response = app
            .oneshot(json_post(
                "/replication/promote",
                &serde_json::json!({
                    "promoted_by": promoter_actor().as_str()
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationPromoteResponse = read_json(response).await;
        assert!(!decoded.changed);
        assert_eq!(decoded.previous_role, RuntimeRole::Leader);
        assert_eq!(decoded.new_role, RuntimeRole::Leader);
        // No new audit commit emitted on the idempotent path.
        assert!(decoded.promotion_sequence.is_none());
    }

    #[tokio::test]
    async fn promote_emits_replica_promoted_audit_commit() {
        use hydra_core::EventKind;
        let (runtime, _processor) = RuntimeBuilder::new().build();
        seed_follower_with_lag(&runtime, &promote_leader_id(), 0).await;
        let role_state = RoleState::new(RuntimeRole::Follower);
        let app = replication_promote_router(
            runtime.clone(),
            role_state.clone(),
            promote_self_id(),
            promote_leader_id(),
        );

        let response = app
            .oneshot(json_post(
                "/replication/promote",
                &serde_json::json!({
                    "promoted_by": promoter_actor().as_str(),
                    "reason": "leader unreachable"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // The engine's recent events contain a ReplicaPromoted with
        // the right peer_id / promoted_by / reason.
        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        let promoted = hydra
            .events()
            .into_iter()
            .rev()
            .find_map(|event| match &event.kind {
                EventKind::ReplicaPromoted { peer_id, promoted_by, reason } => Some((
                    peer_id.clone(),
                    promoted_by.clone(),
                    reason.clone(),
                )),
                _ => None,
            })
            .expect("a ReplicaPromoted event must exist after successful promotion");
        assert_eq!(promoted.0, promote_self_id());
        assert_eq!(promoted.1, promoter_actor());
        assert_eq!(promoted.2.as_deref(), Some("leader unreachable"));
    }

    #[tokio::test]
    async fn promote_forced_appends_forced_marker_in_audit_reason() {
        use hydra_core::EventKind;
        let (runtime, _processor) = RuntimeBuilder::new().build();
        seed_follower_with_lag(&runtime, &promote_leader_id(), 7).await;
        let role_state = RoleState::new(RuntimeRole::Follower);
        let app = replication_promote_router(
            runtime.clone(),
            role_state.clone(),
            promote_self_id(),
            promote_leader_id(),
        );
        let response = app
            .oneshot(json_post(
                "/replication/promote",
                &serde_json::json!({
                    "promoted_by": promoter_actor().as_str(),
                    "reason": "split-brain",
                    "force": true
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        let reason = hydra
            .events()
            .into_iter()
            .rev()
            .find_map(|event| match &event.kind {
                EventKind::ReplicaPromoted { reason, .. } => reason.clone(),
                _ => None,
            })
            .expect("forced promotion must emit audit with reason");
        assert!(reason.contains("split-brain"));
        assert!(reason.contains("FORCED"));
    }

    // === V2 — GET /replication/promotion-status ===

    #[tokio::test]
    async fn promotion_status_returns_null_when_never_promoted() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        seed_follower_with_lag(&runtime, &promote_leader_id(), 0).await;
        let role_state = RoleState::new(RuntimeRole::Follower);
        let app = replication_promote_router(
            runtime,
            role_state,
            promote_self_id(),
            promote_leader_id(),
        );
        let response = app
            .oneshot(empty_get("/replication/promotion-status"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationPromotionStatusResponse = read_json(response).await;
        assert_eq!(decoded.self_peer_id, promote_self_id());
        assert_eq!(decoded.current_role, RuntimeRole::Follower);
        assert!(
            decoded.last_promotion.is_none(),
            "fresh follower must report no promotion history"
        );
    }

    #[tokio::test]
    async fn promotion_status_returns_last_promotion_after_promote() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        seed_follower_with_lag(&runtime, &promote_leader_id(), 0).await;
        let role_state = RoleState::new(RuntimeRole::Follower);
        let app = replication_promote_router(
            runtime.clone(),
            role_state,
            promote_self_id(),
            promote_leader_id(),
        );
        // Promote.
        let promote_resp = app
            .clone()
            .oneshot(json_post(
                "/replication/promote",
                &serde_json::json!({
                    "promoted_by": promoter_actor().as_str(),
                    "reason": "leader unreachable"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(promote_resp.status(), StatusCode::OK);
        let promote_decoded: ReplicationPromoteResponse = read_json(promote_resp).await;
        let expected_seq = promote_decoded.promotion_sequence.unwrap();

        // GET status — last_promotion mirrors the audit fields.
        let status_resp = app
            .oneshot(empty_get("/replication/promotion-status"))
            .await
            .unwrap();
        assert_eq!(status_resp.status(), StatusCode::OK);
        let decoded: ReplicationPromotionStatusResponse = read_json(status_resp).await;
        assert_eq!(decoded.current_role, RuntimeRole::Leader);
        let last = decoded.last_promotion.expect("must carry last_promotion");
        assert_eq!(last.promotion_sequence, expected_seq);
        assert_eq!(last.promoted_by, promoter_actor());
        assert_eq!(last.reason.as_deref(), Some("leader unreachable"));
    }

    #[tokio::test]
    async fn promotion_status_preserves_history_after_demotion() {
        // Promote → demote via the engine setter (the live operator
        // path is `POST /replication/role`, but the engine flip is
        // what the GET handler reads, so direct set_role here is
        // equivalent for the test). last_promotion must remain
        // populated; current_role must reflect the new Follower.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        seed_follower_with_lag(&runtime, &promote_leader_id(), 0).await;
        let role_state = RoleState::new(RuntimeRole::Follower);
        let app = replication_promote_router(
            runtime.clone(),
            role_state.clone(),
            promote_self_id(),
            promote_leader_id(),
        );
        // Promote.
        let _ = app
            .clone()
            .oneshot(json_post(
                "/replication/promote",
                &serde_json::json!({
                    "promoted_by": promoter_actor().as_str(),
                    "reason": "leader unreachable"
                }),
            ))
            .await
            .unwrap();
        // Demote the engine back to Follower (operator runbook step).
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.set_role(EngineRole::Follower);
        }

        let status_resp = app
            .oneshot(empty_get("/replication/promotion-status"))
            .await
            .unwrap();
        assert_eq!(status_resp.status(), StatusCode::OK);
        let decoded: ReplicationPromotionStatusResponse = read_json(status_resp).await;
        assert_eq!(
            decoded.current_role,
            RuntimeRole::Follower,
            "current_role must follow engine state, not history"
        );
        assert!(
            decoded.last_promotion.is_some(),
            "demotion must NOT erase the durable promotion audit"
        );
        let last = decoded.last_promotion.unwrap();
        assert_eq!(last.promoted_by, promoter_actor());
    }

    #[tokio::test]
    async fn promotion_status_filters_by_self_peer_id() {
        // The local ledger contains a ReplicaPromoted for SOME OTHER
        // peer (e.g. replayed from the leader's commit log). The
        // status route must NOT return it — only events whose
        // peer_id matches `self_peer_id` count.
        use hydra_core::EventKind;
        let (runtime, _processor) = RuntimeBuilder::new().build();
        // Seed manually so we control role-flip ordering: ingest
        // ALL events first (as Leader, the default), then flip role
        // to Follower last. The polish-#5 engine guard rejects
        // ingest on Follower, so this ordering is required.
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            // self registration (so a future promote could target self)
            hydra
                .ingest(EventKind::ReplicaRegistered {
                    peer: ReplicationPeer::registered(
                        promote_self_id(),
                        ReplicationRole::Follower,
                        hydra_core::ReplicationMode::SnapshotThenTail,
                        ActorId::from_str("actor_cluster_bootstrap"),
                    ),
                })
                .unwrap();
            // Other peer registration + ReplicaPromoted for them
            let other_id = ReplicaId::from_str("replica_some_other_node");
            hydra
                .ingest(EventKind::ReplicaRegistered {
                    peer: ReplicationPeer::registered(
                        other_id.clone(),
                        ReplicationRole::Follower,
                        hydra_core::ReplicationMode::SnapshotThenTail,
                        ActorId::from_str("actor_bootstrap"),
                    ),
                })
                .unwrap();
            hydra
                .ingest(EventKind::ReplicaPromoted {
                    peer_id: other_id,
                    promoted_by: ActorId::from_str("actor_someone_else"),
                    reason: Some("unrelated".to_string()),
                })
                .unwrap();
            hydra.set_role(EngineRole::Follower);
            hydra.record_replication_heartbeat(
                promote_leader_id(),
                ReplicationLag::observe(100, 100, chrono::Utc::now()),
            );
        }
        let role_state = RoleState::new(RuntimeRole::Follower);
        let app = replication_promote_router(
            runtime,
            role_state,
            promote_self_id(),
            promote_leader_id(),
        );

        let response = app
            .oneshot(empty_get("/replication/promotion-status"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decoded: ReplicationPromotionStatusResponse = read_json(response).await;
        assert!(
            decoded.last_promotion.is_none(),
            "ReplicaPromoted for OTHER peers must not surface in self's status"
        );
    }
}
