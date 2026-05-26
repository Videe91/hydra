//! V2 patch 4A — follower puller worker.
//!
//! `ReplicationPuller::pull_once` is the building block for the
//! automatic-replication loop that lands in 4B/4C. This patch
//! intentionally ships **only** the single-shot pull:
//!
//!   1. read the follower's current local head sequence
//!   2. GET the leader's `/replication/commits?after_sequence=...&limit=...`
//!   3. if the page is empty → no-op report
//!   4. otherwise acquire `runtime.hydra().write()` and call
//!      `Hydra::apply_replication_commits` directly (engine-direct, no
//!      follower-local HTTP hop)
//!   5. return a `ReplicationPullReport`
//!
//! No background spawning, no `poll_interval` config field, no snapshot
//! bootstrap, no heartbeat emission, no error classification. Each
//! belongs to a later 4B/4C patch.
//!
//! Error model: any network / non-2xx / decode failure returns
//! `HydraError::QueryError("leader request failed: …")`. Engine
//! rejection from `apply_replication_commits` (sequence gap, wrong
//! previous_hash, leader compacted past follower head) bubbles up
//! unchanged. Failure classification is the looping worker's job.

use crate::http::replication::{
    ApplyReplicationRequest, ReplicationCommitPage, ReplicationSnapshotBodyResponse,
    ReplicationSnapshotManifestResponse,
};
use crate::runtime::RuntimeHandle;
use hydra_core::error::{HydraError, Result};
use hydra_core::{ActorId, CommitBatch, ReplicaId, SnapshotId};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Configuration for a single-shot replication pull.
///
/// `auth_token` is the bearer token the leader requires (typically the
/// `read:replication` token from the deployment's auth config). `None`
/// is valid when the leader is unsecured — same model as the
/// `AuthMode::Off` path.
///
/// `page_limit` is forwarded as the `limit` query parameter; the
/// leader's `pagination::normalized_limit` clamps to `MAX_LIMIT = 500`,
/// so callers can pass any value safely.
///
/// `restored_by` is the audit `ActorId` attached when bootstrap calls
/// `Hydra::recover_from_snapshot_body_and_replay` — typically a stable
/// per-deployment id like `actor_replica_acme_restorer`. Required at
/// config construction so audit attribution is explicit (V2 patch 4B).
///
/// `poll_interval` controls how often `run_until_cancelled` ticks
/// between `pull_once` calls (V2 patch 4D). Defaults to 1s via `new`.
///
/// `bootstrap_on_start` decides whether `run_until_cancelled` does an
/// initial `bootstrap_from_latest_snapshot` before entering the poll
/// loop (V2 patch 4D). Default `true` — safe for fresh followers and
/// for followers behind a compacted leader. Operators who know they
/// are already caught up set it to `false` for cheaper startup.
#[derive(Debug, Clone)]
pub struct ReplicationPullerConfig {
    pub peer_id: ReplicaId,
    pub leader_base_url: String,
    pub auth_token: Option<String>,
    pub page_limit: usize,
    pub restored_by: ActorId,
    pub poll_interval: Duration,
    pub bootstrap_on_start: bool,
}

impl ReplicationPullerConfig {
    /// Ergonomic constructor with sensible defaults:
    /// `auth_token = None`, `page_limit = 100`,
    /// `poll_interval = 1s`, `bootstrap_on_start = true`.
    ///
    /// Override individual fields after construction:
    ///
    /// ```ignore
    /// let mut config = ReplicationPullerConfig::new(peer, url, restorer);
    /// config.poll_interval = Duration::from_millis(250);
    /// ```
    pub fn new(
        peer_id: ReplicaId,
        leader_base_url: impl Into<String>,
        restored_by: ActorId,
    ) -> Self {
        Self {
            peer_id,
            leader_base_url: leader_base_url.into(),
            auth_token: None,
            page_limit: 100,
            restored_by,
            poll_interval: Duration::from_secs(1),
            bootstrap_on_start: true,
        }
    }
}

/// Follower-side replication puller. Owns a clone of `RuntimeHandle`
/// (RuntimeHandle is `Clone`) so 4B/4C can hold it in a long-lived
/// struct without lifetime juggling.
pub struct ReplicationPuller {
    runtime: RuntimeHandle,
    config: ReplicationPullerConfig,
    client: reqwest::Client,
}

/// Outcome of a single `pull_once` call.
///
/// `latest_sequence` and `next_after_sequence` come from the **leader's**
/// `ReplicationCommitPage`. The caller can compare `latest_sequence`
/// against the local head to learn its remaining lag without making a
/// second round trip.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplicationPullReport {
    pub peer_id: ReplicaId,
    pub requested_after_sequence: u64,
    pub fetched_count: usize,
    pub applied_count: usize,
    pub latest_sequence: Option<u64>,
    pub next_after_sequence: Option<u64>,
}

/// Idempotent process-wide install of rustls's `ring` crypto provider.
///
/// rustls 0.23 panics at runtime if more than one CryptoProvider is
/// reachable from the dep graph (currently both `ring` via rcgen and
/// `aws-lc-rs` via rustls default features are present in the
/// workspace), unless one is installed explicitly. We pin to `ring`
/// once per process before `reqwest::Client::new()` builds its rustls
/// config. `install_default` returns `Err` if a provider is already
/// installed — that's a successful idempotent no-op for us. Operators
/// who want a different provider can call `install_default` themselves
/// at startup; this `Once` only fires if nothing else has installed.
fn ensure_crypto_provider_installed() {
    static INSTALL_PROVIDER: std::sync::Once = std::sync::Once::new();
    INSTALL_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

impl ReplicationPuller {
    pub fn new(runtime: RuntimeHandle, config: ReplicationPullerConfig) -> Self {
        ensure_crypto_provider_installed();
        Self {
            runtime,
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Construct with a caller-supplied `reqwest::Client`. Useful when
    /// the caller wants to configure timeouts, custom roots, or share
    /// connection pools across multiple pullers.
    pub fn with_client(
        runtime: RuntimeHandle,
        config: ReplicationPullerConfig,
        client: reqwest::Client,
    ) -> Self {
        // Caller-supplied client may have been built by a caller that
        // already installed a provider — but if not, this keeps us
        // consistent with `new`.
        ensure_crypto_provider_installed();
        Self {
            runtime,
            config,
            client,
        }
    }

    /// Single-shot pull. See module-level docs for the algorithm.
    pub async fn pull_once(&self) -> Result<ReplicationPullReport> {
        // 1. Read this peer's replication cursor (V2 patch 4C). The
        //    cursor is stamped by `apply_replication_commits` and by
        //    `bootstrap_from_latest_snapshot` — it tracks the LEADER's
        //    chain position we've applied, not the follower's local
        //    commit_ledger head. Falling back to `latest_commit` covers
        //    the fresh-follower case where no apply has happened yet.
        //    Drop the read lock before doing network IO.
        let local_head = {
            let hydra = self.runtime.hydra();
            let hydra = hydra.read().await;
            hydra
                .latest_replication_offset(&self.config.peer_id)
                .map(|o| o.sequence)
                .or_else(|| hydra.latest_commit().map(|r| r.sequence))
                .unwrap_or(0)
        };

        // 2. Single page from the leader (shared with bootstrap tail loop).
        let page = self.fetch_commit_page(local_head).await?;
        let fetched_count = page.commits.len();

        // 3. Empty page → no-op. Still carry leader's head info forward
        //    so callers see the follower's lag in one round trip.
        if page.commits.is_empty() {
            return Ok(ReplicationPullReport {
                peer_id: self.config.peer_id.clone(),
                requested_after_sequence: local_head,
                fetched_count,
                applied_count: 0,
                latest_sequence: Some(page.leader_head_sequence),
                next_after_sequence: page.next_after_sequence,
            });
        }

        // 4. Acquire write lock and apply directly via the engine.
        //    Engine errors (sequence gap, wrong prev_hash, leader
        //    compacted past us) bubble unchanged — failure
        //    classification is the looping worker's responsibility.
        let report = {
            let hydra = self.runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.apply_replication_commits(
                self.config.peer_id.clone(),
                page.commits,
            )?
        };

        Ok(ReplicationPullReport {
            peer_id: report.peer_id,
            requested_after_sequence: local_head,
            fetched_count,
            applied_count: report.applied_count,
            latest_sequence: Some(page.leader_head_sequence),
            next_after_sequence: page.next_after_sequence,
        })
    }

    /// Echo the configured `peer_id` — handy for tests and loggers.
    pub fn peer_id(&self) -> &ReplicaId {
        &self.config.peer_id
    }

    /// V2 patch 4D — drive the puller in a loop until `shutdown` fires.
    ///
    /// Behavior:
    ///   1. **Pre-cancel short-circuit** — if `shutdown.is_cancelled()`
    ///      already, return immediately with `iterations: 0,
    ///      cancelled: true`. Useful when the shutdown signal raced
    ///      construction.
    ///   2. **Bootstrap** — if `config.bootstrap_on_start` is true,
    ///      call `bootstrap_from_latest_snapshot` first and fold its
    ///      `replayed_commits` into `total_applied`. Counts as one
    ///      iteration. Bootstrap errors fail-fast (no retry yet).
    ///   3. **Poll loop** — `select!` on `shutdown.cancelled()` versus
    ///      `tokio::time::sleep(config.poll_interval)`. On a tick, run
    ///      `pull_once` and fold its `fetched_count` / `applied_count`
    ///      into running totals.
    ///   4. **Cancellation** wins via `select!` — the report carries
    ///      `cancelled: true`.
    ///   5. **Errors fail-fast.** Any `pull_once` / bootstrap error
    ///      surfaces as `Err(HydraError::QueryError(...))`. Retry,
    ///      backoff, and transient-error classification are deferred.
    pub async fn run_until_cancelled(
        &self,
        shutdown: CancellationToken,
    ) -> Result<ReplicationLoopReport> {
        let mut report = ReplicationLoopReport {
            peer_id: self.config.peer_id.clone(),
            iterations: 0,
            total_fetched: 0,
            total_applied: 0,
            last_sequence: None,
            cancelled: false,
        };

        // Pre-cancel — return without doing any IO. Operators using a
        // graceful-shutdown path expect this when the shutdown signal
        // arrives before the loop ever ticks.
        if shutdown.is_cancelled() {
            report.cancelled = true;
            return Ok(report);
        }

        // Optional startup bootstrap.
        if self.config.bootstrap_on_start {
            let boot = self.bootstrap_from_latest_snapshot().await?;
            report.iterations += 1;
            report.total_applied += boot.replayed_commits;
            if boot.latest_sequence.is_some() {
                report.last_sequence = boot.latest_sequence;
            }
        }

        // Poll loop. `select!` lets the shutdown token preempt the
        // sleep without waiting for the full interval.
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    report.cancelled = true;
                    return Ok(report);
                }
                _ = tokio::time::sleep(self.config.poll_interval) => {
                    let pull = self.pull_once().await?;
                    report.iterations += 1;
                    report.total_fetched += pull.fetched_count;
                    report.total_applied += pull.applied_count;
                    if pull.latest_sequence.is_some() {
                        report.last_sequence = pull.latest_sequence;
                    }
                }
            }
        }
    }

    /// V2 patch 4B — bootstrap from the leader's latest snapshot, then
    /// apply every commit page after the snapshot until caught up.
    ///
    /// Algorithm:
    ///   1. `GET /replication/snapshot/latest` → manifest or `null`
    ///   2. `None` → fall back to `pull_once()` (handles the
    ///      "fresh leader with no snapshots" case cleanly)
    ///   3. `GET /replication/snapshot/:id` → `SnapshotBody`. Manifest
    ///      present but body missing is a leader bug — return error.
    ///   4. Fetch ALL tail commit pages starting from
    ///      `manifest.sequence`. Loop until `next_after_sequence` is
    ///      `None`. Defensive: also break on an empty page even when
    ///      `next_after_sequence == Some(_)`, so a misbehaving leader
    ///      can't induce an infinite loop.
    ///   5. `runtime.hydra().write()` → `recover_from_snapshot_body_and_replay`
    ///      with the body + collected tail. The engine method filters
    ///      `batch.sequence > snapshot_sequence` and sorts internally.
    ///   6. Build report.
    ///
    /// Returns `ReplicationBootstrapReport`. Bootstrap leaves the
    /// follower caught up to the leader's STATE (graph, event log,
    /// stores) as of the final tail page. New commits that landed
    /// during bootstrap require a subsequent `pull_once`.
    ///
    /// **Commit ledger note (engine behavior)**:
    /// `Hydra::recover_from_snapshot_body_and_replay` resets the
    /// follower's commit ledger before replaying events and then
    /// commits a single `SnapshotRestored` audit event. So the
    /// follower's local `latest_sequence` after bootstrap is `1` (the
    /// audit commit), NOT the leader's head sequence. The event log
    /// carries the full restored state; the commit chain effectively
    /// restarts from the bootstrap moment. A naive `pull_once` after
    /// bootstrap that requests `after_sequence=1` will hit a
    /// `previous_hash` mismatch against the leader's chain — fixing
    /// the chain-reset story is a follow-up (likely tied to runtime
    /// role config or a leader/follower chain-handshake step).
    pub async fn bootstrap_from_latest_snapshot(
        &self,
    ) -> Result<ReplicationBootstrapReport> {
        // 1. Fetch the latest manifest.
        let manifest_response: ReplicationSnapshotManifestResponse =
            self.fetch_snapshot_latest().await?;

        // 2. No snapshot on leader → pull_once fallback.
        let Some(manifest) = manifest_response.manifest else {
            let pull = self.pull_once().await?;
            return Ok(ReplicationBootstrapReport {
                peer_id: pull.peer_id,
                snapshot_id: None,
                snapshot_sequence: None,
                replayed_commits: pull.applied_count,
                latest_sequence: pull.latest_sequence,
            });
        };

        // 3. Fetch the body. Leader returning 404 here is a bug
        //    (manifest claimed the body existed) — surface as error.
        let body_response: ReplicationSnapshotBodyResponse =
            self.fetch_snapshot_body(&manifest.id).await?;
        let body = body_response.body;
        let snapshot_sequence = manifest.sequence;

        // 4. Fetch all tail pages. Defensive: bail on empty page even
        //    if `next_after_sequence` is Some, to guard against a
        //    misbehaving leader.
        let mut tail: Vec<CommitBatch> = Vec::new();
        let mut cursor = snapshot_sequence;
        loop {
            let page = self.fetch_commit_page(cursor).await?;
            if page.commits.is_empty() {
                break;
            }
            // Update cursor BEFORE moving the commits out, so we use
            // the leader's response to decide the next request.
            let next = page.next_after_sequence;
            tail.extend(page.commits);
            match next {
                Some(seq) => cursor = seq,
                None => break,
            }
        }

        // 5. Acquire write lock, recover, and stamp the replication
        //    cursor in one critical section. Cursor is the LAST tail
        //    batch's offset when the tail is non-empty; falls back to
        //    the snapshot manifest head when the tail is empty. This
        //    is the patch 4C post-bootstrap chain-handshake — `pull_once`
        //    will read this cursor instead of the follower's
        //    SnapshotRestored audit-commit head.
        let cursor_offset = if let Some(last) = tail.last() {
            hydra_core::ReplicationOffset {
                sequence: last.sequence,
                commit_id: Some(last.id.clone()),
                commit_hash: last.commit_hash.clone(),
            }
        } else {
            hydra_core::ReplicationOffset {
                sequence: snapshot_sequence,
                commit_id: manifest.head_commit_id.clone(),
                commit_hash: manifest.head_commit_hash.clone(),
            }
        };

        let manifest_applied = {
            let hydra = self.runtime.hydra();
            let mut hydra = hydra.write().await;
            let manifest = hydra.recover_from_snapshot_body_and_replay(
                body,
                tail.clone(),
                self.config.restored_by.clone(),
            )?;
            hydra.record_replication_apply_offset(
                self.config.peer_id.clone(),
                cursor_offset,
            );
            manifest
        };

        let replayed_commits = tail.len();
        let latest_sequence = {
            let hydra = self.runtime.hydra();
            let hydra = hydra.read().await;
            hydra.latest_commit().map(|r| r.sequence)
        };

        Ok(ReplicationBootstrapReport {
            peer_id: self.config.peer_id.clone(),
            snapshot_id: Some(manifest_applied.id),
            snapshot_sequence: Some(snapshot_sequence),
            replayed_commits,
            latest_sequence,
        })
    }

    /// Shared paging helper used by both `pull_once` and the bootstrap
    /// tail loop. Builds the URL, attaches the Bearer token, decodes a
    /// `ReplicationCommitPage`. All errors surface as `QueryError`.
    async fn fetch_commit_page(
        &self,
        after_sequence: u64,
    ) -> Result<ReplicationCommitPage> {
        let base = self.config.leader_base_url.trim_end_matches('/');
        let url = format!("{base}/replication/commits");
        let mut request = self.client.get(&url).query(&[
            ("after_sequence", after_sequence.to_string()),
            ("limit", self.config.page_limit.to_string()),
        ]);
        if let Some(token) = &self.config.auth_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(|err| {
            HydraError::QueryError(format!("leader request failed: {err}"))
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(HydraError::QueryError(format!(
                "leader request failed: HTTP {status}"
            )));
        }
        response.json().await.map_err(|err| {
            HydraError::QueryError(format!("leader request failed: decode {err}"))
        })
    }

    async fn fetch_snapshot_latest(
        &self,
    ) -> Result<ReplicationSnapshotManifestResponse> {
        let base = self.config.leader_base_url.trim_end_matches('/');
        let url = format!("{base}/replication/snapshot/latest");
        let mut request = self.client.get(&url);
        if let Some(token) = &self.config.auth_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(|err| {
            HydraError::QueryError(format!("leader request failed: {err}"))
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(HydraError::QueryError(format!(
                "leader request failed: HTTP {status}"
            )));
        }
        response.json().await.map_err(|err| {
            HydraError::QueryError(format!("leader request failed: decode {err}"))
        })
    }

    async fn fetch_snapshot_body(
        &self,
        id: &SnapshotId,
    ) -> Result<ReplicationSnapshotBodyResponse> {
        let base = self.config.leader_base_url.trim_end_matches('/');
        let url = format!("{base}/replication/snapshot/{id}");
        let mut request = self.client.get(&url);
        if let Some(token) = &self.config.auth_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(|err| {
            HydraError::QueryError(format!("leader request failed: {err}"))
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(HydraError::QueryError(format!(
                "leader request failed: HTTP {status}"
            )));
        }
        response.json().await.map_err(|err| {
            HydraError::QueryError(format!("leader request failed: decode {err}"))
        })
    }
}

/// V2 patch 4B — outcome of `ReplicationPuller::bootstrap_from_latest_snapshot`.
///
/// `snapshot_id` and `snapshot_sequence` are `None` when the leader had
/// no snapshot and the puller fell back to `pull_once`. In that case
/// `replayed_commits` reflects the applied-count from the fallback
/// pull. `latest_sequence` is the follower's local head after bootstrap.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplicationBootstrapReport {
    pub peer_id: ReplicaId,
    pub snapshot_id: Option<SnapshotId>,
    pub snapshot_sequence: Option<u64>,
    pub replayed_commits: usize,
    pub latest_sequence: Option<u64>,
}

/// V2 patch 4D — outcome of `ReplicationPuller::run_until_cancelled`.
///
/// `iterations` counts both the startup-bootstrap (when enabled) AND
/// each completed poll-tick. `total_fetched` and `total_applied`
/// accumulate across the whole loop. `last_sequence` is the most
/// recent value returned by the leader (head sequence on pull, or
/// follower head after bootstrap). `cancelled = true` means the
/// shutdown token fired; `cancelled = false` cannot currently happen
/// because the loop is otherwise infinite — but it is left as a
/// field so a future "max iterations" exit condition has a place to
/// land.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplicationLoopReport {
    pub peer_id: ReplicaId,
    pub iterations: u64,
    pub total_fetched: usize,
    pub total_applied: usize,
    pub last_sequence: Option<u64>,
    pub cancelled: bool,
}

/// Helper builder for the `ApplyReplicationRequest` shape — exposed so
/// custom callers can hand-roll a one-off apply without instantiating
/// the full puller. The puller itself doesn't use it (it goes engine-
/// direct), but keeping the wire shape exported here keeps callers from
/// having to dig into `crate::http::replication`.
pub fn apply_request_for(
    peer_id: ReplicaId,
    commits: Vec<hydra_core::CommitBatch>,
) -> ApplyReplicationRequest {
    ApplyReplicationRequest { peer_id, commits }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::replication::replication_router;
    use crate::runtime::RuntimeBuilder;
    use axum::{
        extract::State,
        http::HeaderMap,
        response::IntoResponse,
        routing::get,
        Json, Router,
    };
    use hydra_core::{EventKind, NodeId};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    fn signal(name: &str) -> EventKind {
        EventKind::Signal {
            source: NodeId::from_str("test.replication_worker"),
            name: name.to_string(),
            payload: HashMap::new(),
        }
    }

    fn follower_peer_id() -> ReplicaId {
        ReplicaId::from_str("replica_puller_test")
    }

    fn restorer() -> ActorId {
        ActorId::from_str("actor_test_restorer")
    }

    /// Spawn `axum::serve(listener, router)` bound to 127.0.0.1:0 and
    /// return both the assigned address and the task handle. The
    /// handle is dropped at the end of each test, killing the server.
    async fn spawn_leader(router: Router) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            // Ignore the result — test teardown happens via handle drop.
            let _ = axum::serve(listener, router).await;
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn pull_once_no_new_commits_returns_zero() {
        let (leader_runtime, _leader_proc) = RuntimeBuilder::new().build();
        let (addr, _server) = spawn_leader(replication_router(leader_runtime)).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let puller = ReplicationPuller::new(
            follower_runtime.clone(),
            ReplicationPullerConfig {
                peer_id: follower_peer_id(),
                leader_base_url: format!("http://{addr}"),
                auth_token: None,
                page_limit: 100,
                restored_by: restorer(),
                poll_interval: Duration::from_millis(10),
                bootstrap_on_start: false,
            },
        );

        let report = puller.pull_once().await.unwrap();
        assert_eq!(report.peer_id, follower_peer_id());
        assert_eq!(report.applied_count, 0);
        assert_eq!(report.fetched_count, 0);
        assert_eq!(report.requested_after_sequence, 0);
        // Leader is at sequence 0 (empty ledger).
        assert_eq!(report.latest_sequence, Some(0));
        assert!(report.next_after_sequence.is_none());
        // Follower state untouched.
        assert_eq!(
            follower_runtime.hydra().read().await.commit_count(),
            0
        );
    }

    #[tokio::test]
    async fn pull_once_fetches_and_applies_leader_commits() {
        let (leader_runtime, _leader_proc) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let (addr, _server) = spawn_leader(replication_router(leader_runtime)).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let puller = ReplicationPuller::new(
            follower_runtime.clone(),
            ReplicationPullerConfig {
                peer_id: follower_peer_id(),
                leader_base_url: format!("http://{addr}/"), // intentional trailing slash
                auth_token: None,
                page_limit: 100,
                restored_by: restorer(),
                poll_interval: Duration::from_millis(10),
                bootstrap_on_start: false,
            },
        );

        let report = puller.pull_once().await.unwrap();
        assert_eq!(report.fetched_count, 2);
        assert_eq!(report.applied_count, 2);
        assert_eq!(report.requested_after_sequence, 0);
        assert_eq!(report.latest_sequence, Some(2));
        // Single page covered everything → no continuation cursor.
        assert!(report.next_after_sequence.is_none());

        // Follower mirrors the leader.
        let follower = follower_runtime.hydra();
        let follower = follower.read().await;
        assert_eq!(follower.commit_count(), 2);
        assert_eq!(follower.events().len(), 2);
    }

    #[derive(Clone)]
    struct CaptureState {
        captured: Arc<Mutex<Vec<HeaderMap>>>,
    }

    async fn capture_handler(
        State(state): State<CaptureState>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        state.captured.lock().unwrap().push(headers);
        // Return a well-formed empty page so the puller's decode succeeds.
        Json(ReplicationCommitPage {
            commits: vec![],
            next_after_sequence: None,
            leader_head_sequence: 0,
            leader_head_commit_id: None,
        })
    }

    #[tokio::test]
    async fn pull_once_sends_bearer_token_header() {
        // Capture router replaces the real leader. We assert the
        // puller's outbound request carries `Authorization: Bearer …`.
        let captured: Arc<Mutex<Vec<HeaderMap>>> =
            Arc::new(Mutex::new(Vec::new()));
        let router = Router::new()
            .route("/replication/commits", get(capture_handler))
            .with_state(CaptureState {
                captured: captured.clone(),
            });
        let (addr, _server) = spawn_leader(router).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let puller = ReplicationPuller::new(
            follower_runtime,
            ReplicationPullerConfig {
                peer_id: follower_peer_id(),
                leader_base_url: format!("http://{addr}"),
                auth_token: Some("alpha".to_string()),
                page_limit: 100,
                restored_by: restorer(),
                poll_interval: Duration::from_millis(10),
                bootstrap_on_start: false,
            },
        );
        let report = puller.pull_once().await.unwrap();
        assert_eq!(report.applied_count, 0);

        let recorded = captured.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let auth = recorded[0]
            .get("authorization")
            .expect("Authorization header must be present");
        assert_eq!(auth.to_str().unwrap(), "Bearer alpha");
    }

    #[tokio::test]
    async fn pull_once_propagates_engine_rejection() {
        // Build a leader with 3 commits, then advance the follower's
        // head ahead of the leader's first batch so the engine rejects
        // the page on sequence gap. This is the failure mode "leader
        // compacted past follower head" surfaces as.
        let (leader_runtime, _leader_proc) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("a")).unwrap();
            hydra.ingest(signal("b")).unwrap();
            hydra.ingest(signal("c")).unwrap();
        }
        let (addr, _server) = spawn_leader(replication_router(leader_runtime)).await;

        // Follower already at sequence 1 — so the leader's page (which
        // starts at sequence 1 too since the follower asks after=1) is
        // chained off the leader's seq=1 hash, but the follower's
        // existing seq=1 hash is different. previous_hash mismatch.
        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        {
            let hydra = follower_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("follower_local")).unwrap();
        }

        let puller = ReplicationPuller::new(
            follower_runtime.clone(),
            ReplicationPullerConfig {
                peer_id: follower_peer_id(),
                leader_base_url: format!("http://{addr}"),
                auth_token: None,
                page_limit: 100,
                restored_by: restorer(),
                poll_interval: Duration::from_millis(10),
                bootstrap_on_start: false,
            },
        );
        // Follower's head is at seq=1 (its own local commit). It asks
        // the leader for `after_sequence=1`, gets the leader's seq=2..3
        // page, then engine rejects on previous_hash mismatch (the
        // leader's seq=2 previous_hash points at the LEADER's seq=1
        // hash, not the follower's).
        let err = puller.pull_once().await.unwrap_err();
        assert!(
            matches!(err, HydraError::QueryError(_)),
            "expected QueryError, got {:?}",
            err
        );
        // Follower's local state unchanged beyond its own seq=1.
        assert_eq!(
            follower_runtime.hydra().read().await.commit_count(),
            1
        );
    }

    // === V2 patch 4B — bootstrap_from_latest_snapshot ===

    #[tokio::test]
    async fn bootstrap_no_snapshot_falls_back_to_pull_once() {
        // Leader has commits but no snapshot. Bootstrap must fall back
        // to `pull_once` and apply the commits to the follower.
        let (leader_runtime, _leader_proc) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let leader_commit_count = leader_runtime.hydra().read().await.commit_count();
        let (addr, _server) = spawn_leader(replication_router(leader_runtime)).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let puller = ReplicationPuller::new(
            follower_runtime.clone(),
            ReplicationPullerConfig {
                peer_id: follower_peer_id(),
                leader_base_url: format!("http://{addr}"),
                auth_token: None,
                page_limit: 100,
                restored_by: restorer(),
                poll_interval: Duration::from_millis(10),
                bootstrap_on_start: false,
            },
        );

        let report = puller.bootstrap_from_latest_snapshot().await.unwrap();
        assert!(report.snapshot_id.is_none());
        assert!(report.snapshot_sequence.is_none());
        assert_eq!(report.replayed_commits, leader_commit_count);
        assert_eq!(report.latest_sequence, Some(leader_commit_count as u64));
        // Follower mirrors the leader.
        assert_eq!(
            follower_runtime.hydra().read().await.commit_count(),
            leader_commit_count
        );
    }

    #[tokio::test]
    async fn bootstrap_from_snapshot_restores_follower() {
        // Leader: ingest "before", snapshot, ingest "after". The
        // follower bootstraps from the snapshot and replays the tail.
        let (leader_runtime, _leader_proc) = RuntimeBuilder::new().build();
        let leader_commit_count;
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("before")).unwrap();
            hydra
                .snapshot(ActorId::from_str("actor_snapshot"))
                .unwrap();
            hydra.ingest(signal("after")).unwrap();
            leader_commit_count = hydra.commit_count();
        }
        let (addr, _server) = spawn_leader(replication_router(leader_runtime)).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let puller = ReplicationPuller::new(
            follower_runtime.clone(),
            ReplicationPullerConfig {
                peer_id: follower_peer_id(),
                leader_base_url: format!("http://{addr}"),
                auth_token: None,
                page_limit: 100,
                restored_by: restorer(),
                poll_interval: Duration::from_millis(10),
                bootstrap_on_start: false,
            },
        );

        let report = puller.bootstrap_from_latest_snapshot().await.unwrap();
        assert!(report.snapshot_id.is_some());
        assert!(report.snapshot_sequence.is_some());
        // NOTE: `recover_from_snapshot_body_and_replay` resets the
        // follower's commit ledger before replaying events, then
        // commits a `SnapshotRestored` audit event. So the follower's
        // local `latest_sequence` after bootstrap is 1 (the audit
        // commit), NOT the leader's head. The event log carries the
        // full restored state. This is honest engine behavior;
        // documented on `bootstrap_from_latest_snapshot` itself.
        assert_eq!(report.latest_sequence, Some(1));
        let _ = leader_commit_count;

        // The follower's events include BOTH "before" (replayed
        // from the snapshot body) and "after" (replayed from the tail).
        let follower = follower_runtime.hydra();
        let follower = follower.read().await;
        let signal_names: Vec<String> = follower
            .events()
            .into_iter()
            .filter_map(|event| match &event.kind {
                EventKind::Signal { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect();
        assert!(
            signal_names.contains(&"before".to_string()),
            "follower must replay before-snapshot events: {:?}",
            signal_names
        );
        assert!(
            signal_names.contains(&"after".to_string()),
            "follower must replay post-snapshot tail events: {:?}",
            signal_names
        );
    }

    #[tokio::test]
    async fn bootstrap_fetches_all_tail_pages() {
        // Leader: ingest "before" → snapshot → ingest 3 more signals.
        // page_limit=2 means the tail must be fetched in at least 2
        // pages. The bootstrap should still arrive at a fully caught
        // up follower.
        let (leader_runtime, _leader_proc) = RuntimeBuilder::new().build();
        let leader_commit_count;
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("before")).unwrap();
            hydra
                .snapshot(ActorId::from_str("actor_snapshot"))
                .unwrap();
            hydra.ingest(signal("after_one")).unwrap();
            hydra.ingest(signal("after_two")).unwrap();
            hydra.ingest(signal("after_three")).unwrap();
            leader_commit_count = hydra.commit_count();
        }
        let (addr, _server) = spawn_leader(replication_router(leader_runtime)).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let puller = ReplicationPuller::new(
            follower_runtime.clone(),
            ReplicationPullerConfig {
                peer_id: follower_peer_id(),
                leader_base_url: format!("http://{addr}"),
                auth_token: None,
                page_limit: 2, // force multi-page pagination
                restored_by: restorer(),
                poll_interval: Duration::from_millis(10),
                bootstrap_on_start: false,
            },
        );

        let report = puller.bootstrap_from_latest_snapshot().await.unwrap();
        // The exact replayed_commits count depends on engine internals
        // (snapshot() itself ingests a SnapshotTaken commit), but the
        // follower MUST have replayed more commits than fit in a single
        // page_limit=2 page — that's the multi-page proof.
        assert!(
            report.replayed_commits > 2,
            "expected >2 tail commits for multi-page test, got {}",
            report.replayed_commits
        );
        let _ = leader_commit_count;

        // All three post-snapshot signals are visible on the follower.
        let follower = follower_runtime.hydra();
        let follower = follower.read().await;
        let signal_names: Vec<String> = follower
            .events()
            .into_iter()
            .filter_map(|event| match &event.kind {
                EventKind::Signal { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect();
        for name in ["after_one", "after_two", "after_three"] {
            assert!(
                signal_names.contains(&name.to_string()),
                "follower missing {name}: got {:?}",
                signal_names
            );
        }
    }

    #[derive(Clone)]
    struct BrokenLeaderState {
        manifest: hydra_core::SnapshotManifest,
    }

    async fn broken_leader_latest(
        State(state): State<BrokenLeaderState>,
    ) -> impl IntoResponse {
        Json(ReplicationSnapshotManifestResponse {
            manifest: Some(state.manifest.clone()),
        })
    }

    async fn broken_leader_body() -> impl IntoResponse {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(crate::http::replication::ErrorResponse {
                error: "snapshot body lost".to_string(),
            }),
        )
    }

    #[tokio::test]
    async fn bootstrap_errors_on_missing_snapshot_body() {
        // Fabricated leader: /latest returns a real manifest, /:id
        // returns 404. Proves the puller surfaces the inconsistency
        // as an error rather than silently swallowing.
        let manifest = hydra_core::SnapshotManifest::committed(
            hydra_core::SnapshotId::new(),
            None,
            5,
            None,
            None,
            ActorId::from_str("actor_fake_snapshot"),
            chrono::Utc::now(),
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        );
        let router = Router::new()
            .route(
                "/replication/snapshot/latest",
                get(broken_leader_latest),
            )
            .route(
                "/replication/snapshot/:snapshot_id",
                get(broken_leader_body),
            )
            .with_state(BrokenLeaderState { manifest });
        let (addr, _server) = spawn_leader(router).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let puller = ReplicationPuller::new(
            follower_runtime.clone(),
            ReplicationPullerConfig {
                peer_id: follower_peer_id(),
                leader_base_url: format!("http://{addr}"),
                auth_token: None,
                page_limit: 100,
                restored_by: restorer(),
                poll_interval: Duration::from_millis(10),
                bootstrap_on_start: false,
            },
        );
        let err = puller.bootstrap_from_latest_snapshot().await.unwrap_err();
        assert!(
            matches!(err, HydraError::QueryError(_)),
            "expected QueryError, got {:?}",
            err
        );
        // Follower untouched.
        assert_eq!(follower_runtime.hydra().read().await.commit_count(), 0);
    }

    // === V2 patch 4C — post-bootstrap chain-handshake ===

    #[tokio::test]
    async fn bootstrap_then_pull_once_continues_from_leader_cursor() {
        // Full V2 P4C composition proof:
        //   leader: ingest "before" → snapshot → ingest "after1"
        //   follower: bootstrap_from_latest_snapshot
        //   leader: ingest "after2"
        //   follower: pull_once   ← must succeed, NOT previous_hash mismatch
        //
        // Without the patch 4C cursor, pull_once would request
        // `after_sequence=1` (the follower's SnapshotRestored audit
        // head) and the engine would reject the leader's continuation
        // batch on previous_hash mismatch. With the cursor, it requests
        // `after_sequence=<last leader head we applied>` and gets only
        // the genuinely-new "after2" batch.
        let (leader_runtime, _leader_proc) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("before")).unwrap();
            hydra
                .snapshot(ActorId::from_str("actor_snapshot"))
                .unwrap();
            hydra.ingest(signal("after1")).unwrap();
        }
        let (addr, _server) = spawn_leader(replication_router(leader_runtime.clone())).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let puller = ReplicationPuller::new(
            follower_runtime.clone(),
            ReplicationPullerConfig {
                peer_id: follower_peer_id(),
                leader_base_url: format!("http://{addr}"),
                auth_token: None,
                page_limit: 100,
                restored_by: restorer(),
                poll_interval: Duration::from_millis(10),
                bootstrap_on_start: false,
            },
        );

        // Bootstrap: pulls snapshot + tail. Follower now has the
        // restored state AND a replication cursor pointing at the
        // leader's chain head at bootstrap time.
        let bootstrap_report = puller.bootstrap_from_latest_snapshot().await.unwrap();
        assert!(bootstrap_report.snapshot_id.is_some());

        // Cursor must be stamped — that's the patch 4C guarantee.
        let cursor_after_bootstrap = {
            let hydra = follower_runtime.hydra();
            let hydra = hydra.read().await;
            hydra
                .latest_replication_offset(&follower_peer_id())
                .cloned()
                .expect("cursor must be stamped after bootstrap")
        };

        // Leader continues with another signal AFTER bootstrap.
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("after2")).unwrap();
        }

        // Follower pulls. This is the test that fails pre-4C: without
        // the cursor, pull_once would use follower.latest_commit() (1)
        // as `after_sequence`, the leader would return its full chain
        // from seq=2, and apply_replication_commits would reject on
        // previous_hash mismatch (follower's head_hash is the
        // SnapshotRestored audit commit's hash, not the leader's
        // chain hash).
        //
        // With the cursor, pull_once uses cursor.sequence
        // (= leader's head at bootstrap time) → leader returns ONLY
        // the new "after2" batch → engine appends it cleanly.
        let pull_report = puller.pull_once().await.unwrap();
        assert_eq!(
            pull_report.requested_after_sequence,
            cursor_after_bootstrap.sequence,
            "pull_once must request from the replication cursor, not local head"
        );
        assert_eq!(pull_report.fetched_count, 1);
        assert_eq!(pull_report.applied_count, 1);

        // The follower's event log now contains all three signals.
        let follower = follower_runtime.hydra();
        let follower = follower.read().await;
        let names: Vec<String> = follower
            .events()
            .into_iter()
            .filter_map(|event| match &event.kind {
                EventKind::Signal { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect();
        for name in ["before", "after1", "after2"] {
            assert!(
                names.contains(&name.to_string()),
                "follower missing {name}: got {:?}",
                names
            );
        }
    }

    // === V2 patch 4D — run_until_cancelled loop driver ===

    /// Poll `condition` every 5ms up to `timeout`. Returns when the
    /// condition is true; panics if it never is. Avoids both fixed
    /// sleeps (flaky on slow CI) and tokio-util `time::timeout`
    /// boilerplate.
    async fn wait_until<F, Fut>(timeout: Duration, mut condition: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if condition().await {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("wait_until: condition never became true within {:?}", timeout);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn loop_config(
        leader_base_url: String,
        poll_interval: Duration,
        bootstrap_on_start: bool,
    ) -> ReplicationPullerConfig {
        let mut config = ReplicationPullerConfig::new(
            follower_peer_id(),
            leader_base_url,
            restorer(),
        );
        config.poll_interval = poll_interval;
        config.bootstrap_on_start = bootstrap_on_start;
        config
    }

    async fn follower_signal_count(runtime: &RuntimeHandle) -> usize {
        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        hydra
            .events()
            .into_iter()
            .filter(|event| matches!(event.kind, EventKind::Signal { .. }))
            .count()
    }

    #[tokio::test]
    async fn run_until_cancelled_stops_without_iterations_when_cancelled_before_start() {
        // Pre-cancel — the loop must return immediately without any
        // bootstrap or pull IO. No leader server needed.
        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let puller = ReplicationPuller::new(
            follower_runtime.clone(),
            loop_config(
                "http://127.0.0.1:1".to_string(), // unreachable, won't matter
                Duration::from_millis(10),
                true,
            ),
        );
        let token = CancellationToken::new();
        token.cancel();

        let report = puller.run_until_cancelled(token).await.unwrap();
        assert!(report.cancelled);
        assert_eq!(report.iterations, 0);
        assert_eq!(report.total_fetched, 0);
        assert_eq!(report.total_applied, 0);
        // Follower untouched.
        assert_eq!(follower_runtime.hydra().read().await.commit_count(), 0);
    }

    #[tokio::test]
    async fn run_until_cancelled_bootstraps_on_start() {
        // Leader has a snapshot to bootstrap from. Loop must run the
        // bootstrap as its first iteration.
        let (leader_runtime, _leader_proc) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("before")).unwrap();
            hydra
                .snapshot(ActorId::from_str("actor_snapshot"))
                .unwrap();
            hydra.ingest(signal("after")).unwrap();
        }
        let (addr, _server) = spawn_leader(replication_router(leader_runtime)).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let puller = ReplicationPuller::new(
            follower_runtime.clone(),
            loop_config(format!("http://{addr}"), Duration::from_millis(50), true),
        );
        let token = CancellationToken::new();

        // Cancel as soon as the follower has applied the bootstrap.
        let token_clone = token.clone();
        let runtime_clone = follower_runtime.clone();
        let canceller = tokio::spawn(async move {
            wait_until(Duration::from_secs(2), || async {
                follower_signal_count(&runtime_clone).await >= 2
            })
            .await;
            token_clone.cancel();
        });

        let report = puller.run_until_cancelled(token).await.unwrap();
        canceller.await.unwrap();
        assert!(report.cancelled);
        assert!(report.iterations >= 1);
        // Bootstrap brings BOTH "before" (snapshot body) and "after"
        // (tail). Visible via the follower's event log.
        assert_eq!(follower_signal_count(&follower_runtime).await, 2);
    }

    #[tokio::test]
    async fn run_until_cancelled_polls_new_commits_until_cancelled() {
        // bootstrap_on_start: false so the first iteration is a pull.
        // Leader has one commit at start; mid-loop we ingest another;
        // the loop must catch both before cancel.
        let (leader_runtime, _leader_proc) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
        }
        let leader_for_ingest = leader_runtime.clone();
        let (addr, _server) = spawn_leader(replication_router(leader_runtime)).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let puller = ReplicationPuller::new(
            follower_runtime.clone(),
            loop_config(format!("http://{addr}"), Duration::from_millis(10), false),
        );
        let token = CancellationToken::new();

        let token_clone = token.clone();
        let follower_clone = follower_runtime.clone();
        let driver = tokio::spawn(async move {
            // Wait for the first commit to land on follower.
            wait_until(Duration::from_secs(2), || async {
                follower_signal_count(&follower_clone).await >= 1
            })
            .await;
            // Leader ingests a second.
            {
                let hydra = leader_for_ingest.hydra();
                let mut hydra = hydra.write().await;
                hydra.ingest(signal("two")).unwrap();
            }
            // Wait for the second to propagate.
            wait_until(Duration::from_secs(2), || async {
                follower_signal_count(&follower_clone).await >= 2
            })
            .await;
            token_clone.cancel();
        });

        let report = puller.run_until_cancelled(token).await.unwrap();
        driver.await.unwrap();
        assert!(report.cancelled);
        assert!(
            report.total_applied >= 2,
            "loop must have applied at least 2 commits; got {}",
            report.total_applied
        );
        assert_eq!(follower_signal_count(&follower_runtime).await, 2);
    }

    #[tokio::test]
    async fn run_until_cancelled_returns_error_on_bad_leader() {
        // Point the puller at an unreachable URL. bootstrap_on_start
        // is false so the first iteration is a pull_once; that fails
        // immediately. The loop returns Err — no retry yet.
        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let puller = ReplicationPuller::new(
            follower_runtime,
            loop_config(
                // Use port 1 — reserved, will reject TCP connect.
                "http://127.0.0.1:1".to_string(),
                Duration::from_millis(10),
                false,
            ),
        );
        let token = CancellationToken::new();
        let result = puller.run_until_cancelled(token).await;
        assert!(
            matches!(result, Err(HydraError::QueryError(_))),
            "expected QueryError, got {:?}",
            result
        );
    }
}
