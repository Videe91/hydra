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
    ApplyReplicationRequest, ReplicationCommitPage,
};
use crate::runtime::RuntimeHandle;
use hydra_core::error::{HydraError, Result};
use hydra_core::ReplicaId;

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
/// **No `poll_interval` yet.** It belongs with the loop driver in 4B/4C.
#[derive(Debug, Clone)]
pub struct ReplicationPullerConfig {
    pub peer_id: ReplicaId,
    pub leader_base_url: String,
    pub auth_token: Option<String>,
    pub page_limit: usize,
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
        // 1. Read local head (drop the read lock before doing network IO).
        let local_head = {
            let hydra = self.runtime.hydra();
            let hydra = hydra.read().await;
            hydra
                .latest_commit()
                .map(|record| record.sequence)
                .unwrap_or(0)
        };

        // 2. GET leader /replication/commits with normalized base URL
        //    (avoids `//replication` when the caller includes a trailing
        //    slash on the base).
        let base = self.config.leader_base_url.trim_end_matches('/');
        let url = format!("{base}/replication/commits");
        let mut request = self.client.get(&url).query(&[
            ("after_sequence", local_head.to_string()),
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
        let page: ReplicationCommitPage = response.json().await.map_err(|err| {
            HydraError::QueryError(format!("leader request failed: decode {err}"))
        })?;

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
}
