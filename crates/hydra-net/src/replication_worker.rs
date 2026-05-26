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
use axum::http::StatusCode;
use hydra_core::error::{HydraError, Result};
use hydra_core::{ActorId, CommitBatch, ReplicaId, ReplicationOffset, SnapshotId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// V2 patch 4E — classified replication failure modes.
///
/// Transient kinds (`Network`, `LeaderUnavailable`, `RateLimited`) are
/// retried with exponential backoff by `run_until_cancelled`. Fatal
/// kinds (everything else) cause the loop to surface
/// `Err(ReplicationLoopError { report, .. })` so the caller sees both
/// the partial report and the precise failure kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicationPullErrorKind {
    /// reqwest connect / timeout / unreachable. Transient.
    Network,
    /// HTTP 5xx from the leader. Transient — the leader is up but
    /// transiently unable to serve.
    LeaderUnavailable,
    /// HTTP 401 — auth token missing / invalid / expired. Fatal:
    /// retrying without operator intervention won't fix it.
    Unauthorized,
    /// HTTP 403 — token authenticated but missing
    /// `read:replication`. Fatal.
    Forbidden,
    /// HTTP 429 — rate-limited. Transient.
    RateLimited,
    /// HTTP 4xx (other) or JSON decode failure. Fatal: leader is
    /// emitting something we can't parse, and retrying without a
    /// leader fix is pointless.
    BadLeaderResponse,
    /// Engine rejected a batch because the leader's chain doesn't
    /// continue from where we expected: sequence gap, previous_hash
    /// mismatch, hash recompute disagreement. Fatal — likely needs
    /// re-bootstrap.
    ChainDivergence,
    /// Engine rejected for any other reason (uncommitted batch,
    /// missing commit_hash, validation outside the chain-continuity
    /// shape). Fatal.
    EngineRejected,
}

impl ReplicationPullErrorKind {
    /// `true` if the loop driver should back off and retry.
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            ReplicationPullErrorKind::Network
                | ReplicationPullErrorKind::LeaderUnavailable
                | ReplicationPullErrorKind::RateLimited
        )
    }
}

/// V2 patch 4E — replication failure carrying a classified kind and a
/// human-readable message. Internal `try_*` helpers return this; the
/// public `pull_once` / `bootstrap_from_latest_snapshot` wrappers
/// convert it to `HydraError` so the engine-facing error type stays
/// stable.
#[derive(Debug, Clone)]
pub struct ReplicationPullError {
    pub kind: ReplicationPullErrorKind,
    pub message: String,
}

impl ReplicationPullError {
    pub fn new(kind: ReplicationPullErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn is_transient(&self) -> bool {
        self.kind.is_transient()
    }
}

impl std::fmt::Display for ReplicationPullError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "replication {:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for ReplicationPullError {}

impl From<ReplicationPullError> for HydraError {
    fn from(err: ReplicationPullError) -> Self {
        HydraError::QueryError(format!("{err}"))
    }
}

/// Classify a reqwest send-side error. Anything network-shaped maps
/// to `Network` (transient). reqwest's classification methods
/// (`is_connect`, `is_timeout`, `is_request`) all funnel here.
fn classify_reqwest_error(err: &reqwest::Error) -> ReplicationPullError {
    ReplicationPullError::new(
        ReplicationPullErrorKind::Network,
        format!("leader request failed: {err}"),
    )
}

/// Classify an HTTP status code from the leader. 401/403/429/5xx have
/// specific kinds; other 4xx is `BadLeaderResponse`.
fn classify_http_status(status: StatusCode) -> ReplicationPullError {
    let kind = match status.as_u16() {
        401 => ReplicationPullErrorKind::Unauthorized,
        403 => ReplicationPullErrorKind::Forbidden,
        429 => ReplicationPullErrorKind::RateLimited,
        500..=599 => ReplicationPullErrorKind::LeaderUnavailable,
        _ => ReplicationPullErrorKind::BadLeaderResponse,
    };
    ReplicationPullError::new(kind, format!("leader request failed: HTTP {status}"))
}

/// Classify a JSON decode failure as `BadLeaderResponse`.
fn classify_decode_error(err: &reqwest::Error) -> ReplicationPullError {
    ReplicationPullError::new(
        ReplicationPullErrorKind::BadLeaderResponse,
        format!("leader request failed: decode {err}"),
    )
}

/// Classify an engine-side error from `apply_replication_commits` /
/// `recover_from_snapshot_body_and_replay`. The engine returns
/// `HydraError::QueryError` with one of a known set of message shapes;
/// "sequence", "previous_hash", or "commit_hash does not match" all
/// indicate chain-continuity issues (`ChainDivergence`), while
/// "is not committed" / "missing commit_hash" / etc. are
/// `EngineRejected`. Message-sniffing is fragile in general, but the
/// engine-side messages are owned by this workspace and stable.
fn classify_engine_error(err: HydraError) -> ReplicationPullError {
    let message = err.to_string();
    let kind = if message.contains("sequence")
        || message.contains("previous_hash")
        || message.contains("commit_hash does not match")
    {
        ReplicationPullErrorKind::ChainDivergence
    } else {
        ReplicationPullErrorKind::EngineRejected
    };
    ReplicationPullError::new(kind, message)
}

/// V2 patch 4E — exponential-backoff retry policy for the loop driver.
///
/// `max_attempts` is the cap on **consecutive transient failures**
/// before the loop surfaces `Err`. Default `usize::MAX` (effectively
/// unlimited — the loop is resilient by default). Tests use small
/// values to assert eventual give-up.
///
/// `initial_backoff` is the wait after the first transient failure.
/// Doubles on each subsequent failure, capped at `max_backoff`. A
/// successful operation resets the backoff to `initial_backoff` and
/// clears the consecutive-failure counter.
#[derive(Debug, Clone)]
pub struct ReplicationRetryConfig {
    pub max_attempts: usize,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for ReplicationRetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: usize::MAX,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
        }
    }
}

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
    /// `true` runs `bootstrap_from_latest_snapshot` as the first
    /// action of `run_until_cancelled`. **Interaction with
    /// `cursor_path` (V2 P4F)**: when both are set, startup
    /// restores the cursor AND still performs a bootstrap. The
    /// bootstrap path resets the follower's commit_ledger (see
    /// `recover_from_snapshot_body_and_replay` doc-comment) and
    /// then the cursor takes over for subsequent pulls. Operators
    /// who want warm cursor-only restart should set
    /// `bootstrap_on_start = false`. A future patch may skip
    /// bootstrap when the restored cursor is already at or past
    /// the leader's latest snapshot — that requires a leader call
    /// before deciding, so it is deferred.
    pub bootstrap_on_start: bool,
    /// V2 patch 4E — exponential-backoff retry policy applied inside
    /// `run_until_cancelled` for transient pull failures.
    pub retry: ReplicationRetryConfig,
    /// V2 patch 4F — optional path to a JSON file that persists
    /// replication cursors across process restarts. `None` keeps
    /// the cursor in-memory only (V2 P4C-E behavior).
    ///
    /// File shape: `{ "version": 1, "cursors": { "<peer_id>": ... }}`.
    /// Written via tempfile + atomic `fs::rename` after every
    /// successful apply / bootstrap. Read by `restore_cursor()`,
    /// which `run_until_cancelled` calls automatically as its
    /// first action.
    ///
    /// Persistence is **best-effort durability**: read failures
    /// (missing / corrupt / no entry for this peer) fall back to
    /// fresh-follower behavior silently; write failures emit a
    /// `tracing::warn` and the loop keeps running on in-memory
    /// state. The in-memory cursor stays the source of correctness.
    pub cursor_path: Option<PathBuf>,
}

impl ReplicationPullerConfig {
    /// Ergonomic constructor with sensible defaults:
    /// `auth_token = None`, `page_limit = 100`,
    /// `poll_interval = 1s`, `bootstrap_on_start = true`,
    /// `retry = ReplicationRetryConfig::default()`.
    ///
    /// Override individual fields after construction:
    ///
    /// ```ignore
    /// let mut config = ReplicationPullerConfig::new(peer, url, restorer);
    /// config.poll_interval = Duration::from_millis(250);
    /// config.retry.max_attempts = 5;
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
            retry: ReplicationRetryConfig::default(),
            cursor_path: None,
        }
    }
}

/// V2 patch 4F — on-disk shape of the replication cursor file.
///
/// One JSON file, keyed by peer_id, so a single follower process
/// could in principle track cursors for multiple leaders without
/// changing the schema. Today every puller has exactly one peer_id
/// so the map carries at most one entry — but the shape is
/// forward-compat.
///
/// `version: 1` for future format migrations.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CursorFile {
    version: u32,
    cursors: HashMap<ReplicaId, ReplicationOffset>,
}

impl Default for CursorFile {
    fn default() -> Self {
        Self {
            version: 1,
            cursors: HashMap::new(),
        }
    }
}

/// V2 patch 4F — atomic-rename helpers for reading/writing the cursor
/// file. All errors here are surfaced as `std::io::Error`; callers
/// translate to either `Ok(None)` (read path) or `tracing::warn`
/// (write path).
struct CursorPersistence;

impl CursorPersistence {
    /// Load the cursor entry for a specific peer. Missing file or
    /// missing peer entry both return `Ok(None)`. Corrupt JSON
    /// returns an `io::Error` — the public `restore_cursor` then
    /// downgrades that to `tracing::warn` + `Ok(None)`.
    fn load_for_peer(
        path: &Path,
        peer_id: &ReplicaId,
    ) -> std::io::Result<Option<ReplicationOffset>> {
        let raw = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        let parsed: CursorFile = serde_json::from_str(&raw)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        Ok(parsed.cursors.get(peer_id).cloned())
    }

    /// Atomically write the offset for `peer_id`. Preserves entries
    /// for any other peers already in the file (read-modify-write).
    /// Uses tempfile + `fs::rename` so a crash mid-write never
    /// leaves a half-serialized file at the canonical path —
    /// same pattern as `FileSnapshotStore`.
    fn save(
        path: &Path,
        peer_id: ReplicaId,
        offset: ReplicationOffset,
    ) -> std::io::Result<()> {
        // Read-modify-write. Treat missing OR corrupt as "start
        // fresh" — the in-memory cursor is the source of truth for
        // correctness, and overwriting a corrupt file with a valid
        // single-entry file is the right repair.
        let mut file = match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str::<CursorFile>(&raw).unwrap_or_default(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => CursorFile::default(),
            Err(err) => return Err(err),
        };
        file.cursors.insert(peer_id, offset);
        let serialized = serde_json::to_string_pretty(&file)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
        // Ensure parent dir exists so callers don't have to.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let temp_path = path.with_extension("json.tmp");
        std::fs::write(&temp_path, serialized)?;
        std::fs::rename(&temp_path, path)?;
        Ok(())
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
        self.try_pull_once().await.map_err(Into::into)
    }

    /// Typed-error variant of `pull_once`. Used internally by
    /// `run_until_cancelled` for retry classification. Public callers
    /// should use `pull_once` (HydraError-returning).
    async fn try_pull_once(
        &self,
    ) -> std::result::Result<ReplicationPullReport, ReplicationPullError> {
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

        // 2. Single page from the leader.
        let page = self.try_fetch_commit_page(local_head).await?;
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
        //    Engine errors are classified as `ChainDivergence` or
        //    `EngineRejected` so the loop driver picks the right
        //    retry policy (both are fatal).
        let report = {
            let hydra = self.runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra
                .apply_replication_commits(self.config.peer_id.clone(), page.commits)
                .map_err(classify_engine_error)?
        };

        // V2 patch 4F — persist the cursor after every successful apply.
        // Best-effort; failures log via tracing but don't crash.
        self.persist_cursor_best_effort().await;

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

    /// V2 patch 4F — hydrate the in-memory replication cursor for
    /// this peer from `config.cursor_path`.
    ///
    /// Returns:
    ///   - `Ok(None)` when `cursor_path` is unset, the file is
    ///     missing, the file is corrupt, or the file is valid but
    ///     doesn't carry an entry for `config.peer_id`. Corrupt
    ///     files emit a `tracing::warn` but still return Ok — the
    ///     in-memory cursor stays empty and the loop falls back to
    ///     fresh-follower behavior.
    ///   - `Ok(Some(offset))` when a valid entry was loaded and
    ///     stamped into Hydra via `record_replication_apply_offset`.
    ///
    /// `run_until_cancelled` calls this automatically as its first
    /// action (after the pre-cancel check). Operators using
    /// `pull_once` / `bootstrap_from_latest_snapshot` directly can
    /// call it explicitly before their first operation.
    pub async fn restore_cursor(&self) -> Result<Option<ReplicationOffset>> {
        let Some(path) = self.config.cursor_path.as_ref() else {
            return Ok(None);
        };
        let loaded = match CursorPersistence::load_for_peer(path, &self.config.peer_id) {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(
                    target: "hydra::replication",
                    path = %path.display(),
                    peer_id = %self.config.peer_id,
                    error = %err,
                    "replication cursor load failed; falling back to fresh-follower behavior"
                );
                return Ok(None);
            }
        };
        let Some(offset) = loaded else {
            return Ok(None);
        };
        // Stamp the in-memory cursor under the write lock.
        let hydra = self.runtime.hydra();
        let mut hydra = hydra.write().await;
        hydra.record_replication_apply_offset(
            self.config.peer_id.clone(),
            offset.clone(),
        );
        Ok(Some(offset))
    }

    /// V2 patch 4F — best-effort write of the current in-memory
    /// cursor for this peer to `config.cursor_path`. Called by
    /// `try_pull_once` and `try_bootstrap_from_latest_snapshot`
    /// after a successful apply. Failures emit `tracing::warn` but
    /// do NOT bubble — replication keeps running on in-memory
    /// state.
    async fn persist_cursor_best_effort(&self) {
        let Some(path) = self.config.cursor_path.as_ref() else {
            return;
        };
        // Read the just-stamped cursor back out of Hydra.
        let offset = {
            let hydra = self.runtime.hydra();
            let hydra = hydra.read().await;
            hydra
                .latest_replication_offset(&self.config.peer_id)
                .cloned()
        };
        let Some(offset) = offset else {
            // Nothing to persist — apply path didn't stamp a cursor
            // (e.g. empty page). Silent no-op.
            return;
        };
        let path = path.clone();
        let peer_id = self.config.peer_id.clone();
        // Do the disk IO on a blocking pool so we don't stall the
        // async runtime. Bound by a small spawn_blocking call.
        if let Err(err) = tokio::task::spawn_blocking(move || {
            CursorPersistence::save(&path, peer_id, offset)
        })
        .await
        .unwrap_or_else(|join_err| {
            Err(std::io::Error::new(std::io::ErrorKind::Other, join_err))
        }) {
            tracing::warn!(
                target: "hydra::replication",
                peer_id = %self.config.peer_id,
                error = %err,
                "replication cursor persist failed; in-memory cursor still consistent"
            );
        }
    }

    /// V2 patch 4D + 4E — drive the puller in a loop until `shutdown`
    /// fires.
    ///
    /// Behavior:
    ///   1. **Pre-cancel short-circuit** — `shutdown.is_cancelled()`
    ///      before any IO → immediate Ok(report) with iterations=0,
    ///      cancelled=true.
    ///   2. **Bootstrap on start** — if `config.bootstrap_on_start`,
    ///      bootstrap first. Counts as a successful iteration on
    ///      success.
    ///   3. **Poll loop** — `select!` over `shutdown.cancelled()` vs
    ///      `sleep(poll_interval)`. On tick, `pull_once` + fold.
    ///   4. **Retry policy (V2 patch 4E)** — every operation classifies
    ///      its error:
    ///        - Transient (Network / LeaderUnavailable / RateLimited)
    ///          → record on `report.failures`, sleep exponential
    ///          backoff (initial → doubled per failure, capped at
    ///          `max_backoff`), retry the SAME operation. The
    ///          backoff sleep is also preemptible via the shutdown
    ///          token. Resets on success.
    ///        - Fatal (Unauthorized / Forbidden / BadLeaderResponse /
    ///          ChainDivergence / EngineRejected) → return
    ///          `Err(ReplicationLoopError { report, kind, message })`.
    ///        - Transient that exceeds `retry.max_attempts`
    ///          consecutive failures → same: return Err with the
    ///          last transient kind.
    ///   5. **Cancellation** wins via `select!` at every wait point
    ///      (poll sleep, backoff sleep). Returns Ok with
    ///      `cancelled: true`.
    pub async fn run_until_cancelled(
        &self,
        shutdown: CancellationToken,
    ) -> std::result::Result<ReplicationLoopReport, ReplicationLoopError> {
        let mut report = ReplicationLoopReport {
            peer_id: self.config.peer_id.clone(),
            iterations: 0,
            total_fetched: 0,
            total_applied: 0,
            last_sequence: None,
            cancelled: false,
            failures: 0,
            last_error: None,
            last_error_kind: None,
        };

        if shutdown.is_cancelled() {
            report.cancelled = true;
            return Ok(report);
        }

        // V2 patch 4F — restore the persisted cursor before the first
        // operation, so the first pull queries from the resumed
        // leader position instead of the cold-start fallback. Errors
        // are swallowed (restore_cursor downgrades them to Ok(None));
        // unreachable here unless the runtime itself is broken.
        let _ = self.restore_cursor().await;

        // State machine: either the bootstrap step (if requested) or
        // the pull loop. `bootstrap_pending` flips to false after a
        // successful bootstrap; transient retries leave it true so
        // the retry path keeps targeting bootstrap.
        let mut bootstrap_pending = self.config.bootstrap_on_start;
        let mut consecutive_failures: usize = 0;
        let mut current_backoff = self.config.retry.initial_backoff;

        loop {
            // Run the next operation: bootstrap (if pending) or pull.
            let op_result = if bootstrap_pending {
                self.try_bootstrap_from_latest_snapshot().await.map(|boot| {
                    bootstrap_pending = false;
                    report.iterations += 1;
                    report.total_applied += boot.replayed_commits;
                    if boot.latest_sequence.is_some() {
                        report.last_sequence = boot.latest_sequence;
                    }
                })
            } else {
                self.try_pull_once().await.map(|pull| {
                    report.iterations += 1;
                    report.total_fetched += pull.fetched_count;
                    report.total_applied += pull.applied_count;
                    if pull.latest_sequence.is_some() {
                        report.last_sequence = pull.latest_sequence;
                    }
                })
            };

            match op_result {
                Ok(()) => {
                    // Success — reset retry state. Sleep poll_interval
                    // before next tick. Cancel wins.
                    consecutive_failures = 0;
                    current_backoff = self.config.retry.initial_backoff;
                    tokio::select! {
                        _ = shutdown.cancelled() => {
                            report.cancelled = true;
                            return Ok(report);
                        }
                        _ = tokio::time::sleep(self.config.poll_interval) => {}
                    }
                }
                Err(err) if err.is_transient() => {
                    // Transient — record, check attempt budget, back off.
                    consecutive_failures += 1;
                    report.failures += 1;
                    report.last_error = Some(err.message.clone());
                    report.last_error_kind = Some(err.kind);
                    if consecutive_failures > self.config.retry.max_attempts {
                        return Err(ReplicationLoopError {
                            report,
                            kind: err.kind,
                            message: err.message,
                        });
                    }
                    // Sleep current_backoff with shutdown preempting,
                    // then double the backoff (capped). Hold on to the
                    // pre-double value so the FIRST failure waits
                    // exactly `initial_backoff` ms.
                    let to_sleep = current_backoff;
                    current_backoff = (current_backoff * 2).min(self.config.retry.max_backoff);
                    tokio::select! {
                        _ = shutdown.cancelled() => {
                            report.cancelled = true;
                            return Ok(report);
                        }
                        _ = tokio::time::sleep(to_sleep) => {}
                    }
                    // Loop again — same operation retried.
                }
                Err(err) => {
                    // Fatal — stamp last_error fields and surface as
                    // ReplicationLoopError with the partial report.
                    report.last_error = Some(err.message.clone());
                    report.last_error_kind = Some(err.kind);
                    return Err(ReplicationLoopError {
                        report,
                        kind: err.kind,
                        message: err.message,
                    });
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
        self.try_bootstrap_from_latest_snapshot()
            .await
            .map_err(Into::into)
    }

    /// Typed-error variant of `bootstrap_from_latest_snapshot`. Used
    /// internally by `run_until_cancelled` for retry classification.
    async fn try_bootstrap_from_latest_snapshot(
        &self,
    ) -> std::result::Result<ReplicationBootstrapReport, ReplicationPullError> {
        // 1. Fetch the latest manifest.
        let manifest_response = self.try_fetch_snapshot_latest().await?;

        // 2. No snapshot on leader → pull_once fallback.
        let Some(manifest) = manifest_response.manifest else {
            let pull = self.try_pull_once().await?;
            return Ok(ReplicationBootstrapReport {
                peer_id: pull.peer_id,
                snapshot_id: None,
                snapshot_sequence: None,
                replayed_commits: pull.applied_count,
                latest_sequence: pull.latest_sequence,
            });
        };

        // 3. Fetch the body. Leader returning 404 here is a bug
        //    (manifest claimed the body existed). The 404 surfaces as
        //    `BadLeaderResponse` via `classify_http_status`.
        let body_response = self.try_fetch_snapshot_body(&manifest.id).await?;
        let body = body_response.body;
        let snapshot_sequence = manifest.sequence;

        // 4. Fetch all tail pages. Defensive: bail on empty page even
        //    if `next_after_sequence` is Some, to guard against a
        //    misbehaving leader.
        let mut tail: Vec<CommitBatch> = Vec::new();
        let mut cursor = snapshot_sequence;
        loop {
            let page = self.try_fetch_commit_page(cursor).await?;
            if page.commits.is_empty() {
                break;
            }
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
        //    the snapshot manifest head when the tail is empty.
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
            let manifest = hydra
                .recover_from_snapshot_body_and_replay(
                    body,
                    tail.clone(),
                    self.config.restored_by.clone(),
                )
                .map_err(classify_engine_error)?;
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

        // V2 patch 4F — persist cursor after bootstrap success too.
        self.persist_cursor_best_effort().await;

        Ok(ReplicationBootstrapReport {
            peer_id: self.config.peer_id.clone(),
            snapshot_id: Some(manifest_applied.id),
            snapshot_sequence: Some(snapshot_sequence),
            replayed_commits,
            latest_sequence,
        })
    }

    /// Shared GET-and-decode helper. Builds the URL, attaches the
    /// Bearer token (if configured), optionally appends a `query`,
    /// classifies any error into `ReplicationPullError` so the loop
    /// driver can pick the right retry policy.
    ///
    /// All three fetch helpers (commits, snapshot/latest, snapshot/:id)
    /// funnel through this one path so error classification stays
    /// uniform.
    async fn send_and_decode<T: DeserializeOwned>(
        &self,
        url: &str,
        query: Option<&[(&str, String)]>,
    ) -> std::result::Result<T, ReplicationPullError> {
        let mut request = self.client.get(url);
        if let Some(query) = query {
            request = request.query(query);
        }
        if let Some(token) = &self.config.auth_token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|err| classify_reqwest_error(&err))?;
        let status = response.status();
        // axum's StatusCode is the same crate as reqwest's via http.
        let axum_status =
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        if !status.is_success() {
            return Err(classify_http_status(axum_status));
        }
        response
            .json::<T>()
            .await
            .map_err(|err| classify_decode_error(&err))
    }

    async fn try_fetch_commit_page(
        &self,
        after_sequence: u64,
    ) -> std::result::Result<ReplicationCommitPage, ReplicationPullError> {
        let base = self.config.leader_base_url.trim_end_matches('/');
        let url = format!("{base}/replication/commits");
        self.send_and_decode(
            &url,
            Some(&[
                ("after_sequence", after_sequence.to_string()),
                ("limit", self.config.page_limit.to_string()),
            ]),
        )
        .await
    }

    async fn try_fetch_snapshot_latest(
        &self,
    ) -> std::result::Result<ReplicationSnapshotManifestResponse, ReplicationPullError> {
        let base = self.config.leader_base_url.trim_end_matches('/');
        let url = format!("{base}/replication/snapshot/latest");
        self.send_and_decode(&url, None).await
    }

    async fn try_fetch_snapshot_body(
        &self,
        id: &SnapshotId,
    ) -> std::result::Result<ReplicationSnapshotBodyResponse, ReplicationPullError> {
        let base = self.config.leader_base_url.trim_end_matches('/');
        let url = format!("{base}/replication/snapshot/{id}");
        self.send_and_decode(&url, None).await
    }

    /// Backwards-compatible HydraError-returning fetch — unused now
    /// that callers use the `try_*` typed variants, but kept private
    /// in case external callers want a HydraError-returning helper.
    #[allow(dead_code)]
    async fn fetch_commit_page(
        &self,
        after_sequence: u64,
    ) -> Result<ReplicationCommitPage> {
        self.try_fetch_commit_page(after_sequence)
            .await
            .map_err(Into::into)
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
/// `iterations` counts SUCCESSFUL operations (startup-bootstrap when
/// enabled + each successful poll-tick). Failed retries do NOT count
/// as iterations; they bump `failures` instead.
///
/// `total_fetched` and `total_applied` accumulate across the whole
/// loop. `last_sequence` is the most recent value returned by the
/// leader (head sequence on pull, or follower head after bootstrap).
///
/// V2 patch 4E:
///   - `failures` counts transient errors the loop recovered from
///     (retried with backoff and continued). Fatal failures
///     surface as `Err(ReplicationLoopError { report, .. })`.
///   - `last_error` / `last_error_kind` carry the most recent
///     failure (transient or fatal) for diagnostics.
///   - `cancelled = true` means the shutdown token fired.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplicationLoopReport {
    pub peer_id: ReplicaId,
    pub iterations: u64,
    pub total_fetched: usize,
    pub total_applied: usize,
    pub last_sequence: Option<u64>,
    pub cancelled: bool,
    pub failures: u64,
    pub last_error: Option<String>,
    pub last_error_kind: Option<ReplicationPullErrorKind>,
}

/// V2 patch 4E — fatal-exit error from `run_until_cancelled`. Carries
/// the partial report so the caller can see how far the loop got
/// (successful iterations, recovered transient failures, last seen
/// leader head) before the fatal kind ended things.
#[derive(Debug, Clone)]
pub struct ReplicationLoopError {
    pub report: ReplicationLoopReport,
    pub kind: ReplicationPullErrorKind,
    pub message: String,
}

impl std::fmt::Display for ReplicationLoopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "replication loop {:?}: {} (iterations={}, failures={})",
            self.kind, self.message, self.report.iterations, self.report.failures
        )
    }
}

impl std::error::Error for ReplicationLoopError {}

impl From<ReplicationLoopError> for HydraError {
    fn from(err: ReplicationLoopError) -> Self {
        HydraError::QueryError(format!("{err}"))
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
                retry: ReplicationRetryConfig::default(),
                cursor_path: None,
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
                retry: ReplicationRetryConfig::default(),
                cursor_path: None,
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
                retry: ReplicationRetryConfig::default(),
                cursor_path: None,
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
                retry: ReplicationRetryConfig::default(),
                cursor_path: None,
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
                retry: ReplicationRetryConfig::default(),
                cursor_path: None,
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
                retry: ReplicationRetryConfig::default(),
                cursor_path: None,
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
                retry: ReplicationRetryConfig::default(),
                cursor_path: None,
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
                retry: ReplicationRetryConfig::default(),
                cursor_path: None,
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
                retry: ReplicationRetryConfig::default(),
                cursor_path: None,
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
        // Port 1 — reserved, refuses TCP connect. With V2 patch 4E,
        // this surfaces as `Network` (transient). Override
        // `retry.max_attempts = 1` so the loop gives up after one
        // failed attempt instead of retrying forever (the default).
        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let mut config = loop_config(
            "http://127.0.0.1:1".to_string(),
            Duration::from_millis(10),
            false,
        );
        config.retry.max_attempts = 1;
        config.retry.initial_backoff = Duration::from_millis(1);
        let puller = ReplicationPuller::new(follower_runtime, config);
        let token = CancellationToken::new();
        let err = puller.run_until_cancelled(token).await.unwrap_err();
        assert_eq!(err.kind, ReplicationPullErrorKind::Network);
        // Partial report carries the transient failure count.
        assert!(err.report.failures >= 1, "got {:?}", err.report);
    }

    // === V2 patch 4E — retry / backoff / failure classification ===

    /// Flaky leader fixture: returns 503 for the first N hits to
    /// `/replication/commits`, then returns a valid empty
    /// `ReplicationCommitPage`. Lets the test prove the loop retries
    /// and eventually converges without needing a real upstream leader.
    #[derive(Clone)]
    struct FlakyLeaderState {
        // AtomicI32 (signed) so once the counter hits 0 and decrements
        // further it goes negative — `prev > 0` keeps being false.
        // AtomicU32 would wrap around to u32::MAX and re-enter the
        // 503-emitting branch.
        remaining_503: std::sync::Arc<std::sync::atomic::AtomicI32>,
    }

    async fn flaky_commits_handler(
        State(state): State<FlakyLeaderState>,
    ) -> impl IntoResponse {
        let prev = state
            .remaining_503
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        if prev > 0 {
            return (StatusCode::SERVICE_UNAVAILABLE, "leader unavailable")
                .into_response();
        }
        Json(ReplicationCommitPage {
            commits: vec![],
            next_after_sequence: None,
            leader_head_sequence: 0,
            leader_head_commit_id: None,
        })
        .into_response()
    }

    #[tokio::test]
    async fn run_until_cancelled_retries_transient_network_error() {
        // Flaky leader returns 503 on the first 2 requests, then a
        // valid empty page. The loop must retry transient failures
        // (LeaderUnavailable kind) and converge to a clean state.
        let flaky = FlakyLeaderState {
            remaining_503: std::sync::Arc::new(std::sync::atomic::AtomicI32::new(2)),
        };
        let router = Router::new()
            .route("/replication/commits", get(flaky_commits_handler))
            .with_state(flaky);
        let (addr, _server) = spawn_leader(router).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let mut config = loop_config(format!("http://{addr}"), Duration::from_millis(20), false);
        config.retry.max_attempts = 5;
        config.retry.initial_backoff = Duration::from_millis(1);
        config.retry.max_backoff = Duration::from_millis(5);
        let puller = ReplicationPuller::new(follower_runtime, config);
        let token = CancellationToken::new();

        // Cancel after the loop has reported at least one success.
        let token_clone = token.clone();
        // We can't easily observe a successful pull from outside
        // (empty page is a no-op on follower state), so cancel after
        // a generous timeout. The retry behavior is asserted via the
        // failures counter.
        let canceller = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            token_clone.cancel();
        });

        let report = puller.run_until_cancelled(token).await.unwrap();
        canceller.await.unwrap();
        assert!(report.cancelled);
        // Two 503s → at least 2 transient failures recorded.
        assert!(
            report.failures >= 2,
            "expected >=2 transient failures, got {:?}",
            report
        );
        // Most recent error kind was transient (loop kept going).
        assert_eq!(
            report.last_error_kind,
            Some(ReplicationPullErrorKind::LeaderUnavailable)
        );
    }

    #[derive(Clone)]
    struct AlwaysStatusState {
        status: StatusCode,
    }

    async fn always_status_handler(
        State(state): State<AlwaysStatusState>,
    ) -> impl IntoResponse {
        (state.status, "rejected").into_response()
    }

    #[tokio::test]
    async fn run_until_cancelled_stops_on_unauthorized() {
        // Leader returns 401 unconditionally. The loop classifies as
        // Unauthorized (fatal) and returns Err immediately — no retry.
        let router = Router::new()
            .route("/replication/commits", get(always_status_handler))
            .route("/replication/snapshot/latest", get(always_status_handler))
            .with_state(AlwaysStatusState {
                status: StatusCode::UNAUTHORIZED,
            });
        let (addr, _server) = spawn_leader(router).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let mut config = loop_config(format!("http://{addr}"), Duration::from_millis(10), false);
        config.retry.max_attempts = 100; // doesn't matter — fatal short-circuits
        let puller = ReplicationPuller::new(follower_runtime, config);
        let token = CancellationToken::new();
        let err = puller.run_until_cancelled(token).await.unwrap_err();
        assert_eq!(err.kind, ReplicationPullErrorKind::Unauthorized);
        // Fatal short-circuit — no transient retries before exit.
        assert_eq!(err.report.failures, 0);
    }

    #[tokio::test]
    async fn run_until_cancelled_stops_on_chain_divergence() {
        // Follower's local cursor is already at sequence 5 (manually
        // stamped). Leader's actual chain head is at seq=2. Pull
        // requests `after_sequence=5`, leader returns nothing, no
        // error — that's actually success (just a no-op page). To
        // genuinely trigger ChainDivergence we need the FOLLOWER's
        // state to disagree with the leader's chain on a real apply.
        //
        // Setup: follower has its OWN local commit at seq=1 with a
        // different hash. Cursor unstamped, so ledger mode applies
        // and the engine sees the leader's seq=2 chain continuing
        // from a DIFFERENT previous_hash than the follower's seq=1.
        // → ChainDivergence (fatal).
        let (leader_runtime, _leader_proc) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("leader_one")).unwrap();
            hydra.ingest(signal("leader_two")).unwrap();
        }
        let (addr, _server) = spawn_leader(replication_router(leader_runtime)).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        {
            let hydra = follower_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("follower_local")).unwrap();
        }

        let mut config = loop_config(format!("http://{addr}"), Duration::from_millis(10), false);
        config.retry.max_attempts = 100;
        let puller = ReplicationPuller::new(follower_runtime, config);
        let token = CancellationToken::new();
        let err = puller.run_until_cancelled(token).await.unwrap_err();
        assert_eq!(err.kind, ReplicationPullErrorKind::ChainDivergence);
        // Fatal — no transient retries.
        assert_eq!(err.report.failures, 0);
    }

    #[tokio::test]
    async fn run_until_cancelled_retry_backoff_capped_and_loop_keeps_running() {
        // One 503 then valid empty pages. Test confirms:
        //   - backoff is capped via `max_backoff` (set to initial)
        //   - after success, the loop keeps polling instead of
        //     exiting with the prior transient as a fatal
        //   - failures counter shows exactly one transient failure
        let flaky = FlakyLeaderState {
            remaining_503: std::sync::Arc::new(std::sync::atomic::AtomicI32::new(1)),
        };
        let router = Router::new()
            .route("/replication/commits", get(flaky_commits_handler))
            .with_state(flaky);
        let (addr, _server) = spawn_leader(router).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let mut config = loop_config(format!("http://{addr}"), Duration::from_millis(10), false);
        config.retry.max_attempts = 5;
        config.retry.initial_backoff = Duration::from_millis(1);
        // Cap = initial — confirms the doubling-then-min() works.
        config.retry.max_backoff = Duration::from_millis(1);
        let puller = ReplicationPuller::new(follower_runtime, config);
        let token = CancellationToken::new();

        let token_clone = token.clone();
        let canceller = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            token_clone.cancel();
        });

        let report = puller.run_until_cancelled(token).await.unwrap();
        canceller.await.unwrap();
        assert!(report.cancelled);
        // Exactly one transient failure (the single 503).
        assert_eq!(report.failures, 1);
        // The loop continued past the failure rather than fataling.
        assert!(report.iterations >= 1);
    }

    // === V2 patch 4F — persistent replication cursor ===

    fn temp_cursor_path(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hydra_replication_cursor_{label}_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("replication-cursors.json")
    }

    /// Write a pre-populated cursor file with one peer entry.
    fn write_cursor_file(path: &Path, peer_id: ReplicaId, offset: ReplicationOffset) {
        let mut file = CursorFile::default();
        file.cursors.insert(peer_id, offset);
        let raw = serde_json::to_string_pretty(&file).unwrap();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, raw).unwrap();
    }

    fn read_cursor_file_for(
        path: &Path,
        peer_id: &ReplicaId,
    ) -> Option<ReplicationOffset> {
        let raw = std::fs::read_to_string(path).ok()?;
        let parsed: CursorFile = serde_json::from_str(&raw).ok()?;
        parsed.cursors.get(peer_id).cloned()
    }

    #[tokio::test]
    async fn restore_cursor_loads_from_disk_into_hydra() {
        let cursor_path = temp_cursor_path("restore");
        let persisted = ReplicationOffset::from_sequence(42);
        write_cursor_file(&cursor_path, follower_peer_id(), persisted.clone());

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let mut config = ReplicationPullerConfig::new(
            follower_peer_id(),
            "http://127.0.0.1:1".to_string(),
            restorer(),
        );
        config.cursor_path = Some(cursor_path.clone());

        let puller = ReplicationPuller::new(follower_runtime.clone(), config);
        let loaded = puller.restore_cursor().await.unwrap();
        assert_eq!(loaded, Some(persisted.clone()));
        // Stamped into Hydra in-memory cursor.
        let hydra_cursor = follower_runtime
            .hydra()
            .read()
            .await
            .latest_replication_offset(&follower_peer_id())
            .cloned();
        assert_eq!(hydra_cursor, Some(persisted));

        let _ = std::fs::remove_file(&cursor_path);
    }

    #[tokio::test]
    async fn apply_persists_cursor_to_disk() {
        // Leader ingests 2 commits, follower pull_once applies them,
        // cursor file should now reflect the last applied offset.
        let cursor_path = temp_cursor_path("apply");
        let (leader_runtime, _leader_proc) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let leader_head = leader_runtime
            .hydra()
            .read()
            .await
            .latest_commit()
            .unwrap()
            .id
            .clone();
        let (addr, _server) = spawn_leader(replication_router(leader_runtime)).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let mut config = ReplicationPullerConfig::new(
            follower_peer_id(),
            format!("http://{addr}"),
            restorer(),
        );
        config.cursor_path = Some(cursor_path.clone());

        let puller = ReplicationPuller::new(follower_runtime, config);
        let report = puller.pull_once().await.unwrap();
        assert_eq!(report.applied_count, 2);

        let persisted = read_cursor_file_for(&cursor_path, &follower_peer_id())
            .expect("cursor file must exist with our peer entry");
        assert_eq!(persisted.sequence, 2);
        assert_eq!(persisted.commit_id.as_ref(), Some(&leader_head));

        let _ = std::fs::remove_file(&cursor_path);
    }

    #[tokio::test]
    async fn run_until_cancelled_auto_restores_cursor_on_start() {
        // Pre-stamp the cursor file to leader's head. The loop's first
        // pull should request `after_sequence = 2` (the persisted
        // value) and find nothing new — i.e. fetched_count = 0.
        let cursor_path = temp_cursor_path("auto_restore");
        let (leader_runtime, _leader_proc) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let leader_head_record = leader_runtime
            .hydra()
            .read()
            .await
            .latest_commit()
            .cloned()
            .unwrap();
        let persisted = ReplicationOffset {
            sequence: leader_head_record.sequence,
            commit_id: Some(leader_head_record.id.clone()),
            commit_hash: Some(leader_head_record.commit_hash.clone()),
        };
        write_cursor_file(&cursor_path, follower_peer_id(), persisted);
        let (addr, _server) = spawn_leader(replication_router(leader_runtime)).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let mut config = loop_config(format!("http://{addr}"), Duration::from_millis(10), false);
        config.cursor_path = Some(cursor_path.clone());
        let puller = ReplicationPuller::new(follower_runtime.clone(), config);
        let token = CancellationToken::new();

        let token_clone = token.clone();
        let canceller = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            token_clone.cancel();
        });

        let report = puller.run_until_cancelled(token).await.unwrap();
        canceller.await.unwrap();
        assert!(report.cancelled);
        // Loop ran, applied nothing — restored cursor said "we're
        // already at leader head".
        assert_eq!(report.total_applied, 0);
        // Follower's local commit_ledger stayed empty (no apply
        // happened); the cursor came from disk, not from apply.
        assert_eq!(follower_runtime.hydra().read().await.commit_count(), 0);

        let _ = std::fs::remove_file(&cursor_path);
    }

    #[tokio::test]
    async fn corrupt_cursor_file_falls_back_to_fresh_follower_behavior() {
        let cursor_path = temp_cursor_path("corrupt");
        // Write garbage that's not valid JSON.
        std::fs::write(&cursor_path, b"not-json-at-all{").unwrap();

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let mut config = ReplicationPullerConfig::new(
            follower_peer_id(),
            "http://127.0.0.1:1".to_string(),
            restorer(),
        );
        config.cursor_path = Some(cursor_path.clone());

        let puller = ReplicationPuller::new(follower_runtime.clone(), config);
        let loaded = puller.restore_cursor().await.unwrap();
        // Ok(None) — corruption is logged via tracing::warn but not
        // surfaced as an error.
        assert!(loaded.is_none());
        // Hydra cursor stays empty.
        assert!(follower_runtime
            .hydra()
            .read()
            .await
            .latest_replication_offset(&follower_peer_id())
            .is_none());

        let _ = std::fs::remove_file(&cursor_path);
    }

    #[tokio::test]
    async fn missing_cursor_file_is_not_an_error_and_first_apply_creates_it() {
        let cursor_path = temp_cursor_path("create");
        // Make sure the file does NOT exist (parent dir does).
        let _ = std::fs::remove_file(&cursor_path);
        assert!(!cursor_path.exists());

        let (leader_runtime, _leader_proc) = RuntimeBuilder::new().build();
        {
            let hydra = leader_runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal("first")).unwrap();
        }
        let (addr, _server) = spawn_leader(replication_router(leader_runtime)).await;

        let (follower_runtime, _follower_proc) = RuntimeBuilder::new().build();
        let mut config = ReplicationPullerConfig::new(
            follower_peer_id(),
            format!("http://{addr}"),
            restorer(),
        );
        config.cursor_path = Some(cursor_path.clone());

        let puller = ReplicationPuller::new(follower_runtime, config);
        // restore_cursor: missing file → Ok(None), no error.
        let loaded = puller.restore_cursor().await.unwrap();
        assert!(loaded.is_none());

        // First successful apply creates the file.
        let report = puller.pull_once().await.unwrap();
        assert_eq!(report.applied_count, 1);
        assert!(cursor_path.exists());
        let entry = read_cursor_file_for(&cursor_path, &follower_peer_id())
            .expect("cursor file created with our peer entry");
        assert_eq!(entry.sequence, 1);

        let _ = std::fs::remove_file(&cursor_path);
    }
}
