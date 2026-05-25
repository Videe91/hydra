//! Replication vocabulary (V2 — patch 1).
//!
//! Patch 1 introduces the **types only**. Hydra can speak replication
//! in its event log after this patch, but does not yet replicate. The
//! roadmap is:
//!
//!   1. vocabulary  — this patch
//!   2. store       — durable ReplicationStore (next)
//!   3. network     — leader/follower HTTP
//!   4. workers     — background streaming + bootstrap
//!
//! V2 ships single-leader / many-followers with commit-log streaming
//! and snapshot bootstrap. Multi-leader, elections, and Raft-style
//! consensus are explicitly out of scope.

use crate::commit::CommitHash;
use crate::event::Value;
use crate::id::{ActorId, CommitId, ReplicaId, ReplicationRunId, TenantId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Role a replica plays in the cluster.
///
/// V2 only uses `Leader` and `Follower`. `Observer` is reserved for
/// read-only lag monitors and future analytics nodes that consume the
/// commit stream but never participate in writes or promotion.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReplicationRole {
    Leader,
    Follower,
    Observer,
}

/// Lifecycle status of a replication peer.
///
/// `Registered` — peer is known to the leader but has not yet checked in.
/// `Online`     — peer is streaming within an acceptable lag window.
/// `Lagging`    — peer is online but behind the configured lag threshold.
/// `Offline`    — peer has missed enough heartbeats to be considered out.
/// `Failed`     — peer reported a fatal error or was force-quarantined.
/// `Promoted` / `Demoted` — terminal markers around role changes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReplicationPeerStatus {
    Registered,
    Online,
    Lagging,
    Offline,
    Failed,
    Promoted,
    Demoted,
}

/// Lifecycle status of a single replication run.
///
/// Distinct from `ReplicationPeerStatus` because a run is a bounded
/// operation (bootstrap or a streaming session) with a Started → terminal
/// shape, while the peer status is the long-lived cluster view.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReplicationRunStatus {
    Started,
    Completed,
    Failed,
}

/// How a follower is being brought into sync.
///
/// `CommitLogStreaming` — the follower is already bootstrapped; the
/// leader streams new commits as they happen.
/// `SnapshotThenTail`   — the follower is fresh (or too far behind to
/// catch up via commits alone); restore the latest snapshot, then
/// replay the tail of commits committed after the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReplicationMode {
    CommitLogStreaming,
    SnapshotThenTail,
}

/// A point in the commit ledger. Identifies "how far along" a replica is.
///
/// `sequence` is required (the canonical position). `commit_id` and
/// `commit_hash` are best-effort context for operators and integrity
/// checks — useful but not load-bearing for ordering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplicationOffset {
    pub sequence: u64,
    pub commit_id: Option<CommitId>,
    pub commit_hash: Option<CommitHash>,
}

impl ReplicationOffset {
    /// Sequence-only offset (commit_id and commit_hash unknown).
    pub fn from_sequence(sequence: u64) -> Self {
        Self {
            sequence,
            commit_id: None,
            commit_hash: None,
        }
    }
}

/// Snapshot of how far behind a follower is, as observed at a point in time.
///
/// `lag_commits` is `leader_sequence.saturating_sub(follower_sequence)`,
/// computed eagerly in the constructor so consumers never have to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplicationLag {
    pub leader_sequence: u64,
    pub follower_sequence: u64,
    pub lag_commits: u64,
    pub observed_at: DateTime<Utc>,
}

impl ReplicationLag {
    /// Compute lag eagerly. `saturating_sub` so a follower that briefly
    /// reports ahead of the leader (clock skew, stale leader read) is
    /// recorded as zero lag rather than wrapping to u64::MAX.
    pub fn observe(
        leader_sequence: u64,
        follower_sequence: u64,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            leader_sequence,
            follower_sequence,
            lag_commits: leader_sequence.saturating_sub(follower_sequence),
            observed_at,
        }
    }
}

/// A registered replication peer.
///
/// `tenant_id` is `None` for cluster-wide peers (the common case in V2).
/// Per-tenant replicas may exist in the future for tenant-scoped
/// fan-out, hence the optional field.
///
/// `endpoint` is whatever the network layer needs to reach this peer —
/// typically an HTTPS URL. `None` is valid for peers that pull from
/// the leader rather than being pushed to (e.g. read-only Observers
/// that subscribe via the leader's existing HTTP API).
///
/// `mode` records how this peer is currently being kept in sync. It
/// flips from `SnapshotThenTail` to `CommitLogStreaming` once bootstrap
/// completes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplicationPeer {
    pub id: ReplicaId,
    pub tenant_id: Option<TenantId>,
    pub role: ReplicationRole,
    pub status: ReplicationPeerStatus,
    pub endpoint: Option<String>,
    pub mode: ReplicationMode,
    pub last_offset: Option<ReplicationOffset>,
    pub last_lag: Option<ReplicationLag>,
    pub registered_by: ActorId,
    pub registered_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, Value>,
}

impl ReplicationPeer {
    /// Construct a freshly-registered peer. Caller chooses role + mode;
    /// status starts at `Registered`, offsets/lag start empty.
    pub fn registered(
        id: ReplicaId,
        role: ReplicationRole,
        mode: ReplicationMode,
        registered_by: ActorId,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            tenant_id: None,
            role,
            status: ReplicationPeerStatus::Registered,
            endpoint: None,
            mode,
            last_offset: None,
            last_lag: None,
            registered_by,
            registered_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        }
    }
}

/// A bounded replication operation against a peer.
///
/// One `ReplicationRun` covers a single session: either a bootstrap
/// (snapshot restore + tail replay) or a streaming session that
/// eventually disconnects. The `mode` here matches the peer's mode at
/// the time the run started; if the peer was promoted out of bootstrap
/// mid-run, a new run is started.
///
/// `status` uses `ReplicationRunStatus`, not the peer status, because
/// a run only ever has three terminal shapes: Started, Completed, Failed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplicationRun {
    pub id: ReplicationRunId,
    pub peer_id: ReplicaId,
    pub tenant_id: Option<TenantId>,
    pub mode: ReplicationMode,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: ReplicationRunStatus,
    pub started_offset: Option<ReplicationOffset>,
    pub completed_offset: Option<ReplicationOffset>,
    pub error: Option<String>,
    pub metadata: HashMap<String, Value>,
}

impl ReplicationRun {
    /// Construct a freshly-started run. Caller supplies the peer + mode;
    /// status is `Started`, started_offset is optional (commonly `None`
    /// for a brand-new bootstrap, `Some(offset)` for streaming resumes).
    pub fn started(
        peer_id: ReplicaId,
        mode: ReplicationMode,
        started_offset: Option<ReplicationOffset>,
    ) -> Self {
        Self {
            id: ReplicationRunId::new(),
            peer_id,
            tenant_id: None,
            mode,
            started_at: Utc::now(),
            completed_at: None,
            status: ReplicationRunStatus::Started,
            started_offset,
            completed_offset: None,
            error: None,
            metadata: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{ActorId, CommitId};

    #[test]
    fn replication_peer_defaults_roundtrip() {
        let peer = ReplicationPeer::registered(
            ReplicaId::from_str("replica_acme"),
            ReplicationRole::Follower,
            ReplicationMode::SnapshotThenTail,
            ActorId::from_str("actor_replication"),
        );
        assert_eq!(peer.status, ReplicationPeerStatus::Registered);
        assert_eq!(peer.role, ReplicationRole::Follower);
        assert_eq!(peer.mode, ReplicationMode::SnapshotThenTail);
        assert!(peer.last_offset.is_none());
        assert!(peer.last_lag.is_none());
        assert!(peer.endpoint.is_none());
        assert!(peer.tenant_id.is_none());

        let json = serde_json::to_string(&peer).unwrap();
        let restored: ReplicationPeer = serde_json::from_str(&json).unwrap();
        assert_eq!(peer, restored);
    }

    #[test]
    fn replication_offset_roundtrip() {
        let offset = ReplicationOffset {
            sequence: 42,
            commit_id: Some(CommitId::from_str("commit_xyz")),
            commit_hash: Some(CommitHash("engine-v0:abc".to_string())),
        };
        let json = serde_json::to_string(&offset).unwrap();
        let restored: ReplicationOffset = serde_json::from_str(&json).unwrap();
        assert_eq!(offset, restored);

        // sequence-only constructor leaves the rest empty
        let sparse = ReplicationOffset::from_sequence(7);
        assert_eq!(sparse.sequence, 7);
        assert!(sparse.commit_id.is_none());
        assert!(sparse.commit_hash.is_none());
    }

    #[test]
    fn replication_lag_computes_lag() {
        let now = Utc::now();
        let lag = ReplicationLag::observe(100, 75, now);
        assert_eq!(lag.lag_commits, 25);

        // Follower briefly ahead (clock skew): lag floors at zero, not wraps.
        let zero = ReplicationLag::observe(50, 60, now);
        assert_eq!(zero.lag_commits, 0);

        // Roundtrip
        let json = serde_json::to_string(&lag).unwrap();
        let restored: ReplicationLag = serde_json::from_str(&json).unwrap();
        assert_eq!(lag, restored);
    }

    #[test]
    fn replication_run_roundtrip() {
        let run = ReplicationRun::started(
            ReplicaId::from_str("replica_acme"),
            ReplicationMode::CommitLogStreaming,
            Some(ReplicationOffset::from_sequence(1000)),
        );
        assert_eq!(run.status, ReplicationRunStatus::Started);
        assert_eq!(run.mode, ReplicationMode::CommitLogStreaming);
        assert!(run.completed_at.is_none());
        assert!(run.completed_offset.is_none());
        assert!(run.error.is_none());

        let json = serde_json::to_string(&run).unwrap();
        let restored: ReplicationRun = serde_json::from_str(&json).unwrap();
        assert_eq!(run, restored);
    }
}
