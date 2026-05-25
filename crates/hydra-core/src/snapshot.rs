use crate::action::Outcome;
use crate::edge::Edge;
use crate::epistemic::{Claim, Evidence};
use crate::event::Value;
use crate::id::{ActorId, SnapshotId, TenantId};
use crate::node::Node;
use crate::policy::{ApprovalRequest, PolicyDecision};
use crate::replication::{ReplicationPeer, ReplicationRun};
use crate::{
    Action, CommitHash, CommitId, CommitRecord, Event, Policy, SchemaDefinition, SensorCheckpoint,
    SensorRun,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Snapshot lifecycle.
///
/// - `Pending`  — snapshot is being built.
/// - `Committed` — snapshot is complete and restorable.
/// - `Stale`    — snapshot is obsolete because a newer snapshot superseded it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SnapshotStatus {
    Pending,
    Committed,
    Stale,
}

/// Lightweight summary of a snapshot.
///
/// Storage backends and HTTP list endpoints should read this first — it
/// avoids loading the full body when callers only need inventory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub id: SnapshotId,
    pub tenant_id: Option<TenantId>,
    /// Commit sequence covered by this snapshot.
    pub sequence: u64,
    /// Head commit included in this snapshot.
    pub head_commit_id: Option<CommitId>,
    pub head_commit_hash: Option<CommitHash>,
    pub status: SnapshotStatus,
    pub created_by: ActorId,
    pub created_at: DateTime<Utc>,
    /// Summary counts for quick auditing.
    pub total_events: usize,
    pub total_commits: usize,
    pub total_nodes: usize,
    pub total_edges: usize,
    pub total_claims: usize,
    pub total_evidence: usize,
    pub total_actions: usize,
    pub total_outcomes: usize,
    pub total_policies: usize,
    pub total_policy_decisions: usize,
    pub total_approval_requests: usize,
    pub total_sensor_checkpoints: usize,
    pub total_schemas: usize,
    /// V2 patch 2 — replication control-plane counts. `#[serde(default)]`
    /// so manifests written before V2 deserialize as zero.
    #[serde(default)]
    pub total_replication_peers: usize,
    #[serde(default)]
    pub total_replication_runs: usize,
    pub metadata: HashMap<String, Value>,
}

/// Owned materialized state captured in a snapshot.
///
/// Patch 1 intentionally keeps this type simple and store-agnostic. The
/// engine patch will decide exactly how each runtime store maps into these
/// vectors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotBody {
    pub manifest: SnapshotManifest,
    /// Graph projection.
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    /// Event / audit state.
    pub events: Vec<Event>,
    pub commit_records: Vec<CommitRecord>,
    /// Epistemic state.
    pub claims: Vec<Claim>,
    pub evidence: Vec<Evidence>,
    /// Action / outcome state.
    pub actions: Vec<Action>,
    pub outcomes: Vec<Outcome>,
    /// Policy / decision / approval state.
    pub policies: Vec<Policy>,
    pub policy_decisions: Vec<PolicyDecision>,
    pub approval_requests: Vec<ApprovalRequest>,
    /// Sensor / checkpoint state.
    pub sensor_runs: Vec<SensorRun>,
    pub sensor_checkpoints: Vec<SensorCheckpoint>,
    /// Schema registry state.
    pub schemas: Vec<SchemaDefinition>,
    /// V2 patch 2 — replication control-plane state. `#[serde(default)]`
    /// so bodies written before V2 deserialize with empty vectors.
    #[serde(default)]
    pub replication_peers: Vec<ReplicationPeer>,
    #[serde(default)]
    pub replication_runs: Vec<ReplicationRun>,
    pub metadata: HashMap<String, Value>,
}

impl SnapshotManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn committed(
        id: SnapshotId,
        tenant_id: Option<TenantId>,
        sequence: u64,
        head_commit_id: Option<CommitId>,
        head_commit_hash: Option<CommitHash>,
        created_by: ActorId,
        created_at: DateTime<Utc>,
        total_events: usize,
        total_commits: usize,
        total_nodes: usize,
        total_edges: usize,
        total_claims: usize,
        total_evidence: usize,
        total_actions: usize,
        total_outcomes: usize,
        total_policies: usize,
        total_policy_decisions: usize,
        total_approval_requests: usize,
        total_sensor_checkpoints: usize,
        total_schemas: usize,
    ) -> Self {
        Self {
            id,
            tenant_id,
            sequence,
            head_commit_id,
            head_commit_hash,
            status: SnapshotStatus::Committed,
            created_by,
            created_at,
            total_events,
            total_commits,
            total_nodes,
            total_edges,
            total_claims,
            total_evidence,
            total_actions,
            total_outcomes,
            total_policies,
            total_policy_decisions,
            total_approval_requests,
            total_sensor_checkpoints,
            total_schemas,
            // V2 patch 2: new fields default to zero. `committed(...)`
            // stays at 19 args; producers that include replication state
            // attach counts via `with_replication_counts(peers, runs)`.
            total_replication_peers: 0,
            total_replication_runs: 0,
            metadata: HashMap::new(),
        }
    }

    /// Attach replication control-plane counts to a manifest.
    ///
    /// Chainable so `SnapshotManifest::committed(...).with_replication_counts(...)`
    /// reads naturally in the engine's snapshot path.
    pub fn with_replication_counts(mut self, peers: usize, runs: usize) -> Self {
        self.total_replication_peers = peers;
        self.total_replication_runs = runs;
        self
    }

    pub fn is_committed(&self) -> bool {
        self.status == SnapshotStatus::Committed
    }
}

impl SnapshotBody {
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn commit_count(&self) -> usize {
        self.commit_records.len()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn schema_count(&self) -> usize {
        self.schemas.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> ActorId {
        ActorId::from_str("actor_snapshot_test")
    }

    #[test]
    fn snapshot_manifest_committed_builder_sets_counts() {
        // events, commits, nodes, edges, claims, evidence, actions, outcomes,
        // policies, policy_decisions, approval_requests, sensor_checkpoints, schemas
        let manifest = SnapshotManifest::committed(
            SnapshotId::new(),
            None,
            42,
            Some(CommitId::from_str("commit_42")),
            Some(CommitHash("engine-v0:abc".to_string())),
            actor(),
            Utc::now(),
            10, 4, 3, 2, 5, 6, 7, 12, 8, 13, 14, 9, 11,
        );
        assert!(manifest.is_committed());
        assert_eq!(manifest.sequence, 42);
        assert_eq!(manifest.total_events, 10);
        assert_eq!(manifest.total_commits, 4);
        assert_eq!(manifest.total_nodes, 3);
        assert_eq!(manifest.total_edges, 2);
        assert_eq!(manifest.total_claims, 5);
        assert_eq!(manifest.total_evidence, 6);
        assert_eq!(manifest.total_actions, 7);
        assert_eq!(manifest.total_outcomes, 12);
        assert_eq!(manifest.total_policies, 8);
        assert_eq!(manifest.total_policy_decisions, 13);
        assert_eq!(manifest.total_approval_requests, 14);
        assert_eq!(manifest.total_sensor_checkpoints, 9);
        assert_eq!(manifest.total_schemas, 11);
    }

    #[test]
    fn with_replication_counts_attaches_counts() {
        let manifest = SnapshotManifest::committed(
            SnapshotId::new(),
            None,
            42,
            None,
            None,
            actor(),
            Utc::now(),
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        );
        // Default to zero for back-compat.
        assert_eq!(manifest.total_replication_peers, 0);
        assert_eq!(manifest.total_replication_runs, 0);
        let with_repl = manifest.clone().with_replication_counts(3, 7);
        assert_eq!(with_repl.total_replication_peers, 3);
        assert_eq!(with_repl.total_replication_runs, 7);
        // Other fields untouched.
        assert_eq!(with_repl.sequence, manifest.sequence);
    }

    #[test]
    fn snapshot_manifest_back_compat_deserializes_without_replication_fields() {
        // Manifest written before V2 patch 2 will not include the
        // replication count fields. `#[serde(default)]` must fill them
        // with zero.
        let json = r#"{
            "id": "snap_legacy",
            "tenant_id": null,
            "sequence": 1,
            "head_commit_id": null,
            "head_commit_hash": null,
            "status": "Committed",
            "created_by": "actor_legacy",
            "created_at": "2026-01-01T00:00:00Z",
            "total_events": 0,
            "total_commits": 0,
            "total_nodes": 0,
            "total_edges": 0,
            "total_claims": 0,
            "total_evidence": 0,
            "total_actions": 0,
            "total_outcomes": 0,
            "total_policies": 0,
            "total_policy_decisions": 0,
            "total_approval_requests": 0,
            "total_sensor_checkpoints": 0,
            "total_schemas": 0,
            "metadata": {}
        }"#;
        let manifest: SnapshotManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.total_replication_peers, 0);
        assert_eq!(manifest.total_replication_runs, 0);
    }

    #[test]
    fn snapshot_manifest_serde_roundtrip() {
        let manifest = SnapshotManifest::committed(
            SnapshotId::new(),
            None,
            1,
            Some(CommitId::from_str("commit_1")),
            Some(CommitHash("engine-v0:hash".to_string())),
            actor(),
            Utc::now(),
            1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        );
        let json = serde_json::to_string(&manifest).unwrap();
        let restored: SnapshotManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, restored);
    }

    #[test]
    fn snapshot_body_serde_roundtrip_empty() {
        let manifest = SnapshotManifest::committed(
            SnapshotId::new(),
            None,
            0,
            None,
            None,
            actor(),
            Utc::now(),
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        );
        let body = SnapshotBody {
            manifest,
            nodes: vec![],
            edges: vec![],
            events: vec![],
            commit_records: vec![],
            claims: vec![],
            evidence: vec![],
            actions: vec![],
            outcomes: vec![],
            policies: vec![],
            policy_decisions: vec![],
            approval_requests: vec![],
            sensor_runs: vec![],
            sensor_checkpoints: vec![],
            schemas: vec![],
            replication_peers: vec![],
            replication_runs: vec![],
            metadata: HashMap::new(),
        };
        let json = serde_json::to_string(&body).unwrap();
        let restored: SnapshotBody = serde_json::from_str(&json).unwrap();
        assert_eq!(body, restored);
        assert_eq!(restored.event_count(), 0);
        assert_eq!(restored.commit_count(), 0);
        assert_eq!(restored.node_count(), 0);
        assert_eq!(restored.edge_count(), 0);
        assert_eq!(restored.schema_count(), 0);
    }
}
