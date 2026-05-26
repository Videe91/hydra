//! V2 patch 2 — durable engine-side mirror of the replication control plane.
//!
//! `ReplicationStore` materializes [`ReplicationPeer`] and [`ReplicationRun`]
//! records from the event log, indexes them by role / status / tenant /
//! peer, and tracks the latest observed offset and lag per peer. It is
//! the read model that future replication HTTP, agents, and workers will
//! query against — but it stays passive in this patch: no network, no
//! background work, no decision-making.
//!
//! Wiring story (matches `SensorCheckpointStore` exactly):
//!
//!   - `Hydra::ingest` post-cascade loop calls `apply_event(event)?`
//!   - `Hydra::recover_from_events` does the same during replay
//!   - `Hydra::reset_runtime_state_preserving_config` rebuilds it fresh
//!   - `Hydra::snapshot` collects `all_peers()` + `all_runs()` into the
//!     SnapshotBody and stamps the manifest via `with_replication_counts`
//!
//! Indexes use [`BTreeSet`] (not `HashSet`) so iteration is deterministic
//! — keeps test assertions and operator-facing listings stable.

use hydra_core::error::{HydraError, Result};
use hydra_core::{
    Event, EventKind, ReplicaId, ReplicationLag, ReplicationOffset, ReplicationPeer,
    ReplicationPeerStatus, ReplicationRole, ReplicationRun, ReplicationRunId, ReplicationRunStatus,
    TenantId,
};
use std::collections::{BTreeSet, HashMap};

/// Materialized replication peer + run state.
///
/// Built from the event log. Survives restart via snapshot + replay.
#[derive(Debug, Clone, Default)]
pub struct ReplicationStore {
    peers: HashMap<ReplicaId, ReplicationPeer>,
    runs: HashMap<ReplicationRunId, ReplicationRun>,

    peers_by_role: HashMap<ReplicationRole, BTreeSet<ReplicaId>>,
    peers_by_status: HashMap<ReplicationPeerStatus, BTreeSet<ReplicaId>>,
    peers_by_tenant: HashMap<TenantId, BTreeSet<ReplicaId>>,

    runs_by_peer: HashMap<ReplicaId, BTreeSet<ReplicationRunId>>,
    runs_by_status: HashMap<ReplicationRunStatus, BTreeSet<ReplicationRunId>>,
    runs_by_tenant: HashMap<TenantId, BTreeSet<ReplicationRunId>>,

    latest_offset_by_peer: HashMap<ReplicaId, ReplicationOffset>,
    latest_lag_by_peer: HashMap<ReplicaId, ReplicationLag>,
}

impl ReplicationStore {
    pub fn new() -> Self {
        Self::default()
    }

    // === Counts ===

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn run_count(&self) -> usize {
        self.runs.len()
    }

    // === Direct lookups ===

    pub fn peer(&self, id: &ReplicaId) -> Option<&ReplicationPeer> {
        self.peers.get(id)
    }

    pub fn run(&self, id: &ReplicationRunId) -> Option<&ReplicationRun> {
        self.runs.get(id)
    }

    pub fn all_peers(&self) -> impl Iterator<Item = &ReplicationPeer> {
        self.peers.values()
    }

    pub fn all_runs(&self) -> impl Iterator<Item = &ReplicationRun> {
        self.runs.values()
    }

    // === Indexed lookups ===

    pub fn peers_with_role(&self, role: ReplicationRole) -> Vec<&ReplicationPeer> {
        self.peers_by_role
            .get(&role)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.peers.get(id))
            .collect()
    }

    pub fn peers_with_status(&self, status: ReplicationPeerStatus) -> Vec<&ReplicationPeer> {
        self.peers_by_status
            .get(&status)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.peers.get(id))
            .collect()
    }

    pub fn peers_for_tenant(&self, tenant: &TenantId) -> Vec<&ReplicationPeer> {
        self.peers_by_tenant
            .get(tenant)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.peers.get(id))
            .collect()
    }

    pub fn runs_for_peer(&self, peer_id: &ReplicaId) -> Vec<&ReplicationRun> {
        self.runs_by_peer
            .get(peer_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.runs.get(id))
            .collect()
    }

    pub fn runs_with_status(&self, status: ReplicationRunStatus) -> Vec<&ReplicationRun> {
        self.runs_by_status
            .get(&status)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.runs.get(id))
            .collect()
    }

    pub fn runs_for_tenant(&self, tenant: &TenantId) -> Vec<&ReplicationRun> {
        self.runs_by_tenant
            .get(tenant)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.runs.get(id))
            .collect()
    }

    pub fn latest_offset(&self, peer_id: &ReplicaId) -> Option<&ReplicationOffset> {
        self.latest_offset_by_peer.get(peer_id)
    }

    pub fn latest_lag(&self, peer_id: &ReplicaId) -> Option<&ReplicationLag> {
        self.latest_lag_by_peer.get(peer_id)
    }

    /// V2 patch 4C — record a follower's local replication cursor after
    /// applying or bootstrapping from a leader peer.
    ///
    /// Direct in-memory update, **not event-sourced**, and intentionally
    /// **does not require the peer to be registered**. The puller carries
    /// its own `peer_id` as config identity (the local leader's logical
    /// id), and we don't want a follower to synthesize a local
    /// `ReplicaRegistered` event for the leader — that would diverge the
    /// follower's commit chain from the leader's.
    ///
    /// If `peer.last_offset` exists (the peer IS registered, e.g. on the
    /// leader where the puller is talking back to its own state), keep
    /// the registered peer in sync too. Otherwise just stamp the cursor.
    ///
    /// Survives in-process. Lost on restart — operators currently
    /// re-bootstrap. Persistent cursor is a later patch.
    pub fn record_local_apply_offset(
        &mut self,
        peer_id: ReplicaId,
        offset: ReplicationOffset,
    ) {
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.last_offset = Some(offset.clone());
            peer.updated_at = chrono::Utc::now();
        }
        self.latest_offset_by_peer.insert(peer_id, offset);
    }

    // === Event application ===

    /// Apply one Hydra event to the replication store.
    ///
    /// Non-replication events are ignored. Replication events that
    /// reference an unknown peer or run return `HydraError::QueryError`
    /// — matches the contract `SensorCheckpointStore` uses for unknown
    /// run / checkpoint IDs.
    pub fn apply_event(&mut self, event: &Event) -> Result<()> {
        let event_ts = event.timestamp;
        match &event.kind {
            EventKind::ReplicaRegistered { peer } => {
                self.insert_peer(peer.clone());
            }
            EventKind::ReplicaHeartbeatRecorded {
                peer_id,
                offset,
                lag,
            } => {
                let offset = offset.clone();
                let lag = lag.clone();
                self.mutate_peer(peer_id, |peer| {
                    peer.last_offset = Some(offset.clone());
                    peer.last_lag = lag.clone();
                    peer.updated_at = event_ts;
                })?;
                self.latest_offset_by_peer
                    .insert(peer_id.clone(), offset);
                if let Some(lag) = lag {
                    self.latest_lag_by_peer.insert(peer_id.clone(), lag);
                }
            }
            EventKind::ReplicationRunStarted { run } => {
                self.insert_run(run.clone());
            }
            EventKind::ReplicationRunCompleted {
                run_id,
                completed_offset,
            } => {
                let completed_offset = completed_offset.clone();
                self.mutate_run(run_id, |run| {
                    run.status = ReplicationRunStatus::Completed;
                    run.completed_at = Some(event_ts);
                    run.completed_offset = Some(completed_offset.clone());
                    run.error = None;
                })?;
            }
            EventKind::ReplicationRunFailed { run_id, error } => {
                let error = error.clone();
                self.mutate_run(run_id, |run| {
                    run.status = ReplicationRunStatus::Failed;
                    run.completed_at = Some(event_ts);
                    run.error = Some(error.clone());
                })?;
            }
            EventKind::ReplicaStatusChanged {
                peer_id, status, ..
            } => {
                let status = status.clone();
                self.mutate_peer(peer_id, |peer| {
                    peer.status = status.clone();
                    peer.updated_at = event_ts;
                })?;
            }
            EventKind::ReplicaPromoted { peer_id, .. } => {
                self.mutate_peer(peer_id, |peer| {
                    peer.role = ReplicationRole::Leader;
                    peer.status = ReplicationPeerStatus::Promoted;
                    peer.updated_at = event_ts;
                })?;
            }
            EventKind::ReplicaDemoted { peer_id, .. } => {
                self.mutate_peer(peer_id, |peer| {
                    peer.role = ReplicationRole::Follower;
                    peer.status = ReplicationPeerStatus::Demoted;
                    peer.updated_at = event_ts;
                })?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn apply_events<'a>(&mut self, events: impl IntoIterator<Item = &'a Event>) -> Result<()> {
        for event in events {
            self.apply_event(event)?;
        }
        Ok(())
    }

    // === Internal: insert / mutate helpers (mirror SensorCheckpointStore) ===

    fn insert_peer(&mut self, peer: ReplicationPeer) {
        let id = peer.id.clone();
        if let Some(existing) = self.peers.get(&id).cloned() {
            self.remove_peer_indexes(&existing);
        }
        self.peers.insert(id.clone(), peer);
        if let Some(inserted) = self.peers.get(&id).cloned() {
            self.insert_peer_indexes(&inserted);
        }
    }

    fn mutate_peer<F>(&mut self, id: &ReplicaId, mutation: F) -> Result<()>
    where
        F: FnOnce(&mut ReplicationPeer),
    {
        let mut peer = self.peers.remove(id).ok_or_else(|| {
            HydraError::QueryError(format!("unknown replication peer: {}", id))
        })?;
        self.remove_peer_indexes(&peer);
        mutation(&mut peer);
        self.insert_peer_indexes(&peer);
        self.peers.insert(id.clone(), peer);
        Ok(())
    }

    fn insert_run(&mut self, run: ReplicationRun) {
        let id = run.id.clone();
        if let Some(existing) = self.runs.get(&id).cloned() {
            self.remove_run_indexes(&existing);
        }
        self.runs.insert(id.clone(), run);
        if let Some(inserted) = self.runs.get(&id).cloned() {
            self.insert_run_indexes(&inserted);
        }
    }

    fn mutate_run<F>(&mut self, id: &ReplicationRunId, mutation: F) -> Result<()>
    where
        F: FnOnce(&mut ReplicationRun),
    {
        let mut run = self.runs.remove(id).ok_or_else(|| {
            HydraError::QueryError(format!("unknown replication run: {}", id))
        })?;
        self.remove_run_indexes(&run);
        mutation(&mut run);
        self.insert_run_indexes(&run);
        self.runs.insert(id.clone(), run);
        Ok(())
    }

    fn insert_peer_indexes(&mut self, peer: &ReplicationPeer) {
        let id = peer.id.clone();
        self.peers_by_role
            .entry(peer.role.clone())
            .or_default()
            .insert(id.clone());
        self.peers_by_status
            .entry(peer.status.clone())
            .or_default()
            .insert(id.clone());
        if let Some(tenant) = &peer.tenant_id {
            self.peers_by_tenant
                .entry(tenant.clone())
                .or_default()
                .insert(id);
        }
    }

    fn remove_peer_indexes(&mut self, peer: &ReplicationPeer) {
        let id = &peer.id;
        remove_from_btree_index(&mut self.peers_by_role, &peer.role, id);
        remove_from_btree_index(&mut self.peers_by_status, &peer.status, id);
        if let Some(tenant) = &peer.tenant_id {
            remove_from_btree_index(&mut self.peers_by_tenant, tenant, id);
        }
    }

    fn insert_run_indexes(&mut self, run: &ReplicationRun) {
        let id = run.id.clone();
        self.runs_by_peer
            .entry(run.peer_id.clone())
            .or_default()
            .insert(id.clone());
        self.runs_by_status
            .entry(run.status.clone())
            .or_default()
            .insert(id.clone());
        if let Some(tenant) = &run.tenant_id {
            self.runs_by_tenant
                .entry(tenant.clone())
                .or_default()
                .insert(id);
        }
    }

    fn remove_run_indexes(&mut self, run: &ReplicationRun) {
        let id = &run.id;
        remove_from_btree_index(&mut self.runs_by_peer, &run.peer_id, id);
        remove_from_btree_index(&mut self.runs_by_status, &run.status, id);
        if let Some(tenant) = &run.tenant_id {
            remove_from_btree_index(&mut self.runs_by_tenant, tenant, id);
        }
    }
}

fn remove_from_btree_index<K, V>(index: &mut HashMap<K, BTreeSet<V>>, key: &K, value: &V)
where
    K: std::hash::Hash + Eq + Clone,
    V: Ord,
{
    let should_remove_key = if let Some(values) = index.get_mut(key) {
        values.remove(value);
        values.is_empty()
    } else {
        false
    };
    if should_remove_key {
        index.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{
        ActorId, CascadeId, EventId, ReplicaId, ReplicationLag, ReplicationMode,
        ReplicationOffset, ReplicationPeer, ReplicationPeerStatus, ReplicationRole,
        ReplicationRun, ReplicationRunStatus, TenantId,
    };

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_replication_test")
    }

    fn actor() -> ActorId {
        ActorId::from_str("actor_replication")
    }

    fn event(kind: EventKind) -> Event {
        Event {
            id: EventId::new(),
            tenant_id: Some(tenant()),
            timestamp: chrono::Utc::now(),
            kind,
            caused_by: vec![],
            cascade_id: CascadeId::new(),
            cascade_depth: 0,
            cascade_breadth_index: 0,
        }
    }

    fn peer(id: &str, role: ReplicationRole, with_tenant: bool) -> ReplicationPeer {
        let mut p = ReplicationPeer::registered(
            ReplicaId::from_str(id),
            role,
            ReplicationMode::SnapshotThenTail,
            actor(),
        );
        if with_tenant {
            p.tenant_id = Some(tenant());
        }
        p
    }

    fn run(peer_id: &str, with_tenant: bool) -> ReplicationRun {
        let mut r = ReplicationRun::started(
            ReplicaId::from_str(peer_id),
            ReplicationMode::CommitLogStreaming,
            Some(ReplicationOffset::from_sequence(100)),
        );
        if with_tenant {
            r.tenant_id = Some(tenant());
        }
        r
    }

    #[test]
    fn registers_peer_and_indexes_by_role_status_tenant() {
        let mut store = ReplicationStore::new();
        let p = peer("replica_acme", ReplicationRole::Follower, true);
        let peer_id = p.id.clone();
        store
            .apply_event(&event(EventKind::ReplicaRegistered { peer: p.clone() }))
            .unwrap();
        assert_eq!(store.peer_count(), 1);
        assert_eq!(store.peer(&peer_id), Some(&p));
        assert_eq!(store.peers_with_role(ReplicationRole::Follower).len(), 1);
        assert_eq!(
            store
                .peers_with_status(ReplicationPeerStatus::Registered)
                .len(),
            1
        );
        assert_eq!(store.peers_for_tenant(&tenant()).len(), 1);
    }

    #[test]
    fn heartbeat_updates_latest_offset_and_lag() {
        let mut store = ReplicationStore::new();
        let p = peer("replica_acme", ReplicationRole::Follower, false);
        let peer_id = p.id.clone();
        store
            .apply_event(&event(EventKind::ReplicaRegistered { peer: p }))
            .unwrap();

        let offset = ReplicationOffset::from_sequence(500);
        let lag = ReplicationLag::observe(1000, 500, chrono::Utc::now());
        store
            .apply_event(&event(EventKind::ReplicaHeartbeatRecorded {
                peer_id: peer_id.clone(),
                offset: offset.clone(),
                lag: Some(lag.clone()),
            }))
            .unwrap();

        let stored_peer = store.peer(&peer_id).unwrap();
        assert_eq!(stored_peer.last_offset, Some(offset.clone()));
        assert_eq!(stored_peer.last_lag, Some(lag.clone()));
        assert_eq!(store.latest_offset(&peer_id), Some(&offset));
        assert_eq!(store.latest_lag(&peer_id), Some(&lag));
    }

    #[test]
    fn heartbeat_without_known_peer_errors() {
        let mut store = ReplicationStore::new();
        let err = store
            .apply_event(&event(EventKind::ReplicaHeartbeatRecorded {
                peer_id: ReplicaId::from_str("replica_ghost"),
                offset: ReplicationOffset::from_sequence(1),
                lag: None,
            }))
            .unwrap_err();
        assert!(
            matches!(err, HydraError::QueryError(_)),
            "expected QueryError for unknown peer, got {:?}",
            err
        );
    }

    #[test]
    fn run_started_completed_reindexes_status() {
        let mut store = ReplicationStore::new();
        let r = run("replica_acme", true);
        let run_id = r.id.clone();
        store
            .apply_event(&event(EventKind::ReplicationRunStarted { run: r }))
            .unwrap();
        assert_eq!(store.run_count(), 1);
        assert_eq!(
            store
                .runs_with_status(ReplicationRunStatus::Started)
                .len(),
            1
        );

        store
            .apply_event(&event(EventKind::ReplicationRunCompleted {
                run_id: run_id.clone(),
                completed_offset: ReplicationOffset::from_sequence(2000),
            }))
            .unwrap();
        let stored = store.run(&run_id).unwrap();
        assert_eq!(stored.status, ReplicationRunStatus::Completed);
        assert!(stored.completed_at.is_some());
        assert_eq!(
            stored.completed_offset,
            Some(ReplicationOffset::from_sequence(2000))
        );
        assert_eq!(
            store
                .runs_with_status(ReplicationRunStatus::Started)
                .len(),
            0
        );
        assert_eq!(
            store
                .runs_with_status(ReplicationRunStatus::Completed)
                .len(),
            1
        );
    }

    #[test]
    fn run_failed_sets_error_and_reindexes() {
        let mut store = ReplicationStore::new();
        let r = run("replica_acme", false);
        let run_id = r.id.clone();
        store
            .apply_event(&event(EventKind::ReplicationRunStarted { run: r }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ReplicationRunFailed {
                run_id: run_id.clone(),
                error: "stream closed".to_string(),
            }))
            .unwrap();
        let stored = store.run(&run_id).unwrap();
        assert_eq!(stored.status, ReplicationRunStatus::Failed);
        assert_eq!(stored.error.as_deref(), Some("stream closed"));
    }

    #[test]
    fn unknown_run_completion_errors() {
        let mut store = ReplicationStore::new();
        let err = store
            .apply_event(&event(EventKind::ReplicationRunCompleted {
                run_id: ReplicationRunId::from_str("replrun_ghost"),
                completed_offset: ReplicationOffset::from_sequence(1),
            }))
            .unwrap_err();
        assert!(matches!(err, HydraError::QueryError(_)));
    }

    #[test]
    fn status_change_reindexes_peer() {
        let mut store = ReplicationStore::new();
        let p = peer("replica_acme", ReplicationRole::Follower, false);
        let peer_id = p.id.clone();
        store
            .apply_event(&event(EventKind::ReplicaRegistered { peer: p }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ReplicaStatusChanged {
                peer_id: peer_id.clone(),
                status: ReplicationPeerStatus::Lagging,
                reason: Some("lag > threshold".to_string()),
            }))
            .unwrap();
        let stored = store.peer(&peer_id).unwrap();
        assert_eq!(stored.status, ReplicationPeerStatus::Lagging);
        assert_eq!(
            store
                .peers_with_status(ReplicationPeerStatus::Registered)
                .len(),
            0
        );
        assert_eq!(
            store
                .peers_with_status(ReplicationPeerStatus::Lagging)
                .len(),
            1
        );
    }

    #[test]
    fn promote_sets_leader_role_and_promoted_status() {
        let mut store = ReplicationStore::new();
        let p = peer("replica_acme", ReplicationRole::Follower, false);
        let peer_id = p.id.clone();
        store
            .apply_event(&event(EventKind::ReplicaRegistered { peer: p }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ReplicaPromoted {
                peer_id: peer_id.clone(),
                promoted_by: actor(),
                reason: Some("manual promote".to_string()),
            }))
            .unwrap();
        let stored = store.peer(&peer_id).unwrap();
        assert_eq!(stored.role, ReplicationRole::Leader);
        assert_eq!(stored.status, ReplicationPeerStatus::Promoted);
        assert_eq!(store.peers_with_role(ReplicationRole::Leader).len(), 1);
        assert_eq!(store.peers_with_role(ReplicationRole::Follower).len(), 0);
    }

    #[test]
    fn demote_sets_follower_role_and_demoted_status() {
        let mut store = ReplicationStore::new();
        let p = peer("replica_acme", ReplicationRole::Leader, false);
        let peer_id = p.id.clone();
        store
            .apply_event(&event(EventKind::ReplicaRegistered { peer: p }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ReplicaDemoted {
                peer_id: peer_id.clone(),
                demoted_by: actor(),
                reason: None,
            }))
            .unwrap();
        let stored = store.peer(&peer_id).unwrap();
        assert_eq!(stored.role, ReplicationRole::Follower);
        assert_eq!(stored.status, ReplicationPeerStatus::Demoted);
    }

    #[test]
    fn unknown_peer_promote_errors() {
        let mut store = ReplicationStore::new();
        let err = store
            .apply_event(&event(EventKind::ReplicaPromoted {
                peer_id: ReplicaId::from_str("replica_ghost"),
                promoted_by: actor(),
                reason: None,
            }))
            .unwrap_err();
        assert!(matches!(err, HydraError::QueryError(_)));
    }

    #[test]
    fn ignores_non_replication_events() {
        let mut store = ReplicationStore::new();
        // A non-replication event must be silently ignored, not error.
        let mut payload = std::collections::HashMap::new();
        payload.insert("k".to_string(), hydra_core::Value::Int(1));
        store
            .apply_event(&event(EventKind::Signal {
                source: hydra_core::NodeId::from_str("node_unrelated"),
                name: "unrelated".to_string(),
                payload,
            }))
            .unwrap();
        assert_eq!(store.peer_count(), 0);
        assert_eq!(store.run_count(), 0);
    }

    #[test]
    fn runs_for_peer_and_tenant_indexes_work() {
        let mut store = ReplicationStore::new();
        let peer_id = ReplicaId::from_str("replica_acme");
        let p = peer(peer_id.as_str(), ReplicationRole::Follower, true);
        store
            .apply_event(&event(EventKind::ReplicaRegistered { peer: p }))
            .unwrap();
        for _ in 0..3 {
            let r = run(peer_id.as_str(), true);
            store
                .apply_event(&event(EventKind::ReplicationRunStarted { run: r }))
                .unwrap();
        }
        assert_eq!(store.runs_for_peer(&peer_id).len(), 3);
        assert_eq!(store.runs_for_tenant(&tenant()).len(), 3);
    }
}
