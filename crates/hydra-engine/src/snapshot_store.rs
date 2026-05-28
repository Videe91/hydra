use hydra_core::error::{HydraError, Result};
use hydra_core::{SnapshotBody, SnapshotId, SnapshotManifest};
use std::collections::{BTreeMap, HashMap};

/// Pluggable durable backend for snapshot persistence.
///
/// `Hydra::snapshot()` calls `write_snapshot` *before* committing the
/// `SnapshotTaken` audit event, so if the backend fails the in-memory
/// snapshot is never inserted and no audit event is emitted — the engine
/// stays consistent.
///
/// Implemented in `hydra-storage::FileSnapshotStore` for the on-disk
/// case. The engine is backend-agnostic.
pub trait SnapshotBackend: Send + Sync {
    fn write_snapshot(&self, body: &SnapshotBody) -> Result<()>;
    fn read_snapshot(&self, id: &SnapshotId) -> Result<SnapshotBody>;
    fn list_snapshot_manifests(&self) -> Result<Vec<SnapshotManifest>>;
    fn delete_snapshot(&self, id: &SnapshotId) -> Result<()>;
}

/// In-memory store of snapshot bodies.
///
/// Snapshots are indexed two ways:
/// - by `SnapshotId` for direct lookup
/// - by `sequence` (the commit-ledger sequence the snapshot was taken at)
///   so list / latest queries can walk in sequence order
///
/// Storage is intentionally in-memory in Patch 2. Patch 3 will introduce a
/// `FileSnapshotStore` (or similar) backed by disk.
#[derive(Debug, Clone, Default)]
pub struct SnapshotStore {
    snapshots: HashMap<SnapshotId, SnapshotBody>,
    by_sequence: BTreeMap<u64, Vec<SnapshotId>>,
}

impl SnapshotStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a snapshot body. Returns the snapshot's id.
    ///
    /// Replacement re-indexes the sequence entry so a snapshot whose
    /// sequence changes (e.g. its manifest was updated) stays consistent.
    pub fn insert(&mut self, body: SnapshotBody) -> SnapshotId {
        let id = body.manifest.id.clone();
        if let Some(existing) = self.snapshots.get(&id).cloned() {
            self.remove_indexes(&existing);
        }
        self.by_sequence
            .entry(body.manifest.sequence)
            .or_default()
            .push(id.clone());
        self.snapshots.insert(id.clone(), body);
        id
    }

    pub fn body(&self, id: &SnapshotId) -> Option<&SnapshotBody> {
        self.snapshots.get(id)
    }

    pub fn manifest(&self, id: &SnapshotId) -> Option<&SnapshotManifest> {
        self.snapshots.get(id).map(|body| &body.manifest)
    }

    /// All manifests, ordered ascending by `sequence`. Ties within the same
    /// sequence are returned in insertion order.
    pub fn manifests(&self) -> Vec<&SnapshotManifest> {
        self.by_sequence
            .values()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.manifest(id))
            .collect()
    }

    /// Highest-sequence manifest, if any. Within the same sequence the most
    /// recently inserted wins (the latest entry in the bucket).
    pub fn latest_manifest(&self) -> Option<&SnapshotManifest> {
        self.by_sequence
            .iter()
            .next_back()
            .and_then(|(_, ids)| ids.last())
            .and_then(|id| self.manifest(id))
    }

    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Lookup-or-error helper for restore code paths.
    pub fn require_body(&self, id: &SnapshotId) -> Result<&SnapshotBody> {
        self.body(id)
            .ok_or_else(|| HydraError::QueryError(format!("unknown snapshot: {id}")))
    }

    fn remove_indexes(&mut self, body: &SnapshotBody) {
        let id = &body.manifest.id;
        let sequence = body.manifest.sequence;
        let should_remove_key = if let Some(ids) = self.by_sequence.get_mut(&sequence) {
            ids.retain(|existing| existing != id);
            ids.is_empty()
        } else {
            false
        };
        if should_remove_key {
            self.by_sequence.remove(&sequence);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{
        ActorId, CommitHash, CommitId, SnapshotBody, SnapshotId, SnapshotManifest,
    };
    use std::collections::HashMap;

    fn actor() -> ActorId {
        ActorId::from_str("actor_snapshot_store")
    }

    fn body(sequence: u64) -> SnapshotBody {
        let manifest = SnapshotManifest::committed(
            SnapshotId::new(),
            None,
            sequence,
            Some(CommitId::from_str(&format!("commit_{sequence}"))),
            Some(CommitHash(format!("engine-v0:{sequence}"))),
            actor(),
            chrono::Utc::now(),
            0, sequence as usize, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        );
        SnapshotBody {
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
            micro_models: vec![],
            micro_model_predictions: vec![],
            micro_model_observations: vec![],
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn insert_and_lookup_snapshot_body() {
        let mut store = SnapshotStore::new();
        let body = body(1);
        let id = body.manifest.id.clone();
        let inserted = store.insert(body.clone());
        assert_eq!(inserted, id);
        assert_eq!(store.len(), 1);
        assert_eq!(store.body(&id), Some(&body));
        assert_eq!(store.manifest(&id), Some(&body.manifest));
    }

    #[test]
    fn manifests_are_ordered_by_sequence() {
        let mut store = SnapshotStore::new();
        store.insert(body(2));
        store.insert(body(1));
        store.insert(body(3));
        let sequences = store
            .manifests()
            .into_iter()
            .map(|manifest| manifest.sequence)
            .collect::<Vec<_>>();
        assert_eq!(sequences, vec![1, 2, 3]);
        assert_eq!(store.latest_manifest().unwrap().sequence, 3);
    }

    #[test]
    fn replacing_snapshot_reindexes_sequence() {
        let mut store = SnapshotStore::new();
        let mut first = body(1);
        let id = first.manifest.id.clone();
        store.insert(first.clone());
        first.manifest.sequence = 9;
        store.insert(first);
        let sequences = store
            .manifests()
            .into_iter()
            .map(|manifest| manifest.sequence)
            .collect::<Vec<_>>();
        assert_eq!(sequences, vec![9]);
        assert_eq!(store.manifest(&id).unwrap().sequence, 9);
    }

    #[test]
    fn require_body_rejects_unknown_snapshot() {
        let store = SnapshotStore::new();
        let result = store.require_body(&SnapshotId::new());
        assert!(result.is_err());
    }
}
