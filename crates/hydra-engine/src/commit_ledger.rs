use hydra_core::error::{HydraError, Result};
use hydra_core::{
    CommitBatch, CommitHash, CommitId, CommitRecord, CommitStatus, Event, EventCommitRecord,
    EventHash, IdempotencyKey,
};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

/// Pluggable sink for durable commit batch persistence.
///
/// HydraEngine owns commit creation and sequencing.
/// Storage backends implement this trait to persist committed batches.
///
/// This keeps hydra-engine independent from hydra-storage.
pub trait CommitBatchWriter: Send + Sync {
    fn append_commit(&self, batch: &CommitBatch) -> Result<()>;
}

/// In-memory commit ledger for committed cascade batches.
///
/// v0 intentionally uses deterministic std hashing over serialized event/batch
/// material. This is NOT cryptographic. The storage layer can later replace the
/// digest implementation with SHA-256 over canonical JSON without changing the
/// ledger API.
#[derive(Debug, Clone, Default)]
pub struct CommitLedger {
    next_sequence: u64,
    head_hash: Option<CommitHash>,
    records: Vec<CommitRecord>,
    batches_by_id: HashMap<CommitId, CommitBatch>,
    idempotency_index: HashMap<IdempotencyKey, CommitId>,
}

impl CommitLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence + 1
    }

    pub fn head_hash(&self) -> Option<&CommitHash> {
        self.head_hash.as_ref()
    }

    pub fn commit_count(&self) -> usize {
        self.records.len()
    }

    pub fn records(&self) -> &[CommitRecord] {
        &self.records
    }

    pub fn latest_record(&self) -> Option<&CommitRecord> {
        self.records.last()
    }

    pub fn batch(&self, id: &CommitId) -> Option<&CommitBatch> {
        self.batches_by_id.get(id)
    }

    pub fn record(&self, id: &CommitId) -> Option<&CommitRecord> {
        self.records.iter().find(|record| &record.id == id)
    }

    pub fn commit_for_idempotency_key(&self, key: &IdempotencyKey) -> Option<&CommitBatch> {
        let commit_id = self.idempotency_index.get(key)?;
        self.batch(commit_id)
    }

    /// Commit an atomic event batch.
    ///
    /// If the idempotency key was already used, returns the original committed
    /// batch and does not append a duplicate.
    pub fn commit_events(
        &mut self,
        events: Vec<Event>,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Result<CommitBatch> {
        if events.is_empty() {
            return Err(HydraError::QueryError(
                "cannot commit an empty event batch".to_string(),
            ));
        }

        if let Some(key) = &idempotency_key {
            if let Some(existing) = self.commit_for_idempotency_key(key) {
                return Ok(existing.clone());
            }
        }

        let sequence = self.next_sequence();
        let previous_hash = self.head_hash.clone();

        let mut batch = CommitBatch::new(events)
            .with_sequence(sequence)
            .with_previous_hash(previous_hash);
        if let Some(key) = idempotency_key.clone() {
            batch = batch.with_idempotency_key(key);
        }

        batch.event_records = batch
            .events
            .iter()
            .map(|event| -> Result<EventCommitRecord> {
                Ok(EventCommitRecord {
                    event_id: event.id.clone(),
                    event_hash: hash_event(event)?,
                    cascade_id: event.cascade_id.clone(),
                    cascade_depth: event.cascade_depth,
                    cascade_breadth_index: event.cascade_breadth_index,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let commit_hash = hash_commit_material(&batch)?;
        batch = batch
            .with_commit_hash(commit_hash.clone())
            .mark_committed(None);

        let record = CommitRecord::try_from(&batch)
            .map_err(|err| HydraError::QueryError(err.to_string()))?;

        self.next_sequence = sequence;
        self.head_hash = Some(commit_hash);
        if let Some(key) = batch.idempotency_key.clone() {
            self.idempotency_index.insert(key, batch.id.clone());
        }
        self.records.push(record);
        self.batches_by_id.insert(batch.id.clone(), batch.clone());

        Ok(batch)
    }

    /// Load an already-committed batch into the in-memory ledger.
    ///
    /// This is used during recovery from durable storage. It does not
    /// recompute a new commit. It trusts the supplied CommitBatch shape,
    /// indexes it, then verify_chain() can recompute hashes and validate
    /// the chain.
    pub fn load_committed_batch(&mut self, batch: CommitBatch) -> Result<()> {
        if batch.status != CommitStatus::Committed {
            return Err(HydraError::QueryError(format!(
                "cannot load non-committed batch {} with status {:?}",
                batch.id, batch.status
            )));
        }
        if batch.commit_hash.is_none() {
            return Err(HydraError::QueryError(format!(
                "cannot load committed batch {} without commit_hash",
                batch.id
            )));
        }
        if self.batches_by_id.contains_key(&batch.id) {
            return Err(HydraError::QueryError(format!(
                "duplicate commit id during recovery: {}",
                batch.id
            )));
        }
        if let Some(key) = &batch.idempotency_key {
            if self.idempotency_index.contains_key(key) {
                return Err(HydraError::QueryError(format!(
                    "duplicate idempotency key during recovery: {}",
                    key.value()
                )));
            }
        }
        let record = CommitRecord::try_from(&batch)
            .map_err(|err| HydraError::QueryError(err.to_string()))?;
        if let Some(key) = batch.idempotency_key.clone() {
            self.idempotency_index.insert(key, batch.id.clone());
        }
        self.next_sequence = self.next_sequence.max(batch.sequence);
        self.head_hash = batch.commit_hash.clone();
        self.records.push(record);
        self.batches_by_id.insert(batch.id.clone(), batch);
        Ok(())
    }

    /// Load committed batches in order, then verify the resulting chain.
    pub fn load_committed_batches<I>(&mut self, batches: I) -> Result<()>
    where
        I: IntoIterator<Item = CommitBatch>,
    {
        for batch in batches {
            self.load_committed_batch(batch)?;
        }
        self.verify_chain()
    }

    /// Append a leader-supplied committed batch as the next entry in this
    /// ledger's chain.
    ///
    /// Stricter than `load_committed_batch` — validates ALL of:
    ///   - `batch.sequence == self.next_sequence()`
    ///   - `batch.previous_hash == self.head_hash`
    ///   - `batch.status == Committed`
    ///   - `batch.commit_hash` is `Some`
    ///   - no duplicate commit id
    ///   - no duplicate idempotency key
    ///   - recomputed `hash_commit_material(&batch) == batch.commit_hash`
    ///     (so a malicious or corrupt leader cannot slip in a doctored hash)
    ///
    /// On success: indexes the batch, pushes the record, advances head.
    /// On failure: returns `Err` without mutating self.
    ///
    /// Used by V2 replication (`Hydra::apply_replication_commits`).
    /// `load_committed_batch` stays the right call for recovery from a
    /// trusted, well-ordered durable log; `append_committed_batch` is the
    /// right call when accepting a batch from an external source.
    pub fn append_committed_batch(&mut self, batch: CommitBatch) -> Result<()> {
        let expected_sequence = self.next_sequence();
        if batch.sequence != expected_sequence {
            return Err(HydraError::QueryError(format!(
                "replication batch sequence mismatch: expected {}, got {}",
                expected_sequence, batch.sequence
            )));
        }
        if batch.previous_hash != self.head_hash {
            return Err(HydraError::QueryError(format!(
                "replication batch previous_hash mismatch at sequence {}",
                batch.sequence
            )));
        }
        if batch.status != CommitStatus::Committed {
            return Err(HydraError::QueryError(format!(
                "replication batch {} is not committed (status {:?})",
                batch.id, batch.status
            )));
        }
        let Some(commit_hash) = batch.commit_hash.clone() else {
            return Err(HydraError::QueryError(format!(
                "replication batch {} missing commit_hash",
                batch.id
            )));
        };
        if self.batches_by_id.contains_key(&batch.id) {
            return Err(HydraError::QueryError(format!(
                "duplicate commit id during replication: {}",
                batch.id
            )));
        }
        if let Some(key) = &batch.idempotency_key {
            if self.idempotency_index.contains_key(key) {
                return Err(HydraError::QueryError(format!(
                    "duplicate idempotency key during replication: {}",
                    key.value()
                )));
            }
        }
        // Integrity recompute — a corrupt or hostile leader cannot ship
        // a batch whose stored commit_hash disagrees with its material.
        let recomputed = hash_commit_material(&batch)?;
        if recomputed != commit_hash {
            return Err(HydraError::QueryError(format!(
                "replication batch {} commit_hash does not match recomputed hash",
                batch.id
            )));
        }
        let record = CommitRecord::try_from(&batch)
            .map_err(|err| HydraError::QueryError(err.to_string()))?;
        if let Some(key) = batch.idempotency_key.clone() {
            self.idempotency_index.insert(key, batch.id.clone());
        }
        self.next_sequence = batch.sequence;
        self.head_hash = Some(commit_hash);
        self.records.push(record);
        self.batches_by_id.insert(batch.id.clone(), batch);
        Ok(())
    }

    /// Return all loaded batches ordered by commit sequence.
    pub fn batches_in_sequence(&self) -> Vec<&CommitBatch> {
        let mut batches: Vec<&CommitBatch> = self.batches_by_id.values().collect();
        batches.sort_by_key(|batch| batch.sequence);
        batches
    }

    /// Verify the in-memory hash chain and record/batch consistency.
    pub fn verify_chain(&self) -> Result<()> {
        let mut previous_hash: Option<CommitHash> = None;
        for (index, record) in self.records.iter().enumerate() {
            let expected_sequence = (index as u64) + 1;
            if record.sequence != expected_sequence {
                return Err(HydraError::QueryError(format!(
                    "commit sequence mismatch at index {}: expected {}, got {}",
                    index, expected_sequence, record.sequence
                )));
            }
            if record.previous_hash != previous_hash {
                return Err(HydraError::QueryError(format!(
                    "commit previous_hash mismatch at sequence {}",
                    record.sequence
                )));
            }
            let Some(batch) = self.batches_by_id.get(&record.id) else {
                return Err(HydraError::QueryError(format!(
                    "missing commit batch for record {}",
                    record.id
                )));
            };
            if batch.status != CommitStatus::Committed {
                return Err(HydraError::QueryError(format!(
                    "commit batch {} is not committed",
                    batch.id
                )));
            }
            if batch.event_count() != record.event_count {
                return Err(HydraError::QueryError(format!(
                    "event count mismatch for commit {}",
                    batch.id
                )));
            }
            if batch.commit_hash.as_ref() != Some(&record.commit_hash) {
                return Err(HydraError::QueryError(format!(
                    "commit hash mismatch for commit {}",
                    batch.id
                )));
            }
            let recomputed_hash = hash_commit_material(batch)?;
            if recomputed_hash != record.commit_hash {
                return Err(HydraError::QueryError(format!(
                    "recomputed commit hash mismatch for commit {}",
                    batch.id
                )));
            }
            previous_hash = Some(record.commit_hash.clone());
        }
        if self.head_hash != previous_hash {
            return Err(HydraError::QueryError(
                "ledger head_hash does not match last record".to_string(),
            ));
        }
        Ok(())
    }
}

fn hash_event(event: &Event) -> Result<EventHash> {
    let encoded = serde_json::to_string(event).map_err(|err| {
        HydraError::SerializationError(format!("failed to serialize event for hashing: {err}"))
    })?;
    Ok(EventHash::new(engine_digest_v0(&encoded)))
}

fn hash_commit_material(batch: &CommitBatch) -> Result<CommitHash> {
    let material = CommitHashMaterial {
        id: batch.id.to_string(),
        tenant_id: batch.tenant_id.as_ref().map(ToString::to_string),
        sequence: batch.sequence,
        previous_hash: batch
            .previous_hash
            .as_ref()
            .map(|hash| hash.value().to_string()),
        idempotency_key: batch
            .idempotency_key
            .as_ref()
            .map(|key| key.value().to_string()),
        event_records: batch
            .event_records
            .iter()
            .map(|record| EventHashMaterial {
                event_id: record.event_id.to_string(),
                event_hash: record.event_hash.value().to_string(),
                cascade_id: record.cascade_id.to_string(),
                cascade_depth: record.cascade_depth,
                cascade_breadth_index: record.cascade_breadth_index,
            })
            .collect(),
        metadata: batch
            .metadata
            .iter()
            .map(|(key, value)| (key.clone(), format!("{value:?}")))
            .collect(),
    };
    let encoded = serde_json::to_string(&material).map_err(|err| {
        HydraError::SerializationError(format!("failed to serialize commit for hashing: {err}"))
    })?;
    Ok(CommitHash::new(engine_digest_v0(&encoded)))
}

/// Non-cryptographic deterministic digest used only for engine v0 tests and
/// in-memory integrity checks.
fn engine_digest_v0(input: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    input.hash(&mut hasher);
    format!("engine-v0:{:016x}", hasher.finish())
}

#[derive(Debug, serde::Serialize)]
struct CommitHashMaterial {
    id: String,
    tenant_id: Option<String>,
    sequence: u64,
    previous_hash: Option<String>,
    idempotency_key: Option<String>,
    event_records: Vec<EventHashMaterial>,
    metadata: Vec<(String, String)>,
}

#[derive(Debug, serde::Serialize)]
struct EventHashMaterial {
    event_id: String,
    event_hash: String,
    cascade_id: String,
    cascade_depth: u32,
    cascade_breadth_index: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{CascadeId, EventId, EventKind, NodeId, Value};
    use std::collections::HashMap;

    fn signal_event(name: &str) -> Event {
        Event {
            id: EventId::new(),
            tenant_id: None,
            timestamp: chrono::Utc::now(),
            kind: EventKind::Signal {
                source: NodeId::from_str("test"),
                name: name.to_string(),
                payload: HashMap::new(),
            },
            caused_by: vec![],
            cascade_id: CascadeId::new(),
            cascade_depth: 0,
            cascade_breadth_index: 0,
        }
    }

    #[test]
    fn commits_event_batch_with_sequence_and_hashes() {
        let mut ledger = CommitLedger::new();
        let batch = ledger
            .commit_events(vec![signal_event("first")], None)
            .unwrap();
        assert_eq!(batch.sequence, 1);
        assert!(batch.previous_hash.is_none());
        assert!(batch.commit_hash.is_some());
        assert_eq!(batch.event_records.len(), 1);
        assert_eq!(batch.status, CommitStatus::Committed);
        assert_eq!(ledger.commit_count(), 1);
        assert_eq!(ledger.head_hash(), batch.commit_hash.as_ref());
        ledger.verify_chain().unwrap();
    }

    #[test]
    fn links_commit_hash_chain() {
        let mut ledger = CommitLedger::new();
        let first = ledger
            .commit_events(vec![signal_event("first")], None)
            .unwrap();
        let second = ledger
            .commit_events(vec![signal_event("second")], None)
            .unwrap();
        assert_eq!(first.sequence, 1);
        assert_eq!(second.sequence, 2);
        assert_eq!(second.previous_hash, first.commit_hash);
        assert_eq!(ledger.commit_count(), 2);
        ledger.verify_chain().unwrap();
    }

    #[test]
    fn idempotency_key_returns_original_commit() {
        let mut ledger = CommitLedger::new();
        let key = IdempotencyKey::new("request-1");
        let first = ledger
            .commit_events(vec![signal_event("first")], Some(key.clone()))
            .unwrap();
        let second = ledger
            .commit_events(vec![signal_event("duplicate")], Some(key.clone()))
            .unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(first.commit_hash, second.commit_hash);
        assert_eq!(ledger.commit_count(), 1);
        assert_eq!(
            ledger.commit_for_idempotency_key(&key).unwrap().id,
            first.id
        );
        ledger.verify_chain().unwrap();
    }

    #[test]
    fn rejects_empty_event_batch() {
        let mut ledger = CommitLedger::new();
        let result = ledger.commit_events(Vec::new(), None);
        assert!(result.is_err());
    }

    #[test]
    fn records_are_index_friendly() {
        let mut ledger = CommitLedger::new();
        let batch = ledger
            .commit_events(vec![signal_event("first"), signal_event("second")], None)
            .unwrap();
        let record = ledger.latest_record().unwrap();
        assert_eq!(record.id, batch.id);
        assert_eq!(record.sequence, 1);
        assert_eq!(record.event_count, 2);
        assert_eq!(record.commit_hash, batch.commit_hash.unwrap());
        assert!(record.first_event_id.is_some());
        assert!(record.last_event_id.is_some());
    }

    #[test]
    fn record_lookup_by_commit_id() {
        let mut ledger = CommitLedger::new();
        let batch = ledger
            .commit_events(vec![signal_event("first")], None)
            .unwrap();
        assert_eq!(ledger.batch(&batch.id).unwrap().id, batch.id);
        assert_eq!(ledger.record(&batch.id).unwrap().id, batch.id);
    }

    #[test]
    fn next_sequence_reports_next_commit_number() {
        let mut ledger = CommitLedger::new();
        assert_eq!(ledger.next_sequence(), 1);
        ledger
            .commit_events(vec![signal_event("first")], None)
            .unwrap();
        assert_eq!(ledger.next_sequence(), 2);
    }

    #[test]
    fn unused_import_guard() {
        let _ = Value::Bool(true);
    }

    #[test]
    fn loads_committed_batches_and_verifies_chain() {
        let mut original = CommitLedger::new();
        let first = original
            .commit_events(
                vec![signal_event("first")],
                Some(IdempotencyKey::new("first-key")),
            )
            .unwrap();
        let second = original
            .commit_events(
                vec![signal_event("second")],
                Some(IdempotencyKey::new("second-key")),
            )
            .unwrap();

        let mut recovered = CommitLedger::new();
        recovered
            .load_committed_batches(vec![first.clone(), second.clone()])
            .unwrap();

        assert_eq!(recovered.commit_count(), 2);
        assert_eq!(recovered.latest_record().unwrap().sequence, 2);
        assert_eq!(recovered.head_hash(), second.commit_hash.as_ref());
        assert_eq!(
            recovered
                .commit_for_idempotency_key(&IdempotencyKey::new("first-key"))
                .unwrap()
                .id,
            first.id
        );
        recovered.verify_chain().unwrap();
    }

    #[test]
    fn rejects_pending_batch_during_recovery() {
        let event = signal_event("pending");
        let batch = CommitBatch::new(vec![event]);
        let mut ledger = CommitLedger::new();
        let result = ledger.load_committed_batch(batch);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_duplicate_commit_id_during_recovery() {
        let mut original = CommitLedger::new();
        let batch = original
            .commit_events(vec![signal_event("first")], None)
            .unwrap();
        let mut recovered = CommitLedger::new();
        recovered.load_committed_batch(batch.clone()).unwrap();
        let result = recovered.load_committed_batch(batch);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_duplicate_idempotency_key_during_recovery() {
        let mut original = CommitLedger::new();
        let first = original
            .commit_events(
                vec![signal_event("first")],
                Some(IdempotencyKey::new("same-key")),
            )
            .unwrap();
        let mut second = original
            .commit_events(
                vec![signal_event("second")],
                Some(IdempotencyKey::new("other-key")),
            )
            .unwrap();
        second.idempotency_key = Some(IdempotencyKey::new("same-key"));
        let mut recovered = CommitLedger::new();
        recovered.load_committed_batch(first).unwrap();
        let result = recovered.load_committed_batch(second);
        assert!(result.is_err());
    }

    #[test]
    fn batches_in_sequence_returns_ordered_batches() {
        let mut ledger = CommitLedger::new();
        let first = ledger
            .commit_events(vec![signal_event("first")], None)
            .unwrap();
        let second = ledger
            .commit_events(vec![signal_event("second")], None)
            .unwrap();
        let batches = ledger.batches_in_sequence();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].id, first.id);
        assert_eq!(batches[1].id, second.id);
    }

    // === V2 patch 3B — append_committed_batch ===

    /// Build two leader batches with a valid chain. Returns owned clones
    /// so each test can mutate them in isolation.
    fn leader_batches(count: usize) -> Vec<CommitBatch> {
        let mut leader = CommitLedger::new();
        let mut batches = Vec::new();
        for i in 0..count {
            let batch = leader
                .commit_events(vec![signal_event(&format!("evt_{i}"))], None)
                .unwrap();
            batches.push(batch);
        }
        batches
    }

    #[test]
    fn append_committed_batch_appends_clean_chain() {
        let leader = leader_batches(2);
        let mut follower = CommitLedger::new();
        follower.append_committed_batch(leader[0].clone()).unwrap();
        follower.append_committed_batch(leader[1].clone()).unwrap();
        assert_eq!(follower.commit_count(), 2);
        assert_eq!(follower.head_hash(), leader[1].commit_hash.as_ref());
        follower.verify_chain().unwrap();
    }

    #[test]
    fn append_committed_batch_rejects_sequence_gap() {
        let leader = leader_batches(2);
        let mut follower = CommitLedger::new();
        // Skip seq=1 and try to apply seq=2 directly.
        let err = follower
            .append_committed_batch(leader[1].clone())
            .unwrap_err();
        assert!(matches!(err, HydraError::QueryError(_)));
        assert_eq!(follower.commit_count(), 0);
    }

    #[test]
    fn append_committed_batch_rejects_wrong_previous_hash() {
        let leader = leader_batches(2);
        let mut follower = CommitLedger::new();
        follower.append_committed_batch(leader[0].clone()).unwrap();
        let mut tampered = leader[1].clone();
        tampered.previous_hash = Some(CommitHash("engine-v0:bogus".to_string()));
        let err = follower
            .append_committed_batch(tampered)
            .unwrap_err();
        assert!(matches!(err, HydraError::QueryError(_)));
    }

    #[test]
    fn append_committed_batch_rejects_uncommitted_status() {
        let leader = leader_batches(1);
        let mut tampered = leader[0].clone();
        tampered.status = CommitStatus::Pending;
        let mut follower = CommitLedger::new();
        let err = follower
            .append_committed_batch(tampered)
            .unwrap_err();
        assert!(matches!(err, HydraError::QueryError(_)));
    }

    #[test]
    fn append_committed_batch_rejects_missing_commit_hash() {
        let leader = leader_batches(1);
        let mut tampered = leader[0].clone();
        tampered.commit_hash = None;
        let mut follower = CommitLedger::new();
        let err = follower
            .append_committed_batch(tampered)
            .unwrap_err();
        assert!(matches!(err, HydraError::QueryError(_)));
    }

    #[test]
    fn append_committed_batch_rejects_doctored_commit_hash() {
        let leader = leader_batches(1);
        let mut tampered = leader[0].clone();
        // Keep the chain valid (previous_hash is None for first batch) but
        // doctor the stored commit_hash. The recompute MUST catch this.
        tampered.commit_hash = Some(CommitHash("engine-v0:fabricated".to_string()));
        let mut follower = CommitLedger::new();
        let err = follower
            .append_committed_batch(tampered)
            .unwrap_err();
        assert!(matches!(err, HydraError::QueryError(_)));
    }

    #[test]
    fn append_committed_batch_rejects_duplicate_commit_id() {
        let leader = leader_batches(1);
        let mut follower = CommitLedger::new();
        follower.append_committed_batch(leader[0].clone()).unwrap();
        // Re-applying the SAME batch now fails on sequence (head is at
        // seq=1, expected next is seq=2). To exercise the dup-id check
        // specifically, bump sequence so the gap check passes, then leave
        // id colliding — but bumping seq invalidates the hash. So the
        // sequence guard IS the dup-id guard at the ledger level.
        let err = follower
            .append_committed_batch(leader[0].clone())
            .unwrap_err();
        assert!(matches!(err, HydraError::QueryError(_)));
    }

    #[test]
    fn append_committed_batch_rejects_duplicate_idempotency_key() {
        // Two distinct batches with the same idempotency key on a single
        // follower's chain. This is the realistic case the dup-key check
        // protects against (a buggy/hostile leader shipping a colliding
        // key). We build it by re-keying batch 2 to collide with batch 1.
        let leader = leader_batches(2);
        let key = IdempotencyKey::new("dup-key-test");

        // Re-key batch 0 to carry the key, then re-hash so it's well-formed.
        let mut batch_a = leader[0].clone();
        batch_a.idempotency_key = Some(key.clone());
        let hash_a = hash_commit_material(&batch_a).unwrap();
        batch_a.commit_hash = Some(hash_a.clone());

        // Re-key batch 1 to carry the same key; rebuild its previous_hash
        // to chain off batch_a, then re-hash.
        let mut batch_b = leader[1].clone();
        batch_b.idempotency_key = Some(key.clone());
        batch_b.previous_hash = Some(hash_a);
        let hash_b = hash_commit_material(&batch_b).unwrap();
        batch_b.commit_hash = Some(hash_b);

        let mut follower = CommitLedger::new();
        follower.append_committed_batch(batch_a).unwrap();
        let err = follower
            .append_committed_batch(batch_b)
            .unwrap_err();
        assert!(matches!(err, HydraError::QueryError(_)));
        assert_eq!(follower.commit_count(), 1);
    }
}
