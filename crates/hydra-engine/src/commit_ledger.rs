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
}
