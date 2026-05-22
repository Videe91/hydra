use crate::event::{Event, Value};
use crate::id::{ActorId, CascadeId, CommitId, EventId, TenantId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Stable digest string for an event.
///
/// v0 keeps hashes as strings so the storage layer can choose the concrete
/// hash algorithm. The recommended default later is SHA-256 over canonical JSON.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventHash(pub String);

impl EventHash {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

/// Stable digest string for a commit.
///
/// Commit hashes should eventually cover:
/// - commit id
/// - sequence number
/// - previous commit hash
/// - event hashes
/// - metadata
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitHash(pub String);

impl CommitHash {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

/// Client-provided idempotency key.
///
/// This lets external callers safely retry an ingest without duplicating
/// effects. The engine/storage layer can map a key to the original CommitId.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdempotencyKey(pub String);

impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

/// Commit lifecycle.
///
/// v0 mostly uses Committed. Pending/Aborted are included so future storage
/// engines can model two-phase or WAL-backed commit protocols.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CommitStatus {
    Pending,
    Committed,
    Aborted,
}

/// Digest metadata for a single event included in a commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventCommitRecord {
    pub event_id: EventId,
    pub event_hash: EventHash,
    pub cascade_id: CascadeId,
    pub cascade_depth: u32,
    pub cascade_breadth_index: u32,
}

/// Atomic batch of events produced by one ingest/cascade.
///
/// This is the core DB-grade durability primitive:
/// all events in a cascade should eventually be persisted as one commit batch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitBatch {
    pub id: CommitId,
    pub tenant_id: Option<TenantId>,
    /// Monotonic sequence number assigned by the durable ledger.
    pub sequence: u64,
    /// Hash of the previous committed batch.
    pub previous_hash: Option<CommitHash>,
    /// Hash of this commit batch.
    pub commit_hash: Option<CommitHash>,
    /// Optional idempotency key supplied by client/runtime.
    pub idempotency_key: Option<IdempotencyKey>,
    /// All events included in the atomic batch.
    pub events: Vec<Event>,
    /// Event-level hash records.
    pub event_records: Vec<EventCommitRecord>,
    pub status: CommitStatus,
    pub committed_by: Option<ActorId>,
    pub committed_at: DateTime<Utc>,
    /// Free structured metadata for storage engines, sensors, APIs, etc.
    pub metadata: HashMap<String, Value>,
}

impl CommitBatch {
    pub fn new(events: Vec<Event>) -> Self {
        Self {
            id: CommitId::new(),
            tenant_id: events.first().and_then(|event| event.tenant_id.clone()),
            sequence: 0,
            previous_hash: None,
            commit_hash: None,
            idempotency_key: None,
            event_records: Vec::new(),
            events,
            status: CommitStatus::Pending,
            committed_by: None,
            committed_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_sequence(mut self, sequence: u64) -> Self {
        self.sequence = sequence;
        self
    }

    pub fn with_previous_hash(mut self, previous_hash: Option<CommitHash>) -> Self {
        self.previous_hash = previous_hash;
        self
    }

    pub fn with_commit_hash(mut self, commit_hash: CommitHash) -> Self {
        self.commit_hash = Some(commit_hash);
        self
    }

    pub fn with_idempotency_key(mut self, key: IdempotencyKey) -> Self {
        self.idempotency_key = Some(key);
        self
    }

    pub fn mark_committed(mut self, committed_by: Option<ActorId>) -> Self {
        self.status = CommitStatus::Committed;
        self.committed_by = committed_by;
        self.committed_at = Utc::now();
        self
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn first_event_id(&self) -> Option<&EventId> {
        self.events.first().map(|event| &event.id)
    }

    pub fn last_event_id(&self) -> Option<&EventId> {
        self.events.last().map(|event| &event.id)
    }

    pub fn cascade_id(&self) -> Option<&CascadeId> {
        self.events.first().map(|event| &event.cascade_id)
    }

    pub fn is_committed(&self) -> bool {
        self.status == CommitStatus::Committed
    }
}

/// Persisted commit record without requiring callers to load full event bodies.
///
/// This is useful for indexes, integrity verification, and sync metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitRecord {
    pub id: CommitId,
    pub tenant_id: Option<TenantId>,
    pub sequence: u64,
    pub previous_hash: Option<CommitHash>,
    pub commit_hash: CommitHash,
    pub idempotency_key: Option<IdempotencyKey>,
    pub event_count: usize,
    pub first_event_id: Option<EventId>,
    pub last_event_id: Option<EventId>,
    pub cascade_id: Option<CascadeId>,
    pub status: CommitStatus,
    pub committed_by: Option<ActorId>,
    pub committed_at: DateTime<Utc>,
    pub metadata: HashMap<String, Value>,
}

impl TryFrom<&CommitBatch> for CommitRecord {
    type Error = &'static str;

    fn try_from(batch: &CommitBatch) -> Result<Self, Self::Error> {
        let Some(commit_hash) = batch.commit_hash.clone() else {
            return Err("commit batch has no commit_hash");
        };
        Ok(Self {
            id: batch.id.clone(),
            tenant_id: batch.tenant_id.clone(),
            sequence: batch.sequence,
            previous_hash: batch.previous_hash.clone(),
            commit_hash,
            idempotency_key: batch.idempotency_key.clone(),
            event_count: batch.event_count(),
            first_event_id: batch.first_event_id().cloned(),
            last_event_id: batch.last_event_id().cloned(),
            cascade_id: batch.cascade_id().cloned(),
            status: batch.status.clone(),
            committed_by: batch.committed_by.clone(),
            committed_at: batch.committed_at,
            metadata: batch.metadata.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventKind};

    fn actor() -> ActorId {
        ActorId::from_str("actor_commit_test")
    }

    #[test]
    fn commit_batch_tracks_events_and_status() {
        let event = Event::trigger(EventKind::Signal {
            source: crate::NodeId::from_str("test"),
            name: "commit_test".to_string(),
            payload: HashMap::new(),
        });
        let event_id = event.id.clone();
        let cascade_id = event.cascade_id.clone();

        let batch = CommitBatch::new(vec![event])
            .with_sequence(7)
            .with_previous_hash(Some(CommitHash::new("prev")))
            .with_commit_hash(CommitHash::new("hash"))
            .with_idempotency_key(IdempotencyKey::new("idem-1"))
            .mark_committed(Some(actor()));

        assert_eq!(batch.sequence, 7);
        assert_eq!(batch.event_count(), 1);
        assert_eq!(batch.first_event_id(), Some(&event_id));
        assert_eq!(batch.last_event_id(), Some(&event_id));
        assert_eq!(batch.cascade_id(), Some(&cascade_id));
        assert!(batch.is_committed());
        assert_eq!(batch.committed_by, Some(actor()));
    }

    #[test]
    fn commit_record_requires_commit_hash() {
        let event = Event::trigger(EventKind::Signal {
            source: crate::NodeId::from_str("test"),
            name: "commit_test".to_string(),
            payload: HashMap::new(),
        });
        let batch = CommitBatch::new(vec![event]);
        assert!(CommitRecord::try_from(&batch).is_err());
    }

    #[test]
    fn commit_record_from_batch() {
        let event = Event::trigger(EventKind::Signal {
            source: crate::NodeId::from_str("test"),
            name: "commit_test".to_string(),
            payload: HashMap::new(),
        });
        let event_id = event.id.clone();
        let cascade_id = event.cascade_id.clone();
        let batch = CommitBatch::new(vec![event])
            .with_sequence(1)
            .with_commit_hash(CommitHash::new("hash-1"))
            .mark_committed(Some(actor()));

        let record = CommitRecord::try_from(&batch).unwrap();
        assert_eq!(record.sequence, 1);
        assert_eq!(record.commit_hash, CommitHash::new("hash-1"));
        assert_eq!(record.event_count, 1);
        assert_eq!(record.first_event_id, Some(event_id.clone()));
        assert_eq!(record.last_event_id, Some(event_id));
        assert_eq!(record.cascade_id, Some(cascade_id));
        assert_eq!(record.status, CommitStatus::Committed);
    }

    #[test]
    fn commit_serde_roundtrip() {
        let event = Event::trigger(EventKind::Signal {
            source: crate::NodeId::from_str("test"),
            name: "commit_test".to_string(),
            payload: HashMap::new(),
        });
        let batch = CommitBatch::new(vec![event])
            .with_sequence(42)
            .with_previous_hash(Some(CommitHash::new("prev")))
            .with_commit_hash(CommitHash::new("hash"))
            .with_idempotency_key(IdempotencyKey::new("idem"))
            .mark_committed(Some(actor()));

        let json = serde_json::to_string(&batch).unwrap();
        let restored: CommitBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(batch, restored);
    }
}
