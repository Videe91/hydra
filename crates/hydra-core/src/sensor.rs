use crate::commit::IdempotencyKey;
use crate::event::Value;
use crate::id::{
    ActorId, CommitId, EventId, SensorCheckpointId, SensorId, SensorRunId, TenantId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// External source cursor for reliable ingestion.
///
/// This is intentionally generic so it can model:
/// - Kafka topic/partition/offset
/// - Kinesis stream/shard/sequence number
/// - S3 bucket/key/version
/// - GitHub event delivery id
/// - bank feed cursor
/// - payroll provider cursor
/// - webhook delivery id
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceCursor {
    Offset {
        stream: String,
        partition: Option<String>,
        offset: String,
    },
    Sequence {
        stream: String,
        shard: Option<String>,
        sequence: String,
    },
    ObjectVersion {
        bucket: String,
        key: String,
        version: Option<String>,
    },
    DeliveryId {
        source: String,
        delivery_id: String,
    },
    Timestamp {
        source: String,
        timestamp: DateTime<Utc>,
    },
    Custom {
        source: String,
        value: String,
    },
}

impl SourceCursor {
    pub fn source_name(&self) -> &str {
        match self {
            SourceCursor::Offset { stream, .. } => stream,
            SourceCursor::Sequence { stream, .. } => stream,
            SourceCursor::ObjectVersion { bucket, .. } => bucket,
            SourceCursor::DeliveryId { source, .. } => source,
            SourceCursor::Timestamp { source, .. } => source,
            SourceCursor::Custom { source, .. } => source,
        }
    }

    /// Stable string suitable for deriving idempotency keys.
    pub fn stable_key_material(&self) -> String {
        match self {
            SourceCursor::Offset {
                stream,
                partition,
                offset,
            } => format!(
                "offset:{}:{}:{}",
                stream,
                partition.clone().unwrap_or_default(),
                offset
            ),
            SourceCursor::Sequence {
                stream,
                shard,
                sequence,
            } => format!(
                "sequence:{}:{}:{}",
                stream,
                shard.clone().unwrap_or_default(),
                sequence
            ),
            SourceCursor::ObjectVersion {
                bucket,
                key,
                version,
            } => format!(
                "object:{}:{}:{}",
                bucket,
                key,
                version.clone().unwrap_or_default()
            ),
            SourceCursor::DeliveryId {
                source,
                delivery_id,
            } => format!("delivery:{}:{}", source, delivery_id),
            SourceCursor::Timestamp { source, timestamp } => {
                format!("timestamp:{}:{}", source, timestamp.to_rfc3339())
            }
            SourceCursor::Custom { source, value } => format!("custom:{}:{}", source, value),
        }
    }
}

/// Sensor run lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensorRunStatus {
    Started,
    Completed,
    Failed,
}

/// Checkpoint lifecycle.
///
/// Recorded means the checkpoint was durably captured after a successful ingest.
/// Superseded is reserved for future compaction / checkpoint consolidation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensorCheckpointStatus {
    Recorded,
    Superseded,
}

/// A single external ingestion run.
///
/// A run can cover one message, a micro-batch, or a polling cycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensorRun {
    pub id: SensorRunId,
    pub tenant_id: Option<TenantId>,
    pub sensor_id: SensorId,
    pub status: SensorRunStatus,
    pub source_system: String,
    pub stream: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub failed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub actor_id: Option<ActorId>,
    pub metadata: HashMap<String, Value>,
}

/// Durable checkpoint for an external sensor/source.
///
/// The critical invariant:
///
/// The checkpoint should only advance after the corresponding CommitBatch has
/// been accepted by Hydra. This makes external ingestion safely resumable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensorCheckpoint {
    pub id: SensorCheckpointId,
    pub tenant_id: Option<TenantId>,
    pub sensor_id: SensorId,
    pub run_id: Option<SensorRunId>,
    pub status: SensorCheckpointStatus,
    pub source_system: String,
    pub cursor: SourceCursor,
    /// Stable idempotency key used for the ingest associated with this cursor.
    pub idempotency_key: IdempotencyKey,
    /// Commit accepted by Hydra for this observed cursor.
    pub commit_id: CommitId,
    /// Optional first/representative event committed from this observation.
    pub event_id: Option<EventId>,
    pub observed_at: DateTime<Utc>,
    pub recorded_at: DateTime<Utc>,
    pub metadata: HashMap<String, Value>,
}

impl SensorCheckpoint {
    pub fn new(
        sensor_id: SensorId,
        source_system: impl Into<String>,
        cursor: SourceCursor,
        idempotency_key: IdempotencyKey,
        commit_id: CommitId,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: SensorCheckpointId::new(),
            tenant_id: None,
            sensor_id,
            run_id: None,
            status: SensorCheckpointStatus::Recorded,
            source_system: source_system.into(),
            cursor,
            idempotency_key,
            commit_id,
            event_id: None,
            observed_at: now,
            recorded_at: now,
            metadata: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{CommitId, SensorId};

    #[test]
    fn source_cursor_stable_key_material_for_offset() {
        let cursor = SourceCursor::Offset {
            stream: "bank-feed".to_string(),
            partition: Some("account-1".to_string()),
            offset: "42".to_string(),
        };
        assert_eq!(cursor.source_name(), "bank-feed");
        assert_eq!(
            cursor.stable_key_material(),
            "offset:bank-feed:account-1:42"
        );
    }

    #[test]
    fn source_cursor_stable_key_material_for_delivery() {
        let cursor = SourceCursor::DeliveryId {
            source: "stripe".to_string(),
            delivery_id: "evt_123".to_string(),
        };
        assert_eq!(cursor.source_name(), "stripe");
        assert_eq!(cursor.stable_key_material(), "delivery:stripe:evt_123");
    }

    #[test]
    fn sensor_checkpoint_new_defaults_to_recorded() {
        let cursor = SourceCursor::Custom {
            source: "test".to_string(),
            value: "cursor-1".to_string(),
        };
        let checkpoint = SensorCheckpoint::new(
            SensorId::from_str("sensor_test"),
            "test",
            cursor,
            IdempotencyKey::new("idem-1"),
            CommitId::new(),
        );
        assert_eq!(checkpoint.status, SensorCheckpointStatus::Recorded);
        assert_eq!(checkpoint.source_system, "test");
        assert!(checkpoint.run_id.is_none());
        assert!(checkpoint.event_id.is_none());
    }

    #[test]
    fn sensor_run_serde_roundtrip() {
        let now = Utc::now();
        let run = SensorRun {
            id: SensorRunId::new(),
            tenant_id: None,
            sensor_id: SensorId::from_str("sensor_bank"),
            status: SensorRunStatus::Started,
            source_system: "bank-feed".to_string(),
            stream: Some("checking".to_string()),
            started_at: now,
            completed_at: None,
            failed_at: None,
            error: None,
            actor_id: None,
            metadata: HashMap::new(),
        };
        let json = serde_json::to_string(&run).unwrap();
        let restored: SensorRun = serde_json::from_str(&json).unwrap();
        assert_eq!(run, restored);
    }

    #[test]
    fn sensor_checkpoint_serde_roundtrip() {
        let checkpoint = SensorCheckpoint::new(
            SensorId::from_str("sensor_webhook"),
            "github",
            SourceCursor::DeliveryId {
                source: "github".to_string(),
                delivery_id: "delivery-1".to_string(),
            },
            IdempotencyKey::new("github-delivery-1"),
            CommitId::new(),
        );
        let json = serde_json::to_string(&checkpoint).unwrap();
        let restored: SensorCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(checkpoint, restored);
    }
}
