use hydra_core::event::Event;
use hydra_core::id::{CascadeId, EventId, SnapshotId, TenantId};

/// A snapshot of the graph state at a point in time.
/// Used for compaction — instead of replaying 100K events,
/// load the last snapshot and replay only events after it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    pub id: SnapshotId,
    pub tenant_id: TenantId,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// The serialized projection state
    pub data: Vec<u8>,
    /// The event ID this snapshot was taken after
    pub after_event: EventId,
    /// How many events were compacted into this snapshot
    pub event_count: u64,
}

/// The storage backend trait. All persistence operations go through this.
///
/// Implementations:
/// - MemoryBackend: for testing (stores everything in-memory)
/// - FileBackend: NDJSON file per tenant (for local dev / single-node)
/// - (Future) S3Backend, PostgresBackend, etc.
///
/// All methods are synchronous. Async wrapping happens at the hydra-net layer.
pub trait StorageBackend: Send + Sync {
    /// Append events to the log for a tenant
    fn append_events(
        &mut self,
        tenant_id: &TenantId,
        events: &[Event],
    ) -> hydra_core::error::Result<()>;

    /// Read all events for a tenant, in order
    fn read_events(
        &self,
        tenant_id: &TenantId,
    ) -> hydra_core::error::Result<Vec<Event>>;

    /// Read events after a specific event ID (for incremental replay)
    fn read_events_after(
        &self,
        tenant_id: &TenantId,
        after: &EventId,
    ) -> hydra_core::error::Result<Vec<Event>>;

    /// Read events belonging to a specific cascade
    fn read_cascade_events(
        &self,
        tenant_id: &TenantId,
        cascade_id: &CascadeId,
    ) -> hydra_core::error::Result<Vec<Event>>;

    /// Save a snapshot
    fn save_snapshot(
        &mut self,
        snapshot: Snapshot,
    ) -> hydra_core::error::Result<()>;

    /// Load the latest snapshot for a tenant
    fn load_latest_snapshot(
        &self,
        tenant_id: &TenantId,
    ) -> hydra_core::error::Result<Option<Snapshot>>;

    /// Total event count for a tenant
    fn event_count(&self, tenant_id: &TenantId) -> hydra_core::error::Result<u64>;

    /// List all tenant IDs that have data
    fn list_tenants(&self) -> hydra_core::error::Result<Vec<TenantId>>;
}
