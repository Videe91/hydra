use crate::backend::{Snapshot, StorageBackend};
use hydra_core::event::Event;
use hydra_core::id::{CascadeId, EventId, TenantId};
use std::collections::HashMap;

/// In-memory storage backend. Perfect for testing — no disk I/O, no setup.
/// All data lives in HashMaps and is lost when the backend is dropped.
pub struct MemoryBackend {
    /// TenantId → ordered list of events
    events: HashMap<String, Vec<Event>>,
    /// TenantId → latest snapshot
    snapshots: HashMap<String, Snapshot>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            events: HashMap::new(),
            snapshots: HashMap::new(),
        }
    }

    fn tenant_key(tenant_id: &TenantId) -> String {
        tenant_id.as_str().to_string()
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for MemoryBackend {
    fn append_events(
        &mut self,
        tenant_id: &TenantId,
        events: &[Event],
    ) -> hydra_core::error::Result<()> {
        let key = Self::tenant_key(tenant_id);
        let log = self.events.entry(key).or_default();
        log.extend(events.iter().cloned());
        Ok(())
    }

    fn read_events(
        &self,
        tenant_id: &TenantId,
    ) -> hydra_core::error::Result<Vec<Event>> {
        let key = Self::tenant_key(tenant_id);
        Ok(self.events.get(&key).cloned().unwrap_or_default())
    }

    fn read_events_after(
        &self,
        tenant_id: &TenantId,
        after: &EventId,
    ) -> hydra_core::error::Result<Vec<Event>> {
        let key = Self::tenant_key(tenant_id);
        let events = self.events.get(&key).cloned().unwrap_or_default();

        // Find the position of the 'after' event, return everything after it
        let pos = events.iter().position(|e| &e.id == after);
        match pos {
            Some(idx) => Ok(events[idx + 1..].to_vec()),
            None => Ok(events), // If not found, return all (defensive)
        }
    }

    fn read_cascade_events(
        &self,
        tenant_id: &TenantId,
        cascade_id: &CascadeId,
    ) -> hydra_core::error::Result<Vec<Event>> {
        let key = Self::tenant_key(tenant_id);
        let events = self.events.get(&key).cloned().unwrap_or_default();
        Ok(events
            .into_iter()
            .filter(|e| &e.cascade_id == cascade_id)
            .collect())
    }

    fn save_snapshot(
        &mut self,
        snapshot: Snapshot,
    ) -> hydra_core::error::Result<()> {
        let key = snapshot.tenant_id.as_str().to_string();
        self.snapshots.insert(key, snapshot);
        Ok(())
    }

    fn load_latest_snapshot(
        &self,
        tenant_id: &TenantId,
    ) -> hydra_core::error::Result<Option<Snapshot>> {
        let key = Self::tenant_key(tenant_id);
        Ok(self.snapshots.get(&key).cloned())
    }

    fn event_count(&self, tenant_id: &TenantId) -> hydra_core::error::Result<u64> {
        let key = Self::tenant_key(tenant_id);
        Ok(self.events.get(&key).map(|v| v.len() as u64).unwrap_or(0))
    }

    fn list_tenants(&self) -> hydra_core::error::Result<Vec<TenantId>> {
        Ok(self
            .events
            .keys()
            .map(|k| TenantId::from_str(k))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::{Event, EventKind};
    use hydra_core::id::{NodeId, SnapshotId, TenantId};
    use std::collections::HashMap;

    fn tenant() -> TenantId {
        TenantId::from_str("ten_TEST")
    }

    fn make_event(type_id: &str) -> Event {
        Event::trigger(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: type_id.to_string(),
            properties: HashMap::new(),
        })
    }

    #[test]
    fn append_and_read() {
        let mut backend = MemoryBackend::new();
        let t = tenant();

        let e1 = make_event("ec2");
        let e2 = make_event("rds");
        backend.append_events(&t, &[e1.clone(), e2.clone()]).unwrap();

        let events = backend.read_events(&t).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, e1.id);
        assert_eq!(events[1].id, e2.id);
    }

    #[test]
    fn read_events_after() {
        let mut backend = MemoryBackend::new();
        let t = tenant();

        let e1 = make_event("ec2");
        let e2 = make_event("rds");
        let e3 = make_event("s3");
        let e1_id = e1.id.clone();

        backend.append_events(&t, &[e1, e2, e3]).unwrap();

        let after = backend.read_events_after(&t, &e1_id).unwrap();
        assert_eq!(after.len(), 2); // e2 and e3
    }

    #[test]
    fn read_cascade_events() {
        let mut backend = MemoryBackend::new();
        let t = tenant();

        let trigger = make_event("ec2");
        let cascade_id = trigger.cascade_id.clone();
        let reaction = Event::reaction(
            EventKind::NodeUpdated {
                node_id: NodeId::new(),
                changes: HashMap::new(),
            },
            &trigger,
        );
        let unrelated = make_event("rds"); // Different cascade

        backend
            .append_events(&t, &[trigger, reaction, unrelated])
            .unwrap();

        let cascade = backend.read_cascade_events(&t, &cascade_id).unwrap();
        assert_eq!(cascade.len(), 2);
    }

    #[test]
    fn event_count() {
        let mut backend = MemoryBackend::new();
        let t = tenant();

        assert_eq!(backend.event_count(&t).unwrap(), 0);
        backend.append_events(&t, &[make_event("ec2")]).unwrap();
        assert_eq!(backend.event_count(&t).unwrap(), 1);
        backend
            .append_events(&t, &[make_event("rds"), make_event("s3")])
            .unwrap();
        assert_eq!(backend.event_count(&t).unwrap(), 3);
    }

    #[test]
    fn snapshot_save_and_load() {
        let mut backend = MemoryBackend::new();
        let t = tenant();

        assert!(backend.load_latest_snapshot(&t).unwrap().is_none());

        let snap = Snapshot {
            id: SnapshotId::new(),
            tenant_id: t.clone(),
            timestamp: chrono::Utc::now(),
            data: vec![1, 2, 3, 4],
            after_event: hydra_core::id::EventId::from_str("evt_SNAP"),
            event_count: 100,
        };

        backend.save_snapshot(snap.clone()).unwrap();
        let loaded = backend.load_latest_snapshot(&t).unwrap().unwrap();
        assert_eq!(loaded.data, vec![1, 2, 3, 4]);
        assert_eq!(loaded.event_count, 100);
    }

    #[test]
    fn multi_tenant_isolation() {
        let mut backend = MemoryBackend::new();
        let t1 = TenantId::from_str("ten_A");
        let t2 = TenantId::from_str("ten_B");

        backend.append_events(&t1, &[make_event("ec2")]).unwrap();
        backend
            .append_events(&t2, &[make_event("rds"), make_event("s3")])
            .unwrap();

        assert_eq!(backend.event_count(&t1).unwrap(), 1);
        assert_eq!(backend.event_count(&t2).unwrap(), 2);
        assert_eq!(backend.read_events(&t1).unwrap().len(), 1);
        assert_eq!(backend.read_events(&t2).unwrap().len(), 2);
    }

    #[test]
    fn list_tenants() {
        let mut backend = MemoryBackend::new();
        let t1 = TenantId::from_str("ten_A");
        let t2 = TenantId::from_str("ten_B");

        backend.append_events(&t1, &[make_event("ec2")]).unwrap();
        backend.append_events(&t2, &[make_event("rds")]).unwrap();

        let tenants = backend.list_tenants().unwrap();
        assert_eq!(tenants.len(), 2);
    }

    #[test]
    fn empty_tenant_returns_empty() {
        let backend = MemoryBackend::new();
        let t = TenantId::from_str("ten_NOBODY");

        assert_eq!(backend.read_events(&t).unwrap().len(), 0);
        assert_eq!(backend.event_count(&t).unwrap(), 0);
        assert!(backend.load_latest_snapshot(&t).unwrap().is_none());
    }
}
