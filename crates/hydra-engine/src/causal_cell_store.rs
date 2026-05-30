//! Materialized CausalCell registry — Patch 20 store.
//!
//! Tiny passive store that mirrors `EventKind::CausalCellCreated`
//! into in-memory indexes:
//!
//! - `cells_by_id` — direct lookup
//! - `cells_by_kind` — keyed by `CausalCellKind::discriminant()`
//!   (a `String`, not the enum itself, so the `Custom(_)`
//!   variant doesn't need an `Ord` impl)
//! - `cells_by_tenant` — `None`-tenanted cells skip this index
//!
//! Rebuilt by `Hydra::recover_from_events` via `apply_event`;
//! restored from a snapshot body via direct insertion. Patch 20
//! ships only the create path — no update / link / close events
//! yet.

use hydra_core::{
    error::Result, CausalCell, CausalCellId, CausalCellKind, Event, EventKind,
    TenantId,
};
use std::collections::{BTreeSet, HashMap};

/// Materialized causal-cell state. Built from the event log;
/// survives restart via snapshot + replay (same lifecycle as
/// `ReplicationStore` and `MicroModelStore`).
#[derive(Debug, Clone, Default)]
pub struct CausalCellStore {
    cells_by_id: HashMap<CausalCellId, CausalCell>,
    cells_by_kind: HashMap<String, BTreeSet<CausalCellId>>,
    cells_by_tenant: HashMap<TenantId, BTreeSet<CausalCellId>>,
}

impl CausalCellStore {
    pub fn new() -> Self {
        Self::default()
    }

    // === Counts ===

    pub fn cell_count(&self) -> usize {
        self.cells_by_id.len()
    }

    // === Direct lookups ===

    pub fn cell(&self, id: &CausalCellId) -> Option<&CausalCell> {
        self.cells_by_id.get(id)
    }

    pub fn all_cells(&self) -> impl Iterator<Item = &CausalCell> {
        self.cells_by_id.values()
    }

    // === Indexed lookups ===

    /// All cells whose `kind` matches the given variant (via
    /// `kind.discriminant()`). Returns owned `Vec<&CausalCell>`
    /// so callers don't have to chain `.into_iter()` themselves
    /// — matches the `ReplicationStore::peers_with_role` shape.
    pub fn cells_with_kind(
        &self,
        kind: &CausalCellKind,
    ) -> Vec<&CausalCell> {
        let key = kind.discriminant();
        self.cells_by_kind
            .get(&key)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.cells_by_id.get(id))
            .collect()
    }

    /// All cells scoped to a given tenant. `None`-tenanted
    /// (system-wide) cells are NOT returned by this method —
    /// callers asking "for this tenant" want strict scoping.
    pub fn cells_for_tenant(&self, tenant: &TenantId) -> Vec<&CausalCell> {
        self.cells_by_tenant
            .get(tenant)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.cells_by_id.get(id))
            .collect()
    }

    // === Event ingest ===

    /// Apply one event. Patch 20's only relevant variant is
    /// `CausalCellCreated`; other variants are silently ignored
    /// — same pattern every other engine store follows so the
    /// event log can stream through many stores cheaply.
    pub fn apply_event(&mut self, event: &Event) -> Result<()> {
        if let EventKind::CausalCellCreated { cell } = &event.kind {
            self.insert_cell(cell.clone());
        }
        Ok(())
    }

    pub fn apply_events<'a>(
        &mut self,
        events: impl IntoIterator<Item = &'a Event>,
    ) -> Result<()> {
        for event in events {
            self.apply_event(event)?;
        }
        Ok(())
    }

    // === Snapshot restore ===

    /// Insert a cell directly (bypasses the event log). Used by
    /// `Hydra::restore_from_snapshot` to seed the store from a
    /// snapshot body's `causal_cells` vec without re-emitting
    /// `CausalCellCreated` events.
    pub fn insert_cell(&mut self, cell: CausalCell) {
        let id = cell.id.clone();
        // Idempotent on re-insert: replace the existing entry and
        // remove its old index entries before inserting fresh.
        if let Some(existing) = self.cells_by_id.remove(&id) {
            self.remove_indexes(&existing);
        }
        self.add_indexes(&cell);
        self.cells_by_id.insert(id, cell);
    }

    fn add_indexes(&mut self, cell: &CausalCell) {
        let key = cell.kind.discriminant();
        self.cells_by_kind
            .entry(key)
            .or_default()
            .insert(cell.id.clone());
        if let Some(tenant) = &cell.tenant_id {
            self.cells_by_tenant
                .entry(tenant.clone())
                .or_default()
                .insert(cell.id.clone());
        }
    }

    fn remove_indexes(&mut self, cell: &CausalCell) {
        let key = cell.kind.discriminant();
        if let Some(set) = self.cells_by_kind.get_mut(&key) {
            set.remove(&cell.id);
            if set.is_empty() {
                self.cells_by_kind.remove(&key);
            }
        }
        if let Some(tenant) = &cell.tenant_id {
            if let Some(set) = self.cells_by_tenant.get_mut(tenant) {
                set.remove(&cell.id);
                if set.is_empty() {
                    self.cells_by_tenant.remove(tenant);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{ActorId, CascadeId, EventId};

    fn event_of(kind: EventKind) -> Event {
        Event {
            id: EventId::new(),
            timestamp: chrono::Utc::now(),
            kind,
            caused_by: Vec::new(),
            cascade_id: CascadeId::new(),
            cascade_depth: 0,
            cascade_breadth_index: 0,
            tenant_id: None,
        }
    }

    fn cell_with(
        kind: CausalCellKind,
        subject: &str,
        tenant: Option<TenantId>,
    ) -> CausalCell {
        let mut cell = CausalCell::new(
            kind,
            subject,
            ActorId::from_str("actor_ops"),
        );
        cell.tenant_id = tenant;
        cell
    }

    #[test]
    fn apply_event_inserts_cell_into_store() {
        let mut store = CausalCellStore::new();
        assert_eq!(store.cell_count(), 0);
        let cell = cell_with(CausalCellKind::Reflex, "hydra.commit-rate", None);
        let cell_id = cell.id.clone();
        store
            .apply_event(&event_of(EventKind::CausalCellCreated {
                cell: cell.clone(),
            }))
            .unwrap();
        assert_eq!(store.cell_count(), 1);
        assert_eq!(store.cell(&cell_id), Some(&cell));
    }

    #[test]
    fn apply_event_ignores_unrelated_event_kinds() {
        // Every other store follows the silent-ignore pattern.
        // Pin that the causal cell store does the same.
        let mut store = CausalCellStore::new();
        let unrelated = event_of(EventKind::Signal {
            source: hydra_core::NodeId::from_str("test.signal"),
            name: "noise".to_string(),
            payload: std::collections::HashMap::new(),
        });
        store.apply_event(&unrelated).unwrap();
        assert_eq!(store.cell_count(), 0);
    }

    #[test]
    fn cells_with_kind_filters_correctly() {
        let mut store = CausalCellStore::new();
        let reflex_a =
            cell_with(CausalCellKind::Reflex, "hydra.commit-rate", None);
        let reflex_b =
            cell_with(CausalCellKind::Reflex, "hydra.replication", None);
        let incident =
            cell_with(CausalCellKind::Incident, "incident-1", None);
        store.insert_cell(reflex_a.clone());
        store.insert_cell(reflex_b.clone());
        store.insert_cell(incident.clone());

        let reflexes = store.cells_with_kind(&CausalCellKind::Reflex);
        assert_eq!(reflexes.len(), 2);
        let incidents = store.cells_with_kind(&CausalCellKind::Incident);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].subject, "incident-1");

        // Custom kinds index by their label — different labels are
        // distinct buckets.
        let custom_a =
            cell_with(CausalCellKind::Custom("alpha".into()), "x", None);
        let custom_b =
            cell_with(CausalCellKind::Custom("beta".into()), "y", None);
        store.insert_cell(custom_a.clone());
        store.insert_cell(custom_b.clone());
        let alpha = store
            .cells_with_kind(&CausalCellKind::Custom("alpha".into()));
        assert_eq!(alpha.len(), 1);
        assert_eq!(alpha[0].subject, "x");
    }

    #[test]
    fn cells_for_tenant_filters_strictly() {
        // Patch 20 spec: `None`-tenanted cells are NOT returned
        // by tenant queries. Operators asking "for this tenant"
        // want strict scoping.
        let mut store = CausalCellStore::new();
        let scoped = cell_with(
            CausalCellKind::Health,
            "tenant_a.health",
            Some(TenantId::from_str("ten_a")),
        );
        let unscoped = cell_with(
            CausalCellKind::Health,
            "system.health",
            None,
        );
        store.insert_cell(scoped.clone());
        store.insert_cell(unscoped.clone());

        let for_a = store.cells_for_tenant(&TenantId::from_str("ten_a"));
        assert_eq!(for_a.len(), 1);
        assert_eq!(for_a[0].id, scoped.id);

        let for_b = store.cells_for_tenant(&TenantId::from_str("ten_b"));
        assert!(for_b.is_empty());
    }

    #[test]
    fn insert_cell_is_idempotent_on_replay() {
        // Replay path may re-apply the same `CausalCellCreated`
        // event during recovery. Inserting the same id twice
        // must not double-count.
        let mut store = CausalCellStore::new();
        let cell = cell_with(CausalCellKind::Reflex, "x", None);
        store.insert_cell(cell.clone());
        store.insert_cell(cell.clone());
        assert_eq!(store.cell_count(), 1);
        assert_eq!(
            store.cells_with_kind(&CausalCellKind::Reflex).len(),
            1
        );
    }
}
