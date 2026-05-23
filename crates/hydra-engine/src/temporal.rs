use hydra_core::event::{Event, EventKind, Value};
use hydra_core::id::{EdgeId, EventId, NodeId};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// A snapshot of a single property at a point in time.
/// This is the core unit of temporal storage — one per property change.
#[derive(Debug, Clone)]
pub struct PropertyVersion {
    /// When this version became effective
    pub effective_from: DateTime<Utc>,
    /// When this version was superseded (None = current)
    pub effective_until: Option<DateTime<Utc>>,
    /// The value at this point in time (None = property didn't exist / was removed)
    pub value: Option<Value>,
    /// Which event caused this version
    pub caused_by: EventId,
}

/// Tracks the alive/dead status over time for a node or edge.
#[derive(Debug, Clone)]
pub struct LifecycleVersion {
    pub effective_from: DateTime<Utc>,
    pub effective_until: Option<DateTime<Utc>>,
    pub alive: bool,
    pub caused_by: EventId,
}

/// Temporal history for a single node.
/// Properties are tracked independently — only changed properties get new versions.
#[derive(Debug, Clone)]
pub struct NodeHistory {
    pub node_id: NodeId,
    pub type_id: String,
    /// Per-property version chains, sorted by effective_from ascending
    pub properties: HashMap<String, Vec<PropertyVersion>>,
    /// Alive/dead lifecycle, sorted by effective_from ascending
    pub lifecycle: Vec<LifecycleVersion>,
}

impl NodeHistory {
    fn new(node_id: NodeId, type_id: String, timestamp: DateTime<Utc>, event_id: EventId) -> Self {
        Self {
            node_id,
            type_id,
            properties: HashMap::new(),
            lifecycle: vec![LifecycleVersion {
                effective_from: timestamp,
                effective_until: None,
                alive: true,
                caused_by: event_id,
            }],
        }
    }

    /// Record a property change
    fn set_property(
        &mut self,
        key: &str,
        value: Value,
        timestamp: DateTime<Utc>,
        event_id: EventId,
    ) {
        let versions = self.properties.entry(key.to_string()).or_default();

        // Close the current version
        if let Some(last) = versions.last_mut() {
            if last.effective_until.is_none() {
                last.effective_until = Some(timestamp);
            }
        }

        // Add new version
        versions.push(PropertyVersion {
            effective_from: timestamp,
            effective_until: None,
            value: Some(value),
            caused_by: event_id,
        });
    }

    /// Record creation with initial properties
    fn record_creation(
        &mut self,
        properties: &HashMap<String, Value>,
        timestamp: DateTime<Utc>,
        event_id: &EventId,
    ) {
        for (key, value) in properties {
            self.set_property(key, value.clone(), timestamp, event_id.clone());
        }
    }

    /// Record property updates
    fn record_update(
        &mut self,
        changes: &HashMap<String, Value>,
        timestamp: DateTime<Utc>,
        event_id: &EventId,
    ) {
        for (key, value) in changes {
            self.set_property(key, value.clone(), timestamp, event_id.clone());
        }
    }

    /// Record deletion
    fn record_deletion(&mut self, timestamp: DateTime<Utc>, event_id: &EventId) {
        // Close the current lifecycle version
        if let Some(last) = self.lifecycle.last_mut() {
            if last.effective_until.is_none() {
                last.effective_until = Some(timestamp);
            }
        }

        self.lifecycle.push(LifecycleVersion {
            effective_from: timestamp,
            effective_until: None,
            alive: false,
            caused_by: event_id.clone(),
        });
    }

    /// Get the value of a property at a specific point in time.
    /// Returns None if the property didn't exist at that time.
    pub fn property_at(&self, key: &str, at: DateTime<Utc>) -> Option<&Value> {
        let versions = self.properties.get(key)?;

        // Binary search: find the last version where effective_from <= at.
        // partition_point returns the first index where the predicate is false,
        // so idx-1 is the last version where effective_from <= at.
        let idx = versions.partition_point(|v| v.effective_from <= at);
        if idx == 0 {
            return None; // Before any version
        }

        // Return the value from the latest applicable version.
        // This handles the edge case where multiple versions have the same
        // effective_from timestamp — partition_point finds the last one.
        versions[idx - 1].value.as_ref()
    }

    /// Was this node alive at a specific point in time?
    pub fn alive_at(&self, at: DateTime<Utc>) -> bool {
        let idx = self.lifecycle.partition_point(|v| v.effective_from <= at);
        if idx == 0 {
            return false; // Before creation
        }
        self.lifecycle[idx - 1].alive
    }

    /// Get all properties at a specific point in time
    pub fn state_at(&self, at: DateTime<Utc>) -> HashMap<String, Value> {
        let mut state = HashMap::new();
        for (key, _versions) in &self.properties {
            if let Some(value) = self.property_at(key, at) {
                state.insert(key.clone(), value.clone());
            }
        }
        state
    }

    /// Get the history of a specific property over time as a time series.
    /// Returns (timestamp, value) pairs in chronological order.
    pub fn trend(&self, key: &str) -> Vec<(DateTime<Utc>, Value)> {
        let versions = match self.properties.get(key) {
            Some(v) => v,
            None => return Vec::new(),
        };

        versions
            .iter()
            .filter_map(|v| v.value.as_ref().map(|val| (v.effective_from, val.clone())))
            .collect()
    }

    /// Total number of versions across all properties
    pub fn version_count(&self) -> usize {
        self.properties.values().map(|v| v.len()).sum::<usize>()
            + self.lifecycle.len()
    }
}

/// Temporal history for a single edge (same structure as node).
#[derive(Debug, Clone)]
pub struct EdgeHistory {
    pub edge_id: EdgeId,
    pub type_id: String,
    pub source: NodeId,
    pub target: NodeId,
    pub properties: HashMap<String, Vec<PropertyVersion>>,
    pub lifecycle: Vec<LifecycleVersion>,
}

impl EdgeHistory {
    fn new(
        edge_id: EdgeId,
        type_id: String,
        source: NodeId,
        target: NodeId,
        timestamp: DateTime<Utc>,
        event_id: EventId,
    ) -> Self {
        Self {
            edge_id,
            type_id,
            source,
            target,
            properties: HashMap::new(),
            lifecycle: vec![LifecycleVersion {
                effective_from: timestamp,
                effective_until: None,
                alive: true,
                caused_by: event_id,
            }],
        }
    }

    fn record_creation(
        &mut self,
        properties: &HashMap<String, Value>,
        timestamp: DateTime<Utc>,
        event_id: &EventId,
    ) {
        for (key, value) in properties {
            let versions = self.properties.entry(key.clone()).or_default();
            versions.push(PropertyVersion {
                effective_from: timestamp,
                effective_until: None,
                value: Some(value.clone()),
                caused_by: event_id.clone(),
            });
        }
    }

    fn record_update(
        &mut self,
        changes: &HashMap<String, Value>,
        timestamp: DateTime<Utc>,
        event_id: &EventId,
    ) {
        for (key, value) in changes {
            let versions = self.properties.entry(key.clone()).or_default();
            if let Some(last) = versions.last_mut() {
                if last.effective_until.is_none() {
                    last.effective_until = Some(timestamp);
                }
            }
            versions.push(PropertyVersion {
                effective_from: timestamp,
                effective_until: None,
                value: Some(value.clone()),
                caused_by: event_id.clone(),
            });
        }
    }

    fn record_deletion(&mut self, timestamp: DateTime<Utc>, event_id: &EventId) {
        if let Some(last) = self.lifecycle.last_mut() {
            if last.effective_until.is_none() {
                last.effective_until = Some(timestamp);
            }
        }
        self.lifecycle.push(LifecycleVersion {
            effective_from: timestamp,
            effective_until: None,
            alive: false,
            caused_by: event_id.clone(),
        });
    }

    /// Was this edge alive at a specific point in time?
    pub fn alive_at(&self, at: DateTime<Utc>) -> bool {
        let idx = self.lifecycle.partition_point(|v| v.effective_from <= at);
        if idx == 0 {
            return false;
        }
        self.lifecycle[idx - 1].alive
    }

    pub fn version_count(&self) -> usize {
        self.properties.values().map(|v| v.len()).sum::<usize>()
            + self.lifecycle.len()
    }
}

/// The Temporal Index. Records every mutation as a versioned entry.
/// Sits alongside the Projection — the Projection is the "current state" fast path,
/// the TemporalIndex is the "history" query path.
///
/// Not embedded in Projection to avoid polluting the counterfactual replay path
/// (which doesn't need temporal history and would waste memory building it).
pub struct TemporalIndex {
    nodes: HashMap<NodeId, NodeHistory>,
    edges: HashMap<EdgeId, EdgeHistory>,
}

impl TemporalIndex {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
        }
    }

    /// Record an event in the temporal index.
    /// Called alongside Projection::apply() — same event stream, separate storage.
    /// Returns true if the event was temporally significant (created a version).
    pub fn record(&mut self, event: &Event) -> bool {
        match &event.kind {
            EventKind::NodeCreated {
                node_id,
                type_id,
                properties,
            } => {
                let mut history = NodeHistory::new(
                    node_id.clone(),
                    type_id.clone(),
                    event.timestamp,
                    event.id.clone(),
                );
                history.record_creation(properties, event.timestamp, &event.id);
                self.nodes.insert(node_id.clone(), history);
                true
            }

            EventKind::NodeUpdated { node_id, changes } => {
                if let Some(history) = self.nodes.get_mut(node_id) {
                    history.record_update(changes, event.timestamp, &event.id);
                    true
                } else {
                    false // Node not tracked (shouldn't happen)
                }
            }

            EventKind::NodeDeleted { node_id } => {
                if let Some(history) = self.nodes.get_mut(node_id) {
                    history.record_deletion(event.timestamp, &event.id);
                    true
                } else {
                    false
                }
            }

            EventKind::EdgeCreated {
                edge_id,
                source,
                target,
                type_id,
                properties,
            } => {
                let mut history = EdgeHistory::new(
                    edge_id.clone(),
                    type_id.clone(),
                    source.clone(),
                    target.clone(),
                    event.timestamp,
                    event.id.clone(),
                );
                history.record_creation(properties, event.timestamp, &event.id);
                self.edges.insert(edge_id.clone(), history);
                true
            }

            EventKind::EdgeUpdated { edge_id, changes } => {
                if let Some(history) = self.edges.get_mut(edge_id) {
                    history.record_update(changes, event.timestamp, &event.id);
                    true
                } else {
                    false
                }
            }

            EventKind::EdgeDeleted { edge_id } => {
                if let Some(history) = self.edges.get_mut(edge_id) {
                    history.record_deletion(event.timestamp, &event.id);
                    true
                } else {
                    false
                }
            }

            EventKind::Signal { .. }
            | EventKind::Snapshot { .. }
            | EventKind::EvidenceAdded { .. }
            | EventKind::ClaimProposed { .. }
            | EventKind::ClaimSupported { .. }
            | EventKind::ClaimDisputed { .. }
            | EventKind::ClaimVerified { .. }
            | EventKind::ClaimRetracted { .. }
            | EventKind::ClaimStaled { .. }
            | EventKind::TopologyCommittedFromClaim { .. }
            | EventKind::ActionProposed { .. }
            | EventKind::ActionApproved { .. }
            | EventKind::ActionRejected { .. }
            | EventKind::ActionExecuting { .. }
            | EventKind::ActionExecuted { .. }
            | EventKind::ActionFailed { .. }
            | EventKind::ActionCancelled { .. }
            | EventKind::OutcomeObserved { .. }
            | EventKind::PolicyRegistered { .. }
            | EventKind::PolicyDisabled { .. }
            | EventKind::PolicyDecisionRecorded { .. }
            | EventKind::ApprovalRequested { .. }
            | EventKind::ApprovalGranted { .. }
            | EventKind::ApprovalRejected { .. }
            | EventKind::ApprovalCancelled { .. }
            | EventKind::SensorRunStarted { .. }
            | EventKind::SensorRunCompleted { .. }
            | EventKind::SensorRunFailed { .. }
            | EventKind::SensorCheckpointRecorded { .. }
            | EventKind::SensorCheckpointSuperseded { .. }
            | EventKind::SchemaRegistered { .. }
            | EventKind::SchemaDisabled { .. }
            | EventKind::SchemaArchived { .. } => false,
        }
    }

    // === Node temporal queries ===

    /// Get a node's history
    pub fn node_history(&self, node_id: &NodeId) -> Option<&NodeHistory> {
        self.nodes.get(node_id)
    }

    /// Get a node's properties at a specific point in time
    pub fn node_state_at(
        &self,
        node_id: &NodeId,
        at: DateTime<Utc>,
    ) -> Option<HashMap<String, Value>> {
        let history = self.nodes.get(node_id)?;
        if !history.alive_at(at) {
            return None; // Node didn't exist or was deleted at this time
        }
        Some(history.state_at(at))
    }

    /// Was a node alive at a specific point in time?
    pub fn node_alive_at(&self, node_id: &NodeId, at: DateTime<Utc>) -> bool {
        self.nodes
            .get(node_id)
            .map(|h| h.alive_at(at))
            .unwrap_or(false)
    }

    /// Get the trend of a specific property over time
    pub fn node_trend(
        &self,
        node_id: &NodeId,
        property: &str,
    ) -> Vec<(DateTime<Utc>, Value)> {
        self.nodes
            .get(node_id)
            .map(|h| h.trend(property))
            .unwrap_or_default()
    }

    // === Edge temporal queries ===

    pub fn edge_history(&self, edge_id: &EdgeId) -> Option<&EdgeHistory> {
        self.edges.get(edge_id)
    }

    pub fn edge_alive_at(&self, edge_id: &EdgeId, at: DateTime<Utc>) -> bool {
        self.edges
            .get(edge_id)
            .map(|h| h.alive_at(at))
            .unwrap_or(false)
    }

    // === Graph-level temporal queries ===

    /// Diff the graph between two points in time.
    /// Returns which nodes/edges were added, removed, or changed.
    pub fn diff(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> TemporalDiff {
        let mut result = TemporalDiff {
            nodes_created: Vec::new(),
            nodes_deleted: Vec::new(),
            nodes_changed: Vec::new(),
            edges_created: Vec::new(),
            edges_deleted: Vec::new(),
            edges_changed: Vec::new(),
        };

        for (node_id, history) in &self.nodes {
            let alive_from = history.alive_at(from);
            let alive_to = history.alive_at(to);

            match (alive_from, alive_to) {
                (false, true) => result.nodes_created.push(node_id.clone()),
                (true, false) => result.nodes_deleted.push(node_id.clone()),
                (true, true) => {
                    // Check if properties changed between from and to
                    let state_from = history.state_at(from);
                    let state_to = history.state_at(to);
                    if state_from != state_to {
                        result.nodes_changed.push(TemporalNodeChange {
                            node_id: node_id.clone(),
                            type_id: history.type_id.clone(),
                            properties_before: state_from,
                            properties_after: state_to,
                        });
                    }
                }
                (false, false) => {} // Never existed in either window
            }
        }

        for (edge_id, history) in &self.edges {
            let alive_from = history.alive_at(from);
            let alive_to = history.alive_at(to);

            match (alive_from, alive_to) {
                (false, true) => result.edges_created.push(edge_id.clone()),
                (true, false) => result.edges_deleted.push(edge_id.clone()),
                (true, true) => {
                    // Check property changes between from and to
                    let mut changed = false;
                    for versions in history.properties.values() {
                        if versions.iter().any(|v| v.effective_from > from && v.effective_from <= to) {
                            changed = true;
                            break;
                        }
                    }
                    if changed {
                        result.edges_changed.push(edge_id.clone());
                    }
                }
                (false, false) => {}
            }
        }

        result
    }

    // === Diagnostics ===

    /// Total nodes with temporal history
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total edges with temporal history
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Total version entries across all nodes and edges
    pub fn total_versions(&self) -> usize {
        let node_versions: usize = self.nodes.values().map(|h| h.version_count()).sum();
        let edge_versions: usize = self.edges.values().map(|h| h.version_count()).sum();
        node_versions + edge_versions
    }

    /// Iterate all node histories (for batch anomaly detection)
    pub fn iter_nodes(&self) -> impl Iterator<Item = (&NodeId, &NodeHistory)> {
        self.nodes.iter()
    }

    /// Iterate all edge histories
    pub fn iter_edges(&self) -> impl Iterator<Item = (&EdgeId, &EdgeHistory)> {
        self.edges.iter()
    }

    /// Materialize the entire graph at a specific point in time.
    /// Returns a `TemporalGraphView` that implements `GraphReader`.
    pub fn graph_at(&self, at: DateTime<Utc>) -> TemporalGraphView {
        TemporalGraphView::at(self, at)
    }
}

impl Default for TemporalIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// The diff between two points in time
#[derive(Debug, Clone)]
pub struct TemporalDiff {
    pub nodes_created: Vec<NodeId>,
    pub nodes_deleted: Vec<NodeId>,
    pub nodes_changed: Vec<TemporalNodeChange>,
    pub edges_created: Vec<EdgeId>,
    pub edges_deleted: Vec<EdgeId>,
    pub edges_changed: Vec<EdgeId>,
}

impl TemporalDiff {
    pub fn is_empty(&self) -> bool {
        self.nodes_created.is_empty()
            && self.nodes_deleted.is_empty()
            && self.nodes_changed.is_empty()
            && self.edges_created.is_empty()
            && self.edges_deleted.is_empty()
            && self.edges_changed.is_empty()
    }

    pub fn total_changes(&self) -> usize {
        self.nodes_created.len()
            + self.nodes_deleted.len()
            + self.nodes_changed.len()
            + self.edges_created.len()
            + self.edges_deleted.len()
            + self.edges_changed.len()
    }
}

/// A specific node that changed between two points in time
#[derive(Debug, Clone)]
pub struct TemporalNodeChange {
    pub node_id: NodeId,
    pub type_id: String,
    pub properties_before: HashMap<String, Value>,
    pub properties_after: HashMap<String, Value>,
}

// ============================================================================
// TemporalGraphView — point-in-time GraphReader implementation
// ============================================================================

use hydra_core::edge::{Edge, EdgeMeta};
use hydra_core::graph::GraphReader;
use hydra_core::node::{Node, NodeMeta};
use std::collections::HashSet;

/// A materialized snapshot of the graph at a specific point in time.
/// Implements `GraphReader` so it can be used with BFS, blast radius,
/// and any other graph query that works on the current-state Projection.
///
/// Construction materializes all alive nodes/edges at the requested timestamp
/// into owned storage with topology indexes. Queries are then O(1) lookups.
///
/// Usage:
/// ```ignore
/// let view = TemporalGraphView::at(&temporal_index, timestamp);
/// let neighbors = view.outgoing_neighbors(&node_id);
/// let blast = bfs_dyn(&view, &start, TraversalDirection::Outgoing, &|_| true);
/// ```
pub struct TemporalGraphView {
    /// Materialized nodes at the target timestamp
    nodes: HashMap<NodeId, Node>,
    /// Materialized edges at the target timestamp
    edges: HashMap<EdgeId, Edge>,
    /// Type index: type_id → set of alive node IDs
    type_index: HashMap<String, HashSet<NodeId>>,
    /// Topology index: source node → set of alive edge IDs
    outgoing_index: HashMap<NodeId, HashSet<EdgeId>>,
    /// Topology index: target node → set of alive edge IDs
    incoming_index: HashMap<NodeId, HashSet<EdgeId>>,
    /// The timestamp this view represents
    pub as_of: DateTime<Utc>,
}

impl TemporalGraphView {
    /// Materialize the graph at a specific point in time.
    /// Iterates all node/edge histories in the temporal index and reconstructs
    /// those that were alive at `at` with their properties as of that moment.
    pub fn at(temporal: &TemporalIndex, at: DateTime<Utc>) -> Self {
        let mut nodes = HashMap::new();
        let mut edges = HashMap::new();
        let mut type_index: HashMap<String, HashSet<NodeId>> = HashMap::new();
        let mut outgoing_index: HashMap<NodeId, HashSet<EdgeId>> = HashMap::new();
        let mut incoming_index: HashMap<NodeId, HashSet<EdgeId>> = HashMap::new();

        // Materialize nodes
        for (node_id, history) in temporal.iter_nodes() {
            if !history.alive_at(at) {
                continue;
            }

            let properties = history.state_at(at);

            // Reconstruct the lifecycle timestamp for created_at:
            // find the first lifecycle entry (always the creation)
            let created_at = history
                .lifecycle
                .first()
                .map(|lc| lc.effective_from)
                .unwrap_or(at);

            let meta = NodeMeta {
                id: node_id.clone(),
                type_id: history.type_id.clone(),
                created_at,
                updated_at: at,
                version: history.version_count() as u64,
                alive: true,
            };

            let node = Node { meta, properties };
            type_index
                .entry(history.type_id.clone())
                .or_default()
                .insert(node_id.clone());
            nodes.insert(node_id.clone(), node);
        }

        // Materialize edges (only if both endpoints are alive)
        for (edge_id, history) in temporal.iter_edges() {
            if !history.alive_at(at) {
                continue;
            }

            // Only include if both endpoints are alive at this time
            if !nodes.contains_key(&history.source) || !nodes.contains_key(&history.target) {
                continue;
            }

            // Reconstruct edge properties at this timestamp
            let mut properties = HashMap::new();
            for (key, versions) in &history.properties {
                let idx = versions.partition_point(|v| v.effective_from <= at);
                if idx > 0 {
                    if let Some(ref value) = versions[idx - 1].value {
                        properties.insert(key.clone(), value.clone());
                    }
                }
            }

            let created_at = history
                .lifecycle
                .first()
                .map(|lc| lc.effective_from)
                .unwrap_or(at);

            let meta = EdgeMeta {
                id: edge_id.clone(),
                type_id: history.type_id.clone(),
                source: history.source.clone(),
                target: history.target.clone(),
                created_at,
                updated_at: at,
                version: history.version_count() as u64,
                alive: true,
            };

            let edge = Edge { meta, properties };

            outgoing_index
                .entry(history.source.clone())
                .or_default()
                .insert(edge_id.clone());
            incoming_index
                .entry(history.target.clone())
                .or_default()
                .insert(edge_id.clone());

            edges.insert(edge_id.clone(), edge);
        }

        Self {
            nodes,
            edges,
            type_index,
            outgoing_index,
            incoming_index,
            as_of: at,
        }
    }
}

impl GraphReader for TemporalGraphView {
    fn node(&self, id: &NodeId) -> Option<&Node> {
        self.nodes.get(id)
    }

    fn edge(&self, id: &EdgeId) -> Option<&Edge> {
        self.edges.get(id)
    }

    fn nodes_by_type(&self, type_id: &str) -> Vec<&Node> {
        self.type_index
            .get(type_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.nodes.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn edges_by_type(&self, type_id: &str) -> Vec<&Edge> {
        self.edges
            .values()
            .filter(|e| e.type_id() == type_id)
            .collect()
    }

    fn outgoing_edges(&self, node_id: &NodeId) -> Vec<&Edge> {
        self.outgoing_index
            .get(node_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.edges.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn incoming_edges(&self, node_id: &NodeId) -> Vec<&Edge> {
        self.incoming_index
            .get(node_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.edges.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn node_count(&self) -> usize {
        self.nodes.len()
    }

    fn edge_count(&self) -> usize {
        self.edges.len()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::{Event, EventKind, Value};
    use hydra_core::id::{EdgeId, NodeId};
    use std::collections::HashMap;
    use chrono::{Duration, Utc};

    fn ts(offset_ms: i64) -> DateTime<Utc> {
        Utc::now() + Duration::milliseconds(offset_ms)
    }

    fn make_create_at(
        node_id: &NodeId,
        type_id: &str,
        props: HashMap<String, Value>,
        timestamp: DateTime<Utc>,
    ) -> Event {
        let mut e = Event::trigger(EventKind::NodeCreated {
            node_id: node_id.clone(),
            type_id: type_id.to_string(),
            properties: props,
        });
        e.timestamp = timestamp;
        e
    }

    fn make_update_at(
        node_id: &NodeId,
        changes: HashMap<String, Value>,
        timestamp: DateTime<Utc>,
        parent: &Event,
    ) -> Event {
        let mut e = Event::reaction(
            EventKind::NodeUpdated {
                node_id: node_id.clone(),
                changes,
            },
            parent,
        );
        e.timestamp = timestamp;
        e
    }

    fn make_delete_at(
        node_id: &NodeId,
        timestamp: DateTime<Utc>,
    ) -> Event {
        let mut e = Event::trigger(EventKind::NodeDeleted {
            node_id: node_id.clone(),
        });
        e.timestamp = timestamp;
        e
    }

    // ================================================================
    // Test 1: Basic temporal recording — create + update + query
    // ================================================================
    #[test]
    fn node_state_at_different_times() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();

        let t0 = ts(0);
        let t1 = ts(100);
        let t2 = ts(200);

        let e1 = make_create_at(
            &n, "ec2",
            HashMap::from([("state".into(), Value::String("pending".into()))]),
            t0,
        );
        idx.record(&e1);

        let e2 = make_update_at(
            &n,
            HashMap::from([("state".into(), Value::String("running".into()))]),
            t1,
            &e1,
        );
        idx.record(&e2);

        let e3 = make_update_at(
            &n,
            HashMap::from([("state".into(), Value::String("stopped".into()))]),
            t2,
            &e2,
        );
        idx.record(&e3);

        // At t0: state = "pending"
        let s0 = idx.node_state_at(&n, t0).unwrap();
        assert_eq!(s0.get("state").unwrap().as_str(), Some("pending"));

        // At t1: state = "running"
        let s1 = idx.node_state_at(&n, t1).unwrap();
        assert_eq!(s1.get("state").unwrap().as_str(), Some("running"));

        // At t2: state = "stopped"
        let s2 = idx.node_state_at(&n, t2).unwrap();
        assert_eq!(s2.get("state").unwrap().as_str(), Some("stopped"));

        // Between t0 and t1: still "pending" (t1 hasn't happened yet)
        let s_between = idx.node_state_at(&n, t0 + Duration::milliseconds(50)).unwrap();
        assert_eq!(s_between.get("state").unwrap().as_str(), Some("pending"));
    }

    // ================================================================
    // Test 2: Node creation and deletion lifecycle
    // ================================================================
    #[test]
    fn node_lifecycle_alive_at() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();

        let t0 = ts(0);
        let t1 = ts(100);

        let e1 = make_create_at(&n, "ec2", HashMap::new(), t0);
        idx.record(&e1);

        let e2 = make_delete_at(&n, t1);
        idx.record(&e2);

        // Before creation: not alive
        assert!(!idx.node_alive_at(&n, t0 - Duration::milliseconds(10)));

        // At creation: alive
        assert!(idx.node_alive_at(&n, t0));

        // Between creation and deletion: alive
        assert!(idx.node_alive_at(&n, t0 + Duration::milliseconds(50)));

        // At deletion: not alive
        assert!(!idx.node_alive_at(&n, t1));

        // After deletion: not alive
        assert!(!idx.node_alive_at(&n, t1 + Duration::milliseconds(50)));

        // state_at returns None for deleted node
        assert!(idx.node_state_at(&n, t1).is_none());
    }

    // ================================================================
    // Test 3: Trend query — property over time
    // ================================================================
    #[test]
    fn trend_returns_property_series() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();

        let t0 = ts(0);
        let t1 = ts(100);
        let t2 = ts(200);

        let e1 = make_create_at(
            &n, "ec2",
            HashMap::from([("trust_score".into(), Value::Int(100))]),
            t0,
        );
        idx.record(&e1);

        let e2 = make_update_at(
            &n,
            HashMap::from([("trust_score".into(), Value::Int(75))]),
            t1, &e1,
        );
        idx.record(&e2);

        let e3 = make_update_at(
            &n,
            HashMap::from([("trust_score".into(), Value::Int(42))]),
            t2, &e2,
        );
        idx.record(&e3);

        let trend = idx.node_trend(&n, "trust_score");
        assert_eq!(trend.len(), 3);
        assert_eq!(trend[0].1.as_i64(), Some(100));
        assert_eq!(trend[1].1.as_i64(), Some(75));
        assert_eq!(trend[2].1.as_i64(), Some(42));
    }

    // ================================================================
    // Test 4: Temporal diff between two timestamps
    // ================================================================
    #[test]
    fn diff_detects_changes_between_timestamps() {
        let mut idx = TemporalIndex::new();
        let n1 = NodeId::new();
        let n2 = NodeId::new();

        let t0 = ts(0);
        let t1 = ts(100);
        let t2 = ts(200);
        let t3 = ts(300);

        // n1 created at t0
        let e1 = make_create_at(&n1, "ec2", HashMap::new(), t0);
        idx.record(&e1);

        // n2 created at t1
        let e2 = make_create_at(&n2, "rds", HashMap::new(), t1);
        idx.record(&e2);

        // n1 updated at t2
        let e3 = make_update_at(
            &n1,
            HashMap::from([("state".into(), Value::String("stopped".into()))]),
            t2, &e1,
        );
        idx.record(&e3);

        // Diff from t0 to t3: n2 was created, n1 was changed
        let diff = idx.diff(t0, t3);
        assert_eq!(diff.nodes_created.len(), 1); // n2
        assert_eq!(diff.nodes_created[0], n2);
        assert_eq!(diff.nodes_changed.len(), 1); // n1 had property change
        assert_eq!(diff.nodes_changed[0].node_id, n1);
        assert!(diff.nodes_deleted.is_empty());
    }

    // ================================================================
    // Test 5: Diff detects deletions
    // ================================================================
    #[test]
    fn diff_detects_deletions() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();

        let t0 = ts(0);
        let t1 = ts(100);
        let t2 = ts(200);

        let e1 = make_create_at(&n, "ec2", HashMap::new(), t0);
        idx.record(&e1);

        let e2 = make_delete_at(&n, t1);
        idx.record(&e2);

        let diff = idx.diff(t0, t2);
        assert_eq!(diff.nodes_deleted.len(), 1);
        assert_eq!(diff.nodes_deleted[0], n);
    }

    // ================================================================
    // Test 6: Multiple properties tracked independently
    // ================================================================
    #[test]
    fn multiple_properties_independent() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();

        let t0 = ts(0);
        let t1 = ts(100);

        let e1 = make_create_at(
            &n, "ec2",
            HashMap::from([
                ("state".into(), Value::String("running".into())),
                ("trust_score".into(), Value::Int(100)),
            ]),
            t0,
        );
        idx.record(&e1);

        // Only update trust_score
        let e2 = make_update_at(
            &n,
            HashMap::from([("trust_score".into(), Value::Int(50))]),
            t1, &e1,
        );
        idx.record(&e2);

        // At t1: state is still "running" (unchanged), trust_score is 50
        let s = idx.node_state_at(&n, t1).unwrap();
        assert_eq!(s.get("state").unwrap().as_str(), Some("running"));
        assert_eq!(s.get("trust_score").unwrap().as_i64(), Some(50));

        // At t0: both at original values
        let s0 = idx.node_state_at(&n, t0).unwrap();
        assert_eq!(s0.get("trust_score").unwrap().as_i64(), Some(100));
    }

    // ================================================================
    // Test 7: Edge temporal tracking
    // ================================================================
    #[test]
    fn edge_lifecycle() {
        let mut idx = TemporalIndex::new();
        let n1 = NodeId::new();
        let n2 = NodeId::new();
        let edge_id = EdgeId::new();

        let t0 = ts(0);
        let t1 = ts(100);

        let mut e1 = Event::trigger(EventKind::EdgeCreated {
            edge_id: edge_id.clone(),
            source: n1,
            target: n2,
            type_id: "in_vpc".to_string(),
            properties: HashMap::from([("weight".into(), Value::Float(1.0))]),
        });
        e1.timestamp = t0;
        idx.record(&e1);

        assert!(idx.edge_alive_at(&edge_id, t0));

        let mut e2 = Event::trigger(EventKind::EdgeDeleted {
            edge_id: edge_id.clone(),
        });
        e2.timestamp = t1;
        idx.record(&e2);

        assert!(!idx.edge_alive_at(&edge_id, t1));
        assert!(idx.edge_alive_at(&edge_id, t0 + Duration::milliseconds(50)));
    }

    // ================================================================
    // Test 8: Empty temporal index
    // ================================================================
    #[test]
    fn empty_index() {
        let idx = TemporalIndex::new();
        assert_eq!(idx.node_count(), 0);
        assert_eq!(idx.edge_count(), 0);
        assert_eq!(idx.total_versions(), 0);

        let ghost = NodeId::from_str("node_GHOST");
        assert!(idx.node_state_at(&ghost, Utc::now()).is_none());
        assert!(!idx.node_alive_at(&ghost, Utc::now()));
        assert!(idx.node_trend(&ghost, "anything").is_empty());
    }

    // ================================================================
    // Test 9: Query before any event
    // ================================================================
    #[test]
    fn query_before_creation() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();
        let t0 = ts(100);

        let e1 = make_create_at(&n, "ec2", HashMap::new(), t0);
        idx.record(&e1);

        // Before creation
        assert!(idx.node_state_at(&n, t0 - Duration::milliseconds(10)).is_none());
        assert!(!idx.node_alive_at(&n, t0 - Duration::milliseconds(10)));
    }

    // ================================================================
    // Test 10: Diagnostics — version counting
    // ================================================================
    #[test]
    fn version_counting() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();

        let t0 = ts(0);
        let t1 = ts(100);

        let e1 = make_create_at(
            &n, "ec2",
            HashMap::from([("state".into(), Value::String("running".into()))]),
            t0,
        );
        idx.record(&e1);
        // 1 lifecycle version + 1 property version = 2

        let e2 = make_update_at(
            &n,
            HashMap::from([("state".into(), Value::String("stopped".into()))]),
            t1, &e1,
        );
        idx.record(&e2);
        // 1 lifecycle version + 2 property versions = 3

        assert_eq!(idx.total_versions(), 3);
        assert_eq!(idx.node_history(&n).unwrap().version_count(), 3);
    }

    // ================================================================
    // Test 11: Diff with edge changes
    // ================================================================
    #[test]
    fn diff_with_edges() {
        let mut idx = TemporalIndex::new();
        let edge_id = EdgeId::new();

        let t0 = ts(0);
        let t1 = ts(100);
        let t2 = ts(200);

        let mut e1 = Event::trigger(EventKind::EdgeCreated {
            edge_id: edge_id.clone(),
            source: NodeId::new(),
            target: NodeId::new(),
            type_id: "dep".to_string(),
            properties: HashMap::new(),
        });
        e1.timestamp = t1;
        idx.record(&e1);

        let diff = idx.diff(t0, t2);
        assert_eq!(diff.edges_created.len(), 1);
        assert_eq!(diff.edges_created[0], edge_id);
    }

    // ================================================================
    // Test 12: TemporalDiff helpers
    // ================================================================
    #[test]
    fn temporal_diff_helpers() {
        let empty = TemporalDiff {
            nodes_created: vec![],
            nodes_deleted: vec![],
            nodes_changed: vec![],
            edges_created: vec![],
            edges_deleted: vec![],
            edges_changed: vec![],
        };
        assert!(empty.is_empty());
        assert_eq!(empty.total_changes(), 0);
    }

    // ================================================================
    // Test 13: Rapid updates on same property
    // ================================================================
    #[test]
    fn rapid_updates_same_property() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();

        let t0 = ts(0);
        let e0 = make_create_at(
            &n, "ec2",
            HashMap::from([("counter".into(), Value::Int(0))]),
            t0,
        );
        idx.record(&e0);

        let mut prev = e0;
        for i in 1..=100 {
            let t = ts(i);
            let e = make_update_at(
                &n,
                HashMap::from([("counter".into(), Value::Int(i))]),
                t,
                &prev,
            );
            idx.record(&e);
            prev = e;
        }

        // 101 property versions (1 create + 100 updates) + 1 lifecycle = 102
        assert_eq!(idx.node_history(&n).unwrap().version_count(), 102);

        // State at each point should be correct
        assert_eq!(
            idx.node_state_at(&n, ts(50)).unwrap().get("counter").unwrap().as_i64(),
            Some(50)
        );
        assert_eq!(
            idx.node_state_at(&n, ts(99)).unwrap().get("counter").unwrap().as_i64(),
            Some(99)
        );

        // Trend should have 101 entries
        let trend = idx.node_trend(&n, "counter");
        assert_eq!(trend.len(), 101);
    }

    // === Adversarial tests (three-skill audit) ===

    // ================================================================
    // Test 14: Same-timestamp updates — last one wins
    // ================================================================
    #[test]
    fn same_timestamp_updates_last_wins() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();
        let t0 = ts(0);

        let e1 = make_create_at(
            &n, "ec2",
            HashMap::from([("val".into(), Value::Int(1))]),
            t0,
        );
        idx.record(&e1);

        // Two updates at the EXACT same timestamp
        let e2 = make_update_at(
            &n,
            HashMap::from([("val".into(), Value::Int(2))]),
            t0, &e1,
        );
        idx.record(&e2);

        let e3 = make_update_at(
            &n,
            HashMap::from([("val".into(), Value::Int(3))]),
            t0, &e2,
        );
        idx.record(&e3);

        // At t0, the last update (val=3) should win
        let state = idx.node_state_at(&n, t0).unwrap();
        assert_eq!(state.get("val").unwrap().as_i64(), Some(3));
    }

    // ================================================================
    // Test 15: Diff with zero-width window (from == to)
    // ================================================================
    #[test]
    fn diff_zero_width_window() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();
        let t0 = ts(0);

        let e1 = make_create_at(&n, "ec2", HashMap::new(), t0);
        idx.record(&e1);

        // from == to: nothing can have changed in zero time
        let diff = idx.diff(t0, t0);
        assert!(diff.is_empty());
    }

    // ================================================================
    // Test 16: Diff with inverted range (from > to)
    // ================================================================
    #[test]
    fn diff_inverted_range() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();
        let t0 = ts(0);
        let t1 = ts(100);

        let e1 = make_create_at(&n, "ec2", HashMap::new(), t0);
        idx.record(&e1);

        // Inverted range: from=t1, to=t0
        // Node is alive at t1, not at t0. In inverted range, diff sees
        // alive_from=true (at t1), alive_to=false (at t0) → deletion.
        // This is technically correct given the inverted semantics, but callers
        // should validate the range. The function doesn't panic.
        let diff = idx.diff(t1, t0);
        // Not asserting specific behavior — just ensuring no panic
        let _ = diff.total_changes();
    }

    // ================================================================
    // Test 17: Node created and deleted at same timestamp
    // ================================================================
    #[test]
    fn created_and_deleted_same_timestamp() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();
        let t0 = ts(0);

        let e1 = make_create_at(&n, "ec2", HashMap::new(), t0);
        idx.record(&e1);

        let e2 = make_delete_at(&n, t0);
        idx.record(&e2);

        // At t0: lifecycle has two entries with same timestamp.
        // partition_point finds the last entry where effective_from <= t0,
        // which is the deletion entry (alive=false).
        assert!(!idx.node_alive_at(&n, t0));
    }

    // ================================================================
    // Test 18: Update on non-tracked node returns false
    // ================================================================
    #[test]
    fn update_on_non_tracked_node() {
        let mut idx = TemporalIndex::new();
        let ghost = NodeId::from_str("node_GHOST");

        let mut e = Event::trigger(EventKind::NodeUpdated {
            node_id: ghost,
            changes: HashMap::from([("x".into(), Value::Int(1))]),
        });
        e.timestamp = ts(0);

        assert!(!idx.record(&e));
    }

    // ================================================================
    // Test 19: Integration — Hydra ingest feeds temporal index
    // ================================================================
    #[test]
    fn hydra_integration_temporal_tracks_ingest() {
        use crate::hydra::Hydra;

        let mut hydra = Hydra::new();
        let n = NodeId::new();

        hydra.ingest(EventKind::NodeCreated {
            node_id: n.clone(),
            type_id: "ec2".to_string(),
            properties: HashMap::from([("state".into(), Value::String("pending".into()))]),
        }).unwrap();

        hydra.ingest(EventKind::NodeUpdated {
            node_id: n.clone(),
            changes: HashMap::from([("state".into(), Value::String("running".into()))]),
        }).unwrap();

        // Temporal: trend should show 2 values for "state"
        let trend = hydra.trend(&n, "state");
        assert_eq!(trend.len(), 2);

        // Version count:
        // NodeCreated → 1 lifecycle version + 1 property version ("state") = 2
        // NodeUpdated → 1 property version ("state") = 1
        // Total = 3
        assert_eq!(hydra.temporal().total_versions(), 3);

        // Node is tracked
        assert_eq!(hydra.temporal().node_count(), 1);
        assert!(hydra.temporal().node_history(&n).is_some());
    }

    // === TemporalGraphView tests ===

    // ================================================================
    // Test 20: GraphView at creation time shows the created node
    // ================================================================
    #[test]
    fn graph_view_shows_alive_nodes() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();
        let t0 = ts(0);
        let _t1 = ts(100); // unused — retained for consistent test structure

        let e1 = make_create_at(
            &n, "ec2",
            HashMap::from([("state".into(), Value::String("running".into()))]),
            t0,
        );
        idx.record(&e1);

        // View at t0: node exists
        let view = idx.graph_at(t0);
        assert_eq!(view.node_count(), 1);
        assert!(view.has_node(&n));
        assert_eq!(view.node(&n).unwrap().get_str("state"), Some("running"));
        assert_eq!(view.nodes_by_type("ec2").len(), 1);

        // View before creation: nothing
        let view_before = idx.graph_at(t0 - Duration::milliseconds(10));
        assert_eq!(view_before.node_count(), 0);
        assert!(!view_before.has_node(&n));
    }

    // ================================================================
    // Test 21: GraphView shows properties at the queried timestamp
    // ================================================================
    #[test]
    fn graph_view_shows_historical_properties() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();
        let t0 = ts(0);
        let t1 = ts(100);
        let _t2 = ts(200); // available for future assertions

        let e1 = make_create_at(
            &n, "ec2",
            HashMap::from([("trust".into(), Value::Int(100))]),
            t0,
        );
        idx.record(&e1);

        let e2 = make_update_at(
            &n,
            HashMap::from([("trust".into(), Value::Int(50))]),
            t1, &e1,
        );
        idx.record(&e2);

        // At t0: trust=100
        let v0 = idx.graph_at(t0);
        assert_eq!(v0.node(&n).unwrap().get_i64("trust"), Some(100));

        // At t1: trust=50
        let v1 = idx.graph_at(t1);
        assert_eq!(v1.node(&n).unwrap().get_i64("trust"), Some(50));

        // Between: still 100
        let v_mid = idx.graph_at(t0 + Duration::milliseconds(50));
        assert_eq!(v_mid.node(&n).unwrap().get_i64("trust"), Some(100));
    }

    // ================================================================
    // Test 22: GraphView hides deleted nodes
    // ================================================================
    #[test]
    fn graph_view_hides_deleted_nodes() {
        let mut idx = TemporalIndex::new();
        let n = NodeId::new();
        let t0 = ts(0);
        let t1 = ts(100);

        idx.record(&make_create_at(&n, "ec2", HashMap::new(), t0));
        idx.record(&make_delete_at(&n, t1));

        // Before deletion: alive
        let v0 = idx.graph_at(t0 + Duration::milliseconds(50));
        assert_eq!(v0.node_count(), 1);

        // After deletion: gone
        let v1 = idx.graph_at(t1);
        assert_eq!(v1.node_count(), 0);
    }

    // ================================================================
    // Test 23: GraphView with edges and topology queries
    // ================================================================
    #[test]
    fn graph_view_with_edges_and_topology() {
        let mut idx = TemporalIndex::new();
        let n1 = NodeId::new();
        let n2 = NodeId::new();
        let edge_id = EdgeId::new();

        let t0 = ts(0);

        // Create two nodes
        idx.record(&make_create_at(&n1, "ec2", HashMap::new(), t0));
        idx.record(&make_create_at(&n2, "vpc", HashMap::new(), t0));

        // Create edge
        let mut e_edge = Event::trigger(EventKind::EdgeCreated {
            edge_id: edge_id.clone(),
            source: n1.clone(),
            target: n2.clone(),
            type_id: "in_vpc".to_string(),
            properties: HashMap::new(),
        });
        e_edge.timestamp = t0;
        idx.record(&e_edge);

        let view = idx.graph_at(t0);
        assert_eq!(view.node_count(), 2);
        assert_eq!(view.edge_count(), 1);

        // Topology queries work
        assert_eq!(view.outgoing_edges(&n1).len(), 1);
        assert_eq!(view.incoming_edges(&n2).len(), 1);
        assert_eq!(view.outgoing_neighbors(&n1).len(), 1);
        assert_eq!(view.outgoing_neighbors(&n1)[0].type_id(), "vpc");
    }

    // ================================================================
    // Test 24: GraphView edge excluded when endpoint deleted
    // ================================================================
    #[test]
    fn graph_view_edge_excluded_when_endpoint_deleted() {
        let mut idx = TemporalIndex::new();
        let n1 = NodeId::new();
        let n2 = NodeId::new();
        let edge_id = EdgeId::new();

        let t0 = ts(0);
        let t1 = ts(100);

        idx.record(&make_create_at(&n1, "ec2", HashMap::new(), t0));
        idx.record(&make_create_at(&n2, "vpc", HashMap::new(), t0));

        let mut e_edge = Event::trigger(EventKind::EdgeCreated {
            edge_id: edge_id.clone(),
            source: n1.clone(),
            target: n2.clone(),
            type_id: "in_vpc".to_string(),
            properties: HashMap::new(),
        });
        e_edge.timestamp = t0;
        idx.record(&e_edge);

        // Delete n1
        idx.record(&make_delete_at(&n1, t1));

        // At t0: edge exists (both endpoints alive)
        let v0 = idx.graph_at(t0);
        assert_eq!(v0.edge_count(), 1);

        // At t1: edge excluded (n1 is dead)
        let v1 = idx.graph_at(t1);
        assert_eq!(v1.edge_count(), 0);
        assert_eq!(v1.node_count(), 1); // only n2
    }

    // ================================================================
    // Test 25: GraphView with BFS traversal (the whole point)
    // ================================================================
    #[test]
    fn graph_view_supports_bfs() {
        use hydra_core::graph::{bfs_dyn, TraversalDirection};

        let mut idx = TemporalIndex::new();
        let n1 = NodeId::new();
        let n2 = NodeId::new();
        let n3 = NodeId::new();

        let t0 = ts(0);
        let t1 = ts(100);

        // Create 3-node chain: n1 → n2 → n3 at t0
        idx.record(&make_create_at(&n1, "ec2", HashMap::new(), t0));
        idx.record(&make_create_at(&n2, "rds", HashMap::new(), t0));
        idx.record(&make_create_at(&n3, "s3", HashMap::new(), t0));

        let mut e1 = Event::trigger(EventKind::EdgeCreated {
            edge_id: EdgeId::new(),
            source: n1.clone(),
            target: n2.clone(),
            type_id: "dep".to_string(),
            properties: HashMap::new(),
        });
        e1.timestamp = t0;
        idx.record(&e1);

        let mut e2 = Event::trigger(EventKind::EdgeCreated {
            edge_id: EdgeId::new(),
            source: n2.clone(),
            target: n3.clone(),
            type_id: "dep".to_string(),
            properties: HashMap::new(),
        });
        e2.timestamp = t0;
        idx.record(&e2);

        // Delete n3 at t1
        idx.record(&make_delete_at(&n3, t1));

        // BFS at t0: n1 → n2 → n3 (3 nodes reachable)
        let view_t0 = idx.graph_at(t0);
        let reachable = bfs_dyn(&view_t0, &n1, TraversalDirection::Outgoing, &|_| true);
        assert_eq!(reachable.len(), 3);

        // BFS at t1: n1 → n2 only (n3 deleted, edge to it excluded)
        let view_t1 = idx.graph_at(t1);
        let reachable_t1 = bfs_dyn(&view_t1, &n1, TraversalDirection::Outgoing, &|_| true);
        assert_eq!(reachable_t1.len(), 2);
        assert!(reachable_t1.contains(&n1));
        assert!(reachable_t1.contains(&n2));
        assert!(!reachable_t1.contains(&n3));
    }

    // ================================================================
    // Test 26: Empty temporal index → empty graph view
    // ================================================================
    #[test]
    fn empty_temporal_empty_view() {
        let idx = TemporalIndex::new();
        let view = idx.graph_at(Utc::now());
        assert_eq!(view.node_count(), 0);
        assert_eq!(view.edge_count(), 0);
    }
}
