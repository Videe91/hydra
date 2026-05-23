use hydra_core::edge::Edge;
use hydra_core::event::{Event, EventKind};
use hydra_core::graph::GraphReader;
use hydra_core::id::{EdgeId, NodeId};
use hydra_core::node::Node;
use std::collections::{HashMap, HashSet};

/// The materialized graph state. All events are applied here to produce the
/// current view of the graph. Maintains indexes for fast topology queries.
///
/// This is the "projection" in event-sourcing terms: the current state
/// derived from the event log. It can be rebuilt from scratch by replaying
/// all events.
pub struct Projection {
    /// Primary node storage
    nodes: HashMap<NodeId, Node>,
    /// Primary edge storage
    edges: HashMap<EdgeId, Edge>,

    // === Indexes ===
    /// Node type → set of node IDs (alive only)
    type_index: HashMap<String, HashSet<NodeId>>,
    /// Edge type → set of edge IDs (alive only)
    edge_type_index: HashMap<String, HashSet<EdgeId>>,
    /// Source node → set of edge IDs (outgoing)
    outgoing_index: HashMap<NodeId, HashSet<EdgeId>>,
    /// Target node → set of edge IDs (incoming)
    incoming_index: HashMap<NodeId, HashSet<EdgeId>>,

    /// Total events applied (for diagnostics)
    events_applied: u64,
}

impl Projection {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            type_index: HashMap::new(),
            edge_type_index: HashMap::new(),
            outgoing_index: HashMap::new(),
            incoming_index: HashMap::new(),
            events_applied: 0,
        }
    }

    /// Apply an event to the projection, updating all indexes.
    /// Returns Ok(true) if state actually changed, Ok(false) if no-op.
    pub fn apply(&mut self, event: &Event) -> hydra_core::error::Result<bool> {
        self.events_applied += 1;
        match &event.kind {
            EventKind::NodeCreated {
                node_id,
                type_id,
                properties,
            } => {
                if self.nodes.contains_key(node_id) {
                    return Err(hydra_core::error::HydraError::NodeAlreadyExists(
                        node_id.clone(),
                    ));
                }
                let node = Node::new(node_id.clone(), type_id.clone(), properties.clone());
                // Update type index
                self.type_index
                    .entry(type_id.clone())
                    .or_default()
                    .insert(node_id.clone());
                self.nodes.insert(node_id.clone(), node);
                Ok(true)
            }

            EventKind::NodeUpdated { node_id, changes } => {
                let node = self
                    .nodes
                    .get_mut(node_id)
                    .ok_or_else(|| hydra_core::error::HydraError::NodeNotFound(node_id.clone()))?;

                if !node.is_alive() {
                    return Err(hydra_core::error::HydraError::NodeNotFound(node_id.clone()));
                }

                let changed = node.apply_changes(changes);
                Ok(!changed.is_empty())
            }

            EventKind::NodeDeleted { node_id } => {
                let node = self
                    .nodes
                    .get_mut(node_id)
                    .ok_or_else(|| hydra_core::error::HydraError::NodeNotFound(node_id.clone()))?;

                if !node.is_alive() {
                    return Ok(false); // Already dead
                }

                // Remove from type index
                if let Some(set) = self.type_index.get_mut(node.type_id()) {
                    set.remove(node_id);
                }

                node.delete();

                // Cascade-delete all connected edges (outgoing + incoming).
                // Collect edge IDs first to avoid borrowing conflicts.
                let outgoing_edge_ids: Vec<EdgeId> = self
                    .outgoing_index
                    .get(node_id)
                    .map(|s| s.iter().cloned().collect())
                    .unwrap_or_default();
                let incoming_edge_ids: Vec<EdgeId> = self
                    .incoming_index
                    .get(node_id)
                    .map(|s| s.iter().cloned().collect())
                    .unwrap_or_default();

                for edge_id in outgoing_edge_ids.iter().chain(incoming_edge_ids.iter()) {
                    if let Some(edge) = self.edges.get_mut(edge_id) {
                        if edge.is_alive() {
                            // Remove from the OTHER endpoint's index
                            if let Some(set) = self.incoming_index.get_mut(edge.target()) {
                                set.remove(edge_id);
                            }
                            if let Some(set) = self.outgoing_index.get_mut(edge.source()) {
                                set.remove(edge_id);
                            }
                            // Remove from edge type index
                            if let Some(set) = self.edge_type_index.get_mut(edge.type_id()) {
                                set.remove(edge_id);
                            }
                            edge.delete();
                        }
                    }
                }

                // Clear this node's own index entries
                self.outgoing_index.remove(node_id);
                self.incoming_index.remove(node_id);

                Ok(true)
            }

            EventKind::EdgeCreated {
                edge_id,
                source,
                target,
                type_id,
                properties,
            } => {
                if self.edges.contains_key(edge_id) {
                    return Err(hydra_core::error::HydraError::EdgeAlreadyExists(
                        edge_id.clone(),
                    ));
                }

                // Verify endpoints exist and are alive
                if !self.has_node(source) {
                    return Err(hydra_core::error::HydraError::InvalidEdgeEndpoints {
                        source: source.clone(),
                        target: target.clone(),
                    });
                }
                if !self.has_node(target) {
                    return Err(hydra_core::error::HydraError::InvalidEdgeEndpoints {
                        source: source.clone(),
                        target: target.clone(),
                    });
                }

                let edge = Edge::new(
                    edge_id.clone(),
                    type_id.clone(),
                    source.clone(),
                    target.clone(),
                    properties.clone(),
                );

                // Update topology indexes
                self.outgoing_index
                    .entry(source.clone())
                    .or_default()
                    .insert(edge_id.clone());
                self.incoming_index
                    .entry(target.clone())
                    .or_default()
                    .insert(edge_id.clone());
                // Update edge type index
                self.edge_type_index
                    .entry(type_id.clone())
                    .or_default()
                    .insert(edge_id.clone());

                self.edges.insert(edge_id.clone(), edge);
                Ok(true)
            }

            EventKind::EdgeUpdated { edge_id, changes } => {
                let edge = self
                    .edges
                    .get_mut(edge_id)
                    .ok_or_else(|| hydra_core::error::HydraError::EdgeNotFound(edge_id.clone()))?;

                if !edge.is_alive() {
                    return Err(hydra_core::error::HydraError::EdgeNotFound(edge_id.clone()));
                }

                let changed = edge.apply_changes(changes);
                Ok(!changed.is_empty())
            }

            EventKind::EdgeDeleted { edge_id } => {
                let edge = self
                    .edges
                    .get_mut(edge_id)
                    .ok_or_else(|| hydra_core::error::HydraError::EdgeNotFound(edge_id.clone()))?;

                if !edge.is_alive() {
                    return Ok(false);
                }

                // Remove from topology indexes
                if let Some(set) = self.outgoing_index.get_mut(edge.source()) {
                    set.remove(edge_id);
                }
                if let Some(set) = self.incoming_index.get_mut(edge.target()) {
                    set.remove(edge_id);
                }
                // Remove from edge type index
                if let Some(set) = self.edge_type_index.get_mut(edge.type_id()) {
                    set.remove(edge_id);
                }

                edge.delete();
                Ok(true)
            }

            EventKind::Signal { .. } => {
                // Signals don't mutate graph state — they only trigger subscriptions
                Ok(false)
            }

            EventKind::Snapshot { .. } => {
                // Snapshots are for compaction — handled by storage, not projection
                Ok(false)
            }

            // Epistemic events live in the claims/evidence layer, not the graph
            // topology projection. They don't mutate nodes/edges directly.
            // (TopologyCommittedFromClaim is a *marker* event — the actual
            // NodeCreated/EdgeCreated it produced are separate events.)
            // Action/outcome events live in the action layer, not graph topology.
            EventKind::EvidenceAdded { .. }
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
            | EventKind::SchemaArchived { .. }
            | EventKind::SnapshotTaken { .. }
            | EventKind::SnapshotRestored { .. } => Ok(false),
        }
    }

    /// How many events have been applied to this projection
    pub fn events_applied(&self) -> u64 {
        self.events_applied
    }

    /// All node IDs ever stored (including dead nodes).
    /// Used by the counterfactual engine to diff two projections.
    pub fn all_node_ids(&self) -> Vec<NodeId> {
        self.nodes.keys().cloned().collect()
    }

    /// All edge IDs ever stored (including dead edges).
    pub fn all_edge_ids(&self) -> Vec<EdgeId> {
        self.edges.keys().cloned().collect()
    }

    /// All stored nodes (including dead ones). Used by snapshotting to
    /// capture the full projection state.
    pub fn all_nodes(&self) -> Vec<&Node> {
        self.nodes.values().collect()
    }

    /// All stored edges (including dead ones). Used by snapshotting to
    /// capture the full projection state.
    pub fn all_edges(&self) -> Vec<&Edge> {
        self.edges.values().collect()
    }

}

impl Default for Projection {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphReader for Projection {
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
                    .filter(|n| n.is_alive())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn edges_by_type(&self, type_id: &str) -> Vec<&Edge> {
        self.edge_type_index
            .get(type_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.edges.get(id))
                    .filter(|e| e.is_alive())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn outgoing_edges(&self, node_id: &NodeId) -> Vec<&Edge> {
        self.outgoing_index
            .get(node_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.edges.get(id))
                    .filter(|e| e.is_alive())
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
                    .filter(|e| e.is_alive())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn node_count(&self) -> usize {
        self.type_index.values().map(|s| s.len()).sum()
    }

    fn edge_count(&self) -> usize {
        self.edges.values().filter(|e| e.is_alive()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::Value;
    use hydra_core::id::{EdgeId, NodeId};
    use std::collections::HashMap;

    fn node_created_event(node_id: &NodeId, type_id: &str) -> Event {
        Event::trigger(EventKind::NodeCreated {
            node_id: node_id.clone(),
            type_id: type_id.to_string(),
            properties: HashMap::new(),
        })
    }

    fn node_created_with_props(
        node_id: &NodeId,
        type_id: &str,
        props: HashMap<String, Value>,
    ) -> Event {
        Event::trigger(EventKind::NodeCreated {
            node_id: node_id.clone(),
            type_id: type_id.to_string(),
            properties: props,
        })
    }

    #[test]
    fn create_node() {
        let mut proj = Projection::new();
        let id = NodeId::new();
        let evt = node_created_event(&id, "ec2_instance");

        let changed = proj.apply(&evt).unwrap();
        assert!(changed);
        assert!(proj.has_node(&id));
        assert_eq!(proj.node(&id).unwrap().type_id(), "ec2_instance");
        assert_eq!(proj.node_count(), 1);
        assert_eq!(proj.events_applied(), 1);
    }

    #[test]
    fn create_duplicate_node_fails() {
        let mut proj = Projection::new();
        let id = NodeId::new();
        proj.apply(&node_created_event(&id, "ec2")).unwrap();

        let result = proj.apply(&node_created_event(&id, "ec2"));
        assert!(result.is_err());
    }

    #[test]
    fn update_node() {
        let mut proj = Projection::new();
        let id = NodeId::new();
        proj.apply(&node_created_with_props(
            &id,
            "ec2",
            HashMap::from([("state".to_string(), Value::String("running".to_string()))]),
        ))
        .unwrap();

        let update = Event::trigger(EventKind::NodeUpdated {
            node_id: id.clone(),
            changes: HashMap::from([("state".to_string(), Value::String("stopped".to_string()))]),
        });

        let changed = proj.apply(&update).unwrap();
        assert!(changed);
        assert_eq!(proj.node(&id).unwrap().get_str("state"), Some("stopped"));
        assert_eq!(proj.node(&id).unwrap().meta.version, 2);
    }

    #[test]
    fn update_nonexistent_node_fails() {
        let mut proj = Projection::new();
        let update = Event::trigger(EventKind::NodeUpdated {
            node_id: NodeId::from_str("node_GHOST"),
            changes: HashMap::new(),
        });
        assert!(proj.apply(&update).is_err());
    }

    #[test]
    fn delete_node() {
        let mut proj = Projection::new();
        let id = NodeId::new();
        proj.apply(&node_created_event(&id, "ec2")).unwrap();

        let delete = Event::trigger(EventKind::NodeDeleted {
            node_id: id.clone(),
        });
        let changed = proj.apply(&delete).unwrap();
        assert!(changed);
        assert!(!proj.has_node(&id)); // has_node checks alive
        assert_eq!(proj.node_count(), 0);
        assert_eq!(proj.nodes_by_type("ec2").len(), 0);
    }

    #[test]
    fn delete_already_dead_is_noop() {
        let mut proj = Projection::new();
        let id = NodeId::new();
        proj.apply(&node_created_event(&id, "ec2")).unwrap();
        proj.apply(&Event::trigger(EventKind::NodeDeleted {
            node_id: id.clone(),
        }))
        .unwrap();

        let result = proj.apply(&Event::trigger(EventKind::NodeDeleted {
            node_id: id.clone(),
        }));
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn create_edge() {
        let mut proj = Projection::new();
        let src = NodeId::new();
        let tgt = NodeId::new();
        proj.apply(&node_created_event(&src, "ec2")).unwrap();
        proj.apply(&node_created_event(&tgt, "vpc")).unwrap();

        let edge_id = EdgeId::new();
        let evt = Event::trigger(EventKind::EdgeCreated {
            edge_id: edge_id.clone(),
            source: src.clone(),
            target: tgt.clone(),
            type_id: "in_vpc".to_string(),
            properties: HashMap::new(),
        });

        let changed = proj.apply(&evt).unwrap();
        assert!(changed);
        assert!(proj.has_edge(&edge_id));
        assert_eq!(proj.edge_count(), 1);
        assert_eq!(proj.outgoing_edges(&src).len(), 1);
        assert_eq!(proj.incoming_edges(&tgt).len(), 1);
    }

    #[test]
    fn create_edge_with_missing_source_fails() {
        let mut proj = Projection::new();
        let tgt = NodeId::new();
        proj.apply(&node_created_event(&tgt, "vpc")).unwrap();

        let evt = Event::trigger(EventKind::EdgeCreated {
            edge_id: EdgeId::new(),
            source: NodeId::from_str("node_GHOST"),
            target: tgt,
            type_id: "in_vpc".to_string(),
            properties: HashMap::new(),
        });
        assert!(proj.apply(&evt).is_err());
    }

    #[test]
    fn update_edge() {
        let mut proj = Projection::new();
        let src = NodeId::new();
        let tgt = NodeId::new();
        proj.apply(&node_created_event(&src, "ec2")).unwrap();
        proj.apply(&node_created_event(&tgt, "vpc")).unwrap();

        let edge_id = EdgeId::new();
        proj.apply(&Event::trigger(EventKind::EdgeCreated {
            edge_id: edge_id.clone(),
            source: src,
            target: tgt,
            type_id: "in_vpc".to_string(),
            properties: HashMap::from([("weight".to_string(), Value::Float(1.0))]),
        }))
        .unwrap();

        let update = Event::trigger(EventKind::EdgeUpdated {
            edge_id: edge_id.clone(),
            changes: HashMap::from([("weight".to_string(), Value::Float(2.0))]),
        });
        let changed = proj.apply(&update).unwrap();
        assert!(changed);
        assert_eq!(
            proj.edge(&edge_id)
                .unwrap()
                .get("weight")
                .and_then(|v| v.as_f64()),
            Some(2.0)
        );
    }

    #[test]
    fn delete_edge() {
        let mut proj = Projection::new();
        let src = NodeId::new();
        let tgt = NodeId::new();
        proj.apply(&node_created_event(&src, "ec2")).unwrap();
        proj.apply(&node_created_event(&tgt, "vpc")).unwrap();

        let edge_id = EdgeId::new();
        proj.apply(&Event::trigger(EventKind::EdgeCreated {
            edge_id: edge_id.clone(),
            source: src.clone(),
            target: tgt.clone(),
            type_id: "dep".to_string(),
            properties: HashMap::new(),
        }))
        .unwrap();

        let delete = Event::trigger(EventKind::EdgeDeleted {
            edge_id: edge_id.clone(),
        });
        let changed = proj.apply(&delete).unwrap();
        assert!(changed);
        assert!(!proj.has_edge(&edge_id));
        assert_eq!(proj.outgoing_edges(&src).len(), 0);
        assert_eq!(proj.incoming_edges(&tgt).len(), 0);
        assert_eq!(proj.edge_count(), 0);
    }

    #[test]
    fn type_index_works() {
        let mut proj = Projection::new();
        let a = NodeId::new();
        let b = NodeId::new();
        let c = NodeId::new();
        proj.apply(&node_created_event(&a, "ec2")).unwrap();
        proj.apply(&node_created_event(&b, "ec2")).unwrap();
        proj.apply(&node_created_event(&c, "rds")).unwrap();

        assert_eq!(proj.nodes_by_type("ec2").len(), 2);
        assert_eq!(proj.nodes_by_type("rds").len(), 1);
        assert_eq!(proj.nodes_by_type("s3").len(), 0);
    }

    #[test]
    fn topology_index_multiple_edges() {
        let mut proj = Projection::new();
        let a = NodeId::new();
        let b = NodeId::new();
        let c = NodeId::new();
        proj.apply(&node_created_event(&a, "ec2")).unwrap();
        proj.apply(&node_created_event(&b, "vpc")).unwrap();
        proj.apply(&node_created_event(&c, "sg")).unwrap();

        proj.apply(&Event::trigger(EventKind::EdgeCreated {
            edge_id: EdgeId::new(),
            source: a.clone(),
            target: b.clone(),
            type_id: "in_vpc".to_string(),
            properties: HashMap::new(),
        }))
        .unwrap();
        proj.apply(&Event::trigger(EventKind::EdgeCreated {
            edge_id: EdgeId::new(),
            source: a.clone(),
            target: c.clone(),
            type_id: "uses_sg".to_string(),
            properties: HashMap::new(),
        }))
        .unwrap();

        assert_eq!(proj.outgoing_edges(&a).len(), 2);
        assert_eq!(proj.incoming_edges(&a).len(), 0);
        assert_eq!(proj.incoming_edges(&b).len(), 1);
        assert_eq!(proj.incoming_edges(&c).len(), 1);
    }

    #[test]
    fn signal_does_not_mutate_state() {
        let mut proj = Projection::new();
        let evt = Event::trigger(EventKind::Signal {
            name: "classify".to_string(),
            source: NodeId::new(),
            payload: HashMap::new(),
        });
        let changed = proj.apply(&evt).unwrap();
        assert!(!changed);
        assert_eq!(proj.node_count(), 0);
    }

    #[test]
    fn graphreader_trait_works_on_projection() {
        let mut proj = Projection::new();
        let a = NodeId::new();
        let b = NodeId::new();
        proj.apply(&node_created_event(&a, "ec2")).unwrap();
        proj.apply(&node_created_event(&b, "rds")).unwrap();
        proj.apply(&Event::trigger(EventKind::EdgeCreated {
            edge_id: EdgeId::new(),
            source: a.clone(),
            target: b.clone(),
            type_id: "depends_on".to_string(),
            properties: HashMap::new(),
        }))
        .unwrap();

        // Use GraphReader trait methods
        fn query(g: &dyn GraphReader, a: &NodeId, b: &NodeId) {
            assert_eq!(g.node_count(), 2);
            assert_eq!(g.edge_count(), 1);
            assert!(g.has_node(a));
            assert_eq!(g.outgoing_neighbors(a).len(), 1);
            assert_eq!(g.outgoing_neighbors(a)[0].id(), b);
            assert_eq!(g.incoming_neighbors(b).len(), 1);
        }
        query(&proj, &a, &b);
    }

    // === Adversarial tests (code review audit) ===

    #[test]
    fn update_deleted_node_fails() {
        let mut proj = Projection::new();
        let id = NodeId::new();
        proj.apply(&node_created_event(&id, "ec2")).unwrap();
        proj.apply(&Event::trigger(EventKind::NodeDeleted {
            node_id: id.clone(),
        }))
        .unwrap();

        // Trying to update a dead node should fail
        let update = Event::trigger(EventKind::NodeUpdated {
            node_id: id.clone(),
            changes: HashMap::from([("state".to_string(), Value::String("zombie".into()))]),
        });
        assert!(proj.apply(&update).is_err());
    }

    #[test]
    fn create_edge_to_dead_target_fails() {
        let mut proj = Projection::new();
        let src = NodeId::new();
        let tgt = NodeId::new();
        proj.apply(&node_created_event(&src, "ec2")).unwrap();
        proj.apply(&node_created_event(&tgt, "rds")).unwrap();

        // Kill the target
        proj.apply(&Event::trigger(EventKind::NodeDeleted {
            node_id: tgt.clone(),
        }))
        .unwrap();

        // Creating an edge to a dead node should fail
        let edge_evt = Event::trigger(EventKind::EdgeCreated {
            edge_id: EdgeId::new(),
            source: src,
            target: tgt,
            type_id: "depends_on".to_string(),
            properties: HashMap::new(),
        });
        assert!(proj.apply(&edge_evt).is_err());
    }

    #[test]
    fn deleting_node_cascade_deletes_edges() {
        // When a node is deleted, all its edges are also deleted.
        // This prevents phantom edges from accumulating in the graph.
        let mut proj = Projection::new();
        let a = NodeId::new();
        let b = NodeId::new();
        proj.apply(&node_created_event(&a, "ec2")).unwrap();
        proj.apply(&node_created_event(&b, "vpc")).unwrap();

        let edge_id = EdgeId::new();
        proj.apply(&Event::trigger(EventKind::EdgeCreated {
            edge_id: edge_id.clone(),
            source: a.clone(),
            target: b.clone(),
            type_id: "in_vpc".to_string(),
            properties: HashMap::new(),
        }))
        .unwrap();

        // Delete node a — edge is cascade-deleted
        proj.apply(&Event::trigger(EventKind::NodeDeleted {
            node_id: a.clone(),
        }))
        .unwrap();

        // Edge is now dead
        assert!(!proj.has_edge(&edge_id));
        assert_eq!(proj.edge_count(), 0);
        // b's incoming index is also cleaned
        assert_eq!(proj.incoming_edges(&b).len(), 0);
    }

    #[test]
    fn node_returns_dead_nodes_has_node_does_not() {
        let mut proj = Projection::new();
        let id = NodeId::new();
        proj.apply(&node_created_event(&id, "ec2")).unwrap();
        proj.apply(&Event::trigger(EventKind::NodeDeleted {
            node_id: id.clone(),
        }))
        .unwrap();

        // node() returns it (dead nodes are still in storage)
        assert!(proj.node(&id).is_some());
        assert!(!proj.node(&id).unwrap().is_alive());

        // has_node() returns false (checks alive)
        assert!(!proj.has_node(&id));
    }

    #[test]
    fn no_op_update_returns_false() {
        let mut proj = Projection::new();
        let id = NodeId::new();
        proj.apply(&node_created_with_props(
            &id,
            "ec2",
            HashMap::from([("state".to_string(), Value::String("running".into()))]),
        ))
        .unwrap();

        // Same value — not a change
        let update = Event::trigger(EventKind::NodeUpdated {
            node_id: id.clone(),
            changes: HashMap::from([("state".to_string(), Value::String("running".into()))]),
        });
        let changed = proj.apply(&update).unwrap();
        assert!(!changed); // No actual mutation
    }

    #[test]
    fn node_deletion_cascades_to_edges() {
        let mut proj = Projection::new();
        let a = NodeId::new();
        let b = NodeId::new();
        let c = NodeId::new();
        let e1 = EdgeId::new();
        let e2 = EdgeId::new();

        // Create nodes
        proj.apply(&node_created_event(&a, "ec2")).unwrap();
        proj.apply(&node_created_event(&b, "rds")).unwrap();
        proj.apply(&node_created_event(&c, "vpc")).unwrap();

        // Create edges: a->b, a->c
        proj.apply(&Event::trigger(EventKind::EdgeCreated {
            edge_id: e1.clone(),
            source: a.clone(),
            target: b.clone(),
            type_id: "depends_on".to_string(),
            properties: HashMap::new(),
        })).unwrap();
        proj.apply(&Event::trigger(EventKind::EdgeCreated {
            edge_id: e2.clone(),
            source: a.clone(),
            target: c.clone(),
            type_id: "in_vpc".to_string(),
            properties: HashMap::new(),
        })).unwrap();

        assert_eq!(proj.edge_count(), 2);
        assert_eq!(proj.outgoing_edges(&a).len(), 2);
        assert_eq!(proj.incoming_edges(&b).len(), 1);
        assert_eq!(proj.incoming_edges(&c).len(), 1);

        // Delete node a — both edges should die
        proj.apply(&Event::trigger(EventKind::NodeDeleted {
            node_id: a.clone(),
        })).unwrap();

        assert_eq!(proj.node_count(), 2); // b and c remain
        assert_eq!(proj.edge_count(), 0); // both edges deleted
        assert_eq!(proj.outgoing_edges(&a).len(), 0);
        assert_eq!(proj.incoming_edges(&b).len(), 0);
        assert_eq!(proj.incoming_edges(&c).len(), 0);

        // Edges should be marked dead
        assert!(!proj.edge(&e1).unwrap().is_alive());
        assert!(!proj.edge(&e2).unwrap().is_alive());
    }

    #[test]
    fn node_deletion_cleans_incoming_edges_from_other_nodes() {
        let mut proj = Projection::new();
        let a = NodeId::new();
        let b = NodeId::new();
        let e1 = EdgeId::new();

        proj.apply(&node_created_event(&a, "ec2")).unwrap();
        proj.apply(&node_created_event(&b, "vpc")).unwrap();

        // a -> b
        proj.apply(&Event::trigger(EventKind::EdgeCreated {
            edge_id: e1.clone(),
            source: a.clone(),
            target: b.clone(),
            type_id: "in_vpc".to_string(),
            properties: HashMap::new(),
        })).unwrap();

        // Delete b (the target) — the edge should be cleaned from a's outgoing index too
        proj.apply(&Event::trigger(EventKind::NodeDeleted {
            node_id: b.clone(),
        })).unwrap();

        assert_eq!(proj.edge_count(), 0);
        assert_eq!(proj.outgoing_edges(&a).len(), 0); // a's outgoing cleaned
    }

    #[test]
    fn double_deletion_is_noop() {
        let mut proj = Projection::new();
        let a = NodeId::new();
        proj.apply(&node_created_event(&a, "ec2")).unwrap();

        let del = Event::trigger(EventKind::NodeDeleted { node_id: a.clone() });
        assert!(proj.apply(&del).unwrap()); // First delete: true
        assert!(!proj.apply(&del).unwrap()); // Second delete: false (already dead)
    }
}
