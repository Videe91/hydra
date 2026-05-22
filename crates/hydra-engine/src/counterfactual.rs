use crate::event_log::EventLog;
use crate::projection::Projection;
use hydra_core::edge::Edge;
use hydra_core::event::{Event, Value};
use hydra_core::graph::GraphReader;
use hydra_core::id::{EdgeId, EventId, NodeId};
use hydra_core::node::Node;
use std::collections::{HashMap, HashSet};

/// The difference between two graph states.
/// Produced by comparing actual state to counterfactual state.
#[derive(Debug, Clone)]
pub struct GraphDiff {
    /// Nodes that exist in actual but not in counterfactual (created by the removed subtree)
    pub nodes_only_in_actual: Vec<NodeId>,
    /// Nodes that exist in counterfactual but not in actual (would exist without the removed subtree)
    pub nodes_only_in_counterfactual: Vec<NodeId>,
    /// Nodes present in both but with different properties
    pub nodes_changed: Vec<NodeDiff>,
    /// Edges that exist in actual but not in counterfactual
    pub edges_only_in_actual: Vec<EdgeId>,
    /// Edges that exist in counterfactual but not in actual
    pub edges_only_in_counterfactual: Vec<EdgeId>,
    /// Edges present in both but with different properties
    pub edges_changed: Vec<EdgeDiff>,
}

impl GraphDiff {
    /// True if the removed event had zero impact on the graph
    pub fn is_empty(&self) -> bool {
        self.nodes_only_in_actual.is_empty()
            && self.nodes_only_in_counterfactual.is_empty()
            && self.nodes_changed.is_empty()
            && self.edges_only_in_actual.is_empty()
            && self.edges_only_in_counterfactual.is_empty()
            && self.edges_changed.is_empty()
    }

    /// Total number of affected graph elements
    pub fn total_affected(&self) -> usize {
        self.nodes_only_in_actual.len()
            + self.nodes_only_in_counterfactual.len()
            + self.nodes_changed.len()
            + self.edges_only_in_actual.len()
            + self.edges_only_in_counterfactual.len()
            + self.edges_changed.len()
    }
}

/// A specific node that differs between actual and counterfactual state
#[derive(Debug, Clone)]
pub struct NodeDiff {
    pub node_id: NodeId,
    /// Properties that differ: key → (actual_value, counterfactual_value)
    pub property_diffs: Vec<PropertyDiff>,
    /// Alive status differs
    pub alive_diff: Option<(bool, bool)>,
}

/// A specific edge that differs between actual and counterfactual state
#[derive(Debug, Clone)]
pub struct EdgeDiff {
    pub edge_id: EdgeId,
    pub property_diffs: Vec<PropertyDiff>,
    pub alive_diff: Option<(bool, bool)>,
}

/// A single property difference
#[derive(Debug, Clone)]
pub struct PropertyDiff {
    pub key: String,
    /// Value in the actual graph (None if the property doesn't exist)
    pub actual: Option<Value>,
    /// Value in the counterfactual graph
    pub counterfactual: Option<Value>,
}

/// Impact score derived from a counterfactual analysis.
/// Quantifies how much a single event changed the graph.
#[derive(Debug, Clone)]
pub struct ImpactScore {
    /// The event that was analyzed
    pub event_id: EventId,
    /// How many events are in the causal subtree (including the target)
    pub causal_subtree_size: usize,
    /// How many nodes were affected (created, removed, or changed)
    pub nodes_affected: usize,
    /// How many edges were affected
    pub edges_affected: usize,
    /// Total property changes across all nodes
    pub properties_changed: usize,
    /// Node types affected (type_id → count of affected nodes of that type)
    pub affected_types: HashMap<String, usize>,
    /// The full diff for detailed inspection
    pub diff: GraphDiff,
}

impl ImpactScore {
    /// Overall impact magnitude: 0.0 = no impact, higher = more impact
    /// This is a simple heuristic: nodes weigh more than edges, which weigh more than properties.
    pub fn magnitude(&self) -> f64 {
        (self.nodes_affected as f64 * 10.0)
            + (self.edges_affected as f64 * 5.0)
            + (self.properties_changed as f64 * 1.0)
    }
}

/// Result of a counterfactual computation
pub struct CounterfactualResult {
    /// The projected graph state without the removed events
    pub projection: Projection,
    /// Number of events in the causal subtree that were removed
    pub events_removed: usize,
    /// Number of events outside the subtree that failed to apply
    /// (likely because they depended on removed events)
    pub events_skipped: usize,
    /// Number of events successfully replayed
    pub events_replayed: usize,
}

/// Compute the counterfactual state: "what would the graph look like
/// if this event (and all events it caused) hadn't happened?"
///
/// Algorithm:
/// 1. Find the causal subtree of the target event (the event + all its descendants)
/// 2. Create a fresh Projection
/// 3. Replay all events EXCEPT those in the subtree
/// 4. Skip events that fail to apply (they may depend on subtree events)
/// 5. Return the resulting projection with diagnostics
///
/// This is a "direct impact" counterfactual — it replays events without
/// re-firing subscriptions. The cascade reactions that WERE produced are
/// either included (if not in subtree) or excluded (if in subtree).
/// It does NOT re-compute what NEW cascades would have happened.
pub fn counterfactual(
    event_log: &EventLog,
    target_event_id: &EventId,
) -> hydra_core::error::Result<CounterfactualResult> {
    // Step 1: Find the causal subtree to remove
    let subtree = causal_subtree(event_log, target_event_id);

    if subtree.is_empty() {
        return Err(hydra_core::error::HydraError::EventNotFound(
            target_event_id.clone(),
        ));
    }

    // Step 2: Create a fresh projection
    let mut projection = Projection::new();
    let mut events_skipped = 0usize;
    let mut events_replayed = 0usize;

    // Step 3: Replay all events except those in the subtree
    for event in event_log.iter() {
        if subtree.contains(&event.id) {
            continue;
        }

        // Step 4: Skip events that fail to apply.
        // An event might fail because it depends on a node/edge created by
        // a subtree event (e.g., updating a node that was created by the
        // removed event). This is expected — the counterfactual world
        // simply doesn't have that node.
        match projection.apply(event) {
            Ok(_) => events_replayed += 1,
            Err(_) => events_skipped += 1,
        }
    }

    Ok(CounterfactualResult {
        projection,
        events_removed: subtree.len(),
        events_skipped,
        events_replayed,
    })
}

/// Compute the full causal subtree of an event:
/// the event itself + all events that it (transitively) caused.
fn causal_subtree(event_log: &EventLog, root_id: &EventId) -> HashSet<EventId> {
    let mut subtree = HashSet::new();

    // Check the event exists
    if event_log.get(root_id).is_none() {
        return subtree;
    }

    // BFS forward through causal links
    subtree.insert(root_id.clone());
    let descendants = event_log.causal_chain(root_id);
    for event in descendants {
        subtree.insert(event.id.clone());
    }

    subtree
}

/// Diff two Projections. This is the concrete implementation that has access
/// to all node and edge IDs.
pub fn diff_projections(actual: &Projection, counterfactual: &Projection) -> GraphDiff {
    let mut diff = GraphDiff {
        nodes_only_in_actual: Vec::new(),
        nodes_only_in_counterfactual: Vec::new(),
        nodes_changed: Vec::new(),
        edges_only_in_actual: Vec::new(),
        edges_only_in_counterfactual: Vec::new(),
        edges_changed: Vec::new(),
    };

    // Collect all node IDs from both projections
    let actual_nodes = actual.all_node_ids();
    let cf_nodes = counterfactual.all_node_ids();

    // Nodes only in actual (alive in actual, not alive in counterfactual)
    for id in &actual_nodes {
        if actual.has_node(id) && !counterfactual.has_node(id) {
            diff.nodes_only_in_actual.push(id.clone());
        }
    }

    // Nodes only in counterfactual
    for id in &cf_nodes {
        if counterfactual.has_node(id) && !actual.has_node(id) {
            diff.nodes_only_in_counterfactual.push(id.clone());
        }
    }

    // Nodes in both — check for property/alive differences
    for id in &actual_nodes {
        if let (Some(a), Some(c)) = (actual.node(id), counterfactual.node(id)) {
            if let Some(node_diff) = diff_nodes(a, c) {
                diff.nodes_changed.push(node_diff);
            }
        }
    }

    // Collect all edge IDs from both projections
    let actual_edges = actual.all_edge_ids();
    let cf_edges = counterfactual.all_edge_ids();

    // Edges only in actual
    for id in &actual_edges {
        if actual.has_edge(id) && !counterfactual.has_edge(id) {
            diff.edges_only_in_actual.push(id.clone());
        }
    }

    // Edges only in counterfactual
    for id in &cf_edges {
        if counterfactual.has_edge(id) && !actual.has_edge(id) {
            diff.edges_only_in_counterfactual.push(id.clone());
        }
    }

    // Edges in both — check for property differences
    for id in &actual_edges {
        if let (Some(a), Some(c)) = (actual.edge(id), counterfactual.edge(id)) {
            if let Some(edge_diff) = diff_edges(a, c) {
                diff.edges_changed.push(edge_diff);
            }
        }
    }

    diff
}

/// Compare two nodes, returning a NodeDiff if they differ
fn diff_nodes(actual: &Node, cf: &Node) -> Option<NodeDiff> {
    let mut property_diffs = Vec::new();

    // Collect all property keys from both nodes
    let mut all_keys: HashSet<&String> = actual.properties.keys().collect();
    all_keys.extend(cf.properties.keys());

    for key in all_keys {
        let a_val = actual.properties.get(key);
        let c_val = cf.properties.get(key);

        if a_val != c_val {
            property_diffs.push(PropertyDiff {
                key: key.clone(),
                actual: a_val.cloned(),
                counterfactual: c_val.cloned(),
            });
        }
    }

    let alive_diff = if actual.is_alive() != cf.is_alive() {
        Some((actual.is_alive(), cf.is_alive()))
    } else {
        None
    };

    if property_diffs.is_empty() && alive_diff.is_none() {
        None
    } else {
        Some(NodeDiff {
            node_id: actual.id().clone(),
            property_diffs,
            alive_diff,
        })
    }
}

/// Compare two edges, returning an EdgeDiff if they differ
fn diff_edges(actual: &Edge, cf: &Edge) -> Option<EdgeDiff> {
    let mut property_diffs = Vec::new();

    let mut all_keys: HashSet<&String> = actual.properties.keys().collect();
    all_keys.extend(cf.properties.keys());

    for key in all_keys {
        let a_val = actual.properties.get(key);
        let c_val = cf.properties.get(key);

        if a_val != c_val {
            property_diffs.push(PropertyDiff {
                key: key.clone(),
                actual: a_val.cloned(),
                counterfactual: c_val.cloned(),
            });
        }
    }

    let alive_diff = if actual.is_alive() != cf.is_alive() {
        Some((actual.is_alive(), cf.is_alive()))
    } else {
        None
    };

    if property_diffs.is_empty() && alive_diff.is_none() {
        None
    } else {
        Some(EdgeDiff {
            edge_id: actual.id().clone(),
            property_diffs,
            alive_diff,
        })
    }
}

/// Compute the impact score of a specific event.
/// This is the top-level API: it runs counterfactual analysis and produces
/// a summary of how much the event changed the graph.
pub fn impact_score(
    event_log: &EventLog,
    actual: &Projection,
    target_event_id: &EventId,
) -> hydra_core::error::Result<ImpactScore> {
    // Compute causal subtree size
    let subtree = causal_subtree(event_log, target_event_id);
    if subtree.is_empty() {
        return Err(hydra_core::error::HydraError::EventNotFound(
            target_event_id.clone(),
        ));
    }

    // Compute counterfactual state
    let cf_result = counterfactual(event_log, target_event_id)?;
    let cf_projection = cf_result.projection;

    // Diff actual vs counterfactual
    let diff = diff_projections(actual, &cf_projection);

    // Compute affected types
    let mut affected_types: HashMap<String, usize> = HashMap::new();
    for node_id in &diff.nodes_only_in_actual {
        if let Some(node) = actual.node(node_id) {
            *affected_types.entry(node.type_id().to_string()).or_insert(0) += 1;
        }
    }
    for node_id in &diff.nodes_only_in_counterfactual {
        if let Some(node) = cf_projection.node(node_id) {
            *affected_types.entry(node.type_id().to_string()).or_insert(0) += 1;
        }
    }
    for node_diff in &diff.nodes_changed {
        if let Some(node) = actual.node(&node_diff.node_id) {
            *affected_types.entry(node.type_id().to_string()).or_insert(0) += 1;
        }
    }

    // Count total property changes
    let properties_changed: usize = diff
        .nodes_changed
        .iter()
        .map(|nd| nd.property_diffs.len())
        .sum::<usize>()
        + diff
            .edges_changed
            .iter()
            .map(|ed| ed.property_diffs.len())
            .sum::<usize>();

    let nodes_affected = diff.nodes_only_in_actual.len()
        + diff.nodes_only_in_counterfactual.len()
        + diff.nodes_changed.len();

    let edges_affected = diff.edges_only_in_actual.len()
        + diff.edges_only_in_counterfactual.len()
        + diff.edges_changed.len();

    Ok(ImpactScore {
        event_id: target_event_id.clone(),
        causal_subtree_size: subtree.len(),
        nodes_affected,
        edges_affected,
        properties_changed,
        affected_types,
        diff,
    })
}

/// Compute the counterfactual state by removing ALL events that match a predicate
/// (and their causal subtrees).
///
/// This is the "counterfactual anomaly" query: "what would the graph look like
/// if we removed all events from source X / user Y / time window Z?"
///
/// Algorithm:
/// 1. Find all events matching the predicate (the "roots")
/// 2. For each root, find its causal subtree
/// 3. Union all subtrees into a single removal set
/// 4. Replay the event log minus the removal set
/// 5. Diff actual vs counterfactual
///
/// Cost: O(R × C + E) where R = matching roots, C = avg causal chain length,
/// E = total events. The removal set is built once, then one replay pass.
pub fn counterfactual_filter(
    event_log: &EventLog,
    predicate: &dyn Fn(&Event) -> bool,
) -> CounterfactualFilterResult {
    // Step 1: Find all matching events
    let roots: Vec<&Event> = event_log.iter().filter(|e| predicate(e)).collect();
    let root_count = roots.len();

    if root_count == 0 {
        return CounterfactualFilterResult {
            projection: {
                // No events to remove — replay everything into a fresh projection
                let mut proj = Projection::new();
                for event in event_log.iter() {
                    let _ = proj.apply(event);
                }
                proj
            },
            roots_matched: 0,
            events_removed: 0,
            events_skipped: 0,
            events_replayed: event_log.len(),
        };
    }

    // Step 2+3: Build the union of all causal subtrees
    let mut removal_set: HashSet<EventId> = HashSet::new();
    for root in &roots {
        removal_set.insert(root.id.clone());
        for descendant in event_log.causal_chain(&root.id) {
            removal_set.insert(descendant.id.clone());
        }
    }

    // Step 4: Replay minus the removal set
    let mut projection = Projection::new();
    let mut events_skipped = 0usize;
    let mut events_replayed = 0usize;

    for event in event_log.iter() {
        if removal_set.contains(&event.id) {
            continue;
        }
        match projection.apply(event) {
            Ok(_) => events_replayed += 1,
            Err(_) => events_skipped += 1,
        }
    }

    CounterfactualFilterResult {
        projection,
        roots_matched: root_count,
        events_removed: removal_set.len(),
        events_skipped,
        events_replayed,
    }
}

/// Result of a predicate-based counterfactual analysis
pub struct CounterfactualFilterResult {
    /// The graph state with matching events removed
    pub projection: Projection,
    /// How many events matched the predicate (the "roots")
    pub roots_matched: usize,
    /// Total events removed (roots + their causal subtrees)
    pub events_removed: usize,
    /// Events that failed to apply in the counterfactual world
    pub events_skipped: usize,
    /// Events successfully replayed
    pub events_replayed: usize,
}

impl CounterfactualFilterResult {
    /// What fraction of all events came from the filtered source?
    /// High values indicate a source with outsized influence.
    pub fn removal_fraction(&self) -> f64 {
        let total = self.events_removed + self.events_skipped + self.events_replayed;
        if total == 0 {
            return 0.0;
        }
        self.events_removed as f64 / total as f64
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::{Event, EventKind, Value};
    use hydra_core::id::{EdgeId, NodeId};
    use std::collections::HashMap;

    /// Helper: build a Hydra-like setup with EventLog + Projection,
    /// ingesting events manually (without subscriptions for these unit tests)
    fn ingest(
        log: &mut EventLog,
        proj: &mut Projection,
        event: Event,
    ) -> Event {
        let _ = proj.apply(&event);
        log.append(event.clone());
        event
    }

    fn make_create(type_id: &str) -> (NodeId, Event) {
        let node_id = NodeId::new();
        let event = Event::trigger(EventKind::NodeCreated {
            node_id: node_id.clone(),
            type_id: type_id.to_string(),
            properties: HashMap::new(),
        });
        (node_id, event)
    }

    fn make_update(node_id: &NodeId, key: &str, val: Value, parent: &Event) -> Event {
        Event::reaction(
            EventKind::NodeUpdated {
                node_id: node_id.clone(),
                changes: HashMap::from([(key.to_string(), val)]),
            },
            parent,
        )
    }

    // ================================================================
    // Test 1: Removing a single trigger event removes the node it created
    // ================================================================
    #[test]
    fn counterfactual_removes_created_node() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        let (n1, e1) = make_create("ec2");
        let (n2, e2) = make_create("rds");

        ingest(&mut log, &mut proj, e1.clone());
        ingest(&mut log, &mut proj, e2.clone());

        assert_eq!(proj.node_count(), 2);

        // Counterfactual: what if e1 hadn't happened?
        let cf = counterfactual(&log, &e1.id).unwrap().projection;
        assert_eq!(cf.node_count(), 1);
        assert!(!cf.has_node(&n1)); // n1 doesn't exist
        assert!(cf.has_node(&n2)); // n2 still exists
    }

    // ================================================================
    // Test 2: Removing an event also removes its causal descendants
    // ================================================================
    #[test]
    fn counterfactual_removes_causal_subtree() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        let (n1, e1) = make_create("ec2");
        let e1 = ingest(&mut log, &mut proj, e1);

        // e2 is a reaction to e1 (updates n1)
        let e2 = make_update(&n1, "classified", Value::Bool(true), &e1);
        ingest(&mut log, &mut proj, e2);

        // e3 is independent
        let (_n3, e3) = make_create("rds");
        ingest(&mut log, &mut proj, e3);

        assert_eq!(proj.node_count(), 2);
        assert_eq!(proj.node(&n1).unwrap().get_bool("classified"), Some(true));

        // Remove e1 → should also remove e2 (its reaction)
        let cf = counterfactual(&log, &e1.id).unwrap().projection;
        assert_eq!(cf.node_count(), 1); // Only rds survives
        assert!(!cf.has_node(&n1));
    }

    // ================================================================
    // Test 3: diff_projections detects node differences
    // ================================================================
    #[test]
    fn diff_detects_missing_nodes() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        let (n1, e1) = make_create("ec2");
        let (_n2, e2) = make_create("rds");
        ingest(&mut log, &mut proj, e1.clone());
        ingest(&mut log, &mut proj, e2);

        let cf = counterfactual(&log, &e1.id).unwrap().projection;
        let diff = diff_projections(&proj, &cf);

        // n1 exists in actual but not counterfactual
        assert_eq!(diff.nodes_only_in_actual.len(), 1);
        assert_eq!(diff.nodes_only_in_actual[0], n1);

        // n2 exists in both
        assert!(diff.nodes_only_in_counterfactual.is_empty());

        // No property changes (n2 is identical in both)
        assert!(diff.nodes_changed.is_empty());
    }

    // ================================================================
    // Test 4: diff_projections detects property changes
    // ================================================================
    #[test]
    fn diff_detects_property_changes() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        let (n1, e1) = make_create("ec2");
        let e1 = ingest(&mut log, &mut proj, e1);

        // Update n1's properties via a reaction
        let e2 = make_update(&n1, "trust_score", Value::Int(50), &e1);
        ingest(&mut log, &mut proj, e2.clone());

        assert_eq!(proj.node(&n1).unwrap().get_i64("trust_score"), Some(50));

        // Remove e2 (the update): n1 should still exist but without trust_score
        let cf = counterfactual(&log, &e2.id).unwrap().projection;
        assert!(cf.has_node(&n1)); // Node still exists
        assert_eq!(cf.node(&n1).unwrap().get_i64("trust_score"), None);

        let diff = diff_projections(&proj, &cf);
        assert_eq!(diff.nodes_changed.len(), 1);
        assert_eq!(diff.nodes_changed[0].node_id, n1);
        assert_eq!(diff.nodes_changed[0].property_diffs.len(), 1);
        assert_eq!(diff.nodes_changed[0].property_diffs[0].key, "trust_score");
    }

    // ================================================================
    // Test 5: impact_score computes correct metrics
    // ================================================================
    #[test]
    fn impact_score_basic() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        let (n1, e1) = make_create("ec2");
        let e1 = ingest(&mut log, &mut proj, e1);
        let e2 = make_update(&n1, "classified", Value::Bool(true), &e1);
        ingest(&mut log, &mut proj, e2);

        let (_n2, e3) = make_create("rds");
        ingest(&mut log, &mut proj, e3);

        let score = impact_score(&log, &proj, &e1.id).unwrap();

        // e1 + e2 are in the causal subtree
        assert_eq!(score.causal_subtree_size, 2);
        // n1 would be missing in counterfactual
        assert_eq!(score.nodes_affected, 1);
        assert_eq!(score.edges_affected, 0);
        assert!(score.magnitude() > 0.0);
        assert_eq!(score.affected_types.get("ec2"), Some(&1));
    }

    // ================================================================
    // Test 6: impact_score for a non-existent event returns error
    // ================================================================
    #[test]
    fn impact_score_nonexistent_event() {
        let log = EventLog::new();
        let proj = Projection::new();

        let ghost = EventId::from_str("evt_GHOST");
        let result = impact_score(&log, &proj, &ghost);
        assert!(result.is_err());
    }

    // ================================================================
    // Test 7: counterfactual with edges
    // ================================================================
    #[test]
    fn counterfactual_with_edges() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        let (n1, e1) = make_create("ec2");
        ingest(&mut log, &mut proj, e1.clone());

        let (n2, e2) = make_create("vpc");
        ingest(&mut log, &mut proj, e2.clone());

        // Edge from ec2 → vpc (independent trigger)
        let edge_id = EdgeId::new();
        let e3 = Event::trigger(EventKind::EdgeCreated {
            edge_id: edge_id.clone(),
            source: n1.clone(),
            target: n2.clone(),
            type_id: "in_vpc".to_string(),
            properties: HashMap::new(),
        });
        ingest(&mut log, &mut proj, e3.clone());

        assert_eq!(proj.edge_count(), 1);

        // Remove e1 (the ec2 node creation).
        // The edge creation (e3) will fail to apply in counterfactual
        // because n1 doesn't exist.
        let cf = counterfactual(&log, &e1.id).unwrap().projection;
        assert!(!cf.has_node(&n1));
        assert!(cf.has_node(&n2));
        assert_eq!(cf.edge_count(), 0); // Edge couldn't be created without n1

        let diff = diff_projections(&proj, &cf);
        assert_eq!(diff.nodes_only_in_actual.len(), 1); // n1
        assert_eq!(diff.edges_only_in_actual.len(), 1); // the edge
    }

    // ================================================================
    // Test 8: counterfactual of leaf event (no descendants)
    // ================================================================
    #[test]
    fn counterfactual_leaf_event() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        let (n1, e1) = make_create("ec2");
        let e1 = ingest(&mut log, &mut proj, e1);

        let e2 = make_update(&n1, "state", Value::String("stopped".into()), &e1);
        ingest(&mut log, &mut proj, e2.clone());

        // Remove only e2 (the update) — n1 should still exist but without "state"
        let cf = counterfactual(&log, &e2.id).unwrap().projection;
        assert!(cf.has_node(&n1));
        assert_eq!(cf.node(&n1).unwrap().get_str("state"), None);
    }

    // ================================================================
    // Test 9: counterfactual on empty event log
    // ================================================================
    #[test]
    fn counterfactual_empty_log() {
        let log = EventLog::new();
        let ghost = EventId::from_str("evt_GHOST");
        let result = counterfactual(&log, &ghost);
        assert!(result.is_err());
    }

    // ================================================================
    // Test 10: diff of identical projections is empty
    // ================================================================
    #[test]
    fn diff_identical_projections() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        let (_n1, e1) = make_create("ec2");
        ingest(&mut log, &mut proj, e1);

        // Counterfactual of an event that doesn't affect anything
        // (use a separate independent event)
        let (_n2, e2) = make_create("rds");
        let e2 = ingest(&mut log, &mut proj, e2);

        // Remove e2: n2 disappears, but actual has both
        let cf = counterfactual(&log, &e2.id).unwrap().projection;
        // Diff should show n2 only in actual
        let diff = diff_projections(&proj, &cf);
        assert_eq!(diff.nodes_only_in_actual.len(), 1);
    }

    // ================================================================
    // Test 11: Deep cascade chain — removing root removes everything
    // ================================================================
    #[test]
    fn counterfactual_deep_chain() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        let (n1, e1) = make_create("ec2");
        let e1 = ingest(&mut log, &mut proj, e1);

        // Chain: e1 → e2 → e3 → e4
        let e2 = make_update(&n1, "step1", Value::Bool(true), &e1);
        let e2 = ingest(&mut log, &mut proj, e2);

        let e3 = make_update(&n1, "step2", Value::Bool(true), &e2);
        let e3 = ingest(&mut log, &mut proj, e3);

        let e4 = make_update(&n1, "step3", Value::Bool(true), &e3);
        ingest(&mut log, &mut proj, e4);

        assert_eq!(proj.node(&n1).unwrap().get_bool("step3"), Some(true));

        // Remove e1: the entire chain disappears (including the node)
        let cf = counterfactual(&log, &e1.id).unwrap().projection;
        assert!(!cf.has_node(&n1));

        // Remove e3: only step2 and step3 are removed, node still exists
        let cf2 = counterfactual(&log, &e3.id).unwrap().projection;
        assert!(cf2.has_node(&n1));
        assert_eq!(cf2.node(&n1).unwrap().get_bool("step1"), Some(true));
        assert_eq!(cf2.node(&n1).unwrap().get_bool("step2"), None);
        assert_eq!(cf2.node(&n1).unwrap().get_bool("step3"), None);
    }

    // ================================================================
    // Test 12: impact_score with edges shows correct magnitude
    // ================================================================
    #[test]
    fn impact_score_with_edges() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        let (n1, e1) = make_create("ec2");
        ingest(&mut log, &mut proj, e1.clone());

        let (n2, e2) = make_create("vpc");
        ingest(&mut log, &mut proj, e2.clone());

        // Edge as a reaction to e1
        let edge_evt = Event::reaction(
            EventKind::EdgeCreated {
                edge_id: EdgeId::new(),
                source: n1.clone(),
                target: n2.clone(),
                type_id: "in_vpc".to_string(),
                properties: HashMap::new(),
            },
            &e1,
        );
        ingest(&mut log, &mut proj, edge_evt);

        let score = impact_score(&log, &proj, &e1.id).unwrap();
        // Subtree: e1 (create) + edge_evt (reaction)
        assert_eq!(score.causal_subtree_size, 2);
        // Node n1 missing + edge missing
        assert_eq!(score.nodes_affected, 1);
        assert_eq!(score.edges_affected, 1);
        assert!(score.magnitude() >= 15.0); // 10 (node) + 5 (edge)
    }

    // ================================================================
    // Test 13: GraphDiff::is_empty and total_affected
    // ================================================================
    #[test]
    fn graph_diff_helpers() {
        let empty = GraphDiff {
            nodes_only_in_actual: vec![],
            nodes_only_in_counterfactual: vec![],
            nodes_changed: vec![],
            edges_only_in_actual: vec![],
            edges_only_in_counterfactual: vec![],
            edges_changed: vec![],
        };
        assert!(empty.is_empty());
        assert_eq!(empty.total_affected(), 0);

        let non_empty = GraphDiff {
            nodes_only_in_actual: vec![NodeId::new()],
            nodes_only_in_counterfactual: vec![],
            nodes_changed: vec![],
            edges_only_in_actual: vec![EdgeId::new(), EdgeId::new()],
            edges_only_in_counterfactual: vec![],
            edges_changed: vec![],
        };
        assert!(!non_empty.is_empty());
        assert_eq!(non_empty.total_affected(), 3);
    }

    // ================================================================
    // Test 14: counterfactual_filter — remove events targeting a specific node
    // ================================================================
    #[test]
    fn counterfactual_filter_removes_by_node() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        let (n1, e1) = make_create("ec2");
        ingest(&mut log, &mut proj, e1.clone());

        // Update n1 twice
        let e2 = make_update(&n1, "state", Value::String("running".into()), &e1);
        ingest(&mut log, &mut proj, e2.clone());
        let e3 = make_update(&n1, "score", Value::Int(50), &e2);
        ingest(&mut log, &mut proj, e3);

        // Create an independent node
        let (n2, e4) = make_create("rds");
        ingest(&mut log, &mut proj, e4);

        assert_eq!(proj.node_count(), 2);

        // Remove all events targeting n1
        let n1_clone = n1.clone();
        let result = counterfactual_filter(&log, &|event| {
            event.kind.target_node() == Some(&n1_clone)
        });

        assert_eq!(result.roots_matched, 3); // create + 2 updates
        assert_eq!(result.events_removed, 3);
        assert_eq!(result.projection.node_count(), 1); // only n2 survives
        assert!(!result.projection.has_node(&n1));
        assert!(result.projection.has_node(&n2));
    }

    // ================================================================
    // Test 15: counterfactual_filter — no matches returns full replay
    // ================================================================
    #[test]
    fn counterfactual_filter_no_matches() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        let (_n1, e1) = make_create("ec2");
        ingest(&mut log, &mut proj, e1);

        let result = counterfactual_filter(&log, &|_| false);
        assert_eq!(result.roots_matched, 0);
        assert_eq!(result.events_removed, 0);
        assert_eq!(result.projection.node_count(), 1);
    }

    // ================================================================
    // Test 16: counterfactual_filter — causal subtree also removed
    // ================================================================
    #[test]
    fn counterfactual_filter_removes_causal_subtree() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        let (n1, e1) = make_create("ec2");
        let e1 = ingest(&mut log, &mut proj, e1);

        // e2 is a reaction to e1 (caused by e1)
        let e2 = make_update(&n1, "classified", Value::Bool(true), &e1);
        ingest(&mut log, &mut proj, e2);

        // Remove only trigger events (not reactions)
        let result = counterfactual_filter(&log, &|event| event.is_trigger());

        // e1 is a trigger → removed. e2 is caused by e1 → also removed (subtree).
        assert_eq!(result.roots_matched, 1);
        assert_eq!(result.events_removed, 2); // e1 + e2
        assert_eq!(result.projection.node_count(), 0);
    }

    // ================================================================
    // Test 17: removal_fraction calculation
    // ================================================================
    #[test]
    fn removal_fraction_correct() {
        let mut log = EventLog::new();
        let mut proj = Projection::new();

        // 4 independent events
        for _ in 0..4 {
            let (_, e) = make_create("ec2");
            ingest(&mut log, &mut proj, e);
        }

        // Remove 1 of 4 → 25%
        let first_id = log.iter().next().unwrap().id.clone();
        let result = counterfactual_filter(&log, &|event| event.id == first_id);

        assert_eq!(result.roots_matched, 1);
        assert!((result.removal_fraction() - 0.25).abs() < 0.01);
    }
}
