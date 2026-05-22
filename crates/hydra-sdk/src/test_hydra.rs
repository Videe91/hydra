use hydra_core::event::{EventKind, Value};
use hydra_core::graph::GraphReader;
use hydra_core::id::{EdgeId, NodeId};
use hydra_core::subscription::Subscription;
use hydra_engine::cascade::CascadeResult;
use hydra_engine::hydra::Hydra;
use std::collections::HashMap;

/// Test harness for Hydra. Provides helpers for writing concise, readable tests.
///
/// ```ignore
/// let mut t = TestHydra::new();
/// t.register(my_subscription);
/// let node_id = t.create_node("ec2", props![("state", "running")]);
/// t.assert_property(&node_id, "classified", Value::Bool(true));
/// ```
pub struct TestHydra {
    hydra: Hydra,
    /// The result of the last ingest operation
    last_result: Option<CascadeResult>,
}

impl TestHydra {
    pub fn new() -> Self {
        Self {
            hydra: Hydra::new(),
            last_result: None,
        }
    }

    /// Register a subscription
    pub fn register(&mut self, sub: Subscription) {
        self.hydra.register(sub);
    }

    /// Ingest an event kind and store the result
    pub fn ingest(&mut self, kind: EventKind) -> &CascadeResult {
        let result = self.hydra.ingest(kind).expect("ingest failed");
        self.last_result = Some(result);
        self.last_result.as_ref().unwrap()
    }

    /// Create a node with properties. Returns the NodeId.
    pub fn create_node(
        &mut self,
        type_id: &str,
        properties: HashMap<String, Value>,
    ) -> NodeId {
        let node_id = NodeId::new();
        self.ingest(EventKind::NodeCreated {
            node_id: node_id.clone(),
            type_id: type_id.to_string(),
            properties,
        });
        node_id
    }

    /// Create a node with no properties
    pub fn create_bare_node(&mut self, type_id: &str) -> NodeId {
        self.create_node(type_id, HashMap::new())
    }

    /// Create an edge between two nodes. Returns the EdgeId.
    pub fn create_edge(
        &mut self,
        source: &NodeId,
        target: &NodeId,
        type_id: &str,
        properties: HashMap<String, Value>,
    ) -> EdgeId {
        let edge_id = EdgeId::new();
        self.ingest(EventKind::EdgeCreated {
            edge_id: edge_id.clone(),
            source: source.clone(),
            target: target.clone(),
            type_id: type_id.to_string(),
            properties,
        });
        edge_id
    }

    /// Create a bare edge (no properties)
    pub fn create_bare_edge(&mut self, source: &NodeId, target: &NodeId, type_id: &str) -> EdgeId {
        self.create_edge(source, target, type_id, HashMap::new())
    }

    /// Update a node's properties
    pub fn update_node(&mut self, node_id: &NodeId, changes: HashMap<String, Value>) {
        self.ingest(EventKind::NodeUpdated {
            node_id: node_id.clone(),
            changes,
        });
    }

    /// Delete a node
    pub fn delete_node(&mut self, node_id: &NodeId) {
        self.ingest(EventKind::NodeDeleted {
            node_id: node_id.clone(),
        });
    }

    /// Emit a signal
    pub fn signal(
        &mut self,
        name: &str,
        source: &NodeId,
        payload: HashMap<String, Value>,
    ) {
        self.ingest(EventKind::Signal {
            name: name.to_string(),
            source: source.clone(),
            payload,
        });
    }

    // === Queries ===

    /// Get the graph reader
    pub fn graph(&self) -> &dyn GraphReader {
        self.hydra.graph()
    }

    /// Get the last cascade result
    pub fn last_result(&self) -> Option<&CascadeResult> {
        self.last_result.as_ref()
    }

    /// How many events were in the last cascade
    pub fn last_event_count(&self) -> usize {
        self.last_result.as_ref().map_or(0, |r| r.events.len())
    }

    /// Was the last cascade truncated?
    pub fn last_truncated(&self) -> bool {
        self.last_result.as_ref().map_or(false, |r| r.truncated)
    }

    // === Assertions ===

    /// Assert a node exists and is alive
    pub fn assert_node_exists(&self, id: &NodeId) {
        assert!(
            self.hydra.graph().has_node(id),
            "Expected node {} to exist and be alive",
            id
        );
    }

    /// Assert a node does NOT exist (or is dead)
    pub fn assert_node_absent(&self, id: &NodeId) {
        assert!(
            !self.hydra.graph().has_node(id),
            "Expected node {} to not exist or be dead",
            id
        );
    }

    /// Assert a node property has a specific value
    pub fn assert_property(&self, node_id: &NodeId, key: &str, expected: Value) {
        let node = self
            .hydra
            .graph()
            .node(node_id)
            .unwrap_or_else(|| panic!("Node {} not found", node_id));
        let actual = node
            .get(key)
            .unwrap_or_else(|| panic!("Property '{}' not found on node {}", key, node_id));
        assert_eq!(
            *actual, expected,
            "Property '{}' on node {}: expected {:?}, got {:?}",
            key, node_id, expected, actual
        );
    }

    /// Assert the node count
    pub fn assert_node_count(&self, expected: usize) {
        let actual = self.hydra.graph().node_count();
        assert_eq!(
            actual, expected,
            "Expected {} nodes, got {}",
            expected, actual
        );
    }

    /// Assert the edge count
    pub fn assert_edge_count(&self, expected: usize) {
        let actual = self.hydra.graph().edge_count();
        assert_eq!(
            actual, expected,
            "Expected {} edges, got {}",
            expected, actual
        );
    }

    /// Assert the total events stored
    pub fn assert_total_events(&self, expected: usize) {
        let actual = self.hydra.total_events();
        assert_eq!(
            actual, expected,
            "Expected {} total events, got {}",
            expected, actual
        );
    }

    /// Assert how many events the last cascade produced
    pub fn assert_last_event_count(&self, expected: usize) {
        let actual = self.last_event_count();
        assert_eq!(
            actual, expected,
            "Expected last cascade to produce {} events, got {}",
            expected, actual
        );
    }

    /// Assert a node has a specific type
    pub fn assert_node_type(&self, node_id: &NodeId, expected_type: &str) {
        let node = self
            .hydra
            .graph()
            .node(node_id)
            .unwrap_or_else(|| panic!("Node {} not found", node_id));
        assert_eq!(
            node.type_id(),
            expected_type,
            "Node {} type: expected '{}', got '{}'",
            node_id,
            expected_type,
            node.type_id()
        );
    }

    /// Assert outgoing edge count from a node
    pub fn assert_outgoing_count(&self, node_id: &NodeId, expected: usize) {
        let actual = self.hydra.graph().outgoing_edges(node_id).len();
        assert_eq!(
            actual, expected,
            "Node {} outgoing edges: expected {}, got {}",
            node_id, expected, actual
        );
    }

    /// Assert incoming edge count to a node
    pub fn assert_incoming_count(&self, node_id: &NodeId, expected: usize) {
        let actual = self.hydra.graph().incoming_edges(node_id).len();
        assert_eq!(
            actual, expected,
            "Node {} incoming edges: expected {}, got {}",
            node_id, expected, actual
        );
    }

    /// Access the underlying Hydra for advanced operations
    pub fn hydra(&self) -> &Hydra {
        &self.hydra
    }

    /// Access the underlying Hydra mutably
    pub fn hydra_mut(&mut self) -> &mut Hydra {
        &mut self.hydra
    }
}

impl Default for TestHydra {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper macro for building property maps concisely
#[macro_export]
macro_rules! props {
    () => { std::collections::HashMap::new() };
    ($($key:expr => $val:expr),+ $(,)?) => {{
        let mut map = std::collections::HashMap::new();
        $(map.insert($key.to_string(), $val);)+
        map
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::{Event, EventKind, Value};
    use hydra_core::subscription::{EventFilter, Subscription, SubscriptionHandler};

    struct AutoClassify;
    impl SubscriptionHandler for AutoClassify {
        fn handle(
            &self,
            event: &Event,
            _graph: &dyn hydra_core::graph::GraphReader,
        ) -> Vec<EventKind> {
            if let EventKind::NodeCreated { node_id, type_id, .. } = &event.kind {
                vec![EventKind::NodeUpdated {
                    node_id: node_id.clone(),
                    changes: HashMap::from([
                        ("classified".to_string(), Value::Bool(true)),
                        ("category".to_string(), Value::String(type_id.clone())),
                    ]),
                }]
            } else {
                vec![]
            }
        }
    }

    #[test]
    fn test_hydra_basic_flow() {
        let mut t = TestHydra::new();

        let ec2 = t.create_bare_node("ec2_instance");
        t.assert_node_exists(&ec2);
        t.assert_node_type(&ec2, "ec2_instance");
        t.assert_node_count(1);
    }

    #[test]
    fn test_hydra_with_subscription() {
        let mut t = TestHydra::new();
        t.register(Subscription::new(
            "auto_classify",
            EventFilter::NodeCreated,
            100,
            Box::new(AutoClassify),
        ));

        let ec2 = t.create_bare_node("ec2_instance");
        t.assert_property(&ec2, "classified", Value::Bool(true));
        t.assert_property(&ec2, "category", Value::String("ec2_instance".into()));
        t.assert_last_event_count(2); // trigger + reaction
    }

    #[test]
    fn test_hydra_edges() {
        let mut t = TestHydra::new();

        let ec2 = t.create_bare_node("ec2");
        let vpc = t.create_bare_node("vpc");
        let sg = t.create_bare_node("sg");

        t.create_bare_edge(&ec2, &vpc, "in_vpc");
        t.create_bare_edge(&ec2, &sg, "uses_sg");

        t.assert_node_count(3);
        t.assert_edge_count(2);
        t.assert_outgoing_count(&ec2, 2);
        t.assert_incoming_count(&vpc, 1);
        t.assert_incoming_count(&sg, 1);
    }

    #[test]
    fn test_hydra_update_and_delete() {
        let mut t = TestHydra::new();

        let node = t.create_node("ec2", props!("state" => Value::String("running".into())));
        t.assert_property(&node, "state", Value::String("running".into()));

        t.update_node(&node, props!("state" => Value::String("stopped".into())));
        t.assert_property(&node, "state", Value::String("stopped".into()));

        t.delete_node(&node);
        t.assert_node_absent(&node);
        t.assert_node_count(0);
    }

    #[test]
    fn test_hydra_signal() {
        let mut t = TestHydra::new();

        struct OnSignal;
        impl SubscriptionHandler for OnSignal {
            fn handle(
                &self,
                event: &Event,
                _graph: &dyn hydra_core::graph::GraphReader,
            ) -> Vec<EventKind> {
                if let EventKind::Signal { source, .. } = &event.kind {
                    vec![EventKind::NodeUpdated {
                        node_id: source.clone(),
                        changes: HashMap::from([("signaled".to_string(), Value::Bool(true))]),
                    }]
                } else {
                    vec![]
                }
            }
        }

        t.register(Subscription::new(
            "on_alert",
            EventFilter::SignalName("alert".into()),
            100,
            Box::new(OnSignal),
        ));

        let node = t.create_bare_node("ec2");
        t.signal("alert", &node, HashMap::new());
        t.assert_property(&node, "signaled", Value::Bool(true));
    }

    #[test]
    fn props_macro() {
        let empty: HashMap<String, Value> = props!();
        assert!(empty.is_empty());

        let filled = props!(
            "name" => Value::String("test".into()),
            "count" => Value::Int(42),
        );
        assert_eq!(filled.len(), 2);
        assert_eq!(filled.get("count").and_then(|v| v.as_i64()), Some(42));
    }

    #[test]
    fn total_events_accumulate() {
        let mut t = TestHydra::new();
        t.create_bare_node("a");
        t.create_bare_node("b");
        t.create_bare_node("c");
        t.assert_total_events(3);
    }
}
