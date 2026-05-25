use crate::edge::Edge;
use crate::id::{EdgeId, NodeId};
use crate::node::Node;

/// Read-only view of the graph. All queries and subscriptions read through this trait.
///
/// Design principle: NO MUTATION METHODS. The graph is mutated ONLY through events
/// processed by the cascade engine. This trait provides read access to the
/// materialized projection.
///
/// This separation ensures that:
/// 1. All mutations are captured as events (auditability)
/// 2. The projection is always consistent (no partial updates)
/// 3. Subscriptions can read but not write (preventing cascade loops from side effects)
pub trait GraphReader {
    // === Point lookups ===

    /// Get a node by ID. Returns None if not found or deleted.
    fn node(&self, id: &NodeId) -> Option<&Node>;

    /// Get an edge by ID. Returns None if not found or deleted.
    fn edge(&self, id: &EdgeId) -> Option<&Edge>;

    /// Check if a node exists and is alive
    fn has_node(&self, id: &NodeId) -> bool {
        self.node(id).map_or(false, |n| n.is_alive())
    }

    /// Check if an edge exists and is alive
    fn has_edge(&self, id: &EdgeId) -> bool {
        self.edge(id).map_or(false, |e| e.is_alive())
    }

    // === Type-based lookups ===

    /// Get all alive nodes of a specific type
    fn nodes_by_type(&self, type_id: &str) -> Vec<&Node>;

    /// Get all alive edges of a specific type
    fn edges_by_type(&self, type_id: &str) -> Vec<&Edge>;

    /// Count alive nodes of a specific type
    fn count_nodes_by_type(&self, type_id: &str) -> usize {
        self.nodes_by_type(type_id).len()
    }

    // === Topology traversal ===

    /// Get all outgoing edges from a node (edges where node is the source)
    fn outgoing_edges(&self, node_id: &NodeId) -> Vec<&Edge>;

    /// Get all incoming edges to a node (edges where node is the target)
    fn incoming_edges(&self, node_id: &NodeId) -> Vec<&Edge>;

    /// Get outgoing edges filtered by edge type
    fn outgoing_edges_of_type(&self, node_id: &NodeId, edge_type: &str) -> Vec<&Edge> {
        self.outgoing_edges(node_id)
            .into_iter()
            .filter(|e| e.type_id() == edge_type)
            .collect()
    }

    /// Get incoming edges filtered by edge type
    fn incoming_edges_of_type(&self, node_id: &NodeId, edge_type: &str) -> Vec<&Edge> {
        self.incoming_edges(node_id)
            .into_iter()
            .filter(|e| e.type_id() == edge_type)
            .collect()
    }

    /// Get direct neighbor nodes via outgoing edges
    fn outgoing_neighbors(&self, node_id: &NodeId) -> Vec<&Node> {
        self.outgoing_edges(node_id)
            .iter()
            .filter_map(|e| self.node(e.target()))
            .collect()
    }

    /// Get direct neighbor nodes via incoming edges
    fn incoming_neighbors(&self, node_id: &NodeId) -> Vec<&Node> {
        self.incoming_edges(node_id)
            .iter()
            .filter_map(|e| self.node(e.source()))
            .collect()
    }

    /// Get all neighbors (both directions), deduplicated
    fn neighbors(&self, node_id: &NodeId) -> Vec<&Node> {
        let mut seen = std::collections::HashSet::new();
        let mut result: Vec<&Node> = Vec::new();
        for node in self.outgoing_neighbors(node_id) {
            if seen.insert(node.id().clone()) {
                result.push(node);
            }
        }
        for node in self.incoming_neighbors(node_id) {
            if seen.insert(node.id().clone()) {
                result.push(node);
            }
        }
        result
    }

    // === Counts ===

    /// Total alive nodes in the graph
    fn node_count(&self) -> usize;

    /// Total alive edges in the graph
    fn edge_count(&self) -> usize;
}

/// Breadth-first search from a starting node.
/// Returns all reachable node IDs in BFS order.
/// `filter` controls which nodes to continue traversing through.
/// `direction` controls whether to follow outgoing, incoming, or both edges.
pub fn bfs<G: GraphReader>(
    graph: &G,
    start: &NodeId,
    direction: TraversalDirection,
    filter: &dyn Fn(&Node) -> bool,
) -> Vec<NodeId> {
    use std::collections::{HashSet, VecDeque};

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut result = Vec::new();

    visited.insert(start.clone());
    queue.push_back(start.clone());

    while let Some(current) = queue.pop_front() {
        if let Some(node) = graph.node(&current) {
            if !node.is_alive() {
                continue;
            }
            result.push(current.clone());

            let next_ids: Vec<NodeId> = match direction {
                TraversalDirection::Outgoing => graph
                    .outgoing_edges(&current)
                    .iter()
                    .map(|e| e.target().clone())
                    .collect(),
                TraversalDirection::Incoming => graph
                    .incoming_edges(&current)
                    .iter()
                    .map(|e| e.source().clone())
                    .collect(),
                TraversalDirection::Both => {
                    let mut ids: Vec<NodeId> = graph
                        .outgoing_edges(&current)
                        .iter()
                        .map(|e| e.target().clone())
                        .collect();
                    ids.extend(
                        graph
                            .incoming_edges(&current)
                            .iter()
                            .map(|e| e.source().clone()),
                    );
                    ids
                }
            };

            for next_id in next_ids {
                if !visited.contains(&next_id) {
                    if let Some(next_node) = graph.node(&next_id) {
                        if next_node.is_alive() {
                            visited.insert(next_id.clone());
                            // Always add to results, but only continue traversing
                            // if the filter passes
                            if filter(next_node) {
                                queue.push_back(next_id);
                            } else {
                                // Still record this node — it's reachable — but
                                // don't traverse further from it
                                result.push(next_id);
                            }
                        }
                    }
                }
            }
        }
    }

    result
}

/// BFS variant that works with `&dyn GraphReader` (trait object compatible).
/// Same algorithm as `bfs`, but doesn't require the `Sized` bound on the graph.
pub fn bfs_dyn(
    graph: &dyn GraphReader,
    start: &NodeId,
    direction: TraversalDirection,
    filter: &dyn Fn(&Node) -> bool,
) -> Vec<NodeId> {
    use std::collections::{HashSet, VecDeque};

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut result = Vec::new();

    visited.insert(start.clone());
    queue.push_back(start.clone());

    while let Some(current) = queue.pop_front() {
        if let Some(node) = graph.node(&current) {
            if !node.is_alive() {
                continue;
            }
            result.push(current.clone());

            let next_ids: Vec<NodeId> = match direction {
                TraversalDirection::Outgoing => graph
                    .outgoing_edges(&current)
                    .iter()
                    .map(|e| e.target().clone())
                    .collect(),
                TraversalDirection::Incoming => graph
                    .incoming_edges(&current)
                    .iter()
                    .map(|e| e.source().clone())
                    .collect(),
                TraversalDirection::Both => {
                    let mut ids: Vec<NodeId> = graph
                        .outgoing_edges(&current)
                        .iter()
                        .map(|e| e.target().clone())
                        .collect();
                    ids.extend(
                        graph
                            .incoming_edges(&current)
                            .iter()
                            .map(|e| e.source().clone()),
                    );
                    ids
                }
            };

            for next_id in next_ids {
                if !visited.contains(&next_id) {
                    if let Some(next_node) = graph.node(&next_id) {
                        if next_node.is_alive() {
                            visited.insert(next_id.clone());
                            if filter(next_node) {
                                queue.push_back(next_id);
                            } else {
                                result.push(next_id);
                            }
                        }
                    }
                }
            }
        }
    }

    result
}

/// Direction for graph traversal
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TraversalDirection {
    Outgoing,
    Incoming,
    Both,
}

/// Topological sort of a set of nodes based on dependency edges.
/// Returns nodes in dependency order (dependencies first).
/// Returns Err if there's a cycle.
pub fn topological_sort<G: GraphReader>(
    graph: &G,
    nodes: &[NodeId],
    dependency_edge_type: &str,
) -> crate::error::Result<Vec<NodeId>> {
    use std::collections::{HashMap, HashSet, VecDeque};

    let node_set: HashSet<&NodeId> = nodes.iter().collect();
    let mut in_degree: HashMap<NodeId, usize> = HashMap::new();
    let mut adjacency: HashMap<NodeId, Vec<NodeId>> = HashMap::new();

    // Initialize
    for id in nodes {
        in_degree.entry(id.clone()).or_insert(0);
        adjacency.entry(id.clone()).or_insert_with(Vec::new);
    }

    // Build adjacency from dependency edges (within the node set).
    // A "depends_on" edge from A to B means "A depends on B", so B must come before A.
    // In Kahn's terms: B → A in the adjacency list, and A gets +1 in-degree.
    for id in nodes {
        for edge in graph.outgoing_edges_of_type(id, dependency_edge_type) {
            if node_set.contains(edge.target()) {
                // id depends on target → target must come before id
                // So adjacency: target → id
                adjacency
                    .entry(edge.target().clone())
                    .or_default()
                    .push(id.clone());
                *in_degree.entry(id.clone()).or_insert(0) += 1;
            }
        }
    }

    // Kahn's algorithm
    let mut queue: VecDeque<NodeId> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(id, _)| id.clone())
        .collect();

    let mut sorted = Vec::new();

    while let Some(current) = queue.pop_front() {
        sorted.push(current.clone());
        if let Some(neighbors) = adjacency.get(&current) {
            for neighbor in neighbors {
                if let Some(deg) = in_degree.get_mut(neighbor) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(neighbor.clone());
                    }
                }
            }
        }
    }

    if sorted.len() != nodes.len() {
        return Err(crate::error::HydraError::QueryError(
            "cycle detected in dependency graph — topological sort impossible".to_string(),
        ));
    }

    Ok(sorted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::Edge;
    use crate::id::{EdgeId, NodeId};
    use crate::node::Node;
    use std::collections::HashMap;

    /// A simple in-memory graph implementation for testing the trait and algorithms
    struct TestGraph {
        nodes: HashMap<NodeId, Node>,
        edges: HashMap<EdgeId, Edge>,
    }

    impl TestGraph {
        fn new() -> Self {
            Self {
                nodes: HashMap::new(),
                edges: HashMap::new(),
            }
        }

        fn add_node(&mut self, type_id: &str) -> NodeId {
            let id = NodeId::new();
            let node = Node::new(id.clone(), type_id.to_string(), HashMap::new());
            self.nodes.insert(id.clone(), node);
            id
        }

        fn add_edge(&mut self, source: &NodeId, target: &NodeId, type_id: &str) -> EdgeId {
            let id = EdgeId::new();
            let edge = Edge::new(
                id.clone(),
                type_id.to_string(),
                source.clone(),
                target.clone(),
                HashMap::new(),
            );
            self.edges.insert(id.clone(), edge);
            id
        }
    }

    impl GraphReader for TestGraph {
        fn node(&self, id: &NodeId) -> Option<&Node> {
            self.nodes.get(id)
        }

        fn edge(&self, id: &EdgeId) -> Option<&Edge> {
            self.edges.get(id)
        }

        fn nodes_by_type(&self, type_id: &str) -> Vec<&Node> {
            self.nodes
                .values()
                .filter(|n| n.type_id() == type_id && n.is_alive())
                .collect()
        }

        fn edges_by_type(&self, type_id: &str) -> Vec<&Edge> {
            self.edges
                .values()
                .filter(|e| e.type_id() == type_id && e.is_alive())
                .collect()
        }

        fn outgoing_edges(&self, node_id: &NodeId) -> Vec<&Edge> {
            self.edges
                .values()
                .filter(|e| e.source() == node_id && e.is_alive())
                .collect()
        }

        fn incoming_edges(&self, node_id: &NodeId) -> Vec<&Edge> {
            self.edges
                .values()
                .filter(|e| e.target() == node_id && e.is_alive())
                .collect()
        }

        fn node_count(&self) -> usize {
            self.nodes.values().filter(|n| n.is_alive()).count()
        }

        fn edge_count(&self) -> usize {
            self.edges.values().filter(|e| e.is_alive()).count()
        }
    }

    #[test]
    fn graph_reader_point_lookups() {
        let mut g = TestGraph::new();
        let id = g.add_node("ec2");
        assert!(g.has_node(&id));
        assert_eq!(g.node(&id).unwrap().type_id(), "ec2");
        assert!(!g.has_node(&NodeId::from_str("node_NONEXISTENT")));
    }

    #[test]
    fn graph_reader_type_lookups() {
        let mut g = TestGraph::new();
        g.add_node("ec2");
        g.add_node("ec2");
        g.add_node("rds");

        assert_eq!(g.nodes_by_type("ec2").len(), 2);
        assert_eq!(g.nodes_by_type("rds").len(), 1);
        assert_eq!(g.nodes_by_type("s3").len(), 0);
        assert_eq!(g.count_nodes_by_type("ec2"), 2);
    }

    #[test]
    fn graph_reader_topology() {
        let mut g = TestGraph::new();
        let a = g.add_node("ec2");
        let b = g.add_node("vpc");
        let c = g.add_node("sg");

        g.add_edge(&a, &b, "in_vpc");
        g.add_edge(&a, &c, "uses_sg");
        g.add_edge(&b, &c, "contains");

        assert_eq!(g.outgoing_edges(&a).len(), 2);
        assert_eq!(g.incoming_edges(&a).len(), 0);
        assert_eq!(g.outgoing_edges(&b).len(), 1);
        assert_eq!(g.incoming_edges(&b).len(), 1);
        assert_eq!(g.incoming_edges(&c).len(), 2);

        assert_eq!(g.outgoing_edges_of_type(&a, "in_vpc").len(), 1);
        assert_eq!(g.outgoing_edges_of_type(&a, "uses_sg").len(), 1);
        assert_eq!(g.outgoing_edges_of_type(&a, "nonexistent").len(), 0);
    }

    #[test]
    fn graph_reader_neighbors() {
        let mut g = TestGraph::new();
        let a = g.add_node("ec2");
        let b = g.add_node("vpc");
        let c = g.add_node("sg");

        g.add_edge(&a, &b, "dep");
        g.add_edge(&c, &a, "dep");

        let out = g.outgoing_neighbors(&a);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id(), &b);

        let inc = g.incoming_neighbors(&a);
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].id(), &c);

        let all = g.neighbors(&a);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn bfs_outgoing() {
        let mut g = TestGraph::new();
        // A → B → C → D
        let a = g.add_node("n");
        let b = g.add_node("n");
        let c = g.add_node("n");
        let d = g.add_node("n");

        g.add_edge(&a, &b, "dep");
        g.add_edge(&b, &c, "dep");
        g.add_edge(&c, &d, "dep");

        let result = bfs(&g, &a, TraversalDirection::Outgoing, &|_| true);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], a);
        assert_eq!(result[1], b);
        assert_eq!(result[2], c);
        assert_eq!(result[3], d);
    }

    #[test]
    fn bfs_with_filter() {
        let mut g = TestGraph::new();
        let a = g.add_node("ec2");
        let b = g.add_node("vpc");
        let c = g.add_node("ec2");

        g.add_edge(&a, &b, "dep");
        g.add_edge(&b, &c, "dep");

        // Only traverse through ec2 nodes
        let result = bfs(&g, &a, TraversalDirection::Outgoing, &|n| {
            n.type_id() == "ec2"
        });
        // Starts at a (ec2), finds b (vpc) but doesn't traverse through it
        assert_eq!(result.len(), 2); // a, b (b is added but not traversed further)
    }

    #[test]
    fn bfs_handles_cycles() {
        let mut g = TestGraph::new();
        let a = g.add_node("n");
        let b = g.add_node("n");
        let c = g.add_node("n");

        g.add_edge(&a, &b, "dep");
        g.add_edge(&b, &c, "dep");
        g.add_edge(&c, &a, "dep"); // Cycle!

        let result = bfs(&g, &a, TraversalDirection::Outgoing, &|_| true);
        assert_eq!(result.len(), 3); // Visits each once, doesn't loop
    }

    #[test]
    fn topological_sort_linear() {
        let mut g = TestGraph::new();
        // Database → API → Frontend (deps flow left to right)
        let db = g.add_node("rds");
        let api = g.add_node("ec2");
        let fe = g.add_node("ec2");

        g.add_edge(&api, &db, "depends_on");
        g.add_edge(&fe, &api, "depends_on");

        let sorted = topological_sort(&g, &[db.clone(), api.clone(), fe.clone()], "depends_on")
            .unwrap();

        // db has no deps → comes first (or at least before api)
        // api depends on db → comes after db
        // fe depends on api → comes last
        let db_pos = sorted.iter().position(|id| id == &db).unwrap();
        let api_pos = sorted.iter().position(|id| id == &api).unwrap();
        let fe_pos = sorted.iter().position(|id| id == &fe).unwrap();

        assert!(db_pos < api_pos);
        assert!(api_pos < fe_pos);
    }

    #[test]
    fn topological_sort_detects_cycle() {
        let mut g = TestGraph::new();
        let a = g.add_node("n");
        let b = g.add_node("n");

        g.add_edge(&a, &b, "depends_on");
        g.add_edge(&b, &a, "depends_on"); // Cycle!

        let result = topological_sort(&g, &[a, b], "depends_on");
        assert!(result.is_err());
    }

    #[test]
    fn topological_sort_independent_nodes() {
        let mut g = TestGraph::new();
        let a = g.add_node("n");
        let b = g.add_node("n");
        let c = g.add_node("n");

        // No edges — all independent
        let sorted = topological_sort(&g, &[a.clone(), b.clone(), c.clone()], "depends_on")
            .unwrap();
        assert_eq!(sorted.len(), 3);
    }

    #[test]
    fn deleted_nodes_excluded_from_type_query() {
        let mut g = TestGraph::new();
        let a = g.add_node("ec2");
        g.add_node("ec2");

        g.nodes.get_mut(&a).unwrap().delete();

        assert_eq!(g.nodes_by_type("ec2").len(), 1); // Only the alive one
        assert_eq!(g.node_count(), 1);
    }
}
