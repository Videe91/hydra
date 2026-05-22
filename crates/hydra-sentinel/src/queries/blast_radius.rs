//! # Blast Radius Query
//!
//! "If this node fails, what else breaks?"
//!
//! Traverses the dependency graph from a starting node, following INCOMING
//! `depends_on` edges (nodes that depend ON the failing node). Scores each
//! affected node by business criticality, data sensitivity, and dependency
//! depth. Returns a structured map of the damage zone.
//!
//! ## Edge Direction
//!
//! `depends_on` edges point from dependent → dependency:
//!   EC2 --depends_on--> RDS  (EC2 depends on RDS)
//!
//! So if RDS fails, we follow INCOMING depends_on edges to find EC2.
//! If RDS also has INCOMING edges from Lambda, those are in the blast too.
//!
//! We also follow IN_NETWORK edges to find co-located resources that might
//! be affected by a network-level failure.

use hydra_core::graph::GraphReader;
use hydra_core::id::NodeId;
use crate::nodes::{prop, DEPENDS_ON, IN_NETWORK, ASSUMES_ROLE};

use std::collections::HashMap;

/// A single node in the blast radius with its impact context.
#[derive(Debug, Clone)]
pub struct BlastNode {
    /// The affected node's ID
    pub node_id: NodeId,
    /// Node type (compute_instance, managed_database, etc.)
    pub node_type: String,
    /// Human-readable name if available
    pub name: Option<String>,
    /// Cloud provider (aws, azure, gcp, on_prem, saas)
    pub cloud_provider: Option<String>,
    /// How many hops from the origin
    pub depth: u32,
    /// How the failure propagates to this node
    pub impact_path: ImpactPath,
    /// Business criticality (from node properties, 0 = unknown)
    pub business_criticality: i64,
    /// Data sensitivity level
    pub data_sensitivity: Option<String>,
    /// Current trust composite score
    pub trust_score: f64,
    /// Protection status
    pub protection_status: Option<String>,
}

/// How the failure reaches an affected node
#[derive(Debug, Clone, PartialEq)]
pub enum ImpactPath {
    /// Direct dependency: the node depends_on the failing node
    DirectDependency,
    /// Transitive dependency: failure propagates through intermediate nodes
    TransitiveDependency { hops: u32 },
    /// Network co-location: in the same virtual network
    NetworkCoLocation,
    /// Identity chain: shares an identity role with the failing node
    IdentityChain,
}

/// Complete blast radius analysis result.
#[derive(Debug)]
pub struct BlastRadiusReport {
    /// The node that failed/was compromised
    pub origin: NodeId,
    /// Origin node type
    pub origin_type: String,
    /// All affected nodes, sorted by depth then criticality (descending)
    pub affected: Vec<BlastNode>,
    /// Total number of affected nodes (excluding origin)
    pub total_affected: usize,
    /// Highest business criticality in the blast radius
    pub max_criticality: i64,
    /// Summary: how many of each type are affected
    pub type_counts: HashMap<String, usize>,
    /// Summary: how many per cloud provider
    pub provider_counts: HashMap<String, usize>,
    /// Aggregate risk score: weighted sum of criticality × (1/depth)
    pub risk_score: f64,
}

/// Configuration for blast radius analysis
#[derive(Debug, Clone)]
pub struct BlastRadiusConfig {
    /// Maximum BFS depth (default: 10)
    pub max_depth: u32,
    /// Whether to include network co-location (default: true)
    pub include_network: bool,
    /// Whether to include identity chain (default: true)
    pub include_identity: bool,
    /// Minimum dependency confidence to follow (default: 0.0)
    pub min_confidence: f64,
}

impl Default for BlastRadiusConfig {
    fn default() -> Self {
        Self {
            max_depth: 10,
            include_network: true,
            include_identity: true,
            min_confidence: 0.0,
        }
    }
}

/// Compute the blast radius from a failing node.
///
/// Returns all nodes that would be affected if `origin` failed,
/// with impact context for each.
pub fn blast_radius(
    graph: &dyn GraphReader,
    origin: &NodeId,
    config: &BlastRadiusConfig,
) -> Option<BlastRadiusReport> {
    let origin_node = graph.node(origin)?;
    if !origin_node.is_alive() {
        return None;
    }

    let origin_type = origin_node.type_id().to_string();
    let mut affected: Vec<BlastNode> = Vec::new();
    let mut visited: HashMap<NodeId, u32> = HashMap::new(); // node_id → depth

    // Add origin
    visited.insert(origin.clone(), 0);

    // Phase 1: Follow INCOMING depends_on edges (things that depend on us)
    dependency_bfs(graph, origin, config, &mut visited, &mut affected);

    // Phase 2: Network co-location (same VPC/VNet)
    if config.include_network {
        network_colocation(graph, origin, config, &mut visited, &mut affected);
    }

    // Phase 3: Identity chain (shares IAM role)
    if config.include_identity {
        identity_chain(graph, origin, config, &mut visited, &mut affected);
    }

    // Sort: depth ascending, then criticality descending
    affected.sort_by(|a, b| {
        a.depth.cmp(&b.depth)
            .then(b.business_criticality.cmp(&a.business_criticality))
    });

    // Compute summaries
    let total_affected = affected.len();
    let max_criticality = affected.iter().map(|n| n.business_criticality).max().unwrap_or(0);

    let mut type_counts: HashMap<String, usize> = HashMap::new();
    let mut provider_counts: HashMap<String, usize> = HashMap::new();
    let mut risk_score: f64 = 0.0;

    for node in &affected {
        *type_counts.entry(node.node_type.clone()).or_default() += 1;
        if let Some(ref p) = node.cloud_provider {
            *provider_counts.entry(p.clone()).or_default() += 1;
        }
        // Risk: criticality weighted by inverse depth (closer = worse)
        let depth_weight = if node.depth == 0 { 1.0 } else { 1.0 / node.depth as f64 };
        risk_score += node.business_criticality as f64 * depth_weight;
    }

    Some(BlastRadiusReport {
        origin: origin.clone(),
        origin_type,
        affected,
        total_affected,
        max_criticality,
        type_counts,
        provider_counts,
        risk_score,
    })
}

/// BFS following INCOMING depends_on edges
fn dependency_bfs(
    graph: &dyn GraphReader,
    origin: &NodeId,
    config: &BlastRadiusConfig,
    visited: &mut HashMap<NodeId, u32>,
    affected: &mut Vec<BlastNode>,
) {
    use std::collections::VecDeque;

    let mut queue: VecDeque<(NodeId, u32)> = VecDeque::new();
    queue.push_back((origin.clone(), 0));

    while let Some((current_id, depth)) = queue.pop_front() {
        if depth >= config.max_depth {
            continue;
        }

        // Find nodes that depend on current_id (INCOMING depends_on edges)
        let incoming = graph.incoming_edges_of_type(&current_id, DEPENDS_ON);
        for edge in incoming {
            let dependent_id = edge.source(); // source --depends_on--> target (current)

            // Check confidence threshold
            let confidence = edge.properties.get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(1.0);
            if confidence < config.min_confidence {
                continue;
            }

            let new_depth = depth + 1;
            if visited.contains_key(dependent_id) {
                continue; // Already found via a shorter/different path
            }
            visited.insert(dependent_id.clone(), new_depth);

            if let Some(node) = graph.node(dependent_id) {
                if !node.is_alive() {
                    continue;
                }
                let impact = if new_depth == 1 {
                    ImpactPath::DirectDependency
                } else {
                    ImpactPath::TransitiveDependency { hops: new_depth }
                };

                affected.push(enrich_blast_node(node, dependent_id, new_depth, impact));
                queue.push_back((dependent_id.clone(), new_depth));
            }
        }
    }
}

/// Find resources in the same network as the origin
fn network_colocation(
    graph: &dyn GraphReader,
    origin: &NodeId,
    _config: &BlastRadiusConfig,
    visited: &mut HashMap<NodeId, u32>,
    affected: &mut Vec<BlastNode>,
) {
    // Find origin's network: follow OUTGOING in_network edges
    let network_edges = graph.outgoing_edges_of_type(origin, IN_NETWORK);
    for net_edge in network_edges {
        let network_id = net_edge.target();

        // Find all other nodes in this network: INCOMING in_network edges to the same network
        let peers = graph.incoming_edges_of_type(network_id, IN_NETWORK);
        for peer_edge in peers {
            let peer_id = peer_edge.source();
            if peer_id == origin {
                continue;
            }
            if visited.contains_key(peer_id) {
                continue;
            }
            visited.insert(peer_id.clone(), 1);

            if let Some(node) = graph.node(peer_id) {
                if node.is_alive() {
                    affected.push(enrich_blast_node(
                        node, peer_id, 1, ImpactPath::NetworkCoLocation,
                    ));
                }
            }
        }
    }
}

/// Find resources sharing identity roles with the origin
fn identity_chain(
    graph: &dyn GraphReader,
    origin: &NodeId,
    _config: &BlastRadiusConfig,
    visited: &mut HashMap<NodeId, u32>,
    affected: &mut Vec<BlastNode>,
) {
    // Find roles the origin assumes: OUTGOING assumes_role edges
    let role_edges = graph.outgoing_edges_of_type(origin, ASSUMES_ROLE);
    for role_edge in role_edges {
        let role_id = role_edge.target();

        // Find other nodes that assume the same role: INCOMING assumes_role to same role
        let co_users = graph.incoming_edges_of_type(role_id, ASSUMES_ROLE);
        for co_edge in co_users {
            let co_id = co_edge.source();
            if co_id == origin {
                continue;
            }
            if visited.contains_key(co_id) {
                continue;
            }
            visited.insert(co_id.clone(), 2); // Identity chain is depth 2

            if let Some(node) = graph.node(co_id) {
                if node.is_alive() {
                    affected.push(enrich_blast_node(
                        node, co_id, 2, ImpactPath::IdentityChain,
                    ));
                }
            }
        }
    }
}

/// Extract properties from a node into a BlastNode
fn enrich_blast_node(
    node: &hydra_core::node::Node,
    node_id: &NodeId,
    depth: u32,
    impact: ImpactPath,
) -> BlastNode {
    BlastNode {
        node_id: node_id.clone(),
        node_type: node.type_id().to_string(),
        name: node.get_str(prop::NAME).map(|s| s.to_string()),
        cloud_provider: node.get_str("cloud_provider").map(|s| s.to_string()),
        depth,
        impact_path: impact,
        business_criticality: node.get_i64(prop::BUSINESS_CRITICALITY).unwrap_or(0),
        data_sensitivity: node.get_str(prop::DATA_SENSITIVITY).map(|s| s.to_string()),
        trust_score: node.get_f64(prop::TRUST_COMPOSITE).unwrap_or(0.0),
        protection_status: node.get_str(prop::PROTECTION_STATUS).map(|s| s.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_engine::prelude::*;
    use hydra_core::id::NodeId;
    use crate::nodes::aws::*;
    use crate::edges;

    fn build_test_estate() -> (Hydra, NodeId, NodeId, NodeId, NodeId, NodeId, NodeId) {
        let mut hydra = Hydra::new();

        // RDS (the origin we'll test blast from)
        let (rds, ev) = RdsBuilder::new("db-prod")
            .name("prod-db")
            .business_criticality(9)
            .data_sensitivity("critical")
            .build();
        hydra.ingest(ev).unwrap();

        // EC2-1 depends on RDS
        let (ec2_1, ev) = Ec2Builder::new("i-001")
            .name("api-server-1")
            .business_criticality(7)
            .build();
        hydra.ingest(ev).unwrap();

        // EC2-2 depends on RDS
        let (ec2_2, ev) = Ec2Builder::new("i-002")
            .name("api-server-2")
            .business_criticality(7)
            .build();
        hydra.ingest(ev).unwrap();

        // Lambda depends on EC2-1 (transitive)
        let (lambda, ev) = LambdaBuilder::new("order-processor")
            .build();
        hydra.ingest(ev).unwrap();

        // S3 — no dependency on RDS (should NOT be in blast)
        let (s3, ev) = S3BucketBuilder::new("assets-bucket")
            .build();
        hydra.ingest(ev).unwrap();

        // VPC
        let (vpc, ev) = VpcBuilder::new("vpc-prod").name("prod-vpc").build();
        hydra.ingest(ev).unwrap();

        // IAM Role shared between EC2-1 and EC2-2
        let (role, ev) = IamRoleBuilder::new("api-role").build();
        hydra.ingest(ev).unwrap();

        // Edges: EC2-1 --depends_on--> RDS
        let (_, ev) = edges::depends_on(ec2_1.clone(), rds.clone(), "database", 1.0);
        hydra.ingest(ev).unwrap();

        // EC2-2 --depends_on--> RDS
        let (_, ev) = edges::depends_on(ec2_2.clone(), rds.clone(), "database", 0.95);
        hydra.ingest(ev).unwrap();

        // Lambda --depends_on--> EC2-1
        let (_, ev) = edges::depends_on(lambda.clone(), ec2_1.clone(), "api", 0.8);
        hydra.ingest(ev).unwrap();

        // EC2-1 --in_vpc--> VPC, EC2-2 --in_vpc--> VPC
        let (_, ev) = edges::in_vpc(ec2_1.clone(), vpc.clone());
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::in_vpc(ec2_2.clone(), vpc.clone());
        hydra.ingest(ev).unwrap();
        // RDS --in_vpc--> VPC
        let (_, ev) = edges::in_vpc(rds.clone(), vpc.clone());
        hydra.ingest(ev).unwrap();

        // EC2-1 --assumes_role--> role, EC2-2 --assumes_role--> role
        let (_, ev) = edges::assumes_role(ec2_1.clone(), role.clone());
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::assumes_role(ec2_2.clone(), role.clone());
        hydra.ingest(ev).unwrap();

        (hydra, rds, ec2_1, ec2_2, lambda, s3, vpc)
    }

    #[test]
    fn blast_from_database_finds_direct_dependents() {
        let (hydra, rds, _ec2_1, _ec2_2, _lambda, _s3, _vpc) = build_test_estate();
        let config = BlastRadiusConfig {
            include_network: false,
            include_identity: false,
            ..Default::default()
        };

        let report = blast_radius(hydra.graph(), &rds, &config).unwrap();

        assert_eq!(report.origin, rds);
        // EC2-1 and EC2-2 are direct dependents, Lambda is transitive via EC2-1
        assert_eq!(report.total_affected, 3);

        let direct: Vec<_> = report.affected.iter()
            .filter(|n| n.impact_path == ImpactPath::DirectDependency)
            .collect();
        assert_eq!(direct.len(), 2, "EC2-1 and EC2-2 are direct dependents");

        let transitive: Vec<_> = report.affected.iter()
            .filter(|n| matches!(n.impact_path, ImpactPath::TransitiveDependency { .. }))
            .collect();
        assert_eq!(transitive.len(), 1, "Lambda is transitive via EC2-1");
    }

    #[test]
    fn blast_includes_network_colocation() {
        let (hydra, rds, _ec2_1, _ec2_2, _lambda, _s3, _vpc) = build_test_estate();
        let config = BlastRadiusConfig::default();

        let report = blast_radius(hydra.graph(), &rds, &config).unwrap();

        // With network: EC2-1 and EC2-2 found via dependency + they're in same VPC
        // Network co-location shouldn't add duplicates
        let network: Vec<_> = report.affected.iter()
            .filter(|n| n.impact_path == ImpactPath::NetworkCoLocation)
            .collect();
        // EC2-1 and EC2-2 already found via dependency, so network finds nothing new
        // (they're already in visited)
        assert_eq!(network.len(), 0, "No new nodes from network — already found via dependency");
    }

    #[test]
    fn blast_includes_identity_chain() {
        let (hydra, _rds, ec2_1, _ec2_2, _lambda, _s3, _vpc) = build_test_estate();

        // Blast from Lambda — it depends on EC2-1
        // EC2-1 shares role with EC2-2 → identity chain
        let config = BlastRadiusConfig {
            include_network: false,
            include_identity: true,
            ..Default::default()
        };

        let report = blast_radius(hydra.graph(), &_lambda, &config).unwrap();

        // Lambda depends on EC2-1 (direct)
        // EC2-1 depends on RDS (transitive from Lambda, depth 2)
        // EC2-2 shares role with EC2-1 (identity chain)
        let identity: Vec<_> = report.affected.iter()
            .filter(|n| n.impact_path == ImpactPath::IdentityChain)
            .collect();
        // EC2-2 is already found transitively (EC2-2 depends on RDS, RDS is at depth 2)
        // But identity chain from Lambda's perspective: Lambda doesn't assume any role
        // So no identity hits from Lambda
        assert_eq!(identity.len(), 0);

        // Blast from EC2-1: shares role with EC2-2
        let report2 = blast_radius(hydra.graph(), &ec2_1, &config).unwrap();
        let identity2: Vec<_> = report2.affected.iter()
            .filter(|n| n.impact_path == ImpactPath::IdentityChain)
            .collect();
        assert_eq!(identity2.len(), 1, "EC2-2 shares role with EC2-1");
    }

    #[test]
    fn blast_excludes_unrelated_nodes() {
        let (hydra, rds, _, _, _, s3, _) = build_test_estate();
        let config = BlastRadiusConfig::default();

        let report = blast_radius(hydra.graph(), &rds, &config).unwrap();

        let s3_in_blast = report.affected.iter().any(|n| n.node_id == s3);
        assert!(!s3_in_blast, "S3 has no dependency on RDS — should not be in blast");
    }

    #[test]
    fn blast_respects_max_depth() {
        let (hydra, rds, _, _, _, _, _) = build_test_estate();
        let config = BlastRadiusConfig {
            max_depth: 1,
            include_network: false,
            include_identity: false,
            ..Default::default()
        };

        let report = blast_radius(hydra.graph(), &rds, &config).unwrap();

        // Only direct dependents, no transitive
        assert_eq!(report.total_affected, 2, "Depth 1 = only direct dependents");
        for node in &report.affected {
            assert_eq!(node.depth, 1);
        }
    }

    #[test]
    fn blast_respects_confidence_threshold() {
        let (hydra, rds, _, _, _, _, _) = build_test_estate();
        let config = BlastRadiusConfig {
            min_confidence: 0.99,
            include_network: false,
            include_identity: false,
            ..Default::default()
        };

        let report = blast_radius(hydra.graph(), &rds, &config).unwrap();

        // EC2-1 has confidence 1.0 (passes), EC2-2 has 0.95 (filtered)
        // Lambda→EC2-1 has confidence 0.8 (also filtered)
        assert_eq!(report.total_affected, 1, "Only EC2-1 passes min_confidence 0.99");
    }

    #[test]
    fn blast_computes_risk_score() {
        let (hydra, rds, _, _, _, _, _) = build_test_estate();
        let config = BlastRadiusConfig {
            include_network: false,
            include_identity: false,
            ..Default::default()
        };

        let report = blast_radius(hydra.graph(), &rds, &config).unwrap();
        assert!(report.risk_score > 0.0);
        assert!(report.type_counts.contains_key("compute_instance"));
    }

    #[test]
    fn blast_nonexistent_node_returns_none() {
        let hydra = Hydra::new();
        let fake = NodeId::from_str("node_FAKE");
        assert!(blast_radius(hydra.graph(), &fake, &BlastRadiusConfig::default()).is_none());
    }

    #[test]
    fn blast_sorted_by_depth_then_criticality() {
        let (hydra, rds, _, _, _, _, _) = build_test_estate();
        let config = BlastRadiusConfig {
            include_network: false,
            include_identity: false,
            ..Default::default()
        };

        let report = blast_radius(hydra.graph(), &rds, &config).unwrap();

        for window in report.affected.windows(2) {
            assert!(
                window[0].depth < window[1].depth
                    || (window[0].depth == window[1].depth
                        && window[0].business_criticality >= window[1].business_criticality),
                "Should be sorted by depth asc, criticality desc"
            );
        }
    }

    #[test]
    fn blast_cycle_in_dependencies_terminates() {
        // A→B→C→A cycle — BFS must not loop forever
        let mut hydra = Hydra::new();

        let (a, ev) = Ec2Builder::new("i-a").name("node-a").build();
        hydra.ingest(ev).unwrap();
        let (b, ev) = Ec2Builder::new("i-b").name("node-b").build();
        hydra.ingest(ev).unwrap();
        let (c, ev) = Ec2Builder::new("i-c").name("node-c").build();
        hydra.ingest(ev).unwrap();

        // A depends on B, B depends on C, C depends on A
        let (_, ev) = edges::depends_on(a.clone(), b.clone(), "api", 1.0);
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::depends_on(b.clone(), c.clone(), "api", 1.0);
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::depends_on(c.clone(), a.clone(), "api", 1.0);
        hydra.ingest(ev).unwrap();

        let config = BlastRadiusConfig {
            include_network: false,
            include_identity: false,
            ..Default::default()
        };

        // Must terminate and return a valid report
        let report = blast_radius(hydra.graph(), &a, &config).unwrap();
        // B depends on A (direct), C depends on B (transitive)
        // A depends on C... but A is origin (already visited), so no infinite loop
        assert_eq!(report.total_affected, 2);
    }

    #[test]
    fn blast_skips_deleted_nodes_in_chain() {
        use hydra_core::event::EventKind;

        let mut hydra = Hydra::new();

        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();
        let (api, ev) = Ec2Builder::new("i-api").build();
        hydra.ingest(ev).unwrap();
        let (fe, ev) = Ec2Builder::new("i-fe").build();
        hydra.ingest(ev).unwrap();

        // fe -> api -> db
        let (_, ev) = edges::depends_on(fe.clone(), api.clone(), "api", 1.0);
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::depends_on(api.clone(), db.clone(), "database", 1.0);
        hydra.ingest(ev).unwrap();

        // Delete API server
        hydra.ingest(EventKind::NodeDeleted { node_id: api.clone() }).unwrap();

        let config = BlastRadiusConfig {
            include_network: false,
            include_identity: false,
            ..Default::default()
        };

        let report = blast_radius(hydra.graph(), &db, &config).unwrap();
        // API is deleted, so it should be skipped. FE depends on API (deleted),
        // so FE won't be found via BFS through a dead node.
        let has_api = report.affected.iter().any(|n| n.node_id == api);
        assert!(!has_api, "Deleted API should not appear in blast radius");
    }
}
