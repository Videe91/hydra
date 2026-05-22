//! # Recovery Plan Query
//!
//! "If this node is down, what's the ordered sequence of steps to recover?"
//!
//! Uses topological sort on the dependency subgraph to produce a recovery
//! order that restores foundations before dependents. Enriches each step
//! with backup availability, estimated recovery time, and verification status.

use hydra_core::graph::GraphReader;
use hydra_core::id::NodeId;
use crate::nodes::{prop, DEPENDS_ON, PROTECTED_BY, VERIFIED_BY};
use crate::queries::blast_radius::{blast_radius, BlastRadiusConfig};

use std::collections::{HashMap, HashSet, VecDeque};

/// A single step in the recovery plan
#[derive(Debug, Clone)]
pub struct RecoveryStep {
    /// Sequence number (1-based)
    pub order: usize,
    /// The node to recover
    pub node_id: NodeId,
    pub node_type: String,
    pub name: Option<String>,
    pub cloud_provider: Option<String>,
    /// Business criticality
    pub criticality: i64,
    /// Can this node be recovered? (has backups)
    pub recoverable: bool,
    /// How many backup snapshots are available
    pub snapshot_count: usize,
    /// Whether any snapshot has been verified
    pub verified: bool,
    /// Nodes that must be recovered before this one
    pub depends_on: Vec<NodeId>,
    /// What type of action is needed
    pub action: RecoveryAction,
    /// Protection status before failure
    pub was_protected: bool,
}

/// What action to take for recovery
#[derive(Debug, Clone, PartialEq)]
pub enum RecoveryAction {
    /// Restore from backup
    RestoreFromBackup,
    /// Rebuild/redeploy (no backup, but can be reconstructed)
    Rebuild,
    /// Cannot recover — no backup, no way to rebuild
    ManualIntervention,
    /// Already healthy — not affected
    NoAction,
}

/// Complete recovery plan
#[derive(Debug)]
pub struct RecoveryPlan {
    /// The failed node
    pub origin: NodeId,
    pub origin_type: String,
    /// Ordered recovery steps (foundations first, dependents last)
    pub steps: Vec<RecoveryStep>,
    /// Total nodes to recover
    pub total_nodes: usize,
    /// Nodes that can be automatically recovered
    pub auto_recoverable: usize,
    /// Nodes requiring manual intervention
    pub manual_required: usize,
    /// Whether all affected nodes have verified backups
    pub full_verified: bool,
    /// Highest criticality among non-recoverable nodes
    pub max_unrecoverable_criticality: i64,
    /// Whether the dependency graph contains cycles (degraded ordering)
    pub has_cycles: bool,
}

/// Generate a recovery plan for a failed node.
///
/// Steps:
/// 1. Compute blast radius (who's affected)
/// 2. Build dependency subgraph of affected nodes
/// 3. Topological sort: dependencies before dependents
/// 4. Enrich each step with backup/verification status
pub fn recovery_plan(
    graph: &dyn GraphReader,
    origin: &NodeId,
) -> Option<RecoveryPlan> {
    let origin_node = graph.node(origin)?;
    if !origin_node.is_alive() {
        return None;
    }
    let origin_type = origin_node.type_id().to_string();

    // Step 1: Get blast radius (dependency-only, no network/identity)
    let blast_config = BlastRadiusConfig {
        max_depth: 20,
        include_network: false,
        include_identity: false,
        min_confidence: 0.0,
    };
    let blast = blast_radius(graph, origin, &blast_config)?;

    // Step 2: Build dependency subgraph among affected nodes
    let affected_set: HashSet<NodeId> = blast.affected.iter()
        .map(|n| n.node_id.clone())
        .chain(std::iter::once(origin.clone()))
        .collect();

    // For each affected node, find which other affected nodes it depends on
    let mut deps: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    for node_id in &affected_set {
        let outgoing = graph.outgoing_edges_of_type(node_id, DEPENDS_ON);
        let my_deps: Vec<NodeId> = outgoing.iter()
            .map(|e| e.target().clone())
            .filter(|t| affected_set.contains(t))
            .collect();
        deps.insert(node_id.clone(), my_deps);
    }

    // Step 3: Topological sort (Kahn's algorithm)
    // We want foundations (things with zero in-scope dependencies) FIRST
    let mut in_degree: HashMap<NodeId, usize> = HashMap::new();
    let mut adjacency: HashMap<NodeId, Vec<NodeId>> = HashMap::new();

    for node_id in &affected_set {
        in_degree.entry(node_id.clone()).or_insert(0);
        adjacency.entry(node_id.clone()).or_insert_with(Vec::new);
    }

    for (dependent, dependencies) in &deps {
        for dep in dependencies {
            // dependent depends on dep → dep must come first
            // In topo sort terms: dep → dependent (dep has an edge to dependent)
            adjacency.entry(dep.clone()).or_default().push(dependent.clone());
            *in_degree.entry(dependent.clone()).or_default() += 1;
        }
    }

    let mut queue: VecDeque<NodeId> = in_degree.iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(id, _)| id.clone())
        .collect();

    let mut sorted: Vec<NodeId> = Vec::new();
    while let Some(current) = queue.pop_front() {
        sorted.push(current.clone());
        if let Some(neighbors) = adjacency.get(&current) {
            for next in neighbors {
                if let Some(deg) = in_degree.get_mut(next) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        queue.push_back(next.clone());
                    }
                }
            }
        }
    }

    // If topo sort didn't include all nodes, there's a cycle — append remaining
    let has_cycles = sorted.len() < affected_set.len();
    if has_cycles {
        let sorted_set: HashSet<&NodeId> = sorted.iter().collect();
        let missing: Vec<NodeId> = affected_set.iter()
            .filter(|id| !sorted_set.contains(id))
            .cloned()
            .collect();
        sorted.extend(missing);
    }

    // Step 4: Enrich each step
    let mut steps: Vec<RecoveryStep> = Vec::new();
    for (order, node_id) in sorted.iter().enumerate() {
        let node = match graph.node(node_id) {
            Some(n) if n.is_alive() => n,
            _ => continue,
        };

        let backup_edges = graph.outgoing_edges_of_type(node_id, PROTECTED_BY);
        let snapshot_count = backup_edges.len();
        let verified = backup_edges.iter().any(|e| {
            let snap_id = e.target();
            !graph.outgoing_edges_of_type(snap_id, VERIFIED_BY).is_empty()
        });
        let was_protected = node.get_str(prop::PROTECTION_STATUS)
            .map(|s| s == "protected")
            .unwrap_or(false);

        let action = if snapshot_count > 0 {
            RecoveryAction::RestoreFromBackup
        } else if node.type_id() == "serverless_function" {
            // Functions can be redeployed from code
            RecoveryAction::Rebuild
        } else {
            RecoveryAction::ManualIntervention
        };

        let my_deps = deps.get(node_id)
            .cloned()
            .unwrap_or_default();

        steps.push(RecoveryStep {
            order: order + 1,
            node_id: node_id.clone(),
            node_type: node.type_id().to_string(),
            name: node.get_str(prop::NAME).map(|s| s.to_string()),
            cloud_provider: node.get_str("cloud_provider").map(|s| s.to_string()),
            criticality: node.get_i64(prop::BUSINESS_CRITICALITY).unwrap_or(0),
            recoverable: snapshot_count > 0 || action == RecoveryAction::Rebuild,
            snapshot_count,
            verified,
            depends_on: my_deps,
            action,
            was_protected,
        });
    }

    let total_nodes = steps.len();
    let auto_recoverable = steps.iter()
        .filter(|s| s.action == RecoveryAction::RestoreFromBackup || s.action == RecoveryAction::Rebuild)
        .count();
    let manual_required = steps.iter()
        .filter(|s| s.action == RecoveryAction::ManualIntervention)
        .count();
    let full_verified = steps.iter().all(|s| s.verified || s.action == RecoveryAction::Rebuild);
    let max_unrecoverable_criticality = steps.iter()
        .filter(|s| s.action == RecoveryAction::ManualIntervention)
        .map(|s| s.criticality)
        .max()
        .unwrap_or(0);

    Some(RecoveryPlan {
        origin: origin.clone(),
        origin_type,
        steps,
        total_nodes,
        auto_recoverable,
        manual_required,
        full_verified,
        max_unrecoverable_criticality,
        has_cycles,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_engine::prelude::*;
    use hydra_core::id::NodeId;
    use crate::nodes::aws::*;
    use crate::nodes::protection::*;
    use crate::edges;

    #[test]
    fn recovery_plan_orders_dependencies_first() {
        let mut hydra = Hydra::new();

        // DB (foundation)
        let (db, ev) = RdsBuilder::new("db-prod").name("prod-db").business_criticality(9).build();
        hydra.ingest(ev).unwrap();

        // API server depends on DB
        let (api, ev) = Ec2Builder::new("i-api").name("api-server").business_criticality(7).build();
        hydra.ingest(ev).unwrap();

        // Frontend depends on API
        let (fe, ev) = Ec2Builder::new("i-fe").name("frontend").business_criticality(5).build();
        hydra.ingest(ev).unwrap();

        // Dependencies: fe -> api -> db
        let (_, ev) = edges::depends_on(fe.clone(), api.clone(), "api", 1.0);
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::depends_on(api.clone(), db.clone(), "database", 1.0);
        hydra.ingest(ev).unwrap();

        let plan = recovery_plan(hydra.graph(), &db).unwrap();

        assert_eq!(plan.total_nodes, 3);

        // DB should come first (no in-scope dependencies)
        let db_idx = plan.steps.iter().position(|s| s.node_id == db).unwrap();
        let api_idx = plan.steps.iter().position(|s| s.node_id == api).unwrap();
        let fe_idx = plan.steps.iter().position(|s| s.node_id == fe).unwrap();

        assert!(db_idx < api_idx, "DB must be recovered before API");
        assert!(api_idx < fe_idx, "API must be recovered before frontend");
    }

    #[test]
    fn recovery_plan_identifies_unrecoverable() {
        let mut hydra = Hydra::new();

        // DB with no backups
        let (db, ev) = RdsBuilder::new("db-prod").business_criticality(10).build();
        hydra.ingest(ev).unwrap();

        // EC2 depends on DB, also no backups
        let (ec2, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::depends_on(ec2.clone(), db.clone(), "database", 1.0);
        hydra.ingest(ev).unwrap();

        let plan = recovery_plan(hydra.graph(), &db).unwrap();

        assert_eq!(plan.manual_required, 2);
        assert_eq!(plan.auto_recoverable, 0);
        assert_eq!(plan.max_unrecoverable_criticality, 10);
        assert!(!plan.full_verified);
    }

    #[test]
    fn recovery_plan_with_backups() {
        let mut hydra = Hydra::new();

        let (db, ev) = RdsBuilder::new("db-prod").business_criticality(9).build();
        hydra.ingest(ev).unwrap();

        // Add a backup snapshot
        let (snap, ev) = BackupSnapshotBuilder::new("snap-001")
            .encrypted(true)
            .build();
        hydra.ingest(ev).unwrap();

        // DB --protected_by--> snapshot
        let (_, ev) = edges::protected_by(db.clone(), snap.clone());
        hydra.ingest(ev).unwrap();

        let plan = recovery_plan(hydra.graph(), &db).unwrap();

        let db_step = plan.steps.iter().find(|s| s.node_id == db).unwrap();
        assert_eq!(db_step.action, RecoveryAction::RestoreFromBackup);
        assert_eq!(db_step.snapshot_count, 1);
        assert!(db_step.recoverable);
    }

    #[test]
    fn lambda_gets_rebuild_action() {
        let mut hydra = Hydra::new();

        let (api, ev) = Ec2Builder::new("i-api").build();
        hydra.ingest(ev).unwrap();

        let (lambda, ev) = LambdaBuilder::new("processor").build();
        hydra.ingest(ev).unwrap();

        let (_, ev) = edges::depends_on(lambda.clone(), api.clone(), "api", 1.0);
        hydra.ingest(ev).unwrap();

        let plan = recovery_plan(hydra.graph(), &api).unwrap();

        let lambda_step = plan.steps.iter().find(|s| s.node_id == lambda).unwrap();
        assert_eq!(lambda_step.action, RecoveryAction::Rebuild);
        assert!(lambda_step.recoverable);
    }

    #[test]
    fn recovery_plan_nonexistent_returns_none() {
        let hydra = Hydra::new();
        let fake = NodeId::from_str("node_FAKE");
        assert!(recovery_plan(hydra.graph(), &fake).is_none());
    }

    #[test]
    fn recovery_plan_single_node_no_dependents() {
        let mut hydra = Hydra::new();
        let (db, ev) = RdsBuilder::new("db-solo").build();
        hydra.ingest(ev).unwrap();

        let plan = recovery_plan(hydra.graph(), &db).unwrap();
        assert_eq!(plan.total_nodes, 1);
        assert_eq!(plan.steps[0].node_id, db);
    }

    #[test]
    fn recovery_steps_include_dependency_info() {
        let mut hydra = Hydra::new();

        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();
        let (api, ev) = Ec2Builder::new("i-api").build();
        hydra.ingest(ev).unwrap();

        let (_, ev) = edges::depends_on(api.clone(), db.clone(), "database", 1.0);
        hydra.ingest(ev).unwrap();

        let plan = recovery_plan(hydra.graph(), &db).unwrap();

        let api_step = plan.steps.iter().find(|s| s.node_id == api).unwrap();
        assert!(api_step.depends_on.contains(&db), "API step should list DB as dependency");
    }

    #[test]
    fn recovery_plan_handles_dependency_cycle() {
        let mut hydra = Hydra::new();

        let (a, ev) = Ec2Builder::new("i-a").build();
        hydra.ingest(ev).unwrap();
        let (b, ev) = Ec2Builder::new("i-b").build();
        hydra.ingest(ev).unwrap();
        let (c, ev) = Ec2Builder::new("i-c").build();
        hydra.ingest(ev).unwrap();

        // Cycle: a->b->c->a
        let (_, ev) = edges::depends_on(a.clone(), b.clone(), "api", 1.0);
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::depends_on(b.clone(), c.clone(), "api", 1.0);
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::depends_on(c.clone(), a.clone(), "api", 1.0);
        hydra.ingest(ev).unwrap();

        let plan = recovery_plan(hydra.graph(), &a).unwrap();

        // Must terminate and flag the cycle
        assert!(plan.has_cycles, "Should detect dependency cycle");
        // All nodes in blast still get recovery steps
        assert!(plan.total_nodes >= 2);
    }
}
