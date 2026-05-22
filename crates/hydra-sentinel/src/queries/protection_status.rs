//! # Protection Status Query
//!
//! "Show me every resource that's unprotected, overdue for backup, or has
//! failed verification — sorted by business criticality."
//!
//! This is the dashboard query — the first thing a Sentinel user sees.

use hydra_core::graph::GraphReader;
use hydra_core::id::NodeId;
use crate::nodes::prop;
use crate::nodes::{
    COMPUTE_INSTANCE, MANAGED_DATABASE, OBJECT_STORE,
    SERVERLESS_FUNCTION, SAAS_APPLICATION, ENDPOINT, ON_PREM_SERVER,
    CONTAINER_CLUSTER, CONTAINER_SERVICE, CACHE_CLUSTER, DATA_WAREHOUSE,
    STREAM, ML_ENDPOINT, MESSAGE_QUEUE, LOAD_BALANCER, FILE_SYSTEM, DNS_ZONE,
};

/// Protectable resource types — these are what Sentinel cares about.
pub const PROTECTABLE_TYPES: &[&str] = &[
    COMPUTE_INSTANCE,
    MANAGED_DATABASE,
    OBJECT_STORE,
    SERVERLESS_FUNCTION,
    SAAS_APPLICATION,
    ENDPOINT,
    ON_PREM_SERVER,
    CONTAINER_CLUSTER,
    CONTAINER_SERVICE,
    CACHE_CLUSTER,
    DATA_WAREHOUSE,
    STREAM,
    ML_ENDPOINT,
    MESSAGE_QUEUE,
    LOAD_BALANCER,
    FILE_SYSTEM,
    DNS_ZONE,
];

/// Protection status for a single resource
#[derive(Debug, Clone)]
pub struct ResourceProtection {
    pub node_id: NodeId,
    pub node_type: String,
    pub name: Option<String>,
    pub cloud_provider: Option<String>,
    pub region: Option<String>,
    /// "protected", "unprotected", "partial", "unknown"
    pub protection_status: String,
    /// Business criticality (0 = unknown, higher = more critical)
    pub business_criticality: i64,
    /// Data sensitivity level
    pub data_sensitivity: Option<String>,
    /// Trust composite score (0-100)
    pub trust_composite: f64,
    /// Whether this resource has any backup snapshots (PROTECTED_BY edges)
    pub has_backups: bool,
    /// Number of backup snapshots
    pub snapshot_count: usize,
    /// Environment (production, staging, dev)
    pub environment: Option<String>,
    /// Monthly cost in cents
    pub monthly_cost_cents: i64,
    /// Risk tier computed from status + criticality
    pub risk_tier: RiskTier,
}

/// Risk tier for prioritization
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskTier {
    /// Unprotected + high criticality
    Critical,
    /// Unprotected + medium criticality, or partial + high criticality
    High,
    /// Partial protection, or low criticality unprotected
    Medium,
    /// Protected and healthy
    Low,
}

/// Summary across the entire estate
#[derive(Debug)]
pub struct ProtectionSummary {
    /// All resources with their protection status
    pub resources: Vec<ResourceProtection>,
    /// Total protectable resources
    pub total: usize,
    /// Fully protected count
    pub protected: usize,
    /// Partially protected count
    pub partial: usize,
    /// Unprotected count
    pub unprotected: usize,
    /// Unknown status count
    pub unknown: usize,
    /// Overall protection percentage (0.0 - 1.0)
    pub coverage_ratio: f64,
    /// Total monthly cost of unprotected resources (cents)
    pub unprotected_cost_cents: i64,
    /// Breakdown by resource type
    pub by_type: std::collections::HashMap<String, TypeBreakdown>,
    /// Breakdown by cloud provider
    pub by_provider: std::collections::HashMap<String, TypeBreakdown>,
}

/// Counts for a category
#[derive(Debug, Clone, Default)]
pub struct TypeBreakdown {
    pub total: usize,
    pub protected: usize,
    pub unprotected: usize,
}

/// Query the protection status of all protectable resources.
pub fn protection_summary(graph: &dyn GraphReader) -> ProtectionSummary {
    let mut resources: Vec<ResourceProtection> = Vec::new();

    for &type_id in PROTECTABLE_TYPES {
        let nodes = graph.nodes_by_type(type_id);
        for node in nodes {
            if !node.is_alive() {
                continue;
            }

            let status = node.get_str(prop::PROTECTION_STATUS)
                .unwrap_or("unknown")
                .to_string();
            let criticality = node.get_i64(prop::BUSINESS_CRITICALITY).unwrap_or(0);

            // Count backup snapshots via PROTECTED_BY edges
            let backup_edges = graph.outgoing_edges_of_type(node.id(), crate::nodes::PROTECTED_BY);
            let snapshot_count = backup_edges.len();
            let has_backups = snapshot_count > 0;

            let risk_tier = compute_risk_tier(&status, criticality);

            resources.push(ResourceProtection {
                node_id: node.id().clone(),
                node_type: type_id.to_string(),
                name: node.get_str(prop::NAME).map(|s| s.to_string()),
                cloud_provider: node.get_str("cloud_provider").map(|s| s.to_string()),
                region: node.get_str(prop::REGION).map(|s| s.to_string()),
                protection_status: status,
                business_criticality: criticality,
                data_sensitivity: node.get_str(prop::DATA_SENSITIVITY).map(|s| s.to_string()),
                trust_composite: node.get_f64(prop::TRUST_COMPOSITE).unwrap_or(0.0),
                has_backups,
                snapshot_count,
                environment: node.get_str(prop::ENVIRONMENT).map(|s| s.to_string()),
                monthly_cost_cents: node.get_i64(prop::MONTHLY_COST_CENTS).unwrap_or(0),
                risk_tier,
            });
        }
    }

    // Sort by risk tier (Critical first), then by criticality descending
    resources.sort_by(|a, b| {
        a.risk_tier.cmp(&b.risk_tier)
            .then(b.business_criticality.cmp(&a.business_criticality))
    });

    // Compute summaries
    let total = resources.len();
    let protected = resources.iter().filter(|r| r.protection_status == "protected").count();
    let partial = resources.iter().filter(|r| r.protection_status == "partial").count();
    let unprotected = resources.iter().filter(|r| r.protection_status == "unprotected").count();
    let unknown = total - protected - partial - unprotected;
    let coverage_ratio = if total == 0 { 1.0 } else { protected as f64 / total as f64 };
    let unprotected_cost_cents: i64 = resources.iter()
        .filter(|r| r.protection_status == "unprotected")
        .map(|r| r.monthly_cost_cents)
        .sum();

    let mut by_type: std::collections::HashMap<String, TypeBreakdown> = std::collections::HashMap::new();
    let mut by_provider: std::collections::HashMap<String, TypeBreakdown> = std::collections::HashMap::new();

    for r in &resources {
        let t = by_type.entry(r.node_type.clone()).or_default();
        t.total += 1;
        if r.protection_status == "protected" { t.protected += 1; }
        if r.protection_status == "unprotected" { t.unprotected += 1; }

        if let Some(ref p) = r.cloud_provider {
            let pb = by_provider.entry(p.clone()).or_default();
            pb.total += 1;
            if r.protection_status == "protected" { pb.protected += 1; }
            if r.protection_status == "unprotected" { pb.unprotected += 1; }
        }
    }

    ProtectionSummary {
        resources,
        total,
        protected,
        partial,
        unprotected,
        unknown,
        coverage_ratio,
        unprotected_cost_cents,
        by_type,
        by_provider,
    }
}

fn compute_risk_tier(status: &str, criticality: i64) -> RiskTier {
    match (status, criticality) {
        ("unprotected", c) if c >= 7 => RiskTier::Critical,
        ("unprotected", c) if c >= 4 => RiskTier::High,
        ("unprotected", _) => RiskTier::Medium,
        ("partial", c) if c >= 7 => RiskTier::High,
        ("partial", _) => RiskTier::Medium,
        ("protected", _) => RiskTier::Low,
        _ => RiskTier::Medium, // unknown status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_engine::prelude::*;
    use crate::nodes::aws::*;
    use crate::nodes::resource::*;

    #[test]
    fn empty_graph_returns_full_coverage() {
        let hydra = Hydra::new();
        let summary = protection_summary(hydra.graph());
        assert_eq!(summary.total, 0);
        assert!((summary.coverage_ratio - 1.0).abs() < 0.001);
    }

    #[test]
    fn unprotected_resources_detected() {
        let mut hydra = Hydra::new();

        // RDS with business_criticality=9, unprotected
        let (rds, ev) = RdsBuilder::new("db-prod")
            .business_criticality(9)
            .data_sensitivity("critical")
            .monthly_cost_cents(50000)
            .build();
        hydra.ingest(ev).unwrap();

        // EC2, unprotected
        let (_, ev) = Ec2Builder::new("i-001").business_criticality(5).build();
        hydra.ingest(ev).unwrap();

        let summary = protection_summary(hydra.graph());
        assert_eq!(summary.total, 2);
        assert_eq!(summary.unprotected, 2);
        assert_eq!(summary.protected, 0);
        assert!((summary.coverage_ratio - 0.0).abs() < 0.001);
        assert_eq!(summary.unprotected_cost_cents, 50000);

        // First resource should be the RDS (Critical risk tier)
        assert_eq!(summary.resources[0].node_id, rds);
        assert_eq!(summary.resources[0].risk_tier, RiskTier::Critical);
    }

    #[test]
    fn multi_cloud_protection_status() {
        let mut hydra = Hydra::new();
        use crate::nodes::azure::*;
        use crate::nodes::gcp::*;

        let (_, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = AzureVmBuilder::new("vm-001").build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = GceBuilder::new("gce-001").build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = SaasApplicationBuilder::new("m365", "microsoft_365").build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = EndpointBuilder::new("laptop-001").build();
        hydra.ingest(ev).unwrap();

        let summary = protection_summary(hydra.graph());
        assert_eq!(summary.total, 5);
        assert!(summary.by_provider.contains_key("aws"));
        assert!(summary.by_provider.contains_key("azure"));
        assert!(summary.by_provider.contains_key("gcp"));
        assert!(summary.by_provider.contains_key("saas"));
        assert!(summary.by_provider.contains_key("on_prem"));
    }

    #[test]
    fn risk_tier_classification() {
        assert_eq!(compute_risk_tier("unprotected", 9), RiskTier::Critical);
        assert_eq!(compute_risk_tier("unprotected", 5), RiskTier::High);
        assert_eq!(compute_risk_tier("unprotected", 2), RiskTier::Medium);
        assert_eq!(compute_risk_tier("partial", 8), RiskTier::High);
        assert_eq!(compute_risk_tier("partial", 3), RiskTier::Medium);
        assert_eq!(compute_risk_tier("protected", 10), RiskTier::Low);
        assert_eq!(compute_risk_tier("unknown", 5), RiskTier::Medium);
    }

    #[test]
    fn by_type_breakdown() {
        let mut hydra = Hydra::new();

        let (_, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = Ec2Builder::new("i-002").build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = RdsBuilder::new("db-001").build();
        hydra.ingest(ev).unwrap();

        let summary = protection_summary(hydra.graph());
        let compute = summary.by_type.get(COMPUTE_INSTANCE).unwrap();
        assert_eq!(compute.total, 2);
        assert_eq!(compute.unprotected, 2);

        let db = summary.by_type.get(MANAGED_DATABASE).unwrap();
        assert_eq!(db.total, 1);
    }

    #[test]
    fn protected_resource_counted_correctly() {
        use hydra_core::event::{EventKind, Value};

        let mut hydra = Hydra::new();
        let (rds, ev) = RdsBuilder::new("db-001").build();
        hydra.ingest(ev).unwrap();

        // Mark as protected
        hydra.ingest(EventKind::NodeUpdated {
            node_id: rds.clone(),
            changes: std::collections::HashMap::from([
                (crate::nodes::prop::PROTECTION_STATUS.to_string(), Value::String("protected".into())),
            ]),
        }).unwrap();

        let summary = protection_summary(hydra.graph());
        assert_eq!(summary.protected, 1);
        assert_eq!(summary.unprotected, 0);
        assert!((summary.coverage_ratio - 1.0).abs() < 0.001);
        assert_eq!(summary.resources[0].risk_tier, RiskTier::Low);
    }
}
