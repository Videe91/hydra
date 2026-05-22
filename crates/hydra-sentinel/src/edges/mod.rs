//! # Sentinel Edge Factories
//!
//! Typed edge construction for the Sentinel data resilience graph.
//!
//! ## Direction Convention
//!
//! Every edge follows: `source VERB target`
//! - EC2 --IN_VPC--> VPC  (EC2 is IN the VPC)
//! - EC2 --DEPENDS_ON--> RDS  (EC2 depends ON the RDS)
//! - Snapshot --SNAPSHOT_OF--> RDS  (Snapshot is a snapshot OF the RDS)
//! - Policy --POLICY_APPLIES_TO--> EC2  (Policy applies TO the EC2)
//!
//! This means:
//! - `outgoing_edges(ec2)` → finds what EC2 depends on / lives in
//! - `incoming_edges(rds)` → finds what depends on / protects the RDS
//! - BFS from a compromised node follows INCOMING edges to find blast radius
//!   (what depends on this node? what would break?)
//!
//! ## Property Convention
//!
//! Every edge carries:
//! - `discovered_by`: which Arm or sensor created this edge
//! - `confidence`: 0.0-1.0 how certain we are this relationship exists
//! - `discovered_at`: when this edge was first created
//!
//! Domain-specific edges add additional properties that the anomaly engine
//! can detect patterns on (e.g., dependency_type, permission_level).

use hydra_core::event::{EventKind, Value};
use hydra_core::id::{EdgeId, NodeId};
use std::collections::HashMap;
use chrono::Utc;

use crate::nodes::*;

// ============================================================================
// Common edge property keys
// ============================================================================
pub mod edge_prop {
    pub const DISCOVERED_BY: &str = "discovered_by";
    pub const CONFIDENCE: &str = "confidence";
    pub const DISCOVERED_AT: &str = "discovered_at";
}

// ============================================================================
// Helper: base properties every edge gets
// ============================================================================
fn base_props(discovered_by: &str, confidence: f64) -> HashMap<String, Value> {
    let mut props = HashMap::new();
    props.insert(edge_prop::DISCOVERED_BY.into(), Value::String(discovered_by.into()));
    props.insert(edge_prop::CONFIDENCE.into(), Value::Float(confidence.clamp(0.0, 1.0)));
    props.insert(edge_prop::DISCOVERED_AT.into(), Value::Timestamp(Utc::now()));
    props
}

fn make_edge(
    source: NodeId,
    target: NodeId,
    type_id: &str,
    props: HashMap<String, Value>,
) -> (EdgeId, EventKind) {
    let edge_id = EdgeId::new();
    let eid = edge_id.clone();
    (eid, EventKind::EdgeCreated {
        edge_id,
        source,
        target,
        type_id: type_id.to_string(),
        properties: props,
    })
}

// ============================================================================
// Infrastructure Edges
// ============================================================================

/// EC2/RDS/Lambda → VPC: resource lives in this VPC.
///
/// Coverage rule: every compute/db node MUST have exactly 1 IN_VPC edge.
/// Topology rule: VPC with 0 incoming IN_VPC edges = orphan VPC (anomaly).
/// BFS: from VPC, incoming IN_VPC gives all resources in the VPC.
pub fn in_vpc(resource: NodeId, vpc: NodeId) -> (EdgeId, EventKind) {
    let mut props = base_props("discovery_arm", 1.0);
    props.insert("relationship".into(), Value::String("containment".into()));
    make_edge(resource, vpc, IN_VPC, props)
}

/// EC2/Lambda → Subnet: resource lives in this subnet.
///
/// More granular than IN_VPC. Enables blast radius scoping by subnet.
pub fn in_subnet(resource: NodeId, subnet: NodeId) -> (EdgeId, EventKind) {
    let mut props = base_props("discovery_arm", 1.0);
    props.insert("relationship".into(), Value::String("containment".into()));
    make_edge(resource, subnet, IN_SUBNET, props)
}

/// EC2/RDS/Lambda → SecurityGroup: resource uses this security group.
///
/// Pattern rule: node with > 10 HAS_SECURITY_GROUP edges = over-permissioned.
/// BFS: from SecurityGroup, incoming edges show all protected resources.
pub fn has_security_group(resource: NodeId, sg: NodeId) -> (EdgeId, EventKind) {
    let mut props = base_props("discovery_arm", 1.0);
    props.insert("relationship".into(), Value::String("access_control".into()));
    make_edge(resource, sg, HAS_SECURITY_GROUP, props)
}

/// EBS Volume → EC2: volume is attached to this instance.
///
/// Coverage rule: every EBS volume SHOULD have 1 ATTACHED_TO edge
/// (unattached volumes = cost waste or orphaned data).
pub fn attached_to(volume: NodeId, instance: NodeId) -> (EdgeId, EventKind) {
    let mut props = base_props("discovery_arm", 1.0);
    props.insert("device".into(), Value::String("/dev/xvda".into()));
    make_edge(volume, instance, ATTACHED_TO, props)
}

/// EC2/Lambda → IAM Role: resource assumes this role.
///
/// Pattern rule: IAM role with incoming ASSUMES_ROLE from > 20 resources = blast risk.
/// Anomaly: new resource assuming admin role = high severity alert.
pub fn assumes_role(resource: NodeId, role: NodeId) -> (EdgeId, EventKind) {
    let mut props = base_props("discovery_arm", 1.0);
    props.insert("relationship".into(), Value::String("identity".into()));
    make_edge(resource, role, ASSUMES_ROLE, props)
}

// ============================================================================
// Dependency Edges
// ============================================================================

/// Resource → Resource: source depends on target.
///
/// This is the most critical edge type for blast radius computation.
/// BFS from a compromised node following INCOMING depends_on edges
/// gives the full blast radius (everything that would break).
///
/// `dependency_type` property enables anomaly rules:
/// - "database": RDS goes down → all dependent EC2s affected
/// - "network": VPC peering breaks → cross-VPC dependencies fail
/// - "storage": S3 bucket deleted → all readers break
/// - "compute": upstream service down → downstream cascades
/// - "identity": IAM role revoked → all assumers lose access
pub fn depends_on(
    dependent: NodeId,
    dependency: NodeId,
    dependency_type: &str,
    confidence: f64,
) -> (EdgeId, EventKind) {
    let mut props = base_props("discovery_arm", confidence);
    props.insert("dependency_type".into(), Value::String(dependency_type.into()));
    props.insert("is_hard_dependency".into(), Value::Bool(true));
    make_edge(dependent, dependency, DEPENDS_ON, props)
}

/// Soft dependency — system degrades but doesn't fail without it.
/// Separate from hard dependency for blast radius severity calculation.
pub fn depends_on_soft(
    dependent: NodeId,
    dependency: NodeId,
    dependency_type: &str,
    confidence: f64,
) -> (EdgeId, EventKind) {
    let mut props = base_props("discovery_arm", confidence);
    props.insert("dependency_type".into(), Value::String(dependency_type.into()));
    props.insert("is_hard_dependency".into(), Value::Bool(false));
    make_edge(dependent, dependency, DEPENDS_ON, props)
}

// ============================================================================
// Protection Edges
// ============================================================================

/// Snapshot → Resource: this snapshot protects this resource.
///
/// Coverage rule: every protectable resource MUST have ≥1 SNAPSHOT_OF edge.
/// Resources with 0 incoming SNAPSHOT_OF = unprotected (critical gap).
/// Temporal: track when SNAPSHOT_OF edges are created to detect backup gaps.
pub fn snapshot_of(snapshot: NodeId, resource: NodeId) -> (EdgeId, EventKind) {
    let props = base_props("execution_arm", 1.0);
    make_edge(snapshot, resource, SNAPSHOT_OF, props)
}

/// Resource → Snapshot: resource is protected by this snapshot.
/// Inverse of snapshot_of — used when the resource "has" a backup.
///
/// This edge is on the resource, pointing to its latest verified backup.
/// When the anomaly engine sees a resource with no outgoing PROTECTED_BY edge,
/// that's a gap in protection.
pub fn protected_by(resource: NodeId, snapshot: NodeId) -> (EdgeId, EventKind) {
    let mut props = base_props("execution_arm", 1.0);
    props.insert("protection_type".into(), Value::String("backup".into()));
    make_edge(resource, snapshot, PROTECTED_BY, props)
}

/// VerificationResult → Snapshot: this verification tested this snapshot.
///
/// Coverage rule: every snapshot SHOULD have ≥1 VERIFIED_BY edge.
/// Snapshots with 0 incoming VERIFIED_BY = unverified (trust gap).
/// Temporal: when was the last VERIFIED_BY edge created? Staleness detection.
pub fn verified_by(snapshot: NodeId, verification: NodeId) -> (EdgeId, EventKind) {
    let props = base_props("verification_arm", 1.0);
    make_edge(snapshot, verification, VERIFIED_BY, props)
}

/// Policy → Resource: this policy governs this resource's protection.
///
/// Coverage: every protectable resource SHOULD have ≥1 POLICY_APPLIES_TO incoming.
/// Resources without policy = unmanaged (the Policy Arm should create one).
/// Pattern: policy with 0 outgoing POLICY_APPLIES_TO = unused policy (cost waste).
pub fn policy_applies_to(policy: NodeId, resource: NodeId) -> (EdgeId, EventKind) {
    let props = base_props("policy_arm", 1.0);
    make_edge(policy, resource, POLICY_APPLIES_TO, props)
}

/// RecoveryPlan → Resource: this recovery plan targets this resource.
///
/// Created by the Response Arm during incident response.
/// Multiple resources can be targeted by one recovery plan.
pub fn recovery_targets(plan: NodeId, resource: NodeId, priority: i64) -> (EdgeId, EventKind) {
    let mut props = base_props("response_arm", 1.0);
    props.insert("recovery_priority".into(), Value::Int(priority));
    make_edge(plan, resource, RECOVERY_TARGETS, props)
}

// ============================================================================
// Intelligence Edges
// ============================================================================

/// TrustScore → Resource: this trust score evaluates this resource.
///
/// One trust score node per resource. The score node carries the 7 dimensions
/// as properties, and this edge connects it to the resource it evaluates.
pub fn scored_by(resource: NodeId, trust_score: NodeId) -> (EdgeId, EventKind) {
    let props = base_props("trust_arm", 1.0);
    make_edge(resource, trust_score, SCORED_BY, props)
}

/// Anomaly → Resource: this anomaly was detected on this resource.
///
/// A single anomaly can be DETECTED_ON multiple resources (cascade anomalies).
/// BFS from anomaly following DETECTED_ON shows all affected resources.
/// Pattern: resource with > 5 incoming DETECTED_ON in 24h = hot spot.
pub fn detected_on(anomaly: NodeId, resource: NodeId, severity: f64) -> (EdgeId, EventKind) {
    let mut props = base_props("detection_arm", 1.0);
    props.insert("severity".into(), Value::Float(severity.clamp(0.0, 1.0)));
    make_edge(anomaly, resource, DETECTED_ON, props)
}

/// Incident → Resource: this incident involves this resource.
///
/// Similar to DETECTED_ON but for confirmed incidents (higher severity).
/// BFS from incident shows full blast radius of the incident.
pub fn incident_involves(incident: NodeId, resource: NodeId, role: &str) -> (EdgeId, EventKind) {
    let mut props = base_props("response_arm", 1.0);
    props.insert("role".into(), Value::String(role.into()));
    make_edge(incident, resource, INCIDENT_INVOLVES, props)
}

// ============================================================================
// Compliance Edges
// ============================================================================

/// Resource → Regulation: this resource is regulated by this framework.
///
/// Created by the Compliance Arm when it matches resource classification
/// (data_sensitivity, regulatory_scope) to applicable regulations.
/// Coverage: every high-sensitivity resource SHOULD have ≥1 REGULATED_BY.
pub fn regulated_by(resource: NodeId, regulation: NodeId) -> (EdgeId, EventKind) {
    let props = base_props("compliance_arm", 1.0);
    make_edge(resource, regulation, REGULATED_BY, props)
}

/// ComplianceStatus → Resource: this compliance evaluation covers this resource.
///
/// One ComplianceStatus per (resource, regulation) pair.
/// The compliance status node carries per-requirement check results.
pub fn compliance_of(compliance_status: NodeId, resource: NodeId) -> (EdgeId, EventKind) {
    let props = base_props("compliance_arm", 1.0);
    make_edge(compliance_status, resource, COMPLIANCE_OF, props)
}


// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_engine::prelude::*;

    /// Helper: ingest an edge event and return the edge_id
    fn ingest_edge(hydra: &mut Hydra, edge_event: (EdgeId, EventKind)) -> EdgeId {
        let (eid, ev) = edge_event;
        hydra.ingest(ev).unwrap();
        eid
    }

    // ================================================================
    // Pass 1 (Security): Confidence clamping, no injection via strings
    // ================================================================

    #[test]
    fn confidence_clamped_to_valid_range() {
        let a = NodeId::new();
        let b = NodeId::new();
        let (_, ev) = depends_on(a, b, "database", 999.0);
        if let EventKind::EdgeCreated { properties, .. } = &ev {
            let conf = properties.get(edge_prop::CONFIDENCE)
                .and_then(|v| v.as_f64()).unwrap();
            assert!((conf - 1.0).abs() < 0.001, "Confidence should clamp to 1.0, got {}", conf);
        } else {
            panic!("Expected EdgeCreated");
        }
    }

    #[test]
    fn confidence_clamped_negative() {
        let a = NodeId::new();
        let b = NodeId::new();
        let (_, ev) = depends_on(a, b, "database", -5.0);
        if let EventKind::EdgeCreated { properties, .. } = &ev {
            let conf = properties.get(edge_prop::CONFIDENCE)
                .and_then(|v| v.as_f64()).unwrap();
            assert!((conf - 0.0).abs() < 0.001, "Negative confidence should clamp to 0.0, got {}", conf);
        } else {
            panic!("Expected EdgeCreated");
        }
    }

    // ================================================================
    // Pass 2 (Correctness): Direction, properties, type_id
    // ================================================================

    #[test]
    fn in_vpc_direction_and_type() {
        let ec2 = NodeId::new();
        let vpc = NodeId::new();
        let (_, ev) = in_vpc(ec2.clone(), vpc.clone());
        if let EventKind::EdgeCreated { source, target, type_id, .. } = &ev {
            assert_eq!(source, &ec2, "Source should be the resource");
            assert_eq!(target, &vpc, "Target should be the VPC");
            assert_eq!(type_id, IN_VPC);
        } else {
            panic!("Expected EdgeCreated");
        }
    }

    #[test]
    fn depends_on_carries_dependency_type() {
        let a = NodeId::new();
        let b = NodeId::new();
        let (_, ev) = depends_on(a, b, "database", 0.95);
        if let EventKind::EdgeCreated { properties, .. } = &ev {
            assert_eq!(
                properties.get("dependency_type").and_then(|v| v.as_str()),
                Some("database")
            );
            assert_eq!(
                properties.get("is_hard_dependency").and_then(|v| v.as_bool()),
                Some(true)
            );
        } else {
            panic!("Expected EdgeCreated");
        }
    }

    #[test]
    fn soft_dependency_flagged_correctly() {
        let a = NodeId::new();
        let b = NodeId::new();
        let (_, ev) = depends_on_soft(a, b, "cache", 0.7);
        if let EventKind::EdgeCreated { properties, .. } = &ev {
            assert_eq!(
                properties.get("is_hard_dependency").and_then(|v| v.as_bool()),
                Some(false)
            );
        } else {
            panic!("Expected EdgeCreated");
        }
    }

    #[test]
    fn snapshot_of_direction() {
        let snap = NodeId::new();
        let rds = NodeId::new();
        let (_, ev) = snapshot_of(snap.clone(), rds.clone());
        if let EventKind::EdgeCreated { source, target, type_id, .. } = &ev {
            assert_eq!(source, &snap, "Source = snapshot");
            assert_eq!(target, &rds, "Target = resource being backed up");
            assert_eq!(type_id, SNAPSHOT_OF);
        } else {
            panic!("Expected EdgeCreated");
        }
    }

    #[test]
    fn detected_on_severity_clamped() {
        let anomaly = NodeId::new();
        let resource = NodeId::new();
        let (_, ev) = detected_on(anomaly, resource, 5.0);
        if let EventKind::EdgeCreated { properties, .. } = &ev {
            let sev = properties.get("severity").and_then(|v| v.as_f64()).unwrap();
            assert!((sev - 1.0).abs() < 0.001, "Severity should clamp to 1.0");
        } else {
            panic!("Expected EdgeCreated");
        }
    }

    #[test]
    fn recovery_targets_carries_priority() {
        let plan = NodeId::new();
        let resource = NodeId::new();
        let (_, ev) = recovery_targets(plan, resource, 1);
        if let EventKind::EdgeCreated { properties, .. } = &ev {
            assert_eq!(
                properties.get("recovery_priority").and_then(|v| v.as_i64()),
                Some(1)
            );
        } else {
            panic!("Expected EdgeCreated");
        }
    }

    #[test]
    fn incident_involves_carries_role() {
        let inc = NodeId::new();
        let res = NodeId::new();
        let (_, ev) = incident_involves(inc, res, "patient_zero");
        if let EventKind::EdgeCreated { properties, .. } = &ev {
            assert_eq!(
                properties.get("role").and_then(|v| v.as_str()),
                Some("patient_zero")
            );
        } else {
            panic!("Expected EdgeCreated");
        }
    }

    #[test]
    fn all_edges_have_base_properties() {
        let a = NodeId::new();
        let b = NodeId::new();

        let edge_events: Vec<(EdgeId, EventKind)> = vec![
            in_vpc(a.clone(), b.clone()),
            in_subnet(a.clone(), b.clone()),
            has_security_group(a.clone(), b.clone()),
            attached_to(a.clone(), b.clone()),
            assumes_role(a.clone(), b.clone()),
            depends_on(a.clone(), b.clone(), "database", 0.9),
            depends_on_soft(a.clone(), b.clone(), "cache", 0.5),
            snapshot_of(a.clone(), b.clone()),
            protected_by(a.clone(), b.clone()),
            verified_by(a.clone(), b.clone()),
            policy_applies_to(a.clone(), b.clone()),
            recovery_targets(a.clone(), b.clone(), 1),
            scored_by(a.clone(), b.clone()),
            detected_on(a.clone(), b.clone(), 0.8),
            incident_involves(a.clone(), b.clone(), "source"),
            regulated_by(a.clone(), b.clone()),
            compliance_of(a.clone(), b.clone()),
        ];

        for (i, (_, ev)) in edge_events.iter().enumerate() {
            if let EventKind::EdgeCreated { properties, type_id, .. } = ev {
                assert!(
                    properties.contains_key(edge_prop::DISCOVERED_BY),
                    "Edge {} ({}) missing discovered_by", i, type_id
                );
                assert!(
                    properties.contains_key(edge_prop::CONFIDENCE),
                    "Edge {} ({}) missing confidence", i, type_id
                );
                assert!(
                    properties.contains_key(edge_prop::DISCOVERED_AT),
                    "Edge {} ({}) missing discovered_at", i, type_id
                );
            } else {
                panic!("Edge {} was not EdgeCreated", i);
            }
        }
    }

    // ================================================================
    // Pass 3 (Performance): edges work with engine topology queries
    // ================================================================

    #[test]
    fn engine_topology_queries_with_sentinel_edges() {
        let mut hydra = Hydra::new();

        // Build: VPC ← EC2 → RDS, EC2 → SecurityGroup
        let (vpc_id, vpc_ev) = crate::nodes::aws::VpcBuilder::new("vpc-1").build();
        hydra.ingest(vpc_ev).unwrap();

        let (ec2_id, ec2_ev) = crate::nodes::aws::Ec2Builder::new("i-001").build();
        hydra.ingest(ec2_ev).unwrap();

        let (rds_id, rds_ev) = crate::nodes::aws::RdsBuilder::new("db-001").build();
        hydra.ingest(rds_ev).unwrap();

        let (sg_id, sg_ev) = crate::nodes::aws::VpcBuilder::new("sg-001").build();
        hydra.ingest(sg_ev).unwrap();

        // EC2 --IN_VPC--> VPC
        ingest_edge(&mut hydra, in_vpc(ec2_id.clone(), vpc_id.clone()));

        // EC2 --DEPENDS_ON--> RDS
        ingest_edge(&mut hydra, depends_on(ec2_id.clone(), rds_id.clone(), "database", 0.99));

        // EC2 --HAS_SECURITY_GROUP--> SG
        ingest_edge(&mut hydra, has_security_group(ec2_id.clone(), sg_id.clone()));

        // Verify: outgoing from EC2 = 3 edges (IN_VPC, DEPENDS_ON, HAS_SECURITY_GROUP)
        let outgoing = hydra.graph().outgoing_edges(&ec2_id);
        assert_eq!(outgoing.len(), 3, "EC2 should have 3 outgoing edges");

        // Verify: outgoing_of_type
        let vpc_edges = hydra.graph().outgoing_edges_of_type(&ec2_id, IN_VPC);
        assert_eq!(vpc_edges.len(), 1);

        let dep_edges = hydra.graph().outgoing_edges_of_type(&ec2_id, DEPENDS_ON);
        assert_eq!(dep_edges.len(), 1);
        assert_eq!(dep_edges[0].meta.target, rds_id);

        // Verify: incoming to RDS = 1 (DEPENDS_ON from EC2)
        let incoming = hydra.graph().incoming_edges_of_type(&rds_id, DEPENDS_ON);
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].meta.source, ec2_id);
    }

    #[test]
    fn bfs_follows_sentinel_edges_for_blast_radius() {
        use hydra_core::graph::{bfs_dyn, TraversalDirection};

        let mut hydra = Hydra::new();

        // Build: EC2 → RDS → S3 (dependency chain)
        let (ec2_id, ec2_ev) = crate::nodes::aws::Ec2Builder::new("i-001").build();
        hydra.ingest(ec2_ev).unwrap();

        let (rds_id, rds_ev) = crate::nodes::aws::RdsBuilder::new("db-001").build();
        hydra.ingest(rds_ev).unwrap();

        let (s3_id, s3_ev) = crate::nodes::aws::S3BucketBuilder::new("bucket-001").build();
        hydra.ingest(s3_ev).unwrap();

        // EC2 depends on RDS, RDS depends on S3
        ingest_edge(&mut hydra, depends_on(ec2_id.clone(), rds_id.clone(), "database", 1.0));
        ingest_edge(&mut hydra, depends_on(rds_id.clone(), s3_id.clone(), "storage", 1.0));

        // Blast radius from S3: follow INCOMING direction (who depends on S3?)
        let blast = bfs_dyn(
            hydra.graph(),
            &s3_id,
            TraversalDirection::Incoming,
            &|_| true,
        );
        assert_eq!(blast.len(), 3, "Blast from S3 should reach S3 + RDS + EC2");

        // Blast radius from RDS: RDS ← EC2
        let blast = bfs_dyn(
            hydra.graph(),
            &rds_id,
            TraversalDirection::Incoming,
            &|_| true,
        );
        assert_eq!(blast.len(), 2, "Blast from RDS should reach RDS + EC2");

        // Forward BFS from EC2: EC2 → RDS → S3
        let forward = bfs_dyn(
            hydra.graph(),
            &ec2_id,
            TraversalDirection::Outgoing,
            &|_| true,
        );
        assert_eq!(forward.len(), 3, "Forward from EC2 should reach EC2 + RDS + S3");
    }

    // ================================================================
    // Pass 4 (Integration): edges work with anomaly + coverage engines
    // ================================================================

    #[test]
    fn coverage_engine_validates_sentinel_edge_presence() {
        let mut hydra = Hydra::new();

        // Two EC2 instances, one VPC
        let (vpc_id, vpc_ev) = crate::nodes::aws::VpcBuilder::new("vpc-1").build();
        hydra.ingest(vpc_ev).unwrap();

        let (ec2_a, ec2_a_ev) = crate::nodes::aws::Ec2Builder::new("i-001").build();
        hydra.ingest(ec2_a_ev).unwrap();

        let (_ec2_b, ec2_b_ev) = crate::nodes::aws::Ec2Builder::new("i-002").build();
        hydra.ingest(ec2_b_ev).unwrap();

        // Only ec2_a has IN_VPC edge — ec2_b is orphaned
        ingest_edge(&mut hydra, in_vpc(ec2_a.clone(), vpc_id.clone()));

        hydra.coverage_engine_mut().add_model(CoverageModel {
            name: "all_ec2_in_vpc".to_string(),
            expectations: vec![
                CoverageExpectation::EdgeCoverage {
                    source_type: EC2_INSTANCE.to_string(),
                    edge_type: IN_VPC.to_string(),
                    target_type: VPC.to_string(),
                    min_per_source: 1,
                },
            ],
            scope_node_type: None,
        });

        let reports = hydra.evaluate_coverage();
        assert_eq!(reports.len(), 1);
        assert!(!reports[0].is_complete(), "Should detect ec2_b missing IN_VPC");
        assert!(reports[0].score < 1.0, "Score should be < 1.0 with gap");
        assert!(!reports[0].gaps.is_empty(), "Should have at least 1 gap");
    }

    #[test]
    fn topology_rule_detects_ec2_missing_vpc_edge() {
        let mut hydra = Hydra::new();

        // EC2 with no edges at all
        let (_ec2_id, ec2_ev) = crate::nodes::aws::Ec2Builder::new("i-orphan").build();
        hydra.ingest(ec2_ev).unwrap();

        hydra.anomaly_engine_mut().add_topology_rule(TopologyRule {
            node_type: EC2_INSTANCE.to_string(),
            edge_type: IN_VPC.to_string(),
            min_degree: 1,
            max_degree: 1,
            severity: 0.9,
        });

        let anomalies = hydra.analyze_batch();
        let relevant: Vec<_> = anomalies.iter()
            .filter(|a| matches!(a.kind, AnomalyKind::StructuralOrphan { .. }))
            .collect();
        assert!(!relevant.is_empty(), "Should detect orphan EC2 with no IN_VPC edge");
    }

    #[test]
    fn topology_rule_detects_overpermissioned_role() {
        let mut hydra = Hydra::new();

        // 1 IAM role, 12 EC2 instances all assuming it
        // Edge direction: EC2 --ASSUMES_ROLE--> IAM_ROLE
        // So IAM_ROLE has 12 INCOMING assumes_role edges
        let (role_id, role_ev) = crate::nodes::aws::IamRoleBuilder::new("admin-role")
            .has_admin_access(true)
            .build();
        hydra.ingest(role_ev).unwrap();

        for i in 0..12 {
            let (ec2_id, ec2_ev) = crate::nodes::aws::Ec2Builder::new(&format!("i-{:03}", i)).build();
            hydra.ingest(ec2_ev).unwrap();
            ingest_edge(&mut hydra, assumes_role(ec2_id.clone(), role_id.clone()));
        }

        // TopologyRule counts BOTH outgoing + incoming, so it catches
        // IAM_ROLE with 12 incoming ASSUMES_ROLE edges (degree = 12 > max 10)
        hydra.anomaly_engine_mut().add_topology_rule(TopologyRule {
            node_type: IAM_ROLE.to_string(),
            edge_type: ASSUMES_ROLE.to_string(),
            min_degree: 0,
            max_degree: 10,
            severity: 0.95,
        });

        let anomalies = hydra.analyze_batch();
        let relevant: Vec<_> = anomalies.iter()
            .filter(|a| matches!(a.kind, AnomalyKind::TopologyDegree { .. }))
            .collect();
        assert!(!relevant.is_empty(), "Should detect admin role with 12 assumers exceeding max_degree 10");
    }

    // ================================================================
    // Pass 5 (Completeness): all 16 edge types produce unique type_ids
    // ================================================================

    #[test]
    fn all_edge_types_produce_correct_type_ids() {
        let a = NodeId::new();
        let b = NodeId::new();

        let cases: Vec<(&str, (EdgeId, EventKind))> = vec![
            (IN_VPC, in_vpc(a.clone(), b.clone())),
            (IN_SUBNET, in_subnet(a.clone(), b.clone())),
            (HAS_SECURITY_GROUP, has_security_group(a.clone(), b.clone())),
            (ATTACHED_TO, attached_to(a.clone(), b.clone())),
            (ASSUMES_ROLE, assumes_role(a.clone(), b.clone())),
            (DEPENDS_ON, depends_on(a.clone(), b.clone(), "db", 1.0)),
            (SNAPSHOT_OF, snapshot_of(a.clone(), b.clone())),
            (PROTECTED_BY, protected_by(a.clone(), b.clone())),
            (VERIFIED_BY, verified_by(a.clone(), b.clone())),
            (POLICY_APPLIES_TO, policy_applies_to(a.clone(), b.clone())),
            (RECOVERY_TARGETS, recovery_targets(a.clone(), b.clone(), 1)),
            (SCORED_BY, scored_by(a.clone(), b.clone())),
            (DETECTED_ON, detected_on(a.clone(), b.clone(), 0.5)),
            (INCIDENT_INVOLVES, incident_involves(a.clone(), b.clone(), "target")),
            (REGULATED_BY, regulated_by(a.clone(), b.clone())),
            (COMPLIANCE_OF, compliance_of(a.clone(), b.clone())),
        ];

        for (expected_type, (_, ev)) in &cases {
            if let EventKind::EdgeCreated { type_id, .. } = ev {
                assert_eq!(type_id, expected_type, "Type mismatch for {}", expected_type);
            } else {
                panic!("Expected EdgeCreated for {}", expected_type);
            }
        }
    }
}
