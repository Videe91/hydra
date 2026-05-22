//! # Confidence Report Query
//!
//! "How confident are we that we can recover from a disaster right now?"
//!
//! Aggregates trust scores, verification status, and recovery readiness
//! across the entire estate into a single confidence assessment.

use hydra_core::graph::GraphReader;
use hydra_core::id::NodeId;
use crate::nodes::prop;
use crate::queries::protection_status::PROTECTABLE_TYPES;

/// Confidence assessment for the entire estate
#[derive(Debug)]
pub struct ConfidenceReport {
    /// Overall confidence score (0.0 - 100.0)
    pub overall_score: f64,
    /// Confidence grade (A-F)
    pub grade: ConfidenceGrade,
    /// Per-dimension scores
    pub dimensions: ConfidenceDimensions,
    /// Resources with lowest trust scores (weakest links)
    pub weakest_links: Vec<WeakLink>,
    /// Total protectable resources evaluated
    pub resources_evaluated: usize,
    /// How many have trust_composite > 0
    pub resources_with_trust: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfidenceGrade {
    A, // 90-100: Excellent
    B, // 75-89: Good
    C, // 60-74: Fair
    D, // 40-59: Poor
    F, // 0-39: Failing
}

/// Aggregated scores across all 7 trust dimensions
#[derive(Debug, Clone)]
pub struct ConfidenceDimensions {
    /// Average backup freshness across all resources
    pub backup_freshness: f64,
    /// Average backup verification score
    pub backup_verified: f64,
    /// Average recovery tested score
    pub recovery_tested: f64,
    /// Average dependency health
    pub dependency_health: f64,
    /// Average compliance status
    pub compliance_status: f64,
    /// Average anomaly-free score
    pub anomaly_free: f64,
    /// Average replication health
    pub replication_health: f64,
}

/// A resource that's dragging down the overall confidence
#[derive(Debug, Clone)]
pub struct WeakLink {
    pub node_id: NodeId,
    pub node_type: String,
    pub name: Option<String>,
    pub trust_composite: f64,
    pub business_criticality: i64,
    /// Which dimension is the weakest for this resource
    pub weakest_dimension: String,
    pub weakest_dimension_score: f64,
}

/// Generate the confidence report for the estate.
///
/// The overall score is a weighted average of the 7 trust dimensions
/// across all protectable resources, with business criticality as the weight.
/// A critical database at trust=20 drags the score down more than
/// a dev EC2 at trust=20.
pub fn confidence_report(
    graph: &dyn GraphReader,
    max_weak_links: usize,
) -> ConfidenceReport {
    let mut total_weight: f64 = 0.0;
    let mut dim_sums = [0.0f64; 7]; // One per trust dimension
    let mut resources_evaluated: usize = 0;
    let mut resources_with_trust: usize = 0;
    let mut weak_links: Vec<WeakLink> = Vec::new();

    let trust_keys = [
        prop::TRUST_BACKUP_FRESHNESS,
        prop::TRUST_BACKUP_VERIFIED,
        prop::TRUST_RECOVERY_TESTED,
        prop::TRUST_DEPENDENCY_HEALTH,
        prop::TRUST_COMPLIANCE_STATUS,
        prop::TRUST_ANOMALY_FREE,
        prop::TRUST_REPLICATION_HEALTH,
    ];
    let dim_names = [
        "backup_freshness",
        "backup_verified",
        "recovery_tested",
        "dependency_health",
        "compliance_status",
        "anomaly_free",
        "replication_health",
    ];

    for &type_id in PROTECTABLE_TYPES {
        for node in graph.nodes_by_type(type_id) {
            if !node.is_alive() {
                continue;
            }
            resources_evaluated += 1;

            let composite = node.get_f64(prop::TRUST_COMPOSITE).unwrap_or(0.0);
            if composite > 0.0 {
                resources_with_trust += 1;
            }

            // Weight by criticality (minimum 1 so every resource counts)
            let weight = (node.get_i64(prop::BUSINESS_CRITICALITY).unwrap_or(1) as f64).max(1.0);
            total_weight += weight;

            // Read each dimension
            let mut dim_values = [0.0f64; 7];
            let mut weakest_idx = 0;
            let mut weakest_val = f64::MAX;

            for (i, key) in trust_keys.iter().enumerate() {
                let val = node.get_f64(key).unwrap_or(0.0);
                dim_values[i] = val;
                dim_sums[i] += val * weight;
                if val < weakest_val {
                    weakest_val = val;
                    weakest_idx = i;
                }
            }

            weak_links.push(WeakLink {
                node_id: node.id().clone(),
                node_type: type_id.to_string(),
                name: node.get_str(prop::NAME).map(|s| s.to_string()),
                trust_composite: composite,
                business_criticality: node.get_i64(prop::BUSINESS_CRITICALITY).unwrap_or(0),
                weakest_dimension: dim_names[weakest_idx].to_string(),
                weakest_dimension_score: weakest_val,
            });
        }
    }

    // Sort weak links by trust_composite ascending (weakest first),
    // then by criticality descending (most important first among equally weak)
    weak_links.sort_by(|a, b| {
        a.trust_composite.partial_cmp(&b.trust_composite).unwrap_or(std::cmp::Ordering::Equal)
            .then(b.business_criticality.cmp(&a.business_criticality))
    });
    weak_links.truncate(max_weak_links);

    // Compute dimension averages
    let dimensions = if total_weight > 0.0 {
        ConfidenceDimensions {
            backup_freshness: dim_sums[0] / total_weight,
            backup_verified: dim_sums[1] / total_weight,
            recovery_tested: dim_sums[2] / total_weight,
            dependency_health: dim_sums[3] / total_weight,
            compliance_status: dim_sums[4] / total_weight,
            anomaly_free: dim_sums[5] / total_weight,
            replication_health: dim_sums[6] / total_weight,
        }
    } else {
        ConfidenceDimensions {
            backup_freshness: 0.0,
            backup_verified: 0.0,
            recovery_tested: 0.0,
            dependency_health: 0.0,
            compliance_status: 0.0,
            anomaly_free: 0.0,
            replication_health: 0.0,
        }
    };

    // Overall = average of dimension averages
    let overall_score = if total_weight > 0.0 {
        let sum: f64 = dim_sums.iter().sum();
        (sum / (total_weight * 7.0)) * 100.0 // Scale to 0-100
    } else {
        0.0
    };
    let overall_clamped = overall_score.clamp(0.0, 100.0);

    let grade = match overall_clamped as u32 {
        90..=100 => ConfidenceGrade::A,
        75..=89 => ConfidenceGrade::B,
        60..=74 => ConfidenceGrade::C,
        40..=59 => ConfidenceGrade::D,
        _ => ConfidenceGrade::F,
    };

    ConfidenceReport {
        overall_score: overall_clamped,
        grade,
        dimensions,
        weakest_links: weak_links,
        resources_evaluated,
        resources_with_trust,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_engine::prelude::*;
    use hydra_core::event::{EventKind, Value};
    use crate::nodes::aws::*;
    use crate::nodes::prop as p;

    #[test]
    fn empty_estate_grade_f() {
        let hydra = Hydra::new();
        let report = confidence_report(hydra.graph(), 5);
        assert_eq!(report.grade, ConfidenceGrade::F);
        assert_eq!(report.resources_evaluated, 0);
    }

    #[test]
    fn all_zeros_grade_f() {
        let mut hydra = Hydra::new();
        let (_, ev) = Ec2Builder::new("i-001").business_criticality(5).build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = RdsBuilder::new("db-001").business_criticality(9).build();
        hydra.ingest(ev).unwrap();

        let report = confidence_report(hydra.graph(), 5);
        assert_eq!(report.grade, ConfidenceGrade::F);
        assert_eq!(report.resources_evaluated, 2);
        // anomaly_free starts at 1.0, everything else at 0.0
        // So overall ≈ 1/7 * 100 = 14.3 → F
        assert!(report.overall_score < 20.0);
    }

    #[test]
    fn weakest_links_sorted_by_trust_then_criticality() {
        let mut hydra = Hydra::new();
        // Low trust, high crit
        let (_rds, ev) = RdsBuilder::new("db-001").business_criticality(9).build();
        hydra.ingest(ev).unwrap();
        // Low trust, low crit
        let (_ec2, ev) = Ec2Builder::new("i-001").business_criticality(2).build();
        hydra.ingest(ev).unwrap();

        let report = confidence_report(hydra.graph(), 5);
        assert_eq!(report.weakest_links.len(), 2);
        // Both have same trust (≈0), but RDS has higher criticality → first
        assert_eq!(report.weakest_links[0].business_criticality, 9);
    }

    #[test]
    fn criticality_weights_the_average() {
        let mut hydra = Hydra::new();

        // High criticality resource with bad trust
        let (_rds, ev) = RdsBuilder::new("db-001").business_criticality(10).build();
        hydra.ingest(ev).unwrap();

        // Low criticality resource — won't affect overall much
        let (ec2, ev) = Ec2Builder::new("i-001").business_criticality(1).build();
        hydra.ingest(ev).unwrap();

        // Boost EC2's trust
        hydra.ingest(EventKind::NodeUpdated {
            node_id: ec2.clone(),
            changes: std::collections::HashMap::from([
                (p::TRUST_BACKUP_FRESHNESS.to_string(), Value::Float(1.0)),
                (p::TRUST_BACKUP_VERIFIED.to_string(), Value::Float(1.0)),
                (p::TRUST_RECOVERY_TESTED.to_string(), Value::Float(1.0)),
                (p::TRUST_DEPENDENCY_HEALTH.to_string(), Value::Float(1.0)),
                (p::TRUST_COMPLIANCE_STATUS.to_string(), Value::Float(1.0)),
                (p::TRUST_ANOMALY_FREE.to_string(), Value::Float(1.0)),
                (p::TRUST_REPLICATION_HEALTH.to_string(), Value::Float(1.0)),
                (p::TRUST_COMPOSITE.to_string(), Value::Float(100.0)),
            ]),
        }).unwrap();

        let report = confidence_report(hydra.graph(), 5);
        // RDS (crit=10, trust≈0) dominates the score, EC2 (crit=1, trust=100) barely helps
        // Overall should be low because the critical resource has no trust
        assert!(report.overall_score < 30.0, "Critical untrusted resource should drag score down, got {}", report.overall_score);
    }

    #[test]
    fn dimension_averages_computed() {
        let mut hydra = Hydra::new();
        let (_ec2, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();

        let report = confidence_report(hydra.graph(), 5);
        // anomaly_free defaults to 1.0, all others 0.0
        assert!((report.dimensions.anomaly_free - 1.0).abs() < 0.001);
        assert!((report.dimensions.backup_freshness - 0.0).abs() < 0.001);
    }

    #[test]
    fn all_dimensions_max_gives_grade_a() {
        let mut hydra = Hydra::new();
        let (ec2, ev) = Ec2Builder::new("i-001").business_criticality(5).build();
        hydra.ingest(ev).unwrap();

        // Set all 7 dimensions to 1.0
        hydra.ingest(EventKind::NodeUpdated {
            node_id: ec2.clone(),
            changes: std::collections::HashMap::from([
                (p::TRUST_BACKUP_FRESHNESS.to_string(), Value::Float(1.0)),
                (p::TRUST_BACKUP_VERIFIED.to_string(), Value::Float(1.0)),
                (p::TRUST_RECOVERY_TESTED.to_string(), Value::Float(1.0)),
                (p::TRUST_DEPENDENCY_HEALTH.to_string(), Value::Float(1.0)),
                (p::TRUST_COMPLIANCE_STATUS.to_string(), Value::Float(1.0)),
                (p::TRUST_ANOMALY_FREE.to_string(), Value::Float(1.0)),
                (p::TRUST_REPLICATION_HEALTH.to_string(), Value::Float(1.0)),
                (p::TRUST_COMPOSITE.to_string(), Value::Float(100.0)),
            ]),
        }).unwrap();

        let report = confidence_report(hydra.graph(), 5);
        assert_eq!(report.grade, ConfidenceGrade::A);
        assert!(report.overall_score >= 90.0, "All 1.0 dimensions should give ≥90 score, got {}", report.overall_score);
    }
}
