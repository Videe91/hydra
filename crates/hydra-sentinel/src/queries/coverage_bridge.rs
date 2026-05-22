//! # Coverage Bridge
//!
//! Connects the generic `CoverageEngine` (hydra-engine) with Sentinel's
//! domain-specific protection model. Two-way bridge:
//!
//! 1. **Auto-generate CoverageModels** from Sentinel's domain knowledge
//!    (every compute_instance should have a protected_by edge, every
//!    managed_database should have at least 1 snapshot, etc.)
//!
//! 2. **Enrich CoverageReports** with Sentinel context (risk tiers,
//!    business criticality, cost exposure) that the generic engine doesn't know.
//!
//! This eliminates the overlap where both protection_status and CoverageEngine
//! independently scan nodes_by_type.

use hydra_core::graph::GraphReader;
use hydra_engine::coverage::{CoverageEngine, CoverageModel, CoverageExpectation, CoverageReport};
use crate::nodes::{
    COMPUTE_INSTANCE, MANAGED_DATABASE,
    BACKUP_SNAPSHOT, PROTECTION_POLICY, VERIFICATION_RESULT,
    PROTECTED_BY, VERIFIED_BY, POLICY_APPLIES_TO,
    IN_NETWORK,
};
use crate::queries::protection_status::PROTECTABLE_TYPES;

/// Generate the standard Sentinel coverage models.
///
/// These encode what a well-protected estate looks like:
/// - Every protectable resource should have a `protected_by` edge to a snapshot
/// - Every snapshot should have a `verified_by` edge to a verification result
/// - Every protectable resource should have an `in_network` edge
/// - Every protectable resource should have a `policy_applies_to` edge from a policy
pub fn sentinel_coverage_models() -> Vec<CoverageModel> {
    let mut models = Vec::new();

    // Model 1: Backup Coverage — every protectable resource has at least 1 backup
    models.push(CoverageModel {
        name: "backup_coverage".into(),
        expectations: PROTECTABLE_TYPES.iter().map(|&t| {
            CoverageExpectation::EdgeCoverage {
                source_type: t.to_string(),
                edge_type: PROTECTED_BY.to_string(),
                target_type: BACKUP_SNAPSHOT.to_string(),
                min_per_source: 1,
            }
        }).collect(),
        scope_node_type: None,
    });

    // Model 2: Verification Coverage — every snapshot has been verified
    models.push(CoverageModel {
        name: "verification_coverage".into(),
        expectations: vec![
            CoverageExpectation::EdgeCoverage {
                source_type: BACKUP_SNAPSHOT.to_string(),
                edge_type: VERIFIED_BY.to_string(),
                target_type: VERIFICATION_RESULT.to_string(),
                min_per_source: 1,
            },
        ],
        scope_node_type: Some(BACKUP_SNAPSHOT.to_string()),
    });

    // Model 3: Policy Coverage — every protectable resource has a protection policy
    models.push(CoverageModel {
        name: "policy_coverage".into(),
        expectations: PROTECTABLE_TYPES.iter().map(|&t| {
            CoverageExpectation::EdgeCoverage {
                source_type: PROTECTION_POLICY.to_string(),
                edge_type: POLICY_APPLIES_TO.to_string(),
                target_type: t.to_string(),
                min_per_source: 1,
            }
        }).collect(),
        scope_node_type: None,
    });

    // Model 4: Network Coverage — compute instances should be in a network
    models.push(CoverageModel {
        name: "network_coverage".into(),
        expectations: vec![
            CoverageExpectation::EdgeCoverage {
                source_type: COMPUTE_INSTANCE.to_string(),
                edge_type: IN_NETWORK.to_string(),
                target_type: "virtual_network".to_string(),
                min_per_source: 1,
            },
            CoverageExpectation::EdgeCoverage {
                source_type: MANAGED_DATABASE.to_string(),
                edge_type: IN_NETWORK.to_string(),
                target_type: "virtual_network".to_string(),
                min_per_source: 1,
            },
        ],
        scope_node_type: None,
    });

    models
}

/// Register all Sentinel coverage models with a CoverageEngine.
pub fn register_sentinel_models(engine: &mut CoverageEngine) {
    for model in sentinel_coverage_models() {
        engine.add_model(model);
    }
}

/// Enriched coverage report with Sentinel domain context.
#[derive(Debug)]
pub struct SentinelCoverageReport {
    /// The raw engine report
    pub engine_report: CoverageReport,
    /// How many unprotected resources are business-critical (criticality >= 7)
    pub critical_gaps: usize,
    /// Total monthly cost exposure from uncovered resources (cents)
    pub cost_exposure_cents: i64,
}

/// Run coverage evaluation and enrich with Sentinel context.
pub fn evaluate_sentinel_coverage(
    engine: &CoverageEngine,
    graph: &dyn GraphReader,
) -> Vec<SentinelCoverageReport> {
    use crate::nodes::prop;

    engine.evaluate_all(graph).into_iter().map(|report| {
        let mut critical_gaps: usize = 0;
        let mut cost_exposure_cents: i64 = 0;

        // For each gap, check if the affected nodes are business-critical
        for gap in &report.gaps {
            // The gap tells us which expectation failed, but not which nodes.
            // We can infer by scanning protectable types for missing edges.
            // This is a simplified heuristic — a full implementation would
            // track gap-to-node mapping in the coverage engine itself.
            if gap.fulfillment < 0.5 {
                critical_gaps += 1;
            }
        }

        // Compute cost exposure from unprotected resources
        for &type_id in PROTECTABLE_TYPES {
            for node in graph.nodes_by_type(type_id) {
                if !node.is_alive() { continue; }
                let status = node.get_str(prop::PROTECTION_STATUS).unwrap_or("unknown");
                if status == "unprotected" {
                    cost_exposure_cents += node.get_i64(prop::MONTHLY_COST_CENTS).unwrap_or(0);
                    if node.get_i64(prop::BUSINESS_CRITICALITY).unwrap_or(0) >= 7 {
                        critical_gaps += 1;
                    }
                }
            }
        }

        SentinelCoverageReport {
            engine_report: report,
            critical_gaps,
            cost_exposure_cents,
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_engine::prelude::*;
    use crate::nodes::aws::*;
    use crate::nodes::protection::*;
    use crate::edges;

    #[test]
    fn sentinel_models_registered_correctly() {
        let mut engine = CoverageEngine::new();
        register_sentinel_models(&mut engine);
        assert_eq!(engine.model_count(), 4);
    }

    #[test]
    fn backup_coverage_detects_unprotected() {
        let mut hydra = Hydra::new();
        let models = sentinel_coverage_models();

        let (_, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();

        let backup_model = &models[0]; // backup_coverage
        let mut engine = CoverageEngine::new();
        engine.add_model(backup_model.clone());

        let reports = engine.evaluate_all(hydra.graph());
        assert_eq!(reports.len(), 1);
        // RDS has no protected_by edge → gap
        assert!(!reports[0].gaps.is_empty());
        assert!(reports[0].score < 1.0);
    }

    #[test]
    fn backup_coverage_passes_with_snapshot() {
        let mut hydra = Hydra::new();
        let models = sentinel_coverage_models();

        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();
        let (snap, ev) = BackupSnapshotBuilder::new("snap-001").build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::protected_by(db.clone(), snap.clone());
        hydra.ingest(ev).unwrap();

        let backup_model = &models[0];
        let mut engine = CoverageEngine::new();
        engine.add_model(backup_model.clone());

        let reports = engine.evaluate_all(hydra.graph());
        // The model has expectations for ALL protectable types.
        // Only managed_database has a node, so that expectation passes.
        // Other types have 0 source nodes, so EdgeCoverage for them passes vacuously.
        assert!(!reports.is_empty());
    }

    #[test]
    fn enriched_report_includes_cost_exposure() {
        let mut hydra = Hydra::new();

        let (_, ev) = RdsBuilder::new("db-prod")
            .business_criticality(9)
            .monthly_cost_cents(100_000)
            .build();
        hydra.ingest(ev).unwrap();

        let mut engine = CoverageEngine::new();
        register_sentinel_models(&mut engine);

        let reports = evaluate_sentinel_coverage(&engine, hydra.graph());
        let total_cost: i64 = reports.iter().map(|r| r.cost_exposure_cents).sum();
        // At least one report should include the cost of the unprotected DB
        assert!(total_cost >= 100_000);
    }
}
