//! # Temporal Query Adapter
//!
//! Wraps all Sentinel queries to work at any point in time.
//!
//! Since every query takes `&dyn GraphReader` and `TemporalGraphView`
//! implements `GraphReader`, temporal queries require zero changes to
//! the query functions themselves. This module provides:
//!
//! 1. Convenience wrappers that take a `&Hydra` + timestamp
//! 2. Diff functions that compare query results across two timestamps
//! 3. Trend functions that run a query at N points and return the series
//!
//! ## Why this exists
//!
//! Without this, every caller has to do:
//! ```ignore
//! let view = hydra.graph_at(timestamp);
//! let report = blast_radius(&view, origin, config);
//! ```
//!
//! With this, callers do:
//! ```ignore
//! let report = temporal::blast_radius_at(hydra, origin, config, timestamp);
//! let diff = temporal::blast_radius_diff(hydra, origin, config, t1, t2);
//! ```

use chrono::{DateTime, Utc};
use hydra_core::id::NodeId;
use hydra_engine::prelude::Hydra;

use crate::queries::blast_radius::{BlastRadiusReport, BlastRadiusConfig, blast_radius};
use crate::queries::protection_status::{ProtectionSummary, protection_summary};
use crate::queries::compliance_gaps::{ComplianceReport, ComplianceRule, compliance_gaps};
use crate::queries::confidence_report::{ConfidenceReport, confidence_report};
use crate::queries::recovery_plan::{RecoveryPlan, recovery_plan};

// ============================================================================
// Temporal query wrappers — "what was the answer at time T?"
// ============================================================================

/// Blast radius at a specific point in time.
pub fn blast_radius_at(
    hydra: &Hydra,
    origin: &NodeId,
    config: &BlastRadiusConfig,
    at: DateTime<Utc>,
) -> Option<BlastRadiusReport> {
    let view = hydra.graph_at(at);
    blast_radius(&view, origin, config)
}

/// Protection summary at a specific point in time.
pub fn protection_summary_at(
    hydra: &Hydra,
    at: DateTime<Utc>,
) -> ProtectionSummary {
    let view = hydra.graph_at(at);
    protection_summary(&view)
}

/// Compliance gaps at a specific point in time.
pub fn compliance_gaps_at(
    hydra: &Hydra,
    rules: &[ComplianceRule],
    at: DateTime<Utc>,
) -> ComplianceReport {
    let view = hydra.graph_at(at);
    compliance_gaps(&view, rules)
}

/// Confidence report at a specific point in time.
pub fn confidence_report_at(
    hydra: &Hydra,
    max_weak_links: usize,
    at: DateTime<Utc>,
) -> ConfidenceReport {
    let view = hydra.graph_at(at);
    confidence_report(&view, max_weak_links)
}

/// Recovery plan at a specific point in time.
pub fn recovery_plan_at(
    hydra: &Hydra,
    origin: &NodeId,
    at: DateTime<Utc>,
) -> Option<RecoveryPlan> {
    let view = hydra.graph_at(at);
    recovery_plan(&view, origin)
}

// ============================================================================
// Temporal diffs — "how did the answer change between T1 and T2?"
// ============================================================================

/// How the blast radius changed between two points in time.
#[derive(Debug)]
pub struct BlastRadiusDiff {
    /// Nodes in blast at T2 that weren't at T1
    pub new_in_blast: Vec<NodeId>,
    /// Nodes in blast at T1 that aren't at T2
    pub removed_from_blast: Vec<NodeId>,
    /// Risk score delta (T2 - T1). Positive = worse.
    pub risk_delta: f64,
    /// Total affected delta
    pub affected_delta: i64,
}

/// Compare blast radius at two timestamps.
pub fn blast_radius_diff(
    hydra: &Hydra,
    origin: &NodeId,
    config: &BlastRadiusConfig,
    t1: DateTime<Utc>,
    t2: DateTime<Utc>,
) -> Option<BlastRadiusDiff> {
    let r1 = blast_radius_at(hydra, origin, config, t1);
    let r2 = blast_radius_at(hydra, origin, config, t2);

    match (r1, r2) {
        (Some(r1), Some(r2)) => {
            let ids_t1: std::collections::HashSet<NodeId> = r1.affected.iter()
                .map(|n| n.node_id.clone()).collect();
            let ids_t2: std::collections::HashSet<NodeId> = r2.affected.iter()
                .map(|n| n.node_id.clone()).collect();

            let new_in_blast = ids_t2.difference(&ids_t1).cloned().collect();
            let removed_from_blast = ids_t1.difference(&ids_t2).cloned().collect();
            let risk_delta = r2.risk_score - r1.risk_score;
            let affected_delta = r2.total_affected as i64 - r1.total_affected as i64;

            Some(BlastRadiusDiff {
                new_in_blast,
                removed_from_blast,
                risk_delta,
                affected_delta,
            })
        }
        // Node didn't exist at one of the timestamps
        (None, Some(r2)) => Some(BlastRadiusDiff {
            new_in_blast: r2.affected.iter().map(|n| n.node_id.clone()).collect(),
            removed_from_blast: vec![],
            risk_delta: r2.risk_score,
            affected_delta: r2.total_affected as i64,
        }),
        (Some(r1), None) => Some(BlastRadiusDiff {
            new_in_blast: vec![],
            removed_from_blast: r1.affected.iter().map(|n| n.node_id.clone()).collect(),
            risk_delta: -r1.risk_score,
            affected_delta: -(r1.total_affected as i64),
        }),
        (None, None) => None,
    }
}

/// How protection coverage changed between two timestamps.
#[derive(Debug)]
pub struct ProtectionDiff {
    /// Coverage ratio at T1
    pub coverage_t1: f64,
    /// Coverage ratio at T2
    pub coverage_t2: f64,
    /// Delta (positive = improved)
    pub coverage_delta: f64,
    /// Resources that became unprotected
    pub newly_unprotected: usize,
    /// Resources that became protected
    pub newly_protected: usize,
}

/// Compare protection summary at two timestamps.
pub fn protection_diff(
    hydra: &Hydra,
    t1: DateTime<Utc>,
    t2: DateTime<Utc>,
) -> ProtectionDiff {
    let s1 = protection_summary_at(hydra, t1);
    let s2 = protection_summary_at(hydra, t2);

    // Count resources that changed status
    let ids_protected_t1: std::collections::HashSet<NodeId> = s1.resources.iter()
        .filter(|r| r.protection_status == "protected")
        .map(|r| r.node_id.clone()).collect();
    let ids_protected_t2: std::collections::HashSet<NodeId> = s2.resources.iter()
        .filter(|r| r.protection_status == "protected")
        .map(|r| r.node_id.clone()).collect();

    let newly_protected = ids_protected_t2.difference(&ids_protected_t1).count();
    let newly_unprotected = ids_protected_t1.difference(&ids_protected_t2).count();

    ProtectionDiff {
        coverage_t1: s1.coverage_ratio,
        coverage_t2: s2.coverage_ratio,
        coverage_delta: s2.coverage_ratio - s1.coverage_ratio,
        newly_unprotected,
        newly_protected,
    }
}

/// How confidence changed between two timestamps.
#[derive(Debug)]
pub struct ConfidenceDiff {
    pub score_t1: f64,
    pub score_t2: f64,
    pub score_delta: f64,
    pub grade_changed: bool,
}

/// Compare confidence report at two timestamps.
pub fn confidence_diff(
    hydra: &Hydra,
    max_weak_links: usize,
    t1: DateTime<Utc>,
    t2: DateTime<Utc>,
) -> ConfidenceDiff {
    let c1 = confidence_report_at(hydra, max_weak_links, t1);
    let c2 = confidence_report_at(hydra, max_weak_links, t2);

    ConfidenceDiff {
        score_t1: c1.overall_score,
        score_t2: c2.overall_score,
        score_delta: c2.overall_score - c1.overall_score,
        grade_changed: c1.grade != c2.grade,
    }
}

// ============================================================================
// Trend — "how has this metric evolved over N sample points?"
// ============================================================================

/// A single point in a confidence trend.
#[derive(Debug, Clone)]
pub struct ConfidenceSample {
    pub at: DateTime<Utc>,
    pub score: f64,
    pub grade: crate::queries::confidence_report::ConfidenceGrade,
    pub resources_evaluated: usize,
}

/// Sample confidence_report at evenly spaced points between t_start and t_end.
pub fn confidence_trend(
    hydra: &Hydra,
    max_weak_links: usize,
    t_start: DateTime<Utc>,
    t_end: DateTime<Utc>,
    samples: usize,
) -> Vec<ConfidenceSample> {
    if samples < 2 {
        return vec![];
    }

    let total_duration = (t_end - t_start).num_milliseconds();
    let step = total_duration / (samples as i64 - 1);

    (0..samples)
        .map(|i| {
            let at = t_start + chrono::Duration::milliseconds(step * i as i64);
            let report = confidence_report_at(hydra, max_weak_links, at);
            ConfidenceSample {
                at,
                score: report.overall_score,
                grade: report.grade,
                resources_evaluated: report.resources_evaluated,
            }
        })
        .collect()
}

/// A single point in a protection coverage trend.
#[derive(Debug, Clone)]
pub struct ProtectionSample {
    pub at: DateTime<Utc>,
    pub coverage_ratio: f64,
    pub total: usize,
    pub unprotected: usize,
}

/// Sample protection_summary at evenly spaced points.
pub fn protection_trend(
    hydra: &Hydra,
    t_start: DateTime<Utc>,
    t_end: DateTime<Utc>,
    samples: usize,
) -> Vec<ProtectionSample> {
    if samples < 2 {
        return vec![];
    }

    let total_duration = (t_end - t_start).num_milliseconds();
    let step = total_duration / (samples as i64 - 1);

    (0..samples)
        .map(|i| {
            let at = t_start + chrono::Duration::milliseconds(step * i as i64);
            let summary = protection_summary_at(hydra, at);
            ProtectionSample {
                at,
                coverage_ratio: summary.coverage_ratio,
                total: summary.total,
                unprotected: summary.unprotected,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use hydra_core::event::{EventKind, Value};
    use crate::nodes::aws::*;
    use crate::nodes::prop;
    use crate::edges;

    #[test]
    fn blast_radius_at_works_through_temporal_view() {
        let mut hydra = Hydra::new();

        let (db, ev) = RdsBuilder::new("db-prod").business_criticality(9).build();
        hydra.ingest(ev).unwrap();

        let (api, ev) = Ec2Builder::new("i-api").business_criticality(7).build();
        hydra.ingest(ev).unwrap();

        let (_, ev) = edges::depends_on(api.clone(), db.clone(), "database", 1.0);
        hydra.ingest(ev).unwrap();

        // Query at "now" through temporal view should work
        let now = Utc::now();
        let config = BlastRadiusConfig::default();
        let report = blast_radius_at(&hydra, &db, &config, now);
        assert!(report.is_some());
        assert_eq!(report.unwrap().total_affected, 1); // api depends on db
    }

    #[test]
    fn protection_summary_at_past_timestamp() {
        let mut hydra = Hydra::new();

        let before = Utc::now();

        let (_db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();

        let after = Utc::now();

        // Before the node was created: should see 0 resources
        let summary_before = protection_summary_at(&hydra, before);
        assert_eq!(summary_before.total, 0);

        // After: should see 1 resource
        let summary_after = protection_summary_at(&hydra, after);
        assert_eq!(summary_after.total, 1);
    }

    #[test]
    fn confidence_report_at_temporal() {
        let mut hydra = Hydra::new();
        let (_ec2, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();

        let now = Utc::now();
        let report = confidence_report_at(&hydra, 5, now);
        assert_eq!(report.resources_evaluated, 1);
    }

    #[test]
    fn blast_radius_diff_detects_new_dependency() {
        let mut hydra = Hydra::new();

        let (db, ev) = RdsBuilder::new("db-prod").business_criticality(9).build();
        hydra.ingest(ev).unwrap();

        let t1 = Utc::now();

        // Add a dependency after t1
        let (api, ev) = Ec2Builder::new("i-api").business_criticality(7).build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::depends_on(api.clone(), db.clone(), "database", 1.0);
        hydra.ingest(ev).unwrap();

        let t2 = Utc::now();

        let config = BlastRadiusConfig {
            include_network: false,
            include_identity: false,
            ..Default::default()
        };
        let diff = blast_radius_diff(&hydra, &db, &config, t1, t2).unwrap();

        assert_eq!(diff.new_in_blast.len(), 1, "API should appear as new in blast");
        assert_eq!(diff.removed_from_blast.len(), 0);
        assert!(diff.risk_delta > 0.0, "Risk should increase with criticality-7 node added");
        assert_eq!(diff.affected_delta, 1);
    }

    #[test]
    fn protection_diff_detects_improvement() {
        let mut hydra = Hydra::new();

        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();

        let t1 = Utc::now();

        // Protect the database
        hydra.ingest(EventKind::NodeUpdated {
            node_id: db.clone(),
            changes: std::collections::HashMap::from([
                (prop::PROTECTION_STATUS.to_string(), Value::String("protected".into())),
            ]),
        }).unwrap();

        let t2 = Utc::now();

        let diff = protection_diff(&hydra, t1, t2);
        assert!(diff.coverage_delta > 0.0, "Protection improved");
        assert_eq!(diff.newly_protected, 1);
        assert_eq!(diff.newly_unprotected, 0);
    }

    #[test]
    fn confidence_diff_detects_score_change() {
        let mut hydra = Hydra::new();

        let (ec2, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();

        let t1 = Utc::now();

        // Boost trust
        hydra.ingest(EventKind::NodeUpdated {
            node_id: ec2.clone(),
            changes: std::collections::HashMap::from([
                (prop::TRUST_BACKUP_FRESHNESS.to_string(), Value::Float(1.0)),
                (prop::TRUST_BACKUP_VERIFIED.to_string(), Value::Float(1.0)),
                (prop::TRUST_RECOVERY_TESTED.to_string(), Value::Float(1.0)),
                (prop::TRUST_DEPENDENCY_HEALTH.to_string(), Value::Float(1.0)),
                (prop::TRUST_COMPLIANCE_STATUS.to_string(), Value::Float(1.0)),
                (prop::TRUST_ANOMALY_FREE.to_string(), Value::Float(1.0)),
                (prop::TRUST_REPLICATION_HEALTH.to_string(), Value::Float(1.0)),
                (prop::TRUST_COMPOSITE.to_string(), Value::Float(100.0)),
            ]),
        }).unwrap();

        let t2 = Utc::now();

        let diff = confidence_diff(&hydra, 5, t1, t2);
        assert!(diff.score_delta > 0.0, "Confidence should improve after trust boost");
        assert!(diff.grade_changed, "Grade should change from F to A");
    }

    #[test]
    fn confidence_trend_produces_samples() {
        let mut hydra = Hydra::new();
        let (_, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();

        let end = Utc::now();
        let start = end - chrono::Duration::seconds(10);

        let trend = confidence_trend(&hydra, 5, start, end, 5);
        assert_eq!(trend.len(), 5);
        // All samples should have 0 or 1 resources (node created at some point in the window)
        for sample in &trend {
            assert!(sample.resources_evaluated <= 1);
        }
    }

    #[test]
    fn recovery_plan_at_temporal() {
        let mut hydra = Hydra::new();
        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();

        let now = Utc::now();
        let plan = recovery_plan_at(&hydra, &db, now);
        assert!(plan.is_some());
    }
}
