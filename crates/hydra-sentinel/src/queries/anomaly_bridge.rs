//! # Anomaly-Query Bridge
//!
//! Connects the `AnomalyEngine` (hydra-engine) to Sentinel queries.
//!
//! When anomalies are detected on a cascade result, this bridge:
//! 1. Runs `blast_radius` on each affected node to scope the threat
//! 2. Computes trust score deltas (how much should trust drop?)
//! 3. Produces a structured `ThreatAssessment` that Arms can act on
//!
//! This is the "thinking" layer between detection and response.

use hydra_core::graph::GraphReader;
use hydra_core::id::NodeId;
use hydra_core::event::{EventKind, Value};
use hydra_engine::anomaly::Anomaly;
use crate::queries::blast_radius::{BlastRadiusReport, BlastRadiusConfig, blast_radius};
use crate::nodes::prop;

/// A structured threat assessment combining anomaly + blast radius.
#[derive(Debug)]
pub struct ThreatAssessment {
    /// The anomaly that triggered this assessment
    pub anomaly_summary: String,
    /// Affected nodes from the anomaly
    pub affected_nodes: Vec<NodeId>,
    /// Blast radius from each affected node (if computable)
    pub blast_reports: Vec<BlastRadiusReport>,
    /// Combined unique nodes in all blast radii
    pub total_blast_scope: usize,
    /// Maximum risk score across all blast reports
    pub max_risk_score: f64,
    /// Recommended trust score adjustments
    pub trust_adjustments: Vec<TrustAdjustment>,
    /// Overall severity: Critical / High / Medium / Low
    pub severity: ThreatSeverity,
}

/// A recommended trust score change for a specific node.
#[derive(Debug, Clone)]
pub struct TrustAdjustment {
    pub node_id: NodeId,
    /// Which trust dimension to adjust
    pub dimension: String,
    /// How much to subtract (always positive; caller subtracts)
    pub penalty: f64,
    /// Why this adjustment
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Assess a set of anomalies against the current graph state.
///
/// For each anomaly with affected nodes, computes blast radius,
/// trust penalties, and overall severity.
pub fn assess_threats(
    graph: &dyn GraphReader,
    anomalies: &[Anomaly],
) -> ThreatAssessment {
    let config = BlastRadiusConfig {
        max_depth: 5, // Shorter depth for threat assessment (speed)
        include_network: true,
        include_identity: true,
        min_confidence: 0.0,
    };

    let mut all_affected: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
    let mut blast_reports: Vec<BlastRadiusReport> = Vec::new();
    let mut trust_adjustments: Vec<TrustAdjustment> = Vec::new();
    let mut max_risk_score: f64 = 0.0;

    // Collect all affected nodes from anomalies
    let mut affected_nodes: Vec<NodeId> = Vec::new();
    let mut anomaly_summaries: Vec<String> = Vec::new();

    for anomaly in anomalies {
        anomaly_summaries.push(anomaly.description.clone());
        for node_id in &anomaly.affected_nodes {
            if all_affected.insert(node_id.clone()) {
                affected_nodes.push(node_id.clone());
            }
        }
    }

    // Compute blast radius for each affected node
    for node_id in &affected_nodes {
        if let Some(report) = blast_radius(graph, node_id, &config) {
            if report.risk_score > max_risk_score {
                max_risk_score = report.risk_score;
            }
            for blast_node in &report.affected {
                all_affected.insert(blast_node.node_id.clone());
            }
            blast_reports.push(report);
        }

        // Compute trust adjustments for the directly affected node
        let penalty = compute_anomaly_penalty(anomalies.len());
        trust_adjustments.push(TrustAdjustment {
            node_id: node_id.clone(),
            dimension: prop::TRUST_ANOMALY_FREE.to_string(),
            penalty,
            reason: format!("{} anomalies detected", anomalies.len()),
        });
    }

    let total_blast_scope = all_affected.len();

    // Determine severity based on blast scope + risk score + criticality
    let severity = if max_risk_score > 50.0 || total_blast_scope > 20 {
        ThreatSeverity::Critical
    } else if max_risk_score > 20.0 || total_blast_scope > 10 {
        ThreatSeverity::High
    } else if max_risk_score > 5.0 || total_blast_scope > 3 {
        ThreatSeverity::Medium
    } else {
        ThreatSeverity::Low
    };

    ThreatAssessment {
        anomaly_summary: anomaly_summaries.join("; "),
        affected_nodes,
        blast_reports,
        total_blast_scope,
        max_risk_score,
        trust_adjustments,
        severity,
    }
}

/// Generate EventKinds that apply trust adjustments to the graph.
///
/// These can be fed back into `hydra.ingest()` to update trust scores.
/// This closes the loop: anomaly → assessment → trust update → graph change.
pub fn trust_adjustment_events(adjustments: &[TrustAdjustment]) -> Vec<EventKind> {
    adjustments.iter().map(|adj| {
        let mut changes = std::collections::HashMap::new();
        // We emit the penalty as a direct value set.
        // In production, the TrustArm would read the current value,
        // subtract the penalty, clamp to [0, 1], and emit the result.
        // Here we emit the penalty as a signal for the Arm to interpret.
        changes.insert(
            adj.dimension.clone(),
            Value::Float(adj.penalty),
        );
        EventKind::Signal {
            source: adj.node_id.clone(),
            name: "trust_penalty".to_string(),
            payload: changes,
        }
    }).collect()
}

/// Compute how much to penalize anomaly_free based on anomaly count.
/// More anomalies = harder penalty. Diminishing returns past 5.
fn compute_anomaly_penalty(anomaly_count: usize) -> f64 {
    match anomaly_count {
        0 => 0.0,
        1 => 0.1,
        2 => 0.2,
        3 => 0.3,
        4 => 0.4,
        _ => 0.5, // Cap at 0.5 — even heavy anomaly load doesn't zero out trust
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_engine::prelude::*;
    use hydra_engine::anomaly::Anomaly;
    use hydra_core::id::NodeId;
    use crate::nodes::aws::*;
    use crate::edges;

    fn make_anomaly(affected: Vec<NodeId>) -> Anomaly {
        use hydra_engine::anomaly::AnomalyKind;
        Anomaly {
            kind: AnomalyKind::CascadeAmplification {
                cascade_event_count: 10,
                cascade_depth: 5,
                normal_max_count: 3,
                normal_max_depth: 2,
            },
            description: "test anomaly detected".to_string(),
            severity: 0.8,
            affected_nodes: affected,
            trigger_event: None,
            detected_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn assess_single_anomaly_with_blast() {
        let mut hydra = Hydra::new();

        let (db, ev) = RdsBuilder::new("db-prod").business_criticality(9).build();
        hydra.ingest(ev).unwrap();
        let (api, ev) = Ec2Builder::new("i-api").business_criticality(7).build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::depends_on(api.clone(), db.clone(), "database", 1.0);
        hydra.ingest(ev).unwrap();

        let anomalies = vec![make_anomaly(vec![db.clone()])];
        let assessment = assess_threats(hydra.graph(), &anomalies);

        assert_eq!(assessment.affected_nodes.len(), 1);
        assert_eq!(assessment.blast_reports.len(), 1);
        assert!(assessment.total_blast_scope >= 2, "DB + API in blast scope");
        assert!(!assessment.trust_adjustments.is_empty());
    }

    #[test]
    fn assess_empty_anomalies() {
        let hydra = Hydra::new();
        let assessment = assess_threats(hydra.graph(), &[]);
        assert_eq!(assessment.severity, ThreatSeverity::Low);
        assert_eq!(assessment.total_blast_scope, 0);
    }

    #[test]
    fn trust_adjustment_events_generated() {
        let adjustments = vec![TrustAdjustment {
            node_id: NodeId::from_str("node_test"),
            dimension: prop::TRUST_ANOMALY_FREE.to_string(),
            penalty: 0.3,
            reason: "3 anomalies".into(),
        }];

        let events = trust_adjustment_events(&adjustments);
        assert_eq!(events.len(), 1);
        match &events[0] {
            EventKind::Signal { name, .. } => assert_eq!(name, "trust_penalty"),
            _ => panic!("Expected Signal event"),
        }
    }

    #[test]
    fn severity_scales_with_blast() {
        let mut hydra = Hydra::new();

        // Build a wide dependency tree: DB with 25 dependents
        let (db, ev) = RdsBuilder::new("db-prod").business_criticality(10).build();
        hydra.ingest(ev).unwrap();

        for i in 0..25 {
            let (ec2, ev) = Ec2Builder::new(&format!("i-{:03}", i))
                .business_criticality(5)
                .build();
            hydra.ingest(ev).unwrap();
            let (_, ev) = edges::depends_on(ec2, db.clone(), "database", 1.0);
            hydra.ingest(ev).unwrap();
        }

        let anomalies = vec![make_anomaly(vec![db.clone()])];
        let assessment = assess_threats(hydra.graph(), &anomalies);

        assert_eq!(assessment.severity, ThreatSeverity::Critical,
            "25+ nodes in blast = Critical. Got {:?} with scope {}", assessment.severity, assessment.total_blast_scope);
    }

    #[test]
    fn penalty_caps_at_half() {
        assert!((compute_anomaly_penalty(100) - 0.5).abs() < 0.001);
        assert!((compute_anomaly_penalty(1) - 0.1).abs() < 0.001);
    }
}
