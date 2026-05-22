//! # Compliance Gaps Query
//!
//! "Which resources are violating their compliance requirements?"
//!
//! Cross-references resources' regulatory_scope with their actual protection
//! state, backup frequency, retention, encryption, and verification status.

use hydra_core::graph::GraphReader;
use hydra_core::id::NodeId;
use crate::nodes::{prop, PROTECTED_BY, VERIFIED_BY};
use crate::queries::protection_status::PROTECTABLE_TYPES;

/// A single compliance gap — a resource failing a specific requirement.
#[derive(Debug, Clone)]
pub struct ComplianceGap {
    /// The resource that's non-compliant
    pub node_id: NodeId,
    pub node_type: String,
    pub name: Option<String>,
    pub cloud_provider: Option<String>,
    /// The requirement being violated
    pub requirement: ComplianceRequirement,
    /// Current value (what the resource actually has)
    pub actual: String,
    /// Required value (what the regulation demands)
    pub required: String,
    /// Severity: how bad is this gap
    pub severity: GapSeverity,
}

/// Types of compliance requirements
#[derive(Debug, Clone, PartialEq)]
pub enum ComplianceRequirement {
    /// Resource must be backed up
    BackupRequired,
    /// Backups must be verified/tested
    VerificationRequired,
    /// Minimum backup frequency (hours)
    MinBackupFrequency { max_hours: i64 },
    /// Minimum retention (days)
    MinRetention { min_days: i64 },
    /// Data must be encrypted at rest
    EncryptionRequired,
    /// Resource must have protection_status = "protected"
    ProtectionRequired,
    /// Trust score must be above threshold
    MinTrustScore { min_score: f64 },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum GapSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Full compliance report
#[derive(Debug)]
pub struct ComplianceReport {
    /// All gaps found, sorted by severity then criticality
    pub gaps: Vec<ComplianceGap>,
    /// Total resources evaluated
    pub resources_evaluated: usize,
    /// Resources with zero gaps
    pub compliant_count: usize,
    /// Resources with at least one gap
    pub non_compliant_count: usize,
    /// Compliance percentage
    pub compliance_ratio: f64,
    /// Gaps by requirement type
    pub gap_counts: std::collections::HashMap<String, usize>,
}

/// A compliance rule to check against resources.
/// These are the "regulations" that Sentinel enforces.
#[derive(Debug, Clone)]
pub struct ComplianceRule {
    /// Human-readable name (e.g., "HIPAA backup requirement")
    pub name: String,
    /// Which resource types this applies to (empty = all protectable types)
    pub applies_to: Vec<String>,
    /// The requirement
    pub requirement: ComplianceRequirement,
    /// Gap severity if violated
    pub severity: GapSeverity,
}

/// Evaluate compliance rules against the graph.
///
/// For each rule, check every applicable resource. Produce a gap for each
/// resource that fails the rule.
pub fn compliance_gaps(
    graph: &dyn GraphReader,
    rules: &[ComplianceRule],
) -> ComplianceReport {
    let mut gaps: Vec<ComplianceGap> = Vec::new();
    let mut all_resource_ids: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
    let mut non_compliant_ids: std::collections::HashSet<NodeId> = std::collections::HashSet::new();

    for rule in rules {
        let target_types: Vec<&str> = if rule.applies_to.is_empty() {
            PROTECTABLE_TYPES.to_vec()
        } else {
            rule.applies_to.iter().map(|s| s.as_str()).collect()
        };

        for type_id in &target_types {
            let nodes = graph.nodes_by_type(type_id);
            for node in nodes {
                if !node.is_alive() {
                    continue;
                }
                all_resource_ids.insert(node.id().clone());

                if let Some(gap) = check_rule(graph, node, rule) {
                    non_compliant_ids.insert(node.id().clone());
                    gaps.push(gap);
                }
            }
        }
    }

    gaps.sort_by(|a, b| a.severity.cmp(&b.severity));

    let resources_evaluated = all_resource_ids.len();
    let non_compliant_count = non_compliant_ids.len();
    let compliant_count = resources_evaluated.saturating_sub(non_compliant_count);
    let compliance_ratio = if resources_evaluated == 0 {
        1.0
    } else {
        compliant_count as f64 / resources_evaluated as f64
    };

    let mut gap_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for gap in &gaps {
        let key = format!("{:?}", gap.requirement);
        *gap_counts.entry(key).or_default() += 1;
    }

    ComplianceReport {
        gaps,
        resources_evaluated,
        compliant_count,
        non_compliant_count,
        compliance_ratio,
        gap_counts,
    }
}

fn check_rule(
    graph: &dyn GraphReader,
    node: &hydra_core::node::Node,
    rule: &ComplianceRule,
) -> Option<ComplianceGap> {
    let (actual, required, is_gap) = match &rule.requirement {
        ComplianceRequirement::ProtectionRequired => {
            let status = node.get_str(prop::PROTECTION_STATUS).unwrap_or("unknown");
            let is_gap = status != "protected";
            (status.to_string(), "protected".to_string(), is_gap)
        }
        ComplianceRequirement::BackupRequired => {
            let has_backup = !graph.outgoing_edges_of_type(node.id(), PROTECTED_BY).is_empty();
            let actual = if has_backup { "has backups" } else { "no backups" };
            (!has_backup).then(|| ())?; // short-circuit if compliant
            return Some(make_gap(node, &rule, actual.to_string(), "must have backups".to_string()));
        }
        ComplianceRequirement::VerificationRequired => {
            // Check if any backup snapshot linked to this node has been verified
            let backups = graph.outgoing_edges_of_type(node.id(), PROTECTED_BY);
            let any_verified = backups.iter().any(|e| {
                let snap_id = e.target();
                !graph.outgoing_edges_of_type(snap_id, VERIFIED_BY).is_empty()
            });
            let actual = if any_verified { "verified" } else { "unverified" };
            (!any_verified).then(|| ())?;
            return Some(make_gap(node, &rule, actual.to_string(), "backups must be verified".to_string()));
        }
        ComplianceRequirement::MinBackupFrequency { max_hours } => {
            let actual_hours = node.get_i64(prop::BACKUP_FREQUENCY_HOURS).unwrap_or(0);
            let is_gap = actual_hours == 0 || actual_hours > *max_hours;
            (
                format!("{}h", actual_hours),
                format!("≤{}h", max_hours),
                is_gap,
            )
        }
        ComplianceRequirement::MinRetention { min_days } => {
            let actual_days = node.get_i64(prop::RETENTION_DAYS).unwrap_or(0);
            let is_gap = actual_days < *min_days;
            (
                format!("{}d", actual_days),
                format!("≥{}d", min_days),
                is_gap,
            )
        }
        ComplianceRequirement::EncryptionRequired => {
            let encrypted = node.get_bool("storage_encrypted").unwrap_or(false);
            let actual = if encrypted { "encrypted" } else { "unencrypted" };
            (!encrypted).then(|| ())?;
            return Some(make_gap(node, &rule, actual.to_string(), "must be encrypted".to_string()));
        }
        ComplianceRequirement::MinTrustScore { min_score } => {
            let actual_score = node.get_f64(prop::TRUST_COMPOSITE).unwrap_or(0.0);
            let is_gap = actual_score < *min_score;
            (
                format!("{:.1}", actual_score),
                format!("≥{:.1}", min_score),
                is_gap,
            )
        }
    };

    if is_gap {
        Some(make_gap(node, rule, actual, required))
    } else {
        None
    }
}

fn make_gap(
    node: &hydra_core::node::Node,
    rule: &ComplianceRule,
    actual: String,
    required: String,
) -> ComplianceGap {
    ComplianceGap {
        node_id: node.id().clone(),
        node_type: node.type_id().to_string(),
        name: node.get_str(prop::NAME).map(|s| s.to_string()),
        cloud_provider: node.get_str("cloud_provider").map(|s| s.to_string()),
        requirement: rule.requirement.clone(),
        actual,
        required,
        severity: rule.severity.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_engine::prelude::*;
    use crate::nodes::aws::*;
    use crate::nodes::MANAGED_DATABASE;

    #[test]
    fn no_rules_means_full_compliance() {
        let mut hydra = Hydra::new();
        let (_, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();

        let report = compliance_gaps(hydra.graph(), &[]);
        assert_eq!(report.resources_evaluated, 0); // no rules = no evaluation
        assert!((report.compliance_ratio - 1.0).abs() < 0.001);
    }

    #[test]
    fn protection_required_finds_unprotected() {
        let mut hydra = Hydra::new();
        let (_, ev) = RdsBuilder::new("db-001").name("prod-db").build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = Ec2Builder::new("i-001").name("api-1").build();
        hydra.ingest(ev).unwrap();

        let rules = vec![ComplianceRule {
            name: "All resources must be protected".into(),
            applies_to: vec![],
            requirement: ComplianceRequirement::ProtectionRequired,
            severity: GapSeverity::High,
        }];

        let report = compliance_gaps(hydra.graph(), &rules);
        assert_eq!(report.resources_evaluated, 2);
        assert_eq!(report.non_compliant_count, 2);
        assert_eq!(report.gaps.len(), 2);
    }

    #[test]
    fn targeted_rule_only_checks_specified_types() {
        let mut hydra = Hydra::new();
        let (_, ev) = RdsBuilder::new("db-001").build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();

        let rules = vec![ComplianceRule {
            name: "Databases must be encrypted".into(),
            applies_to: vec![MANAGED_DATABASE.to_string()],
            requirement: ComplianceRequirement::EncryptionRequired,
            severity: GapSeverity::Critical,
        }];

        let report = compliance_gaps(hydra.graph(), &rules);
        // Only RDS evaluated, EC2 not checked
        assert_eq!(report.resources_evaluated, 1);
        assert_eq!(report.gaps.len(), 1);
        assert_eq!(report.gaps[0].severity, GapSeverity::Critical);
    }

    #[test]
    fn trust_score_rule() {
        let mut hydra = Hydra::new();
        let (_, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();

        let rules = vec![ComplianceRule {
            name: "Trust score must be >= 50".into(),
            applies_to: vec![],
            requirement: ComplianceRequirement::MinTrustScore { min_score: 50.0 },
            severity: GapSeverity::Medium,
        }];

        let report = compliance_gaps(hydra.graph(), &rules);
        // EC2 starts with trust_composite = 0.0, so it fails
        assert_eq!(report.gaps.len(), 1);
    }

    #[test]
    fn multiple_rules_on_same_resource() {
        let mut hydra = Hydra::new();
        let (_rds, ev) = RdsBuilder::new("db-001").build();
        hydra.ingest(ev).unwrap();

        let rules = vec![
            ComplianceRule {
                name: "Must be protected".into(),
                applies_to: vec![],
                requirement: ComplianceRequirement::ProtectionRequired,
                severity: GapSeverity::High,
            },
            ComplianceRule {
                name: "Must be encrypted".into(),
                applies_to: vec![MANAGED_DATABASE.to_string()],
                requirement: ComplianceRequirement::EncryptionRequired,
                severity: GapSeverity::Critical,
            },
        ];

        let report = compliance_gaps(hydra.graph(), &rules);
        assert_eq!(report.resources_evaluated, 1);
        assert_eq!(report.non_compliant_count, 1);
        assert_eq!(report.gaps.len(), 2); // same resource, two gaps
    }

    #[test]
    fn fully_compliant_resource_has_zero_gaps() {
        use hydra_core::event::{EventKind, Value};

        let mut hydra = Hydra::new();
        let (rds, ev) = RdsBuilder::new("db-001")
            .storage_encrypted(true)
            .build();
        hydra.ingest(ev).unwrap();

        // Mark as protected
        hydra.ingest(EventKind::NodeUpdated {
            node_id: rds.clone(),
            changes: std::collections::HashMap::from([
                (crate::nodes::prop::PROTECTION_STATUS.to_string(), Value::String("protected".into())),
                (crate::nodes::prop::TRUST_COMPOSITE.to_string(), Value::Float(80.0)),
            ]),
        }).unwrap();

        let rules = vec![
            ComplianceRule {
                name: "Must be protected".into(),
                applies_to: vec![],
                requirement: ComplianceRequirement::ProtectionRequired,
                severity: GapSeverity::High,
            },
            ComplianceRule {
                name: "Must be encrypted".into(),
                applies_to: vec![MANAGED_DATABASE.to_string()],
                requirement: ComplianceRequirement::EncryptionRequired,
                severity: GapSeverity::Critical,
            },
            ComplianceRule {
                name: "Trust >= 50".into(),
                applies_to: vec![],
                requirement: ComplianceRequirement::MinTrustScore { min_score: 50.0 },
                severity: GapSeverity::Medium,
            },
        ];

        let report = compliance_gaps(hydra.graph(), &rules);
        assert_eq!(report.gaps.len(), 0, "Fully compliant resource should have zero gaps");
        assert_eq!(report.compliant_count, 1);
        assert!((report.compliance_ratio - 1.0).abs() < 0.001);
    }
}
