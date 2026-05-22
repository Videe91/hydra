//! # Compliance Arm
//!
//! Evaluates compliance rules against the graph when resources change.
//!
//! Fires on: NodeCreated (new resource), NodeUpdated (protection/config changes),
//!           Signal (periodic_compliance_check from clock).
//!
//! Reads: compliance_gaps query
//! Emits: Signal("compliance_violation") for each new gap found

use hydra_core::event::{Event, EventKind, Value};
use hydra_core::graph::GraphReader;
use hydra_core::subscription::SubscriptionHandler;
use crate::nodes::prop;
use crate::queries::compliance_gaps::{ComplianceRule, ComplianceRequirement, GapSeverity, compliance_gaps};
use crate::queries::protection_status::PROTECTABLE_TYPES;

/// Compliance Arm — evaluates regulatory requirements.
pub struct ComplianceArm {
    rules: Vec<ComplianceRule>,
}

impl ComplianceArm {
    pub fn new(rules: Vec<ComplianceRule>) -> Self {
        Self { rules }
    }

    /// Create with a default set of rules that most estates need.
    pub fn with_defaults() -> Self {
        Self {
            rules: vec![
                ComplianceRule {
                    name: "All resources must be protected".into(),
                    applies_to: vec![],
                    requirement: ComplianceRequirement::ProtectionRequired,
                    severity: GapSeverity::High,
                },
                ComplianceRule {
                    name: "Trust score must be >= 30".into(),
                    applies_to: vec![],
                    requirement: ComplianceRequirement::MinTrustScore { min_score: 30.0 },
                    severity: GapSeverity::Medium,
                },
            ],
        }
    }
}

impl SubscriptionHandler for ComplianceArm {
    fn handle(
        &self,
        event: &Event,
        graph: &dyn GraphReader,
    ) -> Vec<EventKind> {
        let mut events = Vec::new();

        // Only run on relevant triggers
        let should_check = match &event.kind {
            EventKind::NodeCreated { type_id, .. } => {
                PROTECTABLE_TYPES.contains(&type_id.as_str())
            }
            EventKind::NodeUpdated { changes, .. } => {
                // Only fire on protection-relevant property changes
                changes.contains_key(prop::PROTECTION_STATUS)
                    || changes.contains_key(prop::TRUST_COMPOSITE)
                    || changes.contains_key("classification")
                    || changes.contains_key(prop::BUSINESS_CRITICALITY)
            }
            EventKind::Signal { name, .. } => name == "periodic_compliance_check",
            _ => false,
        };

        if !should_check {
            return events;
        }

        let report = compliance_gaps(graph, &self.rules);

        // Emit a signal for each gap (Arms downstream can react)
        for gap in &report.gaps {
            let mut payload = std::collections::HashMap::new();
            payload.insert("rule".to_string(), Value::String(format!("{:?}", gap.requirement)));
            payload.insert("actual".to_string(), Value::String(gap.actual.clone()));
            payload.insert("required".to_string(), Value::String(gap.required.clone()));
            payload.insert("severity".to_string(), Value::String(format!("{:?}", gap.severity)));
            if let Some(ref name) = gap.name {
                payload.insert("resource_name".to_string(), Value::String(name.clone()));
            }

            events.push(EventKind::Signal {
                source: gap.node_id.clone(),
                name: "compliance_violation".to_string(),
                payload,
            });
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_engine::prelude::*;
    use hydra_core::subscription::{Subscription, EventFilter};
    use crate::nodes::aws::*;

    #[test]
    fn compliance_arm_detects_unprotected_on_create() {
        let mut hydra = Hydra::new();

        let arm = ComplianceArm::with_defaults();
        let sub = Subscription::new(
            "compliance_arm",
            EventFilter::EventKindName("node_created".to_string()),
            90,
            Box::new(arm),
        );
        hydra.register(sub);

        // Creating an unprotected resource should trigger compliance violation
        let (_, ev) = RdsBuilder::new("db-prod").build();
        let result = hydra.ingest(ev).unwrap();

        // Arm should emit compliance_violation signals
        assert!(result.events.len() > 1,
            "Compliance arm should emit violation signals. Got {} events", result.events.len());
    }

    #[test]
    fn compliance_arm_fires_on_periodic_signal() {
        let mut hydra = Hydra::new();

        // Add an unprotected resource first
        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();

        // Register arm to listen for periodic check signals
        let arm = ComplianceArm::with_defaults();
        let sub = Subscription::new(
            "compliance_arm",
            EventFilter::SignalName("periodic_compliance_check".to_string()),
            90,
            Box::new(arm),
        );
        hydra.register(sub);

        // Send periodic check signal
        let result = hydra.ingest(EventKind::Signal {
            source: db.clone(),
            name: "periodic_compliance_check".to_string(),
            payload: std::collections::HashMap::new(),
        }).unwrap();

        assert!(result.events.len() > 1);
    }

    #[test]
    fn compliance_arm_quiet_when_compliant() {
        let mut hydra = Hydra::new();

        // Use a rule that the empty graph satisfies
        let arm = ComplianceArm::new(vec![]);
        let sub = Subscription::new(
            "compliance_arm",
            EventFilter::EventKindName("node_created".to_string()),
            90,
            Box::new(arm),
        );
        hydra.register(sub);

        let (_, ev) = RdsBuilder::new("db-prod").build();
        let result = hydra.ingest(ev).unwrap();

        // No rules = no violations = only the initial event
        assert_eq!(result.events.len(), 1);
    }
}
