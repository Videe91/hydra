//! # Policy Arm (B3)
//!
//! Computes protection policies automatically based on classification.
//!
//! Policy = f(criticality, sensitivity, compliance_requirements, budget_constraints)
//!
//! Fires on: NodeUpdated (classification/criticality changed)
//! Reads: node properties (criticality, sensitivity, classification)
//! Emits: NodeCreated (protection_policy node) + EdgeCreated (policy_applies_to)
//!        + Signal("policy_computed") for Execution Arm

use hydra_core::event::{Event, EventKind, Value};
use hydra_core::graph::GraphReader;
use hydra_core::id::{NodeId, EdgeId};
use hydra_core::subscription::SubscriptionHandler;
use crate::nodes::prop;
use std::collections::HashMap;

/// Policy Arm — computes protection policies for classified resources.
pub struct PolicyArm;

impl PolicyArm {
    pub fn new() -> Self { Self }

    /// Compute policy parameters from resource classification.
    fn compute_policy(
        &self,
        node_id: &NodeId,
        graph: &dyn GraphReader,
    ) -> Option<PolicyParams> {
        let node = graph.node(node_id)?;
        if !node.is_alive() { return None; }

        let criticality = node.get_i64(prop::BUSINESS_CRITICALITY).unwrap_or(0);
        let sensitivity = node.get_str(prop::DATA_SENSITIVITY).unwrap_or("unknown");

        // Skip if not yet classified
        if criticality == 0 && sensitivity == "unknown" {
            return None;
        }

        // Check if a policy already exists for this node
        let policy_node_id = NodeId::from_str(&format!("policy_{}", node_id.as_str()));
        if graph.node(&policy_node_id).is_some() {
            return None; // Policy node already exists
        }
        let existing_policies = graph.incoming_edges_of_type(node_id, crate::nodes::POLICY_APPLIES_TO);
        if !existing_policies.is_empty() {
            return None; // Already has a policy edge
        }

        // Compute policy based on classification
        let (frequency_hours, retention_days, storage_tier, replication) = match criticality {
            9..=10 => (1, 365, "hot", true),        // Tier 1: hourly, 1yr, hot, replicated
            7..=8 => (4, 90, "warm", true),          // Tier 2: 4hr, 90d, warm, replicated
            5..=6 => (12, 30, "warm", false),        // Tier 3: 12hr, 30d, warm, no replication
            3..=4 => (24, 14, "cold", false),        // Tier 4: daily, 14d, cold
            _ => (168, 7, "archive", false),          // Default: weekly, 7d, archive
        };

        // Sensitivity override: high sensitivity gets encryption + longer retention
        let (retention_days, encryption) = match sensitivity {
            "high" => (retention_days.max(365), true),
            "medium" => (retention_days.max(90), true),
            _ => (retention_days, false),
        };

        Some(PolicyParams {
            frequency_hours,
            retention_days,
            storage_tier: storage_tier.to_string(),
            replication,
            encryption,
        })
    }
}

struct PolicyParams {
    frequency_hours: i64,
    retention_days: i64,
    storage_tier: String,
    replication: bool,
    encryption: bool,
}

impl SubscriptionHandler for PolicyArm {
    fn handle(
        &self,
        event: &Event,
        graph: &dyn GraphReader,
    ) -> Vec<EventKind> {
        let mut events = Vec::new();

        let node_id = match &event.kind {
            // Fire when classification or criticality changes
            EventKind::NodeUpdated { node_id, changes }
                if changes.contains_key("classification")
                    || changes.contains_key(prop::BUSINESS_CRITICALITY) =>
            {
                node_id.clone()
            }
            _ => return events,
        };

        if let Some(params) = self.compute_policy(&node_id, graph) {
            // Create a protection policy node
            let policy_id = NodeId::from_str(&format!("policy_{}", node_id.as_str()));
            let mut props = HashMap::new();
            props.insert("name".to_string(), Value::String(format!("Auto-policy for {}", node_id.as_str())));
            props.insert(prop::BACKUP_FREQUENCY_HOURS.to_string(), Value::Int(params.frequency_hours));
            props.insert(prop::RETENTION_DAYS.to_string(), Value::Int(params.retention_days));
            props.insert("storage_tier".to_string(), Value::String(params.storage_tier));
            props.insert("replication_enabled".to_string(), Value::Bool(params.replication));
            props.insert("encryption_required".to_string(), Value::Bool(params.encryption));
            props.insert("auto_generated".to_string(), Value::Bool(true));

            events.push(EventKind::NodeCreated {
                node_id: policy_id.clone(),
                type_id: crate::nodes::PROTECTION_POLICY.to_string(),
                properties: props,
            });

            // Link policy to resource
            let edge_id = EdgeId::new();
            events.push(EventKind::EdgeCreated {
                edge_id,
                source: policy_id.clone(),
                target: node_id.clone(),
                type_id: crate::nodes::POLICY_APPLIES_TO.to_string(),
                properties: HashMap::from([
                    ("confidence".to_string(), Value::Float(1.0)),
                    ("discovered_by".to_string(), Value::String("policy_arm".into())),
                ]),
            });

            // Signal for Execution Arm
            events.push(EventKind::Signal {
                source: node_id,
                name: "policy_computed".to_string(),
                payload: HashMap::from([
                    ("policy_id".to_string(), Value::String(policy_id.as_str().to_string())),
                    ("frequency_hours".to_string(), Value::Int(params.frequency_hours)),
                ]),
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
    fn policy_computed_for_critical_database() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "policy_arm",
            EventFilter::NodeUpdated,
            180,
            Box::new(PolicyArm::new()),
        ));

        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();

        // Simulate classification
        hydra.ingest(EventKind::NodeUpdated {
            node_id: db.clone(),
            changes: HashMap::from([
                (prop::BUSINESS_CRITICALITY.to_string(), Value::Int(10)),
                (prop::DATA_SENSITIVITY.to_string(), Value::String("high".into())),
                ("classification".to_string(), Value::String("tier_1_critical_data".into())),
            ]),
        }).unwrap();

        // Policy node should exist
        let policy_id = NodeId::from_str(&format!("policy_{}", db.as_str()));
        let policy = hydra.graph().node(&policy_id);
        assert!(policy.is_some(), "Policy node should be created");
        let policy = policy.unwrap();
        assert_eq!(policy.get_i64(prop::BACKUP_FREQUENCY_HOURS), Some(1));
        assert_eq!(policy.get_i64(prop::RETENTION_DAYS), Some(365));
        assert_eq!(policy.get_bool("replication_enabled"), Some(true));
        assert_eq!(policy.get_bool("encryption_required"), Some(true));
    }

    #[test]
    fn policy_not_duplicated() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "policy_arm",
            EventFilter::NodeUpdated,
            180,
            Box::new(PolicyArm::new()),
        ));

        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();

        // First classification → policy created
        hydra.ingest(EventKind::NodeUpdated {
            node_id: db.clone(),
            changes: HashMap::from([
                (prop::BUSINESS_CRITICALITY.to_string(), Value::Int(9)),
                ("classification".to_string(), Value::String("tier_1".into())),
            ]),
        }).unwrap();

        // Second classification update → should NOT create another policy
        let _result = hydra.ingest(EventKind::NodeUpdated {
            node_id: db.clone(),
            changes: HashMap::from([
                (prop::BUSINESS_CRITICALITY.to_string(), Value::Int(10)),
            ]),
        }).unwrap();

        // Only 1 policy node should exist
        let policies = hydra.graph().nodes_by_type(crate::nodes::PROTECTION_POLICY);
        assert_eq!(policies.len(), 1, "Should not duplicate policy");
    }

    #[test]
    fn low_criticality_gets_relaxed_policy() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "policy_arm",
            EventFilter::NodeUpdated,
            180,
            Box::new(PolicyArm::new()),
        ));

        let (lambda, ev) = LambdaBuilder::new("fn-processor").build();
        hydra.ingest(ev).unwrap();

        hydra.ingest(EventKind::NodeUpdated {
            node_id: lambda.clone(),
            changes: HashMap::from([
                (prop::BUSINESS_CRITICALITY.to_string(), Value::Int(3)),
                (prop::DATA_SENSITIVITY.to_string(), Value::String("low".into())),
                ("classification".to_string(), Value::String("tier_4".into())),
            ]),
        }).unwrap();

        let policy_id = NodeId::from_str(&format!("policy_{}", lambda.as_str()));
        let policy = hydra.graph().node(&policy_id).unwrap();
        assert_eq!(policy.get_i64(prop::BACKUP_FREQUENCY_HOURS), Some(24));
        assert_eq!(policy.get_i64(prop::RETENTION_DAYS), Some(14));
        assert_eq!(policy.get_bool("replication_enabled"), Some(false));
    }
}
