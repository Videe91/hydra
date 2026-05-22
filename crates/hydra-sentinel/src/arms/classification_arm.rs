//! # Classification Arm (B2)
//!
//! Auto-classifies resources by sensitivity and business criticality.
//!
//! When a new node is created (or a needs_classification signal fires),
//! this Arm applies heuristic classification rules:
//!
//! - Databases → high sensitivity, critical by default
//! - Object stores → medium sensitivity (may contain PII)
//! - Compute → low sensitivity (stateless), criticality from dependencies
//! - Serverless → low sensitivity, low criticality
//!
//! Fires on: NodeCreated (protectable types), Signal("needs_classification")
//! Reads: graph (dependency count to infer criticality)
//! Emits: NodeUpdated (business_criticality, data_sensitivity, classification)

use hydra_core::event::{Event, EventKind, Value};
use hydra_core::graph::GraphReader;
use hydra_core::id::NodeId;
use hydra_core::subscription::SubscriptionHandler;
use crate::nodes::prop;

use crate::queries::protection_status::PROTECTABLE_TYPES;
use std::collections::HashMap;

/// Classification rules for automatic resource scoring.
#[derive(Debug, Clone)]
pub struct ClassificationRule {
    /// Node type this rule applies to
    pub node_type: String,
    /// Default business criticality (0-10)
    pub default_criticality: i64,
    /// Default data sensitivity
    pub default_sensitivity: String,
    /// Classification label
    pub classification: String,
}

/// Classification Arm — auto-classifies newly discovered resources.
pub struct ClassificationArm {
    rules: Vec<ClassificationRule>,
}

impl ClassificationArm {
    pub fn new(rules: Vec<ClassificationRule>) -> Self {
        Self { rules }
    }

    /// Create with sensible defaults for data protection.
    pub fn with_defaults() -> Self {
        use crate::nodes::*;
        Self {
            rules: vec![
                ClassificationRule {
                    node_type: MANAGED_DATABASE.into(),
                    default_criticality: 9,
                    default_sensitivity: "high".into(),
                    classification: "tier_1_critical_data".into(),
                },
                ClassificationRule {
                    node_type: OBJECT_STORE.into(),
                    default_criticality: 7,
                    default_sensitivity: "medium".into(),
                    classification: "tier_2_important_data".into(),
                },
                ClassificationRule {
                    node_type: COMPUTE_INSTANCE.into(),
                    default_criticality: 5,
                    default_sensitivity: "low".into(),
                    classification: "tier_3_compute".into(),
                },
                ClassificationRule {
                    node_type: SERVERLESS_FUNCTION.into(),
                    default_criticality: 3,
                    default_sensitivity: "low".into(),
                    classification: "tier_4_ephemeral".into(),
                },
                ClassificationRule {
                    node_type: SAAS_APPLICATION.into(),
                    default_criticality: 6,
                    default_sensitivity: "medium".into(),
                    classification: "tier_2_important_data".into(),
                },
                ClassificationRule {
                    node_type: ENDPOINT.into(),
                    default_criticality: 4,
                    default_sensitivity: "low".into(),
                    classification: "tier_3_compute".into(),
                },
                ClassificationRule {
                    node_type: ON_PREM_SERVER.into(),
                    default_criticality: 7,
                    default_sensitivity: "high".into(),
                    classification: "tier_1_critical_data".into(),
                },
                // --- New resource types ---
                ClassificationRule {
                    node_type: CONTAINER_CLUSTER.into(),
                    default_criticality: 7,
                    default_sensitivity: "medium".into(),
                    classification: "tier_2_important_data".into(),
                },
                ClassificationRule {
                    node_type: CONTAINER_SERVICE.into(),
                    default_criticality: 6,
                    default_sensitivity: "medium".into(),
                    classification: "tier_2_important_data".into(),
                },
                ClassificationRule {
                    node_type: CACHE_CLUSTER.into(),
                    default_criticality: 6,
                    default_sensitivity: "medium".into(),
                    classification: "tier_2_important_data".into(),
                },
                ClassificationRule {
                    node_type: DATA_WAREHOUSE.into(),
                    default_criticality: 9,
                    default_sensitivity: "high".into(),
                    classification: "tier_1_critical_data".into(),
                },
                ClassificationRule {
                    node_type: STREAM.into(),
                    default_criticality: 5,
                    default_sensitivity: "medium".into(),
                    classification: "tier_3_compute".into(),
                },
                ClassificationRule {
                    node_type: ML_ENDPOINT.into(),
                    default_criticality: 5,
                    default_sensitivity: "medium".into(),
                    classification: "tier_3_compute".into(),
                },
                ClassificationRule {
                    node_type: MESSAGE_QUEUE.into(),
                    default_criticality: 5,
                    default_sensitivity: "low".into(),
                    classification: "tier_3_compute".into(),
                },
                ClassificationRule {
                    node_type: NOTIFICATION_TOPIC.into(),
                    default_criticality: 3,
                    default_sensitivity: "low".into(),
                    classification: "tier_4_ephemeral".into(),
                },
                ClassificationRule {
                    node_type: LOAD_BALANCER.into(),
                    default_criticality: 6,
                    default_sensitivity: "low".into(),
                    classification: "tier_2_important_data".into(),
                },
                ClassificationRule {
                    node_type: CDN_DISTRIBUTION.into(),
                    default_criticality: 4,
                    default_sensitivity: "low".into(),
                    classification: "tier_3_compute".into(),
                },
                ClassificationRule {
                    node_type: DNS_ZONE.into(),
                    default_criticality: 8,
                    default_sensitivity: "low".into(),
                    classification: "tier_1_critical_data".into(),
                },
                ClassificationRule {
                    node_type: FILE_SYSTEM.into(),
                    default_criticality: 7,
                    default_sensitivity: "high".into(),
                    classification: "tier_1_critical_data".into(),
                },
            ],
        }
    }

    fn classify_node(
        &self,
        node_id: &NodeId,
        type_id: &str,
        graph: &dyn GraphReader,
    ) -> Option<EventKind> {
        // Find the matching rule
        let rule = self.rules.iter().find(|r| r.node_type == type_id)?;

        // Boost criticality based on incoming dependency count
        // (more things depend on this → more critical)
        let incoming_deps = graph.incoming_edges_of_type(node_id, crate::nodes::DEPENDS_ON).len();
        let criticality_boost = (incoming_deps as i64).min(3); // cap at +3
        let final_criticality = (rule.default_criticality + criticality_boost).min(10);

        // Check if already classified (don't overwrite human classification)
        if let Some(node) = graph.node(node_id) {
            if node.get_str("classification").is_some() {
                return None; // Already classified, skip
            }
        }

        let mut changes = HashMap::new();
        changes.insert(prop::BUSINESS_CRITICALITY.to_string(), Value::Int(final_criticality));
        changes.insert(prop::DATA_SENSITIVITY.to_string(), Value::String(rule.default_sensitivity.clone()));
        changes.insert("classification".to_string(), Value::String(rule.classification.clone()));

        Some(EventKind::NodeUpdated {
            node_id: node_id.clone(),
            changes,
        })
    }
}

impl SubscriptionHandler for ClassificationArm {
    fn handle(
        &self,
        event: &Event,
        graph: &dyn GraphReader,
    ) -> Vec<EventKind> {
        match &event.kind {
            EventKind::NodeCreated { node_id, type_id, .. } => {
                if PROTECTABLE_TYPES.contains(&type_id.as_str()) {
                    self.classify_node(node_id, type_id, graph)
                        .into_iter().collect()
                } else {
                    vec![]
                }
            }

            EventKind::Signal { source, name, .. } if name == "needs_classification" => {
                if let Some(node) = graph.node(source) {
                    if node.is_alive() {
                        self.classify_node(source, node.type_id(), graph)
                            .into_iter().collect()
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            }

            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_engine::prelude::*;
    use hydra_core::subscription::{Subscription, EventFilter};
    use crate::nodes::aws::*;
    use crate::edges;

    #[test]
    fn classifies_database_as_tier1() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "classification_arm",
            EventFilter::NodeCreated,
            190,
            Box::new(ClassificationArm::with_defaults()),
        ));

        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();

        let node = hydra.graph().node(&db).unwrap();
        assert_eq!(node.get_i64(prop::BUSINESS_CRITICALITY), Some(9));
        assert_eq!(node.get_str(prop::DATA_SENSITIVITY), Some("high"));
        assert_eq!(node.get_str("classification"), Some("tier_1_critical_data"));
    }

    #[test]
    fn boosts_criticality_for_heavily_depended_node() {
        let mut hydra = Hydra::new();

        // Create DB first WITHOUT the arm
        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();

        // Add 3 dependents
        for i in 0..3 {
            let (ec2, ev) = Ec2Builder::new(&format!("i-{}", i)).build();
            hydra.ingest(ev).unwrap();
            let (_, ev) = edges::depends_on(ec2, db.clone(), "database", 1.0);
            hydra.ingest(ev).unwrap();
        }

        // Now register arm and trigger classification
        hydra.register(Subscription::new(
            "classification_arm",
            EventFilter::SignalName("needs_classification".to_string()),
            190,
            Box::new(ClassificationArm::with_defaults()),
        ));

        hydra.ingest(EventKind::Signal {
            source: db.clone(),
            name: "needs_classification".to_string(),
            payload: HashMap::new(),
        }).unwrap();

        let node = hydra.graph().node(&db).unwrap();
        let crit = node.get_i64(prop::BUSINESS_CRITICALITY).unwrap_or(0);
        // Base 9 + 3 deps = 12, capped at 10
        assert_eq!(crit, 10, "Criticality should be capped at 10");
    }

    #[test]
    fn does_not_overwrite_existing_classification() {
        let mut hydra = Hydra::new();

        // Pre-classify the node
        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();
        hydra.ingest(EventKind::NodeUpdated {
            node_id: db.clone(),
            changes: HashMap::from([
                ("classification".to_string(), Value::String("custom_class".into())),
            ]),
        }).unwrap();

        // Register arm
        hydra.register(Subscription::new(
            "classification_arm",
            EventFilter::SignalName("needs_classification".to_string()),
            190,
            Box::new(ClassificationArm::with_defaults()),
        ));

        hydra.ingest(EventKind::Signal {
            source: db.clone(),
            name: "needs_classification".to_string(),
            payload: HashMap::new(),
        }).unwrap();

        let node = hydra.graph().node(&db).unwrap();
        assert_eq!(node.get_str("classification"), Some("custom_class"),
            "Should not overwrite human classification");
    }
}
