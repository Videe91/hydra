//! # Trust Arm
//!
//! Recomputes trust scores when protection or dependency state changes.
//!
//! Fires on: NodeUpdated (protection_status changed), EdgeCreated/Deleted
//! (dependency or backup edges changed), Signal (trust_penalty from anomaly bridge).
//!
//! Reads: confidence_report query to find weakest links
//! Emits: NodeUpdated events to adjust trust dimensions

use hydra_core::event::{Event, EventKind, Value};
use hydra_core::graph::GraphReader;
use hydra_core::subscription::SubscriptionHandler;
use crate::nodes::prop;
use crate::nodes::trust::{TrustWeights};

/// Trust Arm — recomputes trust scores based on graph state.
pub struct TrustArm {
    weights: TrustWeights,
}

impl TrustArm {
    pub fn new() -> Self {
        Self {
            weights: TrustWeights::default_weights(),
        }
    }

    pub fn with_weights(weights: TrustWeights) -> Self {
        Self { weights }
    }
}

impl SubscriptionHandler for TrustArm {
    fn handle(
        &self,
        event: &Event,
        graph: &dyn GraphReader,
    ) -> Vec<EventKind> {
        let mut events = Vec::new();

        match &event.kind {
            // Trust penalty signal from anomaly bridge
            EventKind::Signal { source, name, payload } if name == "trust_penalty" => {
                if let Some(node) = graph.node(source) {
                    if !node.is_alive() { return events; }

                    let mut changes = std::collections::HashMap::new();

                    // Apply penalty to anomaly_free dimension
                    if let Some(Value::Float(penalty)) = payload.get(prop::TRUST_ANOMALY_FREE) {
                        let current = node.get_f64(prop::TRUST_ANOMALY_FREE).unwrap_or(1.0);
                        let new_val = (current - penalty).max(0.0);
                        changes.insert(prop::TRUST_ANOMALY_FREE.to_string(), Value::Float(new_val));
                    }

                    // Recompute composite
                    if !changes.is_empty() {
                        let composite = self.recompute_composite(node, &changes);
                        changes.insert(prop::TRUST_COMPOSITE.to_string(), Value::Float(composite));

                        events.push(EventKind::NodeUpdated {
                            node_id: source.clone(),
                            changes,
                        });
                    }
                }
            }

            // Protection status changed — update backup_freshness dimension
            EventKind::NodeUpdated { node_id, changes }
                if changes.contains_key(prop::PROTECTION_STATUS) =>
            {
                if let Some(node) = graph.node(node_id) {
                    if !node.is_alive() { return events; }

                    let status = changes.get(prop::PROTECTION_STATUS)
                        .and_then(|v| match v {
                            Value::String(s) => Some(s.as_str()),
                            _ => None,
                        })
                        .unwrap_or("unknown");

                    let freshness = if status == "protected" { 1.0 } else { 0.0 };

                    let mut new_changes = std::collections::HashMap::new();
                    new_changes.insert(
                        prop::TRUST_BACKUP_FRESHNESS.to_string(),
                        Value::Float(freshness),
                    );

                    let composite = self.recompute_composite(node, &new_changes);
                    new_changes.insert(prop::TRUST_COMPOSITE.to_string(), Value::Float(composite));

                    events.push(EventKind::NodeUpdated {
                        node_id: node_id.clone(),
                        changes: new_changes,
                    });
                }
            }

            // New backup edge created — improve backup_freshness
            EventKind::EdgeCreated { source, type_id, .. }
                if type_id == crate::nodes::PROTECTED_BY =>
            {
                // Edge: resource --protected_by--> snapshot
                // source = the resource that just got a backup
                if let Some(node) = graph.node(source) {
                    if !node.is_alive() { return events; }

                    let mut new_changes = std::collections::HashMap::new();
                    new_changes.insert(
                        prop::TRUST_BACKUP_FRESHNESS.to_string(),
                        Value::Float(1.0),
                    );
                    let composite = self.recompute_composite(node, &new_changes);
                    new_changes.insert(
                        prop::TRUST_COMPOSITE.to_string(),
                        Value::Float(composite),
                    );
                    events.push(EventKind::NodeUpdated {
                        node_id: source.clone(),
                        changes: new_changes,
                    });
                }
            }

            _ => {}
        }

        events
    }
}

impl TrustArm {
    /// Recompute composite trust score, overriding specific dimensions.
    fn recompute_composite(
        &self,
        node: &hydra_core::node::Node,
        overrides: &std::collections::HashMap<String, Value>,
    ) -> f64 {
        let get = |key: &str| -> f64 {
            if let Some(Value::Float(v)) = overrides.get(key) {
                *v
            } else {
                node.get_f64(key).unwrap_or(0.0)
            }
        };

        let dims = [
            (get(prop::TRUST_BACKUP_FRESHNESS), self.weights.backup_freshness),
            (get(prop::TRUST_BACKUP_VERIFIED), self.weights.backup_verified),
            (get(prop::TRUST_RECOVERY_TESTED), self.weights.recovery_tested),
            (get(prop::TRUST_DEPENDENCY_HEALTH), self.weights.dependency_health),
            (get(prop::TRUST_COMPLIANCE_STATUS), self.weights.compliance_status),
            (get(prop::TRUST_ANOMALY_FREE), self.weights.anomaly_free),
            (get(prop::TRUST_REPLICATION_HEALTH), self.weights.replication_health),
        ];

        let total_weight: f64 = dims.iter().map(|(_, w)| w).sum();
        if total_weight == 0.0 { return 0.0; }

        let weighted_sum: f64 = dims.iter().map(|(v, w)| v * w).sum();
        ((weighted_sum / total_weight) * 100.0).clamp(0.0, 100.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_engine::prelude::*;
    use hydra_core::subscription::{Subscription, EventFilter};
    use crate::nodes::aws::*;

    #[test]
    fn trust_arm_handles_trust_penalty_signal() {
        let mut hydra = Hydra::new();

        let (ec2, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();

        // Register TrustArm
        let arm = TrustArm::new();
        let sub = Subscription::new(
            "trust_arm",
            EventFilter::SignalName("trust_penalty".to_string()),
            100,
            Box::new(arm),
        );
        hydra.register(sub);

        // Send a trust penalty signal
        let result = hydra.ingest(EventKind::Signal {
            source: ec2.clone(),
            name: "trust_penalty".to_string(),
            payload: std::collections::HashMap::from([
                (prop::TRUST_ANOMALY_FREE.to_string(), Value::Float(0.3)),
            ]),
        }).unwrap();

        // The TrustArm should have emitted a NodeUpdated
        assert!(result.events.len() > 1, "Arm should emit events. Got {}", result.events.len());

        // Check that the node's trust was actually updated
        let node = hydra.graph().node(&ec2).unwrap();
        let anomaly_free = node.get_f64(prop::TRUST_ANOMALY_FREE).unwrap_or(1.0);
        // Started at 1.0 (default), penalty 0.3 → should be 0.7
        assert!((anomaly_free - 0.7).abs() < 0.01,
            "anomaly_free should be 0.7, got {}", anomaly_free);
    }

    #[test]
    fn trust_arm_handles_protection_change() {
        let mut hydra = Hydra::new();

        let (ec2, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();

        let arm = TrustArm::new();
        let sub = Subscription::new(
            "trust_arm",
            EventFilter::EventKindName("node_updated".to_string()),
            100,
            Box::new(arm),
        );
        hydra.register(sub);

        // Mark as protected
        let result = hydra.ingest(EventKind::NodeUpdated {
            node_id: ec2.clone(),
            changes: std::collections::HashMap::from([
                (prop::PROTECTION_STATUS.to_string(), Value::String("protected".into())),
            ]),
        }).unwrap();

        // Arm should emit trust update
        assert!(result.events.len() > 1);

        let node = hydra.graph().node(&ec2).unwrap();
        let freshness = node.get_f64(prop::TRUST_BACKUP_FRESHNESS).unwrap_or(0.0);
        assert!((freshness - 1.0).abs() < 0.01,
            "backup_freshness should be 1.0 after protection, got {}", freshness);
    }

    #[test]
    fn trust_arm_recomputes_composite() {
        let arm = TrustArm::new();
        let mut hydra = Hydra::new();
        let (ec2, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();

        let node = hydra.graph().node(&ec2).unwrap();
        let overrides = std::collections::HashMap::from([
            (prop::TRUST_BACKUP_FRESHNESS.to_string(), Value::Float(1.0)),
            (prop::TRUST_ANOMALY_FREE.to_string(), Value::Float(1.0)),
        ]);

        let composite = arm.recompute_composite(node, &overrides);
        // With default weights, 2 of 7 dimensions at 1.0, rest at 0.0
        assert!(composite > 0.0 && composite < 50.0);
    }
}
