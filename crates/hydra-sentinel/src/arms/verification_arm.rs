//! # Verification Arm (B5) — THE KEY DIFFERENTIATOR
//!
//! Verifies that completed backups are actually restorable.
//!
//! In production, this Arm would:
//! - Spin up a sandbox environment
//! - Restore the backup
//! - Run integrity checks (checksums, row counts, health endpoints)
//! - Record the results as VerificationResult nodes
//!
//! In Hydra, it creates the verification graph structure and
//! updates the 7-dimension trust score.
//!
//! Fires on: Signal("backup_completed")
//! Reads: snapshot node, resource node (for trust dimensions)
//! Emits: NodeCreated (verification_result), EdgeCreated (verified_by),
//!        NodeUpdated (trust dimensions on the resource)

use hydra_core::event::{Event, EventKind, Value};
use hydra_core::graph::GraphReader;
use hydra_core::id::{NodeId, EdgeId};
use hydra_core::subscription::SubscriptionHandler;
use crate::nodes::prop;
use std::collections::HashMap;

/// Verification Arm — verifies backup integrity and updates trust.
pub struct VerificationArm;

impl VerificationArm {
    pub fn new() -> Self { Self }
}

impl SubscriptionHandler for VerificationArm {
    fn handle(
        &self,
        event: &Event,
        graph: &dyn GraphReader,
    ) -> Vec<EventKind> {
        let mut events = Vec::new();

        match &event.kind {
            EventKind::Signal { source, name, payload }
                if name == "backup_completed" =>
            {
                let resource_id = source;
                let snap_id_str = match payload.get("snapshot_id") {
                    Some(Value::String(s)) => s.clone(),
                    _ => return events,
                };
                let snap_id = NodeId::from_str(&snap_id_str);

                // Verify both nodes exist
                if graph.node(resource_id).is_none() || graph.node(&snap_id).is_none() {
                    return events;
                }

                // In production: run actual verification (restore in sandbox, check integrity)
                // Determine verification outcome from snapshot state
                let snap_node = graph.node(&snap_id).unwrap();
                let snap_status = snap_node.get_str("status").unwrap_or("unknown");
                let verification_passed = snap_status == "completed";

                let verification_id = NodeId::from_str(
                    &format!("verify_{}", snap_id_str)
                );

                let status = if verification_passed { "passed" } else { "failed" };

                let mut verify_props = HashMap::new();
                verify_props.insert("name".to_string(),
                    Value::String(format!("Verification of {}", snap_id_str)));
                verify_props.insert("verified_by".to_string(),
                    Value::String("verification_arm".into()));
                verify_props.insert("status".to_string(),
                    Value::String(status.into()));
                verify_props.insert("integrity_check".to_string(),
                    Value::Bool(verification_passed));
                verify_props.insert("restore_tested".to_string(),
                    Value::Bool(verification_passed));

                // Create verification result node
                events.push(EventKind::NodeCreated {
                    node_id: verification_id.clone(),
                    type_id: crate::nodes::VERIFICATION_RESULT.to_string(),
                    properties: verify_props,
                });

                // Link: snapshot --verified_by--> verification_result
                events.push(EventKind::EdgeCreated {
                    edge_id: EdgeId::new(),
                    source: snap_id.clone(),
                    target: verification_id.clone(),
                    type_id: crate::nodes::VERIFIED_BY.to_string(),
                    properties: HashMap::from([
                        ("confidence".to_string(), Value::Float(1.0)),
                        ("discovered_by".to_string(), Value::String("verification_arm".into())),
                    ]),
                });

                // Update trust dimensions based on verification outcome
                let (freshness, verified, tested) = if verification_passed {
                    (1.0, 1.0, 1.0)
                } else {
                    // Failed verification: backup exists but can't be restored
                    (0.5, 0.0, 0.0)
                };

                events.push(EventKind::NodeUpdated {
                    node_id: resource_id.clone(),
                    changes: HashMap::from([
                        (prop::TRUST_BACKUP_FRESHNESS.to_string(), Value::Float(freshness)),
                        (prop::TRUST_BACKUP_VERIFIED.to_string(), Value::Float(verified)),
                        (prop::TRUST_RECOVERY_TESTED.to_string(), Value::Float(tested)),
                    ]),
                });

                // Signal for downstream consumers
                let signal_name = if verification_passed {
                    "verification_completed"
                } else {
                    "verification_failed"
                };
                events.push(EventKind::Signal {
                    source: resource_id.clone(),
                    name: signal_name.to_string(),
                    payload: HashMap::from([
                        ("snapshot_id".to_string(), Value::String(snap_id_str)),
                        ("verification_id".to_string(), Value::String(verification_id.as_str().to_string())),
                        ("status".to_string(), Value::String(status.into())),
                    ]),
                });
            }

            _ => {}
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
    fn verification_creates_result_and_updates_trust() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "verification_arm",
            EventFilter::SignalName("backup_completed".to_string()),
            160,
            Box::new(VerificationArm::new()),
        ));

        // Set up: resource + snapshot
        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();

        // Create snapshot with a known deterministic ID
        let snap_id = NodeId::from_str("snap-001");
        hydra.ingest(EventKind::NodeCreated {
            node_id: snap_id.clone(),
            type_id: crate::nodes::BACKUP_SNAPSHOT.to_string(),
            properties: HashMap::from([
                ("name".to_string(), Value::String("test snapshot".into())),
                ("status".to_string(), Value::String("completed".into())),
            ]),
        }).unwrap();

        // Trigger verification
        hydra.ingest(EventKind::Signal {
            source: db.clone(),
            name: "backup_completed".to_string(),
            payload: HashMap::from([
                ("snapshot_id".to_string(), Value::String("snap-001".into())),
            ]),
        }).unwrap();

        // Verification result should exist
        let verify_id = NodeId::from_str("verify_snap-001");
        let verify_node = hydra.graph().node(&verify_id);
        assert!(verify_node.is_some(), "Verification result should be created");
        assert_eq!(verify_node.unwrap().get_str("status"), Some("passed"));

        // verified_by edge should exist
        let edges = hydra.graph().outgoing_edges_of_type(
            &NodeId::from_str("snap-001"), crate::nodes::VERIFIED_BY);
        assert_eq!(edges.len(), 1);

        // Trust should be updated on the resource
        let node = hydra.graph().node(&db).unwrap();
        assert_eq!(node.get_f64(prop::TRUST_BACKUP_FRESHNESS), Some(1.0));
        assert_eq!(node.get_f64(prop::TRUST_BACKUP_VERIFIED), Some(1.0));
        assert_eq!(node.get_f64(prop::TRUST_RECOVERY_TESTED), Some(1.0));
    }

    #[test]
    fn verification_skips_missing_snapshot() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "verification_arm",
            EventFilter::SignalName("backup_completed".to_string()),
            160,
            Box::new(VerificationArm::new()),
        ));

        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();

        // Trigger with nonexistent snapshot
        let result = hydra.ingest(EventKind::Signal {
            source: db.clone(),
            name: "backup_completed".to_string(),
            payload: HashMap::from([
                ("snapshot_id".to_string(), Value::String("nonexistent".into())),
            ]),
        }).unwrap();

        assert_eq!(result.events.len(), 1, "Should only have the trigger event");
    }
}
