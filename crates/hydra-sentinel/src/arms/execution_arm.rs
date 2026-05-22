//! # Execution Arm (B4)
//!
//! Triggers backup execution when policies are ready.
//!
//! In production, this Arm would call cloud APIs (AWS Backup, Azure Recovery
//! Services, GCP Backup). In Hydra, it emits the graph events that represent
//! a backup being taken and completes the protection chain.
//!
//! Fires on: Signal("policy_computed"), Signal("scheduled_backup")
//! Reads: policy node (frequency, retention, storage tier)
//! Emits: NodeCreated (backup_snapshot), EdgeCreated (protected_by),
//!        NodeUpdated (protection_status), Signal("backup_completed")

use hydra_core::event::{Event, EventKind, Value};
use hydra_core::graph::GraphReader;
use hydra_core::id::{NodeId, EdgeId};
use hydra_core::subscription::SubscriptionHandler;
use crate::nodes::prop;
use std::collections::HashMap;

/// Execution Arm — executes protection operations.
pub struct ExecutionArm;

impl ExecutionArm {
    pub fn new() -> Self { Self }
}

impl SubscriptionHandler for ExecutionArm {
    fn handle(
        &self,
        event: &Event,
        graph: &dyn GraphReader,
    ) -> Vec<EventKind> {
        let mut events = Vec::new();

        match &event.kind {
            EventKind::Signal { source, name, payload }
                if name == "policy_computed" || name == "scheduled_backup" =>
            {
                let resource_id = source;

                // Verify the resource exists and is alive
                let _node = match graph.node(resource_id) {
                    Some(n) if n.is_alive() => n,
                    _ => return events,
                };

                // Get policy parameters from the signal
                let frequency = payload.get("frequency_hours")
                    .and_then(|v| match v { Value::Int(i) => Some(*i), _ => None })
                    .unwrap_or(24);

                // Generate a unique snapshot ID using the event ID for uniqueness
                let unique_suffix = &event.id.as_str()[..8.min(event.id.as_str().len())];
                let snap_id = NodeId::from_str(
                    &format!("snap_{}_{}", resource_id.as_str(), unique_suffix)
                );

                // Create the backup snapshot node
                let mut snap_props = HashMap::new();
                snap_props.insert("name".to_string(),
                    Value::String(format!("Backup of {}", resource_id.as_str())));
                snap_props.insert("source_resource".to_string(),
                    Value::String(resource_id.as_str().to_string()));
                snap_props.insert("created_by".to_string(),
                    Value::String("execution_arm".into()));
                snap_props.insert("status".to_string(),
                    Value::String("completed".into()));
                snap_props.insert("backup_type".to_string(),
                    Value::String(if frequency <= 4 { "incremental" } else { "full" }.into()));

                events.push(EventKind::NodeCreated {
                    node_id: snap_id.clone(),
                    type_id: crate::nodes::BACKUP_SNAPSHOT.to_string(),
                    properties: snap_props,
                });

                // Link snapshot to resource
                events.push(EventKind::EdgeCreated {
                    edge_id: EdgeId::new(),
                    source: resource_id.clone(),
                    target: snap_id.clone(),
                    type_id: crate::nodes::PROTECTED_BY.to_string(),
                    properties: HashMap::from([
                        ("confidence".to_string(), Value::Float(1.0)),
                        ("discovered_by".to_string(), Value::String("execution_arm".into())),
                    ]),
                });

                // Update protection status on the resource
                events.push(EventKind::NodeUpdated {
                    node_id: resource_id.clone(),
                    changes: HashMap::from([
                        (prop::PROTECTION_STATUS.to_string(), Value::String("protected".into())),
                    ]),
                });

                // Signal completion for Verification Arm
                events.push(EventKind::Signal {
                    source: resource_id.clone(),
                    name: "backup_completed".to_string(),
                    payload: HashMap::from([
                        ("snapshot_id".to_string(), Value::String(snap_id.as_str().to_string())),
                        ("backup_type".to_string(),
                            Value::String(if frequency <= 4 { "incremental" } else { "full" }.into())),
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
    fn execution_arm_creates_snapshot_on_policy() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "execution_arm",
            EventFilter::SignalName("policy_computed".to_string()),
            170,
            Box::new(ExecutionArm::new()),
        ));

        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();

        // Simulate policy_computed signal
        hydra.ingest(EventKind::Signal {
            source: db.clone(),
            name: "policy_computed".to_string(),
            payload: HashMap::from([
                ("frequency_hours".to_string(), Value::Int(1)),
            ]),
        }).unwrap();

        // Snapshot should exist
        let snapshots = hydra.graph().nodes_by_type(crate::nodes::BACKUP_SNAPSHOT);
        assert_eq!(snapshots.len(), 1, "Should create one snapshot");

        // Resource should be marked as protected
        let node = hydra.graph().node(&db).unwrap();
        assert_eq!(node.get_str(prop::PROTECTION_STATUS), Some("protected"));

        // Protected_by edge should exist
        let edges = hydra.graph().outgoing_edges_of_type(&db, crate::nodes::PROTECTED_BY);
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn execution_arm_skips_deleted_resource() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "execution_arm",
            EventFilter::SignalName("policy_computed".to_string()),
            170,
            Box::new(ExecutionArm::new()),
        ));

        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();
        hydra.ingest(EventKind::NodeDeleted { node_id: db.clone() }).unwrap();

        let _result = hydra.ingest(EventKind::Signal {
            source: db.clone(),
            name: "policy_computed".to_string(),
            payload: HashMap::new(),
        }).unwrap();

        let snapshots = hydra.graph().nodes_by_type(crate::nodes::BACKUP_SNAPSHOT);
        assert_eq!(snapshots.len(), 0, "Should not backup a deleted resource");
    }

    #[test]
    fn scheduled_backup_also_triggers_execution() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "execution_arm",
            EventFilter::Or(vec![
                EventFilter::SignalName("policy_computed".to_string()),
                EventFilter::SignalName("scheduled_backup".to_string()),
            ]),
            170,
            Box::new(ExecutionArm::new()),
        ));

        let (db, ev) = RdsBuilder::new("db-prod").build();
        hydra.ingest(ev).unwrap();

        hydra.ingest(EventKind::Signal {
            source: db.clone(),
            name: "scheduled_backup".to_string(),
            payload: HashMap::from([
                ("frequency_hours".to_string(), Value::Int(24)),
            ]),
        }).unwrap();

        let snapshots = hydra.graph().nodes_by_type(crate::nodes::BACKUP_SNAPSHOT);
        assert_eq!(snapshots.len(), 1);
    }
}
