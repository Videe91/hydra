//! # Discovery Arm (B1)
//!
//! Converts raw infrastructure sensor signals into typed Hydra graph nodes.
//!
//! In production, sensors (CloudTrail, Azure Activity Log, GCP Audit Log)
//! emit Signal("resource_discovered") events with raw metadata. This Arm
//! interprets the metadata and emits the correct NodeCreated events.
//!
//! Fires on: Signal("resource_discovered")
//! Reads: graph (to check if resource already exists — deduplication)
//! Emits: NodeCreated + EdgeCreated events for new resources and dependencies
//!
//! Also handles: Signal("resource_deleted") → NodeDeleted
//!               Signal("dependency_discovered") → EdgeCreated

use hydra_core::event::{Event, EventKind, Value};
use hydra_core::graph::GraphReader;
use hydra_core::id::NodeId;
use hydra_core::subscription::SubscriptionHandler;
use std::collections::HashMap;

/// Discovery Arm — transforms sensor signals into graph structure.
pub struct DiscoveryArm;

impl DiscoveryArm {
    pub fn new() -> Self { Self }
}

impl SubscriptionHandler for DiscoveryArm {
    fn handle(
        &self,
        event: &Event,
        graph: &dyn GraphReader,
    ) -> Vec<EventKind> {
        let mut events = Vec::new();

        match &event.kind {
            EventKind::Signal { name, payload, .. } if name == "resource_discovered" => {
                let resource_id = match payload.get("resource_id") {
                    Some(Value::String(id)) if !id.is_empty() && id.len() <= 256 => id.clone(),
                    _ => return events,
                };
                let resource_type = match payload.get("resource_type") {
                    Some(Value::String(t)) if !t.is_empty() && t.len() <= 128 => t.clone(),
                    _ => return events,
                };

                // Validate resource_type against known protectable types + infra types
                const ALLOWED_TYPES: &[&str] = &[
                    crate::nodes::COMPUTE_INSTANCE,
                    crate::nodes::MANAGED_DATABASE,
                    crate::nodes::OBJECT_STORE,
                    crate::nodes::BLOCK_VOLUME,
                    crate::nodes::VIRTUAL_NETWORK,
                    crate::nodes::NETWORK_SEGMENT,
                    crate::nodes::FIREWALL_RULE,
                    crate::nodes::IDENTITY_ROLE,
                    crate::nodes::IDENTITY_USER,
                    crate::nodes::SERVERLESS_FUNCTION,
                    crate::nodes::SAAS_APPLICATION,
                    crate::nodes::ENDPOINT,
                    crate::nodes::ON_PREM_SERVER,
                    crate::nodes::CONTAINER_CLUSTER,
                    crate::nodes::CONTAINER_SERVICE,
                    crate::nodes::CACHE_CLUSTER,
                    crate::nodes::DATA_WAREHOUSE,
                    crate::nodes::STREAM,
                    crate::nodes::ML_ENDPOINT,
                    crate::nodes::MESSAGE_QUEUE,
                    crate::nodes::NOTIFICATION_TOPIC,
                    crate::nodes::LOAD_BALANCER,
                    crate::nodes::CDN_DISTRIBUTION,
                    crate::nodes::DNS_ZONE,
                    crate::nodes::FILE_SYSTEM,
                ];
                if !ALLOWED_TYPES.contains(&resource_type.as_str()) {
                    return events; // Reject unknown resource types
                }

                let node_id = NodeId::from_str(&resource_id);

                // Deduplication: skip if already exists
                if graph.node(&node_id).is_some() {
                    return events;
                }

                // Build properties from payload
                let mut properties = HashMap::new();
                if let Some(Value::String(name)) = payload.get("name") {
                    properties.insert("name".to_string(), Value::String(name.clone()));
                }
                if let Some(Value::String(region)) = payload.get("region") {
                    properties.insert("region".to_string(), Value::String(region.clone()));
                }
                if let Some(Value::String(provider)) = payload.get("cloud_provider") {
                    properties.insert("cloud_provider".to_string(), Value::String(provider.clone()));
                }
                if let Some(Value::String(env)) = payload.get("environment") {
                    properties.insert("environment".to_string(), Value::String(env.clone()));
                }
                // Default protection status
                properties.insert(
                    crate::nodes::prop::PROTECTION_STATUS.to_string(),
                    Value::String("unprotected".into()),
                );

                events.push(EventKind::NodeCreated {
                    node_id: node_id.clone(),
                    type_id: resource_type,
                    properties,
                });

                // ClassificationArm fires on NodeCreated directly.
                // Signal("needs_classification") is only for explicit re-classification.
            }

            EventKind::Signal { name, payload, .. } if name == "resource_deleted" => {
                if let Some(Value::String(id)) = payload.get("resource_id") {
                    let node_id = NodeId::from_str(id);
                    if graph.node(&node_id).is_some() {
                        events.push(EventKind::NodeDeleted { node_id });
                    }
                }
            }

            EventKind::Signal { name, payload, .. } if name == "dependency_discovered" => {
                let source_id = match payload.get("source") {
                    Some(Value::String(s)) => NodeId::from_str(s),
                    _ => return events,
                };
                let target_id = match payload.get("target") {
                    Some(Value::String(t)) => NodeId::from_str(t),
                    _ => return events,
                };
                let dep_type = payload.get("dependency_type")
                    .and_then(|v| match v { Value::String(s) => Some(s.as_str()), _ => None })
                    .unwrap_or("unknown");
                let confidence = payload.get("confidence")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.8);

                // Only create edge if both nodes exist
                if graph.node(&source_id).is_some() && graph.node(&target_id).is_some() {
                    let edge_id = hydra_core::id::EdgeId::new();
                    let mut props = HashMap::new();
                    props.insert("confidence".to_string(), Value::Float(confidence));
                    props.insert("dependency_type".to_string(), Value::String(dep_type.to_string()));
                    props.insert("discovered_by".to_string(), Value::String("discovery_arm".into()));

                    events.push(EventKind::EdgeCreated {
                        edge_id,
                        source: source_id,
                        target: target_id,
                        type_id: crate::nodes::DEPENDS_ON.to_string(),
                        properties: props,
                    });
                }
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

    #[test]
    fn discovery_arm_creates_node_from_sensor_signal() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "discovery_arm",
            EventFilter::SignalName("resource_discovered".to_string()),
            200,
            Box::new(DiscoveryArm::new()),
        ));

        let mut payload = HashMap::new();
        payload.insert("resource_id".to_string(), Value::String("i-abc123".into()));
        payload.insert("resource_type".to_string(), Value::String("compute_instance".into()));
        payload.insert("name".to_string(), Value::String("api-server-1".into()));
        payload.insert("region".to_string(), Value::String("us-east-1".into()));
        payload.insert("cloud_provider".to_string(), Value::String("aws".into()));

        let result = hydra.ingest(EventKind::Signal {
            source: NodeId::from_str("sensor_cloudtrail"),
            name: "resource_discovered".to_string(),
            payload,
        }).unwrap();

        // Should have created the node (trigger + NodeCreated = 2 events minimum)
        assert!(result.events.len() >= 2);
        let node = hydra.graph().node(&NodeId::from_str("i-abc123"));
        assert!(node.is_some(), "Node should be created");
        assert_eq!(node.unwrap().type_id(), "compute_instance");
    }

    #[test]
    fn discovery_arm_deduplicates() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "discovery_arm",
            EventFilter::SignalName("resource_discovered".to_string()),
            200,
            Box::new(DiscoveryArm::new()),
        ));

        let mut payload = HashMap::new();
        payload.insert("resource_id".to_string(), Value::String("i-abc123".into()));
        payload.insert("resource_type".to_string(), Value::String("compute_instance".into()));

        // First discovery
        hydra.ingest(EventKind::Signal {
            source: NodeId::from_str("sensor"),
            name: "resource_discovered".to_string(),
            payload: payload.clone(),
        }).unwrap();

        // Second discovery of same resource
        let result = hydra.ingest(EventKind::Signal {
            source: NodeId::from_str("sensor"),
            name: "resource_discovered".to_string(),
            payload,
        }).unwrap();

        // Second time should only have the trigger signal, no new node
        assert_eq!(result.events.len(), 1, "Duplicate should be skipped");
        assert_eq!(hydra.graph().nodes_by_type("compute_instance").len(), 1);
    }

    #[test]
    fn discovery_arm_handles_deletion() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "discovery_arm",
            EventFilter::Or(vec![
                EventFilter::SignalName("resource_discovered".to_string()),
                EventFilter::SignalName("resource_deleted".to_string()),
            ]),
            200,
            Box::new(DiscoveryArm::new()),
        ));

        // Create
        let mut payload = HashMap::new();
        payload.insert("resource_id".to_string(), Value::String("i-abc123".into()));
        payload.insert("resource_type".to_string(), Value::String("compute_instance".into()));
        hydra.ingest(EventKind::Signal {
            source: NodeId::from_str("sensor"),
            name: "resource_discovered".to_string(),
            payload,
        }).unwrap();

        assert!(hydra.graph().node(&NodeId::from_str("i-abc123")).unwrap().is_alive());

        // Delete
        let mut del_payload = HashMap::new();
        del_payload.insert("resource_id".to_string(), Value::String("i-abc123".into()));
        hydra.ingest(EventKind::Signal {
            source: NodeId::from_str("sensor"),
            name: "resource_deleted".to_string(),
            payload: del_payload,
        }).unwrap();

        let node = hydra.graph().node(&NodeId::from_str("i-abc123")).unwrap();
        assert!(!node.is_alive(), "Node should be deleted");
    }
}
