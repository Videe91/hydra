//! # Response Arm (B7)
//!
//! Generates recovery plans and manages incidents when threats are detected.
//!
//! Fires on: Signal("threat_alert")
//! Reads: recovery_plan query, blast_radius query, graph state
//! Emits: NodeCreated (incident + recovery_plan nodes), Signal("recovery_ready")

use hydra_core::event::{Event, EventKind, Value};
use hydra_core::graph::GraphReader;
use hydra_core::id::NodeId;
use hydra_core::subscription::SubscriptionHandler;
use crate::queries::recovery_plan::{recovery_plan, RecoveryAction};
use std::collections::HashMap;

/// Response Arm — generates recovery plans for detected threats.
pub struct ResponseArm;

impl ResponseArm {
    pub fn new() -> Self { Self }
}

impl SubscriptionHandler for ResponseArm {
    fn handle(
        &self,
        event: &Event,
        graph: &dyn GraphReader,
    ) -> Vec<EventKind> {
        let mut events = Vec::new();

        match &event.kind {
            EventKind::Signal { source, name, payload }
                if name == "threat_alert" =>
            {
                let severity = payload.get("severity")
                    .and_then(|v| match v { Value::String(s) => Some(s.as_str()), _ => None })
                    .unwrap_or("Low");
                let blast_scope = payload.get("blast_scope")
                    .and_then(|v| match v { Value::Int(i) => Some(*i), _ => None })
                    .unwrap_or(0);

                // Create incident node using event ID for uniqueness
                let unique_suffix = &event.id.as_str()[..8.min(event.id.as_str().len())];
                let incident_id = NodeId::from_str(
                    &format!("incident_{}_{}", source.as_str(), unique_suffix)
                );

                let mut incident_props = HashMap::new();
                incident_props.insert("name".to_string(),
                    Value::String(format!("Threat on {} — {}", source.as_str(), severity)));
                incident_props.insert("severity".to_string(),
                    Value::String(severity.to_string()));
                incident_props.insert("blast_scope".to_string(),
                    Value::Int(blast_scope));
                incident_props.insert("status".to_string(),
                    Value::String("open".into()));
                incident_props.insert("origin_resource".to_string(),
                    Value::String(source.as_str().to_string()));

                events.push(EventKind::NodeCreated {
                    node_id: incident_id.clone(),
                    type_id: crate::nodes::INCIDENT.to_string(),
                    properties: incident_props,
                });

                // Link incident to affected resource (only if it exists)
                if graph.node(source).is_some() {
                    events.push(EventKind::EdgeCreated {
                        edge_id: hydra_core::id::EdgeId::new(),
                        source: incident_id.clone(),
                        target: source.clone(),
                        type_id: crate::nodes::INCIDENT_INVOLVES.to_string(),
                        properties: HashMap::from([
                            ("confidence".to_string(), Value::Float(1.0)),
                        ]),
                    });
                }

                // Generate recovery plan
                if let Some(plan) = recovery_plan(graph, source) {
                    let mut plan_summary = Vec::new();
                    let mut restorable_count = 0;
                    let mut manual_count = 0;

                    for step in &plan.steps {
                        match &step.action {
                            RecoveryAction::RestoreFromBackup => {
                                restorable_count += 1;
                                plan_summary.push(format!(
                                    "Restore {}", step.node_id.as_str()
                                ));
                            }
                            RecoveryAction::Rebuild => {
                                plan_summary.push(format!(
                                    "Rebuild {}", step.node_id.as_str()
                                ));
                            }
                            RecoveryAction::ManualIntervention => {
                                manual_count += 1;
                                plan_summary.push(format!(
                                    "MANUAL: {}", step.node_id.as_str()
                                ));
                            }
                            RecoveryAction::NoAction => {}
                        }
                    }

                    // Create recovery plan node
                    let plan_id = NodeId::from_str(
                        &format!("recovery_{}_{}", source.as_str(), unique_suffix)
                    );

                    let mut plan_props = HashMap::new();
                    plan_props.insert("name".to_string(),
                        Value::String(format!("Recovery plan for incident {}", incident_id.as_str())));
                    plan_props.insert("total_steps".to_string(),
                        Value::Int(plan.steps.len() as i64));
                    plan_props.insert("restorable".to_string(),
                        Value::Int(restorable_count));
                    plan_props.insert("manual_required".to_string(),
                        Value::Int(manual_count));
                    plan_props.insert("has_cycles".to_string(),
                        Value::Bool(plan.has_cycles));
                    plan_props.insert("summary".to_string(),
                        Value::String(plan_summary.join("; ")));

                    events.push(EventKind::NodeCreated {
                        node_id: plan_id.clone(),
                        type_id: crate::nodes::RECOVERY_PLAN.to_string(),
                        properties: plan_props,
                    });

                    // Signal readiness
                    events.push(EventKind::Signal {
                        source: source.clone(),
                        name: "recovery_ready".to_string(),
                        payload: HashMap::from([
                            ("incident_id".to_string(), Value::String(incident_id.as_str().to_string())),
                            ("plan_id".to_string(), Value::String(plan_id.as_str().to_string())),
                            ("total_steps".to_string(), Value::Int(plan.steps.len() as i64)),
                            ("manual_required".to_string(), Value::Int(manual_count)),
                        ]),
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
    use crate::nodes::aws::*;
    use crate::edges;

    #[test]
    fn response_arm_creates_incident_and_plan() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "response_arm",
            EventFilter::SignalName("threat_alert".to_string()),
            70,
            Box::new(ResponseArm::new()),
        ));

        // Build infrastructure
        let (db, ev) = RdsBuilder::new("db-prod").business_criticality(9).build();
        hydra.ingest(ev).unwrap();
        let (api, ev) = Ec2Builder::new("i-api").business_criticality(7).build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::depends_on(api.clone(), db.clone(), "database", 1.0);
        hydra.ingest(ev).unwrap();

        // Trigger threat alert
        hydra.ingest(EventKind::Signal {
            source: db.clone(),
            name: "threat_alert".to_string(),
            payload: HashMap::from([
                ("severity".to_string(), Value::String("High".into())),
                ("blast_scope".to_string(), Value::Int(3)),
            ]),
        }).unwrap();

        // Incident should exist
        let incidents = hydra.graph().nodes_by_type(crate::nodes::INCIDENT);
        assert_eq!(incidents.len(), 1, "Should create one incident");
        assert_eq!(incidents[0].get_str("severity"), Some("High"));

        // Recovery plan should exist
        let plans = hydra.graph().nodes_by_type(crate::nodes::RECOVERY_PLAN);
        assert_eq!(plans.len(), 1, "Should create one recovery plan");
        let plan = &plans[0];
        assert!(plan.get_i64("total_steps").unwrap_or(0) > 0);
    }

    #[test]
    fn response_arm_handles_no_recovery_path() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "response_arm",
            EventFilter::SignalName("threat_alert".to_string()),
            70,
            Box::new(ResponseArm::new()),
        ));

        // Trigger for nonexistent resource
        let _result = hydra.ingest(EventKind::Signal {
            source: NodeId::from_str("nonexistent"),
            name: "threat_alert".to_string(),
            payload: HashMap::from([
                ("severity".to_string(), Value::String("Low".into())),
            ]),
        }).unwrap();

        // Should still create the incident
        let incidents = hydra.graph().nodes_by_type(crate::nodes::INCIDENT);
        assert_eq!(incidents.len(), 1);
        // But no recovery plan (no node to plan for)
        let plans = hydra.graph().nodes_by_type(crate::nodes::RECOVERY_PLAN);
        assert_eq!(plans.len(), 0);
    }
}
