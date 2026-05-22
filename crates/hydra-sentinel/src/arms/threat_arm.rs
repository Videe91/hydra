//! # Threat Arm
//!
//! Responds to anomaly detection by running threat assessment.
//!
//! Fires on: Signal("anomaly_detected")
//!
//! Reads: blast_radius query via anomaly_bridge::assess_threats
//! Emits: Signal("trust_penalty") for trust degradation,
//!        Signal("threat_alert") for downstream consumers (API, alerts)

use hydra_core::event::{Event, EventKind, Value};
use hydra_core::graph::GraphReader;
use hydra_core::subscription::SubscriptionHandler;

use hydra_engine::anomaly::Anomaly;
use crate::queries::anomaly_bridge::{assess_threats, trust_adjustment_events};

/// Threat Arm — responds to anomalies with threat assessment.
pub struct ThreatArm;

impl ThreatArm {
    pub fn new() -> Self {
        Self
    }
}

impl SubscriptionHandler for ThreatArm {
    fn handle(
        &self,
        event: &Event,
        graph: &dyn GraphReader,
    ) -> Vec<EventKind> {
        let mut events = Vec::new();

        match &event.kind {
            EventKind::Signal { source, name, payload } if name == "anomaly_detected" => {
                // Reconstruct a minimal Anomaly from the signal payload
                let description = payload.get("description")
                    .and_then(|v| match v { Value::String(s) => Some(s.as_str()), _ => None })
                    .unwrap_or("unknown anomaly")
                    .to_string();

                let severity = payload.get("severity")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.5);

                let anomaly = Anomaly {
                    kind: hydra_engine::anomaly::AnomalyKind::CascadeAmplification {
                        cascade_event_count: 1,
                        cascade_depth: 1,
                        normal_max_count: 0,
                        normal_max_depth: 0,
                    },
                    description,
                    severity,
                    affected_nodes: vec![source.clone()],
                    trigger_event: Some(event.id.clone()),
                    detected_at: chrono::Utc::now(),
                };

                // Run threat assessment
                let assessment = assess_threats(graph, &[anomaly]);

                // Emit trust penalties
                events.extend(trust_adjustment_events(&assessment.trust_adjustments));

                // Emit threat alert for downstream consumers
                let mut alert_payload = std::collections::HashMap::new();
                alert_payload.insert("severity".to_string(),
                    Value::String(format!("{:?}", assessment.severity)));
                alert_payload.insert("blast_scope".to_string(),
                    Value::Int(assessment.total_blast_scope as i64));
                alert_payload.insert("risk_score".to_string(),
                    Value::Float(assessment.max_risk_score));
                alert_payload.insert("affected_count".to_string(),
                    Value::Int(assessment.affected_nodes.len() as i64));

                events.push(EventKind::Signal {
                    source: source.clone(),
                    name: "threat_alert".to_string(),
                    payload: alert_payload,
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
    use crate::edges;

    #[test]
    fn threat_arm_responds_to_anomaly_signal() {
        let mut hydra = Hydra::new();

        let (db, ev) = RdsBuilder::new("db-prod").business_criticality(9).build();
        hydra.ingest(ev).unwrap();
        let (api, ev) = Ec2Builder::new("i-api").business_criticality(7).build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = edges::depends_on(api.clone(), db.clone(), "database", 1.0);
        hydra.ingest(ev).unwrap();

        // Register ThreatArm
        let arm = ThreatArm::new();
        let sub = Subscription::new(
            "threat_arm",
            EventFilter::SignalName("anomaly_detected".to_string()),
            80,
            Box::new(arm),
        );
        hydra.register(sub);

        // Simulate anomaly detection
        let mut payload = std::collections::HashMap::new();
        payload.insert("description".to_string(),
            Value::String("unusual deletion pattern".into()));
        payload.insert("severity".to_string(), Value::Float(0.9));

        let result = hydra.ingest(EventKind::Signal {
            source: db.clone(),
            name: "anomaly_detected".to_string(),
            payload,
        }).unwrap();

        // Should emit trust_penalty + threat_alert signals
        assert!(result.events.len() >= 3,
            "Should emit at least: anomaly_detected + trust_penalty + threat_alert. Got {}",
            result.events.len());
    }

    #[test]
    fn threat_arm_ignores_non_anomaly_signals() {
        let mut hydra = Hydra::new();

        let (ec2, ev) = Ec2Builder::new("i-001").build();
        hydra.ingest(ev).unwrap();

        let arm = ThreatArm::new();
        let sub = Subscription::new(
            "threat_arm",
            EventFilter::SignalName("anomaly_detected".to_string()),
            80,
            Box::new(arm),
        );
        hydra.register(sub);

        // Send a non-anomaly signal — arm should ignore it
        let result = hydra.ingest(EventKind::Signal {
            source: ec2.clone(),
            name: "something_else".to_string(),
            payload: std::collections::HashMap::new(),
        }).unwrap();

        assert_eq!(result.events.len(), 1, "ThreatArm should not fire on non-anomaly signals");
    }

    #[test]
    fn full_loop_anomaly_to_trust_to_compliance() {
        // This test verifies the complete feedback loop:
        // anomaly_detected → ThreatArm → trust_penalty → TrustArm → trust updated
        let mut hydra = Hydra::new();

        let (db, ev) = RdsBuilder::new("db-prod").business_criticality(9).build();
        hydra.ingest(ev).unwrap();

        // Register both Arms
        use crate::arms::trust_arm::TrustArm;

        let threat_arm = ThreatArm::new();
        let trust_arm = TrustArm::new();

        hydra.register(Subscription::new(
            "threat_arm",
            EventFilter::SignalName("anomaly_detected".to_string()),
            80,
            Box::new(threat_arm),
        ));
        hydra.register(Subscription::new(
            "trust_arm",
            EventFilter::SignalName("trust_penalty".to_string()),
            100,
            Box::new(trust_arm),
        ));

        // Fire anomaly
        let mut payload = std::collections::HashMap::new();
        payload.insert("description".to_string(),
            Value::String("bulk deletion detected".into()));
        payload.insert("severity".to_string(), Value::Float(0.9));

        let result = hydra.ingest(EventKind::Signal {
            source: db.clone(),
            name: "anomaly_detected".to_string(),
            payload,
        }).unwrap();

        // The cascade should be:
        // 1. anomaly_detected (trigger)
        // 2. ThreatArm fires → trust_penalty + threat_alert
        // 3. TrustArm fires on trust_penalty → NodeUpdated (trust scores)
        assert!(result.events.len() >= 4,
            "Full loop should produce multiple cascade events. Got {}", result.events.len());

        // Verify trust was actually degraded
        let node = hydra.graph().node(&db).unwrap();
        let anomaly_free = node.get_f64(crate::nodes::prop::TRUST_ANOMALY_FREE).unwrap_or(1.0);
        assert!(anomaly_free < 1.0,
            "Trust anomaly_free should be degraded. Got {}", anomaly_free);
    }
}
