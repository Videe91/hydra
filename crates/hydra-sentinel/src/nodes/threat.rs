use hydra_core::event::Value;
use hydra_core::id::NodeId;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

use super::{create_node};
use super::*;
use hydra_core::event::EventKind;

// ============================================================================
// Anomaly Record — a detected anomaly persisted as a graph node
// ============================================================================
//
// Why a node, not just an Anomaly struct? Because:
// - Edges connect it to affected resources (DETECTED_ON edges)
// - Temporal engine tracks anomaly_status over time (open → investigating → resolved)
// - Other anomalies can be linked (caused_by edges for cascading anomalies)
// - Coverage engine can check "every critical asset should have 0 open anomalies"

pub struct AnomalyRecordBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl AnomalyRecordBuilder {
    pub fn new(anomaly_type: &str, description: &str) -> Self {
        let node_id = NodeId::new();
        let now = Utc::now();
        let mut props = HashMap::new();
        props.insert("anomaly_type".into(), Value::String(anomaly_type.into()));
        props.insert("description".into(), Value::String(description.into()));
        props.insert("detected_at".into(), Value::Timestamp(now));
        props.insert("severity".into(), Value::Float(0.5));
        props.insert("anomaly_status".into(), Value::String("open".into()));
        props.insert("resolved_at".into(), Value::Null);
        props.insert("resolution".into(), Value::Null);
        // For causal tracing — which event triggered this anomaly
        props.insert("trigger_event_id".into(), Value::Null);
        // For counterfactual analysis — how much of the graph would differ without this
        props.insert("impact_score".into(), Value::Float(0.0));
        props.insert("affected_node_count".into(), Value::Int(0));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn severity(mut self, s: f64) -> Self { self.props.insert("severity".into(), Value::Float(s)); self }
    pub fn trigger_event(mut self, id: &str) -> Self { self.props.insert("trigger_event_id".into(), Value::String(id.into())); self }
    pub fn impact_score(mut self, s: f64) -> Self { self.props.insert("impact_score".into(), Value::Float(s)); self }
    pub fn affected_count(mut self, c: i64) -> Self { self.props.insert("affected_node_count".into(), Value::Int(c)); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, ANOMALY_RECORD, self.props))
    }
}

// ============================================================================
// Incident — a confirmed security or operational event requiring response
// ============================================================================

pub struct IncidentBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl IncidentBuilder {
    pub fn new(incident_type: &str, title: &str) -> Self {
        let node_id = NodeId::new();
        let now = Utc::now();
        let mut props = HashMap::new();
        props.insert("incident_type".into(), Value::String(incident_type.into()));
        props.insert("title".into(), Value::String(title.into()));
        props.insert("detected_at".into(), Value::Timestamp(now));
        props.insert("incident_status".into(), Value::String("detected".into()));
        props.insert("severity".into(), Value::String("medium".into()));
        props.insert("resolved_at".into(), Value::Null);
        props.insert("resolution_method".into(), Value::Null);
        // Infection timeline (for ransomware — when did it start?)
        props.insert("estimated_start_at".into(), Value::Null);
        props.insert("confirmed_clean_before".into(), Value::Null);
        // Response metrics
        props.insert("time_to_detect_secs".into(), Value::Null);
        props.insert("time_to_respond_secs".into(), Value::Null);
        props.insert("time_to_recover_secs".into(), Value::Null);
        // Blast radius snapshot
        props.insert("blast_radius_nodes".into(), Value::Int(0));
        props.insert("blast_radius_critical".into(), Value::Int(0));
        props.insert("estimated_data_at_risk_bytes".into(), Value::Int(0));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn severity(mut self, s: &str) -> Self { self.props.insert("severity".into(), Value::String(s.into())); self }
    pub fn estimated_start(mut self, t: DateTime<Utc>) -> Self { self.props.insert("estimated_start_at".into(), Value::Timestamp(t)); self }
    pub fn confirmed_clean_before(mut self, t: DateTime<Utc>) -> Self { self.props.insert("confirmed_clean_before".into(), Value::Timestamp(t)); self }
    pub fn blast_radius(mut self, nodes: i64, critical: i64) -> Self {
        self.props.insert("blast_radius_nodes".into(), Value::Int(nodes));
        self.props.insert("blast_radius_critical".into(), Value::Int(critical));
        self
    }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, INCIDENT, self.props))
    }
}

// ============================================================================
// Blast Radius — a snapshot of what's affected by a compromised resource
// ============================================================================

pub struct BlastRadiusBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl BlastRadiusBuilder {
    pub fn new(source_node_id: &NodeId) -> Self {
        let node_id = NodeId::new();
        let now = Utc::now();
        let mut props = HashMap::new();
        props.insert("source_node".into(), Value::String(source_node_id.as_str().to_string()));
        props.insert("computed_at".into(), Value::Timestamp(now));
        props.insert("total_affected".into(), Value::Int(0));
        props.insert("directly_affected".into(), Value::Int(0));
        props.insert("transitively_affected".into(), Value::Int(0));
        props.insert("critical_affected".into(), Value::Int(0));
        props.insert("unprotected_affected".into(), Value::Int(0));
        props.insert("estimated_recovery_hours".into(), Value::Float(0.0));
        props.insert("estimated_data_at_risk_bytes".into(), Value::Int(0));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn total_affected(mut self, n: i64) -> Self { self.props.insert("total_affected".into(), Value::Int(n)); self }
    pub fn directly_affected(mut self, n: i64) -> Self { self.props.insert("directly_affected".into(), Value::Int(n)); self }
    pub fn transitively_affected(mut self, n: i64) -> Self { self.props.insert("transitively_affected".into(), Value::Int(n)); self }
    pub fn critical_affected(mut self, n: i64) -> Self { self.props.insert("critical_affected".into(), Value::Int(n)); self }
    pub fn unprotected_affected(mut self, n: i64) -> Self { self.props.insert("unprotected_affected".into(), Value::Int(n)); self }
    pub fn recovery_hours(mut self, h: f64) -> Self { self.props.insert("estimated_recovery_hours".into(), Value::Float(h)); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, BLAST_RADIUS, self.props))
    }
}
