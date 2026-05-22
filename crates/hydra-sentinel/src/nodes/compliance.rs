use hydra_core::event::Value;
use hydra_core::id::NodeId;
use std::collections::HashMap;
use chrono::{Utc};

use super::{prop, create_node};
use super::*;
use hydra_core::event::EventKind;

// ============================================================================
// Regulation — a compliance framework (HIPAA, SOC2, GDPR, PCI-DSS, etc.)
// ============================================================================

pub struct RegulationBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl RegulationBuilder {
    pub fn new(framework: &str) -> Self {
        let node_id = NodeId::new();
        let now = Utc::now();
        let mut props = HashMap::new();
        props.insert(prop::NAME.into(), Value::String(framework.into()));
        props.insert("framework".into(), Value::String(framework.into()));
        props.insert(prop::DISCOVERED_AT.into(), Value::Timestamp(now));
        // Requirements — what the regulation demands
        props.insert("min_backup_frequency_hours".into(), Value::Int(24));
        props.insert("min_retention_days".into(), Value::Int(90));
        props.insert("encryption_required".into(), Value::Bool(true));
        props.insert("replication_required".into(), Value::Bool(false));
        props.insert("verification_required".into(), Value::Bool(false));
        props.insert("audit_trail_required".into(), Value::Bool(true));
        // Scope — which data sensitivity levels this applies to
        props.insert("applies_to_sensitivity".into(), Value::String("high".into()));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn min_backup_frequency_hours(mut self, h: i64) -> Self { self.props.insert("min_backup_frequency_hours".into(), Value::Int(h)); self }
    pub fn min_retention_days(mut self, d: i64) -> Self { self.props.insert("min_retention_days".into(), Value::Int(d)); self }
    pub fn encryption_required(mut self, v: bool) -> Self { self.props.insert("encryption_required".into(), Value::Bool(v)); self }
    pub fn replication_required(mut self, v: bool) -> Self { self.props.insert("replication_required".into(), Value::Bool(v)); self }
    pub fn verification_required(mut self, v: bool) -> Self { self.props.insert("verification_required".into(), Value::Bool(v)); self }
    pub fn applies_to(mut self, s: &str) -> Self { self.props.insert("applies_to_sensitivity".into(), Value::String(s.into())); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, REGULATION, self.props))
    }
}

// ============================================================================
// Compliance Status — the compliance state of an asset against a regulation
// ============================================================================

pub struct ComplianceStatusBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl ComplianceStatusBuilder {
    pub fn new(regulation_name: &str) -> Self {
        let node_id = NodeId::new();
        let now = Utc::now();
        let mut props = HashMap::new();
        props.insert("regulation".into(), Value::String(regulation_name.into()));
        props.insert("evaluated_at".into(), Value::Timestamp(now));
        props.insert("compliant".into(), Value::Bool(false));
        props.insert("compliance_score".into(), Value::Float(0.0));
        // Per-requirement checks
        props.insert("frequency_met".into(), Value::Bool(false));
        props.insert("retention_met".into(), Value::Bool(false));
        props.insert("encryption_met".into(), Value::Bool(false));
        props.insert("replication_met".into(), Value::Bool(false));
        props.insert("verification_met".into(), Value::Bool(false));
        props.insert("audit_trail_met".into(), Value::Bool(true)); // Hydra provides this by default
        // Gap details
        props.insert("gap_count".into(), Value::Int(0));
        props.insert("gap_summary".into(), Value::Null);
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn compliant(mut self, v: bool) -> Self { self.props.insert("compliant".into(), Value::Bool(v)); self }
    pub fn compliance_score(mut self, s: f64) -> Self { self.props.insert("compliance_score".into(), Value::Float(s)); self }
    pub fn frequency_met(mut self, v: bool) -> Self { self.props.insert("frequency_met".into(), Value::Bool(v)); self }
    pub fn retention_met(mut self, v: bool) -> Self { self.props.insert("retention_met".into(), Value::Bool(v)); self }
    pub fn encryption_met(mut self, v: bool) -> Self { self.props.insert("encryption_met".into(), Value::Bool(v)); self }
    pub fn replication_met(mut self, v: bool) -> Self { self.props.insert("replication_met".into(), Value::Bool(v)); self }
    pub fn verification_met(mut self, v: bool) -> Self { self.props.insert("verification_met".into(), Value::Bool(v)); self }
    pub fn gap_count(mut self, c: i64) -> Self { self.props.insert("gap_count".into(), Value::Int(c)); self }
    pub fn gap_summary(mut self, s: &str) -> Self { self.props.insert("gap_summary".into(), Value::String(s.into())); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, COMPLIANCE_STATUS, self.props))
    }
}
