use hydra_core::event::Value;
use hydra_core::id::NodeId;
use std::collections::HashMap;
use chrono::{Utc};

use super::{prop, create_node};
use super::*;
use hydra_core::event::EventKind;

// ============================================================================
// Backup Snapshot — a point-in-time backup of a resource
// ============================================================================

pub struct BackupSnapshotBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl BackupSnapshotBuilder {
    pub fn new(snapshot_id: &str) -> Self {
        let node_id = NodeId::new();
        let now = Utc::now();
        let mut props = HashMap::new();
        props.insert(prop::CLOUD_ID.into(), Value::String(snapshot_id.into()));
        props.insert(prop::STATUS.into(), Value::String("completed".into()));
        props.insert(prop::DISCOVERED_AT.into(), Value::Timestamp(now));
        props.insert("created_at_cloud".into(), Value::Timestamp(now));
        props.insert("size_bytes".into(), Value::Int(0));
        props.insert("snapshot_type".into(), Value::String("full".into()));
        props.insert("encrypted".into(), Value::Bool(false));
        props.insert("storage_tier".into(), Value::String("standard".into()));
        // Verification status — feeds Layer 3 (anomaly on unverified backups)
        props.insert("verified".into(), Value::Bool(false));
        props.insert("verified_at".into(), Value::Null);
        props.insert("verification_method".into(), Value::Null);
        props.insert("restorable".into(), Value::Null); // null = unknown
        // Integrity
        props.insert("checksum".into(), Value::Null);
        props.insert("corruption_detected".into(), Value::Bool(false));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn arn(mut self, arn: &str) -> Self { self.props.insert(prop::ARN.into(), Value::String(arn.into())); self }
    pub fn region(mut self, r: &str) -> Self { self.props.insert(prop::REGION.into(), Value::String(r.into())); self }
    pub fn size_bytes(mut self, s: i64) -> Self { self.props.insert("size_bytes".into(), Value::Int(s)); self }
    pub fn snapshot_type(mut self, t: &str) -> Self { self.props.insert("snapshot_type".into(), Value::String(t.into())); self }
    pub fn encrypted(mut self, v: bool) -> Self { self.props.insert("encrypted".into(), Value::Bool(v)); self }
    pub fn storage_tier(mut self, t: &str) -> Self { self.props.insert("storage_tier".into(), Value::String(t.into())); self }
    pub fn status(mut self, s: &str) -> Self { self.props.insert(prop::STATUS.into(), Value::String(s.into())); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, BACKUP_SNAPSHOT, self.props))
    }
}

// ============================================================================
// Protection Policy — defines how a resource should be protected
// ============================================================================

pub struct ProtectionPolicyBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl ProtectionPolicyBuilder {
    pub fn new(policy_name: &str) -> Self {
        let node_id = NodeId::new();
        let now = Utc::now();
        let mut props = HashMap::new();
        props.insert(prop::NAME.into(), Value::String(policy_name.into()));
        props.insert(prop::STATUS.into(), Value::String("active".into()));
        props.insert(prop::DISCOVERED_AT.into(), Value::Timestamp(now));
        // Policy parameters — changes here trigger the entire protection cascade
        props.insert(prop::BACKUP_FREQUENCY_HOURS.into(), Value::Int(24));
        props.insert(prop::RETENTION_DAYS.into(), Value::Int(30));
        props.insert(prop::REPLICATION_TARGETS.into(), Value::Int(0));
        props.insert("verification_enabled".into(), Value::Bool(false));
        props.insert("verification_frequency_hours".into(), Value::Int(168)); // weekly
        // Classification-driven (set by Classification Arm)
        props.insert("target_data_sensitivity".into(), Value::String("any".into()));
        props.insert("target_environment".into(), Value::String("any".into()));
        props.insert("target_criticality_min".into(), Value::Int(0));
        // Cost tracking
        props.insert(prop::MONTHLY_COST_CENTS.into(), Value::Int(0));
        props.insert("assets_covered".into(), Value::Int(0));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn frequency_hours(mut self, h: i64) -> Self { self.props.insert(prop::BACKUP_FREQUENCY_HOURS.into(), Value::Int(h)); self }
    pub fn retention_days(mut self, d: i64) -> Self { self.props.insert(prop::RETENTION_DAYS.into(), Value::Int(d)); self }
    pub fn replication_targets(mut self, n: i64) -> Self { self.props.insert(prop::REPLICATION_TARGETS.into(), Value::Int(n)); self }
    pub fn verification_enabled(mut self, v: bool) -> Self { self.props.insert("verification_enabled".into(), Value::Bool(v)); self }
    pub fn target_sensitivity(mut self, s: &str) -> Self { self.props.insert("target_data_sensitivity".into(), Value::String(s.into())); self }
    pub fn target_environment(mut self, e: &str) -> Self { self.props.insert("target_environment".into(), Value::String(e.into())); self }
    pub fn target_criticality_min(mut self, c: i64) -> Self { self.props.insert("target_criticality_min".into(), Value::Int(c)); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, PROTECTION_POLICY, self.props))
    }
}

// ============================================================================
// Verification Result — proof that a backup is restorable
// ============================================================================

pub struct VerificationResultBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl VerificationResultBuilder {
    pub fn new() -> Self {
        let node_id = NodeId::new();
        let now = Utc::now();
        let mut props = HashMap::new();
        props.insert("verified_at".into(), Value::Timestamp(now));
        props.insert("method".into(), Value::String("restore_test".into()));
        props.insert("passed".into(), Value::Bool(false));
        props.insert("duration_secs".into(), Value::Int(0));
        // Granular results — each is a sub-check
        props.insert("restore_completed".into(), Value::Bool(false));
        props.insert("data_integrity_ok".into(), Value::Bool(false));
        props.insert("service_responds".into(), Value::Bool(false));
        props.insert("dependency_chain_ok".into(), Value::Bool(false));
        // Failure details (if any)
        props.insert("failure_reason".into(), Value::Null);
        props.insert("failure_stage".into(), Value::Null);
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn method(mut self, m: &str) -> Self { self.props.insert("method".into(), Value::String(m.into())); self }
    pub fn passed(mut self, v: bool) -> Self { self.props.insert("passed".into(), Value::Bool(v)); self }
    pub fn duration_secs(mut self, s: i64) -> Self { self.props.insert("duration_secs".into(), Value::Int(s)); self }
    pub fn restore_completed(mut self, v: bool) -> Self { self.props.insert("restore_completed".into(), Value::Bool(v)); self }
    pub fn data_integrity_ok(mut self, v: bool) -> Self { self.props.insert("data_integrity_ok".into(), Value::Bool(v)); self }
    pub fn service_responds(mut self, v: bool) -> Self { self.props.insert("service_responds".into(), Value::Bool(v)); self }
    pub fn dependency_chain_ok(mut self, v: bool) -> Self { self.props.insert("dependency_chain_ok".into(), Value::Bool(v)); self }
    pub fn failure_reason(mut self, r: &str) -> Self { self.props.insert("failure_reason".into(), Value::String(r.into())); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, VERIFICATION_RESULT, self.props))
    }
}
