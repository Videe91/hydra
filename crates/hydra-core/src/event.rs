use crate::action::{Action, Outcome};
use crate::epistemic::{Claim, Evidence};
use crate::id::{
    ActionId, ActorId, ApprovalId, CascadeId, ClaimId, EdgeId, EventId, EvidenceId, MicroModelId,
    NodeId, PolicyId, ReplicaId, ReplicationRunId, SchemaId, SensorCheckpointId, SensorRunId,
    TenantId,
};
use crate::micromodel::{MicroModelDefinition, MicroModelObservation, MicroModelPrediction, MicroModelStatus};
use crate::policy::{ApprovalRequest, Policy, PolicyDecision};
use crate::replication::{
    ReplicationLag, ReplicationOffset, ReplicationPeer, ReplicationPeerStatus, ReplicationRun,
};
use crate::schema::SchemaDefinition;
use crate::sensor::{SensorCheckpoint, SensorRun};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A property value in the graph. Strongly typed to prevent ambiguity.
/// Every value knows its type — no stringly-typed confusion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Timestamp(DateTime<Utc>),
    List(Vec<Value>),
    Map(HashMap<String, Value>),
    Null,
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(n) => Some(*n),
            Value::Int(n) => Some(*n as f64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_timestamp(&self) -> Option<DateTime<Utc>> {
        match self {
            Value::Timestamp(t) => Some(*t),
            _ => None,
        }
    }
}

/// What happened. Every possible mutation to the graph is an EventKind.
/// No mutation happens outside of this enum — the event log is the ONLY truth.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EventKind {
    // Node lifecycle
    NodeCreated {
        node_id: NodeId,
        type_id: String,
        properties: HashMap<String, Value>,
    },
    NodeUpdated {
        node_id: NodeId,
        changes: HashMap<String, Value>,
    },
    NodeDeleted {
        node_id: NodeId,
    },

    // Edge lifecycle
    EdgeCreated {
        edge_id: EdgeId,
        source: NodeId,
        target: NodeId,
        type_id: String,
        properties: HashMap<String, Value>,
    },
    EdgeUpdated {
        edge_id: EdgeId,
        changes: HashMap<String, Value>,
    },
    EdgeDeleted {
        edge_id: EdgeId,
    },

    // Signals — domain-level notifications that trigger subscriptions
    Signal {
        name: String,
        source: NodeId,
        payload: HashMap<String, Value>,
    },

    // Snapshots — point-in-time captures for compaction
    Snapshot {
        node_id: NodeId,
        state: HashMap<String, Value>,
        edge_count: u32,
    },

    // Epistemic lifecycle — observations become evidence, evidence supports claims,
    // verified claims may become operational topology.
    EvidenceAdded {
        evidence: Evidence,
    },
    ClaimProposed {
        claim: Claim,
    },
    ClaimSupported {
        claim_id: ClaimId,
        evidence_id: EvidenceId,
    },
    ClaimDisputed {
        claim_id: ClaimId,
        evidence_id: EvidenceId,
        reason: Option<String>,
    },
    ClaimVerified {
        claim_id: ClaimId,
        verified_by: ActorId,
    },
    ClaimRetracted {
        claim_id: ClaimId,
        retracted_by: ActorId,
        reason: String,
    },
    ClaimStaled {
        claim_id: ClaimId,
        reason: Option<String>,
    },
    TopologyCommittedFromClaim {
        claim_id: ClaimId,
        node_id: Option<NodeId>,
        edge_id: Option<EdgeId>,
    },

    // Agentic action lifecycle — actions are explicit, auditable interventions.
    ActionProposed {
        action: Action,
    },
    ActionApproved {
        action_id: ActionId,
        approved_by: ActorId,
        /// Operator-supplied rationale for the approval. Patch 6
        /// (operator approval workflow) added this field with
        /// `#[serde(default)]` so events written before Patch 6
        /// deserialize as `None`. Stored in the audit log; not yet
        /// surfaced on `Action.payload` — that's a future enhancement.
        #[serde(default)]
        reason: Option<String>,
    },
    ActionRejected {
        action_id: ActionId,
        rejected_by: ActorId,
        reason: String,
    },
    ActionExecuting {
        action_id: ActionId,
    },
    ActionExecuted {
        action_id: ActionId,
    },
    ActionFailed {
        action_id: ActionId,
        reason: String,
    },
    ActionCancelled {
        action_id: ActionId,
        cancelled_by: ActorId,
        reason: Option<String>,
    },
    OutcomeObserved {
        outcome: Outcome,
    },

    // Policy / approval lifecycle — policies govern whether actions can proceed.
    PolicyRegistered {
        policy: Policy,
    },
    PolicyDisabled {
        policy_id: PolicyId,
        disabled_by: ActorId,
        reason: Option<String>,
    },
    PolicyDecisionRecorded {
        decision: PolicyDecision,
    },
    ApprovalRequested {
        request: ApprovalRequest,
    },
    ApprovalGranted {
        approval_id: ApprovalId,
        approved_by: ActorId,
    },
    ApprovalRejected {
        approval_id: ApprovalId,
        rejected_by: ActorId,
        reason: String,
    },
    ApprovalCancelled {
        approval_id: ApprovalId,
        cancelled_by: ActorId,
        reason: Option<String>,
    },

    // Sensor ingestion lifecycle — reliable external observation checkpoints.
    SensorRunStarted {
        run: SensorRun,
    },
    SensorRunCompleted {
        run_id: SensorRunId,
    },
    SensorRunFailed {
        run_id: SensorRunId,
        error: String,
    },
    SensorCheckpointRecorded {
        checkpoint: SensorCheckpoint,
    },
    SensorCheckpointSuperseded {
        checkpoint_id: SensorCheckpointId,
        superseded_by: Option<SensorCheckpointId>,
        reason: Option<String>,
    },

    // Schema/type registry lifecycle — database validation vocabulary.
    SchemaRegistered {
        schema: SchemaDefinition,
    },
    SchemaDisabled {
        schema_id: SchemaId,
        disabled_by: ActorId,
        reason: Option<String>,
    },
    SchemaArchived {
        schema_id: SchemaId,
        archived_by: ActorId,
        reason: Option<String>,
    },

    // Snapshots — point-in-time captures of the full runtime state
    SnapshotTaken {
        manifest: crate::snapshot::SnapshotManifest,
    },
    SnapshotRestored {
        manifest: crate::snapshot::SnapshotManifest,
        replayed_commit_count: usize,
    },

    // Replication lifecycle (V2 patch 1 — vocabulary only; no engine
    // behavior, no network, no workers). Variants are durable so the
    // event log can record replication topology changes once later
    // patches start emitting them.
    ReplicaRegistered {
        peer: ReplicationPeer,
    },
    ReplicaHeartbeatRecorded {
        peer_id: ReplicaId,
        offset: ReplicationOffset,
        lag: Option<ReplicationLag>,
    },
    ReplicationRunStarted {
        run: ReplicationRun,
    },
    ReplicationRunCompleted {
        run_id: ReplicationRunId,
        completed_offset: ReplicationOffset,
    },
    ReplicationRunFailed {
        run_id: ReplicationRunId,
        error: String,
    },
    ReplicaStatusChanged {
        peer_id: ReplicaId,
        status: ReplicationPeerStatus,
        reason: Option<String>,
    },
    ReplicaPromoted {
        peer_id: ReplicaId,
        promoted_by: ActorId,
        reason: Option<String>,
    },
    ReplicaDemoted {
        peer_id: ReplicaId,
        demoted_by: ActorId,
        reason: Option<String>,
    },

    // MicroModel lifecycle (Patch 1 — vocabulary + registry only).
    // Control-plane events: do not touch the graph projection. Routed
    // through `Hydra::ingest` so they're durable, auditable, and
    // replicable like every other Hydra event.
    MicroModelRegistered {
        model: MicroModelDefinition,
    },
    MicroModelStatusChanged {
        model_id: MicroModelId,
        status: MicroModelStatus,
        reason: Option<String>,
    },
    MicroModelPredictionRecorded {
        prediction: MicroModelPrediction,
    },
    MicroModelObservationRecorded {
        observation: MicroModelObservation,
    },

    // CausalCell lifecycle (Patch 20 — vocabulary only). One
    // event variant: cells are immutable once created in v0. No
    // composition / closure / link events yet — those land in
    // later patches.
    CausalCellCreated {
        cell: crate::causal_cell::CausalCell,
    },

    // Identity Graph lifecycle (Patch 29 — vocabulary only).
    // One event variant: identity entities are immutable once
    // created in v0. No alias merges / canonical merges / links
    // / deletes yet — those land in later patches (P30+).
    IdentityEntityCreated {
        entity: crate::identity::IdentityEntity,
    },
}

impl EventKind {
    /// The primary node affected by this event (for routing)
    pub fn target_node(&self) -> Option<&NodeId> {
        match self {
            EventKind::NodeCreated { node_id, .. } => Some(node_id),
            EventKind::NodeUpdated { node_id, .. } => Some(node_id),
            EventKind::NodeDeleted { node_id } => Some(node_id),
            EventKind::EdgeCreated { source, .. } => Some(source),
            EventKind::EdgeUpdated { .. } => None,
            EventKind::EdgeDeleted { .. } => None,
            EventKind::Signal { source, .. } => Some(source),
            EventKind::Snapshot { node_id, .. } => Some(node_id),
            EventKind::TopologyCommittedFromClaim {
                node_id: Some(node_id),
                ..
            } => Some(node_id),
            EventKind::EvidenceAdded { .. }
            | EventKind::ClaimProposed { .. }
            | EventKind::ClaimSupported { .. }
            | EventKind::ClaimDisputed { .. }
            | EventKind::ClaimVerified { .. }
            | EventKind::ClaimRetracted { .. }
            | EventKind::ClaimStaled { .. }
            | EventKind::TopologyCommittedFromClaim { node_id: None, .. }
            | EventKind::ActionProposed { .. }
            | EventKind::ActionApproved { .. }
            | EventKind::ActionRejected { .. }
            | EventKind::ActionExecuting { .. }
            | EventKind::ActionExecuted { .. }
            | EventKind::ActionFailed { .. }
            | EventKind::ActionCancelled { .. }
            | EventKind::OutcomeObserved { .. }
            | EventKind::PolicyRegistered { .. }
            | EventKind::PolicyDisabled { .. }
            | EventKind::PolicyDecisionRecorded { .. }
            | EventKind::ApprovalRequested { .. }
            | EventKind::ApprovalGranted { .. }
            | EventKind::ApprovalRejected { .. }
            | EventKind::ApprovalCancelled { .. }
            | EventKind::SensorRunStarted { .. }
            | EventKind::SensorRunCompleted { .. }
            | EventKind::SensorRunFailed { .. }
            | EventKind::SensorCheckpointRecorded { .. }
            | EventKind::SensorCheckpointSuperseded { .. }
            | EventKind::SchemaRegistered { .. }
            | EventKind::SchemaDisabled { .. }
            | EventKind::SchemaArchived { .. }
            | EventKind::SnapshotTaken { .. }
            | EventKind::SnapshotRestored { .. }
            | EventKind::ReplicaRegistered { .. }
            | EventKind::ReplicaHeartbeatRecorded { .. }
            | EventKind::ReplicationRunStarted { .. }
            | EventKind::ReplicationRunCompleted { .. }
            | EventKind::ReplicationRunFailed { .. }
            | EventKind::ReplicaStatusChanged { .. }
            | EventKind::ReplicaPromoted { .. }
            | EventKind::ReplicaDemoted { .. }
            | EventKind::MicroModelRegistered { .. }
            | EventKind::MicroModelStatusChanged { .. }
            | EventKind::MicroModelPredictionRecorded { .. }
            | EventKind::MicroModelObservationRecorded { .. }
            | EventKind::CausalCellCreated { .. }
            | EventKind::IdentityEntityCreated { .. } => None,
        }
    }

    /// Human-readable name for this event kind
    pub fn kind_name(&self) -> &'static str {
        match self {
            EventKind::NodeCreated { .. } => "node_created",
            EventKind::NodeUpdated { .. } => "node_updated",
            EventKind::NodeDeleted { .. } => "node_deleted",
            EventKind::EdgeCreated { .. } => "edge_created",
            EventKind::EdgeUpdated { .. } => "edge_updated",
            EventKind::EdgeDeleted { .. } => "edge_deleted",
            EventKind::Signal { .. } => "signal",
            EventKind::Snapshot { .. } => "snapshot",
            EventKind::EvidenceAdded { .. } => "evidence_added",
            EventKind::ClaimProposed { .. } => "claim_proposed",
            EventKind::ClaimSupported { .. } => "claim_supported",
            EventKind::ClaimDisputed { .. } => "claim_disputed",
            EventKind::ClaimVerified { .. } => "claim_verified",
            EventKind::ClaimRetracted { .. } => "claim_retracted",
            EventKind::ClaimStaled { .. } => "claim_staled",
            EventKind::TopologyCommittedFromClaim { .. } => "topology_committed_from_claim",
            EventKind::ActionProposed { .. } => "action_proposed",
            EventKind::ActionApproved { .. } => "action_approved",
            EventKind::ActionRejected { .. } => "action_rejected",
            EventKind::ActionExecuting { .. } => "action_executing",
            EventKind::ActionExecuted { .. } => "action_executed",
            EventKind::ActionFailed { .. } => "action_failed",
            EventKind::ActionCancelled { .. } => "action_cancelled",
            EventKind::OutcomeObserved { .. } => "outcome_observed",
            EventKind::PolicyRegistered { .. } => "policy_registered",
            EventKind::PolicyDisabled { .. } => "policy_disabled",
            EventKind::PolicyDecisionRecorded { .. } => "policy_decision_recorded",
            EventKind::ApprovalRequested { .. } => "approval_requested",
            EventKind::ApprovalGranted { .. } => "approval_granted",
            EventKind::ApprovalRejected { .. } => "approval_rejected",
            EventKind::ApprovalCancelled { .. } => "approval_cancelled",
            EventKind::SensorRunStarted { .. } => "sensor_run_started",
            EventKind::SensorRunCompleted { .. } => "sensor_run_completed",
            EventKind::SensorRunFailed { .. } => "sensor_run_failed",
            EventKind::SensorCheckpointRecorded { .. } => "sensor_checkpoint_recorded",
            EventKind::SensorCheckpointSuperseded { .. } => "sensor_checkpoint_superseded",
            EventKind::SchemaRegistered { .. } => "schema_registered",
            EventKind::SchemaDisabled { .. } => "schema_disabled",
            EventKind::SchemaArchived { .. } => "schema_archived",
            EventKind::SnapshotTaken { .. } => "snapshot_taken",
            EventKind::SnapshotRestored { .. } => "snapshot_restored",
            EventKind::ReplicaRegistered { .. } => "replica_registered",
            EventKind::ReplicaHeartbeatRecorded { .. } => "replica_heartbeat_recorded",
            EventKind::ReplicationRunStarted { .. } => "replication_run_started",
            EventKind::ReplicationRunCompleted { .. } => "replication_run_completed",
            EventKind::ReplicationRunFailed { .. } => "replication_run_failed",
            EventKind::ReplicaStatusChanged { .. } => "replica_status_changed",
            EventKind::ReplicaPromoted { .. } => "replica_promoted",
            EventKind::ReplicaDemoted { .. } => "replica_demoted",
            EventKind::MicroModelRegistered { .. } => "micro_model_registered",
            EventKind::MicroModelStatusChanged { .. } => "micro_model_status_changed",
            EventKind::MicroModelPredictionRecorded { .. } => "micro_model_prediction_recorded",
            EventKind::MicroModelObservationRecorded { .. } => "micro_model_observation_recorded",
            EventKind::CausalCellCreated { .. } => "causal_cell_created",
            EventKind::IdentityEntityCreated { .. } => "identity_entity_created",
        }
    }
}

/// The core event struct. Every mutation to the graph produces one of these.
///
/// THE KEY INNOVATION: `caused_by` forms a causal DAG.
/// - A trigger event (from a sensor or API) has caused_by = vec![]
/// - A reactive event (from a subscription) has caused_by = vec![parent_event_id]
/// - An event caused by multiple parents has caused_by = vec![parent_a, parent_b]
///
/// This enables:
/// - causal_chain(id): trace forward what an event caused
/// - root_cause(id): trace backward to the original trigger
/// - counterfactual(id): "what if this event hadn't happened?"
/// - impact_score(id): how much did this event change the graph?
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Unique identifier. ULID-based — sortable by creation time.
    pub id: EventId,

    /// When this event occurred
    pub timestamp: DateTime<Utc>,

    /// What happened
    pub kind: EventKind,

    /// Causal parents — which event(s) triggered this one.
    /// Empty for external trigger events (sensor input, API call).
    /// Single parent for most reactive events (subscription fired).
    /// Multiple parents for convergent causation (rare but possible).
    pub caused_by: Vec<EventId>,

    /// Groups all events in one reactive cascade.
    /// Every event in the same cascade shares this ID.
    /// The trigger event creates the cascade_id; all reactions inherit it.
    pub cascade_id: CascadeId,

    /// How deep in the cascade. 0 = trigger, 1 = first reaction, etc.
    /// Used for cycle detection (if depth exceeds max, cascade is killed).
    pub cascade_depth: u32,

    /// Position within the same depth level in the cascade.
    /// When a parent event triggers 3 reactions, they get breadth indices 0, 1, 2.
    /// Combined with cascade_depth, this gives a unique coordinate (depth, breadth)
    /// within the cascade tree. Useful for deterministic ordering and visualization.
    #[serde(default)]
    pub cascade_breadth_index: u32,

    /// Which tenant this event belongs to. None for single-tenant deployments.
    /// The engine carries this field but does not enforce tenant isolation —
    /// that's the product layer's responsibility (Sentinel, etc.).
    /// Reactions inherit the parent's tenant_id.
    #[serde(default)]
    pub tenant_id: Option<TenantId>,
}

impl Event {
    /// Create a new trigger event (external input, no causal parent)
    pub fn trigger(kind: EventKind) -> Self {
        Self {
            id: EventId::new(),
            timestamp: Utc::now(),
            kind,
            caused_by: vec![],
            cascade_id: CascadeId::new(),
            cascade_depth: 0,
            cascade_breadth_index: 0,
            tenant_id: None,
        }
    }

    /// Create a trigger event with a tenant
    pub fn trigger_for_tenant(kind: EventKind, tenant: TenantId) -> Self {
        Self {
            id: EventId::new(),
            timestamp: Utc::now(),
            kind,
            caused_by: vec![],
            cascade_id: CascadeId::new(),
            cascade_depth: 0,
            cascade_breadth_index: 0,
            tenant_id: Some(tenant),
        }
    }

    /// Create a reactive event (caused by a parent event in an existing cascade).
    /// Inherits the parent's tenant_id.
    /// breadth_index defaults to 0 — the cascade engine overrides this when
    /// multiple reactions are produced from the same parent.
    pub fn reaction(kind: EventKind, parent: &Event) -> Self {
        Self {
            id: EventId::new(),
            timestamp: Utc::now(),
            kind,
            caused_by: vec![parent.id.clone()],
            cascade_id: parent.cascade_id.clone(),
            cascade_depth: parent.cascade_depth + 1,
            cascade_breadth_index: 0,
            tenant_id: parent.tenant_id.clone(),
        }
    }

    /// Create a reactive event caused by multiple parents.
    /// Inherits the first parent's tenant_id.
    pub fn convergent_reaction(kind: EventKind, parents: &[&Event]) -> Self {
        assert!(!parents.is_empty(), "convergent reaction needs at least one parent");
        Self {
            id: EventId::new(),
            timestamp: Utc::now(),
            kind,
            caused_by: parents.iter().map(|p| p.id.clone()).collect(),
            cascade_id: parents[0].cascade_id.clone(),
            cascade_depth: parents.iter().map(|p| p.cascade_depth).max().unwrap_or(0) + 1,
            cascade_breadth_index: 0,
            tenant_id: parents[0].tenant_id.clone(),
        }
    }

    /// Is this a trigger event (no causal parent)?
    pub fn is_trigger(&self) -> bool {
        self.caused_by.is_empty()
    }

    /// Is this a reactive event (has causal parent)?
    pub fn is_reaction(&self) -> bool {
        !self.caused_by.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_node_created() -> EventKind {
        EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "ec2_instance".to_string(),
            properties: HashMap::from([
                ("instance_id".to_string(), Value::String("i-1234".to_string())),
                ("state".to_string(), Value::String("running".to_string())),
            ]),
        }
    }

    #[test]
    fn trigger_event_has_no_parent() {
        let evt = Event::trigger(sample_node_created());
        assert!(evt.is_trigger());
        assert!(!evt.is_reaction());
        assert!(evt.caused_by.is_empty());
        assert_eq!(evt.cascade_depth, 0);
    }

    #[test]
    fn reaction_event_links_to_parent() {
        let trigger = Event::trigger(sample_node_created());
        let reaction = Event::reaction(
            EventKind::Signal {
                name: "classify".to_string(),
                source: NodeId::new(),
                payload: HashMap::new(),
            },
            &trigger,
        );

        assert!(reaction.is_reaction());
        assert_eq!(reaction.caused_by.len(), 1);
        assert_eq!(reaction.caused_by[0], trigger.id);
        assert_eq!(reaction.cascade_id, trigger.cascade_id);
        assert_eq!(reaction.cascade_depth, 1);
    }

    #[test]
    fn reaction_chain_increments_depth() {
        let e0 = Event::trigger(sample_node_created());
        let e1 = Event::reaction(sample_node_created(), &e0);
        let e2 = Event::reaction(sample_node_created(), &e1);
        let e3 = Event::reaction(sample_node_created(), &e2);

        assert_eq!(e0.cascade_depth, 0);
        assert_eq!(e1.cascade_depth, 1);
        assert_eq!(e2.cascade_depth, 2);
        assert_eq!(e3.cascade_depth, 3);

        // All share the same cascade_id
        assert_eq!(e1.cascade_id, e0.cascade_id);
        assert_eq!(e2.cascade_id, e0.cascade_id);
        assert_eq!(e3.cascade_id, e0.cascade_id);
    }

    #[test]
    fn convergent_reaction_has_multiple_parents() {
        let trigger_a = Event::trigger(sample_node_created());
        let trigger_b = Event::trigger(sample_node_created());
        // Give trigger_b the same cascade for this test
        let trigger_b_same_cascade = Event {
            cascade_id: trigger_a.cascade_id.clone(),
            ..trigger_b
        };

        let converged = Event::convergent_reaction(
            EventKind::Signal {
                name: "merged".to_string(),
                source: NodeId::new(),
                payload: HashMap::new(),
            },
            &[&trigger_a, &trigger_b_same_cascade],
        );

        assert_eq!(converged.caused_by.len(), 2);
        assert_eq!(converged.cascade_depth, 1); // max(0, 0) + 1
    }

    #[test]
    fn event_kind_target_node() {
        let node_id = NodeId::new();
        let kind = EventKind::NodeCreated {
            node_id: node_id.clone(),
            type_id: "test".to_string(),
            properties: HashMap::new(),
        };
        assert_eq!(kind.target_node(), Some(&node_id));

        let kind = EventKind::EdgeDeleted {
            edge_id: EdgeId::new(),
        };
        assert_eq!(kind.target_node(), None);
    }

    #[test]
    fn event_kind_names_are_snake_case() {
        let kind = EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "t".to_string(),
            properties: HashMap::new(),
        };
        assert_eq!(kind.kind_name(), "node_created");
    }

    #[test]
    fn identity_entity_created_event_kind_name_is_snake_case() {
        // Patch 29 — the new variant must produce a snake_case
        // name like every other EventKind. Pinned so a future
        // refactor doesn't accidentally drift naming.
        use crate::identity::{IdentityEntity, IdentityEntityKind};
        use crate::epistemic::Confidence;
        use chrono::Utc;
        let now = Utc::now();
        let kind = EventKind::IdentityEntityCreated {
            entity: IdentityEntity {
                id: crate::id::IdentityEntityId::new(),
                tenant_id: None,
                kind: IdentityEntityKind::Dataset,
                canonical_key: "dataset/x".to_string(),
                display_name: "x".to_string(),
                aliases: vec![],
                confidence: Confidence::new(1.0),
                metadata: HashMap::new(),
                created_by: crate::id::ActorId::from_str("actor_ops"),
                created_at: now,
                updated_at: now,
                caused_by: None,
            },
        };
        assert_eq!(kind.kind_name(), "identity_entity_created");
        // Identity events have no target node (mirrors CausalCellCreated).
        assert!(kind.target_node().is_none());
    }

    #[test]
    fn value_type_conversions() {
        assert_eq!(Value::String("hello".into()).as_str(), Some("hello"));
        assert_eq!(Value::Int(42).as_i64(), Some(42));
        assert_eq!(Value::Float(3.14).as_f64(), Some(3.14));
        assert_eq!(Value::Int(42).as_f64(), Some(42.0)); // int-to-float coercion
        assert_eq!(Value::Bool(true).as_bool(), Some(true));
        assert_eq!(Value::Null.as_str(), None);
        assert_eq!(Value::String("hello".into()).as_i64(), None);
    }

    #[test]
    fn value_serde_roundtrip() {
        let values = vec![
            Value::String("test".into()),
            Value::Int(42),
            Value::Float(3.14),
            Value::Bool(false),
            Value::Timestamp(Utc::now()),
            Value::List(vec![Value::Int(1), Value::Int(2)]),
            Value::Map(HashMap::from([("key".to_string(), Value::Bool(true))])),
            Value::Null,
        ];

        for val in &values {
            let json = serde_json::to_string(val).unwrap();
            let restored: Value = serde_json::from_str(&json).unwrap();
            assert_eq!(*val, restored, "roundtrip failed for {:?}", val);
        }
    }

    #[test]
    fn event_serde_roundtrip() {
        let evt = Event::trigger(EventKind::NodeCreated {
            node_id: NodeId::from_str("node_TEST"),
            type_id: "ec2".to_string(),
            properties: HashMap::from([
                ("ami".to_string(), Value::String("ami-123".to_string())),
                ("cpu".to_string(), Value::Int(4)),
            ]),
        });

        let json = serde_json::to_string(&evt).unwrap();
        let restored: Event = serde_json::from_str(&json).unwrap();

        assert_eq!(evt.id, restored.id);
        assert_eq!(evt.cascade_depth, restored.cascade_depth);
        assert_eq!(evt.caused_by, restored.caused_by);
        assert_eq!(evt.kind, restored.kind);
        assert_eq!(evt.cascade_breadth_index, restored.cascade_breadth_index);
    }

    #[test]
    fn breadth_index_defaults_to_zero() {
        let trigger = Event::trigger(sample_node_created());
        assert_eq!(trigger.cascade_breadth_index, 0);

        let reaction = Event::reaction(sample_node_created(), &trigger);
        assert_eq!(reaction.cascade_breadth_index, 0);
    }

    #[test]
    fn serde_backward_compat_missing_breadth_index() {
        // Simulate old JSON that doesn't have cascade_breadth_index
        let json = r#"{
            "id": "evt_TEST",
            "timestamp": "2025-01-01T00:00:00Z",
            "kind": {"Signal": {"name": "test", "source": "node_X", "payload": {}}},
            "caused_by": [],
            "cascade_id": "cas_TEST",
            "cascade_depth": 0
        }"#;

        let event: Event = serde_json::from_str(json).unwrap();
        assert_eq!(event.cascade_breadth_index, 0); // serde(default) → 0
        assert_eq!(event.cascade_depth, 0);
    }

    #[test]
    fn trigger_has_no_tenant_by_default() {
        let event = Event::trigger(sample_node_created());
        assert_eq!(event.tenant_id, None);
    }

    #[test]
    fn trigger_for_tenant_sets_tenant() {
        let tenant = TenantId::from_str("ten_ACME");
        let event = Event::trigger_for_tenant(sample_node_created(), tenant.clone());
        assert_eq!(event.tenant_id, Some(tenant));
    }

    #[test]
    fn reaction_inherits_tenant() {
        let tenant = TenantId::from_str("ten_ACME");
        let trigger = Event::trigger_for_tenant(sample_node_created(), tenant.clone());
        let reaction = Event::reaction(sample_node_created(), &trigger);
        assert_eq!(reaction.tenant_id, Some(tenant));
    }

    #[test]
    fn reaction_inherits_none_tenant() {
        let trigger = Event::trigger(sample_node_created());
        let reaction = Event::reaction(sample_node_created(), &trigger);
        assert_eq!(reaction.tenant_id, None);
    }

    #[test]
    fn convergent_reaction_inherits_first_parent_tenant() {
        let tenant = TenantId::from_str("ten_ACME");
        let a = Event::trigger_for_tenant(sample_node_created(), tenant.clone());
        let b = Event::trigger(sample_node_created());
        // Give b the same cascade for the test
        let b = Event { cascade_id: a.cascade_id.clone(), ..b };

        let converged = Event::convergent_reaction(
            sample_node_created(),
            &[&a, &b],
        );
        assert_eq!(converged.tenant_id, Some(tenant));
    }

    #[test]
    fn serde_backward_compat_missing_tenant_id() {
        // Old JSON without tenant_id field
        let json = r#"{
            "id": "evt_TEST2",
            "timestamp": "2025-01-01T00:00:00Z",
            "kind": {"Signal": {"name": "test", "source": "node_X", "payload": {}}},
            "caused_by": [],
            "cascade_id": "cas_TEST2",
            "cascade_depth": 0
        }"#;

        let event: Event = serde_json::from_str(json).unwrap();
        assert_eq!(event.tenant_id, None); // serde(default) → None
    }

    #[test]
    fn serde_roundtrip_with_tenant() {
        let tenant = TenantId::from_str("ten_ACME");
        let event = Event::trigger_for_tenant(sample_node_created(), tenant.clone());

        let json = serde_json::to_string(&event).unwrap();
        let restored: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.tenant_id, Some(tenant));
    }

    #[test]
    fn action_and_outcome_event_kind_names() {
        use crate::action::{
            Action, ActionKind, ActionStatus, ActionTarget, Outcome, OutcomeKind,
        };
        use crate::id::{ActionId, ActorId, OutcomeId};
        use chrono::Utc;
        use std::collections::HashMap;

        let now = Utc::now();
        let actor = ActorId::from_str("actor_prometheus");
        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::Backfill,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::Dataset(
                "analytics.public.revenue_daily".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: None,
            rejected_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        assert_eq!(
            EventKind::ActionProposed { action }.kind_name(),
            "action_proposed"
        );

        let outcome = Outcome {
            id: OutcomeId::new(),
            tenant_id: None,
            action_id: ActionId::new(),
            kind: OutcomeKind::Success,
            observed_events: vec![],
            updated_claims: vec![],
            produced_evidence: vec![],
            impact: HashMap::new(),
            observed_at: now,
            recorded_at: now,
            recorded_by: actor,
            caused_by: None,
        };
        assert_eq!(
            EventKind::OutcomeObserved { outcome }.kind_name(),
            "outcome_observed"
        );
    }

    #[test]
    fn policy_event_kind_names() {
        use crate::id::{ActionId, ActorId, PolicyDecisionId, PolicyId};
        use crate::policy::{
            ApprovalRequest, ApprovalStatus, Policy, PolicyDecision, PolicyDecisionKind,
            PolicyKind, PolicyScope, PolicyStatus,
        };
        use chrono::Utc;
        use std::collections::HashMap;

        let now = Utc::now();
        let actor = ActorId::from_str("actor_policy");

        let policy = Policy {
            id: PolicyId::new(),
            tenant_id: None,
            name: "Require approval for payroll runs".to_string(),
            kind: PolicyKind::HumanApproval,
            status: PolicyStatus::Active,
            scope: PolicyScope::ActionKind("RunPayroll".to_string()),
            condition: HashMap::new(),
            metadata: HashMap::new(),
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        assert_eq!(
            EventKind::PolicyRegistered { policy }.kind_name(),
            "policy_registered"
        );

        let decision = PolicyDecision {
            id: PolicyDecisionId::new(),
            tenant_id: None,
            policy_id: Some(PolicyId::new()),
            action_id: ActionId::new(),
            kind: PolicyDecisionKind::RequireApproval,
            reason: "payroll runs require approval".to_string(),
            evidence: vec![],
            related_claims: vec![],
            decided_by: actor.clone(),
            decided_at: now,
            caused_by: None,
            details: HashMap::new(),
        };
        assert_eq!(
            EventKind::PolicyDecisionRecorded { decision }.kind_name(),
            "policy_decision_recorded"
        );

        let request = ApprovalRequest {
            id: crate::id::ApprovalId::new(),
            tenant_id: None,
            action_id: ActionId::new(),
            policy_decision_id: Some(PolicyDecisionId::new()),
            status: ApprovalStatus::Requested,
            requested_by: actor.clone(),
            requested_from: vec![ActorId::from_str("actor_accountant")],
            reason: "accountant approval required".to_string(),
            requested_at: now,
            resolved_at: None,
            resolved_by: None,
            caused_by: None,
            metadata: HashMap::new(),
        };
        assert_eq!(
            EventKind::ApprovalRequested { request }.kind_name(),
            "approval_requested"
        );
    }

    #[test]
    fn sensor_event_kind_names() {
        use crate::commit::IdempotencyKey;
        use crate::id::{CommitId, SensorCheckpointId, SensorId, SensorRunId};
        use crate::sensor::{
            SensorCheckpoint, SensorCheckpointStatus, SensorRun, SensorRunStatus, SourceCursor,
        };
        use chrono::Utc;
        use std::collections::HashMap;

        let now = Utc::now();
        let run = SensorRun {
            id: SensorRunId::new(),
            tenant_id: None,
            sensor_id: SensorId::from_str("sensor_github"),
            status: SensorRunStatus::Started,
            source_system: "github".to_string(),
            stream: Some("webhooks".to_string()),
            started_at: now,
            completed_at: None,
            failed_at: None,
            error: None,
            actor_id: None,
            metadata: HashMap::new(),
        };
        assert_eq!(
            EventKind::SensorRunStarted { run }.kind_name(),
            "sensor_run_started"
        );

        assert_eq!(
            EventKind::SensorRunCompleted {
                run_id: SensorRunId::new()
            }
            .kind_name(),
            "sensor_run_completed"
        );

        assert_eq!(
            EventKind::SensorRunFailed {
                run_id: SensorRunId::new(),
                error: "boom".to_string()
            }
            .kind_name(),
            "sensor_run_failed"
        );

        let checkpoint = SensorCheckpoint {
            id: SensorCheckpointId::new(),
            tenant_id: None,
            sensor_id: SensorId::from_str("sensor_github"),
            run_id: None,
            status: SensorCheckpointStatus::Recorded,
            source_system: "github".to_string(),
            cursor: SourceCursor::DeliveryId {
                source: "github".to_string(),
                delivery_id: "delivery-1".to_string(),
            },
            idempotency_key: IdempotencyKey::new("github-delivery-1"),
            commit_id: CommitId::new(),
            event_id: None,
            observed_at: now,
            recorded_at: now,
            metadata: HashMap::new(),
        };
        assert_eq!(
            EventKind::SensorCheckpointRecorded { checkpoint }.kind_name(),
            "sensor_checkpoint_recorded"
        );

        assert_eq!(
            EventKind::SensorCheckpointSuperseded {
                checkpoint_id: SensorCheckpointId::new(),
                superseded_by: None,
                reason: Some("compacted".to_string())
            }
            .kind_name(),
            "sensor_checkpoint_superseded"
        );
    }

    #[test]
    fn schema_event_kind_names() {
        use crate::id::{ActorId, SchemaId, TypeId};
        use crate::schema::{
            EntityTypeSchema, FieldSchema, SchemaDefinition, SchemaStatus, ValueType,
        };
        use chrono::Utc;
        use std::collections::HashMap;

        let now = Utc::now();
        let actor = ActorId::from_str("actor_schema");
        let schema = EntityTypeSchema {
            id: SchemaId::new(),
            tenant_id: None,
            type_id: TypeId::from_str("type_invoice"),
            name: "Invoice".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("invoice_number", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
            ],
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        assert_eq!(
            EventKind::SchemaRegistered {
                schema: SchemaDefinition::EntityType(schema)
            }
            .kind_name(),
            "schema_registered"
        );

        assert_eq!(
            EventKind::SchemaDisabled {
                schema_id: SchemaId::new(),
                disabled_by: actor.clone(),
                reason: Some("test".to_string())
            }
            .kind_name(),
            "schema_disabled"
        );

        assert_eq!(
            EventKind::SchemaArchived {
                schema_id: SchemaId::new(),
                archived_by: actor,
                reason: None
            }
            .kind_name(),
            "schema_archived"
        );
    }

    #[test]
    fn snapshot_event_kind_names() {
        use crate::snapshot::SnapshotManifest;
        use crate::{ActorId, CommitHash, CommitId, SnapshotId};

        let manifest = SnapshotManifest::committed(
            SnapshotId::new(),
            None,
            1,
            Some(CommitId::from_str("commit_1")),
            Some(CommitHash("engine-v0:hash".to_string())),
            ActorId::from_str("actor_snapshot"),
            Utc::now(),
            1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        );
        assert_eq!(
            EventKind::SnapshotTaken {
                manifest: manifest.clone()
            }
            .kind_name(),
            "snapshot_taken"
        );
        assert_eq!(
            EventKind::SnapshotRestored {
                manifest,
                replayed_commit_count: 3
            }
            .kind_name(),
            "snapshot_restored"
        );
    }

    #[test]
    fn replication_event_kind_names() {
        use crate::id::{ActorId, ReplicaId};
        use crate::replication::{
            ReplicationLag, ReplicationMode, ReplicationOffset, ReplicationPeer,
            ReplicationPeerStatus, ReplicationRole, ReplicationRun,
        };

        let actor = ActorId::from_str("actor_replication");
        let peer = ReplicationPeer::registered(
            ReplicaId::from_str("replica_acme"),
            ReplicationRole::Follower,
            ReplicationMode::SnapshotThenTail,
            actor.clone(),
        );
        assert_eq!(
            EventKind::ReplicaRegistered { peer }.kind_name(),
            "replica_registered"
        );

        assert_eq!(
            EventKind::ReplicaHeartbeatRecorded {
                peer_id: ReplicaId::from_str("replica_acme"),
                offset: ReplicationOffset::from_sequence(42),
                lag: Some(ReplicationLag::observe(100, 75, Utc::now())),
            }
            .kind_name(),
            "replica_heartbeat_recorded"
        );

        let run = ReplicationRun::started(
            ReplicaId::from_str("replica_acme"),
            ReplicationMode::CommitLogStreaming,
            None,
        );
        let run_id = run.id.clone();
        assert_eq!(
            EventKind::ReplicationRunStarted { run }.kind_name(),
            "replication_run_started"
        );

        assert_eq!(
            EventKind::ReplicationRunCompleted {
                run_id: run_id.clone(),
                completed_offset: ReplicationOffset::from_sequence(999),
            }
            .kind_name(),
            "replication_run_completed"
        );

        assert_eq!(
            EventKind::ReplicationRunFailed {
                run_id,
                error: "stream closed".to_string()
            }
            .kind_name(),
            "replication_run_failed"
        );

        assert_eq!(
            EventKind::ReplicaStatusChanged {
                peer_id: ReplicaId::from_str("replica_acme"),
                status: ReplicationPeerStatus::Lagging,
                reason: Some("lag > threshold".to_string())
            }
            .kind_name(),
            "replica_status_changed"
        );

        assert_eq!(
            EventKind::ReplicaPromoted {
                peer_id: ReplicaId::from_str("replica_acme"),
                promoted_by: actor.clone(),
                reason: None,
            }
            .kind_name(),
            "replica_promoted"
        );

        assert_eq!(
            EventKind::ReplicaDemoted {
                peer_id: ReplicaId::from_str("replica_acme"),
                demoted_by: actor,
                reason: Some("manual demote".to_string()),
            }
            .kind_name(),
            "replica_demoted"
        );

        // Sanity: replication events have no target node.
        assert!(EventKind::ReplicaPromoted {
            peer_id: ReplicaId::from_str("replica_acme"),
            promoted_by: ActorId::from_str("actor_replication"),
            reason: None,
        }
        .target_node()
        .is_none());
    }

    #[test]
    fn micromodel_event_kind_names() {
        use crate::id::MicroModelId;
        use crate::micromodel::{MicroModelDefinition, MicroModelKind, MicroModelStatus};

        let actor = ActorId::from_str("actor_micromodel");
        let now = chrono::Utc::now();
        let definition = MicroModelDefinition::registered(
            MicroModelId::from_str("mm_lag_v0"),
            MicroModelKind::ReplicationLagAnomaly,
            "lag_anomaly_v0",
            1,
            vec![],
            vec![],
            actor.clone(),
            now,
        );

        // The four new EventKind discriminants map to snake_case
        // names so downstream metrics + lineage rendering can
        // discriminate them by string.
        assert_eq!(
            EventKind::MicroModelRegistered {
                model: definition.clone()
            }
            .kind_name(),
            "micro_model_registered"
        );
        assert_eq!(
            EventKind::MicroModelStatusChanged {
                model_id: MicroModelId::from_str("mm_lag_v0"),
                status: MicroModelStatus::Active,
                reason: None,
            }
            .kind_name(),
            "micro_model_status_changed"
        );
        assert_eq!(
            EventKind::MicroModelPredictionRecorded {
                prediction: crate::micromodel::MicroModelPrediction {
                    model_id: MicroModelId::from_str("mm_lag_v0"),
                    run_id: crate::id::MicroModelRunId::from_str("mmrun_001"),
                    input: serde_json::json!({}),
                    output: serde_json::json!({}),
                    confidence: 1.0,
                    explanation: None,
                    created_at: now,
                }
            }
            .kind_name(),
            "micro_model_prediction_recorded"
        );
        assert_eq!(
            EventKind::MicroModelObservationRecorded {
                observation: crate::micromodel::MicroModelObservation {
                    run_id: crate::id::MicroModelRunId::from_str("mmrun_001"),
                    observed_outcome: serde_json::json!({}),
                    error: None,
                    observed_at: now,
                }
            }
            .kind_name(),
            "micro_model_observation_recorded"
        );

        // Control-plane events: none of them target a graph node.
        assert!(EventKind::MicroModelRegistered { model: definition }
            .target_node()
            .is_none());
    }
}
