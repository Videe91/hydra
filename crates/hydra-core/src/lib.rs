pub mod id;
pub mod error;
pub mod event;
pub mod epistemic;
pub mod action;
pub mod policy;
pub mod commit;
pub mod sensor;
pub mod schema;
pub mod node;
pub mod edge;
pub mod graph;
pub mod snapshot;
pub mod subscription;
pub mod automation;
pub mod micromodel;
pub mod replication;
pub mod trust;

pub use id::{
    ActionId, ActorId, ApprovalId, CascadeId, ClaimId, CommitId, EdgeId, EventId, EvidenceId,
    MicroModelId, MicroModelRunId, NodeId, OutcomeId, PolicyDecisionId, PolicyId, ReplicaId,
    ReplicationRunId, SchemaId, SensorCheckpointId, SensorId, SensorRunId, SnapshotId,
    SubscriptionId, TenantId, TypeId,
};
pub use event::{Event, EventKind, Value};
pub use epistemic::{
    Claim,
    ClaimKind,
    ClaimObject,
    ClaimStatus,
    ClaimSubject,
    Confidence,
    Evidence,
    EvidencePayload,
    EvidenceSource,
};
pub use action::{
    Action,
    ActionExecutionReport,
    ActionKind,
    ActionStatus,
    ActionTarget,
    Outcome,
    OutcomeKind,
};
pub use policy::{
    ApprovalRequest,
    ApprovalStatus,
    Policy,
    PolicyDecision,
    PolicyDecisionKind,
    PolicyKind,
    PolicyScope,
    PolicyStatus,
};
pub use commit::{
    CommitBatch,
    CommitHash,
    CommitRecord,
    CommitStatus,
    EventCommitRecord,
    EventHash,
    IdempotencyKey,
};
pub use sensor::{
    SensorCheckpoint,
    SensorCheckpointStatus,
    SensorRun,
    SensorRunStatus,
    SourceCursor,
};
pub use schema::{
    ActionPayloadSchema,
    ClaimPredicateSchema,
    EdgeTypeSchema,
    EntityTypeSchema,
    EvidencePayloadSchema,
    FieldSchema,
    PolicyConditionSchema,
    SchemaDefinition,
    SchemaStatus,
    ValueType,
};
pub use snapshot::{SnapshotBody, SnapshotManifest, SnapshotStatus};
pub use micromodel::{
    MicroModelDefinition, MicroModelKind, MicroModelObservation, MicroModelPrediction,
    MicroModelStatus,
};
pub use replication::{
    ReplicationLag, ReplicationMode, ReplicationOffset, ReplicationPeer, ReplicationPeerStatus,
    ReplicationRole, ReplicationRun, ReplicationRunStatus,
};
pub use trust::{
    is_cascade_approver, TrustAssessment, TrustFactor, TrustLevel, HYDRA_POLICY_AGENT_ACTOR,
};
pub use automation::AutoExecutionDecision;

/// Convenience re-exports for common types
pub mod prelude {
    pub use crate::id::{
        ActionId, ActorId, ApprovalId, CascadeId, ClaimId, CommitId, EdgeId, EventId, EvidenceId,
        MicroModelId, MicroModelRunId, NodeId, OutcomeId, PolicyDecisionId, PolicyId, ReplicaId,
        ReplicationRunId, SchemaId, SensorCheckpointId, SensorId, SensorRunId, SnapshotId,
        SubscriptionId, TenantId, TypeId,
    };
    pub use crate::error::{HydraError, Result};
    pub use crate::event::{Event, EventKind, Value};
    pub use crate::epistemic::{
        Claim, ClaimKind, ClaimObject, ClaimStatus, ClaimSubject, Confidence, Evidence,
        EvidencePayload, EvidenceSource,
    };
    pub use crate::action::{
        Action, ActionExecutionReport, ActionKind, ActionStatus, ActionTarget, Outcome,
        OutcomeKind,
    };
    pub use crate::policy::{
        ApprovalRequest, ApprovalStatus, Policy, PolicyDecision, PolicyDecisionKind, PolicyKind,
        PolicyScope, PolicyStatus,
    };
    pub use crate::commit::{
        CommitBatch, CommitHash, CommitRecord, CommitStatus, EventCommitRecord, EventHash,
        IdempotencyKey,
    };
    pub use crate::sensor::{
        SensorCheckpoint, SensorCheckpointStatus, SensorRun, SensorRunStatus, SourceCursor,
    };
    pub use crate::schema::{
        ActionPayloadSchema, ClaimPredicateSchema, EdgeTypeSchema, EntityTypeSchema,
        EvidencePayloadSchema, FieldSchema, PolicyConditionSchema, SchemaDefinition, SchemaStatus,
        ValueType,
    };
    pub use crate::snapshot::{SnapshotBody, SnapshotManifest, SnapshotStatus};
    pub use crate::micromodel::{
        MicroModelDefinition, MicroModelKind, MicroModelObservation, MicroModelPrediction,
        MicroModelStatus,
    };
    pub use crate::replication::{
        ReplicationLag, ReplicationMode, ReplicationOffset, ReplicationPeer,
        ReplicationPeerStatus, ReplicationRole, ReplicationRun, ReplicationRunStatus,
    };
    pub use crate::trust::{
        is_cascade_approver, TrustAssessment, TrustFactor, TrustLevel,
        HYDRA_POLICY_AGENT_ACTOR,
    };
    pub use crate::automation::AutoExecutionDecision;
    pub use crate::node::{Node, NodeMeta, NodeValidator};
    pub use crate::edge::{Edge, EdgeMeta};
    pub use crate::graph::{GraphReader, TraversalDirection, bfs, bfs_dyn, topological_sort};
    pub use crate::subscription::{EventFilter, Subscription, SubscriptionHandler};
}
