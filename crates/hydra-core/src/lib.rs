pub mod id;
pub mod error;
pub mod event;
pub mod epistemic;
pub mod action;
pub mod policy;
pub mod node;
pub mod edge;
pub mod graph;
pub mod subscription;

pub use id::{
    ActionId, ActorId, ApprovalId, CascadeId, ClaimId, EdgeId, EventId, EvidenceId, NodeId,
    OutcomeId, PolicyDecisionId, PolicyId, SnapshotId, SubscriptionId, TenantId,
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

/// Convenience re-exports for common types
pub mod prelude {
    pub use crate::id::{
        ActionId, ActorId, ApprovalId, CascadeId, ClaimId, EdgeId, EventId, EvidenceId, NodeId,
        OutcomeId, PolicyDecisionId, PolicyId, SnapshotId, SubscriptionId, TenantId,
    };
    pub use crate::error::{HydraError, Result};
    pub use crate::event::{Event, EventKind, Value};
    pub use crate::epistemic::{
        Claim, ClaimKind, ClaimObject, ClaimStatus, ClaimSubject, Confidence, Evidence,
        EvidencePayload, EvidenceSource,
    };
    pub use crate::action::{
        Action, ActionKind, ActionStatus, ActionTarget, Outcome, OutcomeKind,
    };
    pub use crate::policy::{
        ApprovalRequest, ApprovalStatus, Policy, PolicyDecision, PolicyDecisionKind, PolicyKind,
        PolicyScope, PolicyStatus,
    };
    pub use crate::node::{Node, NodeMeta, NodeValidator};
    pub use crate::edge::{Edge, EdgeMeta};
    pub use crate::graph::{GraphReader, TraversalDirection, bfs, bfs_dyn, topological_sort};
    pub use crate::subscription::{EventFilter, Subscription, SubscriptionHandler};
}
