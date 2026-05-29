use crate::event::Value;
use crate::id::{
    ActionId, ActorId, ClaimId, EdgeId, EventId, EvidenceId, NodeId, OutcomeId, PolicyId, TenantId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// What kind of intervention Hydra or an agent is proposing/executing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionKind {
    Notify,
    CreateTicket,
    AssignOwner,
    RequestEvidence,
    Quarantine,
    Backfill,
    Repair,
    Approve,
    Reject,
    ExecuteWorkflow,
    PostLedgerEntry,
    RunPayroll,
    Custom(String),
}

/// Current lifecycle of an action.
///
/// Actions are not hidden side effects in Hydra. They move through an explicit
/// event-sourced lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionStatus {
    Proposed,
    Approved,
    Rejected,
    Executing,
    Executed,
    Failed,
    Cancelled,
}

/// What the action is aimed at.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionTarget {
    Node(NodeId),
    Edge(EdgeId),
    Claim(ClaimId),
    Evidence(EvidenceId),
    ExternalRef(String),
    Dataset(String),
    System(String),
}

/// An intervention proposed or executed by a human, agent, or system.
///
/// Examples:
/// - rerun a pipeline
/// - request missing invoice
/// - quarantine a dataset
/// - create a ticket
/// - post a ledger entry
/// - run payroll
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub id: ActionId,
    pub tenant_id: Option<TenantId>,
    pub kind: ActionKind,
    pub status: ActionStatus,
    pub targets: Vec<ActionTarget>,
    pub related_claims: Vec<ClaimId>,
    pub supporting_evidence: Vec<EvidenceId>,
    /// Actor who proposed the action.
    pub proposed_by: ActorId,
    /// Actor who approved the action, if approval was required.
    pub approved_by: Option<ActorId>,
    /// Actor who rejected the action — populated by
    /// `EventKind::ActionRejected` (Trust Patch 5 / Patch 13).
    /// `#[serde(default)]` so audit logs / snapshots written
    /// before Patch 13 replay unchanged.
    #[serde(default)]
    pub rejected_by: Option<ActorId>,
    /// Optional policy that allowed/blocked/required review for this action.
    pub policy_id: Option<PolicyId>,
    /// Free structured payload for action-specific details.
    pub payload: HashMap<String, Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
    /// Timestamp at which the action was rejected (Patch 13).
    /// Mirrors `approved_at` for symmetric audit. `#[serde(default)]`
    /// for pre-Patch-13 replay compatibility.
    #[serde(default)]
    pub rejected_at: Option<DateTime<Utc>>,
    pub executed_at: Option<DateTime<Utc>>,
    pub caused_by: Option<EventId>,
}

/// What kind of result was observed after an action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutcomeKind {
    Success,
    Failure,
    PartialSuccess,
    NoEffect,
    Regression,
    Unknown,
    Custom(String),
}

/// Observed result of an action.
///
/// Outcomes are how Hydra learns whether actions actually improved reality.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub id: OutcomeId,
    pub tenant_id: Option<TenantId>,
    pub action_id: ActionId,
    pub kind: OutcomeKind,
    /// Events observed after the action.
    pub observed_events: Vec<EventId>,
    /// Claims updated or affected by this outcome.
    pub updated_claims: Vec<ClaimId>,
    /// Evidence produced by the action outcome.
    pub produced_evidence: Vec<EvidenceId>,
    /// Structured impact assessment.
    pub impact: HashMap<String, Value>,
    pub observed_at: DateTime<Utc>,
    pub recorded_at: DateTime<Utc>,
    pub recorded_by: ActorId,
    pub caused_by: Option<EventId>,
}

/// Result of executing an action — MicroModel Patch 7.
///
/// The execution stub walks an Approved action through
/// `ActionExecuting → ActionExecuted → OutcomeObserved` and returns
/// this report so callers can audit the transition and reach the
/// recorded outcome by id without a follow-up query.
///
/// `previous_status` is always `Approved` in v0 (Patch 7 enforces
/// the strict precondition) but the field is preserved for future
/// patches where execution may be triggered from other states.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionExecutionReport {
    pub action_id: ActionId,
    pub previous_status: ActionStatus,
    pub final_status: ActionStatus,
    pub outcome_id: OutcomeId,
    pub executed_by: ActorId,
    pub executed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{ActionId, ActorId, ClaimId, EvidenceId, OutcomeId};

    fn actor() -> ActorId {
        ActorId::from_str("actor_prometheus")
    }

    #[test]
    fn action_serde_roundtrip() {
        let now = Utc::now();
        let mut payload = HashMap::new();
        payload.insert(
            "ticket_title".to_string(),
            Value::String("Backfill stale revenue table".to_string()),
        );
        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::Backfill,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::Dataset(
                "analytics.public.revenue_daily".to_string(),
            )],
            related_claims: vec![ClaimId::new()],
            supporting_evidence: vec![EvidenceId::new()],
            proposed_by: actor(),
            approved_by: None,
            rejected_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        let json = serde_json::to_string(&action).unwrap();
        let restored: Action = serde_json::from_str(&json).unwrap();
        assert_eq!(action, restored);
    }

    #[test]
    fn outcome_serde_roundtrip() {
        let now = Utc::now();
        let mut impact = HashMap::new();
        impact.insert("freshness_restored".to_string(), Value::Bool(true));
        impact.insert("lag_hours_after".to_string(), Value::Float(0.0));
        let outcome = Outcome {
            id: OutcomeId::new(),
            tenant_id: None,
            action_id: ActionId::new(),
            kind: OutcomeKind::Success,
            observed_events: vec![],
            updated_claims: vec![ClaimId::new()],
            produced_evidence: vec![EvidenceId::new()],
            impact,
            observed_at: now,
            recorded_at: now,
            recorded_by: actor(),
            caused_by: None,
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let restored: Outcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, restored);
    }
}
