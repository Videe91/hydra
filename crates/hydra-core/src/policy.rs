use crate::event::Value;
use crate::id::{
    ActionId, ActorId, ApprovalId, ClaimId, EventId, EvidenceId, PolicyDecisionId, PolicyId,
    TenantId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// What type of policy this is.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyKind {
    AutoApproval,
    HumanApproval,
    Block,
    Escalation,
    ReviewRequirement,
    Compliance,
    Security,
    Finance,
    Payroll,
    Custom(String),
}

/// Which action this policy applies to.
///
/// Keep this generic so Hydra remains a database substrate, not a domain app.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyScope {
    AnyAction,
    ActionKind(String),
    Actor(ActorId),
    Claim(ClaimId),
    Tenant(TenantId),
    Custom(String),
}

/// Policy lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyStatus {
    Active,
    Disabled,
    Archived,
}

/// A rule/constraint that governs whether an action may proceed.
///
/// v0 keeps the condition generic as structured data. Later, this can become
/// a typed expression language or WASM/predicate engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    pub id: PolicyId,
    pub tenant_id: Option<TenantId>,
    pub name: String,
    pub kind: PolicyKind,
    pub status: PolicyStatus,
    pub scope: PolicyScope,
    /// Structured condition payload.
    ///
    /// Examples:
    /// - {"max_amount": 5000}
    /// - {"requires_role": "accountant"}
    /// - {"action_kind": "PostLedgerEntry"}
    pub condition: HashMap<String, Value>,
    /// Free metadata for UI/search/audit.
    pub metadata: HashMap<String, Value>,
    pub created_by: ActorId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub caused_by: Option<EventId>,
}

/// Result of evaluating policy against an action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyDecisionKind {
    Allow,
    AutoApprove,
    RequireApproval,
    Reject,
    Block,
    Escalate,
    NeedsHumanReview,
}

/// A policy evaluation result.
///
/// This does not mutate the action directly. It records the policy decision
/// so agents/reflexes can emit ActionApproved / ActionRejected / Signal events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub id: PolicyDecisionId,
    pub tenant_id: Option<TenantId>,
    pub policy_id: Option<PolicyId>,
    pub action_id: ActionId,
    pub kind: PolicyDecisionKind,
    pub reason: String,
    pub evidence: Vec<EvidenceId>,
    pub related_claims: Vec<ClaimId>,
    pub decided_by: ActorId,
    pub decided_at: DateTime<Utc>,
    pub caused_by: Option<EventId>,
    /// Structured details.
    pub details: HashMap<String, Value>,
}

/// Approval lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Requested,
    Approved,
    Rejected,
    Cancelled,
    Expired,
}

/// A human/system approval request for an action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: ApprovalId,
    pub tenant_id: Option<TenantId>,
    pub action_id: ActionId,
    pub policy_decision_id: Option<PolicyDecisionId>,
    pub status: ApprovalStatus,
    pub requested_by: ActorId,
    pub requested_from: Vec<ActorId>,
    pub reason: String,
    pub requested_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<ActorId>,
    pub caused_by: Option<EventId>,
    pub metadata: HashMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{ActionId, ActorId, PolicyDecisionId, PolicyId};

    fn actor() -> ActorId {
        ActorId::from_str("actor_policy")
    }

    #[test]
    fn policy_serde_roundtrip() {
        let now = Utc::now();
        let mut condition = HashMap::new();
        condition.insert("max_amount".to_string(), Value::Float(5000.0));
        let policy = Policy {
            id: PolicyId::new(),
            tenant_id: None,
            name: "Auto approve small ledger entries".to_string(),
            kind: PolicyKind::AutoApproval,
            status: PolicyStatus::Active,
            scope: PolicyScope::ActionKind("PostLedgerEntry".to_string()),
            condition,
            metadata: HashMap::new(),
            created_by: actor(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let restored: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, restored);
    }

    #[test]
    fn policy_decision_serde_roundtrip() {
        let now = Utc::now();
        let decision = PolicyDecision {
            id: PolicyDecisionId::new(),
            tenant_id: None,
            policy_id: Some(PolicyId::new()),
            action_id: ActionId::new(),
            kind: PolicyDecisionKind::RequireApproval,
            reason: "amount exceeds auto-approval threshold".to_string(),
            evidence: vec![],
            related_claims: vec![],
            decided_by: actor(),
            decided_at: now,
            caused_by: None,
            details: HashMap::new(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let restored: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, restored);
    }

    #[test]
    fn approval_request_serde_roundtrip() {
        let now = Utc::now();
        let approval = ApprovalRequest {
            id: ApprovalId::new(),
            tenant_id: None,
            action_id: ActionId::new(),
            policy_decision_id: Some(PolicyDecisionId::new()),
            status: ApprovalStatus::Requested,
            requested_by: actor(),
            requested_from: vec![ActorId::from_str("actor_accountant")],
            reason: "ledger entry requires accountant approval".to_string(),
            requested_at: now,
            resolved_at: None,
            resolved_by: None,
            caused_by: None,
            metadata: HashMap::new(),
        };
        let json = serde_json::to_string(&approval).unwrap();
        let restored: ApprovalRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(approval, restored);
    }
}
