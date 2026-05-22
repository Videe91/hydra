use hydra_core::{
    Action, ActorId, ApprovalRequest, ApprovalStatus, Event, EventKind, PolicyDecision,
    PolicyDecisionId, PolicyDecisionKind, Value,
};
use std::collections::HashMap;

use crate::action_store::ActionStore;
use crate::policy_engine::{PolicyEngine, PolicyEvaluationDecision, PolicyEvaluationReport};
use crate::policy_store::PolicyStore;

/// Deterministic governance agent that turns policy evaluation reports into
/// event-sourced transitions.
///
/// Important:
/// This agent does not mutate Hydra state directly.
/// It only emits EventKind values. PolicyStore and ActionStore materialize
/// state later from those events.
#[derive(Debug, Clone)]
pub struct PolicyAgent {
    actor_id: ActorId,
    /// Default actor who receives approval requests when a policy requires
    /// human approval and no more specific approver is configured.
    default_approver: ActorId,
}

impl PolicyAgent {
    pub fn new(actor_id: ActorId, default_approver: ActorId) -> Self {
        Self {
            actor_id,
            default_approver,
        }
    }

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    pub fn default_approver(&self) -> &ActorId {
        &self.default_approver
    }

    /// React to a full event.
    ///
    /// Currently this only reacts to ActionProposed.
    pub fn react(
        &self,
        event: &Event,
        action_store: &ActionStore,
        policy_store: &PolicyStore,
        policy_engine: &PolicyEngine,
    ) -> Vec<EventKind> {
        self.react_to_kind(&event.kind, action_store, policy_store, policy_engine)
    }

    /// React to an EventKind.
    pub fn react_to_kind(
        &self,
        kind: &EventKind,
        action_store: &ActionStore,
        policy_store: &PolicyStore,
        policy_engine: &PolicyEngine,
    ) -> Vec<EventKind> {
        match kind {
            EventKind::ActionProposed { action } => {
                let action_from_store = action_store.action(&action.id).unwrap_or(action);
                let report = policy_engine.evaluate_action(policy_store, action_from_store);
                self.events_from_report(action_from_store, &report)
            }
            _ => Vec::new(),
        }
    }

    /// Convert a policy evaluation report into event-sourced transitions.
    pub fn events_from_report(
        &self,
        action: &Action,
        report: &PolicyEvaluationReport,
    ) -> Vec<EventKind> {
        let decision_kind = policy_decision_kind(&report.decision);
        let decision = PolicyDecision {
            id: PolicyDecisionId::new(),
            tenant_id: action.tenant_id.clone(),
            policy_id: report.matched_policy_id.clone(),
            action_id: action.id.clone(),
            kind: decision_kind,
            reason: report.reasons.join("; "),
            evidence: action.supporting_evidence.clone(),
            related_claims: action.related_claims.clone(),
            decided_by: self.actor_id.clone(),
            decided_at: chrono::Utc::now(),
            caused_by: None,
            details: report_details(report),
        };

        let mut events = vec![EventKind::PolicyDecisionRecorded {
            decision: decision.clone(),
        }];

        match report.decision {
            PolicyEvaluationDecision::Allow | PolicyEvaluationDecision::AutoApprove => {
                events.push(EventKind::ActionApproved {
                    action_id: action.id.clone(),
                    approved_by: self.actor_id.clone(),
                });
            }
            PolicyEvaluationDecision::RequireApproval => {
                events.push(EventKind::ApprovalRequested {
                    request: self.approval_request(action, &decision),
                });
            }
            PolicyEvaluationDecision::Reject | PolicyEvaluationDecision::Block => {
                events.push(EventKind::ActionRejected {
                    action_id: action.id.clone(),
                    rejected_by: self.actor_id.clone(),
                    reason: decision.reason.clone(),
                });
            }
            PolicyEvaluationDecision::NeedsHumanReview => {
                events.push(self.signal(
                    "policy_needs_human_review",
                    action,
                    Some(&decision),
                    report.reasons.clone(),
                ));
            }
            PolicyEvaluationDecision::Escalate => {
                events.push(self.signal(
                    "policy_escalated",
                    action,
                    Some(&decision),
                    report.reasons.clone(),
                ));
            }
        }

        events
    }

    fn approval_request(&self, action: &Action, decision: &PolicyDecision) -> ApprovalRequest {
        ApprovalRequest {
            id: hydra_core::ApprovalId::new(),
            tenant_id: action.tenant_id.clone(),
            action_id: action.id.clone(),
            policy_decision_id: Some(decision.id.clone()),
            status: ApprovalStatus::Requested,
            requested_by: self.actor_id.clone(),
            requested_from: vec![self.default_approver.clone()],
            reason: decision.reason.clone(),
            requested_at: chrono::Utc::now(),
            resolved_at: None,
            resolved_by: None,
            caused_by: None,
            metadata: HashMap::new(),
        }
    }

    fn signal(
        &self,
        name: &str,
        action: &Action,
        decision: Option<&PolicyDecision>,
        reasons: Vec<String>,
    ) -> EventKind {
        let mut payload = HashMap::new();
        payload.insert("agent".to_string(), Value::String(self.actor_id.to_string()));
        payload.insert(
            "action_id".to_string(),
            Value::String(action.id.to_string()),
        );
        if let Some(decision) = decision {
            payload.insert(
                "policy_decision_id".to_string(),
                Value::String(decision.id.to_string()),
            );
            if let Some(policy_id) = &decision.policy_id {
                payload.insert(
                    "policy_id".to_string(),
                    Value::String(policy_id.to_string()),
                );
            }
            payload.insert(
                "policy_decision_kind".to_string(),
                Value::String(format!("{:?}", decision.kind)),
            );
        }
        payload.insert(
            "reasons".to_string(),
            Value::List(reasons.into_iter().map(Value::String).collect()),
        );
        EventKind::Signal {
            source: hydra_core::NodeId::from_str("hydra.policy_agent"),
            name: name.to_string(),
            payload,
        }
    }
}

fn policy_decision_kind(decision: &PolicyEvaluationDecision) -> PolicyDecisionKind {
    match decision {
        PolicyEvaluationDecision::Allow => PolicyDecisionKind::Allow,
        PolicyEvaluationDecision::AutoApprove => PolicyDecisionKind::AutoApprove,
        PolicyEvaluationDecision::RequireApproval => PolicyDecisionKind::RequireApproval,
        PolicyEvaluationDecision::Reject => PolicyDecisionKind::Reject,
        PolicyEvaluationDecision::Block => PolicyDecisionKind::Block,
        PolicyEvaluationDecision::Escalate => PolicyDecisionKind::Escalate,
        PolicyEvaluationDecision::NeedsHumanReview => PolicyDecisionKind::NeedsHumanReview,
    }
}

fn report_details(report: &PolicyEvaluationReport) -> HashMap<String, Value> {
    let mut details = HashMap::new();
    details.insert(
        "evaluation_decision".to_string(),
        Value::String(format!("{:?}", report.decision)),
    );
    if let Some(policy_id) = &report.matched_policy_id {
        details.insert(
            "matched_policy_id".to_string(),
            Value::String(policy_id.to_string()),
        );
    }
    if let Some(policy_kind) = &report.matched_policy_kind {
        details.insert(
            "matched_policy_kind".to_string(),
            Value::String(format!("{:?}", policy_kind)),
        );
    }
    details.insert(
        "reasons".to_string(),
        Value::List(
            report
                .reasons
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    details
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_store::ActionStore;
    use crate::policy_engine::PolicyEngine;
    use crate::policy_store::PolicyStore;
    use hydra_core::{
        Action, ActionId, ActionKind, ActionStatus, ActionTarget, CascadeId, EventId, Policy,
        PolicyId, PolicyKind, PolicyScope, PolicyStatus, TenantId,
    };

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_policy_agent_test")
    }

    fn actor() -> ActorId {
        ActorId::from_str("actor_policy_agent")
    }

    fn approver() -> ActorId {
        ActorId::from_str("actor_accountant")
    }

    fn proposer() -> ActorId {
        ActorId::from_str("actor_prometheus")
    }

    fn event(kind: EventKind) -> Event {
        Event {
            id: EventId::new(),
            tenant_id: Some(tenant()),
            timestamp: chrono::Utc::now(),
            kind,
            caused_by: vec![],
            cascade_id: CascadeId::new(),
            cascade_depth: 0,
            cascade_breadth_index: 0,
        }
    }

    fn action(kind: ActionKind) -> Action {
        let now = chrono::Utc::now();
        Action {
            id: ActionId::new(),
            tenant_id: Some(tenant()),
            kind,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("test".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: proposer(),
            approved_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        }
    }

    fn policy(kind: PolicyKind, scope: PolicyScope) -> Policy {
        let now = chrono::Utc::now();
        Policy {
            id: PolicyId::new(),
            tenant_id: Some(tenant()),
            name: format!("{:?} policy", kind),
            kind,
            status: PolicyStatus::Active,
            scope,
            condition: HashMap::new(),
            metadata: HashMap::new(),
            created_by: actor(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn stores_with_policy(
        policy: Option<Policy>,
        action: &Action,
    ) -> (ActionStore, PolicyStore) {
        let mut action_store = ActionStore::new();
        let mut policy_store = PolicyStore::new();
        if let Some(policy) = policy {
            policy_store
                .apply_event(&event(EventKind::PolicyRegistered { policy }))
                .unwrap();
        }
        action_store
            .apply_event(&event(EventKind::ActionProposed {
                action: action.clone(),
            }))
            .unwrap();
        (action_store, policy_store)
    }

    fn agent() -> PolicyAgent {
        PolicyAgent::new(actor(), approver())
    }

    #[test]
    fn allow_emits_policy_decision_and_action_approved() {
        let action = action(ActionKind::Backfill);
        let (action_store, policy_store) = stores_with_policy(None, &action);
        let policy_engine = PolicyEngine::new();
        let events = agent().react_to_kind(
            &EventKind::ActionProposed {
                action: action.clone(),
            },
            &action_store,
            &policy_store,
            &policy_engine,
        );
        assert_eq!(events.len(), 2);
        match &events[0] {
            EventKind::PolicyDecisionRecorded { decision } => {
                assert_eq!(decision.action_id, action.id);
                assert_eq!(decision.kind, PolicyDecisionKind::Allow);
            }
            other => panic!("expected PolicyDecisionRecorded, got {other:?}"),
        }
        match &events[1] {
            EventKind::ActionApproved {
                action_id,
                approved_by,
            } => {
                assert_eq!(action_id, &action.id);
                assert_eq!(approved_by, &actor());
            }
            other => panic!("expected ActionApproved, got {other:?}"),
        }
    }

    #[test]
    fn auto_approval_emits_policy_decision_and_action_approved() {
        let action = action(ActionKind::Backfill);
        let policy = policy(
            PolicyKind::AutoApproval,
            PolicyScope::ActionKind("Backfill".to_string()),
        );
        let policy_id = policy.id.clone();
        let (action_store, policy_store) = stores_with_policy(Some(policy), &action);
        let policy_engine = PolicyEngine::new();
        let events = agent().react_to_kind(
            &EventKind::ActionProposed {
                action: action.clone(),
            },
            &action_store,
            &policy_store,
            &policy_engine,
        );
        assert_eq!(events.len(), 2);
        match &events[0] {
            EventKind::PolicyDecisionRecorded { decision } => {
                assert_eq!(decision.kind, PolicyDecisionKind::AutoApprove);
                assert_eq!(decision.policy_id, Some(policy_id));
            }
            other => panic!("expected PolicyDecisionRecorded, got {other:?}"),
        }
        assert!(matches!(events[1], EventKind::ActionApproved { .. }));
    }

    #[test]
    fn require_approval_emits_policy_decision_and_approval_requested() {
        let action = action(ActionKind::RunPayroll);
        let policy = policy(
            PolicyKind::HumanApproval,
            PolicyScope::ActionKind("RunPayroll".to_string()),
        );
        let (action_store, policy_store) = stores_with_policy(Some(policy), &action);
        let policy_engine = PolicyEngine::new();
        let events = agent().react_to_kind(
            &EventKind::ActionProposed {
                action: action.clone(),
            },
            &action_store,
            &policy_store,
            &policy_engine,
        );
        assert_eq!(events.len(), 2);
        let decision_id = match &events[0] {
            EventKind::PolicyDecisionRecorded { decision } => {
                assert_eq!(decision.kind, PolicyDecisionKind::RequireApproval);
                decision.id.clone()
            }
            other => panic!("expected PolicyDecisionRecorded, got {other:?}"),
        };
        match &events[1] {
            EventKind::ApprovalRequested { request } => {
                assert_eq!(request.action_id, action.id);
                assert_eq!(request.policy_decision_id, Some(decision_id));
                assert_eq!(request.status, ApprovalStatus::Requested);
                assert_eq!(request.requested_from, vec![approver()]);
            }
            other => panic!("expected ApprovalRequested, got {other:?}"),
        }
    }

    #[test]
    fn block_emits_policy_decision_and_action_rejected() {
        let action = action(ActionKind::RunPayroll);
        let policy = policy(PolicyKind::Block, PolicyScope::AnyAction);
        let (action_store, policy_store) = stores_with_policy(Some(policy), &action);
        let policy_engine = PolicyEngine::new();
        let events = agent().react_to_kind(
            &EventKind::ActionProposed {
                action: action.clone(),
            },
            &action_store,
            &policy_store,
            &policy_engine,
        );
        assert_eq!(events.len(), 2);
        match &events[0] {
            EventKind::PolicyDecisionRecorded { decision } => {
                assert_eq!(decision.kind, PolicyDecisionKind::Block);
            }
            other => panic!("expected PolicyDecisionRecorded, got {other:?}"),
        }
        match &events[1] {
            EventKind::ActionRejected {
                action_id,
                rejected_by,
                reason,
            } => {
                assert_eq!(action_id, &action.id);
                assert_eq!(rejected_by, &actor());
                assert!(reason.contains("matched active policy"));
            }
            other => panic!("expected ActionRejected, got {other:?}"),
        }
    }

    #[test]
    fn review_requirement_emits_human_review_signal() {
        let action = action(ActionKind::PostLedgerEntry);
        let policy = policy(PolicyKind::ReviewRequirement, PolicyScope::AnyAction);
        let (action_store, policy_store) = stores_with_policy(Some(policy), &action);
        let policy_engine = PolicyEngine::new();
        let events = agent().react_to_kind(
            &EventKind::ActionProposed {
                action: action.clone(),
            },
            &action_store,
            &policy_store,
            &policy_engine,
        );
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], EventKind::PolicyDecisionRecorded { .. }));
        match &events[1] {
            EventKind::Signal { name, payload, .. } => {
                assert_eq!(name, "policy_needs_human_review");
                assert_eq!(
                    payload.get("action_id"),
                    Some(&Value::String(action.id.to_string()))
                );
            }
            other => panic!("expected policy_needs_human_review Signal, got {other:?}"),
        }
    }

    #[test]
    fn escalation_emits_escalation_signal() {
        let action = action(ActionKind::PostLedgerEntry);
        let policy = policy(PolicyKind::Escalation, PolicyScope::AnyAction);
        let (action_store, policy_store) = stores_with_policy(Some(policy), &action);
        let policy_engine = PolicyEngine::new();
        let events = agent().react_to_kind(
            &EventKind::ActionProposed {
                action: action.clone(),
            },
            &action_store,
            &policy_store,
            &policy_engine,
        );
        assert_eq!(events.len(), 2);
        match &events[1] {
            EventKind::Signal { name, payload, .. } => {
                assert_eq!(name, "policy_escalated");
                assert_eq!(
                    payload.get("action_id"),
                    Some(&Value::String(action.id.to_string()))
                );
            }
            other => panic!("expected policy_escalated Signal, got {other:?}"),
        }
    }

    #[test]
    fn noops_for_non_action_proposed_events() {
        let action = action(ActionKind::Backfill);
        let (action_store, policy_store) = stores_with_policy(None, &action);
        let policy_engine = PolicyEngine::new();
        let events = agent().react_to_kind(
            &EventKind::ActionExecuted {
                action_id: action.id,
            },
            &action_store,
            &policy_store,
            &policy_engine,
        );
        assert!(events.is_empty());
    }
}
