use hydra_core::{
    Action, ActionKind, ActionStatus, Policy, PolicyId, PolicyKind, PolicyScope, PolicyStatus,
};

use crate::policy_store::PolicyStore;

/// Deterministic result of evaluating policies for an action.
///
/// This is an engine-level decision, not yet a persisted `PolicyDecision`.
/// A later PolicyAgent will convert this report into:
///
/// - PolicyDecisionRecorded
/// - ActionApproved
/// - ActionRejected
/// - ApprovalRequested
/// - Signal
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyEvaluationDecision {
    Allow,
    AutoApprove,
    RequireApproval,
    Reject,
    Block,
    Escalate,
    NeedsHumanReview,
}

/// Detailed policy evaluation result.
///
/// Reports include matching policy IDs so the later PolicyAgent can create
/// auditable PolicyDecision records referencing the policy that caused the
/// decision.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyEvaluationReport {
    pub action_id: hydra_core::ActionId,
    pub decision: PolicyEvaluationDecision,
    pub matched_policy_id: Option<PolicyId>,
    pub matched_policy_kind: Option<PolicyKind>,
    pub reasons: Vec<String>,
}

impl PolicyEvaluationReport {
    pub fn is_allowed(&self) -> bool {
        matches!(
            self.decision,
            PolicyEvaluationDecision::Allow | PolicyEvaluationDecision::AutoApprove
        )
    }

    pub fn requires_approval(&self) -> bool {
        matches!(self.decision, PolicyEvaluationDecision::RequireApproval)
    }

    pub fn is_blocked(&self) -> bool {
        matches!(
            self.decision,
            PolicyEvaluationDecision::Reject | PolicyEvaluationDecision::Block
        )
    }
}

/// Read-only deterministic policy evaluator.
///
/// v0 matching is intentionally simple and auditable:
///
/// Matching scopes:
/// - PolicyScope::AnyAction
/// - PolicyScope::ActionKind(format!("{:?}", action.kind))
/// - PolicyScope::Tenant(action.tenant_id)
/// - PolicyScope::Actor(action.proposed_by)
///
/// Disabled/archived policies are ignored.
///
/// Decision precedence:
/// Block > Reject > RequireApproval > NeedsHumanReview > Escalate > AutoApprove > Allow
#[derive(Debug, Clone, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate_action(
        &self,
        store: &PolicyStore,
        action: &Action,
    ) -> PolicyEvaluationReport {
        if action.status != ActionStatus::Proposed {
            return PolicyEvaluationReport {
                action_id: action.id.clone(),
                decision: PolicyEvaluationDecision::Allow,
                matched_policy_id: None,
                matched_policy_kind: None,
                reasons: vec![
                    "action is not Proposed; policy engine does not gate this lifecycle state"
                        .to_string(),
                ],
            };
        }

        let matching = self.matching_active_policies(store, action);
        if matching.is_empty() {
            return PolicyEvaluationReport {
                action_id: action.id.clone(),
                decision: PolicyEvaluationDecision::Allow,
                matched_policy_id: None,
                matched_policy_kind: None,
                reasons: vec!["no active matching policy found".to_string()],
            };
        }

        self.decide(action, matching)
    }

    fn matching_active_policies<'a>(
        &self,
        store: &'a PolicyStore,
        action: &Action,
    ) -> Vec<&'a Policy> {
        store
            .active_policies()
            .into_iter()
            .filter(|policy| self.policy_matches_action(policy, action))
            .collect()
    }

    fn policy_matches_action(&self, policy: &Policy, action: &Action) -> bool {
        if policy.status != PolicyStatus::Active {
            return false;
        }
        match &policy.scope {
            PolicyScope::AnyAction => true,
            PolicyScope::ActionKind(value) => value == &action_kind_key(&action.kind),
            PolicyScope::Actor(actor_id) => actor_id == &action.proposed_by,
            PolicyScope::Tenant(tenant_id) => action
                .tenant_id
                .as_ref()
                .map(|action_tenant| action_tenant == tenant_id)
                .unwrap_or(false),
            PolicyScope::Claim(claim_id) => action.related_claims.contains(claim_id),
            PolicyScope::Custom(_) => false,
        }
    }

    fn decide(&self, action: &Action, policies: Vec<&Policy>) -> PolicyEvaluationReport {
        let mut candidates = Vec::new();
        for policy in policies {
            let decision = decision_for_policy_kind(&policy.kind);
            candidates.push((decision, policy));
        }
        candidates.sort_by_key(|(decision, _)| decision_precedence(decision));

        let (decision, policy) = candidates
            .into_iter()
            .next()
            .expect("decide called with non-empty policy list");

        PolicyEvaluationReport {
            action_id: action.id.clone(),
            decision: decision.clone(),
            matched_policy_id: Some(policy.id.clone()),
            matched_policy_kind: Some(policy.kind.clone()),
            reasons: vec![format!(
                "matched active policy '{}' with scope {:?}",
                policy.name, policy.scope
            )],
        }
    }
}

fn decision_for_policy_kind(kind: &PolicyKind) -> PolicyEvaluationDecision {
    match kind {
        PolicyKind::AutoApproval => PolicyEvaluationDecision::AutoApprove,
        PolicyKind::HumanApproval => PolicyEvaluationDecision::RequireApproval,
        PolicyKind::Block => PolicyEvaluationDecision::Block,
        PolicyKind::Escalation => PolicyEvaluationDecision::Escalate,
        PolicyKind::ReviewRequirement => PolicyEvaluationDecision::NeedsHumanReview,
        PolicyKind::Compliance
        | PolicyKind::Security
        | PolicyKind::Finance
        | PolicyKind::Payroll
        | PolicyKind::Custom(_) => PolicyEvaluationDecision::RequireApproval,
    }
}

/// Lower number wins.
fn decision_precedence(decision: &PolicyEvaluationDecision) -> u8 {
    match decision {
        PolicyEvaluationDecision::Block => 0,
        PolicyEvaluationDecision::Reject => 1,
        PolicyEvaluationDecision::RequireApproval => 2,
        PolicyEvaluationDecision::NeedsHumanReview => 3,
        PolicyEvaluationDecision::Escalate => 4,
        PolicyEvaluationDecision::AutoApprove => 5,
        PolicyEvaluationDecision::Allow => 6,
    }
}

fn action_kind_key(kind: &ActionKind) -> String {
    match kind {
        ActionKind::Notify => "Notify".to_string(),
        ActionKind::CreateTicket => "CreateTicket".to_string(),
        ActionKind::AssignOwner => "AssignOwner".to_string(),
        ActionKind::RequestEvidence => "RequestEvidence".to_string(),
        ActionKind::Quarantine => "Quarantine".to_string(),
        ActionKind::Backfill => "Backfill".to_string(),
        ActionKind::Repair => "Repair".to_string(),
        ActionKind::Approve => "Approve".to_string(),
        ActionKind::Reject => "Reject".to_string(),
        ActionKind::ExecuteWorkflow => "ExecuteWorkflow".to_string(),
        ActionKind::PostLedgerEntry => "PostLedgerEntry".to_string(),
        ActionKind::RunPayroll => "RunPayroll".to_string(),
        ActionKind::Custom(value) => format!("Custom:{value}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_store::PolicyStore;
    use hydra_core::{
        ActionId, ActionTarget, ActorId, CascadeId, Event, EventId, EventKind, Policy, PolicyId,
        PolicyStatus, TenantId, Value,
    };
    use std::collections::HashMap;

    fn actor() -> ActorId {
        ActorId::from_str("actor_policy_test")
    }

    fn accountant() -> ActorId {
        ActorId::from_str("actor_accountant")
    }

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_policy_engine_test")
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
            proposed_by: actor(),
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

    fn store_with_policy(policy: Policy) -> PolicyStore {
        let mut store = PolicyStore::new();
        store
            .apply_event(&event(EventKind::PolicyRegistered { policy }))
            .unwrap();
        store
    }

    #[test]
    fn no_matching_policy_allows_action() {
        let store = PolicyStore::new();
        let engine = PolicyEngine::new();
        let action = action(ActionKind::PostLedgerEntry);
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::Allow);
        assert!(report.is_allowed());
        assert_eq!(report.matched_policy_id, None);
    }

    #[test]
    fn auto_approval_policy_auto_approves_action() {
        let policy = policy(
            PolicyKind::AutoApproval,
            PolicyScope::ActionKind("PostLedgerEntry".to_string()),
        );
        let store = store_with_policy(policy.clone());
        let engine = PolicyEngine::new();
        let action = action(ActionKind::PostLedgerEntry);
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::AutoApprove);
        assert_eq!(report.matched_policy_id, Some(policy.id));
        assert_eq!(report.matched_policy_kind, Some(PolicyKind::AutoApproval));
    }

    #[test]
    fn human_approval_policy_requires_approval() {
        let policy = policy(
            PolicyKind::HumanApproval,
            PolicyScope::ActionKind("RunPayroll".to_string()),
        );
        let store = store_with_policy(policy);
        let engine = PolicyEngine::new();
        let action = action(ActionKind::RunPayroll);
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::RequireApproval);
        assert!(report.requires_approval());
    }

    #[test]
    fn block_policy_blocks_action() {
        let policy = policy(PolicyKind::Block, PolicyScope::AnyAction);
        let store = store_with_policy(policy);
        let engine = PolicyEngine::new();
        let action = action(ActionKind::RunPayroll);
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::Block);
        assert!(report.is_blocked());
    }

    #[test]
    fn disabled_policy_is_ignored() {
        let mut policy = policy(
            PolicyKind::Block,
            PolicyScope::ActionKind("PostLedgerEntry".to_string()),
        );
        policy.status = PolicyStatus::Disabled;
        let store = store_with_policy(policy);
        let engine = PolicyEngine::new();
        let action = action(ActionKind::PostLedgerEntry);
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::Allow);
        assert_eq!(report.matched_policy_id, None);
    }

    #[test]
    fn tenant_policy_matches_action_tenant() {
        let policy = policy(PolicyKind::HumanApproval, PolicyScope::Tenant(tenant()));
        let store = store_with_policy(policy);
        let engine = PolicyEngine::new();
        let action = action(ActionKind::PostLedgerEntry);
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::RequireApproval);
    }

    #[test]
    fn actor_policy_matches_action_proposer() {
        let policy = policy(PolicyKind::HumanApproval, PolicyScope::Actor(actor()));
        let store = store_with_policy(policy);
        let engine = PolicyEngine::new();
        let action = action(ActionKind::PostLedgerEntry);
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::RequireApproval);
    }

    #[test]
    fn precedence_prefers_block_over_auto_approval() {
        let mut store = PolicyStore::new();
        let auto = policy(PolicyKind::AutoApproval, PolicyScope::AnyAction);
        let block = policy(PolicyKind::Block, PolicyScope::AnyAction);
        store
            .apply_event(&event(EventKind::PolicyRegistered { policy: auto }))
            .unwrap();
        store
            .apply_event(&event(EventKind::PolicyRegistered { policy: block }))
            .unwrap();
        let engine = PolicyEngine::new();
        let action = action(ActionKind::Backfill);
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::Block);
    }

    #[test]
    fn non_proposed_action_is_allowed_without_gating() {
        let store = PolicyStore::new();
        let engine = PolicyEngine::new();
        let mut action = action(ActionKind::PostLedgerEntry);
        action.status = ActionStatus::Executed;
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::Allow);
        assert!(report.reasons[0].contains("not Proposed"));
    }

    #[test]
    fn custom_action_kind_matches_custom_scope_key() {
        let policy = policy(
            PolicyKind::HumanApproval,
            PolicyScope::ActionKind("Custom:PostCryptoJournal".to_string()),
        );
        let store = store_with_policy(policy);
        let engine = PolicyEngine::new();
        let action = action(ActionKind::Custom("PostCryptoJournal".to_string()));
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::RequireApproval);
    }

    #[test]
    fn custom_policy_scope_does_not_match_in_v0() {
        let policy = policy(
            PolicyKind::Block,
            PolicyScope::Custom("some-expression".to_string()),
        );
        let store = store_with_policy(policy);
        let engine = PolicyEngine::new();
        let action = action(ActionKind::PostLedgerEntry);
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::Allow);
    }

    #[test]
    fn finance_and_payroll_policies_require_approval_by_default() {
        for kind in [PolicyKind::Finance, PolicyKind::Payroll] {
            let store = store_with_policy(policy(kind, PolicyScope::AnyAction));
            let engine = PolicyEngine::new();
            let action = action(ActionKind::PostLedgerEntry);
            let report = engine.evaluate_action(&store, &action);
            assert_eq!(report.decision, PolicyEvaluationDecision::RequireApproval);
        }
    }

    #[test]
    fn review_requirement_maps_to_needs_human_review() {
        let store = store_with_policy(policy(
            PolicyKind::ReviewRequirement,
            PolicyScope::AnyAction,
        ));
        let engine = PolicyEngine::new();
        let action = action(ActionKind::PostLedgerEntry);
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::NeedsHumanReview);
    }

    #[test]
    fn escalation_policy_maps_to_escalate() {
        let store = store_with_policy(policy(PolicyKind::Escalation, PolicyScope::AnyAction));
        let engine = PolicyEngine::new();
        let action = action(ActionKind::PostLedgerEntry);
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::Escalate);
    }

    #[test]
    fn claim_scope_matches_related_claim() {
        let claim_id = hydra_core::ClaimId::new();
        let store = store_with_policy(policy(
            PolicyKind::HumanApproval,
            PolicyScope::Claim(claim_id.clone()),
        ));
        let engine = PolicyEngine::new();
        let mut action = action(ActionKind::PostLedgerEntry);
        action.related_claims.push(claim_id);
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::RequireApproval);
    }

    #[test]
    fn unrelated_claim_scope_does_not_match() {
        let store = store_with_policy(policy(
            PolicyKind::Block,
            PolicyScope::Claim(hydra_core::ClaimId::new()),
        ));
        let engine = PolicyEngine::new();
        let action = action(ActionKind::PostLedgerEntry);
        let report = engine.evaluate_action(&store, &action);
        assert_eq!(report.decision, PolicyEvaluationDecision::Allow);
    }

    #[test]
    fn unused_import_guard() {
        let _ = accountant();
        let _ = Value::Bool(true);
    }
}
