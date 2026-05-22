use hydra_core::error::{HydraError, Result};
use hydra_core::{
    ActionId, ActorId, ApprovalId, ApprovalRequest, ApprovalStatus, Event, EventKind, Policy,
    PolicyDecision, PolicyDecisionId, PolicyDecisionKind, PolicyId, PolicyKind, PolicyScope,
    PolicyStatus,
};
use std::collections::{HashMap, HashSet};

/// Stable, hashable key for policy scope indexing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PolicyScopeKey {
    AnyAction,
    ActionKind(String),
    Actor(ActorId),
    Claim(hydra_core::ClaimId),
    Tenant(hydra_core::TenantId),
    Custom(String),
}

impl From<&PolicyScope> for PolicyScopeKey {
    fn from(scope: &PolicyScope) -> Self {
        match scope {
            PolicyScope::AnyAction => Self::AnyAction,
            PolicyScope::ActionKind(value) => Self::ActionKind(value.clone()),
            PolicyScope::Actor(id) => Self::Actor(id.clone()),
            PolicyScope::Claim(id) => Self::Claim(id.clone()),
            PolicyScope::Tenant(id) => Self::Tenant(id.clone()),
            PolicyScope::Custom(value) => Self::Custom(value.clone()),
        }
    }
}

/// Materialized governance state derived from policy/approval events.
///
/// This store answers:
/// - Which policies exist?
/// - Which policies are active?
/// - What decisions were made for an action?
/// - Which approvals are pending?
/// - Who needs to approve what?
#[derive(Debug, Clone, Default)]
pub struct PolicyStore {
    policies: HashMap<PolicyId, Policy>,
    decisions: HashMap<PolicyDecisionId, PolicyDecision>,
    approvals: HashMap<ApprovalId, ApprovalRequest>,

    policies_by_status: HashMap<PolicyStatus, HashSet<PolicyId>>,
    policies_by_kind: HashMap<PolicyKind, HashSet<PolicyId>>,
    policies_by_scope: HashMap<PolicyScopeKey, HashSet<PolicyId>>,

    decisions_by_action: HashMap<ActionId, HashSet<PolicyDecisionId>>,
    decisions_by_kind: HashMap<PolicyDecisionKind, HashSet<PolicyDecisionId>>,

    approvals_by_action: HashMap<ActionId, HashSet<ApprovalId>>,
    approvals_by_status: HashMap<ApprovalStatus, HashSet<ApprovalId>>,
    approvals_by_requested_actor: HashMap<ActorId, HashSet<ApprovalId>>,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    pub fn decision_count(&self) -> usize {
        self.decisions.len()
    }

    pub fn approval_count(&self) -> usize {
        self.approvals.len()
    }

    pub fn policy(&self, id: &PolicyId) -> Option<&Policy> {
        self.policies.get(id)
    }

    pub fn decision(&self, id: &PolicyDecisionId) -> Option<&PolicyDecision> {
        self.decisions.get(id)
    }

    pub fn approval(&self, id: &ApprovalId) -> Option<&ApprovalRequest> {
        self.approvals.get(id)
    }

    pub fn all_policies(&self) -> impl Iterator<Item = &Policy> {
        self.policies.values()
    }

    pub fn all_decisions(&self) -> impl Iterator<Item = &PolicyDecision> {
        self.decisions.values()
    }

    pub fn all_approvals(&self) -> impl Iterator<Item = &ApprovalRequest> {
        self.approvals.values()
    }

    pub fn policies_with_status(&self, status: PolicyStatus) -> Vec<&Policy> {
        self.policies_by_status
            .get(&status)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.policies.get(id))
            .collect()
    }

    pub fn active_policies(&self) -> Vec<&Policy> {
        self.policies_with_status(PolicyStatus::Active)
    }

    pub fn disabled_policies(&self) -> Vec<&Policy> {
        self.policies_with_status(PolicyStatus::Disabled)
    }

    pub fn policies_with_kind(&self, kind: PolicyKind) -> Vec<&Policy> {
        self.policies_by_kind
            .get(&kind)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.policies.get(id))
            .collect()
    }

    pub fn policies_for_scope(&self, scope: &PolicyScope) -> Vec<&Policy> {
        let key = PolicyScopeKey::from(scope);
        self.policies_by_scope
            .get(&key)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.policies.get(id))
            .collect()
    }

    pub fn decisions_for_action(&self, action_id: &ActionId) -> Vec<&PolicyDecision> {
        self.decisions_by_action
            .get(action_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.decisions.get(id))
            .collect()
    }

    pub fn decisions_with_kind(&self, kind: PolicyDecisionKind) -> Vec<&PolicyDecision> {
        self.decisions_by_kind
            .get(&kind)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.decisions.get(id))
            .collect()
    }

    pub fn approvals_for_action(&self, action_id: &ActionId) -> Vec<&ApprovalRequest> {
        self.approvals_by_action
            .get(action_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.approvals.get(id))
            .collect()
    }

    pub fn approvals_with_status(&self, status: ApprovalStatus) -> Vec<&ApprovalRequest> {
        self.approvals_by_status
            .get(&status)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.approvals.get(id))
            .collect()
    }

    pub fn pending_approvals(&self) -> Vec<&ApprovalRequest> {
        self.approvals_with_status(ApprovalStatus::Requested)
    }

    pub fn approved_requests(&self) -> Vec<&ApprovalRequest> {
        self.approvals_with_status(ApprovalStatus::Approved)
    }

    pub fn rejected_requests(&self) -> Vec<&ApprovalRequest> {
        self.approvals_with_status(ApprovalStatus::Rejected)
    }

    pub fn approvals_requested_from(&self, actor_id: &ActorId) -> Vec<&ApprovalRequest> {
        self.approvals_by_requested_actor
            .get(actor_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.approvals.get(id))
            .collect()
    }

    /// Apply one Hydra event to the policy store.
    ///
    /// Non-policy events are ignored.
    pub fn apply_event(&mut self, event: &Event) -> Result<()> {
        match &event.kind {
            EventKind::PolicyRegistered { policy } => {
                self.insert_policy(policy.clone());
            }
            EventKind::PolicyDisabled { policy_id, .. } => {
                self.mutate_policy(policy_id, |policy| {
                    policy.status = PolicyStatus::Disabled;
                    policy.updated_at = event.timestamp;
                })?;
            }
            EventKind::PolicyDecisionRecorded { decision } => {
                self.insert_decision(decision.clone());
            }
            EventKind::ApprovalRequested { request } => {
                self.insert_approval(request.clone());
            }
            EventKind::ApprovalGranted {
                approval_id,
                approved_by,
            } => {
                self.mutate_approval(approval_id, |approval| {
                    approval.status = ApprovalStatus::Approved;
                    approval.resolved_by = Some(approved_by.clone());
                    approval.resolved_at = Some(event.timestamp);
                })?;
            }
            EventKind::ApprovalRejected {
                approval_id,
                rejected_by,
                ..
            } => {
                self.mutate_approval(approval_id, |approval| {
                    approval.status = ApprovalStatus::Rejected;
                    approval.resolved_by = Some(rejected_by.clone());
                    approval.resolved_at = Some(event.timestamp);
                })?;
            }
            EventKind::ApprovalCancelled {
                approval_id,
                cancelled_by,
                ..
            } => {
                self.mutate_approval(approval_id, |approval| {
                    approval.status = ApprovalStatus::Cancelled;
                    approval.resolved_by = Some(cancelled_by.clone());
                    approval.resolved_at = Some(event.timestamp);
                })?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn apply_events<'a>(&mut self, events: impl IntoIterator<Item = &'a Event>) -> Result<()> {
        for event in events {
            self.apply_event(event)?;
        }
        Ok(())
    }

    fn insert_policy(&mut self, policy: Policy) {
        let policy_id = policy.id.clone();
        if let Some(existing) = self.policies.get(&policy_id).cloned() {
            self.remove_policy_indexes(&existing);
        }
        self.policies.insert(policy_id.clone(), policy);
        if let Some(inserted) = self.policies.get(&policy_id).cloned() {
            self.insert_policy_indexes(&inserted);
        }
    }

    fn insert_decision(&mut self, decision: PolicyDecision) {
        let decision_id = decision.id.clone();
        if let Some(existing) = self.decisions.get(&decision_id).cloned() {
            self.remove_decision_indexes(&existing);
        }
        self.decisions.insert(decision_id.clone(), decision);
        if let Some(inserted) = self.decisions.get(&decision_id).cloned() {
            self.insert_decision_indexes(&inserted);
        }
    }

    fn insert_approval(&mut self, approval: ApprovalRequest) {
        let approval_id = approval.id.clone();
        if let Some(existing) = self.approvals.get(&approval_id).cloned() {
            self.remove_approval_indexes(&existing);
        }
        self.approvals.insert(approval_id.clone(), approval);
        if let Some(inserted) = self.approvals.get(&approval_id).cloned() {
            self.insert_approval_indexes(&inserted);
        }
    }

    fn mutate_policy<F>(&mut self, policy_id: &PolicyId, mutation: F) -> Result<()>
    where
        F: FnOnce(&mut Policy),
    {
        let mut policy = self
            .policies
            .remove(policy_id)
            .ok_or_else(|| HydraError::QueryError(format!("unknown policy: {}", policy_id)))?;
        self.remove_policy_indexes(&policy);
        mutation(&mut policy);
        self.insert_policy_indexes(&policy);
        self.policies.insert(policy_id.clone(), policy);
        Ok(())
    }

    fn mutate_approval<F>(&mut self, approval_id: &ApprovalId, mutation: F) -> Result<()>
    where
        F: FnOnce(&mut ApprovalRequest),
    {
        let mut approval = self
            .approvals
            .remove(approval_id)
            .ok_or_else(|| HydraError::QueryError(format!("unknown approval: {}", approval_id)))?;
        self.remove_approval_indexes(&approval);
        mutation(&mut approval);
        self.insert_approval_indexes(&approval);
        self.approvals.insert(approval_id.clone(), approval);
        Ok(())
    }

    fn insert_policy_indexes(&mut self, policy: &Policy) {
        let policy_id = policy.id.clone();
        self.policies_by_status
            .entry(policy.status.clone())
            .or_default()
            .insert(policy_id.clone());
        self.policies_by_kind
            .entry(policy.kind.clone())
            .or_default()
            .insert(policy_id.clone());
        self.policies_by_scope
            .entry(PolicyScopeKey::from(&policy.scope))
            .or_default()
            .insert(policy_id);
    }

    fn remove_policy_indexes(&mut self, policy: &Policy) {
        let policy_id = &policy.id;
        remove_from_index(&mut self.policies_by_status, &policy.status, policy_id);
        remove_from_index(&mut self.policies_by_kind, &policy.kind, policy_id);
        let scope_key = PolicyScopeKey::from(&policy.scope);
        remove_from_index(&mut self.policies_by_scope, &scope_key, policy_id);
    }

    fn insert_decision_indexes(&mut self, decision: &PolicyDecision) {
        let decision_id = decision.id.clone();
        self.decisions_by_action
            .entry(decision.action_id.clone())
            .or_default()
            .insert(decision_id.clone());
        self.decisions_by_kind
            .entry(decision.kind.clone())
            .or_default()
            .insert(decision_id);
    }

    fn remove_decision_indexes(&mut self, decision: &PolicyDecision) {
        let decision_id = &decision.id;
        remove_from_index(
            &mut self.decisions_by_action,
            &decision.action_id,
            decision_id,
        );
        remove_from_index(&mut self.decisions_by_kind, &decision.kind, decision_id);
    }

    fn insert_approval_indexes(&mut self, approval: &ApprovalRequest) {
        let approval_id = approval.id.clone();
        self.approvals_by_action
            .entry(approval.action_id.clone())
            .or_default()
            .insert(approval_id.clone());
        self.approvals_by_status
            .entry(approval.status.clone())
            .or_default()
            .insert(approval_id.clone());
        for actor_id in &approval.requested_from {
            self.approvals_by_requested_actor
                .entry(actor_id.clone())
                .or_default()
                .insert(approval_id.clone());
        }
    }

    fn remove_approval_indexes(&mut self, approval: &ApprovalRequest) {
        let approval_id = &approval.id;
        remove_from_index(
            &mut self.approvals_by_action,
            &approval.action_id,
            approval_id,
        );
        remove_from_index(
            &mut self.approvals_by_status,
            &approval.status,
            approval_id,
        );
        for actor_id in &approval.requested_from {
            remove_from_index(
                &mut self.approvals_by_requested_actor,
                actor_id,
                approval_id,
            );
        }
    }
}

fn remove_from_index<K, V>(index: &mut HashMap<K, HashSet<V>>, key: &K, value: &V)
where
    K: std::hash::Hash + Eq + Clone,
    V: std::hash::Hash + Eq,
{
    let should_remove_key = if let Some(values) = index.get_mut(key) {
        values.remove(value);
        values.is_empty()
    } else {
        false
    };
    if should_remove_key {
        index.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{
        ActionId, ApprovalId, ApprovalStatus, CascadeId, EventId, PolicyDecisionId, TenantId,
        Value,
    };

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_policy_store_test")
    }

    fn actor() -> ActorId {
        ActorId::from_str("actor_policy")
    }

    fn accountant() -> ActorId {
        ActorId::from_str("actor_accountant")
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

    fn policy() -> Policy {
        let now = chrono::Utc::now();
        let mut condition = HashMap::new();
        condition.insert("max_amount".to_string(), Value::Float(5000.0));
        Policy {
            id: PolicyId::new(),
            tenant_id: Some(tenant()),
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
        }
    }

    fn decision(action_id: ActionId, kind: PolicyDecisionKind) -> PolicyDecision {
        PolicyDecision {
            id: PolicyDecisionId::new(),
            tenant_id: Some(tenant()),
            policy_id: Some(PolicyId::new()),
            action_id,
            kind,
            reason: "test policy decision".to_string(),
            evidence: vec![],
            related_claims: vec![],
            decided_by: actor(),
            decided_at: chrono::Utc::now(),
            caused_by: None,
            details: HashMap::new(),
        }
    }

    fn approval(action_id: ActionId) -> ApprovalRequest {
        ApprovalRequest {
            id: ApprovalId::new(),
            tenant_id: Some(tenant()),
            action_id,
            policy_decision_id: Some(PolicyDecisionId::new()),
            status: ApprovalStatus::Requested,
            requested_by: actor(),
            requested_from: vec![accountant()],
            reason: "accountant approval required".to_string(),
            requested_at: chrono::Utc::now(),
            resolved_at: None,
            resolved_by: None,
            caused_by: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn stores_registered_policy() {
        let mut store = PolicyStore::new();
        let policy = policy();
        let policy_id = policy.id.clone();
        store
            .apply_event(&event(EventKind::PolicyRegistered {
                policy: policy.clone(),
            }))
            .unwrap();
        assert_eq!(store.policy_count(), 1);
        assert_eq!(store.policy(&policy_id), Some(&policy));
        assert_eq!(store.active_policies().len(), 1);
        assert_eq!(store.policies_with_kind(PolicyKind::AutoApproval).len(), 1);
        assert_eq!(
            store
                .policies_for_scope(&PolicyScope::ActionKind("PostLedgerEntry".to_string()))
                .len(),
            1
        );
    }

    #[test]
    fn disables_policy_and_reindexes_status() {
        let mut store = PolicyStore::new();
        let policy = policy();
        let policy_id = policy.id.clone();
        store
            .apply_event(&event(EventKind::PolicyRegistered { policy }))
            .unwrap();
        assert_eq!(store.active_policies().len(), 1);

        store
            .apply_event(&event(EventKind::PolicyDisabled {
                policy_id: policy_id.clone(),
                disabled_by: actor(),
                reason: Some("manual disable".to_string()),
            }))
            .unwrap();
        assert_eq!(store.active_policies().len(), 0);
        assert_eq!(store.disabled_policies().len(), 1);
        assert_eq!(
            store.policy(&policy_id).unwrap().status,
            PolicyStatus::Disabled
        );
    }

    #[test]
    fn stores_policy_decision_and_indexes_by_action_and_kind() {
        let mut store = PolicyStore::new();
        let action_id = ActionId::new();
        let decision = decision(action_id.clone(), PolicyDecisionKind::RequireApproval);
        let decision_id = decision.id.clone();
        store
            .apply_event(&event(EventKind::PolicyDecisionRecorded {
                decision: decision.clone(),
            }))
            .unwrap();
        assert_eq!(store.decision_count(), 1);
        assert_eq!(store.decision(&decision_id), Some(&decision));
        assert_eq!(store.decisions_for_action(&action_id).len(), 1);
        assert_eq!(
            store
                .decisions_with_kind(PolicyDecisionKind::RequireApproval)
                .len(),
            1
        );
    }

    #[test]
    fn stores_approval_request_and_indexes_by_action_status_and_actor() {
        let mut store = PolicyStore::new();
        let action_id = ActionId::new();
        let approval = approval(action_id.clone());
        let approval_id = approval.id.clone();
        store
            .apply_event(&event(EventKind::ApprovalRequested {
                request: approval.clone(),
            }))
            .unwrap();
        assert_eq!(store.approval_count(), 1);
        assert_eq!(store.approval(&approval_id), Some(&approval));
        assert_eq!(store.approvals_for_action(&action_id).len(), 1);
        assert_eq!(store.pending_approvals().len(), 1);
        assert_eq!(store.approvals_requested_from(&accountant()).len(), 1);
    }

    #[test]
    fn approval_granted_updates_status_and_resolution_fields() {
        let mut store = PolicyStore::new();
        let action_id = ActionId::new();
        let approval = approval(action_id);
        let approval_id = approval.id.clone();
        store
            .apply_event(&event(EventKind::ApprovalRequested { request: approval }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ApprovalGranted {
                approval_id: approval_id.clone(),
                approved_by: accountant(),
            }))
            .unwrap();
        let stored = store.approval(&approval_id).unwrap();
        assert_eq!(stored.status, ApprovalStatus::Approved);
        assert_eq!(stored.resolved_by, Some(accountant()));
        assert!(stored.resolved_at.is_some());
        assert_eq!(store.pending_approvals().len(), 0);
        assert_eq!(store.approved_requests().len(), 1);
    }

    #[test]
    fn approval_rejected_and_cancelled_are_indexed() {
        let mut store = PolicyStore::new();
        let rejected = approval(ActionId::new());
        let rejected_id = rejected.id.clone();
        store
            .apply_event(&event(EventKind::ApprovalRequested { request: rejected }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ApprovalRejected {
                approval_id: rejected_id,
                rejected_by: accountant(),
                reason: "not allowed".to_string(),
            }))
            .unwrap();
        assert_eq!(store.rejected_requests().len(), 1);

        let cancelled = approval(ActionId::new());
        let cancelled_id = cancelled.id.clone();
        store
            .apply_event(&event(EventKind::ApprovalRequested { request: cancelled }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ApprovalCancelled {
                approval_id: cancelled_id,
                cancelled_by: actor(),
                reason: Some("superseded".to_string()),
            }))
            .unwrap();
        assert_eq!(
            store.approvals_with_status(ApprovalStatus::Cancelled).len(),
            1
        );
    }

    #[test]
    fn rejects_unknown_policy_or_approval_transitions() {
        let mut store = PolicyStore::new();
        let missing_policy = store.apply_event(&event(EventKind::PolicyDisabled {
            policy_id: PolicyId::new(),
            disabled_by: actor(),
            reason: None,
        }));
        assert!(missing_policy.is_err());

        let missing_approval = store.apply_event(&event(EventKind::ApprovalGranted {
            approval_id: ApprovalId::new(),
            approved_by: actor(),
        }));
        assert!(missing_approval.is_err());
    }
}
