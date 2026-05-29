use hydra_core::error::{HydraError, Result};
use hydra_core::{
    Action, ActionId, ActionStatus, ActionTarget, ClaimId, Event, EventKind, Outcome, OutcomeId,
};
use std::collections::{HashMap, HashSet};

/// Stable key for indexing actions by target.
///
/// This mirrors `ActionTarget`, but keeps index behavior explicit and hashable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ActionTargetKey {
    Node(hydra_core::NodeId),
    Edge(hydra_core::EdgeId),
    Claim(hydra_core::ClaimId),
    Evidence(hydra_core::EvidenceId),
    ExternalRef(String),
    Dataset(String),
    System(String),
}

impl From<&ActionTarget> for ActionTargetKey {
    fn from(target: &ActionTarget) -> Self {
        match target {
            ActionTarget::Node(id) => Self::Node(id.clone()),
            ActionTarget::Edge(id) => Self::Edge(id.clone()),
            ActionTarget::Claim(id) => Self::Claim(id.clone()),
            ActionTarget::Evidence(id) => Self::Evidence(id.clone()),
            ActionTarget::ExternalRef(value) => Self::ExternalRef(value.clone()),
            ActionTarget::Dataset(value) => Self::Dataset(value.clone()),
            ActionTarget::System(value) => Self::System(value.clone()),
        }
    }
}

/// Materialized action/outcome state derived from action lifecycle events.
///
/// This is intentionally separate from graph projection and epistemic state:
/// - Projection answers: what topology is operational?
/// - EpistemicStore answers: what does Hydra believe?
/// - ActionStore answers: what interventions were proposed/executed, and what happened?
#[derive(Debug, Clone, Default)]
pub struct ActionStore {
    actions: HashMap<ActionId, Action>,
    outcomes: HashMap<OutcomeId, Outcome>,
    actions_by_status: HashMap<ActionStatus, HashSet<ActionId>>,
    actions_by_target: HashMap<ActionTargetKey, HashSet<ActionId>>,
    actions_by_claim: HashMap<ClaimId, HashSet<ActionId>>,
    outcomes_by_action: HashMap<ActionId, HashSet<OutcomeId>>,
}

impl ActionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    pub fn outcome_count(&self) -> usize {
        self.outcomes.len()
    }

    pub fn action(&self, id: &ActionId) -> Option<&Action> {
        self.actions.get(id)
    }

    pub fn outcome(&self, id: &OutcomeId) -> Option<&Outcome> {
        self.outcomes.get(id)
    }

    pub fn all_actions(&self) -> impl Iterator<Item = &Action> {
        self.actions.values()
    }

    pub fn all_outcomes(&self) -> impl Iterator<Item = &Outcome> {
        self.outcomes.values()
    }

    pub fn actions_with_status(&self, status: ActionStatus) -> Vec<&Action> {
        self.actions_by_status
            .get(&status)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.actions.get(id))
            .collect()
    }

    pub fn proposed_actions(&self) -> Vec<&Action> {
        self.actions_with_status(ActionStatus::Proposed)
    }

    pub fn approved_actions(&self) -> Vec<&Action> {
        self.actions_with_status(ActionStatus::Approved)
    }

    pub fn executing_actions(&self) -> Vec<&Action> {
        self.actions_with_status(ActionStatus::Executing)
    }

    pub fn executed_actions(&self) -> Vec<&Action> {
        self.actions_with_status(ActionStatus::Executed)
    }

    pub fn failed_actions(&self) -> Vec<&Action> {
        self.actions_with_status(ActionStatus::Failed)
    }

    pub fn cancelled_actions(&self) -> Vec<&Action> {
        self.actions_with_status(ActionStatus::Cancelled)
    }

    pub fn actions_for_target(&self, target: &ActionTarget) -> Vec<&Action> {
        let key = ActionTargetKey::from(target);
        self.actions_by_target
            .get(&key)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.actions.get(id))
            .collect()
    }

    pub fn actions_for_claim(&self, claim_id: &ClaimId) -> Vec<&Action> {
        self.actions_by_claim
            .get(claim_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.actions.get(id))
            .collect()
    }

    pub fn outcomes_for_action(&self, action_id: &ActionId) -> Vec<&Outcome> {
        self.outcomes_by_action
            .get(action_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.outcomes.get(id))
            .collect()
    }

    /// Apply one Hydra event to the action store.
    ///
    /// Non-action events are ignored. This lets the store subscribe to the full
    /// event stream without callers needing to pre-filter.
    pub fn apply_event(&mut self, event: &Event) -> Result<()> {
        match &event.kind {
            EventKind::ActionProposed { action } => {
                self.insert_action(action.clone());
            }
            EventKind::ActionApproved {
                action_id,
                approved_by,
                // Patch 6 — operator-supplied reason is captured in
                // the event itself for audit but not yet projected
                // onto Action.payload. The store mutates only the
                // status / approver / timestamps.
                reason: _,
            } => {
                self.mutate_action(action_id, |action| {
                    action.status = ActionStatus::Approved;
                    action.approved_by = Some(approved_by.clone());
                    action.approved_at = Some(event.timestamp);
                    action.updated_at = event.timestamp;
                })?;
            }
            EventKind::ActionRejected { action_id, .. } => {
                self.mutate_action(action_id, |action| {
                    action.status = ActionStatus::Rejected;
                    action.updated_at = event.timestamp;
                })?;
            }
            EventKind::ActionExecuting { action_id } => {
                self.mutate_action(action_id, |action| {
                    action.status = ActionStatus::Executing;
                    action.updated_at = event.timestamp;
                })?;
            }
            EventKind::ActionExecuted { action_id } => {
                self.mutate_action(action_id, |action| {
                    action.status = ActionStatus::Executed;
                    action.executed_at = Some(event.timestamp);
                    action.updated_at = event.timestamp;
                })?;
            }
            EventKind::ActionFailed { action_id, .. } => {
                self.mutate_action(action_id, |action| {
                    action.status = ActionStatus::Failed;
                    action.updated_at = event.timestamp;
                })?;
            }
            EventKind::ActionCancelled { action_id, .. } => {
                self.mutate_action(action_id, |action| {
                    action.status = ActionStatus::Cancelled;
                    action.updated_at = event.timestamp;
                })?;
            }
            EventKind::OutcomeObserved { outcome } => {
                self.insert_outcome(outcome.clone())?;
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

    fn insert_action(&mut self, action: Action) {
        let action_id = action.id.clone();
        if let Some(existing) = self.actions.get(&action_id).cloned() {
            self.remove_action_indexes(&existing);
        }
        self.actions.insert(action_id.clone(), action);
        if let Some(inserted) = self.actions.get(&action_id).cloned() {
            self.insert_action_indexes(&inserted);
        }
    }

    fn insert_outcome(&mut self, outcome: Outcome) -> Result<()> {
        if !self.actions.contains_key(&outcome.action_id) {
            return Err(HydraError::QueryError(format!(
                "unknown action for outcome: {}",
                outcome.action_id
            )));
        }
        let outcome_id = outcome.id.clone();
        let action_id = outcome.action_id.clone();
        if let Some(existing) = self.outcomes.get(&outcome_id).cloned() {
            self.remove_outcome_indexes(&existing);
        }
        self.outcomes.insert(outcome_id.clone(), outcome);
        self.outcomes_by_action
            .entry(action_id)
            .or_default()
            .insert(outcome_id);
        Ok(())
    }

    fn mutate_action<F>(&mut self, action_id: &ActionId, mutation: F) -> Result<()>
    where
        F: FnOnce(&mut Action),
    {
        let mut action = self
            .actions
            .remove(action_id)
            .ok_or_else(|| HydraError::QueryError(format!("unknown action: {}", action_id)))?;
        self.remove_action_indexes(&action);
        mutation(&mut action);
        self.insert_action_indexes(&action);
        self.actions.insert(action_id.clone(), action);
        Ok(())
    }

    fn insert_action_indexes(&mut self, action: &Action) {
        let action_id = action.id.clone();
        self.actions_by_status
            .entry(action.status.clone())
            .or_default()
            .insert(action_id.clone());
        for target in &action.targets {
            self.actions_by_target
                .entry(ActionTargetKey::from(target))
                .or_default()
                .insert(action_id.clone());
        }
        for claim_id in &action.related_claims {
            self.actions_by_claim
                .entry(claim_id.clone())
                .or_default()
                .insert(action_id.clone());
        }
    }

    fn remove_action_indexes(&mut self, action: &Action) {
        let action_id = &action.id;
        remove_from_index(&mut self.actions_by_status, &action.status, action_id);
        for target in &action.targets {
            let key = ActionTargetKey::from(target);
            remove_from_index(&mut self.actions_by_target, &key, action_id);
        }
        for claim_id in &action.related_claims {
            remove_from_index(&mut self.actions_by_claim, claim_id, action_id);
        }
    }

    fn remove_outcome_indexes(&mut self, outcome: &Outcome) {
        remove_from_index(
            &mut self.outcomes_by_action,
            &outcome.action_id,
            &outcome.id,
        );
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
        ActionKind, ActorId, CascadeId, ClaimId, EventId, OutcomeKind, TenantId, Value,
    };
    use std::collections::HashMap;

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_action_store_test")
    }

    fn actor() -> ActorId {
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

    fn action() -> Action {
        let now = chrono::Utc::now();
        let mut payload = HashMap::new();
        payload.insert(
            "reason".to_string(),
            Value::String("dataset freshness anomaly".to_string()),
        );
        Action {
            id: ActionId::new(),
            tenant_id: Some(tenant()),
            kind: ActionKind::Backfill,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::Dataset(
                "analytics.public.revenue_daily".to_string(),
            )],
            related_claims: vec![ClaimId::new()],
            supporting_evidence: vec![],
            proposed_by: actor(),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        }
    }

    fn outcome(action_id: ActionId) -> Outcome {
        let now = chrono::Utc::now();
        let mut impact = HashMap::new();
        impact.insert("freshness_restored".to_string(), Value::Bool(true));
        Outcome {
            id: OutcomeId::new(),
            tenant_id: Some(tenant()),
            action_id,
            kind: OutcomeKind::Success,
            observed_events: vec![],
            updated_claims: vec![],
            produced_evidence: vec![],
            impact,
            observed_at: now,
            recorded_at: now,
            recorded_by: actor(),
            caused_by: None,
        }
    }

    #[test]
    fn stores_proposed_action() {
        let mut store = ActionStore::new();
        let action = action();
        let action_id = action.id.clone();
        store
            .apply_event(&event(EventKind::ActionProposed {
                action: action.clone(),
            }))
            .unwrap();
        assert_eq!(store.action_count(), 1);
        assert_eq!(store.outcome_count(), 0);
        assert_eq!(store.action(&action_id), Some(&action));
        assert_eq!(store.proposed_actions().len(), 1);
    }

    #[test]
    fn transitions_action_lifecycle() {
        let mut store = ActionStore::new();
        let action = action();
        let action_id = action.id.clone();
        store
            .apply_event(&event(EventKind::ActionProposed { action }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ActionApproved {
                action_id: action_id.clone(),
                approved_by: actor(),
                reason: None,
            }))
            .unwrap();
        let approved = store.action(&action_id).unwrap();
        assert_eq!(approved.status, ActionStatus::Approved);
        assert_eq!(approved.approved_by, Some(actor()));
        assert!(approved.approved_at.is_some());

        store
            .apply_event(&event(EventKind::ActionExecuting {
                action_id: action_id.clone(),
            }))
            .unwrap();
        assert_eq!(
            store.action(&action_id).unwrap().status,
            ActionStatus::Executing
        );

        store
            .apply_event(&event(EventKind::ActionExecuted {
                action_id: action_id.clone(),
            }))
            .unwrap();
        let executed = store.action(&action_id).unwrap();
        assert_eq!(executed.status, ActionStatus::Executed);
        assert!(executed.executed_at.is_some());
        assert_eq!(store.executed_actions().len(), 1);
    }

    #[test]
    fn stores_outcome_for_action() {
        let mut store = ActionStore::new();
        let action = action();
        let action_id = action.id.clone();
        store
            .apply_event(&event(EventKind::ActionProposed { action }))
            .unwrap();
        let outcome = outcome(action_id.clone());
        let outcome_id = outcome.id.clone();
        store
            .apply_event(&event(EventKind::OutcomeObserved {
                outcome: outcome.clone(),
            }))
            .unwrap();
        assert_eq!(store.outcome_count(), 1);
        assert_eq!(store.outcome(&outcome_id), Some(&outcome));
        assert_eq!(store.outcomes_for_action(&action_id).len(), 1);
    }

    #[test]
    fn rejects_outcome_for_unknown_action() {
        let mut store = ActionStore::new();
        let outcome = outcome(ActionId::new());
        let result = store.apply_event(&event(EventKind::OutcomeObserved { outcome }));
        assert!(result.is_err());
    }

    #[test]
    fn indexes_actions_by_target_and_claim() {
        let mut store = ActionStore::new();
        let action = action();
        let target = action.targets[0].clone();
        let claim_id = action.related_claims[0].clone();
        store
            .apply_event(&event(EventKind::ActionProposed {
                action: action.clone(),
            }))
            .unwrap();
        assert_eq!(store.actions_for_target(&target).len(), 1);
        assert_eq!(store.actions_for_claim(&claim_id).len(), 1);
        assert_eq!(store.actions_for_target(&target)[0].id, action.id);
        assert_eq!(store.actions_for_claim(&claim_id)[0].id, action.id);
    }

    #[test]
    fn failed_and_cancelled_actions_are_indexed() {
        let mut store = ActionStore::new();
        let failed = action();
        let failed_id = failed.id.clone();
        store
            .apply_event(&event(EventKind::ActionProposed { action: failed }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ActionFailed {
                action_id: failed_id.clone(),
                reason: "pipeline permission denied".to_string(),
            }))
            .unwrap();
        assert_eq!(store.failed_actions().len(), 1);

        let cancelled = action();
        let cancelled_id = cancelled.id.clone();
        store
            .apply_event(&event(EventKind::ActionProposed { action: cancelled }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ActionCancelled {
                action_id: cancelled_id,
                cancelled_by: actor(),
                reason: Some("manual override".to_string()),
            }))
            .unwrap();
        assert_eq!(store.cancelled_actions().len(), 1);
    }
}
