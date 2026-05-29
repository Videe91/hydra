use hydra_core::{
    Action, ActionKind, ActionStatus, ActorId, Event, EventKind, Outcome, OutcomeId, OutcomeKind,
    Value,
};
use std::collections::HashMap;

use crate::action_store::ActionStore;

/// Deterministic agent that turns executed actions into observed outcomes.
///
/// Important:
/// This agent does not mutate Hydra state directly.
/// It only emits EventKind values. ActionStore materializes outcomes later
/// from OutcomeObserved events.
///
/// v0 behavior:
/// - Reacts only to ActionExecuted.
/// - Looks up the action in ActionStore.
/// - For Backfill actions, emits OutcomeObserved { kind: Unknown }.
///
/// Why Unknown?
/// ActionExecuted means the action ran. It does not prove the action worked.
/// Success should be inferred later from fresh evidence, such as:
/// - dataset freshness restored
/// - validation passed
/// - stale claim retracted
#[derive(Debug, Clone)]
pub struct OutcomeAgent {
    actor_id: ActorId,
}

impl OutcomeAgent {
    pub fn new(actor_id: ActorId) -> Self {
        Self { actor_id }
    }

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    /// React to a full event.
    ///
    /// Currently this only reacts to ActionExecuted.
    pub fn react(&self, event: &Event, action_store: &ActionStore) -> Vec<EventKind> {
        self.react_to_kind(&event.kind, action_store)
    }

    /// React to an EventKind.
    pub fn react_to_kind(&self, kind: &EventKind, action_store: &ActionStore) -> Vec<EventKind> {
        match kind {
            EventKind::ActionExecuted { action_id } => {
                let Some(action) = action_store.action(action_id) else {
                    return vec![self.signal(
                        "outcome_missing_action",
                        Some(action_id.to_string()),
                        vec![
                            "ActionExecuted referenced an action missing from ActionStore"
                                .to_string(),
                        ],
                    )];
                };
                self.outcomes_for_executed_action(action)
            }
            _ => Vec::new(),
        }
    }

    /// Convert an executed action into outcome events.
    ///
    /// v0 only handles:
    /// - action.status == Executed
    /// - action.kind == Backfill
    ///
    /// Output:
    /// OutcomeObserved { kind: Unknown }
    pub fn outcomes_for_executed_action(&self, action: &Action) -> Vec<EventKind> {
        if action.status != ActionStatus::Executed {
            return Vec::new();
        }
        if action.kind != ActionKind::Backfill {
            return Vec::new();
        }

        let now = chrono::Utc::now();
        let mut impact = HashMap::new();
        impact.insert(
            "reason".to_string(),
            Value::String(
                "backfill action executed; outcome requires confirming evidence".to_string(),
            ),
        );
        impact.insert(
            "action_kind".to_string(),
            Value::String("backfill".to_string()),
        );

        let outcome = Outcome {
            id: OutcomeId::new(),
            tenant_id: action.tenant_id.clone(),
            action_id: action.id.clone(),
            kind: OutcomeKind::Unknown,
            observed_events: vec![],
            updated_claims: action.related_claims.clone(),
            produced_evidence: vec![],
            impact,
            observed_at: now,
            recorded_at: now,
            recorded_by: self.actor_id.clone(),
            caused_by: None,
        };

        vec![EventKind::OutcomeObserved { outcome }]
    }

    fn signal(&self, name: &str, action_id: Option<String>, reasons: Vec<String>) -> EventKind {
        let mut payload = HashMap::new();
        payload.insert("agent".to_string(), Value::String(self.actor_id.to_string()));
        if let Some(action_id) = action_id {
            payload.insert("action_id".to_string(), Value::String(action_id));
        }
        payload.insert(
            "reasons".to_string(),
            Value::List(reasons.into_iter().map(Value::String).collect()),
        );
        EventKind::Signal {
            source: hydra_core::NodeId::from_str("hydra.outcome_agent"),
            name: name.to_string(),
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_store::ActionStore;
    use hydra_core::{
        Action, ActionId, ActionTarget, CascadeId, ClaimId, EventId, TenantId,
    };

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_outcome_agent_test")
    }

    fn actor() -> ActorId {
        ActorId::from_str("actor_sentinel")
    }

    fn prometheus() -> ActorId {
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

    fn backfill_action(status: ActionStatus) -> Action {
        let now = chrono::Utc::now();
        let executed_at = if status == ActionStatus::Executed {
            Some(now)
        } else {
            None
        };
        let mut payload = HashMap::new();
        payload.insert(
            "reason".to_string(),
            Value::String("verified dataset freshness anomaly".to_string()),
        );
        Action {
            id: ActionId::new(),
            tenant_id: Some(tenant()),
            kind: ActionKind::Backfill,
            status,
            targets: vec![ActionTarget::Dataset(
                "analytics.public.revenue_daily".to_string(),
            )],
            related_claims: vec![ClaimId::new()],
            supporting_evidence: vec![],
            proposed_by: prometheus(),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at,
            caused_by: None,
        }
    }

    fn notify_action(status: ActionStatus) -> Action {
        let mut action = backfill_action(status);
        action.kind = ActionKind::Notify;
        action
    }

    fn store_with_action(action: Action) -> ActionStore {
        let mut store = ActionStore::new();
        let action_id = action.id.clone();
        store
            .apply_event(&event(EventKind::ActionProposed {
                action: action.clone(),
            }))
            .unwrap();
        match action.status {
            ActionStatus::Approved => {
                store
                    .apply_event(&event(EventKind::ActionApproved {
                        action_id,
                        approved_by: prometheus(),
                        reason: None,
                    }))
                    .unwrap();
            }
            ActionStatus::Executing => {
                store
                    .apply_event(&event(EventKind::ActionExecuting { action_id }))
                    .unwrap();
            }
            ActionStatus::Executed => {
                store
                    .apply_event(&event(EventKind::ActionExecuted { action_id }))
                    .unwrap();
            }
            ActionStatus::Failed => {
                store
                    .apply_event(&event(EventKind::ActionFailed {
                        action_id,
                        reason: "test failure".to_string(),
                    }))
                    .unwrap();
            }
            ActionStatus::Cancelled => {
                store
                    .apply_event(&event(EventKind::ActionCancelled {
                        action_id,
                        cancelled_by: prometheus(),
                        reason: Some("test cancel".to_string()),
                    }))
                    .unwrap();
            }
            ActionStatus::Proposed | ActionStatus::Rejected => {}
        }
        store
    }

    #[test]
    fn emits_unknown_outcome_for_executed_backfill_action() {
        let action = backfill_action(ActionStatus::Executed);
        let action_id = action.id.clone();
        let store = store_with_action(action);
        let agent = OutcomeAgent::new(actor());
        let events = agent.react_to_kind(
            &EventKind::ActionExecuted {
                action_id: action_id.clone(),
            },
            &store,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            EventKind::OutcomeObserved { outcome } => {
                assert_eq!(outcome.action_id, action_id);
                assert_eq!(outcome.kind, OutcomeKind::Unknown);
                assert_eq!(outcome.recorded_by, actor());
                assert_eq!(outcome.updated_claims.len(), 1);
            }
            other => panic!("expected OutcomeObserved, got {other:?}"),
        }
    }

    #[test]
    fn noops_for_unexecuted_backfill_action() {
        let action = backfill_action(ActionStatus::Proposed);
        let action_id = action.id.clone();
        let store = store_with_action(action);
        let agent = OutcomeAgent::new(actor());
        let events = agent.react_to_kind(
            &EventKind::ActionExecuted { action_id },
            &store,
        );
        // The store still has the action as Proposed, so outcome emission is blocked.
        assert!(events.is_empty());
    }

    #[test]
    fn noops_for_non_backfill_action() {
        let action = notify_action(ActionStatus::Executed);
        let action_id = action.id.clone();
        let store = store_with_action(action);
        let agent = OutcomeAgent::new(actor());
        let events = agent.react_to_kind(
            &EventKind::ActionExecuted { action_id },
            &store,
        );
        assert!(events.is_empty());
    }

    #[test]
    fn emits_signal_when_action_executed_references_missing_action() {
        let store = ActionStore::new();
        let missing_action_id = ActionId::new();
        let agent = OutcomeAgent::new(actor());
        let events = agent.react_to_kind(
            &EventKind::ActionExecuted {
                action_id: missing_action_id.clone(),
            },
            &store,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            EventKind::Signal { name, payload, .. } => {
                assert_eq!(name, "outcome_missing_action");
                assert_eq!(
                    payload.get("action_id"),
                    Some(&Value::String(missing_action_id.to_string()))
                );
            }
            other => panic!("expected Signal, got {other:?}"),
        }
    }

    #[test]
    fn noops_for_non_action_executed_events() {
        let action = backfill_action(ActionStatus::Executed);
        let store = store_with_action(action.clone());
        let agent = OutcomeAgent::new(actor());
        let events = agent.react_to_kind(
            &EventKind::ActionProposed { action },
            &store,
        );
        assert!(events.is_empty());
    }
}
