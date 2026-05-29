use crate::action_store::ActionStore;
use crate::epistemic_store::EpistemicStore;
use crate::outcome_agent::OutcomeAgent;
use crate::policy_agent::PolicyAgent;
use crate::policy_engine::PolicyEngine;
use crate::policy_store::PolicyStore;
use crate::projection::Projection;
use crate::reflex::{ReflexContext, ReflexRegistry};
use crate::registry::SubscriptionRegistry;
use crate::remediation_agent::RemediationAgent;
use crate::verification::VerificationEngine;
use crate::verification_agent::VerificationAgent;
use hydra_core::event::{Event, EventKind};
use std::collections::VecDeque;

/// Configuration for the cascade engine
#[derive(Debug, Clone)]
pub struct CascadeConfig {
    /// Maximum cascade depth before killing the cascade
    pub max_depth: u32,
    /// Maximum total events in a single cascade
    pub max_events: usize,
}

impl Default for CascadeConfig {
    fn default() -> Self {
        Self {
            max_depth: 50,
            max_events: 10_000,
        }
    }
}

/// The result of processing a cascade
#[derive(Debug)]
pub struct CascadeResult {
    /// All events produced in this cascade (trigger + reactions), in order
    pub events: Vec<Event>,
    /// How many events mutated the graph state
    pub mutations: usize,
    /// Peak depth reached
    pub max_depth_reached: u32,
    /// Whether the cascade was killed due to depth/event limit
    pub truncated: bool,
}

impl CascadeResult {
    /// Reconstruct a CascadeResult from already-committed events.
    ///
    /// Used for idempotent replay responses: when an IdempotencyKey already
    /// maps to a committed batch, Hydra must not rerun the cascade. It returns
    /// the original events as a response envelope instead.
    ///
    /// Mutation count is not persisted in CommitBatch v0, so this returns 0.
    /// Later we can store cascade summary metadata in CommitBatch.
    pub fn from_committed_events(events: Vec<Event>) -> Self {
        let max_depth_reached = events
            .iter()
            .map(|event| event.cascade_depth)
            .max()
            .unwrap_or(0);
        Self {
            events,
            mutations: 0,
            max_depth_reached,
            truncated: false,
        }
    }
}

/// The cascade engine. Processes events breadth-first through subscriptions.
///
/// Processing model:
/// 1. Receive trigger event
/// 2. Apply it to the projection (mutate graph state)
/// 3. Check all subscriptions against the event
/// 4. Matching handlers produce new EventKind values
/// 5. Wrap them as reaction events (with causal links to the triggering event)
/// 6. Enqueue reactions
/// 7. Process next event from queue (goto step 2)
/// 8. Repeat until queue is empty or limits are hit
///
/// This is 100% synchronous and deterministic.
/// Given the same initial state + same trigger event + same subscriptions,
/// the cascade produces the exact same sequence of events every time.
pub struct CascadeEngine {
    config: CascadeConfig,
}

impl CascadeEngine {
    pub fn new(config: CascadeConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self {
            config: CascadeConfig::default(),
        }
    }

    /// Process a trigger event through the cascade.
    /// Applies the event to the projection and fires all matching subscriptions.
    /// Reactions are processed breadth-first until the cascade completes.
    pub fn process(
        &self,
        trigger: Event,
        projection: &mut Projection,
        registry: &SubscriptionRegistry,
    ) -> hydra_core::error::Result<CascadeResult> {
        let mut queue: VecDeque<Event> = VecDeque::new();
        let mut result = CascadeResult {
            events: Vec::new(),
            mutations: 0,
            max_depth_reached: 0,
            truncated: false,
        };

        queue.push_back(trigger);

        while let Some(event) = queue.pop_front() {
            // Check limits
            if event.cascade_depth > self.config.max_depth {
                result.truncated = true;
                break;
            }
            if result.events.len() >= self.config.max_events {
                result.truncated = true;
                break;
            }

            // Track max depth
            if event.cascade_depth > result.max_depth_reached {
                result.max_depth_reached = event.cascade_depth;
            }

            // Step 1: Apply event to projection (mutate graph state)
            let mutated = projection.apply(&event)?;
            if mutated {
                result.mutations += 1;
            }

            // Step 2: Find all matching subscriptions, sorted by priority (high first)
            let matching = registry.matching_subscriptions(&event);

            // Step 3: Fire handlers, collect reaction EventKinds.
            // Handlers are wrapped in catch_unwind to prevent a panicking handler
            // from killing the entire cascade. A panicking handler is skipped.
            let mut reaction_kinds: Vec<EventKind> = Vec::new();
            for sub in &matching {
                let handler_result = std::panic::catch_unwind(
                    std::panic::AssertUnwindSafe(|| {
                        sub.handler.handle(&event, projection)
                    })
                );
                match handler_result {
                    Ok(new_kinds) => reaction_kinds.extend(new_kinds),
                    Err(_) => {
                        // Handler panicked — skip it, continue with other subscriptions.
                        // In production, this would be logged/alerted.
                    }
                }
            }

            // Step 4: Wrap as reaction events with causal links and breadth indices
            for (breadth_index, kind) in reaction_kinds.into_iter().enumerate() {
                let mut reaction = Event::reaction(kind, &event);
                reaction.cascade_breadth_index = breadth_index as u32;
                queue.push_back(reaction);
            }

            // Record this event
            result.events.push(event);
        }

        Ok(result)
    }

    /// Process a trigger event through the cascade with the epistemic trust
    /// reflex enabled.
    ///
    /// This is the first "living trust" path:
    ///
    /// ClaimProposed
    ///   → EpistemicStore materializes the claim
    ///   → VerificationAgent evaluates it through VerificationEngine
    ///   → ClaimVerified / ClaimSupported / ClaimDisputed / Signal is emitted
    ///
    /// The generated events still re-enter the same cascade queue, so causality,
    /// depth, breadth index, and truncation limits are preserved.
    ///
    /// Important:
    /// If callers use this method, they should not apply the same cascade events
    /// to EpistemicStore again after the cascade completes, or the store will be
    /// updated twice. Recovery/replay code should still rebuild EpistemicStore
    /// from stored events normally.
    pub fn process_with_epistemics(
        &self,
        trigger: Event,
        projection: &mut Projection,
        registry: &SubscriptionRegistry,
        epistemic_store: &mut EpistemicStore,
        verification_engine: &VerificationEngine,
        verification_agent: &VerificationAgent,
        remediation_agent: &RemediationAgent,
        action_store: &mut ActionStore,
        outcome_agent: &OutcomeAgent,
        policy_store: &mut PolicyStore,
        policy_engine: &PolicyEngine,
        policy_agent: &PolicyAgent,
        reflex_registry: &ReflexRegistry,
    ) -> hydra_core::error::Result<CascadeResult> {
        let mut queue: VecDeque<Event> = VecDeque::new();
        let mut result = CascadeResult {
            events: Vec::new(),
            mutations: 0,
            max_depth_reached: 0,
            truncated: false,
        };

        queue.push_back(trigger);

        while let Some(event) = queue.pop_front() {
            if event.cascade_depth > self.config.max_depth {
                result.truncated = true;
                break;
            }
            if result.events.len() >= self.config.max_events {
                result.truncated = true;
                break;
            }
            if event.cascade_depth > result.max_depth_reached {
                result.max_depth_reached = event.cascade_depth;
            }

            // 1. Apply graph-topology mutation.
            let mutated = projection.apply(&event)?;
            if mutated {
                result.mutations += 1;
            }

            // 2. Apply epistemic mutation before verification reacts.
            //
            // This matters for ClaimProposed:
            // the claim must be visible in EpistemicStore before the verifier
            // evaluates it by ID.
            epistemic_store.apply_event(&event)?;

            // 2b. Apply action-layer mutation before outcome agent reacts.
            //
            // Mirrors the epistemic store pattern: ActionExecuted must mark the
            // action as Executed in ActionStore before the outcome agent looks
            // up the action by ID and decides whether to emit OutcomeObserved.
            action_store.apply_event(&event)?;

            // 2c. Apply governance-layer mutation before policy agent reacts.
            //
            // ActionProposed has already touched ActionStore; PolicyAgent now
            // sees the materialized action when it evaluates policy. Policy
            // lifecycle events (PolicyRegistered/PolicyDecisionRecorded/
            // ApprovalRequested/Granted/Rejected/Cancelled) are also applied
            // here so reflexes downstream see consistent state.
            policy_store.apply_event(&event)?;

            // 3. Existing registry subscriptions.
            let matching = registry.matching_subscriptions(&event);
            let mut reaction_kinds: Vec<EventKind> = Vec::new();
            for sub in &matching {
                let handler_result = std::panic::catch_unwind(
                    std::panic::AssertUnwindSafe(|| sub.handler.handle(&event, projection)),
                );
                match handler_result {
                    Ok(new_kinds) => reaction_kinds.extend(new_kinds),
                    Err(_) => {
                        // Handler panicked — skip it, continue with other subscriptions.
                        // In production this should be surfaced as an engine diagnostic.
                    }
                }
            }

            // 4. Built-in epistemic verification reflex.
            //
            // This is intentionally implemented as EventKind generation, not direct
            // mutation. Trust transitions remain event-sourced.
            reaction_kinds.extend(verification_agent.react(
                &event,
                epistemic_store,
                verification_engine,
            ));

            // 5. Built-in remediation reflex (ARGUS → PROMETHEUS).
            //
            // Turns verified claims into proposed actions. Also event-sourced —
            // emits ActionProposed (or recovery Signals), never mutates state.
            reaction_kinds.extend(remediation_agent.react(&event, epistemic_store));

            // 5b. Built-in policy reflex (governance gate).
            //
            // Turns proposed actions into PolicyDecisionRecorded + one of
            // ActionApproved / ApprovalRequested / ActionRejected / Signal.
            // Runs after remediation so it can immediately gate the
            // ActionProposed that remediation just emitted.
            reaction_kinds.extend(policy_agent.react(
                &event,
                action_store,
                policy_store,
                policy_engine,
            ));

            // 6. Built-in outcome reflex (PROMETHEUS → SENTINEL).
            //
            // Turns executed actions into observed outcomes. Conservative by
            // design — emits OutcomeObserved { kind: Unknown } until fresh
            // evidence proves success.
            reaction_kinds.extend(outcome_agent.react(&event, action_store));

            // 7. Generic programmable reflex registry.
            //
            // User-defined reflexes get read-only access to projection /
            // epistemic store / action store / verification engine. They emit
            // EventKind reactions only — never mutate state.
            let reflex_context = ReflexContext::new(
                projection,
                epistemic_store,
                action_store,
                verification_engine,
            );
            reaction_kinds.extend(reflex_registry.react(&event, &reflex_context));

            // 8. Wrap reactions with causal links.
            for (breadth_index, kind) in reaction_kinds.into_iter().enumerate() {
                let mut reaction = Event::reaction(kind, &event);
                reaction.cascade_breadth_index = breadth_index as u32;
                queue.push_back(reaction);
            }

            result.events.push(event);
        }

        Ok(result)
    }

    /// Process a raw EventKind as a new trigger (creates the Event wrapper)
    pub fn trigger(
        &self,
        kind: EventKind,
        projection: &mut Projection,
        registry: &SubscriptionRegistry,
    ) -> hydra_core::error::Result<CascadeResult> {
        let event = Event::trigger(kind);
        self.process(event, projection, registry)
    }

    /// Process a raw EventKind as a new trigger with the epistemic trust reflex.
    pub fn trigger_with_epistemics(
        &self,
        kind: EventKind,
        projection: &mut Projection,
        registry: &SubscriptionRegistry,
        epistemic_store: &mut EpistemicStore,
        verification_engine: &VerificationEngine,
        verification_agent: &VerificationAgent,
        remediation_agent: &RemediationAgent,
        action_store: &mut ActionStore,
        outcome_agent: &OutcomeAgent,
        policy_store: &mut PolicyStore,
        policy_engine: &PolicyEngine,
        policy_agent: &PolicyAgent,
        reflex_registry: &ReflexRegistry,
    ) -> hydra_core::error::Result<CascadeResult> {
        let event = Event::trigger(kind);
        self.process_with_epistemics(
            event,
            projection,
            registry,
            epistemic_store,
            verification_engine,
            verification_agent,
            remediation_agent,
            action_store,
            outcome_agent,
            policy_store,
            policy_engine,
            policy_agent,
            reflex_registry,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_store::ActionStore;
    use crate::epistemic_store::EpistemicStore;
    use crate::outcome_agent::OutcomeAgent;
    use crate::policy_agent::PolicyAgent;
    use crate::policy_engine::PolicyEngine;
    use crate::policy_store::PolicyStore;
    use crate::reflex::ReflexRegistry;
    use crate::registry::SubscriptionRegistry;
    use crate::remediation_agent::RemediationAgent;
    use crate::verification::VerificationEngine;
    use crate::verification_agent::VerificationAgent;
    use hydra_core::event::Value;
    use hydra_core::graph::GraphReader;
    use hydra_core::id::{EventId, NodeId};
    use hydra_core::subscription::{EventFilter, Subscription, SubscriptionHandler};
    use hydra_core::{
        ActionKind, ActorId, Claim, ClaimId, ClaimKind, ClaimObject, ClaimStatus, ClaimSubject,
        Confidence, Evidence, EvidenceId, EvidencePayload, EvidenceSource, TenantId,
    };
    use std::collections::HashMap;

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_epistemic_cascade_test")
    }

    fn verifier_actor() -> ActorId {
        ActorId::from_str("actor_verifier")
    }

    fn evidence_with_reliability(reliability: f64) -> Evidence {
        let mut data = HashMap::new();
        data.insert(
            "dataset".to_string(),
            Value::String("analytics.public.revenue_daily".to_string()),
        );
        data.insert("freshness_lag_hours".to_string(), Value::Float(7.0));
        Evidence {
            id: EvidenceId::new(),
            tenant_id: Some(tenant()),
            source: EvidenceSource::Warehouse {
                system: "snowflake".to_string(),
                database: Some("analytics".to_string()),
                schema: Some("public".to_string()),
                table: Some("revenue_daily".to_string()),
            },
            payload: EvidencePayload {
                kind: "freshness_check".to_string(),
                data,
            },
            reliability: Confidence::new(reliability),
            observed_at: chrono::Utc::now(),
            recorded_at: chrono::Utc::now(),
            caused_by: None,
        }
    }

    fn claim_with_evidence(evidence_id: EvidenceId, confidence: f64) -> Claim {
        let now = chrono::Utc::now();
        Claim {
            id: ClaimId::new(),
            tenant_id: Some(tenant()),
            kind: ClaimKind::AnomalyFinding,
            subject: ClaimSubject::Dataset("analytics.public.revenue_daily".to_string()),
            predicate: "is_stale".to_string(),
            object: ClaimObject::Value(Value::Bool(true)),
            confidence: Confidence::new(confidence),
            status: ClaimStatus::Proposed,
            evidence_for: vec![evidence_id],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: verifier_actor(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    #[test]
    fn epistemic_cascade_verifies_claim_proposed() {
        let engine = CascadeEngine::with_defaults();
        let mut projection = Projection::new();
        let registry = SubscriptionRegistry::new();
        let mut epistemic_store = EpistemicStore::new();
        let verification_engine = VerificationEngine::with_default_policy();
        let verification_agent = VerificationAgent::new(verifier_actor());
        let remediation_agent =
            RemediationAgent::new(ActorId::from_str("actor_hydra_prometheus"));
        let mut action_store = ActionStore::new();
        let outcome_agent = OutcomeAgent::new(ActorId::from_str("actor_hydra_sentinel"));
        let mut policy_store = PolicyStore::new();
        let policy_engine = PolicyEngine::new();
        let policy_agent = PolicyAgent::new(
            ActorId::from_str("actor_hydra_policy"),
            ActorId::from_str("actor_hydra_approver"),
        );
        let reflex_registry = ReflexRegistry::new();

        let evidence = evidence_with_reliability(0.95);
        let claim = claim_with_evidence(evidence.id.clone(), 0.91);
        let claim_id = claim.id.clone();

        epistemic_store
            .apply_event(&Event::trigger(EventKind::EvidenceAdded { evidence }))
            .unwrap();

        let result = engine
            .trigger_with_epistemics(
                EventKind::ClaimProposed { claim },
                &mut projection,
                &registry,
                &mut epistemic_store,
                &verification_engine,
                &verification_agent,
                &remediation_agent,
                &mut action_store,
                &outcome_agent,
                &mut policy_store,
                &policy_engine,
                &policy_agent,
                &reflex_registry,
            )
            .unwrap();

        // ClaimProposed → ClaimVerified (verification agent) → ActionProposed
        // (remediation agent) → PolicyDecisionRecorded + ActionApproved
        // (policy agent, Allow because no matching policy).
        assert_eq!(result.events.len(), 5);
        assert_eq!(result.mutations, 0);
        assert_eq!(result.max_depth_reached, 3);

        assert!(matches!(
            result.events[0].kind,
            EventKind::ClaimProposed { .. }
        ));
        match &result.events[1].kind {
            EventKind::ClaimVerified {
                claim_id: verified_claim_id,
                verified_by,
            } => {
                assert_eq!(verified_claim_id, &claim_id);
                assert_eq!(verified_by, &verifier_actor());
            }
            other => panic!("expected ClaimVerified, got {other:?}"),
        }
        match &result.events[2].kind {
            EventKind::ActionProposed { action } => {
                assert_eq!(action.kind, ActionKind::Backfill);
                assert_eq!(action.related_claims, vec![claim_id.clone()]);
            }
            other => panic!("expected ActionProposed, got {other:?}"),
        }
        assert!(matches!(
            result.events[3].kind,
            EventKind::PolicyDecisionRecorded { .. }
        ));
        assert!(matches!(
            result.events[4].kind,
            EventKind::ActionApproved { .. }
        ));

        let stored = epistemic_store.claim(&claim_id).unwrap();
        assert_eq!(stored.status, ClaimStatus::Verified);
        assert_eq!(result.events[1].caused_by, vec![result.events[0].id.clone()]);
        assert_eq!(result.events[2].caused_by, vec![result.events[1].id.clone()]);
        // PolicyDecisionRecorded and ActionApproved are both reactions to event[2] (ActionProposed)
        assert_eq!(result.events[3].caused_by, vec![result.events[2].id.clone()]);
        assert_eq!(result.events[4].caused_by, vec![result.events[2].id.clone()]);
        assert_eq!(result.events[0].cascade_id, result.events[1].cascade_id);
        assert_eq!(result.events[1].cascade_id, result.events[2].cascade_id);
        assert_eq!(result.events[2].cascade_id, result.events[3].cascade_id);
    }

    #[test]
    fn epistemic_cascade_supports_low_confidence_claim() {
        let engine = CascadeEngine::with_defaults();
        let mut projection = Projection::new();
        let registry = SubscriptionRegistry::new();
        let mut epistemic_store = EpistemicStore::new();
        let verification_engine = VerificationEngine::with_default_policy();
        let verification_agent = VerificationAgent::new(verifier_actor());
        let remediation_agent =
            RemediationAgent::new(ActorId::from_str("actor_hydra_prometheus"));
        let mut action_store = ActionStore::new();
        let outcome_agent = OutcomeAgent::new(ActorId::from_str("actor_hydra_sentinel"));
        let mut policy_store = PolicyStore::new();
        let policy_engine = PolicyEngine::new();
        let policy_agent = PolicyAgent::new(
            ActorId::from_str("actor_hydra_policy"),
            ActorId::from_str("actor_hydra_approver"),
        );
        let reflex_registry = ReflexRegistry::new();

        let evidence = evidence_with_reliability(0.95);
        let evidence_id = evidence.id.clone();
        let claim = claim_with_evidence(evidence_id.clone(), 0.60);
        let claim_id = claim.id.clone();

        epistemic_store
            .apply_event(&Event::trigger(EventKind::EvidenceAdded { evidence }))
            .unwrap();

        let result = engine
            .trigger_with_epistemics(
                EventKind::ClaimProposed { claim },
                &mut projection,
                &registry,
                &mut epistemic_store,
                &verification_engine,
                &verification_agent,
                &remediation_agent,
                &mut action_store,
                &outcome_agent,
                &mut policy_store,
                &policy_engine,
                &policy_agent,
                &reflex_registry,
            )
            .unwrap();

        assert_eq!(result.events.len(), 2);
        match &result.events[1].kind {
            EventKind::ClaimSupported {
                claim_id: supported_claim_id,
                evidence_id: supported_evidence_id,
            } => {
                assert_eq!(supported_claim_id, &claim_id);
                assert_eq!(supported_evidence_id, &evidence_id);
            }
            other => panic!("expected ClaimSupported, got {other:?}"),
        }

        let stored = epistemic_store.claim(&claim_id).unwrap();
        assert_eq!(stored.status, ClaimStatus::Supported);
        assert!(stored.evidence_for.contains(&evidence_id));
    }

    #[test]
    fn epistemic_cascade_emits_missing_evidence_signal() {
        let engine = CascadeEngine::with_defaults();
        let mut projection = Projection::new();
        let registry = SubscriptionRegistry::new();
        let mut epistemic_store = EpistemicStore::new();
        let verification_engine = VerificationEngine::with_default_policy();
        let verification_agent = VerificationAgent::new(verifier_actor());
        let remediation_agent =
            RemediationAgent::new(ActorId::from_str("actor_hydra_prometheus"));
        let mut action_store = ActionStore::new();
        let outcome_agent = OutcomeAgent::new(ActorId::from_str("actor_hydra_sentinel"));
        let mut policy_store = PolicyStore::new();
        let policy_engine = PolicyEngine::new();
        let policy_agent = PolicyAgent::new(
            ActorId::from_str("actor_hydra_policy"),
            ActorId::from_str("actor_hydra_approver"),
        );
        let reflex_registry = ReflexRegistry::new();

        let missing_evidence_id = EvidenceId::new();
        let claim = claim_with_evidence(missing_evidence_id.clone(), 0.91);
        let claim_id = claim.id.clone();

        let result = engine
            .trigger_with_epistemics(
                EventKind::ClaimProposed { claim },
                &mut projection,
                &registry,
                &mut epistemic_store,
                &verification_engine,
                &verification_agent,
                &remediation_agent,
                &mut action_store,
                &outcome_agent,
                &mut policy_store,
                &policy_engine,
                &policy_agent,
                &reflex_registry,
            )
            .unwrap();

        assert_eq!(result.events.len(), 2);
        match &result.events[1].kind {
            EventKind::Signal { name, payload, .. } => {
                assert_eq!(name, "claim_missing_evidence");
                assert_eq!(
                    payload.get("claim_id"),
                    Some(&Value::String(claim_id.to_string()))
                );
                assert_eq!(
                    payload.get("evidence_id"),
                    Some(&Value::String(missing_evidence_id.to_string()))
                );
            }
            other => panic!("expected claim_missing_evidence Signal, got {other:?}"),
        }

        let stored = epistemic_store.claim(&claim_id).unwrap();
        assert_eq!(stored.status, ClaimStatus::Proposed);
    }

    #[test]
    fn epistemic_cascade_observes_unknown_outcome_for_executed_backfill() {
        use hydra_core::{
            Action, ActionId, ActionKind, ActionStatus, ActionTarget, OutcomeKind,
        };

        let engine = CascadeEngine::with_defaults();
        let mut projection = Projection::new();
        let registry = SubscriptionRegistry::new();
        let mut epistemic_store = EpistemicStore::new();
        let verification_engine = VerificationEngine::with_default_policy();
        let verification_agent = VerificationAgent::new(verifier_actor());
        let remediation_agent =
            RemediationAgent::new(ActorId::from_str("actor_hydra_prometheus"));
        let mut action_store = ActionStore::new();
        let outcome_agent = OutcomeAgent::new(ActorId::from_str("actor_hydra_sentinel"));
        let mut policy_store = PolicyStore::new();
        let policy_engine = PolicyEngine::new();
        let policy_agent = PolicyAgent::new(
            ActorId::from_str("actor_hydra_policy"),
            ActorId::from_str("actor_hydra_approver"),
        );
        let reflex_registry = ReflexRegistry::new();

        let now = chrono::Utc::now();
        let action = Action {
            id: ActionId::new(),
            tenant_id: Some(tenant()),
            kind: ActionKind::Backfill,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::Dataset(
                "analytics.public.revenue_daily".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_hydra_prometheus"),
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
        let action_id = action.id.clone();
        action_store
            .apply_event(&Event::trigger(EventKind::ActionProposed { action }))
            .unwrap();

        let result = engine
            .trigger_with_epistemics(
                EventKind::ActionExecuted {
                    action_id: action_id.clone(),
                },
                &mut projection,
                &registry,
                &mut epistemic_store,
                &verification_engine,
                &verification_agent,
                &remediation_agent,
                &mut action_store,
                &outcome_agent,
                &mut policy_store,
                &policy_engine,
                &policy_agent,
                &reflex_registry,
            )
            .unwrap();

        assert_eq!(result.events.len(), 2);
        assert!(matches!(
            result.events[0].kind,
            EventKind::ActionExecuted { .. }
        ));
        match &result.events[1].kind {
            EventKind::OutcomeObserved { outcome } => {
                assert_eq!(outcome.action_id, action_id);
                assert_eq!(outcome.kind, OutcomeKind::Unknown);
            }
            other => panic!("expected OutcomeObserved, got {other:?}"),
        }
        assert_eq!(action_store.outcomes_for_action(&action_id).len(), 1);
    }

    #[test]
    fn policy_cascade_auto_approves_action_when_no_policy_matches() {
        use hydra_core::{
            Action, ActionId, ActionKind, ActionStatus, ActionTarget, PolicyDecisionKind,
        };

        let engine = CascadeEngine::with_defaults();
        let mut projection = Projection::new();
        let registry = SubscriptionRegistry::new();
        let mut epistemic_store = EpistemicStore::new();
        let verification_engine = VerificationEngine::with_default_policy();
        let verification_agent = VerificationAgent::new(verifier_actor());
        let remediation_agent =
            RemediationAgent::new(ActorId::from_str("actor_hydra_prometheus"));
        let mut action_store = ActionStore::new();
        let outcome_agent = OutcomeAgent::new(ActorId::from_str("actor_hydra_sentinel"));
        let mut policy_store = PolicyStore::new();
        let policy_engine = PolicyEngine::new();
        let policy_agent = PolicyAgent::new(
            ActorId::from_str("actor_hydra_policy"),
            ActorId::from_str("actor_hydra_approver"),
        );
        let reflex_registry = ReflexRegistry::new();

        let now = chrono::Utc::now();
        let action = Action {
            id: ActionId::new(),
            tenant_id: Some(tenant()),
            kind: ActionKind::Backfill,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::Dataset(
                "analytics.public.revenue_daily".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_prometheus"),
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
        let action_id = action.id.clone();

        let result = engine
            .trigger_with_epistemics(
                EventKind::ActionProposed { action },
                &mut projection,
                &registry,
                &mut epistemic_store,
                &verification_engine,
                &verification_agent,
                &remediation_agent,
                &mut action_store,
                &outcome_agent,
                &mut policy_store,
                &policy_engine,
                &policy_agent,
                &reflex_registry,
            )
            .unwrap();

        assert_eq!(result.events.len(), 3);
        assert!(matches!(result.events[0].kind, EventKind::ActionProposed { .. }));
        match &result.events[1].kind {
            EventKind::PolicyDecisionRecorded { decision } => {
                assert_eq!(decision.action_id, action_id);
                assert_eq!(decision.kind, PolicyDecisionKind::Allow);
            }
            other => panic!("expected PolicyDecisionRecorded, got {other:?}"),
        }
        match &result.events[2].kind {
            EventKind::ActionApproved {
                action_id: approved_action_id,
                ..
            } => {
                assert_eq!(approved_action_id, &action_id);
            }
            other => panic!("expected ActionApproved, got {other:?}"),
        }
        assert_eq!(
            action_store.action(&action_id).unwrap().status,
            ActionStatus::Approved
        );
        assert_eq!(policy_store.decisions_for_action(&action_id).len(), 1);
    }

    #[test]
    fn policy_cascade_requests_approval_for_matching_human_policy() {
        use hydra_core::{
            Action, ActionId, ActionKind, ActionStatus, ActionTarget, Policy, PolicyId, PolicyKind,
            PolicyScope, PolicyStatus,
        };

        let engine = CascadeEngine::with_defaults();
        let mut projection = Projection::new();
        let registry = SubscriptionRegistry::new();
        let mut epistemic_store = EpistemicStore::new();
        let verification_engine = VerificationEngine::with_default_policy();
        let verification_agent = VerificationAgent::new(verifier_actor());
        let remediation_agent =
            RemediationAgent::new(ActorId::from_str("actor_hydra_prometheus"));
        let mut action_store = ActionStore::new();
        let outcome_agent = OutcomeAgent::new(ActorId::from_str("actor_hydra_sentinel"));
        let mut policy_store = PolicyStore::new();
        let policy_engine = PolicyEngine::new();
        let approver = ActorId::from_str("actor_accountant");
        let policy_agent = PolicyAgent::new(
            ActorId::from_str("actor_hydra_policy"),
            approver.clone(),
        );
        let reflex_registry = ReflexRegistry::new();

        let now = chrono::Utc::now();
        let policy = Policy {
            id: PolicyId::new(),
            tenant_id: Some(tenant()),
            name: "Payroll approval required".to_string(),
            kind: PolicyKind::HumanApproval,
            status: PolicyStatus::Active,
            scope: PolicyScope::ActionKind("RunPayroll".to_string()),
            condition: HashMap::new(),
            metadata: HashMap::new(),
            created_by: ActorId::from_str("actor_policy_admin"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        policy_store
            .apply_event(&Event::trigger(EventKind::PolicyRegistered { policy }))
            .unwrap();

        let action = Action {
            id: ActionId::new(),
            tenant_id: Some(tenant()),
            kind: ActionKind::RunPayroll,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("payroll".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_payroll_agent"),
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
        let action_id = action.id.clone();

        let result = engine
            .trigger_with_epistemics(
                EventKind::ActionProposed { action },
                &mut projection,
                &registry,
                &mut epistemic_store,
                &verification_engine,
                &verification_agent,
                &remediation_agent,
                &mut action_store,
                &outcome_agent,
                &mut policy_store,
                &policy_engine,
                &policy_agent,
                &reflex_registry,
            )
            .unwrap();

        assert_eq!(result.events.len(), 3);
        assert!(matches!(result.events[0].kind, EventKind::ActionProposed { .. }));
        assert!(matches!(
            result.events[1].kind,
            EventKind::PolicyDecisionRecorded { .. }
        ));
        match &result.events[2].kind {
            EventKind::ApprovalRequested { request } => {
                assert_eq!(request.action_id, action_id);
                assert_eq!(request.requested_from, vec![approver]);
            }
            other => panic!("expected ApprovalRequested, got {other:?}"),
        }
        assert_eq!(
            action_store.action(&action_id).unwrap().status,
            ActionStatus::Proposed
        );
        assert_eq!(policy_store.decisions_for_action(&action_id).len(), 1);
        assert_eq!(policy_store.approvals_for_action(&action_id).len(), 1);
    }

    /// A handler that classifies new nodes by emitting a NodeUpdated event
    struct ClassifyHandler;
    impl SubscriptionHandler for ClassifyHandler {
        fn handle(
            &self,
            event: &Event,
            _graph: &dyn hydra_core::graph::GraphReader,
        ) -> Vec<EventKind> {
            if let EventKind::NodeCreated { node_id, .. } = &event.kind {
                vec![EventKind::NodeUpdated {
                    node_id: node_id.clone(),
                    changes: HashMap::from([(
                        "classified".to_string(),
                        Value::Bool(true),
                    )]),
                }]
            } else {
                vec![]
            }
        }
    }

    /// A handler that emits a signal when a node is classified
    struct AlertOnClassifyHandler;
    impl SubscriptionHandler for AlertOnClassifyHandler {
        fn handle(
            &self,
            event: &Event,
            graph: &dyn hydra_core::graph::GraphReader,
        ) -> Vec<EventKind> {
            if let EventKind::NodeUpdated { node_id, changes } = &event.kind {
                if changes.contains_key("classified") {
                    if let Some(node) = graph.node(node_id) {
                        return vec![EventKind::Signal {
                            name: "classified_alert".to_string(),
                            source: node_id.clone(),
                            payload: HashMap::from([(
                                "type".to_string(),
                                Value::String(node.type_id().to_string()),
                            )]),
                        }];
                    }
                }
            }
            vec![]
        }
    }

    /// A handler that would cause infinite recursion if depth limit didn't exist
    struct InfiniteHandler;
    impl SubscriptionHandler for InfiniteHandler {
        fn handle(
            &self,
            event: &Event,
            _graph: &dyn hydra_core::graph::GraphReader,
        ) -> Vec<EventKind> {
            if let EventKind::Signal { source, .. } = &event.kind {
                vec![EventKind::Signal {
                    name: "loop".to_string(),
                    source: source.clone(),
                    payload: HashMap::new(),
                }]
            } else {
                vec![]
            }
        }
    }

    #[test]
    fn simple_trigger_no_subscriptions() {
        let engine = CascadeEngine::with_defaults();
        let mut proj = Projection::new();
        let reg = SubscriptionRegistry::new();

        let result = engine
            .trigger(
                EventKind::NodeCreated {
                    node_id: NodeId::new(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                },
                &mut proj,
                &reg,
            )
            .unwrap();

        assert_eq!(result.events.len(), 1);
        assert_eq!(result.mutations, 1);
        assert_eq!(result.max_depth_reached, 0);
        assert!(!result.truncated);
        assert_eq!(proj.node_count(), 1);
    }

    #[test]
    fn cascade_classify_on_create() {
        let engine = CascadeEngine::with_defaults();
        let mut proj = Projection::new();
        let mut reg = SubscriptionRegistry::new();

        reg.register(Subscription::new(
            "classify",
            EventFilter::NodeCreated,
            100,
            Box::new(ClassifyHandler),
        ));

        let node_id = NodeId::new();
        let result = engine
            .trigger(
                EventKind::NodeCreated {
                    node_id: node_id.clone(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                },
                &mut proj,
                &reg,
            )
            .unwrap();

        // Trigger (NodeCreated) + Reaction (NodeUpdated)
        assert_eq!(result.events.len(), 2);
        assert_eq!(result.mutations, 2);
        assert_eq!(result.max_depth_reached, 1);

        // Verify the node was classified
        let node = proj.node(&node_id).unwrap();
        assert_eq!(node.get_bool("classified"), Some(true));
        assert_eq!(node.meta.version, 2); // created + updated
    }

    #[test]
    fn multi_level_cascade() {
        let engine = CascadeEngine::with_defaults();
        let mut proj = Projection::new();
        let mut reg = SubscriptionRegistry::new();

        // Level 1: NodeCreated → classify (NodeUpdated)
        reg.register(Subscription::new(
            "classify",
            EventFilter::NodeCreated,
            100,
            Box::new(ClassifyHandler),
        ));
        // Level 2: NodeUpdated(classified) → alert (Signal)
        reg.register(Subscription::new(
            "alert_on_classify",
            EventFilter::NodeUpdated,
            90,
            Box::new(AlertOnClassifyHandler),
        ));

        let node_id = NodeId::new();
        let result = engine
            .trigger(
                EventKind::NodeCreated {
                    node_id: node_id.clone(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                },
                &mut proj,
                &reg,
            )
            .unwrap();

        // Trigger (NodeCreated) → classify (NodeUpdated) → alert (Signal)
        assert_eq!(result.events.len(), 3);
        assert_eq!(result.max_depth_reached, 2);

        // Verify causal chain
        assert!(result.events[0].is_trigger());
        assert_eq!(result.events[1].caused_by, vec![result.events[0].id.clone()]);
        assert_eq!(result.events[2].caused_by, vec![result.events[1].id.clone()]);

        // All share the same cascade_id
        assert_eq!(result.events[0].cascade_id, result.events[1].cascade_id);
        assert_eq!(result.events[1].cascade_id, result.events[2].cascade_id);
    }

    #[test]
    fn depth_limit_stops_infinite_cascade() {
        let engine = CascadeEngine::new(CascadeConfig {
            max_depth: 5,
            max_events: 1000,
        });
        let mut proj = Projection::new();
        let mut reg = SubscriptionRegistry::new();

        // This handler re-emits a signal on every signal → infinite loop
        reg.register(Subscription::new(
            "infinite",
            EventFilter::SignalName("loop".to_string()),
            100,
            Box::new(InfiniteHandler),
        ));

        let node_id = NodeId::new();
        // First create the node so signals have a valid source
        proj.apply(&Event::trigger(EventKind::NodeCreated {
            node_id: node_id.clone(),
            type_id: "test".to_string(),
            properties: HashMap::new(),
        }))
        .unwrap();

        let result = engine
            .trigger(
                EventKind::Signal {
                    name: "loop".to_string(),
                    source: node_id,
                    payload: HashMap::new(),
                },
                &mut proj,
                &reg,
            )
            .unwrap();

        assert!(result.truncated);
        assert!(result.events.len() <= 7); // 0..5 depth + some extra
    }

    #[test]
    fn event_limit_stops_wide_cascade() {
        let engine = CascadeEngine::new(CascadeConfig {
            max_depth: 100,
            max_events: 5,
        });
        let mut proj = Projection::new();
        let mut reg = SubscriptionRegistry::new();

        /// Handler that emits 3 signals per signal (exponential growth)
        struct FanOutHandler;
        impl SubscriptionHandler for FanOutHandler {
            fn handle(
                &self,
                event: &Event,
                _graph: &dyn hydra_core::graph::GraphReader,
            ) -> Vec<EventKind> {
                if let EventKind::Signal { source, .. } = &event.kind {
                    (0..3)
                        .map(|i| EventKind::Signal {
                            name: format!("fan_{}", i),
                            source: source.clone(),
                            payload: HashMap::new(),
                        })
                        .collect()
                } else {
                    vec![]
                }
            }
        }

        reg.register(Subscription::new(
            "fanout",
            EventFilter::EventKindName("signal".to_string()),
            100,
            Box::new(FanOutHandler),
        ));

        let result = engine
            .trigger(
                EventKind::Signal {
                    name: "start".to_string(),
                    source: NodeId::new(),
                    payload: HashMap::new(),
                },
                &mut proj,
                &reg,
            )
            .unwrap();

        assert!(result.truncated);
        assert!(result.events.len() <= 5);
    }

    #[test]
    fn causal_links_form_proper_dag() {
        let engine = CascadeEngine::with_defaults();
        let mut proj = Projection::new();
        let mut reg = SubscriptionRegistry::new();

        reg.register(Subscription::new(
            "classify",
            EventFilter::NodeCreated,
            100,
            Box::new(ClassifyHandler),
        ));

        let result = engine
            .trigger(
                EventKind::NodeCreated {
                    node_id: NodeId::new(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                },
                &mut proj,
                &reg,
            )
            .unwrap();

        // Build a set of all event IDs
        let all_ids: std::collections::HashSet<EventId> =
            result.events.iter().map(|e| e.id.clone()).collect();

        // Every caused_by reference must point to an event in this cascade
        for event in &result.events {
            for parent_id in &event.caused_by {
                assert!(
                    all_ids.contains(parent_id),
                    "Event {} references non-existent parent {}",
                    event.id,
                    parent_id
                );
            }
        }
    }

    #[test]
    fn subscription_priority_determines_order() {
        let engine = CascadeEngine::with_defaults();
        let mut proj = Projection::new();
        let mut reg = SubscriptionRegistry::new();

        /// Records a marker property to prove execution order
        struct MarkerHandler {
            key: String,
        }
        impl SubscriptionHandler for MarkerHandler {
            fn handle(
                &self,
                event: &Event,
                _graph: &dyn hydra_core::graph::GraphReader,
            ) -> Vec<EventKind> {
                if let EventKind::NodeCreated { node_id, .. } = &event.kind {
                    vec![EventKind::NodeUpdated {
                        node_id: node_id.clone(),
                        changes: HashMap::from([(
                            self.key.clone(),
                            Value::Bool(true),
                        )]),
                    }]
                } else {
                    vec![]
                }
            }
        }

        // Higher priority fires first
        reg.register(Subscription::new(
            "low",
            EventFilter::NodeCreated,
            10,
            Box::new(MarkerHandler {
                key: "low".to_string(),
            }),
        ));
        reg.register(Subscription::new(
            "high",
            EventFilter::NodeCreated,
            100,
            Box::new(MarkerHandler {
                key: "high".to_string(),
            }),
        ));

        let node_id = NodeId::new();
        let result = engine
            .trigger(
                EventKind::NodeCreated {
                    node_id: node_id.clone(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                },
                &mut proj,
                &reg,
            )
            .unwrap();

        // 1 trigger + 2 reactions
        assert_eq!(result.events.len(), 3);

        // High priority should be the first reaction
        assert!(matches!(
            &result.events[1].kind,
            EventKind::NodeUpdated { changes, .. } if changes.contains_key("high")
        ));
        assert!(matches!(
            &result.events[2].kind,
            EventKind::NodeUpdated { changes, .. } if changes.contains_key("low")
        ));
    }

    // === Adversarial tests (code review audit) ===

    #[test]
    fn panicking_handler_does_not_kill_cascade() {
        let engine = CascadeEngine::with_defaults();
        let mut proj = Projection::new();
        let mut reg = SubscriptionRegistry::new();

        struct PanicHandler;
        impl SubscriptionHandler for PanicHandler {
            fn handle(
                &self,
                _event: &Event,
                _graph: &dyn hydra_core::graph::GraphReader,
            ) -> Vec<EventKind> {
                panic!("handler bug!");
            }
        }

        struct SafeHandler;
        impl SubscriptionHandler for SafeHandler {
            fn handle(
                &self,
                event: &Event,
                _graph: &dyn hydra_core::graph::GraphReader,
            ) -> Vec<EventKind> {
                if let EventKind::NodeCreated { node_id, .. } = &event.kind {
                    vec![EventKind::NodeUpdated {
                        node_id: node_id.clone(),
                        changes: HashMap::from([("safe".to_string(), Value::Bool(true))]),
                    }]
                } else {
                    vec![]
                }
            }
        }

        // Panic handler fires first (higher priority), safe handler second
        reg.register(Subscription::new(
            "panicker",
            EventFilter::NodeCreated,
            200,
            Box::new(PanicHandler),
        ));
        reg.register(Subscription::new(
            "safe",
            EventFilter::NodeCreated,
            100,
            Box::new(SafeHandler),
        ));

        let node_id = NodeId::new();
        let result = engine
            .trigger(
                EventKind::NodeCreated {
                    node_id: node_id.clone(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                },
                &mut proj,
                &reg,
            )
            .unwrap();

        // Cascade survived the panic, and the safe handler still fired
        assert_eq!(result.events.len(), 2); // trigger + safe reaction
        let node = proj.node(&node_id).unwrap();
        assert_eq!(node.get_bool("safe"), Some(true));
    }

    #[test]
    fn handler_targeting_nonexistent_node_errors() {
        let engine = CascadeEngine::with_defaults();
        let mut proj = Projection::new();
        let mut reg = SubscriptionRegistry::new();

        struct BadTargetHandler;
        impl SubscriptionHandler for BadTargetHandler {
            fn handle(
                &self,
                _event: &Event,
                _graph: &dyn hydra_core::graph::GraphReader,
            ) -> Vec<EventKind> {
                // Returns a NodeUpdated for a node that doesn't exist
                vec![EventKind::NodeUpdated {
                    node_id: NodeId::from_str("node_GHOST"),
                    changes: HashMap::from([("x".to_string(), Value::Int(1))]),
                }]
            }
        }

        reg.register(Subscription::new(
            "bad_target",
            EventFilter::NodeCreated,
            100,
            Box::new(BadTargetHandler),
        ));

        // This should return an error because the reaction targets a non-existent node
        let result = engine.trigger(
            EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: "ec2".to_string(),
                properties: HashMap::new(),
            },
            &mut proj,
            &reg,
        );
        assert!(result.is_err());
    }

    #[test]
    fn breadth_index_assigned_to_sibling_reactions() {
        let engine = CascadeEngine::with_defaults();
        let mut proj = Projection::new();
        let mut reg = SubscriptionRegistry::new();

        // Two handlers that both react to NodeCreated — they produce sibling reactions
        struct TagHandler { key: String }
        impl SubscriptionHandler for TagHandler {
            fn handle(
                &self,
                event: &Event,
                _graph: &dyn hydra_core::graph::GraphReader,
            ) -> Vec<EventKind> {
                if let EventKind::NodeCreated { node_id, .. } = &event.kind {
                    vec![EventKind::NodeUpdated {
                        node_id: node_id.clone(),
                        changes: HashMap::from([(self.key.clone(), Value::Bool(true))]),
                    }]
                } else {
                    vec![]
                }
            }
        }

        reg.register(Subscription::new(
            "first",
            EventFilter::NodeCreated,
            100,
            Box::new(TagHandler { key: "a".into() }),
        ));
        reg.register(Subscription::new(
            "second",
            EventFilter::NodeCreated,
            50,
            Box::new(TagHandler { key: "b".into() }),
        ));

        let result = engine
            .trigger(
                EventKind::NodeCreated {
                    node_id: NodeId::new(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                },
                &mut proj,
                &reg,
            )
            .unwrap();

        // Trigger at depth=0, breadth=0
        assert_eq!(result.events[0].cascade_depth, 0);
        assert_eq!(result.events[0].cascade_breadth_index, 0);

        // Two reactions at depth=1, breadth=0 and breadth=1
        assert_eq!(result.events[1].cascade_depth, 1);
        assert_eq!(result.events[1].cascade_breadth_index, 0);

        assert_eq!(result.events[2].cascade_depth, 1);
        assert_eq!(result.events[2].cascade_breadth_index, 1);
    }

    #[test]
    fn breadth_index_resets_per_parent() {
        let engine = CascadeEngine::with_defaults();
        let mut proj = Projection::new();
        let mut reg = SubscriptionRegistry::new();

        // Handler that produces TWO reactions per event
        struct DoubleHandler;
        impl SubscriptionHandler for DoubleHandler {
            fn handle(
                &self,
                event: &Event,
                _graph: &dyn hydra_core::graph::GraphReader,
            ) -> Vec<EventKind> {
                if let EventKind::NodeCreated { node_id, .. } = &event.kind {
                    vec![
                        EventKind::NodeUpdated {
                            node_id: node_id.clone(),
                            changes: HashMap::from([("tag_a".into(), Value::Bool(true))]),
                        },
                        EventKind::NodeUpdated {
                            node_id: node_id.clone(),
                            changes: HashMap::from([("tag_b".into(), Value::Bool(true))]),
                        },
                    ]
                } else {
                    vec![]
                }
            }
        }

        reg.register(Subscription::new(
            "doubler",
            EventFilter::NodeCreated,
            100,
            Box::new(DoubleHandler),
        ));

        let result = engine
            .trigger(
                EventKind::NodeCreated {
                    node_id: NodeId::new(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                },
                &mut proj,
                &reg,
            )
            .unwrap();

        // Trigger (depth=0, breadth=0) + 2 reactions (depth=1, breadth=0,1)
        assert_eq!(result.events.len(), 3);
        assert_eq!(result.events[1].cascade_breadth_index, 0);
        assert_eq!(result.events[2].cascade_breadth_index, 1);

        // Both reactions share the same parent
        assert_eq!(result.events[1].caused_by, result.events[2].caused_by);
    }

    #[test]
    fn trigger_event_has_breadth_index_zero() {
        let event = Event::trigger(EventKind::Signal {
            name: "test".into(),
            source: NodeId::new(),
            payload: HashMap::new(),
        });
        assert_eq!(event.cascade_breadth_index, 0);
    }

    #[test]
    fn max_events_limit_truncates_cascade() {
        // Config: max_events = 5, with a subscription that spawns reactions
        let config = CascadeConfig {
            max_depth: 100,
            max_events: 5,
        };
        let engine = CascadeEngine::new(config);
        let mut proj = Projection::new();
        let registry = SubscriptionRegistry::new();

        // Ingest many triggers — should stop at 5
        // Without subscriptions, each trigger is 1 event, so first 5 succeed
        for i in 0..10 {
            let kind = EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: format!("type_{}", i),
                properties: HashMap::new(),
            };
            let result = engine.trigger(kind, &mut proj, &registry);
            if i < 5 {
                assert!(result.is_ok(), "Event {} should succeed", i);
            }
            // After 5, the engine should truncate individual cascades
            // (each trigger is its own cascade of 1 event, so they all succeed
            // individually — the max_events limit is per-cascade)
        }
        // The limit is per-cascade, not global — all 10 succeed since each is 1 event
        assert_eq!(proj.node_count(), 10);

        // Now test with a chain reaction that exceeds the per-cascade limit
        let mut registry2 = SubscriptionRegistry::new();
        use hydra_core::subscription::{EventFilter, Subscription, SubscriptionHandler};

        struct SpawnHandler;
        impl SubscriptionHandler for SpawnHandler {
            fn handle(
                &self,
                event: &Event,
                _graph: &dyn hydra_core::graph::GraphReader,
            ) -> Vec<EventKind> {
                // Every node create spawns another node create
                if let EventKind::NodeCreated { .. } = &event.kind {
                    vec![EventKind::NodeCreated {
                        node_id: NodeId::new(),
                        type_id: "spawned".to_string(),
                        properties: HashMap::new(),
                    }]
                } else {
                    vec![]
                }
            }
        }

        registry2.register(Subscription::new(
            "spawner",
            EventFilter::NodeCreated,
            100,
            Box::new(SpawnHandler),
        ));

        let engine2 = CascadeEngine::new(CascadeConfig {
            max_depth: 100,
            max_events: 5,
        });
        let mut proj2 = Projection::new();
        let result = engine2.trigger(
            EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: "trigger".to_string(),
                properties: HashMap::new(),
            },
            &mut proj2,
            &registry2,
        ).unwrap();

        // Without limit this would be infinite. With max_events=5, it stops.
        assert!(result.truncated, "Should be truncated by max_events");
        assert!(result.events.len() <= 5, "Should not exceed 5 events");
    }
}
