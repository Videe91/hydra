use hydra_core::{Event, EventKind};

use crate::action_store::ActionStore;
use crate::epistemic_store::EpistemicStore;
use crate::projection::Projection;
use crate::verification::VerificationEngine;

/// Read-only state exposed to reflexes.
///
/// A reflex can inspect Hydra state and emit new EventKind values,
/// but it must not mutate state directly.
///
/// This keeps Hydra database-like:
/// - events are the only mutation path
/// - reactions are auditable
/// - replay stays deterministic when reflexes are deterministic
pub struct ReflexContext<'a> {
    pub projection: &'a Projection,
    pub epistemic_store: &'a EpistemicStore,
    pub action_store: &'a ActionStore,
    pub verification_engine: &'a VerificationEngine,
}

impl<'a> ReflexContext<'a> {
    pub fn new(
        projection: &'a Projection,
        epistemic_store: &'a EpistemicStore,
        action_store: &'a ActionStore,
        verification_engine: &'a VerificationEngine,
    ) -> Self {
        Self {
            projection,
            epistemic_store,
            action_store,
            verification_engine,
        }
    }
}

/// Programmable database reflex.
///
/// A reflex reacts to an event and emits zero or more follow-up EventKinds.
///
/// Reflexes are how Hydra becomes programmable like a database:
///
/// - ClaimVerified -> ActionProposed
/// - ActionExecuted -> OutcomeObserved
/// - EvidenceAdded -> ClaimProposed
/// - PolicyViolated -> ActionRejected
///
/// Reflexes must not mutate Hydra state directly.
pub trait Reflex: Send + Sync {
    fn name(&self) -> &'static str;
    fn react(&self, event: &Event, ctx: &ReflexContext<'_>) -> Vec<EventKind>;
}

/// Type-erased reflex collection.
///
/// This lets Hydra register built-in reflexes and user-defined reflexes through
/// one common mechanism.
#[derive(Default)]
pub struct ReflexRegistry {
    reflexes: Vec<Box<dyn Reflex>>,
}

impl ReflexRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<R>(&mut self, reflex: R)
    where
        R: Reflex + 'static,
    {
        self.reflexes.push(Box::new(reflex));
    }

    pub fn len(&self) -> usize {
        self.reflexes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.reflexes.is_empty()
    }

    pub fn reflex_names(&self) -> Vec<&'static str> {
        self.reflexes.iter().map(|reflex| reflex.name()).collect()
    }

    pub fn react(&self, event: &Event, ctx: &ReflexContext<'_>) -> Vec<EventKind> {
        let mut reactions = Vec::new();
        for reflex in &self.reflexes {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                reflex.react(event, ctx)
            }));
            match result {
                Ok(mut event_kinds) => reactions.append(&mut event_kinds),
                Err(_) => {
                    // Keep cascade alive if a reflex panics.
                    // Later we can emit a ReflexFailed diagnostic Signal.
                }
            }
        }
        reactions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{
        ActorId, CascadeId, Claim, ClaimId, ClaimKind, ClaimObject, ClaimStatus, ClaimSubject,
        Confidence, EventId, EvidenceId, Value,
    };

    struct TestReflex;
    impl Reflex for TestReflex {
        fn name(&self) -> &'static str {
            "test_reflex"
        }

        fn react(&self, event: &Event, _ctx: &ReflexContext<'_>) -> Vec<EventKind> {
            match &event.kind {
                EventKind::ClaimVerified { claim_id, .. } => {
                    vec![EventKind::ClaimStaled {
                        claim_id: claim_id.clone(),
                        reason: Some("test reflex".to_string()),
                    }]
                }
                _ => Vec::new(),
            }
        }
    }

    struct PanicReflex;
    impl Reflex for PanicReflex {
        fn name(&self) -> &'static str {
            "panic_reflex"
        }

        fn react(&self, _event: &Event, _ctx: &ReflexContext<'_>) -> Vec<EventKind> {
            panic!("intentional test panic");
        }
    }

    fn actor() -> ActorId {
        ActorId::from_str("actor_test")
    }

    fn event(kind: EventKind) -> Event {
        Event {
            id: EventId::new(),
            tenant_id: None,
            timestamp: chrono::Utc::now(),
            kind,
            caused_by: vec![],
            cascade_id: CascadeId::new(),
            cascade_depth: 0,
            cascade_breadth_index: 0,
        }
    }

    fn claim() -> Claim {
        let now = chrono::Utc::now();
        Claim {
            id: ClaimId::new(),
            tenant_id: None,
            kind: ClaimKind::AnomalyFinding,
            subject: ClaimSubject::Dataset("analytics.public.revenue_daily".to_string()),
            predicate: "is_stale".to_string(),
            object: ClaimObject::Value(Value::Bool(true)),
            confidence: Confidence::new(0.91),
            status: ClaimStatus::Verified,
            evidence_for: vec![EvidenceId::new()],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: actor(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn context<'a>(
        projection: &'a Projection,
        epistemic_store: &'a EpistemicStore,
        action_store: &'a ActionStore,
        verification_engine: &'a VerificationEngine,
    ) -> ReflexContext<'a> {
        ReflexContext::new(
            projection,
            epistemic_store,
            action_store,
            verification_engine,
        )
    }

    #[test]
    fn registry_registers_and_lists_reflexes() {
        let mut registry = ReflexRegistry::new();
        assert!(registry.is_empty());
        registry.register(TestReflex);
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.reflex_names(), vec!["test_reflex"]);
    }

    #[test]
    fn registry_reacts_to_events() {
        let mut registry = ReflexRegistry::new();
        registry.register(TestReflex);

        let projection = Projection::new();
        let epistemic_store = EpistemicStore::new();
        let action_store = ActionStore::new();
        let verification_engine = VerificationEngine::with_default_policy();

        let claim = claim();
        let claim_id = claim.id.clone();
        let event = event(EventKind::ClaimVerified {
            claim_id: claim_id.clone(),
            verified_by: actor(),
        });

        let reactions = registry.react(
            &event,
            &context(
                &projection,
                &epistemic_store,
                &action_store,
                &verification_engine,
            ),
        );

        assert_eq!(reactions.len(), 1);
        match &reactions[0] {
            EventKind::ClaimStaled {
                claim_id: staled_claim_id,
                reason,
            } => {
                assert_eq!(staled_claim_id, &claim_id);
                assert_eq!(reason.as_deref(), Some("test reflex"));
            }
            other => panic!("expected ClaimStaled, got {other:?}"),
        }
    }

    #[test]
    fn registry_continues_if_one_reflex_panics() {
        let mut registry = ReflexRegistry::new();
        registry.register(PanicReflex);
        registry.register(TestReflex);

        let projection = Projection::new();
        let epistemic_store = EpistemicStore::new();
        let action_store = ActionStore::new();
        let verification_engine = VerificationEngine::with_default_policy();

        let claim_id = ClaimId::new();
        let event = event(EventKind::ClaimVerified {
            claim_id,
            verified_by: actor(),
        });

        let reactions = registry.react(
            &event,
            &context(
                &projection,
                &epistemic_store,
                &action_store,
                &verification_engine,
            ),
        );

        assert_eq!(reactions.len(), 1);
    }

    #[test]
    fn registry_noops_when_no_reflex_matches() {
        let mut registry = ReflexRegistry::new();
        registry.register(TestReflex);

        let projection = Projection::new();
        let epistemic_store = EpistemicStore::new();
        let action_store = ActionStore::new();
        let verification_engine = VerificationEngine::with_default_policy();

        let event = event(EventKind::Signal {
            source: hydra_core::NodeId::from_str("test"),
            name: "noop".to_string(),
            payload: std::collections::HashMap::new(),
        });

        let reactions = registry.react(
            &event,
            &context(
                &projection,
                &epistemic_store,
                &action_store,
                &verification_engine,
            ),
        );

        assert!(reactions.is_empty());
    }
}
