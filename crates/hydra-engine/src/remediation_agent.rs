use hydra_core::{
    Action, ActionId, ActionKind, ActionStatus, ActionTarget, ActorId, Claim, ClaimKind,
    ClaimObject, ClaimStatus, ClaimSubject, Event, EventKind, Value,
};
use std::collections::HashMap;

use crate::epistemic_store::EpistemicStore;

/// A deterministic remediation agent that turns trusted claims into proposed actions.
///
/// This is the first ARGUS → PROMETHEUS bridge:
///
/// EvidenceAdded
/// → ClaimProposed
/// → ClaimVerified
/// → ActionProposed
///
/// Important:
/// This agent does not mutate Hydra state directly.
/// It only emits EventKind values. ActionStore materializes action state later
/// from ActionProposed / ActionApproved / ActionExecuted / OutcomeObserved events.
#[derive(Debug, Clone)]
pub struct RemediationAgent {
    actor_id: ActorId,
}

impl RemediationAgent {
    pub fn new(actor_id: ActorId) -> Self {
        Self { actor_id }
    }

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    /// React to a full event.
    ///
    /// Currently this only reacts to ClaimVerified.
    pub fn react(&self, event: &Event, store: &EpistemicStore) -> Vec<EventKind> {
        self.react_to_kind(&event.kind, store)
    }

    /// React to an EventKind.
    pub fn react_to_kind(&self, kind: &EventKind, store: &EpistemicStore) -> Vec<EventKind> {
        match kind {
            EventKind::ClaimVerified { claim_id, .. } => {
                let Some(claim) = store.claim(claim_id) else {
                    return vec![self.signal(
                        "remediation_missing_claim",
                        Some(claim_id.to_string()),
                        None,
                        vec![
                            "ClaimVerified referenced a claim missing from EpistemicStore"
                                .to_string(),
                        ],
                    )];
                };
                self.actions_for_verified_claim(claim)
            }
            _ => Vec::new(),
        }
    }

    /// Convert a verified claim into proposed action events.
    ///
    /// v0 only handles:
    ///
    /// ClaimKind::AnomalyFinding
    /// predicate == "is_stale"
    /// subject == Dataset(...)
    /// object == true
    ///
    /// Output:
    /// ActionProposed { kind: Backfill, target: Dataset(...) }
    pub fn actions_for_verified_claim(&self, claim: &Claim) -> Vec<EventKind> {
        if claim.status != ClaimStatus::Verified && claim.status != ClaimStatus::Operational {
            return Vec::new();
        }
        if claim.kind != ClaimKind::AnomalyFinding {
            return Vec::new();
        }
        if claim.predicate != "is_stale" {
            return Vec::new();
        }
        if !matches!(claim.object, ClaimObject::Value(Value::Bool(true))) {
            return Vec::new();
        }
        let ClaimSubject::Dataset(dataset) = &claim.subject else {
            return Vec::new();
        };

        let now = chrono::Utc::now();
        let mut payload = HashMap::new();
        payload.insert(
            "reason".to_string(),
            Value::String("verified dataset freshness anomaly".to_string()),
        );
        payload.insert("dataset".to_string(), Value::String(dataset.clone()));
        payload.insert("claim_id".to_string(), Value::String(claim.id.to_string()));

        let action = Action {
            id: ActionId::new(),
            tenant_id: claim.tenant_id.clone(),
            kind: ActionKind::Backfill,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::Dataset(dataset.clone())],
            related_claims: vec![claim.id.clone()],
            supporting_evidence: claim.evidence_for.clone(),
            proposed_by: self.actor_id.clone(),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };

        vec![EventKind::ActionProposed { action }]
    }

    fn signal(
        &self,
        name: &str,
        claim_id: Option<String>,
        dataset: Option<String>,
        reasons: Vec<String>,
    ) -> EventKind {
        let mut payload = HashMap::new();
        payload.insert("agent".to_string(), Value::String(self.actor_id.to_string()));
        if let Some(claim_id) = claim_id {
            payload.insert("claim_id".to_string(), Value::String(claim_id));
        }
        if let Some(dataset) = dataset {
            payload.insert("dataset".to_string(), Value::String(dataset));
        }
        payload.insert(
            "reasons".to_string(),
            Value::List(reasons.into_iter().map(Value::String).collect()),
        );
        EventKind::Signal {
            source: hydra_core::NodeId::from_str("hydra.remediation_agent"),
            name: name.to_string(),
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epistemic_store::EpistemicStore;
    use hydra_core::{
        CascadeId, ClaimId, Confidence, EventId, Evidence, EvidenceId, EvidencePayload,
        EvidenceSource, TenantId,
    };

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_remediation_agent_test")
    }

    fn actor() -> ActorId {
        ActorId::from_str("actor_prometheus")
    }

    fn verifier() -> ActorId {
        ActorId::from_str("actor_verifier")
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

    fn evidence() -> Evidence {
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
            reliability: Confidence::new(0.95),
            observed_at: chrono::Utc::now(),
            recorded_at: chrono::Utc::now(),
            caused_by: None,
        }
    }

    fn stale_dataset_claim(evidence_id: EvidenceId, status: ClaimStatus) -> Claim {
        let now = chrono::Utc::now();
        Claim {
            id: ClaimId::new(),
            tenant_id: Some(tenant()),
            kind: ClaimKind::AnomalyFinding,
            subject: ClaimSubject::Dataset("analytics.public.revenue_daily".to_string()),
            predicate: "is_stale".to_string(),
            object: ClaimObject::Value(Value::Bool(true)),
            confidence: Confidence::new(0.91),
            status,
            evidence_for: vec![evidence_id],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: verifier(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn store_with_verified_stale_claim() -> (EpistemicStore, Claim, Evidence) {
        let mut store = EpistemicStore::new();
        let evidence = evidence();
        let claim = stale_dataset_claim(evidence.id.clone(), ClaimStatus::Proposed);
        let claim_id = claim.id.clone();
        store
            .apply_event(&event(EventKind::EvidenceAdded {
                evidence: evidence.clone(),
            }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ClaimProposed {
                claim: claim.clone(),
            }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ClaimVerified {
                claim_id,
                verified_by: verifier(),
            }))
            .unwrap();
        let verified_claim = store.claim(&claim.id).unwrap().clone();
        (store, verified_claim, evidence)
    }

    #[test]
    fn proposes_backfill_for_verified_stale_dataset_claim() {
        let (_store, claim, evidence) = store_with_verified_stale_claim();
        let agent = RemediationAgent::new(actor());
        let events = agent.actions_for_verified_claim(&claim);
        assert_eq!(events.len(), 1);
        match &events[0] {
            EventKind::ActionProposed { action } => {
                assert_eq!(action.kind, ActionKind::Backfill);
                assert_eq!(action.status, ActionStatus::Proposed);
                assert_eq!(action.proposed_by, actor());
                assert_eq!(action.related_claims, vec![claim.id.clone()]);
                assert_eq!(action.supporting_evidence, vec![evidence.id.clone()]);
                assert_eq!(
                    action.targets,
                    vec![ActionTarget::Dataset(
                        "analytics.public.revenue_daily".to_string()
                    )]
                );
            }
            other => panic!("expected ActionProposed, got {other:?}"),
        }
    }

    #[test]
    fn reacts_to_claim_verified_event() {
        let (store, claim, _) = store_with_verified_stale_claim();
        let agent = RemediationAgent::new(actor());
        let events = agent.react_to_kind(
            &EventKind::ClaimVerified {
                claim_id: claim.id.clone(),
                verified_by: verifier(),
            },
            &store,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            EventKind::ActionProposed { action } => {
                assert_eq!(action.related_claims, vec![claim.id.clone()]);
            }
            other => panic!("expected ActionProposed, got {other:?}"),
        }
    }

    #[test]
    fn noops_for_unverified_claim() {
        let evidence = evidence();
        let claim = stale_dataset_claim(evidence.id.clone(), ClaimStatus::Proposed);
        let agent = RemediationAgent::new(actor());
        let events = agent.actions_for_verified_claim(&claim);
        assert!(events.is_empty());
    }

    #[test]
    fn noops_for_non_stale_claim() {
        let evidence = evidence();
        let mut claim = stale_dataset_claim(evidence.id.clone(), ClaimStatus::Verified);
        claim.predicate = "has_schema_drift".to_string();
        let agent = RemediationAgent::new(actor());
        let events = agent.actions_for_verified_claim(&claim);
        assert!(events.is_empty());
    }

    #[test]
    fn emits_signal_when_claim_verified_references_missing_claim() {
        let store = EpistemicStore::new();
        let missing_claim_id = ClaimId::new();
        let agent = RemediationAgent::new(actor());
        let events = agent.react_to_kind(
            &EventKind::ClaimVerified {
                claim_id: missing_claim_id.clone(),
                verified_by: verifier(),
            },
            &store,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            EventKind::Signal { name, payload, .. } => {
                assert_eq!(name, "remediation_missing_claim");
                assert_eq!(
                    payload.get("claim_id"),
                    Some(&Value::String(missing_claim_id.to_string()))
                );
            }
            other => panic!("expected Signal, got {other:?}"),
        }
    }

    #[test]
    fn noops_for_non_claim_verified_events() {
        let (store, _, evidence) = store_with_verified_stale_claim();
        let agent = RemediationAgent::new(actor());
        let events = agent.react_to_kind(
            &EventKind::EvidenceAdded { evidence },
            &store,
        );
        assert!(events.is_empty());
    }
}
