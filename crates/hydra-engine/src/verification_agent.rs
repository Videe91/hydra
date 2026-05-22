use hydra_core::{
    ActorId, ClaimId, Event, EventKind, EvidenceId, NodeId, Value,
};

use crate::epistemic_store::EpistemicStore;
use crate::verification::{
    VerificationDecision, VerificationEngine, VerificationReport,
};

/// A deterministic agent that reacts to claim lifecycle events and proposes
/// epistemic transition events.
///
/// Important:
/// This agent does not mutate Hydra state directly.
/// It only returns EventKind values. The cascade/event system remains the only
/// path by which claim state changes.
#[derive(Debug, Clone)]
pub struct VerificationAgent {
    actor_id: ActorId,
}

impl VerificationAgent {
    pub fn new(actor_id: ActorId) -> Self {
        Self { actor_id }
    }

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    /// React to a full event.
    ///
    /// Currently this only reacts to `ClaimProposed`.
    pub fn react(
        &self,
        event: &Event,
        store: &EpistemicStore,
        engine: &VerificationEngine,
    ) -> Vec<EventKind> {
        self.react_to_kind(&event.kind, store, engine)
    }

    /// React to an EventKind.
    ///
    /// This is useful for tests and for subscription handlers that receive
    /// EventKind values directly.
    pub fn react_to_kind(
        &self,
        kind: &EventKind,
        store: &EpistemicStore,
        engine: &VerificationEngine,
    ) -> Vec<EventKind> {
        match kind {
            EventKind::ClaimProposed { claim } => {
                let report = engine.evaluate_claim_by_id(store, &claim.id);
                self.events_from_report(&claim.id, &report)
            }
            _ => Vec::new(),
        }
    }

    /// Convert a verification report into transition events.
    ///
    /// This method is deterministic:
    /// - MarkSupported uses the first reliable supporting evidence ID.
    /// - MarkDisputed uses the first contradicting evidence ID.
    /// - Verify emits ClaimVerified.
    /// - human/recovery paths emit Signal events for downstream agents.
    pub fn events_from_report(
        &self,
        claim_id: &ClaimId,
        report: &VerificationReport,
    ) -> Vec<EventKind> {
        match &report.decision {
            VerificationDecision::Verify => {
                vec![EventKind::ClaimVerified {
                    claim_id: claim_id.clone(),
                    verified_by: self.actor_id.clone(),
                }]
            }
            VerificationDecision::MarkSupported => {
                let Some(evidence_id) = report.reliable_supporting_evidence_ids.first() else {
                    return vec![self.signal(
                        "claim_support_missing_reliable_evidence",
                        Some(claim_id),
                        None,
                        vec![
                            "verification decision requested MarkSupported but no reliable evidence ID was present"
                                .to_string(),
                        ],
                    )];
                };
                vec![EventKind::ClaimSupported {
                    claim_id: claim_id.clone(),
                    evidence_id: evidence_id.clone(),
                }]
            }
            VerificationDecision::MarkDisputed => {
                let Some(evidence_id) = report.contradicting_evidence_ids.first() else {
                    return vec![self.signal(
                        "claim_dispute_missing_contradicting_evidence",
                        Some(claim_id),
                        None,
                        vec![
                            "verification decision requested MarkDisputed but no contradicting evidence ID was present"
                                .to_string(),
                        ],
                    )];
                };
                vec![EventKind::ClaimDisputed {
                    claim_id: claim_id.clone(),
                    evidence_id: evidence_id.clone(),
                    reason: Some(report.reasons.join("; ")),
                }]
            }
            VerificationDecision::NeedsHumanReview => {
                vec![self.signal(
                    "claim_needs_human_review",
                    Some(claim_id),
                    None,
                    report.reasons.clone(),
                )]
            }
            VerificationDecision::MissingEvidence { evidence_id } => {
                vec![self.signal(
                    "claim_missing_evidence",
                    Some(claim_id),
                    Some(evidence_id),
                    report.reasons.clone(),
                )]
            }
            VerificationDecision::KeepProposed
            | VerificationDecision::AlreadyVerified
            | VerificationDecision::MissingClaim => Vec::new(),
        }
    }

    fn signal(
        &self,
        name: &str,
        claim_id: Option<&ClaimId>,
        evidence_id: Option<&EvidenceId>,
        reasons: Vec<String>,
    ) -> EventKind {
        let mut payload = std::collections::HashMap::new();
        payload.insert("agent".to_string(), Value::String(self.actor_id.to_string()));
        if let Some(claim_id) = claim_id {
            payload.insert("claim_id".to_string(), Value::String(claim_id.to_string()));
        }
        if let Some(evidence_id) = evidence_id {
            payload.insert(
                "evidence_id".to_string(),
                Value::String(evidence_id.to_string()),
            );
        }
        payload.insert(
            "reasons".to_string(),
            Value::List(reasons.into_iter().map(Value::String).collect()),
        );
        EventKind::Signal {
            source: NodeId::from_str("hydra.verification_agent"),
            name: name.to_string(),
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epistemic_store::EpistemicStore;
    use crate::verification::VerificationEngine;
    use hydra_core::{
        CascadeId, Claim, ClaimKind, ClaimObject, ClaimStatus, ClaimSubject, Confidence, EventId,
        Evidence, EvidencePayload, EvidenceSource, TenantId,
    };
    use std::collections::HashMap;

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_verification_agent_test")
    }

    fn actor() -> ActorId {
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

    fn claim_with_confidence(evidence_id: EvidenceId, confidence: f64) -> Claim {
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
            created_by: actor(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn store_with_claim_and_evidence(
        claim_confidence: f64,
        evidence_reliability: f64,
    ) -> (EpistemicStore, Claim, Evidence) {
        let mut store = EpistemicStore::new();
        let evidence = evidence_with_reliability(evidence_reliability);
        let claim = claim_with_confidence(evidence.id.clone(), claim_confidence);
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
        (store, claim, evidence)
    }

    #[test]
    fn emits_claim_verified_when_report_says_verify() {
        let (store, claim, _) = store_with_claim_and_evidence(0.91, 0.95);
        let agent = VerificationAgent::new(actor());
        let engine = VerificationEngine::with_default_policy();
        let events = agent.react_to_kind(
            &EventKind::ClaimProposed {
                claim: claim.clone(),
            },
            &store,
            &engine,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            EventKind::ClaimVerified {
                claim_id,
                verified_by,
            } => {
                assert_eq!(claim_id, &claim.id);
                assert_eq!(verified_by, &actor());
            }
            other => panic!("expected ClaimVerified, got {other:?}"),
        }
    }

    #[test]
    fn emits_claim_supported_when_report_says_mark_supported() {
        let (store, claim, evidence) = store_with_claim_and_evidence(0.60, 0.95);
        let agent = VerificationAgent::new(actor());
        let engine = VerificationEngine::with_default_policy();
        let events = agent.react_to_kind(
            &EventKind::ClaimProposed {
                claim: claim.clone(),
            },
            &store,
            &engine,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            EventKind::ClaimSupported {
                claim_id,
                evidence_id,
            } => {
                assert_eq!(claim_id, &claim.id);
                assert_eq!(evidence_id, &evidence.id);
            }
            other => panic!("expected ClaimSupported, got {other:?}"),
        }
    }

    #[test]
    fn emits_claim_disputed_when_report_says_mark_disputed() {
        let (mut store, claim, _) = store_with_claim_and_evidence(0.91, 0.95);
        let dispute = evidence_with_reliability(0.90);
        let dispute_id = dispute.id.clone();
        store
            .apply_event(&event(EventKind::EvidenceAdded { evidence: dispute }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ClaimDisputed {
                claim_id: claim.id.clone(),
                evidence_id: dispute_id.clone(),
                reason: Some("newer contradicting evidence".to_string()),
            }))
            .unwrap();
        let agent = VerificationAgent::new(actor());
        let engine = VerificationEngine::with_default_policy();
        let events = agent.react_to_kind(
            &EventKind::ClaimProposed {
                claim: claim.clone(),
            },
            &store,
            &engine,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            EventKind::ClaimDisputed {
                claim_id,
                evidence_id,
                reason,
            } => {
                assert_eq!(claim_id, &claim.id);
                assert_eq!(evidence_id, &dispute_id);
                assert!(reason.as_ref().unwrap().contains("contradicting"));
            }
            other => panic!("expected ClaimDisputed, got {other:?}"),
        }
    }

    #[test]
    fn emits_human_review_signal_for_non_auto_verifiable_claim() {
        let mut store = EpistemicStore::new();
        let evidence = evidence_with_reliability(0.95);
        let mut claim = claim_with_confidence(evidence.id.clone(), 0.91);
        claim.kind = ClaimKind::Recommendation;
        store
            .apply_event(&event(EventKind::EvidenceAdded { evidence }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ClaimProposed {
                claim: claim.clone(),
            }))
            .unwrap();
        let agent = VerificationAgent::new(actor());
        let engine = VerificationEngine::with_default_policy();
        let events = agent.react_to_kind(
            &EventKind::ClaimProposed {
                claim: claim.clone(),
            },
            &store,
            &engine,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            EventKind::Signal { name, payload, .. } => {
                assert_eq!(name, "claim_needs_human_review");
                assert_eq!(
                    payload.get("claim_id"),
                    Some(&Value::String(claim.id.to_string()))
                );
            }
            other => panic!("expected Signal, got {other:?}"),
        }
    }

    #[test]
    fn emits_missing_evidence_signal() {
        let mut store = EpistemicStore::new();
        let missing_evidence_id = EvidenceId::new();
        let claim = claim_with_confidence(missing_evidence_id.clone(), 0.91);
        store
            .apply_event(&event(EventKind::ClaimProposed {
                claim: claim.clone(),
            }))
            .unwrap();
        let agent = VerificationAgent::new(actor());
        let engine = VerificationEngine::with_default_policy();
        let events = agent.react_to_kind(
            &EventKind::ClaimProposed {
                claim: claim.clone(),
            },
            &store,
            &engine,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            EventKind::Signal { name, payload, .. } => {
                assert_eq!(name, "claim_missing_evidence");
                assert_eq!(
                    payload.get("claim_id"),
                    Some(&Value::String(claim.id.to_string()))
                );
                assert_eq!(
                    payload.get("evidence_id"),
                    Some(&Value::String(missing_evidence_id.to_string()))
                );
            }
            other => panic!("expected Signal, got {other:?}"),
        }
    }

    #[test]
    fn noops_for_keep_proposed() {
        let (store, claim, _) = store_with_claim_and_evidence(0.91, 0.20);
        let agent = VerificationAgent::new(actor());
        let engine = VerificationEngine::with_default_policy();
        let events = agent.react_to_kind(
            &EventKind::ClaimProposed { claim },
            &store,
            &engine,
        );
        assert!(events.is_empty());
    }

    #[test]
    fn noops_for_non_claim_events() {
        let (store, _, evidence) = store_with_claim_and_evidence(0.91, 0.95);
        let agent = VerificationAgent::new(actor());
        let engine = VerificationEngine::with_default_policy();
        let events = agent.react_to_kind(
            &EventKind::EvidenceAdded { evidence },
            &store,
            &engine,
        );
        assert!(events.is_empty());
    }
}
