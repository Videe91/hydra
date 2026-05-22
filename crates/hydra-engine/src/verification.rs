use hydra_core::{
    Claim, ClaimKind, ClaimStatus, Confidence, Evidence, EvidenceId,
};

use crate::epistemic_store::EpistemicStore;

/// Policy controlling how Hydra evaluates whether a claim is trusted enough
/// to move forward in the epistemic lifecycle.
///
/// This is intentionally deterministic. LLM/agent reasoning can propose claims,
/// but trust decisions should be reproducible and auditable.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationPolicy {
    /// Minimum confidence the claim itself must carry.
    pub min_claim_confidence: Confidence,
    /// Minimum reliability required for each supporting evidence object to count.
    pub min_evidence_reliability: Confidence,
    /// Minimum number of reliable supporting evidence objects required.
    pub min_supporting_evidence: usize,
    /// If true, any contradicting evidence prevents auto-verification.
    pub block_on_contradicting_evidence: bool,
    /// Claim kinds allowed to be auto-verified.
    ///
    /// If empty, all claim kinds may be considered.
    pub auto_verifiable_kinds: Vec<ClaimKind>,
    /// If true, an Operational claim is considered already accepted.
    pub treat_operational_as_verified: bool,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            min_claim_confidence: Confidence::new(0.80),
            min_evidence_reliability: Confidence::new(0.75),
            min_supporting_evidence: 1,
            block_on_contradicting_evidence: true,
            auto_verifiable_kinds: vec![
                ClaimKind::Fact,
                ClaimKind::AnomalyFinding,
                ClaimKind::LineageFinding,
            ],
            treat_operational_as_verified: true,
        }
    }
}

/// A deterministic recommendation from the verification engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationDecision {
    /// Claim already has an accepted status.
    AlreadyVerified,
    /// Claim is too weak or incomplete; leave it proposed.
    KeepProposed,
    /// Claim has enough evidence to be supported, but not enough to verify.
    MarkSupported,
    /// Claim has contradicting evidence and should be disputed.
    MarkDisputed,
    /// Claim passes policy and can be verified.
    Verify,
    /// Claim kind/status/evidence pattern requires human review.
    NeedsHumanReview,
    /// Claim cannot be evaluated because data is missing from the store.
    MissingEvidence {
        evidence_id: EvidenceId,
    },
    /// Claim does not exist in the store.
    MissingClaim,
}

/// Full evaluation report. This is more useful than returning only the decision,
/// because agents and audit logs need to know why the decision was made.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationReport {
    pub claim_id: hydra_core::ClaimId,
    pub decision: VerificationDecision,
    pub claim_confidence: Confidence,
    pub reliable_supporting_evidence: usize,
    pub unreliable_supporting_evidence: usize,
    pub contradicting_evidence: usize,
    pub reliable_supporting_evidence_ids: Vec<EvidenceId>,
    pub unreliable_supporting_evidence_ids: Vec<EvidenceId>,
    pub contradicting_evidence_ids: Vec<EvidenceId>,
    pub reasons: Vec<String>,
}

impl VerificationReport {
    pub fn should_verify(&self) -> bool {
        matches!(self.decision, VerificationDecision::Verify)
    }

    pub fn needs_human_review(&self) -> bool {
        matches!(self.decision, VerificationDecision::NeedsHumanReview)
    }

    fn basic(
        claim_id: hydra_core::ClaimId,
        decision: VerificationDecision,
        claim_confidence: Confidence,
        reasons: Vec<String>,
    ) -> Self {
        Self {
            claim_id,
            decision,
            claim_confidence,
            reliable_supporting_evidence: 0,
            unreliable_supporting_evidence: 0,
            contradicting_evidence: 0,
            reliable_supporting_evidence_ids: Vec::new(),
            unreliable_supporting_evidence_ids: Vec::new(),
            contradicting_evidence_ids: Vec::new(),
            reasons,
        }
    }
}

/// Hydra's first deterministic trust evaluator.
///
/// It reads from EpistemicStore and does not mutate state directly.
/// Mutations should still happen through events:
///
/// - ClaimSupported
/// - ClaimVerified
/// - ClaimDisputed
/// - ClaimRetracted
/// - TopologyCommittedFromClaim
#[derive(Debug, Clone)]
pub struct VerificationEngine {
    policy: VerificationPolicy,
}

impl VerificationEngine {
    pub fn new(policy: VerificationPolicy) -> Self {
        Self { policy }
    }

    pub fn with_default_policy() -> Self {
        Self::new(VerificationPolicy::default())
    }

    pub fn policy(&self) -> &VerificationPolicy {
        &self.policy
    }

    pub fn evaluate_claim_by_id(
        &self,
        store: &EpistemicStore,
        claim_id: &hydra_core::ClaimId,
    ) -> VerificationReport {
        match store.claim(claim_id) {
            Some(claim) => self.evaluate_claim(store, claim),
            None => VerificationReport::basic(
                claim_id.clone(),
                VerificationDecision::MissingClaim,
                Confidence::new(0.0),
                vec!["claim does not exist in epistemic store".to_string()],
            ),
        }
    }

    pub fn evaluate_claim(
        &self,
        store: &EpistemicStore,
        claim: &Claim,
    ) -> VerificationReport {
        let mut reasons = Vec::new();

        if matches!(claim.status, ClaimStatus::Verified) {
            return VerificationReport::basic(
                claim.id.clone(),
                VerificationDecision::AlreadyVerified,
                claim.confidence,
                vec!["claim is already verified".to_string()],
            );
        }

        if self.policy.treat_operational_as_verified
            && matches!(claim.status, ClaimStatus::Operational)
        {
            return VerificationReport::basic(
                claim.id.clone(),
                VerificationDecision::AlreadyVerified,
                claim.confidence,
                vec!["claim is already operational".to_string()],
            );
        }

        if matches!(claim.status, ClaimStatus::Retracted | ClaimStatus::Archived) {
            return VerificationReport::basic(
                claim.id.clone(),
                VerificationDecision::NeedsHumanReview,
                claim.confidence,
                vec!["claim is retracted or archived and cannot be auto-verified".to_string()],
            );
        }

        if !self.policy.auto_verifiable_kinds.is_empty()
            && !self.policy.auto_verifiable_kinds.contains(&claim.kind)
        {
            return VerificationReport::basic(
                claim.id.clone(),
                VerificationDecision::NeedsHumanReview,
                claim.confidence,
                vec![format!(
                    "claim kind {:?} is not allowed for auto-verification",
                    claim.kind
                )],
            );
        }

        let supporting = match self.collect_evidence(store, &claim.evidence_for) {
            EvidenceCollection::Complete(values) => values,
            EvidenceCollection::Missing(evidence_id) => {
                return VerificationReport::basic(
                    claim.id.clone(),
                    VerificationDecision::MissingEvidence { evidence_id },
                    claim.confidence,
                    vec!["supporting evidence is missing".to_string()],
                );
            }
        };

        let contradicting = match self.collect_evidence(store, &claim.evidence_against) {
            EvidenceCollection::Complete(values) => values,
            EvidenceCollection::Missing(evidence_id) => {
                return VerificationReport::basic(
                    claim.id.clone(),
                    VerificationDecision::MissingEvidence { evidence_id },
                    claim.confidence,
                    vec!["contradicting evidence is missing".to_string()],
                );
            }
        };

        let mut reliable_supporting_evidence_ids = Vec::new();
        let mut unreliable_supporting_evidence_ids = Vec::new();
        for evidence in &supporting {
            if evidence.reliability.value() >= self.policy.min_evidence_reliability.value() {
                reliable_supporting_evidence_ids.push(evidence.id.clone());
            } else {
                unreliable_supporting_evidence_ids.push(evidence.id.clone());
            }
        }
        let contradicting_evidence_ids: Vec<EvidenceId> = contradicting
            .iter()
            .map(|evidence| evidence.id.clone())
            .collect();
        let reliable_supporting_evidence = reliable_supporting_evidence_ids.len();
        let unreliable_supporting_evidence = unreliable_supporting_evidence_ids.len();
        let contradicting_evidence = contradicting_evidence_ids.len();

        if claim.confidence.value() < self.policy.min_claim_confidence.value() {
            reasons.push(format!(
                "claim confidence {:.3} is below minimum {:.3}",
                claim.confidence.value(),
                self.policy.min_claim_confidence.value()
            ));
        }

        if reliable_supporting_evidence < self.policy.min_supporting_evidence {
            reasons.push(format!(
                "reliable supporting evidence count {} is below minimum {}",
                reliable_supporting_evidence,
                self.policy.min_supporting_evidence
            ));
        }

        if unreliable_supporting_evidence > 0 {
            reasons.push(format!(
                "{} supporting evidence object(s) were below reliability threshold",
                unreliable_supporting_evidence
            ));
        }

        if self.policy.block_on_contradicting_evidence && contradicting_evidence > 0 {
            reasons.push(format!(
                "{} contradicting evidence object(s) block auto-verification",
                contradicting_evidence
            ));
            return self.report(
                claim,
                VerificationDecision::MarkDisputed,
                reliable_supporting_evidence_ids,
                unreliable_supporting_evidence_ids,
                contradicting_evidence_ids,
                reasons,
            );
        }

        if claim.confidence.value() >= self.policy.min_claim_confidence.value()
            && reliable_supporting_evidence >= self.policy.min_supporting_evidence
        {
            reasons.push("claim satisfies verification policy".to_string());
            return self.report(
                claim,
                VerificationDecision::Verify,
                reliable_supporting_evidence_ids,
                unreliable_supporting_evidence_ids,
                contradicting_evidence_ids,
                reasons,
            );
        }

        if reliable_supporting_evidence > 0 {
            return self.report(
                claim,
                VerificationDecision::MarkSupported,
                reliable_supporting_evidence_ids,
                unreliable_supporting_evidence_ids,
                contradicting_evidence_ids,
                reasons,
            );
        }

        self.report(
            claim,
            VerificationDecision::KeepProposed,
            reliable_supporting_evidence_ids,
            unreliable_supporting_evidence_ids,
            contradicting_evidence_ids,
            reasons,
        )
    }

    fn report(
        &self,
        claim: &Claim,
        decision: VerificationDecision,
        reliable_supporting_evidence_ids: Vec<EvidenceId>,
        unreliable_supporting_evidence_ids: Vec<EvidenceId>,
        contradicting_evidence_ids: Vec<EvidenceId>,
        reasons: Vec<String>,
    ) -> VerificationReport {
        VerificationReport {
            claim_id: claim.id.clone(),
            decision,
            claim_confidence: claim.confidence,
            reliable_supporting_evidence: reliable_supporting_evidence_ids.len(),
            unreliable_supporting_evidence: unreliable_supporting_evidence_ids.len(),
            contradicting_evidence: contradicting_evidence_ids.len(),
            reliable_supporting_evidence_ids,
            unreliable_supporting_evidence_ids,
            contradicting_evidence_ids,
            reasons,
        }
    }

    fn collect_evidence<'a>(
        &self,
        store: &'a EpistemicStore,
        ids: &[EvidenceId],
    ) -> EvidenceCollection<'a> {
        let mut evidence = Vec::with_capacity(ids.len());
        for id in ids {
            match store.evidence(id) {
                Some(value) => evidence.push(value),
                None => return EvidenceCollection::Missing(id.clone()),
            }
        }
        EvidenceCollection::Complete(evidence)
    }
}

enum EvidenceCollection<'a> {
    Complete(Vec<&'a Evidence>),
    Missing(EvidenceId),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{
        ActorId, CascadeId, ClaimId, ClaimObject, ClaimSubject, Event, EventId, EventKind,
        EvidencePayload, EvidenceSource, TenantId, Value,
    };
    use std::collections::HashMap;

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_verification_test")
    }

    fn actor() -> ActorId {
        ActorId::from_str("actor_argus")
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
    ) -> (EpistemicStore, ClaimId, EvidenceId) {
        let mut store = EpistemicStore::new();
        let evidence = evidence_with_reliability(evidence_reliability);
        let evidence_id = evidence.id.clone();
        let claim = claim_with_confidence(evidence_id.clone(), claim_confidence);
        let claim_id = claim.id.clone();
        store
            .apply_event(&event(EventKind::EvidenceAdded { evidence }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ClaimProposed { claim }))
            .unwrap();
        (store, claim_id, evidence_id)
    }

    #[test]
    fn verifies_claim_when_policy_is_satisfied() {
        let (store, claim_id, _) = store_with_claim_and_evidence(0.91, 0.95);
        let engine = VerificationEngine::with_default_policy();
        let report = engine.evaluate_claim_by_id(&store, &claim_id);
        assert_eq!(report.decision, VerificationDecision::Verify);
        assert!(report.should_verify());
        assert_eq!(report.reliable_supporting_evidence, 1);
        assert_eq!(report.unreliable_supporting_evidence, 0);
        assert_eq!(report.reliable_supporting_evidence_ids.len(), 1);
        assert_eq!(report.unreliable_supporting_evidence_ids.len(), 0);
        assert_eq!(report.contradicting_evidence_ids.len(), 0);
    }

    #[test]
    fn marks_supported_when_evidence_is_reliable_but_claim_confidence_is_low() {
        let (store, claim_id, _) = store_with_claim_and_evidence(0.60, 0.95);
        let engine = VerificationEngine::with_default_policy();
        let report = engine.evaluate_claim_by_id(&store, &claim_id);
        assert_eq!(report.decision, VerificationDecision::MarkSupported);
        assert_eq!(report.reliable_supporting_evidence, 1);
    }

    #[test]
    fn keeps_proposed_when_no_reliable_supporting_evidence_exists() {
        let (store, claim_id, _) = store_with_claim_and_evidence(0.91, 0.20);
        let engine = VerificationEngine::with_default_policy();
        let report = engine.evaluate_claim_by_id(&store, &claim_id);
        assert_eq!(report.decision, VerificationDecision::KeepProposed);
        assert_eq!(report.reliable_supporting_evidence, 0);
        assert_eq!(report.unreliable_supporting_evidence, 1);
        assert_eq!(report.reliable_supporting_evidence_ids.len(), 0);
        assert_eq!(report.unreliable_supporting_evidence_ids.len(), 1);
    }

    #[test]
    fn marks_disputed_when_contradicting_evidence_exists() {
        let (mut store, claim_id, _) = store_with_claim_and_evidence(0.91, 0.95);
        let dispute = evidence_with_reliability(0.90);
        let dispute_id = dispute.id.clone();
        store
            .apply_event(&event(EventKind::EvidenceAdded { evidence: dispute }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ClaimDisputed {
                claim_id: claim_id.clone(),
                evidence_id: dispute_id,
                reason: Some("warehouse emitted newer contradictory freshness evidence".to_string()),
            }))
            .unwrap();
        let engine = VerificationEngine::with_default_policy();
        let report = engine.evaluate_claim_by_id(&store, &claim_id);
        assert_eq!(report.decision, VerificationDecision::MarkDisputed);
        assert_eq!(report.contradicting_evidence, 1);
        assert_eq!(report.contradicting_evidence_ids.len(), 1);
    }

    #[test]
    fn non_auto_verifiable_claim_kinds_need_human_review() {
        let mut store = EpistemicStore::new();
        let evidence = evidence_with_reliability(0.95);
        let evidence_id = evidence.id.clone();
        let mut claim = claim_with_confidence(evidence_id, 0.91);
        claim.kind = ClaimKind::Recommendation;
        let claim_id = claim.id.clone();
        store
            .apply_event(&event(EventKind::EvidenceAdded { evidence }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ClaimProposed { claim }))
            .unwrap();
        let engine = VerificationEngine::with_default_policy();
        let report = engine.evaluate_claim_by_id(&store, &claim_id);
        assert_eq!(report.decision, VerificationDecision::NeedsHumanReview);
        assert!(report.needs_human_review());
    }

    #[test]
    fn missing_claim_is_reported() {
        let store = EpistemicStore::new();
        let engine = VerificationEngine::with_default_policy();
        let report = engine.evaluate_claim_by_id(&store, &ClaimId::new());
        assert_eq!(report.decision, VerificationDecision::MissingClaim);
    }

    #[test]
    fn missing_evidence_is_reported() {
        let mut store = EpistemicStore::new();
        let missing_evidence_id = EvidenceId::new();
        let claim = claim_with_confidence(missing_evidence_id.clone(), 0.91);
        let claim_id = claim.id.clone();
        store
            .apply_event(&event(EventKind::ClaimProposed { claim }))
            .unwrap();
        let engine = VerificationEngine::with_default_policy();
        let report = engine.evaluate_claim_by_id(&store, &claim_id);
        assert_eq!(
            report.decision,
            VerificationDecision::MissingEvidence {
                evidence_id: missing_evidence_id
            }
        );
    }

    #[test]
    fn already_verified_claim_is_reported() {
        let (mut store, claim_id, _) = store_with_claim_and_evidence(0.91, 0.95);
        store
            .apply_event(&event(EventKind::ClaimVerified {
                claim_id: claim_id.clone(),
                verified_by: actor(),
            }))
            .unwrap();
        let engine = VerificationEngine::with_default_policy();
        let report = engine.evaluate_claim_by_id(&store, &claim_id);
        assert_eq!(report.decision, VerificationDecision::AlreadyVerified);
    }
}
