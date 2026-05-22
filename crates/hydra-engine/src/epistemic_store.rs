use hydra_core::{
    Claim, ClaimId, ClaimKind, ClaimStatus, ClaimSubject, EdgeId, Event, EventKind, Evidence,
    EvidenceId, NodeId,
};
use hydra_core::error::{HydraError, Result};
use std::collections::{HashMap, HashSet};

/// A stable, hashable key for indexing claims by subject.
///
/// `ClaimSubject` itself may contain richer values later, so this key keeps
/// indexing explicit and resilient.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClaimSubjectKey {
    Node(NodeId),
    Edge(EdgeId),
    ExternalRef(String),
    Dataset(String),
    Metric(String),
    System(String),
}

impl From<&ClaimSubject> for ClaimSubjectKey {
    fn from(subject: &ClaimSubject) -> Self {
        match subject {
            ClaimSubject::Node(id) => Self::Node(id.clone()),
            ClaimSubject::Edge(id) => Self::Edge(id.clone()),
            ClaimSubject::ExternalRef(value) => Self::ExternalRef(value.clone()),
            ClaimSubject::Dataset(value) => Self::Dataset(value.clone()),
            ClaimSubject::Metric(value) => Self::Metric(value.clone()),
            ClaimSubject::System(value) => Self::System(value.clone()),
        }
    }
}

/// Materialized belief/evidence state derived from epistemic events.
///
/// This is intentionally separate from the graph projection:
/// - `Projection` answers: what topology is operational?
/// - `EpistemicStore` answers: what does Hydra believe, why, and with what status?
#[derive(Debug, Clone, Default)]
pub struct EpistemicStore {
    evidence: HashMap<EvidenceId, Evidence>,
    claims: HashMap<ClaimId, Claim>,
    claims_by_subject: HashMap<ClaimSubjectKey, HashSet<ClaimId>>,
    claims_by_status: HashMap<ClaimStatus, HashSet<ClaimId>>,
    claims_by_kind: HashMap<ClaimKind, HashSet<ClaimId>>,
    claims_by_evidence: HashMap<EvidenceId, HashSet<ClaimId>>,
}

impl EpistemicStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }

    pub fn claim_count(&self) -> usize {
        self.claims.len()
    }

    pub fn evidence(&self, id: &EvidenceId) -> Option<&Evidence> {
        self.evidence.get(id)
    }

    pub fn claim(&self, id: &ClaimId) -> Option<&Claim> {
        self.claims.get(id)
    }

    pub fn all_evidence(&self) -> impl Iterator<Item = &Evidence> {
        self.evidence.values()
    }

    pub fn all_claims(&self) -> impl Iterator<Item = &Claim> {
        self.claims.values()
    }

    pub fn claims_for_subject(&self, subject: &ClaimSubject) -> Vec<&Claim> {
        let key = ClaimSubjectKey::from(subject);
        self.claims_by_subject
            .get(&key)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.claims.get(id))
            .collect()
    }

    pub fn claims_with_status(&self, status: ClaimStatus) -> Vec<&Claim> {
        self.claims_by_status
            .get(&status)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.claims.get(id))
            .collect()
    }

    pub fn claims_with_kind(&self, kind: ClaimKind) -> Vec<&Claim> {
        self.claims_by_kind
            .get(&kind)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.claims.get(id))
            .collect()
    }

    pub fn claims_using_evidence(&self, evidence_id: &EvidenceId) -> Vec<&Claim> {
        self.claims_by_evidence
            .get(evidence_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.claims.get(id))
            .collect()
    }

    pub fn verified_claims(&self) -> Vec<&Claim> {
        self.claims_with_status(ClaimStatus::Verified)
    }

    pub fn operational_claims(&self) -> Vec<&Claim> {
        self.claims_with_status(ClaimStatus::Operational)
    }

    pub fn disputed_claims(&self) -> Vec<&Claim> {
        self.claims_with_status(ClaimStatus::Disputed)
    }

    pub fn stale_claims(&self) -> Vec<&Claim> {
        self.claims_with_status(ClaimStatus::Stale)
    }

    pub fn retracted_claims(&self) -> Vec<&Claim> {
        self.claims_with_status(ClaimStatus::Retracted)
    }

    /// Apply one Hydra event to the epistemic store.
    ///
    /// Non-epistemic events are ignored. This lets the store subscribe to the
    /// full event log without requiring callers to filter events first.
    pub fn apply_event(&mut self, event: &Event) -> Result<()> {
        match &event.kind {
            EventKind::EvidenceAdded { evidence } => {
                self.insert_evidence(evidence.clone());
            }
            EventKind::ClaimProposed { claim } => {
                self.insert_claim(claim.clone());
            }
            EventKind::ClaimSupported {
                claim_id,
                evidence_id,
            } => {
                self.add_supporting_evidence(claim_id, evidence_id)?;
            }
            EventKind::ClaimDisputed {
                claim_id,
                evidence_id,
                ..
            } => {
                self.add_disputing_evidence(claim_id, evidence_id)?;
            }
            EventKind::ClaimVerified { claim_id, .. } => {
                self.update_claim_status(claim_id, ClaimStatus::Verified, event.timestamp)?;
            }
            EventKind::ClaimRetracted { claim_id, .. } => {
                self.update_claim_status(claim_id, ClaimStatus::Retracted, event.timestamp)?;
            }
            EventKind::ClaimStaled { claim_id, .. } => {
                self.update_claim_status(claim_id, ClaimStatus::Stale, event.timestamp)?;
            }
            EventKind::TopologyCommittedFromClaim { claim_id, .. } => {
                self.update_claim_status(claim_id, ClaimStatus::Operational, event.timestamp)?;
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

    fn insert_evidence(&mut self, evidence: Evidence) {
        self.evidence.insert(evidence.id.clone(), evidence);
    }

    fn insert_claim(&mut self, claim: Claim) {
        let claim_id = claim.id.clone();
        if let Some(existing) = self.claims.get(&claim_id).cloned() {
            self.remove_claim_indexes(&existing);
        }
        self.claims.insert(claim_id.clone(), claim);
        if let Some(inserted) = self.claims.get(&claim_id).cloned() {
            self.insert_claim_indexes(&inserted);
        }
    }

    fn add_supporting_evidence(
        &mut self,
        claim_id: &ClaimId,
        evidence_id: &EvidenceId,
    ) -> Result<()> {
        self.ensure_evidence_exists(evidence_id)?;
        self.mutate_claim(claim_id, |claim| {
            if !claim.evidence_for.contains(evidence_id) {
                claim.evidence_for.push(evidence_id.clone());
            }
            if matches!(claim.status, ClaimStatus::Proposed) {
                claim.status = ClaimStatus::Supported;
            }
        })
    }

    fn add_disputing_evidence(
        &mut self,
        claim_id: &ClaimId,
        evidence_id: &EvidenceId,
    ) -> Result<()> {
        self.ensure_evidence_exists(evidence_id)?;
        self.mutate_claim(claim_id, |claim| {
            if !claim.evidence_against.contains(evidence_id) {
                claim.evidence_against.push(evidence_id.clone());
            }
            claim.status = ClaimStatus::Disputed;
        })
    }

    fn update_claim_status(
        &mut self,
        claim_id: &ClaimId,
        status: ClaimStatus,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        self.mutate_claim(claim_id, |claim| {
            claim.status = status;
            claim.updated_at = updated_at;
        })
    }

    fn mutate_claim<F>(&mut self, claim_id: &ClaimId, mutation: F) -> Result<()>
    where
        F: FnOnce(&mut Claim),
    {
        let mut claim = self
            .claims
            .remove(claim_id)
            .ok_or_else(|| HydraError::QueryError(format!("unknown claim: {}", claim_id)))?;
        self.remove_claim_indexes(&claim);
        mutation(&mut claim);
        self.insert_claim_indexes(&claim);
        self.claims.insert(claim_id.clone(), claim);
        Ok(())
    }

    fn ensure_evidence_exists(&self, evidence_id: &EvidenceId) -> Result<()> {
        if self.evidence.contains_key(evidence_id) {
            Ok(())
        } else {
            Err(HydraError::QueryError(format!(
                "unknown evidence: {}",
                evidence_id
            )))
        }
    }

    fn insert_claim_indexes(&mut self, claim: &Claim) {
        let claim_id = claim.id.clone();
        self.claims_by_subject
            .entry(ClaimSubjectKey::from(&claim.subject))
            .or_default()
            .insert(claim_id.clone());
        self.claims_by_status
            .entry(claim.status.clone())
            .or_default()
            .insert(claim_id.clone());
        self.claims_by_kind
            .entry(claim.kind.clone())
            .or_default()
            .insert(claim_id.clone());
        for evidence_id in claim.evidence_for.iter().chain(claim.evidence_against.iter()) {
            self.claims_by_evidence
                .entry(evidence_id.clone())
                .or_default()
                .insert(claim_id.clone());
        }
    }

    fn remove_claim_indexes(&mut self, claim: &Claim) {
        let claim_id = &claim.id;
        let subject_key = ClaimSubjectKey::from(&claim.subject);
        remove_from_index(&mut self.claims_by_subject, &subject_key, claim_id);
        remove_from_index(&mut self.claims_by_status, &claim.status, claim_id);
        remove_from_index(&mut self.claims_by_kind, &claim.kind, claim_id);
        for evidence_id in claim.evidence_for.iter().chain(claim.evidence_against.iter()) {
            remove_from_index(&mut self.claims_by_evidence, evidence_id, claim_id);
        }
    }
}

fn remove_from_index<K>(index: &mut HashMap<K, HashSet<ClaimId>>, key: &K, claim_id: &ClaimId)
where
    K: std::hash::Hash + Eq + Clone,
{
    let should_remove_key = if let Some(ids) = index.get_mut(key) {
        ids.remove(claim_id);
        ids.is_empty()
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
        ActorId, CascadeId, ClaimKind, ClaimObject, ClaimStatus, Confidence, EventId,
        EvidencePayload, EvidenceSource, TenantId, Value,
    };
    use std::collections::HashMap;

    fn actor() -> ActorId {
        ActorId::from_str("actor_argus")
    }

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_test")
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
        data.insert("table".to_string(), Value::String("revenue_daily".to_string()));
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

    fn claim(evidence_id: EvidenceId) -> Claim {
        let now = chrono::Utc::now();
        Claim {
            id: ClaimId::new(),
            tenant_id: Some(tenant()),
            kind: ClaimKind::AnomalyFinding,
            subject: ClaimSubject::Dataset("analytics.public.revenue_daily".to_string()),
            predicate: "is_stale".to_string(),
            object: ClaimObject::Value(Value::Bool(true)),
            confidence: Confidence::new(0.91),
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

    #[test]
    fn stores_evidence_and_claims() {
        let mut store = EpistemicStore::new();
        let evidence = evidence();
        let claim = claim(evidence.id.clone());

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

        assert_eq!(store.evidence_count(), 1);
        assert_eq!(store.claim_count(), 1);
        assert_eq!(store.evidence(&evidence.id), Some(&evidence));
        assert_eq!(store.claim(&claim.id), Some(&claim));
    }

    #[test]
    fn supports_verifies_and_operationalizes_claims() {
        let mut store = EpistemicStore::new();
        let evidence = evidence();
        let mut claim = claim(evidence.id.clone());
        claim.evidence_for.clear();
        let claim_id = claim.id.clone();
        let evidence_id = evidence.id.clone();

        store
            .apply_event(&event(EventKind::EvidenceAdded { evidence }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ClaimProposed { claim }))
            .unwrap();
        assert_eq!(store.claim(&claim_id).unwrap().status, ClaimStatus::Proposed);

        store
            .apply_event(&event(EventKind::ClaimSupported {
                claim_id: claim_id.clone(),
                evidence_id: evidence_id.clone(),
            }))
            .unwrap();

        let supported = store.claim(&claim_id).unwrap();
        assert_eq!(supported.status, ClaimStatus::Supported);
        assert!(supported.evidence_for.contains(&evidence_id));

        store
            .apply_event(&event(EventKind::ClaimVerified {
                claim_id: claim_id.clone(),
                verified_by: actor(),
            }))
            .unwrap();
        assert_eq!(store.claim(&claim_id).unwrap().status, ClaimStatus::Verified);
        assert_eq!(store.verified_claims().len(), 1);

        store
            .apply_event(&event(EventKind::TopologyCommittedFromClaim {
                claim_id: claim_id.clone(),
                node_id: None,
                edge_id: None,
            }))
            .unwrap();
        assert_eq!(store.claim(&claim_id).unwrap().status, ClaimStatus::Operational);
        assert_eq!(store.operational_claims().len(), 1);
        assert_eq!(store.verified_claims().len(), 0);
    }

    #[test]
    fn disputes_claims_with_contradicting_evidence() {
        let mut store = EpistemicStore::new();
        let supporting = evidence();
        let contradicting = Evidence {
            id: EvidenceId::new(),
            ..evidence()
        };
        let claim = claim(supporting.id.clone());
        let claim_id = claim.id.clone();
        let contradicting_id = contradicting.id.clone();

        store
            .apply_event(&event(EventKind::EvidenceAdded {
                evidence: supporting,
            }))
            .unwrap();
        store
            .apply_event(&event(EventKind::EvidenceAdded {
                evidence: contradicting,
            }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ClaimProposed { claim }))
            .unwrap();

        store
            .apply_event(&event(EventKind::ClaimDisputed {
                claim_id: claim_id.clone(),
                evidence_id: contradicting_id.clone(),
                reason: Some("fresh warehouse update observed".to_string()),
            }))
            .unwrap();

        let disputed = store.claim(&claim_id).unwrap();
        assert_eq!(disputed.status, ClaimStatus::Disputed);
        assert!(disputed.evidence_against.contains(&contradicting_id));
        assert_eq!(store.disputed_claims().len(), 1);
    }

    #[test]
    fn rejects_unknown_evidence_reference() {
        let mut store = EpistemicStore::new();
        let claim = claim(EvidenceId::new());
        let claim_id = claim.id.clone();

        store
            .apply_event(&event(EventKind::ClaimProposed { claim }))
            .unwrap();

        let result = store.apply_event(&event(EventKind::ClaimSupported {
            claim_id,
            evidence_id: EvidenceId::new(),
        }));
        assert!(result.is_err());
    }

    #[test]
    fn claims_can_be_queried_by_subject_status_kind_and_evidence() {
        let mut store = EpistemicStore::new();
        let evidence = evidence();
        let evidence_id = evidence.id.clone();
        let claim = claim(evidence_id.clone());
        let subject = claim.subject.clone();
        let claim_id = claim.id.clone();

        store
            .apply_event(&event(EventKind::EvidenceAdded { evidence }))
            .unwrap();
        store
            .apply_event(&event(EventKind::ClaimProposed { claim }))
            .unwrap();

        assert_eq!(store.claims_for_subject(&subject).len(), 1);
        assert_eq!(store.claims_with_status(ClaimStatus::Proposed).len(), 1);
        assert_eq!(store.claims_with_kind(ClaimKind::AnomalyFinding).len(), 1);
        assert_eq!(store.claims_using_evidence(&evidence_id).len(), 1);
        assert_eq!(store.claims_using_evidence(&evidence_id)[0].id, claim_id);
    }
}
