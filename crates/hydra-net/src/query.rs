use hydra_core::edge::Edge;
use hydra_core::event::Event;
use hydra_core::graph::{bfs_dyn, TraversalDirection};
use hydra_core::id::{CascadeId, EdgeId, EventId, NodeId};
use hydra_core::node::Node;
use hydra_core::{
    Action, ActionId, ActionStatus, Claim, ClaimId, ClaimKind, ClaimStatus, ClaimSubject, Evidence,
    EvidenceId, Outcome, OutcomeId,
};
use hydra_engine::hydra::Hydra;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Thread-safe async query interface to Hydra.
///
/// Wraps the Hydra engine in an Arc<RwLock> so multiple query tasks can
/// read concurrently while ingestion holds the write lock.
///
/// All query methods acquire a read lock — they never block each other.
/// Only ingestion (via the runtime) acquires a write lock.
#[derive(Clone)]
pub struct QueryService {
    hydra: Arc<RwLock<Hydra>>,
}

impl QueryService {
    pub(crate) fn new(hydra: Arc<RwLock<Hydra>>) -> Self {
        Self { hydra }
    }

    // === Node queries ===

    /// Get a node by ID (cloned to release the lock)
    pub async fn node(&self, id: &NodeId) -> Option<Node> {
        let guard = self.hydra.read().await;
        guard.graph().node(id).cloned()
    }

    /// Check if a node exists and is alive
    pub async fn has_node(&self, id: &NodeId) -> bool {
        let guard = self.hydra.read().await;
        guard.graph().has_node(id)
    }

    /// Get all nodes of a specific type
    pub async fn nodes_by_type(&self, type_id: &str) -> Vec<Node> {
        let guard = self.hydra.read().await;
        guard.graph().nodes_by_type(type_id).into_iter().cloned().collect()
    }

    /// Count nodes of a specific type
    pub async fn count_nodes_by_type(&self, type_id: &str) -> usize {
        let guard = self.hydra.read().await;
        guard.graph().count_nodes_by_type(type_id)
    }

    /// Total alive node count
    pub async fn node_count(&self) -> usize {
        let guard = self.hydra.read().await;
        guard.graph().node_count()
    }

    // === Edge queries ===

    /// Get an edge by ID
    pub async fn edge(&self, id: &EdgeId) -> Option<Edge> {
        let guard = self.hydra.read().await;
        guard.graph().edge(id).cloned()
    }

    /// Get outgoing edges from a node
    pub async fn outgoing_edges(&self, node_id: &NodeId) -> Vec<Edge> {
        let guard = self.hydra.read().await;
        guard.graph().outgoing_edges(node_id).into_iter().cloned().collect()
    }

    /// Get incoming edges to a node
    pub async fn incoming_edges(&self, node_id: &NodeId) -> Vec<Edge> {
        let guard = self.hydra.read().await;
        guard.graph().incoming_edges(node_id).into_iter().cloned().collect()
    }

    /// Get neighbor nodes (both directions)
    pub async fn neighbors(&self, node_id: &NodeId) -> Vec<Node> {
        let guard = self.hydra.read().await;
        guard.graph().neighbors(node_id).into_iter().cloned().collect()
    }

    /// Total alive edge count
    pub async fn edge_count(&self) -> usize {
        let guard = self.hydra.read().await;
        guard.graph().edge_count()
    }

    // === Graph traversal ===

    /// BFS from a starting node
    pub async fn bfs(
        &self,
        start: &NodeId,
        direction: TraversalDirection,
    ) -> Vec<NodeId> {
        let guard = self.hydra.read().await;
        bfs_dyn(guard.graph(), start, direction, &|_| true)
    }

    /// BFS with a type filter — only traverse through nodes of the given type
    pub async fn bfs_by_type(
        &self,
        start: &NodeId,
        direction: TraversalDirection,
        type_filter: String,
    ) -> Vec<NodeId> {
        let guard = self.hydra.read().await;
        bfs_dyn(guard.graph(), start, direction, &|n| {
            n.type_id() == type_filter
        })
    }

    // === Causal queries ===

    /// What did this event cause? (forward chain)
    pub async fn causal_chain(&self, id: &EventId) -> Vec<Event> {
        let guard = self.hydra.read().await;
        guard.causal_chain(id).into_iter().cloned().collect()
    }

    /// What triggered this event? (backward chain)
    pub async fn root_cause(&self, id: &EventId) -> Vec<Event> {
        let guard = self.hydra.read().await;
        guard.root_cause(id).into_iter().cloned().collect()
    }

    /// All events in a cascade
    pub async fn cascade_events(&self, cascade_id: &CascadeId) -> Vec<Event> {
        let guard = self.hydra.read().await;
        guard.cascade_events(cascade_id).into_iter().cloned().collect()
    }

    // === Counterfactual queries ===

    /// What would the graph look like if this event hadn't happened?
    /// Returns the diff between actual and counterfactual state.
    pub async fn counterfactual(
        &self,
        event_id: &EventId,
    ) -> hydra_core::error::Result<hydra_engine::counterfactual::GraphDiff> {
        let guard = self.hydra.read().await;
        guard.counterfactual(event_id)
    }

    /// How much did this event change the graph?
    pub async fn impact_score(
        &self,
        event_id: &EventId,
    ) -> hydra_core::error::Result<hydra_engine::counterfactual::ImpactScore> {
        let guard = self.hydra.read().await;
        guard.impact_score(event_id)
    }

    // === Diagnostics ===

    /// Total events ever processed
    pub async fn total_events(&self) -> usize {
        let guard = self.hydra.read().await;
        guard.total_events()
    }

    /// Subscription count
    pub async fn subscription_count(&self) -> usize {
        let guard = self.hydra.read().await;
        guard.subscription_count()
    }

    /// Combined stats snapshot
    pub async fn stats(&self) -> QueryStats {
        let guard = self.hydra.read().await;
        QueryStats {
            node_count: guard.graph().node_count(),
            edge_count: guard.graph().edge_count(),
            total_events: guard.total_events(),
            subscription_count: guard.subscription_count(),
        }
    }

    // === Epistemic queries (claims + evidence) ===

    /// Get evidence by ID.
    pub async fn evidence(&self, id: &EvidenceId) -> Option<Evidence> {
        let hydra = self.hydra.read().await;
        hydra.evidence(id).cloned()
    }

    /// Get claim by ID.
    pub async fn claim(&self, id: &ClaimId) -> Option<Claim> {
        let hydra = self.hydra.read().await;
        hydra.claim(id).cloned()
    }

    /// Get all claims about a subject.
    pub async fn claims_for_subject(&self, subject: ClaimSubject) -> Vec<Claim> {
        let hydra = self.hydra.read().await;
        hydra
            .claims_for_subject(&subject)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all claims with a specific lifecycle status.
    pub async fn claims_with_status(&self, status: ClaimStatus) -> Vec<Claim> {
        let hydra = self.hydra.read().await;
        hydra
            .claims_with_status(status)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all claims of a specific kind.
    pub async fn claims_with_kind(&self, kind: ClaimKind) -> Vec<Claim> {
        let hydra = self.hydra.read().await;
        hydra
            .claims_with_kind(kind)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all verified claims.
    pub async fn verified_claims(&self) -> Vec<Claim> {
        let hydra = self.hydra.read().await;
        hydra
            .verified_claims()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all operational claims.
    ///
    /// Operational claims are beliefs that Hydra has accepted into active
    /// operational reality, usually after a topology commit or equivalent
    /// verification path.
    pub async fn operational_claims(&self) -> Vec<Claim> {
        let hydra = self.hydra.read().await;
        hydra
            .operational_claims()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all disputed claims.
    pub async fn disputed_claims(&self) -> Vec<Claim> {
        let hydra = self.hydra.read().await;
        hydra
            .disputed_claims()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all evidence-backed claims that use a specific evidence object.
    pub async fn claims_using_evidence(&self, evidence_id: &EvidenceId) -> Vec<Claim> {
        let hydra = self.hydra.read().await;
        hydra
            .epistemic_store()
            .claims_using_evidence(evidence_id)
            .into_iter()
            .cloned()
            .collect()
    }

    // === Action / outcome queries ===

    /// Get an action by ID.
    pub async fn action(&self, id: &ActionId) -> Option<Action> {
        let hydra = self.hydra.read().await;
        hydra.action(id).cloned()
    }

    /// Get an outcome by ID.
    pub async fn outcome(&self, id: &OutcomeId) -> Option<Outcome> {
        let hydra = self.hydra.read().await;
        hydra.outcome(id).cloned()
    }

    /// Get all actions with a specific lifecycle status.
    pub async fn actions_with_status(&self, status: ActionStatus) -> Vec<Action> {
        let hydra = self.hydra.read().await;
        hydra
            .actions_with_status(status)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all proposed actions.
    pub async fn proposed_actions(&self) -> Vec<Action> {
        let hydra = self.hydra.read().await;
        hydra
            .proposed_actions()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all approved actions.
    pub async fn approved_actions(&self) -> Vec<Action> {
        let hydra = self.hydra.read().await;
        hydra
            .approved_actions()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all executing actions.
    pub async fn executing_actions(&self) -> Vec<Action> {
        let hydra = self.hydra.read().await;
        hydra
            .executing_actions()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all executed actions.
    pub async fn executed_actions(&self) -> Vec<Action> {
        let hydra = self.hydra.read().await;
        hydra
            .executed_actions()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all failed actions.
    pub async fn failed_actions(&self) -> Vec<Action> {
        let hydra = self.hydra.read().await;
        hydra
            .failed_actions()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all cancelled actions.
    pub async fn cancelled_actions(&self) -> Vec<Action> {
        let hydra = self.hydra.read().await;
        hydra
            .action_store()
            .cancelled_actions()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all outcomes recorded for an action.
    pub async fn outcomes_for_action(&self, action_id: &ActionId) -> Vec<Outcome> {
        let hydra = self.hydra.read().await;
        hydra
            .outcomes_for_action(action_id)
            .into_iter()
            .cloned()
            .collect()
    }
}

/// A snapshot of graph statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct QueryStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub total_events: usize,
    pub subscription_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::{EventKind, Value};
    use hydra_core::id::{EdgeId, NodeId};
    use std::collections::HashMap;

    fn make_hydra() -> Arc<RwLock<Hydra>> {
        Arc::new(RwLock::new(Hydra::new()))
    }

    #[tokio::test]
    async fn query_empty_graph() {
        let qs = QueryService::new(make_hydra());
        assert_eq!(qs.node_count().await, 0);
        assert_eq!(qs.edge_count().await, 0);
        assert_eq!(qs.total_events().await, 0);
        assert!(!qs.has_node(&NodeId::from_str("node_GHOST")).await);
    }

    #[tokio::test]
    async fn query_after_ingest() {
        let hydra = make_hydra();
        let node_id = NodeId::new();

        // Ingest via write lock
        {
            let mut h = hydra.write().await;
            h.ingest(EventKind::NodeCreated {
                node_id: node_id.clone(),
                type_id: "ec2".to_string(),
                properties: HashMap::from([
                    ("state".to_string(), Value::String("running".to_string())),
                ]),
            })
            .unwrap();
        }

        // Query via QueryService
        let qs = QueryService::new(hydra);
        assert_eq!(qs.node_count().await, 1);
        assert!(qs.has_node(&node_id).await);

        let node = qs.node(&node_id).await.unwrap();
        assert_eq!(node.get_str("state"), Some("running"));
        assert_eq!(node.type_id(), "ec2");

        let ec2s = qs.nodes_by_type("ec2").await;
        assert_eq!(ec2s.len(), 1);
    }

    #[tokio::test]
    async fn query_edges() {
        let hydra = make_hydra();
        let a = NodeId::new();
        let b = NodeId::new();
        let edge_id = EdgeId::new();

        {
            let mut h = hydra.write().await;
            h.ingest(EventKind::NodeCreated {
                node_id: a.clone(),
                type_id: "ec2".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();
            h.ingest(EventKind::NodeCreated {
                node_id: b.clone(),
                type_id: "vpc".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();
            h.ingest(EventKind::EdgeCreated {
                edge_id: edge_id.clone(),
                source: a.clone(),
                target: b.clone(),
                type_id: "in_vpc".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();
        }

        let qs = QueryService::new(hydra);
        assert_eq!(qs.edge_count().await, 1);

        let outgoing = qs.outgoing_edges(&a).await;
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].target(), &b);

        let neighbors = qs.neighbors(&a).await;
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].type_id(), "vpc");
    }

    #[tokio::test]
    async fn query_stats() {
        let hydra = make_hydra();
        {
            let mut h = hydra.write().await;
            h.ingest(EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: "ec2".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();
        }

        let qs = QueryService::new(hydra);
        let stats = qs.stats().await;
        assert_eq!(stats.node_count, 1);
        assert_eq!(stats.total_events, 1);
    }

    #[tokio::test]
    async fn concurrent_reads_dont_block() {
        let hydra = make_hydra();
        {
            let mut h = hydra.write().await;
            for _ in 0..10 {
                h.ingest(EventKind::NodeCreated {
                    node_id: NodeId::new(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                })
                .unwrap();
            }
        }

        let qs = QueryService::new(hydra);

        // Spawn 10 concurrent reads
        let mut handles = Vec::new();
        for _ in 0..10 {
            let qs_clone = qs.clone();
            handles.push(tokio::spawn(async move {
                qs_clone.node_count().await
            }));
        }

        for handle in handles {
            let count = handle.await.unwrap();
            assert_eq!(count, 10);
        }
    }
}

#[cfg(test)]
mod epistemic_query_tests {
    use super::*;
    use hydra_core::{
        ActorId, CascadeId, Claim, ClaimId, ClaimKind, ClaimObject, ClaimStatus, ClaimSubject,
        Confidence, Event, EventId, EventKind, Evidence, EvidenceId, EvidencePayload,
        EvidenceSource, TenantId, Value,
    };
    use hydra_engine::hydra::Hydra;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_query_test")
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

    #[tokio::test]
    async fn query_service_exposes_epistemic_state() {
        let mut hydra = Hydra::new();
        let evidence = evidence();
        let claim = claim(evidence.id.clone());
        let evidence_id = evidence.id.clone();
        let claim_id = claim.id.clone();
        let subject = claim.subject.clone();

        hydra
            .ingest_event(event(EventKind::EvidenceAdded {
                evidence: evidence.clone(),
            }))
            .unwrap();
        hydra
            .ingest_event(event(EventKind::ClaimProposed {
                claim: claim.clone(),
            }))
            .unwrap();
        hydra
            .ingest_event(event(EventKind::ClaimVerified {
                claim_id: claim_id.clone(),
                verified_by: actor(),
            }))
            .unwrap();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));

        assert_eq!(service.evidence(&evidence_id).await, Some(evidence));
        assert_eq!(service.claim(&claim_id).await.unwrap().id, claim_id);
        assert_eq!(service.claims_for_subject(subject).await.len(), 1);
        assert_eq!(
            service.claims_with_kind(ClaimKind::AnomalyFinding).await.len(),
            1
        );
        assert_eq!(
            service.claims_with_status(ClaimStatus::Verified).await.len(),
            1
        );
        assert_eq!(service.verified_claims().await.len(), 1);
        assert_eq!(service.disputed_claims().await.len(), 0);
        assert_eq!(service.claims_using_evidence(&evidence_id).await.len(), 1);
    }

    #[tokio::test]
    async fn query_service_exposes_disputed_claims() {
        let mut hydra = Hydra::new();
        let support = evidence();
        let dispute = Evidence {
            id: EvidenceId::new(),
            ..evidence()
        };
        let claim = claim(support.id.clone());
        let claim_id = claim.id.clone();

        hydra
            .ingest_event(event(EventKind::EvidenceAdded { evidence: support }))
            .unwrap();
        hydra
            .ingest_event(event(EventKind::EvidenceAdded {
                evidence: dispute.clone(),
            }))
            .unwrap();
        hydra
            .ingest_event(event(EventKind::ClaimProposed { claim }))
            .unwrap();
        hydra
            .ingest_event(event(EventKind::ClaimDisputed {
                claim_id: claim_id.clone(),
                evidence_id: dispute.id.clone(),
                reason: Some("newer warehouse evidence contradicted stale claim".to_string()),
            }))
            .unwrap();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        let disputed = service.disputed_claims().await;
        assert_eq!(disputed.len(), 1);
        assert_eq!(disputed[0].id, claim_id);
        assert_eq!(disputed[0].status, ClaimStatus::Disputed);
    }
}

#[cfg(test)]
mod action_outcome_query_tests {
    use super::*;
    use hydra_core::{
        Action, ActionId, ActionKind, ActionStatus, ActionTarget, ActorId, EventKind, Outcome,
        OutcomeId, OutcomeKind, Value,
    };
    use hydra_engine::hydra::Hydra;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn actor() -> ActorId {
        ActorId::from_str("actor_prometheus")
    }

    fn action() -> Action {
        let now = chrono::Utc::now();
        let mut payload = HashMap::new();
        payload.insert(
            "reason".to_string(),
            Value::String("verified stale dataset claim".to_string()),
        );
        Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::Backfill,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::Dataset(
                "analytics.public.revenue_daily".to_string(),
            )],
            related_claims: vec![],
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
            tenant_id: None,
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

    #[tokio::test]
    async fn query_service_exposes_action_lifecycle_state() {
        let mut hydra = Hydra::new();
        let action = action();
        let action_id = action.id.clone();
        hydra
            .ingest(EventKind::ActionProposed {
                action: action.clone(),
            })
            .unwrap();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));

        // PolicyAgent auto-approves when no policy matches, so the materialized
        // action is in Approved state after a single ingest.
        let stored = service.action(&action_id).await.unwrap();
        assert_eq!(stored.id, action.id);
        assert_eq!(stored.status, ActionStatus::Approved);
        assert_eq!(service.proposed_actions().await.len(), 0);
        assert_eq!(
            service.actions_with_status(ActionStatus::Approved).await.len(),
            1
        );
        assert_eq!(service.approved_actions().await.len(), 1);
        assert_eq!(service.executed_actions().await.len(), 0);
    }

    #[tokio::test]
    async fn query_service_exposes_approved_and_executed_actions() {
        let mut hydra = Hydra::new();
        let action = action();
        let action_id = action.id.clone();
        hydra
            .ingest(EventKind::ActionProposed { action })
            .unwrap();
        hydra
            .ingest(EventKind::ActionApproved {
                action_id: action_id.clone(),
                approved_by: actor(),
            })
            .unwrap();
        hydra
            .ingest(EventKind::ActionExecuting {
                action_id: action_id.clone(),
            })
            .unwrap();
        hydra
            .ingest(EventKind::ActionExecuted {
                action_id: action_id.clone(),
            })
            .unwrap();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        assert_eq!(service.approved_actions().await.len(), 0);
        assert_eq!(service.executing_actions().await.len(), 0);
        assert_eq!(service.executed_actions().await.len(), 1);

        let fetched = service.action(&action_id).await.unwrap();
        assert_eq!(fetched.status, ActionStatus::Executed);
        assert!(fetched.executed_at.is_some());

        // OutcomeAgent emits an Unknown outcome for executed Backfill actions.
        let outcomes = service.outcomes_for_action(&action_id).await;
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].kind, OutcomeKind::Unknown);
    }

    #[tokio::test]
    async fn query_service_exposes_failed_and_cancelled_actions() {
        let mut hydra = Hydra::new();
        let failed = action();
        let failed_id = failed.id.clone();
        hydra
            .ingest(EventKind::ActionProposed { action: failed })
            .unwrap();
        hydra
            .ingest(EventKind::ActionFailed {
                action_id: failed_id.clone(),
                reason: "pipeline permission denied".to_string(),
            })
            .unwrap();

        let cancelled = action();
        let cancelled_id = cancelled.id.clone();
        hydra
            .ingest(EventKind::ActionProposed { action: cancelled })
            .unwrap();
        hydra
            .ingest(EventKind::ActionCancelled {
                action_id: cancelled_id.clone(),
                cancelled_by: actor(),
                reason: Some("manual override".to_string()),
            })
            .unwrap();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        assert_eq!(service.failed_actions().await.len(), 1);
        assert_eq!(service.cancelled_actions().await.len(), 1);
        assert_eq!(
            service.action(&failed_id).await.unwrap().status,
            ActionStatus::Failed
        );
        assert_eq!(
            service.action(&cancelled_id).await.unwrap().status,
            ActionStatus::Cancelled
        );
    }

    #[tokio::test]
    async fn query_service_exposes_explicit_outcomes() {
        let mut hydra = Hydra::new();
        let action = action();
        let action_id = action.id.clone();
        hydra
            .ingest(EventKind::ActionProposed { action })
            .unwrap();

        let outcome = outcome(action_id.clone());
        let outcome_id = outcome.id.clone();
        hydra
            .ingest(EventKind::OutcomeObserved {
                outcome: outcome.clone(),
            })
            .unwrap();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        assert_eq!(service.outcome(&outcome_id).await, Some(outcome));
        let outcomes = service.outcomes_for_action(&action_id).await;
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].id, outcome_id);
    }
}
