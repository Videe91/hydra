use hydra_core::edge::Edge;
use hydra_core::event::Event;
use hydra_core::graph::{bfs_dyn, TraversalDirection};
use hydra_core::id::{CascadeId, EdgeId, EventId, NodeId};
use hydra_core::node::Node;
use hydra_core::{
    Action, ActionId, ActionStatus, Claim, ClaimId, ClaimKind, ClaimStatus, ClaimSubject, Evidence,
    EvidenceId, Outcome, OutcomeId, SensorCheckpoint, SensorId, SensorRun, TenantId,
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

    /// All alive nodes (unfiltered). Read-side query API entry point —
    /// pairs with [`Self::node`] for single lookups.
    pub async fn nodes(&self) -> Vec<Node> {
        let guard = self.hydra.read().await;
        guard.all_nodes().into_iter().cloned().collect()
    }

    // === Edge queries ===

    /// Get an edge by ID
    pub async fn edge(&self, id: &EdgeId) -> Option<Edge> {
        let guard = self.hydra.read().await;
        guard.graph().edge(id).cloned()
    }

    /// All alive edges (unfiltered). Read-side query API entry point.
    pub async fn edges(&self) -> Vec<Edge> {
        let guard = self.hydra.read().await;
        guard.all_edges().into_iter().cloned().collect()
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

    /// Single event by id. Pair to the causal-chain / root-cause /
    /// counterfactual / impact routes — those need an existence check
    /// because their own return shapes (empty Vec, Err) don't always
    /// distinguish a leaf event from an unknown one.
    pub async fn event(&self, id: &EventId) -> Option<Event> {
        let guard = self.hydra.read().await;
        guard.event(id).cloned()
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

    /// All evidence (unfiltered). Read-side query API entry point.
    /// Named `evidence_items` to avoid collision with [`Self::evidence`].
    pub async fn evidence_items(&self) -> Vec<Evidence> {
        let hydra = self.hydra.read().await;
        hydra.all_evidence().into_iter().cloned().collect()
    }

    /// Get claim by ID.
    pub async fn claim(&self, id: &ClaimId) -> Option<Claim> {
        let hydra = self.hydra.read().await;
        hydra.claim(id).cloned()
    }

    /// All claims (unfiltered). Read-side query API entry point.
    pub async fn claims(&self) -> Vec<Claim> {
        let hydra = self.hydra.read().await;
        hydra.epistemic_store().all_claims().cloned().collect()
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

    /// All actions (unfiltered). Read-side query API entry point.
    pub async fn actions(&self) -> Vec<Action> {
        let hydra = self.hydra.read().await;
        hydra.action_store().all_actions().cloned().collect()
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

    // === Sensor queries ===

    /// All sensor runs recorded for a given sensor. Returns an empty
    /// vector when the sensor has no runs (sensor_id is just a string
    /// key — there is no "sensor exists?" notion at this layer).
    pub async fn runs_for_sensor(&self, sensor_id: &SensorId) -> Vec<SensorRun> {
        let hydra = self.hydra.read().await;
        hydra
            .runs_for_sensor(sensor_id)
            .into_iter()
            .cloned()
            .collect()
    }

    /// All checkpoints recorded for a given sensor.
    pub async fn checkpoints_for_sensor(&self, sensor_id: &SensorId) -> Vec<SensorCheckpoint> {
        let hydra = self.hydra.read().await;
        hydra
            .checkpoints_for_sensor(sensor_id)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Latest checkpoint for a (sensor, source) pair, or `None` if no
    /// checkpoint has been recorded for that combination yet. This is
    /// the read pair to `Hydra::record_sensor_observation`.
    pub async fn latest_sensor_checkpoint(
        &self,
        sensor_id: &SensorId,
        source: &str,
    ) -> Option<SensorCheckpoint> {
        let hydra = self.hydra.read().await;
        hydra.latest_sensor_checkpoint(sensor_id, source).cloned()
    }

    // === Tenant-aware queries (Multi-tenant Patch 2A) ===
    //
    // These mirror the non-tenant accessors above with strict scope:
    // `entity.tenant_id == Some(tenant)` — entities with `tenant_id: None`
    // (system/global data) are *not* returned. Single-id lookups return
    // `None` when the entity exists but belongs to another tenant so
    // HTTP handlers can 404 without leaking existence.

    pub async fn claims_for_tenant(&self, tenant: &TenantId) -> Vec<Claim> {
        self.claims()
            .await
            .into_iter()
            .filter(|c| c.tenant_id.as_ref() == Some(tenant))
            .collect()
    }

    pub async fn claim_for_tenant(&self, id: &ClaimId, tenant: &TenantId) -> Option<Claim> {
        self.claim(id)
            .await
            .filter(|c| c.tenant_id.as_ref() == Some(tenant))
    }

    pub async fn claims_with_status_for_tenant(
        &self,
        status: ClaimStatus,
        tenant: &TenantId,
    ) -> Vec<Claim> {
        self.claims_with_status(status)
            .await
            .into_iter()
            .filter(|c| c.tenant_id.as_ref() == Some(tenant))
            .collect()
    }

    pub async fn claims_with_kind_for_tenant(
        &self,
        kind: ClaimKind,
        tenant: &TenantId,
    ) -> Vec<Claim> {
        self.claims_with_kind(kind)
            .await
            .into_iter()
            .filter(|c| c.tenant_id.as_ref() == Some(tenant))
            .collect()
    }

    pub async fn claims_for_subject_for_tenant(
        &self,
        subject: ClaimSubject,
        tenant: &TenantId,
    ) -> Vec<Claim> {
        self.claims_for_subject(subject)
            .await
            .into_iter()
            .filter(|c| c.tenant_id.as_ref() == Some(tenant))
            .collect()
    }

    pub async fn claims_using_evidence_for_tenant(
        &self,
        evidence_id: &EvidenceId,
        tenant: &TenantId,
    ) -> Vec<Claim> {
        self.claims_using_evidence(evidence_id)
            .await
            .into_iter()
            .filter(|c| c.tenant_id.as_ref() == Some(tenant))
            .collect()
    }

    pub async fn evidence_for_tenant(
        &self,
        id: &EvidenceId,
        tenant: &TenantId,
    ) -> Option<Evidence> {
        self.evidence(id)
            .await
            .filter(|e| e.tenant_id.as_ref() == Some(tenant))
    }

    pub async fn evidence_items_for_tenant(&self, tenant: &TenantId) -> Vec<Evidence> {
        self.evidence_items()
            .await
            .into_iter()
            .filter(|e| e.tenant_id.as_ref() == Some(tenant))
            .collect()
    }

    pub async fn action_for_tenant(&self, id: &ActionId, tenant: &TenantId) -> Option<Action> {
        self.action(id)
            .await
            .filter(|a| a.tenant_id.as_ref() == Some(tenant))
    }

    pub async fn actions_for_tenant(&self, tenant: &TenantId) -> Vec<Action> {
        self.actions()
            .await
            .into_iter()
            .filter(|a| a.tenant_id.as_ref() == Some(tenant))
            .collect()
    }

    pub async fn actions_with_status_for_tenant(
        &self,
        status: ActionStatus,
        tenant: &TenantId,
    ) -> Vec<Action> {
        self.actions_with_status(status)
            .await
            .into_iter()
            .filter(|a| a.tenant_id.as_ref() == Some(tenant))
            .collect()
    }

    pub async fn outcome_for_tenant(
        &self,
        id: &OutcomeId,
        tenant: &TenantId,
    ) -> Option<Outcome> {
        self.outcome(id)
            .await
            .filter(|o| o.tenant_id.as_ref() == Some(tenant))
    }

    pub async fn outcomes_for_action_for_tenant(
        &self,
        action_id: &ActionId,
        tenant: &TenantId,
    ) -> Vec<Outcome> {
        self.outcomes_for_action(action_id)
            .await
            .into_iter()
            .filter(|o| o.tenant_id.as_ref() == Some(tenant))
            .collect()
    }

    pub async fn runs_for_sensor_for_tenant(
        &self,
        sensor_id: &SensorId,
        tenant: &TenantId,
    ) -> Vec<SensorRun> {
        self.runs_for_sensor(sensor_id)
            .await
            .into_iter()
            .filter(|r| r.tenant_id.as_ref() == Some(tenant))
            .collect()
    }

    pub async fn checkpoints_for_sensor_for_tenant(
        &self,
        sensor_id: &SensorId,
        tenant: &TenantId,
    ) -> Vec<SensorCheckpoint> {
        self.checkpoints_for_sensor(sensor_id)
            .await
            .into_iter()
            .filter(|c| c.tenant_id.as_ref() == Some(tenant))
            .collect()
    }

    pub async fn latest_sensor_checkpoint_for_tenant(
        &self,
        sensor_id: &SensorId,
        source: &str,
        tenant: &TenantId,
    ) -> Option<SensorCheckpoint> {
        self.latest_sensor_checkpoint(sensor_id, source)
            .await
            .filter(|c| c.tenant_id.as_ref() == Some(tenant))
    }

    /// Event lookup gated by tenant. Returns `None` when the event
    /// exists but its envelope's `tenant_id` doesn't match — same
    /// 404-on-other-tenant policy as the entity lookups above.
    pub async fn event_for_tenant(&self, id: &EventId, tenant: &TenantId) -> Option<Event> {
        self.event(id)
            .await
            .filter(|e| e.tenant_id.as_ref() == Some(tenant))
    }

    // === Tenant-aware graph topology (Multi-tenant Patch 2B) ===
    //
    // NodeMeta and EdgeMeta gained `tenant_id` in Patch 2B (stamped
    // from the creating Event's envelope), so these methods are now
    // strict filters on a real field rather than approximations.

    pub async fn nodes_for_tenant(&self, tenant: &TenantId) -> Vec<Node> {
        let guard = self.hydra.read().await;
        guard
            .all_nodes()
            .into_iter()
            .filter(|n| n.tenant_id() == Some(tenant))
            .cloned()
            .collect()
    }

    pub async fn node_for_tenant(&self, id: &NodeId, tenant: &TenantId) -> Option<Node> {
        self.node(id)
            .await
            .filter(|n| n.tenant_id() == Some(tenant))
    }

    pub async fn edges_for_tenant(&self, tenant: &TenantId) -> Vec<Edge> {
        let guard = self.hydra.read().await;
        guard
            .all_edges()
            .into_iter()
            .filter(|e| e.tenant_id() == Some(tenant))
            .cloned()
            .collect()
    }

    pub async fn edge_for_tenant(&self, id: &EdgeId, tenant: &TenantId) -> Option<Edge> {
        self.edge(id)
            .await
            .filter(|e| e.tenant_id() == Some(tenant))
    }

    /// Neighbors filtered to the requesting tenant. Other-tenant
    /// nodes connected to `node_id` are excluded — clients see only
    /// the slice of the graph they own.
    pub async fn neighbors_for_tenant(
        &self,
        node_id: &NodeId,
        tenant: &TenantId,
    ) -> Vec<Node> {
        self.neighbors(node_id)
            .await
            .into_iter()
            .filter(|n| n.tenant_id() == Some(tenant))
            .collect()
    }

    pub async fn outgoing_edges_for_tenant(
        &self,
        node_id: &NodeId,
        tenant: &TenantId,
    ) -> Vec<Edge> {
        self.outgoing_edges(node_id)
            .await
            .into_iter()
            .filter(|e| e.tenant_id() == Some(tenant))
            .collect()
    }

    pub async fn incoming_edges_for_tenant(
        &self,
        node_id: &NodeId,
        tenant: &TenantId,
    ) -> Vec<Edge> {
        self.incoming_edges(node_id)
            .await
            .into_iter()
            .filter(|e| e.tenant_id() == Some(tenant))
            .collect()
    }

    /// Strict tenant-scoped BFS. Both the start node and every node
    /// visited must belong to `tenant`; cross-tenant nodes are
    /// excluded from the result *and* from the traversal frontier
    /// (so an attacker can't reach into another tenant's graph by
    /// hopping through a shared node — there are no shared nodes
    /// under this contract).
    ///
    /// Returns an empty vector when:
    ///   - the start node doesn't exist, OR
    ///   - the start node belongs to a different tenant
    /// (HTTP handlers translate that into 404.)
    pub async fn bfs_for_tenant(
        &self,
        start: &NodeId,
        direction: TraversalDirection,
        tenant: &TenantId,
    ) -> Vec<NodeId> {
        self.bfs_for_tenant_inner(start, direction, tenant, None).await
    }

    /// Tenant-scoped BFS with an additional node-type filter.
    pub async fn bfs_by_type_for_tenant(
        &self,
        start: &NodeId,
        direction: TraversalDirection,
        type_filter: String,
        tenant: &TenantId,
    ) -> Vec<NodeId> {
        self.bfs_for_tenant_inner(start, direction, tenant, Some(type_filter)).await
    }

    async fn bfs_for_tenant_inner(
        &self,
        start: &NodeId,
        direction: TraversalDirection,
        tenant: &TenantId,
        type_filter: Option<String>,
    ) -> Vec<NodeId> {
        use std::collections::{HashSet, VecDeque};

        let guard = self.hydra.read().await;
        let graph = guard.graph();
        let mut result = Vec::new();

        // Gate the start: must exist, be alive, and belong to the
        // requesting tenant.
        match graph.node(start) {
            Some(node)
                if node.is_alive()
                    && node.tenant_id() == Some(tenant)
                    && type_filter
                        .as_deref()
                        .map_or(true, |t| node.type_id() == t) => {}
            _ => return result,
        }

        let mut visited: HashSet<NodeId> = HashSet::new();
        let mut queue: VecDeque<NodeId> = VecDeque::new();
        visited.insert(start.clone());
        queue.push_back(start.clone());

        while let Some(current) = queue.pop_front() {
            let Some(node) = graph.node(&current) else { continue };
            if !node.is_alive() || node.tenant_id() != Some(tenant) {
                continue;
            }
            if let Some(ref t) = type_filter {
                if node.type_id() != t {
                    continue;
                }
            }
            result.push(current.clone());

            let next_ids: Vec<NodeId> = match direction {
                TraversalDirection::Outgoing => graph
                    .outgoing_edges(&current)
                    .iter()
                    .map(|e| e.target().clone())
                    .collect(),
                TraversalDirection::Incoming => graph
                    .incoming_edges(&current)
                    .iter()
                    .map(|e| e.source().clone())
                    .collect(),
                TraversalDirection::Both => {
                    let mut ids: Vec<NodeId> = graph
                        .outgoing_edges(&current)
                        .iter()
                        .map(|e| e.target().clone())
                        .collect();
                    ids.extend(
                        graph
                            .incoming_edges(&current)
                            .iter()
                            .map(|e| e.source().clone()),
                    );
                    ids
                }
            };

            for next_id in next_ids {
                if visited.contains(&next_id) {
                    continue;
                }
                if let Some(next_node) = graph.node(&next_id) {
                    if next_node.is_alive() && next_node.tenant_id() == Some(tenant) {
                        if let Some(ref t) = type_filter {
                            if next_node.type_id() != t {
                                continue;
                            }
                        }
                        visited.insert(next_id.clone());
                        queue.push_back(next_id);
                    }
                }
            }
        }

        result
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
    async fn edges_returns_all_alive_edges() {
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
        let all = qs.edges().await;
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id(), &edge_id);
    }

    #[tokio::test]
    async fn nodes_returns_all_alive_nodes() {
        let hydra = make_hydra();
        let a = NodeId::new();
        let b = NodeId::new();
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
        }

        let qs = QueryService::new(hydra);
        let all = qs.nodes().await;
        assert_eq!(all.len(), 2);
        let ids: Vec<_> = all.iter().map(|n| n.id().clone()).collect();
        assert!(ids.contains(&a));
        assert!(ids.contains(&b));
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

    #[tokio::test]
    async fn evidence_items_returns_all_evidence() {
        let mut hydra = Hydra::new();
        let ev_one = evidence();
        let ev_two = Evidence {
            id: EvidenceId::new(),
            ..evidence()
        };
        let id_one = ev_one.id.clone();
        let id_two = ev_two.id.clone();
        hydra
            .ingest_event(event(EventKind::EvidenceAdded { evidence: ev_one }))
            .unwrap();
        hydra
            .ingest_event(event(EventKind::EvidenceAdded { evidence: ev_two }))
            .unwrap();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        let all = service.evidence_items().await;
        assert_eq!(all.len(), 2);
        let ids: Vec<_> = all.iter().map(|e| e.id.clone()).collect();
        assert!(ids.contains(&id_one));
        assert!(ids.contains(&id_two));
    }

    #[tokio::test]
    async fn claims_returns_all_claims_unfiltered() {
        let mut hydra = Hydra::new();
        let ev = evidence();
        let claim_one = claim(ev.id.clone());
        let claim_two = Claim {
            id: ClaimId::new(),
            ..claim(ev.id.clone())
        };
        let id_one = claim_one.id.clone();
        let id_two = claim_two.id.clone();

        hydra
            .ingest_event(event(EventKind::EvidenceAdded { evidence: ev }))
            .unwrap();
        hydra
            .ingest_event(event(EventKind::ClaimProposed { claim: claim_one }))
            .unwrap();
        hydra
            .ingest_event(event(EventKind::ClaimProposed { claim: claim_two }))
            .unwrap();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        let all = service.claims().await;
        assert_eq!(all.len(), 2);
        let ids: Vec<_> = all.iter().map(|c| c.id.clone()).collect();
        assert!(ids.contains(&id_one));
        assert!(ids.contains(&id_two));
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
                reason: None,
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

    #[tokio::test]
    async fn actions_returns_all_actions_unfiltered() {
        let mut hydra = Hydra::new();
        let action_one = action();
        let action_two = Action {
            id: ActionId::new(),
            ..action()
        };
        let id_one = action_one.id.clone();
        let id_two = action_two.id.clone();
        hydra
            .ingest(EventKind::ActionProposed { action: action_one })
            .unwrap();
        hydra
            .ingest(EventKind::ActionProposed { action: action_two })
            .unwrap();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        let all = service.actions().await;
        assert_eq!(all.len(), 2);
        let ids: Vec<_> = all.iter().map(|a| a.id.clone()).collect();
        assert!(ids.contains(&id_one));
        assert!(ids.contains(&id_two));
    }
}

#[cfg(test)]
mod sensor_query_tests {
    use super::*;
    use hydra_core::{EventKind, NodeId, SensorId, SourceCursor, Value};
    use hydra_engine::hydra::Hydra;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn sensor() -> SensorId {
        SensorId::from_str("sensor_bank")
    }

    fn signal(name: &str) -> EventKind {
        EventKind::Signal {
            source: NodeId::from_str("sensor.test"),
            name: name.to_string(),
            payload: HashMap::from([(
                "id".to_string(),
                Value::String(name.to_string()),
            )]),
        }
    }

    fn cursor(offset: &str) -> SourceCursor {
        SourceCursor::Offset {
            stream: "bank.transactions".to_string(),
            partition: Some("acct-9001".to_string()),
            offset: offset.to_string(),
        }
    }

    fn observe(hydra: &mut Hydra, offset: &str) {
        hydra
            .record_sensor_observation(
                sensor(),
                "bank",
                cursor(offset),
                signal(&format!("obs_{offset}")),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn runs_for_sensor_is_empty_when_no_runs() {
        let hydra = Arc::new(RwLock::new(Hydra::new()));
        let service = QueryService::new(hydra);
        assert!(service.runs_for_sensor(&sensor()).await.is_empty());
    }

    #[tokio::test]
    async fn checkpoints_for_sensor_reflects_recorded_observations() {
        let mut hydra = Hydra::new();
        observe(&mut hydra, "1");
        observe(&mut hydra, "2");
        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        let checkpoints = service.checkpoints_for_sensor(&sensor()).await;
        assert_eq!(checkpoints.len(), 2);
        assert!(checkpoints.iter().any(|c| matches!(
            &c.cursor,
            SourceCursor::Offset { offset, .. } if offset == "1"
        )));
        assert!(checkpoints.iter().any(|c| matches!(
            &c.cursor,
            SourceCursor::Offset { offset, .. } if offset == "2"
        )));
    }

    #[tokio::test]
    async fn latest_sensor_checkpoint_tracks_most_recent() {
        let mut hydra = Hydra::new();
        observe(&mut hydra, "1");
        observe(&mut hydra, "2");
        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        let latest = service
            .latest_sensor_checkpoint(&sensor(), "bank.transactions")
            .await
            .expect("expected a latest checkpoint after two observations");
        assert!(matches!(
            latest.cursor,
            SourceCursor::Offset { ref offset, .. } if offset == "2"
        ));

        // Unknown source returns None.
        assert!(service
            .latest_sensor_checkpoint(&sensor(), "unknown.stream")
            .await
            .is_none());
    }
}

#[cfg(test)]
mod tenant_query_tests {
    //! Tenant Patch 2A: QueryService tenant-aware filter tests.
    //! Helper coverage for `_for_tenant` variants — proves each
    //! filter actually excludes other-tenant data (no leaks).

    use super::*;
    use hydra_core::{
        ActionKind, ActionStatus, ActionTarget, ActorId, CascadeId, Confidence, Event, EventId,
        EventKind, EvidenceId, EvidencePayload, EvidenceSource, NodeId, SourceCursor, TenantId,
        Value,
    };
    use hydra_engine::hydra::Hydra;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn tenant_a() -> TenantId {
        TenantId::from_str("tenant_a")
    }
    fn tenant_b() -> TenantId {
        TenantId::from_str("tenant_b")
    }

    fn evt(kind: EventKind, owner: TenantId) -> Event {
        Event {
            id: EventId::new(),
            tenant_id: Some(owner),
            timestamp: chrono::Utc::now(),
            kind,
            caused_by: vec![],
            cascade_id: CascadeId::new(),
            cascade_depth: 0,
            cascade_breadth_index: 0,
        }
    }

    fn evidence_for(owner: TenantId) -> Evidence {
        Evidence {
            id: EvidenceId::new(),
            tenant_id: Some(owner),
            source: EvidenceSource::Warehouse {
                system: "x".into(),
                database: None,
                schema: None,
                table: None,
            },
            payload: EvidencePayload {
                kind: "k".to_string(),
                data: HashMap::new(),
            },
            reliability: Confidence::new(0.9),
            observed_at: chrono::Utc::now(),
            recorded_at: chrono::Utc::now(),
            caused_by: None,
        }
    }

    fn claim_for(owner: TenantId, ev_id: EvidenceId) -> Claim {
        let now = chrono::Utc::now();
        Claim {
            id: ClaimId::new(),
            tenant_id: Some(owner),
            kind: ClaimKind::AnomalyFinding,
            subject: ClaimSubject::Dataset("d".to_string()),
            predicate: "p".to_string(),
            object: hydra_core::ClaimObject::Value(Value::Bool(true)),
            confidence: Confidence::new(0.9),
            status: ClaimStatus::Proposed,
            evidence_for: vec![ev_id],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: ActorId::from_str("actor_a"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn action_for(owner: TenantId) -> Action {
        let now = chrono::Utc::now();
        Action {
            id: ActionId::new(),
            tenant_id: Some(owner),
            kind: ActionKind::Backfill,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::Dataset("d".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_a"),
            approved_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        }
    }

    #[tokio::test]
    async fn claims_for_tenant_filters() {
        let mut hydra = Hydra::new();
        let ev_a = evidence_for(tenant_a());
        let ev_b = evidence_for(tenant_b());
        let cl_a = claim_for(tenant_a(), ev_a.id.clone());
        let cl_b = claim_for(tenant_b(), ev_b.id.clone());
        let cl_a_id = cl_a.id.clone();
        hydra
            .ingest_event(evt(EventKind::EvidenceAdded { evidence: ev_a }, tenant_a()))
            .unwrap();
        hydra
            .ingest_event(evt(EventKind::EvidenceAdded { evidence: ev_b }, tenant_b()))
            .unwrap();
        hydra
            .ingest_event(evt(EventKind::ClaimProposed { claim: cl_a }, tenant_a()))
            .unwrap();
        hydra
            .ingest_event(evt(EventKind::ClaimProposed { claim: cl_b }, tenant_b()))
            .unwrap();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        let a_claims = service.claims_for_tenant(&tenant_a()).await;
        assert_eq!(a_claims.len(), 1);
        assert_eq!(a_claims[0].id, cl_a_id);

        // Single-id lookup across tenants: tenant_a can fetch their
        // claim, but lookup of tenant_b's claim returns None.
        assert!(service
            .claim_for_tenant(&cl_a_id, &tenant_a())
            .await
            .is_some());
        let b_claim_id = service.claims_for_tenant(&tenant_b()).await[0].id.clone();
        assert!(service
            .claim_for_tenant(&b_claim_id, &tenant_a())
            .await
            .is_none());
    }

    #[tokio::test]
    async fn evidence_for_tenant_filters() {
        let mut hydra = Hydra::new();
        let ev_a = evidence_for(tenant_a());
        let ev_b = evidence_for(tenant_b());
        let ev_a_id = ev_a.id.clone();
        let ev_b_id = ev_b.id.clone();
        hydra
            .ingest_event(evt(EventKind::EvidenceAdded { evidence: ev_a }, tenant_a()))
            .unwrap();
        hydra
            .ingest_event(evt(EventKind::EvidenceAdded { evidence: ev_b }, tenant_b()))
            .unwrap();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        let a_view = service.evidence_items_for_tenant(&tenant_a()).await;
        assert_eq!(a_view.len(), 1);
        assert_eq!(a_view[0].id, ev_a_id);
        assert!(service
            .evidence_for_tenant(&ev_b_id, &tenant_a())
            .await
            .is_none());
    }

    #[tokio::test]
    async fn actions_for_tenant_filters() {
        let mut hydra = Hydra::new();
        let action_a = action_for(tenant_a());
        let action_a_id = action_a.id.clone();
        let action_b = action_for(tenant_b());
        let action_b_id = action_b.id.clone();
        hydra
            .ingest_for_tenant(EventKind::ActionProposed { action: action_a }, tenant_a())
            .unwrap();
        hydra
            .ingest_for_tenant(EventKind::ActionProposed { action: action_b }, tenant_b())
            .unwrap();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        let a_view = service.actions_for_tenant(&tenant_a()).await;
        assert_eq!(a_view.len(), 1);
        assert_eq!(a_view[0].id, action_a_id);
        assert!(service
            .action_for_tenant(&action_b_id, &tenant_a())
            .await
            .is_none());
    }

    #[tokio::test]
    async fn sensor_checkpoints_for_tenant_filters() {
        let mut hydra = Hydra::new();
        let cursor = |off: &str| SourceCursor::Offset {
            stream: "s".to_string(),
            partition: Some("p".to_string()),
            offset: off.to_string(),
        };
        let signal = |name: &str| EventKind::Signal {
            source: NodeId::from_str("test"),
            name: name.to_string(),
            payload: HashMap::new(),
        };
        let cp_a = hydra
            .record_sensor_observation_for_tenant(
                hydra_core::SensorId::from_str("sensor_x"),
                "sys",
                cursor("a"),
                signal("a"),
                tenant_a(),
            )
            .unwrap();
        let _cp_b = hydra
            .record_sensor_observation_for_tenant(
                hydra_core::SensorId::from_str("sensor_x"),
                "sys",
                cursor("b"),
                signal("b"),
                tenant_b(),
            )
            .unwrap();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        let a_view = service
            .checkpoints_for_sensor_for_tenant(
                &hydra_core::SensorId::from_str("sensor_x"),
                &tenant_a(),
            )
            .await;
        assert_eq!(a_view.len(), 1);
        assert_eq!(a_view[0].id, cp_a.id);
    }

    #[tokio::test]
    async fn event_for_tenant_hides_other_tenant() {
        let mut hydra = Hydra::new();
        let result_a = hydra
            .ingest_for_tenant(
                EventKind::Signal {
                    source: NodeId::from_str("a"),
                    name: "a".to_string(),
                    payload: HashMap::new(),
                },
                tenant_a(),
            )
            .unwrap();
        let result_b = hydra
            .ingest_for_tenant(
                EventKind::Signal {
                    source: NodeId::from_str("b"),
                    name: "b".to_string(),
                    payload: HashMap::new(),
                },
                tenant_b(),
            )
            .unwrap();
        let event_a_id = result_a.events[0].id.clone();
        let event_b_id = result_b.events[0].id.clone();

        let service = QueryService::new(Arc::new(RwLock::new(hydra)));
        assert!(service
            .event_for_tenant(&event_a_id, &tenant_a())
            .await
            .is_some());
        assert!(service
            .event_for_tenant(&event_b_id, &tenant_a())
            .await
            .is_none());
    }
}
