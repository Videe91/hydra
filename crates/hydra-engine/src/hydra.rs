use crate::anomaly::{Anomaly, AnomalyEngine};
use crate::cascade::{CascadeConfig, CascadeEngine, CascadeResult};
use crate::commit_ledger::CommitLedger;
use crate::coverage::{CoverageEngine, CoverageReport};
use crate::sensor_checkpoint_store::SensorCheckpointStore;
use crate::action_store::ActionStore;
use crate::epistemic_store::EpistemicStore;
use crate::event_log::EventLog;
use crate::evolution::SubscriptionTracker;
use crate::projection::Projection;
use crate::registry::SubscriptionRegistry;
use crate::temporal::TemporalIndex;
use crate::outcome_agent::OutcomeAgent;
use crate::policy_agent::PolicyAgent;
use crate::policy_engine::PolicyEngine;
use crate::policy_store::PolicyStore;
use crate::reflex::ReflexRegistry;
use crate::remediation_agent::RemediationAgent;
use crate::verification::{VerificationEngine, VerificationPolicy, VerificationReport};
use crate::verification_agent::VerificationAgent;
use hydra_core::event::{Event, EventKind};
use hydra_core::graph::GraphReader;
use hydra_core::id::{ActorId, CascadeId, ClaimId, EventId, EvidenceId, SubscriptionId, TenantId};
use hydra_core::subscription::Subscription;
use hydra_core::{Claim, ClaimKind, ClaimStatus, ClaimSubject, Evidence};

/// The complete Hydra engine. Single entry point for all operations.
///
/// Composes: Projection (current state) + EventLog (history) +
/// SubscriptionRegistry (reactive rules) + CascadeEngine (processing loop) +
/// TemporalIndex (temporal versioning for state_at/diff/trend queries) +
/// AnomalyEngine (graph-native anomaly detection) +
/// SubscriptionTracker (self-evolving subscription effectiveness tracking) +
/// CoverageEngine (graph completeness reasoning).
///
/// Usage:
/// ```ignore
/// let mut hydra = Hydra::new();
/// hydra.register(subscription);
/// let result = hydra.ingest(event_kind)?;
/// let node = hydra.graph().node(&node_id);
/// ```
pub struct Hydra {
    projection: Projection,
    event_log: EventLog,
    registry: SubscriptionRegistry,
    engine: CascadeEngine,
    temporal: TemporalIndex,
    anomaly_engine: AnomalyEngine,
    tracker: SubscriptionTracker,
    coverage_engine: CoverageEngine,
    epistemic_store: EpistemicStore,
    verification_engine: VerificationEngine,
    verification_agent: VerificationAgent,
    remediation_agent: RemediationAgent,
    action_store: ActionStore,
    outcome_agent: OutcomeAgent,
    policy_store: PolicyStore,
    policy_engine: PolicyEngine,
    policy_agent: PolicyAgent,
    commit_ledger: CommitLedger,
    commit_writer: Option<Box<dyn crate::commit_ledger::CommitBatchWriter>>,
    sensor_checkpoint_store: SensorCheckpointStore,
    reflex_registry: ReflexRegistry,
    limits: ResourceLimits,
    /// Optional WAL for crash recovery
    wal: Option<Box<dyn WalWriter>>,
}

/// Configurable resource limits to prevent unbounded growth.
/// All limits default to `usize::MAX` (effectively unlimited).
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_events: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_nodes: usize::MAX,
            max_edges: usize::MAX,
            max_events: usize::MAX,
        }
    }
}

/// Write-ahead log trait. Implementations persist events durably
/// before they are processed by the cascade engine.
///
/// The WAL is the crash-recovery mechanism:
/// 1. Event arrives → WAL.append() → durable
/// 2. Cascade processes event → in-memory state updated
/// 3. On crash → replay WAL to rebuild state
///
/// Callers can implement this trait using hydra-storage backends,
/// file I/O, or any durable storage.
pub trait WalWriter: Send + Sync {
    /// Persist events durably. Called AFTER cascade processing
    /// with the full set of cascade events (trigger + reactions).
    /// Must be durable before returning (fsync or equivalent).
    fn persist_cascade(&mut self, events: &[Event]) -> hydra_core::error::Result<()>;

    /// Persist a checkpoint marker. The checkpoint ID references
    /// the last event that was included. On recovery, events after
    /// this checkpoint are replayed.
    fn persist_checkpoint(&mut self, checkpoint_event_id: &EventId) -> hydra_core::error::Result<()>;
}

impl Hydra {
    pub fn new() -> Self {
        Self {
            projection: Projection::new(),
            event_log: EventLog::new(),
            registry: SubscriptionRegistry::new(),
            engine: CascadeEngine::with_defaults(),
            temporal: TemporalIndex::new(),
            anomaly_engine: AnomalyEngine::new(),
            tracker: SubscriptionTracker::new(),
            coverage_engine: CoverageEngine::new(),
            epistemic_store: EpistemicStore::new(),
            verification_engine: VerificationEngine::with_default_policy(),
            verification_agent: VerificationAgent::new(ActorId::from_str("actor_hydra_verifier")),
            remediation_agent: RemediationAgent::new(ActorId::from_str("actor_hydra_prometheus")),
            action_store: ActionStore::new(),
            outcome_agent: OutcomeAgent::new(ActorId::from_str("actor_hydra_sentinel")),
            policy_store: PolicyStore::new(),
            policy_engine: PolicyEngine::new(),
            policy_agent: PolicyAgent::new(
                ActorId::from_str("actor_hydra_policy"),
                ActorId::from_str("actor_hydra_approver"),
            ),
            commit_ledger: CommitLedger::new(),
            commit_writer: None,
            sensor_checkpoint_store: SensorCheckpointStore::new(),
            reflex_registry: ReflexRegistry::new(),
            limits: ResourceLimits::default(),
            wal: None,
        }
    }

    pub fn with_config(config: CascadeConfig) -> Self {
        Self {
            projection: Projection::new(),
            event_log: EventLog::new(),
            registry: SubscriptionRegistry::new(),
            engine: CascadeEngine::new(config),
            temporal: TemporalIndex::new(),
            anomaly_engine: AnomalyEngine::new(),
            tracker: SubscriptionTracker::new(),
            coverage_engine: CoverageEngine::new(),
            epistemic_store: EpistemicStore::new(),
            verification_engine: VerificationEngine::with_default_policy(),
            verification_agent: VerificationAgent::new(ActorId::from_str("actor_hydra_verifier")),
            remediation_agent: RemediationAgent::new(ActorId::from_str("actor_hydra_prometheus")),
            action_store: ActionStore::new(),
            outcome_agent: OutcomeAgent::new(ActorId::from_str("actor_hydra_sentinel")),
            policy_store: PolicyStore::new(),
            policy_engine: PolicyEngine::new(),
            policy_agent: PolicyAgent::new(
                ActorId::from_str("actor_hydra_policy"),
                ActorId::from_str("actor_hydra_approver"),
            ),
            commit_ledger: CommitLedger::new(),
            commit_writer: None,
            sensor_checkpoint_store: SensorCheckpointStore::new(),
            reflex_registry: ReflexRegistry::new(),
            limits: ResourceLimits::default(),
            wal: None,
        }
    }

    /// Attach a WAL writer for crash recovery.
    /// When set, all cascade events are persisted after processing.
    pub fn set_wal(&mut self, wal: Box<dyn WalWriter>) {
        self.wal = Some(wal);
    }

    /// Set resource limits for this Hydra instance
    pub fn set_limits(&mut self, limits: ResourceLimits) {
        self.limits = limits;
    }

    /// Check resource limits before ingestion
    fn check_limits(&self) -> hydra_core::error::Result<()> {
        let nodes = self.projection.node_count();
        if nodes >= self.limits.max_nodes {
            return Err(hydra_core::error::HydraError::ResourceExhausted {
                resource: "nodes".to_string(),
                limit: self.limits.max_nodes,
                current: nodes,
            });
        }
        let edges = self.projection.edge_count();
        if edges >= self.limits.max_edges {
            return Err(hydra_core::error::HydraError::ResourceExhausted {
                resource: "edges".to_string(),
                limit: self.limits.max_edges,
                current: edges,
            });
        }
        let events = self.event_log.len();
        if events >= self.limits.max_events {
            return Err(hydra_core::error::HydraError::ResourceExhausted {
                resource: "events".to_string(),
                limit: self.limits.max_events,
                current: events,
            });
        }
        Ok(())
    }

    // === Ingestion ===

    /// Ingest an event kind as a new trigger.
    /// Processes the full cascade and returns the result.
    pub fn ingest(&mut self, kind: EventKind) -> hydra_core::error::Result<CascadeResult> {
        self.ingest_internal(kind, None)
    }

    /// Ingest an event kind scoped to a specific tenant.
    /// Only tenant-scoped subscriptions (or global subscriptions) will fire.
    pub fn ingest_for_tenant(
        &mut self,
        kind: EventKind,
        tenant: TenantId,
    ) -> hydra_core::error::Result<CascadeResult> {
        self.ingest_internal(kind, Some(tenant))
    }

    /// Internal ingest with optional tenant scoping.
    fn ingest_internal(
        &mut self,
        kind: EventKind,
        tenant: Option<TenantId>,
    ) -> hydra_core::error::Result<CascadeResult> {
        self.check_limits()?;
        let event = match tenant {
            Some(t) => Event::trigger_for_tenant(kind, t),
            None => Event::trigger(kind),
        };
        self.ingest_event_internal(event, None)
    }

    /// Ingest a pre-built Event (useful for replay)
    pub fn ingest_event(&mut self, event: Event) -> hydra_core::error::Result<CascadeResult> {
        self.ingest_event_internal(event, None)
    }

    /// Ingest an EventKind with an idempotency key.
    ///
    /// If the key has already been committed, Hydra returns the original
    /// committed cascade events and does NOT rerun the cascade. This makes
    /// external retries safe — no duplicate state mutations, no duplicate
    /// commit batches, no duplicate writer appends.
    pub fn ingest_with_idempotency_key(
        &mut self,
        kind: EventKind,
        key: hydra_core::IdempotencyKey,
    ) -> hydra_core::error::Result<CascadeResult> {
        self.check_limits()?;
        let event = Event::trigger(kind);
        self.ingest_event_internal(event, Some(key))
    }

    /// Ingest a pre-built Event with an idempotency key.
    ///
    /// Duplicate keys short-circuit before cascade processing.
    pub fn ingest_event_with_idempotency_key(
        &mut self,
        event: Event,
        key: hydra_core::IdempotencyKey,
    ) -> hydra_core::error::Result<CascadeResult> {
        self.ingest_event_internal(event, Some(key))
    }

    /// Shared cascade + commit + writer + WAL body.
    ///
    /// When `idempotency_key` is `Some`, looks up the key in the commit ledger
    /// first. If it's already been committed, returns the original events as a
    /// `CascadeResult` without running the cascade, mutating state, appending
    /// a commit, or writing to the durable sink.
    fn ingest_event_internal(
        &mut self,
        event: Event,
        idempotency_key: Option<hydra_core::IdempotencyKey>,
    ) -> hydra_core::error::Result<CascadeResult> {
        // Idempotent short-circuit BEFORE cascade — duplicate retries return
        // the original committed events.
        if let Some(key) = &idempotency_key {
            if let Some(batch) = self.commit_ledger.commit_for_idempotency_key(key) {
                return Ok(CascadeResult::from_committed_events(batch.events.clone()));
            }
        }

        // The cascade engine drives both topology projection AND the epistemic
        // store, so verification / remediation / policy / outcome reflexes
        // see fresh state inline.
        let result = self.engine.process_with_epistemics(
            event,
            &mut self.projection,
            &self.registry,
            &mut self.epistemic_store,
            &self.verification_engine,
            &self.verification_agent,
            &self.remediation_agent,
            &mut self.action_store,
            &self.outcome_agent,
            &mut self.policy_store,
            &self.policy_engine,
            &self.policy_agent,
            &self.reflex_registry,
        )?;

        // Record all events in the log AND the temporal index.
        // The sensor checkpoint store is post-cascade for now — no sensor
        // agent runs inline yet. When one is wired, move into the cascade.
        for event in &result.events {
            self.event_log.append(event.clone());
            self.temporal.record(event);
            self.sensor_checkpoint_store.apply_event(event)?;
        }

        // Record an atomic commit batch for this cascade. v0 ledger is
        // in-memory; if a CommitBatchWriter is attached, the batch is also
        // appended durably.
        let commit = self
            .commit_ledger
            .commit_events(result.events.clone(), idempotency_key)?;
        if let Some(writer) = &self.commit_writer {
            writer.append_commit(&commit)?;
        }

        // I8: Persist cascade events to WAL (if configured)
        if let Some(ref mut wal) = self.wal {
            wal.persist_cascade(&result.events)?;
        }

        // Auto-compact event log if over threshold
        self.event_log.auto_compact();

        // Track subscription fires for self-evolution
        self.tracker.record_cascade(&result, &self.registry);

        // I4: Truncation alarm — if cascade was truncated, emit a warning signal
        // as a SEPARATE cascade to avoid recursive truncation
        if result.truncated {
            let dropped_count = result.events.len();
            let mut payload = std::collections::HashMap::new();
            payload.insert(
                "cascade_id".to_string(),
                hydra_core::event::Value::String(
                    result.events.first()
                        .map(|e| e.cascade_id.as_str().to_string())
                        .unwrap_or_default(),
                ),
            );
            payload.insert(
                "events_processed".to_string(),
                hydra_core::event::Value::Int(dropped_count as i64),
            );
            payload.insert(
                "max_depth_reached".to_string(),
                hydra_core::event::Value::Int(result.max_depth_reached as i64),
            );

            // Fire truncation alarm as a new, separate cascade
            // Use a minimal cascade config to prevent alarm cascades from also truncating
            let alarm_event = Event::trigger(EventKind::Signal {
                source: hydra_core::id::NodeId::from_str("hydra_engine"),
                name: "cascade_truncated".to_string(),
                payload,
            });
            // Apply directly — don't recurse through full ingest
            let _ = self.projection.apply(&alarm_event);
            self.event_log.append(alarm_event.clone());
            self.temporal.record(&alarm_event);
        }

        Ok(result)
    }

    // === Subscriptions ===

    /// Register a subscription (reactive rule)
    pub fn register(&mut self, sub: Subscription) -> SubscriptionId {
        self.registry.register(sub)
    }

    /// Unregister a subscription
    pub fn unregister(&mut self, id: &SubscriptionId) -> bool {
        self.registry.unregister(id)
    }

    /// Enable/disable a subscription
    pub fn set_enabled(&mut self, id: &SubscriptionId, enabled: bool) -> bool {
        self.registry.set_enabled(id, enabled)
    }

    // === Anomaly Detection ===

    // === Persistence (WAL + Checkpoint + Recovery) ===

    /// Create a checkpoint. Records the current event log position
    /// so that on recovery, only events after this point need replaying.
    /// Returns the checkpoint event ID, or None if the log is empty.
    pub fn checkpoint(&mut self) -> hydra_core::error::Result<Option<EventId>> {
        let last_event_id = match self.event_log.iter().last() {
            Some(e) => e.id.clone(),
            None => return Ok(None),
        };

        if let Some(ref mut wal) = self.wal {
            wal.persist_checkpoint(&last_event_id)?;
        }

        Ok(Some(last_event_id))
    }

    /// Recover state by replaying events.
    /// This rebuilds the projection, temporal index, and event log
    /// from a sequence of historical events (e.g., read from WAL/storage).
    ///
    /// Events are applied in order without triggering subscriptions
    /// (since the original cascade already happened — we just need state).
    pub fn recover_from_events(&mut self, events: Vec<Event>) -> hydra_core::error::Result<usize> {
        let mut count = 0;
        for event in events {
            self.projection.apply(&event)?;
            self.event_log.append(event.clone());
            self.temporal.record(&event);
            self.epistemic_store.apply_event(&event)?;
            self.action_store.apply_event(&event)?;
            self.policy_store.apply_event(&event)?;
            self.sensor_checkpoint_store.apply_event(&event)?;
            count += 1;
        }
        Ok(count)
    }

    /// Recover Hydra state from committed batches.
    ///
    /// This is database recovery:
    /// - rebuild the in-memory CommitLedger from supplied committed batches
    /// - verify the hash chain
    /// - replay committed events in sequence
    /// - rebuild graph, temporal, epistemic, action, and policy stores
    ///
    /// It does not:
    /// - run cascades
    /// - run agents/reflexes
    /// - append new commits
    /// - write to the commit writer
    pub fn recover_from_commits(
        &mut self,
        batches: Vec<hydra_core::CommitBatch>,
    ) -> hydra_core::error::Result<()> {
        // First validate/rebuild a fresh ledger. Do this before mutating
        // runtime state so an invalid commit log does not partially recover.
        let mut recovered_ledger = CommitLedger::new();
        recovered_ledger.load_committed_batches(batches)?;

        let mut events = Vec::new();
        for batch in recovered_ledger.batches_in_sequence() {
            events.extend(batch.events.iter().cloned());
        }

        self.reset_runtime_state_preserving_config();
        self.commit_ledger = recovered_ledger;
        self.recover_from_events(events)?;
        Ok(())
    }

    /// Reset runtime-derived state while preserving configuration and pluggable hooks.
    ///
    /// This is used before recovery so replay starts from a clean projection.
    /// Engines, agents, reflex registry, commit writer, WAL, and resource
    /// limits are all preserved.
    fn reset_runtime_state_preserving_config(&mut self) {
        self.projection = Projection::new();
        self.event_log = EventLog::with_config(self.event_log.config().clone());
        self.temporal = TemporalIndex::new();
        self.epistemic_store = EpistemicStore::new();
        self.action_store = ActionStore::new();
        self.policy_store = PolicyStore::new();
        self.sensor_checkpoint_store = SensorCheckpointStore::new();
    }

    // === Anomaly Detection (cont.) ===

    /// Mutable access to the anomaly engine for adding rules
    pub fn anomaly_engine_mut(&mut self) -> &mut AnomalyEngine {
        &mut self.anomaly_engine
    }

    /// Read access to the anomaly engine
    pub fn anomaly_engine(&self) -> &AnomalyEngine {
        &self.anomaly_engine
    }

    /// Run real-time anomaly analysis on a cascade result.
    /// Called automatically by ingest() — or manually for external cascade results.
    pub fn analyze_cascade(&self, result: &CascadeResult) -> Vec<Anomaly> {
        self.anomaly_engine.analyze_cascade(result, &self.projection)
    }

    /// Run batch anomaly detection across the entire graph.
    /// Call this periodically (e.g., every minute) or on demand.
    pub fn analyze_batch(&self) -> Vec<Anomaly> {
        self.anomaly_engine
            .analyze_batch(&self.projection, &self.temporal, &self.event_log)
    }

    // === Subscription Evolution ===

    /// Mutable access to the subscription tracker
    pub fn tracker_mut(&mut self) -> &mut SubscriptionTracker {
        &mut self.tracker
    }

    /// Read access to the subscription tracker
    pub fn tracker(&self) -> &SubscriptionTracker {
        &self.tracker
    }

    // === Queries ===

    /// Read-only access to the current graph state
    pub fn graph(&self) -> &dyn GraphReader {
        &self.projection
    }

    /// Access the event log for causal queries
    pub fn event_log(&self) -> &EventLog {
        &self.event_log
    }

    /// Mutable access to the event log (for configuring retention policy).
    pub fn event_log_mut(&mut self) -> &mut EventLog {
        &mut self.event_log
    }

    /// Convenience: trace what an event caused
    pub fn causal_chain(&self, id: &EventId) -> Vec<&Event> {
        self.event_log.causal_chain(id)
    }

    /// Convenience: trace back to root cause
    pub fn root_cause(&self, id: &EventId) -> Vec<&Event> {
        self.event_log.root_cause(id)
    }

    /// Convenience: all events in a cascade
    pub fn cascade_events(&self, cascade_id: &CascadeId) -> Vec<&Event> {
        self.event_log.cascade_events(cascade_id)
    }

    // === Temporal queries ===

    /// Access the temporal index directly for advanced queries
    pub fn temporal(&self) -> &TemporalIndex {
        &self.temporal
    }

    /// Get a node's properties at a specific point in time
    pub fn node_state_at(
        &self,
        node_id: &hydra_core::id::NodeId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Option<std::collections::HashMap<String, hydra_core::event::Value>> {
        self.temporal.node_state_at(node_id, at)
    }

    /// Diff the graph between two points in time
    pub fn temporal_diff(
        &self,
        from: chrono::DateTime<chrono::Utc>,
        to: chrono::DateTime<chrono::Utc>,
    ) -> crate::temporal::TemporalDiff {
        self.temporal.diff(from, to)
    }

    /// Get a property's trend over time
    pub fn trend(
        &self,
        node_id: &hydra_core::id::NodeId,
        property: &str,
    ) -> Vec<(chrono::DateTime<chrono::Utc>, hydra_core::event::Value)> {
        self.temporal.node_trend(node_id, property)
    }

    /// Materialize the graph at a specific point in time.
    /// Returns a `TemporalGraphView` that implements `GraphReader` —
    /// use it for BFS, blast radius, or any graph query on historical state.
    pub fn graph_at(
        &self,
        at: chrono::DateTime<chrono::Utc>,
    ) -> crate::temporal::TemporalGraphView {
        self.temporal.graph_at(at)
    }

    // === Diagnostics ===

    /// Counterfactual analysis: "what would the graph look like if this event
    /// (and everything it caused) hadn't happened?"
    /// Returns the diff between actual and counterfactual state.
    pub fn counterfactual(&self, event_id: &EventId) -> hydra_core::error::Result<crate::counterfactual::GraphDiff> {
        let cf_result = crate::counterfactual::counterfactual(&self.event_log, event_id)?;
        Ok(crate::counterfactual::diff_projections(&self.projection, &cf_result.projection))
    }

    /// Impact score: how much did a specific event change the graph?
    /// Combines causal subtree size, node/edge/property impact, and a magnitude score.
    pub fn impact_score(&self, event_id: &EventId) -> hydra_core::error::Result<crate::counterfactual::ImpactScore> {
        crate::counterfactual::impact_score(&self.event_log, &self.projection, event_id)
    }

    /// Total events stored
    pub fn total_events(&self) -> usize {
        self.event_log.len()
    }

    /// Node count in the graph
    pub fn node_count(&self) -> usize {
        self.projection.node_count()
    }

    /// Edge count in the graph
    pub fn edge_count(&self) -> usize {
        self.projection.edge_count()
    }

    /// Number of registered subscriptions
    pub fn subscription_count(&self) -> usize {
        self.registry.count()
    }

    // === Coverage ===

    /// Mutable access to the coverage engine for adding models
    pub fn coverage_engine_mut(&mut self) -> &mut CoverageEngine {
        &mut self.coverage_engine
    }

    /// Evaluate all coverage models against the current graph state.
    pub fn evaluate_coverage(&self) -> Vec<CoverageReport> {
        self.coverage_engine.evaluate_all(&self.projection)
    }

    // === Epistemic store ===

    /// Read access to the epistemic store (claims + evidence).
    pub fn epistemic_store(&self) -> &EpistemicStore {
        &self.epistemic_store
    }

    pub fn evidence(&self, id: &EvidenceId) -> Option<&Evidence> {
        self.epistemic_store.evidence(id)
    }

    pub fn claim(&self, id: &ClaimId) -> Option<&Claim> {
        self.epistemic_store.claim(id)
    }

    pub fn claims_for_subject(&self, subject: &ClaimSubject) -> Vec<&Claim> {
        self.epistemic_store.claims_for_subject(subject)
    }

    pub fn claims_with_status(&self, status: ClaimStatus) -> Vec<&Claim> {
        self.epistemic_store.claims_with_status(status)
    }

    pub fn claims_with_kind(&self, kind: ClaimKind) -> Vec<&Claim> {
        self.epistemic_store.claims_with_kind(kind)
    }

    pub fn verified_claims(&self) -> Vec<&Claim> {
        self.epistemic_store.verified_claims()
    }

    pub fn operational_claims(&self) -> Vec<&Claim> {
        self.epistemic_store.operational_claims()
    }

    pub fn disputed_claims(&self) -> Vec<&Claim> {
        self.epistemic_store.disputed_claims()
    }

    // === Verification (trust evaluation) ===

    /// Read access to the verification engine (policy + evaluator).
    pub fn verification_engine(&self) -> &VerificationEngine {
        &self.verification_engine
    }

    /// Replace the verification policy.
    pub fn set_verification_policy(&mut self, policy: VerificationPolicy) {
        self.verification_engine = VerificationEngine::new(policy);
    }

    /// Run the verification engine against a claim in the epistemic store.
    /// Returns a deterministic report — does not mutate state.
    pub fn evaluate_claim(&self, claim_id: &ClaimId) -> VerificationReport {
        self.verification_engine
            .evaluate_claim_by_id(&self.epistemic_store, claim_id)
    }

    /// Read access to the built-in verification agent that the cascade engine
    /// invokes on `ClaimProposed`.
    pub fn verification_agent(&self) -> &VerificationAgent {
        &self.verification_agent
    }

    /// Read access to the built-in remediation agent (PROMETHEUS reflex) that
    /// the cascade engine invokes on `ClaimVerified`.
    pub fn remediation_agent(&self) -> &RemediationAgent {
        &self.remediation_agent
    }

    /// Read access to the built-in outcome agent (SENTINEL reflex) that the
    /// cascade engine invokes on `ActionExecuted`.
    pub fn outcome_agent(&self) -> &OutcomeAgent {
        &self.outcome_agent
    }

    // === Programmable reflexes ===

    /// Read access to the generic reflex registry.
    pub fn reflex_registry(&self) -> &ReflexRegistry {
        &self.reflex_registry
    }

    /// Mutable access to the reflex registry.
    pub fn reflex_registry_mut(&mut self) -> &mut ReflexRegistry {
        &mut self.reflex_registry
    }

    /// Convenience: register a user-defined reflex on this Hydra instance.
    pub fn register_reflex<R>(&mut self, reflex: R)
    where
        R: crate::reflex::Reflex + 'static,
    {
        self.reflex_registry.register(reflex);
    }

    // === Action store ===

    /// Read access to the action store (proposed/approved/executed actions + outcomes).
    pub fn action_store(&self) -> &ActionStore {
        &self.action_store
    }

    pub fn action(&self, id: &hydra_core::ActionId) -> Option<&hydra_core::Action> {
        self.action_store.action(id)
    }

    pub fn outcome(&self, id: &hydra_core::OutcomeId) -> Option<&hydra_core::Outcome> {
        self.action_store.outcome(id)
    }

    pub fn actions_with_status(
        &self,
        status: hydra_core::ActionStatus,
    ) -> Vec<&hydra_core::Action> {
        self.action_store.actions_with_status(status)
    }

    pub fn proposed_actions(&self) -> Vec<&hydra_core::Action> {
        self.action_store.proposed_actions()
    }

    pub fn approved_actions(&self) -> Vec<&hydra_core::Action> {
        self.action_store.approved_actions()
    }

    pub fn executing_actions(&self) -> Vec<&hydra_core::Action> {
        self.action_store.executing_actions()
    }

    pub fn executed_actions(&self) -> Vec<&hydra_core::Action> {
        self.action_store.executed_actions()
    }

    pub fn failed_actions(&self) -> Vec<&hydra_core::Action> {
        self.action_store.failed_actions()
    }

    pub fn outcomes_for_action(
        &self,
        action_id: &hydra_core::ActionId,
    ) -> Vec<&hydra_core::Outcome> {
        self.action_store.outcomes_for_action(action_id)
    }

    // === Policy / approval store ===

    /// Read access to the policy store (registered policies, decisions, approvals).
    pub fn policy_store(&self) -> &PolicyStore {
        &self.policy_store
    }

    pub fn policy(&self, id: &hydra_core::PolicyId) -> Option<&hydra_core::Policy> {
        self.policy_store.policy(id)
    }

    pub fn policy_decision(
        &self,
        id: &hydra_core::PolicyDecisionId,
    ) -> Option<&hydra_core::PolicyDecision> {
        self.policy_store.decision(id)
    }

    pub fn approval(
        &self,
        id: &hydra_core::ApprovalId,
    ) -> Option<&hydra_core::ApprovalRequest> {
        self.policy_store.approval(id)
    }

    pub fn active_policies(&self) -> Vec<&hydra_core::Policy> {
        self.policy_store.active_policies()
    }

    pub fn policies_with_kind(
        &self,
        kind: hydra_core::PolicyKind,
    ) -> Vec<&hydra_core::Policy> {
        self.policy_store.policies_with_kind(kind)
    }

    pub fn policies_for_scope(
        &self,
        scope: &hydra_core::PolicyScope,
    ) -> Vec<&hydra_core::Policy> {
        self.policy_store.policies_for_scope(scope)
    }

    pub fn decisions_for_action(
        &self,
        action_id: &hydra_core::ActionId,
    ) -> Vec<&hydra_core::PolicyDecision> {
        self.policy_store.decisions_for_action(action_id)
    }

    pub fn pending_approvals(&self) -> Vec<&hydra_core::ApprovalRequest> {
        self.policy_store.pending_approvals()
    }

    pub fn approvals_for_action(
        &self,
        action_id: &hydra_core::ActionId,
    ) -> Vec<&hydra_core::ApprovalRequest> {
        self.policy_store.approvals_for_action(action_id)
    }

    pub fn approvals_requested_from(
        &self,
        actor_id: &hydra_core::ActorId,
    ) -> Vec<&hydra_core::ApprovalRequest> {
        self.policy_store.approvals_requested_from(actor_id)
    }

    // === Policy evaluation ===

    /// Read access to the policy evaluation engine.
    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    /// Evaluate the policy store against a known proposed action.
    ///
    /// Returns `None` if the action is not in the action store. Otherwise
    /// returns a deterministic `PolicyEvaluationReport` — no state mutated,
    /// no events emitted. The later PolicyAgent translates these reports
    /// into event-sourced transitions.
    pub fn evaluate_action_policy(
        &self,
        action_id: &hydra_core::ActionId,
    ) -> Option<crate::policy_engine::PolicyEvaluationReport> {
        let action = self.action_store.action(action_id)?;
        Some(self.policy_engine.evaluate_action(&self.policy_store, action))
    }

    /// Read access to the built-in policy agent that the cascade engine
    /// invokes on `ActionProposed`.
    pub fn policy_agent(&self) -> &PolicyAgent {
        &self.policy_agent
    }

    // === Sensor checkpoints ===

    /// Read access to the sensor checkpoint store.
    pub fn sensor_checkpoint_store(&self) -> &SensorCheckpointStore {
        &self.sensor_checkpoint_store
    }

    pub fn sensor_run(
        &self,
        id: &hydra_core::SensorRunId,
    ) -> Option<&hydra_core::SensorRun> {
        self.sensor_checkpoint_store.run(id)
    }

    pub fn sensor_checkpoint(
        &self,
        id: &hydra_core::SensorCheckpointId,
    ) -> Option<&hydra_core::SensorCheckpoint> {
        self.sensor_checkpoint_store.checkpoint(id)
    }

    pub fn runs_for_sensor(
        &self,
        sensor_id: &hydra_core::SensorId,
    ) -> Vec<&hydra_core::SensorRun> {
        self.sensor_checkpoint_store.runs_for_sensor(sensor_id)
    }

    pub fn runs_with_status(
        &self,
        status: hydra_core::SensorRunStatus,
    ) -> Vec<&hydra_core::SensorRun> {
        self.sensor_checkpoint_store.runs_with_status(status)
    }

    pub fn checkpoints_for_sensor(
        &self,
        sensor_id: &hydra_core::SensorId,
    ) -> Vec<&hydra_core::SensorCheckpoint> {
        self.sensor_checkpoint_store
            .checkpoints_for_sensor(sensor_id)
    }

    pub fn checkpoints_for_source(
        &self,
        source: &str,
    ) -> Vec<&hydra_core::SensorCheckpoint> {
        self.sensor_checkpoint_store.checkpoints_for_source(source)
    }

    pub fn checkpoint_for_cursor(
        &self,
        cursor: &hydra_core::SourceCursor,
    ) -> Option<&hydra_core::SensorCheckpoint> {
        self.sensor_checkpoint_store.checkpoint_for_cursor(cursor)
    }

    pub fn latest_sensor_checkpoint(
        &self,
        sensor_id: &hydra_core::SensorId,
        source: &str,
    ) -> Option<&hydra_core::SensorCheckpoint> {
        self.sensor_checkpoint_store
            .latest_checkpoint(sensor_id, source)
    }

    pub fn checkpoint_for_idempotency_key(
        &self,
        key: &hydra_core::IdempotencyKey,
    ) -> Option<&hydra_core::SensorCheckpoint> {
        self.sensor_checkpoint_store
            .checkpoint_for_idempotency_key(key)
    }

    pub fn checkpoint_for_commit(
        &self,
        commit_id: &hydra_core::CommitId,
    ) -> Option<&hydra_core::SensorCheckpoint> {
        self.sensor_checkpoint_store
            .checkpoint_for_commit(commit_id)
    }

    // === Commit ledger ===

    /// Read access to the in-memory commit ledger.
    pub fn commit_ledger(&self) -> &CommitLedger {
        &self.commit_ledger
    }

    /// Most recent commit record, if any.
    pub fn latest_commit(&self) -> Option<&hydra_core::CommitRecord> {
        self.commit_ledger.latest_record()
    }

    /// Number of commits recorded in the ledger.
    pub fn commit_count(&self) -> usize {
        self.commit_ledger.commit_count()
    }

    /// Verify the in-memory commit hash chain.
    pub fn verify_commit_chain(&self) -> hydra_core::error::Result<()> {
        self.commit_ledger.verify_chain()
    }

    /// Attach a durable commit writer.
    ///
    /// The writer receives every committed cascade batch after the in-memory
    /// CommitLedger accepts it.
    pub fn set_commit_writer<W>(&mut self, writer: W)
    where
        W: crate::commit_ledger::CommitBatchWriter + 'static,
    {
        self.commit_writer = Some(Box::new(writer));
    }

    /// Remove the durable commit writer.
    ///
    /// Hydra will continue maintaining its in-memory CommitLedger.
    pub fn clear_commit_writer(&mut self) {
        self.commit_writer = None;
    }

    pub fn has_commit_writer(&self) -> bool {
        self.commit_writer.is_some()
    }
}

impl Default for Hydra {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::{EventKind, Value};
    use hydra_core::id::{EdgeId, NodeId};
    use hydra_core::subscription::{EventFilter, Subscription, SubscriptionHandler};
    use std::collections::HashMap;

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

    #[test]
    fn end_to_end_ingest_and_query() {
        let mut hydra = Hydra::new();

        let node_id = NodeId::new();
        hydra
            .ingest(EventKind::NodeCreated {
                node_id: node_id.clone(),
                type_id: "ec2_instance".to_string(),
                properties: HashMap::from([
                    ("instance_id".to_string(), Value::String("i-abc123".to_string())),
                    ("state".to_string(), Value::String("running".to_string())),
                ]),
            })
            .unwrap();

        assert_eq!(hydra.node_count(), 1);
        let node = hydra.graph().node(&node_id).unwrap();
        assert_eq!(node.get_str("instance_id"), Some("i-abc123"));
        assert_eq!(hydra.total_events(), 1);
    }

    #[test]
    fn end_to_end_with_subscriptions() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "classify",
            EventFilter::NodeCreated,
            100,
            Box::new(ClassifyHandler),
        ));

        let node_id = NodeId::new();
        let result = hydra
            .ingest(EventKind::NodeCreated {
                node_id: node_id.clone(),
                type_id: "ec2".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();

        assert_eq!(result.events.len(), 2); // trigger + classify reaction
        assert_eq!(hydra.total_events(), 2);
        assert_eq!(
            hydra.graph().node(&node_id).unwrap().get_bool("classified"),
            Some(true)
        );
    }

    #[test]
    fn causal_queries_work() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "classify",
            EventFilter::NodeCreated,
            100,
            Box::new(ClassifyHandler),
        ));

        let result = hydra
            .ingest(EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: "ec2".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();

        let trigger_id = &result.events[0].id;
        let reaction_id = &result.events[1].id;

        // Forward: what did the trigger cause?
        let chain = hydra.causal_chain(trigger_id);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].id, *reaction_id);

        // Backward: what caused the reaction?
        let root = hydra.root_cause(reaction_id);
        assert_eq!(root.len(), 2); // trigger, reaction
        assert_eq!(root[0].id, *trigger_id);
    }

    #[test]
    fn build_graph_with_edges() {
        let mut hydra = Hydra::new();

        let ec2 = NodeId::new();
        let vpc = NodeId::new();

        hydra
            .ingest(EventKind::NodeCreated {
                node_id: ec2.clone(),
                type_id: "ec2".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();

        hydra
            .ingest(EventKind::NodeCreated {
                node_id: vpc.clone(),
                type_id: "vpc".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();

        hydra
            .ingest(EventKind::EdgeCreated {
                edge_id: EdgeId::new(),
                source: ec2.clone(),
                target: vpc.clone(),
                type_id: "in_vpc".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();

        assert_eq!(hydra.node_count(), 2);
        assert_eq!(hydra.edge_count(), 1);
        assert_eq!(hydra.graph().outgoing_edges(&ec2).len(), 1);
        assert_eq!(hydra.graph().incoming_edges(&vpc).len(), 1);
        assert_eq!(hydra.graph().outgoing_neighbors(&ec2).len(), 1);
        assert_eq!(hydra.graph().outgoing_neighbors(&ec2)[0].type_id(), "vpc");
    }

    #[test]
    fn multiple_cascades_are_independent() {
        let mut hydra = Hydra::new();

        let r1 = hydra
            .ingest(EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: "ec2".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();

        let r2 = hydra
            .ingest(EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: "rds".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();

        // Different cascade IDs
        assert_ne!(r1.events[0].cascade_id, r2.events[0].cascade_id);

        // Cascade query returns only events from that cascade
        assert_eq!(
            hydra.cascade_events(&r1.events[0].cascade_id).len(),
            1
        );
    }

    #[test]
    fn subscription_management() {
        let mut hydra = Hydra::new();

        struct CountHandler;
        impl SubscriptionHandler for CountHandler {
            fn handle(
                &self,
                event: &Event,
                _graph: &dyn hydra_core::graph::GraphReader,
            ) -> Vec<EventKind> {
                if let EventKind::NodeCreated { node_id, .. } = &event.kind {
                    vec![EventKind::NodeUpdated {
                        node_id: node_id.clone(),
                        changes: HashMap::from([("counted".to_string(), Value::Bool(true))]),
                    }]
                } else {
                    vec![]
                }
            }
        }

        let sub_id = hydra.register(Subscription::new(
            "counter",
            EventFilter::NodeCreated,
            100,
            Box::new(CountHandler),
        ));

        // With subscription enabled: 2 events (trigger + reaction)
        let r1 = hydra
            .ingest(EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: "ec2".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();
        assert_eq!(r1.events.len(), 2);

        // Disable subscription
        hydra.set_enabled(&sub_id, false);

        // With subscription disabled: 1 event (trigger only)
        let r2 = hydra
            .ingest(EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: "ec2".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();
        assert_eq!(r2.events.len(), 1);

        // Re-enable
        hydra.set_enabled(&sub_id, true);
        let r3 = hydra
            .ingest(EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: "ec2".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();
        assert_eq!(r3.events.len(), 2);
    }

    #[test]
    fn resource_limits_block_ingestion() {
        let mut hydra = Hydra::new();
        hydra.set_limits(ResourceLimits {
            max_nodes: 2,
            max_edges: usize::MAX,
            max_events: usize::MAX,
        });

        // First two nodes succeed
        hydra.ingest(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "ec2".to_string(),
            properties: HashMap::new(),
        }).unwrap();
        hydra.ingest(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "rds".to_string(),
            properties: HashMap::new(),
        }).unwrap();

        // Third node is rejected
        let result = hydra.ingest(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "s3".to_string(),
            properties: HashMap::new(),
        });
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("nodes"));
        assert!(err.to_string().contains("2"));
    }

    #[test]
    fn event_limits_block_ingestion() {
        let mut hydra = Hydra::new();
        hydra.set_limits(ResourceLimits {
            max_nodes: usize::MAX,
            max_edges: usize::MAX,
            max_events: 3,
        });

        hydra.ingest(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "a".to_string(),
            properties: HashMap::new(),
        }).unwrap();
        hydra.ingest(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "b".to_string(),
            properties: HashMap::new(),
        }).unwrap();
        hydra.ingest(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "c".to_string(),
            properties: HashMap::new(),
        }).unwrap();

        // Fourth ingest blocked by event limit
        let result = hydra.ingest(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "d".to_string(),
            properties: HashMap::new(),
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("events"));
    }
}

#[cfg(test)]
mod sprint1_tests {
    use super::*;
    use hydra_core::event::{EventKind, Value};
    use hydra_core::id::{NodeId, TenantId};
    use hydra_core::subscription::{EventFilter, Subscription, SubscriptionHandler};
    use std::collections::HashMap;

    struct CountingHandler { tag: String }
    impl SubscriptionHandler for CountingHandler {
        fn handle(&self, event: &Event, _graph: &dyn GraphReader) -> Vec<EventKind> {
            if let EventKind::NodeCreated { node_id, .. } = &event.kind {
                vec![EventKind::NodeUpdated {
                    node_id: node_id.clone(),
                    changes: HashMap::from([
                        (self.tag.clone(), Value::Bool(true)),
                    ]),
                }]
            } else {
                vec![]
            }
        }
    }

    // === I1: Tenant Isolation ===

    #[test]
    fn tenant_scoped_subscription_only_fires_for_its_tenant() {
        let mut hydra = Hydra::new();

        let tenant_a = TenantId::from_str("ten_acme");
        let tenant_b = TenantId::from_str("ten_globex");

        // Register a subscription for tenant A only
        hydra.register(Subscription::for_tenant(
            "acme_classifier",
            EventFilter::NodeCreated,
            100,
            Box::new(CountingHandler { tag: "acme_classified".into() }),
            tenant_a.clone(),
        ));

        // Register a subscription for tenant B only
        hydra.register(Subscription::for_tenant(
            "globex_classifier",
            EventFilter::NodeCreated,
            100,
            Box::new(CountingHandler { tag: "globex_classified".into() }),
            tenant_b.clone(),
        ));

        // Ingest for tenant A
        let node_a = NodeId::from_str("node_a");
        hydra.ingest_for_tenant(EventKind::NodeCreated {
            node_id: node_a.clone(),
            type_id: "compute_instance".to_string(),
            properties: HashMap::new(),
        }, tenant_a.clone()).unwrap();

        // Verify: only acme_classifier fired
        let node = hydra.graph().node(&node_a).unwrap();
        assert_eq!(node.get_bool("acme_classified"), Some(true),
            "Tenant A's subscription should fire");
        assert_eq!(node.get_bool("globex_classified"), None,
            "Tenant B's subscription should NOT fire for tenant A's event");
    }

    #[test]
    fn global_subscription_fires_for_all_tenants() {
        let mut hydra = Hydra::new();

        let tenant_a = TenantId::from_str("ten_acme");

        // Register a GLOBAL subscription (no tenant)
        hydra.register(Subscription::new(
            "global_classifier",
            EventFilter::NodeCreated,
            100,
            Box::new(CountingHandler { tag: "globally_classified".into() }),
        ));

        // Register a tenant-scoped subscription
        hydra.register(Subscription::for_tenant(
            "acme_only",
            EventFilter::NodeCreated,
            90,
            Box::new(CountingHandler { tag: "acme_only".into() }),
            tenant_a.clone(),
        ));

        // Ingest for tenant A
        let node_a = NodeId::from_str("node_a");
        hydra.ingest_for_tenant(EventKind::NodeCreated {
            node_id: node_a.clone(),
            type_id: "compute_instance".to_string(),
            properties: HashMap::new(),
        }, tenant_a).unwrap();

        let node = hydra.graph().node(&node_a).unwrap();
        assert_eq!(node.get_bool("globally_classified"), Some(true),
            "Global subscription should fire for any tenant");
        assert_eq!(node.get_bool("acme_only"), Some(true),
            "Tenant-scoped subscription should fire for matching tenant");
    }

    #[test]
    fn non_tenant_ingest_skips_tenant_scoped_subs() {
        let mut hydra = Hydra::new();

        let tenant_a = TenantId::from_str("ten_acme");

        hydra.register(Subscription::for_tenant(
            "acme_only",
            EventFilter::NodeCreated,
            100,
            Box::new(CountingHandler { tag: "acme_only".into() }),
            tenant_a,
        ));

        // Ingest WITHOUT tenant (legacy path)
        let node_id = NodeId::from_str("node_legacy");
        hydra.ingest(EventKind::NodeCreated {
            node_id: node_id.clone(),
            type_id: "compute_instance".to_string(),
            properties: HashMap::new(),
        }).unwrap();

        let node = hydra.graph().node(&node_id).unwrap();
        assert_eq!(node.get_bool("acme_only"), None,
            "Tenant-scoped sub should NOT fire for non-tenant event");
    }

    // === I4: Truncation Alarm ===

    #[test]
    fn truncated_cascade_emits_alarm_signal() {
        // Use very small cascade limit
        let mut hydra = Hydra::with_config(CascadeConfig {
            max_depth: 3,
            max_events: 4,
        });

        // Handler that spawns more NodeCreated → infinite growth if unchecked
        struct SpawnHandler;
        impl SubscriptionHandler for SpawnHandler {
            fn handle(&self, event: &Event, _graph: &dyn GraphReader) -> Vec<EventKind> {
                if let EventKind::NodeCreated { .. } = &event.kind {
                    vec![
                        EventKind::NodeCreated {
                            node_id: NodeId::new(),
                            type_id: "spawned".to_string(),
                            properties: HashMap::new(),
                        },
                    ]
                } else {
                    vec![]
                }
            }
        }

        hydra.register(Subscription::new(
            "spawner",
            EventFilter::NodeCreated,
            100,
            Box::new(SpawnHandler),
        ));

        // This should truncate (each NodeCreated spawns another → exponential)
        let result = hydra.ingest(EventKind::NodeCreated {
            node_id: NodeId::from_str("node_test"),
            type_id: "compute_instance".to_string(),
            properties: HashMap::new(),
        }).unwrap();

        assert!(result.truncated, "Cascade should be truncated");

        // The event log should contain a cascade_truncated signal
        let has_alarm = hydra.event_log().iter().any(|e| {
            matches!(&e.kind, EventKind::Signal { name, .. } if name == "cascade_truncated")
        });
        assert!(has_alarm, "Should emit cascade_truncated alarm signal");
    }

    // === I2: Windowed Event Log ===

    #[test]
    fn event_log_auto_compacts_during_ingest() {
        let mut hydra = Hydra::new();

        // Set a small event log limit
        hydra.event_log_mut().set_config(crate::event_log::EventLogConfig {
            max_events: 20,
            compact_fraction: 0.5,
        });

        // Ingest many events
        for i in 0..30 {
            hydra.ingest(EventKind::NodeCreated {
                node_id: NodeId::from_str(&format!("node_{}", i)),
                type_id: "compute_instance".to_string(),
                properties: HashMap::new(),
            }).unwrap();
        }

        // Event log should have been auto-compacted
        assert!(hydra.event_log().len() <= 25,
            "Event log should auto-compact, got {} events", hydra.event_log().len());
        assert!(hydra.event_log().total_appended() >= 30,
            "Total appended should track all events");
    }

    // === I8: WAL + Checkpoint + Recovery ===

    use std::sync::{Arc, Mutex};

    /// In-memory WAL for testing
    struct MemoryWal {
        events: Arc<Mutex<Vec<Event>>>,
        checkpoints: Arc<Mutex<Vec<EventId>>>,
    }
    impl MemoryWal {
        fn new() -> (Self, Arc<Mutex<Vec<Event>>>, Arc<Mutex<Vec<EventId>>>) {
            let events = Arc::new(Mutex::new(Vec::new()));
            let checkpoints = Arc::new(Mutex::new(Vec::new()));
            (Self {
                events: events.clone(),
                checkpoints: checkpoints.clone(),
            }, events, checkpoints)
        }
    }
    impl WalWriter for MemoryWal {
        fn persist_cascade(&mut self, events: &[Event]) -> hydra_core::error::Result<()> {
            self.events.lock().unwrap().extend(events.iter().cloned());
            Ok(())
        }
        fn persist_checkpoint(&mut self, id: &EventId) -> hydra_core::error::Result<()> {
            self.checkpoints.lock().unwrap().push(id.clone());
            Ok(())
        }
    }

    #[test]
    fn wal_receives_all_cascade_events() {
        let (wal, wal_events, _) = MemoryWal::new();
        let mut hydra = Hydra::new();
        hydra.set_wal(Box::new(wal));

        hydra.ingest(EventKind::NodeCreated {
            node_id: NodeId::from_str("node_wal_test"),
            type_id: "compute_instance".to_string(),
            properties: HashMap::new(),
        }).unwrap();

        let persisted = wal_events.lock().unwrap();
        assert_eq!(persisted.len(), 1, "WAL should have 1 event");
        assert!(matches!(&persisted[0].kind, EventKind::NodeCreated { .. }));
    }

    #[test]
    fn checkpoint_records_last_event_id() {
        let (wal, _, wal_checkpoints) = MemoryWal::new();
        let mut hydra = Hydra::new();
        hydra.set_wal(Box::new(wal));

        hydra.ingest(EventKind::NodeCreated {
            node_id: NodeId::from_str("node_1"),
            type_id: "compute_instance".to_string(),
            properties: HashMap::new(),
        }).unwrap();

        let checkpoint_id = hydra.checkpoint().unwrap();
        assert!(checkpoint_id.is_some());

        let checkpoints = wal_checkpoints.lock().unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0], checkpoint_id.unwrap());
    }

    #[test]
    fn recover_from_events_rebuilds_state() {
        let mut original = Hydra::new();
        original.ingest(EventKind::NodeCreated {
            node_id: NodeId::from_str("db_prod"),
            type_id: "managed_database".to_string(),
            properties: HashMap::from([
                ("name".to_string(), Value::String("Production DB".into())),
            ]),
        }).unwrap();
        original.ingest(EventKind::NodeCreated {
            node_id: NodeId::from_str("api_server"),
            type_id: "compute_instance".to_string(),
            properties: HashMap::new(),
        }).unwrap();

        let events: Vec<Event> = original.event_log().iter().cloned().collect();

        let mut recovered = Hydra::new();
        let count = recovered.recover_from_events(events).unwrap();
        assert_eq!(count, 2);
        assert_eq!(recovered.node_count(), 2);

        let db = recovered.graph().node(&NodeId::from_str("db_prod"));
        assert!(db.is_some());
        assert_eq!(db.unwrap().get_str("name"), Some("Production DB"));
    }

    #[test]
    fn wal_not_required_for_basic_operation() {
        let mut hydra = Hydra::new();
        assert!(hydra.checkpoint().unwrap().is_none());

        hydra.ingest(EventKind::NodeCreated {
            node_id: NodeId::from_str("node_nowal"),
            type_id: "compute_instance".to_string(),
            properties: HashMap::new(),
        }).unwrap();

        assert_eq!(hydra.node_count(), 1);
        assert!(hydra.checkpoint().unwrap().is_some());
    }

    #[test]
    fn hydra_verifies_stale_dataset_claim_and_proposes_backfill_action() {
        use hydra_core::{
            Claim, ClaimId, ClaimKind, ClaimObject, ClaimStatus, ClaimSubject, Confidence,
            EventKind, Evidence, EvidenceId, EvidencePayload, EvidenceSource, TenantId, Value,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let tenant = TenantId::from_str("tenant_hydra_prometheus_test");
        let now = chrono::Utc::now();

        let mut data = HashMap::new();
        data.insert(
            "dataset".to_string(),
            Value::String("analytics.public.revenue_daily".to_string()),
        );
        data.insert("freshness_lag_hours".to_string(), Value::Float(7.0));

        let evidence = Evidence {
            id: EvidenceId::new(),
            tenant_id: Some(tenant.clone()),
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
            observed_at: now,
            recorded_at: now,
            caused_by: None,
        };

        let claim = Claim {
            id: ClaimId::new(),
            tenant_id: Some(tenant),
            kind: ClaimKind::AnomalyFinding,
            subject: ClaimSubject::Dataset("analytics.public.revenue_daily".to_string()),
            predicate: "is_stale".to_string(),
            object: ClaimObject::Value(Value::Bool(true)),
            confidence: Confidence::new(0.91),
            status: ClaimStatus::Proposed,
            evidence_for: vec![evidence.id.clone()],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: hydra_core::ActorId::from_str("actor_argus"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        let claim_id = claim.id.clone();

        hydra
            .ingest(EventKind::EvidenceAdded { evidence })
            .unwrap();
        let result = hydra.ingest(EventKind::ClaimProposed { claim }).unwrap();

        // ClaimProposed → ClaimVerified → ActionProposed → PolicyDecisionRecorded
        // → ActionApproved. PolicyAgent auto-approves because no policy matches.
        assert_eq!(result.events.len(), 5);
        assert!(matches!(
            result.events[0].kind,
            EventKind::ClaimProposed { .. }
        ));
        assert!(matches!(
            result.events[1].kind,
            EventKind::ClaimVerified { .. }
        ));
        assert!(matches!(
            result.events[2].kind,
            EventKind::ActionProposed { .. }
        ));
        assert!(matches!(
            result.events[3].kind,
            EventKind::PolicyDecisionRecorded { .. }
        ));
        assert!(matches!(
            result.events[4].kind,
            EventKind::ActionApproved { .. }
        ));

        assert_eq!(hydra.verified_claims().len(), 1);
        // Action auto-approved by PolicyAgent, so it sits in Approved (not Proposed).
        assert_eq!(hydra.proposed_actions().len(), 0);
        assert_eq!(hydra.approved_actions().len(), 1);

        let action = hydra.approved_actions()[0];
        assert_eq!(action.kind, hydra_core::ActionKind::Backfill);
        assert_eq!(action.related_claims, vec![claim_id]);
        assert_eq!(
            action.targets,
            vec![hydra_core::ActionTarget::Dataset(
                "analytics.public.revenue_daily".to_string()
            )]
        );
    }

    #[test]
    fn hydra_materializes_action_and_outcome_state() {
        use hydra_core::{
            Action, ActionId, ActionKind, ActionStatus, ActionTarget, ActorId, EventKind, Outcome,
            OutcomeId, OutcomeKind, Value,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = ActorId::from_str("actor_prometheus");

        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::Backfill,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::Dataset(
                "analytics.public.revenue_daily".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };
        let action_id = action.id.clone();

        hydra
            .ingest(EventKind::ActionProposed { action })
            .unwrap();
        // PolicyAgent auto-approves when no policy matches, so the action is
        // already in Approved status after a single ingest.
        assert_eq!(hydra.proposed_actions().len(), 0);
        assert_eq!(hydra.approved_actions().len(), 1);

        // The explicit ActionApproved below is now idempotent — status stays
        // Approved.
        hydra
            .ingest(EventKind::ActionApproved {
                action_id: action_id.clone(),
                approved_by: actor.clone(),
            })
            .unwrap();
        assert_eq!(hydra.approved_actions().len(), 1);

        hydra
            .ingest(EventKind::ActionExecuted {
                action_id: action_id.clone(),
            })
            .unwrap();
        assert_eq!(hydra.executed_actions().len(), 1);

        let mut impact = HashMap::new();
        impact.insert("freshness_restored".to_string(), Value::Bool(true));
        let outcome = Outcome {
            id: OutcomeId::new(),
            tenant_id: None,
            action_id: action_id.clone(),
            kind: OutcomeKind::Success,
            observed_events: vec![],
            updated_claims: vec![],
            produced_evidence: vec![],
            impact,
            observed_at: now,
            recorded_at: now,
            recorded_by: actor,
            caused_by: None,
        };
        hydra
            .ingest(EventKind::OutcomeObserved {
                outcome: outcome.clone(),
            })
            .unwrap();
        // The cascade's OutcomeAgent already emitted an Unknown outcome when
        // ActionExecuted was ingested, so the explicit Success outcome makes
        // it the second one for this action.
        let outcomes = hydra.outcomes_for_action(&action_id);
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().any(|o| o.id == outcome.id));
    }

    #[test]
    fn hydra_runs_user_registered_reflex() {
        use crate::reflex::{Reflex, ReflexContext};
        use hydra_core::{
            ActorId, Claim, ClaimId, ClaimKind, ClaimObject, ClaimStatus, ClaimSubject,
            Confidence, Event, EventKind, Value,
        };

        struct StaleOnVerifiedReflex;
        impl Reflex for StaleOnVerifiedReflex {
            fn name(&self) -> &'static str {
                "stale_on_verified"
            }
            fn react(&self, event: &Event, _ctx: &ReflexContext<'_>) -> Vec<EventKind> {
                match &event.kind {
                    EventKind::ClaimVerified { claim_id, .. } => {
                        vec![EventKind::ClaimStaled {
                            claim_id: claim_id.clone(),
                            reason: Some("user reflex test".to_string()),
                        }]
                    }
                    _ => Vec::new(),
                }
            }
        }

        let mut hydra = Hydra::new();
        hydra.register_reflex(StaleOnVerifiedReflex);

        // Pre-stage a claim so EpistemicStore can apply ClaimVerified / ClaimStaled.
        // Kind is Fact (not AnomalyFinding) so the remediation agent doesn't fire.
        // Confidence + zero evidence means the verification agent decides
        // KeepProposed (no auto-Verify), keeping the cascade clean.
        let now = chrono::Utc::now();
        let claim = Claim {
            id: ClaimId::new(),
            tenant_id: None,
            kind: ClaimKind::Fact,
            subject: ClaimSubject::System("test".to_string()),
            predicate: "exists".to_string(),
            object: ClaimObject::Value(Value::Bool(true)),
            confidence: Confidence::new(0.99),
            status: ClaimStatus::Proposed,
            evidence_for: vec![],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: ActorId::from_str("actor_test"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        let claim_id = claim.id.clone();
        hydra.ingest(EventKind::ClaimProposed { claim }).unwrap();

        let result = hydra
            .ingest(EventKind::ClaimVerified {
                claim_id: claim_id.clone(),
                verified_by: ActorId::from_str("actor_test"),
            })
            .unwrap();

        assert_eq!(result.events.len(), 2);
        assert!(matches!(result.events[0].kind, EventKind::ClaimVerified { .. }));
        match &result.events[1].kind {
            EventKind::ClaimStaled {
                claim_id: staled_claim_id,
                reason,
            } => {
                assert_eq!(staled_claim_id, &claim_id);
                assert_eq!(reason.as_deref(), Some("user reflex test"));
            }
            other => panic!("expected ClaimStaled, got {other:?}"),
        }
        assert_eq!(result.events[1].caused_by, vec![result.events[0].id.clone()]);
        assert_eq!(result.events[1].cascade_id, result.events[0].cascade_id);
    }

    #[derive(Debug, Default)]
    struct TestCommitWriter {
        commits: std::sync::Arc<std::sync::Mutex<Vec<hydra_core::CommitBatch>>>,
    }

    impl TestCommitWriter {
        fn new() -> Self {
            Self::default()
        }

        fn commits(&self) -> std::sync::Arc<std::sync::Mutex<Vec<hydra_core::CommitBatch>>> {
            self.commits.clone()
        }
    }

    impl crate::commit_ledger::CommitBatchWriter for TestCommitWriter {
        fn append_commit(
            &self,
            batch: &hydra_core::CommitBatch,
        ) -> hydra_core::error::Result<()> {
            self.commits.lock().unwrap().push(batch.clone());
            Ok(())
        }
    }

    #[test]
    fn hydra_writes_commit_to_attached_writer() {
        use hydra_core::EventKind;
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let writer = TestCommitWriter::new();
        let commits = writer.commits();
        assert!(!hydra.has_commit_writer());
        hydra.set_commit_writer(writer);
        assert!(hydra.has_commit_writer());

        let result = hydra
            .ingest(EventKind::Signal {
                source: hydra_core::NodeId::from_str("test"),
                name: "commit_writer_test".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();

        assert_eq!(hydra.commit_count(), 1);
        let written = commits.lock().unwrap();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].sequence, 1);
        assert_eq!(written[0].event_count(), result.events.len());
        assert_eq!(
            written[0].commit_hash,
            Some(hydra.latest_commit().unwrap().commit_hash.clone())
        );
        hydra.verify_commit_chain().unwrap();
    }

    #[test]
    fn hydra_can_clear_commit_writer() {
        let mut hydra = Hydra::new();
        let writer = TestCommitWriter::new();
        hydra.set_commit_writer(writer);
        assert!(hydra.has_commit_writer());
        hydra.clear_commit_writer();
        assert!(!hydra.has_commit_writer());
    }

    #[test]
    fn ingest_with_idempotency_key_short_circuits_duplicate_without_new_commit() {
        use hydra_core::{EventKind, IdempotencyKey};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let key = IdempotencyKey::new("request-123");
        let first = hydra
            .ingest_with_idempotency_key(
                EventKind::Signal {
                    source: hydra_core::NodeId::from_str("test"),
                    name: "first".to_string(),
                    payload: HashMap::new(),
                },
                key.clone(),
            )
            .unwrap();
        assert_eq!(hydra.commit_count(), 1);
        assert_eq!(hydra.total_events(), first.events.len());
        let total_events_after_first = hydra.total_events();

        let second = hydra
            .ingest_with_idempotency_key(
                EventKind::Signal {
                    source: hydra_core::NodeId::from_str("test"),
                    name: "duplicate_should_not_run".to_string(),
                    payload: HashMap::new(),
                },
                key.clone(),
            )
            .unwrap();

        assert_eq!(hydra.commit_count(), 1);
        assert_eq!(hydra.total_events(), total_events_after_first);
        assert_eq!(second.events.len(), first.events.len());
        assert_eq!(second.events[0].id, first.events[0].id);
        match &second.events[0].kind {
            EventKind::Signal { name, .. } => {
                assert_eq!(name, "first");
            }
            other => panic!("expected original Signal event, got {other:?}"),
        }
        hydra.verify_commit_chain().unwrap();
    }

    #[test]
    fn different_idempotency_keys_create_distinct_commits() {
        use hydra_core::{EventKind, IdempotencyKey};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        hydra
            .ingest_with_idempotency_key(
                EventKind::Signal {
                    source: hydra_core::NodeId::from_str("test"),
                    name: "first".to_string(),
                    payload: HashMap::new(),
                },
                IdempotencyKey::new("request-1"),
            )
            .unwrap();
        hydra
            .ingest_with_idempotency_key(
                EventKind::Signal {
                    source: hydra_core::NodeId::from_str("test"),
                    name: "second".to_string(),
                    payload: HashMap::new(),
                },
                IdempotencyKey::new("request-2"),
            )
            .unwrap();

        assert_eq!(hydra.commit_count(), 2);
        assert_eq!(hydra.total_events(), 2);
        let latest = hydra.latest_commit().unwrap();
        assert_eq!(latest.sequence, 2);
        hydra.verify_commit_chain().unwrap();
    }

    #[test]
    fn duplicate_idempotency_key_does_not_append_to_writer_twice() {
        use hydra_core::{EventKind, IdempotencyKey};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let writer = TestCommitWriter::new();
        let commits = writer.commits();
        hydra.set_commit_writer(writer);

        let key = IdempotencyKey::new("request-writer");
        hydra
            .ingest_with_idempotency_key(
                EventKind::Signal {
                    source: hydra_core::NodeId::from_str("test"),
                    name: "first".to_string(),
                    payload: HashMap::new(),
                },
                key.clone(),
            )
            .unwrap();
        hydra
            .ingest_with_idempotency_key(
                EventKind::Signal {
                    source: hydra_core::NodeId::from_str("test"),
                    name: "duplicate".to_string(),
                    payload: HashMap::new(),
                },
                key,
            )
            .unwrap();

        assert_eq!(hydra.commit_count(), 1);
        assert_eq!(commits.lock().unwrap().len(), 1);
    }

    #[test]
    fn hydra_materializes_sensor_runs_and_checkpoints() {
        use hydra_core::{
            CommitId, EventKind, IdempotencyKey, SensorCheckpoint, SensorCheckpointId,
            SensorCheckpointStatus, SensorId, SensorRun, SensorRunId, SensorRunStatus,
            SourceCursor,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let sensor_id = SensorId::from_str("sensor_bank_feed");

        let run = SensorRun {
            id: SensorRunId::new(),
            tenant_id: None,
            sensor_id: sensor_id.clone(),
            status: SensorRunStatus::Started,
            source_system: "bank".to_string(),
            stream: Some("transactions".to_string()),
            started_at: now,
            completed_at: None,
            failed_at: None,
            error: None,
            actor_id: None,
            metadata: HashMap::new(),
        };
        let run_id = run.id.clone();
        hydra.ingest(EventKind::SensorRunStarted { run }).unwrap();
        assert_eq!(hydra.runs_for_sensor(&sensor_id).len(), 1);
        assert_eq!(
            hydra.sensor_run(&run_id).unwrap().status,
            SensorRunStatus::Started
        );

        let cursor = SourceCursor::Offset {
            stream: "bank.transactions".to_string(),
            partition: Some("acct-9001".to_string()),
            offset: "42".to_string(),
        };
        let key = IdempotencyKey::new(cursor.stable_key_material());
        let commit_id = CommitId::new();
        let checkpoint = SensorCheckpoint {
            id: SensorCheckpointId::new(),
            tenant_id: None,
            sensor_id: sensor_id.clone(),
            run_id: Some(run_id.clone()),
            status: SensorCheckpointStatus::Recorded,
            source_system: "bank".to_string(),
            cursor: cursor.clone(),
            idempotency_key: key.clone(),
            commit_id: commit_id.clone(),
            event_id: None,
            observed_at: now,
            recorded_at: now,
            metadata: HashMap::new(),
        };
        let checkpoint_id = checkpoint.id.clone();
        hydra
            .ingest(EventKind::SensorCheckpointRecorded { checkpoint })
            .unwrap();

        assert_eq!(hydra.checkpoints_for_sensor(&sensor_id).len(), 1);
        assert_eq!(hydra.checkpoints_for_source("bank.transactions").len(), 1);
        assert_eq!(
            hydra.checkpoint_for_cursor(&cursor).unwrap().id,
            checkpoint_id
        );
        assert_eq!(
            hydra.checkpoint_for_idempotency_key(&key).unwrap().id,
            checkpoint_id
        );
        assert_eq!(
            hydra.checkpoint_for_commit(&commit_id).unwrap().id,
            checkpoint_id
        );
        assert_eq!(
            hydra
                .latest_sensor_checkpoint(&sensor_id, "bank.transactions")
                .unwrap()
                .id,
            checkpoint_id
        );

        hydra
            .ingest(EventKind::SensorRunCompleted {
                run_id: run_id.clone(),
            })
            .unwrap();
        assert_eq!(
            hydra.sensor_run(&run_id).unwrap().status,
            SensorRunStatus::Completed
        );
    }

    #[test]
    fn hydra_recovers_sensor_checkpoint_state_from_commits() {
        use hydra_core::{
            CommitId, EventKind, IdempotencyKey, SensorCheckpoint, SensorCheckpointId,
            SensorCheckpointStatus, SensorId, SourceCursor,
        };
        use std::collections::HashMap;

        let mut original = Hydra::new();
        let now = chrono::Utc::now();
        let sensor_id = SensorId::from_str("sensor_bank_feed");
        let cursor = SourceCursor::DeliveryId {
            source: "stripe".to_string(),
            delivery_id: "evt_123".to_string(),
        };
        let key = IdempotencyKey::new(cursor.stable_key_material());
        let commit_id = CommitId::new();
        let checkpoint = SensorCheckpoint {
            id: SensorCheckpointId::new(),
            tenant_id: None,
            sensor_id: sensor_id.clone(),
            run_id: None,
            status: SensorCheckpointStatus::Recorded,
            source_system: "stripe".to_string(),
            cursor: cursor.clone(),
            idempotency_key: key.clone(),
            commit_id: commit_id.clone(),
            event_id: None,
            observed_at: now,
            recorded_at: now,
            metadata: HashMap::new(),
        };
        let checkpoint_id = checkpoint.id.clone();
        original
            .ingest(EventKind::SensorCheckpointRecorded { checkpoint })
            .unwrap();

        let batches: Vec<hydra_core::CommitBatch> = original
            .commit_ledger()
            .batches_in_sequence()
            .into_iter()
            .cloned()
            .collect();

        let mut recovered = Hydra::new();
        recovered.recover_from_commits(batches).unwrap();

        assert_eq!(
            recovered.checkpoint_for_cursor(&cursor).unwrap().id,
            checkpoint_id
        );
        assert_eq!(
            recovered.checkpoint_for_idempotency_key(&key).unwrap().id,
            checkpoint_id
        );
        assert_eq!(
            recovered.checkpoint_for_commit(&commit_id).unwrap().id,
            checkpoint_id
        );
        recovered.verify_commit_chain().unwrap();
    }

    #[test]
    fn hydra_recovers_state_from_commit_batches() {
        use hydra_core::{
            Action, ActionId, ActionKind, ActionStatus, ActionTarget, ActorId, EventKind,
        };
        use std::collections::HashMap;

        let mut original = Hydra::new();
        let now = chrono::Utc::now();
        let actor = ActorId::from_str("actor_recovery_test");
        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::Backfill,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::Dataset(
                "analytics.public.revenue_daily".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor,
            approved_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };
        let action_id = action.id.clone();
        original
            .ingest(EventKind::ActionProposed { action })
            .unwrap();
        // PolicyAgent auto-approves when no policy matches.
        assert_eq!(
            original.action(&action_id).unwrap().status,
            ActionStatus::Approved
        );

        let batches: Vec<hydra_core::CommitBatch> = original
            .commit_ledger()
            .batches_in_sequence()
            .into_iter()
            .cloned()
            .collect();

        let mut recovered = Hydra::new();
        recovered.recover_from_commits(batches).unwrap();

        assert_eq!(recovered.commit_count(), original.commit_count());
        assert_eq!(
            recovered.latest_commit().unwrap().commit_hash,
            original.latest_commit().unwrap().commit_hash
        );
        assert_eq!(
            recovered.action(&action_id).unwrap().status,
            ActionStatus::Approved
        );
        assert_eq!(
            recovered.decisions_for_action(&action_id).len(),
            original.decisions_for_action(&action_id).len()
        );
        recovered.verify_commit_chain().unwrap();
    }

    #[test]
    fn hydra_recovery_from_commits_does_not_append_to_writer() {
        use hydra_core::EventKind;
        use std::collections::HashMap;

        let mut original = Hydra::new();
        original
            .ingest(EventKind::Signal {
                source: hydra_core::NodeId::from_str("test"),
                name: "recovery_writer_test".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();

        let batches: Vec<hydra_core::CommitBatch> = original
            .commit_ledger()
            .batches_in_sequence()
            .into_iter()
            .cloned()
            .collect();

        let writer = TestCommitWriter::new();
        let commits = writer.commits();
        let mut recovered = Hydra::new();
        recovered.set_commit_writer(writer);
        recovered.recover_from_commits(batches).unwrap();

        assert_eq!(recovered.commit_count(), 1);
        assert_eq!(commits.lock().unwrap().len(), 0);
    }

    #[test]
    fn hydra_rejects_invalid_commit_chain_during_recovery() {
        use hydra_core::EventKind;
        use std::collections::HashMap;

        let mut original = Hydra::new();
        original
            .ingest(EventKind::Signal {
                source: hydra_core::NodeId::from_str("test"),
                name: "first".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();
        original
            .ingest(EventKind::Signal {
                source: hydra_core::NodeId::from_str("test"),
                name: "second".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();

        let mut batches: Vec<hydra_core::CommitBatch> = original
            .commit_ledger()
            .batches_in_sequence()
            .into_iter()
            .cloned()
            .collect();
        // Break the chain.
        batches[1].previous_hash = None;

        let mut recovered = Hydra::new();
        let result = recovered.recover_from_commits(batches);
        assert!(result.is_err());
        assert_eq!(recovered.commit_count(), 0);
    }

    #[test]
    fn hydra_records_commit_for_ingest_cascade() {
        use hydra_core::EventKind;
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        assert_eq!(hydra.commit_count(), 0);

        let result = hydra
            .ingest(EventKind::Signal {
                source: hydra_core::NodeId::from_str("test"),
                name: "commit_test".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();

        assert_eq!(hydra.commit_count(), 1);
        let commit = hydra.latest_commit().unwrap();
        assert_eq!(commit.sequence, 1);
        assert_eq!(commit.event_count, result.events.len());
        assert_eq!(commit.cascade_id, Some(result.events[0].cascade_id.clone()));
        hydra.verify_commit_chain().unwrap();
    }

    #[test]
    fn hydra_commit_chain_links_multiple_ingests() {
        use hydra_core::EventKind;
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        hydra
            .ingest(EventKind::Signal {
                source: hydra_core::NodeId::from_str("test"),
                name: "first".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();
        let first_hash = hydra.latest_commit().unwrap().commit_hash.clone();

        hydra
            .ingest(EventKind::Signal {
                source: hydra_core::NodeId::from_str("test"),
                name: "second".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();

        assert_eq!(hydra.commit_count(), 2);
        let second = hydra.latest_commit().unwrap();
        assert_eq!(second.sequence, 2);
        assert_eq!(second.previous_hash, Some(first_hash));
        hydra.verify_commit_chain().unwrap();
    }

    #[test]
    fn hydra_policy_agent_requests_approval_for_payroll_action() {
        use hydra_core::{
            Action, ActionId, ActionKind, ActionStatus, ActionTarget, ActorId, EventKind, Policy,
            PolicyId, PolicyKind, PolicyScope, PolicyStatus,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = ActorId::from_str("actor_policy_admin");
        let policy = Policy {
            id: PolicyId::new(),
            tenant_id: None,
            name: "Payroll approval required".to_string(),
            kind: PolicyKind::HumanApproval,
            status: PolicyStatus::Active,
            scope: PolicyScope::ActionKind("RunPayroll".to_string()),
            condition: HashMap::new(),
            metadata: HashMap::new(),
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        hydra
            .ingest(EventKind::PolicyRegistered { policy })
            .unwrap();

        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::RunPayroll,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("payroll".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_payroll_agent"),
            approved_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };
        let action_id = action.id.clone();
        let result = hydra
            .ingest(EventKind::ActionProposed { action })
            .unwrap();

        assert_eq!(result.events.len(), 3);
        assert!(matches!(
            result.events[0].kind,
            EventKind::ActionProposed { .. }
        ));
        assert!(matches!(
            result.events[1].kind,
            EventKind::PolicyDecisionRecorded { .. }
        ));
        assert!(matches!(
            result.events[2].kind,
            EventKind::ApprovalRequested { .. }
        ));
        assert_eq!(hydra.decisions_for_action(&action_id).len(), 1);
        assert_eq!(hydra.approvals_for_action(&action_id).len(), 1);
        assert_eq!(hydra.pending_approvals().len(), 1);
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            ActionStatus::Proposed
        );
    }

    #[test]
    fn hydra_evaluates_policy_for_action() {
        use hydra_core::{
            Action, ActionId, ActionKind, ActionStatus, ActionTarget, ActorId, EventKind, Policy,
            PolicyId, PolicyKind, PolicyScope, PolicyStatus,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = ActorId::from_str("actor_policy_test");

        let policy = Policy {
            id: PolicyId::new(),
            tenant_id: None,
            name: "Require approval for payroll runs".to_string(),
            kind: PolicyKind::HumanApproval,
            status: PolicyStatus::Active,
            scope: PolicyScope::ActionKind("RunPayroll".to_string()),
            condition: HashMap::new(),
            metadata: HashMap::new(),
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        hydra
            .ingest(EventKind::PolicyRegistered { policy })
            .unwrap();

        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::RunPayroll,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("payroll".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor,
            approved_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };
        let action_id = action.id.clone();
        hydra
            .ingest(EventKind::ActionProposed { action })
            .unwrap();

        let report = hydra.evaluate_action_policy(&action_id).unwrap();
        assert_eq!(
            report.decision,
            crate::policy_engine::PolicyEvaluationDecision::RequireApproval
        );
    }

    #[test]
    fn hydra_materializes_policy_decision_and_approval_state() {
        use hydra_core::{
            ActionId, ActorId, ApprovalId, ApprovalRequest, ApprovalStatus, EventKind, Policy,
            PolicyDecision, PolicyDecisionId, PolicyDecisionKind, PolicyId, PolicyKind,
            PolicyScope, PolicyStatus,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = ActorId::from_str("actor_policy");
        let accountant = ActorId::from_str("actor_accountant");

        let policy = Policy {
            id: PolicyId::new(),
            tenant_id: None,
            name: "Require approval for payroll runs".to_string(),
            kind: PolicyKind::HumanApproval,
            status: PolicyStatus::Active,
            scope: PolicyScope::ActionKind("RunPayroll".to_string()),
            condition: HashMap::new(),
            metadata: HashMap::new(),
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        let policy_id = policy.id.clone();
        hydra
            .ingest(EventKind::PolicyRegistered { policy })
            .unwrap();
        assert_eq!(hydra.active_policies().len(), 1);
        assert_eq!(
            hydra.policy(&policy_id).unwrap().status,
            PolicyStatus::Active
        );

        let action_id = ActionId::new();
        let decision = PolicyDecision {
            id: PolicyDecisionId::new(),
            tenant_id: None,
            policy_id: Some(policy_id),
            action_id: action_id.clone(),
            kind: PolicyDecisionKind::RequireApproval,
            reason: "payroll runs require approval".to_string(),
            evidence: vec![],
            related_claims: vec![],
            decided_by: actor.clone(),
            decided_at: now,
            caused_by: None,
            details: HashMap::new(),
        };
        let decision_id = decision.id.clone();
        hydra
            .ingest(EventKind::PolicyDecisionRecorded { decision })
            .unwrap();
        assert_eq!(hydra.decisions_for_action(&action_id).len(), 1);
        assert_eq!(
            hydra.policy_decision(&decision_id).unwrap().kind,
            PolicyDecisionKind::RequireApproval
        );

        let approval = ApprovalRequest {
            id: ApprovalId::new(),
            tenant_id: None,
            action_id: action_id.clone(),
            policy_decision_id: Some(decision_id),
            status: ApprovalStatus::Requested,
            requested_by: actor.clone(),
            requested_from: vec![accountant.clone()],
            reason: "accountant approval required".to_string(),
            requested_at: now,
            resolved_at: None,
            resolved_by: None,
            caused_by: None,
            metadata: HashMap::new(),
        };
        let approval_id = approval.id.clone();
        hydra
            .ingest(EventKind::ApprovalRequested { request: approval })
            .unwrap();
        assert_eq!(hydra.pending_approvals().len(), 1);
        assert_eq!(hydra.approvals_for_action(&action_id).len(), 1);
        assert_eq!(hydra.approvals_requested_from(&accountant).len(), 1);

        hydra
            .ingest(EventKind::ApprovalGranted {
                approval_id: approval_id.clone(),
                approved_by: accountant.clone(),
            })
            .unwrap();
        let stored = hydra.approval(&approval_id).unwrap();
        assert_eq!(stored.status, ApprovalStatus::Approved);
        assert_eq!(stored.resolved_by, Some(accountant));
        assert!(stored.resolved_at.is_some());
        assert_eq!(hydra.pending_approvals().len(), 0);
    }

    #[test]
    fn hydra_records_unknown_outcome_after_backfill_action_executes() {
        use hydra_core::{
            Action, ActionId, ActionKind, ActionStatus, ActionTarget, ActorId, EventKind,
            OutcomeKind,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = ActorId::from_str("actor_prometheus");
        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::Backfill,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::Dataset(
                "analytics.public.revenue_daily".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };
        let action_id = action.id.clone();

        hydra.ingest(EventKind::ActionProposed { action }).unwrap();
        hydra
            .ingest(EventKind::ActionExecuted {
                action_id: action_id.clone(),
            })
            .unwrap();

        let outcomes = hydra.outcomes_for_action(&action_id);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].kind, OutcomeKind::Unknown);
    }
}
