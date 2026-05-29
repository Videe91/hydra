use crate::anomaly::{Anomaly, AnomalyEngine};
use crate::cascade::{CascadeConfig, CascadeEngine, CascadeResult};
use crate::commit_ledger::CommitLedger;
use crate::coverage::{CoverageEngine, CoverageReport};
use crate::schema_gate::{SchemaGate, SchemaGateConfig};
use crate::micromodel_store::MicroModelStore;
use crate::schema_registry_store::SchemaRegistryStore;
use crate::snapshot_store::SnapshotStore;
use crate::schema_validator::SchemaValidator;
use crate::sensor_checkpoint_store::SensorCheckpointStore;
use crate::replication_store::ReplicationStore;
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
// === MicroModel Patch 2 — built-in CommitRateAnomalyModel identity ===
//
// Stable so re-runs and snapshot restores resolve to the same
// registry entry. `BUILTIN_COMMIT_RATE_MODEL_ID` is the
// `MicroModelId` recorded on every prediction event;
// `BUILTIN_COMMIT_RATE_ACTOR_ID` is the system actor recorded as
// `created_by` on the auto-register event.
pub const BUILTIN_COMMIT_RATE_MODEL_ID: &str = "mm_builtin_commit_rate_v0";
pub const BUILTIN_COMMIT_RATE_ACTOR_ID: &str = "actor_hydra_commit_rate_model";

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
    /// Live fan-out for committed batches. Called AFTER the durable
    /// writer succeeds; failures cannot affect commit success because
    /// the trait returns `()`. `None` by default — no in-process
    /// subscribers, no overhead.
    commit_observer: Option<std::sync::Arc<dyn crate::commit_ledger::CommitObserver>>,
    sensor_checkpoint_store: SensorCheckpointStore,
    replication_store: ReplicationStore,
    schema_registry_store: SchemaRegistryStore,
    /// MicroModel Patch 1 — registry + audit only. Inference and
    /// background runner land in Patch 2+.
    micromodel_store: MicroModelStore,
    /// MicroModel Patch 2 — built-in `CommitRateAnomalyModel`.
    /// Transient by design (cold restart re-enters WarmingUp).
    /// `None` until the first call to `evaluate_commit_rate_anomaly`,
    /// which also auto-registers the model definition in the
    /// registry.
    commit_rate_anomaly_model:
        Option<crate::micromodels::CommitRateAnomalyModel>,
    schema_validator: SchemaValidator,
    schema_gate: SchemaGate,
    snapshot_store: SnapshotStore,
    snapshot_backend: Option<Box<dyn crate::snapshot_store::SnapshotBackend>>,
    reflex_registry: ReflexRegistry,
    limits: ResourceLimits,
    /// Optional WAL for crash recovery
    wal: Option<Box<dyn WalWriter>>,
    /// V2 polish #5 — engine-level role. Defaults to `Leader`.
    /// When set to `Follower`, in-process ingest paths return
    /// `HydraError::ReadOnlyFollower`. Replication apply and
    /// recovery paths are exempt — see [`EngineRole`].
    role: EngineRole,
}

/// V2 polish #5 — engine-level role guard.
///
/// Mirrors the HTTP-layer `hydra_api::security::RuntimeRole` from V2
/// P4H but lives in `hydra-engine` so it covers in-process write
/// paths (sensor bus, SDK, embedded callers) that don't traverse the
/// HTTP middleware.
///
/// `Leader` (default) accepts every write. `Follower` rejects engine
/// mutating entry points with `HydraError::ReadOnlyFollower`. The
/// follower path still accepts:
///   - `apply_replication_commits` (the receive path)
///   - `recover_from_*` (bootstrap / replay)
///   - `record_replication_apply_offset`, `record_replication_heartbeat`
///   - subscription / schema-gate / reflex / sensor-checkpoint config
///
/// `RuntimeRole` (hydra-api) and `EngineRole` (hydra-engine) are
/// deliberately separate types — the engine crate doesn't depend on
/// hydra-api. Operators set both for follower deployments:
///   - `Hydra::set_role(EngineRole::Follower)`
///   - `ServerSecurityConfig::with_role(RuntimeRole::Follower)`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineRole {
    Leader,
    Follower,
}

impl Default for EngineRole {
    fn default() -> Self {
        Self::Leader
    }
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

/// V2 patch 3B — outcome of `Hydra::apply_replication_commits`.
///
/// `latest_sequence` / `latest_commit_id` reflect the follower's ledger
/// head **after** the apply (or before, if `applied_count == 0`).
/// Returned regardless of whether any commits were actually applied, so
/// pull loops always learn the follower's current cursor in one round
/// trip.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplicationApplyReport {
    pub peer_id: hydra_core::ReplicaId,
    pub applied_count: usize,
    pub latest_sequence: Option<u64>,
    pub latest_commit_id: Option<hydra_core::CommitId>,
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
            commit_observer: None,
            sensor_checkpoint_store: SensorCheckpointStore::new(),
            replication_store: ReplicationStore::new(),
            schema_registry_store: SchemaRegistryStore::new(),
            micromodel_store: MicroModelStore::new(),
            commit_rate_anomaly_model: None,
            schema_validator: SchemaValidator::new(),
            schema_gate: SchemaGate::disabled(),
            snapshot_store: SnapshotStore::new(),
            snapshot_backend: None,
            reflex_registry: ReflexRegistry::new(),
            limits: ResourceLimits::default(),
            wal: None,
            role: EngineRole::Leader,
        }
    }

    /// V2 polish #5 — construct a Hydra with a specific role.
    /// Ergonomic shortcut for follower deployments; equivalent to
    /// `Hydra::new()` followed by `.set_role(role)`.
    pub fn new_with_role(role: EngineRole) -> Self {
        let mut hydra = Self::new();
        hydra.role = role;
        hydra
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
            commit_observer: None,
            sensor_checkpoint_store: SensorCheckpointStore::new(),
            replication_store: ReplicationStore::new(),
            schema_registry_store: SchemaRegistryStore::new(),
            micromodel_store: MicroModelStore::new(),
            commit_rate_anomaly_model: None,
            schema_validator: SchemaValidator::new(),
            schema_gate: SchemaGate::disabled(),
            snapshot_store: SnapshotStore::new(),
            snapshot_backend: None,
            reflex_registry: ReflexRegistry::new(),
            limits: ResourceLimits::default(),
            wal: None,
            role: EngineRole::Leader,
        }
    }

    /// V2 polish #5 — current engine role. `Copy`, so returned by
    /// value.
    pub fn role(&self) -> EngineRole {
        self.role
    }

    /// V2 polish #5 — set the engine role at runtime. Used by
    /// operator boot code (typically once at startup) and the
    /// future role-flip admin route (polish #6).
    pub fn set_role(&mut self, role: EngineRole) {
        self.role = role;
    }

    /// V2 polish #5 — engine-level role guard. Returns
    /// `HydraError::ReadOnlyFollower { method }` when the role is
    /// `Follower`. Mutating entry points that should be available
    /// to followers (replication apply, recovery) do not call this.
    fn ensure_leader_for_write(&self, method: &'static str) -> hydra_core::error::Result<()> {
        if self.role == EngineRole::Follower {
            return Err(hydra_core::error::HydraError::ReadOnlyFollower { method });
        }
        Ok(())
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
        // V2 polish #5 — engine-level role guard. All 5 public
        // `ingest*` methods funnel into the *_unguarded body below
        // through this method, so a single check covers every
        // external ingest variant. Recovery audit paths (which need
        // to emit a SnapshotRestored event even on a follower)
        // bypass the guard by calling `ingest_event_internal_unguarded`
        // directly. `apply_replication_commits` is exempt by virtue
        // of not routing through this method at all.
        self.ensure_leader_for_write("ingest")?;
        self.ingest_event_internal_unguarded(event, idempotency_key)
    }

    /// V2 polish #5 — guard-free body of `ingest_event_internal`.
    /// Used by recovery audit paths (`recover_from_snapshot_*` and
    /// `restore_from_snapshot`) to emit the `SnapshotRestored`
    /// audit event without tripping the follower role guard.
    /// External callers must go through `ingest_event_internal`
    /// (or one of the public `ingest*` methods) so the guard fires.
    fn ingest_event_internal_unguarded(
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

        // Schema gate runs AFTER idempotency short-circuit and BEFORE cascade.
        // In Strict mode, invalid writes are rejected here — no cascade, no
        // commit, no writer, no WAL. Permissive and Off modes always allow
        // through.
        //
        // NodeUpdated needs a NodeId → TypeId lookup to know which entity
        // schema to validate against, so we hand the gate a projection-
        // backed resolver closure.
        let projection = &self.projection;
        let node_type_resolver = |node_id: &hydra_core::NodeId| -> Option<hydra_core::TypeId> {
            projection
                .node(node_id)
                .map(|node| hydra_core::TypeId::from_str(&node.meta.type_id))
        };
        // EdgeUpdated needs the same projection-backed lookup that
        // NodeUpdated does. With Patch 2B + Edge Gating, the engine
        // already stamps NodeMeta/EdgeMeta with tenant + type_id at
        // projection apply time, so this resolver only needs the
        // type lookup.
        let edge_type_resolver = |edge_id: &hydra_core::EdgeId| -> Option<hydra_core::TypeId> {
            projection
                .edge(edge_id)
                .map(|edge| hydra_core::TypeId::from_str(&edge.meta.type_id))
        };
        self.schema_gate.validate_event_with_resolvers(
            &self.schema_registry_store,
            &self.schema_validator,
            &event,
            Some(&node_type_resolver),
            Some(&edge_type_resolver),
        )?;

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
            self.replication_store.apply_event(event)?;
            self.schema_registry_store.apply_event(event)?;
            self.micromodel_store.apply_event(event)?;
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
        // Live fan-out — calls the observer (if attached) AFTER the
        // durable writer has succeeded. The trait returns `()`, so a
        // saturated channel or disconnected subscriber can't roll
        // back a commit that's already on disk. See
        // `commit_ledger::CommitObserver` for the contract.
        if let Some(observer) = &self.commit_observer {
            observer.observe_commit(&commit);
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
            self.apply_replayed_event(&event)?;
            count += 1;
        }
        Ok(count)
    }

    /// Apply a single historical event to all materialized state in
    /// pure-replay mode — projection, event log, temporal index, and
    /// every store.
    ///
    /// **Does not** fire the cascade, agents, reflexes, WAL, or the
    /// commit writer. Used by both `recover_from_events` (durable
    /// recovery) and `apply_replication_commits` (V2 follower apply)
    /// so the two replay paths stay byte-identical.
    fn apply_replayed_event(&mut self, event: &Event) -> hydra_core::error::Result<()> {
        self.projection.apply(event)?;
        self.event_log.append(event.clone());
        self.temporal.record(event);
        self.epistemic_store.apply_event(event)?;
        self.action_store.apply_event(event)?;
        self.policy_store.apply_event(event)?;
        self.sensor_checkpoint_store.apply_event(event)?;
        self.replication_store.apply_event(event)?;
        self.schema_registry_store.apply_event(event)?;
        self.micromodel_store.apply_event(event)?;
        Ok(())
    }

    /// Validate that a sequence of commit batches forms a contiguous tail
    /// starting at `snapshot_sequence + 1`. Each batch must also be
    /// committed (`is_committed`) — uncommitted batches in the replay tail
    /// indicate a corrupt or in-flight commit stream.
    ///
    /// This is intentionally separate from `CommitLedger::verify_chain`,
    /// which expects a full chain from sequence 1. Snapshot replay starts
    /// at `snapshot.sequence + 1`, so it needs its own validator.
    fn validate_snapshot_replay_tail(
        snapshot_sequence: u64,
        batches: &[hydra_core::CommitBatch],
    ) -> hydra_core::error::Result<()> {
        let mut expected_sequence = snapshot_sequence + 1;
        for batch in batches {
            if batch.sequence != expected_sequence {
                return Err(hydra_core::error::HydraError::StorageError(format!(
                    "snapshot replay expected commit sequence {expected_sequence}, got {}",
                    batch.sequence
                )));
            }
            if !batch.is_committed() {
                return Err(hydra_core::error::HydraError::StorageError(format!(
                    "snapshot replay encountered uncommitted batch {}",
                    batch.id
                )));
            }
            expected_sequence += 1;
        }
        Ok(())
    }

    /// Fast-restart recovery: restore materialized state from a stored
    /// snapshot, then replay every commit whose sequence is greater than
    /// the snapshot's sequence.
    ///
    /// Looks up the snapshot body in `snapshot_store` and delegates to
    /// [`Hydra::recover_from_snapshot_body_and_replay`].
    ///
    /// v0 semantics:
    /// - Replays ALL commits with `sequence > snapshot.sequence`,
    ///   including `SnapshotTaken` control-plane commits — the commit log
    ///   replay is faithful to what happened after the snapshot, with no
    ///   filtering. This is the cleanest model; "business-only" replay
    ///   can be a future option.
    /// - The validate-then-mutate pattern: replay-tail validation happens
    ///   before any state reset, so a sequence gap leaves the runtime
    ///   untouched.
    ///
    /// v0 limitation:
    /// - The in-memory `commit_ledger` is NOT reconstructed from
    ///   historical commits. `SnapshotBody` stores `CommitRecord`
    ///   summaries (no event bodies for ledger replay) and the snapshot
    ///   replay tail covers only post-snapshot batches. After this call,
    ///   `commit_ledger` reflects the post-restore commits only (e.g.
    ///   the audit `SnapshotRestored` batch). Full ledger reconstruction
    ///   is `recover_from_commits` territory.
    pub fn recover_from_snapshot_and_replay(
        &mut self,
        snapshot_id: &hydra_core::SnapshotId,
        commits: Vec<hydra_core::CommitBatch>,
        restored_by: hydra_core::ActorId,
    ) -> hydra_core::error::Result<hydra_core::SnapshotManifest> {
        let body = self.snapshot_store.require_body(snapshot_id)?.clone();
        self.recover_from_snapshot_body_and_replay(body, commits, restored_by)
    }

    /// Same as [`Hydra::recover_from_snapshot_and_replay`] but takes a
    /// `SnapshotBody` directly. Useful for restart flows that loaded the
    /// snapshot from disk before constructing a fresh `Hydra`.
    pub fn recover_from_snapshot_body_and_replay(
        &mut self,
        body: hydra_core::SnapshotBody,
        commits: Vec<hydra_core::CommitBatch>,
        restored_by: hydra_core::ActorId,
    ) -> hydra_core::error::Result<hydra_core::SnapshotManifest> {
        let manifest = body.manifest.clone();
        let snapshot_sequence = manifest.sequence;

        // Filter to post-snapshot batches and sort by sequence BEFORE
        // validating, so callers can pass batches in any order.
        let mut replay_batches: Vec<hydra_core::CommitBatch> = commits
            .into_iter()
            .filter(|batch| batch.sequence > snapshot_sequence)
            .collect();
        replay_batches.sort_by_key(|batch| batch.sequence);

        // Validate the replay tail BEFORE any mutation. A gap or
        // uncommitted batch errors out without touching runtime state.
        Self::validate_snapshot_replay_tail(snapshot_sequence, &replay_batches)?;
        let replayed_commit_count = replay_batches.len();

        // Assemble the full event sequence: snapshot body's captured
        // events, followed by every event from the replay tail in order.
        let mut all_events = body.events.clone();
        all_events.extend(
            replay_batches
                .iter()
                .flat_map(|batch| batch.events.clone()),
        );

        // Mutation phase. recover_from_events is the pure replay path:
        // it applies events to projection / event_log / temporal /
        // epistemic / action / policy / sensor_checkpoint /
        // schema_registry stores, without running cascades, agents,
        // reflexes, commit writers, or WAL writes.
        //
        // reset_runtime_state_preserving_config() clears materialized
        // stores but deliberately leaves snapshot_store alone — so the
        // restored snapshot survives.
        self.reset_runtime_state_preserving_config();
        self.recover_from_events(all_events)?;

        // Re-insert the body so callers can later list / inspect /
        // re-restore this snapshot. Idempotent on the same id.
        self.snapshot_store.insert(body);

        // Audit the restore. The SnapshotRestored event commits on top
        // of the now-fresh commit_ledger. V2 polish #5 — route through
        // the unguarded body so a follower (which is the typical
        // bootstrap caller) can still record the audit commit.
        self.ingest_event_internal_unguarded(
            Event::trigger(hydra_core::EventKind::SnapshotRestored {
                manifest: manifest.clone(),
                replayed_commit_count,
            }),
            None,
        )?;

        // restored_by is captured for future SnapshotRestored audit
        // metadata; the current variant doesn't yet carry an actor field.
        let _ = restored_by;
        Ok(manifest)
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
        self.replication_store = ReplicationStore::new();
        self.schema_registry_store = SchemaRegistryStore::new();
        self.micromodel_store = MicroModelStore::new();
        // MicroModel Patch 2 — transient by design; cold restart
        // re-enters WarmingUp on the next evaluation.
        self.commit_rate_anomaly_model = None;
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

    /// All events in the log, in insertion order. Thin wrapper over the
    /// log's iterator — useful for audit views and HTTP listing routes.
    pub fn events(&self) -> Vec<&hydra_core::Event> {
        self.event_log.iter().collect()
    }

    /// Look up a single event by id. Linear scan — fine for audit
    /// surfaces; not intended for hot-path lookups.
    pub fn event(&self, event_id: &hydra_core::EventId) -> Option<&hydra_core::Event> {
        self.event_log.iter().find(|event| &event.id == event_id)
    }

    /// All events that share a given cascade id, in insertion order.
    /// Empty if the cascade is unknown.
    pub fn events_for_cascade(
        &self,
        cascade_id: &hydra_core::CascadeId,
    ) -> Vec<&hydra_core::Event> {
        self.event_log
            .iter()
            .filter(|event| &event.cascade_id == cascade_id)
            .collect()
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

    /// All alive nodes in the projection (unfiltered).
    ///
    /// Used by the read-side query API. Edges and filtered views have their
    /// own dedicated accessors; this is the flat "list everything" hook.
    pub fn all_nodes(&self) -> Vec<&hydra_core::node::Node> {
        self.projection.all_nodes()
    }

    /// All alive edges in the projection (unfiltered). Pair to
    /// [`Self::all_nodes`] for the read-side query API.
    pub fn all_edges(&self) -> Vec<&hydra_core::edge::Edge> {
        self.projection.all_edges()
    }

    /// All evidence currently held by the epistemic store. Pair to
    /// [`EpistemicStore::all_claims`] / [`Self::all_nodes`] for the
    /// read-side query API.
    pub fn all_evidence(&self) -> Vec<&hydra_core::Evidence> {
        self.epistemic_store.all_evidence().collect()
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

    /// Read-only access to the coverage engine (for `model_count`
    /// and similar introspection from outside the engine crate).
    pub fn coverage_engine(&self) -> &CoverageEngine {
        &self.coverage_engine
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

    // === MicroModel Patch 6 — operator approval workflow ===
    //
    // Direct approve / reject helpers for the HTTP layer. Both
    // ingest the corresponding `EventKind::Action{Approved,Rejected}`
    // event (so the audit log, commit ledger, durable writer, and
    // commit observer all see the transition) and return the
    // post-cascade `Action` snapshot for the caller's response.
    //
    // No state-machine enforcement in v0: a Rejected action can be
    // re-approved, an Approved action re-rejected, etc. The HTTP
    // layer surfaces `previous_status` so the caller sees the flip.
    // Future patches may add terminal-state guards. Unknown
    // action_id returns `HydraError::QueryError("unknown action: ...")`
    // via the action_store; the HTTP layer maps that to 404.

    /// Approve a proposed (or otherwise non-terminal) action. The
    /// `reason` is optional — operators may approve with no
    /// rationale, or supply context that gets stored in the audit
    /// log. Returns a clone of the post-cascade `Action`.
    pub fn approve_action(
        &mut self,
        action_id: hydra_core::ActionId,
        actor: hydra_core::ActorId,
        reason: Option<String>,
    ) -> hydra_core::error::Result<hydra_core::Action> {
        // Validate the action exists BEFORE we ingest. The
        // action_store would error on `mutate_action`, but the
        // ingest would still record the event in the audit log.
        // We want clean 404 semantics — no audit pollution from
        // missing ids.
        if self.action_store.action(&action_id).is_none() {
            return Err(hydra_core::error::HydraError::QueryError(format!(
                "unknown action: {action_id}"
            )));
        }
        self.ingest(hydra_core::EventKind::ActionApproved {
            action_id: action_id.clone(),
            approved_by: actor,
            reason,
        })?;
        self.action_store
            .action(&action_id)
            .cloned()
            .ok_or_else(|| {
                hydra_core::error::HydraError::QueryError(format!(
                    "action vanished after approve: {action_id}"
                ))
            })
    }

    /// Reject a proposed (or otherwise non-terminal) action. The
    /// `reason` is required — explicit rejection rationale is
    /// load-bearing for audit + downstream learning. Returns a
    /// clone of the post-cascade `Action`.
    pub fn reject_action(
        &mut self,
        action_id: hydra_core::ActionId,
        actor: hydra_core::ActorId,
        reason: String,
    ) -> hydra_core::error::Result<hydra_core::Action> {
        if self.action_store.action(&action_id).is_none() {
            return Err(hydra_core::error::HydraError::QueryError(format!(
                "unknown action: {action_id}"
            )));
        }
        self.ingest(hydra_core::EventKind::ActionRejected {
            action_id: action_id.clone(),
            rejected_by: actor,
            reason,
        })?;
        self.action_store
            .action(&action_id)
            .cloned()
            .ok_or_else(|| {
                hydra_core::error::HydraError::QueryError(format!(
                    "action vanished after reject: {action_id}"
                ))
            })
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

    // === Replication (V2 patch 2) ===

    /// Read access to the replication control-plane store. Returns the
    /// materialized view of registered peers + runs derived from the
    /// event log; no network or background behavior is implied.
    pub fn replication_store(&self) -> &ReplicationStore {
        &self.replication_store
    }

    pub fn replication_peer(
        &self,
        id: &hydra_core::ReplicaId,
    ) -> Option<&hydra_core::ReplicationPeer> {
        self.replication_store.peer(id)
    }

    pub fn replication_run(
        &self,
        id: &hydra_core::ReplicationRunId,
    ) -> Option<&hydra_core::ReplicationRun> {
        self.replication_store.run(id)
    }

    pub fn replication_peers_with_role(
        &self,
        role: hydra_core::ReplicationRole,
    ) -> Vec<&hydra_core::ReplicationPeer> {
        self.replication_store.peers_with_role(role)
    }

    pub fn replication_peers_with_status(
        &self,
        status: hydra_core::ReplicationPeerStatus,
    ) -> Vec<&hydra_core::ReplicationPeer> {
        self.replication_store.peers_with_status(status)
    }

    pub fn replication_peers_for_tenant(
        &self,
        tenant: &hydra_core::TenantId,
    ) -> Vec<&hydra_core::ReplicationPeer> {
        self.replication_store.peers_for_tenant(tenant)
    }

    pub fn replication_runs_for_peer(
        &self,
        peer_id: &hydra_core::ReplicaId,
    ) -> Vec<&hydra_core::ReplicationRun> {
        self.replication_store.runs_for_peer(peer_id)
    }

    pub fn replication_runs_with_status(
        &self,
        status: hydra_core::ReplicationRunStatus,
    ) -> Vec<&hydra_core::ReplicationRun> {
        self.replication_store.runs_with_status(status)
    }

    pub fn replication_runs_for_tenant(
        &self,
        tenant: &hydra_core::TenantId,
    ) -> Vec<&hydra_core::ReplicationRun> {
        self.replication_store.runs_for_tenant(tenant)
    }

    pub fn latest_replication_offset(
        &self,
        peer_id: &hydra_core::ReplicaId,
    ) -> Option<&hydra_core::ReplicationOffset> {
        self.replication_store.latest_offset(peer_id)
    }

    pub fn latest_replication_lag(
        &self,
        peer_id: &hydra_core::ReplicaId,
    ) -> Option<&hydra_core::ReplicationLag> {
        self.replication_store.latest_lag(peer_id)
    }

    /// V2 patch 4C — stamp a runtime-local replication cursor for the
    /// given peer. Direct in-memory update, not event-sourced — keeps
    /// the follower's commit ledger byte-identical to the leader's.
    ///
    /// Called automatically by `apply_replication_commits` (with the
    /// last applied batch) and by the worker's bootstrap path (with
    /// either the last tail batch or the snapshot manifest head if the
    /// tail was empty). Surviving in-memory only — operators
    /// re-bootstrap on restart for now.
    ///
    /// `pull_once` and other puller flows read this cursor in
    /// preference to `latest_commit().sequence` to decide
    /// `after_sequence` on the next fetch — that's the patch 4C
    /// post-bootstrap chain-handshake.
    pub fn record_replication_apply_offset(
        &mut self,
        peer_id: hydra_core::ReplicaId,
        offset: hydra_core::ReplicationOffset,
    ) {
        self.replication_store
            .record_local_apply_offset(peer_id, offset);
    }

    /// V2 patch 4G — stamp a runtime-local replication lag observation
    /// for the given peer. Direct in-memory update, **not event-sourced**
    /// — emitting a heartbeat event would diverge the follower's
    /// commit chain from the leader's (same constraint as patch 4C
    /// cursor).
    ///
    /// Called by the puller after every page fetch (including empty
    /// pages — lag tracking matters most when the follower is caught
    /// up). `latest_replication_lag` (already public from V2 P2) reads
    /// the in-memory value back. Side-channel file persistence is
    /// configured at the puller level via `heartbeat_path`.
    pub fn record_replication_heartbeat(
        &mut self,
        peer_id: hydra_core::ReplicaId,
        lag: hydra_core::ReplicationLag,
    ) {
        self.replication_store
            .record_local_heartbeat(peer_id, lag);
    }

    /// V2 patch 3B — apply a leader-supplied page of committed batches to
    /// this follower.
    ///
    /// Strictly leader-equivalent: appends to the commit ledger and
    /// replays events into every materialized store, but does **not**
    /// fire the cascade, agents, reflexes, WAL, or commit writer. This
    /// keeps the follower's chain byte-identical to the leader's — no
    /// follower-local commits are synthesized, including replication
    /// heartbeats. Heartbeat / lag-recording lives in a future side
    /// channel.
    ///
    /// Validation contract:
    ///   - empty `commits` → success no-op (returns current head info)
    ///   - reject unsorted (must be strictly ascending by sequence)
    ///   - reject sequence gaps relative to current head
    ///   - reject mismatched `previous_hash` continuity
    ///   - reject `status != Committed`
    ///   - reject missing `commit_hash`
    ///   - reject duplicate commit id / idempotency key
    ///   - `append_committed_batch` recomputes `commit_hash` and rejects
    ///     if it doesn't match the stored value
    ///
    /// Validation runs as a **dry pass** against `(projected_sequence,
    /// projected_head_hash)` before any mutation — so a bad batch list
    /// can't leave the engine half-mutated.
    ///
    /// **Partial-state caveat**: if dry-run validation succeeds but
    /// `apply_replayed_event` later errors mid-list (e.g. the leader's
    /// events reference state this follower never had), the follower
    /// may be left at a partial state. Recovery is "re-bootstrap from
    /// snapshot" — landing in a later V2 patch. This method does not
    /// yet provide transactional rollback across materialized stores.
    pub fn apply_replication_commits(
        &mut self,
        peer_id: hydra_core::ReplicaId,
        commits: Vec<hydra_core::CommitBatch>,
    ) -> hydra_core::error::Result<ReplicationApplyReport> {
        let head_report = || ReplicationApplyReport {
            peer_id: peer_id.clone(),
            applied_count: 0,
            latest_sequence: self.commit_ledger.latest_record().map(|r| r.sequence),
            latest_commit_id: self.commit_ledger.latest_record().map(|r| r.id.clone()),
        };

        if commits.is_empty() {
            return Ok(head_report());
        }

        // Reject unsorted. Sorting silently would mask leader/export
        // bugs — surface them.
        for window in commits.windows(2) {
            if window[0].sequence >= window[1].sequence {
                return Err(hydra_core::error::HydraError::QueryError(format!(
                    "replication commits not strictly ascending by sequence: {} then {}",
                    window[0].sequence, window[1].sequence
                )));
            }
        }

        // V2 patch 4C: dual-mode dry-pass. The follower's commit_ledger
        // and the follower's replication CURSOR for this peer can either
        // be aligned (clean append: fresh follower, or follower-as-leader
        // chain replay) or diverged (post-bootstrap: follower's ledger
        // has a SnapshotRestored audit commit, but the cursor tracks the
        // leader's chain head at bootstrap time).
        //
        // - **Ledger mode**: cursor matches ledger head (or no cursor) →
        //   use ledger.next_sequence + ledger.head_hash as the expected
        //   chain head. Append batches to commit_ledger as usual (3B
        //   behavior).
        // - **Cursor mode**: cursor diverges from ledger → use the
        //   cursor's sequence + commit_hash as the expected chain head.
        //   Skip ledger append; follower's local commit_ledger stays
        //   the local audit chain. The cursor advances on each batch.
        //
        // Either way the cursor is stamped at the last applied batch's
        // offset on success — so subsequent `pull_once` calls read the
        // cursor as `after_sequence` and the chain stays consistent.
        let cursor_for_peer = self
            .replication_store
            .latest_offset(&peer_id)
            .cloned();
        let cursor_mode = match &cursor_for_peer {
            Some(cursor) => cursor.commit_hash != self.commit_ledger.head_hash().cloned(),
            None => false,
        };
        let mut projected_seq = if cursor_mode {
            cursor_for_peer.as_ref().unwrap().sequence + 1
        } else {
            self.commit_ledger.next_sequence()
        };
        let mut projected_head = if cursor_mode {
            cursor_for_peer.as_ref().unwrap().commit_hash.clone()
        } else {
            self.commit_ledger.head_hash().cloned()
        };
        for batch in &commits {
            if batch.sequence != projected_seq {
                return Err(hydra_core::error::HydraError::QueryError(format!(
                    "replication batch sequence gap: expected {}, got {}",
                    projected_seq, batch.sequence
                )));
            }
            if batch.previous_hash != projected_head {
                return Err(hydra_core::error::HydraError::QueryError(format!(
                    "replication batch previous_hash mismatch at sequence {}",
                    batch.sequence
                )));
            }
            if batch.status != hydra_core::CommitStatus::Committed {
                return Err(hydra_core::error::HydraError::QueryError(format!(
                    "replication batch {} is not committed (status {:?})",
                    batch.id, batch.status
                )));
            }
            if batch.commit_hash.is_none() {
                return Err(hydra_core::error::HydraError::QueryError(format!(
                    "replication batch {} missing commit_hash",
                    batch.id
                )));
            }
            projected_seq += 1;
            projected_head = batch.commit_hash.clone();
        }

        // Apply. In **ledger mode**, `append_committed_batch` re-validates
        // atomically at the ledger boundary (including hash recompute) so
        // any divergence between dry pass and final apply still aborts
        // cleanly. In **cursor mode** the follower's commit_ledger is NOT
        // touched — the leader's chain lives in the cursor only, and the
        // follower's ledger stays local-audit-only. Events are replayed
        // into materialized stores in both modes via `apply_replayed_event`.
        //
        // V2 patch 4C: track the last applied batch's (sequence, id,
        // hash) so we can stamp it into the replication store as the
        // follower's local cursor for this peer. The cursor is what
        // `pull_once` reads on the next fetch — NOT the follower's
        // commit_ledger head — so post-bootstrap pull stays composable.
        let mut applied_count = 0usize;
        let mut last_applied_offset: Option<hydra_core::ReplicationOffset> = None;
        for batch in commits {
            let events = batch.events.clone();
            let batch_id = batch.id.clone();
            let batch_sequence = batch.sequence;
            let batch_commit_hash = batch.commit_hash.clone();
            if cursor_mode {
                // Skip ledger append — the cursor is the source of truth.
            } else {
                self.commit_ledger.append_committed_batch(batch)?;
            }
            for event in &events {
                self.apply_replayed_event(event)?;
            }
            last_applied_offset = Some(hydra_core::ReplicationOffset {
                sequence: batch_sequence,
                commit_id: Some(batch_id),
                commit_hash: batch_commit_hash,
            });
            applied_count += 1;
        }

        if let Some(offset) = last_applied_offset {
            self.record_replication_apply_offset(peer_id.clone(), offset);
        }

        Ok(ReplicationApplyReport {
            peer_id,
            applied_count,
            latest_sequence: self.commit_ledger.latest_record().map(|r| r.sequence),
            latest_commit_id: self.commit_ledger.latest_record().map(|r| r.id.clone()),
        })
    }

    // === MicroModel registry (Patch 1 — vocabulary + audit only) ===
    //
    // Every helper here routes through `self.ingest(EventKind::*)`
    // rather than mutating `self.micromodel_store` directly — so the
    // commit ledger, durable writer, observer, and replication path
    // all see micro-model lifecycle events like any other event.

    /// Read access to the micro-model store.
    pub fn micromodel_store(&self) -> &crate::micromodel_store::MicroModelStore {
        &self.micromodel_store
    }

    /// Register a micro-model. Emits `EventKind::MicroModelRegistered`
    /// through `ingest(...)` so the registration is durable,
    /// auditable, and replicable. Returns the model's id back for
    /// caller convenience.
    pub fn register_micro_model(
        &mut self,
        model: hydra_core::MicroModelDefinition,
    ) -> hydra_core::error::Result<hydra_core::MicroModelId> {
        let id = model.id.clone();
        self.ingest(hydra_core::EventKind::MicroModelRegistered { model })?;
        Ok(id)
    }

    /// Move a registered micro-model into a new lifecycle status
    /// (Registered → Active ↔ Disabled → Archived). Emits
    /// `EventKind::MicroModelStatusChanged`.
    pub fn change_micro_model_status(
        &mut self,
        model_id: hydra_core::MicroModelId,
        status: hydra_core::MicroModelStatus,
        reason: Option<String>,
    ) -> hydra_core::error::Result<()> {
        self.ingest(hydra_core::EventKind::MicroModelStatusChanged {
            model_id,
            status,
            reason,
        })?;
        Ok(())
    }

    /// Record one prediction made by a registered model. Patch 1
    /// does NOT run inference — this helper exists so external
    /// agents (or Patch 2's first real model) have a single
    /// engine-level entry point to durably log a prediction.
    pub fn record_micro_model_prediction(
        &mut self,
        prediction: hydra_core::MicroModelPrediction,
    ) -> hydra_core::error::Result<()> {
        self.ingest(hydra_core::EventKind::MicroModelPredictionRecorded { prediction })?;
        Ok(())
    }

    /// Record the ground-truth observation paired with a prior
    /// prediction (matched by `run_id`).
    pub fn record_micro_model_observation(
        &mut self,
        observation: hydra_core::MicroModelObservation,
    ) -> hydra_core::error::Result<()> {
        self.ingest(hydra_core::EventKind::MicroModelObservationRecorded { observation })?;
        Ok(())
    }

    /// Read one registered model by id.
    pub fn micro_model(
        &self,
        id: &hydra_core::MicroModelId,
    ) -> Option<&hydra_core::MicroModelDefinition> {
        self.micromodel_store.model(id)
    }

    /// Snapshot all registered models. Iteration order is the
    /// underlying HashMap order; callers that need stable ordering
    /// should sort the returned slice by id.
    pub fn micro_models(&self) -> Vec<&hydra_core::MicroModelDefinition> {
        self.micromodel_store.all_models().collect()
    }

    /// All models registered with the given `kind`. Order is stable
    /// (sorted by id) per the store's `BTreeSet` index.
    pub fn micro_models_by_kind(
        &self,
        kind: &hydra_core::MicroModelKind,
    ) -> Vec<&hydra_core::MicroModelDefinition> {
        self.micromodel_store.models_by_kind(kind)
    }

    /// Look up one prediction by its `run_id`.
    pub fn micro_model_prediction(
        &self,
        run_id: &hydra_core::MicroModelRunId,
    ) -> Option<&hydra_core::MicroModelPrediction> {
        self.micromodel_store.prediction(run_id)
    }

    /// Look up the observation paired with one prediction by
    /// `run_id`. Returns `None` if the observation hasn't been
    /// recorded yet (the typical "prediction made, outcome pending"
    /// state).
    pub fn micro_model_observation(
        &self,
        run_id: &hydra_core::MicroModelRunId,
    ) -> Option<&hydra_core::MicroModelObservation> {
        self.micromodel_store.observation(run_id)
    }

    // === MicroModel Patch 2 — built-in CommitRateAnomalyModel ===

    /// Run one observation of the built-in commit-rate anomaly
    /// model and record the prediction.
    ///
    /// On first call this auto-registers the model definition
    /// (`mm_builtin_commit_rate_v0`, kind `CommitRatePredictor`,
    /// status `Active`) and lazily initializes the in-memory model
    /// state. The window is `config.window_secs` ending at "now";
    /// commits in that window are counted and converted to
    /// commits/minute before being scored against the EWMA
    /// baseline.
    ///
    /// **State is transient**. A process restart drops the EWMA
    /// state and the next call re-enters `WarmingUp`. The model
    /// registry entry survives via the snapshot/restore path
    /// (Patch 1), but the running statistics do not — this is the
    /// approved Patch 2 boundary; durable model state can come
    /// later.
    ///
    /// `actor` is the actor invoking this evaluation. Patch 2
    /// doesn't yet thread the requesting actor into the prediction
    /// event body — the parameter is reserved for a future audit
    /// surface so the signature stays stable as Patch 3+ refines
    /// the prediction shape.
    ///
    /// Patch boundary: this method records
    /// `MicroModelPredictionRecorded` only. It does NOT emit
    /// `EvidenceAdded`, `ClaimProposed`, or `ActionProposed` — that
    /// linkage is Patch 3, where predictions enter the living loop.
    pub fn evaluate_commit_rate_anomaly(
        &mut self,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<hydra_core::MicroModelPrediction> {
        // Patch 2's public surface — unchanged. Funnels through the
        // shared private helper that Patch 3's bridge also uses.
        // The typed `Output` and the prediction event id are
        // available to the helper but discarded here so the legacy
        // return type stays stable.
        let (prediction, _event_id, _output) =
            self.record_commit_rate_prediction(actor)?;
        Ok(prediction)
    }

    /// Evaluate the built-in commit-rate model AND, on Warning /
    /// Critical, propose paired Evidence + Claim records linked
    /// back to the prediction event.
    ///
    /// This is the MicroModel Patch 3 bridge: a single call moves
    /// the model's verdict from a free-standing prediction (Patch 2)
    /// into Hydra's epistemic loop — `prediction event → evidence →
    /// claim`. Lineage queries on the prediction event id surface
    /// the entire chain.
    ///
    /// Behavior by level:
    /// - `WarmingUp` / `Normal` → prediction only. `evidence_id`
    ///   and `claim_id` on the returned assessment are `None`.
    /// - `Warning` / `Critical` → prediction + Evidence + Claim.
    ///   Both records carry `caused_by = prediction_event_id`. The
    ///   Claim's `evidence_for` references the new evidence id.
    ///
    /// Evidence shape:
    /// ```text
    ///   source     = EvidenceSource::System { name: "mm_builtin_commit_rate_v0" }
    ///   payload    = { kind: "micro_model_prediction", data: typed Values }
    ///   reliability = prediction.confidence
    ///   caused_by  = prediction_event_id
    /// ```
    ///
    /// Claim shape:
    /// ```text
    ///   kind         = AnomalyFinding
    ///   subject      = ClaimSubject::System("hydra")
    ///   predicate    = "under_abnormal_load"
    ///   object       = ClaimObject::Value(Value::Bool(true))
    ///   confidence   = prediction.confidence
    ///   evidence_for = [evidence_id]
    ///   created_by   = actor  (caller's identity — "this agent believes")
    ///   caused_by    = prediction_event_id
    /// ```
    ///
    /// Non-idempotent (matches Patch 2): two calls on the same
    /// condition produce two distinct assessments, each with its
    /// own prediction event, evidence, and claim. Patch 4 may
    /// dedup at the action layer.
    ///
    /// Patch 3 does NOT yet emit `ActionProposed` — that's Patch 4.
    pub fn evaluate_commit_rate_anomaly_and_propose_claim(
        &mut self,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<crate::micromodels::CommitRateAnomalyAssessment>
    {
        let (prediction, prediction_event_id, output) =
            self.record_commit_rate_prediction(actor.clone())?;

        let (evidence_id, evidence_event_id, claim_id, claim_event_id) =
            if output.level.is_actionable() {
                // Build + record Evidence first so the Claim can
                // reference its id in `evidence_for`. Capture the
                // EvidenceAdded event id off the cascade result so
                // downstream (Patch 4 action bridge) can chain
                // `caused_by` cleanly.
                let evidence = build_evidence_from_prediction(
                    &prediction,
                    &output,
                    prediction_event_id.clone(),
                );
                let new_evidence_id = evidence.id.clone();
                let evidence_cascade = self
                    .ingest(hydra_core::EventKind::EvidenceAdded { evidence })?;
                let new_evidence_event_id = evidence_cascade
                    .events
                    .first()
                    .map(|event| event.id.clone())
                    .expect(
                        "ingest produces at least the trigger event for \
                         EvidenceAdded",
                    );

                // Now the Claim. `created_by` is the caller-
                // supplied actor — "I, this agent, believe Hydra
                // is under abnormal load because the model fired."
                // Capture the ClaimProposed event id (events[0]
                // — the trigger). The verification cascade may
                // append a ClaimVerified event later in the same
                // cascade; that one lives at events[1+] and is NOT
                // what we want for the action bridge's caused_by.
                let claim = build_claim_from_prediction(
                    &prediction,
                    &new_evidence_id,
                    actor,
                    prediction_event_id.clone(),
                );
                let new_claim_id = claim.id.clone();
                let claim_cascade =
                    self.ingest(hydra_core::EventKind::ClaimProposed { claim })?;
                let new_claim_event_id = claim_cascade
                    .events
                    .first()
                    .map(|event| event.id.clone())
                    .expect(
                        "ingest produces at least the trigger event for \
                         ClaimProposed",
                    );

                (
                    Some(new_evidence_id),
                    Some(new_evidence_event_id),
                    Some(new_claim_id),
                    Some(new_claim_event_id),
                )
            } else {
                // WarmingUp / Normal: no belief formed against a
                // baseline the model hasn't trusted (warmup) or a
                // steady-state observation (normal).
                (None, None, None, None)
            };

        Ok(crate::micromodels::CommitRateAnomalyAssessment {
            level: output.level,
            prediction,
            prediction_event_id,
            evidence_id,
            evidence_event_id,
            claim_id,
            claim_event_id,
        })
    }

    /// Evaluate the built-in commit-rate model AND, on
    /// Warning / Critical, propose an `ActionKind::Notify` action
    /// gated by the claim's verification state.
    ///
    /// This is the MicroModel Patch 4 reflex: a single call extends
    /// the Patch 3 chain (`prediction → evidence → claim`) with a
    /// downstream `ActionProposed { action }` event whose
    /// `caused_by` points at the `ClaimProposed` event id. Lineage
    /// queries on the prediction event id surface the full
    /// `prediction → evidence + claim → action` chain.
    ///
    /// Gate (deterministic, no policy DSL in v0):
    ///
    /// ```text
    ///   claim.predicate == "under_abnormal_load"
    ///   AND (claim.status == Verified OR claim.confidence >= 0.9)
    /// ```
    ///
    /// In practice Hydra's verification agent auto-promotes the
    /// Patch 3 claim to `Verified` within the same cascade once
    /// the paired evidence lands. The confidence-OR-Verified gate
    /// is belt-and-braces for future scenarios where the
    /// verification cascade doesn't run.
    ///
    /// Action shape (full):
    ///
    /// ```text
    ///   kind                 = ActionKind::Notify
    ///   status               = Proposed
    ///   targets              = [ActionTarget::System("hydra")]
    ///   related_claims       = [claim_id]
    ///   supporting_evidence  = [evidence_id]
    ///   proposed_by          = actor
    ///   payload              = {
    ///     "severity":  Value::String(level.wire_name())
    ///     "reason":    Value::String(prediction.explanation)
    ///     "model_id":  Value::String("mm_builtin_commit_rate_v0")
    ///     "run_id":    Value::String(prediction.run_id)
    ///   }
    ///   caused_by            = claim_event_id
    ///   tenant_id            = None
    /// ```
    ///
    /// `action_ids` on the returned assessment is a `Vec` so future
    /// patches can add Critical-tier extras (`snapshot_now`,
    /// `throttle_agents`) without changing the assessment shape.
    /// Patch 4 ships exactly one action — `Notify` — for both
    /// Warning and Critical.
    ///
    /// Non-idempotent (matches Patches 2 + 3): two calls on the
    /// same condition produce two distinct assessments, each with
    /// their own prediction event, evidence, claim, AND action.
    ///
    /// Patch 4 does NOT execute the action. `ActionStatus` stays
    /// `Proposed`; execution, real delivery, throttle, and snapshot
    /// remain explicit future patches.
    pub fn evaluate_commit_rate_anomaly_and_propose_action(
        &mut self,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<
        crate::micromodels::CommitRateAnomalyActionAssessment,
    > {
        // Step 1 — drive Patch 3. Captures prediction + (maybe)
        // evidence + (maybe) claim + their event ids.
        let claim_assessment = self
            .evaluate_commit_rate_anomaly_and_propose_claim(actor.clone())?;

        // Step 2 — decide whether to fire. WarmingUp / Normal
        // assessments arrive with `claim_id = None` and we exit
        // immediately with an empty action vec.
        let mut action_ids: Vec<hydra_core::ActionId> = Vec::new();
        if let (Some(claim_id), Some(evidence_id), Some(claim_event_id)) = (
            claim_assessment.claim_id.as_ref(),
            claim_assessment.evidence_id.as_ref(),
            claim_assessment.claim_event_id.as_ref(),
        ) {
            // Step 3 — re-read the claim to get its POST-cascade
            // state. The verification agent may have auto-promoted
            // it to Verified within the same cascade as the
            // ClaimProposed ingest.
            let passes_gate = self
                .claim(claim_id)
                .map(|claim| {
                    claim.predicate == "under_abnormal_load"
                        && (claim.status
                            == hydra_core::epistemic::ClaimStatus::Verified
                            || claim.confidence.value() >= 0.9)
                })
                .unwrap_or(false);

            if passes_gate {
                // Step 4 — build + ingest one Notify action.
                let action = build_action_from_assessment(
                    &claim_assessment,
                    claim_id.clone(),
                    evidence_id.clone(),
                    claim_event_id.clone(),
                    actor,
                );
                let new_action_id = action.id.clone();
                self.ingest(hydra_core::EventKind::ActionProposed { action })?;
                action_ids.push(new_action_id);
            }
        }

        // Step 5 — build the action assessment, mirroring the
        // Patch 3 fields and adding `action_ids`.
        Ok(crate::micromodels::CommitRateAnomalyActionAssessment {
            level: claim_assessment.level,
            prediction: claim_assessment.prediction,
            prediction_event_id: claim_assessment.prediction_event_id,
            evidence_id: claim_assessment.evidence_id,
            claim_id: claim_assessment.claim_id,
            claim_event_id: claim_assessment.claim_event_id,
            action_ids,
        })
    }

    /// Shared helper: auto-register the built-in model if missing,
    /// count commits in the window, evaluate the model, record
    /// `MicroModelPredictionRecorded`, and return the typed
    /// triple `(prediction, prediction_event_id, output)`.
    ///
    /// Both Patch 2's `evaluate_commit_rate_anomaly` and Patch 3's
    /// bridge funnel through here so the auto-register + counting
    /// + recording logic lives in one place.
    ///
    /// **Made public in Patch 5** so the HTTP layer
    /// (`hydra-net::http::micromodels`) can drive `mode =
    /// "prediction_only"` evaluations and still report the
    /// prediction event id back to callers — without forcing
    /// Patch 2's `evaluate_commit_rate_anomaly` signature to change.
    pub fn record_commit_rate_prediction(
        &mut self,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<(
        hydra_core::MicroModelPrediction,
        hydra_core::EventId,
        crate::micromodels::CommitRateAnomalyOutput,
    )> {
        // Step 1 — auto-register the built-in model definition if
        // missing. Goes through `register_micro_model` →
        // `self.ingest(EventKind::MicroModelRegistered)`, so this
        // is durable, auditable, and replicable like any other
        // control-plane event. Promote to Active immediately —
        // built-in models are usable on register.
        let model_id =
            hydra_core::MicroModelId::from_str(BUILTIN_COMMIT_RATE_MODEL_ID);
        if self.micro_model(&model_id).is_none() {
            let now = chrono::Utc::now();
            let definition = hydra_core::MicroModelDefinition::registered(
                model_id.clone(),
                hydra_core::MicroModelKind::CommitRatePredictor,
                "builtin_commit_rate_v0",
                1,
                vec![],
                vec![],
                hydra_core::ActorId::from_str(BUILTIN_COMMIT_RATE_ACTOR_ID),
                now,
            );
            self.register_micro_model(definition)?;
            self.change_micro_model_status(
                model_id.clone(),
                hydra_core::MicroModelStatus::Active,
                Some("built-in micro-model: active on register".to_string()),
            )?;
        }

        // Step 2 — count commits in the model's configured window.
        let window_secs = self
            .commit_rate_anomaly_model
            .as_ref()
            .map(|m| m.config().window_secs)
            .unwrap_or_else(|| {
                crate::micromodels::CommitRateAnomalyConfig::default().window_secs
            });
        let now = chrono::Utc::now();
        let window_start =
            now - chrono::Duration::seconds(window_secs as i64);
        let commit_count_in_window = self
            .commit_ledger
            .batches_in_sequence()
            .iter()
            .rev()
            .take_while(|batch| batch.committed_at >= window_start)
            .count() as u64;

        // Step 3 — evaluate via the pure model.
        let (samples_seen_before, output) = {
            let model = self
                .commit_rate_anomaly_model
                .get_or_insert_with(crate::micromodels::CommitRateAnomalyModel::default);
            let samples_before = model.state().samples_seen;
            let output = model.evaluate_observation(now, commit_count_in_window);
            (samples_before, output)
        };

        // Step 4 — build the typed prediction.
        let prediction = hydra_core::MicroModelPrediction {
            model_id: model_id.clone(),
            run_id: hydra_core::MicroModelRunId::new(),
            input: serde_json::json!({
                "observed_at": now.to_rfc3339(),
                "window_secs": window_secs,
                "commit_count_in_window": commit_count_in_window,
                "samples_seen_before_this": samples_seen_before,
            }),
            output: serde_json::to_value(&output)
                .expect("CommitRateAnomalyOutput is serde-derived; cannot fail"),
            confidence: output.level.confidence(),
            explanation: Some(output.reason.clone()),
            created_at: now,
        };

        // Step 5 — record through ingest, capture the trigger
        // event id off the CascadeResult.
        let cascade = self.ingest(
            hydra_core::EventKind::MicroModelPredictionRecorded {
                prediction: prediction.clone(),
            },
        )?;
        let prediction_event_id = cascade
            .events
            .first()
            .map(|event| event.id.clone())
            .expect(
                "ingest produces at least the trigger event for \
                 MicroModelPredictionRecorded",
            );

        // `actor` is reserved for a future MicroModelPredictionRecorded
        // variant that carries the requesting actor in the event
        // body. Patch 2/3 don't yet plumb it through.
        let _ = actor;
        Ok((prediction, prediction_event_id, output))
    }

    /// Read access to the running `CommitRateAnomalyModel`. `None`
    /// until the first call to `evaluate_commit_rate_anomaly`.
    pub fn commit_rate_anomaly_model(
        &self,
    ) -> Option<&crate::micromodels::CommitRateAnomalyModel> {
        self.commit_rate_anomaly_model.as_ref()
    }

    /// Replace the running commit-rate anomaly model with a
    /// preconfigured instance.
    ///
    /// Used by:
    /// - Integration tests that need a deterministic baseline (e.g.
    ///   `hydra-net`'s HTTP tests for the Patch 5 evaluate endpoint
    ///   prime the model with `ewma_rate=10, samples_seen=10` so a
    ///   subsequent spike lands in Critical without walking through
    ///   warmup).
    /// - Future state-restoration patches that load EWMA state from
    ///   a snapshot.
    pub fn set_commit_rate_anomaly_model(
        &mut self,
        model: crate::micromodels::CommitRateAnomalyModel,
    ) {
        self.commit_rate_anomaly_model = Some(model);
    }

    // === Schema registry ===

    /// Read access to the schema registry store.
    pub fn schema_registry_store(&self) -> &SchemaRegistryStore {
        &self.schema_registry_store
    }

    pub fn schema(
        &self,
        id: &hydra_core::SchemaId,
    ) -> Option<&hydra_core::SchemaDefinition> {
        self.schema_registry_store.schema(id)
    }

    pub fn active_schemas(&self) -> Vec<&hydra_core::SchemaDefinition> {
        self.schema_registry_store.active_schemas()
    }

    pub fn disabled_schemas(&self) -> Vec<&hydra_core::SchemaDefinition> {
        self.schema_registry_store.disabled_schemas()
    }

    pub fn archived_schemas(&self) -> Vec<&hydra_core::SchemaDefinition> {
        self.schema_registry_store.archived_schemas()
    }

    pub fn entity_schema(
        &self,
        type_id: &hydra_core::TypeId,
    ) -> Option<&hydra_core::EntityTypeSchema> {
        self.schema_registry_store.entity_schema(type_id)
    }

    pub fn evidence_schema(
        &self,
        kind: &str,
    ) -> Option<&hydra_core::EvidencePayloadSchema> {
        self.schema_registry_store.evidence_schema(kind)
    }

    pub fn claim_predicate_schema(
        &self,
        predicate: &str,
    ) -> Option<&hydra_core::ClaimPredicateSchema> {
        self.schema_registry_store
            .claim_predicate_schema(predicate)
    }

    pub fn action_payload_schema(
        &self,
        action_kind: &str,
    ) -> Option<&hydra_core::ActionPayloadSchema> {
        self.schema_registry_store
            .action_payload_schema(action_kind)
    }

    pub fn policy_condition_schema(
        &self,
        policy_kind: &str,
    ) -> Option<&hydra_core::PolicyConditionSchema> {
        self.schema_registry_store
            .policy_condition_schema(policy_kind)
    }

    // === Schema validator (read-only) ===

    pub fn schema_validator(&self) -> &SchemaValidator {
        &self.schema_validator
    }

    pub fn validate_action_payload(
        &self,
        action: &hydra_core::Action,
    ) -> crate::schema_validator::SchemaValidationReport {
        self.schema_validator
            .validate_action_payload(&self.schema_registry_store, action)
    }

    pub fn validate_policy_condition(
        &self,
        policy: &hydra_core::Policy,
    ) -> crate::schema_validator::SchemaValidationReport {
        self.schema_validator
            .validate_policy_condition(&self.schema_registry_store, policy)
    }

    pub fn validate_evidence_payload(
        &self,
        evidence_kind: &str,
        payload: &std::collections::HashMap<String, hydra_core::Value>,
    ) -> crate::schema_validator::SchemaValidationReport {
        self.schema_validator
            .validate_evidence_payload(&self.schema_registry_store, evidence_kind, payload)
    }

    pub fn validate_evidence(
        &self,
        evidence: &hydra_core::Evidence,
    ) -> crate::schema_validator::SchemaValidationReport {
        self.schema_validator
            .validate_evidence(&self.schema_registry_store, evidence)
    }

    pub fn validate_claim(
        &self,
        claim: &hydra_core::Claim,
    ) -> crate::schema_validator::SchemaValidationReport {
        self.schema_validator
            .validate_claim(&self.schema_registry_store, claim)
    }

    pub fn validate_node_create(
        &self,
        type_id: &hydra_core::TypeId,
        properties: &std::collections::HashMap<String, hydra_core::Value>,
    ) -> crate::schema_validator::SchemaValidationReport {
        self.schema_validator
            .validate_node_create(&self.schema_registry_store, type_id, properties)
    }

    pub fn validate_node_update(
        &self,
        type_id: &hydra_core::TypeId,
        changes: &std::collections::HashMap<String, hydra_core::Value>,
    ) -> crate::schema_validator::SchemaValidationReport {
        match self.entity_schema(type_id) {
            Some(schema) => self.schema_validator.validate_node_update(schema, changes),
            None => crate::schema_validator::SchemaValidationReport::valid(None),
        }
    }

    /// Look up an edge type schema by `TypeId`.
    pub fn edge_schema(
        &self,
        type_id: &hydra_core::TypeId,
    ) -> Option<&hydra_core::EdgeTypeSchema> {
        self.schema_registry_store.edge_schema(type_id)
    }

    /// Read-only validation entrypoint for an edge create. Useful
    /// for HTTP preflight (`POST /schemas/validate/edge-create` will
    /// land in Edge Gating Patch 2).
    pub fn validate_edge_create(
        &self,
        type_id: &hydra_core::TypeId,
        properties: &std::collections::HashMap<String, hydra_core::Value>,
    ) -> crate::schema_validator::SchemaValidationReport {
        self.schema_validator
            .validate_edge_create(&self.schema_registry_store, type_id, properties)
    }

    /// Read-only validation entrypoint for an edge update. Resolves
    /// the edge's `type_id` via the projection, then runs the
    /// validator. Returns `None` if the edge doesn't exist (so HTTP
    /// callers can 404 cleanly).
    pub fn validate_edge_update(
        &self,
        edge_id: &hydra_core::EdgeId,
        changes: &std::collections::HashMap<String, hydra_core::Value>,
    ) -> Option<crate::schema_validator::SchemaValidationReport> {
        let edge = self.projection.edge(edge_id)?;
        let type_id = hydra_core::TypeId::from_str(&edge.meta.type_id);
        let report = match self.edge_schema(&type_id) {
            Some(schema) => self.schema_validator.validate_edge_update(schema, changes),
            None => crate::schema_validator::SchemaValidationReport::valid(None),
        };
        Some(report)
    }

    /// Look up the current TypeId for a node by reading the projection.
    /// Returns None for unknown / deleted nodes.
    pub fn resolve_node_type_id(
        &self,
        node_id: &hydra_core::NodeId,
    ) -> Option<hydra_core::TypeId> {
        self.projection
            .node(node_id)
            .map(|node| hydra_core::TypeId::from_str(&node.meta.type_id))
    }

    // === Schema gate (pre-cascade enforcement) ===

    pub fn schema_gate(&self) -> &SchemaGate {
        &self.schema_gate
    }

    pub fn schema_gate_mut(&mut self) -> &mut SchemaGate {
        &mut self.schema_gate
    }

    pub fn set_schema_gate_config(&mut self, config: SchemaGateConfig) {
        self.schema_gate.set_config(config);
    }

    /// Record one external sensor observation safely.
    ///
    /// This is the high-level reliable-ingestion helper:
    ///
    /// 1. Derive a stable IdempotencyKey from the SourceCursor.
    /// 2. If a checkpoint already exists for that key, return it without ingesting.
    /// 3. Ingest the business event with that idempotency key.
    /// 4. Find the committed batch associated with that key.
    /// 5. Record a SensorCheckpoint that links cursor → idempotency key → commit.
    /// 6. Return the recorded checkpoint.
    ///
    /// This method makes at-least-once external sources effectively safe:
    /// duplicate sensor reads reuse the same key and short-circuit.
    pub fn record_sensor_observation(
        &mut self,
        sensor_id: hydra_core::SensorId,
        source_system: impl Into<String>,
        cursor: hydra_core::SourceCursor,
        business_event: hydra_core::EventKind,
    ) -> hydra_core::error::Result<hydra_core::SensorCheckpoint> {
        self.record_sensor_observation_for_run(
            None,
            sensor_id,
            source_system,
            cursor,
            business_event,
        )
    }

    /// Record one external sensor observation associated with a SensorRun.
    pub fn record_sensor_observation_for_run(
        &mut self,
        run_id: Option<hydra_core::SensorRunId>,
        sensor_id: hydra_core::SensorId,
        source_system: impl Into<String>,
        cursor: hydra_core::SourceCursor,
        business_event: hydra_core::EventKind,
    ) -> hydra_core::error::Result<hydra_core::SensorCheckpoint> {
        self.record_sensor_observation_for_run_inner(
            run_id,
            sensor_id,
            source_system,
            cursor,
            business_event,
            None,
        )
    }

    /// Tenant-scoped variant of [`Self::record_sensor_observation`].
    /// Stamps the business event, the checkpoint manifest, AND the
    /// resulting `SensorCheckpointRecorded` event with the supplied
    /// tenant.
    pub fn record_sensor_observation_for_tenant(
        &mut self,
        sensor_id: hydra_core::SensorId,
        source_system: impl Into<String>,
        cursor: hydra_core::SourceCursor,
        business_event: hydra_core::EventKind,
        tenant: TenantId,
    ) -> hydra_core::error::Result<hydra_core::SensorCheckpoint> {
        self.record_sensor_observation_for_run_inner(
            None,
            sensor_id,
            source_system,
            cursor,
            business_event,
            Some(tenant),
        )
    }

    /// Tenant-scoped variant of [`Self::record_sensor_observation_for_run`].
    pub fn record_sensor_observation_for_run_for_tenant(
        &mut self,
        run_id: Option<hydra_core::SensorRunId>,
        sensor_id: hydra_core::SensorId,
        source_system: impl Into<String>,
        cursor: hydra_core::SourceCursor,
        business_event: hydra_core::EventKind,
        tenant: TenantId,
    ) -> hydra_core::error::Result<hydra_core::SensorCheckpoint> {
        self.record_sensor_observation_for_run_inner(
            run_id,
            sensor_id,
            source_system,
            cursor,
            business_event,
            Some(tenant),
        )
    }

    /// Shared body for the four sensor-observation entry points.
    fn record_sensor_observation_for_run_inner(
        &mut self,
        run_id: Option<hydra_core::SensorRunId>,
        sensor_id: hydra_core::SensorId,
        source_system: impl Into<String>,
        cursor: hydra_core::SourceCursor,
        business_event: hydra_core::EventKind,
        tenant: Option<TenantId>,
    ) -> hydra_core::error::Result<hydra_core::SensorCheckpoint> {
        let source_system = source_system.into();
        let key = hydra_core::IdempotencyKey::new(cursor.stable_key_material());

        if let Some(existing) = self.checkpoint_for_idempotency_key(&key) {
            return Ok(existing.clone());
        }

        // Build the business event with the right tenant envelope so
        // the commit ledger and downstream stores see the correct
        // scope.
        let event = match &tenant {
            Some(t) => Event::trigger_for_tenant(business_event, t.clone()),
            None => Event::trigger(business_event),
        };
        let result = self.ingest_event_with_idempotency_key(event, key.clone())?;

        let commit = self
            .commit_ledger
            .commit_for_idempotency_key(&key)
            .ok_or_else(|| {
                hydra_core::error::HydraError::StorageError(format!(
                    "missing commit for sensor observation idempotency key {}",
                    key.value()
                ))
            })?
            .clone();

        let event_id = result
            .events
            .first()
            .map(|event| event.id.clone())
            .or_else(|| commit.first_event_id().cloned());

        let now = chrono::Utc::now();
        let checkpoint = hydra_core::SensorCheckpoint {
            id: hydra_core::SensorCheckpointId::new(),
            tenant_id: tenant.clone().or_else(|| commit.tenant_id.clone()),
            sensor_id,
            run_id,
            status: hydra_core::SensorCheckpointStatus::Recorded,
            source_system,
            cursor,
            idempotency_key: key,
            commit_id: commit.id.clone(),
            event_id,
            observed_at: now,
            recorded_at: now,
            metadata: std::collections::HashMap::new(),
        };

        let recorded_event = match &tenant {
            Some(t) => Event::trigger_for_tenant(
                hydra_core::EventKind::SensorCheckpointRecorded {
                    checkpoint: checkpoint.clone(),
                },
                t.clone(),
            ),
            None => Event::trigger(hydra_core::EventKind::SensorCheckpointRecorded {
                checkpoint: checkpoint.clone(),
            }),
        };
        self.ingest_event(recorded_event)?;

        Ok(checkpoint)
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

    /// All committed records, in sequence. Useful for audit views and HTTP
    /// listing routes that need lightweight commit metadata without loading
    /// full event bodies.
    pub fn commit_records(&self) -> &[hydra_core::CommitRecord] {
        self.commit_ledger.records()
    }

    /// Full commit batch (including events) for a specific commit id.
    /// Returns `None` if the id is unknown.
    pub fn commit_batch(
        &self,
        id: &hydra_core::CommitId,
    ) -> Option<&hydra_core::CommitBatch> {
        self.commit_ledger.batch(id)
    }

    /// Verify the in-memory commit hash chain.
    pub fn verify_commit_chain(&self) -> hydra_core::error::Result<()> {
        self.commit_ledger.verify_chain()
    }

    // === Snapshots ===

    /// Read access to the snapshot store.
    pub fn snapshot_store(&self) -> &SnapshotStore {
        &self.snapshot_store
    }

    pub fn snapshot_manifest(
        &self,
        id: &hydra_core::SnapshotId,
    ) -> Option<&hydra_core::SnapshotManifest> {
        self.snapshot_store.manifest(id)
    }

    pub fn snapshot_body(
        &self,
        id: &hydra_core::SnapshotId,
    ) -> Option<&hydra_core::SnapshotBody> {
        self.snapshot_store.body(id)
    }

    pub fn snapshot_manifests(&self) -> Vec<&hydra_core::SnapshotManifest> {
        self.snapshot_store.manifests()
    }

    pub fn latest_snapshot_manifest(&self) -> Option<&hydra_core::SnapshotManifest> {
        self.snapshot_store.latest_manifest()
    }

    /// Capture the current materialized state as a snapshot.
    ///
    /// Walks every store, clones its visible state into a `SnapshotBody`,
    /// inserts the body into `snapshot_store`, and emits a
    /// `SnapshotTaken` audit event. The returned manifest's `sequence`
    /// reflects the last commit included in the body; the `SnapshotTaken`
    /// audit event is committed as a separate (later) commit.
    /// Tenant-scoped snapshot. The body still captures global engine
    /// state (snapshots are not per-tenant in v0), but the manifest
    /// records the tenant that requested the snapshot — useful for
    /// audit trails. True tenant-scoped snapshot bodies are a future
    /// patch.
    pub fn snapshot_for_tenant(
        &mut self,
        created_by: hydra_core::ActorId,
        tenant: TenantId,
    ) -> hydra_core::error::Result<hydra_core::SnapshotManifest> {
        self.snapshot_internal(created_by, Some(tenant))
    }

    pub fn snapshot(
        &mut self,
        created_by: hydra_core::ActorId,
    ) -> hydra_core::error::Result<hydra_core::SnapshotManifest> {
        self.snapshot_internal(created_by, None)
    }

    fn snapshot_internal(
        &mut self,
        created_by: hydra_core::ActorId,
        tenant: Option<TenantId>,
    ) -> hydra_core::error::Result<hydra_core::SnapshotManifest> {
        let latest_commit = self.latest_commit().cloned();
        let sequence = latest_commit
            .as_ref()
            .map(|commit| commit.sequence)
            .unwrap_or(0);
        let head_commit_id = latest_commit.as_ref().map(|commit| commit.id.clone());
        let head_commit_hash = latest_commit
            .as_ref()
            .map(|commit| commit.commit_hash.clone());

        let nodes = self
            .projection
            .all_nodes()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let edges = self
            .projection
            .all_edges()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let events = self.events().into_iter().cloned().collect::<Vec<_>>();
        let commit_records = self.commit_records().to_vec();
        let claims = self
            .epistemic_store
            .all_claims()
            .cloned()
            .collect::<Vec<_>>();
        let evidence = self
            .epistemic_store
            .all_evidence()
            .cloned()
            .collect::<Vec<_>>();
        let actions = self
            .action_store
            .all_actions()
            .cloned()
            .collect::<Vec<_>>();
        let outcomes = self
            .action_store
            .all_outcomes()
            .cloned()
            .collect::<Vec<_>>();
        let policies = self
            .policy_store
            .all_policies()
            .cloned()
            .collect::<Vec<_>>();
        let policy_decisions = self
            .policy_store
            .all_decisions()
            .cloned()
            .collect::<Vec<_>>();
        let approval_requests = self
            .policy_store
            .all_approvals()
            .cloned()
            .collect::<Vec<_>>();
        let sensor_runs = self
            .sensor_checkpoint_store
            .all_runs()
            .cloned()
            .collect::<Vec<_>>();
        let sensor_checkpoints = self
            .sensor_checkpoint_store
            .all_checkpoints()
            .cloned()
            .collect::<Vec<_>>();
        let schemas = self
            .schema_registry_store
            .all_schemas()
            .cloned()
            .collect::<Vec<_>>();
        let replication_peers = self
            .replication_store
            .all_peers()
            .cloned()
            .collect::<Vec<_>>();
        let replication_runs = self
            .replication_store
            .all_runs()
            .cloned()
            .collect::<Vec<_>>();
        let micro_models = self
            .micromodel_store
            .all_models()
            .cloned()
            .collect::<Vec<_>>();
        let micro_model_predictions = self
            .micromodel_store
            .all_predictions()
            .cloned()
            .collect::<Vec<_>>();
        let micro_model_observations = self
            .micromodel_store
            .all_observations()
            .cloned()
            .collect::<Vec<_>>();

        let manifest = hydra_core::SnapshotManifest::committed(
            hydra_core::SnapshotId::new(),
            tenant.clone(),
            sequence,
            head_commit_id,
            head_commit_hash,
            created_by,
            chrono::Utc::now(),
            events.len(),
            commit_records.len(),
            nodes.len(),
            edges.len(),
            claims.len(),
            evidence.len(),
            actions.len(),
            outcomes.len(),
            policies.len(),
            policy_decisions.len(),
            approval_requests.len(),
            sensor_checkpoints.len(),
            schemas.len(),
        )
        .with_replication_counts(replication_peers.len(), replication_runs.len())
        .with_micro_model_counts(
            micro_models.len(),
            micro_model_predictions.len(),
            micro_model_observations.len(),
        );
        let body = hydra_core::SnapshotBody {
            manifest: manifest.clone(),
            nodes,
            edges,
            events,
            commit_records,
            claims,
            evidence,
            actions,
            outcomes,
            policies,
            policy_decisions,
            approval_requests,
            sensor_runs,
            sensor_checkpoints,
            schemas,
            replication_peers,
            replication_runs,
            micro_models,
            micro_model_predictions,
            micro_model_observations,
            metadata: std::collections::HashMap::new(),
        };
        // Persist to the backend FIRST so a backend failure aborts the
        // snapshot before any in-memory mutation or audit event commit.
        if let Some(backend) = &self.snapshot_backend {
            backend.write_snapshot(&body)?;
        }
        self.snapshot_store.insert(body);
        // Audit event is tenant-scoped when the snapshot itself was.
        let snapshot_event = match &tenant {
            Some(t) => Event::trigger_for_tenant(
                hydra_core::EventKind::SnapshotTaken {
                    manifest: manifest.clone(),
                },
                t.clone(),
            ),
            None => Event::trigger(hydra_core::EventKind::SnapshotTaken {
                manifest: manifest.clone(),
            }),
        };
        self.ingest_event(snapshot_event)?;
        Ok(manifest)
    }

    /// Attach a durable snapshot backend.
    ///
    /// When set, `snapshot()` calls `backend.write_snapshot(&body)?` BEFORE
    /// inserting the body into the in-memory store and committing the
    /// `SnapshotTaken` audit event — backend failures cleanly abort the
    /// whole snapshot.
    pub fn set_snapshot_backend<B>(&mut self, backend: B)
    where
        B: crate::snapshot_store::SnapshotBackend + 'static,
    {
        self.snapshot_backend = Some(Box::new(backend));
    }

    pub fn clear_snapshot_backend(&mut self) {
        self.snapshot_backend = None;
    }

    pub fn has_snapshot_backend(&self) -> bool {
        self.snapshot_backend.is_some()
    }

    /// Restore the runtime from a previously captured snapshot.
    ///
    /// Patch 2 restores by replaying the events captured in the snapshot
    /// body — slightly slower than direct state injection but avoids
    /// adding per-store "replace entire map" APIs. Patch 3+ may optimize.
    /// After restore, a `SnapshotRestored` audit event is committed.
    /// `replayed_commit_count` is 0 in Patch 2; "snapshot + replay newer
    /// commits" lands in Patch 3.
    pub fn restore_from_snapshot(
        &mut self,
        snapshot_id: &hydra_core::SnapshotId,
        restored_by: hydra_core::ActorId,
    ) -> hydra_core::error::Result<hydra_core::SnapshotManifest> {
        let body = self.snapshot_store.require_body(snapshot_id)?.clone();
        let manifest = body.manifest.clone();
        self.reset_runtime_state_preserving_config();
        self.recover_from_events(body.events.clone())?;
        // Re-insert is a no-op when reset_runtime_state_preserving_config
        // doesn't touch the snapshot store, but keeps the intent explicit
        // and protects against future reset behavior changes.
        self.snapshot_store.insert(body);
        // restored_by is captured for future audit metadata; the current
        // SnapshotRestored event variant doesn't yet carry an actor field.
        let _ = restored_by;
        // V2 polish #5 — restore is a follower-legitimate path; bypass
        // the role guard for the audit commit (see
        // `ingest_event_internal_unguarded`).
        self.ingest_event_internal_unguarded(
            Event::trigger(hydra_core::EventKind::SnapshotRestored {
                manifest: manifest.clone(),
                replayed_commit_count: 0,
            }),
            None,
        )?;
        Ok(manifest)
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

    /// Attach a live commit observer.
    ///
    /// The observer is called on every committed batch AFTER the
    /// durable writer (if any) succeeds. Observer failures cannot
    /// affect commit success — the trait returns `()`. The argument
    /// is an `Arc` so the same observer can be shared with HTTP
    /// state, metrics sinks, or other components that also need to
    /// react to commits.
    pub fn set_commit_observer(
        &mut self,
        observer: std::sync::Arc<dyn crate::commit_ledger::CommitObserver>,
    ) {
        self.commit_observer = Some(observer);
    }

    /// Detach the live commit observer. The durable writer (if any)
    /// is untouched.
    pub fn clear_commit_observer(&mut self) {
        self.commit_observer = None;
    }

    pub fn has_commit_observer(&self) -> bool {
        self.commit_observer.is_some()
    }
}

impl Default for Hydra {
    fn default() -> Self {
        Self::new()
    }
}

// === MicroModel Patch 3 — prediction → evidence + claim builders ===

/// Build the `Evidence` record paired with a Warning/Critical
/// commit-rate prediction. Pure function — no engine access; the
/// caller passes everything in. Used by the bridge in
/// `Hydra::evaluate_commit_rate_anomaly_and_propose_claim` and
/// kept module-private since the shape is part of Patch 3's
/// internal contract.
fn build_evidence_from_prediction(
    prediction: &hydra_core::MicroModelPrediction,
    output: &crate::micromodels::CommitRateAnomalyOutput,
    prediction_event_id: hydra_core::EventId,
) -> hydra_core::Evidence {
    use hydra_core::epistemic::{Confidence, EvidencePayload, EvidenceSource};

    let mut data: std::collections::HashMap<String, hydra_core::Value> =
        std::collections::HashMap::new();
    data.insert(
        "model_id".to_string(),
        hydra_core::Value::String(prediction.model_id.as_str().to_string()),
    );
    data.insert(
        "run_id".to_string(),
        hydra_core::Value::String(prediction.run_id.as_str().to_string()),
    );
    data.insert(
        "level".to_string(),
        hydra_core::Value::String(output.level.wire_name().to_string()),
    );
    data.insert(
        "direction".to_string(),
        hydra_core::Value::String(output.direction.wire_name().to_string()),
    );
    data.insert(
        "observed_rate".to_string(),
        hydra_core::Value::Float(output.observed_rate),
    );
    data.insert(
        "expected_rate".to_string(),
        hydra_core::Value::Float(output.expected_rate),
    );
    data.insert(
        "z_score".to_string(),
        hydra_core::Value::Float(output.z_score),
    );
    data.insert(
        "reason".to_string(),
        hydra_core::Value::String(output.reason.clone()),
    );

    hydra_core::Evidence {
        id: hydra_core::EvidenceId::new(),
        // Tenant scoping mirrors Patch 2's prediction event — None
        // in v0; future patches can thread tenant through the
        // bridge if needed.
        tenant_id: None,
        // Use the model id (not a friendly name) as the source
        // identifier so evidence joins cleanly back to the registry
        // entry for `mm_builtin_commit_rate_v0`.
        source: EvidenceSource::System {
            name: prediction.model_id.as_str().to_string(),
        },
        payload: EvidencePayload {
            kind: "micro_model_prediction".to_string(),
            data,
        },
        reliability: Confidence::new(prediction.confidence),
        observed_at: prediction.created_at,
        recorded_at: prediction.created_at,
        caused_by: Some(prediction_event_id),
    }
}

/// Build the `Claim` paired with the Evidence above. Same purity
/// contract — no engine access. The Patch 3 spec pins this shape:
///
///   subject       = ClaimSubject::System("hydra")
///   predicate     = "under_abnormal_load"
///   object        = ClaimObject::Value(Value::Bool(true))
///   kind          = AnomalyFinding
///   evidence_for  = [evidence_id]
///   caused_by     = prediction_event_id
fn build_claim_from_prediction(
    prediction: &hydra_core::MicroModelPrediction,
    evidence_id: &hydra_core::EvidenceId,
    actor: hydra_core::ActorId,
    prediction_event_id: hydra_core::EventId,
) -> hydra_core::Claim {
    use hydra_core::epistemic::{
        ClaimKind, ClaimObject, ClaimStatus, ClaimSubject, Confidence,
    };

    hydra_core::Claim {
        id: hydra_core::ClaimId::new(),
        tenant_id: None,
        kind: ClaimKind::AnomalyFinding,
        subject: ClaimSubject::System("hydra".to_string()),
        predicate: "under_abnormal_load".to_string(),
        object: ClaimObject::Value(hydra_core::Value::Bool(true)),
        confidence: Confidence::new(prediction.confidence),
        status: ClaimStatus::Proposed,
        evidence_for: vec![evidence_id.clone()],
        evidence_against: vec![],
        valid_from: prediction.created_at,
        valid_until: None,
        created_by: actor,
        created_at: prediction.created_at,
        updated_at: prediction.created_at,
        caused_by: Some(prediction_event_id),
    }
}

/// Build the `Action` paired with a Warning/Critical claim.
/// Returns an `ActionKind::Notify` targeting `System("hydra")`,
/// with the claim + evidence referenced and the model context in
/// the payload. Pure constructor — no engine access; callers pass
/// every input.
///
/// The Patch 4 spec pins this shape (see
/// `evaluate_commit_rate_anomaly_and_propose_action` docstring).
fn build_action_from_assessment(
    assessment: &crate::micromodels::CommitRateAnomalyAssessment,
    claim_id: hydra_core::ClaimId,
    evidence_id: hydra_core::EvidenceId,
    claim_event_id: hydra_core::EventId,
    actor: hydra_core::ActorId,
) -> hydra_core::Action {
    use hydra_core::action::{ActionKind, ActionStatus, ActionTarget};

    let prediction = &assessment.prediction;
    let mut payload: std::collections::HashMap<String, hydra_core::Value> =
        std::collections::HashMap::new();
    // Severity = the level's wire name. WarmingUp / Normal don't
    // reach this builder (gated upstream), so the only values that
    // ever land here are "warning" or "critical".
    payload.insert(
        "severity".to_string(),
        hydra_core::Value::String(assessment.level.wire_name().to_string()),
    );
    // Reason mirrors the prediction's `explanation` (set by the
    // model's `render_reason`). One pithy line operators can drop
    // straight into a ticket title.
    payload.insert(
        "reason".to_string(),
        hydra_core::Value::String(
            prediction
                .explanation
                .clone()
                .unwrap_or_default(),
        ),
    );
    payload.insert(
        "model_id".to_string(),
        hydra_core::Value::String(prediction.model_id.as_str().to_string()),
    );
    payload.insert(
        "run_id".to_string(),
        hydra_core::Value::String(prediction.run_id.as_str().to_string()),
    );

    hydra_core::Action {
        id: hydra_core::ActionId::new(),
        // Matches Patches 2 + 3 — multi-tenant action surface is a
        // future patch.
        tenant_id: None,
        // Use the existing ActionKind::Notify vocabulary so any
        // agent that already pattern-matches on `Notify` sees this
        // without a code change. The "operator notification" intent
        // is encoded in the payload's `severity` + `reason`.
        kind: ActionKind::Notify,
        // Patch 4 ships proposals only. Execution is a future
        // patch (Patch 5+).
        status: ActionStatus::Proposed,
        targets: vec![ActionTarget::System("hydra".to_string())],
        related_claims: vec![claim_id],
        supporting_evidence: vec![evidence_id],
        proposed_by: actor,
        approved_by: None,
        // No policy DSL in v0. The gate that fires this action is
        // inline in `evaluate_commit_rate_anomaly_and_propose_action`,
        // not a registered Policy record.
        policy_id: None,
        payload,
        created_at: prediction.created_at,
        updated_at: prediction.created_at,
        approved_at: None,
        executed_at: None,
        // The load-bearing causal link of Patch 4: action points
        // back at the claim event, which already points back at
        // the prediction event. Lineage walks the chain.
        caused_by: Some(claim_event_id),
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

    // === CommitObserver — live fan-out for committed batches ===

    #[test]
    fn commit_observer_fires_on_each_ingest() {
        use crate::commit_ledger::CommitObserver;
        use std::sync::{Arc, Mutex};

        #[derive(Debug, Default)]
        struct CountingObserver {
            count: Mutex<usize>,
            last_seq: Mutex<Option<u64>>,
        }

        impl CommitObserver for CountingObserver {
            fn observe_commit(&self, batch: &hydra_core::CommitBatch) {
                *self.count.lock().unwrap() += 1;
                *self.last_seq.lock().unwrap() = Some(batch.sequence);
            }
        }

        let observer = Arc::new(CountingObserver::default());
        let mut hydra = Hydra::new();
        hydra.set_commit_observer(observer.clone() as Arc<dyn CommitObserver>);
        assert!(hydra.has_commit_observer());

        // Three independent ingests → three observer fires, three
        // distinct sequences.
        for i in 0..3 {
            hydra
                .ingest(hydra_core::EventKind::Signal {
                    source: hydra_core::id::NodeId::from_str("test.observer"),
                    name: format!("tick-{i}"),
                    payload: HashMap::new(),
                })
                .unwrap();
        }

        assert_eq!(*observer.count.lock().unwrap(), 3);
        // Sequences are 1-indexed and monotonic.
        assert_eq!(*observer.last_seq.lock().unwrap(), Some(3));
    }

    #[test]
    fn commit_observer_clears_correctly() {
        use crate::commit_ledger::CommitObserver;
        use std::sync::{Arc, Mutex};

        #[derive(Debug, Default)]
        struct CountingObserver(Mutex<usize>);
        impl CommitObserver for CountingObserver {
            fn observe_commit(&self, _batch: &hydra_core::CommitBatch) {
                *self.0.lock().unwrap() += 1;
            }
        }

        let observer = Arc::new(CountingObserver::default());
        let mut hydra = Hydra::new();
        hydra.set_commit_observer(observer.clone() as Arc<dyn CommitObserver>);

        hydra
            .ingest(hydra_core::EventKind::Signal {
                source: hydra_core::id::NodeId::from_str("test.clear"),
                name: "before".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();
        assert_eq!(*observer.0.lock().unwrap(), 1);

        // After clear the observer must no longer fire — even though
        // the Arc still has a clone outstanding, the engine drops
        // its reference and never calls observe_commit again.
        hydra.clear_commit_observer();
        assert!(!hydra.has_commit_observer());

        hydra
            .ingest(hydra_core::EventKind::Signal {
                source: hydra_core::id::NodeId::from_str("test.clear"),
                name: "after".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();
        // Count is unchanged.
        assert_eq!(*observer.0.lock().unwrap(), 1);
    }

    // === MicroModel Patch 1 — registry + audit only ===

    fn micromodel_actor() -> hydra_core::ActorId {
        hydra_core::ActorId::from_str("actor_hydra_micromodel_test")
    }

    fn lag_anomaly_definition() -> hydra_core::MicroModelDefinition {
        hydra_core::MicroModelDefinition::registered(
            hydra_core::MicroModelId::from_str("mm_lag_v0"),
            hydra_core::MicroModelKind::ReplicationLagAnomaly,
            "lag_anomaly_v0",
            1,
            vec![hydra_core::FieldSchema::required(
                "recent_lag_commits",
                hydra_core::ValueType::List(Box::new(hydra_core::ValueType::Int)),
            )],
            vec![hydra_core::FieldSchema::required(
                "is_anomalous",
                hydra_core::ValueType::Bool,
            )],
            micromodel_actor(),
            chrono::Utc::now(),
        )
    }

    #[test]
    fn hydra_registers_micro_model() {
        let mut hydra = Hydra::new();
        let def = lag_anomaly_definition();
        let id = hydra.register_micro_model(def.clone()).unwrap();
        // Round trip through the store.
        assert_eq!(hydra.micro_model(&id), Some(&def));
        // Indexed by kind too.
        let by_kind =
            hydra.micro_models_by_kind(&hydra_core::MicroModelKind::ReplicationLagAnomaly);
        assert_eq!(by_kind.len(), 1);
        assert_eq!(by_kind[0].id, id);
        // The event landed in the audit log.
        let kinds: Vec<_> = hydra
            .events()
            .iter()
            .map(|e| e.kind.kind_name())
            .collect();
        assert!(kinds.contains(&"micro_model_registered"));
    }

    #[test]
    fn hydra_records_prediction_and_observation() {
        let mut hydra = Hydra::new();
        let id = hydra.register_micro_model(lag_anomaly_definition()).unwrap();
        let run_id = hydra_core::MicroModelRunId::from_str("mmrun_hydra_001");

        // One prediction.
        let prediction = hydra_core::MicroModelPrediction {
            model_id: id,
            run_id: run_id.clone(),
            input: serde_json::json!({"recent_lag_commits": [10, 12, 11]}),
            output: serde_json::json!({"is_anomalous": false}),
            confidence: 0.88,
            explanation: Some("flat trend".to_string()),
            created_at: chrono::Utc::now(),
        };
        hydra
            .record_micro_model_prediction(prediction.clone())
            .unwrap();
        assert_eq!(hydra.micro_model_prediction(&run_id), Some(&prediction));
        // Observation matched by run_id.
        assert!(hydra.micro_model_observation(&run_id).is_none());
        let observation = hydra_core::MicroModelObservation {
            run_id: run_id.clone(),
            observed_outcome: serde_json::json!({"is_anomalous": false}),
            error: Some(0.0),
            observed_at: chrono::Utc::now(),
        };
        hydra
            .record_micro_model_observation(observation.clone())
            .unwrap();
        assert_eq!(hydra.micro_model_observation(&run_id), Some(&observation));
    }

    #[test]
    fn hydra_status_change_updates_store() {
        let mut hydra = Hydra::new();
        let id = hydra.register_micro_model(lag_anomaly_definition()).unwrap();
        assert_eq!(
            hydra.micro_model(&id).unwrap().status,
            hydra_core::MicroModelStatus::Registered
        );
        hydra
            .change_micro_model_status(
                id.clone(),
                hydra_core::MicroModelStatus::Active,
                Some("promote after smoke test".to_string()),
            )
            .unwrap();
        assert_eq!(
            hydra.micro_model(&id).unwrap().status,
            hydra_core::MicroModelStatus::Active
        );
    }

    #[test]
    fn hydra_snapshot_restore_preserves_micro_models() {
        let mut hydra = Hydra::new();
        let id = hydra.register_micro_model(lag_anomaly_definition()).unwrap();
        let run_id = hydra_core::MicroModelRunId::from_str("mmrun_hydra_restore");
        hydra
            .record_micro_model_prediction(hydra_core::MicroModelPrediction {
                model_id: id.clone(),
                run_id: run_id.clone(),
                input: serde_json::json!({}),
                output: serde_json::json!({"is_anomalous": true}),
                confidence: 0.93,
                explanation: None,
                created_at: chrono::Utc::now(),
            })
            .unwrap();
        hydra
            .record_micro_model_observation(hydra_core::MicroModelObservation {
                run_id: run_id.clone(),
                observed_outcome: serde_json::json!({"is_anomalous": true}),
                error: Some(0.0),
                observed_at: chrono::Utc::now(),
            })
            .unwrap();

        // Snapshot.
        let manifest = hydra.snapshot(micromodel_actor()).unwrap();
        assert_eq!(manifest.total_micro_models, 1);
        assert_eq!(manifest.total_micro_model_predictions, 1);
        assert_eq!(manifest.total_micro_model_observations, 1);

        // Pull the snapshot body out and restore into a FRESH hydra
        // via the body-and-replay path. The store must rehydrate
        // from event replay alone.
        let body = hydra
            .snapshot_body(&manifest.id)
            .expect("snapshot body present")
            .clone();
        let mut restored = Hydra::new();
        restored
            .recover_from_snapshot_body_and_replay(body, vec![], micromodel_actor())
            .unwrap();

        // Model survives.
        assert!(restored.micro_model(&id).is_some());
        // Prediction + observation join by run_id.
        assert!(restored.micro_model_prediction(&run_id).is_some());
        assert!(restored.micro_model_observation(&run_id).is_some());
        // And the kind index works after restore.
        assert_eq!(
            restored
                .micro_models_by_kind(&hydra_core::MicroModelKind::ReplicationLagAnomaly)
                .len(),
            1
        );
    }

    // === MicroModel Patch 2 — built-in CommitRateAnomalyModel ===

    fn requester() -> hydra_core::ActorId {
        hydra_core::ActorId::from_str("actor_test_commit_rate_caller")
    }

    fn count_prediction_events(hydra: &Hydra) -> usize {
        hydra
            .events()
            .iter()
            .filter(|e| matches!(e.kind, hydra_core::EventKind::MicroModelPredictionRecorded { .. }))
            .count()
    }

    #[test]
    fn hydra_evaluate_commit_rate_anomaly_auto_registers_builtin() {
        // First call on a fresh engine should auto-register the
        // built-in model definition under the stable id and
        // promote it to Active in one call.
        let mut hydra = Hydra::new();
        let model_id = hydra_core::MicroModelId::from_str(BUILTIN_COMMIT_RATE_MODEL_ID);
        assert!(hydra.micro_model(&model_id).is_none());

        let _ = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();

        let registered = hydra.micro_model(&model_id).expect("registered");
        assert_eq!(registered.kind, hydra_core::MicroModelKind::CommitRatePredictor);
        // Auto-registration promotes to Active immediately so the
        // model is usable for subsequent evaluations.
        assert_eq!(registered.status, hydra_core::MicroModelStatus::Active);
        assert_eq!(registered.version, 1);
        assert_eq!(
            registered.created_by,
            hydra_core::ActorId::from_str(BUILTIN_COMMIT_RATE_ACTOR_ID)
        );
    }

    #[test]
    fn hydra_evaluate_idempotent_register() {
        // Two evaluations must NOT register two model definitions.
        // Re-registration would overwrite metadata and reset the
        // status; the auto-register path must be gated on first-use.
        let mut hydra = Hydra::new();
        let model_id = hydra_core::MicroModelId::from_str(BUILTIN_COMMIT_RATE_MODEL_ID);
        let _ = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        let after_first = hydra.micro_model(&model_id).unwrap().clone();

        let _ = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        let after_second = hydra.micro_model(&model_id).unwrap();

        // Identity (id, kind, created_at, version) is unchanged.
        assert_eq!(after_first.id, after_second.id);
        assert_eq!(after_first.version, after_second.version);
        assert_eq!(after_first.created_at, after_second.created_at);
        // Exactly one registered model under this kind.
        assert_eq!(
            hydra
                .micro_models_by_kind(&hydra_core::MicroModelKind::CommitRatePredictor)
                .len(),
            1
        );
    }

    #[test]
    fn hydra_evaluate_records_prediction_event() {
        // The prediction event must land in the audit log so
        // commit-stream subscribers and lineage walkers see it.
        let mut hydra = Hydra::new();
        assert_eq!(count_prediction_events(&hydra), 0);

        let prediction = hydra
            .evaluate_commit_rate_anomaly(requester())
            .unwrap();

        // Exactly one MicroModelPredictionRecorded event was
        // appended.
        assert_eq!(count_prediction_events(&hydra), 1);

        // The stored prediction matches what was returned.
        let stored = hydra
            .micro_model_prediction(&prediction.run_id)
            .expect("prediction is queryable by run_id");
        assert_eq!(stored.model_id, prediction.model_id);
        assert_eq!(stored.confidence, prediction.confidence);
        assert_eq!(stored.output, prediction.output);
    }

    #[test]
    fn hydra_evaluate_run_id_is_unique_per_call() {
        // Each call mints its own run_id so observations can be
        // joined back to the right prediction. The Patch 1 store
        // is keyed by run_id; collisions would silently overwrite.
        let mut hydra = Hydra::new();
        let a = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        let b = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        assert_ne!(a.run_id, b.run_id);
        // Both are queryable independently.
        assert!(hydra.micro_model_prediction(&a.run_id).is_some());
        assert!(hydra.micro_model_prediction(&b.run_id).is_some());
        assert_eq!(count_prediction_events(&hydra), 2);
    }

    #[test]
    fn hydra_evaluate_returns_warming_up_on_fresh_engine() {
        // Cold engine, no prior observations — the model must
        // honestly report WarmingUp rather than fabricating a
        // baseline.
        let mut hydra = Hydra::new();
        let prediction = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();

        let output: crate::micromodels::CommitRateAnomalyOutput =
            serde_json::from_value(prediction.output.clone()).unwrap();
        assert_eq!(output.level, crate::micromodels::AnomalyLevel::WarmingUp);
        assert_eq!(output.direction, crate::micromodels::Direction::Stable);
        assert_eq!(output.z_score, 0.0);

        // Confidence matches the deterministic table.
        assert_eq!(prediction.confidence, 0.50);
    }

    #[test]
    fn hydra_evaluate_input_payload_is_self_describing() {
        // The Patch 2 spec pins the `input` shape — agents and
        // future Patch 3 evidence-builders rely on these keys.
        let mut hydra = Hydra::new();
        let prediction = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        let input = prediction.input.as_object().expect("input is a JSON object");
        for key in [
            "observed_at",
            "window_secs",
            "commit_count_in_window",
            "samples_seen_before_this",
        ] {
            assert!(input.contains_key(key), "missing input key {key}");
        }
        // The first call's input reports samples_seen_before_this=0
        // (no prior observations).
        assert_eq!(input["samples_seen_before_this"], serde_json::json!(0));
        // window_secs defaults to 60.
        assert_eq!(input["window_secs"], serde_json::json!(60));
    }

    #[test]
    fn hydra_reset_runtime_state_clears_commit_rate_model_state() {
        // `reset_runtime_state_preserving_config` is the recovery
        // entry point. The transient model state must be dropped
        // so a recovered engine re-enters WarmingUp rather than
        // carrying stale EWMA history forward.
        let mut hydra = Hydra::new();
        // Run a couple of evaluations to build state.
        let _ = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        let _ = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        assert!(hydra.commit_rate_anomaly_model().is_some());
        assert!(hydra.commit_rate_anomaly_model().unwrap().state().samples_seen >= 1);

        hydra.reset_runtime_state_preserving_config();
        assert!(hydra.commit_rate_anomaly_model().is_none());
    }

    // === MicroModel Patch 3 — prediction → evidence + claim bridge ===

    fn primed_model_with_baseline(
        rate: f64,
        variance: f64,
    ) -> crate::micromodels::CommitRateAnomalyModel {
        // Build a CommitRateAnomalyModel that's already past
        // warmup, so the bridge tests don't have to ingest dozens
        // of priming events before they can observe a Warning or
        // Critical level. The `last_observed_at` is set to "long
        // ago" so the recency check inside evaluate_observation
        // (none in v0) wouldn't fire.
        let config = crate::micromodels::CommitRateAnomalyConfig::default();
        let state = crate::micromodels::CommitRateAnomalyState {
            ewma_rate: rate,
            ewma_variance: variance,
            samples_seen: 10, // past default warmup_samples = 5
            last_observed_at: Some(chrono::Utc::now()),
        };
        crate::micromodels::CommitRateAnomalyModel::with_state(config, state)
    }

    fn ingest_signals(hydra: &mut Hydra, count: u64) {
        for i in 0..count {
            hydra
                .ingest(hydra_core::EventKind::Signal {
                    source: hydra_core::NodeId::from_str("test.bridge"),
                    name: format!("noise-{i}"),
                    payload: std::collections::HashMap::new(),
                })
                .unwrap();
        }
    }

    /// Test fixture: build a Hydra with the built-in model
    /// auto-registered, then OVERWRITE the model state with a
    /// primed baseline at `rate`/`variance`. After this returns,
    /// the ledger holds 3 background commits (Registered,
    /// StatusChanged, the warmup-prediction) and the model is past
    /// warmup with `samples_seen=10`. Tests then ingest a known
    /// number of signals to drive the observed rate into the
    /// target band.
    fn primed_hydra(rate: f64, variance: f64) -> Hydra {
        let mut hydra = Hydra::new();
        // First evaluate forces auto-register so the registry
        // commits don't appear inside the next evaluation's window
        // count "by surprise."
        let _ = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        hydra.commit_rate_anomaly_model =
            Some(primed_model_with_baseline(rate, variance));
        hydra
    }

    /// How many commits already sit in the ledger after
    /// `primed_hydra`. Lets tests target a specific
    /// `commit_count_in_window` deterministically.
    fn ledger_count(hydra: &Hydra) -> u64 {
        hydra.commit_ledger.batches_in_sequence().len() as u64
    }

    fn count_evidence_events(hydra: &Hydra) -> usize {
        hydra
            .events()
            .iter()
            .filter(|e| matches!(e.kind, hydra_core::EventKind::EvidenceAdded { .. }))
            .count()
    }

    fn count_claim_events(hydra: &Hydra) -> usize {
        hydra
            .events()
            .iter()
            .filter(|e| matches!(e.kind, hydra_core::EventKind::ClaimProposed { .. }))
            .count()
    }

    #[test]
    fn normal_prediction_creates_no_evidence_or_claim() {
        // Prime model with rate=10, var=1. Then drive the window
        // count to ~11 (z ≈ 1, Normal). `primed_hydra` already
        // contains 3 background commits; add 8 more signals so the
        // count lands at 11.
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 11u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);

        let pre_evidence = count_evidence_events(&hydra);
        let pre_claim = count_claim_events(&hydra);

        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();

        assert_eq!(assessment.level, crate::micromodels::AnomalyLevel::Normal);
        assert!(assessment.evidence_id.is_none());
        assert!(assessment.claim_id.is_none());
        // No new Evidence or Claim events landed.
        assert_eq!(count_evidence_events(&hydra), pre_evidence);
        assert_eq!(count_claim_events(&hydra), pre_claim);
    }

    #[test]
    fn warming_up_assessment_omits_evidence_and_claim() {
        // No primed model → first call is WarmingUp by design.
        // Bridge must NOT propose evidence or claim against a
        // baseline the model hasn't trusted.
        let mut hydra = Hydra::new();
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();

        assert_eq!(
            assessment.level,
            crate::micromodels::AnomalyLevel::WarmingUp
        );
        assert!(assessment.evidence_id.is_none());
        assert!(assessment.claim_id.is_none());
    }

    #[test]
    fn critical_prediction_creates_evidence_and_claim() {
        // Prime + drive window count to 100. z = (100-10)/1 = 90 →
        // Critical / Spike.
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);

        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();

        assert_eq!(
            assessment.level,
            crate::micromodels::AnomalyLevel::Critical
        );
        assert!(assessment.evidence_id.is_some());
        assert!(assessment.claim_id.is_some());

        // One Evidence + one Claim event landed.
        assert_eq!(count_evidence_events(&hydra), 1);
        assert_eq!(count_claim_events(&hydra), 1);

        // The records are queryable via Hydra accessors.
        let evidence_id = assessment.evidence_id.as_ref().unwrap();
        let claim_id = assessment.claim_id.as_ref().unwrap();
        assert!(hydra.evidence(evidence_id).is_some());
        assert!(hydra.claim(claim_id).is_some());
    }

    #[test]
    fn warning_prediction_creates_evidence_and_claim() {
        // Drive window count to 13. z = (13-10)/1 = 3 → Warning
        // (z >= warning_z_score=3, < critical_z_score=5).
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 13u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);

        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();

        assert_eq!(
            assessment.level,
            crate::micromodels::AnomalyLevel::Warning
        );
        assert!(assessment.evidence_id.is_some());
        assert!(assessment.claim_id.is_some());
    }

    #[test]
    fn evidence_carries_micromodel_payload() {
        // Pin the 8-key Evidence payload shape that Patch 3 promised.
        // Future patches may add fields but must not rename these.
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);

        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();
        let evidence = hydra
            .evidence(assessment.evidence_id.as_ref().unwrap())
            .unwrap();

        // Source is the model id, NOT a friendly name (joins back
        // to the registry).
        match &evidence.source {
            hydra_core::epistemic::EvidenceSource::System { name } => {
                assert_eq!(name, BUILTIN_COMMIT_RATE_MODEL_ID);
            }
            other => panic!("unexpected EvidenceSource variant: {other:?}"),
        }
        // Payload kind is the durable discriminant Patch 4+ will
        // pattern-match on.
        assert_eq!(evidence.payload.kind, "micro_model_prediction");
        // All 8 typed fields present.
        for key in [
            "model_id",
            "run_id",
            "level",
            "direction",
            "observed_rate",
            "expected_rate",
            "z_score",
            "reason",
        ] {
            assert!(
                evidence.payload.data.contains_key(key),
                "missing payload key {key}"
            );
        }
        // Type discipline — floats are Float, strings are String.
        assert!(matches!(
            evidence.payload.data.get("observed_rate"),
            Some(hydra_core::Value::Float(_))
        ));
        assert!(matches!(
            evidence.payload.data.get("level"),
            Some(hydra_core::Value::String(s)) if s == "critical"
        ));
        // Reliability mirrors the prediction confidence.
        assert_eq!(
            evidence.reliability.value(),
            assessment.prediction.confidence
        );
        // Tenant scoping is None in v0.
        assert!(evidence.tenant_id.is_none());
    }

    #[test]
    fn claim_references_evidence_via_evidence_for() {
        // `claim.evidence_for == [evidence_id]` — the structural
        // belief→support edge that lineage walkers traverse.
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);

        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();
        let evidence_id = assessment.evidence_id.clone().unwrap();
        let claim = hydra
            .claim(assessment.claim_id.as_ref().unwrap())
            .unwrap();

        assert_eq!(claim.evidence_for, vec![evidence_id]);
        assert!(claim.evidence_against.is_empty());

        // Pin the rest of the Patch 3 claim shape.
        assert_eq!(claim.kind, hydra_core::epistemic::ClaimKind::AnomalyFinding);
        assert_eq!(
            claim.subject,
            hydra_core::epistemic::ClaimSubject::System("hydra".to_string())
        );
        assert_eq!(claim.predicate, "under_abnormal_load");
        assert_eq!(
            claim.object,
            hydra_core::epistemic::ClaimObject::Value(hydra_core::Value::Bool(true))
        );
        // The bridge proposes the claim as `Proposed`. Hydra's
        // verification agent may auto-promote it to `Verified`
        // within the same cascade once it sees the paired
        // evidence — that promotion is desired engine behavior,
        // not a Patch 3 bug, so accept either status here.
        assert!(matches!(
            claim.status,
            hydra_core::epistemic::ClaimStatus::Proposed
                | hydra_core::epistemic::ClaimStatus::Verified
        ));
        assert_eq!(claim.created_by, requester());
        assert!(claim.tenant_id.is_none());
    }

    #[test]
    fn evidence_and_claim_caused_by_prediction_event() {
        // The most important invariant of Patch 3: both downstream
        // records' `caused_by` point at the prediction event. This
        // is what lets `hy.lineage(prediction_event_id)` traverse
        // forward and surface evidence + claim.
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);

        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();

        let evidence = hydra
            .evidence(assessment.evidence_id.as_ref().unwrap())
            .unwrap();
        let claim = hydra
            .claim(assessment.claim_id.as_ref().unwrap())
            .unwrap();

        assert_eq!(
            evidence.caused_by.as_ref(),
            Some(&assessment.prediction_event_id)
        );
        assert_eq!(
            claim.caused_by.as_ref(),
            Some(&assessment.prediction_event_id)
        );
    }

    #[test]
    fn lineage_from_prediction_event_includes_evidence_and_claim() {
        // The "explain it" pin. The HTTP lineage handler's
        // enrichment scan filters each store by
        // `record.caused_by ∈ events_in_lineage`. We mirror that
        // here at the engine level: scan all evidence + claims and
        // confirm at least one of each points at the prediction
        // event we just produced.
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);

        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();
        let seed_id = &assessment.prediction_event_id;

        // The prediction event must be in the engine's audit log.
        assert!(hydra
            .events()
            .iter()
            .any(|event| &event.id == seed_id
                && matches!(event.kind, hydra_core::EventKind::MicroModelPredictionRecorded { .. })));

        let evidence_for_seed: Vec<_> = hydra
            .epistemic_store()
            .all_evidence()
            .filter(|e| e.caused_by.as_ref() == Some(seed_id))
            .collect();
        assert_eq!(evidence_for_seed.len(), 1);

        let claims_for_seed: Vec<_> = hydra
            .epistemic_store()
            .all_claims()
            .filter(|c| c.caused_by.as_ref() == Some(seed_id))
            .collect();
        assert_eq!(claims_for_seed.len(), 1);
        assert_eq!(claims_for_seed[0].predicate, "under_abnormal_load");
    }

    #[test]
    fn assessment_carries_level_for_callers() {
        // Callers branch on `assessment.level` directly rather than
        // parsing prediction.output JSON. Pin both the actionable
        // and non-actionable paths.
        let mut hydra = Hydra::new();

        // First call: WarmingUp.
        let warming = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();
        assert_eq!(
            warming.level,
            crate::micromodels::AnomalyLevel::WarmingUp
        );
        assert!(!warming.level.is_actionable());

        // Prime + trigger Critical on the same Hydra. WarmingUp
        // already auto-registered, so background = current ledger.
        hydra.commit_rate_anomaly_model = Some(primed_model_with_baseline(10.0, 1.0));
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);
        let critical = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();
        assert_eq!(
            critical.level,
            crate::micromodels::AnomalyLevel::Critical
        );
        assert!(critical.level.is_actionable());
    }

    #[test]
    fn two_critical_calls_produce_two_independent_assessments() {
        // Non-idempotent (matches Patch 2). Each call mints a new
        // prediction event, a new evidence id, and a new claim id.
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);
        let a = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();
        // Re-prime to undo the EWMA shift caused by the first call,
        // so the second call also lands in Critical.
        hydra.commit_rate_anomaly_model = Some(primed_model_with_baseline(10.0, 1.0));
        let b = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();

        assert_ne!(a.prediction_event_id, b.prediction_event_id);
        assert_ne!(a.prediction.run_id, b.prediction.run_id);
        assert_ne!(a.evidence_id, b.evidence_id);
        assert_ne!(a.claim_id, b.claim_id);
        assert_eq!(a.level, crate::micromodels::AnomalyLevel::Critical);
        assert_eq!(b.level, crate::micromodels::AnomalyLevel::Critical);

        // Audit log records both pairs (2 evidence + 2 claim events).
        assert_eq!(count_evidence_events(&hydra), 2);
        assert_eq!(count_claim_events(&hydra), 2);
    }

    // === MicroModel Patch 4 — Claim-to-Action Reflex ===

    fn count_action_events(hydra: &Hydra) -> usize {
        hydra
            .events()
            .iter()
            .filter(|e| matches!(e.kind, hydra_core::EventKind::ActionProposed { .. }))
            .count()
    }

    #[test]
    fn normal_prediction_creates_no_action() {
        // Drive count to 11 (z=1, Normal). The bridge must:
        // - return level=Normal
        // - leave evidence_id / claim_id / claim_event_id None
        // - return empty action_ids
        // - NOT append any ActionProposed event.
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 11u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);

        let pre_actions = count_action_events(&hydra);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();

        assert_eq!(assessment.level, crate::micromodels::AnomalyLevel::Normal);
        assert!(assessment.evidence_id.is_none());
        assert!(assessment.claim_id.is_none());
        assert!(assessment.claim_event_id.is_none());
        assert!(assessment.action_ids.is_empty());
        assert_eq!(count_action_events(&hydra), pre_actions);
    }

    #[test]
    fn warming_up_creates_no_action() {
        // Cold engine — first call is WarmingUp by design. The bridge
        // must NOT fabricate an action against an untrusted baseline.
        let mut hydra = Hydra::new();
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();

        assert_eq!(
            assessment.level,
            crate::micromodels::AnomalyLevel::WarmingUp
        );
        assert!(assessment.action_ids.is_empty());
        assert!(assessment.claim_event_id.is_none());
    }

    #[test]
    fn warning_claim_does_not_pass_default_gate() {
        // Drive count to 13 (z=3, Warning, confidence=0.75). The
        // verification agent's default `min_claim_confidence = 0.80`
        // means Warning claims STAY at `Proposed` (not auto-promoted
        // to Verified). Combined with the Patch 4 gate
        // (`Verified OR confidence >= 0.9`), Warning predictions do
        // NOT fire actions under the default verification policy.
        //
        // This is a safety property: only high-confidence beliefs
        // (auto-verified Critical, OR Warning with operator-tuned
        // verification policy) trigger operator notifications.
        // Documented here as load-bearing behavior.
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 13u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);

        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();

        assert_eq!(
            assessment.level,
            crate::micromodels::AnomalyLevel::Warning
        );
        // Patch 3 records still land — only the action gate blocks.
        assert!(assessment.evidence_id.is_some());
        assert!(assessment.claim_id.is_some());
        // No action: Warning doesn't pass the default gate.
        assert!(assessment.action_ids.is_empty());
        let claim = hydra.claim(assessment.claim_id.as_ref().unwrap()).unwrap();
        // The epistemic cascade walks the claim through
        // `Proposed → Supported → Verified` as evidence + confidence
        // thresholds are met. Warning's 0.75 confidence is below
        // the verification floor (0.80), so the claim lands at
        // `Supported` — not `Verified`, which is what the Patch 4
        // gate requires for low-confidence claims.
        assert!(matches!(
            claim.status,
            hydra_core::epistemic::ClaimStatus::Proposed
                | hydra_core::epistemic::ClaimStatus::Supported
        ));
        assert!(claim.confidence.value() < 0.9);
    }

    #[test]
    fn critical_claim_proposes_notify_operator() {
        // Drive count to 100 (z=90, Critical). Same Notify action,
        // higher prediction confidence (0.90).
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);

        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();

        assert_eq!(
            assessment.level,
            crate::micromodels::AnomalyLevel::Critical
        );
        assert_eq!(assessment.action_ids.len(), 1);

        let action = hydra.action(&assessment.action_ids[0]).unwrap();
        assert_eq!(action.kind, hydra_core::action::ActionKind::Notify);
        // Action lands as `Proposed` from the bridge but the policy
        // cascade may auto-approve low-risk Notify actions. Accept
        // either Proposed or Approved here — Patch 4's contract is
        // "action proposed", post-propose cascade behavior is the
        // engine's, not Patch 4's.
        assert!(matches!(
            action.status,
            hydra_core::action::ActionStatus::Proposed
                | hydra_core::action::ActionStatus::Approved
        ));
        // The Critical-tier prediction confidence is 0.90, so even a
        // claim that somehow wasn't auto-verified would still pass
        // the confidence-OR-Verified gate.
        assert!(assessment.prediction.confidence >= 0.90);
    }

    #[test]
    fn action_references_claim_and_evidence() {
        // The action carries `related_claims` + `supporting_evidence`
        // pointing back at the same ids the assessment surfaces.
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let action = hydra.action(&assessment.action_ids[0]).unwrap();

        assert_eq!(
            action.related_claims,
            vec![assessment.claim_id.clone().unwrap()]
        );
        assert_eq!(
            action.supporting_evidence,
            vec![assessment.evidence_id.clone().unwrap()]
        );
        assert_eq!(action.proposed_by, requester());
        assert!(action.tenant_id.is_none());
        // NOTE: `approved_by` and `policy_id` may be touched by
        // Hydra's policy/approval cascade after the action lands
        // (auto-approval for low-risk Notify actions, for example).
        // Patch 4's contract is "action proposed"; what the
        // cascade does after is desired engine behavior.
    }

    #[test]
    fn action_caused_by_claim_event() {
        // The load-bearing causal link of Patch 4:
        //   action.caused_by == claim_event_id
        // (not prediction_event_id — that would short-circuit the
        // chain and lose the "belief → action" hop).
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let action = hydra.action(&assessment.action_ids[0]).unwrap();

        assert_eq!(
            action.caused_by.as_ref(),
            assessment.claim_event_id.as_ref()
        );
        assert_ne!(
            action.caused_by.as_ref(),
            Some(&assessment.prediction_event_id)
        );
    }

    #[test]
    fn action_payload_carries_severity_reason_model_run() {
        // Pin the 4-key Notify payload shape Patch 4 promised.
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let action = hydra.action(&assessment.action_ids[0]).unwrap();

        for key in ["severity", "reason", "model_id", "run_id"] {
            assert!(
                action.payload.contains_key(key),
                "missing payload key {key}"
            );
        }
        // Severity matches level.wire_name().
        assert!(matches!(
            action.payload.get("severity"),
            Some(hydra_core::Value::String(s)) if s == "critical"
        ));
        // Reason mirrors the model's `explanation` field.
        let reason_str = match action.payload.get("reason") {
            Some(hydra_core::Value::String(s)) => s.clone(),
            other => panic!("expected reason String, got {other:?}"),
        };
        assert_eq!(Some(reason_str), assessment.prediction.explanation);
        // Model id and run id match the prediction.
        assert!(matches!(
            action.payload.get("model_id"),
            Some(hydra_core::Value::String(s)) if s == BUILTIN_COMMIT_RATE_MODEL_ID
        ));
        assert!(matches!(
            action.payload.get("run_id"),
            Some(hydra_core::Value::String(s)) if s == assessment.prediction.run_id.as_str()
        ));
    }

    #[test]
    fn action_targets_system_hydra() {
        // ActionTarget mirrors ClaimSubject — both are
        // `System("hydra")`. Stable across Patches 3 and 4.
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let action = hydra.action(&assessment.action_ids[0]).unwrap();

        assert_eq!(action.targets.len(), 1);
        assert_eq!(
            action.targets[0],
            hydra_core::action::ActionTarget::System("hydra".to_string())
        );
    }

    #[test]
    fn lineage_from_prediction_event_includes_action() {
        // The "explain the full chain" pin. Walking
        // `caused_by` from the prediction event must surface:
        //   - the EvidenceAdded record (via evidence.caused_by)
        //   - the Claim (via claim.caused_by)
        //   - and ALSO the Action (via action.caused_by →
        //     claim_event_id, which itself is reachable from
        //     the prediction event via the Claim record's
        //     caused_by chain).
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let prediction_event_id = &assessment.prediction_event_id;
        let claim_event_id = assessment.claim_event_id.as_ref().unwrap();

        // Prediction event is in the audit log.
        assert!(hydra
            .events()
            .iter()
            .any(|event| &event.id == prediction_event_id
                && matches!(event.kind, hydra_core::EventKind::MicroModelPredictionRecorded { .. })));

        // ClaimProposed event is in the audit log AND its caused_by
        // points at the prediction event. Bind `events` first so the
        // borrowed iterator outlives the find.
        let events = hydra.events();
        let claim_proposed = events
            .iter()
            .find(|event| &event.id == claim_event_id)
            .expect("claim event present");
        assert!(matches!(
            claim_proposed.kind,
            hydra_core::EventKind::ClaimProposed { .. }
        ));

        // Action records caused_by the CLAIM event (Patch 4
        // invariant).
        let actions_for_claim: Vec<_> = hydra
            .action_store()
            .all_actions()
            .filter(|a| a.caused_by.as_ref() == Some(claim_event_id))
            .collect();
        assert_eq!(actions_for_claim.len(), 1);
        assert_eq!(actions_for_claim[0].id, assessment.action_ids[0]);

        // And by transitive walk: claim.caused_by points to
        // prediction event, so the full chain is reachable from
        // the seed.
        let claim = hydra.claim(assessment.claim_id.as_ref().unwrap()).unwrap();
        assert_eq!(
            claim.caused_by.as_ref(),
            Some(prediction_event_id)
        );
    }

    #[test]
    fn two_critical_calls_produce_two_independent_actions() {
        // Non-idempotent — each call mints a distinct action_id and
        // appends a separate ActionProposed event.
        let mut hydra = primed_hydra(10.0, 1.0);
        let target_count = 100u64;
        let need = target_count - ledger_count(&hydra);
        ingest_signals(&mut hydra, need);

        let a = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        // Re-prime so the second call also lands in Critical.
        hydra.commit_rate_anomaly_model =
            Some(primed_model_with_baseline(10.0, 1.0));
        let b = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();

        assert_eq!(a.action_ids.len(), 1);
        assert_eq!(b.action_ids.len(), 1);
        assert_ne!(a.action_ids[0], b.action_ids[0]);
        assert_ne!(a.claim_event_id, b.claim_event_id);
        assert_ne!(a.prediction_event_id, b.prediction_event_id);

        // Audit log records both action events.
        assert_eq!(count_action_events(&hydra), 2);
    }

    // === MicroModel Patch 6 — operator approval helpers ===

    fn propose_one_test_action(hydra: &mut Hydra) -> hydra_core::ActionId {
        // Drive a Critical assessment so the engine cascade
        // produces an ActionProposed event we can approve/reject.
        // primed_hydra primes the model past warmup; ingesting 97
        // signals on top of the existing ledger pushes the count
        // into Critical territory.
        *hydra = primed_hydra(10.0, 1.0);
        let target = 100u64;
        let need = target - ledger_count(hydra);
        ingest_signals(hydra, need);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        assessment.action_ids.into_iter().next().expect("critical produced an action")
    }

    #[test]
    fn approve_action_flips_status_and_records_reason() {
        let mut hydra = Hydra::new();
        let action_id = propose_one_test_action(&mut hydra);
        // The Critical cascade auto-approves the Notify action via
        // the policy agent — so the action may already be Approved
        // before the operator's explicit approve. That's fine: the
        // operator approval is still recorded in the audit log and
        // the post-cascade state remains Approved.
        let approver = hydra_core::ActorId::from_str("actor_oncall_alice");
        let approved = hydra
            .approve_action(
                action_id.clone(),
                approver.clone(),
                Some("confirmed by alice".to_string()),
            )
            .unwrap();

        assert_eq!(approved.id, action_id);
        assert_eq!(approved.status, hydra_core::action::ActionStatus::Approved);
        assert_eq!(approved.approved_by, Some(approver));
        assert!(approved.approved_at.is_some());

        // The ActionApproved event is in the audit log with the
        // operator-supplied reason.
        let found = hydra.events().iter().any(|event| {
            matches!(
                &event.kind,
                hydra_core::EventKind::ActionApproved { reason: Some(r), .. }
                if r == "confirmed by alice"
            )
        });
        assert!(found, "explicit ActionApproved with operator reason missing");
    }

    #[test]
    fn reject_action_flips_status_to_rejected() {
        let mut hydra = Hydra::new();
        let action_id = propose_one_test_action(&mut hydra);
        let rejecter = hydra_core::ActorId::from_str("actor_oncall_alice");
        let rejected = hydra
            .reject_action(
                action_id.clone(),
                rejecter.clone(),
                "false alarm — planned maintenance".to_string(),
            )
            .unwrap();

        assert_eq!(rejected.id, action_id);
        assert_eq!(
            rejected.status,
            hydra_core::action::ActionStatus::Rejected
        );

        // The ActionRejected event carries the rejecter + reason.
        let found = hydra.events().iter().any(|event| {
            matches!(
                &event.kind,
                hydra_core::EventKind::ActionRejected { rejected_by, reason, .. }
                if rejected_by == &rejecter && reason == "false alarm — planned maintenance"
            )
        });
        assert!(found);
    }

    #[test]
    fn approve_unknown_action_returns_query_error() {
        let mut hydra = Hydra::new();
        let result = hydra.approve_action(
            hydra_core::ActionId::from_str("act_does_not_exist"),
            hydra_core::ActorId::from_str("actor_test"),
            None,
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("unknown action"));
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
        // No spurious event lands in the audit log.
        let count = hydra
            .events()
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    hydra_core::EventKind::ActionApproved { .. }
                )
            })
            .count();
        assert_eq!(count, 0);
    }

    #[test]
    fn reject_unknown_action_returns_query_error() {
        let mut hydra = Hydra::new();
        let result = hydra.reject_action(
            hydra_core::ActionId::from_str("act_does_not_exist"),
            hydra_core::ActorId::from_str("actor_test"),
            "ghost".to_string(),
        );
        assert!(matches!(
            result,
            Err(hydra_core::error::HydraError::QueryError(_))
        ));
    }

    #[test]
    fn approve_action_is_idempotent_no_state_machine_enforcement() {
        // v0 explicitly does NOT enforce terminal states. An
        // already-Approved action can be approved again (a second
        // approver overrides the first, audit captures both
        // events). Documented as a Patch 6 limitation.
        let mut hydra = Hydra::new();
        let action_id = propose_one_test_action(&mut hydra);
        let _ = hydra
            .approve_action(
                action_id.clone(),
                hydra_core::ActorId::from_str("actor_first"),
                None,
            )
            .unwrap();
        let second = hydra
            .approve_action(
                action_id.clone(),
                hydra_core::ActorId::from_str("actor_second"),
                None,
            )
            .unwrap();
        // Status still Approved. Approver is now the second one.
        assert_eq!(
            second.status,
            hydra_core::action::ActionStatus::Approved
        );
        assert_eq!(
            second.approved_by,
            Some(hydra_core::ActorId::from_str("actor_second"))
        );
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
                reason: None,
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
    fn hydra_records_sensor_observation_and_checkpoint() {
        use hydra_core::{
            EventKind, IdempotencyKey, NodeId, SensorCheckpointStatus, SensorId, SourceCursor,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let sensor_id = SensorId::from_str("sensor_bank_feed");
        let cursor = SourceCursor::Offset {
            stream: "bank.transactions".to_string(),
            partition: Some("acct-9001".to_string()),
            offset: "42".to_string(),
        };
        let key = IdempotencyKey::new(cursor.stable_key_material());

        let checkpoint = hydra
            .record_sensor_observation(
                sensor_id.clone(),
                "bank",
                cursor.clone(),
                EventKind::Signal {
                    source: NodeId::from_str("bank.feed"),
                    name: "bank_transaction_observed".to_string(),
                    payload: HashMap::new(),
                },
            )
            .unwrap();

        assert_eq!(checkpoint.sensor_id, sensor_id);
        assert_eq!(checkpoint.cursor, cursor);
        assert_eq!(checkpoint.idempotency_key, key);
        assert_eq!(checkpoint.status, SensorCheckpointStatus::Recorded);
        assert!(checkpoint.event_id.is_some());

        // Commit 1 = business event. Commit 2 = checkpoint event.
        assert_eq!(hydra.commit_count(), 2);
        assert!(hydra.commit_ledger().batch(&checkpoint.commit_id).is_some());
        assert_eq!(
            hydra
                .checkpoint_for_idempotency_key(&checkpoint.idempotency_key)
                .unwrap()
                .id,
            checkpoint.id
        );
        assert_eq!(
            hydra.checkpoint_for_cursor(&checkpoint.cursor).unwrap().id,
            checkpoint.id
        );
        assert_eq!(
            hydra
                .latest_sensor_checkpoint(&checkpoint.sensor_id, "bank.transactions")
                .unwrap()
                .id,
            checkpoint.id
        );
        hydra.verify_commit_chain().unwrap();
    }

    #[test]
    fn hydra_record_sensor_observation_is_idempotent() {
        use hydra_core::{EventKind, NodeId, SensorId, SourceCursor};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let sensor_id = SensorId::from_str("sensor_bank_feed");
        let cursor = SourceCursor::DeliveryId {
            source: "stripe".to_string(),
            delivery_id: "evt_123".to_string(),
        };

        let first = hydra
            .record_sensor_observation(
                sensor_id.clone(),
                "stripe",
                cursor.clone(),
                EventKind::Signal {
                    source: NodeId::from_str("stripe.webhook"),
                    name: "stripe_event_observed".to_string(),
                    payload: HashMap::new(),
                },
            )
            .unwrap();
        let commit_count_after_first = hydra.commit_count();
        let event_count_after_first = hydra.total_events();

        let second = hydra
            .record_sensor_observation(
                sensor_id,
                "stripe",
                cursor,
                EventKind::Signal {
                    source: NodeId::from_str("stripe.webhook"),
                    name: "duplicate_should_not_run".to_string(),
                    payload: HashMap::new(),
                },
            )
            .unwrap();

        assert_eq!(second.id, first.id);
        assert_eq!(hydra.commit_count(), commit_count_after_first);
        assert_eq!(hydra.total_events(), event_count_after_first);
        hydra.verify_commit_chain().unwrap();
    }

    #[test]
    fn hydra_records_sensor_observation_for_run() {
        use hydra_core::{
            EventKind, NodeId, SensorId, SensorRun, SensorRunId, SensorRunStatus, SourceCursor,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let sensor_id = SensorId::from_str("sensor_github");
        let run_id = SensorRunId::new();
        let run = SensorRun {
            id: run_id.clone(),
            tenant_id: None,
            sensor_id: sensor_id.clone(),
            status: SensorRunStatus::Started,
            source_system: "github".to_string(),
            stream: Some("webhooks".to_string()),
            started_at: now,
            completed_at: None,
            failed_at: None,
            error: None,
            actor_id: None,
            metadata: HashMap::new(),
        };
        hydra.ingest(EventKind::SensorRunStarted { run }).unwrap();

        let checkpoint = hydra
            .record_sensor_observation_for_run(
                Some(run_id.clone()),
                sensor_id,
                "github",
                SourceCursor::DeliveryId {
                    source: "github".to_string(),
                    delivery_id: "delivery-1".to_string(),
                },
                EventKind::Signal {
                    source: NodeId::from_str("github.webhook"),
                    name: "github_delivery_observed".to_string(),
                    payload: HashMap::new(),
                },
            )
            .unwrap();

        assert_eq!(checkpoint.run_id, Some(run_id.clone()));
        assert_eq!(
            hydra.sensor_run(&run_id).unwrap().status,
            SensorRunStatus::Started
        );
        hydra.verify_commit_chain().unwrap();
    }

    #[test]
    fn hydra_sensor_observation_helper_writes_to_commit_writer() {
        use hydra_core::{EventKind, NodeId, SensorId, SourceCursor};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let writer = TestCommitWriter::new();
        let commits = writer.commits();
        hydra.set_commit_writer(writer);

        hydra
            .record_sensor_observation(
                SensorId::from_str("sensor_writer"),
                "test",
                SourceCursor::Custom {
                    source: "test".to_string(),
                    value: "cursor-1".to_string(),
                },
                EventKind::Signal {
                    source: NodeId::from_str("test.sensor"),
                    name: "observation".to_string(),
                    payload: HashMap::new(),
                },
            )
            .unwrap();

        // One commit for business event, one commit for SensorCheckpointRecorded.
        assert_eq!(hydra.commit_count(), 2);
        assert_eq!(commits.lock().unwrap().len(), 2);
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

    #[test]
    fn hydra_materializes_schema_registry_state() {
        use hydra_core::{
            ActorId, EntityTypeSchema, EventKind, EvidencePayloadSchema, FieldSchema,
            SchemaDefinition, SchemaId, SchemaStatus, TypeId, ValueType,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = ActorId::from_str("actor_schema_admin");
        let type_id = TypeId::from_str("type_dataset");
        let entity = SchemaDefinition::EntityType(EntityTypeSchema {
            id: SchemaId::new(),
            tenant_id: None,
            type_id: type_id.clone(),
            name: "Dataset".to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("name", ValueType::String)],
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        });
        let entity_schema_id = entity.id().clone();

        let evidence = SchemaDefinition::EvidencePayload(EvidencePayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            kind: "bank_transaction".to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("amount", ValueType::Float)],
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        });
        let evidence_schema_id = evidence.id().clone();

        hydra
            .ingest(EventKind::SchemaRegistered { schema: entity })
            .unwrap();
        hydra
            .ingest(EventKind::SchemaRegistered { schema: evidence })
            .unwrap();

        assert_eq!(hydra.schema_registry_store().schema_count(), 2);
        assert_eq!(hydra.active_schemas().len(), 2);
        assert_eq!(
            hydra.entity_schema(&type_id).unwrap().name,
            "Dataset"
        );
        assert!(hydra.evidence_schema("bank_transaction").is_some());

        hydra
            .ingest(EventKind::SchemaDisabled {
                schema_id: evidence_schema_id.clone(),
                disabled_by: actor.clone(),
                reason: Some("deprecated".to_string()),
            })
            .unwrap();

        assert_eq!(hydra.active_schemas().len(), 1);
        assert_eq!(hydra.disabled_schemas().len(), 1);
        assert_eq!(
            hydra.schema(&evidence_schema_id).unwrap().status(),
            &SchemaStatus::Disabled
        );

        hydra
            .ingest(EventKind::SchemaArchived {
                schema_id: entity_schema_id.clone(),
                archived_by: actor,
                reason: None,
            })
            .unwrap();

        assert_eq!(hydra.active_schemas().len(), 0);
        assert_eq!(hydra.archived_schemas().len(), 1);
        assert_eq!(
            hydra.schema(&entity_schema_id).unwrap().status(),
            &SchemaStatus::Archived
        );
    }

    #[test]
    fn hydra_recovers_schema_registry_state_from_commits() {
        use hydra_core::{
            ActionPayloadSchema, ActorId, ClaimPredicateSchema, EntityTypeSchema, EventKind,
            EvidencePayloadSchema, FieldSchema, PolicyConditionSchema, SchemaDefinition, SchemaId,
            SchemaStatus, TypeId, ValueType,
        };
        use std::collections::HashMap;

        let mut original = Hydra::new();
        let now = chrono::Utc::now();
        let actor = ActorId::from_str("actor_recovery_schema");
        let type_id = TypeId::from_str("type_invoice");

        let entity = SchemaDefinition::EntityType(EntityTypeSchema {
            id: SchemaId::new(),
            tenant_id: None,
            type_id: type_id.clone(),
            name: "Invoice".to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("amount", ValueType::Float)],
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        });
        let evidence = SchemaDefinition::EvidencePayload(EvidencePayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            kind: "bank_transaction".to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("amount", ValueType::Float)],
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        });
        let claim = SchemaDefinition::ClaimPredicate(ClaimPredicateSchema {
            id: SchemaId::new(),
            tenant_id: None,
            predicate: "is_stale".to_string(),
            status: SchemaStatus::Active,
            subject_type: Some(type_id.clone()),
            object_type: ValueType::Bool,
            allowed_claim_kinds: vec!["AnomalyFinding".to_string()],
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        });
        let action = SchemaDefinition::ActionPayload(ActionPayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            action_kind: "Backfill".to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("dataset", ValueType::String)],
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        });
        let policy = SchemaDefinition::PolicyCondition(PolicyConditionSchema {
            id: SchemaId::new(),
            tenant_id: None,
            policy_kind: "AutoApproval".to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("max_amount", ValueType::Float)],
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        });

        let evidence_schema_id = evidence.id().clone();

        original
            .ingest(EventKind::SchemaRegistered { schema: entity })
            .unwrap();
        original
            .ingest(EventKind::SchemaRegistered { schema: evidence })
            .unwrap();
        original
            .ingest(EventKind::SchemaRegistered { schema: claim })
            .unwrap();
        original
            .ingest(EventKind::SchemaRegistered { schema: action })
            .unwrap();
        original
            .ingest(EventKind::SchemaRegistered { schema: policy })
            .unwrap();
        original
            .ingest(EventKind::SchemaDisabled {
                schema_id: evidence_schema_id.clone(),
                disabled_by: actor,
                reason: Some("rotated".to_string()),
            })
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
            recovered.schema_registry_store().schema_count(),
            original.schema_registry_store().schema_count()
        );
        assert_eq!(recovered.active_schemas().len(), 4);
        assert_eq!(recovered.disabled_schemas().len(), 1);
        assert_eq!(
            recovered.entity_schema(&type_id).unwrap().name,
            "Invoice"
        );
        assert_eq!(
            recovered
                .schema(&evidence_schema_id)
                .unwrap()
                .status(),
            &SchemaStatus::Disabled
        );
        assert!(recovered.claim_predicate_schema("is_stale").is_some());
        assert!(recovered.action_payload_schema("Backfill").is_some());
        assert!(recovered.policy_condition_schema("AutoApproval").is_some());
        recovered.verify_commit_chain().unwrap();
    }

    #[test]
    fn hydra_validates_action_payload_against_registered_schema() {
        use hydra_core::{
            Action, ActionId, ActionKind, ActionPayloadSchema, ActionStatus, ActionTarget, ActorId,
            EventKind, FieldSchema, SchemaDefinition, SchemaId, SchemaStatus, Value, ValueType,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let schema = ActionPayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            action_kind: "PostLedgerEntry".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("account", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
            ],
            created_by: ActorId::from_str("actor_schema"),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        hydra
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::ActionPayload(schema),
            })
            .unwrap();

        let mut payload = HashMap::new();
        payload.insert("account".to_string(), Value::String("Cash".to_string()));
        payload.insert("amount".to_string(), Value::Float(100.0));
        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::PostLedgerEntry,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("ledger".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_bookkeeper"),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };

        let report = hydra.validate_action_payload(&action);
        assert!(report.is_valid());
        assert!(report.schema_id.is_some());
    }

    #[test]
    fn hydra_reports_invalid_action_payload() {
        use hydra_core::{
            Action, ActionId, ActionKind, ActionPayloadSchema, ActionStatus, ActionTarget, ActorId,
            EventKind, FieldSchema, SchemaDefinition, SchemaId, SchemaStatus, Value, ValueType,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let schema = ActionPayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            action_kind: "PostLedgerEntry".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("account", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
            ],
            created_by: ActorId::from_str("actor_schema"),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        hydra
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::ActionPayload(schema),
            })
            .unwrap();

        let mut payload = HashMap::new();
        payload.insert("account".to_string(), Value::String("Cash".to_string()));
        payload.insert(
            "amount".to_string(),
            Value::String("not-a-number".to_string()),
        );
        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::PostLedgerEntry,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("ledger".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_bookkeeper"),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };

        let report = hydra.validate_action_payload(&action);
        assert!(report.is_invalid());
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].path, "amount");
    }

    #[test]
    fn hydra_schema_gate_default_off_does_not_block_invalid_action() {
        use hydra_core::{
            Action, ActionId, ActionKind, ActionStatus, ActionTarget, ActorId, EventKind, Value,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let mut payload = HashMap::new();
        payload.insert("amount".to_string(), Value::String("bad".to_string()));
        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::PostLedgerEntry,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("ledger".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_bookkeeper"),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };
        let result = hydra.ingest(EventKind::ActionProposed { action });
        assert!(result.is_ok());
        assert_eq!(hydra.commit_count(), 1);
    }

    #[test]
    fn hydra_schema_gate_strict_rejects_invalid_action_before_commit() {
        use crate::schema_gate::{SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy};
        use hydra_core::{
            Action, ActionId, ActionKind, ActionPayloadSchema, ActionStatus, ActionTarget, ActorId,
            EventKind, FieldSchema, SchemaDefinition, SchemaId, SchemaStatus, Value, ValueType,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let schema = ActionPayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            action_kind: "PostLedgerEntry".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("account", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
            ],
            created_by: ActorId::from_str("actor_schema"),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        hydra
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::ActionPayload(schema),
            })
            .unwrap();
        assert_eq!(hydra.commit_count(), 1);

        hydra.set_schema_gate_config(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        });

        let mut payload = HashMap::new();
        payload.insert("account".to_string(), Value::String("Cash".to_string()));
        payload.insert("amount".to_string(), Value::String("bad".to_string()));
        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::PostLedgerEntry,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("ledger".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_bookkeeper"),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };
        let events_before = hydra.total_events();
        let result = hydra.ingest(EventKind::ActionProposed { action });
        assert!(result.is_err());
        // No new commit, no new event.
        assert_eq!(hydra.commit_count(), 1);
        assert_eq!(hydra.total_events(), events_before);
    }

    #[test]
    fn hydra_schema_gate_strict_allows_valid_action() {
        use crate::schema_gate::{SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy};
        use hydra_core::{
            Action, ActionId, ActionKind, ActionPayloadSchema, ActionStatus, ActionTarget, ActorId,
            EventKind, FieldSchema, SchemaDefinition, SchemaId, SchemaStatus, Value, ValueType,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let schema = ActionPayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            action_kind: "PostLedgerEntry".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("account", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
            ],
            created_by: ActorId::from_str("actor_schema"),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        hydra
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::ActionPayload(schema),
            })
            .unwrap();

        hydra.set_schema_gate_config(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        });

        let mut payload = HashMap::new();
        payload.insert("account".to_string(), Value::String("Cash".to_string()));
        payload.insert("amount".to_string(), Value::Float(100.0));
        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::PostLedgerEntry,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("ledger".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_bookkeeper"),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };
        let result = hydra.ingest(EventKind::ActionProposed { action });
        assert!(result.is_ok());
        assert_eq!(hydra.commit_count(), 2);
    }

    #[test]
    fn hydra_schema_gate_strict_reject_unknown_schema() {
        use crate::schema_gate::{SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy};
        use hydra_core::{
            Action, ActionId, ActionKind, ActionStatus, ActionTarget, ActorId, EventKind,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        hydra.set_schema_gate_config(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Reject,
        });

        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::PostLedgerEntry,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("ledger".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_bookkeeper"),
            approved_by: None,
            policy_id: None,
            payload: HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };
        let result = hydra.ingest(EventKind::ActionProposed { action });
        assert!(result.is_err());
        assert_eq!(hydra.commit_count(), 0);
        assert_eq!(hydra.total_events(), 0);
    }

    fn test_claim(object: hydra_core::ClaimObject) -> hydra_core::Claim {
        let now = chrono::Utc::now();
        hydra_core::Claim {
            id: hydra_core::ClaimId::new(),
            tenant_id: None,
            kind: hydra_core::ClaimKind::AnomalyFinding,
            subject: hydra_core::ClaimSubject::Dataset(
                "analytics.public.revenue_daily".to_string(),
            ),
            predicate: "is_stale".to_string(),
            object,
            confidence: hydra_core::Confidence::default(),
            status: hydra_core::ClaimStatus::Proposed,
            evidence_for: vec![],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: hydra_core::ActorId::from_str("actor_schema_test"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn test_evidence(
        kind: &str,
        data: std::collections::HashMap<String, hydra_core::Value>,
    ) -> hydra_core::Evidence {
        let now = chrono::Utc::now();
        hydra_core::Evidence {
            id: hydra_core::EvidenceId::new(),
            tenant_id: None,
            source: hydra_core::EvidenceSource::System {
                name: "test".to_string(),
            },
            payload: hydra_core::EvidencePayload {
                kind: kind.to_string(),
                data,
            },
            reliability: hydra_core::Confidence::default(),
            observed_at: now,
            recorded_at: now,
            caused_by: None,
        }
    }

    #[test]
    fn hydra_schema_gate_strict_rejects_invalid_evidence_before_commit() {
        use crate::schema_gate::{SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy};
        use hydra_core::{
            ActorId, EventKind, EvidencePayloadSchema, FieldSchema, SchemaDefinition, SchemaId,
            SchemaStatus, Value, ValueType,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let schema = EvidencePayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            kind: "bank_transaction".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("amount", ValueType::Float),
                FieldSchema::required("currency", ValueType::String),
            ],
            created_by: ActorId::from_str("actor_schema"),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        hydra
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::EvidencePayload(schema),
            })
            .unwrap();
        assert_eq!(hydra.commit_count(), 1);

        hydra.set_schema_gate_config(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        });

        let mut payload = HashMap::new();
        payload.insert("amount".to_string(), Value::String("bad".to_string()));
        payload.insert("currency".to_string(), Value::String("USD".to_string()));
        let result = hydra.ingest(EventKind::EvidenceAdded {
            evidence: test_evidence("bank_transaction", payload),
        });
        assert!(result.is_err());
        // Only the schema registration commit exists.
        assert_eq!(hydra.commit_count(), 1);
    }

    #[test]
    fn hydra_schema_gate_strict_allows_valid_evidence() {
        use crate::schema_gate::{SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy};
        use hydra_core::{
            ActorId, EventKind, EvidencePayloadSchema, FieldSchema, SchemaDefinition, SchemaId,
            SchemaStatus, Value, ValueType,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let schema = EvidencePayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            kind: "bank_transaction".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("amount", ValueType::Float),
                FieldSchema::required("currency", ValueType::String),
            ],
            created_by: ActorId::from_str("actor_schema"),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        hydra
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::EvidencePayload(schema),
            })
            .unwrap();

        hydra.set_schema_gate_config(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        });

        let mut payload = HashMap::new();
        payload.insert("amount".to_string(), Value::Float(42.0));
        payload.insert("currency".to_string(), Value::String("USD".to_string()));
        let result = hydra.ingest(EventKind::EvidenceAdded {
            evidence: test_evidence("bank_transaction", payload),
        });
        assert!(result.is_ok());
        assert_eq!(hydra.commit_count(), 2);
    }

    #[test]
    fn hydra_validates_evidence_against_registered_schema() {
        use hydra_core::{
            ActorId, EventKind, EvidencePayloadSchema, FieldSchema, SchemaDefinition, SchemaId,
            SchemaStatus, Value, ValueType,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let schema = EvidencePayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            kind: "bank_transaction".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("amount", ValueType::Float),
                FieldSchema::required("currency", ValueType::String),
            ],
            created_by: ActorId::from_str("actor_schema"),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        hydra
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::EvidencePayload(schema),
            })
            .unwrap();

        let mut payload = HashMap::new();
        payload.insert("amount".to_string(), Value::Float(42.0));
        payload.insert("currency".to_string(), Value::String("USD".to_string()));
        let evidence = test_evidence("bank_transaction", payload);
        let report = hydra.validate_evidence(&evidence);
        assert!(report.is_valid());
        assert!(report.schema_id.is_some());
    }

    #[test]
    fn hydra_schema_gate_strict_rejects_invalid_claim_before_commit() {
        use crate::schema_gate::{SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy};
        use hydra_core::{
            ActorId, ClaimObject, ClaimPredicateSchema, EventKind, SchemaDefinition, SchemaId,
            SchemaStatus, TypeId, Value, ValueType,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let schema = ClaimPredicateSchema {
            id: SchemaId::new(),
            tenant_id: None,
            predicate: "is_stale".to_string(),
            status: SchemaStatus::Active,
            subject_type: Some(TypeId::from_str("type_dataset")),
            object_type: ValueType::Bool,
            allowed_claim_kinds: vec!["AnomalyFinding".to_string()],
            created_by: ActorId::from_str("actor_schema"),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        hydra
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::ClaimPredicate(schema),
            })
            .unwrap();
        assert_eq!(hydra.commit_count(), 1);

        hydra.set_schema_gate_config(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        });

        let result = hydra.ingest(EventKind::ClaimProposed {
            claim: test_claim(ClaimObject::Value(Value::String("yes".to_string()))),
        });
        assert!(result.is_err());
        assert_eq!(hydra.commit_count(), 1);
    }

    #[test]
    fn hydra_schema_gate_strict_allows_valid_claim() {
        use crate::schema_gate::{SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy};
        use hydra_core::{
            ActorId, ClaimObject, ClaimPredicateSchema, EventKind, SchemaDefinition, SchemaId,
            SchemaStatus, TypeId, Value, ValueType,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let schema = ClaimPredicateSchema {
            id: SchemaId::new(),
            tenant_id: None,
            predicate: "is_stale".to_string(),
            status: SchemaStatus::Active,
            subject_type: Some(TypeId::from_str("type_dataset")),
            object_type: ValueType::Bool,
            allowed_claim_kinds: vec!["AnomalyFinding".to_string()],
            created_by: ActorId::from_str("actor_schema"),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        hydra
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::ClaimPredicate(schema),
            })
            .unwrap();

        hydra.set_schema_gate_config(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        });

        let result = hydra.ingest(EventKind::ClaimProposed {
            claim: test_claim(ClaimObject::Value(Value::Bool(true))),
        });
        assert!(result.is_ok());
        assert_eq!(hydra.commit_count(), 2);
    }

    #[test]
    fn hydra_validates_claim_against_registered_schema() {
        use hydra_core::{
            ActorId, ClaimObject, ClaimPredicateSchema, EventKind, SchemaDefinition, SchemaId,
            SchemaStatus, TypeId, Value, ValueType,
        };
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let schema = ClaimPredicateSchema {
            id: SchemaId::new(),
            tenant_id: None,
            predicate: "is_stale".to_string(),
            status: SchemaStatus::Active,
            subject_type: Some(TypeId::from_str("type_dataset")),
            object_type: ValueType::Bool,
            allowed_claim_kinds: vec!["AnomalyFinding".to_string()],
            created_by: ActorId::from_str("actor_schema"),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        hydra
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::ClaimPredicate(schema),
            })
            .unwrap();

        let claim = test_claim(ClaimObject::Value(Value::Bool(true)));
        let report = hydra.validate_claim(&claim);
        assert!(report.is_valid());
        assert!(report.schema_id.is_some());
    }

    fn register_invoice_entity_schema(hydra: &mut Hydra) {
        use hydra_core::{
            ActorId, EntityTypeSchema, EventKind, FieldSchema, SchemaDefinition, SchemaId,
            SchemaStatus, TypeId, ValueType,
        };
        use std::collections::HashMap;

        let now = chrono::Utc::now();
        let schema = EntityTypeSchema {
            id: SchemaId::new(),
            tenant_id: None,
            type_id: TypeId::from_str("type_invoice"),
            name: "Invoice".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("invoice_number", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
                FieldSchema::optional("memo", ValueType::String),
            ],
            created_by: ActorId::from_str("actor_schema"),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        hydra
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::EntityType(schema),
            })
            .unwrap();
    }

    #[test]
    fn hydra_schema_gate_strict_rejects_invalid_node_create_before_commit() {
        use crate::schema_gate::{SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy};
        use hydra_core::{EventKind, NodeId, Value};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        register_invoice_entity_schema(&mut hydra);
        assert_eq!(hydra.commit_count(), 1);

        hydra.set_schema_gate_config(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        });

        let mut properties = HashMap::new();
        properties.insert(
            "invoice_number".to_string(),
            Value::String("INV-001".to_string()),
        );
        properties.insert("amount".to_string(), Value::String("bad".to_string()));
        let result = hydra.ingest(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "type_invoice".to_string(),
            properties,
        });
        assert!(result.is_err());
        assert_eq!(hydra.commit_count(), 1);
    }

    #[test]
    fn hydra_schema_gate_strict_allows_valid_node_create() {
        use crate::schema_gate::{SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy};
        use hydra_core::{EventKind, NodeId, Value};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        register_invoice_entity_schema(&mut hydra);

        hydra.set_schema_gate_config(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        });

        let mut properties = HashMap::new();
        properties.insert(
            "invoice_number".to_string(),
            Value::String("INV-001".to_string()),
        );
        properties.insert("amount".to_string(), Value::Float(100.0));
        let node_id = NodeId::new();
        let result = hydra.ingest(EventKind::NodeCreated {
            node_id: node_id.clone(),
            type_id: "type_invoice".to_string(),
            properties,
        });
        assert!(result.is_ok());
        assert_eq!(hydra.commit_count(), 2);
        assert!(hydra.resolve_node_type_id(&node_id).is_some());
    }

    #[test]
    fn hydra_schema_gate_strict_rejects_invalid_node_update_before_commit() {
        use crate::schema_gate::{SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy};
        use hydra_core::{EventKind, NodeId, Value};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        register_invoice_entity_schema(&mut hydra);

        let mut properties = HashMap::new();
        properties.insert(
            "invoice_number".to_string(),
            Value::String("INV-001".to_string()),
        );
        properties.insert("amount".to_string(), Value::Float(100.0));
        let node_id = NodeId::new();
        hydra
            .ingest(EventKind::NodeCreated {
                node_id: node_id.clone(),
                type_id: "type_invoice".to_string(),
                properties,
            })
            .unwrap();
        let commit_count_before_update = hydra.commit_count();

        hydra.set_schema_gate_config(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        });

        let mut changes = HashMap::new();
        changes.insert("amount".to_string(), Value::String("bad".to_string()));
        let result = hydra.ingest(EventKind::NodeUpdated { node_id, changes });
        assert!(result.is_err());
        assert_eq!(hydra.commit_count(), commit_count_before_update);
    }

    #[test]
    fn hydra_schema_gate_strict_allows_valid_node_update() {
        use crate::schema_gate::{SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy};
        use hydra_core::{EventKind, NodeId, Value};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        register_invoice_entity_schema(&mut hydra);

        let mut properties = HashMap::new();
        properties.insert(
            "invoice_number".to_string(),
            Value::String("INV-001".to_string()),
        );
        properties.insert("amount".to_string(), Value::Float(100.0));
        let node_id = NodeId::new();
        hydra
            .ingest(EventKind::NodeCreated {
                node_id: node_id.clone(),
                type_id: "type_invoice".to_string(),
                properties,
            })
            .unwrap();

        hydra.set_schema_gate_config(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        });

        let mut changes = HashMap::new();
        changes.insert("amount".to_string(), Value::Float(125.0));
        let result = hydra.ingest(EventKind::NodeUpdated { node_id, changes });
        assert!(result.is_ok());
    }

    #[test]
    fn idempotent_retry_short_circuits_before_schema_gate() {
        use crate::schema_gate::{SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy};
        use hydra_core::{EventKind, IdempotencyKey, NodeId};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let key = IdempotencyKey::new("schema-gate-retry");
        let first = hydra
            .ingest_with_idempotency_key(
                EventKind::Signal {
                    source: NodeId::from_str("test"),
                    name: "first".to_string(),
                    payload: HashMap::new(),
                },
                key.clone(),
            )
            .unwrap();
        assert_eq!(hydra.commit_count(), 1);

        hydra.set_schema_gate_config(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Reject,
        });

        let second = hydra
            .ingest_with_idempotency_key(
                EventKind::Signal {
                    source: NodeId::from_str("test"),
                    name: "second_should_not_run".to_string(),
                    payload: HashMap::new(),
                },
                key,
            )
            .unwrap();
        assert_eq!(hydra.commit_count(), 1);
        assert_eq!(second.events[0].id, first.events[0].id);
    }

    #[test]
    fn hydra_snapshot_captures_current_state() {
        use hydra_core::{ActorId, EventKind, NodeId};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        hydra
            .ingest(EventKind::Signal {
                source: NodeId::from_str("snapshot.test"),
                name: "one".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();
        hydra
            .ingest(EventKind::Signal {
                source: NodeId::from_str("snapshot.test"),
                name: "two".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();

        let manifest = hydra
            .snapshot(ActorId::from_str("actor_snapshot"))
            .unwrap();
        assert_eq!(manifest.total_events, 2);
        assert_eq!(manifest.total_commits, 2);
        assert!(manifest.is_committed());

        let body = hydra.snapshot_body(&manifest.id).unwrap();
        assert_eq!(body.events.len(), 2);
        assert_eq!(body.commit_records.len(), 2);

        // SnapshotTaken itself is audited after the snapshot body is captured.
        assert_eq!(hydra.commit_count(), 3);
    }

    #[test]
    fn hydra_restore_from_snapshot_resets_to_snapshot_state() {
        use hydra_core::{ActorId, EventKind, NodeId};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        hydra
            .ingest(EventKind::Signal {
                source: NodeId::from_str("snapshot.test"),
                name: "before".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();

        let manifest = hydra
            .snapshot(ActorId::from_str("actor_snapshot"))
            .unwrap();
        let commits_at_snapshot = hydra.commit_count();

        hydra
            .ingest(EventKind::Signal {
                source: NodeId::from_str("snapshot.test"),
                name: "after".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();
        assert!(hydra.commit_count() > commits_at_snapshot);

        hydra
            .restore_from_snapshot(&manifest.id, ActorId::from_str("actor_restore"))
            .unwrap();

        // After restore, the event log contains:
        // - 1 original signal recovered from the snapshot body
        // - 1 SnapshotRestored audit event committed after restore
        let names: Vec<String> = hydra
            .events()
            .into_iter()
            .map(|event| event.kind.kind_name().to_string())
            .collect();
        assert!(names.contains(&"signal".to_string()));
        assert!(names.contains(&"snapshot_restored".to_string()));
        // The "after" signal that came in post-snapshot is gone.
        assert!(!hydra.events().iter().any(|event| matches!(
            &event.kind,
            EventKind::Signal { name, .. } if name == "after"
        )));
    }

    #[test]
    fn hydra_latest_snapshot_manifest_tracks_highest_sequence() {
        use hydra_core::{ActorId, EventKind, NodeId};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        hydra
            .ingest(EventKind::Signal {
                source: NodeId::from_str("snapshot.test"),
                name: "one".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();
        let first = hydra
            .snapshot(ActorId::from_str("actor_snapshot"))
            .unwrap();

        hydra
            .ingest(EventKind::Signal {
                source: NodeId::from_str("snapshot.test"),
                name: "two".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();
        let second = hydra
            .snapshot(ActorId::from_str("actor_snapshot"))
            .unwrap();

        assert_eq!(hydra.latest_snapshot_manifest().unwrap().id, second.id);
        assert!(second.sequence > first.sequence);
        assert_eq!(hydra.snapshot_manifests().len(), 2);
    }

    #[derive(Clone, Default)]
    struct TestSnapshotBackend {
        bodies: std::sync::Arc<std::sync::Mutex<Vec<hydra_core::SnapshotBody>>>,
    }

    impl crate::snapshot_store::SnapshotBackend for TestSnapshotBackend {
        fn write_snapshot(
            &self,
            body: &hydra_core::SnapshotBody,
        ) -> hydra_core::error::Result<()> {
            self.bodies.lock().unwrap().push(body.clone());
            Ok(())
        }

        fn read_snapshot(
            &self,
            id: &hydra_core::SnapshotId,
        ) -> hydra_core::error::Result<hydra_core::SnapshotBody> {
            self.bodies
                .lock()
                .unwrap()
                .iter()
                .find(|body| &body.manifest.id == id)
                .cloned()
                .ok_or_else(|| {
                    hydra_core::error::HydraError::QueryError(format!("unknown snapshot: {id}"))
                })
        }

        fn list_snapshot_manifests(
            &self,
        ) -> hydra_core::error::Result<Vec<hydra_core::SnapshotManifest>> {
            Ok(self
                .bodies
                .lock()
                .unwrap()
                .iter()
                .map(|body| body.manifest.clone())
                .collect())
        }

        fn delete_snapshot(
            &self,
            _id: &hydra_core::SnapshotId,
        ) -> hydra_core::error::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn hydra_snapshot_writes_to_attached_backend_before_audit_event() {
        use hydra_core::{ActorId, EventKind, NodeId};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        hydra
            .ingest(EventKind::Signal {
                source: NodeId::from_str("snapshot.backend"),
                name: "one".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();

        let backend = TestSnapshotBackend::default();
        let observed = backend.bodies.clone();
        hydra.set_snapshot_backend(backend);
        assert!(hydra.has_snapshot_backend());

        let manifest = hydra
            .snapshot(ActorId::from_str("actor_snapshot_backend"))
            .unwrap();
        let bodies = observed.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].manifest.id, manifest.id);
        assert_eq!(bodies[0].events.len(), 1);
        // SnapshotTaken commits AFTER the backend write succeeds.
        assert_eq!(hydra.commit_count(), 2);
    }

    #[test]
    fn hydra_clear_snapshot_backend_stops_writes() {
        use hydra_core::{ActorId, EventKind, NodeId};
        use std::collections::HashMap;

        let mut hydra = Hydra::new();
        let backend = TestSnapshotBackend::default();
        let observed = backend.bodies.clone();
        hydra.set_snapshot_backend(backend);
        hydra.clear_snapshot_backend();
        assert!(!hydra.has_snapshot_backend());

        hydra
            .ingest(EventKind::Signal {
                source: NodeId::from_str("snapshot.backend"),
                name: "one".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();
        hydra
            .snapshot(ActorId::from_str("actor_no_backend"))
            .unwrap();

        // Backend cleared before snapshot — nothing should have reached it.
        assert_eq!(observed.lock().unwrap().len(), 0);
    }

    fn snapshot_replay_signal(name: &str) -> hydra_core::EventKind {
        hydra_core::EventKind::Signal {
            source: hydra_core::NodeId::from_str("snapshot.replay"),
            name: name.to_string(),
            payload: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn hydra_recover_from_snapshot_and_replay_applies_post_snapshot_commits() {
        use hydra_core::ActorId;

        let mut source = Hydra::new();
        source.ingest(snapshot_replay_signal("before")).unwrap();
        let manifest = source
            .snapshot(ActorId::from_str("actor_snapshot"))
            .unwrap();
        source.ingest(snapshot_replay_signal("after")).unwrap();
        let commits = source
            .commit_ledger()
            .batches_in_sequence()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let body = source.snapshot_body(&manifest.id).unwrap().clone();

        let mut target = Hydra::new();
        target
            .recover_from_snapshot_body_and_replay(
                body,
                commits,
                ActorId::from_str("actor_restore"),
            )
            .unwrap();

        let names = target
            .events()
            .into_iter()
            .map(|event| event.kind.kind_name().to_string())
            .collect::<Vec<_>>();
        // 2 signals: "before" (from body) + "after" (from replay tail).
        assert_eq!(
            names.iter().filter(|name| *name == "signal").count(),
            2
        );
        assert!(names.contains(&"snapshot_restored".to_string()));
        // SnapshotTaken is replayed faithfully from the post-snapshot
        // commit at sequence N+1 (Option A semantics).
        assert!(names.contains(&"snapshot_taken".to_string()));
    }

    #[test]
    fn hydra_recover_from_snapshot_and_replay_records_replayed_commit_count() {
        use hydra_core::{ActorId, EventKind};

        let mut source = Hydra::new();
        source.ingest(snapshot_replay_signal("before")).unwrap();
        let manifest = source
            .snapshot(ActorId::from_str("actor_snapshot"))
            .unwrap();
        source.ingest(snapshot_replay_signal("after_one")).unwrap();
        source.ingest(snapshot_replay_signal("after_two")).unwrap();
        let commits = source
            .commit_ledger()
            .batches_in_sequence()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let body = source.snapshot_body(&manifest.id).unwrap().clone();

        let mut target = Hydra::new();
        target
            .recover_from_snapshot_body_and_replay(
                body,
                commits,
                ActorId::from_str("actor_restore"),
            )
            .unwrap();

        let restored_event = target
            .events()
            .into_iter()
            .find(|event| event.kind.kind_name() == "snapshot_restored")
            .unwrap();
        match &restored_event.kind {
            EventKind::SnapshotRestored {
                replayed_commit_count,
                ..
            } => {
                // 3 commits after snapshot.sequence: SnapshotTaken (N+1),
                // after_one (N+2), after_two (N+3). Option A semantics.
                assert_eq!(*replayed_commit_count, 3);
            }
            other => panic!("expected SnapshotRestored, got {other:?}"),
        }
    }

    #[test]
    fn hydra_recover_from_snapshot_and_replay_rejects_sequence_gap_before_mutation() {
        use hydra_core::ActorId;

        let mut source = Hydra::new();
        source.ingest(snapshot_replay_signal("before")).unwrap();
        let manifest = source
            .snapshot(ActorId::from_str("actor_snapshot"))
            .unwrap();
        source.ingest(snapshot_replay_signal("after")).unwrap();
        let mut commits = source
            .commit_ledger()
            .batches_in_sequence()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        // Drop the SnapshotTaken commit (sequence = manifest.sequence + 1)
        // to create a gap in the replay tail.
        commits.retain(|batch| batch.sequence != manifest.sequence + 1);
        let body = source.snapshot_body(&manifest.id).unwrap().clone();

        let mut target = Hydra::new();
        let result = target.recover_from_snapshot_body_and_replay(
            body,
            commits,
            ActorId::from_str("actor_restore"),
        );
        assert!(result.is_err());
        // No partial mutation — validation runs before reset/replay.
        assert_eq!(target.events().len(), 0);
        assert_eq!(target.commit_count(), 0);
    }

    #[test]
    fn hydra_recover_from_snapshot_and_replay_by_id_works() {
        use hydra_core::ActorId;

        let mut source = Hydra::new();
        source.ingest(snapshot_replay_signal("before")).unwrap();
        let manifest = source
            .snapshot(ActorId::from_str("actor_snapshot"))
            .unwrap();
        source.ingest(snapshot_replay_signal("after")).unwrap();
        let commits = source
            .commit_ledger()
            .batches_in_sequence()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let body = source.snapshot_body(&manifest.id).unwrap().clone();

        let mut target = Hydra::new();
        target.snapshot_store.insert(body);
        target
            .recover_from_snapshot_and_replay(
                &manifest.id,
                commits,
                ActorId::from_str("actor_restore"),
            )
            .unwrap();

        let names = target
            .events()
            .into_iter()
            .map(|event| event.kind.kind_name().to_string())
            .collect::<Vec<_>>();
        assert!(names.contains(&"snapshot_restored".to_string()));
        assert_eq!(
            names.iter().filter(|name| *name == "signal").count(),
            2
        );
    }

    // === V2 patch 2 — ReplicationStore integration ===

    #[test]
    fn replication_events_populate_store_through_ingest() {
        use hydra_core::{
            ActorId, EventKind, ReplicaId, ReplicationMode, ReplicationOffset, ReplicationPeer,
            ReplicationPeerStatus, ReplicationRole,
        };
        let mut hydra = Hydra::new();
        let peer = ReplicationPeer::registered(
            ReplicaId::from_str("replica_acme"),
            ReplicationRole::Follower,
            ReplicationMode::SnapshotThenTail,
            ActorId::from_str("actor_replication"),
        );
        let peer_id = peer.id.clone();
        hydra
            .ingest(EventKind::ReplicaRegistered { peer })
            .unwrap();
        hydra
            .ingest(EventKind::ReplicaHeartbeatRecorded {
                peer_id: peer_id.clone(),
                offset: ReplicationOffset::from_sequence(42),
                lag: None,
            })
            .unwrap();
        assert!(hydra.replication_peer(&peer_id).is_some());
        assert_eq!(
            hydra.latest_replication_offset(&peer_id).map(|o| o.sequence),
            Some(42)
        );
        assert_eq!(
            hydra
                .replication_peers_with_status(ReplicationPeerStatus::Registered)
                .len(),
            1
        );
    }

    #[test]
    fn snapshot_round_trip_preserves_replication_state() {
        use hydra_core::{
            ActorId, EventKind, ReplicaId, ReplicationMode, ReplicationOffset, ReplicationPeer,
            ReplicationRole, ReplicationRun,
        };

        let mut source = Hydra::new();
        let peer = ReplicationPeer::registered(
            ReplicaId::from_str("replica_acme"),
            ReplicationRole::Follower,
            ReplicationMode::CommitLogStreaming,
            ActorId::from_str("actor_replication"),
        );
        let peer_id = peer.id.clone();
        source
            .ingest(EventKind::ReplicaRegistered { peer })
            .unwrap();
        let run = ReplicationRun::started(
            peer_id.clone(),
            ReplicationMode::CommitLogStreaming,
            Some(ReplicationOffset::from_sequence(100)),
        );
        let run_id = run.id.clone();
        source
            .ingest(EventKind::ReplicationRunStarted { run })
            .unwrap();

        let manifest = source
            .snapshot(ActorId::from_str("actor_snapshot"))
            .unwrap();
        // Manifest carries the new counts.
        assert_eq!(manifest.total_replication_peers, 1);
        assert_eq!(manifest.total_replication_runs, 1);

        // Restore into a fresh Hydra; the store must rebuild from replay.
        let mut target = Hydra::new();
        target
            .recover_from_events(source.events().into_iter().cloned().collect())
            .unwrap();
        assert!(target.replication_peer(&peer_id).is_some());
        assert!(target.replication_run(&run_id).is_some());
    }

    // === V2 patch 3B — apply_replication_commits ===

    fn replication_signal(name: &str) -> hydra_core::EventKind {
        hydra_core::EventKind::Signal {
            source: hydra_core::NodeId::from_str("test.replication"),
            name: name.to_string(),
            payload: std::collections::HashMap::new(),
        }
    }

    fn leader_with_signals(count: usize) -> Hydra {
        let mut leader = Hydra::new();
        for i in 0..count {
            leader
                .ingest(replication_signal(&format!("signal_{i}")))
                .unwrap();
        }
        leader
    }

    fn batches_from(hydra: &Hydra) -> Vec<hydra_core::CommitBatch> {
        hydra
            .commit_ledger()
            .batches_in_sequence()
            .into_iter()
            .cloned()
            .collect()
    }

    fn peer_id() -> hydra_core::ReplicaId {
        hydra_core::ReplicaId::from_str("replica_follower_test")
    }

    #[test]
    fn apply_empty_commits_is_noop() {
        let mut follower = Hydra::new();
        let report = follower
            .apply_replication_commits(peer_id(), vec![])
            .unwrap();
        assert_eq!(report.applied_count, 0);
        assert_eq!(report.latest_sequence, None);
        assert_eq!(report.latest_commit_id, None);
        assert_eq!(follower.commit_count(), 0);
        assert_eq!(follower.events().len(), 0);
    }

    #[test]
    fn apply_replication_commits_to_empty_follower() {
        let leader = leader_with_signals(3);
        let commits = batches_from(&leader);
        let leader_commit_count = leader.commit_count();
        let leader_event_count = leader.events().len();
        let leader_head_id = leader.latest_commit().unwrap().id.clone();

        let mut follower = Hydra::new();
        let report = follower
            .apply_replication_commits(peer_id(), commits)
            .unwrap();
        assert_eq!(report.applied_count, 3);
        assert_eq!(report.latest_sequence, Some(3));
        assert_eq!(report.latest_commit_id, Some(leader_head_id));
        assert_eq!(follower.commit_count(), leader_commit_count);
        assert_eq!(follower.events().len(), leader_event_count);
        // Hash-chain consistency carried over.
        follower.verify_commit_chain().unwrap();
    }

    #[test]
    fn apply_replication_commits_rejects_sequence_gap() {
        let leader = leader_with_signals(3);
        // Drop the middle batch to manufacture a gap.
        let mut commits = batches_from(&leader);
        commits.remove(1); // now sequence 1, 3 — gap at 2

        let mut follower = Hydra::new();
        let err = follower
            .apply_replication_commits(peer_id(), commits)
            .unwrap_err();
        assert!(
            matches!(err, hydra_core::error::HydraError::QueryError(_)),
            "expected QueryError for sequence gap, got {:?}",
            err
        );
        // No mutation on failure.
        assert_eq!(follower.commit_count(), 0);
    }

    #[test]
    fn apply_replication_commits_rejects_wrong_previous_hash() {
        let leader = leader_with_signals(2);
        let mut commits = batches_from(&leader);
        // Tamper with the previous_hash of the second batch.
        commits[1].previous_hash = Some(hydra_core::CommitHash("engine-v0:bogus".to_string()));

        let mut follower = Hydra::new();
        let err = follower
            .apply_replication_commits(peer_id(), commits)
            .unwrap_err();
        assert!(matches!(
            err,
            hydra_core::error::HydraError::QueryError(_)
        ));
        assert_eq!(follower.commit_count(), 0);
    }

    #[test]
    fn apply_replication_commits_rejects_uncommitted_batch() {
        let leader = leader_with_signals(1);
        let mut commits = batches_from(&leader);
        commits[0].status = hydra_core::CommitStatus::Pending;

        let mut follower = Hydra::new();
        let err = follower
            .apply_replication_commits(peer_id(), commits)
            .unwrap_err();
        assert!(matches!(
            err,
            hydra_core::error::HydraError::QueryError(_)
        ));
        assert_eq!(follower.commit_count(), 0);
    }

    #[test]
    fn apply_replication_commits_rejects_unsorted_batches() {
        let leader = leader_with_signals(2);
        let mut commits = batches_from(&leader);
        commits.reverse(); // [seq=2, seq=1]

        let mut follower = Hydra::new();
        let err = follower
            .apply_replication_commits(peer_id(), commits)
            .unwrap_err();
        assert!(matches!(
            err,
            hydra_core::error::HydraError::QueryError(_)
        ));
        assert_eq!(follower.commit_count(), 0);
    }

    #[test]
    fn apply_replication_commits_rejects_replay_of_already_applied_batch() {
        // Re-sending an already-applied batch is caught by the sequence
        // gate (the head has already advanced past it). This is the
        // strongest guard against follower double-apply.
        let leader = leader_with_signals(1);
        let commits = batches_from(&leader);

        let mut follower = Hydra::new();
        follower
            .apply_replication_commits(peer_id(), commits.clone())
            .unwrap();
        // Same batch again — sequence is now 1 + 1 = 2 expected, batch is
        // sequence 1 → reject.
        let err = follower
            .apply_replication_commits(peer_id(), commits)
            .unwrap_err();
        assert!(matches!(
            err,
            hydra_core::error::HydraError::QueryError(_)
        ));
    }

    struct ReplicationFollowUpHandler;
    impl hydra_core::subscription::SubscriptionHandler for ReplicationFollowUpHandler {
        fn handle(
            &self,
            event: &Event,
            _graph: &dyn hydra_core::graph::GraphReader,
        ) -> Vec<EventKind> {
            if let EventKind::NodeCreated { node_id, .. } = &event.kind {
                vec![EventKind::NodeUpdated {
                    node_id: node_id.clone(),
                    changes: std::collections::HashMap::from([(
                        "follow_up".to_string(),
                        hydra_core::Value::Bool(true),
                    )]),
                }]
            } else {
                vec![]
            }
        }
    }

    #[test]
    fn apply_replication_commits_replays_state_without_agents() {
        use hydra_core::subscription::{EventFilter, Subscription};
        // Leader runs a subscription that emits a NodeUpdated reaction
        // whenever a NodeCreated is ingested. That reaction goes through
        // the cascade and becomes a SEPARATE event in the leader's log.
        // Two events per ingest, packaged into one commit batch.
        let mut leader = Hydra::new();
        leader.register(Subscription::new(
            "follow_up",
            EventFilter::Any,
            100,
            Box::new(ReplicationFollowUpHandler),
        ));
        let node_id = hydra_core::NodeId::new();
        leader
            .ingest(EventKind::NodeCreated {
                node_id: node_id.clone(),
                type_id: "test_node".to_string(),
                properties: std::collections::HashMap::new(),
            })
            .unwrap();
        let leader_event_count = leader.events().len();
        let leader_commit_count = leader.commit_count();
        // Sanity: the subscription DID fire on the leader (we should see
        // both NodeCreated and the reactive NodeUpdated in the same
        // cascade batch).
        assert!(
            leader_event_count >= 2,
            "leader subscription must have fired — got {} events",
            leader_event_count
        );

        let commits = batches_from(&leader);

        // Follower is a fresh Hydra with NO subscription registered. If
        // apply_replication_commits accidentally went through the cascade
        // engine (or fired agents that synthesize new events), the
        // follower's event count would differ. Strict equality is the
        // contract.
        let mut follower = Hydra::new();
        follower
            .apply_replication_commits(peer_id(), commits)
            .unwrap();
        assert_eq!(follower.commit_count(), leader_commit_count);
        assert_eq!(follower.events().len(), leader_event_count);
        // The replayed reaction (NodeUpdated with follow_up=true) is
        // visible on the follower's projection — proves the replay path
        // ran the EXISTING events, not a re-derived cascade.
        let node = follower.graph().node(&node_id).unwrap();
        assert_eq!(
            node.properties.get("follow_up"),
            Some(&hydra_core::Value::Bool(true))
        );
    }

    // === V2 patch 4C — replication cursor / chain-handshake ===

    #[test]
    fn apply_replication_commits_records_latest_offset() {
        use hydra_core::ReplicaId;

        let leader = leader_with_signals(3);
        let commits = batches_from(&leader);
        let last_leader_batch = commits.last().cloned().unwrap();
        let peer = ReplicaId::from_str("replica_cursor_test");

        let mut follower = Hydra::new();
        follower
            .apply_replication_commits(peer.clone(), commits)
            .unwrap();

        // The cursor must match the LAST applied batch — the leader's
        // chain head, NOT the follower's local commit ledger head.
        let cursor = follower
            .latest_replication_offset(&peer)
            .expect("replication cursor must be recorded after apply");
        assert_eq!(cursor.sequence, last_leader_batch.sequence);
        assert_eq!(cursor.commit_id.as_ref(), Some(&last_leader_batch.id));
        assert_eq!(cursor.commit_hash, last_leader_batch.commit_hash);
        // Sanity: cursor and local head sequence agree here (no
        // bootstrap in this path; both are the leader's chain).
        assert_eq!(
            Some(cursor.sequence),
            follower.latest_commit().map(|r| r.sequence)
        );

        // Empty apply does NOT stamp a cursor on top of an existing one.
        let pre = follower.latest_replication_offset(&peer).cloned().unwrap();
        follower
            .apply_replication_commits(peer.clone(), vec![])
            .unwrap();
        let post = follower
            .latest_replication_offset(&peer)
            .expect("cursor preserved after empty apply");
        assert_eq!(&pre, post);
    }

    // === V2 polish #5 — engine-level role guard ===

    #[test]
    fn ingest_rejected_on_follower() {
        use hydra_core::error::HydraError;

        // new_with_role(Follower) builds a follower-mode engine.
        let mut follower = Hydra::new_with_role(EngineRole::Follower);
        assert_eq!(follower.role(), EngineRole::Follower);

        let err = follower.ingest(replication_signal("blocked")).unwrap_err();
        match err {
            HydraError::ReadOnlyFollower { method } => {
                assert_eq!(method, "ingest");
            }
            other => panic!("expected ReadOnlyFollower, got {other:?}"),
        }

        // No state mutation — the rejected ingest must leave the
        // engine completely untouched.
        assert_eq!(follower.commit_count(), 0);
        assert_eq!(follower.events().len(), 0);
    }

    #[test]
    fn apply_replication_commits_succeeds_on_follower() {
        // The receive path must work even when role=Follower —
        // that's the whole point of a follower.
        let leader = leader_with_signals(2);
        let commits = batches_from(&leader);

        let mut follower = Hydra::new_with_role(EngineRole::Follower);
        let report = follower
            .apply_replication_commits(peer_id(), commits)
            .unwrap();
        assert_eq!(report.applied_count, 2);
        assert_eq!(follower.commit_count(), 2);
    }

    #[test]
    fn bootstrap_recovery_succeeds_on_follower() {
        use hydra_core::ActorId;

        // recover_from_snapshot_body_and_replay must work on a
        // follower — bootstrap is how a fresh follower catches up.
        let mut source = Hydra::new();
        source.ingest(replication_signal("before")).unwrap();
        let manifest = source
            .snapshot(ActorId::from_str("actor_snapshot"))
            .unwrap();
        source.ingest(replication_signal("after")).unwrap();
        let commits = source
            .commit_ledger()
            .batches_in_sequence()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let body = source.snapshot_body(&manifest.id).unwrap().clone();

        let mut follower = Hydra::new_with_role(EngineRole::Follower);
        follower
            .recover_from_snapshot_body_and_replay(
                body,
                commits,
                ActorId::from_str("actor_restore"),
            )
            .expect("follower bootstrap must succeed");

        // Two "signal" events made it through (one from body, one
        // from replay tail). Plus a SnapshotRestored audit commit.
        let kinds: Vec<String> = follower
            .events()
            .into_iter()
            .map(|event| event.kind.kind_name().to_string())
            .collect();
        assert_eq!(kinds.iter().filter(|k| *k == "signal").count(), 2);
        assert!(kinds.contains(&"snapshot_restored".to_string()));
    }

    #[test]
    fn set_role_back_to_leader_re_enables_ingest() {
        use hydra_core::error::HydraError;

        let mut hydra = Hydra::new_with_role(EngineRole::Follower);
        // Confirm follower rejects.
        assert!(matches!(
            hydra.ingest(replication_signal("blocked")).unwrap_err(),
            HydraError::ReadOnlyFollower { method: "ingest" }
        ));

        // Flip back to leader at runtime (the future role-flip
        // admin route uses this same setter).
        hydra.set_role(EngineRole::Leader);
        assert_eq!(hydra.role(), EngineRole::Leader);

        // Ingest now succeeds.
        hydra.ingest(replication_signal("allowed")).unwrap();
        assert_eq!(hydra.commit_count(), 1);
    }
}
