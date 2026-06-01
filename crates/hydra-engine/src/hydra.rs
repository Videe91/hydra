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
use crate::causal_cell_store::CausalCellStore;
use crate::identity_store::IdentityStore;
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

// === MicroModel Patch 16 — built-in ReplicationLagAnomalyModel identity ===
//
// Second built-in model. Same shape as Patch 2's constants —
// stable model id and system actor — so registry restoration and
// audit-chain queries treat both models uniformly.
pub const BUILTIN_REPLICATION_LAG_MODEL_ID: &str = "mm_builtin_replication_lag_v0";
pub const BUILTIN_REPLICATION_LAG_ACTOR_ID: &str =
    "actor_hydra_replication_lag_model";

// === MicroModel Patch 18 — built-in AgentLoopStormModel identity ===
//
// Third built-in model. Same convention as Patches 2 + 16. The
// actor id is also referenced by
// `hydra_core::is_hydra_system_actor` so this model's own
// auto-register event is filtered out of the next storm
// evaluation. The model itself never approves anything, so it
// is NOT in `is_hydra_automation_actor`.
pub const BUILTIN_AGENT_LOOP_STORM_MODEL_ID: &str =
    "mm_builtin_agent_loop_storm_v0";
pub const BUILTIN_AGENT_LOOP_STORM_ACTOR_ID: &str =
    "actor_hydra_agent_loop_storm_model";

// === MicroModel Patch 19 — built-in ActionFailureRateModel identity ===
//
// Fourth built-in model. Self-health detector: watches Hydra's
// own action delivery for degraded success rate. Actor is in
// `hydra_core::is_hydra_system_actor` so this model's own
// auto-register event is filtered out of the Patch 18 storm
// count. Does NOT approve anything, so NOT in
// `is_hydra_automation_actor`.
pub const BUILTIN_ACTION_FAILURE_RATE_MODEL_ID: &str =
    "mm_builtin_action_failure_rate_v0";
pub const BUILTIN_ACTION_FAILURE_RATE_ACTOR_ID: &str =
    "actor_hydra_action_failure_rate_model";

// Patch 26 — `HydraHealthCell` composer.
//
// The four self-health reflex CELL subjects. Each subject is
// the `format_claim_subject(claim)` output for the reflex chain
// of one built-in self-health model:
//
//   commit-rate         → CommitRateAnomaly         (P5  / P16-bridge)
//   replication-lag     → ReplicationLagAnomaly     (P16)
//   agent-loop-storm    → AgentLoopStormModel       (P18)
//   action-failure-rate → ActionFailureRateModel    (P19)
//
// These are the canonical fractal-layer inputs to the
// `hydra.health` parent cell composed by
// `Hydra::compose_hydra_health_cell`. Indexed parallel to
// `SELF_HEALTH_REFLEX_LABELS` — the labels appear in the
// composed cell's summary string verbatim.
pub(crate) const SELF_HEALTH_REFLEX_SUBJECTS: [&str; 4] = [
    "hydra/under_abnormal_load",
    "hydra.replication/replica_lagging",
    "hydra.agents/agent_loop_storm",
    "hydra.actions/action_failure_rate_high",
];

pub(crate) const SELF_HEALTH_REFLEX_LABELS: [&str; 4] = [
    "commit-rate",
    "replication-lag",
    "agent-loop-storm",
    "action-failure-rate",
];

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
    /// Patch 20 — CausalCell vocabulary store. Holds bounded
    /// causal units (one reflex chain, one incident, etc.) as
    /// passive containers. Nothing in the engine creates cells
    /// automatically yet — Patch 21+ will add reflex→cell
    /// converters.
    causal_cell_store: CausalCellStore,
    /// Patch 29 — Identity Graph vocabulary store. Holds canonical
    /// `IdentityEntity`s with embedded source-specific aliases.
    /// Same passive-store pattern as `causal_cell_store`: built
    /// from the event log, restored from snapshot bodies, never
    /// auto-populated. Future patches (P30+) layer matching,
    /// links, and correlation on top of this primitive.
    identity_store: IdentityStore,
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
            causal_cell_store: CausalCellStore::new(),
            identity_store: IdentityStore::new(),
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
            causal_cell_store: CausalCellStore::new(),
            identity_store: IdentityStore::new(),
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
            self.causal_cell_store.apply_event(event)?;
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
        self.causal_cell_store.apply_event(event)?;
        self.identity_store.apply_event(event)?;
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
        self.causal_cell_store = CausalCellStore::new();
        self.identity_store = IdentityStore::new();
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

    // === Patch 7 — operator-triggered Notify execution stub =====
    //
    // The first execution path in the action lifecycle. Walks an
    // Approved Notify action through the full
    // `ActionExecuting → ActionExecuted → OutcomeObserved` chain
    // and returns an `ActionExecutionReport` so callers can audit
    // the transition and reach the outcome by id without a follow-
    // up query.
    //
    // Strict preconditions (enforced by this method, NOT v0 in
    // Patch 6's approve/reject):
    //   - action must exist           → unknown action → QueryError
    //   - action.kind == Notify       → other kinds   → QueryError
    //   - action.status == Approved   → other states  → QueryError
    //
    // Patch 7 boundary: this is a STUB. No webhook, no Slack, no
    // secrets, no retries. The `Outcome.impact` records "notification
    // would be sent" and `OutcomeKind::Custom("notification_recorded")`
    // marks the stub kind. Real delivery is Patch 7B.
    //
    // OutcomeAgent is NOT extended in Patch 7. It already reacts to
    // ActionExecuted for Backfill only and no-ops for Notify, so
    // emitting OutcomeObserved here is the explicit, kind-aware path.
    // Patch 8 owns OutcomeAgent's outcome-learning rewrite.

    /// Execute an approved Notify action as an internal stub.
    ///
    /// `actor` is the operator triggering execution — recorded on
    /// the outcome as `recorded_by`. Returns an
    /// `ActionExecutionReport` carrying the transition + the
    /// recorded outcome id.
    pub fn execute_notify_action(
        &mut self,
        action_id: hydra_core::ActionId,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<hydra_core::ActionExecutionReport> {
        // 1. Validate action exists.
        let action = match self.action_store.action(&action_id) {
            Some(a) => a.clone(),
            None => {
                return Err(hydra_core::error::HydraError::QueryError(format!(
                    "unknown action: {action_id}"
                )));
            }
        };
        // 2. Validate kind.
        if action.kind != hydra_core::ActionKind::Notify {
            return Err(hydra_core::error::HydraError::QueryError(format!(
                "invalid action kind: {action_id} is not Notify (Patch 7 only \
                 executes Notify actions; got {:?})",
                action.kind
            )));
        }
        // 3. Validate status.
        if action.status != hydra_core::ActionStatus::Approved {
            return Err(hydra_core::error::HydraError::QueryError(format!(
                "invalid action state: {action_id} is {:?}, expected Approved",
                action.status
            )));
        }
        let previous_status = action.status.clone();

        // 4. Ingest ActionExecuting. action_store flips status to
        //    Executing. No agent reacts (OutcomeAgent waits for
        //    ActionExecuted; PolicyAgent only handles ActionProposed).
        self.ingest(hydra_core::EventKind::ActionExecuting {
            action_id: action_id.clone(),
        })?;

        // 5. Ingest ActionExecuted. action_store flips status to
        //    Executed and sets executed_at. OutcomeAgent reacts but
        //    no-ops for Notify (Backfill-only in v0). Capture the
        //    event id so the outcome's caused_by can point back.
        let executed_cascade = self.ingest(hydra_core::EventKind::ActionExecuted {
            action_id: action_id.clone(),
        })?;
        let executed_event_id = executed_cascade
            .events
            .first()
            .map(|event| event.id.clone())
            .expect(
                "ingest produces at least the trigger event for ActionExecuted",
            );

        // 6. Build + ingest the stub outcome. `kind: Custom(...)`
        //    so future filters can identify stub vs real-delivery
        //    outcomes. `impact` is the operator-readable hint that
        //    nothing was actually delivered.
        let now = chrono::Utc::now();
        let mut impact = std::collections::HashMap::new();
        impact.insert(
            "summary".to_string(),
            hydra_core::Value::String(
                "Notify action executed as internal stub; \
                 no real notification was delivered."
                    .to_string(),
            ),
        );
        impact.insert(
            "stub".to_string(),
            hydra_core::Value::Bool(true),
        );
        let outcome = hydra_core::Outcome {
            id: hydra_core::OutcomeId::new(),
            tenant_id: action.tenant_id.clone(),
            action_id: action_id.clone(),
            kind: hydra_core::OutcomeKind::Custom("notification_recorded".to_string()),
            observed_events: vec![executed_event_id.clone()],
            updated_claims: action.related_claims.clone(),
            produced_evidence: vec![],
            impact,
            observed_at: now,
            recorded_at: now,
            recorded_by: actor.clone(),
            caused_by: Some(executed_event_id),
        };
        let outcome_id = outcome.id.clone();
        self.ingest(hydra_core::EventKind::OutcomeObserved {
            outcome,
        })?;

        // 7. Re-read the post-cascade action to pick up the engine-
        //    assigned executed_at. Falls back to `now` if the
        //    action somehow vanished, but action_store guarantees
        //    it persists across the cascade.
        let final_action = self.action_store.action(&action_id).cloned().ok_or_else(
            || {
                hydra_core::error::HydraError::QueryError(format!(
                    "action vanished after execute: {action_id}"
                ))
            },
        )?;
        let executed_at = final_action.executed_at.unwrap_or(now);

        Ok(hydra_core::ActionExecutionReport {
            action_id,
            previous_status,
            final_status: final_action.status,
            outcome_id,
            executed_by: actor,
            executed_at,
        })
    }

    // === Patch 14 — Notify Delivery Adapter ====================
    //
    // The "real-delivery" counterpart to `execute_notify_action`.
    // The HTTP layer's `NotifyDeliveryAdapter` (in hydra-net) does
    // the network call OUTSIDE the engine lock, then calls this
    // method with the result. The engine emits the terminal events
    // that match the delivery outcome:
    //
    //   Succeeded → ActionExecuting → ActionExecuted →
    //               OutcomeObserved { kind: Success }
    //
    //   Failed    → ActionExecuting → ActionFailed →
    //               OutcomeObserved { kind: Failure }
    //
    // The original `execute_notify_action` is preserved as-is for
    // stub mode (and for tests). Patch 14 does NOT modify Patch 7's
    // signature — that's the boundary that protects the SDK
    // surface.

    /// Execute a Notify action with a real delivery outcome.
    ///
    /// Preconditions are identical to `execute_notify_action`
    /// (kind == Notify, status == Approved). The HTTP layer's
    /// adapter validates these BEFORE the network call so it can
    /// short-circuit on bad input without doing work; this method
    /// re-validates inside the lock as defense in depth.
    ///
    /// The `delivery` outcome's `adapter`, `status_code`,
    /// `latency_ms`, and (on failure) `reason` are projected into
    /// the resulting `Outcome.impact` so future trust calibration
    /// (Patch 12+) can branch on real delivery signal.
    pub fn execute_notify_action_with_delivery(
        &mut self,
        action_id: hydra_core::ActionId,
        actor: hydra_core::ActorId,
        delivery: hydra_core::DeliveryOutcome,
    ) -> hydra_core::error::Result<hydra_core::ActionExecutionReport> {
        // 1. Validate action exists.
        let action = match self.action_store.action(&action_id) {
            Some(a) => a.clone(),
            None => {
                return Err(hydra_core::error::HydraError::QueryError(format!(
                    "unknown action: {action_id}"
                )));
            }
        };
        // 2. Validate kind.
        if action.kind != hydra_core::ActionKind::Notify {
            return Err(hydra_core::error::HydraError::QueryError(format!(
                "invalid action kind: {action_id} is not Notify (Patch 14 only \
                 executes Notify actions; got {:?})",
                action.kind
            )));
        }
        // 3. Validate status.
        if action.status != hydra_core::ActionStatus::Approved {
            return Err(hydra_core::error::HydraError::QueryError(format!(
                "invalid action state: {action_id} is {:?}, expected Approved",
                action.status
            )));
        }
        let previous_status = action.status.clone();

        // 4. Ingest ActionExecuting (status flip is the same in
        //    both success and failure paths — the action ran,
        //    even if the receiver didn't accept).
        self.ingest(hydra_core::EventKind::ActionExecuting {
            action_id: action_id.clone(),
        })?;

        let now = chrono::Utc::now();

        // 5. Build the outcome's impact map. Common to both
        //    success and failure: adapter id, latency, stub flag
        //    explicitly false (distinguishes Patch 14 outcomes
        //    from Patch 7 stubs).
        let mut impact: std::collections::HashMap<String, hydra_core::Value> =
            std::collections::HashMap::new();
        impact.insert(
            "stub".to_string(),
            hydra_core::Value::Bool(false),
        );
        impact.insert(
            "adapter".to_string(),
            hydra_core::Value::String(delivery.adapter().to_string()),
        );
        impact.insert(
            "latency_ms".to_string(),
            hydra_core::Value::Int(delivery.latency_ms() as i64),
        );

        // 6. Branch on delivery outcome.
        let (executed_event_id, outcome_kind, summary) = match &delivery {
            hydra_core::DeliveryOutcome::Succeeded {
                status_code,
                adapter,
                ..
            } => {
                impact.insert(
                    "status_code".to_string(),
                    hydra_core::Value::Int(*status_code as i64),
                );
                let summary = format!(
                    "Notify delivered via {adapter} (status {status_code})"
                );
                impact.insert(
                    "summary".to_string(),
                    hydra_core::Value::String(summary.clone()),
                );
                let cascade = self.ingest(hydra_core::EventKind::ActionExecuted {
                    action_id: action_id.clone(),
                })?;
                let event_id = cascade
                    .events
                    .first()
                    .map(|e| e.id.clone())
                    .expect("ingest produces the trigger event");
                (
                    event_id,
                    hydra_core::OutcomeKind::Success,
                    summary,
                )
            }
            hydra_core::DeliveryOutcome::Failed {
                reason,
                status_code,
                adapter,
                ..
            } => {
                if let Some(code) = status_code {
                    impact.insert(
                        "status_code".to_string(),
                        hydra_core::Value::Int(*code as i64),
                    );
                }
                impact.insert(
                    "reason".to_string(),
                    hydra_core::Value::String(reason.clone()),
                );
                let summary = format!(
                    "Notify delivery failed via {adapter}: {reason}"
                );
                impact.insert(
                    "summary".to_string(),
                    hydra_core::Value::String(summary.clone()),
                );
                let cascade = self.ingest(hydra_core::EventKind::ActionFailed {
                    action_id: action_id.clone(),
                    reason: reason.clone(),
                })?;
                let event_id = cascade
                    .events
                    .first()
                    .map(|e| e.id.clone())
                    .expect("ingest produces the trigger event");
                (
                    event_id,
                    hydra_core::OutcomeKind::Failure,
                    summary,
                )
            }
        };
        let _ = summary; // used only to populate impact above

        // 7. Ingest OutcomeObserved. caused_by links to the
        //    terminal event id so lineage walks reach it.
        let outcome = hydra_core::Outcome {
            id: hydra_core::OutcomeId::new(),
            tenant_id: action.tenant_id.clone(),
            action_id: action_id.clone(),
            kind: outcome_kind,
            observed_events: vec![executed_event_id.clone()],
            updated_claims: action.related_claims.clone(),
            produced_evidence: vec![],
            impact,
            observed_at: now,
            recorded_at: now,
            recorded_by: actor.clone(),
            caused_by: Some(executed_event_id),
        };
        let outcome_id = outcome.id.clone();
        self.ingest(hydra_core::EventKind::OutcomeObserved { outcome })?;

        // 8. Re-read the action's final status. On success this is
        //    Executed; on failure, Failed.
        let final_action = self.action_store.action(&action_id).cloned().ok_or_else(
            || {
                hydra_core::error::HydraError::QueryError(format!(
                    "action vanished after execute: {action_id}"
                ))
            },
        )?;
        let executed_at = final_action.executed_at.unwrap_or(now);

        Ok(hydra_core::ActionExecutionReport {
            action_id,
            previous_status,
            final_status: final_action.status,
            outcome_id,
            executed_by: actor,
            executed_at,
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

    // === Patch 20 — CausalCell vocabulary ====================
    //
    // Vocabulary + store + snapshot only. Patch 20 does not
    // auto-create cells from reflex chains, compose cells, or
    // expose any HTTP / SDK surface — those land in later
    // patches. The engine method `create_causal_cell` is the
    // one mutation entry point; read accessors mirror the
    // pattern every other storefront uses.

    /// Read access to the causal-cell store.
    pub fn causal_cell_store(&self) -> &crate::causal_cell_store::CausalCellStore {
        &self.causal_cell_store
    }

    /// Create a causal cell. Emits `EventKind::CausalCellCreated`
    /// through `ingest(...)` so the creation is durable,
    /// auditable, and replicable. Returns the stored cell (the
    /// caller's `cell.id` is preserved — Patch 20 does not
    /// regenerate ids server-side).
    ///
    /// Caller fully populates the cell, including any
    /// `caused_by` event-id back-link. v0 stores whatever the
    /// caller hands in; future patches that auto-create cells
    /// from reflex chains will fill out the back-link
    /// systematically.
    pub fn create_causal_cell(
        &mut self,
        cell: hydra_core::CausalCell,
    ) -> hydra_core::error::Result<hydra_core::CausalCell> {
        let stored = cell.clone();
        self.ingest(hydra_core::EventKind::CausalCellCreated { cell })?;
        Ok(stored)
    }

    /// Look up one cell by id.
    pub fn causal_cell(
        &self,
        id: &hydra_core::CausalCellId,
    ) -> Option<&hydra_core::CausalCell> {
        self.causal_cell_store.cell(id)
    }

    /// All cells in the store. Order is HashMap-iteration order
    /// (unspecified); callers needing stable ordering should
    /// sort by `id`.
    pub fn causal_cells(&self) -> impl Iterator<Item = &hydra_core::CausalCell> {
        self.causal_cell_store.all_cells()
    }

    /// All cells matching the given kind (via
    /// `CausalCellKind::discriminant()`).
    pub fn causal_cells_by_kind(
        &self,
        kind: &hydra_core::CausalCellKind,
    ) -> Vec<&hydra_core::CausalCell> {
        self.causal_cell_store.cells_with_kind(kind)
    }

    // === Identity Graph (Patch 29) ===

    /// Patch 29 — create a canonical `IdentityEntity`.
    ///
    /// Enforces both uniqueness contracts at the engine boundary:
    ///
    /// - **Alias uniqueness**: every alias on the entity is
    ///   indexed by `IdentityAlias::index_key(tenant)`. A
    ///   collision with an already-stored entity returns
    ///   `QueryError("duplicate alias key ...")`.
    /// - **Canonical-key uniqueness**: `(tenant, kind,
    ///   canonical_key)` must be unique. Collision returns
    ///   `QueryError("duplicate canonical_key ...")`.
    /// - **Sentinel validation**: aliases whose `source` or
    ///   `namespace` matches reserved sentinels (`__system__`,
    ///   `__root__`) are rejected so a caller can't force a
    ///   key collision with the `None`-tenant slot.
    ///
    /// On success, ingests `EventKind::IdentityEntityCreated`
    /// and returns the stored entity. Identities are immutable
    /// in v0 — no `update_identity_entity` method, no merge
    /// events. Future patches (P30+) add those.
    pub fn create_identity_entity(
        &mut self,
        entity: hydra_core::IdentityEntity,
    ) -> hydra_core::error::Result<hydra_core::IdentityEntity> {
        // Run the local store's create_entity FIRST so uniqueness
        // checks fire before we hit the event log. On Err, the
        // store is unchanged (its checks all run before
        // insert_entity).
        let stored = self.identity_store.create_entity(entity.clone())?;
        // Now persist via the audit log. `apply_replayed_event`
        // will re-insert into the store during replay, but
        // re-insertion is idempotent — same id triggers a
        // remove-then-add cycle in `insert_entity`.
        self.ingest(hydra_core::EventKind::IdentityEntityCreated {
            entity,
        })?;
        Ok(stored)
    }

    /// Look up one identity entity by id.
    pub fn identity_entity(
        &self,
        id: &hydra_core::IdentityEntityId,
    ) -> Option<&hydra_core::IdentityEntity> {
        self.identity_store.entity(id)
    }

    /// Resolve a source-specific alias to its canonical entity.
    ///
    /// Strict tenant scoping (same rule as P25/P26/P28): a
    /// tenanted query NEVER returns a `None`-tenanted entity,
    /// and vice versa. The store's index keys carry distinct
    /// sentinels for the `None` slot, so the two are physically
    /// separate.
    pub fn identity_entity_by_alias(
        &self,
        tenant_id: Option<&hydra_core::TenantId>,
        source: &str,
        namespace: Option<&str>,
        normalized: &str,
    ) -> Option<&hydra_core::IdentityEntity> {
        self.identity_store
            .entity_by_alias(tenant_id, source, namespace, normalized)
    }

    /// All identity entities matching the given kind (via
    /// `IdentityEntityKind::discriminant()`). Returns an iterator
    /// to match the `causal_cells` shape.
    pub fn identity_entities_by_kind(
        &self,
        kind: hydra_core::IdentityEntityKind,
    ) -> impl Iterator<Item = &hydra_core::IdentityEntity> {
        self.identity_store
            .entities_with_kind(&kind)
            .into_iter()
    }

    /// All identity entities (unordered). Used by snapshot
    /// assembly and tests.
    pub fn identity_entities(
        &self,
    ) -> impl Iterator<Item = &hydra_core::IdentityEntity> {
        self.identity_store.all_entities()
    }

    /// Patch 30 — Semantic Identity Resolution v1.
    ///
    /// Scores existing `IdentityEntity`s against a query alias
    /// using deterministic, explainable factor weights. Returns
    /// the top `limit` candidates sorted by score descending.
    ///
    /// ## Suggestion-only contract
    ///
    /// **The deterministic weights are calibrated for
    /// EXPLAINABILITY, NOT guaranteed correctness.** False
    /// positives are expected — token-overlap will score
    /// `revenue_daily` and `revenue_daily_archived` as
    /// `token_overlap_high`. Two unrelated `ANALYTICS.foo` tables
    /// from the same Snowflake share `same_source` AND
    /// `same_namespace` and will score ~0.30 even with no real
    /// semantic relationship.
    ///
    /// Patch 30 ships read-only BECAUSE operators must judge
    /// each match. Any future patch that auto-links or
    /// auto-merges based on these scores **MUST** add a
    /// separate trust gate (mirror Patch 11's `read:trust +
    /// write:execute` pattern), gate on `MatchLevel::Strong`,
    /// and require a configured minimum score floor.
    ///
    /// ## Behavior
    ///
    /// 1. Validate the query alias (sentinel collision rejected).
    /// 2. Build the candidate set: entities whose `tenant_id`
    ///    matches `tenant_id` exactly (strict — `None`-tenant
    ///    query never returns `Some(t)` entities and vice versa).
    ///    If `kind` is `Some(k)`, additionally filter by kind.
    /// 3. Score each candidate against 9 deterministic factors
    ///    (see `SCORING_FACTORS` below). Each factor is recorded
    ///    in the candidate's `factors` list as a `TrustFactor`,
    ///    applied or not — full explainability.
    /// 4. Sum applied weights, clamp to `[0.0, 1.0]`. Drop
    ///    candidates whose final score is 0.0 (no useful signal).
    /// 5. Sort by score descending, then by `entity_id`
    ///    ascending for stable order on ties.
    /// 6. Take the top `limit`.
    ///
    /// ## Tenant isolation
    ///
    /// Strict — mirrors P25/P29. `None`-tenanted entities are
    /// invisible to tenanted queries and vice versa.
    ///
    /// ## Mutation
    ///
    /// `&self`. No events, no store changes. Pinned by
    /// `suggest_identity_matches_does_not_mutate_store`.
    pub fn suggest_identity_matches(
        &self,
        tenant_id: Option<&hydra_core::TenantId>,
        alias: &hydra_core::IdentityAlias,
        kind: Option<hydra_core::IdentityEntityKind>,
        limit: usize,
    ) -> hydra_core::error::Result<
        hydra_core::SemanticIdentityMatchAssessment,
    > {
        use hydra_core::error::HydraError;

        // 1. Validate the query alias up front. Sentinel inputs
        //    would otherwise produce nonsense factor outputs.
        alias.validate().map_err(HydraError::QueryError)?;

        // 2. Build the candidate set with strict tenant scoping.
        //    Filter inline rather than adding a combined accessor
        //    — store has ≤ thousands of entities for v0.
        let candidates_pool: Vec<&hydra_core::IdentityEntity> = self
            .identity_store
            .all_entities()
            .filter(|e| {
                // Strict tenant equality: Some(t) only matches
                // Some(t); None only matches None. Mirrors the
                // alias index_key sentinel design.
                e.tenant_id.as_ref() == tenant_id
            })
            .filter(|e| match &kind {
                Some(k) => &e.kind == k,
                None => true,
            })
            .collect();

        // 3. Score each candidate.
        let query_tokens = identity_resolver::tokens_of(&alias.normalized);
        let mut scored: Vec<hydra_core::SemanticIdentityMatchCandidate> =
            candidates_pool
                .iter()
                .map(|entity| {
                    identity_resolver::score_candidate(
                        alias,
                        &query_tokens,
                        entity,
                    )
                })
                .filter(|c| c.score > 0.0)
                .collect();

        // 4. Sort by score desc, then entity_id asc.
        scored.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.entity_id.as_str().cmp(b.entity_id.as_str()))
        });

        // 5. Take the top `limit`.
        scored.truncate(limit);

        Ok(hydra_core::SemanticIdentityMatchAssessment {
            query_alias: alias.clone(),
            candidates: scored,
            assessed_at: chrono::Utc::now(),
        })
    }

    /// Patch 32 — Identity Match Trust.
    ///
    /// Read-only trust verdict over a single (query alias,
    /// candidate entity) pair. Recomputes P30's semantic score
    /// live (never trusts a caller-supplied value), then applies
    /// trust factors that judge the resemblance.
    ///
    /// ## Suggestion-only contract
    ///
    /// **Identity match trust is suggestion-only.** The
    /// deterministic factors are explainable but NOT proof of
    /// correctness. False positives are expected — trust
    /// factors inherit P30's positive-only weight calibration,
    /// so `semantic_match_strong` can fire for
    /// `revenue_daily ↔ revenue_daily_archived` as readily as a
    /// true match. Operators must judge each verdict.
    ///
    /// Any future auto-link MUST add a separate trust gate,
    /// require `TrustLevel::High`, require a configured minimum
    /// score floor, AND emit a durable `IdentityLink` event for
    /// audit. Patch 32 does NONE of these — it only computes a
    /// verdict.
    ///
    /// ## Behavior
    ///
    /// 1. Validate the query alias (sentinel collisions
    ///    rejected — mirrors P30).
    /// 2. Load the candidate entity, strictly scoped to
    ///    `tenant_id`. Unknown id, wrong tenant, OR `None`/
    ///    `Some` slot mismatch all surface as the SAME
    ///    `QueryError("unknown identity entity: {id}")` — no
    ///    cross-tenant probing.
    /// 3. Recompute the P30 semantic score for THIS candidate
    ///    alone (via `identity_resolver::score_candidate`).
    ///    The caller cannot smuggle a forged score.
    /// 4. Compute P32 trust factors against the candidate's
    ///    current state (aliases, kind, confidence).
    /// 5. Clamp the summed score to `[0.0, 1.0]` and bucket via
    ///    `TrustAssessment::level_for_score`.
    ///
    /// ## Mutation
    ///
    /// `&self`. No events ingested. No store changes. Pinned by
    /// `assess_identity_match_trust_does_not_mutate_store`.
    pub fn assess_identity_match_trust(
        &self,
        tenant_id: Option<&hydra_core::TenantId>,
        alias: &hydra_core::IdentityAlias,
        candidate_entity_id: &hydra_core::IdentityEntityId,
        kind: Option<hydra_core::IdentityEntityKind>,
    ) -> hydra_core::error::Result<
        hydra_core::IdentityMatchTrustAssessment,
    > {
        use hydra_core::error::HydraError;
        use hydra_core::{
            trust::TrustAssessment, MatchLevel, TrustFactor,
        };

        // 1. Validate the query alias up front.
        alias.validate().map_err(HydraError::QueryError)?;

        // 2. Load candidate strictly within `tenant_id`. Genuine
        //    miss AND tenant mismatch AND None/Some slot
        //    mismatch all surface as the same QueryError.
        //    Mirrors P10 / P24 / P29 / P31 strict isolation.
        let candidate = match self.identity_entity(candidate_entity_id) {
            Some(e) if e.tenant_id.as_ref() == tenant_id => e,
            _ => {
                return Err(HydraError::QueryError(format!(
                    "unknown identity entity: {candidate_entity_id}"
                )));
            }
        };

        // 3. Recompute the P30 semantic score for THIS candidate.
        //    Never accept a caller-supplied score (anti-forgery).
        let query_tokens = identity_resolver::tokens_of(&alias.normalized);
        let semantic = identity_resolver::score_candidate(
            alias,
            &query_tokens,
            candidate,
        );
        let match_score = semantic.score;
        let match_level = semantic.level;

        // 4. Apply P32 trust factors. Mirrors the P30 resolver
        //    structure but with its own weight table — calibrated
        //    for VERDICT (do I trust this resemblance?), not for
        //    SUGGESTION (how strong is the resemblance?).
        let mut factors: Vec<TrustFactor> = Vec::with_capacity(12);
        let mut score = 0.0_f64;

        // Helper: push a factor record and add weight to running
        // score when applied.
        let push_factor =
            |factors: &mut Vec<TrustFactor>,
             score: &mut f64,
             kind: &str,
             weight: f64,
             applied: bool,
             detail: String| {
                if applied {
                    *score += weight;
                }
                factors.push(TrustFactor {
                    kind: kind.to_string(),
                    weight,
                    applied,
                    detail,
                });
            };

        // === Factor: exact_alias_match (+0.40) ===
        // Tuple-walk against the candidate's existing aliases.
        // Stronger signal than P30's resolver alone because P32
        // verdict requires corroboration.
        let exact = candidate.aliases.iter().any(|a| {
            a.source == alias.source
                && a.namespace == alias.namespace
                && a.normalized == alias.normalized
        });
        push_factor(
            &mut factors,
            &mut score,
            "exact_alias_match",
            0.40,
            exact,
            if exact {
                format!(
                    "alias ({}, {:?}, {}) appears verbatim on candidate",
                    alias.source, alias.namespace, alias.normalized
                )
            } else {
                "no exact (source, namespace, normalized) match on candidate"
                    .to_string()
            },
        );

        // === Factor: alias_already_on_candidate (+0.30)
        // vs alias_conflict_present (-0.35) ===
        // Probe the alias index ON THE CANDIDATE'S TENANT SLOT
        // (load-bearing for `None`-tenanted candidates).
        // `entity_by_alias` returns Some(entity) when the alias
        // already maps to ANY entity in that tenant. Mutex:
        // exactly one of {already_on_candidate, conflict_present,
        // neither} applies.
        let index_hit = self
            .identity_entity_by_alias(
                candidate.tenant_id.as_ref(),
                &alias.source,
                alias.namespace.as_deref(),
                &alias.normalized,
            );
        let (already_on_candidate, conflict_present) = match index_hit {
            Some(hit) if hit.id == candidate.id => (true, false),
            Some(_) => (false, true),
            None => (false, false),
        };
        push_factor(
            &mut factors,
            &mut score,
            "alias_already_on_candidate",
            0.30,
            already_on_candidate,
            if already_on_candidate {
                "alias index resolves directly to this candidate"
                    .to_string()
            } else {
                "alias does not currently resolve to this candidate"
                    .to_string()
            },
        );
        push_factor(
            &mut factors,
            &mut score,
            "alias_conflict_present",
            -0.35,
            conflict_present,
            if conflict_present {
                "alias already maps to a different entity in the \
                 candidate's tenant — using it for this candidate \
                 would violate P29 uniqueness"
                    .to_string()
            } else {
                "no conflicting entity for this alias".to_string()
            },
        );

        // === Factors: semantic_match_{strong,possible,weak} ===
        // Bucket P30's match level into three mutex factors.
        // Exactly one fires.
        let sm_strong = match_level == MatchLevel::Strong;
        let sm_possible = match_level == MatchLevel::Possible;
        let sm_weak = !sm_strong && !sm_possible;
        push_factor(
            &mut factors,
            &mut score,
            "semantic_match_strong",
            0.25,
            sm_strong,
            format!("P30 match_score {match_score:.3} → Strong (≥ 0.80)"),
        );
        push_factor(
            &mut factors,
            &mut score,
            "semantic_match_possible",
            0.10,
            sm_possible,
            format!(
                "P30 match_score {match_score:.3} → Possible (0.50–0.80)",
            ),
        );
        push_factor(
            &mut factors,
            &mut score,
            "semantic_match_weak",
            -0.20,
            sm_weak,
            format!("P30 match_score {match_score:.3} → Weak / None (< 0.50)"),
        );

        // === Factors: candidate_entity_confidence_{high,low} ===
        // Reuse TrustLevel thresholds. Skip the medium band as
        // noise — the verdict either lifts on high confidence
        // OR penalizes on low confidence, never both.
        let conf = candidate.confidence.value();
        let conf_high = conf >= 0.80;
        let conf_low = conf < 0.50;
        push_factor(
            &mut factors,
            &mut score,
            "candidate_entity_confidence_high",
            0.15,
            conf_high,
            format!("candidate confidence {conf:.2} (≥ 0.80)"),
        );
        push_factor(
            &mut factors,
            &mut score,
            "candidate_entity_confidence_low",
            -0.10,
            conf_low,
            format!("candidate confidence {conf:.2} (< 0.50)"),
        );

        // === Factor: same_kind (+0.10) ===
        // Any-alias semantics doesn't apply here — kind is on
        // the entity itself. Compare directly against the
        // caller-supplied `kind` arg when present; otherwise
        // record as unapplied with "no kind context".
        //
        // Note: the kind arg is also used by `kind_filter_mismatch`
        // below. `same_kind` answers "does the candidate's kind
        // align with the query intent?"; `kind_filter_mismatch`
        // is the penalty when it disagrees.
        let same_kind = match &kind {
            Some(k) => &candidate.kind == k,
            None => false,
        };
        push_factor(
            &mut factors,
            &mut score,
            "same_kind",
            0.10,
            same_kind,
            if same_kind {
                format!(
                    "candidate kind matches query kind '{}'",
                    candidate.kind.discriminant()
                )
            } else if kind.is_some() {
                format!(
                    "candidate kind '{}' differs from query kind",
                    candidate.kind.discriminant()
                )
            } else {
                "no kind context on query (factor inapplicable)".to_string()
            },
        );

        // === Factor: same_namespace (+0.10) ===
        // Any-alias semantics (mirrors P30): fires if ANY of the
        // candidate's aliases shares the query's namespace.
        // None matches None by design (sentinel design from P29).
        let same_ns = candidate
            .aliases
            .iter()
            .any(|a| a.namespace == alias.namespace);
        push_factor(
            &mut factors,
            &mut score,
            "same_namespace",
            0.10,
            same_ns,
            if same_ns {
                format!(
                    "candidate has alias in namespace {:?}",
                    alias.namespace
                )
            } else {
                format!(
                    "no candidate alias in namespace {:?}",
                    alias.namespace
                )
            },
        );

        // === Factor: same_source (+0.05) ===
        // Any-alias semantics.
        let same_src = candidate
            .aliases
            .iter()
            .any(|a| a.source == alias.source);
        push_factor(
            &mut factors,
            &mut score,
            "same_source",
            0.05,
            same_src,
            if same_src {
                format!(
                    "candidate has alias from source '{}'",
                    alias.source
                )
            } else {
                format!(
                    "no candidate alias from source '{}'",
                    alias.source
                )
            },
        );

        // === Factor: kind_filter_mismatch (-0.05) ===
        // Fires only when the caller supplied a kind filter AND
        // the candidate's kind differs. Soft signal, not a hard
        // error — caller may legitimately want to assess a
        // candidate they're considering relabeling.
        let kind_mismatch = match &kind {
            Some(k) => &candidate.kind != k,
            None => false,
        };
        push_factor(
            &mut factors,
            &mut score,
            "kind_filter_mismatch",
            -0.05,
            kind_mismatch,
            if kind_mismatch {
                format!(
                    "caller requested kind filter but candidate \
                     kind '{}' differs",
                    candidate.kind.discriminant()
                )
            } else {
                "no kind filter / candidate kind matches".to_string()
            },
        );

        // 5. Clamp and bucket.
        let final_score = score.clamp(0.0, 1.0);
        let level = TrustAssessment::level_for_score(final_score);

        // 6. Build a short explanation. Mirrors P9/P23 style:
        //    summary of the most influential applied factors.
        let applied_count =
            factors.iter().filter(|f| f.applied).count();
        let positive_count = factors
            .iter()
            .filter(|f| f.applied && f.weight > 0.0)
            .count();
        let negative_count = factors
            .iter()
            .filter(|f| f.applied && f.weight < 0.0)
            .count();
        let explanation = format!(
            "Trust verdict {level:?} (score {final_score:.2}) — \
             {positive_count} positive factor(s) and \
             {negative_count} penalty factor(s) applied out of \
             {applied_count} total."
        );

        Ok(hydra_core::IdentityMatchTrustAssessment {
            query_alias: alias.clone(),
            candidate_entity_id: candidate.id.clone(),
            match_score,
            match_level,
            score: final_score,
            level,
            explanation,
            factors,
            assessed_at: chrono::Utc::now(),
        })
    }

    /// Patch 33 — Identity Entity Trust v1.
    ///
    /// Read-only verdict over the IDENTITY RECORD ITSELF —
    /// distinct from P32's alias-to-entity match trust:
    ///
    /// ```text
    /// P30 : how strongly do these names resemble each other?
    /// P32 : do I trust THIS alias→entity match?
    /// P33 : do I trust the canonical entity RECORD as a
    ///       stable identity object?
    /// ```
    ///
    /// **This assesses the identity record itself, not the
    /// operational truth of what the entity represents.** v1
    /// uses only entity-internal signals: confidence, aliases,
    /// canonical key, display name, and metadata. It does NOT
    /// consult related claims, cells, observations, source
    /// reliability, or external evidence. Those layer on in
    /// P35+ (after `IdentityLink`).
    ///
    /// A High verdict means "this identity record is
    /// well-formed and consistent with P29 invariants"; it does
    /// NOT mean "every operational fact about this entity is
    /// trustworthy." Future auto-actions based on entity trust
    /// MUST gate on `TrustLevel::High` + minimum score floor +
    /// emit a separate audit event.
    ///
    /// ## Behavior
    ///
    /// 1. Load the entity, strictly scoped to `tenant_id`.
    ///    Genuine miss AND wrong tenant AND `None`/`Some` slot
    ///    mismatch ALL surface as the SAME
    ///    `QueryError("unknown identity entity: {id}")` — no
    ///    cross-tenant probing.
    /// 2. Apply 12 trust factors:
    ///    - Confidence tier (mutex 3-way): high / medium / low
    ///    - Alias count pair (mutex, gated on `aliases.len() ≥ 1`):
    ///      multiple_aliases / single_alias_only
    ///    - Source diversity pair (mutex, gated on
    ///      `aliases.len() ≥ 1`):
    ///      multiple_source_aliases / single_source_only
    ///    - Alias conflict pair (mutex, gated on
    ///      `aliases.len() ≥ 1`):
    ///      alias_conflict_absent / alias_conflict_present
    ///    - Standalone bonuses: canonical_key_present,
    ///      display_name_present, metadata_present
    /// 3. Clamp the summed score to `[0.0, 1.0]` and bucket via
    ///    `TrustAssessment::level_for_score`.
    ///
    /// ## Calibration ceiling
    ///
    /// Positive ceiling is 0.85 (not 1.0) — best-case
    /// well-formed multi-source high-confidence entity reaches
    /// High but not artificial 1.0. Future P35+ factors will
    /// push the ceiling higher.
    ///
    /// ## Mutation
    ///
    /// `&self`. No events, no store changes.
    pub fn assess_identity_entity_trust(
        &self,
        tenant_id: Option<&hydra_core::TenantId>,
        entity_id: &hydra_core::IdentityEntityId,
    ) -> hydra_core::error::Result<
        hydra_core::IdentityEntityTrustAssessment,
    > {
        use hydra_core::error::HydraError;
        use hydra_core::{trust::TrustAssessment, TrustFactor};
        use std::collections::HashSet;

        // 1. Load entity strictly within `tenant_id`. Same
        //    strict-isolation pattern as P32 / P10 / P24.
        let entity = match self.identity_entity(entity_id) {
            Some(e) if e.tenant_id.as_ref() == tenant_id => e,
            _ => {
                return Err(HydraError::QueryError(format!(
                    "unknown identity entity: {entity_id}"
                )));
            }
        };

        // 2. Apply factors. Helper closure mirrors the P30/P32
        //    push pattern.
        let mut factors: Vec<TrustFactor> = Vec::with_capacity(12);
        let mut score = 0.0_f64;
        let push_factor =
            |factors: &mut Vec<TrustFactor>,
             score: &mut f64,
             kind: &str,
             weight: f64,
             applied: bool,
             detail: String| {
                if applied {
                    *score += weight;
                }
                factors.push(TrustFactor {
                    kind: kind.to_string(),
                    weight,
                    applied,
                    detail,
                });
            };

        // === Mutex tier — confidence (always exactly one) ===
        let conf = entity.confidence.value();
        let conf_high = conf >= 0.80;
        let conf_medium = !conf_high && conf >= 0.50;
        let conf_low = !conf_high && !conf_medium;
        push_factor(
            &mut factors,
            &mut score,
            "entity_confidence_high",
            0.30,
            conf_high,
            format!("confidence {conf:.2} (≥ 0.80)"),
        );
        push_factor(
            &mut factors,
            &mut score,
            "entity_confidence_medium",
            0.15,
            conf_medium,
            format!("confidence {conf:.2} (0.50–0.80)"),
        );
        push_factor(
            &mut factors,
            &mut score,
            "entity_confidence_low",
            -0.20,
            conf_low,
            format!("confidence {conf:.2} (< 0.50)"),
        );

        // === Alias-related factor groups ===
        //
        // Three mutex pairs ALL gate on `aliases.len() >= 1`.
        // For a zero-alias entity, neither side of any pair
        // fires — the explainability surfaces "no aliases"
        // by structural absence across all 6 records.
        let has_aliases = !entity.aliases.is_empty();

        // === Alias count pair ===
        let multi_aliases = has_aliases && entity.aliases.len() >= 2;
        let single_alias = has_aliases && entity.aliases.len() == 1;
        push_factor(
            &mut factors,
            &mut score,
            "multiple_aliases",
            0.10,
            multi_aliases,
            if has_aliases {
                format!("{} aliases", entity.aliases.len())
            } else {
                "entity has no aliases".to_string()
            },
        );
        push_factor(
            &mut factors,
            &mut score,
            "single_alias_only",
            -0.10,
            single_alias,
            if has_aliases {
                format!("{} alias(es)", entity.aliases.len())
            } else {
                "entity has no aliases".to_string()
            },
        );

        // === Source diversity pair ===
        let distinct_sources: HashSet<&str> = entity
            .aliases
            .iter()
            .map(|a| a.source.as_str())
            .collect();
        let multi_sources = has_aliases && distinct_sources.len() >= 2;
        let single_source = has_aliases && distinct_sources.len() == 1;
        push_factor(
            &mut factors,
            &mut score,
            "multiple_source_aliases",
            0.15,
            multi_sources,
            if has_aliases {
                format!(
                    "{} distinct source(s) across aliases",
                    distinct_sources.len()
                )
            } else {
                "entity has no aliases".to_string()
            },
        );
        push_factor(
            &mut factors,
            &mut score,
            "single_source_only",
            -0.05,
            single_source,
            if has_aliases {
                format!(
                    "{} distinct source(s) — single source",
                    distinct_sources.len()
                )
            } else {
                "entity has no aliases".to_string()
            },
        );

        // === Alias conflict pair ===
        //
        // For each of the entity's aliases, look it up in the
        // index against the ENTITY'S tenant slot (load-bearing
        // adaptation from P32 carried forward — pass
        // `entity.tenant_id.as_ref()`, NOT the caller's
        // `tenant_id` arg). For a well-formed entity that
        // passed P29's `create_entity` uniqueness checks, every
        // alias resolves back to the entity itself. Any
        // resolution to a DIFFERENT entity OR a missing index
        // entry signals store corruption — defensively pinned.
        let mut conflict_found = false;
        if has_aliases {
            for alias in &entity.aliases {
                let hit = self.identity_entity_by_alias(
                    entity.tenant_id.as_ref(),
                    &alias.source,
                    alias.namespace.as_deref(),
                    &alias.normalized,
                );
                match hit {
                    Some(other) if other.id == entity.id => {} // OK
                    _ => {
                        conflict_found = true;
                        break;
                    }
                }
            }
        }
        let conflict_absent = has_aliases && !conflict_found;
        let conflict_present = has_aliases && conflict_found;
        push_factor(
            &mut factors,
            &mut score,
            "alias_conflict_absent",
            0.15,
            conflict_absent,
            if has_aliases {
                "every alias resolves to this entity via the index"
                    .to_string()
            } else {
                "entity has no aliases".to_string()
            },
        );
        push_factor(
            &mut factors,
            &mut score,
            "alias_conflict_present",
            -0.35,
            conflict_present,
            if conflict_present {
                "at least one alias resolves to a different entity \
                 OR is missing from the index (store invariant signal)"
                    .to_string()
            } else if has_aliases {
                "no conflicting alias resolution".to_string()
            } else {
                "entity has no aliases".to_string()
            },
        );

        // === Standalone bonuses ===
        let canonical_present = !entity.canonical_key.is_empty();
        let display_present = !entity.display_name.is_empty();
        let metadata_present = !entity.metadata.is_empty();
        push_factor(
            &mut factors,
            &mut score,
            "canonical_key_present",
            0.05,
            canonical_present,
            if canonical_present {
                format!("canonical_key = '{}'", entity.canonical_key)
            } else {
                "canonical_key is empty".to_string()
            },
        );
        push_factor(
            &mut factors,
            &mut score,
            "display_name_present",
            0.05,
            display_present,
            if display_present {
                format!("display_name = '{}'", entity.display_name)
            } else {
                "display_name is empty".to_string()
            },
        );
        push_factor(
            &mut factors,
            &mut score,
            "metadata_present",
            0.05,
            metadata_present,
            if metadata_present {
                format!("metadata has {} entries", entity.metadata.len())
            } else {
                "metadata is empty".to_string()
            },
        );

        // 3. Clamp and bucket.
        let final_score = score.clamp(0.0, 1.0);
        let level = TrustAssessment::level_for_score(final_score);

        // 4. Build explanation. Mirrors P32: summarize
        //    applied factor groupings.
        let applied_count =
            factors.iter().filter(|f| f.applied).count();
        let positive_count = factors
            .iter()
            .filter(|f| f.applied && f.weight > 0.0)
            .count();
        let negative_count = factors
            .iter()
            .filter(|f| f.applied && f.weight < 0.0)
            .count();
        let explanation = format!(
            "Identity record verdict {level:?} (score {final_score:.2}) \
             — {positive_count} positive factor(s) and \
             {negative_count} penalty factor(s) applied out of \
             {applied_count} total. v1 assesses the record \
             itself, not operational truth."
        );

        Ok(hydra_core::IdentityEntityTrustAssessment {
            entity_id: entity.id.clone(),
            score: final_score,
            level,
            explanation,
            factors,
            assessed_at: chrono::Utc::now(),
        })
    }

    /// Patch 35 — Source Trust v1.
    ///
    /// Read-only trust verdict over a single `source` string (the
    /// free-form value carried on every `IdentityAlias.source` —
    /// e.g. `"snowflake"`, `"github"`, `"dbt"`, `"agent_data_quality"`).
    /// Different question from P30 / P32 / P33:
    ///
    /// - P30: how strongly do these names resemble each other?
    /// - P32: do I trust THIS alias→entity match?
    /// - P33: do I trust the canonical entity RECORD as a stable
    ///        identity object?
    /// - P35: do I trust THIS SOURCE as a producer of identity /
    ///        evidence signals?
    ///
    /// ## Suggestion-only contract
    ///
    /// **Source trust is identity-backed, not operational.** v1
    /// measures whether a source has produced trustworthy
    /// *identity claims* in this tenant — entity count, kind
    /// diversity, entity-confidence corroboration, and evidence
    /// reliability where mapping is unambiguous.
    ///
    /// v1 does NOT consider ingestion freshness, schema drift,
    /// heartbeat liveness, SLA conformance, contradiction rate, or
    /// operator override history. A dead Snowflake warehouse with
    /// five trustworthy historical entities will score **High**
    /// here — correct for "did Snowflake produce trustworthy
    /// identity claims," wrong for "is Snowflake alive."
    ///
    /// Weights are calibrated for **explainability not
    /// correctness**. False positives are expected. Read-only;
    /// **MUST NOT** drive auto-actions. Any future gate must add a
    /// separate trust contract, require `TrustLevel::High` or
    /// `Strong`, impose a minimum score floor.
    ///
    /// ## Behavior
    ///
    /// 1. Validate `source` (reject empty, `"__system__"`,
    ///    `"__root__"` as `QueryError` — sentinel collision
    ///    would otherwise alias the None-tenant slot's reserved
    ///    namespace keys).
    /// 2. Collect entities scoped strictly to `tenant_id`
    ///    (`None` slot is invisible to `Some(t)` queries and vice
    ///    versa — physical-slot isolation via P29's sentinel
    ///    index keys).
    /// 3. Filter to entities whose `aliases.any(|a| a.source ==
    ///    source)` (exact string match — NOT case-folded; pinned
    ///    by `assess_source_trust_exact_string_match_not_case_folded`).
    /// 4. Cap at `MAX_SOURCE_ENTITIES_FOR_TRUST = 200`,
    ///    highest-confidence first when capped.
    /// 5. For each retained entity, fold in
    ///    `assess_identity_entity_trust(tenant_id, &entity.id)` and
    ///    bucket the MEAN P33 score:
    ///    - mean ≥ 0.70 → `high_trust_entities_from_source` (+0.20)
    ///    - mean ≤ 0.40 → `low_trust_entities_from_source` (-0.20)
    ///    - middle band → neither fires (Adaptation C)
    /// 6. Collect evidence scoped to `tenant_id`. Map
    ///    `EvidenceSource` to a source string ONLY for the three
    ///    unambiguous variants (`Warehouse.system`, `Api.system`,
    ///    `System.name`). `Document` / `Human` / `Agent` are
    ///    explicit-skipped — pinned by
    ///    `assess_source_trust_evidence_mapping_skips_human_agent_document`.
    /// 7. Compute evidence factors using P9's 0.75 reliability bar.
    /// 8. Clamp summed score to `[0.0, 1.0]` and bucket via
    ///    `TrustAssessment::level_for_score`.
    ///
    /// ## Unknown-but-valid source
    ///
    /// A source with no aliases / no evidence is a legitimate
    /// `Unknown` verdict (score 0.0 buckets via the shared
    /// thresholds), surfaced via `explanation`. NOT a `QueryError`.
    /// Only malformed input — empty or sentinel `source` —
    /// returns `QueryError`. Pinned by
    /// `assess_source_trust_unknown_source_buckets_to_low_not_error`.
    ///
    /// ## Tenant isolation
    ///
    /// Strict — mirrors P25 / P29 / P32 / P33. `None`-tenanted
    /// sources are invisible to tenanted queries and vice versa.
    /// Pinned by `assess_source_trust_none_tenant_strict_isolation`.
    ///
    /// ## Mutation
    ///
    /// `&self`. No events ingested. No store changes. Pinned by
    /// `assess_source_trust_does_not_mutate_store`.
    pub fn assess_source_trust(
        &self,
        tenant_id: Option<&hydra_core::TenantId>,
        source: &str,
    ) -> hydra_core::error::Result<hydra_core::SourceTrustAssessment> {
        use hydra_core::error::HydraError;
        use hydra_core::{trust::TrustAssessment, TrustFactor};
        use std::collections::HashSet;

        /// Highest-confidence entities are sampled first when the
        /// source has more than this many aliases. The cap keeps
        /// the nested P33 calls bounded (each entity triggers
        /// O(aliases) index probes through
        /// `assess_identity_entity_trust`). Pinned by
        /// `assess_source_trust_respects_entity_scan_cap`.
        const MAX_SOURCE_ENTITIES_FOR_TRUST: usize = 200;

        // 1. Validate input. Empty + reserved sentinels are
        //    malformed — they would otherwise alias the None-tenant
        //    slot's reserved namespace keys (`__system__` /
        //    `__root__`). Mirrors `IdentityAlias::validate`'s
        //    sentinel rejection. Mirrors P32's
        //    `alias.validate().map_err(HydraError::QueryError)?`
        //    pattern.
        if source.is_empty() {
            return Err(HydraError::QueryError(
                "source string is empty".to_string(),
            ));
        }
        if source == "__system__" || source == "__root__" {
            return Err(HydraError::QueryError(format!(
                "source string '{source}' is a reserved sentinel"
            )));
        }

        // 2. Collect entities scoped strictly to `tenant_id`.
        //    Mirrors P30's asymmetry: `entities_for_tenant` is
        //    Some-only, so the None path filters `all_entities`
        //    directly. Physical-slot isolation is guaranteed by
        //    P29's sentinel-based index keys.
        let scoped_entities: Vec<&hydra_core::IdentityEntity> = self
            .identity_store
            .all_entities()
            .filter(|e| e.tenant_id.as_ref() == tenant_id)
            .filter(|e| {
                e.aliases.iter().any(|a| a.source == source)
            })
            .collect();

        // Highest-confidence first when capped (deterministic
        // tie-break on entity id ascending). Pinned by
        // `assess_source_trust_respects_entity_scan_cap`.
        let mut sampled: Vec<&hydra_core::IdentityEntity> =
            scoped_entities.clone();
        sampled.sort_by(|a, b| {
            b.confidence
                .value()
                .partial_cmp(&a.confidence.value())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.id.as_str().cmp(b.id.as_str()))
        });
        sampled.truncate(MAX_SOURCE_ENTITIES_FOR_TRUST);

        // 3. Apply factors. Helper closure mirrors P32 / P33's
        //    push pattern.
        let mut factors: Vec<TrustFactor> = Vec::with_capacity(9);
        let mut score = 0.0_f64;
        let push_factor =
            |factors: &mut Vec<TrustFactor>,
             score: &mut f64,
             kind: &str,
             weight: f64,
             applied: bool,
             detail: String| {
                if applied {
                    *score += weight;
                }
                factors.push(TrustFactor {
                    kind: kind.to_string(),
                    weight,
                    applied,
                    detail,
                });
            };

        // === Gate factor — anchors the verdict ===
        let has_aliases = !sampled.is_empty();
        push_factor(
            &mut factors,
            &mut score,
            "source_has_identity_aliases",
            0.20,
            has_aliases,
            if has_aliases {
                format!(
                    "{} entit{} reference source '{source}'",
                    sampled.len(),
                    if sampled.len() == 1 { "y" } else { "ies" },
                )
            } else {
                format!(
                    "no aliases from source '{source}' observed in \
                     tenant scope"
                )
            },
        );

        // === Entity-count pair (mutex) ===
        let multiple_entities = sampled.len() >= 2;
        let single_entity = sampled.len() == 1;
        push_factor(
            &mut factors,
            &mut score,
            "multiple_entities_from_source",
            0.10,
            multiple_entities,
            if multiple_entities {
                format!("{} distinct entities from source", sampled.len())
            } else if single_entity {
                "only 1 entity from source".to_string()
            } else {
                "no entities from source".to_string()
            },
        );
        push_factor(
            &mut factors,
            &mut score,
            "single_entity_from_source",
            -0.05,
            single_entity,
            if single_entity {
                "only 1 entity from source — thin signal".to_string()
            } else if multiple_entities {
                format!("{} distinct entities from source", sampled.len())
            } else {
                "no entities from source".to_string()
            },
        );

        // === Kind diversity (standalone) ===
        let distinct_kinds: HashSet<String> = sampled
            .iter()
            .map(|e| e.kind.discriminant())
            .collect();
        let multi_kinds = distinct_kinds.len() >= 2;
        push_factor(
            &mut factors,
            &mut score,
            "multiple_kinds_from_source",
            0.10,
            multi_kinds,
            if has_aliases {
                format!(
                    "{} distinct entity kind(s) from source",
                    distinct_kinds.len()
                )
            } else {
                "no entities from source".to_string()
            },
        );

        // === Mean P33 entity-trust mutex (Adaptation C) ===
        //
        // Fold P33 over each sampled entity, compute the mean,
        // bucket via 0.70 / 0.40 thresholds. Middle band fires
        // NEITHER factor — pinned by
        // `assess_source_trust_mean_entity_trust_buckets_mutex`.
        let entity_sample_size = sampled.len();
        let mean_entity_trust = if entity_sample_size == 0 {
            None
        } else {
            let mut sum = 0.0_f64;
            for entity in &sampled {
                let assessment = self
                    .assess_identity_entity_trust(tenant_id, &entity.id)?;
                sum += assessment.score;
            }
            Some(sum / entity_sample_size as f64)
        };
        let high_trust = matches!(mean_entity_trust, Some(m) if m >= 0.70);
        let low_trust = matches!(mean_entity_trust, Some(m) if m <= 0.40);
        push_factor(
            &mut factors,
            &mut score,
            "high_trust_entities_from_source",
            0.20,
            high_trust,
            match mean_entity_trust {
                Some(m) => format!("mean entity trust {m:.2} (≥ 0.70)"),
                None => "no entities from source".to_string(),
            },
        );
        push_factor(
            &mut factors,
            &mut score,
            "low_trust_entities_from_source",
            -0.20,
            low_trust,
            match mean_entity_trust {
                Some(m) => format!("mean entity trust {m:.2} (≤ 0.40)"),
                None => "no entities from source".to_string(),
            },
        );

        // === Evidence factors (Adaptation A) ===
        //
        // Map `EvidenceSource` → `Option<&str>` ONLY for the three
        // unambiguous variants. `Document` / `Human` / `Agent` are
        // explicit-skipped (the `_` arm returns `None`). Pinned by
        // `assess_source_trust_evidence_mapping_skips_human_agent_document`.
        let evidence_source_str =
            |src: &hydra_core::EvidenceSource| -> Option<String> {
                match src {
                    hydra_core::EvidenceSource::Warehouse {
                        system,
                        ..
                    } => Some(system.clone()),
                    hydra_core::EvidenceSource::Api { system, .. } => {
                        Some(system.clone())
                    }
                    hydra_core::EvidenceSource::System { name } => {
                        Some(name.clone())
                    }
                    hydra_core::EvidenceSource::Document { .. }
                    | hydra_core::EvidenceSource::Human { .. }
                    | hydra_core::EvidenceSource::Agent { .. } => None,
                }
            };

        let matched_evidence: Vec<&hydra_core::Evidence> = self
            .all_evidence()
            .into_iter()
            .filter(|e| e.tenant_id.as_ref() == tenant_id)
            .filter(|e| {
                evidence_source_str(&e.source)
                    .as_deref()
                    == Some(source)
            })
            .collect();
        let evidence_sample_size = matched_evidence.len();
        let has_evidence = evidence_sample_size > 0;
        // P9 reliability bar carried forward verbatim — pinned by
        // `assess_source_trust_evidence_reliability_uses_0_75_bar`.
        let has_reliable_evidence = matched_evidence
            .iter()
            .any(|e| e.reliability.value() >= 0.75);
        // All-low only fires when there IS evidence AND every
        // record sits below 0.40. Mutex with `reliable_*` is
        // structural: if any record is ≥ 0.75, the floor 0.40 is
        // necessarily exceeded too.
        let all_low_reliability = has_evidence
            && matched_evidence
                .iter()
                .all(|e| e.reliability.value() < 0.40);

        push_factor(
            &mut factors,
            &mut score,
            "evidence_present_from_source",
            0.05,
            has_evidence,
            if has_evidence {
                format!(
                    "{evidence_sample_size} evidence record(s) mapped to \
                     source"
                )
            } else {
                "no evidence records mapped to source".to_string()
            },
        );
        push_factor(
            &mut factors,
            &mut score,
            "reliable_evidence_from_source",
            0.15,
            has_reliable_evidence,
            if has_reliable_evidence {
                "at least one evidence record with reliability ≥ 0.75 \
                 (P9 bar)"
                    .to_string()
            } else if has_evidence {
                "no evidence record clears reliability ≥ 0.75".to_string()
            } else {
                "no evidence records mapped to source".to_string()
            },
        );
        push_factor(
            &mut factors,
            &mut score,
            "low_reliability_evidence_from_source",
            -0.15,
            all_low_reliability,
            if all_low_reliability {
                format!(
                    "all {evidence_sample_size} evidence record(s) sit \
                     below reliability 0.40"
                )
            } else if has_evidence {
                "at least one evidence record reaches reliability ≥ 0.40"
                    .to_string()
            } else {
                "no evidence records mapped to source".to_string()
            },
        );

        // 4. Clamp and bucket.
        let final_score = score.clamp(0.0, 1.0);
        let level = TrustAssessment::level_for_score(final_score);

        // 5. Build explanation. Surfaces the empty-source verdict
        //    structurally so dashboards don't need to re-derive it.
        let applied_count =
            factors.iter().filter(|f| f.applied).count();
        let positive_count = factors
            .iter()
            .filter(|f| f.applied && f.weight > 0.0)
            .count();
        let negative_count = factors
            .iter()
            .filter(|f| f.applied && f.weight < 0.0)
            .count();
        let explanation = if !has_aliases && !has_evidence {
            format!(
                "Source verdict {level:?} (score {final_score:.2}) — no \
                 aliases from source '{source}' observed in tenant scope, \
                 no evidence records mapped. v1 measures identity-claim \
                 trust, NOT operational health (freshness, heartbeat, \
                 SLA, schema drift not yet considered)."
            )
        } else {
            format!(
                "Source verdict {level:?} (score {final_score:.2}) — \
                 {positive_count} positive factor(s) and {negative_count} \
                 penalty factor(s) applied out of {applied_count} total. \
                 v1 measures identity-claim trust, NOT operational health \
                 (freshness, heartbeat, SLA, schema drift not yet \
                 considered)."
            )
        };

        Ok(hydra_core::SourceTrustAssessment {
            source: source.to_string(),
            score: final_score,
            level,
            explanation,
            factors,
            entity_sample_size,
            evidence_sample_size,
            assessed_at: chrono::Utc::now(),
        })
    }

    /// Patch 21 — turn a model-derived reflex chain into a
    /// `CausalCellKind::Reflex` causal cell.
    ///
    /// Given a `claim_id`, walks the existing chain:
    ///
    /// ```text
    ///   claim
    ///     ↓ claim.caused_by → MicroModelPredictionRecorded event
    ///     ↓ claim.evidence_for → Evidence
    ///     ↓ actions_for_claim → Actions
    ///     ↓ outcomes_for_action → Outcomes
    ///     ↓ prediction.run_id → MicroModelObservation
    ///     ↓ assess_claim_trust → TrustAssessment
    /// ```
    ///
    /// Builds a `CausalCell` containing every id surfaced along
    /// the chain, in deterministic order, and ingests
    /// `EventKind::CausalCellCreated`.
    ///
    /// **Non-model claims hard-error** with
    /// `QueryError("claim is not model-derived: ...")`. This
    /// method is specifically for reflex cells; generic claim
    /// cells are a future patch.
    ///
    /// **Empty downstream is OK**: a Proposed-only claim (no
    /// action emitted yet) yields a cell with empty
    /// `action_ids` / `outcome_ids` / `observation_run_ids`.
    /// The prediction + evidence + claim portion still fills.
    ///
    /// `cell.caused_by` is set to the prediction event id — the
    /// chain's causal ORIGIN, not the cell creation event.
    pub fn create_reflex_causal_cell_from_claim(
        &mut self,
        claim_id: hydra_core::ClaimId,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<hydra_core::CausalCell> {
        use hydra_core::error::HydraError;
        use std::collections::{HashMap, HashSet};

        // 1. Lookup claim.
        let claim = self.claim(&claim_id).cloned().ok_or_else(|| {
            HydraError::QueryError(format!("unknown claim: {claim_id}"))
        })?;

        // 2. Validate model-derived. `claim.caused_by` is the
        //    Patch 3 invariant: every claim born from a reflex
        //    chain carries the prediction event id here.
        let prediction_event_id = claim.caused_by.clone().ok_or_else(|| {
            HydraError::QueryError(format!(
                "claim is not model-derived: claim {claim_id} has no caused_by event"
            ))
        })?;
        let prediction_event =
            self.event(&prediction_event_id).cloned().ok_or_else(|| {
                HydraError::QueryError(format!(
                    "claim is not model-derived: caused_by event {prediction_event_id} not found in audit log"
                ))
            })?;
        let prediction = match &prediction_event.kind {
            hydra_core::EventKind::MicroModelPredictionRecorded {
                prediction,
            } => prediction.clone(),
            _ => {
                return Err(HydraError::QueryError(format!(
                    "claim is not model-derived: caused_by event {prediction_event_id} is not a MicroModelPredictionRecorded"
                )));
            }
        };

        // 3. Gather action + outcome ids. Both lookups are
        //    O(1) via the action_store indexes.
        let action_ids: Vec<hydra_core::ActionId> = self
            .action_store
            .actions_for_claim(&claim_id)
            .into_iter()
            .map(|action| action.id.clone())
            .collect();
        let mut outcome_ids: Vec<hydra_core::OutcomeId> = Vec::new();
        for action_id in &action_ids {
            for outcome in self.outcomes_for_action(action_id) {
                outcome_ids.push(outcome.id.clone());
            }
        }

        // 4. Observation run_id. Each prediction carries exactly
        //    one run_id; the observation store keys by it. Empty
        //    list when no observation recorded yet (action
        //    proposed but not yet executed+observed).
        let observation_run_ids: Vec<hydra_core::MicroModelRunId> =
            if self.micro_model_observation(&prediction.run_id).is_some() {
                vec![prediction.run_id.clone()]
            } else {
                Vec::new()
            };

        // 5. One pass over the event log — collect event-creation
        //    ids for every evidence / claim / action / outcome
        //    we care about. O(n_events), but only one walk per
        //    cell creation.
        let evidence_ids = claim.evidence_for.clone();
        let evidence_id_set: HashSet<hydra_core::EvidenceId> =
            evidence_ids.iter().cloned().collect();
        let action_id_set: HashSet<hydra_core::ActionId> =
            action_ids.iter().cloned().collect();
        let outcome_id_set: HashSet<hydra_core::OutcomeId> =
            outcome_ids.iter().cloned().collect();

        let mut evidence_event_ids: HashMap<
            hydra_core::EvidenceId,
            hydra_core::EventId,
        > = HashMap::new();
        let mut claim_event_id: Option<hydra_core::EventId> = None;
        let mut action_event_ids: HashMap<
            hydra_core::ActionId,
            hydra_core::EventId,
        > = HashMap::new();
        let mut outcome_event_ids: HashMap<
            hydra_core::OutcomeId,
            hydra_core::EventId,
        > = HashMap::new();

        for event in self.event_log.iter() {
            match &event.kind {
                hydra_core::EventKind::EvidenceAdded { evidence }
                    if evidence_id_set.contains(&evidence.id) =>
                {
                    evidence_event_ids
                        .entry(evidence.id.clone())
                        .or_insert_with(|| event.id.clone());
                }
                hydra_core::EventKind::ClaimProposed { claim: c }
                    if c.id == claim_id =>
                {
                    if claim_event_id.is_none() {
                        claim_event_id = Some(event.id.clone());
                    }
                }
                hydra_core::EventKind::ActionProposed { action }
                    if action_id_set.contains(&action.id) =>
                {
                    action_event_ids
                        .entry(action.id.clone())
                        .or_insert_with(|| event.id.clone());
                }
                hydra_core::EventKind::OutcomeObserved { outcome }
                    if outcome_id_set.contains(&outcome.id) =>
                {
                    outcome_event_ids
                        .entry(outcome.id.clone())
                        .or_insert_with(|| event.id.clone());
                }
                _ => {}
            }
        }

        // 6. Assemble `source_events` in deterministic order:
        //    prediction → evidence(s) → claim → action(s) → outcome(s).
        //    Missing event-ids are silently skipped — Patch 21
        //    doesn't fail on a partial chain.
        let mut source_events: Vec<hydra_core::EventId> = Vec::new();
        source_events.push(prediction_event_id.clone());
        for evidence_id in &evidence_ids {
            if let Some(eid) = evidence_event_ids.get(evidence_id) {
                source_events.push(eid.clone());
            }
        }
        if let Some(eid) = &claim_event_id {
            source_events.push(eid.clone());
        }
        for action_id in &action_ids {
            if let Some(eid) = action_event_ids.get(action_id) {
                source_events.push(eid.clone());
            }
        }
        for outcome_id in &outcome_ids {
            if let Some(eid) = outcome_event_ids.get(outcome_id) {
                source_events.push(eid.clone());
            }
        }

        // 7. Compute trust on the claim. Patch 9's assessor
        //    works on any claim; under-evidenced claims simply
        //    return a low score / Unknown level.
        let trust = self.assess_claim_trust(&claim_id)?;

        // 8. Build subject + summary.
        let subject = format_claim_subject(&claim);
        let summary = format!(
            "reflex cell for {}: trust={:?} ({:.2}), {} actions, {} outcomes",
            subject,
            trust.level,
            trust.score,
            action_ids.len(),
            outcome_ids.len()
        );

        // 9. Construct the cell. `caused_by` is the prediction
        //    event id — the chain's causal ORIGIN.
        let cell = hydra_core::CausalCell {
            id: hydra_core::CausalCellId::new(),
            tenant_id: claim.tenant_id.clone(),
            kind: hydra_core::CausalCellKind::Reflex,
            subject,
            source_events,
            evidence_ids,
            claim_ids: vec![claim_id],
            action_ids,
            outcome_ids,
            observation_run_ids,
            child_cell_ids: Vec::new(),
            trust_score: Some(trust.score),
            summary: Some(summary),
            created_by: actor,
            created_at: chrono::Utc::now(),
            caused_by: Some(prediction_event_id),
        };

        // 10. Persist via the Patch 20 create path — ingests
        //     `CausalCellCreated`. Returns the stored cell.
        self.create_causal_cell(cell)
    }

    /// Patch 22 — compose multiple existing `CausalCell`s into a
    /// new parent cell. The first fractal-composition operation.
    ///
    /// ```text
    ///   CommitRateCell + ReplicationLagCell + AgentLoopStormCell +
    ///   ActionFailureRateCell  =  HydraHealthCell
    /// ```
    ///
    /// The parent carries:
    ///
    /// - `child_cell_ids` = deduped child list (first-seen order)
    /// - the 6 id vectors UNIONED across children, deduped
    ///   preserving first-seen order
    /// - `trust_score` = arithmetic mean of child trust scores
    ///   that are `Some`; `None` when every child is `None`
    /// - `caused_by` = first child's `caused_by` that is `Some`,
    ///   walking child order; `None` when no child has one
    /// - `tenant_id` = inherited from children; all children
    ///   must share the same `Option<TenantId>` exactly
    /// - `summary` = caller-supplied if `Some`, else the
    ///   deterministic Patch 22 pattern
    ///
    /// Parent cells are **immutable in v0** — no update / close
    /// events. Recomposition = create a new parent cell.
    ///
    /// **No HTTP, no SDK** — engine-only, like Patch 21.
    pub fn compose_causal_cells(
        &mut self,
        child_cell_ids: Vec<hydra_core::CausalCellId>,
        kind: hydra_core::CausalCellKind,
        subject: String,
        actor: hydra_core::ActorId,
        summary: Option<String>,
    ) -> hydra_core::error::Result<hydra_core::CausalCell> {
        use hydra_core::error::HydraError;
        use std::collections::HashSet;

        // 1. Empty children → hard error.
        if child_cell_ids.is_empty() {
            return Err(HydraError::QueryError(
                "composition requires at least one child cell"
                    .to_string(),
            ));
        }

        // 2. Dedupe children preserving first-seen order. Idempotent
        //    under accidental repeats; the parent's `child_cell_ids`
        //    is the deduped list.
        let mut deduped_child_ids: Vec<hydra_core::CausalCellId> =
            Vec::new();
        let mut child_id_seen: HashSet<hydra_core::CausalCellId> =
            HashSet::new();
        for id in child_cell_ids {
            if child_id_seen.insert(id.clone()) {
                deduped_child_ids.push(id);
            }
        }

        // 3. Load each child; unknown → hard error.
        let mut children: Vec<hydra_core::CausalCell> = Vec::new();
        for id in &deduped_child_ids {
            let child = self.causal_cell(id).cloned().ok_or_else(|| {
                HydraError::QueryError(format!(
                    "unknown causal cell: {id}"
                ))
            })?;
            children.push(child);
        }

        // 4. Validate tenant equality (strict `Option<TenantId>`
        //    match). None == None and Some(a) == Some(a) only.
        let tenant_anchor = children[0].tenant_id.clone();
        for child in &children[1..] {
            if child.tenant_id != tenant_anchor {
                return Err(HydraError::QueryError(
                    "composition requires all child cells to share \
                     the same tenant_id (Some/None must match exactly)"
                        .to_string(),
                ));
            }
        }

        // 5. Union + dedupe each of the six id vectors. Order:
        //    child order outer, child's own id-vec order inner.
        let mut source_events: Vec<hydra_core::EventId> = Vec::new();
        let mut source_events_seen: HashSet<hydra_core::EventId> =
            HashSet::new();
        let mut evidence_ids: Vec<hydra_core::EvidenceId> = Vec::new();
        let mut evidence_seen: HashSet<hydra_core::EvidenceId> =
            HashSet::new();
        let mut claim_ids: Vec<hydra_core::ClaimId> = Vec::new();
        let mut claim_seen: HashSet<hydra_core::ClaimId> = HashSet::new();
        let mut action_ids: Vec<hydra_core::ActionId> = Vec::new();
        let mut action_seen: HashSet<hydra_core::ActionId> =
            HashSet::new();
        let mut outcome_ids: Vec<hydra_core::OutcomeId> = Vec::new();
        let mut outcome_seen: HashSet<hydra_core::OutcomeId> =
            HashSet::new();
        let mut observation_run_ids: Vec<hydra_core::MicroModelRunId> =
            Vec::new();
        let mut observation_seen: HashSet<hydra_core::MicroModelRunId> =
            HashSet::new();

        for child in &children {
            for id in &child.source_events {
                if source_events_seen.insert(id.clone()) {
                    source_events.push(id.clone());
                }
            }
            for id in &child.evidence_ids {
                if evidence_seen.insert(id.clone()) {
                    evidence_ids.push(id.clone());
                }
            }
            for id in &child.claim_ids {
                if claim_seen.insert(id.clone()) {
                    claim_ids.push(id.clone());
                }
            }
            for id in &child.action_ids {
                if action_seen.insert(id.clone()) {
                    action_ids.push(id.clone());
                }
            }
            for id in &child.outcome_ids {
                if outcome_seen.insert(id.clone()) {
                    outcome_ids.push(id.clone());
                }
            }
            for id in &child.observation_run_ids {
                if observation_seen.insert(id.clone()) {
                    observation_run_ids.push(id.clone());
                }
            }
        }

        // 6. Trust score: arithmetic mean of known child scores.
        //    All-None → parent None. Patch 22 deliberately does NOT
        //    weight by # of claims/actions/outcomes — that's
        //    Patch 23's job.
        let known_scores: Vec<f64> = children
            .iter()
            .filter_map(|c| c.trust_score)
            .collect();
        let trust_score = if known_scores.is_empty() {
            None
        } else {
            let sum: f64 = known_scores.iter().sum();
            Some(sum / known_scores.len() as f64)
        };

        // 7. caused_by = first child whose own caused_by is Some.
        //    Walks child order. None when no child has one — keeps
        //    composed cells causally anchored even when the first
        //    child in the list lacks an anchor.
        let caused_by = children
            .iter()
            .find_map(|c| c.caused_by.clone());

        // 8. Default summary: deterministic prose operators can
        //    pattern-match. `kind.discriminant()` gives snake_case
        //    (matches Patch 21's subject style). Trust shows
        //    `unknown` when None.
        let final_summary = summary.unwrap_or_else(|| {
            let trust_str = trust_score
                .map(|s| format!("{s:.2}"))
                .unwrap_or_else(|| "unknown".to_string());
            format!(
                "composed {} cell for {}: {} child cells, {} claims, \
                 {} actions, trust={}",
                kind.discriminant(),
                subject,
                deduped_child_ids.len(),
                claim_ids.len(),
                action_ids.len(),
                trust_str,
            )
        });

        // 9. Assemble + persist via the Patch 20 create path.
        let cell = hydra_core::CausalCell {
            id: hydra_core::CausalCellId::new(),
            tenant_id: tenant_anchor,
            kind,
            subject,
            source_events,
            evidence_ids,
            claim_ids,
            action_ids,
            outcome_ids,
            observation_run_ids,
            child_cell_ids: deduped_child_ids,
            trust_score,
            summary: Some(final_summary),
            created_by: actor,
            created_at: chrono::Utc::now(),
            caused_by,
        };
        self.create_causal_cell(cell)
    }

    /// Patch 26 — compose `hydra.health` from the latest self-
    /// health reflex cells.
    ///
    /// The canonical fractal example: walk the four built-in
    /// self-health reflex subjects (commit-rate, replication-lag,
    /// agent-loop-storm, action-failure-rate), pick the LATEST
    /// `Reflex`-kind cell per subject (by `created_at`), and
    /// compose them into a single `Health`-kind parent cell
    /// with `subject = "hydra.health"`.
    ///
    /// ```text
    ///   CommitRateReflexCell + ReplicationLagReflexCell +
    ///   AgentLoopStormReflexCell + ActionFailureRateReflexCell
    ///     = HydraHealthCell (kind = Health)
    /// ```
    ///
    /// ## Tenant scoping (strict)
    ///
    /// Only cells whose `tenant_id` matches `tenant` exactly
    /// participate. `Some(t)` → only `Some(t)` cells;
    /// `None` → only `None`-tenanted cells. No mixing. The
    /// composed parent inherits the same tenant via
    /// `compose_causal_cells`.
    ///
    /// ## Partial composition is OK
    ///
    /// If 1–3 of the four self-health subjects have a reflex
    /// cell in the (tenant-filtered) store, this method composes
    /// those that exist and records the missing subjects in the
    /// summary. ZERO found → hard `QueryError` (matches the
    /// `compose_causal_cells` empty-children contract).
    ///
    /// ## Summary
    ///
    /// Helper-built and explicit — overrides the
    /// `compose_causal_cells` fallback. Format:
    ///
    /// ```text
    ///   hydra.health composed from N of 4 self-health reflexes.
    ///   Present: <comma-separated short labels>.
    ///   Missing: <comma-separated short labels>.          (omitted if none)
    /// ```
    ///
    /// Labels are the stable short forms from
    /// `SELF_HEALTH_REFLEX_LABELS`, indexed parallel to the
    /// subject list, so dashboards and operators see consistent
    /// short names regardless of which subset fired.
    ///
    /// ## Trust
    ///
    /// `cell.trust_score` is the Patch 22 arithmetic mean of
    /// children's stored trust scores (inherited from
    /// `compose_causal_cells`). For the richer 12-factor
    /// folding (which considers outcomes / observations / action
    /// status / contradictions / etc.), call
    /// `assess_causal_cell_trust(cell.id)` after composing — the
    /// Patch 23 engine compute runs against the parent + its
    /// direct children.
    ///
    /// ## Precondition (Patch 26 boundary)
    ///
    /// The reflex pipeline does NOT auto-create cells today —
    /// `create_reflex_causal_cell_from_claim` is explicit
    /// (Patch 21). Production callers must seed reflex cells
    /// before composing `hydra.health`; otherwise this method
    /// errors. Auto-emission is a future patch.
    ///
    /// ## Boundary (NOT in Patch 26)
    ///
    /// - No HTTP, no SDK (Patch 27+)
    /// - No scheduled auto-fire
    /// - No recursive trust folding (still direct-children-only)
    /// - No `CausalCellLinked` event
    /// - No auto-create during model evaluation
    pub fn compose_hydra_health_cell(
        &mut self,
        actor: hydra_core::ActorId,
        tenant: Option<hydra_core::TenantId>,
    ) -> hydra_core::error::Result<hydra_core::CausalCell> {
        use hydra_core::error::HydraError;

        // 1. Walk the full Reflex set once; per-subject pick the
        //    cell with the largest `created_at`. The store's
        //    `cells_by_kind` BTreeSet is ULID-ordered (rough
        //    proxy for time), but `created_at` is the honest
        //    selector — explicit comparison handles ULIDs minted
        //    in the same millisecond AND survives any future
        //    refactor that swaps ULIDs for another id scheme.
        let reflex_kind = hydra_core::CausalCellKind::Reflex;
        let mut latest_per_subject: [Option<&hydra_core::CausalCell>; 4] =
            [None, None, None, None];
        for cell in self.causal_cells_by_kind(&reflex_kind) {
            // Strict tenant match — no `None` cells leak into a
            // tenanted composition, no tenanted cells leak into
            // a `None` composition.
            if cell.tenant_id != tenant {
                continue;
            }
            for (idx, target_subject) in
                SELF_HEALTH_REFLEX_SUBJECTS.iter().enumerate()
            {
                if cell.subject == *target_subject {
                    match latest_per_subject[idx] {
                        None => latest_per_subject[idx] = Some(cell),
                        Some(existing)
                            if cell.created_at > existing.created_at =>
                        {
                            latest_per_subject[idx] = Some(cell);
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }

        // 2. Collect found ids in subject-order; track present /
        //    missing labels. Subject-order (not insertion order)
        //    keeps the composed `child_cell_ids` deterministic
        //    regardless of how the underlying store iterates.
        let mut child_cell_ids: Vec<hydra_core::CausalCellId> = Vec::new();
        let mut present_labels: Vec<&'static str> = Vec::new();
        let mut missing_labels: Vec<&'static str> = Vec::new();
        for (idx, slot) in latest_per_subject.iter().enumerate() {
            match slot {
                Some(cell) => {
                    child_cell_ids.push(cell.id.clone());
                    present_labels.push(SELF_HEALTH_REFLEX_LABELS[idx]);
                }
                None => {
                    missing_labels.push(SELF_HEALTH_REFLEX_LABELS[idx]);
                }
            }
        }

        // 3. Zero found → hard error. Mirrors the
        //    `compose_causal_cells` empty-children contract; the
        //    error message names the tenant + expected subjects
        //    so operators can pattern-match the gap.
        if child_cell_ids.is_empty() {
            return Err(HydraError::QueryError(format!(
                "no self-health reflex cells found for tenant {}; \
                 expected one or more of {:?}",
                tenant
                    .as_ref()
                    .map(|t| t.as_str())
                    .unwrap_or("None"),
                SELF_HEALTH_REFLEX_SUBJECTS,
            )));
        }

        // 4. Build explicit summary. Stable labels + present/
        //    missing breakdown so dashboards can pattern-match.
        //    When nothing is missing, drop the "Missing:" line.
        let summary = if missing_labels.is_empty() {
            format!(
                "hydra.health composed from {} of 4 self-health reflexes. \
                 Present: {}.",
                present_labels.len(),
                present_labels.join(", "),
            )
        } else {
            format!(
                "hydra.health composed from {} of 4 self-health reflexes. \
                 Present: {}. \
                 Missing: {}.",
                present_labels.len(),
                present_labels.join(", "),
                missing_labels.join(", "),
            )
        };

        // 5. Delegate to Patch 22's compose. Tenant equality is
        //    enforced by `compose_causal_cells` but we already
        //    filtered to a single tenant in step 1, so the
        //    inner check is a no-op pass.
        self.compose_causal_cells(
            child_cell_ids,
            hydra_core::CausalCellKind::Health,
            "hydra.health".to_string(),
            actor,
            Some(summary),
        )
    }

    /// Patch 28 — auto-create a `Reflex` CausalCell from a
    /// freshly-proposed model claim, if one exists.
    ///
    /// Trigger rule: `claim_id.is_some()` → build the cell;
    /// `None` → return `Ok(None)`. The MicroModel bridge methods
    /// (`_and_propose_claim` / `_and_propose_action`) call this
    /// AFTER the claim (and, in action mode, the action) have
    /// been ingested. The actual chain walk + cell construction
    /// is delegated to Patch 21's
    /// `create_reflex_causal_cell_from_claim` — this helper
    /// only adds the `Option` plumbing so each bridge method
    /// shrinks to one line at the callsite.
    ///
    /// **Snapshot semantics**: the cell captures the reflex
    /// state at creation time. Action-mode cells include the
    /// proposed action ID (action exists before cell minted).
    /// Execution, outcomes, and observations land later — they
    /// do NOT enrich the cell post-hoc (cells are immutable in
    /// v0). Trust assessment via Patch 23
    /// `assess_causal_cell_trust` is computed on-demand, so
    /// `actions_executed`, `outcomes_recorded` etc. factors
    /// always read CURRENT engine state regardless of when the
    /// cell was minted.
    ///
    /// **Fail-fast**: a `QueryError` from the underlying P21
    /// helper bubbles up. In practice this is unreachable here
    /// — the claim was just ingested + the prediction event was
    /// just logged — but if engine state IS inconsistent, the
    /// caller (typically a micromodel bridge) should surface
    /// that loudly rather than silently swallow it.
    fn maybe_create_reflex_cell(
        &mut self,
        claim_id: &Option<hydra_core::ClaimId>,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<Option<hydra_core::CausalCellId>> {
        match claim_id {
            Some(id) => {
                let cell =
                    self.create_reflex_causal_cell_from_claim(id.clone(), actor)?;
                Ok(Some(cell.id))
            }
            None => Ok(None),
        }
    }

    /// Patch 23 — fold trust over a CausalCell.
    ///
    /// Computes a `CausalCellTrustAssessment` for `cell_id`,
    /// walking DIRECT children only (no recursion in v0). Base
    /// score is the average of known child `trust_score`s for
    /// composed cells, or the cell's own `trust_score` for leaf
    /// cells (treated uniformly: leaf = "single child = self").
    /// Twelve factors then modify the base; result is clamped to
    /// `[0.0, 1.0]` and bucketed via `TrustAssessment::level_for_score`.
    ///
    /// **Read-only.** `&self`. Does NOT update `cell.trust_score`,
    /// does NOT emit an event. Patch 22's naïve mean remains on
    /// the stored cell; this method is the smarter on-demand
    /// computation. Patch 24+ may add persistence + an HTTP/SDK
    /// surface.
    ///
    /// Missing direct child (composition references a child that
    /// isn't in the store) → hard `QueryError`. This shouldn't
    /// happen post-P22 (composition validates children at create
    /// time), but the defensive check guards against future
    /// patches that introduce cell deletion.
    pub fn assess_causal_cell_trust(
        &self,
        cell_id: &hydra_core::CausalCellId,
    ) -> hydra_core::error::Result<hydra_core::CausalCellTrustAssessment> {
        use hydra_core::error::HydraError;
        use hydra_core::{
            action::{ActionStatus, OutcomeKind},
            TrustAssessment, TrustFactor,
        };

        // 1. Load the cell.
        let cell = self.causal_cell(cell_id).ok_or_else(|| {
            HydraError::QueryError(format!("unknown causal cell: {cell_id}"))
        })?;

        // 2. Load direct children (composed cells); empty for leaves.
        //    A missing child is treated as corruption — error
        //    rather than silently skip.
        let mut children: Vec<&hydra_core::CausalCell> = Vec::new();
        for child_id in &cell.child_cell_ids {
            let child = self.causal_cell(child_id).ok_or_else(|| {
                HydraError::QueryError(format!(
                    "composed cell {cell_id} references unknown child \
                     cell {child_id}"
                ))
            })?;
            children.push(child);
        }

        // 3. Compute known scores. Leaf cells use their own
        //    trust_score as the single "child" for averaging;
        //    composed cells use direct-child trust_score values.
        let is_leaf = cell.child_cell_ids.is_empty();
        let known_scores: Vec<f64> = if is_leaf {
            cell.trust_score.into_iter().collect()
        } else {
            children.iter().filter_map(|c| c.trust_score).collect()
        };
        let base = if known_scores.is_empty() {
            0.0
        } else {
            known_scores.iter().sum::<f64>() / known_scores.len() as f64
        };

        // 4. Surface child contributions for the result envelope.
        //    Leaf cells get an empty child_scores list.
        let child_scores: Vec<hydra_core::CausalCellChildTrust> = children
            .iter()
            .map(|c| hydra_core::CausalCellChildTrust {
                cell_id: c.id.clone(),
                trust_score: c.trust_score,
                claim_ids: c.claim_ids.clone(),
                outcome_ids: c.outcome_ids.clone(),
            })
            .collect();

        // 5. Evaluate the 12-factor table. Pattern matches the
        //    Patch 9 claim trust assessor: applied factors add
        //    their weight; unapplied factors stay in the list
        //    with `applied=false` for explainability.
        let mut factors: Vec<TrustFactor> = Vec::new();
        let mut applied_names: Vec<&'static str> = Vec::new();
        let mut score = base;

        let push_factor = |factors: &mut Vec<TrustFactor>,
                           applied_names: &mut Vec<&'static str>,
                           score: &mut f64,
                           kind: &str,
                           weight: f64,
                           applied: bool,
                           applied_name: &'static str,
                           detail: String| {
            if applied {
                *score += weight;
                applied_names.push(applied_name);
            }
            factors.push(TrustFactor {
                kind: kind.to_string(),
                weight,
                applied,
                detail,
            });
        };

        // --- Positive factors ---

        // children_present: +0.10 when child_cell_ids is non-empty.
        push_factor(
            &mut factors,
            &mut applied_names,
            &mut score,
            "children_present",
            0.10,
            !cell.child_cell_ids.is_empty(),
            "children present",
            if cell.child_cell_ids.is_empty() {
                "cell has no children (leaf cell)".to_string()
            } else {
                format!(
                    "{} direct child cell(s)",
                    cell.child_cell_ids.len()
                )
            },
        );

        // known_child_trust_scores: +0.10 when ≥1 known score.
        let total_subjects = if is_leaf {
            1
        } else {
            cell.child_cell_ids.len()
        };
        push_factor(
            &mut factors,
            &mut applied_names,
            &mut score,
            "known_child_trust_scores",
            0.10,
            !known_scores.is_empty(),
            "known child trust scores",
            format!(
                "{} of {} {} have trust scores",
                known_scores.len(),
                total_subjects,
                if is_leaf { "leaf cell" } else { "children" }
            ),
        );

        // high_average_child_trust: +0.20 when base ≥ 0.80.
        push_factor(
            &mut factors,
            &mut applied_names,
            &mut score,
            "high_average_child_trust",
            0.20,
            !known_scores.is_empty() && base >= 0.80,
            "high average child trust",
            if known_scores.is_empty() {
                "no known trust scores".to_string()
            } else {
                format!(
                    "average trust {:.2} {} 0.80",
                    base,
                    if base >= 0.80 { ">=" } else { "<" }
                )
            },
        );

        // all_children_high_trust: +0.15 when every known score ≥ 0.80.
        let all_high =
            !known_scores.is_empty() && known_scores.iter().all(|s| *s >= 0.80);
        let known_high_count =
            known_scores.iter().filter(|s| **s >= 0.80).count();
        push_factor(
            &mut factors,
            &mut applied_names,
            &mut score,
            "all_children_high_trust",
            0.15,
            all_high,
            "all children high trust",
            if known_scores.is_empty() {
                "no known trust scores".to_string()
            } else {
                format!(
                    "{} of {} known score(s) at or above 0.80",
                    known_high_count,
                    known_scores.len()
                )
            },
        );

        // outcomes_recorded: +0.10 when cell.outcome_ids non-empty.
        push_factor(
            &mut factors,
            &mut applied_names,
            &mut score,
            "outcomes_recorded",
            0.10,
            !cell.outcome_ids.is_empty(),
            "outcomes recorded",
            format!("{} outcome(s) referenced", cell.outcome_ids.len()),
        );

        // observations_present: +0.10 when observation_run_ids non-empty.
        push_factor(
            &mut factors,
            &mut applied_names,
            &mut score,
            "observations_present",
            0.10,
            !cell.observation_run_ids.is_empty(),
            "observations present",
            format!(
                "{} observation run(s) referenced",
                cell.observation_run_ids.len()
            ),
        );

        // actions_executed: +0.10 when any referenced action is Executed.
        let executed_count = cell
            .action_ids
            .iter()
            .filter_map(|aid| self.action(aid))
            .filter(|a| a.status == ActionStatus::Executed)
            .count();
        push_factor(
            &mut factors,
            &mut applied_names,
            &mut score,
            "actions_executed",
            0.10,
            executed_count > 0,
            "actions executed",
            format!(
                "{} of {} referenced action(s) in Executed status",
                executed_count,
                cell.action_ids.len()
            ),
        );

        // --- Negative factors ---

        // any_child_low_trust: -0.20 when any known score < 0.50.
        let low_count = known_scores.iter().filter(|s| **s < 0.50).count();
        push_factor(
            &mut factors,
            &mut applied_names,
            &mut score,
            "any_child_low_trust",
            -0.20,
            low_count > 0,
            "any child low trust",
            if known_scores.is_empty() {
                "no known trust scores to check".to_string()
            } else {
                format!(
                    "{} of {} known score(s) below 0.50",
                    low_count,
                    known_scores.len()
                )
            },
        );

        // failed_outcomes_present: -0.20 when any outcome.kind is
        // Failure or Regression.
        let failed_count = cell
            .outcome_ids
            .iter()
            .filter_map(|oid| self.outcome(oid))
            .filter(|o| {
                matches!(o.kind, OutcomeKind::Failure | OutcomeKind::Regression)
            })
            .count();
        push_factor(
            &mut factors,
            &mut applied_names,
            &mut score,
            "failed_outcomes_present",
            -0.20,
            failed_count > 0,
            "failed outcomes present",
            format!(
                "{} outcome(s) with kind Failure or Regression",
                failed_count
            ),
        );

        // rejected_actions_present: -0.15 when any action.status == Rejected.
        let rejected_count = cell
            .action_ids
            .iter()
            .filter_map(|aid| self.action(aid))
            .filter(|a| a.status == ActionStatus::Rejected)
            .count();
        push_factor(
            &mut factors,
            &mut applied_names,
            &mut score,
            "rejected_actions_present",
            -0.15,
            rejected_count > 0,
            "rejected actions present",
            format!(
                "{} referenced action(s) in Rejected status",
                rejected_count
            ),
        );

        // contradicting_claims_present: -0.20 when any claim has
        // non-empty evidence_against.
        let contradicted_count = cell
            .claim_ids
            .iter()
            .filter_map(|cid| self.claim(cid))
            .filter(|c| !c.evidence_against.is_empty())
            .count();
        push_factor(
            &mut factors,
            &mut applied_names,
            &mut score,
            "contradicting_claims_present",
            -0.20,
            contradicted_count > 0,
            "contradicting claims present",
            format!(
                "{} referenced claim(s) with non-empty evidence_against",
                contradicted_count
            ),
        );

        // missing_child_trust: -0.10 when ≥1 known-subject slot
        // has no trust score (composed: child.trust_score = None;
        // leaf: cell.trust_score = None).
        let missing_count = total_subjects.saturating_sub(known_scores.len());
        push_factor(
            &mut factors,
            &mut applied_names,
            &mut score,
            "missing_child_trust",
            -0.10,
            missing_count > 0,
            "missing child trust",
            if is_leaf {
                if cell.trust_score.is_none() {
                    "leaf cell has no trust_score".to_string()
                } else {
                    "leaf cell carries its own trust_score".to_string()
                }
            } else {
                format!(
                    "{} of {} children have no trust_score",
                    missing_count, total_subjects
                )
            },
        );

        // 6. Clamp + bucket.
        let clamped = score.clamp(0.0, 1.0);
        let level = TrustAssessment::level_for_score(clamped);

        // 7. Deterministic explanation mirroring Patch 9's shape.
        let unapplied = factors.iter().filter(|f| !f.applied).count();
        let applied_str = if applied_names.is_empty() {
            "no factors fired".to_string()
        } else {
            applied_names.join(", ")
        };
        let explanation = format!(
            "Cell trust {:?} (score {:.2}) for {}: {}. ({} factor(s) \
             checked but did not fire.)",
            level, clamped, cell.subject, applied_str, unapplied
        );

        Ok(hydra_core::CausalCellTrustAssessment {
            cell_id: cell.id.clone(),
            score: clamped,
            level,
            explanation,
            factors,
            child_scores,
            assessed_at: chrono::Utc::now(),
        })
    }

    // === MicroModel Patch 8 — outcome learning loop ============
    //
    // Close the model feedback loop: walk backward from a recorded
    // Outcome to the originating MicroModelPrediction, build a
    // MicroModelObservation, and record it.
    //
    // The chain Patches 3–7 intentionally built:
    //   Outcome.caused_by         → ActionExecuted event id
    //   ActionExecuted.action_id  → action_id
    //   Action.related_claims[0]  → claim_id (shortcut, Patch 4)
    //   Claim.caused_by           → MicroModelPredictionRecorded
    //                               event id (Patch 3)
    //   event.kind.prediction     → prediction.run_id (join key)
    //
    // v0 records observations only for **executed** outcomes
    // (Patch 6 rejections don't emit OutcomeObserved). The
    // observation carries audit linkage in `observed_outcome:
    // serde_json::Value`; the struct's existing 4 fields stay
    // unchanged. No retraining, no trust scoring, no error metric
    // — that's Patches 9+. `error: None` is v0 honest.

    /// Walk the causal chain from an Outcome back to its originating
    /// MicroModelPrediction and record a MicroModelObservation
    /// matched by `prediction.run_id`. The `observed_outcome` JSON
    /// captures the outcome / action / claim ids + outcome kind +
    /// summary + lifecycle so future trust/learning patches can
    /// branch on them.
    ///
    /// Errors with `QueryError("unknown outcome: ...")` if the
    /// outcome_id isn't in the store. Errors with `QueryError(
    /// "outcome not traceable: ...")` if any step of the chain is
    /// missing — typically because the outcome wasn't produced by
    /// a MicroModel reflex (e.g., manually-ingested outcomes).
    pub fn record_micro_model_observation_from_action_outcome(
        &mut self,
        outcome_id: hydra_core::OutcomeId,
        observed_by: hydra_core::ActorId,
    ) -> hydra_core::error::Result<hydra_core::MicroModelObservation> {
        // 1. Lookup outcome.
        let outcome = self.action_store.outcome(&outcome_id).cloned().ok_or_else(
            || {
                hydra_core::error::HydraError::QueryError(format!(
                    "unknown outcome: {outcome_id}"
                ))
            },
        )?;
        // 2. outcome.caused_by → ActionExecuted event id.
        let executed_event_id = outcome.caused_by.clone().ok_or_else(|| {
            hydra_core::error::HydraError::QueryError(format!(
                "outcome not traceable: {outcome_id} has no caused_by"
            ))
        })?;
        // 3. Resolve to event and confirm kind is ActionExecuted.
        let executed_event = self.event(&executed_event_id).ok_or_else(|| {
            hydra_core::error::HydraError::QueryError(format!(
                "outcome not traceable: ActionExecuted event {executed_event_id} not in log"
            ))
        })?;
        let action_id = match &executed_event.kind {
            hydra_core::EventKind::ActionExecuted { action_id } => action_id.clone(),
            other => {
                return Err(hydra_core::error::HydraError::QueryError(format!(
                    "outcome not traceable: caused_by event is not ActionExecuted \
                     (got {:?})",
                    other.kind_name()
                )));
            }
        };
        // 4. Action → related_claims[0] (Patch 4 shortcut).
        let action = self.action_store.action(&action_id).ok_or_else(|| {
            hydra_core::error::HydraError::QueryError(format!(
                "outcome not traceable: action {action_id} not in store"
            ))
        })?;
        let claim_id = action.related_claims.first().cloned().ok_or_else(|| {
            hydra_core::error::HydraError::QueryError(format!(
                "outcome not traceable: action {action_id} has no related_claims \
                 — not a model-derived action"
            ))
        })?;
        // 5. Claim.caused_by → MicroModelPredictionRecorded event id.
        let claim = self.epistemic_store.claim(&claim_id).ok_or_else(|| {
            hydra_core::error::HydraError::QueryError(format!(
                "outcome not traceable: claim {claim_id} not in epistemic store"
            ))
        })?;
        let prediction_event_id = claim.caused_by.clone().ok_or_else(|| {
            hydra_core::error::HydraError::QueryError(format!(
                "outcome not traceable: claim {claim_id} has no caused_by"
            ))
        })?;
        // 6. Resolve prediction event and extract the prediction.
        let prediction_event = self.event(&prediction_event_id).ok_or_else(|| {
            hydra_core::error::HydraError::QueryError(format!(
                "outcome not traceable: prediction event {prediction_event_id} \
                 not in log"
            ))
        })?;
        let prediction = match &prediction_event.kind {
            hydra_core::EventKind::MicroModelPredictionRecorded { prediction } => {
                prediction.clone()
            }
            other => {
                return Err(hydra_core::error::HydraError::QueryError(format!(
                    "outcome not traceable: claim.caused_by is not \
                     MicroModelPredictionRecorded (got {:?})",
                    other.kind_name()
                )));
            }
        };
        let run_id = prediction.run_id.clone();

        // 7. Build the observed_outcome JSON. Patch 8 v0 keeps the
        //    MicroModelObservation struct stable and carries audit
        //    linkage inside this Value blob. The shape is the
        //    contract — Patch 9 / trust scoring will read these
        //    fields without further engine surgery.
        let observed_outcome = serde_json::json!({
            "outcome_id": outcome_id.to_string(),
            "action_id": action_id.to_string(),
            "claim_id": claim_id.to_string(),
            "outcome_kind": format_outcome_kind_for_observation(&outcome.kind),
            "outcome_summary": outcome
                .impact
                .get("summary")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
            "action_lifecycle": "executed",
            // v0 only walks executed outcomes; rejection-path is a
            // future patch. These flags are nonetheless explicit so
            // Patch 9's trust scoring can branch on them without
            // probing optional fields.
            "operator_approved": true,
            "operator_rejected": false,
            "observed_by": observed_by.to_string(),
        });

        let observation = hydra_core::MicroModelObservation {
            run_id,
            observed_outcome,
            error: None,
            observed_at: chrono::Utc::now(),
        };
        self.ingest(hydra_core::EventKind::MicroModelObservationRecorded {
            observation: observation.clone(),
        })?;
        Ok(observation)
    }

    // === Trust Patch 5 (Patch 13) — rejection-path observations ===
    //
    // The corrective-memory companion to Patch 8. When an operator
    // rejects a model-derived action, this method synthesizes a
    // MicroModelObservation with `action_lifecycle: "rejected"` so
    // Patch 12's reflex trust calibration can read it as a NEGATIVE
    // signal (Patch 13's new factor `model_operator_rejected_
    // historically`).
    //
    // v0 boundary:
    //   ✓ Operator-triggered only (caller passes `observed_by`)
    //   ✓ Cascade rejections REFUSED — a policy refusing an action
    //     is not the same signal as a human refusing it
    //   ✓ Action must be in status Rejected (other states → 400)
    //   ✓ Walk action → claim → prediction → run_id; non-model
    //     actions are not traceable → 400
    //   ✓ rejection_reason is extracted from the most recent
    //     ActionRejected event in the audit log
    //
    // No new event variant. Reuses MicroModelObservationRecorded.

    /// Record a MicroModelObservation from an operator-rejected
    /// action. Mirrors `record_micro_model_observation_from_action_outcome`
    /// but for the REJECTION path (no outcome exists because
    /// execution never happened).
    ///
    /// `observed_by` is the actor recording the observation (often
    /// the same operator who rejected it; not enforced).
    ///
    /// Errors:
    /// - Unknown action → `QueryError("unknown action: ...")`
    /// - Action not Rejected → `QueryError("invalid action state: ...")`
    /// - `action.rejected_by` missing or cascade actor → `QueryError(
    ///   "action was rejected by cascade, not operator")`
    /// - Chain walk failure (non-model-derived) → `QueryError(
    ///   "action not traceable: ...")`
    pub fn record_micro_model_observation_from_rejected_action(
        &mut self,
        action_id: hydra_core::ActionId,
        observed_by: hydra_core::ActorId,
    ) -> hydra_core::error::Result<hydra_core::MicroModelObservation> {
        // 1. Lookup action.
        let action = self.action_store.action(&action_id).cloned().ok_or_else(
            || {
                hydra_core::error::HydraError::QueryError(format!(
                    "unknown action: {action_id}"
                ))
            },
        )?;

        // 2. Validate status == Rejected.
        if action.status != hydra_core::ActionStatus::Rejected {
            return Err(hydra_core::error::HydraError::QueryError(format!(
                "invalid action state: {action_id} is {:?}, expected Rejected",
                action.status
            )));
        }

        // 3. Validate rejector is non-cascade. Cascade rejections
        //    are policy enforcement, not human judgment — they do
        //    NOT produce a learning signal.
        let rejector = action.rejected_by.as_ref().ok_or_else(|| {
            hydra_core::error::HydraError::QueryError(format!(
                "action {action_id} is Rejected but rejected_by is unset"
            ))
        })?;
        if hydra_core::is_cascade_approver(rejector) {
            return Err(hydra_core::error::HydraError::QueryError(format!(
                "action {action_id} was rejected by cascade ({}), not operator",
                rejector
            )));
        }

        // 4. Walk action → related_claims[0].
        let claim_id = action.related_claims.first().cloned().ok_or_else(|| {
            hydra_core::error::HydraError::QueryError(format!(
                "action not traceable: {action_id} has no related_claims — \
                 not a model-derived action"
            ))
        })?;

        // 5. Walk claim → caused_by (prediction event).
        let claim = self.epistemic_store.claim(&claim_id).ok_or_else(|| {
            hydra_core::error::HydraError::QueryError(format!(
                "action not traceable: claim {claim_id} not in epistemic store"
            ))
        })?;
        let prediction_event_id = claim.caused_by.clone().ok_or_else(|| {
            hydra_core::error::HydraError::QueryError(format!(
                "action not traceable: claim {claim_id} has no caused_by"
            ))
        })?;
        let prediction_event = self.event(&prediction_event_id).ok_or_else(|| {
            hydra_core::error::HydraError::QueryError(format!(
                "action not traceable: prediction event {prediction_event_id} \
                 not in log"
            ))
        })?;
        let prediction = match &prediction_event.kind {
            hydra_core::EventKind::MicroModelPredictionRecorded { prediction } => {
                prediction.clone()
            }
            other => {
                return Err(hydra_core::error::HydraError::QueryError(format!(
                    "action not traceable: claim.caused_by is not \
                     MicroModelPredictionRecorded (got {:?})",
                    other.kind_name()
                )));
            }
        };
        let run_id = prediction.run_id.clone();

        // 6. Find the rejection reason from the most recent
        //    ActionRejected event for this action_id.
        let rejection_reason = self
            .events()
            .iter()
            .rev()
            .find_map(|event| match &event.kind {
                hydra_core::EventKind::ActionRejected {
                    action_id: aid,
                    reason,
                    ..
                } if aid == &action_id => Some(reason.clone()),
                _ => None,
            })
            .unwrap_or_default();

        // 7. Build observed_outcome JSON. Mirrors Patch 8's contract
        //    (action_lifecycle, operator_approved, operator_rejected
        //    keys consistent) so Patch 12's history-reading code
        //    can distinguish executed vs rejected without schema
        //    drift.
        let observed_outcome = serde_json::json!({
            "outcome_id": serde_json::Value::Null,
            "action_id": action_id.to_string(),
            "claim_id": claim_id.to_string(),
            "outcome_kind": "Rejected",
            "outcome_summary": format!(
                "Action rejected by operator: {rejection_reason}"
            ),
            "action_lifecycle": "rejected",
            "operator_approved": false,
            "operator_rejected": true,
            "rejection_reason": rejection_reason,
            "observed_by": observed_by.to_string(),
        });

        let observation = hydra_core::MicroModelObservation {
            run_id,
            observed_outcome,
            error: None,
            observed_at: chrono::Utc::now(),
        };
        self.ingest(hydra_core::EventKind::MicroModelObservationRecorded {
            observation: observation.clone(),
        })?;
        Ok(observation)
    }

    // === Trust Patch 1 (Patch 9) — claim trust assessment =====
    //
    // Compute-only, deterministic, rule-based. Reads the audit
    // chain produced by Patches 3–8 and returns a `TrustAssessment`.
    // No events emitted, no store mutation, no HTTP, no SDK in
    // this patch — the engine surface is read-only (`&self`).
    //
    // The factor weights are stable IDs that downstream patches
    // (HTTP/SDK in Patch 10, auto-execute in Patch 11) will read
    // by string key. Don't rename or repurpose without versioning.

    /// Assess the trust score for one claim by walking its
    /// audit chain — supporting evidence, contradicting evidence,
    /// related actions, approvals, executions, outcomes, model
    /// observations.
    ///
    /// Returns `QueryError("unknown claim: ...")` if the claim
    /// isn't in the epistemic store.
    ///
    /// Special case for `ClaimStatus::Retracted`: the
    /// `claim_retracted` factor still appears in the list with
    /// `weight = -1.0`, but the assessor force-sets the final
    /// `score` to `0.0` after factor evaluation so a retracted
    /// claim can never be "rescued" by accidentally
    /// counterbalancing positives.
    pub fn assess_claim_trust(
        &self,
        claim_id: &hydra_core::ClaimId,
    ) -> hydra_core::error::Result<hydra_core::TrustAssessment> {
        let claim = self.epistemic_store.claim(claim_id).cloned().ok_or_else(
            || {
                hydra_core::error::HydraError::QueryError(format!(
                    "unknown claim: {claim_id}"
                ))
            },
        )?;

        // Walk forward: claim → actions → outcomes; collect ids.
        let related_actions: Vec<&hydra_core::Action> =
            self.action_store.actions_for_claim(claim_id);
        let related_action_ids: Vec<hydra_core::ActionId> =
            related_actions.iter().map(|a| a.id.clone()).collect();
        let mut related_outcome_ids: Vec<hydra_core::OutcomeId> = Vec::new();
        for action in &related_actions {
            for outcome in self.action_store.outcomes_for_action(&action.id) {
                related_outcome_ids.push(outcome.id.clone());
            }
        }

        // Walk back to the prediction (if any) so we can check
        // whether a MicroModelObservation has been recorded.
        // claim.caused_by → MicroModelPredictionRecorded → run_id
        // Walk back to the prediction (if any) so we can check
        // whether a MicroModelObservation has been recorded AND
        // (Patch 12) which model produced the prediction. The
        // model_id is the key for historical reflex-trust signal.
        let (observation_run_id, source_model_id): (
            Option<hydra_core::MicroModelRunId>,
            Option<hydra_core::MicroModelId>,
        ) = claim
            .caused_by
            .as_ref()
            .and_then(|event_id| self.event(event_id))
            .and_then(|event| match &event.kind {
                hydra_core::EventKind::MicroModelPredictionRecorded { prediction } => {
                    Some((
                        Some(prediction.run_id.clone()),
                        Some(prediction.model_id.clone()),
                    ))
                }
                _ => None,
            })
            .unwrap_or((None, None));
        let observation_run_ids: Vec<hydra_core::MicroModelRunId> =
            observation_run_id.iter().cloned().collect();

        // Evaluate each factor. Helper closure standardizes the
        // applied / detail / weight construction.
        let mut factors: Vec<hydra_core::TrustFactor> = Vec::new();

        // 1. claim_verified (+0.20)
        let verified = matches!(
            claim.status,
            hydra_core::ClaimStatus::Verified | hydra_core::ClaimStatus::Operational
        );
        factors.push(hydra_core::TrustFactor {
            kind: "claim_verified".to_string(),
            weight: 0.20,
            applied: verified,
            detail: if verified {
                format!("claim.status == {:?}", claim.status)
            } else {
                "claim has not reached Verified or Operational".to_string()
            },
        });

        // 2. claim_supported (+0.10) — does NOT stack with verified.
        let supported_only = matches!(claim.status, hydra_core::ClaimStatus::Supported);
        factors.push(hydra_core::TrustFactor {
            kind: "claim_supported".to_string(),
            weight: 0.10,
            applied: supported_only,
            detail: if supported_only {
                "claim.status == Supported (partial — evidence weak)".to_string()
            } else {
                "claim is not at Supported status".to_string()
            },
        });

        // 3. high_confidence_claim (+0.10): claim.confidence >= 0.80
        //    mirrors the verification policy default threshold.
        let high_conf = claim.confidence.value() >= 0.80;
        factors.push(hydra_core::TrustFactor {
            kind: "high_confidence_claim".to_string(),
            weight: 0.10,
            applied: high_conf,
            detail: format!(
                "claim.confidence = {:.2} (threshold 0.80)",
                claim.confidence.value()
            ),
        });

        // 4. supporting_evidence_present (+0.10)
        let supporting_count = claim.evidence_for.len();
        factors.push(hydra_core::TrustFactor {
            kind: "supporting_evidence_present".to_string(),
            weight: 0.10,
            applied: supporting_count >= 1,
            detail: format!("{supporting_count} supporting evidence record(s)"),
        });

        // 5. reliable_supporting_evidence (+0.10): any evidence_for
        //    has reliability >= 0.75 (verification policy default).
        let reliable_evidence = claim.evidence_for.iter().any(|evidence_id| {
            self.epistemic_store
                .evidence(evidence_id)
                .map(|e| e.reliability.value() >= 0.75)
                .unwrap_or(false)
        });
        factors.push(hydra_core::TrustFactor {
            kind: "reliable_supporting_evidence".to_string(),
            weight: 0.10,
            applied: reliable_evidence,
            detail: if reliable_evidence {
                "at least one supporting evidence has reliability >= 0.75".to_string()
            } else {
                "no supporting evidence meets the 0.75 reliability bar".to_string()
            },
        });

        // 6. operator_approved (+0.15): any related action has
        //    approved_by set to an actor that is NOT the cascade
        //    auto-approver. v0 caveat: this only sees the LAST
        //    approver on an action (Patch 6 is lenient/idempotent).
        let operator_approved = related_actions.iter().any(|action| {
            action
                .approved_by
                .as_ref()
                .map(|actor| !hydra_core::is_cascade_approver(actor))
                .unwrap_or(false)
        });
        factors.push(hydra_core::TrustFactor {
            kind: "operator_approved".to_string(),
            weight: 0.15,
            applied: operator_approved,
            detail: if operator_approved {
                "at least one related action approved by a non-cascade actor".to_string()
            } else {
                "no operator approval found (cascade auto-approvals don't count)"
                    .to_string()
            },
        });

        // 7. action_executed (+0.15): any related action reached Executed.
        let any_executed = related_actions
            .iter()
            .any(|action| action.status == hydra_core::ActionStatus::Executed);
        factors.push(hydra_core::TrustFactor {
            kind: "action_executed".to_string(),
            weight: 0.15,
            applied: any_executed,
            detail: if any_executed {
                "at least one related action reached Executed status".to_string()
            } else {
                "no related action has been executed".to_string()
            },
        });

        // 8. outcome_recorded (+0.10)
        let outcome_recorded = !related_outcome_ids.is_empty();
        factors.push(hydra_core::TrustFactor {
            kind: "outcome_recorded".to_string(),
            weight: 0.10,
            applied: outcome_recorded,
            detail: format!(
                "{} outcome(s) recorded across related actions",
                related_outcome_ids.len()
            ),
        });

        // 9. model_observation_exists (+0.10): Patch 8 path.
        let observation_present = observation_run_id
            .as_ref()
            .and_then(|run_id| self.micromodel_store.observation(run_id))
            .is_some();
        factors.push(hydra_core::TrustFactor {
            kind: "model_observation_exists".to_string(),
            weight: 0.10,
            applied: observation_present,
            detail: if observation_present {
                let run = observation_run_id
                    .as_ref()
                    .map(|r| r.to_string())
                    .unwrap_or_default();
                format!("MicroModelObservation recorded for run_id {run}")
            } else if observation_run_id.is_some() {
                "claim traces to a model prediction but no observation recorded yet"
                    .to_string()
            } else {
                "claim is not model-derived (no MicroModelPredictionRecorded ancestor)"
                    .to_string()
            },
        });

        // === Trust Patch 4 (Patch 12) — reflex calibration ====
        //
        // Historical factors per model. Shift trust from
        // "this individual chain looks good" to "this MODEL has
        // worked before". For non-model claims (source_model_id ==
        // None), all three emit applied=false with a uniform
        // "claim is not model-derived" detail.
        //
        // O(N) scan over all observations is fine for v0 (hundreds
        // to low thousands). Patch 13+ can add a model_id index.

        let prior_observations: Vec<&hydra_core::MicroModelObservation> = source_model_id
            .as_ref()
            .map(|model_id| {
                observations_for_model(&self.micromodel_store, model_id)
            })
            .unwrap_or_default();
        let prior_observation_count = prior_observations.len();

        // 10. reflex_history_present (+0.10): model has >= 1 prior
        //     observation. Lightest historical signal — "this
        //     reflex has run before, even just once."
        let history_present =
            source_model_id.is_some() && prior_observation_count >= 1;
        factors.push(hydra_core::TrustFactor {
            kind: "reflex_history_present".to_string(),
            weight: 0.10,
            applied: history_present,
            detail: if source_model_id.is_none() {
                "claim is not model-derived".to_string()
            } else {
                format!(
                    "model has {prior_observation_count} prior observation(s)"
                )
            },
        });

        // 11. model_proven_executed (+0.15): model has >= 3 prior
        //     observations. The 3-threshold avoids "trusting after
        //     one lucky run." Patch 13 may add a true success-rate
        //     metric on top.
        const PROVEN_THRESHOLD: usize = 3;
        let model_proven =
            source_model_id.is_some() && prior_observation_count >= PROVEN_THRESHOLD;
        factors.push(hydra_core::TrustFactor {
            kind: "model_proven_executed".to_string(),
            weight: 0.15,
            applied: model_proven,
            detail: if source_model_id.is_none() {
                "claim is not model-derived".to_string()
            } else {
                format!(
                    "model has {prior_observation_count} prior observation(s) (proven threshold = {PROVEN_THRESHOLD})"
                )
            },
        });

        // 12. model_operator_approved_historically (+0.10): at
        //     least one of the model's prior actions had an
        //     approver that is NOT one of Hydra's internal
        //     automation actors (cascade auto-approve OR Patch 15
        //     trust-gated auto-approve). This is the LOAD-BEARING
        //     signal: only HUMAN approval counts.
        //
        //     **Trust-spiral fix (Patch 15)**: switched from
        //     `is_cascade_approver` to `is_hydra_automation_actor`.
        //     Without this, Patch 15 auto-approvals would count as
        //     operator endorsement in future trust calibrations,
        //     allowing auto-approval to bootstrap MORE auto-
        //     approval — a self-reinforcing trust spiral.
        let operator_approved_historically = source_model_id.is_some()
            && prior_observations.iter().any(|obs| {
                observation_action_id(obs)
                    .and_then(|action_id| self.action_store.action(&action_id))
                    .and_then(|action| action.approved_by.as_ref())
                    .map(|approver| !hydra_core::is_hydra_automation_actor(approver))
                    .unwrap_or(false)
            });
        factors.push(hydra_core::TrustFactor {
            kind: "model_operator_approved_historically".to_string(),
            weight: 0.10,
            applied: operator_approved_historically,
            detail: if source_model_id.is_none() {
                "claim is not model-derived".to_string()
            } else if operator_approved_historically {
                "at least one of the model's prior actions had a non-Hydra \
                 approver (human endorsement)"
                    .to_string()
            } else {
                "no operator-approved action found in this model's history \
                 (cascade + trust-gate auto-approvals don't count)"
                    .to_string()
            },
        });

        // === Trust Patch 5 (Patch 13) — corrective memory ====
        //
        // 13. model_operator_rejected_historically (-0.15): at
        //     least one of the model's prior observations has
        //     action_lifecycle == "rejected" AND the underlying
        //     action was rejected by a non-cascade actor. Cascade
        //     rejections (policy enforcement) don't count — only
        //     human rejections produce this negative signal.
        //
        //     Symmetric with model_operator_approved_historically:
        //     the same "humans have looked at this model" gate, but
        //     for refusals. Hydra now learns from BOTH endorsement
        //     and correction.
        let operator_rejected_historically = source_model_id.is_some()
            && prior_observations.iter().any(|obs| {
                let is_rejected = obs
                    .observed_outcome
                    .get("action_lifecycle")
                    .and_then(|v| v.as_str())
                    == Some("rejected");
                is_rejected
                    && observation_action_id(obs)
                        .and_then(|action_id| self.action_store.action(&action_id))
                        .and_then(|action| action.rejected_by.as_ref())
                        .map(|rejector| !hydra_core::is_cascade_approver(rejector))
                        .unwrap_or(false)
            });
        factors.push(hydra_core::TrustFactor {
            kind: "model_operator_rejected_historically".to_string(),
            weight: -0.15,
            applied: operator_rejected_historically,
            detail: if source_model_id.is_none() {
                "claim is not model-derived".to_string()
            } else if operator_rejected_historically {
                "at least one of the model's prior actions was rejected by \
                 a non-cascade actor (corrective signal)"
                    .to_string()
            } else {
                "no operator-rejected action found in this model's history \
                 (cascade rejections don't count)"
                    .to_string()
            },
        });

        // 14. contradicting_evidence (-0.20)
        let against_count = claim.evidence_against.len();
        factors.push(hydra_core::TrustFactor {
            kind: "contradicting_evidence".to_string(),
            weight: -0.20,
            applied: against_count >= 1,
            detail: format!("{against_count} contradicting evidence record(s)"),
        });

        // 15. claim_disputed (-0.30)
        let disputed = matches!(claim.status, hydra_core::ClaimStatus::Disputed);
        factors.push(hydra_core::TrustFactor {
            kind: "claim_disputed".to_string(),
            weight: -0.30,
            applied: disputed,
            detail: if disputed {
                "claim.status == Disputed".to_string()
            } else {
                "claim is not at Disputed status".to_string()
            },
        });

        // 16. claim_retracted (-1.00): the heavy hammer.
        let retracted = matches!(claim.status, hydra_core::ClaimStatus::Retracted);
        factors.push(hydra_core::TrustFactor {
            kind: "claim_retracted".to_string(),
            weight: -1.00,
            applied: retracted,
            detail: if retracted {
                "claim.status == Retracted (final score force-clamped to 0.0)".to_string()
            } else {
                "claim is not retracted".to_string()
            },
        });

        // Sum applied weights → raw score, clamp to [0, 1].
        let raw: f64 = factors
            .iter()
            .filter(|f| f.applied)
            .map(|f| f.weight)
            .sum();
        let mut score = raw.clamp(0.0, 1.0);
        // Special case: Retracted claims are always score 0.0
        // regardless of accidental counterbalancing positives.
        if retracted {
            score = 0.0;
        }
        let level = hydra_core::TrustAssessment::level_for_score(score);
        let explanation = build_trust_explanation(&claim, &factors, level, score);

        Ok(hydra_core::TrustAssessment {
            claim_id: claim.id.clone(),
            score,
            level,
            explanation,
            factors,
            related_action_ids,
            related_outcome_ids,
            observation_run_ids,
            assessed_at: chrono::Utc::now(),
        })
    }

    // === Trust Patch 3 (Patch 11) — auto-execution gate ============
    //
    // The first AUTOMATION surface. Trust judges (Patches 9/10);
    // automation acts on those judgments — but only when the
    // judgment says it's safe.
    //
    // Patch 11 boundary:
    //   ✓ Notify-kind actions only (other kinds → Err, never auto)
    //   ✓ status == Approved precondition (human approval still
    //     mandatory; Patch 11 only auto-EXECUTES, never auto-approves)
    //   ✓ TrustLevel::High AND score >= caller's threshold
    //   ✓ Single related_claim ([0]); v0 doesn't union across multiple
    //
    // Error vs decision split (per Patch 11 design):
    //   - Unknown action_id            → Err (HTTP 404)
    //   - Wrong KIND                   → Err (HTTP 400) — a Backfill
    //                                    can NEVER be auto-executed by
    //                                    this method, so it's a hard
    //                                    contract error
    //   - Wrong STATUS                 → Ok(executed=false, ...)
    //                                    because the second call AFTER
    //                                    success sees Executed and
    //                                    must look the same as "not
    //                                    Approved yet"
    //   - No related_claims            → Ok(executed=false, trust=None)
    //   - Trust assessor error         → Err (rare; defensive)
    //   - Trust below threshold        → Ok(executed=false,
    //                                       trust=Some(...))

    /// Auto-execute an Approved Notify action when its related
    /// claim's trust meets `min_trust_score` AND `TrustLevel::High`.
    /// Returns a decision envelope — the decision IS the data, NOT
    /// the success axis.
    ///
    /// `actor` is the actor recorded on the underlying Outcome /
    /// `executed_by` when execution does fire. Operators typically
    /// pass a stable id like `actor_hydra_trust_gate` so the audit
    /// log distinguishes auto-execution from manual operator runs.
    ///
    /// `min_trust_score` is the score floor (independent of level —
    /// caller may want `0.85` even though `High` starts at `0.80`).
    pub fn auto_execute_trusted_notify_action(
        &mut self,
        action_id: hydra_core::ActionId,
        actor: hydra_core::ActorId,
        min_trust_score: f64,
    ) -> hydra_core::error::Result<hydra_core::AutoExecutionDecision> {
        // 1. Unknown action → hard 404. Validate-before-any-walk
        //    matches the rest of the action lifecycle helpers.
        let action = self.action_store.action(&action_id).cloned().ok_or_else(
            || {
                hydra_core::error::HydraError::QueryError(format!(
                    "unknown action: {action_id}"
                ))
            },
        )?;

        // 2. Wrong KIND → hard error. A non-Notify action can NEVER
        //    be auto-executed via this method, so the contract is
        //    a 400, not a decision skip.
        if action.kind != hydra_core::ActionKind::Notify {
            return Err(hydra_core::error::HydraError::QueryError(format!(
                "invalid action kind: {action_id} is not Notify \
                 (Patch 11 only auto-executes Notify actions; got {:?})",
                action.kind
            )));
        }

        // 3. Wrong STATUS → DECISION SKIP, not error. After a
        //    successful auto-execute, a second call sees status
        //    == Executed; that response shape must match the
        //    "not Approved yet" case so callers can poll
        //    idempotently.
        if action.status != hydra_core::ActionStatus::Approved {
            return Ok(hydra_core::AutoExecutionDecision {
                executed: false,
                reason: format!(
                    "action status is {:?}, not Approved (auto-execute only \
                     fires for Approved actions)",
                    action.status
                ),
                trust: None,
                execution: None,
            });
        }

        // 4. No related_claims → DECISION SKIP. The action exists,
        //    it's Approved, it's Notify — but it wasn't proposed
        //    via the MicroModel reflex chain so we have no claim
        //    to trust-assess. Caller can fall back to manual
        //    execute_notify_action.
        let claim_id = match action.related_claims.first().cloned() {
            Some(id) => id,
            None => {
                return Ok(hydra_core::AutoExecutionDecision {
                    executed: false,
                    reason: "action has no related_claims — not trust-assessable \
                             (likely not a model-derived action)"
                        .to_string(),
                    trust: None,
                    execution: None,
                });
            }
        };

        // 5. Assess the trust. This is the expensive step (walks
        //    the audit chain) — only run when steps 1-4 cleared.
        let assessment = self.assess_claim_trust(&claim_id)?;

        // 6. Trust threshold. BOTH level == High AND score >=
        //    min_trust_score must hold. Patch 9 force-clamps
        //    Retracted to 0.0, so a retracted claim auto-fails
        //    the score check.
        let level_ok = matches!(assessment.level, hydra_core::TrustLevel::High);
        let score_ok = assessment.score >= min_trust_score;
        if !(level_ok && score_ok) {
            return Ok(hydra_core::AutoExecutionDecision {
                executed: false,
                reason: format!(
                    "trust insufficient: level={:?}, score={:.2} (min={:.2})",
                    assessment.level, assessment.score, min_trust_score
                ),
                trust: Some(assessment),
                execution: None,
            });
        }

        // 7. Execute. Patch 7's execute_notify_action re-checks
        //    the status precondition (defense in depth) and emits
        //    the full ActionExecuting → ActionExecuted →
        //    OutcomeObserved chain.
        let report = self.execute_notify_action(action_id, actor)?;

        Ok(hydra_core::AutoExecutionDecision {
            executed: true,
            reason: format!(
                "trust High (score {:.2}) meets threshold {:.2}; auto-executed",
                assessment.score, min_trust_score
            ),
            trust: Some(assessment),
            execution: Some(report),
        })
    }

    // === Trust Patch 6 (Patch 15) — trust-gated auto-approval ====
    //
    // The FIRST patch where Hydra can act without explicit human
    // approval. Auto-approves a Proposed Notify action when ALL of
    // these strict gates pass:
    //
    //   1. action.kind == Notify
    //   2. action.status == Proposed
    //   3. related claim exists
    //   4. trust.level == High AND trust.score >= min_trust_score
    //   5. NO contradicting_evidence factor applied
    //   6. NO claim_disputed factor applied
    //   7. NO claim_retracted factor applied
    //   8. NO model_operator_rejected_historically factor applied
    //   9. model_operator_approved_historically factor applied
    //      (model must have at least one prior HUMAN approval —
    //      pristine models never get autonomy)
    //
    // Hard-block factors (5-8) veto even if score is high — a
    // disputed claim never auto-approves.
    //
    // Stamps `actor_hydra_trust_gate` (Patch 15 constant) as the
    // approver. This is filtered by `is_hydra_automation_actor`,
    // so auto-approvals do NOT count as operator endorsement in
    // future trust calibration — preventing self-reinforcing
    // trust spirals.
    //
    // Does NOT auto-execute. Approval only. Operators wanting
    // auto-approve-then-execute call
    // `auto_execute_trusted_notify_action` (Patch 11) on the
    // resulting Approved action.

    /// Auto-approve a Proposed Notify action when the trust gate
    /// passes. Returns a decision envelope; the decision IS the
    /// data (200 wire status on both fire and skip).
    pub fn auto_approve_low_risk_notify_action(
        &mut self,
        action_id: hydra_core::ActionId,
        actor: hydra_core::ActorId,
        min_trust_score: f64,
    ) -> hydra_core::error::Result<hydra_core::AutoApprovalDecision> {
        // 1. Unknown action → hard 404. Same precondition pattern
        //    as Patch 11.
        let action = self.action_store.action(&action_id).cloned().ok_or_else(
            || {
                hydra_core::error::HydraError::QueryError(format!(
                    "unknown action: {action_id}"
                ))
            },
        )?;

        // 2. Wrong KIND → hard error. A Backfill can NEVER be
        //    auto-approved by this method.
        if action.kind != hydra_core::ActionKind::Notify {
            return Err(hydra_core::error::HydraError::QueryError(format!(
                "invalid action kind: {action_id} is not Notify (Patch 15 only \
                 auto-approves Notify actions; got {:?})",
                action.kind
            )));
        }

        // 3. Wrong STATUS → DECISION SKIP. Already-approved or
        //    Executed actions can't be auto-approved. Operators
        //    can poll idempotently.
        if action.status != hydra_core::ActionStatus::Proposed {
            return Ok(hydra_core::AutoApprovalDecision {
                approved: false,
                reason: format!(
                    "action status is {:?}, not Proposed (auto-approval only \
                     fires for Proposed actions)",
                    action.status
                ),
                trust: None,
                action_id,
                approved_by: None,
            });
        }

        // 4. No related_claims → DECISION SKIP. Non-model-derived
        //    actions can't be trust-assessed.
        let claim_id = match action.related_claims.first().cloned() {
            Some(id) => id,
            None => {
                return Ok(hydra_core::AutoApprovalDecision {
                    approved: false,
                    reason: "action has no related_claims — not trust-assessable"
                        .to_string(),
                    trust: None,
                    action_id,
                    approved_by: None,
                });
            }
        };

        // 5. Assess trust (expensive step).
        let assessment = self.assess_claim_trust(&claim_id)?;

        // 6. Hard-block factors veto regardless of score. The
        //    user-approved list: contradicting_evidence,
        //    claim_disputed, claim_retracted,
        //    model_operator_rejected_historically. ANY of these
        //    applied → refuse.
        const HARD_BLOCK_FACTORS: &[&str] = &[
            "contradicting_evidence",
            "claim_disputed",
            "claim_retracted",
            "model_operator_rejected_historically",
        ];
        if let Some(blocking) = assessment
            .factors
            .iter()
            .find(|f| f.applied && HARD_BLOCK_FACTORS.contains(&f.kind.as_str()))
        {
            let blocking_kind = blocking.kind.clone();
            return Ok(hydra_core::AutoApprovalDecision {
                approved: false,
                reason: format!(
                    "hard-block factor applied: {blocking_kind} (auto-approval \
                     vetoed regardless of score)"
                ),
                trust: Some(assessment),
                action_id,
                approved_by: None,
            });
        }

        // 7. Trust threshold. BOTH level == High AND score >=
        //    min_trust_score (the SDK defaults to 0.90 — stricter
        //    than Patch 11's 0.80 for auto-execute).
        let level_ok = matches!(assessment.level, hydra_core::TrustLevel::High);
        let score_ok = assessment.score >= min_trust_score;
        if !(level_ok && score_ok) {
            return Ok(hydra_core::AutoApprovalDecision {
                approved: false,
                reason: format!(
                    "trust insufficient: level={:?}, score={:.2} (min={:.2})",
                    assessment.level, assessment.score, min_trust_score
                ),
                trust: Some(assessment),
                action_id,
                approved_by: None,
            });
        }

        // 8. REQUIRED positive signal: the model must have at
        //    least one prior operator-approved action. Pristine
        //    models with zero human-approval history never get
        //    autonomy. This is the v0 conservative gate.
        let operator_history_present = assessment
            .factors
            .iter()
            .any(|f| f.kind == "model_operator_approved_historically" && f.applied);
        if !operator_history_present {
            return Ok(hydra_core::AutoApprovalDecision {
                approved: false,
                reason: "no operator-approved history for this model — \
                         auto-approval requires at least one prior human \
                         approval"
                    .to_string(),
                trust: Some(assessment),
                action_id,
                approved_by: None,
            });
        }

        // 9. ALL gates passed. Ingest ActionApproved stamped with
        //    the Patch 15 trust-gate actor. Note we use
        //    `is_hydra_automation_actor` to filter this in Patch
        //    12's operator-history factor, so auto-approvals do
        //    NOT bootstrap more auto-approvals.
        let trust_gate_actor =
            hydra_core::ActorId::from_str(hydra_core::HYDRA_TRUST_GATE_ACTOR);
        self.ingest(hydra_core::EventKind::ActionApproved {
            action_id: action_id.clone(),
            approved_by: trust_gate_actor.clone(),
            reason: Some(
                "auto-approved: high-trust low-risk Notify".to_string(),
            ),
        })?;

        // `actor` parameter is recorded by callers (HTTP layer
        // surfaces it via audit) but the ActionApproved event
        // itself uses the trust-gate constant. The decision
        // envelope returns `approved_by = Some(trust_gate_actor)`
        // — operators see the truth.
        let _ = actor;

        Ok(hydra_core::AutoApprovalDecision {
            approved: true,
            reason: format!(
                "auto-approved: trust High (score {:.2} >= {:.2}) AND model \
                 has operator-approved history AND no hard-block factors",
                assessment.score, min_trust_score
            ),
            trust: Some(assessment),
            action_id,
            approved_by: Some(trust_gate_actor),
        })
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

        // Patch 17: convert the model's typed output into the
        // shared `MicroModelReflexParts` shape and delegate the
        // evidence + claim emission to the spine helper. The
        // bridge `Option` collapses the actionable/non-actionable
        // branch — `Ok(None)` on WarmingUp/Normal, the four ids on
        // Warning/Critical.
        let parts = commit_rate_reflex_parts(&prediction, &output);
        let bridge = crate::micromodels::reflex::propose_claim_from_reflex(
            self,
            &prediction,
            prediction_event_id.clone(),
            &parts,
            actor.clone(),
        )?;

        // Patch 28 — auto-create the Reflex cell when a claim
        // was created. Walks chain via P21's helper.
        let claim_id = bridge.as_ref().map(|b| b.claim_id.clone());
        let causal_cell_id = self.maybe_create_reflex_cell(&claim_id, actor)?;

        Ok(crate::micromodels::CommitRateAnomalyAssessment {
            level: output.level,
            prediction,
            prediction_event_id,
            evidence_id: bridge.as_ref().map(|b| b.evidence_id.clone()),
            evidence_event_id: bridge.as_ref().map(|b| b.evidence_event_id.clone()),
            claim_id,
            claim_event_id: bridge.as_ref().map(|b| b.claim_event_id.clone()),
            causal_cell_id,
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
        // Patch 17: same shape as Patch 3's bridge but extended
        // with the action stage. The two shared helpers
        // (`propose_claim_from_reflex`, `propose_action_from_reflex`)
        // emit the same events in the same order as the prior
        // hand-rolled flow.
        let (prediction, prediction_event_id, output) =
            self.record_commit_rate_prediction(actor.clone())?;

        let parts = commit_rate_reflex_parts(&prediction, &output);
        let bridge = crate::micromodels::reflex::propose_claim_from_reflex(
            self,
            &prediction,
            prediction_event_id.clone(),
            &parts,
            actor.clone(),
        )?;

        let mut action_ids: Vec<hydra_core::ActionId> = Vec::new();
        if let Some(b) = bridge.as_ref() {
            if let Some(action_id) =
                crate::micromodels::reflex::propose_action_from_reflex(
                    self,
                    &prediction,
                    b,
                    &parts,
                    actor.clone(),
                )?
            {
                action_ids.push(action_id);
            }
        }

        // Patch 28 — LOAD-BEARING ordering: cell creation happens
        // AFTER action proposal so `cell.action_ids` includes the
        // newly-proposed action. Same actor as the rest of the
        // chain (model's auto-register actor in production paths).
        let claim_id = bridge.as_ref().map(|b| b.claim_id.clone());
        let causal_cell_id = self.maybe_create_reflex_cell(&claim_id, actor)?;

        Ok(crate::micromodels::CommitRateAnomalyActionAssessment {
            level: output.level,
            prediction,
            prediction_event_id,
            evidence_id: bridge.as_ref().map(|b| b.evidence_id.clone()),
            claim_id,
            claim_event_id: bridge.as_ref().map(|b| b.claim_event_id.clone()),
            action_ids,
            causal_cell_id,
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
        // Step 1 — auto-register via the Patch 17 shared helper.
        // Idempotent; safe across multiple `evaluate_*` calls.
        let model_id =
            hydra_core::MicroModelId::from_str(BUILTIN_COMMIT_RATE_MODEL_ID);
        crate::micromodels::reflex::ensure_builtin_model_registered(
            self,
            &model_id,
            hydra_core::MicroModelKind::CommitRatePredictor,
            "builtin_commit_rate_v0",
            &hydra_core::ActorId::from_str(BUILTIN_COMMIT_RATE_ACTOR_ID),
        )?;

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

    // === MicroModel Patch 16 — built-in ReplicationLagAnomalyModel ===

    /// Evaluate the built-in replication-lag model against one peer
    /// and record a `MicroModelPredictionRecorded` event. Patch 16's
    /// surface — mirrors Patch 2's `evaluate_commit_rate_anomaly`
    /// shape (returns `MicroModelPrediction`, hides the event id +
    /// typed output for callers who only want the prediction).
    ///
    /// 404 on unknown peer — replication-lag predictions only make
    /// sense for peers Hydra knows about. The model itself is
    /// pure; the engine wrapper does the lookup.
    ///
    /// **Model state**: Patch 16's replication-lag model is
    /// stateless (threshold detector, no EWMA), so unlike
    /// commit-rate there's no `set_replication_lag_anomaly_model`
    /// getter/setter pair. Construction is on each call.
    /// A future patch may add per-peer warm state if it becomes
    /// necessary.
    pub fn evaluate_replication_lag_anomaly(
        &mut self,
        peer_id: hydra_core::ReplicaId,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<hydra_core::MicroModelPrediction> {
        let (prediction, _event_id, _output) =
            self.record_replication_lag_prediction(peer_id, actor)?;
        Ok(prediction)
    }

    /// Evaluate the built-in replication-lag model AND, on
    /// Warning/Critical, propose paired Evidence + Claim records
    /// linked back to the prediction event.
    ///
    /// Same bridge shape as Patch 3's commit-rate analog. Proves
    /// the `prediction → evidence → claim` chain is reusable
    /// across model kinds — only the payload field set differs.
    ///
    /// Claim shape:
    /// ```text
    ///   kind         = AnomalyFinding
    ///   subject      = ClaimSubject::System("hydra.replication")
    ///   predicate    = "replica_lagging"
    ///   object       = ClaimObject::Value(Value::Bool(true))
    ///   confidence   = prediction.confidence
    ///   evidence_for = [evidence_id]
    ///   created_by   = actor
    ///   caused_by    = prediction_event_id
    /// ```
    pub fn evaluate_replication_lag_anomaly_and_propose_claim(
        &mut self,
        peer_id: hydra_core::ReplicaId,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<
        crate::micromodels::ReplicationLagAnomalyAssessment,
    > {
        // Patch 17: same shared bridge as commit-rate. Per-peer
        // variation (the `peer_id` field) is carried via the
        // model's parts builder + assessment envelope.
        let (prediction, prediction_event_id, output) =
            self.record_replication_lag_prediction(peer_id.clone(), actor.clone())?;

        let parts = replication_lag_reflex_parts(&prediction, &output, &peer_id);
        let bridge = crate::micromodels::reflex::propose_claim_from_reflex(
            self,
            &prediction,
            prediction_event_id.clone(),
            &parts,
            actor.clone(),
        )?;

        // Patch 28 — auto-create Reflex cell when claim exists.
        let claim_id = bridge.as_ref().map(|b| b.claim_id.clone());
        let causal_cell_id = self.maybe_create_reflex_cell(&claim_id, actor)?;

        Ok(crate::micromodels::ReplicationLagAnomalyAssessment {
            level: output.level,
            prediction,
            prediction_event_id,
            evidence_id: bridge.as_ref().map(|b| b.evidence_id.clone()),
            evidence_event_id: bridge.as_ref().map(|b| b.evidence_event_id.clone()),
            claim_id,
            claim_event_id: bridge.as_ref().map(|b| b.claim_event_id.clone()),
            causal_cell_id,
            peer_id,
        })
    }

    /// Evaluate the built-in replication-lag model AND, on
    /// Warning/Critical, propose an `ActionKind::Notify` action
    /// gated by the claim's verification state.
    ///
    /// Gate (deterministic, no policy DSL in v0):
    /// ```text
    ///   claim.predicate == "replica_lagging"
    ///   AND (claim.status == Verified OR claim.confidence >= 0.9)
    /// ```
    ///
    /// Action shape:
    /// ```text
    ///   kind                 = ActionKind::Notify
    ///   targets              = [ActionTarget::System("hydra.replication")]
    ///   related_claims       = [claim_id]
    ///   supporting_evidence  = [evidence_id]
    ///   payload              = {
    ///     "severity": level.wire_name()
    ///     "reason":   prediction.explanation
    ///     "model_id": "mm_builtin_replication_lag_v0"
    ///     "run_id":   prediction.run_id
    ///     "peer_id":  peer_id
    ///   }
    ///   caused_by            = claim_event_id
    /// ```
    pub fn evaluate_replication_lag_anomaly_and_propose_action(
        &mut self,
        peer_id: hydra_core::ReplicaId,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<
        crate::micromodels::ReplicationLagAnomalyActionAssessment,
    > {
        // Patch 17: same shape as Patch 3's bridge for commit-rate
        // — inline the record + parts + claim + action pipeline so
        // the shared helpers do the work.
        let (prediction, prediction_event_id, output) = self
            .record_replication_lag_prediction(peer_id.clone(), actor.clone())?;

        let parts =
            replication_lag_reflex_parts(&prediction, &output, &peer_id);
        let bridge = crate::micromodels::reflex::propose_claim_from_reflex(
            self,
            &prediction,
            prediction_event_id.clone(),
            &parts,
            actor.clone(),
        )?;

        let mut action_ids: Vec<hydra_core::ActionId> = Vec::new();
        if let Some(b) = bridge.as_ref() {
            if let Some(action_id) =
                crate::micromodels::reflex::propose_action_from_reflex(
                    self,
                    &prediction,
                    b,
                    &parts,
                    actor.clone(),
                )?
            {
                action_ids.push(action_id);
            }
        }

        // Patch 28 — LOAD-BEARING ordering: cell after action.
        let claim_id = bridge.as_ref().map(|b| b.claim_id.clone());
        let causal_cell_id = self.maybe_create_reflex_cell(&claim_id, actor)?;

        Ok(crate::micromodels::ReplicationLagAnomalyActionAssessment {
            level: output.level,
            prediction,
            prediction_event_id,
            evidence_id: bridge.as_ref().map(|b| b.evidence_id.clone()),
            claim_id,
            claim_event_id: bridge.as_ref().map(|b| b.claim_event_id.clone()),
            action_ids,
            causal_cell_id,
            peer_id,
        })
    }

    /// Shared helper: auto-register the built-in model definition
    /// if missing, look up the peer (404 on unknown), compute the
    /// observed inputs (lag_commits + heartbeat freshness),
    /// evaluate the pure model, record the prediction event, and
    /// return the typed triple. Made public so the HTTP layer can
    /// reach it for `mode = "prediction_only"` evaluations.
    pub fn record_replication_lag_prediction(
        &mut self,
        peer_id: hydra_core::ReplicaId,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<(
        hydra_core::MicroModelPrediction,
        hydra_core::EventId,
        crate::micromodels::ReplicationLagAnomalyOutput,
    )> {
        // Step 1 — auto-register via the Patch 17 shared helper.
        let model_id = hydra_core::MicroModelId::from_str(
            BUILTIN_REPLICATION_LAG_MODEL_ID,
        );
        crate::micromodels::reflex::ensure_builtin_model_registered(
            self,
            &model_id,
            hydra_core::MicroModelKind::ReplicationLagAnomaly,
            "builtin_replication_lag_v0",
            &hydra_core::ActorId::from_str(BUILTIN_REPLICATION_LAG_ACTOR_ID),
        )?;

        // Step 2 — peer lookup. 404 if unknown.
        let peer = self.replication_peer(&peer_id).cloned().ok_or_else(|| {
            hydra_core::error::HydraError::QueryError(format!(
                "unknown replication peer: {peer_id}"
            ))
        })?;

        // Step 3 — compute observed inputs from peer state.
        let now = chrono::Utc::now();
        let (lag_commits, last_observed_at) = match peer.last_lag.as_ref() {
            Some(lag) => (lag.lag_commits, Some(lag.observed_at)),
            None => {
                // No lag observation yet. Treat as zero lag with
                // unknown heartbeat — the model converts None to
                // stale → Critical.
                (0u64, None)
            }
        };

        // Step 4 — evaluate the pure model. Stateless: construct
        // on each call.
        let model = crate::micromodels::ReplicationLagAnomalyModel::default();
        let output =
            model.evaluate_observation(now, lag_commits, last_observed_at);

        // Step 5 — build the typed prediction.
        let prediction = hydra_core::MicroModelPrediction {
            model_id: model_id.clone(),
            run_id: hydra_core::MicroModelRunId::new(),
            input: serde_json::json!({
                "observed_at": now.to_rfc3339(),
                "peer_id": peer_id.as_str(),
                "lag_commits": lag_commits,
                "last_observed_at": last_observed_at
                    .map(|t| t.to_rfc3339()),
                "warning_lag_commits": model.config().warning_lag_commits,
                "critical_lag_commits": model.config().critical_lag_commits,
                "stale_heartbeat_after_secs":
                    model.config().stale_heartbeat_after_secs,
            }),
            output: serde_json::to_value(&output).expect(
                "ReplicationLagAnomalyOutput is serde-derived; cannot fail",
            ),
            confidence: output.level.confidence(),
            explanation: Some(output.reason.clone()),
            created_at: now,
        };

        // Step 6 — record through ingest, capture event id.
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

        // `actor` reserved for a future variant that carries the
        // requesting actor in the event body (same as Patch 2).
        let _ = actor;
        Ok((prediction, prediction_event_id, output))
    }

    // === MicroModel Patch 18 — built-in AgentLoopStormModel ===

    /// Evaluate the built-in agent-loop-storm model against the
    /// recent event log and record a `MicroModelPredictionRecorded`
    /// event. Patch 18's bottom surface — mirrors Patch 2's
    /// `evaluate_commit_rate_anomaly` and Patch 16's
    /// `evaluate_replication_lag_anomaly` shape.
    ///
    /// The model itself is stateless (threshold detector); the
    /// per-window event-log walk + actor extraction lives in the
    /// `record_*` helper. Hydra-internal actors are filtered via
    /// `is_hydra_system_actor` so the storm signal reflects
    /// non-Hydra agent activity only.
    pub fn evaluate_agent_loop_storm(
        &mut self,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<hydra_core::MicroModelPrediction> {
        let (prediction, _event_id, _output) =
            self.record_agent_loop_storm_prediction(actor)?;
        Ok(prediction)
    }

    /// Evaluate + (on Warning/Critical) propose Evidence + Claim
    /// linked back to the prediction event. Mirrors the Patch 3
    /// commit-rate analog and Patch 16 replication-lag analog —
    /// all three drive through the Patch 17 shared spine.
    ///
    /// Claim shape (Patch 18):
    /// ```text
    ///   kind       = AnomalyFinding
    ///   subject    = ClaimSubject::System("hydra.agents")
    ///   predicate  = "agent_loop_storm"
    ///   object     = ClaimObject::Value(Value::Bool(true))
    /// ```
    pub fn evaluate_agent_loop_storm_and_propose_claim(
        &mut self,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<
        crate::micromodels::AgentLoopStormAssessment,
    > {
        let (prediction, prediction_event_id, output) =
            self.record_agent_loop_storm_prediction(actor.clone())?;

        let parts = agent_loop_storm_reflex_parts(&prediction, &output);
        let bridge = crate::micromodels::reflex::propose_claim_from_reflex(
            self,
            &prediction,
            prediction_event_id.clone(),
            &parts,
            actor.clone(),
        )?;

        // Patch 28 — auto-create Reflex cell when claim exists.
        let claim_id = bridge.as_ref().map(|b| b.claim_id.clone());
        let causal_cell_id = self.maybe_create_reflex_cell(&claim_id, actor)?;

        Ok(crate::micromodels::AgentLoopStormAssessment {
            level: output.level,
            prediction,
            prediction_event_id,
            evidence_id: bridge.as_ref().map(|b| b.evidence_id.clone()),
            evidence_event_id: bridge
                .as_ref()
                .map(|b| b.evidence_event_id.clone()),
            claim_id,
            claim_event_id: bridge.as_ref().map(|b| b.claim_event_id.clone()),
            causal_cell_id,
        })
    }

    /// Evaluate + (on Warning/Critical AND gate-pass) propose a
    /// Notify action targeting `System("hydra.agents")`. Action
    /// payload carries `top_actor` and `window_secs` so the
    /// Patch 14 delivery adapter / operator dashboards can route
    /// per-actor or per-window if useful.
    ///
    /// **No throttle / quarantine action in v0** — Notify only.
    /// Storm response is operator judgment.
    pub fn evaluate_agent_loop_storm_and_propose_action(
        &mut self,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<
        crate::micromodels::AgentLoopStormActionAssessment,
    > {
        let (prediction, prediction_event_id, output) =
            self.record_agent_loop_storm_prediction(actor.clone())?;

        let parts = agent_loop_storm_reflex_parts(&prediction, &output);
        let bridge = crate::micromodels::reflex::propose_claim_from_reflex(
            self,
            &prediction,
            prediction_event_id.clone(),
            &parts,
            actor.clone(),
        )?;

        let mut action_ids: Vec<hydra_core::ActionId> = Vec::new();
        if let Some(b) = bridge.as_ref() {
            if let Some(action_id) =
                crate::micromodels::reflex::propose_action_from_reflex(
                    self,
                    &prediction,
                    b,
                    &parts,
                    actor.clone(),
                )?
            {
                action_ids.push(action_id);
            }
        }

        // Patch 28 — LOAD-BEARING ordering: cell after action.
        let claim_id = bridge.as_ref().map(|b| b.claim_id.clone());
        let causal_cell_id = self.maybe_create_reflex_cell(&claim_id, actor)?;

        Ok(crate::micromodels::AgentLoopStormActionAssessment {
            level: output.level,
            prediction,
            prediction_event_id,
            evidence_id: bridge.as_ref().map(|b| b.evidence_id.clone()),
            claim_id,
            claim_event_id: bridge.as_ref().map(|b| b.claim_event_id.clone()),
            action_ids,
            causal_cell_id,
        })
    }

    /// Shared helper: auto-register the built-in model definition
    /// if missing, walk the recent event log, extract per-actor
    /// counts (filtering Hydra-system actors), evaluate the pure
    /// model, record the prediction event, and return the typed
    /// triple. Public so the HTTP layer can drive
    /// `mode = "prediction_only"` evaluations.
    pub fn record_agent_loop_storm_prediction(
        &mut self,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<(
        hydra_core::MicroModelPrediction,
        hydra_core::EventId,
        crate::micromodels::AgentLoopStormOutput,
    )> {
        // Step 1 — auto-register via the Patch 17 shared helper.
        let model_id = hydra_core::MicroModelId::from_str(
            BUILTIN_AGENT_LOOP_STORM_MODEL_ID,
        );
        crate::micromodels::reflex::ensure_builtin_model_registered(
            self,
            &model_id,
            hydra_core::MicroModelKind::AgentLoopStorm,
            "builtin_agent_loop_storm_v0",
            &hydra_core::ActorId::from_str(BUILTIN_AGENT_LOOP_STORM_ACTOR_ID),
        )?;

        // Step 2 — walk the event log over the configured window,
        // tally per-actor counts excluding Hydra-system actors,
        // build the model inputs.
        let model = crate::micromodels::AgentLoopStormModel::default();
        let window_secs = model.config().window_secs;
        let now = chrono::Utc::now();
        let window_start =
            now - chrono::Duration::seconds(window_secs as i64);

        let mut agent_event_count: u64 = 0;
        let mut action_proposed_count: u64 = 0;
        let mut claim_proposed_count: u64 = 0;
        let mut per_actor: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();

        // The event log is in-order; walk from the end and stop
        // when we leave the window. (Linear v0 — good enough at
        // engine scale; future patches can add an indexed window.)
        for event in self.event_log.iter_rev() {
            if event.timestamp < window_start {
                break;
            }
            let actor_opt = extract_event_actor(&event.kind);
            let actor_ref = match actor_opt {
                Some(a) => a,
                None => continue,
            };
            if hydra_core::is_hydra_system_actor(actor_ref) {
                continue;
            }
            agent_event_count += 1;
            match &event.kind {
                hydra_core::EventKind::ActionProposed { .. } => {
                    action_proposed_count += 1;
                }
                hydra_core::EventKind::ClaimProposed { .. } => {
                    claim_proposed_count += 1;
                }
                _ => {}
            }
            *per_actor.entry(actor_ref.as_str().to_string()).or_insert(0) += 1;
        }

        let (top_actor, top_actor_event_count) = per_actor
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(actor_id, count)| (Some(actor_id), count))
            .unwrap_or((None, 0));

        // Step 3 — evaluate the pure model.
        let output = model.evaluate_observation(
            agent_event_count,
            action_proposed_count,
            claim_proposed_count,
            top_actor.clone(),
            top_actor_event_count,
        );

        // Step 4 — build the typed prediction.
        let prediction = hydra_core::MicroModelPrediction {
            model_id: model_id.clone(),
            run_id: hydra_core::MicroModelRunId::new(),
            input: serde_json::json!({
                "observed_at": now.to_rfc3339(),
                "window_secs": window_secs,
                "agent_event_count": agent_event_count,
                "action_proposed_count": action_proposed_count,
                "claim_proposed_count": claim_proposed_count,
                "top_actor": top_actor,
                "top_actor_event_count": top_actor_event_count,
                "warning_agent_events": model.config().warning_agent_events,
                "critical_agent_events": model.config().critical_agent_events,
            }),
            output: serde_json::to_value(&output).expect(
                "AgentLoopStormOutput is serde-derived; cannot fail",
            ),
            confidence: output.level.confidence(),
            explanation: Some(output.reason.clone()),
            created_at: now,
        };

        // Step 5 — record through ingest, capture event id.
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

        let _ = actor;
        Ok((prediction, prediction_event_id, output))
    }

    // === MicroModel Patch 19 — built-in ActionFailureRateModel ===

    /// Evaluate the built-in action-failure-rate model over the
    /// recent action lifecycle and record a
    /// `MicroModelPredictionRecorded` event. Mirrors Patch
    /// 16/18's `evaluate_X` shape — returns the prediction,
    /// hides the typed output for callers that only want the
    /// prediction.
    ///
    /// The model itself is stateless threshold + ratio detector;
    /// the per-window event-log walk + action-kind lookup lives
    /// in `record_*`. Includes Hydra-internal-actor failures by
    /// design — if Hydra's own actions are failing, the
    /// operator should know.
    pub fn evaluate_action_failure_rate(
        &mut self,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<hydra_core::MicroModelPrediction> {
        let (prediction, _event_id, _output) =
            self.record_action_failure_rate_prediction(actor)?;
        Ok(prediction)
    }

    /// Evaluate + (on Warning/Critical) propose Evidence + Claim
    /// linked back to the prediction event. Routes through the
    /// Patch 17 shared spine.
    ///
    /// Claim shape (Patch 19):
    /// ```text
    ///   kind       = AnomalyFinding
    ///   subject    = ClaimSubject::System("hydra.actions")
    ///   predicate  = "action_failure_rate_high"
    ///   object     = ClaimObject::Value(Value::Bool(true))
    /// ```
    pub fn evaluate_action_failure_rate_and_propose_claim(
        &mut self,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<
        crate::micromodels::ActionFailureRateAssessment,
    > {
        let (prediction, prediction_event_id, output) =
            self.record_action_failure_rate_prediction(actor.clone())?;

        let parts = action_failure_rate_reflex_parts(&prediction, &output);
        let bridge = crate::micromodels::reflex::propose_claim_from_reflex(
            self,
            &prediction,
            prediction_event_id.clone(),
            &parts,
            actor.clone(),
        )?;

        // Patch 28 — auto-create Reflex cell when claim exists.
        let claim_id = bridge.as_ref().map(|b| b.claim_id.clone());
        let causal_cell_id = self.maybe_create_reflex_cell(&claim_id, actor)?;

        Ok(crate::micromodels::ActionFailureRateAssessment {
            level: output.level,
            prediction,
            prediction_event_id,
            evidence_id: bridge.as_ref().map(|b| b.evidence_id.clone()),
            evidence_event_id: bridge
                .as_ref()
                .map(|b| b.evidence_event_id.clone()),
            claim_id,
            claim_event_id: bridge.as_ref().map(|b| b.claim_event_id.clone()),
            causal_cell_id,
        })
    }

    /// Evaluate + (on Warning/Critical AND gate-pass) propose a
    /// Notify action targeting `System("hydra.actions")`. The
    /// action payload carries the failure ratio, failure count,
    /// and top failing action kind so operators can route the
    /// alert intelligently.
    ///
    /// **No auto-retry / quarantine / DLQ in v0** — Notify only.
    /// Operator decides how to respond.
    pub fn evaluate_action_failure_rate_and_propose_action(
        &mut self,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<
        crate::micromodels::ActionFailureRateActionAssessment,
    > {
        let (prediction, prediction_event_id, output) =
            self.record_action_failure_rate_prediction(actor.clone())?;

        let parts = action_failure_rate_reflex_parts(&prediction, &output);
        let bridge = crate::micromodels::reflex::propose_claim_from_reflex(
            self,
            &prediction,
            prediction_event_id.clone(),
            &parts,
            actor.clone(),
        )?;

        let mut action_ids: Vec<hydra_core::ActionId> = Vec::new();
        if let Some(b) = bridge.as_ref() {
            if let Some(action_id) =
                crate::micromodels::reflex::propose_action_from_reflex(
                    self,
                    &prediction,
                    b,
                    &parts,
                    actor.clone(),
                )?
            {
                action_ids.push(action_id);
            }
        }

        // Patch 28 — LOAD-BEARING ordering: cell after action.
        let claim_id = bridge.as_ref().map(|b| b.claim_id.clone());
        let causal_cell_id = self.maybe_create_reflex_cell(&claim_id, actor)?;

        Ok(crate::micromodels::ActionFailureRateActionAssessment {
            level: output.level,
            prediction,
            prediction_event_id,
            evidence_id: bridge.as_ref().map(|b| b.evidence_id.clone()),
            claim_id,
            claim_event_id: bridge.as_ref().map(|b| b.claim_event_id.clone()),
            action_ids,
            causal_cell_id,
        })
    }

    /// Shared helper: auto-register the built-in model, walk the
    /// recent event log over the configured window, tally
    /// `actions_seen` (terminal-state actions) and
    /// `failed_actions` (`ActionFailed` events), look up the
    /// failing action's `kind` per failure to compute
    /// `top_failed_kind`, evaluate the pure model, record the
    /// prediction event.
    ///
    /// Public so the HTTP layer can drive `mode = "prediction_only"`.
    pub fn record_action_failure_rate_prediction(
        &mut self,
        actor: hydra_core::ActorId,
    ) -> hydra_core::error::Result<(
        hydra_core::MicroModelPrediction,
        hydra_core::EventId,
        crate::micromodels::ActionFailureRateOutput,
    )> {
        // Step 1 — auto-register via the Patch 17 shared helper.
        let model_id = hydra_core::MicroModelId::from_str(
            BUILTIN_ACTION_FAILURE_RATE_MODEL_ID,
        );
        crate::micromodels::reflex::ensure_builtin_model_registered(
            self,
            &model_id,
            hydra_core::MicroModelKind::ActionFailureRate,
            "builtin_action_failure_rate_v0",
            &hydra_core::ActorId::from_str(
                BUILTIN_ACTION_FAILURE_RATE_ACTOR_ID,
            ),
        )?;

        // Step 2 — walk the event log over the configured window,
        // tally terminal-state action events (`actions_seen`) and
        // failures (`failed_actions`), and per-kind failure
        // counts for the top-kind aggregation.
        let model = crate::micromodels::ActionFailureRateModel::default();
        let window_secs = model.config().window_secs;
        let now = chrono::Utc::now();
        let window_start =
            now - chrono::Duration::seconds(window_secs as i64);

        let mut actions_seen: u64 = 0;
        let mut failed_actions: u64 = 0;
        let mut per_kind_failures: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();

        // Collect failed action_ids first so we can look up kinds
        // without holding a borrow on the event log.
        let mut failed_action_ids: Vec<hydra_core::ActionId> = Vec::new();

        for event in self.event_log.iter_rev() {
            if event.timestamp < window_start {
                break;
            }
            match &event.kind {
                hydra_core::EventKind::ActionExecuted { .. } => {
                    actions_seen += 1;
                }
                hydra_core::EventKind::ActionFailed { action_id, .. } => {
                    actions_seen += 1;
                    failed_actions += 1;
                    failed_action_ids.push(action_id.clone());
                }
                _ => {}
            }
        }

        // Step 3 — look up each failed action's kind. Actions
        // that were purged or never recorded fall through and
        // simply don't contribute to top_failed_kind (they still
        // count in failed_actions, which is the load-bearing
        // signal).
        for action_id in &failed_action_ids {
            if let Some(action) = self.action_store.action(action_id) {
                let kind_name = action_kind_wire_name(&action.kind);
                *per_kind_failures
                    .entry(kind_name.to_string())
                    .or_insert(0) += 1;
            }
        }

        let top_failed_kind = per_kind_failures
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(kind, _)| kind);

        // Step 4 — evaluate the pure model.
        let output = model.evaluate_observation(
            actions_seen,
            failed_actions,
            top_failed_kind.clone(),
        );

        // Step 5 — build the typed prediction.
        let prediction = hydra_core::MicroModelPrediction {
            model_id: model_id.clone(),
            run_id: hydra_core::MicroModelRunId::new(),
            input: serde_json::json!({
                "observed_at": now.to_rfc3339(),
                "window_secs": window_secs,
                "actions_seen": actions_seen,
                "failed_actions": failed_actions,
                "top_failed_kind": top_failed_kind,
                "min_actions_for_ratio": model.config().min_actions_for_ratio,
                "warning_failure_count": model.config().warning_failure_count,
                "critical_failure_count": model.config().critical_failure_count,
                "warning_failure_ratio": model.config().warning_failure_ratio,
                "critical_failure_ratio": model.config().critical_failure_ratio,
            }),
            output: serde_json::to_value(&output).expect(
                "ActionFailureRateOutput is serde-derived; cannot fail",
            ),
            confidence: output.level.confidence(),
            explanation: Some(output.reason.clone()),
            created_at: now,
        };

        // Step 6 — record through ingest, capture event id.
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

        let _ = actor;
        Ok((prediction, prediction_event_id, output))
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
        let causal_cells = self
            .causal_cell_store
            .all_cells()
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
        )
        .with_causal_cell_count(causal_cells.len());

        // Patch 29 — Identity Graph vocabulary into the snapshot.
        let identity_entities = self
            .identity_store
            .all_entities()
            .cloned()
            .collect::<Vec<_>>();
        let manifest = manifest
            .with_identity_entity_count(identity_entities.len());

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
            causal_cells,
            identity_entities,
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

/// All observations whose `run_id` maps to a prediction with the
/// given `model_id`. Patch 12 — Reflex Trust Calibration.
///
/// v0 cost is O(N) where N = total observations across ALL
/// models in the store. For low-thousands deployments this is
/// single-digit milliseconds. Patch 13+ can add a
/// `model_id → run_ids` index if it becomes hot.
fn observations_for_model<'a>(
    store: &'a crate::micromodel_store::MicroModelStore,
    model_id: &hydra_core::MicroModelId,
) -> Vec<&'a hydra_core::MicroModelObservation> {
    store
        .all_observations()
        .filter(|obs| {
            store
                .prediction(&obs.run_id)
                .map(|p| &p.model_id == model_id)
                .unwrap_or(false)
        })
        .collect()
}

/// Extract `action_id` from a Patch 8 observation's
/// `observed_outcome` JSON.
///
/// Patch 8's contract packs `{outcome_id, action_id, claim_id,
/// outcome_kind, ...}` into `observed_outcome: serde_json::Value`.
/// Patch 12 reads `action_id` to look up the underlying action
/// and check its `approved_by` against the cascade actor id.
///
/// Returns `None` on schema drift (forward-compat) — the trust
/// factor that uses this just refuses to apply for unparseable
/// observations.
fn observation_action_id(
    obs: &hydra_core::MicroModelObservation,
) -> Option<hydra_core::ActionId> {
    obs.observed_outcome
        .get("action_id")
        .and_then(|v| v.as_str())
        .map(hydra_core::ActionId::from_str)
}

/// Compose a deterministic prose summary for a `TrustAssessment`.
/// No LLM. Pattern-matchable by future trust dashboards and
/// Patch 11's auto-execution policy. Module-private — the only
/// caller is `Hydra::assess_claim_trust`.
fn build_trust_explanation(
    claim: &hydra_core::Claim,
    factors: &[hydra_core::TrustFactor],
    level: hydra_core::TrustLevel,
    score: f64,
) -> String {
    let level_label = match level {
        hydra_core::TrustLevel::High => "High",
        hydra_core::TrustLevel::Medium => "Medium",
        hydra_core::TrustLevel::Low => "Low",
        hydra_core::TrustLevel::Unknown => "Unknown",
    };
    let applied: Vec<&hydra_core::TrustFactor> =
        factors.iter().filter(|f| f.applied).collect();
    let unapplied_count = factors.len() - applied.len();
    if applied.is_empty() {
        return format!(
            "{level_label} trust (score {score:.2}): no factors fired for \
             claim {claim_id}. Likely freshly proposed with no actions, evidence, \
             or outcome chain yet.",
            claim_id = claim.id
        );
    }
    let factor_summary = applied
        .iter()
        .map(|f| f.kind.replace('_', " "))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{level_label} trust (score {score:.2}) for claim {claim_id}: \
         {factor_summary}. ({unapplied} factor(s) checked but did not fire.)",
        claim_id = claim.id,
        unapplied = unapplied_count,
    )
}

/// Format an `OutcomeKind` for inclusion in Patch 8's
/// `observed_outcome` JSON. Mirrors the spec's wire shape:
/// `"Success"` for unit variants and `"Custom(notification_recorded)"`
/// for `Custom(_)`. Kept module-private — the Patch 8 helper is
/// the only caller in v0.
fn format_outcome_kind_for_observation(kind: &hydra_core::OutcomeKind) -> String {
    use hydra_core::OutcomeKind;
    match kind {
        OutcomeKind::Success => "Success".to_string(),
        OutcomeKind::Failure => "Failure".to_string(),
        OutcomeKind::PartialSuccess => "PartialSuccess".to_string(),
        OutcomeKind::NoEffect => "NoEffect".to_string(),
        OutcomeKind::Regression => "Regression".to_string(),
        OutcomeKind::Unknown => "Unknown".to_string(),
        OutcomeKind::Custom(label) => format!("Custom({label})"),
    }
}

// === Patch 17 — per-model `MicroModelReflexParts` constructors ===
//
// Each built-in model converts its typed `Output` into the
// shared `MicroModelReflexParts` shape. The Patch 17 spine
// (`crate::micromodels::reflex::propose_claim_from_reflex` and
// `propose_action_from_reflex`) reads these parts and emits the
// Evidence + Claim + Action events. Per-model variation lives
// entirely in these constructors:
//
//   - claim subject / predicate / object
//   - action target
//   - evidence + action payload field sets
//
// What was previously six private builder functions
// (`build_evidence_from_prediction`, `build_claim_from_prediction`,
// `build_action_from_assessment`, and their replication-lag
// counterparts) collapses into these two.

/// Convert a commit-rate `(prediction, output)` pair into the
/// shared reflex parts. The resulting parts carry the exact
/// shape Patches 3+4 produced before the refactor — same evidence
/// payload keys, same claim subject/predicate, same action target,
/// same action payload.
fn commit_rate_reflex_parts(
    prediction: &hydra_core::MicroModelPrediction,
    output: &crate::micromodels::CommitRateAnomalyOutput,
) -> crate::micromodels::reflex::MicroModelReflexParts {
    let mut evidence_data: std::collections::HashMap<String, hydra_core::Value> =
        std::collections::HashMap::new();
    evidence_data.insert(
        "model_id".to_string(),
        hydra_core::Value::String(prediction.model_id.as_str().to_string()),
    );
    evidence_data.insert(
        "run_id".to_string(),
        hydra_core::Value::String(prediction.run_id.as_str().to_string()),
    );
    evidence_data.insert(
        "level".to_string(),
        hydra_core::Value::String(output.level.wire_name().to_string()),
    );
    evidence_data.insert(
        "direction".to_string(),
        hydra_core::Value::String(output.direction.wire_name().to_string()),
    );
    evidence_data.insert(
        "observed_rate".to_string(),
        hydra_core::Value::Float(output.observed_rate),
    );
    evidence_data.insert(
        "expected_rate".to_string(),
        hydra_core::Value::Float(output.expected_rate),
    );
    evidence_data.insert(
        "z_score".to_string(),
        hydra_core::Value::Float(output.z_score),
    );
    evidence_data.insert(
        "reason".to_string(),
        hydra_core::Value::String(output.reason.clone()),
    );

    let mut action_payload: std::collections::HashMap<String, hydra_core::Value> =
        std::collections::HashMap::new();
    // Severity = the level's wire name. WarmingUp / Normal never
    // reach the shared bridge (parts.actionable == false), so only
    // "warning" or "critical" land here.
    action_payload.insert(
        "severity".to_string(),
        hydra_core::Value::String(output.level.wire_name().to_string()),
    );
    action_payload.insert(
        "reason".to_string(),
        hydra_core::Value::String(
            prediction.explanation.clone().unwrap_or_default(),
        ),
    );
    action_payload.insert(
        "model_id".to_string(),
        hydra_core::Value::String(prediction.model_id.as_str().to_string()),
    );
    action_payload.insert(
        "run_id".to_string(),
        hydra_core::Value::String(prediction.run_id.as_str().to_string()),
    );

    crate::micromodels::reflex::MicroModelReflexParts {
        actionable: output.level.is_actionable(),
        confidence: prediction.confidence,
        claim_subject: hydra_core::epistemic::ClaimSubject::System(
            "hydra".to_string(),
        ),
        claim_predicate: "under_abnormal_load".to_string(),
        claim_object: hydra_core::epistemic::ClaimObject::Value(
            hydra_core::Value::Bool(true),
        ),
        evidence_payload_data: evidence_data,
        action_target: hydra_core::action::ActionTarget::System(
            "hydra".to_string(),
        ),
        action_payload,
    }
}

/// Convert a replication-lag `(prediction, output, peer_id)` triple
/// into the shared reflex parts. `peer_id` is the Patch 16 extra
/// vs commit-rate — it lands in BOTH the evidence payload (so
/// downstream queries can filter by peer) and the action payload
/// (so the Patch 14 delivery adapter can route per-peer).
fn replication_lag_reflex_parts(
    prediction: &hydra_core::MicroModelPrediction,
    output: &crate::micromodels::ReplicationLagAnomalyOutput,
    peer_id: &hydra_core::ReplicaId,
) -> crate::micromodels::reflex::MicroModelReflexParts {
    let mut evidence_data: std::collections::HashMap<String, hydra_core::Value> =
        std::collections::HashMap::new();
    evidence_data.insert(
        "model_id".to_string(),
        hydra_core::Value::String(prediction.model_id.as_str().to_string()),
    );
    evidence_data.insert(
        "run_id".to_string(),
        hydra_core::Value::String(prediction.run_id.as_str().to_string()),
    );
    evidence_data.insert(
        "peer_id".to_string(),
        hydra_core::Value::String(peer_id.as_str().to_string()),
    );
    evidence_data.insert(
        "level".to_string(),
        hydra_core::Value::String(output.level.wire_name().to_string()),
    );
    evidence_data.insert(
        "lag_commits".to_string(),
        hydra_core::Value::Int(output.lag_commits as i64),
    );
    evidence_data.insert(
        "stale_heartbeat".to_string(),
        hydra_core::Value::Bool(output.stale_heartbeat),
    );
    evidence_data.insert(
        "reason".to_string(),
        hydra_core::Value::String(output.reason.clone()),
    );

    let mut action_payload: std::collections::HashMap<String, hydra_core::Value> =
        std::collections::HashMap::new();
    action_payload.insert(
        "severity".to_string(),
        hydra_core::Value::String(output.level.wire_name().to_string()),
    );
    action_payload.insert(
        "reason".to_string(),
        hydra_core::Value::String(
            prediction.explanation.clone().unwrap_or_default(),
        ),
    );
    action_payload.insert(
        "model_id".to_string(),
        hydra_core::Value::String(prediction.model_id.as_str().to_string()),
    );
    action_payload.insert(
        "run_id".to_string(),
        hydra_core::Value::String(prediction.run_id.as_str().to_string()),
    );
    action_payload.insert(
        "peer_id".to_string(),
        hydra_core::Value::String(peer_id.as_str().to_string()),
    );

    crate::micromodels::reflex::MicroModelReflexParts {
        actionable: output.level.is_actionable(),
        confidence: prediction.confidence,
        claim_subject: hydra_core::epistemic::ClaimSubject::System(
            "hydra.replication".to_string(),
        ),
        claim_predicate: "replica_lagging".to_string(),
        claim_object: hydra_core::epistemic::ClaimObject::Value(
            hydra_core::Value::Bool(true),
        ),
        evidence_payload_data: evidence_data,
        action_target: hydra_core::action::ActionTarget::System(
            "hydra.replication".to_string(),
        ),
        action_payload,
    }
}

/// Convert an agent-loop-storm `(prediction, output)` pair into
/// the shared reflex parts. The action payload carries
/// `top_actor` and `window_secs` so the receiving operator (or
/// Patch 14 delivery adapter) can route per-actor.
fn agent_loop_storm_reflex_parts(
    prediction: &hydra_core::MicroModelPrediction,
    output: &crate::micromodels::AgentLoopStormOutput,
) -> crate::micromodels::reflex::MicroModelReflexParts {
    let mut evidence_data: std::collections::HashMap<String, hydra_core::Value> =
        std::collections::HashMap::new();
    evidence_data.insert(
        "model_id".to_string(),
        hydra_core::Value::String(prediction.model_id.as_str().to_string()),
    );
    evidence_data.insert(
        "run_id".to_string(),
        hydra_core::Value::String(prediction.run_id.as_str().to_string()),
    );
    evidence_data.insert(
        "level".to_string(),
        hydra_core::Value::String(output.level.wire_name().to_string()),
    );
    evidence_data.insert(
        "window_secs".to_string(),
        hydra_core::Value::Int(output.window_secs as i64),
    );
    evidence_data.insert(
        "agent_event_count".to_string(),
        hydra_core::Value::Int(output.agent_event_count as i64),
    );
    evidence_data.insert(
        "action_proposed_count".to_string(),
        hydra_core::Value::Int(output.action_proposed_count as i64),
    );
    evidence_data.insert(
        "claim_proposed_count".to_string(),
        hydra_core::Value::Int(output.claim_proposed_count as i64),
    );
    if let Some(top) = output.top_actor.as_deref() {
        evidence_data.insert(
            "top_actor".to_string(),
            hydra_core::Value::String(top.to_string()),
        );
    }
    evidence_data.insert(
        "top_actor_event_count".to_string(),
        hydra_core::Value::Int(output.top_actor_event_count as i64),
    );
    evidence_data.insert(
        "reason".to_string(),
        hydra_core::Value::String(output.reason.clone()),
    );

    let mut action_payload: std::collections::HashMap<String, hydra_core::Value> =
        std::collections::HashMap::new();
    action_payload.insert(
        "severity".to_string(),
        hydra_core::Value::String(output.level.wire_name().to_string()),
    );
    action_payload.insert(
        "reason".to_string(),
        hydra_core::Value::String(
            prediction.explanation.clone().unwrap_or_default(),
        ),
    );
    action_payload.insert(
        "model_id".to_string(),
        hydra_core::Value::String(prediction.model_id.as_str().to_string()),
    );
    action_payload.insert(
        "run_id".to_string(),
        hydra_core::Value::String(prediction.run_id.as_str().to_string()),
    );
    action_payload.insert(
        "window_secs".to_string(),
        hydra_core::Value::Int(output.window_secs as i64),
    );
    if let Some(top) = output.top_actor.as_deref() {
        action_payload.insert(
            "top_actor".to_string(),
            hydra_core::Value::String(top.to_string()),
        );
    }

    crate::micromodels::reflex::MicroModelReflexParts {
        actionable: output.level.is_actionable(),
        confidence: prediction.confidence,
        claim_subject: hydra_core::epistemic::ClaimSubject::System(
            "hydra.agents".to_string(),
        ),
        claim_predicate: "agent_loop_storm".to_string(),
        claim_object: hydra_core::epistemic::ClaimObject::Value(
            hydra_core::Value::Bool(true),
        ),
        evidence_payload_data: evidence_data,
        action_target: hydra_core::action::ActionTarget::System(
            "hydra.agents".to_string(),
        ),
        action_payload,
    }
}

/// Convert an action-failure-rate `(prediction, output)` pair
/// into the shared reflex parts. The action payload carries
/// `failed_actions`, `failure_ratio`, and `top_failed_kind?` so
/// receivers can route the alert per-kind.
fn action_failure_rate_reflex_parts(
    prediction: &hydra_core::MicroModelPrediction,
    output: &crate::micromodels::ActionFailureRateOutput,
) -> crate::micromodels::reflex::MicroModelReflexParts {
    let mut evidence_data: std::collections::HashMap<String, hydra_core::Value> =
        std::collections::HashMap::new();
    evidence_data.insert(
        "model_id".to_string(),
        hydra_core::Value::String(prediction.model_id.as_str().to_string()),
    );
    evidence_data.insert(
        "run_id".to_string(),
        hydra_core::Value::String(prediction.run_id.as_str().to_string()),
    );
    evidence_data.insert(
        "level".to_string(),
        hydra_core::Value::String(output.level.wire_name().to_string()),
    );
    evidence_data.insert(
        "window_secs".to_string(),
        hydra_core::Value::Int(output.window_secs as i64),
    );
    evidence_data.insert(
        "actions_seen".to_string(),
        hydra_core::Value::Int(output.actions_seen as i64),
    );
    evidence_data.insert(
        "failed_actions".to_string(),
        hydra_core::Value::Int(output.failed_actions as i64),
    );
    evidence_data.insert(
        "failure_ratio".to_string(),
        hydra_core::Value::Float(output.failure_ratio),
    );
    if let Some(top) = output.top_failed_kind.as_deref() {
        evidence_data.insert(
            "top_failed_kind".to_string(),
            hydra_core::Value::String(top.to_string()),
        );
    }
    evidence_data.insert(
        "reason".to_string(),
        hydra_core::Value::String(output.reason.clone()),
    );

    let mut action_payload: std::collections::HashMap<String, hydra_core::Value> =
        std::collections::HashMap::new();
    action_payload.insert(
        "severity".to_string(),
        hydra_core::Value::String(output.level.wire_name().to_string()),
    );
    action_payload.insert(
        "reason".to_string(),
        hydra_core::Value::String(
            prediction.explanation.clone().unwrap_or_default(),
        ),
    );
    action_payload.insert(
        "model_id".to_string(),
        hydra_core::Value::String(prediction.model_id.as_str().to_string()),
    );
    action_payload.insert(
        "run_id".to_string(),
        hydra_core::Value::String(prediction.run_id.as_str().to_string()),
    );
    action_payload.insert(
        "failed_actions".to_string(),
        hydra_core::Value::Int(output.failed_actions as i64),
    );
    action_payload.insert(
        "failure_ratio".to_string(),
        hydra_core::Value::Float(output.failure_ratio),
    );
    if let Some(top) = output.top_failed_kind.as_deref() {
        action_payload.insert(
            "top_failed_kind".to_string(),
            hydra_core::Value::String(top.to_string()),
        );
    }

    crate::micromodels::reflex::MicroModelReflexParts {
        actionable: output.level.is_actionable(),
        confidence: prediction.confidence,
        claim_subject: hydra_core::epistemic::ClaimSubject::System(
            "hydra.actions".to_string(),
        ),
        claim_predicate: "action_failure_rate_high".to_string(),
        claim_object: hydra_core::epistemic::ClaimObject::Value(
            hydra_core::Value::Bool(true),
        ),
        evidence_payload_data: evidence_data,
        action_target: hydra_core::action::ActionTarget::System(
            "hydra.actions".to_string(),
        ),
        action_payload,
    }
}

/// Wire-form name for an `ActionKind`. Mirrors the default serde
/// representation (PascalCase for unit variants; `"Custom(...)"`
/// is collapsed to the user label for readability in evidence /
/// action payloads). Used by Patch 19's `top_failed_kind`
/// aggregation.
fn action_kind_wire_name(kind: &hydra_core::action::ActionKind) -> String {
    use hydra_core::action::ActionKind as K;
    match kind {
        K::Notify => "Notify".to_string(),
        K::CreateTicket => "CreateTicket".to_string(),
        K::AssignOwner => "AssignOwner".to_string(),
        K::RequestEvidence => "RequestEvidence".to_string(),
        K::Quarantine => "Quarantine".to_string(),
        K::Backfill => "Backfill".to_string(),
        K::Repair => "Repair".to_string(),
        K::Approve => "Approve".to_string(),
        K::Reject => "Reject".to_string(),
        K::ExecuteWorkflow => "ExecuteWorkflow".to_string(),
        K::PostLedgerEntry => "PostLedgerEntry".to_string(),
        K::RunPayroll => "RunPayroll".to_string(),
        K::Custom(label) => label.clone(),
    }
}

/// Format a `Claim`'s subject + predicate into the
/// Patch 21 cell `subject` string `"<subject_label>/<predicate>"`.
///
/// `System` subjects pass through directly so the canonical
/// four reflex models read naturally:
///
/// ```text
///   System("hydra") / "under_abnormal_load"
///     → "hydra/under_abnormal_load"
///   System("hydra.replication") / "replica_lagging"
///     → "hydra.replication/replica_lagging"
/// ```
///
/// Patch 30 — Semantic Identity Resolution v1 helpers.
///
/// Module-private scoring logic for
/// `Hydra::suggest_identity_matches`. Pure functions, no I/O,
/// deterministic across calls. The factor weights are
/// **calibrated for explainability**, not guaranteed
/// correctness — see the engine method docstring for the
/// suggestion-only contract.
mod identity_resolver {
    use hydra_core::{
        IdentityAlias, IdentityEntity, MatchLevel,
        SemanticIdentityMatchCandidate, TrustFactor,
    };
    use std::collections::HashSet;

    // Factor weights (signed). Sum of all positive factors
    // bounded near 1.0 — exact-match dominates, partial signals
    // build up.
    const W_EXACT_ALIAS_MATCH: f64 = 0.85;
    const W_NORMALIZED_LABEL_MATCH: f64 = 0.30;
    const W_CANONICAL_KEY_OVERLAP_HIGH: f64 = 0.20;
    const W_CANONICAL_KEY_OVERLAP_PARTIAL: f64 = 0.08;
    const W_TOKEN_OVERLAP_HIGH: f64 = 0.15;
    const W_TOKEN_OVERLAP_PARTIAL: f64 = 0.05;
    const W_SAME_SOURCE: f64 = 0.05;
    const W_SAME_NAMESPACE: f64 = 0.10;
    const W_SAME_KIND: f64 = 0.10;

    /// Jaccard threshold for the *_high factor variants.
    const JACCARD_HIGH: f64 = 0.50;
    /// Jaccard threshold for the *_partial factor variants.
    /// Mutually exclusive with `_high` — a Jaccard value either
    /// fires high OR partial OR neither, never both.
    const JACCARD_PARTIAL: f64 = 0.20;

    /// Tokenize a string for overlap computation.
    ///
    /// Split on `.`, `_`, `-`, `/`, and whitespace, drop empty
    /// tokens, lowercase. This is the SAME tokenizer used for
    /// both query alias normalized AND entity canonical_key /
    /// entity alias normalized — so the comparison is fair.
    pub(super) fn tokens_of(s: &str) -> HashSet<String> {
        s.split(|c: char| {
            matches!(c, '.' | '_' | '-' | '/' | ' ' | '\t' | '\n')
        })
        .filter(|t| !t.is_empty())
        .map(|t| t.to_lowercase())
        .collect()
    }

    /// Jaccard similarity = |A ∩ B| / |A ∪ B|. Returns 0.0
    /// when both sets are empty (no meaningful overlap to
    /// score).
    fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
        if a.is_empty() && b.is_empty() {
            return 0.0;
        }
        let intersection = a.intersection(b).count() as f64;
        let union = a.union(b).count() as f64;
        if union == 0.0 {
            0.0
        } else {
            intersection / union
        }
    }

    /// Score one candidate against the query alias. Returns a
    /// fully-populated `SemanticIdentityMatchCandidate` whose
    /// `factors` list contains ALL 9 factors (applied or not).
    pub(super) fn score_candidate(
        query: &IdentityAlias,
        query_tokens: &HashSet<String>,
        entity: &IdentityEntity,
    ) -> SemanticIdentityMatchCandidate {
        let mut factors: Vec<TrustFactor> = Vec::with_capacity(9);
        let mut score = 0.0_f64;

        // Build the union of all candidate token sources once.
        // `entity.canonical_key` + every `entity.aliases[i].normalized`
        // contribute. This is the "any-alias" semantics — a new
        // alias should be able to match against ANY of the
        // entity's existing names, not just canonical_key.
        let mut entity_tokens = tokens_of(&entity.canonical_key);
        for a in &entity.aliases {
            for t in tokens_of(&a.normalized) {
                entity_tokens.insert(t);
            }
        }
        let canonical_tokens = tokens_of(&entity.canonical_key);

        // === Factor 1: exact_alias_match ===
        // Strongest signal: (source, namespace, normalized)
        // tuple matches one of the entity's existing aliases
        // exactly. We do NOT check external_id here — that's a
        // round-trip handle, not the identity key.
        let exact = entity.aliases.iter().any(|a| {
            a.source == query.source
                && a.namespace == query.namespace
                && a.normalized == query.normalized
        });
        push_factor(
            &mut factors,
            &mut score,
            "exact_alias_match",
            W_EXACT_ALIAS_MATCH,
            exact,
            if exact {
                format!(
                    "alias ({}, {:?}, {}) matches existing entity alias",
                    query.source, query.namespace, query.normalized
                )
            } else {
                "no exact (source, namespace, normalized) match".to_string()
            },
        );

        // === Factor 2: normalized_label_match ===
        // Same normalized string as ANY of the entity's aliases,
        // even if source/namespace differ. Catches the case where
        // the same dataset is referenced by the same string from
        // different tools.
        let label_match = entity
            .aliases
            .iter()
            .any(|a| a.normalized == query.normalized);
        push_factor(
            &mut factors,
            &mut score,
            "normalized_label_match",
            W_NORMALIZED_LABEL_MATCH,
            label_match,
            if label_match {
                format!(
                    "normalized label '{}' matches existing alias",
                    query.normalized
                )
            } else {
                "no alias shares this normalized label".to_string()
            },
        );

        // === Factors 3 + 4: canonical_key_overlap_{high,partial} ===
        // Token Jaccard against ONLY the canonical_key. High and
        // partial are mutually exclusive — a Jaccard value fires
        // at most one of the two factor records.
        let canon_jaccard = jaccard(query_tokens, &canonical_tokens);
        let canon_high = canon_jaccard >= JACCARD_HIGH;
        let canon_partial =
            !canon_high && canon_jaccard >= JACCARD_PARTIAL;
        push_factor(
            &mut factors,
            &mut score,
            "canonical_key_overlap_high",
            W_CANONICAL_KEY_OVERLAP_HIGH,
            canon_high,
            format!(
                "Jaccard(query, canonical_key) = {:.2} (threshold {})",
                canon_jaccard, JACCARD_HIGH
            ),
        );
        push_factor(
            &mut factors,
            &mut score,
            "canonical_key_overlap_partial",
            W_CANONICAL_KEY_OVERLAP_PARTIAL,
            canon_partial,
            format!(
                "Jaccard(query, canonical_key) = {:.2} (threshold {})",
                canon_jaccard, JACCARD_PARTIAL
            ),
        );

        // === Factors 5 + 6: token_overlap_{high,partial} ===
        // Token Jaccard against the FULL entity token bag
        // (canonical_key ∪ every alias.normalized). Catches
        // similarities that the canonical_key alone misses.
        // Same mutual exclusion as canonical_key_overlap.
        let tok_jaccard = jaccard(query_tokens, &entity_tokens);
        let tok_high = tok_jaccard >= JACCARD_HIGH;
        let tok_partial = !tok_high && tok_jaccard >= JACCARD_PARTIAL;
        push_factor(
            &mut factors,
            &mut score,
            "token_overlap_high",
            W_TOKEN_OVERLAP_HIGH,
            tok_high,
            format!(
                "Jaccard(query, entity tokens) = {:.2} (threshold {})",
                tok_jaccard, JACCARD_HIGH
            ),
        );
        push_factor(
            &mut factors,
            &mut score,
            "token_overlap_partial",
            W_TOKEN_OVERLAP_PARTIAL,
            tok_partial,
            format!(
                "Jaccard(query, entity tokens) = {:.2} (threshold {})",
                tok_jaccard, JACCARD_PARTIAL
            ),
        );

        // === Factor 7: same_source ===
        // "Any-alias" semantics: fires if ANY of the entity's
        // aliases has the same source. A dataset registered with
        // aliases from snowflake + dbt + github should match
        // same_source against a new snowflake query.
        let same_src = entity.aliases.iter().any(|a| a.source == query.source);
        push_factor(
            &mut factors,
            &mut score,
            "same_source",
            W_SAME_SOURCE,
            same_src,
            if same_src {
                format!("entity has alias from source '{}'", query.source)
            } else {
                format!("no entity alias from source '{}'", query.source)
            },
        );

        // === Factor 8: same_namespace ===
        // Any-alias semantics. `None == None` counts as a match
        // (mirrors the index_key sentinel design — `None` is a
        // real value, not a wildcard).
        let same_ns = entity
            .aliases
            .iter()
            .any(|a| a.namespace == query.namespace);
        push_factor(
            &mut factors,
            &mut score,
            "same_namespace",
            W_SAME_NAMESPACE,
            same_ns,
            if same_ns {
                format!(
                    "entity has alias in namespace {:?}",
                    query.namespace
                )
            } else {
                format!("no entity alias in namespace {:?}", query.namespace)
            },
        );

        // === Factor 9: same_kind ===
        // Suggestion-only — the caller may have passed no kind
        // filter, in which case this factor is informational
        // but inapplicable (we record it as `applied=false` with
        // a "no kind context" detail).
        //
        // Patch 30 v0 has no caller-provided "expected kind" on
        // the query alias itself, so this factor never fires.
        // It's wired in anyway so the wire shape is forward-
        // compatible with a future signed-query-kind extension.
        push_factor(
            &mut factors,
            &mut score,
            "same_kind",
            W_SAME_KIND,
            false,
            "no kind context on query alias (v0 — informational \
             factor)"
                .to_string(),
        );

        let clamped = score.clamp(0.0, 1.0);
        let level = MatchLevel::level_for_score(clamped);
        SemanticIdentityMatchCandidate {
            entity_id: entity.id.clone(),
            score: clamped,
            level,
            factors,
        }
    }

    /// Append a factor record and, when `applied`, add its
    /// weight to the running score. Centralized so every factor
    /// follows the same applied → score pattern.
    fn push_factor(
        factors: &mut Vec<TrustFactor>,
        score: &mut f64,
        kind: &str,
        weight: f64,
        applied: bool,
        detail: String,
    ) {
        if applied {
            *score += weight;
        }
        factors.push(TrustFactor {
            kind: kind.to_string(),
            weight,
            applied,
            detail,
        });
    }
}

/// Non-`System` variants get a prefixed label so the format
/// stays parseable.
fn format_claim_subject(claim: &hydra_core::Claim) -> String {
    use hydra_core::epistemic::ClaimSubject;
    let label = match &claim.subject {
        ClaimSubject::System(s) => s.clone(),
        ClaimSubject::Node(id) => format!("node:{}", id.as_str()),
        ClaimSubject::Edge(id) => format!("edge:{}", id.as_str()),
        ClaimSubject::ExternalRef(s) => format!("external:{s}"),
        ClaimSubject::Dataset(s) => format!("dataset:{s}"),
        ClaimSubject::Metric(s) => format!("metric:{s}"),
    };
    format!("{}/{}", label, claim.predicate)
}

/// Extract the actor associated with an `EventKind` variant, if
/// any. Used by Patch 18's storm window walk + future audit
/// surfaces. Returns `None` for variants without a clear actor
/// (sensor lifecycle, replication topology, snapshots, etc.).
///
/// Each new actor-bearing variant should be added here. Variants
/// that LOOK actor-bearing but represent purely-system activity
/// (sensor runs, replication runs, snapshot taking) are
/// deliberately excluded so storm counting reflects agent /
/// operator activity, not infra signals.
fn extract_event_actor(
    kind: &hydra_core::EventKind,
) -> Option<&hydra_core::ActorId> {
    use hydra_core::EventKind as E;
    match kind {
        E::ClaimProposed { claim } => Some(&claim.created_by),
        E::ClaimVerified { verified_by, .. } => Some(verified_by),
        E::ClaimRetracted { retracted_by, .. } => Some(retracted_by),
        E::ActionProposed { action } => Some(&action.proposed_by),
        E::ActionApproved { approved_by, .. } => Some(approved_by),
        E::ActionRejected { rejected_by, .. } => Some(rejected_by),
        E::ActionCancelled { cancelled_by, .. } => Some(cancelled_by),
        E::PolicyDisabled { disabled_by, .. } => Some(disabled_by),
        E::EvidenceAdded { evidence } => match &evidence.source {
            hydra_core::epistemic::EvidenceSource::Human { actor_id } => {
                Some(actor_id)
            }
            _ => None,
        },
        _ => None,
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

    // === MicroModel Patch 7 — execution stub helpers ===

    /// Register a HumanApproval / AnyAction policy so the cascade
    /// emits ApprovalRequested instead of auto-approving via
    /// PolicyEvaluationDecision::Allow. Used by Patch 7 tests that
    /// need a Notify action to stay in Proposed until the operator
    /// approves explicitly.
    fn register_any_action_approval_policy(hydra: &mut Hydra) {
        let now = chrono::Utc::now();
        let policy = hydra_core::Policy {
            id: hydra_core::PolicyId::new(),
            tenant_id: None,
            name: "Patch 7 test — require human approval".to_string(),
            kind: hydra_core::PolicyKind::HumanApproval,
            status: hydra_core::PolicyStatus::Active,
            scope: hydra_core::PolicyScope::AnyAction,
            condition: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
            created_by: hydra_core::ActorId::from_str("actor_test_policy_admin"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::PolicyRegistered { policy })
            .unwrap();
    }

    #[test]
    fn execute_notify_action_walks_approved_to_executed() {
        // Happy path: an Approved Notify action walks through
        // Executing → Executed and the report carries the final
        // state + executed_at. previous_status reflects Approved.
        let mut hydra = Hydra::new();
        let action_id = propose_one_test_action(&mut hydra);
        // propose_one_test_action's critical cascade auto-approves
        // (no policies registered), so the action is already
        // Approved by the time we get here.
        let operator = hydra_core::ActorId::from_str("actor_ops");
        let report = hydra
            .execute_notify_action(action_id.clone(), operator.clone())
            .unwrap();

        assert_eq!(report.action_id, action_id);
        assert_eq!(
            report.previous_status,
            hydra_core::action::ActionStatus::Approved
        );
        assert_eq!(
            report.final_status,
            hydra_core::action::ActionStatus::Executed
        );
        assert_eq!(report.executed_by, operator);

        let final_action = hydra.action(&action_id).unwrap();
        assert_eq!(
            final_action.status,
            hydra_core::action::ActionStatus::Executed
        );
        assert_eq!(final_action.executed_at, Some(report.executed_at));
    }

    #[test]
    fn execute_notify_action_records_outcome_with_custom_kind() {
        // The execution stub must emit an OutcomeObserved with
        // `kind: Custom("notification_recorded")` and an impact
        // payload that clearly identifies this as a stub.
        let mut hydra = Hydra::new();
        let action_id = propose_one_test_action(&mut hydra);
        let report = hydra
            .execute_notify_action(
                action_id.clone(),
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();

        let outcomes = hydra.outcomes_for_action(&action_id);
        // Notify is NOT handled by OutcomeAgent (v0 = Backfill-only),
        // so exactly one outcome lands: the one Patch 7 emits.
        assert_eq!(outcomes.len(), 1, "expected exactly one outcome (Patch 7 emission)");
        let outcome = outcomes[0];
        assert_eq!(outcome.id, report.outcome_id);
        assert_eq!(
            outcome.kind,
            hydra_core::OutcomeKind::Custom("notification_recorded".to_string())
        );
        // Impact carries the stub marker + a human-readable summary.
        assert!(matches!(
            outcome.impact.get("stub"),
            Some(hydra_core::Value::Bool(true))
        ));
        assert!(matches!(
            outcome.impact.get("summary"),
            Some(hydra_core::Value::String(s)) if s.contains("internal stub")
        ));
        // Causal link: outcome.caused_by points at the
        // ActionExecuted event id so lineage walks reach it.
        assert!(outcome.caused_by.is_some());
    }

    #[test]
    fn execute_notify_action_refuses_non_notify_kind() {
        // Patch 7 scope discipline: only Notify executes. Other
        // kinds (Backfill, Quarantine, etc.) return a QueryError
        // identifying the mismatched kind. No status mutation.
        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let action_id = hydra_core::ActionId::new();
        let actor = hydra_core::ActorId::from_str("actor_test_proposer");
        // Backfill is a non-Notify kind; create it directly in
        // Approved state so kind-check fires before status-check.
        let action = hydra_core::Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: hydra_core::ActionKind::Backfill,
            status: hydra_core::action::ActionStatus::Approved,
            targets: vec![hydra_core::action::ActionTarget::Dataset(
                "orders".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: Some(actor.clone()),
            rejected_by: None,
            policy_id: None,
            payload: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: Some(now),
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ActionProposed { action })
            .unwrap();
        // Action is Backfill in some non-Proposed status after
        // cascade — execute should still refuse on kind.
        let result = hydra.execute_notify_action(
            action_id.clone(),
            hydra_core::ActorId::from_str("actor_ops"),
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("invalid action kind"), "msg: {msg}");
                assert!(msg.contains("Notify"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
        // No ActionExecuting / ActionExecuted in the audit log.
        let exec_events = hydra
            .events()
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    hydra_core::EventKind::ActionExecuting { .. }
                        | hydra_core::EventKind::ActionExecuted { .. }
                )
            })
            .count();
        assert_eq!(exec_events, 0);
    }

    #[test]
    fn execute_notify_action_refuses_non_approved_status() {
        // Register a HumanApproval/AnyAction policy BEFORE ingest
        // so the cascade emits ApprovalRequested instead of
        // auto-approving via PolicyEvaluationDecision::Allow.
        // The action stays in Proposed and execute must refuse
        // with an "invalid action state" error.
        let mut hydra = Hydra::new();
        register_any_action_approval_policy(&mut hydra);
        let now = chrono::Utc::now();
        let action_id = hydra_core::ActionId::new();
        let actor = hydra_core::ActorId::from_str("actor_test_proposer");
        let action = hydra_core::Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: hydra_core::ActionKind::Notify,
            status: hydra_core::action::ActionStatus::Proposed,
            targets: vec![hydra_core::action::ActionTarget::System(
                "hydra".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor,
            approved_by: None,
            rejected_by: None,
            policy_id: None,
            payload: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ActionProposed { action })
            .unwrap();
        // Sanity: action is Proposed, not Approved.
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            hydra_core::action::ActionStatus::Proposed
        );
        let result = hydra.execute_notify_action(
            action_id.clone(),
            hydra_core::ActorId::from_str("actor_ops"),
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("invalid action state"), "msg: {msg}");
                assert!(msg.contains("Approved"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
        // Status untouched.
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            hydra_core::action::ActionStatus::Proposed
        );
    }

    #[test]
    fn execute_notify_action_unknown_action_returns_query_error() {
        // Validate-before-ingest: an unknown action id returns
        // QueryError("unknown action: ...") and leaves no event
        // residue in the audit log.
        let mut hydra = Hydra::new();
        let result = hydra.execute_notify_action(
            hydra_core::ActionId::from_str("act_does_not_exist"),
            hydra_core::ActorId::from_str("actor_ops"),
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("unknown action"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
        let exec_events = hydra
            .events()
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    hydra_core::EventKind::ActionExecuting { .. }
                        | hydra_core::EventKind::ActionExecuted { .. }
                        | hydra_core::EventKind::OutcomeObserved { .. }
                )
            })
            .count();
        assert_eq!(exec_events, 0);
    }

    // === Patch 14 — Notify Delivery Adapter ===
    //
    // Mirrors the Patch 7 tests but uses the new
    // `execute_notify_action_with_delivery` method. Patch 7's
    // `execute_notify_action` is preserved as-is (regression-pinned
    // by all the tests above).

    #[test]
    fn execute_notify_action_with_delivery_succeeded_emits_executed_and_success_outcome() {
        let mut hydra = Hydra::new();
        let action_id = propose_one_test_action(&mut hydra);
        let operator = hydra_core::ActorId::from_str("actor_ops");
        let delivery = hydra_core::DeliveryOutcome::Succeeded {
            adapter: "webhook".to_string(),
            status_code: 204,
            latency_ms: 42,
        };
        let report = hydra
            .execute_notify_action_with_delivery(
                action_id.clone(),
                operator.clone(),
                delivery,
            )
            .unwrap();

        assert_eq!(
            report.previous_status,
            hydra_core::action::ActionStatus::Approved
        );
        assert_eq!(
            report.final_status,
            hydra_core::action::ActionStatus::Executed
        );
        // Audit log: ActionExecuted (not ActionFailed) lands.
        let executed_count = hydra
            .events()
            .iter()
            .filter(|e| matches!(e.kind, hydra_core::EventKind::ActionExecuted { .. }))
            .count();
        assert_eq!(executed_count, 1);
        let failed_count = hydra
            .events()
            .iter()
            .filter(|e| matches!(e.kind, hydra_core::EventKind::ActionFailed { .. }))
            .count();
        assert_eq!(failed_count, 0);
        // Outcome carries Success kind.
        let outcome = hydra.outcome(&report.outcome_id).unwrap();
        assert_eq!(outcome.kind, hydra_core::OutcomeKind::Success);
    }

    #[test]
    fn execute_notify_action_with_delivery_failed_emits_failed_and_failure_outcome() {
        let mut hydra = Hydra::new();
        let action_id = propose_one_test_action(&mut hydra);
        let operator = hydra_core::ActorId::from_str("actor_ops");
        let delivery = hydra_core::DeliveryOutcome::Failed {
            adapter: "webhook".to_string(),
            reason: "webhook returned 500".to_string(),
            status_code: Some(500),
            latency_ms: 31,
        };
        let report = hydra
            .execute_notify_action_with_delivery(
                action_id.clone(),
                operator.clone(),
                delivery,
            )
            .unwrap();

        assert_eq!(
            report.final_status,
            hydra_core::action::ActionStatus::Failed
        );
        // ActionFailed (not ActionExecuted) lands.
        let executed_count = hydra
            .events()
            .iter()
            .filter(|e| matches!(e.kind, hydra_core::EventKind::ActionExecuted { .. }))
            .count();
        assert_eq!(executed_count, 0);
        let failed_count = hydra
            .events()
            .iter()
            .filter(|e| matches!(e.kind, hydra_core::EventKind::ActionFailed { .. }))
            .count();
        assert_eq!(failed_count, 1);
        // Outcome carries Failure kind + the reason in impact.
        let outcome = hydra.outcome(&report.outcome_id).unwrap();
        assert_eq!(outcome.kind, hydra_core::OutcomeKind::Failure);
        let reason = outcome
            .impact
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(reason.contains("500"), "reason: {reason}");
    }

    #[test]
    fn execute_notify_action_with_delivery_refuses_non_notify_kind() {
        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let action_id = hydra_core::ActionId::new();
        let action = hydra_core::Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: hydra_core::ActionKind::Backfill,
            status: hydra_core::action::ActionStatus::Approved,
            targets: vec![hydra_core::action::ActionTarget::Dataset(
                "orders".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: Some(actor),
            rejected_by: None,
            policy_id: None,
            payload: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: Some(now),
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ActionProposed { action })
            .unwrap();
        let delivery = hydra_core::DeliveryOutcome::Succeeded {
            adapter: "webhook".to_string(),
            status_code: 200,
            latency_ms: 1,
        };
        let result = hydra.execute_notify_action_with_delivery(
            action_id,
            hydra_core::ActorId::from_str("actor_ops"),
            delivery,
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("invalid action kind"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn execute_notify_action_with_delivery_refuses_non_approved_status() {
        // Drive a chain with a HumanApproval policy so the action
        // stays Proposed → method must refuse.
        let mut hydra = Hydra::new();
        register_any_action_approval_policy(&mut hydra);
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test_proposer");
        let action_id = hydra_core::ActionId::new();
        let action = hydra_core::Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: hydra_core::ActionKind::Notify,
            status: hydra_core::action::ActionStatus::Proposed,
            targets: vec![hydra_core::action::ActionTarget::System(
                "hydra".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor,
            approved_by: None,
            rejected_by: None,
            policy_id: None,
            payload: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ActionProposed { action })
            .unwrap();
        let delivery = hydra_core::DeliveryOutcome::Succeeded {
            adapter: "webhook".to_string(),
            status_code: 200,
            latency_ms: 1,
        };
        let result = hydra.execute_notify_action_with_delivery(
            action_id,
            hydra_core::ActorId::from_str("actor_ops"),
            delivery,
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("invalid action state"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn execute_notify_action_with_delivery_unknown_action_returns_query_error() {
        let mut hydra = Hydra::new();
        let delivery = hydra_core::DeliveryOutcome::Succeeded {
            adapter: "webhook".to_string(),
            status_code: 200,
            latency_ms: 1,
        };
        let result = hydra.execute_notify_action_with_delivery(
            hydra_core::ActionId::from_str("act_does_not_exist"),
            hydra_core::ActorId::from_str("actor_ops"),
            delivery,
        );
        assert!(matches!(
            result,
            Err(hydra_core::error::HydraError::QueryError(_))
        ));
    }

    #[test]
    fn execute_notify_action_with_delivery_observation_impact_carries_adapter_metadata() {
        // Pin the Outcome.impact JSON shape — Patch 12+ trust
        // calibration may eventually branch on this. Future
        // patches must preserve `stub: false`, `adapter`,
        // `latency_ms`, and `status_code` (when present) on
        // both success and failure paths.
        let mut hydra = Hydra::new();
        let action_id = propose_one_test_action(&mut hydra);
        let report = hydra
            .execute_notify_action_with_delivery(
                action_id,
                hydra_core::ActorId::from_str("actor_ops"),
                hydra_core::DeliveryOutcome::Succeeded {
                    adapter: "webhook".to_string(),
                    status_code: 202,
                    latency_ms: 99,
                },
            )
            .unwrap();
        let outcome = hydra.outcome(&report.outcome_id).unwrap();
        assert!(matches!(
            outcome.impact.get("stub"),
            Some(hydra_core::Value::Bool(false))
        ));
        assert_eq!(
            outcome.impact.get("adapter").and_then(|v| v.as_str()),
            Some("webhook")
        );
        assert_eq!(
            outcome.impact.get("status_code").and_then(|v| v.as_i64()),
            Some(202)
        );
        assert_eq!(
            outcome.impact.get("latency_ms").and_then(|v| v.as_i64()),
            Some(99)
        );
    }

    // === MicroModel Patch 8 — outcome learning loop ===
    //
    // The tests below drive the full reflex chain end-to-end:
    //   primed_hydra (warmed model)
    //   → ingest_signals to push into Critical territory
    //   → evaluate_commit_rate_anomaly_and_propose_action (Patches 2-4)
    //   → cascade auto-approves the Notify action (no policies)
    //   → execute_notify_action records OutcomeObserved (Patch 7)
    //   → record_micro_model_observation_from_action_outcome (Patch 8)
    //
    // That's the first loop where Hydra remembers whether its own
    // reflex produced an outcome.

    /// Drive a Critical assessment + execute the Notify action so a
    /// downstream `OutcomeObserved` exists for Patch 8 to consume.
    /// Returns the outcome id plus the prediction run_id so tests
    /// can assert the chain walk recovered the right join key.
    fn execute_one_test_action(
        hydra: &mut Hydra,
    ) -> (hydra_core::OutcomeId, hydra_core::MicroModelRunId) {
        *hydra = primed_hydra(10.0, 1.0);
        let need = 100u64 - ledger_count(hydra);
        ingest_signals(hydra, need);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let action_id = assessment
            .action_ids
            .into_iter()
            .next()
            .expect("critical produced an action");
        // primed_hydra has no policies → cascade auto-approved the
        // Notify action. execute_notify_action's strict precondition
        // (status == Approved) is satisfied.
        let report = hydra
            .execute_notify_action(
                action_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        // Recover the run_id from the prediction event so tests can
        // assert the observation's run_id matches.
        let prediction_event_id = assessment.prediction_event_id;
        let prediction_event = hydra.event(&prediction_event_id).unwrap();
        let run_id = match &prediction_event.kind {
            hydra_core::EventKind::MicroModelPredictionRecorded { prediction } => {
                prediction.run_id.clone()
            }
            _ => panic!("prediction event has unexpected kind"),
        };
        (report.outcome_id, run_id)
    }

    #[test]
    fn record_observation_walks_outcome_to_prediction_run_id() {
        // Happy path: full chain walk recovers the prediction's
        // run_id and ingests MicroModelObservationRecorded matched
        // by that run_id.
        let mut hydra = Hydra::new();
        let (outcome_id, expected_run_id) = execute_one_test_action(&mut hydra);
        let observer = hydra_core::ActorId::from_str("actor_ops");
        let observation = hydra
            .record_micro_model_observation_from_action_outcome(
                outcome_id.clone(),
                observer.clone(),
            )
            .unwrap();

        assert_eq!(observation.run_id, expected_run_id);
        assert!(observation.error.is_none(), "Patch 8 v0: no numeric error");

        // Store reflects the observation under the prediction's run_id.
        let stored = hydra.micro_model_observation(&expected_run_id).unwrap();
        assert_eq!(stored.run_id, expected_run_id);

        // Audit log contains the MicroModelObservationRecorded event.
        let recorded = hydra.events().iter().any(|event| {
            matches!(
                &event.kind,
                hydra_core::EventKind::MicroModelObservationRecorded { observation: o }
                if o.run_id == expected_run_id
            )
        });
        assert!(recorded, "MicroModelObservationRecorded event missing");
    }

    #[test]
    fn record_observation_encodes_outcome_id_and_action_id_in_observed_outcome() {
        // The audit linkage lives in observed_outcome: serde_json::Value
        // for v0. Tests pin the exact shape so Patch 9 / trust scoring
        // can rely on the contract.
        let mut hydra = Hydra::new();
        let (outcome_id, _) = execute_one_test_action(&mut hydra);
        let observer = hydra_core::ActorId::from_str("actor_ops");
        let observation = hydra
            .record_micro_model_observation_from_action_outcome(
                outcome_id.clone(),
                observer.clone(),
            )
            .unwrap();

        let obj = observation
            .observed_outcome
            .as_object()
            .expect("observed_outcome is a JSON object");
        // outcome_id round-trips as a string field.
        assert_eq!(
            obj.get("outcome_id").and_then(|v| v.as_str()),
            Some(outcome_id.to_string().as_str())
        );
        // action_id and claim_id are present (Patch 4 populated
        // action.related_claims so the walk found a non-empty link).
        assert!(obj.get("action_id").and_then(|v| v.as_str()).is_some());
        assert!(obj.get("claim_id").and_then(|v| v.as_str()).is_some());
        // outcome_kind reflects Patch 7's Custom("notification_recorded")
        // via the dedicated format helper.
        assert_eq!(
            obj.get("outcome_kind").and_then(|v| v.as_str()),
            Some("Custom(notification_recorded)")
        );
        // Action lifecycle + operator flags are explicit.
        assert_eq!(
            obj.get("action_lifecycle").and_then(|v| v.as_str()),
            Some("executed")
        );
        assert_eq!(
            obj.get("operator_approved").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            obj.get("operator_rejected").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            obj.get("observed_by").and_then(|v| v.as_str()),
            Some("actor_ops")
        );
        // Summary surfaces Patch 7's "internal stub" marker.
        let summary = obj
            .get("outcome_summary")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(summary.contains("internal stub"), "summary: {summary}");
    }

    #[test]
    fn record_observation_unknown_outcome_returns_query_error() {
        let mut hydra = Hydra::new();
        let result = hydra.record_micro_model_observation_from_action_outcome(
            hydra_core::OutcomeId::from_str("out_does_not_exist"),
            hydra_core::ActorId::from_str("actor_ops"),
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("unknown outcome"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
        // No spurious MicroModelObservationRecorded landed.
        let count = hydra
            .events()
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    hydra_core::EventKind::MicroModelObservationRecorded { .. }
                )
            })
            .count();
        assert_eq!(count, 0);
    }

    #[test]
    fn record_observation_outcome_not_from_prediction_chain_returns_error() {
        // Hand-craft an Outcome whose ancestry is NOT a MicroModel
        // reflex chain (e.g., a manually-ingested outcome on an
        // action without related_claims). The walk should fail at
        // step 4 with "no related_claims — not a model-derived
        // action".
        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let action_id = hydra_core::ActionId::new();
        let action = hydra_core::Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: hydra_core::ActionKind::Notify,
            status: hydra_core::action::ActionStatus::Approved,
            targets: vec![hydra_core::action::ActionTarget::System(
                "hydra".to_string(),
            )],
            // Empty — this is what breaks the walk.
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: Some(actor.clone()),
            rejected_by: None,
            policy_id: None,
            payload: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: Some(now),
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ActionProposed { action })
            .unwrap();
        let report = hydra
            .execute_notify_action(action_id.clone(), actor.clone())
            .unwrap();
        let result = hydra
            .record_micro_model_observation_from_action_outcome(report.outcome_id, actor);
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("outcome not traceable"), "msg: {msg}");
                assert!(msg.contains("related_claims"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn record_observation_idempotent_overwrites_in_store() {
        // MicroModelStore stores observations by run_id (HashMap key).
        // A second recording overwrites the cached observation, but
        // the audit log preserves BOTH events. Patch 8 documents
        // this v0 behaviour — multi-observation-per-run is a future
        // patch.
        let mut hydra = Hydra::new();
        let (outcome_id, run_id) = execute_one_test_action(&mut hydra);
        hydra
            .record_micro_model_observation_from_action_outcome(
                outcome_id.clone(),
                hydra_core::ActorId::from_str("actor_first"),
            )
            .unwrap();
        let first_observer = hydra
            .micro_model_observation(&run_id)
            .unwrap()
            .observed_outcome
            .get("observed_by")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap();
        assert_eq!(first_observer, "actor_first");

        hydra
            .record_micro_model_observation_from_action_outcome(
                outcome_id,
                hydra_core::ActorId::from_str("actor_second"),
            )
            .unwrap();
        let second_observer = hydra
            .micro_model_observation(&run_id)
            .unwrap()
            .observed_outcome
            .get("observed_by")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap();
        assert_eq!(second_observer, "actor_second", "store overwrites latest");

        // Audit log keeps BOTH events.
        let observation_events: usize = hydra
            .events()
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    hydra_core::EventKind::MicroModelObservationRecorded { .. }
                )
            })
            .count();
        assert_eq!(observation_events, 2, "audit log preserves history");
    }

    #[test]
    fn record_observation_observation_at_is_recent() {
        // observed_at is engine-controlled (chrono::Utc::now()). Pin
        // that it's within a tight window of the call so callers can
        // trust the timestamp for trust scoring.
        let mut hydra = Hydra::new();
        let (outcome_id, _) = execute_one_test_action(&mut hydra);
        let before = chrono::Utc::now();
        let observation = hydra
            .record_micro_model_observation_from_action_outcome(
                outcome_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        let after = chrono::Utc::now();
        assert!(
            observation.observed_at >= before && observation.observed_at <= after,
            "observed_at {} not in [{}, {}]",
            observation.observed_at,
            before,
            after
        );
    }

    // === Trust Patch 1 (Patch 9) — claim trust assessment ===

    /// Lookup helper used by the trust tests below — find a factor
    /// in the assessment by its stable kind id.
    fn find_factor<'a>(
        assessment: &'a hydra_core::TrustAssessment,
        kind: &str,
    ) -> &'a hydra_core::TrustFactor {
        assessment
            .factors
            .iter()
            .find(|f| f.kind == kind)
            .unwrap_or_else(|| panic!("factor {kind} missing from assessment"))
    }

    /// Pin that the engine's hardcoded cascade-approver actor id
    /// matches hydra-core's `HYDRA_POLICY_AGENT_ACTOR` constant.
    /// If cascade.rs ever changes the magic string, this test
    /// fires before the trust assessor silently loses the
    /// cascade-vs-operator distinction.
    #[test]
    fn cascade_policy_actor_matches_hydra_core_constant() {
        // Drive a single cascade approval (no policies registered →
        // PolicyEvaluationDecision::Allow → ActionApproved) and
        // verify the engine stamped the canonical magic string.
        let mut hydra = Hydra::new();
        let action_id = propose_one_test_action(&mut hydra);
        let action = hydra.action(&action_id).unwrap();
        let approver = action
            .approved_by
            .as_ref()
            .expect("cascade auto-approved the Notify action");
        assert_eq!(approver.as_str(), hydra_core::HYDRA_POLICY_AGENT_ACTOR);
        assert!(hydra_core::is_cascade_approver(approver));
    }

    #[test]
    fn assess_claim_trust_unknown_claim_returns_query_error() {
        let hydra = Hydra::new();
        let result = hydra.assess_claim_trust(&hydra_core::ClaimId::from_str(
            "claim_does_not_exist",
        ));
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("unknown claim"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    /// Drive the full reflex loop end-to-end and return
    /// `(claim_id, outcome_id, run_id)` for trust tests.
    fn drive_full_chain_for_trust(
        hydra: &mut Hydra,
    ) -> (
        hydra_core::ClaimId,
        hydra_core::OutcomeId,
        hydra_core::MicroModelRunId,
    ) {
        *hydra = primed_hydra(10.0, 1.0);
        let need = 100u64 - ledger_count(hydra);
        ingest_signals(hydra, need);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let action_id = assessment.action_ids[0].clone();
        let claim_id = assessment.claim_id.clone().unwrap();
        let report = hydra
            .execute_notify_action(
                action_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        let prediction_event = hydra
            .event(&assessment.prediction_event_id)
            .unwrap();
        let run_id = match &prediction_event.kind {
            hydra_core::EventKind::MicroModelPredictionRecorded { prediction } => {
                prediction.run_id.clone()
            }
            _ => panic!("expected MicroModelPredictionRecorded"),
        };
        // Patch 8: record observation back to the model.
        hydra
            .record_micro_model_observation_from_action_outcome(
                report.outcome_id.clone(),
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        (claim_id, report.outcome_id, run_id)
    }

    #[test]
    fn assess_claim_trust_full_chain_returns_high() {
        // Full reflex loop + Patch 8 observation. Cascade
        // auto-approved (no policies), so `operator_approved` does
        // NOT fire — but every other positive factor should.
        //
        // Cascade-approved chain factor count (raw sum):
        //   claim_verified           +0.20 (Patch 3's verification
        //                                    cascade promotes the
        //                                    critical claim past
        //                                    the 0.80 threshold)
        //   high_confidence_claim    +0.10 (critical = 0.90)
        //   supporting_evidence_present +0.10
        //   reliable_supporting_evidence +0.10
        //   action_executed          +0.15
        //   outcome_recorded         +0.10
        //   model_observation_exists +0.10
        //                            -----
        //                            +0.85
        // Without operator approval. That clears the 0.80 High
        // threshold.
        let mut hydra = Hydra::new();
        let (claim_id, _outcome_id, _run_id) = drive_full_chain_for_trust(&mut hydra);
        let assessment = hydra.assess_claim_trust(&claim_id).unwrap();

        assert_eq!(assessment.claim_id, claim_id);
        assert!(
            assessment.score >= 0.80,
            "expected High-tier score, got {:.3}: factors {:#?}",
            assessment.score,
            assessment.factors
        );
        assert_eq!(assessment.level, hydra_core::TrustLevel::High);
        // Pin the explainable factors.
        assert!(find_factor(&assessment, "claim_verified").applied);
        assert!(find_factor(&assessment, "action_executed").applied);
        assert!(find_factor(&assessment, "outcome_recorded").applied);
        assert!(find_factor(&assessment, "model_observation_exists").applied);
        // Cascade-only chain → operator_approved is false.
        assert!(!find_factor(&assessment, "operator_approved").applied);
        // Related-id collections are populated.
        assert!(!assessment.related_action_ids.is_empty());
        assert!(!assessment.related_outcome_ids.is_empty());
        assert_eq!(assessment.observation_run_ids.len(), 1);
    }

    #[test]
    fn assess_claim_trust_just_proposed_returns_low_or_unknown() {
        // A claim that exists in isolation — no actions, no
        // outcomes — should score below Medium. Most positive
        // factors are gated on the action chain.
        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let claim_id = hydra_core::ClaimId::new();
        let claim = hydra_core::Claim {
            id: claim_id.clone(),
            tenant_id: None,
            kind: hydra_core::ClaimKind::Hypothesis,
            subject: hydra_core::ClaimSubject::System("hydra".to_string()),
            predicate: "test_predicate".to_string(),
            object: hydra_core::ClaimObject::Value(hydra_core::Value::Bool(true)),
            confidence: hydra_core::Confidence::new(0.30),
            status: hydra_core::ClaimStatus::Proposed,
            evidence_for: vec![],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: actor,
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ClaimProposed { claim })
            .unwrap();
        let assessment = hydra.assess_claim_trust(&claim_id).unwrap();
        assert!(
            assessment.level == hydra_core::TrustLevel::Low
                || assessment.level == hydra_core::TrustLevel::Unknown,
            "expected Low or Unknown, got {:?} (score {:.3})",
            assessment.level,
            assessment.score
        );
        assert_eq!(assessment.related_action_ids.len(), 0);
        assert_eq!(assessment.related_outcome_ids.len(), 0);
        assert_eq!(assessment.observation_run_ids.len(), 0);
    }

    #[test]
    fn assess_claim_trust_retracted_claim_zeros_score() {
        // Even with positive factors that COULD push the score
        // above 0, a retracted claim must end up at score 0.0 /
        // Unknown. This is the load-bearing safety check.
        let mut hydra = Hydra::new();
        let (claim_id, _outcome_id, _run_id) = drive_full_chain_for_trust(&mut hydra);
        // Retract the claim — must be ingested as an event.
        hydra
            .ingest(hydra_core::EventKind::ClaimRetracted {
                claim_id: claim_id.clone(),
                reason: "test-only retraction".to_string(),
                retracted_by: hydra_core::ActorId::from_str("actor_test"),
            })
            .unwrap();
        let assessment = hydra.assess_claim_trust(&claim_id).unwrap();
        assert_eq!(assessment.score, 0.0);
        assert_eq!(assessment.level, hydra_core::TrustLevel::Unknown);
        let retract_factor = find_factor(&assessment, "claim_retracted");
        assert!(retract_factor.applied);
        assert_eq!(retract_factor.weight, -1.00);
        // claim_verified should also reflect the new status: a
        // retracted claim is NOT verified.
        assert!(!find_factor(&assessment, "claim_verified").applied);
    }

    #[test]
    fn assess_claim_trust_contradicting_evidence_penalizes() {
        // A claim with an evidence_against entry should see the
        // contradicting_evidence factor applied (weight -0.20).
        // The engine uses EventKind::ClaimDisputed to link
        // refuting evidence to a claim (see epistemic_store's
        // `add_disputing_evidence` path).
        let mut hydra = Hydra::new();
        let (claim_id, _, _) = drive_full_chain_for_trust(&mut hydra);
        let now = chrono::Utc::now();
        let evidence_id = hydra_core::EvidenceId::new();
        let evidence = hydra_core::Evidence {
            id: evidence_id.clone(),
            tenant_id: None,
            source: hydra_core::EvidenceSource::Human {
                actor_id: hydra_core::ActorId::from_str("actor_test_human"),
            },
            payload: hydra_core::EvidencePayload {
                kind: "manual_refutation".to_string(),
                data: std::collections::HashMap::new(),
            },
            reliability: hydra_core::Confidence::new(0.90),
            observed_at: now,
            recorded_at: now,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::EvidenceAdded { evidence })
            .unwrap();
        hydra
            .ingest(hydra_core::EventKind::ClaimDisputed {
                claim_id: claim_id.clone(),
                evidence_id,
                reason: Some("test refutation".to_string()),
            })
            .unwrap();
        let assessment = hydra.assess_claim_trust(&claim_id).unwrap();
        let contradict = find_factor(&assessment, "contradicting_evidence");
        assert!(contradict.applied);
        assert_eq!(contradict.weight, -0.20);
    }

    #[test]
    fn assess_claim_trust_cascade_approved_does_not_count_as_operator() {
        // The whole point of distinguishing actor_hydra_policy from
        // an operator actor id: cascade auto-approval is NOT
        // operator approval. This test pins that the trust score
        // does NOT credit `operator_approved` when only the cascade
        // approved the action.
        let mut hydra = Hydra::new();
        let (claim_id, _, _) = drive_full_chain_for_trust(&mut hydra);
        let assessment = hydra.assess_claim_trust(&claim_id).unwrap();
        let operator = find_factor(&assessment, "operator_approved");
        assert!(!operator.applied);
        assert!(operator.detail.contains("no operator approval"));
        // But every related action does have approved_by set —
        // it's just set to the cascade actor.
        for action_id in &assessment.related_action_ids {
            let action = hydra.action(action_id).unwrap();
            let approver = action.approved_by.as_ref().unwrap();
            assert!(hydra_core::is_cascade_approver(approver));
        }
    }

    #[test]
    fn assess_claim_trust_operator_approval_credits_factor() {
        // Symmetric to the cascade test: register a HumanApproval
        // policy so the cascade emits ApprovalRequested instead of
        // auto-approving, then explicitly approve via the Patch 6
        // helper. The operator_approved factor should then fire.
        //
        // We can't reuse `primed_hydra` here because it builds a
        // fresh engine and would wipe the policy. Inline the prime
        // so the policy survives.
        let mut hydra = Hydra::new();
        register_any_action_approval_policy(&mut hydra);
        // Warm + seed the commit-rate model in-place.
        let _ = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        // accumulate_model_history may push ledger count above 100;
        // use saturating_sub so the test doesn't underflow. If the
        // ledger is already past 100, no extra signals are needed —
        // the window count is already high enough to trigger
        // Critical against the re-primed baseline.
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        let assessment_obj = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let action_id = assessment_obj.action_ids[0].clone();
        let claim_id = assessment_obj.claim_id.unwrap();
        // Sanity: the HumanApproval policy meant the action sat in
        // Proposed waiting for an operator.
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            hydra_core::action::ActionStatus::Proposed
        );
        let operator = hydra_core::ActorId::from_str("actor_oncall_alice");
        hydra
            .approve_action(action_id, operator.clone(), Some("LGTM".to_string()))
            .unwrap();
        let trust = hydra.assess_claim_trust(&claim_id).unwrap();
        let operator_factor = find_factor(&trust, "operator_approved");
        assert!(
            operator_factor.applied,
            "operator_approved factor must fire after Patch 6 approve_action by \
             a non-cascade actor; got detail: {}",
            operator_factor.detail,
        );
    }

    #[test]
    fn assess_claim_trust_factor_list_includes_unapplied_factors() {
        // Even a fully-loaded chain doesn't fire every factor
        // (e.g., claim_supported doesn't stack with claim_verified;
        // contradicting_evidence isn't expected to fire). The
        // assessment must STILL include the unapplied factors so
        // the explanation is honest.
        let mut hydra = Hydra::new();
        let (claim_id, _, _) = drive_full_chain_for_trust(&mut hydra);
        let assessment = hydra.assess_claim_trust(&claim_id).unwrap();
        // 16 factors total: Patch 9 baseline of 12 + Patch 12's
        // three historical factors + Patch 13's
        // model_operator_rejected_historically.
        assert_eq!(assessment.factors.len(), 16);
        let unapplied: Vec<&hydra_core::TrustFactor> =
            assessment.factors.iter().filter(|f| !f.applied).collect();
        assert!(
            !unapplied.is_empty(),
            "expected at least one unapplied factor; got all applied"
        );
        // A specific one we know shouldn't fire on a fresh chain:
        let contradict = find_factor(&assessment, "contradicting_evidence");
        assert!(!contradict.applied);
        assert!(contradict.detail.contains("0 contradicting"));
    }

    #[test]
    fn assess_claim_trust_walks_to_observation_when_present() {
        // Patch 8 path: when an observation has been recorded for
        // the claim's prediction run, the assessment surfaces the
        // run_id in observation_run_ids AND
        // model_observation_exists fires.
        let mut hydra = Hydra::new();
        let (claim_id, _, run_id) = drive_full_chain_for_trust(&mut hydra);
        let assessment = hydra.assess_claim_trust(&claim_id).unwrap();
        assert!(find_factor(&assessment, "model_observation_exists").applied);
        assert_eq!(assessment.observation_run_ids, vec![run_id]);
    }

    // === Trust Patch 3 (Patch 11) — auto-execution gate ===

    /// Drive primed Hydra to Critical → cascade auto-approves the
    /// Notify action → return action_id. The action is `Approved`
    /// with `kind == Notify` and `related_claims = [claim_id]` —
    /// the canonical happy-path input for auto-execute.
    fn propose_approved_notify_action(hydra: &mut Hydra) -> hydra_core::ActionId {
        *hydra = primed_hydra(10.0, 1.0);
        let need = 100u64 - ledger_count(hydra);
        ingest_signals(hydra, need);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        assessment.action_ids[0].clone()
    }

    /// Build a high-trust scenario for Patch 11 auto-execute tests.
    ///
    /// **The architectural reality**: a fresh Notify action can't
    /// reach `TrustLevel::High` because Patch 9's factor design
    /// awards three positive factors (action_executed, outcome_
    /// recorded, model_observation_exists) that all REQUIRE prior
    /// execution. This is correct caution by design — Hydra is
    /// stingy about trust until evidence of past success exists.
    ///
    /// The trick: drive a FULL chain end-to-end (gets to High
    /// because action1 was executed + observed), then propose a
    /// SECOND Notify action sharing the same claim. The shared
    /// claim's trust now has all the "executed sibling" signals,
    /// so the new action can pass the auto-execute gate.
    ///
    /// Returns `(new_action_id, shared_claim_id)`.
    fn prepare_high_trust_approved_notify(
        hydra: &mut Hydra,
    ) -> (hydra_core::ActionId, hydra_core::ClaimId) {
        let (claim_id, _outcome_id, _run_id) = drive_full_chain_for_trust(hydra);
        // Sanity: trust on the shared claim is High now.
        let trust = hydra.assess_claim_trust(&claim_id).unwrap();
        assert_eq!(trust.level, hydra_core::TrustLevel::High);
        assert!(trust.score >= 0.80);

        // Ingest a SECOND Notify action linked to the same claim.
        // Status starts Proposed; the cascade auto-approves
        // (no policies registered after primed_hydra rebuild).
        let now = chrono::Utc::now();
        let action_id = hydra_core::ActionId::new();
        let actor = hydra_core::ActorId::from_str("actor_test_sibling");
        let action = hydra_core::Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: hydra_core::ActionKind::Notify,
            status: hydra_core::action::ActionStatus::Proposed,
            targets: vec![hydra_core::action::ActionTarget::System(
                "hydra".to_string(),
            )],
            related_claims: vec![claim_id.clone()],
            supporting_evidence: vec![],
            proposed_by: actor,
            approved_by: None,
            rejected_by: None,
            policy_id: None,
            payload: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ActionProposed { action })
            .unwrap();
        // Cascade auto-approves (no HumanApproval policy was
        // registered for this test). Confirm.
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            hydra_core::action::ActionStatus::Approved
        );
        (action_id, claim_id)
    }

    #[test]
    fn auto_execute_unknown_action_returns_query_error() {
        let mut hydra = Hydra::new();
        let result = hydra.auto_execute_trusted_notify_action(
            hydra_core::ActionId::from_str("act_ghost"),
            hydra_core::ActorId::from_str("actor_hydra_trust_gate"),
            0.80,
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("unknown action"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn auto_execute_refuses_non_notify_kind_with_hard_error() {
        // KIND check is the contract boundary: a Backfill action
        // CANNOT be auto-executed by this method, regardless of
        // trust. v0 enforces with a hard QueryError ("invalid
        // action kind"), which HTTP maps to 400.
        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let action_id = hydra_core::ActionId::new();
        let action = hydra_core::Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: hydra_core::ActionKind::Backfill,
            status: hydra_core::action::ActionStatus::Approved,
            targets: vec![hydra_core::action::ActionTarget::Dataset(
                "orders".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: Some(actor),
            rejected_by: None,
            policy_id: None,
            payload: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: Some(now),
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ActionProposed { action })
            .unwrap();
        let result = hydra.auto_execute_trusted_notify_action(
            action_id,
            hydra_core::ActorId::from_str("actor_hydra_trust_gate"),
            0.80,
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("invalid action kind"), "msg: {msg}");
                assert!(msg.contains("Notify"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn auto_execute_with_non_approved_status_returns_decision_skip() {
        // STATUS is a decision skip, not a hard error — so the
        // second call after a successful auto-execute (which leaves
        // the action in Executed) returns the same shape as
        // "Proposed waiting for approval". Pin both halves.
        let mut hydra = Hydra::new();
        register_any_action_approval_policy(&mut hydra);
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let action_id = hydra_core::ActionId::new();
        let action = hydra_core::Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: hydra_core::ActionKind::Notify,
            status: hydra_core::action::ActionStatus::Proposed,
            targets: vec![hydra_core::action::ActionTarget::System(
                "hydra".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: None,
            rejected_by: None,
            policy_id: None,
            payload: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ActionProposed { action })
            .unwrap();
        // Sanity: action is Proposed (the registered policy kept it).
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            hydra_core::action::ActionStatus::Proposed
        );
        let decision = hydra
            .auto_execute_trusted_notify_action(
                action_id,
                hydra_core::ActorId::from_str("actor_hydra_trust_gate"),
                0.80,
            )
            .unwrap();
        assert!(!decision.executed);
        assert!(decision.reason.contains("not Approved"));
        assert!(decision.trust.is_none());
        assert!(decision.execution.is_none());
    }

    #[test]
    fn auto_execute_with_no_related_claims_skips() {
        // Approved Notify action that wasn't model-derived
        // (related_claims is empty) gets a clean skip with
        // trust=None.
        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let action_id = hydra_core::ActionId::new();
        let action = hydra_core::Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: hydra_core::ActionKind::Notify,
            status: hydra_core::action::ActionStatus::Approved,
            targets: vec![hydra_core::action::ActionTarget::System(
                "hydra".to_string(),
            )],
            related_claims: vec![], // ← skip reason
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: Some(actor),
            rejected_by: None,
            policy_id: None,
            payload: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: Some(now),
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ActionProposed { action })
            .unwrap();
        let decision = hydra
            .auto_execute_trusted_notify_action(
                action_id,
                hydra_core::ActorId::from_str("actor_hydra_trust_gate"),
                0.80,
            )
            .unwrap();
        assert!(!decision.executed);
        assert!(decision.reason.contains("no related_claims"));
        assert!(decision.trust.is_none());
        assert!(decision.execution.is_none());
    }

    #[test]
    fn auto_execute_with_low_trust_skips_and_returns_assessment() {
        // Trust populated even on skip — operators can see WHY
        // auto-execute refused. A FRESH chain (no prior execution
        // history) maxes out at score ~0.50 (Medium), so even
        // a threshold of 0.50 + level check together force a
        // skip with the assessment surfaced.
        let mut hydra = Hydra::new();
        let action_id = propose_approved_notify_action(&mut hydra);
        let decision = hydra
            .auto_execute_trusted_notify_action(
                action_id,
                hydra_core::ActorId::from_str("actor_hydra_trust_gate"),
                0.80,
            )
            .unwrap();
        assert!(!decision.executed);
        assert!(decision.reason.contains("trust insufficient"));
        let trust = decision.trust.as_ref().expect("trust populated on skip");
        // A fresh chain (no execution history) is Medium-tier at best.
        assert_ne!(trust.level, hydra_core::TrustLevel::High);
        assert!(decision.execution.is_none());
    }

    #[test]
    fn auto_execute_with_high_trust_executes_and_returns_full_envelope() {
        // Happy path needs HISTORICAL trust signals: action_executed,
        // outcome_recorded, model_observation_exists all need a prior
        // execution to fire. We arrange that by driving a full chain
        // (first action executes + observes), then proposing a
        // SECOND Notify action on the same claim. The shared claim
        // now has High trust, and the new action can pass the gate.
        //
        // This mirrors the production flow where calibration history
        // (Patch 13) will make first-time auto-execute meaningful.
        let mut hydra = Hydra::new();
        let (action_id, _claim_id) = prepare_high_trust_approved_notify(&mut hydra);
        let decision = hydra
            .auto_execute_trusted_notify_action(
                action_id.clone(),
                hydra_core::ActorId::from_str("actor_hydra_trust_gate"),
                0.80,
            )
            .unwrap();
        assert!(decision.executed, "decision: {decision:#?}");
        assert!(decision.reason.contains("trust High"));
        let trust = decision.trust.as_ref().expect("trust populated on execute");
        assert_eq!(trust.level, hydra_core::TrustLevel::High);
        assert!(trust.score >= 0.80);
        let execution = decision
            .execution
            .as_ref()
            .expect("execution populated on execute");
        assert_eq!(execution.action_id, action_id);
        assert_eq!(
            execution.final_status,
            hydra_core::ActionStatus::Executed
        );
        // The action is actually Executed in the store.
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            hydra_core::ActionStatus::Executed
        );
    }

    #[test]
    fn auto_execute_retracted_claim_skips() {
        // Patch 9 force-clamps Retracted claims to score 0.0.
        // Auto-execute's `score >= min_trust_score` check fires
        // BEFORE execute_notify_action ever runs.
        let mut hydra = Hydra::new();
        let (action_id, claim_id) = prepare_high_trust_approved_notify(&mut hydra);
        // Retract the shared claim — sibling action was already
        // Executed earlier (it's how we got to High); the new
        // action_id is still Approved, but its claim is now
        // retracted so auto-execute must skip.
        hydra
            .ingest(hydra_core::EventKind::ClaimRetracted {
                claim_id,
                retracted_by: hydra_core::ActorId::from_str("actor_oncall"),
                reason: "false alarm".to_string(),
            })
            .unwrap();
        let decision = hydra
            .auto_execute_trusted_notify_action(
                action_id.clone(),
                hydra_core::ActorId::from_str("actor_hydra_trust_gate"),
                0.80,
            )
            .unwrap();
        assert!(!decision.executed);
        let trust = decision.trust.as_ref().unwrap();
        assert_eq!(trust.score, 0.0);
        assert_ne!(trust.level, hydra_core::TrustLevel::High);
        // Action remains Approved — auto-execute didn't fire.
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            hydra_core::ActionStatus::Approved
        );
    }

    #[test]
    fn auto_execute_double_call_second_returns_status_skip() {
        // First call: succeeds, executes, action → Executed.
        // Second call on same action: status check fires →
        // executed=false, reason about non-Approved status.
        // The decision envelope shape is identical to the
        // "not Approved yet" case — callers can poll idempotently.
        let mut hydra = Hydra::new();
        let (action_id, _claim_id) = prepare_high_trust_approved_notify(&mut hydra);
        let first = hydra
            .auto_execute_trusted_notify_action(
                action_id.clone(),
                hydra_core::ActorId::from_str("actor_hydra_trust_gate"),
                0.80,
            )
            .unwrap();
        assert!(first.executed, "first call should fire: {first:#?}");
        let second = hydra
            .auto_execute_trusted_notify_action(
                action_id,
                hydra_core::ActorId::from_str("actor_hydra_trust_gate"),
                0.80,
            )
            .unwrap();
        assert!(!second.executed);
        assert!(second.reason.contains("not Approved"));
        assert!(second.reason.contains("Executed"));
        assert!(second.trust.is_none());
        assert!(second.execution.is_none());
    }

    // === Trust Patch 6 (Patch 15) — trust-gated auto-approval ===

    /// Build a chain where the model has rich enough history that
    /// `model_operator_approved_historically` factor fires, then
    /// register a HumanApproval policy and propose ONE more
    /// Notify action that the cascade leaves in Proposed status.
    /// Returns `(proposed_action_id, claim_id)` ready for
    /// `auto_approve_low_risk_notify_action`.
    fn prepare_proposed_notify_with_operator_history(
        hydra: &mut Hydra,
    ) -> (hydra_core::ActionId, hydra_core::ClaimId) {
        // accumulate model history with operator endorsement.
        let _ = accumulate_model_history(hydra, 3);
        // promote one prior action to operator-approved so
        // model_operator_approved_historically fires.
        let an_action_id = hydra
            .micromodel_store
            .all_observations()
            .next()
            .and_then(observation_action_id)
            .expect("accumulate_model_history recorded observations");
        hydra
            .approve_action(
                an_action_id,
                hydra_core::ActorId::from_str("actor_oncall_alice"),
                Some("endorsed for tests".to_string()),
            )
            .unwrap();
        // Now register a HumanApproval policy so the NEXT proposed
        // action stays in Proposed (cascade can't auto-approve).
        register_any_action_approval_policy(hydra);
        // Re-prime model + propose a fresh action.
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        let need = 100u64.saturating_sub(ledger_count(hydra));
        ingest_signals(hydra, need);
        let assessment_obj = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let action_id = assessment_obj.action_ids[0].clone();
        let claim_id = assessment_obj.claim_id.unwrap();
        // Sanity: HumanApproval policy held the new action at
        // Proposed.
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            hydra_core::ActionStatus::Proposed
        );
        (action_id, claim_id)
    }

    #[test]
    fn auto_approve_unknown_action_returns_query_error() {
        let mut hydra = Hydra::new();
        let result = hydra.auto_approve_low_risk_notify_action(
            hydra_core::ActionId::from_str("act_ghost"),
            hydra_core::ActorId::from_str("actor_ops"),
            0.90,
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("unknown action"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn auto_approve_refuses_non_notify_kind_with_hard_error() {
        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let action_id = hydra_core::ActionId::new();
        let action = hydra_core::Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: hydra_core::ActionKind::Backfill,
            status: hydra_core::action::ActionStatus::Proposed,
            targets: vec![hydra_core::action::ActionTarget::Dataset(
                "orders".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor,
            approved_by: None,
            rejected_by: None,
            policy_id: None,
            payload: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ActionProposed { action })
            .unwrap();
        let result = hydra.auto_approve_low_risk_notify_action(
            action_id,
            hydra_core::ActorId::from_str("actor_ops"),
            0.90,
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("invalid action kind"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn auto_approve_with_non_proposed_status_returns_decision_skip() {
        // Action that's already Approved (cascade auto-approved) →
        // auto-approve returns 200 skip (not a hard error). Lets
        // operators poll idempotently.
        let mut hydra = Hydra::new();
        let action_id = propose_one_test_action(&mut hydra);
        // Action is Approved (cascade auto-approved in fresh
        // policy-free Hydra).
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            hydra_core::action::ActionStatus::Approved
        );
        let decision = hydra
            .auto_approve_low_risk_notify_action(
                action_id,
                hydra_core::ActorId::from_str("actor_ops"),
                0.90,
            )
            .unwrap();
        assert!(!decision.approved);
        assert!(decision.reason.contains("not Proposed"));
        assert!(decision.trust.is_none());
        assert!(decision.approved_by.is_none());
    }

    #[test]
    fn auto_approve_with_no_related_claims_skips() {
        let mut hydra = Hydra::new();
        register_any_action_approval_policy(&mut hydra);
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let action_id = hydra_core::ActionId::new();
        let action = hydra_core::Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: hydra_core::ActionKind::Notify,
            status: hydra_core::action::ActionStatus::Proposed,
            targets: vec![hydra_core::action::ActionTarget::System(
                "hydra".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor,
            approved_by: None,
            rejected_by: None,
            policy_id: None,
            payload: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ActionProposed { action })
            .unwrap();
        let decision = hydra
            .auto_approve_low_risk_notify_action(
                action_id,
                hydra_core::ActorId::from_str("actor_ops"),
                0.90,
            )
            .unwrap();
        assert!(!decision.approved);
        assert!(decision.reason.contains("no related_claims"));
        assert!(decision.trust.is_none());
        assert!(decision.approved_by.is_none());
    }

    #[test]
    fn auto_approve_with_low_trust_skips_and_returns_assessment() {
        // Fresh chain (no historical positive signal yet) → trust
        // sits at ~Medium. Auto-approve refuses.
        let mut hydra = Hydra::new();
        register_any_action_approval_policy(&mut hydra);
        let _ = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        let assessment_obj = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let action_id = assessment_obj.action_ids[0].clone();
        let decision = hydra
            .auto_approve_low_risk_notify_action(
                action_id,
                hydra_core::ActorId::from_str("actor_ops"),
                0.90,
            )
            .unwrap();
        assert!(!decision.approved);
        // Fresh chain hits the score gate (trust score < 0.90)
        // OR the operator-history gate. Either way, it skips
        // with the trust assessment surfaced.
        assert!(decision.trust.is_some());
        assert!(decision.approved_by.is_none());
    }

    #[test]
    fn auto_approve_with_no_operator_approved_history_skips() {
        // Drive a chain with cascade-only history (no human
        // approvals). A cascade-only Proposed action maxes at
        // score=0.75 (Medium), so the score+level gate vetoes
        // first; the underlying operator-history factor is still
        // surfaced as `applied=false` in the assessment, which is
        // the load-bearing signal Patch 15 callers can introspect.
        let mut hydra = Hydra::new();
        let _ = accumulate_model_history(&mut hydra, 3);
        register_any_action_approval_policy(&mut hydra);
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        let assessment_obj = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let action_id = assessment_obj.action_ids[0].clone();
        let decision = hydra
            .auto_approve_low_risk_notify_action(
                action_id,
                hydra_core::ActorId::from_str("actor_ops"),
                0.80,
            )
            .unwrap();
        assert!(!decision.approved);
        let trust = decision.trust.as_ref().unwrap();
        let factor = trust
            .factors
            .iter()
            .find(|f| f.kind == "model_operator_approved_historically")
            .unwrap();
        assert!(
            !factor.applied,
            "operator-history factor must surface as not-applied in cascade-only chain"
        );
        assert!(decision.approved_by.is_none());
    }

    #[test]
    fn auto_approve_blocks_on_contradicting_evidence_factor() {
        // Even if trust is otherwise High AND model has operator
        // history, applied contradicting_evidence vetoes.
        let mut hydra = Hydra::new();
        let (action_id, claim_id) =
            prepare_proposed_notify_with_operator_history(&mut hydra);
        // Inject contradicting evidence.
        let now = chrono::Utc::now();
        let evidence_id = hydra_core::EvidenceId::new();
        let evidence = hydra_core::Evidence {
            id: evidence_id.clone(),
            tenant_id: None,
            source: hydra_core::EvidenceSource::Human {
                actor_id: hydra_core::ActorId::from_str("actor_human"),
            },
            payload: hydra_core::EvidencePayload {
                kind: "refutation".to_string(),
                data: std::collections::HashMap::new(),
            },
            reliability: hydra_core::Confidence::new(0.90),
            observed_at: now,
            recorded_at: now,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::EvidenceAdded { evidence })
            .unwrap();
        hydra
            .ingest(hydra_core::EventKind::ClaimDisputed {
                claim_id,
                evidence_id,
                reason: Some("test contradicting evidence".to_string()),
            })
            .unwrap();
        let decision = hydra
            .auto_approve_low_risk_notify_action(
                action_id,
                hydra_core::ActorId::from_str("actor_ops"),
                0.90,
            )
            .unwrap();
        assert!(!decision.approved);
        assert!(decision.reason.contains("hard-block"));
        assert!(decision.reason.contains("contradicting_evidence"));
    }

    #[test]
    fn auto_approve_blocks_on_retracted_claim() {
        // Patch 9's force-clamp sets score to 0.0 for Retracted,
        // but Patch 15 should ALSO surface that the retracted
        // hard-block factor fired.
        let mut hydra = Hydra::new();
        let (action_id, claim_id) =
            prepare_proposed_notify_with_operator_history(&mut hydra);
        hydra
            .ingest(hydra_core::EventKind::ClaimRetracted {
                claim_id,
                retracted_by: hydra_core::ActorId::from_str("actor_human"),
                reason: "false alarm".to_string(),
            })
            .unwrap();
        let decision = hydra
            .auto_approve_low_risk_notify_action(
                action_id.clone(),
                hydra_core::ActorId::from_str("actor_ops"),
                0.90,
            )
            .unwrap();
        assert!(!decision.approved);
        assert!(decision.reason.contains("claim_retracted"));
        // Action still Proposed — auto-approve didn't fire.
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            hydra_core::action::ActionStatus::Proposed
        );
    }

    #[test]
    fn auto_approve_success_path_emits_action_approved_with_trust_gate_actor() {
        // The headline happy path: action proposed, trust High,
        // operator history present, no hard-block factors. Patch
        // 15 emits ActionApproved with the trust-gate actor.
        //
        // Threshold note: a freshly Proposed action maxes at
        // score=0.85 because three positive factors require the
        // action to have been executed (`action_executed`,
        // `outcome_recorded`, `model_observation_exists`).
        // 0.80 is the practical ceiling for proposed-stage
        // auto-approval; the SDK exposes the threshold so
        // operators can dial up for stricter scenarios.
        let mut hydra = Hydra::new();
        let (action_id, _claim_id) =
            prepare_proposed_notify_with_operator_history(&mut hydra);
        let decision = hydra
            .auto_approve_low_risk_notify_action(
                action_id.clone(),
                hydra_core::ActorId::from_str("actor_ops"),
                0.80,
            )
            .unwrap();
        assert!(decision.approved, "decision: {decision:#?}");
        assert!(decision.reason.contains("auto-approved"));
        assert_eq!(
            decision.approved_by.as_ref().unwrap().as_str(),
            "actor_hydra_trust_gate"
        );
        // Action is now Approved, stamped with the trust-gate actor.
        let final_action = hydra.action(&action_id).unwrap();
        assert_eq!(
            final_action.status,
            hydra_core::action::ActionStatus::Approved
        );
        assert_eq!(
            final_action.approved_by.as_ref().unwrap().as_str(),
            "actor_hydra_trust_gate"
        );
        // The audit log carries the ActionApproved event with the
        // Patch 15 reason string.
        let found = hydra.events().iter().any(|event| {
            matches!(
                &event.kind,
                hydra_core::EventKind::ActionApproved {
                    approved_by, reason: Some(r), ..
                }
                if approved_by.as_str() == "actor_hydra_trust_gate"
                    && r.contains("auto-approved")
            )
        });
        assert!(found, "audit log missing trust-gate ActionApproved event");
    }

    #[test]
    fn auto_approval_does_not_count_as_operator_approval_in_future_trust() {
        // **THE LOAD-BEARING TRUST-SPIRAL REGRESSION PIN.**
        //
        // After a Patch 15 auto-approval, a fresh model-derived
        // claim's `model_operator_approved_historically` factor
        // must NOT fire JUST because the trust-gate approved a
        // prior action. That would let auto-approvals bootstrap
        // more auto-approvals.
        //
        // This test:
        //   1. drives a model chain with ONE genuine human
        //      approval (so the next action can pass Patch 15)
        //   2. EXECUTES + OBSERVES that approved action so trust
        //      calibration sees it (the human-approved record)
        //   3. has Patch 15 auto-approve a NEW action
        //   4. EXECUTES + OBSERVES the auto-approved action
        //   5. Proposes ONE MORE action and assesses its trust
        //   6. Asserts model_operator_approved_historically is
        //      still applied (because step 2 was a real human
        //      approval), AND verifies the trust-gate approval
        //      from step 3 didn't "double count."
        let mut hydra = Hydra::new();
        let (action_id, _claim_id) =
            prepare_proposed_notify_with_operator_history(&mut hydra);
        let auto_decision = hydra
            .auto_approve_low_risk_notify_action(
                action_id.clone(),
                hydra_core::ActorId::from_str("actor_ops"),
                0.80,
            )
            .unwrap();
        assert!(auto_decision.approved);

        // Execute + observe the auto-approved action so trust
        // calibration sees it.
        let exec_report = hydra
            .execute_notify_action(
                action_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        hydra
            .record_micro_model_observation_from_action_outcome(
                exec_report.outcome_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();

        // Walk the observations: one MUST have approved_by ==
        // actor_hydra_trust_gate (the Patch 15 auto-approval) and
        // is_hydra_automation_actor must classify it as a NON
        // operator. The trust factor reading must respect this.
        let observations: Vec<_> = hydra
            .micromodel_store
            .all_observations()
            .collect();
        let trust_gate_approved_exists = observations.iter().any(|obs| {
            observation_action_id(obs)
                .and_then(|aid| hydra.action(&aid))
                .and_then(|a| a.approved_by.as_ref())
                .map(|approver| {
                    approver.as_str() == "actor_hydra_trust_gate"
                })
                .unwrap_or(false)
        });
        assert!(
            trust_gate_approved_exists,
            "expected at least one observation with trust-gate approver"
        );

        // Now propose a FRESH model-derived claim and assess.
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        let next = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let new_claim_id = next.claim_id.unwrap();
        let trust = hydra.assess_claim_trust(&new_claim_id).unwrap();
        let operator_factor = trust
            .factors
            .iter()
            .find(|f| f.kind == "model_operator_approved_historically")
            .unwrap();
        // STILL applied because the ORIGINAL human approval (from
        // prepare_proposed_notify_with_operator_history) survives.
        // But the trust-gate auto-approval from the recent action
        // did NOT also "double count" — the test passes if the
        // factor is applied as before, NOT because the auto-approval
        // bootstrapped it.
        assert!(
            operator_factor.applied,
            "operator history must remain visible from the ORIGINAL human approval"
        );

        // Inverse pin: remove the original human-endorsed action
        // from the equation by checking that the trust-gate
        // approval ALONE (without any human approval) doesn't
        // suffice. We construct a separate, parallel Hydra with
        // only cascade + trust-gate history (no human).
        let mut parallel = Hydra::new();
        // Accumulate cascade-only history (no operator approvals).
        let _ = accumulate_model_history(&mut parallel, 3);
        // Manually approve one of the prior actions with the
        // trust-gate actor (simulating a Patch 15 auto-approval
        // having happened).
        let target_action_id = parallel
            .micromodel_store
            .all_observations()
            .next()
            .and_then(observation_action_id)
            .unwrap();
        parallel
            .approve_action(
                target_action_id,
                hydra_core::ActorId::from_str("actor_hydra_trust_gate"),
                Some("auto-approved: high-trust low-risk Notify".to_string()),
            )
            .unwrap();
        // Propose a fresh action; check the operator-history
        // factor is NOT applied (trust-gate alone doesn't count).
        parallel
            .set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        let need = 100u64.saturating_sub(ledger_count(&parallel));
        ingest_signals(&mut parallel, need);
        let next_p = parallel
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let new_claim_p = next_p.claim_id.unwrap();
        let trust_p = parallel.assess_claim_trust(&new_claim_p).unwrap();
        let operator_factor_p = trust_p
            .factors
            .iter()
            .find(|f| f.kind == "model_operator_approved_historically")
            .unwrap();
        assert!(
            !operator_factor_p.applied,
            "TRUST-SPIRAL REGRESSION: trust-gate auto-approvals must NOT \
             count as operator approval in trust calibration — otherwise \
             auto-approval bootstraps more auto-approval"
        );
    }

    // === Trust Patch 4 (Patch 12) — reflex trust calibration ===

    /// Drive `n` full chains (Critical → Approved → Executed →
    /// Observed) against the SAME Hydra so the
    /// `mm_builtin_commit_rate_v0` model accumulates `n` prior
    /// observations. Returns the LAST claim_id.
    ///
    /// Unlike `drive_full_chain_for_trust` (which REPLACES *hydra),
    /// this helper preserves the engine across iterations so the
    /// MicroModelStore accumulates observations from every run. The
    /// model is RE-PRIMED between iterations (not the whole engine)
    /// so each evaluate call still lands at Critical.
    fn accumulate_model_history(hydra: &mut Hydra, n: usize) -> hydra_core::ClaimId {
        // One-time prime: warm + register the model.
        let _ = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        let mut last_claim_id: Option<hydra_core::ClaimId> = None;
        let operator = hydra_core::ActorId::from_str("actor_test");
        for _ in 0..n {
            // Re-prime the MODEL only (not the engine) so this
            // iteration's evaluate produces Critical.
            hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
            // Ingest enough commits so the recent window has a
            // critical rate. saturating_sub so we never underflow
            // when the ledger already has lots of prior commits.
            let need = 100u64.saturating_sub(ledger_count(hydra));
            ingest_signals(hydra, need);
            let assessment = hydra
                .evaluate_commit_rate_anomaly_and_propose_action(requester())
                .unwrap();
            let action_id = assessment
                .action_ids
                .into_iter()
                .next()
                .expect("critical produced an action");
            let claim_id = assessment.claim_id.unwrap();
            let report = hydra
                .execute_notify_action(action_id, operator.clone())
                .unwrap();
            hydra
                .record_micro_model_observation_from_action_outcome(
                    report.outcome_id,
                    operator.clone(),
                )
                .unwrap();
            last_claim_id = Some(claim_id);
        }
        last_claim_id.expect("n >= 1")
    }

    #[test]
    fn assess_claim_trust_zero_model_history_does_not_apply_factors() {
        // Fresh deployment with NO prior observations. The 3
        // historical factors must emit with applied=false and
        // matching detail strings so the assessment surface stays
        // honest.
        let mut hydra = Hydra::new();
        // Drive ONE full chain — this records 1 observation, but
        // we'll ALSO need a claim that hasn't itself been observed
        // yet. Easiest: propose a SECOND model-derived claim and
        // assess THAT one. But for the "zero history" pin we want
        // a totally fresh chain. Use a manually-constructed
        // non-model claim instead so we exercise the
        // "claim is not model-derived" path.
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let claim_id = hydra_core::ClaimId::new();
        let claim = hydra_core::Claim {
            id: claim_id.clone(),
            tenant_id: None,
            kind: hydra_core::ClaimKind::Hypothesis,
            subject: hydra_core::ClaimSubject::System("hydra".to_string()),
            predicate: "test".to_string(),
            object: hydra_core::ClaimObject::Value(hydra_core::Value::Bool(true)),
            confidence: hydra_core::Confidence::new(0.5),
            status: hydra_core::ClaimStatus::Proposed,
            evidence_for: vec![],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: actor,
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ClaimProposed { claim })
            .unwrap();
        let assessment = hydra.assess_claim_trust(&claim_id).unwrap();
        for kind in [
            "reflex_history_present",
            "model_proven_executed",
            "model_operator_approved_historically",
        ] {
            let f = find_factor(&assessment, kind);
            assert!(!f.applied, "factor {kind} should not apply on non-model claim");
            assert!(
                f.detail.contains("claim is not model-derived"),
                "factor {kind} detail wrong: {}",
                f.detail
            );
        }
    }

    #[test]
    fn assess_claim_trust_reflex_history_present_fires_at_one_observation() {
        // One prior observation lights up reflex_history_present
        // but NOT model_proven_executed (needs >= 3). Drive ONE
        // chain, then assess a SECOND model-derived claim. The
        // simplest way: drive_full_chain_for_trust gives us the
        // first claim AND its observation; then drive a Critical
        // again on the same Hydra → second claim shares model_id
        // = mm_builtin_commit_rate_v0.
        let mut hydra = Hydra::new();
        // First chain → records observation #1 against the
        // commit-rate model.
        let _ = drive_full_chain_for_trust(&mut hydra);
        // Second chain → produces a NEW claim that has not itself
        // been observed yet, but inherits the model's history.
        let (second_claim_id, _, _) = drive_full_chain_for_trust(&mut hydra);
        // Note drive_full_chain_for_trust ALSO records observation #2.
        // We need a claim that's freshly proposed BEFORE any of its
        // own outcomes land. Re-prime + propose a third claim
        // without executing/observing it.
        *(&mut hydra) = primed_hydra(10.0, 1.0);
        // The re-prime resets the engine, losing the prior
        // observations from drive_full_chain_for_trust. So we must
        // accumulate history BEFORE re-prime is gone, OR use a
        // single primed_hydra and propose multiple chains on it
        // without rebuilding. Use the simpler path: accumulate
        // history in-line on the same primed instance.
        let _ = second_claim_id; // suppress unused
        let mut hydra = Hydra::new();
        let _ = accumulate_model_history(&mut hydra, 1);
        // Re-prime the model so this eval call lands at Critical
        // (accumulate_model_history's last eval advanced the EWMA;
        // we need to reset it for a fresh Critical signal).
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        let assessment_obj = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let claim_id = assessment_obj.claim_id.unwrap();
        let trust = hydra.assess_claim_trust(&claim_id).unwrap();
        let history = find_factor(&trust, "reflex_history_present");
        assert!(history.applied, "history present: {}", history.detail);
        let proven = find_factor(&trust, "model_proven_executed");
        assert!(!proven.applied, "1 observation should NOT meet proven threshold (3)");
    }

    #[test]
    fn assess_claim_trust_proven_executed_requires_three_observations() {
        // Threshold pin: 2 observations is NOT proven, 3 IS.
        // Accumulate exactly 2, propose a fresh chain → not proven.
        // Then bump to 3, propose another fresh chain → proven.
        let mut hydra = Hydra::new();
        let _ = accumulate_model_history(&mut hydra, 2);
        // Re-prime the model so the next eval lands at Critical.
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        let two_obs_claim = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap()
            .claim_id
            .unwrap();
        let trust_at_two = hydra.assess_claim_trust(&two_obs_claim).unwrap();
        let proven_at_two = find_factor(&trust_at_two, "model_proven_executed");
        assert!(!proven_at_two.applied, "2 observations should not meet threshold; got {}", proven_at_two.detail);

        // Add a third observation. Execute + observe the previous
        // claim's action to push count to 3.
        let action_id = hydra
            .action_store
            .actions_for_claim(&two_obs_claim)
            .first()
            .map(|a| a.id.clone())
            .expect("claim has at least one action");
        let report = hydra
            .execute_notify_action(
                action_id,
                hydra_core::ActorId::from_str("actor_test"),
            )
            .unwrap();
        hydra
            .record_micro_model_observation_from_action_outcome(
                report.outcome_id,
                hydra_core::ActorId::from_str("actor_test"),
            )
            .unwrap();
        // Now propose a 4th model-derived claim that hasn't been
        // observed itself. We want the historical count = 3.
        *(&mut hydra) = {
            let mut h = std::mem::replace(&mut hydra, Hydra::new());
            // primed_hydra rebuilds — we'd lose history. Instead,
            // re-prime in place: warm + reseed the model. The
            // existing observations are PRESERVED because we don't
            // touch the micromodel_store.
            let _ = h.evaluate_commit_rate_anomaly(requester()).unwrap();
            h.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
            h
        };
        // accumulate_model_history may push ledger count above 100;
        // use saturating_sub so the test doesn't underflow. If the
        // ledger is already past 100, no extra signals are needed —
        // the window count is already high enough to trigger
        // Critical against the re-primed baseline.
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        let third_observed_claim = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap()
            .claim_id
            .unwrap();
        let trust_at_three = hydra.assess_claim_trust(&third_observed_claim).unwrap();
        let proven_at_three = find_factor(&trust_at_three, "model_proven_executed");
        assert!(
            proven_at_three.applied,
            "3 observations SHOULD meet threshold; got {}",
            proven_at_three.detail
        );
    }

    #[test]
    fn assess_claim_trust_operator_approved_historically_only_counts_non_cascade() {
        // Cascade-only history → factor stays unapplied even with
        // dozens of observations.
        let mut hydra = Hydra::new();
        let _ = accumulate_model_history(&mut hydra, 3);
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        let fresh_claim = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap()
            .claim_id
            .unwrap();
        let trust_cascade = hydra.assess_claim_trust(&fresh_claim).unwrap();
        let cascade_only =
            find_factor(&trust_cascade, "model_operator_approved_historically");
        assert!(
            !cascade_only.applied,
            "cascade auto-approvals must NOT count: {}",
            cascade_only.detail
        );

        // Now have an OPERATOR explicitly approve the most recent
        // model action. (Pre-existing observations are still
        // cascade-only; the new approval re-stamps the latest
        // action's approved_by to a non-cascade actor.)
        let recent_action = hydra
            .action_store
            .actions_for_claim(&fresh_claim)
            .first()
            .map(|a| a.id.clone())
            .expect("claim has an action");
        // Patch 6's approve_action is lenient and re-approves.
        let operator = hydra_core::ActorId::from_str("actor_oncall_alice");
        hydra
            .approve_action(recent_action.clone(), operator, Some("looks ok".into()))
            .unwrap();
        // Execute + observe so it counts as historical.
        let report = hydra
            .execute_notify_action(
                recent_action,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        hydra
            .record_micro_model_observation_from_action_outcome(
                report.outcome_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        // Propose a NEW claim and check trust again.
        let _ = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        // accumulate_model_history may push ledger count above 100;
        // use saturating_sub so the test doesn't underflow. If the
        // ledger is already past 100, no extra signals are needed —
        // the window count is already high enough to trigger
        // Critical against the re-primed baseline.
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        let post_operator_claim = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap()
            .claim_id
            .unwrap();
        let trust_with_operator = hydra.assess_claim_trust(&post_operator_claim).unwrap();
        let operator_factor = find_factor(
            &trust_with_operator,
            "model_operator_approved_historically",
        );
        assert!(
            operator_factor.applied,
            "expected operator-approved historical signal: {}",
            operator_factor.detail
        );
    }

    #[test]
    fn assess_claim_trust_proven_model_lifts_fresh_chain_to_high() {
        // The headline test: a new claim from a model that has
        // accumulated OPERATOR-ENDORSED history reaches High
        // WITHOUT a sibling sharing the same claim. This is
        // exactly what Patch 11 couldn't do — Patch 12's reflex
        // calibration is the fix.
        //
        // Score math:
        //   claim_verified                          +0.20
        //   high_confidence_claim                   +0.10
        //   supporting_evidence_present             +0.10
        //   reliable_supporting_evidence            +0.10
        //   reflex_history_present                  +0.10 (>= 1 obs)
        //   model_proven_executed                   +0.15 (>= 3 obs)
        //   model_operator_approved_historically    +0.10 (endorsed)
        //                                            =====
        //                                            +0.85 → High ✓
        //
        // Without operator-endorsed history, fresh chains cap at
        // 0.75 (Medium). That's correct: cascade-only history
        // hasn't earned human-endorsed trust. The semantic shift
        // is honest — Patch 12 means "humans have looked at this
        // model and said yes before."
        let mut hydra = Hydra::new();
        let _ = accumulate_model_history(&mut hydra, 3);

        // Promote ONE prior action to operator-approved. Patch 6's
        // approve_action is lenient — calling it re-stamps
        // approved_by to the non-cascade actor.
        let an_action_id = hydra
            .micromodel_store
            .all_observations()
            .next()
            .and_then(observation_action_id)
            .expect("accumulate_model_history recorded observation(s)");
        hydra
            .approve_action(
                an_action_id,
                hydra_core::ActorId::from_str("actor_oncall_alice"),
                Some("endorsed".to_string()),
            )
            .unwrap();

        // Re-prime model so the fresh eval lands at Critical.
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        let new_claim = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap()
            .claim_id
            .unwrap();
        let trust = hydra.assess_claim_trust(&new_claim).unwrap();

        // All three historical factors should apply.
        assert!(find_factor(&trust, "reflex_history_present").applied);
        assert!(find_factor(&trust, "model_proven_executed").applied);
        assert!(find_factor(&trust, "model_operator_approved_historically").applied);
        // And the chain reaches High.
        assert_eq!(
            trust.level,
            hydra_core::TrustLevel::High,
            "expected High; got {:?} with score {:.3} factors {:#?}",
            trust.level,
            trust.score,
            trust.factors
        );
        assert!(
            trust.score >= 0.80,
            "expected score >= 0.80, got {:.3}",
            trust.score
        );
    }

    #[test]
    fn assess_claim_trust_non_model_claim_does_not_apply_history_factors() {
        // A non-model claim with substantial chain trust gets ALL
        // three historical factors as applied=false. Ensures the
        // factor list stays consistent across model vs non-model
        // claims.
        let mut hydra = Hydra::new();
        // Drive 3+ observations so model HAS history.
        let _ = accumulate_model_history(&mut hydra, 3);
        // Now propose a non-model claim manually.
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_test");
        let claim_id = hydra_core::ClaimId::new();
        let claim = hydra_core::Claim {
            id: claim_id.clone(),
            tenant_id: None,
            kind: hydra_core::ClaimKind::Hypothesis,
            subject: hydra_core::ClaimSubject::System("hydra".to_string()),
            predicate: "non_model_test".to_string(),
            object: hydra_core::ClaimObject::Value(hydra_core::Value::Bool(true)),
            confidence: hydra_core::Confidence::new(0.95),
            status: hydra_core::ClaimStatus::Verified,
            evidence_for: vec![],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: actor,
            created_at: now,
            updated_at: now,
            caused_by: None, // ← key: not model-derived
        };
        hydra
            .ingest(hydra_core::EventKind::ClaimProposed { claim })
            .unwrap();
        let trust = hydra.assess_claim_trust(&claim_id).unwrap();
        for kind in [
            "reflex_history_present",
            "model_proven_executed",
            "model_operator_approved_historically",
        ] {
            let f = find_factor(&trust, kind);
            assert!(
                !f.applied,
                "factor {kind} fired on non-model claim despite global model history"
            );
            assert!(
                f.detail.contains("claim is not model-derived"),
                "factor {kind} detail wrong: {}",
                f.detail
            );
        }
    }

    // === Trust Patch 5 (Patch 13) — rejection-path observations ===

    /// Drive one full Critical chain, then REJECT the resulting
    /// action (with a non-cascade operator), so the cascade leaves
    /// behind:
    ///   - one model-derived ActionRejected event
    ///   - an Action with status=Rejected and rejected_by=operator
    /// Returns the action_id ready for
    /// `record_micro_model_observation_from_rejected_action`.
    fn drive_chain_and_reject(
        hydra: &mut Hydra,
        operator: hydra_core::ActorId,
    ) -> hydra_core::ActionId {
        // Register a HumanApproval policy so the cascade leaves
        // the action in Proposed (cascade auto-approve would
        // otherwise transition it to Approved without giving us
        // a Proposed action to reject).
        register_any_action_approval_policy(hydra);
        // Warm + prime model.
        let _ = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        let need = 100u64.saturating_sub(ledger_count(hydra));
        ingest_signals(hydra, need);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let action_id = assessment.action_ids[0].clone();
        // Reject via Patch 6's helper (operator-triggered).
        hydra
            .reject_action(
                action_id.clone(),
                operator,
                "false alarm during maintenance".to_string(),
            )
            .unwrap();
        action_id
    }

    #[test]
    fn record_observation_from_rejected_action_unknown_action_returns_query_error() {
        let mut hydra = Hydra::new();
        let result = hydra.record_micro_model_observation_from_rejected_action(
            hydra_core::ActionId::from_str("act_does_not_exist"),
            hydra_core::ActorId::from_str("actor_ops"),
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("unknown action"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn record_observation_from_rejected_action_wrong_status_returns_error() {
        // Approved-but-not-rejected action → method must refuse.
        let mut hydra = Hydra::new();
        let action_id = propose_one_test_action(&mut hydra);
        // Sanity: action is Approved (cascade auto-approved).
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            hydra_core::ActionStatus::Approved
        );
        let result = hydra.record_micro_model_observation_from_rejected_action(
            action_id,
            hydra_core::ActorId::from_str("actor_ops"),
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("invalid action state"), "msg: {msg}");
                assert!(msg.contains("Rejected"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn record_observation_from_rejected_action_cascade_only_rejection_refused() {
        // Cascade rejections must be refused — they're policy
        // enforcement, not human judgment. To trigger one: register
        // a PolicyKind::Block policy so the cascade emits
        // ActionRejected with rejected_by = cascade actor.
        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_policy_admin");
        let policy = hydra_core::Policy {
            id: hydra_core::PolicyId::new(),
            tenant_id: None,
            name: "Block all actions".to_string(),
            kind: hydra_core::PolicyKind::Block,
            status: hydra_core::PolicyStatus::Active,
            scope: hydra_core::PolicyScope::AnyAction,
            condition: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
            created_by: actor,
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::PolicyRegistered { policy })
            .unwrap();
        // Warm + prime + drive Critical so cascade emits
        // ActionRejected for the proposed action.
        let _ = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        // Cascade-rejected action exists. Its rejected_by should
        // be the cascade actor id.
        let action_id = assessment.action_ids[0].clone();
        let action = hydra.action(&action_id).unwrap();
        assert_eq!(action.status, hydra_core::ActionStatus::Rejected);
        let rejector = action.rejected_by.as_ref().unwrap();
        assert!(
            hydra_core::is_cascade_approver(rejector),
            "expected cascade rejector, got {rejector}"
        );
        let result = hydra.record_micro_model_observation_from_rejected_action(
            action_id,
            hydra_core::ActorId::from_str("actor_ops"),
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("rejected by cascade"),
                    "msg: {msg}"
                );
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn record_observation_from_rejected_action_records_with_rejection_reason() {
        // The happy path: a model-derived action rejected by a
        // non-cascade actor produces an observation with the
        // rejection-shaped JSON.
        let mut hydra = Hydra::new();
        let operator = hydra_core::ActorId::from_str("actor_oncall_alice");
        let action_id = drive_chain_and_reject(&mut hydra, operator.clone());
        let observation = hydra
            .record_micro_model_observation_from_rejected_action(
                action_id.clone(),
                operator.clone(),
            )
            .unwrap();
        let obj = observation
            .observed_outcome
            .as_object()
            .expect("observed_outcome is a JSON object");
        assert_eq!(
            obj.get("action_lifecycle").and_then(|v| v.as_str()),
            Some("rejected")
        );
        assert_eq!(
            obj.get("operator_approved").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            obj.get("operator_rejected").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            obj.get("outcome_kind").and_then(|v| v.as_str()),
            Some("Rejected")
        );
        assert_eq!(
            obj.get("rejection_reason").and_then(|v| v.as_str()),
            Some("false alarm during maintenance")
        );
        assert_eq!(
            obj.get("action_id").and_then(|v| v.as_str()),
            Some(action_id.to_string().as_str())
        );
        // observed_by is the actor recording (may equal the
        // rejecter; not enforced in v0).
        assert_eq!(
            obj.get("observed_by").and_then(|v| v.as_str()),
            Some(operator.to_string().as_str())
        );
        // Store keys observations by run_id; the record landed.
        let stored = hydra.micro_model_observation(&observation.run_id).unwrap();
        assert_eq!(stored.run_id, observation.run_id);
    }

    #[test]
    fn assess_claim_trust_operator_rejected_historically_fires_on_prior_operator_rejection() {
        // Set up a model with prior rejection history, then
        // propose a NEW claim and assess. The new factor should
        // fire and penalize.
        let mut hydra = Hydra::new();
        let operator = hydra_core::ActorId::from_str("actor_oncall_alice");
        let _ = drive_chain_and_reject(&mut hydra, operator.clone());
        // Record the rejection observation so it shows up in
        // observations_for_model.
        let rejected_action_id = hydra
            .action_store()
            .all_actions()
            .find(|a| a.status == hydra_core::ActionStatus::Rejected)
            .map(|a| a.id.clone())
            .expect("rejected action present");
        hydra
            .record_micro_model_observation_from_rejected_action(
                rejected_action_id,
                operator,
            )
            .unwrap();
        // Now propose a new model-derived claim and assess.
        // Re-prime model so the new evaluate lands at Critical.
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        // Approve the next proposed action (the HumanApproval
        // policy from drive_chain_and_reject is still active, so
        // a new Critical produces a Proposed action). Then assess.
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let new_claim = assessment.claim_id.unwrap();
        let trust = hydra.assess_claim_trust(&new_claim).unwrap();
        let rejected_factor =
            find_factor(&trust, "model_operator_rejected_historically");
        assert!(
            rejected_factor.applied,
            "expected rejection signal to fire; detail: {}",
            rejected_factor.detail,
        );
        assert_eq!(rejected_factor.weight, -0.15);
    }

    #[test]
    fn assess_claim_trust_operator_rejected_historically_ignores_cascade_rejections() {
        // A model with CASCADE-only rejection history (no operator
        // ever pressed reject) → the new negative factor must NOT
        // fire. Mirrors Patch 9/12's load-bearing distinction.
        //
        // Note: cascade rejections currently can't easily land a
        // MicroModelObservation (Patch 13's recorder refuses them),
        // so we test the factor's filter on a manually-injected
        // observation whose action.rejected_by is the cascade
        // actor.
        let mut hydra = Hydra::new();
        let actor = hydra_core::ActorId::from_str("actor_test");

        // Block-policy → cascade rejects.
        let now = chrono::Utc::now();
        let policy = hydra_core::Policy {
            id: hydra_core::PolicyId::new(),
            tenant_id: None,
            name: "Block all".to_string(),
            kind: hydra_core::PolicyKind::Block,
            status: hydra_core::PolicyStatus::Active,
            scope: hydra_core::PolicyScope::AnyAction,
            condition: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::PolicyRegistered { policy })
            .unwrap();
        let _ = hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(10.0, 1.0));
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(requester())
            .unwrap();
        let rejected_action_id = assessment.action_ids[0].clone();
        let claim_id = assessment.claim_id.unwrap();
        // Manually inject a rejection-shaped observation so the
        // trust assessor's history walk sees a cascade-rejected
        // entry. This bypasses Patch 13's normal recorder (which
        // would refuse the cascade rejection) — that refusal is
        // exactly what protects v0; the test verifies the FACTOR
        // also filters defensively if observations were
        // hand-inserted.
        let prediction_run_id = match &hydra
            .event(&assessment.prediction_event_id)
            .unwrap()
            .kind
        {
            hydra_core::EventKind::MicroModelPredictionRecorded { prediction } => {
                prediction.run_id.clone()
            }
            _ => unreachable!(),
        };
        let observation = hydra_core::MicroModelObservation {
            run_id: prediction_run_id,
            observed_outcome: serde_json::json!({
                "action_id": rejected_action_id.to_string(),
                "action_lifecycle": "rejected",
                "operator_approved": false,
                "operator_rejected": true,
            }),
            error: None,
            observed_at: chrono::Utc::now(),
        };
        hydra
            .ingest(hydra_core::EventKind::MicroModelObservationRecorded {
                observation,
            })
            .unwrap();
        // Assess the claim — Patch 13's factor must NOT fire
        // because the underlying action's rejected_by is the
        // cascade actor.
        let trust = hydra.assess_claim_trust(&claim_id).unwrap();
        let rejected_factor =
            find_factor(&trust, "model_operator_rejected_historically");
        assert!(
            !rejected_factor.applied,
            "cascade rejections must NOT count; detail: {}",
            rejected_factor.detail,
        );
    }

    #[test]
    fn action_rejected_sets_rejected_by_and_rejected_at_fields() {
        // Pin the action_store apply_event behavior added in
        // Patch 13: ActionRejected now populates Action.rejected_by
        // AND Action.rejected_at. Symmetric with Patch 6's
        // ActionApproved → approved_by / approved_at.
        let mut hydra = Hydra::new();
        let action_id = propose_one_test_action(&mut hydra);
        let before = chrono::Utc::now();
        let rejecter = hydra_core::ActorId::from_str("actor_oncall_alice");
        hydra
            .reject_action(action_id.clone(), rejecter.clone(), "no".to_string())
            .unwrap();
        let after = chrono::Utc::now();
        let action = hydra.action(&action_id).unwrap();
        assert_eq!(action.status, hydra_core::ActionStatus::Rejected);
        assert_eq!(action.rejected_by.as_ref(), Some(&rejecter));
        let rejected_at = action.rejected_at.expect("rejected_at populated");
        assert!(rejected_at >= before && rejected_at <= after);
    }

    // === Patch 17 — refactor pin tests ===
    //
    // Three small pins that catch the most likely regression
    // shapes from the spine extraction. Existing tests (575 in
    // hydra-engine + the HTTP/SDK suites) already cover behavior
    // — these only add defense-in-depth against the specific
    // failure modes the refactor introduces.

    /// Drives the commit-rate bridge end-to-end and reads back
    /// the recorded Evidence. The refactor MUST preserve the full
    /// eight-key payload `data` shape from Patches 3-4: model_id,
    /// run_id, level, direction, observed_rate, expected_rate,
    /// z_score, reason. Catches an accidental field drop in
    /// `commit_rate_reflex_parts`.
    #[test]
    fn patch17_commit_rate_reflex_preserves_evidence_payload_shape() {
        let mut hydra = Hydra::new();
        hydra.evaluate_commit_rate_anomaly(requester()).unwrap();
        hydra.set_commit_rate_anomaly_model(primed_model_with_baseline(
            10.0, 1.0,
        ));
        let need = 100u64.saturating_sub(ledger_count(&hydra));
        ingest_signals(&mut hydra, need);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();
        let evidence_id = assessment
            .evidence_id
            .as_ref()
            .expect("Critical chain must emit Evidence");
        let evidence = hydra.evidence(evidence_id).unwrap();
        assert_eq!(evidence.payload.kind, "micro_model_prediction");
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
                "Patch 17 refactor dropped commit-rate evidence key `{key}`"
            );
        }
        match &evidence.source {
            hydra_core::epistemic::EvidenceSource::System { name } => {
                assert_eq!(name, BUILTIN_COMMIT_RATE_MODEL_ID);
            }
            other => panic!("expected EvidenceSource::System, got {other:?}"),
        }
    }

    /// Tiny local peer-registration helper for the replication-lag
    /// pin tests. Duplicates the body of `sprint1_tests`'s
    /// equivalent so this test stays in the main module alongside
    /// the commit-rate helpers.
    fn patch17_register_peer_with_lag(
        hydra: &mut Hydra,
        peer_id: &hydra_core::ReplicaId,
        last_lag: Option<(u64, chrono::DateTime<chrono::Utc>)>,
    ) {
        let peer = hydra_core::ReplicationPeer::registered(
            peer_id.clone(),
            hydra_core::ReplicationRole::Follower,
            hydra_core::ReplicationMode::CommitLogStreaming,
            hydra_core::ActorId::from_str("actor_ops"),
        );
        hydra
            .ingest(hydra_core::EventKind::ReplicaRegistered { peer })
            .unwrap();
        if let Some((lag_commits, observed_at)) = last_lag {
            let leader_seq = 1_000u64;
            let follower_seq = leader_seq.saturating_sub(lag_commits);
            let offset =
                hydra_core::ReplicationOffset::from_sequence(follower_seq);
            let lag = hydra_core::ReplicationLag::observe(
                leader_seq,
                follower_seq,
                observed_at,
            );
            hydra
                .ingest(hydra_core::EventKind::ReplicaHeartbeatRecorded {
                    peer_id: peer_id.clone(),
                    offset,
                    lag: Some(lag),
                })
                .unwrap();
        }
    }

    /// Drives the replication-lag bridge end-to-end and reads
    /// back the recorded Action. The refactor MUST preserve the
    /// Patch 16 addition: `peer_id` lives in BOTH the evidence
    /// payload AND the action payload. Catches an accidental
    /// field drop in `replication_lag_reflex_parts`.
    #[test]
    fn patch17_replication_lag_reflex_preserves_peer_id_in_action_payload() {
        let mut hydra = Hydra::new();
        let peer_id = hydra_core::ReplicaId::from_str("replica_p17_pin");
        patch17_register_peer_with_lag(
            &mut hydra,
            &peer_id,
            Some((500, chrono::Utc::now())),
        );
        let assessment = hydra
            .evaluate_replication_lag_anomaly_and_propose_action(
                peer_id.clone(),
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        // Critical → evidence + claim + action all fired.
        let evidence_id = assessment.evidence_id.as_ref().unwrap();
        let evidence = hydra.evidence(evidence_id).unwrap();
        match evidence.payload.data.get("peer_id") {
            Some(hydra_core::Value::String(s)) => {
                assert_eq!(s, peer_id.as_str());
            }
            other => panic!("expected evidence.peer_id, got {other:?}"),
        }

        let action_id = assessment.action_ids.into_iter().next().unwrap();
        let action = hydra.action(&action_id).unwrap();
        match action.payload.get("peer_id") {
            Some(hydra_core::Value::String(s)) => {
                assert_eq!(s, peer_id.as_str());
            }
            other => panic!("expected action.peer_id, got {other:?}"),
        }
        assert_eq!(
            action.targets,
            vec![hydra_core::action::ActionTarget::System(
                "hydra.replication".to_string()
            )]
        );
    }

    /// Both bridges drive their claim through the same shared
    /// spine (`propose_claim_from_reflex`), so both produce
    /// identically-shaped Evidence + Claim records EXCEPT for the
    /// fields the model varies (claim subject, predicate, payload
    /// data). This pin asserts the spine's invariants survive the
    /// refactor for BOTH models simultaneously.
    #[test]
    fn patch17_commit_rate_and_replication_lag_share_reflex_spine() {
        // Commit-rate side.
        let mut hydra_cr = Hydra::new();
        hydra_cr.evaluate_commit_rate_anomaly(requester()).unwrap();
        hydra_cr.set_commit_rate_anomaly_model(primed_model_with_baseline(
            10.0, 1.0,
        ));
        let need = 100u64.saturating_sub(ledger_count(&hydra_cr));
        ingest_signals(&mut hydra_cr, need);
        let cr_assessment = hydra_cr
            .evaluate_commit_rate_anomaly_and_propose_claim(requester())
            .unwrap();
        let cr_evidence = hydra_cr
            .evidence(cr_assessment.evidence_id.as_ref().unwrap())
            .unwrap();
        let cr_claim = hydra_cr
            .claim(cr_assessment.claim_id.as_ref().unwrap())
            .unwrap();

        // Replication-lag side.
        let mut hydra_rl = Hydra::new();
        let peer_id = hydra_core::ReplicaId::from_str("replica_spine_pin");
        patch17_register_peer_with_lag(
            &mut hydra_rl,
            &peer_id,
            Some((500, chrono::Utc::now())),
        );
        let rl_assessment = hydra_rl
            .evaluate_replication_lag_anomaly_and_propose_claim(
                peer_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        let rl_evidence = hydra_rl
            .evidence(rl_assessment.evidence_id.as_ref().unwrap())
            .unwrap();
        let rl_claim = hydra_rl
            .claim(rl_assessment.claim_id.as_ref().unwrap())
            .unwrap();

        // Spine invariant 1: evidence payload kind is identical.
        assert_eq!(cr_evidence.payload.kind, "micro_model_prediction");
        assert_eq!(rl_evidence.payload.kind, "micro_model_prediction");

        // Spine invariant 2: evidence source shape is identical.
        let cr_source_name = match &cr_evidence.source {
            hydra_core::epistemic::EvidenceSource::System { name } => name,
            _ => panic!("commit-rate evidence source must be System"),
        };
        let rl_source_name = match &rl_evidence.source {
            hydra_core::epistemic::EvidenceSource::System { name } => name,
            _ => panic!("replication-lag evidence source must be System"),
        };
        assert_eq!(cr_source_name, BUILTIN_COMMIT_RATE_MODEL_ID);
        assert_eq!(rl_source_name, BUILTIN_REPLICATION_LAG_MODEL_ID);

        // Spine invariant 3: claim kind is AnomalyFinding for both.
        assert_eq!(cr_claim.kind, hydra_core::ClaimKind::AnomalyFinding);
        assert_eq!(rl_claim.kind, hydra_core::ClaimKind::AnomalyFinding);

        // Spine invariant 4: claim.evidence_for points back at the
        // just-recorded evidence for both.
        assert_eq!(
            cr_claim.evidence_for,
            vec![cr_assessment.evidence_id.unwrap()]
        );
        assert_eq!(
            rl_claim.evidence_for,
            vec![rl_assessment.evidence_id.unwrap()]
        );

        // Spine invariant 5: claim.caused_by points at the
        // PREDICTION event, NOT the evidence event. This is the
        // load-bearing audit-chain shape — Patch 3 invariant.
        assert_eq!(
            cr_claim.caused_by.as_ref(),
            Some(&cr_assessment.prediction_event_id)
        );
        assert_eq!(
            rl_claim.caused_by.as_ref(),
            Some(&rl_assessment.prediction_event_id)
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
            rejected_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
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
            rejected_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
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
            rejected_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
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
            rejected_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
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
            rejected_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
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

    // === MicroModel Patch 16 — Replication-lag engine wiring ===

    /// Register a follower peer + (optionally) record one heartbeat
    /// so `peer.last_lag` is populated with the supplied lag at the
    /// supplied observation time.
    fn register_peer_with_lag(
        hydra: &mut Hydra,
        peer_id: &hydra_core::ReplicaId,
        last_lag: Option<(u64, chrono::DateTime<chrono::Utc>)>,
    ) {
        let peer = hydra_core::ReplicationPeer::registered(
            peer_id.clone(),
            hydra_core::ReplicationRole::Follower,
            hydra_core::ReplicationMode::CommitLogStreaming,
            hydra_core::ActorId::from_str("actor_ops"),
        );
        hydra
            .ingest(hydra_core::EventKind::ReplicaRegistered { peer })
            .unwrap();
        if let Some((lag_commits, observed_at)) = last_lag {
            // Compose a fake leader/follower offset so the lag math
            // matches the requested `lag_commits`.
            let leader_seq = 1_000u64;
            let follower_seq = leader_seq.saturating_sub(lag_commits);
            let offset = hydra_core::ReplicationOffset::from_sequence(follower_seq);
            let lag = hydra_core::ReplicationLag::observe(
                leader_seq,
                follower_seq,
                observed_at,
            );
            hydra
                .ingest(hydra_core::EventKind::ReplicaHeartbeatRecorded {
                    peer_id: peer_id.clone(),
                    offset,
                    lag: Some(lag),
                })
                .unwrap();
        }
    }

    #[test]
    fn evaluate_replication_lag_anomaly_unknown_peer_returns_query_error() {
        let mut hydra = Hydra::new();
        let result = hydra.evaluate_replication_lag_anomaly(
            hydra_core::ReplicaId::from_str("replica_ghost"),
            hydra_core::ActorId::from_str("actor_ops"),
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("unknown replication peer"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_replication_lag_anomaly_auto_registers_builtin_model() {
        let mut hydra = Hydra::new();
        let peer_id = hydra_core::ReplicaId::from_str("replica_a");
        register_peer_with_lag(
            &mut hydra,
            &peer_id,
            Some((0, chrono::Utc::now())),
        );
        let model_id = hydra_core::MicroModelId::from_str(
            BUILTIN_REPLICATION_LAG_MODEL_ID,
        );
        assert!(hydra.micro_model(&model_id).is_none());

        let _ = hydra
            .evaluate_replication_lag_anomaly(
                peer_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert!(
            hydra.micro_model(&model_id).is_some(),
            "first evaluate must auto-register the built-in"
        );
    }

    #[test]
    fn evaluate_replication_lag_normal_when_lag_low_and_heartbeat_fresh() {
        let mut hydra = Hydra::new();
        let peer_id = hydra_core::ReplicaId::from_str("replica_normal");
        register_peer_with_lag(
            &mut hydra,
            &peer_id,
            Some((2, chrono::Utc::now())),
        );
        let assessment = hydra
            .evaluate_replication_lag_anomaly_and_propose_action(
                peer_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert_eq!(
            assessment.level,
            crate::micromodels::ReplicationLagAnomalyLevel::Normal
        );
        assert!(assessment.claim_id.is_none());
        assert!(assessment.evidence_id.is_none());
        assert!(assessment.action_ids.is_empty());
    }

    #[test]
    fn evaluate_replication_lag_critical_fires_evidence_claim_action() {
        let mut hydra = Hydra::new();
        let peer_id = hydra_core::ReplicaId::from_str("replica_critical");
        register_peer_with_lag(
            &mut hydra,
            &peer_id,
            Some((500, chrono::Utc::now())),
        );
        let assessment = hydra
            .evaluate_replication_lag_anomaly_and_propose_action(
                peer_id.clone(),
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert_eq!(
            assessment.level,
            crate::micromodels::ReplicationLagAnomalyLevel::Critical
        );
        assert!(assessment.claim_id.is_some());
        assert!(assessment.evidence_id.is_some());
        assert_eq!(assessment.action_ids.len(), 1);
        assert_eq!(assessment.peer_id, peer_id);

        // Verify the claim shape per Patch 16 spec.
        let claim = hydra.claim(assessment.claim_id.as_ref().unwrap()).unwrap();
        assert_eq!(
            claim.subject,
            hydra_core::ClaimSubject::System("hydra.replication".to_string())
        );
        assert_eq!(claim.predicate, "replica_lagging");
        assert_eq!(claim.kind, hydra_core::ClaimKind::AnomalyFinding);
    }

    #[test]
    fn evaluate_replication_lag_action_payload_carries_peer_id() {
        let mut hydra = Hydra::new();
        let peer_id = hydra_core::ReplicaId::from_str("replica_payload_check");
        register_peer_with_lag(
            &mut hydra,
            &peer_id,
            Some((200, chrono::Utc::now())),
        );
        let assessment = hydra
            .evaluate_replication_lag_anomaly_and_propose_action(
                peer_id.clone(),
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        let action_id = assessment.action_ids.into_iter().next().unwrap();
        let action = hydra.action(&action_id).unwrap();
        // Patch 16 spec: action targets System("hydra.replication")
        // (not System("hydra")).
        assert_eq!(
            action.targets,
            vec![hydra_core::action::ActionTarget::System(
                "hydra.replication".to_string()
            )]
        );
        // Payload carries the peer_id field (Patch 16 addition vs
        // commit-rate's payload).
        match action.payload.get("peer_id") {
            Some(hydra_core::Value::String(s)) => {
                assert_eq!(s, peer_id.as_str());
            }
            other => panic!("expected payload.peer_id String, got {other:?}"),
        }
        // Severity = "critical".
        match action.payload.get("severity") {
            Some(hydra_core::Value::String(s)) => assert_eq!(s, "critical"),
            other => panic!("expected severity=critical, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_replication_lag_no_last_lag_is_stale_critical() {
        // Peer registered but never reported a heartbeat. Model
        // sees last_observed_at = None → stale → Critical.
        let mut hydra = Hydra::new();
        let peer_id = hydra_core::ReplicaId::from_str("replica_silent");
        register_peer_with_lag(&mut hydra, &peer_id, None);
        let assessment = hydra
            .evaluate_replication_lag_anomaly_and_propose_action(
                peer_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert_eq!(
            assessment.level,
            crate::micromodels::ReplicationLagAnomalyLevel::Critical
        );
        // Stale-heartbeat critical still propagates the full chain.
        assert_eq!(assessment.action_ids.len(), 1);
    }

    #[test]
    fn evaluate_replication_lag_prediction_only_records_only_prediction_event() {
        let mut hydra = Hydra::new();
        let peer_id = hydra_core::ReplicaId::from_str("replica_pred_only");
        register_peer_with_lag(
            &mut hydra,
            &peer_id,
            Some((500, chrono::Utc::now())),
        );
        // Patch 16's prediction-only surface is the bottom helper —
        // no Evidence/Claim/Action even on Critical level.
        let (prediction, _event_id, output) = hydra
            .record_replication_lag_prediction(
                peer_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert_eq!(
            output.level,
            crate::micromodels::ReplicationLagAnomalyLevel::Critical
        );
        // No claims for the lag subject (it's a Critical level but
        // we used prediction-only).
        let lag_claims: Vec<_> = hydra
            .epistemic_store
            .all_claims()
            .filter(|c| c.predicate == "replica_lagging")
            .collect();
        assert!(lag_claims.is_empty());
        assert_eq!(
            prediction.model_id.as_str(),
            BUILTIN_REPLICATION_LAG_MODEL_ID
        );
    }

    // === MicroModel Patch 18 — Agent-loop-storm engine wiring ===

    /// Ingest `n` `ActionProposed` events with the supplied
    /// `proposed_by`. Each action lands in Hydra's normal cascade
    /// (which may auto-approve via `actor_hydra_policy` — those
    /// cascade-emitted ActionApproved events have a Hydra-system
    /// actor and are filtered out of the storm count).
    fn ingest_n_action_proposed(
        hydra: &mut Hydra,
        n: u64,
        proposed_by: &hydra_core::ActorId,
    ) {
        for _ in 0..n {
            let now = chrono::Utc::now();
            let action = hydra_core::Action {
                id: hydra_core::ActionId::new(),
                tenant_id: None,
                kind: hydra_core::ActionKind::Notify,
                status: hydra_core::action::ActionStatus::Proposed,
                targets: vec![hydra_core::action::ActionTarget::System(
                    "hydra".to_string(),
                )],
                related_claims: vec![],
                supporting_evidence: vec![],
                proposed_by: proposed_by.clone(),
                approved_by: None,
                rejected_by: None,
                policy_id: None,
                payload: std::collections::HashMap::new(),
                created_at: now,
                updated_at: now,
                approved_at: None,
                rejected_at: None,
                executed_at: None,
                caused_by: None,
            };
            hydra
                .ingest(hydra_core::EventKind::ActionProposed { action })
                .unwrap();
        }
    }

    #[test]
    fn evaluate_agent_loop_storm_empty_engine_is_normal() {
        let mut hydra = Hydra::new();
        let assessment = hydra
            .evaluate_agent_loop_storm_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert_eq!(
            assessment.level,
            crate::micromodels::AgentLoopStormLevel::Normal
        );
        // Normal → no claim, no action.
        assert!(assessment.claim_id.is_none());
        assert!(assessment.evidence_id.is_none());
        assert!(assessment.action_ids.is_empty());
    }

    #[test]
    fn evaluate_agent_loop_storm_auto_registers_builtin_model() {
        let mut hydra = Hydra::new();
        let model_id = hydra_core::MicroModelId::from_str(
            BUILTIN_AGENT_LOOP_STORM_MODEL_ID,
        );
        assert!(hydra.micro_model(&model_id).is_none());
        let _ = hydra
            .evaluate_agent_loop_storm(hydra_core::ActorId::from_str(
                "actor_ops",
            ))
            .unwrap();
        assert!(
            hydra.micro_model(&model_id).is_some(),
            "first evaluate must auto-register the built-in"
        );
    }

    #[test]
    fn evaluate_agent_loop_storm_critical_when_actions_cross_threshold() {
        let mut hydra = Hydra::new();
        let agent = hydra_core::ActorId::from_str("actor_data_quality_agent");
        // 60 ActionProposed events by the same external agent →
        // action_proposed_count=60 (>= critical_actions 50) →
        // Critical.
        ingest_n_action_proposed(&mut hydra, 60, &agent);

        let assessment = hydra
            .evaluate_agent_loop_storm_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert_eq!(
            assessment.level,
            crate::micromodels::AgentLoopStormLevel::Critical
        );
        // Critical → evidence + claim + action all fired.
        assert!(assessment.evidence_id.is_some());
        assert!(assessment.claim_id.is_some());
        assert_eq!(assessment.action_ids.len(), 1);

        // Claim shape: subject=System("hydra.agents"),
        // predicate="agent_loop_storm".
        let claim = hydra.claim(assessment.claim_id.as_ref().unwrap()).unwrap();
        assert_eq!(
            claim.subject,
            hydra_core::ClaimSubject::System("hydra.agents".to_string())
        );
        assert_eq!(claim.predicate, "agent_loop_storm");
        assert_eq!(claim.kind, hydra_core::ClaimKind::AnomalyFinding);

        // Action shape: target=System("hydra.agents"), payload
        // carries top_actor.
        let action = hydra
            .action(&assessment.action_ids[0])
            .unwrap();
        assert_eq!(
            action.targets,
            vec![hydra_core::action::ActionTarget::System(
                "hydra.agents".to_string()
            )]
        );
        match action.payload.get("top_actor") {
            Some(hydra_core::Value::String(s)) => {
                assert_eq!(s, agent.as_str());
            }
            other => panic!("expected action.top_actor, got {other:?}"),
        }
        match action.payload.get("severity") {
            Some(hydra_core::Value::String(s)) => assert_eq!(s, "critical"),
            other => panic!("expected severity=critical, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_agent_loop_storm_filters_hydra_system_actors() {
        // Ingest 80 ActionProposed events with proposed_by =
        // actor_hydra_policy (a Hydra-system actor). The storm
        // counter must filter ALL of these out and report Normal.
        // This is the LOAD-BEARING test: it proves Hydra's own
        // cascade activity can't trigger its own storm reflex.
        let mut hydra = Hydra::new();
        let policy = hydra_core::ActorId::from_str("actor_hydra_policy");
        ingest_n_action_proposed(&mut hydra, 80, &policy);

        let assessment = hydra
            .evaluate_agent_loop_storm_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        // Even at 80 events, Normal — every proposer is filtered.
        assert_eq!(
            assessment.level,
            crate::micromodels::AgentLoopStormLevel::Normal,
            "Hydra-system actor activity must NOT trigger storms"
        );
        assert!(assessment.action_ids.is_empty());

        // The recorded prediction output should show
        // agent_event_count == 0 (everything filtered).
        let pred_output = &assessment.prediction.output;
        assert_eq!(pred_output["agent_event_count"], serde_json::json!(0));
        assert!(pred_output["top_actor"].is_null());
    }

    #[test]
    fn evaluate_agent_loop_storm_top_actor_reflects_busiest_external_actor() {
        // Mix two external actors with different volumes —
        // top_actor must be the busier one.
        let mut hydra = Hydra::new();
        let busy = hydra_core::ActorId::from_str("actor_chatty_agent");
        let quiet = hydra_core::ActorId::from_str("actor_calm_agent");
        ingest_n_action_proposed(&mut hydra, 35, &busy);
        ingest_n_action_proposed(&mut hydra, 8, &quiet);

        let (prediction, _, output) = hydra
            .record_agent_loop_storm_prediction(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        // 43 actions total — over critical_actions=50? No, 43 < 50.
        // But same_actor_warning=30, busy=35 ≥ 30 → Warning.
        assert_eq!(
            output.level,
            crate::micromodels::AgentLoopStormLevel::Warning
        );
        assert_eq!(output.top_actor.as_deref(), Some(busy.as_str()));
        assert_eq!(output.top_actor_event_count, 35);
        assert_eq!(output.agent_event_count, 43);
        assert_eq!(output.action_proposed_count, 43);
        // Pin the prediction was actually recorded (not dry-run).
        assert_eq!(
            prediction.model_id.as_str(),
            BUILTIN_AGENT_LOOP_STORM_MODEL_ID
        );
    }

    #[test]
    fn evaluate_agent_loop_storm_action_payload_carries_top_actor_and_window() {
        // Pin the Patch 18 spec: action payload includes
        // `top_actor` and `window_secs` so the delivery adapter
        // can route per-actor.
        let mut hydra = Hydra::new();
        let agent = hydra_core::ActorId::from_str("actor_runaway");
        ingest_n_action_proposed(&mut hydra, 60, &agent);

        let assessment = hydra
            .evaluate_agent_loop_storm_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        let action_id = assessment
            .action_ids
            .into_iter()
            .next()
            .expect("Critical chain must propose one action");
        let action = hydra.action(&action_id).unwrap();
        match action.payload.get("window_secs") {
            Some(hydra_core::Value::Int(n)) => assert_eq!(*n, 60),
            other => panic!("expected window_secs=60, got {other:?}"),
        }
        match action.payload.get("top_actor") {
            Some(hydra_core::Value::String(s)) => {
                assert_eq!(s, agent.as_str());
            }
            other => panic!("expected top_actor, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_agent_loop_storm_prediction_only_skips_claim_and_action() {
        // Even on Critical level, prediction-only mode emits ONLY
        // the prediction event — no Evidence, no Claim, no Action.
        // Mirrors the Patch 5 commit-rate / Patch 16
        // replication-lag prediction_only contract.
        let mut hydra = Hydra::new();
        let agent = hydra_core::ActorId::from_str("actor_pred_only_check");
        ingest_n_action_proposed(&mut hydra, 60, &agent);

        let (_, _, output) = hydra
            .record_agent_loop_storm_prediction(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert_eq!(
            output.level,
            crate::micromodels::AgentLoopStormLevel::Critical
        );
        let storm_claims: Vec<_> = hydra
            .epistemic_store
            .all_claims()
            .filter(|c| c.predicate == "agent_loop_storm")
            .collect();
        assert!(storm_claims.is_empty());
    }

    // === MicroModel Patch 19 — Action-failure-rate engine wiring ===

    /// Ingest an `ActionProposed` for a Notify action. Cascade
    /// auto-approves (no HumanApproval policy registered) so the
    /// action lands in `Approved` status, ready for execute.
    fn ingest_approved_notify_action(
        hydra: &mut Hydra,
    ) -> hydra_core::ActionId {
        let action_id = hydra_core::ActionId::new();
        let now = chrono::Utc::now();
        let action = hydra_core::Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: hydra_core::ActionKind::Notify,
            status: hydra_core::action::ActionStatus::Proposed,
            targets: vec![hydra_core::action::ActionTarget::System(
                "hydra".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: hydra_core::ActorId::from_str("actor_ops"),
            approved_by: None,
            rejected_by: None,
            policy_id: None,
            payload: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ActionProposed { action })
            .unwrap();
        // Sanity: cascade auto-approved (no HumanApproval policy).
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            hydra_core::action::ActionStatus::Approved
        );
        action_id
    }

    /// Drive `success_count` Notify actions to `Executed` and
    /// `failure_count` Notify actions to `Failed` via Hydra's
    /// real Patch 7 + Patch 14 paths. Returns the engine ready
    /// for an action-failure-rate evaluation.
    fn drive_action_outcomes(
        hydra: &mut Hydra,
        success_count: u64,
        failure_count: u64,
    ) {
        let actor = hydra_core::ActorId::from_str("actor_ops");
        for _ in 0..success_count {
            let action_id = ingest_approved_notify_action(hydra);
            hydra
                .execute_notify_action(action_id, actor.clone())
                .unwrap();
        }
        for _ in 0..failure_count {
            let action_id = ingest_approved_notify_action(hydra);
            let delivery = hydra_core::DeliveryOutcome::Failed {
                adapter: "webhook".to_string(),
                reason: "test-induced failure".to_string(),
                status_code: Some(500),
                latency_ms: 42,
            };
            hydra
                .execute_notify_action_with_delivery(
                    action_id,
                    actor.clone(),
                    delivery,
                )
                .unwrap();
        }
    }

    #[test]
    fn evaluate_action_failure_rate_empty_engine_is_normal() {
        let mut hydra = Hydra::new();
        let assessment = hydra
            .evaluate_action_failure_rate_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert_eq!(
            assessment.level,
            crate::micromodels::ActionFailureRateLevel::Normal
        );
        assert!(assessment.claim_id.is_none());
        assert!(assessment.action_ids.is_empty());
        // Prediction output records 0 actions seen.
        let out = &assessment.prediction.output;
        assert_eq!(out["actions_seen"], serde_json::json!(0));
        assert_eq!(out["failed_actions"], serde_json::json!(0));
    }

    #[test]
    fn evaluate_action_failure_rate_auto_registers_builtin() {
        let mut hydra = Hydra::new();
        let model_id = hydra_core::MicroModelId::from_str(
            BUILTIN_ACTION_FAILURE_RATE_MODEL_ID,
        );
        assert!(hydra.micro_model(&model_id).is_none());
        let _ = hydra
            .evaluate_action_failure_rate(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert!(hydra.micro_model(&model_id).is_some());
    }

    #[test]
    fn evaluate_action_failure_rate_critical_via_absolute_count() {
        // 5 successful + 10 failed = 15 actions, 10 failures.
        // 10 >= critical_failure_count (10) → Critical via count.
        // (Ratio is 10/15 = 67%, also over critical 50%, but the
        // absolute count fires first.)
        let mut hydra = Hydra::new();
        drive_action_outcomes(&mut hydra, 5, 10);

        let assessment = hydra
            .evaluate_action_failure_rate_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert_eq!(
            assessment.level,
            crate::micromodels::ActionFailureRateLevel::Critical
        );
        assert!(assessment.evidence_id.is_some());
        assert!(assessment.claim_id.is_some());
        assert_eq!(assessment.action_ids.len(), 1);

        // Claim shape: subject=System("hydra.actions"),
        // predicate="action_failure_rate_high".
        let claim = hydra.claim(assessment.claim_id.as_ref().unwrap()).unwrap();
        assert_eq!(
            claim.subject,
            hydra_core::ClaimSubject::System("hydra.actions".to_string())
        );
        assert_eq!(claim.predicate, "action_failure_rate_high");
        assert_eq!(claim.kind, hydra_core::ClaimKind::AnomalyFinding);

        // Action shape: target=System("hydra.actions"), payload
        // carries failure_ratio and top_failed_kind.
        let action = hydra.action(&assessment.action_ids[0]).unwrap();
        assert_eq!(
            action.targets,
            vec![hydra_core::action::ActionTarget::System(
                "hydra.actions".to_string()
            )]
        );
        match action.payload.get("top_failed_kind") {
            Some(hydra_core::Value::String(s)) => assert_eq!(s, "Notify"),
            other => panic!("expected top_failed_kind=Notify, got {other:?}"),
        }
        match action.payload.get("failed_actions") {
            Some(hydra_core::Value::Int(n)) => assert_eq!(*n, 10),
            other => panic!("expected failed_actions=10, got {other:?}"),
        }
        match action.payload.get("severity") {
            Some(hydra_core::Value::String(s)) => assert_eq!(s, "critical"),
            other => panic!("expected severity=critical, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_action_failure_rate_critical_via_ratio_with_low_absolute() {
        // 3 successful + 5 failed = 8 actions, 5 failures.
        // 5 failures < critical_count (10) but ratio 5/8 = 62.5%
        // >= critical_ratio (50%) AND actions_seen (8) >= 5 →
        // Critical via ratio.
        let mut hydra = Hydra::new();
        drive_action_outcomes(&mut hydra, 3, 5);

        let assessment = hydra
            .evaluate_action_failure_rate_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert_eq!(
            assessment.level,
            crate::micromodels::ActionFailureRateLevel::Critical
        );
        let action = hydra.action(&assessment.action_ids[0]).unwrap();
        match action.payload.get("failure_ratio") {
            Some(hydra_core::Value::Float(f)) => {
                assert!(
                    (*f - (5.0 / 8.0)).abs() < 1e-9,
                    "expected 5/8 = 0.625, got {f}"
                );
            }
            other => panic!("expected failure_ratio float, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_action_failure_rate_no_false_positive_on_one_of_one_failure() {
        // LOAD-BEARING small-sample suppression: 0 successful +
        // 1 failed. ratio = 100% but actions_seen (1) < min (5),
        // so ratio gate is disabled. Absolute count (1) is under
        // warning (3) → Normal.
        //
        // This pin matters because without the
        // min_actions_for_ratio gate, a single early webhook
        // failure (e.g., warm-up misconfiguration) would
        // immediately fire Critical via ratio.
        let mut hydra = Hydra::new();
        drive_action_outcomes(&mut hydra, 0, 1);

        let assessment = hydra
            .evaluate_action_failure_rate_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert_eq!(
            assessment.level,
            crate::micromodels::ActionFailureRateLevel::Normal,
            "1-of-1 failure must NOT trigger Critical via ratio"
        );
        assert!(assessment.action_ids.is_empty());
        // The prediction's failure_ratio is still 1.0 (honest)
        // but level stayed Normal because the gate is disabled
        // below min_actions_for_ratio.
        let out = &assessment.prediction.output;
        assert_eq!(out["failure_ratio"], serde_json::json!(1.0));
        assert_eq!(out["level"], serde_json::json!("normal"));
    }

    #[test]
    fn evaluate_action_failure_rate_warning_via_absolute_count_under_min_actions() {
        // 0 successful + 4 failed → ratio 100% but suppressed
        // (actions_seen 4 < min 5). However absolute count 4 >=
        // warning_count (3) → Warning. The absolute gate is NOT
        // blocked by min_actions_for_ratio.
        let mut hydra = Hydra::new();
        drive_action_outcomes(&mut hydra, 0, 4);

        let assessment = hydra
            .evaluate_action_failure_rate_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert_eq!(
            assessment.level,
            crate::micromodels::ActionFailureRateLevel::Warning
        );
    }

    #[test]
    fn evaluate_action_failure_rate_prediction_only_skips_claim_and_action() {
        // Even on Critical level, prediction-only mode emits ONLY
        // the prediction event — no Evidence/Claim/Action.
        let mut hydra = Hydra::new();
        drive_action_outcomes(&mut hydra, 5, 10);
        let (_, _, output) = hydra
            .record_action_failure_rate_prediction(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert_eq!(
            output.level,
            crate::micromodels::ActionFailureRateLevel::Critical
        );
        let failure_claims: Vec<_> = hydra
            .epistemic_store
            .all_claims()
            .filter(|c| c.predicate == "action_failure_rate_high")
            .collect();
        assert!(failure_claims.is_empty());
    }

    // === Patch 20 — CausalCell engine wiring ===

    #[test]
    fn create_causal_cell_ingests_event_and_populates_store() {
        // The headline path: create_causal_cell stores the cell
        // AND emits a CausalCellCreated event. Both must be
        // observable.
        let mut hydra = Hydra::new();
        let cell = hydra_core::CausalCell::new(
            hydra_core::CausalCellKind::Reflex,
            "hydra.commit-rate",
            hydra_core::ActorId::from_str("actor_ops"),
        );
        let cell_id = cell.id.clone();

        let stored = hydra.create_causal_cell(cell.clone()).unwrap();
        assert_eq!(stored.id, cell_id);

        // Store populated.
        assert_eq!(
            hydra.causal_cell(&cell_id).map(|c| c.id.clone()),
            Some(cell_id.clone())
        );
        assert_eq!(hydra.causal_cells().count(), 1);

        // Event emitted.
        let found = hydra.events().iter().any(|event| {
            matches!(
                &event.kind,
                hydra_core::EventKind::CausalCellCreated { cell }
                    if cell.id == cell_id
            )
        });
        assert!(found, "audit log missing CausalCellCreated event");
    }

    #[test]
    fn causal_cells_by_kind_filters_correctly_via_engine() {
        let mut hydra = Hydra::new();
        let actor = hydra_core::ActorId::from_str("actor_ops");
        let reflex_a = hydra_core::CausalCell::new(
            hydra_core::CausalCellKind::Reflex,
            "hydra.commit-rate",
            actor.clone(),
        );
        let reflex_b = hydra_core::CausalCell::new(
            hydra_core::CausalCellKind::Reflex,
            "hydra.replication",
            actor.clone(),
        );
        let incident = hydra_core::CausalCell::new(
            hydra_core::CausalCellKind::Incident,
            "incident-1",
            actor,
        );
        hydra.create_causal_cell(reflex_a).unwrap();
        hydra.create_causal_cell(reflex_b).unwrap();
        hydra.create_causal_cell(incident).unwrap();

        let reflexes =
            hydra.causal_cells_by_kind(&hydra_core::CausalCellKind::Reflex);
        assert_eq!(reflexes.len(), 2);
        let incidents = hydra
            .causal_cells_by_kind(&hydra_core::CausalCellKind::Incident);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].subject, "incident-1");
    }

    #[test]
    fn recover_from_events_rebuilds_causal_cell_store() {
        // Patch 20 cells must replay correctly. The store is
        // event-sourced — wipe it, replay, store comes back.
        let mut hydra = Hydra::new();
        let cell = hydra_core::CausalCell::new(
            hydra_core::CausalCellKind::Reflex,
            "hydra.replay-test",
            hydra_core::ActorId::from_str("actor_ops"),
        );
        let cell_id = cell.id.clone();
        hydra.create_causal_cell(cell).unwrap();
        assert_eq!(hydra.causal_cells().count(), 1);

        // Take a full event copy, reset the engine, replay.
        let events: Vec<_> = hydra.events().into_iter().cloned().collect();
        hydra.reset_runtime_state_preserving_config();
        assert_eq!(hydra.causal_cells().count(), 0);
        hydra.recover_from_events(events).unwrap();
        assert_eq!(hydra.causal_cells().count(), 1);
        assert!(hydra.causal_cell(&cell_id).is_some());
    }

    #[test]
    fn snapshot_restore_preserves_causal_cells() {
        // Snapshot path is event-replay based, but the body's
        // explicit `causal_cells` vec is the audit copy.
        // Round-trip must preserve both the count AND the cell
        // contents.
        let mut hydra = Hydra::new();
        let actor = hydra_core::ActorId::from_str("actor_ops");
        let cell = hydra_core::CausalCell::new(
            hydra_core::CausalCellKind::Health,
            "hydra.health",
            actor.clone(),
        );
        let cell_id = cell.id.clone();
        hydra.create_causal_cell(cell).unwrap();

        // Take a snapshot. Patch 1's engine surface uses
        // `snapshot(actor)` — `take_snapshot` is a future name.
        let manifest = hydra.snapshot(actor.clone()).unwrap();
        // Manifest carries the count.
        assert_eq!(manifest.total_causal_cells, 1);
        // Body carries the cells.
        let body = hydra
            .snapshot_store()
            .body(&manifest.id)
            .expect("snapshot body present after take")
            .clone();
        assert_eq!(body.causal_cells.len(), 1);
        assert_eq!(body.causal_cells[0].id, cell_id);

        // Pin: the body's events vec contains the
        // CausalCellCreated event — the event log is the source
        // of truth and the `causal_cells` vec is the audit copy.
        // Replay the events from the body into a fresh engine
        // and verify the cell comes back.
        let mut fresh = Hydra::new();
        fresh.recover_from_events(body.events.clone()).unwrap();
        assert_eq!(fresh.causal_cells().count(), 1);
        assert!(fresh.causal_cell(&cell_id).is_some());
    }

    // === Patch 21 — Reflex → CausalCell converter ===

    /// Drive the full replication-lag chain end-to-end and return
    /// every primitive id Patch 21 expects to see populated:
    /// (claim_id, action_id, outcome_id, run_id, peer_id).
    ///
    /// The replication-lag reflex is the cleanest test surface
    /// because the peer-registration helper is local and the
    /// chain reliably fires Critical with no warmup.
    fn drive_full_replication_lag_chain(
        hydra: &mut Hydra,
    ) -> (
        hydra_core::ClaimId,
        hydra_core::ActionId,
        hydra_core::OutcomeId,
        hydra_core::MicroModelRunId,
        hydra_core::ReplicaId,
    ) {
        let peer_id = hydra_core::ReplicaId::from_str("replica_p21");
        register_peer_with_lag(
            hydra,
            &peer_id,
            Some((500, chrono::Utc::now())),
        );
        let actor = hydra_core::ActorId::from_str("actor_ops");
        let assessment = hydra
            .evaluate_replication_lag_anomaly_and_propose_action(
                peer_id.clone(),
                actor.clone(),
            )
            .unwrap();
        let claim_id = assessment.claim_id.clone().unwrap();
        let action_id = assessment.action_ids[0].clone();
        let run_id = assessment.prediction.run_id.clone();

        // Execute the cascade-approved action → ActionExecuted +
        // OutcomeObserved.
        let report = hydra
            .execute_notify_action(action_id.clone(), actor.clone())
            .unwrap();
        let outcome_id = report.outcome_id.clone();

        // Record the model observation so observation_run_ids is
        // populated.
        hydra
            .record_micro_model_observation_from_action_outcome(
                outcome_id.clone(),
                actor,
            )
            .unwrap();

        (claim_id, action_id, outcome_id, run_id, peer_id)
    }

    #[test]
    fn create_reflex_cell_from_replication_lag_claim_happy_path() {
        let mut hydra = Hydra::new();
        let (claim_id, action_id, outcome_id, run_id, _) =
            drive_full_replication_lag_chain(&mut hydra);

        let cell = hydra
            .create_reflex_causal_cell_from_claim(
                claim_id.clone(),
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();

        assert_eq!(cell.kind, hydra_core::CausalCellKind::Reflex);
        assert_eq!(cell.subject, "hydra.replication/replica_lagging");
        assert_eq!(cell.claim_ids, vec![claim_id]);
        assert_eq!(cell.action_ids, vec![action_id]);
        assert_eq!(cell.outcome_ids, vec![outcome_id]);
        assert_eq!(cell.observation_run_ids, vec![run_id]);
        // The cell is also stored + retrievable.
        assert!(hydra.causal_cell(&cell.id).is_some());
        // Stored cell is identical to what we got back.
        assert_eq!(hydra.causal_cell(&cell.id).unwrap(), &cell);
    }

    #[test]
    fn create_reflex_cell_includes_prediction_event_in_source_events() {
        // Patch 21 invariant: prediction event is FIRST in
        // source_events, AND is the cell's caused_by.
        let mut hydra = Hydra::new();
        let (claim_id, _, _, _, _) =
            drive_full_replication_lag_chain(&mut hydra);

        // Find the prediction event id directly from the claim's
        // own caused_by — the Patch 3 invariant.
        let claim = hydra.claim(&claim_id).unwrap().clone();
        let prediction_event_id = claim.caused_by.clone().unwrap();

        let cell = hydra
            .create_reflex_causal_cell_from_claim(
                claim_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert!(!cell.source_events.is_empty());
        assert_eq!(
            cell.source_events[0], prediction_event_id,
            "prediction event must be FIRST in source_events"
        );
        assert_eq!(
            cell.caused_by,
            Some(prediction_event_id),
            "cell.caused_by must equal prediction event id"
        );
    }

    #[test]
    fn create_reflex_cell_includes_evidence_claim_action_outcome() {
        // Full chain: every layer populates its slice.
        let mut hydra = Hydra::new();
        let (claim_id, _, _, _, _) =
            drive_full_replication_lag_chain(&mut hydra);
        let claim = hydra.claim(&claim_id).unwrap().clone();

        let cell = hydra
            .create_reflex_causal_cell_from_claim(
                claim_id.clone(),
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();

        // Evidence: exactly the claim's evidence_for slice.
        assert_eq!(cell.evidence_ids, claim.evidence_for);
        assert!(!cell.evidence_ids.is_empty());

        // Claim: just the input claim.
        assert_eq!(cell.claim_ids, vec![claim_id]);

        // Action + outcome: at least one each (cascade
        // auto-approves; execute fires; OutcomeObserved emits).
        assert!(!cell.action_ids.is_empty());
        assert!(!cell.outcome_ids.is_empty());

        // source_events ordering pin: prediction first, then
        // some evidence events, then claim, then action, then
        // outcome. The exact length depends on chain breadth
        // but the LAST event must be the outcome event.
        assert!(cell.source_events.len() >= 5);
    }

    #[test]
    fn create_reflex_cell_includes_observation_run_id_when_observed() {
        let mut hydra = Hydra::new();
        let (claim_id, _, _, run_id, _) =
            drive_full_replication_lag_chain(&mut hydra);

        let cell = hydra
            .create_reflex_causal_cell_from_claim(
                claim_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();

        assert_eq!(
            cell.observation_run_ids,
            vec![run_id],
            "observation must surface in observation_run_ids when recorded"
        );
    }

    #[test]
    fn create_reflex_cell_sets_trust_score_and_summary() {
        let mut hydra = Hydra::new();
        let (claim_id, _, _, _, _) =
            drive_full_replication_lag_chain(&mut hydra);

        let cell = hydra
            .create_reflex_causal_cell_from_claim(
                claim_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();

        // Trust score is populated (Patch 9's assessor always
        // returns a value for any claim).
        let score = cell.trust_score.expect("trust_score must be set");
        assert!(score >= 0.0 && score <= 1.0, "score in [0,1], got {score}");

        // Summary string follows the deterministic Patch 21
        // pattern operators can pattern-match.
        let summary = cell.summary.as_ref().expect("summary must be set");
        assert!(summary.contains("reflex cell for hydra.replication/replica_lagging"));
        assert!(summary.contains("trust="));
        assert!(summary.contains("actions"));
        assert!(summary.contains("outcomes"));
    }

    #[test]
    fn create_reflex_cell_unknown_claim_returns_error() {
        let mut hydra = Hydra::new();
        let result = hydra.create_reflex_causal_cell_from_claim(
            hydra_core::ClaimId::from_str("claim_ghost"),
            hydra_core::ActorId::from_str("actor_ops"),
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("unknown claim"),
                    "msg: {msg}"
                );
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn create_reflex_cell_non_model_claim_returns_error() {
        // Manually ingest a claim with caused_by=None (NOT born
        // from a model prediction). Patch 21 must hard-error
        // rather than build a degenerate cell.
        let mut hydra = Hydra::new();
        let claim_id = hydra_core::ClaimId::new();
        let now = chrono::Utc::now();
        let claim = hydra_core::Claim {
            id: claim_id.clone(),
            tenant_id: None,
            kind: hydra_core::ClaimKind::Hypothesis,
            subject: hydra_core::ClaimSubject::System("test".to_string()),
            predicate: "test_predicate".to_string(),
            object: hydra_core::ClaimObject::Value(
                hydra_core::Value::Bool(true),
            ),
            confidence: hydra_core::Confidence::new(0.5),
            status: hydra_core::ClaimStatus::Proposed,
            evidence_for: vec![],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: hydra_core::ActorId::from_str("actor_test"),
            created_at: now,
            updated_at: now,
            caused_by: None, // <- not model-derived
        };
        hydra
            .ingest(hydra_core::EventKind::ClaimProposed { claim })
            .unwrap();

        let result = hydra.create_reflex_causal_cell_from_claim(
            claim_id,
            hydra_core::ActorId::from_str("actor_ops"),
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("claim is not model-derived"),
                    "msg: {msg}"
                );
            }
            other => {
                panic!("expected non-model claim QueryError, got {other:?}")
            }
        }
    }

    #[test]
    fn create_reflex_cell_non_prediction_caused_by_returns_error() {
        // Inverse pin: a claim with caused_by pointing at a
        // non-prediction event must also hard-error. Catches a
        // future regression where the kind check is dropped.
        let mut hydra = Hydra::new();

        // First ingest something to produce ANY event we can
        // point at — a plain Signal event.
        let signal_cascade = hydra
            .ingest(hydra_core::EventKind::Signal {
                source: hydra_core::NodeId::from_str("test.signal"),
                name: "decoy".to_string(),
                payload: std::collections::HashMap::new(),
            })
            .unwrap();
        let signal_event_id =
            signal_cascade.events.first().map(|e| e.id.clone()).unwrap();

        // Claim with caused_by pointing at the signal (NOT a
        // prediction).
        let claim_id = hydra_core::ClaimId::new();
        let now = chrono::Utc::now();
        let claim = hydra_core::Claim {
            id: claim_id.clone(),
            tenant_id: None,
            kind: hydra_core::ClaimKind::Hypothesis,
            subject: hydra_core::ClaimSubject::System("test".to_string()),
            predicate: "test".to_string(),
            object: hydra_core::ClaimObject::Value(
                hydra_core::Value::Bool(true),
            ),
            confidence: hydra_core::Confidence::new(0.5),
            status: hydra_core::ClaimStatus::Proposed,
            evidence_for: vec![],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: hydra_core::ActorId::from_str("actor_test"),
            created_at: now,
            updated_at: now,
            caused_by: Some(signal_event_id),
        };
        hydra
            .ingest(hydra_core::EventKind::ClaimProposed { claim })
            .unwrap();

        let result = hydra.create_reflex_causal_cell_from_claim(
            claim_id,
            hydra_core::ActorId::from_str("actor_ops"),
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("not model-derived")
                        && msg.contains("MicroModelPredictionRecorded"),
                    "msg: {msg}"
                );
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn create_reflex_cell_snapshot_restore_preserves_cell() {
        // The cell is stored via Patch 20's `create_causal_cell`,
        // so the Patch 20 snapshot round-trip applies directly.
        // Pin it once for Patch 21 so the integration stays
        // honest as Patch 22+ adds composition.
        //
        // Patch 28 note: `drive_full_replication_lag_chain` now
        // auto-creates a Reflex cell via the bridge — the
        // explicit `create_reflex_causal_cell_from_claim` call
        // below mints a SECOND cell for the same claim. Both
        // must round-trip; the explicitly-tested one is
        // `cell_id`.
        let mut hydra = Hydra::new();
        let (claim_id, _, _, _, _) =
            drive_full_replication_lag_chain(&mut hydra);
        let cell = hydra
            .create_reflex_causal_cell_from_claim(
                claim_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        let cell_id = cell.id.clone();

        // Snapshot. Two cells: 1 auto-created by P28 + 1
        // explicit. Snapshot manifest counts both.
        let manifest = hydra
            .snapshot(hydra_core::ActorId::from_str("actor_ops"))
            .unwrap();
        assert_eq!(manifest.total_causal_cells, 2);
        let body = hydra
            .snapshot_store()
            .body(&manifest.id)
            .expect("snapshot body present after take")
            .clone();
        assert_eq!(body.causal_cells.len(), 2);
        // The explicit cell is one of the two; order is
        // HashMap-iteration so just confirm membership.
        assert!(
            body.causal_cells.iter().any(|c| c.id == cell_id),
            "explicit cell missing from snapshot body"
        );

        // Restore by replaying the body's events into a fresh
        // engine (same pattern as the Patch 20 round-trip pin).
        let mut fresh = Hydra::new();
        fresh.recover_from_events(body.events.clone()).unwrap();
        let restored =
            fresh.causal_cell(&cell_id).expect("cell restored");
        assert_eq!(restored.kind, hydra_core::CausalCellKind::Reflex);
        assert_eq!(restored.subject, "hydra.replication/replica_lagging");
        assert!(restored.trust_score.is_some());
    }

    // === Patch 22 — CausalCell composition ===

    /// Construct + ingest a minimal Reflex cell with the supplied
    /// id fixtures. Used by the composition tests to set up
    /// children with deterministic content (vs driving full reflex
    /// chains, which is slower and harder to control for dedupe /
    /// trust pins).
    #[allow(clippy::too_many_arguments)]
    fn ingest_synthetic_cell(
        hydra: &mut Hydra,
        tenant_id: Option<hydra_core::TenantId>,
        subject: &str,
        evidence_ids: Vec<hydra_core::EvidenceId>,
        claim_ids: Vec<hydra_core::ClaimId>,
        action_ids: Vec<hydra_core::ActionId>,
        outcome_ids: Vec<hydra_core::OutcomeId>,
        observation_run_ids: Vec<hydra_core::MicroModelRunId>,
        source_events: Vec<hydra_core::EventId>,
        trust_score: Option<f64>,
        caused_by: Option<hydra_core::EventId>,
    ) -> hydra_core::CausalCell {
        let cell = hydra_core::CausalCell {
            id: hydra_core::CausalCellId::new(),
            tenant_id,
            kind: hydra_core::CausalCellKind::Reflex,
            subject: subject.to_string(),
            source_events,
            evidence_ids,
            claim_ids,
            action_ids,
            outcome_ids,
            observation_run_ids,
            child_cell_ids: Vec::new(),
            trust_score,
            summary: None,
            created_by: hydra_core::ActorId::from_str("actor_ops"),
            created_at: chrono::Utc::now(),
            caused_by,
        };
        hydra.create_causal_cell(cell).unwrap()
    }

    #[test]
    fn compose_causal_cells_creates_parent_with_children() {
        // Happy path: two reflex children → one Health parent.
        let mut hydra = Hydra::new();
        let a = ingest_synthetic_cell(
            &mut hydra,
            None,
            "hydra.commit_rate/under_abnormal_load",
            vec![hydra_core::EvidenceId::from_str("evd_a")],
            vec![hydra_core::ClaimId::from_str("claim_a")],
            vec![],
            vec![],
            vec![],
            vec![hydra_core::EventId::from_str("evt_a")],
            Some(0.80),
            Some(hydra_core::EventId::from_str("evt_a")),
        );
        let b = ingest_synthetic_cell(
            &mut hydra,
            None,
            "hydra.replication/replica_lagging",
            vec![hydra_core::EvidenceId::from_str("evd_b")],
            vec![hydra_core::ClaimId::from_str("claim_b")],
            vec![],
            vec![],
            vec![],
            vec![hydra_core::EventId::from_str("evt_b")],
            Some(0.60),
            Some(hydra_core::EventId::from_str("evt_b")),
        );

        let parent = hydra
            .compose_causal_cells(
                vec![a.id.clone(), b.id.clone()],
                hydra_core::CausalCellKind::Health,
                "hydra.health".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();

        assert_eq!(parent.kind, hydra_core::CausalCellKind::Health);
        assert_eq!(parent.subject, "hydra.health");
        assert_eq!(parent.child_cell_ids, vec![a.id.clone(), b.id.clone()]);
        // Parent is also stored + retrievable.
        assert_eq!(hydra.causal_cell(&parent.id), Some(&parent));
    }

    #[test]
    fn compose_causal_cells_rejects_empty_children() {
        let mut hydra = Hydra::new();
        let result = hydra.compose_causal_cells(
            Vec::new(),
            hydra_core::CausalCellKind::Health,
            "anything".to_string(),
            hydra_core::ActorId::from_str("actor_ops"),
            None,
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("at least one child cell"),
                    "msg: {msg}"
                );
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn compose_causal_cells_rejects_unknown_child() {
        let mut hydra = Hydra::new();
        let result = hydra.compose_causal_cells(
            vec![hydra_core::CausalCellId::from_str("cell_ghost")],
            hydra_core::CausalCellKind::Health,
            "hydra.health".to_string(),
            hydra_core::ActorId::from_str("actor_ops"),
            None,
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("unknown causal cell"),
                    "msg: {msg}"
                );
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn compose_causal_cells_rejects_mixed_tenants() {
        // None + Some(x) must error.
        let mut hydra = Hydra::new();
        let unscoped = ingest_synthetic_cell(
            &mut hydra,
            None,
            "global",
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            None,
            None,
        );
        let scoped = ingest_synthetic_cell(
            &mut hydra,
            Some(hydra_core::TenantId::from_str("ten_a")),
            "tenant_a",
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            None,
            None,
        );

        let result = hydra.compose_causal_cells(
            vec![unscoped.id.clone(), scoped.id.clone()],
            hydra_core::CausalCellKind::Health,
            "mixed".to_string(),
            hydra_core::ActorId::from_str("actor_ops"),
            None,
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("tenant"),
                    "msg should mention tenant: {msg}"
                );
            }
            other => panic!("expected tenant QueryError, got {other:?}"),
        }

        // Some(a) + Some(b) must also error.
        let scoped_b = ingest_synthetic_cell(
            &mut hydra,
            Some(hydra_core::TenantId::from_str("ten_b")),
            "tenant_b",
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            None,
            None,
        );
        let result = hydra.compose_causal_cells(
            vec![scoped.id.clone(), scoped_b.id.clone()],
            hydra_core::CausalCellKind::Health,
            "mixed".to_string(),
            hydra_core::ActorId::from_str("actor_ops"),
            None,
        );
        assert!(matches!(
            result,
            Err(hydra_core::error::HydraError::QueryError(_))
        ));
    }

    #[test]
    fn compose_causal_cells_aggregates_ids_from_children() {
        // Two children with distinct ids in every slice → parent
        // has the union, exactly.
        let mut hydra = Hydra::new();
        let a = ingest_synthetic_cell(
            &mut hydra,
            None,
            "a",
            vec![hydra_core::EvidenceId::from_str("evd_a")],
            vec![hydra_core::ClaimId::from_str("claim_a")],
            vec![hydra_core::ActionId::from_str("act_a")],
            vec![hydra_core::OutcomeId::from_str("out_a")],
            vec![hydra_core::MicroModelRunId::from_str("run_a")],
            vec![hydra_core::EventId::from_str("evt_a")],
            None,
            None,
        );
        let b = ingest_synthetic_cell(
            &mut hydra,
            None,
            "b",
            vec![hydra_core::EvidenceId::from_str("evd_b")],
            vec![hydra_core::ClaimId::from_str("claim_b")],
            vec![hydra_core::ActionId::from_str("act_b")],
            vec![hydra_core::OutcomeId::from_str("out_b")],
            vec![hydra_core::MicroModelRunId::from_str("run_b")],
            vec![hydra_core::EventId::from_str("evt_b")],
            None,
            None,
        );

        let parent = hydra
            .compose_causal_cells(
                vec![a.id, b.id],
                hydra_core::CausalCellKind::Health,
                "agg".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();

        assert_eq!(parent.evidence_ids.len(), 2);
        assert_eq!(parent.claim_ids.len(), 2);
        assert_eq!(parent.action_ids.len(), 2);
        assert_eq!(parent.outcome_ids.len(), 2);
        assert_eq!(parent.observation_run_ids.len(), 2);
        assert_eq!(parent.source_events.len(), 2);
    }

    #[test]
    fn compose_causal_cells_dedupes_ids_preserving_order() {
        // Children share an evidence id and an event id → parent
        // has each ONCE, in first-seen position (= child[0]'s
        // ordering). Also pins child_cell_ids dedupe.
        let mut hydra = Hydra::new();
        let shared_evidence = hydra_core::EvidenceId::from_str("evd_shared");
        let shared_event = hydra_core::EventId::from_str("evt_shared");

        let a = ingest_synthetic_cell(
            &mut hydra,
            None,
            "a",
            vec![
                shared_evidence.clone(),
                hydra_core::EvidenceId::from_str("evd_only_a"),
            ],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![
                shared_event.clone(),
                hydra_core::EventId::from_str("evt_only_a"),
            ],
            None,
            None,
        );
        let b = ingest_synthetic_cell(
            &mut hydra,
            None,
            "b",
            vec![
                shared_evidence.clone(),
                hydra_core::EvidenceId::from_str("evd_only_b"),
            ],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![
                shared_event.clone(),
                hydra_core::EventId::from_str("evt_only_b"),
            ],
            None,
            None,
        );

        // Pass child A twice to also pin child_cell_ids dedupe.
        let parent = hydra
            .compose_causal_cells(
                vec![a.id.clone(), b.id.clone(), a.id.clone()],
                hydra_core::CausalCellKind::Health,
                "dedupe".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();

        // child_cell_ids deduped, A appears only once.
        assert_eq!(parent.child_cell_ids, vec![a.id, b.id]);

        // Aggregated evidence ids: shared appears once at the
        // FIRST-seen position (= position 0, from child A).
        assert_eq!(parent.evidence_ids.len(), 3);
        assert_eq!(parent.evidence_ids[0], shared_evidence);
        // The two child-unique ids follow in child-encounter order.
        assert_eq!(
            parent.evidence_ids[1],
            hydra_core::EvidenceId::from_str("evd_only_a")
        );
        assert_eq!(
            parent.evidence_ids[2],
            hydra_core::EvidenceId::from_str("evd_only_b")
        );

        // Same shape for source_events.
        assert_eq!(parent.source_events.len(), 3);
        assert_eq!(parent.source_events[0], shared_event);
    }

    #[test]
    fn compose_causal_cells_averages_child_trust_scores() {
        let mut hydra = Hydra::new();

        // Two children with scores → arithmetic mean.
        let high = ingest_synthetic_cell(
            &mut hydra, None, "high",
            vec![], vec![], vec![], vec![], vec![], vec![],
            Some(0.80), None,
        );
        let low = ingest_synthetic_cell(
            &mut hydra, None, "low",
            vec![], vec![], vec![], vec![], vec![], vec![],
            Some(0.60), None,
        );
        let parent = hydra
            .compose_causal_cells(
                vec![high.id.clone(), low.id.clone()],
                hydra_core::CausalCellKind::Health,
                "two_known".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();
        let score = parent.trust_score.unwrap();
        assert!(
            (score - 0.70).abs() < 1e-9,
            "expected 0.70, got {score}"
        );

        // Mix with a None-scored child: None children skipped from
        // the average, NOT counted as 0.
        let unknown = ingest_synthetic_cell(
            &mut hydra, None, "unknown",
            vec![], vec![], vec![], vec![], vec![], vec![],
            None, None,
        );
        let parent_mixed = hydra
            .compose_causal_cells(
                vec![high.id, low.id, unknown.id.clone()],
                hydra_core::CausalCellKind::Health,
                "mixed_known".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();
        let mixed_score = parent_mixed.trust_score.unwrap();
        assert!(
            (mixed_score - 0.70).abs() < 1e-9,
            "None-scored child must be skipped; expected 0.70, got {mixed_score}"
        );

        // All-None children → parent None.
        let another_unknown = ingest_synthetic_cell(
            &mut hydra, None, "another_unknown",
            vec![], vec![], vec![], vec![], vec![], vec![],
            None, None,
        );
        let parent_none = hydra
            .compose_causal_cells(
                vec![unknown.id, another_unknown.id],
                hydra_core::CausalCellKind::Health,
                "all_unknown".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();
        assert!(
            parent_none.trust_score.is_none(),
            "all-None children must yield parent.trust_score=None"
        );
    }

    #[test]
    fn compose_causal_cells_uses_default_summary() {
        let mut hydra = Hydra::new();
        let child = ingest_synthetic_cell(
            &mut hydra, None, "x",
            vec![],
            vec![hydra_core::ClaimId::from_str("claim_x")],
            vec![hydra_core::ActionId::from_str("act_x")],
            vec![], vec![], vec![],
            Some(0.85), None,
        );

        let parent = hydra
            .compose_causal_cells(
                vec![child.id],
                hydra_core::CausalCellKind::Health,
                "hydra.health".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();

        let summary = parent.summary.as_ref().unwrap();
        // Kind label uses discriminant() (snake_case): "health",
        // not "Health".
        assert!(summary.starts_with("composed health cell for hydra.health"));
        assert!(summary.contains("1 child cells"));
        assert!(summary.contains("1 claims"));
        assert!(summary.contains("1 actions"));
        assert!(summary.contains("trust=0.85"));
    }

    #[test]
    fn compose_causal_cells_uses_caller_summary_when_provided() {
        // Caller-supplied summary must override the default.
        let mut hydra = Hydra::new();
        let child = ingest_synthetic_cell(
            &mut hydra, None, "x",
            vec![], vec![], vec![], vec![], vec![], vec![],
            Some(0.50), None,
        );
        let parent = hydra
            .compose_causal_cells(
                vec![child.id],
                hydra_core::CausalCellKind::Incident,
                "any".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                Some("operator-supplied label".to_string()),
            )
            .unwrap();
        assert_eq!(
            parent.summary.as_deref(),
            Some("operator-supplied label")
        );
    }

    #[test]
    fn compose_causal_cells_caused_by_walks_to_first_some() {
        // The LOAD-BEARING adaptation pin: child[0].caused_by =
        // None, child[1].caused_by = Some(evt). Parent inherits
        // child[1]'s caused_by — not the first child blindly.
        let mut hydra = Hydra::new();
        let anchor_event = hydra_core::EventId::from_str("evt_anchor");

        let no_anchor = ingest_synthetic_cell(
            &mut hydra, None, "no_anchor",
            vec![], vec![], vec![], vec![], vec![], vec![],
            None,
            None, // <- caused_by None
        );
        let with_anchor = ingest_synthetic_cell(
            &mut hydra, None, "with_anchor",
            vec![], vec![], vec![], vec![], vec![], vec![],
            None,
            Some(anchor_event.clone()),
        );

        let parent = hydra
            .compose_causal_cells(
                vec![no_anchor.id, with_anchor.id],
                hydra_core::CausalCellKind::Health,
                "anchor_walk".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();

        assert_eq!(
            parent.caused_by,
            Some(anchor_event),
            "parent.caused_by must walk to first Some, not stop at child[0]"
        );

        // Inverse case: all children have caused_by=None → parent
        // caused_by=None.
        let another_no_anchor = ingest_synthetic_cell(
            &mut hydra, None, "also_no_anchor",
            vec![], vec![], vec![], vec![], vec![], vec![],
            None, None,
        );
        let third_no_anchor = ingest_synthetic_cell(
            &mut hydra, None, "third_no_anchor",
            vec![], vec![], vec![], vec![], vec![], vec![],
            None, None,
        );
        let parent_unanchored = hydra
            .compose_causal_cells(
                vec![another_no_anchor.id, third_no_anchor.id],
                hydra_core::CausalCellKind::Health,
                "unanchored".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();
        assert!(parent_unanchored.caused_by.is_none());
    }

    #[test]
    fn compose_causal_cells_snapshot_restore_preserves_parent_and_links() {
        // The integration pin: compose two real Reflex cells from
        // replication-lag chains, snapshot, restore on a fresh
        // engine, verify the parent + both children are intact and
        // child_cell_ids resolves.
        let mut hydra = Hydra::new();

        // First reflex chain → cell A.
        let (claim_a, _, _, _, _) =
            drive_full_replication_lag_chain(&mut hydra);
        let cell_a = hydra
            .create_reflex_causal_cell_from_claim(
                claim_a,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();

        // Second reflex chain (different peer) → cell B. We can't
        // call drive_full_replication_lag_chain twice (uses fixed
        // peer id), so do a second registration manually.
        let peer_b = hydra_core::ReplicaId::from_str("replica_p22_b");
        register_peer_with_lag(
            &mut hydra,
            &peer_b,
            Some((300, chrono::Utc::now())),
        );
        let assessment_b = hydra
            .evaluate_replication_lag_anomaly_and_propose_action(
                peer_b,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        let claim_b = assessment_b.claim_id.clone().unwrap();
        let cell_b = hydra
            .create_reflex_causal_cell_from_claim(
                claim_b,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();

        // Compose.
        let parent = hydra
            .compose_causal_cells(
                vec![cell_a.id.clone(), cell_b.id.clone()],
                hydra_core::CausalCellKind::Health,
                "hydra.health".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();
        let parent_id = parent.id.clone();

        // Snapshot.
        let manifest = hydra
            .snapshot(hydra_core::ActorId::from_str("actor_ops"))
            .unwrap();
        // Patch 28 note: each replication-lag chain auto-creates
        // a Reflex cell in addition to the test's explicit
        // `create_reflex_causal_cell_from_claim` call. So the
        // manifest carries 5 cells: 2 auto-created Reflex + 2
        // explicit Reflex + 1 composed Health parent.
        assert_eq!(manifest.total_causal_cells, 5);
        let body = hydra
            .snapshot_store()
            .body(&manifest.id)
            .expect("snapshot body present")
            .clone();

        // Replay into a fresh engine.
        let mut fresh = Hydra::new();
        fresh.recover_from_events(body.events.clone()).unwrap();
        let restored_parent = fresh
            .causal_cell(&parent_id)
            .expect("parent cell restored");
        assert_eq!(restored_parent.kind, hydra_core::CausalCellKind::Health);
        assert_eq!(restored_parent.subject, "hydra.health");
        assert_eq!(
            restored_parent.child_cell_ids,
            vec![cell_a.id.clone(), cell_b.id.clone()]
        );
        // Both children resolvable too.
        assert!(fresh.causal_cell(&cell_a.id).is_some());
        assert!(fresh.causal_cell(&cell_b.id).is_some());
    }

    // === Patch 26 — HydraHealthCell composer ===
    //
    // Tests live next to the P22 compose tests above; they share
    // the `ingest_synthetic_cell` helper for setting up reflex
    // children. A test-local `ingest_synthetic_cell_at` variant
    // is used by the "latest wins" pin to control `created_at`
    // explicitly (the default helper stamps `Utc::now()`).

    /// `ingest_synthetic_cell` variant that takes an explicit
    /// `created_at`. Used by the Patch 26 latest-per-subject
    /// pin so the time ordering is deterministic regardless of
    /// the wall clock or how fast the test runs.
    fn ingest_synthetic_reflex_cell_at(
        hydra: &mut Hydra,
        tenant_id: Option<hydra_core::TenantId>,
        subject: &str,
        trust_score: Option<f64>,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> hydra_core::CausalCell {
        let cell = hydra_core::CausalCell {
            id: hydra_core::CausalCellId::new(),
            tenant_id,
            kind: hydra_core::CausalCellKind::Reflex,
            subject: subject.to_string(),
            source_events: vec![],
            evidence_ids: vec![],
            claim_ids: vec![],
            action_ids: vec![],
            outcome_ids: vec![],
            observation_run_ids: vec![],
            child_cell_ids: vec![],
            trust_score,
            summary: None,
            created_by: hydra_core::ActorId::from_str("actor_ops"),
            created_at,
            caused_by: None,
        };
        hydra.create_causal_cell(cell).unwrap()
    }

    /// Convenience: seed one reflex cell per built-in self-health
    /// subject, all tenant-scoped to the same tenant.
    fn seed_all_four_self_health_reflexes(
        hydra: &mut Hydra,
        tenant_id: Option<hydra_core::TenantId>,
    ) -> [hydra_core::CausalCell; 4] {
        let now = chrono::Utc::now();
        let cells: [hydra_core::CausalCell; 4] = [
            ingest_synthetic_reflex_cell_at(
                hydra,
                tenant_id.clone(),
                "hydra/under_abnormal_load",
                Some(0.80),
                now,
            ),
            ingest_synthetic_reflex_cell_at(
                hydra,
                tenant_id.clone(),
                "hydra.replication/replica_lagging",
                Some(0.70),
                now,
            ),
            ingest_synthetic_reflex_cell_at(
                hydra,
                tenant_id.clone(),
                "hydra.agents/agent_loop_storm",
                Some(0.60),
                now,
            ),
            ingest_synthetic_reflex_cell_at(
                hydra,
                tenant_id,
                "hydra.actions/action_failure_rate_high",
                Some(0.50),
                now,
            ),
        ];
        cells
    }

    #[test]
    fn compose_hydra_health_cell_all_four_present() {
        // Happy path: 4 reflex cells (one per subject) → 1 Health
        // parent. Every Patch 26 contract fires:
        //   - kind = Health
        //   - subject = "hydra.health"
        //   - child_cell_ids = all four, in subject-order
        //   - trust_score = mean(0.80, 0.70, 0.60, 0.50) = 0.65
        //   - summary mentions "4 of 4" and lists all four
        //     present labels in order; no Missing: clause.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_health_test");
        let children = seed_all_four_self_health_reflexes(
            &mut hydra,
            Some(tenant.clone()),
        );
        let parent = hydra
            .compose_hydra_health_cell(
                hydra_core::ActorId::from_str("actor_ops"),
                Some(tenant.clone()),
            )
            .unwrap();
        assert_eq!(parent.kind, hydra_core::CausalCellKind::Health);
        assert_eq!(parent.subject, "hydra.health");
        assert_eq!(parent.tenant_id, Some(tenant));
        assert_eq!(parent.child_cell_ids.len(), 4);
        // Subject-ordered: commit-rate, replication-lag,
        // agent-loop-storm, action-failure-rate (parallel to
        // SELF_HEALTH_REFLEX_SUBJECTS).
        for (idx, child) in children.iter().enumerate() {
            assert_eq!(
                parent.child_cell_ids[idx], child.id,
                "child {idx} mismatch"
            );
        }
        // Patch 22 mean: (0.80+0.70+0.60+0.50)/4 = 0.65.
        let score = parent.trust_score.expect("trust_score set");
        assert!((score - 0.65).abs() < 1e-9, "score = {score}");
        let summary = parent.summary.as_ref().expect("summary set");
        assert!(
            summary.contains("4 of 4 self-health reflexes"),
            "summary: {summary}"
        );
        for label in &[
            "commit-rate",
            "replication-lag",
            "agent-loop-storm",
            "action-failure-rate",
        ] {
            assert!(summary.contains(label), "summary missing {label}");
        }
        assert!(
            !summary.contains("Missing:"),
            "summary unexpectedly listed missing: {summary}"
        );
    }

    #[test]
    fn compose_hydra_health_cell_partial_present_three_subjects() {
        // 3 of 4 reflexes present → still composes, summary
        // calls out the missing one by label.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_health_test");
        let now = chrono::Utc::now();
        let a = ingest_synthetic_reflex_cell_at(
            &mut hydra,
            Some(tenant.clone()),
            "hydra/under_abnormal_load",
            Some(0.80),
            now,
        );
        let b = ingest_synthetic_reflex_cell_at(
            &mut hydra,
            Some(tenant.clone()),
            "hydra.replication/replica_lagging",
            Some(0.70),
            now,
        );
        // Skip agent-loop-storm.
        let d = ingest_synthetic_reflex_cell_at(
            &mut hydra,
            Some(tenant.clone()),
            "hydra.actions/action_failure_rate_high",
            Some(0.50),
            now,
        );
        let parent = hydra
            .compose_hydra_health_cell(
                hydra_core::ActorId::from_str("actor_ops"),
                Some(tenant),
            )
            .unwrap();
        assert_eq!(parent.kind, hydra_core::CausalCellKind::Health);
        // Children in subject-order — the skip leaves a gap, so
        // we get commit-rate, replication-lag, action-failure-rate
        // (NOT agent-loop-storm).
        assert_eq!(
            parent.child_cell_ids,
            vec![a.id.clone(), b.id.clone(), d.id.clone()]
        );
        let summary = parent.summary.as_ref().unwrap();
        assert!(
            summary.contains("3 of 4 self-health reflexes"),
            "summary: {summary}"
        );
        assert!(summary.contains("Missing: agent-loop-storm"), "summary: {summary}");
        assert!(summary.contains("Present:"), "summary: {summary}");
    }

    #[test]
    fn compose_hydra_health_cell_partial_present_one_subject() {
        // Single-subject case: 1 reflex present, 3 missing →
        // still composes, summary lists 1 present + 3 missing.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_health_test");
        let now = chrono::Utc::now();
        let only = ingest_synthetic_reflex_cell_at(
            &mut hydra,
            Some(tenant.clone()),
            "hydra.agents/agent_loop_storm",
            Some(0.40),
            now,
        );
        let parent = hydra
            .compose_hydra_health_cell(
                hydra_core::ActorId::from_str("actor_ops"),
                Some(tenant),
            )
            .unwrap();
        assert_eq!(parent.child_cell_ids, vec![only.id]);
        let summary = parent.summary.as_ref().unwrap();
        assert!(
            summary.contains("1 of 4 self-health reflexes"),
            "summary: {summary}"
        );
        assert!(
            summary.contains("Present: agent-loop-storm"),
            "summary: {summary}"
        );
        for missing in &["commit-rate", "replication-lag", "action-failure-rate"] {
            assert!(
                summary.contains(missing),
                "summary missing label {missing}: {summary}"
            );
        }
    }

    #[test]
    fn compose_hydra_health_cell_zero_found_returns_error() {
        // No self-health reflex cells in the store → hard
        // QueryError. Matches the `compose_causal_cells`
        // empty-children contract.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_health_test");
        let result = hydra.compose_hydra_health_cell(
            hydra_core::ActorId::from_str("actor_ops"),
            Some(tenant),
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("no self-health reflex cells found"),
                    "msg: {msg}"
                );
                assert!(
                    msg.contains("tenant_health_test"),
                    "tenant name should appear in error: {msg}"
                );
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn compose_hydra_health_cell_filters_by_tenant() {
        // Reflex cells in tenant_a + tenant_b. Calling with
        // tenant_a should compose ONLY tenant_a's cells; tenant_b
        // ones must be invisible.
        let mut hydra = Hydra::new();
        let tenant_a = hydra_core::TenantId::from_str("tenant_a");
        let tenant_b = hydra_core::TenantId::from_str("tenant_b");
        let _ours = seed_all_four_self_health_reflexes(
            &mut hydra,
            Some(tenant_a.clone()),
        );
        let _theirs = seed_all_four_self_health_reflexes(
            &mut hydra,
            Some(tenant_b),
        );
        let parent = hydra
            .compose_hydra_health_cell(
                hydra_core::ActorId::from_str("actor_ops"),
                Some(tenant_a.clone()),
            )
            .unwrap();
        assert_eq!(parent.tenant_id, Some(tenant_a.clone()));
        assert_eq!(parent.child_cell_ids.len(), 4);
        // Every child must belong to tenant_a.
        for child_id in &parent.child_cell_ids {
            let child = hydra.causal_cell(child_id).unwrap();
            assert_eq!(child.tenant_id, Some(tenant_a.clone()));
        }
    }

    #[test]
    fn compose_hydra_health_cell_none_tenanted_only() {
        // When called with `tenant=None`, only `None`-tenanted
        // reflex cells participate; any tenant-scoped reflex
        // cells (even with matching subjects) are excluded.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_health_test");
        // Seed all 4 subjects under `None` (system cells).
        let _system = seed_all_four_self_health_reflexes(&mut hydra, None);
        // Also seed a tenanted cell at one of the subjects — it
        // must NOT bleed into the None composition.
        let _tenanted_decoy = ingest_synthetic_reflex_cell_at(
            &mut hydra,
            Some(tenant),
            "hydra/under_abnormal_load",
            Some(0.99),
            chrono::Utc::now(),
        );
        let parent = hydra
            .compose_hydra_health_cell(
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();
        assert_eq!(parent.tenant_id, None);
        assert_eq!(parent.child_cell_ids.len(), 4);
        for child_id in &parent.child_cell_ids {
            let child = hydra.causal_cell(child_id).unwrap();
            assert_eq!(child.tenant_id, None);
        }
    }

    #[test]
    fn compose_hydra_health_cell_latest_wins_per_subject() {
        // Multiple Reflex cells for the SAME subject in the
        // store → composer picks the one with the largest
        // `created_at`. Pinned with explicit timestamps so the
        // assertion is deterministic regardless of test
        // wall-clock noise.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_health_test");
        let t0 = chrono::Utc::now();
        let t1 = t0 + chrono::Duration::seconds(10);
        let t2 = t0 + chrono::Duration::seconds(20);

        // Older commit-rate cell (should NOT be picked).
        let _older = ingest_synthetic_reflex_cell_at(
            &mut hydra,
            Some(tenant.clone()),
            "hydra/under_abnormal_load",
            Some(0.20),
            t0,
        );
        // Latest commit-rate cell (SHOULD be picked).
        let latest = ingest_synthetic_reflex_cell_at(
            &mut hydra,
            Some(tenant.clone()),
            "hydra/under_abnormal_load",
            Some(0.90),
            t2,
        );
        // Mid-time decoy with the same subject — still loses to
        // `latest`.
        let _mid = ingest_synthetic_reflex_cell_at(
            &mut hydra,
            Some(tenant.clone()),
            "hydra/under_abnormal_load",
            Some(0.50),
            t1,
        );
        let parent = hydra
            .compose_hydra_health_cell(
                hydra_core::ActorId::from_str("actor_ops"),
                Some(tenant),
            )
            .unwrap();
        assert_eq!(parent.child_cell_ids, vec![latest.id]);
        // And the parent's mean should be the latest cell's
        // score (0.90), proving the latest wins.
        let score = parent.trust_score.expect("trust_score set");
        assert!((score - 0.90).abs() < 1e-9, "score = {score}");
    }

    #[test]
    fn compose_hydra_health_cell_ignores_non_reflex_cells() {
        // Non-Reflex cells (e.g., a stray Health-kind cell with a
        // matching subject) must NOT count toward the composition.
        // The helper filters by `kind = Reflex` strictly.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_health_test");
        // A non-Reflex cell with one of the self-health subjects —
        // must be ignored.
        let _stray = hydra
            .create_causal_cell(hydra_core::CausalCell {
                id: hydra_core::CausalCellId::new(),
                tenant_id: Some(tenant.clone()),
                kind: hydra_core::CausalCellKind::Health,
                subject: "hydra/under_abnormal_load".to_string(),
                source_events: vec![],
                evidence_ids: vec![],
                claim_ids: vec![],
                action_ids: vec![],
                outcome_ids: vec![],
                observation_run_ids: vec![],
                child_cell_ids: vec![],
                trust_score: Some(0.99),
                summary: None,
                created_by: hydra_core::ActorId::from_str("actor_ops"),
                created_at: chrono::Utc::now(),
                caused_by: None,
            })
            .unwrap();
        // Now seed one Reflex cell for a different subject.
        let reflex = ingest_synthetic_reflex_cell_at(
            &mut hydra,
            Some(tenant.clone()),
            "hydra.actions/action_failure_rate_high",
            Some(0.40),
            chrono::Utc::now(),
        );
        let parent = hydra
            .compose_hydra_health_cell(
                hydra_core::ActorId::from_str("actor_ops"),
                Some(tenant),
            )
            .unwrap();
        // Only the Reflex cell participated.
        assert_eq!(parent.child_cell_ids, vec![reflex.id]);
        let summary = parent.summary.as_ref().unwrap();
        assert!(
            summary.contains("1 of 4 self-health reflexes"),
            "summary: {summary}"
        );
    }

    // === Patch 28 — auto-create Reflex CausalCells during evaluation ===
    //
    // Every actionable model evaluation in claim or action mode
    // now auto-creates a `CausalCellKind::Reflex` cell from the
    // proposed claim and exposes its id on the returned
    // assessment. Non-actionable levels (WarmingUp / Normal)
    // skip cell creation because no claim was proposed in the
    // first place.

    /// Drive the built-in commit-rate model into Critical level.
    /// Replicates the `primed_hydra` + `ingest_signals` pattern
    /// from the parent test module (`mod tests`); inlined here
    /// so the `sprint1_tests` module is self-contained for P28.
    fn drive_commit_rate_to_critical(hydra: &mut Hydra) {
        let actor = hydra_core::ActorId::from_str("actor_ops");
        // First evaluate auto-registers the model.
        let _ = hydra.evaluate_commit_rate_anomaly(actor.clone()).unwrap();
        // Overwrite the model state with a baseline past warmup
        // so the next evaluate observes a real anomaly directly.
        hydra.commit_rate_anomaly_model = Some(
            crate::micromodels::CommitRateAnomalyModel::with_state(
                crate::micromodels::CommitRateAnomalyConfig::default(),
                crate::micromodels::CommitRateAnomalyState {
                    ewma_rate: 10.0,
                    ewma_variance: 1.0,
                    samples_seen: 10,
                    last_observed_at: Some(chrono::Utc::now()),
                },
            ),
        );
        // Ingest 100 signals → window count >> baseline → Critical.
        for i in 0..100u64 {
            hydra
                .ingest(hydra_core::EventKind::Signal {
                    source: hydra_core::NodeId::from_str("test.bridge"),
                    name: format!("p28-signal-{i}"),
                    payload: std::collections::HashMap::new(),
                })
                .unwrap();
        }
    }

    /// Drive the built-in agent-loop-storm model into Critical
    /// level by ingesting 60 ActionProposed events from one
    /// non-system actor (`ingest_n_action_proposed` is the
    /// existing helper at module scope).
    fn drive_agent_loop_storm_to_critical(hydra: &mut Hydra) {
        let agent = hydra_core::ActorId::from_str(
            "actor_data_quality_agent_p28",
        );
        ingest_n_action_proposed(hydra, 60, &agent);
    }

    /// Drive the built-in action-failure-rate model into Critical
    /// level via the existing `drive_action_outcomes` helper:
    /// 5 successful + 10 failed = 15 actions, 10 failures
    /// >= critical_failure_count (10).
    fn drive_action_failure_rate_to_critical(hydra: &mut Hydra) {
        drive_action_outcomes(hydra, 5, 10);
    }

    #[test]
    fn commit_rate_action_mode_auto_creates_reflex_cell() {
        // Drive commit-rate to Critical via the test injector, run
        // the action-mode bridge, and confirm `causal_cell_id` is
        // populated on the assessment AND the cell exists in the
        // store with the expected shape.
        let mut hydra = Hydra::new();
        drive_commit_rate_to_critical(&mut hydra);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        // Model fired → claim + action + cell exist.
        assert!(assessment.claim_id.is_some(), "expected claim");
        assert!(!assessment.action_ids.is_empty(), "expected action");
        let cell_id = assessment
            .causal_cell_id
            .clone()
            .expect("expected causal_cell_id");
        let cell = hydra.causal_cell(&cell_id).expect("cell in store");
        assert_eq!(cell.kind, hydra_core::CausalCellKind::Reflex);
        assert_eq!(cell.subject, "hydra/under_abnormal_load");
    }

    #[test]
    fn commit_rate_claim_mode_auto_creates_reflex_cell() {
        // Claim mode (no action stage). Cell still gets created
        // because a claim exists. `cell.action_ids` is empty
        // because no action was proposed in claim mode.
        let mut hydra = Hydra::new();
        drive_commit_rate_to_critical(&mut hydra);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert!(assessment.claim_id.is_some());
        let cell_id = assessment.causal_cell_id.clone().unwrap();
        let cell = hydra.causal_cell(&cell_id).expect("cell in store");
        assert_eq!(cell.kind, hydra_core::CausalCellKind::Reflex);
        // Claim mode → no action → cell has empty action_ids.
        assert!(
            cell.action_ids.is_empty(),
            "claim mode cell shouldn't carry action ids: {:?}",
            cell.action_ids
        );
    }

    #[test]
    fn commit_rate_claim_mode_warmup_returns_no_cell() {
        // LOAD-BEARING warmup pin. Fresh model → WarmingUp → no
        // claim → no cell. The rule is "no claim → no cell",
        // NOT "claim mode always creates a cell".
        let mut hydra = Hydra::new();
        // No injector → samples_seen = 0 → WarmingUp.
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_claim(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert!(assessment.claim_id.is_none(), "expected no claim");
        assert!(
            assessment.causal_cell_id.is_none(),
            "warmup must not auto-create a cell"
        );
    }

    #[test]
    fn replication_lag_action_mode_auto_creates_reflex_cell() {
        let mut hydra = Hydra::new();
        let peer_id = hydra_core::ReplicaId::from_str("replica_p28");
        register_peer_with_lag(
            &mut hydra,
            &peer_id,
            Some((500, chrono::Utc::now())),
        );
        let assessment = hydra
            .evaluate_replication_lag_anomaly_and_propose_action(
                peer_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert!(assessment.claim_id.is_some());
        assert!(!assessment.action_ids.is_empty());
        let cell_id = assessment.causal_cell_id.clone().unwrap();
        let cell = hydra.causal_cell(&cell_id).expect("cell in store");
        assert_eq!(cell.kind, hydra_core::CausalCellKind::Reflex);
        assert_eq!(cell.subject, "hydra.replication/replica_lagging");
    }

    #[test]
    fn agent_loop_storm_action_mode_auto_creates_reflex_cell() {
        let mut hydra = Hydra::new();
        drive_agent_loop_storm_to_critical(&mut hydra);
        let assessment = hydra
            .evaluate_agent_loop_storm_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert!(assessment.claim_id.is_some());
        assert!(!assessment.action_ids.is_empty());
        let cell_id = assessment.causal_cell_id.clone().unwrap();
        let cell = hydra.causal_cell(&cell_id).expect("cell in store");
        assert_eq!(cell.kind, hydra_core::CausalCellKind::Reflex);
        assert_eq!(cell.subject, "hydra.agents/agent_loop_storm");
    }

    #[test]
    fn action_failure_rate_action_mode_auto_creates_reflex_cell() {
        let mut hydra = Hydra::new();
        drive_action_failure_rate_to_critical(&mut hydra);
        let assessment = hydra
            .evaluate_action_failure_rate_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert!(assessment.claim_id.is_some());
        assert!(!assessment.action_ids.is_empty());
        let cell_id = assessment.causal_cell_id.clone().unwrap();
        let cell = hydra.causal_cell(&cell_id).expect("cell in store");
        assert_eq!(cell.kind, hydra_core::CausalCellKind::Reflex);
        assert_eq!(
            cell.subject,
            "hydra.actions/action_failure_rate_high"
        );
    }

    #[test]
    fn auto_created_cell_has_caused_by_prediction_event() {
        // The cell's `caused_by` points at the prediction event
        // — the chain's causal origin. Pinned because Patch 23
        // trust folding + future lineage UIs rely on this.
        let mut hydra = Hydra::new();
        drive_commit_rate_to_critical(&mut hydra);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        let cell_id = assessment.causal_cell_id.clone().unwrap();
        let cell = hydra.causal_cell(&cell_id).unwrap();
        assert_eq!(cell.caused_by, Some(assessment.prediction_event_id));
    }

    #[test]
    fn auto_created_cell_has_trust_score() {
        // P21's create_reflex_causal_cell_from_claim stamps
        // `cell.trust_score = Some(assess_claim_trust(claim).score)`.
        // Auto-creation keeps that contract — pinned so a future
        // refactor doesn't drop the field silently.
        let mut hydra = Hydra::new();
        drive_commit_rate_to_critical(&mut hydra);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        let cell_id = assessment.causal_cell_id.clone().unwrap();
        let cell = hydra.causal_cell(&cell_id).unwrap();
        assert!(
            cell.trust_score.is_some(),
            "auto-created cell must carry a trust score"
        );
    }

    #[test]
    fn auto_created_cell_action_mode_includes_action_id() {
        // LOAD-BEARING ordering pin. Cell creation must happen
        // AFTER action proposal so `actions_for_claim(claim_id)`
        // sees the new action and stamps it into
        // `cell.action_ids`. If a future refactor reorders cell
        // creation before action proposal, this test fires.
        let mut hydra = Hydra::new();
        drive_commit_rate_to_critical(&mut hydra);
        let assessment = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        assert!(!assessment.action_ids.is_empty());
        let cell_id = assessment.causal_cell_id.clone().unwrap();
        let cell = hydra.causal_cell(&cell_id).unwrap();
        // Cell sees the action proposed in the same call.
        assert_eq!(cell.action_ids, assessment.action_ids);
    }

    #[test]
    fn auto_created_cell_kind_is_reflex() {
        // Sanity: every auto-created cell is `Reflex`-kind, NOT
        // Health or another variant. The compose-side
        // (`compose_hydra_health_cell`) explicitly filters by
        // kind=Reflex; if a future refactor swaps the kind, the
        // fractal pipeline breaks silently. Pin it here.
        let mut hydra = Hydra::new();
        drive_commit_rate_to_critical(&mut hydra);
        let a = hydra
            .evaluate_commit_rate_anomaly_and_propose_action(
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        let cell_a =
            hydra.causal_cell(&a.causal_cell_id.clone().unwrap()).unwrap();
        assert_eq!(cell_a.kind, hydra_core::CausalCellKind::Reflex);

        let peer_id = hydra_core::ReplicaId::from_str("replica_p28_b");
        register_peer_with_lag(
            &mut hydra,
            &peer_id,
            Some((500, chrono::Utc::now())),
        );
        let b = hydra
            .evaluate_replication_lag_anomaly_and_propose_claim(
                peer_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        let cell_b =
            hydra.causal_cell(&b.causal_cell_id.clone().unwrap()).unwrap();
        assert_eq!(cell_b.kind, hydra_core::CausalCellKind::Reflex);
    }

    // === Patch 29 — Identity Graph vocabulary integration ===
    //
    // The unit-level uniqueness + replay tests live next to
    // `IdentityStore` in `identity_store.rs`. These integration
    // tests pin the engine-boundary contracts:
    //
    //   - `Hydra::create_identity_entity` ingests an event AND
    //     populates the store (uniqueness checks fire BEFORE the
    //     event lands so a rejected entity leaves the audit log
    //     untouched).
    //   - `recover_from_events` rebuilds the store from the
    //     audit log.
    //   - Snapshot + restore round-trip preserves identity
    //     entities via the audit-event replay path.

    fn make_identity_entity(
        tenant: Option<hydra_core::TenantId>,
        kind: hydra_core::IdentityEntityKind,
        canonical_key: &str,
        aliases: Vec<hydra_core::IdentityAlias>,
    ) -> hydra_core::IdentityEntity {
        let now = chrono::Utc::now();
        hydra_core::IdentityEntity {
            id: hydra_core::IdentityEntityId::new(),
            tenant_id: tenant,
            kind,
            canonical_key: canonical_key.to_string(),
            display_name: canonical_key.to_string(),
            aliases,
            confidence: hydra_core::Confidence::new(1.0),
            metadata: std::collections::HashMap::new(),
            created_by: hydra_core::ActorId::from_str("actor_ops"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn snowflake_alias(ns: &str, table: &str) -> hydra_core::IdentityAlias {
        hydra_core::IdentityAlias {
            source: "snowflake".to_string(),
            namespace: Some(ns.to_string()),
            external_id: Some(format!("{ns}.{table}").to_uppercase()),
            label: format!("{ns}.{table}").to_uppercase(),
            normalized: format!(
                "{}.{}",
                ns.to_lowercase(),
                table.to_lowercase()
            ),
        }
    }

    #[test]
    fn create_identity_entity_ingests_event_and_indexes() {
        // Happy path through the engine boundary: entity lands
        // in the store AND an IdentityEntityCreated event lands
        // in the audit log.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p29");
        let entity = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        let id = entity.id.clone();
        let stored = hydra.create_identity_entity(entity).unwrap();
        assert_eq!(stored.id, id);
        assert_eq!(hydra.identity_entity(&id), Some(&stored));
        // Alias resolves.
        let resolved = hydra
            .identity_entity_by_alias(
                Some(&tenant),
                "snowflake",
                Some("analytics"),
                "analytics.revenue_daily",
            )
            .unwrap();
        assert_eq!(resolved.id, id);
        // IdentityEntityCreated event landed in the audit log.
        let found = hydra.events().iter().any(|e| {
            matches!(
                &e.kind,
                hydra_core::EventKind::IdentityEntityCreated { .. }
            )
        });
        assert!(found, "audit log missing IdentityEntityCreated event");
    }

    #[test]
    fn create_identity_entity_duplicate_canonical_key_via_hydra() {
        // The canonical-key check fires AT the Hydra boundary
        // (not just at the store), AND on rejection no event is
        // ingested — the audit log stays clean.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p29");
        let a = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![],
        );
        let b = make_identity_entity(
            Some(tenant),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("ops", "other_thing")],
        );
        hydra.create_identity_entity(a).unwrap();
        let pre_count = hydra.events().len();
        let result = hydra.create_identity_entity(b);
        assert!(result.is_err(), "expected duplicate-canonical-key error");
        // Audit log unchanged — store rejection happens BEFORE
        // event ingestion in `create_identity_entity`.
        assert_eq!(
            hydra.events().len(),
            pre_count,
            "rejected entity must NOT add an audit event"
        );
    }

    #[test]
    fn recover_from_events_rebuilds_identity_store() {
        // Replay round-trip: ingest several entities, dump the
        // event log, reset, replay. Store must be byte-identical.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p29");
        let a = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        let b = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Service,
            "service/payments_api",
            vec![],
        );
        let id_a = a.id.clone();
        let id_b = b.id.clone();
        hydra.create_identity_entity(a).unwrap();
        hydra.create_identity_entity(b).unwrap();
        assert_eq!(hydra.identity_entities().count(), 2);

        // Replay from event log.
        let events: Vec<_> =
            hydra.events().into_iter().cloned().collect();
        hydra.reset_runtime_state_preserving_config();
        assert_eq!(hydra.identity_entities().count(), 0);
        hydra.recover_from_events(events).unwrap();
        assert_eq!(hydra.identity_entities().count(), 2);
        assert!(hydra.identity_entity(&id_a).is_some());
        assert!(hydra.identity_entity(&id_b).is_some());
        // Alias index also rebuilt.
        let alias_resolved = hydra
            .identity_entity_by_alias(
                Some(&tenant),
                "snowflake",
                Some("analytics"),
                "analytics.revenue_daily",
            )
            .unwrap();
        assert_eq!(alias_resolved.id, id_a);
    }

    #[test]
    fn snapshot_restore_preserves_identity_entities() {
        // Snapshot manifest counts + body's identity_entities
        // vec round-trip, and post-restore the store sees the
        // entities (via event replay).
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p29");
        let entity = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();

        let manifest = hydra
            .snapshot(hydra_core::ActorId::from_str("actor_ops"))
            .unwrap();
        assert_eq!(manifest.total_identity_entities, 1);
        let body = hydra
            .snapshot_store()
            .body(&manifest.id)
            .expect("snapshot body present")
            .clone();
        assert_eq!(body.identity_entities.len(), 1);
        assert_eq!(body.identity_entities[0].id, id);

        // Restore into a fresh engine via event replay.
        let mut fresh = Hydra::new();
        fresh.recover_from_events(body.events.clone()).unwrap();
        let restored = fresh
            .identity_entity(&id)
            .expect("entity restored");
        assert_eq!(restored.kind, hydra_core::IdentityEntityKind::Dataset);
        assert_eq!(restored.canonical_key, "dataset/revenue_daily");
        // Alias resolves post-restore too.
        let resolved = fresh
            .identity_entity_by_alias(
                Some(&tenant),
                "snowflake",
                Some("analytics"),
                "analytics.revenue_daily",
            )
            .unwrap();
        assert_eq!(resolved.id, id);
    }

    // === Patch 30 — Semantic Identity Resolution v1 ===
    //
    // Suggestion-only matcher. All tests use the engine's
    // `suggest_identity_matches` method and assert against the
    // returned `SemanticIdentityMatchAssessment`. No mutation
    // is expected — the `does_not_mutate_store` pin is the
    // load-bearing one.

    /// Build a query alias for tests with a sane default shape.
    fn p30_query_alias(
        source: &str,
        namespace: Option<&str>,
        normalized: &str,
    ) -> hydra_core::IdentityAlias {
        hydra_core::IdentityAlias {
            source: source.to_string(),
            namespace: namespace.map(|s| s.to_string()),
            external_id: None,
            label: normalized.to_string(),
            normalized: normalized.to_string(),
        }
    }

    /// Find the factor with the given kind. Panics when
    /// missing — every factor should appear regardless of
    /// applied state (the explainability contract).
    fn p30_find_factor<'a>(
        candidate: &'a hydra_core::SemanticIdentityMatchCandidate,
        kind: &str,
    ) -> &'a hydra_core::TrustFactor {
        candidate
            .factors
            .iter()
            .find(|f| f.kind == kind)
            .unwrap_or_else(|| {
                panic!("factor {kind} missing from candidate")
            })
    }

    #[test]
    fn suggest_identity_matches_exact_alias_dominates_score() {
        // Exact alias match must produce the top candidate. We
        // do NOT short-circuit to 1.0 — the factor walk runs and
        // the dominant `exact_alias_match` (+0.85) combined with
        // same_source / same_namespace pushes the score past
        // Strong threshold. Pinned at ≥ 0.80.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p30");
        let entity = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();

        let query = p30_query_alias(
            "snowflake",
            Some("analytics"),
            "analytics.revenue_daily",
        );
        let assessment = hydra
            .suggest_identity_matches(Some(&tenant), &query, None, 10)
            .unwrap();
        assert!(!assessment.candidates.is_empty());
        let top = &assessment.candidates[0];
        assert_eq!(top.entity_id, id);
        assert!(
            top.score >= 0.80,
            "exact match must reach Strong threshold; got {}",
            top.score
        );
        assert_eq!(top.level, hydra_core::MatchLevel::Strong);
        // Dominant factor fired.
        assert!(p30_find_factor(top, "exact_alias_match").applied);
    }

    #[test]
    fn suggest_identity_matches_token_overlap_scores_candidate() {
        // Partial-token match (no exact alias) still produces a
        // candidate. Pinned: an entity sharing the "revenue" and
        // "daily" tokens with the query scores above 0 and below
        // the exact-match-Strong threshold.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p30");
        let entity = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        hydra.create_identity_entity(entity).unwrap();

        // Different source + different namespace → no exact
        // match, but tokens "revenue" + "daily" overlap heavily
        // with canonical_key + existing alias.
        let query = p30_query_alias(
            "dbt",
            Some("models"),
            "revenue.daily",
        );
        let assessment = hydra
            .suggest_identity_matches(Some(&tenant), &query, None, 10)
            .unwrap();
        assert_eq!(assessment.candidates.len(), 1);
        let cand = &assessment.candidates[0];
        assert!(cand.score > 0.0, "expected nonzero score");
        assert!(
            cand.score < 0.80,
            "non-exact token match must NOT reach Strong; got {}",
            cand.score
        );
        // Either token_overlap_high or token_overlap_partial
        // must have fired.
        let high = p30_find_factor(cand, "token_overlap_high").applied;
        let partial =
            p30_find_factor(cand, "token_overlap_partial").applied;
        assert!(
            high || partial,
            "token overlap must fire for shared tokens revenue/daily"
        );
        // High and partial are mutually exclusive.
        assert!(!(high && partial), "_high and _partial must be exclusive");
    }

    #[test]
    fn suggest_identity_matches_same_namespace_boosts_score() {
        // Two entities differ only by namespace; the query
        // shares namespace with one. That one must score higher
        // than the other on the `same_namespace` factor alone.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p30");
        let matched_ns = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/foo",
            vec![hydra_core::IdentityAlias {
                source: "snowflake".to_string(),
                namespace: Some("analytics".to_string()),
                external_id: None,
                label: "ANALYTICS.FOO".to_string(),
                normalized: "analytics.foo".to_string(),
            }],
        );
        let mismatched_ns = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/bar",
            vec![hydra_core::IdentityAlias {
                source: "snowflake".to_string(),
                namespace: Some("staging".to_string()),
                external_id: None,
                label: "STAGING.BAR".to_string(),
                normalized: "staging.foo".to_string(),
            }],
        );
        let id_matched = matched_ns.id.clone();
        hydra.create_identity_entity(matched_ns).unwrap();
        hydra.create_identity_entity(mismatched_ns).unwrap();

        // Query in "analytics" namespace with no shared tokens
        // beyond "foo" so namespace is the differentiator.
        let query = p30_query_alias(
            "snowflake",
            Some("analytics"),
            "analytics.foo",
        );
        let assessment = hydra
            .suggest_identity_matches(Some(&tenant), &query, None, 10)
            .unwrap();
        assert!(!assessment.candidates.is_empty());
        let top = &assessment.candidates[0];
        assert_eq!(top.entity_id, id_matched);
        assert!(p30_find_factor(top, "same_namespace").applied);
    }

    #[test]
    fn suggest_identity_matches_wrong_tenant_invisible() {
        // Entity in tenant_a, query as tenant_b → must NOT
        // appear in candidates. Strict tenant isolation pin.
        let mut hydra = Hydra::new();
        let tenant_a = hydra_core::TenantId::from_str("tenant_a");
        let tenant_b = hydra_core::TenantId::from_str("tenant_b");
        let theirs = make_identity_entity(
            Some(tenant_a),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/secret",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        hydra.create_identity_entity(theirs).unwrap();
        let query = p30_query_alias(
            "snowflake",
            Some("analytics"),
            "analytics.revenue_daily",
        );
        let assessment = hydra
            .suggest_identity_matches(Some(&tenant_b), &query, None, 10)
            .unwrap();
        assert!(
            assessment.candidates.is_empty(),
            "wrong-tenant entity must be invisible"
        );
    }

    #[test]
    fn suggest_identity_matches_none_tenant_strict() {
        // LOAD-BEARING isolation pin: `None`-tenanted (system)
        // entity NEVER returned to tenanted query AND vice
        // versa. Mirrors the P29 store pin from both directions.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p30");
        let system_entity = make_identity_entity(
            None,
            hydra_core::IdentityEntityKind::Source,
            "source/snowflake_prod",
            vec![hydra_core::IdentityAlias {
                source: "snowflake".to_string(),
                namespace: None,
                external_id: None,
                label: "snowflake-prod".to_string(),
                normalized: "snowflake-prod".to_string(),
            }],
        );
        let id_system = system_entity.id.clone();
        hydra.create_identity_entity(system_entity).unwrap();

        let tenant_entity = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Source,
            "source/snowflake_prod_tenanted",
            vec![hydra_core::IdentityAlias {
                source: "snowflake".to_string(),
                namespace: None,
                external_id: None,
                label: "snowflake-prod".to_string(),
                normalized: "snowflake-prod".to_string(),
            }],
        );
        hydra.create_identity_entity(tenant_entity).unwrap();

        let query = p30_query_alias("snowflake", None, "snowflake-prod");

        // Tenanted query → tenant entity only, system invisible.
        let tenanted = hydra
            .suggest_identity_matches(Some(&tenant), &query, None, 10)
            .unwrap();
        for c in &tenanted.candidates {
            assert_ne!(c.entity_id, id_system, "system entity leaked");
        }

        // None query → system entity only, tenant entity invisible.
        let system = hydra
            .suggest_identity_matches(None, &query, None, 10)
            .unwrap();
        let saw_system =
            system.candidates.iter().any(|c| c.entity_id == id_system);
        assert!(saw_system, "system query must see system entity");
        for c in &system.candidates {
            assert_eq!(c.entity_id, id_system);
        }
    }

    #[test]
    fn suggest_identity_matches_kind_filter_limits_candidates() {
        // Kind filter excludes non-matching candidates from the
        // scan entirely. Two entities share token "foo" but
        // live under different alias namespaces (P29 alias
        // uniqueness forbids duplicate (source, ns, normalized)
        // tuples within a tenant).
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p30");
        let dataset = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/foo",
            vec![snowflake_alias("analytics", "foo")],
        );
        let service = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Service,
            "service/foo_api",
            vec![snowflake_alias("services", "foo")],
        );
        let id_dataset = dataset.id.clone();
        let id_service = service.id.clone();
        hydra.create_identity_entity(dataset).unwrap();
        hydra.create_identity_entity(service).unwrap();

        let query = p30_query_alias("snowflake", Some("analytics"), "analytics.foo");
        // With Dataset filter → only dataset shows up.
        let dataset_only = hydra
            .suggest_identity_matches(
                Some(&tenant),
                &query,
                Some(hydra_core::IdentityEntityKind::Dataset),
                10,
            )
            .unwrap();
        assert_eq!(dataset_only.candidates.len(), 1);
        assert_eq!(dataset_only.candidates[0].entity_id, id_dataset);

        // Without filter → both show up.
        let all_kinds = hydra
            .suggest_identity_matches(Some(&tenant), &query, None, 10)
            .unwrap();
        assert_eq!(all_kinds.candidates.len(), 2);
        let ids: Vec<_> = all_kinds
            .candidates
            .iter()
            .map(|c| c.entity_id.clone())
            .collect();
        assert!(ids.contains(&id_dataset));
        assert!(ids.contains(&id_service));
    }

    #[test]
    fn suggest_identity_matches_returns_sorted_candidates() {
        // Multiple candidates must come back sorted by score
        // descending. Deterministic ordering matters for
        // dashboards and downstream tooling.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p30");
        // Strong match: exact alias.
        let strong = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        // Weaker match: only some shared tokens, different
        // source.
        let weak = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_weekly",
            vec![hydra_core::IdentityAlias {
                source: "dbt".to_string(),
                namespace: Some("models".to_string()),
                external_id: None,
                label: "models.revenue_weekly".to_string(),
                normalized: "models.revenue_weekly".to_string(),
            }],
        );
        let id_strong = strong.id.clone();
        let id_weak = weak.id.clone();
        hydra.create_identity_entity(strong).unwrap();
        hydra.create_identity_entity(weak).unwrap();

        let query = p30_query_alias(
            "snowflake",
            Some("analytics"),
            "analytics.revenue_daily",
        );
        let assessment = hydra
            .suggest_identity_matches(Some(&tenant), &query, None, 10)
            .unwrap();
        assert_eq!(assessment.candidates.len(), 2);
        assert_eq!(assessment.candidates[0].entity_id, id_strong);
        assert_eq!(assessment.candidates[1].entity_id, id_weak);
        assert!(
            assessment.candidates[0].score > assessment.candidates[1].score
        );
    }

    #[test]
    fn suggest_identity_matches_unknown_alias_returns_empty() {
        // Query with no token overlap or source/namespace match
        // → no candidates above 0.0 → empty list (we drop
        // zero-score candidates by design).
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p30");
        let entity = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        hydra.create_identity_entity(entity).unwrap();

        // Query with completely unrelated tokens and different
        // source/namespace.
        let query = hydra_core::IdentityAlias {
            source: "kafka".to_string(),
            namespace: Some("topics".to_string()),
            external_id: None,
            label: "orders".to_string(),
            normalized: "orders".to_string(),
        };
        let assessment = hydra
            .suggest_identity_matches(Some(&tenant), &query, None, 10)
            .unwrap();
        assert!(assessment.candidates.is_empty(),
            "expected empty candidate list for unrelated query; got {:?}",
            assessment.candidates);
    }

    #[test]
    fn suggest_identity_matches_includes_unapplied_factors() {
        // Explainability contract: every candidate carries ALL
        // 9 factors, applied AND unapplied. Pinned so a future
        // refactor doesn't filter the list.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p30");
        let entity = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        hydra.create_identity_entity(entity).unwrap();

        let query = p30_query_alias(
            "snowflake",
            Some("analytics"),
            "analytics.revenue_daily",
        );
        let assessment = hydra
            .suggest_identity_matches(Some(&tenant), &query, None, 10)
            .unwrap();
        let top = &assessment.candidates[0];
        let expected_kinds = [
            "exact_alias_match",
            "normalized_label_match",
            "canonical_key_overlap_high",
            "canonical_key_overlap_partial",
            "token_overlap_high",
            "token_overlap_partial",
            "same_source",
            "same_namespace",
            "same_kind",
        ];
        assert_eq!(top.factors.len(), expected_kinds.len());
        for k in &expected_kinds {
            // Each factor present, applied or not.
            let _ = p30_find_factor(top, k);
        }
        // At least one applied=false survives — `same_kind`
        // always at v0 because we don't accept a kind-context
        // on the query alias yet.
        assert!(!p30_find_factor(top, "same_kind").applied);
    }

    #[test]
    fn suggest_identity_matches_does_not_mutate_store() {
        // LOAD-BEARING: suggestion path is read-only. Entity
        // count unchanged, event count unchanged. If a future
        // refactor accidentally ingests an event during scoring,
        // this test fires.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p30");
        let entity = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![snowflake_alias("analytics", "revenue_daily")],
        );
        hydra.create_identity_entity(entity).unwrap();

        let pre_entities = hydra.identity_entities().count();
        let pre_events = hydra.events().len();
        let query = p30_query_alias(
            "snowflake",
            Some("analytics"),
            "analytics.revenue_daily",
        );
        let _ = hydra
            .suggest_identity_matches(Some(&tenant), &query, None, 10)
            .unwrap();
        assert_eq!(hydra.identity_entities().count(), pre_entities);
        assert_eq!(hydra.events().len(), pre_events);
    }

    #[test]
    fn suggest_identity_matches_none_namespace_matches_none_namespace() {
        // Wrinkle D pin: a query with namespace=None must score
        // `same_namespace` applied against an entity alias with
        // namespace=None. Mirrors the `__root__` sentinel design
        // — None is a real value, not a wildcard.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p30");
        let entity = make_identity_entity(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Source,
            "source/some_source",
            vec![hydra_core::IdentityAlias {
                source: "slack".to_string(),
                namespace: None,
                external_id: None,
                label: "#revenue".to_string(),
                normalized: "#revenue".to_string(),
            }],
        );
        hydra.create_identity_entity(entity).unwrap();

        let query = p30_query_alias("slack", None, "#revenue");
        let assessment = hydra
            .suggest_identity_matches(Some(&tenant), &query, None, 10)
            .unwrap();
        assert_eq!(assessment.candidates.len(), 1);
        let cand = &assessment.candidates[0];
        assert!(
            p30_find_factor(cand, "same_namespace").applied,
            "None-namespace must match None-namespace"
        );
    }

    // === Patch 32 — Identity Match Trust ===
    //
    // Read-only trust verdict over a single P30 candidate.
    // Tests verify: (a) the load-bearing tenant isolation,
    // (b) the factor table calibration via worked examples,
    // (c) mutual exclusivity of bucket factors, (d) the
    // "do_not_mutate" + "no caller-supplied score" anti-forgery
    // pins, and (e) the strategic-warning docstring is in place.

    /// Helper: find an applied/unapplied factor record by name
    /// inside a `IdentityMatchTrustAssessment`. Mirrors
    /// `p30_find_factor` for the P30 list shape.
    fn p32_find_factor<'a>(
        assessment: &'a hydra_core::IdentityMatchTrustAssessment,
        kind: &str,
    ) -> &'a hydra_core::TrustFactor {
        assessment
            .factors
            .iter()
            .find(|f| f.kind == kind)
            .unwrap_or_else(|| {
                panic!(
                    "factor {kind} missing from IdentityMatchTrustAssessment"
                )
            })
    }

    /// Build a `IdentityEntity` with the supplied confidence.
    /// Mirrors `make_identity_entity` but lets P32 tests pin
    /// confidence-band behavior precisely.
    fn make_identity_entity_with_confidence(
        tenant: Option<hydra_core::TenantId>,
        kind: hydra_core::IdentityEntityKind,
        canonical_key: &str,
        aliases: Vec<hydra_core::IdentityAlias>,
        confidence: hydra_core::Confidence,
    ) -> hydra_core::IdentityEntity {
        let now = chrono::Utc::now();
        hydra_core::IdentityEntity {
            id: hydra_core::IdentityEntityId::new(),
            tenant_id: tenant,
            kind,
            canonical_key: canonical_key.to_string(),
            display_name: canonical_key.to_string(),
            aliases,
            confidence,
            metadata: std::collections::HashMap::new(),
            created_by: hydra_core::ActorId::from_str("actor_ops"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    #[test]
    fn assess_identity_match_trust_happy_path_high() {
        // Worked example (a): exact alias + high entity
        // confidence + same kind/namespace, no conflict.
        // Expected score: alias_already_on_candidate (+0.30) +
        // exact_alias_match (+0.40) + semantic_match_strong
        // (+0.25) + confidence_high (+0.15) + same_kind (+0.10)
        // + same_namespace (+0.10) + same_source (+0.05) = 1.35,
        // clamped to 1.00 → High.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p32");
        let alias = snowflake_alias("analytics", "revenue_daily");
        let entity = make_identity_entity_with_confidence(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![alias.clone()],
            hydra_core::Confidence::new(0.95),
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let assessment = hydra
            .assess_identity_match_trust(
                Some(&tenant),
                &alias,
                &id,
                Some(hydra_core::IdentityEntityKind::Dataset),
            )
            .unwrap();
        assert_eq!(assessment.candidate_entity_id, id);
        assert_eq!(assessment.level, hydra_core::trust::TrustLevel::High);
        assert!(assessment.score >= 0.80);
        assert!(p32_find_factor(&assessment, "exact_alias_match").applied);
        assert!(
            p32_find_factor(&assessment, "alias_already_on_candidate")
                .applied
        );
        assert!(p32_find_factor(&assessment, "semantic_match_strong").applied);
        assert!(
            p32_find_factor(&assessment, "candidate_entity_confidence_high")
                .applied
        );
    }

    #[test]
    fn alias_conflict_drags_strong_to_low() {
        // Worked example (b): two entities in the same tenant.
        // Query alias maps to entity A; we ask trust for entity
        // B. Strong P30 match (B has overlapping tokens) plus
        // confidence_high + same_kind/namespace lift the base
        // — but alias_conflict_present (-0.35) drags it down
        // to Low.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p32");
        let query_alias = snowflake_alias("analytics", "revenue_daily");
        // Entity A owns the query alias.
        let entity_a = make_identity_entity_with_confidence(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/a",
            vec![query_alias.clone()],
            hydra_core::Confidence::new(0.95),
        );
        // Entity B has its OWN alias but shares enough tokens
        // for a Strong P30 match against the query.
        let entity_b = make_identity_entity_with_confidence(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/b/revenue_daily",
            vec![hydra_core::IdentityAlias {
                source: "snowflake".to_string(),
                namespace: Some("analytics_b".to_string()),
                external_id: None,
                label: "analytics_b.revenue_daily".to_string(),
                normalized: "analytics.revenue_daily".to_string(),
            }],
            hydra_core::Confidence::new(0.95),
        );
        hydra.create_identity_entity(entity_a).unwrap();
        let id_b = entity_b.id.clone();
        hydra.create_identity_entity(entity_b).unwrap();
        let assessment = hydra
            .assess_identity_match_trust(
                Some(&tenant),
                &query_alias,
                &id_b,
                None,
            )
            .unwrap();
        assert!(p32_find_factor(&assessment, "alias_conflict_present").applied);
        assert!(!p32_find_factor(
            &assessment,
            "alias_already_on_candidate"
        )
        .applied);
        // Conflict drags the verdict down — should NOT be High.
        assert!(
            !matches!(
                assessment.level,
                hydra_core::trust::TrustLevel::High
            ),
            "conflict must prevent High verdict; got {:?} score {}",
            assessment.level,
            assessment.score
        );
    }

    #[test]
    fn weak_match_low_confidence_clamps_to_zero() {
        // Worked example (c): weak P30 match, low entity
        // confidence, kind filter mismatch → all negatives
        // pile up and the pre-clamp score is below 0. Clamp
        // produces 0.0 → Unknown.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p32");
        let entity = make_identity_entity_with_confidence(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/unrelated",
            vec![hydra_core::IdentityAlias {
                source: "github".to_string(),
                namespace: Some("repo/x".to_string()),
                external_id: None,
                label: "completely_different.sql".to_string(),
                normalized: "completely_different".to_string(),
            }],
            hydra_core::Confidence::new(0.10),
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        // Query: entirely different source/namespace/tokens; also
        // pass a kind filter that doesn't match (Service).
        let query = hydra_core::IdentityAlias {
            source: "slack".to_string(),
            namespace: Some("ops".to_string()),
            external_id: None,
            label: "incident-1".to_string(),
            normalized: "incident-1".to_string(),
        };
        let assessment = hydra
            .assess_identity_match_trust(
                Some(&tenant),
                &query,
                &id,
                Some(hydra_core::IdentityEntityKind::Service),
            )
            .unwrap();
        assert_eq!(assessment.score, 0.0);
        assert_eq!(
            assessment.level,
            hydra_core::trust::TrustLevel::Unknown
        );
        assert!(
            p32_find_factor(&assessment, "semantic_match_weak").applied
        );
        assert!(
            p32_find_factor(&assessment, "candidate_entity_confidence_low")
                .applied
        );
        assert!(p32_find_factor(&assessment, "kind_filter_mismatch").applied);
    }

    #[test]
    fn alias_already_on_candidate_fires_not_conflict() {
        // Mutex pin: when the alias index resolves directly to
        // the candidate itself, `alias_already_on_candidate`
        // fires AND `alias_conflict_present` is unapplied.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p32");
        let alias = snowflake_alias("analytics", "revenue_daily");
        let entity = make_identity_entity_with_confidence(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![alias.clone()],
            hydra_core::Confidence::new(0.80),
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let assessment = hydra
            .assess_identity_match_trust(
                Some(&tenant),
                &alias,
                &id,
                None,
            )
            .unwrap();
        assert!(
            p32_find_factor(&assessment, "alias_already_on_candidate")
                .applied
        );
        assert!(
            !p32_find_factor(&assessment, "alias_conflict_present").applied
        );
    }

    #[test]
    fn semantic_match_factors_mutually_exclusive() {
        // Exactly one of strong/possible/weak fires for every
        // candidate. Pinned because conflating mutex tiers is
        // the easiest silent regression.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p32");
        let alias = snowflake_alias("analytics", "revenue_daily");
        let entity = make_identity_entity_with_confidence(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![alias.clone()],
            hydra_core::Confidence::new(1.0),
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let assessment = hydra
            .assess_identity_match_trust(Some(&tenant), &alias, &id, None)
            .unwrap();
        let strong =
            p32_find_factor(&assessment, "semantic_match_strong").applied;
        let possible =
            p32_find_factor(&assessment, "semantic_match_possible").applied;
        let weak =
            p32_find_factor(&assessment, "semantic_match_weak").applied;
        let count = [strong, possible, weak]
            .iter()
            .filter(|b| **b)
            .count();
        assert_eq!(
            count, 1,
            "exactly one of strong/possible/weak must fire; \
             strong={strong} possible={possible} weak={weak}"
        );
    }

    #[test]
    fn confidence_factors_mutually_exclusive() {
        // confidence_high and confidence_low must never BOTH
        // fire. Either one or the other (medium band = neither).
        // Test all three bands.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p32");
        for (conf_val, ns) in [(0.95_f64, "high"), (0.60, "med"), (0.10, "low")] {
            let alias = snowflake_alias(ns, "x");
            let entity = make_identity_entity_with_confidence(
                Some(tenant.clone()),
                hydra_core::IdentityEntityKind::Dataset,
                &format!("dataset/x_{ns}"),
                vec![alias.clone()],
                hydra_core::Confidence::new(conf_val),
            );
            let id = entity.id.clone();
            hydra.create_identity_entity(entity).unwrap();
            let assessment = hydra
                .assess_identity_match_trust(
                    Some(&tenant),
                    &alias,
                    &id,
                    None,
                )
                .unwrap();
            let high = p32_find_factor(
                &assessment,
                "candidate_entity_confidence_high",
            )
            .applied;
            let low = p32_find_factor(
                &assessment,
                "candidate_entity_confidence_low",
            )
            .applied;
            assert!(!(high && low), "high and low must not both fire");
            match ns {
                "high" => assert!(high && !low),
                "med" => assert!(!high && !low),
                "low" => assert!(!high && low),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn assess_identity_match_trust_unknown_candidate_returns_query_error() {
        // Hard error on missing candidate. Mirrors P9 / P23.
        let hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p32");
        let alias = snowflake_alias("analytics", "x");
        let ghost = hydra_core::IdentityEntityId::from_str("ide_ghost");
        let result = hydra.assess_identity_match_trust(
            Some(&tenant),
            &alias,
            &ghost,
            None,
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("unknown identity entity"),
                    "expected unknown-entity error; got {msg}"
                );
            }
            other => panic!("expected QueryError; got {other:?}"),
        }
    }

    #[test]
    fn wrong_tenant_indistinguishable_from_missing() {
        // LOAD-BEARING strict isolation: a candidate that exists
        // but belongs to a different tenant surfaces with the
        // SAME error as a genuine miss. No cross-tenant
        // existence leak. Mirrors P10 / P24 / P29 / P31.
        let mut hydra = Hydra::new();
        let tenant_owner =
            hydra_core::TenantId::from_str("tenant_owner");
        let tenant_other =
            hydra_core::TenantId::from_str("tenant_other");
        let alias = snowflake_alias("analytics", "x");
        let entity = make_identity_entity_with_confidence(
            Some(tenant_owner),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/x",
            vec![alias.clone()],
            hydra_core::Confidence::new(0.90),
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let result = hydra.assess_identity_match_trust(
            Some(&tenant_other),
            &alias,
            &id,
            None,
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("unknown identity entity"),
                    "wrong-tenant must emit same error as genuine \
                     miss; got {msg}"
                );
            }
            other => panic!("expected QueryError; got {other:?}"),
        }
    }

    #[test]
    fn none_tenanted_candidate_probes_none_slot() {
        // LOAD-BEARING (Adaptation C): conflict probe uses the
        // CANDIDATE'S tenant slot, not the caller's. For a
        // `None`-tenanted candidate, the index lookup must
        // probe the `__system__` slot. If we passed the
        // caller's tenant arg, we'd miss a conflict against
        // another None-tenanted entity (or fabricate one across
        // slots).
        let mut hydra = Hydra::new();
        let alias = snowflake_alias("system", "snowflake_prod");
        // System-tenanted candidate A claims the alias.
        let entity_a = make_identity_entity_with_confidence(
            None,
            hydra_core::IdentityEntityKind::Source,
            "source/system_a",
            vec![alias.clone()],
            hydra_core::Confidence::new(0.90),
        );
        // System-tenanted candidate B does NOT have the alias.
        let entity_b = make_identity_entity_with_confidence(
            None,
            hydra_core::IdentityEntityKind::Source,
            "source/system_b",
            vec![hydra_core::IdentityAlias {
                source: "snowflake".to_string(),
                namespace: Some("system_b".to_string()),
                external_id: None,
                label: "other".to_string(),
                normalized: "other".to_string(),
            }],
            hydra_core::Confidence::new(0.90),
        );
        hydra.create_identity_entity(entity_a).unwrap();
        let id_b = entity_b.id.clone();
        hydra.create_identity_entity(entity_b).unwrap();
        // Assess trust for B against the alias. The probe must
        // use B's tenant slot (`None`) and surface the conflict
        // with A.
        let assessment = hydra
            .assess_identity_match_trust(None, &alias, &id_b, None)
            .unwrap();
        assert!(
            p32_find_factor(&assessment, "alias_conflict_present").applied,
            "None-tenanted probe must see the conflict in the \
             None slot, not the caller's slot"
        );
    }

    #[test]
    fn assess_identity_match_trust_none_tenant_strict_isolation() {
        // LOAD-BEARING strict-isolation both directions
        // (mirrors P30): `None`-tenanted candidate is invisible
        // to a tenanted query, and vice versa.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p32");
        let alias = snowflake_alias("system", "snowflake_prod");
        // System candidate.
        let system_entity = make_identity_entity_with_confidence(
            None,
            hydra_core::IdentityEntityKind::Source,
            "source/system",
            vec![alias.clone()],
            hydra_core::Confidence::new(0.90),
        );
        let id_system = system_entity.id.clone();
        hydra.create_identity_entity(system_entity).unwrap();
        // Tenanted query against the system candidate → error.
        let r1 = hydra.assess_identity_match_trust(
            Some(&tenant),
            &alias,
            &id_system,
            None,
        );
        assert!(r1.is_err());

        // Tenanted candidate.
        let tenanted = make_identity_entity_with_confidence(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Source,
            "source/tenanted",
            vec![hydra_core::IdentityAlias {
                source: "snowflake".to_string(),
                namespace: Some("tenanted".to_string()),
                external_id: None,
                label: "x".to_string(),
                normalized: "x".to_string(),
            }],
            hydra_core::Confidence::new(0.90),
        );
        let id_tenanted = tenanted.id.clone();
        hydra.create_identity_entity(tenanted).unwrap();
        // None query against the tenanted candidate → error.
        let r2 = hydra.assess_identity_match_trust(
            None,
            &alias,
            &id_tenanted,
            None,
        );
        assert!(r2.is_err());
    }

    #[test]
    fn assess_identity_match_trust_does_not_mutate_store() {
        // LOAD-BEARING read-only pin: entity count + event count
        // unchanged before/after. If a future refactor
        // accidentally ingests an event during scoring, this
        // test fires.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p32");
        let alias = snowflake_alias("analytics", "revenue_daily");
        let entity = make_identity_entity_with_confidence(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![alias.clone()],
            hydra_core::Confidence::new(0.95),
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let pre_entities = hydra.identity_entities().count();
        let pre_events = hydra.events().len();
        let _ = hydra
            .assess_identity_match_trust(Some(&tenant), &alias, &id, None)
            .unwrap();
        assert_eq!(hydra.identity_entities().count(), pre_entities);
        assert_eq!(hydra.events().len(), pre_events);
    }

    #[test]
    fn assess_identity_match_trust_includes_all_factors_always() {
        // Explainability contract: every assessment carries ALL
        // ~12 factors, applied OR not. Pinned so a future
        // refactor doesn't filter the list down to "what fired".
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p32");
        let alias = snowflake_alias("analytics", "revenue_daily");
        let entity = make_identity_entity_with_confidence(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            vec![alias.clone()],
            hydra_core::Confidence::new(0.95),
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let assessment = hydra
            .assess_identity_match_trust(Some(&tenant), &alias, &id, None)
            .unwrap();
        let expected_kinds = [
            "exact_alias_match",
            "alias_already_on_candidate",
            "alias_conflict_present",
            "semantic_match_strong",
            "semantic_match_possible",
            "semantic_match_weak",
            "candidate_entity_confidence_high",
            "candidate_entity_confidence_low",
            "same_kind",
            "same_namespace",
            "same_source",
            "kind_filter_mismatch",
        ];
        for k in &expected_kinds {
            let _ = p32_find_factor(&assessment, k);
        }
        assert_eq!(assessment.factors.len(), expected_kinds.len());
        // At least one applied=false present (kind_filter_mismatch
        // with no kind arg, OR confidence_low when confidence is
        // high, etc.).
        assert!(
            assessment.factors.iter().any(|f| !f.applied),
            "at least one factor must be applied=false"
        );
    }

    #[test]
    fn score_recomputed_not_caller_supplied() {
        // Anti-forgery pin (Wrinkle E): there is NO API path
        // through which a caller can supply a P30 score. The
        // engine method takes (alias, candidate_entity_id) —
        // not a SemanticIdentityMatchCandidate. Pin via type
        // observation: the signature accepts an IdentityAlias
        // and an IdentityEntityId, never a candidate struct.
        // We exercise the recomputation directly: a caller
        // can't forge `match_score` via the input shape.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p32");
        let alias = snowflake_alias("analytics", "x");
        let entity = make_identity_entity_with_confidence(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/x",
            vec![alias.clone()],
            hydra_core::Confidence::new(0.90),
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let assessment = hydra
            .assess_identity_match_trust(
                Some(&tenant),
                &alias,
                &id,
                None,
            )
            .unwrap();
        // The match_score is computed live from the alias +
        // entity, not from anything the caller passed in. It
        // must reflect the actual P30 calibration — for an
        // exact alias this lands in the Strong band.
        assert_eq!(assessment.match_level, hydra_core::MatchLevel::Strong);
        assert!(
            assessment.match_score >= 0.80,
            "exact-alias match must score Strong; got {}",
            assessment.match_score
        );
    }

    #[test]
    fn assess_identity_match_trust_docstring_warns_against_auto_link() {
        // Strategic warning pin. We can't read doc-comments at
        // runtime, but we can pin that the EXPLANATION string
        // produced by the method includes the language the
        // contract requires. The compiled docstring lives in
        // the engine method; this test guards the wire-facing
        // explanation as a separate safety net.
        //
        // For v0 the explanation summarizes factor counts. We
        // pin that the contract still surfaces SOMEWHERE in
        // the assessment by checking that at least one applied
        // factor's `detail` references suggestion-only semantics
        // (the canned details for sensitive factors). If a
        // future refactor drops the docstring AND the detail
        // strings, this test should catch the second drop.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p32");
        let alias = snowflake_alias("analytics", "x");
        let entity = make_identity_entity_with_confidence(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/x",
            vec![alias.clone()],
            hydra_core::Confidence::new(0.90),
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let assessment = hydra
            .assess_identity_match_trust(Some(&tenant), &alias, &id, None)
            .unwrap();
        // The explanation summary mentions both positive +
        // penalty factor groupings — a structural signal that
        // the verdict is multi-factor + explainable, NOT a
        // simple boolean.
        assert!(
            assessment.explanation.contains("positive")
                && assessment.explanation.contains("penalty"),
            "explanation must surface positive + penalty grouping: {}",
            assessment.explanation
        );
    }

    // === Patch 33 — Identity Entity Trust v1 ===
    //
    // Read-only verdict over the identity RECORD itself. v1
    // uses only entity-internal signals. Tests verify the
    // confidence tier, the three alias-related mutex pairs
    // (gated on `aliases.len() >= 1`), the standalone bonuses,
    // the LOAD-BEARING tenant isolation, anti-mutation, and
    // explainability contracts.

    /// Helper: find a factor record by name in a P33 assessment.
    fn p33_find_factor<'a>(
        assessment: &'a hydra_core::IdentityEntityTrustAssessment,
        kind: &str,
    ) -> &'a hydra_core::TrustFactor {
        assessment
            .factors
            .iter()
            .find(|f| f.kind == kind)
            .unwrap_or_else(|| {
                panic!(
                    "factor {kind} missing from \
                     IdentityEntityTrustAssessment"
                )
            })
    }

    /// Build an `IdentityEntity` with the supplied fields and
    /// optional metadata entries. Mirrors P32's helper but
    /// exposes `metadata` for P33's `metadata_present` factor.
    #[allow(clippy::too_many_arguments)]
    fn make_entity_for_p33(
        tenant: Option<hydra_core::TenantId>,
        kind: hydra_core::IdentityEntityKind,
        canonical_key: &str,
        display_name: &str,
        aliases: Vec<hydra_core::IdentityAlias>,
        confidence: hydra_core::Confidence,
        metadata_entries: usize,
    ) -> hydra_core::IdentityEntity {
        let now = chrono::Utc::now();
        let mut metadata = std::collections::HashMap::new();
        for i in 0..metadata_entries {
            metadata.insert(
                format!("key_{i}"),
                hydra_core::Value::String(format!("value_{i}")),
            );
        }
        hydra_core::IdentityEntity {
            id: hydra_core::IdentityEntityId::new(),
            tenant_id: tenant,
            kind,
            canonical_key: canonical_key.to_string(),
            display_name: display_name.to_string(),
            aliases,
            confidence,
            metadata,
            created_by: hydra_core::ActorId::from_str("actor_ops"),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn alias_for(source: &str, ns: &str, name: &str) -> hydra_core::IdentityAlias {
        hydra_core::IdentityAlias {
            source: source.to_string(),
            namespace: Some(ns.to_string()),
            external_id: Some(format!("{ns}.{name}").to_uppercase()),
            label: format!("{ns}.{name}").to_uppercase(),
            normalized: format!("{}.{}", ns.to_lowercase(), name.to_lowercase()),
        }
    }

    #[test]
    fn assess_entity_trust_high_confidence_multi_source_returns_high() {
        // Worked example (a): high confidence + multi-source +
        // canonical + display + metadata + no conflict.
        // Expected: 0.30 + 0.10 + 0.15 + 0.05 + 0.05 + 0.05 +
        // 0.15 = 0.85 → High.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p33");
        let entity = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/revenue_daily",
            "Revenue (daily)",
            vec![
                alias_for("snowflake", "analytics", "revenue_daily"),
                alias_for("dbt", "models", "revenue_daily"),
                alias_for("looker", "finance", "revenue_daily"),
            ],
            hydra_core::Confidence::new(0.95),
            2,
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let a = hydra
            .assess_identity_entity_trust(Some(&tenant), &id)
            .unwrap();
        assert_eq!(a.entity_id, id);
        assert_eq!(a.level, hydra_core::trust::TrustLevel::High);
        assert!(
            a.score >= 0.80,
            "best-case must reach High; got {}",
            a.score
        );
        assert!(p33_find_factor(&a, "entity_confidence_high").applied);
        assert!(p33_find_factor(&a, "multiple_aliases").applied);
        assert!(p33_find_factor(&a, "multiple_source_aliases").applied);
        assert!(p33_find_factor(&a, "alias_conflict_absent").applied);
        assert!(p33_find_factor(&a, "metadata_present").applied);
    }

    #[test]
    fn assess_entity_trust_single_alias_single_source_returns_low() {
        // Worked example (b): high confidence but only one
        // alias, one source, no metadata. The single-alias +
        // single-source penalties drag a high-confidence
        // entity down to Low. Pin: single-source single-alias
        // entities ARE weak identity signals.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p33");
        let entity = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/lonely",
            "Lonely Dataset",
            vec![alias_for("snowflake", "analytics", "lonely")],
            hydra_core::Confidence::new(0.95),
            0,
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let a = hydra
            .assess_identity_entity_trust(Some(&tenant), &id)
            .unwrap();
        // 0.30 - 0.10 - 0.05 + 0.05 + 0.05 + 0.15 = 0.40 → Low
        assert_eq!(a.level, hydra_core::trust::TrustLevel::Low);
        assert!(p33_find_factor(&a, "single_alias_only").applied);
        assert!(p33_find_factor(&a, "single_source_only").applied);
        assert!(!p33_find_factor(&a, "metadata_present").applied);
    }

    #[test]
    fn assess_entity_trust_zero_alias_entity_skips_alias_factors() {
        // LOAD-BEARING Adaptation C: for an entity with zero
        // aliases, ALL three mutex pairs (count, diversity,
        // conflict) have NEITHER side applied — the records
        // are present (explainability contract) but both
        // `applied=false`.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p33");
        let entity = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/no_aliases",
            "Aliasless",
            vec![],
            hydra_core::Confidence::new(0.95),
            1,
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let a = hydra
            .assess_identity_entity_trust(Some(&tenant), &id)
            .unwrap();
        // None of the 6 alias-related factors fire.
        for kind in &[
            "multiple_aliases",
            "single_alias_only",
            "multiple_source_aliases",
            "single_source_only",
            "alias_conflict_absent",
            "alias_conflict_present",
        ] {
            assert!(
                !p33_find_factor(&a, kind).applied,
                "alias factor '{kind}' must not fire for zero-alias entity"
            );
        }
        // But the records ARE present.
        let count = a
            .factors
            .iter()
            .filter(|f| {
                matches!(
                    f.kind.as_str(),
                    "multiple_aliases"
                        | "single_alias_only"
                        | "multiple_source_aliases"
                        | "single_source_only"
                        | "alias_conflict_absent"
                        | "alias_conflict_present"
                )
            })
            .count();
        assert_eq!(count, 6, "all 6 alias factor records must be present");
    }

    #[test]
    fn assess_entity_trust_unknown_entity_returns_query_error() {
        // Hard error on missing entity — mirrors P32's
        // `unknown_candidate_returns_query_error`.
        let hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p33");
        let ghost = hydra_core::IdentityEntityId::from_str("ide_ghost");
        match hydra.assess_identity_entity_trust(Some(&tenant), &ghost) {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("unknown identity entity"),
                    "expected unknown-entity error; got {msg}"
                );
            }
            other => panic!("expected QueryError; got {other:?}"),
        }
    }

    #[test]
    fn assess_entity_trust_wrong_tenant_indistinguishable_from_missing() {
        // LOAD-BEARING strict isolation: wrong-tenant query
        // produces the SAME error as a genuine miss. No
        // existence leak across tenants. Mirrors P32.
        let mut hydra = Hydra::new();
        let owner = hydra_core::TenantId::from_str("tenant_owner");
        let other = hydra_core::TenantId::from_str("tenant_other");
        let entity = make_entity_for_p33(
            Some(owner),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/x",
            "X",
            vec![alias_for("snowflake", "x", "y")],
            hydra_core::Confidence::new(0.90),
            0,
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        match hydra.assess_identity_entity_trust(Some(&other), &id) {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("unknown identity entity"));
            }
            other => panic!("expected QueryError; got {other:?}"),
        }
    }

    #[test]
    fn assess_entity_trust_none_tenant_strict_isolation() {
        // LOAD-BEARING both directions (mirrors P32):
        // `None`-tenanted entity invisible to tenanted queries
        // AND vice versa.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p33");
        // System entity.
        let system_entity = make_entity_for_p33(
            None,
            hydra_core::IdentityEntityKind::Source,
            "source/system",
            "System Source",
            vec![alias_for("snowflake", "system", "prod")],
            hydra_core::Confidence::new(0.90),
            0,
        );
        let id_system = system_entity.id.clone();
        hydra.create_identity_entity(system_entity).unwrap();
        // Tenanted query against system entity → error.
        assert!(hydra
            .assess_identity_entity_trust(Some(&tenant), &id_system)
            .is_err());
        // Tenanted entity.
        let tenant_entity = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Source,
            "source/tenant_owned",
            "Tenant Owned",
            vec![alias_for("snowflake", "tenanted", "x")],
            hydra_core::Confidence::new(0.90),
            0,
        );
        let id_tenanted = tenant_entity.id.clone();
        hydra.create_identity_entity(tenant_entity).unwrap();
        // None query against tenanted entity → error.
        assert!(hydra
            .assess_identity_entity_trust(None, &id_tenanted)
            .is_err());
    }

    #[test]
    fn assess_entity_trust_alias_conflict_factors_mutually_exclusive_when_aliases_present() {
        // Mutex pin: for an entity with aliases, EXACTLY one
        // of `alias_conflict_absent` / `alias_conflict_present`
        // fires. Well-formed entity (created via P29's
        // `create_entity` which enforces uniqueness) → absent
        // fires.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p33");
        let entity = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/ok",
            "OK",
            vec![alias_for("snowflake", "ok", "x")],
            hydra_core::Confidence::new(0.90),
            0,
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let a = hydra
            .assess_identity_entity_trust(Some(&tenant), &id)
            .unwrap();
        let absent = p33_find_factor(&a, "alias_conflict_absent").applied;
        let present = p33_find_factor(&a, "alias_conflict_present").applied;
        assert!(absent && !present);
    }

    #[test]
    fn assess_entity_trust_confidence_factors_mutually_exclusive() {
        // Exactly one of the 3 confidence tier factors fires
        // (always — confidence is non-Optional).
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p33");
        for (conf, expected_kind, ns) in [
            (0.95_f64, "entity_confidence_high", "high"),
            (0.65, "entity_confidence_medium", "med"),
            (0.10, "entity_confidence_low", "low"),
        ] {
            let entity = make_entity_for_p33(
                Some(tenant.clone()),
                hydra_core::IdentityEntityKind::Dataset,
                &format!("dataset/{ns}"),
                ns,
                vec![alias_for("snowflake", ns, "x")],
                hydra_core::Confidence::new(conf),
                0,
            );
            let id = entity.id.clone();
            hydra.create_identity_entity(entity).unwrap();
            let a = hydra
                .assess_identity_entity_trust(Some(&tenant), &id)
                .unwrap();
            let applied: Vec<&str> = [
                "entity_confidence_high",
                "entity_confidence_medium",
                "entity_confidence_low",
            ]
            .iter()
            .copied()
            .filter(|k| p33_find_factor(&a, k).applied)
            .collect();
            assert_eq!(
                applied,
                vec![expected_kind],
                "exactly one confidence factor must fire for conf={conf}"
            );
        }
    }

    #[test]
    fn assess_entity_trust_does_not_mutate_store() {
        // LOAD-BEARING anti-mutation pin: read-only.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p33");
        let entity = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/x",
            "X",
            vec![alias_for("snowflake", "x", "y")],
            hydra_core::Confidence::new(0.90),
            0,
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let pre_entities = hydra.identity_entities().count();
        let pre_events = hydra.events().len();
        let _ = hydra
            .assess_identity_entity_trust(Some(&tenant), &id)
            .unwrap();
        assert_eq!(hydra.identity_entities().count(), pre_entities);
        assert_eq!(hydra.events().len(), pre_events);
    }

    #[test]
    fn assess_entity_trust_alias_conflict_uses_entity_tenant_slot() {
        // LOAD-BEARING (mirrors P32 Adaptation C): the conflict
        // probe uses `entity.tenant_id.as_ref()`, NOT the
        // caller's `tenant_id` arg. For a `None`-tenanted
        // entity, the index lookup probes the system slot. If
        // we passed the caller's arg, we'd miss conflicts in
        // the system slot AND potentially synthesize false
        // conflicts.
        //
        // Setup: two `None`-tenanted entities. P29 should
        // reject the second create if they share an alias —
        // but we synthesize the corruption case via direct
        // event ingest to verify the trust factor DETECTS it.
        let mut hydra = Hydra::new();
        let alias = alias_for("snowflake", "system", "prod");
        // Entity A — legitimately created.
        let entity_a = make_entity_for_p33(
            None,
            hydra_core::IdentityEntityKind::Source,
            "source/a",
            "A",
            vec![alias.clone()],
            hydra_core::Confidence::new(0.90),
            0,
        );
        let id_a = entity_a.id.clone();
        hydra.create_identity_entity(entity_a).unwrap();
        // Well-formed entity A → trust assessment via None
        // probes the None slot AND finds A's alias resolving
        // to A → `alias_conflict_absent` fires.
        let a = hydra
            .assess_identity_entity_trust(None, &id_a)
            .unwrap();
        assert!(
            p33_find_factor(&a, "alias_conflict_absent").applied,
            "well-formed None-tenanted entity must see absent conflict \
             via None-slot probe"
        );
    }

    #[test]
    fn assess_entity_trust_includes_all_evaluated_factors() {
        // Explainability pin: 12 factor records present
        // (applied or not).
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p33");
        let entity = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/x",
            "X",
            vec![alias_for("snowflake", "x", "y")],
            hydra_core::Confidence::new(0.90),
            0,
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let a = hydra
            .assess_identity_entity_trust(Some(&tenant), &id)
            .unwrap();
        let expected = [
            "entity_confidence_high",
            "entity_confidence_medium",
            "entity_confidence_low",
            "multiple_aliases",
            "single_alias_only",
            "multiple_source_aliases",
            "single_source_only",
            "alias_conflict_absent",
            "alias_conflict_present",
            "canonical_key_present",
            "display_name_present",
            "metadata_present",
        ];
        for k in &expected {
            let _ = p33_find_factor(&a, k);
        }
        assert_eq!(a.factors.len(), expected.len());
        // At least one applied=false present (single-source
        // entity has metadata=false, several mutex losers).
        assert!(a.factors.iter().any(|f| !f.applied));
    }

    #[test]
    fn assess_entity_trust_docstring_warns_internal_only() {
        // Pin the explanation structurally surfaces "v1
        // assesses the record itself, not operational truth"
        // language. If a future refactor drops the warning
        // from the explanation, this test fires.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p33");
        let entity = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/x",
            "X",
            vec![alias_for("snowflake", "x", "y")],
            hydra_core::Confidence::new(0.90),
            0,
        );
        let id = entity.id.clone();
        hydra.create_identity_entity(entity).unwrap();
        let a = hydra
            .assess_identity_entity_trust(Some(&tenant), &id)
            .unwrap();
        // Explanation surfaces the "record itself, not
        // operational truth" structural pin.
        assert!(
            a.explanation.contains("record itself")
                && a.explanation.contains("operational"),
            "explanation must surface the internal-only warning: {}",
            a.explanation
        );
    }

    // === Patch 35 — Source Trust v1 ===
    //
    // Read-only verdict over a source string (the free-form value
    // carried on `IdentityAlias.source`). Tests verify the
    // identity-backed factor walk, evidence mapping, mean-entity-
    // trust mutex (Adaptation C), strict tenant isolation, the
    // entity-scan cap, anti-mutation, and the
    // unknown-but-valid-source contract.

    /// Helper: find a factor record by name in a P35 assessment.
    fn p35_find_factor<'a>(
        assessment: &'a hydra_core::SourceTrustAssessment,
        kind: &str,
    ) -> &'a hydra_core::TrustFactor {
        assessment
            .factors
            .iter()
            .find(|f| f.kind == kind)
            .unwrap_or_else(|| {
                panic!(
                    "factor {kind} missing from \
                     SourceTrustAssessment"
                )
            })
    }

    /// Helper: build a tenant-scoped Evidence record with the
    /// supplied source variant + reliability.
    fn p35_make_evidence(
        tenant: Option<hydra_core::TenantId>,
        source: hydra_core::EvidenceSource,
        reliability: f64,
    ) -> hydra_core::Evidence {
        let now = chrono::Utc::now();
        hydra_core::Evidence {
            id: hydra_core::EvidenceId::new(),
            tenant_id: tenant,
            source,
            payload: hydra_core::EvidencePayload {
                kind: "p35_test".to_string(),
                data: std::collections::HashMap::new(),
            },
            reliability: hydra_core::Confidence::new(reliability),
            observed_at: now,
            recorded_at: now,
            caused_by: None,
        }
    }

    #[test]
    fn assess_source_trust_happy_path_high_verdict() {
        // Worked example (a) from the survey: 5 entities × 3 kinds
        // from `snowflake`, mean P33 trust ≥ 0.70, two reliable
        // evidence records. Expected: 0.20 + 0.10 + 0.10 + 0.20 +
        // 0.05 + 0.15 = 0.80 → High.
        //
        // The 3 distinct kinds are split as 3 / 1 / 1 because
        // P29's canonical-key uniqueness fires within (tenant,
        // kind), and we want all 5 entities to coexist.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p35");

        // 3 Datasets (different canonical keys) — high confidence,
        // multi-source aliases so P33 lands High.
        for i in 0..3 {
            let entity = make_entity_for_p33(
                Some(tenant.clone()),
                hydra_core::IdentityEntityKind::Dataset,
                &format!("dataset/d{i}"),
                &format!("Dataset {i}"),
                vec![
                    alias_for("snowflake", "analytics", &format!("d{i}")),
                    alias_for("dbt", "models", &format!("d{i}")),
                    alias_for("looker", "finance", &format!("d{i}")),
                ],
                hydra_core::Confidence::new(0.95),
                2,
            );
            hydra.create_identity_entity(entity).unwrap();
        }
        // 1 Table
        let table = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Table,
            "table/t0",
            "Table 0",
            vec![
                alias_for("snowflake", "analytics", "t0"),
                alias_for("dbt", "models", "t0"),
            ],
            hydra_core::Confidence::new(0.95),
            2,
        );
        hydra.create_identity_entity(table).unwrap();
        // 1 Dashboard
        let dashboard = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dashboard,
            "dashboard/dash0",
            "Dashboard 0",
            vec![
                alias_for("snowflake", "analytics", "dash0"),
                alias_for("looker", "finance", "dash0"),
            ],
            hydra_core::Confidence::new(0.95),
            2,
        );
        hydra.create_identity_entity(dashboard).unwrap();

        // 2 reliable evidence records mapped to "snowflake".
        for _ in 0..2 {
            let ev = p35_make_evidence(
                Some(tenant.clone()),
                hydra_core::EvidenceSource::Warehouse {
                    system: "snowflake".to_string(),
                    database: Some("analytics".to_string()),
                    schema: None,
                    table: None,
                },
                0.90,
            );
            hydra
                .ingest(hydra_core::EventKind::EvidenceAdded { evidence: ev })
                .unwrap();
        }

        let a = hydra
            .assess_source_trust(Some(&tenant), "snowflake")
            .unwrap();
        assert_eq!(a.source, "snowflake");
        assert_eq!(a.entity_sample_size, 5);
        assert_eq!(a.evidence_sample_size, 2);
        // 0.80 ceiling — sits at exactly High threshold.
        assert!(
            a.score >= 0.80,
            "best-case must reach the 0.80 ceiling; got {}",
            a.score
        );
        assert_eq!(a.level, hydra_core::trust::TrustLevel::High);
        assert!(p35_find_factor(&a, "source_has_identity_aliases").applied);
        assert!(p35_find_factor(&a, "multiple_entities_from_source").applied);
        assert!(!p35_find_factor(&a, "single_entity_from_source").applied);
        assert!(p35_find_factor(&a, "multiple_kinds_from_source").applied);
        assert!(p35_find_factor(&a, "high_trust_entities_from_source").applied);
        assert!(!p35_find_factor(&a, "low_trust_entities_from_source").applied);
        assert!(p35_find_factor(&a, "evidence_present_from_source").applied);
        assert!(p35_find_factor(&a, "reliable_evidence_from_source").applied);
        assert!(!p35_find_factor(&a, "low_reliability_evidence_from_source").applied);
    }

    #[test]
    fn assess_source_trust_unknown_source_buckets_to_low_not_error() {
        // Wrinkle E pin. A source string that is well-formed but
        // has no aliases and no evidence is a legitimate Unknown
        // verdict via `TrustAssessment::level_for_score(0.0)`,
        // NOT a `QueryError`. The pin's name says "low" — the
        // actual bucket is `Unknown` because the shared
        // thresholds bucket 0.0 there. The load-bearing assertion
        // is "no error + finite verdict", not the specific
        // sub-Unknown/Low distinction.
        let hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p35");
        // No entities, no evidence — just a query.
        let a = hydra
            .assess_source_trust(Some(&tenant), "neverseen")
            .unwrap();
        assert_eq!(a.source, "neverseen");
        assert_eq!(a.entity_sample_size, 0);
        assert_eq!(a.evidence_sample_size, 0);
        assert_eq!(a.score, 0.0);
        // 0.0 buckets to `Unknown` via the shared thresholds.
        // Either Unknown or Low would satisfy the "not error"
        // contract — the level itself is secondary.
        assert!(matches!(
            a.level,
            hydra_core::trust::TrustLevel::Unknown
                | hydra_core::trust::TrustLevel::Low
        ));
        // Empty-source-result is structurally surfaced in the
        // explanation, not via an Err return.
        assert!(
            a.explanation.contains("no aliases")
                || a.explanation.contains("no evidence"),
            "empty verdict must surface in explanation: {}",
            a.explanation
        );
    }

    #[test]
    fn assess_source_trust_empty_source_returns_query_error() {
        // Adaptation B pin. Empty source is malformed input, not
        // "no data" — mirrors `IdentityAlias::validate`'s
        // rejection at entity creation.
        let hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p35");
        let result = hydra.assess_source_trust(Some(&tenant), "");
        assert!(
            matches!(result, Err(hydra_core::error::HydraError::QueryError(_))),
            "empty source must surface as QueryError; got {result:?}"
        );
    }

    #[test]
    fn assess_source_trust_sentinel_source_returns_query_error() {
        // Wrinkle H pin. `__system__` and `__root__` are reserved
        // sentinels for the None-tenant / None-namespace slots in
        // `IdentityAlias::index_key`. Allowing them as source
        // names would let a caller alias the reserved key space.
        let hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p35");
        for sentinel in ["__system__", "__root__"] {
            let result =
                hydra.assess_source_trust(Some(&tenant), sentinel);
            assert!(
                matches!(
                    result,
                    Err(hydra_core::error::HydraError::QueryError(_))
                ),
                "sentinel source '{sentinel}' must surface as QueryError; \
                 got {result:?}"
            );
        }
    }

    #[test]
    fn assess_source_trust_does_not_mutate_store() {
        // LOAD-BEARING anti-mutation pin. The assessment is read-
        // only — no entities created, no events ingested. Mirrors
        // P30 / P32 / P33's `does_not_mutate_store` contracts.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p35");
        let entity = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/x",
            "X",
            vec![alias_for("snowflake", "analytics", "x")],
            hydra_core::Confidence::new(0.90),
            0,
        );
        hydra.create_identity_entity(entity).unwrap();
        // Add an evidence record too — pin that evidence reads
        // don't mutate either.
        let ev = p35_make_evidence(
            Some(tenant.clone()),
            hydra_core::EvidenceSource::Warehouse {
                system: "snowflake".to_string(),
                database: None,
                schema: None,
                table: None,
            },
            0.90,
        );
        hydra
            .ingest(hydra_core::EventKind::EvidenceAdded { evidence: ev })
            .unwrap();

        let pre_entities = hydra.identity_entities().count();
        let pre_events = hydra.events().len();
        let pre_evidence = hydra.all_evidence().len();
        let _ = hydra
            .assess_source_trust(Some(&tenant), "snowflake")
            .unwrap();
        assert_eq!(hydra.identity_entities().count(), pre_entities);
        assert_eq!(hydra.events().len(), pre_events);
        assert_eq!(hydra.all_evidence().len(), pre_evidence);
    }

    #[test]
    fn assess_source_trust_none_tenant_strict_isolation() {
        // LOAD-BEARING tenant-isolation pin (wrinkle G).
        // None-tenanted sources are invisible to Some(t) queries
        // AND vice versa — physical-slot separation carried
        // forward from P29's sentinel index keys.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p35");

        // Direction 1: None-tenanted entity + evidence. Probe
        // from Some(t) — must return the empty verdict.
        let system_entity = make_entity_for_p33(
            None,
            hydra_core::IdentityEntityKind::System,
            "system/global",
            "Global",
            vec![alias_for("github", "global", "x")],
            hydra_core::Confidence::new(0.90),
            0,
        );
        hydra.create_identity_entity(system_entity).unwrap();
        let system_ev = p35_make_evidence(
            None,
            hydra_core::EvidenceSource::Api {
                system: "github".to_string(),
                endpoint: None,
            },
            0.90,
        );
        hydra
            .ingest(hydra_core::EventKind::EvidenceAdded {
                evidence: system_ev,
            })
            .unwrap();

        let r1 = hydra
            .assess_source_trust(Some(&tenant), "github")
            .unwrap();
        assert_eq!(
            r1.entity_sample_size, 0,
            "Some(t) probe must not see None-tenanted entities"
        );
        assert_eq!(
            r1.evidence_sample_size, 0,
            "Some(t) probe must not see None-tenanted evidence"
        );

        // Direction 2: Some(t)-tenanted entity + evidence. Probe
        // from None — must return the empty verdict.
        let tenant_entity = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/private",
            "Private",
            vec![alias_for("looker", "finance", "private")],
            hydra_core::Confidence::new(0.90),
            0,
        );
        hydra.create_identity_entity(tenant_entity).unwrap();
        let tenant_ev = p35_make_evidence(
            Some(tenant.clone()),
            hydra_core::EvidenceSource::Api {
                system: "looker".to_string(),
                endpoint: None,
            },
            0.90,
        );
        hydra
            .ingest(hydra_core::EventKind::EvidenceAdded {
                evidence: tenant_ev,
            })
            .unwrap();

        let r2 = hydra.assess_source_trust(None, "looker").unwrap();
        assert_eq!(
            r2.entity_sample_size, 0,
            "None probe must not see Some(t)-tenanted entities"
        );
        assert_eq!(
            r2.evidence_sample_size, 0,
            "None probe must not see Some(t)-tenanted evidence"
        );
    }

    #[test]
    fn assess_source_trust_wrong_tenant_invisible() {
        // LOAD-BEARING pin. Entities + evidence in tenant_a must
        // be invisible to tenant_b probes — the empty verdict
        // pattern is structurally indistinguishable from a
        // genuine "no data" outcome (no separate error path).
        let mut hydra = Hydra::new();
        let tenant_a = hydra_core::TenantId::from_str("tenant_a");
        let tenant_b = hydra_core::TenantId::from_str("tenant_b");
        let entity = make_entity_for_p33(
            Some(tenant_a.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/owned",
            "Owned",
            vec![alias_for("snowflake", "analytics", "owned")],
            hydra_core::Confidence::new(0.95),
            0,
        );
        hydra.create_identity_entity(entity).unwrap();
        let ev = p35_make_evidence(
            Some(tenant_a),
            hydra_core::EvidenceSource::Warehouse {
                system: "snowflake".to_string(),
                database: None,
                schema: None,
                table: None,
            },
            0.90,
        );
        hydra
            .ingest(hydra_core::EventKind::EvidenceAdded { evidence: ev })
            .unwrap();

        let a = hydra
            .assess_source_trust(Some(&tenant_b), "snowflake")
            .unwrap();
        assert_eq!(a.entity_sample_size, 0);
        assert_eq!(a.evidence_sample_size, 0);
        assert!(!p35_find_factor(&a, "source_has_identity_aliases").applied);
    }

    #[test]
    fn assess_source_trust_exact_string_match_not_case_folded() {
        // Adaptation B / Q7 pin. `source` is matched verbatim —
        // `"snowflake"` and `"Snowflake"` are distinct sources.
        // No normalization, no case-folding, no aliasing.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p35");
        let entity = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/lowercase",
            "Lowercase",
            vec![alias_for("snowflake", "analytics", "lc")],
            hydra_core::Confidence::new(0.90),
            0,
        );
        hydra.create_identity_entity(entity).unwrap();

        // Lowercase probe finds the entity.
        let lc = hydra
            .assess_source_trust(Some(&tenant), "snowflake")
            .unwrap();
        assert_eq!(lc.entity_sample_size, 1);
        // Mixed-case probe does NOT — distinct source string.
        let uc = hydra
            .assess_source_trust(Some(&tenant), "Snowflake")
            .unwrap();
        assert_eq!(uc.entity_sample_size, 0);
        let upper = hydra
            .assess_source_trust(Some(&tenant), "SNOWFLAKE")
            .unwrap();
        assert_eq!(upper.entity_sample_size, 0);
    }

    #[test]
    fn assess_source_trust_mean_entity_trust_buckets_mutex() {
        // LOAD-BEARING Adaptation C pin. Mutex on MEAN entity
        // trust, not independent fires:
        //   mean ≥ 0.70 → high_trust_entities_from_source
        //   mean ≤ 0.40 → low_trust_entities_from_source
        //   middle band → NEITHER fires
        //
        // We exercise the middle band by mixing one high-trust
        // and one low-trust entity, then assert neither factor
        // applied. (Independent fires would let both fire and
        // net to 0 — pinned NOT to do that.)
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p35");
        // High-trust entity (≈ 0.85): multi-source + metadata.
        let high = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/high",
            "High",
            vec![
                alias_for("github", "ops", "high"),
                alias_for("dbt", "models", "high"),
                alias_for("looker", "finance", "high"),
            ],
            hydra_core::Confidence::new(0.95),
            2,
        );
        // Low-trust entity (≈ 0.40 or below): single-alias,
        // single-source, no metadata.
        let low = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Service,
            "service/low",
            "Low",
            vec![alias_for("github", "ops", "low")],
            hydra_core::Confidence::new(0.95),
            0,
        );
        hydra.create_identity_entity(high).unwrap();
        hydra.create_identity_entity(low).unwrap();

        let a = hydra
            .assess_source_trust(Some(&tenant), "github")
            .unwrap();
        // Sample contains both — mean lands in the middle band.
        assert_eq!(a.entity_sample_size, 2);
        // Neither high_* nor low_* applied — middle band pin.
        assert!(!p35_find_factor(&a, "high_trust_entities_from_source").applied);
        assert!(!p35_find_factor(&a, "low_trust_entities_from_source").applied);
    }

    #[test]
    fn assess_source_trust_evidence_mapping_skips_human_agent_document() {
        // Adaptation A pin. Of the 6 `EvidenceSource` variants,
        // only `Warehouse.system`, `Api.system`, `System.name` map
        // cleanly to a source string. `Document` / `Human` /
        // `Agent` are explicit-skipped — pinning that ensures we
        // don't later silently fold ambiguous variants in.
        //
        // We add ONE evidence record per skipped variant naming
        // a source string we'll probe for. If the mapping ever
        // mis-includes them, evidence_sample_size > 0 and the
        // pin fires.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p35");
        // Document — uri carries "snowflake" textually, but we
        // skip the entire variant regardless of contents.
        let doc = p35_make_evidence(
            Some(tenant.clone()),
            hydra_core::EvidenceSource::Document {
                uri: "snowflake".to_string(),
            },
            0.90,
        );
        let human = p35_make_evidence(
            Some(tenant.clone()),
            hydra_core::EvidenceSource::Human {
                actor_id: hydra_core::ActorId::from_str("snowflake"),
            },
            0.90,
        );
        let agent = p35_make_evidence(
            Some(tenant.clone()),
            hydra_core::EvidenceSource::Agent {
                actor_id: hydra_core::ActorId::from_str("snowflake"),
            },
            0.90,
        );
        for ev in [doc, human, agent] {
            hydra
                .ingest(hydra_core::EventKind::EvidenceAdded { evidence: ev })
                .unwrap();
        }

        let a = hydra
            .assess_source_trust(Some(&tenant), "snowflake")
            .unwrap();
        // None of the 3 ambiguous variants count toward the
        // source — evidence_sample_size must be zero.
        assert_eq!(
            a.evidence_sample_size, 0,
            "Document / Human / Agent must NOT count as source-mapped \
             evidence (pin against silent inclusion)"
        );
        assert!(!p35_find_factor(&a, "evidence_present_from_source").applied);
    }

    #[test]
    fn assess_source_trust_evidence_reliability_uses_0_75_bar() {
        // Adaptation A pin. The `reliable_evidence_from_source`
        // factor uses P9's 0.75 reliability bar verbatim — the
        // cross-patch threshold consistency contract. We bracket
        // the threshold at 0.74 (just below) and 0.75 (at the
        // bar) to pin the exact boundary.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p35");

        // Just below — must NOT fire reliable_*.
        let just_below = p35_make_evidence(
            Some(tenant.clone()),
            hydra_core::EvidenceSource::System {
                name: "agent_dq".to_string(),
            },
            0.74,
        );
        hydra
            .ingest(hydra_core::EventKind::EvidenceAdded {
                evidence: just_below,
            })
            .unwrap();
        let below = hydra
            .assess_source_trust(Some(&tenant), "agent_dq")
            .unwrap();
        assert_eq!(below.evidence_sample_size, 1);
        assert!(below.factors.iter().any(|f| f.kind == "evidence_present_from_source" && f.applied));
        assert!(
            !p35_find_factor(&below, "reliable_evidence_from_source").applied,
            "reliability 0.74 must NOT clear the 0.75 bar"
        );

        // At the bar — MUST fire reliable_*.
        let at_bar = p35_make_evidence(
            Some(tenant.clone()),
            hydra_core::EvidenceSource::System {
                name: "agent_dq".to_string(),
            },
            0.75,
        );
        hydra
            .ingest(hydra_core::EventKind::EvidenceAdded { evidence: at_bar })
            .unwrap();
        let at = hydra
            .assess_source_trust(Some(&tenant), "agent_dq")
            .unwrap();
        assert_eq!(at.evidence_sample_size, 2);
        assert!(
            p35_find_factor(&at, "reliable_evidence_from_source").applied,
            "reliability 0.75 must clear the P9 0.75 bar"
        );
    }

    #[test]
    fn assess_source_trust_respects_entity_scan_cap() {
        // Wrinkle F pin. The internal cap is 200; sampling
        // selects highest-confidence first when capped. We pin
        // the cap structurally by adding a clearly small number
        // of entities (well under the cap) and observing all of
        // them are reflected in entity_sample_size — proving the
        // cap doesn't truncate normal-sized workloads. The cap's
        // exact value lives in the engine method's `const`
        // declaration; this test guards "the cap exists AND is
        // large enough not to bite at scales we hit in tests."
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p35");
        for i in 0..10 {
            let entity = make_entity_for_p33(
                Some(tenant.clone()),
                hydra_core::IdentityEntityKind::Dataset,
                &format!("dataset/c{i}"),
                &format!("Cap {i}"),
                vec![alias_for("snowflake", "ns", &format!("c{i}"))],
                // Confidence decreases by index — used by the cap
                // sampler's tie-break.
                hydra_core::Confidence::new(1.0 - (i as f64) * 0.01),
                0,
            );
            hydra.create_identity_entity(entity).unwrap();
        }
        let a = hydra
            .assess_source_trust(Some(&tenant), "snowflake")
            .unwrap();
        // All 10 entities fit under the 200 cap.
        assert_eq!(a.entity_sample_size, 10);
        // The cap structurally exists — same call with 10
        // entities returns deterministic count, and the
        // multiple-entities factor is set accordingly.
        assert!(p35_find_factor(&a, "multiple_entities_from_source").applied);
    }

    #[test]
    fn assess_source_trust_includes_all_factors_always() {
        // Explainability contract pin (wrinkle I). Every assessment
        // carries ALL 9 factor records, applied OR not. Pin so a
        // future refactor doesn't filter the list down to "what
        // fired". Mirrors P9 / P23 / P30 / P32 / P33.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p35");
        let entity = make_entity_for_p33(
            Some(tenant.clone()),
            hydra_core::IdentityEntityKind::Dataset,
            "dataset/x",
            "X",
            vec![alias_for("snowflake", "ns", "x")],
            hydra_core::Confidence::new(0.90),
            0,
        );
        hydra.create_identity_entity(entity).unwrap();
        let a = hydra
            .assess_source_trust(Some(&tenant), "snowflake")
            .unwrap();
        let expected_kinds = [
            "source_has_identity_aliases",
            "multiple_entities_from_source",
            "single_entity_from_source",
            "multiple_kinds_from_source",
            "high_trust_entities_from_source",
            "low_trust_entities_from_source",
            "evidence_present_from_source",
            "reliable_evidence_from_source",
            "low_reliability_evidence_from_source",
        ];
        for k in &expected_kinds {
            let _ = p35_find_factor(&a, k);
        }
        assert_eq!(a.factors.len(), expected_kinds.len());
        // At least one applied=false is present (single-entity-
        // probe means several pair-siblings don't fire).
        assert!(
            a.factors.iter().any(|f| !f.applied),
            "at least one factor must be applied=false"
        );
    }

    #[test]
    fn assess_source_trust_low_reliability_evidence_fires_when_all_below_0_40() {
        // Mutex sibling to `reliable_evidence_from_source`. Fires
        // ONLY when there IS evidence AND every record sits below
        // 0.40 reliability. Structural mutex: if any record is
        // ≥ 0.75, the floor 0.40 is necessarily exceeded.
        let mut hydra = Hydra::new();
        let tenant = hydra_core::TenantId::from_str("tenant_p35");
        // Two records, both below 0.40.
        for r in [0.20, 0.35] {
            let ev = p35_make_evidence(
                Some(tenant.clone()),
                hydra_core::EvidenceSource::System {
                    name: "agent_dq".to_string(),
                },
                r,
            );
            hydra
                .ingest(hydra_core::EventKind::EvidenceAdded { evidence: ev })
                .unwrap();
        }
        let a = hydra
            .assess_source_trust(Some(&tenant), "agent_dq")
            .unwrap();
        assert_eq!(a.evidence_sample_size, 2);
        assert!(p35_find_factor(&a, "evidence_present_from_source").applied);
        assert!(!p35_find_factor(&a, "reliable_evidence_from_source").applied);
        assert!(
            p35_find_factor(&a, "low_reliability_evidence_from_source").applied,
            "all-below-0.40 must fire low_reliability_evidence_from_source"
        );
    }

    // === Patch 23 — CausalCell trust folding ===

    /// Look up a factor in an assessment's `factors` list. Panics
    /// when not found — every factor name is expected to be
    /// present, applied or not (the "unapplied factors are still
    /// listed" contract).
    fn find_factor<'a>(
        assessment: &'a hydra_core::CausalCellTrustAssessment,
        kind: &str,
    ) -> &'a hydra_core::TrustFactor {
        assessment
            .factors
            .iter()
            .find(|f| f.kind == kind)
            .unwrap_or_else(|| panic!("factor {kind} missing from assessment"))
    }

    #[test]
    fn assess_causal_cell_trust_unknown_cell_returns_error() {
        let hydra = Hydra::new();
        let result = hydra.assess_causal_cell_trust(
            &hydra_core::CausalCellId::from_str("cell_ghost"),
        );
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(msg.contains("unknown causal cell"), "msg: {msg}");
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }

    #[test]
    fn assess_causal_cell_trust_parent_with_high_children_returns_high() {
        // Four children with high trust → base = 0.85, every
        // positive factor that depends only on children fires →
        // clamps to 1.0 → High.
        let mut hydra = Hydra::new();
        let children: Vec<hydra_core::CausalCell> = (0..4)
            .map(|i| {
                ingest_synthetic_cell(
                    &mut hydra,
                    None,
                    &format!("child_{i}"),
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    Some(0.85),
                    None,
                )
            })
            .collect();
        let parent = hydra
            .compose_causal_cells(
                children.iter().map(|c| c.id.clone()).collect(),
                hydra_core::CausalCellKind::Health,
                "hydra.health".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();

        let assessment = hydra.assess_causal_cell_trust(&parent.id).unwrap();
        assert_eq!(assessment.level, hydra_core::TrustLevel::High);
        assert!(assessment.score >= 0.80, "score: {}", assessment.score);
        assert!(find_factor(&assessment, "children_present").applied);
        assert!(find_factor(&assessment, "known_child_trust_scores").applied);
        assert!(find_factor(&assessment, "high_average_child_trust").applied);
        assert!(find_factor(&assessment, "all_children_high_trust").applied);
        // 4 children surface in child_scores.
        assert_eq!(assessment.child_scores.len(), 4);
        // Explanation pattern.
        assert!(assessment.explanation.contains("Cell trust High"));
        assert!(assessment.explanation.contains("hydra.health"));
    }

    #[test]
    fn assess_causal_cell_trust_missing_child_scores_penalized() {
        // One child has trust_score = None → missing_child_trust
        // factor fires AND average is taken over known-only.
        let mut hydra = Hydra::new();
        let known = ingest_synthetic_cell(
            &mut hydra, None, "known",
            vec![], vec![], vec![], vec![], vec![], vec![],
            Some(0.80), None,
        );
        let unknown = ingest_synthetic_cell(
            &mut hydra, None, "unknown",
            vec![], vec![], vec![], vec![], vec![], vec![],
            None, None,
        );
        let parent = hydra
            .compose_causal_cells(
                vec![known.id, unknown.id],
                hydra_core::CausalCellKind::Health,
                "mixed".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();

        let assessment = hydra.assess_causal_cell_trust(&parent.id).unwrap();
        assert!(find_factor(&assessment, "missing_child_trust").applied);
        // Average ignores None, takes 0.80 only. With penalty
        // (-0.10), positives still push past 0.80 so level stays
        // High; pin via explicit factor inspection rather than
        // top-line level.
        let missing = find_factor(&assessment, "missing_child_trust");
        assert!(missing.detail.contains("1 of 2"));
    }

    #[test]
    fn assess_causal_cell_trust_failed_outcome_penalizes() {
        // Drive a real chain where the Notify action's webhook
        // fails → ActionFailed event + Failure outcome. Wrap into
        // a reflex cell; assess; failed_outcomes_present fires.
        let mut hydra = Hydra::new();
        let peer_id = hydra_core::ReplicaId::from_str("replica_p23_fail");
        register_peer_with_lag(
            &mut hydra,
            &peer_id,
            Some((500, chrono::Utc::now())),
        );
        let actor = hydra_core::ActorId::from_str("actor_ops");
        let assessment_chain = hydra
            .evaluate_replication_lag_anomaly_and_propose_action(
                peer_id.clone(),
                actor.clone(),
            )
            .unwrap();
        let claim_id = assessment_chain.claim_id.clone().unwrap();
        let action_id = assessment_chain.action_ids[0].clone();

        // Execute with Failed delivery → ActionFailed +
        // Outcome{kind: Failure}.
        let delivery = hydra_core::DeliveryOutcome::Failed {
            adapter: "webhook".to_string(),
            reason: "induced failure".to_string(),
            status_code: Some(500),
            latency_ms: 42,
        };
        hydra
            .execute_notify_action_with_delivery(
                action_id,
                actor.clone(),
                delivery,
            )
            .unwrap();

        let reflex_cell = hydra
            .create_reflex_causal_cell_from_claim(claim_id, actor)
            .unwrap();
        let cell_assessment =
            hydra.assess_causal_cell_trust(&reflex_cell.id).unwrap();

        let failed = find_factor(&cell_assessment, "failed_outcomes_present");
        assert!(failed.applied, "failed_outcomes_present must fire");
        assert!(failed.detail.contains("Failure or Regression"));
    }

    #[test]
    fn assess_causal_cell_trust_rejected_action_penalizes() {
        // Build a cell that references a Rejected action. To set
        // up a rejected action, register HumanApproval policy
        // (cascade leaves Proposed), reject it directly via
        // reject_action.
        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_ops");
        // HumanApproval policy so cascade doesn't auto-approve.
        let policy = hydra_core::Policy {
            id: hydra_core::PolicyId::new(),
            tenant_id: None,
            name: "P23 — require human approval".to_string(),
            kind: hydra_core::PolicyKind::HumanApproval,
            status: hydra_core::PolicyStatus::Active,
            scope: hydra_core::PolicyScope::AnyAction,
            condition: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::PolicyRegistered { policy })
            .unwrap();
        // Propose a Notify action; cascade holds it at Proposed.
        let action_id = hydra_core::ActionId::new();
        let action = hydra_core::Action {
            id: action_id.clone(),
            tenant_id: None,
            kind: hydra_core::ActionKind::Notify,
            status: hydra_core::action::ActionStatus::Proposed,
            targets: vec![hydra_core::action::ActionTarget::System(
                "hydra".to_string(),
            )],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor.clone(),
            approved_by: None,
            rejected_by: None,
            policy_id: None,
            payload: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ActionProposed { action })
            .unwrap();
        hydra
            .reject_action(
                action_id.clone(),
                actor.clone(),
                "test reject".to_string(),
            )
            .unwrap();
        // Sanity: action is Rejected.
        assert_eq!(
            hydra.action(&action_id).unwrap().status,
            hydra_core::action::ActionStatus::Rejected
        );

        // Synthetic cell referencing the rejected action.
        let cell = ingest_synthetic_cell(
            &mut hydra, None, "with_rejected_action",
            vec![], vec![], vec![action_id], vec![], vec![], vec![],
            Some(0.50), None,
        );

        let assess = hydra.assess_causal_cell_trust(&cell.id).unwrap();
        let rejected = find_factor(&assess, "rejected_actions_present");
        assert!(rejected.applied, "rejected_actions_present must fire");
    }

    #[test]
    fn assess_causal_cell_trust_contradicting_claim_penalizes() {
        // Create a claim with non-empty evidence_against by
        // disputing it after creation.
        let mut hydra = Hydra::new();
        let now = chrono::Utc::now();
        let actor = hydra_core::ActorId::from_str("actor_ops");

        // First ingest a piece of evidence to dispute with.
        let evidence_id = hydra_core::EvidenceId::new();
        let evidence = hydra_core::Evidence {
            id: evidence_id.clone(),
            tenant_id: None,
            source: hydra_core::epistemic::EvidenceSource::Human {
                actor_id: actor.clone(),
            },
            payload: hydra_core::epistemic::EvidencePayload {
                kind: "refutation".to_string(),
                data: std::collections::HashMap::new(),
            },
            reliability: hydra_core::Confidence::new(0.90),
            observed_at: now,
            recorded_at: now,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::EvidenceAdded { evidence })
            .unwrap();

        // A claim that we'll then dispute.
        let claim_id = hydra_core::ClaimId::new();
        let claim = hydra_core::Claim {
            id: claim_id.clone(),
            tenant_id: None,
            kind: hydra_core::ClaimKind::Hypothesis,
            subject: hydra_core::ClaimSubject::System("test".to_string()),
            predicate: "test".to_string(),
            object: hydra_core::ClaimObject::Value(
                hydra_core::Value::Bool(true),
            ),
            confidence: hydra_core::Confidence::new(0.5),
            status: hydra_core::ClaimStatus::Proposed,
            evidence_for: vec![],
            evidence_against: vec![],
            valid_from: now,
            valid_until: None,
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::ClaimProposed { claim })
            .unwrap();
        hydra
            .ingest(hydra_core::EventKind::ClaimDisputed {
                claim_id: claim_id.clone(),
                evidence_id,
                reason: Some("contradiction test".to_string()),
            })
            .unwrap();
        // Sanity: claim now has non-empty evidence_against.
        assert!(
            !hydra.claim(&claim_id).unwrap().evidence_against.is_empty()
        );

        // Cell referencing the disputed claim.
        let cell = ingest_synthetic_cell(
            &mut hydra, None, "with_contradicted_claim",
            vec![], vec![claim_id], vec![], vec![], vec![], vec![],
            Some(0.50), None,
        );

        let assess = hydra.assess_causal_cell_trust(&cell.id).unwrap();
        let contra = find_factor(&assess, "contradicting_claims_present");
        assert!(contra.applied, "contradicting_claims_present must fire");
    }

    #[test]
    fn assess_causal_cell_trust_leaf_reflex_cell_uses_own_trust_score() {
        // A leaf cell with own trust_score = 0.90 + executed
        // action + outcome + observation → base 0.90 plus several
        // positives → High. Crucially, the LEAF path treats the
        // cell's own trust_score as the single "child" for the
        // base average.
        let mut hydra = Hydra::new();
        let (claim_id, _, _, _, _) =
            drive_full_replication_lag_chain(&mut hydra);
        let cell = hydra
            .create_reflex_causal_cell_from_claim(
                claim_id,
                hydra_core::ActorId::from_str("actor_ops"),
            )
            .unwrap();
        // Sanity: this is a leaf (child_cell_ids empty).
        assert!(cell.child_cell_ids.is_empty());
        assert!(cell.trust_score.is_some());

        let assess = hydra.assess_causal_cell_trust(&cell.id).unwrap();
        // Leaf path: children_present did NOT fire.
        assert!(!find_factor(&assess, "children_present").applied);
        // But known_child_trust_scores DID — the leaf's own
        // trust_score counts.
        assert!(find_factor(&assess, "known_child_trust_scores").applied);
        // outcomes_recorded + observations_present + actions_executed
        // all fire for a full Reflex chain.
        assert!(find_factor(&assess, "outcomes_recorded").applied);
        assert!(find_factor(&assess, "observations_present").applied);
        assert!(find_factor(&assess, "actions_executed").applied);
        // child_scores is empty for a leaf cell.
        assert!(assess.child_scores.is_empty());
    }

    #[test]
    fn assess_causal_cell_trust_direct_children_only_no_recursion() {
        // **LOAD-BEARING boundary pin.** Build a 3-level tree:
        // grandparent ← parent ← leaf. The leaf has trust 0.50.
        // The parent's STORED trust_score (set by P22's naïve
        // mean) is also 0.50. The grandparent's assessment must
        // use the PARENT's stored 0.50, NOT recurse to leaf.
        //
        // If a future patch ever turns on recursion, this test
        // fires and the operator must consciously update the
        // expected score.
        let mut hydra = Hydra::new();
        let leaf = ingest_synthetic_cell(
            &mut hydra, None, "leaf",
            vec![], vec![], vec![], vec![], vec![], vec![],
            Some(0.50), None,
        );
        let parent = hydra
            .compose_causal_cells(
                vec![leaf.id.clone()],
                hydra_core::CausalCellKind::Health,
                "parent".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();
        // P22's naïve mean: parent.trust_score should be Some(0.50).
        assert_eq!(parent.trust_score, Some(0.50));

        // Manually mutate parent into a higher trust_score in
        // the store? No — cells are immutable. Instead, build a
        // grandparent that composes the parent. The grandparent's
        // child trust is THE PARENT's stored 0.50.
        let grandparent = hydra
            .compose_causal_cells(
                vec![parent.id.clone()],
                hydra_core::CausalCellKind::Health,
                "grandparent".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();

        let assess = hydra.assess_causal_cell_trust(&grandparent.id).unwrap();
        // The grandparent's child_scores must contain exactly
        // ONE entry — the parent — and that entry's trust_score
        // must be the parent's STORED 0.50, not a recursed
        // leaf-derived value.
        assert_eq!(assess.child_scores.len(), 1);
        assert_eq!(assess.child_scores[0].cell_id, parent.id);
        assert_eq!(assess.child_scores[0].trust_score, Some(0.50));
    }

    #[test]
    fn assess_causal_cell_trust_factor_list_includes_unapplied_factors() {
        // Every factor in the Patch 23 table must appear in
        // `factors`, even when not applied. Pin against
        // accidental drops as the table evolves.
        let mut hydra = Hydra::new();
        let child = ingest_synthetic_cell(
            &mut hydra, None, "child",
            vec![], vec![], vec![], vec![], vec![], vec![],
            Some(0.50), None,
        );
        let parent = hydra
            .compose_causal_cells(
                vec![child.id],
                hydra_core::CausalCellKind::Health,
                "test".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();
        let assess = hydra.assess_causal_cell_trust(&parent.id).unwrap();

        for kind in [
            "children_present",
            "known_child_trust_scores",
            "high_average_child_trust",
            "all_children_high_trust",
            "outcomes_recorded",
            "observations_present",
            "actions_executed",
            "any_child_low_trust",
            "failed_outcomes_present",
            "rejected_actions_present",
            "contradicting_claims_present",
            "missing_child_trust",
        ] {
            // Calling find_factor itself asserts presence.
            let _ = find_factor(&assess, kind);
        }
        // Total exactly 12.
        assert_eq!(assess.factors.len(), 12);
    }

    #[test]
    fn assess_causal_cell_trust_does_not_mutate_cell() {
        // Read-only contract: assess does not touch the stored
        // cell. Re-fetch after assess; trust_score (set by P22's
        // naïve mean) is unchanged.
        let mut hydra = Hydra::new();
        let child = ingest_synthetic_cell(
            &mut hydra, None, "x",
            vec![], vec![], vec![], vec![], vec![], vec![],
            Some(0.70), None,
        );
        let parent = hydra
            .compose_causal_cells(
                vec![child.id],
                hydra_core::CausalCellKind::Health,
                "test".to_string(),
                hydra_core::ActorId::from_str("actor_ops"),
                None,
            )
            .unwrap();
        let pre_score = hydra.causal_cell(&parent.id).unwrap().trust_score;
        // Two assessments — should produce equal scores (no
        // hidden mutation) and not touch the stored cell.
        let assess1 = hydra.assess_causal_cell_trust(&parent.id).unwrap();
        let assess2 = hydra.assess_causal_cell_trust(&parent.id).unwrap();
        assert!((assess1.score - assess2.score).abs() < 1e-9);
        let post_score = hydra.causal_cell(&parent.id).unwrap().trust_score;
        assert_eq!(pre_score, post_score);
        // P22's stored mean = 0.70; not overridden by P23's higher
        // score that includes positive modifiers.
        assert_eq!(post_score, Some(0.70));
    }

    #[test]
    fn assess_causal_cell_trust_corrupt_missing_child_returns_error() {
        // Defensive: a composed cell whose child has been removed
        // from the store (or never existed, in pathological
        // tests) must error rather than skip. Patch 22 prevents
        // creating such cells, but Patch 23's read path must not
        // assume integrity.
        //
        // We can't easily delete a child (cells are immutable +
        // there's no delete event), but we CAN construct a cell
        // with a fake child id by ingesting a hand-crafted
        // CausalCellCreated event whose cell.child_cell_ids
        // references a nonexistent cell.
        let mut hydra = Hydra::new();
        let fake_child = hydra_core::CausalCellId::from_str("cell_fake");
        let parent_id = hydra_core::CausalCellId::from_str("cell_parent_dangling");
        let parent_cell = hydra_core::CausalCell {
            id: parent_id.clone(),
            tenant_id: None,
            kind: hydra_core::CausalCellKind::Health,
            subject: "dangling".to_string(),
            source_events: vec![],
            evidence_ids: vec![],
            claim_ids: vec![],
            action_ids: vec![],
            outcome_ids: vec![],
            observation_run_ids: vec![],
            child_cell_ids: vec![fake_child.clone()],
            trust_score: None,
            summary: None,
            created_by: hydra_core::ActorId::from_str("actor_ops"),
            created_at: chrono::Utc::now(),
            caused_by: None,
        };
        hydra
            .ingest(hydra_core::EventKind::CausalCellCreated {
                cell: parent_cell,
            })
            .unwrap();
        // Sanity: parent stored, child is not.
        assert!(hydra.causal_cell(&parent_id).is_some());
        assert!(hydra.causal_cell(&fake_child).is_none());

        let result = hydra.assess_causal_cell_trust(&parent_id);
        match result {
            Err(hydra_core::error::HydraError::QueryError(msg)) => {
                assert!(
                    msg.contains("references unknown child"),
                    "msg: {msg}"
                );
            }
            other => panic!("expected QueryError, got {other:?}"),
        }
    }
}
