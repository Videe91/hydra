//! MicroModel vocabulary (Patch 1 — vocabulary + registry only).
//!
//! Establishes the data shape Hydra will use to register, run, audit,
//! and store predictions from small internal ML models. **No
//! inference engine, no background runner, no actual neural nets are
//! introduced in this patch** — only the typed surface that future
//! patches will build on.
//!
//! The thesis behind micro-models: Hydra is already
//! self-introspective (anomaly, coverage, counterfactual, evolution).
//! Once an agent can ask "predict X based on these recent
//! observations," Hydra graduates from a self-describing database to
//! a self-improving one. Predictions become a first-class durable
//! artifact alongside Evidence, Claim, and Action — and the same
//! lineage / counterfactual / evolution machinery applies to them.
//!
//! ## Lifecycle (matches Schema)
//!
//! ```text
//! Registered → Active ↔ Disabled → Archived
//! ```
//!
//! - `Registered` is the freshly-declared state right after the
//!   `MicroModelRegistered` event lands.
//! - `Active` is the running state — predictions are recorded
//!   against models in this state. (Patch 1 has no auto-promotion
//!   from Registered → Active yet; the operator sets it explicitly
//!   via a future status-change event.)
//! - `Disabled` removes the model from active selection without
//!   destroying its history.
//! - `Archived` is terminal; predictions and observations remain
//!   queryable but no new ones are recorded.
//!
//! ## Run identity
//!
//! Every prediction is tagged with a `MicroModelRunId`. The
//! companion `MicroModelObservation` carries the SAME `run_id` and
//! records what actually happened — letting evolution metrics
//! compute precision / recall / error per run without a separate
//! join. This mirrors Hydra's subscription-fire / evidence-record
//! pattern.

use crate::id::{ActorId, MicroModelId, MicroModelRunId};
use crate::schema::FieldSchema;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Catalog of micro-model purposes Hydra knows how to reason about.
///
/// Variants are intentionally concrete (not free-form strings) so
/// future patches can dispatch on them statically. Adding a new
/// variant is a breaking change; this is the right trade for a
/// closed v0 vocabulary — operators should not be inventing new
/// model purposes from outside.
///
/// Default-derived `Serialize` / `Deserialize` produces PascalCase
/// wire form (`"ReplicationLagAnomaly"`, etc.), matching every
/// other Hydra enum.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MicroModelKind {
    /// Anomaly detector over `ReplicationLag` observations. The
    /// first model Hydra will ship in Patch 2.
    ReplicationLagAnomaly,
    /// Short-window predictor for commit throughput. Used by
    /// auto-tuners and capacity planners.
    CommitRatePredictor,
    /// Per-query cost estimator (rows scanned, wall-clock, memory).
    /// Future query-planner input.
    QueryCostEstimator,
    /// Cardinality estimator (set-size predictor) for graph
    /// traversals and joins.
    CardinalityEstimator,
    /// General-purpose auto-tuner: takes a configuration vector +
    /// observed-perf vector, suggests a new configuration.
    AutoTuner,
    /// Learned-index head — the eventual replacement for B-tree
    /// page lookups inside the storage layer. Wire-only in v0.
    LearnedIndex,
    /// Patch 18 safety reflex: watches whether the system is
    /// producing too many self-triggered events / actions / claims
    /// in a short window — i.e. agents chasing their own tail.
    /// Stateless threshold detector; counts non-Hydra-system
    /// actor activity per window.
    AgentLoopStorm,
    /// Patch 19 self-health model: watches whether Hydra's own
    /// actions are completing successfully. Combines absolute
    /// failure counts with a failure-rate ratio over a 5-minute
    /// default window; fires Warning/Critical Notify alerts when
    /// the delivery layer (Patch 14 webhooks etc.) starts
    /// degrading. Stateless.
    ActionFailureRate,
}

impl MicroModelKind {
    /// Stable snake_case discriminant string. Useful for metrics
    /// labels and HTTP query params later.
    pub fn discriminant(&self) -> &'static str {
        match self {
            MicroModelKind::ReplicationLagAnomaly => "replication_lag_anomaly",
            MicroModelKind::CommitRatePredictor => "commit_rate_predictor",
            MicroModelKind::QueryCostEstimator => "query_cost_estimator",
            MicroModelKind::CardinalityEstimator => "cardinality_estimator",
            MicroModelKind::AutoTuner => "auto_tuner",
            MicroModelKind::LearnedIndex => "learned_index",
            MicroModelKind::AgentLoopStorm => "agent_loop_storm",
            MicroModelKind::ActionFailureRate => "action_failure_rate",
        }
    }
}

/// Lifecycle status for a registered model. Matches Schema's
/// `Registered → Active → Disabled → Archived` shape so operators
/// learn one model lifecycle, not two.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MicroModelStatus {
    Registered,
    Active,
    Disabled,
    Archived,
}

/// One registered micro-model: identity + purpose + IO schemas +
/// audit metadata. Version-stamped so future patches can ship
/// multiple variants of the same `MicroModelKind` and roll between
/// them under feature flags.
///
/// `input_schema` and `output_schema` use `FieldSchema` for the
/// same reasons the regular schema registry does: declarative,
/// already-validated shape, future-compatible with the schema gate.
/// Models that take a sliding window of observations (e.g.
/// `ReplicationLagAnomaly` reading the last N `ReplicationLag`s)
/// express it via a single field with `ValueType::List(...)` —
/// no special vocabulary needed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MicroModelDefinition {
    pub id: MicroModelId,
    pub kind: MicroModelKind,
    /// Operator-supplied name. Human-facing — e.g.
    /// `"lag_anomaly_v0"`. Not unique by itself; the `id` is the
    /// canonical handle.
    pub name: String,
    /// Monotonic version per `(kind, name)`. Bumped when an
    /// operator ships a retrained or restructured model variant.
    pub version: u32,
    pub status: MicroModelStatus,
    /// Declared shape of `prediction.input`.
    pub input_schema: Vec<FieldSchema>,
    /// Declared shape of `prediction.output`.
    pub output_schema: Vec<FieldSchema>,
    pub created_by: ActorId,
    pub created_at: DateTime<Utc>,
    /// Free-form operator metadata — training notes, calibration
    /// stats, source repo hash, etc.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl MicroModelDefinition {
    /// Construct a freshly-registered model in `Registered` status.
    /// Helper for tests and for the engine's
    /// `Hydra::register_micro_model(...)` wrapper.
    pub fn registered(
        id: MicroModelId,
        kind: MicroModelKind,
        name: impl Into<String>,
        version: u32,
        input_schema: Vec<FieldSchema>,
        output_schema: Vec<FieldSchema>,
        created_by: ActorId,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            kind,
            name: name.into(),
            version,
            status: MicroModelStatus::Registered,
            input_schema,
            output_schema,
            created_by,
            created_at,
            metadata: HashMap::new(),
        }
    }
}

/// One prediction made by a registered model. Always carries a
/// `run_id` so the matching `MicroModelObservation` (recorded once
/// ground truth is known) can be joined back.
///
/// `input` and `output` are kept as free JSON so Patch 1 doesn't
/// have to encode the strongly-typed boundary. The `input_schema`
/// / `output_schema` on the model definition is what callers
/// validate against (in a later patch).
///
/// `confidence` is `[0.0, 1.0]` by convention — interpreted as the
/// model's self-reported certainty. Models that don't produce a
/// confidence estimate set it to `1.0` (point estimate, no
/// uncertainty channel).
///
/// `explanation` is an optional short string — the agent-facing
/// "why this prediction" line. LLM-friendly when present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MicroModelPrediction {
    pub model_id: MicroModelId,
    pub run_id: MicroModelRunId,
    pub input: serde_json::Value,
    pub output: serde_json::Value,
    pub confidence: f64,
    pub explanation: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Ground-truth observation for one prior prediction. Matched to
/// its prediction via `run_id`.
///
/// `observed_outcome` is what actually happened — same JSON shape
/// the model emitted as `output`, populated from whatever real
/// process produced the outcome (the engine's anomaly engine, an
/// operator's manual judgment, a downstream metric).
///
/// `error` is the operator-supplied scalar error / distance between
/// `prediction.output` and `observed_outcome`. Models with no
/// natural error metric leave this `None`. Predictions whose
/// outcome was "n/a" (e.g. the predicted condition didn't apply by
/// the time observation was recorded) also use `None`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MicroModelObservation {
    pub run_id: MicroModelRunId,
    pub observed_outcome: serde_json::Value,
    pub error: Option<f64>,
    pub observed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::ValueType;

    fn actor() -> ActorId {
        ActorId::from_str("actor_micromodel_test")
    }

    fn lag_anomaly_definition() -> MicroModelDefinition {
        MicroModelDefinition::registered(
            MicroModelId::from_str("mm_lag_v0"),
            MicroModelKind::ReplicationLagAnomaly,
            "lag_anomaly_v0",
            1,
            vec![FieldSchema::required(
                "recent_lag_commits",
                ValueType::List(Box::new(ValueType::Int)),
            )],
            vec![FieldSchema::required(
                "is_anomalous",
                ValueType::Bool,
            )],
            actor(),
            Utc::now(),
        )
    }

    #[test]
    fn micromodel_definition_serde_roundtrip() {
        let def = lag_anomaly_definition();
        let json = serde_json::to_string(&def).unwrap();
        let restored: MicroModelDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(def, restored);
        // The wire form for `kind` uses PascalCase (Rust serde default),
        // matching every other Hydra enum on the wire.
        assert!(json.contains("\"ReplicationLagAnomaly\""));
        // `status` defaults to Registered.
        assert!(json.contains("\"Registered\""));
    }

    #[test]
    fn micromodel_prediction_serde_roundtrip() {
        let prediction = MicroModelPrediction {
            model_id: MicroModelId::from_str("mm_lag_v0"),
            run_id: MicroModelRunId::from_str("mmrun_001"),
            input: serde_json::json!({"recent_lag_commits": [12, 13, 14]}),
            output: serde_json::json!({"is_anomalous": false}),
            confidence: 0.87,
            explanation: Some(
                "lag stable within last 3 samples; no z-score outlier".to_string(),
            ),
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&prediction).unwrap();
        let restored: MicroModelPrediction = serde_json::from_str(&json).unwrap();
        assert_eq!(prediction, restored);
    }

    #[test]
    fn micromodel_observation_serde_roundtrip() {
        let observation = MicroModelObservation {
            run_id: MicroModelRunId::from_str("mmrun_001"),
            observed_outcome: serde_json::json!({"is_anomalous": false}),
            error: Some(0.0),
            observed_at: Utc::now(),
        };
        let json = serde_json::to_string(&observation).unwrap();
        let restored: MicroModelObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(observation, restored);
    }

    #[test]
    fn micromodel_kind_discriminants_are_snake_case() {
        // The discriminant strings are the public face of
        // MicroModelKind for metrics labels and future HTTP filters.
        // Lock them in so a rename here is a deliberate decision.
        assert_eq!(
            MicroModelKind::ReplicationLagAnomaly.discriminant(),
            "replication_lag_anomaly"
        );
        assert_eq!(
            MicroModelKind::CommitRatePredictor.discriminant(),
            "commit_rate_predictor"
        );
        assert_eq!(
            MicroModelKind::QueryCostEstimator.discriminant(),
            "query_cost_estimator"
        );
        assert_eq!(
            MicroModelKind::CardinalityEstimator.discriminant(),
            "cardinality_estimator"
        );
        assert_eq!(MicroModelKind::AutoTuner.discriminant(), "auto_tuner");
        assert_eq!(
            MicroModelKind::LearnedIndex.discriminant(),
            "learned_index"
        );
    }

    #[test]
    fn micromodel_status_serde_pascal_case() {
        // Statuses match Schema's lifecycle vocabulary, also
        // PascalCase on the wire.
        for status in [
            MicroModelStatus::Registered,
            MicroModelStatus::Active,
            MicroModelStatus::Disabled,
            MicroModelStatus::Archived,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let restored: MicroModelStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, restored);
        }
    }
}
