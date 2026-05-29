//! Built-in micro-models that the engine runs natively (MicroModel
//! Patch 2+).
//!
//! Patch 1 established the *vocabulary* for micro-models (kind,
//! status, definition, prediction, observation) and the registry
//! that stores them. This module ships the first *real* internal
//! model: a classical statistical anomaly detector over Hydra's
//! commit pulse.
//!
//! ## Patch boundary (Patch 2 — `CommitRateAnomalyModel`)
//!
//! - Pure online statistical model (EWMA mean + variance, Z-score
//!   detection). NO neural net, NO ONNX, NO LLM, NO XGBoost.
//! - State is transient in-memory on the `Hydra` instance. A cold
//!   restart re-enters WarmingUp. Durable model state is a
//!   future-patch concern; documented in `Hydra::evaluate_commit_rate_anomaly`.
//! - Records `MicroModelPredictionRecorded` events via the normal
//!   `Hydra::ingest` path. Does NOT yet emit `EvidenceAdded` /
//!   `ClaimProposed` / `ActionProposed` — that's Patch 3, where
//!   predictions enter the living loop.
//! - No background runner, no HTTP route, no Python SDK method.
//!   Hydra-level helper `evaluate_commit_rate_anomaly(actor)`
//!   is the only entry point.
//!
//! Future patches add models for replication lag, query cost,
//! cardinality, auto-tuning, and learned indexes — each as its own
//! `pub mod` here, slotting into the same registry vocabulary.

pub mod commit_rate;

pub use commit_rate::{
    AnomalyLevel, CommitRateAnomalyAssessment, CommitRateAnomalyConfig, CommitRateAnomalyModel,
    CommitRateAnomalyOutput, CommitRateAnomalyState, Direction,
};
