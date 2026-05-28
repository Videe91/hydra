//! Materialized state for the micro-model registry (Patch 1).
//!
//! Patch 1 is registry + audit only — no inference engine, no
//! background runner, no actual ML. This store records:
//!
//!   - Every registered `MicroModelDefinition` indexed by id, kind,
//!     and status.
//!   - Every `MicroModelPrediction` keyed by its `run_id`.
//!   - Every `MicroModelObservation` keyed by the same `run_id`,
//!     so a prediction's outcome can be joined back without an
//!     extra index.
//!
//! All mutations flow through `apply_event`. Non-micro-model
//! `EventKind` variants are silently ignored (matches the pattern
//! every other store in `hydra-engine` follows so the store can
//! subscribe to the full event log without callers pre-filtering).
//!
//! The store does NOT make predictions. Patch 2 will add the first
//! real model (`ReplicationLagAnomalyModel`) and the inference path
//! that produces `MicroModelPredictionRecorded` events.

use hydra_core::error::Result;
use hydra_core::{
    Event, EventKind, MicroModelDefinition, MicroModelId, MicroModelKind, MicroModelObservation,
    MicroModelPrediction, MicroModelStatus,
};
use std::collections::{BTreeSet, HashMap};

/// In-memory registry of micro-models, their predictions, and the
/// observed outcomes paired with each prediction.
///
/// `BTreeSet` for the kind / status indexes so iteration order is
/// deterministic (helps tests and snapshot diffs). Lookup is O(log N);
/// for v0 registry sizes (single-digit models per kind) this is
/// negligible.
#[derive(Debug, Clone, Default)]
pub struct MicroModelStore {
    models: HashMap<MicroModelId, MicroModelDefinition>,
    predictions: HashMap<hydra_core::MicroModelRunId, MicroModelPrediction>,
    observations: HashMap<hydra_core::MicroModelRunId, MicroModelObservation>,
    models_by_kind: HashMap<MicroModelKind, BTreeSet<MicroModelId>>,
    models_by_status: HashMap<MicroModelStatus, BTreeSet<MicroModelId>>,
}

impl MicroModelStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one event. Non-micro-model variants are ignored so the
    /// store can subscribe to the full event log unconditionally.
    pub fn apply_event(&mut self, event: &Event) -> Result<()> {
        match &event.kind {
            EventKind::MicroModelRegistered { model } => {
                self.insert_model(model.clone());
            }
            EventKind::MicroModelStatusChanged {
                model_id, status, ..
            } => {
                self.update_status(model_id, status.clone());
            }
            EventKind::MicroModelPredictionRecorded { prediction } => {
                self.predictions
                    .insert(prediction.run_id.clone(), prediction.clone());
            }
            EventKind::MicroModelObservationRecorded { observation } => {
                self.observations
                    .insert(observation.run_id.clone(), observation.clone());
            }
            // Every other EventKind variant is a no-op for the
            // micro-model store. Patch 2+ will not add to this match
            // — additional behavior (e.g. routing observation-arrival
            // to retrain a model) belongs in a separate cascade
            // reaction, not here.
            _ => {}
        }
        Ok(())
    }

    fn insert_model(&mut self, model: MicroModelDefinition) {
        let id = model.id.clone();
        let kind = model.kind.clone();
        let status = model.status.clone();
        // Replace any prior model with the same id. Re-registration
        // is allowed (operator workflow); the kind/status indexes
        // must be rebuilt against the OLD model's slots if it
        // differed.
        if let Some(prior) = self.models.insert(id.clone(), model) {
            if prior.kind != kind {
                if let Some(set) = self.models_by_kind.get_mut(&prior.kind) {
                    set.remove(&id);
                }
            }
            if prior.status != status {
                if let Some(set) = self.models_by_status.get_mut(&prior.status) {
                    set.remove(&id);
                }
            }
        }
        self.models_by_kind
            .entry(kind)
            .or_default()
            .insert(id.clone());
        self.models_by_status
            .entry(status)
            .or_default()
            .insert(id);
    }

    fn update_status(&mut self, model_id: &MicroModelId, new_status: MicroModelStatus) {
        // Move the model between status indexes and update its
        // embedded `status` field. Unknown model_id is a no-op —
        // the store stays in a coherent state.
        let Some(model) = self.models.get_mut(model_id) else {
            return;
        };
        if model.status == new_status {
            return;
        }
        let old_status = std::mem::replace(&mut model.status, new_status.clone());
        if let Some(set) = self.models_by_status.get_mut(&old_status) {
            set.remove(model_id);
        }
        self.models_by_status
            .entry(new_status)
            .or_default()
            .insert(model_id.clone());
    }

    // === Reads ===

    pub fn model(&self, id: &MicroModelId) -> Option<&MicroModelDefinition> {
        self.models.get(id)
    }

    pub fn all_models(&self) -> impl Iterator<Item = &MicroModelDefinition> {
        self.models.values()
    }

    pub fn models_by_kind(&self, kind: &MicroModelKind) -> Vec<&MicroModelDefinition> {
        self.models_by_kind
            .get(kind)
            .map(|set| {
                set.iter()
                    .filter_map(|id| self.models.get(id))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    pub fn models_by_status(&self, status: &MicroModelStatus) -> Vec<&MicroModelDefinition> {
        self.models_by_status
            .get(status)
            .map(|set| {
                set.iter()
                    .filter_map(|id| self.models.get(id))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    pub fn prediction(
        &self,
        run_id: &hydra_core::MicroModelRunId,
    ) -> Option<&MicroModelPrediction> {
        self.predictions.get(run_id)
    }

    pub fn observation(
        &self,
        run_id: &hydra_core::MicroModelRunId,
    ) -> Option<&MicroModelObservation> {
        self.observations.get(run_id)
    }

    pub fn all_predictions(&self) -> impl Iterator<Item = &MicroModelPrediction> {
        self.predictions.values()
    }

    pub fn all_observations(&self) -> impl Iterator<Item = &MicroModelObservation> {
        self.observations.values()
    }

    pub fn model_count(&self) -> usize {
        self.models.len()
    }

    pub fn prediction_count(&self) -> usize {
        self.predictions.len()
    }

    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{
        ActorId, Event, EventKind, FieldSchema, MicroModelDefinition, MicroModelId,
        MicroModelKind, MicroModelObservation, MicroModelPrediction, MicroModelRunId,
        MicroModelStatus, ValueType,
    };

    fn actor() -> ActorId {
        ActorId::from_str("actor_micromodel_store_test")
    }

    fn definition(id: &str, kind: MicroModelKind) -> MicroModelDefinition {
        MicroModelDefinition::registered(
            MicroModelId::from_str(id),
            kind,
            id.to_string(),
            1,
            vec![FieldSchema::required(
                "recent_lag_commits",
                ValueType::List(Box::new(ValueType::Int)),
            )],
            vec![FieldSchema::required("is_anomalous", ValueType::Bool)],
            actor(),
            chrono::Utc::now(),
        )
    }

    fn apply(store: &mut MicroModelStore, kind: EventKind) {
        let event = Event::trigger(kind);
        store.apply_event(&event).unwrap();
    }

    #[test]
    fn register_model_indexes_kind_status() {
        let mut store = MicroModelStore::new();
        let def = definition("mm_lag_v0", MicroModelKind::ReplicationLagAnomaly);
        let id = def.id.clone();
        apply(
            &mut store,
            EventKind::MicroModelRegistered { model: def.clone() },
        );

        // Direct lookup hits the inserted model.
        assert_eq!(store.model(&id), Some(&def));
        assert_eq!(store.model_count(), 1);

        // Kind index resolves to the same model.
        let by_kind = store.models_by_kind(&MicroModelKind::ReplicationLagAnomaly);
        assert_eq!(by_kind.len(), 1);
        assert_eq!(by_kind[0].id, id);

        // Status index starts in Registered (per
        // MicroModelDefinition::registered).
        let by_status = store.models_by_status(&MicroModelStatus::Registered);
        assert_eq!(by_status.len(), 1);
        assert_eq!(by_status[0].id, id);

        // Unknown kind / status returns empty Vec rather than None.
        assert!(store
            .models_by_kind(&MicroModelKind::AutoTuner)
            .is_empty());
        assert!(store
            .models_by_status(&MicroModelStatus::Archived)
            .is_empty());
    }

    #[test]
    fn status_change_reindexes() {
        let mut store = MicroModelStore::new();
        let def = definition("mm_pred_v0", MicroModelKind::CommitRatePredictor);
        let id = def.id.clone();
        apply(&mut store, EventKind::MicroModelRegistered { model: def });

        // Registered → Active.
        apply(
            &mut store,
            EventKind::MicroModelStatusChanged {
                model_id: id.clone(),
                status: MicroModelStatus::Active,
                reason: None,
            },
        );

        // The embedded model's `status` is updated.
        assert_eq!(
            store.model(&id).unwrap().status,
            MicroModelStatus::Active
        );
        // Old status bucket is empty; new one carries the model.
        assert!(store
            .models_by_status(&MicroModelStatus::Registered)
            .is_empty());
        let active = store.models_by_status(&MicroModelStatus::Active);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, id);

        // Active → Disabled.
        apply(
            &mut store,
            EventKind::MicroModelStatusChanged {
                model_id: id.clone(),
                status: MicroModelStatus::Disabled,
                reason: Some("noisy in staging".to_string()),
            },
        );
        assert!(store
            .models_by_status(&MicroModelStatus::Active)
            .is_empty());
        assert_eq!(
            store.models_by_status(&MicroModelStatus::Disabled).len(),
            1
        );
    }

    #[test]
    fn status_change_on_unknown_model_is_no_op() {
        // Defensive — applying a status change for a model that was
        // never registered must leave the store in a coherent state.
        let mut store = MicroModelStore::new();
        apply(
            &mut store,
            EventKind::MicroModelStatusChanged {
                model_id: MicroModelId::from_str("mm_ghost"),
                status: MicroModelStatus::Active,
                reason: None,
            },
        );
        assert_eq!(store.model_count(), 0);
        assert!(store
            .models_by_status(&MicroModelStatus::Active)
            .is_empty());
    }

    #[test]
    fn prediction_recorded_roundtrip() {
        let mut store = MicroModelStore::new();
        let run_id = MicroModelRunId::from_str("mmrun_001");
        let prediction = MicroModelPrediction {
            model_id: MicroModelId::from_str("mm_lag_v0"),
            run_id: run_id.clone(),
            input: serde_json::json!({"recent_lag_commits": [12, 13, 14]}),
            output: serde_json::json!({"is_anomalous": false}),
            confidence: 0.87,
            explanation: Some("stable trend".to_string()),
            created_at: chrono::Utc::now(),
        };
        apply(
            &mut store,
            EventKind::MicroModelPredictionRecorded {
                prediction: prediction.clone(),
            },
        );
        assert_eq!(store.prediction(&run_id), Some(&prediction));
        assert_eq!(store.prediction_count(), 1);
    }

    #[test]
    fn observation_recorded_roundtrip() {
        let mut store = MicroModelStore::new();
        let run_id = MicroModelRunId::from_str("mmrun_001");
        let observation = MicroModelObservation {
            run_id: run_id.clone(),
            observed_outcome: serde_json::json!({"is_anomalous": false}),
            error: Some(0.0),
            observed_at: chrono::Utc::now(),
        };
        apply(
            &mut store,
            EventKind::MicroModelObservationRecorded {
                observation: observation.clone(),
            },
        );
        assert_eq!(store.observation(&run_id), Some(&observation));
        assert_eq!(store.observation_count(), 1);
    }

    #[test]
    fn non_micromodel_events_are_ignored() {
        // Stores in hydra-engine subscribe to the full event log;
        // non-relevant variants must be silently dropped without
        // touching state.
        let mut store = MicroModelStore::new();
        let irrelevant = Event::trigger(EventKind::Signal {
            source: hydra_core::NodeId::from_str("test"),
            name: "x".to_string(),
            payload: Default::default(),
        });
        store.apply_event(&irrelevant).unwrap();
        assert_eq!(store.model_count(), 0);
        assert_eq!(store.prediction_count(), 0);
        assert_eq!(store.observation_count(), 0);
    }
}
