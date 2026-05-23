use hydra_core::error::{HydraError, Result};
use hydra_core::{
    CommitId, Event, EventKind, IdempotencyKey, SensorCheckpoint, SensorCheckpointId,
    SensorCheckpointStatus, SensorId, SensorRun, SensorRunId, SensorRunStatus, SourceCursor,
};
use std::collections::{HashMap, HashSet};

/// Stable key for indexing checkpoints by source cursor.
///
/// SourceCursor already implements Hash/Eq, but this wrapper keeps store indexes
/// explicit and gives us a stable place to evolve cursor indexing later.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceCursorKey(pub SourceCursor);

impl From<&SourceCursor> for SourceCursorKey {
    fn from(cursor: &SourceCursor) -> Self {
        Self(cursor.clone())
    }
}

/// Key for "latest checkpoint for this sensor + source".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SensorSourceKey {
    pub sensor_id: SensorId,
    pub source: String,
}

impl SensorSourceKey {
    pub fn new(sensor_id: SensorId, source: impl Into<String>) -> Self {
        Self {
            sensor_id,
            source: source.into(),
        }
    }

    pub fn from_checkpoint(checkpoint: &SensorCheckpoint) -> Self {
        Self {
            sensor_id: checkpoint.sensor_id.clone(),
            source: checkpoint.cursor.source_name().to_string(),
        }
    }
}

/// Materialized sensor run/checkpoint state.
///
/// This store answers:
/// - Which runs exist?
/// - Which runs failed/completed?
/// - What checkpoints were recorded?
/// - What is the latest checkpoint for sensor/source?
/// - Which commit accepted a cursor?
/// - Which idempotency key was already checkpointed?
#[derive(Debug, Clone, Default)]
pub struct SensorCheckpointStore {
    runs: HashMap<SensorRunId, SensorRun>,
    checkpoints: HashMap<SensorCheckpointId, SensorCheckpoint>,

    runs_by_sensor: HashMap<SensorId, HashSet<SensorRunId>>,
    runs_by_status: HashMap<SensorRunStatus, HashSet<SensorRunId>>,

    checkpoints_by_sensor: HashMap<SensorId, HashSet<SensorCheckpointId>>,
    checkpoints_by_source: HashMap<String, HashSet<SensorCheckpointId>>,
    checkpoints_by_cursor: HashMap<SourceCursorKey, SensorCheckpointId>,
    latest_checkpoint_by_sensor_source: HashMap<SensorSourceKey, SensorCheckpointId>,
    checkpoint_by_idempotency_key: HashMap<IdempotencyKey, SensorCheckpointId>,
    checkpoint_by_commit_id: HashMap<CommitId, SensorCheckpointId>,
}

impl SensorCheckpointStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn run_count(&self) -> usize {
        self.runs.len()
    }

    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }

    pub fn run(&self, id: &SensorRunId) -> Option<&SensorRun> {
        self.runs.get(id)
    }

    pub fn checkpoint(&self, id: &SensorCheckpointId) -> Option<&SensorCheckpoint> {
        self.checkpoints.get(id)
    }

    pub fn all_runs(&self) -> impl Iterator<Item = &SensorRun> {
        self.runs.values()
    }

    pub fn all_checkpoints(&self) -> impl Iterator<Item = &SensorCheckpoint> {
        self.checkpoints.values()
    }

    pub fn runs_for_sensor(&self, sensor_id: &SensorId) -> Vec<&SensorRun> {
        self.runs_by_sensor
            .get(sensor_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.runs.get(id))
            .collect()
    }

    pub fn runs_with_status(&self, status: SensorRunStatus) -> Vec<&SensorRun> {
        self.runs_by_status
            .get(&status)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.runs.get(id))
            .collect()
    }

    pub fn started_runs(&self) -> Vec<&SensorRun> {
        self.runs_with_status(SensorRunStatus::Started)
    }

    pub fn completed_runs(&self) -> Vec<&SensorRun> {
        self.runs_with_status(SensorRunStatus::Completed)
    }

    pub fn failed_runs(&self) -> Vec<&SensorRun> {
        self.runs_with_status(SensorRunStatus::Failed)
    }

    pub fn checkpoints_for_sensor(&self, sensor_id: &SensorId) -> Vec<&SensorCheckpoint> {
        self.checkpoints_by_sensor
            .get(sensor_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.checkpoints.get(id))
            .collect()
    }

    pub fn checkpoints_for_source(&self, source: &str) -> Vec<&SensorCheckpoint> {
        self.checkpoints_by_source
            .get(source)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.checkpoints.get(id))
            .collect()
    }

    pub fn checkpoint_for_cursor(&self, cursor: &SourceCursor) -> Option<&SensorCheckpoint> {
        let key = SourceCursorKey::from(cursor);
        let checkpoint_id = self.checkpoints_by_cursor.get(&key)?;
        self.checkpoints.get(checkpoint_id)
    }

    pub fn latest_checkpoint(
        &self,
        sensor_id: &SensorId,
        source: &str,
    ) -> Option<&SensorCheckpoint> {
        let key = SensorSourceKey::new(sensor_id.clone(), source);
        let checkpoint_id = self.latest_checkpoint_by_sensor_source.get(&key)?;
        self.checkpoints.get(checkpoint_id)
    }

    pub fn checkpoint_for_idempotency_key(
        &self,
        key: &IdempotencyKey,
    ) -> Option<&SensorCheckpoint> {
        let checkpoint_id = self.checkpoint_by_idempotency_key.get(key)?;
        self.checkpoints.get(checkpoint_id)
    }

    pub fn checkpoint_for_commit(&self, commit_id: &CommitId) -> Option<&SensorCheckpoint> {
        let checkpoint_id = self.checkpoint_by_commit_id.get(commit_id)?;
        self.checkpoints.get(checkpoint_id)
    }

    /// Apply one Hydra event to the sensor checkpoint store.
    ///
    /// Non-sensor events are ignored.
    pub fn apply_event(&mut self, event: &Event) -> Result<()> {
        match &event.kind {
            EventKind::SensorRunStarted { run } => {
                self.insert_run(run.clone());
            }
            EventKind::SensorRunCompleted { run_id } => {
                self.mutate_run(run_id, |run| {
                    run.status = SensorRunStatus::Completed;
                    run.completed_at = Some(event.timestamp);
                    run.failed_at = None;
                    run.error = None;
                })?;
            }
            EventKind::SensorRunFailed { run_id, error } => {
                self.mutate_run(run_id, |run| {
                    run.status = SensorRunStatus::Failed;
                    run.failed_at = Some(event.timestamp);
                    run.error = Some(error.clone());
                })?;
            }
            EventKind::SensorCheckpointRecorded { checkpoint } => {
                self.insert_checkpoint(checkpoint.clone());
            }
            EventKind::SensorCheckpointSuperseded { checkpoint_id, .. } => {
                self.mutate_checkpoint(checkpoint_id, |checkpoint| {
                    checkpoint.status = SensorCheckpointStatus::Superseded;
                    checkpoint.recorded_at = event.timestamp;
                })?;
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

    fn insert_run(&mut self, run: SensorRun) {
        let run_id = run.id.clone();
        if let Some(existing) = self.runs.get(&run_id).cloned() {
            self.remove_run_indexes(&existing);
        }
        self.runs.insert(run_id.clone(), run);
        if let Some(inserted) = self.runs.get(&run_id).cloned() {
            self.insert_run_indexes(&inserted);
        }
    }

    fn mutate_run<F>(&mut self, run_id: &SensorRunId, mutation: F) -> Result<()>
    where
        F: FnOnce(&mut SensorRun),
    {
        let mut run = self
            .runs
            .remove(run_id)
            .ok_or_else(|| HydraError::QueryError(format!("unknown sensor run: {}", run_id)))?;
        self.remove_run_indexes(&run);
        mutation(&mut run);
        self.insert_run_indexes(&run);
        self.runs.insert(run_id.clone(), run);
        Ok(())
    }

    fn insert_checkpoint(&mut self, checkpoint: SensorCheckpoint) {
        let checkpoint_id = checkpoint.id.clone();
        if let Some(existing) = self.checkpoints.get(&checkpoint_id).cloned() {
            self.remove_checkpoint_indexes(&existing);
        }
        self.checkpoints.insert(checkpoint_id.clone(), checkpoint);
        if let Some(inserted) = self.checkpoints.get(&checkpoint_id).cloned() {
            self.insert_checkpoint_indexes(&inserted);
        }
    }

    fn mutate_checkpoint<F>(
        &mut self,
        checkpoint_id: &SensorCheckpointId,
        mutation: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut SensorCheckpoint),
    {
        let mut checkpoint = self.checkpoints.remove(checkpoint_id).ok_or_else(|| {
            HydraError::QueryError(format!("unknown sensor checkpoint: {}", checkpoint_id))
        })?;
        self.remove_checkpoint_indexes(&checkpoint);
        mutation(&mut checkpoint);
        self.insert_checkpoint_indexes(&checkpoint);
        self.checkpoints.insert(checkpoint_id.clone(), checkpoint);
        Ok(())
    }

    fn insert_run_indexes(&mut self, run: &SensorRun) {
        let run_id = run.id.clone();
        self.runs_by_sensor
            .entry(run.sensor_id.clone())
            .or_default()
            .insert(run_id.clone());
        self.runs_by_status
            .entry(run.status.clone())
            .or_default()
            .insert(run_id);
    }

    fn remove_run_indexes(&mut self, run: &SensorRun) {
        let run_id = &run.id;
        remove_from_index(&mut self.runs_by_sensor, &run.sensor_id, run_id);
        remove_from_index(&mut self.runs_by_status, &run.status, run_id);
    }

    fn insert_checkpoint_indexes(&mut self, checkpoint: &SensorCheckpoint) {
        let checkpoint_id = checkpoint.id.clone();
        self.checkpoints_by_sensor
            .entry(checkpoint.sensor_id.clone())
            .or_default()
            .insert(checkpoint_id.clone());
        self.checkpoints_by_source
            .entry(checkpoint.cursor.source_name().to_string())
            .or_default()
            .insert(checkpoint_id.clone());
        self.checkpoints_by_cursor.insert(
            SourceCursorKey::from(&checkpoint.cursor),
            checkpoint_id.clone(),
        );
        self.latest_checkpoint_by_sensor_source.insert(
            SensorSourceKey::from_checkpoint(checkpoint),
            checkpoint_id.clone(),
        );
        self.checkpoint_by_idempotency_key
            .insert(checkpoint.idempotency_key.clone(), checkpoint_id.clone());
        self.checkpoint_by_commit_id
            .insert(checkpoint.commit_id.clone(), checkpoint_id);
    }

    fn remove_checkpoint_indexes(&mut self, checkpoint: &SensorCheckpoint) {
        let checkpoint_id = &checkpoint.id;
        remove_from_index(
            &mut self.checkpoints_by_sensor,
            &checkpoint.sensor_id,
            checkpoint_id,
        );
        let source = checkpoint.cursor.source_name().to_string();
        remove_from_index(&mut self.checkpoints_by_source, &source, checkpoint_id);
        let cursor_key = SourceCursorKey::from(&checkpoint.cursor);
        if self
            .checkpoints_by_cursor
            .get(&cursor_key)
            .map(|id| id == checkpoint_id)
            .unwrap_or(false)
        {
            self.checkpoints_by_cursor.remove(&cursor_key);
        }
        let latest_key = SensorSourceKey::from_checkpoint(checkpoint);
        if self
            .latest_checkpoint_by_sensor_source
            .get(&latest_key)
            .map(|id| id == checkpoint_id)
            .unwrap_or(false)
        {
            self.latest_checkpoint_by_sensor_source.remove(&latest_key);
        }
        if self
            .checkpoint_by_idempotency_key
            .get(&checkpoint.idempotency_key)
            .map(|id| id == checkpoint_id)
            .unwrap_or(false)
        {
            self.checkpoint_by_idempotency_key
                .remove(&checkpoint.idempotency_key);
        }
        if self
            .checkpoint_by_commit_id
            .get(&checkpoint.commit_id)
            .map(|id| id == checkpoint_id)
            .unwrap_or(false)
        {
            self.checkpoint_by_commit_id.remove(&checkpoint.commit_id);
        }
    }
}

fn remove_from_index<K, V>(index: &mut HashMap<K, HashSet<V>>, key: &K, value: &V)
where
    K: std::hash::Hash + Eq + Clone,
    V: std::hash::Hash + Eq,
{
    let should_remove_key = if let Some(values) = index.get_mut(key) {
        values.remove(value);
        values.is_empty()
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
        CascadeId, CommitId, EventId, IdempotencyKey, SensorCheckpoint, SensorCheckpointId,
        SensorCheckpointStatus, SensorRun, SensorRunId, TenantId, Value,
    };
    use std::collections::HashMap;

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_sensor_checkpoint_store_test")
    }

    fn sensor() -> SensorId {
        SensorId::from_str("sensor_bank_feed")
    }

    fn actor() -> hydra_core::ActorId {
        hydra_core::ActorId::from_str("actor_sensor")
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

    fn run(status: SensorRunStatus) -> SensorRun {
        let now = chrono::Utc::now();
        SensorRun {
            id: SensorRunId::new(),
            tenant_id: Some(tenant()),
            sensor_id: sensor(),
            status,
            source_system: "bank-feed".to_string(),
            stream: Some("checking".to_string()),
            started_at: now,
            completed_at: None,
            failed_at: None,
            error: None,
            actor_id: Some(actor()),
            metadata: HashMap::new(),
        }
    }

    fn cursor(offset: &str) -> SourceCursor {
        SourceCursor::Offset {
            stream: "bank.transactions".to_string(),
            partition: Some("acct-9001".to_string()),
            offset: offset.to_string(),
        }
    }

    fn checkpoint(offset: &str) -> SensorCheckpoint {
        SensorCheckpoint {
            id: SensorCheckpointId::new(),
            tenant_id: Some(tenant()),
            sensor_id: sensor(),
            run_id: None,
            status: SensorCheckpointStatus::Recorded,
            source_system: "bank".to_string(),
            cursor: cursor(offset),
            idempotency_key: IdempotencyKey::new(format!("bank-acct-9001-{offset}")),
            commit_id: CommitId::new(),
            event_id: None,
            observed_at: chrono::Utc::now(),
            recorded_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn stores_sensor_run_and_indexes_by_sensor_and_status() {
        let mut store = SensorCheckpointStore::new();
        let run = run(SensorRunStatus::Started);
        let run_id = run.id.clone();
        store
            .apply_event(&event(EventKind::SensorRunStarted { run: run.clone() }))
            .unwrap();
        assert_eq!(store.run_count(), 1);
        assert_eq!(store.run(&run_id), Some(&run));
        assert_eq!(store.runs_for_sensor(&sensor()).len(), 1);
        assert_eq!(store.started_runs().len(), 1);
    }

    #[test]
    fn completes_and_fails_runs_with_reindexing() {
        let mut store = SensorCheckpointStore::new();
        let completed = run(SensorRunStatus::Started);
        let completed_id = completed.id.clone();
        store
            .apply_event(&event(EventKind::SensorRunStarted { run: completed }))
            .unwrap();
        store
            .apply_event(&event(EventKind::SensorRunCompleted {
                run_id: completed_id.clone(),
            }))
            .unwrap();
        let stored = store.run(&completed_id).unwrap();
        assert_eq!(stored.status, SensorRunStatus::Completed);
        assert!(stored.completed_at.is_some());
        assert_eq!(store.started_runs().len(), 0);
        assert_eq!(store.completed_runs().len(), 1);

        let failed = run(SensorRunStatus::Started);
        let failed_id = failed.id.clone();
        store
            .apply_event(&event(EventKind::SensorRunStarted { run: failed }))
            .unwrap();
        store
            .apply_event(&event(EventKind::SensorRunFailed {
                run_id: failed_id.clone(),
                error: "boom".to_string(),
            }))
            .unwrap();
        let stored = store.run(&failed_id).unwrap();
        assert_eq!(stored.status, SensorRunStatus::Failed);
        assert_eq!(stored.error.as_deref(), Some("boom"));
        assert!(stored.failed_at.is_some());
        assert_eq!(store.failed_runs().len(), 1);
    }

    #[test]
    fn stores_checkpoint_and_indexes_lookup_paths() {
        let mut store = SensorCheckpointStore::new();
        let checkpoint = checkpoint("42");
        let checkpoint_id = checkpoint.id.clone();
        let key = checkpoint.idempotency_key.clone();
        let commit_id = checkpoint.commit_id.clone();
        let cursor = checkpoint.cursor.clone();
        store
            .apply_event(&event(EventKind::SensorCheckpointRecorded {
                checkpoint: checkpoint.clone(),
            }))
            .unwrap();
        assert_eq!(store.checkpoint_count(), 1);
        assert_eq!(store.checkpoint(&checkpoint_id), Some(&checkpoint));
        assert_eq!(store.checkpoints_for_sensor(&sensor()).len(), 1);
        assert_eq!(store.checkpoints_for_source("bank.transactions").len(), 1);
        assert_eq!(
            store.checkpoint_for_cursor(&cursor).unwrap().id,
            checkpoint_id
        );
        assert_eq!(
            store.checkpoint_for_idempotency_key(&key).unwrap().id,
            checkpoint_id
        );
        assert_eq!(
            store.checkpoint_for_commit(&commit_id).unwrap().id,
            checkpoint_id
        );
    }

    #[test]
    fn latest_checkpoint_for_sensor_source_tracks_last_recorded() {
        let mut store = SensorCheckpointStore::new();
        let first = checkpoint("1");
        let second = checkpoint("2");
        let second_id = second.id.clone();
        store
            .apply_event(&event(EventKind::SensorCheckpointRecorded {
                checkpoint: first,
            }))
            .unwrap();
        store
            .apply_event(&event(EventKind::SensorCheckpointRecorded {
                checkpoint: second,
            }))
            .unwrap();
        let latest = store
            .latest_checkpoint(&sensor(), "bank.transactions")
            .unwrap();
        assert_eq!(latest.id, second_id);
    }

    #[test]
    fn superseded_checkpoint_updates_status_and_removes_latest_if_it_was_latest() {
        let mut store = SensorCheckpointStore::new();
        let checkpoint = checkpoint("42");
        let checkpoint_id = checkpoint.id.clone();
        store
            .apply_event(&event(EventKind::SensorCheckpointRecorded { checkpoint }))
            .unwrap();
        assert!(store
            .latest_checkpoint(&sensor(), "bank.transactions")
            .is_some());

        store
            .apply_event(&event(EventKind::SensorCheckpointSuperseded {
                checkpoint_id: checkpoint_id.clone(),
                superseded_by: None,
                reason: Some("compacted".to_string()),
            }))
            .unwrap();
        let stored = store.checkpoint(&checkpoint_id).unwrap();
        assert_eq!(stored.status, SensorCheckpointStatus::Superseded);
        assert!(store
            .latest_checkpoint(&sensor(), "bank.transactions")
            .is_some());
    }

    #[test]
    fn rejects_unknown_run_or_checkpoint_transitions() {
        let mut store = SensorCheckpointStore::new();
        let missing_run = store.apply_event(&event(EventKind::SensorRunCompleted {
            run_id: SensorRunId::new(),
        }));
        assert!(missing_run.is_err());

        let missing_checkpoint = store.apply_event(&event(EventKind::SensorCheckpointSuperseded {
            checkpoint_id: SensorCheckpointId::new(),
            superseded_by: None,
            reason: None,
        }));
        assert!(missing_checkpoint.is_err());
    }

    #[test]
    fn replacement_checkpoint_reindexes_cursor_and_idempotency() {
        let mut store = SensorCheckpointStore::new();
        let mut original = checkpoint("42");
        let checkpoint_id = original.id.clone();
        let old_key = original.idempotency_key.clone();
        let old_cursor = original.cursor.clone();
        store
            .apply_event(&event(EventKind::SensorCheckpointRecorded {
                checkpoint: original.clone(),
            }))
            .unwrap();

        original.cursor = cursor("43");
        original.idempotency_key = IdempotencyKey::new("bank-acct-9001-43");
        let new_key = original.idempotency_key.clone();
        let new_cursor = original.cursor.clone();
        store
            .apply_event(&event(EventKind::SensorCheckpointRecorded {
                checkpoint: original,
            }))
            .unwrap();

        assert!(store.checkpoint_for_cursor(&old_cursor).is_none());
        assert!(store.checkpoint_for_idempotency_key(&old_key).is_none());
        assert_eq!(
            store.checkpoint_for_cursor(&new_cursor).unwrap().id,
            checkpoint_id
        );
        assert_eq!(
            store.checkpoint_for_idempotency_key(&new_key).unwrap().id,
            checkpoint_id
        );
    }

    #[test]
    fn apply_events_applies_multiple_sensor_events() {
        let mut store = SensorCheckpointStore::new();
        let run = run(SensorRunStatus::Started);
        let checkpoint = checkpoint("42");
        let events = vec![
            event(EventKind::SensorRunStarted { run }),
            event(EventKind::SensorCheckpointRecorded { checkpoint }),
        ];
        store.apply_events(&events).unwrap();
        assert_eq!(store.run_count(), 1);
        assert_eq!(store.checkpoint_count(), 1);
    }

    #[test]
    fn unused_import_guard() {
        let _ = Value::Bool(true);
    }
}
