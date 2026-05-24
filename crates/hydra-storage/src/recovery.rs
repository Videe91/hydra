use crate::commit_log::CommitLog;
use hydra_core::error::Result;
use hydra_core::{ActorId, SnapshotId, SnapshotManifest};
use hydra_engine::hydra::Hydra;
use hydra_engine::snapshot_store::SnapshotBackend;

/// How `recover_from_latest_snapshot_or_commit_log` chose to recover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryMode {
    /// No snapshots and no commits — Hydra was left empty.
    Empty,
    /// Snapshots were absent. Recovery replayed the full commit log.
    CommitLog,
    /// Latest snapshot loaded; replay tail applied on top.
    SnapshotAndReplay,
}

/// Result of a one-call restart.
///
/// Includes the mode chosen, the snapshot used (if any), and counts useful
/// for operator dashboards and startup logs.
#[derive(Debug, Clone)]
pub struct RecoveryReport {
    pub mode: RecoveryMode,
    pub snapshot_id: Option<SnapshotId>,
    pub snapshot_sequence: Option<u64>,
    pub replayed_commit_count: usize,
    pub total_commits_loaded: usize,
    pub manifest: Option<SnapshotManifest>,
}

impl RecoveryReport {
    pub fn empty() -> Self {
        Self {
            mode: RecoveryMode::Empty,
            snapshot_id: None,
            snapshot_sequence: None,
            replayed_commit_count: 0,
            total_commits_loaded: 0,
            manifest: None,
        }
    }
}

/// Recover `hydra` from the fastest available durable source.
///
/// Decision tree:
/// 1. If the snapshot backend has at least one manifest, load the latest
///    body and call `Hydra::recover_from_snapshot_body_and_replay` with
///    every commit batch from the log. The engine filters the replay tail
///    to batches with `sequence > snapshot.sequence`.
/// 2. Else if the commit log is non-empty, call `Hydra::recover_from_commits`.
/// 3. Else leave `hydra` untouched and report `RecoveryMode::Empty`.
///
/// Returns a `RecoveryReport` so callers can log the choice and counts.
pub fn recover_from_latest_snapshot_or_commit_log<B>(
    snapshot_backend: &B,
    commit_log: &CommitLog,
    hydra: &mut Hydra,
    actor: ActorId,
) -> Result<RecoveryReport>
where
    B: SnapshotBackend,
{
    let commits = commit_log.load_all()?;
    let manifests = snapshot_backend.list_snapshot_manifests()?;
    let latest = manifests
        .into_iter()
        .max_by_key(|manifest| manifest.sequence);

    match latest {
        Some(manifest) => {
            let body = snapshot_backend.read_snapshot(&manifest.id)?;
            let total_commits_loaded = commits.len();
            // Count the replay tail before handing `commits` to the engine
            // (which consumes it). Mirrors the engine's filter rule so the
            // report stays accurate.
            let replayed_commit_count = commits
                .iter()
                .filter(|batch| batch.sequence > manifest.sequence)
                .count();
            let restored_manifest = hydra.recover_from_snapshot_body_and_replay(
                body,
                commits,
                actor,
            )?;
            Ok(RecoveryReport {
                mode: RecoveryMode::SnapshotAndReplay,
                snapshot_id: Some(manifest.id),
                snapshot_sequence: Some(manifest.sequence),
                replayed_commit_count,
                total_commits_loaded,
                manifest: Some(restored_manifest),
            })
        }
        None if !commits.is_empty() => {
            let total_commits_loaded = commits.len();
            hydra.recover_from_commits(commits)?;
            Ok(RecoveryReport {
                mode: RecoveryMode::CommitLog,
                snapshot_id: None,
                snapshot_sequence: None,
                replayed_commit_count: total_commits_loaded,
                total_commits_loaded,
                manifest: None,
            })
        }
        None => Ok(RecoveryReport::empty()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit_log::CommitLog;
    use crate::snapshot::FileSnapshotStore;
    use hydra_core::{ActorId, EventKind, NodeId};
    use hydra_engine::hydra::Hydra;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn actor() -> ActorId {
        ActorId::from_str("actor_storage_recovery")
    }

    fn signal(name: &str) -> EventKind {
        EventKind::Signal {
            source: NodeId::from_str("storage.recovery"),
            name: name.to_string(),
            payload: HashMap::new(),
        }
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hydra_storage_recovery_{name}_{}_{}",
            std::process::id(),
            chrono::Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
        ))
    }

    #[test]
    fn recovery_empty_when_no_snapshots_or_commits() {
        let root = temp_root("empty");
        let snapshot_store = FileSnapshotStore::open(&root).unwrap();
        let commit_log = CommitLog::open(root.join("commits.jsonl")).unwrap();

        let mut hydra = Hydra::new();
        let report = recover_from_latest_snapshot_or_commit_log(
            &snapshot_store,
            &commit_log,
            &mut hydra,
            actor(),
        )
        .unwrap();

        assert_eq!(report.mode, RecoveryMode::Empty);
        assert_eq!(report.total_commits_loaded, 0);
        assert_eq!(hydra.commit_count(), 0);
        assert_eq!(hydra.events().len(), 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn recovery_falls_back_to_commit_log_when_no_snapshot_exists() {
        let root = temp_root("commit_log");
        let snapshot_store = FileSnapshotStore::open(&root).unwrap();
        let commit_log = CommitLog::open(root.join("commits.jsonl")).unwrap();

        // Build a source Hydra that writes its commits through to the
        // shared CommitLog. No snapshots are taken.
        let mut source = Hydra::new();
        source.set_commit_writer(commit_log.clone());
        source.ingest(signal("one")).unwrap();
        source.ingest(signal("two")).unwrap();

        let mut recovered = Hydra::new();
        let report = recover_from_latest_snapshot_or_commit_log(
            &snapshot_store,
            &commit_log,
            &mut recovered,
            actor(),
        )
        .unwrap();

        assert_eq!(report.mode, RecoveryMode::CommitLog);
        assert_eq!(report.total_commits_loaded, 2);
        assert_eq!(report.replayed_commit_count, 2);
        assert_eq!(recovered.commit_count(), 2);
        assert_eq!(
            recovered
                .events()
                .into_iter()
                .filter(|event| event.kind.kind_name() == "signal")
                .count(),
            2
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn recovery_uses_latest_snapshot_and_replays_commit_tail() {
        let root = temp_root("snapshot_tail");
        let snapshot_store = FileSnapshotStore::open(&root).unwrap();
        let commit_log = CommitLog::open(root.join("commits.jsonl")).unwrap();

        // Source Hydra wired to BOTH a CommitLog writer and a
        // FileSnapshotStore backend. Ingest one signal, snapshot, then
        // ingest two more — exercises the snapshot + replay-tail path.
        let mut source = Hydra::new();
        source.set_commit_writer(commit_log.clone());
        source.set_snapshot_backend(snapshot_store.clone());
        source.ingest(signal("before")).unwrap();
        let manifest = source.snapshot(actor()).unwrap();
        source.ingest(signal("after_one")).unwrap();
        source.ingest(signal("after_two")).unwrap();

        let mut recovered = Hydra::new();
        let report = recover_from_latest_snapshot_or_commit_log(
            &snapshot_store,
            &commit_log,
            &mut recovered,
            actor(),
        )
        .unwrap();

        assert_eq!(report.mode, RecoveryMode::SnapshotAndReplay);
        assert_eq!(report.snapshot_id, Some(manifest.id.clone()));
        assert_eq!(report.snapshot_sequence, Some(manifest.sequence));
        // Replay tail: SnapshotTaken (N+1) + after_one (N+2) + after_two (N+3).
        assert_eq!(report.replayed_commit_count, 3);

        let names = recovered
            .events()
            .into_iter()
            .map(|event| event.kind.kind_name().to_string())
            .collect::<Vec<_>>();
        assert!(names.contains(&"snapshot_taken".to_string()));
        assert!(names.contains(&"snapshot_restored".to_string()));
        // "before" (from snapshot body) + "after_one" + "after_two" = 3 signals.
        assert_eq!(
            names.iter().filter(|name| *name == "signal").count(),
            3
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Load-bearing proof for commit-log compaction: snapshot at N, drop
    /// commits <= N from the log, recovery must still rebuild the same
    /// state from the snapshot body + the retained replay tail.
    #[test]
    fn recovery_works_after_snapshot_compacts_commit_log() {
        let root = temp_root("compact_after_snapshot");
        let snapshot_store = FileSnapshotStore::open(&root).unwrap();
        let commit_log = CommitLog::open(root.join("commits.jsonl")).unwrap();

        let mut source = Hydra::new();
        source.set_commit_writer(commit_log.clone());
        source.set_snapshot_backend(snapshot_store.clone());
        source.ingest(signal("before")).unwrap();
        let manifest = source.snapshot(actor()).unwrap();
        source.ingest(signal("after_one")).unwrap();
        source.ingest(signal("after_two")).unwrap();

        // Compact pre-snapshot commits. After this, the on-disk log only
        // contains sequence N+1 (SnapshotTaken), N+2, N+3.
        let report = commit_log.compact_through(manifest.sequence).unwrap();
        assert!(report.removed_count >= 1);
        assert_eq!(report.retained_count, 3);

        // Recovery must still succeed: snapshot body covers sequence <= N,
        // retained log covers sequence > N. Together they reconstruct the
        // full materialized state.
        let mut recovered = Hydra::new();
        let recovery = recover_from_latest_snapshot_or_commit_log(
            &snapshot_store,
            &commit_log,
            &mut recovered,
            actor(),
        )
        .unwrap();
        assert_eq!(recovery.mode, RecoveryMode::SnapshotAndReplay);
        assert_eq!(recovery.replayed_commit_count, 3);

        let names = recovered
            .events()
            .into_iter()
            .map(|event| event.kind.kind_name().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            names.iter().filter(|name| *name == "signal").count(),
            3
        );
        assert!(names.contains(&"snapshot_taken".to_string()));
        assert!(names.contains(&"snapshot_restored".to_string()));

        let _ = std::fs::remove_dir_all(&root);
    }
}
