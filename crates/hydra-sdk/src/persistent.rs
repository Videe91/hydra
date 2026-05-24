use hydra_core::error::Result;
use hydra_core::ActorId;
use hydra_engine::cascade::CascadeConfig;
use hydra_engine::hydra::Hydra;
use hydra_engine::snapshot_store::SnapshotBackend;
use hydra_storage::commit_log::{CommitLog, CommitLogCompactionReport};
use hydra_storage::recovery::{recover_from_latest_snapshot_or_commit_log, RecoveryReport};
use hydra_storage::snapshot::FileSnapshotStore;
use std::path::{Path, PathBuf};

/// SDK-facing persistent runtime bootstrap.
///
/// The "open a real on-disk Hydra" convenience layer:
/// - opens the commit log at `<root>/commits.jsonl`
/// - opens the snapshot store rooted at `<root>`
/// - recovers from the fastest available durable source
/// - attaches both backends to the recovered Hydra so future writes
///   and snapshots persist automatically
///
/// Layout on disk:
/// ```text
/// <root>/
///     commits.jsonl                       JSONL commit log
///     snapshots/
///         index.jsonl                     manifest index
///         <snapshot_id>.json              full snapshot bodies
/// ```
pub struct HydraRuntime;

impl HydraRuntime {
    /// Open (or create) a persistent Hydra rooted at `root`.
    ///
    /// On fresh roots returns an empty `Hydra` ready for first writes.
    /// On existing roots recovers from the latest snapshot + replay tail
    /// (or full commit log if no snapshots exist).
    pub fn open_persistent(
        root: impl AsRef<Path>,
        actor: ActorId,
    ) -> Result<(Hydra, RecoveryReport)> {
        Self::open_persistent_inner(root.as_ref(), actor, None)
    }

    /// Same as [`open_persistent`], but with a custom `CascadeConfig` used
    /// only on cold-start (no existing snapshot/commits).
    ///
    /// Note: when recovery loads from disk, the engine's cascade config
    /// is re-applied through `reset_runtime_state_preserving_config` —
    /// the supplied config is the initial config for a fresh Hydra.
    pub fn open_persistent_with_config(
        root: impl AsRef<Path>,
        actor: ActorId,
        config: CascadeConfig,
    ) -> Result<(Hydra, RecoveryReport)> {
        Self::open_persistent_inner(root.as_ref(), actor, Some(config))
    }

    fn open_persistent_inner(
        root: &Path,
        actor: ActorId,
        config: Option<CascadeConfig>,
    ) -> Result<(Hydra, RecoveryReport)> {
        let commit_log = CommitLog::open(commit_log_path(root))?;
        let snapshot_store = FileSnapshotStore::open(root)?;

        let mut hydra = match config {
            Some(config) => Hydra::with_config(config),
            None => Hydra::new(),
        };

        let report = recover_from_latest_snapshot_or_commit_log(
            &snapshot_store,
            &commit_log,
            &mut hydra,
            actor,
        )?;

        // Attach persistence AFTER recovery so recovery itself does not
        // write fresh commits or snapshots through to disk. Future writes
        // are durable.
        hydra.set_commit_writer(commit_log);
        hydra.set_snapshot_backend(snapshot_store);

        Ok((hydra, report))
    }

    /// Compact the persistent commit log through the latest durable snapshot.
    ///
    /// Opens both backends at `root`, finds the latest snapshot manifest,
    /// and drops every commit batch with `sequence <= manifest.sequence`.
    /// On restart, recovery loads the snapshot body and replays the
    /// retained tail — identical post-state to a never-compacted log.
    ///
    /// Returns:
    /// - `Ok(None)` when no snapshots exist (nothing safe to drop yet).
    /// - `Ok(Some(report))` when compaction ran.
    ///
    /// Safe by construction: always compacts through a snapshot's
    /// sequence, never past one. Callers can run this on a live root
    /// while another process holds the runtime; the compaction is an
    /// atomic file rewrite (tempfile + rename) so the worst case is
    /// the running process sees its log replaced under it on next
    /// `load_all` — recovery on that process's next restart still works.
    /// Concurrent-writer hardening (file locking) is a future patch.
    pub fn compact_commit_log_through_latest_snapshot(
        root: impl AsRef<Path>,
    ) -> Result<Option<CommitLogCompactionReport>> {
        let root = root.as_ref();
        let commit_log = CommitLog::open(commit_log_path(root))?;
        let snapshot_store = FileSnapshotStore::open(root)?;
        let latest = snapshot_store
            .list_snapshot_manifests()?
            .into_iter()
            .max_by_key(|manifest| manifest.sequence);
        match latest {
            Some(manifest) => {
                let report = commit_log.compact_through(manifest.sequence)?;
                Ok(Some(report))
            }
            None => Ok(None),
        }
    }
}

fn commit_log_path(root: &Path) -> PathBuf {
    root.join("commits.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{EventKind, NodeId};
    use hydra_storage::recovery::RecoveryMode;
    use std::collections::HashMap;

    fn actor() -> ActorId {
        ActorId::from_str("actor_sdk_persistent")
    }

    fn signal(name: &str) -> EventKind {
        EventKind::Signal {
            source: NodeId::from_str("sdk.persistent"),
            name: name.to_string(),
            payload: HashMap::new(),
        }
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hydra_sdk_persistent_{name}_{}_{}",
            std::process::id(),
            chrono::Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
        ))
    }

    #[test]
    fn open_persistent_fresh_root_returns_empty_report() {
        let root = temp_root("fresh");
        let (hydra, report) = HydraRuntime::open_persistent(&root, actor()).unwrap();

        assert_eq!(report.mode, RecoveryMode::Empty);
        assert_eq!(hydra.commit_count(), 0);
        assert!(hydra.has_commit_writer());
        assert!(hydra.has_snapshot_backend());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_persistent_recovers_commit_log_after_restart() {
        let root = temp_root("commit_log");
        // Phase 1: open fresh, ingest, drop.
        {
            let (mut hydra, report) = HydraRuntime::open_persistent(&root, actor()).unwrap();
            assert_eq!(report.mode, RecoveryMode::Empty);
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
            assert_eq!(hydra.commit_count(), 2);
        }
        // Phase 2: reopen, verify recovery from commit log.
        {
            let (hydra, report) = HydraRuntime::open_persistent(&root, actor()).unwrap();
            assert_eq!(report.mode, RecoveryMode::CommitLog);
            assert_eq!(report.total_commits_loaded, 2);
            assert_eq!(hydra.commit_count(), 2);
            let signal_count = hydra
                .events()
                .into_iter()
                .filter(|event| event.kind.kind_name() == "signal")
                .count();
            assert_eq!(signal_count, 2);
            assert!(hydra.has_commit_writer());
            assert!(hydra.has_snapshot_backend());
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_persistent_recovers_snapshot_and_replays_tail() {
        let root = temp_root("snapshot_tail");
        // Phase 1: ingest, snapshot, ingest more, drop.
        {
            let (mut hydra, report) = HydraRuntime::open_persistent(&root, actor()).unwrap();
            assert_eq!(report.mode, RecoveryMode::Empty);
            hydra.ingest(signal("before")).unwrap();
            hydra.snapshot(actor()).unwrap();
            hydra.ingest(signal("after_one")).unwrap();
            hydra.ingest(signal("after_two")).unwrap();
        }
        // Phase 2: reopen, verify snapshot+replay path.
        {
            let (hydra, report) = HydraRuntime::open_persistent(&root, actor()).unwrap();
            assert_eq!(report.mode, RecoveryMode::SnapshotAndReplay);
            // Replay tail: SnapshotTaken (N+1) + after_one (N+2) + after_two (N+3).
            assert_eq!(report.replayed_commit_count, 3);

            let names = hydra
                .events()
                .into_iter()
                .map(|event| event.kind.kind_name().to_string())
                .collect::<Vec<_>>();
            assert!(names.contains(&"snapshot_taken".to_string()));
            assert!(names.contains(&"snapshot_restored".to_string()));
            assert_eq!(
                names.iter().filter(|name| *name == "signal").count(),
                3
            );
            assert!(hydra.has_commit_writer());
            assert!(hydra.has_snapshot_backend());
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_persistent_with_config_uses_supplied_config() {
        let root = temp_root("config");
        let config = CascadeConfig::default();
        let (hydra, report) =
            HydraRuntime::open_persistent_with_config(&root, actor(), config).unwrap();

        assert_eq!(report.mode, RecoveryMode::Empty);
        assert_eq!(hydra.commit_count(), 0);
        assert!(hydra.has_commit_writer());
        assert!(hydra.has_snapshot_backend());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compact_commit_log_through_latest_snapshot_returns_none_without_snapshots() {
        let root = temp_root("compact_none");
        // Open + drop just to materialize the directory and an empty log file.
        {
            let (_, _) = HydraRuntime::open_persistent(&root, actor()).unwrap();
        }
        let result =
            HydraRuntime::compact_commit_log_through_latest_snapshot(&root).unwrap();
        assert!(result.is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compact_commit_log_through_latest_snapshot_compacts_and_recovery_still_works() {
        let root = temp_root("compact_latest");

        // Phase 1: open, ingest, snapshot, ingest more.
        let snapshot_sequence;
        {
            let (mut hydra, report) =
                HydraRuntime::open_persistent(&root, actor()).unwrap();
            assert_eq!(report.mode, RecoveryMode::Empty);
            hydra.ingest(signal("before")).unwrap();
            let manifest = hydra.snapshot(actor()).unwrap();
            hydra.ingest(signal("after_one")).unwrap();
            hydra.ingest(signal("after_two")).unwrap();
            snapshot_sequence = manifest.sequence;
            assert_eq!(snapshot_sequence, 1);
        }

        // Phase 2: compact through the snapshot.
        let report =
            HydraRuntime::compact_commit_log_through_latest_snapshot(&root)
                .unwrap()
                .unwrap();
        assert_eq!(report.cutoff_sequence, snapshot_sequence);
        assert_eq!(report.removed_count, 1);
        // Retained: SnapshotTaken (N+1), after_one (N+2), after_two (N+3).
        assert_eq!(report.retained_count, 3);

        // Phase 3: recovery still works using snapshot + compacted tail.
        {
            let (hydra, recovery) =
                HydraRuntime::open_persistent(&root, actor()).unwrap();
            assert_eq!(recovery.mode, RecoveryMode::SnapshotAndReplay);
            assert_eq!(recovery.replayed_commit_count, 3);
            let names = hydra
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
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compact_commit_log_through_latest_snapshot_uses_highest_sequence() {
        let root = temp_root("compact_latest_sequence");

        // Two snapshots — the helper must use the later one as the cutoff.
        let (first_sequence, second_sequence);
        {
            let (mut hydra, _) =
                HydraRuntime::open_persistent(&root, actor()).unwrap();
            hydra.ingest(signal("one")).unwrap();
            let first = hydra.snapshot(actor()).unwrap();
            hydra.ingest(signal("two")).unwrap();
            let second = hydra.snapshot(actor()).unwrap();
            assert!(second.sequence > first.sequence);
            first_sequence = first.sequence;
            second_sequence = second.sequence;
        }

        let report =
            HydraRuntime::compact_commit_log_through_latest_snapshot(&root)
                .unwrap()
                .unwrap();
        assert_eq!(report.cutoff_sequence, second_sequence);
        assert!(report.cutoff_sequence > first_sequence);

        // Recovery loads the second (latest) snapshot.
        let (hydra, recovery) =
            HydraRuntime::open_persistent(&root, actor()).unwrap();
        assert_eq!(recovery.mode, RecoveryMode::SnapshotAndReplay);
        assert_eq!(recovery.snapshot_sequence, Some(second_sequence));
        let names = hydra
            .events()
            .into_iter()
            .map(|event| event.kind.kind_name().to_string())
            .collect::<Vec<_>>();
        assert!(names.contains(&"snapshot_restored".to_string()));

        let _ = std::fs::remove_dir_all(&root);
    }
}
