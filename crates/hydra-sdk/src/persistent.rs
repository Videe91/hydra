use hydra_core::error::Result;
use hydra_core::ActorId;
use hydra_engine::cascade::CascadeConfig;
use hydra_engine::hydra::Hydra;
use hydra_engine::snapshot_store::SnapshotBackend;
use hydra_storage::commit_log::{CommitLog, CommitLogCompactionReport};
use hydra_storage::recovery::{
    recover_from_latest_snapshot_or_commit_log, RecoveryMode, RecoveryReport,
};
use hydra_storage::snapshot::FileSnapshotStore;
use std::path::{Path, PathBuf};

/// Read-only summary of a persistent Hydra root.
///
/// Returned by [`HydraRuntime::inspect_persistent_state`]. Lets operators
/// see what `open_persistent` would do without actually opening the engine
/// or mutating anything on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectReport {
    pub commit_count: usize,
    pub snapshot_count: usize,
    pub latest_snapshot_sequence: Option<u64>,
    pub recommended_recovery: RecoveryMode,
}

/// Result of [`HydraRuntime::verify_persistent_state`].
///
/// `valid == true` means the durable commit log is a self-consistent
/// hash chain. `message` carries the engine's error string when invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub valid: bool,
    pub commits: usize,
    pub message: Option<String>,
}

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
    /// Open a persistent Hydra root, take a durable snapshot, and return
    /// its manifest.
    ///
    /// The opened `Hydra` has both the commit writer and snapshot backend
    /// attached, so `snapshot(...)` writes the body through to disk before
    /// committing the `SnapshotTaken` audit event. The Hydra is dropped at
    /// the end of the call — this helper is for one-shot operator tooling
    /// (cron snapshots, `hydra-cli snapshot`), not long-lived processes.
    pub fn snapshot_persistent_root(
        root: impl AsRef<Path>,
        actor: ActorId,
    ) -> Result<hydra_core::SnapshotManifest> {
        let (mut hydra, _report) = Self::open_persistent(root, actor.clone())?;
        hydra.snapshot(actor)
    }

    /// Inspect persistent Hydra state without performing recovery or
    /// mutating anything on disk.
    ///
    /// Opens the commit log + snapshot store read-only, counts durable
    /// records, and computes the recovery path that a subsequent
    /// [`open_persistent`](Self::open_persistent) call would take. Useful
    /// as a pre-flight check before running [`compact_commit_log_through_latest_snapshot`](Self::compact_commit_log_through_latest_snapshot)
    /// or before promoting a directory to a hot Hydra instance.
    pub fn inspect_persistent_state(
        root: impl AsRef<Path>,
    ) -> Result<InspectReport> {
        let root = root.as_ref();
        let commit_log = CommitLog::open(commit_log_path(root))?;
        let snapshot_store = FileSnapshotStore::open(root)?;
        let commits = commit_log.load_all()?;
        let manifests = snapshot_store.list_snapshot_manifests()?;

        let latest_snapshot_sequence =
            manifests.iter().map(|manifest| manifest.sequence).max();
        let recommended_recovery = if manifests.is_empty() && commits.is_empty() {
            RecoveryMode::Empty
        } else if manifests.is_empty() {
            RecoveryMode::CommitLog
        } else {
            RecoveryMode::SnapshotAndReplay
        };

        Ok(InspectReport {
            commit_count: commits.len(),
            snapshot_count: manifests.len(),
            latest_snapshot_sequence,
            recommended_recovery,
        })
    }

    /// Verify the persistent commit chain from the full commit log.
    ///
    /// Intentionally bypasses snapshot fast-recovery: verification is a
    /// full-chain operation that validates the durable commit log itself,
    /// not just the materialized state restored from the latest snapshot.
    /// The helper opens the log, loads every batch, rebuilds an in-memory
    /// `Hydra` via `recover_from_commits`, then runs `verify_commit_chain`.
    ///
    /// On success returns `valid: true, message: None`. Any engine error
    /// during recovery or verification is captured as `valid: false` with
    /// the error's `Display` form in `message`.
    ///
    /// **Limitation**: this verifies the current commit log file as a
    /// standalone genesis chain. If the log has been compacted past a
    /// snapshot, the retained tail does not start at sequence 1 and
    /// `recover_from_commits` may reject it as non-contiguous. A future
    /// snapshot-aware verifier (`verify_recoverability`) will validate
    /// compacted roots by combining snapshot + tail.
    pub fn verify_persistent_state(
        root: impl AsRef<Path>,
    ) -> Result<VerifyReport> {
        let root = root.as_ref();
        let commit_log = CommitLog::open(commit_log_path(root))?;
        let commits = commit_log.load_all()?;
        let commit_count = commits.len();
        let mut hydra = Hydra::new();
        match hydra.recover_from_commits(commits) {
            Ok(()) => match hydra.verify_commit_chain() {
                Ok(()) => Ok(VerifyReport {
                    valid: true,
                    commits: commit_count,
                    message: None,
                }),
                Err(error) => Ok(VerifyReport {
                    valid: false,
                    commits: commit_count,
                    message: Some(error.to_string()),
                }),
            },
            Err(error) => Ok(VerifyReport {
                valid: false,
                commits: commit_count,
                message: Some(error.to_string()),
            }),
        }
    }

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
    fn snapshot_persistent_root_creates_snapshot_on_disk() {
        let root = temp_root("snapshot_root");

        // Phase 1: open, ingest one signal, drop.
        {
            let (mut hydra, report) =
                HydraRuntime::open_persistent(&root, actor()).unwrap();
            assert_eq!(report.mode, RecoveryMode::Empty);
            hydra.ingest(signal("before")).unwrap();
        }

        // Phase 2: snapshot via the SDK helper.
        let manifest =
            HydraRuntime::snapshot_persistent_root(&root, actor()).unwrap();
        assert_eq!(manifest.sequence, 1);
        assert_eq!(manifest.total_events, 1);
        assert_eq!(manifest.total_commits, 1);

        // Phase 3: inspect — the snapshot must be visible on disk.
        let report = HydraRuntime::inspect_persistent_state(&root).unwrap();
        assert_eq!(report.snapshot_count, 1);
        assert_eq!(report.latest_snapshot_sequence, Some(1));
        assert_eq!(report.recommended_recovery, RecoveryMode::SnapshotAndReplay);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_persistent_root_allows_snapshot_recovery_on_reopen() {
        let root = temp_root("snapshot_reopen");

        // Phase 1: open + ingest.
        {
            let (mut hydra, _) =
                HydraRuntime::open_persistent(&root, actor()).unwrap();
            hydra.ingest(signal("before")).unwrap();
        }

        // Phase 2: snapshot through the helper.
        let manifest =
            HydraRuntime::snapshot_persistent_root(&root, actor()).unwrap();

        // Phase 3: reopen — recovery picks SnapshotAndReplay using the
        // snapshot we just took.
        {
            let (mut hydra, recovery) =
                HydraRuntime::open_persistent(&root, actor()).unwrap();
            assert_eq!(recovery.mode, RecoveryMode::SnapshotAndReplay);
            assert_eq!(recovery.snapshot_id, Some(manifest.id.clone()));
            hydra.ingest(signal("after")).unwrap();
        }

        // Snapshot count stable, commit count grew on reopen + ingest.
        let report = HydraRuntime::inspect_persistent_state(&root).unwrap();
        assert_eq!(report.snapshot_count, 1);
        assert!(report.commit_count >= 3);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_persistent_state_empty_root_is_valid() {
        let root = temp_root("verify_empty");
        let report = HydraRuntime::verify_persistent_state(&root).unwrap();
        assert!(report.valid);
        assert_eq!(report.commits, 0);
        assert_eq!(report.message, None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_persistent_state_reports_valid_chain() {
        let root = temp_root("verify_valid");
        {
            let (mut hydra, _) =
                HydraRuntime::open_persistent(&root, actor()).unwrap();
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let report = HydraRuntime::verify_persistent_state(&root).unwrap();
        assert!(report.valid, "message: {:?}", report.message);
        assert_eq!(report.commits, 2);
        assert_eq!(report.message, None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn inspect_persistent_state_reports_empty_root() {
        let root = temp_root("inspect_empty");
        let report = HydraRuntime::inspect_persistent_state(&root).unwrap();
        assert_eq!(report.commit_count, 0);
        assert_eq!(report.snapshot_count, 0);
        assert_eq!(report.latest_snapshot_sequence, None);
        assert_eq!(report.recommended_recovery, RecoveryMode::Empty);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn inspect_persistent_state_reports_commit_log_recovery() {
        let root = temp_root("inspect_commit_log");
        {
            let (mut hydra, _) =
                HydraRuntime::open_persistent(&root, actor()).unwrap();
            hydra.ingest(signal("one")).unwrap();
            hydra.ingest(signal("two")).unwrap();
        }
        let report = HydraRuntime::inspect_persistent_state(&root).unwrap();
        assert_eq!(report.commit_count, 2);
        assert_eq!(report.snapshot_count, 0);
        assert_eq!(report.latest_snapshot_sequence, None);
        assert_eq!(report.recommended_recovery, RecoveryMode::CommitLog);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn inspect_persistent_state_reports_snapshot_and_replay_recovery() {
        let root = temp_root("inspect_snapshot");
        {
            let (mut hydra, _) =
                HydraRuntime::open_persistent(&root, actor()).unwrap();
            hydra.ingest(signal("before")).unwrap();
            let manifest = hydra.snapshot(actor()).unwrap();
            hydra.ingest(signal("after")).unwrap();
            assert_eq!(manifest.sequence, 1);
        }
        let report = HydraRuntime::inspect_persistent_state(&root).unwrap();
        // 1 "before" + SnapshotTaken + 1 "after" = 3 commits durable on disk.
        assert_eq!(report.commit_count, 3);
        assert_eq!(report.snapshot_count, 1);
        assert_eq!(report.latest_snapshot_sequence, Some(1));
        assert_eq!(
            report.recommended_recovery,
            RecoveryMode::SnapshotAndReplay
        );
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
