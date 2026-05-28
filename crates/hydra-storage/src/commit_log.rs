use crate::durability::{sync_file, sync_parent_dir, DurabilityPolicy};
use hydra_core::commit::CommitBatch;
use hydra_core::error::{HydraError, Result};
use hydra_engine::commit_ledger::CommitBatchWriter;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Append-only persistent commit log.
///
/// v0 storage format:
/// - one JSON object per line
/// - each line is a serialized CommitBatch
/// - file order is commit order
///
/// This intentionally mirrors a database journal:
///
/// CommitLedger creates an atomic CommitBatch.
/// CommitLog persists that batch durably.
///
/// Durability is governed by [`DurabilityPolicy`]. The default
/// (`DurabilityPolicy::DataOnly`) calls `File::sync_data()` after
/// every append so a committed batch survives a power loss the
/// instant `append()` returns. Tests can opt out via
/// `open_with_policy(path, DurabilityPolicy::None)` for speed.
///
/// Later versions can replace JSONL with a framed binary format, checksummed
/// pages, compression, encryption, or segment files without changing the
/// higher-level database contract.
#[derive(Debug, Clone)]
pub struct CommitLog {
    path: PathBuf,
    policy: DurabilityPolicy,
}

/// Result of `CommitLog::compact_through`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitLogCompactionReport {
    /// All batches with sequence `<= cutoff_sequence` were dropped.
    pub cutoff_sequence: u64,
    pub removed_count: usize,
    pub retained_count: usize,
}

impl CommitLog {
    /// Open or create a commit log at `path` with the production
    /// default durability policy ([`DurabilityPolicy::DataOnly`]).
    ///
    /// Parent directories are created automatically.
    ///
    /// To opt out of fsync (tests, dev), use
    /// [`CommitLog::open_with_policy`] with [`DurabilityPolicy::None`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_policy(path, DurabilityPolicy::default())
    }

    /// Open or create a commit log with an explicit durability policy.
    ///
    /// Production callers should prefer [`CommitLog::open`], which
    /// defaults to `DataOnly`. The escape hatch exists so tests can
    /// configure `None` (no fsync) and operators with niche needs can
    /// pick `Full` (sync_all per write).
    pub fn open_with_policy(
        path: impl AsRef<Path>,
        policy: DurabilityPolicy,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                HydraError::StorageError(format!(
                    "failed to create commit log directory {}: {err}",
                    parent.display()
                ))
            })?;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|err| {
                HydraError::StorageError(format!(
                    "failed to open commit log {}: {err}",
                    path.display()
                ))
            })?;
        Ok(Self { path, policy })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The durability policy configured at construction time.
    pub fn policy(&self) -> DurabilityPolicy {
        self.policy
    }

    /// Append one committed batch to the log.
    ///
    /// On return, the batch is durable to the level configured by the
    /// [`DurabilityPolicy`]:
    ///   - `None`     → only the BufWriter is flushed into the OS
    ///   - `DataOnly` → `File::sync_data()` (fdatasync) called
    ///   - `Full`     → `File::sync_all()` (fsync) called
    ///
    /// `append` does NOT fsync the parent directory because the log
    /// file's directory entry already exists — only renames need
    /// `sync_parent_dir`. See `compact_through` for that path.
    pub fn append(&self, batch: &CommitBatch) -> Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|err| {
                HydraError::StorageError(format!(
                    "failed to open commit log {} for append: {err}",
                    self.path.display()
                ))
            })?;
        let mut writer = BufWriter::new(file);
        let line = serde_json::to_string(batch).map_err(|err| {
            HydraError::SerializationError(format!(
                "failed to serialize CommitBatch for commit log append: {err}"
            ))
        })?;
        writer.write_all(line.as_bytes()).map_err(|err| {
            HydraError::StorageError(format!(
                "failed to write CommitBatch to commit log {}: {err}",
                self.path.display()
            ))
        })?;
        writer.write_all(b"\n").map_err(|err| {
            HydraError::StorageError(format!(
                "failed to write newline to commit log {}: {err}",
                self.path.display()
            ))
        })?;
        writer.flush().map_err(|err| {
            HydraError::StorageError(format!(
                "failed to flush commit log {}: {err}",
                self.path.display()
            ))
        })?;
        let file = writer.into_inner().map_err(|err| {
            HydraError::StorageError(format!(
                "failed to recover commit log file handle {}: {}",
                self.path.display(),
                err.into_error()
            ))
        })?;
        sync_file(&file, self.policy).map_err(|err| {
            HydraError::StorageError(format!(
                "failed to fsync commit log {}: {err}",
                self.path.display()
            ))
        })?;
        Ok(())
    }

    /// Load every CommitBatch from the log in file order.
    pub fn load_all(&self) -> Result<Vec<CommitBatch>> {
        let file = File::open(&self.path).map_err(|err| {
            HydraError::StorageError(format!(
                "failed to open commit log {} for read: {err}",
                self.path.display()
            ))
        })?;
        let reader = BufReader::new(file);
        let mut batches = Vec::new();
        for (index, line) in reader.lines().enumerate() {
            let line_number = index + 1;
            let line = line.map_err(|err| {
                HydraError::StorageError(format!(
                    "failed to read line {line_number} from commit log {}: {err}",
                    self.path.display()
                ))
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let batch: CommitBatch = serde_json::from_str(&line).map_err(|err| {
                HydraError::SerializationError(format!(
                    "failed to parse CommitBatch at commit log {} line {}: {err}",
                    self.path.display(),
                    line_number
                ))
            })?;
            batches.push(batch);
        }
        Ok(batches)
    }

    /// Return true if the commit log contains no committed batches.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.load_all()?.is_empty())
    }

    /// Return the number of committed batches in the log.
    pub fn len(&self) -> Result<usize> {
        Ok(self.load_all()?.len())
    }

    /// Compact the commit log by dropping every batch whose sequence is
    /// `<= cutoff_sequence`. Batches with sequence `> cutoff_sequence` are
    /// retained in their original order.
    ///
    /// Intended use: after taking a snapshot at sequence N, call
    /// `compact_through(N)` to drop pre-snapshot batches — recovery can
    /// reconstruct state from the snapshot body + the retained tail.
    ///
    /// **Do not** call this with a cutoff past your latest snapshot's
    /// sequence; doing so would discard commits that the snapshot does
    /// NOT cover, breaking recovery.
    ///
    /// Atomic write: serializes the retained batches into a sibling
    /// `<path>.tmp` file, then `fs::rename`s it over the canonical path.
    /// On POSIX the rename is atomic, so a crash mid-compaction leaves
    /// either the original log or the fully compacted log — never a
    /// partial file.
    ///
    /// Idempotent: a second call with the same cutoff is a no-op
    /// (`removed_count: 0`) since the matching batches were already
    /// dropped.
    pub fn compact_through(
        &self,
        cutoff_sequence: u64,
    ) -> Result<CommitLogCompactionReport> {
        let batches = self.load_all()?;
        let removed_count = batches
            .iter()
            .filter(|batch| batch.sequence <= cutoff_sequence)
            .count();
        let retained: Vec<CommitBatch> = batches
            .into_iter()
            .filter(|batch| batch.sequence > cutoff_sequence)
            .collect();
        let retained_count = retained.len();

        let temp_path = self.path.with_extension("jsonl.tmp");
        {
            let file = File::create(&temp_path).map_err(|err| {
                HydraError::StorageError(format!(
                    "failed to create compacted commit log {}: {err}",
                    temp_path.display()
                ))
            })?;
            let mut writer = BufWriter::new(file);
            for batch in &retained {
                let line = serde_json::to_string(batch).map_err(|err| {
                    HydraError::SerializationError(format!(
                        "failed to serialize commit batch {} during compaction: {err}",
                        batch.id
                    ))
                })?;
                writer.write_all(line.as_bytes()).map_err(|err| {
                    HydraError::StorageError(format!(
                        "failed to write compacted commit log {}: {err}",
                        temp_path.display()
                    ))
                })?;
                writer.write_all(b"\n").map_err(|err| {
                    HydraError::StorageError(format!(
                        "failed to terminate compacted commit log line {}: {err}",
                        temp_path.display()
                    ))
                })?;
            }
            writer.flush().map_err(|err| {
                HydraError::StorageError(format!(
                    "failed to flush compacted commit log {}: {err}",
                    temp_path.display()
                ))
            })?;
            // Step 1 of the rename trap: fsync the temp file BEFORE
            // the rename so its contents survive a power loss between
            // the rename and the next page-cache flush.
            let file = writer.into_inner().map_err(|err| {
                HydraError::StorageError(format!(
                    "failed to recover compacted commit log file handle {}: {}",
                    temp_path.display(),
                    err.into_error()
                ))
            })?;
            sync_file(&file, self.policy).map_err(|err| {
                HydraError::StorageError(format!(
                    "failed to fsync compacted commit log {}: {err}",
                    temp_path.display()
                ))
            })?;
        }
        // Step 2: rename is atomic on POSIX (for visibility).
        fs::rename(&temp_path, &self.path).map_err(|err| {
            HydraError::StorageError(format!(
                "failed to atomically replace commit log {} with {}: {err}",
                self.path.display(),
                temp_path.display()
            ))
        })?;
        // Step 3: fsync the parent directory so the rename itself —
        // i.e. the directory-entry change — is durable.
        sync_parent_dir(&self.path, self.policy)?;
        Ok(CommitLogCompactionReport {
            cutoff_sequence,
            removed_count,
            retained_count,
        })
    }
}

/// Persist committed batches via the engine's pluggable writer trait.
///
/// This is the seam that lets `Hydra::set_commit_writer(commit_log)` attach a
/// disk-backed journal without hydra-engine depending on hydra-storage.
impl CommitBatchWriter for CommitLog {
    fn append_commit(&self, batch: &CommitBatch) -> Result<()> {
        self.append(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{CommitHash, CommitStatus, Event, EventKind, IdempotencyKey, NodeId};
    use std::collections::HashMap;

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "hydra_commit_log_test_{}_{}_{}.jsonl",
            name,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        path
    }

    fn signal_event(name: &str) -> Event {
        Event::trigger(EventKind::Signal {
            source: NodeId::from_str("test.commit_log"),
            name: name.to_string(),
            payload: HashMap::new(),
        })
    }

    fn commit_batch(name: &str, sequence: u64) -> CommitBatch {
        CommitBatch::new(vec![signal_event(name)])
            .with_sequence(sequence)
            .with_previous_hash(if sequence > 1 {
                Some(CommitHash::new(format!("hash-{}", sequence - 1)))
            } else {
                None
            })
            .with_commit_hash(CommitHash::new(format!("hash-{sequence}")))
            .with_idempotency_key(IdempotencyKey::new(format!("key-{sequence}")))
            .mark_committed(None)
    }

    #[test]
    fn opens_empty_log() {
        let path = temp_path("opens_empty_log");
        let log = CommitLog::open(&path).unwrap();
        assert_eq!(log.path(), path.as_path());
        assert!(path.exists());
        assert!(log.is_empty().unwrap());
        assert_eq!(log.len().unwrap(), 0);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn appends_and_loads_one_batch() {
        let path = temp_path("one_batch");
        let log = CommitLog::open(&path).unwrap();
        let batch = commit_batch("first", 1);
        let batch_id = batch.id.clone();
        log.append(&batch).unwrap();
        let loaded = log.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, batch_id);
        assert_eq!(loaded[0].sequence, 1);
        assert_eq!(loaded[0].status, CommitStatus::Committed);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn appends_and_loads_multiple_batches_in_order() {
        let path = temp_path("multiple_batches");
        let log = CommitLog::open(&path).unwrap();
        let first = commit_batch("first", 1);
        let second = commit_batch("second", 2);
        let third = commit_batch("third", 3);
        let first_id = first.id.clone();
        let second_id = second.id.clone();
        let third_id = third.id.clone();
        log.append(&first).unwrap();
        log.append(&second).unwrap();
        log.append(&third).unwrap();
        let loaded = log.load_all().unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].id, first_id);
        assert_eq!(loaded[1].id, second_id);
        assert_eq!(loaded[2].id, third_id);
        assert_eq!(loaded[0].sequence, 1);
        assert_eq!(loaded[1].sequence, 2);
        assert_eq!(loaded[2].sequence, 3);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn skips_blank_lines() {
        let path = temp_path("blank_lines");
        fs::write(&path, "\n\n").unwrap();
        let log = CommitLog::open(&path).unwrap();
        assert!(log.load_all().unwrap().is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_malformed_line() {
        let path = temp_path("malformed");
        fs::write(&path, "{not valid json}\n").unwrap();
        let log = CommitLog::open(&path).unwrap();
        let result = log.load_all();
        assert!(result.is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn commit_log_implements_commit_batch_writer() {
        use hydra_engine::commit_ledger::CommitBatchWriter;
        let path = temp_path("writer_trait");
        let log = CommitLog::open(&path).unwrap();
        let batch = commit_batch("first", 1);
        let batch_id = batch.id.clone();
        log.append_commit(&batch).unwrap();
        let loaded = log.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, batch_id);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn commit_log_batches_can_recover_hydra_state() {
        use hydra_core::{EventKind, NodeId};
        use hydra_engine::hydra::Hydra;
        use std::collections::HashMap;

        let path = temp_path("recover_hydra");
        let log = CommitLog::open(&path).unwrap();
        let mut hydra = Hydra::new();
        hydra.set_commit_writer(log.clone());

        hydra
            .ingest(EventKind::Signal {
                source: NodeId::from_str("test"),
                name: "persisted".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();

        let batches = log.load_all().unwrap();
        let mut recovered = Hydra::new();
        recovered.recover_from_commits(batches).unwrap();
        assert_eq!(recovered.commit_count(), 1);
        recovered.verify_commit_chain().unwrap();

        let _ = fs::remove_file(path);
    }

    #[test]
    fn commit_log_persists_only_one_commit_for_duplicate_idempotency_key() {
        use hydra_core::{EventKind, IdempotencyKey, NodeId};
        use hydra_engine::hydra::Hydra;
        use std::collections::HashMap;

        let path = temp_path("idempotency_one_commit");
        let log = CommitLog::open(&path).unwrap();
        let mut hydra = Hydra::new();
        hydra.set_commit_writer(log.clone());

        let key = IdempotencyKey::new("external-request-1");
        hydra
            .ingest_with_idempotency_key(
                EventKind::Signal {
                    source: NodeId::from_str("test"),
                    name: "first".to_string(),
                    payload: HashMap::new(),
                },
                key.clone(),
            )
            .unwrap();
        hydra
            .ingest_with_idempotency_key(
                EventKind::Signal {
                    source: NodeId::from_str("test"),
                    name: "duplicate".to_string(),
                    payload: HashMap::new(),
                },
                key,
            )
            .unwrap();

        let batches = log.load_all().unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].sequence, 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn commit_log_persists_sensor_observation_helper_commits() {
        use hydra_core::{EventKind, NodeId, SensorId, SourceCursor};
        use hydra_engine::hydra::Hydra;
        use std::collections::HashMap;

        let path = temp_path("sensor_observation_helper");
        let log = CommitLog::open(&path).unwrap();
        let mut hydra = Hydra::new();
        hydra.set_commit_writer(log.clone());

        let checkpoint = hydra
            .record_sensor_observation(
                SensorId::from_str("sensor_commit_log"),
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

        let batches = log.load_all().unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].id, checkpoint.commit_id);
        assert_eq!(batches[1].events.len(), 1);

        let mut recovered = Hydra::new();
        recovered.recover_from_commits(batches).unwrap();
        assert_eq!(
            recovered
                .checkpoint_for_idempotency_key(&checkpoint.idempotency_key)
                .unwrap()
                .id,
            checkpoint.id
        );
        recovered.verify_commit_chain().unwrap();

        let _ = fs::remove_file(path);
    }

    #[test]
    fn open_creates_parent_directory() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "hydra_commit_log_dir_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        path.push("nested");
        path.push("commit-log.jsonl");
        let log = CommitLog::open(&path).unwrap();
        assert!(log.path().exists());
        let root = path
            .parent()
            .and_then(|parent| parent.parent())
            .map(Path::to_path_buf)
            .unwrap();
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn commit_log_compact_through_removes_older_batches() {
        let path = temp_path("compact_through_removes_older");
        let log = CommitLog::open(&path).unwrap();
        log.append(&commit_batch("a", 1)).unwrap();
        log.append(&commit_batch("b", 2)).unwrap();
        log.append(&commit_batch("c", 3)).unwrap();

        let report = log.compact_through(2).unwrap();
        assert_eq!(report.cutoff_sequence, 2);
        assert_eq!(report.removed_count, 2);
        assert_eq!(report.retained_count, 1);

        let loaded = log.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].sequence, 3);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn commit_log_compact_through_is_idempotent() {
        let path = temp_path("compact_through_idempotent");
        let log = CommitLog::open(&path).unwrap();
        log.append(&commit_batch("a", 1)).unwrap();
        log.append(&commit_batch("b", 2)).unwrap();

        let first = log.compact_through(1).unwrap();
        let second = log.compact_through(1).unwrap();

        assert_eq!(first.removed_count, 1);
        assert_eq!(first.retained_count, 1);
        // Second call sees a log that already lacks sequence 1.
        assert_eq!(second.removed_count, 0);
        assert_eq!(second.retained_count, 1);

        let loaded = log.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].sequence, 2);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn commit_log_compact_through_zero_is_no_op() {
        let path = temp_path("compact_through_zero");
        let log = CommitLog::open(&path).unwrap();
        log.append(&commit_batch("a", 1)).unwrap();
        log.append(&commit_batch("b", 2)).unwrap();

        // Sequence 0 doesn't exist — all batches survive.
        let report = log.compact_through(0).unwrap();
        assert_eq!(report.removed_count, 0);
        assert_eq!(report.retained_count, 2);

        let loaded = log.load_all().unwrap();
        assert_eq!(loaded.len(), 2);

        let _ = fs::remove_file(&path);
    }

    // === Durability policy ===
    //
    // These tests pin behavior, not crash-safety. Proving crash-safety
    // under power loss requires fault injection (kill -9 between
    // syscalls); see the durability module docs and the operator
    // runbook for the manual procedure.

    #[test]
    fn commit_log_open_defaults_to_dataonly() {
        let path = temp_path("open_default_is_dataonly");
        let log = CommitLog::open(&path).unwrap();
        // Production default: writes are durable on return.
        assert_eq!(log.policy(), DurabilityPolicy::DataOnly);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn commit_log_open_with_policy_none_round_trips() {
        // `None` policy skips fsync but must still produce a usable
        // commit log — same write/read contract, just less durability.
        let path = temp_path("policy_none_round_trips");
        let log = CommitLog::open_with_policy(&path, DurabilityPolicy::None).unwrap();
        assert_eq!(log.policy(), DurabilityPolicy::None);
        log.append(&commit_batch("a", 1)).unwrap();
        log.append(&commit_batch("b", 2)).unwrap();
        let loaded = log.load_all().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].sequence, 1);
        assert_eq!(loaded[1].sequence, 2);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn commit_log_open_with_policy_dataonly_round_trips() {
        // `DataOnly` fsyncs every append. The append/load contract is
        // unchanged; this test is the existence proof that fsync
        // doesn't break the read path.
        let path = temp_path("policy_dataonly_round_trips");
        let log = CommitLog::open_with_policy(&path, DurabilityPolicy::DataOnly).unwrap();
        assert_eq!(log.policy(), DurabilityPolicy::DataOnly);
        log.append(&commit_batch("a", 1)).unwrap();
        log.append(&commit_batch("b", 2)).unwrap();
        log.append(&commit_batch("c", 3)).unwrap();
        let loaded = log.load_all().unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[2].sequence, 3);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn commit_log_compact_round_trips_under_dataonly() {
        // Compaction goes through the rename trap (temp file fsync,
        // rename, parent-dir fsync). Verify it still produces the
        // expected retained set when the policy is `DataOnly`.
        let path = temp_path("compact_under_dataonly");
        let log = CommitLog::open_with_policy(&path, DurabilityPolicy::DataOnly).unwrap();
        log.append(&commit_batch("a", 1)).unwrap();
        log.append(&commit_batch("b", 2)).unwrap();
        log.append(&commit_batch("c", 3)).unwrap();
        let report = log.compact_through(2).unwrap();
        assert_eq!(report.removed_count, 2);
        assert_eq!(report.retained_count, 1);
        let loaded = log.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].sequence, 3);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn durability_policy_none_and_dataonly_bytes_match() {
        // The fsync policy must NOT change the on-disk byte stream.
        // It only changes whether those bytes are durably flushed to
        // physical media. A drift here would mean the policies write
        // different content, which would break read-back compatibility.
        let path_none = temp_path("bytes_match_none");
        let path_data = temp_path("bytes_match_dataonly");
        let batches = vec![
            commit_batch("a", 1),
            commit_batch("b", 2),
            commit_batch("c", 3),
        ];

        let log_none =
            CommitLog::open_with_policy(&path_none, DurabilityPolicy::None).unwrap();
        let log_data =
            CommitLog::open_with_policy(&path_data, DurabilityPolicy::DataOnly).unwrap();
        for batch in &batches {
            log_none.append(batch).unwrap();
            log_data.append(batch).unwrap();
        }

        let bytes_none = fs::read(&path_none).unwrap();
        let bytes_data = fs::read(&path_data).unwrap();
        assert_eq!(
            bytes_none, bytes_data,
            "DurabilityPolicy must not change on-disk bytes"
        );

        // And compaction should also produce identical bytes.
        log_none.compact_through(1).unwrap();
        log_data.compact_through(1).unwrap();
        let after_none = fs::read(&path_none).unwrap();
        let after_data = fs::read(&path_data).unwrap();
        assert_eq!(
            after_none, after_data,
            "compaction must also be byte-identical across policies"
        );

        let _ = fs::remove_file(path_none);
        let _ = fs::remove_file(path_data);
    }
}
