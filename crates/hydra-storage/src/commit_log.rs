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
/// Later versions can replace JSONL with a framed binary format, checksummed
/// pages, compression, encryption, or segment files without changing the
/// higher-level database contract.
#[derive(Debug, Clone)]
pub struct CommitLog {
    path: PathBuf,
}

impl CommitLog {
    /// Open or create a commit log at `path`.
    ///
    /// Parent directories are created automatically.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
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
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one committed batch to the log.
    ///
    /// The write is flushed before returning. v0 does not fsync yet; a later
    /// durability patch can add configurable fsync policy.
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
}
