use crate::durability::{sync_file, sync_parent_dir, DurabilityPolicy};
use hydra_core::error::{HydraError, Result};
use hydra_core::{SnapshotBody, SnapshotId, SnapshotManifest};
use hydra_engine::snapshot_store::SnapshotBackend;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

/// File-backed snapshot store.
///
/// Layout:
/// ```text
/// <root>/snapshots/
///     <snapshot_id>.json     full SnapshotBody, one file per snapshot
///     index.jsonl            append-only JSONL of SnapshotManifest records
/// ```
///
/// Snapshot bodies are written via `tempfile + rename` so a crash mid-write
/// never leaves a partially-serialized snapshot at the canonical path.
/// The manifest index is append-only on writes and atomically rewritten on
/// deletes.
///
/// Durability is governed by [`DurabilityPolicy`]. The default
/// (`DurabilityPolicy::DataOnly`) fsyncs every body before its rename,
/// the parent directory after the rename, and every manifest-index
/// append. See `crate::durability` for the rename-trap rationale.
///
/// Concurrent multi-writer safety (file locking) is intentionally deferred
/// to a hardening patch — this version assumes a single writer.
#[derive(Debug, Clone)]
pub struct FileSnapshotStore {
    root: PathBuf,
    policy: DurabilityPolicy,
}

impl FileSnapshotStore {
    /// Open or create a `FileSnapshotStore` rooted at `root` with the
    /// production default durability policy
    /// ([`DurabilityPolicy::DataOnly`]).
    ///
    /// Creates the `snapshots/` directory and `index.jsonl` if they
    /// don't exist.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_policy(root, DurabilityPolicy::default())
    }

    /// Open or create a `FileSnapshotStore` with an explicit
    /// durability policy. Production callers should prefer
    /// [`FileSnapshotStore::open`].
    pub fn open_with_policy(
        root: impl AsRef<Path>,
        policy: DurabilityPolicy,
    ) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let snapshots_dir = root.join("snapshots");
        fs::create_dir_all(&snapshots_dir).map_err(|error| {
            HydraError::StorageError(format!(
                "failed to create snapshot directory {}: {error}",
                snapshots_dir.display()
            ))
        })?;
        let index = snapshots_dir.join("index.jsonl");
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&index)
            .map_err(|error| {
                HydraError::StorageError(format!(
                    "failed to open snapshot index {}: {error}",
                    index.display()
                ))
            })?;
        Ok(Self { root, policy })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The durability policy configured at construction time.
    pub fn policy(&self) -> DurabilityPolicy {
        self.policy
    }

    fn snapshots_dir(&self) -> PathBuf {
        self.root.join("snapshots")
    }

    fn index_path(&self) -> PathBuf {
        self.snapshots_dir().join("index.jsonl")
    }

    fn snapshot_path(&self, id: &SnapshotId) -> PathBuf {
        self.snapshots_dir().join(format!("{id}.json"))
    }

    fn temp_snapshot_path(&self, id: &SnapshotId) -> PathBuf {
        self.snapshots_dir().join(format!("{id}.json.tmp"))
    }

    fn append_manifest(&self, manifest: &SnapshotManifest) -> Result<()> {
        let index_path = self.index_path();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&index_path)
            .map_err(|error| {
                HydraError::StorageError(format!(
                    "failed to open snapshot index {}: {error}",
                    index_path.display()
                ))
            })?;
        let mut writer = BufWriter::new(file);
        let json = serde_json::to_string(manifest).map_err(|error| {
            HydraError::SerializationError(format!(
                "failed to serialize snapshot manifest {}: {error}",
                manifest.id
            ))
        })?;
        writer.write_all(json.as_bytes()).map_err(|error| {
            HydraError::StorageError(format!(
                "failed to write snapshot manifest {}: {error}",
                manifest.id
            ))
        })?;
        writer.write_all(b"\n").map_err(|error| {
            HydraError::StorageError(format!(
                "failed to terminate snapshot manifest {}: {error}",
                manifest.id
            ))
        })?;
        writer.flush().map_err(|error| {
            HydraError::StorageError(format!(
                "failed to flush snapshot index {}: {error}",
                index_path.display()
            ))
        })?;
        // Index is append-only on this path (no rename), so we only
        // need to fsync the file itself. The directory entry already
        // exists from `open()`.
        let file = writer.into_inner().map_err(|error| {
            HydraError::StorageError(format!(
                "failed to recover snapshot index file handle {}: {}",
                index_path.display(),
                error.into_error()
            ))
        })?;
        sync_file(&file, self.policy).map_err(|error| {
            HydraError::StorageError(format!(
                "failed to fsync snapshot index {}: {error}",
                index_path.display()
            ))
        })?;
        Ok(())
    }

    fn rewrite_index_without(&self, id: &SnapshotId) -> Result<()> {
        let manifests = self
            .list_snapshot_manifests()?
            .into_iter()
            .filter(|manifest| &manifest.id != id)
            .collect::<Vec<_>>();
        let index_path = self.index_path();
        let temp_path = self.snapshots_dir().join("index.jsonl.tmp");
        {
            let file = File::create(&temp_path).map_err(|error| {
                HydraError::StorageError(format!(
                    "failed to create temp snapshot index {}: {error}",
                    temp_path.display()
                ))
            })?;
            let mut writer = BufWriter::new(file);
            for manifest in manifests {
                let json = serde_json::to_string(&manifest).map_err(|error| {
                    HydraError::SerializationError(format!(
                        "failed to serialize snapshot manifest {}: {error}",
                        manifest.id
                    ))
                })?;
                writer.write_all(json.as_bytes()).map_err(|error| {
                    HydraError::StorageError(format!(
                        "failed to write temp snapshot index {}: {error}",
                        temp_path.display()
                    ))
                })?;
                writer.write_all(b"\n").map_err(|error| {
                    HydraError::StorageError(format!(
                        "failed to terminate temp snapshot index line {}: {error}",
                        temp_path.display()
                    ))
                })?;
            }
            writer.flush().map_err(|error| {
                HydraError::StorageError(format!(
                    "failed to flush temp snapshot index {}: {error}",
                    temp_path.display()
                ))
            })?;
            // Step 1: fsync the temp file BEFORE the rename.
            let file = writer.into_inner().map_err(|error| {
                HydraError::StorageError(format!(
                    "failed to recover temp snapshot index file handle {}: {}",
                    temp_path.display(),
                    error.into_error()
                ))
            })?;
            sync_file(&file, self.policy).map_err(|error| {
                HydraError::StorageError(format!(
                    "failed to fsync temp snapshot index {}: {error}",
                    temp_path.display()
                ))
            })?;
        }
        // Step 2: atomic rename.
        fs::rename(&temp_path, &index_path).map_err(|error| {
            HydraError::StorageError(format!(
                "failed to replace snapshot index {} with {}: {error}",
                index_path.display(),
                temp_path.display()
            ))
        })?;
        // Step 3: fsync the parent directory so the rename itself is
        // durable. Without this, a power loss can leave the canonical
        // name pointing at the old inode after recovery.
        sync_parent_dir(&index_path, self.policy)?;
        Ok(())
    }
}

impl SnapshotBackend for FileSnapshotStore {
    fn write_snapshot(&self, body: &SnapshotBody) -> Result<()> {
        let final_path = self.snapshot_path(&body.manifest.id);
        let temp_path = self.temp_snapshot_path(&body.manifest.id);
        {
            let file = File::create(&temp_path).map_err(|error| {
                HydraError::StorageError(format!(
                    "failed to create temp snapshot {}: {error}",
                    temp_path.display()
                ))
            })?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer(&mut writer, body).map_err(|error| {
                HydraError::SerializationError(format!(
                    "failed to serialize snapshot body {}: {error}",
                    body.manifest.id
                ))
            })?;
            writer.flush().map_err(|error| {
                HydraError::StorageError(format!(
                    "failed to flush temp snapshot {}: {error}",
                    temp_path.display()
                ))
            })?;
            // Step 1: fsync the temp body BEFORE the rename.
            let file = writer.into_inner().map_err(|error| {
                HydraError::StorageError(format!(
                    "failed to recover temp snapshot file handle {}: {}",
                    temp_path.display(),
                    error.into_error()
                ))
            })?;
            sync_file(&file, self.policy).map_err(|error| {
                HydraError::StorageError(format!(
                    "failed to fsync temp snapshot {}: {error}",
                    temp_path.display()
                ))
            })?;
        }
        // Step 2: atomic rename.
        fs::rename(&temp_path, &final_path).map_err(|error| {
            HydraError::StorageError(format!(
                "failed to atomically move snapshot {} to {}: {error}",
                temp_path.display(),
                final_path.display()
            ))
        })?;
        // Step 3: fsync the parent directory so the rename itself is
        // durable. Without this, a recovery scan might not see the
        // body file even though `write_snapshot` returned Ok.
        sync_parent_dir(&final_path, self.policy)?;
        // Manifest append handles its own fsync inside append_manifest.
        self.append_manifest(&body.manifest)?;
        Ok(())
    }

    fn read_snapshot(&self, id: &SnapshotId) -> Result<SnapshotBody> {
        let path = self.snapshot_path(id);
        let file = File::open(&path).map_err(|error| {
            HydraError::StorageError(format!(
                "failed to open snapshot {}: {error}",
                path.display()
            ))
        })?;
        serde_json::from_reader(file).map_err(|error| {
            HydraError::SerializationError(format!(
                "failed to deserialize snapshot {}: {error}",
                path.display()
            ))
        })
    }

    fn list_snapshot_manifests(&self) -> Result<Vec<SnapshotManifest>> {
        let index_path = self.index_path();
        let file = File::open(&index_path).map_err(|error| {
            HydraError::StorageError(format!(
                "failed to open snapshot index {}: {error}",
                index_path.display()
            ))
        })?;
        let reader = BufReader::new(file);
        let mut manifests = Vec::new();
        for (line_index, line) in reader.lines().enumerate() {
            let line = line.map_err(|error| {
                HydraError::StorageError(format!(
                    "failed to read snapshot index {} line {}: {error}",
                    index_path.display(),
                    line_index + 1
                ))
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let manifest = serde_json::from_str::<SnapshotManifest>(&line).map_err(|error| {
                HydraError::SerializationError(format!(
                    "failed to parse snapshot index {} line {}: {error}",
                    index_path.display(),
                    line_index + 1
                ))
            })?;
            manifests.push(manifest);
        }
        manifests.sort_by_key(|manifest| manifest.sequence);
        Ok(manifests)
    }

    fn delete_snapshot(&self, id: &SnapshotId) -> Result<()> {
        let path = self.snapshot_path(id);
        if path.exists() {
            fs::remove_file(&path).map_err(|error| {
                HydraError::StorageError(format!(
                    "failed to delete snapshot {}: {error}",
                    path.display()
                ))
            })?;
        }
        self.rewrite_index_without(id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{ActorId, CommitHash, CommitId, SnapshotBody, SnapshotId, SnapshotManifest};
    use std::collections::HashMap;

    fn temp_root(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "hydra_file_snapshot_store_test_{}_{}_{}",
            name,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        path
    }

    fn actor() -> ActorId {
        ActorId::from_str("actor_file_snapshot_store")
    }

    fn body(sequence: u64) -> SnapshotBody {
        let manifest = SnapshotManifest::committed(
            SnapshotId::new(),
            None,
            sequence,
            Some(CommitId::from_str(&format!("commit_{sequence}"))),
            Some(CommitHash(format!("engine-v0:{sequence}"))),
            actor(),
            chrono::Utc::now(),
            0, sequence as usize, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        );
        SnapshotBody {
            manifest,
            nodes: vec![],
            edges: vec![],
            events: vec![],
            commit_records: vec![],
            claims: vec![],
            evidence: vec![],
            actions: vec![],
            outcomes: vec![],
            policies: vec![],
            policy_decisions: vec![],
            approval_requests: vec![],
            sensor_runs: vec![],
            sensor_checkpoints: vec![],
            schemas: vec![],
            replication_peers: vec![],
            replication_runs: vec![],
            micro_models: vec![],
            micro_model_predictions: vec![],
            micro_model_observations: vec![],
            causal_cells: vec![],
            identity_entities: vec![],
            identity_links: vec![],
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn file_snapshot_store_writes_lists_and_reads_snapshot() {
        let root = temp_root("write_list_read");
        let store = FileSnapshotStore::open(&root).unwrap();
        let body = body(1);
        let id = body.manifest.id.clone();
        store.write_snapshot(&body).unwrap();

        let manifests = store.list_snapshot_manifests().unwrap();
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].id, id);

        let restored = store.read_snapshot(&id).unwrap();
        assert_eq!(restored, body);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn file_snapshot_store_lists_manifests_in_sequence_order() {
        let root = temp_root("sequence_order");
        let store = FileSnapshotStore::open(&root).unwrap();
        store.write_snapshot(&body(3)).unwrap();
        store.write_snapshot(&body(1)).unwrap();
        store.write_snapshot(&body(2)).unwrap();

        let sequences = store
            .list_snapshot_manifests()
            .unwrap()
            .into_iter()
            .map(|manifest| manifest.sequence)
            .collect::<Vec<_>>();
        assert_eq!(sequences, vec![1, 2, 3]);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn file_snapshot_store_delete_removes_body_and_manifest() {
        let root = temp_root("delete");
        let store = FileSnapshotStore::open(&root).unwrap();
        let body = body(1);
        let id = body.manifest.id.clone();
        store.write_snapshot(&body).unwrap();

        store.delete_snapshot(&id).unwrap();

        assert!(store.read_snapshot(&id).is_err());
        assert!(store.list_snapshot_manifests().unwrap().is_empty());

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn file_snapshot_store_reopens_existing_directory() {
        let root = temp_root("reopen");
        {
            let store = FileSnapshotStore::open(&root).unwrap();
            store.write_snapshot(&body(1)).unwrap();
            store.write_snapshot(&body(2)).unwrap();
        }

        // Reopen the same directory; manifests should survive.
        let store = FileSnapshotStore::open(&root).unwrap();
        let manifests = store.list_snapshot_manifests().unwrap();
        assert_eq!(manifests.len(), 2);

        fs::remove_dir_all(&root).ok();
    }

    // === Durability policy ===

    #[test]
    fn snapshot_store_open_defaults_to_dataonly() {
        let root = temp_root("snapshot_default_dataonly");
        let store = FileSnapshotStore::open(&root).unwrap();
        assert_eq!(store.policy(), DurabilityPolicy::DataOnly);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn snapshot_store_write_read_under_dataonly() {
        // Write goes through the rename trap (sync body, rename, sync
        // parent dir, then sync the manifest index). Verify the
        // round-trip is unchanged under DataOnly.
        let root = temp_root("snapshot_write_read_dataonly");
        let store =
            FileSnapshotStore::open_with_policy(&root, DurabilityPolicy::DataOnly).unwrap();
        assert_eq!(store.policy(), DurabilityPolicy::DataOnly);

        let body = body(1);
        let id = body.manifest.id.clone();
        store.write_snapshot(&body).unwrap();

        let manifests = store.list_snapshot_manifests().unwrap();
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].id, id);

        let restored = store.read_snapshot(&id).unwrap();
        assert_eq!(restored, body);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn snapshot_store_delete_rewrites_index_under_dataonly() {
        // Delete exercises `rewrite_index_without`, which uses the
        // full rename-trap dance for the index file. Verify the index
        // is correctly rewritten and the deleted body is unreadable.
        let root = temp_root("snapshot_delete_dataonly");
        let store =
            FileSnapshotStore::open_with_policy(&root, DurabilityPolicy::DataOnly).unwrap();

        let first = body(1);
        let second = body(2);
        let first_id = first.manifest.id.clone();
        let second_id = second.manifest.id.clone();
        store.write_snapshot(&first).unwrap();
        store.write_snapshot(&second).unwrap();

        store.delete_snapshot(&first_id).unwrap();

        // First is gone — body unreadable, manifest absent.
        assert!(store.read_snapshot(&first_id).is_err());
        let manifests = store.list_snapshot_manifests().unwrap();
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].id, second_id);

        // Second still resolves.
        let restored = store.read_snapshot(&second_id).unwrap();
        assert_eq!(restored, second);

        fs::remove_dir_all(&root).ok();
    }
}
