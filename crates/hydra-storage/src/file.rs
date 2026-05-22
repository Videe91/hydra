use crate::backend::{Snapshot, StorageBackend};
use hydra_core::event::Event;
use hydra_core::id::{CascadeId, EventId, TenantId};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// File-based storage backend using NDJSON (newline-delimited JSON).
///
/// Directory layout:
/// ```text
/// base_dir/
///   {tenant_id}/
///     events.ndjson      — one JSON event per line
///     snapshot.json      — latest snapshot
/// ```
///
/// NDJSON is human-inspectable, grep-friendly, and append-only.
/// Not suitable for production at scale — use for dev, testing, single-node.
pub struct FileBackend {
    base_dir: PathBuf,
}

impl FileBackend {
    pub fn new(base_dir: impl AsRef<Path>) -> hydra_core::error::Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir).map_err(|e| {
            hydra_core::error::HydraError::StorageError(format!(
                "failed to create base dir {}: {}",
                base_dir.display(),
                e
            ))
        })?;
        Ok(Self { base_dir })
    }

    fn tenant_dir(&self, tenant_id: &TenantId) -> PathBuf {
        self.base_dir.join(Self::sanitize_tenant_id(tenant_id))
    }

    /// Sanitize tenant ID for use as a directory name.
    /// Rejects path separators, dot sequences, and non-alphanumeric chars
    /// (except underscore and hyphen) to prevent path traversal.
    fn sanitize_tenant_id(tenant_id: &TenantId) -> String {
        let raw = tenant_id.as_str();
        // Only allow alphanumeric, underscore, hyphen
        let sanitized: String = raw
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
            .collect();
        // Reject empty or dot-only results
        if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
            return format!("_invalid_{}", sanitized.len());
        }
        sanitized
    }

    fn events_path(&self, tenant_id: &TenantId) -> PathBuf {
        self.tenant_dir(tenant_id).join("events.ndjson")
    }

    fn snapshot_path(&self, tenant_id: &TenantId) -> PathBuf {
        self.tenant_dir(tenant_id).join("snapshot.json")
    }

    fn ensure_tenant_dir(&self, tenant_id: &TenantId) -> hydra_core::error::Result<()> {
        let dir = self.tenant_dir(tenant_id);
        fs::create_dir_all(&dir).map_err(|e| {
            hydra_core::error::HydraError::StorageError(format!(
                "failed to create tenant dir {}: {}",
                dir.display(),
                e
            ))
        })
    }

    fn storage_err(msg: impl Into<String>) -> hydra_core::error::HydraError {
        hydra_core::error::HydraError::StorageError(msg.into())
    }

    /// Acquire an exclusive (write) lock on the events file for a tenant.
    /// Returns the locked File handle. Lock is released when the File is dropped.
    #[cfg(unix)]
    fn lock_exclusive(
        &self,
        tenant_id: &TenantId,
    ) -> hydra_core::error::Result<fs::File> {
        self.ensure_tenant_dir(tenant_id)?;
        let lock_path = self.tenant_dir(tenant_id).join("events.lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| Self::storage_err(format!("open lock {}: {}", lock_path.display(), e)))?;

        use std::os::unix::io::AsRawFd;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(Self::storage_err(format!(
                "flock exclusive on {}: errno {}",
                lock_path.display(),
                std::io::Error::last_os_error()
            )));
        }
        Ok(file)
    }

    /// Acquire a shared (read) lock on the events file for a tenant.
    #[cfg(unix)]
    fn lock_shared(
        &self,
        tenant_id: &TenantId,
    ) -> hydra_core::error::Result<Option<fs::File>> {
        let lock_path = self.tenant_dir(tenant_id).join("events.lock");
        if !lock_path.exists() {
            return Ok(None); // No lock file yet — no data to read
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .open(&lock_path)
            .map_err(|e| Self::storage_err(format!("open lock {}: {}", lock_path.display(), e)))?;

        use std::os::unix::io::AsRawFd;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) };
        if rc != 0 {
            return Err(Self::storage_err(format!(
                "flock shared on {}: errno {}",
                lock_path.display(),
                std::io::Error::last_os_error()
            )));
        }
        Ok(Some(file))
    }

    /// No-op lock for non-Unix platforms
    #[cfg(not(unix))]
    fn lock_exclusive(&self, tenant_id: &TenantId) -> hydra_core::error::Result<()> {
        self.ensure_tenant_dir(tenant_id)?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn lock_shared(&self, _tenant_id: &TenantId) -> hydra_core::error::Result<Option<()>> {
        Ok(None)
    }
}

impl StorageBackend for FileBackend {
    fn append_events(
        &mut self,
        tenant_id: &TenantId,
        events: &[Event],
    ) -> hydra_core::error::Result<()> {
        // Acquire exclusive lock — prevents concurrent writes from corrupting the file.
        // Lock is held for the duration of this method (dropped at end of scope).
        let _lock = self.lock_exclusive(tenant_id)?;

        let path = self.events_path(tenant_id);

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| Self::storage_err(format!("open {}: {}", path.display(), e)))?;

        for event in events {
            let json = serde_json::to_string(event).map_err(|e| {
                hydra_core::error::HydraError::SerializationError(format!(
                    "serialize event {}: {}",
                    event.id, e
                ))
            })?;
            writeln!(file, "{}", json)
                .map_err(|e| Self::storage_err(format!("write {}: {}", path.display(), e)))?;
        }

        file.flush()
            .map_err(|e| Self::storage_err(format!("flush {}: {}", path.display(), e)))?;

        Ok(())
    }

    fn read_events(
        &self,
        tenant_id: &TenantId,
    ) -> hydra_core::error::Result<Vec<Event>> {
        let path = self.events_path(tenant_id);
        if !path.exists() {
            return Ok(Vec::new());
        }

        // Acquire shared lock — allows concurrent reads, blocks during writes.
        let _lock = self.lock_shared(tenant_id)?;

        let file = fs::File::open(&path)
            .map_err(|e| Self::storage_err(format!("open {}: {}", path.display(), e)))?;
        let reader = BufReader::new(file);

        let mut events = Vec::new();
        for (line_num, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| {
                Self::storage_err(format!("read {}:{}: {}", path.display(), line_num + 1, e))
            })?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event: Event = serde_json::from_str(trimmed).map_err(|e| {
                hydra_core::error::HydraError::SerializationError(format!(
                    "deserialize {}:{}: {}",
                    path.display(),
                    line_num + 1,
                    e
                ))
            })?;
            events.push(event);
        }

        Ok(events)
    }

    fn read_events_after(
        &self,
        tenant_id: &TenantId,
        after: &EventId,
    ) -> hydra_core::error::Result<Vec<Event>> {
        let all = self.read_events(tenant_id)?;
        let pos = all.iter().position(|e| &e.id == after);
        match pos {
            Some(idx) => Ok(all[idx + 1..].to_vec()),
            None => Ok(all),
        }
    }

    fn read_cascade_events(
        &self,
        tenant_id: &TenantId,
        cascade_id: &CascadeId,
    ) -> hydra_core::error::Result<Vec<Event>> {
        let all = self.read_events(tenant_id)?;
        Ok(all
            .into_iter()
            .filter(|e| &e.cascade_id == cascade_id)
            .collect())
    }

    fn save_snapshot(
        &mut self,
        snapshot: Snapshot,
    ) -> hydra_core::error::Result<()> {
        let _lock = self.lock_exclusive(&snapshot.tenant_id)?;
        let path = self.snapshot_path(&snapshot.tenant_id);

        let json = serde_json::to_string_pretty(&snapshot).map_err(|e| {
            hydra_core::error::HydraError::SerializationError(format!(
                "serialize snapshot: {}",
                e
            ))
        })?;

        fs::write(&path, json)
            .map_err(|e| Self::storage_err(format!("write {}: {}", path.display(), e)))?;

        Ok(())
    }

    fn load_latest_snapshot(
        &self,
        tenant_id: &TenantId,
    ) -> hydra_core::error::Result<Option<Snapshot>> {
        let path = self.snapshot_path(tenant_id);
        if !path.exists() {
            return Ok(None);
        }

        let _lock = self.lock_shared(tenant_id)?;

        let data = fs::read_to_string(&path)
            .map_err(|e| Self::storage_err(format!("read {}: {}", path.display(), e)))?;

        let snapshot: Snapshot = serde_json::from_str(&data).map_err(|e| {
            hydra_core::error::HydraError::SerializationError(format!(
                "deserialize snapshot {}: {}",
                path.display(),
                e
            ))
        })?;

        Ok(Some(snapshot))
    }

    fn event_count(&self, tenant_id: &TenantId) -> hydra_core::error::Result<u64> {
        let path = self.events_path(tenant_id);
        if !path.exists() {
            return Ok(0);
        }

        let file = fs::File::open(&path)
            .map_err(|e| Self::storage_err(format!("open {}: {}", path.display(), e)))?;
        let reader = BufReader::new(file);

        let count = reader
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.trim().is_empty())
            .count();

        Ok(count as u64)
    }

    fn list_tenants(&self) -> hydra_core::error::Result<Vec<TenantId>> {
        if !self.base_dir.exists() {
            return Ok(Vec::new());
        }

        let mut tenants = Vec::new();
        let entries = fs::read_dir(&self.base_dir)
            .map_err(|e| Self::storage_err(format!("read dir {}: {}", self.base_dir.display(), e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| Self::storage_err(format!("read entry: {}", e)))?;
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    tenants.push(TenantId::from_str(name));
                }
            }
        }

        Ok(tenants)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::{Event, EventKind};
    use hydra_core::id::{NodeId, SnapshotId, TenantId};
    use std::collections::HashMap;

    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "hydra_test_{}_{}", std::process::id(), n
        ));
        // Clean up from previous runs
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn tenant() -> TenantId {
        TenantId::from_str("ten_FILE_TEST")
    }

    fn make_event(type_id: &str) -> Event {
        Event::trigger(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: type_id.to_string(),
            properties: HashMap::new(),
        })
    }

    #[test]
    fn file_append_and_read() {
        let dir = temp_dir();
        let mut backend = FileBackend::new(&dir).unwrap();
        let t = tenant();

        let e1 = make_event("ec2");
        let e2 = make_event("rds");
        let e1_id = e1.id.clone();
        let e2_id = e2.id.clone();

        backend.append_events(&t, &[e1, e2]).unwrap();

        let events = backend.read_events(&t).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, e1_id);
        assert_eq!(events[1].id, e2_id);

        // Verify NDJSON file exists
        let path = backend.events_path(&t);
        assert!(path.exists());
        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_append_is_incremental() {
        let dir = temp_dir();
        let mut backend = FileBackend::new(&dir).unwrap();
        let t = tenant();

        backend.append_events(&t, &[make_event("ec2")]).unwrap();
        backend.append_events(&t, &[make_event("rds")]).unwrap();

        let events = backend.read_events(&t).unwrap();
        assert_eq!(events.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_read_events_after() {
        let dir = temp_dir();
        let mut backend = FileBackend::new(&dir).unwrap();
        let t = tenant();

        let e1 = make_event("ec2");
        let e1_id = e1.id.clone();
        backend
            .append_events(&t, &[e1, make_event("rds"), make_event("s3")])
            .unwrap();

        let after = backend.read_events_after(&t, &e1_id).unwrap();
        assert_eq!(after.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_cascade_events() {
        let dir = temp_dir();
        let mut backend = FileBackend::new(&dir).unwrap();
        let t = tenant();

        let trigger = make_event("ec2");
        let cascade_id = trigger.cascade_id.clone();
        let reaction = Event::reaction(
            EventKind::NodeUpdated {
                node_id: NodeId::new(),
                changes: HashMap::new(),
            },
            &trigger,
        );
        let unrelated = make_event("rds");

        backend
            .append_events(&t, &[trigger, reaction, unrelated])
            .unwrap();

        let cascade = backend.read_cascade_events(&t, &cascade_id).unwrap();
        assert_eq!(cascade.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_event_count() {
        let dir = temp_dir();
        let mut backend = FileBackend::new(&dir).unwrap();
        let t = tenant();

        assert_eq!(backend.event_count(&t).unwrap(), 0);
        backend
            .append_events(&t, &[make_event("ec2"), make_event("rds")])
            .unwrap();
        assert_eq!(backend.event_count(&t).unwrap(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_snapshot() {
        let dir = temp_dir();
        let mut backend = FileBackend::new(&dir).unwrap();
        let t = tenant();

        assert!(backend.load_latest_snapshot(&t).unwrap().is_none());

        let snap = Snapshot {
            id: SnapshotId::new(),
            tenant_id: t.clone(),
            timestamp: chrono::Utc::now(),
            data: vec![10, 20, 30],
            after_event: hydra_core::id::EventId::from_str("evt_SNAP"),
            event_count: 50,
        };

        backend.save_snapshot(snap).unwrap();

        let loaded = backend.load_latest_snapshot(&t).unwrap().unwrap();
        assert_eq!(loaded.data, vec![10, 20, 30]);
        assert_eq!(loaded.event_count, 50);

        // Verify file exists and is readable JSON
        let path = backend.snapshot_path(&t);
        assert!(path.exists());
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"event_count\": 50"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_multi_tenant() {
        let dir = temp_dir();
        let mut backend = FileBackend::new(&dir).unwrap();

        let t1 = TenantId::from_str("ten_A");
        let t2 = TenantId::from_str("ten_B");

        backend.append_events(&t1, &[make_event("ec2")]).unwrap();
        backend
            .append_events(&t2, &[make_event("rds"), make_event("s3")])
            .unwrap();

        assert_eq!(backend.event_count(&t1).unwrap(), 1);
        assert_eq!(backend.event_count(&t2).unwrap(), 2);

        let tenants = backend.list_tenants().unwrap();
        assert_eq!(tenants.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_empty_tenant_returns_empty() {
        let dir = temp_dir();
        let backend = FileBackend::new(&dir).unwrap();
        let t = TenantId::from_str("ten_GHOST");

        assert_eq!(backend.read_events(&t).unwrap().len(), 0);
        assert_eq!(backend.event_count(&t).unwrap(), 0);
        assert!(backend.load_latest_snapshot(&t).unwrap().is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    // === Adversarial tests (code review audit) ===

    #[test]
    fn path_traversal_tenant_id_is_sanitized() {
        let dir = temp_dir();
        let mut backend = FileBackend::new(&dir).unwrap();

        // A malicious tenant ID with path traversal
        let evil_tenant = TenantId::from_str("../../etc/passwd");
        backend
            .append_events(&evil_tenant, &[make_event("ec2")])
            .unwrap();

        // The directory should be inside base_dir, NOT at ../../etc/passwd
        let tenant_dir = backend.tenant_dir(&evil_tenant);
        assert!(
            tenant_dir.starts_with(&dir),
            "Path traversal! tenant_dir {} escaped base_dir {}",
            tenant_dir.display(),
            dir.display()
        );

        // The sanitized name should have replaced dots and slashes
        let dir_name = tenant_dir.file_name().unwrap().to_str().unwrap();
        assert!(!dir_name.contains('/'));
        assert!(!dir_name.contains(".."));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_ndjson_line_fails_gracefully() {
        let dir = temp_dir();
        let mut backend = FileBackend::new(&dir).unwrap();
        let t = tenant();

        // Write a valid event
        backend.append_events(&t, &[make_event("ec2")]).unwrap();

        // Manually corrupt the file by appending invalid JSON
        let path = backend.events_path(&t);
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        use std::io::Write;
        writeln!(file, "{{not valid json}}").unwrap();

        // Reading should fail with a serialization error
        let result = backend.read_events(&t);
        assert!(result.is_err());
    }

    #[test]
    fn empty_tenant_id_is_handled() {
        let dir = temp_dir();
        let mut backend = FileBackend::new(&dir).unwrap();
        let empty_tenant = TenantId::from_str("");

        // Should still work — sanitizer produces a safe fallback name
        backend
            .append_events(&empty_tenant, &[make_event("ec2")])
            .unwrap();
        assert_eq!(backend.event_count(&empty_tenant).unwrap(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_writes_are_serialized_by_flock() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = temp_dir();
        let base_dir = dir.clone();
        let t = TenantId::from_str("ten_CONCURRENT");
        let num_threads = 8;
        let events_per_thread = 50;

        // Create a shared barrier so all threads start writing at once
        let barrier = Arc::new(Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let barrier = Arc::clone(&barrier);
                let base = base_dir.clone();
                let tenant = t.clone();
                thread::spawn(move || {
                    let mut backend = FileBackend::new(&base).unwrap();
                    barrier.wait(); // All threads start simultaneously

                    for j in 0..events_per_thread {
                        let evt = Event::trigger(EventKind::NodeCreated {
                            node_id: NodeId::new(),
                            type_id: format!("thread_{}_{}", i, j),
                            properties: HashMap::new(),
                        });
                        backend.append_events(&tenant, &[evt]).unwrap();
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // Read back — every event should be a valid, parseable JSON line
        let backend = FileBackend::new(&dir).unwrap();
        let events = backend.read_events(&t).unwrap();
        assert_eq!(
            events.len(),
            num_threads * events_per_thread,
            "Expected {} events, got {} — writes were corrupted by concurrency",
            num_threads * events_per_thread,
            events.len()
        );

        // Verify uniqueness — no duplicate event IDs
        let unique: std::collections::HashSet<_> = events.iter().map(|e| e.id.clone()).collect();
        assert_eq!(unique.len(), events.len(), "Duplicate events found!");

        let _ = fs::remove_dir_all(&dir);
    }
}
