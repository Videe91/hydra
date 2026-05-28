//! Configurable on-disk durability for the storage backends.
//!
//! The storage layer's `flush()` calls only push data from the
//! `BufWriter` into the underlying `File` — they do NOT instruct the
//! OS to flush the file's kernel page cache to physical media. After
//! a `flush()` returns, an OS panic or power loss can still lose the
//! most recent writes.
//!
//! For a journal-style commit log this is unacceptable for production;
//! for in-process tests it's actively desirable (fsync per test is
//! slow). This module exposes a small policy enum that the
//! `CommitLog` and `FileSnapshotStore` consume on construction. The
//! default is durable; tests opt out explicitly.
//!
//! ## What each variant maps to
//!
//! - `None`      — no fsync. `flush()` only. Test/dev opt-in.
//! - `DataOnly`  — `File::sync_data()` after every write
//!                 (Linux `fdatasync(2)`). Production default;
//!                 matches Postgres `wal_sync_method = fdatasync`.
//!                 Skips metadata-timestamp flush for speed.
//! - `Full`      — `File::sync_all()` after every write
//!                 (Linux `fsync(2)`). Also flushes timestamps and
//!                 other metadata. Rarely needed; matches Postgres
//!                 `wal_sync_method = fsync`.
//!
//! ## The "rename trap"
//!
//! On POSIX, `fs::rename(temp, canonical)` is atomic for visibility
//! but not for durability. Three steps are required:
//!   1. fsync the temp file BEFORE the rename
//!   2. rename (atomic on POSIX)
//!   3. fsync the PARENT directory AFTER the rename — the directory
//!      entry change lives in the parent inode's data
//!
//! `sync_parent_dir(path, policy)` handles step 3. The temp-file
//! sync (step 1) is handled inline at each call site via
//! `sync_file(&file, policy)` right after `flush()`.
//!
//! On non-Unix platforms directory fsync is a no-op — Windows uses
//! `ReplaceFileW`-style atomicity with different durability
//! guarantees and we don't emulate it here.

use hydra_core::error::{HydraError, Result};
use std::fs::File;
use std::io;
use std::path::Path;

/// Durability policy for storage backends. See module docs for the
/// per-variant semantics. Default is `DataOnly`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityPolicy {
    /// No fsync. Writes are flushed from the BufWriter into the file
    /// handle but the OS page cache is not forced to disk. Choose
    /// this for tests and dev; never for production data.
    None,
    /// `File::sync_data()` per write. Production default. Matches
    /// `fdatasync(2)` on Linux — flushes file data + the minimal
    /// metadata required to read it back (notably, the file size).
    DataOnly,
    /// `File::sync_all()` per write. Same as `DataOnly` plus
    /// metadata (timestamps, owner, etc.). Matches `fsync(2)` on
    /// Linux. Use only when you also need durable mtime/atime.
    Full,
}

impl Default for DurabilityPolicy {
    fn default() -> Self {
        Self::DataOnly
    }
}

/// Sync the file's data to disk per the configured policy. Returns
/// the underlying `io::Result` so the caller can attach path context
/// when wrapping it into `HydraError`.
pub(crate) fn sync_file(file: &File, policy: DurabilityPolicy) -> io::Result<()> {
    match policy {
        DurabilityPolicy::None => Ok(()),
        DurabilityPolicy::DataOnly => file.sync_data(),
        DurabilityPolicy::Full => file.sync_all(),
    }
}

/// Sync the parent directory of `path` so a freshly-renamed file's
/// directory entry survives a power loss. No-op when policy is
/// `None`. No-op on non-Unix platforms.
///
/// The Linux/macOS implementation opens the parent directory read-
/// only and calls `sync_all()` on it. `sync_data` is not portable
/// for directories — `sync_all` is the safe choice across both
/// platforms.
pub(crate) fn sync_parent_dir(path: &Path, policy: DurabilityPolicy) -> Result<()> {
    if matches!(policy, DurabilityPolicy::None) {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => return Ok(()),
        };
        let dir = File::open(parent).map_err(|err| {
            HydraError::StorageError(format!(
                "failed to open parent directory {} for fsync: {err}",
                parent.display()
            ))
        })?;
        dir.sync_all().map_err(|err| {
            HydraError::StorageError(format!(
                "failed to fsync parent directory {}: {err}",
                parent.display()
            ))
        })?;
    }
    #[cfg(not(unix))]
    {
        // Directory fsync is a no-op on non-Unix platforms. Windows
        // rename atomicity has different semantics (ReplaceFileW) and
        // is not emulated here.
        let _ = path;
    }
    Ok(())
}
