pub mod backend;
pub mod memory;
pub mod file;
pub mod commit_log;
pub mod recovery;
pub mod snapshot;

pub mod prelude {
    pub use crate::backend::{Snapshot, StorageBackend};
    pub use crate::memory::MemoryBackend;
    pub use crate::file::FileBackend;
    pub use crate::commit_log::CommitLog;
    pub use crate::recovery::{
        recover_from_latest_snapshot_or_commit_log, RecoveryMode, RecoveryReport,
    };
    pub use crate::snapshot::FileSnapshotStore;
}
