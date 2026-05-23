pub mod backend;
pub mod memory;
pub mod file;
pub mod commit_log;

pub mod prelude {
    pub use crate::backend::{Snapshot, StorageBackend};
    pub use crate::memory::MemoryBackend;
    pub use crate::file::FileBackend;
    pub use crate::commit_log::CommitLog;
}
