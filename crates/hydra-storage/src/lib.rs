pub mod backend;
pub mod memory;
pub mod file;

pub mod prelude {
    pub use crate::backend::{Snapshot, StorageBackend};
    pub use crate::memory::MemoryBackend;
    pub use crate::file::FileBackend;
}
