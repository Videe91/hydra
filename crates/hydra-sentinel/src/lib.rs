pub mod nodes;
pub mod edges;
pub mod queries;
pub mod arms;

/// Convenience re-exports
pub mod prelude {
    pub use crate::nodes::*;
    // Abstract builders
    pub use crate::nodes::resource::*;
    // Cloud adapters
    pub use crate::nodes::aws::*;
    pub use crate::nodes::azure::*;
    pub use crate::nodes::gcp::*;
    // Domain modules
    pub use crate::nodes::protection::*;
    pub use crate::nodes::trust::*;
    pub use crate::nodes::threat::*;
    pub use crate::nodes::compliance::*;
    pub use crate::edges::*;
    pub use crate::edges::edge_prop;
    // Queries
    pub use crate::queries::*;
    // Arms
    pub use crate::arms::*;
}
