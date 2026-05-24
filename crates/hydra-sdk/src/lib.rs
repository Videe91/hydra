pub mod builder;
pub mod persistent;
pub mod schema;
pub mod schema_admin;
pub mod test_hydra;

pub use persistent::{HydraRuntime, InspectReport, RecoverabilityReport, VerifyReport};

pub mod prelude {
    pub use crate::builder::HydraBuilder;
    pub use crate::persistent::{
        HydraRuntime, InspectReport, RecoverabilityReport, VerifyReport,
    };
    pub use crate::schema::SchemaApi;
    pub use crate::schema_admin::{SchemaAdmin, SchemaFields};
    pub use crate::test_hydra::TestHydra;

    // Re-export the most commonly needed types from downstream crates
    pub use hydra_core::prelude::*;
    pub use hydra_engine::prelude::*;
    pub use hydra_storage::prelude::*;
}
