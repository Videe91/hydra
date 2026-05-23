pub mod sensor;
pub mod bus;
pub mod http;
pub mod query;
pub mod schema_admin_service;
pub mod schema_service;
pub mod runtime;

/// Convenience re-exports
pub mod prelude {
    pub use crate::sensor::{
        PollSensor, PollSensorHandle, SensorBatch, SensorEmitter, SensorError, SensorResult,
    };
    pub use crate::bus::{BusConfig, BusMetrics, CascadeNotification};
    pub use crate::http::{
        ingest_router, schema_router, sensor_router, IngestHttpState, SchemaHttpState,
        SensorHttpState,
    };
    pub use crate::query::{QueryService, QueryStats};
    pub use crate::schema_admin_service::{SchemaAdminService, SchemaFields};
    pub use crate::schema_service::SchemaService;
    pub use crate::runtime::{RuntimeBuilder, RuntimeConfig, RuntimeHandle, RuntimeProcessor};
}
