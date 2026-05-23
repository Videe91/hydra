pub mod sensor;
pub mod bus;
pub mod query;
pub mod schema_service;
pub mod runtime;

/// Convenience re-exports
pub mod prelude {
    pub use crate::sensor::{
        PollSensor, PollSensorHandle, SensorBatch, SensorEmitter, SensorError, SensorResult,
    };
    pub use crate::bus::{BusConfig, BusMetrics, CascadeNotification};
    pub use crate::query::{QueryService, QueryStats};
    pub use crate::schema_service::SchemaService;
    pub use crate::runtime::{RuntimeBuilder, RuntimeConfig, RuntimeHandle, RuntimeProcessor};
}
