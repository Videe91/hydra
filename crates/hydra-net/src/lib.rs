pub mod sensor;
pub mod bus;
pub mod http;
pub mod query;
pub mod replication_worker;
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
        commits_router, events_router, ingest_router, query_router, schema_router, sensor_router,
        snapshots_router, CommitsHttpState, EventsHttpState, IngestHttpState, QueryHttpState,
        SchemaHttpState, SensorHttpState, SnapshotsHttpState,
    };
    pub use crate::query::{QueryService, QueryStats};
    pub use crate::replication_worker::{
        ReplicationBootstrapReport, ReplicationPuller, ReplicationPullReport,
        ReplicationPullerConfig,
    };
    pub use crate::schema_admin_service::{SchemaAdminService, SchemaFields};
    pub use crate::schema_service::SchemaService;
    pub use crate::runtime::{RuntimeBuilder, RuntimeConfig, RuntimeHandle, RuntimeProcessor};
}
