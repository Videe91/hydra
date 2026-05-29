pub mod sensor;
pub mod bus;
pub mod http;
pub mod metrics;
pub mod query;
pub mod replication_worker;
pub mod role;
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
        actions_router, commit_stream_router, commits_router, diagnostics_router, events_router,
        ingest_router, lineage_router, micromodels_router, observations_router, query_router,
        schema_router, sensor_router, snapshots_router, trust_router, ActionExecutionResponse,
        ActionTransitionResponse, ActionsHttpState, AnomalyResponse, ApproveActionRequest,
        AutoExecuteActionRequest, AutoExecuteActionResponse, CommitBroadcaster,
        CommitStreamHttpState, CommitsHttpState, CounterfactualDiagnosticsResponse,
        CoverageDiagnosticsResponse, DiagnosticsHttpState, EvaluateCommitRateRequest,
        EvaluateCommitRateResponse, EvaluationMode, EventsHttpState,
        EvolutionDiagnosticsResponse, ExecuteActionRequest, IngestHttpState, LineageHttpState,
        LineageResponse, MicroModelObservationResponse, MicroModelsHttpState,
        ObservationsHttpState, QueryHttpState, RecordObservationFromOutcomeRequest,
        RecordObservationFromRejectedActionRequest, RejectActionRequest, SchemaHttpState,
        SensorHttpState, SnapshotsHttpState, TrustHttpState, COMMIT_STREAM_CAPACITY,
    };
    pub use crate::metrics::{
        metrics_router, MetricsRecorder, NoopRecorder, PrometheusTextRecorder,
    };
    pub use crate::query::{QueryService, QueryStats};
    pub use crate::replication_worker::{
        ReplicationBootstrapReport, ReplicationHeartbeatRecord, ReplicationLoopError,
        ReplicationLoopReport, ReplicationPullError, ReplicationPullErrorKind, ReplicationPuller,
        ReplicationPullReport, ReplicationPullerConfig, ReplicationRetryConfig,
    };
    pub use crate::role::{RoleState, RuntimeRole};
    pub use crate::schema_admin_service::{SchemaAdminService, SchemaFields};
    pub use crate::schema_service::SchemaService;
    pub use crate::runtime::{RuntimeBuilder, RuntimeConfig, RuntimeHandle, RuntimeProcessor};
}
