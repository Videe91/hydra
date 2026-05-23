//! # Application State
//!
//! Shared state accessible by all HTTP handlers.
//!
//! `AppState` holds a [`RuntimeHandle`] (the same one served by
//! `hydra-net`), so legacy CloudTrail/Sentinel routes and the
//! `/schemas/*` routes share a single underlying `Hydra` instance.

use crate::transport::CloudTrailTransport;
use hydra_net::runtime::RuntimeHandle;
use std::sync::Arc;
use std::time::Instant;

/// Shared application state passed to every handler via Axum's State extractor.
#[derive(Clone)]
pub struct AppState {
    /// Shared engine handle. Legacy routes acquire `runtime.hydra().read().await`
    /// or `.write().await` as needed; schema routes go through the typed
    /// `schema()` / `schema_admin()` services on the same `RuntimeHandle`.
    pub runtime: RuntimeHandle,
    /// CloudTrail transport (thread-safe sensor wrapper)
    pub transport: Arc<CloudTrailTransport>,
    /// Server start time (for uptime calculation)
    pub started_at: Instant,
}

impl AppState {
    pub fn new(runtime: RuntimeHandle) -> Self {
        Self {
            runtime,
            transport: Arc::new(CloudTrailTransport::new()),
            started_at: Instant::now(),
        }
    }

    pub fn with_transport(runtime: RuntimeHandle, transport: CloudTrailTransport) -> Self {
        Self {
            runtime,
            transport: Arc::new(transport),
            started_at: Instant::now(),
        }
    }
}
