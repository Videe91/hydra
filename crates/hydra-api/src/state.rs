//! # Application State
//!
//! Shared state accessible by all HTTP handlers.

use crate::transport::CloudTrailTransport;
use hydra_engine::prelude::Hydra;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Shared application state passed to every handler via Axum's State extractor.
#[derive(Clone)]
pub struct AppState {
    /// The Hydra engine (behind Mutex for exclusive write access)
    pub hydra: Arc<Mutex<Hydra>>,
    /// CloudTrail transport (thread-safe sensor wrapper)
    pub transport: Arc<CloudTrailTransport>,
    /// Server start time (for uptime calculation)
    pub started_at: Instant,
}

impl AppState {
    pub fn new(hydra: Hydra) -> Self {
        Self {
            hydra: Arc::new(Mutex::new(hydra)),
            transport: Arc::new(CloudTrailTransport::new()),
            started_at: Instant::now(),
        }
    }

    pub fn with_transport(hydra: Hydra, transport: CloudTrailTransport) -> Self {
        Self {
            hydra: Arc::new(Mutex::new(hydra)),
            transport: Arc::new(transport),
            started_at: Instant::now(),
        }
    }
}
