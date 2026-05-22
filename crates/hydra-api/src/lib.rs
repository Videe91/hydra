//! # Hydra API
//!
//! HTTP API layer for Hydra Sentinel.
//!
//! Provides:
//! - REST endpoints for graph queries and Sentinel-specific queries
//! - CloudTrail ingestion endpoint
//! - Prometheus-compatible metrics
//! - CORS and security headers
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use hydra_api::{server, state::AppState};
//! use hydra_engine::prelude::*;
//!
//! #[tokio::main]
//! async fn main() {
//!     let hydra = Hydra::new();
//!     // ... register Arms ...
//!     let state = AppState::new(hydra);
//!     server::serve(state, "0.0.0.0:3000").await.unwrap();
//! }
//! ```

pub mod responses;
pub mod routes;
pub mod server;
pub mod state;
pub mod transport;
