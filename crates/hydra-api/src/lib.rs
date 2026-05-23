//! # Hydra API
//!
//! HTTP API layer for Hydra Sentinel.
//!
//! Provides:
//! - REST endpoints for graph queries and Sentinel-specific queries
//! - CloudTrail ingestion endpoint
//! - `/schemas/*` schema introspection / preflight / register / lifecycle
//!   (mounted from `hydra-net::http`)
//! - Prometheus-compatible metrics
//! - CORS and security headers
//!
//! ## Two engine ownership models (transitional)
//!
//! The legacy [`state::AppState`]-backed server uses
//! `Arc<std::sync::Mutex<Hydra>>` (sync). The schema HTTP surface mounts a
//! [`hydra_net::runtime::RuntimeHandle`], which owns
//! `Arc<tokio::sync::RwLock<Hydra>>` (async). They cannot share a single
//! `Hydra` instance today. Unifying them is a dedicated follow-up patch.
//!
//! ## Quick Start (legacy AppState-backed server)
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
//!
//! ## Quick Start (schema HTTP server)
//!
//! ```rust,ignore
//! use hydra_api::server;
//! use hydra_net::runtime::RuntimeBuilder;
//!
//! #[tokio::main]
//! async fn main() {
//!     let (runtime, _processor) = RuntimeBuilder::new().build();
//!     server::serve_schema(runtime, "0.0.0.0:3000").await.unwrap();
//! }
//! ```

pub mod responses;
pub mod routes;
pub mod server;
pub mod state;
pub mod transport;
