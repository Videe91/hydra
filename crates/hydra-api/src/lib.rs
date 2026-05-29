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
//! ## Engine ownership
//!
//! Every router exposed by hydra-api is built from a single
//! [`hydra_net::runtime::RuntimeHandle`], which holds
//! `Arc<tokio::sync::RwLock<Hydra>>`. Legacy CloudTrail/Sentinel routes and
//! the `/schemas/*` surface share the same `Hydra` instance through this
//! handle — schema writes are immediately visible to legacy queries, and
//! CloudTrail ingestion is immediately visible to `/schemas/*`. There is
//! no split-brain.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use hydra_api::server;
//! use hydra_net::runtime::RuntimeBuilder;
//!
//! #[tokio::main]
//! async fn main() {
//!     let (runtime, _processor) = RuntimeBuilder::new()
//!         // ... .subscription(...) to register Sentinel Arms ...
//!         .build();
//!     server::serve(runtime, "0.0.0.0:3000").await.unwrap();
//! }
//! ```
//!
//! For a schema-only deployment without the legacy surface, use
//! [`server::serve_schema`] instead.
//!
//! ## Quick Start (persistent server — restart-safe, snapshot-aware, auth-gated)
//!
//! ```rust,ignore
//! use hydra_api::auth::AuthConfig;
//! use hydra_api::server::serve_persistent_with_auth;
//! use hydra_core::ActorId;
//!
//! #[tokio::main]
//! async fn main() {
//!     serve_persistent_with_auth(
//!         "/var/lib/hydra",
//!         "0.0.0.0:3000",
//!         ActorId::from_str("actor_boot"),
//!         AuthConfig::require_for_mutations(["change-me"]),
//!     )
//!     .await
//!     .unwrap();
//! }
//! ```
//!
//! `serve_persistent_with_auth` opens the commit log + snapshot store at
//! `root`, recovers from the fastest available source, attaches both
//! backends for write-through, and serves the full route surface with
//! the supplied auth policy.
//!
//! ## Authentication
//!
//! Authentication is opt-in in v0. Use [`server::build_router_with_auth`]
//! or [`server::serve_with_auth`] with
//! [`AuthConfig::require_for_mutations`] before exposing destructive
//! routes (`POST /ingest`, `POST /schemas/*`, `POST /snapshots`,
//! `POST /snapshots/:id/restore`, etc.) to untrusted clients. The
//! default [`AuthConfig::off`] preserves existing behavior.

pub mod auth;
pub mod responses;
pub mod routes;
pub mod security;
pub mod server;
pub mod state;
pub mod transport;

pub use auth::{AuthConfig, AuthMode};
pub use security::{NotifyDeliveryConfig, RateLimitMode, ServerSecurityConfig, TlsConfig};
