//! # Sentinel Query Layer
//!
//! Pure functions over `&dyn GraphReader` + engine indexes.
//! No mutations — these are read-only projections of the graph into
//! structured answers that Arms, APIs, and UIs consume.
//!
//! ## Design Principles
//!
//! 1. **Pure functions** — every query takes `&dyn GraphReader` (+ optional
//!    `&TemporalIndex`, `&EventLog`), never `&mut`. They cannot create events.
//! 2. **Rich return types** — no raw `Vec<NodeId>`. Every query returns a
//!    struct with context (severity, reason, affected nodes, recommendations).
//! 3. **Cloud-agnostic** — queries operate on abstract types (COMPUTE_INSTANCE,
//!    MANAGED_DATABASE, etc.), never on AWS/Azure/GCP-specific names.
//! 4. **Bounded traversal** — BFS queries accept max_depth to prevent
//!    unbounded graph walks on large estates.

pub mod blast_radius;
pub mod recovery_plan;
pub mod compliance_gaps;
pub mod confidence_report;
pub mod protection_status;
pub mod temporal;
pub mod coverage_bridge;
pub mod anomaly_bridge;

pub use blast_radius::*;
pub use recovery_plan::*;
pub use compliance_gaps::*;
pub use confidence_report::*;
pub use protection_status::*;
// temporal, coverage_bridge, anomaly_bridge accessed as queries::temporal::*, etc.
