//! # Hydra Sensor
//!
//! Cloud infrastructure sensors that convert cloud provider events
//! into Hydra EventKind::Signal events.
//!
//! Currently supports:
//! - AWS CloudTrail (management events)
//!
//! Future:
//! - Azure Activity Log
//! - GCP Audit Log
//! - AWS Config (configuration snapshots)
//! - AWS GuardDuty (threat intelligence)

pub mod cloudtrail;
pub mod cloudtrail_mapping;

pub use cloudtrail::{CloudTrailSensor, CloudTrailConfig, ParseResult};
pub use cloudtrail_mapping::SignalKind;
