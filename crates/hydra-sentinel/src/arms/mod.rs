//! # Sentinel Arms — 10 Autonomous Subscription Handlers
//!
//! Arms are `SubscriptionHandler` implementations that use Sentinel queries
//! to make autonomous decisions. Each solves one bottleneck (B1-B10).
//!
//! ## Full Feedback Loop
//! ```text
//! Sensor → Event → Cascade Engine → Arm.handle(event, graph)
//!                                     ↓
//!                                   Query (pure read)
//!                                     ↓
//!                                   Decision
//!                                     ↓
//!                                   Vec<EventKind> (emitted back into cascade)
//! ```
//!
//! ## Design Rules
//!
//! 1. Arms are stateless — all state lives in the graph.
//! 2. Arms call queries, never modify the graph directly.
//! 3. Arms emit events (NodeUpdated, Signal) that the cascade engine applies.
//! 4. Arms must converge — output events must not re-trigger the same Arm.
//!
//! ## Priority Chain (higher = fires first)
//!
//! ```text
//! Discovery      (200) → B1: Converts sensor signals to graph nodes
//! Classification (190) → B2: Auto-classifies resources by criticality
//! Policy         (180) → B3: Computes protection policies
//! Execution      (170) → B4: Triggers backup operations
//! Verification   (160) → B5: Verifies backup integrity (KEY DIFFERENTIATOR)
//! Trust          (100) → B5: Recomputes trust scores
//! Compliance     (90)  → B8: Checks regulatory requirements
//! Threat/Detect  (80)  → B6: Assesses anomalies via blast_radius
//! Response       (70)  → B7: Generates recovery plans + incidents
//! Cost           (60)  → B9: Optimizes storage costs
//! ```
//!
//! Scaling (B10) is emergent: Discovery + Classification chaining
//! means new resources get protected within one cascade cycle.

pub mod discovery_arm;
pub mod classification_arm;
pub mod policy_arm;
pub mod execution_arm;
pub mod verification_arm;
pub mod trust_arm;
pub mod compliance_arm;
pub mod threat_arm;
pub mod response_arm;
pub mod cost_arm;

pub use discovery_arm::DiscoveryArm;
pub use classification_arm::ClassificationArm;
pub use policy_arm::PolicyArm;
pub use execution_arm::ExecutionArm;
pub use verification_arm::VerificationArm;
pub use trust_arm::TrustArm;
pub use compliance_arm::ComplianceArm;
pub use threat_arm::ThreatArm;
pub use response_arm::ResponseArm;
pub use cost_arm::CostArm;
