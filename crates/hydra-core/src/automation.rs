//! Automation Layer — Patch 11 vocabulary.
//!
//! The forward-looking namespace for Hydra's automated decision
//! envelopes. Trust judges (Patch 9/10); automation acts on those
//! judgments — but only when the judgment says it's safe.
//!
//! Patch 11 introduces the first automation: trust-aware
//! auto-execution of low-risk Notify actions. Future patches add
//! auto-quarantine, auto-throttle, etc. All share this module.
//!
//! ## Decision envelope vs error
//!
//! Auto-actions return a `Decision` envelope, NOT a Result of
//! success/failure. The decision IS the data:
//!
//! ```text
//!   executed: true  → Hydra ran the action; here's the trust
//!                     judgment that justified it + the execution
//!                     report
//!   executed: false → Hydra DIDN'T run it; here's the trust
//!                     judgment (if assessed) + the reason
//! ```
//!
//! Both 200 OK on the wire. The only true errors are: unknown
//! action id (404) and "this action can never be auto-executed"
//! (wrong kind → 400). "Not ready yet" and "below trust" are
//! decisions, not errors.

use crate::action::ActionExecutionReport;
use crate::trust::TrustAssessment;
use serde::{Deserialize, Serialize};

/// The result of `Hydra::auto_execute_trusted_notify_action` —
/// the first automation surface in Hydra.
///
/// Field semantics:
///
/// - `executed`: true iff Hydra actually called the underlying
///   execute path. When true, both `trust` and `execution` are
///   populated.
///
/// - `reason`: deterministic prose explaining the decision. Read
///   by operator dashboards + Patch 12's auto-quarantine, etc.
///   Stable enough that test pins on substrings are honest.
///
/// - `trust`: populated whenever the assessor was invoked. `None`
///   when the action failed precondition checks BEFORE trust was
///   read (no related_claims, wrong status, etc.). This split
///   matters: future audit dashboards can distinguish "trust said
///   no" from "we never asked trust".
///
/// - `execution`: populated only when `executed == true`. None
///   on every skip path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutoExecutionDecision {
    pub executed: bool,
    pub reason: String,
    pub trust: Option<TrustAssessment>,
    pub execution: Option<ActionExecutionReport>,
}

/// Outcome of a Notify delivery attempt — Patch 14.
///
/// Produced by a `NotifyDeliveryAdapter` (in `hydra-net`) and
/// passed back to the engine via
/// `Hydra::execute_notify_action_with_delivery`. The engine uses
/// this to choose which terminal lifecycle event to emit:
///
/// ```text
///   Succeeded → ActionExecuted + OutcomeObserved { Success }
///   Failed    → ActionFailed   + OutcomeObserved { Failure }
/// ```
///
/// `latency_ms` is measured from the moment the adapter starts
/// the delivery attempt to when it gets a result (success, error,
/// or timeout). Always present so trust calibration can later
/// branch on slow-but-eventually-OK deliveries.
///
/// `status_code` is the HTTP status of the receiver's response.
/// `Some(...)` when a real HTTP response landed (regardless of
/// 2xx vs non-2xx). `None` on timeout / network error / DNS
/// failure / any path that never got a status back. This keeps
/// "the receiver rejected us" distinguishable from "we never
/// reached the receiver."
///
/// `adapter` is a stable string id (e.g. `"webhook"`, `"stub"`,
/// future `"slack"`/`"pagerduty"`). Stored on the outcome's
/// `impact` so future patches can filter trust calibration by
/// delivery mechanism.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DeliveryOutcome {
    Succeeded {
        adapter: String,
        status_code: u16,
        latency_ms: u64,
    },
    Failed {
        adapter: String,
        reason: String,
        status_code: Option<u16>,
        latency_ms: u64,
    },
}

impl DeliveryOutcome {
    pub fn is_succeeded(&self) -> bool {
        matches!(self, DeliveryOutcome::Succeeded { .. })
    }

    pub fn adapter(&self) -> &str {
        match self {
            DeliveryOutcome::Succeeded { adapter, .. } => adapter,
            DeliveryOutcome::Failed { adapter, .. } => adapter,
        }
    }

    pub fn latency_ms(&self) -> u64 {
        match self {
            DeliveryOutcome::Succeeded { latency_ms, .. } => *latency_ms,
            DeliveryOutcome::Failed { latency_ms, .. } => *latency_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{ActionId, ActorId, ClaimId, OutcomeId};
    use crate::trust::TrustLevel;

    fn sample_trust() -> TrustAssessment {
        TrustAssessment {
            claim_id: ClaimId::from_str("claim_t1"),
            score: 0.92,
            level: TrustLevel::High,
            explanation: "test".to_string(),
            factors: vec![],
            related_action_ids: vec![],
            related_outcome_ids: vec![],
            observation_run_ids: vec![],
            assessed_at: chrono::Utc::now(),
        }
    }

    fn sample_execution() -> ActionExecutionReport {
        ActionExecutionReport {
            action_id: ActionId::from_str("act_x"),
            previous_status: crate::action::ActionStatus::Approved,
            final_status: crate::action::ActionStatus::Executed,
            outcome_id: OutcomeId::from_str("out_x"),
            executed_by: ActorId::from_str("actor_test"),
            executed_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn auto_execution_decision_skip_serializes_with_null_subobjects() {
        // Skip path: trust may or may not be present; execution
        // is None. Pin that None serializes as JSON `null` so the
        // SDK's `Optional` typing round-trips faithfully.
        let decision = AutoExecutionDecision {
            executed: false,
            reason: "not Approved".to_string(),
            trust: None,
            execution: None,
        };
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["executed"], false);
        assert!(json["trust"].is_null());
        assert!(json["execution"].is_null());
    }

    #[test]
    fn auto_execution_decision_execute_path_carries_both_subobjects() {
        let decision = AutoExecutionDecision {
            executed: true,
            reason: "trust High passed".to_string(),
            trust: Some(sample_trust()),
            execution: Some(sample_execution()),
        };
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["executed"], true);
        assert!(json["trust"].is_object());
        assert!(json["execution"].is_object());
    }

    #[test]
    fn delivery_outcome_succeeded_round_trips_through_json() {
        let outcome = DeliveryOutcome::Succeeded {
            adapter: "webhook".to_string(),
            status_code: 204,
            latency_ms: 42,
        };
        let json = serde_json::to_value(&outcome).unwrap();
        // PascalCase via serde default — matches every core enum.
        let succeeded = json
            .get("Succeeded")
            .expect("variant-tagged shape: {Succeeded: ...}");
        assert_eq!(succeeded["adapter"], "webhook");
        assert_eq!(succeeded["status_code"], 204);
        assert_eq!(succeeded["latency_ms"], 42);
        // Roundtrip.
        let back: DeliveryOutcome = serde_json::from_value(json).unwrap();
        assert!(back.is_succeeded());
        assert_eq!(back.adapter(), "webhook");
        assert_eq!(back.latency_ms(), 42);
    }

    #[test]
    fn delivery_outcome_failed_status_code_none_serializes_as_null() {
        // Network errors / timeouts have no HTTP status. Pin that
        // None serializes as JSON `null` so downstream consumers
        // can distinguish "receiver rejected us" from "we never
        // reached the receiver."
        let outcome = DeliveryOutcome::Failed {
            adapter: "webhook".to_string(),
            reason: "timeout after 5000ms".to_string(),
            status_code: None,
            latency_ms: 5000,
        };
        let json = serde_json::to_value(&outcome).unwrap();
        let failed = json.get("Failed").unwrap();
        assert!(failed["status_code"].is_null());
        assert!(!outcome.is_succeeded());
    }
}
