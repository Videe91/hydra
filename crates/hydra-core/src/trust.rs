//! Trust Layer — Patch 9 vocabulary.
//!
//! After Patches 1–8 closed the reflex loop (model predicts →
//! evidence → claim → action → approval → execution → outcome →
//! observation), Hydra has enough audit data to start asking:
//!
//! ```text
//! Can I trust this claim?
//! ```
//!
//! Patch 9 introduces a **compute-only**, rule-based trust scoring
//! over a single claim. No persistence (no `TrustAssessmentRecorded`
//! event, no store). No HTTP. No SDK. The engine method
//! `Hydra::assess_claim_trust(claim_id) -> Result<TrustAssessment>`
//! reads the existing audit chain and returns a deterministic
//! envelope.
//!
//! ## Wire form
//!
//! `TrustLevel` is PascalCase via serde default — matches every
//! other core enum (ClaimStatus, ActionKind, OutcomeKind). Patch 10
//! may add a lowercase wire alias if HTTP clients prefer; the
//! engine's typed form stays PascalCase.

use crate::id::{ActionId, ActorId, ClaimId, MicroModelRunId, OutcomeId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Top-level result of `Hydra::assess_claim_trust`.
///
/// `score` is the sum of `factors[i].weight` for every applied
/// factor, clamped to `[0.0, 1.0]`. **Special case**: when
/// `claim.status == Retracted`, the assessor force-sets the
/// score to `0.0` after factor evaluation so a retracted claim
/// can never be "rescued" by accidentally-counterbalancing
/// positives. The `claim_retracted` factor still appears in the
/// list with weight `-1.0` so the explanation remains complete.
///
/// `factors` includes EVERY factor evaluated — `applied=true` for
/// the ones that fired, `applied=false` for the ones that were
/// checked but didn't trigger. This makes trust explainable:
/// "no operator approval found" is as load-bearing as
/// "verified claim".
///
/// `related_action_ids`, `related_outcome_ids`, and
/// `observation_run_ids` are the artifacts the walk surfaced —
/// callers can introspect them without re-walking the chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustAssessment {
    pub claim_id: ClaimId,
    pub score: f64,
    pub level: TrustLevel,
    pub explanation: String,
    pub factors: Vec<TrustFactor>,
    pub related_action_ids: Vec<ActionId>,
    pub related_outcome_ids: Vec<OutcomeId>,
    pub observation_run_ids: Vec<MicroModelRunId>,
    pub assessed_at: DateTime<Utc>,
}

/// Coarse trust bucket. Mapping from `score`:
///
/// ```text
///   score >= 0.80 → High
///   score >= 0.50 → Medium
///   score >= 0.20 → Low
///   score <  0.20 → Unknown   (also when no factors applied)
/// ```
///
/// `Unknown` doubles as "not enough audit data yet" — a freshly-
/// proposed claim with no actions or evidence lands here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    High,
    Medium,
    Low,
    Unknown,
}

/// One factor evaluated during trust assessment.
///
/// `weight` is **signed**: positive contributes to the score,
/// negative penalizes. `applied=true` means the factor's condition
/// fired and its `weight` was added to the running total;
/// `applied=false` means the factor was checked but didn't trigger
/// (its `weight` is the value it WOULD have contributed if it
/// had).
///
/// `kind` is a stable string key — Patch 10's HTTP/SDK surface
/// will treat it as the canonical id for documentation, dashboards,
/// and future factor-weight tuning. Keep it snake_case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustFactor {
    pub kind: String,
    pub weight: f64,
    pub applied: bool,
    pub detail: String,
}

impl TrustAssessment {
    /// Compute the `TrustLevel` for a clamped `score` in `[0.0, 1.0]`.
    /// Centralized so the table is the only place thresholds live.
    pub fn level_for_score(score: f64) -> TrustLevel {
        if score >= 0.80 {
            TrustLevel::High
        } else if score >= 0.50 {
            TrustLevel::Medium
        } else if score >= 0.20 {
            TrustLevel::Low
        } else {
            TrustLevel::Unknown
        }
    }
}

/// Stable string identifier used by `Hydra` for the cascade-driven
/// auto-approver. Trust assessment uses this to distinguish
/// cascade auto-approvals (which DON'T count as operator approval)
/// from real operator approvals. Stays in `hydra-core` so callers
/// outside the engine (the trust assessor in `hydra-engine`, any
/// future HTTP surface) can compare without re-hardcoding the
/// magic string.
pub const HYDRA_POLICY_AGENT_ACTOR: &str = "actor_hydra_policy";

/// Stable string identifier used by `Hydra` for the Patch 15
/// trust-gated auto-approver. Like `HYDRA_POLICY_AGENT_ACTOR`,
/// approvals stamped with this actor MUST NOT count as operator
/// approval for trust calibration — otherwise auto-approvals
/// would bootstrap more auto-approvals (a self-reinforcing
/// trust spiral).
pub const HYDRA_TRUST_GATE_ACTOR: &str = "actor_hydra_trust_gate";

/// Convenience: is this actor the cascade auto-approver?
pub fn is_cascade_approver(actor: &ActorId) -> bool {
    actor.as_str() == HYDRA_POLICY_AGENT_ACTOR
}

/// True for any actor that represents Hydra acting on its own
/// behalf — the cascade policy agent (Patch 6/9) OR the Patch 15
/// trust-gated auto-approver.
///
/// **Load-bearing**: Patch 12's `model_operator_approved_historically`
/// factor uses this to exclude Hydra's own automation from the
/// "humans-endorsed" historical signal. Without this exclusion,
/// Patch 15 auto-approvals would count as operator approval in
/// future trust calibrations, allowing auto-approval to bootstrap
/// more auto-approval — a self-reinforcing trust spiral.
///
/// Future internal actors (e.g., a Patch 16 model's reflex actor)
/// should be added here so they're filtered uniformly.
pub fn is_hydra_automation_actor(actor: &ActorId) -> bool {
    let s = actor.as_str();
    s == HYDRA_POLICY_AGENT_ACTOR || s == HYDRA_TRUST_GATE_ACTOR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_for_score_thresholds_pinned() {
        assert_eq!(TrustAssessment::level_for_score(1.0), TrustLevel::High);
        assert_eq!(TrustAssessment::level_for_score(0.80), TrustLevel::High);
        assert_eq!(TrustAssessment::level_for_score(0.799), TrustLevel::Medium);
        assert_eq!(TrustAssessment::level_for_score(0.50), TrustLevel::Medium);
        assert_eq!(TrustAssessment::level_for_score(0.499), TrustLevel::Low);
        assert_eq!(TrustAssessment::level_for_score(0.20), TrustLevel::Low);
        assert_eq!(TrustAssessment::level_for_score(0.199), TrustLevel::Unknown);
        assert_eq!(TrustAssessment::level_for_score(0.0), TrustLevel::Unknown);
    }

    #[test]
    fn cascade_approver_check_uses_stable_magic_string() {
        // The magic string is the contract — if PolicyAgent ever
        // changes its actor id, trust assessment quietly silently
        // becomes incorrect. This pin (and the engine pin that
        // matches it to `policy_agent::ACTOR_ID`) protects the
        // boundary.
        assert!(is_cascade_approver(&ActorId::from_str("actor_hydra_policy")));
        assert!(!is_cascade_approver(&ActorId::from_str("actor_oncall_alice")));
        assert!(!is_cascade_approver(&ActorId::from_str("actor_ops")));
        assert!(!is_cascade_approver(&ActorId::from_str("hydra_policy")));
        // The Patch 15 trust-gate actor is NOT the cascade actor
        // (cascade auto-approves; trust gate is a separate
        // automation path). Different magic strings on purpose.
        assert!(!is_cascade_approver(&ActorId::from_str(
            "actor_hydra_trust_gate"
        )));
    }

    #[test]
    fn is_hydra_automation_actor_recognizes_both_internal_actors() {
        // CRITICAL for Patch 15: this helper feeds Patch 12's
        // `model_operator_approved_historically` factor. Both
        // Hydra-internal actors must be filtered so neither cascade
        // approval nor trust-gate auto-approval counts as operator
        // endorsement.
        assert!(is_hydra_automation_actor(&ActorId::from_str(
            "actor_hydra_policy"
        )));
        assert!(is_hydra_automation_actor(&ActorId::from_str(
            "actor_hydra_trust_gate"
        )));
    }

    #[test]
    fn is_hydra_automation_actor_does_not_match_operator_actors() {
        // Real operator actors MUST register as non-automation so
        // the operator-history positive trust signal can still
        // fire on genuine human approvals.
        assert!(!is_hydra_automation_actor(&ActorId::from_str(
            "actor_oncall_alice"
        )));
        assert!(!is_hydra_automation_actor(&ActorId::from_str("actor_ops")));
        // Substring-match guard — must compare full string, not
        // prefix.
        assert!(!is_hydra_automation_actor(&ActorId::from_str(
            "actor_hydra_policy_admin"
        )));
        assert!(!is_hydra_automation_actor(&ActorId::from_str(
            "actor_hydra_trust_gate_v2"
        )));
    }

    #[test]
    fn trust_level_serde_is_pascal_case() {
        // Pinned so a future change to `#[serde(rename_all)]` doesn't
        // silently break the wire contract.
        let h = serde_json::to_string(&TrustLevel::High).unwrap();
        assert_eq!(h, "\"High\"");
        let m = serde_json::to_string(&TrustLevel::Medium).unwrap();
        assert_eq!(m, "\"Medium\"");
        let l = serde_json::to_string(&TrustLevel::Low).unwrap();
        assert_eq!(l, "\"Low\"");
        let u = serde_json::to_string(&TrustLevel::Unknown).unwrap();
        assert_eq!(u, "\"Unknown\"");
    }
}
