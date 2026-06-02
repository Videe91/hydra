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

use crate::id::{
    ActionId, ActorId, CausalCellId, ClaimId, MicroModelRunId, OutcomeId,
};
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

/// Patch 41 — pinned floor for `Hydra::accept_semantic_identity_match`.
///
/// Equals the current `TrustLevel::High` threshold (0.80), but
/// **defined as a separate constant** so future trust
/// recalibration cannot silently lower the accept-match gate
/// without an explicit amendment + test bump. The gate composes
/// `level == TrustLevel::High AND score >= ACCEPT_MATCH_SCORE_FLOOR`
/// across THREE axes (match + entity + source) — belt-and-
/// suspenders so a one-day relaxation of the `High` threshold
/// alone doesn't weaken P41's gate.
///
/// If a future patch wants to drift the trust thresholds, the
/// `accept_floor_equals_high_threshold` test will fire — forcing
/// an explicit decision rather than silent loosening.
pub const ACCEPT_MATCH_SCORE_FLOOR: f64 = 0.80;

/// Patch 45 — pinned floor for auto-actions on correlation candidates.
///
/// Equals the current `TrustLevel::High` / `CorrelationStrength::Strong`
/// threshold (0.80), but **defined as a separate constant** so future
/// trust recalibration cannot silently lower the gate at which an
/// agent is allowed to act on a `CorrelationCandidate`. The future
/// auto-action workflow MUST compose
/// `trust.level == TrustLevel::High AND trust.score >= ACCEPT_CORRELATION_FLOOR`
/// rather than relying on the band threshold alone.
///
/// Mirrors `ACCEPT_MATCH_SCORE_FLOOR` (Patch 41) — the same belt-
/// and-suspenders pattern. Pinned by
/// `accept_correlation_floor_is_eighty` in `hydra-core::trust::tests`.
pub const ACCEPT_CORRELATION_FLOOR: f64 = 0.80;

/// Patch 45 — pairwise `observed_at` delta gate for the
/// `CorrelationReasonKind::TimeProximity` reason.
///
/// Default: 15 minutes (900 seconds). Wide enough to span typical
/// ETL-fail → dashboard-alert chains, tight enough to avoid spurious
/// co-occurrence between unrelated streams. The
/// `assess_correlation_candidate` engine method fires the
/// `TimeProximity` factor only when SOME pair of supplied signals
/// both carry `observed_at == Some(_)` AND their delta in seconds is
/// `<= CORRELATION_TIME_PROXIMITY_WINDOW_SECS`.
///
/// Pinned by `correlation_time_proximity_window_is_nine_hundred` in
/// `hydra-core::trust::tests`. A future patch may want to make this
/// per-tenant configurable — that requires an explicit amendment, not
/// a silent recalibration.
pub const CORRELATION_TIME_PROXIMITY_WINDOW_SECS: u64 = 900;

// === Patch 23 — CausalCell trust folding ===========================
//
// Cell trust is structurally different from claim trust: it walks
// a (small, single-level in v0) tree of cells rather than a single
// claim's evidence chain. The fields differ enough that a new
// envelope reads more clearly than overloading `TrustAssessment`,
// but the level threshold table is shared (via
// `TrustAssessment::level_for_score`) and the factor records
// reuse `TrustFactor`.

/// Top-level result of `Hydra::assess_causal_cell_trust`.
///
/// `score` is the base score (average of known child trust scores
/// in [0.0, 1.0]; falls back to the cell's own `trust_score` for
/// leaf cells with no children) modified by the Patch 23 factor
/// table, clamped to `[0.0, 1.0]`.
///
/// `factors` includes EVERY factor evaluated — `applied=true` for
/// the ones that fired, `applied=false` for the ones that were
/// checked but didn't trigger. Same "explainable trust" pattern
/// as Patch 9's claim trust.
///
/// `child_scores` surfaces each direct child's (cell_id,
/// trust_score, claim_ids, outcome_ids) so callers can render a
/// composition tree without re-walking the store. Empty for
/// leaf cells.
///
/// Patch 23 boundary: this is READ-ONLY compute. Nothing in the
/// engine persists or events this back. `cell.trust_score`
/// (set by Patch 22's naïve mean) stays as-is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalCellTrustAssessment {
    pub cell_id: CausalCellId,
    pub score: f64,
    pub level: TrustLevel,
    pub explanation: String,
    pub factors: Vec<TrustFactor>,
    pub child_scores: Vec<CausalCellChildTrust>,
    pub assessed_at: DateTime<Utc>,
}

/// One direct child's contribution to a cell's trust assessment.
/// Surfaced on the parent's assessment so callers can render the
/// composition tree's leaves without re-walking the store.
///
/// `trust_score` is the child's stored `cell.trust_score` —
/// Patch 23 v0 does NOT recompute child trust; it folds over
/// already-stored values. (Patch 24+ may add a recompute mode.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalCellChildTrust {
    pub cell_id: CausalCellId,
    pub trust_score: Option<f64>,
    pub claim_ids: Vec<ClaimId>,
    pub outcome_ids: Vec<OutcomeId>,
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

/// True for ANY Hydra-internal actor — a strict superset of
/// `is_hydra_automation_actor`. Patch 18's `AgentLoopStormModel`
/// uses this to filter out Hydra's own structural activity from
/// the per-window event tally so the storm signal reflects
/// non-Hydra agent activity only.
///
/// **Why not extend `is_hydra_automation_actor`?** That helper has
/// narrower load-bearing semantics: actors whose *approvals* must
/// not count as human endorsement. Broadening it to include
/// non-approver internals (verification agent, model auto-register
/// actors, etc.) would silently change the trust-spiral filter's
/// meaning across Patches 12, 15, and any future calibration
/// patches. Two helpers with two purposes is the safer split.
///
/// The list is currently inlined for v0 to keep the patch focused.
/// When the list grows or starts to need lookup in non-engine
/// crates, a const registry will make sense — until then, the
/// inline match is honest about the scope.
pub fn is_hydra_system_actor(actor: &ActorId) -> bool {
    let s = actor.as_str();
    matches!(
        s,
        // Approvers (cascade + trust-gate). Also covered by
        // `is_hydra_automation_actor`; included here for a single
        // authoritative answer to "is this Hydra acting?".
        "actor_hydra_policy"
            | "actor_hydra_trust_gate"
            // Belief / outcome / remediation / approver agents
            // wired in `Hydra::new`.
            | "actor_hydra_verifier"
            | "actor_hydra_prometheus"
            | "actor_hydra_sentinel"
            | "actor_hydra_approver"
            // Built-in micro-model auto-register actors. Each new
            // built-in model adds one entry here.
            | "actor_hydra_commit_rate_model"
            | "actor_hydra_replication_lag_model"
            | "actor_hydra_agent_loop_storm_model"
            | "actor_hydra_action_failure_rate_model"
    )
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
    fn is_hydra_system_actor_recognizes_all_internal_actors() {
        // Patch 18 storm filter — every Hydra-wired internal actor
        // must register so the storm signal reflects non-Hydra
        // activity only. If a future patch wires a new internal
        // actor (e.g., a new model's auto-register actor) and
        // forgets to add it here, that actor's events will show up
        // as agent storm activity. This test catches the omission.
        for actor in [
            "actor_hydra_policy",
            "actor_hydra_trust_gate",
            "actor_hydra_verifier",
            "actor_hydra_prometheus",
            "actor_hydra_sentinel",
            "actor_hydra_approver",
            "actor_hydra_commit_rate_model",
            "actor_hydra_replication_lag_model",
            "actor_hydra_agent_loop_storm_model",
            "actor_hydra_action_failure_rate_model",
        ] {
            assert!(
                is_hydra_system_actor(&ActorId::from_str(actor)),
                "{actor} must be recognized as a Hydra system actor"
            );
        }
    }

    #[test]
    fn is_hydra_system_actor_does_not_match_operator_or_arbitrary_actors() {
        // Real operator actors (alice, ops, etc.) must NOT register
        // — their events are exactly what the storm model is
        // counting.
        assert!(!is_hydra_system_actor(&ActorId::from_str(
            "actor_oncall_alice"
        )));
        assert!(!is_hydra_system_actor(&ActorId::from_str("actor_ops")));
        assert!(!is_hydra_system_actor(&ActorId::from_str(
            "actor_data_quality_agent"
        )));
        // Substring/prefix-match guards.
        assert!(!is_hydra_system_actor(&ActorId::from_str(
            "actor_hydra_policy_admin"
        )));
        assert!(!is_hydra_system_actor(&ActorId::from_str(
            "actor_hydra_external_collaborator"
        )));
    }

    #[test]
    fn is_hydra_system_actor_is_strict_superset_of_automation_actor() {
        // Every automation actor (approvers) must also be a system
        // actor. The inverse is NOT true — verification agent etc.
        // are system actors but not automation actors.
        for actor in [HYDRA_POLICY_AGENT_ACTOR, HYDRA_TRUST_GATE_ACTOR] {
            let a = ActorId::from_str(actor);
            assert!(is_hydra_automation_actor(&a));
            assert!(
                is_hydra_system_actor(&a),
                "system-actor set must be a superset of automation-actor set"
            );
        }
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

    #[test]
    fn accept_correlation_floor_is_eighty() {
        // LOAD-BEARING pin: Patch 45's auto-action gate floor must
        // equal the `TrustLevel::High` band threshold (0.80) AND must
        // sit inside the `High` bucket — drift of either side without
        // an explicit amendment is forbidden. Mirrors the P41
        // `ACCEPT_MATCH_SCORE_FLOOR` discipline.
        assert_eq!(ACCEPT_CORRELATION_FLOOR, 0.80);
        assert_eq!(
            TrustAssessment::level_for_score(ACCEPT_CORRELATION_FLOOR),
            TrustLevel::High
        );
        // Just below the floor must NOT clear High — proves the
        // gate-band relationship is `score >= floor`, not `score >
        // floor`.
        assert_eq!(
            TrustAssessment::level_for_score(ACCEPT_CORRELATION_FLOOR - 0.0001),
            TrustLevel::Medium
        );
    }

    #[test]
    fn correlation_time_proximity_window_is_nine_hundred() {
        // LOAD-BEARING pin: Patch 45's `TimeProximity` reason fires
        // for signal pairs within 900s (15min). A silent widening
        // would make unrelated streams appear correlated; a silent
        // tightening would suppress legitimate ETL → alert chains.
        // Either drift requires a deliberate amendment.
        assert_eq!(CORRELATION_TIME_PROXIMITY_WINDOW_SECS, 900);
        // 15 minutes spelled in seconds — guards against a future
        // accidental unit change (e.g., minutes vs. seconds).
        assert_eq!(CORRELATION_TIME_PROXIMITY_WINDOW_SECS, 15 * 60);
    }
}
