//! Correlation vocabulary — Patch 43 (trust contract first).
//!
//! Correlation is Hydra's mechanism for grouping signals that
//! belong to the same real-world story across the trusted
//! Identity Graph. Examples:
//!
//! ```text
//!   GitHub change
//!   + dbt failure
//!   + Snowflake anomaly
//!   + dashboard complaint
//!   = RevenuePipelineIncident
//! ```
//!
//! Patch 43 establishes the **TRUST CONTRACT** for correlations
//! BEFORE the correlation engine ships. The principle:
//!
//! ```text
//!   correlation without trust becomes grouping
//!   correlation with trust becomes judgment
//! ```
//!
//! Future correlation engine (P45+) MUST emit verdicts using
//! these types and gate auto-actions on
//! `CorrelationTrustAssessment::level == TrustLevel::High`
//! AND `score >= ACCEPT_CORRELATION_FLOOR` (constant lands
//! with the engine, NOT here — P43 is vocabulary-only).
//!
//! ## Two axes
//!
//! Every `CorrelationTrustAssessment` carries BOTH:
//!
//! - `strength: CorrelationStrength` — how strongly the signals
//!   appear to belong to the same story (Strong / Possible /
//!   Weak / None — same numeric thresholds as `MatchLevel`).
//! - `level: TrustLevel` — how much Hydra trusts the
//!   correlation assessment itself (High / Medium / Low /
//!   Unknown — shared with claim trust + cell trust + identity
//!   trust).
//!
//! These are **INDEPENDENTLY REPRESENTABLE**:
//!
//! ```text
//!   strength = Strong, level = Low   — signals look very
//!                                       related, but the
//!                                       assessment itself is
//!                                       low-confidence (thin
//!                                       evidence, weak sources).
//!   strength = Weak, level = High    — signals look only
//!                                       weakly related, but the
//!                                       assessment is well-
//!                                       grounded — Hydra
//!                                       confidently says "no
//!                                       strong story here".
//! ```
//!
//! Mirrors the P32 `IdentityMatchTrustAssessment` two-axis
//! pattern (`match_level` + `level`) — vocabulary-wide
//! consistency across Hydra's trust dashboards.
//!
//! ## v1 correlation trust will eventually consider
//!
//! - Same canonical `IdentityEntity` references across signals
//! - Trusted `IdentityLink` relationships (depends_on,
//!   downstream_of, owned_by, produced_by, ...)
//! - Per-side source trust (`assess_source_trust`)
//! - Per-side entity trust (`assess_identity_entity_trust`)
//! - Per-side cell trust (`assess_causal_cell_trust`)
//! - Time proximity (signals within a tunable window)
//! - Semantic match strength
//! - Claim predicate similarity
//! - Contradictions (signals that point in conflicting
//!   directions weaken correlation trust)
//! - Operator confirmation (explicit human signal)
//!
//! Patch 43 defines the vocabulary; later patches add the
//! engine logic that computes these factors.
//!
//! ## Suggestion-only contract
//!
//! Correlation trust is **suggestion-only**. Weights are
//! calibrated for **explainability, NOT correctness**. False
//! positives are expected — many signals "near each other in
//! time and entity space" are coincidence rather than causal
//! relation. Operators must judge each correlated story.
//!
//! Any future auto-action (auto-create incident cell, auto-
//! notify owners, auto-escalate) MUST add a separate gate,
//! require `TrustLevel::High` + a minimum score floor, AND
//! emit a durable audit event. The correlation engine MUST NOT
//! become untrusted grouping — that is exactly the failure
//! mode this patch's vocabulary-first sequencing prevents.
//!
//! ## Boundary
//!
//! Patch 43 ships ONLY the core types. NO engine logic, NO
//! HTTP, NO SDK, NO constants (like `ACCEPT_CORRELATION_FLOOR`),
//! NO event variants, NO CausalCell creation, NO trust
//! persistence, NO auto-actions.

use crate::id::CausalCellId;
use crate::trust::{TrustFactor, TrustLevel};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How strongly Hydra believes a set of signals belong to the
/// same real-world story.
///
/// Distinct vocabulary from `TrustLevel` (which judges the
/// assessment itself) and `MatchLevel` (which judges
/// name-resemblance). Shares numeric thresholds with both via
/// `level_for_score` for operator UI consistency.
///
/// Wire form: PascalCase strings (`"Strong"`, `"Possible"`,
/// `"Weak"`, `"None"`). **Note**: the `"None"` value is a
/// STRING, NOT Python `None` — same gotcha as `MatchLevel` (a
/// future SDK patch must document this carefully).
///
/// **Adopts `Possible` not `Moderate`** for Hydra-wide
/// vocabulary consistency with `MatchLevel::Possible`. Pinned
/// by `correlation_strength_uses_possible_not_moderate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CorrelationStrength {
    /// Score ≥ 0.80. Signals are very likely the same story.
    Strong,
    /// Score ≥ 0.50. Operator should compare. Adopts the
    /// `Possible` lexicon from `MatchLevel` for Hydra-wide
    /// vocabulary consistency (NOT `Moderate`).
    Possible,
    /// Score ≥ 0.20. Weak signal — usually a coincidence
    /// driven by shared tokens or near-time co-occurrence.
    Weak,
    /// Score < 0.20. Effectively no correlation.
    None,
}

impl CorrelationStrength {
    /// Bucket a clamped `[0.0, 1.0]` score into a
    /// `CorrelationStrength`. Uses the SAME numeric thresholds
    /// as `MatchLevel::level_for_score` AND
    /// `TrustAssessment::level_for_score` so operators see a
    /// consistent scale across all Hydra trust dashboards.
    ///
    /// LOAD-BEARING: vocabulary consistency. Pinned by
    /// `correlation_strength_uses_match_level_thresholds`.
    pub fn level_for_score(score: f64) -> CorrelationStrength {
        if score >= 0.80 {
            CorrelationStrength::Strong
        } else if score >= 0.50 {
            CorrelationStrength::Possible
        } else if score >= 0.20 {
            CorrelationStrength::Weak
        } else {
            CorrelationStrength::None
        }
    }
}

/// Trust verdict over a correlation candidate or assembled
/// correlation cell. Two-axis (mirrors P32 pattern):
///
/// - `strength: CorrelationStrength` — how strongly the
///   underlying signals look like the same story
/// - `level: TrustLevel` — how much Hydra trusts THIS
///   correlation assessment
///
/// Independently representable: Strong/Low and Weak/High are
/// both valid states.
///
/// ## Field semantics
///
/// - `correlation_id` — Optional anchor to a durable
///   `CausalCellKind::Incident` (or `Custom("correlation")`)
///   cell that holds the correlated signals. `None` for
///   synthetic candidates or test fixtures. P45+ engine
///   populates this when correlation grouping ships.
/// - `score` — P43+ trust score, clamped to `[0.0, 1.0]`. Sum
///   of applied factor weights, clamped. Maximum reachable
///   ceiling is engine-dependent (P45 defines factor weights).
/// - `level` — `TrustLevel` bucket via
///   `TrustAssessment::level_for_score` (≥0.80 High, ≥0.50
///   Medium, ≥0.20 Low, else Unknown — shared with all other
///   Hydra trust verdicts).
/// - `strength` — `CorrelationStrength` bucket via
///   `CorrelationStrength::level_for_score` (≥0.80 Strong,
///   ≥0.50 Possible, ≥0.20 Weak, else None — shared with
///   `MatchLevel`).
/// - `explanation` — short prose summary for operator
///   dashboards. The correlation engine must include the
///   structural-only warning so future maintainers see the v1
///   contract without parsing the docstring.
/// - `factors` — ALL evaluated factors (applied AND unapplied
///   — same explainability contract as every other Hydra
///   trust assessment). Reuses `TrustFactor` — no new
///   `CorrelationFactor` type by design (the user's
///   instinct was correct: factor shape is universal across
///   Hydra trust verdicts).
/// - `assessed_at` — wall-clock at compute.
///
/// ## Strategic warning carry-forward
///
/// **Suggestion-only.** Weights calibrated for explainability,
/// NOT correctness. False positives expected. Auto-actions MUST
/// compose with semantic validation, separate trust gates,
/// operator approval, AND a durable audit event. See module
/// docstring for the full v1 contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelationTrustAssessment {
    pub correlation_id: Option<CausalCellId>,
    pub score: f64,
    pub level: TrustLevel,
    pub strength: CorrelationStrength,
    pub explanation: String,
    pub factors: Vec<TrustFactor>,
    pub assessed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::TrustAssessment;

    fn sample_assessment() -> CorrelationTrustAssessment {
        CorrelationTrustAssessment {
            correlation_id: Some(CausalCellId::from_str("cell_p43_sample")),
            score: 0.80,
            level: TrustLevel::High,
            strength: CorrelationStrength::Strong,
            explanation: "Sample correlation: 3 signals share \
                          identity entities + within 5min window."
                .to_string(),
            factors: vec![
                TrustFactor {
                    kind: "same_identity_entity".to_string(),
                    weight: 0.30,
                    applied: true,
                    detail: "all 3 signals reference ide_revenue_daily"
                        .to_string(),
                },
                TrustFactor {
                    kind: "time_proximity_high".to_string(),
                    weight: 0.20,
                    applied: true,
                    detail: "max delta 4min37s (≤ 5min window)"
                        .to_string(),
                },
                TrustFactor {
                    kind: "operator_confirmation".to_string(),
                    weight: 0.15,
                    applied: false,
                    detail: "no operator confirmation".to_string(),
                },
            ],
            assessed_at: chrono::DateTime::parse_from_rfc3339(
                "2026-06-02T12:00:00Z",
            )
            .unwrap()
            .with_timezone(&Utc),
        }
    }

    #[test]
    fn correlation_strength_for_score_thresholds_pinned() {
        // Exact thresholds: 0.80 / 0.50 / 0.20 → Strong /
        // Possible / Weak / None. Edge cases pinned —
        // immediately-below-threshold scores fall into the
        // next band.
        assert_eq!(
            CorrelationStrength::level_for_score(1.0),
            CorrelationStrength::Strong
        );
        assert_eq!(
            CorrelationStrength::level_for_score(0.80),
            CorrelationStrength::Strong
        );
        assert_eq!(
            CorrelationStrength::level_for_score(0.799),
            CorrelationStrength::Possible
        );
        assert_eq!(
            CorrelationStrength::level_for_score(0.50),
            CorrelationStrength::Possible
        );
        assert_eq!(
            CorrelationStrength::level_for_score(0.499),
            CorrelationStrength::Weak
        );
        assert_eq!(
            CorrelationStrength::level_for_score(0.20),
            CorrelationStrength::Weak
        );
        assert_eq!(
            CorrelationStrength::level_for_score(0.199),
            CorrelationStrength::None
        );
        assert_eq!(
            CorrelationStrength::level_for_score(0.0),
            CorrelationStrength::None
        );
    }

    #[test]
    fn correlation_strength_uses_match_level_thresholds() {
        // LOAD-BEARING vocabulary consistency: the threshold
        // table MUST be identical across MatchLevel,
        // CorrelationStrength, and TrustAssessment::level_for_score.
        // Iterate a spread of scores and confirm parallel
        // bucketing.
        use crate::identity::MatchLevel;
        for score in [0.0_f64, 0.10, 0.20, 0.35, 0.50, 0.65, 0.80, 0.95, 1.0]
        {
            let cs = CorrelationStrength::level_for_score(score);
            let ml = MatchLevel::level_for_score(score);
            let tl = TrustAssessment::level_for_score(score);
            // Strong ↔ Strong ↔ High share the same band.
            // Possible ↔ Possible ↔ Medium.
            // Weak ↔ Weak ↔ Low.
            // None ↔ None ↔ Unknown.
            let cs_band = match cs {
                CorrelationStrength::Strong => 3,
                CorrelationStrength::Possible => 2,
                CorrelationStrength::Weak => 1,
                CorrelationStrength::None => 0,
            };
            let ml_band = match ml {
                MatchLevel::Strong => 3,
                MatchLevel::Possible => 2,
                MatchLevel::Weak => 1,
                MatchLevel::None => 0,
            };
            let tl_band = match tl {
                TrustLevel::High => 3,
                TrustLevel::Medium => 2,
                TrustLevel::Low => 1,
                TrustLevel::Unknown => 0,
            };
            assert_eq!(
                cs_band, ml_band,
                "CorrelationStrength and MatchLevel must share thresholds; \
                 score={score} cs={cs:?} ml={ml:?}"
            );
            assert_eq!(
                cs_band, tl_band,
                "CorrelationStrength and TrustLevel must share thresholds; \
                 score={score} cs={cs:?} tl={tl:?}"
            );
        }
    }

    #[test]
    fn correlation_strength_serializes_pascal_case() {
        // Wire form pin: bare PascalCase strings. The "None"
        // value is a STRING — future SDK MatchLevel-style
        // gotcha carries forward.
        assert_eq!(
            serde_json::to_string(&CorrelationStrength::Strong).unwrap(),
            "\"Strong\""
        );
        assert_eq!(
            serde_json::to_string(&CorrelationStrength::Possible).unwrap(),
            "\"Possible\""
        );
        assert_eq!(
            serde_json::to_string(&CorrelationStrength::Weak).unwrap(),
            "\"Weak\""
        );
        assert_eq!(
            serde_json::to_string(&CorrelationStrength::None).unwrap(),
            "\"None\""
        );
        // Round-trip.
        let parsed: CorrelationStrength =
            serde_json::from_str("\"Possible\"").unwrap();
        assert_eq!(parsed, CorrelationStrength::Possible);
    }

    #[test]
    fn correlation_strength_uses_possible_not_moderate() {
        // LOAD-BEARING: the Possible variant exists (mirrors
        // MatchLevel::Possible) — drift back to "Moderate"
        // would fork Hydra's trust vocabulary for no semantic
        // gain. This test asserts the variant binding at
        // compile time; any future rename to Moderate would
        // fail to compile here.
        let _possible = CorrelationStrength::Possible;
        let _strong = CorrelationStrength::Strong;
        let _weak = CorrelationStrength::Weak;
        let _none = CorrelationStrength::None;
        // Also exercise the level_for_score path: a sub-Strong
        // score (>= 0.50, < 0.80) MUST return Possible — never
        // a hypothetical Moderate variant.
        assert_eq!(
            CorrelationStrength::level_for_score(0.65),
            CorrelationStrength::Possible,
            "sub-Strong band must bucket to Possible (NOT Moderate)"
        );
    }

    #[test]
    fn correlation_trust_assessment_serde_round_trip() {
        // Full envelope must round-trip through serde. Pinned
        // so the future P44+ engine wire surface lands without
        // rewriting fixtures. Includes correlation_id: Some(...),
        // applied + unapplied factors (explainability), and
        // PascalCase level/strength.
        let assessment = sample_assessment();
        let json = serde_json::to_string(&assessment).unwrap();
        assert!(json.contains("\"level\":\"High\""));
        assert!(json.contains("\"strength\":\"Strong\""));
        assert!(json.contains("\"correlation_id\":\"cell_p43_sample\""));
        let restored: CorrelationTrustAssessment =
            serde_json::from_str(&json).unwrap();
        assert_eq!(restored, assessment);

        // Also pin None correlation_id round-trips.
        let mut no_id = assessment;
        no_id.correlation_id = None;
        let json2 = serde_json::to_string(&no_id).unwrap();
        let restored2: CorrelationTrustAssessment =
            serde_json::from_str(&json2).unwrap();
        assert_eq!(restored2, no_id);
        assert!(restored2.correlation_id.is_none());
    }

    #[test]
    fn correlation_trust_assessment_two_axes_independent() {
        // LOAD-BEARING two-axis contract: `strength` and
        // `level` are INDEPENDENTLY representable. Pin all
        // four corners of the 2x2 to prevent any future
        // refactor from collapsing them.
        let combos = [
            (CorrelationStrength::Strong, TrustLevel::High),
            (CorrelationStrength::Strong, TrustLevel::Low),
            (CorrelationStrength::Weak, TrustLevel::High),
            (CorrelationStrength::Weak, TrustLevel::Low),
            (CorrelationStrength::None, TrustLevel::High),
        ];
        for (strength, level) in combos {
            let mut a = sample_assessment();
            a.strength = strength;
            a.level = level;
            // Serde survives the combo.
            let json = serde_json::to_string(&a).unwrap();
            let restored: CorrelationTrustAssessment =
                serde_json::from_str(&json).unwrap();
            assert_eq!(restored.strength, strength);
            assert_eq!(restored.level, level);
        }
    }
}
