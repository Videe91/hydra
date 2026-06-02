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

use crate::event::Value;
use crate::id::{
    CausalCellId, ClaimId, EvidenceId, IdentityEntityId, TenantId,
};
use crate::trust::{TrustFactor, TrustLevel};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

// === Patch 44 — Correlation Vocabulary =============================
//
// Extends the Patch 43 trust contract with the core SHAPES the
// future correlation engine (P45+) will populate:
//
//   signals → reasons → candidate → trust verdict
//
// CORE-ONLY. No engine logic. No event variants. No CausalCell
// creation. No HTTP. No SDK. No `CorrelationCandidateId` —
// candidates may be ephemeral OR anchored to a future
// `CausalCellKind::Incident` cell; the engine decides in P45.
//
// **Vocabulary safety carries forward from P37 IdentityLinkKind**:
// every `Custom`-bearing enum implements `validate()` that
// rejects empty / sentinel / built-in-collision labels. This
// patch does NOT inherit the P20 / P29 / P30 gap.

/// Kind of signal that participates in a correlation candidate.
/// Covers all of Hydra's primary durable objects plus an
/// `External` escape hatch for future connector signals that
/// haven't yet been mapped to a typed Hydra bridge.
///
/// Wire form: PascalCase strings for built-ins;
/// `{"Custom": "label"}` externally-tagged dict for the open-
/// ended escape hatch. Mirrors `IdentityEntityKind` /
/// `IdentityLinkKind` / `CausalCellKind` exactly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CorrelationSignalKind {
    /// A `Claim` from the epistemic store.
    Claim,
    /// An `Evidence` record.
    Evidence,
    /// A `CausalCell` (incident, reflex, manual story, etc.).
    CausalCell,
    /// An `IdentityEntity` reference (e.g., "the dataset itself
    /// is a signal in this incident").
    IdentityEntity,
    /// An `IdentityLink` edge (e.g., "this `depends_on` edge
    /// recently appeared / activated").
    IdentityLink,
    /// A source-trust-derived signal (e.g., "snowflake source
    /// trust dropped below High at T").
    Source,
    /// A connector signal that hasn't yet been mapped into a
    /// typed Hydra primitive. Engine resolves via the
    /// `metadata` bag on `CorrelationSignalRef` during P45+.
    External,
    /// Open-ended escape hatch. Label MUST pass `validate()`:
    /// non-empty, no reserved sentinels, no built-in
    /// discriminant collision.
    Custom(String),
}

impl CorrelationSignalKind {
    /// snake_case discriminant string. Mirrors
    /// `IdentityLinkKind::discriminant`. Used by future engine
    /// indexes + the wire `?kind=` filter.
    pub fn discriminant(&self) -> String {
        match self {
            Self::Claim => "claim".to_string(),
            Self::Evidence => "evidence".to_string(),
            Self::CausalCell => "causal_cell".to_string(),
            Self::IdentityEntity => "identity_entity".to_string(),
            Self::IdentityLink => "identity_link".to_string(),
            Self::Source => "source".to_string(),
            Self::External => "external".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    /// Validate that this kind is well-formed. `Custom(label)`
    /// must NOT be empty, must NOT collide with reserved
    /// sentinels (`__system__`, `__root__`), and must NOT
    /// collide with a built-in discriminant.
    ///
    /// Mirrors `IdentityLinkKind::validate` exactly — P37
    /// established the pattern as a deliberate carve-out from
    /// the older `IdentityEntityKind` / `CausalCellKind`
    /// non-validation gap. P44 does NOT inherit that gap.
    pub fn validate(&self) -> Result<(), String> {
        let Self::Custom(label) = self else {
            return Ok(());
        };
        if label.is_empty() {
            return Err(
                "custom correlation signal kind label cannot be empty"
                    .to_string(),
            );
        }
        if label == "__system__" || label == "__root__" {
            return Err(format!(
                "custom correlation signal kind label collides with \
                 reserved sentinel: {label}"
            ));
        }
        const BUILTIN_DISCRIMINANTS: &[&str] = &[
            "claim",
            "evidence",
            "causal_cell",
            "identity_entity",
            "identity_link",
            "source",
            "external",
        ];
        if BUILTIN_DISCRIMINANTS.contains(&label.as_str()) {
            return Err(format!(
                "custom correlation signal kind label '{label}' \
                 collides with built-in discriminant"
            ));
        }
        Ok(())
    }
}

/// Reference to one signal participating in a correlation
/// candidate. The `id` field is a free-form `String` because
/// signals may reference any of Hydra's typed ID kinds
/// (`ClaimId`, `EvidenceId`, `CausalCellId`,
/// `IdentityEntityId`, `IdentityLinkId`) OR free-form external
/// strings — the `kind` field disambiguates which store the
/// engine resolves against in P45+.
///
/// The cross-store id arrays (`entity_ids` / `cell_ids` /
/// `claim_ids` / `evidence_ids`) surface auxiliary references
/// the engine extracted from the signal so correlation
/// factors (P45+) can compute without re-walking the stores.
///
/// `observed_at` is `Option` because some signals (e.g., a
/// `CausalCell` summary) don't carry a single timestamp.
/// The `TimeProximity` reason kind fires only when both signals
/// in a pair have `Some(observed_at)`.
///
/// `metadata` convention: keys with prefix `_hydra_` SHOULD be
/// avoided by callers (reserved for future engine use; NOT
/// enforced in v1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelationSignalRef {
    pub kind: CorrelationSignalKind,
    pub id: String,
    pub tenant_id: Option<TenantId>,
    pub observed_at: Option<DateTime<Utc>>,
    pub entity_ids: Vec<IdentityEntityId>,
    pub cell_ids: Vec<CausalCellId>,
    pub claim_ids: Vec<ClaimId>,
    pub evidence_ids: Vec<EvidenceId>,
    pub metadata: HashMap<String, Value>,
}

/// Kind of reason the engine cited for grouping signals into a
/// candidate. Mirrors the factor-list explainability contract
/// (every reason emits, applied OR not) used across P9 / P23 /
/// P30 / P32 / P33 / P35 / P39 / P43.
///
/// `Contradiction` is the only kind expected to carry a
/// NEGATIVE weight in P45+ — the enum itself doesn't encode
/// sign; the engine assigns weight per reason.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CorrelationReasonKind {
    /// Two or more signals reference the SAME `IdentityEntity`.
    SameIdentityEntity,
    /// Two or more signals are connected by a trusted
    /// `IdentityLink` (e.g., `depends_on` between datasets).
    TrustedIdentityLink,
    /// Two or more signals share a `source` (alias source string).
    SameSource,
    /// The shared source carries P35 source-trust ≥ High.
    SourceTrustHigh,
    /// Per-side entity trust ≥ High.
    EntityTrustHigh,
    /// Per-side cell trust ≥ High.
    CellTrustHigh,
    /// Signals fall within a tunable time window.
    TimeProximity,
    /// Aliases / names surface strong semantic resemblance
    /// (P30 score ≥ Strong band).
    SemanticSimilarity,
    /// Claim predicates / objects suggest related propositions.
    ClaimPredicateSimilarity,
    /// Signals point in CONFLICTING directions (e.g., one
    /// claims `is_healthy=true`, another claims `is_healthy=false`).
    /// Expected to carry NEGATIVE weight in P45+; the kind
    /// itself just names the reason.
    Contradiction,
    /// An operator explicitly confirmed the correlation.
    OperatorConfirmed,
    /// Open-ended escape hatch. Label MUST pass `validate()`.
    Custom(String),
}

impl CorrelationReasonKind {
    pub fn discriminant(&self) -> String {
        match self {
            Self::SameIdentityEntity => "same_identity_entity".to_string(),
            Self::TrustedIdentityLink => "trusted_identity_link".to_string(),
            Self::SameSource => "same_source".to_string(),
            Self::SourceTrustHigh => "source_trust_high".to_string(),
            Self::EntityTrustHigh => "entity_trust_high".to_string(),
            Self::CellTrustHigh => "cell_trust_high".to_string(),
            Self::TimeProximity => "time_proximity".to_string(),
            Self::SemanticSimilarity => "semantic_similarity".to_string(),
            Self::ClaimPredicateSimilarity => {
                "claim_predicate_similarity".to_string()
            }
            Self::Contradiction => "contradiction".to_string(),
            Self::OperatorConfirmed => "operator_confirmed".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    /// Validate that this reason kind is well-formed. Same
    /// rules as `CorrelationSignalKind::validate` —
    /// empty / sentinel / built-in-collision rejection on
    /// `Custom(label)`.
    pub fn validate(&self) -> Result<(), String> {
        let Self::Custom(label) = self else {
            return Ok(());
        };
        if label.is_empty() {
            return Err(
                "custom correlation reason kind label cannot be empty"
                    .to_string(),
            );
        }
        if label == "__system__" || label == "__root__" {
            return Err(format!(
                "custom correlation reason kind label collides with \
                 reserved sentinel: {label}"
            ));
        }
        const BUILTIN_DISCRIMINANTS: &[&str] = &[
            "same_identity_entity",
            "trusted_identity_link",
            "same_source",
            "source_trust_high",
            "entity_trust_high",
            "cell_trust_high",
            "time_proximity",
            "semantic_similarity",
            "claim_predicate_similarity",
            "contradiction",
            "operator_confirmed",
        ];
        if BUILTIN_DISCRIMINANTS.contains(&label.as_str()) {
            return Err(format!(
                "custom correlation reason kind label '{label}' \
                 collides with built-in discriminant"
            ));
        }
        Ok(())
    }
}

/// One reason the engine cited for grouping signals into this
/// candidate. Shape mirrors `TrustFactor` — same four fields
/// (`kind`, `weight`, `applied`, `detail`) — but kept as a
/// **distinct type** because the semantic purpose differs:
///
///   `TrustFactor`        — explains TRUST scoring
///   `CorrelationReason`  — explains story GROUPING
///
/// Future patches may unify if a concrete reuse case emerges;
/// v1 keeps them separate for clarity. The engine populates
/// the `applied=false` records too (full explainability
/// contract).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelationReason {
    pub kind: CorrelationReasonKind,
    pub weight: f64,
    pub applied: bool,
    pub detail: String,
}

/// A correlation candidate — a set of signals the future
/// engine believes belong to the same real-world story, with
/// the grouping `reasons`, the `time_window` envelope, the
/// extracted cross-store id arrays, and the **REQUIRED** P43
/// `CorrelationTrustAssessment` attached.
///
/// **NO `id` field in v1.** Candidates may be ephemeral
/// (computed → returned via HTTP → not persisted) OR anchored
/// to a future `CausalCellKind::Incident` (or
/// `Custom("correlation")`) cell at engine time. Deferring
/// the id decision keeps the P45+ engine's hands free.
///
/// **`trust` is REQUIRED, not Option.** This is the load-
/// bearing P43 commitment: a correlation candidate never
/// exists without a trust verdict. The vocabulary-first
/// sequencing of P43 → P44 → P45 prevents "correlation
/// without trust" from being structurally possible.
///
/// ## Tenant isolation
///
/// Correlation candidates are SINGLE-TENANT in v1. Either:
///
///   - `tenant_id == Some(t)` AND every signal has
///     `tenant_id == Some(t)`
///   - `tenant_id == None` AND every signal has
///     `tenant_id == None` (synthetic / admin-only candidates)
///
/// Validated by `validate_tenant_consistency`. Empty signals
/// list is vacuously consistent (P44 doesn't enforce min-
/// signals; the engine does).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelationCandidate {
    pub tenant_id: Option<TenantId>,
    pub signals: Vec<CorrelationSignalRef>,
    pub entity_ids: Vec<IdentityEntityId>,
    pub cell_ids: Vec<CausalCellId>,
    pub time_window_start: Option<DateTime<Utc>>,
    pub time_window_end: Option<DateTime<Utc>>,
    pub reasons: Vec<CorrelationReason>,
    pub trust: CorrelationTrustAssessment,
    pub created_at: DateTime<Utc>,
}

impl CorrelationCandidate {
    /// Validate that every signal's `tenant_id` matches the
    /// candidate's `tenant_id` — strict, including
    /// `None == None`. Empty signals list is vacuously
    /// consistent.
    ///
    /// **LOAD-BEARING tenant rule** carried forward from the
    /// Identity arc: candidates do not cross tenants. The
    /// future engine (P45+) builds candidate sets per-tenant;
    /// this validator catches accidental cross-tenant
    /// construction.
    pub fn validate_tenant_consistency(&self) -> Result<(), String> {
        for (idx, signal) in self.signals.iter().enumerate() {
            if signal.tenant_id != self.tenant_id {
                return Err(format!(
                    "tenant mismatch: candidate tenant_id {:?} but \
                     signals[{idx}].tenant_id {:?}",
                    self.tenant_id, signal.tenant_id
                ));
            }
        }
        Ok(())
    }

    /// Validate that the time window is internally consistent:
    /// when both bounds are `Some`, `start <= end`. Either
    /// bound being `None` is allowed and means "engine didn't
    /// fence by time on this axis."
    pub fn validate_time_window(&self) -> Result<(), String> {
        if let (Some(start), Some(end)) =
            (self.time_window_start, self.time_window_end)
        {
            if start > end {
                return Err(format!(
                    "invalid time window: start {start} > end {end}"
                ));
            }
        }
        Ok(())
    }
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

    // === Patch 44 — Correlation Vocabulary tests ===========

    fn p44_tenant() -> TenantId {
        TenantId::from_str("tenant_p44")
    }

    fn p44_signal(
        kind: CorrelationSignalKind,
        id: &str,
        tenant: Option<TenantId>,
    ) -> CorrelationSignalRef {
        CorrelationSignalRef {
            kind,
            id: id.to_string(),
            tenant_id: tenant,
            observed_at: Some(
                chrono::DateTime::parse_from_rfc3339(
                    "2026-06-02T12:00:00Z",
                )
                .unwrap()
                .with_timezone(&Utc),
            ),
            entity_ids: vec![],
            cell_ids: vec![],
            claim_ids: vec![],
            evidence_ids: vec![],
            metadata: HashMap::new(),
        }
    }

    fn p44_assessment() -> CorrelationTrustAssessment {
        CorrelationTrustAssessment {
            correlation_id: None,
            score: 0.85,
            level: TrustLevel::High,
            strength: CorrelationStrength::Strong,
            explanation: "p44 fixture".to_string(),
            factors: vec![],
            assessed_at: chrono::DateTime::parse_from_rfc3339(
                "2026-06-02T12:00:00Z",
            )
            .unwrap()
            .with_timezone(&Utc),
        }
    }

    fn p44_candidate(
        tenant: Option<TenantId>,
        signals: Vec<CorrelationSignalRef>,
    ) -> CorrelationCandidate {
        CorrelationCandidate {
            tenant_id: tenant,
            signals,
            entity_ids: vec![],
            cell_ids: vec![],
            time_window_start: Some(
                chrono::DateTime::parse_from_rfc3339(
                    "2026-06-02T12:00:00Z",
                )
                .unwrap()
                .with_timezone(&Utc),
            ),
            time_window_end: Some(
                chrono::DateTime::parse_from_rfc3339(
                    "2026-06-02T12:05:00Z",
                )
                .unwrap()
                .with_timezone(&Utc),
            ),
            reasons: vec![],
            trust: p44_assessment(),
            created_at: chrono::DateTime::parse_from_rfc3339(
                "2026-06-02T12:00:00Z",
            )
            .unwrap()
            .with_timezone(&Utc),
        }
    }

    #[test]
    fn correlation_signal_kind_serializes_pascal_case() {
        // Wire form: PascalCase strings for built-ins,
        // externally-tagged `{"Custom": "label"}` for the
        // escape hatch. Mirrors IdentityEntityKind /
        // IdentityLinkKind / CausalCellKind.
        assert_eq!(
            serde_json::to_string(&CorrelationSignalKind::Claim).unwrap(),
            "\"Claim\""
        );
        assert_eq!(
            serde_json::to_string(&CorrelationSignalKind::CausalCell)
                .unwrap(),
            "\"CausalCell\""
        );
        assert_eq!(
            serde_json::to_string(&CorrelationSignalKind::IdentityLink)
                .unwrap(),
            "\"IdentityLink\""
        );
        assert_eq!(
            serde_json::to_string(&CorrelationSignalKind::External)
                .unwrap(),
            "\"External\""
        );
        // Externally-tagged custom.
        assert_eq!(
            serde_json::to_string(&CorrelationSignalKind::Custom(
                "anomaly_burst".to_string()
            ))
            .unwrap(),
            "{\"Custom\":\"anomaly_burst\"}"
        );
        // Round-trip.
        let parsed: CorrelationSignalKind =
            serde_json::from_str("\"Source\"").unwrap();
        assert_eq!(parsed, CorrelationSignalKind::Source);
    }

    #[test]
    fn correlation_signal_kind_discriminant_returns_snake_case() {
        assert_eq!(
            CorrelationSignalKind::Claim.discriminant(),
            "claim"
        );
        assert_eq!(
            CorrelationSignalKind::Evidence.discriminant(),
            "evidence"
        );
        assert_eq!(
            CorrelationSignalKind::CausalCell.discriminant(),
            "causal_cell"
        );
        assert_eq!(
            CorrelationSignalKind::IdentityEntity.discriminant(),
            "identity_entity"
        );
        assert_eq!(
            CorrelationSignalKind::IdentityLink.discriminant(),
            "identity_link"
        );
        assert_eq!(
            CorrelationSignalKind::Source.discriminant(),
            "source"
        );
        assert_eq!(
            CorrelationSignalKind::External.discriminant(),
            "external"
        );
        assert_eq!(
            CorrelationSignalKind::Custom("anomaly_burst".to_string())
                .discriminant(),
            "anomaly_burst"
        );
    }

    #[test]
    fn correlation_signal_kind_custom_rejects_sentinel_label() {
        // Vocabulary safety carries forward from P37: Custom
        // MUST reject empty + sentinel + built-in collisions.
        // P44 inherits this — does NOT inherit the P20/P29/P30
        // gap.
        assert!(CorrelationSignalKind::Custom("".to_string())
            .validate()
            .is_err());
        assert!(
            CorrelationSignalKind::Custom("__system__".to_string())
                .validate()
                .is_err()
        );
        assert!(CorrelationSignalKind::Custom("__root__".to_string())
            .validate()
            .is_err());
        // Built-in discriminant collision.
        assert!(CorrelationSignalKind::Custom("claim".to_string())
            .validate()
            .is_err());
        assert!(CorrelationSignalKind::Custom("causal_cell".to_string())
            .validate()
            .is_err());
        // Built-ins themselves pass.
        assert!(CorrelationSignalKind::Claim.validate().is_ok());
        // Legitimate custom passes.
        assert!(CorrelationSignalKind::Custom(
            "anomaly_burst".to_string()
        )
        .validate()
        .is_ok());
    }

    #[test]
    fn correlation_reason_kind_serializes_pascal_case() {
        assert_eq!(
            serde_json::to_string(
                &CorrelationReasonKind::SameIdentityEntity
            )
            .unwrap(),
            "\"SameIdentityEntity\""
        );
        assert_eq!(
            serde_json::to_string(
                &CorrelationReasonKind::TrustedIdentityLink
            )
            .unwrap(),
            "\"TrustedIdentityLink\""
        );
        assert_eq!(
            serde_json::to_string(&CorrelationReasonKind::Contradiction)
                .unwrap(),
            "\"Contradiction\""
        );
        // Externally-tagged custom.
        assert_eq!(
            serde_json::to_string(&CorrelationReasonKind::Custom(
                "ml_cluster".to_string()
            ))
            .unwrap(),
            "{\"Custom\":\"ml_cluster\"}"
        );
        // Round-trip.
        let parsed: CorrelationReasonKind =
            serde_json::from_str("\"OperatorConfirmed\"").unwrap();
        assert_eq!(parsed, CorrelationReasonKind::OperatorConfirmed);
    }

    #[test]
    fn correlation_reason_kind_discriminant_returns_snake_case() {
        assert_eq!(
            CorrelationReasonKind::SameIdentityEntity.discriminant(),
            "same_identity_entity"
        );
        assert_eq!(
            CorrelationReasonKind::TrustedIdentityLink.discriminant(),
            "trusted_identity_link"
        );
        assert_eq!(
            CorrelationReasonKind::SameSource.discriminant(),
            "same_source"
        );
        assert_eq!(
            CorrelationReasonKind::SourceTrustHigh.discriminant(),
            "source_trust_high"
        );
        assert_eq!(
            CorrelationReasonKind::EntityTrustHigh.discriminant(),
            "entity_trust_high"
        );
        assert_eq!(
            CorrelationReasonKind::CellTrustHigh.discriminant(),
            "cell_trust_high"
        );
        assert_eq!(
            CorrelationReasonKind::TimeProximity.discriminant(),
            "time_proximity"
        );
        assert_eq!(
            CorrelationReasonKind::SemanticSimilarity.discriminant(),
            "semantic_similarity"
        );
        assert_eq!(
            CorrelationReasonKind::ClaimPredicateSimilarity.discriminant(),
            "claim_predicate_similarity"
        );
        assert_eq!(
            CorrelationReasonKind::Contradiction.discriminant(),
            "contradiction"
        );
        assert_eq!(
            CorrelationReasonKind::OperatorConfirmed.discriminant(),
            "operator_confirmed"
        );
        assert_eq!(
            CorrelationReasonKind::Custom("ml_cluster".to_string())
                .discriminant(),
            "ml_cluster"
        );
    }

    #[test]
    fn correlation_reason_kind_custom_rejects_builtin_collision() {
        // Mirrors signal-kind validation; pin each rejection
        // axis on the reason side.
        assert!(CorrelationReasonKind::Custom("".to_string())
            .validate()
            .is_err());
        assert!(
            CorrelationReasonKind::Custom("__system__".to_string())
                .validate()
                .is_err()
        );
        assert!(CorrelationReasonKind::Custom("__root__".to_string())
            .validate()
            .is_err());
        // Each built-in discriminant must be rejected as a
        // custom label.
        for builtin in [
            "same_identity_entity",
            "trusted_identity_link",
            "same_source",
            "source_trust_high",
            "entity_trust_high",
            "cell_trust_high",
            "time_proximity",
            "semantic_similarity",
            "claim_predicate_similarity",
            "contradiction",
            "operator_confirmed",
        ] {
            let err = CorrelationReasonKind::Custom(builtin.to_string())
                .validate();
            assert!(
                err.is_err(),
                "expected reject for built-in collision: {builtin}"
            );
        }
        // Legitimate custom + built-ins pass.
        assert!(CorrelationReasonKind::Custom("ml_cluster".to_string())
            .validate()
            .is_ok());
        assert!(CorrelationReasonKind::SameIdentityEntity.validate().is_ok());
    }

    #[test]
    fn correlation_candidate_serde_round_trip() {
        // Full envelope must round-trip — including REQUIRED
        // trust verdict, time window bounds, signal kinds, and
        // reasons. Pinned so the future P45+ engine wire
        // surface lands without rewriting fixtures.
        let tenant = p44_tenant();
        let signals = vec![
            p44_signal(
                CorrelationSignalKind::Claim,
                "clm_a",
                Some(tenant.clone()),
            ),
            p44_signal(
                CorrelationSignalKind::CausalCell,
                "cell_b",
                Some(tenant.clone()),
            ),
            p44_signal(
                CorrelationSignalKind::Custom("anomaly_burst".to_string()),
                "ext_c",
                Some(tenant.clone()),
            ),
        ];
        let mut candidate = p44_candidate(Some(tenant), signals);
        candidate.reasons = vec![
            CorrelationReason {
                kind: CorrelationReasonKind::SameIdentityEntity,
                weight: 0.30,
                applied: true,
                detail: "all 3 reference ide_revenue".to_string(),
            },
            CorrelationReason {
                kind: CorrelationReasonKind::Contradiction,
                weight: -0.15,
                applied: false,
                detail: "no contradictions detected".to_string(),
            },
        ];

        let json = serde_json::to_string(&candidate).unwrap();
        // Trust is REQUIRED (not Option) — assert it shows up
        // unwrapped in the wire form.
        assert!(json.contains("\"trust\":{"));
        assert!(json.contains("\"strength\":\"Strong\""));
        // PascalCase signal-kind built-in.
        assert!(json.contains("\"Claim\""));
        // Externally-tagged custom signal kind.
        assert!(json.contains("{\"Custom\":\"anomaly_burst\"}"));
        // PascalCase reason-kind built-in.
        assert!(json.contains("\"SameIdentityEntity\""));

        let restored: CorrelationCandidate =
            serde_json::from_str(&json).unwrap();
        assert_eq!(restored, candidate);
    }

    #[test]
    fn correlation_candidate_validates_tenant_consistency() {
        // LOAD-BEARING tenant rule: every signal's tenant_id
        // MUST match the candidate's tenant_id, strict.
        // Empty signals list is vacuously consistent.
        let tenant = p44_tenant();
        let other = TenantId::from_str("tenant_other");

        // All-match: ok.
        let ok = p44_candidate(
            Some(tenant.clone()),
            vec![
                p44_signal(
                    CorrelationSignalKind::Claim,
                    "clm_a",
                    Some(tenant.clone()),
                ),
                p44_signal(
                    CorrelationSignalKind::Evidence,
                    "evd_b",
                    Some(tenant.clone()),
                ),
            ],
        );
        ok.validate_tenant_consistency()
            .expect("matching tenants must validate");

        // One signal in a different tenant: must reject.
        let bad = p44_candidate(
            Some(tenant.clone()),
            vec![
                p44_signal(
                    CorrelationSignalKind::Claim,
                    "clm_a",
                    Some(tenant.clone()),
                ),
                p44_signal(
                    CorrelationSignalKind::Evidence,
                    "evd_b",
                    Some(other.clone()),
                ),
            ],
        );
        let err = bad.validate_tenant_consistency().unwrap_err();
        assert!(
            err.contains("tenant mismatch"),
            "expected tenant mismatch error, got: {err}"
        );

        // Signal None vs candidate Some: also reject (strict).
        let mismatch_none = p44_candidate(
            Some(tenant.clone()),
            vec![p44_signal(
                CorrelationSignalKind::Claim,
                "clm_a",
                None,
            )],
        );
        assert!(
            mismatch_none.validate_tenant_consistency().is_err(),
            "Some/None mismatch must reject"
        );

        // Empty signals list: vacuously consistent.
        let empty = p44_candidate(Some(tenant), vec![]);
        empty.validate_tenant_consistency().expect("empty is vacuous");
    }

    #[test]
    fn correlation_candidate_allows_none_tenant() {
        // tenant_id == None AND every signal tenant_id == None
        // is a valid synthetic/admin-only candidate shape.
        let candidate = p44_candidate(
            None,
            vec![
                p44_signal(CorrelationSignalKind::External, "x_a", None),
                p44_signal(CorrelationSignalKind::External, "x_b", None),
            ],
        );
        candidate
            .validate_tenant_consistency()
            .expect("None tenant + all-None signals is valid");

        // But None candidate with a Some signal must reject —
        // proves the rule is strict, not "default to None if
        // candidate is None".
        let bad = p44_candidate(
            None,
            vec![p44_signal(
                CorrelationSignalKind::External,
                "x_a",
                Some(p44_tenant()),
            )],
        );
        assert!(bad.validate_tenant_consistency().is_err());
    }

    #[test]
    fn correlation_candidate_time_window_must_be_valid() {
        // When both bounds Some, start MUST be <= end.
        // Either bound being None is allowed.
        let tenant = p44_tenant();
        let mut candidate = p44_candidate(Some(tenant.clone()), vec![]);
        // start <= end: ok.
        candidate
            .validate_time_window()
            .expect("start <= end is valid");

        // start > end: reject.
        candidate.time_window_start = Some(
            chrono::DateTime::parse_from_rfc3339(
                "2026-06-02T12:10:00Z",
            )
            .unwrap()
            .with_timezone(&Utc),
        );
        candidate.time_window_end = Some(
            chrono::DateTime::parse_from_rfc3339(
                "2026-06-02T12:00:00Z",
            )
            .unwrap()
            .with_timezone(&Utc),
        );
        let err = candidate.validate_time_window().unwrap_err();
        assert!(
            err.contains("invalid time window"),
            "expected invalid time window error, got: {err}"
        );

        // Either bound None: ok.
        candidate.time_window_start = None;
        candidate.time_window_end = Some(
            chrono::DateTime::parse_from_rfc3339(
                "2026-06-02T12:00:00Z",
            )
            .unwrap()
            .with_timezone(&Utc),
        );
        candidate
            .validate_time_window()
            .expect("None start with Some end is valid");

        candidate.time_window_start = Some(
            chrono::DateTime::parse_from_rfc3339(
                "2026-06-02T12:00:00Z",
            )
            .unwrap()
            .with_timezone(&Utc),
        );
        candidate.time_window_end = None;
        candidate
            .validate_time_window()
            .expect("Some start with None end is valid");

        // Both None: ok.
        candidate.time_window_start = None;
        candidate.time_window_end = None;
        candidate
            .validate_time_window()
            .expect("None/None is valid");
    }
}
