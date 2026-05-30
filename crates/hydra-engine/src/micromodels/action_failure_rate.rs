//! `ActionFailureRateModel` — stateless detector for degrading
//! action delivery. The fourth built-in micro-model (MicroModel
//! Patch 19).
//!
//! ## What it watches
//!
//! Patches 6-15 wired Hydra's outward-acting reflex (propose →
//! approve → execute → outcome). Patch 14 made delivery
//! externally real (real webhook calls). Patch 19 closes the
//! self-health loop: if Hydra's own actions start failing —
//! webhook timeouts, non-2xx responses, receiver errors — the
//! model fires.
//!
//! The model watches a sliding window (default 300s) and counts:
//!
//! - `actions_seen` — actions that reached a terminal execution
//!   state (`ActionExecuted` ∪ `ActionFailed`) in the window.
//! - `failed_actions` — actions that emitted `ActionFailed` in
//!   the window. The Patch 14 delivery adapter emits this on
//!   every non-2xx / timeout / network-error path.
//! - `failure_ratio = failed_actions / actions_seen` (0.0 when
//!   `actions_seen == 0`).
//! - `top_failed_kind` — most-common `ActionKind` among the
//!   failed actions in the window. Looked up by `action_id` in
//!   the engine's action store.
//!
//! ## What it does NOT do (Patch 19 boundary)
//!
//! - No retry / backoff / DLQ. Failure detection only — Notify
//!   only.
//! - No adapter quarantine / disable. Operator judgment in v0.
//! - No EWMA / Z-score. Pure threshold + ratio gates.
//! - No per-tenant scoping. Global signal.
//! - Skips `OutcomeObserved { Failure }` events on purpose —
//!   `ActionFailed` already covers the same failure path one-to-
//!   one; counting both would double-count.
//!
//! ## Pure-function design
//!
//! Same shape as Patches 16 + 18: this module owns the math (the
//! threshold + ratio ladder). The engine wrapper owns the
//! event-log walk + action-store lookup + per-kind tally.

use serde::{Deserialize, Serialize};

/// Anomaly level. Same vocabulary as
/// `ReplicationLagAnomalyLevel` / `AgentLoopStormLevel` — no
/// `WarmingUp` (the model is stateless and answers from the
/// first call).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionFailureRateLevel {
    Normal,
    Warning,
    Critical,
}

impl ActionFailureRateLevel {
    /// Deterministic confidence per level. Matches the other
    /// Patch 16+18 threshold models for cross-model consistency.
    pub fn confidence(&self) -> f64 {
        match self {
            ActionFailureRateLevel::Normal => 0.85,
            ActionFailureRateLevel::Warning => 0.85,
            ActionFailureRateLevel::Critical => 0.95,
        }
    }

    pub fn wire_name(&self) -> &'static str {
        match self {
            ActionFailureRateLevel::Normal => "normal",
            ActionFailureRateLevel::Warning => "warning",
            ActionFailureRateLevel::Critical => "critical",
        }
    }

    pub fn is_actionable(&self) -> bool {
        matches!(
            self,
            ActionFailureRateLevel::Warning | ActionFailureRateLevel::Critical
        )
    }
}

/// Tunable thresholds. `Default::default()` returns the Patch 19
/// approved values — conservative numbers that fire only on
/// genuinely-degraded delivery.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ActionFailureRateConfig {
    pub window_secs: u64,
    /// Minimum `actions_seen` before the failure-RATIO gates are
    /// allowed to fire. Below this, only the absolute failure-
    /// count gates can trigger. Prevents 1-of-1 = 100% false
    /// positives on tiny samples.
    pub min_actions_for_ratio: u64,
    pub warning_failure_count: u64,
    pub critical_failure_count: u64,
    pub warning_failure_ratio: f64,
    pub critical_failure_ratio: f64,
}

impl Default for ActionFailureRateConfig {
    fn default() -> Self {
        Self {
            window_secs: 300,
            min_actions_for_ratio: 5,
            warning_failure_count: 3,
            critical_failure_count: 10,
            warning_failure_ratio: 0.25,
            critical_failure_ratio: 0.50,
        }
    }
}

/// One prediction. Goes verbatim into
/// `MicroModelPrediction.output` via `serde_json::to_value`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionFailureRateOutput {
    pub level: ActionFailureRateLevel,
    pub window_secs: u64,
    pub actions_seen: u64,
    pub failed_actions: u64,
    /// `failed_actions / actions_seen`, or `0.0` when
    /// `actions_seen == 0`. NEVER NaN.
    pub failure_ratio: f64,
    /// Wire form of `Option<String>` — `None` when no actions
    /// failed in the window (in which case the kind question is
    /// undefined). PascalCase wire form (`"Notify"` / `"Backfill"`)
    /// because it mirrors `ActionKind` serde output.
    pub top_failed_kind: Option<String>,
    pub reason: String,
}

/// Stateless threshold + ratio model. Construct via
/// `Default::default()` or `with_config(...)`.
#[derive(Debug, Clone, Default)]
pub struct ActionFailureRateModel {
    config: ActionFailureRateConfig,
}

impl ActionFailureRateModel {
    pub fn with_config(config: ActionFailureRateConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &ActionFailureRateConfig {
        &self.config
    }

    /// Score one observation. Pure: no I/O, no state mutation,
    /// no clock reads. Engine wrapper does the event-log walk +
    /// action-store lookups and passes the tallies in.
    pub fn evaluate_observation(
        &self,
        actions_seen: u64,
        failed_actions: u64,
        top_failed_kind: Option<String>,
    ) -> ActionFailureRateOutput {
        let cfg = &self.config;
        let failure_ratio = if actions_seen == 0 {
            0.0
        } else {
            failed_actions as f64 / actions_seen as f64
        };
        let ratio_eligible = actions_seen >= cfg.min_actions_for_ratio;

        let critical_hit = failed_actions >= cfg.critical_failure_count
            || (ratio_eligible
                && failure_ratio >= cfg.critical_failure_ratio);
        let warning_hit = failed_actions >= cfg.warning_failure_count
            || (ratio_eligible && failure_ratio >= cfg.warning_failure_ratio);

        let level = if critical_hit {
            ActionFailureRateLevel::Critical
        } else if warning_hit {
            ActionFailureRateLevel::Warning
        } else {
            ActionFailureRateLevel::Normal
        };

        let reason = render_reason(
            level,
            cfg,
            actions_seen,
            failed_actions,
            failure_ratio,
            top_failed_kind.as_deref(),
        );

        ActionFailureRateOutput {
            level,
            window_secs: cfg.window_secs,
            actions_seen,
            failed_actions,
            failure_ratio,
            top_failed_kind,
            reason,
        }
    }
}

fn render_reason(
    level: ActionFailureRateLevel,
    cfg: &ActionFailureRateConfig,
    actions_seen: u64,
    failed_actions: u64,
    failure_ratio: f64,
    top_failed_kind: Option<&str>,
) -> String {
    if matches!(level, ActionFailureRateLevel::Normal) {
        return if actions_seen == 0 {
            format!(
                "no actions reached terminal state in {ws}s — delivery healthy by absence",
                ws = cfg.window_secs
            )
        } else {
            format!(
                "{failed_actions} of {actions_seen} actions failed in \
                 {ws}s — within thresholds",
                ws = cfg.window_secs
            )
        };
    }

    let tier = if matches!(level, ActionFailureRateLevel::Critical) {
        "critical"
    } else {
        "warning"
    };
    let kind_phrase = match top_failed_kind {
        Some(k) => format!("; top failed kind {k}"),
        None => String::new(),
    };
    format!(
        "action delivery {tier}: {failed_actions} of {actions_seen} \
         actions failed in {ws}s; failure ratio {pct:.1}%{kind_phrase}",
        ws = cfg.window_secs,
        pct = failure_ratio * 100.0
    )
}

/// Result of `Hydra::evaluate_action_failure_rate_and_propose_claim`.
/// Same envelope shape as Patches 3 / 16 / 18 — the Patch 17
/// spine consumes the same parts shape across all reflex models.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionFailureRateAssessment {
    pub prediction: hydra_core::MicroModelPrediction,
    pub prediction_event_id: hydra_core::EventId,
    pub evidence_id: Option<hydra_core::EvidenceId>,
    pub evidence_event_id: Option<hydra_core::EventId>,
    pub claim_id: Option<hydra_core::ClaimId>,
    pub claim_event_id: Option<hydra_core::EventId>,
    /// Patch 28 — auto-created Reflex CausalCell id (if a claim
    /// was created).
    pub causal_cell_id: Option<hydra_core::CausalCellId>,
    pub level: ActionFailureRateLevel,
}

/// Result of `Hydra::evaluate_action_failure_rate_and_propose_action`.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionFailureRateActionAssessment {
    pub prediction: hydra_core::MicroModelPrediction,
    pub prediction_event_id: hydra_core::EventId,
    pub evidence_id: Option<hydra_core::EvidenceId>,
    pub claim_id: Option<hydra_core::ClaimId>,
    pub claim_event_id: Option<hydra_core::EventId>,
    pub action_ids: Vec<hydra_core::ActionId>,
    /// Patch 28 — auto-created Reflex CausalCell id, populated
    /// AFTER the action is proposed.
    pub causal_cell_id: Option<hydra_core::CausalCellId>,
    pub level: ActionFailureRateLevel,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_patch_19_design_table() {
        let cfg = ActionFailureRateConfig::default();
        assert_eq!(cfg.window_secs, 300);
        assert_eq!(cfg.min_actions_for_ratio, 5);
        assert_eq!(cfg.warning_failure_count, 3);
        assert_eq!(cfg.critical_failure_count, 10);
        assert!((cfg.warning_failure_ratio - 0.25).abs() < 1e-9);
        assert!((cfg.critical_failure_ratio - 0.50).abs() < 1e-9);
    }

    #[test]
    fn normal_when_no_actions_in_window() {
        let model = ActionFailureRateModel::default();
        let out = model.evaluate_observation(0, 0, None);
        assert_eq!(out.level, ActionFailureRateLevel::Normal);
        assert_eq!(out.actions_seen, 0);
        assert_eq!(out.failed_actions, 0);
        assert_eq!(out.failure_ratio, 0.0);
        assert!(out.top_failed_kind.is_none());
        assert!(out.reason.contains("healthy by absence"));
    }

    #[test]
    fn normal_when_failures_under_count_and_ratio() {
        let model = ActionFailureRateModel::default();
        // 100 actions, 2 failed → 2% failure (under 25% warning)
        // and absolute count 2 (under warning_count 3) → Normal.
        let out = model.evaluate_observation(100, 2, Some("Notify".into()));
        assert_eq!(out.level, ActionFailureRateLevel::Normal);
        assert!((out.failure_ratio - 0.02).abs() < 1e-9);
    }

    #[test]
    fn warning_when_absolute_count_crosses_warning() {
        let model = ActionFailureRateModel::default();
        // 100 actions, 3 failed → 3% ratio (well under warning)
        // but absolute count == 3 (== warning_count) → Warning.
        let out = model.evaluate_observation(100, 3, Some("Notify".into()));
        assert_eq!(out.level, ActionFailureRateLevel::Warning);
        assert!(out.reason.contains("warning"));
    }

    #[test]
    fn critical_when_absolute_count_crosses_critical() {
        let model = ActionFailureRateModel::default();
        // 100 actions, 10 failed → 10% ratio (still under critical
        // 50%) but absolute count == 10 (== critical_count) →
        // Critical.
        let out = model.evaluate_observation(100, 10, Some("Notify".into()));
        assert_eq!(out.level, ActionFailureRateLevel::Critical);
        assert!(out.reason.contains("critical"));
    }

    #[test]
    fn critical_via_ratio_when_eligible() {
        let model = ActionFailureRateModel::default();
        // 8 actions, 4 failed → 50% ratio (== critical_ratio) AND
        // actions_seen (8) >= min_actions_for_ratio (5) → Critical
        // via ratio. Absolute count (4) is under critical_count
        // (10), so this isolates the ratio gate.
        let out = model.evaluate_observation(8, 4, Some("Notify".into()));
        assert_eq!(out.level, ActionFailureRateLevel::Critical);
        assert!((out.failure_ratio - 0.5).abs() < 1e-9);
    }

    #[test]
    fn ratio_gate_suppressed_below_min_actions_for_ratio() {
        // 1 action, 1 failed → 100% ratio. But actions_seen (1) <
        // min_actions_for_ratio (5), so the ratio gate is
        // disabled. Absolute count (1) is under warning_count (3),
        // so → Normal. This is the load-bearing
        // small-sample-no-false-positive pin.
        let model = ActionFailureRateModel::default();
        let out = model.evaluate_observation(1, 1, Some("Notify".into()));
        assert_eq!(out.level, ActionFailureRateLevel::Normal);
        // failure_ratio is still computed honestly — 1.0 — just
        // not USED for gating.
        assert!((out.failure_ratio - 1.0).abs() < 1e-9);
    }

    #[test]
    fn ratio_gate_disabled_does_not_block_absolute_count_gate() {
        // 4 actions, 4 failed → 100% ratio. actions_seen (4) <
        // min_actions_for_ratio (5) so ratio is disabled. But
        // absolute count (4) >= warning_count (3) → Warning. The
        // small-sample suppression must NOT block the absolute
        // gate.
        let model = ActionFailureRateModel::default();
        let out = model.evaluate_observation(4, 4, Some("Notify".into()));
        assert_eq!(out.level, ActionFailureRateLevel::Warning);
    }

    #[test]
    fn failure_ratio_is_zero_not_nan_when_actions_seen_zero() {
        // Pin: f64 division by zero in IEEE 754 would produce
        // NaN. The model must clamp to 0.0 so JSON serialization
        // and downstream comparisons stay sane.
        let model = ActionFailureRateModel::default();
        let out = model.evaluate_observation(0, 0, None);
        assert_eq!(out.failure_ratio, 0.0);
        assert!(out.failure_ratio.is_finite());
    }

    #[test]
    fn output_serializes_to_expected_json_shape() {
        // Pin wire fields so a future rename is a deliberate
        // breaking change.
        let model = ActionFailureRateModel::default();
        let out = model.evaluate_observation(20, 8, Some("Notify".into()));
        let value = serde_json::to_value(&out).unwrap();
        let obj = value.as_object().unwrap();
        for key in [
            "level",
            "window_secs",
            "actions_seen",
            "failed_actions",
            "failure_ratio",
            "top_failed_kind",
            "reason",
        ] {
            assert!(obj.contains_key(key), "missing field {key}");
        }
        assert_eq!(obj["level"], serde_json::json!("warning"));
        assert_eq!(obj["actions_seen"], serde_json::json!(20));
        assert_eq!(obj["failed_actions"], serde_json::json!(8));
        assert_eq!(obj["top_failed_kind"], serde_json::json!("Notify"));
    }

    #[test]
    fn top_failed_kind_serializes_to_null_when_absent() {
        let model = ActionFailureRateModel::default();
        let out = model.evaluate_observation(0, 0, None);
        let value = serde_json::to_value(&out).unwrap();
        assert!(value["top_failed_kind"].is_null());
    }

    #[test]
    fn confidence_table_pinned() {
        assert_eq!(ActionFailureRateLevel::Normal.confidence(), 0.85);
        assert_eq!(ActionFailureRateLevel::Warning.confidence(), 0.85);
        assert_eq!(ActionFailureRateLevel::Critical.confidence(), 0.95);
    }

    #[test]
    fn is_actionable_matches_other_threshold_models() {
        assert!(!ActionFailureRateLevel::Normal.is_actionable());
        assert!(ActionFailureRateLevel::Warning.is_actionable());
        assert!(ActionFailureRateLevel::Critical.is_actionable());
    }

    #[test]
    fn with_config_overrides_defaults() {
        let cfg = ActionFailureRateConfig {
            window_secs: 120,
            min_actions_for_ratio: 2,
            warning_failure_count: 1,
            critical_failure_count: 5,
            warning_failure_ratio: 0.10,
            critical_failure_ratio: 0.30,
        };
        let model = ActionFailureRateModel::with_config(cfg);
        // 1 failure → Warning by absolute count.
        let out = model.evaluate_observation(10, 1, Some("Notify".into()));
        assert_eq!(out.level, ActionFailureRateLevel::Warning);
        // 5 of 10 → Critical by absolute count AND ratio.
        let out = model.evaluate_observation(10, 5, Some("Notify".into()));
        assert_eq!(out.level, ActionFailureRateLevel::Critical);
    }
}
