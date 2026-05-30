//! `AgentLoopStormModel` — stateless threshold detector for
//! runaway agent / reflex activity. The third built-in
//! micro-model (MicroModel Patch 18).
//!
//! ## What it watches
//!
//! After Patches 1-17 wired the full reflex loop (model →
//! evidence → claim → action → approval → execution → outcome →
//! observation → trust), the next operational risk is no longer
//! a single metric spike. It's:
//!
//! ```text
//! Hydra or its agents accidentally forming a feedback loop —
//! producing too many self-triggered events, claims, actions,
//! or commits in a short time.
//! ```
//!
//! Patch 18's model watches a sliding window (default 60s) of
//! recent events and counts agent activity per actor. Hydra's
//! own internal actors (cascade, trust-gate, verification agent,
//! built-in model auto-registers, etc.) are filtered out by the
//! engine wrapper using `hydra_core::is_hydra_system_actor` so
//! only external agent / operator activity contributes.
//!
//! ## What it does NOT do (Patch 18 boundary)
//!
//! - No throttle / quarantine / pause action — Notify only.
//!   Throttling agents based on a model verdict is an explicit
//!   operator decision in v0.
//! - No EWMA / Z-score / online baseline. Pure absolute
//!   thresholds. Patch 19+ may upgrade.
//! - No ratio thresholds (e.g. actions_per_event). Patch 18 ships
//!   absolute counts only.
//! - No per-cascade depth scoring. A long cascade and a wide
//!   cascade count identically for v0.
//!
//! ## Pure-function design
//!
//! Same pattern as `replication_lag`: this module owns the math
//! (a small threshold ladder). The engine wrapper owns the
//! event-log walk + actor extraction + per-actor tally. The
//! model gets `(agent_event_count, action_proposed_count,
//! claim_proposed_count, top_actor, top_actor_event_count,
//! window_secs)` and returns a level.

use serde::{Deserialize, Serialize};

/// Anomaly level for the storm detector. Same vocabulary as
/// `ReplicationLagAnomalyLevel` — no `WarmingUp` (the model
/// is stateless and answers from the first call).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLoopStormLevel {
    Normal,
    Warning,
    Critical,
}

impl AgentLoopStormLevel {
    /// Deterministic confidence per level. Pinned by the Patch 18
    /// design table — matches replication-lag's confidence
    /// numbers (both are threshold models with direct inputs).
    pub fn confidence(&self) -> f64 {
        match self {
            AgentLoopStormLevel::Normal => 0.85,
            AgentLoopStormLevel::Warning => 0.85,
            AgentLoopStormLevel::Critical => 0.95,
        }
    }

    pub fn wire_name(&self) -> &'static str {
        match self {
            AgentLoopStormLevel::Normal => "normal",
            AgentLoopStormLevel::Warning => "warning",
            AgentLoopStormLevel::Critical => "critical",
        }
    }

    pub fn is_actionable(&self) -> bool {
        matches!(self, AgentLoopStormLevel::Warning | AgentLoopStormLevel::Critical)
    }
}

/// Tunable thresholds for the storm detector. `Default::default()`
/// returns the Patch 18 approved values — conservative numbers
/// chosen to fire only on clearly anomalous activity. Operators
/// dial down by passing a tighter config to the engine method.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AgentLoopStormConfig {
    pub window_secs: u64,
    /// Total non-Hydra-system events in the window at or above
    /// this triggers `Warning`.
    pub warning_agent_events: u64,
    /// Same total, but for `Critical`.
    pub critical_agent_events: u64,
    /// ActionProposed events in the window at or above this
    /// triggers `Warning`.
    pub warning_actions_proposed: u64,
    pub critical_actions_proposed: u64,
    /// Single-actor event count (the "top actor" tally) at or
    /// above this triggers `Warning`.
    pub same_actor_warning: u64,
    pub same_actor_critical: u64,
}

impl Default for AgentLoopStormConfig {
    fn default() -> Self {
        Self {
            window_secs: 60,
            warning_agent_events: 50,
            critical_agent_events: 200,
            warning_actions_proposed: 10,
            critical_actions_proposed: 50,
            same_actor_warning: 30,
            same_actor_critical: 100,
        }
    }
}

/// One prediction. Goes verbatim into
/// `MicroModelPrediction.output` via `serde_json::to_value`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentLoopStormOutput {
    pub level: AgentLoopStormLevel,
    pub window_secs: u64,
    pub agent_event_count: u64,
    pub action_proposed_count: u64,
    pub claim_proposed_count: u64,
    /// Wire form of `Option<ActorId>` — `None` when no
    /// non-Hydra-system actor had any events in the window.
    pub top_actor: Option<String>,
    pub top_actor_event_count: u64,
    /// Short prose for the prediction's `explanation` field.
    pub reason: String,
}

/// Pure stateless threshold model. Construct via
/// `Default::default()` or `with_config(...)`.
#[derive(Debug, Clone, Default)]
pub struct AgentLoopStormModel {
    config: AgentLoopStormConfig,
}

impl AgentLoopStormModel {
    pub fn with_config(config: AgentLoopStormConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &AgentLoopStormConfig {
        &self.config
    }

    /// Score one observation. Pure: no I/O, no state mutation,
    /// no clock reads. Engine wrapper does the event-log walk
    /// and passes the tallies in.
    pub fn evaluate_observation(
        &self,
        agent_event_count: u64,
        action_proposed_count: u64,
        claim_proposed_count: u64,
        top_actor: Option<String>,
        top_actor_event_count: u64,
    ) -> AgentLoopStormOutput {
        let cfg = &self.config;
        let critical_hit = agent_event_count >= cfg.critical_agent_events
            || action_proposed_count >= cfg.critical_actions_proposed
            || top_actor_event_count >= cfg.same_actor_critical;
        let warning_hit = agent_event_count >= cfg.warning_agent_events
            || action_proposed_count >= cfg.warning_actions_proposed
            || top_actor_event_count >= cfg.same_actor_warning;

        let level = if critical_hit {
            AgentLoopStormLevel::Critical
        } else if warning_hit {
            AgentLoopStormLevel::Warning
        } else {
            AgentLoopStormLevel::Normal
        };

        let reason = render_reason(
            level,
            cfg,
            agent_event_count,
            action_proposed_count,
            claim_proposed_count,
            top_actor.as_deref(),
            top_actor_event_count,
        );

        AgentLoopStormOutput {
            level,
            window_secs: cfg.window_secs,
            agent_event_count,
            action_proposed_count,
            claim_proposed_count,
            top_actor,
            top_actor_event_count,
            reason,
        }
    }
}

fn render_reason(
    level: AgentLoopStormLevel,
    cfg: &AgentLoopStormConfig,
    agent_events: u64,
    actions_proposed: u64,
    claims_proposed: u64,
    top_actor: Option<&str>,
    top_actor_events: u64,
) -> String {
    match level {
        AgentLoopStormLevel::Normal => format!(
            "{agent_events} agent events / {actions_proposed} actions / \
             {claims_proposed} claims in {ws}s — within thresholds",
            ws = cfg.window_secs
        ),
        AgentLoopStormLevel::Warning | AgentLoopStormLevel::Critical => {
            let tier = if matches!(level, AgentLoopStormLevel::Critical) {
                "critical"
            } else {
                "warning"
            };
            let actor_phrase = match top_actor {
                Some(a) if top_actor_events > 0 => format!(
                    "; top actor {a} contributed {top_actor_events} events"
                ),
                _ => String::new(),
            };
            format!(
                "agent loop storm at {tier} level: {agent_events} agent \
                 events / {actions_proposed} actions / {claims_proposed} \
                 claims in {ws}s{actor_phrase}",
                ws = cfg.window_secs
            )
        }
    }
}

/// Result of `Hydra::evaluate_agent_loop_storm_and_propose_claim`.
/// Same envelope shape as Patches 3 + 16 — proves the bridge
/// generalizes (Patch 17 spine consumes the same parts).
#[derive(Debug, Clone, PartialEq)]
pub struct AgentLoopStormAssessment {
    pub prediction: hydra_core::MicroModelPrediction,
    pub prediction_event_id: hydra_core::EventId,
    pub evidence_id: Option<hydra_core::EvidenceId>,
    pub evidence_event_id: Option<hydra_core::EventId>,
    pub claim_id: Option<hydra_core::ClaimId>,
    pub claim_event_id: Option<hydra_core::EventId>,
    pub level: AgentLoopStormLevel,
}

/// Result of `Hydra::evaluate_agent_loop_storm_and_propose_action`.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentLoopStormActionAssessment {
    pub prediction: hydra_core::MicroModelPrediction,
    pub prediction_event_id: hydra_core::EventId,
    pub evidence_id: Option<hydra_core::EvidenceId>,
    pub claim_id: Option<hydra_core::ClaimId>,
    pub claim_event_id: Option<hydra_core::EventId>,
    pub action_ids: Vec<hydra_core::ActionId>,
    pub level: AgentLoopStormLevel,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_patch_18_design_table() {
        let cfg = AgentLoopStormConfig::default();
        assert_eq!(cfg.window_secs, 60);
        assert_eq!(cfg.warning_agent_events, 50);
        assert_eq!(cfg.critical_agent_events, 200);
        assert_eq!(cfg.warning_actions_proposed, 10);
        assert_eq!(cfg.critical_actions_proposed, 50);
        assert_eq!(cfg.same_actor_warning, 30);
        assert_eq!(cfg.same_actor_critical, 100);
    }

    #[test]
    fn normal_when_all_counts_under_thresholds() {
        let model = AgentLoopStormModel::default();
        let out = model.evaluate_observation(10, 2, 3, Some("actor_x".into()), 5);
        assert_eq!(out.level, AgentLoopStormLevel::Normal);
        assert!(out.reason.contains("within thresholds"));
    }

    #[test]
    fn warning_when_total_agent_events_crosses_warning() {
        let model = AgentLoopStormModel::default();
        // Exactly at warning_agent_events = 50 → Warning.
        let out = model.evaluate_observation(50, 0, 0, None, 0);
        assert_eq!(out.level, AgentLoopStormLevel::Warning);
        assert!(out.reason.contains("warning level"));
    }

    #[test]
    fn critical_when_total_agent_events_crosses_critical() {
        let model = AgentLoopStormModel::default();
        let out = model.evaluate_observation(245, 0, 0, None, 0);
        assert_eq!(out.level, AgentLoopStormLevel::Critical);
        assert!(out.reason.contains("critical level"));
    }

    #[test]
    fn critical_when_actions_proposed_crosses_critical_only() {
        // Total events under threshold, but actions alone cross.
        let model = AgentLoopStormModel::default();
        let out = model.evaluate_observation(20, 50, 0, None, 0);
        assert_eq!(out.level, AgentLoopStormLevel::Critical);
    }

    #[test]
    fn critical_when_top_actor_alone_crosses_critical() {
        // Total events and actions under thresholds, but a single
        // actor's count crosses → Critical. This is the
        // "one actor running wild" detection path.
        let model = AgentLoopStormModel::default();
        let out = model.evaluate_observation(
            120, // < critical_agent_events 200 → not by total
            5,   // < critical_actions 50 → not by actions
            5,
            Some("actor_data_quality_agent".into()),
            100, // == same_actor_critical → critical
        );
        assert_eq!(out.level, AgentLoopStormLevel::Critical);
        assert!(out.reason.contains("actor_data_quality_agent"));
    }

    #[test]
    fn warning_via_top_actor_only() {
        let model = AgentLoopStormModel::default();
        let out = model.evaluate_observation(
            10,
            3,
            3,
            Some("actor_chatty".into()),
            30, // == same_actor_warning
        );
        assert_eq!(out.level, AgentLoopStormLevel::Warning);
        assert!(out.reason.contains("actor_chatty"));
    }

    #[test]
    fn output_serializes_to_expected_json_shape() {
        // Pin wire fields so a future rename is a deliberate
        // breaking change.
        let model = AgentLoopStormModel::default();
        let out = model.evaluate_observation(
            5,
            1,
            2,
            Some("actor_a".into()),
            5,
        );
        let value = serde_json::to_value(&out).unwrap();
        let obj = value.as_object().unwrap();
        for key in [
            "level",
            "window_secs",
            "agent_event_count",
            "action_proposed_count",
            "claim_proposed_count",
            "top_actor",
            "top_actor_event_count",
            "reason",
        ] {
            assert!(obj.contains_key(key), "missing field {key}");
        }
        assert_eq!(obj["level"], serde_json::json!("normal"));
        assert_eq!(obj["top_actor"], serde_json::json!("actor_a"));
        assert_eq!(obj["agent_event_count"], serde_json::json!(5));
    }

    #[test]
    fn top_actor_serializes_to_null_when_absent() {
        // None top_actor must serialize as JSON `null` so SDKs can
        // round-trip the Optional through Pydantic cleanly.
        let model = AgentLoopStormModel::default();
        let out = model.evaluate_observation(0, 0, 0, None, 0);
        let value = serde_json::to_value(&out).unwrap();
        assert!(value["top_actor"].is_null());
        assert_eq!(value["top_actor_event_count"], serde_json::json!(0));
    }

    #[test]
    fn confidence_table_pinned() {
        assert_eq!(AgentLoopStormLevel::Normal.confidence(), 0.85);
        assert_eq!(AgentLoopStormLevel::Warning.confidence(), 0.85);
        assert_eq!(AgentLoopStormLevel::Critical.confidence(), 0.95);
    }

    #[test]
    fn is_actionable_matches_other_threshold_models() {
        assert!(!AgentLoopStormLevel::Normal.is_actionable());
        assert!(AgentLoopStormLevel::Warning.is_actionable());
        assert!(AgentLoopStormLevel::Critical.is_actionable());
    }

    #[test]
    fn with_config_overrides_defaults() {
        let cfg = AgentLoopStormConfig {
            window_secs: 30,
            warning_agent_events: 5,
            critical_agent_events: 20,
            warning_actions_proposed: 2,
            critical_actions_proposed: 10,
            same_actor_warning: 3,
            same_actor_critical: 7,
        };
        let model = AgentLoopStormModel::with_config(cfg);
        // 6 events → Warning by total.
        let out = model.evaluate_observation(6, 0, 0, None, 0);
        assert_eq!(out.level, AgentLoopStormLevel::Warning);
        // 7 same-actor → Critical by top-actor.
        let out = model.evaluate_observation(4, 0, 0, Some("a".into()), 7);
        assert_eq!(out.level, AgentLoopStormLevel::Critical);
    }
}
