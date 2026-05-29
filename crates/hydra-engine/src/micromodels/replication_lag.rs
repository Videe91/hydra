//! `ReplicationLagAnomalyModel` — threshold detector over a peer's
//! replication lag + heartbeat freshness. The **second** built-in
//! micro-model (MicroModel Patch 16).
//!
//! Patch 16 exists to prove the reflex stack is GENERAL — not
//! specialized to commit-rate. The same vocabulary (prediction →
//! evidence → claim → action) and the same auxiliary infrastructure
//! (registry, evaluation HTTP surface, trust assessment, approval/
//! execution/auto-approval) accept this model with no architectural
//! changes. Patch 17 may then extract the shared abstraction; until
//! then the parallel structure is the proof.
//!
//! ## What it watches
//!
//! One follower at a time:
//!
//! - `lag_commits` — how many commits behind the leader the
//!   follower currently is, taken from `peer.last_lag.lag_commits`.
//! - `stale_heartbeat` — whether the most recent lag observation
//!   is older than `stale_heartbeat_after_secs`. A follower that
//!   stopped reporting is at least as serious as one reporting a
//!   high lag.
//!
//! Thresholds (in `ReplicationLagAnomalyConfig`):
//!
//! ```text
//! lag_commits >= critical_lag_commits  → Critical
//! lag_commits >= warning_lag_commits   → Warning
//! stale_heartbeat == true              → Critical (overrides)
//! otherwise                            → Normal
//! ```
//!
//! ## Pure-function design
//!
//! Same shape as `CommitRateAnomalyModel`: the model owns the math
//! (a small threshold ladder); the engine wrapper owns the data
//! lookup (read peer, compute heartbeat freshness, build the
//! prediction, record events). No state on the model — replication
//! lag does not need an online baseline.
//!
//! ## What it does NOT do (Patch 16 boundary)
//!
//! - No background scheduler.
//! - No per-tenant fan-out (the route walks one peer at a time).
//! - No throttling action on Critical — the action is still
//!   `Notify` only. Future patches may add `quarantine_peer`,
//!   `pause_writes_to_peer`, etc.
//! - No re-use of approval/execution/trust/auto-approval code —
//!   they already exist; the action surfaces by the same
//!   `ActionStatus::Proposed → Approved → Executed` lifecycle.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Anomaly level returned with every prediction. Serialized as
/// snake_case so `level: "critical"` reads naturally in JSON.
///
/// **Difference from `commit_rate::AnomalyLevel`**: no `WarmingUp`.
/// Replication lag is a snapshot quantity — there is no online
/// baseline to converge, no warmup samples to absorb. The model
/// answers from the first call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationLagAnomalyLevel {
    Normal,
    Warning,
    Critical,
}

impl ReplicationLagAnomalyLevel {
    /// Deterministic confidence per level. Pinned by the Patch 16
    /// design table so downstream callers can rely on these.
    /// Higher than commit-rate's warmup-suppressed numbers because
    /// the inputs are direct (no statistical inference required).
    pub fn confidence(&self) -> f64 {
        match self {
            ReplicationLagAnomalyLevel::Normal => 0.85,
            ReplicationLagAnomalyLevel::Warning => 0.85,
            ReplicationLagAnomalyLevel::Critical => 0.95,
        }
    }

    /// Stable snake_case wire string. Same role as
    /// `commit_rate::AnomalyLevel::wire_name` — lets the bridge
    /// stash the level in a typed `Value::String` without going
    /// through serde_json.
    pub fn wire_name(&self) -> &'static str {
        match self {
            ReplicationLagAnomalyLevel::Normal => "normal",
            ReplicationLagAnomalyLevel::Warning => "warning",
            ReplicationLagAnomalyLevel::Critical => "critical",
        }
    }

    /// True for levels that warrant downstream action — Warning or
    /// Critical. The Patch 16 bridge fires Evidence + Claim only
    /// when this returns `true`.
    pub fn is_actionable(&self) -> bool {
        matches!(
            self,
            ReplicationLagAnomalyLevel::Warning
                | ReplicationLagAnomalyLevel::Critical
        )
    }
}

/// Tunable thresholds for the replication-lag detector.
///
/// `Default::default()` returns the Patch 16 approved values.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ReplicationLagAnomalyConfig {
    /// `lag_commits` at or above this triggers `Warning`.
    pub warning_lag_commits: u64,
    /// `lag_commits` at or above this triggers `Critical`. Must be
    /// `>= warning_lag_commits` — enforced at construction time
    /// (see `with_thresholds`).
    pub critical_lag_commits: u64,
    /// Seconds of silence (no lag observation) after which the
    /// follower is treated as un-heartbeating and the model emits
    /// `Critical` regardless of last-known lag.
    pub stale_heartbeat_after_secs: u64,
}

impl Default for ReplicationLagAnomalyConfig {
    fn default() -> Self {
        Self {
            warning_lag_commits: 10,
            critical_lag_commits: 100,
            stale_heartbeat_after_secs: 60,
        }
    }
}

/// One prediction. Goes verbatim into
/// `MicroModelPrediction.output` via `serde_json::to_value`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplicationLagAnomalyOutput {
    pub level: ReplicationLagAnomalyLevel,
    /// Lag observed at evaluation time, in commits.
    pub lag_commits: u64,
    /// True iff the most recent observation is older than
    /// `stale_heartbeat_after_secs`. When true, `level` is
    /// `Critical` regardless of lag_commits.
    pub stale_heartbeat: bool,
    /// Short prose for the prediction's `explanation` field.
    /// Stable format across calls so agents can pattern-match.
    pub reason: String,
}

/// Pure threshold model. No state. Construct via
/// `Default::default()` (default thresholds) or `with_config(...)`
/// for explicit tuning.
#[derive(Debug, Clone, Default)]
pub struct ReplicationLagAnomalyModel {
    config: ReplicationLagAnomalyConfig,
}

impl ReplicationLagAnomalyModel {
    pub fn with_config(config: ReplicationLagAnomalyConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &ReplicationLagAnomalyConfig {
        &self.config
    }

    /// Score one observation. Pure: no I/O, no state mutation, no
    /// clock reads — `now` and the peer-side observations come in
    /// as arguments. `last_observed_at == None` means the peer has
    /// never reported a lag, which counts as stale.
    pub fn evaluate_observation(
        &self,
        now: DateTime<Utc>,
        lag_commits: u64,
        last_observed_at: Option<DateTime<Utc>>,
    ) -> ReplicationLagAnomalyOutput {
        let stale_heartbeat = match last_observed_at {
            None => true,
            Some(ts) => {
                let elapsed = now.signed_duration_since(ts).num_seconds();
                // `signed_duration_since` is negative if `ts > now`
                // (clock skew). Treat that as "fresh" — only the
                // forward direction counts as stale.
                elapsed > self.config.stale_heartbeat_after_secs as i64
            }
        };

        let level = if stale_heartbeat {
            // Stale heartbeat OVERRIDES lag count: a silent
            // follower is at least as serious as a high-lag one.
            ReplicationLagAnomalyLevel::Critical
        } else if lag_commits >= self.config.critical_lag_commits {
            ReplicationLagAnomalyLevel::Critical
        } else if lag_commits >= self.config.warning_lag_commits {
            ReplicationLagAnomalyLevel::Warning
        } else {
            ReplicationLagAnomalyLevel::Normal
        };

        let reason = render_reason(
            level,
            lag_commits,
            stale_heartbeat,
            self.config.warning_lag_commits,
            self.config.critical_lag_commits,
            self.config.stale_heartbeat_after_secs,
        );

        ReplicationLagAnomalyOutput {
            level,
            lag_commits,
            stale_heartbeat,
            reason,
        }
    }
}

fn render_reason(
    level: ReplicationLagAnomalyLevel,
    lag_commits: u64,
    stale_heartbeat: bool,
    warning_lag_commits: u64,
    critical_lag_commits: u64,
    stale_heartbeat_after_secs: u64,
) -> String {
    if stale_heartbeat {
        return format!(
            "replication heartbeat stale: no observation in last {stale_heartbeat_after_secs}s"
        );
    }
    match level {
        ReplicationLagAnomalyLevel::Normal => format!(
            "replication lag {lag_commits} commits within warning threshold {warning_lag_commits}"
        ),
        ReplicationLagAnomalyLevel::Warning => format!(
            "replication lag {lag_commits} commits exceeds warning threshold {warning_lag_commits}"
        ),
        ReplicationLagAnomalyLevel::Critical => format!(
            "replication lag {lag_commits} commits exceeds critical threshold {critical_lag_commits}"
        ),
    }
}

/// Result of `Hydra::evaluate_replication_lag_anomaly_and_propose_claim`
/// (MicroModel Patch 16). Same shape as
/// `CommitRateAnomalyAssessment` — proves the bridge return type
/// generalizes across models. Includes `peer_id` so callers don't
/// have to re-derive it.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplicationLagAnomalyAssessment {
    pub prediction: hydra_core::MicroModelPrediction,
    pub prediction_event_id: hydra_core::EventId,
    pub evidence_id: Option<hydra_core::EvidenceId>,
    pub evidence_event_id: Option<hydra_core::EventId>,
    pub claim_id: Option<hydra_core::ClaimId>,
    pub claim_event_id: Option<hydra_core::EventId>,
    pub level: ReplicationLagAnomalyLevel,
    pub peer_id: hydra_core::ReplicaId,
}

/// Result of `Hydra::evaluate_replication_lag_anomaly_and_propose_action`
/// (MicroModel Patch 16). Mirrors the commit-rate action assessment.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplicationLagAnomalyActionAssessment {
    pub prediction: hydra_core::MicroModelPrediction,
    pub prediction_event_id: hydra_core::EventId,
    pub evidence_id: Option<hydra_core::EvidenceId>,
    pub claim_id: Option<hydra_core::ClaimId>,
    pub claim_event_id: Option<hydra_core::EventId>,
    pub action_ids: Vec<hydra_core::ActionId>,
    pub level: ReplicationLagAnomalyLevel,
    pub peer_id: hydra_core::ReplicaId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn at(seconds_offset: i64) -> DateTime<Utc> {
        let base = chrono::DateTime::parse_from_rfc3339("2026-05-29T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        base + Duration::seconds(seconds_offset)
    }

    #[test]
    fn defaults_match_patch_16_design_table() {
        let cfg = ReplicationLagAnomalyConfig::default();
        assert_eq!(cfg.warning_lag_commits, 10);
        assert_eq!(cfg.critical_lag_commits, 100);
        assert_eq!(cfg.stale_heartbeat_after_secs, 60);
    }

    #[test]
    fn normal_when_lag_under_warning_threshold_and_heartbeat_fresh() {
        let model = ReplicationLagAnomalyModel::default();
        let out = model.evaluate_observation(at(0), 5, Some(at(-10)));
        assert_eq!(out.level, ReplicationLagAnomalyLevel::Normal);
        assert!(!out.stale_heartbeat);
        assert_eq!(out.lag_commits, 5);
        assert!(out.reason.contains("within warning threshold"));
    }

    #[test]
    fn warning_when_lag_crosses_warning_threshold() {
        let model = ReplicationLagAnomalyModel::default();
        // Exactly at warning_lag_commits = 10 → Warning (inclusive).
        let out = model.evaluate_observation(at(0), 10, Some(at(-10)));
        assert_eq!(out.level, ReplicationLagAnomalyLevel::Warning);
        assert_eq!(out.lag_commits, 10);
        assert!(out.reason.contains("exceeds warning threshold"));
    }

    #[test]
    fn critical_when_lag_crosses_critical_threshold() {
        let model = ReplicationLagAnomalyModel::default();
        // Exactly at critical_lag_commits = 100 → Critical.
        let out = model.evaluate_observation(at(0), 100, Some(at(-10)));
        assert_eq!(out.level, ReplicationLagAnomalyLevel::Critical);
        assert!(out.reason.contains("exceeds critical threshold"));

        // Well above critical → still Critical.
        let high = model.evaluate_observation(at(0), 500, Some(at(-10)));
        assert_eq!(high.level, ReplicationLagAnomalyLevel::Critical);
        assert_eq!(high.lag_commits, 500);
    }

    #[test]
    fn stale_heartbeat_overrides_low_lag_to_critical() {
        // Last observation 120s ago > default 60s → stale → Critical
        // even though lag_commits is zero.
        let model = ReplicationLagAnomalyModel::default();
        let out = model.evaluate_observation(at(0), 0, Some(at(-120)));
        assert_eq!(out.level, ReplicationLagAnomalyLevel::Critical);
        assert!(out.stale_heartbeat);
        assert!(out.reason.contains("heartbeat stale"));
    }

    #[test]
    fn never_observed_peer_is_stale() {
        let model = ReplicationLagAnomalyModel::default();
        let out = model.evaluate_observation(at(0), 0, None);
        assert_eq!(out.level, ReplicationLagAnomalyLevel::Critical);
        assert!(out.stale_heartbeat);
    }

    #[test]
    fn clock_skew_future_timestamp_counts_as_fresh() {
        // Last observation 10s in the future (peer clock ahead of
        // ours). Treat as fresh — only forward drift counts as
        // stale. Lag is small so we should see Normal.
        let model = ReplicationLagAnomalyModel::default();
        let out = model.evaluate_observation(at(0), 0, Some(at(10)));
        assert_eq!(out.level, ReplicationLagAnomalyLevel::Normal);
        assert!(!out.stale_heartbeat);
    }

    #[test]
    fn confidence_table_pinned() {
        assert_eq!(
            ReplicationLagAnomalyLevel::Normal.confidence(),
            0.85
        );
        assert_eq!(
            ReplicationLagAnomalyLevel::Warning.confidence(),
            0.85
        );
        assert_eq!(
            ReplicationLagAnomalyLevel::Critical.confidence(),
            0.95
        );
    }

    #[test]
    fn is_actionable_matches_commit_rate_semantics() {
        // Warning + Critical → actionable; Normal → not.
        assert!(!ReplicationLagAnomalyLevel::Normal.is_actionable());
        assert!(ReplicationLagAnomalyLevel::Warning.is_actionable());
        assert!(ReplicationLagAnomalyLevel::Critical.is_actionable());
    }

    #[test]
    fn output_serializes_to_expected_json_shape() {
        // The output struct goes verbatim into
        // MicroModelPrediction.output via serde_json::to_value.
        // Pin the wire shape so a future field rename is a
        // deliberate breaking change.
        let model = ReplicationLagAnomalyModel::default();
        let out = model.evaluate_observation(at(0), 5, Some(at(-10)));
        let value = serde_json::to_value(&out).unwrap();
        let obj = value.as_object().unwrap();
        for key in ["level", "lag_commits", "stale_heartbeat", "reason"] {
            assert!(obj.contains_key(key), "missing field {key}");
        }
        assert_eq!(obj["level"], serde_json::json!("normal"));
        assert_eq!(obj["lag_commits"], serde_json::json!(5));
        assert_eq!(obj["stale_heartbeat"], serde_json::json!(false));
    }

    #[test]
    fn with_config_overrides_defaults() {
        // Custom thresholds: warning at 5, critical at 50.
        let cfg = ReplicationLagAnomalyConfig {
            warning_lag_commits: 5,
            critical_lag_commits: 50,
            stale_heartbeat_after_secs: 30,
        };
        let model = ReplicationLagAnomalyModel::with_config(cfg);
        let out = model.evaluate_observation(at(0), 6, Some(at(-10)));
        assert_eq!(out.level, ReplicationLagAnomalyLevel::Warning);
        let out_crit = model.evaluate_observation(at(0), 50, Some(at(-10)));
        assert_eq!(out_crit.level, ReplicationLagAnomalyLevel::Critical);
        let out_stale = model.evaluate_observation(at(0), 0, Some(at(-31)));
        assert_eq!(out_stale.level, ReplicationLagAnomalyLevel::Critical);
        assert!(out_stale.stale_heartbeat);
    }
}
