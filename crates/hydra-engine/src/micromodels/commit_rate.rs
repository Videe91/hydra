//! `CommitRateAnomalyModel` — EWMA + Z-score anomaly detector over
//! Hydra's commit pulse. The first *real* internal micro-model
//! (MicroModel Patch 2).
//!
//! ## What it watches
//!
//! Commits per minute, sampled per call. EWMA-tracked mean and
//! variance form an online baseline of "normal" commit rate. Each
//! new observation is scored against that baseline:
//!
//! ```text
//! z = (observed - ewma_rate) / sqrt(ewma_variance)
//! ```
//!
//! Absolute `|z|` selects the anomaly level (Normal / Warning /
//! Critical). Sign selects direction (Spike / Drop). Quiet windows
//! below `min_expected_rate` are suppressed to Normal — small
//! absolute changes against a near-zero baseline are not
//! operationally interesting.
//!
//! ## Pure-function design
//!
//! Per the user-approved Patch 2 structure: this module owns the
//! math. `CommitRateAnomalyModel::evaluate_observation(now, count)`
//! takes external inputs and returns a pure `Output` value. State
//! lives on `self` and mutates in place; no I/O, no clock reads, no
//! commit-ledger access. The Hydra wiring (`Hydra::evaluate_commit_rate_anomaly`)
//! handles counting commits in the window, auto-registering the
//! built-in model definition, building the `MicroModelPrediction`,
//! and recording the event. This separation keeps the model unit-
//! testable independently of the engine.
//!
//! ## What it does NOT do (Patch 2 boundary)
//!
//! - No background runner (caller invokes per evaluation cadence)
//! - No HTTP route
//! - No Python SDK method
//! - Does NOT emit Evidence / Claim / Action (that's Patch 3)
//! - State does NOT survive process restart (Patch 4+ polish)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Anomaly level returned with every prediction.
///
/// Serialized as snake_case so `level: "warming_up"` reads naturally
/// in JSON output and log lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyLevel {
    /// Insufficient samples to compute a reliable baseline. The
    /// model still records a prediction — agents may want to count
    /// warmup samples — but `z_score = 0.0` and direction is
    /// `Stable`.
    WarmingUp,
    /// |z| below the warning threshold, OR EWMA baseline is below
    /// `min_expected_rate` (suppression). Steady-state.
    Normal,
    /// |z| in the band `[warning_z_score, critical_z_score)`.
    /// Operator attention recommended.
    Warning,
    /// |z| >= `critical_z_score`. Operator action recommended.
    Critical,
}

impl AnomalyLevel {
    /// Deterministic confidence per level. Pinned by the Patch 2
    /// design table — agents downstream can rely on these values
    /// being stable.
    pub fn confidence(&self) -> f64 {
        match self {
            AnomalyLevel::WarmingUp => 0.50,
            AnomalyLevel::Normal => 0.80,
            AnomalyLevel::Warning => 0.75,
            AnomalyLevel::Critical => 0.90,
        }
    }

    /// Stable snake_case wire string. Identical to the serde
    /// representation — exposed here so the Patch 3 bridge can
    /// stash the level inside a typed `Value::String` in an
    /// Evidence payload without round-tripping through serde_json.
    pub fn wire_name(&self) -> &'static str {
        match self {
            AnomalyLevel::WarmingUp => "warming_up",
            AnomalyLevel::Normal => "normal",
            AnomalyLevel::Warning => "warning",
            AnomalyLevel::Critical => "critical",
        }
    }

    /// True for levels that warrant downstream action — Warning or
    /// Critical. The Patch 3 bridge fires Evidence + Claim only
    /// when this returns `true`.
    pub fn is_actionable(&self) -> bool {
        matches!(self, AnomalyLevel::Warning | AnomalyLevel::Critical)
    }
}

/// Direction of the deviation from the EWMA baseline. Only meaningful
/// for `Warning` / `Critical` — `Normal` and `WarmingUp` always
/// report `Stable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Observed rate exceeds the EWMA baseline by more than the
    /// warning threshold (signed z > +warning_z_score).
    Spike,
    /// Observed rate is below the EWMA baseline by more than the
    /// warning threshold (signed z < -warning_z_score).
    Drop,
    /// Observed rate is within the warning band, OR EWMA baseline
    /// is below `min_expected_rate` (suppression in effect).
    Stable,
}

impl Direction {
    /// Stable snake_case wire string. Same role as
    /// `AnomalyLevel::wire_name` — lets the bridge stash the
    /// direction in a typed Evidence payload value.
    pub fn wire_name(&self) -> &'static str {
        match self {
            Direction::Spike => "spike",
            Direction::Drop => "drop",
            Direction::Stable => "stable",
        }
    }
}

/// Tunable thresholds for the EWMA + Z-score detector.
///
/// `Default::default()` returns the Patch 2 approved values.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CommitRateAnomalyConfig {
    /// Number of initial observations to absorb before the model
    /// emits anything but `WarmingUp`. The EWMA mean is initialized
    /// from the first observation; the variance accumulates from
    /// `(observed - mean_before)^2` deltas across the warmup window.
    pub warmup_samples: u64,
    /// |z| at or above this threshold and below `critical_z_score`
    /// triggers `AnomalyLevel::Warning`.
    pub warning_z_score: f64,
    /// |z| at or above this threshold triggers `AnomalyLevel::Critical`.
    pub critical_z_score: f64,
    /// EWMA decay factor. `0 < alpha <= 1`. Higher = more weight on
    /// the most recent sample (faster reaction, noisier baseline);
    /// lower = smoother baseline (slower reaction).
    pub alpha: f64,
    /// Width of the rate-counting window in seconds. The Hydra
    /// wrapper counts commits whose `committed_at` falls in
    /// `[now - window_secs, now]`, converts to commits/minute, and
    /// passes that as the observation.
    pub window_secs: u64,
    /// Suppression floor. When the EWMA baseline is at or below
    /// this rate (commits/minute), the model returns
    /// `AnomalyLevel::Normal` regardless of z-score. Prevents false
    /// positives on tiny absolute changes against quiet workloads.
    pub min_expected_rate: f64,
}

impl Default for CommitRateAnomalyConfig {
    fn default() -> Self {
        Self {
            warmup_samples: 5,
            warning_z_score: 3.0,
            critical_z_score: 5.0,
            alpha: 0.2,
            window_secs: 60,
            min_expected_rate: 5.0,
        }
    }
}

/// Online state for the EWMA + variance baseline.
///
/// `Default::default()` is the cold-start state (no observations
/// seen yet, baseline at zero). A fresh `Hydra` engine reaches this
/// state on construction and re-reaches it after
/// `Hydra::reset_runtime_state_preserving_config`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct CommitRateAnomalyState {
    /// EWMA-tracked mean of observed commits-per-minute.
    pub ewma_rate: f64,
    /// EWMA-tracked variance. Floored at `1.0` when computing the
    /// z-score so a long stable run doesn't produce a divide-by-
    /// near-zero singularity.
    pub ewma_variance: f64,
    /// How many observations the state has absorbed. Used to gate
    /// out of `WarmingUp` once `>= config.warmup_samples`.
    pub samples_seen: u64,
    /// Wall-clock at the most recent observation, captured from the
    /// `observed_at` argument to `evaluate_observation`. None until
    /// the first call.
    pub last_observed_at: Option<DateTime<Utc>>,
}

/// One prediction. Goes verbatim into
/// `MicroModelPrediction.output` via `serde_json::to_value`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitRateAnomalyOutput {
    pub level: AnomalyLevel,
    pub direction: Direction,
    /// commits/minute computed from the observation window.
    pub observed_rate: f64,
    /// EWMA baseline BEFORE this observation was absorbed. Lets a
    /// caller see "what the model thought normal looked like" at
    /// the time it scored this sample.
    pub expected_rate: f64,
    /// Signed `(observed - expected) / sqrt(max(variance, 1.0))`.
    /// `0.0` during warmup or when suppressed.
    pub z_score: f64,
    /// Short prose for the prediction's `explanation` field. Stable
    /// format across calls so agents can pattern-match.
    pub reason: String,
}

/// EWMA + Z-score commit-rate anomaly detector. State updates in
/// place on each call to `evaluate_observation`. Construct via
/// `Default::default()` (uses default config) or
/// `with_config(...)` for explicit tuning.
#[derive(Debug, Clone, Default)]
pub struct CommitRateAnomalyModel {
    config: CommitRateAnomalyConfig,
    state: CommitRateAnomalyState,
}

impl CommitRateAnomalyModel {
    pub fn with_config(config: CommitRateAnomalyConfig) -> Self {
        Self {
            config,
            state: CommitRateAnomalyState::default(),
        }
    }

    /// Construct a model with an explicit pre-seeded state. Primary
    /// use case: test fixtures that need a deterministic EWMA
    /// baseline (e.g. `ewma_rate=10`, `samples_seen` past warmup)
    /// so the next observation deterministically lands in a chosen
    /// anomaly band. Also useful for future state-restoration
    /// patches that load EWMA state from disk.
    pub fn with_state(config: CommitRateAnomalyConfig, state: CommitRateAnomalyState) -> Self {
        Self { config, state }
    }

    pub fn config(&self) -> &CommitRateAnomalyConfig {
        &self.config
    }

    pub fn state(&self) -> &CommitRateAnomalyState {
        &self.state
    }

    /// Score one observation against the EWMA baseline. Pure
    /// function in `commit_count_in_window` / `observed_at`; the
    /// only side effect is mutating `self.state`.
    pub fn evaluate_observation(
        &mut self,
        observed_at: DateTime<Utc>,
        commit_count_in_window: u64,
    ) -> CommitRateAnomalyOutput {
        let observed_rate = commits_per_minute(commit_count_in_window, self.config.window_secs);
        let expected_rate = self.state.ewma_rate;
        let was_warmup = self.state.samples_seen < self.config.warmup_samples;

        // Score against the PRE-update baseline.
        let z_signed = signed_z_score(observed_rate, expected_rate, self.state.ewma_variance);
        let abs_z = z_signed.abs();

        let level = if was_warmup {
            AnomalyLevel::WarmingUp
        } else if expected_rate <= self.config.min_expected_rate {
            // Suppression floor: the baseline itself is below the
            // threshold for caring. Small absolute deviations
            // against a quiet workload are not operationally
            // interesting.
            AnomalyLevel::Normal
        } else if abs_z >= self.config.critical_z_score {
            AnomalyLevel::Critical
        } else if abs_z >= self.config.warning_z_score {
            AnomalyLevel::Warning
        } else {
            AnomalyLevel::Normal
        };

        let direction = match level {
            AnomalyLevel::Warning | AnomalyLevel::Critical => {
                if z_signed > 0.0 {
                    Direction::Spike
                } else if z_signed < 0.0 {
                    Direction::Drop
                } else {
                    Direction::Stable
                }
            }
            AnomalyLevel::WarmingUp | AnomalyLevel::Normal => Direction::Stable,
        };

        let reason = render_reason(
            level,
            direction,
            observed_rate,
            expected_rate,
            z_signed,
            self.state.samples_seen,
            self.config.warmup_samples,
        );

        // Now update state with this observation. EWMA mean +
        // variance (Welford-style EWMA pair).
        self.update_state(observed_at, observed_rate);

        CommitRateAnomalyOutput {
            level,
            direction,
            observed_rate,
            expected_rate,
            z_score: if matches!(level, AnomalyLevel::WarmingUp) {
                0.0
            } else {
                z_signed
            },
            reason,
        }
    }

    fn update_state(&mut self, observed_at: DateTime<Utc>, observed_rate: f64) {
        // First observation: seed the mean directly (no decay
        // averaging against an uninitialized zero) so warmup
        // converges in `warmup_samples` calls rather than slowly
        // bleeding zero into the EWMA.
        if self.state.samples_seen == 0 {
            self.state.ewma_rate = observed_rate;
            // Leave variance at zero for the first sample; the
            // delta is by definition zero against an initial mean.
        } else {
            let delta = observed_rate - self.state.ewma_rate;
            self.state.ewma_rate += self.config.alpha * delta;
            self.state.ewma_variance =
                (1.0 - self.config.alpha) * self.state.ewma_variance
                    + self.config.alpha * delta * delta;
        }
        self.state.samples_seen += 1;
        self.state.last_observed_at = Some(observed_at);
    }
}

/// Convert a raw commit count over the configured window into
/// commits/minute. Inlined so callers can compute the same value
/// without instantiating the model — used by the test fixture and
/// by Hydra's prediction-input builder.
fn commits_per_minute(count: u64, window_secs: u64) -> f64 {
    if window_secs == 0 {
        // Defensive: callers should never configure a zero window,
        // but a divide-by-zero in a hot path would be worse than
        // returning a sentinel.
        return 0.0;
    }
    count as f64 * 60.0 / window_secs as f64
}

fn signed_z_score(observed: f64, mean: f64, variance: f64) -> f64 {
    // Variance floor of 1.0 (commits/minute units). A long stable
    // run drives variance toward zero — without the floor, the
    // first ordinary fluctuation produces an absurd z-score.
    let var = variance.max(1.0);
    (observed - mean) / var.sqrt()
}

/// Result of a `Hydra::evaluate_commit_rate_anomaly_and_propose_claim`
/// call (MicroModel Patch 3 — the prediction bridge).
///
/// Every assessment carries the underlying prediction and the event
/// id under which it was recorded. When the model returns Warning or
/// Critical, the bridge ALSO records a paired `EvidenceAdded` and
/// `ClaimProposed` event — both with `caused_by = prediction_event_id`
/// — and the assessment carries the new ids back to the caller.
///
/// For `WarmingUp` and `Normal` predictions, `evidence_id` and
/// `claim_id` are `None`: no belief is formed against a baseline the
/// model hasn't trusted yet (warmup) or a steady-state observation
/// (normal). The prediction is still recorded for audit and
/// evolution metrics.
///
/// The top-level `level` field is duplicated from the prediction
/// output for ergonomic branching — callers shouldn't have to parse
/// `prediction.output` just to decide whether evidence + claim
/// landed.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitRateAnomalyAssessment {
    pub prediction: hydra_core::MicroModelPrediction,
    pub prediction_event_id: hydra_core::EventId,
    pub evidence_id: Option<hydra_core::EvidenceId>,
    pub claim_id: Option<hydra_core::ClaimId>,
    pub level: AnomalyLevel,
}

fn render_reason(
    level: AnomalyLevel,
    direction: Direction,
    observed_rate: f64,
    expected_rate: f64,
    z_signed: f64,
    samples_seen: u64,
    warmup_samples: u64,
) -> String {
    match level {
        AnomalyLevel::WarmingUp => format!(
            "warming up: {}/{} samples collected",
            samples_seen + 1,
            warmup_samples
        ),
        AnomalyLevel::Normal => format!(
            "commit rate {observed:.0}/min within ±{warn:.1}σ of expected {expected:.0}/min",
            observed = observed_rate,
            warn = z_signed.abs(),
            expected = expected_rate
        ),
        AnomalyLevel::Warning | AnomalyLevel::Critical => {
            let level_word = match level {
                AnomalyLevel::Warning => "exceeds",
                AnomalyLevel::Critical => "vastly exceeds",
                _ => unreachable!(),
            };
            let verb = match direction {
                Direction::Spike => level_word,
                Direction::Drop => "falls below",
                Direction::Stable => "deviates from",
            };
            format!(
                "commit rate {observed:.0}/min {verb} expected {expected:.0}/min by z-score {z:.1}",
                observed = observed_rate,
                verb = verb,
                expected = expected_rate,
                z = z_signed
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn at(seconds_offset: i64) -> DateTime<Utc> {
        // Stable base time so tests don't depend on Utc::now().
        let base = chrono::DateTime::parse_from_rfc3339("2026-05-29T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        base + Duration::seconds(seconds_offset)
    }

    fn observation(model: &mut CommitRateAnomalyModel, t_offset: i64, count: u64) -> CommitRateAnomalyOutput {
        model.evaluate_observation(at(t_offset), count)
    }

    #[test]
    fn model_in_warmup_returns_warming_up() {
        let mut model = CommitRateAnomalyModel::default();
        // warmup_samples = 5; the first five evaluations are warmup.
        for i in 0..5 {
            let out = observation(&mut model, (i * 60) as i64, 100);
            assert_eq!(out.level, AnomalyLevel::WarmingUp, "sample {i}");
            assert_eq!(out.direction, Direction::Stable);
            assert_eq!(out.z_score, 0.0);
            assert_eq!(out.level.confidence(), 0.50);
        }
        // Sixth evaluation is past warmup.
        let out = observation(&mut model, 360, 100);
        assert_ne!(out.level, AnomalyLevel::WarmingUp);
    }

    #[test]
    fn model_warmup_initializes_ewma_to_first_sample() {
        // First observation seeds the EWMA mean directly so warmup
        // converges immediately rather than slowly bleeding zero in.
        let mut model = CommitRateAnomalyModel::default();
        let _ = observation(&mut model, 0, 100);
        assert!((model.state().ewma_rate - 100.0).abs() < 1e-9);
        assert_eq!(model.state().samples_seen, 1);
        assert!(model.state().last_observed_at.is_some());
    }

    #[test]
    fn model_normal_stable_traffic_after_warmup() {
        let mut model = CommitRateAnomalyModel::default();
        // Five warmup samples at 100/min.
        for i in 0..5 {
            let _ = observation(&mut model, (i * 60) as i64, 100);
        }
        // Post-warmup, same rate → Normal, Stable.
        let out = observation(&mut model, 360, 100);
        assert_eq!(out.level, AnomalyLevel::Normal);
        assert_eq!(out.direction, Direction::Stable);
        assert!(out.z_score.abs() < 3.0);
        assert!(out.observed_rate.is_finite());
        assert!(out.expected_rate.is_finite());
    }

    #[test]
    fn model_detects_spike_critical() {
        let mut model = CommitRateAnomalyModel::default();
        // Build a stable 100/min baseline.
        for i in 0..10 {
            let _ = observation(&mut model, (i * 60) as i64, 100);
        }
        // Sudden 50× spike.
        let out = observation(&mut model, 600, 5000);
        assert_eq!(out.level, AnomalyLevel::Critical);
        assert_eq!(out.direction, Direction::Spike);
        assert!(
            out.z_score >= 5.0,
            "expected z >= 5.0 (critical), got {}",
            out.z_score
        );
        assert!(out.reason.contains("vastly exceeds") || out.reason.contains("exceeds"));
        assert_eq!(out.level.confidence(), 0.90);
    }

    #[test]
    fn model_detects_drop() {
        // High baseline that then collapses to zero — agents should
        // see a Critical Drop, not a "missing" prediction.
        let mut model = CommitRateAnomalyModel::default();
        for i in 0..10 {
            let _ = observation(&mut model, (i * 60) as i64, 200);
        }
        let out = observation(&mut model, 600, 0);
        assert!(matches!(
            out.level,
            AnomalyLevel::Warning | AnomalyLevel::Critical
        ));
        assert_eq!(out.direction, Direction::Drop);
        assert!(out.z_score < 0.0, "drop direction implies negative signed z");
        assert!(out.reason.contains("falls below"));
    }

    #[test]
    fn model_warning_band() {
        // Tweak the config so the warning/critical bands are
        // narrow enough to force a Warning outcome with a moderate
        // observation. With variance floored at 1.0 and a stable
        // baseline near 100, the warning band is roughly +/-2 to
        // +/-3 commits/min.
        let mut model = CommitRateAnomalyModel::with_config(CommitRateAnomalyConfig {
            warning_z_score: 2.0,
            critical_z_score: 4.0,
            ..CommitRateAnomalyConfig::default()
        });
        for i in 0..10 {
            let _ = observation(&mut model, (i * 60) as i64, 100);
        }
        // Small spike: 100 → 103. With variance floor = 1.0 and
        // expected = 100, z = 3.0 → solidly in the warning band.
        let out = observation(&mut model, 600, 103);
        assert_eq!(out.level, AnomalyLevel::Warning);
        assert_eq!(out.direction, Direction::Spike);
        assert!(out.z_score >= 2.0 && out.z_score < 4.0);
        assert_eq!(out.level.confidence(), 0.75);
    }

    #[test]
    fn model_suppresses_below_min_expected_rate() {
        // Set min_expected_rate generously so a stable 2/min
        // baseline is "too quiet to care."
        let mut model = CommitRateAnomalyModel::with_config(CommitRateAnomalyConfig {
            min_expected_rate: 10.0,
            ..CommitRateAnomalyConfig::default()
        });
        for i in 0..10 {
            let _ = observation(&mut model, (i * 60) as i64, 2);
        }
        // 5× the baseline in absolute terms, but baseline is below
        // the floor → Normal, no fire.
        let out = observation(&mut model, 600, 10);
        assert_eq!(out.level, AnomalyLevel::Normal);
        assert_eq!(out.direction, Direction::Stable);
    }

    #[test]
    fn model_confidence_table_matches_design() {
        // Lock the deterministic confidence table so a future
        // change here is a deliberate decision.
        assert_eq!(AnomalyLevel::WarmingUp.confidence(), 0.50);
        assert_eq!(AnomalyLevel::Normal.confidence(), 0.80);
        assert_eq!(AnomalyLevel::Warning.confidence(), 0.75);
        assert_eq!(AnomalyLevel::Critical.confidence(), 0.90);
    }

    #[test]
    fn model_state_updates_each_call() {
        let mut model = CommitRateAnomalyModel::default();
        assert_eq!(model.state().samples_seen, 0);
        assert!(model.state().last_observed_at.is_none());

        let _ = observation(&mut model, 0, 100);
        assert_eq!(model.state().samples_seen, 1);
        assert_eq!(model.state().last_observed_at, Some(at(0)));

        let _ = observation(&mut model, 60, 110);
        assert_eq!(model.state().samples_seen, 2);
        // EWMA mean has moved off 100 toward 110 (alpha=0.2 by default).
        assert!(model.state().ewma_rate > 100.0);
        assert!(model.state().ewma_rate < 110.0);
    }

    #[test]
    fn model_output_serializes_to_expected_json_shape() {
        // The output struct goes verbatim into
        // `MicroModelPrediction.output` via serde_json::to_value.
        // Pin the wire shape so a future field rename is a deliberate
        // breaking change.
        let mut model = CommitRateAnomalyModel::default();
        for i in 0..5 {
            let _ = observation(&mut model, (i * 60) as i64, 100);
        }
        let out = observation(&mut model, 360, 100);
        let value = serde_json::to_value(&out).unwrap();
        let obj = value.as_object().unwrap();
        // Every documented field is present.
        for key in [
            "level",
            "direction",
            "observed_rate",
            "expected_rate",
            "z_score",
            "reason",
        ] {
            assert!(obj.contains_key(key), "missing field {key}");
        }
        // Wire form for level / direction is snake_case strings.
        assert_eq!(obj["level"], serde_json::json!("normal"));
        assert_eq!(obj["direction"], serde_json::json!("stable"));
    }

    #[test]
    fn commits_per_minute_handles_non_minute_windows() {
        // 30-second window, 60 commits → 120/min.
        assert_eq!(commits_per_minute(60, 30), 120.0);
        // 60-second window (default), 100 commits → 100/min.
        assert_eq!(commits_per_minute(100, 60), 100.0);
        // 120-second window, 100 commits → 50/min.
        assert_eq!(commits_per_minute(100, 120), 50.0);
        // Defensive zero-window guard.
        assert_eq!(commits_per_minute(100, 0), 0.0);
    }
}
