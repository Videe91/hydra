use hydra_core::event::Value;

use std::collections::HashMap;
use chrono::{DateTime, Utc};

use super::{prop, update_node};

use hydra_core::event::EventKind;

// ============================================================================
// Trust Score — The 7-Dimension Recovery Confidence Score
// ============================================================================
//
// This is Sentinel's core differentiator. Nobody else has this.
//
// Each dimension is a float 0.0 - 100.0 tracked as a SEPARATE property so:
// - Layer 2 (Temporal): each dimension has independent version history
// - Layer 3 (Anomaly): DriftRule can detect "backup_freshness declining for 14 days"
// - Layer 3 (Anomaly): ChangeRateRule can detect "trust_composite changed 20 times today"
// - Layer 4 (Evolution): subscriptions on trust_composite < 50 track precision/recall
//
// The 7 dimensions:
// 1. Backup Freshness  — how recent is the latest backup?
// 2. Backup Verified   — has the backup been proven restorable?
// 3. Recovery Tested   — has end-to-end recovery been tested?
// 4. Dependency Health  — are all dependencies also protected?
// 5. Compliance Status  — does protection meet regulatory requirements?
// 6. Anomaly Free      — has the asset been free of anomalies?
// 7. Replication Health — are backups replicated to other regions?
//
// Composite = weighted average of all 7 dimensions.
// The weights are configurable per data_sensitivity level.

/// Weights for computing the composite trust score.
/// Different sensitivity levels weight dimensions differently.
pub struct TrustWeights {
    pub backup_freshness: f64,
    pub backup_verified: f64,
    pub recovery_tested: f64,
    pub dependency_health: f64,
    pub compliance_status: f64,
    pub anomaly_free: f64,
    pub replication_health: f64,
}

impl TrustWeights {
    /// Default weights — balanced across all dimensions
    pub fn default_weights() -> Self {
        Self {
            backup_freshness: 1.0,
            backup_verified: 1.0,
            recovery_tested: 1.0,
            dependency_health: 1.0,
            compliance_status: 1.0,
            anomaly_free: 1.0,
            replication_health: 1.0,
        }
    }

    /// For high-sensitivity data (PII, financial) — compliance and verification matter more
    pub fn high_sensitivity() -> Self {
        Self {
            backup_freshness: 1.0,
            backup_verified: 2.0,
            recovery_tested: 2.0,
            dependency_health: 1.0,
            compliance_status: 3.0,
            anomaly_free: 1.5,
            replication_health: 1.5,
        }
    }

    /// For critical infrastructure — freshness and dependency health matter more
    pub fn critical_infra() -> Self {
        Self {
            backup_freshness: 3.0,
            backup_verified: 1.5,
            recovery_tested: 1.5,
            dependency_health: 2.0,
            compliance_status: 1.0,
            anomaly_free: 2.0,
            replication_health: 1.0,
        }
    }

    /// Compute weighted average of 7 dimensions
    pub fn composite(
        &self,
        freshness: f64,
        verified: f64,
        recovery: f64,
        dependency: f64,
        compliance: f64,
        anomaly: f64,
        replication: f64,
    ) -> f64 {
        let total_weight = self.backup_freshness
            + self.backup_verified
            + self.recovery_tested
            + self.dependency_health
            + self.compliance_status
            + self.anomaly_free
            + self.replication_health;

        if total_weight == 0.0 {
            return 0.0;
        }

        let weighted_sum = freshness * self.backup_freshness
            + verified * self.backup_verified
            + recovery * self.recovery_tested
            + dependency * self.dependency_health
            + compliance * self.compliance_status
            + anomaly * self.anomaly_free
            + replication * self.replication_health;

        (weighted_sum / total_weight).clamp(0.0, 100.0)
    }
}

/// Compute the composite trust score for a node and return an update event.
/// Reads the 7 dimensions from the node's current properties.
pub fn compute_trust_update(
    node: &hydra_core::node::Node,
    weights: &TrustWeights,
) -> EventKind {
    let get = |key: &str| -> f64 {
        node.get_f64(key).unwrap_or(0.0)
    };

    let composite = weights.composite(
        get(prop::TRUST_BACKUP_FRESHNESS),
        get(prop::TRUST_BACKUP_VERIFIED),
        get(prop::TRUST_RECOVERY_TESTED),
        get(prop::TRUST_DEPENDENCY_HEALTH),
        get(prop::TRUST_COMPLIANCE_STATUS),
        get(prop::TRUST_ANOMALY_FREE),
        get(prop::TRUST_REPLICATION_HEALTH),
    );

    update_node(
        node.id().clone(),
        HashMap::from([(prop::TRUST_COMPOSITE.to_string(), Value::Float(composite))]),
    )
}

/// Compute the backup freshness dimension based on time since last backup.
/// Returns 0-100 where 100 = just backed up, 0 = way overdue.
pub fn freshness_score(
    last_backup_at: Option<DateTime<Utc>>,
    required_frequency_hours: i64,
    now: DateTime<Utc>,
) -> f64 {
    let last = match last_backup_at {
        Some(t) => t,
        None => return 0.0, // Never backed up
    };

    let hours_since = (now - last).num_hours() as f64;
    let required = required_frequency_hours as f64;

    if required <= 0.0 {
        return 100.0;
    }

    if hours_since <= required {
        100.0 // Within window
    } else if hours_since <= required * 2.0 {
        // Linear degradation from 100 to 0 between 1x and 2x the window
        100.0 * (1.0 - (hours_since - required) / required)
    } else {
        0.0 // More than 2x overdue
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_weights_balanced() {
        let w = TrustWeights::default_weights();
        let score = w.composite(100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0);
        assert!((score - 100.0).abs() < 0.001);

        let score = w.composite(50.0, 50.0, 50.0, 50.0, 50.0, 50.0, 50.0);
        assert!((score - 50.0).abs() < 0.001);

        let score = w.composite(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        assert!((score - 0.0).abs() < 0.001);
    }

    #[test]
    fn high_sensitivity_weights_compliance_heavy() {
        let w = TrustWeights::high_sensitivity();
        // All 100 except compliance at 0 → score should be below 100
        let score = w.composite(100.0, 100.0, 100.0, 100.0, 0.0, 100.0, 100.0);
        assert!(score < 80.0, "Compliance at 0 should drag high-sensitivity score down significantly: {}", score);
    }

    #[test]
    fn freshness_score_within_window() {
        let now = Utc::now();
        let one_hour_ago = now - chrono::Duration::hours(1);
        assert!((freshness_score(Some(one_hour_ago), 24, now) - 100.0).abs() < 0.001);
    }

    #[test]
    fn freshness_score_overdue() {
        let now = Utc::now();
        let two_days_ago = now - chrono::Duration::hours(48);
        // Required: 24h, actual: 48h = 2x overdue → score 0
        assert!((freshness_score(Some(two_days_ago), 24, now) - 0.0).abs() < 0.001);
    }

    #[test]
    fn freshness_score_degrading() {
        let now = Utc::now();
        let thirty_hours_ago = now - chrono::Duration::hours(30);
        // Required: 24h, actual: 30h → between 1x and 2x → linear degradation
        let score = freshness_score(Some(thirty_hours_ago), 24, now);
        assert!(score > 0.0 && score < 100.0, "Should be degrading: {}", score);
    }

    #[test]
    fn freshness_score_never_backed_up() {
        assert!((freshness_score(None, 24, Utc::now()) - 0.0).abs() < 0.001);
    }

    #[test]
    fn composite_clamped_to_100() {
        let w = TrustWeights::default_weights();
        // Even with values > 100, composite should clamp
        let score = w.composite(200.0, 200.0, 200.0, 200.0, 200.0, 200.0, 200.0);
        assert!((score - 100.0).abs() < 0.001);
    }
}
