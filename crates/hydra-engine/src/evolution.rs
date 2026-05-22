use hydra_core::event::Event;
use hydra_core::id::{EventId, SubscriptionId};
use hydra_core::subscription::EventFilter;
use crate::cascade::CascadeResult;
use crate::event_log::EventLog;
use crate::registry::SubscriptionRegistry;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

// ============================================================================
// Metrics — per-subscription effectiveness tracking
// ============================================================================

/// Tracks how effective a single subscription has been over time.
#[derive(Debug, Clone)]
pub struct SubscriptionMetrics {
    /// Which subscription this tracks
    pub subscription_id: SubscriptionId,
    /// Human-readable name (cached for diagnostics)
    pub subscription_name: String,
    /// Total times this subscription's filter matched an event
    pub total_fires: u64,
    /// Total reaction events this subscription produced
    pub total_reactions: u64,
    /// Human confirmed the action was correct
    pub true_positives: u64,
    /// Human dismissed the action (false alarm)
    pub false_positives: u64,
    /// Outcomes where no human action was taken (auto-accepted)
    pub auto_accepted: u64,
    /// Retroactively labeled: subscription should have fired but didn't.
    /// Recorded via record_miss() during incident review.
    pub false_negatives: u64,
    /// Individual fire records for replay and analysis
    pub fire_log: Vec<FireRecord>,
    /// Individual miss records — events the subscription should have caught
    pub miss_log: Vec<MissRecord>,
}

impl SubscriptionMetrics {
    fn new(id: SubscriptionId, name: String) -> Self {
        Self {
            subscription_id: id,
            subscription_name: name,
            total_fires: 0,
            total_reactions: 0,
            true_positives: 0,
            false_positives: 0,
            auto_accepted: 0,
            false_negatives: 0,
            fire_log: Vec::new(),
            miss_log: Vec::new(),
        }
    }

    /// Precision: what fraction of fires were correct?
    /// Returns None if no outcomes have been recorded.
    pub fn precision(&self) -> Option<f64> {
        let total_judged = self.true_positives + self.false_positives;
        if total_judged == 0 {
            return None;
        }
        Some(self.true_positives as f64 / total_judged as f64)
    }

    /// False positive rate: what fraction of fires were false alarms?
    pub fn false_positive_rate(&self) -> Option<f64> {
        self.precision().map(|p| 1.0 - p)
    }

    /// Recall: what fraction of bad events did this subscription catch?
    /// recall = TP / (TP + FN). Returns None if no positives or misses recorded.
    pub fn recall(&self) -> Option<f64> {
        let total = self.true_positives + self.false_negatives;
        if total == 0 {
            return None;
        }
        Some(self.true_positives as f64 / total as f64)
    }

    /// How many fires have no outcome yet (neither confirmed nor dismissed)
    pub fn pending_outcomes(&self) -> u64 {
        self.total_fires - self.true_positives - self.false_positives - self.auto_accepted
    }
}

/// A record of a single subscription fire
#[derive(Debug, Clone)]
pub struct FireRecord {
    /// When the subscription fired
    pub timestamp: DateTime<Utc>,
    /// The event that triggered the fire
    pub trigger_event_id: EventId,
    /// How many reaction events this fire produced
    pub reaction_count: usize,
    /// Human outcome (None = pending)
    pub outcome: Option<SubscriptionOutcome>,
}

/// A record of a missed event — retroactively labeled by a human during
/// incident review. "This subscription should have caught event X but didn't."
#[derive(Debug, Clone)]
pub struct MissRecord {
    /// When the miss was recorded (not when the event happened)
    pub recorded_at: DateTime<Utc>,
    /// The event that was missed
    pub missed_event_id: EventId,
    /// Optional explanation from the reviewer
    pub reason: Option<String>,
}

/// Human judgment on a subscription fire.
///
/// Renamed from `Outcome` to avoid colliding with the universal
/// `hydra_core::Outcome` (which is the result of an executed action). A
/// deprecated `Outcome` type alias is kept below for back-compat.
#[derive(Debug, Clone, PartialEq)]
pub enum SubscriptionOutcome {
    /// Human confirmed the action was correct
    Confirmed,
    /// Human dismissed the action (false alarm)
    Dismissed,
    /// System auto-accepted (no human review needed)
    AutoAccepted,
}

/// Deprecated alias for `SubscriptionOutcome`.
///
/// The bare `Outcome` name now refers to `hydra_core::Outcome`, the result of an
/// executed action. New code should use [`SubscriptionOutcome`] directly. This
/// alias keeps `hydra_engine::evolution::Outcome` working for existing users.
#[deprecated(
    note = "Use SubscriptionOutcome. Outcome is reserved for hydra_core::Outcome action results."
)]
pub type Outcome = SubscriptionOutcome;

// ============================================================================
// Mutation Proposals — the self-evolution mechanism
// ============================================================================

/// A proposed change to a subscription's behavior
#[derive(Debug, Clone)]
pub struct MutationProposal {
    /// Which subscription this proposes to change
    pub subscription_id: SubscriptionId,
    /// Human-readable description of the change
    pub description: String,
    /// Why this change is being proposed
    pub rationale: String,
    /// The proposed new filter (None = no filter change, adjust thresholds in handler)
    pub proposed_filter: Option<EventFilter>,
    /// Estimated precision with the new filter (from historical replay)
    pub estimated_precision: Option<f64>,
    /// How many historical fires would have been prevented
    pub fires_prevented: u64,
    /// How many true positives would have been lost
    pub true_positives_lost: u64,
    /// Current status
    pub status: ProposalStatus,
    /// When this was proposed
    pub proposed_at: DateTime<Utc>,
    /// When this was resolved (approved/rejected)
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Status of a mutation proposal
#[derive(Debug, Clone, PartialEq)]
pub enum ProposalStatus {
    /// Awaiting human review
    Proposed,
    /// Human approved — ready to apply
    Approved,
    /// Human rejected — keep current behavior
    Rejected,
    /// Applied to the subscription
    Applied,
}

// ============================================================================
// The Tracker — the core of self-evolving subscriptions
// ============================================================================

/// Tracks subscription effectiveness and proposes improvements.
///
/// Standalone module — not embedded in the cascade engine.
/// Hydra calls `record_cascade()` after each ingest.
/// Humans call `record_outcome()` to provide feedback.
/// `generate_proposals()` analyzes metrics and proposes filter changes.
pub struct SubscriptionTracker {
    /// Per-subscription metrics
    metrics: HashMap<SubscriptionId, SubscriptionMetrics>,
    /// Pending and resolved mutation proposals
    pub(crate) proposals: Vec<MutationProposal>,
    /// Minimum fires before generating proposals
    min_fires_for_proposal: u64,
    /// False positive rate threshold that triggers a proposal
    fp_rate_threshold: f64,
}

impl SubscriptionTracker {
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
            proposals: Vec::new(),
            min_fires_for_proposal: 10,
            fp_rate_threshold: 0.5,
        }
    }

    /// Configure the minimum fires before proposals are generated
    pub fn with_min_fires(mut self, min: u64) -> Self {
        self.min_fires_for_proposal = min;
        self
    }

    /// Configure the false positive rate that triggers proposals
    pub fn with_fp_threshold(mut self, threshold: f64) -> Self {
        self.fp_rate_threshold = threshold;
        self
    }

    // ========================================================================
    // Recording — called after each cascade
    // ========================================================================

    /// Record which subscriptions fired during a cascade.
    /// Performs post-hoc attribution by replaying filter matches on the
    /// cascade's events against the registry. Does NOT modify the cascade engine.
    pub fn record_cascade(
        &mut self,
        result: &CascadeResult,
        registry: &SubscriptionRegistry,
    ) {
        if result.events.is_empty() {
            return;
        }

        // Pre-build parent → child count index (O(E) instead of O(E²))
        let mut reaction_counts: HashMap<EventId, usize> = HashMap::new();
        for event in &result.events {
            for parent_id in &event.caused_by {
                *reaction_counts.entry(parent_id.clone()).or_insert(0) += 1;
            }
        }

        // For each event in the cascade, check which subscriptions would have matched
        for event in &result.events {
            let reaction_count = reaction_counts.get(&event.id).copied().unwrap_or(0);

            for sub_id in subscription_ids_matching(event, registry) {
                let name = registry
                    .get(&sub_id)
                    .map(|s| s.name.clone())
                    .unwrap_or_default();

                let metrics = self
                    .metrics
                    .entry(sub_id.clone())
                    .or_insert_with(|| SubscriptionMetrics::new(sub_id.clone(), name));

                metrics.total_fires += 1;
                metrics.total_reactions += reaction_count as u64;

                metrics.fire_log.push(FireRecord {
                    timestamp: event.timestamp,
                    trigger_event_id: event.id.clone(),
                    reaction_count,
                    outcome: None,
                });
            }
        }
    }

    /// Record a human outcome for a specific subscription fire.
    /// `fire_index` is the index into the fire_log for that subscription.
    pub fn record_outcome(
        &mut self,
        subscription_id: &SubscriptionId,
        fire_index: usize,
        outcome: SubscriptionOutcome,
    ) -> bool {
        if let Some(metrics) = self.metrics.get_mut(subscription_id) {
            if let Some(record) = metrics.fire_log.get_mut(fire_index) {
                // Don't overwrite existing outcomes
                if record.outcome.is_some() {
                    return false;
                }

                match &outcome {
                    SubscriptionOutcome::Confirmed => metrics.true_positives += 1,
                    SubscriptionOutcome::Dismissed => metrics.false_positives += 1,
                    SubscriptionOutcome::AutoAccepted => metrics.auto_accepted += 1,
                }

                record.outcome = Some(outcome);
                return true;
            }
        }
        false
    }

    /// Bulk-record outcomes: mark all pending fires for a subscription
    pub fn record_all_outcomes(
        &mut self,
        subscription_id: &SubscriptionId,
        outcome: SubscriptionOutcome,
    ) -> usize {
        let mut count = 0;
        if let Some(metrics) = self.metrics.get_mut(subscription_id) {
            for record in &mut metrics.fire_log {
                if record.outcome.is_none() {
                    match &outcome {
                        SubscriptionOutcome::Confirmed => metrics.true_positives += 1,
                        SubscriptionOutcome::Dismissed => metrics.false_positives += 1,
                        SubscriptionOutcome::AutoAccepted => metrics.auto_accepted += 1,
                    }
                    record.outcome = Some(outcome.clone());
                    count += 1;
                }
            }
        }
        count
    }

    /// Record a false negative: "subscription X should have fired on event Y but didn't."
    /// Called retroactively during incident review (manual) or by correlate_anomalies (autonomous).
    ///
    /// If the subscription has never been tracked (no fires recorded yet),
    /// it will be initialized from the registry name.
    pub fn record_miss(
        &mut self,
        subscription_id: &SubscriptionId,
        missed_event_id: EventId,
        reason: Option<String>,
    ) -> bool {
        let metrics = self
            .metrics
            .entry(subscription_id.clone())
            .or_insert_with(|| {
                SubscriptionMetrics::new(subscription_id.clone(), String::new())
            });

        // Don't record the same miss twice
        if metrics
            .miss_log
            .iter()
            .any(|m| m.missed_event_id == missed_event_id)
        {
            return false;
        }

        metrics.false_negatives += 1;
        metrics.miss_log.push(MissRecord {
            recorded_at: Utc::now(),
            missed_event_id,
            reason,
        });
        true
    }

    // ========================================================================
    // Autonomous false negative detection — Layer 3 → Layer 4 coupling
    // ========================================================================

    /// Correlate detected anomalies with subscription fires to find autonomous
    /// false negatives: "an anomaly was detected, but no subscription fired on
    /// the events leading to it."
    ///
    /// For each anomaly above `min_severity`:
    /// 1. Collect events related to the anomaly (trigger event + causal chain,
    ///    or recent events on affected nodes)
    /// 2. For each tracked subscription, check if it fired on ANY of those events
    /// 3. If a subscription's filter COULD match those events but didn't fire →
    ///    record as autonomous false negative
    ///
    /// This is how the system detects its own blind spots without human labeling.
    pub fn correlate_anomalies(
        &mut self,
        anomalies: &[crate::anomaly::Anomaly],
        event_log: &EventLog,
        registry: &SubscriptionRegistry,
        min_severity: f64,
    ) -> usize {
        let mut total_misses = 0usize;

        for anomaly in anomalies {
            if anomaly.severity < min_severity {
                continue;
            }

            // Step 1: Collect relevant events for this anomaly
            let relevant_events = self.collect_anomaly_events(anomaly, event_log);
            if relevant_events.is_empty() {
                continue;
            }

            // Step 2: For each relevant event, find subscriptions whose filter
            // matches but that didn't actually fire — autonomous false negatives
            for event in &relevant_events {
                let would_match = registry.matching_subscriptions(event);

                for sub in would_match {
                    // Check if this subscription actually fired on this event
                    let did_fire = self
                        .metrics
                        .get(&sub.id)
                        .map_or(false, |m| {
                            m.fire_log.iter().any(|f| f.trigger_event_id == event.id)
                        });

                    if !did_fire {
                        let reason = format!(
                            "Autonomous: anomaly '{}' (severity {:.2}) detected, but subscription '{}' \
                             did not fire on event {}",
                            anomaly.description, anomaly.severity,
                            sub.name, event.id,
                        );
                        if self.record_miss(&sub.id, event.id.clone(), Some(reason)) {
                            total_misses += 1;
                        }
                    }
                }
            }
        }

        total_misses
    }

    /// Collect events related to an anomaly for false negative correlation.
    /// Uses trigger_event's causal chain if available, otherwise finds recent
    /// events targeting affected nodes.
    fn collect_anomaly_events<'a>(
        &self,
        anomaly: &crate::anomaly::Anomaly,
        event_log: &'a EventLog,
    ) -> Vec<&'a Event> {
        let mut events = Vec::new();

        // If the anomaly has a trigger event, use its root cause chain
        if let Some(ref trigger_id) = anomaly.trigger_event {
            let chain = event_log.root_cause(trigger_id);
            events.extend(chain);
            // Also include the trigger itself and its forward chain
            if let Some(trigger) = event_log.get(trigger_id) {
                events.push(trigger);
            }
            let forward = event_log.causal_chain(trigger_id);
            events.extend(forward);
        }

        // Also collect recent events targeting affected nodes
        // (scan backward, take the most recent events per node)
        if events.is_empty() {
            for event in event_log.iter_rev() {
                if let Some(target) = event.kind.target_node() {
                    if anomaly.affected_nodes.contains(target) {
                        events.push(event);
                        // Limit to avoid excessive scanning
                        if events.len() >= 50 {
                            break;
                        }
                    }
                }
            }
        }

        events
    }
    // Querying — inspect subscription effectiveness
    // ========================================================================

    /// Get metrics for a specific subscription
    pub fn metrics(&self, id: &SubscriptionId) -> Option<&SubscriptionMetrics> {
        self.metrics.get(id)
    }

    /// Get metrics for all tracked subscriptions
    pub fn all_metrics(&self) -> Vec<&SubscriptionMetrics> {
        self.metrics.values().collect()
    }

    /// Get subscriptions ranked by false positive rate (worst first)
    pub fn worst_performers(&self) -> Vec<&SubscriptionMetrics> {
        let mut rated: Vec<&SubscriptionMetrics> = self
            .metrics
            .values()
            .filter(|m| m.precision().is_some())
            .collect();
        rated.sort_by(|a, b| {
            let fpr_a = a.false_positive_rate().unwrap_or(0.0);
            let fpr_b = b.false_positive_rate().unwrap_or(0.0);
            fpr_b
                .partial_cmp(&fpr_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        rated
    }

    // ========================================================================
    // Proposals — the self-evolution mechanism
    // ========================================================================

    /// Generate mutation proposals for subscriptions that are underperforming.
    /// A subscription is underperforming if:
    /// 1. It has fired at least `min_fires_for_proposal` times
    /// 2. Its false positive rate exceeds `fp_rate_threshold`
    ///
    /// For each underperforming subscription, the system proposes disabling it
    /// and includes the metrics as rationale. More sophisticated proposals
    /// (threshold adjustment, filter narrowing) require domain-specific logic
    /// that sentinel or other verticals provide.
    pub fn generate_proposals(&mut self) -> Vec<&MutationProposal> {
        let now = Utc::now();
        let mut new_proposals = Vec::new();

        for metrics in self.metrics.values() {
            // Skip if not enough data
            if metrics.total_fires < self.min_fires_for_proposal {
                continue;
            }

            // Skip if no outcomes recorded
            let fpr = match metrics.false_positive_rate() {
                Some(rate) => rate,
                None => continue,
            };

            // Skip if performing well
            if fpr < self.fp_rate_threshold {
                continue;
            }

            // Skip if we already have a pending proposal for this subscription
            let has_pending = self.proposals.iter().any(|p| {
                p.subscription_id == metrics.subscription_id
                    && p.status == ProposalStatus::Proposed
            });
            if has_pending {
                continue;
            }

            let precision = metrics.precision().unwrap_or(0.0);

            new_proposals.push(MutationProposal {
                subscription_id: metrics.subscription_id.clone(),
                description: format!(
                    "Subscription '{}' has a {:.0}% false positive rate ({} false / {} total judged). Consider adjusting its filter or threshold.",
                    metrics.subscription_name,
                    fpr * 100.0,
                    metrics.false_positives,
                    metrics.true_positives + metrics.false_positives,
                ),
                rationale: format!(
                    "Precision: {:.1}%. Recall: {}. {} fires, {} true positives, {} false positives, {} false negatives, {} auto-accepted, {} pending.",
                    precision * 100.0,
                    metrics.recall().map_or("N/A".to_string(), |r| format!("{:.1}%", r * 100.0)),
                    metrics.total_fires,
                    metrics.true_positives,
                    metrics.false_positives,
                    metrics.false_negatives,
                    metrics.auto_accepted,
                    metrics.pending_outcomes(),
                ),
                proposed_filter: None,
                estimated_precision: Some(precision),
                fires_prevented: metrics.false_positives,
                true_positives_lost: 0,
                status: ProposalStatus::Proposed,
                proposed_at: now,
                resolved_at: None,
            });
        }

        // Store new proposals
        let start_idx = self.proposals.len();
        self.proposals.extend(new_proposals);

        // Return references to newly generated proposals
        self.proposals[start_idx..].iter().collect()
    }

    /// Simulate what would happen if a subscription's filter were changed.
    /// Replays the event log through the proposed filter and counts matches.
    /// Returns (would_match, would_not_match) counts.
    pub fn simulate_filter(
        &self,
        subscription_id: &SubscriptionId,
        proposed_filter: &EventFilter,
        event_log: &EventLog,
    ) -> FilterSimulation {
        let mut would_match = 0u64;
        let mut would_not_match = 0u64;
        let mut true_positives_kept = 0u64;
        let mut false_positives_removed = 0u64;

        let metrics = match self.metrics.get(subscription_id) {
            Some(m) => m,
            None => {
                return FilterSimulation {
                    would_match: 0,
                    would_not_match: 0,
                    true_positives_kept: 0,
                    false_positives_removed: 0,
                    estimated_precision: None,
                };
            }
        };

        // Replay each fire record through the proposed filter
        for record in &metrics.fire_log {
            if let Some(event) = event_log.get(&record.trigger_event_id) {
                if proposed_filter.matches(event) {
                    would_match += 1;
                    if record.outcome == Some(SubscriptionOutcome::Confirmed) {
                        true_positives_kept += 1;
                    }
                } else {
                    would_not_match += 1;
                    if record.outcome == Some(SubscriptionOutcome::Dismissed) {
                        false_positives_removed += 1;
                    }
                }
            }
        }

        let estimated_precision = if would_match > 0 {
            Some(true_positives_kept as f64 / would_match as f64)
        } else {
            None
        };

        FilterSimulation {
            would_match,
            would_not_match,
            true_positives_kept,
            false_positives_removed,
            estimated_precision,
        }
    }

    /// Approve a proposal by index
    pub fn approve_proposal(&mut self, index: usize) -> bool {
        if let Some(proposal) = self.proposals.get_mut(index) {
            if proposal.status == ProposalStatus::Proposed {
                proposal.status = ProposalStatus::Approved;
                proposal.resolved_at = Some(Utc::now());
                return true;
            }
        }
        false
    }

    /// Reject a proposal by index
    pub fn reject_proposal(&mut self, index: usize) -> bool {
        if let Some(proposal) = self.proposals.get_mut(index) {
            if proposal.status == ProposalStatus::Proposed {
                proposal.status = ProposalStatus::Rejected;
                proposal.resolved_at = Some(Utc::now());
                return true;
            }
        }
        false
    }

    /// Apply an approved mutation: replace the subscription's filter in the registry.
    /// The proposal must be in `Approved` status. After applying, the proposal
    /// moves to `Applied` status and the subscription's filter is replaced.
    ///
    /// Returns false if: proposal doesn't exist, isn't Approved, has no proposed_filter,
    /// or the subscription isn't found in the registry.
    pub fn apply_mutation(
        &mut self,
        index: usize,
        registry: &mut SubscriptionRegistry,
    ) -> bool {
        // Validate proposal state first (without borrowing self.proposals mutably yet)
        let (sub_id, new_filter) = {
            let proposal = match self.proposals.get(index) {
                Some(p) => p,
                None => return false,
            };
            if proposal.status != ProposalStatus::Approved {
                return false;
            }
            let filter = match &proposal.proposed_filter {
                Some(f) => f.clone(),
                None => return false,
            };
            (proposal.subscription_id.clone(), filter)
        };

        // Apply the filter change in the registry
        if !registry.set_filter(&sub_id, new_filter) {
            return false;
        }

        // Mark proposal as applied
        let proposal = &mut self.proposals[index];
        proposal.status = ProposalStatus::Applied;
        proposal.resolved_at = Some(Utc::now());
        true
    }

    /// Get all proposals
    pub fn proposals(&self) -> &[MutationProposal] {
        &self.proposals
    }

    /// Get only pending proposals
    pub fn pending_proposals(&self) -> Vec<&MutationProposal> {
        self.proposals
            .iter()
            .filter(|p| p.status == ProposalStatus::Proposed)
            .collect()
    }

    /// Total tracked subscriptions
    pub fn tracked_count(&self) -> usize {
        self.metrics.len()
    }
}

impl Default for SubscriptionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of simulating a filter change against historical data
#[derive(Debug, Clone)]
pub struct FilterSimulation {
    /// How many historical fires would still match the new filter
    pub would_match: u64,
    /// How many historical fires would NOT match (prevented)
    pub would_not_match: u64,
    /// Of the would-match fires, how many were true positives
    pub true_positives_kept: u64,
    /// Of the would-not-match fires, how many were false positives (good)
    pub false_positives_removed: u64,
    /// Estimated precision with the new filter
    pub estimated_precision: Option<f64>,
}

// ============================================================================
// Helpers
// ============================================================================

/// Get subscription IDs that match an event (post-hoc filter replay)
fn subscription_ids_matching(
    event: &Event,
    registry: &SubscriptionRegistry,
) -> Vec<SubscriptionId> {
    registry
        .matching_subscriptions(event)
        .iter()
        .map(|s| s.id.clone())
        .collect()
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::cascade::CascadeEngine;
    use crate::projection::Projection;
    use hydra_core::event::{Event, EventKind, Value};
    use hydra_core::id::NodeId;
    use hydra_core::subscription::{Subscription, SubscriptionHandler};
    use std::collections::HashMap;

    struct TagHandler {
        key: String,
    }
    impl SubscriptionHandler for TagHandler {
        fn handle(
            &self,
            event: &Event,
            _graph: &dyn hydra_core::graph::GraphReader,
        ) -> Vec<EventKind> {
            if let EventKind::NodeCreated { node_id, .. } = &event.kind {
                vec![EventKind::NodeUpdated {
                    node_id: node_id.clone(),
                    changes: HashMap::from([(self.key.clone(), Value::Bool(true))]),
                }]
            } else {
                vec![]
            }
        }
    }

    fn setup_registry() -> (SubscriptionRegistry, SubscriptionId) {
        let mut registry = SubscriptionRegistry::new();
        let sub = Subscription::new(
            "tagger",
            EventFilter::NodeCreated,
            100,
            Box::new(TagHandler { key: "tagged".into() }),
        );
        let id = sub.id.clone();
        registry.register(sub);
        (registry, id)
    }

    fn run_cascade(registry: &SubscriptionRegistry) -> CascadeResult {
        let engine = CascadeEngine::with_defaults();
        let mut proj = Projection::new();
        engine
            .trigger(
                EventKind::NodeCreated {
                    node_id: NodeId::new(),
                    type_id: "ec2".to_string(),
                    properties: HashMap::new(),
                },
                &mut proj,
                registry,
            )
            .unwrap()
    }

    // ================================================================
    // Test 1: Record cascade fires
    // ================================================================
    #[test]
    fn records_cascade_fires() {
        let (registry, sub_id) = setup_registry();
        let result = run_cascade(&registry);

        let mut tracker = SubscriptionTracker::new();
        tracker.record_cascade(&result, &registry);

        let metrics = tracker.metrics(&sub_id).unwrap();
        assert!(metrics.total_fires > 0);
        assert_eq!(metrics.subscription_name, "tagger");
    }

    // ================================================================
    // Test 2: Record outcomes
    // ================================================================
    #[test]
    fn records_outcomes() {
        let (registry, sub_id) = setup_registry();
        let result = run_cascade(&registry);

        let mut tracker = SubscriptionTracker::new();
        tracker.record_cascade(&result, &registry);

        // Record first fire as a true positive
        assert!(tracker.record_outcome(&sub_id, 0, SubscriptionOutcome::Confirmed));

        let metrics = tracker.metrics(&sub_id).unwrap();
        assert_eq!(metrics.true_positives, 1);
        assert_eq!(metrics.false_positives, 0);
    }

    // ================================================================
    // Test 3: Precision calculation
    // ================================================================
    #[test]
    fn precision_calculation() {
        let (registry, sub_id) = setup_registry();

        let mut tracker = SubscriptionTracker::new();

        // Run 4 cascades
        for _ in 0..4 {
            let result = run_cascade(&registry);
            tracker.record_cascade(&result, &registry);
        }

        let metrics = tracker.metrics(&sub_id).unwrap();
        let fire_count = metrics.fire_log.len();

        // Mark first 3 as confirmed, last 1 as dismissed
        for i in 0..fire_count.saturating_sub(1) {
            tracker.record_outcome(&sub_id, i, SubscriptionOutcome::Confirmed);
        }
        if fire_count > 0 {
            tracker.record_outcome(&sub_id, fire_count - 1, SubscriptionOutcome::Dismissed);
        }

        let metrics = tracker.metrics(&sub_id).unwrap();
        // Precision should reflect the split
        let precision = metrics.precision().unwrap();
        assert!(precision > 0.0 && precision < 1.0);
    }

    // ================================================================
    // Test 4: No precision without outcomes
    // ================================================================
    #[test]
    fn no_precision_without_outcomes() {
        let (registry, sub_id) = setup_registry();
        let result = run_cascade(&registry);

        let mut tracker = SubscriptionTracker::new();
        tracker.record_cascade(&result, &registry);

        let metrics = tracker.metrics(&sub_id).unwrap();
        assert!(metrics.precision().is_none());
    }

    // ================================================================
    // Test 5: Generate proposals for high FP rate
    // ================================================================
    #[test]
    fn generates_proposals_for_high_fp_rate() {
        let (registry, sub_id) = setup_registry();

        let mut tracker = SubscriptionTracker::new()
            .with_min_fires(3)
            .with_fp_threshold(0.5);

        // Run 5 cascades
        for _ in 0..5 {
            let result = run_cascade(&registry);
            tracker.record_cascade(&result, &registry);
        }

        // Mark all as dismissed (100% false positive rate)
        tracker.record_all_outcomes(&sub_id, SubscriptionOutcome::Dismissed);

        let proposals = tracker.generate_proposals();
        assert!(!proposals.is_empty());
        assert_eq!(proposals[0].subscription_id, sub_id);
        assert_eq!(proposals[0].status, ProposalStatus::Proposed);
    }

    // ================================================================
    // Test 6: No proposals for good subscriptions
    // ================================================================
    #[test]
    fn no_proposals_for_good_subscriptions() {
        let (registry, sub_id) = setup_registry();

        let mut tracker = SubscriptionTracker::new()
            .with_min_fires(3)
            .with_fp_threshold(0.5);

        // Run 5 cascades
        for _ in 0..5 {
            let result = run_cascade(&registry);
            tracker.record_cascade(&result, &registry);
        }

        // Mark all as confirmed (0% false positive rate)
        tracker.record_all_outcomes(&sub_id, SubscriptionOutcome::Confirmed);

        let proposals = tracker.generate_proposals();
        assert!(proposals.is_empty());
    }

    // ================================================================
    // Test 7: Approve and reject proposals
    // ================================================================
    #[test]
    fn approve_reject_proposals() {
        let (registry, sub_id) = setup_registry();

        let mut tracker = SubscriptionTracker::new()
            .with_min_fires(2)
            .with_fp_threshold(0.3);

        for _ in 0..5 {
            let result = run_cascade(&registry);
            tracker.record_cascade(&result, &registry);
        }

        tracker.record_all_outcomes(&sub_id, SubscriptionOutcome::Dismissed);
        tracker.generate_proposals();

        assert!(!tracker.pending_proposals().is_empty());

        // Approve the first proposal
        assert!(tracker.approve_proposal(0));
        assert_eq!(tracker.proposals()[0].status, ProposalStatus::Approved);
        assert!(tracker.proposals()[0].resolved_at.is_some());

        // Can't approve again
        assert!(!tracker.approve_proposal(0));
    }

    // ================================================================
    // Test 8: Simulate filter change
    // ================================================================
    #[test]
    fn simulate_filter_change() {
        let (registry, sub_id) = setup_registry();

        let mut tracker = SubscriptionTracker::new();
        let mut log = EventLog::new();

        // Run cascades and record events in the log
        for _ in 0..5 {
            let result = run_cascade(&registry);
            tracker.record_cascade(&result, &registry);
            for event in &result.events {
                log.append(event.clone());
            }
        }

        // Mark first 2 fires as confirmed, rest as dismissed
        let metrics = tracker.metrics(&sub_id).unwrap();
        let fire_count = metrics.fire_log.len();
        for i in 0..fire_count.min(2) {
            tracker.record_outcome(&sub_id, i, SubscriptionOutcome::Confirmed);
        }
        for i in 2..fire_count {
            tracker.record_outcome(&sub_id, i, SubscriptionOutcome::Dismissed);
        }

        // Simulate with a more restrictive filter (only ec2 type)
        let narrow_filter = EventFilter::And(vec![
            EventFilter::NodeCreated,
            EventFilter::NodeType("ec2".to_string()),
        ]);

        let sim = tracker.simulate_filter(&sub_id, &narrow_filter, &log);

        // All events were ec2 NodeCreated, so the narrow filter should match all
        assert_eq!(sim.would_match + sim.would_not_match, fire_count as u64);
    }

    // ================================================================
    // Test 9: Don't overwrite existing outcomes
    // ================================================================
    #[test]
    fn dont_overwrite_outcomes() {
        let (registry, sub_id) = setup_registry();
        let result = run_cascade(&registry);

        let mut tracker = SubscriptionTracker::new();
        tracker.record_cascade(&result, &registry);

        assert!(tracker.record_outcome(&sub_id, 0, SubscriptionOutcome::Confirmed));
        // Second recording should fail
        assert!(!tracker.record_outcome(&sub_id, 0, SubscriptionOutcome::Dismissed));

        let metrics = tracker.metrics(&sub_id).unwrap();
        assert_eq!(metrics.true_positives, 1);
        assert_eq!(metrics.false_positives, 0);
    }

    // ================================================================
    // Test 10: Worst performers ranking
    // ================================================================
    #[test]
    fn worst_performers_sorted() {
        let mut registry = SubscriptionRegistry::new();

        let good_sub = Subscription::new(
            "good",
            EventFilter::NodeCreated,
            100,
            Box::new(TagHandler { key: "good".into() }),
        );
        let good_id = good_sub.id.clone();
        registry.register(good_sub);

        let bad_sub = Subscription::new(
            "bad",
            EventFilter::NodeCreated,
            50,
            Box::new(TagHandler { key: "bad".into() }),
        );
        let bad_id = bad_sub.id.clone();
        registry.register(bad_sub);

        let mut tracker = SubscriptionTracker::new();

        for _ in 0..5 {
            let result = run_cascade(&registry);
            tracker.record_cascade(&result, &registry);
        }

        // Good sub: all confirmed. Bad sub: all dismissed.
        tracker.record_all_outcomes(&good_id, SubscriptionOutcome::Confirmed);
        tracker.record_all_outcomes(&bad_id, SubscriptionOutcome::Dismissed);

        let worst = tracker.worst_performers();
        assert!(worst.len() >= 2);
        // Bad sub should be first (highest FP rate)
        assert_eq!(worst[0].subscription_id, bad_id);
    }

    // ================================================================
    // Test 11: Empty tracker
    // ================================================================
    #[test]
    fn empty_tracker() {
        let tracker = SubscriptionTracker::new();
        assert_eq!(tracker.tracked_count(), 0);
        assert!(tracker.all_metrics().is_empty());
        assert!(tracker.worst_performers().is_empty());
        assert!(tracker.proposals().is_empty());
        assert!(tracker.pending_proposals().is_empty());
    }

    // ================================================================
    // Test 12: Pending outcomes count
    // ================================================================
    #[test]
    fn pending_outcomes_tracking() {
        let (registry, sub_id) = setup_registry();

        let mut tracker = SubscriptionTracker::new();

        for _ in 0..5 {
            let result = run_cascade(&registry);
            tracker.record_cascade(&result, &registry);
        }

        let metrics = tracker.metrics(&sub_id).unwrap();
        let total = metrics.total_fires;
        assert_eq!(metrics.pending_outcomes(), total);

        // Confirm one
        tracker.record_outcome(&sub_id, 0, SubscriptionOutcome::Confirmed);
        let metrics = tracker.metrics(&sub_id).unwrap();
        assert_eq!(metrics.pending_outcomes(), total - 1);
    }

    // ================================================================
    // Test 13: No duplicate proposals
    // ================================================================
    #[test]
    fn no_duplicate_proposals() {
        let (registry, sub_id) = setup_registry();

        let mut tracker = SubscriptionTracker::new()
            .with_min_fires(2)
            .with_fp_threshold(0.3);

        for _ in 0..5 {
            let result = run_cascade(&registry);
            tracker.record_cascade(&result, &registry);
        }

        tracker.record_all_outcomes(&sub_id, SubscriptionOutcome::Dismissed);

        // Generate proposals twice — should not create duplicates
        let p1 = tracker.generate_proposals();
        assert_eq!(p1.len(), 1);

        let p2 = tracker.generate_proposals();
        assert_eq!(p2.len(), 0); // Already has a pending proposal

        assert_eq!(tracker.proposals().len(), 1);
    }

    // ================================================================
    // Test 14: Integration — full evolution loop
    // ================================================================
    #[test]
    fn full_evolution_loop() {
        let (registry, sub_id) = setup_registry();

        let mut tracker = SubscriptionTracker::new()
            .with_min_fires(3)
            .with_fp_threshold(0.4);

        // Phase 1: Accumulate data
        for _ in 0..10 {
            let result = run_cascade(&registry);
            tracker.record_cascade(&result, &registry);
        }

        // Phase 2: Human provides feedback (mostly false positives)
        let fire_count = tracker.metrics(&sub_id).unwrap().fire_log.len();
        for i in 0..fire_count {
            if i < 2 {
                tracker.record_outcome(&sub_id, i, SubscriptionOutcome::Confirmed);
            } else {
                tracker.record_outcome(&sub_id, i, SubscriptionOutcome::Dismissed);
            }
        }

        // Phase 3: System generates proposals
        let proposals = tracker.generate_proposals();
        assert!(!proposals.is_empty(), "Should propose changes for high FP sub");

        // Phase 4: Human approves
        assert!(tracker.approve_proposal(0));

        // Phase 5: Verify state
        assert_eq!(tracker.proposals()[0].status, ProposalStatus::Approved);
        assert!(tracker.pending_proposals().is_empty());

        // Metrics should still be queryable
        let metrics = tracker.metrics(&sub_id).unwrap();
        assert!(metrics.precision().is_some());
        let precision = metrics.precision().unwrap();
        assert!(precision < 0.5, "Precision should be low: {}", precision);
    }

    // ================================================================
    // Test 15: Record a miss (false negative)
    // ================================================================
    #[test]
    fn records_miss() {
        let (registry, sub_id) = setup_registry();
        let result = run_cascade(&registry);

        let mut tracker = SubscriptionTracker::new();
        tracker.record_cascade(&result, &registry);

        // Record a missed event
        let missed_event_id = EventId::new();
        assert!(tracker.record_miss(&sub_id, missed_event_id.clone(), Some("incident #42".into())));

        let metrics = tracker.metrics(&sub_id).unwrap();
        assert_eq!(metrics.false_negatives, 1);
        assert_eq!(metrics.miss_log.len(), 1);
        assert_eq!(metrics.miss_log[0].missed_event_id, missed_event_id);
        assert_eq!(metrics.miss_log[0].reason, Some("incident #42".into()));
    }

    // ================================================================
    // Test 16: Recall calculation
    // ================================================================
    #[test]
    fn recall_calculation() {
        let (registry, sub_id) = setup_registry();

        let mut tracker = SubscriptionTracker::new();

        // Run cascades and mark as confirmed (true positives)
        for _ in 0..3 {
            let result = run_cascade(&registry);
            tracker.record_cascade(&result, &registry);
        }
        tracker.record_all_outcomes(&sub_id, SubscriptionOutcome::Confirmed);

        let metrics = tracker.metrics(&sub_id).unwrap();
        let tp = metrics.true_positives;

        // No misses → recall is 100%
        assert_eq!(metrics.recall(), Some(1.0));

        // Record 1 miss
        tracker.record_miss(&sub_id, EventId::new(), None);

        let metrics = tracker.metrics(&sub_id).unwrap();
        // recall = TP / (TP + FN) = tp / (tp + 1)
        let expected = tp as f64 / (tp as f64 + 1.0);
        assert!((metrics.recall().unwrap() - expected).abs() < 0.001);
    }

    // ================================================================
    // Test 17: No recall without data
    // ================================================================
    #[test]
    fn no_recall_without_data() {
        let tracker = SubscriptionTracker::new();
        // Unknown subscription → no metrics
        let id = SubscriptionId::new();
        assert!(tracker.metrics(&id).is_none());
    }

    // ================================================================
    // Test 18: Duplicate miss is rejected
    // ================================================================
    #[test]
    fn duplicate_miss_rejected() {
        let mut tracker = SubscriptionTracker::new();
        let sub_id = SubscriptionId::new();
        let event_id = EventId::new();

        assert!(tracker.record_miss(&sub_id, event_id.clone(), None));
        assert!(!tracker.record_miss(&sub_id, event_id.clone(), None));

        let metrics = tracker.metrics(&sub_id).unwrap();
        assert_eq!(metrics.false_negatives, 1);
    }

    // ================================================================
    // Test 19: Miss on untracked subscription initializes metrics
    // ================================================================
    #[test]
    fn miss_on_untracked_sub_initializes() {
        let mut tracker = SubscriptionTracker::new();
        let sub_id = SubscriptionId::new();

        // No fires recorded, but we can still record a miss
        assert!(tracker.record_miss(&sub_id, EventId::new(), None));
        assert_eq!(tracker.tracked_count(), 1);

        let metrics = tracker.metrics(&sub_id).unwrap();
        assert_eq!(metrics.total_fires, 0);
        assert_eq!(metrics.false_negatives, 1);
        // recall = 0 / (0 + 1) = 0
        assert_eq!(metrics.recall(), Some(0.0));
    }

    // ================================================================
    // Test 20: Autonomous false negative — anomaly with no subscription fire
    // ================================================================
    #[test]
    fn autonomous_false_negative_detection() {
        use crate::anomaly::{Anomaly, AnomalyKind};

        let (registry, sub_id) = setup_registry();
        let mut tracker = SubscriptionTracker::new();
        let mut log = EventLog::new();

        // Create an event that the subscription WOULD match (NodeCreated)
        // but we DON'T run it through the cascade — so no fire is recorded
        let node_id = NodeId::new();
        let event = Event::trigger(EventKind::NodeCreated {
            node_id: node_id.clone(),
            type_id: "ec2".to_string(),
            properties: HashMap::new(),
        });
        log.append(event.clone());

        // Simulate an anomaly detected on this node, referencing the event
        let anomaly = Anomaly {
            kind: AnomalyKind::StructuralOrphan {
                node_id: node_id.clone(),
                missing_edge_type: "in_vpc".to_string(),
            },
            description: "ec2 orphaned".to_string(),
            severity: 0.8,
            affected_nodes: vec![node_id.clone()],
            trigger_event: Some(event.id.clone()),
            detected_at: Utc::now(),
        };

        // Correlate: the subscription's filter matches NodeCreated,
        // and the anomaly's trigger event is a NodeCreated → should detect FN
        let misses = tracker.correlate_anomalies(&[anomaly], &log, &registry, 0.5);

        assert!(misses > 0, "Should detect autonomous false negative");

        let metrics = tracker.metrics(&sub_id).unwrap();
        assert!(metrics.false_negatives > 0);
        assert_eq!(metrics.miss_log.len(), metrics.false_negatives as usize);
        assert!(metrics.miss_log[0].reason.as_ref().unwrap().contains("Autonomous"));
    }

    // ================================================================
    // Test 21: No FN when subscription actually fired
    // ================================================================
    #[test]
    fn no_fn_when_subscription_fired() {
        use crate::anomaly::{Anomaly, AnomalyKind};

        let (registry, sub_id) = setup_registry();
        let mut tracker = SubscriptionTracker::new();
        let mut log = EventLog::new();

        // Run a cascade — subscription fires and is recorded
        let result = run_cascade(&registry);
        tracker.record_cascade(&result, &registry);
        for event in &result.events {
            log.append(event.clone());
        }

        // Now an anomaly is detected on the same event
        let trigger_event = &result.events[0];
        let anomaly = Anomaly {
            kind: AnomalyKind::CascadeAmplification {
                cascade_event_count: 100,
                cascade_depth: 10,
                normal_max_count: 5,
                normal_max_depth: 3,
            },
            description: "cascade too big".to_string(),
            severity: 0.9,
            affected_nodes: vec![],
            trigger_event: Some(trigger_event.id.clone()),
            detected_at: Utc::now(),
        };

        // Correlate: subscription DID fire → no false negative
        let misses = tracker.correlate_anomalies(&[anomaly], &log, &registry, 0.5);
        assert_eq!(misses, 0);

        let metrics = tracker.metrics(&sub_id).unwrap();
        assert_eq!(metrics.false_negatives, 0);
    }

    // ================================================================
    // Test 22: Anomaly below severity threshold is ignored
    // ================================================================
    #[test]
    fn anomaly_below_threshold_ignored() {
        use crate::anomaly::{Anomaly, AnomalyKind};

        let (registry, _sub_id) = setup_registry();
        let mut tracker = SubscriptionTracker::new();
        let mut log = EventLog::new();

        let event = Event::trigger(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "ec2".to_string(),
            properties: HashMap::new(),
        });
        log.append(event.clone());

        let anomaly = Anomaly {
            kind: AnomalyKind::StructuralOrphan {
                node_id: NodeId::new(),
                missing_edge_type: "x".to_string(),
            },
            description: "low severity".to_string(),
            severity: 0.2, // Below threshold
            affected_nodes: vec![],
            trigger_event: Some(event.id.clone()),
            detected_at: Utc::now(),
        };

        let misses = tracker.correlate_anomalies(&[anomaly], &log, &registry, 0.5);
        assert_eq!(misses, 0);
    }

    // ================================================================
    // Test 23: Anomaly with affected_nodes but no trigger_event
    // ================================================================
    #[test]
    fn anomaly_with_affected_nodes_only() {
        use crate::anomaly::{Anomaly, AnomalyKind};

        let (registry, sub_id) = setup_registry();
        let mut tracker = SubscriptionTracker::new();
        let mut log = EventLog::new();

        let node_id = NodeId::new();
        let event = Event::trigger(EventKind::NodeCreated {
            node_id: node_id.clone(),
            type_id: "ec2".to_string(),
            properties: HashMap::new(),
        });
        log.append(event.clone());

        // Anomaly with affected_nodes but no trigger_event (batch-detected)
        let anomaly = Anomaly {
            kind: AnomalyKind::TemporalDrift {
                node_id: node_id.clone(),
                property: "trust".to_string(),
                direction: crate::anomaly::DriftDirection::Decreasing,
                data_points: 10,
                duration_secs: 3600,
            },
            description: "trust drifting".to_string(),
            severity: 0.7,
            affected_nodes: vec![node_id.clone()],
            trigger_event: None, // No trigger — batch detected
            detected_at: Utc::now(),
        };

        let misses = tracker.correlate_anomalies(&[anomaly], &log, &registry, 0.5);
        assert!(misses > 0, "Should find events on affected nodes and detect FN");

        let metrics = tracker.metrics(&sub_id).unwrap();
        assert!(metrics.false_negatives > 0);
    }

    // ================================================================
    // Test 24: Apply mutation — changes the filter in the registry
    // ================================================================
    #[test]
    fn apply_mutation_changes_filter() {
        let (mut registry, sub_id) = setup_registry();

        let mut tracker = SubscriptionTracker::new()
            .with_min_fires(2)
            .with_fp_threshold(0.3);

        // Run cascades and dismiss all → high FP rate
        for _ in 0..5 {
            let result = run_cascade(&registry);
            tracker.record_cascade(&result, &registry);
        }
        tracker.record_all_outcomes(&sub_id, SubscriptionOutcome::Dismissed);

        // Generate proposals
        tracker.generate_proposals();
        assert!(!tracker.proposals().is_empty());

        // Approve the proposal
        assert!(tracker.approve_proposal(0));

        // Set a proposed filter on the proposal (normally generate_proposals or
        // simulate_filter would set this, but for the test we set it directly)
        tracker.proposals[0].proposed_filter = Some(EventFilter::And(vec![
            EventFilter::NodeCreated,
            EventFilter::NodeType("ec2".to_string()),
        ]));

        // Apply it
        assert!(tracker.apply_mutation(0, &mut registry));
        assert_eq!(tracker.proposals()[0].status, ProposalStatus::Applied);

        // Verify the filter actually changed in the registry
        let sub = registry.get(&sub_id).unwrap();
        assert!(matches!(sub.filter, EventFilter::And(_)));
    }

    // ================================================================
    // Test 25: Apply fails if not approved
    // ================================================================
    #[test]
    fn apply_mutation_fails_if_not_approved() {
        let (mut registry, sub_id) = setup_registry();

        let mut tracker = SubscriptionTracker::new()
            .with_min_fires(2)
            .with_fp_threshold(0.3);

        for _ in 0..5 {
            let result = run_cascade(&registry);
            tracker.record_cascade(&result, &registry);
        }
        tracker.record_all_outcomes(&sub_id, SubscriptionOutcome::Dismissed);
        tracker.generate_proposals();

        // Still in Proposed status — not approved
        tracker.proposals[0].proposed_filter = Some(EventFilter::NodeDeleted);
        assert!(!tracker.apply_mutation(0, &mut registry));

        // Filter unchanged
        let sub = registry.get(&sub_id).unwrap();
        assert!(matches!(sub.filter, EventFilter::NodeCreated));
    }

    // ================================================================
    // Test 26: Apply fails if no proposed_filter
    // ================================================================
    #[test]
    fn apply_mutation_fails_without_proposed_filter() {
        let (mut registry, sub_id) = setup_registry();

        let mut tracker = SubscriptionTracker::new()
            .with_min_fires(2)
            .with_fp_threshold(0.3);

        for _ in 0..5 {
            let result = run_cascade(&registry);
            tracker.record_cascade(&result, &registry);
        }
        tracker.record_all_outcomes(&sub_id, SubscriptionOutcome::Dismissed);
        tracker.generate_proposals();
        tracker.approve_proposal(0);

        // proposed_filter is None (default from generate_proposals)
        assert!(!tracker.apply_mutation(0, &mut registry));
        assert_eq!(tracker.proposals()[0].status, ProposalStatus::Approved); // unchanged
    }

    // ================================================================
    // Test 27: Registry set_filter works
    // ================================================================
    #[test]
    fn registry_set_filter() {
        let (mut registry, sub_id) = setup_registry();

        // Original filter is NodeCreated
        let sub = registry.get(&sub_id).unwrap();
        assert!(matches!(sub.filter, EventFilter::NodeCreated));

        // Change it
        assert!(registry.set_filter(&sub_id, EventFilter::NodeDeleted));

        // Verify
        let sub = registry.get(&sub_id).unwrap();
        assert!(matches!(sub.filter, EventFilter::NodeDeleted));

        // Non-existent ID fails
        assert!(!registry.set_filter(&SubscriptionId::new(), EventFilter::Any));
    }
}
