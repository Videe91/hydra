use crate::cascade::CascadeResult;
use crate::counterfactual::{counterfactual_filter, diff_projections};
use crate::event_log::EventLog;
use crate::projection::Projection;
use crate::temporal::TemporalIndex;
use hydra_core::event::Value;
use hydra_core::graph::GraphReader;
use hydra_core::id::{EventId, NodeId};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ============================================================================
// Anomaly Types
// ============================================================================

/// A detected anomaly — the output of the detection engine.
/// Anomalies are reports, not events. The caller decides whether to
/// inject them as Signal events into the cascade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// What kind of anomaly was detected
    pub kind: AnomalyKind,
    /// Human-readable description
    pub description: String,
    /// Severity: 0.0 (informational) to 1.0 (critical)
    pub severity: f64,
    /// Which node(s) are involved
    pub affected_nodes: Vec<NodeId>,
    /// Which event triggered the detection (if real-time)
    pub trigger_event: Option<EventId>,
    /// When the anomaly was detected
    pub detected_at: DateTime<Utc>,
}

impl AnomalyKind {
    /// Stable snake_case discriminant string. Matches the serde
    /// `rename_all = "snake_case"` wire form, so query strings like
    /// `?kind=topology_degree` round-trip cleanly to a single arm.
    pub fn kind_name(&self) -> &'static str {
        match self {
            AnomalyKind::TopologyDegree { .. } => "topology_degree",
            AnomalyKind::CascadeAmplification { .. } => "cascade_amplification",
            AnomalyKind::TemporalDrift { .. } => "temporal_drift",
            AnomalyKind::ChangeRateAnomaly { .. } => "change_rate_anomaly",
            AnomalyKind::StructuralOrphan { .. } => "structural_orphan",
            AnomalyKind::TimeWindowViolation { .. } => "time_window_violation",
            AnomalyKind::CounterfactualOutlier { .. } => "counterfactual_outlier",
            AnomalyKind::ForbiddenPattern { .. } => "forbidden_pattern",
        }
    }
}

impl Anomaly {
    /// Deterministic stable id for this anomaly, derived from its
    /// content (kind discriminant + affected_nodes + description).
    /// The same logical anomaly recomputed in a later batch returns
    /// the same id — so operators can acknowledge / mute / track /
    /// correlate by id even though anomalies themselves are
    /// ephemeral (no persistence in v0). Prefixed `anom_` so it
    /// sorts/groups visually alongside the other id types.
    pub fn stable_id(&self) -> String {
        let mut hasher = DefaultHasher::new();
        // Use the kind's Debug rendering as a stable discriminator —
        // includes the variant name AND its inner field values, so
        // two anomalies on the same node with different rule outputs
        // get different ids. Plus affected_nodes (sorted via the
        // Vec's order, which the engine produces deterministically)
        // and description.
        format!("{:?}", self.kind).hash(&mut hasher);
        for node in &self.affected_nodes {
            node.as_str().hash(&mut hasher);
        }
        self.description.hash(&mut hasher);
        let h = hasher.finish();
        format!("anom_{h:016x}")
    }
}

/// Categories of anomaly
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "details", rename_all = "snake_case")]
pub enum AnomalyKind {
    /// A node's edge count violates expected topology
    TopologyDegree {
        node_id: NodeId,
        edge_type: String,
        expected_min: u32,
        expected_max: u32,
        actual: u32,
    },
    /// A cascade was abnormally large or deep
    CascadeAmplification {
        cascade_event_count: usize,
        cascade_depth: u32,
        normal_max_count: usize,
        normal_max_depth: u32,
    },
    /// A property is drifting monotonically over time
    TemporalDrift {
        node_id: NodeId,
        property: String,
        direction: DriftDirection,
        data_points: usize,
        duration_secs: i64,
    },
    /// A node's change rate is abnormal
    ChangeRateAnomaly {
        node_id: NodeId,
        changes_in_window: usize,
        normal_max: usize,
        window_secs: i64,
    },
    /// A node was orphaned — lost all edges of an expected type
    StructuralOrphan {
        node_id: NodeId,
        missing_edge_type: String,
    },
    /// Changes happened outside the expected time window
    TimeWindowViolation {
        node_id: NodeId,
        /// The hour (UTC, 0-23) when the offending change occurred
        change_hour: u32,
        /// Expected window start hour (UTC, 0-23)
        expected_start_hour: u32,
        /// Expected window end hour (UTC, 0-23)
        expected_end_hour: u32,
        /// How many changes fell outside the window
        violations: usize,
        /// Total changes inspected
        total_changes: usize,
    },
    /// A single source (node) is responsible for an outsized fraction of graph state.
    /// Detected by counterfactual analysis: removing all events targeting this node
    /// causes a disproportionate graph diff.
    CounterfactualOutlier {
        /// The node whose events were removed
        source_node: NodeId,
        /// How many events were in the removal set (root + causal subtree)
        events_removed: usize,
        /// How many graph elements differ in the counterfactual world
        graph_elements_affected: usize,
        /// What fraction of all events came from this source
        removal_fraction: f64,
    },
    /// A forbidden multi-node graph pattern was matched.
    /// Example: admin account → broad permissions → backup config changes.
    ForbiddenPattern {
        /// The anchor node where the pattern starts
        anchor_node: NodeId,
        /// Name of the pattern rule that matched
        pattern_name: String,
        /// How many target nodes the anchor fans out to
        fan_out: usize,
        /// IDs of the matched target nodes
        matched_targets: Vec<NodeId>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftDirection {
    Increasing,
    Decreasing,
}

// ============================================================================
// Rules — Configurable detection parameters
// ============================================================================

/// A topology rule: "nodes of type X should have between min and max edges of type Y"
#[derive(Debug, Clone)]
pub struct TopologyRule {
    /// Which node type this rule applies to
    pub node_type: String,
    /// Which edge type to count
    pub edge_type: String,
    /// Expected minimum degree (0 = no minimum)
    pub min_degree: u32,
    /// Expected maximum degree (u32::MAX = no maximum)
    pub max_degree: u32,
    /// Severity if violated (0.0 - 1.0)
    pub severity: f64,
}

/// A cascade rule: "cascades should normally produce at most N events and reach depth D"
#[derive(Debug, Clone)]
pub struct CascadeRule {
    /// Maximum events before flagging as amplification
    pub max_event_count: usize,
    /// Maximum depth before flagging
    pub max_depth: u32,
    /// Severity if violated
    pub severity: f64,
}

impl Default for CascadeRule {
    fn default() -> Self {
        Self {
            max_event_count: 50,
            max_depth: 10,
            severity: 0.7,
        }
    }
}

/// A temporal drift rule: "property X on node type Y should not drift monotonically
/// for more than N data points"
#[derive(Debug, Clone)]
pub struct DriftRule {
    /// Which node type this rule applies to
    pub node_type: String,
    /// Which property to monitor
    pub property: String,
    /// How many consecutive monotonic changes before flagging
    pub min_consecutive: usize,
    /// Severity if violated
    pub severity: f64,
}

/// A change rate rule: "nodes of type X should not change more than N times in W seconds"
#[derive(Debug, Clone)]
pub struct ChangeRateRule {
    /// Which node type this rule applies to
    pub node_type: String,
    /// Maximum changes in the window
    pub max_changes: usize,
    /// Window duration in seconds
    pub window_secs: i64,
    /// Severity if violated
    pub severity: f64,
}

/// A time window rule: "changes to nodes of type X should only happen
/// between hour A and hour B (UTC). Changes outside this window are anomalous."
///
/// Handles wraparound: start_hour=22, end_hour=4 means 10pm-4am UTC is normal.
/// The window is inclusive on both ends.
#[derive(Debug, Clone)]
pub struct TimeWindowRule {
    /// Which node type this rule applies to
    pub node_type: String,
    /// Start of the normal window (UTC hour, 0-23)
    pub start_hour: u32,
    /// End of the normal window (UTC hour, 0-23)
    pub end_hour: u32,
    /// How many out-of-window changes are tolerated before flagging
    pub tolerance: usize,
    /// How far back to look (seconds). 0 = all history.
    pub lookback_secs: i64,
    /// Severity if violated
    pub severity: f64,
}

/// A counterfactual anomaly rule: "if removing all events targeting a single node
/// changes more than X% of the graph, that node is an outsized influence — possible
/// compromised credential or misconfigured automation."
///
/// This is an expensive check (O(N × E) per candidate node). It runs only in
/// batch mode, not real-time, and only checks nodes of the specified type.
#[derive(Debug, Clone)]
pub struct CounterfactualRule {
    /// Which node type to analyze as potential outlier sources
    pub node_type: String,
    /// Minimum fraction of events removed to flag as anomalous (0.0-1.0).
    /// Example: 0.3 = if removing events for one node removes >30% of all events
    pub min_removal_fraction: f64,
    /// Minimum graph elements affected in the diff to flag
    pub min_graph_impact: usize,
    /// Severity if violated
    pub severity: f64,
}

/// A predicate on a node's properties. Used by PatternRule to constrain
/// which target nodes count as matches.
#[derive(Debug, Clone)]
pub enum PropertyPredicate {
    /// Property exists (any value)
    Exists(String),
    /// Property equals a specific value
    Equals(String, Value),
    /// Property is a number greater than threshold
    GreaterThan(String, f64),
    /// Property is a number less than threshold
    LessThan(String, f64),
    /// All sub-predicates must match
    All(Vec<PropertyPredicate>),
    /// At least one sub-predicate must match
    Any(Vec<PropertyPredicate>),
}

impl PropertyPredicate {
    /// Test whether a node's properties satisfy this predicate
    pub fn matches(&self, node: &hydra_core::node::Node) -> bool {
        match self {
            PropertyPredicate::Exists(key) => node.get(key).is_some(),
            PropertyPredicate::Equals(key, expected) => {
                node.get(key).map_or(false, |v| v == expected)
            }
            PropertyPredicate::GreaterThan(key, threshold) => {
                match node.get(key) {
                    Some(Value::Int(n)) => {
                        let t = *threshold;
                        // If threshold is a whole number that fits in i64, compare as integers
                        // to avoid f64 precision loss for large values
                        if t.fract() == 0.0 && t >= i64::MIN as f64 && t <= i64::MAX as f64 {
                            *n > t as i64
                        } else {
                            (*n as f64) > t
                        }
                    }
                    Some(Value::Float(n)) => *n > *threshold,
                    _ => false,
                }
            }
            PropertyPredicate::LessThan(key, threshold) => {
                match node.get(key) {
                    Some(Value::Int(n)) => {
                        let t = *threshold;
                        if t.fract() == 0.0 && t >= i64::MIN as f64 && t <= i64::MAX as f64 {
                            *n < t as i64
                        } else {
                            (*n as f64) < t
                        }
                    }
                    Some(Value::Float(n)) => *n < *threshold,
                    _ => false,
                }
            }
            PropertyPredicate::All(preds) => preds.iter().all(|p| p.matches(node)),
            PropertyPredicate::Any(preds) => preds.iter().any(|p| p.matches(node)),
        }
    }
}

/// A forbidden graph pattern rule: "if a node of type A has N+ edges of type E
/// to nodes of type B (optionally matching a property predicate), flag it."
///
/// This is an anchored hub-and-spoke pattern — the anchor node fans out via
/// edges to target nodes. Covers the Ripple doc's examples:
/// - "admin → has_permission → resource" (fan-out attack)
/// - "user → modified → backup_config" (suspicious config changes)
///
/// Checked in both real-time (on cascade-affected nodes) and batch (all anchors).
#[derive(Debug, Clone)]
pub struct PatternRule {
    /// Human-readable name for this pattern
    pub name: String,
    /// Anchor node type (the "from" node)
    pub anchor_type: String,
    /// Edge type to follow from anchor to targets
    pub edge_type: String,
    /// Target node type (the "to" nodes)
    pub target_type: String,
    /// Minimum fan-out (number of matching targets) to trigger
    pub min_fan_out: usize,
    /// Optional property predicate on target nodes
    pub target_predicate: Option<PropertyPredicate>,
    /// Optional property predicate on the anchor node itself
    pub anchor_predicate: Option<PropertyPredicate>,
    /// Severity if the pattern matches
    pub severity: f64,
}

// ============================================================================
// The Engine
// ============================================================================

/// The anomaly detection engine. Configured with rules, runs detection
/// against the current graph state, event log, and temporal index.
///
/// Design: standalone, not a SubscriptionHandler. Called by Hydra after
/// each cascade completes. Produces Anomaly reports that the caller
/// can optionally inject as Signal events. This prevents feedback loops.
pub struct AnomalyEngine {
    topology_rules: Vec<TopologyRule>,
    cascade_rule: CascadeRule,
    drift_rules: Vec<DriftRule>,
    change_rate_rules: Vec<ChangeRateRule>,
    time_window_rules: Vec<TimeWindowRule>,
    counterfactual_rules: Vec<CounterfactualRule>,
    pattern_rules: Vec<PatternRule>,
}

impl AnomalyEngine {
    pub fn new() -> Self {
        Self {
            topology_rules: Vec::new(),
            cascade_rule: CascadeRule::default(),
            drift_rules: Vec::new(),
            change_rate_rules: Vec::new(),
            time_window_rules: Vec::new(),
            counterfactual_rules: Vec::new(),
            pattern_rules: Vec::new(),
        }
    }

    pub fn with_cascade_rule(mut self, rule: CascadeRule) -> Self {
        self.cascade_rule = rule;
        self
    }

    pub fn add_topology_rule(&mut self, rule: TopologyRule) {
        self.topology_rules.push(rule);
    }

    pub fn add_drift_rule(&mut self, rule: DriftRule) {
        self.drift_rules.push(rule);
    }

    pub fn add_change_rate_rule(&mut self, rule: ChangeRateRule) {
        self.change_rate_rules.push(rule);
    }

    /// # Panics
    /// Panics if `start_hour` or `end_hour` is >= 24.
    pub fn add_time_window_rule(&mut self, rule: TimeWindowRule) {
        assert!(rule.start_hour < 24, "start_hour must be 0-23, got {}", rule.start_hour);
        assert!(rule.end_hour < 24, "end_hour must be 0-23, got {}", rule.end_hour);
        self.time_window_rules.push(rule);
    }

    pub fn add_counterfactual_rule(&mut self, rule: CounterfactualRule) {
        self.counterfactual_rules.push(rule);
    }

    pub fn add_pattern_rule(&mut self, rule: PatternRule) {
        self.pattern_rules.push(rule);
    }

    /// Total number of configured rules
    pub fn rule_count(&self) -> usize {
        self.topology_rules.len()
            + 1 // cascade rule always exists
            + self.drift_rules.len()
            + self.change_rate_rules.len()
            + self.time_window_rules.len()
            + self.counterfactual_rules.len()
            + self.pattern_rules.len()
    }

    // ========================================================================
    // Real-time detection: called after each cascade completes
    // ========================================================================

    /// Analyze a cascade result for anomalies.
    /// Called after every Hydra::ingest(). Fast path — only checks cascade
    /// behavior and topology of affected nodes.
    pub fn analyze_cascade(
        &self,
        result: &CascadeResult,
        graph: &dyn GraphReader,
    ) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        let now = Utc::now();

        // --- Cascade amplification ---
        self.check_cascade_amplification(result, now, &mut anomalies);

        // --- Topology checks on affected nodes ---
        self.check_topology_for_cascade(result, graph, now, &mut anomalies);

        // --- Pattern checks on affected nodes ---
        self.check_patterns_for_cascade(result, graph, now, &mut anomalies);

        anomalies
    }

    /// Check if a cascade was abnormally large or deep
    fn check_cascade_amplification(
        &self,
        result: &CascadeResult,
        now: DateTime<Utc>,
        anomalies: &mut Vec<Anomaly>,
    ) {
        let event_count = result.events.len();
        let depth = result.max_depth_reached;
        let rule = &self.cascade_rule;

        if event_count > rule.max_event_count || depth > rule.max_depth {
            let trigger_id = result.events.first().map(|e| e.id.clone());
            anomalies.push(Anomaly {
                kind: AnomalyKind::CascadeAmplification {
                    cascade_event_count: event_count,
                    cascade_depth: depth,
                    normal_max_count: rule.max_event_count,
                    normal_max_depth: rule.max_depth,
                },
                description: format!(
                    "Cascade produced {} events (max {}) at depth {} (max {})",
                    event_count, rule.max_event_count, depth, rule.max_depth
                ),
                severity: rule.severity,
                affected_nodes: Vec::new(),
                trigger_event: trigger_id,
                detected_at: now,
            });
        }
    }

    /// Check topology rules for nodes affected by a cascade
    fn check_topology_for_cascade(
        &self,
        result: &CascadeResult,
        graph: &dyn GraphReader,
        now: DateTime<Utc>,
        anomalies: &mut Vec<Anomaly>,
    ) {
        if self.topology_rules.is_empty() {
            return;
        }

        // Collect unique node IDs affected by this cascade
        let mut affected_nodes: Vec<NodeId> = Vec::new();
        for event in &result.events {
            if let Some(node_id) = event.kind.target_node() {
                if !affected_nodes.contains(node_id) {
                    affected_nodes.push(node_id.clone());
                }
            }
        }

        // Check topology rules for each affected node
        for node_id in &affected_nodes {
            if let Some(node) = graph.node(node_id) {
                if !node.is_alive() {
                    continue;
                }
                for rule in &self.topology_rules {
                    if node.type_id() != rule.node_type {
                        continue;
                    }
                    let degree = graph
                        .outgoing_edges_of_type(node_id, &rule.edge_type)
                        .len() as u32
                        + graph
                            .incoming_edges_of_type(node_id, &rule.edge_type)
                            .len() as u32;

                    if degree < rule.min_degree || degree > rule.max_degree {
                        anomalies.push(Anomaly {
                            kind: AnomalyKind::TopologyDegree {
                                node_id: node_id.clone(),
                                edge_type: rule.edge_type.clone(),
                                expected_min: rule.min_degree,
                                expected_max: rule.max_degree,
                                actual: degree,
                            },
                            description: format!(
                                "{} {} has {} '{}' edges (expected {}-{})",
                                rule.node_type, node_id, degree,
                                rule.edge_type, rule.min_degree, rule.max_degree
                            ),
                            severity: rule.severity,
                            affected_nodes: vec![node_id.clone()],
                            trigger_event: result.events.first().map(|e| e.id.clone()),
                            detected_at: now,
                        });
                    }
                }
            }
        }
    }

    // ========================================================================
    // Batch detection: called periodically (e.g., every minute or on-demand)
    // ========================================================================

    /// Run all batch anomaly checks across the entire graph.
    /// More expensive than analyze_cascade — scans all nodes against all rules.
    ///
    /// Takes `&Projection` (not `&dyn GraphReader`) because the counterfactual
    /// check needs the concrete Projection for `diff_projections`. Projection
    /// implements `GraphReader`, so topology checks still work.
    pub fn analyze_batch(
        &self,
        projection: &Projection,
        temporal: &TemporalIndex,
        event_log: &EventLog,
    ) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        let now = Utc::now();

        // --- Topology: scan all nodes against topology rules ---
        self.check_topology_batch(projection, now, &mut anomalies);

        // --- Temporal drift: check trending properties ---
        self.check_drift_batch(temporal, now, &mut anomalies);

        // --- Change rate: check for abnormally active nodes ---
        self.check_change_rate_batch(temporal, now, &mut anomalies);

        // --- Time window: check for changes outside expected hours ---
        self.check_time_window_batch(temporal, now, &mut anomalies);

        // --- Counterfactual: check for nodes with outsized graph influence ---
        self.check_counterfactual_batch(projection, event_log, now, &mut anomalies);

        // --- Forbidden patterns: check all anchor nodes against pattern rules ---
        self.check_patterns_batch(projection, now, &mut anomalies);

        anomalies
    }

    /// Check all topology rules across all nodes of each rule's target type
    fn check_topology_batch(
        &self,
        graph: &dyn GraphReader,
        now: DateTime<Utc>,
        anomalies: &mut Vec<Anomaly>,
    ) {
        for rule in &self.topology_rules {
            let nodes = graph.nodes_by_type(&rule.node_type);
            for node in nodes {
                let node_id = node.id();
                let degree = graph
                    .outgoing_edges_of_type(node_id, &rule.edge_type)
                    .len() as u32
                    + graph
                        .incoming_edges_of_type(node_id, &rule.edge_type)
                        .len() as u32;

                if degree < rule.min_degree || degree > rule.max_degree {
                    // Check for orphan specifically
                    let kind = if degree == 0 && rule.min_degree > 0 {
                        AnomalyKind::StructuralOrphan {
                            node_id: node_id.clone(),
                            missing_edge_type: rule.edge_type.clone(),
                        }
                    } else {
                        AnomalyKind::TopologyDegree {
                            node_id: node_id.clone(),
                            edge_type: rule.edge_type.clone(),
                            expected_min: rule.min_degree,
                            expected_max: rule.max_degree,
                            actual: degree,
                        }
                    };

                    anomalies.push(Anomaly {
                        kind,
                        description: format!(
                            "{} {} has {} '{}' edges (expected {}-{})",
                            rule.node_type, node_id, degree,
                            rule.edge_type, rule.min_degree, rule.max_degree
                        ),
                        severity: rule.severity,
                        affected_nodes: vec![node_id.clone()],
                        trigger_event: None,
                        detected_at: now,
                    });
                }
            }
        }
    }

    /// Check temporal drift rules: detect monotonic trends in numeric properties
    fn check_drift_batch(
        &self,
        temporal: &TemporalIndex,
        now: DateTime<Utc>,
        anomalies: &mut Vec<Anomaly>,
    ) {
        for rule in &self.drift_rules {
            // We need to iterate all nodes of this type.
            // TemporalIndex stores by NodeId, not by type. We iterate all
            // node histories and filter by type.
            for (node_id, history) in temporal.iter_nodes() {
                if history.type_id != rule.node_type {
                    continue;
                }

                let trend = history.trend(&rule.property);
                if trend.len() < rule.min_consecutive {
                    continue;
                }

                // Check the last N data points for monotonic trend
                let recent = &trend[trend.len().saturating_sub(rule.min_consecutive + 1)..];
                if let Some(direction) = detect_monotonic_trend(recent) {
                    let first_ts = recent.first().map(|(t, _)| *t).unwrap_or(now);
                    let last_ts = recent.last().map(|(t, _)| *t).unwrap_or(now);
                    let duration_secs = (last_ts - first_ts).num_seconds();

                    anomalies.push(Anomaly {
                        kind: AnomalyKind::TemporalDrift {
                            node_id: node_id.clone(),
                            property: rule.property.clone(),
                            direction,
                            data_points: recent.len(),
                            duration_secs,
                        },
                        description: format!(
                            "{} {} property '{}' has been monotonically changing for {} data points",
                            rule.node_type, node_id, rule.property, recent.len()
                        ),
                        severity: rule.severity,
                        affected_nodes: vec![node_id.clone()],
                        trigger_event: None,
                        detected_at: now,
                    });
                }
            }
        }
    }

    /// Check change rate rules: detect abnormally active nodes
    fn check_change_rate_batch(
        &self,
        temporal: &TemporalIndex,
        now: DateTime<Utc>,
        anomalies: &mut Vec<Anomaly>,
    ) {
        for rule in &self.change_rate_rules {
            let window_start = now - Duration::seconds(rule.window_secs);

            for (node_id, history) in temporal.iter_nodes() {
                if history.type_id != rule.node_type {
                    continue;
                }

                // Count property versions within the window
                let changes: usize = history
                    .properties
                    .values()
                    .flat_map(|versions| versions.iter())
                    .filter(|v| v.effective_from >= window_start && v.effective_from <= now)
                    .count();

                if changes > rule.max_changes {
                    anomalies.push(Anomaly {
                        kind: AnomalyKind::ChangeRateAnomaly {
                            node_id: node_id.clone(),
                            changes_in_window: changes,
                            normal_max: rule.max_changes,
                            window_secs: rule.window_secs,
                        },
                        description: format!(
                            "{} {} changed {} times in {} seconds (max {})",
                            rule.node_type, node_id, changes,
                            rule.window_secs, rule.max_changes
                        ),
                        severity: rule.severity,
                        affected_nodes: vec![node_id.clone()],
                        trigger_event: None,
                        detected_at: now,
                    });
                }
            }
        }
    }

    /// Check time window rules: detect changes that happened outside expected hours.
    /// Uses chrono::Timelike to extract the UTC hour from each property version's timestamp.
    fn check_time_window_batch(
        &self,
        temporal: &TemporalIndex,
        now: DateTime<Utc>,
        anomalies: &mut Vec<Anomaly>,
    ) {
        use chrono::Timelike;

        for rule in &self.time_window_rules {
            let lookback_start = if rule.lookback_secs > 0 {
                now - Duration::seconds(rule.lookback_secs)
            } else {
                DateTime::<Utc>::MIN_UTC
            };

            for (node_id, history) in temporal.iter_nodes() {
                if history.type_id != rule.node_type {
                    continue;
                }

                let mut total_changes = 0usize;
                let mut violations = 0usize;
                let mut worst_hour: Option<u32> = None;

                // Scan all property versions in the lookback window
                for versions in history.properties.values() {
                    for version in versions {
                        if version.effective_from < lookback_start {
                            continue;
                        }
                        if version.effective_from > now {
                            continue;
                        }

                        total_changes += 1;
                        let hour = version.effective_from.hour();

                        if !is_in_time_window(hour, rule.start_hour, rule.end_hour) {
                            violations += 1;
                            if worst_hour.is_none() {
                                worst_hour = Some(hour);
                            }
                        }
                    }
                }

                if violations > rule.tolerance {
                    anomalies.push(Anomaly {
                        kind: AnomalyKind::TimeWindowViolation {
                            node_id: node_id.clone(),
                            change_hour: worst_hour.unwrap_or(0),
                            expected_start_hour: rule.start_hour,
                            expected_end_hour: rule.end_hour,
                            violations,
                            total_changes,
                        },
                        description: format!(
                            "{} {} had {} changes outside the {}-{} UTC window ({} total changes)",
                            rule.node_type, node_id, violations,
                            rule.start_hour, rule.end_hour, total_changes
                        ),
                        severity: rule.severity,
                        affected_nodes: vec![node_id.clone()],
                        trigger_event: None,
                        detected_at: now,
                    });
                }
            }
        }
    }

    /// Check counterfactual rules: for each candidate node type, remove all events
    /// targeting each node and measure the graph diff. Nodes with outsized impact
    /// are flagged as counterfactual outliers.
    ///
    /// This is the most expensive check — O(N × E) per node type where N = nodes
    /// of that type and E = total events. Only runs in batch mode.
    fn check_counterfactual_batch(
        &self,
        actual_proj: &Projection,
        event_log: &EventLog,
        now: DateTime<Utc>,
        anomalies: &mut Vec<Anomaly>,
    ) {
        if self.counterfactual_rules.is_empty() || event_log.len() == 0 {
            return;
        }

        for rule in &self.counterfactual_rules {
            let nodes = actual_proj.nodes_by_type(&rule.node_type);

            for node in nodes {
                let node_id = node.id().clone();

                // Run counterfactual: remove all events targeting this node
                let cf_result = counterfactual_filter(event_log, &|event| {
                    event.kind.target_node() == Some(&node_id)
                });

                if cf_result.roots_matched == 0 {
                    continue;
                }

                let removal_fraction = cf_result.removal_fraction();
                let diff = diff_projections(actual_proj, &cf_result.projection);
                let graph_impact = diff.total_affected();

                if removal_fraction >= rule.min_removal_fraction
                    || graph_impact >= rule.min_graph_impact
                {
                    anomalies.push(Anomaly {
                        kind: AnomalyKind::CounterfactualOutlier {
                            source_node: node_id.clone(),
                            events_removed: cf_result.events_removed,
                            graph_elements_affected: graph_impact,
                            removal_fraction,
                        },
                        description: format!(
                            "{} {} accounts for {:.0}% of events ({} removed). \
                             Removing them changes {} graph elements.",
                            rule.node_type, node_id,
                            removal_fraction * 100.0,
                            cf_result.events_removed,
                            graph_impact,
                        ),
                        severity: rule.severity,
                        affected_nodes: vec![node_id],
                        trigger_event: None,
                        detected_at: now,
                    });
                }
            }
        }
    }

    /// Core pattern matching logic: check one node against all pattern rules.
    /// Returns anomalies for any matching patterns.
    fn match_patterns_for_node(
        &self,
        node: &hydra_core::node::Node,
        graph: &dyn GraphReader,
        now: DateTime<Utc>,
        trigger_event: Option<&EventId>,
    ) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        for rule in &self.pattern_rules {
            if node.type_id() != rule.anchor_type {
                continue;
            }

            // Check anchor predicate (if any)
            if let Some(ref pred) = rule.anchor_predicate {
                if !pred.matches(node) {
                    continue;
                }
            }

            // Follow edges of the specified type from this anchor
            let edges = graph.outgoing_edges_of_type(node.id(), &rule.edge_type);

            // Filter targets by type and predicate
            let mut matched_targets: Vec<NodeId> = Vec::new();
            for edge in &edges {
                if let Some(target) = graph.node(edge.target()) {
                    if !target.is_alive() || target.type_id() != rule.target_type {
                        continue;
                    }
                    if let Some(ref pred) = rule.target_predicate {
                        if !pred.matches(target) {
                            continue;
                        }
                    }
                    matched_targets.push(target.id().clone());
                }
            }

            if matched_targets.len() >= rule.min_fan_out {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::ForbiddenPattern {
                        anchor_node: node.id().clone(),
                        pattern_name: rule.name.clone(),
                        fan_out: matched_targets.len(),
                        matched_targets: matched_targets.clone(),
                    },
                    description: format!(
                        "Pattern '{}': {} {} fans out to {} '{}' nodes via '{}' edges (threshold: {})",
                        rule.name, rule.anchor_type, node.id(),
                        matched_targets.len(), rule.target_type,
                        rule.edge_type, rule.min_fan_out,
                    ),
                    severity: rule.severity,
                    affected_nodes: {
                        let mut v = vec![node.id().clone()];
                        v.extend(matched_targets);
                        v
                    },
                    trigger_event: trigger_event.cloned(),
                    detected_at: now,
                });
            }
        }

        anomalies
    }

    /// Real-time pattern check: only checks nodes affected by this cascade.
    fn check_patterns_for_cascade(
        &self,
        result: &CascadeResult,
        graph: &dyn GraphReader,
        now: DateTime<Utc>,
        anomalies: &mut Vec<Anomaly>,
    ) {
        if self.pattern_rules.is_empty() {
            return;
        }

        // Collect unique affected node IDs
        let mut checked: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
        let trigger_id = result.events.first().map(|e| &e.id);

        for event in &result.events {
            if let Some(node_id) = event.kind.target_node() {
                if checked.contains(node_id) {
                    continue;
                }
                checked.insert(node_id.clone());

                if let Some(node) = graph.node(node_id) {
                    if node.is_alive() {
                        let mut found = self.match_patterns_for_node(node, graph, now, trigger_id);
                        anomalies.append(&mut found);
                    }
                }
            }
        }
    }

    /// Batch pattern check: scan all anchor nodes of each pattern's type.
    fn check_patterns_batch(
        &self,
        graph: &dyn GraphReader,
        now: DateTime<Utc>,
        anomalies: &mut Vec<Anomaly>,
    ) {
        if self.pattern_rules.is_empty() {
            return;
        }

        // Collect unique anchor types to avoid scanning the same type multiple times
        let mut anchor_types: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for rule in &self.pattern_rules {
            anchor_types.insert(&rule.anchor_type);
        }

        for anchor_type in anchor_types {
            for node in graph.nodes_by_type(anchor_type) {
                let mut found = self.match_patterns_for_node(node, graph, now, None);
                anomalies.append(&mut found);
            }
        }
    }
}

impl Default for AnomalyEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Detect if a time series is monotonically increasing or decreasing.
/// Only works on numeric values (Int, Float). Returns None if not monotonic
/// or if values aren't numeric.
fn detect_monotonic_trend(data: &[(DateTime<Utc>, Value)]) -> Option<DriftDirection> {
    if data.len() < 2 {
        return None;
    }

    let mut all_increasing = true;
    let mut all_decreasing = true;

    for window in data.windows(2) {
        let a = value_to_f64(&window[0].1);
        let b = value_to_f64(&window[1].1);

        match (a, b) {
            (Some(a), Some(b)) => {
                if b <= a {
                    all_increasing = false;
                }
                if b >= a {
                    all_decreasing = false;
                }
            }
            _ => return None, // Non-numeric value breaks the trend
        }
    }

    if all_increasing {
        Some(DriftDirection::Increasing)
    } else if all_decreasing {
        Some(DriftDirection::Decreasing)
    } else {
        None
    }
}

/// Convert a Value to f64 for numeric comparison
fn value_to_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Int(n) => Some(*n as f64),
        Value::Float(n) => Some(*n),
        _ => None,
    }
}

/// Check if a UTC hour falls within a time window.
/// Handles wraparound: start=22, end=4 means 22,23,0,1,2,3,4 are in-window.
/// Both start and end are inclusive.
fn is_in_time_window(hour: u32, start: u32, end: u32) -> bool {
    if start <= end {
        // Normal range: e.g., 2-4 means hours 2,3,4
        hour >= start && hour <= end
    } else {
        // Wraparound: e.g., 22-4 means hours 22,23,0,1,2,3,4
        hour >= start || hour <= end
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::Projection;
    
    use hydra_core::event::{Event, EventKind, Value};
    use hydra_core::id::{EdgeId, NodeId};
    use std::collections::HashMap;

    // Helper: build Projection + EventLog + TemporalIndex by ingesting events
    struct TestEnv {
        proj: Projection,
        log: EventLog,
        temporal: TemporalIndex,
    }

    impl TestEnv {
        fn new() -> Self {
            Self {
                proj: Projection::new(),
                log: EventLog::new(),
                temporal: TemporalIndex::new(),
            }
        }

        fn ingest(&mut self, event: Event) -> Event {
            let _ = self.proj.apply(&event);
            self.log.append(event.clone());
            self.temporal.record(&event);
            event
        }

        fn create_node(&mut self, type_id: &str) -> (NodeId, Event) {
            let node_id = NodeId::new();
            let event = Event::trigger(EventKind::NodeCreated {
                node_id: node_id.clone(),
                type_id: type_id.to_string(),
                properties: HashMap::new(),
            });
            let event = self.ingest(event);
            (node_id, event)
        }

        fn create_node_with_props(
            &mut self,
            type_id: &str,
            props: HashMap<String, Value>,
        ) -> (NodeId, Event) {
            let node_id = NodeId::new();
            let event = Event::trigger(EventKind::NodeCreated {
                node_id: node_id.clone(),
                type_id: type_id.to_string(),
                properties: props,
            });
            let event = self.ingest(event);
            (node_id, event)
        }

        fn create_edge(
            &mut self,
            source: &NodeId,
            target: &NodeId,
            type_id: &str,
        ) -> (EdgeId, Event) {
            let edge_id = EdgeId::new();
            let event = Event::trigger(EventKind::EdgeCreated {
                edge_id: edge_id.clone(),
                source: source.clone(),
                target: target.clone(),
                type_id: type_id.to_string(),
                properties: HashMap::new(),
            });
            let event = self.ingest(event);
            (edge_id, event)
        }

        fn update_at(
            &mut self,
            node_id: &NodeId,
            changes: HashMap<String, Value>,
            timestamp: DateTime<Utc>,
            parent: &Event,
        ) -> Event {
            let mut event = Event::reaction(
                EventKind::NodeUpdated {
                    node_id: node_id.clone(),
                    changes,
                },
                parent,
            );
            event.timestamp = timestamp;
            self.ingest(event)
        }
    }

    // ================================================================
    // Test 1: Cascade amplification detection
    // ================================================================
    #[test]
    fn detects_cascade_amplification() {
        let engine = AnomalyEngine::new().with_cascade_rule(CascadeRule {
            max_event_count: 5,
            max_depth: 3,
            severity: 0.8,
        });

        // Simulate a large cascade result
        let mut events = Vec::new();
        for _ in 0..10 {
            events.push(Event::trigger(EventKind::Signal {
                name: "test".to_string(),
                source: NodeId::new(),
                payload: HashMap::new(),
            }));
        }

        let result = CascadeResult {
            events,
            mutations: 0,
            max_depth_reached: 5,
            truncated: false,
        };

        let proj = Projection::new();
        let anomalies = engine.analyze_cascade(&result, &proj);

        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].kind,
            AnomalyKind::CascadeAmplification { cascade_event_count: 10, cascade_depth: 5, .. }
        ));
        assert!((anomalies[0].severity - 0.8).abs() < f64::EPSILON);
    }

    // ================================================================
    // Test 2: Normal cascade produces no anomaly
    // ================================================================
    #[test]
    fn normal_cascade_no_anomaly() {
        let engine = AnomalyEngine::new();

        let result = CascadeResult {
            events: vec![Event::trigger(EventKind::Signal {
                name: "ok".to_string(),
                source: NodeId::new(),
                payload: HashMap::new(),
            })],
            mutations: 1,
            max_depth_reached: 0,
            truncated: false,
        };

        let proj = Projection::new();
        let anomalies = engine.analyze_cascade(&result, &proj);
        assert!(anomalies.is_empty());
    }

    // ================================================================
    // Test 3: Topology violation — node missing required edges
    // ================================================================
    #[test]
    fn detects_topology_violation() {
        let mut env = TestEnv::new();
        let (ec2, _) = env.create_node("ec2");
        let (_vpc, _) = env.create_node("vpc");
        // ec2 has NO "in_vpc" edge — violates the rule

        let mut engine = AnomalyEngine::new();
        engine.add_topology_rule(TopologyRule {
            node_type: "ec2".to_string(),
            edge_type: "in_vpc".to_string(),
            min_degree: 1,
            max_degree: 5,
            severity: 0.6,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            &anomalies[0].kind,
            AnomalyKind::StructuralOrphan { node_id, missing_edge_type }
            if *node_id == ec2 && missing_edge_type == "in_vpc"
        ));
    }

    // ================================================================
    // Test 4: Topology satisfied — no anomaly
    // ================================================================
    #[test]
    fn topology_satisfied_no_anomaly() {
        let mut env = TestEnv::new();
        let (ec2, _) = env.create_node("ec2");
        let (vpc, _) = env.create_node("vpc");
        env.create_edge(&ec2, &vpc, "in_vpc");

        let mut engine = AnomalyEngine::new();
        engine.add_topology_rule(TopologyRule {
            node_type: "ec2".to_string(),
            edge_type: "in_vpc".to_string(),
            min_degree: 1,
            max_degree: 5,
            severity: 0.6,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        assert!(anomalies.is_empty());
    }

    // ================================================================
    // Test 5: Topology violation — too many edges
    // ================================================================
    #[test]
    fn detects_too_many_edges() {
        let mut env = TestEnv::new();
        let (admin, _) = env.create_node("admin");

        // Create 10 resources connected to admin
        for _ in 0..10 {
            let (resource, _) = env.create_node("resource");
            env.create_edge(&admin, &resource, "has_permission");
        }

        let mut engine = AnomalyEngine::new();
        engine.add_topology_rule(TopologyRule {
            node_type: "admin".to_string(),
            edge_type: "has_permission".to_string(),
            min_degree: 1,
            max_degree: 5,
            severity: 0.9,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            &anomalies[0].kind,
            AnomalyKind::TopologyDegree { actual: 10, expected_max: 5, .. }
        ));
    }

    // ================================================================
    // Test 6: Temporal drift detection — decreasing trust score
    // ================================================================
    #[test]
    fn detects_monotonic_drift() {
        let mut env = TestEnv::new();

        let (n, e0) = env.create_node_with_props(
            "ec2",
            HashMap::from([("trust_score".into(), Value::Int(100))]),
        );

        // Simulate decreasing trust score over 5 updates
        let mut prev = e0;
        for i in 1..=5 {
            let ts = Utc::now() + Duration::milliseconds(i * 100);
            prev = env.update_at(
                &n,
                HashMap::from([("trust_score".into(), Value::Int(100 - i * 10))]),
                ts,
                &prev,
            );
        }

        let mut engine = AnomalyEngine::new();
        engine.add_drift_rule(DriftRule {
            node_type: "ec2".to_string(),
            property: "trust_score".to_string(),
            min_consecutive: 4,
            severity: 0.7,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            &anomalies[0].kind,
            AnomalyKind::TemporalDrift { direction: DriftDirection::Decreasing, .. }
        ));
    }

    // ================================================================
    // Test 7: No drift when values oscillate
    // ================================================================
    #[test]
    fn no_drift_when_oscillating() {
        let mut env = TestEnv::new();

        let (n, e0) = env.create_node_with_props(
            "ec2",
            HashMap::from([("trust_score".into(), Value::Int(50))]),
        );

        // Oscillating: 50, 60, 50, 60, 50
        let values = [60, 50, 60, 50];
        let mut prev = e0;
        for (i, &val) in values.iter().enumerate() {
            let ts = Utc::now() + Duration::milliseconds((i as i64 + 1) * 100);
            prev = env.update_at(
                &n,
                HashMap::from([("trust_score".into(), Value::Int(val))]),
                ts,
                &prev,
            );
        }

        let mut engine = AnomalyEngine::new();
        engine.add_drift_rule(DriftRule {
            node_type: "ec2".to_string(),
            property: "trust_score".to_string(),
            min_consecutive: 3,
            severity: 0.7,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        assert!(anomalies.is_empty());
    }

    // ================================================================
    // Test 8: Change rate anomaly
    // ================================================================
    #[test]
    fn detects_change_rate_anomaly() {
        let mut env = TestEnv::new();

        let (n, e0) = env.create_node_with_props(
            "ec2",
            HashMap::from([("counter".into(), Value::Int(0))]),
        );

        // 20 rapid changes in the recent past (well within detection window)
        let mut prev = e0;
        let base = Utc::now() - Duration::seconds(60); // 60 seconds ago
        for i in 1..=20 {
            let ts = base + Duration::milliseconds(i);
            prev = env.update_at(
                &n,
                HashMap::from([("counter".into(), Value::Int(i))]),
                ts,
                &prev,
            );
        }

        let mut engine = AnomalyEngine::new();
        engine.add_change_rate_rule(ChangeRateRule {
            node_type: "ec2".to_string(),
            max_changes: 5,
            window_secs: 3600, // 1 hour
            severity: 0.8,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            &anomalies[0].kind,
            AnomalyKind::ChangeRateAnomaly { normal_max: 5, .. }
        ));
    }

    // ================================================================
    // Test 9: No rules → no anomalies
    // ================================================================
    #[test]
    fn no_rules_no_anomalies() {
        let env = TestEnv::new();
        let engine = AnomalyEngine::new();

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        assert!(anomalies.is_empty());
    }

    // ================================================================
    // Test 10: Real-time topology check on cascade-affected nodes
    // ================================================================
    #[test]
    fn realtime_topology_check_on_affected_nodes() {
        let mut env = TestEnv::new();
        let (ec2, _) = env.create_node("ec2");
        // ec2 has no VPC edge

        let mut engine = AnomalyEngine::new();
        engine.add_topology_rule(TopologyRule {
            node_type: "ec2".to_string(),
            edge_type: "in_vpc".to_string(),
            min_degree: 1,
            max_degree: 5,
            severity: 0.6,
        });

        // Simulate a cascade result that affects this ec2 node
        let cascade_result = CascadeResult {
            events: vec![Event::trigger(EventKind::NodeUpdated {
                node_id: ec2.clone(),
                changes: HashMap::from([("state".into(), Value::String("running".into()))]),
            })],
            mutations: 1,
            max_depth_reached: 0,
            truncated: false,
        };

        let anomalies = engine.analyze_cascade(&cascade_result, &env.proj);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            &anomalies[0].kind,
            AnomalyKind::TopologyDegree { actual: 0, .. }
        ));
    }

    // ================================================================
    // Test 11: Multiple rules, multiple violations
    // ================================================================
    #[test]
    fn multiple_violations_detected() {
        let mut env = TestEnv::new();
        let (_ec2, _) = env.create_node("ec2"); // No VPC edge
        let (_rds, _) = env.create_node("rds"); // No VPC edge

        let mut engine = AnomalyEngine::new();
        engine.add_topology_rule(TopologyRule {
            node_type: "ec2".to_string(),
            edge_type: "in_vpc".to_string(),
            min_degree: 1,
            max_degree: 5,
            severity: 0.6,
        });
        engine.add_topology_rule(TopologyRule {
            node_type: "rds".to_string(),
            edge_type: "in_vpc".to_string(),
            min_degree: 1,
            max_degree: 3,
            severity: 0.7,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        assert_eq!(anomalies.len(), 2);
    }

    // ================================================================
    // Test 12: Rule count
    // ================================================================
    #[test]
    fn rule_count_tracks_all_rule_types() {
        let mut engine = AnomalyEngine::new(); // 1 cascade rule (default)
        assert_eq!(engine.rule_count(), 1);

        engine.add_topology_rule(TopologyRule {
            node_type: "ec2".to_string(),
            edge_type: "in_vpc".to_string(),
            min_degree: 1,
            max_degree: 5,
            severity: 0.6,
        });
        assert_eq!(engine.rule_count(), 2);

        engine.add_drift_rule(DriftRule {
            node_type: "ec2".to_string(),
            property: "trust_score".to_string(),
            min_consecutive: 5,
            severity: 0.7,
        });
        assert_eq!(engine.rule_count(), 3);

        engine.add_change_rate_rule(ChangeRateRule {
            node_type: "ec2".to_string(),
            max_changes: 10,
            window_secs: 3600,
            severity: 0.5,
        });
        assert_eq!(engine.rule_count(), 4);
    }

    // ================================================================
    // Test 13: detect_monotonic_trend helper
    // ================================================================
    #[test]
    fn monotonic_trend_detection() {
        let now = Utc::now();

        // Increasing
        let increasing = vec![
            (now, Value::Int(1)),
            (now + Duration::seconds(1), Value::Int(2)),
            (now + Duration::seconds(2), Value::Int(3)),
        ];
        assert_eq!(detect_monotonic_trend(&increasing), Some(DriftDirection::Increasing));

        // Decreasing
        let decreasing = vec![
            (now, Value::Float(3.0)),
            (now + Duration::seconds(1), Value::Float(2.0)),
            (now + Duration::seconds(2), Value::Float(1.0)),
        ];
        assert_eq!(detect_monotonic_trend(&decreasing), Some(DriftDirection::Decreasing));

        // Not monotonic
        let zigzag = vec![
            (now, Value::Int(1)),
            (now + Duration::seconds(1), Value::Int(3)),
            (now + Duration::seconds(2), Value::Int(2)),
        ];
        assert_eq!(detect_monotonic_trend(&zigzag), None);

        // Non-numeric
        let strings = vec![
            (now, Value::String("a".into())),
            (now + Duration::seconds(1), Value::String("b".into())),
        ];
        assert_eq!(detect_monotonic_trend(&strings), None);

        // Single point
        let single = vec![(now, Value::Int(1))];
        assert_eq!(detect_monotonic_trend(&single), None);

        // Empty
        assert_eq!(detect_monotonic_trend(&[]), None);
    }

    // ================================================================
    // Test 14: is_in_time_window helper — normal range
    // ================================================================
    #[test]
    fn time_window_normal_range() {
        // 2am-4am window
        assert!(is_in_time_window(2, 2, 4));
        assert!(is_in_time_window(3, 2, 4));
        assert!(is_in_time_window(4, 2, 4));
        assert!(!is_in_time_window(1, 2, 4));
        assert!(!is_in_time_window(5, 2, 4));
        assert!(!is_in_time_window(14, 2, 4));
    }

    // ================================================================
    // Test 15: is_in_time_window helper — wraparound range
    // ================================================================
    #[test]
    fn time_window_wraparound() {
        // 10pm-4am window (22-4, crosses midnight)
        assert!(is_in_time_window(22, 22, 4));
        assert!(is_in_time_window(23, 22, 4));
        assert!(is_in_time_window(0, 22, 4));
        assert!(is_in_time_window(3, 22, 4));
        assert!(is_in_time_window(4, 22, 4));
        assert!(!is_in_time_window(5, 22, 4));
        assert!(!is_in_time_window(14, 22, 4));
        assert!(!is_in_time_window(21, 22, 4));
    }

    // ================================================================
    // Test 16: Detect changes outside time window
    // ================================================================
    #[test]
    fn detects_time_window_violation() {
        use chrono::TimeZone;

        let mut env = TestEnv::new();

        // Create a node with a change at 2pm UTC (hour 14) — outside a 2am-4am window
        let n = NodeId::new();
        let at_2pm = Utc.with_ymd_and_hms(2025, 6, 15, 14, 0, 0).unwrap();
        let create_event = {
            let mut e = Event::trigger(EventKind::NodeCreated {
                node_id: n.clone(),
                type_id: "backup_job".to_string(),
                properties: HashMap::from([("status".into(), Value::String("complete".into()))]),
            });
            e.timestamp = at_2pm;
            e
        };
        env.ingest(create_event);

        let mut engine = AnomalyEngine::new();
        engine.add_time_window_rule(TimeWindowRule {
            node_type: "backup_job".to_string(),
            start_hour: 2,
            end_hour: 4,
            tolerance: 0,
            lookback_secs: 0, // all history
            severity: 0.8,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            &anomalies[0].kind,
            AnomalyKind::TimeWindowViolation {
                change_hour: 14,
                expected_start_hour: 2,
                expected_end_hour: 4,
                violations: 1,
                ..
            }
        ));
    }

    // ================================================================
    // Test 17: No violation when changes are in-window
    // ================================================================
    #[test]
    fn no_violation_when_in_window() {
        use chrono::TimeZone;

        let mut env = TestEnv::new();
        let n = NodeId::new();

        // Change at 3am UTC — inside 2am-4am window
        let at_3am = Utc.with_ymd_and_hms(2025, 6, 15, 3, 0, 0).unwrap();
        let create_event = {
            let mut e = Event::trigger(EventKind::NodeCreated {
                node_id: n.clone(),
                type_id: "backup_job".to_string(),
                properties: HashMap::from([("status".into(), Value::String("complete".into()))]),
            });
            e.timestamp = at_3am;
            e
        };
        env.ingest(create_event);

        let mut engine = AnomalyEngine::new();
        engine.add_time_window_rule(TimeWindowRule {
            node_type: "backup_job".to_string(),
            start_hour: 2,
            end_hour: 4,
            tolerance: 0,
            lookback_secs: 0,
            severity: 0.8,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        assert!(anomalies.is_empty());
    }

    // ================================================================
    // Test 18: Tolerance allows some out-of-window changes
    // ================================================================
    #[test]
    fn tolerance_allows_some_violations() {
        use chrono::TimeZone;

        let mut env = TestEnv::new();
        let n = NodeId::new();

        // One change at 2pm (outside window)
        let at_2pm = Utc.with_ymd_and_hms(2025, 6, 15, 14, 0, 0).unwrap();
        let e1 = {
            let mut e = Event::trigger(EventKind::NodeCreated {
                node_id: n.clone(),
                type_id: "backup_job".to_string(),
                properties: HashMap::from([("status".into(), Value::String("running".into()))]),
            });
            e.timestamp = at_2pm;
            e
        };
        env.ingest(e1);

        let mut engine = AnomalyEngine::new();
        engine.add_time_window_rule(TimeWindowRule {
            node_type: "backup_job".to_string(),
            start_hour: 2,
            end_hour: 4,
            tolerance: 1, // Allow 1 out-of-window change
            lookback_secs: 0,
            severity: 0.8,
        });

        // 1 violation with tolerance=1 → no anomaly
        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        assert!(anomalies.is_empty());
    }

    // ================================================================
    // Test 19: Wraparound window detection works
    // ================================================================
    #[test]
    fn wraparound_window_detection() {
        use chrono::TimeZone;

        let mut env = TestEnv::new();
        let n = NodeId::new();

        // Change at 11pm UTC (hour 23) — inside a 22-4 wraparound window
        let at_11pm = Utc.with_ymd_and_hms(2025, 6, 15, 23, 0, 0).unwrap();
        let e1 = {
            let mut e = Event::trigger(EventKind::NodeCreated {
                node_id: n.clone(),
                type_id: "backup_job".to_string(),
                properties: HashMap::from([("status".into(), Value::String("ok".into()))]),
            });
            e.timestamp = at_11pm;
            e
        };
        env.ingest(e1);

        let mut engine = AnomalyEngine::new();
        engine.add_time_window_rule(TimeWindowRule {
            node_type: "backup_job".to_string(),
            start_hour: 22,
            end_hour: 4,
            tolerance: 0,
            lookback_secs: 0,
            severity: 0.8,
        });

        // 11pm is inside the 10pm-4am window → no anomaly
        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        assert!(anomalies.is_empty());
    }

    // ================================================================
    // Test 20: Rule count includes time window rules
    // ================================================================
    #[test]
    fn rule_count_includes_time_window() {
        let mut engine = AnomalyEngine::new();
        assert_eq!(engine.rule_count(), 1); // cascade only

        engine.add_time_window_rule(TimeWindowRule {
            node_type: "backup_job".to_string(),
            start_hour: 2,
            end_hour: 4,
            tolerance: 0,
            lookback_secs: 0,
            severity: 0.5,
        });
        assert_eq!(engine.rule_count(), 2);
    }

    #[test]
    #[should_panic(expected = "start_hour must be 0-23")]
    fn invalid_start_hour_panics() {
        let mut engine = AnomalyEngine::new();
        engine.add_time_window_rule(TimeWindowRule {
            node_type: "x".to_string(),
            start_hour: 24,
            end_hour: 4,
            tolerance: 0,
            lookback_secs: 0,
            severity: 0.5,
        });
    }

    #[test]
    #[should_panic(expected = "end_hour must be 0-23")]
    fn invalid_end_hour_panics() {
        let mut engine = AnomalyEngine::new();
        engine.add_time_window_rule(TimeWindowRule {
            node_type: "x".to_string(),
            start_hour: 2,
            end_hour: 25,
            tolerance: 0,
            lookback_secs: 0,
            severity: 0.5,
        });
    }

    // ================================================================
    // Test 22: Counterfactual anomaly — detect outsized node influence
    // ================================================================
    #[test]
    fn detects_counterfactual_outlier() {
        let mut env = TestEnv::new();

        // Create one "admin" node with many events
        let (admin, e0) = env.create_node("admin");
        for i in 0..10 {
            let mut e = Event::reaction(
                EventKind::NodeUpdated {
                    node_id: admin.clone(),
                    changes: HashMap::from([(format!("action_{}", i), Value::Bool(true))]),
                },
                &e0,
            );
            e.timestamp = Utc::now();
            env.ingest(e);
        }

        // Create a few independent nodes
        for _ in 0..3 {
            env.create_node("resource");
        }

        let mut engine = AnomalyEngine::new();
        engine.add_counterfactual_rule(CounterfactualRule {
            node_type: "admin".to_string(),
            min_removal_fraction: 0.3,
            min_graph_impact: 1,
            severity: 0.9,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);

        // The admin node accounts for 11 of ~14 events (~79%) → should flag
        let cf_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| matches!(a.kind, AnomalyKind::CounterfactualOutlier { .. }))
            .collect();
        assert_eq!(cf_anomalies.len(), 1);

        if let AnomalyKind::CounterfactualOutlier {
            source_node,
            removal_fraction,
            ..
        } = &cf_anomalies[0].kind
        {
            assert_eq!(*source_node, admin);
            assert!(*removal_fraction > 0.3);
        } else {
            panic!("Expected CounterfactualOutlier");
        }
    }

    // ================================================================
    // Test 23: No counterfactual anomaly for balanced graph
    // ================================================================
    #[test]
    fn no_counterfactual_anomaly_for_balanced_graph() {
        let mut env = TestEnv::new();

        // Create 5 nodes of equal weight — no single node dominates
        for _ in 0..5 {
            env.create_node("admin");
        }

        let mut engine = AnomalyEngine::new();
        engine.add_counterfactual_rule(CounterfactualRule {
            node_type: "admin".to_string(),
            min_removal_fraction: 0.5, // Need >50% to trigger
            min_graph_impact: 3,
            severity: 0.9,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        let cf_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| matches!(a.kind, AnomalyKind::CounterfactualOutlier { .. }))
            .collect();
        assert!(cf_anomalies.is_empty());
    }

    // ================================================================
    // Test 24: Rule count includes counterfactual rules
    // ================================================================
    #[test]
    fn rule_count_includes_counterfactual() {
        let mut engine = AnomalyEngine::new();
        let base = engine.rule_count(); // cascade only = 1

        engine.add_counterfactual_rule(CounterfactualRule {
            node_type: "admin".to_string(),
            min_removal_fraction: 0.3,
            min_graph_impact: 1,
            severity: 0.9,
        });
        assert_eq!(engine.rule_count(), base + 1);
    }

    // ================================================================
    // Test 25: Forbidden pattern — admin with broad permissions
    // ================================================================
    #[test]
    fn detects_forbidden_pattern_fan_out() {
        let mut env = TestEnv::new();

        // Create admin node
        let (admin, _) = env.create_node("admin");

        // Create 10 resources connected via has_permission
        for _ in 0..10 {
            let (resource, _) = env.create_node("resource");
            env.create_edge(&admin, &resource, "has_permission");
        }

        let mut engine = AnomalyEngine::new();
        engine.add_pattern_rule(PatternRule {
            name: "broad_permissions".to_string(),
            anchor_type: "admin".to_string(),
            edge_type: "has_permission".to_string(),
            target_type: "resource".to_string(),
            min_fan_out: 5,
            target_predicate: None,
            anchor_predicate: None,
            severity: 0.9,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        let pattern_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| matches!(a.kind, AnomalyKind::ForbiddenPattern { .. }))
            .collect();

        assert_eq!(pattern_anomalies.len(), 1);
        if let AnomalyKind::ForbiddenPattern { fan_out, pattern_name, .. } = &pattern_anomalies[0].kind {
            assert_eq!(*fan_out, 10);
            assert_eq!(pattern_name, "broad_permissions");
        }
    }

    // ================================================================
    // Test 26: No pattern match when below threshold
    // ================================================================
    #[test]
    fn no_pattern_match_below_threshold() {
        let mut env = TestEnv::new();
        let (admin, _) = env.create_node("admin");

        // Only 2 resources — below threshold of 5
        for _ in 0..2 {
            let (resource, _) = env.create_node("resource");
            env.create_edge(&admin, &resource, "has_permission");
        }

        let mut engine = AnomalyEngine::new();
        engine.add_pattern_rule(PatternRule {
            name: "broad_permissions".to_string(),
            anchor_type: "admin".to_string(),
            edge_type: "has_permission".to_string(),
            target_type: "resource".to_string(),
            min_fan_out: 5,
            target_predicate: None,
            anchor_predicate: None,
            severity: 0.9,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        let pattern_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| matches!(a.kind, AnomalyKind::ForbiddenPattern { .. }))
            .collect();
        assert!(pattern_anomalies.is_empty());
    }

    // ================================================================
    // Test 27: Pattern with target property predicate
    // ================================================================
    #[test]
    fn pattern_with_target_predicate() {
        let mut env = TestEnv::new();
        let (admin, _) = env.create_node("admin");

        // 5 resources, but only 3 have "modified=true"
        for i in 0..5 {
            let props = if i < 3 {
                HashMap::from([("modified".to_string(), Value::Bool(true))])
            } else {
                HashMap::new()
            };
            let (resource, _) = env.create_node_with_props("backup_config", props);
            env.create_edge(&admin, &resource, "modified");
        }

        let mut engine = AnomalyEngine::new();
        engine.add_pattern_rule(PatternRule {
            name: "suspicious_backup_changes".to_string(),
            anchor_type: "admin".to_string(),
            edge_type: "modified".to_string(),
            target_type: "backup_config".to_string(),
            min_fan_out: 3,
            target_predicate: Some(PropertyPredicate::Equals(
                "modified".to_string(),
                Value::Bool(true),
            )),
            anchor_predicate: None,
            severity: 0.95,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        let pattern_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| matches!(a.kind, AnomalyKind::ForbiddenPattern { .. }))
            .collect();

        assert_eq!(pattern_anomalies.len(), 1);
        if let AnomalyKind::ForbiddenPattern { fan_out, .. } = &pattern_anomalies[0].kind {
            assert_eq!(*fan_out, 3); // Only the 3 with modified=true
        }
    }

    // ================================================================
    // Test 28: Pattern with anchor predicate
    // ================================================================
    #[test]
    fn pattern_with_anchor_predicate() {
        let mut env = TestEnv::new();

        // Two admins: one new (flagged), one old (not flagged)
        let (new_admin, _) = env.create_node_with_props(
            "admin",
            HashMap::from([("is_new".to_string(), Value::Bool(true))]),
        );
        let (old_admin, _) = env.create_node_with_props(
            "admin",
            HashMap::from([("is_new".to_string(), Value::Bool(false))]),
        );

        // Both connect to 5 resources
        for _ in 0..5 {
            let (r, _) = env.create_node("resource");
            env.create_edge(&new_admin, &r, "has_permission");
        }
        for _ in 0..5 {
            let (r, _) = env.create_node("resource");
            env.create_edge(&old_admin, &r, "has_permission");
        }

        let mut engine = AnomalyEngine::new();
        engine.add_pattern_rule(PatternRule {
            name: "new_admin_broad_access".to_string(),
            anchor_type: "admin".to_string(),
            edge_type: "has_permission".to_string(),
            target_type: "resource".to_string(),
            min_fan_out: 5,
            target_predicate: None,
            anchor_predicate: Some(PropertyPredicate::Equals(
                "is_new".to_string(),
                Value::Bool(true),
            )),
            severity: 0.95,
        });

        let anomalies = engine.analyze_batch(&env.proj, &env.temporal, &env.log);
        let pattern_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| matches!(a.kind, AnomalyKind::ForbiddenPattern { .. }))
            .collect();

        // Only the new admin should match
        assert_eq!(pattern_anomalies.len(), 1);
        if let AnomalyKind::ForbiddenPattern { anchor_node, .. } = &pattern_anomalies[0].kind {
            assert_eq!(*anchor_node, new_admin);
        }
    }

    // ================================================================
    // Test 29: PropertyPredicate logic
    // ================================================================
    #[test]
    fn property_predicate_logic() {
        use hydra_core::node::Node;

        let node = Node::new(
            NodeId::new(),
            "test".to_string(),
            HashMap::from([
                ("score".to_string(), Value::Int(75)),
                ("name".to_string(), Value::String("test".into())),
                ("active".to_string(), Value::Bool(true)),
            ]),
        );

        assert!(PropertyPredicate::Exists("score".to_string()).matches(&node));
        assert!(!PropertyPredicate::Exists("missing".to_string()).matches(&node));

        assert!(PropertyPredicate::Equals("active".to_string(), Value::Bool(true)).matches(&node));
        assert!(!PropertyPredicate::Equals("active".to_string(), Value::Bool(false)).matches(&node));

        assert!(PropertyPredicate::GreaterThan("score".to_string(), 50.0).matches(&node));
        assert!(!PropertyPredicate::GreaterThan("score".to_string(), 80.0).matches(&node));

        assert!(PropertyPredicate::LessThan("score".to_string(), 100.0).matches(&node));
        assert!(!PropertyPredicate::LessThan("score".to_string(), 50.0).matches(&node));

        // All
        let all = PropertyPredicate::All(vec![
            PropertyPredicate::Exists("score".to_string()),
            PropertyPredicate::GreaterThan("score".to_string(), 50.0),
        ]);
        assert!(all.matches(&node));

        // Any
        let any = PropertyPredicate::Any(vec![
            PropertyPredicate::GreaterThan("score".to_string(), 90.0), // false
            PropertyPredicate::Exists("name".to_string()),              // true
        ]);
        assert!(any.matches(&node));
    }

    // ================================================================
    // Test 30: Large i64 precision — no f64 loss
    // ================================================================
    #[test]
    fn predicate_large_i64_precision() {
        use hydra_core::node::Node;

        // 2^53 + 1 = 9007199254740993 — this value loses precision as f64
        // (f64 can only represent integers exactly up to 2^53)
        let big = 9_007_199_254_740_993i64;
        let big_minus_one = 9_007_199_254_740_992i64;

        let node = Node::new(
            NodeId::new(),
            "test".to_string(),
            HashMap::from([("big".to_string(), Value::Int(big))]),
        );

        // big > big_minus_one should be true (integer comparison)
        // With f64 coercion, both would become the same f64 value → false
        assert!(
            PropertyPredicate::GreaterThan("big".to_string(), big_minus_one as f64).matches(&node),
            "Large i64 should compare correctly without f64 precision loss"
        );

        // big < big + 2 should be true
        assert!(
            PropertyPredicate::LessThan("big".to_string(), (big + 2) as f64).matches(&node),
        );

        // Float values still work normally
        let float_node = Node::new(
            NodeId::new(),
            "test".to_string(),
            HashMap::from([("val".to_string(), Value::Float(3.14))]),
        );
        assert!(PropertyPredicate::GreaterThan("val".to_string(), 3.0).matches(&float_node));
        assert!(!PropertyPredicate::GreaterThan("val".to_string(), 4.0).matches(&float_node));
    }

    // ================================================================
    // Test 31: Real-time pattern check on cascade-affected nodes
    // ================================================================
    #[test]
    fn realtime_pattern_check() {
        let mut env = TestEnv::new();
        let (admin, _) = env.create_node("admin");

        for _ in 0..5 {
            let (r, _) = env.create_node("resource");
            env.create_edge(&admin, &r, "has_permission");
        }

        let mut engine = AnomalyEngine::new();
        engine.add_pattern_rule(PatternRule {
            name: "broad_access".to_string(),
            anchor_type: "admin".to_string(),
            edge_type: "has_permission".to_string(),
            target_type: "resource".to_string(),
            min_fan_out: 3,
            target_predicate: None,
            anchor_predicate: None,
            severity: 0.8,
        });

        // Simulate a cascade that affects the admin node
        let cascade_result = CascadeResult {
            events: vec![Event::trigger(EventKind::NodeUpdated {
                node_id: admin.clone(),
                changes: HashMap::from([("last_login".into(), Value::String("now".into()))]),
            })],
            mutations: 1,
            max_depth_reached: 0,
            truncated: false,
        };

        let anomalies = engine.analyze_cascade(&cascade_result, &env.proj);
        let pattern_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| matches!(a.kind, AnomalyKind::ForbiddenPattern { .. }))
            .collect();
        assert_eq!(pattern_anomalies.len(), 1);
    }

    // ================================================================
    // Test 31: Rule count includes pattern rules
    // ================================================================
    #[test]
    fn rule_count_includes_pattern() {
        let mut engine = AnomalyEngine::new();
        let base = engine.rule_count();

        engine.add_pattern_rule(PatternRule {
            name: "test".to_string(),
            anchor_type: "x".to_string(),
            edge_type: "y".to_string(),
            target_type: "z".to_string(),
            min_fan_out: 1,
            target_predicate: None,
            anchor_predicate: None,
            severity: 0.5,
        });
        assert_eq!(engine.rule_count(), base + 1);
    }
}
