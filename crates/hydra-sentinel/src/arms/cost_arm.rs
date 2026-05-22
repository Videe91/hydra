//! # Cost Arm (B9)
//!
//! Optimizes storage costs continuously.
//!
//! Fires on: Signal("periodic_cost_review"), NodeCreated (backup_snapshot)
//! Reads: all snapshot nodes (storage tiers, retention), policy nodes
//! Emits: NodeUpdated (storage_tier changes), Signal("cost_optimization")

use hydra_core::event::{Event, EventKind, Value};
use hydra_core::graph::GraphReader;
use hydra_core::subscription::SubscriptionHandler;
use crate::nodes::prop;
use crate::queries::protection_status::PROTECTABLE_TYPES;
use std::collections::HashMap;

/// Cost Arm — continuously optimizes storage and protection costs.
pub struct CostArm {
    /// Monthly budget ceiling in cents. Optimizations trigger when
    /// projected cost exceeds this threshold.
    pub budget_ceiling_cents: i64,
}

impl CostArm {
    pub fn new(budget_ceiling_cents: i64) -> Self {
        Self { budget_ceiling_cents }
    }

    /// Default: $10K/month ceiling
    pub fn with_defaults() -> Self {
        Self { budget_ceiling_cents: 1_000_000 }
    }
}

impl SubscriptionHandler for CostArm {
    fn handle(
        &self,
        event: &Event,
        graph: &dyn GraphReader,
    ) -> Vec<EventKind> {
        let mut events = Vec::new();

        match &event.kind {
            EventKind::Signal { name, .. }
                if name == "periodic_cost_review" =>
            {
                // Compute total estate cost
                let mut total_cost_cents: i64 = 0;
                let mut optimization_candidates = Vec::new();

                for &type_id in PROTECTABLE_TYPES {
                    for node in graph.nodes_by_type(type_id) {
                        if !node.is_alive() { continue; }
                        let cost = node.get_i64(prop::MONTHLY_COST_CENTS).unwrap_or(0);
                        total_cost_cents += cost;

                        let criticality = node.get_i64(prop::BUSINESS_CRITICALITY).unwrap_or(5);
                        let protection = node.get_str(prop::PROTECTION_STATUS).unwrap_or("unknown");

                        // Flag over-protected low-criticality resources
                        if criticality <= 3 && protection == "protected" {
                            // Check if multiple backups exist (over-retention)
                            let backup_count = graph.outgoing_edges_of_type(
                                node.id(), crate::nodes::PROTECTED_BY).len();
                            if backup_count > 3 {
                                optimization_candidates.push((
                                    node.id().clone(),
                                    "over_retention".to_string(),
                                    cost,
                                ));
                            }
                        }

                        // Flag unprotected resources that could use cold storage
                        if protection == "unprotected" && criticality <= 2 && cost > 0 {
                            optimization_candidates.push((
                                node.id().clone(),
                                "cold_storage_candidate".to_string(),
                                cost,
                            ));
                        }
                    }
                }

                // Emit cost report signal
                events.push(EventKind::Signal {
                    source: hydra_core::id::NodeId::from_str("cost_arm"),
                    name: "cost_report".to_string(),
                    payload: HashMap::from([
                        ("total_monthly_cents".to_string(), Value::Int(total_cost_cents)),
                        ("budget_ceiling_cents".to_string(), Value::Int(self.budget_ceiling_cents)),
                        ("over_budget".to_string(), Value::Bool(total_cost_cents > self.budget_ceiling_cents)),
                        ("optimization_count".to_string(), Value::Int(optimization_candidates.len() as i64)),
                    ]),
                });

                // Emit per-resource optimization signals
                for (node_id, optimization_type, cost) in &optimization_candidates {
                    events.push(EventKind::Signal {
                        source: node_id.clone(),
                        name: "cost_optimization".to_string(),
                        payload: HashMap::from([
                            ("optimization_type".to_string(), Value::String(optimization_type.clone())),
                            ("monthly_cost_cents".to_string(), Value::Int(*cost)),
                            ("recommendation".to_string(), Value::String(
                                match optimization_type.as_str() {
                                    "over_retention" => "Reduce backup count or move old snapshots to archive tier".into(),
                                    "cold_storage_candidate" => "Move to cold storage tier for cost savings".into(),
                                    _ => "Review manually".into(),
                                }
                            )),
                        ]),
                    });
                }
            }

            _ => {}
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_engine::prelude::*;
    use hydra_core::subscription::{Subscription, EventFilter};
    use crate::nodes::aws::*;

    #[test]
    fn cost_arm_computes_total_cost() {
        let mut hydra = Hydra::new();
        hydra.register(Subscription::new(
            "cost_arm",
            EventFilter::SignalName("periodic_cost_review".to_string()),
            60,
            Box::new(CostArm::with_defaults()),
        ));

        let (_, ev) = RdsBuilder::new("db-1").monthly_cost_cents(500_000).build();
        hydra.ingest(ev).unwrap();
        let (_, ev) = RdsBuilder::new("db-2").monthly_cost_cents(300_000).build();
        hydra.ingest(ev).unwrap();

        let result = hydra.ingest(EventKind::Signal {
            source: hydra_core::id::NodeId::from_str("clock"),
            name: "periodic_cost_review".to_string(),
            payload: HashMap::new(),
        }).unwrap();

        // Should emit a cost_report signal
        assert!(result.events.len() >= 2);
    }

    #[test]
    fn cost_arm_detects_over_budget() {
        let mut hydra = Hydra::new();
        // Low budget ceiling: $50/month
        hydra.register(Subscription::new(
            "cost_arm",
            EventFilter::SignalName("periodic_cost_review".to_string()),
            60,
            Box::new(CostArm::new(5_000)),
        ));

        let (_, ev) = RdsBuilder::new("db-expensive").monthly_cost_cents(100_000).build();
        hydra.ingest(ev).unwrap();

        let result = hydra.ingest(EventKind::Signal {
            source: hydra_core::id::NodeId::from_str("clock"),
            name: "periodic_cost_review".to_string(),
            payload: HashMap::new(),
        }).unwrap();

        // The cost_report signal should indicate over_budget
        let has_cost_report = result.events.iter().any(|e| {
            matches!(&e.kind, EventKind::Signal { name, payload, .. }
                if name == "cost_report"
                && payload.get("over_budget") == Some(&Value::Bool(true)))
        });
        assert!(has_cost_report, "Should report over budget");
    }
}
