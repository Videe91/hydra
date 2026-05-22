use hydra_core::graph::GraphReader;
use hydra_core::id::NodeId;
use chrono::{DateTime, Utc};

// ============================================================================
// Coverage Expectations — what the graph SHOULD contain
// ============================================================================

/// A single expectation about what the graph should contain.
#[derive(Debug, Clone)]
pub enum CoverageExpectation {
    /// "There should be at least N nodes of type T"
    /// Example: "at least 1 VPC node should exist per AWS account"
    MinNodeCount {
        node_type: String,
        min_count: usize,
    },

    /// "Every node of type A should have at least M edges of type E to nodes of type B"
    /// Example: "every EC2 instance should have at least 1 'in_vpc' edge to a VPC node"
    EdgeCoverage {
        source_type: String,
        edge_type: String,
        target_type: String,
        min_per_source: usize,
    },

    /// "The ratio of type X count to type Y count should be at least R"
    /// Example: "there should be at least 0.5 backup_policy nodes per data_asset node"
    TypeRatio {
        numerator_type: String,
        denominator_type: String,
        min_ratio: f64,
    },
}

/// A coverage model: a named set of expectations with an optional scope filter.
/// Domain verticals (Sentinel, etc.) register models describing what a
/// healthy graph looks like.
#[derive(Debug, Clone)]
pub struct CoverageModel {
    /// Human-readable name
    pub name: String,
    /// The expectations that define completeness
    pub expectations: Vec<CoverageExpectation>,
    /// Optional: only evaluate nodes matching this type for scoping.
    /// If None, evaluates against the entire graph.
    pub scope_node_type: Option<String>,
}

// ============================================================================
// Coverage Report — what the engine finds
// ============================================================================

/// A gap: one expectation that was not met
#[derive(Debug, Clone)]
pub struct CoverageGap {
    /// Which expectation failed
    pub expectation_index: usize,
    /// Human-readable description of what's missing
    pub description: String,
    /// How far off we are (0.0 = completely missing, approaching 1.0 = almost met)
    pub fulfillment: f64,
    /// Nodes involved in the gap (if applicable)
    pub affected_nodes: Vec<NodeId>,
}

/// The result of evaluating a coverage model against the graph
#[derive(Debug, Clone)]
pub struct CoverageReport {
    /// Which model was evaluated
    pub model_name: String,
    /// Overall coverage score: 0.0 (nothing met) to 1.0 (everything met)
    pub score: f64,
    /// Total expectations evaluated
    pub total_expectations: usize,
    /// How many expectations were fully met
    pub met: usize,
    /// Detailed gaps for unmet expectations
    pub gaps: Vec<CoverageGap>,
    /// When this report was generated
    pub evaluated_at: DateTime<Utc>,
}

impl CoverageReport {
    /// Are all expectations met?
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }
}

// ============================================================================
// The Engine
// ============================================================================

/// Evaluates coverage models against the current graph state.
///
/// This is the mechanism for "the graph that reasons about its own completeness."
/// The engine doesn't know what complete means — domain verticals register
/// CoverageModels that define completeness. The engine evaluates them.
///
/// Usage:
/// ```ignore
/// let mut engine = CoverageEngine::new();
/// engine.add_model(sentinel_coverage_model());
/// let report = engine.evaluate(&projection);
/// if report.score < 0.8 {
///     // trigger broader discovery
/// }
/// ```
pub struct CoverageEngine {
    models: Vec<CoverageModel>,
}

impl CoverageEngine {
    pub fn new() -> Self {
        Self { models: Vec::new() }
    }

    pub fn add_model(&mut self, model: CoverageModel) {
        self.models.push(model);
    }

    pub fn model_count(&self) -> usize {
        self.models.len()
    }

    /// Evaluate all models against the current graph state.
    pub fn evaluate_all(&self, graph: &dyn GraphReader) -> Vec<CoverageReport> {
        self.models.iter().map(|m| self.evaluate(m, graph)).collect()
    }

    /// Evaluate a single model against the current graph state.
    pub fn evaluate(&self, model: &CoverageModel, graph: &dyn GraphReader) -> CoverageReport {
        let now = Utc::now();
        let mut gaps = Vec::new();
        let total = model.expectations.len();

        for (idx, expectation) in model.expectations.iter().enumerate() {
            if let Some(gap) = self.check_expectation(idx, expectation, graph) {
                gaps.push(gap);
            }
        }

        let met = total - gaps.len();
        let score = if total == 0 {
            1.0
        } else {
            // Weighted score: fully met expectations contribute 1.0,
            // partially met contribute their fulfillment fraction
            let total_fulfillment: f64 = (met as f64)
                + gaps.iter().map(|g| g.fulfillment).sum::<f64>();
            total_fulfillment / total as f64
        };

        CoverageReport {
            model_name: model.name.clone(),
            score,
            total_expectations: total,
            met,
            gaps,
            evaluated_at: now,
        }
    }

    /// Check a single expectation. Returns Some(gap) if not fully met.
    fn check_expectation(
        &self,
        index: usize,
        expectation: &CoverageExpectation,
        graph: &dyn GraphReader,
    ) -> Option<CoverageGap> {
        match expectation {
            CoverageExpectation::MinNodeCount { node_type, min_count } => {
                let actual = graph.count_nodes_by_type(node_type);
                if actual >= *min_count {
                    None
                } else {
                    let fulfillment = if *min_count == 0 {
                        1.0
                    } else {
                        actual as f64 / *min_count as f64
                    };
                    Some(CoverageGap {
                        expectation_index: index,
                        description: format!(
                            "Expected at least {} '{}' nodes, found {}",
                            min_count, node_type, actual,
                        ),
                        fulfillment,
                        affected_nodes: vec![],
                    })
                }
            }

            CoverageExpectation::EdgeCoverage {
                source_type,
                edge_type,
                target_type,
                min_per_source,
            } => {
                let sources = graph.nodes_by_type(source_type);
                if sources.is_empty() {
                    // No source nodes → can't evaluate edge coverage
                    // This might be a MinNodeCount gap instead
                    return None;
                }

                let mut violators = Vec::new();
                for source in &sources {
                    let edges = graph.outgoing_edges_of_type(source.id(), edge_type);
                    let matching_targets = edges
                        .iter()
                        .filter(|e| {
                            graph
                                .node(e.target())
                                .map_or(false, |n| n.is_alive() && n.type_id() == target_type)
                        })
                        .count();

                    if matching_targets < *min_per_source {
                        violators.push(source.id().clone());
                    }
                }

                if violators.is_empty() {
                    None
                } else {
                    let fulfillment =
                        1.0 - (violators.len() as f64 / sources.len() as f64);
                    Some(CoverageGap {
                        expectation_index: index,
                        description: format!(
                            "{}/{} '{}' nodes lack the required {} '{}' edges to '{}' nodes",
                            violators.len(),
                            sources.len(),
                            source_type,
                            min_per_source,
                            edge_type,
                            target_type,
                        ),
                        fulfillment,
                        affected_nodes: violators,
                    })
                }
            }

            CoverageExpectation::TypeRatio {
                numerator_type,
                denominator_type,
                min_ratio,
            } => {
                let num = graph.count_nodes_by_type(numerator_type);
                let den = graph.count_nodes_by_type(denominator_type);

                if den == 0 {
                    // No denominator nodes → ratio is undefined, not a gap
                    return None;
                }

                let actual_ratio = num as f64 / den as f64;
                if actual_ratio >= *min_ratio {
                    None
                } else {
                    let fulfillment = if *min_ratio == 0.0 {
                        1.0
                    } else {
                        (actual_ratio / min_ratio).min(1.0)
                    };
                    Some(CoverageGap {
                        expectation_index: index,
                        description: format!(
                            "Ratio of '{}' to '{}' is {:.2} (expected >= {:.2}). \
                             Have {} '{}' for {} '{}'.",
                            numerator_type, denominator_type,
                            actual_ratio, min_ratio,
                            num, numerator_type,
                            den, denominator_type,
                        ),
                        fulfillment,
                        affected_nodes: vec![],
                    })
                }
            }
        }
    }
}

impl Default for CoverageEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::Projection;
    use hydra_core::event::{Event, EventKind};
    use hydra_core::id::{EdgeId, NodeId};
    use std::collections::HashMap;

    fn create_node(proj: &mut Projection, type_id: &str) -> NodeId {
        let id = NodeId::new();
        let event = Event::trigger(EventKind::NodeCreated {
            node_id: id.clone(),
            type_id: type_id.to_string(),
            properties: HashMap::new(),
        });
        proj.apply(&event).unwrap();
        id
    }

    fn create_edge(proj: &mut Projection, source: &NodeId, target: &NodeId, type_id: &str) {
        let event = Event::trigger(EventKind::EdgeCreated {
            edge_id: EdgeId::new(),
            source: source.clone(),
            target: target.clone(),
            type_id: type_id.to_string(),
            properties: HashMap::new(),
        });
        proj.apply(&event).unwrap();
    }

    // ================================================================
    // Test 1: MinNodeCount — met
    // ================================================================
    #[test]
    fn min_node_count_met() {
        let mut proj = Projection::new();
        create_node(&mut proj, "ec2");
        create_node(&mut proj, "ec2");

        let engine = CoverageEngine::new();
        let model = CoverageModel {
            name: "test".to_string(),
            expectations: vec![CoverageExpectation::MinNodeCount {
                node_type: "ec2".to_string(),
                min_count: 2,
            }],
            scope_node_type: None,
        };

        let report = engine.evaluate(&model, &proj);
        assert!(report.is_complete());
        assert_eq!(report.score, 1.0);
        assert_eq!(report.met, 1);
    }

    // ================================================================
    // Test 2: MinNodeCount — not met
    // ================================================================
    #[test]
    fn min_node_count_not_met() {
        let mut proj = Projection::new();
        create_node(&mut proj, "ec2");

        let engine = CoverageEngine::new();
        let model = CoverageModel {
            name: "test".to_string(),
            expectations: vec![CoverageExpectation::MinNodeCount {
                node_type: "ec2".to_string(),
                min_count: 5,
            }],
            scope_node_type: None,
        };

        let report = engine.evaluate(&model, &proj);
        assert!(!report.is_complete());
        assert_eq!(report.gaps.len(), 1);
        assert!((report.gaps[0].fulfillment - 0.2).abs() < 0.001); // 1/5
        assert!(report.score < 1.0);
    }

    // ================================================================
    // Test 3: EdgeCoverage — all nodes have required edges
    // ================================================================
    #[test]
    fn edge_coverage_met() {
        let mut proj = Projection::new();
        let ec2 = create_node(&mut proj, "ec2");
        let vpc = create_node(&mut proj, "vpc");
        create_edge(&mut proj, &ec2, &vpc, "in_vpc");

        let engine = CoverageEngine::new();
        let model = CoverageModel {
            name: "test".to_string(),
            expectations: vec![CoverageExpectation::EdgeCoverage {
                source_type: "ec2".to_string(),
                edge_type: "in_vpc".to_string(),
                target_type: "vpc".to_string(),
                min_per_source: 1,
            }],
            scope_node_type: None,
        };

        let report = engine.evaluate(&model, &proj);
        assert!(report.is_complete());
    }

    // ================================================================
    // Test 4: EdgeCoverage — some nodes missing edges
    // ================================================================
    #[test]
    fn edge_coverage_partial() {
        let mut proj = Projection::new();
        let ec2_a = create_node(&mut proj, "ec2");
        let ec2_b = create_node(&mut proj, "ec2");
        let vpc = create_node(&mut proj, "vpc");
        // Only ec2_a has the edge
        create_edge(&mut proj, &ec2_a, &vpc, "in_vpc");

        let engine = CoverageEngine::new();
        let model = CoverageModel {
            name: "test".to_string(),
            expectations: vec![CoverageExpectation::EdgeCoverage {
                source_type: "ec2".to_string(),
                edge_type: "in_vpc".to_string(),
                target_type: "vpc".to_string(),
                min_per_source: 1,
            }],
            scope_node_type: None,
        };

        let report = engine.evaluate(&model, &proj);
        assert!(!report.is_complete());
        assert_eq!(report.gaps.len(), 1);
        // 1 of 2 ec2 nodes violate → fulfillment = 0.5
        assert!((report.gaps[0].fulfillment - 0.5).abs() < 0.001);
        assert_eq!(report.gaps[0].affected_nodes.len(), 1);
        assert_eq!(report.gaps[0].affected_nodes[0], ec2_b);
    }

    // ================================================================
    // Test 5: TypeRatio — met
    // ================================================================
    #[test]
    fn type_ratio_met() {
        let mut proj = Projection::new();
        // 3 data assets, 2 backup policies → ratio = 2/3 = 0.67
        for _ in 0..3 {
            create_node(&mut proj, "data_asset");
        }
        for _ in 0..2 {
            create_node(&mut proj, "backup_policy");
        }

        let engine = CoverageEngine::new();
        let model = CoverageModel {
            name: "test".to_string(),
            expectations: vec![CoverageExpectation::TypeRatio {
                numerator_type: "backup_policy".to_string(),
                denominator_type: "data_asset".to_string(),
                min_ratio: 0.5,
            }],
            scope_node_type: None,
        };

        let report = engine.evaluate(&model, &proj);
        assert!(report.is_complete());
    }

    // ================================================================
    // Test 6: TypeRatio — not met
    // ================================================================
    #[test]
    fn type_ratio_not_met() {
        let mut proj = Projection::new();
        // 10 data assets, 1 backup policy → ratio = 0.1
        for _ in 0..10 {
            create_node(&mut proj, "data_asset");
        }
        create_node(&mut proj, "backup_policy");

        let engine = CoverageEngine::new();
        let model = CoverageModel {
            name: "test".to_string(),
            expectations: vec![CoverageExpectation::TypeRatio {
                numerator_type: "backup_policy".to_string(),
                denominator_type: "data_asset".to_string(),
                min_ratio: 0.5,
            }],
            scope_node_type: None,
        };

        let report = engine.evaluate(&model, &proj);
        assert!(!report.is_complete());
        assert_eq!(report.gaps.len(), 1);
        // fulfillment = 0.1 / 0.5 = 0.2
        assert!((report.gaps[0].fulfillment - 0.2).abs() < 0.001);
    }

    // ================================================================
    // Test 7: Multiple expectations — mixed results
    // ================================================================
    #[test]
    fn mixed_expectations() {
        let mut proj = Projection::new();
        let ec2 = create_node(&mut proj, "ec2");
        let vpc = create_node(&mut proj, "vpc");
        create_edge(&mut proj, &ec2, &vpc, "in_vpc");
        // No RDS nodes (gap)

        let engine = CoverageEngine::new();
        let model = CoverageModel {
            name: "sentinel_aws".to_string(),
            expectations: vec![
                CoverageExpectation::MinNodeCount {
                    node_type: "ec2".to_string(),
                    min_count: 1,
                },
                CoverageExpectation::MinNodeCount {
                    node_type: "rds".to_string(),
                    min_count: 1,
                },
                CoverageExpectation::EdgeCoverage {
                    source_type: "ec2".to_string(),
                    edge_type: "in_vpc".to_string(),
                    target_type: "vpc".to_string(),
                    min_per_source: 1,
                },
            ],
            scope_node_type: None,
        };

        let report = engine.evaluate(&model, &proj);
        assert_eq!(report.total_expectations, 3);
        assert_eq!(report.met, 2);
        assert_eq!(report.gaps.len(), 1);
        // Score: 2 fully met + 0 fulfillment from the gap = 2/3 ≈ 0.667
        assert!((report.score - 2.0 / 3.0).abs() < 0.001);
    }

    // ================================================================
    // Test 8: Empty graph against non-trivial model
    // ================================================================
    #[test]
    fn empty_graph_coverage() {
        let proj = Projection::new();

        let engine = CoverageEngine::new();
        let model = CoverageModel {
            name: "test".to_string(),
            expectations: vec![
                CoverageExpectation::MinNodeCount {
                    node_type: "ec2".to_string(),
                    min_count: 5,
                },
            ],
            scope_node_type: None,
        };

        let report = engine.evaluate(&model, &proj);
        assert_eq!(report.score, 0.0);
        assert_eq!(report.gaps.len(), 1);
    }

    // ================================================================
    // Test 9: Empty model → perfect score
    // ================================================================
    #[test]
    fn empty_model_perfect_score() {
        let proj = Projection::new();

        let engine = CoverageEngine::new();
        let model = CoverageModel {
            name: "empty".to_string(),
            expectations: vec![],
            scope_node_type: None,
        };

        let report = engine.evaluate(&model, &proj);
        assert_eq!(report.score, 1.0);
        assert!(report.is_complete());
    }

    // ================================================================
    // Test 10: evaluate_all runs all models
    // ================================================================
    #[test]
    fn evaluate_all() {
        let mut proj = Projection::new();
        create_node(&mut proj, "ec2");

        let mut engine = CoverageEngine::new();
        engine.add_model(CoverageModel {
            name: "model_a".to_string(),
            expectations: vec![CoverageExpectation::MinNodeCount {
                node_type: "ec2".to_string(),
                min_count: 1,
            }],
            scope_node_type: None,
        });
        engine.add_model(CoverageModel {
            name: "model_b".to_string(),
            expectations: vec![CoverageExpectation::MinNodeCount {
                node_type: "rds".to_string(),
                min_count: 1,
            }],
            scope_node_type: None,
        });

        let reports = engine.evaluate_all(&proj);
        assert_eq!(reports.len(), 2);
        assert!(reports[0].is_complete()); // ec2 exists
        assert!(!reports[1].is_complete()); // rds missing
    }

    // ================================================================
    // Test 11: EdgeCoverage with no source nodes → no gap
    // ================================================================
    #[test]
    fn edge_coverage_no_source_nodes() {
        let proj = Projection::new(); // empty graph

        let engine = CoverageEngine::new();
        let model = CoverageModel {
            name: "test".to_string(),
            expectations: vec![CoverageExpectation::EdgeCoverage {
                source_type: "ec2".to_string(),
                edge_type: "in_vpc".to_string(),
                target_type: "vpc".to_string(),
                min_per_source: 1,
            }],
            scope_node_type: None,
        };

        let report = engine.evaluate(&model, &proj);
        // No source nodes → can't evaluate → not a gap
        assert!(report.is_complete());
    }

    // ================================================================
    // Test 12: TypeRatio with zero denominator → no gap
    // ================================================================
    #[test]
    fn type_ratio_zero_denominator() {
        let proj = Projection::new();

        let engine = CoverageEngine::new();
        let model = CoverageModel {
            name: "test".to_string(),
            expectations: vec![CoverageExpectation::TypeRatio {
                numerator_type: "backup_policy".to_string(),
                denominator_type: "data_asset".to_string(),
                min_ratio: 0.5,
            }],
            scope_node_type: None,
        };

        let report = engine.evaluate(&model, &proj);
        // No denominator → undefined → not a gap
        assert!(report.is_complete());
    }
}
