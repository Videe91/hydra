use hydra_core::subscription::Subscription;
use hydra_engine::cascade::CascadeConfig;
use hydra_engine::hydra::Hydra;

/// Fluent builder for constructing a Hydra engine instance.
///
/// ```ignore
/// let hydra = HydraBuilder::new()
///     .with_cascade_depth(100)
///     .with_cascade_max_events(50_000)
///     .subscription("classify", EventFilter::NodeCreated, 100, Box::new(handler))
///     .build();
/// ```
pub struct HydraBuilder {
    config: CascadeConfig,
    subscriptions: Vec<Subscription>,
}

impl HydraBuilder {
    pub fn new() -> Self {
        Self {
            config: CascadeConfig::default(),
            subscriptions: Vec::new(),
        }
    }

    /// Set the maximum cascade depth
    pub fn with_cascade_depth(mut self, depth: u32) -> Self {
        self.config.max_depth = depth;
        self
    }

    /// Set the maximum total events per cascade
    pub fn with_cascade_max_events(mut self, max: usize) -> Self {
        self.config.max_events = max;
        self
    }

    /// Set the full cascade config
    pub fn with_cascade_config(mut self, config: CascadeConfig) -> Self {
        self.config = config;
        self
    }

    /// Add a subscription
    pub fn subscription(mut self, sub: Subscription) -> Self {
        self.subscriptions.push(sub);
        self
    }

    /// Add multiple subscriptions
    pub fn subscriptions(mut self, subs: Vec<Subscription>) -> Self {
        self.subscriptions.extend(subs);
        self
    }

    /// Build the Hydra engine
    pub fn build(self) -> Hydra {
        let mut hydra = Hydra::with_config(self.config);
        for sub in self.subscriptions {
            hydra.register(sub);
        }
        hydra
    }
}

impl Default for HydraBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::{EventKind, Value};
    use hydra_core::id::NodeId;
    use hydra_core::subscription::{EventFilter, SubscriptionHandler};
    use std::collections::HashMap;

    struct TagHandler {
        tag: String,
    }
    impl SubscriptionHandler for TagHandler {
        fn handle(
            &self,
            event: &hydra_core::event::Event,
            _graph: &dyn hydra_core::graph::GraphReader,
        ) -> Vec<EventKind> {
            if let EventKind::NodeCreated { node_id, .. } = &event.kind {
                vec![EventKind::NodeUpdated {
                    node_id: node_id.clone(),
                    changes: HashMap::from([(
                        self.tag.clone(),
                        Value::Bool(true),
                    )]),
                }]
            } else {
                vec![]
            }
        }
    }

    #[test]
    fn builder_default() {
        let hydra = HydraBuilder::new().build();
        assert_eq!(hydra.node_count(), 0);
        assert_eq!(hydra.subscription_count(), 0);
    }

    #[test]
    fn builder_with_subscriptions() {
        let mut hydra = HydraBuilder::new()
            .subscription(Subscription::new(
                "tag_a",
                EventFilter::NodeCreated,
                100,
                Box::new(TagHandler { tag: "a".into() }),
            ))
            .subscription(Subscription::new(
                "tag_b",
                EventFilter::NodeCreated,
                50,
                Box::new(TagHandler { tag: "b".into() }),
            ))
            .build();

        assert_eq!(hydra.subscription_count(), 2);

        let node_id = NodeId::new();
        let result = hydra
            .ingest(EventKind::NodeCreated {
                node_id: node_id.clone(),
                type_id: "test".to_string(),
                properties: HashMap::new(),
            })
            .unwrap();

        // 1 trigger + 2 reactions from two subscriptions
        assert_eq!(result.events.len(), 3);
        let node = hydra.graph().node(&node_id).unwrap();
        assert_eq!(node.get_bool("a"), Some(true));
        assert_eq!(node.get_bool("b"), Some(true));
    }

    #[test]
    fn builder_with_custom_config() {
        let hydra = HydraBuilder::new()
            .with_cascade_depth(10)
            .with_cascade_max_events(100)
            .build();
        // Can't inspect config directly, but it should work
        assert_eq!(hydra.node_count(), 0);
    }
}
