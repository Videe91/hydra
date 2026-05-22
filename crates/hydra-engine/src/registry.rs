use hydra_core::event::Event;
use hydra_core::id::SubscriptionId;
use hydra_core::subscription::{EventFilter, Subscription};

/// Registry that stores all subscriptions and matches events against them.
/// Subscriptions are returned in priority order (highest first).
pub struct SubscriptionRegistry {
    subscriptions: Vec<Subscription>,
}

impl SubscriptionRegistry {
    pub fn new() -> Self {
        Self {
            subscriptions: Vec::new(),
        }
    }

    /// Register a new subscription
    pub fn register(&mut self, sub: Subscription) -> SubscriptionId {
        let id = sub.id.clone();
        self.subscriptions.push(sub);
        // Keep sorted by priority (descending) for consistent firing order
        self.subscriptions
            .sort_by(|a, b| b.priority.cmp(&a.priority));
        id
    }

    /// Unregister a subscription by ID
    pub fn unregister(&mut self, id: &SubscriptionId) -> bool {
        let before = self.subscriptions.len();
        self.subscriptions.retain(|s| &s.id != id);
        self.subscriptions.len() < before
    }

    /// Enable/disable a subscription
    pub fn set_enabled(&mut self, id: &SubscriptionId, enabled: bool) -> bool {
        if let Some(sub) = self.subscriptions.iter_mut().find(|s| &s.id == id) {
            sub.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Get all enabled subscriptions that match an event, sorted by priority (high first).
    /// Tenant isolation: if a subscription has a tenant_id, it only matches events
    /// with the same tenant_id. Subscriptions with tenant_id=None match all events.
    pub fn matching_subscriptions(&self, event: &Event) -> Vec<&Subscription> {
        self.subscriptions
            .iter()
            .filter(|s| {
                if !s.enabled {
                    return false;
                }
                // Tenant isolation check
                if let Some(ref sub_tenant) = s.tenant_id {
                    match &event.tenant_id {
                        Some(evt_tenant) if evt_tenant == sub_tenant => {}
                        _ => return false, // Tenant mismatch → skip
                    }
                }
                s.filter.matches(event)
            })
            .collect()
    }

    /// How many subscriptions are registered
    pub fn count(&self) -> usize {
        self.subscriptions.len()
    }

    /// How many subscriptions are enabled
    pub fn enabled_count(&self) -> usize {
        self.subscriptions.iter().filter(|s| s.enabled).count()
    }

    /// Get a subscription by ID
    pub fn get(&self, id: &SubscriptionId) -> Option<&Subscription> {
        self.subscriptions.iter().find(|s| &s.id == id)
    }

    /// Replace a subscription's event filter. Used by the self-evolution system
    /// to apply approved mutations. Does not change priority, handler, or enabled state.
    pub fn set_filter(&mut self, id: &SubscriptionId, filter: EventFilter) -> bool {
        if let Some(sub) = self.subscriptions.iter_mut().find(|s| &s.id == id) {
            sub.filter = filter;
            true
        } else {
            false
        }
    }

    /// List all subscription names (for diagnostics)
    pub fn names(&self) -> Vec<&str> {
        self.subscriptions.iter().map(|s| s.name.as_str()).collect()
    }
}

impl Default for SubscriptionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::{Event, EventKind};
    use hydra_core::id::NodeId;
    use hydra_core::subscription::{EventFilter, SubscriptionHandler};
    use std::collections::HashMap;

    struct NoopHandler;
    impl SubscriptionHandler for NoopHandler {
        fn handle(
            &self,
            _event: &Event,
            _graph: &dyn hydra_core::graph::GraphReader,
        ) -> Vec<EventKind> {
            vec![]
        }
    }

    #[test]
    fn register_and_count() {
        let mut reg = SubscriptionRegistry::new();
        assert_eq!(reg.count(), 0);

        reg.register(Subscription::new(
            "test",
            EventFilter::Any,
            100,
            Box::new(NoopHandler),
        ));
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn matching_respects_filter() {
        let mut reg = SubscriptionRegistry::new();
        reg.register(Subscription::new(
            "only_creates",
            EventFilter::NodeCreated,
            100,
            Box::new(NoopHandler),
        ));
        reg.register(Subscription::new(
            "only_signals",
            EventFilter::SignalName("test".to_string()),
            90,
            Box::new(NoopHandler),
        ));

        let create_event = Event::trigger(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "ec2".to_string(),
            properties: HashMap::new(),
        });
        let signal_event = Event::trigger(EventKind::Signal {
            name: "test".to_string(),
            source: NodeId::new(),
            payload: HashMap::new(),
        });

        let create_matches = reg.matching_subscriptions(&create_event);
        assert_eq!(create_matches.len(), 1);
        assert_eq!(create_matches[0].name, "only_creates");

        let signal_matches = reg.matching_subscriptions(&signal_event);
        assert_eq!(signal_matches.len(), 1);
        assert_eq!(signal_matches[0].name, "only_signals");
    }

    #[test]
    fn matching_sorted_by_priority_descending() {
        let mut reg = SubscriptionRegistry::new();
        reg.register(Subscription::new(
            "low",
            EventFilter::Any,
            10,
            Box::new(NoopHandler),
        ));
        reg.register(Subscription::new(
            "high",
            EventFilter::Any,
            100,
            Box::new(NoopHandler),
        ));
        reg.register(Subscription::new(
            "mid",
            EventFilter::Any,
            50,
            Box::new(NoopHandler),
        ));

        let evt = Event::trigger(EventKind::Signal {
            name: "test".to_string(),
            source: NodeId::new(),
            payload: HashMap::new(),
        });
        let matches = reg.matching_subscriptions(&evt);
        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].name, "high");
        assert_eq!(matches[1].name, "mid");
        assert_eq!(matches[2].name, "low");
    }

    #[test]
    fn unregister() {
        let mut reg = SubscriptionRegistry::new();
        let id = reg.register(Subscription::new(
            "test",
            EventFilter::Any,
            100,
            Box::new(NoopHandler),
        ));
        assert_eq!(reg.count(), 1);
        assert!(reg.unregister(&id));
        assert_eq!(reg.count(), 0);
        assert!(!reg.unregister(&id)); // Already gone
    }

    #[test]
    fn disable_subscription() {
        let mut reg = SubscriptionRegistry::new();
        let id = reg.register(Subscription::new(
            "test",
            EventFilter::Any,
            100,
            Box::new(NoopHandler),
        ));

        let evt = Event::trigger(EventKind::Signal {
            name: "x".to_string(),
            source: NodeId::new(),
            payload: HashMap::new(),
        });

        assert_eq!(reg.matching_subscriptions(&evt).len(), 1);

        reg.set_enabled(&id, false);
        assert_eq!(reg.matching_subscriptions(&evt).len(), 0);
        assert_eq!(reg.enabled_count(), 0);

        reg.set_enabled(&id, true);
        assert_eq!(reg.matching_subscriptions(&evt).len(), 1);
    }

    #[test]
    fn names_for_diagnostics() {
        let mut reg = SubscriptionRegistry::new();
        reg.register(Subscription::new(
            "alpha",
            EventFilter::Any,
            100,
            Box::new(NoopHandler),
        ));
        reg.register(Subscription::new(
            "beta",
            EventFilter::Any,
            50,
            Box::new(NoopHandler),
        ));
        let names = reg.names();
        assert_eq!(names, vec!["alpha", "beta"]);
    }
}
