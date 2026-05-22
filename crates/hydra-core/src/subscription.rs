use crate::event::{Event, EventKind};
use crate::id::{NodeId, SubscriptionId, TenantId};

/// Filters that determine which events a subscription reacts to.
/// Composable with And/Or/Not for complex patterns.
#[derive(Debug, Clone)]
pub enum EventFilter {
    /// Match any event (useful as a catch-all)
    Any,

    /// Match events on a specific node
    Node(NodeId),

    /// Match events on any node of a given type
    NodeType(String),

    /// Match a specific event kind by name
    EventKindName(String),

    /// Match NodeCreated events specifically
    NodeCreated,

    /// Match NodeUpdated events specifically
    NodeUpdated,

    /// Match NodeDeleted events specifically
    NodeDeleted,

    /// Match EdgeCreated events specifically
    EdgeCreated,

    /// Match Signal events with a specific signal name
    SignalName(String),

    /// Logical AND: all sub-filters must match
    And(Vec<EventFilter>),

    /// Logical OR: at least one sub-filter must match
    Or(Vec<EventFilter>),

    /// Logical NOT: inverts the sub-filter
    Not(Box<EventFilter>),
}

impl EventFilter {
    /// Test whether an event matches this filter
    pub fn matches(&self, event: &Event) -> bool {
        match self {
            EventFilter::Any => true,

            EventFilter::Node(node_id) => event
                .kind
                .target_node()
                .map_or(false, |target| target == node_id),

            EventFilter::NodeType(type_id) => match &event.kind {
                EventKind::NodeCreated {
                    type_id: t, ..
                } => t == type_id,
                // For NodeUpdated/NodeDeleted, we'd need the graph to look up the type.
                // At the filter level, we can only match on NodeCreated type_id.
                // The engine enriches the filter context for non-creation events.
                _ => false,
            },

            EventFilter::EventKindName(name) => event.kind.kind_name() == name.as_str(),

            EventFilter::NodeCreated => matches!(event.kind, EventKind::NodeCreated { .. }),

            EventFilter::NodeUpdated => matches!(event.kind, EventKind::NodeUpdated { .. }),

            EventFilter::NodeDeleted => matches!(event.kind, EventKind::NodeDeleted { .. }),

            EventFilter::EdgeCreated => matches!(event.kind, EventKind::EdgeCreated { .. }),

            EventFilter::SignalName(name) => matches!(
                &event.kind,
                EventKind::Signal { name: n, .. } if n == name
            ),

            EventFilter::And(filters) => filters.iter().all(|f| f.matches(event)),

            EventFilter::Or(filters) => filters.iter().any(|f| f.matches(event)),

            EventFilter::Not(filter) => !filter.matches(event),
        }
    }
}

/// A registered subscription — a filter + handler + priority.
///
/// When the cascade engine processes an event, it checks all subscriptions.
/// Matching subscriptions fire in priority order (highest first).
/// Each handler can produce new events, which re-enter the cascade.
pub struct Subscription {
    pub id: SubscriptionId,
    pub name: String,
    pub filter: EventFilter,
    pub priority: u32,
    pub handler: Box<dyn SubscriptionHandler>,
    pub enabled: bool,
    /// If set, this subscription only fires for events from this tenant.
    /// If None, fires for all events (backward compatible default).
    pub tenant_id: Option<TenantId>,
}

impl Subscription {
    pub fn new(
        name: impl Into<String>,
        filter: EventFilter,
        priority: u32,
        handler: Box<dyn SubscriptionHandler>,
    ) -> Self {
        Self {
            id: SubscriptionId::new(),
            name: name.into(),
            filter,
            priority,
            handler,
            enabled: true,
            tenant_id: None,
        }
    }

    /// Create a tenant-scoped subscription.
    /// Only fires for events belonging to the specified tenant.
    pub fn for_tenant(
        name: impl Into<String>,
        filter: EventFilter,
        priority: u32,
        handler: Box<dyn SubscriptionHandler>,
        tenant: TenantId,
    ) -> Self {
        Self {
            id: SubscriptionId::new(),
            name: name.into(),
            filter,
            priority,
            handler,
            enabled: true,
            tenant_id: Some(tenant),
        }
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("priority", &self.priority)
            .field("enabled", &self.enabled)
            .field("tenant_id", &self.tenant_id)
            .finish()
    }
}

/// The handler trait. Domain code implements this to react to events.
///
/// Handlers receive:
/// - The triggering event
/// - A read-only view of the graph (GraphReader)
///
/// Handlers return:
/// - A list of new EventKind values to be emitted as reactions
///
/// Handlers MUST NOT have side effects (no I/O, no network, no file access).
/// They are pure functions: event + graph state → new events.
/// This ensures deterministic cascade processing.
pub trait SubscriptionHandler: Send + Sync {
    /// Process the triggering event. Return new events to emit.
    /// The returned EventKinds will be wrapped in Event structs by the cascade engine
    /// with proper causal links (caused_by = triggering event).
    fn handle(
        &self,
        event: &Event,
        graph: &dyn crate::graph::GraphReader,
    ) -> Vec<EventKind>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventKind};
    use crate::id::NodeId;
    use std::collections::HashMap;

    fn make_node_created(type_id: &str) -> Event {
        Event::trigger(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: type_id.to_string(),
            properties: HashMap::new(),
        })
    }

    fn make_node_updated() -> Event {
        Event::trigger(EventKind::NodeUpdated {
            node_id: NodeId::new(),
            changes: HashMap::new(),
        })
    }

    fn make_signal(name: &str) -> Event {
        Event::trigger(EventKind::Signal {
            name: name.to_string(),
            source: NodeId::new(),
            payload: HashMap::new(),
        })
    }

    #[test]
    fn filter_any_matches_everything() {
        let filter = EventFilter::Any;
        assert!(filter.matches(&make_node_created("ec2")));
        assert!(filter.matches(&make_signal("test")));
    }

    #[test]
    fn filter_node_created() {
        let filter = EventFilter::NodeCreated;
        assert!(filter.matches(&make_node_created("ec2")));
        assert!(!filter.matches(&make_node_updated()));
        assert!(!filter.matches(&make_signal("test")));
    }

    #[test]
    fn filter_node_type() {
        let filter = EventFilter::NodeType("ec2_instance".to_string());
        assert!(filter.matches(&make_node_created("ec2_instance")));
        assert!(!filter.matches(&make_node_created("rds_database")));
    }

    #[test]
    fn filter_signal_name() {
        let filter = EventFilter::SignalName("classify".to_string());
        assert!(filter.matches(&make_signal("classify")));
        assert!(!filter.matches(&make_signal("other")));
        assert!(!filter.matches(&make_node_created("ec2")));
    }

    #[test]
    fn filter_specific_node() {
        let target = NodeId::from_str("node_SPECIFIC");
        let filter = EventFilter::Node(target.clone());

        let matching = Event::trigger(EventKind::NodeUpdated {
            node_id: target,
            changes: HashMap::new(),
        });
        assert!(filter.matches(&matching));

        let non_matching = Event::trigger(EventKind::NodeUpdated {
            node_id: NodeId::from_str("node_OTHER"),
            changes: HashMap::new(),
        });
        assert!(!filter.matches(&non_matching));
    }

    #[test]
    fn filter_and_composition() {
        let filter = EventFilter::And(vec![
            EventFilter::NodeCreated,
            EventFilter::NodeType("ec2_instance".to_string()),
        ]);

        assert!(filter.matches(&make_node_created("ec2_instance")));
        assert!(!filter.matches(&make_node_created("rds")));
        assert!(!filter.matches(&make_node_updated()));
    }

    #[test]
    fn filter_or_composition() {
        let filter = EventFilter::Or(vec![
            EventFilter::NodeType("ec2_instance".to_string()),
            EventFilter::NodeType("rds_database".to_string()),
        ]);

        assert!(filter.matches(&make_node_created("ec2_instance")));
        assert!(filter.matches(&make_node_created("rds_database")));
        assert!(!filter.matches(&make_node_created("s3_bucket")));
    }

    #[test]
    fn filter_not() {
        let filter = EventFilter::Not(Box::new(EventFilter::NodeCreated));

        assert!(!filter.matches(&make_node_created("ec2")));
        assert!(filter.matches(&make_node_updated()));
        assert!(filter.matches(&make_signal("test")));
    }

    #[test]
    fn filter_complex_composition() {
        // Match: (NodeCreated AND ec2_instance) OR classify signal
        let filter = EventFilter::Or(vec![
            EventFilter::And(vec![
                EventFilter::NodeCreated,
                EventFilter::NodeType("ec2_instance".to_string()),
            ]),
            EventFilter::SignalName("classify".to_string()),
        ]);

        assert!(filter.matches(&make_node_created("ec2_instance")));
        assert!(filter.matches(&make_signal("classify")));
        assert!(!filter.matches(&make_node_created("rds")));
        assert!(!filter.matches(&make_signal("other")));
    }

    #[test]
    fn filter_event_kind_name() {
        let filter = EventFilter::EventKindName("signal".to_string());
        assert!(filter.matches(&make_signal("anything")));
        assert!(!filter.matches(&make_node_created("ec2")));
    }

    #[test]
    fn subscription_creation() {
        struct DummyHandler;
        impl SubscriptionHandler for DummyHandler {
            fn handle(&self, _: &Event, _: &dyn crate::graph::GraphReader) -> Vec<EventKind> {
                vec![]
            }
        }

        let sub = Subscription::new(
            "classify_on_discover",
            EventFilter::NodeCreated,
            100,
            Box::new(DummyHandler),
        );

        assert_eq!(sub.name, "classify_on_discover");
        assert_eq!(sub.priority, 100);
        assert!(sub.enabled);
        assert!(sub.id.as_str().starts_with("sub_"));
    }

    // === Adversarial tests (code review audit) ===

    #[test]
    fn empty_and_matches_everything() {
        // Mathematical identity: AND of nothing is true (vacuous truth)
        let filter = EventFilter::And(vec![]);
        assert!(filter.matches(&make_node_created("ec2")));
        assert!(filter.matches(&make_signal("test")));
    }

    #[test]
    fn empty_or_matches_nothing() {
        // Mathematical identity: OR of nothing is false
        let filter = EventFilter::Or(vec![]);
        assert!(!filter.matches(&make_node_created("ec2")));
        assert!(!filter.matches(&make_signal("test")));
    }

    #[test]
    fn deeply_nested_filters_dont_stack_overflow() {
        // Build a 100-deep nested Not(Not(Not(...)))
        let mut filter = EventFilter::NodeCreated;
        for _ in 0..100 {
            filter = EventFilter::Not(Box::new(filter));
        }
        // 100 nots = even number = same as original (NodeCreated)
        assert!(filter.matches(&make_node_created("ec2")));
        assert!(!filter.matches(&make_signal("test")));
    }

    #[test]
    fn double_not_is_identity() {
        let filter = EventFilter::Not(Box::new(EventFilter::Not(Box::new(
            EventFilter::NodeCreated,
        ))));
        assert!(filter.matches(&make_node_created("ec2")));
        assert!(!filter.matches(&make_signal("test")));
    }
}
