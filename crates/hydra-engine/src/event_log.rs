use hydra_core::event::Event;
use hydra_core::id::{CascadeId, EventId};
use std::collections::HashMap;

/// Configuration for event log retention.
#[derive(Debug, Clone)]
pub struct EventLogConfig {
    /// Maximum number of events to keep in memory.
    /// When exceeded, oldest events are auto-compacted.
    /// Default: usize::MAX (unlimited).
    pub max_events: usize,
    /// How many events to remove during auto-compaction (as a fraction).
    /// Default: 0.2 (remove oldest 20%).
    pub compact_fraction: f64,
}

impl Default for EventLogConfig {
    fn default() -> Self {
        Self {
            max_events: usize::MAX,
            compact_fraction: 0.2,
        }
    }
}

/// Append-only event log. The single source of truth.
/// All events ever processed are stored here in order.
///
/// Provides causal chain queries:
/// - causal_chain(id): what did this event cause? (forward)
/// - root_cause(id): what triggered this event? (backward)
/// - cascade_events(cascade_id): all events in a cascade
#[derive(Debug)]
pub struct EventLog {
    /// Events in insertion order
    events: Vec<Event>,
    /// ID → index for O(1) lookup
    index: HashMap<EventId, usize>,
    /// CascadeId → list of event indices
    cascade_index: HashMap<CascadeId, Vec<usize>>,
    /// Parent EventId → list of child event indices (forward causal links)
    children_index: HashMap<EventId, Vec<usize>>,
    /// Configuration for retention and auto-compaction
    config: EventLogConfig,
    /// Total events ever appended (including compacted ones)
    total_appended: u64,
}

impl EventLog {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            index: HashMap::new(),
            cascade_index: HashMap::new(),
            children_index: HashMap::new(),
            config: EventLogConfig::default(),
            total_appended: 0,
        }
    }

    /// Create with a retention config.
    pub fn with_config(config: EventLogConfig) -> Self {
        Self {
            events: Vec::new(),
            index: HashMap::new(),
            cascade_index: HashMap::new(),
            children_index: HashMap::new(),
            config,
            total_appended: 0,
        }
    }

    /// Set the config (can be changed at runtime).
    pub fn set_config(&mut self, config: EventLogConfig) {
        self.config = config;
    }

    /// Append an event to the log and update all indexes
    pub fn append(&mut self, event: Event) {
        let idx = self.events.len();
        self.index.insert(event.id.clone(), idx);

        // Update cascade index
        self.cascade_index
            .entry(event.cascade_id.clone())
            .or_default()
            .push(idx);

        // Update children index (forward causal links)
        for parent_id in &event.caused_by {
            self.children_index
                .entry(parent_id.clone())
                .or_default()
                .push(idx);
        }

        self.events.push(event);
        self.total_appended += 1;
    }

    /// Auto-compact if the event log exceeds the configured maximum.
    /// Removes the oldest fraction of events (default 20%).
    /// Returns the number of events removed, or 0 if no compaction needed.
    pub fn auto_compact(&mut self) -> usize {
        if self.events.len() <= self.config.max_events {
            return 0;
        }

        let remove_count = (self.events.len() as f64 * self.config.compact_fraction) as usize;
        let remove_count = remove_count.max(1).min(self.events.len() - 1);

        // Find the cutoff event
        if let Some(cutoff_event) = self.events.get(remove_count - 1) {
            let cutoff_id = cutoff_event.id.clone();
            self.compact(&cutoff_id)
        } else {
            0
        }
    }

    /// Total events ever appended (including compacted ones).
    pub fn total_appended(&self) -> u64 {
        self.total_appended
    }

    /// Get an event by ID
    pub fn get(&self, id: &EventId) -> Option<&Event> {
        self.index.get(id).map(|&idx| &self.events[idx])
    }

    /// Get all events in a cascade, in order
    pub fn cascade_events(&self, cascade_id: &CascadeId) -> Vec<&Event> {
        self.cascade_index
            .get(cascade_id)
            .map(|indices| indices.iter().map(|&idx| &self.events[idx]).collect())
            .unwrap_or_default()
    }

    /// Trace the causal chain forward: what did this event cause?
    /// Returns all descendant events in BFS order.
    pub fn causal_chain(&self, id: &EventId) -> Vec<&Event> {
        use std::collections::{HashSet, VecDeque};

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        visited.insert(id.clone());
        queue.push_back(id.clone());

        while let Some(current_id) = queue.pop_front() {
            if let Some(children) = self.children_index.get(&current_id) {
                for &child_idx in children {
                    let child = &self.events[child_idx];
                    if !visited.contains(&child.id) {
                        visited.insert(child.id.clone());
                        result.push(child);
                        queue.push_back(child.id.clone());
                    }
                }
            }
        }

        result
    }

    /// Trace backward to the root cause: what triggered this event?
    /// Returns the chain from this event back to the trigger, oldest first.
    pub fn root_cause(&self, id: &EventId) -> Vec<&Event> {
        let mut chain = Vec::new();
        let mut current_id = id.clone();

        loop {
            let event = match self.get(&current_id) {
                Some(e) => e,
                None => break,
            };

            chain.push(event);

            if event.caused_by.is_empty() {
                break; // Reached the trigger
            }

            // Follow the first parent (primary cause)
            current_id = event.caused_by[0].clone();
        }

        chain.reverse(); // Oldest first
        chain
    }

    /// Total number of events
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// All events, in order
    pub fn iter(&self) -> impl Iterator<Item = &Event> {
        self.events.iter()
    }

    /// Events in reverse order (most recent first)
    pub fn iter_rev(&self) -> impl Iterator<Item = &Event> {
        self.events.iter().rev()
    }

    /// Count events in a cascade
    pub fn cascade_size(&self, cascade_id: &CascadeId) -> usize {
        self.cascade_index
            .get(cascade_id)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Compact the event log by removing events at or before the given event ID.
    /// This is called after a snapshot is taken — events before the snapshot
    /// are no longer needed for projection rebuild.
    ///
    /// Returns the number of events removed.
    /// Causal chain queries for compacted events will return empty — this is
    /// expected behavior (history before the snapshot is lost from memory).
    pub fn compact(&mut self, up_to_inclusive: &EventId) -> usize {
        let cutoff = match self.index.get(up_to_inclusive) {
            Some(&idx) => idx,
            None => return 0, // Event not found, nothing to compact
        };

        // Keep only events after the cutoff
        let kept: Vec<Event> = self.events.drain(cutoff + 1..).collect();
        let removed = self.events.len(); // events before cutoff + the cutoff event itself

        // Clear and rebuild from kept events
        self.events.clear();
        self.index.clear();
        self.cascade_index.clear();
        self.children_index.clear();

        for event in kept {
            self.append(event);
        }

        removed
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::{Event, EventKind};
    use hydra_core::id::NodeId;
    use std::collections::HashMap;

    fn make_trigger() -> Event {
        Event::trigger(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "ec2".to_string(),
            properties: HashMap::new(),
        })
    }

    #[test]
    fn append_and_get() {
        let mut log = EventLog::new();
        let evt = make_trigger();
        let id = evt.id.clone();

        log.append(evt);
        assert_eq!(log.len(), 1);
        assert!(log.get(&id).is_some());
        assert_eq!(log.get(&id).unwrap().id, id);
    }

    #[test]
    fn cascade_events_grouped() {
        let mut log = EventLog::new();
        let trigger = make_trigger();
        let cascade_id = trigger.cascade_id.clone();

        let reaction = Event::reaction(
            EventKind::NodeUpdated {
                node_id: NodeId::new(),
                changes: HashMap::new(),
            },
            &trigger,
        );

        log.append(trigger);
        log.append(reaction);

        let cascade = log.cascade_events(&cascade_id);
        assert_eq!(cascade.len(), 2);
    }

    #[test]
    fn causal_chain_forward() {
        let mut log = EventLog::new();

        let e0 = make_trigger();
        let e1 = Event::reaction(
            EventKind::NodeUpdated {
                node_id: NodeId::new(),
                changes: HashMap::new(),
            },
            &e0,
        );
        let e2 = Event::reaction(
            EventKind::Signal {
                name: "alert".to_string(),
                source: NodeId::new(),
                payload: HashMap::new(),
            },
            &e1,
        );

        let e0_id = e0.id.clone();
        let e1_id = e1.id.clone();
        let e2_id = e2.id.clone();

        log.append(e0);
        log.append(e1);
        log.append(e2);

        let chain = log.causal_chain(&e0_id);
        assert_eq!(chain.len(), 2); // e1 and e2 (not e0 itself)
        assert_eq!(chain[0].id, e1_id);
        assert_eq!(chain[1].id, e2_id);
    }

    #[test]
    fn root_cause_backward() {
        let mut log = EventLog::new();

        let e0 = make_trigger();
        let e1 = Event::reaction(
            EventKind::NodeUpdated {
                node_id: NodeId::new(),
                changes: HashMap::new(),
            },
            &e0,
        );
        let e2 = Event::reaction(
            EventKind::Signal {
                name: "alert".to_string(),
                source: NodeId::new(),
                payload: HashMap::new(),
            },
            &e1,
        );

        let e0_id = e0.id.clone();
        let e2_id = e2.id.clone();

        log.append(e0);
        log.append(e1);
        log.append(e2);

        let chain = log.root_cause(&e2_id);
        assert_eq!(chain.len(), 3); // e0, e1, e2 (oldest first)
        assert_eq!(chain[0].id, e0_id);
        assert_eq!(chain[2].id, e2_id);
        assert!(chain[0].is_trigger());
    }

    #[test]
    fn causal_chain_of_leaf_is_empty() {
        let mut log = EventLog::new();
        let evt = make_trigger();
        let id = evt.id.clone();
        log.append(evt);

        let chain = log.causal_chain(&id);
        assert!(chain.is_empty()); // No children
    }

    #[test]
    fn root_cause_of_trigger_is_itself() {
        let mut log = EventLog::new();
        let evt = make_trigger();
        let id = evt.id.clone();
        log.append(evt);

        let chain = log.root_cause(&id);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].id, id);
    }

    #[test]
    fn cascade_size() {
        let mut log = EventLog::new();
        let trigger = make_trigger();
        let cascade_id = trigger.cascade_id.clone();
        let r1 = Event::reaction(
            EventKind::Signal {
                name: "x".to_string(),
                source: NodeId::new(),
                payload: HashMap::new(),
            },
            &trigger,
        );
        let r2 = Event::reaction(
            EventKind::Signal {
                name: "y".to_string(),
                source: NodeId::new(),
                payload: HashMap::new(),
            },
            &trigger,
        );

        log.append(trigger);
        log.append(r1);
        log.append(r2);

        assert_eq!(log.cascade_size(&cascade_id), 3);
    }

    #[test]
    fn iter_order() {
        let mut log = EventLog::new();
        let e0 = make_trigger();
        let e1 = make_trigger();
        let id0 = e0.id.clone();
        let id1 = e1.id.clone();

        log.append(e0);
        log.append(e1);

        let ids: Vec<_> = log.iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids[0], id0);
        assert_eq!(ids[1], id1);

        let rev_ids: Vec<_> = log.iter_rev().map(|e| e.id.clone()).collect();
        assert_eq!(rev_ids[0], id1);
        assert_eq!(rev_ids[1], id0);
    }

    #[test]
    fn compact_removes_events_up_to_cutoff() {
        let mut log = EventLog::new();
        let e0 = make_trigger();
        let e1 = make_trigger();
        let e2 = make_trigger();
        let e3 = make_trigger();
        let id1 = e1.id.clone();
        let id2 = e2.id.clone();
        let id3 = e3.id.clone();

        log.append(e0);
        log.append(e1);
        log.append(e2);
        log.append(e3);
        assert_eq!(log.len(), 4);

        // Compact up to e1 (removes e0 and e1)
        let removed = log.compact(&id1);
        assert_eq!(removed, 2);
        assert_eq!(log.len(), 2);

        // e2 and e3 remain, e0 and e1 are gone
        assert!(log.get(&id2).is_some());
        assert!(log.get(&id3).is_some());
        assert!(log.get(&id1).is_none());
    }

    #[test]
    fn compact_nonexistent_event_is_noop() {
        let mut log = EventLog::new();
        log.append(make_trigger());
        let fake_id = hydra_core::id::EventId::from_str("evt_FAKE");
        let removed = log.compact(&fake_id);
        assert_eq!(removed, 0);
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn auto_compact_when_over_max() {
        let mut log = EventLog::with_config(EventLogConfig {
            max_events: 10,
            compact_fraction: 0.5,
        });

        for _ in 0..15 {
            log.append(make_trigger());
        }
        assert_eq!(log.len(), 15);

        let removed = log.auto_compact();
        assert!(removed >= 5, "Should remove at least 5 events, removed {}", removed);
        assert!(log.len() <= 10, "Should be under max after compact, got {}", log.len());
    }

    #[test]
    fn auto_compact_noop_when_under_max() {
        let mut log = EventLog::with_config(EventLogConfig {
            max_events: 100,
            compact_fraction: 0.2,
        });

        for _ in 0..5 {
            log.append(make_trigger());
        }

        let removed = log.auto_compact();
        assert_eq!(removed, 0);
        assert_eq!(log.len(), 5);
    }

    #[test]
    fn total_appended_tracks_across_compactions() {
        let mut log = EventLog::with_config(EventLogConfig {
            max_events: 50,
            compact_fraction: 0.5,
        });

        for _ in 0..60 {
            log.append(make_trigger());
        }

        // Should have auto-compacted at least once
        log.auto_compact();
        assert!(log.total_appended() >= 60, "Total appended should be >= 60, got {}", log.total_appended());
        assert!(log.len() < 60, "In-memory count should be less than 60 after compact");
    }
}
