use crate::sensor::SensorBatch;
use hydra_engine::cascade::CascadeResult;
use tokio::sync::{broadcast, mpsc};

/// Configuration for the event bus
#[derive(Debug, Clone)]
pub struct BusConfig {
    /// How many sensor batches can be buffered before backpressure kicks in
    pub inbound_buffer: usize,
    /// How many cascade results are buffered for subscribers
    pub outbound_buffer: usize,
}

impl Default for BusConfig {
    fn default() -> Self {
        Self {
            inbound_buffer: 1024,
            outbound_buffer: 256,
        }
    }
}

/// Metrics tracked by the event bus
#[derive(Debug, Clone, Default)]
pub struct BusMetrics {
    /// Total sensor batches received
    pub batches_received: u64,
    /// Total events ingested (across all batches)
    pub events_ingested: u64,
    /// Total cascades processed successfully
    pub cascades_processed: u64,
    /// Total cascade (ingestion) errors
    pub cascade_errors: u64,
    /// Total storage persistence errors
    pub storage_errors: u64,
    /// Total events produced by cascades (including reactions)
    pub events_produced: u64,
    /// Total cascades that were truncated (hit depth/event limit)
    pub cascades_truncated: u64,
}

/// A published cascade result for subscribers to consume
#[derive(Debug, Clone)]
pub struct CascadeNotification {
    /// The sensor that triggered this cascade
    pub sensor_name: String,
    /// How many events the cascade produced
    pub event_count: usize,
    /// How many mutations to the graph
    pub mutation_count: usize,
    /// Peak cascade depth
    pub max_depth: u32,
    /// Whether the cascade was truncated
    pub truncated: bool,
    /// The trigger event ID
    pub trigger_event_id: hydra_core::id::EventId,
    /// The cascade ID
    pub cascade_id: hydra_core::id::CascadeId,
}

impl CascadeNotification {
    pub fn from_result(result: &CascadeResult, sensor_name: &str) -> Option<Self> {
        let trigger = result.events.first()?;
        Some(Self {
            sensor_name: sensor_name.to_string(),
            event_count: result.events.len(),
            mutation_count: result.mutations,
            max_depth: result.max_depth_reached,
            truncated: result.truncated,
            trigger_event_id: trigger.id.clone(),
            cascade_id: trigger.cascade_id.clone(),
        })
    }
}

/// The outbound side of the bus — subscribers listen for cascade results
pub struct BusOutbound {
    pub sender: broadcast::Sender<CascadeNotification>,
}

impl BusOutbound {
    /// Subscribe to cascade notifications
    pub fn subscribe(&self) -> broadcast::Receiver<CascadeNotification> {
        self.sender.subscribe()
    }
}

/// Create a matched pair of inbound + outbound bus channels.
/// Returns (sender, receiver, outbound) — the sender goes to the handle,
/// the receiver goes to the processor.
///
/// # Panics
/// Panics if `inbound_buffer` or `outbound_buffer` is 0.
pub fn create_bus(config: &BusConfig) -> (mpsc::Sender<SensorBatch>, mpsc::Receiver<SensorBatch>, BusOutbound) {
    assert!(config.inbound_buffer > 0, "inbound_buffer must be > 0");
    assert!(config.outbound_buffer > 0, "outbound_buffer must be > 0");

    let (in_tx, in_rx) = mpsc::channel(config.inbound_buffer);
    let (out_tx, _) = broadcast::channel(config.outbound_buffer);

    (in_tx, in_rx, BusOutbound { sender: out_tx })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::EventKind;
    use hydra_core::id::NodeId;
    use std::collections::HashMap;

    fn make_batch(name: &str, count: usize) -> SensorBatch {
        let events: Vec<EventKind> = (0..count)
            .map(|i| EventKind::NodeCreated {
                node_id: NodeId::new(),
                type_id: format!("type_{}", i),
                properties: HashMap::new(),
            })
            .collect();
        SensorBatch::new(name, events)
    }

    #[tokio::test]
    async fn bus_inbound_sends_and_receives() {
        let config = BusConfig::default();
        let (sender, mut receiver, _outbound) = create_bus(&config);

        let batch = make_batch("sensor_a", 3);
        sender.send(batch).await.unwrap();

        let received = receiver.recv().await.unwrap();
        assert_eq!(received.sensor_name, "sensor_a");
        assert_eq!(received.len(), 3);
    }

    #[tokio::test]
    async fn bus_outbound_broadcast() {
        let config = BusConfig::default();
        let (_sender, _receiver, outbound) = create_bus(&config);

        let mut sub1 = outbound.subscribe();
        let mut sub2 = outbound.subscribe();

        let notification = CascadeNotification {
            sensor_name: "test".to_string(),
            event_count: 5,
            mutation_count: 3,
            max_depth: 2,
            truncated: false,
            trigger_event_id: hydra_core::id::EventId::new(),
            cascade_id: hydra_core::id::CascadeId::new(),
        };

        outbound.sender.send(notification).unwrap();

        let n1 = sub1.recv().await.unwrap();
        let n2 = sub2.recv().await.unwrap();
        assert_eq!(n1.event_count, 5);
        assert_eq!(n2.event_count, 5);
    }

    #[tokio::test]
    async fn bus_backpressure() {
        // Small buffer to test backpressure
        let config = BusConfig {
            inbound_buffer: 2,
            outbound_buffer: 2,
        };
        let (sender, _receiver, _outbound) = create_bus(&config);

        // Fill the buffer
        sender.send(make_batch("a", 1)).await.unwrap();
        sender.send(make_batch("b", 1)).await.unwrap();

        // Third send should not complete immediately (buffer full)
        let send_result = sender.try_send(make_batch("c", 1));
        assert!(send_result.is_err()); // Channel full
    }

    #[test]
    fn cascade_notification_from_result() {
        use hydra_core::event::Event;

        let trigger = Event::trigger(EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: "ec2".to_string(),
            properties: HashMap::new(),
        });

        let result = CascadeResult {
            events: vec![trigger],
            mutations: 1,
            max_depth_reached: 0,
            truncated: false,
        };

        let notif = CascadeNotification::from_result(&result, "cloudtrail").unwrap();
        assert_eq!(notif.sensor_name, "cloudtrail");
        assert_eq!(notif.event_count, 1);
        assert_eq!(notif.mutation_count, 1);
        assert!(!notif.truncated);
    }

    #[test]
    fn cascade_notification_from_empty_result() {
        let result = CascadeResult {
            events: vec![],
            mutations: 0,
            max_depth_reached: 0,
            truncated: false,
        };
        assert!(CascadeNotification::from_result(&result, "test").is_none());
    }

    #[test]
    fn bus_metrics_default() {
        let m = BusMetrics::default();
        assert_eq!(m.batches_received, 0);
        assert_eq!(m.events_ingested, 0);
        assert_eq!(m.cascades_processed, 0);
    }
}
