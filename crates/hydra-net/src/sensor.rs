use hydra_core::event::EventKind;
use std::fmt;

/// A sensor connects to an external system and emits events into Hydra.
///
/// Examples:
/// - CloudTrailSensor: polls AWS CloudTrail and emits NodeCreated/NodeUpdated events
/// - WebhookSensor: receives HTTP webhooks and translates them to EventKinds
/// - PollerSensor: periodically calls an API and diffs state
///
/// Sensors are async — they run as tokio tasks, polling or listening,
/// and push EventKinds into the event bus when they detect changes.
///
/// Lifecycle:
/// 1. Runtime calls `start()` — sensor begins polling/listening
/// 2. Sensor calls `emitter.emit(event_kind)` whenever it detects a change
/// 3. Runtime calls `stop()` or drops the sensor — sensor shuts down gracefully
///
/// Sensors must be:
/// - Idempotent: re-processing the same external event produces the same EventKind
/// - Resilient: transient failures (network timeout, API error) are retried, not fatal
/// - Bounded: backpressure from the bus (full channel) causes the sensor to slow down, not crash

/// What a sensor sends back: a batch of EventKinds discovered from the external world.
#[derive(Debug, Clone)]
pub struct SensorBatch {
    /// The sensor that produced this batch
    pub sensor_name: String,
    /// The events discovered
    pub events: Vec<EventKind>,
    /// Opaque cursor for the sensor to track where it left off
    /// (e.g., CloudTrail NextToken, last poll timestamp)
    pub cursor: Option<String>,
}

impl SensorBatch {
    pub fn new(sensor_name: impl Into<String>, events: Vec<EventKind>) -> Self {
        Self {
            sensor_name: sensor_name.into(),
            events,
            cursor: None,
        }
    }

    pub fn with_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }
}

/// The emitter that sensors use to push events into the bus.
/// Wraps a tokio mpsc sender with backpressure.
#[derive(Clone)]
pub struct SensorEmitter {
    sender: tokio::sync::mpsc::Sender<SensorBatch>,
    sensor_name: String,
}

impl SensorEmitter {
    pub(crate) fn new(
        sender: tokio::sync::mpsc::Sender<SensorBatch>,
        sensor_name: String,
    ) -> Self {
        Self {
            sender,
            sensor_name,
        }
    }

    /// Emit a batch of events. Blocks (async) if the channel is full (backpressure).
    /// Returns Err if the runtime has shut down (receiver dropped).
    pub async fn emit(&self, events: Vec<EventKind>) -> SensorResult<()> {
        if events.is_empty() {
            return Ok(());
        }
        let batch = SensorBatch::new(self.sensor_name.clone(), events);
        self.sender
            .send(batch)
            .await
            .map_err(|_| SensorError::RuntimeShutdown)
    }

    /// Emit a single event
    pub async fn emit_one(&self, event: EventKind) -> SensorResult<()> {
        self.emit(vec![event]).await
    }

    /// Emit a batch with a cursor for resumption
    pub async fn emit_with_cursor(
        &self,
        events: Vec<EventKind>,
        cursor: impl Into<String>,
    ) -> SensorResult<()> {
        if events.is_empty() {
            return Ok(());
        }
        let batch = SensorBatch::new(self.sensor_name.clone(), events)
            .with_cursor(cursor);
        self.sender
            .send(batch)
            .await
            .map_err(|_| SensorError::RuntimeShutdown)
    }
}

impl fmt::Debug for SensorEmitter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensorEmitter")
            .field("sensor_name", &self.sensor_name)
            .finish()
    }
}

/// Errors that sensors can produce
#[derive(Debug)]
pub enum SensorError {
    /// The runtime has shut down — stop emitting
    RuntimeShutdown,
    /// A transient error that the sensor can retry
    Transient(String),
    /// A permanent error — the sensor should stop
    Fatal(String),
}

impl fmt::Display for SensorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeShutdown => write!(f, "runtime has shut down"),
            Self::Transient(msg) => write!(f, "transient sensor error: {}", msg),
            Self::Fatal(msg) => write!(f, "fatal sensor error: {}", msg),
        }
    }
}

impl std::error::Error for SensorError {}

pub type SensorResult<T> = std::result::Result<T, SensorError>;

/// A simple polling sensor that calls a closure on each tick.
/// Useful for building sensors without implementing the full trait.
pub struct PollSensor<F>
where
    F: Fn() -> Vec<EventKind> + Send + Sync + 'static,
{
    name: String,
    poll_fn: F,
    interval: std::time::Duration,
    cancel: tokio::sync::watch::Receiver<bool>,
}

/// Handle to stop a PollSensor gracefully
#[derive(Clone)]
pub struct PollSensorHandle {
    cancel: tokio::sync::watch::Sender<bool>,
}

impl PollSensorHandle {
    /// Signal the sensor to stop after its current tick
    pub fn stop(&self) {
        let _ = self.cancel.send(true);
    }
}

impl<F> PollSensor<F>
where
    F: Fn() -> Vec<EventKind> + Send + Sync + 'static,
{
    /// Create a new PollSensor with a cancel handle.
    /// Returns (sensor, handle) — drop or call handle.stop() to shut down.
    pub fn new(
        name: impl Into<String>,
        interval: std::time::Duration,
        poll_fn: F,
    ) -> (Self, PollSensorHandle) {
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let sensor = Self {
            name: name.into(),
            poll_fn,
            interval,
            cancel: cancel_rx,
        };
        let handle = PollSensorHandle { cancel: cancel_tx };
        (sensor, handle)
    }

    /// Run the poll loop, emitting events on each tick.
    /// Stops gracefully when the cancel handle is dropped or stop() is called.
    pub async fn run(&mut self, emitter: SensorEmitter) -> SensorResult<()> {
        let mut interval = tokio::time::interval(self.interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let events = (self.poll_fn)();
                    if !events.is_empty() {
                        emitter.emit(events).await?;
                    }
                }
                _ = self.cancel.changed() => {
                    // Cancel signal received — shut down gracefully
                    return Ok(());
                }
            }
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl<F> fmt::Debug for PollSensor<F>
where
    F: Fn() -> Vec<EventKind> + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PollSensor")
            .field("name", &self.name)
            .field("interval", &self.interval)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::EventKind;
    use hydra_core::id::NodeId;
    use std::collections::HashMap;

    fn make_event(type_id: &str) -> EventKind {
        EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: type_id.to_string(),
            properties: HashMap::new(),
        }
    }

    #[test]
    fn sensor_batch_creation() {
        let batch = SensorBatch::new("test_sensor", vec![make_event("ec2")]);
        assert_eq!(batch.sensor_name, "test_sensor");
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
        assert!(batch.cursor.is_none());
    }

    #[test]
    fn sensor_batch_with_cursor() {
        let batch = SensorBatch::new("test", vec![make_event("ec2")])
            .with_cursor("next_token_abc");
        assert_eq!(batch.cursor, Some("next_token_abc".to_string()));
    }

    #[test]
    fn empty_batch() {
        let batch = SensorBatch::new("test", vec![]);
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
    }

    #[tokio::test]
    async fn emitter_sends_through_channel() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let emitter = SensorEmitter::new(tx, "test_sensor".to_string());

        emitter.emit_one(make_event("ec2")).await.unwrap();

        let batch = rx.recv().await.unwrap();
        assert_eq!(batch.sensor_name, "test_sensor");
        assert_eq!(batch.len(), 1);
    }

    #[tokio::test]
    async fn emitter_skip_empty() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let emitter = SensorEmitter::new(tx, "test".to_string());

        // Empty emit should be a no-op
        emitter.emit(vec![]).await.unwrap();

        // Channel should be empty
        let result = rx.try_recv();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn emitter_detects_shutdown() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let emitter = SensorEmitter::new(tx, "test".to_string());

        // Drop receiver to simulate shutdown
        drop(rx);

        let result = emitter.emit_one(make_event("ec2")).await;
        assert!(matches!(result, Err(SensorError::RuntimeShutdown)));
    }

    #[tokio::test]
    async fn emitter_with_cursor() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let emitter = SensorEmitter::new(tx, "ct".to_string());

        emitter
            .emit_with_cursor(vec![make_event("ec2")], "token_xyz")
            .await
            .unwrap();

        let batch = rx.recv().await.unwrap();
        assert_eq!(batch.cursor, Some("token_xyz".to_string()));
    }

    #[test]
    fn sensor_error_display() {
        assert_eq!(
            SensorError::RuntimeShutdown.to_string(),
            "runtime has shut down"
        );
        assert!(SensorError::Transient("timeout".into())
            .to_string()
            .contains("timeout"));
        assert!(SensorError::Fatal("auth failed".into())
            .to_string()
            .contains("auth failed"));
    }

    #[tokio::test]
    async fn poll_sensor_emits_on_tick() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        let (mut sensor, cancel_handle) = PollSensor::new(
            "tick_sensor",
            std::time::Duration::from_millis(10),
            move || {
                let n = counter_clone.fetch_add(1, Ordering::Relaxed);
                if n < 3 {
                    vec![make_event(&format!("tick_{}", n))]
                } else {
                    vec![]
                }
            },
        );

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let emitter = SensorEmitter::new(tx, sensor.name().to_string());

        // Run sensor for a short time then cancel
        let handle = tokio::spawn(async move {
            sensor.run(emitter).await
        });

        // Collect at least 3 batches
        let mut received = 0;
        let timeout = tokio::time::sleep(std::time::Duration::from_millis(200));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                Some(batch) = rx.recv() => {
                    received += batch.len();
                    if received >= 3 { break; }
                }
                _ = &mut timeout => { break; }
            }
        }

        cancel_handle.stop();
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "PollSensor should return Ok on cancel");
        assert!(received >= 3, "Expected at least 3 events, got {}", received);
    }
}
