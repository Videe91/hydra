use crate::bus::{BusConfig, BusMetrics, BusOutbound, CascadeNotification, create_bus};
use crate::query::QueryService;
use crate::schema_admin_service::SchemaAdminService;
use crate::schema_service::SchemaService;
use crate::sensor::{SensorBatch, SensorEmitter};
use hydra_core::id::TenantId;
use hydra_core::subscription::Subscription;
use hydra_engine::cascade::CascadeConfig;
use hydra_engine::hydra::Hydra;
use hydra_storage::backend::StorageBackend;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Configuration for the Hydra runtime
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Tenant ID for this runtime instance
    pub tenant_id: TenantId,
    /// Cascade engine configuration
    pub cascade: CascadeConfig,
    /// Event bus configuration
    pub bus: BusConfig,
    /// Whether to persist events to the storage backend
    pub persist: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            tenant_id: TenantId::from_str("default"),
            cascade: CascadeConfig::default(),
            bus: BusConfig::default(),
            persist: true,
        }
    }
}

/// Builder for constructing a HydraRuntime
pub struct RuntimeBuilder {
    config: RuntimeConfig,
    subscriptions: Vec<Subscription>,
    storage: Option<Box<dyn StorageBackend>>,
    /// Optional pre-built engine. If set, [`build`] uses it instead of
    /// constructing a fresh `Hydra::with_config(self.config.cascade)`.
    /// Used by persistent bootstrap paths (e.g.
    /// `HydraRuntime::open_persistent`) that recover a Hydra from disk
    /// before wiring it into a runtime.
    hydra: Option<Hydra>,
}

impl RuntimeBuilder {
    pub fn new() -> Self {
        Self {
            config: RuntimeConfig::default(),
            subscriptions: Vec::new(),
            storage: None,
            hydra: None,
        }
    }

    /// Construct a `RuntimeBuilder` pre-seeded with a specific `Hydra`.
    ///
    /// `build()` will use this engine instead of creating a fresh one
    /// from the cascade config. Subscriptions registered through
    /// [`subscription`] are still applied on top of the supplied Hydra,
    /// so this composes cleanly with `.subscription(...)` chains.
    pub fn from_hydra(hydra: Hydra) -> Self {
        Self {
            config: RuntimeConfig::default(),
            subscriptions: Vec::new(),
            storage: None,
            hydra: Some(hydra),
        }
    }

    pub fn tenant(mut self, tenant_id: TenantId) -> Self {
        self.config.tenant_id = tenant_id;
        self
    }

    pub fn cascade_config(mut self, config: CascadeConfig) -> Self {
        self.config.cascade = config;
        self
    }

    pub fn bus_config(mut self, config: BusConfig) -> Self {
        self.config.bus = config;
        self
    }

    pub fn persist(mut self, persist: bool) -> Self {
        self.config.persist = persist;
        self
    }

    pub fn subscription(mut self, sub: Subscription) -> Self {
        self.subscriptions.push(sub);
        self
    }

    pub fn storage(mut self, backend: Box<dyn StorageBackend>) -> Self {
        self.storage = Some(backend);
        self
    }

    /// Build the runtime components without starting the processing loop.
    /// Returns a RuntimeHandle for interaction and a RuntimeProcessor for running.
    pub fn build(self) -> (RuntimeHandle, RuntimeProcessor) {
        // Use a pre-seeded Hydra when present (persistent bootstrap path),
        // otherwise construct one from the cascade config as before.
        let mut hydra = match self.hydra {
            Some(hydra) => hydra,
            None => Hydra::with_config(self.config.cascade.clone()),
        };
        for sub in self.subscriptions {
            hydra.register(sub);
        }

        let hydra = Arc::new(RwLock::new(hydra));
        let (in_tx, in_rx, outbound) = create_bus(&self.config.bus);

        let query_service = QueryService::new(Arc::clone(&hydra));
        let schema_service = SchemaService::new(Arc::clone(&hydra));
        let schema_admin_service = SchemaAdminService::new(
            Arc::clone(&hydra),
            hydra_core::ActorId::from_str("actor_hydra_schema_admin"),
        );
        let outbound = Arc::new(outbound);

        let handle = RuntimeHandle {
            hydra: Arc::clone(&hydra),
            inbound_sender: in_tx,
            query: query_service,
            schema: schema_service,
            schema_admin: schema_admin_service,
            outbound: Arc::clone(&outbound),
        };

        let processor = RuntimeProcessor {
            hydra,
            receiver: in_rx,
            outbound,
            storage: self.storage,
            config: self.config,
            metrics: BusMetrics::default(),
        };

        (handle, processor)
    }
}

impl Default for RuntimeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// The external API for interacting with a running Hydra runtime.
/// Cheaply cloneable — share across tasks.
pub struct RuntimeHandle {
    hydra: Arc<RwLock<Hydra>>,
    inbound_sender: mpsc::Sender<SensorBatch>,
    query: QueryService,
    schema: SchemaService,
    schema_admin: SchemaAdminService,
    outbound: Arc<BusOutbound>,
}

impl RuntimeHandle {
    /// Direct access to the shared `Arc<RwLock<Hydra>>`.
    ///
    /// Useful for callers that need to compose their own routes or services
    /// against the same engine instance. Most callers should prefer the
    /// typed service accessors (`query()`, `schema()`, `schema_admin()`)
    /// which acquire the lock automatically and return cloned data.
    pub fn hydra(&self) -> Arc<RwLock<Hydra>> {
        self.hydra.clone()
    }

    /// Get the query service for reading the graph
    pub fn query(&self) -> &QueryService {
        &self.query
    }

    /// Get the schema service for introspecting schemas and preflighting
    /// payloads before attempting writes.
    pub fn schema(&self) -> &SchemaService {
        &self.schema
    }

    /// Get the schema administration service for registering, disabling,
    /// and archiving schemas through the normal event-sourced path.
    pub fn schema_admin(&self) -> &SchemaAdminService {
        &self.schema_admin
    }

    /// Create a sensor emitter for a named sensor
    pub fn sensor_emitter(&self, sensor_name: impl Into<String>) -> SensorEmitter {
        SensorEmitter::new(self.inbound_sender.clone(), sensor_name.into())
    }

    /// Subscribe to cascade notifications
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<CascadeNotification> {
        self.outbound.subscribe()
    }
}

impl Clone for RuntimeHandle {
    fn clone(&self) -> Self {
        Self {
            hydra: Arc::clone(&self.hydra),
            inbound_sender: self.inbound_sender.clone(),
            query: self.query.clone(),
            schema: self.schema.clone(),
            schema_admin: self.schema_admin.clone(),
            outbound: Arc::clone(&self.outbound),
        }
    }
}

/// The processing loop. Call `run()` to start processing sensor batches.
/// Typically spawned as a tokio task.
pub struct RuntimeProcessor {
    hydra: Arc<RwLock<Hydra>>,
    receiver: mpsc::Receiver<SensorBatch>,
    outbound: Arc<BusOutbound>,
    storage: Option<Box<dyn StorageBackend>>,
    config: RuntimeConfig,
    metrics: BusMetrics,
}

impl RuntimeProcessor {
    /// Run the processing loop. Processes sensor batches until the inbound
    /// channel is closed (all senders dropped).
    ///
    /// This is the hot loop:
    /// 1. Receive a SensorBatch from the bus
    /// 2. Acquire write lock on Hydra
    /// 3. Ingest each event through the cascade engine
    /// 4. Persist events to storage backend (if enabled)
    /// 5. Publish CascadeNotification to subscribers
    /// 6. Release write lock
    /// 7. Update metrics
    pub async fn run(mut self) -> BusMetrics {
        while let Some(batch) = self.receiver.recv().await {
            self.process_batch(batch).await;
        }
        self.metrics
    }

    /// Process a single sensor batch
    async fn process_batch(&mut self, batch: SensorBatch) {
        let sensor_name = batch.sensor_name.clone();
        let event_count = batch.events.len();

        self.metrics.batches_received += 1;
        self.metrics.events_ingested += event_count as u64;

        // Process each event individually, acquiring/releasing the write lock
        // per event. This prevents a large batch from blocking reads for the
        // entire duration.
        for event_kind in batch.events {
            let mut hydra = self.hydra.write().await;

            match hydra.ingest(event_kind) {
                Ok(result) => {
                    self.metrics.cascades_processed += 1;
                    self.metrics.events_produced += result.events.len() as u64;

                    if result.truncated {
                        self.metrics.cascades_truncated += 1;
                    }

                    // Persist to storage
                    if self.config.persist {
                        if let Some(ref mut storage) = self.storage {
                            if storage
                                .append_events(&self.config.tenant_id, &result.events)
                                .is_err()
                            {
                                self.metrics.storage_errors += 1;
                                // Storage errors don't stop processing.
                                // The in-memory projection is the primary state.
                            }
                        }
                    }

                    // Release write lock before publishing notification
                    drop(hydra);

                    // Publish notification
                    if let Some(notification) =
                        CascadeNotification::from_result(&result, &sensor_name)
                    {
                        let _ = self.outbound.sender.send(notification);
                    }
                }
                Err(_err) => {
                    self.metrics.cascade_errors += 1;
                    // Drop lock before continuing
                    drop(hydra);
                }
            }
        }
    }

    /// Get a snapshot of current metrics
    pub fn metrics(&self) -> &BusMetrics {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::event::{EventKind, Value};
    use hydra_core::id::NodeId;
    use hydra_core::subscription::{EventFilter, Subscription, SubscriptionHandler};
    use hydra_storage::memory::MemoryBackend;
    use std::collections::HashMap;

    fn make_event(type_id: &str) -> EventKind {
        EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: type_id.to_string(),
            properties: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn runtime_builder_from_hydra_uses_supplied_engine() {
        // Pre-seed a Hydra with an event, then hand it to RuntimeBuilder.
        // The resulting RuntimeHandle should expose the same engine — proves
        // build() reused the supplied Hydra instead of constructing a fresh one.
        let mut hydra = Hydra::new();
        hydra
            .ingest(EventKind::Signal {
                source: NodeId::from_str("runtime.from_hydra"),
                name: "preloaded".to_string(),
                payload: HashMap::new(),
            })
            .unwrap();

        let (runtime, _processor) = RuntimeBuilder::from_hydra(hydra).build();
        let hydra_arc = runtime.hydra();
        let hydra = hydra_arc.read().await;
        assert_eq!(hydra.events().len(), 1);
        assert_eq!(hydra.events()[0].kind.kind_name(), "signal");
    }

    #[tokio::test]
    async fn runtime_processes_batch() {
        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .build();

        // Spawn the processor
        let proc_handle = tokio::spawn(processor.run());

        // Send a batch
        let emitter = handle.sensor_emitter("test_sensor");
        emitter.emit(vec![make_event("ec2"), make_event("rds")]).await.unwrap();

        // Give the processor time to work
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Query the graph
        assert_eq!(handle.query().node_count().await, 2);

        // Drop the emitter (and handle's sender) to close the channel
        drop(emitter);
        drop(handle);

        let metrics = proc_handle.await.unwrap();
        assert_eq!(metrics.batches_received, 1);
        assert_eq!(metrics.events_ingested, 2);
        assert_eq!(metrics.cascades_processed, 2);
    }

    #[tokio::test]
    async fn runtime_with_subscriptions() {
        struct Tagger;
        impl SubscriptionHandler for Tagger {
            fn handle(
                &self,
                event: &hydra_core::event::Event,
                _graph: &dyn hydra_core::graph::GraphReader,
            ) -> Vec<EventKind> {
                if let EventKind::NodeCreated { node_id, .. } = &event.kind {
                    vec![EventKind::NodeUpdated {
                        node_id: node_id.clone(),
                        changes: HashMap::from([("tagged".to_string(), Value::Bool(true))]),
                    }]
                } else {
                    vec![]
                }
            }
        }

        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .subscription(Subscription::new(
                "tagger",
                EventFilter::NodeCreated,
                100,
                Box::new(Tagger),
            ))
            .build();

        let proc_handle = tokio::spawn(processor.run());

        let node_id = NodeId::new();
        let emitter = handle.sensor_emitter("test");
        emitter
            .emit_one(EventKind::NodeCreated {
                node_id: node_id.clone(),
                type_id: "ec2".to_string(),
                properties: HashMap::new(),
            })
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let node = handle.query().node(&node_id).await.unwrap();
        assert_eq!(node.get_bool("tagged"), Some(true));

        drop(emitter);
        drop(handle);
        let metrics = proc_handle.await.unwrap();
        // 1 trigger + 1 reaction = 2 events produced
        assert_eq!(metrics.events_produced, 2);
    }

    #[tokio::test]
    async fn runtime_with_storage() {
        let tenant = TenantId::from_str("ten_RUNTIME_TEST");
        let storage = Box::new(MemoryBackend::new());

        let (handle, processor) = RuntimeBuilder::new()
            .tenant(tenant.clone())
            .storage(storage)
            .build();

        let proc_handle = tokio::spawn(processor.run());

        let emitter = handle.sensor_emitter("test");
        emitter.emit_one(make_event("ec2")).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // The event was ingested
        assert_eq!(handle.query().node_count().await, 1);

        drop(emitter);
        drop(handle);
        let _metrics = proc_handle.await.unwrap();
        // Storage was written to (we can't check the MemoryBackend here because
        // it was moved into the processor — in real code you'd use Arc<Mutex<>>)
    }

    #[tokio::test]
    async fn runtime_notifications() {
        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .build();

        let mut subscriber = handle.subscribe();
        let proc_handle = tokio::spawn(processor.run());

        let emitter = handle.sensor_emitter("sensor_a");
        emitter.emit_one(make_event("ec2")).await.unwrap();

        // Receive the notification
        let notification = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            subscriber.recv(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(notification.sensor_name, "sensor_a");
        assert_eq!(notification.event_count, 1);
        assert_eq!(notification.mutation_count, 1);

        drop(emitter);
        drop(handle);
        proc_handle.await.unwrap();
    }

    #[tokio::test]
    async fn runtime_handles_cascade_errors_gracefully() {
        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .build();

        let proc_handle = tokio::spawn(processor.run());

        // Send an event that targets a non-existent node (will error)
        let emitter = handle.sensor_emitter("bad_sensor");
        emitter
            .emit_one(EventKind::NodeUpdated {
                node_id: NodeId::from_str("node_GHOST"),
                changes: HashMap::from([("x".to_string(), Value::Int(1))]),
            })
            .await
            .unwrap();

        // Also send a valid event after the error
        emitter.emit_one(make_event("ec2")).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // The valid event should still have been processed
        assert_eq!(handle.query().node_count().await, 1);

        drop(emitter);
        drop(handle);
        let metrics = proc_handle.await.unwrap();
        assert_eq!(metrics.cascade_errors, 1);
        assert_eq!(metrics.cascades_processed, 1); // Only the successful one
    }

    #[tokio::test]
    async fn runtime_multiple_sensors() {
        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .build();

        let proc_handle = tokio::spawn(processor.run());

        let sensor_a = handle.sensor_emitter("cloudtrail");
        let sensor_b = handle.sensor_emitter("config");

        sensor_a.emit_one(make_event("ec2")).await.unwrap();
        sensor_b.emit_one(make_event("rds")).await.unwrap();
        sensor_a.emit_one(make_event("s3")).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(handle.query().node_count().await, 3);

        drop(sensor_a);
        drop(sensor_b);
        drop(handle);
        let metrics = proc_handle.await.unwrap();
        assert_eq!(metrics.batches_received, 3);
        assert_eq!(metrics.cascades_processed, 3);
    }

    #[tokio::test]
    async fn runtime_handle_is_cloneable() {
        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .build();

        let proc_handle = tokio::spawn(processor.run());

        let handle2 = handle.clone();

        let emitter = handle.sensor_emitter("a");
        emitter.emit_one(make_event("ec2")).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Both handles see the same graph
        assert_eq!(handle.query().node_count().await, 1);
        assert_eq!(handle2.query().node_count().await, 1);

        drop(emitter);
        drop(handle);
        drop(handle2);
        proc_handle.await.unwrap();
    }

    #[tokio::test]
    async fn builder_defaults() {
        let (handle, processor) = RuntimeBuilder::new().persist(false).build();
        let proc_handle = tokio::spawn(processor.run());

        assert_eq!(handle.query().node_count().await, 0);
        assert_eq!(handle.query().total_events().await, 0);

        drop(handle);
        proc_handle.await.unwrap();
    }
}
