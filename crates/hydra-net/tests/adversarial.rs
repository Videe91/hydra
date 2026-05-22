//! Adversarial tests for hydra-net
//!
//! These tests cover the attack surface identified in the three-skill audit:
//! - Write lock contention (concurrent reads during heavy ingestion)
//! - Large batch processing
//! - PollSensor graceful cancellation
//! - BusConfig validation
//! - Storage error metric tracking
//! - Processor shutdown and final metrics
//! - Notification subscriber lagging behind
//! - Concurrent sensor interleaving
//! - Rapid handle clone/drop
//! - Query on deleted nodes after graph mutations

#[cfg(test)]
mod adversarial {
    use hydra_core::event::{EventKind, Value};
    use hydra_core::id::{EdgeId, NodeId};
    use hydra_core::subscription::{EventFilter, Subscription, SubscriptionHandler};
    use hydra_net::bus::BusConfig;
    use hydra_net::runtime::RuntimeBuilder;
    use hydra_net::sensor::PollSensor;
    use std::collections::HashMap;

    fn make_event(type_id: &str) -> EventKind {
        EventKind::NodeCreated {
            node_id: NodeId::new(),
            type_id: type_id.to_string(),
            properties: HashMap::new(),
        }
    }

    // ===================================================================
    // T1: Concurrent reads during heavy write load
    // Verifies readers aren't starved by the writer. With the per-event
    // lock release, readers should get a chance between events.
    // ===================================================================
    #[tokio::test]
    async fn concurrent_reads_during_ingestion() {
        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .build();

        let proc_handle = tokio::spawn(processor.run());

        // Start 5 reader tasks that continuously poll
        let mut readers = Vec::new();
        for _ in 0..5 {
            let q = handle.query().clone();
            readers.push(tokio::spawn(async move {
                let mut reads = 0u64;
                let deadline =
                    tokio::time::Instant::now() + std::time::Duration::from_millis(300);
                while tokio::time::Instant::now() < deadline {
                    let _ = q.node_count().await;
                    reads += 1;
                    // Yield to let the writer work too
                    tokio::task::yield_now().await;
                }
                reads
            }));
        }

        // Meanwhile, ingest 200 events
        let emitter = handle.sensor_emitter("load_sensor");
        for _ in 0..200 {
            emitter.emit_one(make_event("ec2")).await.unwrap();
        }

        // Wait for readers
        let mut total_reads = 0u64;
        for r in readers {
            total_reads += r.await.unwrap();
        }

        // Readers should have completed many reads despite writer pressure
        assert!(
            total_reads > 50,
            "Readers starved — only {} reads during 200-event ingestion",
            total_reads
        );

        // All events should be ingested
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(handle.query().node_count().await, 200);

        drop(emitter);
        drop(handle);
        proc_handle.await.unwrap();
    }

    // ===================================================================
    // T2: Large batch — 500 events in a single batch
    // ===================================================================
    #[tokio::test]
    async fn large_batch_processing() {
        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .build();

        let proc_handle = tokio::spawn(processor.run());

        let emitter = handle.sensor_emitter("bulk");
        let events: Vec<EventKind> = (0..500).map(|i| make_event(&format!("type_{}", i))).collect();
        emitter.emit(events).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        assert_eq!(handle.query().node_count().await, 500);

        drop(emitter);
        drop(handle);
        let metrics = proc_handle.await.unwrap();
        assert_eq!(metrics.batches_received, 1);
        assert_eq!(metrics.events_ingested, 500);
        assert_eq!(metrics.cascades_processed, 500);
    }

    // ===================================================================
    // T3: PollSensor graceful cancellation via handle.stop()
    // ===================================================================
    #[tokio::test]
    async fn poll_sensor_graceful_cancel() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        let (mut sensor, cancel_handle) = PollSensor::new(
            "cancel_test",
            std::time::Duration::from_millis(5),
            move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
                vec![make_event("tick")]
            },
        );

        let (handle, processor) = RuntimeBuilder::new().persist(false).build();
        let proc_handle = tokio::spawn(processor.run());
        let emitter = handle.sensor_emitter("cancel_test");

        let sensor_handle = tokio::spawn(async move { sensor.run(emitter).await });

        // Let it tick a few times
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let ticks_before = counter.load(Ordering::Relaxed);
        assert!(ticks_before > 0, "Sensor should have ticked");

        // Cancel gracefully
        cancel_handle.stop();

        // Should return Ok (not panic or hang)
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            sensor_handle,
        )
        .await
        .expect("PollSensor should stop within 200ms")
        .expect("Task should not panic");

        assert!(result.is_ok(), "PollSensor::run should return Ok on cancel");

        drop(handle);
        proc_handle.await.unwrap();
    }

    // ===================================================================
    // T4: PollSensor handle drop also cancels
    // ===================================================================
    #[tokio::test]
    async fn poll_sensor_cancel_on_handle_drop() {
        let (mut sensor, cancel_handle) = PollSensor::new(
            "drop_cancel",
            std::time::Duration::from_millis(5),
            || vec![make_event("tick")],
        );

        let (handle, processor) = RuntimeBuilder::new().persist(false).build();
        let proc_handle = tokio::spawn(processor.run());
        let emitter = handle.sensor_emitter("drop_cancel");

        let sensor_handle = tokio::spawn(async move { sensor.run(emitter).await });

        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        // Drop the cancel handle — the watch channel sender is dropped,
        // which causes changed() to return an error, stopping the sensor
        drop(cancel_handle);

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            sensor_handle,
        )
        .await
        .expect("PollSensor should stop when cancel handle is dropped")
        .expect("Task should not panic");

        assert!(result.is_ok());

        drop(handle);
        proc_handle.await.unwrap();
    }

    // ===================================================================
    // T5: BusConfig zero buffer panics
    // ===================================================================
    #[test]
    #[should_panic(expected = "inbound_buffer must be > 0")]
    fn bus_config_zero_inbound_panics() {
        let config = BusConfig {
            inbound_buffer: 0,
            outbound_buffer: 16,
        };
        hydra_net::bus::create_bus(&config);
    }

    #[test]
    #[should_panic(expected = "outbound_buffer must be > 0")]
    fn bus_config_zero_outbound_panics() {
        let config = BusConfig {
            inbound_buffer: 16,
            outbound_buffer: 0,
        };
        hydra_net::bus::create_bus(&config);
    }

    // ===================================================================
    // T6: Processor shutdown returns correct final metrics
    // ===================================================================
    #[tokio::test]
    async fn processor_shutdown_returns_final_metrics() {
        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .build();

        let proc_handle = tokio::spawn(processor.run());

        let emitter = handle.sensor_emitter("metrics_test");
        emitter.emit_one(make_event("a")).await.unwrap();
        emitter.emit_one(make_event("b")).await.unwrap();
        emitter
            .emit_one(EventKind::NodeUpdated {
                node_id: NodeId::from_str("node_GHOST"),
                changes: HashMap::from([("x".to_string(), Value::Int(1))]),
            })
            .await
            .unwrap();
        emitter.emit_one(make_event("c")).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Drop everything to trigger shutdown
        drop(emitter);
        drop(handle);

        let metrics = proc_handle.await.unwrap();
        assert_eq!(metrics.batches_received, 4);
        assert_eq!(metrics.events_ingested, 4);
        assert_eq!(metrics.cascades_processed, 3); // 3 successes
        assert_eq!(metrics.cascade_errors, 1); // 1 ghost node error
        assert_eq!(metrics.storage_errors, 0); // no storage configured
    }

    // ===================================================================
    // T7: Broadcast notification subscriber lagging
    // When a subscriber is slow, it should get a Lagged error, not block
    // the producer.
    // ===================================================================
    #[tokio::test]
    async fn notification_subscriber_lagging() {
        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .bus_config(BusConfig {
                inbound_buffer: 512,
                outbound_buffer: 4, // Tiny outbound buffer
            })
            .build();

        let mut subscriber = handle.subscribe();
        let proc_handle = tokio::spawn(processor.run());

        // Send many events to overflow the small broadcast buffer
        let emitter = handle.sensor_emitter("flood");
        for _ in 0..20 {
            emitter.emit_one(make_event("ec2")).await.unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Subscriber should see a Lagged error (missed messages)
        let mut lagged = false;
        let mut received = 0;
        loop {
            match subscriber.try_recv() {
                Ok(_) => received += 1,
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                    lagged = true;
                    // Skip the lagged messages and continue
                    let _ = n;
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
            }
        }

        // With buffer=4 and 20 notifications, subscriber MUST have lagged
        assert!(lagged, "Expected subscriber to lag with buffer=4 and 20 events, got {} clean receives", received);

        // But the producer should have processed everything just fine
        assert_eq!(handle.query().node_count().await, 20);

        drop(emitter);
        drop(handle);
        proc_handle.await.unwrap();
    }

    // ===================================================================
    // T8: Concurrent sensors interleaving — order doesn't matter, all arrive
    // ===================================================================
    #[tokio::test]
    async fn concurrent_sensors_all_events_arrive() {
        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .build();

        let proc_handle = tokio::spawn(processor.run());

        // Spawn 5 sensors, each emitting 20 events concurrently
        let mut sensor_handles = Vec::new();
        for i in 0..5 {
            let emitter = handle.sensor_emitter(format!("sensor_{}", i));
            sensor_handles.push(tokio::spawn(async move {
                for j in 0..20 {
                    emitter
                        .emit_one(make_event(&format!("s{}_e{}", i, j)))
                        .await
                        .unwrap();
                }
            }));
        }

        for h in sensor_handles {
            h.await.unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // All 100 events should arrive regardless of interleaving order
        assert_eq!(handle.query().node_count().await, 100);

        drop(handle);
        let metrics = proc_handle.await.unwrap();
        assert_eq!(metrics.events_ingested, 100);
        assert_eq!(metrics.cascades_processed, 100);
        assert_eq!(metrics.cascade_errors, 0);
    }

    // ===================================================================
    // T9: Rapid handle clone/drop doesn't leak or crash
    // ===================================================================
    #[tokio::test]
    async fn rapid_handle_clone_drop() {
        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .build();

        let proc_handle = tokio::spawn(processor.run());

        // Clone the handle 100 times, use each one, then drop
        for _ in 0..100 {
            let h = handle.clone();
            let _ = h.query().node_count().await;
            drop(h);
        }

        // Original handle should still work
        let emitter = handle.sensor_emitter("after_clones");
        emitter.emit_one(make_event("ec2")).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(handle.query().node_count().await, 1);

        drop(emitter);
        drop(handle);
        proc_handle.await.unwrap();
    }

    // ===================================================================
    // T10: Query on deleted node returns None, not stale data
    // ===================================================================
    #[tokio::test]
    async fn query_after_node_deletion() {
        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .build();

        let proc_handle = tokio::spawn(processor.run());

        let node_id = NodeId::new();
        let emitter = handle.sensor_emitter("lifecycle");

        // Create a node
        emitter
            .emit_one(EventKind::NodeCreated {
                node_id: node_id.clone(),
                type_id: "ec2".to_string(),
                properties: HashMap::from([("state".to_string(), Value::String("running".to_string()))]),
            })
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(handle.query().has_node(&node_id).await);
        assert_eq!(handle.query().node_count().await, 1);

        // Delete the node
        emitter
            .emit_one(EventKind::NodeDeleted {
                node_id: node_id.clone(),
            })
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Node should no longer be "alive"
        assert!(!handle.query().has_node(&node_id).await);
        assert_eq!(handle.query().node_count().await, 0);
        assert_eq!(handle.query().nodes_by_type("ec2").await.len(), 0);

        drop(emitter);
        drop(handle);
        proc_handle.await.unwrap();
    }

    // ===================================================================
    // T11: Subscription cascade through runtime produces correct chain
    // ===================================================================
    #[tokio::test]
    async fn cascading_subscriptions_through_runtime() {
        // Handler that creates an edge to a "monitor" node when any node is created
        struct MonitorLinker {
            monitor_id: NodeId,
        }
        impl SubscriptionHandler for MonitorLinker {
            fn handle(
                &self,
                event: &hydra_core::event::Event,
                _graph: &dyn hydra_core::graph::GraphReader,
            ) -> Vec<EventKind> {
                if let EventKind::NodeCreated { node_id, .. } = &event.kind {
                    if *node_id != self.monitor_id {
                        vec![EventKind::EdgeCreated {
                            edge_id: EdgeId::new(),
                            source: node_id.clone(),
                            target: self.monitor_id.clone(),
                            type_id: "monitored_by".to_string(),
                            properties: HashMap::new(),
                        }]
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            }
        }

        let monitor_id = NodeId::new();

        let (handle, processor) = RuntimeBuilder::new()
            .persist(false)
            .subscription(Subscription::new(
                "monitor_linker",
                EventFilter::NodeCreated,
                100,
                Box::new(MonitorLinker {
                    monitor_id: monitor_id.clone(),
                }),
            ))
            .build();

        let proc_handle = tokio::spawn(processor.run());
        let emitter = handle.sensor_emitter("setup");

        // Create the monitor node first
        emitter
            .emit_one(EventKind::NodeCreated {
                node_id: monitor_id.clone(),
                type_id: "monitor".to_string(),
                properties: HashMap::new(),
            })
            .await
            .unwrap();

        // Create 3 target nodes
        for i in 0..3 {
            emitter
                .emit_one(EventKind::NodeCreated {
                    node_id: NodeId::new(),
                    type_id: format!("target_{}", i),
                    properties: HashMap::new(),
                })
                .await
                .unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 4 nodes total (1 monitor + 3 targets)
        assert_eq!(handle.query().node_count().await, 4);
        // 3 edges (each target → monitor)
        assert_eq!(handle.query().edge_count().await, 3);
        // Monitor should have 3 incoming edges
        let incoming = handle.query().incoming_edges(&monitor_id).await;
        assert_eq!(incoming.len(), 3);

        drop(emitter);
        drop(handle);
        proc_handle.await.unwrap();
    }
}
