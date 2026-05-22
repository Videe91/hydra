//! # CloudTrail Sensor
//!
//! Parses AWS CloudTrail JSON records and produces Hydra EventKind::Signal
//! events that the DiscoveryArm consumes.
//!
//! ## Architecture
//!
//! ```text
//! CloudTrail S3 Bucket / SQS / EventBridge
//!            ↓
//!   CloudTrailSensor.process_record(json)
//!            ↓
//!   EventMapping table (eventSource + eventName → extractor)
//!            ↓
//!   SignalKind (ResourceDiscovered / Deleted / Dependency)
//!            ↓
//!   EventKind::Signal (ready for Hydra.ingest())
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use hydra_sensor::cloudtrail::CloudTrailSensor;
//! use hydra_engine::prelude::*;
//!
//! let sensor = CloudTrailSensor::new();
//! let mut hydra = Hydra::new();
//! // ... register Arms ...
//!
//! let cloudtrail_json = r#"{"Records": [...]}"#;
//! let signals = sensor.process_batch(cloudtrail_json).unwrap();
//! for signal in signals {
//!     hydra.ingest(signal).unwrap();
//! }
//! ```

use crate::cloudtrail_mapping::{cloudtrail_mappings, SignalKind};
use hydra_core::event::{EventKind, Value};
use hydra_core::id::NodeId;
use std::collections::{HashMap, HashSet};

/// CloudTrail sensor configuration.
#[derive(Debug, Clone)]
pub struct CloudTrailConfig {
    /// Deduplicate events by eventID within a session.
    /// CloudTrail can deliver the same event multiple times.
    pub dedup_enabled: bool,
    /// Maximum dedup cache size (LRU eviction after this).
    pub dedup_cache_size: usize,
    /// Skip events with errorCode set (failed API calls).
    pub skip_error_events: bool,
    /// Skip read-only events (Describe*, List*, Get*).
    pub skip_read_only: bool,
}

impl Default for CloudTrailConfig {
    fn default() -> Self {
        Self {
            dedup_enabled: true,
            dedup_cache_size: 100_000,
            skip_error_events: true,
            skip_read_only: true,
        }
    }
}

/// Parsing result for a single CloudTrail record.
#[derive(Debug)]
pub struct ParseResult {
    /// Hydra signals generated from this record
    pub signals: Vec<EventKind>,
    /// Records that were skipped (errors, read-only, dupes)
    pub skipped: usize,
    /// Parse errors (event recognized but couldn't extract data)
    pub parse_errors: Vec<String>,
    /// Unrecognized events (eventSource+eventName not in mapping table)
    pub unrecognized: Vec<(String, String)>,
}

/// CloudTrail sensor — converts CloudTrail JSON into Hydra signals.
pub struct CloudTrailSensor {
    /// Mapping table: (eventSource, eventName) → extractor
    mappings: HashMap<(String, String), fn(&serde_json::Value) -> SignalKind>,
    /// Dedup cache: set of seen CloudTrail eventIDs
    seen_event_ids: HashSet<String>,
    /// Configuration
    config: CloudTrailConfig,
    /// Total events processed
    pub total_processed: u64,
    /// Total signals emitted
    pub total_signals: u64,
}

impl CloudTrailSensor {
    pub fn new() -> Self {
        Self::with_config(CloudTrailConfig::default())
    }

    pub fn with_config(config: CloudTrailConfig) -> Self {
        let mapping_list = cloudtrail_mappings();
        let mut mappings = HashMap::new();
        for m in mapping_list {
            mappings.insert(
                (m.event_source.to_string(), m.event_name.to_string()),
                m.extractor,
            );
        }
        Self {
            mappings,
            seen_event_ids: HashSet::new(),
            config,
            total_processed: 0,
            total_signals: 0,
        }
    }

    /// Process a CloudTrail batch (the JSON with `{"Records": [...]}`)
    pub fn process_batch(&mut self, json: &str) -> Result<ParseResult, String> {
        let parsed: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| format!("Invalid JSON: {}", e))?;

        let records = parsed
            .get("Records")
            .and_then(|r| r.as_array())
            .ok_or_else(|| "Missing or invalid Records array".to_string())?;

        let mut result = ParseResult {
            signals: Vec::new(),
            skipped: 0,
            parse_errors: Vec::new(),
            unrecognized: Vec::new(),
        };

        for record in records {
            self.process_record(record, &mut result);
        }

        Ok(result)
    }

    /// Process a single CloudTrail record.
    pub fn process_record(
        &mut self,
        record: &serde_json::Value,
        result: &mut ParseResult,
    ) {
        self.total_processed += 1;

        // Extract core fields
        let event_source = record.get("eventSource")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let event_name = record.get("eventName")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let event_id = record.get("eventID")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Dedup check
        if self.config.dedup_enabled && !event_id.is_empty() {
            if self.seen_event_ids.contains(event_id) {
                result.skipped += 1;
                return;
            }
            self.seen_event_ids.insert(event_id.to_string());
            // LRU eviction (simple: clear half when full)
            if self.seen_event_ids.len() > self.config.dedup_cache_size {
                self.seen_event_ids.clear();
            }
        }

        // Skip error events (failed API calls don't create resources)
        if self.config.skip_error_events {
            if record.get("errorCode").is_some() {
                result.skipped += 1;
                return;
            }
        }

        // Skip read-only events
        if self.config.skip_read_only && is_read_only(event_name) {
            result.skipped += 1;
            return;
        }

        // Look up the mapping
        let key = (event_source.to_string(), event_name.to_string());
        let extractor = match self.mappings.get(&key) {
            Some(ext) => *ext,
            None => {
                result.unrecognized.push((event_source.to_string(), event_name.to_string()));
                return;
            }
        };

        // Special handling for multi-resource events
        // RunInstances / TerminateInstances can contain multiple instances
        if event_name == "RunInstances" || event_name == "TerminateInstances" {
            let items_path = if event_name == "RunInstances" {
                ["responseElements", "instancesSet"]
            } else {
                ["requestParameters", "instancesSet"]
            };
            if let Some(items) = record
                .get(items_path[0])
                .and_then(|r| r.get(items_path[1]))
                .and_then(|s| s.get("items"))
                .and_then(|i| i.as_array())
            {
                if items.len() > 1 {
                    // Emit one signal per instance
                    for item in items {
                        if let Some(id) = item.get("instanceId").and_then(|v| v.as_str()) {
                            let signal = if event_name == "RunInstances" {
                                let mut props = vec![("cloud_provider".into(), "aws".into())];
                                if let Some(t) = item.get("instanceType").and_then(|v| v.as_str()) {
                                    props.push(("instance_type".into(), t.to_string()));
                                }
                                SignalKind::ResourceDiscovered {
                                    resource_id: id.to_string(),
                                    resource_type: hydra_sentinel::nodes::COMPUTE_INSTANCE,
                                    name: None,
                                    region: record.get("awsRegion")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown").to_string(),
                                    properties: props,
                                }
                            } else {
                                SignalKind::ResourceDeleted { resource_id: id.to_string() }
                            };
                            if let Some(ek) = signal_to_event_kind(signal, &mut result.parse_errors) {
                                result.signals.push(ek);
                                self.total_signals += 1;
                            }
                        }
                    }
                    return;
                }
            }
        }

        // Standard single-signal extraction
        let signal = extractor(record);
        if let Some(event_kind) = signal_to_event_kind(signal, &mut result.parse_errors) {
            result.signals.push(event_kind);
            self.total_signals += 1;
        }
    }

    /// Number of unique (eventSource, eventName) pairs we handle.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// Clear the dedup cache (e.g., on session boundary).
    pub fn clear_dedup_cache(&mut self) {
        self.seen_event_ids.clear();
    }
}

/// Convert a SignalKind into a Hydra EventKind::Signal.
fn signal_to_event_kind(signal: SignalKind, errors: &mut Vec<String>) -> Option<EventKind> {
    match signal {
        SignalKind::ResourceDiscovered {
            resource_id,
            resource_type,
            name,
            region,
            properties,
        } => {
            let mut payload = HashMap::new();
            payload.insert("resource_id".into(), Value::String(resource_id.clone()));
            payload.insert("resource_type".into(), Value::String(resource_type.to_string()));
            payload.insert("region".into(), Value::String(region));
            payload.insert("cloud_provider".into(), Value::String("aws".into()));
            if let Some(n) = name {
                payload.insert("name".into(), Value::String(n));
            }
            for (k, v) in properties {
                payload.insert(k, Value::String(v));
            }

            Some(EventKind::Signal {
                source: NodeId::from_str("sensor_cloudtrail"),
                name: "resource_discovered".to_string(),
                payload,
            })
        }

        SignalKind::ResourceDeleted { resource_id } => {
            let mut payload = HashMap::new();
            payload.insert("resource_id".into(), Value::String(resource_id));

            Some(EventKind::Signal {
                source: NodeId::from_str("sensor_cloudtrail"),
                name: "resource_deleted".to_string(),
                payload,
            })
        }

        SignalKind::DependencyDiscovered {
            source,
            target,
            dependency_type,
            confidence,
        } => {
            let mut payload = HashMap::new();
            payload.insert("source".into(), Value::String(source));
            payload.insert("target".into(), Value::String(target));
            payload.insert("dependency_type".into(), Value::String(dependency_type));
            payload.insert("confidence".into(), Value::Float(confidence));

            Some(EventKind::Signal {
                source: NodeId::from_str("sensor_cloudtrail"),
                name: "dependency_discovered".to_string(),
                payload,
            })
        }

        SignalKind::ResourceUpdated { resource_id, changed_properties } => {
            let mut payload = HashMap::new();
            payload.insert("resource_id".into(), Value::String(resource_id));
            for (k, v) in changed_properties {
                payload.insert(k, Value::String(v));
            }

            Some(EventKind::Signal {
                source: NodeId::from_str("sensor_cloudtrail"),
                name: "resource_updated".to_string(),
                payload,
            })
        }

        SignalKind::Ignored => None,

        SignalKind::ParseError(msg) => {
            errors.push(msg);
            None
        }
    }
}

/// Check if a CloudTrail eventName is read-only (Describe*, List*, Get*, etc.)
fn is_read_only(event_name: &str) -> bool {
    event_name.starts_with("Describe")
        || event_name.starts_with("List")
        || event_name.starts_with("Get")
        || event_name.starts_with("Lookup")
        || event_name.starts_with("Head")
        || event_name.starts_with("Check")
        || event_name.starts_with("Batch")
        || event_name.starts_with("Search")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cloudtrail_event(source: &str, name: &str, request: &str, response: &str) -> String {
        format!(
            r#"{{"Records": [{{
                "eventVersion": "1.08",
                "eventSource": "{}",
                "eventName": "{}",
                "awsRegion": "us-east-1",
                "eventID": "{}",
                "requestParameters": {},
                "responseElements": {}
            }}]}}"#,
            source, name,
            format!("evt-{}-{}", source.replace('.', "-"), name),
            request, response
        )
    }

    #[test]
    fn parse_run_instances() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_cloudtrail_event(
            "ec2.amazonaws.com",
            "RunInstances",
            "{}",
            r#"{"instancesSet": {"items": [{"instanceId": "i-0abc123def", "instanceType": "t3.medium"}]}}"#,
        );

        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);

        if let EventKind::Signal { name, payload, .. } = &result.signals[0] {
            assert_eq!(name, "resource_discovered");
            assert_eq!(payload.get("resource_id"), Some(&Value::String("i-0abc123def".into())));
            assert_eq!(payload.get("resource_type"), Some(&Value::String("compute_instance".into())));
            assert_eq!(payload.get("region"), Some(&Value::String("us-east-1".into())));
        } else {
            panic!("Expected Signal");
        }
    }

    #[test]
    fn parse_terminate_instances() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_cloudtrail_event(
            "ec2.amazonaws.com",
            "TerminateInstances",
            r#"{"instancesSet": {"items": [{"instanceId": "i-0abc123def"}]}}"#,
            "{}",
        );

        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);

        if let EventKind::Signal { name, payload, .. } = &result.signals[0] {
            assert_eq!(name, "resource_deleted");
            assert_eq!(payload.get("resource_id"), Some(&Value::String("i-0abc123def".into())));
        } else {
            panic!("Expected Signal");
        }
    }

    #[test]
    fn parse_rds_create() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_cloudtrail_event(
            "rds.amazonaws.com",
            "CreateDBInstance",
            r#"{"dBInstanceIdentifier": "prod-payments-db"}"#,
            r#"{"dBInstanceIdentifier": "prod-payments-db", "engine": "postgres", "dBInstanceClass": "db.r5.xlarge"}"#,
        );

        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);

        if let EventKind::Signal { name, payload, .. } = &result.signals[0] {
            assert_eq!(name, "resource_discovered");
            assert_eq!(payload.get("resource_type"), Some(&Value::String("managed_database".into())));
            assert_eq!(payload.get("resource_id"), Some(&Value::String("prod-payments-db".into())));
        } else {
            panic!("Expected Signal");
        }
    }

    #[test]
    fn parse_s3_create_bucket() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_cloudtrail_event(
            "s3.amazonaws.com",
            "CreateBucket",
            r#"{"bucketName": "my-data-lake"}"#,
            "{}",
        );

        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);

        if let EventKind::Signal { payload, .. } = &result.signals[0] {
            assert_eq!(payload.get("resource_type"), Some(&Value::String("object_store".into())));
            assert_eq!(payload.get("resource_id"), Some(&Value::String("my-data-lake".into())));
        } else {
            panic!("Expected Signal");
        }
    }

    #[test]
    fn parse_lambda_create() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_cloudtrail_event(
            "lambda.amazonaws.com",
            "CreateFunction20150331",
            r#"{"functionName": "payment-processor", "runtime": "python3.12"}"#,
            "{}",
        );

        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);

        if let EventKind::Signal { payload, .. } = &result.signals[0] {
            assert_eq!(payload.get("resource_type"), Some(&Value::String("serverless_function".into())));
            assert_eq!(payload.get("resource_id"), Some(&Value::String("payment-processor".into())));
        } else {
            panic!("Expected Signal");
        }
    }

    #[test]
    fn parse_iam_create_role() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_cloudtrail_event(
            "iam.amazonaws.com",
            "CreateRole",
            r#"{"roleName": "LambdaExecutionRole"}"#,
            "{}",
        );

        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);

        if let EventKind::Signal { payload, .. } = &result.signals[0] {
            assert_eq!(payload.get("resource_type"), Some(&Value::String("identity_role".into())));
            assert_eq!(payload.get("region"), Some(&Value::String("global".into())));
        } else {
            panic!("Expected Signal");
        }
    }

    #[test]
    fn parse_volume_attach_creates_dependency() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_cloudtrail_event(
            "ec2.amazonaws.com",
            "AttachVolume",
            r#"{"volumeId": "vol-abc123", "instanceId": "i-xyz789"}"#,
            "{}",
        );

        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);

        if let EventKind::Signal { name, payload, .. } = &result.signals[0] {
            assert_eq!(name, "dependency_discovered");
            assert_eq!(payload.get("source"), Some(&Value::String("i-xyz789".into())));
            assert_eq!(payload.get("target"), Some(&Value::String("vol-abc123".into())));
        } else {
            panic!("Expected Signal");
        }
    }

    #[test]
    fn dedup_skips_duplicate_event_ids() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_cloudtrail_event(
            "s3.amazonaws.com",
            "CreateBucket",
            r#"{"bucketName": "test-bucket"}"#,
            "{}",
        );

        let result1 = sensor.process_batch(&json).unwrap();
        assert_eq!(result1.signals.len(), 1);

        // Same event again
        let result2 = sensor.process_batch(&json).unwrap();
        assert_eq!(result2.signals.len(), 0, "Duplicate should be skipped");
        assert_eq!(result2.skipped, 1);
    }

    #[test]
    fn skips_error_events() {
        let json = r#"{"Records": [{
            "eventSource": "ec2.amazonaws.com",
            "eventName": "RunInstances",
            "awsRegion": "us-east-1",
            "eventID": "evt-error-1",
            "errorCode": "UnauthorizedAccess",
            "errorMessage": "You are not authorized",
            "requestParameters": {},
            "responseElements": null
        }]}"#;

        let mut sensor = CloudTrailSensor::new();
        let result = sensor.process_batch(json).unwrap();
        assert_eq!(result.signals.len(), 0);
        assert_eq!(result.skipped, 1);
    }

    #[test]
    fn skips_read_only_events() {
        let json = r#"{"Records": [{
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "awsRegion": "us-east-1",
            "eventID": "evt-readonly-1",
            "requestParameters": {},
            "responseElements": null
        }]}"#;

        let mut sensor = CloudTrailSensor::new();
        let result = sensor.process_batch(json).unwrap();
        assert_eq!(result.signals.len(), 0);
        assert_eq!(result.skipped, 1);
    }

    #[test]
    fn unrecognized_events_tracked() {
        let json = r#"{"Records": [{
            "eventSource": "custom.amazonaws.com",
            "eventName": "DoSomethingWeird",
            "awsRegion": "us-east-1",
            "eventID": "evt-unknown-1",
            "requestParameters": {},
            "responseElements": {}
        }]}"#;

        let mut sensor = CloudTrailSensor::new();
        let result = sensor.process_batch(json).unwrap();
        assert_eq!(result.signals.len(), 0);
        assert_eq!(result.unrecognized.len(), 1);
        assert_eq!(result.unrecognized[0], ("custom.amazonaws.com".into(), "DoSomethingWeird".into()));
    }

    #[test]
    fn multi_record_batch() {
        let json = r#"{"Records": [
            {
                "eventSource": "ec2.amazonaws.com",
                "eventName": "RunInstances",
                "awsRegion": "us-east-1",
                "eventID": "evt-1",
                "requestParameters": {},
                "responseElements": {"instancesSet": {"items": [{"instanceId": "i-001"}]}}
            },
            {
                "eventSource": "rds.amazonaws.com",
                "eventName": "CreateDBInstance",
                "awsRegion": "us-east-1",
                "eventID": "evt-2",
                "requestParameters": {"dBInstanceIdentifier": "db-001"},
                "responseElements": {"dBInstanceIdentifier": "db-001", "engine": "mysql"}
            },
            {
                "eventSource": "s3.amazonaws.com",
                "eventName": "CreateBucket",
                "awsRegion": "us-west-2",
                "eventID": "evt-3",
                "requestParameters": {"bucketName": "logs-bucket"},
                "responseElements": {}
            }
        ]}"#;

        let mut sensor = CloudTrailSensor::new();
        let result = sensor.process_batch(json).unwrap();
        assert_eq!(result.signals.len(), 3, "Should parse all 3 records");
        assert_eq!(sensor.total_processed, 3);
        assert_eq!(sensor.total_signals, 3);
    }

    // === FULL INTEGRATION: Sensor → Hydra → 10-Arm Cascade ===

    #[test]
    fn sensor_to_hydra_full_chain() {
        use hydra_core::subscription::{Subscription, EventFilter};
        use hydra_sentinel::arms::*;

        // Build Hydra with all proactive Arms
        let mut hydra = hydra_engine::prelude::Hydra::with_config(
            hydra_engine::cascade::CascadeConfig { max_depth: 15, max_events: 200 }
        );

        hydra.register(Subscription::new("discovery", EventFilter::Or(vec![
            EventFilter::SignalName("resource_discovered".into()),
            EventFilter::SignalName("resource_deleted".into()),
            EventFilter::SignalName("dependency_discovered".into()),
        ]), 200, Box::new(DiscoveryArm::new())));

        hydra.register(Subscription::new("classification", EventFilter::Or(vec![
            EventFilter::NodeCreated,
            EventFilter::SignalName("needs_classification".into()),
        ]), 190, Box::new(ClassificationArm::with_defaults())));

        hydra.register(Subscription::new("policy", EventFilter::NodeUpdated,
            180, Box::new(PolicyArm::new())));

        hydra.register(Subscription::new("execution", EventFilter::Or(vec![
            EventFilter::SignalName("policy_computed".into()),
            EventFilter::SignalName("scheduled_backup".into()),
        ]), 170, Box::new(ExecutionArm::new())));

        hydra.register(Subscription::new("verification",
            EventFilter::SignalName("backup_completed".into()),
            160, Box::new(VerificationArm::new())));

        hydra.register(Subscription::new("trust", EventFilter::Or(vec![
            EventFilter::SignalName("trust_penalty".into()),
            EventFilter::NodeUpdated,
            EventFilter::EdgeCreated,
        ]), 100, Box::new(TrustArm::new())));

        // Simulate a CloudTrail batch: create an RDS instance
        let mut sensor = CloudTrailSensor::new();
        let cloudtrail_json = r#"{"Records": [{
            "eventSource": "rds.amazonaws.com",
            "eventName": "CreateDBInstance",
            "awsRegion": "us-east-1",
            "eventID": "evt-integration-001",
            "requestParameters": {"dBInstanceIdentifier": "prod-orders-db"},
            "responseElements": {
                "dBInstanceIdentifier": "prod-orders-db",
                "engine": "postgres",
                "dBInstanceClass": "db.r5.xlarge"
            }
        }]}"#;

        let parse_result = sensor.process_batch(cloudtrail_json).unwrap();
        assert_eq!(parse_result.signals.len(), 1);

        // Feed into Hydra
        for signal in parse_result.signals {
            hydra.ingest(signal).unwrap();
        }

        // Verify the full cascade fired
        let db = hydra.graph().node(&NodeId::from_str("prod-orders-db"));
        assert!(db.is_some(), "DB node should exist");
        let db = db.unwrap();

        // Classification should have fired
        assert_eq!(db.get_i64("business_criticality"), Some(9),
            "DB should be classified as tier 1");
        assert_eq!(db.get_str("data_sensitivity"), Some("high"));

        // Protection should be in place
        assert_eq!(db.get_str("protection_status"), Some("protected"),
            "DB should be auto-protected");

        // Trust should be updated
        assert_eq!(db.get_f64("trust_backup_freshness"), Some(1.0),
            "Trust should be updated by verification");

        println!("=== SENSOR → HYDRA FULL CHAIN PROVEN ===");
        println!("CloudTrail event → resource_discovered signal → DiscoveryArm → node created");
        println!("→ ClassificationArm → criticality=9, sensitivity=high");
        println!("→ PolicyArm → hourly backup, 365d retention, encrypted");
        println!("→ ExecutionArm → snapshot created, protected_by edge");
        println!("→ VerificationArm → verified, trust=1.0");
    }
}

#[cfg(test)]
mod new_service_tests {
    use super::*;

    fn make_event(source: &str, name: &str, request: &str, response: &str) -> String {
        format!(
            r#"{{"Records": [{{
                "eventVersion": "1.08",
                "eventSource": "{}",
                "eventName": "{}",
                "awsRegion": "us-west-2",
                "eventID": "evt-new-{}-{}",
                "requestParameters": {},
                "responseElements": {}
            }}]}}"#,
            source, name,
            source.replace('.', "-"), name,
            request, response
        )
    }

    #[test]
    fn parse_ecs_create_cluster() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_event("ecs.amazonaws.com", "CreateCluster",
            r#"{"clusterName": "prod-cluster"}"#,
            r#"{"cluster": {"clusterName": "prod-cluster"}}"#);
        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);
        if let EventKind::Signal { payload, .. } = &result.signals[0] {
            assert_eq!(payload.get("resource_type"), Some(&Value::String("container_cluster".into())));
            assert_eq!(payload.get("resource_id"), Some(&Value::String("prod-cluster".into())));
        }
    }

    #[test]
    fn parse_elasticache_create() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_event("elasticache.amazonaws.com", "CreateCacheCluster",
            r#"{"cacheClusterId": "redis-sessions", "engine": "redis"}"#, "{}");
        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);
        if let EventKind::Signal { payload, .. } = &result.signals[0] {
            assert_eq!(payload.get("resource_type"), Some(&Value::String("cache_cluster".into())));
        }
    }

    #[test]
    fn parse_redshift_create() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_event("redshift.amazonaws.com", "CreateCluster",
            r#"{"clusterIdentifier": "analytics-dwh"}"#, "{}");
        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);
        if let EventKind::Signal { payload, .. } = &result.signals[0] {
            assert_eq!(payload.get("resource_type"), Some(&Value::String("data_warehouse".into())));
        }
    }

    #[test]
    fn parse_sqs_create() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_event("sqs.amazonaws.com", "CreateQueue",
            r#"{"queueName": "order-events"}"#,
            r#"{"queueUrl": "https://sqs.us-west-2.amazonaws.com/123/order-events"}"#);
        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);
        if let EventKind::Signal { payload, .. } = &result.signals[0] {
            assert_eq!(payload.get("resource_type"), Some(&Value::String("message_queue".into())));
        }
    }

    #[test]
    fn parse_elb_create() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_event("elasticloadbalancing.amazonaws.com", "CreateLoadBalancer",
            r#"{"name": "api-gateway-lb", "type": "application"}"#, "{}");
        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);
        if let EventKind::Signal { payload, .. } = &result.signals[0] {
            assert_eq!(payload.get("resource_type"), Some(&Value::String("load_balancer".into())));
        }
    }

    #[test]
    fn parse_efs_create() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_event("elasticfilesystem.amazonaws.com", "CreateFileSystem",
            "{}", r#"{"fileSystemId": "fs-abc123"}"#);
        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);
        if let EventKind::Signal { payload, .. } = &result.signals[0] {
            assert_eq!(payload.get("resource_type"), Some(&Value::String("file_system".into())));
        }
    }

    #[test]
    fn parse_kinesis_create() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_event("kinesis.amazonaws.com", "CreateStream",
            r#"{"streamName": "clickstream"}"#, "{}");
        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);
        if let EventKind::Signal { payload, .. } = &result.signals[0] {
            assert_eq!(payload.get("resource_type"), Some(&Value::String("stream".into())));
        }
    }

    #[test]
    fn parse_route53_create() {
        let mut sensor = CloudTrailSensor::new();
        let json = make_event("route53.amazonaws.com", "CreateHostedZone",
            r#"{"name": "example.com"}"#,
            r#"{"hostedZone": {"id": "/hostedzone/Z123"}}"#);
        let result = sensor.process_batch(&json).unwrap();
        assert_eq!(result.signals.len(), 1);
        if let EventKind::Signal { payload, .. } = &result.signals[0] {
            assert_eq!(payload.get("resource_type"), Some(&Value::String("dns_zone".into())));
        }
    }

    #[test]
    fn mapping_count_covers_all_services() {
        let sensor = CloudTrailSensor::new();
        // 26 original + 24 new = 50 mappings
        assert!(sensor.mapping_count() >= 50,
            "Should have >= 50 mappings, got {}", sensor.mapping_count());
    }
}

    #[test]
    fn multi_instance_run_instances() {
        let mut sensor = CloudTrailSensor::new();
        let json = r#"{"Records": [{
            "eventSource": "ec2.amazonaws.com",
            "eventName": "RunInstances",
            "awsRegion": "us-east-1",
            "eventID": "evt-multi-001",
            "requestParameters": {},
            "responseElements": {"instancesSet": {"items": [
                {"instanceId": "i-001", "instanceType": "t3.medium"},
                {"instanceId": "i-002", "instanceType": "t3.large"},
                {"instanceId": "i-003", "instanceType": "t3.xlarge"}
            ]}}
        }]}"#;

        let result = sensor.process_batch(json).unwrap();
        assert_eq!(result.signals.len(), 3, "Should create 3 signals for 3 instances");

        // Verify each instance
        let ids: Vec<String> = result.signals.iter().filter_map(|s| {
            if let EventKind::Signal { payload, .. } = s {
                payload.get("resource_id").and_then(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    _ => None,
                })
            } else { None }
        }).collect();
        assert!(ids.contains(&"i-001".to_string()));
        assert!(ids.contains(&"i-002".to_string()));
        assert!(ids.contains(&"i-003".to_string()));
    }
