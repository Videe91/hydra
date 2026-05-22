//! # CloudTrail Transport
//!
//! Bridges the CloudTrail sensor (parser) with the Hydra runtime (async event bus).
//!
//! Two modes:
//! 1. **Push mode**: HTTP endpoint receives CloudTrail JSON → parses → injects into Hydra
//! 2. **Pull mode**: Polls an SQS queue or reads from S3 (future, needs AWS SDK)
//!
//! Currently implements push mode (sufficient for EventBridge → HTTP webhook delivery
//! and for manual/testing ingestion).

use hydra_sensor::cloudtrail::{CloudTrailSensor, CloudTrailConfig};
use hydra_core::event::EventKind;
use std::sync::Mutex;

/// Thread-safe wrapper around CloudTrailSensor for use in HTTP handlers.
/// The sensor maintains dedup state across requests.
pub struct CloudTrailTransport {
    sensor: Mutex<CloudTrailSensor>,
}

impl CloudTrailTransport {
    pub fn new() -> Self {
        Self {
            sensor: Mutex::new(CloudTrailSensor::new()),
        }
    }

    pub fn with_config(config: CloudTrailConfig) -> Self {
        Self {
            sensor: Mutex::new(CloudTrailSensor::with_config(config)),
        }
    }

    /// Parse a CloudTrail JSON batch and return Hydra signals.
    /// Thread-safe: acquires mutex on the sensor for dedup state.
    pub fn parse_batch(&self, json: &str) -> Result<TransportResult, String> {
        let mut sensor = self.sensor.lock()
            .map_err(|e| format!("Sensor lock poisoned: {}", e))?;

        let result = sensor.process_batch(json)?;

        Ok(TransportResult {
            signals: result.signals,
            skipped: result.skipped,
            parse_errors: result.parse_errors,
            unrecognized: result.unrecognized,
            total_processed: sensor.total_processed,
            total_signals: sensor.total_signals,
        })
    }

    /// Get sensor stats without parsing anything.
    pub fn stats(&self) -> (u64, u64) {
        let sensor = self.sensor.lock().unwrap();
        (sensor.total_processed, sensor.total_signals)
    }
}

/// Result of parsing a CloudTrail batch through the transport.
pub struct TransportResult {
    pub signals: Vec<EventKind>,
    pub skipped: usize,
    pub parse_errors: Vec<String>,
    pub unrecognized: Vec<(String, String)>,
    pub total_processed: u64,
    pub total_signals: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_is_thread_safe() {
        let transport = CloudTrailTransport::new();
        let json = r#"{"Records": [{
            "eventSource": "s3.amazonaws.com",
            "eventName": "CreateBucket",
            "awsRegion": "us-east-1",
            "eventID": "evt-transport-1",
            "requestParameters": {"bucketName": "test-bucket"},
            "responseElements": {}
        }]}"#;

        let result = transport.parse_batch(json).unwrap();
        assert_eq!(result.signals.len(), 1);
        assert_eq!(result.total_processed, 1);
    }

    #[test]
    fn transport_dedup_across_calls() {
        let transport = CloudTrailTransport::new();
        let json = r#"{"Records": [{
            "eventSource": "s3.amazonaws.com",
            "eventName": "CreateBucket",
            "awsRegion": "us-east-1",
            "eventID": "evt-dedup-1",
            "requestParameters": {"bucketName": "test-bucket"},
            "responseElements": {}
        }]}"#;

        let r1 = transport.parse_batch(json).unwrap();
        assert_eq!(r1.signals.len(), 1);

        let r2 = transport.parse_batch(json).unwrap();
        assert_eq!(r2.signals.len(), 0, "Should dedup across calls");
    }
}
