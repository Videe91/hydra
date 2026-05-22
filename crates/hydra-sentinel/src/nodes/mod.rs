pub mod resource;
pub mod aws;
pub mod azure;
pub mod gcp;
pub mod protection;
pub mod trust;
pub mod threat;
pub mod compliance;

use hydra_core::event::{EventKind, Value};
use hydra_core::id::NodeId;
use std::collections::HashMap;


// ============================================================================
// Node Type Constants — ABSTRACT (cloud-agnostic)
// ============================================================================

// --- Infrastructure (any cloud, on-prem, or hybrid) ---
pub const COMPUTE_INSTANCE: &str = "compute_instance";
pub const MANAGED_DATABASE: &str = "managed_database";
pub const OBJECT_STORE: &str = "object_store";
pub const BLOCK_VOLUME: &str = "block_volume";
pub const VIRTUAL_NETWORK: &str = "virtual_network";
pub const NETWORK_SEGMENT: &str = "network_segment";
pub const FIREWALL_RULE: &str = "firewall_rule";
pub const IDENTITY_ROLE: &str = "identity_role";
pub const IDENTITY_USER: &str = "identity_user";
pub const SERVERLESS_FUNCTION: &str = "serverless_function";

// --- SaaS + Endpoints ---
pub const SAAS_APPLICATION: &str = "saas_application";
pub const ENDPOINT: &str = "endpoint";
pub const ON_PREM_SERVER: &str = "on_prem_server";

// --- Containers + Orchestration ---
pub const CONTAINER_CLUSTER: &str = "container_cluster";
pub const CONTAINER_SERVICE: &str = "container_service";

// --- Data + Analytics ---
pub const CACHE_CLUSTER: &str = "cache_cluster";
pub const DATA_WAREHOUSE: &str = "data_warehouse";
pub const STREAM: &str = "stream";
pub const ML_ENDPOINT: &str = "ml_endpoint";

// --- Messaging ---
pub const MESSAGE_QUEUE: &str = "message_queue";
pub const NOTIFICATION_TOPIC: &str = "notification_topic";

// --- Networking ---
pub const LOAD_BALANCER: &str = "load_balancer";
pub const CDN_DISTRIBUTION: &str = "cdn_distribution";
pub const DNS_ZONE: &str = "dns_zone";

// --- Storage ---
pub const FILE_SYSTEM: &str = "file_system";

// --- Protection ---
pub const BACKUP_SNAPSHOT: &str = "backup_snapshot";
pub const PROTECTION_POLICY: &str = "protection_policy";
pub const VERIFICATION_RESULT: &str = "verification_result";
pub const RECOVERY_PLAN: &str = "recovery_plan";

// --- Intelligence ---
pub const TRUST_SCORE: &str = "trust_score";
pub const ANOMALY_RECORD: &str = "anomaly_record";
pub const INCIDENT: &str = "incident";
pub const BLAST_RADIUS: &str = "blast_radius";

// --- Compliance ---
pub const REGULATION: &str = "regulation";
pub const COMPLIANCE_STATUS: &str = "compliance_status";

// ============================================================================
// Backward-Compatible AWS Aliases
// ============================================================================
// These map the old AWS-specific constants to abstract types.
// All coverage rules, anomaly rules, and edges now use the abstract names.
// Old code referencing EC2_INSTANCE etc. continues to work.

pub const EC2_INSTANCE: &str = COMPUTE_INSTANCE;
pub const RDS_DATABASE: &str = MANAGED_DATABASE;
pub const S3_BUCKET: &str = OBJECT_STORE;
pub const EBS_VOLUME: &str = BLOCK_VOLUME;
pub const VPC: &str = VIRTUAL_NETWORK;
pub const SUBNET: &str = NETWORK_SEGMENT;
pub const SECURITY_GROUP: &str = FIREWALL_RULE;
pub const IAM_ROLE: &str = IDENTITY_ROLE;
pub const IAM_USER: &str = IDENTITY_USER;
pub const LAMBDA_FUNCTION: &str = SERVERLESS_FUNCTION;

// ============================================================================
// Edge Type Constants — ABSTRACT (cloud-agnostic)
// ============================================================================

pub const IN_NETWORK: &str = "in_network";
pub const IN_SEGMENT: &str = "in_segment";
pub const HAS_FIREWALL_RULE: &str = "has_firewall_rule";
pub const ATTACHED_TO: &str = "attached_to";
pub const ASSUMES_ROLE: &str = "assumes_role";
pub const DEPENDS_ON: &str = "depends_on";
pub const PROTECTED_BY: &str = "protected_by";
pub const SNAPSHOT_OF: &str = "snapshot_of";
pub const VERIFIED_BY: &str = "verified_by";
pub const POLICY_APPLIES_TO: &str = "policy_applies_to";
pub const SCORED_BY: &str = "scored_by";
pub const DETECTED_ON: &str = "detected_on";
pub const INCIDENT_INVOLVES: &str = "incident_involves";
pub const REGULATED_BY: &str = "regulated_by";
pub const COMPLIANCE_OF: &str = "compliance_of";
pub const RECOVERY_TARGETS: &str = "recovery_targets";

// Backward-compatible AWS aliases
pub const IN_VPC: &str = IN_NETWORK;
pub const IN_SUBNET: &str = IN_SEGMENT;
pub const HAS_SECURITY_GROUP: &str = HAS_FIREWALL_RULE;

// ============================================================================
// Common Property Keys — standardized across all node types
// ============================================================================

/// Every resource node has these
pub mod prop {
    // Identity
    pub const RESOURCE_URI: &str = "resource_uri"; // arn, azure resource id, gcp self_link
    pub const ARN: &str = RESOURCE_URI; // backward compat alias
    pub const CLOUD_ID: &str = "cloud_id";
    pub const CLOUD_PROVIDER: &str = "cloud_provider";
    pub const REGION: &str = "region";
    pub const ACCOUNT_ID: &str = "account_id";
    pub const NAME: &str = "name";
    pub const TAGS: &str = "tags";

    // State
    pub const STATUS: &str = "status";
    pub const LAST_SEEN: &str = "last_seen";
    pub const DISCOVERED_AT: &str = "discovered_at";

    // Classification (fed by the Classification Arm)
    pub const DATA_SENSITIVITY: &str = "data_sensitivity";
    pub const BUSINESS_CRITICALITY: &str = "business_criticality";
    pub const REGULATORY_SCOPE: &str = "regulatory_scope";
    pub const ENVIRONMENT: &str = "environment";
    pub const DATA_CLASSIFICATION: &str = "data_classification";

    // Protection (fed by the Policy + Execution Arms)
    pub const PROTECTION_STATUS: &str = "protection_status";
    pub const LAST_BACKUP_AT: &str = "last_backup_at";
    pub const BACKUP_FREQUENCY_HOURS: &str = "backup_frequency_hours";
    pub const RETENTION_DAYS: &str = "retention_days";
    pub const BACKUP_SIZE_BYTES: &str = "backup_size_bytes";
    pub const REPLICATION_TARGETS: &str = "replication_targets";

    // Trust Score — 7 dimensions (each tracked independently by temporal engine)
    pub const TRUST_BACKUP_FRESHNESS: &str = "trust_backup_freshness";
    pub const TRUST_BACKUP_VERIFIED: &str = "trust_backup_verified";
    pub const TRUST_RECOVERY_TESTED: &str = "trust_recovery_tested";
    pub const TRUST_DEPENDENCY_HEALTH: &str = "trust_dependency_health";
    pub const TRUST_COMPLIANCE_STATUS: &str = "trust_compliance_status";
    pub const TRUST_ANOMALY_FREE: &str = "trust_anomaly_free";
    pub const TRUST_REPLICATION_HEALTH: &str = "trust_replication_health";
    pub const TRUST_COMPOSITE: &str = "trust_composite";

    // Anomaly tracking
    pub const ANOMALY_COUNT_24H: &str = "anomaly_count_24h";
    pub const LAST_ANOMALY_AT: &str = "last_anomaly_at";
    pub const INCIDENT_COUNT: &str = "incident_count";

    // Cost
    pub const MONTHLY_COST_CENTS: &str = "monthly_cost_cents";
    pub const STORAGE_TIER: &str = "storage_tier";
}

// ============================================================================
// Factory helper — build EventKind::NodeCreated with properties
// ============================================================================

/// Create a NodeCreated event for a sentinel node
pub fn create_node(
    node_id: NodeId,
    type_id: &str,
    properties: HashMap<String, Value>,
) -> EventKind {
    EventKind::NodeCreated {
        node_id,
        type_id: type_id.to_string(),
        properties,
    }
}

/// Create a NodeUpdated event
pub fn update_node(
    node_id: NodeId,
    changes: HashMap<String, Value>,
) -> EventKind {
    EventKind::NodeUpdated {
        node_id,
        changes,
    }
}

/// Helper: build a properties HashMap from key-value pairs
#[macro_export]
macro_rules! props {
    ($($key:expr => $val:expr),* $(,)?) => {{
        let mut map = std::collections::HashMap::new();
        $(map.insert($key.to_string(), $val);)*
        map
    }};
}
