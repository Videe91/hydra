//! # Abstract Resource Builders
//!
//! Cloud-agnostic resource types that Sentinel's engine, edges, anomaly rules,
//! coverage models, and Arms all operate on. A compute instance is a compute
//! instance whether it's an EC2, Azure VM, GCE, or a VMware guest.
//!
//! ## Cloud Provider Property
//!
//! Every resource carries `cloud_provider` (aws/azure/gcp/on_prem/saas)
//! and `source_type` (the vendor-specific name: "ec2", "azure_vm", "gce", etc.)
//! so adapters can round-trip and the UI can show the right icon.

use hydra_core::event::{EventKind, Value};
use hydra_core::id::NodeId;
use std::collections::HashMap;
use chrono::Utc;

use super::{prop, create_node};
use super::*;

// ============================================================================
// Base: trust dimensions + anomaly counters every protectable resource gets
// ============================================================================

fn trust_defaults(props: &mut HashMap<String, Value>) {
    props.insert(prop::TRUST_BACKUP_FRESHNESS.into(), Value::Float(0.0));
    props.insert(prop::TRUST_BACKUP_VERIFIED.into(), Value::Float(0.0));
    props.insert(prop::TRUST_RECOVERY_TESTED.into(), Value::Float(0.0));
    props.insert(prop::TRUST_DEPENDENCY_HEALTH.into(), Value::Float(0.0));
    props.insert(prop::TRUST_COMPLIANCE_STATUS.into(), Value::Float(0.0));
    props.insert(prop::TRUST_ANOMALY_FREE.into(), Value::Float(1.0)); // starts clean
    props.insert(prop::TRUST_REPLICATION_HEALTH.into(), Value::Float(0.0));
    props.insert(prop::TRUST_COMPOSITE.into(), Value::Float(0.0));
    props.insert(prop::ANOMALY_COUNT_24H.into(), Value::Int(0));
    props.insert(prop::INCIDENT_COUNT.into(), Value::Int(0));
}

fn identity_defaults(props: &mut HashMap<String, Value>, resource_id: &str) {
    let now = Utc::now();
    props.insert(prop::CLOUD_ID.into(), Value::String(resource_id.into()));
    props.insert(prop::DISCOVERED_AT.into(), Value::Timestamp(now));
    props.insert(prop::LAST_SEEN.into(), Value::Timestamp(now));
}

// ============================================================================
// Compute Instance — EC2, Azure VM, GCE, VMware guest, bare metal
// ============================================================================

pub struct ComputeInstanceBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl ComputeInstanceBuilder {
    pub fn new(resource_id: &str) -> Self {
        let node_id = NodeId::new();
        let mut props = HashMap::new();
        identity_defaults(&mut props, resource_id);
        trust_defaults(&mut props);
        props.insert(prop::STATUS.into(), Value::String("running".into()));
        props.insert(prop::PROTECTION_STATUS.into(), Value::String("unprotected".into()));
        props.insert("cloud_provider".into(), Value::String("unknown".into()));
        props.insert("source_type".into(), Value::String("compute_instance".into()));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn cloud_provider(mut self, p: &str) -> Self { self.props.insert("cloud_provider".into(), Value::String(p.into())); self }
    pub fn source_type(mut self, t: &str) -> Self { self.props.insert("source_type".into(), Value::String(t.into())); self }
    pub fn arn(mut self, arn: &str) -> Self { self.props.insert(prop::ARN.into(), Value::String(arn.into())); self }
    pub fn region(mut self, r: &str) -> Self { self.props.insert(prop::REGION.into(), Value::String(r.into())); self }
    pub fn account_id(mut self, id: &str) -> Self { self.props.insert(prop::ACCOUNT_ID.into(), Value::String(id.into())); self }
    pub fn name(mut self, n: &str) -> Self { self.props.insert(prop::NAME.into(), Value::String(n.into())); self }
    pub fn status(mut self, s: &str) -> Self { self.props.insert(prop::STATUS.into(), Value::String(s.into())); self }
    pub fn instance_type(mut self, t: &str) -> Self { self.props.insert("instance_type".into(), Value::String(t.into())); self }
    pub fn os(mut self, o: &str) -> Self { self.props.insert("os".into(), Value::String(o.into())); self }
    pub fn environment(mut self, e: &str) -> Self { self.props.insert(prop::ENVIRONMENT.into(), Value::String(e.into())); self }
    pub fn data_sensitivity(mut self, s: &str) -> Self { self.props.insert(prop::DATA_SENSITIVITY.into(), Value::String(s.into())); self }
    pub fn business_criticality(mut self, c: i64) -> Self { self.props.insert(prop::BUSINESS_CRITICALITY.into(), Value::Int(c)); self }
    pub fn monthly_cost_cents(mut self, c: i64) -> Self { self.props.insert(prop::MONTHLY_COST_CENTS.into(), Value::Int(c)); self }
    pub fn prop(mut self, k: &str, v: Value) -> Self { self.props.insert(k.into(), v); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, COMPUTE_INSTANCE, self.props))
    }
}

// ============================================================================
// Managed Database — RDS, Azure SQL, Cloud SQL, on-prem Postgres/MySQL
// ============================================================================

pub struct ManagedDatabaseBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl ManagedDatabaseBuilder {
    pub fn new(resource_id: &str) -> Self {
        let node_id = NodeId::new();
        let mut props = HashMap::new();
        identity_defaults(&mut props, resource_id);
        trust_defaults(&mut props);
        props.insert(prop::STATUS.into(), Value::String("available".into()));
        props.insert(prop::PROTECTION_STATUS.into(), Value::String("unprotected".into()));
        props.insert("cloud_provider".into(), Value::String("unknown".into()));
        props.insert("source_type".into(), Value::String("managed_database".into()));
        props.insert("engine".into(), Value::String("unknown".into()));
        props.insert("engine_version".into(), Value::String("unknown".into()));
        props.insert("multi_az".into(), Value::Bool(false));
        props.insert("storage_encrypted".into(), Value::Bool(false));
        props.insert("allocated_storage_gb".into(), Value::Int(0));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn cloud_provider(mut self, p: &str) -> Self { self.props.insert("cloud_provider".into(), Value::String(p.into())); self }
    pub fn source_type(mut self, t: &str) -> Self { self.props.insert("source_type".into(), Value::String(t.into())); self }
    pub fn arn(mut self, arn: &str) -> Self { self.props.insert(prop::ARN.into(), Value::String(arn.into())); self }
    pub fn region(mut self, r: &str) -> Self { self.props.insert(prop::REGION.into(), Value::String(r.into())); self }
    pub fn account_id(mut self, id: &str) -> Self { self.props.insert(prop::ACCOUNT_ID.into(), Value::String(id.into())); self }
    pub fn name(mut self, n: &str) -> Self { self.props.insert(prop::NAME.into(), Value::String(n.into())); self }
    pub fn engine(mut self, e: &str) -> Self { self.props.insert("engine".into(), Value::String(e.into())); self }
    pub fn engine_version(mut self, v: &str) -> Self { self.props.insert("engine_version".into(), Value::String(v.into())); self }
    pub fn multi_az(mut self, v: bool) -> Self { self.props.insert("multi_az".into(), Value::Bool(v)); self }
    pub fn storage_encrypted(mut self, v: bool) -> Self { self.props.insert("storage_encrypted".into(), Value::Bool(v)); self }
    pub fn allocated_storage_gb(mut self, gb: i64) -> Self { self.props.insert("allocated_storage_gb".into(), Value::Int(gb)); self }
    pub fn environment(mut self, e: &str) -> Self { self.props.insert(prop::ENVIRONMENT.into(), Value::String(e.into())); self }
    pub fn data_sensitivity(mut self, s: &str) -> Self { self.props.insert(prop::DATA_SENSITIVITY.into(), Value::String(s.into())); self }
    pub fn business_criticality(mut self, c: i64) -> Self { self.props.insert(prop::BUSINESS_CRITICALITY.into(), Value::Int(c)); self }
    pub fn monthly_cost_cents(mut self, c: i64) -> Self { self.props.insert(prop::MONTHLY_COST_CENTS.into(), Value::Int(c)); self }
    pub fn prop(mut self, k: &str, v: Value) -> Self { self.props.insert(k.into(), v); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, MANAGED_DATABASE, self.props))
    }
}

// ============================================================================
// Object Store — S3, Azure Blob, GCS, MinIO, NAS share
// ============================================================================

pub struct ObjectStoreBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl ObjectStoreBuilder {
    pub fn new(resource_id: &str) -> Self {
        let node_id = NodeId::new();
        let mut props = HashMap::new();
        identity_defaults(&mut props, resource_id);
        trust_defaults(&mut props);
        // Object stores typically have no upstream dependencies
        props.insert(prop::TRUST_DEPENDENCY_HEALTH.into(), Value::Float(1.0));
        props.insert(prop::STATUS.into(), Value::String("active".into()));
        props.insert(prop::PROTECTION_STATUS.into(), Value::String("unprotected".into()));
        props.insert("cloud_provider".into(), Value::String("unknown".into()));
        props.insert("source_type".into(), Value::String("object_store".into()));
        props.insert("versioning_enabled".into(), Value::Bool(false));
        props.insert("encryption_type".into(), Value::String("none".into()));
        props.insert("public_access_blocked".into(), Value::Bool(true));
        props.insert("object_count".into(), Value::Int(0));
        props.insert("total_size_bytes".into(), Value::Int(0));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn cloud_provider(mut self, p: &str) -> Self { self.props.insert("cloud_provider".into(), Value::String(p.into())); self }
    pub fn source_type(mut self, t: &str) -> Self { self.props.insert("source_type".into(), Value::String(t.into())); self }
    pub fn arn(mut self, arn: &str) -> Self { self.props.insert(prop::ARN.into(), Value::String(arn.into())); self }
    pub fn region(mut self, r: &str) -> Self { self.props.insert(prop::REGION.into(), Value::String(r.into())); self }
    pub fn account_id(mut self, id: &str) -> Self { self.props.insert(prop::ACCOUNT_ID.into(), Value::String(id.into())); self }
    pub fn name(mut self, n: &str) -> Self { self.props.insert(prop::NAME.into(), Value::String(n.into())); self }
    pub fn versioning(mut self, v: bool) -> Self { self.props.insert("versioning_enabled".into(), Value::Bool(v)); self }
    pub fn encryption(mut self, e: &str) -> Self { self.props.insert("encryption_type".into(), Value::String(e.into())); self }
    pub fn public_access_blocked(mut self, v: bool) -> Self { self.props.insert("public_access_blocked".into(), Value::Bool(v)); self }
    pub fn data_sensitivity(mut self, s: &str) -> Self { self.props.insert(prop::DATA_SENSITIVITY.into(), Value::String(s.into())); self }
    pub fn business_criticality(mut self, c: i64) -> Self { self.props.insert(prop::BUSINESS_CRITICALITY.into(), Value::Int(c)); self }
    pub fn prop(mut self, k: &str, v: Value) -> Self { self.props.insert(k.into(), v); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, OBJECT_STORE, self.props))
    }
}

// ============================================================================
// Virtual Network — VPC, Azure VNet, GCP VPC
// ============================================================================

pub struct VirtualNetworkBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl VirtualNetworkBuilder {
    pub fn new(resource_id: &str) -> Self {
        let node_id = NodeId::new();
        let mut props = HashMap::new();
        identity_defaults(&mut props, resource_id);
        props.insert(prop::STATUS.into(), Value::String("available".into()));
        props.insert("cloud_provider".into(), Value::String("unknown".into()));
        props.insert("source_type".into(), Value::String("virtual_network".into()));
        props.insert("cidr_block".into(), Value::String("10.0.0.0/16".into()));
        props.insert("is_default".into(), Value::Bool(false));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn cloud_provider(mut self, p: &str) -> Self { self.props.insert("cloud_provider".into(), Value::String(p.into())); self }
    pub fn source_type(mut self, t: &str) -> Self { self.props.insert("source_type".into(), Value::String(t.into())); self }
    pub fn arn(mut self, arn: &str) -> Self { self.props.insert(prop::ARN.into(), Value::String(arn.into())); self }
    pub fn region(mut self, r: &str) -> Self { self.props.insert(prop::REGION.into(), Value::String(r.into())); self }
    pub fn account_id(mut self, id: &str) -> Self { self.props.insert(prop::ACCOUNT_ID.into(), Value::String(id.into())); self }
    pub fn name(mut self, n: &str) -> Self { self.props.insert(prop::NAME.into(), Value::String(n.into())); self }
    pub fn cidr(mut self, c: &str) -> Self { self.props.insert("cidr_block".into(), Value::String(c.into())); self }
    pub fn is_default(mut self, v: bool) -> Self { self.props.insert("is_default".into(), Value::Bool(v)); self }
    pub fn prop(mut self, k: &str, v: Value) -> Self { self.props.insert(k.into(), v); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, VIRTUAL_NETWORK, self.props))
    }
}

// ============================================================================
// Identity Role — IAM Role, Azure AD Role, GCP Service Account
// ============================================================================

pub struct IdentityRoleBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl IdentityRoleBuilder {
    pub fn new(role_name: &str) -> Self {
        let node_id = NodeId::new();
        let now = Utc::now();
        let mut props = HashMap::new();
        identity_defaults(&mut props, role_name);
        props.insert(prop::NAME.into(), Value::String(role_name.into()));
        props.insert("cloud_provider".into(), Value::String("unknown".into()));
        props.insert("source_type".into(), Value::String("identity_role".into()));
        props.insert("is_service_role".into(), Value::Bool(false));
        props.insert("has_admin_access".into(), Value::Bool(false));
        props.insert("attached_policy_count".into(), Value::Int(0));
        props.insert("last_used_at".into(), Value::Null);
        props.insert("created_at_cloud".into(), Value::Timestamp(now));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn cloud_provider(mut self, p: &str) -> Self { self.props.insert("cloud_provider".into(), Value::String(p.into())); self }
    pub fn source_type(mut self, t: &str) -> Self { self.props.insert("source_type".into(), Value::String(t.into())); self }
    pub fn arn(mut self, arn: &str) -> Self { self.props.insert(prop::ARN.into(), Value::String(arn.into())); self }
    pub fn account_id(mut self, id: &str) -> Self { self.props.insert(prop::ACCOUNT_ID.into(), Value::String(id.into())); self }
    pub fn has_admin_access(mut self, v: bool) -> Self { self.props.insert("has_admin_access".into(), Value::Bool(v)); self }
    pub fn is_service_role(mut self, v: bool) -> Self { self.props.insert("is_service_role".into(), Value::Bool(v)); self }
    pub fn attached_policy_count(mut self, c: i64) -> Self { self.props.insert("attached_policy_count".into(), Value::Int(c)); self }
    pub fn prop(mut self, k: &str, v: Value) -> Self { self.props.insert(k.into(), v); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, IDENTITY_ROLE, self.props))
    }
}

// ============================================================================
// Identity User — IAM User, Azure AD User, Google Workspace User
// ============================================================================

pub struct IdentityUserBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl IdentityUserBuilder {
    pub fn new(user_name: &str) -> Self {
        let node_id = NodeId::new();
        let mut props = HashMap::new();
        identity_defaults(&mut props, user_name);
        props.insert(prop::NAME.into(), Value::String(user_name.into()));
        props.insert("cloud_provider".into(), Value::String("unknown".into()));
        props.insert("source_type".into(), Value::String("identity_user".into()));
        props.insert("has_console_access".into(), Value::Bool(false));
        props.insert("has_api_keys".into(), Value::Bool(false));
        props.insert("mfa_enabled".into(), Value::Bool(false));
        props.insert("last_login_at".into(), Value::Null);
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn cloud_provider(mut self, p: &str) -> Self { self.props.insert("cloud_provider".into(), Value::String(p.into())); self }
    pub fn source_type(mut self, t: &str) -> Self { self.props.insert("source_type".into(), Value::String(t.into())); self }
    pub fn arn(mut self, arn: &str) -> Self { self.props.insert(prop::ARN.into(), Value::String(arn.into())); self }
    pub fn account_id(mut self, id: &str) -> Self { self.props.insert(prop::ACCOUNT_ID.into(), Value::String(id.into())); self }
    pub fn has_console_access(mut self, v: bool) -> Self { self.props.insert("has_console_access".into(), Value::Bool(v)); self }
    pub fn has_api_keys(mut self, v: bool) -> Self { self.props.insert("has_api_keys".into(), Value::Bool(v)); self }
    pub fn mfa_enabled(mut self, v: bool) -> Self { self.props.insert("mfa_enabled".into(), Value::Bool(v)); self }
    pub fn has_admin_access(mut self, v: bool) -> Self { self.props.insert("has_admin_access".into(), Value::Bool(v)); self }
    pub fn prop(mut self, k: &str, v: Value) -> Self { self.props.insert(k.into(), v); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, IDENTITY_USER, self.props))
    }
}

// ============================================================================
// Serverless Function — Lambda, Azure Functions, Cloud Functions
// ============================================================================

pub struct ServerlessFunctionBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl ServerlessFunctionBuilder {
    pub fn new(function_name: &str) -> Self {
        let node_id = NodeId::new();
        let mut props = HashMap::new();
        identity_defaults(&mut props, function_name);
        props.insert(prop::NAME.into(), Value::String(function_name.into()));
        props.insert(prop::STATUS.into(), Value::String("active".into()));
        props.insert("cloud_provider".into(), Value::String("unknown".into()));
        props.insert("source_type".into(), Value::String("serverless_function".into()));
        props.insert("runtime".into(), Value::String("unknown".into()));
        props.insert("memory_mb".into(), Value::Int(128));
        props.insert("timeout_secs".into(), Value::Int(30));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn cloud_provider(mut self, p: &str) -> Self { self.props.insert("cloud_provider".into(), Value::String(p.into())); self }
    pub fn source_type(mut self, t: &str) -> Self { self.props.insert("source_type".into(), Value::String(t.into())); self }
    pub fn arn(mut self, arn: &str) -> Self { self.props.insert(prop::ARN.into(), Value::String(arn.into())); self }
    pub fn region(mut self, r: &str) -> Self { self.props.insert(prop::REGION.into(), Value::String(r.into())); self }
    pub fn account_id(mut self, id: &str) -> Self { self.props.insert(prop::ACCOUNT_ID.into(), Value::String(id.into())); self }
    pub fn runtime(mut self, r: &str) -> Self { self.props.insert("runtime".into(), Value::String(r.into())); self }
    pub fn memory_mb(mut self, m: i64) -> Self { self.props.insert("memory_mb".into(), Value::Int(m)); self }
    pub fn prop(mut self, k: &str, v: Value) -> Self { self.props.insert(k.into(), v); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, SERVERLESS_FUNCTION, self.props))
    }
}

// ============================================================================
// SaaS Application — M365 tenant, Google Workspace, Salesforce org
// ============================================================================

pub struct SaasApplicationBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl SaasApplicationBuilder {
    pub fn new(app_id: &str, platform: &str) -> Self {
        let node_id = NodeId::new();
        let mut props = HashMap::new();
        identity_defaults(&mut props, app_id);
        trust_defaults(&mut props);
        props.insert(prop::STATUS.into(), Value::String("active".into()));
        props.insert(prop::PROTECTION_STATUS.into(), Value::String("unprotected".into()));
        props.insert("cloud_provider".into(), Value::String("saas".into()));
        props.insert("source_type".into(), Value::String(platform.into()));
        props.insert("user_count".into(), Value::Int(0));
        props.insert("data_volume_gb".into(), Value::Int(0));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn name(mut self, n: &str) -> Self { self.props.insert(prop::NAME.into(), Value::String(n.into())); self }
    pub fn user_count(mut self, c: i64) -> Self { self.props.insert("user_count".into(), Value::Int(c)); self }
    pub fn data_volume_gb(mut self, gb: i64) -> Self { self.props.insert("data_volume_gb".into(), Value::Int(gb)); self }
    pub fn data_sensitivity(mut self, s: &str) -> Self { self.props.insert(prop::DATA_SENSITIVITY.into(), Value::String(s.into())); self }
    pub fn business_criticality(mut self, c: i64) -> Self { self.props.insert(prop::BUSINESS_CRITICALITY.into(), Value::Int(c)); self }
    pub fn prop(mut self, k: &str, v: Value) -> Self { self.props.insert(k.into(), v); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, SAAS_APPLICATION, self.props))
    }
}

// ============================================================================
// Endpoint — laptop, workstation, mobile device
// ============================================================================

pub struct EndpointBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl EndpointBuilder {
    pub fn new(device_id: &str) -> Self {
        let node_id = NodeId::new();
        let mut props = HashMap::new();
        identity_defaults(&mut props, device_id);
        trust_defaults(&mut props);
        props.insert(prop::STATUS.into(), Value::String("online".into()));
        props.insert(prop::PROTECTION_STATUS.into(), Value::String("unprotected".into()));
        props.insert("cloud_provider".into(), Value::String("on_prem".into()));
        props.insert("source_type".into(), Value::String("endpoint".into()));
        props.insert("device_type".into(), Value::String("laptop".into()));
        props.insert("os".into(), Value::String("unknown".into()));
        props.insert("agent_installed".into(), Value::Bool(false));
        props.insert("agent_version".into(), Value::Null);
        props.insert("last_backup_at".into(), Value::Null);
        props.insert("disk_size_gb".into(), Value::Int(0));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn name(mut self, n: &str) -> Self { self.props.insert(prop::NAME.into(), Value::String(n.into())); self }
    pub fn device_type(mut self, t: &str) -> Self { self.props.insert("device_type".into(), Value::String(t.into())); self }
    pub fn os(mut self, o: &str) -> Self { self.props.insert("os".into(), Value::String(o.into())); self }
    pub fn agent_installed(mut self, v: bool) -> Self { self.props.insert("agent_installed".into(), Value::Bool(v)); self }
    pub fn agent_version(mut self, v: &str) -> Self { self.props.insert("agent_version".into(), Value::String(v.into())); self }
    pub fn disk_size_gb(mut self, gb: i64) -> Self { self.props.insert("disk_size_gb".into(), Value::Int(gb)); self }
    pub fn data_sensitivity(mut self, s: &str) -> Self { self.props.insert(prop::DATA_SENSITIVITY.into(), Value::String(s.into())); self }
    pub fn prop(mut self, k: &str, v: Value) -> Self { self.props.insert(k.into(), v); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, ENDPOINT, self.props))
    }
}

// ============================================================================
// On-Prem Server — VMware guest, Hyper-V VM, bare metal, NAS
// ============================================================================

pub struct OnPremServerBuilder {
    node_id: NodeId,
    props: HashMap<String, Value>,
}

impl OnPremServerBuilder {
    pub fn new(server_id: &str) -> Self {
        let node_id = NodeId::new();
        let mut props = HashMap::new();
        identity_defaults(&mut props, server_id);
        trust_defaults(&mut props);
        props.insert(prop::STATUS.into(), Value::String("running".into()));
        props.insert(prop::PROTECTION_STATUS.into(), Value::String("unprotected".into()));
        props.insert("cloud_provider".into(), Value::String("on_prem".into()));
        props.insert("source_type".into(), Value::String("server".into()));
        props.insert("hypervisor".into(), Value::String("none".into()));
        props.insert("os".into(), Value::String("unknown".into()));
        Self { node_id, props }
    }

    pub fn node_id(&self) -> &NodeId { &self.node_id }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.node_id = id; self }
    pub fn name(mut self, n: &str) -> Self { self.props.insert(prop::NAME.into(), Value::String(n.into())); self }
    pub fn hypervisor(mut self, h: &str) -> Self { self.props.insert("hypervisor".into(), Value::String(h.into())); self }
    pub fn os(mut self, o: &str) -> Self { self.props.insert("os".into(), Value::String(o.into())); self }
    pub fn data_sensitivity(mut self, s: &str) -> Self { self.props.insert(prop::DATA_SENSITIVITY.into(), Value::String(s.into())); self }
    pub fn business_criticality(mut self, c: i64) -> Self { self.props.insert(prop::BUSINESS_CRITICALITY.into(), Value::Int(c)); self }
    pub fn prop(mut self, k: &str, v: Value) -> Self { self.props.insert(k.into(), v); self }

    pub fn build(self) -> (NodeId, EventKind) {
        let id = self.node_id.clone();
        (id, create_node(self.node_id, ON_PREM_SERVER, self.props))
    }
}
