//! # GCP Cloud Adapter
//!
//! Thin wrappers around abstract resource builders that pre-set
//! `cloud_provider = "gcp"` and `source_type` to the GCP-specific name.

use hydra_core::event::{EventKind, Value};
use hydra_core::id::NodeId;
use super::resource::*;

// ============================================================================
// GCE → ComputeInstance
// ============================================================================

pub struct GceBuilder(ComputeInstanceBuilder);

impl GceBuilder {
    pub fn new(instance_id: &str) -> Self {
        Self(ComputeInstanceBuilder::new(instance_id)
            .cloud_provider("gcp")
            .source_type("gce"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn self_link(mut self, link: &str) -> Self { self.0 = self.0.arn(link); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn zone(mut self, z: &str) -> Self { self.0 = self.0.prop("zone", Value::String(z.into())); self }
    pub fn project_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn name(mut self, n: &str) -> Self { self.0 = self.0.name(n); self }
    pub fn machine_type(mut self, t: &str) -> Self { self.0 = self.0.instance_type(t); self }
    pub fn environment(mut self, e: &str) -> Self { self.0 = self.0.environment(e); self }
    pub fn data_sensitivity(mut self, s: &str) -> Self { self.0 = self.0.data_sensitivity(s); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// Cloud SQL → ManagedDatabase
// ============================================================================

pub struct CloudSqlBuilder(ManagedDatabaseBuilder);

impl CloudSqlBuilder {
    pub fn new(instance_id: &str) -> Self {
        Self(ManagedDatabaseBuilder::new(instance_id)
            .cloud_provider("gcp")
            .source_type("cloud_sql")
            .engine("postgres"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn self_link(mut self, link: &str) -> Self { self.0 = self.0.arn(link); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn project_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn name(mut self, n: &str) -> Self { self.0 = self.0.name(n); self }
    pub fn engine(mut self, e: &str) -> Self { self.0 = self.0.engine(e); self }
    pub fn tier(mut self, t: &str) -> Self { self.0 = self.0.prop("tier", Value::String(t.into())); self }
    pub fn high_availability(mut self, v: bool) -> Self { self.0 = self.0.multi_az(v); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// GCS → ObjectStore
// ============================================================================

pub struct GcsBuilder(ObjectStoreBuilder);

impl GcsBuilder {
    pub fn new(bucket_name: &str) -> Self {
        Self(ObjectStoreBuilder::new(bucket_name)
            .cloud_provider("gcp")
            .source_type("gcs")
            .name(bucket_name))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn self_link(mut self, link: &str) -> Self { self.0 = self.0.arn(link); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn project_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn storage_class(mut self, c: &str) -> Self { self.0 = self.0.prop("storage_class", Value::String(c.into())); self }
    pub fn data_sensitivity(mut self, s: &str) -> Self { self.0 = self.0.data_sensitivity(s); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// GCP VPC → VirtualNetwork
// ============================================================================

pub struct GcpVpcBuilder(VirtualNetworkBuilder);

impl GcpVpcBuilder {
    pub fn new(vpc_name: &str) -> Self {
        Self(VirtualNetworkBuilder::new(vpc_name)
            .cloud_provider("gcp")
            .source_type("gcp_vpc"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn self_link(mut self, link: &str) -> Self { self.0 = self.0.arn(link); self }
    pub fn project_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn name(mut self, n: &str) -> Self { self.0 = self.0.name(n); self }
    pub fn auto_create_subnets(mut self, v: bool) -> Self { self.0 = self.0.prop("auto_create_subnets", Value::Bool(v)); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// Cloud Functions → ServerlessFunction
// ============================================================================

pub struct CloudFunctionBuilder(ServerlessFunctionBuilder);

impl CloudFunctionBuilder {
    pub fn new(function_name: &str) -> Self {
        Self(ServerlessFunctionBuilder::new(function_name)
            .cloud_provider("gcp")
            .source_type("cloud_function")
            .runtime("python312"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn self_link(mut self, link: &str) -> Self { self.0 = self.0.arn(link); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn project_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn runtime(mut self, r: &str) -> Self { self.0 = self.0.runtime(r); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}
