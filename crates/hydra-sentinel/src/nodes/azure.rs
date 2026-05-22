//! # Azure Cloud Adapter
//!
//! Thin wrappers around abstract resource builders that pre-set
//! `cloud_provider = "azure"` and `source_type` to the Azure-specific name.

use hydra_core::event::{EventKind, Value};
use hydra_core::id::NodeId;
use super::resource::*;

// ============================================================================
// Azure VM → ComputeInstance
// ============================================================================

pub struct AzureVmBuilder(ComputeInstanceBuilder);

impl AzureVmBuilder {
    pub fn new(vm_id: &str) -> Self {
        Self(ComputeInstanceBuilder::new(vm_id)
            .cloud_provider("azure")
            .source_type("azure_vm"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn resource_id(mut self, rid: &str) -> Self { self.0 = self.0.arn(rid); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn subscription_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn resource_group(mut self, rg: &str) -> Self { self.0 = self.0.prop("resource_group", Value::String(rg.into())); self }
    pub fn name(mut self, n: &str) -> Self { self.0 = self.0.name(n); self }
    pub fn vm_size(mut self, s: &str) -> Self { self.0 = self.0.instance_type(s); self }
    pub fn os(mut self, o: &str) -> Self { self.0 = self.0.os(o); self }
    pub fn environment(mut self, e: &str) -> Self { self.0 = self.0.environment(e); self }
    pub fn data_sensitivity(mut self, s: &str) -> Self { self.0 = self.0.data_sensitivity(s); self }
    pub fn business_criticality(mut self, c: i64) -> Self { self.0 = self.0.business_criticality(c); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// Azure SQL → ManagedDatabase
// ============================================================================

pub struct AzureSqlBuilder(ManagedDatabaseBuilder);

impl AzureSqlBuilder {
    pub fn new(db_id: &str) -> Self {
        Self(ManagedDatabaseBuilder::new(db_id)
            .cloud_provider("azure")
            .source_type("azure_sql")
            .engine("mssql"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn resource_id(mut self, rid: &str) -> Self { self.0 = self.0.arn(rid); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn subscription_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn resource_group(mut self, rg: &str) -> Self { self.0 = self.0.prop("resource_group", Value::String(rg.into())); self }
    pub fn name(mut self, n: &str) -> Self { self.0 = self.0.name(n); self }
    pub fn sku_tier(mut self, t: &str) -> Self { self.0 = self.0.prop("sku_tier", Value::String(t.into())); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// Azure Blob Storage → ObjectStore
// ============================================================================

pub struct AzureBlobBuilder(ObjectStoreBuilder);

impl AzureBlobBuilder {
    pub fn new(account_name: &str) -> Self {
        Self(ObjectStoreBuilder::new(account_name)
            .cloud_provider("azure")
            .source_type("azure_blob")
            .name(account_name))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn resource_id(mut self, rid: &str) -> Self { self.0 = self.0.arn(rid); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn subscription_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn replication_type(mut self, t: &str) -> Self { self.0 = self.0.prop("replication_type", Value::String(t.into())); self }
    pub fn data_sensitivity(mut self, s: &str) -> Self { self.0 = self.0.data_sensitivity(s); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// Azure VNet → VirtualNetwork
// ============================================================================

pub struct AzureVnetBuilder(VirtualNetworkBuilder);

impl AzureVnetBuilder {
    pub fn new(vnet_id: &str) -> Self {
        Self(VirtualNetworkBuilder::new(vnet_id)
            .cloud_provider("azure")
            .source_type("azure_vnet"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn resource_id(mut self, rid: &str) -> Self { self.0 = self.0.arn(rid); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn subscription_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn cidr(mut self, c: &str) -> Self { self.0 = self.0.cidr(c); self }
    pub fn name(mut self, n: &str) -> Self { self.0 = self.0.name(n); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// Azure Functions → ServerlessFunction
// ============================================================================

pub struct AzureFunctionBuilder(ServerlessFunctionBuilder);

impl AzureFunctionBuilder {
    pub fn new(function_name: &str) -> Self {
        Self(ServerlessFunctionBuilder::new(function_name)
            .cloud_provider("azure")
            .source_type("azure_function")
            .runtime("dotnet"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn resource_id(mut self, rid: &str) -> Self { self.0 = self.0.arn(rid); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn runtime(mut self, r: &str) -> Self { self.0 = self.0.runtime(r); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}
