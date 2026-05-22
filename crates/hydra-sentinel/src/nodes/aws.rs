//! # AWS Cloud Adapter
//!
//! Thin wrappers around abstract resource builders that pre-set
//! `cloud_provider = "aws"` and `source_type` to the AWS-specific name.
//! Adds AWS-specific convenience methods (AMI, VPC ID, etc.).

use hydra_core::event::{EventKind, Value};
use hydra_core::id::NodeId;
use super::resource::*;

// ============================================================================
// EC2 → ComputeInstance
// ============================================================================

pub struct Ec2Builder(ComputeInstanceBuilder);

impl Ec2Builder {
    pub fn new(instance_id: &str) -> Self {
        Self(ComputeInstanceBuilder::new(instance_id)
            .cloud_provider("aws")
            .source_type("ec2"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn arn(mut self, arn: &str) -> Self { self.0 = self.0.arn(arn); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn account_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn name(mut self, n: &str) -> Self { self.0 = self.0.name(n); self }
    pub fn status(mut self, s: &str) -> Self { self.0 = self.0.status(s); self }
    pub fn instance_type(mut self, t: &str) -> Self { self.0 = self.0.instance_type(t); self }
    pub fn environment(mut self, e: &str) -> Self { self.0 = self.0.environment(e); self }
    pub fn data_sensitivity(mut self, s: &str) -> Self { self.0 = self.0.data_sensitivity(s); self }
    pub fn business_criticality(mut self, c: i64) -> Self { self.0 = self.0.business_criticality(c); self }
    pub fn monthly_cost_cents(mut self, c: i64) -> Self { self.0 = self.0.monthly_cost_cents(c); self }
    // AWS-specific
    pub fn ami(mut self, a: &str) -> Self { self.0 = self.0.prop("ami", Value::String(a.into())); self }
    pub fn az(mut self, az: &str) -> Self { self.0 = self.0.prop("availability_zone", Value::String(az.into())); self }
    pub fn vpc_id(mut self, v: &str) -> Self { self.0 = self.0.prop("vpc_id", Value::String(v.into())); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// RDS → ManagedDatabase
// ============================================================================

pub struct RdsBuilder(ManagedDatabaseBuilder);

impl RdsBuilder {
    pub fn new(db_instance_id: &str) -> Self {
        Self(ManagedDatabaseBuilder::new(db_instance_id)
            .cloud_provider("aws")
            .source_type("rds")
            .engine("postgres")
            .engine_version("15.4"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn arn(mut self, arn: &str) -> Self { self.0 = self.0.arn(arn); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn account_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn name(mut self, n: &str) -> Self { self.0 = self.0.name(n); self }
    pub fn engine(mut self, e: &str) -> Self { self.0 = self.0.engine(e); self }
    pub fn engine_version(mut self, v: &str) -> Self { self.0 = self.0.engine_version(v); self }
    pub fn multi_az(mut self, v: bool) -> Self { self.0 = self.0.multi_az(v); self }
    pub fn storage_encrypted(mut self, v: bool) -> Self { self.0 = self.0.storage_encrypted(v); self }
    pub fn allocated_storage_gb(mut self, gb: i64) -> Self { self.0 = self.0.allocated_storage_gb(gb); self }
    pub fn environment(mut self, e: &str) -> Self { self.0 = self.0.environment(e); self }
    pub fn data_sensitivity(mut self, s: &str) -> Self { self.0 = self.0.data_sensitivity(s); self }
    pub fn business_criticality(mut self, c: i64) -> Self { self.0 = self.0.business_criticality(c); self }
    pub fn monthly_cost_cents(mut self, c: i64) -> Self { self.0 = self.0.monthly_cost_cents(c); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// S3 → ObjectStore
// ============================================================================

pub struct S3BucketBuilder(ObjectStoreBuilder);

impl S3BucketBuilder {
    pub fn new(bucket_name: &str) -> Self {
        Self(ObjectStoreBuilder::new(bucket_name)
            .cloud_provider("aws")
            .source_type("s3")
            .name(bucket_name))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn arn(mut self, arn: &str) -> Self { self.0 = self.0.arn(arn); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn account_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn versioning(mut self, v: bool) -> Self { self.0 = self.0.versioning(v); self }
    pub fn encryption(mut self, e: &str) -> Self { self.0 = self.0.encryption(e); self }
    pub fn public_access_blocked(mut self, v: bool) -> Self { self.0 = self.0.public_access_blocked(v); self }
    pub fn data_sensitivity(mut self, s: &str) -> Self { self.0 = self.0.data_sensitivity(s); self }
    pub fn business_criticality(mut self, c: i64) -> Self { self.0 = self.0.business_criticality(c); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// VPC → VirtualNetwork
// ============================================================================

pub struct VpcBuilder(VirtualNetworkBuilder);

impl VpcBuilder {
    pub fn new(vpc_id: &str) -> Self {
        Self(VirtualNetworkBuilder::new(vpc_id)
            .cloud_provider("aws")
            .source_type("vpc"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn arn(mut self, arn: &str) -> Self { self.0 = self.0.arn(arn); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn account_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn cidr(mut self, c: &str) -> Self { self.0 = self.0.cidr(c); self }
    pub fn is_default(mut self, v: bool) -> Self { self.0 = self.0.is_default(v); self }
    pub fn name(mut self, n: &str) -> Self { self.0 = self.0.name(n); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// IAM Role → IdentityRole
// ============================================================================

pub struct IamRoleBuilder(IdentityRoleBuilder);

impl IamRoleBuilder {
    pub fn new(role_name: &str) -> Self {
        Self(IdentityRoleBuilder::new(role_name)
            .cloud_provider("aws")
            .source_type("iam_role"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn arn(mut self, arn: &str) -> Self { self.0 = self.0.arn(arn); self }
    pub fn account_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn has_admin_access(mut self, v: bool) -> Self { self.0 = self.0.has_admin_access(v); self }
    pub fn is_service_role(mut self, v: bool) -> Self { self.0 = self.0.is_service_role(v); self }
    pub fn attached_policy_count(mut self, c: i64) -> Self { self.0 = self.0.attached_policy_count(c); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// IAM User → IdentityUser
// ============================================================================

pub struct IamUserBuilder(IdentityUserBuilder);

impl IamUserBuilder {
    pub fn new(user_name: &str) -> Self {
        Self(IdentityUserBuilder::new(user_name)
            .cloud_provider("aws")
            .source_type("iam_user"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn arn(mut self, arn: &str) -> Self { self.0 = self.0.arn(arn); self }
    pub fn account_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn has_console_access(mut self, v: bool) -> Self { self.0 = self.0.has_console_access(v); self }
    pub fn has_api_keys(mut self, v: bool) -> Self { self.0 = self.0.has_api_keys(v); self }
    pub fn mfa_enabled(mut self, v: bool) -> Self { self.0 = self.0.mfa_enabled(v); self }
    pub fn has_admin_access(mut self, v: bool) -> Self { self.0 = self.0.has_admin_access(v); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}

// ============================================================================
// Lambda → ServerlessFunction
// ============================================================================

pub struct LambdaBuilder(ServerlessFunctionBuilder);

impl LambdaBuilder {
    pub fn new(function_name: &str) -> Self {
        Self(ServerlessFunctionBuilder::new(function_name)
            .cloud_provider("aws")
            .source_type("lambda")
            .runtime("python3.12"))
    }
    pub fn node_id(&self) -> &NodeId { self.0.node_id() }
    pub fn with_node_id(mut self, id: NodeId) -> Self { self.0 = self.0.with_node_id(id); self }
    pub fn arn(mut self, arn: &str) -> Self { self.0 = self.0.arn(arn); self }
    pub fn region(mut self, r: &str) -> Self { self.0 = self.0.region(r); self }
    pub fn account_id(mut self, id: &str) -> Self { self.0 = self.0.account_id(id); self }
    pub fn runtime(mut self, r: &str) -> Self { self.0 = self.0.runtime(r); self }
    pub fn memory_mb(mut self, m: i64) -> Self { self.0 = self.0.memory_mb(m); self }

    pub fn build(self) -> (NodeId, EventKind) { self.0.build() }
}
