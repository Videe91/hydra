//! # CloudTrail Event Mapping
//!
//! Maps AWS CloudTrail `eventSource` + `eventName` combinations to
//! Hydra abstract resource types and signal kinds.
//!
//! CloudTrail events follow a pattern:
//! - `eventSource`: the AWS service (e.g., "ec2.amazonaws.com")
//! - `eventName`: the API action (e.g., "RunInstances", "TerminateInstances")
//! - `requestParameters` / `responseElements`: service-specific JSON
//!
//! This module defines the mapping from CloudTrail → Hydra signals:
//! - Create events → Signal("resource_discovered")
//! - Delete events → Signal("resource_deleted")
//! - Relationship events → Signal("dependency_discovered")
//! - Mutation events → Signal("resource_updated")

use hydra_sentinel::nodes;

/// The kind of Hydra signal a CloudTrail event should produce.
#[derive(Debug, Clone, PartialEq)]
pub enum SignalKind {
    /// A new resource was created
    ResourceDiscovered {
        resource_id: String,
        resource_type: &'static str,
        name: Option<String>,
        region: String,
        properties: Vec<(String, String)>,
    },
    /// A resource was destroyed
    ResourceDeleted {
        resource_id: String,
    },
    /// A dependency relationship was discovered
    DependencyDiscovered {
        source: String,
        target: String,
        dependency_type: String,
        confidence: f64,
    },
    /// A resource was modified (triggers reclassification)
    ResourceUpdated {
        resource_id: String,
        changed_properties: Vec<(String, String)>,
    },
    /// Not a resource lifecycle event — skip
    Ignored,
    /// CloudTrail event we recognize but can't fully parse
    ParseError(String),
}

/// A single mapping rule: eventSource + eventName → signal extraction function.
#[derive(Clone)]
pub struct EventMapping {
    pub event_source: &'static str,
    pub event_name: &'static str,
    pub extractor: fn(&serde_json::Value) -> SignalKind,
}

/// Build the complete mapping table.
/// Each entry maps a CloudTrail (eventSource, eventName) pair
/// to a function that extracts the Hydra signal from the event JSON.
pub fn cloudtrail_mappings() -> Vec<EventMapping> {
    vec![
        // ============================
        // EC2 (Compute Instances)
        // ============================
        EventMapping {
            event_source: "ec2.amazonaws.com",
            event_name: "RunInstances",
            extractor: extract_ec2_run_instances,
        },
        EventMapping {
            event_source: "ec2.amazonaws.com",
            event_name: "TerminateInstances",
            extractor: extract_ec2_terminate,
        },
        EventMapping {
            event_source: "ec2.amazonaws.com",
            event_name: "CreateVolume",
            extractor: extract_ec2_create_volume,
        },
        EventMapping {
            event_source: "ec2.amazonaws.com",
            event_name: "DeleteVolume",
            extractor: extract_generic_delete("volumeId"),
        },
        EventMapping {
            event_source: "ec2.amazonaws.com",
            event_name: "AttachVolume",
            extractor: extract_ec2_attach_volume,
        },
        EventMapping {
            event_source: "ec2.amazonaws.com",
            event_name: "CreateVpc",
            extractor: extract_ec2_create_vpc,
        },
        EventMapping {
            event_source: "ec2.amazonaws.com",
            event_name: "DeleteVpc",
            extractor: extract_generic_delete("vpcId"),
        },
        EventMapping {
            event_source: "ec2.amazonaws.com",
            event_name: "CreateSecurityGroup",
            extractor: extract_ec2_create_sg,
        },
        EventMapping {
            event_source: "ec2.amazonaws.com",
            event_name: "DeleteSecurityGroup",
            extractor: extract_generic_delete("groupId"),
        },

        // ============================
        // RDS (Managed Databases)
        // ============================
        EventMapping {
            event_source: "rds.amazonaws.com",
            event_name: "CreateDBInstance",
            extractor: extract_rds_create,
        },
        EventMapping {
            event_source: "rds.amazonaws.com",
            event_name: "DeleteDBInstance",
            extractor: extract_rds_delete,
        },
        EventMapping {
            event_source: "rds.amazonaws.com",
            event_name: "CreateDBCluster",
            extractor: extract_rds_create_cluster,
        },
        EventMapping {
            event_source: "rds.amazonaws.com",
            event_name: "DeleteDBCluster",
            extractor: extract_rds_delete_cluster,
        },

        // ============================
        // S3 (Object Store)
        // ============================
        EventMapping {
            event_source: "s3.amazonaws.com",
            event_name: "CreateBucket",
            extractor: extract_s3_create_bucket,
        },
        EventMapping {
            event_source: "s3.amazonaws.com",
            event_name: "DeleteBucket",
            extractor: extract_s3_delete_bucket,
        },

        // ============================
        // Lambda (Serverless)
        // ============================
        EventMapping {
            event_source: "lambda.amazonaws.com",
            event_name: "CreateFunction20150331",
            extractor: extract_lambda_create,
        },
        EventMapping {
            event_source: "lambda.amazonaws.com",
            event_name: "DeleteFunction20150331",
            extractor: extract_lambda_delete,
        },

        // ============================
        // IAM (Identity)
        // ============================
        EventMapping {
            event_source: "iam.amazonaws.com",
            event_name: "CreateRole",
            extractor: extract_iam_create_role,
        },
        EventMapping {
            event_source: "iam.amazonaws.com",
            event_name: "DeleteRole",
            extractor: extract_iam_delete_role,
        },
        EventMapping {
            event_source: "iam.amazonaws.com",
            event_name: "CreateUser",
            extractor: extract_iam_create_user,
        },
        EventMapping {
            event_source: "iam.amazonaws.com",
            event_name: "DeleteUser",
            extractor: extract_iam_delete_user,
        },

        // ============================
        // DynamoDB (Managed Database)
        // ============================
        EventMapping {
            event_source: "dynamodb.amazonaws.com",
            event_name: "CreateTable",
            extractor: extract_dynamodb_create,
        },
        EventMapping {
            event_source: "dynamodb.amazonaws.com",
            event_name: "DeleteTable",
            extractor: extract_dynamodb_delete,
        },

        // ============================
        // EBS Snapshots (Backup)
        // ============================
        EventMapping {
            event_source: "ec2.amazonaws.com",
            event_name: "CreateSnapshot",
            extractor: extract_ec2_create_snapshot,
        },
        EventMapping {
            event_source: "ec2.amazonaws.com",
            event_name: "DeleteSnapshot",
            extractor: extract_generic_delete("snapshotId"),
        },

        // ============================
        // ECS (Container Service)
        // ============================
        EventMapping {
            event_source: "ecs.amazonaws.com",
            event_name: "CreateCluster",
            extractor: extract_ecs_create_cluster,
        },
        EventMapping {
            event_source: "ecs.amazonaws.com",
            event_name: "DeleteCluster",
            extractor: extract_ecs_delete_cluster,
        },
        EventMapping {
            event_source: "ecs.amazonaws.com",
            event_name: "CreateService",
            extractor: extract_ecs_create_service,
        },
        EventMapping {
            event_source: "ecs.amazonaws.com",
            event_name: "DeleteService",
            extractor: extract_ecs_delete_service,
        },

        // ============================
        // EKS (Kubernetes)
        // ============================
        EventMapping {
            event_source: "eks.amazonaws.com",
            event_name: "CreateCluster",
            extractor: extract_eks_create_cluster,
        },
        EventMapping {
            event_source: "eks.amazonaws.com",
            event_name: "DeleteCluster",
            extractor: extract_eks_delete_cluster,
        },

        // ============================
        // ElastiCache
        // ============================
        EventMapping {
            event_source: "elasticache.amazonaws.com",
            event_name: "CreateCacheCluster",
            extractor: extract_elasticache_create,
        },
        EventMapping {
            event_source: "elasticache.amazonaws.com",
            event_name: "DeleteCacheCluster",
            extractor: extract_elasticache_delete,
        },
        EventMapping {
            event_source: "elasticache.amazonaws.com",
            event_name: "CreateReplicationGroup",
            extractor: extract_elasticache_create_repl,
        },
        EventMapping {
            event_source: "elasticache.amazonaws.com",
            event_name: "DeleteReplicationGroup",
            extractor: extract_elasticache_delete_repl,
        },

        // ============================
        // Redshift (Data Warehouse)
        // ============================
        EventMapping {
            event_source: "redshift.amazonaws.com",
            event_name: "CreateCluster",
            extractor: extract_redshift_create,
        },
        EventMapping {
            event_source: "redshift.amazonaws.com",
            event_name: "DeleteCluster",
            extractor: extract_redshift_delete,
        },

        // ============================
        // SQS (Message Queue)
        // ============================
        EventMapping {
            event_source: "sqs.amazonaws.com",
            event_name: "CreateQueue",
            extractor: extract_sqs_create,
        },
        EventMapping {
            event_source: "sqs.amazonaws.com",
            event_name: "DeleteQueue",
            extractor: extract_sqs_delete,
        },

        // ============================
        // SNS (Notification)
        // ============================
        EventMapping {
            event_source: "sns.amazonaws.com",
            event_name: "CreateTopic",
            extractor: extract_sns_create,
        },
        EventMapping {
            event_source: "sns.amazonaws.com",
            event_name: "DeleteTopic",
            extractor: extract_sns_delete,
        },

        // ============================
        // ELB (Load Balancer)
        // ============================
        EventMapping {
            event_source: "elasticloadbalancing.amazonaws.com",
            event_name: "CreateLoadBalancer",
            extractor: extract_elb_create,
        },
        EventMapping {
            event_source: "elasticloadbalancing.amazonaws.com",
            event_name: "DeleteLoadBalancer",
            extractor: extract_elb_delete,
        },

        // ============================
        // CloudFront (CDN)
        // ============================
        EventMapping {
            event_source: "cloudfront.amazonaws.com",
            event_name: "CreateDistribution",
            extractor: extract_cloudfront_create,
        },
        EventMapping {
            event_source: "cloudfront.amazonaws.com",
            event_name: "DeleteDistribution",
            extractor: extract_cloudfront_delete,
        },

        // ============================
        // Route53 (DNS)
        // ============================
        EventMapping {
            event_source: "route53.amazonaws.com",
            event_name: "CreateHostedZone",
            extractor: extract_route53_create,
        },
        EventMapping {
            event_source: "route53.amazonaws.com",
            event_name: "DeleteHostedZone",
            extractor: extract_route53_delete,
        },

        // ============================
        // EFS (File System)
        // ============================
        EventMapping {
            event_source: "elasticfilesystem.amazonaws.com",
            event_name: "CreateFileSystem",
            extractor: extract_efs_create,
        },
        EventMapping {
            event_source: "elasticfilesystem.amazonaws.com",
            event_name: "DeleteFileSystem",
            extractor: extract_efs_delete,
        },

        // ============================
        // Kinesis (Stream)
        // ============================
        EventMapping {
            event_source: "kinesis.amazonaws.com",
            event_name: "CreateStream",
            extractor: extract_kinesis_create,
        },
        EventMapping {
            event_source: "kinesis.amazonaws.com",
            event_name: "DeleteStream",
            extractor: extract_kinesis_delete,
        },

        // ============================
        // SageMaker (ML)
        // ============================
        EventMapping {
            event_source: "sagemaker.amazonaws.com",
            event_name: "CreateEndpoint",
            extractor: extract_sagemaker_create,
        },
        EventMapping {
            event_source: "sagemaker.amazonaws.com",
            event_name: "DeleteEndpoint",
            extractor: extract_sagemaker_delete,
        },
    ]
}

// ===========================
// Extractor Functions
// ===========================

fn json_str<'a>(v: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
    let mut current = v;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn json_string(v: &serde_json::Value, path: &[&str]) -> Option<String> {
    json_str(v, path).map(|s| s.to_string())
}

fn extract_region(event: &serde_json::Value) -> String {
    json_string(event, &["awsRegion"]).unwrap_or_else(|| "unknown".into())
}

fn extract_ec2_run_instances(event: &serde_json::Value) -> SignalKind {
    // responseElements.instancesSet.items[*].instanceId
    let items = event
        .get("responseElements")
        .and_then(|r| r.get("instancesSet"))
        .and_then(|s| s.get("items"))
        .and_then(|i| i.as_array());

    match items {
        Some(instances) if !instances.is_empty() => {
            // Return first instance — caller should handle multi-instance launches
            // by calling this extractor per item
            let instance = &instances[0];
            let instance_id = json_string(instance, &["instanceId"])
                .unwrap_or_else(|| "unknown".into());
            let instance_type = json_string(instance, &["instanceType"]);

            let mut props = vec![
                ("cloud_provider".into(), "aws".into()),
            ];
            if let Some(t) = instance_type {
                props.push(("instance_type".into(), t));
            }

            SignalKind::ResourceDiscovered {
                resource_id: instance_id,
                resource_type: nodes::COMPUTE_INSTANCE,
                name: None,
                region: extract_region(event),
                properties: props,
            }
        }
        _ => SignalKind::ParseError("RunInstances: no instances in response".into()),
    }
}

fn extract_ec2_terminate(event: &serde_json::Value) -> SignalKind {
    let items = event
        .get("requestParameters")
        .and_then(|r| r.get("instancesSet"))
        .and_then(|s| s.get("items"))
        .and_then(|i| i.as_array());

    match items {
        Some(instances) if !instances.is_empty() => {
            let instance_id = json_string(&instances[0], &["instanceId"])
                .unwrap_or_else(|| "unknown".into());
            SignalKind::ResourceDeleted { resource_id: instance_id }
        }
        _ => SignalKind::ParseError("TerminateInstances: no instances in request".into()),
    }
}

fn extract_ec2_create_volume(event: &serde_json::Value) -> SignalKind {
    let volume_id = json_string(event, &["responseElements", "volumeId"])
        .unwrap_or_else(|| "unknown".into());
    let size = event.get("responseElements")
        .and_then(|r| r.get("size"))
        .and_then(|s| s.as_i64())
        .map(|s| s.to_string());

    let mut props = vec![("cloud_provider".into(), "aws".into())];
    if let Some(s) = size {
        props.push(("size_gb".into(), s));
    }

    SignalKind::ResourceDiscovered {
        resource_id: volume_id,
        resource_type: nodes::BLOCK_VOLUME,
        name: None,
        region: extract_region(event),
        properties: props,
    }
}

fn extract_ec2_attach_volume(event: &serde_json::Value) -> SignalKind {
    let volume_id = json_string(event, &["requestParameters", "volumeId"]);
    let instance_id = json_string(event, &["requestParameters", "instanceId"]);

    match (volume_id, instance_id) {
        (Some(vol), Some(inst)) => SignalKind::DependencyDiscovered {
            source: inst.to_string(),
            target: vol.to_string(),
            dependency_type: "attached_volume".into(),
            confidence: 1.0,
        },
        _ => SignalKind::ParseError("AttachVolume: missing volumeId or instanceId".into()),
    }
}

fn extract_ec2_create_vpc(event: &serde_json::Value) -> SignalKind {
    let vpc_id = json_string(event, &["responseElements", "vpc", "vpcId"])
        .unwrap_or_else(|| "unknown".into());
    let cidr = json_string(event, &["responseElements", "vpc", "cidrBlock"]);

    let mut props = vec![("cloud_provider".into(), "aws".into())];
    if let Some(c) = cidr {
        props.push(("cidr_block".into(), c));
    }

    SignalKind::ResourceDiscovered {
        resource_id: vpc_id,
        resource_type: nodes::VIRTUAL_NETWORK,
        name: None,
        region: extract_region(event),
        properties: props,
    }
}

fn extract_ec2_create_sg(event: &serde_json::Value) -> SignalKind {
    let group_id = json_string(event, &["responseElements", "groupId"])
        .unwrap_or_else(|| "unknown".into());
    let group_name = json_string(event, &["requestParameters", "groupName"]);

    SignalKind::ResourceDiscovered {
        resource_id: group_id,
        resource_type: nodes::FIREWALL_RULE,
        name: group_name,
        region: extract_region(event),
        properties: vec![("cloud_provider".into(), "aws".into())],
    }
}

fn extract_rds_create(event: &serde_json::Value) -> SignalKind {
    let db_id = json_string(event, &["responseElements", "dBInstanceIdentifier"])
        .or_else(|| json_string(event, &["requestParameters", "dBInstanceIdentifier"]))
        .unwrap_or_else(|| "unknown".into());
    let engine = json_string(event, &["responseElements", "engine"]);
    let db_class = json_string(event, &["responseElements", "dBInstanceClass"]);

    let mut props = vec![("cloud_provider".into(), "aws".into())];
    if let Some(e) = engine {
        props.push(("engine".into(), e));
    }
    if let Some(c) = db_class {
        props.push(("instance_class".into(), c));
    }

    SignalKind::ResourceDiscovered {
        resource_id: db_id.clone(),
        resource_type: nodes::MANAGED_DATABASE,
        name: Some(db_id),
        region: extract_region(event),
        properties: props,
    }
}

fn extract_rds_delete(event: &serde_json::Value) -> SignalKind {
    let db_id = json_string(event, &["requestParameters", "dBInstanceIdentifier"])
        .unwrap_or_else(|| "unknown".into());
    SignalKind::ResourceDeleted { resource_id: db_id }
}

fn extract_rds_create_cluster(event: &serde_json::Value) -> SignalKind {
    let cluster_id = json_string(event, &["responseElements", "dBClusterIdentifier"])
        .or_else(|| json_string(event, &["requestParameters", "dBClusterIdentifier"]))
        .unwrap_or_else(|| "unknown".into());

    SignalKind::ResourceDiscovered {
        resource_id: cluster_id.clone(),
        resource_type: nodes::MANAGED_DATABASE,
        name: Some(cluster_id),
        region: extract_region(event),
        properties: vec![
            ("cloud_provider".into(), "aws".into()),
            ("db_type".into(), "cluster".into()),
        ],
    }
}

fn extract_rds_delete_cluster(event: &serde_json::Value) -> SignalKind {
    let cluster_id = json_string(event, &["requestParameters", "dBClusterIdentifier"])
        .unwrap_or_else(|| "unknown".into());
    SignalKind::ResourceDeleted { resource_id: cluster_id }
}

fn extract_s3_create_bucket(event: &serde_json::Value) -> SignalKind {
    let bucket = json_string(event, &["requestParameters", "bucketName"])
        .unwrap_or_else(|| "unknown".into());

    SignalKind::ResourceDiscovered {
        resource_id: bucket.clone(),
        resource_type: nodes::OBJECT_STORE,
        name: Some(bucket),
        region: extract_region(event),
        properties: vec![("cloud_provider".into(), "aws".into())],
    }
}

fn extract_s3_delete_bucket(event: &serde_json::Value) -> SignalKind {
    let bucket = json_string(event, &["requestParameters", "bucketName"])
        .unwrap_or_else(|| "unknown".into());
    SignalKind::ResourceDeleted { resource_id: bucket }
}

fn extract_lambda_create(event: &serde_json::Value) -> SignalKind {
    let name = json_string(event, &["requestParameters", "functionName"])
        .unwrap_or_else(|| "unknown".into());
    let runtime = json_string(event, &["requestParameters", "runtime"]);

    let mut props = vec![("cloud_provider".into(), "aws".into())];
    if let Some(r) = runtime {
        props.push(("runtime".into(), r));
    }

    SignalKind::ResourceDiscovered {
        resource_id: name.clone(),
        resource_type: nodes::SERVERLESS_FUNCTION,
        name: Some(name),
        region: extract_region(event),
        properties: props,
    }
}

fn extract_lambda_delete(event: &serde_json::Value) -> SignalKind {
    let name = json_string(event, &["requestParameters", "functionName"])
        .unwrap_or_else(|| "unknown".into());
    SignalKind::ResourceDeleted { resource_id: name }
}

fn extract_iam_create_role(event: &serde_json::Value) -> SignalKind {
    let role_name = json_string(event, &["requestParameters", "roleName"])
        .unwrap_or_else(|| "unknown".into());

    SignalKind::ResourceDiscovered {
        resource_id: role_name.clone(),
        resource_type: nodes::IDENTITY_ROLE,
        name: Some(role_name),
        region: "global".into(),
        properties: vec![("cloud_provider".into(), "aws".into())],
    }
}

fn extract_iam_delete_role(event: &serde_json::Value) -> SignalKind {
    let role_name = json_string(event, &["requestParameters", "roleName"])
        .unwrap_or_else(|| "unknown".into());
    SignalKind::ResourceDeleted { resource_id: role_name }
}

fn extract_iam_create_user(event: &serde_json::Value) -> SignalKind {
    let user_name = json_string(event, &["requestParameters", "userName"])
        .unwrap_or_else(|| "unknown".into());

    SignalKind::ResourceDiscovered {
        resource_id: user_name.clone(),
        resource_type: nodes::IDENTITY_USER,
        name: Some(user_name),
        region: "global".into(),
        properties: vec![("cloud_provider".into(), "aws".into())],
    }
}

fn extract_iam_delete_user(event: &serde_json::Value) -> SignalKind {
    let user_name = json_string(event, &["requestParameters", "userName"])
        .unwrap_or_else(|| "unknown".into());
    SignalKind::ResourceDeleted { resource_id: user_name }
}

fn extract_dynamodb_create(event: &serde_json::Value) -> SignalKind {
    let table_name = json_string(event, &["requestParameters", "tableName"])
        .unwrap_or_else(|| "unknown".into());

    SignalKind::ResourceDiscovered {
        resource_id: table_name.clone(),
        resource_type: nodes::MANAGED_DATABASE,
        name: Some(table_name),
        region: extract_region(event),
        properties: vec![
            ("cloud_provider".into(), "aws".into()),
            ("engine".into(), "dynamodb".into()),
        ],
    }
}

fn extract_dynamodb_delete(event: &serde_json::Value) -> SignalKind {
    let table_name = json_string(event, &["requestParameters", "tableName"])
        .unwrap_or_else(|| "unknown".into());
    SignalKind::ResourceDeleted { resource_id: table_name }
}

fn extract_ec2_create_snapshot(event: &serde_json::Value) -> SignalKind {
    let snap_id = json_string(event, &["responseElements", "snapshotId"])
        .unwrap_or_else(|| "unknown".into());
    let volume_id = json_string(event, &["requestParameters", "volumeId"]);

    // A snapshot is a backup — but it's also a dependency on the volume
    let mut props = vec![("cloud_provider".into(), "aws".into())];
    if let Some(v) = volume_id {
        props.push(("source_volume".into(), v));
    }

    SignalKind::ResourceDiscovered {
        resource_id: snap_id,
        resource_type: nodes::BACKUP_SNAPSHOT,
        name: None,
        region: extract_region(event),
        properties: props,
    }
}

/// Factory for generic delete extractors that read a single ID field
/// from requestParameters.
fn extract_generic_delete(field: &'static str) -> fn(&serde_json::Value) -> SignalKind {
    // Can't capture in fn pointer, so use a match approach
    // This is a compile-time dispatch trick
    match field {
        "volumeId" => |event: &serde_json::Value| {
            let id = json_string(event, &["requestParameters", "volumeId"])
                .unwrap_or_else(|| "unknown".into());
            SignalKind::ResourceDeleted { resource_id: id }
        },
        "vpcId" => |event: &serde_json::Value| {
            let id = json_string(event, &["requestParameters", "vpcId"])
                .unwrap_or_else(|| "unknown".into());
            SignalKind::ResourceDeleted { resource_id: id }
        },
        "groupId" => |event: &serde_json::Value| {
            let id = json_string(event, &["requestParameters", "groupId"])
                .unwrap_or_else(|| "unknown".into());
            SignalKind::ResourceDeleted { resource_id: id }
        },
        "snapshotId" => |event: &serde_json::Value| {
            let id = json_string(event, &["requestParameters", "snapshotId"])
                .unwrap_or_else(|| "unknown".into());
            SignalKind::ResourceDeleted { resource_id: id }
        },
        _ => |_: &serde_json::Value| SignalKind::Ignored,
    }
}

// ===========================
// New Service Extractors
// ===========================

/// Helper: simple create extractor for services with a single ID field
fn simple_create(
    event: &serde_json::Value,
    id_path: &[&str],
    resource_type: &'static str,
) -> SignalKind {
    let id = json_string(event, id_path).unwrap_or_else(|| "unknown".into());
    SignalKind::ResourceDiscovered {
        resource_id: id.clone(),
        resource_type,
        name: Some(id),
        region: extract_region(event),
        properties: vec![("cloud_provider".into(), "aws".into())],
    }
}

/// Helper: simple delete extractor
fn simple_delete(event: &serde_json::Value, id_path: &[&str]) -> SignalKind {
    let id = json_string(event, id_path).unwrap_or_else(|| "unknown".into());
    SignalKind::ResourceDeleted { resource_id: id }
}

// --- ECS ---
fn extract_ecs_create_cluster(event: &serde_json::Value) -> SignalKind {
    let name = json_string(event, &["requestParameters", "clusterName"])
        .or_else(|| json_string(event, &["responseElements", "cluster", "clusterName"]))
        .unwrap_or_else(|| "unknown".into());
    SignalKind::ResourceDiscovered {
        resource_id: name.clone(),
        resource_type: nodes::CONTAINER_CLUSTER,
        name: Some(name),
        region: extract_region(event),
        properties: vec![("cloud_provider".into(), "aws".into()), ("engine".into(), "ecs".into())],
    }
}

fn extract_ecs_delete_cluster(event: &serde_json::Value) -> SignalKind {
    simple_delete(event, &["requestParameters", "cluster"])
}

fn extract_ecs_create_service(event: &serde_json::Value) -> SignalKind {
    let name = json_string(event, &["requestParameters", "serviceName"])
        .unwrap_or_else(|| "unknown".into());
    let cluster = json_string(event, &["requestParameters", "cluster"]);
    let mut props = vec![("cloud_provider".into(), "aws".into()), ("engine".into(), "ecs".into())];
    if let Some(c) = cluster {
        props.push(("cluster".into(), c));
    }
    SignalKind::ResourceDiscovered {
        resource_id: name.clone(),
        resource_type: nodes::CONTAINER_SERVICE,
        name: Some(name),
        region: extract_region(event),
        properties: props,
    }
}

fn extract_ecs_delete_service(event: &serde_json::Value) -> SignalKind {
    simple_delete(event, &["requestParameters", "service"])
}

// --- EKS ---
fn extract_eks_create_cluster(event: &serde_json::Value) -> SignalKind {
    simple_create(event, &["requestParameters", "name"], nodes::CONTAINER_CLUSTER)
}

fn extract_eks_delete_cluster(event: &serde_json::Value) -> SignalKind {
    simple_delete(event, &["requestParameters", "name"])
}

// --- ElastiCache ---
fn extract_elasticache_create(event: &serde_json::Value) -> SignalKind {
    let id = json_string(event, &["requestParameters", "cacheClusterId"])
        .unwrap_or_else(|| "unknown".into());
    let engine = json_string(event, &["requestParameters", "engine"]);
    let mut props = vec![("cloud_provider".into(), "aws".into())];
    if let Some(e) = engine {
        props.push(("engine".into(), e));
    }
    SignalKind::ResourceDiscovered {
        resource_id: id.clone(),
        resource_type: nodes::CACHE_CLUSTER,
        name: Some(id),
        region: extract_region(event),
        properties: props,
    }
}

fn extract_elasticache_delete(event: &serde_json::Value) -> SignalKind {
    simple_delete(event, &["requestParameters", "cacheClusterId"])
}

fn extract_elasticache_create_repl(event: &serde_json::Value) -> SignalKind {
    simple_create(event, &["requestParameters", "replicationGroupId"], nodes::CACHE_CLUSTER)
}

fn extract_elasticache_delete_repl(event: &serde_json::Value) -> SignalKind {
    simple_delete(event, &["requestParameters", "replicationGroupId"])
}

// --- Redshift ---
fn extract_redshift_create(event: &serde_json::Value) -> SignalKind {
    simple_create(event, &["requestParameters", "clusterIdentifier"], nodes::DATA_WAREHOUSE)
}

fn extract_redshift_delete(event: &serde_json::Value) -> SignalKind {
    simple_delete(event, &["requestParameters", "clusterIdentifier"])
}

// --- SQS ---
fn extract_sqs_create(event: &serde_json::Value) -> SignalKind {
    let name = json_string(event, &["requestParameters", "queueName"])
        .unwrap_or_else(|| "unknown".into());
    // SQS queue URL is the real identifier, but name is what CloudTrail gives us at create time
    let queue_url = json_string(event, &["responseElements", "queueUrl"]);
    let id = queue_url.unwrap_or_else(|| name.clone());
    SignalKind::ResourceDiscovered {
        resource_id: id,
        resource_type: nodes::MESSAGE_QUEUE,
        name: Some(name),
        region: extract_region(event),
        properties: vec![("cloud_provider".into(), "aws".into())],
    }
}

fn extract_sqs_delete(event: &serde_json::Value) -> SignalKind {
    simple_delete(event, &["requestParameters", "queueUrl"])
}

// --- SNS ---
fn extract_sns_create(event: &serde_json::Value) -> SignalKind {
    let name = json_string(event, &["requestParameters", "name"])
        .unwrap_or_else(|| "unknown".into());
    let arn = json_string(event, &["responseElements", "topicArn"]);
    let id = arn.unwrap_or_else(|| name.clone());
    SignalKind::ResourceDiscovered {
        resource_id: id,
        resource_type: nodes::NOTIFICATION_TOPIC,
        name: Some(name),
        region: extract_region(event),
        properties: vec![("cloud_provider".into(), "aws".into())],
    }
}

fn extract_sns_delete(event: &serde_json::Value) -> SignalKind {
    simple_delete(event, &["requestParameters", "topicArn"])
}

// --- ELB ---
fn extract_elb_create(event: &serde_json::Value) -> SignalKind {
    // ALB/NLB use "name", classic ELB uses "loadBalancerName"
    let name = json_string(event, &["requestParameters", "name"])
        .or_else(|| json_string(event, &["requestParameters", "loadBalancerName"]))
        .unwrap_or_else(|| "unknown".into());
    let lb_type = json_string(event, &["requestParameters", "type"]);
    let mut props = vec![("cloud_provider".into(), "aws".into())];
    if let Some(t) = lb_type {
        props.push(("lb_type".into(), t));
    }
    SignalKind::ResourceDiscovered {
        resource_id: name.clone(),
        resource_type: nodes::LOAD_BALANCER,
        name: Some(name),
        region: extract_region(event),
        properties: props,
    }
}

fn extract_elb_delete(event: &serde_json::Value) -> SignalKind {
    let arn = json_string(event, &["requestParameters", "loadBalancerArn"]);
    let name = json_string(event, &["requestParameters", "loadBalancerName"]);
    let id = arn.or(name).unwrap_or_else(|| "unknown".into());
    SignalKind::ResourceDeleted { resource_id: id }
}

// --- CloudFront ---
fn extract_cloudfront_create(event: &serde_json::Value) -> SignalKind {
    let id = json_string(event, &["responseElements", "distribution", "id"])
        .unwrap_or_else(|| "unknown".into());
    SignalKind::ResourceDiscovered {
        resource_id: id.clone(),
        resource_type: nodes::CDN_DISTRIBUTION,
        name: Some(id),
        region: "global".into(),
        properties: vec![("cloud_provider".into(), "aws".into())],
    }
}

fn extract_cloudfront_delete(event: &serde_json::Value) -> SignalKind {
    simple_delete(event, &["requestParameters", "id"])
}

// --- Route53 ---
fn extract_route53_create(event: &serde_json::Value) -> SignalKind {
    let name = json_string(event, &["requestParameters", "name"])
        .or_else(|| json_string(event, &["requestParameters", "hostedZoneConfig", "name"]))
        .unwrap_or_else(|| "unknown".into());
    let zone_id = json_string(event, &["responseElements", "hostedZone", "id"]);
    let id = zone_id.unwrap_or_else(|| name.clone());
    SignalKind::ResourceDiscovered {
        resource_id: id,
        resource_type: nodes::DNS_ZONE,
        name: Some(name),
        region: "global".into(),
        properties: vec![("cloud_provider".into(), "aws".into())],
    }
}

fn extract_route53_delete(event: &serde_json::Value) -> SignalKind {
    simple_delete(event, &["requestParameters", "id"])
}

// --- EFS ---
fn extract_efs_create(event: &serde_json::Value) -> SignalKind {
    let id = json_string(event, &["responseElements", "fileSystemId"])
        .unwrap_or_else(|| "unknown".into());
    SignalKind::ResourceDiscovered {
        resource_id: id.clone(),
        resource_type: nodes::FILE_SYSTEM,
        name: Some(id),
        region: extract_region(event),
        properties: vec![("cloud_provider".into(), "aws".into())],
    }
}

fn extract_efs_delete(event: &serde_json::Value) -> SignalKind {
    simple_delete(event, &["requestParameters", "fileSystemId"])
}

// --- Kinesis ---
fn extract_kinesis_create(event: &serde_json::Value) -> SignalKind {
    simple_create(event, &["requestParameters", "streamName"], nodes::STREAM)
}

fn extract_kinesis_delete(event: &serde_json::Value) -> SignalKind {
    simple_delete(event, &["requestParameters", "streamName"])
}

// --- SageMaker ---
fn extract_sagemaker_create(event: &serde_json::Value) -> SignalKind {
    simple_create(event, &["requestParameters", "endpointName"], nodes::ML_ENDPOINT)
}

fn extract_sagemaker_delete(event: &serde_json::Value) -> SignalKind {
    simple_delete(event, &["requestParameters", "endpointName"])
}
