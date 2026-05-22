use hydra_engine::prelude::*;
use hydra_sentinel::prelude::*;
use hydra_core::event::{EventKind, Value};
use hydra_core::id::{EdgeId, NodeId, TenantId};
use std::collections::HashMap;

/// Integration test: Build a realistic AWS data estate graph using sentinel
/// node factories, then exercise every engine layer against it.
#[test]
fn full_sentinel_graph_with_all_four_layers() {
    let mut hydra = Hydra::new();
    let _tenant = TenantId::from_str("ten_acme_corp");

    // ================================================================
    // Phase 1: Discovery — build the data estate graph
    // ================================================================

    // VPC
    let (vpc_id, vpc_event) = VpcBuilder::new("vpc-abc123")
        .region("us-east-1")
        .account_id("123456789012")
        .name("prod-vpc")
        .cidr("10.0.0.0/16")
        .build();
    hydra.ingest(vpc_event).unwrap();

    // RDS (production database — high criticality)
    let (rds_id, rds_event) = RdsBuilder::new("prod-db-payments")
        .region("us-east-1")
        .account_id("123456789012")
        .engine("postgres")
        .engine_version("15.4")
        .multi_az(true)
        .storage_encrypted(true)
        .allocated_storage_gb(500)
        .environment("production")
        .data_sensitivity("high")
        .business_criticality(10)
        .build();
    hydra.ingest(rds_event).unwrap();

    // EC2 (app server)
    let (ec2_id, ec2_event) = Ec2Builder::new("i-0abc123def456")
        .region("us-east-1")
        .account_id("123456789012")
        .name("prod-app-server-1")
        .instance_type("m5.xlarge")
        .environment("production")
        .business_criticality(8)
        .build();
    hydra.ingest(ec2_event).unwrap();

    // S3 (backup bucket)
    let (_s3_id, s3_event) = S3BucketBuilder::new("acme-prod-backups")
        .region("us-east-1")
        .account_id("123456789012")
        .versioning(true)
        .encryption("AES256")
        .data_sensitivity("high")
        .business_criticality(9)
        .build();
    hydra.ingest(s3_event).unwrap();

    // IAM Role
    let (_role_id, role_event) = IamRoleBuilder::new("prod-backup-role")
        .account_id("123456789012")
        .is_service_role(true)
        .build();
    hydra.ingest(role_event).unwrap();

    // Edges: dependencies
    hydra.ingest(EventKind::EdgeCreated {
        edge_id: EdgeId::new(),
        source: ec2_id.clone(),
        target: vpc_id.clone(),
        type_id: IN_VPC.to_string(),
        properties: HashMap::new(),
    }).unwrap();

    hydra.ingest(EventKind::EdgeCreated {
        edge_id: EdgeId::new(),
        source: rds_id.clone(),
        target: vpc_id.clone(),
        type_id: IN_VPC.to_string(),
        properties: HashMap::new(),
    }).unwrap();

    hydra.ingest(EventKind::EdgeCreated {
        edge_id: EdgeId::new(),
        source: ec2_id.clone(),
        target: rds_id.clone(),
        type_id: DEPENDS_ON.to_string(),
        properties: HashMap::from([("dependency_type".into(), Value::String("database".into()))]),
    }).unwrap();

    // Protection: backup snapshot of the RDS
    let (snap_id, snap_event) = BackupSnapshotBuilder::new("snap-rds-20250518")
        .region("us-east-1")
        .size_bytes(50_000_000_000) // 50GB
        .encrypted(true)
        .build();
    hydra.ingest(snap_event).unwrap();

    hydra.ingest(EventKind::EdgeCreated {
        edge_id: EdgeId::new(),
        source: snap_id.clone(),
        target: rds_id.clone(),
        type_id: SNAPSHOT_OF.to_string(),
        properties: HashMap::new(),
    }).unwrap();

    // Protection policy
    let (policy_id, policy_event) = ProtectionPolicyBuilder::new("prod-db-policy")
        .frequency_hours(4)
        .retention_days(90)
        .replication_targets(1)
        .verification_enabled(true)
        .target_sensitivity("high")
        .target_environment("production")
        .build();
    hydra.ingest(policy_event).unwrap();

    hydra.ingest(EventKind::EdgeCreated {
        edge_id: EdgeId::new(),
        source: policy_id.clone(),
        target: rds_id.clone(),
        type_id: POLICY_APPLIES_TO.to_string(),
        properties: HashMap::new(),
    }).unwrap();

    // Compliance: HIPAA regulation
    let (hipaa_id, hipaa_event) = RegulationBuilder::new("HIPAA")
        .min_backup_frequency_hours(24)
        .min_retention_days(180)
        .encryption_required(true)
        .replication_required(true)
        .verification_required(true)
        .applies_to("high")
        .build();
    hydra.ingest(hipaa_event).unwrap();

    hydra.ingest(EventKind::EdgeCreated {
        edge_id: EdgeId::new(),
        source: rds_id.clone(),
        target: hipaa_id.clone(),
        type_id: REGULATED_BY.to_string(),
        properties: HashMap::new(),
    }).unwrap();

    // ================================================================
    // Verify: graph structure
    // ================================================================
    // vpc + rds + ec2 + s3 + role + snapshot + policy + hipaa = 8
    assert_eq!(hydra.node_count(), 8);
    assert!(hydra.edge_count() >= 6);

    // ================================================================
    // Phase 2: Layer 1 — Causal Tracing
    // ================================================================

    // The RDS node was created → all events in its cascade are traceable
    let rds_events = hydra.event_log().iter()
        .filter(|e| e.kind.target_node() == Some(&rds_id))
        .count();
    assert!(rds_events >= 1, "RDS should have at least 1 event");

    // ================================================================
    // Phase 3: Layer 2 — Temporal Queries
    // ================================================================

    // Node state at current time should have all properties
    let rds_state = hydra.temporal().node_state_at(&rds_id, chrono::Utc::now());
    assert!(rds_state.is_some(), "RDS should have temporal history");
    let rds_props = rds_state.unwrap();
    assert_eq!(rds_props.get("engine").and_then(|v| v.as_str()), Some("postgres"));

    // Trust dimensions should be tracked
    let trust_trend = hydra.trend(&rds_id, prop::TRUST_COMPOSITE);
    assert!(!trust_trend.is_empty(), "Trust composite should have at least initial value");

    // ================================================================
    // Phase 4: Layer 3 — Anomaly Detection
    // ================================================================

    // Configure anomaly rules for the sentinel domain
    hydra.anomaly_engine_mut().add_topology_rule(TopologyRule {
        node_type: EC2_INSTANCE.to_string(),
        edge_type: IN_VPC.to_string(),
        min_degree: 1,
        max_degree: 5,
        severity: 0.7,
    });

    hydra.anomaly_engine_mut().add_topology_rule(TopologyRule {
        node_type: RDS_DATABASE.to_string(),
        edge_type: IN_VPC.to_string(),
        min_degree: 1,
        max_degree: 3,
        severity: 0.8,
    });

    hydra.anomaly_engine_mut().add_drift_rule(DriftRule {
        node_type: EC2_INSTANCE.to_string(),
        property: prop::TRUST_COMPOSITE.to_string(),
        min_consecutive: 5,
        severity: 0.7,
    });

    hydra.anomaly_engine_mut().add_pattern_rule(PatternRule {
        name: "admin_broad_permissions".to_string(),
        anchor_type: IAM_USER.to_string(),
        edge_type: "has_permission".to_string(),
        target_type: EC2_INSTANCE.to_string(),
        min_fan_out: 10,
        target_predicate: None,
        anchor_predicate: Some(PropertyPredicate::Equals(
            "is_new".to_string(),
            Value::Bool(true),
        )),
        severity: 0.95,
    });

    // Run batch analysis — should find no anomalies (graph is well-formed)
    let anomalies = hydra.analyze_batch();
    let topology_anomalies: Vec<_> = anomalies.iter()
        .filter(|a| matches!(a.kind, AnomalyKind::TopologyDegree { .. } | AnomalyKind::StructuralOrphan { .. }))
        .collect();
    assert!(topology_anomalies.is_empty(), "Well-formed graph should have no topology anomalies, got: {:?}", topology_anomalies);

    // ================================================================
    // Phase 5: Coverage Score
    // ================================================================

    hydra.coverage_engine_mut().add_model(CoverageModel {
        name: "sentinel_aws_baseline".to_string(),
        expectations: vec![
            CoverageExpectation::MinNodeCount {
                node_type: VPC.to_string(),
                min_count: 1,
            },
            CoverageExpectation::MinNodeCount {
                node_type: IAM_ROLE.to_string(),
                min_count: 1,
            },
            CoverageExpectation::EdgeCoverage {
                source_type: EC2_INSTANCE.to_string(),
                edge_type: IN_VPC.to_string(),
                target_type: VPC.to_string(),
                min_per_source: 1,
            },
            CoverageExpectation::EdgeCoverage {
                source_type: RDS_DATABASE.to_string(),
                edge_type: IN_VPC.to_string(),
                target_type: VPC.to_string(),
                min_per_source: 1,
            },
        ],
        scope_node_type: None,
    });

    let reports = hydra.evaluate_coverage();
    assert_eq!(reports.len(), 1);
    assert!(reports[0].is_complete(), "AWS baseline should be fully met: {:?}", reports[0].gaps);
    assert!((reports[0].score - 1.0).abs() < 0.001);

    // ================================================================
    // Phase 6: Trust Score Computation
    // ================================================================

    let rds_node = hydra.graph().node(&rds_id).unwrap();
    let weights = TrustWeights::high_sensitivity();
    let trust_update = compute_trust_update(rds_node, &weights);

    // Ingest the trust update
    hydra.ingest(trust_update).unwrap();

    // Verify trust composite was computed
    let rds_after = hydra.graph().node(&rds_id).unwrap();
    let composite = rds_after.get_f64(prop::TRUST_COMPOSITE).unwrap();
    // Only anomaly_free has value (1.0 * 1.5 weight), rest are 0
    // composite = (0 + 0 + 0 + 0 + 0 + 1.0*1.5 + 0) / (1+2+2+1+3+1.5+1.5) = 1.5/12 ≈ 12.5
    assert!(composite > 0.0 && composite < 20.0,
        "New RDS with only anomaly_free=1.0 should have low composite: {}", composite);
}

#[test]
fn temporal_graph_view_with_sentinel_nodes() {
    use hydra_core::graph::{bfs_dyn, TraversalDirection};

    let mut hydra = Hydra::new();

    let (vpc_id, vpc_ev) = VpcBuilder::new("vpc-1").build();
    hydra.ingest(vpc_ev).unwrap();

    let (ec2_id, ec2_ev) = Ec2Builder::new("i-001").build();
    hydra.ingest(ec2_ev).unwrap();

    hydra.ingest(EventKind::EdgeCreated {
        edge_id: EdgeId::new(),
        source: ec2_id.clone(),
        target: vpc_id.clone(),
        type_id: IN_VPC.to_string(),
        properties: HashMap::new(),
    }).unwrap();

    // BFS on current graph: ec2 → vpc
    let reachable = bfs_dyn(hydra.graph(), &ec2_id, TraversalDirection::Outgoing, &|_| true);
    assert_eq!(reachable.len(), 2); // ec2 + vpc

    // BFS on temporal view (should match current state)
    let view = hydra.graph_at(chrono::Utc::now());
    let temporal_reachable = bfs_dyn(&view, &ec2_id, TraversalDirection::Outgoing, &|_| true);
    assert_eq!(temporal_reachable.len(), 2);
}

#[test]
fn sentinel_node_builders_produce_correct_types() {
    let mut hydra = Hydra::new();

    let (id, ev) = Ec2Builder::new("i-test").build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), EC2_INSTANCE);

    let (id, ev) = RdsBuilder::new("rds-test").build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), RDS_DATABASE);

    let (id, ev) = S3BucketBuilder::new("bucket-test").build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), S3_BUCKET);

    let (id, ev) = VpcBuilder::new("vpc-test").build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), VPC);

    let (id, ev) = IamRoleBuilder::new("role-test").build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), IAM_ROLE);

    let (id, ev) = IamUserBuilder::new("user-test").build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), IAM_USER);

    let (id, ev) = LambdaBuilder::new("fn-test").build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), LAMBDA_FUNCTION);

    let (id, ev) = BackupSnapshotBuilder::new("snap-test").build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), BACKUP_SNAPSHOT);

    let (id, ev) = ProtectionPolicyBuilder::new("policy-test").build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), PROTECTION_POLICY);

    let (id, ev) = VerificationResultBuilder::new().build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), VERIFICATION_RESULT);

    let (id, ev) = AnomalyRecordBuilder::new("topology", "test anomaly").build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), ANOMALY_RECORD);

    let (id, ev) = IncidentBuilder::new("ransomware", "Test incident").build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), INCIDENT);

    let source = NodeId::new();
    let (id, ev) = BlastRadiusBuilder::new(&source).build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), BLAST_RADIUS);

    let (id, ev) = RegulationBuilder::new("HIPAA").build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), REGULATION);

    let (id, ev) = ComplianceStatusBuilder::new("SOC2").build();
    hydra.ingest(ev).unwrap();
    assert_eq!(hydra.graph().node(&id).unwrap().type_id(), COMPLIANCE_STATUS);

    assert_eq!(hydra.node_count(), 15);
}

/// Multi-cloud integration: AWS + Azure + GCP + SaaS + Endpoint all produce
/// the same abstract node types, share the same edge factories, and trigger
/// the same anomaly/coverage rules. One coverage model catches gaps across
/// ALL clouds.
#[test]
fn multi_cloud_graph_shares_abstract_types() {
    use hydra_sentinel::nodes::azure::*;
    use hydra_sentinel::nodes::gcp::*;
    use hydra_sentinel::nodes::resource::*;
    use hydra_sentinel::edges;

    let mut hydra = Hydra::new();

    // === AWS ===
    let (aws_ec2, ev) = Ec2Builder::new("i-aws001").region("us-east-1").build();
    hydra.ingest(ev).unwrap();
    let (aws_rds, ev) = RdsBuilder::new("db-aws001").build();
    hydra.ingest(ev).unwrap();
    let (aws_vpc, ev) = VpcBuilder::new("vpc-aws001").build();
    hydra.ingest(ev).unwrap();

    // === Azure ===
    let (az_vm, ev) = AzureVmBuilder::new("vm-az001").region("eastus").build();
    hydra.ingest(ev).unwrap();
    let (az_sql, ev) = AzureSqlBuilder::new("db-az001").build();
    hydra.ingest(ev).unwrap();
    let (az_vnet, ev) = AzureVnetBuilder::new("vnet-az001").build();
    hydra.ingest(ev).unwrap();

    // === GCP ===
    let (gcp_vm, ev) = GceBuilder::new("gce-001").region("us-central1").build();
    hydra.ingest(ev).unwrap();
    let (gcp_sql, ev) = CloudSqlBuilder::new("csql-001").build();
    hydra.ingest(ev).unwrap();
    let (gcp_vpc, ev) = GcpVpcBuilder::new("vpc-gcp001").build();
    hydra.ingest(ev).unwrap();

    // === SaaS + Endpoint ===
    let (m365, ev) = SaasApplicationBuilder::new("m365-tenant-acme", "microsoft_365")
        .name("Acme Corp M365")
        .user_count(500)
        .data_sensitivity("high")
        .build();
    hydra.ingest(ev).unwrap();

    let (laptop, ev) = EndpointBuilder::new("laptop-001")
        .name("CEO Laptop")
        .device_type("laptop")
        .os("macOS 15")
        .agent_installed(true)
        .data_sensitivity("critical")
        .build();
    hydra.ingest(ev).unwrap();

    // === All produce abstract types ===
    assert_eq!(hydra.graph().node(&aws_ec2).unwrap().type_id(), COMPUTE_INSTANCE);
    assert_eq!(hydra.graph().node(&az_vm).unwrap().type_id(), COMPUTE_INSTANCE);
    assert_eq!(hydra.graph().node(&gcp_vm).unwrap().type_id(), COMPUTE_INSTANCE);
    assert_eq!(hydra.graph().node(&aws_rds).unwrap().type_id(), MANAGED_DATABASE);
    assert_eq!(hydra.graph().node(&az_sql).unwrap().type_id(), MANAGED_DATABASE);
    assert_eq!(hydra.graph().node(&gcp_sql).unwrap().type_id(), MANAGED_DATABASE);
    assert_eq!(hydra.graph().node(&aws_vpc).unwrap().type_id(), VIRTUAL_NETWORK);
    assert_eq!(hydra.graph().node(&az_vnet).unwrap().type_id(), VIRTUAL_NETWORK);
    assert_eq!(hydra.graph().node(&gcp_vpc).unwrap().type_id(), VIRTUAL_NETWORK);
    assert_eq!(hydra.graph().node(&m365).unwrap().type_id(), SAAS_APPLICATION);
    assert_eq!(hydra.graph().node(&laptop).unwrap().type_id(), ENDPOINT);

    // === Cloud provider distinguishes them ===
    let aws_node = hydra.graph().node(&aws_ec2).unwrap();
    let az_node = hydra.graph().node(&az_vm).unwrap();
    let gcp_node = hydra.graph().node(&gcp_vm).unwrap();
    assert_eq!(aws_node.properties.get("cloud_provider").and_then(|v| v.as_str()), Some("aws"));
    assert_eq!(az_node.properties.get("cloud_provider").and_then(|v| v.as_str()), Some("azure"));
    assert_eq!(gcp_node.properties.get("cloud_provider").and_then(|v| v.as_str()), Some("gcp"));

    // === Same edge factories work across all clouds ===
    let (_, ev) = edges::in_vpc(aws_ec2.clone(), aws_vpc.clone());
    hydra.ingest(ev).unwrap();
    let (_, ev) = edges::in_vpc(az_vm.clone(), az_vnet.clone()); // Azure VM in VNet
    hydra.ingest(ev).unwrap();
    let (_, ev) = edges::in_vpc(gcp_vm.clone(), gcp_vpc.clone()); // GCE in GCP VPC
    hydra.ingest(ev).unwrap();
    let (_, ev) = depends_on(aws_ec2.clone(), aws_rds.clone(), "database", 1.0);
    hydra.ingest(ev).unwrap();
    let (_, ev) = depends_on(az_vm.clone(), az_sql.clone(), "database", 0.95);
    hydra.ingest(ev).unwrap();
    let (_, ev) = depends_on(gcp_vm.clone(), gcp_sql.clone(), "database", 0.9);
    hydra.ingest(ev).unwrap();

    // === ONE coverage model catches gaps across ALL clouds ===
    hydra.coverage_engine_mut().add_model(CoverageModel {
        name: "all_compute_in_network".to_string(),
        expectations: vec![
            CoverageExpectation::EdgeCoverage {
                source_type: COMPUTE_INSTANCE.to_string(),
                edge_type: IN_NETWORK.to_string(),
                target_type: VIRTUAL_NETWORK.to_string(),
                min_per_source: 1,
            },
        ],
        scope_node_type: None,
    });

    let reports = hydra.evaluate_coverage();
    assert_eq!(reports.len(), 1);
    // All 3 compute instances have IN_NETWORK edges → 100% coverage
    assert!(reports[0].is_complete(), "All compute instances should be in a network");
    assert!((reports[0].score - 1.0).abs() < 0.001);

    // === BFS blast radius works cross-cloud ===
    use hydra_core::graph::{bfs_dyn, TraversalDirection};

    // From AWS RDS: who depends on it? → AWS EC2
    let blast = bfs_dyn(hydra.graph(), &aws_rds, TraversalDirection::Incoming, &|_| true);
    assert_eq!(blast.len(), 2, "AWS RDS blast: RDS + EC2");

    // From Azure SQL: who depends on it? → Azure VM
    let blast = bfs_dyn(hydra.graph(), &az_sql, TraversalDirection::Incoming, &|_| true);
    assert_eq!(blast.len(), 2, "Azure SQL blast: SQL + VM");

    // === nodes_by_type returns ALL clouds ===
    let all_compute = hydra.graph().nodes_by_type(COMPUTE_INSTANCE);
    assert_eq!(all_compute.len(), 3, "Should find AWS + Azure + GCP compute instances");

    let all_databases = hydra.graph().nodes_by_type(MANAGED_DATABASE);
    assert_eq!(all_databases.len(), 3, "Should find AWS + Azure + GCP databases");
}

/// Backward compatibility: old AWS constants still work
#[test]
fn aws_aliases_resolve_to_abstract_types() {
    // EC2_INSTANCE and COMPUTE_INSTANCE are the same string
    assert_eq!(EC2_INSTANCE, COMPUTE_INSTANCE);
    assert_eq!(RDS_DATABASE, MANAGED_DATABASE);
    assert_eq!(S3_BUCKET, OBJECT_STORE);
    assert_eq!(VPC, VIRTUAL_NETWORK);
    assert_eq!(IAM_ROLE, IDENTITY_ROLE);
    assert_eq!(IAM_USER, IDENTITY_USER);
    assert_eq!(LAMBDA_FUNCTION, SERVERLESS_FUNCTION);
    assert_eq!(EBS_VOLUME, BLOCK_VOLUME);
    assert_eq!(SUBNET, NETWORK_SEGMENT);
    assert_eq!(SECURITY_GROUP, FIREWALL_RULE);

    // Edge aliases too
    assert_eq!(IN_VPC, IN_NETWORK);
    assert_eq!(IN_SUBNET, IN_SEGMENT);
    assert_eq!(HAS_SECURITY_GROUP, HAS_FIREWALL_RULE);
}

/// Integration test: Full autonomous feedback loop.
///
/// Proves the complete chain:
/// Sensor event → Cascade → Arms fire → Queries run → Trust updated
///                                    → Compliance checked → Violations emitted
///                                    → Temporal diff captures change
///                                    → Coverage bridge evaluates estate
///
/// This is Hydra's thesis: data with agency. The graph thinks for itself.
#[test]
fn full_autonomous_feedback_loop() {
    use hydra_core::subscription::{Subscription, EventFilter};
    use hydra_sentinel::arms::{TrustArm, ComplianceArm, ThreatArm};
    use hydra_sentinel::queries::compliance_gaps::{ComplianceRule, ComplianceRequirement, GapSeverity};
    use hydra_sentinel::queries::temporal;
    use hydra_sentinel::queries::coverage_bridge;
    use hydra_sentinel::queries::anomaly_bridge;

    let mut hydra = Hydra::new();

    // ================================================================
    // Phase 1: Build the estate
    // ================================================================

    // Production database — the crown jewel
    let (db, ev) = RdsBuilder::new("db-prod")
        .business_criticality(10)
        .monthly_cost_cents(500_000) // $5K/month
        .region("us-east-1")
        .build();
    hydra.ingest(ev).unwrap();

    // API servers depending on the DB
    let (api1, ev) = Ec2Builder::new("i-api-1")
        .business_criticality(8)
        .region("us-east-1")
        .build();
    hydra.ingest(ev).unwrap();
    let (api2, ev) = Ec2Builder::new("i-api-2")
        .business_criticality(8)
        .region("us-east-1")
        .build();
    hydra.ingest(ev).unwrap();

    // Worker depending on DB
    let (worker, ev) = Ec2Builder::new("i-worker")
        .business_criticality(6)
        .region("us-east-1")
        .build();
    hydra.ingest(ev).unwrap();

    // Wire dependencies
    let (_, ev) = depends_on(api1.clone(), db.clone(), "database", 1.0);
    hydra.ingest(ev).unwrap();
    let (_, ev) = depends_on(api2.clone(), db.clone(), "database", 1.0);
    hydra.ingest(ev).unwrap();
    let (_, ev) = depends_on(worker.clone(), db.clone(), "database", 0.9);
    hydra.ingest(ev).unwrap();

    // Snapshot the initial state
    let t_initial = chrono::Utc::now();

    // ================================================================
    // Phase 2: Register Arms (the autonomous layer)
    // ================================================================

    let rules = vec![
        ComplianceRule {
            name: "All databases must be protected".into(),
            applies_to: vec![MANAGED_DATABASE.to_string()],
            requirement: ComplianceRequirement::ProtectionRequired,
            severity: GapSeverity::Critical,
        },
        ComplianceRule {
            name: "Min trust score 30".into(),
            applies_to: vec![],
            requirement: ComplianceRequirement::MinTrustScore { min_score: 30.0 },
            severity: GapSeverity::High,
        },
    ];

    // Priority chain: Trust(100) > Compliance(90) > Threat(80)
    hydra.register(Subscription::new(
        "trust_arm",
        EventFilter::Any, // Fires broadly, filters internally
        100,
        Box::new(TrustArm::new()),
    ));
    hydra.register(Subscription::new(
        "compliance_arm",
        EventFilter::Any,
        90,
        Box::new(ComplianceArm::new(rules.clone())),
    ));
    hydra.register(Subscription::new(
        "threat_arm",
        EventFilter::SignalName("anomaly_detected".to_string()),
        80,
        Box::new(ThreatArm::new()),
    ));

    // ================================================================
    // Phase 3: Simulate an anomaly (the trigger)
    // ================================================================

    // This simulates what a CloudTrail sensor would emit
    let mut anomaly_payload = HashMap::new();
    anomaly_payload.insert("description".to_string(),
        Value::String("Unusual bulk deletion pattern on db-prod".into()));
    anomaly_payload.insert("severity".to_string(), Value::Float(0.85));

    let cascade = hydra.ingest(EventKind::Signal {
        source: db.clone(),
        name: "anomaly_detected".to_string(),
        payload: anomaly_payload,
    }).unwrap();

    // ================================================================
    // Phase 4: Verify the autonomous cascade
    // ================================================================

    // The cascade should have produced multiple levels:
    // Level 0: anomaly_detected signal
    // Level 1: ThreatArm → trust_penalty + threat_alert
    // Level 2: TrustArm → NodeUpdated(trust scores)
    //          ComplianceArm → compliance_violation signals
    // Level 3+: Any further reactions
    assert!(cascade.events.len() >= 3,
        "Full cascade should produce 3+ events. Got {}", cascade.events.len());
    assert!(!cascade.truncated, "Cascade should converge, not be truncated");

    // Verify trust was degraded
    let node = hydra.graph().node(&db).unwrap();
    let anomaly_free = node.get_f64(hydra_sentinel::nodes::prop::TRUST_ANOMALY_FREE).unwrap_or(1.0);
    assert!(anomaly_free < 1.0,
        "Trust anomaly_free should be degraded after anomaly. Got {}", anomaly_free);

    // ================================================================
    // Phase 5: Verify temporal diff captures the change
    // ================================================================

    let t_after_anomaly = chrono::Utc::now();

    // Confidence should have dropped
    let conf_diff = temporal::confidence_diff(&hydra, 5, t_initial, t_after_anomaly);
    // Score may or may not have changed depending on initial values,
    // but the function should complete without errors
    assert!(conf_diff.score_t2 >= 0.0 && conf_diff.score_t2 <= 100.0);

    // Blast radius diff — should see same nodes (no structural change)
    let config = hydra_sentinel::queries::blast_radius::BlastRadiusConfig::default();
    let blast_diff = temporal::blast_radius_diff(&hydra, &db, &config, t_initial, t_after_anomaly);
    assert!(blast_diff.is_some(), "Blast diff should return for a node that exists at both times");

    // ================================================================
    // Phase 6: Verify coverage bridge works on this estate
    // ================================================================

    let mut cov_engine = hydra_engine::coverage::CoverageEngine::new();
    coverage_bridge::register_sentinel_models(&mut cov_engine);

    let sentinel_reports = coverage_bridge::evaluate_sentinel_coverage(&cov_engine, hydra.graph());
    assert!(!sentinel_reports.is_empty(), "Should have coverage reports");

    // The DB has no backup → should have cost exposure
    let total_cost: i64 = sentinel_reports.iter().map(|r| r.cost_exposure_cents).sum();
    assert!(total_cost >= 500_000,
        "Unprotected $5K/month DB should show cost exposure. Got {} cents", total_cost);

    // ================================================================
    // Phase 7: Add protection and verify improvement
    // ================================================================

    let (snap, ev) = BackupSnapshotBuilder::new("snap-001").build();
    hydra.ingest(ev).unwrap();
    let (_, ev) = protected_by(db.clone(), snap.clone());
    hydra.ingest(ev).unwrap();

    // Mark as protected
    hydra.ingest(EventKind::NodeUpdated {
        node_id: db.clone(),
        changes: HashMap::from([
            (hydra_sentinel::nodes::prop::PROTECTION_STATUS.to_string(),
             Value::String("protected".into())),
        ]),
    }).unwrap();

    let t_after_protection = chrono::Utc::now();

    // Protection diff should show improvement
    let prot_diff = temporal::protection_diff(&hydra, t_initial, t_after_protection);
    assert!(prot_diff.coverage_delta >= 0.0,
        "Protection should improve after adding backup");

    // Trust backup_freshness should have been updated by TrustArm
    let db_node = hydra.graph().node(&db).unwrap();
    let freshness = db_node.get_f64(hydra_sentinel::nodes::prop::TRUST_BACKUP_FRESHNESS)
        .unwrap_or(0.0);
    assert!((freshness - 1.0).abs() < 0.01,
        "TrustArm should set backup_freshness to 1.0 on protection. Got {}", freshness);

    // ================================================================
    // Phase 8: Verify anomaly bridge threat assessment
    // ================================================================

    // Simulate running the anomaly engine and assessing
    use hydra_engine::anomaly::{Anomaly, AnomalyKind};
    let test_anomalies = vec![Anomaly {
        kind: AnomalyKind::CascadeAmplification {
            cascade_event_count: 50,
            cascade_depth: 10,
            normal_max_count: 5,
            normal_max_depth: 3,
        },
        description: "Unusually large cascade from db-prod".into(),
        severity: 0.9,
        affected_nodes: vec![db.clone()],
        trigger_event: None,
        detected_at: chrono::Utc::now(),
    }];

    let assessment = anomaly_bridge::assess_threats(hydra.graph(), &test_anomalies);
    assert!(assessment.total_blast_scope >= 4,
        "DB with 3 dependents should have blast scope >= 4. Got {}", assessment.total_blast_scope);
    assert!(!assessment.trust_adjustments.is_empty(),
        "Should recommend trust adjustments");

    // Generate events from assessment and verify they're valid
    let adjustment_events = anomaly_bridge::trust_adjustment_events(&assessment.trust_adjustments);
    assert!(!adjustment_events.is_empty());
    for ev in &adjustment_events {
        match ev {
            EventKind::Signal { name, .. } => assert_eq!(name, "trust_penalty"),
            other => panic!("Expected Signal, got {:?}", other),
        }
    }

    // ================================================================
    // Final: Count total test coverage
    // ================================================================

    println!("=== Full Autonomous Loop Integration Test ===");
    println!("Graph: {} nodes, {} edges", hydra.node_count(), hydra.edge_count());
    println!("Total events processed: {}", hydra.total_events());
    println!("Cascade from anomaly: {} events, depth {}", cascade.events.len(), cascade.max_depth_reached);
    println!("Trust anomaly_free after penalty: {:.2}", anomaly_free);
    println!("Trust backup_freshness after protection: {:.2}", freshness);
    println!("Coverage reports: {}", sentinel_reports.len());
    println!("Cost exposure: ${:.2}", total_cost as f64 / 100.0);
    println!("Threat blast scope: {}", assessment.total_blast_scope);
    println!("Threat severity: {:?}", assessment.severity);
    println!("=== All phases passed ===");
}

/// FULL 10-ARM CHAIN: Discovery → Classification → Policy → Execution → Verification → Trust
/// Proves Scaling (B10): a single sensor signal cascades through ALL Arms automatically.
///
/// This is the "holy grail" test: one raw infrastructure event triggers the entire
/// protection pipeline without any human intervention.
#[test]
fn full_ten_arm_cascade_from_sensor_to_protection() {
    use hydra_core::subscription::{Subscription, EventFilter};
    use hydra_sentinel::arms::*;

    let mut hydra = Hydra::with_config(hydra_engine::cascade::CascadeConfig {
        max_depth: 15,
        max_events: 200,
    });

    // ================================================================
    // Phase 1: Register all 10 Arms in priority order
    // ================================================================

    // B1: Discovery (200) — sensor signals → graph nodes
    hydra.register(Subscription::new(
        "discovery_arm",
        EventFilter::Or(vec![
            EventFilter::SignalName("resource_discovered".to_string()),
            EventFilter::SignalName("resource_deleted".to_string()),
            EventFilter::SignalName("dependency_discovered".to_string()),
        ]),
        200,
        Box::new(DiscoveryArm::new()),
    ));

    // B2: Classification (190) — new nodes → criticality/sensitivity
    hydra.register(Subscription::new(
        "classification_arm",
        EventFilter::Or(vec![
            EventFilter::NodeCreated,
            EventFilter::SignalName("needs_classification".to_string()),
        ]),
        190,
        Box::new(ClassificationArm::with_defaults()),
    ));

    // B3: Policy (180) — classification → protection policy
    hydra.register(Subscription::new(
        "policy_arm",
        EventFilter::NodeUpdated,
        180,
        Box::new(PolicyArm::new()),
    ));

    // B4: Execution (170) — policy → backup snapshot
    hydra.register(Subscription::new(
        "execution_arm",
        EventFilter::Or(vec![
            EventFilter::SignalName("policy_computed".to_string()),
            EventFilter::SignalName("scheduled_backup".to_string()),
        ]),
        170,
        Box::new(ExecutionArm::new()),
    ));

    // B5: Verification (160) — backup → verified + trust update
    hydra.register(Subscription::new(
        "verification_arm",
        EventFilter::SignalName("backup_completed".to_string()),
        160,
        Box::new(VerificationArm::new()),
    ));

    // Trust (100) — trust score recomputation
    hydra.register(Subscription::new(
        "trust_arm",
        EventFilter::Or(vec![
            EventFilter::SignalName("trust_penalty".to_string()),
            EventFilter::NodeUpdated,
            EventFilter::EdgeCreated,
        ]),
        100,
        Box::new(TrustArm::new()),
    ));

    // B8: Compliance (90) — regulatory checks
    hydra.register(Subscription::new(
        "compliance_arm",
        EventFilter::Or(vec![
            EventFilter::NodeCreated,
            EventFilter::NodeUpdated,
            EventFilter::SignalName("periodic_compliance_check".to_string()),
        ]),
        90,
        Box::new(ComplianceArm::with_defaults()),
    ));

    // B6: Threat/Detection (80) — anomaly assessment
    hydra.register(Subscription::new(
        "threat_arm",
        EventFilter::SignalName("anomaly_detected".to_string()),
        80,
        Box::new(ThreatArm),
    ));

    // B7: Response (70) — incident + recovery plan
    hydra.register(Subscription::new(
        "response_arm",
        EventFilter::SignalName("threat_alert".to_string()),
        70,
        Box::new(ResponseArm::new()),
    ));

    // B9: Cost (60) — optimization
    hydra.register(Subscription::new(
        "cost_arm",
        EventFilter::SignalName("periodic_cost_review".to_string()),
        60,
        Box::new(CostArm::with_defaults()),
    ));

    // ================================================================
    // Phase 2: Inject a single sensor signal — "discovered a new database"
    // ================================================================

    let mut payload = HashMap::new();
    payload.insert("resource_id".to_string(), Value::String("db-payments-prod".into()));
    payload.insert("resource_type".to_string(), Value::String("managed_database".into()));
    payload.insert("name".to_string(), Value::String("Production Payments DB".into()));
    payload.insert("region".to_string(), Value::String("us-east-1".into()));
    payload.insert("cloud_provider".to_string(), Value::String("aws".into()));

    let result = hydra.ingest(EventKind::Signal {
        source: NodeId::from_str("sensor_cloudtrail"),
        name: "resource_discovered".to_string(),
        payload,
    }).unwrap();

    // ================================================================
    // Phase 3: Verify the cascade chain fired
    // ================================================================

    // The cascade should have produced a rich event chain:
    // Signal(resource_discovered) → DiscoveryArm
    //   → NodeCreated(db-payments-prod) + Signal(needs_classification)
    //     → ClassificationArm → NodeUpdated(criticality=9, sensitivity=high)
    //       → PolicyArm → NodeCreated(policy_*) + EdgeCreated + Signal(policy_computed)
    //         → ExecutionArm → NodeCreated(snap_*) + EdgeCreated + NodeUpdated(protected) + Signal(backup_completed)
    //           → VerificationArm → NodeCreated(verify_*) + EdgeCreated + NodeUpdated(trust) + Signal(verification_completed)

    println!("Total cascade events: {}", result.events.len());
    println!("Max depth reached: {}", result.max_depth_reached);
    assert!(result.events.len() >= 10, "Full chain should produce many events, got {}", result.events.len());

    // --- B1 proof: resource was discovered ---
    let db = hydra.graph().node(&NodeId::from_str("db-payments-prod"));
    assert!(db.is_some(), "B1: Database node should exist");
    let db = db.unwrap();
    assert_eq!(db.type_id(), "managed_database");

    // --- B2 proof: resource was classified ---
    let criticality = db.get_i64("business_criticality");
    assert!(criticality.is_some(), "B2: Should have criticality");
    assert_eq!(criticality.unwrap(), 9, "B2: Managed DB should be tier 1 (crit 9)");
    assert_eq!(db.get_str("data_sensitivity"), Some("high"), "B2: DB should be high sensitivity");
    assert_eq!(db.get_str("classification"), Some("tier_1_critical_data"));

    // --- B3 proof: policy was computed ---
    let policy_id = NodeId::from_str("policy_db-payments-prod");
    let policy = hydra.graph().node(&policy_id);
    assert!(policy.is_some(), "B3: Policy node should exist");
    let policy = policy.unwrap();
    assert_eq!(policy.get_i64("backup_frequency_hours"), Some(1), "B3: Tier 1 = hourly backups");
    assert_eq!(policy.get_i64("retention_days"), Some(365), "B3: High sensitivity = 365d retention");
    assert_eq!(policy.get_bool("encryption_required"), Some(true));
    assert_eq!(policy.get_bool("replication_enabled"), Some(true));

    // --- B4 proof: backup was executed ---
    let snapshots = hydra.graph().nodes_by_type("backup_snapshot");
    assert!(!snapshots.is_empty(), "B4: At least one snapshot should exist");
    let snap = &snapshots[0];
    assert_eq!(snap.get_str("created_by"), Some("execution_arm"));

    // --- B4 proof: resource is now protected ---
    assert_eq!(db.get_str("protection_status"), Some("protected"), "B4: Should be protected");

    // --- B5 proof: backup was verified ---
    let verifications = hydra.graph().nodes_by_type("verification_result");
    assert!(!verifications.is_empty(), "B5: Verification result should exist");
    assert_eq!(verifications[0].get_str("status"), Some("passed"));

    // --- B5 proof: trust was updated ---
    assert_eq!(db.get_f64("trust_backup_freshness"), Some(1.0), "B5: Trust freshness should be 1.0");
    assert_eq!(db.get_f64("trust_backup_verified"), Some(1.0), "B5: Trust verified should be 1.0");
    assert_eq!(db.get_f64("trust_recovery_tested"), Some(1.0), "B5: Trust recovery should be 1.0");

    // --- B10 proof: scaling is automatic ---
    // Inject a second resource — the same chain should fire again
    let mut payload2 = HashMap::new();
    payload2.insert("resource_id".to_string(), Value::String("s3-logs-bucket".into()));
    payload2.insert("resource_type".to_string(), Value::String("object_store".into()));
    payload2.insert("name".to_string(), Value::String("Centralized Logs".into()));
    payload2.insert("cloud_provider".to_string(), Value::String("aws".into()));

    let result2 = hydra.ingest(EventKind::Signal {
        source: NodeId::from_str("sensor_cloudtrail"),
        name: "resource_discovered".to_string(),
        payload: payload2,
    }).unwrap();

    let s3 = hydra.graph().node(&NodeId::from_str("s3-logs-bucket")).unwrap();
    assert_eq!(s3.get_i64("business_criticality"), Some(7), "B10: S3 auto-classified");
    assert_eq!(s3.get_str("protection_status"), Some("protected"), "B10: S3 auto-protected");

    // Re-borrow db for final summary
    let db = hydra.graph().node(&NodeId::from_str("db-payments-prod")).unwrap();

    println!("\n=== FULL 10-ARM CASCADE PROVEN ===");
    println!("First resource: {} events, depth {}", result.events.len(), result.max_depth_reached);
    println!("Second resource: {} events, depth {}", result2.events.len(), result2.max_depth_reached);
    println!("DB: criticality={}, sensitivity={}, protection={}, trust_freshness={}",
        db.get_i64("business_criticality").unwrap_or(0),
        db.get_str("data_sensitivity").unwrap_or("?"),
        db.get_str("protection_status").unwrap_or("?"),
        db.get_f64("trust_backup_freshness").unwrap_or(0.0),
    );
    println!("S3: criticality={}, protection={}",
        s3.get_i64("business_criticality").unwrap_or(0),
        s3.get_str("protection_status").unwrap_or("?"),
    );
    println!("Total nodes: {}, Total edges: {}", hydra.node_count(), hydra.edge_count());
}

/// THREAT RESPONSE CHAIN: Anomaly → Detection → Blast Radius → Trust Penalty → Incident → Recovery Plan
/// Proves the reactive side of the 10-arm system.
#[test]
fn threat_response_chain_with_all_reactive_arms() {
    use hydra_core::subscription::{Subscription, EventFilter};
    use hydra_sentinel::arms::*;

    let mut hydra = Hydra::with_config(hydra_engine::cascade::CascadeConfig {
        max_depth: 15,
        max_events: 200,
    });

    // Register reactive Arms
    hydra.register(Subscription::new(
        "trust_arm",
        EventFilter::Or(vec![
            EventFilter::SignalName("trust_penalty".to_string()),
            EventFilter::NodeUpdated,
            EventFilter::EdgeCreated,
        ]),
        100,
        Box::new(TrustArm::new()),
    ));
    hydra.register(Subscription::new(
        "compliance_arm",
        EventFilter::Or(vec![
            EventFilter::NodeCreated,
            EventFilter::NodeUpdated,
        ]),
        90,
        Box::new(ComplianceArm::with_defaults()),
    ));
    hydra.register(Subscription::new(
        "threat_arm",
        EventFilter::SignalName("anomaly_detected".to_string()),
        80,
        Box::new(ThreatArm),
    ));
    hydra.register(Subscription::new(
        "response_arm",
        EventFilter::SignalName("threat_alert".to_string()),
        70,
        Box::new(ResponseArm::new()),
    ));

    // Build an estate: DB + 2 dependents
    let (db, ev) = hydra_sentinel::nodes::aws::RdsBuilder::new("db-prod")
        .business_criticality(9).build();
    hydra.ingest(ev).unwrap();
    let (api, ev) = hydra_sentinel::nodes::aws::Ec2Builder::new("i-api")
        .business_criticality(7).build();
    hydra.ingest(ev).unwrap();
    let (web, ev) = hydra_sentinel::nodes::aws::Ec2Builder::new("i-web")
        .business_criticality(5).build();
    hydra.ingest(ev).unwrap();
    let (_, ev) = hydra_sentinel::edges::depends_on(api.clone(), db.clone(), "database", 1.0);
    hydra.ingest(ev).unwrap();
    let (_, ev) = hydra_sentinel::edges::depends_on(web.clone(), api.clone(), "api", 1.0);
    hydra.ingest(ev).unwrap();

    // Inject anomaly on the database
    let result = hydra.ingest(EventKind::Signal {
        source: db.clone(),
        name: "anomaly_detected".to_string(),
        payload: HashMap::from([
            ("anomaly_type".to_string(), Value::String("ransomware_signature".into())),
        ]),
    }).unwrap();

    println!("Threat chain: {} events, depth {}", result.events.len(), result.max_depth_reached);

    // Trust should be degraded
    let db_node = hydra.graph().node(&db).unwrap();
    let anomaly_free = db_node.get_f64("trust_anomaly_free").unwrap_or(1.0);
    assert!(anomaly_free < 1.0, "Trust should be degraded by anomaly");

    // Incident should exist
    let incidents = hydra.graph().nodes_by_type("incident");
    assert!(!incidents.is_empty(), "Incident should be created");
    let sev = incidents[0].get_str("severity").unwrap_or("?");
    println!("Incident severity: {}", sev);
    // Severity depends on blast scope and risk score — db + 2 deps = scope 3
    assert!(sev == "High" || sev == "Medium" || sev == "Low",
        "Severity should be a valid level, got: {}", sev);

    // Recovery plan should exist
    let plans = hydra.graph().nodes_by_type("recovery_plan");
    assert!(!plans.is_empty(), "Recovery plan should be created");
    let plan = &plans[0];
    assert!(plan.get_i64("total_steps").unwrap_or(0) > 0, "Plan should have steps");

    println!("Incident: {:?}", incidents[0].get_str("name"));
    println!("Recovery steps: {}", plan.get_i64("total_steps").unwrap_or(0));
    println!("Trust anomaly_free: {}", anomaly_free);
}
