use hydra_core::{
    Action, ActionPayloadSchema, Claim, ClaimPredicateSchema, EntityTypeSchema, Evidence,
    EvidencePayloadSchema, Policy, PolicyConditionSchema, SchemaDefinition, SchemaId, TypeId,
    Value,
};
use hydra_engine::hydra::Hydra;
use hydra_engine::schema_validator::SchemaValidationReport;
use std::collections::HashMap;

/// Ergonomic SDK-facing schema API.
///
/// Borrows `&Hydra` and groups schema-related accessors and preflight
/// validators under one handle, so callers can write:
///
/// ```ignore
/// let report = sdk.schema().validate_action_payload(&action);
/// if report.is_invalid() {
///     return Err(report);
/// }
/// ```
///
/// All methods are read-only and do not mutate Hydra state. Validation
/// methods return the same SchemaValidationReport the strict SchemaGate
/// produces during ingestion, so preflight and enforcement agree by
/// construction.
#[derive(Clone, Copy)]
pub struct SchemaApi<'a> {
    hydra: &'a Hydra,
}

impl<'a> SchemaApi<'a> {
    pub fn new(hydra: &'a Hydra) -> Self {
        Self { hydra }
    }

    // === Registry introspection ===

    pub fn schema(&self, id: &SchemaId) -> Option<&'a SchemaDefinition> {
        self.hydra.schema(id)
    }

    pub fn active_schemas(&self) -> Vec<&'a SchemaDefinition> {
        self.hydra.active_schemas()
    }

    pub fn disabled_schemas(&self) -> Vec<&'a SchemaDefinition> {
        self.hydra.disabled_schemas()
    }

    pub fn archived_schemas(&self) -> Vec<&'a SchemaDefinition> {
        self.hydra.archived_schemas()
    }

    pub fn entity_schema(&self, type_id: &TypeId) -> Option<&'a EntityTypeSchema> {
        self.hydra.entity_schema(type_id)
    }

    pub fn evidence_schema(&self, kind: &str) -> Option<&'a EvidencePayloadSchema> {
        self.hydra.evidence_schema(kind)
    }

    pub fn claim_predicate_schema(&self, predicate: &str) -> Option<&'a ClaimPredicateSchema> {
        self.hydra.claim_predicate_schema(predicate)
    }

    pub fn action_payload_schema(&self, action_kind: &str) -> Option<&'a ActionPayloadSchema> {
        self.hydra.action_payload_schema(action_kind)
    }

    pub fn policy_condition_schema(&self, policy_kind: &str) -> Option<&'a PolicyConditionSchema> {
        self.hydra.policy_condition_schema(policy_kind)
    }

    // === Preflight validation ===
    //
    // Each method returns the same SchemaValidationReport that strict
    // SchemaGate would produce at ingestion time. Callers can use these
    // to surface validation errors before attempting a write.

    pub fn validate_action_payload(&self, action: &Action) -> SchemaValidationReport {
        self.hydra.validate_action_payload(action)
    }

    pub fn validate_policy_condition(&self, policy: &Policy) -> SchemaValidationReport {
        self.hydra.validate_policy_condition(policy)
    }

    pub fn validate_evidence(&self, evidence: &Evidence) -> SchemaValidationReport {
        self.hydra.validate_evidence(evidence)
    }

    pub fn validate_claim(&self, claim: &Claim) -> SchemaValidationReport {
        self.hydra.validate_claim(claim)
    }

    pub fn validate_node_create(
        &self,
        type_id: &TypeId,
        properties: &HashMap<String, Value>,
    ) -> SchemaValidationReport {
        self.hydra.validate_node_create(type_id, properties)
    }

    pub fn validate_node_update(
        &self,
        type_id: &TypeId,
        changes: &HashMap<String, Value>,
    ) -> SchemaValidationReport {
        self.hydra.validate_node_update(type_id, changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_hydra::TestHydra;
    use hydra_core::{
        Action, ActionId, ActionKind, ActionPayloadSchema, ActionStatus, ActionTarget, ActorId,
        EntityTypeSchema, EventKind, FieldSchema, SchemaDefinition, SchemaId, SchemaStatus,
        TypeId, ValueType,
    };
    use std::collections::HashMap;

    fn actor() -> ActorId {
        ActorId::from_str("actor_sdk_schema")
    }

    fn post_ledger_schema() -> SchemaDefinition {
        let now = chrono::Utc::now();
        SchemaDefinition::ActionPayload(ActionPayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            action_kind: "PostLedgerEntry".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("account", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
            ],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        })
    }

    fn invoice_entity_schema() -> SchemaDefinition {
        let now = chrono::Utc::now();
        SchemaDefinition::EntityType(EntityTypeSchema {
            id: SchemaId::new(),
            tenant_id: None,
            type_id: TypeId::from_str("type_invoice"),
            name: "Invoice".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("invoice_number", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
            ],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        })
    }

    fn post_ledger_action(amount: Value) -> Action {
        let now = chrono::Utc::now();
        let mut payload = HashMap::new();
        payload.insert("account".to_string(), Value::String("Cash".to_string()));
        payload.insert("amount".to_string(), amount);
        Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::PostLedgerEntry,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("ledger".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor(),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        }
    }

    #[test]
    fn sdk_schema_api_exposes_registered_schemas() {
        let mut t = TestHydra::new();
        t.ingest(EventKind::SchemaRegistered {
            schema: post_ledger_schema(),
        });
        t.ingest(EventKind::SchemaRegistered {
            schema: invoice_entity_schema(),
        });
        let schema = t.schema();
        assert_eq!(schema.active_schemas().len(), 2);
        assert!(schema.action_payload_schema("PostLedgerEntry").is_some());
        assert!(schema
            .entity_schema(&TypeId::from_str("type_invoice"))
            .is_some());
    }

    #[test]
    fn sdk_schema_api_validates_action_payload() {
        let mut t = TestHydra::new();
        t.ingest(EventKind::SchemaRegistered {
            schema: post_ledger_schema(),
        });
        let action = post_ledger_action(Value::Float(100.0));
        let report = t.schema().validate_action_payload(&action);
        assert!(report.is_valid());
        assert!(report.schema_id.is_some());
    }

    #[test]
    fn sdk_schema_api_reports_invalid_action_payload() {
        let mut t = TestHydra::new();
        t.ingest(EventKind::SchemaRegistered {
            schema: post_ledger_schema(),
        });
        let action = post_ledger_action(Value::String("bad".to_string()));
        let report = t.schema().validate_action_payload(&action);
        assert!(report.is_invalid());
        assert_eq!(report.errors[0].path, "amount");
    }

    #[test]
    fn sdk_schema_api_validates_node_create() {
        let mut t = TestHydra::new();
        t.ingest(EventKind::SchemaRegistered {
            schema: invoice_entity_schema(),
        });
        let mut properties = HashMap::new();
        properties.insert(
            "invoice_number".to_string(),
            Value::String("INV-001".to_string()),
        );
        properties.insert("amount".to_string(), Value::Float(100.0));
        let report = t
            .schema()
            .validate_node_create(&TypeId::from_str("type_invoice"), &properties);
        assert!(report.is_valid());
        assert!(report.schema_id.is_some());
    }

    #[test]
    fn sdk_schema_preflight_matches_strict_gate_rejection() {
        use hydra_engine::schema_gate::{SchemaGateConfig, SchemaGateMode, UnknownSchemaPolicy};

        let mut t = TestHydra::new();
        t.ingest(EventKind::SchemaRegistered {
            schema: post_ledger_schema(),
        });
        t.hydra_mut().set_schema_gate_config(SchemaGateConfig {
            mode: SchemaGateMode::Strict,
            unknown_schema_policy: UnknownSchemaPolicy::Allow,
        });

        let action = post_ledger_action(Value::String("bad".to_string()));

        // Preflight says invalid.
        let report = t.schema().validate_action_payload(&action);
        assert!(report.is_invalid());

        // Strict gate rejects ingest with the same payload — preflight and
        // enforcement agree.
        let result = t.hydra_mut().ingest(EventKind::ActionProposed { action });
        assert!(result.is_err());
    }
}
