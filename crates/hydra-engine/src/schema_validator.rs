use crate::schema_registry_store::SchemaRegistryStore;
use hydra_core::error::{HydraError, Result};
use hydra_core::{
    Action, ActionKind, FieldSchema, Policy, PolicyKind, SchemaId, SchemaStatus, Value, ValueType,
};
use std::collections::HashMap;

/// One schema validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaValidationError {
    pub schema_id: Option<SchemaId>,
    pub path: String,
    pub message: String,
}

impl SchemaValidationError {
    pub fn new(
        schema_id: Option<SchemaId>,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            schema_id,
            path: path.into(),
            message: message.into(),
        }
    }
}

/// Read-only validation report.
///
/// The validator does not mutate state and does not emit events.
/// A later SchemaGate/SchemaAgent will decide whether validation failures
/// reject, quarantine, or emit diagnostic Signals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaValidationReport {
    pub valid: bool,
    pub schema_id: Option<SchemaId>,
    pub errors: Vec<SchemaValidationError>,
}

impl SchemaValidationReport {
    pub fn valid(schema_id: Option<SchemaId>) -> Self {
        Self {
            valid: true,
            schema_id,
            errors: Vec::new(),
        }
    }

    pub fn invalid(schema_id: Option<SchemaId>, errors: Vec<SchemaValidationError>) -> Self {
        Self {
            valid: false,
            schema_id,
            errors,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn is_invalid(&self) -> bool {
        !self.valid
    }

    pub fn into_result(self) -> Result<()> {
        if self.valid {
            return Ok(());
        }
        let message = self
            .errors
            .iter()
            .map(|error| format!("{}: {}", error.path, error.message))
            .collect::<Vec<_>>()
            .join("; ");
        Err(HydraError::QueryError(format!(
            "schema validation failed: {message}"
        )))
    }
}

/// Read-only schema validator.
///
/// v0 validates HashMap<String, Value> payloads against FieldSchema lists.
/// It can validate:
///
/// - action payloads via ActionPayloadSchema
/// - policy condition maps via PolicyConditionSchema
/// - evidence payload maps when callers provide the evidence kind + payload
///
/// The later SchemaGate will call this before cascade/commit.
#[derive(Debug, Clone, Default)]
pub struct SchemaValidator;

impl SchemaValidator {
    pub fn new() -> Self {
        Self
    }

    /// Validate a raw object payload against field schemas.
    pub fn validate_fields(
        &self,
        schema_id: Option<SchemaId>,
        fields: &[FieldSchema],
        payload: &HashMap<String, Value>,
    ) -> SchemaValidationReport {
        let mut errors = Vec::new();
        for field in fields {
            match payload.get(&field.name) {
                Some(value) => {
                    if let Err(message) = value_matches_type(value, &field.value_type) {
                        errors.push(SchemaValidationError::new(
                            schema_id.clone(),
                            field.name.clone(),
                            message,
                        ));
                    }
                }
                None if field.required => {
                    errors.push(SchemaValidationError::new(
                        schema_id.clone(),
                        field.name.clone(),
                        "missing required field",
                    ));
                }
                None => {}
            }
        }
        if errors.is_empty() {
            SchemaValidationReport::valid(schema_id)
        } else {
            SchemaValidationReport::invalid(schema_id, errors)
        }
    }

    /// Validate an action payload using the registered ActionPayloadSchema.
    ///
    /// If no schema exists, this returns valid. Enforcement policy for unknown
    /// schemas will be handled later by SchemaGateConfig.
    pub fn validate_action_payload(
        &self,
        store: &SchemaRegistryStore,
        action: &Action,
    ) -> SchemaValidationReport {
        let action_kind = action_kind_key(&action.kind);
        let Some(schema) = store.action_payload_schema(&action_kind) else {
            return SchemaValidationReport::valid(None);
        };
        if schema.status != SchemaStatus::Active {
            return SchemaValidationReport::invalid(
                Some(schema.id.clone()),
                vec![SchemaValidationError::new(
                    Some(schema.id.clone()),
                    action_kind,
                    "action payload schema is not active",
                )],
            );
        }
        self.validate_fields(Some(schema.id.clone()), &schema.fields, &action.payload)
    }

    /// Validate a policy condition map using the registered PolicyConditionSchema.
    ///
    /// If no schema exists, this returns valid. Strict unknown-schema behavior
    /// belongs in the later SchemaGate.
    pub fn validate_policy_condition(
        &self,
        store: &SchemaRegistryStore,
        policy: &Policy,
    ) -> SchemaValidationReport {
        let policy_kind = policy_kind_key(&policy.kind);
        let Some(schema) = store.policy_condition_schema(&policy_kind) else {
            return SchemaValidationReport::valid(None);
        };
        if schema.status != SchemaStatus::Active {
            return SchemaValidationReport::invalid(
                Some(schema.id.clone()),
                vec![SchemaValidationError::new(
                    Some(schema.id.clone()),
                    policy_kind,
                    "policy condition schema is not active",
                )],
            );
        }
        self.validate_fields(Some(schema.id.clone()), &schema.fields, &policy.condition)
    }

    /// Validate an Evidence object against the registered EvidencePayloadSchema.
    ///
    /// Adapter over validate_evidence_payload that reads the kind + data out
    /// of the nested EvidencePayload struct. hydra-core stores them as
    /// evidence.payload.kind and evidence.payload.data.
    pub fn validate_evidence(
        &self,
        store: &SchemaRegistryStore,
        evidence: &hydra_core::Evidence,
    ) -> SchemaValidationReport {
        self.validate_evidence_payload(store, &evidence.payload.kind, &evidence.payload.data)
    }

    /// Validate an evidence payload by evidence kind.
    ///
    /// This is intentionally generic because evidence payload shape may be
    /// supplied by multiple caller paths.
    pub fn validate_evidence_payload(
        &self,
        store: &SchemaRegistryStore,
        evidence_kind: &str,
        payload: &HashMap<String, Value>,
    ) -> SchemaValidationReport {
        let Some(schema) = store.evidence_schema(evidence_kind) else {
            return SchemaValidationReport::valid(None);
        };
        if schema.status != SchemaStatus::Active {
            return SchemaValidationReport::invalid(
                Some(schema.id.clone()),
                vec![SchemaValidationError::new(
                    Some(schema.id.clone()),
                    evidence_kind,
                    "evidence payload schema is not active",
                )],
            );
        }
        self.validate_fields(Some(schema.id.clone()), &schema.fields, payload)
    }
}

fn value_matches_type(value: &Value, expected: &ValueType) -> std::result::Result<(), String> {
    match expected {
        ValueType::Any => Ok(()),
        ValueType::Null => match value {
            Value::Null => Ok(()),
            other => Err(type_error("Null", other)),
        },
        ValueType::Bool => match value {
            Value::Bool(_) => Ok(()),
            other => Err(type_error("Bool", other)),
        },
        ValueType::Int => match value {
            Value::Int(_) => Ok(()),
            other => Err(type_error("Int", other)),
        },
        ValueType::Float => match value {
            Value::Float(_) | Value::Int(_) => Ok(()),
            other => Err(type_error("Float", other)),
        },
        ValueType::String => match value {
            Value::String(_) => Ok(()),
            other => Err(type_error("String", other)),
        },
        // Native Value::Timestamp is accepted directly; RFC3339 strings are
        // also accepted so external/JSON callers can pass timestamps without
        // pre-parsing.
        ValueType::Timestamp => match value {
            Value::Timestamp(_) => Ok(()),
            Value::String(value) if chrono::DateTime::parse_from_rfc3339(value).is_ok() => Ok(()),
            Value::String(_) => Err("expected Timestamp string in RFC3339 format".to_string()),
            other => Err(type_error("Timestamp", other)),
        },
        ValueType::List(inner) => match value {
            Value::List(values) => {
                for (index, item) in values.iter().enumerate() {
                    value_matches_type(item, inner)
                        .map_err(|message| format!("list[{index}] {message}"))?;
                }
                Ok(())
            }
            other => Err(type_error("List", other)),
        },
        // hydra-core uses Value::Map for object-shaped values.
        ValueType::Object => match value {
            Value::Map(_) => Ok(()),
            other => Err(type_error("Object", other)),
        },
        // v0 custom types accept string identifiers or map payloads.
        // The later validator can resolve TypeId against EntityTypeSchema.
        ValueType::Custom(_) => match value {
            Value::String(_) | Value::Map(_) => Ok(()),
            other => Err(type_error("Custom", other)),
        },
    }
}

fn type_error(expected: &str, actual: &Value) -> String {
    format!("expected {expected}, got {}", value_kind_name(actual))
}

fn value_kind_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "Null",
        Value::Bool(_) => "Bool",
        Value::Int(_) => "Int",
        Value::Float(_) => "Float",
        Value::String(_) => "String",
        Value::Timestamp(_) => "Timestamp",
        Value::List(_) => "List",
        Value::Map(_) => "Map",
    }
}

fn action_kind_key(kind: &ActionKind) -> String {
    match kind {
        ActionKind::Notify => "Notify".to_string(),
        ActionKind::CreateTicket => "CreateTicket".to_string(),
        ActionKind::AssignOwner => "AssignOwner".to_string(),
        ActionKind::RequestEvidence => "RequestEvidence".to_string(),
        ActionKind::Quarantine => "Quarantine".to_string(),
        ActionKind::Backfill => "Backfill".to_string(),
        ActionKind::Repair => "Repair".to_string(),
        ActionKind::Approve => "Approve".to_string(),
        ActionKind::Reject => "Reject".to_string(),
        ActionKind::ExecuteWorkflow => "ExecuteWorkflow".to_string(),
        ActionKind::PostLedgerEntry => "PostLedgerEntry".to_string(),
        ActionKind::RunPayroll => "RunPayroll".to_string(),
        ActionKind::Custom(value) => format!("Custom:{value}"),
    }
}

fn policy_kind_key(kind: &PolicyKind) -> String {
    match kind {
        PolicyKind::AutoApproval => "AutoApproval".to_string(),
        PolicyKind::HumanApproval => "HumanApproval".to_string(),
        PolicyKind::Block => "Block".to_string(),
        PolicyKind::Escalation => "Escalation".to_string(),
        PolicyKind::ReviewRequirement => "ReviewRequirement".to_string(),
        PolicyKind::Compliance => "Compliance".to_string(),
        PolicyKind::Security => "Security".to_string(),
        PolicyKind::Finance => "Finance".to_string(),
        PolicyKind::Payroll => "Payroll".to_string(),
        PolicyKind::Custom(value) => format!("Custom:{value}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema_registry_store::SchemaRegistryStore;
    use hydra_core::{
        Action, ActionId, ActionKind, ActionPayloadSchema, ActionStatus, ActionTarget, ActorId,
        Event, EventId, EventKind, FieldSchema, Policy, PolicyConditionSchema, PolicyId,
        PolicyKind, PolicyScope, PolicyStatus, SchemaDefinition, SchemaId, ValueType,
    };
    use std::collections::HashMap;

    fn actor() -> ActorId {
        ActorId::from_str("actor_schema_validator")
    }

    fn event(kind: EventKind) -> Event {
        Event {
            id: EventId::new(),
            tenant_id: None,
            timestamp: chrono::Utc::now(),
            kind,
            caused_by: vec![],
            cascade_id: hydra_core::CascadeId::new(),
            cascade_depth: 0,
            cascade_breadth_index: 0,
        }
    }

    fn action(kind: ActionKind, payload: HashMap<String, Value>) -> Action {
        let now = chrono::Utc::now();
        Action {
            id: ActionId::new(),
            tenant_id: None,
            kind,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("test".to_string())],
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

    fn policy(kind: PolicyKind, condition: HashMap<String, Value>) -> Policy {
        let now = chrono::Utc::now();
        Policy {
            id: PolicyId::new(),
            tenant_id: None,
            name: "test policy".to_string(),
            kind,
            status: PolicyStatus::Active,
            scope: PolicyScope::AnyAction,
            condition,
            metadata: HashMap::new(),
            created_by: actor(),
            created_at: now,
            updated_at: now,
            caused_by: None,
        }
    }

    fn store_with_action_schema(status: SchemaStatus) -> SchemaRegistryStore {
        let now = chrono::Utc::now();
        let mut store = SchemaRegistryStore::new();
        let schema = ActionPayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            action_kind: "PostLedgerEntry".to_string(),
            status,
            fields: vec![
                FieldSchema::required("account", ValueType::String),
                FieldSchema::required("amount", ValueType::Float),
                FieldSchema::optional("memo", ValueType::String),
            ],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        store
            .apply_event(&event(EventKind::SchemaRegistered {
                schema: SchemaDefinition::ActionPayload(schema),
            }))
            .unwrap();
        store
    }

    fn store_with_policy_schema(status: SchemaStatus) -> SchemaRegistryStore {
        let now = chrono::Utc::now();
        let mut store = SchemaRegistryStore::new();
        let schema = PolicyConditionSchema {
            id: SchemaId::new(),
            tenant_id: None,
            policy_kind: "AutoApproval".to_string(),
            status,
            fields: vec![FieldSchema::required("max_amount", ValueType::Float)],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        store
            .apply_event(&event(EventKind::SchemaRegistered {
                schema: SchemaDefinition::PolicyCondition(schema),
            }))
            .unwrap();
        store
    }

    #[test]
    fn validates_required_fields_and_types() {
        let validator = SchemaValidator::new();
        let fields = vec![
            FieldSchema::required("amount", ValueType::Float),
            FieldSchema::required("currency", ValueType::String),
            FieldSchema::optional("memo", ValueType::String),
        ];
        let mut payload = HashMap::new();
        payload.insert("amount".to_string(), Value::Float(10.5));
        payload.insert("currency".to_string(), Value::String("USD".to_string()));
        let report = validator.validate_fields(None, &fields, &payload);
        assert!(report.is_valid());
    }

    #[test]
    fn reports_missing_required_field() {
        let validator = SchemaValidator::new();
        let fields = vec![FieldSchema::required("amount", ValueType::Float)];
        let payload = HashMap::new();
        let report = validator.validate_fields(None, &fields, &payload);
        assert!(report.is_invalid());
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].path, "amount");
        assert!(report.errors[0].message.contains("missing required"));
    }

    #[test]
    fn reports_wrong_type() {
        let validator = SchemaValidator::new();
        let fields = vec![FieldSchema::required("amount", ValueType::Float)];
        let mut payload = HashMap::new();
        payload.insert("amount".to_string(), Value::String("10.5".to_string()));
        let report = validator.validate_fields(None, &fields, &payload);
        assert!(report.is_invalid());
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].message.contains("expected Float"));
    }

    #[test]
    fn int_is_valid_for_float() {
        let validator = SchemaValidator::new();
        let fields = vec![FieldSchema::required("amount", ValueType::Float)];
        let mut payload = HashMap::new();
        payload.insert("amount".to_string(), Value::Int(10));
        let report = validator.validate_fields(None, &fields, &payload);
        assert!(report.is_valid());
    }

    #[test]
    fn validates_list_inner_types() {
        let validator = SchemaValidator::new();
        let fields = vec![FieldSchema::required(
            "tags",
            ValueType::List(Box::new(ValueType::String)),
        )];
        let mut payload = HashMap::new();
        payload.insert(
            "tags".to_string(),
            Value::List(vec![
                Value::String("a".to_string()),
                Value::String("b".to_string()),
            ]),
        );
        let report = validator.validate_fields(None, &fields, &payload);
        assert!(report.is_valid());
        payload.insert(
            "tags".to_string(),
            Value::List(vec![Value::String("a".to_string()), Value::Bool(true)]),
        );
        let report = validator.validate_fields(None, &fields, &payload);
        assert!(report.is_invalid());
        assert!(report.errors[0].message.contains("list[1]"));
    }

    #[test]
    fn validates_timestamp_strings() {
        let validator = SchemaValidator::new();
        let fields = vec![FieldSchema::required("posted_at", ValueType::Timestamp)];
        let mut payload = HashMap::new();
        payload.insert(
            "posted_at".to_string(),
            Value::String("2026-01-01T00:00:00Z".to_string()),
        );
        assert!(validator.validate_fields(None, &fields, &payload).is_valid());
        payload.insert(
            "posted_at".to_string(),
            Value::String("not-a-date".to_string()),
        );
        assert!(validator
            .validate_fields(None, &fields, &payload)
            .is_invalid());
    }

    #[test]
    fn validates_native_timestamp_value() {
        let validator = SchemaValidator::new();
        let fields = vec![FieldSchema::required("posted_at", ValueType::Timestamp)];
        let mut payload = HashMap::new();
        payload.insert("posted_at".to_string(), Value::Timestamp(chrono::Utc::now()));
        assert!(validator.validate_fields(None, &fields, &payload).is_valid());
    }

    #[test]
    fn validates_action_payload_against_registered_schema() {
        let store = store_with_action_schema(SchemaStatus::Active);
        let validator = SchemaValidator::new();
        let mut payload = HashMap::new();
        payload.insert("account".to_string(), Value::String("Revenue".to_string()));
        payload.insert("amount".to_string(), Value::Float(100.0));
        let action = action(ActionKind::PostLedgerEntry, payload);
        let report = validator.validate_action_payload(&store, &action);
        assert!(report.is_valid());
        assert!(report.schema_id.is_some());
    }

    #[test]
    fn invalid_action_payload_reports_errors() {
        let store = store_with_action_schema(SchemaStatus::Active);
        let validator = SchemaValidator::new();
        let mut payload = HashMap::new();
        payload.insert("account".to_string(), Value::String("Revenue".to_string()));
        payload.insert("amount".to_string(), Value::String("bad".to_string()));
        let action = action(ActionKind::PostLedgerEntry, payload);
        let report = validator.validate_action_payload(&store, &action);
        assert!(report.is_invalid());
        assert_eq!(report.errors.len(), 1);
    }

    #[test]
    fn unknown_action_schema_is_valid_in_read_only_v0() {
        let store = SchemaRegistryStore::new();
        let validator = SchemaValidator::new();
        let action = action(ActionKind::Backfill, HashMap::new());
        let report = validator.validate_action_payload(&store, &action);
        assert!(report.is_valid());
        assert_eq!(report.schema_id, None);
    }

    #[test]
    fn disabled_action_schema_is_invalid() {
        let store = store_with_action_schema(SchemaStatus::Disabled);
        let validator = SchemaValidator::new();
        let action = action(ActionKind::PostLedgerEntry, HashMap::new());
        let report = validator.validate_action_payload(&store, &action);
        assert!(report.is_invalid());
        assert!(report.errors[0].message.contains("not active"));
    }

    #[test]
    fn validates_policy_condition_against_registered_schema() {
        let store = store_with_policy_schema(SchemaStatus::Active);
        let validator = SchemaValidator::new();
        let mut condition = HashMap::new();
        condition.insert("max_amount".to_string(), Value::Float(5000.0));
        let policy = policy(PolicyKind::AutoApproval, condition);
        let report = validator.validate_policy_condition(&store, &policy);
        assert!(report.is_valid());
        assert!(report.schema_id.is_some());
    }

    #[test]
    fn invalid_policy_condition_reports_errors() {
        let store = store_with_policy_schema(SchemaStatus::Active);
        let validator = SchemaValidator::new();
        let condition = HashMap::new();
        let policy = policy(PolicyKind::AutoApproval, condition);
        let report = validator.validate_policy_condition(&store, &policy);
        assert!(report.is_invalid());
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].path, "max_amount");
    }

    #[test]
    fn validation_report_converts_to_result() {
        let report = SchemaValidationReport::invalid(
            None,
            vec![SchemaValidationError::new(
                None,
                "amount",
                "missing required field",
            )],
        );
        let result = report.into_result();
        assert!(result.is_err());
    }
}
